// =====================================================================================
// `P10.32-s` — L'AVEU « CAPTEUR INDISPONIBLE » N'EST PAS UN SIGNE DE VIE.
//
// La sonde de flux (`Sonde::EventFlux`) prenait `MAX(ts)` sur toute ligne de la source, aveu compris.
// Un capteur qui dit « je ne collecte pas » (`collectors/lib.sh`, `plume_report_availability` :
// `category=config`, `fields.type=collector-availability`, `fields.collect_status=unavailable`) se
// faisait donc compter VIVANT par son propre aveu.
//
// CE QUE CES TÉMOINS JOUENT, sur la base que la production construit (`test_db`), avec les
// descripteurs RÉELS de `COLLECTORS` et des instants INJECTÉS (aucune horloge mesurée) :
//   - l'aveu seul ne fait pas de dernière collecte (une source, et le flux multi-sources du journal) ;
//   - il ne masque pas le dernier événement réel, plus ancien que lui ;
//   - l'auto-rapport `category=config` sans forme d'aveu RESTE compté (seul signe de vie de `web`) ;
//   - `disabled`, `fallback`, `partial` restent comptés ; un seul des deux champs ne suffit pas ;
//   - le verdict de bout en bout : `ufw` (événementiel) reste « inconnu », `audit` (continu) n'est
//     pas remis à zéro ;
//   - le coût : aveux FIXES + flux x4 -> VM steps constants, plan SEARCH sur idx_event_src_ts ; la
//     pente par aveu, MESURÉE et affichée (le coût de la sonde suit le nombre d'aveux, c'est dit) ;
//   - Fraîcheur et `/api/sources` (lus sur `event_rollup.last_ts`) : l'aveu n'y fait plus une source
//     « fraîche », la correction est byte-identique sur le chemin nominal sans filtre d'environnement (sous filtre,
//     un reste dit : `p10_32s_la_borne_ne_prend_jamais_l_instant_d_une_ligne_qui_n_est_pas_de_cette_source`),
//     plafonnée, AU PLAFOND un
//     FAIT BORNÉ (jamais une lecture ratée : ni `non_lu`, ni `non_lus`, ni `error`), et dite quand
//     sa lecture échoue vraiment (index absent) ; sans borne de date (un dernier réel d'avant la fenêtre est servi « en
//     retard »), sous le filtre d'environnement (une ligne d'un autre environnement ne rajeunit pas,
//     mais compte dans le plafond), et le prédicat jugé à ce site (clés absentes, disabled/partial).
// =====================================================================================

const T2_MAINTENANT: i64 = 1_750_000_000;
const T2_AVEU_LIB_SH: &str =
    r#"{"type":"collector-availability","collector":"ufw","collect_status":"unavailable","reason":"missing-source","detail":"journal ufw absent"}"#;

fn t2_sonde(id: &str) -> &'static Sonde {
    &COLLECTORS.iter().find(|c| c.0 == id).unwrap_or_else(|| panic!("capteur {id} absent de COLLECTORS")).3
}

fn t2_insere(conn: &Connection, ts: i64, source: &str, category: &str, fields: Option<&str>) {
    conn.prepare_cached(
        "INSERT INTO event(ts,source,category,severity,host,message,fields) VALUES(?1,?2,?3,2,'machine0','m',?4)",
    )
    .unwrap()
    .execute(params![ts, source, category, fields])
    .unwrap();
}

fn t2_aveu(source: &str, statut: &str) -> String {
    format!(
        r#"{{"type":"collector-availability","collector":"{source}","collect_status":"{statut}","reason":"missing-source","detail":"d"}}"#
    )
}

#[test]
fn p10_32s_un_aveu_seul_ne_fait_pas_de_derniere_collecte() {
    let conn = test_db();
    t2_insere(&conn, T2_MAINTENANT - 10, "ufw", "config", Some(T2_AVEU_LIB_SH));
    assert_eq!(
        t2_sonde("ufw").derniere_collecte(&conn).unwrap(),
        None,
        "un capteur qui n'a JAMAIS rien collecté et qui l'avoue reste « jamais vu »"
    );
    // Le flux multi-sources (`source IN (…)`) : même règle.
    t2_insere(&conn, T2_MAINTENANT - 10, "sshd", "config", Some(&t2_aveu("sshd", "unavailable")));
    t2_insere(&conn, T2_MAINTENANT - 9, "sudo", "config", Some(&t2_aveu("sudo", "unavailable")));
    assert_eq!(t2_sonde("journal").derniere_collecte(&conn).unwrap(), None, "flux du journal : aveux seuls");
}

#[test]
fn p10_32s_l_aveu_ne_masque_pas_le_dernier_evenement_reel() {
    let conn = test_db();
    t2_insere(&conn, T2_MAINTENANT - 5_000, "ufw", "firewall", None);
    t2_insere(&conn, T2_MAINTENANT - 4_000, "ufw", "firewall", Some(r#"{"action":"block"}"#));
    t2_insere(&conn, T2_MAINTENANT - 10, "ufw", "config", Some(T2_AVEU_LIB_SH));
    t2_insere(&conn, T2_MAINTENANT - 3_610, "ufw", "config", Some(&t2_aveu("ufw", "unavailable")));
    assert_eq!(t2_sonde("ufw").derniere_collecte(&conn).unwrap(), Some(T2_MAINTENANT - 4_000));
    t2_insere(&conn, T2_MAINTENANT - 7_000, "su", "auth", None);
    t2_insere(&conn, T2_MAINTENANT - 20, "sudo", "config", Some(&t2_aveu("sudo", "unavailable")));
    assert_eq!(t2_sonde("journal").derniere_collecte(&conn).unwrap(), Some(T2_MAINTENANT - 7_000));
}

#[test]
fn p10_32s_l_auto_rapport_config_reste_un_signe_de_vie() {
    let conn = test_db();
    // Forme de `collectors/web.sh` : `category=config`, `type=collection-reducing`, aucun `collect_status`.
    let auto_rapport = r#"{"type":"collection-reducing","collector":"web","filters":{"max_lines":"5000"},"note":"n"}"#;
    t2_insere(&conn, T2_MAINTENANT - 30, "web", "config", Some(auto_rapport));
    assert_eq!(
        t2_sonde("web").derniere_collecte(&conn).unwrap(),
        Some(T2_MAINTENANT - 30),
        "l'auto-rapport de configuration est le seul signe de vie de `web` : il reste compté"
    );
    t2_insere(&conn, T2_MAINTENANT - 20, "auditd", "config", None);
    assert_eq!(t2_sonde("audit").derniere_collecte(&conn).unwrap(), Some(T2_MAINTENANT - 20), "config sans fields : compté");
}

#[test]
fn p10_32s_disabled_fallback_partial_et_les_formes_incompletes_restent_comptes() {
    for (n, (source, fields)) in [
        ("ufw", t2_aveu("ufw", "disabled")),
        ("ufw", t2_aveu("ufw", "fallback")),
        ("ufw", t2_aveu("ufw", "partial")),
        // Un seul des deux champs de l'aveu : ce n'est pas un aveu.
        ("ufw", r#"{"type":"autre-forme","collect_status":"unavailable"}"#.to_string()),
        ("ufw", r#"{"type":"collector-availability","collect_status":"available"}"#.to_string()),
        // L'autre clé ABSENTE (`json_extract` -> NULL) : `IS NOT`, pas `<>`, sur CHACUNE des deux clauses.
        ("ufw", r#"{"collect_status":"unavailable"}"#.to_string()),
        ("ufw", r#"{"type":"collector-availability"}"#.to_string()),
        // `fields` qui n'est pas du JSON : pas un aveu, et surtout pas une sonde NON LUE.
        ("ufw", "pas{du json".to_string()),
    ]
    .into_iter()
    .enumerate()
    {
        let conn = test_db();
        t2_insere(&conn, T2_MAINTENANT - 40, source, "config", Some(&fields));
        assert_eq!(
            t2_sonde("ufw").derniere_collecte(&conn).unwrap(),
            Some(T2_MAINTENANT - 40),
            "cas {n} ({fields}) : seul `collector-availability` + `unavailable` est exclu"
        );
    }
}

#[test]
fn p10_32s_le_verdict_de_bout_en_bout_ufw_et_audit() {
    let (_, _, intervalle_ufw, sonde_ufw, evenementiel_ufw) = COLLECTORS.iter().find(|c| c.0 == "ufw").unwrap();
    let (_, _, intervalle_audit, sonde_audit, evenementiel_audit) = COLLECTORS.iter().find(|c| c.0 == "audit").unwrap();
    assert!(*evenementiel_ufw && !*evenementiel_audit, "axes attendus : ufw événementiel, audit continu");

    // ufw (événementiel), pipeline frais : un aveu seul -> « inconnu », jamais « actif ».
    let conn = test_db();
    t2_insere(&conn, T2_MAINTENANT - 10, "ufw", "config", Some(T2_AVEU_LIB_SH));
    let ls = sonde_ufw.derniere_collecte(&conn).unwrap();
    let st = statut_capteur(ls, *intervalle_ufw, *evenementiel_ufw, true, CYCLES_TOLERES_ALERTE, T2_MAINTENANT);
    assert_eq!(st, StatutCapteur::Inconnu, "ufw aveugle qui l'avoue : pas « actif »");

    // audit (continu) : dernier événement réel au-delà de la tolérance, aveu récent -> « muet ».
    let conn = test_db();
    let hors_tolerance = intervalle_audit * CYCLES_TOLERES_ALERTE + 1;
    t2_insere(&conn, T2_MAINTENANT - hors_tolerance, "auditd", "exec", None);
    t2_insere(&conn, T2_MAINTENANT - 10, "auditd", "config", Some(&t2_aveu("auditd", "unavailable")));
    let ls = sonde_audit.derniere_collecte(&conn).unwrap();
    assert_eq!(ls, Some(T2_MAINTENANT - hors_tolerance), "l'aveu ne remet pas l'âge à zéro");
    let st = statut_capteur(ls, *intervalle_audit, *evenementiel_audit, true, CYCLES_TOLERES_ALERTE, T2_MAINTENANT);
    assert_eq!(st, StatutCapteur::Muet, "auditd tu depuis plus de la tolérance, qui avoue : muet");

    // audit, aveu récent SEUL : « inconnu », jamais « actif ».
    let conn = test_db();
    t2_insere(&conn, T2_MAINTENANT - 10, "auditd", "config", Some(&t2_aveu("auditd", "unavailable")));
    let ls = sonde_audit.derniere_collecte(&conn).unwrap();
    let st = statut_capteur(ls, *intervalle_audit, *evenementiel_audit, true, CYCLES_TOLERES_ALERTE, T2_MAINTENANT);
    assert_eq!(st, StatutCapteur::Inconnu);
}

/// Coût compté par SQLite (`SQLITE_STMTSTATUS_VM_STEP`, déterministe), comme `sondes_cout.rs`.
fn t2_cout_vm(conn: &Connection, sonde: &Sonde) -> i64 {
    let r = sonde.requete();
    let mut s = conn.prepare(r.sql()).expect("la sonde émet un SQL valide");
    let _: Option<i64> = s.query_row(rusqlite::params_from_iter(r.binds().iter()), |row| row.get(0)).unwrap_or(None);
    s.get_status(rusqlite::StatementStatus::VmStep) as i64
}

fn t2_base_cout(n: i64) -> Connection {
    let conn = test_db();
    conn.execute_batch("BEGIN").unwrap();
    // FLUX : n lignes réelles par source, qui suivent la mutation du volume.
    for i in 0..n {
        for (s, c) in [("ufw", "firewall"), ("auditd", "exec"), ("sshd", "auth"), ("sudo", "auth")] {
            t2_insere(&conn, T2_MAINTENANT - 100_000 + i, s, c, None);
        }
    }
    // AVEUX : nombre FIXE, tous POSTÉRIEURS au flux réel (le cas qui oblige la sonde à les remonter).
    for j in 0..24i64 {
        for s in ["ufw", "auditd", "sshd", "sudo"] {
            t2_insere(&conn, T2_MAINTENANT - 50 + j, s, "config", Some(&t2_aveu(s, "unavailable")));
        }
    }
    conn.execute_batch("COMMIT").unwrap();
    conn.execute_batch("ANALYZE").unwrap();
    conn
}

#[test]
fn p10_32s_le_cout_ne_suit_pas_le_volume_et_le_plan_reste_un_seek() {
    let petite = t2_base_cout(2_000);
    let grande = t2_base_cout(8_000);
    for id in ["ufw", "audit", "journal"] {
        let sonde = t2_sonde(id);
        assert_eq!(sonde.derniere_collecte(&petite).unwrap(), Some(T2_MAINTENANT - 100_000 + 1_999), "{id} : valeur");
        assert_eq!(sonde.derniere_collecte(&grande).unwrap(), Some(T2_MAINTENANT - 100_000 + 7_999), "{id} : valeur");
        let (a, b) = (t2_cout_vm(&petite, sonde), t2_cout_vm(&grande, sonde));
        assert_eq!(a, b, "{id} : volume x4, aveux fixes -> le coût ne doit pas bouger ({a} -> {b})");
        let r = sonde.requete();
        let plan: String = petite
            .prepare(&format!("EXPLAIN QUERY PLAN {}", r.sql()))
            .unwrap()
            .query_map(rusqlite::params_from_iter(r.binds().iter()), |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .join(" | ");
        assert!(plan.contains("idx_event_src_ts") && plan.contains("SEARCH") && !plan.contains("SCAN"), "{id} : plan = {plan}");
        assert_eq!(r.cout(), Cout::IndexCouvrant("idx_event_src_ts"), "{id} : coût déclaré");
    }
}

#[test]
fn p10_32s_la_sonde_lit_chaque_aveu_posterieur() {
    // Coût de la sonde `ufw` pour 0, 24, 48 aveux postérieurs au dernier événement réel : LINÉAIRE,
    // pente exacte (le compteur de VM steps est déterministe). C'est la dimension que `sondes_cout` ne
    // fait pas varier ; la doc de `EST_SIGNE_DE_VIE` cite cette pente.
    let cout = |aveux: i64| {
        let conn = test_db();
        for i in 0..50 {
            t2_insere(&conn, T2_MAINTENANT - 100_000 + i, "ufw", "firewall", None);
        }
        for j in 0..aveux {
            t2_insere(&conn, T2_MAINTENANT - 1_000 + j, "ufw", "config", Some(&t2_aveu("ufw", "unavailable")));
        }
        assert_eq!(t2_sonde("ufw").derniere_collecte(&conn).unwrap(), Some(T2_MAINTENANT - 100_000 + 49));
        t2_cout_vm(&conn, t2_sonde("ufw"))
    };
    let (c0, c24, c48) = (cout(0), cout(24), cout(48));
    assert!(c24 > c0, "la sonde LIT chaque aveu postérieur ({c0} -> {c24})");
    assert_eq!(c48 - c24, c24 - c0, "pente constante par aveu ({c0}, {c24}, {c48})");
    eprintln!("P10.32-s : sonde ufw, {} VM steps par aveu postérieur (base {c0})", (c24 - c0) / 24);
}

// ------------------------------------------------------------------------------------------------
// FRAÎCHEUR ET /api/sources — `event_rollup.last_ts` compte l'aveu ; corrigé par un SEEK plafonné.
// ------------------------------------------------------------------------------------------------

use crate::handlers::freshness::CHAMP_DERNIERE_COLLECTE_AU_DELA_DES_LIGNES;
use crate::sondes::{derniere_collecte_hors_aveu, requete_hors_aveu, DerniereCollecteHorsAveu, LIGNES_HORS_AVEU_MAX};

fn t2_flux<'a>(corps: &'a Value, nom: &str) -> Option<&'a Value> {
    corps["feeds"].as_array()?.iter().find(|f| f["kind"] == json!("event") && f["name"] == json!(nom))
}

fn t2_source<'a>(corps: &'a Value, nom: &str) -> Option<&'a Value> {
    corps["sources"].as_array()?.iter().find(|f| f["source"] == json!(nom))
}

fn t2_last_du_rollup(st: &AppState, source: &str) -> i64 {
    st.db.lock().query_row("SELECT MAX(last_ts) FROM event_rollup WHERE source=?1", params![source], |r| r.get(0)).unwrap()
}

#[tokio::test]
async fn p10_32s_fraicheur_et_sources_ne_rajeunissent_pas_sur_un_aveu() {
    // Le cas du vérificateur : auditd, dernier événement réel il y a deux heures, aveu il y a 30 s.
    let (st, p) = sp_state("t2-fraicheur-aveu");
    let n = now();
    {
        let w = st.db.lock();
        for i in 0..3 {
            t2_insere(&w, n - 7_200 - i, "auditd", "exec", None);
        }
        t2_insere(&w, n - 30, "auditd", "config", Some(&t2_aveu("auditd", "unavailable")));
        rollup_events(&w);
    }
    assert_eq!(t2_last_du_rollup(&st, "auditd"), n - 30, "fixture : le rollup, lui, a pris l'aveu");
    let f = compute_freshness(&p, None);
    let a = t2_flux(&f, "auditd").unwrap_or_else(|| panic!("auditd listé : {f}"));
    assert_eq!(a["last_seen"], json!(n - 7_200), "Fraîcheur : le dernier événement RÉEL, pas l'aveu : {a}");
    assert_ne!(a["status"], json!("frais"), "deux heures sans collecte ne font pas « frais » : {a}");
    assert!(f.get("non_lus").is_none() && f.get("error").is_none(), "correction établie : rien à avouer : {f}");
    // Les trois surfaces disent la même chose.
    assert_eq!(t2_sonde("audit").derniere_collecte(&st.db.lock()).unwrap(), Some(n - 7_200));
    let inv = is_inventaire(&st, &sp_au("adm", "admin")).await;
    let s = t2_source(&inv, "auditd").unwrap_or_else(|| panic!("auditd à l'inventaire : {inv}"));
    assert_eq!(s["last_seen"], json!(n - 7_200), "/api/sources : idem : {s}");
    assert_ne!(s["status"], json!("frais"), "{s}");
}

#[tokio::test]
async fn p10_32s_que_des_aveux_n_est_pas_une_collecte_et_le_nominal_ne_bouge_pas() {
    let (st, p) = sp_state("t2-fraicheur-que-des-aveux");
    let n = now();
    {
        let w = st.db.lock();
        for (k, age) in [30i64, 3_630, 7_230].into_iter().enumerate() {
            t2_insere(&w, n - age - k as i64, "ufw", "config", Some(T2_AVEU_LIB_SH));
        }
        for i in 0..3 {
            t2_insere(&w, n - 10 - i, "web", "web", None);
        }
        rollup_events(&w);
    }
    let f = compute_freshness(&p, None);
    assert!(t2_flux(&f, "ufw").is_none(), "que des aveux sur la fenêtre : pas listé, comme une source tue : {f}");
    let web = t2_flux(&f, "web").unwrap_or_else(|| panic!("contrôle positif : web listé : {f}"));
    assert_eq!(web["last_seen"], json!(t2_last_du_rollup(&st, "web")), "nominal : le `last` du rollup, tel quel : {web}");
    assert_eq!(web["status"], json!("frais"), "{web}");
    assert!(f.get("non_lus").is_none() && f.get("error").is_none(), "nominal muet : {f}");
    let inv = is_inventaire(&st, &sp_au("adm", "admin")).await;
    let u = t2_source(&inv, "ufw").unwrap_or_else(|| panic!("ufw reste à l'inventaire : {inv}"));
    assert_eq!(u["status"], json!("dormant"), "/api/sources : la forme « aucune donnée observée » : {u}");
    assert_eq!(u["last_seen"], Value::Null, "{u}");
    assert_eq!(u["n_24h"], json!(3), "RESTE assumé : le volume du rollup compte encore les aveux : {u}");

    // BYTE-IDENTIQUE : une ligne RÉELLE plus récente que la dernière passe du rollup ne change pas le
    // `last` servi (la correction ne remplace le rollup que par un instant plus ANCIEN).
    let l_web = t2_last_du_rollup(&st, "web");
    t2_insere(&st.db.lock(), n - 1, "web", "web", None);
    let f = compute_freshness(&p, None);
    assert_eq!(t2_flux(&f, "web").unwrap()["last_seen"], json!(l_web), "le rollup reste la source du `last` nominal : {f}");
    let inv = is_inventaire(&st, &sp_au("adm", "admin")).await;
    assert_eq!(t2_source(&inv, "web").unwrap()["last_seen"], json!(l_web), "{inv}");
}

#[tokio::test]
async fn p10_32s_au_plafond_un_fait_borne_et_le_rollup_seul_est_garde() {
    // `P10.32-s` (reprise) — AU PLAFOND, « aucun signe de vie dans les N dernières lignes » est un FAIT
    // BORNÉ : la source est listée avec la BORNE (plus ancienne ligne lue) pour `last_seen`, le champ du
    // fait, un statut ni `frais` ni `non_lu`, et RIEN à la racine (ni `non_lus`, ni `error`).
    let (st, p) = sp_state("t2-fraicheur-plafond");
    let n = now();
    let bucket = (n / 3_600 - 48) * 3_600;
    {
        let w = st.db.lock();
        // PLAFOND : un événement réel, puis plus d'aveux que `LIGNES_HORS_AVEU_MAX`.
        t2_insere(&w, n - 90_000, "ufw", "firewall", None);
        w.execute_batch("BEGIN").unwrap();
        for j in 0..(LIGNES_HORS_AVEU_MAX + 76) {
            t2_insere(&w, n - 2_000 + j, "ufw", "config", Some(&t2_aveu("ufw", "unavailable")));
        }
        w.execute_batch("COMMIT").unwrap();
        rollup_events(&w);
        // ROLLUP SEUL : la fenêtre d'`event` est vide pour cette source (rétention plus courte que le rollup).
        w.execute(
            "INSERT INTO event_rollup(bucket,source,severity,action,n,last_ts) VALUES(?1,'rollup-seul',1,'',5,?2)",
            params![bucket, bucket + 10],
        )
        .unwrap();
    }
    // La plus ancienne des `LIGNES_HORS_AVEU_MAX` lignes lues à reculons : l'aveu d'indice 76.
    let borne = n - 2_000 + 76;
    assert!(borne < t2_last_du_rollup(&st, "ufw"), "fixture : la borne précède le `last` (aveu) du rollup");
    let f = compute_freshness(&p, None);
    let u = t2_flux(&f, "ufw").unwrap_or_else(|| panic!("plafond : listé, pas retiré : {f}"));
    assert_eq!(u["last_seen"], json!(borne), "la BORNE, jamais le `last` du rollup que l'aveu a rajeuni : {u}");
    assert_eq!(u[CHAMP_DERNIERE_COLLECTE_AU_DELA_DES_LIGNES], json!(LIGNES_HORS_AVEU_MAX), "le fait borné est servi : {u}");
    // Statut EXACT, pas « ni frais ni non_lu » : la borne a ~32 min et le dernier point de la base ~15 min
    // (pipeline périmé), `frais` y est inatteignable — une assertion « jamais frais » serait vacante ici
    // (elle est jugée par `p10_32s_une_borne_recente_ne_fait_pas_frais_sur_les_deux_surfaces`). Ce qui se
    // juge ici : `muet` est MAINTENU sur la borne (l'âge vrai dépasse ce que la borne dépasse déjà).
    assert_eq!(u["status"], json!("muet"), "pipeline périmé : `muet` maintenu sur la borne, ni `non_lu` ni `calme` : {u}");
    assert!(u.get("derniere_collecte_non_etablie").is_none(), "{u}");
    assert!(f.get("non_lus").is_none() && f.get("error").is_none(), "un fait borné n'est pas une lecture ratée : {f}");
    let r = t2_flux(&f, "rollup-seul").unwrap_or_else(|| panic!("rollup seul : gardé : {f}"));
    assert_eq!(r["last_seen"], json!(bucket + 10), "{r}");
    let inv = is_inventaire(&st, &sp_au("adm", "admin")).await;
    let u = t2_source(&inv, "ufw").unwrap();
    assert_eq!(u["last_seen"], json!(borne), "{u}");
    assert_eq!(u[CHAMP_DERNIERE_COLLECTE_AU_DELA_DES_LIGNES], json!(LIGNES_HORS_AVEU_MAX), "{u}");
    assert_eq!(u["status"], json!("muet"), "/api/sources : `muet` maintenu sur la borne, ni `non_lu` ni `dormant` : {u}");
    assert!(u.get("derniere_collecte_non_etablie").is_none(), "{u}");
    assert_eq!(t2_source(&inv, "rollup-seul").unwrap()["last_seen"], json!(bucket + 10), "{inv}");
}

#[test]
fn p10_32s_sans_l_index_la_correction_refuse_au_lieu_de_balayer() {
    let (st, p) = sp_state("t2-fraicheur-sans-index");
    let n = now();
    {
        let w = st.db.lock();
        for i in 0..3 {
            t2_insere(&w, n - 10 - i, "web", "web", None);
        }
        rollup_events(&w);
        w.execute_batch("DROP INDEX idx_event_src_ts").unwrap();
    }
    let f = compute_freshness(&p, None);
    let web = t2_flux(&f, "web").unwrap_or_else(|| panic!("listé : {f}"));
    assert_eq!(web["status"], json!(STATUT_DE_SOURCE_NON_LU), "sans index : non établi, pas un balayage : {web}");
    assert!(web["derniere_collecte_non_etablie"].to_string().contains("idx_event_src_ts"), "{web}");
    // (e) Une lecture RÉELLEMENT ratée reste dite à la racine, et n'est pas un fait borné.
    assert!(f["non_lus"].to_string().contains("web") && f["error"].is_string(), "{f}");
    assert!(web.get(CHAMP_DERNIERE_COLLECTE_AU_DELA_DES_LIGNES).is_none(), "{web}");
}

#[test]
fn p10_32s_la_correction_est_plafonnee_et_reste_un_seek() {
    let base = |aveux: i64| {
        let conn = test_db();
        conn.execute_batch("BEGIN").unwrap();
        t2_insere(&conn, T2_MAINTENANT - 100_000, "ufw", "firewall", None);
        for j in 0..aveux {
            t2_insere(&conn, T2_MAINTENANT - 50_000 + j, "ufw", "config", Some(&t2_aveu("ufw", "unavailable")));
        }
        conn.execute_batch("COMMIT").unwrap();
        conn
    };
    let pas = |conn: &Connection| -> i64 {
        let mut s = conn.prepare(&requete_hors_aveu("")).unwrap();
        let mut l = s.query(params!["ufw", LIGNES_HORS_AVEU_MAX]).unwrap();
        while l.next().unwrap().is_some() {}
        drop(l);
        s.get_status(rusqlite::StatementStatus::VmStep) as i64
    };
    let (petite, grande) = (base(LIGNES_HORS_AVEU_MAX + 100), base(4 * (LIGNES_HORS_AVEU_MAX + 100)));
    // Au plafond : une BORNE, la plus ancienne ligne lue (aveux posés à `T - 50_000 + j`, lus à reculons).
    for (c, aveux) in [(&petite, LIGNES_HORS_AVEU_MAX + 100), (&grande, 4 * (LIGNES_HORS_AVEU_MAX + 100))] {
        assert_eq!(
            derniere_collecte_hors_aveu(c, "ufw", "").unwrap(),
            DerniereCollecteHorsAveu::AuDela { lues: LIGNES_HORS_AVEU_MAX, plus_ancien_ts: T2_MAINTENANT - 50_000 + aveux - LIGNES_HORS_AVEU_MAX }
        );
    }
    let (a, b) = (pas(&petite), pas(&grande));
    assert_eq!(a, b, "aveux x4 : coût plafonné, constant ({a} -> {b})");
    // Sous le plafond, le dernier réel est trouvé ; une seule ligne lue s'il est en tête.
    let peu = base(10);
    assert_eq!(derniere_collecte_hors_aveu(&peu, "ufw", "").unwrap(), DerniereCollecteHorsAveu::Vue(T2_MAINTENANT - 100_000));
    t2_insere(&peu, T2_MAINTENANT - 5, "ufw", "firewall", Some("pas{du json"));
    assert_eq!(derniere_collecte_hors_aveu(&peu, "ufw", "").unwrap(), DerniereCollecteHorsAveu::Vue(T2_MAINTENANT - 5));
    let plan: String = petite
        .prepare(&format!("EXPLAIN QUERY PLAN {}", requete_hors_aveu("")))
        .unwrap()
        .query_map(params!["ufw", LIGNES_HORS_AVEU_MAX], |row| row.get::<_, String>(3))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .join(" | ");
    assert!(plan.contains("idx_event_src_ts") && !plan.contains("SCAN") && !plan.contains("TEMP B-TREE"), "plan = {plan}");
}

// ------------------------------------------------------------------------------------------------
// La correction n'a PAS de borne de date, elle suit le filtre d'environnement, et son prédicat est
// jugé À CE SITE (Fraîcheur et /api/sources), pas seulement par la sonde de flux.
// ------------------------------------------------------------------------------------------------

fn t2_insere_env(conn: &Connection, ts: i64, source: &str, category: &str, fields: Option<&str>, env: &str) {
    conn.prepare_cached(
        "INSERT INTO event(ts,source,category,severity,host,message,fields,env_id) VALUES(?1,?2,?3,2,'machine0','m',?4,?5)",
    )
    .unwrap()
    .execute(params![ts, source, category, fields, env])
    .unwrap();
}

#[tokio::test]
async fn p10_32s_un_dernier_reel_anterieur_a_la_fenetre_est_servi_en_retard() {
    // Un capteur aveugle depuis huit jours qui avoue chaque heure : son dernier événement réel précède
    // la fenêtre de l'inventaire. Il est servi avec CET âge — « en retard » — ni retiré de Fraîcheur, ni
    // « dormant » dans /api/sources : un aveu n'est pas un signe de vie, ET l'aveuglement se voit.
    let (st, p) = sp_state("t2-avant-la-fenetre");
    let n = now();
    let ancien = n - crate::handlers::freshness::FENETRE_INVENTAIRE_S - 86_400;
    {
        let w = st.db.lock();
        t2_insere(&w, ancien, "ufw", "firewall", None);
        for (k, age) in [30i64, 3_630, 7_230].into_iter().enumerate() {
            t2_insere(&w, n - age - k as i64, "ufw", "config", Some(T2_AVEU_LIB_SH));
        }
        for i in 0..3 {
            t2_insere(&w, n - 10 - i, "web", "web", None);
        }
        rollup_events(&w);
    }
    let f = compute_freshness(&p, None);
    let u = t2_flux(&f, "ufw").unwrap_or_else(|| panic!("l'aveuglement se voit : ufw listé dans Fraîcheur : {f}"));
    assert_eq!(u["last_seen"], json!(ancien), "Fraîcheur : le VRAI dernier événement réel, d'avant la fenêtre : {u}");
    assert_eq!(u["status"], json!("en_retard"), "{u}");
    assert!(f.get("non_lus").is_none() && f.get("error").is_none(), "établi : rien à avouer : {f}");
    let inv = is_inventaire(&st, &sp_au("adm", "admin")).await;
    let s = t2_source(&inv, "ufw").unwrap_or_else(|| panic!("ufw à l'inventaire : {inv}"));
    assert_eq!(s["last_seen"], json!(ancien), "/api/sources : idem, pas « dormant » : {s}");
    assert_eq!(s["status"], json!("en_retard"), "{s}");
}

#[test]
fn p10_32s_multi_environnement_une_ligne_d_un_autre_environnement_ne_rajeunit_pas() {
    let (st, p) = sp_state("t2-multi-env");
    let n = now();
    {
        let w = st.db.lock();
        for i in 0..3 {
            t2_insere_env(&w, n - 7_200 - i, "ufw", "firewall", None, "staging");
            t2_insere_env(&w, n - 60 - i, "ufw", "firewall", None, "prod");
            t2_insere_env(&w, n - 10 - i, "web", "web", None, "staging");
        }
        t2_insere_env(&w, n - 30, "ufw", "config", Some(T2_AVEU_LIB_SH), "staging");
        rollup_events(&w);
    }
    let f = compute_freshness(&p, Some("staging"));
    let u = t2_flux(&f, "ufw").unwrap_or_else(|| panic!("staging : ufw listé : {f}"));
    assert_eq!(u["last_seen"], json!(n - 7_200), "staging : la collecte de PROD (n-60) ne rajeunit pas la source : {u}");
    assert_ne!(u["status"], json!("frais"), "{u}");
    assert!(f.get("non_lus").is_none(), "{f}");
    // Contrôle : en prod, la même source est fraîche sur ses propres lignes.
    let f = compute_freshness(&p, Some("prod"));
    let u = t2_flux(&f, "ufw").unwrap_or_else(|| panic!("prod : ufw listé : {f}"));
    assert_eq!(u["last_seen"], json!(n - 60), "{u}");
}

#[test]
fn p10_32s_multi_environnement_le_plafond_compte_les_lignes_des_autres_environnements() {
    // (d) Plus de `LIGNES_HORS_AVEU_MAX` lignes de PROD au-dessus du dernier réel de staging : le plafond
    // les compte (sinon il ne bornerait plus rien) -> en staging, le FAIT BORNÉ « aucun signe de vie de cet
    // environnement dans les N dernières lignes de la source », jamais un balayage ni une lecture ratée.
    // Source hors `COLLECTORS` (cadence non déclarée) et lignes récentes : la borne a moins de `FRAIS_S`,
    // `statut_de_source` dirait « frais » — que la borne n'établit pas.
    let (st, p) = sp_state("t2-multi-env-plafond");
    let n = now();
    let src = "t2-borne-env";
    {
        let w = st.db.lock();
        for i in 0..3 {
            t2_insere_env(&w, n - 90_000 - i, src, "firewall", None, "staging");
        }
        w.execute_batch("BEGIN").unwrap();
        for j in 0..(LIGNES_HORS_AVEU_MAX + 76) {
            t2_insere_env(&w, n - 400 + j / 4, src, "firewall", None, "prod");
        }
        w.execute_batch("COMMIT").unwrap();
        t2_insere_env(&w, n - 10, src, "config", Some(T2_AVEU_LIB_SH), "staging");
        rollup_events(&w);
    }
    // Lues à reculons : l'aveu de staging, puis les `LIGNES_HORS_AVEU_MAX - 1` lignes de prod les plus récentes.
    let borne = n - 400 + (LIGNES_HORS_AVEU_MAX + 76 - (LIGNES_HORS_AVEU_MAX - 1)) / 4;
    let f = compute_freshness(&p, Some("staging"));
    let u = t2_flux(&f, src).unwrap_or_else(|| panic!("staging : {src} listé : {f}"));
    assert_eq!(u["last_seen"], json!(borne), "staging : la borne, pas le dernier réel de staging (n-90000) : {u}");
    assert_eq!(u[CHAMP_DERNIERE_COLLECTE_AU_DELA_DES_LIGNES], json!(LIGNES_HORS_AVEU_MAX), "{u}");
    assert_eq!(u["status"], json!("calme"), "borne récente : `frais` n'est pas établi, `non_lu` est faux : {u}");
    assert!(f.get("non_lus").is_none() && f.get("error").is_none(), "{f}");
}

#[tokio::test]
async fn p10_32s_le_predicat_est_juge_au_site_de_fraicheur_et_de_l_inventaire() {
    // Chaque cas : trois événements réels il y a deux heures, la ligne du cas il y a dix minutes, un vrai
    // aveu il y a 30 s. Seule la forme complète de l'aveu est sautée : la ligne du cas EST la dernière
    // collecte, sur les DEUX surfaces, et sa lecture ne tombe jamais en « non lu ».
    let cas = [
        ("t2cas-statut-seul", r#"{"collect_status":"unavailable"}"#.to_string()),
        ("t2cas-type-seul", r#"{"type":"collector-availability"}"#.to_string()),
        ("t2cas-disabled", t2_aveu("x", "disabled")),
        ("t2cas-partial", t2_aveu("x", "partial")),
        ("t2cas-fallback", t2_aveu("x", "fallback")),
        // Pas de `fields` non JSON ici : `rollup_events` (json_extract sur `$.action`) lève sur lui et
        // n'agrège plus l'heure chaude ; la garde `json_valid` est jugée par
        // `p10_32s_la_correction_est_plafonnee_et_reste_un_seek`.
    ];
    let (st, p) = sp_state("t2-predicat-au-site");
    let n = now();
    {
        let w = st.db.lock();
        for (src, fields) in &cas {
            for i in 0..3 {
                t2_insere(&w, n - 7_200 - i, src, "firewall", None);
            }
            t2_insere(&w, n - 600, src, "config", Some(fields));
            t2_insere(&w, n - 30, src, "config", Some(&t2_aveu(src, "unavailable")));
        }
        rollup_events(&w);
    }
    let f = compute_freshness(&p, None);
    assert!(f.get("non_lus").is_none() && f.get("error").is_none(), "aucune lecture ratée : {f}");
    let inv = is_inventaire(&st, &sp_au("adm", "admin")).await;
    for (src, fields) in &cas {
        let u = t2_flux(&f, src).unwrap_or_else(|| panic!("{src} listé : {f}"));
        assert_eq!(u["last_seen"], json!(n - 600), "Fraîcheur, {src} ({fields}) : pas un aveu : {u}");
        assert_ne!(u["status"], json!(STATUT_DE_SOURCE_NON_LU), "{u}");
        let s = t2_source(&inv, src).unwrap_or_else(|| panic!("{src} à l'inventaire : {inv}"));
        assert_eq!(s["last_seen"], json!(n - 600), "/api/sources, {src} ({fields}) : {s}");
        assert!(s.get("derniere_collecte_non_etablie").is_none(), "{s}");
    }
}

// ------------------------------------------------------------------------------------------------
// `P10.32-s` (reprise) — AU PLAFOND DE LIGNES, UN FAIT BORNÉ, JAMAIS UNE LECTURE RATÉE.
// ------------------------------------------------------------------------------------------------

fn t2_insere_hote(conn: &Connection, ts: i64, source: &str, category: &str, fields: Option<&str>, hote: &str) {
    conn.prepare_cached(
        "INSERT INTO event(ts,source,category,severity,host,message,fields) VALUES(?1,?2,?3,2,?5,'m',?4)",
    )
    .unwrap()
    .execute(params![ts, source, category, fields, hote])
    .unwrap();
}

#[tokio::test]
async fn p10_32s_deux_hotes_qui_avouent_un_mois_sans_reel_un_fait_borne_sur_les_deux_surfaces() {
    // (a) Le cas de la vérification (vt3_a) : 2 hôtes x 720 aveux horaires, AUCUN événement réel. Avant :
    // `non_lu` sur le flux et une `error` racine « lectures ont échoué », alors que rien n'avait échoué.
    let (st, p) = sp_state("t2-deux-hotes-un-mois");
    let n = now();
    {
        let w = st.db.lock();
        w.execute_batch("BEGIN").unwrap();
        for k in 0..720i64 {
            for (h, hote) in ["machine0", "machine1"].into_iter().enumerate() {
                t2_insere_hote(&w, n - 3_600 * k - h as i64, "ufw", "config", Some(T2_AVEU_LIB_SH), hote);
            }
        }
        w.execute_batch("COMMIT").unwrap();
        rollup_events(&w);
    }
    // La `LIGNES_HORS_AVEU_MAX`-ième ligne à reculons : heure 511, second hôte.
    let borne = n - 3_600 * (LIGNES_HORS_AVEU_MAX / 2 - 1) - 1;
    let f = compute_freshness(&p, None);
    assert!(f.get("non_lus").is_none() && f.get("error").is_none(), "rien n'a échoué : {f}");
    let u = t2_flux(&f, "ufw").unwrap_or_else(|| panic!("Fraîcheur : ufw listé avec sa borne : {f}"));
    assert_eq!(u["last_seen"], json!(borne), "la borne, jamais l'aveu de l'heure (`last` du rollup) : {u}");
    assert_eq!(u[CHAMP_DERNIERE_COLLECTE_AU_DELA_DES_LIGNES], json!(LIGNES_HORS_AVEU_MAX), "{u}");
    // Statut EXACT : la borne a ~21 jours, `frais` y est inatteignable (« jamais frais » serait vacant ;
    // jugé par `p10_32s_une_borne_recente_ne_fait_pas_frais_sur_les_deux_surfaces`). L'aveu de l'heure garde
    // le pipeline frais et `ufw` est observé en continu (`ufw-health`, 300 s) : `en_retard` est MAINTENU.
    assert_eq!(u["status"], json!("en_retard"), "Fraîcheur : aveugle depuis 21 jours, ni `non_lu` ni `calme` : {u}");
    assert!(u.get("derniere_collecte_non_etablie").is_none(), "{u}");
    let inv = is_inventaire(&st, &sp_au("adm", "admin")).await;
    let s = t2_source(&inv, "ufw").unwrap_or_else(|| panic!("ufw à l'inventaire : {inv}"));
    assert_eq!(s["last_seen"], json!(borne), "/api/sources : idem : {s}");
    assert_eq!(s[CHAMP_DERNIERE_COLLECTE_AU_DELA_DES_LIGNES], json!(LIGNES_HORS_AVEU_MAX), "{s}");
    assert_eq!(s["status"], json!("en_retard"), "/api/sources : ni `non_lu`, ni `dormant`, ni `calme` : {s}");
    assert!(s.get("derniere_collecte_non_etablie").is_none(), "{s}");
}

#[test]
fn p10_32s_un_reel_juste_au_dela_du_plafond_est_borne_juste_en_deca_il_est_vu() {
    // (b) EXACTEMENT `LIGNES_HORS_AVEU_MAX` aveux au-dessus du dernier réel : il est la ligne suivante, hors
    // lecture -> même verdict borné qu'une source sans réel. (c) Un aveu de moins : le réel est la dernière
    // ligne lue -> servi tel quel, sans champ de fait.
    for (tag, aveux) in [("t2-au-dela", LIGNES_HORS_AVEU_MAX), ("t2-en-deca", LIGNES_HORS_AVEU_MAX - 1)] {
        let (st, p) = sp_state(tag);
        let n = now();
        {
            let w = st.db.lock();
            t2_insere(&w, n - 90_000, "ufw", "firewall", None);
            w.execute_batch("BEGIN").unwrap();
            for j in 0..aveux {
                t2_insere(&w, n - 2_000 + j, "ufw", "config", Some(&t2_aveu("ufw", "unavailable")));
            }
            w.execute_batch("COMMIT").unwrap();
            rollup_events(&w);
        }
        let f = compute_freshness(&p, None);
        assert!(f.get("non_lus").is_none() && f.get("error").is_none(), "{tag} : {f}");
        let u = t2_flux(&f, "ufw").unwrap_or_else(|| panic!("{tag} : listé : {f}"));
        assert_ne!(u["status"], json!(STATUT_DE_SOURCE_NON_LU), "{tag} : {u}");
        if aveux == LIGNES_HORS_AVEU_MAX {
            assert_eq!(u["last_seen"], json!(n - 2_000), "{tag} : borne = le plus ancien aveu lu : {u}");
            assert_eq!(u[CHAMP_DERNIERE_COLLECTE_AU_DELA_DES_LIGNES], json!(LIGNES_HORS_AVEU_MAX), "{tag} : {u}");
        } else {
            assert_eq!(u["last_seen"], json!(n - 90_000), "{tag} : le réel, dans la lecture : {u}");
            assert!(u.get(CHAMP_DERNIERE_COLLECTE_AU_DELA_DES_LIGNES).is_none(), "{tag} : {u}");
        }
    }
}

#[tokio::test]
async fn p10_32s_une_borne_recente_ne_fait_pas_frais_sur_les_deux_surfaces() {
    // Plus de `LIGNES_HORS_AVEU_MAX` aveux en quelques minutes (flotte nombreuse), aucun réel, source hors
    // `COLLECTORS` (cadence non déclarée) : la borne a moins de `FRAIS_S`, `statut_de_source` dirait
    // « frais ». La borne MINORE l'âge vrai : `frais` n'est pas établi -> `calme`, sur les DEUX surfaces.
    let (st, p) = sp_state("t2-borne-recente");
    let n = now();
    let src = "t2-borne-recente";
    {
        let w = st.db.lock();
        w.execute_batch("BEGIN").unwrap();
        for j in 0..(LIGNES_HORS_AVEU_MAX + 76) {
            t2_insere_hote(&w, n - 400 + j / 4, src, "config", Some(T2_AVEU_LIB_SH), &format!("machine{}", j % 50));
        }
        w.execute_batch("COMMIT").unwrap();
        rollup_events(&w);
    }
    let borne = n - 400 + (LIGNES_HORS_AVEU_MAX + 76 - LIGNES_HORS_AVEU_MAX) / 4;
    let f = compute_freshness(&p, None);
    let u = t2_flux(&f, src).unwrap_or_else(|| panic!("{src} listé : {f}"));
    assert_eq!(u["last_seen"], json!(borne), "{u}");
    assert_eq!(u["status"], json!("calme"), "Fraîcheur : {u}");
    let inv = is_inventaire(&st, &sp_au("adm", "admin")).await;
    let s = t2_source(&inv, src).unwrap_or_else(|| panic!("{src} à l'inventaire : {inv}"));
    assert_eq!(s["last_seen"], json!(borne), "{s}");
    assert_eq!(s["status"], json!("calme"), "/api/sources : {s}");
}

// ------------------------------------------------------------------------------------------------
// `P10.32-s` (correction après vérification) — LES BRANCHES QUE RIEN NE JUGEAIT : le `min` de la borne,
// `en_retard` maintenu au plafond avec un pipeline frais, la lecture ratée de `/api/sources`.
// ------------------------------------------------------------------------------------------------

#[tokio::test]
async fn p10_32s_la_borne_ne_prend_jamais_l_instant_d_une_ligne_qui_n_est_pas_de_cette_source() {
    // `borne = min(last du rollup, plus ancienne ligne lue)`. Le `min` compte quand la lecture entière est
    // PLUS RÉCENTE que le `last` du rollup : sans lui, la borne serait l'instant d'une ligne qui ne dit rien
    // de cette source (sous filtre : une ligne d'un AUTRE environnement ; sans filtre : un aveu ingéré
    // depuis la dernière passe du rollup), et la source RAJEUNIRAIT de deux heures.
    let (st, p) = sp_state("t2-borne-min");
    let n = now();
    let (env_src, nominal_src, ingere_src) = ("t2-min-env", "t2-min-env-nominal", "t2-min-ingere");
    {
        let w = st.db.lock();
        // Sous filtre : 3 réels de staging il y a deux heures, puis plus que le plafond de lignes de prod.
        for i in 0..3 {
            t2_insere_env(&w, n - 7_200 - i, env_src, "firewall", None, "staging");
            t2_insere_env(&w, n - 300 - i, nominal_src, "firewall", None, "staging");
        }
        w.execute_batch("BEGIN").unwrap();
        for j in 0..(LIGNES_HORS_AVEU_MAX + 76) {
            t2_insere_env(&w, n - 400 + j / 4, env_src, "firewall", None, "prod");
            t2_insere_env(&w, n - 200 + j / 8, nominal_src, "firewall", None, "prod");
        }
        w.execute_batch("COMMIT").unwrap();
        // Sans filtre : 3 réels il y a deux heures, passés au rollup...
        for i in 0..3 {
            t2_insere(&w, n - 7_200 - i, ingere_src, "firewall", None);
        }
        rollup_events(&w);
        // ... puis plus que le plafond d'aveux, ingérés APRÈS la dernière passe du rollup.
        w.execute_batch("BEGIN").unwrap();
        for j in 0..(LIGNES_HORS_AVEU_MAX + 76) {
            t2_insere_hote(&w, n - 400 + j / 4, ingere_src, "config", Some(T2_AVEU_LIB_SH), &format!("machine{}", j % 50));
        }
        w.execute_batch("COMMIT").unwrap();
    }
    assert_eq!(t2_last_du_rollup(&st, ingere_src), n - 7_200, "fixture : les aveux sont postérieurs à la passe du rollup");

    let f = compute_freshness(&p, Some("staging"));
    let u = t2_flux(&f, env_src).unwrap_or_else(|| panic!("staging : {env_src} listé : {f}"));
    assert_eq!(u["last_seen"], json!(n - 7_200), "staging : jamais l'instant d'une ligne de PROD (n-400 et après) : {u}");
    assert_eq!(u[CHAMP_DERNIERE_COLLECTE_AU_DELA_DES_LIGNES], json!(LIGNES_HORS_AVEU_MAX), "{u}");
    assert_eq!(u["status"], json!("calme"), "{u}");
    // LE RESTE DIT (doc de `last_du_rollup_hors_aveu`) : sous filtre, une source SANS AUCUN aveu, recouverte
    // par plus que le plafond de lignes d'un autre environnement, est servie en borne. `last_seen` exact,
    // mais `calme` au lieu de `frais`, et le champ du fait posé.
    let v = t2_flux(&f, nominal_src).unwrap_or_else(|| panic!("staging : {nominal_src} listé : {f}"));
    assert_eq!(v["last_seen"], json!(n - 300), "le `last` du rollup de staging, exact : {v}");
    assert_eq!(v["status"], json!("calme"), "reste dit : sous filtre, la borne ne fait pas `frais` : {v}");
    assert_eq!(v[CHAMP_DERNIERE_COLLECTE_AU_DELA_DES_LIGNES], json!(LIGNES_HORS_AVEU_MAX), "{v}");
    assert!(f.get("non_lus").is_none() && f.get("error").is_none(), "{f}");
    // Contrôle : sans filtre, la même source est servie par le chemin nominal, sans borne.
    let f0 = compute_freshness(&p, None);
    let v0 = t2_flux(&f0, nominal_src).unwrap_or_else(|| panic!("mode 0 : {nominal_src} listé : {f0}"));
    assert_eq!(v0["status"], json!("frais"), "mode 0 : chemin nominal : {v0}");
    assert!(v0.get(CHAMP_DERNIERE_COLLECTE_AU_DELA_DES_LIGNES).is_none(), "{v0}");

    // Sans filtre, sur les DEUX surfaces : le `last` du rollup, pas l'aveu le plus ancien de la lecture.
    let g = t2_flux(&f0, ingere_src).unwrap_or_else(|| panic!("mode 0 : {ingere_src} listé : {f0}"));
    assert_eq!(g["last_seen"], json!(n - 7_200), "Fraîcheur : jamais l'instant d'un aveu (n-381) : {g}");
    assert_eq!(g[CHAMP_DERNIERE_COLLECTE_AU_DELA_DES_LIGNES], json!(LIGNES_HORS_AVEU_MAX), "{g}");
    let inv = is_inventaire(&st, &sp_au("adm", "admin")).await;
    let s = t2_source(&inv, ingere_src).unwrap_or_else(|| panic!("{ingere_src} à l'inventaire : {inv}"));
    assert_eq!(s["last_seen"], json!(n - 7_200), "/api/sources : idem : {s}");
    assert_eq!(s[CHAMP_DERNIERE_COLLECTE_AU_DELA_DES_LIGNES], json!(LIGNES_HORS_AVEU_MAX), "{s}");
}

#[tokio::test]
async fn p10_32s_au_plafond_avec_un_pipeline_frais_en_retard_est_maintenu_sur_les_deux_surfaces() {
    // `ufw` est observé en continu (`ufw-health`, 300 s) ; son dernier réel a 25 h, plus que le plafond
    // d'aveux au-dessus ; d'autres sources gardent le pipeline frais. La borne (~32 min) dépasse déjà
    // 3 x 300 s : l'âge vrai aussi -> `en_retard`, jamais adouci en `calme` (ni `frais`, ni `non_lu`).
    let (st, p) = sp_state("t2-borne-en-retard");
    let n = now();
    {
        let w = st.db.lock();
        t2_insere(&w, n - 90_000, "ufw", "firewall", None);
        w.execute_batch("BEGIN").unwrap();
        for j in 0..(LIGNES_HORS_AVEU_MAX + 76) {
            t2_insere(&w, n - 2_000 + j, "ufw", "config", Some(&t2_aveu("ufw", "unavailable")));
        }
        w.execute_batch("COMMIT").unwrap();
        for i in 0..3 {
            t2_insere(&w, n - 10 - i, "web", "web", None);
        }
        rollup_events(&w);
    }
    let borne = n - 2_000 + 76;
    let f = compute_freshness(&p, None);
    let u = t2_flux(&f, "ufw").unwrap_or_else(|| panic!("ufw listé : {f}"));
    assert_eq!(u["last_seen"], json!(borne), "{u}");
    assert_eq!(u[CHAMP_DERNIERE_COLLECTE_AU_DELA_DES_LIGNES], json!(LIGNES_HORS_AVEU_MAX), "{u}");
    assert_eq!(u["status"], json!("en_retard"), "Fraîcheur : {u}");
    assert!(f.get("non_lus").is_none() && f.get("error").is_none(), "{f}");
    let inv = is_inventaire(&st, &sp_au("adm", "admin")).await;
    let s = t2_source(&inv, "ufw").unwrap_or_else(|| panic!("ufw à l'inventaire : {inv}"));
    assert_eq!(s["last_seen"], json!(borne), "{s}");
    assert_eq!(s[CHAMP_DERNIERE_COLLECTE_AU_DELA_DES_LIGNES], json!(LIGNES_HORS_AVEU_MAX), "{s}");
    assert_eq!(s["status"], json!("en_retard"), "/api/sources : {s}");
}

#[tokio::test]
async fn p10_32s_sans_l_index_l_inventaire_dit_non_lu_au_lieu_du_rollup() {
    // (e) sur `/api/sources` : une lecture RÉELLEMENT ratée (index absent -> préparation refusée) sert le
    // `last` du rollup AVEC son aveu — `non_lu` et la cause — jamais le statut tiré du rollup seul.
    let (st, _p) = sp_state("t2-inventaire-sans-index");
    let n = now();
    {
        let w = st.db.lock();
        for i in 0..3 {
            t2_insere(&w, n - 10 - i, "web", "web", None);
        }
        rollup_events(&w);
        w.execute_batch("DROP INDEX idx_event_src_ts").unwrap();
    }
    let l_web = t2_last_du_rollup(&st, "web");
    let inv = is_inventaire(&st, &sp_au("adm", "admin")).await;
    let s = t2_source(&inv, "web").unwrap_or_else(|| panic!("web à l'inventaire : {inv}"));
    assert_eq!(s["status"], json!(STATUT_DE_SOURCE_NON_LU), "sans index : non lu, pas `frais` tiré du rollup : {s}");
    assert!(s["derniere_collecte_non_etablie"].to_string().contains("idx_event_src_ts"), "la cause est dite : {s}");
    assert_eq!(s["last_seen"], json!(l_web), "le `last` du rollup, tel quel, à côté de l'aveu : {s}");
    assert!(s.get(CHAMP_DERNIERE_COLLECTE_AU_DELA_DES_LIGNES).is_none(), "une lecture ratée n'est pas un fait borné : {s}");
}
