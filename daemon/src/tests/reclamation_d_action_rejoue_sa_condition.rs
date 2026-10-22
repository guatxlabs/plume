// =====================================================================================
// `P10.21-n` (reste) — L'UPDATE DE RÉCLAMATION D'UN AGENT REJOUE LA CONDITION DE SA LECTURE.
//
// LE DÉFAUT MESURÉ SUR LE SITE (`handlers/actions.rs::actions_pending`, arbre `7ecbec19`, ligne 545) :
// `UPDATE action SET claimed_ts=?2, host=?3 WHERE id=?1`, sans aucune des clauses du SELECT qui a lu
// l'action (`status='approved'`, `kind IN ('ban_ip','unban_ip')`, fenêtre `claimed_ts`, condition
// d'hôte). Entre la lecture et l'écriture, une autre connexion pouvait annuler l'action, la clore, ou la
// réclamer pour un autre agent (action non assignée) : l'UPDATE rendait quand même `Ok(1)`, attribuait
// l'action à cet hôte par-dessus l'autre, et la ligne partait dans le TSV — double exécution d'un ban ou
// d'une levée, ou exécution d'une riposte annulée.
//
// CE QUE CES TÉMOINS TIENNENT, sur `remettre_les_actions_lues` (le point d'entrée qu'appelle
// `actions_pending`), avec DEUX connexions sur le même fichier : la connexion A lit, la connexion B
// modifie l'action, puis A réclame. Une scène par clause, chacune n'en faisant tomber QU'UNE (statut,
// genre, fenêtre, hôte), plus la scène réelle (un autre agent réclame l'action non assignée) : l'action
// n'est pas remise et l'état posé par B reste intact. Une course perdue ne vaut pas anomalie (rien à
// réclamer, pas le 503) ; une réclamation sans effet dont la condition tient encore, ou dont la
// relecture échoue, reste une anomalie. L'équivalence SELECT/UPDATE sur soixante-douze états. Le journal
// de la course perdue (identifiant, jamais la cible) sur le stderr d'un sous-processus.
//
// MUTANTS JOUÉS (VERIF_MUT, retirés avant le commit), chacun vu ROUGE : `aa1_sans_statut`,
// `aa1_sans_genre`, `aa1_sans_fenetre`, `aa1_sans_hote`, `aa1_course_perdue_en_anomalie`,
// `aa1_sans_effet_en_course_perdue`, `aa1_relecture_ratee_en_course_perdue`.
//
// CE QU'ILS NE TIENNENT PAS : la fenêtre `RECLAMATION_PERIMEE_S` (non mesurée), une riposte ré-exécutée
// après l'abandon de son verdict côté agent, et `action_result` — hors de ce lot.
// =====================================================================================

type RrcLigne = (i64, String, String, bool);

const RRC_HOTE: &str = "hote-rrc";

/// Base fichier à migrations complètes : deux actions approuvées, la 1 ciblée sur l'hôte, la 2 NON
/// ASSIGNÉE (host NULL). Rend l'état (connexion A = `st.db`) et le chemin (pour ouvrir B).
fn rrc_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
    let (st, p) = sp_state(&format!("rrc-{tag}"));
    st.db
        .lock()
        .execute_batch(
            "INSERT INTO action(id,ts,kind,target,status,dry_run,host) VALUES(1,1,'ban_ip','203.0.113.1','approved',1,'hote-rrc');\
             INSERT INTO action(id,ts,kind,target,status,dry_run,host) VALUES(2,2,'unban_ip','203.0.113.2','approved',0,NULL);",
        )
        .unwrap();
    (st, p)
}

/// La lecture de A : la condition du PRODUIT (`CONDITION_DE_RECLAMATION_D_AGENT`), pas une recopie.
fn rrc_lire(conn: &Connection, maintenant: i64) -> Vec<RrcLigne> {
    let sql = format!(
        "SELECT id,kind,target,dry_run FROM action WHERE {} ORDER BY id",
        crate::handlers::actions::CONDITION_DE_RECLAMATION_D_AGENT
    );
    let mut s = conn.prepare(&sql).unwrap();
    s.query_map(params![RRC_HOTE, maintenant, crate::handlers::actions::RECLAMATION_PERIMEE_S], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get::<_, i64>(3)? != 0))
    })
    .unwrap()
    .collect::<rusqlite::Result<Vec<_>>>()
    .unwrap()
}

/// (status, kind, claimed_ts, host) de l'action `id`.
fn rrc_ligne(conn: &Connection, id: i64) -> (String, String, Option<i64>, Option<String>) {
    conn.query_row("SELECT status,kind,claimed_ts,host FROM action WHERE id=?1", [id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
}

/// LA SCÈNE ENTRELACÉE : A lit, B écrit `sql_b` (sur une connexion distincte au même fichier ; `?1` =
/// maintenant), A réclame.
/// Rend la réponse de la réclamation et l'état de l'action `id` vu par B avant puis après la réclamation.
fn rrc_scene(tag: &str, id: i64, sql_b: &str) -> (Result<String, &'static str>, (String, String, Option<i64>, Option<String>), (String, String, Option<i64>, Option<String>)) {
    let (st, p) = rrc_etat(tag);
    let maintenant = now();
    let a = st.db.lock();
    let lues = rrc_lire(&a, maintenant);
    assert!(lues.iter().any(|l| l.0 == id), "contrôle {tag} : A a bien LU l'action {id} avant l'écriture de B : {lues:?}");
    let b = open_db(&p).unwrap();
    let ecrit = if sql_b.contains("?1") { b.execute(sql_b, params![maintenant]) } else { b.execute(sql_b, []) };
    ecrit.unwrap_or_else(|e| panic!("contrôle {tag} : B écrit `{sql_b}` ({e})"));
    let avant = rrc_ligne(&b, id);
    let rendu = crate::handlers::actions::remettre_les_actions_lues(&a, &lues.into_iter().filter(|l| l.0 == id).collect::<Vec<_>>(), RRC_HOTE, maintenant);
    let apres = rrc_ligne(&b, id);
    (rendu, avant, apres)
}

fn rrc_juger_non_remise(tag: &str, scene: (Result<String, &'static str>, (String, String, Option<i64>, Option<String>), (String, String, Option<i64>, Option<String>))) {
    let (rendu, avant, apres) = scene;
    assert_eq!(rendu, Ok(String::new()), "{tag} : l'action n'est plus réclamable, elle n'est PAS remise — et ce n'est pas le 503 (rien à réclamer)");
    assert_eq!(apres, avant, "{tag} : la réclamation n'a RIEN écrit par-dessus l'état posé par l'autre connexion");
}

#[test]
fn p10_21n_reclamation_entrelacee_action_annulee_n_est_pas_remise() {
    // Seule la clause de statut tombe : l'action reste ciblée sur cet hôte, jamais réclamée.
    rrc_juger_non_remise("annulée", rrc_scene("annulee", 1, "UPDATE action SET status='cancelled' WHERE id=1"));
    rrc_juger_non_remise("close", rrc_scene("close", 1, "UPDATE action SET status='done', done_ts=?1 WHERE id=1"));
}

#[test]
fn p10_21n_reclamation_entrelacee_genre_change_n_est_pas_remise() {
    rrc_juger_non_remise("genre", rrc_scene("genre", 1, "UPDATE action SET kind='isolate_host' WHERE id=1"));
}

#[test]
fn p10_21n_reclamation_entrelacee_deja_reclamee_dans_la_fenetre_n_est_pas_remise() {
    // Seule la fenêtre tombe : même hôte (un second tour concurrent du même agent), réclamée à l'instant.
    rrc_juger_non_remise("fenêtre", rrc_scene("fenetre", 1, "UPDATE action SET claimed_ts=?1 WHERE id=1"));
}

#[test]
fn p10_21n_reclamation_entrelacee_attribuee_a_un_autre_hote_n_est_pas_remise() {
    // Seule la clause d'hôte tombe : l'action non assignée est attribuée ailleurs, sans réclamation.
    rrc_juger_non_remise("hôte", rrc_scene("hote", 2, "UPDATE action SET host='autre-hote' WHERE id=2"));
}

#[test]
fn p10_21n_reclamation_entrelacee_un_autre_agent_a_reclame_l_action_non_assignee() {
    // La scène réelle : un autre agent a réclamé l'action non assignée entre la lecture et l'écriture.
    let scene = rrc_scene("autre-agent", 2, "UPDATE action SET claimed_ts=?1, host='autre-hote' WHERE id=2");
    assert_eq!(scene.1 .3.as_deref(), Some("autre-hote"), "contrôle : l'autre agent tient l'action");
    rrc_juger_non_remise("autre agent", scene);
}

#[test]
fn p10_21n_course_perdue_sur_une_ligne_de_deux_seule_l_autre_part() {
    let (st, p) = rrc_etat("mixte");
    let maintenant = now();
    let a = st.db.lock();
    let lues = rrc_lire(&a, maintenant);
    assert_eq!(lues.len(), 2, "contrôle : les deux actions lues");
    open_db(&p).unwrap().execute("UPDATE action SET status='cancelled' WHERE id=1", []).unwrap();
    let rendu = crate::handlers::actions::remettre_les_actions_lues(&a, &lues, RRC_HOTE, maintenant);
    assert_eq!(rendu, Ok("2\tunban_ip\t203.0.113.2\t0\n".to_string()), "l'annulée ne part pas, l'autre est remise");
    assert_eq!(rrc_ligne(&a, 1), ("cancelled".into(), "ban_ip".into(), None, Some(RRC_HOTE.into())));
    assert_eq!(rrc_ligne(&a, 2), ("approved".into(), "unban_ip".into(), Some(maintenant), Some(RRC_HOTE.into())));
}

/// Une réclamation SANS EFFET (déclencheur `RAISE(IGNORE)`) dont la condition tient encore n'est pas une
/// course perdue : anomalie, cause du 503.
#[test]
fn p10_21n_reclamation_sans_effet_condition_encore_vraie_reste_une_anomalie() {
    let (st, _p) = rrc_etat("sans-effet");
    let maintenant = now();
    let a = st.db.lock();
    let lues = rrc_lire(&a, maintenant);
    a.execute_batch("CREATE TRIGGER rrc_sans_effet BEFORE UPDATE ON action BEGIN SELECT RAISE(IGNORE); END;").unwrap();
    let rendu = crate::handlers::actions::remettre_les_actions_lues(&a, &lues, RRC_HOTE, maintenant);
    assert_eq!(rendu, Err(crate::handlers::actions::CAUSE_REMISE_D_ACTIONS_NON_RECLAMEE));
}

/// La relecture de la condition qui ÉCHOUE n'est jamais lue « plus réclamable » : anomalie, 503. Le refus
/// vise les seuls SELECT de premier niveau (`accessor` vide) : le SELECT du déclencheur, compilé avec
/// l'UPDATE, passe, donc l'UPDATE rend bien `Ok(0)` et c'est la RELECTURE qui échoue.
#[test]
fn p10_21n_relecture_ratee_de_la_condition_reste_une_anomalie() {
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    let (st, _p) = rrc_etat("relecture");
    let maintenant = now();
    let a = st.db.lock();
    let lues = rrc_lire(&a, maintenant);
    a.execute_batch("CREATE TRIGGER rrc_sans_effet BEFORE UPDATE ON action BEGIN SELECT RAISE(IGNORE); END;").unwrap();
    a.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
        AuthAction::Select if ctx.accessor.is_none() => Authorization::Deny,
        _ => Authorization::Allow,
    }));
    let controle = a.execute("UPDATE action SET claimed_ts=1 WHERE id=1", []);
    let rendu = crate::handlers::actions::remettre_les_actions_lues(&a, &lues, RRC_HOTE, maintenant);
    a.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
    assert_eq!(controle.ok(), Some(0), "instrument : sous le refus, l'UPDATE passe et reste sans effet");
    assert_eq!(rendu, Err(crate::handlers::actions::CAUSE_REMISE_D_ACTIONS_NON_RECLAMEE));
}

/// L'ÉQUIVALENCE : sur soixante-douze états (statut x genre x hôte x réclamation), l'action que
/// `actions_pending` SERT est exactement celle que `remettre_les_actions_lues` RÉCLAME quand on lui
/// présente la ligne comme lue — la condition de l'UPDATE est celle du SELECT, ni plus large ni plus
/// étroite. Et l'une et l'autre suivent la règle écrite ici en Rust.
#[tokio::test]
async fn p10_21n_condition_de_l_update_equivaut_a_celle_du_select() {
    let maintenant = now();
    let recente = maintenant - 1;
    let perimee = maintenant - crate::handlers::actions::RECLAMATION_PERIMEE_S - 100;
    let mut etats: Vec<(i64, &str, &str, Option<&str>, Option<i64>)> = Vec::new();
    let mut id = 0i64;
    for statut in ["approved", "cancelled", "done"] {
        for genre in ["ban_ip", "isolate_host"] {
            for hote in [Some(RRC_HOTE), None, Some(""), Some("autre-hote")] {
                for reclamee in [None, Some(recente), Some(perimee)] {
                    id += 1;
                    etats.push((id, statut, genre, hote, reclamee));
                }
            }
        }
    }
    assert_eq!(etats.len(), 72, "contrôle : sous la borne de 100 du SELECT");
    let poser = |st: &AppState| {
        let c = st.db.lock();
        for (id, statut, genre, hote, reclamee) in &etats {
            c.execute(
                "INSERT INTO action(id,ts,kind,target,status,dry_run,host,claimed_ts) VALUES(?1,?1,?2,?3,?4,1,?5,?6)",
                params![id, genre, format!("198.51.100.{id}"), statut, hote, reclamee],
            )
            .unwrap();
        }
    };
    let (st_servi, _p1) = sp_state("rrc-equiv-servi");
    let (st_reclame, _p2) = sp_state("rrc-equiv-reclame");
    poser(&st_servi);
    poser(&st_reclame);
    let agent = AuthUser {
        name: RRC_HOTE.into(), role: "agent".into(), tenant: "default".into(), is_superadmin: false,
        method: "token".into(), csrf: String::new(), env: None,
    };
    let r = actions_pending(State(st_servi.clone()), Extension(agent)).await;
    assert_eq!(r.status().as_u16(), 200);
    let corps = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
    let servis: std::collections::BTreeSet<i64> =
        String::from_utf8_lossy(&corps).lines().map(|l| l.split('\t').next().unwrap().parse().unwrap()).collect();
    let toutes: Vec<RrcLigne> = etats.iter().map(|(id, _, g, _, _)| (*id, g.to_string(), format!("198.51.100.{id}"), true)).collect();
    let tsv = crate::handlers::actions::remettre_les_actions_lues(&st_reclame.db.lock(), &toutes, RRC_HOTE, maintenant).expect("des réclamations écrites");
    let reclamees: std::collections::BTreeSet<i64> = tsv.lines().map(|l| l.split('\t').next().unwrap().parse().unwrap()).collect();
    let attendu: std::collections::BTreeSet<i64> = etats
        .iter()
        .filter(|(_, s, g, h, c)| {
            *s == "approved" && *g == "ban_ip" && matches!(h, None | Some("") | Some(RRC_HOTE)) && c.map_or(true, |c| c == perimee)
        })
        .map(|e| e.0)
        .collect();
    assert_eq!(attendu.len(), 6, "contrôle : trois hôtes admis x deux réclamations admises");
    assert_eq!(servis, attendu, "le SELECT d'actions_pending suit la règle écrite");
    assert_eq!(reclamees, attendu, "l'UPDATE de réclamation suit la MÊME règle que le SELECT");
}

/// La course perdue est DITE au journal : une ligne qui porte l'identifiant et « plus réclamable »,
/// jamais la cible, jamais « sans effet » (ce n'est pas une anomalie). Sur le stderr d'un sous-processus.
#[test]
fn p10_21n_journal_de_la_course_perdue_porte_l_identifiant_jamais_la_cible() {
    const ENFANT: &str = "RRC_ENFANT_JOURNAL";
    if std::env::var(ENFANT).is_ok() {
        let (rendu, _, _) = rrc_scene("journal", 2, "UPDATE action SET claimed_ts=?1, host='autre-hote' WHERE id=2");
        println!("RRC-RENDU:{rendu:?}");
        return;
    }
    let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
        .args(["--exact", "--nocapture", "--test-threads=1", "tests::p10_21n_journal_de_la_course_perdue_porte_l_identifiant_jamais_la_cible"])
        .env(ENFANT, "1")
        .output()
        .expect("ré-exécution du binaire de test");
    let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
    assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
    assert!(stdout.contains("RRC-RENDU:Ok(\"\")"), "contrôle : course perdue, rien remis : {stdout}");
    let lignes: Vec<&str> = stderr.lines().filter(|l| l.starts_with("[actions]")).collect();
    assert_eq!(lignes.len(), 1, "une ligne, ni plus ni moins : {lignes:?}\n{stderr}");
    assert!(lignes[0].starts_with("[actions] action 2 NON REMISE"), "l'identifiant et le geste : {}", lignes[0]);
    assert!(lignes[0].contains("plus réclamable"), "la voie nommée : {}", lignes[0]);
    assert!(!lignes[0].contains("sans effet"), "une course perdue n'est pas une réclamation sans effet : {}", lignes[0]);
    assert!(!lignes[0].contains("203.0.113."), "jamais la cible : {}", lignes[0]);
}
