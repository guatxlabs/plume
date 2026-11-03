// =====================================================================================
// `P10.29-l` — LES SIX LIGNES `[cache]` DU PRÉ-CHAUFFAGE NOMMENT LE TENANT.
// `P10.20-b` — UN PLANCHER DES LIGNES TARDIVES NON LU NE PUBLIE JAMAIS UNE COUVERTURE QUI LES COMPTE.
//
// MESURÉ SUR LA BASE DE LA VAGUE BG (lecture du source) :
//  * `rollups::cache_refresh_all_panels` ne recevait pas le tenant : la boucle qui l'appelle
//    (`server/boucles_de_fond.rs`, `spawn_panel_refresh_loop`) jetait `_tid`. Ses six lignes `[cache] WARN pré-chauffage du
//    panneau {id} en échec (…) — …` ne disaient pas de quelle base venait l'échec — en mode 1, deux tenants ont chacun
//    leur panneau `#1`.
//  * `rollups::rollup_events`, rollup par dimension : `if let Ok(Some(t)) = conn.query_row("SELECT MIN(ts) FROM event NOT
//    INDEXED WHERE id>?1 …")`, sans branche `Err`. Une lecture ratée laissait le haut de la bande en place, la bande
//    n'était pas ré-agrégée, et `DimRollupCoverage::publish(conn, down_lo, up_hi, recent, dim_at_id)` — borne
//    d'identifiant FRAÎCHE — déclarait couvertes les lignes tardives que le rollup ne porte pas : la route servait des
//    comptes amputés sur la bande témoignée.
//
// LE CORRECTIF :
//  * `cache_refresh_all_panels(…, tenant)` ; `server::boucles_de_fond::prechauffer_les_panneaux_de_chaque_tenant` (le
//    corps de la boucle, sorti pour être joué ici) passe `tid` ; chaque ligne porte `, tenant {:?}` après la cause ;
//  * plancher des retardataires NON LU -> pris au pire : la bande se rétracte à son plancher (`band_hi = band_lo`), la
//    remontée la reconstruit, la couverture publiée ne témoigne que des tranches ré-agrégées ce passage ; ligne
//    `[rollup] WARN plancher des lignes tardives du rollup par dimension NON lu (…)`.
//
// CE QUE CES TÉMOINS JUGENT :
//  (A) `bg4_prechauffage_nomme_le_tenant_a_chaque_ligne_deux_tenants`, en sous-processus (journal capturé), MODE 1, DEUX
//      tenants réels créés par `tenant_create`, par le SITE RÉEL (`prechauffer_les_panneaux_de_chaque_tenant`, qui
//      parcourt `for_each_active_tenant`) : sur chaque tenant, un panneau en échec par issue de
//      `joindre_l_echec_a_la_charge_valide` — aucune charge, charge jointe, charge dont `stats` n'est pas un objet, charge
//      plus récente que la tentative, ligne ILLISIBLE (BLOB), ligne NON LUE (autorisateur) — soit douze lignes, chacune
//      comparée ENTIÈRE, et aucune autre ligne pour ces panneaux. Chaque ligne lue au compteur est jouée seule (un tour
//      par ligne) : le rang « lecture de cache ratée n° N » ne dépend pas de l'ordre des tenants.
//  (B) `bg4_plancher_des_retardataires_non_lu_retracte_la_bande`, en sous-processus : bande établie sur trois jours (le
//      tour sans retardataire ne rétracte rien : `Ok(None)`), lignes tardives posées dans la bande, lecture du plancher
//      INTERROMPUE par l'instrument `rollups::temoin_du_plancher_des_retardataires` (rappel de progression, la requête de
//      production s'exécute) ; la couverture publiée vaut EXACTEMENT `[plancher, plancher + pas)`, ce qu'elle témoigne est
//      égal au brut, le bucket tardif est hors de la bande ; puis, instrument levé, la remontée ré-agrège tout ; journal :
//      UNE ligne, entière.
// MUTANTS JOUÉS (variable d'environnement de mutation lue sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE :
// BG4_BOUCLE_TENANT_FIGE (la boucle passe "default"), BG4_CACHE_ILLISIBLE_SANS_TENANT (une des six lignes sans le
// tenant), BG4_CACHE_TENANT_NON_ECHAPPE (`{}` au lieu de `{:?}` sur une ligne), BG4_TARDIF_ERR_AVALE (le `Err` ne
// rétracte rien, l'ancien comportement), BG4_TARDIF_SANS_JOURNAL (la ligne `[rollup]` retirée), BG4_TARDIF_NONE_RETRACTE
// (`Ok(None)` rétracte aussi).
// CE QUE CES TÉMOINS NE TIENNENT PAS : le pas de la remontée est le défaut (`PLUME_ROLLUP_DIM_BACKFILL` non posé) ; la
// ligne `[rollup]` ne nomme pas le tenant (`rollup_events` ne le reçoit pas, comme ses lignes voisines).
// =====================================================================================
mod prechauffage_nomme_le_tenant_et_plancher_des_retardataires_non_lu {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const BG4_ENFANT_A: &str = "BG4_ENFANT_PRECHAUFFAGE_NOMME_LE_TENANT";
    const BG4_ENFANT_B: &str = "BG4_ENFANT_PLANCHER_DES_RETARDATAIRES";
    const BG4_ATTENDU: &str = "BG4-ATTENDU:";
    const BG4_FIN: &str = "BG4-FIN:";
    const BG4_ALPHA: &str = "bg4-alpha";
    const BG4_BETA: &str = "bg4-beta";
    /// Compile (SQL natif, aucune table), échoue à l'exécution (JSON malformé lu par le moteur).
    const BG4_SQL_EN_PANNE: &str = "SELECT json_extract('{pas du json','$.a') AS a";
    const BG4_ILLISIBLE: &str = "Invalid column type Blob at index: 0, name: payload";
    const BG4_REFUS: &str = "access to panel_cache.payload is prohibited [code étendu 23]";
    const BG4_STATS_PAS_UN_OBJET: &str = "`stats` de la charge utile n'est pas un objet";
    const BG4_INTERROMPU: &str = "interrupted";

    fn bg4_issue(conn: &Connection, id: i64, rk: &str, fp: &str) -> &'static str {
        match panneau_avoue::cache_lire_dit(conn, id, rk, fp) {
            panneau_avoue::LectureDeCache::Lue(..) => "Lue",
            panneau_avoue::LectureDeCache::Absente => "Absente",
            panneau_avoue::LectureDeCache::Illisible(_) => "Illisible",
            panneau_avoue::LectureDeCache::NonLue(_) => "NonLue",
        }
    }

    fn bg4_ligne(id: i64, cause: &str, t: &str, suite: &str) -> String {
        format!("[cache] WARN pré-chauffage du panneau {id} en échec ({cause}), tenant \"{t}\" — {suite}")
    }

    /// Les six panneaux en échec d'un tenant, dans l'ordre : aucune, jointe, non jointe, plus récente, illisible, non lue.
    struct Bg4Tenant {
        t: &'static str,
        handle: Arc<Mutex<Connection>>,
        ids: [i64; 6],
        cause: String,
    }

    fn bg4_preparer(st: &AppState, t: &'static str, rk: &str, fp: &str) -> Bg4Tenant {
        let handle = st.tenants.handle_for(t).expect("contrôle : base du tenant");
        let ids = {
            let conn = handle.lock();
            // Les panneaux semés par les migrations quittent le pré-chauffage : seuls ceux du témoin s'exécutent.
            conn.execute("UPDATE panel SET panel_cache_ttl_s=0", []).expect("fixture : panneaux semés hors du pré-chauffage");
            conn.execute("INSERT INTO dashboard(name,owner,visibility) VALUES('bg4','root','shared')", []).expect("fixture : tableau");
            let did = conn.last_insert_rowid();
            let mut ids = [0i64; 6];
            for slot in ids.iter_mut() {
                conn.execute("INSERT INTO panel(dashboard_id,title,query,is_soql,viz) VALUES(?1,'bg4',?2,0,'table')", params![did, BG4_SQL_EN_PANNE])
                    .expect("fixture : panneau");
                *slot = conn.last_insert_rowid();
            }
            let n = now();
            let poser = |id: i64, calcule_a: i64, payload: &str| {
                conn.execute(
                    "INSERT OR REPLACE INTO panel_cache(panel_id,range_key,query_fp,computed_at,payload) VALUES(?1,?2,?3,?4,?5)",
                    params![id, rk, fp, calcule_a, payload],
                )
                .expect("fixture : ligne de cache");
            };
            poser(ids[1], n - 1_000, &json!({ "columns": ["a"], "rows": [[1]] }).to_string());
            poser(ids[2], n - 1_000, &json!({ "columns": [], "rows": [], "stats": 5 }).to_string());
            poser(ids[3], n + 100_000, &json!({ "columns": ["a"], "rows": [[1]] }).to_string());
            conn.execute(
                "INSERT OR REPLACE INTO panel_cache(panel_id,range_key,query_fp,computed_at,payload) VALUES(?1,?2,?3,?4,X'00FF')",
                params![ids[4], rk, fp, n - 5],
            )
            .expect("fixture : ligne BLOB");
            poser(ids[5], n - 1_000, &json!({ "columns": ["a"], "rows": [[1]] }).to_string());
            ids
        };
        // La cause au journal, par le même chemin que le pré-chauffage (compilation, exécution classée, `au_journal`).
        let dbp = st.tenants.ready_db_path(t).expect("contrôle : chemin de la base du tenant");
        let from = now() - 86_400;
        let pc = panneau_avoue::compile_panneau_avoue(BG4_SQL_EN_PANNE, false, from, 0, None).expect("précondition : le SQL compile");
        let echec = crate::query_exec::en_classant(|| panneau_avoue::executer(&dbp, &load_config(), pc, from))
            .err()
            .unwrap_or_else(|| panic!("précondition {t} : l'exécution échoue"));
        let cause = crate::handlers::dashboards::EchecMisEnCache::de_la_requete(echec).au_journal().to_string();
        Bg4Tenant { t, handle, ids, cause }
    }

    /// Ne laisse au pré-chauffage que les panneaux `garder` des tenants `bases` (TTL nul pour les autres panneaux du témoin).
    fn bg4_seulement(bases: &[&Bg4Tenant], garder: &[(usize, usize)]) {
        for (b, base) in bases.iter().enumerate() {
            let conn = base.handle.lock();
            for (k, id) in base.ids.iter().enumerate() {
                let ttl: Option<i64> = if garder.contains(&(b, k)) { None } else { Some(0) };
                conn.execute("UPDATE panel SET panel_cache_ttl_s=?1 WHERE id=?2", params![ttl, id]).expect("fixture : TTL");
            }
        }
    }

    fn bg4_refuser(handle: &Arc<Mutex<Connection>>) {
        handle.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name: "panel_cache", column_name: "payload" } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn bg4_permettre(handle: &Arc<Mutex<Connection>>) {
        handle.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    #[tokio::test]
    async fn bg4_prechauffage_nomme_le_tenant_a_chaque_ligne_deux_tenants() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // cache_refresh_all_panels lit load_config()
        if std::env::var(BG4_ENFANT_A).is_ok() {
            let (st, _dir) = mk_mode1_state();
            for t in [BG4_ALPHA, BG4_BETA] {
                let r = tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(au_super("op-bg4")), Json(json!({ "id": t, "name": t })))
                    .await;
                assert_eq!(r.status().as_u16(), 201, "contrôle : tenant {t} créé");
            }
            let rk = cache_range_key(now() - 86_400, 0, now());
            let fp = query_fingerprint(BG4_SQL_EN_PANNE, false);
            let alpha = bg4_preparer(&st, BG4_ALPHA, &rk, &fp);
            let beta = bg4_preparer(&st, BG4_BETA, &rk, &fp);
            let bases = [&alpha, &beta];
            for b in bases {
                let conn = b.handle.lock();
                let issues: Vec<&str> = b.ids.iter().map(|id| bg4_issue(&conn, *id, &rk, &fp)).collect();
                assert_eq!(issues, vec!["Absente", "Lue", "Lue", "Lue", "Illisible", "Lue"], "fixture {} : issues de départ", b.t);
            }
            let mut attendus = Vec::new();
            // Tour 1 : les quatre issues sans compteur, sur les deux tenants à la fois.
            bg4_seulement(&bases, &[(0, 0), (0, 1), (0, 2), (0, 3), (1, 0), (1, 1), (1, 2), (1, 3)]);
            crate::server::boucles_de_fond::prechauffer_les_panneaux_de_chaque_tenant(&st.tenants, &st.refresh_sem);
            for b in bases {
                attendus.push(bg4_ligne(b.ids[0], &b.cause, b.t, "rien d'écrit, le chemin à la demande retentera"));
                attendus.push(bg4_ligne(b.ids[1], &b.cause, b.t, "charge utile précédente conservée, échec joint au corps servi"));
                attendus.push(bg4_ligne(
                    b.ids[2],
                    &b.cause,
                    b.t,
                    &format!("charge utile précédente conservée, échec NON joint au corps servi ({BG4_STATS_PAS_UN_OBJET})"),
                ));
                attendus.push(bg4_ligne(b.ids[3], &b.cause, b.t, "charge utile calculée après cette tentative conservée, rien d'écrit"));
            }
            // Tours 2 à 5 : chaque ligne lue au compteur, seule.
            for (b, base) in bases.iter().enumerate() {
                bg4_seulement(&bases, &[(b, 4)]);
                let rang = panneau_avoue::lectures_de_cache_refusees() + 1;
                crate::server::boucles_de_fond::prechauffer_les_panneaux_de_chaque_tenant(&st.tenants, &st.refresh_sem);
                attendus.push(bg4_ligne(
                    base.ids[4],
                    &base.cause,
                    base.t,
                    &format!(
                        "ligne de cache ILLISIBLE (lue, non décodable) : {BG4_ILLISIBLE} (lecture de cache ratée n° {rang} depuis le \
                         démarrage) — rien d'écrit, le chemin à la demande la remplacera"
                    ),
                ));
            }
            for (b, base) in bases.iter().enumerate() {
                bg4_seulement(&bases, &[(b, 5)]);
                let rang = panneau_avoue::lectures_de_cache_refusees() + 1;
                bg4_refuser(&base.handle);
                crate::server::boucles_de_fond::prechauffer_les_panneaux_de_chaque_tenant(&st.tenants, &st.refresh_sem);
                bg4_permettre(&base.handle);
                attendus.push(bg4_ligne(
                    base.ids[5],
                    &base.cause,
                    base.t,
                    &format!("ligne de cache NON LUE : {BG4_REFUS} (lecture de cache ratée n° {rang} depuis le démarrage) — rien d'écrit"),
                ));
            }
            for b in bases {
                for (k, id) in b.ids.iter().enumerate() {
                    println!("BG4-PANNEAU:{}|{id}|{k}", b.t);
                }
            }
            for l in &attendus {
                println!("{BG4_ATTENDU}{l}");
            }
            println!("{BG4_FIN} {}", attendus.len());
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .env(BG4_ENFANT_A, "1")
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::prechauffage_nomme_le_tenant_et_plancher_des_retardataires_non_lu::bg4_prechauffage_nomme_le_tenant_a_chaque_ligne_deux_tenants",
            ])
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "l'enfant prépare chaque issue et sort en 0 : {stdout}\n{stderr}");
        assert!(stdout.contains(&format!("{BG4_FIN} 12")), "contrôle : douze lignes attendues (six issues, deux tenants) : {stdout}");
        let mut attendus: Vec<String> = stdout.lines().filter_map(|l| l.split_once(BG4_ATTENDU).map(|(_, r)| r.to_string())).collect();
        assert!(attendus.len() >= 12, "plancher : douze lignes attendues ({})", attendus.len());
        // Les panneaux du témoin, par tenant : une ligne `[cache]` de l'un d'eux qui ne serait pas attendue rougit aussi.
        let panneaux: Vec<(String, String)> = stdout
            .lines()
            .filter_map(|l| l.split_once("BG4-PANNEAU:").map(|(_, r)| r))
            .filter_map(|r| {
                let mut it = r.split('|');
                Some((it.next()?.to_string(), it.next()?.to_string()))
            })
            .collect();
        assert!(panneaux.len() >= 12, "plancher : six panneaux par tenant ({})", panneaux.len());
        let mut journal: Vec<String> = stderr
            .lines()
            .filter(|l| l.starts_with("[cache] WARN pré-chauffage du panneau "))
            .filter(|l| {
                panneaux.iter().any(|(t, id)| {
                    l.starts_with(&format!("[cache] WARN pré-chauffage du panneau {id} en échec (")) && l.contains(&format!("tenant \"{t}\""))
                }) || !l.contains("tenant \"")
            })
            .map(str::to_string)
            .collect();
        journal.sort();
        attendus.sort();
        assert_eq!(journal, attendus, "chaque ligne `[cache]`, entière, nomme le tenant de sa base :\n{stderr}");
        for l in &journal {
            assert!(!l.contains(BG4_SQL_EN_PANNE), "jamais la requête au journal : {l}");
        }
    }

    // ---------------------------------------------------------------------------------
    // (B) LE PLANCHER DES RETARDATAIRES NON LU.
    // ---------------------------------------------------------------------------------

    fn bg4_bucket(ts: i64) -> i64 {
        (ts / 3600) * 3600
    }

    fn bg4_semer(c: &Connection, ts: i64, val: &str, n: usize, tag: &str) {
        for i in 0..n {
            c.execute(
                "INSERT INTO event(ts,source,fields,dedup) VALUES(?1,'web',?2,?3)",
                params![ts, format!("{{\"status\":\"{val}\"}}"), format!("bg4-{tag}-{i}")],
            )
            .expect("fixture : event");
        }
    }

    /// Ce que le rollup par dimension porte pour `web`/`status` sur `[lo, hi)` (buckets).
    fn bg4_rollup(c: &Connection, lo: i64, hi: i64) -> i64 {
        c.query_row(
            "SELECT COALESCE(SUM(n),0) FROM event_dim_rollup WHERE source='web' AND dim='status' AND bucket>=?1 AND bucket<?2",
            params![lo, hi],
            |r| r.get(0),
        )
        .expect("lecture du rollup")
    }

    /// L'oracle : ce qu'`event` porte pour `web` sur `[lo, hi)`.
    fn bg4_brut(c: &Connection, lo: i64, hi: i64) -> i64 {
        c.query_row("SELECT COUNT(*) FROM event WHERE source='web' AND ts>=?1 AND ts<?2", params![lo, hi], |r| r.get(0)).expect("lecture d'event")
    }

    #[test]
    fn bg4_plancher_des_retardataires_non_lu_retracte_la_bande() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // rollup_events lit load_config() (pas de la remontée)
        if std::env::var(BG4_ENFANT_B).is_ok() {
            let conn = test_db();
            let recent = bg4_bucket(now()) - 3600;
            for h in 1..=72 {
                bg4_semer(&conn, recent - h * 3600 + 61, if h % 2 == 0 { "200" } else { "404" }, 2, &format!("h{h}"));
            }
            for _ in 0..6 {
                rollup_events(&conn);
            }
            let (plancher, haut, _) = DimRollupCoverage::of(&conn).band().expect("socle : couverture établie");
            assert_eq!(plancher, bg4_bucket(recent - 72 * 3600 + 61), "socle : la bande descend jusqu'au plus vieil event");
            assert_eq!(bg4_rollup(&conn, plancher, haut), bg4_brut(&conn, plancher, haut), "socle : bande à jour");
            // `Ok(None)` : aucune retardataire, un tour de plus ne rétracte rien — la bande reste contiguë à la bande
            // volatile (`below == hot_from`), plancher gardé.
            rollup_events(&conn);
            let (p1, h1, c1) = DimRollupCoverage::of(&conn).band().expect("couverture republiée");
            assert_eq!((p1, h1), (plancher, c1), "sans retardataire, la bande garde son plancher et monte jusqu'à la bande volatile");
            // Les retardataires : DANS la bande, sous le haut, après la publication.
            let tardif = recent - 6 * 3600 + 77;
            bg4_semer(&conn, tardif, "500", 5, "tardif");
            crate::rollups::temoin_du_plancher_des_retardataires::armer();
            rollup_events(&conn);
            crate::rollups::temoin_du_plancher_des_retardataires::desarmer();
            let (de, sous, chaud2) = DimRollupCoverage::of(&conn).band().expect("une couverture est publiée sur les tranches ré-agrégées");
            assert_eq!((de, sous), (plancher, (plancher + 86_400).min(chaud2)), "la bande s'est rétractée à son plancher, plus un pas de remontée");
            assert!(bg4_bucket(tardif) >= sous, "le bucket des retardataires n'est pas témoigné ({} >= {sous})", bg4_bucket(tardif));
            assert_eq!(bg4_rollup(&conn, de, sous), bg4_brut(&conn, de, sous), "ce que la couverture témoigne est égal au brut");
            // Contre-épreuve : instrument levé, la remontée reconstruit la bande, retardataires compris.
            for _ in 0..4 {
                rollup_events(&conn);
            }
            let (p2, h2, _) = DimRollupCoverage::of(&conn).band().expect("couverture reconstruite");
            assert!(p2 <= plancher && h2 > bg4_bucket(tardif), "la bande couvre de nouveau les retardataires ({p2}, {h2})");
            assert_eq!(bg4_rollup(&conn, p2, h2), bg4_brut(&conn, p2, h2), "retardataires ré-agrégés");
            println!("{BG4_FIN} B");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .env(BG4_ENFANT_B, "1")
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::prechauffage_nomme_le_tenant_et_plancher_des_retardataires_non_lu::bg4_plancher_des_retardataires_non_lu_retracte_la_bande",
            ])
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "l'enfant juge la bande et sort en 0 : {stdout}\n{stderr}");
        assert!(stdout.contains(&format!("{BG4_FIN} B")), "contrôle : l'enfant a conclu : {stdout}");
        let journal: Vec<&str> = stderr.lines().filter(|l| l.contains("plancher des lignes tardives")).collect();
        let attendue = format!(
            "[rollup] WARN plancher des lignes tardives du rollup par dimension NON lu ({BG4_INTERROMPU}) — bande rétractée à son \
             plancher, reconstruite par la remontée ; la couverture publiée ne témoigne que des tranches ré-agrégées ce passage"
        );
        assert_eq!(journal, vec![attendue.as_str()], "une ligne, entière, au seul tour où la lecture a raté :\n{stderr}");
    }
}
