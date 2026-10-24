// =====================================================================================
// `P10.34-c` (migrations : quatre écritures de `migrate_chain` avalées avant le succès de la chaîne) et `P10.34-f`
// (connecteurs : huit écritures d'état jetées, et le passage raté pris dans une transaction étrangère).
//
// LE DÉFAUT `P10.34-c`, RE-MESURÉ SUR 88afe566 : `daemon/src/migrate.rs` jetait (`let _ = conn.execute(..)`) le `DELETE`
// du watermark `event_rollup_wm` et l'estampille de la v33, et les estampilles des v67 et v77, dans les bras `Ok(())`
// dont le bras `Err` voisin appelle `abort_step`. Un refus laissait la chaîne continuer : l'étape suivante (`migrate_step`)
// restampait une version supérieure, et un watermark périmé restait en place. La cinquième accusation de l'énoncé
// (`CREATE TABLE IF NOT EXISTS host_rollup`) est FAUSSE : son échec est rattrapé par le `?` du remplissage qui lit la
// table (`DELETE FROM host_rollup`), elle n'est pas touchée.
//
// CE QUE CES TÉMOINS TIENNENT (base sur DISQUE migrée, rétrogradée à une version INFÉRIEURE à l'étape, déclencheur
// `RAISE(ABORT)` sur `meta` ciblé sur la clé ou la valeur visée) : `migrate` rend `false`, `schema_version` relue vaut la
// version d'avant (32, 66 ou 76 : la chaîne d'avant allait jusqu'à `CODE_SCHEMA_MAX`), la seule ligne `[migration]` du
// passage est l'échec de l'étape (comparée en entier, cause et version relue), aucun « schéma -> vN ». OBSERVÉ, et dit
// par les témoins : ces écritures ne sont dans AUCUNE transaction — la table recréée (v33, v67) et le remplissage (v77)
// restent ; le watermark est effacé quand seule l'estampille v33 est refusée. Le déclencheur retiré, le passage suivant
// rejoue l'étape et va au bout (`CODE_SCHEMA_MAX`).
//
// LE DÉFAUT `P10.34-f`, RE-MESURÉ SUR 88afe566 : `daemon/src/handlers/connectors/mod.rs` jetait HUIT `UPDATE connector`
// (l'énoncé en comptait six aux numéros de 1287fb98 : le type non supporté et l'échec Defender n'y étaient pas) ; et
// `poser_le_passage_rate` écrivait dans la transaction d'un autre geste quand le lot n'était pas pris pour cette raison.
// Ces témoins jouent les points d'entrée du planificateur (`run_due_connectors` pour le panic capturé,
// `poll_one_connector` pour les sept autres) :
//   - nominal, par site : l'état est écrit en UN essai (un succès n'est pas rejoué), aucune ligne `[connecteurs]` ;
//   - `UPDATE` refusé (déclencheur sur `connector`), par site : état d'avant, UNE ligne fixe comparée en entier (ce que le
//     passage a fait, nature du refus), et DEUX essais comptés (autorisateur qui compte la préparation de l'`UPDATE` :
//     l'attente est bornée par ce compte, aucune durée n'est mesurée) ; sur un succès, le lot déjà écrit (événements,
//     indicateurs) reste ;
//   - transaction étrangère pendante sur l'écrivain (lot non pris pour http_pull et Defender, type non supporté, lot TAXII)
//     : AUCUN essai, l'état relu DANS la transaction est celui d'avant (un `UPDATE` entré dans la transaction s'y verrait),
//     et la ligne le dit ; pour TAXII, les indicateurs sont DANS la transaction et disparaissent avec son `ROLLBACK` : la
//     ligne dit « lot posé dans cette transaction, non acquis », jamais « lot écrit » ;
//   - panic capturé : après un `BEGIN` ouvert PENDANT le passage (crochet qui ouvre la transaction puis panique, comme un
//     panic dans `ingest_events_batch_env` après son `BEGIN`), la transaction est annulée et l'état écrit, en un essai,
//     sans ligne ; une transaction étrangère déjà pendante AVANT le passage n'est pas annulée (ligne de la transaction
//     étrangère) ; un `ROLLBACK` refusé (autorisateur) laisse une ligne qui le dit, et rien n'est écrit ; dans chaque
//     cas le bilan du planificateur compte le passage interrompu (`Lue(1)`) ;
//   - lot non pris par un refus du moteur qui n'est pas un verrou (`BEGIN` refusé par un autorisateur, écrivain libre) :
//     deux essais, la ligne dit la nature.
// Aucune ligne ne porte le nom du connecteur, son URL, son secret ni son `last_error`.
//
// TÉMOINS EXISTANTS RÉÉCRITS (ils produisaient le lot non pris par une transaction étrangère pendante, et affirmaient donc
// l'état écrit ou essayé DANS cette transaction, le défaut corrigé) : `passage_rate_des_connecteurs_et_refus_des_tableaux_
// sans_texte_du_moteur.rs`, phase `moteur`, et `modeles_rapports_et_engagements_lecture_ratee_et_lot_non_pris.rs`,
// `ag4_passage` (`NonPris`). Leur `BEGIN` est désormais refusé par un autorisateur, écrivain libre : leur sens est gardé
// (ligne « refus du moteur », phrase `ECHEC_D_INGESTION_LOT_NON_PRIS` et `last_run` écrits).
//
// MUTANTS JOUÉS (variable de mutation, retirés avant le commit) : AI2_MIG33_WM_JETE, AI2_MIG33_VER_JETE,
// AI2_MIG67_VER_JETE, AI2_MIG77_VER_JETE, AI2_CONN_PANIC_JETE, AI2_CONN_TAXII_OK_JETE, AI2_CONN_TAXII_KO_JETE,
// AI2_CONN_HTTP_OK_JETE, AI2_CONN_HTTP_KO_JETE, AI2_CONN_TYPE_JETE, AI2_CONN_DEF_OK_JETE, AI2_CONN_DEF_KO_JETE,
// AI2_CONN_SANS_TX_ETRANGERE, AI2_CONN_TX_SANS_JOURNAL, AI2_CONN_UN_SEUL_ESSAI, AI2_CONN_SANS_JOURNAL,
// AI2_CONN_NATURE_UNIQUE ; puis AI2_CONN_OK_REJOUE, AI2_CONN_TAXII_TX_DIT_ECRIT, AI2_CONN_PANIC_SANS_ROLLBACK,
// AI2_CONN_PANIC_ROLLBACK_SANS_AVANT, AI2_CONN_PANIC_ROLLBACK_JETE, AI2_CONN_PANIC_ROLLBACK_SANS_JOURNAL,
// AI2_CONN_PANIC_REFUS_NON_COMPTE, AI2_CONN_PANIC_NON_COMPTE, AI2_AG4_NONPRIS_DIT_ANNULE, AI2_NATURE_UNIQUE.
//
// CE QU'ILS NE TIENNENT PAS : la garde des écritures avalées ne lit toujours pas le succès littéral dans l'ancêtre (reste de
// `P10.34-c` rattaché à `P10.34-d`) ; les autres `let _` de `migrate.rs` (`:461`, `:886`, `:1272` et suivants) ; ce que la
// console des connecteurs affiche (web/ hors périmètre) ; un `UPDATE` qui touche zéro ligne (connecteur supprimé pendant
// le passage : rien à écrire).
// =====================================================================================
mod ecritures_d_etat_des_migrations_et_des_connecteurs_consommees {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};
    use rusqlite::OptionalExtension as _;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const AI2_ENFANT: &str = "PLUME_TEMOIN_AI2_ENFANT";
    const AI2_PHASE: &str = "AI2-PHASE:";
    const AI2_REFUS: &str = "ai2 refus de temoin";
    const AI2_WM_ANCIEN: &str = "ai2-watermark-ancien";

    // ---- migrations (`P10.34-c`) ----

    fn ai2_version(c: &Connection) -> String {
        c.query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0)).expect("version lisible")
    }

    fn ai2_watermark_rollup(c: &Connection) -> Option<String> {
        c.query_row("SELECT value FROM meta WHERE key='event_rollup_wm'", [], |r| r.get(0)).optional().expect("watermark lisible")
    }

    fn ai2_base_migree(tag: &str) -> (Connection, crate::tmp_possede::TmpDb) {
        let p = crate::tmp_possede::TmpDb::neuf(&format!("ai2-{tag}"));
        let conn = open_db(&p).expect("fixture : base sur disque");
        conn.execute_batch(include_str!("../../../db/schema.sql")).expect("fixture : schéma");
        assert!(migrate(&conn), "fixture : migrations complètes");
        (conn, p)
    }

    /// Une étape : la base est rétrogradée à `avant` (avec ce que `preparer` pose), le déclencheur `declencheur` posé ;
    /// `migrate` rend `false`, la version relue vaut `avant` ; puis `observer` (l'état laissé), puis le déclencheur retiré,
    /// la reprise va au bout.
    fn ai2_etape(nom: &str, avant: i64, preparer: &str, declencheur: &str, observer: impl Fn(&Connection)) {
        let (conn, _p) = ai2_base_migree(nom);
        conn.execute_batch(preparer).expect("fixture : état d'avant l'étape");
        conn.execute("UPDATE meta SET value=?1 WHERE key='schema_version'", params![avant.to_string()]).expect("fixture : rétrogradation");
        conn.execute_batch(&format!("CREATE TRIGGER ai2_refus {declencheur} BEGIN SELECT RAISE(ABORT, '{AI2_REFUS}'); END;"))
            .expect("fixture : déclencheur");
        eprintln!("{AI2_PHASE}{nom}");
        let alle_au_bout = migrate(&conn);
        eprintln!("{AI2_PHASE}{nom}-reprise");
        assert!(!alle_au_bout, "{nom} : écriture refusée -> la chaîne est interrompue");
        assert_eq!(ai2_version(&conn), avant.to_string(), "{nom} : version relue = celle d'avant l'étape");
        assert!(conn.is_autocommit(), "{nom} : aucune transaction pendante");
        observer(&conn);
        conn.execute_batch("DROP TRIGGER ai2_refus").expect("fixture : déclencheur retiré");
        assert!(migrate(&conn), "{nom} : la reprise va au bout");
        assert_eq!(ai2_version(&conn), CODE_SCHEMA_MAX.to_string(), "{nom} : reprise estampillée à CODE_SCHEMA_MAX");
    }

    const AI2_ROLLUPS_PRE_V67: &str = "DROP TABLE IF EXISTS event_dim_rollup; \
         CREATE TABLE event_dim_rollup(bucket INTEGER NOT NULL, source TEXT NOT NULL DEFAULT '', \
           dim TEXT NOT NULL DEFAULT '', val TEXT NOT NULL DEFAULT '', n INTEGER NOT NULL DEFAULT 0, \
           PRIMARY KEY(bucket,source,dim,val)); \
         INSERT INTO event_dim_rollup(bucket,source,dim,val,n) VALUES(3600,'web','status','200',7); \
         DROP TABLE IF EXISTS event_rollup; \
         CREATE TABLE event_rollup(bucket INTEGER NOT NULL, source TEXT NOT NULL DEFAULT '', \
           severity INTEGER NOT NULL DEFAULT 0, action TEXT NOT NULL DEFAULT '', src_ip TEXT NOT NULL DEFAULT '', \
           host TEXT NOT NULL DEFAULT '', n INTEGER NOT NULL DEFAULT 0, last_ts INTEGER NOT NULL DEFAULT 0, \
           PRIMARY KEY(bucket,source,severity,action,src_ip,host));";

    fn ai2_enfant_des_migrations() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // l'ouverture et la v33 lisent l'environnement
        let wm = format!("INSERT OR REPLACE INTO meta(key,value) VALUES('event_rollup_wm','{AI2_WM_ANCIEN}');");
        ai2_etape("v33-watermark", 32, &wm, "BEFORE DELETE ON meta WHEN OLD.key='event_rollup_wm'", |c| {
            assert_eq!(ai2_watermark_rollup(c).as_deref(), Some(AI2_WM_ANCIEN), "v33-watermark : le watermark refusé reste");
        });
        ai2_etape("v33-version", 32, &wm, "BEFORE UPDATE ON meta WHEN NEW.key='schema_version' AND NEW.value='33'", |c| {
            assert_eq!(ai2_watermark_rollup(c), None, "v33-version : observé, le DELETE qui précède n'est dans aucune transaction");
        });
        ai2_etape("v67-version", 66, AI2_ROLLUPS_PRE_V67, "BEFORE UPDATE ON meta WHEN NEW.key='schema_version' AND NEW.value='67'", |c| {
            assert!(
                col_exists(c, "event_rollup", "env_id") && col_exists(c, "event_dim_rollup", "env_id"),
                "v67-version : observé, la recréation reste (aucune transaction) ; la reprise la saute (col_exists)"
            );
        });
        ai2_etape("v77-version", 76, "DROP TABLE host_rollup;", "BEFORE UPDATE ON meta WHEN NEW.key='schema_version' AND NEW.value='77'", |c| {
            let wm: Option<String> =
                c.query_row("SELECT value FROM meta WHERE key='host_rollup_wm'", [], |r| r.get(0)).optional().expect("lisible");
            assert!(table_exists(c, "host_rollup") && wm.is_some(), "v77-version : observé, le remplissage reste (aucune transaction)");
        });
        eprintln!("{AI2_PHASE}fin");
    }

    fn ai2_phase(stderr: &str, nom: &str, prefixe: &str) -> Vec<String> {
        let debut = stderr.split_once(&format!("{AI2_PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
        let corps = debut.split_once(AI2_PHASE).map(|(c, _)| c).unwrap_or(debut);
        corps.lines().filter(|l| l.starts_with(prefixe)).map(str::to_string).collect()
    }

    /// CE QU'IL TIENT : voir l'en-tête (migrations). États jugés dans l'enfant, lignes `[migration]` dans le parent.
    /// MUTATIONS : AI2_MIG33_WM_JETE, AI2_MIG33_VER_JETE, AI2_MIG67_VER_JETE, AI2_MIG77_VER_JETE (la chaîne continue :
    /// l'enfant sort en erreur, version relue au-delà de celle d'avant, et des lignes « schéma -> vN » paraissent).
    #[test]
    fn ai2_une_ecriture_refusee_de_migrate_chain_interrompt_la_chaine() {
        if std::env::var(AI2_ENFANT).is_ok() {
            ai2_enfant_des_migrations();
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::ecritures_d_etat_des_migrations_et_des_connecteurs_consommees::ai2_une_ecriture_refusee_de_migrate_chain_interrompt_la_chaine",
            ])
            .env(AI2_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "l'enfant sort en 0 (états jugés) : {stdout}\n{stderr}");
        let echec = |v: i64, cause: &str, relue: i64| {
            format!(
                "[migration] v{v} ÉCHEC ({cause} ({AI2_REFUS})) — le message « schéma -> v{v} » éventuellement affiché ci-dessus \
                 est ANNULÉ ; version RELUE en base : {relue}, étape RE-TENTÉE au prochain démarrage (migrate interrompu)"
            )
        };
        let cas = [
            ("v33-watermark", echec(33, "réinitialisation du watermark event_rollup refusée", 32)),
            ("v33-version", echec(33, "estampille de version refusée", 32)),
            ("v67-version", echec(67, "estampille de version refusée", 66)),
            ("v77-version", echec(77, "estampille de version refusée", 76)),
        ];
        assert!(cas.len() >= 4, "plancher : quatre écritures");
        for (nom, attendue) in &cas {
            assert_eq!(ai2_phase(&stderr, nom, "[migration] "), vec![attendue.clone()], "phase {nom} : lignes [migration], en entier");
        }
    }

    // ---- connecteurs (`P10.34-f`) ----

    const AI2_NOM_DU_CONNECTEUR: &str = "ai2-connecteur-nomme";
    const AI2_SECRET_DU_CONNECTEUR: &str = "ai2-valeur-du-secret";
    const AI2_HOTE: &str = "203.0.113.20";
    const AI2_WM: &str = "2020-01-01T00:00:00Z";
    const AI2_ECHEC_DU_VENDEUR: &str = "ai2 echec du vendeur";
    const AI2_TYPE_INCONNU: &str = "ai2-type-inconnu";

    /// Les huit sites, par le geste qui les atteint.
    const AI2_SITES: [&str; 8] = ["panic", "taxii-ok", "taxii-ko", "http-ok", "http-ko", "type", "def-ok", "def-ko"];

    fn ai2_cfg_http() -> String {
        json!({
            "url": format!("https://{AI2_HOTE}/api/alertes"), "records_path": "items", "field_map": { "id": "id", "message": "msg" },
            "watermark": { "field_path": "ts", "param": "since", "format": "iso8601" },
        })
        .to_string()
    }

    fn ai2_fetch_http() -> impl Fn(&str, &str, &[(&str, &str)], Option<&[u8]>) -> Result<HttpResp, String> {
        |_m: &str, _u: &str, _h: &[(&str, &str)], _b: Option<&[u8]>| {
            let corps = json!({ "items": [
                { "id": "ai2-a1", "msg": "un", "ts": "2026-07-01T10:00:00Z" },
                { "id": "ai2-a2", "msg": "deux", "ts": "2026-07-01T11:00:00Z" },
            ] });
            Ok(HttpResp { status: 200, headers: vec![], body: corps.to_string().into_bytes() })
        }
    }

    fn ai2_fetch_ko() -> impl Fn(&str, &str, &[(&str, &str)], Option<&[u8]>) -> Result<HttpResp, String> {
        |_m: &str, _u: &str, _h: &[(&str, &str)], _b: Option<&[u8]>| Err(AI2_ECHEC_DU_VENDEUR.to_string())
    }

    fn ai2_ctype(site: &str) -> &'static str {
        match site.split('-').next().unwrap_or("") {
            "taxii" => "taxii2",
            "def" => "defender",
            "type" => AI2_TYPE_INCONNU,
            _ => "http_pull",
        }
    }

    fn ai2_cfg(ctype: &str) -> String {
        match ctype {
            "taxii2" => taxii_cfg_json(),
            "defender" => defender_cfg_json(),
            _ => ai2_cfg_http(),
        }
    }

    /// Une base sur disque avec le connecteur n°1 (last_run=5, last_ok=111, last_count=7, watermark `AI2_WM`, aucune
    /// erreur), dû au planificateur.
    fn ai2_base_du_connecteur(tag: &str, site: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let (st, p) = sp_state(tag);
        let ctype = if site == "type" { "http_pull" } else { ai2_ctype(site) };
        st.db
            .lock()
            .execute(
                "INSERT INTO connector(id,type,name,enabled,config_json,secret,interval_s,env_id,last_run,last_ok,last_count,watermark) \
                 VALUES(1,?1,?2,1,?3,?4,300,'prod',5,111,7,?5)",
                params![ctype, AI2_NOM_DU_CONNECTEUR, ai2_cfg(ctype), AI2_SECRET_DU_CONNECTEUR, AI2_WM],
            )
            .expect("fixture : connecteur");
        (st, p)
    }

    /// Le passage du site, par son point d'entrée : `run_due_connectors` (un crochet fait paniquer le passage) ou
    /// `poll_one_connector`.
    fn ai2_passer(st: &AppState, p: &str, site: &str, now_ts: i64) {
        let ctype = ai2_ctype(site);
        let cfg = ai2_cfg(ctype);
        let s = AI2_SECRET_DU_CONNECTEUR;
        match site {
            "panic" => {
                crate::handlers::transaction_validee::poser_un_crochet_de_course(&format!("passage-du-connecteur:{p}:1"), || {
                    panic!("ai2 panic de temoin")
                });
                let bilan = run_due_connectors(&st.db, p);
                assert_eq!(bilan, crate::mesure_environnement::Mesure::Lue(1), "panic : le passage interrompu est compté");
            }
            "taxii-ok" => poll_one_connector(&st.db, p, 1, ctype, &cfg, s, "prod", Some(AI2_WM), now_ts, mock_taxii_fetch()),
            "def-ok" => poll_one_connector(&st.db, p, 1, ctype, &cfg, s, "prod", Some(AI2_WM), now_ts, mock_ok_fetch()),
            "http-ok" | "type" => poll_one_connector(&st.db, p, 1, ctype, &cfg, s, "prod", Some(AI2_WM), now_ts, ai2_fetch_http()),
            _ => poll_one_connector(&st.db, p, 1, ctype, &cfg, s, "prod", Some(AI2_WM), now_ts, ai2_fetch_ko()),
        }
    }

    type Ai2Etat = (i64, i64, i64, Option<String>, Option<String>);

    fn ai2_etat(c: &Connection) -> Ai2Etat {
        c.query_row("SELECT last_run,last_ok,last_count,watermark,last_error FROM connector WHERE id=1", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .expect("état du connecteur lisible")
    }

    fn ai2_etat_d_avant() -> Ai2Etat {
        (5, 111, 7, Some(AI2_WM.to_string()), None)
    }

    /// Le lot écrit par le passage : événements (http_pull, Defender) ou indicateurs (TAXII).
    fn ai2_lot_ecrit(c: &Connection, site: &str) -> i64 {
        let sql = if site.starts_with("taxii") { "SELECT COUNT(*) FROM ioc" } else { "SELECT COUNT(*) FROM event" };
        c.query_row(sql, [], |r| r.get(0)).expect("lot lisible")
    }

    /// Compte les ESSAIS de l'`UPDATE connector` : l'autorisateur est appelé à chaque préparation, une fois pour la
    /// colonne `last_run` que posent les neuf écritures. `refuser_begin` refuse aussi le `BEGIN` (lot non pris, écrivain
    /// libre, refus qui n'est pas un verrou) ; `refuser_rollback` refuse le `ROLLBACK`.
    fn ai2_compteur_d_essais(c: &Connection, refuser_begin: bool) -> Arc<AtomicUsize> {
        ai2_compteur_refusant(c, refuser_begin, false)
    }

    fn ai2_compteur_refusant(c: &Connection, refuser_begin: bool, refuser_rollback: bool) -> Arc<AtomicUsize> {
        let n = Arc::new(AtomicUsize::new(0));
        let n_rappel = n.clone();
        c.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Update { table_name: "connector", column_name: "last_run" } => {
                n_rappel.fetch_add(1, Ordering::SeqCst);
                Authorization::Allow
            }
            AuthAction::Transaction { operation: TransactionOperation::Begin } if refuser_begin => Authorization::Deny,
            AuthAction::Transaction { operation: TransactionOperation::Rollback } if refuser_rollback => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        n
    }

    /// Le passage panique APRÈS avoir ouvert une transaction sur l'écrivain (crochet du planificateur, dans
    /// `catch_unwind`) : la forme d'un panic dans `ingest_events_batch_env` après son `BEGIN`.
    fn ai2_passer_panic_apres_begin(st: &AppState, p: &str) {
        let ecrivain = st.db.clone();
        crate::handlers::transaction_validee::poser_un_crochet_de_course(&format!("passage-du-connecteur:{p}:1"), move || {
            ecrivain.lock().execute_batch("BEGIN").expect("crochet : le passage ouvre sa transaction");
            panic!("ai2 panic de temoin apres BEGIN")
        });
        let bilan = run_due_connectors(&st.db, p);
        assert_eq!(bilan, crate::mesure_environnement::Mesure::Lue(1), "panic après BEGIN : le passage interrompu est compté");
    }

    fn ai2_sans_autorisateur(c: &Connection) {
        c.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    fn ai2_refuser_l_update(st: &AppState) {
        st.db
            .lock()
            .execute_batch(&format!("CREATE TRIGGER ai2_connecteur_refuse BEFORE UPDATE ON connector BEGIN SELECT RAISE(ABORT, '{AI2_REFUS}'); END;"))
            .expect("fixture : déclencheur");
    }

    fn ai2_enfant_des_connecteurs() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // le passage lit l'environnement (pages, configuration)
        let now_ts = now();
        assert!(AI2_SITES.len() >= 8, "plancher : huit sites");
        for site in AI2_SITES {
            // (1) nominal : l'état est écrit.
            eprintln!("{AI2_PHASE}nominal-{site}");
            let (st, p) = ai2_base_du_connecteur(&format!("ai2-nominal-{site}"), site);
            let essais = ai2_compteur_d_essais(&st.db.lock(), false);
            ai2_passer(&st, &p, site, now_ts);
            ai2_sans_autorisateur(&st.db.lock());
            assert_eq!(essais.load(Ordering::SeqCst), 1, "{site} nominal : un essai, un succès n'est pas rejoué");
            let (last_run, last_ok, last_count, watermark, last_error) = ai2_etat(&st.db.lock());
            assert!(last_run >= now_ts, "{site} nominal : last_run posé");
            match site {
                "taxii-ok" | "http-ok" | "def-ok" => {
                    assert_eq!((last_ok, last_error.as_deref()), (last_run, None), "{site} nominal : last_ok posé, aucune erreur");
                    assert!(last_count > 0 && watermark.as_deref() != Some(AI2_WM), "{site} nominal : compte et watermark avancés");
                }
                _ => {
                    assert_eq!((last_ok, last_count, watermark.as_deref()), (111, 7, Some(AI2_WM)), "{site} nominal : last_ok inchangé");
                    let attendu = match site {
                        "panic" => "panic interne du connecteur (capturé)".to_string(),
                        "type" => format!("type de connecteur non supporté : {AI2_TYPE_INCONNU}"),
                        _ => last_error.clone().unwrap_or_default(),
                    };
                    assert!(!attendu.is_empty(), "{site} nominal : last_error posé");
                    assert_eq!(last_error.as_deref(), Some(attendu.as_str()), "{site} nominal : last_error");
                }
            }

            // (2) l'`UPDATE` est refusé : rien n'est écrit, deux essais, une ligne ; le lot déjà écrit reste.
            eprintln!("{AI2_PHASE}refus-{site}");
            let (st, p) = ai2_base_du_connecteur(&format!("ai2-refus-{site}"), site);
            ai2_refuser_l_update(&st);
            let essais = ai2_compteur_d_essais(&st.db.lock(), false);
            ai2_passer(&st, &p, site, now_ts);
            ai2_sans_autorisateur(&st.db.lock());
            assert_eq!(essais.load(Ordering::SeqCst), 2, "{site} refus : ESSAIS_DU_PASSAGE_RATE essais, pas un de plus");
            assert_eq!(ai2_etat(&st.db.lock()), ai2_etat_d_avant(), "{site} refus : l'état est celui d'avant");
            if site.ends_with("-ok") {
                assert_eq!(ai2_lot_ecrit(&st.db.lock(), site), 2, "{site} refus : le lot écrit n'est pas annulé");
            }
        }

        // (3) transaction étrangère pendante sur l'écrivain : rien n'est essayé, rien n'entre dans la transaction.
        let etrangeres = ["http-ok", "def-ok", "type", "taxii-ok"];
        assert!(etrangeres.len() >= 4, "plancher : quatre sites sous transaction étrangère");
        for site in etrangeres {
            eprintln!("{AI2_PHASE}etrangere-{site}");
            let (st, p) = ai2_base_du_connecteur(&format!("ai2-etrangere-{site}"), site);
            st.db.lock().execute_batch("BEGIN").expect("fixture : transaction étrangère");
            let essais = ai2_compteur_d_essais(&st.db.lock(), false);
            ai2_passer(&st, &p, site, now_ts);
            ai2_sans_autorisateur(&st.db.lock());
            let etat_dans_la_transaction = ai2_etat(&st.db.lock());
            let lot_dans_la_transaction = ai2_lot_ecrit(&st.db.lock(), site);
            st.db.lock().execute_batch("ROLLBACK").expect("fixture : la transaction étrangère est fermée");
            assert_eq!(essais.load(Ordering::SeqCst), 0, "{site} étrangère : aucun essai");
            assert_eq!(etat_dans_la_transaction, ai2_etat_d_avant(), "{site} étrangère : rien n'est entré dans la transaction");
            if site == "taxii-ok" {
                assert_eq!(lot_dans_la_transaction, 2, "taxii étrangère : les indicateurs sont posés DANS la transaction");
                assert_eq!(ai2_lot_ecrit(&st.db.lock(), site), 0, "taxii étrangère : son ROLLBACK les emporte (non acquis)");
            }
        }

        // (4) panic capturé et transaction ouverte : par le passage (annulée, état écrit), avant lui (étrangère, laissée),
        // par le passage avec un `ROLLBACK` refusé (rien n'est écrit, la ligne le dit).
        eprintln!("{AI2_PHASE}panic-begin");
        let (st, p) = ai2_base_du_connecteur("ai2-panic-begin", "panic");
        let essais = ai2_compteur_d_essais(&st.db.lock(), false);
        ai2_passer_panic_apres_begin(&st, &p);
        ai2_sans_autorisateur(&st.db.lock());
        assert!(st.db.lock().is_autocommit(), "panic-begin : la transaction du passage est annulée");
        assert_eq!(essais.load(Ordering::SeqCst), 1, "panic-begin : l'état est écrit en un essai");
        let (last_run, last_ok, last_count, watermark, last_error) = ai2_etat(&st.db.lock());
        assert!(last_run >= now_ts, "panic-begin : last_run posé (horloge du planificateur), hors transaction");
        assert_eq!(
            (last_ok, last_count, watermark.as_deref(), last_error.as_deref()),
            (111, 7, Some(AI2_WM), Some("panic interne du connecteur (capturé)")),
            "panic-begin : l'erreur du panic, last_ok, last_count et watermark inchangés"
        );

        eprintln!("{AI2_PHASE}panic-etrangere");
        let (st, p) = ai2_base_du_connecteur("ai2-panic-etrangere", "panic");
        st.db.lock().execute_batch("BEGIN").expect("fixture : transaction étrangère");
        let essais = ai2_compteur_d_essais(&st.db.lock(), false);
        ai2_passer(&st, &p, "panic", now_ts);
        ai2_sans_autorisateur(&st.db.lock());
        let toujours_pendante = !st.db.lock().is_autocommit();
        let etat_dans_la_transaction = ai2_etat(&st.db.lock());
        if toujours_pendante {
            st.db.lock().execute_batch("ROLLBACK").expect("fixture : la transaction étrangère est fermée");
        }
        assert!(toujours_pendante, "panic-etrangere : la transaction d'un autre geste n'est pas annulée par le passage");
        assert_eq!(essais.load(Ordering::SeqCst), 0, "panic-etrangere : aucun essai");
        assert_eq!(etat_dans_la_transaction, ai2_etat_d_avant(), "panic-etrangere : rien n'est entré dans la transaction");

        eprintln!("{AI2_PHASE}panic-annulation-refusee");
        let (st, p) = ai2_base_du_connecteur("ai2-panic-annulation-refusee", "panic");
        let essais = ai2_compteur_refusant(&st.db.lock(), false, true);
        ai2_passer_panic_apres_begin(&st, &p);
        ai2_sans_autorisateur(&st.db.lock());
        let toujours_pendante = !st.db.lock().is_autocommit();
        let etat_dans_la_transaction = ai2_etat(&st.db.lock());
        if toujours_pendante {
            st.db.lock().execute_batch("ROLLBACK").expect("fixture : la transaction du passage est fermée");
        }
        assert!(toujours_pendante, "panic-annulation-refusee : contrôle, le ROLLBACK a bien été refusé");
        assert_eq!(essais.load(Ordering::SeqCst), 0, "panic-annulation-refusee : aucun essai dans la transaction du passage");
        assert_eq!(etat_dans_la_transaction, ai2_etat_d_avant(), "panic-annulation-refusee : rien n'est écrit");

        // (5) lot non pris, écrivain libre, refus du moteur qui n'est pas un verrou.
        eprintln!("{AI2_PHASE}moteur-nonpris");
        let (st, p) = ai2_base_du_connecteur("ai2-moteur-nonpris", "http-ok");
        ai2_refuser_l_update(&st);
        let essais = ai2_compteur_d_essais(&st.db.lock(), true);
        ai2_passer(&st, &p, "http-ok", now_ts);
        ai2_sans_autorisateur(&st.db.lock());
        assert_eq!(essais.load(Ordering::SeqCst), 2, "moteur-nonpris : deux essais");
        assert_eq!(ai2_etat(&st.db.lock()), ai2_etat_d_avant(), "moteur-nonpris : rien n'est écrit");
        assert_eq!(ai2_lot_ecrit(&st.db.lock(), "http-ok"), 0, "moteur-nonpris : le lot n'est pas pris");
        eprintln!("{AI2_PHASE}fin");
    }

    /// CE QU'IL TIENT : voir l'en-tête (connecteurs). États et essais jugés dans l'enfant ; lignes `[connecteurs]`, par
    /// phase et en entier, dans le parent.
    /// MUTATIONS : AI2_CONN_<SITE>_JETE (phase refus du site : aucune ligne, un essai), AI2_CONN_SANS_TX_ETRANGERE
    /// (étrangère : essais et état écrit dans la transaction), AI2_CONN_TX_SANS_JOURNAL (étrangère : aucune ligne),
    /// AI2_CONN_UN_SEUL_ESSAI (un essai), AI2_CONN_SANS_JOURNAL (refus : aucune ligne), AI2_CONN_NATURE_UNIQUE (refus :
    /// « verrou »), AI2_CONN_OK_REJOUE (nominal : deux essais), AI2_CONN_TAXII_TX_DIT_ECRIT (étrangère TAXII : « lot
    /// écrit »), AI2_CONN_PANIC_SANS_ROLLBACK (panic-begin : transaction pendante, aucun essai, ligne de transaction
    /// étrangère), AI2_CONN_PANIC_ROLLBACK_SANS_AVANT (panic-etrangere : la transaction étrangère annulée, état écrit),
    /// AI2_CONN_PANIC_ROLLBACK_JETE (panic-annulation-refusee : ligne de transaction étrangère),
    /// AI2_CONN_PANIC_ROLLBACK_SANS_JOURNAL (panic-annulation-refusee : aucune ligne), AI2_CONN_PANIC_REFUS_NON_COMPTE
    /// (panic-annulation-refusee : bilan `Lue(0)`), AI2_CONN_PANIC_NON_COMPTE (panic, panic-begin : bilan `Lue(0)`).
    #[test]
    fn ai2_ecriture_d_etat_d_un_connecteur_consommee_aux_huit_sites() {
        if std::env::var(AI2_ENFANT).is_ok() {
            ai2_enfant_des_connecteurs();
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::ecritures_d_etat_des_migrations_et_des_connecteurs_consommees::ai2_ecriture_d_etat_d_un_connecteur_consommee_aux_huit_sites",
            ])
            .env(AI2_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "l'enfant sort en 0 (états jugés) : {stdout}\n{stderr}");
        let ligne = |passage: &str, nature: &str| format!("[connecteurs] WARN connecteur #1 : {passage}, état non écrit ({nature})");
        let moteur = "refus du moteur qui n'est pas un verrou";
        let etrangere = "transaction d'un autre geste pendante sur l'écrivain, non essayé";
        let passage_du_site = |site: &str| match site {
            "panic" => "passage interrompu (panic capturé)",
            "taxii-ok" | "http-ok" | "def-ok" => "lot écrit",
            "type" => "type non supporté",
            _ => "passage en échec",
        };
        let mut cas: Vec<(String, Vec<String>)> = Vec::new();
        for site in AI2_SITES {
            cas.push((format!("nominal-{site}"), vec![]));
            cas.push((format!("refus-{site}"), vec![ligne(passage_du_site(site), moteur)]));
        }
        cas.push(("etrangere-http-ok".into(), vec![ligne("passage non pris", etrangere)]));
        cas.push(("etrangere-def-ok".into(), vec![ligne("passage non pris", etrangere)]));
        cas.push(("etrangere-type".into(), vec![ligne("type non supporté", etrangere)]));
        cas.push(("etrangere-taxii-ok".into(), vec![ligne("lot posé dans cette transaction, non acquis", etrangere)]));
        cas.push(("moteur-nonpris".into(), vec![ligne("passage non pris", moteur)]));
        cas.push(("panic-begin".into(), vec![]));
        cas.push(("panic-etrangere".into(), vec![ligne("passage interrompu (panic capturé)", etrangere)]));
        cas.push((
            "panic-annulation-refusee".into(),
            vec![ligne("passage interrompu (panic capturé)", "transaction du passage restée ouverte, annulation refusée")],
        ));
        assert!(cas.len() >= 24, "plancher : deux phases sur huit sites, quatre étrangères, un lot non pris, trois panics");
        for (nom, attendues) in &cas {
            assert_eq!(&ai2_phase(&stderr, nom, "[connecteurs] "), attendues, "phase {nom} : lignes [connecteurs], en entier");
        }
        for interdit in [AI2_NOM_DU_CONNECTEUR, AI2_SECRET_DU_CONNECTEUR, AI2_HOTE, AI2_ECHEC_DU_VENDEUR, AI2_TYPE_INCONNU] {
            assert!(
                !stderr.lines().any(|l| l.starts_with("[connecteurs] ") && l.contains(interdit)),
                "`{interdit}` ne paraît dans aucune ligne [connecteurs] : {stderr}"
            );
        }
    }
}
