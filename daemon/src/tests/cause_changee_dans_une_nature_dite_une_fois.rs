// =====================================================================================
// `P10.32-o` (vague CJ) — UNE CAUSE QUI CHANGE DANS UNE MÊME NATURE DE LIGNE `[panel]` EST DITE UNE FOIS.
//
// LE DÉFAUT (base ecc5b404) : le registre des lignes dites (`panneau_avoue::dire_une_ligne_de_panneau`) avait pour clé
// (base, panneau, nature). Une ligne qui cite une cause du moteur (résultat direct non écrit au cache : `{e}` ; ligne de
// cache illisible : `{cause}`) restait tue quand la cause changeait dans la même nature, jusqu'à une durée du cache du
// panneau : le journal disait « not authorized » pendant que la base refusait pour une autre raison.
//
// LE CORRECTIF : le coffre note la CLASSE de la cause qu'il voit (code étendu du moteur, variante de décodage et rang de la
// colonne) par base, panneau et famille (écriture du cache, lecture illisible) ; la clé du registre des lignes dites porte
// la classe observée de la famille de la nature. Une classe neuve sort sa ligne une fois ; la même classe revue (le texte
// porte un rang qui croît à chaque lecture ratée) ne rouvre rien.
//
// CE QUE CES TÉMOINS JUGENT :
//  (A) en sous-processus, MODE 1, DEUX tenants réels, par le HANDLER RÉEL `panel_data`, résultat servi en DIRECT :
//      écriture du cache refusée par l'autorisateur (X) trois fois -> une ligne qui cite X ; puis refusée par un
//      déclencheur (Y) trois fois -> une ligne de plus, qui cite Y ; chaque ligne ENTIÈRE (égalité), aucune autre de sa
//      nature ; le corps servi est le même sous X et sous Y (le résultat ; la cause d'écriture n'est jamais servie) ;
//  (B) même cadre, ligne de cache ILLISIBLE d'un panneau qui ne compile pas : charge BLOB (X) trois fois -> une ligne ;
//      instant écrit en texte (Y) trois fois -> une ligne de plus qui cite Y ; le corps servi est le refus du compilateur
//      sous X comme sous Y ;
//  (C) appel direct, sur une base réelle : chaque nature, après une observation réelle (`cache_lire_dit`,
//      `cache_ecrire_dit`) : les trois natures qui citent une cause sortent une ligne de plus quand la classe change et
//      se taisent quand elle est revue ; les deux qui n'en citent aucune restent tues ;
//  (D) appel direct : `classe_de_la_cause` distingue deux codes et deux rangs, ne porte pas la valeur hors plage ni le
//      texte du moteur. (Correction : la borne et l'oubli des causes observées ont disparu avec leur registre de
//      processus, remplacé par la dernière cause observée PAR CE FIL ; le code étendu de même code primaire, la
//      conversion impossible et l'observation par fil sont jugés dans `cause_du_moteur_code_etendu_et_observee_par_ce_fil.rs`.)
// MUTANTS JOUÉS (posés sous `cfg!(test)`, armés par la variable de mutation de l'exécuteur, retirés avant le commit),
// chacun vu ROUGE :
//  CJ3_SANS_CLASSE (la clé ignore la classe, comme avant : A, B, C) ; CJ3_SANS_OBS_ECRITURE (A, C ; D, qui n'observe
//  rien, reste vert) ; CJ3_SANS_OBS_ILLISIBLE (B, C ; D reste vert) ; CJ3_FAMILLE_SOUS_REFUS_MUETTE (C) ;
//  CJ3_CLASSE_TEXTE (la classe recopie le texte : D) ; CJ3_CLASSE_AVEC_VALEUR (D) ; les deux mutants d'observation
//  rougissent aussi des témoins de `cause_du_moteur_code_etendu_et_observee_par_ce_fil.rs` (nommés dans son en-tête) ;
//  (CJ3_BORNE_SANS_RETRAIT, CJ3_BORNE_RETIRE_SUR_CONNUE, CJ3_OUBLI_SANS_CAUSES : objets retirés par la correction.)
// CE QU'ILS NE TIENNENT PAS : une classe qui revient à une classe déjà dite dans la durée du cache reste tue (la borne
// vaut par classe) ; deux causes de MÊME classe et de textes différents (deux messages `RAISE`, tous deux
// `SQLITE_CONSTRAINT_TRIGGER`) restent tues l'une après l'autre jusqu'à la durée du cache : seul un changement de classe
// est fermé ; les lignes citent toujours le texte du moteur à leur site (`dashboards.rs`) ; le refus du compilateur
// d'un panneau qui ne compile plus n'est cité par aucune ligne (le corps servi le porte, toujours courant) ; les registres
// sont perdus au redémarrage.
// =====================================================================================
mod cause_changee_dans_une_nature_dite_une_fois {
    use super::*;
    use crate::handlers::panneau_avoue::NatureDeLigneDite;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const CJ3_ENFANT: &str = "CJ3_ENFANT_CAUSE_CHANGEE_DANS_UNE_NATURE";
    const CJ3_ATTENDU: &str = "CJ3-ATTENDU:";
    const CJ3_ALPHA: &str = "cj3-alpha";
    const CJ3_BETA: &str = "cj3-beta";
    const CJ3_TTL_PROPRE: i64 = 3600;
    /// Le message du déclencheur qui refuse l'écriture du cache (cause Y du résultat direct).
    const CJ3_DECLENCHEUR: &str = "CREATE TEMP TRIGGER cj3_refus BEFORE INSERT ON panel_cache BEGIN SELECT RAISE(ABORT, 'cj3 refus du declencheur'); END";
    /// Ce que le moteur dit des deux lignes illisibles, écrit ici.
    const CJ3_ILLISIBLE_X: &str = "Invalid column type Blob at index: 0, name: payload";
    const CJ3_ILLISIBLE_Y: &str = "Invalid column type Text at index: 1, name: computed_at";
    const CJ3_FILTRE_DIRECT: &str = "résultat servi en direct NON ÉCRIT au cache";
    const CJ3_FILTRE_ILLISIBLE: &str = "le panneau ne compile pas : le refus du compilateur est servi (400)";

    fn cj3_refuser_par_l_autorisateur(conn: &Connection) {
        conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Insert { table_name: "panel_cache" } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn cj3_refuser_par_le_declencheur(conn: &Connection) {
        conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        conn.execute_batch(CJ3_DECLENCHEUR).expect("fixture : déclencheur qui refuse l'écriture du cache");
    }

    /// Le texte du refus d'écriture que voit le coffre à cet instant (sonde sur un panneau qui n'existe pas).
    fn cj3_sonder_le_refus(conn: &Connection) -> String {
        panneau_avoue::cache_ecrire_dit(conn, -1, "cj3-sonde", "cj3-sonde", now(), "{}").expect_err("contrôle : l'écriture est refusée")
    }

    fn cj3_poser_un_tableau_et_un_panneau(conn: &Connection, q: &str, soql: bool) -> i64 {
        conn.execute("UPDATE panel SET panel_cache_ttl_s=0", []).expect("fixture : panneaux semés hors du pré-chauffage");
        conn.execute("INSERT INTO dashboard(name,owner,visibility) VALUES('cj3','root','shared')", []).expect("fixture : tableau");
        let did = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,panel_cache_ttl_s) VALUES(?1,'cj3',?2,?3,'table',?4)",
            params![did, q, soql as i64, CJ3_TTL_PROPRE],
        )
        .expect("fixture : panneau");
        conn.last_insert_rowid()
    }

    async fn cj3_mode1_deux_tenants() -> (AppState, crate::tmp_possede::TmpPossede) {
        let (st, dir) = mk_mode1_state();
        for t in [CJ3_ALPHA, CJ3_BETA] {
            let r = tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(au_super("op-cj3")), Json(json!({ "id": t, "name": t })))
                .await;
            assert_eq!(r.status().as_u16(), 201, "contrôle : tenant {t} créé");
        }
        (st, dir)
    }

    async fn cj3_servir(st: &AppState, au: &AuthUser, id: i64, from: i64) -> (u16, Value) {
        t3c_json(panel_data(State(st.clone()), Extension(au.clone()), Path(id), t3c_q(from)).await).await
    }

    /// (A) L'enfant du résultat direct : X trois fois, Y trois fois, les lignes attendues imprimées.
    async fn cj3_enfant_direct() {
        let (st, _dir) = cj3_mode1_deux_tenants().await;
        let from = now() - 86_400;
        for t in [CJ3_ALPHA, CJ3_BETA] {
            let handle = st.tenants.handle_for(t).expect("contrôle : base du tenant");
            let (p, refus_x) = {
                let conn = handle.lock();
                let p = cj3_poser_un_tableau_et_un_panneau(&conn, T3C_SQL_SAIN, false);
                record_panel_cost(&conn, p, &query_fingerprint(T3C_SQL_SAIN, false), 0.5, now());
                cj3_refuser_par_l_autorisateur(&conn);
                (p, cj3_sonder_le_refus(&conn))
            };
            let au = au_tadmin("adm", t);
            let mut servis = Vec::new();
            for _ in 0..3 {
                let (code, v) = cj3_servir(&st, &au, p, from).await;
                servis.push((code, v["rows"].clone(), v["columns"].clone()));
            }
            println!("{CJ3_ATTENDU}[panel] WARN panneau #{p}, tenant \"{t}\" : {CJ3_FILTRE_DIRECT} ({refus_x})");
            let refus_y = {
                let conn = handle.lock();
                cj3_refuser_par_le_declencheur(&conn);
                cj3_sonder_le_refus(&conn)
            };
            assert_ne!(refus_x, refus_y, "contrôle : deux causes distinctes");
            assert!(refus_y.contains("cj3 refus du declencheur"), "contrôle : Y vient du déclencheur : {refus_y}");
            for _ in 0..3 {
                let (code, v) = cj3_servir(&st, &au, p, from).await;
                servis.push((code, v["rows"].clone(), v["columns"].clone()));
            }
            println!("{CJ3_ATTENDU}[panel] WARN panneau #{p}, tenant \"{t}\" : {CJ3_FILTRE_DIRECT} ({refus_y})");
            assert!(servis.len() == 6, "contrôle : six interrogations");
            for (i, s) in servis.iter().enumerate() {
                assert_eq!(s, &(200, json!([[1]]), json!(["un"])), "{t} : interrogation {i}, le résultat direct servi, sous X comme sous Y");
            }
        }
    }

    /// (B) L'enfant de la ligne illisible d'un panneau qui ne compile pas.
    async fn cj3_enfant_illisible() {
        let (st, _dir) = cj3_mode1_deux_tenants().await;
        let from = now() - 86_400;
        let rk = env_range_key(None, &cache_range_key(from, 0, now()));
        let fp = query_fingerprint(T3C_GXQL_REFUSE, true);
        let refus = panneau_avoue::compile_panneau_avoue(T3C_GXQL_REFUSE, true, from, 0, None).err().unwrap_or_else(|| panic!("précondition : GXQL refusé"));
        for t in [CJ3_ALPHA, CJ3_BETA] {
            let handle = st.tenants.handle_for(t).expect("contrôle : base du tenant");
            let p = {
                let conn = handle.lock();
                let p = cj3_poser_un_tableau_et_un_panneau(&conn, T3C_GXQL_REFUSE, true);
                conn.execute(
                    "INSERT OR REPLACE INTO panel_cache(panel_id,range_key,query_fp,computed_at,payload) VALUES(?1,?2,?3,?4,X'00FF')",
                    params![p, rk, fp, now() - 5],
                )
                .expect("fixture : charge BLOB");
                p
            };
            let au = au_tadmin("adm", t);
            let mut servis = Vec::new();
            let rang_x = panneau_avoue::lectures_de_cache_refusees() + 1;
            for _ in 0..3 {
                servis.push(cj3_servir(&st, &au, p, from).await);
            }
            println!(
                "{CJ3_ATTENDU}[panel] WARN ligne de cache ILLISIBLE (lue, non décodable), panneau #{p}, tenant \"{t}\" : {CJ3_ILLISIBLE_X} (lecture de cache ratée n° {rang_x} depuis le démarrage) — {CJ3_FILTRE_ILLISIBLE}, rien n'est armé, la ligne reste telle quelle"
            );
            handle
                .lock()
                .execute(
                    "INSERT OR REPLACE INTO panel_cache(panel_id,range_key,query_fp,computed_at,payload) VALUES(?1,?2,?3,'cj3','{}')",
                    params![p, rk, fp],
                )
                .expect("fixture : instant écrit en texte");
            let rang_y = panneau_avoue::lectures_de_cache_refusees() + 1;
            for _ in 0..3 {
                servis.push(cj3_servir(&st, &au, p, from).await);
            }
            println!(
                "{CJ3_ATTENDU}[panel] WARN ligne de cache ILLISIBLE (lue, non décodable), panneau #{p}, tenant \"{t}\" : {CJ3_ILLISIBLE_Y} (lecture de cache ratée n° {rang_y} depuis le démarrage) — {CJ3_FILTRE_ILLISIBLE}, rien n'est armé, la ligne reste telle quelle"
            );
            assert!(servis.len() == 6, "contrôle : six interrogations");
            for (i, s) in servis.iter().enumerate() {
                assert_eq!(s, &(400, json!({ "error": refus })), "{t} : interrogation {i}, le refus du compilateur, corps entier, sous X comme sous Y");
            }
        }
    }

    /// Le parent : les lignes vues de la nature égalent les lignes attendues, ENTIÈRES, aucune autre.
    fn cj3_juger(filtre: &str, sortie: std::process::Output) {
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let mut attendus: Vec<String> = stdout.lines().filter_map(|l| l.split_once(CJ3_ATTENDU)).map(|(_, a)| a.to_string()).collect();
        let mut vus: Vec<String> = stderr.lines().filter(|l| l.contains(filtre)).map(str::to_string).collect();
        attendus.sort();
        vus.sort();
        assert_eq!(attendus.len(), 4, "contrôle : deux lignes attendues par tenant : {stdout}");
        assert_eq!(vus, attendus, "une ligne par classe de cause, ENTIÈRE, la cause neuve dite une fois, aucune autre :\n{stderr}");
    }

    #[tokio::test]
    async fn cj3_resultat_direct_non_ecrit_cause_changee_dite_une_fois_deux_tenants() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // panel_data lit load_config()
        if std::env::var(CJ3_ENFANT).is_ok() {
            cj3_enfant_direct().await;
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::cause_changee_dans_une_nature_dite_une_fois::cj3_resultat_direct_non_ecrit_cause_changee_dite_une_fois_deux_tenants",
            ])
            .env(CJ3_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        cj3_juger(CJ3_FILTRE_DIRECT, sortie);
    }

    #[tokio::test]
    async fn cj3_ligne_illisible_non_compilable_cause_changee_dite_une_fois_deux_tenants() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(CJ3_ENFANT).is_ok() {
            cj3_enfant_illisible().await;
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::cause_changee_dans_une_nature_dite_une_fois::cj3_ligne_illisible_non_compilable_cause_changee_dite_une_fois_deux_tenants",
            ])
            .env(CJ3_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        cj3_juger(CJ3_FILTRE_ILLISIBLE, sortie);
    }

    // ---------------------------------------------------------------------------------
    // (C) APPEL DIRECT, CHAQUE NATURE, OBSERVATIONS RÉELLES.
    // ---------------------------------------------------------------------------------
    struct Cj3Base {
        _dir: crate::tmp_possede::TmpPossede,
        conn: Connection,
    }

    fn cj3_base(nom: &str) -> Cj3Base {
        let dir = crate::tmp_possede::TmpPossede::neuf(nom);
        let racine = std::fs::canonicalize(dir.racine().chemin()).expect("fixture : répertoire résolu");
        let chemin = racine.join("cj3.db").to_string_lossy().into_owned();
        let conn = Connection::open(&chemin).expect("fixture : base");
        conn.execute_batch(
            "CREATE TABLE panel_cache(panel_id INTEGER, range_key TEXT, query_fp TEXT, computed_at INTEGER, payload TEXT, \
             PRIMARY KEY(panel_id, range_key, query_fp))",
        )
        .expect("fixture : table du cache");
        assert_eq!(conn.path().unwrap_or(""), chemin, "contrôle : SQLite nomme la base par ce chemin");
        Cj3Base { _dir: dir, conn }
    }

    /// Une lecture réelle d'une ligne illisible : X (charge BLOB) ou Y (instant en texte).
    fn cj3_lire_illisible(conn: &Connection, id: i64, y: bool) {
        let sql = if y {
            "INSERT OR REPLACE INTO panel_cache VALUES(?1,'rk','fp','cj3','{}')"
        } else {
            "INSERT OR REPLACE INTO panel_cache VALUES(?1,'rk','fp',1,X'00FF')"
        };
        conn.execute(sql, params![id]).expect("fixture : ligne illisible");
        let lue = panneau_avoue::cache_lire_dit(conn, id, "rk", "fp");
        assert!(matches!(lue, panneau_avoue::LectureDeCache::Illisible(_)), "contrôle : ligne illisible : {lue:?}");
    }

    /// Une écriture réelle refusée : X (autorisateur) ou Y (déclencheur).
    fn cj3_ecrire_refusee(conn: &Connection, id: i64, y: bool) {
        conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        let _ = conn.execute_batch("DROP TRIGGER IF EXISTS cj3_refus");
        if y {
            cj3_refuser_par_le_declencheur(conn);
        } else {
            cj3_refuser_par_l_autorisateur(conn);
        }
        let r = panneau_avoue::cache_ecrire_dit(conn, id, "rk-e", "fp-e", now(), "{}");
        conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        let _ = conn.execute_batch("DROP TRIGGER IF EXISTS cj3_refus");
        assert!(r.is_err(), "contrôle : écriture refusée");
    }

    /// Une nature qui cite une cause : X dite, X revue tue, Y dite, Y revue tue.
    fn cj3_nature_qui_cite(b: &Cj3Base, id: i64, nature: NatureDeLigneDite, observer: fn(&Connection, i64, bool)) {
        let t = now();
        let dire = |a: i64| panneau_avoue::dire_une_ligne_de_panneau(&b.conn, id, nature, a, CJ3_TTL_PROPRE);
        observer(&b.conn, id, false);
        assert!(dire(t), "{nature:?} : X, première ligne dite");
        observer(&b.conn, id, false);
        assert!(!dire(t + 1), "{nature:?} : X revue, tue");
        observer(&b.conn, id, true);
        assert!(dire(t + 2), "{nature:?} : Y, la cause neuve dite");
        observer(&b.conn, id, true);
        assert!(!dire(t + 3), "{nature:?} : Y revue, tue");
    }

    /// Une nature qui ne cite aucune cause : la classe observée ne rouvre rien.
    fn cj3_nature_sans_cause(b: &Cj3Base, id: i64, nature: NatureDeLigneDite) {
        let t = now();
        let dire = |a: i64| panneau_avoue::dire_une_ligne_de_panneau(&b.conn, id, nature, a, CJ3_TTL_PROPRE);
        cj3_lire_illisible(&b.conn, id, false);
        cj3_ecrire_refusee(&b.conn, id, false);
        assert!(dire(t), "{nature:?} : première ligne dite");
        cj3_lire_illisible(&b.conn, id, true);
        cj3_ecrire_refusee(&b.conn, id, true);
        assert!(!dire(t + 1), "{nature:?} : aucune cause citée, une classe neuve ne rouvre rien");
    }

    #[test]
    fn cj3_chaque_nature_selon_la_classe_de_sa_cause() {
        let b = cj3_base("cj3-natures");
        cj3_nature_qui_cite(&b, 1, NatureDeLigneDite::ResultatDirectNonEcrit, cj3_ecrire_refusee);
        cj3_nature_qui_cite(&b, 2, NatureDeLigneDite::LigneIllisibleNonCompilable, cj3_lire_illisible);
        cj3_nature_qui_cite(&b, 3, NatureDeLigneDite::LigneIllisibleSousEcritureRefusee, cj3_lire_illisible);
        cj3_nature_sans_cause(&b, 4, NatureDeLigneDite::ChargePerimeeNonCompilable);
        cj3_nature_sans_cause(&b, 5, NatureDeLigneDite::CorpsDEchecPerimeNonCompilable);
        // Une écriture refusée n'est pas la cause d'une ligne illisible : la classe d'une autre famille ne rouvre rien.
        let t = now();
        cj3_lire_illisible(&b.conn, 6, false);
        assert!(panneau_avoue::dire_une_ligne_de_panneau(&b.conn, 6, NatureDeLigneDite::LigneIllisibleSousEcritureRefusee, t, CJ3_TTL_PROPRE));
        cj3_ecrire_refusee(&b.conn, 6, true);
        assert!(
            !panneau_avoue::dire_une_ligne_de_panneau(&b.conn, 6, NatureDeLigneDite::LigneIllisibleSousEcritureRefusee, t + 1, CJ3_TTL_PROPRE),
            "la classe d'un refus d'écriture ne rouvre pas la ligne illisible"
        );
    }

    // ---------------------------------------------------------------------------------
    // (D) CLASSE.
    // ---------------------------------------------------------------------------------
    #[test]
    fn cj3_classe_de_la_cause_sans_texte_ni_valeur() {
        use panneau_avoue::classe_de_la_cause;
        let echec = |code: i32, texte: &str| {
            rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), Some(texte.to_string()))
        };
        let auth = classe_de_la_cause(&echec(rusqlite::ffi::SQLITE_AUTH, "not authorized"));
        assert_eq!(auth, classe_de_la_cause(&echec(rusqlite::ffi::SQLITE_AUTH, "autre texte du moteur")), "même code, textes différents : même classe");
        assert_ne!(auth, classe_de_la_cause(&echec(rusqlite::ffi::SQLITE_FULL, "not authorized")), "deux codes, même texte : deux classes");
        assert!(!auth.contains("not authorized"), "la classe ne recopie pas le texte du moteur : {auth}");
        let hors = |rang: usize, valeur: i64| classe_de_la_cause(&rusqlite::Error::IntegralValueOutOfRange(rang, valeur));
        assert_eq!(hors(1, 7), hors(1, 9_000_000_000), "la valeur hors plage n'est pas dans la classe");
        assert_ne!(hors(0, 7), hors(1, 7), "deux rangs : deux classes");
        let ty = |rang: usize, lu: rusqlite::types::Type| classe_de_la_cause(&rusqlite::Error::InvalidColumnType(rang, "payload".into(), lu));
        assert_ne!(ty(0, rusqlite::types::Type::Blob), ty(0, rusqlite::types::Type::Text), "deux types lus : deux classes");
        assert_ne!(ty(0, rusqlite::types::Type::Blob), ty(1, rusqlite::types::Type::Blob), "deux rangs : deux classes");
    }
}
