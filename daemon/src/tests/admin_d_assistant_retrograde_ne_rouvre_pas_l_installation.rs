// =====================================================================================
// `P10.30-b` — UN ADMINISTRATEUR DE L'ASSISTANT RÉTROGRADÉ (ÉTAT HÉRITÉ D'AVANT LE LOT 202) NE ROUVRE PAS L'INSTALLATION.
// `P10.30-d` (reste du lot X1) — UNE LECTURE RATÉE DE L'ÉTAT D'ADMINISTRATION N'OUVRE PAS L'INSTALLATION.
//
// VU (re-mesuré sur f3d3fc38, `server/mod.rs` lignes 826-866) : le démarrage lisait `meta.admin_user`, puis le haché du
// compte de ce nom `AND role='admin'` avec `.ok()`, et `Err(_) => None` sur la lecture de `meta` ; puis
// `admin0.is_none() && pass.is_empty()` fabriquait un jeton d'installation. Trois chemins menaient au même endroit : le
// compte de l'assistant rétrogradé (une autre administratrice existant pourtant), `meta.admin_user` absent, et TOUTE
// lecture en échec. Installation rouverte : `auth_guard` ferme toute autre route, `/api/setup` livre le compte
// administrateur à qui tient le jeton neuf.
//
// DÉCISION (orchestrateur, la plus sûre) : l'installation ne s'ouvre que si AUCUN compte `role='admin'` n'existe ET
// qu'aucun mot de passe de configuration n'est posé ; une lecture dont la conclusion dépend et qui échoue fait refuser
// le démarrage (nommé) ; aucun compte n'est repromu en silence.
//
// LES TÉMOINS visent `installation_au_demarrage`, la fonction que `run()` appelle (lectures sur une vraie base migrée,
// échecs de lecture injectés par un authorizer SQLite qui refuse UNE colonne), et le jugement pur.
//
// MUTANTS JOUÉS (VERIF_MUT, retirés avant le commit), chacun vu ROUGE : `x1_meta_seul_decide` (l'ancien critère :
// assistant non rechargé + pas de mot de passe => installation), `x1_meta_illisible_vaut_absent` (`Err(_) => None`),
// `x1_hache_illisible_vaut_absent` (`.ok()`), `x1_comptes_illisibles_valent_zero`, `x1_mot_de_passe_ignore`,
// `x1_illisible_ouvre` (l'appelant ouvre l'installation sur un état illisible).
//
// CORRECTION (avis du vérificateur) : l'état hérité redémarrait encore en mode installation, sans jeton — `auth_guard`
// et `/api/setup-status` lisaient « aucun administrateur de l'assistant et mot de passe vide » : `configured:false`, la
// connexion de l'administratrice existante refusée (401). Le fait « installation ouverte » est désormais JUGÉ UNE FOIS au
// démarrage (`InstallationAuDemarrage::ouverte`), porté dans l'état (`AppState::installation_ouverte`), lu par
// `en_mode_installation` (`auth_guard`, `setup_status`, `setup_post`) et fermé par la pose d'un administrateur. Témoin
// sur le routeur réel (`adrr_routeur_`). Mutants de la correction (VERIF_MUT_X1), chacun vu ROUGE : `c1_garde_lit_l_admin`,
// `c1_statut_lit_l_admin`, `c1_setup_lit_l_admin`, `c1_drapeau_ignore`, `c1_pose_ne_ferme_pas`, `c1_mdp_avant_recharge`
// (V2), `c1_residu_garde_sans_assistant` (V15), `c1_jeton_sans_0600` (V14), `c1_admin_hash_non_purge` (V17).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : `run()` lui-même n'est pas exécuté — son appel AVANT `spawn_background_jobs`, son
// refus de démarrer et le report des trois champs dans l'état servi sont épinglés sur la source (non mutés à
// l'exécution : un include_str! ne se mute qu'en recompilant).
// =====================================================================================
mod admin_d_assistant_retrograde_ne_rouvre_pas_l_installation {
    use super::*;
    use crate::server::{
        installation_au_demarrage, juger_l_etat_d_administration, lire_l_etat_d_administration, EtatDAdministrationAuDemarrage as Etat,
        InstallationAuDemarrage,
    };
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    /// Un haché de fixture : la fonction jugée ne le vérifie pas, elle le recharge.
    const ADRR_HACHE: &str = "hache-de-fixture-adrr";
    /// Les mots de passe des comptes du témoin sur le routeur (aucun mot-clé de secret dans le nom).
    const ADRR_MDP_ADM: &str = "adrr-adm-mot-de-passe-long";
    const ADRR_MDP_WIZ: &str = "adrr-wiz-mot-de-passe-long";

    fn adrr_fermee(assistant: Option<(&str, &str)>) -> InstallationAuDemarrage {
        InstallationAuDemarrage {
            administrateur_de_l_assistant: assistant.map(|(n, h)| (n.to_string(), h.to_string())),
            jeton: String::new(),
            ouverte: false,
        }
    }

    fn adrr_base(comptes: &[(&str, &str)], assistant: Option<&str>) -> Connection {
        let c = test_db();
        for (nom, role) in comptes {
            c.execute("INSERT INTO user(name,hash,role) VALUES(?1,?2,?3)", params![nom, ADRR_HACHE, role]).expect("fixture : compte posé");
        }
        if let Some(nom) = assistant {
            c.execute("INSERT INTO meta(key,value) VALUES('admin_user',?1) ON CONFLICT(key) DO UPDATE SET value=?1", params![nom])
                .expect("fixture : meta.admin_user posé");
        }
        c
    }

    /// Refuse la lecture d'UNE colonne : l'énoncé qui la lit échoue à la préparation (« not authorized »).
    fn adrr_refuser_la_colonne(c: &Connection, table: &'static str, colonne: &'static str) {
        c.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name, .. } if table_name == table && column_name == colonne => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn adrr_jeton_sur_disque(db: &crate::tmp_possede::TmpDb) -> Option<String> {
        std::fs::read_to_string(std::path::Path::new(db.as_str()).with_file_name("setup-token.txt")).ok()
    }

    /// `P10.30-b` — L'ÉTAT HÉRITÉ : `meta.admin_user` nomme un compte rétrogradé, une autre administratrice existe.
    #[test]
    fn adrr_assistant_retrograde_et_une_autre_administratrice_n_ouvre_pas() {
        let c = adrr_base(&[("wiz", "editor"), ("adm", "admin")], Some("wiz"));
        // V17 — la copie héritée du haché dans `meta` est purgée au démarrage (code déplacé ici).
        c.execute("INSERT INTO meta(key,value) VALUES('admin_hash','hache-herite')", []).expect("fixture : meta.admin_hash hérité");
        let db = crate::tmp_possede::TmpDb::neuf("adrr-retro");
        let issue = installation_au_demarrage(&c, db.as_str(), false);
        assert_eq!(issue, Ok(adrr_fermee(None)), "installation FERMÉE, aucun jeton, aucun administrateur de l'assistant");
        assert_eq!(
            c.query_row("SELECT COUNT(*) FROM meta WHERE key='admin_hash'", [], |r| r.get::<_, i64>(0)).expect("relue"),
            0,
            "meta.admin_hash purgé"
        );
        assert_eq!(adrr_jeton_sur_disque(&db), None, "aucun setup-token.txt écrit");
        assert_eq!(
            c.query_row("SELECT role FROM user WHERE name='wiz'", [], |r| r.get::<_, String>(0)).expect("relue"),
            "editor",
            "aucune repromotion silencieuse"
        );
    }

    /// `meta.admin_user` absent ne décide plus : un compte administrateur existe, l'installation reste fermée.
    #[test]
    fn adrr_meta_absent_avec_un_administrateur_n_ouvre_pas() {
        let c = adrr_base(&[("adm", "admin")], None);
        assert_eq!(lire_l_etat_d_administration(&c, false), Etat::Fermee(None));
    }

    /// `P10.30-d` — `meta` illisible : refus de démarrer, aucun jeton (avant : `Err(_) => None` puis installation).
    #[test]
    fn adrr_meta_illisible_refuse_le_demarrage() {
        let c = adrr_base(&[], None);
        let db = crate::tmp_possede::TmpDb::neuf("adrr-meta");
        adrr_refuser_la_colonne(&c, "meta", "value");
        let issue = installation_au_demarrage(&c, db.as_str(), false);
        c.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        let cause = issue.expect_err("état illisible => refus de démarrer");
        assert!(cause.contains("meta.admin_user non lu"), "cause nommée : {cause}");
        assert_eq!(adrr_jeton_sur_disque(&db), None, "aucun setup-token.txt écrit");
    }

    /// `P10.30-d` — le haché de l'assistant illisible : refus (avant : `.ok()` puis « aucun administrateur »).
    #[test]
    fn adrr_hache_illisible_refuse_le_demarrage() {
        let c = adrr_base(&[("wiz", "admin")], Some("wiz"));
        let db = crate::tmp_possede::TmpDb::neuf("adrr-hache");
        adrr_refuser_la_colonne(&c, "user", "hash");
        let issue = installation_au_demarrage(&c, db.as_str(), false);
        c.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        let cause = issue.expect_err("état illisible => refus de démarrer");
        assert!(cause.contains("compte de l'administrateur de l'assistant non lu"), "cause nommée : {cause}");
        assert_eq!(adrr_jeton_sur_disque(&db), None, "aucun setup-token.txt écrit");
    }

    /// `P10.30-d` — le compte des administrateurs illisible, sans assistant : refus, jamais « zéro ».
    #[test]
    fn adrr_comptes_illisibles_refusent_le_demarrage() {
        let c = adrr_base(&[("adm", "admin")], None);
        let db = crate::tmp_possede::TmpDb::neuf("adrr-comptes");
        adrr_refuser_la_colonne(&c, "user", "role");
        let issue = installation_au_demarrage(&c, db.as_str(), false);
        c.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        let cause = issue.expect_err("état illisible => refus de démarrer");
        assert!(cause.contains("comptes administrateurs non lus"), "cause nommée : {cause}");
        assert_eq!(adrr_jeton_sur_disque(&db), None, "aucun setup-token.txt écrit");
    }

    /// NON-VACUITÉ : une base sans aucun administrateur ni mot de passe de configuration ouvre l'installation, jeton
    /// fabriqué et écrit ; le même état avec un mot de passe de configuration reste fermé, sans jeton.
    #[test]
    fn adrr_aucun_administrateur_ouvre_et_le_mot_de_passe_ferme() {
        let c = adrr_base(&[("ed", "editor")], None);
        let db = crate::tmp_possede::TmpDb::neuf("adrr-ouverte");
        let issue = installation_au_demarrage(&c, db.as_str(), false).expect("lisible");
        assert_eq!(issue.administrateur_de_l_assistant, None);
        assert!(issue.ouverte, "installation ouverte");
        assert!(!issue.jeton.is_empty(), "jeton fabriqué (entropie disponible)");
        assert_eq!(adrr_jeton_sur_disque(&db).as_deref(), Some(issue.jeton.as_str()), "jeton écrit à côté de la base");
        // V14 — le jeton (il vaut le compte administrateur) n'est lisible que par le démon (stat, aucun descripteur).
        {
            use std::os::unix::fs::PermissionsExt;
            let tp = std::path::Path::new(db.as_str()).with_file_name("setup-token.txt");
            assert_eq!(std::fs::metadata(&tp).expect("stat du jeton").permissions().mode() & 0o777, 0o600, "jeton en 0600");
        }

        let db2 = crate::tmp_possede::TmpDb::neuf("adrr-mdp");
        assert_eq!(installation_au_demarrage(&c, db2.as_str(), true), Ok(adrr_fermee(None)), "mot de passe posé => fermée");
        assert_eq!(adrr_jeton_sur_disque(&db2), None);
    }

    /// L'assistant administrateur se recharge ; un setup-token.txt résiduel est effacé.
    #[test]
    fn adrr_assistant_recharge_et_jeton_residuel_efface() {
        let c = adrr_base(&[("wiz", "admin")], Some("wiz"));
        let db = crate::tmp_possede::TmpDb::neuf("adrr-recharge");
        let tp = std::path::Path::new(db.as_str()).with_file_name("setup-token.txt");
        std::fs::write(&tp, "residu").expect("fixture : résidu posé");
        assert_eq!(installation_au_demarrage(&c, db.as_str(), false), Ok(adrr_fermee(Some(("wiz", ADRR_HACHE)))));
        assert!(!tp.exists(), "résidu effacé");
    }

    /// V2 — LA CONFIGURATION DE PRODUCTION : mot de passe de configuration posé ET administrateur de l'assistant
    /// rechargeable. Il se recharge : sans lui, le refus de rétrograder ou de supprimer son compte (`P10.24-s`, lu sur
    /// `st.admin`) tomberait.
    #[test]
    fn adrr_assistant_recharge_avec_mot_de_passe_de_configuration() {
        let c = adrr_base(&[("wiz", "admin")], Some("wiz"));
        let db = crate::tmp_possede::TmpDb::neuf("adrr-recharge-mdp");
        assert_eq!(installation_au_demarrage(&c, db.as_str(), true), Ok(adrr_fermee(Some(("wiz", ADRR_HACHE)))));
    }

    /// V15 — LE CAS RÉEL APRÈS MISE À NIVEAU : la version fautive a rouvert l'installation et écrit `setup-token.txt` ;
    /// l'état hérité est désormais FERMÉ sans administrateur de l'assistant, et ce résidu est effacé quand même.
    #[test]
    fn adrr_residu_efface_sans_administrateur_de_l_assistant() {
        let c = adrr_base(&[("wiz", "editor"), ("adm", "admin")], Some("wiz"));
        let db = crate::tmp_possede::TmpDb::neuf("adrr-residu");
        let tp = std::path::Path::new(db.as_str()).with_file_name("setup-token.txt");
        std::fs::write(&tp, "residu-de-la-version-fautive").expect("fixture : résidu posé");
        assert_eq!(installation_au_demarrage(&c, db.as_str(), false), Ok(adrr_fermee(None)));
        assert!(!tp.exists(), "résidu effacé sans administrateur de l'assistant");
    }

    /// La pose d'un administrateur (`/api/setup`, `set_admin`) ferme l'installation DANS L'ÉTAT : le fait, pas
    /// seulement `st.admin`.
    #[test]
    fn adrr_la_pose_de_l_administrateur_ferme_l_installation_dans_l_etat() {
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        assert!(st.en_mode_installation(), "fixture : premier démarrage");
        set_admin(&st, "wiz", &hash_pw(ADRR_MDP_WIZ).expect("hachage")).expect("pose de l'administrateur");
        assert!(!st.installation_ouverte.load(std::sync::atomic::Ordering::SeqCst), "le fait est fermé");
        *st.admin.lock() = None;
        assert!(!st.en_mode_installation(), "fermé par le fait, même sans administrateur de l'assistant en mémoire");
    }

    /// L'état servi par `run()` : les trois champs de `InstallationAuDemarrage` (report épinglé sur la source).
    fn adrr_etat_servi(tag: &str, comptes: &[(&str, &str, &str)], assistant: Option<&str>) -> (AppState, crate::tmp_possede::TmpDb, bool) {
        let path = ff_tmp_path(tag);
        {
            let c = open_db(&path).expect("base");
            c.execute_batch(include_str!("../../../db/schema.sql")).expect("schéma");
            assert!(migrate(&c), "fixture : migrations complètes");
            for (nom, role, mdp) in comptes {
                c.execute("INSERT INTO user(name,hash,role) VALUES(?1,?2,?3)", params![nom, hash_pw(mdp).expect("hachage"), role])
                    .expect("fixture : compte posé");
            }
            if let Some(nom) = assistant {
                c.execute("INSERT INTO meta(key,value) VALUES('admin_user',?1)", params![nom]).expect("fixture : meta.admin_user");
            }
        }
        let mut st = ds_file_state(&path);
        st.user = Arc::new(String::new());
        st.pass_hash = Arc::new(String::new());
        let installation = installation_au_demarrage(&st.db.lock(), path.as_str(), false).expect("état lisible");
        let ouverte = installation.ouverte;
        st.admin = Arc::new(Mutex::new(installation.administrateur_de_l_assistant));
        st.setup_token = Arc::new(installation.jeton);
        st.installation_ouverte = Arc::new(std::sync::atomic::AtomicBool::new(installation.ouverte));
        (st, path, ouverte)
    }

    fn adrr_basic(nom: &str, mdp: &str) -> String {
        format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{nom}:{mdp}")))
    }

    /// `P10.30-b` (ATTENDU) — L'ÉTAT HÉRITÉ SUR LE ROUTEUR RÉEL : `meta.admin_user` = `wiz` (rétrogradé editor), `adm`
    /// administratrice, aucun mot de passe de configuration. Avant la correction : `configured:false`, connexion de
    /// `adm` 401, `/api/users` 401. Désormais : installé, `adm` se connecte et administre, `/api/setup` refusé.
    #[tokio::test]
    async fn adrr_routeur_etat_herite_sert_l_administratrice() {
        let (st, _path, ouverte) =
            adrr_etat_servi("adrr-routeur-herite", &[("wiz", "editor", ADRR_MDP_WIZ), ("adm", "admin", ADRR_MDP_ADM)], Some("wiz"));
        assert!(!ouverte, "installation fermée");
        let addr = router_serve(st).await;
        let adm = adrr_basic("adm", ADRR_MDP_ADM);
        let json = [("Content-Type", "application/json")];

        let (code, corps) = router_probe_envoi(addr, "GET", "/api/setup-status", Some(&adm), &[], "").await;
        assert_eq!(code, 200, "{corps}");
        assert!(corps.contains("\"configured\":true"), "installé : {corps}");

        let (code, corps) =
            router_probe_envoi(addr, "POST", "/api/login", None, &json, &format!(r#"{{"user":"adm","pass":"{ADRR_MDP_ADM}"}}"#)).await;
        assert_eq!(code, 200, "l'administratrice existante se connecte : {corps}");

        let (code, corps) = router_probe_envoi(addr, "GET", "/api/users", Some(&adm), &[], "").await;
        assert_eq!(code, 200, "et administre : {corps}");

        let essai = r#"{"token":"x","user":"intrus","password":"adrr-intrus-mot-de-passe"}"#;
        let (code, corps) = router_probe_envoi(addr, "POST", "/api/setup", None, &json, essai).await;
        assert_eq!(code, 401, "anonyme : l'assistant n'est plus public : {corps}");
        let (code, corps) = router_probe_envoi(addr, "POST", "/api/setup", Some(&adm), &json, essai).await;
        assert_eq!(code, 409, "déjà configuré, jugé par le fait : {corps}");
    }

    /// NON-VACUITÉ sur le routeur : aucune administratrice, aucun mot de passe de configuration -> installation ouverte,
    /// `configured:false` servi à un anonyme, toute autre route fermée.
    #[tokio::test]
    async fn adrr_routeur_premier_demarrage_reste_en_installation() {
        let (st, _path, ouverte) = adrr_etat_servi("adrr-routeur-premier", &[("ed", "editor", ADRR_MDP_WIZ)], None);
        assert!(ouverte, "installation ouverte");
        let addr = router_serve(st).await;
        let (code, corps) = router_probe_envoi(addr, "GET", "/api/setup-status", None, &[], "").await;
        assert_eq!(code, 200, "{corps}");
        assert!(corps.contains("\"configured\":false"), "non installé : {corps}");
        let json = [("Content-Type", "application/json")];
        let (code, corps) =
            router_probe_envoi(addr, "POST", "/api/login", None, &json, &format!(r#"{{"user":"ed","pass":"{ADRR_MDP_WIZ}"}}"#)).await;
        assert_eq!(code, 401, "installation : toute autre route fermée : {corps}");
    }

    /// Le jugement pur : une lecture en échec ne décide QUE si la conclusion en dépend.
    #[test]
    fn adrr_jugement_pur_trois_issues() {
        let lu = || Ok(Some(("wiz".to_string(), Some(ADRR_HACHE.to_string()))));
        let ko = || Err::<i64, String>("x".into());
        assert_eq!(juger_l_etat_d_administration(lu(), ko(), false), Etat::Fermee(Some(("wiz".into(), ADRR_HACHE.into()))));
        assert_eq!(juger_l_etat_d_administration(lu(), ko(), true), Etat::Fermee(Some(("wiz".into(), ADRR_HACHE.into()))));
        assert_eq!(juger_l_etat_d_administration(Ok(None), ko(), true), Etat::Fermee(None));
        assert_eq!(juger_l_etat_d_administration(Ok(None), ko(), false), Etat::Illisible("x".into()));
        assert_eq!(juger_l_etat_d_administration(Ok(Some(("wiz".into(), None))), Ok(0), false), Etat::Ouverte);
        assert_eq!(juger_l_etat_d_administration(Ok(Some(("wiz".into(), None))), Ok(2), false), Etat::Fermee(None));
        assert_eq!(juger_l_etat_d_administration(Err("m".into()), Ok(0), true), Etat::Illisible("m".into()));
    }

    /// `run()` n'est pas exécuté : son appel (AVANT les tâches de fond), son refus de démarrer et le report des trois
    /// champs dans l'état servi sont épinglés sur la source.
    #[test]
    fn adrr_run_appelle_l_installation_et_refuse_de_demarrer() {
        let source = include_str!("../server/mod.rs");
        let run = &source[source.find("pub(crate) async fn run()").expect("`run` repérable")..];
        let appel = run.find("installation_au_demarrage(&db.lock(), &db_path, !pass.is_empty())").expect("`run` appelle l'installation");
        let taches = run.find("spawn_background_jobs(").expect("tâches de fond lancées dans `run`");
        let etat = run.find("let state = AppState {").expect("état servi construit dans `run`");
        assert!(appel < taches, "le jugement précède le lancement des tâches de fond");
        assert!(appel < etat);
        let refus = run[appel..taches].find("Err(cause) =>").expect("bras de refus avant les tâches");
        assert!(run[appel..taches][refus..].contains("std::process::exit(1);"), "un état illisible arrête le démon");
        let servi = &run[etat..];
        for champ in [
            "admin: Arc::new(Mutex::new(installation.administrateur_de_l_assistant)),",
            "setup_token: Arc::new(installation.jeton),",
            "installation_ouverte: Arc::new(std::sync::atomic::AtomicBool::new(installation.ouverte)),",
        ] {
            assert!(servi[..servi.find("};").expect("fin de l'état")].contains(champ), "état servi : {champ}");
        }
        assert!(!run.contains("SELECT hash FROM user WHERE name=?1 AND role='admin'"), "aucune seconde lecture dans `run`");
    }
}
