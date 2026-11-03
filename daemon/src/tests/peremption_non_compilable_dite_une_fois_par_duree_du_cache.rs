// =====================================================================================
// `P10.32-o` (vague BK) — LA LIGNE `[panel]` D'UNE CHARGE PÉRIMÉE SERVIE POUR UN PANNEAU QUI NE COMPILE PLUS EST BORNÉE,
// ET LES REGISTRES DE PROCESSUS INDEXÉS PAR LE CHEMIN DE LA BASE OUBLIENT UN TENANT DÉTRUIT.
//
// RELEVÉ PAR LE VÉRIFICATEUR DE LA VAGUE BJ : `serve_swr`, bras HIT « charge périmée, le panneau ne compile plus »,
// écrivait `[panel] WARN … charge utile périmée servie, le panneau ne compile plus …` à CHAQUE interrogation, sans borne,
// alors que le pré-chauffage se tait exprès pour ce panneau. Et `ECRITURES_DE_CACHE_REFUSEES`, indexé par le chemin de la
// base, gardait les refus d'un tenant DÉTRUIT : recréé au même chemin, il héritait d'un 503 `cache_non_ecrit` sans calcul
// armé jusqu'à une durée du cache.
//
// LE CORRECTIF :
//  * `panneau_avoue::dire_la_peremption_non_compilable` (registre de processus borné, clé = base de la connexion +
//    panneau) : la ligne n'est écrite que si aucune n'a été dite pour ce panneau depuis PLUS d'une durée du cache DU
//    PANNEAU ; une ligne tue ne repousse pas l'instant noté ; registre plein -> l'entrée la plus ancienne retirée pour
//    une clé neuve, rien de retiré pour une clé connue. Le corps servi ne change pas ;
//  * `panneau_avoue::oublier_les_registres_d_une_base_detruite`, appelée par `tenants::tenant_destroy` AVANT la
//    suppression du fichier : les entrées de cette base (chemin tel quel ou résolu) sont effacées des deux registres.
//
// CE QUE CES TÉMOINS JUGENT :
//  (A) en sous-processus, MODE 1, DEUX tenants réels, par le HANDLER RÉEL `panel_data` : deux panneaux GXQL refusés par
//      le compilateur, durée du cache PROPRE (plus longue que la globale), charge périmée. Premier panneau interrogé deux
//      fois -> une ligne ; instant antidaté entre la durée globale et la durée propre -> aucune ligne ; antidaté au-delà
//      de la durée propre -> une ligne de plus ; second panneau -> sa ligne ; chaque ligne ENTIÈRE, tenant échappé,
//      aucune autre ; le corps servi porte l'aveu du compilateur à chaque interrogation, ligne dite ou tue ;
//  (B) la décision et la borne, sur le type du registre de production : bord (égal à la durée -> tue, au-delà -> dite),
//      ligne tue qui ne repousse pas l'instant ; registre plein + clé neuve -> la plus ancienne (placée au milieu) seule
//      retirée ; registre plein + clé connue la plus RÉCENTE -> rien de retiré ;
//  (C) MODE 1, données sous un LIEN symbolique (le chemin du plan de contrôle diffère de celui que SQLite nomme) :
//      `tenant_destroy` efface les deux registres pour la base détruite, recréée au même chemin ; l'autre tenant garde
//      les siens ;
//  (D) une base dont le fichier n'existe plus (aucune forme résolue) : le chemin tel quel suffit.
// MUTANTS JOUÉS (variable `VERIF_MUT` sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE : BK1_JOURNAL_SANS_BORNE,
// BK1_TTL_GLOBAL, BK1_CLE_SANS_BASE (A) ; BK1_BORD, BK1_SILENCE_REPOUSSE, BK1_SANS_EVICTION, BK1_EVINCE_RECENTE,
// BK1_CLE_CONNUE_EVINCE (B) ; BK1_OUBLI_ABSENT, BK1_OUBLI_TOUT, BK1_OUBLI_SANS_ECRITURES, BK1_OUBLI_SANS_PEREMPTIONS,
// BK1_OUBLI_SANS_CANON, BK1_OUBLI_APRES_SUPPRESSION (C) ; BK1_OUBLI_SANS_TEL_QUEL (D).
// CE QU'ILS NE TIENNENT PAS : les deux autres lignes `[panel]` d'un panneau qui ne compile pas (corps d'échec périmé servi
// en 400, ligne ILLISIBLE servie en 400) restent écrites à chaque interrogation ; les registres sont des états de
// processus, perdus au redémarrage (une ligne de plus, un refus re-noté au calcul suivant).
// =====================================================================================
mod peremption_non_compilable_dite_une_fois_par_duree_du_cache {
    use super::*;
    use crate::handlers::panneau_avoue::{
        noter_une_ligne_dite, CleDeLigneDite, RefusDEcritureDeCache, BORNE_DES_PEREMPTIONS_NON_COMPILABLES_DITES,
    };
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const BK1_ENFANT: &str = "BK1_ENFANT_PEREMPTION_NON_COMPILABLE_BORNEE";
    const BK1_ATTENDU: &str = "BK1-ATTENDU:";
    const BK1_IDS: &str = "BK1-IDS:";
    const BK1_ALPHA: &str = "bk1-alpha";
    const BK1_BETA: &str = "bk1-beta";
    /// Durée du cache PROPRE des panneaux du témoin : plus longue que la globale, pour que le mutant qui borne par la
    /// globale rougisse.
    const BK1_TTL_PROPRE: i64 = 3600;
    /// La ligne, écrite ici : un témoin qui lirait le texte de production ne verrait pas qu'il change.
    fn bk1_ligne(id: i64, tenant: &str) -> String {
        format!(
            "[panel] WARN panneau #{id}, tenant \"{tenant}\" : charge utile périmée servie, le panneau ne compile plus — refus du compilateur joint au corps (`stats.rafraichissement_en_echec`), aucun calcul armé"
        )
    }

    fn bk1_semer(handle: &Arc<Mutex<Connection>>, rk: &str) -> (i64, i64) {
        let conn = handle.lock();
        conn.execute("UPDATE panel SET panel_cache_ttl_s=0", []).expect("fixture : panneaux semés hors du pré-chauffage");
        conn.execute("INSERT INTO dashboard(name,owner,visibility) VALUES('bk1','root','shared')", []).expect("fixture : tableau");
        let did = conn.last_insert_rowid();
        let mut ids = Vec::new();
        for _ in 0..2 {
            conn.execute(
                "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,panel_cache_ttl_s) VALUES(?1,'bk1',?2,1,'table',?3)",
                params![did, T3C_GXQL_REFUSE, BK1_TTL_PROPRE],
            )
            .expect("fixture : panneau");
            ids.push(conn.last_insert_rowid());
        }
        let fpg = query_fingerprint(T3C_GXQL_REFUSE, true);
        let charge = json!({ "columns": ["a"], "rows": [[42]] }).to_string();
        for id in &ids {
            panneau_avoue::cache_ecrire(&conn, *id, rk, &fpg, now() - BK1_TTL_PROPRE - 50, &charge);
        }
        (ids[0], ids[1])
    }

    /// Une interrogation par le handler réel : la charge servie et l'aveu du compilateur, que la ligne soit dite ou tue.
    async fn bk1_servir(st: &AppState, au: &AuthUser, id: i64, from: i64, refus: &str, quoi: &str) {
        let (code, v) = t3c_json(panel_data(State(st.clone()), Extension(au.clone()), Path(id), t3c_q(from)).await).await;
        assert_eq!((code, v["rows"].clone()), (200, json!([[42]])), "contrôle {} {quoi} : charge servie : {v}", au.tenant);
        assert_eq!(v["stats"]["rafraichissement_en_echec"]["cause"], json!(refus), "{} {quoi} : le corps porte l'aveu : {v}", au.tenant);
    }

    async fn bk1_creer(st: &AppState, t: &str) {
        let r = tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(au_super("op-bk1")), Json(json!({ "id": t, "name": t })))
            .await;
        assert_eq!(r.status().as_u16(), 201, "contrôle : tenant {t} créé");
    }

    // ---------------------------------------------------------------------------------
    // (A) LA LIGNE, PAR LE HANDLER RÉEL, MODE 1, DEUX TENANTS.
    // ---------------------------------------------------------------------------------
    #[tokio::test]
    async fn bk1_charge_perimee_non_compilable_une_ligne_par_panneau_et_par_duree_du_cache_deux_tenants() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // panel_data lit load_config()
        if std::env::var(BK1_ENFANT).is_ok() {
            let (st, _dir) = mk_mode1_state();
            for t in [BK1_ALPHA, BK1_BETA] {
                bk1_creer(&st, t).await;
            }
            let (ttl_global, _) = panel_serve_cfg_de(&load_config());
            assert!(ttl_global + 5 < 600 && 600 < BK1_TTL_PROPRE, "contrôle : globale ({ttl_global}) < 600 < propre");
            let from = now() - 86_400;
            let rk = env_range_key(None, &cache_range_key(from, 0, now()));
            let refus = panneau_avoue::compile_panneau_avoue(T3C_GXQL_REFUSE, true, from, 0, None)
                .err()
                .unwrap_or_else(|| panic!("précondition : GXQL refusé"));
            for t in [BK1_ALPHA, BK1_BETA] {
                let handle = st.tenants.handle_for(t).expect("contrôle : base du tenant");
                let (p1, p2) = bk1_semer(&handle, &rk);
                println!("{BK1_IDS}{t}:{p1}:{p2}");
                let au = au_tadmin("adm", t);
                bk1_servir(&st, &au, p1, from, &refus, "p1 première").await;
                println!("{BK1_ATTENDU}{}", bk1_ligne(p1, t));
                bk1_servir(&st, &au, p1, from, &refus, "p1 seconde, dans la durée").await;
                panneau_avoue::antidater_la_peremption_dite(&handle.lock(), p1, now() - 600);
                bk1_servir(&st, &au, p1, from, &refus, "p1 antidaté entre la durée globale et la propre").await;
                panneau_avoue::antidater_la_peremption_dite(&handle.lock(), p1, now() - BK1_TTL_PROPRE - 5);
                bk1_servir(&st, &au, p1, from, &refus, "p1 antidaté au-delà de la durée propre").await;
                println!("{BK1_ATTENDU}{}", bk1_ligne(p1, t));
                bk1_servir(&st, &au, p2, from, &refus, "p2").await;
                println!("{BK1_ATTENDU}{}", bk1_ligne(p2, t));
            }
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::peremption_non_compilable_dite_une_fois_par_duree_du_cache::bk1_charge_perimee_non_compilable_une_ligne_par_panneau_et_par_duree_du_cache_deux_tenants",
            ])
            .env(BK1_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        // Les mêmes identifiants de panneaux sous les deux tenants : une clé sans la base confondrait leurs lignes.
        let ids: Vec<String> = stdout.lines().filter_map(|l| l.split_once(BK1_IDS)).map(|(_, r)| r.trim().to_string()).collect();
        assert_eq!(ids.len(), 2, "contrôle : identifiants des deux tenants : {stdout}");
        let sans_tenant = |s: &str| s.split_once(':').map(|(_, r)| r.to_string()).unwrap_or_default();
        assert_eq!(sans_tenant(&ids[0]), sans_tenant(&ids[1]), "contrôle : mêmes identifiants sous les deux tenants : {ids:?}");
        let mut attendus: Vec<String> = stdout.lines().filter_map(|l| l.split_once(BK1_ATTENDU)).map(|(_, a)| a.to_string()).collect();
        let mut vus: Vec<String> = stderr.lines().filter(|l| l.contains("charge utile périmée servie")).map(str::to_string).collect();
        attendus.sort();
        vus.sort();
        assert_eq!(attendus.len(), 6, "contrôle : trois lignes attendues par tenant : {stdout}");
        assert_eq!(vus, attendus, "une ligne par panneau et par durée du cache, ENTIÈRE, tenant échappé, aucune autre :\n{stderr}");
    }

    // ---------------------------------------------------------------------------------
    // (B) LA DÉCISION ET LA BORNE, SUR LE TYPE DU REGISTRE DE PRODUCTION.
    // ---------------------------------------------------------------------------------
    #[test]
    fn bk1_bord_de_la_duree_et_ligne_tue_qui_ne_repousse_pas_l_instant() {
        let mut r: HashMap<CleDeLigneDite, i64> = HashMap::new();
        let k: CleDeLigneDite = ("/base-a".to_string(), 7);
        assert!(noter_une_ligne_dite(&mut r, k.clone(), 1000, 60), "première : dite");
        assert!(!noter_une_ligne_dite(&mut r, k.clone(), 1060, 60), "égale à la durée : tue");
        assert_eq!(r.get(&k), Some(&1000), "une ligne tue ne repousse pas l'instant noté");
        assert!(noter_une_ligne_dite(&mut r, k.clone(), 1061, 60), "au-delà de la durée : dite");
        assert_eq!(r.get(&k), Some(&1061), "l'instant de la ligne dite est noté");
        assert!(!noter_une_ligne_dite(&mut r, k.clone(), 1121, 60), "la durée repart de la dernière ligne dite");
        // Une autre base, même panneau : sa propre ligne.
        assert!(noter_une_ligne_dite(&mut r, ("/base-b".to_string(), 7), 1121, 60), "autre base : dite");
    }

    /// Registre plein ; l'entrée la plus ancienne est placée AU MILIEU (clé 77), les autres croissent avec leur rang.
    fn bk1_registre_plein() -> HashMap<CleDeLigneDite, i64> {
        let mut r: HashMap<CleDeLigneDite, i64> = HashMap::new();
        for i in 0..BORNE_DES_PEREMPTIONS_NON_COMPILABLES_DITES as i64 {
            r.insert(("/b".to_string(), i), if i == 77 { 5 } else { 10_000 + i });
        }
        assert_eq!(r.len(), BORNE_DES_PEREMPTIONS_NON_COMPILABLES_DITES, "contrôle : registre plein");
        r
    }

    #[test]
    fn bk1_registre_plein_cle_neuve_retire_la_plus_ancienne_seule() {
        let mut r = bk1_registre_plein();
        let neuve: CleDeLigneDite = ("/neuve".to_string(), 1);
        assert!(noter_une_ligne_dite(&mut r, neuve.clone(), 20_000, 60), "clé neuve : dite");
        assert_eq!(r.len(), BORNE_DES_PEREMPTIONS_NON_COMPILABLES_DITES, "la borne tient");
        assert_eq!(r.get(&neuve), Some(&20_000), "la clé neuve est notée");
        assert!(!r.contains_key(&("/b".to_string(), 77)), "la plus ancienne (au milieu) est retirée");
        let gardees = r.keys().filter(|(b, _)| b == "/b").count();
        assert_eq!(gardees, BORNE_DES_PEREMPTIONS_NON_COMPILABLES_DITES - 1, "elle seule est retirée");
    }

    #[test]
    fn bk1_registre_plein_cle_connue_la_plus_recente_ne_retire_rien() {
        let mut r = bk1_registre_plein();
        let recente: CleDeLigneDite = ("/b".to_string(), BORNE_DES_PEREMPTIONS_NON_COMPILABLES_DITES as i64 - 1);
        let dite_a = *r.get(&recente).expect("contrôle : clé la plus récente");
        assert!(!noter_une_ligne_dite(&mut r, recente.clone(), dite_a + 1, 60), "clé connue dans la durée : tue");
        assert!(noter_une_ligne_dite(&mut r, recente.clone(), dite_a + 61, 60), "clé connue au-delà : dite");
        assert_eq!(r.get(&recente), Some(&(dite_a + 61)), "clé connue mise à jour");
        assert_eq!(r.len(), BORNE_DES_PEREMPTIONS_NON_COMPILABLES_DITES, "rien d'ajouté");
        assert_eq!(r.get(&("/b".to_string(), 77)), Some(&5), "rien de retiré : la plus ancienne reste");
    }

    // ---------------------------------------------------------------------------------
    // (C) LA DESTRUCTION D'UN TENANT, DONNÉES SOUS UN LIEN SYMBOLIQUE.
    // ---------------------------------------------------------------------------------
    /// Comme `mk_mode1_state`, mais la base principale (donc le répertoire des tenants) est nommée À TRAVERS un lien
    /// symbolique : le chemin écrit au plan de contrôle n'est pas celui que SQLite nomme.
    fn bk1_etat_mode1_par_un_lien() -> (AppState, crate::tmp_possede::TmpPossede) {
        let dir = crate::tmp_possede::TmpPossede::neuf("bk1-lien");
        let reel = dir.sous("reel");
        std::fs::create_dir_all(reel.chemin()).expect("fixture : répertoire réel");
        std::os::unix::fs::symlink(reel.chemin(), dir.sous("lien").chemin()).expect("fixture : lien symbolique");
        let main_db = format!("{dir}/lien/plume.db");
        let cp = mk_control_at(dir.sous("control.db").as_str());
        {
            let c = cp.conn.lock();
            c.execute(
                "INSERT OR IGNORE INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES('default','default','',?1,?2,0)",
                params![main_db, now()],
            )
            .expect("fixture : tenant default");
        }
        let mut st = tenant_test_state("plume-admin", "plume-editor", "admins", Some(cp));
        st.db_path = Arc::new(main_db.clone());
        st.tenants.default_db_path = Arc::new(main_db);
        (st, dir)
    }

    fn bk1_noter_dans_les_deux_registres(conn: &Connection) {
        conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Insert { table_name: "panel_cache" } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let r = panneau_avoue::cache_ecrire_dit(conn, 1, "bk1-rk", "bk1-fp", now(), "{}");
        conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert!(r.is_err(), "fixture : l'écriture qui note le refus est refusée");
        assert!(panneau_avoue::dire_la_peremption_non_compilable(conn, 1, now(), BK1_TTL_PROPRE), "fixture : ligne dite notée");
    }

    fn bk1_registres(conn: &Connection) -> (Option<RefusDEcritureDeCache>, Option<i64>) {
        (panneau_avoue::refus_d_ecriture_de_cache(conn, 1, "bk1-rk", "bk1-fp"), panneau_avoue::peremption_dite_a(conn, 1))
    }

    #[tokio::test]
    async fn bk1_tenant_detruit_puis_recree_n_herite_d_aucune_entree_des_registres() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // tenant_create lit la configuration
        let (st, _dir) = bk1_etat_mode1_par_un_lien();
        bk1_creer(&st, BK1_ALPHA).await;
        bk1_creer(&st, BK1_BETA).await;
        let alpha = st.tenants.handle_for(BK1_ALPHA).expect("contrôle : base alpha");
        let beta = st.tenants.handle_for(BK1_BETA).expect("contrôle : base beta");
        bk1_noter_dans_les_deux_registres(&alpha.lock());
        bk1_noter_dans_les_deux_registres(&beta.lock());
        let chemin_ecrit = st.tenants.ready_db_path(BK1_ALPHA).expect("contrôle : chemin écrit d'alpha");
        let chemin_sqlite = alpha.lock().path().unwrap_or("").to_string();
        assert!(chemin_ecrit.contains("/lien/"), "contrôle : le chemin écrit passe par le lien : {chemin_ecrit}");
        assert_ne!(chemin_ecrit, chemin_sqlite, "contrôle : SQLite nomme la base autrement que le plan de contrôle");
        let (refus, dite) = bk1_registres(&alpha.lock());
        assert!(refus.is_some() && dite.is_some(), "contrôle : alpha a ses deux entrées avant la destruction");
        drop(alpha);

        assert!(tenant_destroy(&st.tenants, BK1_ALPHA).is_ok(), "fixture : alpha détruit");
        bk1_creer(&st, BK1_ALPHA).await;
        let alpha = st.tenants.handle_for(BK1_ALPHA).expect("contrôle : alpha recréé");
        assert_eq!(alpha.lock().path().unwrap_or(""), chemin_sqlite, "contrôle : recréé au même chemin");
        assert_eq!(bk1_registres(&alpha.lock()), (None, None), "alpha recréé : aucun refus, aucune ligne tue héritée");
        let (refus, dite) = bk1_registres(&beta.lock());
        assert!(refus.is_some(), "beta garde son refus d'écriture");
        assert!(dite.is_some(), "beta garde sa ligne dite");
    }

    // ---------------------------------------------------------------------------------
    // (D) UN FICHIER DÉJÀ ABSENT : LE CHEMIN TEL QUEL.
    // ---------------------------------------------------------------------------------
    #[test]
    fn bk1_base_sans_fichier_oubliee_par_son_chemin_tel_quel() {
        let dir = crate::tmp_possede::TmpPossede::neuf("bk1-tel-quel");
        let base = std::fs::canonicalize(dir.racine().chemin()).expect("fixture : répertoire résolu").join("d.db");
        let base = base.to_string_lossy().into_owned();
        let conn = Connection::open(&base).expect("fixture : base");
        // Sans table `panel_cache`, l'écriture est refusée par le moteur : le refus est noté.
        assert!(panneau_avoue::cache_ecrire_dit(&conn, 1, "bk1-rk", "bk1-fp", now(), "{}").is_err(), "fixture : refus noté");
        assert!(panneau_avoue::dire_la_peremption_non_compilable(&conn, 1, now(), BK1_TTL_PROPRE), "fixture : ligne dite notée");
        assert_eq!(conn.path().unwrap_or(""), base, "contrôle : SQLite nomme la base par ce chemin");
        std::fs::remove_file(&base).expect("fixture : fichier retiré");
        assert!(std::fs::canonicalize(&base).is_err(), "contrôle : aucune forme résolue");
        let (refus, dite) = bk1_registres(&conn);
        assert!(refus.is_some() && dite.is_some(), "contrôle : deux entrées avant l'oubli");
        panneau_avoue::oublier_les_registres_d_une_base_detruite(&base);
        assert_eq!(bk1_registres(&conn), (None, None), "le chemin tel quel suffit à oublier la base");
    }
}
