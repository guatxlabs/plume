// =====================================================================================
// `P10.32-o` (vague CC) — LES LIGNES `[panel]` QU'UN PANNEAU DANS UN ÉTAT DURABLE ÉCRIVAIT À CHAQUE INTERROGATION SONT
// BORNÉES ; `P11.25-f` / vague CB (restes) — `used_by` garde les trois colonnes hors norme, un panneau orphelin répond
// comme un panneau absent, les branches « hexadécimal illisible » sont tenues par un appel direct.
//
// LE DÉFAUT (base 80a7936d) : la vague BK a borné la ligne de la charge périmée d'un panneau qui ne compile plus ; quatre
// autres lignes revenaient à CHAQUE interrogation d'un panneau dont l'état ne change pas tout seul : ligne de cache
// ILLISIBLE d'un panneau qui ne compile pas (400), corps d'échec PÉRIMÉ d'un panneau qui ne compile plus (400), ligne
// ILLISIBLE sous une écriture refusée notée (503), résultat servi en DIRECT dont l'écriture au cache est refusée.
//
// LE CORRECTIF : `panneau_avoue::dire_une_ligne_de_panneau` (le registre de BK, clé = base de la connexion + panneau +
// NATURE de ligne) borne chacune à une par panneau de cette base, par nature et par durée PROPRE du cache ; la première
// sort toujours ; le corps servi ne dépend pas du registre.
//
// CE QUE CES TÉMOINS JUGENT :
//  (A) en sous-processus, MODE 1, DEUX tenants réels aux mêmes identifiants de panneaux, par le HANDLER RÉEL
//      `panel_data`, pour CHAQUE nature : trois interrogations -> une ligne ; ligne antidatée entre la durée globale et la
//      durée propre -> aucune ; au-delà de la durée propre -> une de plus ; un second panneau -> sa ligne ; chaque ligne
//      ENTIÈRE (égalité), aucune autre de sa nature ; le statut et le corps servis sont les mêmes, ligne dite ou tue ;
//  (A') un même panneau dans trois natures (trois plages) -> trois lignes : une nature n'en tait pas une autre ;
//  (A'') appel direct : chaque nature notée pour deux panneaux de deux bases, l'une oubliée comme à la destruction de
//      son tenant -> la première ligne de CHAQUE nature ressort sur la base oubliée, l'autre base garde les siennes tues ;
//  (B1) par le routeur, `GET /api/library-panels` : un BLOB fabriqué en propriétaire du tableau, en visibilité du
//      tableau, en visibilité du panneau -> la liste répond pour chaque lecteur, le référent n'est compté que par qui le
//      lit (propriétaire textuel, administrateur), jamais par les octets du BLOB ; un entier ne se fabrique pas dans
//      ces colonnes (affinité TEXT : relu `text`), contrôle écrit ;
//  (B2) par le routeur : un panneau orphelin, créé par la route (l'administrateur ne lit pas le tableau à la création),
//      répond à un éditeur et à une lectrice exactement comme un panneau absent sur chaque route de panneau (statut,
//      en-têtes hors date, corps), rien n'est écrit ; l'administrateur garde la main (modification) ;
//  (B3) appel direct : `texte_rendu_en_hex` refuse une longueur impaire, un non-hexadécimal et le signe `+` que
//      `u8::from_str_radix` accepterait ; `referents_lus` rend une erreur sur un hexadécimal illisible, jamais un compte.
// MUTANTS JOUÉS (posés sous `cfg!(test)`, armés par la variable de mutation de l'exécuteur, retirés avant le commit), chacun vu ROUGE :
//  CC3_SANS_BORNE_ILLISIBLE_NC, CC3_SANS_BORNE_ECHEC_NC, CC3_SANS_BORNE_ILLISIBLE_REFUS, CC3_SANS_BORNE_DIRECT,
//  CC3_CLE_SANS_TENANT, CC3_PREMIERE_TUE (A) ; CC3_CLE_PARTAGEE (A') ; CC3_UB_OWNER_SANS_TYPEOF, CC3_UB_VIS_SANS_TYPEOF,
//  CC3_UB_PVIS_SANS_TYPEOF (B1) ; CC3_ORPHELIN_DIT (B2) ; CC3_HEX_SANS_CONTROLE, CC3_REFERENT_ILLISIBLE_SAUTE (B3) ;
//  CC3V_OUBLI_UNE_NATURE (l'oubli ne retire que la nature de BK), CC3V_OUBLI_AUCUNE, CC3V_OUBLI_TOUTES_BASES (A'').
// CE QU'ILS NE TIENNENT PAS : la ligne ILLISIBLE d'un panneau qui compile (un rafraîchissement armé la remplace, non
// bornée) ; les deux lignes qui portent l'identifiant servi dans le corps (NON LUE, résultat NON ÉCRIT en 503) : les
// taire laisserait un identifiant servi sans sa ligne ; la création d'un orphelin par l'administrateur (`POST
// /api/panels` sur un tableau absent rend 200) ; les registres sont perdus au redémarrage ; la borne est posée par
// NATURE, pas par cause : dans une même nature, une cause qui change (le refus du moteur `{e}` du résultat direct non
// écrit qui passe de « not authorized » à « disk full ») est tue jusqu'à une durée du cache du panneau.
// =====================================================================================
mod lignes_de_panneau_bornees_et_restes_des_tableaux {
    use super::*;
    use crate::handlers::panneau_avoue::NatureDeLigneDite;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const CC3_ENFANT: &str = "CC3_ENFANT_LIGNES_DE_PANNEAU_BORNEES";
    const CC3_ATTENDU: &str = "CC3-ATTENDU:";
    const CC3_IDS: &str = "CC3-IDS:";
    const CC3_ALPHA: &str = "cc3-alpha";
    const CC3_BETA: &str = "cc3-beta";
    /// Durée du cache PROPRE des panneaux : plus longue que la globale, pour qu'une borne par la globale rougisse.
    const CC3_TTL_PROPRE: i64 = 3600;
    /// Ce que le moteur dit d'une ligne de cache BLOB, écrit ici.
    const CC3_ILLISIBLE: &str = "Invalid column type Blob at index: 0, name: payload";

    /// Les quatre natures jouées par la route (la cinquième, la charge périmée, est celle de BK).
    #[derive(Clone, Copy, Debug)]
    enum Cc3Cas {
        IllisibleNonCompilable,
        EchecPerimeNonCompilable,
        IllisibleSousRefus,
        DirectNonEcrit,
    }

    impl Cc3Cas {
        fn nature(self) -> NatureDeLigneDite {
            match self {
                Cc3Cas::IllisibleNonCompilable => NatureDeLigneDite::LigneIllisibleNonCompilable,
                Cc3Cas::EchecPerimeNonCompilable => NatureDeLigneDite::CorpsDEchecPerimeNonCompilable,
                Cc3Cas::IllisibleSousRefus => NatureDeLigneDite::LigneIllisibleSousEcritureRefusee,
                Cc3Cas::DirectNonEcrit => NatureDeLigneDite::ResultatDirectNonEcrit,
            }
        }
        /// Un fragment propre à la ligne de cette nature : le parent ne retient que ces lignes.
        fn filtre(self) -> &'static str {
            match self {
                Cc3Cas::IllisibleNonCompilable => "le panneau ne compile pas : le refus du compilateur est servi (400)",
                Cc3Cas::EchecPerimeNonCompilable => "corps d'échec périmé en cache, le panneau ne compile plus",
                Cc3Cas::IllisibleSousRefus => "une écriture refusée est notée pour cette ligne",
                Cc3Cas::DirectNonEcrit => "résultat servi en direct NON ÉCRIT au cache",
            }
        }
        fn compile(self) -> bool {
            matches!(self, Cc3Cas::IllisibleSousRefus | Cc3Cas::DirectNonEcrit)
        }
        /// La ligne attendue, ENTIÈRE, écrite ici (un témoin qui lirait le texte de production ne verrait pas qu'il change).
        fn ligne(self, id: i64, t: &str, rang: u64, refus_du_moteur: &str) -> String {
            match self {
                Cc3Cas::IllisibleNonCompilable => format!(
                    "[panel] WARN ligne de cache ILLISIBLE (lue, non décodable), panneau #{id}, tenant \"{t}\" : {CC3_ILLISIBLE} (lecture de cache ratée n° {rang} depuis le démarrage) — le panneau ne compile pas : le refus du compilateur est servi (400), rien n'est armé, la ligne reste telle quelle"
                ),
                Cc3Cas::EchecPerimeNonCompilable => format!(
                    "[panel] WARN panneau #{id}, tenant \"{t}\" : corps d'échec périmé en cache, le panneau ne compile plus — le refus du compilateur est servi (400), la ligne reste telle quelle"
                ),
                Cc3Cas::IllisibleSousRefus => format!(
                    "[panel] WARN ligne de cache ILLISIBLE (lue, non décodable), panneau #{id}, tenant \"{t}\" : {CC3_ILLISIBLE} (lecture de cache ratée n° {rang} depuis le démarrage) — une écriture refusée est notée pour cette ligne : le refus nommé de l'écriture est servi (503, ligne suivante), pas la charge illisible"
                ),
                Cc3Cas::DirectNonEcrit => format!("[panel] WARN panneau #{id}, tenant \"{t}\" : résultat servi en direct NON ÉCRIT au cache ({refus_du_moteur})"),
            }
        }
    }

    fn cc3_refuser_les_ecritures(conn: &Connection, cout: bool) {
        conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Insert { table_name: "panel_cache" } => Authorization::Deny,
            AuthAction::Insert { table_name: "panel_cost" } if cout => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn cc3_echec_perime() -> String {
        let n = now();
        let mut echec = panneau_avoue::corps_d_echec("cc3 cause servie", n - 86_400, n);
        echec[crate::handlers::dashboards::MARQUEUR_INTERNE_DE_CLASSE_D_ECHEC] = json!("moteur");
        echec.to_string()
    }

    fn cc3_poser_blob(conn: &Connection, id: i64, rk: &str, fp: &str) {
        conn.execute(
            "INSERT OR REPLACE INTO panel_cache(panel_id,range_key,query_fp,computed_at,payload) VALUES(?1,?2,?3,?4,X'00FF')",
            params![id, rk, fp, now() - 5],
        )
        .expect("fixture : ligne de cache BLOB");
    }

    /// Un tableau et deux panneaux du cas, durée du cache propre ; la ligne de cache, le refus noté, le coût ou
    /// l'autorisateur que le cas exige. Rend les deux panneaux et le texte du refus du moteur (cas direct).
    fn cc3_semer(handle: &Arc<Mutex<Connection>>, cas: Cc3Cas, rk: &str) -> (i64, i64, String) {
        let conn = handle.lock();
        conn.execute("UPDATE panel SET panel_cache_ttl_s=0", []).expect("fixture : panneaux semés hors du pré-chauffage");
        conn.execute("INSERT INTO dashboard(name,owner,visibility) VALUES('cc3','root','shared')", []).expect("fixture : tableau");
        let did = conn.last_insert_rowid();
        let (q, soql) = if cas.compile() { (T3C_SQL_SAIN, false) } else { (T3C_GXQL_REFUSE, true) };
        let mut ids = Vec::new();
        for _ in 0..2 {
            conn.execute(
                "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,panel_cache_ttl_s) VALUES(?1,'cc3',?2,?3,'table',?4)",
                params![did, q, soql as i64, CC3_TTL_PROPRE],
            )
            .expect("fixture : panneau");
            ids.push(conn.last_insert_rowid());
        }
        let fp = query_fingerprint(q, soql);
        let mut refus_du_moteur = String::new();
        for id in &ids {
            match cas {
                Cc3Cas::IllisibleNonCompilable => cc3_poser_blob(&conn, *id, rk, &fp),
                Cc3Cas::EchecPerimeNonCompilable => {
                    panneau_avoue::cache_ecrire(&conn, *id, rk, &fp, now() - CC3_TTL_PROPRE - 50, &cc3_echec_perime())
                }
                Cc3Cas::IllisibleSousRefus => cc3_poser_blob(&conn, *id, rk, &fp),
                Cc3Cas::DirectNonEcrit => record_panel_cost(&conn, *id, &fp, 0.5, now()),
            }
        }
        match cas {
            Cc3Cas::IllisibleSousRefus => {
                cc3_refuser_les_ecritures(&conn, true);
                for id in &ids {
                    assert!(panneau_avoue::cache_ecrire_dit(&conn, *id, rk, &fp, now(), "{}").is_err(), "fixture : refus d'écriture noté");
                }
            }
            Cc3Cas::DirectNonEcrit => {
                cc3_refuser_les_ecritures(&conn, false);
                refus_du_moteur = panneau_avoue::cache_ecrire_dit(&conn, -1, "cc3-sonde", "cc3-sonde", now(), "{}")
                    .expect_err("contrôle : l'autorisateur refuse l'écriture");
            }
            _ => {}
        }
        (ids[0], ids[1], refus_du_moteur)
    }

    /// Ce qui est servi, sans ce qui varie d'une interrogation à l'autre quand rien ne change (identifiant de corrélation
    /// d'un 503, statistiques d'exécution d'un résultat direct) : statut, cause, raison, lignes.
    fn cc3_servi(code: u16, v: &Value) -> Value {
        json!({ "code": code, "error": v["error"], "reason": v["stats"]["coverage"]["reason"], "rows": v["rows"], "columns": v["columns"] })
    }

    /// Une interrogation par le handler réel : ce qui est servi, comparé à la forme attendue du cas.
    async fn cc3_servir(st: &AppState, au: &AuthUser, cas: Cc3Cas, id: i64, from: i64, refus: &str) -> Value {
        let (code, v) = t3c_json(panel_data(State(st.clone()), Extension(au.clone()), Path(id), t3c_q(from)).await).await;
        match cas {
            Cc3Cas::IllisibleNonCompilable | Cc3Cas::EchecPerimeNonCompilable => {
                assert_eq!((code, v.clone()), (400, json!({ "error": refus })), "{cas:?} {} : le refus du compilateur, corps entier", au.tenant)
            }
            Cc3Cas::IllisibleSousRefus => {
                assert_eq!((code, v["stats"]["coverage"]["reason"].clone()), (503, json!("cache_non_ecrit")), "{cas:?} {} : le 503 de l'écriture refusée : {v}", au.tenant)
            }
            Cc3Cas::DirectNonEcrit => assert_eq!((code, v["rows"].clone()), (200, json!([[1]])), "{cas:?} {} : le résultat direct : {v}", au.tenant),
        }
        cc3_servi(code, &v)
    }

    /// L'enfant : deux tenants, le même scénario, les lignes attendues imprimées. Le statut et le corps servis sont les
    /// mêmes que la ligne soit dite ou tue.
    async fn cc3_enfant(cas: Cc3Cas) {
        let (st, _dir) = mk_mode1_state();
        for t in [CC3_ALPHA, CC3_BETA] {
            let r = tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(au_super("op-cc3")), Json(json!({ "id": t, "name": t })))
                .await;
            assert_eq!(r.status().as_u16(), 201, "contrôle : tenant {t} créé");
        }
        let (ttl_global, _) = panel_serve_cfg_de(&load_config());
        assert!(ttl_global + 5 < 600 && 600 < CC3_TTL_PROPRE, "contrôle : globale ({ttl_global}) < 600 < propre");
        let from = now() - 86_400;
        let rk = env_range_key(None, &cache_range_key(from, 0, now()));
        let refus = panneau_avoue::compile_panneau_avoue(T3C_GXQL_REFUSE, true, from, 0, None).err().unwrap_or_else(|| panic!("précondition : GXQL refusé"));
        for t in [CC3_ALPHA, CC3_BETA] {
            let handle = st.tenants.handle_for(t).expect("contrôle : base du tenant");
            let (p1, p2, refus_du_moteur) = cc3_semer(&handle, cas, &rk);
            println!("{CC3_IDS}{t}:{p1}:{p2}");
            let au = au_tadmin("adm", t);
            let rang = || panneau_avoue::lectures_de_cache_refusees() + 1;
            let r = rang();
            let premier = cc3_servir(&st, &au, cas, p1, from, &refus).await;
            println!("{CC3_ATTENDU}{}", cas.ligne(p1, t, r, &refus_du_moteur));
            for quoi in ["seconde", "troisième"] {
                let servi = cc3_servir(&st, &au, cas, p1, from, &refus).await;
                assert_eq!(servi, premier, "{cas:?} {t} : {quoi} interrogation, ligne tue : le même statut, le même corps");
            }
            panneau_avoue::antidater_la_ligne_dite(&handle.lock(), p1, cas.nature(), now() - 600);
            let servi = cc3_servir(&st, &au, cas, p1, from, &refus).await;
            assert_eq!(servi, premier, "{cas:?} {t} : antidatée entre la durée globale et la propre, ligne tue : même service");
            panneau_avoue::antidater_la_ligne_dite(&handle.lock(), p1, cas.nature(), now() - CC3_TTL_PROPRE - 5);
            let r = rang();
            let servi = cc3_servir(&st, &au, cas, p1, from, &refus).await;
            assert_eq!(servi, premier, "{cas:?} {t} : au-delà de la durée propre, ligne dite : même service");
            println!("{CC3_ATTENDU}{}", cas.ligne(p1, t, r, &refus_du_moteur));
            let r = rang();
            cc3_servir(&st, &au, cas, p2, from, &refus).await;
            println!("{CC3_ATTENDU}{}", cas.ligne(p2, t, r, &refus_du_moteur));
        }
    }

    /// Le parent : les lignes vues de cette nature égalent les lignes attendues, ENTIÈRES, aucune autre.
    fn cc3_juger(cas: Cc3Cas, sortie: std::process::Output) {
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let ids: Vec<String> = stdout.lines().filter_map(|l| l.split_once(CC3_IDS)).map(|(_, r)| r.trim().to_string()).collect();
        assert_eq!(ids.len(), 2, "contrôle : identifiants des deux tenants : {stdout}");
        let sans_tenant = |s: &str| s.split_once(':').map(|(_, r)| r.to_string()).unwrap_or_default();
        assert_eq!(sans_tenant(&ids[0]), sans_tenant(&ids[1]), "contrôle : mêmes identifiants sous les deux tenants : {ids:?}");
        let mut attendus: Vec<String> = stdout.lines().filter_map(|l| l.split_once(CC3_ATTENDU)).map(|(_, a)| a.to_string()).collect();
        let mut vus: Vec<String> = stderr.lines().filter(|l| l.contains(cas.filtre())).map(str::to_string).collect();
        attendus.sort();
        vus.sort();
        assert_eq!(attendus.len(), 6, "contrôle : trois lignes attendues par tenant : {stdout}");
        assert_eq!(vus, attendus, "{cas:?} : une ligne par panneau, par nature et par durée du cache, ENTIÈRE, aucune autre :\n{stderr}");
    }

    #[tokio::test]
    async fn cc3_ligne_illisible_d_un_panneau_qui_ne_compile_pas_bornee_deux_tenants() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // panel_data lit load_config()
        if std::env::var(CC3_ENFANT).is_ok() {
            cc3_enfant(Cc3Cas::IllisibleNonCompilable).await;
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::lignes_de_panneau_bornees_et_restes_des_tableaux::cc3_ligne_illisible_d_un_panneau_qui_ne_compile_pas_bornee_deux_tenants",
            ])
            .env(CC3_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        cc3_juger(Cc3Cas::IllisibleNonCompilable, sortie);
    }

    #[tokio::test]
    async fn cc3_corps_d_echec_perime_d_un_panneau_qui_ne_compile_plus_borne_deux_tenants() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(CC3_ENFANT).is_ok() {
            cc3_enfant(Cc3Cas::EchecPerimeNonCompilable).await;
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::lignes_de_panneau_bornees_et_restes_des_tableaux::cc3_corps_d_echec_perime_d_un_panneau_qui_ne_compile_plus_borne_deux_tenants",
            ])
            .env(CC3_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        cc3_juger(Cc3Cas::EchecPerimeNonCompilable, sortie);
    }

    #[tokio::test]
    async fn cc3_ligne_illisible_sous_ecriture_refusee_bornee_deux_tenants() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(CC3_ENFANT).is_ok() {
            cc3_enfant(Cc3Cas::IllisibleSousRefus).await;
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::lignes_de_panneau_bornees_et_restes_des_tableaux::cc3_ligne_illisible_sous_ecriture_refusee_bornee_deux_tenants",
            ])
            .env(CC3_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        cc3_juger(Cc3Cas::IllisibleSousRefus, sortie);
    }

    #[tokio::test]
    async fn cc3_resultat_direct_non_ecrit_borne_deux_tenants() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(CC3_ENFANT).is_ok() {
            cc3_enfant(Cc3Cas::DirectNonEcrit).await;
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::lignes_de_panneau_bornees_et_restes_des_tableaux::cc3_resultat_direct_non_ecrit_borne_deux_tenants",
            ])
            .env(CC3_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        cc3_juger(Cc3Cas::DirectNonEcrit, sortie);
    }

    // ---------------------------------------------------------------------------------
    // (A') TROIS NATURES SUR LE MÊME PANNEAU.
    // ---------------------------------------------------------------------------------
    #[tokio::test]
    async fn cc3_trois_natures_sur_le_meme_panneau_trois_lignes() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(CC3_ENFANT).is_ok() {
            let (st, _dir) = mk_mode1_state();
            let r = tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(au_super("op-cc3")), Json(json!({ "id": CC3_ALPHA, "name": CC3_ALPHA })))
                .await;
            assert_eq!(r.status().as_u16(), 201, "contrôle : tenant créé");
            let handle = st.tenants.handle_for(CC3_ALPHA).expect("contrôle : base du tenant");
            let n = now();
            let (f_illisible, f_echec, f_charge) = (n - 86_400, n - 43_200, n - 21_600);
            let rk = |from: i64| env_range_key(None, &cache_range_key(from, 0, now()));
            assert!(rk(f_illisible) != rk(f_echec) && rk(f_echec) != rk(f_charge), "contrôle : trois plages distinctes");
            let fp = query_fingerprint(T3C_GXQL_REFUSE, true);
            let p = {
                let conn = handle.lock();
                conn.execute("INSERT INTO dashboard(name,owner,visibility) VALUES('cc3','root','shared')", []).expect("fixture : tableau");
                let did = conn.last_insert_rowid();
                conn.execute(
                    "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,panel_cache_ttl_s) VALUES(?1,'cc3',?2,1,'table',?3)",
                    params![did, T3C_GXQL_REFUSE, CC3_TTL_PROPRE],
                )
                .expect("fixture : panneau");
                let p = conn.last_insert_rowid();
                cc3_poser_blob(&conn, p, &rk(f_illisible), &fp);
                panneau_avoue::cache_ecrire(&conn, p, &rk(f_echec), &fp, now() - CC3_TTL_PROPRE - 50, &cc3_echec_perime());
                panneau_avoue::cache_ecrire(&conn, p, &rk(f_charge), &fp, now() - CC3_TTL_PROPRE - 50, &json!({ "columns": ["a"], "rows": [[42]] }).to_string());
                p
            };
            let au = au_tadmin("adm", CC3_ALPHA);
            let rang = panneau_avoue::lectures_de_cache_refusees() + 1;
            for (from, attendu) in [(f_illisible, 400), (f_echec, 400), (f_charge, 200)] {
                let (code, v) = t3c_json(panel_data(State(st.clone()), Extension(au.clone()), Path(p), t3c_q(from)).await).await;
                assert_eq!(code, attendu, "contrôle : plage {from} : {v}");
            }
            println!("{CC3_ATTENDU}{}", Cc3Cas::IllisibleNonCompilable.ligne(p, CC3_ALPHA, rang, ""));
            println!("{CC3_ATTENDU}{}", Cc3Cas::EchecPerimeNonCompilable.ligne(p, CC3_ALPHA, 0, ""));
            println!(
                "{CC3_ATTENDU}[panel] WARN panneau #{p}, tenant \"{CC3_ALPHA}\" : charge utile périmée servie, le panneau ne compile plus — refus du compilateur joint au corps (`stats.rafraichissement_en_echec`), aucun calcul armé"
            );
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::lignes_de_panneau_bornees_et_restes_des_tableaux::cc3_trois_natures_sur_le_meme_panneau_trois_lignes"])
            .env(CC3_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let mut attendus: Vec<String> = stdout.lines().filter_map(|l| l.split_once(CC3_ATTENDU)).map(|(_, a)| a.to_string()).collect();
        let mut vus: Vec<String> = stderr.lines().filter(|l| l.starts_with("[panel] WARN")).map(str::to_string).collect();
        attendus.sort();
        vus.sort();
        assert_eq!(attendus.len(), 3, "contrôle : trois natures attendues : {stdout}");
        assert_eq!(vus, attendus, "une nature n'en tait pas une autre, sur le même panneau :\n{stderr}");
    }

    // ---------------------------------------------------------------------------------
    // OUTILS DU ROUTEUR (B1, B2) : comptes alice et bob éditeurs, carol lectrice, adm administrateur.
    // ---------------------------------------------------------------------------------
    const CC3_MDP: &str = "cc3pw1234567";
    /// Un identifiant qu'aucun panneau ni tableau ne porte.
    const CC3_ABSENT: i64 = 999_999;

    fn cc3_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let (st, p) = router_test_state(&format!("cc3-{tag}"));
        let h = hash_pw(CC3_MDP).expect("fixture : empreinte");
        {
            let c = st.db.lock();
            c.execute_batch(
                "DELETE FROM panel_cache; DELETE FROM panel; DELETE FROM dashboard; DELETE FROM view_dashboard; DELETE FROM view; \
                 DELETE FROM library_panel; DELETE FROM playlist; DELETE FROM dashboard_snapshot;",
            )
            .expect("fixture : base vide");
            for (nom, role) in [("alice", "editor"), ("bob", "editor"), ("carol", "viewer"), ("adm", "admin")] {
                c.execute("INSERT INTO user(name,hash,role) VALUES(?1,?2,?3)", params![nom, h, role]).expect("fixture : compte");
            }
        }
        (st, p)
    }

    async fn cc3_envoi(addr: std::net::SocketAddr, qui: &str, methode: &str, chemin: &str, corps: &str) -> (u16, String) {
        let authz = format!("Basic {}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("{qui}:{CC3_MDP}")));
        let en_json = [("Content-Type", "application/json")];
        let entetes: &[(&str, &str)] = if corps.is_empty() { &[] } else { &en_json };
        router_probe_envoi(addr, methode, chemin, Some(&authz), entetes, corps).await
    }

    fn cc3_sans_date(texte: &str) -> String {
        texte.split("\r\n").filter(|l| !l.to_ascii_lowercase().starts_with("date:")).collect::<Vec<_>>().join("\r\n")
    }

    /// Le corps JSON d'une réponse du routeur, découpage `chunked` retiré quand l'en-tête l'annonce (copie de l'outil du
    /// témoin des objets de tableau de bord illisibles).
    fn cc3_corps(texte: &str) -> Value {
        let Some((entetes, corps)) = texte.split_once("\r\n\r\n") else { panic!("réponse sans corps : {texte}") };
        let brut = if !entetes.to_ascii_lowercase().contains("transfer-encoding: chunked") {
            corps.to_string()
        } else {
            let (mut reste, mut sortie) = (corps.as_bytes(), Vec::new());
            loop {
                let Some(fin) = reste.windows(2).position(|w| w == b"\r\n") else { panic!("morceau sans taille : {texte}") };
                let taille = usize::from_str_radix(std::str::from_utf8(&reste[..fin]).unwrap_or("").trim(), 16).unwrap_or_else(|_| panic!("taille illisible : {texte}"));
                if taille == 0 {
                    break;
                }
                sortie.extend_from_slice(&reste[fin + 2..fin + 2 + taille]);
                reste = &reste[fin + 2 + taille + 2..];
            }
            String::from_utf8_lossy(&sortie).into_owned()
        };
        serde_json::from_str(&brut).unwrap_or_else(|_| panic!("corps JSON attendu : {texte}"))
    }

    fn cc3_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn cc3_texte(st: &AppState, sql: &str) -> String {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("relecture `{sql}` : {e}"))
    }

    // ---------------------------------------------------------------------------------
    // (B1) `used_by` : LES TROIS COLONNES HORS NORME.
    // ---------------------------------------------------------------------------------
    /// CE QU'IL TIENT, par la route : une définition commune d'alice référencée par quatre panneaux ; le tableau
    /// de chacun (ou le panneau) porte, une colonne à la fois, les OCTETS d'un texte qui ouvrirait le compte : propriétaire = BLOB
    /// `bob` (tableau privé), visibilité du tableau = BLOB `shared` (tableau d'alice), visibilité du panneau = BLOB
    /// `shared` (panneau d'un tableau commun d'alice, rendu privé à tous sauf le propriétaire), plus un témoin
    /// textuel ordinaire (tableau commun d'alice). La liste répond 200 sans `error` à chacun ; bob compte le seul
    /// témoin ordinaire, alice ses trois tableaux textuels (le propriétaire BLOB n'est pas elle), l'administrateur les
    /// quatre ; `GET /api/dashboard/{id}` ne sert à bob aucun des tableaux hors norme (jamais 200). Contrôle : un entier
    /// écrit dans ces colonnes est relu `text` (affinité TEXT), la valeur hors norme fabricable est le BLOB.
    #[tokio::test]
    async fn cc3_used_by_ne_compte_aucun_referent_par_les_octets_d_un_blob() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestes lisent l'environnement
        let (st, _p) = cc3_etat("ub");
        cc3_ecrire(
            &st,
            "INSERT INTO library_panel(name,title,query,is_soql,viz,drill,owner,visibility,created,updated) VALUES('cc3 commune','T','search | stats count',1,'table','','alice','shared',1000,1000);
             INSERT INTO dashboard(name,owner,visibility) VALUES('cc3 proprietaire blob',X'626F62','private');
             INSERT INTO dashboard(name,owner,visibility) VALUES('cc3 visibilite blob','alice',X'736861726564');
             INSERT INTO dashboard(name,owner,visibility) VALUES('cc3 visibilite du panneau blob','alice','shared');
             INSERT INTO dashboard(name,owner,visibility) VALUES('cc3 ordinaire','alice','shared');
             INSERT INTO panel(dashboard_id,title,query,is_soql,viz,visibility,position,library_panel_id)
                 SELECT id,'cc3','search | stats count',1,'table','shared',0,(SELECT MAX(id) FROM library_panel) FROM dashboard WHERE name LIKE 'cc3 %';
             UPDATE panel SET visibility=X'736861726564' WHERE dashboard_id=(SELECT id FROM dashboard WHERE name='cc3 visibilite du panneau blob');",
        );
        let lib = cc3_texte(&st, "SELECT CAST(MAX(id) AS TEXT) FROM library_panel").parse::<i64>().expect("contrôle : définition");
        assert_eq!(
            cc3_texte(&st, "SELECT group_concat(typeof(owner)||'/'||typeof(visibility),',') FROM (SELECT owner,visibility FROM dashboard ORDER BY id)"),
            "blob/text,text/blob,text/text,text/text",
            "contrôle : les BLOB sont en base"
        );
        assert_eq!(cc3_texte(&st, "SELECT typeof(visibility) FROM panel WHERE visibility=X'736861726564'"), "blob", "contrôle : BLOB du panneau");
        // Contrôle : un entier ne se fabrique pas dans ces trois colonnes (affinité TEXT), il est relu en texte.
        let ordinaire = "(SELECT id FROM dashboard WHERE name='cc3 ordinaire')";
        cc3_ecrire(&st, &format!("UPDATE dashboard SET owner=4242, visibility=7 WHERE id={ordinaire}; UPDATE panel SET visibility=5 WHERE dashboard_id={ordinaire};"));
        assert_eq!(
            cc3_texte(&st, &format!("SELECT typeof(d.owner)||'/'||typeof(d.visibility)||'/'||typeof(p.visibility) FROM dashboard d JOIN panel p ON p.dashboard_id=d.id WHERE d.id={ordinaire}")),
            "text/text/text",
            "contrôle : un entier écrit est relu en texte"
        );
        cc3_ecrire(&st, &format!("UPDATE dashboard SET owner='alice', visibility='shared' WHERE id={ordinaire}; UPDATE panel SET visibility='shared' WHERE dashboard_id={ordinaire};"));
        let addr = router_serve(st.clone()).await;
        for (qui, attendu) in [("bob", 1), ("carol", 1), ("alice", 3), ("adm", 4)] {
            let (code, t) = cc3_envoi(addr, qui, "GET", "/api/library-panels", "").await;
            let v = cc3_corps(&t);
            assert_eq!((code, v.get("error").is_none()), (200, true), "({qui}) la liste répond : {t}");
            let used_by = v["library_panels"].as_array().and_then(|a| a.iter().find(|l| l["id"].as_i64() == Some(lib))).and_then(|l| l["used_by"].as_i64());
            assert_eq!(used_by, Some(attendu), "({qui}) used_by ne compte que les référents que le lecteur lit : {t}");
        }
        for nom in ["cc3 proprietaire blob", "cc3 visibilite blob"] {
            let did = cc3_texte(&st, &format!("SELECT CAST(id AS TEXT) FROM dashboard WHERE name='{nom}'"));
            let (code, t) = cc3_envoi(addr, "bob", "GET", &format!("/api/dashboard/{did}"), "").await;
            assert_ne!(code, 200, "({nom}) dash_get ne sert pas ce tableau à bob : {t}");
        }
    }

    // ---------------------------------------------------------------------------------
    // (B2) LE PANNEAU ORPHELIN.
    // ---------------------------------------------------------------------------------
    /// CE QU'IL TIENT, par la route : l'administrateur crée un panneau sur un tableau absent (`POST /api/panels`, 200 :
    /// l'orphelin est atteignable sans écriture directe en base) ; bob (éditeur) puis carol (lectrice) reçoivent sur
    /// l'orphelin, pour `POST /api/panels/{id}`, `DELETE /api/panels/{id}` et `GET /api/panels/{id}/data`, la réponse
    /// d'un identifiant de panneau absent de la même route, à l'octet (statut, en-têtes hors date, corps) ; le panneau
    /// relu est inchangé ; l'administrateur le modifie (204), décision écrite au site.
    #[tokio::test]
    async fn cc3_panneau_orphelin_repond_comme_un_panneau_absent() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _p) = cc3_etat("orphelin");
        let addr = router_serve(st.clone()).await;
        let (code, t) = cc3_envoi(addr, "adm", "POST", "/api/panels", &format!(r#"{{"dashboard_id":{},"title":"orphelin","query":"search | stats count","is_soql":true}}"#, CC3_ABSENT - 1)).await;
        assert_eq!(code, 200, "contrôle : l'administrateur crée un panneau sur un tableau absent : {t}");
        let orphelin = cc3_corps(&t)["id"].as_i64().expect("contrôle : identifiant créé");
        assert_eq!(cc3_texte(&st, &format!("SELECT CAST(COUNT(*) AS TEXT) FROM dashboard WHERE id={}", CC3_ABSENT - 1)), "0", "contrôle : le tableau n'existe pas");
        let lire = |st: &AppState| cc3_texte(st, &format!("SELECT title||'|'||query||'|'||COALESCE(visibility,'') FROM panel WHERE id={orphelin}"));
        let avant = lire(&st);
        let gestes = [("POST", "/api/panels/{}", r#"{"title":"écrit"}"#), ("DELETE", "/api/panels/{}", ""), ("GET", "/api/panels/{}/data?from=0&to=0", "")];
        assert!(gestes.iter().filter(|(m, ..)| *m != "GET").count() >= 2, "plancher : modification et suppression jouées");
        for qui in ["bob", "carol"] {
            for (methode, chemin, corps) in gestes {
                let (_, absent) = cc3_envoi(addr, qui, methode, &chemin.replace("{}", &CC3_ABSENT.to_string()), corps).await;
                let (code, vu) = cc3_envoi(addr, qui, methode, &chemin.replace("{}", &orphelin.to_string()), corps).await;
                assert_eq!(cc3_sans_date(&vu), cc3_sans_date(&absent), "({qui}) {methode} {chemin} sur l'orphelin : la réponse d'un panneau absent ({code})");
            }
        }
        assert_eq!(lire(&st), avant, "rien n'est écrit sur l'orphelin");
        let (code, t) = cc3_envoi(addr, "adm", "POST", &format!("/api/panels/{orphelin}"), r#"{"title":"repris"}"#).await;
        assert_eq!(code, 204, "l'administrateur garde la main sur l'orphelin : {t}");
    }

    // ---------------------------------------------------------------------------------
    // (B3) LES BRANCHES « HEXADÉCIMAL ILLISIBLE », PAR APPEL DIRECT.
    // ---------------------------------------------------------------------------------
    #[test]
    fn cc3_texte_rendu_en_hex_refuse_ce_qui_n_est_pas_l_hexadecimal_de_sqlite() {
        use crate::handlers::panneau_resolu::texte_rendu_en_hex;
        assert_eq!(texte_rendu_en_hex("616C696365"), Some("alice".to_string()), "contrôle : hexadécimal lu");
        assert_eq!(texte_rendu_en_hex(""), Some(String::new()), "contrôle : vide lu");
        assert_eq!(texte_rendu_en_hex("FF"), Some("\u{FFFD}".to_string()), "contrôle : octet non UTF-8 remplacé");
        assert_eq!(texte_rendu_en_hex("+1"), None, "signe que u8::from_str_radix accepterait : refusé");
        assert_eq!(texte_rendu_en_hex("zz"), None, "non hexadécimal : refusé");
        assert_eq!(texte_rendu_en_hex("616"), None, "longueur impaire : refusée");
    }

    #[test]
    fn cc3_referents_lus_rend_une_erreur_sur_un_hexadecimal_illisible() {
        use crate::handlers::dash_ergonomics::referents_lus;
        let bob = AuthUser { name: "bob".into(), role: "editor".into(), tenant: "default".into(), is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None };
        let adm = AuthUser { name: "adm".into(), role: "admin".into(), ..bob.clone() };
        // Contrôle positif : un référent commun d'un tableau commun d'alice est compté par bob.
        assert_eq!(referents_lus(r#"[[1,"616C696365","736861726564","736861726564"]]"#, &bob).ok(), Some(1), "contrôle : référent lu et compté");
        for qui in [&bob, &adm] {
            for illisible in [r#"[[1,"+1","",""]]"#, r#"[[1,"616C696365","736861726564","73686172656"]]"#] {
                assert!(referents_lus(illisible, qui).is_err(), "({}) {illisible} : la liste est illisible, jamais un compte", qui.name);
            }
        }
    }

    // ---------------------------------------------------------------------------------
    // (A'') LA DESTRUCTION D'UN TENANT OUBLIE LES LIGNES DITES DE TOUTES LES NATURES.
    // ---------------------------------------------------------------------------------
    /// Toutes les natures, la correspondance exhaustive refuse de compiler si une nature neuve n'est pas ajoutée ici.
    fn cc3_toutes_les_natures() -> Vec<NatureDeLigneDite> {
        let toutes = vec![
            NatureDeLigneDite::ChargePerimeeNonCompilable,
            NatureDeLigneDite::CorpsDEchecPerimeNonCompilable,
            NatureDeLigneDite::LigneIllisibleNonCompilable,
            NatureDeLigneDite::LigneIllisibleSousEcritureRefusee,
            NatureDeLigneDite::ResultatDirectNonEcrit,
        ];
        for n in &toutes {
            match n {
                NatureDeLigneDite::ChargePerimeeNonCompilable
                | NatureDeLigneDite::CorpsDEchecPerimeNonCompilable
                | NatureDeLigneDite::LigneIllisibleNonCompilable
                | NatureDeLigneDite::LigneIllisibleSousEcritureRefusee
                | NatureDeLigneDite::ResultatDirectNonEcrit => {}
            }
        }
        toutes
    }

    #[test]
    fn cc3_base_detruite_oublie_les_lignes_dites_de_chaque_nature() {
        use crate::handlers::panneau_avoue::{dire_une_ligne_de_panneau, oublier_les_registres_d_une_base_detruite};
        let dir = crate::tmp_possede::TmpPossede::neuf("cc3-oubli-natures");
        let racine = std::fs::canonicalize(dir.racine().chemin()).expect("fixture : répertoire résolu");
        let chemin = |nom: &str| racine.join(nom).to_string_lossy().into_owned();
        let (detruite, gardee) = (chemin("detruite.db"), chemin("gardee.db"));
        let c_detruite = Connection::open(&detruite).expect("fixture : base détruite");
        let c_gardee = Connection::open(&gardee).expect("fixture : base gardée");
        assert_eq!(c_detruite.path().unwrap_or(""), detruite, "contrôle : SQLite nomme la base par ce chemin");
        let t = now();
        let natures = cc3_toutes_les_natures();
        assert_eq!(natures.len(), 5, "contrôle : cinq natures jouées");
        for conn in [&c_detruite, &c_gardee] {
            for id in [1, 2] {
                for &n in &natures {
                    assert!(dire_une_ligne_de_panneau(conn, id, n, t, CC3_TTL_PROPRE), "contrôle : première ligne {n:?} #{id} dite");
                    assert!(!dire_une_ligne_de_panneau(conn, id, n, t + 1, CC3_TTL_PROPRE), "contrôle : seconde ligne {n:?} #{id} tue");
                }
            }
        }

        oublier_les_registres_d_une_base_detruite(&detruite);

        for id in [1, 2] {
            for &n in &natures {
                assert!(
                    dire_une_ligne_de_panneau(&c_detruite, id, n, t + 2, CC3_TTL_PROPRE),
                    "base détruite puis recréée au même chemin : la première ligne {n:?} du panneau #{id} ressort"
                );
                assert!(
                    !dire_une_ligne_de_panneau(&c_gardee, id, n, t + 2, CC3_TTL_PROPRE),
                    "l'autre base garde sa ligne {n:?} du panneau #{id} : elle reste tue"
                );
            }
        }
    }
}
