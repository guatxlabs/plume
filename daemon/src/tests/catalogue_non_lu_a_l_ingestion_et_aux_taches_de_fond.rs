// =====================================================================================
// `P10.20-b` — UNE LIGNE DU CATALOGUE DES TENANTS QUI N'A PAS ÉTÉ LUE N'ÉCARTE PLUS UN LOT D'ÉVÉNEMENTS COMME SI SON
// TENANT N'EXISTAIT PAS, ET NE FAIT PLUS SAUTER UN TOUR DE FOND SOUS UNE CAUSE FAUSSE.
//
// LE DÉFAUT, LU SUR LA BASE AVANT LE CORRECTIF. `TenantDbManager::ready` rendait `None` pour une ligne de catalogue
// non lue comme pour un tenant absent ou suspendu, et son commentaire disait la différence « dite en amont, aux portes
// d'entrée » — ce qui ne valait pas pour les appelants qui n'y passent pas :
//   * l'ingestion du spool (`ingest_once`) mettait le lot en QUARANTAINE sous « tenant inconnu/suspendu », et le
//     dernier recours de `quarantine_spool_file` le DÉTRUISAIT si le déplacement échouait ;
//   * le parcours des tenants des tâches de fond (`for_each_active_tenant`) sautait le tour sous « tenant suspendu /
//     clé non résolue / schéma refusé » ;
//   * `req_db`, `req_db_path` et `handle_for` prenaient le cul-de-sac ou rendaient `None` sans un mot.
//
// LA FORME DU CORRECTIF est celle de `tenant_available_lu` : `ready_lu`, `handle_for_lu`, `ready_db_path_lu` et
// `resolve_ingest_target_lu` rendent `rusqlite::Result<Option<_>>` ; les formes à deux issues qui restent sont soit
// réservées aux témoins (`ready_db_path`, `resolve_ingest_target`), soit une projection qui DIT la lecture non faite
// au journal (`handle_for`, appelée hors de `state.rs`).
//
// LA VOIE D'ÉCHEC : la ligne du tenant illisible (`key_ref` en BLOB : la requête est saine, seul le mappeur échoue),
// rendue lisible au passage suivant ; et la TABLE RETIRÉE (renommée le temps d'un passage), qui rend toutes les lignes
// illisibles d'un coup. Deux tenants réels, provisionnés avec leur base.
//
// MUTANTS JOUÉS (posés sous `cfg!(test)` et `VERIF_MUT`, retirés avant le commit), chacun vu rouge seul :
// `CJ6_READY_ABSENT` (la ligne non lue rendue à l'absence dans `ready_lu`) ; `CJ6_INGEST_QUARANTAINE` (le bras `Err`
// de l'ingestion qui écarte le lot comme avant) ; `CJ6_INGEST_INGERE` (le lot laissé compté comme ingéré, pas comme
// abandon) ; `CJ6_ABSENT_LAISSE` (le bras `Ok(None)` qui laisse le lot en place au lieu de l'écarter) ;
// `CJ6_MODE0_LU` (le passthrough du mode 0 de `resolve_ingest_target_lu` retiré) ; `CJ6_CACHE_SERVI` (le writer chaud
// servi sur une lecture non faite) ; `CJ6_CACHE_EVINCE` (le writer chaud évincé sur une lecture non faite) ;
// `CJ6_REQ_DB_DEFAUT`, `CJ6_REQ_PATH_DEFAUT` (le chemin requête qui retombe sur la base du processus) ;
// `CJ6_JOBS_DEFAUT` (le tour de fond joué sur la base `default`) ; `CJ6_JOBS_PHRASE` (le tour sauté sous la phrase
// d'avant) ; `CJ6_LIGNE_TUE`, `CJ6_LIGNE_CHAQUE_FOIS`, `CJ6_JAMAIS_OUBLIE`, `CJ6_OUBLI_ABSENT`, `CJ6_TENANT_BRUT` (la
// ligne de l'ingestion : retirée, répétée à chaque fichier, jamais oubliée, oubliée seulement quand le lot est routé,
// tenant cité brut) ; `CJ6_ENTREE_NON_LOT` (le sous-répertoire de quarantaine compté et dit comme un lot du tenant
// `default`) ; `CJ6_REQ_DB_MUET`, `CJ6_REQ_PATH_MUET`, `CJ6_HANDLE_MUET` (chaque ligne du chemin requête et de
// la projection retirée) ; `CJ6_PLAFOND_STRICT`, `CJ6_SANS_PLAFOND` (la borne du mémo).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la liste des tenants actifs de `for_each_active_tenant` (`SELECT id FROM
// tenant WHERE suspended=0`) rend encore une liste VIDE sur une lecture ratée, sans un mot (aucune ligne n'est donc
// dite quand la table entière est illisible) ; les appelants de `handle_for` hors de `state.rs` (accès observé,
// traces d'opérateur, événement d'audit du tenant, suspension, récepteurs Pub/Sub et Firehose) gardent leur
// conduite à deux issues, la projection la dit seulement au journal.
// =====================================================================================
mod catalogue_non_lu_a_l_ingestion_et_aux_taches_de_fond {
    use super::*;

    const CJ6_A: &str = "cj6-a";
    const CJ6_B: &str = "cj6-b";
    const CJ6_FANTOME: &str = "cj6-fantome";
    const CJ6_ENFANT: &str = "CJ6_ENFANT_CATALOGUE_NON_LU_DIT_UNE_FOIS";
    const CJ6_PHASE: &str = "CJ6-PHASE:";
    /// La cause du moteur pour une ligne dont `key_ref` est un BLOB (lu en TEXT), et pour la table retirée.
    const CJ6_CAUSE_BLOB: &str = "Invalid column type Blob at index: 1, name: key_ref";
    const CJ6_CAUSE_TABLE: &str = "no such table: tenant";

    /// LES PHRASES, écrites ici en toutes lettres : le témoin ne compare jamais une sortie de la production à elle-même.
    fn cj6_ligne_ingest(tenant_echappe: &str, cause: &str) -> String {
        format!(
            "[ingest] tenant {tenant_echappe} : ligne du catalogue des tenants NON LUE ({cause}) -> ses lots RESTENT au \
             spool, intacts (ni quarantaine, ni effacement, rien d'ingéré) et seront repris sans geste dès qu'elle \
             se relira. Dit une fois jusqu'à la prochaine lecture réussie de cette ligne ; chaque lot laissé est \
             compté à chaque passage parmi les abandons de l'ingestion (santé)."
        )
    }
    fn cj6_ligne_jobs(tenant: &str, cause: &str) -> String {
        format!(
            "[multi-tenant][jobs] tenant '{tenant}' : ligne du catalogue des tenants NON LUE ({cause}) -> SKIP de ce \
             tour ; ce n'est ni un tenant suspendu, ni une clé non résolue, ni un schéma refusé (job NON \
             exécuté, ni sur sa base ni sur la base default)"
        )
    }
    fn cj6_ligne_req_db(tenant: &str, cause: &str) -> String {
        format!(
            "[multi-tenant] tenant '{tenant}' : ligne du catalogue des tenants NON LUE ({cause}) -> base cul-de-sac pour \
             cette requête (écriture) : rien n'est lu ni écrit, ni dans sa base ni dans celle d'un autre"
        )
    }
    fn cj6_ligne_req_path(tenant: &str, cause: &str) -> String {
        format!(
            "[multi-tenant] tenant '{tenant}' : ligne du catalogue des tenants NON LUE ({cause}) -> chemin cul-de-sac pour \
             cette requête (lecture) : rien n'est lu, ni dans sa base ni dans celle d'un autre"
        )
    }
    fn cj6_ligne_handle(tenant: &str, cause: &str) -> String {
        format!(
            "[multi-tenant] tenant '{tenant}' : ligne du catalogue des tenants NON LUE ({cause}) -> aucune base \
             servie à cet appel ; ce n'est ni un tenant absent ni un tenant suspendu"
        )
    }
    fn cj6_ligne_quarantaine(nom: &str) -> String {
        format!("[ingest] spool non routable (tenant inconnu/suspendu) -> quarantaine : {nom}")
    }

    /// Un plan de contrôle, le tenant `default` sur la base du processus, deux tenants réels provisionnés avec leur
    /// base (`cj6-a`, `cj6-b`), et un spool vide.
    fn cj6_etat() -> (AppState, crate::tmp_possede::TmpPossede) {
        let (mut st, dir) = mk_mode1_state();
        for t in [CJ6_A, CJ6_B] {
            let chemin = String::from(&*dir.sous(&format!("{t}.db")));
            assert!(tenant_provision(&st.tenants, t, t, &chemin, "").is_ok(), "fixture : {t} provisionné");
        }
        let spool = String::from(&*dir.sous("spool"));
        std::fs::create_dir_all(&spool).expect("fixture : spool");
        st.spool = Arc::new(spool);
        (st, dir)
    }

    fn cj6_plan(st: &AppState, sql: &str) {
        st.tenants
            .control
            .as_ref()
            .expect("fixture : mode 1")
            .conn
            .lock()
            .execute_batch(sql)
            .unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    fn cj6_illisible(st: &AppState, t: &str) {
        cj6_plan(st, &format!("UPDATE tenant SET key_ref=X'00' WHERE id='{t}';"));
    }
    fn cj6_lisible(st: &AppState, t: &str) {
        cj6_plan(st, &format!("UPDATE tenant SET key_ref='' WHERE id='{t}';"));
    }

    /// Un lot d'un événement pour `tenant`, sous la forme de nom des récepteurs (`<préfixe>-<ts>-<n>#T#<tenant>#T#.json`).
    fn cj6_lot(st: &AppState, n: u32, tenant: &str, source: &str) -> (std::path::PathBuf, String) {
        let nom = format!("ingest-1-{n}#T#{tenant}#T#.json");
        let chemin = std::path::Path::new(st.spool.as_str()).join(&nom);
        let corps = json!({ "kind": "events", "ts": now(), "data": { "events": [
            { "source": source, "category": "auth", "message": "m", "dedup": format!("cj6-{n}") }
        ] } })
        .to_string();
        std::fs::write(&chemin, &corps).expect("fixture : lot déposé");
        (chemin, nom)
    }

    fn cj6_evenements(st: &AppState, t: &str, source: &str) -> i64 {
        let h = st.tenants.handle_for(t).unwrap_or_else(|| panic!("contrôle : base de {t} servie"));
        let c = h.lock();
        c.query_row("SELECT COUNT(*) FROM event WHERE source=?1", params![source], |r| r.get(0))
            .unwrap_or_else(|e| panic!("contrôle : événements de {t} lus ({e})"))
    }

    fn cj6_quarantaine(st: &AppState) -> std::path::PathBuf {
        std::path::Path::new(st.spool.as_str()).join("quarantine")
    }

    // -------------------------------------------------------------------------------------
    // (1) L'INGESTION — le lot dont la ligne n'est pas lue reste au spool, intact, et s'ingère au passage suivant.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, par la vraie boucle (`ingest_once`, fichiers réels) : la ligne de A illisible pendant deux
    /// passages. Le lot de A reste au spool, ses octets inchangés ; aucune quarantaine n'existe ; rien n'est écrit
    /// dans la base de A ; il est compté parmi les abandons À CHAQUE passage (`Lue(1)`). Le lot de B, dans le même
    /// passage, s'ingère. La ligne relue, le passage suivant ingère le lot de A (`Lue(0)`), sans geste.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `CJ6_READY_ABSENT` et `CJ6_INGEST_QUARANTAINE` (lot écarté en quarantaine),
    /// `CJ6_INGEST_INGERE` (`Lue(0)` sur un lot laissé).
    #[test]
    fn cj6_lot_dont_la_ligne_n_est_pas_lue_reste_au_spool_et_s_ingere_au_passage_suivant() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = cj6_etat();
        let (lot_a, _) = cj6_lot(&st, 1, CJ6_A, "cj6srca");
        let (lot_b, _) = cj6_lot(&st, 2, CJ6_B, "cj6srcb");
        let octets = std::fs::read(&lot_a).expect("fixture : octets du lot");
        cj6_illisible(&st, CJ6_A);
        for passage in ["premier", "second"] {
            assert_eq!(ingest_once(&st.tenants, &st.spool), crate::mesure_environnement::Mesure::Lue(1), "{passage} passage : le lot laissé est un abandon COMPTÉ");
            assert_eq!(std::fs::read(&lot_a).ok().as_deref(), Some(octets.as_slice()), "{passage} passage : le lot RESTE au spool, intact");
            assert!(!cj6_quarantaine(&st).exists(), "{passage} passage : rien n'est écarté en quarantaine");
        }
        assert!(!lot_b.exists(), "le lot de B, lisible, s'ingère dans le même passage");
        cj6_lisible(&st, CJ6_A);
        assert_eq!(cj6_evenements(&st, CJ6_A, "cj6srca"), 0, "rien du lot de A n'a été écrit pendant la panne");
        assert_eq!(cj6_evenements(&st, CJ6_B, "cj6srcb"), 1, "contrôle : B ingéré");
        assert_eq!(ingest_once(&st.tenants, &st.spool), crate::mesure_environnement::Mesure::Lue(0), "la ligne relue : le passage suivant ingère tout");
        assert!(!lot_a.exists(), "le lot de A est ingéré puis retiré du spool");
        assert_eq!(cj6_evenements(&st, CJ6_A, "cj6srca"), 1, "ses événements sont dans la base de A, une fois");
        assert!(!cj6_quarantaine(&st).exists(), "toujours aucune quarantaine");
    }

    /// CE QU'IL TIENT : la conduite d'avant pour un tenant RÉELLEMENT absent du catalogue, et pour un tenant SUSPENDU —
    /// le lot part en quarantaine, sous son nom, octets intacts, et compte comme abandon (`Lue(2)`). La ligne du
    /// catalogue, elle, se lit.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `CJ6_ABSENT_LAISSE` (les deux lots restés au spool).
    #[test]
    fn cj6_tenant_absent_ou_suspendu_garde_la_quarantaine_d_avant() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = cj6_etat();
        let (absent, nom_absent) = cj6_lot(&st, 3, CJ6_FANTOME, "cj6srcf");
        let (suspendu, nom_suspendu) = cj6_lot(&st, 4, CJ6_B, "cj6srcs");
        let octets = (std::fs::read(&absent).expect("fixture"), std::fs::read(&suspendu).expect("fixture"));
        cj6_plan(&st, &format!("UPDATE tenant SET suspended=1 WHERE id='{CJ6_B}';"));
        assert_eq!(ingest_once(&st.tenants, &st.spool), crate::mesure_environnement::Mesure::Lue(2), "deux lots écartés, comptés");
        assert!(!absent.exists() && !suspendu.exists(), "les deux lots ont quitté la file");
        let q = cj6_quarantaine(&st);
        assert_eq!(std::fs::read(q.join(&nom_absent)).ok(), Some(octets.0), "tenant absent : le lot est en quarantaine, intact");
        assert_eq!(std::fs::read(q.join(&nom_suspendu)).ok(), Some(octets.1), "tenant suspendu : le lot est en quarantaine, intact");
    }

    /// CE QU'IL TIENT : le mode 0 (aucun plan de contrôle) ne lit aucun catalogue — un lot qui porte un marqueur de
    /// tenant (fichier en vol d'une installation passée par le mode 1) s'ingère dans la base unique, comme avant.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `CJ6_MODE0_LU` (le lot part en quarantaine).
    #[test]
    fn cj6_mode_zero_ne_lit_aucun_catalogue() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let spool = crate::tmp_possede::TmpPossede::neuf("cj6-mode0");
        let mut st = sso_test_state("plume-admin", "plume-editor", "admins");
        st.spool = Arc::new(spool.to_string_lossy().to_string());
        let (lot, _) = cj6_lot(&st, 5, CJ6_A, "cj6src0");
        assert_eq!(ingest_once(&st.tenants, &st.spool), crate::mesure_environnement::Mesure::Lue(0), "mode 0 : ingéré");
        assert!(!lot.exists(), "le lot quitte le spool");
        assert!(!cj6_quarantaine(&st).exists(), "aucune quarantaine");
        let n: i64 = st.db.lock().query_row("SELECT COUNT(*) FROM event WHERE source='cj6src0'", [], |r| r.get(0)).expect("lecture");
        assert_eq!(n, 1, "dans la base unique");
    }

    // -------------------------------------------------------------------------------------
    // (2) LE CACHE DES WRITERS — ni servi, ni évincé sur une lecture non faite.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : le writer de A chaud au cache. Ligne de A illisible : `handle_for_lu` rend `Err`, jamais le
    /// writer chaud ; le cache garde son entrée. Ligne relue : le MÊME writer (même `Arc`) est servi, sans réouverture.
    /// Puis A SUSPENDU pendant une nouvelle panne : à la relecture, `Ok(None)` — le writer chaud n'est jamais servi à un
    /// tenant suspendu entre-temps.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `CJ6_CACHE_SERVI` (le writer chaud rendu sur la lecture non faite),
    /// `CJ6_CACHE_EVINCE` (entrée retirée, writer différent à la relecture), `CJ6_READY_ABSENT` (`Ok(None)` au lieu d'`Err`).
    #[test]
    fn cj6_le_writer_chaud_n_est_ni_servi_ni_evince_sur_une_lecture_non_faite() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = cj6_etat();
        let chaud = match st.tenants.handle_for_lu(CJ6_A) {
            Ok(Some(h)) => h,
            autre => panic!("contrôle : writer de A servi ({:?})", autre.map(|o| o.is_some())),
        };
        cj6_illisible(&st, CJ6_A);
        let pendant = st.tenants.handle_for_lu(CJ6_A);
        assert!(pendant.is_err(), "ligne non lue : Err, ni writer ni absence ({:?})", pendant.map(|o| o.is_some()));
        assert!(st.tenants.writers.lock().contains_key(CJ6_A), "l'entrée du cache reste");
        cj6_lisible(&st, CJ6_A);
        match st.tenants.handle_for_lu(CJ6_A) {
            Ok(Some(h)) => assert!(Arc::ptr_eq(&h, &chaud), "relue : le MÊME writer, sans réouverture"),
            autre => panic!("relue : writer servi ({:?})", autre.map(|o| o.is_some())),
        }
        cj6_illisible(&st, CJ6_A);
        cj6_plan(&st, &format!("UPDATE tenant SET suspended=1 WHERE id='{CJ6_A}';"));
        assert!(st.tenants.handle_for_lu(CJ6_A).is_err(), "suspendu PENDANT la panne : toujours Err");
        cj6_lisible(&st, CJ6_A);
        assert!(matches!(st.tenants.handle_for_lu(CJ6_A), Ok(None)), "relue suspendue : rien, jamais le writer chaud");
    }

    // -------------------------------------------------------------------------------------
    // (3) LE CHEMIN REQUÊTE ET LES TÂCHES DE FOND.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : ligne de A illisible (writer de A chaud au cache, la base du processus lisible). `req_db` ne
    /// rend ni le writer de A ni celui du processus, et rien ne s'y lit ; `req_db_path` rend le chemin cul-de-sac.
    /// Contrôle positif, ligne relue : le writer de A et son chemin.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `CJ6_REQ_DB_DEFAUT`, `CJ6_REQ_PATH_DEFAUT` (base du processus servie),
    /// `CJ6_CACHE_SERVI` (writer chaud).
    #[test]
    fn cj6_chemin_requete_sur_une_ligne_non_lue_prend_le_cul_de_sac() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = cj6_etat();
        let au = AuthUser { name: "cj6-ana".into(), role: "admin".into(), tenant: CJ6_A.into(), is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None };
        let chaud = st.tenants.handle_for(CJ6_A).expect("contrôle : writer de A");
        let chemin_a = st.tenants.ready_db_path(CJ6_A).expect("contrôle : chemin de A");
        cj6_illisible(&st, CJ6_A);
        let h = req_db(&st, &au);
        let p = req_db_path(&st, &au);
        cj6_lisible(&st, CJ6_A);
        assert!(!Arc::ptr_eq(&h, &chaud) && !Arc::ptr_eq(&h, &st.db), "ni le writer de A ni la base du processus");
        assert!(h.lock().query_row("SELECT COUNT(*) FROM event", [], |r| r.get::<_, i64>(0)).is_err(), "rien ne s'y lit");
        assert_eq!(p, UNAVAILABLE_TENANT_DB_PATH, "le chemin cul-de-sac");
        assert!(Arc::ptr_eq(&req_db(&st, &au), &chaud), "relue : le writer de A");
        assert_eq!(req_db_path(&st, &au), chemin_a, "relue : le chemin de A");
    }

    /// CE QU'IL TIENT : ligne de A illisible, le parcours des tâches de fond appelle le corps pour `default` et B, chacun
    /// avec SA base, et jamais pour A — ni sur la base de A, ni sur la base `default` à sa place. Contrôle positif,
    /// ligne relue : les trois.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `CJ6_JOBS_DEFAUT` (le corps appelé pour A sur la base `default`),
    /// `CJ6_READY_ABSENT` n'y change rien (les deux issues sautent) : c'est la phrase qui les distingue, témoin (5).
    #[test]
    fn cj6_tour_de_fond_saute_le_tenant_dont_la_ligne_n_est_pas_lue() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = cj6_etat();
        let chemin = |t: &str| st.tenants.ready_db_path(t).unwrap_or_else(|| panic!("contrôle : chemin de {t}"));
        let tous = vec![
            ("default".to_string(), chemin("default")),
            (CJ6_A.to_string(), chemin(CJ6_A)),
            (CJ6_B.to_string(), chemin(CJ6_B)),
        ];
        let parcours = |st: &AppState| {
            let mut vus: Vec<(String, String)> = Vec::new();
            for_each_active_tenant(&st.tenants, |tid, _h, p| vus.push((tid.to_string(), p.to_string())));
            vus
        };
        assert_eq!(parcours(&st), tous, "contrôle : les trois tenants, chacun sur sa base");
        cj6_illisible(&st, CJ6_A);
        let vus = parcours(&st);
        cj6_lisible(&st, CJ6_A);
        assert_eq!(vus, vec![tous[0].clone(), tous[2].clone()], "A est sauté ; default et B tournent sur leur base");
        assert_eq!(parcours(&st), tous, "relue : les trois");
    }

    // -------------------------------------------------------------------------------------
    // (4) LA BORNE DU MÉMO — fonction pure, sur un ensemble local.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : une première occurrence est notée, une seconde non ; sous la borne, un tenant neuf est noté et
    /// remplit l'ensemble jusqu'à elle ; À la borne, un tenant neuf n'est ni noté ni mémorisé, un tenant connu non plus.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `CJ6_PLAFOND_STRICT` (`>` au lieu de `>=` : un de plus noté à la borne),
    /// `CJ6_SANS_PLAFOND` (la borne retirée).
    #[test]
    fn cj6_le_memo_des_lignes_dites_est_borne() {
        let mut memo = std::collections::HashSet::new();
        assert!(noter_un_catalogue_non_lu(&mut memo, "t-0"), "première occurrence : notée");
        assert!(!noter_un_catalogue_non_lu(&mut memo, "t-0"), "seconde : tue");
        while memo.len() + 1 < CATALOGUE_NON_LU_MEMO_MAX {
            let n = memo.len();
            assert!(noter_un_catalogue_non_lu(&mut memo, &format!("t-{n}")), "sous la borne : notée");
        }
        assert_eq!(memo.len(), CATALOGUE_NON_LU_MEMO_MAX - 1, "contrôle : une place sous la borne");
        assert!(noter_un_catalogue_non_lu(&mut memo, "derniere-place"), "borne - 1 : notée");
        assert_eq!(memo.len(), CATALOGUE_NON_LU_MEMO_MAX, "la borne est atteinte");
        assert!(!noter_un_catalogue_non_lu(&mut memo, "au-dela"), "à la borne : un tenant neuf n'est pas noté");
        assert!(!noter_un_catalogue_non_lu(&mut memo, "t-0"), "à la borne : un tenant connu non plus");
        assert_eq!(memo.len(), CATALOGUE_NON_LU_MEMO_MAX, "rien n'est mémorisé au-delà");
        assert!(!memo.contains("au-dela"), "le tenant neuf n'est pas dans le mémo");
    }

    // -------------------------------------------------------------------------------------
    // (5) LE JOURNAL, PAR CAPTURE — sous-processus, phases séparées par un marqueur.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, ligne ENTIÈRE par ligne entière, phase par phase (l'ordre des fichiers d'un même passage n'est pas
    /// fixé, les lignes d'une phase se comparent triées) :
    ///   1. ligne de A illisible ; deux lots de A, un de B, un d'un tenant absent : UNE ligne pour A (pas une par lot),
    ///      la ligne de quarantaine d'avant pour l'absent. Rien n'est consommé de A (compteurs de fichiers et
    ///      d'événements : le seul lot de B) ;
    ///   2. second passage, même panne : AUCUNE ligne ;
    ///   3. même panne : le tour de fond, `req_db`, `req_db_path` et `handle_for` disent chacun la ligne non lue ;
    ///   4. ligne relue, passage : aucune ligne, les lots de A ingérés ;
    ///   5. table retirée ; un lot de A, un de B, un lot dont le marqueur porte un saut de ligne : une ligne pour CHACUN
    ///      (A est dit de nouveau : relu entre-temps), le marqueur forgé cité échappé, sur UNE ligne ; le sous-répertoire
    ///      `quarantine` (créé en phase 1, sans marqueur, donc lu comme `default`) n'est ni compté ni dit ;
    ///   6. table remise, B suspendu entre-temps (sa ligne n'a pas été relue avec succès depuis la phase 5) : le lot
    ///      de A s'ingère, celui de B part en quarantaine (ligne d'avant) ;
    ///   7. B réactivé puis sa ligne illisible : B est dit de nouveau (la lecture qui l'a écarté l'a aussi oublié).
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `CJ6_LIGNE_TUE`, `CJ6_LIGNE_CHAQUE_FOIS`, `CJ6_JAMAIS_OUBLIE`,
    /// `CJ6_OUBLI_ABSENT`, `CJ6_TENANT_BRUT`, `CJ6_ENTREE_NON_LOT`, `CJ6_JOBS_PHRASE`, `CJ6_REQ_DB_MUET`, `CJ6_REQ_PATH_MUET`, `CJ6_HANDLE_MUET`.
    #[test]
    fn cj6_la_ligne_non_lue_est_dite_une_fois_par_tenant_et_par_panne() {
        if std::env::var(CJ6_ENFANT).is_ok() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
            cj6_enfant();
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::catalogue_non_lu_a_l_ingestion_et_aux_taches_de_fond::cj6_la_ligne_non_lue_est_dite_une_fois_par_tenant_et_par_panne",
            ])
            .env(CJ6_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let mut phases: Vec<Vec<String>> = Vec::new();
        for l in stderr.lines() {
            if l.starts_with(CJ6_PHASE) {
                phases.push(Vec::new());
            } else if let Some(courante) = phases.last_mut() {
                if l.starts_with("[ingest] ") || l.starts_with("[multi-tenant]") {
                    courante.push(l.to_string());
                }
            }
        }
        for p in phases.iter_mut() {
            p.sort();
        }
        let trie = |mut v: Vec<String>| {
            v.sort();
            v
        };
        let attendu: Vec<Vec<String>> = vec![
            trie(vec![cj6_ligne_ingest("\"cj6-a\"", CJ6_CAUSE_BLOB), cj6_ligne_quarantaine("ingest-1-13#T#cj6-fantome#T#.json")]),
            vec![],
            trie(vec![
                cj6_ligne_jobs(CJ6_A, CJ6_CAUSE_BLOB),
                cj6_ligne_req_db(CJ6_A, CJ6_CAUSE_BLOB),
                cj6_ligne_req_path(CJ6_A, CJ6_CAUSE_BLOB),
                cj6_ligne_handle(CJ6_A, CJ6_CAUSE_BLOB),
            ]),
            vec![],
            trie(vec![
                cj6_ligne_ingest("\"cj6-a\"", CJ6_CAUSE_TABLE),
                cj6_ligne_ingest("\"cj6-b\"", CJ6_CAUSE_TABLE),
                cj6_ligne_ingest("\"x\\ny\"", CJ6_CAUSE_TABLE),
            ]),
            vec![cj6_ligne_quarantaine("ingest-1-16#T#cj6-b#T#.json")],
            vec![cj6_ligne_ingest("\"cj6-b\"", CJ6_CAUSE_BLOB)],
        ];
        assert!(attendu.len() >= 7, "plancher : sept phases attendues");
        assert_eq!(phases.len(), attendu.len(), "une entrée par phase marquée :\n{stderr}");
        for (i, (vu, att)) in phases.iter().zip(attendu.iter()).enumerate() {
            assert_eq!(vu, att, "phase {} : lignes ENTIÈRES, aucune autre :\n{stderr}", i + 1);
        }
    }

    /// Le corps joué par l'enfant ; chaque phase ouvre par son marqueur sur la sortie d'erreur.
    fn cj6_enfant() {
        use std::sync::atomic::Ordering::Relaxed;
        let (st, _dir) = cj6_etat();
        let au = AuthUser { name: "cj6-ana".into(), role: "admin".into(), tenant: CJ6_A.into(), is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None };
        let phase = |n: u32| eprintln!("{CJ6_PHASE}{n}");
        let (lot_a1, _) = cj6_lot(&st, 11, CJ6_A, "cj6ja");
        let (lot_a2, _) = cj6_lot(&st, 12, CJ6_A, "cj6ja");
        cj6_lot(&st, 13, CJ6_FANTOME, "cj6jf");
        cj6_lot(&st, 14, CJ6_B, "cj6jb");
        cj6_illisible(&st, CJ6_A);
        let (fichiers, evenements) = (crate::INGEST_FILES_TOTAL.load(Relaxed), crate::INGEST_EVENTS_TOTAL.load(Relaxed));

        phase(1);
        assert_eq!(ingest_once(&st.tenants, &st.spool), crate::mesure_environnement::Mesure::Lue(3), "enfant : deux lots de A laissés, l'absent écarté");
        assert_eq!(crate::INGEST_FILES_TOTAL.load(Relaxed) - fichiers, 1, "enfant : seul le lot de B est consommé");
        assert_eq!(crate::INGEST_EVENTS_TOTAL.load(Relaxed) - evenements, 1, "enfant : seul l'événement de B est compté");
        phase(2);
        assert_eq!(ingest_once(&st.tenants, &st.spool), crate::mesure_environnement::Mesure::Lue(2), "enfant : les deux lots de A, encore");
        phase(3);
        for_each_active_tenant(&st.tenants, |_, _, _| {});
        let _ = req_db(&st, &au);
        let _ = req_db_path(&st, &au);
        assert!(st.tenants.handle_for(CJ6_A).is_none(), "enfant : la projection ne sert rien");
        phase(4);
        cj6_lisible(&st, CJ6_A);
        assert_eq!(ingest_once(&st.tenants, &st.spool), crate::mesure_environnement::Mesure::Lue(0), "enfant : relue, tout s'ingère");
        assert!(!lot_a1.exists() && !lot_a2.exists(), "enfant : les lots de A sont ingérés");
        phase(5);
        cj6_lot(&st, 15, CJ6_A, "cj6ja");
        cj6_lot(&st, 16, CJ6_B, "cj6jb");
        let (forge, nom_forge) = cj6_lot(&st, 19, "x\ny", "cj6jx");
        cj6_plan(&st, "ALTER TABLE tenant RENAME TO cj6_tenant;");
        let bilan = ingest_once(&st.tenants, &st.spool);
        // B suspendu AVANT toute relecture réussie de sa ligne : la prochaine lecture l'écartera sans l'avoir routé.
        cj6_plan(&st, &format!("UPDATE cj6_tenant SET suspended=1 WHERE id='{CJ6_B}'; ALTER TABLE cj6_tenant RENAME TO tenant;"));
        assert_eq!(bilan, crate::mesure_environnement::Mesure::Lue(3), "enfant : trois lots laissés, le sous-répertoire de quarantaine non compté");
        assert!(forge.exists() && !cj6_quarantaine(&st).join(&nom_forge).exists(), "enfant : le lot forgé reste aussi, il n'est pas écarté");
        // Retiré à la main : sa quarantaine écrirait son nom, saut de ligne compris, dans la phase suivante.
        std::fs::remove_file(&forge).expect("enfant : lot forgé retiré");
        phase(6);
        assert_eq!(ingest_once(&st.tenants, &st.spool), crate::mesure_environnement::Mesure::Lue(1), "enfant : A ingéré, B suspendu écarté");
        assert_eq!(cj6_evenements(&st, CJ6_A, "cj6ja"), 3, "enfant : les trois lots de A, une fois chacun");
        phase(7);
        cj6_plan(&st, &format!("UPDATE tenant SET suspended=0 WHERE id='{CJ6_B}';"));
        cj6_illisible(&st, CJ6_B);
        cj6_lot(&st, 18, CJ6_B, "cj6jb");
        assert_eq!(ingest_once(&st.tenants, &st.spool), crate::mesure_environnement::Mesure::Lue(1), "enfant : B laissé");
        cj6_lisible(&st, CJ6_B);
    }
}
