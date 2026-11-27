// =====================================================================================
// `P10.20-b` — UN TENANT ACTIF DONT LA BASE NE S'OUVRE PAS POUR UNE CAUSE DU MOMENT N'EST PLUS PRIS POUR UN TENANT ABSENT
// OU SUSPENDU.
//
// LE DÉFAUT, LU SUR LA BASE AVANT LE CORRECTIF. `TenantDbManager::catalog_route` rendait `Ok(None)` pour trois faits : la
// ligne du tenant absente, le tenant suspendu, et le tenant ACTIF dont la clé n'était pas résolue (`resolve_tenant_key`
// en erreur : un coffre de secrets injoignable). `ready_lu` y ajoutait un quatrième : la base du tenant actif non ouverte
// ou non préparée (`PreparedWriter::open` en erreur). Les appelants lisaient ce `None` comme « tenant inconnu ou
// suspendu » : le consommateur du spool rangeait un lot VALIDE en quarantaine, la porte de l'accès inter-tenants servait
// le 403 d'une absence, les tâches de fond sautaient le tenant sous la cause d'une suspension, et les deux lignes de
// journal revenaient à CHAQUE requête et à CHAQUE passe pendant toute la panne.
//
// LA SUSPENSION NE DÉPEND PAS DE L'OUVERTURE DE LA BASE. Un exploitant doit pouvoir suspendre un tenant précisément quand
// sa base est cassée ou compromise, ou que le coffre de ses clés est injoignable : la suspension d'un tenant actif non
// ouvrable est FAITE et tracée au journal de contrôle, et l'événement d'audit que sa base ne peut pas recevoir est avoué
// à côté du succès sous sa phrase à elle. La porte d'entrée d'`auth_guard` sert au membre d'un tenant actif non ouvert le
// refus nommé des autres portes (503). Et le verrou du plan de contrôle n'est plus tenu pendant la résolution d'une clé :
// la ligne est relue sous le verrou avant tout enregistrement de la clé.
//
// LES DEUX VOIES D'ÉCHEC, RÉALISTES, SANS TOUCHER AU CODE DE PRODUCTION :
//   * CLÉ NON RÉSOLUE : le tenant A est provisionné sur une clé `vault:<chemin>` dont la valeur est au cache du client
//     Vault (comme après une résolution réussie) ; le coffre n'étant pas configuré dans le processus de test, retirer la
//     valeur du cache (`vault_key_cache_forget`) est exactement ce que vit un démon redémarré pendant que le coffre est
//     injoignable : la résolution échoue. Le retour de la cause : la valeur remise au cache, comme le coffre la rendrait.
//   * BASE NON OUVERTE : la base de A vit dans son propre répertoire ; ce répertoire est mis de côté et remplacé par un
//     FICHIER ordinaire, si bien que l'ouverture de `<répertoire>/plume.db` échoue (ENOTDIR, même pour root), après avoir
//     vidé le cache des écrivains comme le fait un redémarrage. Le retour : le répertoire remis à sa place.
// Deux tenants réels à chaque fois : B, sain, est servi pendant toute la panne de A.
//
// MUTANTS JOUÉS (posés sous `cfg!(test)` et `VERIF_MUT`, retirés avant le commit), chacun vu rouge seul :
// `CL1_CLE_NON_SERVABLE` (la clé non résolue rendue à « non servable » dans `catalog_route`) ;
// `CL1_BASE_NON_SERVABLE` (la base non ouverte rendue à « non servable » dans `ready_lu`) ; `CL1_INGEST_QUARANTAINE`
// (le lot du tenant non ouvert écarté en quarantaine) ; `CL1_INGEST_INGERE` (le lot laissé compté comme ingéré) ;
// `CL1_ENTREE_NON_LOT` (le sous-répertoire de quarantaine compté et dit comme un lot) ; `CL1_CACHE_SERVI` (l'écrivain
// chaud servi sans clé résolue) ; `CL1_JOBS_DEFAUT` (le tour de fond joué sur la base `default`) ; `CL1_REQ_DB_DEFAUT`,
// `CL1_REQ_PATH_DEFAUT` (le chemin requête sur la base du processus) ; `CL1_PUSH_NON_SERVABLE` (la livraison poussée
// refusée comme une source morte) ; `CL1_PORTE_403` (la porte de l'accès inter-tenants rendue au 403 d'une absence) ;
// `CL1_PORTE_CAUSE_SERVIE` (la classe ajoutée à la réponse de la porte) ; `CL1_AUDIT_CATALOGUE` (l'événement d'audit
// avoué sous la phrase d'une ligne non lue) ; `CL1_ACCES_DEFAUT` (l'accès observé inscrit dans la
// base du processus) ; `CL1_OPERATEUR_CAUSE` (la trace d'opérateur perdue sous « base non résoluble ») ;
// `CL1_LIGNE_CHAQUE_FOIS`, `CL1_JAMAIS_OUBLIE`, `CL1_CLASSE_IGNOREE` (la ligne de `state.rs` : redite à chaque appel,
// jamais oubliée, classe nouvelle tue) ; `CL1_BORNE_MUETTE`, `CL1_SANS_BORNE` (la borne du mémo : tenant neuf tu,
// borne retirée) ; `CL1_SPOOL_CHAQUE_FOIS`, `CL1_SPOOL_JAMAIS_OUBLIE`, `CL1_SPOOL_TENANT_BRUT` (la ligne du spool) ;
// `CL1_CATALOGUE_NON_OUBLIE` (la panne de lecture du catalogue non oubliée quand la ligne se relit sur un tenant non
// ouvert) ; `CL1_JOBS_PHRASE` (le tour sauté sous la phrase d'une suspension) ; `CL1_PASSAGE_SANS_MEMO` (le tenant trouvé
// non ouvert retenté à chaque lot du passage) ; `CL1_OUBLI_CACHE`, `CL1_OUBLI_OUVERT` (la ligne de `state.rs` non oubliée
// quand l'écrivain chaud est servi, ou après une ouverture réussie), chacun seul. Puis, sur la suspension faite, la
// porte d'entrée et le verrou : `CL2_REFUS_CLE`, `CL2_REFUS_BASE` (le refus `503` de la suspension remis pour chaque
// cause) ; `CL2_AVEU_RETIRE` ; `CL2_CAUSE_SERVIE` ; `CL2_PORTE_D_ENTREE_403` ; `CL2_VERROU_TENU` ; `CL2_SANS_RELECTURE`,
// `CL2_RELECTURE_CHEMIN_SEUL`, `CL2_RELECTURE_CLE_SEULE`, `CL2_RELECTURE_SANS_SUSPENSION`, `CL2_ENREGISTRE_AU_CHEMIN_RELU`
// (la relecture de la ligne avant l'enregistrement de la clé) ; `CL2_SANS_OUBLI`, `CL2_OUBLI_TOUJOURS` (le cache du
// client du coffre) ; `V2_I_PASSAGE_ENTREE` (l'entrée hors lot dans la carte du passage, `ingest/mod.rs`), chacun seul.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : les bras de réponse des récepteurs poussés, hors d'atteinte par la route (aucune
// clé poussée en mode multi-tenant), tenus par l'appel direct de l'aide partagée ; une base non ouverte n'est vue par
// aucune porte (elles ne jugent que la clé), mais par le premier geste qui demande la base ; la latence d'UNE tentative
// vers un coffre muet (délai de lecture du client, sans délai de connexion borné), payée une fois par tenant et par
// passage dans le fil d'ingestion ; rien ne borne le spool pendant qu'une base reste non ouvrable.
// =====================================================================================
mod tenant_actif_non_ouvrable_n_est_pas_un_tenant_absent {
    use super::*;
    use super::revocation_globale_sans_cookie_et_comptes_du_mode_un::{rgsc_connexion, rgsc_envoyer, rgsc_plateforme};

    pub(super) const CL1_A: &str = "cl1-a";
    const CL1_B: &str = "cl1-b";
    const CL1_ENFANT: &str = "CL1_ENFANT_TENANT_NON_OUVERT_DIT_UNE_FOIS";
    const CL1_PHASE: &str = "CL1-PHASE:";
    /// Le texte du résolveur quand le coffre n'est pas configuré et que la clé n'est pas au cache.
    const CL1_DETAIL_CLE: &str = "vault: mais PLUME_VAULT_ADDR non défini (FAIL-CLOSED)";

    /// LES PHRASES, écrites ici en toutes lettres : le témoin ne compare jamais une sortie de la production à elle-même.
    const CL1_PHRASE_PORTE: &str = "BASE DU TENANT NON OUVERTE : le tenant demandé est actif, mais sa base n'a pas pu être \
         ouverte pour une cause du moment (clé non résolue ou base indisponible) — ce n'est PAS « tenant inconnu ou \
         indisponible » : rien n'est servi ni écrit, ni dans sa base ni dans une autre. Réessayez une fois sa base de \
         nouveau ouvrable.";
    /// L'aveu, à côté du succès de la suspension, de l'événement d'audit que la base non ouvrable n'a pas pu recevoir.
    const CL2_PHRASE_EVENEMENT_BASE_NON_OUVERTE: &str = "ÉVÉNEMENT DU TENANT NON ÉCRIT : le geste d'administration a bien \
         eu lieu, mais la base de ce tenant n'a pas pu être ouverte (clé non résolue ou base indisponible) — l'événement \
         d'audit qui le lui montre n'y est pas écrit, et ce tenant ne verra pas ce changement parmi ses propres événements, \
         même une fois servi de nouveau.";
    const CL1_PHRASE_SANS_BASE_SERVIE: &str = "ÉVÉNEMENT DU TENANT NON ÉCRIT : le geste d'administration a bien eu lieu, \
         mais la base de ce tenant n'est pas servie (un tenant suspendu ne l'est pas) — l'événement d'audit qui le lui \
         montre n'y est pas écrit, et ce tenant ne verra pas ce changement parmi ses propres événements, même une fois \
         servi de nouveau.";

    fn cl1_ligne_cle(tenant: &str) -> String {
        format!(
            "[multi-tenant] tenant '{tenant}' : clé non résolue -> FAIL-CLOSED, base NON ouverte ({CL1_DETAIL_CLE}). Ce \
             n'est ni un tenant absent ni un tenant suspendu : dit une fois jusqu'à la prochaine ouverture réussie de sa base."
        )
    }
    fn cl1_ligne_base(tenant: &str, chemin: &str) -> String {
        format!(
            "[multi-tenant] tenant '{tenant}' : base NON servie — ouverture impossible (unable to open database file: \
             {chemin}). Aucune requête ne sera routée vers elle ; déployer un binaire compatible ou réparer la base, puis \
             réessayer. Ce n'est ni un tenant absent ni un tenant suspendu : dit une fois jusqu'à la prochaine ouverture \
             réussie de sa base."
        )
    }
    fn cl1_ligne_spool(tenant_echappe: &str, mot: &str) -> String {
        format!(
            "[ingest] tenant {tenant_echappe} : base du tenant NON ouverte ({mot}) -> ses lots RESTENT au spool, intacts (ni \
             quarantaine, ni effacement, rien d'ingéré) et seront repris sans geste dès qu'elle s'ouvrira. Ce n'est ni un \
             tenant inconnu ni un tenant suspendu. Dit une fois jusqu'à la prochaine ouverture réussie ; chaque lot laissé \
             est compté à chaque passage parmi les abandons de l'ingestion (santé)."
        )
    }
    fn cl1_ligne_catalogue(tenant_echappe: &str, cause: &str) -> String {
        format!(
            "[ingest] tenant {tenant_echappe} : ligne du catalogue des tenants NON LUE ({cause}) -> ses lots RESTENT au \
             spool, intacts (ni quarantaine, ni effacement, rien d'ingéré) et seront repris sans geste dès qu'elle \
             se relira. Dit une fois jusqu'à la prochaine lecture réussie de cette ligne ; chaque lot laissé est \
             compté à chaque passage parmi les abandons de l'ingestion (santé)."
        )
    }
    fn cl1_ligne_trace(cause: &str) -> String {
        format!(
            "[plume] accès opérateur cross-tenant SANS sa trace 'tenant.plume-operator-access.write' (l'accès n'est servi \
             que si l'autre trace est écrite) : {cause}"
        )
    }

    /// Un mode multi-tenant à DEUX tenants réels : A dans son propre répertoire, sur une clé `vault:` dont la valeur est
    /// au cache ; B en clair. Un spool vide. Rend aussi la clé de cache de A (`chemin#key`) et sa valeur.
    pub(super) struct Cl1 {
        pub(super) st: AppState,
        pub(super) dir: crate::tmp_possede::TmpPossede,
        rangement: String,
        pub(super) cle: String,
    }

    impl Cl1 {
        pub(super) fn neuf(tag: &str) -> Self {
            let (mut st, dir) = mk_mode1_state();
            let coffre = format!("cl1-coffre/{tag}/{}", sha256_hex(format!("{dir}").as_bytes()));
            let rangement = format!("{coffre}#key");
            let cle = sha256_hex(rangement.as_bytes());
            crate::crypto::vault_key_cache_put(&rangement, &cle);
            let chemin_a = String::from(&*dir.sous(&format!("{CL1_A}/plume.db")));
            assert!(tenant_provision(&st.tenants, CL1_A, CL1_A, &chemin_a, &format!("vault:{coffre}")).is_ok(), "fixture : A provisionné sur sa clé Vault");
            let chemin_b = String::from(&*dir.sous(&format!("{CL1_B}.db")));
            assert!(tenant_provision(&st.tenants, CL1_B, CL1_B, &chemin_b, "").is_ok(), "fixture : B provisionné");
            let spool = String::from(&*dir.sous("spool"));
            std::fs::create_dir_all(&spool).expect("fixture : spool");
            st.spool = Arc::new(spool);
            Cl1 { st, dir, rangement, cle }
        }

        fn repertoire_a(&self) -> std::path::PathBuf {
            std::path::PathBuf::from(&*self.dir.sous(CL1_A))
        }
        pub(super) fn chemin_a(&self) -> String {
            String::from(&*self.dir.sous(&format!("{CL1_A}/plume.db")))
        }

        /// Le coffre ne rend plus la clé de A (cache vidé, coffre non configuré).
        pub(super) fn cle_perdue(&self) {
            crate::crypto::vault_key_cache_forget(&self.rangement);
        }
        /// Le coffre rend de nouveau la clé de A.
        fn cle_rendue(&self) {
            crate::crypto::vault_key_cache_put(&self.rangement, &self.cle);
        }
        /// Le répertoire de A indisponible : écrivain retiré du cache (redémarrage), répertoire mis de côté et remplacé
        /// par un fichier ordinaire.
        fn base_perdue(&self) {
            self.st.tenants.writers.lock().remove(CL1_A);
            let rep = self.repertoire_a();
            std::fs::rename(&rep, rep.with_extension("hors")).expect("fixture : répertoire de A mis de côté");
            std::fs::write(&rep, b"pas un repertoire").expect("fixture : fichier à la place du répertoire");
        }
        /// Le répertoire de A remis à sa place.
        fn base_rendue(&self) {
            let rep = self.repertoire_a();
            std::fs::remove_file(&rep).expect("fixture : fichier retiré");
            std::fs::rename(rep.with_extension("hors"), &rep).expect("fixture : répertoire de A remis");
        }

        fn plan(&self, sql: &str) {
            self.st
                .tenants
                .control
                .as_ref()
                .expect("fixture : mode 1")
                .conn
                .lock()
                .execute_batch(sql)
                .unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
        }

        /// Un lot d'un événement pour `tenant`, sous la forme de nom des récepteurs.
        fn lot(&self, n: u32, tenant: &str, source: &str) -> (std::path::PathBuf, String) {
            let nom = format!("ingest-1-{n}#T#{tenant}#T#.json");
            let chemin = std::path::Path::new(self.st.spool.as_str()).join(&nom);
            let corps = json!({ "kind": "events", "ts": now(), "data": { "events": [
                { "source": source, "category": "auth", "message": "m", "dedup": format!("cl1-{n}") }
            ] } })
            .to_string();
            std::fs::write(&chemin, &corps).expect("fixture : lot déposé");
            (chemin, nom)
        }

        fn evenements(&self, t: &str, source: &str) -> i64 {
            let h = self.st.tenants.handle_for(t).unwrap_or_else(|| panic!("contrôle : base de {t} servie"));
            let c = h.lock();
            c.query_row("SELECT COUNT(*) FROM event WHERE source=?1", params![source], |r| r.get(0))
                .unwrap_or_else(|e| panic!("contrôle : événements de {t} lus ({e})"))
        }

        fn quarantaine(&self) -> std::path::PathBuf {
            std::path::Path::new(self.st.spool.as_str()).join("quarantine")
        }
    }

    /// Le coffre n'est pas configuré dans ce processus : la clé de A ne résout que par le cache.
    pub(super) fn cl1_sans_coffre() {
        std::env::remove_var("PLUME_VAULT_ADDR");
        std::env::remove_var("PLUME_VAULT_TOKEN");
        std::env::remove_var("PLUME_VAULT_TOKEN_FILE");
    }

    pub(super) fn cl1_issue<T>(o: &rusqlite::Result<OuvertureDuTenant<T>>) -> String {
        match o {
            Ok(OuvertureDuTenant::Servie(_)) => "servie".into(),
            Ok(OuvertureDuTenant::NonServable) => "non servable".into(),
            Ok(OuvertureDuTenant::NonOuvert(c)) => format!("non ouvert : {}", c.classe.mot()),
            Err(e) => format!("non lu : {e}"),
        }
    }

    // -------------------------------------------------------------------------------------
    // (1) LE CONSOMMATEUR DU SPOOL — le lot reste, intact, compté, et s'ingère au retour.
    // -------------------------------------------------------------------------------------

    /// Le parcours commun des deux causes : deux passages en panne, puis le retour.
    fn cl1_le_lot_reste_puis_s_ingere(f: &Cl1, perdre: impl Fn(&Cl1), rendre: impl Fn(&Cl1), quoi: &str) {
        let (lot_a, _) = f.lot(1, CL1_A, "cl1srca");
        let (lot_b, _) = f.lot(2, CL1_B, "cl1srcb");
        let octets = std::fs::read(&lot_a).expect("fixture : octets du lot");
        perdre(f);
        for passage in ["premier", "second"] {
            assert_eq!(ingest_once(&f.st.tenants, &f.st.spool), crate::mesure_environnement::Mesure::Lue(1), "{quoi}, {passage} passage : le lot laissé est un abandon COMPTÉ (santé de l'ingestion)");
            assert_eq!(std::fs::read(&lot_a).ok().as_deref(), Some(octets.as_slice()), "{quoi}, {passage} passage : le lot RESTE au spool, intact");
            assert!(!f.quarantaine().exists(), "{quoi}, {passage} passage : rien n'est écarté en quarantaine");
        }
        assert!(!lot_b.exists(), "{quoi} : le lot de B, sain, s'ingère dans le même passage");
        assert_eq!(f.evenements(CL1_B, "cl1srcb"), 1, "{quoi} : B ingéré");
        rendre(f);
        assert_eq!(f.evenements(CL1_A, "cl1srca"), 0, "{quoi} : rien du lot de A n'a été écrit pendant la panne");
        assert_eq!(ingest_once(&f.st.tenants, &f.st.spool), crate::mesure_environnement::Mesure::Lue(0), "{quoi} : la cause disparue, le passage suivant ingère tout");
        assert!(!lot_a.exists(), "{quoi} : le lot de A est ingéré puis retiré du spool");
        assert_eq!(f.evenements(CL1_A, "cl1srca"), 1, "{quoi} : ses événements sont dans la base de A, une fois");
        assert!(!f.quarantaine().exists(), "{quoi} : toujours aucune quarantaine");
    }

    /// CE QU'IL TIENT, par la vraie boucle (`ingest_once`, fichiers réels) : la clé de A non résolue pendant deux passages.
    /// Le lot de A reste au spool, ses octets inchangés, aucune quarantaine n'existe, il est compté parmi les abandons À
    /// CHAQUE passage (`Lue(1)`) ; le lot de B s'ingère. La clé rendue : le passage suivant ingère le lot de A (`Lue(0)`),
    /// une fois, sans geste.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `CL1_CLE_NON_SERVABLE` et `CL1_INGEST_QUARANTAINE` (lot écarté),
    /// `CL1_INGEST_INGERE` (`Lue(0)` sur un lot laissé).
    #[test]
    fn cl1_cle_non_resolue_le_lot_reste_au_spool_et_s_ingere_au_retour() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        cl1_sans_coffre();
        let f = Cl1::neuf("spool-cle");
        cl1_le_lot_reste_puis_s_ingere(&f, Cl1::cle_perdue, Cl1::cle_rendue, "clé non résolue");
    }

    /// CE QU'IL TIENT : la même conduite quand la base de A ne s'ouvre pas (son répertoire indisponible), sa clé résolue.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `CL1_BASE_NON_SERVABLE` et `CL1_INGEST_QUARANTAINE` (lot écarté),
    /// `CL1_INGEST_INGERE` (`Lue(0)` sur un lot laissé).
    #[test]
    fn cl1_base_non_ouverte_le_lot_reste_au_spool_et_s_ingere_au_retour() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        cl1_sans_coffre();
        let f = Cl1::neuf("spool-base");
        cl1_le_lot_reste_puis_s_ingere(&f, Cl1::base_perdue, Cl1::base_rendue, "base non ouverte");
    }

    /// CE QU'IL TIENT : le tenant `default` lui-même non ouvert (sa clé repointée vers un coffre muet), le sous-répertoire
    /// de quarantaine — sans marqueur, donc lu comme `default` — n'est ni un lot à laisser ni un abandon : `Lue(0)`.
    /// Contrôle : un lot de B, dans le même passage, s'ingère.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `CL1_ENTREE_NON_LOT` (`Lue(1)`).
    #[test]
    fn cl1_le_sous_repertoire_de_quarantaine_n_est_pas_un_lot_du_tenant_non_ouvert() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        cl1_sans_coffre();
        let f = Cl1::neuf("entree");
        std::fs::create_dir_all(f.quarantaine()).expect("fixture : sous-répertoire de quarantaine");
        let (lot_b, _) = f.lot(3, CL1_B, "cl1srce");
        f.plan("UPDATE tenant SET key_ref='vault:cl1-coffre/jamais-rempli' WHERE id='default';");
        assert_eq!(cl1_issue(&f.st.tenants.handle_ouverte_lu("default")), "non ouvert : clé non résolue", "fixture : default non ouvert");
        let bilan = ingest_once(&f.st.tenants, &f.st.spool);
        f.plan("UPDATE tenant SET key_ref='' WHERE id='default';");
        assert_eq!(bilan, crate::mesure_environnement::Mesure::Lue(0), "le sous-répertoire n'est pas compté");
        assert!(!lot_b.exists(), "contrôle : le lot de B s'ingère");
        assert!(f.quarantaine().is_dir(), "le sous-répertoire est intact");
    }

    // -------------------------------------------------------------------------------------
    // (2) L'ÉCRIVAIN CHAUD, LE CHEMIN REQUÊTE, LES TÂCHES DE FOND, LA LIVRAISON POUSSÉE.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : l'écrivain de A chaud au cache. La clé de A perdue : `handle_ouverte_lu` rend « non ouvert, clé non
    /// résolue », jamais l'écrivain chaud. La clé rendue : le MÊME écrivain (même `Arc`), sans réouverture.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `CL1_CACHE_SERVI`.
    #[test]
    fn cl1_l_ecrivain_chaud_n_est_pas_servi_sans_sa_cle() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        cl1_sans_coffre();
        let f = Cl1::neuf("cache");
        let chaud = f.st.tenants.handle_for(CL1_A).expect("contrôle : écrivain de A servi");
        f.cle_perdue();
        let pendant = f.st.tenants.handle_ouverte_lu(CL1_A);
        f.cle_rendue();
        assert_eq!(cl1_issue(&pendant), "non ouvert : clé non résolue", "clé perdue : ni l'écrivain chaud, ni une absence");
        match f.st.tenants.handle_ouverte_lu(CL1_A) {
            Ok(OuvertureDuTenant::Servie(h)) => assert!(Arc::ptr_eq(&h, &chaud), "clé rendue : le MÊME écrivain"),
            autre => panic!("clé rendue : écrivain servi ({})", cl1_issue(&autre)),
        }
    }

    /// CE QU'IL TIENT, pour chacune des deux causes : `req_db` ne rend ni un écrivain de A ni celui du processus, et rien
    /// ne s'y lit ; `req_db_path` rend le chemin cul-de-sac. Contrôle positif, cause disparue : la base de A et son chemin.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `CL1_REQ_DB_DEFAUT`, `CL1_REQ_PATH_DEFAUT` (base du processus servie).
    #[test]
    fn cl1_chemin_requete_d_un_tenant_non_ouvert_prend_le_cul_de_sac() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        cl1_sans_coffre();
        let f = Cl1::neuf("requete");
        let au = AuthUser { name: "cl1-ana".into(), role: "admin".into(), tenant: CL1_A.into(), is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None };
        let pannes: [(&str, fn(&Cl1), fn(&Cl1)); 2] = [("clé non résolue", Cl1::cle_perdue, Cl1::cle_rendue), ("base non ouverte", Cl1::base_perdue, Cl1::base_rendue)];
        for (quoi, perdre, rendre) in pannes {
            perdre(&f);
            let h = req_db(&f.st, &au);
            let p = req_db_path(&f.st, &au);
            rendre(&f);
            assert!(!Arc::ptr_eq(&h, &f.st.db), "{quoi} : jamais la base du processus");
            assert!(h.lock().query_row("SELECT COUNT(*) FROM event", [], |r| r.get::<_, i64>(0)).is_err(), "{quoi} : rien ne s'y lit");
            assert_eq!(p, UNAVAILABLE_TENANT_DB_PATH, "{quoi} : le chemin cul-de-sac");
            let servie = req_db(&f.st, &au);
            assert!(servie.lock().query_row("SELECT COUNT(*) FROM event", [], |r| r.get::<_, i64>(0)).is_ok(), "{quoi}, retour : la base de A se lit");
            assert_eq!(req_db_path(&f.st, &au), f.chemin_a(), "{quoi}, retour : le chemin de A");
        }
    }

    /// CE QU'IL TIENT, pour chacune des deux causes : le parcours des tâches de fond appelle le corps pour `default` et B,
    /// chacun sur SA base, et jamais pour A — ni sur sa base, ni sur la base `default` à sa place. Le bilan du parcours
    /// reste `Lue(0)` : la liste a été lue. Contrôle positif, cause disparue : les trois.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `CL1_JOBS_DEFAUT`.
    #[test]
    fn cl1_tour_de_fond_saute_le_tenant_non_ouvert() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        cl1_sans_coffre();
        let f = Cl1::neuf("jobs");
        let chemin = |t: &str| f.st.tenants.ready_db_path(t).unwrap_or_else(|| panic!("contrôle : chemin de {t}"));
        let tous = vec![("default".to_string(), chemin("default")), (CL1_A.to_string(), chemin(CL1_A)), (CL1_B.to_string(), chemin(CL1_B))];
        let parcours = |st: &AppState| {
            let mut vus: Vec<(String, String)> = Vec::new();
            let bilan = for_each_active_tenant(&st.tenants, |tid, _h, p| vus.push((tid.to_string(), p.to_string())));
            (vus, bilan)
        };
        assert_eq!(parcours(&f.st).0, tous, "contrôle : les trois tenants, chacun sur sa base");
        let pannes: [(&str, fn(&Cl1), fn(&Cl1)); 2] = [("clé non résolue", Cl1::cle_perdue, Cl1::cle_rendue), ("base non ouverte", Cl1::base_perdue, Cl1::base_rendue)];
        for (quoi, perdre, rendre) in pannes {
            perdre(&f);
            let (vus, bilan) = parcours(&f.st);
            rendre(&f);
            assert_eq!(vus, vec![tous[0].clone(), tous[2].clone()], "{quoi} : A est sauté ; default et B tournent sur leur base");
            assert_eq!(bilan, crate::mesure_environnement::Mesure::Lue(0), "{quoi} : la liste a été lue");
            assert_eq!(parcours(&f.st).0, tous, "{quoi}, retour : les trois");
        }
    }

    /// CE QU'IL TIENT, par appel direct de l'aide partagée des deux récepteurs poussés (leurs bras de réponse sont hors
    /// d'atteinte par la route, cf. l'en-tête) : pour chacune des deux causes, A rend `NonOuvert` — un refus qui invite à
    /// réessayer —, jamais `NonServable`, le refus d'une source morte. B rend sa base ; un tenant absent, `NonServable`.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `CL1_PUSH_NON_SERVABLE` (et `CL1_CLE_NON_SERVABLE`, `CL1_BASE_NON_SERVABLE`).
    #[test]
    fn cl1_la_livraison_poussee_vers_un_tenant_non_ouvert_est_un_refus_passager() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        cl1_sans_coffre();
        let f = Cl1::neuf("push");
        let issue = |t: &str| match base_de_la_livraison_push_lu(&f.st, t) {
            BaseDeLaLivraisonPush::Servie(_) => "servie",
            BaseDeLaLivraisonPush::NonServable => "non servable",
            BaseDeLaLivraisonPush::NonOuvert => "non ouvert",
            BaseDeLaLivraisonPush::CatalogueNonLu(_) => "catalogue non lu",
        };
        assert_eq!((issue(CL1_A), issue(CL1_B), issue("cl1-fantome")), ("servie", "servie", "non servable"), "contrôle");
        let pannes: [(&str, fn(&Cl1), fn(&Cl1)); 2] = [("clé non résolue", Cl1::cle_perdue, Cl1::cle_rendue), ("base non ouverte", Cl1::base_perdue, Cl1::base_rendue)];
        for (quoi, perdre, rendre) in pannes {
            perdre(&f);
            let pendant = (issue(CL1_A), issue(CL1_B));
            rendre(&f);
            assert_eq!(pendant, ("non ouvert", "servie"), "{quoi} : A refusé en passager, B servi");
            assert_eq!(issue(CL1_A), "servie", "{quoi}, retour : A servi");
        }
    }

    // -------------------------------------------------------------------------------------
    // (3) LA PORTE DE L'ACCÈS INTER-TENANTS, PAR LA ROUTE.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, par la route (`GET /api/me`, cookie de `rgsc-sa`, super-administrateur sans droit sur C ni sur B) :
    /// C créé sur une clé Vault. Contrôle : C et B servis (200). La clé de C perdue : `503`, corps entier `{error, id}`,
    /// `error` la phrase fixe, jamais le 403 « tenant inconnu ou indisponible » ni le texte du résolveur ; B, dans le même
    /// temps, 200. La clé rendue : 200.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `CL1_PORTE_403`, `CL1_PORTE_CAUSE_SERVIE`, `CL1_CLE_NON_SERVABLE`.
    #[tokio::test]
    async fn cl1_la_porte_inter_tenants_refuse_un_tenant_non_ouvert_en_503_par_la_route() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        cl1_sans_coffre();
        const CL1_C: &str = "cl1c";
        let (st, dir) = rgsc_plateforme().await;
        let coffre = format!("cl1-coffre/porte/{}", sha256_hex(format!("{dir}").as_bytes()));
        let rangement = format!("{coffre}#key");
        crate::crypto::vault_key_cache_put(&rangement, &sha256_hex(rangement.as_bytes()));
        let cree = tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(au_super("cl1-op")), Json(json!({ "id": CL1_C, "name": CL1_C, "key_ref": format!("vault:{coffre}") }))).await;
        assert_eq!(cree.status().as_u16(), 201, "fixture : C créé sur sa clé Vault");
        let addr = router_serve(st.clone()).await;
        let sa = rgsc_connexion(addr, "rgsc-sa").await;
        let cookie = format!("plume_session={sa}");
        let me = |t: &'static str| {
            let cookie = cookie.clone();
            async move { rgsc_envoyer(addr, "GET", "/api/me", None, &[("Cookie", cookie.as_str()), ("x-plume-tenant", t)], "").await }
        };
        assert_eq!((me(CL1_C).await.statut, me(super::revocation_globale_sans_cookie_et_comptes_du_mode_un::RGSC_TENANT_B).await.statut), (200, 200), "contrôle");
        crate::crypto::vault_key_cache_forget(&rangement);
        let refus = me(CL1_C).await;
        let voisin = me(super::revocation_globale_sans_cookie_et_comptes_du_mode_un::RGSC_TENANT_B).await;
        crate::crypto::vault_key_cache_put(&rangement, &sha256_hex(rangement.as_bytes()));
        assert_eq!(refus.statut, 503, "clé perdue : 503 : {}", refus.texte);
        let cles: std::collections::BTreeSet<&str> = refus.corps.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        assert_eq!(cles, ["error", "id"].into_iter().collect(), "clé perdue : corps entier : {}", refus.texte);
        assert_eq!(refus.corps["error"], json!(CL1_PHRASE_PORTE), "clé perdue : la phrase fixe, rien d'autre : {}", refus.texte);
        assert_eq!(voisin.statut, 200, "clé de C perdue : B reste servi");
        assert_eq!(me(CL1_C).await.statut, 200, "clé rendue : C servi");
    }

    // -------------------------------------------------------------------------------------
    // (4) LA BASCULE DE SUSPENSION ET L'ÉVÉNEMENT D'AUDIT DU TENANT.
    // -------------------------------------------------------------------------------------

    fn cl1_compte_plan(st: &AppState, sql: &str) -> i64 {
        st.tenants.control.as_ref().expect("plan").conn.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("contrôle : `{sql}` ({e})"))
    }

    /// CE QU'IL TIENT, par le gestionnaire de la route (`tenant_suspend`, super-administrateur), pour chacune des deux
    /// causes — il INVERSE le témoin qui affirmait la suspension refusée en `503` : la suspension est FAITE. Corps ENTIER
    /// `{ok, id, suspended: true, evenement_du_tenant_non_ecrit}`, l'aveu sous la phrase de la base non ouvrable, sans la
    /// classe ni le texte du résolveur ou du moteur ; `suspended=1` au catalogue ; le maillon `tenant.suspend` inscrit au
    /// journal de contrôle comme pour toute suspension ; aucun événement d'audit écrit dans la base du processus (que
    /// l'événement ne soit pas tenté dans celle de A, inouvrable jusqu'après la réactivation, est tenu par l'égalité du
    /// corps entier). Puis, la cause durant toujours : A est NON SERVABLE pour tous (`handle_ouverte_lu`),
    /// un lot du spool qui le vise suit la règle d'un tenant suspendu (écarté en quarantaine, octets conservés, compté) ;
    /// réactivé (200, aveu de la base non servie, inchangé), il redevient « actif non ouvert » sous SA classe.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR, chacune seule : `CL2_REFUS_CLE` (le refus `503` remis pour la clé non résolue),
    /// `CL2_REFUS_BASE` (remis pour la base non ouverte), `CL2_AVEU_RETIRE` (l'aveu de l'événement non écrit retiré),
    /// `CL2_CAUSE_SERVIE` (la cause du résolveur ou du moteur ajoutée à l'aveu servi).
    #[tokio::test]
    async fn cl2_la_suspension_d_un_tenant_non_ouvert_est_faite_et_avoue_l_evenement_non_ecrit() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        cl1_sans_coffre();
        let f = Cl1::neuf("cl2-bascule");
        let sa = au_super("cl2-op");
        let audits_du_processus = || f.st.db.lock().query_row("SELECT COUNT(*) FROM event WHERE source='plume-tenant-admin'", [], |r| r.get::<_, i64>(0)).expect("contrôle : base du processus");
        let avant = audits_du_processus();
        let pannes: [(&str, &str, u32, fn(&Cl1), fn(&Cl1)); 2] = [
            ("clé non résolue", "non ouvert : clé non résolue", 40, Cl1::cle_perdue, Cl1::cle_rendue),
            ("base non ouverte", "non ouvert : base non ouverte", 41, Cl1::base_perdue, Cl1::base_rendue),
        ];
        for (quoi, issue_reactive, n, perdre, rendre) in pannes {
            let maillons_avant = cl1_compte_plan(&f.st, "SELECT COUNT(*) FROM control_ledger WHERE kind='tenant.suspend' AND tenant='cl1-a'");
            perdre(&f);
            let (statut, v) = pb_json(tenant_suspend(State(f.st.clone()), Extension(sa.clone()), Path(CL1_A.into())).await).await;
            let suspendu = cl1_compte_plan(&f.st, "SELECT suspended FROM tenant WHERE id='cl1-a'");
            let maillons = cl1_compte_plan(&f.st, "SELECT COUNT(*) FROM control_ledger WHERE kind='tenant.suspend' AND tenant='cl1-a'");
            let pour_tous = cl1_issue(&f.st.tenants.handle_ouverte_lu(CL1_A));
            let (lot, nom) = f.lot(n, CL1_A, "cl2srcq");
            let octets = std::fs::read(&lot).expect("fixture : octets du lot");
            let bilan = ingest_once(&f.st.tenants, &f.st.spool);
            let (statut_r, v_r) = pb_json(tenant_unsuspend(State(f.st.clone()), Extension(sa.clone()), Path(CL1_A.into())).await).await;
            let apres_reactivation = cl1_issue(&f.st.tenants.handle_ouverte_lu(CL1_A));
            rendre(&f);
            assert_eq!(statut, 200, "{quoi} : la suspension est faite : {v}");
            assert_eq!(
                v,
                json!({ "ok": true, "id": CL1_A, "suspended": true, CLE_EVENEMENT_DU_TENANT_NON_ECRIT: CL2_PHRASE_EVENEMENT_BASE_NON_OUVERTE }),
                "{quoi} : corps entier, l'aveu sous la phrase de la base non ouvrable, sans cause"
            );
            assert_eq!(suspendu, 1, "{quoi} : suspended=1 écrit au catalogue");
            assert_eq!(maillons, maillons_avant + 1, "{quoi} : le maillon tenant.suspend est inscrit au journal de contrôle");
            assert_eq!(audits_du_processus(), avant, "{quoi} : rien n'est écrit dans la base du processus");
            assert_eq!(pour_tous, "non servable", "{quoi} : suspendu, A est non servable établi pour tous");
            assert_eq!(bilan, crate::mesure_environnement::Mesure::Lue(1), "{quoi} : le lot du tenant suspendu est un abandon compté");
            assert!(!lot.exists(), "{quoi} : le lot ne reste pas au spool");
            assert_eq!(std::fs::read(f.quarantaine().join(&nom)).ok().as_deref(), Some(octets.as_slice()), "{quoi} : écarté en quarantaine, comme pour un tenant suspendu");
            assert_eq!(statut_r, 200, "{quoi} : la réactivation est faite : {v_r}");
            assert_eq!(v_r[CLE_EVENEMENT_DU_TENANT_NON_ECRIT], json!(CL1_PHRASE_SANS_BASE_SERVIE), "{quoi} : réactivation inchangée : {v_r}");
            assert_eq!(apres_reactivation, issue_reactive, "{quoi} : réactivé, A redevient actif non ouvert tant que la cause dure");
            std::fs::remove_dir_all(f.quarantaine()).expect("fixture : quarantaine vidée");
        }
    }

    /// CE QU'IL TIENT, par le gestionnaire de la route (`tenant_unsuspend`), pour chacune des deux causes : A suspendu,
    /// réactivé pendant la panne : la bascule est faite (200, A actif), et son événement d'audit, qui ne trouve pas sa base,
    /// est avoué sous la phrase de la base non servie — jamais celle d'une ligne non relue — sans rien écrire dans la base
    /// du processus.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `CL1_AUDIT_CATALOGUE`.
    #[tokio::test]
    async fn cl1_l_evenement_d_audit_d_un_tenant_non_ouvert_est_avoue_base_non_servie() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        cl1_sans_coffre();
        let f = Cl1::neuf("audit");
        let sa = au_super("cl1-op");
        let audits_du_processus = || f.st.db.lock().query_row("SELECT COUNT(*) FROM event WHERE source='plume-tenant-admin'", [], |r| r.get::<_, i64>(0)).expect("contrôle : base du processus");
        let avant = audits_du_processus();
        let pannes: [(&str, fn(&Cl1), fn(&Cl1)); 2] = [("clé non résolue", Cl1::cle_perdue, Cl1::cle_rendue), ("base non ouverte", Cl1::base_perdue, Cl1::base_rendue)];
        for (quoi, perdre, rendre) in pannes {
            f.plan("UPDATE tenant SET suspended=1 WHERE id='cl1-a';");
            perdre(&f);
            let (statut, v) = pb_json(tenant_unsuspend(State(f.st.clone()), Extension(sa.clone()), Path(CL1_A.into())).await).await;
            rendre(&f);
            assert_eq!(statut, 200, "{quoi} : la réactivation est faite : {v}");
            assert_eq!(v[CLE_EVENEMENT_DU_TENANT_NON_ECRIT], json!(CL1_PHRASE_SANS_BASE_SERVIE), "{quoi} : avoué base non servie : {v}");
            assert_eq!(cl1_compte_plan(&f.st, "SELECT suspended FROM tenant WHERE id='cl1-a'"), 0, "{quoi} : A actif");
            assert_eq!(audits_du_processus(), avant, "{quoi} : rien n'est écrit dans la base du processus");
        }
    }

    // -------------------------------------------------------------------------------------
    // (5) L'ACCÈS OBSERVÉ — rien n'est inscrit, nulle part.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, par appel direct du site (`consigner_l_acces`, appelé par `auth_guard`), pour chacune des deux
    /// causes : l'accès d'un compte à A n'est inscrit ni dans la base du processus, ni dans celle de B, ni (relue au
    /// retour) dans celle de A. Contrôle positif, cause disparue : un autre compte est inscrit chez A seulement.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `CL1_ACCES_DEFAUT`.
    #[test]
    fn cl1_l_acces_observe_d_un_tenant_non_ouvert_n_est_inscrit_nulle_part() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        cl1_sans_coffre();
        let f = Cl1::neuf("acces");
        let compte = |h: &Arc<Mutex<Connection>>, nom: &str| {
            h.lock().query_row("SELECT COUNT(*) FROM acces_observe WHERE nom=?1", params![nom], |r| r.get::<_, i64>(0)).expect("contrôle : inventaire lu")
        };
        let base_b = f.st.tenants.handle_for(CL1_B).expect("contrôle : base de B");
        let pannes: [(&str, &str, &str, fn(&Cl1), fn(&Cl1)); 2] = [
            ("clé non résolue", "cl1-ana", "cl1-bea", Cl1::cle_perdue, Cl1::cle_rendue),
            ("base non ouverte", "cl1-cyd", "cl1-dan", Cl1::base_perdue, Cl1::base_rendue),
        ];
        for (quoi, pendant, apres, perdre, rendre) in pannes {
            perdre(&f);
            crate::acces_observe::consigner_l_acces(&f.st, CL1_A, pendant, "admin", "basic");
            rendre(&f);
            let base_a = f.st.tenants.handle_for(CL1_A).expect("contrôle : base de A");
            assert_eq!((compte(&base_a, pendant), compte(&f.st.db, pendant), compte(&base_b, pendant)), (0, 0, 0), "{quoi} : rien n'est inscrit, nulle part");
            crate::acces_observe::consigner_l_acces(&f.st, CL1_A, apres, "admin", "basic");
            assert_eq!((compte(&base_a, apres), compte(&f.st.db, apres)), (1, 0), "{quoi}, retour : inscrit chez A seulement");
        }
    }

    // -------------------------------------------------------------------------------------
    // (6) LA BORNE DU MÉMO — fonction pure, sur une carte locale.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : une première occurrence est dite, une seconde de même classe tue, une classe DIFFÉRENTE dite et
    /// notée à sa place ; sous la borne, un tenant neuf est noté jusqu'à elle ; À la borne, un tenant neuf est DIT sans être
    /// mémorisé (et dit encore à l'appel suivant), un tenant connu de même classe reste tu, un tenant connu qui change de
    /// classe est dit et mis à jour sans faire croître la carte.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `CL1_BORNE_MUETTE` (le tenant neuf tu à la borne), `CL1_SANS_BORNE` (mémorisé
    /// au-delà), `CL1_CLASSE_IGNOREE` (le changement de classe tu).
    #[test]
    fn cl1_le_memo_des_tenants_non_ouverts_est_borne() {
        use ClasseDuTenantNonOuvert::{BaseNonOuverte, CleNonResolue};
        let mut memo = HashMap::new();
        assert!(noter_un_tenant_non_ouvert(&mut memo, "t-0", CleNonResolue), "première occurrence : dite");
        assert!(!noter_un_tenant_non_ouvert(&mut memo, "t-0", CleNonResolue), "même classe : tue");
        assert!(noter_un_tenant_non_ouvert(&mut memo, "t-0", BaseNonOuverte), "classe nouvelle : dite");
        assert!(!noter_un_tenant_non_ouvert(&mut memo, "t-0", BaseNonOuverte), "classe nouvelle notée : tue ensuite");
        while memo.len() + 1 < TENANTS_NON_OUVERTS_MEMO_MAX {
            let n = memo.len();
            assert!(noter_un_tenant_non_ouvert(&mut memo, &format!("t-{n}"), CleNonResolue), "sous la borne : dite");
        }
        assert_eq!(memo.len(), TENANTS_NON_OUVERTS_MEMO_MAX - 1, "contrôle : une place sous la borne");
        assert!(noter_un_tenant_non_ouvert(&mut memo, "derniere-place", CleNonResolue), "borne - 1 : dite");
        assert!(!noter_un_tenant_non_ouvert(&mut memo, "derniere-place", CleNonResolue), "borne - 1 : notée, donc tue ensuite");
        assert_eq!(memo.len(), TENANTS_NON_OUVERTS_MEMO_MAX, "la borne est atteinte");
        assert!(noter_un_tenant_non_ouvert(&mut memo, "au-dela", CleNonResolue), "à la borne : un tenant neuf est dit");
        assert!(noter_un_tenant_non_ouvert(&mut memo, "au-dela", CleNonResolue), "à la borne : et dit encore, jamais tu");
        assert_eq!(memo.len(), TENANTS_NON_OUVERTS_MEMO_MAX, "rien n'est mémorisé au-delà");
        assert!(!memo.contains_key("au-dela"), "le tenant neuf n'est pas dans le mémo");
        assert!(!noter_un_tenant_non_ouvert(&mut memo, "t-0", BaseNonOuverte), "à la borne : un tenant connu de même classe reste tu");
        assert!(noter_un_tenant_non_ouvert(&mut memo, "t-0", CleNonResolue), "à la borne : un tenant connu qui change de classe est dit");
        assert_eq!((memo.len(), memo.get("t-0").copied()), (TENANTS_NON_OUVERTS_MEMO_MAX, Some(CleNonResolue)), "mis à jour à sa place");
    }

    // -------------------------------------------------------------------------------------
    // (7) LE JOURNAL, PAR CAPTURE — sous-processus, phases séparées par un marqueur.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, ligne ENTIÈRE par ligne entière, phase par phase (lignes d'une phase triées) :
    ///   1. clé de A perdue ; deux lots de A, un de B : la ligne de `state.rs` (clé non résolue, texte du résolveur) et la
    ///      ligne du spool (tenant échappé, mot de la classe), UNE fois chacune — pas une par lot ;
    ///   2. même panne : un second passage, le tour de fond, `req_db`, `req_db_path` et les deux formes de la disponibilité
    ///      n'écrivent RIEN — ni la ligne redite, ni la ligne d'un tenant suspendu ;
    ///   3. la clé rendue, la base perdue : changement de classe, les deux lignes sont dites de nouveau, sous la base ;
    ///   4. retour : aucune ligne, les lots de A ingérés ;
    ///   5. la base perdue de nouveau, MÊME classe que la dernière notée : les deux lignes sont redites, parce que le
    ///      retour les a oubliées ;
    ///   6. table du catalogue retirée : la ligne de la lecture non faite, pour A ;
    ///   7. table remise, base toujours perdue : aucune ligne (même panne) ;
    ///   8. table retirée de nouveau : la ligne de la lecture non faite est redite (oubliée en 7, la ligne s'étant relue) ;
    ///   9. table remise ; un accès opérateur en écriture vers A : la trace du tenant perdue sous le mot de sa classe ;
    ///  10. base rendue : aucune ligne, le lot de A ingéré.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `CL1_LIGNE_CHAQUE_FOIS`, `CL1_JAMAIS_OUBLIE`, `CL1_CLASSE_IGNOREE`,
    /// `CL1_SPOOL_CHAQUE_FOIS`, `CL1_SPOOL_JAMAIS_OUBLIE`, `CL1_SPOOL_TENANT_BRUT`, `CL1_CATALOGUE_NON_OUBLIE`,
    /// `CL1_JOBS_PHRASE`, `CL1_OPERATEUR_CAUSE`.
    #[test]
    fn cl1_le_tenant_non_ouvert_est_dit_une_fois_par_tenant_et_par_panne() {
        if std::env::var(CL1_ENFANT).is_ok() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
            cl1_enfant();
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::tenant_actif_non_ouvrable_n_est_pas_un_tenant_absent::cl1_le_tenant_non_ouvert_est_dit_une_fois_par_tenant_et_par_panne",
            ])
            .env(CL1_ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let mut phases: Vec<Vec<String>> = Vec::new();
        let mut chemin_a = String::new();
        for l in stderr.lines() {
            if let Some(c) = l.strip_prefix("CL1-CHEMIN-A:") {
                chemin_a = c.to_string();
            } else if l.starts_with(CL1_PHASE) {
                phases.push(Vec::new());
            } else if let Some(courante) = phases.last_mut() {
                if l.starts_with("[ingest] ") || l.starts_with("[multi-tenant]") || l.starts_with("[plume] accès opérateur") {
                    courante.push(l.to_string());
                }
            }
        }
        assert!(!chemin_a.is_empty(), "contrôle : l'enfant dit le chemin de A :\n{stderr}");
        for p in phases.iter_mut() {
            p.sort();
        }
        let trie = |mut v: Vec<String>| {
            v.sort();
            v
        };
        let attendu: Vec<Vec<String>> = vec![
            trie(vec![cl1_ligne_cle(CL1_A), cl1_ligne_spool("\"cl1-a\"", "clé non résolue")]),
            vec![],
            trie(vec![cl1_ligne_base(CL1_A, &chemin_a), cl1_ligne_spool("\"cl1-a\"", "base non ouverte")]),
            vec![],
            trie(vec![cl1_ligne_base(CL1_A, &chemin_a), cl1_ligne_spool("\"cl1-a\"", "base non ouverte")]),
            vec![cl1_ligne_catalogue("\"cl1-a\"", "no such table: tenant")],
            vec![],
            vec![cl1_ligne_catalogue("\"cl1-a\"", "no such table: tenant")],
            vec![cl1_ligne_trace("base du tenant NON ouverte au moment de l'écriture (base non ouverte)")],
            vec![],
        ];
        assert!(attendu.len() >= 10, "plancher : dix phases attendues");
        assert_eq!(phases.len(), attendu.len(), "une entrée par phase marquée :\n{stderr}");
        for (i, (vu, att)) in phases.iter().zip(attendu.iter()).enumerate() {
            assert_eq!(vu, att, "phase {} : lignes ENTIÈRES, aucune autre :\n{stderr}", i + 1);
        }
    }

    /// Le corps joué par l'enfant ; chaque phase ouvre par son marqueur sur la sortie d'erreur.
    fn cl1_enfant() {
        cl1_sans_coffre();
        let f = Cl1::neuf("journal");
        eprintln!("CL1-CHEMIN-A:{}", f.chemin_a());
        let au = AuthUser { name: "cl1-ana".into(), role: "admin".into(), tenant: CL1_A.into(), is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None };
        let phase = |n: u32| eprintln!("{CL1_PHASE}{n}");
        let passe = |attendu: u32, quoi: &str| {
            assert_eq!(ingest_once(&f.st.tenants, &f.st.spool), crate::mesure_environnement::Mesure::Lue(attendu), "enfant : {quoi}");
        };
        f.lot(11, CL1_A, "cl1ja");
        f.lot(12, CL1_A, "cl1ja");
        f.lot(13, CL1_B, "cl1jb");

        phase(1);
        f.cle_perdue();
        passe(2, "deux lots de A laissés, B ingéré");
        phase(2);
        passe(2, "les deux lots de A, encore");
        let _ = for_each_active_tenant(&f.st.tenants, |_, _, _| {});
        let _ = req_db(&f.st, &au);
        let _ = req_db_path(&f.st, &au);
        assert!(matches!(f.st.tenants.tenant_available_lu(CL1_A), Ok(false)), "enfant : projection d'auth.rs");
        assert_eq!(cl1_issue(&f.st.tenants.disponibilite_lu(CL1_A)), "non ouvert : clé non résolue", "enfant : disponibilité");
        phase(3);
        f.cle_rendue();
        f.base_perdue();
        passe(2, "classe changée, toujours laissés");
        phase(4);
        f.base_rendue();
        passe(0, "retour : tout s'ingère");
        assert_eq!(f.evenements(CL1_A, "cl1ja"), 2, "enfant : les deux lots de A, une fois chacun");
        phase(5);
        f.lot(14, CL1_A, "cl1ja");
        f.base_perdue();
        passe(1, "nouvelle panne, même classe que la précédente");
        phase(6);
        f.plan("ALTER TABLE tenant RENAME TO cl1_tenant;");
        passe(1, "catalogue non lu");
        phase(7);
        f.plan("ALTER TABLE cl1_tenant RENAME TO tenant;");
        passe(1, "relu, toujours non ouvert");
        phase(8);
        f.plan("ALTER TABLE tenant RENAME TO cl1_tenant;");
        passe(1, "catalogue non lu de nouveau");
        phase(9);
        f.plan("ALTER TABLE cl1_tenant RENAME TO tenant;");
        let _ = crate::rbac::emit_operator_access(&f.st, "cl1-op", CL1_A, true, Some("cl1 raison"));
        phase(10);
        f.base_rendue();
        passe(0, "base rendue : le lot s'ingère");
        assert_eq!(f.evenements(CL1_A, "cl1ja"), 3, "enfant : les trois lots de A");
    }

    // -------------------------------------------------------------------------------------
    // (8) UNE TENTATIVE PAR TENANT ET PAR PASSAGE ; LA PANNE SUIVANTE REDITE, PAR CHACUN DES DEUX RETOURS.
    // -------------------------------------------------------------------------------------

    /// Un coffre de secrets qui répond, à chaque connexion, `503` sans corps, et COMPTE les connexions reçues.
    fn cl1_coffre_qui_refuse() -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        use std::io::{Read, Write};
        let ecoute = std::net::TcpListener::bind("127.0.0.1:0").expect("fixture : écoute du coffre");
        let adresse = format!("http://{}", ecoute.local_addr().expect("fixture : adresse du coffre"));
        let connexions = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let compte = connexions.clone();
        std::thread::spawn(move || {
            for flux in ecoute.incoming() {
                let Ok(mut flux) = flux else { continue };
                compte.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut requete = [0u8; 4096];
                let _ = flux.read(&mut requete);
                let _ = flux.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            }
        });
        (adresse, connexions)
    }

    /// CE QU'IL TIENT, par la vraie boucle (`ingest_once`) et un vrai coffre local qui refuse : la clé de A hors du cache,
    /// CINQ lots de A et un de B. Chaque passage laisse et compte les cinq lots de A (`Lue(5)`) en n'interrogeant le coffre
    /// qu'UNE fois — une tentative par tenant et par passage, jamais une par lot — ; le passage suivant retente une fois. Le
    /// lot de B s'ingère dès le premier passage. La clé rendue (au cache, comme le coffre la rendrait) : le passage suivant
    /// ingère les cinq lots, sans nouvelle connexion.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `CL1_PASSAGE_SANS_MEMO` (le tenant trouvé non ouvert n'est pas retenu pour le passage :
    /// cinq connexions par passage).
    #[test]
    fn cl1_une_seule_tentative_par_tenant_non_ouvert_et_par_passage() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        cl1_sans_coffre();
        let f = Cl1::neuf("passage");
        let (adresse, connexions) = cl1_coffre_qui_refuse();
        let lots_a: Vec<std::path::PathBuf> = (21..26).map(|n| f.lot(n, CL1_A, "cl1pa").0).collect();
        let (lot_b, _) = f.lot(26, CL1_B, "cl1pb");
        f.cle_perdue();
        std::env::set_var("PLUME_VAULT_ADDR", &adresse);
        std::env::set_var("PLUME_VAULT_TOKEN", "cl1-jeton-de-test");
        let vues = |c: &Arc<std::sync::atomic::AtomicUsize>| c.load(std::sync::atomic::Ordering::SeqCst);
        let premier = ingest_once(&f.st.tenants, &f.st.spool);
        let apres_premier = vues(&connexions);
        let second = ingest_once(&f.st.tenants, &f.st.spool);
        let apres_second = vues(&connexions);
        f.cle_rendue();
        let retour = ingest_once(&f.st.tenants, &f.st.spool);
        let apres_retour = vues(&connexions);
        cl1_sans_coffre();
        assert_eq!(premier, crate::mesure_environnement::Mesure::Lue(5), "premier passage : les cinq lots de A laissés et comptés");
        assert_eq!(apres_premier, 1, "premier passage : UNE tentative pour A, pas une par lot");
        assert_eq!(second, crate::mesure_environnement::Mesure::Lue(5), "second passage : toujours laissés et comptés");
        assert_eq!(apres_second, 2, "second passage : une nouvelle tentative, une seule");
        assert!(!lot_b.exists(), "le lot de B, sain, s'ingère pendant la panne de A");
        assert_eq!(retour, crate::mesure_environnement::Mesure::Lue(0), "clé rendue : tout s'ingère");
        assert_eq!(apres_retour, 2, "clé rendue : aucune connexion de plus (la clé est au cache)");
        assert!(lots_a.iter().all(|l| !l.exists()), "clé rendue : les cinq lots de A ingérés puis retirés");
        assert_eq!(f.evenements(CL1_A, "cl1pa"), 5, "les cinq lots de A dans sa base, une fois chacun");
    }

    const CL1_ENFANT_OUBLI: &str = "CL1_ENFANT_PANNE_SUIVANTE_REDITE";

    /// CE QU'IL TIENT, ligne ENTIÈRE par ligne entière, par `handle_ouverte_lu` seul (aucun lot, aucune ligne du spool) :
    ///   1. l'écrivain de A chaud ; sa clé perdue : la ligne de la clé non résolue ;
    ///   2. la clé rendue : l'écrivain chaud servi (même `Arc`, aucune ouverture), aucune ligne ;
    ///   3. la clé perdue de nouveau, MÊME classe : la ligne est REDITE — le retour par l'écrivain chaud l'a oubliée ;
    ///   4. la clé rendue, la base perdue (écrivain retiré du cache) : la ligne de la base non ouverte ;
    ///   5. la base rendue, aucun écrivain au cache : la base OUVERTE, servie, aucune ligne ;
    ///   6. la base perdue de nouveau, MÊME classe : la ligne est REDITE — l'ouverture réussie l'a oubliée.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR, chacune seule : `CL1_OUBLI_CACHE` (rien n'est oublié quand l'écrivain chaud est
    /// servi : phase 3 muette), `CL1_OUBLI_OUVERT` (rien n'est oublié après une ouverture réussie : phase 6 muette).
    #[test]
    fn cl1_la_panne_suivante_est_redite_apres_chacun_des_deux_retours() {
        if std::env::var(CL1_ENFANT_OUBLI).is_ok() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
            cl1_enfant_oubli();
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::tenant_actif_non_ouvrable_n_est_pas_un_tenant_absent::cl1_la_panne_suivante_est_redite_apres_chacun_des_deux_retours",
            ])
            .env(CL1_ENFANT_OUBLI, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let mut phases: Vec<Vec<String>> = Vec::new();
        let mut chemin_a = String::new();
        for l in stderr.lines() {
            if let Some(c) = l.strip_prefix("CL1-CHEMIN-A:") {
                chemin_a = c.to_string();
            } else if l.starts_with(CL1_PHASE) {
                phases.push(Vec::new());
            } else if let Some(courante) = phases.last_mut() {
                if l.starts_with("[ingest] ") || l.starts_with("[multi-tenant]") {
                    courante.push(l.to_string());
                }
            }
        }
        assert!(!chemin_a.is_empty(), "contrôle : l'enfant dit le chemin de A :\n{stderr}");
        let attendu: Vec<Vec<String>> = vec![
            vec![cl1_ligne_cle(CL1_A)],
            vec![],
            vec![cl1_ligne_cle(CL1_A)],
            vec![cl1_ligne_base(CL1_A, &chemin_a)],
            vec![],
            vec![cl1_ligne_base(CL1_A, &chemin_a)],
        ];
        assert_eq!(phases.len(), attendu.len(), "une entrée par phase marquée :\n{stderr}");
        for (i, (vu, att)) in phases.iter().zip(attendu.iter()).enumerate() {
            assert_eq!(vu, att, "phase {} : lignes ENTIÈRES, aucune autre :\n{stderr}", i + 1);
        }
    }

    /// Le corps joué par l'enfant ; chaque phase ouvre par son marqueur sur la sortie d'erreur.
    fn cl1_enfant_oubli() {
        cl1_sans_coffre();
        let f = Cl1::neuf("oubli");
        eprintln!("CL1-CHEMIN-A:{}", f.chemin_a());
        let phase = |n: u32| eprintln!("{CL1_PHASE}{n}");
        let issue = || cl1_issue(&f.st.tenants.handle_ouverte_lu(CL1_A));
        let chaud = f.st.tenants.handle_for(CL1_A).expect("enfant : écrivain de A servi");

        phase(1);
        f.cle_perdue();
        assert_eq!(issue(), "non ouvert : clé non résolue", "enfant : clé perdue");
        phase(2);
        f.cle_rendue();
        match f.st.tenants.handle_ouverte_lu(CL1_A) {
            Ok(OuvertureDuTenant::Servie(h)) => assert!(Arc::ptr_eq(&h, &chaud), "enfant : clé rendue, le MÊME écrivain chaud"),
            autre => panic!("enfant : clé rendue, écrivain servi ({})", cl1_issue(&autre)),
        }
        phase(3);
        f.cle_perdue();
        assert_eq!(issue(), "non ouvert : clé non résolue", "enfant : clé perdue de nouveau");
        phase(4);
        f.cle_rendue();
        f.base_perdue();
        assert_eq!(issue(), "non ouvert : base non ouverte", "enfant : base perdue");
        phase(5);
        f.base_rendue();
        assert!(f.st.tenants.writers.lock().get(CL1_A).is_none(), "enfant : aucun écrivain de A au cache avant l'ouverture");
        assert_eq!(issue(), "servie", "enfant : base rendue, ouverte");
        phase(6);
        f.base_perdue();
        assert_eq!(issue(), "non ouvert : base non ouverte", "enfant : base perdue de nouveau");
        f.base_rendue();
    }

    // -------------------------------------------------------------------------------------
    // (9) LA PORTE D'ENTRÉE D'`auth_guard`, PAR LA ROUTE — le membre d'un tenant actif non ouvert.
    // -------------------------------------------------------------------------------------

    /// La réponse d'une absence ou d'une suspension à la porte d'entrée, texte nu, à l'octet.
    const CL2_REFUS_D_ABSENCE_A_L_ENTREE: &str = "tenant indisponible (base non résoluble)";
    /// Le refus nommé d'une ligne du catalogue non lue (`rbac::CAUSE_CATALOGUE_DES_TENANTS_NON_LU`).
    const CL2_PHRASE_CATALOGUE_NON_LU: &str = "CATALOGUE DES TENANTS NON LU : le plan de contrôle n'a pas pu lire la ligne \
         du tenant demandé — ce n'est PAS « tenant inconnu ou indisponible » : son existence n'est ni affirmée ni niée, et \
         aucune base n'est servie. Réessayez une fois le plan de contrôle de nouveau lisible.";

    /// CE QU'IL TIENT, par la route, sur les deux chemins qui mènent à la porte d'entrée d'`auth_guard` sans passer par celle
    /// de l'accès inter-tenants : `GET /api/me` sous le cookie de `rgsc-ben`, MEMBRE de C par le droit d'administration posé
    /// à la création de C ; `GET /api/tenants/{id}/grants` sous le cookie de `rgsc-sa`, super-administrateur (route de
    /// gestion). C créé sur une clé Vault. Contrôle : les deux servis (200), B aussi. La clé de C perdue : `503` sur les deux
    /// routes, corps entier `{error, id}`, `error` la phrase fixe des autres portes, jamais le 403 d'une absence ni le texte
    /// du résolveur ; B, dans le même temps, 200 ; la clé rendue, 200. Inchangés à l'octet : un tenant absent du catalogue
    /// et C suspendu gardent leur `403` en texte nu ; la ligne du catalogue non lue (sa colonne de clé renommée : les droits
    /// se lisent, la ligne non) garde son `503` nommé.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `CL2_PORTE_D_ENTREE_403` (le tenant actif non ouvert rendu au 403 d'une absence).
    #[tokio::test]
    async fn cl2_la_porte_d_entree_refuse_le_membre_d_un_tenant_non_ouvert_en_503_par_la_route() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        cl1_sans_coffre();
        let (st, dir) = rgsc_plateforme().await;
        let coffre = format!("cl2-coffre/entree/{}", sha256_hex(format!("{dir}").as_bytes()));
        let rangement = format!("{coffre}#key");
        crate::crypto::vault_key_cache_put(&rangement, &sha256_hex(rangement.as_bytes()));
        let cree = tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(au_super("cl2-op")), Json(json!({ "id": "cl2c", "name": "cl2c", "key_ref": format!("vault:{coffre}"), "admin": "rgsc-ben" }))).await;
        assert_eq!(cree.status().as_u16(), 201, "fixture : C créé sur sa clé Vault, ben administrateur");
        let plan = |sql: &str| {
            st.tenants.control.as_ref().expect("fixture : mode 1").conn.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` ({e})"))
        };
        let addr = router_serve(st.clone()).await;
        let (ben, sa) = (rgsc_connexion(addr, "rgsc-ben").await, rgsc_connexion(addr, "rgsc-sa").await);
        let (cookie_ben, cookie_sa) = (format!("plume_session={ben}"), format!("plume_session={sa}"));
        let me = |t: &'static str| {
            let cookie = cookie_ben.clone();
            async move { rgsc_envoyer(addr, "GET", "/api/me", None, &[("Cookie", cookie.as_str()), ("x-plume-tenant", t)], "").await }
        };
        let droits = |t: &'static str| {
            let cookie = cookie_sa.clone();
            async move { rgsc_envoyer(addr, "GET", &format!("/api/tenants/{t}/grants"), None, &[("Cookie", cookie.as_str())], "").await }
        };
        let tenant_b = super::revocation_globale_sans_cookie_et_comptes_du_mode_un::RGSC_TENANT_B;
        assert_eq!((me("cl2c").await.statut, me(tenant_b).await.statut, droits("cl2c").await.statut), (200, 200, 200), "contrôle : ben membre de C et de B ; le super-administrateur gère C");
        let absent = droits("cl2fantome").await;
        assert_eq!((absent.statut, &absent.corps), (403, &json!(CL2_REFUS_D_ABSENCE_A_L_ENTREE)), "tenant absent : le 403 d'avant, à l'octet : {}", absent.texte);
        crate::crypto::vault_key_cache_forget(&rangement);
        let refus = me("cl2c").await;
        let refus_gestion = droits("cl2c").await;
        let voisin = me(tenant_b).await;
        crate::crypto::vault_key_cache_put(&rangement, &sha256_hex(rangement.as_bytes()));
        for (route, r) in [("GET /api/me", &refus), ("GET /api/tenants/cl2c/grants", &refus_gestion)] {
            assert_eq!(r.statut, 503, "{route}, clé perdue : 503, jamais le 403 d'une absence : {}", r.texte);
            let cles: std::collections::BTreeSet<&str> = r.corps.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
            assert_eq!(cles, ["error", "id"].into_iter().collect(), "{route}, clé perdue : corps entier : {}", r.texte);
            assert_eq!(r.corps["error"], json!(CL1_PHRASE_PORTE), "{route}, clé perdue : la phrase fixe des autres portes, rien d'autre : {}", r.texte);
        }
        assert_eq!(voisin.statut, 200, "clé de C perdue : B reste servi");
        assert_eq!((me("cl2c").await.statut, droits("cl2c").await.statut), (200, 200), "clé rendue : C servi");
        plan("UPDATE tenant SET suspended=1 WHERE id='cl2c';");
        let suspendu = droits("cl2c").await;
        plan("UPDATE tenant SET suspended=0 WHERE id='cl2c';");
        assert_eq!((suspendu.statut, &suspendu.corps), (403, &json!(CL2_REFUS_D_ABSENCE_A_L_ENTREE)), "tenant suspendu : le 403 d'avant, à l'octet : {}", suspendu.texte);
        plan("ALTER TABLE tenant RENAME COLUMN key_ref TO cl2_key_ref;");
        let non_lu = me("cl2c").await;
        plan("ALTER TABLE tenant RENAME COLUMN cl2_key_ref TO key_ref;");
        assert_eq!(non_lu.statut, 503, "ligne du catalogue non lue : 503 : {}", non_lu.texte);
        assert_eq!(non_lu.corps["error"], json!(CL2_PHRASE_CATALOGUE_NON_LU), "ligne du catalogue non lue : sa phrase : {}", non_lu.texte);
        assert_eq!(me("cl2c").await.statut, 200, "contrôle final : C servi");
    }

    // -------------------------------------------------------------------------------------
    // (10) LE VERROU DU PLAN DE CONTRÔLE N'EST PAS TENU PENDANT LA RÉSOLUTION D'UNE CLÉ.
    // -------------------------------------------------------------------------------------

    /// Un coffre de secrets local, une connexion par fil : à chaque requête, il joue `pendant` sur son propre fil, compte
    /// la requête, puis, s'il RETIENT, n'envoie sa réponse (la clé `cle`, forme KV v2) qu'une fois la porte ouverte.
    pub(super) struct Cl2Coffre {
        adresse: String,
        requetes: Arc<std::sync::atomic::AtomicUsize>,
        porte: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    }

    impl Cl2Coffre {
        pub(super) fn neuf(cle: String, retenir: bool, pendant: impl Fn() + Send + Sync + 'static) -> Self {
            use std::io::{Read, Write};
            let ecoute = std::net::TcpListener::bind("127.0.0.1:0").expect("fixture : écoute du coffre");
            let adresse = format!("http://{}", ecoute.local_addr().expect("fixture : adresse du coffre"));
            let requetes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let porte = Arc::new((std::sync::Mutex::new(!retenir), std::sync::Condvar::new()));
            let pendant = Arc::new(pendant);
            let (compte, porte_du_fil) = (requetes.clone(), porte.clone());
            std::thread::spawn(move || {
                for flux in ecoute.incoming() {
                    let Ok(mut flux) = flux else { continue };
                    let (compte, porte, pendant, cle) = (compte.clone(), porte_du_fil.clone(), pendant.clone(), cle.clone());
                    std::thread::spawn(move || {
                        let mut requete = [0u8; 4096];
                        let _ = flux.read(&mut requete);
                        pendant();
                        compte.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let (ouverte, signal) = &*porte;
                        let mut ouverte = ouverte.lock().unwrap_or_else(|e| e.into_inner());
                        let limite = std::time::Instant::now() + std::time::Duration::from_secs(60);
                        while !*ouverte && std::time::Instant::now() < limite {
                            ouverte = signal.wait_timeout(ouverte, std::time::Duration::from_millis(200)).unwrap_or_else(|e| e.into_inner()).0;
                        }
                        drop(ouverte);
                        let corps = json!({ "data": { "data": { "key": cle } } }).to_string();
                        let _ = flux.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{corps}", corps.len()).as_bytes());
                    });
                }
            });
            Cl2Coffre { adresse, requetes, porte }
        }

        pub(super) fn requetes(&self) -> usize {
            self.requetes.load(std::sync::atomic::Ordering::SeqCst)
        }

        /// Les `n` premières requêtes sont-elles arrivées (et leur `pendant` joué) avant `secondes` ?
        fn attendre(&self, n: usize, secondes: u64) -> bool {
            let limite = std::time::Instant::now() + std::time::Duration::from_secs(secondes);
            while self.requetes() < n && std::time::Instant::now() < limite {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            self.requetes() >= n
        }

        fn ouvrir(&self) {
            let (ouverte, signal) = &*self.porte;
            *ouverte.lock().unwrap_or_else(|e| e.into_inner()) = true;
            signal.notify_all();
        }

        /// Ce processus résout désormais les clés `vault:` par ce coffre.
        pub(super) fn brancher(&self) {
            std::env::set_var("PLUME_VAULT_ADDR", &self.adresse);
            std::env::set_var("PLUME_VAULT_TOKEN", "cl1-jeton-de-test");
        }
    }

    pub(super) fn cl2_registre(chemin: &str) -> Option<Option<String>> {
        crate::crypto::db_key_registry().lock().get(chemin).cloned()
    }

    pub(super) fn cl2_chemin_b(f: &Cl1) -> String {
        String::from(&*f.dir.sous(&format!("{CL1_B}.db")))
    }

    /// LA BORNE D'ATTENTE de la lecture de B : large devant une lecture du catalogue (une ligne indexée), et plus courte
    /// que le délai de lecture du client du coffre, si bien que, sous le défaut, la lecture de B n'aboutit pas avant elle.
    const CL2_ATTENTE_DE_LA_LECTURE_VOISINE_S: u64 = 5;

    /// CE QU'IL TIENT, par la mesure du point 3 : la clé de A hors du cache, un coffre local qui RETIENT sa réponse. Pendant
    /// que la résolution de A attend le coffre : le verrou du plan de contrôle est LIBRE (le coffre l'éprouve par
    /// `try_lock` à la réception de la requête) ; une lecture du catalogue pour B, sain, faite d'un autre fil, ABOUTIT
    /// (servie) avant que le coffre ne réponde. Puis la porte ouverte : A servi ; la clé de A enregistrée pour le chemin de
    /// A, l'entrée de B (en clair) intacte ; la clé reste au cache du client du coffre ; une seule requête.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `CL2_VERROU_TENU` (le verrou tenu pendant la résolution : verrou vu tenu, lecture
    /// de B en attente).
    #[test]
    fn cl2_une_lecture_du_catalogue_n_attend_pas_la_resolution_de_la_cle_d_un_autre_tenant() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        cl1_sans_coffre();
        let f = Cl1::neuf("cl2-verrou");
        let plan = f.st.tenants.control.as_ref().expect("fixture : mode 1").conn.clone();
        let verrou_vu_tenu: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(Vec::new()));
        let vus = verrou_vu_tenu.clone();
        let coffre = Cl2Coffre::neuf(f.cle.clone(), true, move || vus.lock().push(plan.try_lock().is_none()));
        f.cle_perdue();
        coffre.brancher();
        let mgr_a = f.st.tenants.clone();
        let resolution_a = std::thread::spawn(move || cl1_issue(&mgr_a.disponibilite_lu(CL1_A)));
        let a_au_coffre = coffre.attendre(1, 30);
        let (envoi, reception) = std::sync::mpsc::channel();
        let mgr_b = f.st.tenants.clone();
        std::thread::spawn(move || {
            let _ = envoi.send(cl1_issue(&mgr_b.disponibilite_lu(CL1_B)));
        });
        let b_pendant = reception.recv_timeout(std::time::Duration::from_secs(CL2_ATTENTE_DE_LA_LECTURE_VOISINE_S)).ok();
        coffre.ouvrir();
        let a = resolution_a.join().expect("fil de la résolution de A");
        if b_pendant.is_none() {
            let _ = reception.recv();
        }
        cl1_sans_coffre();
        assert!(a_au_coffre, "contrôle : la résolution de A a interrogé le coffre");
        assert_eq!(*verrou_vu_tenu.lock(), vec![false], "pendant la résolution de A, le verrou du plan de contrôle est LIBRE");
        assert_eq!(b_pendant.as_deref(), Some("servie"), "B, sain, est lu PENDANT la résolution de A, sans l'attendre");
        assert_eq!(a, "servie", "A servi une fois la clé rendue par le coffre");
        assert_eq!(cl2_registre(&f.chemin_a()), Some(Some(f.cle.clone())), "la clé de A est enregistrée pour le chemin de A");
        assert_eq!(cl2_registre(&cl2_chemin_b(&f)), Some(None), "l'entrée de B (en clair) est intacte : aucune clé de A pour son chemin");
        assert_eq!(crate::crypto::vault_key_cache_get(&f.rangement), Some(f.cle.clone()), "la clé résolue reste au cache du client du coffre");
        assert_eq!(coffre.requetes(), 1, "une seule requête");
    }

    /// CE QU'IL TIENT — ce que le verrou rendu change pour DEUX résolutions concurrentes du même tenant : le verrou ne les
    /// sérialise plus, si bien que la seconde n'attend plus la première pour trouver la clé au cache : chacune interroge
    /// le coffre (deux requêtes reçues pendant que la première est retenue). Les deux rendent A servi, sous la même clé,
    /// et le registre `chemin -> clé` porte cette clé pour le chemin de A.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `CL2_VERROU_TENU` (la seconde attend le verrou puis lit le cache : une requête).
    #[test]
    fn cl2_deux_resolutions_concurrentes_du_meme_tenant_interrogent_chacune_le_coffre() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        cl1_sans_coffre();
        let f = Cl1::neuf("cl2-concurrentes");
        let coffre = Cl2Coffre::neuf(f.cle.clone(), true, || {});
        f.cle_perdue();
        coffre.brancher();
        let (mgr_1, mgr_2) = (f.st.tenants.clone(), f.st.tenants.clone());
        let premiere = std::thread::spawn(move || cl1_issue(&mgr_1.disponibilite_lu(CL1_A)));
        let une = coffre.attendre(1, 30);
        let seconde = std::thread::spawn(move || cl1_issue(&mgr_2.disponibilite_lu(CL1_A)));
        let deux = coffre.attendre(2, CL2_ATTENTE_DE_LA_LECTURE_VOISINE_S);
        coffre.ouvrir();
        let issues = (premiere.join().expect("première résolution"), seconde.join().expect("seconde résolution"));
        cl1_sans_coffre();
        assert!(une, "contrôle : la première résolution a interrogé le coffre");
        assert!(deux, "la seconde résolution interroge le coffre pendant que la première est retenue");
        assert_eq!(coffre.requetes(), 2, "deux requêtes, une par résolution");
        assert_eq!(issues, ("servie".to_string(), "servie".to_string()), "les deux servent A");
        assert_eq!(cl2_registre(&f.chemin_a()), Some(Some(f.cle.clone())), "le registre porte la clé de A pour le chemin de A");
    }

    // -------------------------------------------------------------------------------------
    // (11) LA LIGNE QUI CHANGE PENDANT LA RÉSOLUTION — relue sous le verrou avant tout enregistrement.
    // -------------------------------------------------------------------------------------

    /// Le détail rendu quand la ligne du tenant a changé pendant la résolution de sa clé.
    const CL2_DETAIL_LIGNE_CHANGEE: &str = "la ligne du tenant a changé au catalogue pendant la résolution de sa clé : aucune \
         clé enregistrée";
    /// La référence de la clé d'un A recréé, en clair dans le catalogue (aucun coffre n'est interrogé pour elle).
    const CL2_REF_DU_A_RECREE: &str = "literal:cl2-cle-du-a-recree";

    /// L'issue de `disponibilite_lu`, la cause du tenant non ouvert donnée EN ENTIER (classe et détail).
    fn cl2_issue_entiere(o: &rusqlite::Result<OuvertureDuTenant<()>>) -> String {
        match o {
            Ok(OuvertureDuTenant::NonOuvert(c)) => format!("non ouvert : {c:?}"),
            autre => cl1_issue(autre),
        }
    }

    fn cl2_ligne_changee() -> String {
        format!("non ouvert : TenantNonOuvert {{ classe: CleNonResolue, detail: {CL2_DETAIL_LIGNE_CHANGEE:?} }}")
    }

    /// A, sa clé hors du cache, résolu par un coffre local qui joue `geste` sur le plan de contrôle avant de répondre la
    /// clé d'avant : rend l'issue entière de cette résolution, puis le registre au chemin de A et au chemin de B, et le
    /// cache du client du coffre pour la clé de A, relus JUSTE après elle ; enfin si le geste a réussi et le nombre de
    /// requêtes reçues.
    fn cl2_resolution_pendant_laquelle(f: &Cl1, geste: impl Fn(&TenantDbManager) -> bool + Send + Sync + 'static) -> (String, Option<Option<String>>, Option<Option<String>>, Option<String>, bool, usize) {
        let mgr = f.st.tenants.clone();
        let reussi = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let note = reussi.clone();
        let coffre = Cl2Coffre::neuf(f.cle.clone(), false, move || note.store(geste(&mgr), std::sync::atomic::Ordering::SeqCst));
        f.cle_perdue();
        coffre.brancher();
        let issue = cl2_issue_entiere(&f.st.tenants.disponibilite_lu(CL1_A));
        let releves = (cl2_registre(&f.chemin_a()), cl2_registre(&cl2_chemin_b(f)), crate::crypto::vault_key_cache_get(&f.rangement));
        cl1_sans_coffre();
        (issue, releves.0, releves.1, releves.2, reussi.load(std::sync::atomic::Ordering::SeqCst), coffre.requetes())
    }

    /// CE QU'IL TIENT : A DÉTRUIT puis RECRÉÉ au même chemin, sous une autre clé, pendant que sa clé d'avant se résout. La
    /// ligne relue n'est plus celle qui a été lue : rien n'est enregistré, l'issue est « non ouvert », classe clé non
    /// résolue, avec son détail ; le registre porte, pour ce chemin, la clé du A recréé — jamais celle de l'ancien ; la clé
    /// de l'ancien, que la résolution avait remise au cache du client du coffre après la destruction, en est retirée. La
    /// lecture suivante sert le A recréé.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `CL2_SANS_RELECTURE` (enregistré et servi sans relire la ligne),
    /// `CL2_RELECTURE_CHEMIN_SEUL` (la relecture ne compare que le chemin), `CL2_SANS_OUBLI` (la clé de l'ancien laissée au
    /// cache du client du coffre).
    #[test]
    fn cl2_un_tenant_recree_pendant_la_resolution_n_herite_pas_de_l_ancienne_cle() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        cl1_sans_coffre();
        let f = Cl1::neuf("cl2-recree");
        let chemin_a = f.chemin_a();
        let (issue, registre_a, _, cache, reussi, requetes) = cl2_resolution_pendant_laquelle(&f, move |mgr| {
            tenant_destroy(mgr, CL1_A).is_ok() && tenant_provision(mgr, CL1_A, CL1_A, &chemin_a, CL2_REF_DU_A_RECREE).is_ok()
        });
        assert!(reussi, "fixture : A détruit puis recréé pendant la résolution");
        assert_eq!(requetes, 1, "contrôle : une requête au coffre");
        assert_eq!(issue, cl2_ligne_changee(), "la ligne a changé : non ouvert, rien d'enregistré");
        assert_eq!(registre_a, Some(Some("cl2-cle-du-a-recree".to_string())), "le chemin de A porte la clé du A recréé, jamais celle de l'ancien");
        assert_eq!(cache, None, "la clé de l'ancien A n'est pas laissée au cache du client du coffre");
        assert_eq!(cl1_issue(&f.st.tenants.disponibilite_lu(CL1_A)), "servie", "la lecture suivante sert le A recréé");
    }

    /// CE QU'IL TIENT : A DÉTRUIT pendant que sa clé se résout. La ligne relue est absente : « non servable » ; aucune
    /// entrée n'est rendue au registre pour son chemin (la destruction l'a retirée) ; la clé n'est pas laissée au cache du
    /// client du coffre.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `CL2_SANS_RELECTURE`, `CL2_SANS_OUBLI`.
    #[test]
    fn cl2_un_tenant_detruit_pendant_la_resolution_ne_laisse_aucune_cle_en_memoire() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        cl1_sans_coffre();
        let f = Cl1::neuf("cl2-detruit");
        let (issue, registre_a, _, cache, reussi, _) = cl2_resolution_pendant_laquelle(&f, |mgr| tenant_destroy(mgr, CL1_A).is_ok());
        assert!(reussi, "fixture : A détruit pendant la résolution");
        assert_eq!(issue, "non servable", "la ligne relue est absente");
        assert_eq!(registre_a, None, "aucune clé rendue au registre pour le chemin du tenant détruit");
        assert_eq!(cache, None, "aucune clé laissée au cache du client du coffre");
    }

    /// CE QU'IL TIENT : A SUSPENDU pendant que sa clé se résout. La ligne relue est suspendue : « non servable » ; la clé,
    /// toujours portée par la ligne, reste au cache du client du coffre (rien n'est oublié d'une clé que le catalogue
    /// désigne encore).
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `CL2_SANS_RELECTURE`, `CL2_RELECTURE_SANS_SUSPENSION` (la suspension relue
    /// ignorée), `CL2_OUBLI_TOUJOURS` (la clé oubliée alors que la ligne la porte encore).
    #[test]
    fn cl2_un_tenant_suspendu_pendant_la_resolution_n_est_pas_servi() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        cl1_sans_coffre();
        let f = Cl1::neuf("cl2-suspendu");
        let (issue, _, _, cache, reussi, _) = cl2_resolution_pendant_laquelle(&f, |mgr| {
            let cp = mgr.control.as_ref().expect("fixture : mode 1");
            let ecrit = cp.conn.lock().execute("UPDATE tenant SET suspended=1 WHERE id='cl1-a'", []);
            matches!(ecrit, Ok(1))
        });
        assert!(reussi, "fixture : A suspendu pendant la résolution");
        assert_eq!(issue, "non servable", "la ligne relue est suspendue");
        assert_eq!(cache, Some(f.cle.clone()), "la clé toujours désignée par la ligne reste au cache");
    }

    /// CE QU'IL TIENT : la table du catalogue retirée pendant que la clé de A se résout. La relecture échoue : l'issue est
    /// la ligne NON LUE, cause du moteur jointe — ni servie, ni absente.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `CL2_SANS_RELECTURE`.
    #[test]
    fn cl2_une_relecture_qui_echoue_rend_la_ligne_non_lue() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        cl1_sans_coffre();
        let f = Cl1::neuf("cl2-relecture");
        let (issue, _, _, _, reussi, _) = cl2_resolution_pendant_laquelle(&f, |mgr| {
            let cp = mgr.control.as_ref().expect("fixture : mode 1");
            let retiree = cp.conn.lock().execute_batch("ALTER TABLE tenant RENAME TO cl2_tenant;");
            retiree.is_ok()
        });
        f.plan("ALTER TABLE cl2_tenant RENAME TO tenant;");
        assert!(reussi, "fixture : table du catalogue retirée pendant la résolution");
        assert_eq!(issue, "non lu : no such table: tenant", "la relecture non faite rend la ligne non lue");
        assert_eq!(cl1_issue(&f.st.tenants.disponibilite_lu(CL1_A)), "servie", "contrôle : la table remise, A servi");
    }

    /// CE QU'IL TIENT : le chemin de A repointé sur celui de B pendant que la clé de A se résout. La ligne relue désigne
    /// un autre chemin : non ouvert, avec son détail ; l'entrée de B (en clair) reste intacte — la clé de A n'est jamais
    /// enregistrée pour le chemin d'un autre tenant ; celle du chemin de A est celle d'avant ; la clé, toujours désignée
    /// par la ligne, reste au cache.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `CL2_SANS_RELECTURE`, `CL2_RELECTURE_CLE_SEULE` (la relecture ne compare que la
    /// référence de la clé), `CL2_ENREGISTRE_AU_CHEMIN_RELU` (la clé enregistrée pour le chemin relu).
    #[test]
    fn cl2_un_chemin_repointe_pendant_la_resolution_ne_recoit_pas_la_cle() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
        cl1_sans_coffre();
        let f = Cl1::neuf("cl2-repointe");
        let chemin_b = cl2_chemin_b(&f);
        let avant_b = cl2_registre(&chemin_b);
        let (issue, registre_a, registre_b, cache, reussi, _) = cl2_resolution_pendant_laquelle(&f, move |mgr| {
            let cp = mgr.control.as_ref().expect("fixture : mode 1");
            let ecrit = cp.conn.lock().execute("UPDATE tenant SET db_path=?1 WHERE id='cl1-a'", params![chemin_b]);
            matches!(ecrit, Ok(1))
        });
        assert!(reussi, "fixture : chemin de A repointé pendant la résolution");
        assert_eq!(avant_b, Some(None), "contrôle : B, en clair, a son entrée");
        assert_eq!(issue, cl2_ligne_changee(), "la ligne a changé : non ouvert, rien d'enregistré");
        assert_eq!(registre_b, Some(None), "aucune clé de A pour le chemin de B");
        assert_eq!(registre_a, Some(Some(f.cle.clone())), "le chemin de A garde l'entrée d'avant");
        assert_eq!(cache, Some(f.cle.clone()), "la clé toujours désignée par la ligne reste au cache");
    }

    // -------------------------------------------------------------------------------------
    // (12) LES ENTRÉES QUI NE SONT PAS DES LOTS, DANS LA CARTE DU PASSAGE — sous-processus.
    // -------------------------------------------------------------------------------------

    const CL2_ENFANT_ENTREES: &str = "CL2_ENFANT_ENTREES_HORS_LOT_DU_TENANT_NON_OUVERT";
    const CL2_PASSAGE: &str = "CL2-PASSAGE";
    const CL2_FIN: &str = "CL2-FIN";

    /// CE QU'IL TIENT, par la vraie boucle (`ingest_once`) dans un processus neuf (mémo des lignes vide) : la clé de A
    /// perdue, TROIS entrées marquées pour A qui ne sont pas des lots (ni `.json` ni `.ndjson`) et un lot de B dans le même
    /// passage. La première entrée de A fait la tentative et inscrit A dans la carte du passage ; les deux suivantes
    /// passent par la carte. Aucune n'est comptée (`Lue(0)`), aucune n'est dite (aucune ligne `[ingest]` pendant le
    /// passage), toutes restent au spool, intactes, sans quarantaine ; le lot de B s'ingère.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `V2_I_PASSAGE_ENTREE` (la garde de l'entrée hors lot ignorée dans la branche de la
    /// carte, `ingest/mod.rs` : deux abandons comptés et la ligne du spool dite).
    #[test]
    fn cl2_les_entrees_hors_lot_du_tenant_non_ouvert_ne_sont_ni_comptees_ni_dites_dans_la_carte_du_passage() {
        if std::env::var(CL2_ENFANT_ENTREES).is_ok() {
            let _env = crate::tests::VERROU_ENV_PROCESSUS.write();
            cl2_enfant_entrees();
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::tenant_actif_non_ouvrable_n_est_pas_un_tenant_absent::cl2_les_entrees_hors_lot_du_tenant_non_ouvert_ne_sont_ni_comptees_ni_dites_dans_la_carte_du_passage",
            ])
            .env(CL2_ENFANT_ENTREES, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        let debut = stderr.find(CL2_PASSAGE).unwrap_or_else(|| panic!("contrôle : l'enfant marque le passage :\n{stdout}\n{stderr}"));
        let fin = stderr.find(CL2_FIN).unwrap_or_else(|| panic!("contrôle : l'enfant marque la fin du passage :\n{stdout}\n{stderr}"));
        let pendant: Vec<&str> = stderr[debut..fin].lines().filter(|l| l.starts_with("[ingest] ")).collect();
        assert_eq!(pendant, Vec::<&str>::new(), "aucune ligne du spool pour des entrées qui ne sont pas des lots :\n{stderr}");
        assert_eq!(sortie.status.code(), Some(0), "l'enfant sort en 0 (bilan, entrées intactes, lot de B ingéré) : {stdout}\n{stderr}");
    }

    fn cl2_enfant_entrees() {
        cl1_sans_coffre();
        let f = Cl1::neuf("cl2-entrees");
        let spool = std::path::PathBuf::from(f.st.spool.as_str());
        let entrees: Vec<(std::path::PathBuf, Vec<u8>)> = (1..=3)
            .map(|n| {
                let chemin = spool.join(format!("note-{n}#T#{CL1_A}#T#.txt"));
                let octets = format!("pas un lot {n}").into_bytes();
                std::fs::write(&chemin, &octets).expect("enfant : entrée hors lot déposée");
                (chemin, octets)
            })
            .collect();
        let (lot_b, _) = f.lot(51, CL1_B, "cl2srcn");
        f.cle_perdue();
        assert_eq!(cl1_issue(&f.st.tenants.handle_ouverte_lu(CL1_A)), "non ouvert : clé non résolue", "enfant : A non ouvert");
        eprintln!("{CL2_PASSAGE}");
        let bilan = ingest_once(&f.st.tenants, &f.st.spool);
        eprintln!("{CL2_FIN}");
        f.cle_rendue();
        assert_eq!(bilan, crate::mesure_environnement::Mesure::Lue(0), "enfant : aucune entrée hors lot n'est un abandon");
        for (chemin, octets) in &entrees {
            assert_eq!(std::fs::read(chemin).ok().as_deref(), Some(octets.as_slice()), "enfant : {} reste au spool, intacte", chemin.display());
        }
        assert!(!f.quarantaine().exists(), "enfant : aucune quarantaine");
        assert!(!lot_b.exists(), "enfant : le lot de B s'ingère dans le même passage");
    }
}
