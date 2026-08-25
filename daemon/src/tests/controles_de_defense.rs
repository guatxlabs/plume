    // ================================================================================================
    // `P11.18-i` — UNE ALERTE DE CONTRÔLES QU'ON PEUT LIRE, ET UN CATALOGUE VIDE QUI SE DIT.
    //
    // CE QUE CES TESTS MESURENT, ET DANS QUEL ORDRE :
    //   1. L'ÉNONCÉ. L'alerte NOMME les contrôles manquants, la MACHINE et DEPUIS QUAND. Les trois
    //      réponses étaient déjà en base ; aucune n'était rendue. Témoin NÉGATIF : un contrôle TENU
    //      n'est jamais nommé. Contrôle POSITIF : l'énoncé n'est plus celui d'avant, mot pour mot.
    //   2. LA BORNE DE TEMPS. « Depuis quand » est LU dans la série d'instantanés (une ligne par état,
    //      jamais purgée) et non inventé — et quand la série ne porte aucun autre état, l'alerte le
    //      DIT au lieu de fabriquer une date.
    //   3. LE CATALOGUE VIDE. Zéro contrôle évalué n'est pas « zéro manquant ». Témoin négatif : un
    //      catalogue NON vide dont tout est tenu reste silencieux — sans quoi la nouvelle alerte
    //      remplacerait un mensonge par du bruit.
    //   4. LE TROISIÈME CAS. Une charge qui ne DÉCLARE pas de liste n'est pas un catalogue vide : le
    //      démon ne peut pas affirmer un vide qu'il n'a pas lu, et il dit l'écart plutôt que de le taire.
    //   5. LE CATALOGUE LIVRÉ. Garde DÉRIVÉE sur les deux capteurs : le catalogue n'attend plus un
    //      verrou que rien dans l'arbre ne pose et qu'une autre voie porte déjà — avec son contrôle
    //      positif, sans lequel la garde passerait au vert si les DEUX capteurs le perdaient.
    // ================================================================================================

    /// Enveloppe spool `kind=controls` — MÊME FORME que `collectors/controls.sh` publie. `controls` est
    /// passée telle quelle pour que les charges dégradées (liste vide, liste absente) soient exerçables.
    fn ctl_enveloppe(host: &str, ts: i64, hash: &str, data: Value) -> String {
        json!({ "ts": ts, "host": host, "kind": "controls", "hash": hash, "data": data }).to_string()
    }

    /// Un contrôle tel que le capteur l'écrit. `ok=None` == `ok:null` == verdict NON ÉTABLI.
    fn ctl_item(id: &str, ok: Option<bool>) -> Value {
        match ok {
            Some(b) => json!({ "id": id, "ok": b, "detail": id }),
            None => json!({ "id": id, "ok": null, "verdict": "indetermine", "cause": "source_illisible", "detail": id }),
        }
    }

    /// Le titre de l'UNIQUE alerte d'une règle donnée (échoue s'il y en a zéro ou plusieurs : un test
    /// qui lirait « la première » masquerait une régression de déduplication).
    fn ctl_titre(conn: &Connection, regle: &str) -> String {
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM alert WHERE rule=?1", params![regle], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1, "attendu UNE alerte `{regle}`, trouvé {n}");
        conn.query_row("SELECT title FROM alert WHERE rule=?1", params![regle], |r| r.get(0)).unwrap()
    }

    fn ctl_compte(conn: &Connection, regle: &str) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM alert WHERE rule=?1", params![regle], |r| r.get(0)).unwrap()
    }

    /// (1) L'ÉNONCÉ — LESQUELS, SUR QUELLE MACHINE, DEPUIS QUAND.
    ///
    /// AVANT (mesuré le 2026-08-25 sur l'arbre livré) le titre valait exactement « 2 contrôle(s) de
    /// défense MANQUANT(S) » : un nombre, et rien d'autre. La liste des contrôles était DÉJÀ dans
    /// `alert.detail` (charge du capteur recopiée à la levée) et la machine DÉJÀ dans `alert.host` ;
    /// aucune des deux n'était rendue nulle part.
    #[test]
    fn l_alerte_de_controles_nomme_les_controles_la_machine_et_le_non_etabli() {
        let (st, spool) = ing_state_with_spool();
        let ts0 = 1_785_600_000i64; // 2026-08-01 UTC
        let data = json!({
            "failed": 2,
            "controls": [
                ctl_item("sysctl_kptr_restrict", Some(true)),
                ctl_item("auditd_active", Some(false)),
                ctl_item("fail2ban_active", Some(false)),
                ctl_item("aide_db", None),
            ]
        });
        depose_spool(&spool, "srv01", 0, &ctl_enveloppe("srv01", ts0, "etat_a", data));
        ingest_once(&st.tenants, &st.spool);

        let conn = st.db.lock();
        let titre = ctl_titre(&conn, "control.catalog");
        // LESQUELS.
        assert!(titre.contains("auditd_active"), "le contrôle manquant n'est pas nommé : {titre}");
        assert!(titre.contains("fail2ban_active"), "le second contrôle manquant n'est pas nommé : {titre}");
        // TÉMOIN NÉGATIF — un contrôle TENU n'a rien à faire dans une alerte de manque.
        assert!(!titre.contains("sysctl_kptr_restrict"), "un contrôle TENU est nommé comme manquant : {titre}");
        // SUR QUELLE MACHINE — la colonne `host` était liée par l'INSERT depuis le cloisonnement.
        assert!(titre.contains("srv01"), "la machine n'est pas nommée : {titre}");
        // LE COMPTE EST UN MINORANT tant qu'un verdict n'est pas établi, et l'énoncé le dit.
        assert!(titre.contains("NON ÉTABLI"), "le verdict non établi n'est pas dit : {titre}");
        // DEPUIS QUAND — aucune autre empreinte dans la série : on ne fabrique pas de date.
        assert!(
            titre.contains("aucun état DIFFÉRENT"),
            "sans état antérieur, l'alerte doit le DIRE au lieu d'inventer une date : {titre}"
        );
        // CONTRÔLE POSITIF — l'énoncé d'avant, mot pour mot, ne peut plus être celui qui est écrit.
        assert_ne!(titre, "2 contrôle(s) de défense MANQUANT(S)", "l'énoncé n'a pas changé");
        drop(conn);
        let _ = std::fs::remove_dir_all(&spool);
    }

    /// (2) LA BORNE DE TEMPS EST LUE, PAS INVENTÉE. La table `snapshot` garde une ligne par ÉTAT : le
    /// heartbeat n'avance que le `ts` de la dernière, celles des états précédents gardent le leur, et
    /// aucune rétention ne les efface. Le dernier instant où la machine était dans un AUTRE état borne
    /// donc l'état courant par en haut. MUTATION : la VALEUR qui change est le jour cité dans le titre
    /// de la seconde alerte — absent du premier titre, présent dans le second.
    #[test]
    fn depuis_quand_est_lu_dans_la_serie_dinstantanes() {
        let (st, spool) = ing_state_with_spool();
        let ts0 = 1_785_600_000i64; // 2026-08-01 UTC
        let ts1 = ts0 + 86_400; // 2026-08-02 UTC — empreinte DIFFÉRENTE le lendemain
        let etat = |failed: i64, ids: Vec<&str>| {
            json!({ "failed": failed, "controls": ids.iter().map(|i| ctl_item(i, Some(false))).collect::<Vec<_>>() })
        };
        depose_spool(&spool, "srv01", 0, &ctl_enveloppe("srv01", ts0, "etat_a", etat(2, vec!["auditd_active", "aide_db"])));
        ingest_once(&st.tenants, &st.spool);
        depose_spool(&spool, "srv01", 1, &ctl_enveloppe("srv01", ts1, "etat_b", etat(1, vec!["auditd_active"])));
        ingest_once(&st.tenants, &st.spool);

        let conn = st.db.lock();
        let titres: Vec<(i64, String)> = {
            let mut s = conn
                .prepare("SELECT ts,title FROM alert WHERE rule='control.catalog' ORDER BY ts")
                .unwrap();
            let v = s.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().flatten().collect();
            v
        };
        assert_eq!(titres.len(), 2, "deux ÉTATS distincts -> deux alertes (la dédup porte sur l'état)");
        assert!(
            titres[0].1.contains("aucun état DIFFÉRENT"),
            "premier état relevé : rien à citer, et c'est dit : {}", titres[0].1
        );
        assert!(
            titres[1].1.contains("depuis au moins le 2026-08-01"),
            "la borne doit être le jour du DERNIER état différent : {}", titres[1].1
        );
        drop(conn);
        let _ = std::fs::remove_dir_all(&spool);
    }

    /// (3) UN CATALOGUE VIDE SE DIT — ET UN CATALOGUE TENU RESTE SILENCIEUX.
    ///
    /// C'est l'invariant du chantier : un exploitant qui n'a plus aucun contrôle évalué ne doit pas
    /// obtenir un tableau de bord rassurant. La propriété est DÉRIVÉE de la charge (« zéro contrôle
    /// évalué »), jamais de la RAISON du zéro — outil absent, catalogue retiré, contrôles tous
    /// désactivés y tombent de la même façon.
    #[test]
    fn un_catalogue_vide_se_dit_au_lieu_de_rendre_une_posture_verte() {
        let (st, spool) = ing_state_with_spool();
        let ts0 = 1_785_600_000i64;
        depose_spool(&spool, "min01", 0, &ctl_enveloppe("min01", ts0, "vide", json!({ "failed": 0, "controls": [] })));
        ingest_once(&st.tenants, &st.spool);
        {
            let conn = st.db.lock();
            let titre = ctl_titre(&conn, "control.catalog.vide");
            assert!(titre.contains("min01"), "la machine où rien n'est mesuré doit être nommée : {titre}");
            assert!(titre.contains("VIDE"), "le catalogue vide doit être dit tel quel : {titre}");
            assert_eq!(
                ctl_compte(&conn, "control.catalog"), 0,
                "un catalogue vide n'a AUCUN contrôle manquant — l'alerte de manque n'a rien à dire"
            );
        }
        // TÉMOIN NÉGATIF — un catalogue NON vide, tout tenu : aucune des deux alertes. Sans lui, une
        // alerte qui partirait à chaque passage serait indiscernable de celle qu'on vient d'ajouter.
        depose_spool(
            &spool, "srv02", 1,
            &ctl_enveloppe("srv02", ts0, "tenu", json!({ "failed": 0, "controls": [ctl_item("auditd_active", Some(true))] })),
        );
        ingest_once(&st.tenants, &st.spool);
        let conn = st.db.lock();
        assert_eq!(
            ctl_compte(&conn, "control.catalog.vide"), 1,
            "une machine dont le catalogue est TENU ne doit pas être déclarée vide"
        );
        assert_eq!(ctl_compte(&conn, "control.catalog"), 0, "rien de manquant -> rien à lever");
        drop(conn);
        let _ = std::fs::remove_dir_all(&spool);
    }

    /// (4) « JE N'AI PAS LU DE LISTE » N'EST PAS « LA LISTE EST VIDE ». `POST /api/ingest` accepte
    /// n'importe quel `kind` : une charge `controls` sans liste n'autorise AUCUNE affirmation sur le
    /// catalogue. Et quand elle annonce un compte que rien ne nomme, l'écart est DIT — une liste plus
    /// courte que le compte se lirait autrement comme la liste complète.
    #[test]
    fn une_charge_sans_liste_ne_declare_pas_un_catalogue_vide() {
        let (st, spool) = ing_state_with_spool();
        let ts0 = 1_785_600_000i64;
        depose_spool(&spool, "tiers01", 0, &ctl_enveloppe("tiers01", ts0, "sans_liste", json!({ "failed": 2 })));
        ingest_once(&st.tenants, &st.spool);
        let conn = st.db.lock();
        assert_eq!(
            ctl_compte(&conn, "control.catalog.vide"), 0,
            "sans liste lue, le démon ne peut pas AFFIRMER que le catalogue est vide"
        );
        let titre = ctl_titre(&conn, "control.catalog");
        assert!(
            titre.contains("CHARGE INCOHÉRENTE"),
            "2 annoncés, 0 nommable : l'écart doit être dit, pas tu : {titre}"
        );
        drop(conn);
        let _ = std::fs::remove_dir_all(&spool);
    }

    /// (5) GARDE (SOURCE) — LE CATALOGUE LIVRÉ N'ATTEND PLUS UN VERROU QUE RIEN NE POSE.
    ///
    /// MESURÉ le 2026-08-25 : le catalogue vérifiait deux des trois jambes d'un verrou `iptables` que
    /// `collectors/firewall.sh` vérifie DÉJÀ intégralement, sous la même condition d'applicabilité et
    /// avec son alerte dédiée — deux alertes par jour pour un seul fait, et un désaccord sur la jambe
    /// omise. Aucun artefact livré ne CRÉE cette règle : les seules occurrences de la chaîne dans
    /// l'arbre étaient les vérifications elles-mêmes.
    ///
    /// La propriété gardée est une PROPRIÉTÉ, pas une liste d'identifiants : « le catalogue générique
    /// n'interroge aucun pare-feu ». Elle porte son CONTRÔLE POSITIF — la voie `firewall` doit, elle,
    /// continuer de l'interroger — sans quoi la garde rendrait vert le jour où les DEUX capteurs
    /// perdraient ce contrôle, c'est-à-dire exactement le trou qu'elle prétend surveiller.
    #[test]
    fn le_catalogue_livre_ninterroge_plus_le_pare_feu_ni_ne_se_tait_a_vide() {
        let racine = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
        let lire = |nom: &str| std::fs::read_to_string(racine.join("collectors").join(nom)).unwrap();
        // CODE EXÉCUTÉ seulement : les commentaires de ces deux capteurs EXPLIQUENT le retrait, et une
        // garde qui les compterait accuserait la documentation de ce qu'elle documente.
        let code = |src: &str| -> String {
            src.lines().filter(|l| !l.trim_start().starts_with('#')).collect::<Vec<_>>().join("\n")
        };
        let catalogue = code(&lire("controls.sh"));
        let pare_feu = code(&lire("firewall.sh"));

        assert!(
            !catalogue.contains("iptables"),
            "le catalogue générique interroge de nouveau un pare-feu : ce contrôle est porté par la \
             voie `firewall` (trois jambes, verdict indéterminé, alerte dédiée) et le dupliquer ici \
             lève DEUX alertes par jour pour un seul fait"
        );
        assert!(
            !catalogue.contains("plume_exit_nodata"),
            "le catalogue sort de nouveau en silence : un catalogue VIDE doit être PUBLIÉ, sinon la \
             machine où rien n'est mesuré se lit comme une machine dont le capteur n'a pas parlé"
        );
        assert!(
            catalogue.contains("spool_write"),
            "précondition : ce capteur publie bien un instantané (sinon les deux assertions ci-dessus \
             seraient vraies pour une raison qui n'a rien à voir)"
        );
        // CONTRÔLE POSITIF (1) — l'autre voie porte TOUJOURS le contrôle retiré d'ici.
        assert!(
            pare_feu.contains("iptables") && pare_feu.contains("ip6tables"),
            "CONTRÔLE POSITIF : `firewall.sh` ne vérifie plus le verrou — le retirer du catalogue \
             générique ne se justifie QUE parce que cette voie-là le porte"
        );
        // CONTRÔLE POSITIF (2) — la sortie « rien de neuf » existe toujours dans le dépôt : son
        // absence ici est un CHOIX, pas la disparition de la primitive.
        let lib = lire("lib.sh");
        assert!(
            lib.contains("plume_exit_nodata()"),
            "CONTRÔLE POSITIF : la primitive de sortie « rien de neuf » a disparu — l'assertion \
             ci-dessus ne prouverait alors plus rien"
        );
    }

    /// (6) UNE LISTE TRONQUÉE LE DIT. Un titre est lu dans une ligne de file d'alertes : au-delà de
    /// quelques identifiants il masque ses voisines. La borne est donc posée — mais une liste coupée en
    /// silence AFFIRMERAIT qu'il n'y a rien d'autre, ce qui est le défaut que ce chantier poursuit.
    #[test]
    fn une_liste_de_manquants_tronquee_dit_ce_quelle_ne_montre_pas() {
        let ids: Vec<Value> = (0..9).map(|i| ctl_item(&format!("ctl_{i}"), Some(false))).collect();
        let data = json!({ "failed": 9, "controls": ids });
        let etat = crate::controles_de_defense::lire_le_catalogue(&data);
        assert_eq!(etat.manquants.len(), 9);
        assert!(!etat.declare_vide(), "une liste de neuf éléments n'est pas un catalogue vide");
        let titre = crate::controles_de_defense::enonce_des_manquants(&etat, 9, Some("srv01"), None);
        assert!(titre.contains("ctl_0") && titre.contains("ctl_5"), "les premiers doivent être nommés : {titre}");
        assert!(!titre.contains("ctl_6"), "la borne doit mordre : {titre}");
        assert!(titre.contains("(+3)"), "ce qui n'est pas montré doit être COMPTÉ : {titre}");
        // TÉMOIN NÉGATIF — sous la borne, aucun reste n'est annoncé.
        let court = json!({ "failed": 1, "controls": [ctl_item("auditd_active", Some(false))] });
        let etat_court = crate::controles_de_defense::lire_le_catalogue(&court);
        let titre_court = crate::controles_de_defense::enonce_des_manquants(&etat_court, 1, Some("srv01"), None);
        assert!(!titre_court.contains("(+"), "aucun reste à annoncer ici : {titre_court}");
        assert!(!titre_court.contains("CHARGE INCOHÉRENTE"), "compte et noms s'accordent : {titre_court}");
    }
