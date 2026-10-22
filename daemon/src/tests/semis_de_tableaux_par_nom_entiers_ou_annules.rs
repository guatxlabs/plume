// =====================================================================================
// `P10.28-l` (les semis par nom) — LES DIX TABLEAUX DE BORD SEMÉS PAR NOM ET LA RÈGLE CLAMAV S'ÉCRIVENT ENTIERS OU PAS
// DU TOUT, ET UN REFUS EST COMPTÉ.
//
// LE DÉFAUT, LU SUR 7ecbec19 : `seed_dashboard_head_named` (seeds.rs) écrivait l'en-tête du tableau hors transaction,
// rattachait à la vue en `let _`, puis chaque appelant (web, mail, accès données, carte d'accès, SCA, vulnérabilités,
// conformité, RBAC k8s, MinIO, Vault) écrivait ses panneaux en `let _ = conn.execute(...)`. Un panneau refusé laissait
// un tableau PARTIEL (ou vide) que l'idempotence par nom tenait pour semé : jamais réparé. `seed_malware_rule` avalait
// de même son INSERT. La présence lue par `.is_ok()` prenait une lecture RATÉE pour une ABSENCE (l'énoncé disait
// l'inverse) : le semis réécrivait alors un second tableau du même nom.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : une base EN SERVICE déjà amputée (tableau présent, panneaux manquants) n'est pas
// réparée — le nom présent dit le semis fait ; un rattachement à la vue qui rend `Ok(0)` reste accepté (comme dans
// `seed_dashboard_head`) ; `seed_rollup_dashboard` (main.rs) et `seed_banpass_dashboard` (rollups.rs), semés par nom
// sous la même forme fautive, ne sont pas touchés ; l'aveu au journal (`eprintln!`) n'est pas capturé ; un `COMMIT`
// refusé n'est pas provoqué (il est compté sous la même étape que l'écriture refusée). Les requêtes des panneaux sont
// jugées par la relecture des littéraux (inchangés octet pour octet) ; les témoins jugent titre, `is_soql`, `viz`,
// position et largeur. Aucune variable d'environnement n'est lue par ces semis.
// =====================================================================================
mod semis_de_tableaux_par_nom_entiers_ou_annules {
    use super::*;
    use crate::comptes_de_transaction::compte_des_temoins;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    /// (étiquette, nom du tableau, semis, vue, replié, panneaux « titre|is_soql|viz|position|cols » — ceux d'avant).
    type StpnSemis = (&'static str, &'static str, fn(&Connection), &'static str, bool, Vec<&'static str>);

    fn stpn_semis() -> Vec<StpnSemis> {
        vec![
            (
                "web",
                "Trafic web",
                seed_web_dashboard,
                "Réseau & Web",
                false,
                vec![
                    "Requêtes dans le temps|1|line|0|2",
                    "Top hôtes (sites)|0|bar|1|2",
                    "Codes statut|0|bar|2|2",
                    "Top clients externes|1|table|3|2",
                    "Top URLs|0|table|4|2",
                    "Erreurs 4xx/5xx (détail)|1|table|5|2",
                    "Cloudflare (hors self)|1|table|6|2",
                ],
            ),
            (
                "mail",
                "Mail — flux & verdicts",
                seed_mail_dashboard,
                "Mail",
                false,
                vec![
                    "Verdicts|0|bar|0|2",
                    "Flux mail dans le temps|1|line|1|2",
                    "Top expéditeurs|1|table|2|2",
                    "Top destinataires|1|table|3|2",
                    "Menaces (virus / bannis)|1|table|4|2",
                    "Échecs d'authentification|1|table|5|2",
                ],
            ),
            (
                "dataaccess",
                "Accès données (Varonis)",
                seed_dataaccess_dashboard,
                "Accès données",
                false,
                vec![
                    "Accès aux secrets / creds|1|table|0|2",
                    "Accès par utilisateur|0|bar|1|2",
                    "Accès par action|0|bar|2|2",
                    "Top fichiers touchés|0|table|3|2",
                    "Activité dans le temps|1|line|4|2",
                    "Détail récent (qui/action/fichier)|1|table|5|2",
                ],
            ),
            (
                "dataacl",
                "Carte d'accès (Varonis)",
                seed_dataacl_dashboard,
                "Accès données",
                true,
                vec![
                    "Risques (accès global / SUID)|1|table|0|2",
                    "Par propriétaire|0|bar|1|2",
                    "Par groupe|0|bar|2|2",
                    "Carte des dossiers (perms)|1|table|3|2",
                    "Tout (chemin / owner / perms)|1|table|4|2",
                ],
            ),
            (
                "sca",
                "Posture de configuration (SCA/CIS)",
                seed_sca_dashboard,
                "Endpoint (BYO-agent)",
                false,
                vec![
                    "Contrôles pass / fail|1|bar|0|2",
                    "Échecs par hôte|1|table|1|2",
                    "Échecs par benchmark|1|bar|2|2",
                    "Cadres de conformité impactés|1|table|3|2",
                    "Contrôles échoués (détail)|1|table|4|2",
                ],
            ),
            (
                "vuln",
                "Vulnérabilités (CVE endpoint)",
                seed_vuln_dashboard,
                "Endpoint (BYO-agent)",
                true,
                vec![
                    "CVE par sévérité|1|bar|0|2",
                    "Hôtes les plus vulnérables|1|table|1|2",
                    "Top CVE|1|table|2|2",
                    "Paquets les plus touchés|1|table|3|2",
                    "Critiques / hautes (détail)|1|table|4|2",
                ],
            ),
            (
                "conformite_pci",
                "Conformité — PCI DSS",
                stpn_conformite_pci,
                "Conformité (posture)",
                false,
                vec![
                    "Contrôles pass / fail|1|bar|0|2",
                    "Échecs par contrôle|1|table|1|2",
                    "Échecs par hôte|1|table|2|2",
                    "Contrôles échoués (détail)|1|table|3|2",
                ],
            ),
            (
                "conformite_hipaa",
                "Conformité — HIPAA",
                stpn_conformite_hipaa,
                "Conformité (posture)",
                true,
                vec![
                    "Contrôles pass / fail|1|bar|0|2",
                    "Échecs par contrôle|1|table|1|2",
                    "Échecs par hôte|1|table|2|2",
                    "Contrôles échoués (détail)|1|table|3|2",
                ],
            ),
            (
                "kube_rbac",
                "RBAC k8s (Varonis)",
                seed_kube_rbac_dashboard,
                "Accès infra",
                false,
                vec![
                    "Cluster-admin (clés du royaume)|1|table|0|2",
                    "Accès sensible (secrets / cluster-admin)|1|table|1|2",
                    "Par rôle|0|bar|2|2",
                    "Par sujet|0|table|3|2",
                    "Map complète (sujet -> rôle)|1|table|4|2",
                ],
            ),
            (
                "minio",
                "MinIO / S3 (Varonis)",
                seed_minio_dashboard,
                "Accès infra",
                true,
                vec![
                    "Buckets exposés (PUBLIC)|1|table|0|2",
                    "Accès sensible (admin / rw)|1|table|1|2",
                    "Utilisateurs -> policy|1|table|2|2",
                    "Buckets (accès)|1|table|3|2",
                    "Stockage|1|table|4|2",
                ],
            ),
            (
                "vault",
                "Vault — accès secrets (Varonis)",
                seed_vault_dashboard,
                "Accès infra",
                true,
                vec![
                    "Accès secrets (volume)|1|line|0|2",
                    "Top chemins consultés|1|table|1|2",
                    "Par opération|1|bar|2|2",
                    "Qui accède (identités)|1|table|3|2",
                    "Refus / erreurs|1|table|4|2",
                ],
            ),
        ]
    }

    /// Les deux semis de conformité jugés (PCI DSS déplié, HIPAA replié), sous la forme `fn(&Connection)` des autres.
    fn stpn_conformite_pci(conn: &Connection) {
        seed_compliance_dashboard(conn, "pci_dss", "PCI DSS", true);
    }

    fn stpn_conformite_hipaa(conn: &Connection) {
        seed_compliance_dashboard(conn, "hipaa", "HIPAA", false);
    }

    /// Les onze semis jugés : un tableau pour chacun des dix semeurs par nom, la conformité deux fois.
    const STPN_SEMIS_JUGES: usize = 11;

    const STPN_REGLE_CLAMAV: &str = "ClamAV : virus détecté";
    const STPN_LIGNE_CLAMAV: &str = "ClamAV : virus détecté|search source=mail category=malware | stats count|1|>|0.0|4|300|300|0";

    fn stpn_tableaux(conn: &Connection, nom: &str) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM dashboard WHERE name=?1", params![nom], |r| r.get(0)).expect("tableaux de ce nom")
    }

    fn stpn_panneaux_en_tout(conn: &Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM panel", [], |r| r.get(0)).expect("panneaux")
    }

    fn stpn_panneaux(conn: &Connection, nom: &str) -> Vec<String> {
        let mut st = conn
            .prepare(
                "SELECT p.title||'|'||p.is_soql||'|'||p.viz||'|'||p.position||'|'||p.cols FROM panel p \
                 JOIN dashboard d ON d.id=p.dashboard_id WHERE d.name=?1 AND p.query<>'' ORDER BY p.position, p.id",
            )
            .expect("select");
        st.query_map(params![nom], |r| r.get::<_, String>(0)).expect("panneaux").collect::<Result<Vec<_>, _>>().expect("panneaux lus")
    }

    fn stpn_vue(conn: &Connection, nom: &str) -> (Option<String>, i64) {
        conn.query_row(
            "SELECT v.name, d.collapsed FROM dashboard d LEFT JOIN view v ON v.id=d.view_id WHERE d.name=?1",
            params![nom],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("vue du tableau")
    }

    fn stpn_regles(conn: &Connection) -> Vec<String> {
        let mut st = conn
            .prepare(
                "SELECT name||'|'||query||'|'||is_soql||'|'||op||'|'||printf('%.1f',threshold)||'|'||severity||'|'||interval_s||'|'||window_s||'|'||enabled \
                 FROM rule WHERE name=?1 ORDER BY id",
            )
            .expect("select");
        st.query_map(params![STPN_REGLE_CLAMAV], |r| r.get::<_, String>(0)).expect("règles").collect::<Result<Vec<_>, _>>().expect("règles lues")
    }

    fn stpn_base_sur_disque(tag: &str) -> (crate::tmp_possede::TmpPossede, Connection) {
        let tmp = crate::tmp_possede::TmpPossede::neuf(tag);
        let p = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
        let conn = open_db(&p).expect("base sur disque");
        conn.execute_batch(include_str!("../../../db/schema.sql")).expect("schéma");
        assert!(migrate(&conn), "la chaîne de migrations doit aller au bout");
        (tmp, conn)
    }

    fn stpn_compte(conn: &Connection, geste: &str, etape: &str) -> u64 {
        compte_des_temoins(conn, &format!("geste de fond non validé seed : {geste} : {etape}"))
    }

    /// Refuse la lecture de la colonne `name` de `table` (le nom qui dit le semis fait) ; rien d'autre.
    fn stpn_refuser_la_lecture_du_nom(conn: &Connection, table: &'static str) {
        conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, column_name } if table_name == table && column_name == "name" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn stpn_rendre_la_lecture(conn: &Connection) {
        conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// INVERSE NOMINAL : sur une base neuve, chaque semis écrit son tableau, rattaché à sa vue (replié ou non), et ses
    /// panneaux comme avant ; un second appel n'ajoute rien.
    #[test]
    fn stpn_un_semis_par_nom_nominal_ecrit_son_tableau_entier_une_seule_fois() {
        assert_eq!(stpn_semis().len(), STPN_SEMIS_JUGES, "instrument : les onze semis sont jugés");
        for (tag, nom, semer, vue, replie, attendus) in stpn_semis() {
            let conn = test_db();
            assert_eq!(stpn_tableaux(&conn, nom), 0, "`{tag}` : instrument — base neuve sans ce tableau");
            semer(&conn);
            assert_eq!(stpn_tableaux(&conn, nom), 1, "`{tag}` : un tableau");
            assert_eq!(stpn_panneaux(&conn, nom), attendus, "`{tag}` : panneaux d'avant, dans l'ordre");
            assert_eq!(stpn_vue(&conn, nom), (Some(vue.to_string()), i64::from(replie)), "`{tag}` : vue et repli");
            let total = stpn_panneaux_en_tout(&conn);
            semer(&conn);
            assert_eq!(stpn_tableaux(&conn, nom), 1, "`{tag}` : second appel, aucun doublon");
            assert_eq!(stpn_panneaux_en_tout(&conn), total, "`{tag}` : second appel, aucun panneau de plus");
            assert!(conn.is_autocommit(), "`{tag}` : aucune transaction laissée ouverte");
        }
    }

    /// CE QU'IL TIENT, pour chacun des onze semis, chaque panneau refusé à son tour et deux refus (`RAISE(ABORT)`, et
    /// `RAISE(IGNORE)` qui rend `Ok(0)`) : après le refus, AUCUN tableau de ce nom et aucun panneau de plus, transaction
    /// fermée ; au démarrage suivant (base revenue), le tableau entier ; au démarrage d'après, rien de plus.
    /// MUTATIONS QUI LE FONT ROUGIR : écriture hors transaction, erreur avalée (mutant `AA3_hors_transaction`) ;
    /// panneau avalé dans le web (`AA3_panneau_avale`) et dans la conformité (`AA3_conformite_avale`) ; `Ok(0)` accepté
    /// pour un panneau du mail (`AA3_ok0_accepte`).
    #[test]
    fn stpn_un_panneau_refuse_annule_le_tableau_entier_et_le_semis_suivant_le_reprend() {
        assert_eq!(stpn_semis().len(), STPN_SEMIS_JUGES, "instrument : les onze semis sont jugés");
        for (tag, nom, semer, _vue, _replie, attendus) in stpn_semis() {
            for rang in 0..attendus.len() {
                for (forme, corps) in [("ABORT", "RAISE(ABORT,'stpn refus')"), ("IGNORE", "RAISE(IGNORE)")] {
                    let conn = test_db();
                    let avant = stpn_panneaux_en_tout(&conn);
                    conn.execute_batch(&format!(
                        "CREATE TRIGGER stpn_refus BEFORE INSERT ON panel WHEN NEW.position={rang} BEGIN SELECT {corps}; END;"
                    ))
                    .expect("déclencheur de refus");
                    semer(&conn);
                    assert_eq!(stpn_tableaux(&conn, nom), 0, "`{tag}` ({forme}, panneau {rang}) : aucun tableau conservé après le refus");
                    assert_eq!(stpn_panneaux_en_tout(&conn), avant, "`{tag}` ({forme}, panneau {rang}) : aucun panneau conservé");
                    assert!(conn.is_autocommit(), "`{tag}` ({forme}, panneau {rang}) : la transaction du semis est fermée");
                    conn.execute_batch("DROP TRIGGER stpn_refus;").expect("base revenue");
                    semer(&conn);
                    assert_eq!(stpn_tableaux(&conn, nom), 1, "`{tag}` ({forme}, panneau {rang}) : rejoué au démarrage suivant");
                    assert_eq!(stpn_panneaux(&conn, nom), attendus, "`{tag}` ({forme}, panneau {rang}) : rejoué ENTIER");
                    semer(&conn);
                    assert_eq!(stpn_tableaux(&conn, nom), 1, "`{tag}` ({forme}, panneau {rang}) : aucun doublon ensuite");
                }
            }
        }
    }

    /// L'EN-TÊTE REFUSÉ (ABORT, et IGNORE qui rend `Ok(0)` : l'identifiant lu ensuite serait celui d'une autre ligne) et
    /// LE RATTACHEMENT À LA VUE REFUSÉ (ABORT) : aucun tableau, aucun panneau ; rejoué entier ensuite.
    /// MUTATIONS QUI LE FONT ROUGIR : `Ok(0)` accepté pour l'en-tête (mutant `AA3_entete_ok0`) ; rattachement avalé
    /// (`AA3_rattachement_avale`).
    #[test]
    fn stpn_un_en_tete_ou_un_rattachement_refuse_n_ecrit_rien() {
        assert_eq!(stpn_semis().len(), STPN_SEMIS_JUGES, "instrument : les onze semis sont jugés");
        for (tag, nom, semer, _vue, _replie, attendus) in stpn_semis() {
            let nom_sql = nom.replace('\'', "''");
            for (etape, declencheur) in [
                ("en-tête ABORT", format!("BEFORE INSERT ON dashboard WHEN NEW.name='{nom_sql}' BEGIN SELECT RAISE(ABORT,'stpn refus'); END")),
                ("en-tête IGNORE", format!("BEFORE INSERT ON dashboard WHEN NEW.name='{nom_sql}' BEGIN SELECT RAISE(IGNORE); END")),
                ("rattachement ABORT", "BEFORE UPDATE ON dashboard BEGIN SELECT RAISE(ABORT,'stpn refus'); END".to_string()),
            ] {
                let conn = test_db();
                let avant = stpn_panneaux_en_tout(&conn);
                conn.execute_batch(&format!("CREATE TRIGGER stpn_refus {declencheur};")).expect("déclencheur de refus");
                semer(&conn);
                assert_eq!(stpn_tableaux(&conn, nom), 0, "`{tag}` ({etape}) : aucun tableau");
                assert_eq!(stpn_panneaux_en_tout(&conn), avant, "`{tag}` ({etape}) : aucun panneau, ni ici ni sous un autre tableau");
                assert!(conn.is_autocommit(), "`{tag}` ({etape}) : la transaction du semis est fermée");
                conn.execute_batch("DROP TRIGGER stpn_refus;").expect("base revenue");
                semer(&conn);
                assert_eq!(stpn_panneaux(&conn, nom), attendus, "`{tag}` ({etape}) : rejoué entier ensuite");
            }
        }
    }

    /// LE COMPTE ET LA PRÉSENCE NON LUE, sur une base sur disque (le compte des témoins est tenu par base) : un semis
    /// nominal ne compte rien ; un panneau refusé compte une fois sous « écriture ou COMMIT refusé » ; une présence non
    /// lue (lecture de `dashboard.name` refusée) compte sous « présence non lue » et n'écrit RIEN — ni sur une base sans
    /// le tableau (il est semé au démarrage suivant), ni sur une base qui l'a (aucun second tableau du même nom).
    /// MUTATIONS QUI LE FONT ROUGIR : refus d'écriture non compté (mutant `AA3_sans_compte_ecriture`) ; présence non lue
    /// tue sans compte (`AA3_lecture_ratee_muette`) ; présence non lue prise pour une absence, la forme d'avant
    /// (`AA3_lecture_ratee_absente`).
    #[test]
    fn stpn_un_refus_ou_une_presence_non_lue_est_compte_et_n_ecrit_rien() {
        let (_tmp, conn) = stpn_base_sur_disque("stpn-compte");
        let ecriture = || stpn_compte(&conn, GESTE_TABLEAU_SEME_PAR_NOM, ETAPE_ECRITURE_REFUSEE);
        let presence = || stpn_compte(&conn, GESTE_TABLEAU_SEME_PAR_NOM, ETAPE_PRESENCE_NON_LUE);

        seed_vault_dashboard(&conn);
        assert_eq!(stpn_tableaux(&conn, "Vault — accès secrets (Varonis)"), 1, "nominal : semé");
        assert_eq!((ecriture(), presence()), (0, 0), "nominal : rien n'est compté");

        conn.execute_batch("CREATE TRIGGER stpn_refus BEFORE INSERT ON panel WHEN NEW.position=3 BEGIN SELECT RAISE(ABORT,'stpn refus'); END;")
            .expect("déclencheur de refus");
        seed_web_dashboard(&conn);
        conn.execute_batch("DROP TRIGGER stpn_refus;").expect("base revenue");
        assert_eq!(stpn_tableaux(&conn, "Trafic web"), 0, "panneau refusé : aucun tableau");
        assert_eq!((ecriture(), presence()), (1, 0), "panneau refusé : compté une fois sous son étape");

        stpn_refuser_la_lecture_du_nom(&conn, "dashboard");
        seed_web_dashboard(&conn);
        stpn_rendre_la_lecture(&conn);
        assert_eq!(stpn_tableaux(&conn, "Trafic web"), 0, "présence non lue, tableau absent : rien n'est écrit");
        assert_eq!((ecriture(), presence()), (1, 1), "présence non lue : comptée sous son étape");
        assert!(conn.is_autocommit(), "présence non lue : aucune transaction ouverte");

        seed_web_dashboard(&conn);
        assert_eq!(stpn_tableaux(&conn, "Trafic web"), 1, "démarrage suivant : semé");
        assert_eq!(stpn_panneaux(&conn, "Trafic web").len(), 7, "démarrage suivant : entier");
        let total = stpn_panneaux_en_tout(&conn);

        stpn_refuser_la_lecture_du_nom(&conn, "dashboard");
        seed_web_dashboard(&conn);
        stpn_rendre_la_lecture(&conn);
        assert_eq!(stpn_tableaux(&conn, "Trafic web"), 1, "présence non lue, tableau présent : aucun second tableau du même nom");
        assert_eq!(stpn_panneaux_en_tout(&conn), total, "présence non lue, tableau présent : aucun panneau de plus");
        assert_eq!((ecriture(), presence()), (1, 2), "présence non lue : comptée encore");
    }

    /// LA RÈGLE CLAMAV : nominale (octet pour octet comme avant, une seule fois) ; refusée (ABORT, et IGNORE qui rend
    /// `Ok(0)`) -> aucune ligne, compté, resemée ensuite ; présence non lue sur une base qui l'a -> aucun doublon, compté.
    /// MUTATIONS QUI LE FONT ROUGIR : `Ok(0)` accepté (mutant `AA3_malware_ok0`) ; présence non lue prise pour une absence
    /// (`AA3_lecture_ratee_absente`).
    #[test]
    fn stpn_la_regle_clamav_est_entiere_ou_comptee() {
        let (_tmp, conn) = stpn_base_sur_disque("stpn-clamav");
        let ecriture = || stpn_compte(&conn, GESTE_REGLE_SEMEE_PAR_NOM, ETAPE_ECRITURE_REFUSEE);
        let presence = || stpn_compte(&conn, GESTE_REGLE_SEMEE_PAR_NOM, ETAPE_PRESENCE_NON_LUE);
        assert!(stpn_regles(&conn).is_empty(), "instrument : base neuve sans la règle");

        for (rang, (forme, corps)) in [("ABORT", "RAISE(ABORT,'stpn refus')"), ("IGNORE", "RAISE(IGNORE)")].into_iter().enumerate() {
            conn.execute_batch(&format!(
                "CREATE TRIGGER stpn_refus BEFORE INSERT ON rule WHEN NEW.name='{}' BEGIN SELECT {corps}; END;",
                STPN_REGLE_CLAMAV.replace('\'', "''")
            ))
            .expect("déclencheur de refus");
            seed_malware_rule(&conn);
            conn.execute_batch("DROP TRIGGER stpn_refus;").expect("base revenue");
            assert!(stpn_regles(&conn).is_empty(), "({forme}) : aucune règle conservée");
            assert_eq!(ecriture(), rang as u64 + 1, "({forme}) : refus compté");
            assert!(conn.is_autocommit(), "({forme}) : transaction fermée");
        }

        seed_malware_rule(&conn);
        assert_eq!(stpn_regles(&conn), vec![STPN_LIGNE_CLAMAV], "resemée, octet pour octet comme avant");
        seed_malware_rule(&conn);
        assert_eq!(stpn_regles(&conn), vec![STPN_LIGNE_CLAMAV], "second appel : aucun doublon");

        stpn_refuser_la_lecture_du_nom(&conn, "rule");
        seed_malware_rule(&conn);
        stpn_rendre_la_lecture(&conn);
        assert_eq!(stpn_regles(&conn), vec![STPN_LIGNE_CLAMAV], "présence non lue : aucun doublon");
        assert_eq!((ecriture(), presence()), (2, 1), "présence non lue : comptée sous son étape");
    }
}
