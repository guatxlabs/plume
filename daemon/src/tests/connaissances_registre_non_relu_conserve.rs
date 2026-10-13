// =====================================================================================
// `P10.20-b` (hors `handlers/` : `knowledge_reload`) — UNE LECTURE RATÉE DU REGISTRE DE SAVOIR NE RETIRE
// PAS UN OBJET QU'ELLE N'A PAS RELU.
//
// LE DÉFAUT, LU SUR b96a8c7b. `knowledge_reload` lisait ses six tables (`knowledge_alias`,
// `knowledge_calc`, `knowledge_eventtype`, `knowledge_tag`, `macro_def`, `auto_lookup`) sous
// `if let Ok(..) = prepare` / `if let Ok(..) = query_map` sans branche d'échec, puis `rows.flatten()`, et
// REMPLAÇAIT le jeu de `db_path` par ce qui avait été lu, sans compte ni journal : une table illisible
// retirait tous ses objets, une ligne indécodable (cellule blob dans une colonne TEXT) retirait le sien.
// Les recherches se compilaient alors autrement (alias et macros non résolus, types et tags inconnus,
// calculs et auto-lookups absents) sans que rien ne le dise.
//
// LES TÉMOINS. (1) à (6) blob dans une cellule TEXT de CHAQUE table, jeu en place : l'objet reste appliqué
// à la compilation d'une requête, le SQL compilé est le même octet pour octet, l'échec est compté et le
// compte MONTE au rechargement raté suivant ; (7) table renommée : le jeu entier est gardé, compté ;
// (8) contrôle négatif : une lecture RÉUSSIE de zéro ligne (lignes supprimées ou éteintes) pose le jeu
// vide, rien compté ; (9) jeu jamais chargé : il reçoit ce qui a été décodé ; (10) le jugement est PAR
// TABLE : une table en échec ne fige pas les autres (un alias supprimé sort, un alias posé entre, pendant
// que `macro_def` est illisible et que sa macro reste appliquée) ; (11) interruption du moteur à CHAQUE
// instruction d'un rechargement (`progress_handler`) : jamais de jeu partiel, un échec compté par
// interruption ; (12) « un par échec » : trois échecs dans UN rechargement (deux lignes indécodables dans
// `knowledge_alias`, une dans `knowledge_tag`) montent le compte de TROIS — ni un par rechargement, ni un
// par table ; (13) ordre des calculs : `ORDER BY ord, id` puis `construire` dans cet ordre (un calcul qui
// en reprend un autre posé AVANT lui en id mais APRÈS lui en ord), au chargement nominal et quand la table
// des calculs rate et garde sa part en place ; (14) deux bases : A chargée, B jamais chargée dont les six
// tables ratent — B ne reçoit aucun objet de A (la part gardée est celle de la base rechargée, lue sous sa
// clé `db_path`), et le rechargement de B ne touche pas A.
//
// MUTANTS JOUÉS (variable d'environnement `VERIF_MUT`, retirés du source avant le commit) : `FLATTEN`
// (ligne indécodable sautée sans échec, l'ancien `.flatten()`) -> (1)..(6) (9) ; `VIDE_SUR_ERR` (table en
// échec publiée vide malgré une part en place) -> (1)..(7) (10) (11) ; `DECODE_SUR_ECHEC` (table en échec
// publiée avec ce qu'elle a décodé) -> (1)..(7) (10) (11) ; `MUET` (compteur muet) -> (1)..(7) (9) (10)
// (11) ; `OUBLI_<table>` (un site oublié : SA table lue comme avant, lignes décodées publiées, rien
// compté — le corps d'avant, table par table, donc la preuve que chaque témoin (1)..(6) rougit sans le
// correctif) -> le témoin blob de SA table et (11), plus (7) (9) pour `knowledge_alias` et (10) pour
// `macro_def` ; `JEU_ENTIER` (le jeu en place gardé en entier dès qu'une table rate) -> (10) ;
// `VIDE_SANS_EN_PLACE` (rien publié pour un jeu jamais chargé) -> (9) ; `PREP_MUETTE` (préparation
// ratée sans échec) -> (7) (10) ; `PAS_MUET` (pas du moteur raté sans échec) -> (11). Correction après
// vérification indépendante : `COMPTE_PAR_RECHARGEMENT` (un seul compte si au moins un échec) -> (12) ;
// `COMPTE_PAR_TABLE` (un compte par table en échec) -> (12) ; `ORDRE_CALC` (`construire` parcourt les
// calculs à l'envers) -> (13) ; `ORDRE_SQL_ID` (calculs lus `ORDER BY id`) -> (13). Seconde correction :
// `EN_PLACE_D_UNE_AUTRE_BASE` (part en place lue, à défaut de celle de `db_path`, dans le registre d'une
// autre base) -> (14).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : le prix assumé n'a pas d'autre témoin que (10) — tant qu'une table
// rate, un objet supprimé ou éteint dans CETTE table reste appliqué et un objet posé dans cette table
// n'est pas encore appliqué (une route CRUD rend alors son succès sans que l'objet soit en vigueur) ; un
// jeu JAMAIS chargé dont une table est illisible part sans cette table ; les lignes de stderr (table et
// cause du moteur) ne sont pas témoignées, et il en part UNE par ligne indécodable à CHAQUE rechargement
// (une table de mille lignes blob = mille lignes de stderr par rechargement, aucune agrégation) ; le
// compteur n'est servi ni par `/metrics`, ni par une route, ni par la console, contrairement au précédent
// `processors` (`reload_read_failures` dans son JSON de stats) : `knowledge_lectures_ratees_de` est
// `cfg(test)`, l'aveu en production est stderr SEUL ; l'appel de la route CRUD (`handlers/knowledge.rs`,
// hors périmètre) n'est pas rejoué, seul `knowledge_reload` l'est — elle rend son succès même quand la
// table de l'objet posé rate et que l'objet n'est donc pas appliqué.
// =====================================================================================
mod connaissances_registre_non_relu_conserve {
    use super::*;
    use guatx_core::soql::KnowledgeSet;

    /// Un objet de savoir par table : sa pose, la colonne TEXT qu'un témoin rend indécodable, une requête
    /// qui ne se compile ainsi QUE si l'objet est appliqué, et le fragment qui le prouve.
    struct Objet {
        table: &'static str,
        poser: &'static str,
        colonne_texte: &'static str,
        requete: &'static str,
        fragment: &'static str,
    }

    static OBJETS: [Objet; 6] = [
        Objet {
            table: "knowledge_alias",
            poser: "INSERT INTO knowledge_alias(canonical,source) VALUES('client_ip','src_ip')",
            colonne_texte: "source",
            requete: "search client_ip=1.2.3.4",
            fragment: "\"src_ip\" = '1.2.3.4'",
        },
        Objet {
            table: "knowledge_calc",
            poser: "INSERT INTO knowledge_calc(name,expr) VALUES('sev_up','upper(severity)')",
            colonne_texte: "expr",
            requete: "search | table sev_up",
            fragment: "upper(severity)",
        },
        Objet {
            table: "knowledge_eventtype",
            poser: "INSERT INTO knowledge_eventtype(name,filter) VALUES('web_attack','source=webx severity=HIGH')",
            colonne_texte: "filter",
            requete: "search eventtype=web_attack",
            fragment: "\"source\" = 'webx'",
        },
        Objet {
            table: "knowledge_tag",
            poser: "INSERT INTO knowledge_tag(label,field,value) VALUES('pci','category','payment')",
            colonne_texte: "value",
            requete: "search tag=pci",
            fragment: "\"category\" = 'payment'",
        },
        Objet {
            table: "macro_def",
            poser: "INSERT INTO macro_def(name,params,body) VALUES('m_web','','source=webm')",
            colonne_texte: "body",
            requete: "search `m_web`",
            fragment: "\"source\" = 'webm'",
        },
        Objet {
            table: "auto_lookup",
            poser: "INSERT INTO auto_lookup(name,key_field,out_cols) VALUES('geo','src_ip','country')",
            colonne_texte: "out_cols",
            requete: "search",
            fragment: "lk.name='geo'",
        },
    ];

    fn objet(table: &str) -> &'static Objet {
        OBJETS.iter().find(|o| o.table == table).unwrap()
    }

    fn compiler(ks: KnowledgeSet, q: &str) -> Result<String, String> {
        guatx_core::soql::to_sql(q, 0, 0, &guatx_core::soql::Schema::events().with_knowledge(ks))
    }

    /// L'objet est-il APPLIQUÉ par le jeu publié pour `dbp` ? (requête compilée et fragment présent)
    fn applique(dbp: &str, o: &Objet) -> bool {
        compiler(effective_knowledge(dbp), o.requete).map(|sql| sql.contains(o.fragment)).unwrap_or(false)
    }

    /// Le SQL compilé des six requêtes sous le jeu publié (Err rendue en texte) : une empreinte du jeu.
    fn empreinte(dbp: &str) -> Vec<String> {
        OBJETS
            .iter()
            .map(|o| match compiler(effective_knowledge(dbp), o.requete) {
                Ok(s) => s,
                Err(e) => format!("ERR {e}"),
            })
            .collect()
    }

    fn controle_discriminant(o: &Objet) {
        assert!(
            !compiler(KnowledgeSet::new(), o.requete).map(|sql| sql.contains(o.fragment)).unwrap_or(false),
            "contrôle : sans l'objet de `{}`, la requête `{}` ne porte pas `{}`",
            o.table,
            o.requete,
            o.fragment
        );
    }

    fn blob_dans_une_cellule_texte(table: &str) {
        let o = objet(table);
        controle_discriminant(o);
        let conn = test_db();
        let dbp = format!("n8-blob-{table}");
        conn.execute(o.poser, []).unwrap();
        knowledge_reload(&conn, &dbp);
        assert!(applique(&dbp, o), "contrôle : l'objet de `{table}` est appliqué au chargement nominal");
        assert_eq!(knowledge_lectures_ratees_de(&dbp), 0, "contrôle : aucun échec au chargement nominal");
        let avant = empreinte(&dbp);
        conn.execute(&format!("UPDATE {table} SET {}=x'ff'", o.colonne_texte), []).unwrap();
        let t: String = conn
            .query_row(&format!("SELECT typeof({}) FROM {table}", o.colonne_texte), [], |r| r.get(0))
            .unwrap();
        assert_eq!(t, "blob", "contrôle : la cellule de `{table}` est bien devenue un blob");
        knowledge_reload(&conn, &dbp);
        assert!(applique(&dbp, o), "`{table}` : l'objet non relu reste appliqué à la compilation");
        assert_eq!(empreinte(&dbp), avant, "`{table}` : le jeu publié compile à l'identique (rien perdu, rien doublé)");
        assert_eq!(knowledge_lectures_ratees_de(&dbp), 1, "`{table}` : la ligne non lue est comptée");
        knowledge_reload(&conn, &dbp);
        assert!(applique(&dbp, o), "`{table}` : rechargement raté après rechargement raté, l'objet tient");
        assert_eq!(empreinte(&dbp), avant, "`{table}` : rechargement raté après rechargement raté, aucun doublon");
        assert_eq!(knowledge_lectures_ratees_de(&dbp), 2, "`{table}` : le compte MONTE à chaque lecture ratée");
    }

    #[test]
    fn n8_blob_dans_knowledge_alias_l_alias_reste_applique() {
        blob_dans_une_cellule_texte("knowledge_alias");
    }

    #[test]
    fn n8_blob_dans_knowledge_calc_le_calcul_reste_applique() {
        blob_dans_une_cellule_texte("knowledge_calc");
    }

    #[test]
    fn n8_blob_dans_knowledge_eventtype_le_type_reste_applique() {
        blob_dans_une_cellule_texte("knowledge_eventtype");
    }

    #[test]
    fn n8_blob_dans_knowledge_tag_le_tag_reste_applique() {
        blob_dans_une_cellule_texte("knowledge_tag");
    }

    #[test]
    fn n8_blob_dans_macro_def_la_macro_reste_appliquee() {
        blob_dans_une_cellule_texte("macro_def");
    }

    #[test]
    fn n8_blob_dans_auto_lookup_l_auto_lookup_reste_applique() {
        blob_dans_une_cellule_texte("auto_lookup");
    }

    fn poser_les_six(conn: &Connection) {
        for o in &OBJETS {
            conn.execute(o.poser, []).unwrap();
        }
    }

    #[test]
    fn n8_table_renommee_le_jeu_en_place_est_garde() {
        let conn = test_db();
        let dbp = "n8-table-renommee";
        poser_les_six(&conn);
        knowledge_reload(&conn, dbp);
        for o in &OBJETS {
            assert!(applique(dbp, o), "contrôle : `{}` appliqué", o.table);
        }
        let avant = empreinte(dbp);
        conn.execute_batch("ALTER TABLE knowledge_alias RENAME TO knowledge_alias_ailleurs").unwrap();
        knowledge_reload(&conn, dbp);
        assert_eq!(knowledge_lectures_ratees_de(dbp), 1, "la préparation ratée est comptée");
        for o in &OBJETS {
            assert!(applique(dbp, o), "table renommée : `{}` reste appliqué", o.table);
        }
        assert_eq!(empreinte(dbp), avant, "table renommée : le jeu compile à l'identique");
    }

    #[test]
    fn n8_zero_ligne_lue_avec_succes_pose_le_jeu_vide() {
        let conn = test_db();
        let dbp = "n8-zero-ligne";
        poser_les_six(&conn);
        knowledge_reload(&conn, dbp);
        assert!(!effective_knowledge(dbp).is_empty(), "contrôle : jeu chargé");
        // Trois tables vidées, trois éteintes : toutes les lectures RÉUSSISSENT et rendent zéro ligne.
        for t in ["knowledge_alias", "knowledge_calc", "knowledge_eventtype"] {
            conn.execute(&format!("DELETE FROM {t}"), []).unwrap();
        }
        for t in ["knowledge_tag", "macro_def", "auto_lookup"] {
            conn.execute(&format!("UPDATE {t} SET enabled=0"), []).unwrap();
        }
        knowledge_reload(&conn, dbp);
        assert!(effective_knowledge(dbp).is_empty(), "une lecture réussie de zéro ligne pose le jeu vide (mode 0)");
        for o in &OBJETS {
            assert!(!applique(dbp, o), "`{}` n'est plus appliqué", o.table);
        }
        assert_eq!(knowledge_lectures_ratees_de(dbp), 0, "aucun échec compté");
    }

    #[test]
    fn n8_jeu_jamais_charge_recoit_ce_qui_a_ete_decode() {
        let conn = test_db();
        let dbp = "n8-jamais-charge";
        poser_les_six(&conn);
        conn.execute("INSERT INTO knowledge_alias(canonical,source) VALUES('peer_ip',x'ff')", []).unwrap();
        knowledge_reload(&conn, dbp);
        assert_eq!(knowledge_lectures_ratees_de(dbp), 1, "la ligne indécodable est comptée");
        for o in &OBJETS {
            assert!(applique(dbp, o), "jamais chargé : `{}` décodé est publié", o.table);
        }
    }

    #[test]
    fn n8_une_table_en_echec_ne_fige_pas_les_autres() {
        let conn = test_db();
        let dbp = "n8-par-table";
        poser_les_six(&conn);
        knowledge_reload(&conn, dbp);
        let alias = objet("knowledge_alias");
        let macro_web = objet("macro_def");
        assert!(applique(dbp, alias) && applique(dbp, macro_web), "contrôle : alias et macro appliqués");
        conn.execute_batch("ALTER TABLE macro_def RENAME TO macro_def_ailleurs").unwrap();
        conn.execute("DELETE FROM knowledge_alias WHERE canonical='client_ip'", []).unwrap();
        conn.execute("INSERT INTO knowledge_alias(canonical,source) VALUES('peer_ip','dst_ip')", []).unwrap();
        knowledge_reload(&conn, dbp);
        assert_eq!(knowledge_lectures_ratees_de(dbp), 1, "contrôle : la préparation ratée de macro_def est comptée");
        assert!(applique(dbp, macro_web), "la macro de la table en échec reste appliquée");
        assert!(!applique(dbp, alias), "l'alias SUPPRIMÉ dans une table lue n'est plus appliqué");
        let peer = compiler(effective_knowledge(dbp), "search peer_ip=5.6.7.8").unwrap();
        assert!(peer.contains("\"dst_ip\" = '5.6.7.8'"), "l'alias POSÉ dans une table lue est appliqué : {peer}");
    }

    /// Interruption du moteur à CHAQUE instruction d'un rechargement (`progress_handler`) : la base porte
    /// les six objets, le jeu en place aussi ; quelle que soit l'instruction interrompue (préparation ou
    /// pas du moteur, dans n'importe laquelle des six tables), le jeu publié compile à l'identique et
    /// l'interruption est comptée une fois.
    #[test]
    fn n8_interruption_du_moteur_a_chaque_instruction_aucun_jeu_partiel() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let conn = test_db();
        let dbp = "n8-interruption";
        poser_les_six(&conn);
        knowledge_reload(&conn, dbp);
        let complet = empreinte(dbp);
        for o in &OBJETS {
            assert!(applique(dbp, o), "contrôle : `{}` appliqué", o.table);
        }
        let compte = Arc::new(AtomicU64::new(0));
        let k = compte.clone();
        conn.progress_handler(1, Some(move || { k.fetch_add(1, Ordering::Relaxed); false }));
        knowledge_reload(&conn, dbp);
        conn.progress_handler(1, None::<fn() -> bool>);
        let total = compte.load(Ordering::Relaxed);
        assert!(total > 12, "contrôle : un rechargement exécute plusieurs instructions par table ({total})");
        assert_eq!(knowledge_lectures_ratees_de(dbp), 0, "contrôle : rechargement nominal sans échec");
        for cible in 1..=total {
            let avant = knowledge_lectures_ratees_de(dbp);
            let n = AtomicU64::new(0);
            conn.progress_handler(1, Some(move || n.fetch_add(1, Ordering::Relaxed) + 1 == cible));
            knowledge_reload(&conn, dbp);
            conn.progress_handler(1, None::<fn() -> bool>);
            assert_eq!(empreinte(dbp), complet, "interruption à l'instruction {cible}/{total} : aucun jeu partiel");
            assert_eq!(
                knowledge_lectures_ratees_de(dbp),
                avant + 1,
                "interruption à l'instruction {cible}/{total} : comptée une fois"
            );
        }
    }
    /// (12) « Un par échec » : trois échecs dans UN rechargement -> le compte monte de trois.
    #[test]
    fn n8_trois_echecs_dans_un_rechargement_comptent_trois() {
        let conn = test_db();
        let dbp = "n8-trois-echecs";
        poser_les_six(&conn);
        conn.execute("INSERT INTO knowledge_alias(canonical,source) VALUES('peer_ip','dst_ip')", []).unwrap();
        knowledge_reload(&conn, dbp);
        assert_eq!(knowledge_lectures_ratees_de(dbp), 0, "contrôle : chargement nominal sans échec");
        let avant = empreinte(dbp);
        conn.execute("UPDATE knowledge_alias SET source=x'ff'", []).unwrap();
        conn.execute("UPDATE knowledge_tag SET value=x'ff'", []).unwrap();
        let blobs: i64 = conn
            .query_row(
                "SELECT (SELECT count(*) FROM knowledge_alias WHERE typeof(source)='blob')
                      + (SELECT count(*) FROM knowledge_tag WHERE typeof(value)='blob')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(blobs, 3, "contrôle : deux lignes indécodables dans knowledge_alias, une dans knowledge_tag");
        knowledge_reload(&conn, dbp);
        assert_eq!(
            knowledge_lectures_ratees_de(dbp),
            3,
            "trois lignes non lues dans un rechargement = trois échecs comptés (ni un par rechargement, ni un par table)"
        );
        assert_eq!(empreinte(dbp), avant, "les deux tables en échec gardent leur part en place");
        knowledge_reload(&conn, dbp);
        assert_eq!(knowledge_lectures_ratees_de(dbp), 6, "le rechargement raté suivant en ajoute trois");
    }

    /// (13) Ordre des calculs : `b_low` reprend `a_up` ; il est posé AVANT lui (id plus petit) mais APRÈS
    /// lui en `ord`. Le jeu publié les applique dans l'ordre (ord, id), au chargement nominal comme quand
    /// la table des calculs rate et garde sa part en place.
    #[test]
    fn n8_ordre_des_calculs_ord_puis_id_conserve() {
        let conn = test_db();
        let dbp = "n8-ordre-calc";
        conn.execute("INSERT INTO knowledge_calc(name,expr,ord) VALUES('b_low','lower(a_up)',1)", []).unwrap();
        conn.execute("INSERT INTO knowledge_calc(name,expr,ord) VALUES('a_up','upper(severity)',0)", []).unwrap();
        let mut dans_l_ordre = KnowledgeSet::new();
        dans_l_ordre.add_calc("a_up", "upper(severity)");
        dans_l_ordre.add_calc("b_low", "lower(a_up)");
        let mut a_l_envers = KnowledgeSet::new();
        a_l_envers.add_calc("b_low", "lower(a_up)");
        a_l_envers.add_calc("a_up", "upper(severity)");
        let q = "search | table b_low";
        let attendu = compiler(dans_l_ordre, q);
        assert_ne!(attendu, compiler(a_l_envers, q), "contrôle : l'ordre des calculs change le SQL compilé");
        knowledge_reload(&conn, dbp);
        assert_eq!(compiler(effective_knowledge(dbp), q), attendu, "chargement nominal : calculs dans l'ordre (ord, id)");
        conn.execute("UPDATE knowledge_calc SET expr=x'ff' WHERE name='a_up'", []).unwrap();
        knowledge_reload(&conn, dbp);
        assert_eq!(knowledge_lectures_ratees_de(dbp), 1, "contrôle : la ligne indécodable est comptée");
        assert_eq!(compiler(effective_knowledge(dbp), q), attendu, "table en échec : la part gardée garde son ordre");
    }

    #[test]
    fn n8_part_gardee_vient_de_la_base_rechargee_pas_d_une_autre() {
        // Base A chargée avec ses six objets ; base B JAMAIS chargée, dont les six tables ratent (chaque ligne
        // porte un blob dans sa colonne TEXT). B n'a aucune part en place : elle ne doit recevoir AUCUN objet
        // de A (multi-tenant : les alias, macros et tags d'un tenant ne passent pas à un autre).
        let a = test_db();
        let b = test_db();
        let (dba, dbb) = ("n8-deux-bases-a", "n8-deux-bases-b");
        poser_les_six(&a);
        knowledge_reload(&a, dba);
        for o in &OBJETS {
            assert!(applique(dba, o), "contrôle : A applique `{}`", o.table);
        }
        poser_les_six(&b);
        for o in &OBJETS {
            b.execute(&format!("UPDATE {} SET {}=x'ff'", o.table, o.colonne_texte), []).unwrap();
        }
        knowledge_reload(&b, dbb);
        assert_eq!(knowledge_lectures_ratees_de(dbb), 6, "contrôle : les six tables de B ratent, six échecs comptés à B");
        assert_eq!(knowledge_lectures_ratees_de(dba), 0, "rien compté à A");
        assert_eq!(empreinte(dbb), empreinte("n8-deux-bases-jamais-vue"), "B n'applique aucun objet : son jeu est le jeu vide");
        for o in &OBJETS {
            assert!(!applique(dbb, o), "B jamais chargée, `{}` en échec : elle ne reçoit pas l'objet de A", o.table);
            assert!(applique(dba, o), "le rechargement de B ne touche pas A : `{}` reste appliqué à A", o.table);
        }
    }
}
