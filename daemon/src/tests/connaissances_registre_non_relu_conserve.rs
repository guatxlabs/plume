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
// clé `db_path`), et le rechargement de B ne touche pas A ; (15) le prix assumé, sur CHACUNE des six
// tables : jeu en place, puis dans la table un objet neuf et valide posé, l'objet en place supprimé et
// recréé avec une autre valeur, une ligne indécodable — le jeu publié est la part en place entière et
// seule (l'objet neuf pas encore appliqué, la valeur recréée ne se mêle pas : deux paires d'un même tag,
// deux calculs de même nom), puis la ligne retirée, l'un et l'autre entrent ; (16) la ligne de stderr,
// rendue par `recharger_le_savoir` : elle nomme la table en échec et aucune autre, la base, la cause du
// moteur (type, colonne), jamais la valeur de la cellule ; (17) `GET /api/knowledge` sert le compte de SA
// base sous `CLE_LECTURES_DE_SAVOIR_RATEES`, absente à zéro (le corps nominal porte les six familles et
// rien d'autre, même quand une autre base a raté), un de plus par échec, cumulé ; (18) la forme pure de
// l'aveu.
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
// autre base) -> (14). Lot O6 (vague O) : `UNION_NOUVEAUX` (table en échec publiée avec sa part en place
// PLUS ses lignes décodées) -> (15) sur les six tables ; `NOM_DE_TABLE_FAUX` (étiquette de la ligne
// de stderr fausse) -> (16) ; `CAUSE_TUE` (cause du moteur omise de la ligne) -> (16) ; `CLE_A_ZERO` (clé
// servie même à zéro) -> (17) (18) ; `AUTRE_DB_PATH` (compte lu sur toutes les bases, pas sur celle de la
// requête) -> (17) et les témoins qui relisent le compte ; `ACCESSEUR_CFG_TEST` (l'accesseur laissé
// `#[cfg(test)]`) -> le binaire ne compile plus (`cargo check` hors test : la route le lit).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : le prix assumé reste un prix — tant qu'une table rate, un objet
// supprimé ou éteint dans CETTE table reste appliqué et un objet posé dans cette table n'est pas encore
// appliqué (une route CRUD rend alors son succès sans que l'objet soit en vigueur ; l'appel de la route
// n'est pas rejoué, seul `knowledge_reload` l'est) ; un jeu JAMAIS chargé dont une table est illisible
// part sans cette table ; il part UNE ligne de stderr par ligne indécodable à CHAQUE rechargement (une
// table de mille lignes blob = mille lignes par rechargement, aucune agrégation) ; le compte servi est
// CUMULÉ depuis le démarrage (il ne dit pas si la table rate ENCORE, ni laquelle : stderr le dit), il
// n'est servi ni par `/metrics` ni peint par la console (`web/knowledge.js` ne lit pas la clé).
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

    // ---------------------------------------------------------------------------------------------
    // (15) à (18) — le prix assumé, la ligne de stderr et le compte servi (restes dits par la
    // vérification de N8 : mutants `UNION_NOUVEAUX` et `NOM_DE_TABLE_FAUX` restés verts).
    // ---------------------------------------------------------------------------------------------

    /// Pour une table : un objet NEUF et valide posé après le chargement, la RECRÉATION de l'objet en
    /// place (même nom, autre valeur, après suppression) et une ligne indécodable qui fait rater la table.
    struct Melange {
        table: &'static str,
        neuf: &'static str,
        requete_neuf: &'static str,
        fragment_neuf: &'static str,
        supprimer: &'static str,
        recreer: &'static str,
        requete_recree: &'static str,
        fragment_recree: &'static str,
        /// Le fragment que la valeur EN PLACE (avant suppression) donne à `requete_recree`.
        fragment_en_place: &'static str,
        ligne_indecodable: &'static str,
    }

    static MELANGES: [Melange; 6] = [
        Melange {
            table: "knowledge_alias",
            neuf: "INSERT INTO knowledge_alias(canonical,source) VALUES('peer_ip','dst_ip')",
            requete_neuf: "search peer_ip=5.6.7.8",
            fragment_neuf: "\"dst_ip\" = '5.6.7.8'",
            supprimer: "DELETE FROM knowledge_alias WHERE canonical='client_ip'",
            recreer: "INSERT INTO knowledge_alias(canonical,source) VALUES('client_ip','dst_ip')",
            requete_recree: "search client_ip=1.2.3.4",
            fragment_recree: "\"dst_ip\" = '1.2.3.4'",
            fragment_en_place: "\"src_ip\" = '1.2.3.4'",
            ligne_indecodable: "INSERT INTO knowledge_alias(canonical,source) VALUES('bad_ip',x'ff')",
        },
        Melange {
            table: "knowledge_calc",
            neuf: "INSERT INTO knowledge_calc(name,expr) VALUES('sev_trim','trim(severity)')",
            requete_neuf: "search | table sev_trim",
            fragment_neuf: "trim(severity)",
            supprimer: "DELETE FROM knowledge_calc WHERE name='sev_up'",
            recreer: "INSERT INTO knowledge_calc(name,expr) VALUES('sev_up','lower(severity)')",
            requete_recree: "search | table sev_up",
            fragment_recree: "lower(severity)",
            fragment_en_place: "upper(severity)",
            ligne_indecodable: "INSERT INTO knowledge_calc(name,expr) VALUES('bad_calc',x'ff')",
        },
        Melange {
            table: "knowledge_eventtype",
            neuf: "INSERT INTO knowledge_eventtype(name,filter) VALUES('dns_x','source=dnsx')",
            requete_neuf: "search eventtype=dns_x",
            fragment_neuf: "\"source\" = 'dnsx'",
            supprimer: "DELETE FROM knowledge_eventtype WHERE name='web_attack'",
            recreer: "INSERT INTO knowledge_eventtype(name,filter) VALUES('web_attack','source=webz')",
            requete_recree: "search eventtype=web_attack",
            fragment_recree: "\"source\" = 'webz'",
            fragment_en_place: "\"source\" = 'webx'",
            ligne_indecodable: "INSERT INTO knowledge_eventtype(name,filter) VALUES('bad_et',x'ff')",
        },
        Melange {
            table: "knowledge_tag",
            neuf: "INSERT INTO knowledge_tag(label,field,value) VALUES('sox','category','audit')",
            requete_neuf: "search tag=sox",
            fragment_neuf: "\"category\" = 'audit'",
            supprimer: "DELETE FROM knowledge_tag WHERE label='pci'",
            recreer: "INSERT INTO knowledge_tag(label,field,value) VALUES('pci','category','card')",
            requete_recree: "search tag=pci",
            fragment_recree: "\"category\" = 'card'",
            fragment_en_place: "\"category\" = 'payment'",
            ligne_indecodable: "INSERT INTO knowledge_tag(label,field,value) VALUES('bad_tag','category',x'ff')",
        },
        Melange {
            table: "macro_def",
            neuf: "INSERT INTO macro_def(name,params,body) VALUES('m_dns','','source=dnsm')",
            requete_neuf: "search `m_dns`",
            fragment_neuf: "\"source\" = 'dnsm'",
            supprimer: "DELETE FROM macro_def WHERE name='m_web'",
            recreer: "INSERT INTO macro_def(name,params,body) VALUES('m_web','','source=webn')",
            requete_recree: "search `m_web`",
            fragment_recree: "\"source\" = 'webn'",
            fragment_en_place: "\"source\" = 'webm'",
            ligne_indecodable: "INSERT INTO macro_def(name,params,body) VALUES('m_bad','',x'ff')",
        },
        Melange {
            table: "auto_lookup",
            neuf: "INSERT INTO auto_lookup(name,key_field,out_cols) VALUES('asn','src_ip','asn_org')",
            requete_neuf: "search",
            fragment_neuf: "lk.name='asn'",
            supprimer: "DELETE FROM auto_lookup WHERE name='geo'",
            recreer: "INSERT INTO auto_lookup(name,key_field,out_cols) VALUES('geo','src_ip','city')",
            requete_recree: "search",
            fragment_recree: "city",
            fragment_en_place: "country",
            ligne_indecodable: "INSERT INTO auto_lookup(name,key_field,out_cols) VALUES('bad_lk','src_ip',x'ff')",
        },
    ];

    fn applique_requete(dbp: &str, requete: &str, fragment: &str) -> bool {
        compiler(effective_knowledge(dbp), requete).map(|sql| sql.contains(fragment)).unwrap_or(false)
    }

    /// (15) LE PRIX ASSUMÉ, TÉMOIGNÉ TABLE PAR TABLE. Jeu en place (les six objets) ; dans UNE table, un
    /// objet neuf et valide est posé, l'objet en place est supprimé puis recréé avec une autre valeur, et
    /// une ligne indécodable fait rater la table. Le jeu publié est la part EN PLACE, entière et seule :
    /// le SQL des six requêtes est le même octet pour octet, l'objet neuf n'est pas encore appliqué, la
    /// valeur recréée ne se mêle pas à l'ancienne (deux paires d'un même tag, deux calculs de même nom).
    /// Contrôle positif : la ligne indécodable retirée, l'objet neuf et la valeur recréée entrent, l'ancienne
    /// valeur sort — ils étaient valides, seule la table en échec les retenait.
    fn part_en_place_seule(table: &str) {
        let m = MELANGES.iter().find(|m| m.table == table).unwrap();
        let o = objet(table);
        let conn = test_db();
        let dbp = format!("o6-melange-{table}");
        poser_les_six(&conn);
        knowledge_reload(&conn, &dbp);
        assert!(applique(&dbp, o), "contrôle : l'objet de `{table}` est appliqué");
        assert!(applique_requete(&dbp, m.requete_recree, m.fragment_en_place), "contrôle : la valeur en place de `{table}` est appliquée");
        assert!(!applique_requete(&dbp, m.requete_neuf, m.fragment_neuf), "contrôle : l'objet neuf de `{table}` n'est pas encore là");
        assert!(!applique_requete(&dbp, m.requete_recree, m.fragment_recree), "contrôle : la valeur recréée de `{table}` n'est pas encore là");
        let avant = empreinte(&dbp);
        conn.execute(m.neuf, []).unwrap();
        conn.execute(m.supprimer, []).unwrap();
        conn.execute(m.recreer, []).unwrap();
        conn.execute(m.ligne_indecodable, []).unwrap();
        let lignes = recharger_le_savoir(&conn, &dbp);
        assert_eq!(lignes.len(), 1, "`{table}` : un échec, une ligne de stderr : {lignes:?}");
        assert_eq!(knowledge_lectures_ratees_de(&dbp), 1, "`{table}` : l'échec est compté");
        assert_eq!(empreinte(&dbp), avant, "`{table}` en échec : le jeu publié est la part en place, entière et seule");
        assert!(
            applique_requete(&dbp, m.requete_recree, m.fragment_en_place),
            "`{table}` en échec : la valeur en place (supprimée depuis) reste appliquée — prix assumé"
        );
        assert!(
            !applique_requete(&dbp, m.requete_neuf, m.fragment_neuf),
            "`{table}` en échec : l'objet neuf et valide n'est PAS encore appliqué — ni union, ni mélange"
        );
        assert!(
            !applique_requete(&dbp, m.requete_recree, m.fragment_recree),
            "`{table}` en échec : la valeur recréée ne se mêle pas à la valeur en place"
        );
        conn.execute(&format!("DELETE FROM {table} WHERE typeof({})='blob'", o.colonne_texte), []).unwrap();
        assert!(recharger_le_savoir(&conn, &dbp).is_empty(), "contrôle : la table relue sans échec");
        assert_eq!(knowledge_lectures_ratees_de(&dbp), 1, "contrôle : rien de plus compté");
        assert!(applique_requete(&dbp, m.requete_neuf, m.fragment_neuf), "contrôle positif `{table}` : l'objet neuf était valide");
        assert!(applique_requete(&dbp, m.requete_recree, m.fragment_recree), "contrôle positif `{table}` : la valeur recréée était valide");
        assert!(
            !applique_requete(&dbp, m.requete_recree, m.fragment_en_place),
            "contrôle positif `{table}` : l'ancienne valeur sort une fois la table relue"
        );
    }

    #[test]
    fn o6_knowledge_alias_en_echec_part_en_place_seule() {
        part_en_place_seule("knowledge_alias");
    }

    #[test]
    fn o6_knowledge_calc_en_echec_part_en_place_seule() {
        part_en_place_seule("knowledge_calc");
    }

    #[test]
    fn o6_knowledge_eventtype_en_echec_part_en_place_seule() {
        part_en_place_seule("knowledge_eventtype");
    }

    #[test]
    fn o6_knowledge_tag_en_echec_part_en_place_seule() {
        part_en_place_seule("knowledge_tag");
    }

    #[test]
    fn o6_macro_def_en_echec_part_en_place_seule() {
        part_en_place_seule("macro_def");
    }

    #[test]
    fn o6_auto_lookup_en_echec_part_en_place_seule() {
        part_en_place_seule("auto_lookup");
    }

    /// (16) LA LIGNE DE STDERR, sans capturer stderr : `recharger_le_savoir` rend les lignes que
    /// `knowledge_reload` écrit. Pour chaque table rendue illisible par une cellule blob dont les octets
    /// portent un marqueur, la ligne nomme CETTE table et aucune autre, porte la base et la cause du moteur
    /// (type et colonne), dit que la part en place est gardée, et ne porte pas la valeur de la cellule.
    #[test]
    fn o6_la_ligne_de_stderr_nomme_la_table_et_la_cause_sans_valeur_de_cellule() {
        for o in &OBJETS {
            let conn = test_db();
            let dbp = format!("o6-ligne-{}", o.table);
            poser_les_six(&conn);
            assert!(recharger_le_savoir(&conn, &dbp).is_empty(), "contrôle : chargement nominal sans ligne");
            conn.execute(&format!("UPDATE {} SET {}=CAST('valeur_secrete_o6' AS BLOB)", o.table, o.colonne_texte), []).unwrap();
            let lignes = recharger_le_savoir(&conn, &dbp);
            assert_eq!(lignes.len(), 1, "`{}` : une ligne par échec : {lignes:?}", o.table);
            let l = &lignes[0];
            assert!(l.contains(&format!("`{}`", o.table)), "la ligne nomme `{}` : {l}", o.table);
            for autre in OBJETS.iter().filter(|a| a.table != o.table) {
                assert!(!l.contains(&format!("`{}`", autre.table)), "la ligne de `{}` ne nomme pas `{}` : {l}", o.table, autre.table);
            }
            assert!(l.contains(&dbp), "la ligne nomme la base : {l}");
            assert!(l.contains("Blob") && l.contains(o.colonne_texte), "la ligne porte la cause du moteur (type, colonne) : {l}");
            assert!(l.contains("GARDÉE"), "jeu en place : la ligne dit que la part en place est gardée : {l}");
            assert!(!l.contains("valeur_secrete_o6"), "aucune valeur de cellule dans la ligne : {l}");
        }
        let jamais = ligne_de_lecture_de_savoir_ratee("knowledge_tag", "o6-base", "cause du moteur", false);
        assert!(
            jamais.contains("`knowledge_tag`") && jamais.contains("o6-base") && jamais.contains("cause du moteur")
                && jamais.contains("aucun registre en place"),
            "fonction pure, registre jamais chargé : {jamais}"
        );
    }

    /// (17) LE COMPTE EST SERVI PAR `GET /api/knowledge`, ABSENT À ZÉRO, LU SUR LA BASE DE LA REQUÊTE. Une
    /// autre base a déjà raté (son compte n'est pas le nôtre) ; chargement nominal : le corps porte les six
    /// familles et rien d'autre. Puis chaque échec monte le compte servi d'un (un rechargement à une
    /// ligne indécodable, puis un second, puis un à deux lignes indécodables dans deux tables) ; le
    /// compte est cumulé : un rechargement réussi ne le remet pas à zéro.
    #[tokio::test]
    async fn o6_le_compte_des_lectures_ratees_est_servi_par_la_liste_absent_a_zero() {
        let autre = test_db();
        let dba = "o6-compte-autre-base";
        autre.execute("INSERT INTO knowledge_alias(canonical,source) VALUES('x_ip',x'ff')", []).unwrap();
        knowledge_reload(&autre, dba);
        assert_eq!(knowledge_lectures_ratees_de(dba), 1, "contrôle : une autre base a un échec compté");

        let (st, _p) = sp_state("o6-compte");
        let au = sp_au("adm", "admin");
        let dbp = st.db_path.as_ref().clone();
        let lire = |st: &AppState| {
            let st = st.clone();
            let au = au.clone();
            async move { lsa_corps(knowledge_list(State(st), Extension(au)).await).await }
        };
        {
            let conn = st.db.lock();
            poser_les_six(&conn);
            knowledge_reload(&conn, &dbp);
        }
        assert_eq!(knowledge_lectures_ratees_de(&dbp), 0, "contrôle : chargement nominal sans échec");
        let (statut, nominal) = lire(&st).await;
        assert_eq!(statut, 200);
        let mut cles: Vec<&str> = nominal.as_object().unwrap().keys().map(String::as_str).collect();
        cles.sort();
        assert_eq!(
            cles,
            ["aliases", "auto_lookups", "calcs", "eventtypes", "macros", "tags"],
            "chemin nominal : les six familles et rien d'autre (clé absente à zéro, l'échec d'une autre base n'est pas le nôtre) : {nominal}"
        );
        assert!(nominal.get(CLE_LECTURES_DE_SAVOIR_RATEES).is_none());

        let recharger = |sql: &str| {
            let conn = st.db.lock();
            if !sql.is_empty() {
                conn.execute_batch(sql).unwrap();
            }
            knowledge_reload(&conn, &dbp);
        };
        recharger("UPDATE knowledge_alias SET source=x'ff'");
        let (_, un) = lire(&st).await;
        assert_eq!(un[CLE_LECTURES_DE_SAVOIR_RATEES], json!(1), "un échec : compte servi 1 : {un}");
        recharger("");
        let (_, deux) = lire(&st).await;
        assert_eq!(deux[CLE_LECTURES_DE_SAVOIR_RATEES], json!(2), "second rechargement raté : 2 : {deux}");
        recharger("UPDATE knowledge_tag SET value=x'ff'");
        let (_, quatre) = lire(&st).await;
        assert_eq!(quatre[CLE_LECTURES_DE_SAVOIR_RATEES], json!(4), "deux échecs dans un rechargement : +2 : {quatre}");
        recharger("DELETE FROM knowledge_alias WHERE typeof(source)='blob'; DELETE FROM knowledge_tag WHERE typeof(value)='blob';");
        let (_, cumul) = lire(&st).await;
        assert_eq!(cumul[CLE_LECTURES_DE_SAVOIR_RATEES], json!(4), "compte cumulé depuis le démarrage : {cumul}");
        assert_eq!(knowledge_lectures_ratees_de(dba), 1, "l'autre base garde son compte");
    }

    /// (18) La forme pure : à zéro le corps est rendu tel quel, au-dessus la clé porte le nombre.
    #[test]
    fn o6_l_aveu_du_compte_est_absent_a_zero_et_porte_le_nombre_au_dessus() {
        let corps = json!({ "aliases": [], "tags": [] });
        assert_eq!(avouer_les_lectures_de_savoir_ratees(corps.clone(), 0), corps, "à zéro : corps inchangé octet pour octet");
        let avoue = avouer_les_lectures_de_savoir_ratees(corps, 3);
        assert_eq!(avoue[CLE_LECTURES_DE_SAVOIR_RATEES], json!(3));
        assert_eq!(avoue.as_object().unwrap().len(), 3, "une seule clé ajoutée : {avoue}");
    }
}
