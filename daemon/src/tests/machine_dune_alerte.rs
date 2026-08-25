// P11.18-v — LA MACHINE D'UNE ALERTE EST SERVIE, ET LES TROIS FAITS NE SE CONFONDENT PAS.
//
// LE DÉFAUT MESURÉ. La colonne `alert.host` est LIÉE à l'écriture par les quatre voies de levée (règle
// groupée par hôte, corrélation keyée sur un hôte, instantané de contrôles, amorce), et l'énoncé qui SERT
// la file (`alerts_query_page`) ne la sélectionnait pas : une alerte livrée à la console ne disait jamais
// sur quelle machine elle portait. Un lot voisin avait contourné en écrivant la machine dans le TITRE
// d'une alerte particulière — ce qui vaut pour celle-là et pour aucune autre.
//
// POURQUOI CE FICHIER EXISTE ALORS QUE LA CORRECTION TIENT EN UNE COLONNE. Parce que la colonne seule ne
// suffit pas : le reste de ce module SERT la machine sous `COALESCE(alert.host,'')` (`alert_group_expr`,
// délibérément, pour que le groupe '' round-trippe avec les lignes NULL). Un axe de tri et un fait servi
// ne sont pas la même chose, et transposer ce COALESCE ici aurait rendu INDISCERNABLES deux faits que le
// produit distingue à l'écriture : « cette alerte n'est liée à AUCUNE machine » (la voie de levée n'était
// pas keyée sur un hôte — c'est écrit NULL exprès) et « une machine est attachée mais l'émetteur ne l'a
// pas NOMMÉE » (machine INCONNUE). Les confondre est la famille de défaut que ce dépôt poursuit.
//
// LE CONTRÔLE POSITIF, SANS LEQUEL LE PREMIER TÉMOIN NE PROUVERAIT RIEN. Une clé ABSENTE du corps servi
// se relit `Value::Null` — exactement comme la machine ABSENTE. Un témoin qui n'exigerait que « `host`
// vaut null » serait donc VERT sur le défaut d'origine, où la colonne n'était pas servie du tout. Chaque
// témoin exige donc d'abord la PRÉSENCE de la clé dans l'objet, puis sa valeur.
mod machine_dune_alerte {
    use super::*;

    /// Le nom de machine le plus long du corpus — la valeur qui BORNE le surcoût mesuré au témoin ②.
    const MACHINE_LONGUE: &str = "srv-collecte-frontale-eu-west-01.exemple.invalid";

    /// Un corpus DÉTERMINISTE qui porte les trois faits, une fois chacun, plus un nom long.
    /// Rien n'est tiré au hasard : le surcoût mesuré doit être reproductible d'une exécution à l'autre.
    fn corpus_des_trois_faits(conn: &Connection) {
        // (a) MACHINE NOMMÉE — la voie ordinaire (règle groupée par hôte, corrélation keyée sur un hôte).
        conn.execute(
            "INSERT INTO alert(ts,rule,severity,title,status,host) VALUES(1000,'rule.1',3,'A nommée','new',?1)",
            params!["srv-01"],
        )
        .unwrap();
        // (b) MACHINE INCONNUE — une machine est attachée, l'émetteur ne l'a pas nommée (valeur vide).
        conn.execute(
            "INSERT INTO alert(ts,rule,severity,title,status,host) VALUES(1001,'rule.1',3,'A inconnue','new','')",
            [],
        )
        .unwrap();
        // (c) AUCUNE MACHINE — la colonne n'est pas liée : la voie de levée n'était pas keyée sur un hôte.
        conn.execute(
            "INSERT INTO alert(ts,rule,severity,title,status) VALUES(1002,'rule.1',3,'A sans machine','new')",
            [],
        )
        .unwrap();
        // (d) le NOM LONG : il borne le surcoût, et il ne doit pas être tronqué en route.
        conn.execute(
            "INSERT INTO alert(ts,rule,severity,title,status,host) VALUES(1003,'rule.1',3,'A longue','new',?1)",
            params![MACHINE_LONGUE],
        )
        .unwrap();
    }

    /// L'alerte dont le titre est `titre`, telle qu'elle est SERVIE.
    fn servie<'a>(page: &'a [Value], titre: &str) -> &'a serde_json::Map<String, Value> {
        page.iter()
            .find(|a| a["title"] == titre)
            .unwrap_or_else(|| panic!("l'alerte « {titre} » n'est pas dans la page servie"))
            .as_object()
            .expect("une alerte servie est un objet")
    }

    /// ① LES TROIS FAITS SONT SERVIS, ET DISTINCTS. La valeur qui change est `alerts[i]["host"]` : elle
    /// vaut le nom, la chaîne VIDE, ou `null` — trois valeurs, pour trois faits, sur le MÊME corpus.
    /// Le contrôle positif précède chaque lecture : la CLÉ doit exister, sans quoi le `null` mesuré
    /// serait celui d'un corps qui ne sert pas la colonne (le défaut d'origine, qui passerait vert).
    #[test]
    fn la_machine_est_servie_et_ses_trois_faits_ne_se_confondent_pas() {
        let conn = test_db();
        corpus_des_trois_faits(&conn);
        let (page, _) = alerts_query_page(&conn, &FiltreAlertes::default(), None, "", 50, 0, false);
        assert_eq!(page.len(), 4, "instrument : le corpus des trois faits doit être servi en entier");

        for titre in ["A nommée", "A inconnue", "A sans machine", "A longue"] {
            assert!(
                servie(&page, titre).contains_key("host"),
                "RÉGRESSION P11.18-v : le corps servi ne porte pas la clé `host` pour « {titre} ». La \
                 colonne est LIÉE à l'écriture depuis quatre voies de levée ; ne pas la SÉLECTIONNER \
                 rend une file d'alertes qui ne dit jamais sur quelle machine elle porte."
            );
        }
        assert_eq!(servie(&page, "A nommée")["host"], json!("srv-01"), "la machine nommée est rendue telle quelle");
        assert_eq!(servie(&page, "A longue")["host"], json!(MACHINE_LONGUE), "un nom long n'est pas tronqué en route");
        assert_eq!(
            servie(&page, "A inconnue")["host"],
            json!(""),
            "une machine ATTACHÉE mais NON NOMMÉE par l'émetteur doit rester la chaîne vide : c'est une \
             machine INCONNUE, pas l'absence de machine"
        );
        assert_eq!(
            servie(&page, "A sans machine")["host"],
            Value::Null,
            "une alerte que sa voie de levée n'a PAS liée à une machine doit rester `null` : un \
             `COALESCE(alert.host,'')` — celui de l'axe de TRI, qui est juste là-bas — la rendrait \
             indiscernable d'une machine inconnue"
        );
        // LA MUTATION QUI COMPTE, DANS LE MÊME CORPS : c'est le COALESCE qui détruit la distinction, et
        // on l'exécute pour prouver que le témoin ci-dessus la mesure vraiment. Sur la MÊME base, l'axe
        // de groupement (qui, lui, coalesce délibérément) range les deux lignes dans UN SEUL groupe ''.
        let (groupes, _) = alert_groups_query_page(&conn, "host", &FiltreAlertes::default(), 50, 0);
        let groupe_vide = groupes
            .iter()
            .find(|g| g["gkey"] == json!(""))
            .expect("l'axe de tri par hôte range les lignes sans nom sous la clé ''");
        assert_eq!(
            groupe_vide["n"],
            json!(2),
            "témoin de la mutation : sous COALESCE, « aucune machine » et « machine inconnue » FUSIONNENT \
             (2 lignes pour 1 clé). C'est ce que le corps servi ne doit PAS faire — et ce qu'il aurait \
             fait si l'énoncé de la file avait recopié l'expression de l'axe de tri."
        );
    }

    /// ② CE QUE SERVIR LA MACHINE AJOUTE AU CORPS — mesuré, pas estimé. Cette route est parcourue par les
    /// vues les plus chargées et le produit tient un budget mémoire DUR, donc le surcoût est une donnée de
    /// conception, pas un détail.
    ///
    /// LA MESURE EST UNE DIFFÉRENCE SUR LA MÊME PAGE : le corps servi, puis le MÊME corps privé de la
    /// seule clé `host`. Aucune seconde implémentation n'est écrite pour la comparaison — une seconde
    /// implémentation mesurerait ses propres choix.
    ///
    /// LA BORNE EST DÉRIVÉE, jamais un nombre écrit à la main : par alerte, le surcoût vaut la longueur de
    /// `,"host":` plus celle de la valeur JSON, donc au plus `,"host":""` plus le nom le plus long du
    /// corpus. Un jour où le nom d'une machine devient plus long, la borne suit.
    #[test]
    fn le_surcout_du_corps_est_borne_par_le_nom_de_la_machine() {
        let conn = test_db();
        corpus_des_trois_faits(&conn);
        let (page, _) = alerts_query_page(&conn, &FiltreAlertes::default(), None, "", 50, 0, false);
        assert_eq!(page.len(), 4, "instrument : la mesure porte sur le corpus entier");

        let corps_servi = serde_json::to_string(&json!({ "alerts": page })).expect("le corps servi se sérialise");
        let sans_machine: Vec<Value> = page
            .iter()
            .map(|a| {
                let mut o = a.as_object().expect("une alerte servie est un objet").clone();
                assert!(o.remove("host").is_some(), "contrôle positif : la clé retirée doit avoir existé");
                Value::Object(o)
            })
            .collect();
        let corps_avant = serde_json::to_string(&json!({ "alerts": sans_machine })).expect("le corps d'avant se sérialise");

        let surcout = corps_servi.len() - corps_avant.len();
        // LA FORMULE, DÉRIVÉE DE CE QUI EST RÉELLEMENT SÉRIALISÉ : une virgule de séparation, le nom de la
        // clé, deux-points, la valeur. `host` n'est jamais ni la première ni la dernière clé de l'objet,
        // donc la virgule est toujours là — et si elle cessait de l'être, cette égalité rougirait.
        let attendu: usize = page
            .iter()
            .map(|a| ",\"host\":".len() + serde_json::to_string(&a["host"]).expect("valeur sérialisable").len())
            .sum();
        assert_eq!(
            surcout, attendu,
            "le surcoût mesuré ({surcout} octets) ne s'explique pas par la seule clé servie ({attendu} \
             octets) : la mesure porte sur autre chose que ce qu'elle prétend mesurer"
        );

        // LA BORNE PAR ALERTE — c'est elle qui se transpose à une page pleine (`limit` est plafonné à
        // 1000 par la route, 200 par défaut) : le surcoût croît linéairement, et son coefficient est ici.
        let borne_unitaire = ",\"host\":\"\"".len() + MACHINE_LONGUE.len();
        assert!(
            surcout <= page.len() * borne_unitaire,
            "le surcoût par alerte ({} octets en moyenne) dépasse la borne dérivée du corpus ({} octets) \
             : servir la machine coûterait plus qu'une clé et un nom",
            surcout / page.len(),
            borne_unitaire
        );
        // Et il ne se PAIE que là où il y a quelque chose à dire : une alerte sans machine coûte la
        // valeur `null`, pas un nom. Sans ce témoin, une version qui aurait servi `COALESCE(...,'')`
        // ou un objet enveloppe passerait la borne ci-dessus sans qu'on le voie.
        let cout_sans_machine = ",\"host\":".len() + "null".len();
        assert!(
            surcout >= cout_sans_machine,
            "instrument : une page qui porte une alerte sans machine coûte au moins la clé et son `null`"
        );
    }
}
