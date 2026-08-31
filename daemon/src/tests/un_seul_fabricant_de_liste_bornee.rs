// =================================================================================================
// `P11.22-f` — UNE SEULE ÉCRITURE DE LA FORME HONNÊTE, ET LES QUATRE COPIES Y SONT RALLIÉES
// =================================================================================================
// D'OÙ VIENT CE LOT. `P11.22-e` a fermé UNE route en lui faisant avouer sa borne, puis a mesuré
// l'ampleur de la classe : une VINGTAINE de listes bornées servies sans un mot. Il a REFUSÉ de les
// fermer une à une, et la raison est le cœur de ce lot : la forme honnête — `served` / `window` /
// `total` / `total_capped`, le total mesuré par un comptage borné et rendu `null` (jamais `0`) quand
// il n'a pas pu être lu — existait DÉJÀ, en QUATRE exemplaires recopiés. En écrire une cinquième
// copie aurait converti un défaut de silence en un défaut de divergence.
//
// CE QUE CES TESTS PROUVENT, ET PAR QUELLE VALEUR :
//   ① `la_forme_honnete_n_a_qu_un_seul_auteur` — LE CLIQUET ANTI-COPIE. Aucun fichier de production
//      ne peut assembler le couple `total`/`total_capped` contre le plafond partagé, hors du
//      fabricant unique et de DEUX écarts nommés avec leur raison. C'est la garde qui empêche la
//      cinquième copie de naître, et elle est ancrée sur la FORME du code, pas sur un nom de module.
//   ② `les_quatre_copies_sont_ralliees_et_rendent_la_meme_forme` — les quatre routes qui portaient
//      la copie rendent toujours le quadruplet, et elles le rendent MAINTENANT depuis le fabricant.
//   ③ `l_aveu_se_mesure_a_la_ligne_excedentaire_jamais_a_une_longueur` — LE REFUS CENTRAL. Une base
//      qui porte PILE la borne n'est PAS écourtée ; ce qui fonde l'aveu est l'existence d'une ligne
//      de plus, JAMAIS servie. Le témoin inverse tient l'autre sens.
//   ④ `la_ventilation_par_source_du_magasin_dit_sa_coupe` — LE SITE LE PLUS GRAVE DU RECENSEMENT,
//      fermé : un inventaire par source coupé au cinquantième rang, posé à côté d'un total du
//      magasin ENTIER, se lisait comme une COUVERTURE.
//   ⑤ `une_liste_complete_n_avoue_rien_et_une_tranche_vide_reste_valide` — LE TÉMOIN NÉGATIF, exigé
//      parce que le paravent a déjà été refusé sur cette famille : un aveu inconditionnel ne vaut
//      pas mieux que le silence, et une tranche légitimement VIDE doit rester un fait.
//   ⑥ `une_liste_vide_et_une_liste_illisible_cessent_de_se_confondre` — LA TROISIÈME DISTINCTION,
//      celle que `P11.22-e` déclare ne pas tenir contre son propre travail. Les deux legs tiennent
//      `served` ET `total` ÉGAUX et ne diffèrent que par le verdict : sans cela on prouverait qu'un
//      chemin d'erreur existe, pas qu'il se DISTINGUE d'un fait.
// =================================================================================================

#[cfg(test)]
mod un_seul_fabricant_de_liste_bornee_tests {
    use super::*;
    use crate::handlers::liste_bornee::{corps, couper_a_la_borne, Lignes, TotalBorne};

    /// Sème `n` indicateurs portant `n` sources DISTINCTES : c'est la cardinalité des sources, et non
    /// le nombre d'indicateurs, qui décide de la coupe de la ventilation.
    fn ioc_semer_sources(conn: &Connection, n: i64) {
        conn.execute_batch(&format!(
            "WITH RECURSIVE s(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM s WHERE i<{n}) \
             INSERT INTO ioc(type,value,source,confidence,severity,first_seen,last_seen,env_id) \
             SELECT 'ip','10.1.0.'||i,'flux_'||i,50,2,1700000000+i,1700000000+i,'prod' FROM s;"
        ))
        .unwrap();
    }

    // =============================================================================================
    // ① LE CLIQUET ANTI-COPIE — LA FORME N'A QU'UN SEUL AUTEUR
    // =============================================================================================
    // LA PROPRIÉTÉ, ancrée sur la FORME du code : un fichier de production qui écrit la clé
    // `total_capped` ET nomme le plafond de comptage partagé ASSEMBLE la forme honnête. Il n'y a
    // qu'un seul endroit où cet assemblage a le droit de vivre.
    //
    // POURQUOI CE CRITÈRE-LÀ. Le défaut n'est pas d'employer la forme, c'est de la RÉÉCRIRE : les
    // quatre copies étaient identiques au caractère près, et la cinquième l'aurait été aussi — puis
    // la première qui change aurait laissé les autres derrière. La clé et le plafond ensemble sont
    // exactement ce qu'il faut réunir pour la réécrire.
    //
    // LES ÉCARTS SONT NOMMÉS AVEC LEUR RAISON, ET LE CLIQUET NE REMONTE PAS.
    const AUTEURS_ADMIS: &[(&str, &str)] = &[
        ("handlers/liste_bornee.rs", "LE FABRICANT UNIQUE — c'est ici, et nulle part ailleurs, que la \
          forme est écrite"),
        ("handlers/query.rs", "LA SOURCE DU MOTIF, hors périmètre de ce lot. `/api/query` assemble le \
          couple sur une requête COMPILÉE arbitraire, pas sur une table nommée : son comptage borné \
          enveloppe un sous-énoncé (`SELECT 1 FROM ({sql}) LIMIT …`) que le fabricant ne sait pas \
          construire aujourd'hui. Le rallier demande d'élargir le fabricant, pas de le recopier"),
        ("handlers/admin_ui.rs", "LA PAGE DU JOURNAL D'INTÉGRITÉ, hors périmètre de ce lot (le plafond \
          de six fichiers). Elle porte en plus un curseur, un `has_more` et un saut de page numérotée : \
          son corps est un sur-ensemble du quadruplet, et la rallier suppose que le fabricant accepte \
          ces clés-là"),
    ];

    fn sources_de_production() -> Vec<(String, String)> {
        let racine = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut piles = vec![racine.clone()];
        let mut out = Vec::new();
        while let Some(d) = piles.pop() {
            for e in std::fs::read_dir(&d).expect("le répertoire des sources est lisible") {
                let p = e.expect("entrée lisible").path();
                // `src/tests/` est la couche des témoins : elle CITE la forme, elle ne la sert pas.
                if p.is_dir() {
                    if p.file_name().map(|n| n != "tests").unwrap_or(true) {
                        piles.push(p);
                    }
                } else if p.extension().map(|x| x == "rs").unwrap_or(false) {
                    let rel = p.strip_prefix(&racine).unwrap().to_string_lossy().into_owned();
                    out.push((rel, std::fs::read_to_string(&p).expect("source lisible")));
                }
            }
        }
        out.sort();
        out
    }

    /// Ce fichier ASSEMBLE-T-IL la forme ? Lu SANS les commentaires : la décrire n'est pas l'écrire —
    /// piège d'instrument payé par `P11.22-c`, et l'instrument partagé le ferme désormais.
    fn assemble_la_forme(src: &str) -> bool {
        let net = crate::tests::file_de_riposte_bornee_tests::source_sans_commentaires(src);
        net.contains("\"total_capped\"") && net.contains("PAGINATION_COUNT_CAP")
    }

    #[test]
    fn la_forme_honnete_n_a_qu_un_seul_auteur() {
        // --- VALIDATION DE L'INSTRUMENT, DANS LES DEUX SENS.
        assert!(
            assemble_la_forme("fn p() -> Value { let c = n > PAGINATION_COUNT_CAP; json!({\"total_capped\": c}) }"),
            "(instrument) un assemblage de la forme n'est PAS vu : la garde serait verte sur un arbre fautif"
        );
        assert!(
            !assemble_la_forme("fn p() -> Value { json!({\"total_capped\": c}) }"),
            "(instrument) la seule clé, sans le plafond, suffit à accuser : la garde rougirait sur du code sain"
        );
        assert!(
            !assemble_la_forme("fn p() { /* json!({\"total_capped\": c}) contre PAGINATION_COUNT_CAP */ }"),
            "(instrument) la forme DÉCRITE dans un commentaire est comptée comme ÉCRITE — c'est le piège \
             d'instrument de `P11.22-c`, et il doit rester fermé"
        );

        // --- L'ARBRE RÉEL.
        let sources = sources_de_production();
        assert!(
            sources.len() >= 50,
            "(instrument) {} source(s) de production lue(s) : le parcours est cassé, la garde refuse de \
             conclure vert",
            sources.len()
        );
        let auteurs: Vec<&str> = sources
            .iter()
            .filter(|(_, src)| assemble_la_forme(src))
            .map(|(nom, _)| nom.as_str())
            .collect();

        // TÉMOIN POSITIF SUR L'ARBRE : le fabricant est DANS la liste des auteurs. Sans cette
        // exigence, un critère devenu aveugle rendrait vert sans rien prouver.
        assert!(
            auteurs.iter().any(|a| *a == "handlers/liste_bornee.rs"),
            "le fabricant unique n'assemble plus la forme : le critère ne voit plus ce qu'il est écrit \
             pour tenir (auteurs vus : {auteurs:?})"
        );

        let intrus: Vec<&&str> = auteurs
            .iter()
            .filter(|a| !AUTEURS_ADMIS.iter().any(|(nom, _)| *nom == **a))
            .collect();
        assert!(
            intrus.is_empty(),
            "{} fichier(s) RÉÉCRIVENT la forme honnête au lieu de se rallier au fabricant unique : \
             {intrus:?} — la cinquième copie est l'anti-motif que `P11.22-f` ferme.",
            intrus.len()
        );
        let partis: Vec<&str> = AUTEURS_ADMIS
            .iter()
            .filter(|(nom, _)| !auteurs.iter().any(|a| a == &&nom[..]))
            .map(|(nom, _)| *nom)
            .collect();
        assert!(
            partis.is_empty(),
            "auteur(s) admis qui n'assemblent plus la forme : {partis:?} — le cliquet ne remonte pas, \
             retirez-les de `AUTEURS_ADMIS`"
        );
    }

    // =============================================================================================
    // ② LES QUATRE COPIES SONT RALLIÉES
    // =============================================================================================

    /// Les quatre routes qui portaient la copie rendent TOUJOURS le quadruplet — et le tiennent
    /// désormais d'un seul auteur. Le test lit les bornes DANS le code, il ne les recopie pas.
    #[test]
    fn les_quatre_copies_sont_ralliees_et_rendent_la_meme_forme() {
        let db = test_db();
        let quadruplet = |v: &Value, cle: &str, borne: i64| {
            assert!(v[cle].is_array(), "`{cle}` n'est plus une liste");
            assert_eq!(v["served"], json!(v[cle].as_array().unwrap().len()), "`served` ne compte pas `{cle}`");
            assert_eq!(v["window"], json!(borne), "la borne de la route n'est plus rendue");
            assert_eq!(v["total"], json!(0), "base vide : total EXACT, et il vaut zéro");
            assert_eq!(v["total_capped"], json!(false), "…et rien n'est déclaré plafonné");
            assert!(v.get("error").is_none(), "une base VIDE et LISIBLE n'a rien à avouer");
        };
        quadruplet(&actions_page(&db), "actions", ACTIONS_WINDOW);
        quadruplet(&engagements_page(&db), "engagements", ENGAGEMENTS_WINDOW);
        quadruplet(&iocs_page(&db, 1_700_000_000), "iocs", IOCS_WINDOW);
        let r = risk_entities_page(&db, 100, 3, 50);
        quadruplet(&r, "entities", RISK_ENTITIES_WINDOW);
        assert_eq!(
            r["over_threshold_total"],
            json!(0),
            "la clé PROPRE au panneau de risque a disparu du ralliement : le fabricant ne doit pas \
             raboter ce qu'une route ajoute"
        );
    }

    // =============================================================================================
    // ③ L'AVEU SE MESURE, IL NE SE DÉDUIT PAS D'UNE LONGUEUR
    // =============================================================================================

    /// LE REFUS CENTRAL DE CETTE FAMILLE. Une liste qui porte PILE la borne n'est pas écourtée : le
    /// lui faire dire serait un aveu INCONDITIONNEL, c'est-à-dire un aveu qui n'apprend rien. Ce qui
    /// fonde l'aveu est l'existence d'une ligne de PLUS, et cette ligne n'est JAMAIS servie.
    #[test]
    fn l_aveu_se_mesure_a_la_ligne_excedentaire_jamais_a_une_longueur() {
        let ligne = |i: i64| json!({ "i": i });

        // TÉMOIN INVERSE : sous la borne, et PILE à la borne, rien n'est avoué.
        for n in [0usize, 1, 4, 5] {
            let (servies, ecourtee) = couper_a_la_borne((0..n as i64).map(ligne).collect(), 5);
            assert_eq!(servies.len(), n, "une liste sous la borne est servie ENTIÈRE");
            assert!(
                !ecourtee,
                "{n} ligne(s) pour une borne de 5 : DÉCLARÉ écourté sans ligne excédentaire — c'est \
                 l'aveu inconditionnel que cette famille refuse"
            );
        }

        // LA MUTATION QUI NOMME LA VALEUR : une ligne de plus, et une seule.
        let (servies, ecourtee) = couper_a_la_borne((0..6).map(ligne).collect(), 5);
        assert_eq!(servies.len(), 5, "la borne est servie, jamais la ligne excédentaire");
        assert!(ecourtee, "…et l'existence de la sixième ligne FONDE l'aveu");
        assert_eq!(servies.last(), Some(&ligne(4)), "la coupe garde la TÊTE de la liste, l'ordre est celui du lu");

        // Le `+ 1` n'est écrit qu'à un seul endroit : c'est lui qui sépare « pile la borne » de
        // « il y en avait davantage ». Un site qui l'oublierait rendrait un aveu inconditionnel.
        assert_eq!(
            crate::handlers::liste_bornee::borne_avec_ligne_excedentaire(PAGINATION_COUNT_CAP),
            PAGINATION_COUNT_CAP + 1,
            "la borne de lecture ne réserve plus la ligne excédentaire qui fonde l'aveu"
        );

        // MÊME PROPRIÉTÉ SUR LE COMPTAGE BORNÉ, jusque dans le corps servi : `PAGINATION_COUNT_CAP`
        // lignes EXACTEMENT ne se déclarent pas plafonnées, la suivante si.
        let (t, c) = TotalBorne::depuis_un_comptage_borne(Ok(PAGINATION_COUNT_CAP), PAGINATION_COUNT_CAP).en_json();
        assert_eq!((t, c), (json!(PAGINATION_COUNT_CAP), json!(false)), "PILE le plafond n'est pas plafonné");
        let (t, c) = TotalBorne::depuis_un_comptage_borne(Ok(PAGINATION_COUNT_CAP + 1), PAGINATION_COUNT_CAP).en_json();
        assert_eq!((t, c), (json!(PAGINATION_COUNT_CAP), json!(true)), "une ligne de plus, et il le DIT");
    }

    // =============================================================================================
    // ④ LE SITE LE PLUS GRAVE DU RECENSEMENT, FERMÉ
    // =============================================================================================

    /// LA VENTILATION PAR SOURCE DU MAGASIN D'INDICATEURS. Elle est servie à côté d'un `total` qui
    /// compte le magasin ENTIER : coupée en silence, elle se lit comme une COUVERTURE, et un
    /// exploitant qui n'y voit pas son flux en conclut que ce flux n'alimente pas le magasin. Le corps
    /// est joué en ENTIER (fonction pure extraite) : prouver que la coupe est CALCULÉE ne prouverait
    /// pas qu'elle ATTEINT le client.
    #[test]
    fn la_ventilation_par_source_du_magasin_dit_sa_coupe() {
        let borne = TI_COVERAGE_SOURCES_MAX as i64;

        // TÉMOIN INVERSE, ET IL PORTE SUR LA VRAIE CONSTANTE : PILE le rang de coupe, rien n'est avoué.
        let pile = test_db();
        ioc_semer_sources(&pile, borne);
        let v = ti_coverage_json(&pile, 1_700_000_000);
        assert_eq!(v["by_source"].as_array().unwrap().len(), borne as usize, "la coupe sert son rang entier");
        assert_eq!(v["by_source_window"], json!(TI_COVERAGE_SOURCES_MAX), "la vue reçoit le rang de coupe");
        assert_eq!(
            v["by_source_capped"],
            json!(false),
            "un magasin qui porte PILE le rang de coupe n'est PAS écourté — le lui faire dire serait un \
             aveu inconditionnel"
        );
        assert_eq!(v["total"], json!(borne), "le total du magasin, lui, reste celui du magasin ENTIER");

        // MUTATION DU VOLUME : une source de plus, et la ventilation le DIT — pendant que `total`,
        // qui compte autre chose, continue de suivre. C'est exactement l'écart qui se lisait comme
        // une couverture.
        let deborde = test_db();
        ioc_semer_sources(&deborde, borne + 1);
        let v = ti_coverage_json(&deborde, 1_700_000_000);
        assert_eq!(v["by_source"].as_array().unwrap().len(), borne as usize, "la coupe ne sert jamais l'excédent");
        assert_eq!(v["by_source_capped"], json!(true), "…et l'existence de l'excédent FONDE l'aveu");
        assert_eq!(v["total"], json!(borne + 1), "le total du magasin suit, la ventilation non : voilà l'écart");
    }

    // =============================================================================================
    // ⑤ LE TÉMOIN NÉGATIF — UNE LISTE COMPLÈTE N'AVOUE RIEN
    // =============================================================================================

    /// LE PARAVENT A DÉJÀ ÉTÉ REFUSÉ SUR CETTE FAMILLE, ET C'EST POURQUOI CE TEST EXISTE. Un aveu
    /// posé sans condition ne vaut pas mieux que le silence : il crie à chaque réponse et cesse d'être
    /// lu. Deux propriétés ici : une liste LÉGITIMEMENT COMPLÈTE ne dit rien, et une tranche
    /// LÉGITIMEMENT VIDE reste un FAIT — `total: 0`, `total_capped: false`, aucune cause.
    #[test]
    fn une_liste_complete_n_avoue_rien_et_une_tranche_vide_reste_valide() {
        // (a) COMPLÈTE : trois indicateurs sur trois sources, tout est servi.
        let petit = test_db();
        ioc_semer_sources(&petit, 3);
        let v = ti_coverage_json(&petit, 1_700_000_000);
        assert_eq!(v["by_source"].as_array().unwrap().len(), 3);
        assert_eq!(v["by_source_capped"], json!(false), "une ventilation COMPLÈTE ne s'avoue pas coupée");
        let p = iocs_page(&petit, 1_700_000_000);
        assert_eq!(p["total_capped"], json!(false), "un inventaire COMPLET ne s'avoue pas plafonné");
        assert!(p.get("error").is_none(), "…et il n'invoque aucune cause");

        // (b) VIDE ET LISIBLE : c'est un fait établi, pas un aveu. Rien ne doit apparaître.
        let vide = test_db();
        let v = ti_coverage_json(&vide, 1_700_000_000);
        assert_eq!(v["by_source"], json!([]), "une tranche vide reste une tranche vide");
        assert_eq!(v["by_source_capped"], json!(false), "…et une tranche VIDE ne peut pas être écourtée");
        let p = iocs_page(&vide, 1_700_000_000);
        assert_eq!(p["served"], json!(0));
        assert_eq!(p["total"], json!(0), "VIDE ET LU : le total est zéro, et ce zéro est un FAIT");
        assert_eq!(p["total_capped"], json!(false));
        assert!(
            p.get("error").is_none(),
            "une base vide déclare une cause : l'aveu est devenu INCONDITIONNEL, et un avertissement \
             qu'on lit à chaque réponse cesse d'être lu"
        );
    }

    // =============================================================================================
    // ⑥ LA TROISIÈME DISTINCTION — « VIDE » N'EST PAS « ILLISIBLE »
    // =============================================================================================

    /// CE QUE `P11.22-e` A DÉCLARÉ NE PAS TENIR, CONTRE SON PROPRE TRAVAIL : son type sépare
    /// « bornée » de « complète », jamais « vide » de « illisible ». Une lecture ratée y rend une
    /// liste vide sans s'avouer écourtée — et un vide qu'on croit établi n'alarme personne.
    ///
    /// LES DEUX LEGS TIENNENT `served` ET `total` ÉGAUX, ET NE DIFFÈRENT QUE PAR LE VERDICT. Sans
    /// cette égalité on prouverait qu'un chemin d'erreur existe, pas qu'il se DISTINGUE d'un fait :
    /// c'est la distinction qui est la propriété, pas la présence d'une clé.
    #[test]
    fn une_liste_vide_et_une_liste_illisible_cessent_de_se_confondre() {
        let total = || TotalBorne::depuis_un_comptage_borne(Ok(7), PAGINATION_COUNT_CAP);
        let fait = corps("choses", Lignes::Lues(Vec::new()), 100, total());
        let aveu = corps("choses", Lignes::Illisible, 100, total());

        assert_eq!(fait["served"], aveu["served"], "les deux legs doivent servir AUTANT : sinon la comparaison ment");
        assert_eq!(fait["total"], aveu["total"], "…et annoncer le MÊME total");
        assert_eq!(fait["choses"], json!([]), "la FORME est conservée dans les deux cas");
        assert_eq!(aveu["choses"], json!([]), "un client qui lit la longueur de la liste continue de fonctionner");

        assert!(fait.get("error").is_none(), "une liste VIDE et LUE est un fait : elle n'a rien à avouer");
        assert_eq!(
            aveu["error"],
            json!(crate::handlers::liste_bornee::CAUSE_LISTE_ILLISIBLE),
            "une liste NON LUE se confond avec une liste vide : c'est le reste déclaré par `P11.22-e` \
             contre son propre travail, et il n'est pas fermé"
        );
        assert_ne!(fait, aveu, "les deux corps sont IDENTIQUES : la troisième distinction n'existe pas");

        // ET ELLE ATTEINT LE CLIENT, sur une vraie route. Une table hors d'atteinte n'est pas un
        // registre vide : `served` vaut zéro dans les deux cas, et seul l'un des deux le dit.
        let sans_table = test_db();
        sans_table.execute_batch("DROP TABLE ioc;").expect("la fixture peut retirer la table");
        let p = iocs_page(&sans_table, 1_700_000_000);
        assert_eq!(p["served"], json!(0), "une liste illisible ne sert rien…");
        assert_eq!(p["iocs"], json!([]), "…la forme attendue par le consommateur est conservée…");
        assert!(
            p.get("error").is_some(),
            "…mais elle DOIT dire que ce vide n'a pas été établi — sinon un magasin d'indicateurs \
             illisible se lit « aucun indicateur », et un magasin qu'on croit vide n'alarme personne"
        );
        assert_eq!(p["total"], Value::Null, "un comptage qui échoue rend `null`, jamais un zéro rassurant");
        assert_eq!(p["total_capped"], Value::Null);
    }
}
