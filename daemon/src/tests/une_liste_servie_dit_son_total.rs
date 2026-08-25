// =================================================================================================
// `P11.17-f` — TROIS AUTRES LISTES DISENT CE QU'ELLES SERVENT
// =================================================================================================
// D'OÙ VIENNENT CES TROIS-LÀ. Elles n'ont pas été trouvées par une relecture mais par la GARDE
// DÉRIVÉE de `P11.17-e` (`une_fenetre_de_recence_dit_ce_qu_elle_borne`), qui tient une PROPRIÉTÉ : un
// énoncé qui prend les N dernières lignes d'une table ENTIÈRE, sans filtre ni agrégat, est une
// TRONCATURE et non une réponse, donc le chemin qui l'émet — ou son appelant — doit porter un total
// ou un curseur. La garde nommait trois écarts par leur TABLE, sous un cliquet qui ne remonte pas ;
// ce lot les ferme et le cliquet DESCEND à zéro.
//
// LA GRAVITÉ N'EST PAS LA MÊME POUR LES TROIS, ET ELLE A DICTÉ L'ORDRE :
//   * `ioc` — L'INVENTAIRE DES INDICATEURS, le plus grave. Une liste d'indicateurs tronquée en
//     silence ne se lit pas comme une liste incomplète : elle se lit comme une COUVERTURE. Ne pas y
//     voir un indicateur se conclut « il n'est pas connu du magasin », alors qu'il peut être hors
//     fenêtre. La route rendait un TABLEAU NU — il n'y avait même pas d'enveloppe où poser un total.
//   * `engagement` — LE REGISTRE DES AUTORISATIONS de pentest. Une ligne hors d'atteinte est une
//     autorisation qu'on ne sait plus avoir accordée. La table ne décroît jamais.
//   * `risk_rollup` — LE CLASSEMENT des entités à risque. La borne y est DÉLIBÉRÉE (l'ordre est
//     `score DESC` : la coupe retient les plus à risque, ce qui est la question posée), mais elle
//     était muette, et un classement muet se lit comme un inventaire.
//
// CE QUE CES TESTS PROUVENT, ET PAR QUELLE VALEUR :
//   ① `inventaire_des_indicateurs_total_suit_le_volume_la_fenetre_non` — LE DÉFAUT, NOMMÉ PAR LA
//      VALEUR QUI CHANGE : `served` sature à la fenêtre pendant que `total` suit le magasin.
//   ② `inventaire_des_indicateurs_total_plafonne_est_annonce` — au-dessus du plafond partagé le total
//      est plafonné ET le DIT ; sous le plafond il est EXACT (témoin inverse compris).
//   ③ `le_total_borne_de_l_inventaire_cesse_de_suivre_le_volume_sa_fenetre_non` — CE QUE LA BORNE
//      ACHÈTE, ET CE QU'ELLE N'ACHÈTE PAS. La mutation ÉVIDENTE est RÉFUTÉE DEPUIS `P11.17-e` et n'est
//      PAS rejouée : opposer un comptage borné au même comptage privé de son `LIMIT` ne prouve rien,
//      SQLite servant ce cas par un comptage de B-tree que les compteurs de statement ne voient pas.
//      Le contre-exemple retenu BALAIE vraiment, et il n'est pas fabriqué : c'est LA FENÊTRE SERVIE
//      elle-même. `ioc.last_seen` n'étant indexé par rien, l'ordre servi impose un parcours complet
//      suivi d'un tri — la borne borne l'ENVOI, pas la lecture. Le comptage, lui, s'arrête au plafond.
//   ④ `registre_des_engagements_total_suit_le_volume_la_fenetre_non` — même contrat sur le registre,
//      plafond compris.
//   ⑤ `le_curseur_sur_l_identifiant_ne_sert_pas_l_ordre_des_engagements` — LA RÉFUTATION ÉCRITE :
//      le curseur sur l'identifiant seul de `P11.17-e` ne se recopie PAS ici. `engagement.id` est un
//      TEXTE tiré de `/dev/urandom`, pas un alias de `rowid` : il pagine dans un ordre sans rapport
//      avec les créations. L'instrument est validé dans les deux sens (une clé monotone, elle, sert
//      cet ordre) — sans quoi le test ne prouverait que l'incapacité de son propre comparateur.
//   ⑥ `classement_des_entites_a_risque_declare_sa_coupe` — la coupe de rang est DÉCLARÉE : la vue
//      reçoit le rang, le nombre servi et le total des entités à risque, plafond compris.
//   ⑦ `une_entite_au_dessus_d_un_seuil_sous_le_rang_de_coupe_est_comptee` — POURQUOI UN TOTAL SEUL NE
//      SUFFISAIT PAS ICI. La pastille « seuil » est une DISJONCTION (score OU tactiques OU vélocité) :
//      une entité peut franchir un seuil par les tactiques avec un score modeste, tomber SOUS le rang
//      de coupe, et disparaître du panneau qui existe pour la montrer. La mutation nomme la valeur qui
//      change (`over_threshold_total`), et le témoin inverse tient l'autre sens.
// =================================================================================================

#[cfg(test)]
mod une_liste_servie_dit_son_total_tests {
    use super::*;

    /// LIGNES traversées en balayage, comptées par SQLite lui-même (`FullscanStep`) : la grandeur qui
    /// décide, puisqu'une ligne traversée est une page lue et — sous SQLCipher — déchiffrée. Le
    /// statement est préparé ICI et jeté après la mesure : `sqlite3_stmt_status` rend un CUMUL sur la
    /// vie du statement, donc en réutiliser un mesurerait la somme de toutes ses exécutions.
    fn lignes_traversees(conn: &Connection, sql: &str) -> i64 {
        let mut s = conn.prepare(sql).expect("la route émet un SQL valide");
        {
            let mut rows = s.query([]).unwrap();
            while rows.next().unwrap().is_some() {}
        }
        s.get_status(rusqlite::StatementStatus::FullscanStep) as i64
    }

    /// Sème `n` indicateurs en UN énoncé (CTE récursive), comme `ioc_upsert` les écrirait : valeur
    /// unique (la table porte `UNIQUE(type,value,source,env_id)`), `last_seen` croissant, jamais
    /// expirés. Ce qui compte ici est le NOMBRE de lignes.
    fn ioc_semer(conn: &Connection, n: i64) {
        conn.execute_batch(&format!(
            "WITH RECURSIVE s(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM s WHERE i<{n}) \
             INSERT INTO ioc(type,value,source,confidence,severity,first_seen,last_seen,env_id) \
             SELECT 'ip','10.0.0.'||i,'semé',50,2,1700000000+i,1700000000+i,'prod' FROM s;"
        ))
        .unwrap();
    }

    /// Sème `n` engagements clos en UN énoncé. `created` croissant avec `i` : c'est l'axe de l'ordre
    /// servi. L'identifiant est ici monotone À DESSEIN — les tests qui portent sur l'ORDRE des
    /// identifiants réels passent par `engagement_new_id`, jamais par ce semeur.
    fn eng_semer(conn: &Connection, n: i64) {
        conn.execute_batch(&format!(
            "WITH RECURSIVE s(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM s WHERE i<{n}) \
             INSERT INTO engagement(id,name,box,scope,window_start,window_end,authorizer,reason,status,adapter,env_id,created,created_by) \
             SELECT 'eng_'||i,'semé','blackbox','[]',0,0,'autorité','motif','expired','','prod',1700000000+i,'op' FROM s;"
        ))
        .unwrap();
    }

    /// Sème `n` entités à risque de score CROISSANT (`score = base + i`) : le classement par score
    /// décroissant sert donc les `i` les plus grands. Aucune tactique, aucune vélocité.
    fn risk_semer(conn: &Connection, n: i64, base_score: i64) {
        conn.execute_batch(&format!(
            "WITH RECURSIVE s(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM s WHERE i<{n}) \
             INSERT INTO risk_rollup(entity_type,entity,env_id,score,contrib,distinct_tactics,tactics,score_hot,contrib_hot,max_severity,first_ts,last_ts,updated) \
             SELECT 'ip','10.0.0.'||i,'prod',{base_score}+i,1,0,'',0,0,2,1700000000,1700000000+i,1700000000 FROM s;"
        ))
        .unwrap();
    }

    fn servies(v: &Value, cle: &str) -> usize {
        v[cle].as_array().unwrap().len()
    }

    // =============================================================================================
    // ① — L'INVENTAIRE DES INDICATEURS : LE DÉFAUT, NOMMÉ PAR LA VALEUR QUI CHANGE
    // =============================================================================================

    /// `served` SATURE à la fenêtre pendant que `total` suit le magasin : c'est exactement l'écart que
    /// le panneau présentait comme une couverture, et il grandit avec chaque import. La fenêtre servie
    /// et la borne annoncée sont la MÊME valeur (`IOCS_WINDOW`), lue ici et non recopiée.
    #[test]
    fn inventaire_des_indicateurs_total_suit_le_volume_la_fenetre_non() {
        let petit = test_db();
        ioc_semer(&petit, 3);
        let v = iocs_page(&petit, 1_700_000_000);
        assert_eq!(servies(&v, "iocs"), 3, "sous la fenêtre, tout le magasin est servi");
        assert_eq!(v["served"], json!(3));
        assert_eq!(v["window"], json!(IOCS_WINDOW), "la vue reçoit la borne de la route, elle ne la devine pas");
        assert_eq!(v["total"], json!(3), "total EXACT sous le plafond de comptage");
        assert_eq!(v["total_capped"], json!(false), "…et il ne se déclare pas plafonné");

        // MUTATION du volume : au-delà de la fenêtre, `total` suit et `served` a CESSÉ de suivre.
        let moyen = test_db();
        ioc_semer(&moyen, IOCS_WINDOW + 500);
        let m = iocs_page(&moyen, 1_700_000_000);
        let grand = test_db();
        ioc_semer(&grand, 2 * IOCS_WINDOW + 1_000);
        let g = iocs_page(&grand, 1_700_000_000);

        assert_eq!(servies(&m, "iocs"), IOCS_WINDOW as usize, "au-delà de la fenêtre, la route sert la fenêtre");
        assert_eq!(servies(&g, "iocs"), IOCS_WINDOW as usize, "…et elle sert la MÊME fenêtre bien plus loin");
        assert_eq!(
            servies(&m, "iocs"),
            servies(&g, "iocs"),
            "TÉMOIN DU DÉFAUT : le compte de lignes servies est le MÊME sur deux magasins de tailles \
             différentes — présenté comme une couverture, il est faux d'un écart qui grandit"
        );
        assert_eq!(m["total"], json!(IOCS_WINDOW + 500), "…pendant que le total, lui, dit le magasin");
        assert_eq!(g["total"], json!(2 * IOCS_WINDOW + 1_000), "…et qu'il le dit encore deux fois plus loin");
        assert_eq!(m["total_capped"], json!(false));
        assert_eq!(g["total_capped"], json!(false));

        // Les lignes servies sont les plus RÉCEMMENT VUES — la fenêtre borne, elle ne réordonne rien.
        let vus: Vec<i64> = g["iocs"].as_array().unwrap().iter().map(|x| x["last_seen"].as_i64().unwrap()).collect();
        assert_eq!(vus[0], 1_700_000_000 + 2 * IOCS_WINDOW + 1_000, "première ligne = la vue le plus récemment");
        assert!(vus.windows(2).all(|p| p[0] >= p[1]), "la fenêtre est servie dans l'ordre décroissant de `last_seen`");
    }

    // =============================================================================================
    // ② — LE PLAFOND DE COMPTAGE EST ANNONCÉ, JAMAIS INVENTÉ
    // =============================================================================================

    /// Un chiffre coûteux n'est pas remplacé par un chiffre faux présenté comme exact : `total_capped`
    /// est ce qui autorise la vue à écrire « sur PLUS DE tant » au lieu d'un nombre qu'elle n'a pas.
    #[test]
    fn inventaire_des_indicateurs_total_plafonne_est_annonce() {
        let sous = test_db();
        ioc_semer(&sous, PAGINATION_COUNT_CAP - 1);
        let v = iocs_page(&sous, 1_700_000_000);
        assert_eq!(v["total"], json!(PAGINATION_COUNT_CAP - 1), "sous le plafond : total EXACT");
        assert_eq!(v["total_capped"], json!(false), "TÉMOIN INVERSE : sans franchissement, rien n'est déclaré plafonné");

        let au_dessus = test_db();
        ioc_semer(&au_dessus, PAGINATION_COUNT_CAP + 1);
        let v = iocs_page(&au_dessus, 1_700_000_000);
        assert_eq!(v["total"], json!(PAGINATION_COUNT_CAP), "au plafond : le total est PLAFONNÉ…");
        assert_eq!(v["total_capped"], json!(true), "…et il le DIT");
        assert_eq!(servies(&v, "iocs"), IOCS_WINDOW as usize, "la fenêtre, elle, est servie comme d'habitude");
    }

    // =============================================================================================
    // ③ — CE QUE LA BORNE ACHÈTE, ET CE QU'ELLE N'ACHÈTE PAS
    // =============================================================================================

    /// LE THÉORÈME DU TOTAL, ET SON REVERS SUR CETTE TABLE-CI.
    ///
    /// La grandeur mesurée est le nombre de LIGNES TRAVERSÉES, compté par SQLite lui-même
    /// (`FullscanStep`) : déterministe, indépendante de la machine et de l'horloge, et c'est elle qui
    /// décide — une ligne traversée est une page lue et, sous SQLCipher, déchiffrée.
    ///
    /// LA MUTATION ÉVIDENTE N'EST PAS REJOUÉE, PARCE QU'ELLE EST DÉJÀ RÉFUTÉE (`P11.17-e`, mesuré le
    /// 2026-08-25) : opposer le comptage borné au MÊME comptage privé de son `LIMIT` ne prouve RIEN —
    /// sans clause `WHERE`, SQLite aplatit la sous-requête et sert le compte par un comptage de B-tree
    /// auquel les compteurs de statement sont AVEUGLES. Le contre-exemple retenu ici BALAIE pour de
    /// vrai, et il n'est pas fabriqué pour l'occasion : c'est LA FENÊTRE SERVIE elle-même. Aucun index
    /// ne porte `ioc.last_seen`, donc l'ordre servi impose un parcours complet suivi d'un tri : la
    /// borne de deux mille lignes borne ce qui est ENVOYÉ, pas ce qui est LU. Ce que le total borné
    /// ajoute coûte donc, au-delà du plafond, MOINS que la fenêtre qu'il accompagne.
    ///
    /// MESURÉ SUR CETTE FIXTURE LE 2026-08-25, en lignes traversées : le comptage borné en traverse
    /// 10 000 sur un magasin de 10 500 indicateurs COMME sur un magasin de 21 000 — il cesse de suivre
    /// et s'arrête au plafond ; la fenêtre servie, elle, en traverse 10 499 puis 20 999 — elle suit le
    /// volume ligne pour ligne. Les deux grandeurs sont assertées ci-dessous, jamais recopiées.
    #[test]
    fn le_total_borne_de_l_inventaire_cesse_de_suivre_le_volume_sa_fenetre_non() {
        let petit = test_db();
        ioc_semer(&petit, PAGINATION_COUNT_CAP + 500);
        let grand = test_db();
        risk_semer(&grand, 1, 0); // témoin d'indépendance : une autre table peuplée ne déplace rien
        ioc_semer(&grand, 2 * (PAGINATION_COUNT_CAP + 500));

        let compte = iocs_total_sql();
        let c_petit = lignes_traversees(&petit, &compte);
        let c_grand = lignes_traversees(&grand, &compte);
        assert!(c_petit > 0, "instrument : le comptage borné ne traverse AUCUNE ligne — le compteur ne mesure rien ici");
        assert_eq!(c_petit, c_grand, "MUTATION x2 du volume : le comptage borné traverse le MÊME nombre de lignes");
        assert!(
            c_grand <= PAGINATION_COUNT_CAP + 1,
            "…et ce nombre est le plafond lui-même ({c_grand} lignes pour un plafond de {PAGINATION_COUNT_CAP})"
        );

        // TÉMOIN INVERSE, ET CONSTAT PROPRE À CETTE TABLE : la FENÊTRE SERVIE, elle, suit le volume.
        let fenetre = iocs_window_sql();
        let f_petit = lignes_traversees(&petit, &fenetre);
        let f_grand = lignes_traversees(&grand, &fenetre);
        assert!(
            f_grand > f_petit * 3 / 2,
            "TÉMOIN INVERSE : la fenêtre servie DOIT suivre le volume (petit={f_petit}, grand={f_grand}) — \
             sinon l'invariance mesurée ci-dessus ne serait qu'un compteur coincé"
        );
        assert!(
            c_grand < f_grand,
            "le comptage borné du gros magasin traverse moins de lignes que la fenêtre servie du MÊME magasin \
             (borné={c_grand}, fenêtre={f_grand}) — la borne de la fenêtre borne l'ENVOI, pas la LECTURE"
        );
    }

    // =============================================================================================
    // ④ — LE REGISTRE DES ENGAGEMENTS
    // =============================================================================================

    /// Même contrat que l'inventaire, sur un registre d'AUTORISATIONS qui ne décroît jamais : aucun
    /// `DELETE` ne touche `engagement`, le cycle de vie ne fait que passer `status` à `expired` ou
    /// `revoked`. Le plafond de comptage est éprouvé dans les deux sens ici même.
    #[test]
    fn registre_des_engagements_total_suit_le_volume_la_fenetre_non() {
        let petit = test_db();
        eng_semer(&petit, 3);
        let v = engagements_page(&petit);
        assert_eq!(servies(&v, "engagements"), 3, "sous la fenêtre, tout le registre est servi");
        assert_eq!(v["served"], json!(3));
        assert_eq!(v["window"], json!(ENGAGEMENTS_WINDOW), "le lecteur reçoit la borne de la route, il ne la devine pas");
        assert_eq!(v["total"], json!(3), "total EXACT sous le plafond de comptage");
        assert_eq!(v["total_capped"], json!(false), "…et il ne se déclare pas plafonné");

        let moyen = test_db();
        eng_semer(&moyen, ENGAGEMENTS_WINDOW + 50);
        let m = engagements_page(&moyen);
        let grand = test_db();
        eng_semer(&grand, 25 * ENGAGEMENTS_WINDOW);
        let g = engagements_page(&grand);
        assert_eq!(servies(&m, "engagements"), ENGAGEMENTS_WINDOW as usize, "au-delà de la fenêtre, la route sert la fenêtre");
        assert_eq!(
            servies(&m, "engagements"),
            servies(&g, "engagements"),
            "TÉMOIN DU DÉFAUT : le compte de lignes servies est le MÊME sur deux registres de tailles \
             très différentes — présenté comme un total, il est faux d'un écart qui grandit"
        );
        assert_eq!(m["total"], json!(ENGAGEMENTS_WINDOW + 50), "…pendant que le total, lui, dit le registre");
        assert_eq!(g["total"], json!(25 * ENGAGEMENTS_WINDOW), "…et qu'il le dit encore vingt-cinq fois plus loin");

        // La fenêtre sert les engagements DÉCLARÉS le plus récemment, dans l'ordre servi.
        let crees: Vec<i64> = g["engagements"].as_array().unwrap().iter().map(|e| e["created"].as_i64().unwrap()).collect();
        assert!(crees.windows(2).all(|p| p[0] >= p[1]), "la fenêtre est servie dans l'ordre décroissant de `created`");

        // PLAFOND DE COMPTAGE, DANS LES DEUX SENS.
        let sous = test_db();
        eng_semer(&sous, PAGINATION_COUNT_CAP - 1);
        let v = engagements_page(&sous);
        assert_eq!(v["total"], json!(PAGINATION_COUNT_CAP - 1), "sous le plafond : total EXACT");
        assert_eq!(v["total_capped"], json!(false), "TÉMOIN INVERSE : sans franchissement, rien n'est déclaré plafonné");
        let au_dessus = test_db();
        eng_semer(&au_dessus, PAGINATION_COUNT_CAP + 1);
        let v = engagements_page(&au_dessus);
        assert_eq!(v["total"], json!(PAGINATION_COUNT_CAP), "au plafond : le total est PLAFONNÉ…");
        assert_eq!(v["total_capped"], json!(true), "…et il le DIT");
    }

    // =============================================================================================
    // ⑤ — LA RÉFUTATION : LE CURSEUR DE `P11.17-e` NE SE RECOPIE PAS ICI
    // =============================================================================================

    /// `P11.17-e` a laissé ouverte la possibilité d'un curseur sur l'identifiant SEUL, parce que
    /// `action.id` est l'alias du `rowid` : son ordre EST celui des créations. Recopier cette
    /// conclusion ici serait la faute que ce dépôt a déjà payée deux fois — reprendre un idiome à la
    /// lettre au lieu de vérifier ce que la clé permet. `engagement.id` est un TEXTE
    /// (`eng_<32 hexadécimaux tirés de /dev/urandom>`, cf. `engagement_new_id`) : il est unique et
    /// stable, mais son ordre lexicographique n'a AUCUN rapport avec l'ordre des créations.
    ///
    /// L'INSTRUMENT EST VALIDÉ DANS LES DEUX SENS : la même comparaison, appliquée à une clé MONOTONE,
    /// doit rendre « l'ordre est celui des créations ». Sans ce témoin, le test ne prouverait que
    /// l'incapacité de son propre comparateur.
    #[test]
    fn le_curseur_sur_l_identifiant_ne_sert_pas_l_ordre_des_engagements() {
        const N: usize = 64;

        // TÉMOIN NÉGATIF (l'instrument sait dire « oui ») : une clé monotone sert l'ordre des créations.
        let monotones: Vec<String> = (0..N).map(|i| format!("eng_{i:08}")).collect();
        let mut tries = monotones.clone();
        tries.sort();
        assert_eq!(tries, monotones, "instrument : sur une clé MONOTONE, l'ordre des clés EST celui des créations");

        // LA VRAIE CLÉ : engendrée par la voie de production, dans l'ordre des créations.
        let reels: Vec<String> = (0..N)
            .map(|_| engagement_new_id().expect("la voie de production engendre un identifiant"))
            .collect();
        assert_eq!(
            reels.iter().collect::<std::collections::HashSet<_>>().len(),
            N,
            "prérequis : les identifiants engendrés sont distincts"
        );
        let mut tries = reels.clone();
        tries.sort();
        assert_ne!(
            tries, reels,
            "RÉFUTATION : l'ordre lexicographique des identifiants d'engagement suivrait celui des créations — \
             il ne le suit pas, et un curseur sur cette clé paginerait dans un ordre sans rapport avec la liste servie"
        );

        // ET LA LISTE, ELLE, EST ORDONNÉE PAR `created` : c'est cet axe-là qu'un curseur devrait servir.
        let conn = test_db();
        for (rang, id) in reels.iter().enumerate().take(8) {
            conn.execute(
                "INSERT INTO engagement(id,name,box,scope,window_start,window_end,authorizer,reason,status,adapter,env_id,created,created_by) \
                 VALUES(?1,'semé','blackbox','[]',0,0,'autorité','motif','expired','','prod',?2,'op')",
                params![id, 1_700_000_000i64 + rang as i64],
            )
            .unwrap();
        }
        let v = engagements_page(&conn);
        let servis: Vec<String> = v["engagements"].as_array().unwrap().iter().map(|e| e["id"].as_str().unwrap().to_string()).collect();
        let attendu: Vec<String> = reels.iter().take(8).rev().cloned().collect();
        assert_eq!(servis, attendu, "la liste sert l'ordre des DÉCLARATIONS, décroissant — jamais celui des identifiants");
    }

    // =============================================================================================
    // ⑥ — LE CLASSEMENT DES ENTITÉS À RISQUE DÉCLARE SA COUPE
    // =============================================================================================

    /// La borne est ici DÉLIBÉRÉE : l'ordre étant `score DESC`, la coupe retient les entités les plus à
    /// risque, ce qui est la question d'un panneau de triage — et `risk_rollup` est RECONSTRUITE à
    /// blanc à chaque tick, donc elle ne grossit pas avec le temps. Ce qui manquait n'était pas un
    /// parcours, c'était la DÉCLARATION : le rang de coupe, le nombre servi, le total des entités.
    #[test]
    fn classement_des_entites_a_risque_declare_sa_coupe() {
        let petit = test_db();
        risk_semer(&petit, 3, 0);
        let v = risk_entities_page(&petit, 100, 0, 0);
        assert_eq!(servies(&v, "entities"), 3, "sous la coupe, toutes les entités sont servies");
        assert_eq!(v["served"], json!(3));
        assert_eq!(v["window"], json!(RISK_ENTITIES_WINDOW), "la vue reçoit le rang de coupe, elle ne le devine pas");
        assert_eq!(v["total"], json!(3), "total EXACT sous le plafond de comptage");
        assert_eq!(v["total_capped"], json!(false));

        let moyen = test_db();
        risk_semer(&moyen, RISK_ENTITIES_WINDOW + 50, 0);
        let m = risk_entities_page(&moyen, 100, 0, 0);
        let grand = test_db();
        risk_semer(&grand, 25 * RISK_ENTITIES_WINDOW, 0);
        let g = risk_entities_page(&grand, 100, 0, 0);
        assert_eq!(servies(&m, "entities"), RISK_ENTITIES_WINDOW as usize, "au-delà de la coupe, la route sert la coupe");
        assert_eq!(
            servies(&m, "entities"),
            servies(&g, "entities"),
            "TÉMOIN DU DÉFAUT : le compte d'entités servies est le MÊME sur deux flottes de tailles très \
             différentes — présenté comme un inventaire, il est faux d'un écart qui grandit"
        );
        assert_eq!(m["total"], json!(RISK_ENTITIES_WINDOW + 50), "…pendant que le total, lui, dit la flotte à risque");
        assert_eq!(g["total"], json!(25 * RISK_ENTITIES_WINDOW));

        // La coupe retient bien les PLUS À RISQUE : le score est décroissant et le dernier servi est le
        // bord du rang. C'est ce qui fait de cette borne une réponse et non une troncature.
        let scores: Vec<i64> = g["entities"].as_array().unwrap().iter().map(|e| e["score"].as_i64().unwrap()).collect();
        assert!(scores.windows(2).all(|p| p[0] >= p[1]), "le classement est servi par score décroissant");
        assert_eq!(scores[0], 25 * RISK_ENTITIES_WINDOW, "première ligne = l'entité la plus à risque");

        // PLAFOND DE COMPTAGE, DANS LES DEUX SENS.
        let sous = test_db();
        risk_semer(&sous, PAGINATION_COUNT_CAP - 1, 0);
        let v = risk_entities_page(&sous, 100, 0, 0);
        assert_eq!(v["total"], json!(PAGINATION_COUNT_CAP - 1), "sous le plafond : total EXACT");
        assert_eq!(v["total_capped"], json!(false), "TÉMOIN INVERSE : sans franchissement, rien n'est déclaré plafonné");
        let au_dessus = test_db();
        risk_semer(&au_dessus, PAGINATION_COUNT_CAP + 1, 0);
        let v = risk_entities_page(&au_dessus, 100, 0, 0);
        assert_eq!(v["total"], json!(PAGINATION_COUNT_CAP), "au plafond : le total est PLAFONNÉ…");
        assert_eq!(v["total_capped"], json!(true), "…et il le DIT");
        assert!(
            v["over_threshold_total"].as_i64().unwrap() <= PAGINATION_COUNT_CAP,
            "au plafond, le compte d'entités au-dessus d'un seuil est lui aussi un PLANCHER, jamais un chiffre inventé"
        );
    }

    // =============================================================================================
    // ⑦ — POURQUOI UN TOTAL SEUL NE SUFFISAIT PAS SUR CE CLASSEMENT-LÀ
    // =============================================================================================

    /// LE DANGER PROPRE À UNE COUPE DE RANG. La pastille « seuil » du panneau est une DISJONCTION :
    /// score cumulé, OU tactiques MITRE distinctes, OU vélocité. L'ordre du classement, lui, ne
    /// connaît que le SCORE. Une entité qui franchit un seuil par les TACTIQUES avec un score modeste
    /// tombe donc sous le rang de coupe et disparaît — du panneau qui existe pour la montrer. Un total
    /// seul ne le dirait pas ; le compte d'entités au-dessus d'un seuil, si.
    ///
    /// MUTATION : le seuil de tactiques passe au-dessus de celui de l'entité discrète. La valeur qui
    /// change est `over_threshold_total`, et elle baisse d'EXACTEMENT une. Témoin inverse compris.
    #[test]
    fn une_entite_au_dessus_d_un_seuil_sous_le_rang_de_coupe_est_comptee() {
        let conn = test_db();
        // Le classement est saturé par des entités de score élevé…
        risk_semer(&conn, RISK_ENTITIES_WINDOW + 50, 1_000);
        // …et UNE entité discrète : score sous le seuil, mais cinq tactiques MITRE distinctes.
        conn.execute(
            "INSERT INTO risk_rollup(entity_type,entity,env_id,score,contrib,distinct_tactics,tactics,score_hot,contrib_hot,max_severity,first_ts,last_ts,updated) \
             VALUES('user','discrète','prod',1,5,5,'T1078,T1110,T1059,T1053,T1021',0,0,3,1700000000,1700000000,1700000000)",
            [],
        )
        .unwrap();

        let attendues = RISK_ENTITIES_WINDOW + 51;
        let v = risk_entities_page(&conn, 100, 3, 0);
        assert_eq!(v["total"], json!(attendues), "le total dit la flotte à risque entière");
        assert_eq!(servies(&v, "entities"), RISK_ENTITIES_WINDOW as usize, "…dont la coupe ne sert que le rang");

        // LE DÉFAUT, NOMMÉ : l'entité au-dessus d'un seuil n'est PAS servie.
        let servie = v["entities"].as_array().unwrap().iter().any(|e| e["entity"] == json!("discrète"));
        assert!(!servie, "l'entité discrète est bien SOUS le rang de coupe — sans quoi ce test ne mesurerait rien");

        // CE QUE LA RÉPONSE EN DIT : le compte au-dessus d'un seuil DÉPASSE celui des lignes servies
        // qui portent la pastille. C'est cet écart-là que la vue doit rendre lisible.
        let marquees_servies = v["entities"].as_array().unwrap().iter().filter(|e| e["over_threshold"] == json!(true)).count() as i64;
        assert_eq!(marquees_servies, RISK_ENTITIES_WINDOW, "toutes les entités servies franchissent le seuil de score");
        assert_eq!(
            v["over_threshold_total"],
            json!(attendues),
            "le compte au-dessus d'un seuil inclut l'entité que la coupe ne sert pas"
        );
        assert!(
            v["over_threshold_total"].as_i64().unwrap() > marquees_servies,
            "TÉMOIN DU DÉFAUT : {} entités au-dessus d'un seuil, {marquees_servies} visibles — l'écart était MUET",
            v["over_threshold_total"]
        );

        // MUTATION : le seuil de tactiques passe AU-DESSUS des cinq de l'entité discrète.
        let mute = risk_entities_page(&conn, 100, 6, 0);
        assert_eq!(
            mute["over_threshold_total"],
            json!(attendues - 1),
            "MUTATION du seuil de tactiques : la valeur qui change est `over_threshold_total`, et elle baisse d'exactement une"
        );
        assert_eq!(mute["total"], json!(attendues), "TÉMOIN INVERSE : le total, lui, ne bouge pas — un seuil ne retire aucune entité");
        assert_eq!(
            mute["served"], v["served"],
            "TÉMOIN INVERSE : la coupe ne bouge pas non plus — elle ne connaît que le score"
        );

        // ET LE SEUIL DE BASE FAIT MOUVOIR LE MÊME CHIFFRE DANS L'AUTRE SENS : un seuil de score
        // au-dessus de toutes les entités ne laisse que celle qui franchit par les tactiques.
        let haut = risk_entities_page(&conn, 1_000_000, 3, 0);
        assert_eq!(
            haut["over_threshold_total"],
            json!(1),
            "seuil de score inatteignable : seule l'entité qui franchit par les TACTIQUES reste comptée"
        );
    }
}
