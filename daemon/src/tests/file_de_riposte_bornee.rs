// =================================================================================================
// `P11.17-e` — LA FILE DE RIPOSTE DIT CE QU'ELLE SERT, ET UNE FENÊTRE DE RÉCENCE NE SE SERT PLUS NUE
// =================================================================================================
// LE DÉFAUT. `GET /api/actions` bornait sa lecture à cent lignes et ne rendait QUE ces lignes : ni
// total, ni indicateur de troncature. Le seul chiffre dont la console disposait était donc le nombre
// de lignes SERVIES — que le lecteur prend pour un total alors qu'il est une fenêtre. C'est la famille
// que ce dépôt poursuit — un composant qui SAIT son résultat incomplet et le présente comme complet —
// et elle portait ici sur la file des gestes de RIPOSTE, là où une ligne manquante se paie.
//
// CE QUE CES TESTS PROUVENT, ET PAR QUELLE VALEUR :
//   ① `file_de_riposte_total_suit_le_volume_la_fenetre_non` — LE DÉFAUT, NOMMÉ PAR LA VALEUR QUI
//      CHANGE. Le registre passe de 3 à 250 puis à 5 000 lignes : `served` vaut 3 puis 100 puis 100 —
//      il CESSE de suivre —, pendant que `total` vaut 3, 250, 5 000. Le compte de fenêtre, présenté
//      comme un total, était donc faux d'un écart qui GRANDIT ; et rien dans la réponse ne le disait.
//   ② `file_de_riposte_total_plafonne_est_annonce` — au-dessus du plafond de comptage PARTAGÉ, le
//      total n'est pas INVENTÉ : il est rendu plafonné ET `total_capped:true` le DIT. Sous le plafond
//      il est EXACT. Témoin inverse compris : sans franchissement, `total_capped` reste faux.
//   ③ `file_de_riposte_cout_du_total_borne_par_le_plafond` — LE THÉORÈME du total : le volume DOUBLE,
//      les lignes traversées par le comptage ne bougent PAS, et elles s'arrêtent AU plafond. La
//      mutation ÉVIDENTE — le même comptage privé de son `LIMIT` — y est RÉFUTÉE et l'écrit : sans
//      `WHERE`, SQLite sert ce compte par un comptage de B-tree auquel les deux compteurs de statement
//      sont aveugles. Le contre-exemple retenu est un comptage qui balaie vraiment.
//   ④ `une_fenetre_de_recence_dit_ce_qu_elle_borne` — LA GARDE DÉRIVÉE, qui ne nomme ni ce module ni
//      ce fichier : voir son propre en-tête.
//
// CE QUE CE LOT NE FERME PAS, ÉCRIT PLUTÔT QUE TU. La route ne rend toujours pas de CURSEUR : les
// actions plus anciennes que la fenêtre restent hors d'atteinte depuis le panneau. Rien ne l'interdit
// — `action.id` est l'alias du `rowid` (migration v4), aucune ligne n'est SUPPRIMÉE en production
// (seuls `INSERT` et `UPDATE` touchent cette table), donc un `id` n'est jamais réutilisé et l'ordre
// des `id` est celui des créations ; et `action` ne porte AUCUNE chaîne d'intégrité, contrairement au
// journal d'audit dont l'ordre EST celui de sa chaîne de hash. Le keyset `(ts,id)` de `/api/query`,
// lui, ne se recopie PAS ici : `action.ts` n'est pas indexé et le moteur de réponse insère plusieurs
// actions dans la MÊME seconde, un curseur `(ts,id)` ordonnerait donc autrement que la fenêtre servie.
// C'est la FORME qui se reprend d'un flux à l'autre — un plafond partagé, un total qui s'annonce
// plafonné —, jamais le littéral SQL.
// =================================================================================================

#[cfg(test)]
mod file_de_riposte_bornee_tests {
    use super::*;

    /// Sème `n` actions en UN énoncé (CTE récursive), comme `action_create` les écrirait : `ts`
    /// croissant avec `id`, statut `pending`, dry-run. Ce qui compte ici est le NOMBRE de lignes.
    fn act_semer(conn: &Connection, n: i64) {
        conn.execute_batch(&format!(
            "WITH RECURSIVE s(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM s WHERE i<{n}) \
             INSERT INTO action(ts,kind,target,status,dry_run,reason) \
             SELECT 1700000000+i,'ban_ip','10.0.0.1','pending',1,'semé' FROM s;"
        ))
        .unwrap();
    }

    /// LIGNES traversées en balayage, comptées par SQLite lui-même (`FullscanStep`) : la grandeur qui
    /// décide, puisqu'une ligne traversée est une page lue et — sous SQLCipher — déchiffrée. Le
    /// statement est préparé ICI et jeté après la mesure : `sqlite3_stmt_status` rend un CUMUL sur la
    /// vie du statement, donc en réutiliser un mesurerait la somme de toutes ses exécutions.
    fn act_lignes(conn: &Connection, sql: &str) -> i64 {
        let mut s = conn.prepare(sql).expect("la file émet un SQL valide");
        {
            let mut rows = s.query([]).unwrap();
            while rows.next().unwrap().is_some() {}
        }
        s.get_status(rusqlite::StatementStatus::FullscanStep) as i64
    }

    fn act_servies(v: &Value) -> usize {
        v["actions"].as_array().unwrap().len()
    }

    /// ① LE DÉFAUT, NOMMÉ PAR LA VALEUR QUI CHANGE — et le contrat qui le remplace.
    ///
    /// `served` SATURE à la fenêtre pendant que `total` suit le registre : c'est exactement l'écart
    /// que la console présentait comme un total, et il grandit avec l'usage. La fenêtre servie et la
    /// borne annoncée sont la MÊME valeur (`ACTIONS_WINDOW`), lue ici et non recopiée.
    #[test]
    fn file_de_riposte_total_suit_le_volume_la_fenetre_non() {
        let petit = test_db();
        act_semer(&petit, 3);
        let v = actions_page(&petit);
        assert_eq!(act_servies(&v), 3, "sous la fenêtre, tout le registre est servi");
        assert_eq!(v["served"], json!(3));
        assert_eq!(v["window"], json!(ACTIONS_WINDOW), "la vue reçoit la borne de la route, elle ne la devine pas");
        assert_eq!(v["total"], json!(3), "total EXACT sous le plafond de comptage");
        assert_eq!(v["total_capped"], json!(false), "…et il ne se déclare pas plafonné");

        // MUTATION x83 puis x1666 du volume : `total` suit, `served` a CESSÉ de suivre.
        let moyen = test_db();
        act_semer(&moyen, 250);
        let m = actions_page(&moyen);
        let grand = test_db();
        act_semer(&grand, 5_000);
        let g = actions_page(&grand);

        assert_eq!(act_servies(&m), ACTIONS_WINDOW as usize, "au-delà de la fenêtre, la route sert la fenêtre");
        assert_eq!(act_servies(&g), ACTIONS_WINDOW as usize, "…et elle sert la MÊME fenêtre vingt fois plus loin");
        assert_eq!(
            act_servies(&m),
            act_servies(&g),
            "TÉMOIN DU DÉFAUT : le compte de lignes servies est le MÊME sur 250 et sur 5 000 actions — \
             présenté comme un total, il est faux d'un écart qui grandit"
        );
        assert_eq!(m["total"], json!(250), "…pendant que le total, lui, dit le registre");
        assert_eq!(g["total"], json!(5_000), "…et qu'il le dit encore vingt fois plus loin");
        assert_eq!(m["total_capped"], json!(false));
        assert_eq!(g["total_capped"], json!(false));

        // Les lignes servies sont les plus RÉCENTES, dans l'ordre de la clé — la fenêtre borne, elle
        // ne réordonne rien (l'appui de la vue, qui trie ensuite les états dans ce qu'on lui a servi).
        let ids: Vec<i64> = g["actions"].as_array().unwrap().iter().map(|a| a["id"].as_i64().unwrap()).collect();
        assert_eq!(ids[0], 5_000, "première ligne = la plus récente");
        assert_eq!(ids[ids.len() - 1], 5_000 - ACTIONS_WINDOW + 1, "dernière ligne = le bord de la fenêtre");
    }

    /// ② AU-DESSUS DU PLAFOND, LE TOTAL EST PLAFONNÉ **ET DIT**. Un chiffre coûteux n'est pas remplacé
    /// par un chiffre faux présenté comme exact : `total_capped` est ce qui autorise la vue à écrire
    /// « sur PLUS DE tant » au lieu d'un nombre qu'elle n'a pas.
    #[test]
    fn file_de_riposte_total_plafonne_est_annonce() {
        let sous = test_db();
        act_semer(&sous, PAGINATION_COUNT_CAP - 1);
        let v = actions_page(&sous);
        assert_eq!(v["total"], json!(PAGINATION_COUNT_CAP - 1), "sous le plafond : total EXACT");
        assert_eq!(v["total_capped"], json!(false), "TÉMOIN INVERSE : sans franchissement, rien n'est déclaré plafonné");

        let au_dessus = test_db();
        act_semer(&au_dessus, PAGINATION_COUNT_CAP + 1);
        let v = actions_page(&au_dessus);
        assert_eq!(v["total"], json!(PAGINATION_COUNT_CAP), "au plafond : le total est PLAFONNÉ…");
        assert_eq!(v["total_capped"], json!(true), "…et il le DIT");
        assert_eq!(act_servies(&v), ACTIONS_WINDOW as usize, "la fenêtre, elle, est servie comme d'habitude");
    }

    /// ③ LE THÉORÈME DU TOTAL : les lignes traversées par le comptage cessent de suivre le volume, et
    /// elles s'arrêtent AU plafond.
    ///
    /// La grandeur mesurée est le nombre de LIGNES TRAVERSÉES, compté par SQLite lui-même
    /// (`FullscanStep`) : déterministe, indépendante de la machine et de l'horloge, et c'est elle qui
    /// décide — une ligne traversée est une page lue et, sous SQLCipher, déchiffrée.
    ///
    /// UNE MUTATION ÉVIDENTE EST ICI RÉFUTÉE, ET C'EST POURQUOI ELLE EST ÉCRITE. Opposer le comptage
    /// borné au MÊME comptage privé de son `LIMIT` (`SELECT COUNT(*) FROM (SELECT 1 FROM action)`) ne
    /// prouve RIEN : sans clause `WHERE`, SQLite aplatit la sous-requête et sert le compte par un
    /// comptage de B-tree (`OP_Count`), sans boucle de machine virtuelle. MESURÉ le 2026-08-25 sur cette
    /// fixture : cette forme rend ZÉRO ligne traversée et NEUF pas de machine virtuelle sur 10 500 comme
    /// sur 21 000 actions — les deux compteurs de statement sont AVEUGLES à son coût, qui est celui des
    /// pages du B-tree. Le contre-exemple retenu est donc un comptage qui BALAIE réellement (un `WHERE`
    /// suffit à interdire l'aplatissement) : lui suit le volume, ce qui prouve que le compteur n'est pas
    /// coincé à une constante — sans quoi l'invariance du comptage borné ne voudrait rien dire.
    /// Ce que la borne achète n'est donc pas « moins que la forme nue » : c'est un PLAFOND DUR sur ce
    /// qui est lu, sur une table qu'aucune rétention ne purge et qui ne fait que grossir.
    #[test]
    fn file_de_riposte_cout_du_total_borne_par_le_plafond() {
        let petit = test_db();
        act_semer(&petit, PAGINATION_COUNT_CAP + 500);
        let grand = test_db();
        act_semer(&grand, 2 * (PAGINATION_COUNT_CAP + 500));

        let sql = actions_total_sql();
        let c_petit = act_lignes(&petit, &sql);
        let c_grand = act_lignes(&grand, &sql);
        assert!(c_petit > 0, "instrument : le comptage borné ne traverse AUCUNE ligne — le compteur ne mesure rien ici");
        assert_eq!(c_petit, c_grand, "MUTATION x2 du volume : le comptage borné traverse le MÊME nombre de lignes");
        assert!(
            c_grand <= PAGINATION_COUNT_CAP + 1,
            "…et ce nombre est le plafond lui-même ({c_grand} lignes pour un plafond de {PAGINATION_COUNT_CAP})"
        );

        // TÉMOIN INVERSE — un comptage qui BALAIE, sur les mêmes bases : il DOIT suivre le volume.
        const QUI_BALAIE: &str = "SELECT COUNT(*) FROM (SELECT 1 FROM action WHERE dry_run=1)";
        let b_petit = act_lignes(&petit, QUI_BALAIE);
        let b_grand = act_lignes(&grand, QUI_BALAIE);
        assert!(
            b_grand > b_petit * 3 / 2,
            "TÉMOIN INVERSE : un comptage qui balaie DOIT suivre le volume (petit={b_petit}, grand={b_grand}) —              sinon l'invariance mesurée ci-dessus ne serait qu'un compteur coincé"
        );
        assert!(
            c_grand < b_grand,
            "le comptage borné du GROS registre traverse moins de lignes qu'un balayage du MÊME registre              (borné={c_grand}, balayage={b_grand})"
        );
    }

    // =============================================================================================
    // ④ GARDE DÉRIVÉE — UNE LISTE BORNÉE SERVIE DIT CE QU'ELLE BORNE (élargie par `P11.22-f`)
    // ---------------------------------------------------------------------------------------------
    // LA PROPRIÉTÉ, ÉCRITE UNE FOIS ET ANCRÉE SUR LA FORME DU CODE, JAMAIS SUR UN NOM DE FICHIER NI DE
    // MODULE (ce dépôt a déjà payé une garde aveugle parce qu'elle nommait un fichier — `P11.13-d`) :
    //
    //     Un énoncé qui borne le nombre de lignes qu'il rend est une TRONCATURE d'un registre qui
    //     peut en porter davantage. Le chemin qui l'émet doit donc rendre, à côté des lignes, de quoi
    //     savoir ce qui manque — un drapeau qui porte SUR CETTE LISTE, une continuation, ou le
    //     ralliement au fabricant unique de la forme honnête.
    //
    // CE QUE `P11.22-f` A CHANGÉ, ET POURQUOI CE N'EST PAS UN DÉTAIL. La propriété d'avant portait sur
    // la seule FENÊTRE DE RÉCENCE : les N dernières lignes d'une table ENTIÈRE, sans filtre, sans
    // agrégat, avec un tri et une borne littérale. Six conditions conjointes. Son cliquet est tombé à
    // zéro le 2026-08-25 — et ce zéro s'est LU comme « la famille est fermée » alors qu'une vingtaine
    // de listes bornées muettes vivaient juste à côté, hors du prédicat. Une garde n'était pas cassée :
    // elle mesurait plus étroit que la classe, et c'est le pire cas, parce que rien ne rougit.
    //
    // POPULATION, DÉRIVÉE DE CE QUE LE CODE EST. Tout littéral de chaîne des sources de production de
    // `src/handlers/` qui, commentaires dépouillés, porte un `SELECT … FROM …` et au moins un `LIMIT`
    // dont la borne n'est pas `1` — qu'elle soit littérale, de gabarit (`{…}`) ou liée (`?n`). En sont
    // exclus, et seulement eux : les ÉCRITURES (un `LIMIT` de `DELETE`/`INSERT`/`UPDATE` borne un lot
    // de travail), et le COMPTAGE BORNÉ lui-même (`SELECT 1 FROM … LIMIT plafond+1`), qui est
    // l'INSTRUMENT de l'aveu — l'inscrire dans sa propre population ferait rougir la garde sur son
    // propre remède.
    //
    // VERDICT. La fonction qui porte l'énoncé, OU la chaîne d'appels qui la couvre DANS LE MÊME
    // FICHIER, doit porter un aveu LISTE-SCOPÉ : un drapeau `…_capped` / `truncated` / `ecourtee`, une
    // continuation (`next_cursor`, `has_more`, le finaliseur de curseur partagé), le ralliement au
    // fabricant unique, ou — seul cas où un `total` suffit — un `OFFSET` dans l'énoncé, qui fait de la
    // borne une PAGE D'UN TOUT CONNU. `"total"` SEUL a été RETIRÉ des aveux, et c'est le second geste
    // de l'élargissement : mesuré sur l'arbre réel, la route de couverture du magasin d'indicateurs
    // pose un `total` du magasin ENTIER à côté d'une ventilation coupée au cinquantième rang. Élargir
    // la population sans resserrer l'aveu aurait donc rendu la garde VERTE sur le site le plus grave
    // du recensement — un remède qui referme une fausse accusation en faisant taire une vraie.
    //
    // CE QUE CETTE GARDE NE PROUVE PAS, dit pour qu'on ne s'en réclame pas trop :
    //   * elle ne lit pas le SQL composé morceau par morceau hors d'un seul littéral ;
    //   * elle ne prouve pas qu'un aveu soit rendu sur TOUS les chemins traversant un fabricant
    //     partagé — elle exige qu'une chaîne d'appels l'atteigne ;
    //   * la souplesse `OFFSET` + grandeur nommée `total` reconnaît une PAGE, pas une page CORRECTE :
    //     un total qui porterait sur autre chose que la liste passerait ;
    //   * elle ne distingue pas, dans sa POPULATION, une liste servie à un lecteur d'un lot de travail
    //     de boucle de fond. Cette distinction est une propriété du CHEMIN, pas de l'énoncé ; elle est
    //     donc portée à la main dans le cliquet, en deux familles nommées.
    // =============================================================================================

    /// LES ÉCARTS CONNUS — MÊME FAMILLE, PAS DANS CE LOT. Chacun est nommé par le FICHIER et la
    /// FONCTION qui portent l'énoncé, et par ce qui lui manque. Le cliquet ne remonte pas : un écart
    /// fermé DOIT sortir de cette liste, sinon le test rougit et le dit.
    ///
    /// HISTORIQUE, PARCE QU'UN ZÉRO S'EST DÉJÀ LU COMME UNE COUVERTURE. Le 2026-08-25, sous le
    /// prédicat ÉTROIT (ni `WHERE`, ni agrégat, ni borne liée), la liste portait trois écarts, tous
    /// fermés le même jour par `P11.17-f` ; elle est retombée à zéro — et ce zéro a été LU comme « la
    /// famille est fermée » alors qu'une vingtaine de listes bornées muettes vivaient hors du
    /// prédicat. `P11.22-f` élargit le prédicat et REMPLIT le cliquet de ce qui était invisible.
    ///
    /// RELEVÉ LE 2026-08-31, PRÉDICAT ÉLARGI : **trente** énoncés muets, en DEUX familles qui ne se
    /// valent pas et qu'il serait malhonnête de fondre en un seul nombre.
    ///
    ///   (A) DIX énoncés ne sont PAS servis à un lecteur : ce sont des LOTS DE TRAVAIL de boucle de
    ///       fond (relances d'échéance, activation/expiration d'engagements, notifications, forward
    ///       vers un puits externe) ou une réclamation d'agent. Leur borne se draine par RÉPÉTITION :
    ///       le tour suivant reprend là où celui-ci s'est arrêté, et personne ne lit ce lot comme un
    ///       inventaire. Ils sont dans la population parce qu'AUCUN critère syntaxique honnête ne les
    ///       en sort — « c'est un lot de fond » est une propriété du CHEMIN, pas de l'énoncé — et une
    ///       exclusion par NOM de fonction est précisément ce que ce dépôt s'interdit.
    ///
    ///   (B) VINGT énoncés sont bel et bien SERVIS à un lecteur sans dire si la borne a mordu. C'est
    ///       la classe que `P11.22-f` ouvre. L'ordre de fermeture recommandé est celui de la gravité,
    ///       et le premier de la liste — la ventilation par source du magasin d'indicateurs — est
    ///       FERMÉ par ce lot, ce qui fait passer cette famille de vingt-et-un à vingt.
    const ECARTS_CONNUS: &[(&str, &str, &str)] = &[
        // ---- (A) LOTS DE FOND ET RÉCLAMATIONS : la borne se draine par répétition. -------------
        ("actions.rs", "actions_pending", "réclamation d'agent : le lot est CLAIMÉ puis retiré du \
          prochain tour ; ce n'est pas un inventaire présenté à un lecteur"),
        ("caseops.rs", "sla_multilevel_tick", "boucle de fond des échéances : le tour suivant reprend \
          les dossiers non traités"),
        ("caseops.rs", "sla_recalcule_la_priorite_bornee", "recalcul de fond, borné par tour"),
        ("cases.rs", "escalate_overdue_cases", "boucle de fond d'escalade, bornée par tour"),
        ("destinations.rs", "forward_one_destination", "lot de forward vers un puits externe : le \
          curseur d'avancement EST la position dans `event`, le lot suivant continue"),
        ("engagement.rs", "expire_due_engagements_conn", "boucle de fond, bornée par tour"),
        ("engagement.rs", "activate_due_engagements_conn", "boucle de fond, bornée par tour"),
        ("notifiers.rs", "dispatch_notifications", "lot de notifications non encore envoyées : \
          `notified=0` retire du lot ce qui est parti, le tour suivant prend la suite"),
        // ---- (B) LISTES SERVIES ET MUETTES : la classe ouverte par `P11.22-f`. -----------------
        // L'ORDRE CI-DESSOUS EST CELUI DE LA GRAVITÉ, ET IL EST LA RECOMMANDATION DU LOT.
        ("datasource.rs", "prom_label_values", "LE NAVIGATEUR D'ÉTIQUETTES — trois énoncés à cinq \
          mille valeurs distinctes. Un exploitant qui ne trouve pas son étiquette conclut qu'elle \
          n'existe pas ; c'est la surface où la liste EST l'inventaire"),
        ("datasource.rs", "prom_labels", "LE NAVIGATEUR D'ÉTIQUETTES (noms) — deux mille blobs \
          récents, dont on tire l'UNION des clés : la borne mord sur la RÉCENCE, et rien ne le dit"),
        ("caseops.rs", "client_case_get_json", "LA LIGNE DE TEMPS D'UNE SURFACE EXTERNE — cinq cents \
          entrées servies à un client, hors de la console. Une chronologie tronquée en silence est \
          lue comme la chronologie COMPLÈTE d'un dossier"),
        ("caseops.rs", "case_queues_json", "files par assigné, coupées au cinq-centième : un assigné \
          hors coupe disparaît de la file qui existe pour le montrer"),
        ("caseops.rs", "case_links_json", "liens d'un dossier, coupés au deux-centième"),
        ("caseops.rs", "case_metrics_json", "trois énoncés — l'échantillon de cinquante mille \
          dossiers d'où sortent moyenne et médiane, plus deux ventilations bornées. Une métrique \
          calculée sur un échantillon tronqué se présente comme une métrique"),
        ("search.rs", "search", "trois énoncés de `/api/search` : la borne vient du client, mais la \
          réponse ne dit pas si elle a mordu"),
        ("system.rs", "diag_bundle_json", "trois énoncés du paquet de diagnostic — un diagnostic \
          tronqué en silence est lu comme un diagnostic complet"),
        ("rba.rs", "risk_entity_timeline", "ligne de temps d'une entité à risque, coupée au \
          deux-centième événement"),
        ("datamodels.rs", "run_generated_soql", "exécution du Pivot : borne posée sur la requête \
          compilée, jamais rendue au lecteur"),
        ("datasource.rs", "ds_soql_exec", "surface datasource : même forme, même silence"),
        ("scheduled_reports.rs", "render_report_detail", "détail d'un rapport planifié, coupé au \
          cinq-millième"),
    ];

    /// Un énoncé de la population, tel que la garde le voit.
    #[derive(Debug)]
    struct Fenetre {
        fichier: String,
        table: String,
        fonction: String,
        /// L'énoncé porte-t-il un `GROUP BY` ? Retenu parce que c'est EXACTEMENT ce que le prédicat
        /// étroit excluait : un témoin positif ancré là-dessus rougit si l'élargissement est perdu,
        /// et il l'est sur une PROPRIÉTÉ DE L'ÉNONCÉ, pas sur un nom de fonction — un nom se renomme,
        /// et l'ancre suit alors le renommage sans que personne ne le voie.
        groupe: bool,
        avoue: bool,
    }

    /// LE DÉPOUILLEMENT — commentaires retirés, littéraux relevés, et un MASQUE de même longueur (en
    /// caractères) où le contenu des chaînes et des commentaires est remplacé par des espaces. Le masque
    /// sert à apparier les accolades : une accolade de gabarit (`LIMIT {n}`) ne doit pas déséquilibrer
    /// le corps d'une fonction, et un `//` dans une chaîne ne doit pas manger la ligne.
    struct Depouille {
        masque: Vec<char>,
        /// LA SOURCE PRIVÉE DE SES SEULS COMMENTAIRES — les littéraux y sont INTACTS, parce que
        /// l'aveu vit dans un littéral. `P11.22-c` a payé ce piège : la recherche du nom du geste
        /// commun portait sur la source ENTIÈRE, si bien qu'écrire ce nom dans un commentaire — pour
        /// expliquer pourquoi on ne ralliait PAS un site — y déclarait un ralliement inexistant et
        /// faisait rougir le banc sans qu'une ligne de code ait changé de comportement. Le remède
        /// n'est pas une consigne de rédaction : c'est ce tampon.
        sans_commentaires: Vec<char>,
        source: Vec<char>,
        litteraux: Vec<(usize, String)>,
    }

    fn depouiller(src: &str) -> Depouille {
        let s: Vec<char> = src.chars().collect();
        let mut masque = s.clone();
        let mut sans_commentaires = s.clone();
        let mut litteraux = Vec::new();
        let effacer = |m: &mut Vec<char>, a: usize, b: usize| {
            for c in m.iter_mut().take(b).skip(a) {
                if *c != '\n' {
                    *c = ' ';
                }
            }
        };
        let mut i = 0usize;
        while i < s.len() {
            match s[i] {
                '/' if i + 1 < s.len() && s[i + 1] == '/' => {
                    let mut j = i;
                    while j < s.len() && s[j] != '\n' {
                        j += 1;
                    }
                    effacer(&mut masque, i, j);
                    effacer(&mut sans_commentaires, i, j);
                    i = j;
                }
                '/' if i + 1 < s.len() && s[i + 1] == '*' => {
                    let mut j = i + 2;
                    while j + 1 < s.len() && !(s[j] == '*' && s[j + 1] == '/') {
                        j += 1;
                    }
                    let fin = (j + 2).min(s.len());
                    effacer(&mut masque, i, fin);
                    effacer(&mut sans_commentaires, i, fin);
                    i = fin;
                }
                // Littéral de caractère (`'"'` existe réellement dans ce code) VS durée de vie (`'a`) :
                // on n'avale que ce qui se REFERME, sinon on ne saute que l'apostrophe.
                '\'' => {
                    let ferme = if i + 2 < s.len() && s[i + 1] == '\\' {
                        (i + 2..(i + 8).min(s.len())).find(|&k| s[k] == '\'')
                    } else if i + 2 < s.len() && s[i + 2] == '\'' {
                        Some(i + 2)
                    } else {
                        None
                    };
                    match ferme {
                        Some(f) => {
                            effacer(&mut masque, i, f + 1);
                            i = f + 1;
                        }
                        None => i += 1,
                    }
                }
                // Chaîne BRUTE : `r"…"` / `r#"…"#` — le nombre de dièses ferme.
                'r' if {
                    let mut k = i + 1;
                    while k < s.len() && s[k] == '#' {
                        k += 1;
                    }
                    k < s.len() && s[k] == '"' && !(i > 0 && (s[i - 1].is_alphanumeric() || s[i - 1] == '_'))
                } =>
                {
                    let mut dieses = 0usize;
                    let mut k = i + 1;
                    while k < s.len() && s[k] == '#' {
                        dieses += 1;
                        k += 1;
                    }
                    let debut = k + 1;
                    let mut j = debut;
                    let fin = loop {
                        if j >= s.len() {
                            break s.len();
                        }
                        if s[j] == '"' && s[j + 1..].iter().take(dieses).filter(|c| **c == '#').count() == dieses {
                            break j;
                        }
                        j += 1;
                    };
                    litteraux.push((debut, s[debut..fin.min(s.len())].iter().collect()));
                    let apres = (fin + 1 + dieses).min(s.len());
                    effacer(&mut masque, i, apres);
                    i = apres;
                }
                '"' => {
                    let debut = i + 1;
                    let mut j = debut;
                    while j < s.len() {
                        if s[j] == '\\' {
                            j += 2;
                            continue;
                        }
                        if s[j] == '"' {
                            break;
                        }
                        j += 1;
                    }
                    let fin = j.min(s.len());
                    litteraux.push((debut, s[debut..fin].iter().collect()));
                    let apres = (fin + 1).min(s.len());
                    effacer(&mut masque, i, apres);
                    i = apres;
                }
                _ => i += 1,
            }
        }
        Depouille { masque, sans_commentaires, source: s, litteraux }
    }

    /// Un mot présent, insensible à la casse, entouré de non-lettres — évite qu'un `WHERE` interne à un
    /// identifiant (`nowhere`) ne compte.
    fn contient_mot(hay: &str, mot: &str) -> bool {
        let h = hay.to_ascii_lowercase();
        let m = mot.to_ascii_lowercase();
        let o: Vec<char> = h.chars().collect();
        let n: Vec<char> = m.chars().collect();
        (0..o.len().saturating_sub(n.len() - 1)).any(|i| {
            o[i..i + n.len()] == n[..]
                && (i == 0 || !(o[i - 1].is_alphanumeric() || o[i - 1] == '_'))
                && (i + n.len() >= o.len() || !(o[i + n.len()].is_alphanumeric() || o[i + n.len()] == '_'))
        })
    }

    /// Le jeton qui suit `mot`, s'il y en a un (sert à lire la table d'un `FROM` et la borne d'un `LIMIT`).
    fn jeton_apres(hay: &str, mot: &str) -> Option<String> {
        let bas = hay.to_ascii_lowercase();
        let pos = bas.find(&mot.to_ascii_lowercase())? + mot.len();
        let reste: String = hay.chars().skip(bas[..pos].chars().count()).collect();
        let t: String = reste
            .trim_start()
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '{' || *c == '}' || *c == '?')
            .collect();
        if t.is_empty() {
            None
        } else {
            Some(t)
        }
    }

    /// TOUTES les bornes `LIMIT` d'un énoncé, dans l'ordre. Il en faut PLUSIEURS : un `LIMIT 1` de
    /// sous-requête corrélée précède parfois la borne de la liste servie, et ne lire que le premier
    /// jeton classait l'énoncé « singleton » alors que sa liste, elle, est bel et bien tronquée.
    fn bornes_du_limit(sql: &str) -> Vec<String> {
        let bas = sql.to_ascii_lowercase();
        let o: Vec<char> = bas.chars().collect();
        let src: Vec<char> = sql.chars().collect();
        let mot: Vec<char> = "limit".chars().collect();
        let mut out = Vec::new();
        for i in 0..o.len().saturating_sub(mot.len() - 1) {
            if o[i..i + mot.len()] != mot[..] {
                continue;
            }
            if i > 0 && (o[i - 1].is_alphanumeric() || o[i - 1] == '_') {
                continue;
            }
            let t: String = src[i + mot.len()..]
                .iter()
                .collect::<String>()
                .trim_start()
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '{' || *c == '}' || *c == '?')
                .collect();
            if !t.is_empty() {
                out.push(t);
            }
        }
        out
    }

    /// UNE LISTE BORNÉE SERVIE, au sens de la propriété écrite ci-dessus.
    ///
    /// CE PRÉDICAT EST L'ÉLARGISSEMENT DE `P11.22-f`, ET CE QU'IL ABANDONNE EST LA MESURE QUI LE
    /// JUSTIFIE. Il exigeait auparavant l'ABSENCE de `where`, de `distinct`, de tout agrégat et de
    /// tout `GROUP BY`, PLUS la présence d'un `ORDER BY`, PLUS une borne littérale ou de gabarit —
    /// une conjonction de six conditions. Sa population était donc strictement plus étroite que la
    /// classe de défaut, et son cliquet à zéro se LISAIT comme une couverture alors qu'une vingtaine
    /// de listes bornées muettes vivaient à côté. Trois de ces six conditions étaient FAUSSES comme
    /// critères d'exclusion, et la plus grave l'était doublement :
    ///   * un `WHERE` ne fait pas d'une borne une réponse — `WHERE incident_id=?1 … LIMIT 500` est
    ///     une troncature de la ligne de temps d'un dossier, pas la réponse à une question de rang ;
    ///   * un agrégat non plus — la ventilation par source du magasin d'indicateurs est un
    ///     `GROUP BY … LIMIT 50`, et c'est le site le PLUS grave du lot : posée à côté d'un total du
    ///     magasin entier, une ventilation tronquée en silence se lit comme une COUVERTURE ;
    ///   * une borne portée par un paramètre lié (`LIMIT ?1`) est une borne comme une autre.
    /// Ce qui RESTE exclu l'est pour une raison qui tient :
    ///   * les ÉCRITURES (`DELETE`/`INSERT`/`UPDATE`) — un `LIMIT` y borne un LOT DE TRAVAIL qui se
    ///     draine par répétition, jamais une réponse présentée à un lecteur ;
    ///   * le COMPTAGE BORNÉ lui-même (`SELECT 1 FROM … LIMIT plafond+1`) — c'est l'INSTRUMENT de
    ///     l'aveu ; l'inscrire dans sa propre population ferait rougir la garde sur son remède ;
    ///   * `LIMIT 1` — un singleton n'est pas une liste.
    fn est_une_liste_bornee_servie(sql: &str) -> bool {
        if !contient_mot(sql, "select") || !contient_mot(sql, "from") {
            return false;
        }
        if contient_mot(sql, "delete") || contient_mot(sql, "insert") || contient_mot(sql, "update") {
            return false;
        }
        if sql.to_ascii_lowercase().contains("select 1 from") {
            return false;
        }
        bornes_du_limit(sql).iter().any(|b| {
            b.starts_with('{') || b.starts_with('?') || b.parse::<i64>().map(|n| n >= 2).unwrap_or(false)
        })
    }

    /// Les fonctions d'un fichier : (nom, début du corps, fin du corps), appariées SUR LE MASQUE.
    fn fonctions(d: &Depouille) -> Vec<(String, usize, usize)> {
        let m = &d.masque;
        let mut out = Vec::new();
        let mut i = 0usize;
        while i + 3 < m.len() {
            let mot_fn = m[i] == 'f'
                && m[i + 1] == 'n'
                && m[i + 2].is_whitespace()
                && (i == 0 || !(m[i - 1].is_alphanumeric() || m[i - 1] == '_'));
            if !mot_fn {
                i += 1;
                continue;
            }
            let mut k = i + 3;
            while k < m.len() && m[k].is_whitespace() {
                k += 1;
            }
            let debut_nom = k;
            while k < m.len() && (m[k].is_alphanumeric() || m[k] == '_') {
                k += 1;
            }
            let nom: String = m[debut_nom..k].iter().collect();
            // premier `{` après la signature ; si un `;` le précède, la fonction n'a pas de corps.
            let mut j = k;
            while j < m.len() && m[j] != '{' && m[j] != ';' {
                j += 1;
            }
            if j >= m.len() || m[j] == ';' || nom.is_empty() {
                i += 1;
                continue;
            }
            let mut p = 0i32;
            let mut f = j;
            while f < m.len() {
                if m[f] == '{' {
                    p += 1;
                } else if m[f] == '}' {
                    p -= 1;
                    if p == 0 {
                        break;
                    }
                }
                f += 1;
            }
            out.push((nom, j, f.min(m.len())));
            i = k;
        }
        out
    }

    /// UNE SOURCE PRIVÉE DE SES SEULS COMMENTAIRES, exportée aux gardes voisines. C'est l'INSTRUMENT,
    /// pas la propriété : une garde qui a besoin de lire du code sans sa prose n'a pas à recopier ce
    /// dépouillement — la recopier serait rejouer, dans la couche des témoins, l'anti-motif que
    /// `P11.22-f` ferme dans la couche de production.
    pub(crate) fn source_sans_commentaires(src: &str) -> String {
        depouiller(src).sans_commentaires.iter().collect()
    }

    /// Le corps d'une fonction, PRIVÉ DE SES COMMENTAIRES et de rien d'autre : les littéraux y sont
    /// intacts (c'est là que vit l'aveu), la prose n'y est plus (c'est là que vivait le faux positif).
    fn corps_source(d: &Depouille, a: usize, b: usize) -> String {
        d.sans_commentaires[a..b.min(d.sans_commentaires.len())].iter().collect()
    }

    /// LES AVEUX RECONNUS, ET CE QUI EN A ÉTÉ RETIRÉ — `P11.22-f`.
    ///
    /// `"total"` SEUL N'EST PLUS UN AVEU, et c'est le cœur de l'élargissement. Un `total` est un
    /// nombre posé DANS un corps ; rien ne dit qu'il porte sur la liste bornée qui se trouve dans le
    /// même corps. MESURÉ : la route de couverture du magasin d'indicateurs rend un `total` du
    /// magasin ENTIER à côté d'une ventilation par source coupée au cinquantième rang. Élargir la
    /// population SANS resserrer l'aveu aurait donc rendu la garde VERTE sur le site le plus grave du
    /// lot — un remède qui referme une fausse accusation en faisant taire une vraie.
    ///
    /// CE QUI RESTE UN AVEU est LISTE-SCOPÉ ou CONTINUATIF : un drapeau qui porte sur la liste
    /// (`…_capped`, `truncated`), une continuation (`next_cursor`, `has_more`, le finaliseur de
    /// curseur partagé), ou l'appel au FABRICANT UNIQUE de la forme honnête — lequel, lui, est
    /// prouvé par ses propres témoins.
    const AVEUX: &[&str] = &[
        "_capped",
        "\"truncated\"",
        "\"next_cursor\"",
        "\"has_more\"",
        "keyset_finalize",
        "liste_bornee::corps(",
        "aveu::corps(",
        // `P11.22-e` a écrit le MÊME drapeau sous un autre mot, faute d'un fabricant où le nommer une
        // fois : le type des sources connues porte `ecourtee`, exactement le rôle de `…_capped`. Le
        // reconnaître ici évite d'inscrire au cliquet une route DÉJÀ honnête — et la divergence de
        // vocabulaire est précisément le prix qu'on paie à ne pas avoir eu de fabricant unique.
        "ecourtee",
    ];

    /// UN TROISIÈME AVEU, QUI NE SE LIT PAS DANS LE CORPS SEUL : une borne assortie d'un `OFFSET` et
    /// d'un `total` dans le corps est une PAGE D'UN TOUT CONNU. Le lecteur sait combien il y en a et
    /// par quel geste atteindre la suite ; la borne n'y cache rien. C'est le seul cas où `"total"`
    /// suffit, et il se reconnaît sur l'ÉNONCÉ, pas sur le nom d'une clé.
    fn avoue(corps: &str, sql: &str) -> bool {
        if AVEUX.iter().any(|a| corps.contains(a)) {
            return true;
        }
        // Le total d'une page peut n'être RENDU que par retour de fonction, sans jamais devenir une clé
        // dans ce corps-ci : on cherche donc la GRANDEUR, pas la clé. Ce que cette souplesse ne prouve
        // pas est écrit à la fin du bloc de propriété.
        contient_mot(sql, "offset") && contient_mot(corps, "total")
    }

    /// QUELLES FONCTIONS D'UN FICHIER SONT COUVERTES — par point fixe, et non sur un seul saut.
    ///
    /// UNE FONCTION EST COUVERTE si son corps porte un aveu, OU si elle a des appelants et que TOUS
    /// le sont. La récurrence n'est pas un raffinement gratuit : `P11.22-e` a fermé la liste des
    /// sources connues en posant l'aveu DEUX sauts plus haut (le lecteur borné rend un type qui porte
    /// le drapeau, un cache le relaie, la route l'écrit). Un seul saut accusait donc une route DÉJÀ
    /// HONNÊTE — et inscrire cette accusation au cliquet comme un « écart » aurait consigné un
    /// mensonge dans le témoin, en plus de laisser croire que la famille est plus large qu'elle n'est.
    ///
    /// UN APPELANT est reconnu par MENTION DU NOM (mot entier), pas par la seule forme `nom(` : une
    /// fonction PASSÉE en argument — c'est le cas ici — n'est jamais suivie d'une parenthèse.
    ///
    /// LE POINT FIXE PART DE FAUX et n'ajoute que ce qu'une chaîne d'appels ANCRE sur un aveu réel :
    /// un cycle de fonctions qui s'appellent sans jamais rien avouer ne s'auto-couvre donc pas.
    fn couvertes(d: &Depouille, fns: &[(String, usize, usize)]) -> Vec<bool> {
        let corps: Vec<String> = fns.iter().map(|(_, a, b)| corps_source(d, *a, *b)).collect();
        let mut couvre: Vec<bool> = corps.iter().map(|c| AVEUX.iter().any(|a| c.contains(a))).collect();
        for _ in 0..fns.len() {
            let mut bouge = false;
            for i in 0..fns.len() {
                if couvre[i] {
                    continue;
                }
                let appelants: Vec<usize> = (0..fns.len())
                    .filter(|&j| j != i && contient_mot(&corps[j], &fns[i].0))
                    .collect();
                if !appelants.is_empty() && appelants.iter().all(|&j| couvre[j]) {
                    couvre[i] = true;
                    bouge = true;
                }
            }
            if !bouge {
                break;
            }
        }
        couvre
    }

    /// La population et son verdict, pour UNE source.
    fn fenetres_dune_source(fichier: &str, src: &str) -> Vec<Fenetre> {
        let d = depouiller(src);
        let fns = fonctions(&d);
        let couvre = couvertes(&d, &fns);
        let mut out = Vec::new();
        for (pos, sql) in &d.litteraux {
            if !est_une_liste_bornee_servie(sql) {
                continue;
            }
            let englobante = fns
                .iter()
                .enumerate()
                .filter(|(_, (_, a, b))| *a <= *pos && *pos <= *b)
                .min_by_key(|(_, (_, a, b))| b - a);
            let (nom, corps, idx) = match englobante {
                Some((i, (n, a, b))) => (n.clone(), corps_source(&d, *a, *b), Some(i)),
                None => (String::from("(hors fonction)"), String::new(), None),
            };
            // L'aveu par OFFSET + `total` se lit sur l'ÉNONCÉ, donc il reste au site ; la couverture
            // par la chaîne d'appels, elle, est déjà établie.
            let aveu = idx.map(|i| couvre[i]).unwrap_or(false) || avoue(&corps, sql);
            out.push(Fenetre {
                fichier: fichier.to_string(),
                table: jeton_apres(sql, "from").unwrap_or_else(|| String::from("?")),
                fonction: nom,
                groupe: contient_mot(sql, "group"),
                avoue: aveu,
            });
        }
        out
    }

    /// Les sources de PRODUCTION servies à la console : `src/handlers/`, récursivement.
    fn sources_des_handlers() -> Vec<(String, String)> {
        let racine = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/handlers");
        let mut piles = vec![racine];
        let mut out = Vec::new();
        while let Some(d) = piles.pop() {
            for e in std::fs::read_dir(&d).expect("le répertoire des handlers est lisible") {
                let p = e.expect("entrée lisible").path();
                if p.is_dir() {
                    piles.push(p);
                } else if p.extension().map(|x| x == "rs").unwrap_or(false) {
                    let nom = p.file_name().unwrap().to_string_lossy().into_owned();
                    out.push((nom, std::fs::read_to_string(&p).expect("source lisible")));
                }
            }
        }
        out.sort();
        out
    }

    #[test]
    fn une_liste_bornee_servie_dit_ce_qu_elle_borne() {
        // --- VALIDATION DE L'INSTRUMENT, DANS LES DEUX SENS. Une lecture qui ne verrait rien rendrait
        // vert sur un arbre fautif ; une lecture qui verrait tout ferait rougir sur du code sain.
        let corpus_vu = [
            "fn liste() -> Value { let _ = \"SELECT a,b FROM registre ORDER BY id DESC LIMIT 100\"; json!({}) }",
            "fn liste() -> Value { let _ = format!(\"SELECT a FROM registre ORDER BY id DESC LIMIT {N}\"); json!({}) }",
            // ÉLARGISSEMENT `P11.22-f` — les trois formes que l'ancien prédicat laissait sortir.
            "fn liste() -> Value { let _ = \"SELECT a FROM registre WHERE b=?1 ORDER BY id DESC LIMIT 500\"; json!({}) }",
            "fn liste() -> Value { let _ = \"SELECT a, COUNT(*) n FROM registre WHERE b=?1 GROUP BY a ORDER BY n DESC LIMIT 50\"; json!({}) }",
            "fn liste() -> Value { let _ = \"SELECT DISTINCT a FROM registre ORDER BY a LIMIT ?1\"; json!({}) }",
            // Une borne de sous-requête corrélée à 1 ne doit pas masquer la borne de la liste servie.
            "fn liste() -> Value { let _ = \"SELECT a,(SELECT x FROM t WHERE t.a=r.a LIMIT 1) FROM registre r ORDER BY a LIMIT 200\"; json!({}) }",
        ];
        for src in corpus_vu {
            let f = fenetres_dune_source("temoin.rs", src);
            assert_eq!(f.len(), 1, "(instrument) une fenêtre de récence n'est pas VUE : {src}");
            assert!(!f[0].avoue, "(instrument) une fenêtre sans aveu est comptée couverte : {src}");
        }
        let corpus_ignore = [
            // singleton, pas une liste.
            "fn t() { let _ = \"SELECT hash FROM registre ORDER BY id DESC LIMIT 1\"; }",
            // ÉCRITURE : la borne y est un lot de travail qui se draine par répétition.
            "fn t() { let _ = \"DELETE FROM registre WHERE rowid IN (SELECT rowid FROM registre ORDER BY ts LIMIT 500)\"; }",
            // LE COMPTAGE BORNÉ lui-même : c'est l'instrument de l'aveu, pas une liste servie.
            "fn t() { let _ = \"SELECT COUNT(*) FROM (SELECT 1 FROM registre LIMIT 10001)\"; }",
            // la forme, écrite dans un COMMENTAIRE, ne compte pas.
            "fn t() { /* SELECT a FROM registre ORDER BY id DESC LIMIT 100 */ }",
        ];
        for src in corpus_ignore {
            assert!(
                fenetres_dune_source("temoin.rs", src).is_empty(),
                "(instrument) une forme HORS population est comptée : {src}"
            );
        }
        let corpus_couvert = [
            "fn liste() -> Value { let _ = \"SELECT a FROM registre ORDER BY id DESC LIMIT 100\"; json!({\"total_capped\": false}) }",
            "fn fab_sql() -> String { String::from(\"SELECT a FROM registre ORDER BY id DESC LIMIT 100\") }\n\
             fn page() -> Value { let _ = fab_sql(); json!({\"n_capped\": false}) }",
            // PAGE D'UN TOUT CONNU : borne + `OFFSET` + `total` dans le corps.
            "fn page() -> Value { let _ = \"SELECT a FROM registre ORDER BY a LIMIT ?1 OFFSET ?2\"; json!({\"total\": 7}) }",
            // LE RALLIEMENT AU FABRICANT UNIQUE est un aveu : la forme n'est plus écrite sur place.
            "fn page() -> Value { let _ = \"SELECT a FROM registre ORDER BY a LIMIT 100\"; aveu::corps(\"a\", l, 100, t) }",
        ];
        for src in corpus_couvert {
            let f = fenetres_dune_source("temoin.rs", src);
            assert_eq!(f.len(), 1, "(instrument) la liste n'est plus vue une fois couverte : {src}");
            assert!(f[0].avoue, "(instrument) un aveu — direct ou par l'appelant — n'est pas reconnu : {src}");
        }

        // --- LE PIÈGE D'INSTRUMENT DE `P11.22-c`, DÉSORMAIS FERMÉ PAR CONSTRUCTION. Décrire un site
        // dans un commentaire — jusqu'à y écrire le nom du geste commun — ne doit RIEN déclarer.
        let piege = "fn page() -> Value { let _ = \"SELECT a FROM registre ORDER BY a LIMIT 100\"; \
                     // on ne rallie PAS ce site au fabricant aveu::corps( ici, et voici pourquoi\n \
                     json!({}) }";
        let f = fenetres_dune_source("temoin.rs", piege);
        assert_eq!(f.len(), 1, "(instrument) la liste décrite en commentaire n'est plus vue");
        assert!(
            !f[0].avoue,
            "(instrument) UN COMMENTAIRE DÉCLARE UN RALLIEMENT INEXISTANT — c'est le piège que `P11.22-c` \
             a payé ; le corps doit être lu privé de ses commentaires et de rien d'autre"
        );
        // …et le littéral, lui, reste lu : sans quoi l'aveu (qui EST un littéral) disparaîtrait aussi.
        let litteral = "fn page() -> Value { let _ = \"SELECT a FROM registre ORDER BY a LIMIT 100\"; json!({\"total_capped\": false}) }";
        assert!(
            fenetres_dune_source("temoin.rs", litteral)[0].avoue,
            "(instrument) le dépouillement des commentaires a emporté les littéraux : l'aveu n'est plus vu"
        );
        // Le masque : une accolade de gabarit ne doit pas déséquilibrer un corps de fonction, sinon la
        // fonction englobante serait fausse et l'aveu cherché au mauvais endroit.
        let d = depouiller("fn page() -> Value { let s = format!(\"… LIMIT {n}\"); json!({\"total\": 1}) }");
        assert_eq!(fonctions(&d).len(), 1, "(instrument) l'appariement d'accolades est mangé par un gabarit de format");

        // --- L'ARBRE RÉEL.
        let mut population: Vec<Fenetre> = Vec::new();
        for (nom, src) in sources_des_handlers() {
            population.extend(fenetres_dune_source(&nom, &src));
        }
        assert!(
            population.len() >= 25,
            "(instrument) {} liste(s) bornée(s) vue(s) dans src/handlers/ : la lecture est cassée, \
             la garde refuse de conclure vert (le recensement du 2026-08-30 en voyait plus de trente)",
            population.len()
        );

        // TÉMOINS POSITIFS SUR L'ARBRE — DEUX, ET LE SECOND EST CE QUE L'ÉLARGISSEMENT A ACHETÉ. Sans
        // eux, une correction qui retirerait un énoncé de la population rendrait vert sans rien prouver.
        let action = population.iter().find(|f| f.table == "action");
        assert!(
            action.is_some(),
            "la fenêtre de la file de riposte n'est plus vue par la garde — le critère ne couvre plus le \
             défaut qu'il a été écrit pour tenir"
        );
        assert!(action.unwrap().avoue, "la file de riposte est servie SANS aveu de sa borne");

        // La ventilation par source du magasin d'indicateurs : `GROUP BY` + `WHERE`, donc INVISIBLE au
        // prédicat d'avant. C'est le site le plus grave du lot, et sa présence ici est la preuve que
        // l'élargissement porte — pas seulement que la garde reste verte.
        // L'ANCRE EST POSÉE SUR L'ÉNONCÉ, PAS SUR UN NOM. La ventilation par source du magasin
        // d'indicateurs est un `SELECT … FROM ioc WHERE … GROUP BY … LIMIT …` : filtre ET agrégat,
        // c'est-à-dire DEUX des exclusions du prédicat étroit à la fois. Un `GROUP BY` dans la
        // population est donc la signature de l'élargissement lui-même.
        //
        // POURQUOI PAS LE NOM DE LA FONCTION : il l'a été le temps d'un brouillon, et la campagne de
        // mutation de ce lot l'a pris en défaut — la fonction avait été renommée en extrayant le corps
        // pur, l'ancre ne désignait plus rien, et elle rendait VERT. Une ancre qui suit un renommage
        // sans rougir ne tient rien.
        assert!(
            population.iter().any(|f| f.groupe),
            "aucun énoncé à `GROUP BY` dans la population : l'élargissement de `P11.22-f` a été perdu, \
             et avec lui la forme du site le plus grave du recensement"
        );
        let ventilation: Vec<&Fenetre> = population.iter().filter(|f| f.table == "ioc" && f.groupe).collect();
        assert_eq!(
            ventilation.len(),
            1,
            "la ventilation par source du magasin d'indicateurs n'est plus vue une fois et une seule \
             par la garde (vue {} fois)",
            ventilation.len()
        );
        assert!(
            ventilation[0].avoue,
            "la ventilation par source est servie SANS dire qu'elle est coupée — posée à côté d'un total \
             du magasin ENTIER, elle se lit comme une COUVERTURE"
        );

        // VERDICT + CLIQUET.
        let muettes: Vec<&Fenetre> = population.iter().filter(|f| !f.avoue).collect();
        let connu = |f: &Fenetre| ECARTS_CONNUS.iter().any(|(fi, fo, _)| *fi == f.fichier && *fo == f.fonction);
        let inconnues: Vec<String> = muettes
            .iter()
            .filter(|f| !connu(f))
            .map(|f| format!("{} :: {} (table `{}`)", f.fichier, f.fonction, f.table))
            .collect();
        assert!(
            inconnues.is_empty(),
            "{} liste(s) bornée(s) servie(s) SANS aveu de leur borne : {} — ralliez-les au fabricant \
             unique (`handlers::liste_bornee`), rendez un curseur, ou inscrivez l'écart avec sa raison.",
            inconnues.len(),
            inconnues.join(" ; ")
        );
        let refermes: Vec<String> = ECARTS_CONNUS
            .iter()
            .filter(|(fi, fo, _)| !muettes.iter().any(|f| f.fichier == *fi && f.fonction == *fo))
            .map(|(fi, fo, _)| format!("{fi} :: {fo}"))
            .collect();
        assert!(
            refermes.is_empty(),
            "écart(s) du cliquet qui ne sont plus des écarts : {} — le cliquet ne remonte pas, retirez-les \
             de `ECARTS_CONNUS`",
            refermes.join(", ")
        );
    }
}
