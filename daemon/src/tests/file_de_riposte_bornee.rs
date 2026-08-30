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
    // ④ GARDE DÉRIVÉE — UNE FENÊTRE DE RÉCENCE DIT CE QU'ELLE BORNE
    // ---------------------------------------------------------------------------------------------
    // LA PROPRIÉTÉ, ÉCRITE UNE FOIS ET ANCRÉE SUR LA FORME DU CODE, JAMAIS SUR UN NOM DE FICHIER NI DE
    // MODULE (ce dépôt a déjà payé une garde aveugle parce qu'elle nommait un fichier — `P11.13-d`) :
    //
    //     Un énoncé de lecture qui prend les N dernières lignes d'une TABLE ENTIÈRE est une FENÊTRE DE
    //     RÉCENCE : la borne n'y est pas la réponse à une question, c'est une TRONCATURE d'un registre
    //     qui grossit. Le chemin qui l'émet doit donc rendre, à côté des lignes, de quoi savoir ce qui
    //     manque — un TOTAL, ou un CURSEUR.
    //
    // POPULATION, DÉRIVÉE DE CE QUE LE CODE EST. Tout littéral de chaîne des sources de production de
    // `src/handlers/` qui, commentaires dépouillés :
    //   (a) SELECTionne DEPUIS une table, et ne porte AUCUN `WHERE` — c'est ce qui en fait une fenêtre
    //       sur un registre ENTIER plutôt qu'une réponse à une question posée ;
    //   (b) ne porte NI agrégat NI `GROUP BY` NI `DISTINCT` — sans quoi la borne est le « top N »
    //       DEMANDÉ, donc la réponse elle-même, et non une troncature ;
    //   (c) porte un `ORDER BY` (une fenêtre suppose un ordre) ;
    //   (d) porte `LIMIT <n≥2>` ou `LIMIT {…}` — la borne écrite en clair OU posée par un gabarit de
    //       format, parce qu'une garde qui ne verrait que le chiffre littéral s'aveuglerait le jour où
    //       la borne devient une constante nommée. `LIMIT 1` est exclu : c'est un singleton, pas une
    //       liste.
    //
    // VERDICT. La fonction qui porte l'énoncé, OU l'une de celles qui l'APPELLENT dans le même fichier,
    // doit porter un aveu : la clé `"total"`, la clé `"next_cursor"`, la clé `"has_more"`, ou l'appel au
    // finaliseur de curseur partagé. Le détour par les appelants n'est pas une commodité : un fabricant
    // d'énoncé PUR (`…_sql`) est la bonne architecture — c'est celle de `/api/query` et celle que ce lot
    // pose — et il ne peut par construction rendre aucune réponse.
    //
    // CE QUE CETTE GARDE NE PROUVE PAS, dit pour qu'on ne s'en réclame pas trop : qu'un total soit rendu
    // sur TOUS les chemins qui traversent un fabricant partagé — elle exige qu'au moins un chemin
    // l'atteigne. Elle ne lit pas non plus le SQL composé morceau par morceau hors d'un seul littéral.
    // =============================================================================================

    /// LES ÉCARTS CONNUS — MÊME FAMILLE, PAS DANS CE LOT. Chacun est nommé par la TABLE qu'il fenêtre
    /// (une propriété de l'énoncé), pas par un fichier, et avec ce qui manque. Le cliquet ne remonte
    /// pas : un écart fermé DOIT sortir de cette liste, sinon le test rougit et le dit.
    ///
    /// RELEVÉ LE 2026-08-25 : trois écarts — `engagement`, `risk_rollup`, `ioc`. TOUS TROIS FERMÉS LE
    /// MÊME JOUR par `P11.17-f`, et donc retirés d'ici : la liste est VIDE, et le cliquet est à zéro.
    /// Toute fenêtre de récence servie sans total ni curseur fait désormais rougir la garde par son
    /// seul nom de table, sans qu'aucune inscription ne soit possible sans une raison écrite ici.
    /// Ce que chacune a reçu est écrit dans son propre module ; le TOTAL BORNÉ (le motif de
    /// `PAGINATION_COUNT_CAP`) là où la borne était une troncature, et la DÉCLARATION DE LA COUPE là
    /// où elle était délibérée — le classement par score de `risk_rollup`, qui répond à la question
    /// posée au lieu de tronquer un registre.
    const ECARTS_CONNUS: &[(&str, &str)] = &[];

    /// Un énoncé de la population, tel que la garde le voit.
    #[derive(Debug)]
    struct Fenetre {
        fichier: String,
        table: String,
        fonction: String,
        avoue: bool,
    }

    /// LE DÉPOUILLEMENT — commentaires retirés, littéraux relevés, et un MASQUE de même longueur (en
    /// caractères) où le contenu des chaînes et des commentaires est remplacé par des espaces. Le masque
    /// sert à apparier les accolades : une accolade de gabarit (`LIMIT {n}`) ne doit pas déséquilibrer
    /// le corps d'une fonction, et un `//` dans une chaîne ne doit pas manger la ligne.
    struct Depouille {
        masque: Vec<char>,
        source: Vec<char>,
        litteraux: Vec<(usize, String)>,
    }

    fn depouiller(src: &str) -> Depouille {
        let s: Vec<char> = src.chars().collect();
        let mut masque = s.clone();
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
                    i = j;
                }
                '/' if i + 1 < s.len() && s[i + 1] == '*' => {
                    let mut j = i + 2;
                    while j + 1 < s.len() && !(s[j] == '*' && s[j + 1] == '/') {
                        j += 1;
                    }
                    let fin = (j + 2).min(s.len());
                    effacer(&mut masque, i, fin);
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
        Depouille { masque, source: s, litteraux }
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
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '{' || *c == '}')
            .collect();
        if t.is_empty() {
            None
        } else {
            Some(t)
        }
    }

    /// Une fenêtre de récence, au sens de la propriété écrite ci-dessus.
    ///
    /// SON CLIQUET EST À ZÉRO, ET CE ZÉRO NE VEUT PAS DIRE « IL N'EN RESTE PLUS » — mesuré le
    /// 2026-08-30. Ce prédicat écarte délibérément `where`, `distinct`, les agrégats et les bornes
    /// bâties par assemblage de texte, et il exige un tri. Sa PROPRIÉTÉ est donc STRICTEMENT PLUS
    /// ÉTROITE que la classe de défaut « une liste bornée ne dit pas s'il y en avait davantage » :
    /// VINGT sites sur QUINZE routes portent cette classe, et cette garde est VERTE sur les vingt.
    /// Elle n'est pas cassée ; elle mesure autre chose. Mais un zéro se LIT comme une couverture,
    /// et c'est ce qui rend la confusion coûteuse — un lecteur en conclut que la famille est fermée.
    /// La classe entière est ouverte sous `P11.22-f`, avec la forme commune qui la tiendrait ; tant
    /// qu'elle n'est pas écrite, ce zéro dit « aucune FENÊTRE DE RÉCENCE muette », jamais « aucune
    /// liste bornée muette ».
    fn est_une_fenetre_de_recence(sql: &str) -> bool {
        if !contient_mot(sql, "select") || !contient_mot(sql, "from") {
            return false;
        }
        if contient_mot(sql, "where") || contient_mot(sql, "distinct") {
            return false;
        }
        if contient_mot(sql, "group") {
            return false;
        }
        for agg in ["count(", "sum(", "avg(", "min(", "max("] {
            if sql.to_ascii_lowercase().contains(agg) {
                return false;
            }
        }
        if !(contient_mot(sql, "order") && contient_mot(sql, "by")) {
            return false;
        }
        match jeton_apres(sql, "limit") {
            None => false,
            Some(b) if b.starts_with('{') => true,
            Some(b) => b.parse::<i64>().map(|n| n >= 2).unwrap_or(false),
        }
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

    /// Le corps d'une fonction, lu dans la SOURCE (les littéraux y sont visibles : c'est là que vit l'aveu).
    fn corps_source(d: &Depouille, a: usize, b: usize) -> String {
        d.source[a..b.min(d.source.len())].iter().collect()
    }

    const AVEUX: &[&str] = &["\"total\"", "\"next_cursor\"", "\"has_more\"", "keyset_finalize"];

    fn avoue(corps: &str) -> bool {
        AVEUX.iter().any(|a| corps.contains(a))
    }

    /// La population et son verdict, pour UNE source.
    fn fenetres_dune_source(fichier: &str, src: &str) -> Vec<Fenetre> {
        let d = depouiller(src);
        let fns = fonctions(&d);
        let mut out = Vec::new();
        for (pos, sql) in &d.litteraux {
            if !est_une_fenetre_de_recence(sql) {
                continue;
            }
            let englobante = fns
                .iter()
                .filter(|(_, a, b)| *a <= *pos && *pos <= *b)
                .min_by_key(|(_, a, b)| b - a);
            let (nom, corps) = match englobante {
                Some((n, a, b)) => (n.clone(), corps_source(&d, *a, *b)),
                None => (String::from("(hors fonction)"), String::new()),
            };
            let mut aveu = avoue(&corps);
            if !aveu && !nom.starts_with('(') {
                // Un fabricant PUR est couvert par ses appelants : un `…_sql` ne rend aucune réponse.
                let appelants: Vec<&(String, usize, usize)> = fns
                    .iter()
                    .filter(|(n, a, b)| *n != nom && corps_source(&d, *a, *b).contains(&format!("{nom}(")))
                    .collect();
                aveu = !appelants.is_empty()
                    && appelants.iter().all(|(_, a, b)| avoue(&corps_source(&d, *a, *b)));
            }
            out.push(Fenetre {
                fichier: fichier.to_string(),
                table: jeton_apres(sql, "from").unwrap_or_else(|| String::from("?")),
                fonction: nom,
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
    fn une_fenetre_de_recence_dit_ce_qu_elle_borne() {
        // --- VALIDATION DE L'INSTRUMENT, DANS LES DEUX SENS. Une lecture qui ne verrait rien rendrait
        // vert sur un arbre fautif ; une lecture qui verrait tout ferait rougir sur du code sain.
        let corpus_vu = [
            "fn liste() -> Value { let _ = \"SELECT a,b FROM registre ORDER BY id DESC LIMIT 100\"; json!({}) }",
            "fn liste() -> Value { let _ = format!(\"SELECT a FROM registre ORDER BY id DESC LIMIT {N}\"); json!({}) }",
        ];
        for src in corpus_vu {
            let f = fenetres_dune_source("temoin.rs", src);
            assert_eq!(f.len(), 1, "(instrument) une fenêtre de récence n'est pas VUE : {src}");
            assert!(!f[0].avoue, "(instrument) une fenêtre sans aveu est comptée couverte : {src}");
        }
        let corpus_ignore = [
            // borne = la réponse (top N demandé) ou question posée : hors population.
            "fn t() { let _ = \"SELECT a, COUNT(*) n FROM registre GROUP BY a ORDER BY n DESC LIMIT 20\"; }",
            "fn t() { let _ = \"SELECT a FROM registre WHERE b=?1 ORDER BY id DESC LIMIT 100\"; }",
            "fn t() { let _ = \"SELECT DISTINCT a FROM registre ORDER BY a LIMIT 5000\"; }",
            // singleton, pas une liste.
            "fn t() { let _ = \"SELECT hash FROM registre ORDER BY id DESC LIMIT 1\"; }",
            // pas d'ordre : ce n'est pas une fenêtre de récence.
            "fn t() { let _ = \"SELECT a FROM registre LIMIT 100\"; }",
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
            "fn liste() -> Value { let _ = \"SELECT a FROM registre ORDER BY id DESC LIMIT 100\"; json!({\"total\": 1}) }",
            "fn fab_sql() -> String { String::from(\"SELECT a FROM registre ORDER BY id DESC LIMIT 100\") }\n\
             fn page() -> Value { let _ = fab_sql(); json!({\"total\": 1}) }",
        ];
        for src in corpus_couvert {
            let f = fenetres_dune_source("temoin.rs", src);
            assert_eq!(f.len(), 1, "(instrument) la fenêtre n'est plus vue une fois couverte : {src}");
            assert!(f[0].avoue, "(instrument) un aveu — direct ou par l'appelant — n'est pas reconnu : {src}");
        }
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
            population.len() >= 4,
            "(instrument) {} fenêtre(s) de récence vue(s) dans src/handlers/ : la lecture est cassée, \
             la garde refuse de conclure vert",
            population.len()
        );

        // TÉMOIN POSITIF SUR L'ARBRE : la file de riposte est DANS la population, et elle avoue. Sans
        // cette exigence, une correction qui retirerait l'énoncé de la population rendrait vert sans rien
        // prouver.
        let action = population.iter().find(|f| f.table == "action");
        assert!(
            action.is_some(),
            "la fenêtre de la file de riposte n'est plus vue par la garde — le critère ne couvre plus le \
             défaut qu'il a été écrit pour tenir"
        );
        assert!(action.unwrap().avoue, "la file de riposte est servie SANS total ni curseur");

        // VERDICT + CLIQUET.
        let muettes: Vec<&Fenetre> = population.iter().filter(|f| !f.avoue).collect();
        let inconnues: Vec<String> = muettes
            .iter()
            .filter(|f| !ECARTS_CONNUS.iter().any(|(t, _)| *t == f.table))
            .map(|f| format!("{} :: {} (table `{}`)", f.fichier, f.fonction, f.table))
            .collect();
        assert!(
            inconnues.is_empty(),
            "{} fenêtre(s) de récence servie(s) SANS total ni curseur : {} — rendez un total borné \
             (le motif de `PAGINATION_COUNT_CAP`) ou un curseur, ou inscrivez l'écart avec sa raison.",
            inconnues.len(),
            inconnues.join(" ; ")
        );
        let refermes: Vec<&str> = ECARTS_CONNUS
            .iter()
            .filter(|(t, _)| !muettes.iter().any(|f| f.table == *t))
            .map(|(t, _)| *t)
            .collect();
        assert!(
            refermes.is_empty(),
            "écart(s) du cliquet qui ne sont plus des écarts : {} — le cliquet ne remonte pas, retirez-les \
             de `ECARTS_CONNUS`",
            refermes.join(", ")
        );
    }
}
