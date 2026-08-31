// ================================================================================================
// P6.8-d — LES INDEX DE CHAMP CHAUD SE CONSTATENT AU CATALOGUE, ILS NE SE DÉDUISENT PAS DE LEUR
// DÉCLARATION
// ================================================================================================
// LE DÉFAUT, DANS SA FORME EXACTE. `P6.8-c` a fait entrer deux champs de plus dans la liste chaude en
// tenant pour acquis que les index correspondants naîtraient. Une déclaration d'index et un index créé
// sont deux choses : entre les deux il y a une chaîne de migrations, un réconciliateur synchrone et une
// tâche de fond, dont aucune n'était CONSTATÉE sur une base réelle. Le seul contrôle qui touchait à cette
// famille (`reconcile_expr_index_off_drops_indexes`, rbac.rs) ÉNUMÉRAIT UN SEUL NOM écrit à la main —
// il aurait rendu vert sur les onze autres, et un treizième champ ajouté demain ne ferait rougir personne.
//
// CE QUE CE FICHIER N'EST PAS : une liste de douze noms. Une liste aurait attrapé les douze index
// d'aujourd'hui et RIEN d'autre. Ici l'attente est CONSTRUITE à partir de `HOT_FIELDS` — la déclaration
// unique, celle dont `EXPR_INDEX_FIELDS` (maintenance.rs) est un ALIAS et non une copie — et de la seule
// règle de nommage que le produit applique. Aucun nom de champ, aucun nom d'index n'est écrit ici.
//
// LE PIÈGE QUI REND UNE TELLE GARDE VIDE, ET COMMENT IL EST ÉVITÉ. Comparer une liste dérivée de
// `HOT_FIELDS` à une autre liste dérivée de `HOT_FIELDS` ne prouve RIEN : c'est comparer une chose à
// elle-même, et cela resterait vert avec un réconciliateur entièrement démonté. LE SEUL CÔTÉ QUI COMPTE
// EST LE CATALOGUE DE LA BASE. `famille_au_schema` interroge `sqlite_master` sur une base construite par
// le VRAI chemin de démarrage — `db/schema.sql`, toute la chaîne de migrations, puis les deux étapes que
// `server/mod.rs` et `server/travaux_sur_la_base.rs` exécutent au boot : le réconciliateur synchrone puis
// la tâche de fond qui CRÉE. Rien de ce que ce fichier lit ne vient d'une structure du code.
//
// LES DEUX SENS DU LEVIER, ET POURQUOI LES DEUX SONT EXIGÉS. La famille est gouvernée par
// `PLUME_EXPRINDEX` (défaut : armé). Une garde qui n'énoncerait que « les index existent » rougirait à
// tort chez qui a éteint le levier, et serait désarmée dans la semaine. Sous levier ÉTEINT, l'attente
// n'est pas « rien à dire » : c'est « AUCUN de la famille n'existe » — le kill-switch est une promesse
// aussi ferme que la création. Le régime n'est pas supposé : il est LU par la voie du produit
// (`cfg(&load_config(), …)`, la même précédence env > fichier > défaut), et il est NOMMÉ dans chaque
// verdict pour qu'un rouge dise sous quel régime il tombe.
//
// LA RÉCIPROQUE, ET CE QU'ELLE A DÉCOUVERT. Exiger que chaque champ déclaré ait son index ne suffit
// pas : le réconciliateur ne sait dropper QUE les noms qu'il dérive de la liste. Un index de la famille
// dont le champ a quitté la déclaration n'était donc retiré par personne — ni par le kill-switch, ni par
// la purge de fond, qui ne connaît que la famille `idx_ev_auto_*` (cf. autoindex_retire.rs) : il restait
// sur une base vivante, payé en disque et en écriture btree à chaque ligne ingérée. C'est le constat que
// la clé `P6.8-e` a ouvert, puis fermé par `drop_orphan_expr_field_indexes`, dont le critère est le
// PRÉFIXE de la famille et non la liste des champs (cf. index_de_champ_chaud_orphelin.rs).
//
// CE QUE LE TROISIÈME TEST DIT AUJOURD'HUI, ET POURQUOI IL RESTE. L'inclusion inverse garde tout son
// objet : un orphelin ne doit pas s'INTRODUIRE en silence. Et la seconde moitié du test énonce une
// limite qui n'a pas bougé — le KILL-SWITCH SYNCHRONE, lui, ne sait toujours pas nommer cet index : ce
// n'est pas lui qui le retire, c'est la passe de FOND. Le geste qui répare vit ailleurs que le geste qui
// éteint, et c'est exactement ce qui rendait l'orphelin permanent avant `P6.8-e`.
//
// AUCUN ÉTAT DE PROCESSUS N'EST ÉCRIT ICI. Le régime est lu, jamais posé : `cle_at_rest_voie_unique.rs`
// a mesuré ce que coûte un test qui pose une variable d'environnement — deux tests d'incidents sans
// rapport rendus rouges parce que la configuration ambiante est partagée par TOUS ceux qui ouvrent une
// base. Le sens ÉTEINT est donc obtenu en passant la configuration EN ARGUMENT à `reconcile_index_state`,
// qui l'accepte, et le test dit ce qu'il exige de l'environnement au lieu de le modifier.

#[cfg(test)]
mod index_de_champ_chaud {
    use crate::maintenance::{reconcile_expr_indexes_background, reconcile_index_state};
    use crate::soql_glue::HOT_FIELDS;
    use parking_lot::Mutex;
    use rusqlite::Connection;
    use std::collections::{BTreeSet, HashMap};
    use std::sync::Arc;

    /// LA RÈGLE DE NOMMAGE — le préfixe de la famille, écrit UNE fois. Ce n'est pas un nom d'index :
    /// c'est la règle dont le produit dérive les siens. Elle est CONFRONTÉE à celle du réconciliateur
    /// par `la_regle_de_nommage_est_encore_celle_du_produit` : renommer la famille dans le produit sans
    /// toucher ici ne rend pas cette garde verte-et-aveugle, il la rend rouge.
    const PREFIXE_FAMILLE: &str = "idx_ev_f_";

    /// Le fichier du réconciliateur, tel que la garde anti-faux-vert le relit.
    const FICHIER_RECONCILIATEUR: &str = "maintenance.rs";

    /// Le levier qui gouverne la famille, et sa valeur par défaut — les deux tels que le produit les
    /// écrit (`maintenance.rs`, `cfg(conf, "PLUME_EXPRINDEX", "1")`).
    const LEVIER: &str = "PLUME_EXPRINDEX";
    const LEVIER_DEFAUT: &str = "1";

    /// Le nom que le produit donnera à l'index d'un champ. Dérivé, jamais recopié.
    fn nom_derive(champ: &str) -> String {
        format!("{PREFIXE_FAMILLE}{champ}")
    }

    /// L'ATTENTE, construite à partir de la déclaration seule.
    fn attendus() -> BTreeSet<String> {
        HOT_FIELDS.iter().map(|c| nom_derive(c)).collect()
    }

    /// CE QUE LA BASE DIT D'ELLE-MÊME. Les index de la famille présents au catalogue — pas ceux que le
    /// code déclare. Le motif `LIKE` est construit à partir du préfixe, avec ses `_` ÉCHAPPÉS : sans
    /// échappement ils seraient des jokers et la garde attraperait des noms voisins.
    fn famille_au_schema(conn: &Connection) -> BTreeSet<String> {
        let motif = format!("{}%", PREFIXE_FAMILLE.replace('_', "\\_"));
        let mut st = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE ?1 ESCAPE '\\' ORDER BY name",
            )
            .expect("catalogue des index lisible");
        let it = st
            .query_map(rusqlite::params![motif], |r| r.get::<_, String>(0))
            .expect("catalogue des index lisible");
        it.map(|r| r.expect("nom d'index lisible")).collect()
    }

    /// LE RÉGIME COURANT, LU PAR LA VOIE DU PRODUIT (env > fichier `PLUME_CONFIG` > défaut). On ne
    /// suppose pas que le levier est armé : on demande la même réponse que celle que le réconciliateur
    /// obtiendra.
    fn levier_arme() -> bool {
        crate::cfg(&crate::load_config(), LEVIER, LEVIER_DEFAUT) == LEVIER_DEFAUT
    }

    /// Le mot du régime, pour que chaque verdict dise sous lequel il tombe.
    fn regime() -> &'static str {
        if levier_arme() {
            "ARMÉ"
        } else {
            "ÉTEINT"
        }
    }

    /// LA BASE APRÈS DÉMARRAGE — le chemin réel, dans l'ordre réel :
    ///   1. `db/schema.sql` + TOUTE la chaîne de migrations (`super::test_db`, la fixture partagée) ;
    ///   2. `reconcile_index_state` — l'étape SYNCHRONE du boot (`server/mod.rs`, après `migrate`,
    ///      avant le bind) : DDL pur, elle ne crée rien quand le levier est armé ;
    ///   3. `reconcile_expr_indexes_background` — l'étape de FOND (`server/travaux_sur_la_base.rs`,
    ///      après le bind), la SEULE qui exécute les `CREATE INDEX`.
    /// La configuration passée au point 2 est celle que le boot construit (`load_config`), pas une
    /// configuration de test : le régime mesuré est celui sous lequel la suite tourne réellement.
    fn base_apres_demarrage() -> Arc<Mutex<Connection>> {
        let conn = super::test_db();
        reconcile_index_state(&conn, &crate::load_config());
        let db = Arc::new(Mutex::new(conn));
        reconcile_expr_indexes_background(&db);
        db
    }

    /// UN CHAMP QUE LA DÉCLARATION NE PEUT PAS PRODUIRE, CONSTRUIT À PARTIR D'ELLE. La concaténation de
    /// toutes les entrées n'est aucune d'elles — la propriété est ASSERTÉE, pas espérée. Aucun nom
    /// inventé n'est donc écrit dans ce fichier, pas même celui du témoin négatif.
    fn champ_hors_declaration() -> String {
        let concat = HOT_FIELDS.concat();
        assert!(
            !HOT_FIELDS.contains(&concat.as_str()),
            "prémisse du témoin négatif : la concaténation de la liste chaude ne doit pas être elle-même \
             une entrée de la liste (sinon l'orphelin fabriqué serait un index légitime)"
        );
        concat
    }

    /// Le texte du réconciliateur — lu, jamais deviné.
    fn source_du_reconciliateur() -> String {
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(FICHIER_RECONCILIATEUR),
        )
        .unwrap_or_else(|e| panic!("{FICHIER_RECONCILIATEUR} lisible : {e}"))
    }

    // ============================================================================================

    /// ANTI-FAUX-VERT — LA RÈGLE DE NOMMAGE UTILISÉE ICI EST ENCORE CELLE DU PRODUIT.
    ///
    /// Toute la garde repose sur une dérivation : « le produit nomme `<préfixe><champ>` ». Si le produit
    /// renommait sa famille, `famille_au_schema` ne verrait plus RIEN, l'ensemble attendu ne serait plus
    /// jamais trouvé — et sous levier éteint la garde deviendrait même trivialement verte. On vérifie donc
    /// que les DEUX gestes du réconciliateur (celui qui crée, celui qui droppe) construisent encore leur
    /// nom par ce préfixe suivi du champ. C'est la seule chose que ce test lit dans la source ; tout le
    /// reste de ce fichier lit le catalogue.
    #[test]
    fn la_regle_de_nommage_est_encore_celle_du_produit() {
        let source = source_du_reconciliateur();

        let creation = format!("CREATE INDEX IF NOT EXISTS {PREFIXE_FAMILLE}{{c}} ON event(");
        assert!(
            source.contains(&creation),
            "LA RÈGLE DE NOMMAGE A CHANGÉ CÔTÉ PRODUIT : `{FICHIER_RECONCILIATEUR}` ne construit plus le \
             nom de l'index créé par `{creation}…`. La garde P6.8-d dériverait des noms que plus personne \
             ne crée : elle deviendrait verte en étant AVEUGLE sous levier éteint, et rouge sans raison \
             lisible sous levier armé. Aligner `PREFIXE_FAMILLE` sur la nouvelle règle."
        );

        let retrait = format!("DROP INDEX IF EXISTS {PREFIXE_FAMILLE}{{c}}");
        assert!(
            source.contains(&retrait),
            "LE KILL-SWITCH NE DÉRIVE PLUS SON NOM DE LA MÊME RÈGLE : `{FICHIER_RECONCILIATEUR}` ne \
             contient plus `{retrait}`. Créer et dropper sous deux règles de nommage différentes laisserait \
             des index que le levier ne retire plus."
        );

        // L'alias, et non une copie : c'est la propriété qui fait qu'ajouter un champ à la déclaration
        // SUFFIT. Une copie recréée ici passerait les deux tests de schéma le jour de sa création, puis
        // dériverait en silence.
        assert!(
            source.contains("= HOT_FIELDS;"),
            "LA LISTE DU RÉCONCILIATEUR N'EST PLUS UN ALIAS DE `HOT_FIELDS` : `{FICHIER_RECONCILIATEUR}` ne \
             porte plus `= HOT_FIELDS;`. Une seconde liste peut désormais diverger de la déclaration sans \
             qu'aucune assertion de compilation ne s'y oppose."
        );
    }

    /// LE CONSTAT, SUR LE CATALOGUE D'UNE BASE MIGRÉE — dans les DEUX sens du levier.
    ///
    /// Levier ARMÉ : chaque champ déclaré a son index AU SCHÉMA, et aucun index de la famille ne
    /// correspond à un champ non déclaré.
    /// Levier ÉTEINT : AUCUN index de la famille n'existe — le kill-switch est une promesse, pas une
    /// absence d'exigence.
    #[test]
    fn les_index_de_champ_chaud_sont_au_schema_de_la_base_migree() {
        // Un invariant vide est un invariant mort : une déclaration vidée rendrait les deux inclusions
        // trivialement vraies.
        assert!(
            !HOT_FIELDS.is_empty(),
            "prémisse : la déclaration des champs chauds est VIDE — la garde n'exigerait plus rien"
        );

        let attendus = attendus();
        let db = base_apres_demarrage();
        let vus = famille_au_schema(&db.lock());

        if levier_arme() {
            let manquants: Vec<&String> = attendus.difference(&vus).collect();
            assert!(
                manquants.is_empty(),
                "LEVIER {} — DES CHAMPS DÉCLARÉS N'ONT PAS D'INDEX AU SCHÉMA après `db/schema.sql` + toute \
                 la chaîne de migrations + le réconciliateur synchrone + la tâche de fond du boot. La \
                 déclaration promet un index d'expression par entrée de `HOT_FIELDS` ; le catalogue de la \
                 base ne les porte pas. Le compilateur GXQL, lui, continue de compiler ces champs comme \
                 chauds : leurs filtres dégénèrent de recherche en balayage, sans aucune erreur. \
                 Manquants : {manquants:?}. Attendus ({}) : {attendus:?}. Vus au schéma ({}) : {vus:?}",
                regime(),
                attendus.len(),
                vus.len()
            );

            let orphelins: Vec<&String> = vus.difference(&attendus).collect();
            assert!(
                orphelins.is_empty(),
                "LEVIER {} — DES INDEX DE LA FAMILLE NE CORRESPONDENT À AUCUN CHAMP DÉCLARÉ. Le \
                 réconciliateur ne sait dropper que les noms qu'il DÉRIVE de la liste : ceux-ci ne seront \
                 retirés par personne, ni par le kill-switch, ni par la purge de fond (qui ne connaît que \
                 la famille `idx_ev_auto_*`). Sur une base vivante ils sont payés en disque et en écriture \
                 btree à chaque ligne ingérée. Orphelins : {orphelins:?}",
                regime()
            );
        } else {
            assert!(
                vus.is_empty(),
                "LEVIER {} — LE KILL-SWITCH N'A PAS ÉTÉ APPLIQUÉ : des index de la famille subsistent au \
                 schéma alors que `{LEVIER}` n'est pas à `{LEVIER_DEFAUT}`. Éteindre le levier doit \
                 SUPPRIMER le coût (disque, insert btree), pas seulement cesser d'en créer. Restants : \
                 {vus:?}",
                regime()
            );
        }
    }

    /// LE SENS ÉTEINT, EXERCÉ — et exercé sur la liste ENTIÈRE, dérivée.
    ///
    /// Le contrôle qui existait avant cette clé créait UN index à la main et vérifiait qu'il disparaissait.
    /// Ici les index sont ceux que le PRODUIT a créés, et l'exigence porte sur tous : après le passage du
    /// réconciliateur avec le levier à l'arrêt, la famille est VIDE.
    ///
    /// Aucune variable d'environnement n'est posée : `reconcile_index_state` prend sa configuration en
    /// argument. La précédence du produit étant `env > fichier > défaut`, un levier posé dans
    /// l'environnement masquerait cette configuration — le test le CONSTATE et le dit, plutôt que de
    /// mesurer un autre régime sous ce nom ou d'écrire dans l'environnement du processus.
    #[test]
    fn le_levier_eteint_retire_exactement_les_index_derives() {
        let attendus = attendus();
        let db = base_apres_demarrage();
        let conn = db.lock();
        let avant = famille_au_schema(&conn);

        // RÉGIME AMBIANT ÉTEINT : la tâche de fond n'a rien créé, le retrait n'aurait rien à mordre. Le
        // sens reste tenu — il l'est par le boot lui-même, qui a droppé — et la garde ne rougit pas à tort.
        if !levier_arme() {
            assert!(
                avant.is_empty(),
                "LEVIER {} — la famille subsiste au schéma alors que le boot vient de passer avec le levier \
                 à l'arrêt : le kill-switch n'a pas été appliqué. Restants : {avant:?}",
                regime()
            );
            // `P11.23-b` — L'ASSERTION CI-DESSUS N'EST PAS LA PROMESSE DU TEST : elle tient « la
            // famille est absente », pas « le kill-switch RETIRE exactement les index dérivés ».
            // Rien n'a été créé, donc rien n'a été retiré : le retrait n'est pas éprouvé ici.
            crate::tests::canal_de_refus::refuser_de_conclure(
                module_path!(),
                "le_levier_eteint_retire_exactement_les_index_derives",
                &format!(
                    "levier `{LEVIER}` {} : la tâche de fond n'a créé aucun index dérivé, donc le \
                     RETRAIT n'a rien à mordre et n'est pas éprouvé. Seule l'absence de la famille \
                     vient d'être tenue. Rejouer la suite levier ARMÉ pour éprouver le retrait.",
                    regime()
                ),
            );
            return;
        }

        // Prémisse du sens éteint : il faut quelque chose à retirer. Sans elle, un réconciliateur qui ne
        // dropperait plus rien passerait ce test sur une base déjà vide.
        assert_eq!(
            avant, attendus,
            "prémisse : la tâche de fond du boot doit avoir créé exactement les index dérivés de la \
             déclaration avant qu'on éprouve leur retrait (levier {})",
            regime()
        );
        assert!(!avant.is_empty(), "prémisse : rien à retirer, le sens éteint ne prouverait rien");

        // L'ENVIRONNEMENT POSE LE LEVIER : la précédence du produit est `env > fichier > défaut`, donc la
        // configuration passée en argument ci-dessous serait MASQUÉE. Ce fichier n'écrit AUCUN état de
        // processus (cf. l'en-tête), donc le retrait n'est pas éprouvable ici — on le DIT. La CRÉATION,
        // elle, vient d'être exigée ci-dessus : ce chemin ne rend rien de vide.
        if std::env::var(LEVIER).is_ok() {
            eprintln!(
                "[P6.8-d] retrait NON ÉPROUVÉ : `{LEVIER}` est posé dans l'environnement de cette suite, il \
                 masque la configuration passée en argument. La création reste exigée. Lancer la suite sans \
                 cette variable pour éprouver aussi le kill-switch."
            );
            // `P11.23-b` — l'`eprintln!` ci-dessus est AVALÉ par `libtest` pour un test qui réussit
            // (mesuré : 0 occurrence sous `cargo test` nu). Il reste pour qui joue à la main sous
            // `--nocapture` ; ce qui atteint celui qui décide, c'est la ligne du canal.
            crate::tests::canal_de_refus::refuser_de_conclure(
                module_path!(),
                "le_levier_eteint_retire_exactement_les_index_derives",
                &format!(
                    "`{LEVIER}` est POSÉE dans l'environnement de cette suite : elle masque la \
                     configuration passée en argument (précédence `env > fichier > défaut`), donc \
                     le kill-switch n'est pas éprouvable ici. La CRÉATION, elle, vient d'être \
                     exigée. Rejouer la suite SANS cette variable pour éprouver le retrait."
                ),
            );
            return;
        }

        let eteint: HashMap<String, String> =
            [(LEVIER.to_string(), "0".to_string())].into_iter().collect();
        reconcile_index_state(&conn, &eteint);

        let apres = famille_au_schema(&conn);
        assert!(
            apres.is_empty(),
            "LE KILL-SWITCH NE RETIRE PAS TOUTE LA FAMILLE : `{LEVIER}=0` doit dropper UN index par entrée \
             de la déclaration. {} index sur {} subsistent : {apres:?}",
            apres.len(),
            avant.len()
        );
    }

    /// LA RÉCIPROQUE, ET LA RAISON DE SON EXISTENCE — un index de la famille dont le champ a quitté la
    /// déclaration échappe à TOUT geste dérivé de la liste courante.
    ///
    /// Deux choses sont prouvées ici, et la seconde justifie la première :
    ///   (1) l'inclusion inverse ATTRAPE cet index — le témoin est fabriqué à partir de la déclaration
    ///       elle-même, jamais d'un nom inventé, et le témoin POSITIF (sans orphelin, rien n'est accusé)
    ///       est joué juste avant pour que l'instrument ne puisse pas accuser à vide ;
    ///   (2) le kill-switch SYNCHRONE NE LE RETIRE PAS — le réconciliateur ne droppe que les noms qu'il
    ///       dérive de la liste courante. C'est exactement pourquoi retirer un champ de `HOT_FIELDS`
    ///       laissait un index mort sur toute base déjà déployée, et pourquoi le geste qui le retire
    ///       (`P6.8-e`) dérive son critère du PRÉFIXE et vit dans la passe de FOND, pas ici.
    #[test]
    fn un_index_de_la_famille_sans_champ_declare_est_accuse_et_survit_au_kill_switch() {
        let attendus = attendus();
        let conn = super::test_db();

        // TÉMOIN POSITIF : sur la base migrée, sans orphelin fabriqué, l'inclusion inverse n'accuse rien.
        let sans_orphelin: Vec<String> =
            famille_au_schema(&conn).difference(&attendus).cloned().collect();
        assert!(
            sans_orphelin.is_empty(),
            "témoin positif : aucun orphelin ne doit être accusé sur une base migrée nue, sinon \
             l'instrument accuse à vide. Accusés : {sans_orphelin:?}"
        );

        // L'ORPHELIN — nom DÉRIVÉ d'un champ que la déclaration ne peut pas produire, DDL identique à
        // celle du produit (index d'expression partiel sur `event`).
        let champ = champ_hors_declaration();
        let orphelin = nom_derive(&champ);
        conn.execute(
            &format!(
                "CREATE INDEX IF NOT EXISTS {orphelin} ON event(json_extract(fields,'$.{champ}')) \
                 WHERE json_extract(fields,'$.{champ}') IS NOT NULL"
            ),
            [],
        )
        .expect("création de l'index témoin");

        let accuses: Vec<String> = famille_au_schema(&conn).difference(&attendus).cloned().collect();
        assert_eq!(
            accuses,
            vec![orphelin.clone()],
            "L'INCLUSION INVERSE N'ACCUSE PAS L'ORPHELIN : un index de la famille dont le champ n'est pas \
             déclaré doit être NOMMÉ par la garde. Sans elle, retirer un champ de la déclaration laisserait \
             cet index sur toute base déployée sans que rien ne rougisse."
        );

        // (2) LE KILL-SWITCH SYNCHRONE NE LE VOIT PAS — quelle que soit la valeur du levier dans
        // l'environnement, le réconciliateur ne droppe que `<préfixe><champ déclaré>`. La limite est
        // réelle et nommée : c'est elle qui rend l'inclusion inverse nécessaire plutôt que décorative,
        // et qui a imposé de placer le retrait des orphelins AILLEURS — dans la passe de fond, sur un
        // critère de PRÉFIXE (`P6.8-e`), le seul qui survive au retrait d'un champ.
        let eteint: HashMap<String, String> =
            [(LEVIER.to_string(), "0".to_string())].into_iter().collect();
        reconcile_index_state(&conn, &eteint);
        assert!(
            famille_au_schema(&conn).contains(&orphelin),
            "prémisse de la réciproque RÉFUTÉE : le kill-switch a retiré `{orphelin}`. Le réconciliateur \
             saurait donc dropper un index de la famille hors déclaration — cette garde perdrait sa raison \
             d'être, et le commentaire de tête de ce fichier serait faux."
        );
    }
}
