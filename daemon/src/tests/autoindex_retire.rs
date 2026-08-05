// P6.8-b — LE MÉCANISME D'AUTO-INDEX ADAPTATIF EST RETIRÉ, ET IL NE DOIT PAS REVENIR EN ZOMBIE.
//
// CE QUI A ÉTÉ RETIRÉ. Un registre `autoindex` (table v42), un mainteneur de fond, un tampon de chaleur
// et une promotion d'index `idx_ev_auto_<champ>` sur les champs JSON « chauds et lents ». MESURÉ : ce
// mécanisme n'a JAMAIS promu un seul index. La chaîne était coupée par une FRONTIÈRE DE CRATE — les
// points de collecte `soql_field`/`soql_filter_field` ont migré dans `guatx-core` où ils sont privés,
// et le compilateur le DISAIT (`function autoindex_note is never used`). Le recâbler était par ailleurs
// impossible pour la moitié « numérique » : les parseurs stockent TOUTE valeur de champ en CHAÎNE JSON,
// donc promouvoir un champ (ce qui RETIRE le `CAST(... AS REAL)`) rendrait `search dport=443`
// SILENCIEUSEMENT VIDE — l'ordre inter-types de SQLite étant NULL < INTEGER/REAL < TEXT < BLOB.
//
// POURQUOI UNE GARDE, ET PAS SEULEMENT UNE SUPPRESSION. Ce défaut n'était pas une ligne fausse : c'était
// un sous-système ENTIER, avec ses réglages, son entrée d'UI et sa table, que rien n'obligeait à être
// branché. Il a survécu à plusieurs revues précisément parce qu'il RESSEMBLAIT à du code vivant. Tant que
// le nom peut réapparaître, il réapparaîtra — sous la forme d'un « je remets juste le compteur, on
// branchera plus tard ». La garde échoue AU PLUS TÔT (à la compilation de la suite, sans base, sans I/O
// réseau, sans réglage) et elle est DÉRIVÉE : elle BALAIE le source du daemon, elle n'énumère aucun
// fichier ni aucun symbole. Un `PLUME_AUTOINDEX_V2` écrit demain dans un fichier qui n'existe pas encore
// est attrapé PAR CONSTRUCTION.

/// Le mot que plus aucune ligne de CODE du daemon ne doit porter (hors les deux migrations historiques).
/// En minuscules : la comparaison est insensible à la casse, donc `AUTOINDEX_DENY` et `PLUME_AUTOINDEX`
/// sont attrapés par le même mot.
const MOT_INTERDIT: &str = "autoindex";

/// LE SEUL HOMONYME LÉGITIME, et il n'appartient pas à ce dépôt : SQLite nomme `sqlite_autoindex_<table>_N`
/// l'index qu'il crée LUI-MÊME pour une contrainte UNIQUE/PRIMARY KEY. Le plan de sauvegarde et la
/// ventilation disque doivent le nommer pour le CLASSER — les confondre avec le mécanisme retiré
/// désarmerait la garde en une semaine (on l'exclurait « juste ce fichier », puis un autre).
const HOMONYME_SQLITE: &str = "sqlite_autoindex";

/// LA SEULE fonction autorisée à porter le mot, et l'ancrage est sur la fonction ENGLOBANTE, pas sur le
/// fichier : réintroduire le mécanisme dans une `migrate_v116` est donc ROUGE, alors même que `migrate.rs`
/// contient, lui, une occurrence légitime.
///
/// `migrate_v42` a CRÉÉ la table `autoindex`. HISTORIQUE : une migration ne rejoue pas, on ne réécrit pas
/// le passé. La table est aujourd'hui VESTIGIALE (plus une ligne de code ne la lit ni ne l'écrit) et elle
/// RESTE : la dropper la ferait MANQUER à la forme de RÉFÉRENCE que le contrat de démarrage compare à la
/// base -> refus de démarrer ; et la retirer AUSSI de la référence exigerait une migration, donc un bump de
/// `CODE_SCHEMA_MAX`, donc une base que le binaire précédent refuserait d'ouvrir — ce qui transformerait le
/// rollback automatique de la porte de déploiement en cul-de-sac. Elle partira dans un lot où un bump est
/// de toute façon justifié.
const SITES_AUTORISES: [&str; 1] = ["migrate_v42"];

/// LA PURGE DE FOND, dont la DISPARITION doit être aussi bruyante que le RETOUR du mécanisme. Elle n'a pas
/// besoin de porter le mot interdit (son nom et son motif suffisent), donc l'anti-faux-vert ci-dessus ne la
/// couvrirait pas : on la vérifie séparément, par son NOM et par le MOTIF D'ÉNUMÉRATION qu'elle doit
/// contenir. Sans elle, un `idx_ev_auto_*` sur une base live est un orphelin que PLUS AUCUN code ne peut
/// retirer — et la garde, elle, resterait verte.
const PURGE_FICHIER: &str = "maintenance.rs";
const PURGE_FONCTION: &str = "drop_orphan_auto_field_indexes_background";
/// Le motif LIKE échappé : c'est LUI qui rend la purge DÉRIVÉE (liste demandée à SQLite, jamais écrite).
/// On cherche le TEXTE SOURCE, où les antislashs du motif SQL sont eux-mêmes échappés par Rust — d'où les
/// antislashs DOUBLES ici. (Écrire la forme simple donnait un faux ROUGE : vérifié.)
const PURGE_MOTIF: &str = r"idx\\_ev\\_auto\\_%";

/// Retire d'une ligne Rust ce qui est COMMENTAIRE, sans se laisser piéger par un `//` qui vit à
/// l'intérieur d'une chaîne (`"http://…"`). On ne cherche pas à analyser Rust : on suit l'état
/// « dans une chaîne » et on coupe au premier `//` vu HORS chaîne. Conservateur dans le bon sens —
/// si on doutait, on garderait la ligne, donc la garde rougirait plutôt que de se taire.
fn code_seul(ligne: &str) -> String {
    let octets: Vec<char> = ligne.chars().collect();
    let mut dans_chaine = false;
    let mut echappe = false;
    let mut fin = octets.len();
    let mut i = 0;
    while i < octets.len() {
        let c = octets[i];
        if dans_chaine {
            if echappe {
                echappe = false;
            } else if c == '\\' {
                echappe = true;
            } else if c == '"' {
                dans_chaine = false;
            }
        } else if c == '"' {
            dans_chaine = true;
        } else if c == '/' && i + 1 < octets.len() && octets[i + 1] == '/' {
            fin = i;
            break;
        }
        i += 1;
    }
    octets[..fin].iter().collect()
}

/// Le mot interdit est-il présent dans CE fragment de code, une fois l'homonyme SQLite neutralisé ?
fn porte_le_mot(code: &str) -> bool {
    code.to_lowercase().replace(HOMONYME_SQLITE, "").contains(MOT_INTERDIT)
}

/// Toutes les occurrences de CODE (commentaires dépouillés) du mot interdit dans le source du daemon,
/// rendues avec le fichier, la ligne, la fonction englobante et le texte. Rien n'est énuméré : on
/// descend l'arborescence. Le répertoire `tests/` est EXCLU — c'est ici que le mot doit vivre (ce
/// fichier le porte lui-même), et un test qui rappellerait une fonction supprimée ne COMPILERAIT pas :
/// le compilateur est déjà la garde de ce côté-là.
fn occurrences_du_mot() -> (Vec<(String, usize, String, String)>, usize) {
    let racine = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut trouvees = Vec::new();
    let mut fichiers = 0usize;
    let mut pile = vec![racine.clone()];
    while let Some(d) = pile.pop() {
        for e in std::fs::read_dir(&d).expect("source du daemon lisible") {
            let p = e.expect("entrée de répertoire lisible").path();
            if p.is_dir() {
                if p.file_name().map(|n| n == "tests").unwrap_or(false) {
                    continue;
                }
                pile.push(p);
                continue;
            }
            if p.extension().map(|x| x != "rs").unwrap_or(true) {
                continue;
            }
            fichiers += 1;
            let rel = p.strip_prefix(&racine).expect("chemin sous src/").to_string_lossy().to_string();
            let mut englobante = String::from("<hors fonction>");
            for (n, ligne) in std::fs::read_to_string(&p).expect("fichier source lisible").lines().enumerate() {
                // Ancrage sur la fonction englobante : dans ce dépôt les `fn` de premier niveau sont
                // en colonne 0. Une occurrence dans un corps imbriqué est attribuée à la `fn` de
                // premier niveau qui la contient — c'est exactement la granularité qu'on veut.
                if let Some(reste) = ligne.strip_prefix("fn ").or_else(|| ligne.strip_prefix("pub(crate) fn ")) {
                    englobante = reste.split(['(', '<', ' ']).next().unwrap_or("").to_string();
                }
                let code = code_seul(ligne);
                if porte_le_mot(&code) {
                    trouvees.push((rel.clone(), n + 1, englobante.clone(), ligne.trim().to_string()));
                }
            }
        }
    }
    (trouvees, fichiers)
}

/// LA GARDE. Aucune ligne de CODE du daemon ne porte plus le mot, sauf dans les deux migrations qui ont
/// le droit de le nommer : celle qui a créé la table (historique) et celle qui la purge.
#[test]
fn le_mecanisme_dauto_index_ne_revient_pas() {
    let (occurrences, fichiers) = occurrences_du_mot();

    // ANTI-FAUX-VERT (1) : une garde qui n'a rien LU est indiscernable d'une garde satisfaite.
    assert!(
        fichiers >= 50,
        "ANTI-FAUX-VERT : seulement {fichiers} fichier(s) .rs balayé(s) sous src/ — le balayage ne \
         correspond plus à l'arborescence, cette garde ne prouve donc plus rien"
    );

    let (autorisees, interdites): (Vec<_>, Vec<_>) = occurrences
        .into_iter()
        .partition(|(_, _, fonction, _)| SITES_AUTORISES.contains(&fonction.as_str()));

    // ANTI-FAUX-VERT (2) : le site autorisé doit RÉELLEMENT porter le mot. C'est cette exigence qui prouve
    // que les TROIS pièces de l'instrument mordent encore : le mot cherché, le dépouillement des
    // commentaires (les occurrences visées sont dans des chaînes de CODE, pas dans la doc), et l'ancrage
    // sur la fonction englobante. Un invariant vide est un invariant mort.
    for attendu in SITES_AUTORISES {
        assert!(
            autorisees.iter().any(|(_, _, fonction, _)| fonction == attendu),
            "ANTI-FAUX-VERT : `{attendu}` ne porte plus le mot cherché alors qu'elle CRÉE la table \
             `autoindex` — l'instrument (mot, dépouillement des commentaires, ancrage sur la fonction \
             englobante) ne mord plus, donc cette garde ne prouve plus rien. Vu : {autorisees:?}"
        );
    }

    // ANTI-FAUX-VERT (3) : LA PURGE DE FOND EXISTE ENCORE, ET ELLE EST ENCORE DÉRIVÉE. Retirer le mécanisme
    // sans elle laisserait sur les bases live des `idx_ev_auto_*` que plus AUCUN code ne sait dropper (le
    // réconciliateur ne connaît que `idx_ev_f_*`) : des orphelins permanents, payés en disque et en insert
    // btree par ligne ingérée. Cette garde-ci le rend impossible en silence. On vérifie les DEUX moitiés :
    // la fonction est là (par son nom) ET elle demande encore sa liste à SQLite (par son motif échappé) —
    // une purge qui se remettrait à énumérer des noms EN DUR ne serait plus dérivée et rougirait ici.
    let maintenance = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(PURGE_FICHIER),
    )
    .expect("maintenance.rs lisible");
    assert!(
        maintenance.contains(&format!("fn {PURGE_FONCTION}")),
        "LA PURGE DE FOND A DISPARU : `{PURGE_FONCTION}` n'est plus dans {PURGE_FICHIER}. Le mécanisme \
         d'auto-index a été retiré (P6.8-b) et cette fonction est le SEUL code qui sache encore dropper un \
         `idx_ev_auto_*` — le réconciliateur ne connaît que `idx_ev_f_*`. Sans elle, tout index de cette \
         famille présent sur une base live devient un ORPHELIN PERMANENT que personne ne peut plus retirer."
    );
    assert!(
        maintenance.contains(PURGE_MOTIF),
        "LA PURGE DE FOND N'EST PLUS DÉRIVÉE : le motif d'énumération `{PURGE_MOTIF}` a disparu de \
         `{PURGE_FONCTION}`. La liste des index à dropper doit être DEMANDÉE à sqlite_master, jamais \
         écrite en dur — on ne sait pas quels `idx_ev_auto_*` existent sur une base donnée (mesuré le \
         2026-08-05 : aucun dans les 10 plus gros objets, mais l'instrument ne voit rien sous 21,9 Mio)."
    );

    assert!(
        interdites.is_empty(),
        "LE MÉCANISME D'AUTO-INDEX ADAPTATIF EST REVENU. Il a été retiré (P6.8-b) parce qu'il était INERTE \
         — il n'a jamais promu un seul index, sa chaîne de collecte étant coupée par une frontière de crate \
         — et parce que la moitié « numérique » ne pouvait PAS être recâblée sans rendre `search dport=443` \
         silencieusement VIDE (les parseurs stockent tout en chaîne JSON ; c'est le CAST qui rend le filtre \
         juste). QUOI FAIRE : (a) si le besoin est d'indexer un champ JSON, l'ajouter à `HOT_FIELDS` dans \
         soql_glue.rs ET à sa copie dans `guatx-core` — l'assertion const les tient appariées, et le coût \
         RAM est à MESURER ; (b) si le besoin est vraiment un mécanisme adaptatif, il faut d'abord rouvrir \
         `soql_field`/`soql_filter_field` dans `guatx-core` et résoudre le typage des valeurs, pas remettre \
         un compteur qui n'aura pas d'appelant. Occurrences interdites (fichier, ligne, fonction, texte) : \
         {interdites:#?}"
    );
}

/// LA PURGE DE LA DETTE, PROUVÉE PAR MUTATION SUR UNE BASE QUI LA PORTE. Le retrait du mainteneur a une
/// conséquence qu'aucun test de compilation ne voit : il était le SEUL code qui savait dropper un
/// `idx_ev_auto_*` (le réconciliateur d'index ne connaît que la famille `idx_ev_f_*`). Un tel index
/// deviendrait un ORPHELIN PERMANENT sur une base live. `drop_orphan_auto_field_indexes_background` le
/// retire — et la LISTE N'EST PAS ÉCRITE dans le code : elle est DEMANDÉE à `sqlite_master`. Ce test le
/// prouve avec des noms que la fonction ne peut pas connaître, et vérifie que le motif `LIKE` n'attrape
/// QUE le préfixe littéral (les `_` y sont échappés, sinon ils seraient des jokers).
#[test]
fn la_purge_de_fond_retire_les_index_auto_orphelins_sans_les_nommer() {
    let chemin = crate::tmp_possede::TmpDb::neuf("purge-idx-auto");
    let conn = Connection::open(chemin.as_str()).expect("base fichier ouvrable");
    conn.execute_batch(include_str!("../../../db/schema.sql")).expect("schéma livré applicable");
    assert!(migrate(&conn), "la chaîne de migrations doit aller au bout");

    // La table `autoindex` est VESTIGIALE et doit RESTER : la forme de RÉFÉRENCE que le contrat de
    // démarrage compare à la base est construite depuis la chaîne de migrations, `migrate_v42` incluse.
    // La dropper la ferait MANQUER à la base -> gap -> refus de démarrer. Ce n'est pas un oubli.
    let table: i64 = conn
        .query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='autoindex'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(table, 1, "la table `autoindex` est VESTIGIALE mais doit RESTER (la référence la déclare)");

    // MUTATION — on FABRIQUE la dette avec des noms que la fonction ne peut pas deviner, plus deux TÉMOINS
    // qui doivent SURVIVRE et qui prouvent que le motif ne déborde pas.
    conn.execute_batch(
        "CREATE INDEX idx_ev_auto_champ_invente_xyz ON event(json_extract(fields,'$.champ_invente_xyz')) \
             WHERE json_extract(fields,'$.champ_invente_xyz') IS NOT NULL;
         CREATE INDEX idx_ev_auto_zzz ON event(json_extract(fields,'$.zzz'));
         CREATE INDEX idxaevaautoatemoin ON event(host);
         CREATE INDEX idx_ev_autre_temoin ON event(source);",
    )
    .expect("dette fabricable sur la base");

    let db = std::sync::Arc::new(parking_lot::Mutex::new(conn));
    drop_orphan_auto_field_indexes_background(&db);
    // IDEMPOTENCE : au boot suivant il n'y a plus rien à voir, et ça ne doit rien casser.
    drop_orphan_auto_field_indexes_background(&db);

    let conn = db.lock();
    let survivants: Vec<String> = {
        let mut st = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx%auto%' ORDER BY name")
            .unwrap();
        st.query_map([], |r| r.get::<_, String>(0)).unwrap().map(|r| r.unwrap()).collect()
    };
    assert_eq!(
        survivants,
        vec!["idxaevaautoatemoin".to_string()],
        "les `idx_ev_auto_*` doivent TOUS être droppés — ÉNUMÉRÉS depuis sqlite_master, jamais nommés dans \
         le code (ces deux-là portent des noms que la fonction ne peut pas connaître) — et le témoin \
         `idxaevaautoatemoin` doit SURVIVRE : il a les mêmes lettres aux mêmes places avec `a` là où le \
         motif a `_`, or les `_` du motif sont ÉCHAPPÉS et ne jouent donc PAS leur rôle de joker. \
         Survivants : {survivants:?}"
    );
    let autre: i64 = conn
        .query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_ev_autre_temoin'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(autre, 1, "`idx_ev_autre_temoin` n'est pas de la famille purgée : il doit SURVIVRE");
    // La purge touche les INDEX, jamais la table vestigiale.
    let table_apres: i64 = conn
        .query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='autoindex'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(table_apres, 1, "la purge ne doit PAS dropper la table (cf. la forme de référence)");
}
