// P10.7-a — LE VIDE SILENCIEUX DE LA BARRE `/api/search`.
//
// LE DÉFAUT QUE CE FICHIER FIGE. La barre envoyait les tokens BRUTS à `MATCH` et AVALAIT l'erreur du
// moteur : cinq saisies d'analyste ordinaires (`10.0.0.1`, `/usr/bin/dash`, `kube-audit`, `user:root`,
// `exec(1)`) rendaient `{"results": []}`, c'est-à-dire « rien ne correspond » là où le moteur avait dit
// « je refuse ». La fonction écrite pour ça, `fts_safe`, n'avait AUCUN appelant — et sa liste de
// caractères autorisait `.`, `/` et `@`, trois de ceux que le moteur rejette.
//
// CE QUE CES TESTS NE FONT PAS : recopier une liste de caractères. Le balayage ci-dessous DEMANDE au
// moteur, caractère par caractère et POSITION par position, ce qu'il accepte — donc le 26e caractère
// spécial d'une future version de FTS5 est couvert par CONSTRUCTION, sans que personne ne l'ajoute.
//
// MUTATIONS EXÉCUTÉES le 2026-08-09, et ce qu'elles ont fait rougir (mesuré, pas supposé) :
//   • `fts_plan` rendu transparent (tokens verbatim) -> 6 tests rouges, dont les cinq saisies NOMMÉES,
//     le balayage ASCII, la phrase citée et le bout-en-bout `/api/search` ;
//   • `FtsMirror::retrieves` forcée à `true` (= revenir au seul critère « le moteur accepte ») ->
//     3 rouges : le balayage ASCII (`a^b` accepté, introuvable), `terme_sans_token_*`, `le_miroir_*` ;
//   • `fts_tokenize_clause` forcée à `None` (clause `tokenize=` perdue) -> `le_miroir_*` rouge (et le
//     balayage reste VERT : il ne porte que sur `event_fts`, dont le tokenizer est celui par défaut) ;
//   • les 6 sites d'erreur du handler re-avalés en `{"results": []}` -> le bout-en-bout rouge sur
//     `regex=(`, la seule saisie qui atteint encore le moteur en échec une fois la garde en place.

/// Les CINQ saisies du constat, telles qu'un analyste les tape. Nommées une fois, réutilisées partout :
/// un test qui ne nomme pas la saisie ne dit pas ce qu'il défend.
const SAISIES_ANALYSTE: &[&str] = &["10.0.0.1", "/usr/bin/dash", "kube-audit", "user:root", "exec(1)"];

/// Un document qui CONTIENT la saisie — sinon « 0 résultat » serait la bonne réponse et le test
/// ne prouverait rien.
fn document_portant(saisie: &str) -> String {
    format!("sentinelle {saisie} fin de ligne")
}

/// Insère un event et rend son `id` (= le rowid indexé par `event_fts`, via le trigger `event_ai`).
fn ins_fts(c: &Connection, msg: &str) -> i64 {
    c.execute(
        "INSERT INTO event(ts,source,category,severity,message,dedup,engagement_id,origin,env_id) \
         VALUES(1000,'sshd','auth',3,?1,?2,'','','prod')",
        params![msg, format!("dedup-{msg}")],
    )
    .unwrap();
    c.last_insert_rowid()
}

/// Les rowid que le moteur rend pour cette expression MATCH — ou son message d'erreur BRUT.
/// C'est LE chemin de la barre (`event_fts MATCH ?1`), pas une imitation.
fn match_rowids(c: &Connection, expr: &str) -> Result<Vec<i64>, String> {
    let mut st = c.prepare("SELECT rowid FROM event_fts WHERE event_fts MATCH ?1").map_err(|e| e.to_string())?;
    let rows = st.query_map(params![expr], |r| r.get::<_, i64>(0)).map_err(|e| e.to_string())?;
    rows.collect::<rusqlite::Result<Vec<i64>>>().map_err(|e| e.to_string())
}

/// La suite de tokens que la BARRE produit pour une saisie — exactement l'entrée de `fts_plan` dans
/// `handlers::search` (aucune des cinq saisies n'est un filtre structuré : `field_col("user")` = None).
fn tokens_de_la_barre(saisie: &str) -> Vec<String> {
    soql_glue_spaced_ops(search_tokens(saisie))
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
//  (1) LE CONSTAT — le moteur REFUSE bel et bien ces cinq saisies. Sans ce témoin, tout le reste
//  serait une garde contre un défaut supposé.
// ════════════════════════════════════════════════════════════════════════════════════════════════

#[test]
fn moteur_fts5_refuse_les_cinq_saisies_brutes() {
    let conn = test_db();
    ins_fts(&conn, &document_portant("10.0.0.1"));
    let mut refus = 0usize;
    for s in SAISIES_ANALYSTE {
        let err = match_rowids(&conn, s).unwrap_err();
        assert!(
            err.contains("fts5: syntax error") || err.contains("no such column"),
            "saisie « {s} » : le moteur devait REFUSER (c'est le constat P10.7-a) — il a rendu : {err}"
        );
        refus += 1;
    }
    // VALIDATION DE L'INSTRUMENT : un filtre qui ne rend RIEN se lit « je n'ai pas mesuré ».
    assert_eq!(refus, SAISIES_ANALYSTE.len(), "les cinq saisies doivent toutes avoir été soumises au moteur");
    // ET LE TÉMOIN POSITIF : une saisie ordinaire passe, donc l'instrument n'est pas cassé.
    assert_eq!(match_rowids(&conn, "sentinelle").unwrap().len(), 1, "témoin positif : un mot simple DOIT passer");
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
//  (2) LA FERMETURE — chacune des cinq devient un RÉSULTAT.
// ════════════════════════════════════════════════════════════════════════════════════════════════

#[test]
fn les_cinq_saisies_deviennent_un_resultat_au_lieu_dun_vide() {
    let conn = test_db();
    let attendus: Vec<(&str, i64)> = SAISIES_ANALYSTE.iter().map(|s| (*s, ins_fts(&conn, &document_portant(s)))).collect();
    let mirrors = fts_bar_mirrors(&conn, false);
    assert_eq!(mirrors.len(), 1, "un miroir doit être dérivé de `event_fts` (sinon la garde n'a pas d'oracle)");
    for (saisie, id) in &attendus {
        let expr = match fts_plan(&tokens_de_la_barre(saisie), &mirrors) {
            FtsPlan::Match { expr, literal } => {
                assert_eq!(literal, vec![saisie.to_string()], "saisie « {saisie} » : elle est rendue LITTÉRALE, et ça se dit");
                expr
            }
            FtsPlan::Unindexable { token } => panic!("saisie « {saisie} » : déclarée inexprimable alors qu'elle porte du texte ({token})"),
        };
        let ids = match_rowids(&conn, &expr)
            .unwrap_or_else(|e| panic!("saisie « {saisie} » -> expression `{expr}` REFUSÉE par le moteur : {e}"));
        assert!(
            ids.contains(id),
            "saisie « {saisie} » : le document qui la contient (id={id}) doit être TROUVÉ — expression émise `{expr}`, rendus {ids:?}"
        );
    }
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
//  (3) LA GARDE EST DÉRIVÉE — balayage de TOUT l'ASCII imprimable, sous quatre formes.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/// Aucune saisie ne doit produire un VIDE SILENCIEUX. Pour chaque caractère imprimable et chaque
/// forme (`a<c>b`, `<c>ab`, `ab<c>`, `<c>` seul — 4 × 95 = 380 cas), la garde doit rendre SOIT une expression que le
/// moteur accepte ET qui retrouve le document contenant le terme, SOIT un refus NOMMÉ. Jamais autre chose.
///
/// POURQUOI LES POSITIONS. L'appartenance à la syntaxe FTS5 en DÉPEND — mesuré 2026-08-09 : `^exec` est
/// accepté, `exec^` est un « syntax error » ; `a*b` passe, `*` seul est « unknown special query ». Une
/// liste de caractères, par nature, ne peut pas porter cette distinction : c'est la raison structurelle
/// pour laquelle `fts_safe` a été SUPPRIMÉE plutôt que corrigée.
///
/// CE BALAYAGE A TROUVÉ CE QU'AUCUNE LISTE N'AURAIT VU : `a^b` est ACCEPTÉ par le moteur (zéro erreur)
/// et ne retrouve pourtant jamais une ligne qui le contient — `^` y est l'ancre « premier token de la
/// colonne ». Le critère « le moteur accepte » était donc insuffisant ; c'est ce cas qui a imposé
/// `FtsMirror::retrieves` (le terme doit retrouver SON PROPRE texte) à la place d'un test d'acceptation.
#[test]
fn aucune_saisie_ascii_ne_rend_un_vide_silencieux() {
    let conn = test_db();
    // Le terme est placé EN TÊTE du message, comme dans la sonde du miroir : c'est la position la plus
    // favorable, celle où un terme ancré (`^ab`) a le droit de correspondre. La ligne est mesurée
    // ensuite dans l'autre position, et l'écart est ASSERTÉ plus bas au lieu d'être passé sous silence.
    let mut cas: Vec<(String, i64, i64)> = Vec::new();
    for c in (32u8..=126).map(|b| b as char) {
        for forme in [format!("a{c}b"), format!("{c}ab"), format!("ab{c}"), format!("{c}")] {
            let tete = ins_fts(&conn, &format!("{forme} marqueur{}", cas.len()));
            let milieu = ins_fts(&conn, &format!("prefixe{} {forme} fin", cas.len()));
            cas.push((forme, tete, milieu));
        }
    }
    let mirrors = fts_bar_mirrors(&conn, false);
    let (mut trouves, mut litteralises, mut inexprimables) = (0usize, 0usize, 0usize);
    let (mut refuses_verbatim, mut echecs_en_milieu_de_ligne) = (0usize, Vec::<String>::new());
    let mut refuses_nommement = Vec::<String>::new();
    for (terme, id_tete, id_milieu) in &cas {
        if mirrors[0].accepts(terme).is_err() {
            refuses_verbatim += 1;
        }
        match fts_plan(std::slice::from_ref(terme), &mirrors) {
            FtsPlan::Match { expr, literal } => {
                if !literal.is_empty() {
                    litteralises += 1;
                }
                let ids = match_rowids(&conn, &expr)
                    .unwrap_or_else(|e| panic!("terme « {terme} » -> `{expr}` REFUSÉE par le moteur : {e}"));
                assert!(
                    ids.contains(id_tete),
                    "terme « {terme} » : son propre document (id={id_tete}) n'est pas retrouvé — expression `{expr}`, rendus {ids:?}. \
                     C'est EXACTEMENT le vide silencieux que P10.7-a ferme."
                );
                if !ids.contains(id_milieu) {
                    echecs_en_milieu_de_ligne.push(terme.clone());
                }
                trouves += 1;
            }
            FtsPlan::Unindexable { token } => {
                assert_eq!(&token, terme, "le refus doit NOMMER le terme refusé");
                // Le refus doit être JUSTIFIÉ : même en phrase citée — la forme la plus littérale —
                // le terme ne retrouve pas son propre document. On le vérifie au lieu de le croire.
                let ids = match_rowids(&conn, &fts_quote(terme)).unwrap_or_default();
                assert!(!ids.contains(id_tete), "terme « {terme} » déclaré inexprimable alors que la phrase citée le retrouve");
                refuses_nommement.push(terme.clone());
                inexprimables += 1;
            }
        }
    }
    // VALIDATION DE L'INSTRUMENT : les compteurs doivent être NON NULS, sinon le balayage n'a rien
    // mesuré (par exemple parce que la garde serait devenue un passe-plat).
    assert_eq!(trouves + inexprimables, cas.len(), "chaque cas balayé doit tomber dans l'une des deux issues");
    assert!(refuses_verbatim >= 25, "PLANCHER de validation d'instrument : si le moteur refusait moins de 25 des \
         {} formes balayées, c'est le balayage qui serait cassé, pas le moteur — {refuses_verbatim} refus", cas.len());
    assert!(litteralises >= refuses_verbatim - inexprimables, "tout terme refusé verbatim et exprimable doit avoir été littéralisé");
    assert!(inexprimables > 0, "des termes sans aucun token d'index existent (`.`, `-`, `*` seuls) — aucun n'a été vu");
    assert!(trouves > 300, "l'écrasante majorité des cas doit devenir un RÉSULTAT, pas un refus — {trouves} trouvés sur {}", cas.len());

    // LA LIMITE, NOMMÉE ET BORNÉE plutôt que tue. Les seuls termes que la garde laisse ANCRÉS (donc
    // introuvables ailleurs qu'en tête de champ) sont ceux qui COMMENCENT par `^`, où l'ancre FTS5 est
    // manifestement voulue. Si une version future de FTS5 ajoutait un autre opérateur positionnel, ce
    // test rougirait — c'est le but : la liste n'est pas une hypothèse, c'est une MESURE assertée.
    let attendus: Vec<String> = cas
        .iter()
        .map(|(t, _, _)| t.clone())
        .filter(|t| t.starts_with('^') && !refuses_nommement.contains(t))
        .collect();
    assert_eq!(
        echecs_en_milieu_de_ligne, attendus,
        "termes introuvables hors tête de champ : seuls les termes ANCRÉS (`^…`) sont admis à l'être"
    );
    assert!(!attendus.is_empty(), "l'ancre `^` doit être représentée dans le balayage (sinon la limite n'est pas mesurée)");
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
//  (4) LA RÈGLE D'ÉCHAPPEMENT, VÉRIFIÉE CONTRE LE MOTEUR (et non contre la documentation).
// ════════════════════════════════════════════════════════════════════════════════════════════════

#[test]
fn fts5_quoting_is_a_literal_phrase() {
    let conn = test_db();
    let id_ops = ins_fts(&conn, "le mot exact a\"b puis failed rapide"); // porte un guillemet INTERNE
    let id_ph = ins_fts(&conn, "sshd: failed password for root");
    // (a) un `"` interne se DOUBLE — et la chaîne reste une seule phrase.
    assert_eq!(fts_quote("a\"b"), "\"a\"\"b\"");
    assert!(match_rowids(&conn, &fts_quote("a\"b")).unwrap().contains(&id_ops), "phrase avec guillemet doublé");
    // (b) entre guillemets, RIEN n'est un opérateur : `fail*` cité ne fait plus de préfixe.
    assert!(match_rowids(&conn, "fail*").unwrap().contains(&id_ops), "hors guillemets, `fail*` trouve `failed` : `*` EST un préfixe");
    assert!(!match_rowids(&conn, &fts_quote("fail*")).unwrap().contains(&id_ops), "entre guillemets, `*` n'est plus un opérateur : la phrase cherche le mot `fail`, absent de `failed`");
    // (c) une phrase est ORDONNÉE et ADJACENTE — c'est ce qui la distingue d'un ET de mots.
    assert!(match_rowids(&conn, &fts_quote("failed password")).unwrap().contains(&id_ph), "phrase dans l'ordre");
    assert!(!match_rowids(&conn, &fts_quote("password failed")).unwrap().contains(&id_ph), "phrase inversée : pas de correspondance");
    assert!(match_rowids(&conn, "password failed").unwrap().contains(&id_ph), "hors guillemets : simple ET, l'ordre est indifférent");
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
//  (5) LE SEUL CAS QUE L'ÉCHAPPEMENT NE SAUVE PAS — et pourquoi il doit être DIT, pas servi.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/// Un terme dont le tokenizer ne tire AUCUN token devient une phrase VIDE. Une phrase vide est
/// syntaxiquement valide et ment de DEUX façons selon sa place — les deux sont mesurées ici, et c'est
/// ce qui justifie un refus explicite plutôt qu'un `{"results": []}` ou qu'un silence.
#[test]
fn terme_sans_token_dindex_est_dit_et_jamais_servi() {
    let conn = test_db();
    let id = ins_fts(&conn, "execve /usr/bin/dash par root");
    let mirrors = fts_bar_mirrors(&conn, false);

    // (a) MENSONGE 1 — seule, la phrase vide rend 0 ligne : « rien ne correspond ».
    assert!(match_rowids(&conn, &fts_quote("...")).unwrap().is_empty(), "phrase vide seule : 0 ligne");
    // (b) MENSONGE 2 — accompagnée, elle est purement IGNORÉE : le terme demandé disparaît de la
    //     question, et des lignes qui ne le contiennent pas sont servies comme si elles le contenaient.
    let avec = match_rowids(&conn, &format!("{} execve", fts_quote("..."))).unwrap();
    let sans = match_rowids(&conn, "execve").unwrap();
    assert_eq!(avec, sans, "phrase vide en conjonction : le terme est ignoré, la réponse est ÉLARGIE en silence");
    assert!(avec.contains(&id));

    // (c) LA GARDE : refus NOMMÉ, pour chacune des formes sans token.
    for terme in ["...", "---", "___", "*", "^"] {
        match fts_plan(&[terme.to_string()], &mirrors) {
            FtsPlan::Unindexable { token } => assert_eq!(token, terme, "le refus NOMME la saisie"),
            FtsPlan::Match { expr, .. } => panic!("terme « {terme} » servi comme `{expr}` : c'est l'un des deux mensonges ci-dessus"),
        }
    }
    // (d) ANTI-SUR-REFUS : un terme qui PORTE du texte n'est jamais déclaré inexprimable, même truffé
    //     de syntaxe. Sans ce contre-exemple, une garde qui refuse tout passerait (c) sans rien fermer.
    for terme in ["10.0.0.1", "a...b", "-x-", "exec(1)"] {
        assert!(
            matches!(fts_plan(&[terme.to_string()], &mirrors), FtsPlan::Match { .. }),
            "terme « {terme} » porte du texte : il DOIT rester cherchable"
        );
    }
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
//  (6) CE QUI MARCHAIT DOIT CONTINUER DE MARCHER — la garde préserve, elle ne dégrade pas.
// ════════════════════════════════════════════════════════════════════════════════════════════════

#[test]
fn les_operateurs_fts5_restent_operants_et_ne_sont_pas_litteralises() {
    let conn = test_db();
    let id_a = ins_fts(&conn, "alpha rouge");
    let id_b = ins_fts(&conn, "beta vert");
    let mirrors = fts_bar_mirrors(&conn, false);
    // Ces expressions PASSENT déjà aujourd'hui : la garde doit les rendre VERBATIM (literal vide),
    // sinon elle aurait « réparé » ce qui n'était pas cassé (et perdu le OR, le préfixe, le groupe).
    for saisie in ["alpha OR beta", "alph*", "(alpha OR beta)", "alpha NOT beta"] {
        match fts_plan(&tokens_de_la_barre(saisie), &mirrors) {
            FtsPlan::Match { expr, literal } => {
                assert!(literal.is_empty(), "saisie « {saisie} » : rien à littéraliser, le moteur l'accepte -> {literal:?}");
                assert_eq!(expr, saisie, "saisie « {saisie} » : rendue à l'octet près");
            }
            FtsPlan::Unindexable { token } => panic!("saisie « {saisie} » refusée sur « {token} »"),
        }
    }
    assert_eq!(match_rowids(&conn, "alpha OR beta").unwrap().len(), 2);
    assert_eq!(match_rowids(&conn, "alpha NOT beta").unwrap(), vec![id_a]);
    assert!(!match_rowids(&conn, "bet*").unwrap().contains(&id_a) && match_rowids(&conn, "bet*").unwrap().contains(&id_b));

    // LITTÉRALISATION SÉLECTIVE : mélangée à une IP, la troncature `fail*` reste un OPÉRATEUR. C'est
    // le gain de l'étage 2 sur une littéralisation totale — et il se mesure sur l'expression émise.
    let ins = ins_fts(&conn, "connexion 10.0.0.1 failed twice");
    match fts_plan(&tokens_de_la_barre("10.0.0.1 fail*"), &mirrors) {
        FtsPlan::Match { expr, literal } => {
            assert_eq!(literal, vec!["10.0.0.1".to_string()], "seule l'IP est littéralisée");
            assert_eq!(expr, "\"10.0.0.1\" fail*", "la troncature survit à la réparation");
            assert!(match_rowids(&conn, &expr).unwrap().contains(&ins));
        }
        FtsPlan::Unindexable { token } => panic!("refus inattendu sur « {token} »"),
    }
}

/// LA REQUÊTE DE PHRASE, RENDUE. `search_tokens` retire les guillemets de la saisie et le handler
/// re-joignait les tokens par un espace : `"failed password"` devenait un simple ET de deux mots, donc
/// AUCUNE requête de phrase n'était atteignable depuis la barre. Ce n'était pas un choix documenté —
/// c'était une perte au passage. Elle est rendue, et la propriété qui l'autorise est DÉRIVÉE : un token
/// porteur d'un blanc ne peut venir que d'une saisie entre guillemets, puisque `search_tokens` ne coupe
/// sur un blanc que HORS guillemets.
#[test]
fn une_saisie_entre_guillemets_redevient_une_requete_de_phrase() {
    let conn = test_db();
    let id_ordre = ins_fts(&conn, "sshd: failed password for root");
    let id_inverse = ins_fts(&conn, "password rotation failed hier");
    let mirrors = fts_bar_mirrors(&conn, false);
    let toks = tokens_de_la_barre("\"failed password\"");
    assert_eq!(toks, vec!["failed password".to_string()], "la barre rend UN token porteur d'un blanc");
    match fts_plan(&toks, &mirrors) {
        FtsPlan::Match { expr, literal } => {
            assert_eq!(expr, "\"failed password\"", "phrase citée, pas un ET de mots");
            assert_eq!(literal, vec!["failed password".to_string()]);
            let ids = match_rowids(&conn, &expr).unwrap();
            assert!(ids.contains(&id_ordre), "la phrase trouve la ligne où les mots sont adjacents et dans l'ordre");
            assert!(!ids.contains(&id_inverse), "et NON la ligne où ils sont dispersés — c'est tout l'intérêt");
        }
        FtsPlan::Unindexable { token } => panic!("refus inattendu sur « {token} »"),
    }
    // CONTRE-ÉPREUVE : l'ancien comportement (join par espace) rendait les deux lignes.
    assert_eq!(match_rowids(&conn, "failed password").unwrap().len(), 2, "sans guillemets : ET de mots, 2 lignes");
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
//  (7) LE MIROIR SUIT LA BASE VIVANTE — colonnes ET tokenizer.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/// L'oracle n'a de valeur que s'il est le MÊME moteur, sur le MÊME schéma. Ces deux index diffèrent par
/// leur tokenizer (`event_fields_fts` déclare `tokenchars '_-.:/@'`) et par leurs colonnes — et la garde
/// doit en tenir compte au lieu de supposer un schéma. MUTATION : faire renvoyer `None` à
/// `fts_tokenize_clause` (clause perdue) -> (a) rougit ; ignorer le second miroir -> (b) rougit.
#[test]
fn le_miroir_suit_le_tokenizer_et_les_colonnes_de_la_base() {
    let conn = test_db();
    conn.execute(crate::FTS_FIELDS_VTABLE_DDL, []).expect("DDL de production de event_fields_fts");
    let m_event = FtsMirror::derive(&conn, "event_fts").expect("miroir event_fts");
    let m_fields = FtsMirror::derive(&conn, "event_fields_fts").expect("miroir event_fields_fts");

    // (a) TOKENIZER : `...` n'a aucun token sous le tokenizer par défaut, mais `.` est un `tokenchar`
    //     de `event_fields_fts` -> il y EST indexable. Si la clause `tokenize=` n'était pas recopiée,
    //     les deux répondraient pareil et cette différence disparaîtrait.
    assert!(!m_event.retrieves(&fts_quote("..."), "..."), "tokenizer par défaut : `...` ne produit aucun token, donc rien ne le retrouve");
    assert!(m_fields.retrieves(&fts_quote("..."), "..."), "tokenchars '_-.:/@' : `...` EST un token — le miroir doit le savoir");
    assert!(m_fields.retrieves(&fts_quote("10.0.0.1"), "10.0.0.1") && m_event.retrieves(&fts_quote("10.0.0.1"), "10.0.0.1"),
        "les deux retrouvent une IP citée (en un ou quatre tokens selon le tokenizer)");

    // (b) COLONNES : un filtre de colonne valide sur l'un est invalide sur l'autre. La garde exige donc
    //     l'accord de TOUS les index interrogés — sinon `PLUME_FTS_FIELDS=1` casserait des saisies qui
    //     marchent avec le toggle à 0. Le toggle est passé en ARGUMENT (jamais lu en global ici).
    assert!(m_event.accepts("message:x").is_ok(), "`message` est une colonne de event_fts");
    assert!(m_fields.accepts("message:x").is_err(), "`message` n'existe pas dans event_fields_fts");
    let deux = fts_bar_mirrors(&conn, true);
    assert_eq!(deux.len(), 2, "toggle ON -> les DEUX index sont interrogés, donc les deux sont l'oracle");
    match fts_plan(&["message:x".to_string()], &deux) {
        FtsPlan::Match { expr, literal } => {
            assert_eq!(expr, "\"message:x\"", "désaccord entre les deux index -> littéralisation");
            assert_eq!(literal, vec!["message:x".to_string()]);
        }
        FtsPlan::Unindexable { token } => panic!("refus inattendu sur « {token} »"),
    }
    let un = fts_bar_mirrors(&conn, false);
    assert!(
        matches!(fts_plan(&["message:x".to_string()], &un), FtsPlan::Match { ref expr, .. } if expr == "message:x"),
        "toggle OFF -> le filtre de colonne reste un OPÉRATEUR : la garde suit le câblage, elle ne le suppose pas"
    );
}

/// SANS ORACLE, ON NE DEVINE PAS. Base sans index FTS5 (`event_fts` absente) : la garde rend le verbatim
/// et laisse le filet (c) du handler dire l'erreur du moteur. Une garde qui inventerait une réponse ici
/// serait exactement la `fts_safe` qu'on vient de retirer.
#[test]
fn sans_miroir_la_garde_ne_decide_rien() {
    let conn = Connection::open_in_memory().unwrap();
    let mirrors = fts_bar_mirrors(&conn, true);
    assert!(mirrors.is_empty(), "aucun index FTS5 -> aucun oracle");
    match fts_plan(&["10.0.0.1".to_string()], &mirrors) {
        FtsPlan::Match { expr, literal } => {
            assert_eq!(expr, "10.0.0.1", "verbatim : la garde s'abstient");
            assert!(literal.is_empty());
        }
        FtsPlan::Unindexable { token } => panic!("aucun refus ne peut être PROUVÉ sans oracle (« {token} »)"),
    }
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
//  (8) LE FILET (c) — une erreur du moteur ne devient JAMAIS un tableau vide.
// ════════════════════════════════════════════════════════════════════════════════════════════════

#[test]
fn une_erreur_du_moteur_est_dite_et_distinguee_dune_interruption() {
    // (a) REFUS : le message BRUT du moteur est remonté, et la réponse porte un `error`.
    let conn = test_db();
    let refus = match_rowids(&conn, "10.0.0.1").unwrap_err();
    let e = rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
        Some(refus.clone()),
    );
    let v = search_engine_error(&e);
    assert_eq!(v["results"], json!([]), "la forme reste compatible : `results` existe toujours");
    let msg = v["error"].as_str().expect("un refus DOIT porter un `error`");
    assert!(msg.contains("REFUS"), "le refus est nommé comme tel : {msg}");
    assert!(msg.contains(&refus), "le message du moteur est remonté VERBATIM, pas résumé : {msg}");

    // (b) INTERRUPTION : autre cause, autre conduite à tenir, et le seuil est LU (jamais recopié).
    let i = rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_INTERRUPT), None);
    let vi = search_engine_error(&i);
    let mi = vi["error"].as_str().expect("une interruption DOIT porter un `error`");
    assert!(mi.contains("INTERROMPUE"), "« trop long » n'est pas « rien trouvé » : {mi}");
    assert!(mi.contains(&READ_WATCHDOG_BUDGET_MS.to_string()), "le budget affiché doit venir de la constante : {mi}");
    assert_ne!(mi, msg, "les deux causes ne peuvent pas rendre le même message");
}

/// LE BOUT DU FIL : ce que voit vraiment un client de `/api/search`, à travers le routeur RÉEL
/// (auth + RBAC + sémaphore + pool de lecture + watchdog). Les tests ci-dessus prouvent la garde ;
/// celui-ci prouve qu'elle est CÂBLÉE — c'est précisément ce qui manquait à `fts_safe`, définie et
/// jamais appelée.
#[tokio::test]
async fn api_search_ne_rend_plus_un_tableau_vide_pour_les_cinq_saisies() {
    /// Encodage pourcent d'un composant de query-string (RFC 3986 : on ne laisse passer que le non-réservé).
    fn pct(s: &str) -> String {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
                _ => format!("%{b:02X}"),
            })
            .collect()
    }
    /// GET authentifié -> corps JSON. On lit jusqu'à EOF (`Connection: close`) : le corps entier, pas 64 octets.
    async fn get_json(addr: std::net::SocketAddr, path: &str, authz: &str) -> Value {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let req = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nAuthorization: {authz}\r\n\r\n");
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        let txt = String::from_utf8_lossy(&buf).into_owned();
        let corps = txt.split("\r\n\r\n").nth(1).unwrap_or_default().to_string();
        // Corps possiblement chunké : on repart du premier '{' jusqu'au dernier '}'.
        let (d, f) = (corps.find('{').unwrap_or(0), corps.rfind('}').map(|i| i + 1).unwrap_or(corps.len()));
        serde_json::from_str(&corps[d..f]).unwrap_or_else(|e| panic!("corps non-JSON ({e}) : {corps}"))
    }

    let (st, dbp) = router_test_state("barre-fts-e2e");
    {
        let conn = open_db(&dbp).unwrap();
        for s in SAISIES_ANALYSTE {
            ins_fts(&conn, &document_portant(s));
        }
    }
    let authz = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("root:rootpw1234567"));
    let addr = router_serve(st).await;

    for s in SAISIES_ANALYSTE {
        let v = get_json(addr, &format!("/api/search?q={}", pct(s)), &authz).await;
        let n = v["results"].as_array().map(|a| a.len()).unwrap_or(0);
        assert!(
            n > 0,
            "saisie « {s} » : l'analyste doit VOIR le document qui la contient — reçu {n} résultat(s), erreur={:?}",
            v.get("error")
        );
        assert_eq!(v["literal"]["terms"][0], json!(s), "la réponse DIT que le terme a été cherché littéralement : {v}");
    }
    // ET LE CAS QUI RESTE UN REFUS : il arrive AVEC un message, jamais comme un tableau vide muet.
    let v = get_json(addr, &format!("/api/search?q={}", pct("...")), &authz).await;
    assert_eq!(v["results"], json!([]), "aucun résultat servi");
    let err = v["error"].as_str().unwrap_or("");
    assert!(err.contains("..."), "le refus NOMME le terme : {v}");
    assert!(err.contains("regex="), "et il donne la voie qui, elle, cherche du texte brut : {v}");
    // LE FILET (c) BOUT EN BOUT : un motif regex invalide échoue DANS le moteur (`UserFunctionError`
    // levée par l'UDF `regexp` au premier pas), sur la branche STRUCTURÉE du handler — l'autre endroit
    // où un `{"results": []}` muet était rendu. La saisie est valide côté barre : rien en amont ne peut
    // l'attraper, seul le filet le peut.
    let v = get_json(addr, &format!("/api/search?q={}", pct("regex=(")), &authz).await;
    assert_eq!(v["results"], json!([]), "aucun résultat servi");
    let err = v["error"].as_str().unwrap_or("");
    assert!(err.contains("REFUS"), "l'échec du moteur est DIT, pas avalé : {v}");
    assert!(err.contains("regex"), "et il porte le message BRUT du moteur (motif regex invalide) : {v}");
    // TÉMOIN POSITIF : une saisie ordinaire rend des résultats SANS aucune mention de littéralisation.
    let v = get_json(addr, "/api/search?q=sentinelle", &authz).await;
    assert!(v["results"].as_array().map(|a| a.len()).unwrap_or(0) >= 5, "témoin positif : {v}");
    assert!(v.get("literal").is_none(), "rien n'a été réparé, donc rien n'est annoncé : {v}");
}

