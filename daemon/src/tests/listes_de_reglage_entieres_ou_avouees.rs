// =====================================================================================
// `P10.7-f` (rang 4, vague b) — LES DIX-NEUF LISTES DE RÉGLAGE SONT ENTIÈRES OU AVOUÉES.
//
// LE DÉFAUT MESURÉ (garde de famille `check_a_truncated_list_is_never_served_as_a_complete_one.py`,
// relevé du 2026-09-16) : les DIX-NEUF dernières accusations de RANG QUATRE, portées par DIX-NEUF
// fonctions de `daemon/src/handlers/`, lisaient leur liste par un itérateur de lignes APLATI
// (`.map(|x| x.flatten().collect())` sous un `and_then`, `.map(|rows| rows.flatten().collect())
// .unwrap_or_default()`, `rows.flatten().collect::<Vec<_>>()` derrière deux `unwrap()`). Un itérateur
// de lignes rusqlite rend des `Result` UNE LIGNE À LA FOIS : le mappeur peut échouer sur une seule
// ligne sans que la requête ait échoué — cache de schéma de pool périmé qui rend « no such table » au
// PREMIER pas (famille mesurée dans `flatten-avale-no-such-table-au-premier-pas`), colonne ajoutée par
// une migration que la connexion qui sert ne voit pas encore, valeur corrompue. L'aplatissement jetait
// CETTE ligne-là et rendait la suite, sous un corps rigoureusement identique à celui d'une liste
// complète : aucune clé ne changeait, aucun compte ne manquait.
//
// CE QUE CE RANG PARTAGE, ET QUI LUI EST PROPRE. Ce sont les listes de RÉGLAGE — celles sur lesquelles
// on conclut « ce n'est pas configuré ». Le geste qui suit cette conclusion n'est pas de chercher plus
// loin : c'est de FABRIQUER l'objet une seconde fois. Et la deuxième copie ne remplace pas la
// première, elle s'y AJOUTE, parce que l'objet avalé continue d'exister et d'AGIR — un canal de
// notification invisible émet quand même, un rapport planifié invisible s'exécute quand même sous son
// `run_as_role`, une règle d'ingestion invisible jette ou masque quand même des événements, un lookup
// invisible enrichit quand même toute recherche GXQL, une destination invisible exporte quand même hors
// du périmètre. Le silence du démon fabrique donc du DOUBLON opérant, jamais un simple trou d'affichage.
// Quatre sites portent en plus une gravité qui leur est propre, et elle est MESURÉE plutôt que supposée :
// `notifiers_list`, `processors_list` et `lookups_list` portaient DEUX `unwrap()` chacun (une table
// retirée les faisait PANIQUER, et une panique n'est pas un aveu) ; `host_settings_get` et
// `source_settings_get` avaient DEUX voies de silence (un 500 sur la préparation, un vecteur vide sur la
// ligne) ; `policies_list` et `silences_list` rendaient `{"policies": []}` / `{"silences": []}` en 200
// sur une préparation ratée, c'est-à-dire un fait établi.
//
// LES TROIS FORMES D'AVEU DU DÉPÔT, ET POURQUOI CHAQUE SITE A LA SIENNE.
//   * `liste_bornee::corps_de_liste_illisible` — QUINZE routes servent un OBJET JSON portant une seule
//     liste : la clé existe et est VIDE (un client qui lit `j.<cle>.length` continue de fonctionner) et
//     `error` porte `CAUSE_LISTE_ILLISIBLE`. Les valeurs DÉRIVÉES de la lecture retombent avec elle —
//     `ok` à `false` pour les deux tables de déclaration, exactement comme le catalogue des rôles du
//     rang un — et celles qui viennent d'une AUTRE lecture restent servies (la fiche d'un engagement, la
//     métadonnée d'un runbook, les compteurs live d'ingestion).
//   * LE CINQ CENTS NOMMÉ — DEUX routes ont un corps nominal qui est un TABLEAU NU
//     (`Json(Value::Array(..))`, `ai_providers_list` et `destinations_list`) : aucune clé où poser
//     l'aveu, et lui en donner une changerait le contrat. C'est la situation des fournisseurs
//     d'identité au rang un, et la forme retenue est la sienne à la lettre (`server_err`
//     + `CAUSE_LISTE_ILLISIBLE`).
//   * `liste_bornee::corps_de_listes_illisibles` — UNE route (`case_runbooks_json`) porte DEUX lectures
//     de lignes indépendantes, et l'aveu NOMME celle qui a échoué (`non_lus`), l'autre restant servie.
//     Les DEUX listes de `caseops.rs`, elles, servaient DÉJÀ le corps du fabricant borné
//     (`liste_bornee::corps`) avec sa branche `Lignes::Illisible` : solder en bloc y fait simplement
//     tomber aussi l'erreur de LIGNE, sans changer une seule clé.
//
// DEUX SITES REFUSENT AU LIEU D'AVOUER DANS LEUR CORPS, ET C'EST MESURÉ SUR CE QU'ILS PRODUISENT.
// `dominant_tactic_and_target` ne sert aucun corps : elle rend désormais un `rusqlite::Result`, parce
// que sa valeur ENTRE DANS UNE RECOMMANDATION — les tactiques sont COMPTÉES sur ses lignes et
// `max_by_key` élit la dominante, donc une alerte perdue peut changer le vainqueur, donc le runbook
// recommandé, donc la procédure déroulée. Et un échec TOTAL rendait `(None, None, défaut)`,
// indiscernable d'« aucune alerte liée », le cas où le repli générique `'*'` est LÉGITIME. Son second
// appelant, `case_runbook_attach`, REFUSE en 503 nommé sans rien écrire : attacher FIGE les étapes dans
// `case_step` et le geste est idempotent-REFUSANT, donc des cibles pré-remplies sur un échantillon
// amputé ne se corrigeraient pas par un second essai — c'est le raisonnement de la capture d'instantané
// de la vague A (produit figé), et `attach_runbook` refusait déjà dans ce même esprit sur des étapes
// non lues.
//
// CE QUE CES TÉMOINS JOUENT, ET POURQUOI DEUX VOIES. La voie de la TABLE RETIRÉE (renommée sous les
// pieds du gestionnaire) fait échouer la PRÉPARATION : elle prouve que la route n'invente plus une liste
// vide et ne panique plus. La voie de la LIGNE ILLISIBLE (un `BLOB` posé dans une colonne `TEXT` —
// SQLite conserve un blob tel quel quelle que soit l'affinité, et `get::<String>` le refuse) fait
// échouer le MAPPEUR sur UNE ligne, la requête restant saine : c'est LA voie que l'aplatissement
// avalait, et c'est elle qui tue la mutation. Chaque témoin porte son CONTRÔLE POSITIF (la liste
// complète, COMPTÉE par rapport à ce que la base porte déjà — jamais contre un nombre écrit à la main
// qui vieillirait au prochain semis) dans le même corps de test : sans lui, un aveu INCONDITIONNEL
// passerait pour un aveu.
//
// UNE EXCEPTION, MESURÉE ET DITE PLUTÔT QUE TUE : `ai_providers_list` N'EST PAS JOUÉE. Sa première
// instruction est `ai_gate!(au)`, qui rend 501 tant que le démon n'est pas compilé `--features ai`
// (`crate::ai::require_feature` : la variante sans la feature rend `Err`) — la lecture n'est donc JAMAIS
// atteinte dans le profil par défaut, et la jouer exigerait un `#[cfg(feature = "ai")]`, que ce lot
// s'interdit : aucun ATTRIBUT `#[cfg(feature …)]` n'est posé dans ce fichier — les dix-huit témoins
// tournent dans les DEUX profils mesurés. (Le MOTIF `cfg(feature`, lui, y apparaît cinq fois : quatre en
// PROSE, comme cette phrase-ci, et une dans la chaîne que la garde de source cherche dans
// `handlers/mod.rs`. Le dire ainsi plutôt que « aucun `cfg(feature` dans ce fichier » est délibéré : la
// seconde formulation est fausse dès qu'on la lit au `grep`, et une phrase qu'un `grep` dément
// n'enseigne rien.) Son témoin est donc une GARDE DE SOURCE sur le code de production, de la même famille que
// celui du responder local au rang un — avec, comme lui, un contrôle POSITIF de l'instrument : le
// lecteur est mis à l'épreuve sur un extrait FABRIQUÉ qui porte l'aplatissement, et il doit le voir.
// Le témoin joue AUSSI le 501, pour que la raison de son abstention soit prouvée et non alléguée.
//
// CE QUE CE LOT NE TIENT PAS, DIT PLUTÔT QUE SOUS-ENTENDU :
//   * la CONSOLE ne lit AUCUN de ces aveux JSON. Mesuré : `web/alerting.js:36,57-58` prend
//     `Array.isArray(d.silences)` et itère `d.policies` ; `web/detection_admin.js:533` fait de même pour
//     `d.notifiers` et peint « aucun canal — les alertes ne sont envoyées nulle part » ;
//     `web/lookups.js:48-50` peint « aucun lookup » ; `web/savedqueries.js:121` rend `[]` ;
//     `web/runbooks.js:42` peint la liste vide ; `web/cases.js:738` affiche la fiche de runbooks sans
//     regarder `non_lus`. Le démon avoue ; que la console le PEIGNE se juge dans
//     `check_a_refusal_is_not_rendered_as_an_absence.py`, pas ici. SEULS les deux tableaux nus sont déjà
//     lus de bout en bout, parce qu'ils refusent en HTTP (`fetchInto` écrit la cause dans le panneau) ;
//   * SIX routes de ce lot n'ont AUCUN consommateur dans `web/` au 2026-09-16 (`/api/ai/providers`,
//     `/api/hosts/settings` en GET, `/api/sources/settings` en GET, `/api/scheduled-reports`,
//     `/api/workflow-actions`, `/api/engagements/{id}`) : leur aveu est écrit pour l'API et pour un
//     opérateur, pas pour un écran ;
//   * aucun témoin ne joue `case_runbook_attach` de bout en bout : son refus est tenu par la FORME du
//     `Result` que `dominant_tactic_and_target` rend désormais, pas par une exécution ;
//   * `liste_bornee::lire` et `datamodels::object_field_allow` restent des ARBITRAGES ASSUMÉS de
//     l'ensemble nommé, et `fleet::host_inventory_simple` l'INDÉCIDABLE : ce lot n'y touche pas.
//     ADDENDUM DU 2026-09-16 (lot des connecteurs, écrit ici pour qu'aucune phrase de ce fichier
//     n'enseigne un arbre qui n'existe plus) : l'INDÉCIDABLE a depuis été TRANCHÉ — la fonction était
//     du CODE MORT (aucun appelant de production) et elle est SUPPRIMÉE de `fleet.rs`, ses deux
//     témoins rebranchés sur `hotes_du_panneau_bornes`. Les DEUX arbitrages assumés, eux, sont
//     toujours là, et c'est toujours ce lot-ci qui n'y touche pas.
// =====================================================================================

/// L'état file-backed de cette vague : schéma + migrations complets, un admin. MÊME fixture que les
/// quatre rangs précédents (`sp_state`) — cinq fixtures jumelles vieilliraient séparément.
fn lre_etat(tag: &str) -> (AppState, AuthUser, crate::tmp_possede::TmpDb) {
    let (st, p) = sp_state(&format!("lre-{tag}"));
    (st, sp_au("adm", "admin"), p)
}

/// CE QUE LA BASE PORTE DÉJÀ dans `table`, avant que le témoin n'y écrive. Le contrôle positif se mesure
/// PAR RAPPORT À CELA : un nombre écrit à la main vieillirait au premier semis ajouté par une migration,
/// et le témoin rougirait pour une raison ÉTRANGÈRE à ce qu'il prétend tenir.
fn lre_deja(st: &AppState, table: &str) -> usize {
    st.db
        .lock()
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get::<_, i64>(0))
        .unwrap_or_else(|e| panic!("fixture : la table `{table}` doit être lisible ({e})")) as usize
}

/// LE JUGEMENT D'UN CINQ CENTS NOMMÉ SUR UN CORPS NOMINALEMENT TABLEAU NU. Trois choses tombent
/// ensemble : le statut, le fait que le corps n'est PAS une liste (donc aucune façon de le lire
/// « aucune entrée configurée »), et la cause, qui est celle du fabricant unique.
fn lre_juger_le_refus(statut: u16, corps: &Value) {
    assert_eq!(statut, 500, "un tableau nu n'a aucune clé où poser un aveu : la liste non lue est un 5xx NOMMÉ, jamais un tableau court : {corps}");
    assert!(!corps.is_array(), "le corps du refus n'est PAS une liste : {corps}");
    assert!(
        corps["error"].as_str().unwrap_or("").contains("NON LUE"),
        "le refus NOMME sa cause : {corps}"
    );
}

/// RETIRE UNE COLONNE sous les pieds du gestionnaire — la seconde façon de faire échouer une
/// PRÉPARATION, nécessaire là où retirer la TABLE serait intercepté plus haut par une autre lecture.
/// Un renommage de colonne ne viole aucune contrainte et laisse la table comptable (`COUNT(*)` passe),
/// donc il ne touche QUE l'énoncé qui nomme la colonne.
fn lre_retirer_la_colonne(st: &AppState, table: &str, colonne: &str) {
    lsa_ecrire(st, &format!("ALTER TABLE {table} RENAME COLUMN {colonne} TO {colonne}_hors_d_atteinte;"));
}

/// LE CODE d'une fonction de production, COMMENTAIRES RETIRÉS. Les commentaires de ce dépôt RACONTENT le
/// défaut qu'un lot vient de fermer ; une garde de source qui les lirait interdirait de l'écrire — c'est
/// l'anti-motif « démentir une phrase fausse en la reproduisant ». La borne de fin est la première
/// fermante en colonne zéro, comme le témoin du responder local au rang un.
fn lre_code_de(fichier: &str, signature: &str) -> String {
    let src = std::fs::read_to_string(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(fichier))
        .unwrap_or_else(|e| panic!("instrument : `{fichier}` doit être lisible ({e})"));
    let debut = src.find(signature).unwrap_or_else(|| panic!("instrument : `{signature}` doit exister dans `{fichier}`"));
    let fin = src[debut..].find("\n}\n").map(|x| debut + x + 3).unwrap_or(src.len());
    src[debut..fin]
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Un engagement et ses permis — la fiche que `engagement_get` sert. Rend l'identifiant.
fn lre_engagement(st: &AppState) -> String {
    lsa_ecrire(
        st,
        "INSERT INTO engagement(id,name,box,scope,window_start,window_end,authorizer,reason,status,adapter,created,created_by) \
          VALUES('eng-temoin','Pentest de témoin','greybox','[\"203.0.113.0/24\"]',1000,2000,'DSI','autorisé','active','',1000,'adm');\
         INSERT INTO engagement_grant(engagement_id,kind,ref,idp_adapter,issued_ts,revoked_ts,status) \
          VALUES('eng-temoin','account','eng-cred-a','',1000,NULL,'issued');\
         INSERT INTO engagement_grant(engagement_id,kind,ref,idp_adapter,issued_ts,revoked_ts,status) \
          VALUES('eng-temoin','token','eng-tok-b','',1000,NULL,'issued');",
    );
    "eng-temoin".to_string()
}

/// Un runbook ACTIF portant DEUX étapes, écrit ici plutôt que cueilli d'un semis : mesuré au rang trois,
/// la chaîne de migrations ne sème AUCUN runbook sur une base neuve (`seed_runbooks` est appelé par
/// `tenants.rs`, pas par `migrate`), et un témoin qui dépendrait d'une semence absente rougirait pour une
/// raison ÉTRANGÈRE. `match_kind='*'` pour que `pick_runbook_id` ait toujours un repli à recommander.
fn lre_runbook(st: &AppState, cle: &str) -> i64 {
    lsa_ecrire(
        st,
        &format!(
            "INSERT INTO runbook(key,name,match_kind,match_key,description,managed,active,created) \
              VALUES('{cle}','Runbook de témoin','*','','procédure du témoin',0,1,1000);"
        ),
    );
    let rb: i64 = st.db.lock().query_row("SELECT id FROM runbook ORDER BY id DESC LIMIT 1", [], |r| r.get(0)).expect("fixture : le runbook est écrit");
    lsa_ecrire(
        st,
        &format!(
            "INSERT INTO runbook_step(runbook_id,ordinal,phase,title,guidance,step_kind,search_soql,action_kind) \
              VALUES({rb},1,'contain','Isoler la machine','couper le lien réseau','manual',NULL,NULL);\
             INSERT INTO runbook_step(runbook_id,ordinal,phase,title,guidance,step_kind,search_soql,action_kind) \
              VALUES({rb},2,'eradicate','Retirer la persistance','','manual',NULL,NULL);"
        ),
    );
    rb
}

// -------------------------------------------------------------------------------------
// (1) LES LIENS ET LES FILES D'UN DOSSIER — UN SEUL TÉMOIN, PARCE QUE LA FORME EST LA MÊME
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `case_links_json` et `case_queues_json` servent leur liste ENTIÈRE avec le total
/// borné qui l'accompagne ; une ligne illisible ou une table retirée rendent la liste NON ÉTABLIE (`[]`
/// + `error`) ET les deux chiffres dérivés `total`/`total_capped` à `null` — jamais `0`/`false`, qui se
/// lirait « ce dossier n'a aucun lien » ou « personne n'a de dossier ouvert, et c'est établi ».
///
/// POURQUOI UN SEUL TÉMOIN POUR DEUX FONCTIONS : leur forme est IDENTIQUE à la lettre — même fabricant
/// de corps (`liste_bornee::corps`), même branche d'échec DÉJÀ écrite (`Lignes::Illisible` +
/// `TotalBorne::sans_lecture()`), même geste de réparation (`collect::<rusqlite::Result<Vec<_>>>()` à la
/// place de `.map(|x| x.flatten().collect())` dans l'argument du `and_then`). Les jouer dans deux corps
/// jumeaux ferait deux témoins qui vieilliraient séparément.
///
/// CE QU'IL NE TIENT PAS : il ne joue pas la COUPE à la borne (`CASE_LINKS_WINDOW` /
/// `CASE_QUEUES_WINDOW`, tenue par `listes_bornees_ralliees.rs`), ni les routes HTTP qui enveloppent ces
/// deux fonctions dans un `read_with_watchdog` avec leur propre corps de repli.
///
/// LA MUTATION QUI LE FAIT ROUGIR, JOUÉE : rétablir `.map(|x| x.flatten().collect())` dans
/// `case_queues_json`. MESURÉ : le corps redevient `{"queues": [<une file sur deux>], "served": 1,
/// "total": 1, "total_capped": false}` sans `error` — une file de charge amputée d'un assigné, servie
/// comme complète et confirmée par son propre total.
#[test]
fn p10_7f_listes_de_reglage_les_liens_et_les_files_dun_dossier_sont_entiers_ou_avoues() {
    let conn = test_db();
    // CONTRÔLE POSITIF (liens) : deux dossiers liés, le lien visible depuis le premier.
    let a = case_create_row(&conn, "adm", "dossier A", 3, "", None, 2);
    let b = case_create_row(&conn, "adm", "dossier B", 3, "", None, 2);
    conn.execute(
        "INSERT INTO case_link(src_id,dst_id,kind,note,created,created_by) VALUES(?1,?2,'related','lié par le témoin',1000,'adm')",
        params![a, b],
    )
    .expect("fixture : le lien est écrit");
    let nominal = case_links_json(&conn, a);
    assert_eq!(nominal["links"].as_array().map(Vec::len), Some(1), "contrôle positif : le lien est servi : {nominal}");
    assert_eq!(nominal["total"], json!(1), "contrôle positif : le total borné est MESURÉ : {nominal}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET — un aveu inconditionnel n'est pas un aveu : {nominal}");

    // UNE LIGNE ILLISIBLE : `kind` porte un BLOB, que `get::<String>` refuse. La requête reste saine.
    conn.execute(
        "INSERT INTO case_link(src_id,dst_id,kind,note,created,created_by) VALUES(?1,?2,x'FF','',1001,'adm')",
        params![b, a],
    )
    .expect("fixture : le lien illisible est écrit");
    let avoue = case_links_json(&conn, a);
    lsa_juger_l_aveu(&avoue, "links");
    assert!(avoue["total"].is_null() && avoue["total_capped"].is_null(), "un total DÉRIVÉ d'une liste non lue est `null`, jamais `0`/`false` : {avoue}");

    lcs_retirer_la_table_conn(&conn, "case_link");
    let sans_table = case_links_json(&conn, a);
    lsa_juger_l_aveu(&sans_table, "links");

    // CONTRÔLE POSITIF (files) : deux assignés distincts -> deux seaux.
    let conn2 = test_db();
    case_create_row(&conn2, "adm", "ouvert 1", 3, "", Some("alice"), 2);
    case_create_row(&conn2, "adm", "ouvert 2", 3, "", Some("bob"), 2);
    let files = case_queues_json(&conn2, now());
    assert_eq!(files["queues"].as_array().map(Vec::len), Some(2), "contrôle positif : les deux files sont servies : {files}");
    assert_eq!(files["total"], json!(2), "contrôle positif : le total borné est MESURÉ : {files}");
    assert!(files.get("error").is_none(), "chemin nominal MUET : {files}");

    // UNE LIGNE ILLISIBLE : un assigné BLOB traverse `COALESCE(NULLIF(assignee,''),'(none)')` intact.
    conn2
        .execute(
            "INSERT INTO incident(ts,updated,title,status,severity,priority,assignee,archived) VALUES(1000,1000,'ouvert 3','open',3,2,x'FF',0)",
            [],
        )
        .expect("fixture : le dossier au propriétaire illisible est écrit");
    let avoue2 = case_queues_json(&conn2, now());
    lsa_juger_l_aveu(&avoue2, "queues");
    assert!(avoue2["total"].is_null(), "le total DÉRIVÉ retombe avec la liste : {avoue2}");

    lcs_retirer_la_table_conn(&conn2, "incident");
    let sans_table2 = case_queues_json(&conn2, now());
    lsa_juger_l_aveu(&sans_table2, "queues");
}

// -------------------------------------------------------------------------------------
// (2) LES DÉCLARATIONS D'HÔTES
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `host_settings_get` sert les DEUX déclarations de la fixture avec `ok: true` ; une
/// ligne illisible ou une table retirée rendent `settings` NON ÉTABLIE avec sa cause ET `ok` retombé à
/// `false`. Le point dur est `ok` : un corps qui affirme `ok: true` au-dessus d'une lecture jamais faite
/// est le mensonge exact que ce rang ferme — c'était déjà le défaut le plus grave du catalogue des rôles
/// au rang un.
///
/// CE QU'IL TIENT AUSSI, ET QUI EST PROPRE À CE SITE : la table retirée ne rend plus un 500 en texte
/// brut. Les DEUX voies disent le MÊME fait (« cette liste n'a pas été lue ») et le servent désormais
/// sous la MÊME forme — sans quoi tout consommateur devrait en connaître deux.
///
/// CE QU'IL NE TIENT PAS : il ne juge pas l'ÉCRITURE d'une déclaration (`host_settings_put`, son enum
/// fermé, son motif exigé et son double-audit, tenus par `hotes_declares.rs`), ni ce que l'inventaire de
/// flotte fait de ces déclarations.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.map(|it| it.flatten().collect()).unwrap_or_default()` —
/// le corps redevient `{"ok": true, "settings": [<une déclaration sur deux>]}` sans `error`, et les trois
/// asserts de la branche « ligne illisible » tombent ensemble.
#[tokio::test]
async fn p10_7f_listes_de_reglage_les_declarations_dhotes_sont_entieres_ou_avouees() {
    let (st, au, _p) = lre_etat("hosts");
    let deja = lre_deja(&st, "host_settings");
    lsa_ecrire(&st, "INSERT INTO host_settings(scope,host,attente,attente_motif,attente_par,attente_le,updated,updated_by) \
                      VALUES('global','web-1','silence_attendu','maintenance','adm',10,10,'adm');\
                     INSERT INTO host_settings(scope,host,attente,updated,updated_by) VALUES('global','db-1',NULL,20,'adm');");

    let (statut, nominal) = lsa_corps(host_settings_get(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200);
    assert_eq!(nominal["settings"].as_array().map(Vec::len), Some(deja + 2), "contrôle positif : les deux déclarations sont servies : {nominal}");
    assert_eq!(nominal["ok"], json!(true), "chemin nominal : la liste a bien été lue : {nominal}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET : {nominal}");

    lsa_ecrire(&st, "INSERT INTO host_settings(scope,host,updated,updated_by) VALUES('global',x'FF',30,'adm');");
    let (statut, avoue) = lsa_corps(host_settings_get(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200, "la forme du dépôt pour une liste JSON est `error` DANS le corps, pas un refus HTTP");
    lsa_juger_l_aveu(&avoue, "settings");
    assert_eq!(avoue["ok"], json!(false), "une liste NON LUE ne se sert pas avec `ok: true` : {avoue}");

    lsa_retirer_la_table(&st, "host_settings");
    let (statut, sans_table) = lsa_corps(host_settings_get(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200, "table retirée : le MÊME aveu que la ligne illisible, pas un 500 en texte brut");
    lsa_juger_l_aveu(&sans_table, "settings");
    assert_eq!(sans_table["ok"], json!(false), "table retirée : `ok` retombe aussi : {sans_table}");
}

// -------------------------------------------------------------------------------------
// (3) LES DÉCLARATIONS DE SOURCES
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `source_settings_get` sert les DEUX déclarations de la fixture avec `ok: true` ; une
/// ligne illisible ou une table retirée rendent `settings` NON ÉTABLIE avec sa cause et `ok: false`. Même
/// forme que les déclarations d'hôtes ci-dessus, et c'est voulu : c'est la MÊME table de déclaration à
/// deux colonnes-clés près, et deux formes d'aveu pour un même fait seraient une divergence de plus.
///
/// CE QUE LA LIGNE AVALÉE COÛTAIT ICI : `expected` retombait au DÉFAUT DE COLONNE pour la source
/// disparue — la source repassait « attendue » ou « inattendue » sans que personne ne l'ait dit, et la
/// cadence déclarée par un humain (« continue », avec son intervalle) s'évaporait de la vue qui existe
/// pour la relire.
///
/// CE QU'IL NE TIENT PAS : il ne juge ni `source_settings_put` (enum fermé, sévérité d'audit, verdict de
/// construction à la naissance de la ligne), ni l'inventaire `/api/sources` qui consomme ces
/// déclarations — ce lot tient la LISTE BRUTE servie.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.map(|it| it.flatten().collect()).unwrap_or_default()` —
/// `settings` redevient une liste courte avec `ok: true`.
#[tokio::test]
async fn p10_7f_listes_de_reglage_les_declarations_de_sources_sont_entieres_ou_avouees() {
    let (st, au, _p) = lre_etat("sources");
    let deja = lre_deja(&st, "source_settings");
    lsa_ecrire(&st, "INSERT INTO source_settings(scope,source,expected,label,cadence,cadence_interval_s,cadence_par,cadence_le,updated,updated_by) \
                      VALUES('global','pare-feu',1,'Pare-feu','continue',300,'adm',10,10,'adm');\
                     INSERT INTO source_settings(scope,source,expected,updated,updated_by) VALUES('global','syslog',0,20,'adm');");

    let (statut, nominal) = lsa_corps(source_settings_get(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200);
    assert_eq!(nominal["settings"].as_array().map(Vec::len), Some(deja + 2), "contrôle positif : les deux déclarations sont servies : {nominal}");
    assert_eq!(nominal["ok"], json!(true), "chemin nominal : la liste a bien été lue : {nominal}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET : {nominal}");

    lsa_ecrire(&st, "INSERT INTO source_settings(scope,source,expected,updated,updated_by) VALUES('global',x'FF',1,30,'adm');");
    let (_, avoue) = lsa_corps(source_settings_get(State(st.clone()), Extension(au.clone())).await).await;
    lsa_juger_l_aveu(&avoue, "settings");
    assert_eq!(avoue["ok"], json!(false), "une liste NON LUE ne se sert pas avec `ok: true` : {avoue}");

    lsa_retirer_la_table(&st, "source_settings");
    let (statut, sans_table) = lsa_corps(source_settings_get(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200, "table retirée : le MÊME aveu que la ligne illisible, pas un 500 en texte brut");
    lsa_juger_l_aveu(&sans_table, "settings");
}

// -------------------------------------------------------------------------------------
// (4) L'ARBRE DE ROUTAGE DES NOTIFICATIONS
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `policies_list` sert les DEUX politiques de la fixture ; une ligne illisible ou une
/// table retirée rendent `policies` NON ÉTABLIE avec sa cause, au lieu d'un arbre de routage
/// silencieusement raccourci. Le point propre à ce site est que la préparation ratée rendait
/// `{"policies": []}` EN 200 — c'est-à-dire un fait établi, écrit en toutes lettres dans le code : les
/// deux voies rendent désormais le même aveu.
///
/// POURQUOI CETTE ROUTE ET PAS SEULEMENT `load_policies` (fermée au rang deux) : le CHARGEMENT interne
/// décide du routage, mais c'est ICI que l'administrateur RELIT ce sur quoi le produit route. Une
/// politique absente de cette vue se lit « cette alerte n'est routée nulle part » ; on en crée une
/// seconde, et l'astreinte reçoit deux fois ce qu'une seule règle adressait.
///
/// CE QU'IL NE TIENT PAS : il ne juge ni le dispatch lui-même, ni la validation des matchers
/// (`policy_body`, `parse_matchers`), ni ce que `web/alerting.js:36` peint de l'aveu (il itère
/// `d.policies` sans regarder `error`).
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.map(|x| x.flatten().collect()).unwrap_or_default()` —
/// `policies` redevient une liste d'UNE politique sur deux, sans `error`.
#[tokio::test]
async fn p10_7f_listes_de_reglage_les_politiques_de_notification_sont_entieres_ou_avouees() {
    let (st, au, _p) = lre_etat("policies");
    let deja = lre_deja(&st, "notification_policy");
    lsa_ecrire(&st, "INSERT INTO notification_policy(matchers,contact_points,continue_,enabled,created,created_by) VALUES('{\"sev\":\"4\"}','1',0,1,10,'adm');\
                     INSERT INTO notification_policy(matchers,contact_points,continue_,enabled,created,created_by) VALUES('{\"host\":\"web-1\"}','1,2',1,1,20,'adm');");

    let nominal = policies_list(State(st.clone()), Extension(au.clone())).await.0;
    assert_eq!(nominal["policies"].as_array().map(Vec::len), Some(deja + 2), "contrôle positif : les deux politiques sont servies : {nominal}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET : {nominal}");

    lsa_ecrire(&st, "INSERT INTO notification_policy(matchers,contact_points,continue_,enabled,created,created_by) VALUES(x'FF','1',0,1,30,'adm');");
    let avoue = policies_list(State(st.clone()), Extension(au.clone())).await.0;
    lsa_juger_l_aveu(&avoue, "policies");

    lsa_retirer_la_table(&st, "notification_policy");
    let sans_table = policies_list(State(st.clone()), Extension(au.clone())).await.0;
    lsa_juger_l_aveu(&sans_table, "policies");
}

// -------------------------------------------------------------------------------------
// (5) LES SILENCES
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `silences_list` sert les DEUX silences de la fixture avec leur drapeau `active`
/// dérivé de l'horloge ; une ligne illisible ou une table retirée rendent `silences` NON ÉTABLIE avec sa
/// cause. Même cumul de silences fermé que pour les politiques : la préparation ratée rendait
/// `{"silences": []}` en 200.
///
/// CE QUE LA LIGNE AVALÉE COÛTAIT : un silence absent se lit « cette alerte n'est PAS silencée », et
/// c'est la lecture sur laquelle on décide de ne pas enquêter — ou d'en poser un second, qui prolongera
/// d'autant l'étouffement du signal. Un silence est temporisé PAR CONSTRUCTION (plafond de TTL) ; un
/// silence INVISIBLE, lui, ne se lève pas.
///
/// CE QU'IL NE TIENT PAS : il ne juge ni l'APPLICATION d'un silence au dispatch (`load_active_silences`,
/// fermée au rang deux), ni le plafond de durée à la création.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.map(|x| x.flatten().collect()).unwrap_or_default()` —
/// `silences` redevient une liste d'UN silence sur deux, sans `error`.
#[tokio::test]
async fn p10_7f_listes_de_reglage_les_silences_sont_entiers_ou_avoues() {
    let (st, au, _p) = lre_etat("silences");
    let deja = lre_deja(&st, "silence");
    lsa_ecrire(&st, "INSERT INTO silence(matchers,expires_at,reason,created,created_by) VALUES('{\"rule\":\"bruit\"}',4102444800,'maintenance',10,'adm');\
                     INSERT INTO silence(matchers,expires_at,reason,created,created_by) VALUES('{\"host\":\"db-1\"}',1,'expiré',20,'adm');");

    let nominal = silences_list(State(st.clone()), Extension(au.clone())).await.0;
    assert_eq!(nominal["silences"].as_array().map(Vec::len), Some(deja + 2), "contrôle positif : les deux silences sont servis : {nominal}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET : {nominal}");

    lsa_ecrire(&st, "INSERT INTO silence(matchers,expires_at,reason,created,created_by) VALUES(x'FF',4102444800,'blob',30,'adm');");
    let avoue = silences_list(State(st.clone()), Extension(au.clone())).await.0;
    lsa_juger_l_aveu(&avoue, "silences");

    lsa_retirer_la_table(&st, "silence");
    let sans_table = silences_list(State(st.clone()), Extension(au.clone())).await.0;
    lsa_juger_l_aveu(&sans_table, "silences");
}

// -------------------------------------------------------------------------------------
// (6) LES FOURNISSEURS D'IA — LE SEUL SITE QUE CE LOT NE PEUT PAS JOUER, ET IL LE PROUVE
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT (garde de FORME, sur la source de production, PLUS la raison de s'y résoudre) :
///   (a) la PORTE DE COMPILATION est lue sur l'arbre, pas alléguée : `daemon/src/handlers/mod.rs`
///       déclare `pub(crate) mod ai;` sous `#[cfg(feature = "ai")]`, donc dans le profil par défaut le
///       module n'est même pas COMPILÉ et le symbole `ai_providers_list` n'existe pas — l'appeler ici ne
///       compilerait pas. C'est la preuve, et non l'allégation, qu'un témoin de comportement exigerait
///       `--features ai`, donc un `#[cfg(feature = ...)]` que ce lot s'interdit (et qui rendrait le
///       témoin ABSENT des deux profils que ce lot mesure). Le fait est plus fort qu'un 501 de route :
///       il n'y a pas de route ;
///   (b) dans le CODE de `ai_providers_list` (commentaires exclus : ils DÉCRIVENT le défaut fermé), le
///       parcours est soldé en bloc (`collect::<rusqlite::Result<Vec<_>>>()`), aucune écriture
///       d'aplatissement ne subsiste, et la branche d'échec est un `server_err` portant
///       `CAUSE_LISTE_ILLISIBLE` — la forme du tableau nu, celle de `idp_providers_list` au rang un ;
///   (c) L'INSTRUMENT EST ÉPROUVÉ DANS LES DEUX SENS : le même lecteur, appliqué à un extrait FABRIQUÉ
///       qui porte l'aplatissement, le VOIT. Sans ce contrôle positif, les assertions de (b) seraient
///       vertes même si le lecteur rendait la chaîne vide.
///
/// CE QU'IL NE TIENT PAS, ET C'EST DIT : le comportement n'est PAS exercé. Aucune table retirée, aucune
/// ligne illisible ne traverse cette route ici — la propriété est tenue par la FORME de la source plus la
/// porte de compilation mesurée. C'est la même réserve que le témoin du responder local au rang un, pour
/// une cause différente (là-bas une connexion ouverte depuis la configuration, ici une porte de
/// compilation). RÉSERVE DE SECOND ORDRE, dite aussi : la CORRECTION elle-même n'est compilée que sous
/// `--features ai` ; elle a été vérifiée par un `cargo check --features ai` séparé, pas par les suites
/// que ce lot mesure.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.map(|rows| rows.flatten().collect())
/// .unwrap_or_default()` + `Err(_) => Vec::new()` — l'assert du solde en bloc, celui de l'absence
/// d'aplatissement et celui du refus nommé tombent tous les trois.
#[test]
fn p10_7f_listes_de_reglage_les_fournisseurs_dia_sont_entiers_ou_refuses() {
    // (a) LA PORTE DE COMPILATION, LUE SUR L'ARBRE : le module entier est derrière la feature.
    let mod_rs = std::fs::read_to_string(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/handlers/mod.rs"))
        .expect("instrument : `src/handlers/mod.rs` doit être lisible");
    assert!(
        mod_rs.contains("#[cfg(feature = \"ai\")]\npub(crate) mod ai;"),
        "le module IA est derrière une porte de COMPILATION : c'est POURQUOI ce site est tenu par une garde de source et non par un appel"
    );

    // (b) LA FORME DE LA SOURCE.
    let code = lre_code_de("src/handlers/ai.rs", "pub(crate) async fn ai_providers_list(");
    assert!(
        code.contains("collect::<rusqlite::Result<Vec<_>>>()"),
        "la liste des fournisseurs est SOLDÉE EN BLOC : une ligne illisible ne la raccourcit plus en silence"
    );
    assert!(
        !code.contains(".flatten()") && !code.contains("filter_map(Result::ok)"),
        "aucune écriture d'aplatissement ne subsiste dans le CODE de `ai_providers_list` :\n{}",
        code.lines().filter(|l| l.contains("flatten") || l.contains("filter_map")).collect::<Vec<_>>().join("\n")
    );
    assert!(
        code.contains("server_err(crate::handlers::liste_bornee::CAUSE_LISTE_ILLISIBLE)"),
        "le corps nominal est un TABLEAU NU : l'échec est un 5xx NOMMÉ (forme de `idp_providers_list`), jamais un tableau vide :\n{code}"
    );

    // (c) LE CONTRÔLE POSITIF DE L'INSTRUMENT : le même lecteur VOIT un aplatissement quand il y en a un.
    let fabrique = lre_code_de("src/handlers/liste_bornee.rs", "pub(crate) fn lire<F>(");
    assert!(
        fabrique.contains(".flatten()"),
        "instrument : le lecteur de source doit VOIR un aplatissement là où il y en a un — `liste_bornee::lire` en porte un, ASSUMÉ et documenté :\n{fabrique}"
    );
}

// -------------------------------------------------------------------------------------
// (7) LA FICHE D'UN ENGAGEMENT ET SES PERMIS
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `engagement_get` sert la fiche de l'engagement AVEC ses DEUX permis ; un permis dont
/// la ligne ne se décode pas, ou une table `engagement_grant` retirée, rendent `grants` NON ÉTABLIE avec
/// sa cause — et les champs de l'engagement (nom, portée, fenêtre, autorisant) RESTENT servis, parce
/// qu'ils viennent d'une AUTRE lecture, déjà faite. C'est la règle de `views_list` (`me`/`role`) et de
/// `dash_get` (métadonnées) transposée : un aveu ne prend en otage que ce qu'il couvre.
///
/// CE QUE LA LIGNE AVALÉE COÛTAIT : c'est la seule vue où l'on relit CE QUI A ÉTÉ OCTROYÉ pour un pentest
/// autorisé. Un permis absent se lit « il n'a jamais été émis », donc il n'y a rien à révoquer à la
/// clôture — un credential minté par le provisioning survit alors à l'engagement, sans que personne ne le
/// sache. La portée `scope`, elle, est lue par la MÊME requête que la fiche : elle n'est pas concernée.
///
/// CE QU'IL NE TIENT PAS : il ne joue ni le provisioning (qui PULL les permis 'pending' et écrit leur
/// `ref`), ni le sweep de révocation, ni la route `/api/engagements/active` (corps en tableau nu, fermée
/// au rang deux) ; et il ne dépend pas du mode engagement — `engagement_get` n'est gardée que par
/// `require_admin`.
///
/// LA MUTATION QUI LE FAIT ROUGIR, JOUÉE : rétablir `.map(|m| m.flatten().collect()).unwrap_or_default()`
/// à la place du solde en bloc. MESURÉ : le corps redevient `{"id":"eng-temoin", …,
/// "grants":[<un permis sur deux>]}` sans `error`, et le premier assert de `lsa_juger_l_aveu` tombe en
/// imprimant une fiche d'aspect complet à laquelle il manque un accès octroyé.
#[tokio::test]
async fn p10_7f_listes_de_reglage_la_fiche_dun_engagement_porte_tous_ses_permis_ou_lavoue() {
    let (st, au, _p) = lre_etat("engagement");
    let id = lre_engagement(&st);

    let (statut, nominal) = lsa_corps(engagement_get(State(st.clone()), Extension(au.clone()), Path(id.clone())).await).await;
    assert_eq!(statut, 200);
    assert_eq!(nominal["grants"].as_array().map(Vec::len), Some(2), "contrôle positif : les deux permis sont servis : {nominal}");
    assert_eq!(nominal["name"], json!("Pentest de témoin"), "contrôle positif : la fiche est servie : {nominal}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET : {nominal}");

    lsa_ecrire(&st, "INSERT INTO engagement_grant(engagement_id,kind,ref,idp_adapter,issued_ts,revoked_ts,status) VALUES('eng-temoin',x'FF','','',1000,NULL,'issued');");
    let (statut, avoue) = lsa_corps(engagement_get(State(st.clone()), Extension(au.clone()), Path(id.clone())).await).await;
    assert_eq!(statut, 200, "la forme du dépôt pour une liste JSON est `error` DANS le corps, pas un refus HTTP");
    lsa_juger_l_aveu(&avoue, "grants");
    assert_eq!(avoue["name"], json!("Pentest de témoin"), "la fiche vient d'une AUTRE lecture : elle reste servie : {avoue}");
    assert_eq!(avoue["scope"], json!(["203.0.113.0/24"]), "la portée est lue par la MÊME requête que la fiche : elle reste servie : {avoue}");

    lsa_retirer_la_table(&st, "engagement_grant");
    let (_, sans_table) = lsa_corps(engagement_get(State(st.clone()), Extension(au.clone()), Path(id)).await).await;
    lsa_juger_l_aveu(&sans_table, "grants");
    assert_eq!(sans_table["name"], json!("Pentest de témoin"), "table retirée : la fiche reste servie : {sans_table}");
}

// -------------------------------------------------------------------------------------
// (8) LES RAPPORTS PLANIFIÉS
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `reports_list` sert les DEUX rapports planifiés de la fixture ; une ligne illisible ou
/// une table retirée rendent `reports` NON ÉTABLIE avec sa cause.
///
/// CE QUE LA LIGNE AVALÉE COÛTAIT : un rapport absent se lit « rien n'est planifié ». On en crée un
/// second — qui portera le même nom et sera refusé par `name TEXT NOT NULL UNIQUE`, ou passera sous un
/// autre nom et DOUBLERA l'envoi périodique vers le canal. Pendant ce temps le planificateur continue
/// d'exécuter l'invisible, sous son `run_as_role` : une identité d'exécution qui n'apparaît plus nulle
/// part.
///
/// CE QU'IL NE TIENT PAS : il ne joue ni l'exécution d'un rapport (`report_run_now`, son masquage par
/// `run_as_role` et sa livraison au notifieur), ni le plafonnement du `run_as` au rôle du créateur —
/// tenus ailleurs. Aucun module de `web/` ne lit cette route au 2026-09-16.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.map(|rows| rows.flatten().collect())` puis
/// `.unwrap_or_default()` — `reports` redevient une liste d'UN rapport sur deux, sans `error`.
#[tokio::test]
async fn p10_7f_listes_de_reglage_les_rapports_planifies_sont_entiers_ou_avoues() {
    let (st, au, _p) = lre_etat("reports");
    let deja = lre_deja(&st, "scheduled_report");
    lsa_ecrire(&st, "INSERT INTO scheduled_report(name,dataset_id,notifier_id,run_as_role,tenant,interval_s,enabled,created,created_by,updated) VALUES('hebdo',1,1,'viewer','',604800,1,10,'adm',10);\
                     INSERT INTO scheduled_report(name,dataset_id,notifier_id,run_as_role,tenant,interval_s,enabled,created,created_by,updated) VALUES('quotidien',1,1,'admin','',86400,1,20,'adm',20);");

    let (statut, nominal) = lsa_corps(reports_list(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200);
    assert_eq!(nominal["reports"].as_array().map(Vec::len), Some(deja + 2), "contrôle positif : les deux rapports sont servis : {nominal}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET : {nominal}");

    lsa_ecrire(&st, "INSERT INTO scheduled_report(name,dataset_id,notifier_id,run_as_role,tenant,interval_s,enabled,created,created_by,updated) VALUES(x'FF',1,1,'viewer','',86400,1,30,'adm',30);");
    let (statut, avoue) = lsa_corps(reports_list(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200, "la forme du dépôt pour une liste JSON est `error` DANS le corps, pas un refus HTTP");
    lsa_juger_l_aveu(&avoue, "reports");

    lsa_retirer_la_table(&st, "scheduled_report");
    let (_, sans_table) = lsa_corps(reports_list(State(st.clone()), Extension(au.clone())).await).await;
    lsa_juger_l_aveu(&sans_table, "reports");
}

// -------------------------------------------------------------------------------------
// (9) LA TACTIQUE DOMINANTE — UNE LECTURE QUI ENTRE DANS UNE RECOMMANDATION
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `dominant_tactic_and_target` élit la tactique et la technique dominantes sur les
/// alertes liées, avec la cible best-effort ; une ligne illisible ou une table retirée rendent une
/// ERREUR, jamais un vainqueur élu sur un décompte amputé ni un `(None, None)` qui se relirait « ce
/// dossier n'a aucune alerte liée ».
///
/// LE POINT DUR, ET IL EST PROUVÉ ICI : c'est cette dernière confusion qui rendait la lecture dangereuse.
/// `None` est un état LÉGITIME — un dossier sans alerte liée tombe sur le repli générique `'*'`, et le
/// témoin le montre. Une lecture ratée rendait EXACTEMENT le même triplet, donc le même repli, avec le
/// même aplomb. Le `Result` sépare les deux : « aucune alerte » reste `Ok` et garde son repli, « pas lu »
/// remonte à l'appelant.
///
/// CE QU'IL TIENT AUSSI : qu'une ligne avalée CHANGE le vainqueur, mesuré et non supposé. Deux alertes
/// `T1190` (initial-access) et une `T1110` (credential-access) donnent `initial-access` ; si l'une des
/// deux `T1190` est illisible, l'égalité 1-1 ferait basculer le dominant sur le tie-break lexicographique
/// (`credential-access`) — et donc le runbook recommandé. La branche d'échec rend l'erreur AVANT que ce
/// basculement puisse être servi.
///
/// CE QU'IL NE TIENT PAS : il ne joue pas `case_runbook_attach` (dont le refus 503 est tenu par la FORME
/// du `Result`), ni le tie-break déterministe lui-même (`incidents.rs::dominant_tactic_tie_break_is_
/// deterministic`), ni `pick_runbook_id`, qui n'est pas de cette famille (ses lectures sont des
/// `query_row(..).ok()`, la famille VOISINE que la garde ne juge pas).
///
/// LA MUTATION QUI LE FAIT ROUGIR, JOUÉE : rétablir `.map(|x| x.flatten().collect()).unwrap_or_default()`.
/// MESURÉ : la fonction rend `Ok` sur la branche « ligne illisible », l'`expect_err` panique, et le
/// message imprime le triplet servi — une tactique élue sur deux alertes sur trois.
#[test]
fn p10_7f_listes_de_reglage_la_tactique_dominante_nest_pas_elue_sur_des_alertes_non_lues() {
    let conn = test_db();
    let id = case_create_row(&conn, "adm", "intrusion", 4, "", None, 2);
    link_alert(&conn, id, "T1190", Some("web-1"));
    link_alert(&conn, id, "T1190", None);
    link_alert(&conn, id, "T1110", None);

    // CONTRÔLE POSITIF : le vainqueur est élu sur les TROIS alertes.
    let (tac, tech, cibles) = dominant_tactic_and_target(&conn, id).expect("contrôle positif : les alertes liées sont lisibles");
    assert_eq!(tac.as_deref(), Some("initial-access"), "contrôle positif : la tactique majoritaire gagne");
    assert_eq!(tech.as_deref(), Some("T1190"), "contrôle positif : la technique majoritaire gagne");
    assert_eq!(cibles.host.as_deref(), Some("web-1"), "contrôle positif : la cible best-effort est pré-remplie");

    // CONTRÔLE POSITIF (le second, et c'est lui qui donne son sens à l'aveu) : AUCUNE alerte liée est un
    // FAIT, pas un aveu — le triplet vide reste `Ok`, et c'est le cas où le repli générique est légitime.
    let vide = case_create_row(&conn, "adm", "sans alerte", 2, "", None, 3);
    let (tac_vide, tech_vide, _) = dominant_tactic_and_target(&conn, vide).expect("aucune alerte liée est un fait LU");
    assert_eq!((tac_vide, tech_vide), (None, None), "aucune alerte liée -> triplet vide, mais LU");

    // UNE LIGNE ILLISIBLE : `alert.mitre` porte un BLOB (COALESCE le laisse tel quel), et il suffirait à
    // faire basculer le vainqueur si la ligne était simplement jetée.
    conn.execute("UPDATE alert SET mitre=x'FF' WHERE mitre='T1190' AND host IS NULL", [])
        .expect("fixture : la ligne illisible est posée");
    let refus = dominant_tactic_and_target(&conn, id);
    assert!(
        refus.is_err(),
        "une ligne illisible NE DOIT PAS élire un vainqueur : une tactique servie ici change le runbook recommandé — servi : {:?}",
        refus.map(|(t, k, _)| (t, k))
    );

    // LA TABLE RETIRÉE : la préparation échoue. Avant, elle rendait `(None, None, défaut)`, c'est-à-dire
    // le triplet EXACT d'un dossier sans alerte — le repli générique servi comme un choix fondé.
    lcs_retirer_la_table_conn(&conn, "alert");
    assert!(
        dominant_tactic_and_target(&conn, id).is_err(),
        "table retirée : refus, jamais le triplet vide qui se confond avec « aucune alerte liée »"
    );
}

// -------------------------------------------------------------------------------------
// (10) LA FICHE DE RUNBOOKS D'UN DOSSIER — DEUX LECTURES, L'AVEU NOMME LAQUELLE
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `case_runbooks_json` sert la tactique dominante, le runbook recommandé et le
/// catalogue `available` ; et — c'est le point dur — quand UNE des deux lectures de lignes échoue, l'aveu
/// la NOMME (`non_lus`) et l'AUTRE reste servie. Deux propriétés distinctes tombent avec chacune :
///   * `alertes_liees` non lue -> `dominant_tactic`, `dominant_technique` ET `recommended` valent `null`
///     (`pick_runbook_id` n'est même pas appelé : recommander sur un décompte amputé, c'est dérouler la
///     mauvaise procédure avec l'aplomb d'une procédure lue), `available` restant servi et compté ;
///   * `available` non lu -> le catalogue est vide et nommé, la dominante et la recommandation restant
///     servies.
/// Le nom `alertes_liees` n'apparaît QUE dans l'aveu, parce que cette liste n'est pas servie — ce sont
/// ses DÉRIVÉS qui le sont —, et c'est précisément pour cela qu'il faut la nommer : sans elle,
/// `dominant_tactic: null` + `recommended: null` se relit « ce dossier n'a aucune alerte liée ».
///
/// CE QU'IL NE TIENT PAS : il ne juge ni `runbook_attache` (un `query_row(..).ok()`, famille voisine),
/// ni la projection client-read de cette fiche, ni ce que `web/cases.js:738` en peint (il lit `rb` sans
/// regarder `non_lus`).
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.map(|x| x.flatten().collect()).unwrap_or_default()` sur
/// `available` — le catalogue redevient une liste courte sans `non_lus`, et le premier assert de
/// `lco_juger_l_aveu_nomme` tombe.
#[test]
fn p10_7f_listes_de_reglage_la_fiche_de_runbooks_dun_dossier_nomme_la_lecture_ratee() {
    let conn = test_db();
    let id = case_create_row(&conn, "adm", "intrusion", 4, "", None, 2);
    link_alert(&conn, id, "T1190", Some("web-1"));
    link_alert(&conn, id, "T1190", None);
    conn.execute(
        "INSERT INTO runbook(key,name,match_kind,match_key,description,managed,active,created) VALUES('temoin-generique','Repli','*','','',0,1,1000)",
        [],
    )
    .expect("fixture : le runbook générique est écrit");

    let nominal = case_runbooks_json(&conn, id).expect("contrôle positif : le dossier existe");
    assert_eq!(nominal["available"].as_array().map(Vec::len), Some(1), "contrôle positif : le catalogue est servi : {nominal}");
    assert_eq!(nominal["dominant_tactic"], json!("initial-access"), "contrôle positif : la dominante est élue : {nominal}");
    assert!(!nominal["recommended"].is_null(), "contrôle positif : un runbook est recommandé : {nominal}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET : {nominal}");
    assert!(nominal.get("non_lus").is_none(), "chemin nominal : aucune lecture n'est nommée non lue : {nominal}");

    // (a) LE CATALOGUE NON LU : une ligne illisible dans `runbook.key`. La dominante, elle, reste servie.
    conn.execute(
        "INSERT INTO runbook(key,name,match_kind,match_key,description,managed,active,created) VALUES(x'FF','Illisible','*','','',0,1,1001)",
        [],
    )
    .expect("fixture : le runbook illisible est écrit");
    let sans_catalogue = case_runbooks_json(&conn, id).expect("le dossier existe toujours");
    lco_juger_l_aveu_nomme(&sans_catalogue, "available", &[]);
    assert_eq!(sans_catalogue["dominant_tactic"], json!("initial-access"), "l'AUTRE lecture a abouti : elle reste servie : {sans_catalogue}");
    assert!(!sans_catalogue["recommended"].is_null(), "la recommandation ne DÉRIVE pas du catalogue servi : elle reste servie : {sans_catalogue}");

    // (b) LES ALERTES NON LUES : c'est ELLES qui sont nommées, et le catalogue REDEVIENT servi. La ligne
    // blob du catalogue est retirée d'abord, sinon DEUX lectures échoueraient et le témoin ne prouverait
    // plus que l'aveu désigne la BONNE — il se contenterait de constater qu'il y en a un.
    conn.execute("DELETE FROM runbook WHERE typeof(key)='blob'", []).expect("fixture : la ligne blob est retirée");
    conn.execute("UPDATE alert SET mitre=x'FF' WHERE host IS NULL", []).expect("fixture : l'alerte illisible est posée");
    let sans_dominante = case_runbooks_json(&conn, id).expect("le dossier existe toujours");
    lco_juger_l_aveu_nomme(&sans_dominante, "alertes_liees", &[("available", 1)]);
    assert!(sans_dominante["dominant_tactic"].is_null(), "une dominante élue sur des alertes non lues n'est pas servie : {sans_dominante}");
    assert!(sans_dominante["dominant_technique"].is_null(), "la technique tombe avec la tactique : {sans_dominante}");
    assert!(
        sans_dominante["recommended"].is_null(),
        "AUCUN runbook n'est recommandé quand la dominante n'a pas été lue — le repli générique existe pourtant dans le catalogue : {sans_dominante}"
    );

    // (c) LA TABLE RETIRÉE : la préparation du catalogue échoue. Avant, elle rendait `available: []`, qui
    // se lit « aucune procédure n'est définie » au milieu d'un incident.
    conn.execute("UPDATE alert SET mitre='T1190' WHERE typeof(mitre)='blob'", []).expect("fixture : l'alerte redevient lisible");
    lcs_retirer_la_table_conn(&conn, "runbook");
    let sans_table = case_runbooks_json(&conn, id).expect("le dossier existe toujours");
    lco_juger_l_aveu_nomme(&sans_table, "available", &[]);
    assert_eq!(sans_table["dominant_tactic"], json!("initial-access"), "table retirée : la dominante reste servie : {sans_table}");
}

// -------------------------------------------------------------------------------------
// (11) LE CATALOGUE D'AUTHORING DES RUNBOOKS
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `runbooks_admin_list` sert le catalogue ENTIER avec le nombre d'étapes de chaque
/// runbook ; une ligne illisible ou une table retirée rendent `runbooks` NON ÉTABLIE avec sa cause.
///
/// CE QUE LA LIGNE AVALÉE COÛTAIT : c'est la page où l'on CRÉE des runbooks. Un runbook absent s'y lit
/// « cette procédure n'existe pas » ; on en écrit un second, qui portera la même `key`
/// (`TEXT NOT NULL UNIQUE`) et sera refusé, ou un autre nom et concurrencera le premier au moment du
/// `match_kind`/`match_key`. Le compte d'étapes servi à côté est un sous-`SELECT` de la MÊME ligne : il
/// disparaît avec elle.
///
/// CE QU'IL NE TIENT PAS : il ne joue ni la création/clonage/suppression d'un runbook custom, ni la
/// garde `managed=1 -> 403`, ni ce que `web/runbooks.js:42` peint de l'aveu (il rend la liste vide).
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.map(|x| x.flatten().collect())` puis
/// `.unwrap_or_default()` — `runbooks` redevient une liste courte sans `error`.
#[tokio::test]
async fn p10_7f_listes_de_reglage_le_catalogue_des_runbooks_est_entier_ou_avoue() {
    let (st, au, _p) = lre_etat("runbooks");
    let deja = lre_deja(&st, "runbook");
    lre_runbook(&st, "temoin-a");
    lre_runbook(&st, "temoin-b");

    let (statut, nominal) = lsa_corps(runbooks_admin_list(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200);
    assert_eq!(nominal["runbooks"].as_array().map(Vec::len), Some(deja + 2), "contrôle positif : les deux runbooks sont servis : {nominal}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET : {nominal}");

    lsa_ecrire(&st, "INSERT INTO runbook(key,name,match_kind,match_key,description,managed,active,created) VALUES(x'FF','Illisible','*','','',0,1,1002);");
    let (statut, avoue) = lsa_corps(runbooks_admin_list(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200, "la forme du dépôt pour une liste JSON est `error` DANS le corps, pas un refus HTTP");
    lsa_juger_l_aveu(&avoue, "runbooks");

    lsa_retirer_la_table(&st, "runbook");
    let (_, sans_table) = lsa_corps(runbooks_admin_list(State(st.clone()), Extension(au.clone())).await).await;
    lsa_juger_l_aveu(&sans_table, "runbooks");
}

// -------------------------------------------------------------------------------------
// (12) LES ÉTAPES D'UN RUNBOOK
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `runbook_get` sert la métadonnée du runbook ET ses DEUX étapes sous `step_list` ; une
/// étape dont la ligne ne se décode pas, ou une table `runbook_step` retirée, rendent `step_list` NON
/// ÉTABLIE avec sa cause — la métadonnée, qui vient d'une AUTRE lecture déjà faite, restant servie.
///
/// CE QUE LA LIGNE AVALÉE COÛTAIT, ET C'EST LE PIRE DE CE RANG : `step_list` est la liste QU'ON SUIT.
/// Sauter une étape de confinement au milieu d'un incident se faisait alors sans que rien ne l'écrive. Et
/// le formulaire d'édition RÉENREGISTRE ce qu'il a affiché (la mise à jour remplace TOUTES les étapes) :
/// une troncature de LECTURE devenait une troncature PERSISTÉE, que plus aucune relecture ne pouvait
/// démentir.
///
/// LA VOIE « PRÉPARATION RATÉE » PASSE ICI PAR UNE COLONNE RETIRÉE, ET C'EST MESURÉ PLUTÔT QUE CHOISI :
/// retirer la TABLE `runbook_step` casse d'ABORD la métadonnée, dont le sous-`SELECT` la compte — la
/// route rend alors « runbook introuvable » (404), ce qui est un défaut d'une AUTRE famille (un
/// `query_row(..).ok()`, la famille VOISINE que cette garde ne juge pas) et masquerait la propriété
/// qu'on veut tenir. Retirer la seule colonne `search_soql`, que l'énoncé des ÉTAPES nomme et que le
/// `COUNT(*)` ignore, fait échouer la PRÉPARATION de cette lecture-là et d'elle seule.
///
/// CE QU'IL NE TIENT PAS : il ne joue ni l'édition (`runbook_update_handler`), ni l'INSTANCIATION des
/// étapes dans un dossier (`attach_runbook`, qui soldait déjà son parcours en bloc et REFUSE, lot 106),
/// ni le compte `steps` de la métadonnée, qui est un sous-`SELECT` d'une autre lecture ; il ne dit rien
/// non plus du 404 que rend une table `runbook_step` ENTIÈREMENT retirée — c'est la famille voisine.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.map(|x| x.flatten().collect())` puis
/// `.unwrap_or_default()` — `step_list` redevient une procédure amputée d'une étape, servie comme
/// complète.
#[tokio::test]
async fn p10_7f_listes_de_reglage_les_etapes_dun_runbook_sont_entieres_ou_avouees() {
    let (st, au, _p) = lre_etat("runbook-get");
    let rb = lre_runbook(&st, "temoin-etapes");

    let (statut, nominal) = lsa_corps(runbook_get(State(st.clone()), Extension(au.clone()), Path(rb)).await).await;
    assert_eq!(statut, 200);
    assert_eq!(nominal["step_list"].as_array().map(Vec::len), Some(2), "contrôle positif : les deux étapes sont servies : {nominal}");
    assert_eq!(nominal["key"], json!("temoin-etapes"), "contrôle positif : la métadonnée est servie : {nominal}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET : {nominal}");

    lsa_ecrire(&st, &format!("INSERT INTO runbook_step(runbook_id,ordinal,phase,title,guidance,step_kind,search_soql,action_kind) VALUES({rb},3,'recover',x'FF','','manual',NULL,NULL);"));
    let (statut, avoue) = lsa_corps(runbook_get(State(st.clone()), Extension(au.clone()), Path(rb)).await).await;
    assert_eq!(statut, 200, "la forme du dépôt pour une liste JSON est `error` DANS le corps, pas un refus HTTP");
    lsa_juger_l_aveu(&avoue, "step_list");
    assert_eq!(avoue["key"], json!("temoin-etapes"), "la métadonnée vient d'une AUTRE lecture : elle reste servie : {avoue}");

    lre_retirer_la_colonne(&st, "runbook_step", "search_soql");
    let (statut, sans_colonne) = lsa_corps(runbook_get(State(st.clone()), Extension(au.clone()), Path(rb)).await).await;
    assert_eq!(statut, 200, "préparation ratée : l'aveu est dans le corps, et la métadonnée reste servie");
    lsa_juger_l_aveu(&sans_colonne, "step_list");
    assert_eq!(sans_colonne["key"], json!("temoin-etapes"), "préparation ratée : la métadonnée reste servie : {sans_colonne}");
}

// -------------------------------------------------------------------------------------
// (13) LES CANAUX DE NOTIFICATION
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `notifiers_list` sert les DEUX canaux de la fixture avec leur `has_auth` ; une ligne
/// illisible rend `notifiers` NON ÉTABLIE avec sa cause ; et une table `notifier` retirée ne fait plus
/// PANIQUER la route (elle portait deux `unwrap()`), elle avoue.
///
/// CE QUE LA LIGNE AVALÉE COÛTAIT : un canal absent se lit « aucune notification n'est configurée là » —
/// et `web/detection_admin.js:535` peint littéralement « aucun canal - les alertes ne sont envoyées nulle
/// part ». L'administrateur en crée un second vers la MÊME destination et l'astreinte reçoit tout en
/// double, pendant que le canal invisible continue d'émettre : le dispatch lit la table, pas cette vue.
///
/// CE QU'IL NE TIENT PAS : il ne juge ni la non-projection du secret (`config` n'est jamais rendu ;
/// `has_auth` seul — tenu par les témoins de notifieurs existants), ni l'envoi de test, ni la garde SSRF
/// à la création.
///
/// LA MUTATION QUI LE FAIT ROUGIR, JOUÉE : rétablir `rows.flatten().collect::<Vec<_>>()` derrière les deux
/// `unwrap()`. MESURÉ : sur la branche « ligne illisible » le corps redevient `{"notifiers": [<deux
/// canaux sur trois>]}` sans `error` — le premier assert de `lsa_juger_l_aveu` tombe en imprimant la
/// liste amputée — et sur la branche « table retirée » la route PANIQUE au lieu d'avouer, le test
/// échouant alors par `unwrap()` sur `no such table: notifier`.
#[tokio::test]
async fn p10_7f_listes_de_reglage_les_canaux_de_notification_sont_entiers_ou_avoues() {
    let (st, au, _p) = lre_etat("notifiers");
    let deja = lre_deja(&st, "notifier");
    lsa_ecrire(&st, "INSERT INTO notifier(name,kind,enabled,url,min_severity,config) VALUES('astreinte','ntfy',1,'https://ntfy.example/soc',3,'{\"token\":\"x\"}');\
                     INSERT INTO notifier(name,kind,enabled,url,min_severity,config) VALUES('courriel','email',1,'smtp://relais.interne:25',2,'{}');");

    let (statut, nominal) = lsa_corps(notifiers_list(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200);
    assert_eq!(nominal["notifiers"].as_array().map(Vec::len), Some(deja + 2), "contrôle positif : les deux canaux sont servis : {nominal}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET : {nominal}");

    lsa_ecrire(&st, "INSERT INTO notifier(name,kind,enabled,url,min_severity,config) VALUES(x'FF','ntfy',1,'https://ntfy.example/z',2,'{}');");
    let (statut, avoue) = lsa_corps(notifiers_list(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200, "la forme du dépôt pour une liste JSON est `error` DANS le corps, pas un refus HTTP");
    lsa_juger_l_aveu(&avoue, "notifiers");

    lsa_retirer_la_table(&st, "notifier");
    let (_, sans_table) = lsa_corps(notifiers_list(State(st.clone()), Extension(au.clone())).await).await;
    lsa_juger_l_aveu(&sans_table, "notifiers");
}

// -------------------------------------------------------------------------------------
// (14) LES DESTINATIONS DE SORTIE
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `destinations_list` sert les DEUX destinations configurées ; une ligne illisible ou
/// une table retirée rendent un 5xx qui NOMME sa cause et dont le corps n'est PAS un tableau — donc
/// aucune façon de le lire « rien n'est exporté ».
///
/// POURQUOI UN REFUS ET NON UN `error` DANS LE CORPS : le corps nominal est un TABLEAU NU, sans aucune
/// clé où poser l'aveu, et `web/destinations.js:24` reçoit et itère un tableau. C'est la situation exacte
/// des fournisseurs d'identité au rang un, et la forme retenue est la sienne. `fetchInto` écrit déjà la
/// cause dans le panneau sur un non-2xx : cet aveu-là, contrairement aux quinze autres du lot, est lu de
/// bout en bout AUJOURD'HUI.
///
/// CE QUE LA LIGNE AVALÉE COÛTAIT : une destination absente se lit « rien n'est exporté vers là », alors
/// que le forward CONTINUE (le balayage de sortie lit la table, pas cette vue) — la console montrerait un
/// périmètre de SORTIE plus petit que le réel, et le `watermark`/`error_count` de ce sink, qui sont
/// l'observabilité de son lag, deviendraient invisibles.
///
/// CE QU'IL NE TIENT PAS : il ne joue ni le forward lui-même, ni le `flush` immédiat, ni la non-projection
/// du secret d'auth.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.map(|rows| rows.flatten().collect()).unwrap_or_default()`
/// + `Err(_) => Vec::new()` — la route rend 200 et un tableau d'UNE destination, et l'assert du statut
/// tombe.
#[tokio::test]
async fn p10_7f_listes_de_reglage_les_destinations_de_sortie_sont_entieres_ou_refusees() {
    let (st, au, _p) = lre_etat("destinations");
    let deja = lre_deja(&st, "destination");
    lsa_ecrire(&st, "INSERT INTO destination(type,name,enabled,endpoint,config,filter,batch_max,interval_s,created) VALUES('webhook','SIEM central',1,'https://siem.example/in','{\"auth_header\":\"x\"}','{}',500,30,10);\
                     INSERT INTO destination(type,name,enabled,endpoint,config,filter,batch_max,interval_s,created) VALUES('hec','Splunk',0,'https://hec.example','{}','{}',500,30,20);");

    let (statut, nominal) = lsa_corps(destinations_list(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200);
    assert_eq!(nominal.as_array().map(Vec::len), Some(deja + 2), "contrôle positif : les deux destinations sont servies : {nominal}");

    lsa_ecrire(&st, "INSERT INTO destination(type,name,enabled,endpoint,config,filter,batch_max,interval_s,created) VALUES(x'FF','Illisible',1,'https://z.example','{}','{}',500,30,30);");
    let (statut, refus) = lsa_corps(destinations_list(State(st.clone()), Extension(au.clone())).await).await;
    lre_juger_le_refus(statut, &refus);

    lsa_retirer_la_table(&st, "destination");
    let (statut, sans_table) = lsa_corps(destinations_list(State(st.clone()), Extension(au.clone())).await).await;
    lre_juger_le_refus(statut, &sans_table);
}

// -------------------------------------------------------------------------------------
// (15) LES PROCESSEURS D'INGESTION
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `processors_list` sert les DEUX règles d'ingestion de la fixture À CÔTÉ des compteurs
/// live ; une ligne illisible rend `rules` NON ÉTABLIE avec sa cause, et une table `ingest_rule` retirée
/// ne fait plus PANIQUER la route (elle portait deux `unwrap()`), elle avoue. Les COMPTEURS restent
/// servis dans les deux cas : ils viennent du registre chaud en mémoire, pas de cette lecture — et c'est
/// ce qui rend le désaccord LISIBLE (un compteur qui bouge au-dessus d'une liste non lue) au lieu d'être
/// muet.
///
/// CE QUE LA LIGNE AVALÉE COÛTAIT : c'est la seule vue qui dit CE QUI ARRIVE AUX ÉVÉNEMENTS avant
/// indexation. Une règle avalée continue de s'appliquer (le registre chaud est compilé ailleurs) : une
/// règle `drop` ou `mask` invisible explique une donnée absente ou caviardée que plus rien ne rattache à
/// une décision — et l'administrateur conclut à une perte d'ingestion.
///
/// CE QU'IL NE TIENT PAS : il ne juge ni la compilation à blanc qui valide une règle avant écriture, ni
/// le rechargement du registre chaud, ni la VALEUR des compteurs.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `rows.flatten().collect::<Vec<_>>()` derrière les deux
/// `unwrap()` — `rules` redevient une liste courte sans `error`, et la table retirée fait paniquer.
#[tokio::test]
async fn p10_7f_listes_de_reglage_les_processeurs_dingestion_sont_entiers_ou_avoues() {
    let (st, au, _p) = lre_etat("processors");
    let deja = lre_deja(&st, "ingest_rule");
    lsa_ecrire(&st, "INSERT INTO ingest_rule(name,ord,match_field,match_op,match_value,action,action_arg,enabled,managed,created) VALUES('jeter le bruit',0,'category','eq','debug','drop','',1,2,10);\
                     INSERT INTO ingest_rule(name,ord,match_field,match_op,match_value,action,action_arg,enabled,managed,created) VALUES('masquer le compte',1,'src_user','eq','root','mask','',1,2,20);");

    let nominal = processors_list(State(st.clone()), Extension(au.clone())).await.0;
    assert_eq!(nominal["rules"].as_array().map(Vec::len), Some(deja + 2), "contrôle positif : les deux règles sont servies : {nominal}");
    assert!(nominal["counters"].is_object(), "contrôle positif : les compteurs live sont servis : {nominal}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET : {nominal}");

    lsa_ecrire(&st, "INSERT INTO ingest_rule(name,ord,match_field,match_op,match_value,action,action_arg,enabled,managed,created) VALUES(x'FF',2,'category','eq','x','drop','',1,2,30);");
    let avoue = processors_list(State(st.clone()), Extension(au.clone())).await.0;
    lsa_juger_l_aveu(&avoue, "rules");
    assert!(avoue["counters"].is_object(), "les compteurs viennent du registre EN MÉMOIRE : ils restent servis : {avoue}");

    lsa_retirer_la_table(&st, "ingest_rule");
    let sans_table = processors_list(State(st.clone()), Extension(au.clone())).await.0;
    lsa_juger_l_aveu(&sans_table, "rules");
    assert!(sans_table["counters"].is_object(), "table retirée : les compteurs restent servis : {sans_table}");
}

// -------------------------------------------------------------------------------------
// (16) MES REQUÊTES SAUVEGARDÉES
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `saved_queries_list` sert les DEUX requêtes de l'appelant (et JAMAIS celles d'autrui) ;
/// une ligne illisible ou une table retirée rendent `queries` NON ÉTABLIE avec sa cause. La lecture pure
/// `list_for_owner` rend désormais un `rusqlite::Result` — le geste que la garde nomme pour une fonction
/// qui ne construit aucun corps : rendre le `Result` à l'appelant, qui, lui, en a un.
///
/// CE QUE LA LIGNE AVALÉE COÛTAIT : cette liste est OWNER-SCOPED, donc son propriétaire est le SEUL à
/// pouvoir constater le manque — et il le lit « je l'ai supprimée ». Il la réécrit, ce qui consomme une
/// part du plafond per-user que `count_for_owner` compte, lui, sur la table ENTIÈRE : le trou se referme
/// en rapprochant un plafond atteint d'une liste qui n'affiche rien.
///
/// CE QU'IL NE TIENT PAS : il ne rejoue ni l'isolation IDOR (tenue par les témoins internes de
/// `saved_queries.rs`), ni le plafond, ni l'exécution d'une requête chargée (qui repasse par /api/query).
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.map(|rows| rows.flatten().collect())` puis
/// `.unwrap_or_default()` — `queries` redevient une liste d'UNE requête sur deux, sans `error`.
#[tokio::test]
async fn p10_7f_listes_de_reglage_mes_requetes_sauvegardees_sont_entieres_ou_avouees() {
    let (st, au, _p) = lre_etat("saved-queries");
    lsa_ecrire(&st, "INSERT INTO saved_query(owner,name,soql,created,updated) VALUES('adm','échecs','search action=fail',10,10);\
                     INSERT INTO saved_query(owner,name,soql,created,updated) VALUES('adm','top hôtes','stats count by host',20,20);\
                     INSERT INTO saved_query(owner,name,soql,created,updated) VALUES('alice','à moi','search *',30,30);");

    let (statut, nominal) = lsa_corps(saved_queries_list(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200);
    assert_eq!(nominal["queries"].as_array().map(Vec::len), Some(2), "contrôle positif : MES deux requêtes, jamais celle d'alice : {nominal}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET : {nominal}");

    lsa_ecrire(&st, "INSERT INTO saved_query(owner,name,soql,created,updated) VALUES('adm',x'FF','search *',40,40);");
    let (statut, avoue) = lsa_corps(saved_queries_list(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200, "la forme du dépôt pour une liste JSON est `error` DANS le corps, pas un refus HTTP");
    lsa_juger_l_aveu(&avoue, "queries");

    lsa_retirer_la_table(&st, "saved_query");
    let (_, sans_table) = lsa_corps(saved_queries_list(State(st.clone()), Extension(au.clone())).await).await;
    lsa_juger_l_aveu(&sans_table, "queries");
}

// -------------------------------------------------------------------------------------
// (17) LES TABLES DE CORRESPONDANCE (LOOKUPS)
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `lookups_list` sert les DEUX lookups déclarés avec leur nombre de lignes ; une ligne
/// illisible rend `lookups` NON ÉTABLIE avec sa cause ; et une table `lookup_meta` retirée ne fait plus
/// PANIQUER la route (elle portait deux `unwrap()`), elle avoue.
///
/// CE QUE LA LIGNE AVALÉE COÛTAIT, ET C'EST LA CONCLUSION LA PLUS TROMPEUSE DU RANG : un lookup absent
/// d'ici se lit « ce lookup n'existe pas », alors que la commande `lookup <nom> …` de GXQL CONTINUE de
/// fonctionner sur lui (elle lit `lookup_kv`, pas cette vue). Un enrichissement qu'on croit absent est en
/// réalité INVISIBLE — et le geste qui suit est un rechargement qui REMPLACE intégralement le contenu :
/// l'ancien est alors perdu pour de bon.
///
/// CE QU'IL NE TIENT PAS : il ne juge ni le remplacement atomique d'un lookup, ni la résolution GXQL
/// elle-même, ni ce que `web/lookups.js:50` peint de l'aveu (il affiche « aucun lookup »).
///
/// LA MUTATION QUI LE FAIT ROUGIR, JOUÉE : rétablir `rows.flatten().collect::<Vec<_>>()` derrière les deux
/// `unwrap()`. MESURÉ : sur la branche « ligne illisible » le corps redevient `{"lookups": [<deux lookups
/// sur trois>]}` sans `error`, et sur la branche « table retirée » la route PANIQUE sur
/// `no such table: lookup_meta` au lieu d'avouer.
#[tokio::test]
async fn p10_7f_listes_de_reglage_les_lookups_sont_entiers_ou_avoues() {
    let (st, au, _p) = lre_etat("lookups");
    let deja = lre_deja(&st, "lookup_meta");
    lsa_ecrire(&st, "INSERT INTO lookup_meta(name,key_field,cols,updated) VALUES('geoip','ip','pays,ville',10);\
                     INSERT INTO lookup_meta(name,key_field,cols,updated) VALUES('parc','host','proprietaire',20);\
                     INSERT INTO lookup_kv(name,key,val) VALUES('geoip','203.0.113.1','{\"pays\":\"FR\"}');");

    let nominal = lookups_list(State(st.clone()), Extension(au.clone())).await.0;
    assert_eq!(nominal["lookups"].as_array().map(Vec::len), Some(deja + 2), "contrôle positif : les deux lookups sont servis : {nominal}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET : {nominal}");

    lsa_ecrire(&st, "INSERT INTO lookup_meta(name,key_field,cols,updated) VALUES(x'FF','k','c',30);");
    let avoue = lookups_list(State(st.clone()), Extension(au.clone())).await.0;
    lsa_juger_l_aveu(&avoue, "lookups");

    lsa_retirer_la_table(&st, "lookup_meta");
    let sans_table = lookups_list(State(st.clone()), Extension(au.clone())).await.0;
    lsa_juger_l_aveu(&sans_table, "lookups");
}

// -------------------------------------------------------------------------------------
// (18) LES ACTIONS DE WORKFLOW
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `workflow_actions_list` sert les DEUX actions de la fixture ; une ligne illisible ou
/// une table retirée rendent `workflow_actions` NON ÉTABLIE avec sa cause.
///
/// CE QUE LA LIGNE AVALÉE COÛTAIT : cette liste PEUPLE le menu contextuel des champs. Une action avalée
/// disparaît du pivot que l'analyste cherche ; il conclut qu'il n'a jamais été défini et le refabrique,
/// alors que le nom est déjà pris (`name TEXT NOT NULL UNIQUE`) — la création est refusée sans qu'il
/// puisse voir pourquoi.
///
/// CE QU'IL NE TIENT PAS : il ne juge ni la compile-vérification du gabarit avant persistance, ni la
/// RÉSOLUTION d'une action (`/resolve` lit la ligne par son id et n'est pas de cette famille), ni
/// l'échappement de la valeur substituée. Aucun module de `web/` ne lit cette route au 2026-09-16.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.map(|rows| rows.flatten().collect())` puis
/// `.unwrap_or_default()` — `workflow_actions` redevient une liste d'UNE action sur deux, sans `error`.
#[tokio::test]
async fn p10_7f_listes_de_reglage_les_actions_de_workflow_sont_entieres_ou_avouees() {
    let (st, au, _p) = lre_etat("workflow");
    let deja = lre_deja(&st, "workflow_action");
    lsa_ecrire(&st, "INSERT INTO workflow_action(name,label,scope_field,kind,target,enabled,managed,created,updated) VALUES('pivot_hote','Pivoter sur l''hôte','host','search','search host=$field$',1,2,10,10);\
                     INSERT INTO workflow_action(name,label,scope_field,kind,target,enabled,managed,created,updated) VALUES('bannir','Bannir l''adresse','src_ip','response','ban_ip',1,2,20,20);");

    let (statut, nominal) = lsa_corps(workflow_actions_list(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200);
    assert_eq!(nominal["workflow_actions"].as_array().map(Vec::len), Some(deja + 2), "contrôle positif : les deux actions sont servies : {nominal}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET : {nominal}");

    lsa_ecrire(&st, "INSERT INTO workflow_action(name,label,scope_field,kind,target,enabled,managed,created,updated) VALUES(x'FF','','*','search','search x=$field$',1,2,30,30);");
    let (statut, avoue) = lsa_corps(workflow_actions_list(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200, "la forme du dépôt pour une liste JSON est `error` DANS le corps, pas un refus HTTP");
    lsa_juger_l_aveu(&avoue, "workflow_actions");

    lsa_retirer_la_table(&st, "workflow_action");
    let (_, sans_table) = lsa_corps(workflow_actions_list(State(st.clone()), Extension(au.clone())).await).await;
    lsa_juger_l_aveu(&sans_table, "workflow_actions");
}
