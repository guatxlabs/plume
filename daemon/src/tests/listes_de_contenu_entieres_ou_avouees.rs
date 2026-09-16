// =====================================================================================
// `P10.7-f` (rang 4, vague a) — LES SIX LISTES DE CONTENU ET DE MODÈLES SONT ENTIÈRES OU AVOUÉES.
//
// LE DÉFAUT MESURÉ (garde de famille `check_a_truncated_list_is_never_served_as_a_complete_one.py`,
// relevé du 2026-09-16) : treize accusations de RANG QUATRE, portées par SIX fonctions de
// `daemon/src/handlers/`, lisaient leur liste par un itérateur de lignes APLATI
// (`.map(|rows| rows.flatten().collect()).unwrap_or_default()`, `.unwrap().flatten()`,
// `rows.flatten().collect::<Vec<_>>()`). Un itérateur de lignes rusqlite rend des `Result` UNE LIGNE À
// LA FOIS : le mappeur peut échouer sur une seule ligne sans que la requête ait échoué — cache de
// schéma de pool périmé qui rend « no such table » au PREMIER pas (famille mesurée dans
// `flatten-avale-no-such-table-au-premier-pas`), colonne ajoutée par une migration que la connexion qui
// sert ne voit pas encore, valeur corrompue. L'aplatissement jetait CETTE ligne-là et rendait la suite,
// sous un corps rigoureusement identique à celui d'une liste complète.
//
// POURQUOI LE RANG QUATRE EST UN RANG, ET PAS UN RESTE. Ce sont les listes sur lesquelles on conclut
// « ce n'est pas configuré ». Personne n'y cherche un accès ni une détection : on y VÉRIFIE qu'un objet
// existe, et quand il n'y est pas on en FABRIQUE un second. Un alias de champ avalé se lit « ce champ
// n'est pas renommé » alors qu'il l'est pour TOUTE recherche du produit ; un objet de modèle avalé
// emporte l'affichage de tous SES champs, pourtant lus, parce que la console recompose l'arbre par
// appariement ; un dataset avalé fait peindre à la console l'invitation exacte à en enregistrer un
// nouveau — qui portera le même nom et sera refusé par la contrainte d'unicité ; une vue avalée
// disparaît du sélecteur qui FILTRE les tableaux de bord. Trois des six sites ajoutent une gravité
// propre, et elle n'est PAS la même pour tous — mesuré plutôt que supposé : `dash_get` et `views_list`
// portaient DEUX `unwrap()` chacun (une table retirée les faisait PANIQUER, et une panique n'est pas un
// aveu) ; la CAPTURE, elle, ne paniquait pas — son `unwrap_or_default()` était plus silencieux encore —
// mais elle ne sert pas une page : elle FIGE un artefact.
//
// LA CAPTURE EST LE SEUL SITE QUI REFUSE, ET C'EST MESURÉ SUR SON CONSOMMATEUR. `capture_dashboard_data`
// rend désormais un `rusqlite::Result` et `snapshot_create` répond 503 sans rien écrire. La raison n'est
// pas esthétique : le produit de cette route est sérialisé dans `dashboard_snapshot.data`, rendu
// partageable par un jeton CSPRNG, et relu des semaines plus tard par un TIERS hors de tout contexte
// (`web/dashboards.js` relit `snap.data.panels` et ne connaît que ce blob). Un `error` posé DANS le
// corps y serait figé avec lui, servi à quelqu'un qui ne peut plus refaire la lecture ni la recouper.
// Refuser laisse la main à l'appelant — il réessaie — et garantit qu'aucun instantané amputé n'existe.
//
// LES DEUX CORPS QUI PORTENT PLUSIEURS LISTES AVOUENT PAR LECTURE. `knowledge_list` sert SIX familles et
// `datamodels_list` TROIS étages dans un SEUL corps. Un `error` global y dirait « quelque chose n'a pas
// été lu » sans dire QUOI : cinq familles honnêtes seraient suspectées avec la sixième, et le lecteur ne
// saurait d'aucune d'elles si son vide est un fait. L'aveu NOMME donc la lecture ratée
// (`liste_bornee::corps_de_listes_illisibles` : `non_lus` porte les clés concernées, chacune présente et
// VIDE, `error` s'ouvre sur `CAUSE_LISTE_ILLISIBLE` — la même phrase que la porte à une seule liste). Ce
// n'est pas une forme neuve : c'est celle de `case_metrics_json` (`non_etablis`) et de `freshness.rs` /
// `fleet.rs` (`non_lus`), transposée d'un compte à une liste. Les témoins de ces deux sites posent la
// ligne illisible dans UNE sous-liste et prouvent que les AUTRES restent servies, comptées.
//
// CE QUE CES TÉMOINS JOUENT, ET POURQUOI DEUX VOIES. La voie de la TABLE RETIRÉE (renommée sous les
// pieds du gestionnaire) fait échouer la PRÉPARATION : elle prouve que la route n'invente plus une liste
// vide et ne panique plus. La voie de la LIGNE ILLISIBLE (un `BLOB` posé dans une colonne `TEXT` —
// SQLite conserve un blob tel quel quelle que soit l'affinité, et `get::<String>` le refuse) fait
// échouer le MAPPEUR sur UNE ligne, la requête restant saine : c'est LA voie que l'aplatissement
// avalait, et c'est elle qui tue la mutation. Chaque témoin porte son CONTRÔLE POSITIF (la liste
// complète, comptée) dans le même corps de test : sans lui, un aveu INCONDITIONNEL passerait pour un
// aveu.
//
// CE QUE CE LOT NE TIENT PAS, DIT PLUTÔT QUE SOUS-ENTENDU :
//   * la CONSOLE ne lit AUCUN de ces aveux, et c'est mesuré : `web/knowledge.js:135-138` peint
//     `Array.isArray(d.aliases) ? … : []` sans regarder `error` ni `non_lus` ; `web/datamodels.js:369`
//     fait de même pour les trois étages, et son `loadDatasets` (`:310`) peint « aucun dataset —
//     construisez un Pivot » sur le corps d'aveu ; `web/dashboards.js:399` prend `j.panels || []` et
//     affiche « aucun panneau » ; `loadViews` (`:954`) remplit son sélecteur avec `views || []`. Le
//     démon avoue ; que la console le PEIGNE se juge dans
//     `check_a_refusal_is_not_rendered_as_an_absence.py`, pas ici. SEULE la capture est déjà lue de bout
//     en bout, parce qu'elle refuse en HTTP et que `web/dashboards.js:875` teste `j.error` ;
//   * l'aveu de `knowledge_list` / `datamodels_list` NOMME les sous-listes non lues, mais il ne dit pas
//     ce qui MANQUE dans celles qui ont été lues : une famille servie est entière, point. C'est
//     exactement ce que ce lot promet, et rien de plus ;
//   * aucun de ces témoins ne juge la relecture d'un instantané PAR JETON (`snapshot_get`), ni la purge
//     des instantanés : ce lot tient la CAPTURE, c'est-à-dire ce qui entre dans l'artefact ;
//   * `datamodels.rs::object_field_allow`, dans le même fichier, reste un ARBITRAGE ASSUMÉ de l'ensemble
//     nommé (une allowlist amputée fait REFUSER le champ au Pivot, elle n'en invente aucun) : ce lot n'y
//     touche pas, et son entrée reste dans `SITES_ADMIS`.
// =====================================================================================

/// L'état file-backed de ce rang : schéma + migrations complets, un admin. MÊME fixture que les trois
/// rangs précédents (`sp_state`) — quatre fixtures jumelles vieilliraient séparément.
fn lco_etat(tag: &str) -> (AppState, AuthUser, crate::tmp_possede::TmpDb) {
    let (st, p) = sp_state(&format!("lco-{tag}"));
    (st, sp_au("adm", "admin"), p)
}

/// LE JUGEMENT D'UN CORPS QUI PORTE PLUSIEURS LISTES ET N'EN A PAS LU UNE. Trois choses tombent
/// ensemble, et la troisième est le point dur : la clé non lue est présente et VIDE, l'aveu la NOMME
/// (`non_lus` + `error`), et les AUTRES listes sont toujours servies avec leur compte — un aveu qui
/// viderait tout le corps « couvrirait » la lecture ratée en rendant les cinq autres inutilisables.
fn lco_juger_l_aveu_nomme(corps: &Value, cle_non_lue: &str, encore_servies: &[(&str, usize)]) {
    assert_eq!(
        corps[cle_non_lue],
        json!([]),
        "lecture ratée : `{cle_non_lue}` ne doit porter AUCUNE ligne — une liste amputée servie sans un mot est le défaut : {corps}"
    );
    assert_eq!(
        corps["non_lus"],
        json!([cle_non_lue]),
        "l'aveu NOMME la lecture ratée, et elle seule : {corps}"
    );
    let cause = corps["error"].as_str().unwrap_or("");
    assert!(
        cause.starts_with(crate::handlers::liste_bornee::CAUSE_LISTE_ILLISIBLE),
        "l'aveu s'ouvre sur la cause du fabricant unique, pour qu'un consommateur qui la teste la trouve ici aussi : {corps}"
    );
    assert!(
        cause.contains(cle_non_lue),
        "l'aveu nomme la liste concernée DANS sa phrase : {corps}"
    );
    for (cle, attendu) in encore_servies {
        assert_eq!(
            corps[*cle].as_array().map(Vec::len),
            Some(*attendu),
            "les listes qui ONT été lues restent servies : `{cle}` doit porter {attendu} ligne(s) — un aveu qui vide tout ne dit plus laquelle a échoué : {corps}"
        );
    }
}

/// Un tableau de bord PARTAGÉ appartenant à l'admin de la fixture, rendu par son id.
fn lco_dashboard(st: &AppState) -> i64 {
    lsa_ecrire(st, "INSERT INTO dashboard(name,created,visibility,owner) VALUES('D de témoin',1000,'shared','adm');");
    st.db.lock().query_row("SELECT id FROM dashboard ORDER BY id DESC LIMIT 1", [], |r| r.get(0)).expect("fixture : le dashboard est écrit")
}

/// Un panneau PARTAGÉ sur ce tableau de bord. `titre` entre tel quel (les témoins y posent aussi un blob).
fn lco_panneau(st: &AppState, dashboard: i64, titre: &str, position: i64) {
    let conn = st.db.lock();
    conn.execute(
        "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,visibility) VALUES(?1,?2,'search source=web | table message',1,'table',?3,'shared')",
        params![dashboard, titre, position],
    )
    .expect("fixture : le panneau est écrit");
}

/// Le nombre d'instantanés FIGÉS dans la base — la seule mesure qui dise si un artefact partiel a été
/// écrit, et elle se prend AVANT et APRÈS chaque refus.
fn lco_instantanes(st: &AppState) -> i64 {
    st.db.lock().query_row("SELECT COUNT(*) FROM dashboard_snapshot", [], |r| r.get(0)).expect("la table des instantanés est lisible")
}

/// UNE ligne dans CHACUNE des six familles de savoir — sans quoi une famille servie vide ne se
/// distinguerait pas d'une famille non lue, et le témoin ne mesurerait rien.
fn lco_semer_le_savoir(st: &AppState) {
    lsa_ecrire(
        st,
        "INSERT INTO knowledge_alias(canonical,source,enabled,created,updated) VALUES('utilisateur','src_user',1,1,1);\
         INSERT INTO knowledge_calc(name,expr,enabled,ord,created,updated) VALUES('duree','fin-debut',1,0,1,1);\
         INSERT INTO knowledge_eventtype(name,filter,enabled,created,updated) VALUES('echec_auth','action=fail',1,1,1);\
         INSERT INTO knowledge_tag(label,field,value,enabled,created,updated) VALUES('prod','env','prod',1,1,1);\
         INSERT INTO macro_def(name,params,body,enabled,created,updated) VALUES('dernier_jour','','earliest=-1d',1,1,1);\
         INSERT INTO auto_lookup(name,key_field,out_cols,kind,enabled,created,updated) VALUES('asset','host','proprietaire','lookup',1,1,1);",
    );
}

/// UN modèle, UN objet, UN champ — les trois étages que `datamodels_list` sert dans un seul corps.
fn lco_semer_les_modeles(st: &AppState) {
    lsa_ecrire(
        st,
        "INSERT INTO data_model(name,title,description,category,enabled,created,updated) VALUES('authentification','Auth','','Authentication',1,1,1);\
         INSERT INTO data_model_object(model_id,name,constraint_soql,enabled,created,updated) VALUES(1,'echecs','action=fail',1,1,1);\
         INSERT INTO data_model_field(object_id,name,ftype,expr,created) VALUES(1,'compte','string','src_user',1);",
    );
}

// -------------------------------------------------------------------------------------
// (1) LA CAPTURE D'INSTANTANÉ — LE SEUL SITE QUI REFUSE, PARCE QUE SON PRODUIT VOYAGE
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `snapshot_create` fige les DEUX panneaux du tableau de bord et écrit UN instantané ;
/// et — c'est le point dur — un panneau dont le mappeur échoue, comme une table `panel` retirée, font
/// REFUSER la capture en 503 nommé, avec ZÉRO ligne de plus dans `dashboard_snapshot`. Avant, la
/// préparation ratée rendait `panels: []` (une capture VIDE présentée comme complète, aussitôt figée et
/// dotée d'un jeton de partage) et la ligne illisible rendait une capture AMPUTÉE, également figée : un
/// artefact faux, partageable à des tiers, qu'aucune relecture ne pouvait plus démentir.
///
/// CE QU'IL NE TIENT PAS : il ne juge pas la relecture par jeton (`snapshot_get`), ni le contenu des
/// panneaux capturés (masquage et aveu de fenêtre ont leurs propres témoins, `misc.rs` et
/// `panneau_avoue.rs`) — seulement que la LISTE des panneaux est entière, ou que rien n'est écrit.
///
/// LA MUTATION QUI LE FAIT ROUGIR, JOUÉE : rétablir l'aplatissement dans `capture_dashboard_data`
/// (`.map(|it| it.flatten().collect::<Vec<_>>())` à la place du solde en bloc). MESURÉ : la route rend
/// `200 {"id":2,"token":…}` sur la branche « ligne illisible » — un SECOND instantané est figé, avec
/// deux panneaux sur trois — et l'assert du statut tombe le premier (200 au lieu de 503).
#[tokio::test]
async fn p10_7f_listes_de_contenu_la_capture_dinstantane_est_entiere_ou_refusee() {
    let (st, au, _p) = lco_etat("capture");
    let did = lco_dashboard(&st);
    lco_panneau(&st, did, "messages", 0);
    lco_panneau(&st, did, "erreurs", 1);

    // CONTRÔLE POSITIF : les deux panneaux sont capturés, et UN instantané est écrit.
    let corps_demande = json!({ "dashboard_id": did, "from": 0, "to": 0, "name": "instantané de témoin" });
    let (statut, ok) = lsa_corps(snapshot_create(State(st.clone()), Extension(au.clone()), Json(corps_demande.clone())).await).await;
    assert_eq!(statut, 200, "contrôle positif : la capture aboutit : {ok}");
    assert_eq!(ok["token"].as_str().map(str::len), Some(64), "contrôle positif : un jeton de partage est rendu : {ok}");
    assert_eq!(lco_instantanes(&st), 1, "contrôle positif : UN instantané est figé");
    let fige: String = st.db.lock().query_row("SELECT data FROM dashboard_snapshot ORDER BY id DESC LIMIT 1", [], |r| r.get(0)).unwrap();
    let fige: Value = serde_json::from_str(&fige).expect("l'instantané figé est du JSON");
    assert_eq!(fige["panels"].as_array().map(Vec::len), Some(2), "contrôle positif : les DEUX panneaux sont dans l'artefact : {fige}");

    // UNE LIGNE ILLISIBLE : le titre du troisième panneau porte un BLOB, que `get::<String>` refuse. La
    // requête, elle, est saine — c'est la voie que l'aplatissement avalait.
    {
        let conn = st.db.lock();
        conn.execute(
            "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,visibility) VALUES(?1,x'FF','search source=web | table message',1,'table',2,'shared')",
            params![did],
        )
        .expect("fixture : le panneau illisible est écrit");
    }
    let (statut, refus) = lsa_corps(snapshot_create(State(st.clone()), Extension(au.clone()), Json(corps_demande.clone())).await).await;
    assert_eq!(statut, 503, "une capture dont une LIGNE n'a pas pu être lue est REFUSÉE, jamais figée amputée : {refus}");
    assert!(
        refus["error"].as_str().unwrap_or("").contains("REFUSÉ"),
        "le refus NOMME sa cause : {refus}"
    );
    assert_eq!(lco_instantanes(&st), 1, "lecture ratée : AUCUN instantané de plus — un artefact partiel serait partageable par jeton");

    // LA TABLE RETIRÉE : la préparation échoue. Avant, elle rendait `panels: []` en 200, figé et partagé.
    lsa_retirer_la_table(&st, "panel");
    let (statut, refus) = lsa_corps(snapshot_create(State(st.clone()), Extension(au.clone()), Json(corps_demande)).await).await;
    assert_eq!(statut, 503, "table retirée : refus nommé, jamais une capture VIDE figée comme complète : {refus}");
    assert_eq!(lco_instantanes(&st), 1, "table retirée : aucun instantané de plus");
}

// -------------------------------------------------------------------------------------
// (2) LES PANNEAUX D'UN TABLEAU DE BORD SERVI
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `dash_get` sert les DEUX panneaux du tableau de bord ; un panneau dont la ligne ne
/// se décode pas rend `panels` NON ÉTABLIE (`[]` + `error`), jamais une page amputée d'un panneau et
/// pourtant d'aspect complet ; et une table `panel` retirée ne fait plus PANIQUER la route (elle portait
/// deux `unwrap()`), elle avoue. Le solde en bloc précède le filtre de portée : un échec de ligne ne peut
/// donc pas se cacher derrière « ce panneau était privé ».
///
/// CE QU'IL NE TIENT PAS : il ne joue ni la garde de visibilité (panneau privé d'un tiers, tenue par
/// `objet_sans_proprietaire.rs` et `panneau_bibliotheque.rs`), ni la résolution panneau∪bibliothèque ; et
/// il ne dit rien de ce que `web/dashboards.js:399` peint de cet `error` (il lit `j.panels || []`).
///
/// LA MUTATION QUI LE FERAIT ROUGIR (non jouée : trois suffisent à tuer la forme, et ce sont les trois
/// que le lot rapporte) : rétablir `.unwrap().flatten()` entre la lecture et le filtre — le corps
/// redevient `{"panels": [<deux panneaux sur trois>]}` sans `error`, et le premier assert de
/// `lsa_juger_l_aveu` tombe.
#[tokio::test]
async fn p10_7f_listes_de_contenu_les_panneaux_dun_tableau_de_bord_sont_entiers_ou_avoues() {
    let (st, au, _p) = lco_etat("dash");
    let did = lco_dashboard(&st);
    lco_panneau(&st, did, "messages", 0);
    lco_panneau(&st, did, "erreurs", 1);

    let (statut, nominal) = lsa_corps(dash_get(State(st.clone()), Extension(au.clone()), Path(did)).await).await;
    assert_eq!(statut, 200);
    assert_eq!(nominal["panels"].as_array().map(Vec::len), Some(2), "contrôle positif : les deux panneaux sont servis : {nominal}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET — un aveu inconditionnel n'est pas un aveu : {nominal}");
    assert_eq!(nominal["name"], json!("D de témoin"), "contrôle positif : les métadonnées du tableau de bord sont servies : {nominal}");

    {
        let conn = st.db.lock();
        conn.execute(
            "INSERT INTO panel(dashboard_id,title,query,is_soql,viz,position,visibility) VALUES(?1,x'FF','',1,'table',2,'shared')",
            params![did],
        )
        .expect("fixture : le panneau illisible est écrit");
    }
    let (statut, avoue) = lsa_corps(dash_get(State(st.clone()), Extension(au.clone()), Path(did)).await).await;
    assert_eq!(statut, 200, "la forme du dépôt pour une liste JSON est `error` DANS le corps, pas un refus HTTP");
    lsa_juger_l_aveu(&avoue, "panels");
    assert_eq!(avoue["name"], json!("D de témoin"), "les métadonnées viennent d'une AUTRE lecture, déjà faite : elles restent servies : {avoue}");

    lsa_retirer_la_table(&st, "panel");
    let (_, sans_table) = lsa_corps(dash_get(State(st.clone()), Extension(au.clone()), Path(did)).await).await;
    lsa_juger_l_aveu(&sans_table, "panels");
}

// -------------------------------------------------------------------------------------
// (3) LE SÉLECTEUR DE VUES
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `views_list` sert les DEUX vues de la fixture avec l'identité de l'appelant ; une
/// vue dont la ligne ne se décode pas rend `views` NON ÉTABLIE avec sa cause, au lieu d'un sélecteur
/// silencieusement raccourci qui FILTRE la liste des tableaux de bord ; et une table `view` retirée ne
/// fait plus paniquer (elle portait, elle aussi, deux `unwrap()`).
///
/// CE QU'IL NE TIENT PAS : il ne juge pas la garde de partage (`me`/`role` sont servis pour elle, mais
/// c'est `view_update` qui décide), ni ce que `web/dashboards.js:954` peint de l'aveu (`views || []`).
///
/// LA MUTATION QUI LE FAIT ROUGIR, JOUÉE : rétablir `.map(|rows| rows.flatten().collect::<Vec<_>>())` à
/// la place du solde en bloc. MESURÉ : le corps redevient `{"views": [<les neuf vues lisibles sur
/// dix>], "me": "adm", "role": "admin"}` sans `error`, et le premier assert de `lsa_juger_l_aveu` tombe
/// en imprimant la liste amputée — mot pour mot le défaut.
#[tokio::test]
async fn p10_7f_listes_de_contenu_le_selecteur_de_vues_est_entier_ou_avoue() {
    let (st, au, _p) = lco_etat("views");
    // Les migrations SÈMENT des vues : le contrôle positif se mesure par rapport à ce que la base porte
    // vraiment, jamais contre un nombre écrit à la main qui vieillirait au prochain semis.
    let semees: usize = st.db.lock().query_row("SELECT COUNT(*) FROM view", [], |r| r.get::<_, i64>(0)).unwrap() as usize;
    lsa_ecrire(&st, "INSERT INTO view(name,owner,visibility,created) VALUES('Exploitation','adm','shared',1);\
                     INSERT INTO view(name,owner,visibility,created) VALUES('Conformité','adm','private',2);");
    let nominal = views_list(State(st.clone()), Extension(au.clone())).await.0;
    assert_eq!(nominal["views"].as_array().map(Vec::len), Some(semees + 2), "contrôle positif : les vues semées ET les deux du témoin sont servies : {nominal}");
    assert_eq!(nominal["me"], json!("adm"), "contrôle positif : l'identité de l'appelant est servie : {nominal}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET : {nominal}");

    lsa_ecrire(&st, "INSERT INTO view(name,owner,visibility,created) VALUES(x'FF','adm','shared',3);");
    let avoue = views_list(State(st.clone()), Extension(au.clone())).await.0;
    lsa_juger_l_aveu(&avoue, "views");
    assert_eq!(avoue["me"], json!("adm"), "`me` et `role` ne DÉRIVENT PAS de cette lecture : ils restent servis : {avoue}");

    lsa_retirer_la_table(&st, "view");
    let sans_table = views_list(State(st.clone()), Extension(au.clone())).await.0;
    lsa_juger_l_aveu(&sans_table, "views");
}

// -------------------------------------------------------------------------------------
// (4) LES SIX FAMILLES DE LA BASE DE CONNAISSANCE — L'AVEU NOMME LAQUELLE
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `knowledge_list` sert les SIX familles (une ligne chacune, comptées) ; une ligne
/// illisible dans les CALCULS rend `calcs` NON ÉTABLIE, l'aveu la NOMME (`non_lus: ["calcs"]`) et les
/// CINQ autres restent servies — le point dur de ce site, parce qu'un aveu global aurait suspecté cinq
/// familles honnêtes avec la sixième ; et une table `knowledge_tag` retirée nomme `tags`, les cinq
/// autres restant servies elles aussi.
///
/// CE QU'IL NE TIENT PAS : il ne juge pas la recompilation du `KnowledgeSet` (`knowledge_reload`, qui a
/// sa propre voie et ses témoins), ni ce que `web/knowledge.js:135-138` peint de l'aveu — ce module lit
/// quatre des six familles et ne regarde ni `error` ni `non_lus`.
///
/// LA MUTATION QUI LE FAIT ROUGIR, JOUÉE : rétablir `.map(|rows| rows.flatten().collect::<Vec<_>>())`
/// sur la lecture des CALCULS. MESURÉ : le corps redevient `{"calcs": [<le calcul lisible sur deux>],
/// …}` sans `non_lus` ni `error`, et le premier assert de `lco_juger_l_aveu_nomme` tombe.
#[tokio::test]
async fn p10_7f_listes_de_contenu_les_six_familles_de_savoir_sont_entieres_ou_avouees() {
    let (st, au, _p) = lco_etat("knowledge");
    lco_semer_le_savoir(&st);
    let toutes = [("aliases", 1), ("calcs", 1), ("eventtypes", 1), ("tags", 1), ("macros", 1), ("auto_lookups", 1)];

    let (statut, nominal) = lsa_corps(knowledge_list(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200);
    for (cle, attendu) in toutes {
        assert_eq!(nominal[cle].as_array().map(Vec::len), Some(attendu), "contrôle positif : `{cle}` est servie : {nominal}");
    }
    assert!(nominal.get("error").is_none(), "chemin nominal MUET : {nominal}");
    assert!(nominal.get("non_lus").is_none(), "chemin nominal : aucune lecture n'est nommée non lue : {nominal}");

    // UNE LIGNE ILLISIBLE DANS UNE SEULE FAMILLE : les cinq autres doivent rester servies.
    lsa_ecrire(&st, "INSERT INTO knowledge_calc(name,expr,enabled,ord,created,updated) VALUES(x'FF','x',1,1,1,1);");
    let (statut, avoue) = lsa_corps(knowledge_list(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200, "la forme du dépôt pour une liste JSON est `error` DANS le corps, pas un refus HTTP");
    lco_juger_l_aveu_nomme(&avoue, "calcs", &[("aliases", 1), ("eventtypes", 1), ("tags", 1), ("macros", 1), ("auto_lookups", 1)]);

    // LA TABLE RETIRÉE D'UNE AUTRE FAMILLE : c'est ELLE qui est nommée, et les calculs REDEVIENNENT
    // servis. La ligne blob est retirée d'abord, sinon DEUX familles échoueraient et le témoin ne
    // prouverait plus que l'aveu désigne la BONNE — il se contenterait de constater qu'il y en a un.
    lsa_ecrire(&st, "DELETE FROM knowledge_calc WHERE typeof(name)='blob';");
    lsa_retirer_la_table(&st, "knowledge_tag");
    let (_, sans_table) = lsa_corps(knowledge_list(State(st.clone()), Extension(au.clone())).await).await;
    lco_juger_l_aveu_nomme(&sans_table, "tags", &[("aliases", 1), ("calcs", 1), ("eventtypes", 1), ("macros", 1), ("auto_lookups", 1)]);
}

// -------------------------------------------------------------------------------------
// (5) LES TROIS ÉTAGES DE L'ARBRE DE MODÈLES — L'AVEU NOMME LEQUEL
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `datamodels_list` sert les TROIS étages (modèle, objet, champ, comptés) et les trois
/// vocabulaires constants ; une ligne illisible dans les OBJETS rend `objects` NON ÉTABLIE, l'aveu la
/// NOMME, et `models`/`fields` restent servis — ce qui est le point dur ici, parce que la console
/// RECOMPOSE l'arbre par appariement (`objects.model_id`, `fields.object_id`) : un objet avalé emportait
/// l'affichage de tous SES champs, pourtant lus, et le lecteur en concluait que le modèle était nu.
///
/// CE QU'IL NE TIENT PAS : il ne juge pas l'allowlist du Pivot (`object_field_allow`), qui lit la MÊME
/// table `data_model_field` et reste un ARBITRAGE ASSUMÉ de l'ensemble nommé — une allowlist amputée
/// fait REFUSER le champ (400), elle n'en invente aucun. Il ne dit rien non plus de ce que
/// `web/datamodels.js:369` peint de l'aveu.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.map(|rows| rows.flatten().collect())
/// .unwrap_or_default()` sur la lecture des OBJETS — `objects` redevient une liste courte sans `non_lus`.
#[tokio::test]
async fn p10_7f_listes_de_contenu_les_trois_etages_des_modeles_sont_entiers_ou_avoues() {
    let (st, au, _p) = lco_etat("datamodels");
    lco_semer_les_modeles(&st);

    let (statut, nominal) = lsa_corps(datamodels_list(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200);
    for (cle, attendu) in [("models", 1), ("objects", 1), ("fields", 1)] {
        assert_eq!(nominal[cle].as_array().map(Vec::len), Some(attendu), "contrôle positif : `{cle}` est servi : {nominal}");
    }
    assert!(nominal["field_types"].is_array(), "contrôle positif : les vocabulaires constants sont servis : {nominal}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET : {nominal}");
    assert!(nominal.get("non_lus").is_none(), "chemin nominal : aucune lecture n'est nommée non lue : {nominal}");

    lsa_ecrire(&st, "INSERT INTO data_model_object(model_id,name,constraint_soql,enabled,created,updated) VALUES(1,x'FF','',1,2,2);");
    let (_, avoue) = lsa_corps(datamodels_list(State(st.clone()), Extension(au.clone())).await).await;
    lco_juger_l_aveu_nomme(&avoue, "objects", &[("models", 1), ("fields", 1)]);
    assert!(avoue["field_types"].is_array(), "les vocabulaires sont des CONSTANTES du code, pas une lecture : ils restent servis : {avoue}");

    // La ligne blob est retirée d'abord : DEUX étages en échec ne prouveraient plus que l'aveu nomme le
    // BON, seulement qu'il y en a un.
    lsa_ecrire(&st, "DELETE FROM data_model_object WHERE typeof(name)='blob';");
    lsa_retirer_la_table(&st, "data_model_field");
    let (_, sans_table) = lsa_corps(datamodels_list(State(st.clone()), Extension(au.clone())).await).await;
    lco_juger_l_aveu_nomme(&sans_table, "fields", &[("models", 1), ("objects", 1)]);
}

// -------------------------------------------------------------------------------------
// (6) LES DATASETS
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `datasets_list` sert les DEUX datasets enregistrés ; une ligne illisible ou une table
/// retirée rendent `datasets` NON ÉTABLIE avec sa cause — au lieu d'une liste courte sur laquelle la
/// console peint « aucun dataset — construisez un Pivot puis “Enregistrer comme dataset” », c'est-à-dire
/// l'invitation exacte à en refabriquer un qui portera le même nom et sera refusé à l'insertion.
///
/// CE QU'IL NE TIENT PAS : il ne joue pas l'EXÉCUTION d'un dataset (`run_generated_soql`, dont l'aveu de
/// portillon est déjà lu par `web/datamodels.js:270`), ni la garde `editor+` de l'écriture.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.map(|rows| rows.flatten().collect())
/// .unwrap_or_default()` — le corps redevient `{"datasets": [<un dataset>]}` sans `error`.
#[tokio::test]
async fn p10_7f_listes_de_contenu_les_datasets_sont_entiers_ou_avoues() {
    let (st, au, _p) = lco_etat("datasets");
    lsa_ecrire(&st, "INSERT INTO dataset(name,kind,soql,spec,enabled,created,updated) VALUES('echecs_auth','search','search action=fail','',1,1,1);\
                     INSERT INTO dataset(name,kind,soql,spec,enabled,created,updated) VALUES('top_hotes','pivot','stats count by host','{}',1,2,2);");

    let (statut, nominal) = lsa_corps(datasets_list(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200);
    assert_eq!(nominal["datasets"].as_array().map(Vec::len), Some(2), "contrôle positif : les deux datasets sont servis : {nominal}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET : {nominal}");

    lsa_ecrire(&st, "INSERT INTO dataset(name,kind,soql,spec,enabled,created,updated) VALUES(x'FF','search','','',1,3,3);");
    let (statut, avoue) = lsa_corps(datasets_list(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200, "la forme du dépôt pour une liste JSON est `error` DANS le corps, pas un refus HTTP");
    lsa_juger_l_aveu(&avoue, "datasets");

    lsa_retirer_la_table(&st, "dataset");
    let (_, sans_table) = lsa_corps(datasets_list(State(st.clone()), Extension(au.clone())).await).await;
    lsa_juger_l_aveu(&sans_table, "datasets");
}
