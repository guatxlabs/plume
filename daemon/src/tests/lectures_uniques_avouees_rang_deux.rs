// =====================================================================================
// `P10.20-b` (rang 2) — UNE LECTURE D'UNE SEULE LIGNE QUI N'A PAS EU LIEU NE SE SERT PAS COMME UN FAIT.
//
// CE QUE LE RANG DEUX A DE PROPRE. Le rang un (`lectures_uniques_avouees.rs`, fermé le 2026-09-16)
// tenait ce qui DÉCIDE : un second facteur, une porte de masquage, une porte « SQL brut = admin ». Ici
// rien ne décide — tout est SERVI. Une valeur entre dans un corps JSON, la console la peint, et un
// analyste la lit comme une observation du produit. `query_row(..).ok()` écrase « aucune ligne » (un
// FAIT) et « la lecture a échoué » (une IGNORANCE) en un `None` unique, et chacun des sept sites
// ci-dessous choisissait alors, sans le dire, la lecture la plus RASSURANTE ou la plus BRUYANTE :
//   * la santé du pipeline non lue valait « pas frais » — donc la bannière « Ingestion en panne » et le
//     mot « muet » sur CHAQUE flux listé : un parc entier déclaré en panne sur une ligne qu'on n'a pas
//     su lire (la seule des sept qui penchait du côté BRUYANT, et elle accuse la collecte de tout le
//     monde) ;
//   * le dernier point du flux « métriques » non lu faisait DISPARAÎTRE ce flux de la liste — et une
//     source absente d'une liste de fraîcheur ne se lit pas « je n'ai pas regardé » ;
//   * un niveau de correspondance de runbook non lu faisait RECOMMANDER le runbook du niveau suivant :
//     une AUTRE procédure que celle qui était écrite pour cette technique, servie avec l'aplomb d'un
//     choix fondé — c'est le pire des sept, parce que la valeur servie est PLAUSIBLE ;
//   * la fiche du runbook attaché non lue rendait une checklist SANS nom de procédure, au-dessus
//     d'étapes qui, elles, s'affichaient ;
//   * le runbook attaché non lu se lisait « aucun runbook attaché » — et l'analyste en attache un, que
//     `attach_runbook` refuse parce qu'une progression existe déjà ;
//   * le rollup de risque non lu se lisait « aucun risque cumulé pour cette entité » ;
//   * le bulletin non lu se lisait « aucun bandeau posé », c'est-à-dire l'effacement silencieux du seul
//     canal par lequel un exploitant parle à TOUS les comptes à la fois.
//
// CE QUE CES TÉMOINS JOUENT, ET POURQUOI DEUX VOIES (reprises du rang un). La voie de la TABLE RETIRÉE
// (renommée sous les pieds du gestionnaire) fait échouer la PRÉPARATION. La voie de la LIGNE ILLISIBLE
// (un `BLOB` posé dans une colonne que le mappeur lit en `TEXT` ou en `INTEGER` — SQLite conserve un
// blob tel quel quelle que soit l'affinité) fait échouer le MAPPEUR, la requête restant saine : c'est
// la voie la plus proche des causes de terrain, et celle qu'aucune garde de forme ne verrait. UNE
// TROISIÈME VOIE EXISTE POUR LE BULLETIN, et elle lui est propre : la ligne se lit et ne se DÉCODE pas
// — même geste que la version de schéma du rang un, dont la troisième voie était « la ligne existe et
// n'est pas un entier ». Là où la colonne lue est un `INTEGER PRIMARY KEY` (l'`id` d'un runbook, qu'un
// blob ne peut pas prendre), la ligne illisible est fabriquée par une VUE temporaire qui coiffe la
// table réelle — c'est ce qui permet de rendre UN SEUL niveau de correspondance illisible et de tenir
// la propriété qui compte : le repli d'un niveau à l'autre n'est PAS un rattrapage d'erreur.
//
// CHAQUE TÉMOIN PORTE SON CONTRÔLE POSITIF DANS LE MÊME CORPS : sans lui, un refus INCONDITIONNEL — ou
// un aveu toujours posé — passerait pour un aveu fondé.
//
// LA FORME DES CORRECTIFS EST CELLE DU DÉPÔT, et le rang deux n'a presque pas eu à refuser :
//   * la lecture rend `Result<Option<_>>` (`rusqlite::OptionalExtension::optional`) — l'absence de
//     ligne reste un FAIT, l'échec remonte ;
//   * ce qui SERT rend `null` et pose un aveu NOMMÉ à côté (`recommandation_non_etablie`,
//     `runbook_attache_non_lu`, `runbook_non_lu`, `summary_error`, `bulletin_non_etabli`), ou porte
//     l'aveu SUR l'objet lui-même (`feeds[].non_lu`, sur le modèle de
//     `liste_bornee::poser_la_sous_liste_ou_avouer`) ;
//   * AUCUN de ces aveux n'existe sur le chemin nominal, donc le corps y ressort byte-identique et un
//     aveu inconditionnel est structurellement impossible.
//
// CE QUE CE LOT NE TIENT PAS, ET IL FAUT LE LIRE ICI :
//   * aucun de ces témoins ne juge ce que la CONSOLE peint. `web/freshness.js` teste `!d.pipeline_fresh`
//     et écrit encore « Ingestion en panne » sur un `null` (l'aveu de racine, lui, est déjà lu et rendu
//     en bandeau rouge) ; `web/sources.js` ne connaît pas le mot `non_lu` dans sa table d'états de
//     SOURCE (il le connaît pour les CAPTEURS) et un flux non lu y prendrait le ton « calme » ;
//     `web/cases.js` ne lit aucun des trois aveux de runbook (il teste `rb.recommended` et
//     `steps.runbook != null`) ; `web/risk.js` teste `if (d.summary)` et `web/system.js`
//     `if (!b || !b.message)`, donc une synthèse et un bandeau non établis n'y affichent RIEN. Les
//     surfaces sont nommées dans le rapport de la clé, rien n'a été touché sous `web/` ;
//   * `runbook_admin_json` (`incidents.rs`), classé rang deux, N'EST PAS un fait servi : son unique
//     consommateur (`runbook_get`) rend un 404 « runbook introuvable ». C'est un refus fail-closed à
//     cause fausse — la définition du rang QUATRE — et il n'est donc pas corrigé ici ;
//   * dans `compute_freshness`, une préparation ratée sur les flux d'ÉVÉNEMENTS ou d'INSTANTANÉS est
//     encore avalée par un `if let Ok(mut s) = conn.prepare(..)` qui ne note RIEN : ces deux familles de
//     flux disparaissent alors sans aveu. C'est la famille `P10.7-f` (un parcours, pas une ligne), elle
//     n'est pas dans la population de cette clé, et elle est écrite ici parce que ce fichier est le
//     dernier endroit où on l'a vue.
// =====================================================================================

/// Écrit dans la base du tenant par la MÊME connexion que les gestionnaires (le writer de `AppState`).
fn lqd_ecrire(st: &AppState, sql: &str) {
    let conn = st.db.lock();
    conn.execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
}

/// Retire une table sous les pieds du gestionnaire sans toucher au code servi : renommée, elle n'est
/// plus sous le nom que le SQL servi attend (un renommage ne viole aucune clé étrangère).
fn lqd_retirer_la_table(st: &AppState, table: &str) {
    lqd_ecrire(st, &format!("ALTER TABLE {table} RENAME TO {table}_hors_d_atteinte;"));
}

/// Le flux nommé `nom` dans un corps de fraîcheur, ou `None` s'il n'y est pas. C'est la DISPARITION
/// d'un flux qui est jugée ici, donc on la lit par une absence explicite, jamais par un `[]`.
fn lqd_flux<'a>(corps: &'a Value, nom: &str) -> Option<&'a Value> {
    corps["feeds"].as_array()?.iter().find(|f| f["name"].as_str().map(|n| n.starts_with(nom)).unwrap_or(false))
}

// -------------------------------------------------------------------------------------
// (1) LA SANTÉ DU PIPELINE — LA LECTURE DONT DÉPEND LE MOT DE TOUS LES AUTRES
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `/api/freshness` sert `pipeline_fresh` LU (contrôle positif : `true` sur une base où
/// un événement vient d'arriver, et aucun aveu posé), et sert `null` — jamais `false` — quand la lecture
/// n'a pas eu lieu. La conséquence tenue avec lui est celle qui coûtait : AUCUN flux ne porte le mot
/// « muet », qui veut dire « plus rien n'arrive, toutes sources confondues ». Ils portent `non_lu`, le
/// mot que `StatutCapteur::NonLu` sert déjà au panneau Intégrations. La racine NOMME la lecture
/// manquante dans `error` et dans `non_lus`.
///
/// CE QU'IL NE TIENT PAS : il ne juge pas ce que la console peint. `web/freshness.js` teste
/// `!d.pipeline_fresh`, donc un `null` y allume encore la bannière « Ingestion en panne » — plus fausse
/// qu'avant sur le fond, aussi bruyante, et surmontée du bandeau rouge de l'aveu de racine, que ce
/// module lit déjà (`etatDuReleveServi`). La table d'états de `web/sources.js` ne connaît pas encore
/// `non_lu` pour un FLUX et le peindrait « calme ».
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.ok().flatten()` puis `unwrap_or(false)` sur la lecture
/// de `MAX(ts)` — `pipeline_fresh` redevient `false`, les flux redeviennent « muet », et les deux
/// derniers blocs tombent ensemble.
#[test]
fn p10_20b_la_sante_du_pipeline_non_lue_ne_declare_pas_les_flux_muets() {
    let (st, p) = sp_state("lqd-pipeline");
    {
        let w = st.db.lock();
        imp_flux(&w, "web", "web", 10, 4);
        rollup_events(&w);
    }

    // CONTRÔLE POSITIF — la lecture aboutit : `pipeline_fresh` est un FAIT, et rien n'est avoué.
    let nominal = compute_freshness(&p, None);
    assert_eq!(nominal["pipeline_fresh"], json!(true), "un événement vient d'arriver : le pipeline EST frais : {nominal}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET — un aveu inconditionnel n'est pas un aveu : {nominal}");
    assert!(nominal.get("non_lus").is_none(), "chemin nominal : aucune lecture n'est nommée non lue : {nominal}");
    let flux_nominal = lqd_flux(&nominal, "web").expect("contrôle positif : le flux d'événements est listé");
    assert_eq!(flux_nominal["status"], json!("frais"), "le statut est DÉRIVÉ d'une santé de pipeline lue : {flux_nominal}");

    // UNE LIGNE ILLISIBLE : `event.ts` porte un BLOB, que `get::<Option<i64>>` refuse au-dessus du
    // `MAX`. La requête reste saine, et les flux d'événements — lus du rollup pré-agrégé, pas de
    // `event` — continuent d'être listés : c'est leur MOT qui change, pas leur présence.
    lqd_ecrire(&st, "UPDATE event SET ts=x'FF' WHERE source='web';");
    let avoue = compute_freshness(&p, None);
    assert_eq!(avoue["pipeline_fresh"], Value::Null, "lecture non faite : jamais « false », qui accuse la collecte : {avoue}");
    let flux = lqd_flux(&avoue, "web").expect("le flux reste LISTÉ : sa propre lecture, elle, a abouti");
    assert_eq!(flux["status"], json!("non_lu"), "aucun mot de collecte n'est formé sans santé de pipeline lue : {flux}");
    assert_ne!(flux["status"], json!("muet"), "et surtout pas « muet » : {flux}");
    assert!(
        avoue["error"].as_str().unwrap_or("").contains("LECTURES NON FAITES"),
        "la racine NOMME ce qui n'a pas été lu : {avoue}"
    );
    assert!(
        avoue["non_lus"].as_array().map(|v| v.iter().any(|c| c.as_str().unwrap_or("").contains("santé du pipeline"))).unwrap_or(false),
        "et elle dit LAQUELLE des lectures : {avoue}"
    );

    // LA TABLE RETIRÉE : la préparation échoue, par l'autre voie.
    lqd_ecrire(&st, "UPDATE event SET ts=1 WHERE typeof(ts)='blob';");
    lqd_retirer_la_table(&st, "event");
    let sans_table = compute_freshness(&p, None);
    assert_eq!(sans_table["pipeline_fresh"], Value::Null, "table hors d'atteinte : rien n'est établi : {sans_table}");
    let flux = lqd_flux(&sans_table, "web").expect("le rollup pré-agrégé est intact : le flux reste listé");
    assert_eq!(flux["status"], json!("non_lu"), "table hors d'atteinte : même mot : {flux}");
}

// -------------------------------------------------------------------------------------
// (2) LE FLUX DES MÉTRIQUES — UN FLUX NON LU EST LISTÉ, IL NE DISPARAÎT PAS
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : le flux agrégé des métriques est servi avec son âge quand sa lecture aboutit
/// (contrôle positif), il n'est PAS listé quand la fenêtre de sept jours ne porte aucune métrique (une
/// absence ÉTABLIE, le chemin nominal d'une instance sans remote-write), et il EST listé — avec
/// `non_lu: true`, `status: "non_lu"`, `last_seen: null` — quand sa lecture a échoué. Les trois états
/// sont joués dans ce corps, et c'est le seul moyen de prouver que le troisième n'est pas le deuxième.
///
/// CE QU'IL NE TIENT PAS, ET C'EST MESURÉ : la table `metric` est LUE DEUX FOIS dans ce corps — par la
/// santé du pipeline (une union sur `event`, `metric`, `snapshot`) et par ce flux-ci. La rendre
/// illisible fait donc tomber les DEUX lectures, et ce témoin ne peut pas isoler la seconde. Il juge en
/// conséquence les deux aveux À LA FOIS, et affirme qu'ils restent DISTINCTS — `pipeline_fresh: null`
/// d'un côté, un flux listé et avoué de l'autre. Il ne juge pas non plus `n_24h` ni le compte de séries,
/// qui retombent encore sur `unwrap_or(0)` quand leur propre lecture échoue (reste nommé de la clé).
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.ok().flatten()` sur `MAX(ts) FROM metric` — le flux
/// sort de `feeds`, et `lqd_flux(.., "métriques")` ne trouve plus rien dans les deux derniers blocs.
#[test]
fn p10_20b_le_flux_des_metriques_non_lu_est_liste_avec_son_aveu() {
    let (st, p) = sp_state("lqd-metriques");
    {
        let w = st.db.lock();
        imp_flux(&w, "web", "web", 10, 4);
        rollup_events(&w);
    }

    // CONTRÔLE POSITIF (1/2) — aucune métrique dans la fenêtre : le flux n'est PAS listé, et c'est un
    // FAIT établi. C'est exactement la forme que la lecture ratée empruntait.
    let sans_metrique = compute_freshness(&p, None);
    assert!(lqd_flux(&sans_metrique, "métriques").is_none(), "aucune métrique : aucun flux, et rien à avouer : {sans_metrique}");
    assert!(sans_metrique.get("error").is_none(), "et le corps reste MUET : {sans_metrique}");

    // CONTRÔLE POSITIF (2/2) — une métrique arrive : le flux est listé avec son âge.
    lqd_ecrire(&st, &format!("INSERT INTO metric(ts,host,name,value) VALUES({},'h1','load1',0.5);", now() - 30));
    let nominal = compute_freshness(&p, None);
    let flux = lqd_flux(&nominal, "métriques").expect("contrôle positif : le flux des métriques est listé");
    assert!(flux["last_seen"].is_i64(), "son dernier point est un nombre LU : {flux}");
    assert!(flux.get("non_lu").is_none(), "et rien n'y est avoué : {flux}");

    // UNE LIGNE ILLISIBLE : `metric.ts` porte un BLOB, que `get::<Option<i64>>` refuse.
    lqd_ecrire(&st, "UPDATE metric SET ts=x'FF' WHERE name='load1';");
    let avoue = compute_freshness(&p, None);
    let flux = lqd_flux(&avoue, "métriques").expect("lecture non faite : le flux est LISTÉ, il ne disparaît pas");
    assert_eq!(flux["non_lu"], json!(true), "et il PORTE son aveu, pour qui parcourt `feeds` sans lire la racine : {flux}");
    assert_eq!(flux["status"], json!("non_lu"), "ni frais, ni muet : non lu : {flux}");
    assert_eq!(flux["last_seen"], Value::Null, "aucun âge n'est fabriqué : {flux}");
    assert_eq!(flux["n_24h"], Value::Null, "aucun volume n'est fabriqué : {flux}");
    assert!(flux["cause"].as_str().unwrap_or("").contains("FLUX NON LU"), "la cause est NOMMÉE sur le flux : {flux}");
    assert_eq!(avoue["pipeline_fresh"], Value::Null, "les DEUX lectures tombent ensemble, et restent distinguées : {avoue}");

    // LA TABLE RETIRÉE : la préparation échoue, par l'autre voie.
    lqd_ecrire(&st, "UPDATE metric SET ts=1 WHERE typeof(ts)='blob';");
    lqd_retirer_la_table(&st, "metric");
    let sans_table = compute_freshness(&p, None);
    let flux = lqd_flux(&sans_table, "métriques").expect("table hors d'atteinte : le flux est encore LISTÉ et avoué");
    assert_eq!(flux["non_lu"], json!(true), "table hors d'atteinte : même aveu : {flux}");
}

// -------------------------------------------------------------------------------------
// (3) LA RECOMMANDATION DE RUNBOOK — UN NIVEAU NON LU NE FAIT PAS DÉROULER CELUI D'À CÔTÉ
// -------------------------------------------------------------------------------------

/// Deux runbooks ACTIFS qui se disputent le même incident : l'un keyé sur la TECHNIQUE `T1110`, l'autre
/// sur la TACTIQUE `credential-access`. La précédence dit que le premier gagne ; c'est ce que la lecture
/// ratée du premier niveau retournait en silence.
fn lqd_deux_niveaux_de_runbook(conn: &Connection) {
    conn.execute(
        "INSERT INTO runbook(key,name,match_kind,match_key,description,managed,active,created) \
         VALUES('technique-t1110','Procédure T1110','technique','T1110','',0,1,1000)",
        [],
    )
    .expect("fixture : le runbook de TECHNIQUE");
    conn.execute(
        "INSERT INTO runbook(key,name,match_kind,match_key,description,managed,active,created) \
         VALUES('tactique-credaccess','Procédure de tactique','tactic','credential-access','',0,1,1001)",
        [],
    )
    .expect("fixture : le runbook de TACTIQUE");
}

/// Rend illisible l'`id` des SEULES lignes d'un `match_kind` donné. L'`id` d'un runbook est un
/// `INTEGER PRIMARY KEY` : SQLite refuse d'y écrire un blob, donc la ligne illisible se fabrique par une
/// VUE qui coiffe la table réelle sous son nom. C'est ce détour qui permet de faire échouer UN SEUL
/// niveau de correspondance — sans lui, on ne pourrait pas distinguer « la recherche n'a pas abouti » de
/// « elle est descendue d'un cran ».
fn lqd_id_illisible_pour(conn: &Connection, match_kind: &str) {
    conn.execute_batch(&format!(
        "ALTER TABLE runbook RENAME TO runbook_reel; \
         CREATE VIEW runbook AS SELECT CASE WHEN match_kind='{match_kind}' THEN x'FF' ELSE id END AS id, \
         key, name, match_kind, match_key, description, managed, active, created FROM runbook_reel;"
    ))
    .expect("fixture : la vue qui rend un niveau illisible");
}

/// CE QU'IL TIENT, ET C'EST LE TÉMOIN LE PLUS DUR DU LOT : `pick_runbook_id` rend le runbook de
/// TECHNIQUE quand les deux niveaux sont lisibles (contrôle positif, et il prouve du même coup que le
/// runbook de tactique EXISTE et serait servi par un repli) ; et quand le niveau TECHNIQUE ne se lit
/// plus, il REFUSE — il ne descend pas d'un cran. La propriété est jugée sur l'IDENTITÉ du runbook,
/// jamais sur un simple « non nul » : un repli rendrait `Ok(Some(<tactique>))`, qui a exactement la
/// forme d'une réponse fondée. Le corps servi, lui, rend `recommended: null` avec une cause NOMMÉE.
///
/// CE QU'IL NE TIENT PAS : la vue qui rend un niveau illisible fait aussi échouer la lecture du
/// CATALOGUE (`available` lit les mêmes lignes), donc le corps servi porte en plus l'aveu `available`
/// de `P10.7-f`. Les deux aveux sont distincts et le témoin les lit séparément ; il ne prouve pas qu'ils
/// tomberaient un à un. Il ne joue pas non plus la route HTTP ni ce que `web/cases.js` peint de ce
/// `null` (il ne lit pas encore `recommandation_non_etablie`).
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.ok()` sur `try_match` — le niveau technique rend
/// `None` au lieu de remonter l'erreur, la recherche descend à la tactique, et le premier assert du
/// second bloc rend `Ok(Some(<procédure de tactique>))`.
#[test]
fn p10_20b_un_niveau_de_runbook_non_lu_ne_fait_pas_recommander_celui_du_dessous() {
    let conn = test_db();
    let id = case_create_row(&conn, "adm", "bruteforce", 4, "", None, 2);
    link_alert(&conn, id, "T1110", Some("web-1"));
    link_alert(&conn, id, "T1110", None);
    lqd_deux_niveaux_de_runbook(&conn);
    let nom_du_runbook = |rb: i64| -> String {
        conn.query_row("SELECT name FROM runbook WHERE id=?1", params![rb], |r| r.get::<_, String>(0)).expect("le runbook est là")
    };

    // CONTRÔLE POSITIF — les deux niveaux sont lisibles : la TECHNIQUE gagne, et la tactique est bien là
    // (elle serait servie par un repli, ce qui est précisément ce qu'on refuse plus bas).
    let retenu = pick_runbook_id(&conn, Some("credential-access"), Some("T1110"))
        .expect("lecture faite")
        .expect("un runbook correspond");
    assert_eq!(nom_du_runbook(retenu), "Procédure T1110", "la précédence retient le niveau le plus spécifique");
    assert_eq!(
        nom_du_runbook(pick_runbook_id(&conn, Some("credential-access"), None).expect("lecture faite").expect("un runbook")),
        "Procédure de tactique",
        "contrôle positif : SANS technique, c'est bien la tactique qui répond — donc le repli AURAIT quelque chose à servir"
    );
    let nominal = case_runbooks_json(&conn, id).expect("contrôle positif : le dossier existe");
    assert_eq!(nominal["recommended"]["name"], json!("Procédure T1110"), "le corps servi recommande la procédure de technique : {nominal}");
    assert!(nominal.get("recommandation_non_etablie").is_none(), "chemin nominal MUET : {nominal}");

    // UNE LIGNE ILLISIBLE, AU NIVEAU TECHNIQUE SEULEMENT.
    lqd_id_illisible_pour(&conn, "technique");
    let refus = pick_runbook_id(&conn, Some("credential-access"), Some("T1110"));
    match refus {
        Ok(Some(rb)) => panic!(
            "le niveau technique n'a PAS été lu et la recherche est descendue d'un cran : « {} » est recommandé à sa place",
            nom_du_runbook(rb)
        ),
        Ok(None) => panic!("une lecture ratée rendue « aucun runbook ne correspond » : c'est l'autre moitié du défaut"),
        Err(_) => {}
    }
    let avoue = case_runbooks_json(&conn, id).expect("le dossier existe toujours");
    assert_eq!(avoue["recommended"], Value::Null, "aucune procédure n'est servie : {avoue}");
    assert!(
        avoue["recommandation_non_etablie"].as_str().unwrap_or("").starts_with(CAUSE_RECOMMANDATION_NON_ETABLIE),
        "et le corps DIT que la recommandation n'est pas établie : {avoue}"
    );

    // LA TABLE RETIRÉE : tous les niveaux échouent, par l'autre voie. Le repli générique `'*'` — celui
    // qui rendait `recommended: null`, c'est-à-dire « aucun runbook ne correspond à cet incident » — est
    // lui aussi une lecture, et c'est désormais dit.
    conn.execute_batch("DROP VIEW runbook; ALTER TABLE runbook_reel RENAME TO runbook;").expect("fixture : la vue est retirée");
    lcs_retirer_la_table_conn(&conn, "runbook");
    assert!(pick_runbook_id(&conn, Some("credential-access"), Some("T1110")).is_err(), "table hors d'atteinte : refus");
    let sans_table = case_runbooks_json(&conn, id).expect("le dossier existe toujours");
    assert_eq!(sans_table["recommended"], Value::Null, "table hors d'atteinte : rien n'est recommandé : {sans_table}");
    assert!(
        sans_table["recommandation_non_etablie"].as_str().unwrap_or("").starts_with(CAUSE_RECOMMANDATION_NON_ETABLIE),
        "et ce `null` n'est pas « aucun runbook ne correspond » : {sans_table}"
    );
}

// -------------------------------------------------------------------------------------
// (4) LE RUNBOOK ATTACHÉ À UN DOSSIER — « AUCUN » EST UN FAIT, PAS UN REPLI
// -------------------------------------------------------------------------------------

/// Un dossier, un runbook d'une étape, et le runbook ATTACHÉ par le geste réel (`attach_runbook`) : les
/// lignes de `case_step` sont donc celles que la production écrit, pas une fixture qui pourrait en
/// dériver en silence. Rend l'identifiant du dossier et celui du runbook.
fn lqd_dossier_avec_runbook_attache(conn: &Connection) -> (i64, i64) {
    let id = case_create_row(&conn, "adm", "intrusion", 4, "", None, 2);
    conn.execute(
        "INSERT INTO runbook(key,name,match_kind,match_key,description,managed,active,created) \
         VALUES('temoin-attache','Procédure attachée','*','','',0,1,1000)",
        [],
    )
    .expect("fixture : le runbook");
    let rb = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO runbook_step(runbook_id,ordinal,phase,title,guidance,step_kind) VALUES(?1,0,'triage','Vérifier','',' manual')",
        params![rb],
    )
    .expect("fixture : une étape");
    attach_runbook(conn, id, rb, "adm", &PrefillTargets::default()).expect("fixture : le runbook s'attache");
    (id, rb)
}

/// CE QU'IL TIENT : `attached_runbook_id` porte l'identifiant du runbook attaché quand la lecture
/// aboutit (contrôle positif), et rend `null` AVEC une cause nommée quand elle n'a pas eu lieu — au lieu
/// du même `null` nu, qui se lit « aucun runbook attaché » et fait attacher un second runbook à un
/// dossier qui en porte déjà un. Le `null` de `P7.19-i` — l'ensemble MULTIPLE, deux runbooks sur un même
/// dossier — reste, lui, un refus de NOMMER établi sur des lignes LUES : c'est la distinction que
/// `.ok()` effaçait, et les deux formes sortent désormais par des corps différents.
///
/// CE QU'IL NE TIENT PAS : il ne joue pas `case_runbook_attach` (le geste d'attache, qui refuse déjà sur
/// une lecture ratée de ses alertes, `P10.7-f`), ni la projection client-read de cette fiche, ni ce que
/// `web/cases.js` peint de ce `null` (il ne lit pas `runbook_attache_non_lu`).
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.ok()` sur `runbook_attache` — `attached_runbook_id`
/// redevient un `null` nu, sans la clé d'aveu, et les deux derniers blocs tombent.
#[test]
fn p10_20b_le_runbook_attache_non_lu_n_est_pas_un_dossier_sans_procedure() {
    let conn = test_db();
    let (id, rb) = lqd_dossier_avec_runbook_attache(&conn);

    // CONTRÔLE POSITIF — la lecture aboutit : l'attache est un FAIT.
    let nominal = case_runbooks_json(&conn, id).expect("contrôle positif : le dossier existe");
    assert_eq!(nominal["attached_runbook_id"], json!(rb), "le runbook attaché est servi : {nominal}");
    assert!(nominal.get("runbook_attache_non_lu").is_none(), "chemin nominal MUET : {nominal}");

    // UNE LIGNE ILLISIBLE : `case_step.runbook_id` porte un BLOB, que `get::<i64>` refuse.
    conn.execute("UPDATE case_step SET runbook_id=x'FF' WHERE incident_id=?1", params![id]).expect("fixture : la ligne illisible");
    let avoue = case_runbooks_json(&conn, id).expect("le dossier existe toujours");
    assert_eq!(avoue["attached_runbook_id"], Value::Null, "rien n'est nommé : {avoue}");
    assert!(
        avoue["runbook_attache_non_lu"].as_str().unwrap_or("").starts_with(CAUSE_RUNBOOK_ATTACHE_NON_LU),
        "et ce `null` DIT qu'il n'est pas « aucun runbook attaché » : {avoue}"
    );

    // LA TABLE RETIRÉE : la préparation échoue. Les ÉTAPES tombent avec elle (même table), et les deux
    // aveux cohabitent sans se remplacer — `error` parle des étapes, `runbook_non_lu` de l'en-tête.
    conn.execute("UPDATE case_step SET runbook_id=?2 WHERE incident_id=?1", params![id, rb]).expect("fixture : la ligne redevient lisible");
    lcs_retirer_la_table_conn(&conn, "case_step");
    let sans_table = case_runbooks_json(&conn, id).expect("le dossier existe toujours");
    assert_eq!(sans_table["attached_runbook_id"], Value::Null, "table hors d'atteinte : {sans_table}");
    assert!(sans_table.get("runbook_attache_non_lu").is_some(), "table hors d'atteinte : même aveu : {sans_table}");
    let etapes = case_steps_json(&conn, id);
    assert!(etapes.get("error").is_some(), "les étapes aussi sont non lues, et le disent (`P10.7-f`) : {etapes}");
    assert!(etapes.get("runbook_non_lu").is_some(), "et l'en-tête de la checklist a son aveu PROPRE : {etapes}");
}

// -------------------------------------------------------------------------------------
// (5) LA FICHE DU RUNBOOK D'UNE CHECKLIST — DES ÉTAPES SANS PROCÉDURE NOMMÉE
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `case_steps_json` coiffe ses étapes du nom du runbook quand sa fiche a été lue
/// (contrôle positif), et rend `runbook: null` AVEC une cause quand elle ne l'a pas été — pendant que
/// les ÉTAPES, qui viennent d'une AUTRE lecture, restent servies et comptées. C'est la forme la plus
/// trompeuse des sept : la checklist s'affiche, l'analyste la déroule, et rien ne dit que la procédure
/// qu'il déroule a un nom qu'on n'a pas pu lire.
///
/// CE QU'IL NE TIENT PAS : il ne juge pas la même fiche servie par `case_runbooks_json`
/// (`recommended`), dont la lecture ratée est INDISSOCIABLE de celle du catalogue — les deux énoncés
/// lisent les mêmes colonnes des mêmes lignes ; le témoin (3) l'exerce là-bas avec son aveu propre.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.ok()` sur `runbook_meta_json` — `runbook` redevient un
/// `null` nu sans `runbook_non_lu`, et les deux derniers blocs tombent.
#[test]
fn p10_20b_la_fiche_du_runbook_non_lue_ne_laisse_pas_une_checklist_anonyme() {
    let conn = test_db();
    let (id, rb) = lqd_dossier_avec_runbook_attache(&conn);

    // CONTRÔLE POSITIF — la fiche est lue : la checklist porte son nom, et ses étapes sont là.
    let nominal = case_steps_json(&conn, id);
    assert_eq!(nominal["runbook"]["name"], json!("Procédure attachée"), "la checklist est coiffée de sa procédure : {nominal}");
    assert_eq!(nominal["steps"].as_array().map(Vec::len), Some(1), "contrôle positif : l'étape est servie : {nominal}");
    assert!(nominal.get("runbook_non_lu").is_none(), "chemin nominal MUET : {nominal}");

    // UNE LIGNE ILLISIBLE : `runbook.key` porte un BLOB, que `get::<String>` refuse.
    conn.execute("UPDATE runbook SET key=x'FF' WHERE id=?1", params![rb]).expect("fixture : la ligne illisible");
    let avoue = case_steps_json(&conn, id);
    assert_eq!(avoue["runbook"], Value::Null, "aucune fiche n'est fabriquée : {avoue}");
    assert!(
        avoue["runbook_non_lu"].as_str().unwrap_or("").starts_with(CAUSE_RUNBOOK_ATTACHE_NON_LU),
        "et la checklist DIT pourquoi elle n'a pas de nom : {avoue}"
    );
    assert_eq!(avoue["steps"].as_array().map(Vec::len), Some(1), "l'AUTRE lecture a abouti : les étapes restent servies : {avoue}");
    assert_eq!(avoue["progress"]["total"], json!(1), "et leur progression aussi : {avoue}");

    // LA TABLE RETIRÉE : la préparation de la fiche échoue, les étapes restent lues.
    conn.execute("UPDATE runbook SET key='temoin-attache' WHERE typeof(key)='blob'", []).expect("fixture : la ligne redevient lisible");
    lcs_retirer_la_table_conn(&conn, "runbook");
    let sans_table = case_steps_json(&conn, id);
    assert_eq!(sans_table["runbook"], Value::Null, "table hors d'atteinte : {sans_table}");
    assert!(sans_table.get("runbook_non_lu").is_some(), "table hors d'atteinte : même aveu : {sans_table}");
    assert_eq!(sans_table["steps"].as_array().map(Vec::len), Some(1), "et les étapes sont toujours là : {sans_table}");
}

// -------------------------------------------------------------------------------------
// (6) LA SYNTHÈSE DE RISQUE D'UNE ENTITÉ — « AUCUN RISQUE » EST UNE AFFIRMATION
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `/api/risk/entity/{type}/{entité}` sert la synthèse du rollup quand elle est lue
/// (contrôle positif : le score y est), sert `summary: null` sans un mot pour une entité qui n'a aucune
/// ligne de rollup (une absence ÉTABLIE, le cas nominal), et sert `summary: null` AVEC `summary_error`
/// quand la lecture n'a pas eu lieu. La ligne de temps et les contributions, qui avouaient déjà les
/// leurs (`P10.7-g` lot 107), restent servies : c'est la synthèse seule qui manque, et c'est elle qui
/// porte le SCORE sur lequel un analyste décide de regarder — ou non — cette entité.
///
/// CE QU'IL NE TIENT PAS : il ne juge pas `risk_entities_page` (la LISTE, dont le recensement avoue déjà
/// par `TotalBorne::sans_lecture`), ni ce que `web/risk.js` peint de ce `null`.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.ok()` sur la synthèse — `summary_error` disparaît, et
/// les deux derniers blocs ne distinguent plus une entité sans risque d'un rollup non lu.
#[tokio::test]
async fn p10_20b_la_synthese_de_risque_non_lue_n_est_pas_un_risque_absent() {
    let (st, _p) = sp_state("lqd-risque");
    let au = sp_au("adm", "admin");
    let etype = "ip".to_string();
    let entity = "198.51.100.9".to_string();
    let lire = |st: AppState, au: AuthUser, e: String, n: String| async move {
        risk_entity_timeline(State(st), Extension(au), Path((e, n))).await.0
    };

    // CONTRÔLE POSITIF (1/2) — aucune ligne de rollup : `summary: null` est un FAIT, et rien n'est avoué.
    let vierge = lire(st.clone(), au.clone(), etype.clone(), entity.clone()).await;
    assert_eq!(vierge["summary"], Value::Null, "aucune ligne de rollup : aucune synthèse, et c'est établi : {vierge}");
    assert!(vierge.get("summary_error").is_none(), "chemin nominal MUET : {vierge}");

    // CONTRÔLE POSITIF (2/2) — la ligne existe : la synthèse est servie avec son score.
    lqd_ecrire(&st, &format!(
        "INSERT INTO risk_rollup(entity_type,entity,env_id,score,contrib,distinct_tactics,tactics,score_hot,contrib_hot,max_severity,first_ts,last_ts,updated) \
         VALUES('ip','{entity}','',42,3,2,'initial-access,discovery',10,1,4,1000,2000,2000);"
    ));
    let pleine = lire(st.clone(), au.clone(), etype.clone(), entity.clone()).await;
    assert_eq!(pleine["summary"]["score"], json!(42), "la synthèse lue est servie telle quelle : {pleine}");

    // UNE LIGNE ILLISIBLE : `risk_rollup.tactics` porte un BLOB, que `get::<String>` refuse.
    lqd_ecrire(&st, "UPDATE risk_rollup SET tactics=x'FF' WHERE entity_type='ip';");
    let avoue = lire(st.clone(), au.clone(), etype.clone(), entity.clone()).await;
    assert_eq!(avoue["summary"], Value::Null, "lecture non faite : aucune synthèse fabriquée : {avoue}");
    assert!(
        avoue["summary_error"].as_str().unwrap_or("").contains("NON LUE"),
        "et ce `null` DIT qu'il n'est pas « aucun risque cumulé » : {avoue}"
    );
    assert_eq!(avoue["lecture_non_faite"], json!(true), "le drapeau partagé de ce corps est posé : {avoue}");
    assert!(avoue["timeline"].is_array(), "les AUTRES lectures ont abouti : elles restent servies : {avoue}");

    // LA TABLE RETIRÉE : la préparation échoue, par l'autre voie.
    lqd_retirer_la_table(&st, "risk_rollup");
    let sans_table = lire(st.clone(), au.clone(), etype, entity).await;
    assert_eq!(sans_table["summary"], Value::Null, "table hors d'atteinte : {sans_table}");
    assert!(sans_table.get("summary_error").is_some(), "table hors d'atteinte : même aveu : {sans_table}");
    assert!(sans_table["timeline"].is_array(), "et la ligne de temps est toujours lue : {sans_table}");
}

// -------------------------------------------------------------------------------------
// (7) LE BULLETIN — LE SEUL CANAL QUI PARLE À TOUS LES COMPTES À LA FOIS
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `/api/bulletin` sert le bandeau posé (contrôle positif), sert `{bulletin: null}` sans
/// un mot quand aucun n'est posé (une absence ÉTABLIE, et le mode 0 d'une instance qui n'a rien à
/// annoncer), et sert `{bulletin: null, bulletin_non_etabli: <cause>}` dans les TROIS cas où rien n'est
/// établi — ligne illisible, table hors d'atteinte, valeur stockée qui ne se décode pas. La troisième
/// voie est propre à ce site, comme la version de schéma avait la sienne au rang un : quelqu'un a posé
/// quelque chose, et servir « aucun bandeau » reviendrait à effacer son message en silence.
///
/// CE QU'IL NE TIENT PAS : il ne juge pas ce que `web/system.js` peint (`loadBulletin` teste
/// `if (!b || !b.message)` puis cache le bandeau ; il ne connaît pas `bulletin_non_etabli`, donc un
/// bandeau non établi n'y affiche encore RIEN), ni la pose et l'effacement, jugés par
/// `day2_bulletin_show_and_clear`.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.ok()?` sur la lecture de `setting` — les trois derniers
/// blocs redeviennent `{bulletin: null}` nu, c'est-à-dire indiscernables du premier, qui est le défaut
/// exact.
#[tokio::test]
async fn p10_20b_le_bulletin_non_etabli_n_est_pas_un_bandeau_absent() {
    let (st, _p) = sp_state("lqd-bulletin");
    let au = sp_au("adm", "admin");
    let cle_aveu = crate::handlers::system::CLE_BULLETIN_NON_ETABLI;

    // CONTRÔLE POSITIF (1/2) — aucun bulletin : `null` est un FAIT, et aucun aveu n'est posé.
    let vierge = bulletin_get(State(st.clone()), Extension(au.clone())).await.0;
    assert_eq!(vierge["bulletin"], Value::Null, "aucun bandeau posé : {vierge}");
    assert!(vierge.get(cle_aveu).is_none(), "chemin nominal MUET — un aveu inconditionnel n'est pas un aveu : {vierge}");

    // CONTRÔLE POSITIF (2/2) — un bandeau posé est servi tel quel.
    lqd_ecrire(&st, "INSERT INTO setting(scope,key,value,updated,updated_by) \
                     VALUES('global','bulletin','{\"message\":\"maintenance 22h\",\"level\":\"warn\"}',1,'adm');");
    let pose = bulletin_get(State(st.clone()), Extension(au.clone())).await.0;
    assert_eq!(pose["bulletin"]["message"], json!("maintenance 22h"), "le bandeau lu est servi : {pose}");
    assert!(pose.get(cle_aveu).is_none(), "et rien n'est avoué : {pose}");

    // VOIE 1 — LA VALEUR NE SE DÉCODE PAS : la ligne existe, elle ne porte pas du JSON.
    lqd_ecrire(&st, "UPDATE setting SET value='pas-du-json' WHERE key='bulletin';");
    let texte = bulletin_get(State(st.clone()), Extension(au.clone())).await.0;
    assert_eq!(texte["bulletin"], Value::Null, "rien n'est servi : {texte}");
    assert!(texte[cle_aveu].as_str().unwrap_or("").contains("ne se décode pas"), "la cause DISTINGUE le décodage : {texte}");

    // VOIE 2 — UNE LIGNE ILLISIBLE : `value` porte un BLOB, que `get::<String>` refuse.
    lqd_ecrire(&st, "UPDATE setting SET value=x'FF' WHERE key='bulletin';");
    let blob = bulletin_get(State(st.clone()), Extension(au.clone())).await.0;
    assert_eq!(blob["bulletin"], Value::Null, "rien n'est servi : {blob}");
    assert!(blob[cle_aveu].as_str().unwrap_or("").contains("lecture a échoué"), "la cause DISTINGUE la lecture ratée : {blob}");

    // VOIE 3 — LA TABLE RETIRÉE : la préparation échoue.
    lqd_retirer_la_table(&st, "setting");
    let sans_table = bulletin_get(State(st.clone()), Extension(au.clone())).await.0;
    assert_eq!(sans_table["bulletin"], Value::Null, "table hors d'atteinte : {sans_table}");
    assert!(sans_table[cle_aveu].as_str().unwrap_or("").contains("lecture a échoué"), "et le corps le dit : {sans_table}");
}
