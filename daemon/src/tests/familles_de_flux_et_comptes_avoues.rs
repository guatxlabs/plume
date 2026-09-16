// =====================================================================================
// `P10.20-g` — UNE PRÉPARATION RATÉE NE RETIRE PLUS UNE FAMILLE ENTIÈRE DU RELEVÉ, ET UN COMPTE QU'ON
// N'A PAS FAIT NE VAUT PLUS ZÉRO.
//
// CE QUE CETTE CLÉ A DE PROPRE, APRÈS `P10.20-b`. Le rang deux tenait les lectures d'UNE SEULE LIGNE :
// une valeur manquante remplacée par une autre valeur. Ici il ne manque pas une valeur, il manque une
// LISTE — et pas un préfixe de liste (`P10.7-f`), la liste ENTIÈRE. Les deux défauts sont écrits avec
// la même forme de code, `if let Ok(..) = conn.prepare(..)` sans branche d'échec, et cette forme est
// muette par construction : il n'y a pas de branche où écrire quoi que ce soit.
//
// POURQUOI C'EST LA PIRE DES TROIS. Une surface de fraîcheur n'a qu'un objet : dire ce qui remonte et
// ce qui ne remonte plus. Une famille de flux absente de `feeds` ne se lit pas « je n'ai pas pu
// regarder » — elle se lit « plus rien ne vient de là », c'est-à-dire le verdict le plus grave que
// cette surface sache former, servi sans qu'aucun champ ne bouge et sans qu'un lecteur ait le moindre
// moyen de le soupçonner. La bascule inverse existe aussi : `n_24h` et le nombre de séries retombaient
// sur zéro par `unwrap_or(0)` À CÔTÉ d'un `last_seen` qui, lui, venait d'être lu — un flux daté de
// trente secondes avec « 0 point sur vingt-quatre heures » se lit comme un flux qui vient de s'éteindre.
//
// LES DEUX VOIES, ET CE QU'ELLES ISOLENT.
//   * LA TABLE RETIRÉE (renommée sous les pieds du gestionnaire) fait échouer la PRÉPARATION de tout
//     ce qui la nomme — c'est la voie que la cellule demande pour chacune des deux familles.
//   * LA COLONNE RETIRÉE (renommée) fait échouer la PRÉPARATION D'UN SEUL ÉNONCÉ : `MAX(ts)` ne
//     nomme ni `kind` ni `name`, la santé du pipeline reste donc LUE pendant que la famille, elle, ne
//     l'est pas. C'est cette voie qui PROUVE que l'aveu de famille n'est pas un sous-produit de l'aveu
//     de racine du rang deux — sans elle, les deux tomberaient toujours ensemble et le témoin ne
//     pourrait pas dire lequel des deux correctifs il juge.
//
// CE QUE CE FICHIER NE TIENT PAS, ET C'EST MESURÉ :
//   * il n'existe AUCUNE voie de mappeur pour un COMPTE. Une ligne `COUNT(*)` rend toujours un entier,
//     donc `r.get::<_, i64>(0)` ne peut pas échouer : la seule façon de faire rater ce genre de lecture
//     est de refuser sa PRÉPARATION. Les deux comptes du flux des métriques n'ont donc qu'une voie, et
//     ce n'est pas un oubli de témoin, c'est une propriété de l'énoncé ;
//   * les deux comptes sont désormais lus par UN SEUL énoncé (`COUNT(*)` et `COUNT(DISTINCT name)`
//     ensemble) : ils tombent donc ensemble, et ce témoin ne peut pas — ni ne cherche à — les séparer ;
//   * aucun de ces témoins ne juge ce que la console peint. `web/freshness.js` ne connaît ni
//     `famille_non_lue`, ni `series: null`, ni `nb_series_non_lu` ; `web/fleet.js` teste
//     `pipeline_fresh` sans distinguer `null` de `false`. Les surfaces sont nommées dans le rapport de
//     la clé, rien n'a été touché sous `web/`.
// =====================================================================================

/// Une base de FICHIER : `compute_freshness` passe par `read_with_watchdog`, donc par le pool de
/// lecture — une base en mémoire ne traverserait pas le vrai chemin.
fn fca_base_disque(tag: &str) -> (crate::tmp_possede::TmpPossede, String) {
    let tmp = crate::tmp_possede::TmpPossede::neuf(tag);
    let p = tmp.sous("plume.db").chemin().to_string_lossy().to_string();
    {
        let w = Connection::open(&p).unwrap();
        w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&w), "fixture : la chaîne de migrations doit aller au bout");
    }
    (tmp, p)
}

/// Écrit dans la base de fichier par une connexion d'ÉCRITURE, comme le démon le ferait.
fn fca_ecrire(p: &str, sql: &str) {
    let w = Connection::open(p).unwrap();
    w.execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
}

/// `n` événements d'une source, le plus récent à `now - age`, puis l'agrégat que la surface lit
/// vraiment. Trois au minimum (`HAVING SUM(n)>=3`, anti-artefact one-shot).
fn fca_evenements(p: &str, source: &str, n: i64) {
    let w = Connection::open(p).unwrap();
    for i in 0..n {
        w.execute(
            "INSERT INTO event(ts,host,source,category,severity,message,dedup) VALUES(?1,'srv01',?2,'auth',1,'m',?3)",
            params![now() - 10 - i, source, format!("{source}-{i}")],
        )
        .unwrap();
    }
    rollup_events(&w);
}

/// Le flux nommé `nom` dans un corps de fraîcheur, ou `None` s'il n'y est pas — une DISPARITION se lit
/// par une absence explicite, jamais par un tableau vide.
fn fca_flux<'a>(corps: &'a Value, nom: &str) -> Option<&'a Value> {
    corps["feeds"].as_array()?.iter().find(|f| f["name"].as_str().map(|n| n.starts_with(nom)).unwrap_or(false))
}

/// Les flux d'un `kind` donné, quel que soit leur nom.
fn fca_flux_du_genre<'a>(corps: &'a Value, kind: &str) -> Vec<&'a Value> {
    corps["feeds"].as_array().map(|a| a.iter().filter(|f| f["kind"] == json!(kind)).collect()).unwrap_or_default()
}

// -------------------------------------------------------------------------------------
// (1) LA FAMILLE DES FLUX D'ÉVÉNEMENTS
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : quand l'énoncé qui LISTE les flux d'événements ne démarre pas, `/api/freshness`
/// sert une entrée de FAMILLE (`kind: "event"`, `non_lu: true`, `famille_non_lue: true`, une cause
/// nommée, et aucun nombre) au lieu de ne rien servir du tout, et la racine NOMME le parcours qui n'a
/// pas eu lieu. Le contrôle positif est compté dans le même corps : sur la base intacte, le flux
/// d'événements est listé avec son âge, AUCUNE entrée de famille n'existe et le corps est muet.
///
/// CE QU'IL TIENT AUSSI, ET C'EST LA MOITIÉ QUI COÛTE : la santé du pipeline reste LUE (`true`) et les
/// autres familles restent muettes. L'aveu est donc PORTÉ PAR LA FAMILLE QUI MANQUE, pas répandu sur le
/// corps — un aveu qui condamnerait la réponse entière ne vaudrait pas mieux que pas d'aveu du tout.
///
/// POURQUOI UNE ENTRÉE DE FAMILLE ET NON UNE ENTRÉE PAR FLUX ATTENDU : les flux d'événements sortent
/// d'un `GROUP BY source` — c'est la lecture qui dit lesquels existent. Quand elle ne démarre pas, ni
/// leur nombre ni leurs noms ne sont connus, et les fabriquer serait le défaut poursuivi, à l'envers.
/// Le témoin le tient en exigeant qu'AUCUN nom de source ne soit servi.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `if let Ok(mut s) = conn.prepare(..)` autour de l'énoncé
/// du rollup d'événements — la famille redisparaît et les deux derniers blocs tombent ensemble.
#[test]
fn p10_20g_une_famille_de_flux_devenements_non_lue_est_listee_avec_son_aveu() {
    let (_t, p) = fca_base_disque("fca-evenements");
    fca_evenements(&p, "web", 4);

    // CONTRÔLE POSITIF — la préparation aboutit : le flux est listé, rien n'est avoué.
    let nominal = compute_freshness(&p, None);
    let flux = fca_flux(&nominal, "web").expect("contrôle positif : le flux d'événements est listé");
    assert!(flux["last_seen"].is_i64(), "son dernier point est un nombre LU : {flux}");
    assert!(flux.get("famille_non_lue").is_none(), "et ce n'est pas une entrée d'aveu : {flux}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET — un aveu inconditionnel n'est pas un aveu : {nominal}");

    // LA TABLE RETIRÉE : l'agrégat que cette famille lit n'est plus sous le nom attendu, la préparation
    // est refusée. C'est la voie que la cellule demande.
    fca_ecrire(&p, "ALTER TABLE event_rollup RENAME TO event_rollup_hors_d_atteinte;");
    let avoue = compute_freshness(&p, None);
    let familles = fca_flux_du_genre(&avoue, "event");
    assert_eq!(familles.len(), 1, "la famille est LISTÉE, elle ne disparaît pas : {avoue}");
    let famille = familles[0];
    assert_eq!(famille["famille_non_lue"], json!(true), "et elle se dit famille, pas source : {famille}");
    assert_eq!(famille["non_lu"], json!(true), "elle porte le MÊME mot qu'un flux non lu : {famille}");
    assert_eq!(famille["status"], json!("non_lu"), "ni frais, ni muet : non lu : {famille}");
    assert_eq!(famille["last_seen"], Value::Null, "aucun âge n'est fabriqué : {famille}");
    assert_eq!(famille["n_24h"], Value::Null, "aucun volume n'est fabriqué : {famille}");
    assert_eq!(famille["active_alerts"], Value::Null, "aucune cloche n'est fabriquée : {famille}");
    assert!(
        famille["cause"].as_str().unwrap_or("").contains("FAMILLE DE FLUX NON LUE"),
        "la cause est NOMMÉE sur l'entrée, pour qui parcourt `feeds` sans lire la racine : {famille}"
    );
    assert_ne!(famille["name"], json!("web"), "AUCUN nom de source n'est inventé — on ne sait pas lesquelles existent : {famille}");
    assert!(
        avoue["error"].as_str().unwrap_or("").contains("les flux d'événements"),
        "et la racine nomme le parcours qui n'a pas eu lieu : {avoue}"
    );
    // L'ISOLATION, qui est la moitié qui coûte : le reste du corps a été lu, et le dit.
    assert_eq!(avoue["pipeline_fresh"], json!(true), "la santé du pipeline, elle, a été lue : {avoue}");
    assert!(fca_flux_du_genre(&avoue, "snapshot").is_empty(), "aucune autre famille n'est avouée sans raison : {avoue}");
}

// -------------------------------------------------------------------------------------
// (2) LA FAMILLE DES FLUX D'INSTANTANÉS — DEUX VOIES, DONT UNE QUI ISOLE
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : même propriété que (1) pour les instantanés, par les DEUX voies, et il les
/// distingue. Par la COLONNE retirée, la famille est avouée pendant que la santé du pipeline reste LUE :
/// c'est la preuve que l'aveu de famille est un correctif PROPRE et non un effet de bord de celui du
/// rang deux. Par la TABLE retirée — la voie que la cellule demande —, les deux lectures tombent
/// ensemble, et le témoin exige alors que les deux aveux RESTENT DISTINCTS dans le corps servi
/// (`pipeline_fresh: null` d'un côté, une entrée de famille de l'autre).
///
/// CE QU'IL NE TIENT PAS : il ne juge pas le mot que porterait un flux d'instantanés qui aurait été lu
/// pendant que la santé du pipeline ne l'est pas — c'est la propriété de `P10.20-b`, tenue ailleurs.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `if let Ok(mut s) = conn.prepare(..)` autour de l'énoncé
/// des instantanés.
#[test]
fn p10_20g_une_famille_de_flux_dinstantanes_non_lue_est_listee_avec_son_aveu() {
    let (_t, p) = fca_base_disque("fca-instantanes");
    fca_evenements(&p, "web", 4);
    fca_ecrire(
        &p,
        &format!(
            "INSERT INTO snapshot(ts,host,kind,data) VALUES({0},'srv01','firewall','{{}}'),({0},'srv01','ports','{{}}');",
            now() - 20
        ),
    );

    // CONTRÔLE POSITIF — deux genres d'instantanés, listés avec leur dénominateur d'hôtes.
    let nominal = compute_freshness(&p, None);
    assert_eq!(fca_flux_du_genre(&nominal, "snapshot").len(), 2, "contrôle positif : les deux genres sont listés : {nominal}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET : {nominal}");

    // VOIE ISOLANTE — la COLONNE `kind` est retirée : l'énoncé des instantanés ne se prépare plus,
    // pendant que `MAX(ts)` (qui ne la nomme pas) continue de répondre.
    fca_ecrire(&p, "ALTER TABLE snapshot RENAME COLUMN kind TO kind_hors_d_atteinte;");
    let isole = compute_freshness(&p, None);
    let familles = fca_flux_du_genre(&isole, "snapshot");
    assert_eq!(familles.len(), 1, "la famille entière est remplacée par UNE entrée d'aveu : {isole}");
    assert_eq!(familles[0]["famille_non_lue"], json!(true), "qui se dit famille : {}", familles[0]);
    assert!(
        familles[0]["cause"].as_str().unwrap_or("").contains("FAMILLE DE FLUX NON LUE"),
        "avec sa cause : {}",
        familles[0]
    );
    assert_eq!(isole["pipeline_fresh"], json!(true), "ET LA SANTÉ DU PIPELINE A ÉTÉ LUE : l'aveu de famille se tient seul : {isole}");
    assert!(fca_flux(&isole, "web").is_some(), "les flux d'événements restent lus et listés : {isole}");

    // VOIE DEMANDÉE PAR LA CELLULE — la TABLE est retirée. La santé du pipeline lit `snapshot` dans son
    // union : les deux lectures tombent ensemble, et c'est exactement ce qu'il faut vérifier — deux
    // aveux distincts, pas un seul qui absorbe l'autre.
    fca_ecrire(&p, "ALTER TABLE snapshot RENAME TO snapshot_hors_d_atteinte;");
    let sans_table = compute_freshness(&p, None);
    let familles = fca_flux_du_genre(&sans_table, "snapshot");
    assert_eq!(familles.len(), 1, "table hors d'atteinte : la famille est encore LISTÉE et avouée : {sans_table}");
    assert_eq!(familles[0]["famille_non_lue"], json!(true), "même aveu : {}", familles[0]);
    assert_eq!(sans_table["pipeline_fresh"], Value::Null, "et la santé du pipeline tombe AUSSI, sans se confondre : {sans_table}");
    let racine = sans_table["error"].as_str().unwrap_or("");
    assert!(racine.contains("les flux d'instantanés"), "la racine nomme le PARCOURS : {racine}");
    assert!(racine.contains("LECTURES NON FAITES"), "et, séparément, la LIGNE non lue : {racine}");
}

// -------------------------------------------------------------------------------------
// (3) LES DEUX COMPTES DU FLUX DES MÉTRIQUES — `null`, JAMAIS ZÉRO
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : quand les comptes du flux des métriques ne se lisent pas, le flux reste listé avec
/// son `last_seen` LU (contrôle d'isolation), mais `n_24h` vaut `null` et non zéro, le nombre de séries
/// vaut `null` et non zéro, le NOM du flux ne porte plus de nombre du tout, la sous-liste des séries est
/// `null` et non un tableau vide, et chacune de ces trois absences porte sa cause nommée. La racine les
/// NOMME dans `non_lus`.
///
/// POURQUOI LE NOM COMPTE AUTANT QUE LES CHAMPS : le nombre de séries ne vivait QUE dans le nom servi
/// (« métriques · 12 séries »), qui est la première chose qu'un analyste lit. « métriques · 0 séries »
/// est un verdict, et aucun champ à côté ne l'aurait contredit.
///
/// CE QU'IL NE TIENT PAS : il n'y a qu'UNE voie ici, et ce n'est pas un témoin incomplet — un `COUNT`
/// rend toujours un entier, donc aucune ligne illisible ne peut faire échouer son mappeur ; la seule
/// façon de rater cette lecture est de refuser sa préparation. Et depuis que les deux comptes sont lus
/// par un seul énoncé, ils tombent ensemble par construction : ce témoin ne les sépare pas.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.unwrap_or(0)` sur les comptes — `n_24h` et le nombre de
/// séries redeviennent `0`, le nom redevient « métriques · 0 séries », et les trois premières assertions
/// du dernier bloc tombent.
#[test]
fn p10_20g_les_comptes_du_flux_des_metriques_non_lus_valent_null_et_non_zero() {
    let (_t, p) = fca_base_disque("fca-comptes");
    fca_evenements(&p, "web", 4);
    fca_ecrire(
        &p,
        &format!("INSERT INTO metric(ts,name,value) VALUES({0},'load1',0.5),({0},'load5',0.7);", now() - 30),
    );

    // CONTRÔLE POSITIF — les comptes aboutissent : ce sont des nombres, et le nom les porte.
    let nominal = compute_freshness(&p, None);
    let flux = fca_flux(&nominal, "métriques").expect("contrôle positif : le flux des métriques est listé");
    assert_eq!(flux["n_24h"], json!(2), "le volume est COMPTÉ : {flux}");
    assert_eq!(flux["name"], json!("métriques · 2 séries"), "et le nom porte le nombre COMPTÉ : {flux}");
    assert_eq!(flux["series"].as_array().map(|a| a.len()), Some(2), "la sous-liste est SERVIE : {flux}");
    assert!(flux.get("n_24h_non_lu").is_none(), "et rien n'y est avoué : {flux}");
    assert!(nominal.get("non_lus").is_none(), "chemin nominal : aucune lecture n'est nommée non lue : {nominal}");

    // LA COLONNE RETIRÉE : `COUNT(DISTINCT name)` et la liste des séries ne se préparent plus, pendant
    // que `MAX(ts)` — qui ne nomme pas `name` — continue de répondre. Le flux est donc LU, ses comptes
    // ne le sont pas, et c'est précisément le cas que le zéro rendait indétectable.
    fca_ecrire(&p, "ALTER TABLE metric RENAME COLUMN name TO name_hors_d_atteinte;");
    let avoue = compute_freshness(&p, None);
    let flux = fca_flux(&avoue, "métriques").expect("le flux reste LISTÉ : sa propre lecture, elle, a abouti");
    assert!(flux["last_seen"].is_i64(), "CONTRÔLE D'ISOLATION : son dernier point a bien été lu : {flux}");
    assert_eq!(flux["n_24h"], Value::Null, "le volume non compté vaut `null`, JAMAIS zéro : {flux}");
    assert_eq!(flux["nb_series"], Value::Null, "le nombre de séries non compté vaut `null`, JAMAIS zéro : {flux}");
    assert_eq!(flux["name"], json!("métriques"), "et le NOM ne porte aucun nombre fabriqué : {flux}");
    assert_eq!(flux["series"], Value::Null, "la sous-liste non lue est `null`, pas un tableau vide : {flux}");
    assert_eq!(flux["observed_interval_s"], Value::Null, "le rythme observé, qui en dérive, n'est pas dérivé d'un zéro : {flux}");
    assert!(flux["n_24h_non_lu"].as_str().unwrap_or("").contains("COMPTE NON LU"), "la cause du compte est nommée : {flux}");
    assert!(flux["nb_series_non_lu"].as_str().unwrap_or("").contains("COMPTE NON LU"), "pour les deux comptes : {flux}");
    assert!(
        flux["series_non_lues"].as_str().unwrap_or("").contains("FAMILLE DE FLUX NON LUE"),
        "et la sous-liste dit, elle aussi, qu'elle n'a pas été lue : {flux}"
    );
    assert!(
        avoue["non_lus"].as_array().map(|v| v.iter().any(|c| c.as_str().unwrap_or("").contains("les comptes du flux des métriques"))).unwrap_or(false),
        "la racine NOMME la lecture manquante : {avoue}"
    );
    assert_eq!(avoue["pipeline_fresh"], json!(true), "CONTRÔLE D'ISOLATION : la santé du pipeline a été lue : {avoue}");
}

// -------------------------------------------------------------------------------------
// (4) LA FLOTTE — `pipeline_fresh` N'EST PLUS UN BOOLÉEN NU
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `/api/fleet` sert `pipeline_fresh` LU (contrôle positif) et sert `null` — jamais
/// `false` — quand la lecture n'a pas eu lieu, avec sa cause nommée dans le corps ; l'inventaire d'hôtes,
/// lui, reste COMPLET (contrôle d'isolation : la lecture des hôtes ne passe pas par la même table), et
/// cette flotte-là n'est PAS mise en cache, sans quoi un `null` figé serait resservi trente secondes
/// après que la base est redevenue lisible.
///
/// POURQUOI `false` COÛTAIT : sur cette route, `false` veut dire « plus rien n'arrive, toutes sources
/// confondues » — une panne d'ingestion CONSTATÉE sur toute la flotte, que la console peint en bannière.
/// C'était la valeur servie sur une ligne que personne n'avait lue.
///
/// CE QU'IL NE TIENT PAS : il ne joue pas la route HTTP (le gestionnaire, son cache SWR et son portillon
/// de requêtes), il juge la lecture et le corps que celle-ci alimente.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `pipeline_is_fresh` (donc `unwrap_or(false)`) dans
/// `fleet_scan_all` — `pipeline_fresh` redevient `Some(false)`, la cause disparaît, et la flotte
/// redevient cachable.
#[test]
fn p10_20g_la_flotte_sert_une_sante_de_pipeline_non_lue_en_nul_avec_sa_cause() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
    assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
    let now_ts = now();
    hm_parc_metrique(&conn, &[("srv01", now_ts - 60), ("srv02", now_ts - 60)]);

    // CONTRÔLE POSITIF — la lecture aboutit : la santé est un FAIT, et la flotte est cachable.
    let nominal = fleet_scan_all(&conn, now_ts);
    assert_eq!(nominal.pipeline_fresh, Some(true), "un signal vient d'arriver : le pipeline EST frais, et LU");
    assert!(nominal.pipeline_non_lu.is_none(), "et rien n'est avoué");
    assert!(nominal.lue(), "une flotte entièrement lue est la seule qu'on mette en cache");
    assert_eq!(nominal.hosts.len(), 2, "contrôle positif : les deux machines sont listées");
    let corps = fleet_response(&nominal.hosts, nominal.pipeline_fresh, "host", false, 50, 0, now_ts);
    assert_eq!(corps["pipeline_fresh"], json!(true), "le corps servi porte le fait : {corps}");
    assert!(corps.get("pipeline_fresh_non_lu").is_none(), "et rien n'est avoué sur le chemin nominal : {corps}");

    // LA TABLE RETIRÉE : l'union que lit la santé du pipeline ne se prépare plus. L'inventaire, lu du
    // rollup d'hôtes, n'y touche pas.
    conn.execute_batch("ALTER TABLE event RENAME TO event_hors_d_atteinte;").unwrap();
    let avoue = fleet_scan_all(&conn, now_ts);
    assert_eq!(avoue.pipeline_fresh, None, "lecture non faite : jamais `false`, qui accuse la collecte de toute la flotte");
    assert!(
        avoue.pipeline_non_lu.as_deref().unwrap_or("").contains("SANTÉ DU PIPELINE NON LUE"),
        "et la cause est NOMMÉE : {:?}",
        avoue.pipeline_non_lu
    );
    assert!(avoue.hotes_lus, "CONTRÔLE D'ISOLATION : les hôtes, eux, ont été lus");
    assert_eq!(avoue.hosts.len(), 2, "et l'inventaire reste COMPLET : ce n'est pas une flotte vide");
    assert!(!avoue.lue(), "une santé de pipeline non lue GATE le cache, comme le reste");
    let corps = fleet_response(&avoue.hosts, avoue.pipeline_fresh, "host", false, 50, 0, now_ts);
    assert_eq!(corps["pipeline_fresh"], Value::Null, "et le corps servi porte `null`, pas `false` : {corps}");
    assert!(
        corps["pipeline_fresh_non_lu"].as_str().unwrap_or("").contains("SANTÉ DU PIPELINE NON LUE"),
        "le `null` ne voyage JAMAIS seul : la phrase est posée à côté du champ qu'elle explique : {corps}"
    );
    assert_eq!(corps["hosts"].as_array().map(|a| a.len()), Some(2), "avec l'inventaire complet à côté : {corps}");
    assert!(
        corps.get("error").is_none(),
        "et SURTOUT pas dans `error` : la console y lit un REFUS et viderait une vue dont l'inventaire est \
         complet et juste — on remplacerait une valeur fausse par une page vide : {corps}"
    );
}

// -------------------------------------------------------------------------------------
// (5) LE COMPOSANT D'INGEST — « INACTIF » EST L'ÉTAT D'UNE INSTALLATION NEUVE
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : sur une base dont la dernière donnée reçue ne peut plus être lue, le composant
/// d'ingest ne sort PLUS en `idle` « aucune donnée encore ingérée » — l'état d'une installation NEUVE,
/// servi sur la santé système, le paquet de diagnostic et `/metrics`. Il sort en `yellow` avec une phrase
/// qui dit que la santé du pipeline n'a pas été LUE. Les deux contrôles positifs sont dans le même corps :
/// une base avec une donnée fraîche donne `green`, et une base VIDE donne bien `idle` — sans quoi ce
/// témoin serait vert sur un composant qui ne saurait plus dire « aucune donnée ».
///
/// POURQUOI CE SITE ÉTAIT LE PLUS SOURNOIS DES CINQ : deux replis s'y composaient. La fraîcheur retombait
/// sur « pas frais » et la présence de données sur « aucune », et c'est la seconde qui était testée en
/// premier — une base illisible sortait donc en `idle`, le plus rassurant des cinq états.
///
/// CE QU'IL NE TIENT PAS : il ne juge pas la surface qui affiche ce composant, ni l'ordre des autres
/// bras (file non lisible, backlog, quarantaine), qui gardent leur priorité.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.ok().flatten()` sur la lecture de la dernière donnée —
/// la base illisible ressort en `idle` et le dernier bloc tombe.
#[test]
fn p10_20g_le_composant_dingest_ne_se_declare_pas_inactif_sur_une_lecture_non_faite() {
    let tmp = crate::tmp_possede::TmpPossede::neuf("fca-ingest");
    let spool = tmp.racine().chemin().to_str().unwrap().to_string();
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
    assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
    let fraicheur = FraicheurDesTicks { regles: now(), rollups: now() };
    let ingest = |c: &Connection| -> Value {
        component_health_avec(c, &spool, "", 80, fraicheur)
            .into_iter()
            .find(|v| v["component"] == "ingest")
            .expect("le composant d'ingest est toujours publié")
    };

    // CONTRÔLE POSITIF (1/2) — base VIDE : « aucune donnée encore ingérée » est un FAIT, et il subsiste.
    let vide = ingest(&conn);
    assert_eq!(vide["state"], json!("idle"), "une base neuve est INACTIVE, et doit le rester : {vide}");

    // CONTRÔLE POSITIF (2/2) — une donnée fraîche : le composant est VERT.
    conn.execute("INSERT INTO event(ts,source,category,severity,message) VALUES(?1,'sshd','auth',1,'x')", params![now()]).unwrap();
    let frais = ingest(&conn);
    assert_eq!(frais["state"], json!("green"), "donnée fraîche : {frais}");

    // LA TABLE RETIRÉE : l'union ne se prépare plus. Ce n'est ni « aucune donnée », ni « collecte arrêtée ».
    conn.execute_batch("ALTER TABLE event RENAME TO event_hors_d_atteinte;").unwrap();
    let non_lu = ingest(&conn);
    assert_ne!(non_lu["state"], json!("idle"), "une base illisible n'est PAS une installation neuve : {non_lu}");
    assert_ne!(non_lu["state"], json!("green"), "et elle n'est pas verte non plus : {non_lu}");
    assert_eq!(non_lu["state"], json!("yellow"), "c'est l'état qui appelle un regard : {non_lu}");
    let detail = non_lu["detail"].as_str().unwrap_or("");
    assert!(detail.contains("NON LUE"), "et le détail DIT que la lecture n'a pas eu lieu : {detail}");
    assert!(!detail.contains("aucune donnée encore ingérée"), "il n'affirme plus rien sur la présence de données : {detail}");
}
