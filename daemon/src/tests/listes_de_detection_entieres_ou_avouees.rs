// =====================================================================================
// `P10.7-f` (rang 2) — LES DIX LISTES DE DÉTECTION SONT ENTIÈRES OU AVOUÉES.
//
// LE DÉFAUT MESURÉ (garde de famille `check_a_truncated_list_is_never_served_as_a_complete_one.py`,
// relevé du 2026-09-16) : dix sites de `daemon/src/handlers/` lisaient leur liste par un itérateur de
// lignes APLATI (`query_map(..).flatten()`, deux fois précédé d'un `unwrap()`). Un itérateur de lignes
// rusqlite rend des `Result` UNE LIGNE À LA FOIS : le mappeur peut échouer sur une seule ligne sans que
// la requête ait échoué — cache de schéma périmé qui rend « no such table » au PREMIER pas (famille
// mesurée dans `flatten-avale-no-such-table-au-premier-pas`), colonne ajoutée par une migration que la
// connexion qui sert ne voit pas encore, valeur corrompue. L'aplatissement jetait CETTE ligne-là et
// rendait la suite, sous une forme rigoureusement identique à celle d'une liste complète.
//
// POURQUOI LE RANG DEUX EST UN RANG À PART, ET PAS UN RANG UN AU RABAIS. Au rang un, la liste avalée
// était SERVIE À UN HUMAIN qui décide : un jeton absent est un accès que personne ne révoque. Ici, la
// moitié des sites ne servent RIEN À PERSONNE : ce sont des lectures INTERNES que le produit s'adresse
// à lui-même, et une ligne avalée n'y est pas une ligne d'affichage en moins — c'est de la DÉTECTION EN
// MOINS. Le produit continue de tourner, plus aveugle, et aucune réponse ne ment : une politique de
// routage perdue fait partir sur TOUS les canaux une alerte que l'exploitant avait adressée à une seule
// astreinte ; un silence perdu réveille quelqu'un qui avait été dispensé ; un engagement perdu arme
// l'auto-ban contre une cible de pentest AUTORISÉE ; un historique perdu déplace le z-score et fabrique
// l'anomalie dans les deux sens (manquée si les valeurs hautes sont tombées, inventée si ce sont les
// basses) ; une source dont le connecteur n'a pas pu être lu devient « inattendue », et l'opérateur
// enquête sur un flux qu'il a lui-même configuré. C'est pourquoi ces cinq témoins-là ne jugent pas un
// corps : ils jugent CE QUE L'APPELANT FAIT.
//
// CE QUE CES TÉMOINS JOUENT, ET POURQUOI DEUX VOIES. La voie de la TABLE RETIRÉE (renommée sous les
// pieds du lecteur) fait échouer la PRÉPARATION : elle prouve que le site n'invente plus une liste vide
// et ne panique plus (`playbooks_list` portait deux `unwrap()`). La voie de la LIGNE ILLISIBLE (un
// `BLOB` posé dans une colonne `TEXT` — SQLite conserve un blob tel quel quelle que soit l'affinité, et
// `get::<String>` le refuse ; pour l'historique de ligne de base, un blob dans une colonne `REAL`) fait
// échouer le MAPPEUR sur UNE ligne, la requête restant saine : c'est LA voie que l'aplatissement
// avalait, et c'est elle qui tue la mutation. Chaque témoin porte son CONTRÔLE POSITIF (la liste
// complète, comptée, ou le comportement nominal de l'appelant) dans le même corps de test : sans lui,
// un aveu INCONDITIONNEL passerait pour un aveu.
//
// LA FORME DES CORRECTIFS EST CELLE DU DÉPÔT, PAS UNE FORME NEUVE.
//   * les QUATRE listes JSON servies (`rules_list`, `parsers_list`, `baselines_list`, `playbooks_list`)
//     passent par le fabricant unique `liste_bornee::corps_de_liste_illisible` (`P10.7-z`) : la clé de
//     liste EXISTE, VIDE, et `error` porte `CAUSE_LISTE_ILLISIBLE` — exactement ce que le rang un a posé
//     sur les jetons et le catalogue des rôles ;
//   * le vocabulaire de complétion gagne la TROISIÈME DISTINCTION que son propre type déclarait ne pas
//     tenir (`SourcesConnues::non_lue`), et — c'est le point dur de ce site — son cache SWR de deux
//     minutes N'ACCUEILLE PLUS un aveu : une lecture ratée mise en cache se resservirait longtemps après
//     que sa cause a disparu ;
//   * les CINQ lectures internes rendent un `rusqlite::Result`, et chaque appelant agit en connaissance :
//     le dispatch de notifications SAUTE son tour et le COMPTE (`metrics::compter_un_tick_aveugle`, la
//     forme des lots 106/109 sur cette même fonction) sans marquer aucune alerte `notified=1` ; le cache
//     de portée des engagements GARDE sa valeur précédente et compte le tour, parce que le vider ARME
//     l'auto-ban ; l'évaluation de ligne de base rend `ok=false` — « non évalué », ni anomalie ni
//     normalité —, que `run_baselines` compte sans avancer `last_bucket` ; et l'inventaire des sources
//     sert `indeterminee: true` avec `expected`/`unexpected` à `null`, jamais un `unexpected` établi.
//   * la route `GET /api/engagements/active` rend un 503 NOMMÉ parce que son corps nominal est un
//     TABLEAU NU sans clé où poser un aveu (même contrainte que la liste SSO du rang un), et parce que
//     son unique consommateur — `collectors/engagement-adapter.sh` — porte DÉJÀ un fail-closed gradué
//     sur le statut, qu'un 200 portant un tableau amputé n'emprunterait pas.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : ils ne jugent pas ce que la console PEINT de ces aveux (le démon
// avoue ; que `web/` le rende se juge dans `check_a_refusal_is_not_rendered_as_an_absence.py`), ni le
// script `collectors/engagement-adapter.sh` lui-même, qui est LU et non JOUÉ. Et aucun d'eux n'exerce le
// chemin `notify_send` réseau : les canaux y sont de genre `lookup`, qui n'émet rien et écrit dans une
// table — c'est précisément ce qui rend « à qui l'alerte est partie » OBSERVABLE dans un test.
// =====================================================================================

/// Statut + corps JSON d'une réponse (les listes servies ici rendent `Json<Value>` ; seule la route des
/// engagements rend une `Response`, et c'est son statut qui porte le refus).
async fn lde_corps(r: Response) -> (u16, Value) {
    let statut = r.status().as_u16();
    let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
    (statut, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

/// L'état file-backed de ce rang : schéma + migrations complets, un admin. UNE SEULE ÉCRITURE de cette
/// fixture, partagée avec le rang un (`lsa_etat`) via `sp_state` — deux fixtures jumelles vieilliraient
/// séparément, et ce dépôt paie cher les lecteurs jumeaux.
fn lde_etat(tag: &str) -> (AppState, AuthUser, crate::tmp_possede::TmpDb) {
    let (st, p) = sp_state(&format!("lde-{tag}"));
    (st, sp_au("adm", "admin"), p)
}

/// Un jeton d'agent lié à un hôte (la seule identité que `engagements_active` accepte).
fn lde_au_agent(hote: &str) -> AuthUser {
    AuthUser {
        name: hote.into(), role: "agent".into(), tenant: "default".into(), is_superadmin: false,
        method: "token".into(), csrf: String::new(), env: None,
    }
}

/// Le compte de tours aveugles d'un balayage, AVANT le geste (jamais une valeur absolue : les compteurs
/// sont globaux au processus et d'autres témoins les touchent).
fn lde_ticks(balayage: &str) -> u64 {
    crate::metrics::tick_aveugle_de(balayage).map(|(n, _)| n).unwrap_or(0)
}

/// VRAI si une alerte a été écrite dans le lookup `canal` sous la clé `cle`. C'est l'observable « à qui
/// l'alerte est partie » : un canal de genre `lookup` n'émet aucun réseau, il ÉCRIT.
fn lde_canal_a_recu(conn: &Connection, canal: &str, cle: &str) -> bool {
    conn.query_row::<i64, _, _>(
        "SELECT COUNT(*) FROM lookup_kv WHERE name=?1 AND \"key\"=?2",
        params![canal, cle],
        |r| r.get(0),
    )
    .unwrap_or(0)
        > 0
}

/// L'état `notified` d'une alerte désignée par sa règle.
fn lde_notifiee(conn: &Connection, regle: &str) -> i64 {
    conn.query_row("SELECT notified FROM alert WHERE rule=?1", params![regle], |r| r.get(0)).unwrap()
}

/// Les deux canaux `lookup` du dispatch, plus une alerte à notifier. Rend la connexion prête.
fn lde_base_de_dispatch() -> Connection {
    let conn = test_db();
    conn.execute_batch(
        "INSERT INTO notifier(id,name,kind,enabled,url,min_severity,config) VALUES(1,'a','lookup',1,'',0,'{\"lookup\":\"canal_a\",\"key_field\":\"host\"}');\
         INSERT INTO notifier(id,name,kind,enabled,url,min_severity,config) VALUES(2,'b','lookup',1,'',0,'{\"lookup\":\"canal_b\",\"key_field\":\"host\"}');",
    )
    .expect("fixture : deux canaux lookup");
    conn
}

/// Une alerte à notifier, sur l'hôte donné.
fn lde_alerte(conn: &Connection, regle: &str, host: &str) {
    conn.execute(
        "INSERT INTO alert(ts,rule,severity,title,detail,status,mitre,host) VALUES(?1,?2,3,'A','','new','',?3)",
        params![now(), regle, host],
    )
    .expect("fixture : alerte à notifier");
}

// -------------------------------------------------------------------------------------
// (1) LE CATALOGUE DES RÈGLES DE DÉTECTION
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `rules_list` sert le catalogue ENTIER (les règles semées par les migrations PLUS les
/// deux du témoin, comptées) ; une règle dont le mappeur échoue rend `rules` NON ÉTABLIE (`[]` + `error`)
/// au lieu d'un catalogue amputé servi comme complet ; une table retirée avoue au lieu de rendre `[]`
/// sous 200. L'`avertissement_overlay`, lui, reste servi dans l'aveu : il est DÉRIVÉ DU CODE et non de la
/// lecture, et le taire n'apprendrait rien de plus au client.
///
/// CE QU'IL NE TIENT PAS : il ne dit rien de ce que la console de détection peint de cet `error`
/// (`web/rules.js` ne le lit pas encore), ni du tir des règles — seulement de l'INVENTAIRE servi.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.map(|x| x.flatten().collect()).unwrap_or_default()` —
/// le corps redevient `{"rules": [<n règles sur n+1>]}` sans `error`, et les deux asserts de l'aveu
/// tombent.
#[tokio::test]
async fn p10_7f_listes_de_detection_le_catalogue_des_regles_est_entier_ou_avoue() {
    let (st, au, _p) = lde_etat("rules");
    // Les migrations SÈMENT des règles livrées : le contrôle positif est donc un DELTA mesuré, pas un
    // nombre écrit à la main (qui vieillirait au premier semeur ajouté).
    let semees = rules_list(State(st.clone()), Extension(au.clone())).await.0["rules"]
        .as_array()
        .map(Vec::len)
        .expect("instrument : la liste nominale est un tableau");
    lsa_ecrire(&st, "INSERT INTO rule(name,query) VALUES('r-temoin-a','search source=web | stats count');\
                     INSERT INTO rule(name,query) VALUES('r-temoin-b','search source=auth | stats count');");
    let nominal = rules_list(State(st.clone()), Extension(au.clone())).await.0;
    assert_eq!(
        nominal["rules"].as_array().map(Vec::len),
        Some(semees + 2),
        "contrôle positif : les deux règles du témoin s'ajoutent aux {semees} semées : {nominal}"
    );
    assert!(nominal.get("error").is_none(), "chemin nominal MUET — un aveu inconditionnel n'est pas un aveu : {nominal}");

    // UNE LIGNE ILLISIBLE : `name` porte un BLOB, que `get::<String>` refuse. La requête reste saine.
    lsa_ecrire(&st, "INSERT INTO rule(name,query) VALUES('r-temoin-c','x'); UPDATE rule SET name=x'FF' WHERE name='r-temoin-c';");
    let avoue = rules_list(State(st.clone()), Extension(au.clone())).await.0;
    lsa_juger_l_aveu(&avoue, "rules");
    assert!(
        avoue.as_object().map(|o| o.contains_key("avertissement_overlay")).unwrap_or(false),
        "l'avertissement d'overlay est DÉRIVÉ du code, pas de la lecture : il reste servi dans l'aveu : {avoue}"
    );

    // LA TABLE RETIRÉE : la préparation échoue. Avant, la route rendait `{"rules": []}` sous 200.
    lsa_retirer_la_table(&st, "rule");
    let sans_table = rules_list(State(st.clone()), Extension(au.clone())).await.0;
    lsa_juger_l_aveu(&sans_table, "rules");
}

// -------------------------------------------------------------------------------------
// (2) LE REGISTRE DES ANALYSEURS (PARSERS)
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `parsers_list` sert le registre ENTIER (les analyseurs builtin semés par les
/// migrations PLUS celui du témoin) ; un analyseur dont la ligne ne se décode pas rend `parsers` NON
/// ÉTABLIE avec sa cause, au lieu de faire lire « ce format n'est pas analysé » d'un format qui l'est.
///
/// CE QU'IL NE TIENT PAS : il ne juge pas le cache COMPILÉ des analyseurs (`parsers_reload`), qui a sa
/// propre voie de chargement et ses propres témoins — seulement la liste servie.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.map(|x| x.flatten().collect()).unwrap_or_default()` —
/// la liste revient amputée d'une ligne, sans `error`.
#[tokio::test]
async fn p10_7f_listes_de_detection_le_registre_des_analyseurs_est_entier_ou_avoue() {
    let (st, au, _p) = lde_etat("parsers");
    let semes = parsers_list(State(st.clone()), Extension(au.clone())).await.0["parsers"]
        .as_array()
        .map(Vec::len)
        .expect("instrument : la liste nominale est un tableau");
    assert!(semes > 0, "instrument : les analyseurs builtin sont bien semés par les migrations");
    lsa_ecrire(&st, "INSERT INTO parser(name,source,pattern) VALUES('p-temoin','mon-format','(?P<u>\\S+)');");
    let nominal = parsers_list(State(st.clone()), Extension(au.clone())).await.0;
    assert_eq!(
        nominal["parsers"].as_array().map(Vec::len),
        Some(semes + 1),
        "contrôle positif : l'analyseur du témoin s'ajoute aux {semes} builtin : {nominal}"
    );
    assert!(nominal.get("error").is_none(), "chemin nominal MUET : {nominal}");

    lsa_ecrire(&st, "UPDATE parser SET name=x'FF' WHERE name='p-temoin';");
    let avoue = parsers_list(State(st.clone()), Extension(au.clone())).await.0;
    lsa_juger_l_aveu(&avoue, "parsers");

    lsa_retirer_la_table(&st, "parser");
    let sans_table = parsers_list(State(st.clone()), Extension(au.clone())).await.0;
    lsa_juger_l_aveu(&sans_table, "parsers");
}

// -------------------------------------------------------------------------------------
// (3) LA LISTE DES LIGNES DE BASE (BASELINES)
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `baselines_list` sert les deux lignes de base du témoin ; une ligne illisible ou une
/// table retirée rendent `baselines` NON ÉTABLIE avec sa cause, au lieu de faire conclure « aucune ligne
/// de base ne couvre cette entité » — conclusion au bout de laquelle on en écrit une seconde, en double.
///
/// CE QU'IL NE TIENT PAS : il ne juge pas l'ÉVALUATION des lignes de base — c'est le témoin (9), sur une
/// autre lecture et un autre appelant.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.map(|x| x.flatten().collect()).unwrap_or_default()`.
#[tokio::test]
async fn p10_7f_listes_de_detection_les_lignes_de_base_sont_entieres_ou_avouees() {
    let (st, au, _p) = lde_etat("baselines");
    lsa_ecrire(&st, "INSERT INTO ueba_baseline(name,query,entity_field) VALUES('b-a','search source=auth | stats count by host','host');\
                     INSERT INTO ueba_baseline(name,query,entity_field) VALUES('b-b','search source=web | stats count by host','host');");
    let nominal = baselines_list(State(st.clone()), Extension(au.clone())).await.0;
    assert_eq!(nominal["baselines"].as_array().map(Vec::len), Some(2), "contrôle positif : les deux lignes de base : {nominal}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET : {nominal}");

    lsa_ecrire(&st, "UPDATE ueba_baseline SET name=x'FF' WHERE name='b-b';");
    let avoue = baselines_list(State(st.clone()), Extension(au.clone())).await.0;
    lsa_juger_l_aveu(&avoue, "baselines");

    lsa_retirer_la_table(&st, "ueba_baseline");
    let sans_table = baselines_list(State(st.clone()), Extension(au.clone())).await.0;
    lsa_juger_l_aveu(&sans_table, "baselines");
}

// -------------------------------------------------------------------------------------
// (4) LES PLAYBOOKS — ET LEUR CONSÉQUENCE EFFECTIVE
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `playbooks_list` sert les deux playbooks avec leur `consequence` et le `mode` global ;
/// une ligne illisible ou une table retirée rendent `playbooks` NON ÉTABLIE avec sa cause — et `mode`
/// reste servi, parce qu'il vient d'une AUTRE lecture (la table `meta`) qui, elle, a abouti. C'est la vue
/// où l'on vérifie « qu'est-ce qui peut bannir tout seul ici » : un `ban_ip` avalé s'y lit « aucune
/// réponse automatique n'est armée » pendant qu'elle l'est.
///
/// CE QU'IL TIENT AUSSI, ET C'EST NEUF : la table retirée faisait PANIQUER la route (deux `unwrap()`),
/// et une panique sur l'écrivain partagé n'est pas un aveu — c'est un 500 sans cause et un risque de
/// propagation. Le témoin l'appelle et lit un corps : s'il paniquait, il ne lirait rien.
///
/// CE QU'IL NE TIENT PAS : il ne joue pas `run_playbooks` (l'exécution), ni la porte « SQL brut = admin ».
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `rows.flatten().collect::<Vec<_>>()` après les deux
/// `unwrap()` — la liste revient amputée sans `error`, et la branche « table retirée » panique.
#[tokio::test]
async fn p10_7f_listes_de_detection_les_playbooks_sont_entiers_ou_avoues() {
    let (st, au, _p) = lde_etat("playbooks");
    lsa_ecrire(&st, "INSERT INTO playbook(name,query,action_kind) VALUES('pb-a','search source=web | stats count by src_ip','ban_ip');\
                     INSERT INTO playbook(name,query,action_kind) VALUES('pb-b','search source=auth | stats count by src_ip','unban_ip');");
    let nominal = playbooks_list(State(st.clone()), Extension(au.clone())).await.0;
    assert_eq!(nominal["playbooks"].as_array().map(Vec::len), Some(2), "contrôle positif : les deux playbooks : {nominal}");
    assert!(nominal["mode"].is_string(), "contrôle positif : le mode global est servi : {nominal}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET : {nominal}");

    lsa_ecrire(&st, "UPDATE playbook SET name=x'FF' WHERE name='pb-b';");
    let avoue = playbooks_list(State(st.clone()), Extension(au.clone())).await.0;
    lsa_juger_l_aveu(&avoue, "playbooks");
    assert!(
        avoue["mode"].is_string(),
        "`mode` vient d'une AUTRE lecture, qui a abouti : il reste servi dans l'aveu : {avoue}"
    );

    // LA TABLE RETIRÉE : avant, DEUX `unwrap()` faisaient paniquer la route au lieu d'avouer.
    lsa_retirer_la_table(&st, "playbook");
    let sans_table = playbooks_list(State(st.clone()), Extension(au.clone())).await.0;
    lsa_juger_l_aveu(&sans_table, "playbooks");
}

// -------------------------------------------------------------------------------------
// (5) LE VOCABULAIRE DE COMPLÉTION — ET SON CACHE DE DEUX MINUTES
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT, EN DEUX PROPRIÉTÉS DISTINCTES :
///   (a) `/api/soql/schema` sert `values.source: []` AVEC `values.source_non_lue: true` et `error` quand
///       l'inventaire n'a pas pu être lu — au lieu d'un vocabulaire vide indiscernable d'une base neuve.
///       Le défaut ici n'est pas une erreur visible : c'est que l'analyste NE VOIT PAS la source, donc ne
///       l'interroge pas, donc conclut qu'il n'y a rien à y voir. Le défaut est dans ce qu'il ne cherche pas.
///   (b) — LE POINT DUR — UN AVEU N'ENTRE PAS DANS LE CACHE. Le cache est un SWR de deux minutes keyé par
///       chemin de base : y écrire une lecture ratée la faisait RESSERVIR pendant deux minutes, bien après
///       que sa cause a disparu. Le témoin fait échouer la lecture, puis RÉPARE la cause et rappelle
///       IMMÉDIATEMENT la même route sur la MÊME base : si l'aveu avait été mis en cache, le second appel
///       le resservirait. Il sert le vocabulaire réel.
///
/// POURQUOI DEUX BASES : la voie « ligne illisible » se répare par un `DELETE` (aucune DDL), donc elle
/// porte la propriété (b) sans risque d'imputer à un cache ce qui serait un cache de SCHÉMA. La voie
/// « table retirée » vit sur une base à elle et n'est jouée que dans un sens.
///
/// CE QU'IL NE TIENT PAS : il ne mesure pas le COÛT de la relecture par appel tant que la base refuse
/// (assumé : c'est le chemin d'erreur, et `read_with_watchdog` le borne) ; il ne juge pas non plus les
/// deux lecteurs internes de la façade `soql_known_sources`, qui n'ont pas de corps où porter l'aveu et
/// dont la borne est documentée à l'endroit où elle mord.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `rows.flatten()` (le corps sert un vocabulaire amputé sans
/// `source_non_lue`), ou remettre l'insertion au cache inconditionnelle (le second appel resservirait
/// l'aveu, et l'assert du vocabulaire réel tomberait).
#[tokio::test]
async fn p10_7f_listes_de_detection_le_vocabulaire_de_completion_avoue_et_ne_met_pas_laveu_en_cache() {
    // (a+b) LIGNE ILLISIBLE, puis réparation SANS DDL — la preuve que l'aveu n'a pas été mis en cache.
    let (st, au, _p) = lde_etat("soql-ligne");
    lsa_ecrire(&st, "INSERT INTO event_rollup(bucket,source,severity,action,n) VALUES(1000,'auth',0,'',3);\
                     INSERT INTO event_rollup(bucket,source,severity,action,n) VALUES(1000,'web',0,'',3);\
                     INSERT INTO event_rollup(bucket,source,severity,action,n) VALUES(1000,'zzz-blob',0,'',3);\
                     UPDATE event_rollup SET source=x'FF' WHERE source='zzz-blob';");
    let avoue = soql_schema(State(st.clone()), Extension(au.clone())).await.0;
    assert_eq!(avoue["values"]["source"], json!([]), "une ligne illisible ne rend pas un vocabulaire AMPUTÉ : {}", avoue["values"]);
    assert_eq!(avoue["values"]["source_non_lue"], json!(true), "et le corps DIT que ce vide n'est pas un fait : {}", avoue["values"]);
    assert_eq!(
        avoue["error"],
        json!(crate::handlers::liste_bornee::CAUSE_LISTE_ILLISIBLE),
        "l'aveu prend la clé que tout le dépôt pose : {avoue}"
    );

    // LA CAUSE DISPARAÎT — et le MÊME appel, sur la MÊME base, DANS la fenêtre de deux minutes du cache.
    lsa_ecrire(&st, "DELETE FROM event_rollup WHERE typeof(source)='blob';");
    let repare = soql_schema(State(st.clone()), Extension(au.clone())).await.0;
    assert_eq!(
        repare["values"]["source"],
        json!(["auth", "web"]),
        "CONTRÔLE POSITIF ET PREUVE DU CACHE : l'aveu n'a PAS été mis en cache, le vocabulaire réel est servi : {}",
        repare["values"]
    );
    assert_eq!(repare["values"]["source_non_lue"], json!(false), "chemin nominal : rien à avouer : {}", repare["values"]);
    assert!(repare.get("error").is_none(), "chemin nominal MUET : un aveu inconditionnel n'est pas un aveu");

    // (a) TABLE RETIRÉE, sur une base à elle (aucune restauration : la DDL ne sert pas la propriété (b)).
    let (st2, au2, _p2) = lde_etat("soql-table");
    lsa_ecrire(&st2, "INSERT INTO event_rollup(bucket,source,severity,action,n) VALUES(1000,'auth',0,'',3);");
    lsa_retirer_la_table(&st2, "event_rollup");
    let sans_table = soql_schema(State(st2.clone()), Extension(au2.clone())).await.0;
    assert_eq!(sans_table["values"]["source"], json!([]), "{}", sans_table["values"]);
    assert_eq!(sans_table["values"]["source_non_lue"], json!(true), "table retirée : NON LU, jamais « aucune source » : {}", sans_table["values"]);
}

// -------------------------------------------------------------------------------------
// (6) LE ROUTAGE DES NOTIFICATIONS — L'APPELANT NE ROUTE PAS À PLAT SUR UNE POLITIQUE NON LUE
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT, ET C'EST LE COMPORTEMENT DE L'APPELANT, PAS UN CORPS : sur une lecture ratée des
/// politiques de routage, `dispatch_notifications` SAUTE son tour. Trois faits, tous nécessaires :
///   1. AUCUN FAN-OUT PLAT. C'était le défaut : `load_policies` rendait `Vec::new()` sur échec, et un
///      vecteur vide a un SENS MÉTIER ici — le « MODE 0 » documenté sur `dispatch_notifications`, qui
///      envoie à TOUS les canaux activés. Une lecture ratée se traduisait donc, mot pour mot, en
///      « envoyez à tout le monde ». Le témoin le mesure sur le canal `canal_b`, qu'AUCUNE politique ne
///      route : il doit rester vide, et il le resterait aussi si le dispatch s'était contenté de ne rien
///      faire — c'est pourquoi les deux autres faits sont exigés avec lui.
///   2. L'ALERTE RESTE DISPATCHABLE. Rien ne la marque `notified=1` : la cause corrigée, le tour suivant
///      la route correctement. C'est la propriété que le lot 109 a posée sur cette même fonction, ici
///      étendue à une SECONDE lecture.
///   3. LE TOUR EST COMPTÉ, sous son nom (`dispatch_policies`) et avec sa cause.
///
/// CE QU'IL NE TIENT PAS : il n'exerce aucun envoi RÉSEAU (les deux canaux sont de genre `lookup`, qui
/// écrit dans une table au lieu d'émettre) ; il ne juge donc pas `notify_send`, tenu ailleurs.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.map(|x| x.flatten().collect()).unwrap_or_default()` dans
/// `load_policies` — la table retirée redonne un vecteur vide, le dispatch retombe en fan-out plat,
/// `canal_b` reçoit l'alerte et elle est marquée envoyée. Les trois asserts tombent ensemble.
#[test]
fn p10_7f_listes_de_detection_le_dispatch_ne_route_pas_a_plat_sur_une_politique_non_lue() {
    let conn = lde_base_de_dispatch();
    // UNE politique : tout va au canal #1, et à lui seul. C'est le routage que l'exploitant a écrit.
    conn.execute_batch("INSERT INTO notification_policy(id,matchers,contact_points,continue_,enabled) VALUES(1,'{}','1',0,1);")
        .expect("fixture : une politique de routage");
    lde_alerte(&conn, "r.nominal", "web-01");
    let db = Arc::new(Mutex::new(conn));

    // CONTRÔLE POSITIF : le routage écrit est APPLIQUÉ — canal_a reçoit, canal_b non, l'alerte est marquée.
    dispatch_notifications(&db);
    {
        let c = db.lock();
        assert!(lde_canal_a_recu(&c, "canal_a", "web-01"), "contrôle positif : la politique route vers le canal 1");
        assert!(!lde_canal_a_recu(&c, "canal_b", "web-01"), "contrôle positif : le canal 2 n'est PAS routé — sans cela, « pas de fan-out plat » ne prouverait rien");
        assert_eq!(lde_notifiee(&c, "r.nominal"), 1, "contrôle positif : l'alerte dispatchée est marquée");
    }

    // (a) UNE LIGNE ILLISIBLE : `matchers` porte un BLOB. La requête reste saine, le mappeur échoue.
    let avant = lde_ticks("dispatch_policies");
    {
        let c = db.lock();
        lde_alerte(&c, "r.blob", "web-01");
        c.execute_batch("INSERT INTO notification_policy(id,matchers,contact_points,continue_,enabled) VALUES(2,'{}','2',0,1); UPDATE notification_policy SET matchers=x'FF' WHERE id=2;")
            .expect("fixture : une politique dont la ligne ne se décode pas");
    }
    dispatch_notifications(&db);
    {
        let c = db.lock();
        assert_eq!(lde_notifiee(&c, "r.blob"), 0, "politiques non lues : l'alerte n'est PAS marquée envoyée — elle reste dispatchable");
        assert!(!lde_canal_a_recu(&c, "canal_b", "web-01"), "AUCUN FAN-OUT PLAT : le canal non routé ne reçoit rien");
        let (n, cause) = crate::metrics::tick_aveugle_de("dispatch_policies").expect("le tour aveugle est COMPTÉ, sous son nom");
        assert_eq!(n, avant + 1, "un tour aveugle = un compte de plus");
        assert!(!cause.is_empty(), "la cause du moteur est conservée avec le compte");
    }

    // (b) LA TABLE RETIRÉE : la préparation échoue. Même verdict, et le tour suivant relit.
    {
        let c = db.lock();
        c.execute_batch("DELETE FROM notification_policy WHERE id=2; ALTER TABLE notification_policy RENAME TO notification_policy_hors_d_atteinte;")
            .expect("fixture : la table de routage hors d'atteinte");
    }
    dispatch_notifications(&db);
    {
        let c = db.lock();
        assert_eq!(lde_notifiee(&c, "r.blob"), 0, "table retirée : toujours pas marquée envoyée");
        assert!(!lde_canal_a_recu(&c, "canal_b", "web-01"), "table retirée : toujours aucun fan-out plat");
        assert_eq!(lde_ticks("dispatch_policies"), avant + 2, "le second tour aveugle est compté à son tour");
        c.execute_batch("ALTER TABLE notification_policy_hors_d_atteinte RENAME TO notification_policy;").expect("la table revient");
    }

    // LA CAUSE DISPARUE : l'alerte que rien n'avait marquée part ENFIN, et par la bonne route.
    dispatch_notifications(&db);
    let c = db.lock();
    assert_eq!(lde_notifiee(&c, "r.blob"), 1, "la lecture rétablie, l'alerte conservée est dispatchée au tour suivant");
    assert!(!lde_canal_a_recu(&c, "canal_b", "web-01"), "et elle part par le canal ROUTÉ, jamais par les deux");
    assert_eq!(lde_ticks("dispatch_policies"), avant + 2, "un tour LU ne compte rien");
}

// -------------------------------------------------------------------------------------
// (7) LES SILENCES — L'APPELANT NE NOTIFIE PAS CE QU'UN SILENCE NON LU AURAIT TU
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : sur une lecture ratée des silences, `dispatch_notifications` saute son tour, ne
/// notifie RIEN et ne marque RIEN. Le défaut était symétrique de celui des politiques et plus direct : un
/// vecteur vide se lit « rien n'est muet », donc tout part. Un silence est posé par un humain PENDANT une
/// maintenance ou un exercice rouge ; l'avaler réveille une astreinte explicitement dispensée, et c'est
/// le genre de bruit qui apprend à l'astreinte à ignorer le canal.
///
/// LE CONTRÔLE POSITIF EST DOUBLE, et il le faut : une alerte sur l'hôte SILENCÉ est marquée sans être
/// écrite au canal (la mise en sourdine est GOUVERNÉE, pas une perte), et une alerte sur un AUTRE hôte
/// est bien écrite. Sans la seconde, « le canal n'a rien reçu » ne prouverait pas que le silence agit.
///
/// CE QU'IL NE TIENT PAS : il ne juge pas l'auto-expiration d'un silence (témoin voisin dans
/// `alerting.rs`), ni `notify_send`.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.map(|x| x.flatten().filter(..).collect())
/// .unwrap_or_default()` dans `load_active_silences` — la table retirée redonne un vecteur vide, l'alerte
/// que le silence couvrait est notifiée et marquée, et les asserts du tour sauté tombent.
#[test]
fn p10_7f_listes_de_detection_le_dispatch_ne_notifie_pas_ce_quun_silence_non_lu_aurait_tu() {
    let conn = lde_base_de_dispatch();
    conn.execute(
        "INSERT INTO silence(matchers,expires_at,reason,created,created_by) VALUES(?1,?2,'maintenance',?3,'alice')",
        params![matchers_to_json(&[("host".into(), "web-01".into())]), now() + 600, now()],
    )
    .expect("fixture : un silence actif sur web-01");
    lde_alerte(&conn, "r.mute", "web-01");
    lde_alerte(&conn, "r.bruyante", "db-01");
    let db = Arc::new(Mutex::new(conn));

    // CONTRÔLE POSITIF DOUBLE : l'hôte silencé ne parvient à aucun canal (et est marqué) ; l'autre passe.
    dispatch_notifications(&db);
    {
        let c = db.lock();
        assert!(!lde_canal_a_recu(&c, "canal_a", "web-01"), "contrôle positif : le silence MUSELLE l'alerte de web-01");
        assert_eq!(lde_notifiee(&c, "r.mute"), 1, "contrôle positif : une alerte MUSELÉE est traitée (mute gouverné), pas laissée en file");
        assert!(lde_canal_a_recu(&c, "canal_a", "db-01"), "contrôle positif : l'alerte hors silence, elle, PART — sans quoi le canal vide ne prouverait rien");
    }

    // (a) UNE LIGNE ILLISIBLE : `matchers` porte un BLOB.
    let avant = lde_ticks("dispatch_silences");
    {
        let c = db.lock();
        lde_alerte(&c, "r.apres", "web-01");
        c.execute_batch("INSERT INTO silence(matchers,expires_at,reason,created,created_by) VALUES('{}',9999999999,'x',1,'a');")
            .expect("fixture : une seconde ligne de silence");
        c.execute("UPDATE silence SET matchers=x'FF' WHERE reason='x'", []).expect("fixture : sa ligne ne se décode plus");
    }
    dispatch_notifications(&db);
    {
        let c = db.lock();
        assert_eq!(lde_notifiee(&c, "r.apres"), 0, "silences non lus : l'alerte n'est PAS marquée — rien n'est décidé sur une mise en sourdine inconnue");
        assert!(!lde_canal_a_recu(&c, "canal_a", "web-01"), "et elle n'est PAS notifiée : un silence non lu aurait pu la taire");
        let (n, cause) = crate::metrics::tick_aveugle_de("dispatch_silences").expect("le tour aveugle est COMPTÉ, sous son nom");
        assert_eq!(n, avant + 1, "un tour aveugle = un compte de plus");
        assert!(!cause.is_empty(), "la cause du moteur est conservée avec le compte");
    }

    // (b) LA TABLE RETIRÉE.
    {
        let c = db.lock();
        c.execute_batch("DELETE FROM silence WHERE reason='x'; ALTER TABLE silence RENAME TO silence_hors_d_atteinte;")
            .expect("fixture : la table des silences hors d'atteinte");
    }
    dispatch_notifications(&db);
    {
        let c = db.lock();
        assert_eq!(lde_notifiee(&c, "r.apres"), 0, "table retirée : toujours pas marquée");
        assert!(!lde_canal_a_recu(&c, "canal_a", "web-01"), "table retirée : toujours pas notifiée");
        assert_eq!(lde_ticks("dispatch_silences"), avant + 2, "le second tour aveugle est compté à son tour");
        c.execute_batch("ALTER TABLE silence_hors_d_atteinte RENAME TO silence;").expect("la table revient");
    }

    // LA CAUSE DISPARUE : le silence redevient lisible, et il s'applique — l'alerte est marquée SANS partir.
    dispatch_notifications(&db);
    let c = db.lock();
    assert_eq!(lde_notifiee(&c, "r.apres"), 1, "la lecture rétablie, l'alerte conservée est enfin TRAITÉE");
    assert!(!lde_canal_a_recu(&c, "canal_a", "web-01"), "et le silence que l'exploitant avait posé la MUSELLE, comme il le devait");
}

// -------------------------------------------------------------------------------------
// (8) LE CACHE DE PORTÉE DES ENGAGEMENTS — SE VIDER, C'EST ARMER L'AUTO-BAN
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT, ET C'EST LE SEUL SITE DU RANG OÙ « NE RIEN FAIRE » N'EST PAS LE GESTE NEUTRE. Ce cache
/// est une EXEMPTION : une défense volontairement baissée sur une cible de pentest AUTORISÉE. Le vider
/// n'est pas « perdre une information », c'est ARMER l'auto-ban contre cette cible, en pleine fenêtre,
/// sans qu'aucun corps ne soit servi à personne. Sur une lecture ratée, `engagement_scope_refresh` GARDE
/// donc sa valeur précédente et COMPTE le tour ; le témoin le prouve par le VERDICT DU GARDE
/// (`action_valid_ctx` refuse toujours de bannir l'adresse scopée), pas par l'état de la carte.
///
/// ET LA CONSERVATION EST BORNÉE PAR UNE PROPRIÉTÉ STRUCTURELLE, pas par la cadence du rafraîchissement :
/// `engagement_scope_match` revérifie `window_end` sur le CHEMIN CHAUD. Une entrée conservée cesse donc
/// d'exempter à la seconde où sa fenêtre s'achève, même si plus aucun rafraîchissement ne réussit — le
/// témoin le joue en avançant la fenêtre dans le passé, sans toucher au cache.
///
/// CE QU'IL TIENT AUSSI : la route `GET /api/engagements/active`, qui lit la MÊME fonction, rend un 503
/// NOMMÉ et jamais un tableau court. Son corps nominal est un TABLEAU NU, sans clé où poser un aveu.
///
/// CE QU'IL NE TIENT PAS : `collectors/engagement-adapter.sh` est LU (son `else` fail-closed gradué —
/// HOLD puis REVERT-ALL — est ce qui justifie le statut), il n'est PAS JOUÉ ici.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `rows.flatten()` dans `load_active_engagements` — la
/// lecture rend `Ok(<liste amputée>)` ou `Ok(vec![])`, le rafraîchissement PURGE l'entrée,
/// `action_valid_ctx` autorise le ban de la cible autorisée, et le compteur ne bouge pas.
#[tokio::test]
async fn p10_7f_listes_de_detection_le_cache_dengagements_garde_sa_valeur_sur_une_lecture_ratee() {
    let _g = ENGAGEMENT_TEST_LOCK.lock();
    eng_test_reset();
    set_engagement_mode(true);
    let (st, au, _p) = lde_etat("engagement");
    let agent = lde_au_agent("web-01");
    let chemin = req_db_path(&st, &au);
    // DEUX engagements, et c'est ce qui rend la voie « ligne illisible » MORTELLE : le blob est posé sur
    // le PREMIER, donc un aplatissement ne viderait pas le cache — il le REMPLACERAIT par le second, en
    // gardant l'apparence d'une portée compilée pendant que la cible du premier redevient bannissable.
    lsa_ecrire(&st, &format!(
        "INSERT INTO engagement(id,name,box,scope,window_start,window_end,authorizer,reason,status,adapter,created) \
         VALUES('eng-a','pentest','blackbox','[\"198.51.100.0/24\"]',0,{f},'a','r','active','host-adapter',1); \
         INSERT INTO engagement(id,name,box,scope,window_start,window_end,authorizer,reason,status,adapter,created) \
         VALUES('eng-b','autre','blackbox','[\"203.0.113.0/24\"]',0,{f},'a','r','active','host-adapter',1);",
        f = now() + 3600
    ));

    // CONTRÔLE POSITIF : la portée est compilée, et le garde REFUSE de bannir les deux cibles autorisées.
    with_write(&st, &au, |conn| engagement_scope_refresh(&chemin, conn));
    assert!(
        action_valid_ctx("ban_ip", "198.51.100.9", true, &chemin).is_err(),
        "contrôle positif : une cible de pentest autorisée n'est PAS bannissable"
    );
    assert!(
        action_valid_ctx("ban_ip", "203.0.113.9", true, &chemin).is_err(),
        "contrôle positif : la seconde portée aussi"
    );
    assert!(
        action_valid_ctx("ban_ip", "8.8.8.8", true, &chemin).is_ok(),
        "contrôle positif : hors portée, l'auto-ban reste armé — sans quoi « toujours refusé » ne prouverait rien"
    );
    let (statut, nominal) = lde_corps(engagements_active(State(st.clone()), Extension(agent.clone())).await).await;
    assert_eq!(statut, 200);
    assert_eq!(nominal.as_array().map(Vec::len), Some(2), "contrôle positif : les deux déclarations sont servies : {nominal}");

    // (a) UNE LIGNE ILLISIBLE : le `scope` du PREMIER engagement porte un BLOB.
    let avant = lde_ticks("engagement_scope_refresh");
    lsa_ecrire(&st, "UPDATE engagement SET scope=x'FF' WHERE id='eng-a';");
    with_write(&st, &au, |conn| engagement_scope_refresh(&chemin, conn));
    assert!(
        action_valid_ctx("ban_ip", "198.51.100.9", true, &chemin).is_err(),
        "lecture ratée : le cache GARDE sa valeur — la cible autorisée reste protégée. Un aplatissement aurait \
         gardé `eng-b` et PERDU `eng-a` : la portée aurait eu l'air compilée, et l'auto-ban aurait visé une cible autorisée"
    );
    assert_eq!(lde_ticks("engagement_scope_refresh"), avant + 1, "et le tour est COMPTÉ, sous son nom");
    let (statut, refus) = lde_corps(engagements_active(State(st.clone()), Extension(agent.clone())).await).await;
    assert_eq!(statut, 503, "un tableau nu n'a aucune clé où poser un aveu : la déclaration non lue est un refus NOMMÉ : {refus}");
    assert!(!refus.is_array(), "le corps du refus n'est PAS une liste : {refus}");
    assert!(refus["error"].as_str().unwrap_or("").contains("NON LUS"), "le refus NOMME sa cause : {refus}");

    // (b) LA TABLE RETIRÉE : même verdict, même conservation.
    lsa_retirer_la_table(&st, "engagement");
    with_write(&st, &au, |conn| engagement_scope_refresh(&chemin, conn));
    assert!(
        action_valid_ctx("ban_ip", "198.51.100.9", true, &chemin).is_err(),
        "table retirée : la cible autorisée reste protégée"
    );
    assert_eq!(lde_ticks("engagement_scope_refresh"), avant + 2, "le second tour aveugle est compté à son tour");
    let (statut, _) = lde_corps(engagements_active(State(st.clone()), Extension(agent.clone())).await).await;
    assert_eq!(statut, 503, "table retirée : refus nommé, jamais un tableau vide sous 200");

    // CE QUE LA CONSERVATION NE PROLONGE PAS : la fenêtre. Sans toucher au cache (la table est toujours
    // hors d'atteinte, donc plus aucun rafraîchissement n'aboutit), une fenêtre écoulée cesse d'exempter.
    {
        let mut m = engagement_scope_map().write();
        if let Some(liste) = m.get_mut(&chemin) {
            for e in liste.iter_mut() {
                e.window_end = now() - 1;
            }
        }
    }
    assert!(
        action_valid_ctx("ban_ip", "198.51.100.9", true, &chemin).is_ok(),
        "une entrée CONSERVÉE n'exempte plus au-delà de sa fenêtre : le self-expiry du chemin chaud la borne"
    );
    eng_test_reset();
}

// -------------------------------------------------------------------------------------
// (9) L'ÉVALUATION D'UNE LIGNE DE BASE — « NON ÉVALUÉ » N'EST NI ANOMALIE NI NORMALITÉ
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT, SUR L'APPELANT (`run_baselines`) ET NON SUR LA FONCTION PRIVÉE : quand l'historique
/// d'une entité n'a pas pu être lu, la ligne de base n'est PAS évaluée — aucune alerte n'est levée,
/// AUCUNE observation n'est persistée, et `last_bucket` N'AVANCE PAS, donc le tick suivant réévaluera le
/// MÊME bucket. C'est un troisième état, distinct de « rien d'anormal ».
///
/// POURQUOI CE SITE EST LE PLUS SOURNOIS DU RANG : un historique AMPUTÉ n'est pas une liste plus courte,
/// il DÉPLACE la moyenne et l'écart-type, donc le z-score. Le verdict est faussé dans les DEUX SENS —
/// anomalie MANQUÉE si les valeurs hautes sont tombées, anomalie INVENTÉE si ce sont les basses. Et un
/// historique ENTIÈREMENT illisible rendait `hist` vide, que `baseline_anomaly` traite comme « pas assez
/// d'échantillons » : silence total, indiscernable d'une base jeune. Aucune route ne mentait.
///
/// CE QU'IL NE TIENT PAS : il n'appelle pas `eval_baseline` directement (elle est privée à son module, et
/// la rendre visible pour un test serait élargir une surface pour l'instrument) ; la propriété est tenue
/// par l'EFFET observable du tick. Il ne juge pas non plus l'élagage des observations hors fenêtre.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.map(|x| x.flatten().collect()).unwrap_or_default()` sur
/// la lecture de l'historique — l'évaluation se poursuit sur un historique VIDE, `ok` passe à vrai,
/// l'observation du bucket est persistée et `last_bucket` avance : les trois asserts de la voie tombent.
#[test]
fn p10_7f_listes_de_detection_une_ligne_de_base_sur_un_historique_non_lu_nest_pas_evaluee() {
    /// Une base prête à évaluer : une ligne de base due, dix observations passées basses pour `h1`, et un
    /// PIC de soixante événements dans le bucket clos. Rend (répertoire possédé, chemin, bucket clos).
    fn lde_base_de_ligne_de_base(tag: &str) -> (crate::tmp_possede::TmpDb, String, i64) {
        let tmp = ff_tmp_path(&format!("lde-{tag}"));
        let p = tmp.as_str().to_owned();
        let bucket_s = 3600i64;
        let closed = now() / bucket_s - 1;
        let bstart = closed * bucket_s;
        {
            let w = open_db(&p).unwrap();
            w.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&w), "fixture : la chaîne de migrations doit aller au bout");
            w.execute(
                "INSERT INTO ueba_baseline(name,enabled,query,is_soql,entity_type,entity_field,value_field,bucket_s,min_samples,z_threshold,window_s,interval_s,severity,mitre,risk_score,managed) \
                 VALUES('volume auth par hôte',1,'search source=auth | stats count by host',1,'host','host','',3600,5,3.0,604800,3600,3,'T1110',0,2)",
                [],
            ).unwrap();
            let bid: i64 = w.query_row("SELECT id FROM ueba_baseline", [], |r| r.get(0)).unwrap();
            for (k, v) in [4.0, 5.0, 6.0, 5.0, 4.0, 6.0, 5.0, 4.0, 6.0, 5.0].iter().enumerate() {
                w.execute(
                    "INSERT INTO ueba_baseline_obs(baseline_id,entity_type,entity,bucket,value,env_id) VALUES(?1,'host','h1',?2,?3,'prod')",
                    params![bid, closed - 1 - (k as i64), v],
                ).unwrap();
            }
            for i in 0..60 {
                w.execute("INSERT INTO event(ts,source,host,fields,dedup) VALUES(?1,'auth','h1','{}',?2)", params![bstart + 10, format!("p{i}")]).unwrap();
            }
        }
        (tmp, p, closed)
    }

    /// (alertes levées, observations persistées sur le bucket clos, `last_bucket`) après UN tick.
    fn lde_apres_un_tick(p: &str, closed: i64) -> (i64, i64, Option<i64>) {
        let db = Arc::new(Mutex::new(open_db(p).unwrap()));
        run_baselines(&db, p);
        let c = db.lock();
        (
            c.query_row("SELECT COUNT(*) FROM alert", [], |r| r.get(0)).unwrap(),
            c.query_row("SELECT COUNT(*) FROM ueba_baseline_obs WHERE bucket=?1", params![closed], |r| r.get(0)).unwrap_or(0),
            c.query_row("SELECT last_bucket FROM ueba_baseline", [], |r| r.get::<_, Option<i64>>(0)).unwrap(),
        )
    }

    // CONTRÔLE POSITIF : l'historique lu, le pic est une anomalie, l'observation est persistée, le bucket avance.
    let (_t0, p0, closed) = lde_base_de_ligne_de_base("bl-ok");
    let (alertes, obs, dernier) = lde_apres_un_tick(&p0, closed);
    assert_eq!(alertes, 1, "contrôle positif : un pic massif contre une base basse EST une anomalie");
    assert_eq!(obs, 1, "contrôle positif : l'observation du bucket clos est persistée");
    assert_eq!(dernier, Some(closed), "contrôle positif : le bucket évalué est marqué traité");

    // (a) UNE LIGNE ILLISIBLE dans l'historique : `value` (REAL) porte un BLOB — la requête reste saine.
    let (_t1, p1, _) = lde_base_de_ligne_de_base("bl-blob");
    {
        let w = open_db(&p1).unwrap();
        w.execute("UPDATE ueba_baseline_obs SET value=x'FF' WHERE bucket=(SELECT MIN(bucket) FROM ueba_baseline_obs)", []).unwrap();
    }
    let (alertes, obs, dernier) = lde_apres_un_tick(&p1, closed);
    assert_eq!(alertes, 0, "historique NON LU : aucune anomalie n'est levée — un z-score calculé sur une référence amputée est un verdict inventé");
    assert_eq!(obs, 0, "historique NON LU : AUCUNE observation n'est persistée (une base fausse se propagerait aux ticks suivants)");
    assert_eq!(dernier, None, "historique NON LU : `last_bucket` N'AVANCE PAS — le tick suivant réévaluera le MÊME bucket");

    // (b) LA TABLE RETIRÉE : la préparation de l'historique échoue. Même verdict « non évalué ».
    let (_t2, p2, _) = lde_base_de_ligne_de_base("bl-table");
    {
        let w = open_db(&p2).unwrap();
        w.execute_batch("ALTER TABLE ueba_baseline_obs RENAME TO ueba_baseline_obs_hors_d_atteinte;").unwrap();
    }
    let (alertes, _, dernier) = lde_apres_un_tick(&p2, closed);
    assert_eq!(alertes, 0, "table d'historique retirée : ni anomalie, ni normalité — non évalué");
    assert_eq!(dernier, None, "table d'historique retirée : `last_bucket` n'avance pas");
}

// -------------------------------------------------------------------------------------
// (10) L'INVENTAIRE DES SOURCES — « INDÉTERMINÉE », JAMAIS « INATTENDUE »
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : quand la déclaration par connecteur n'a pas pu être lue, la source n'est PAS classée
/// « inattendue ». `unexpected` et `expected` passent tous deux à `null` — pas l'un à faux et l'autre à
/// vrai : un `false` dirait « établi : elle n'est pas inattendue », ce qui est également faux — et le
/// corps porte `indeterminee: true` avec une raison qui NOMME la lecture manquante.
///
/// POURQUOI C'EST UN DÉFAUT DE DÉTECTION : `unexpected` EST le signal de cette vue. Un connecteur avalé
/// transforme une source parfaitement attendue en signal, l'opérateur enquête sur un flux qu'il a
/// lui-même configuré, et il apprend que les signaux de cette vue ne valent rien. Le coût n'est pas la
/// ligne perdue, c'est le crédit du signal.
///
/// CE QU'IL TIENT AUSSI, ET C'EST LA MOITIÉ QUI SÉPARE CE CORRECTIF D'UN REFUS EN BLOC : les sources que
/// les trois PREMIÈRES dérivations couvrent (fichier livré, sonde, agrégation) restent SERVIES AVEC LEUR
/// VERDICT même quand la table des connecteurs est illisible — ces dérivations sont pures et répondent
/// AVANT la lecture. Rendre l'inventaire entier « non lu » aurait perdu des verdicts réellement établis.
///
/// CE QU'IL NE TIENT PAS : il ne juge pas ce que la console peint d'`indeterminee` (`web/sources.js` ne
/// lit pas encore la clé) ; il ne juge pas non plus le refus de `source_settings_put` sur la même
/// lecture, tenu par sa propre branche.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `rows.flatten()` (et `Err(_) => Vec::new()`) dans
/// `sources_declarees_par_connecteurs` — la source déclarée par le connecteur redevient `unexpected:
/// true` et `indeterminee` disparaît.
#[tokio::test]
async fn p10_7f_listes_de_detection_une_source_dont_la_declaration_nest_pas_lue_est_indeterminee() {
    let (st, au, _p) = lde_etat("sources");
    let b = now();
    lsa_ecrire(&st, &format!(
        "INSERT INTO event_rollup(bucket,source,severity,action,n) VALUES({b},'okta',0,'',5);\
         INSERT INTO event_rollup(bucket,source,severity,action,n) VALUES({b},'totally-new-thing',0,'',5);\
         INSERT INTO event_rollup(bucket,source,severity,action,n) VALUES({b},'portprobe',0,'',5);\
         INSERT INTO connector(id,type,name,enabled,config_json) VALUES(7,'http_pull','x',1,'{{\"source\":\"okta\"}}');"
    ));
    let lire = |v: &Value, n: &str| -> Value {
        v["sources"].as_array().expect("tableau de sources").iter().find(|s| s["source"] == n).cloned()
            .unwrap_or_else(|| panic!("source {n} absente de {v}"))
    };

    // CONTRÔLE POSITIF : le connecteur déclare `okta` ; `totally-new-thing` reste un SIGNAL ; aucune indétermination.
    let nominal = sources_inventory(State(st.clone()), Extension(au.clone())).await.0;
    assert_eq!(nominal["ok"], json!(true), "instrument : l'inventaire est lu : {nominal}");
    let okta = lire(&nominal, "okta");
    assert_eq!(okta["expected"], json!(true), "contrôle positif : le connecteur la déclare : {okta}");
    assert_eq!(okta["declaree_par"], json!("un connecteur"), "contrôle positif : et le corps dit QUI : {okta}");
    assert_eq!(okta["indeterminee"], json!(false), "contrôle positif : rien d'indéterminé ici : {okta}");
    let inconnue = lire(&nominal, "totally-new-thing");
    assert_eq!(inconnue["unexpected"], json!(true), "contrôle positif : une source que RIEN ne déclare reste un signal : {inconnue}");
    // CONTRÔLE POSITIF DU SECOND APPELANT : la lecture aboutit, donc le réglage est ÉCRIT.
    let ecrit = source_settings_put(
        State(st.clone()),
        Extension(au.clone()),
        Json(json!({ "source": "okta", "action": "set_label", "value": "Okta" })),
    )
    .await;
    assert_eq!(ecrit.status(), StatusCode::OK, "contrôle positif : le verdict lu, le réglage est écrit");

    // (a) UNE LIGNE ILLISIBLE : `connector.type` porte un BLOB. La requête reste saine.
    lsa_ecrire(&st, "UPDATE connector SET type=x'FF' WHERE id=7;");
    let avoue = sources_inventory(State(st.clone()), Extension(au.clone())).await.0;
    let okta = lire(&avoue, "okta");
    assert_eq!(okta["indeterminee"], json!(true), "déclaration NON LUE : la source est INDÉTERMINÉE : {okta}");
    assert_eq!(okta["unexpected"], Value::Null, "et surtout PAS « inattendue » — c'est l'accusation que le défaut fabriquait : {okta}");
    assert_eq!(okta["expected"], Value::Null, "ni « attendue » : ni l'un ni l'autre n'a été établi : {okta}");
    assert!(
        okta["raison_attendue"].as_str().unwrap_or("").contains("NON LUE"),
        "la raison NOMME la lecture manquante : {okta}"
    );
    let livree = lire(&avoue, "portprobe");
    assert_eq!(livree["expected"], json!(true), "une source LIVRÉE par ce dépôt garde son verdict : les trois premières dérivations sont pures et répondent avant la lecture : {livree}");
    assert_eq!(livree["indeterminee"], json!(false), "et elle n'est pas indéterminée : {livree}");

    // (b) LA TABLE RETIRÉE : la préparation échoue. Même verdict.
    lsa_retirer_la_table(&st, "connector");
    let sans_table = sources_inventory(State(st.clone()), Extension(au.clone())).await.0;
    let okta = lire(&sans_table, "okta");
    assert_eq!(okta["indeterminee"], json!(true), "table retirée : indéterminée : {okta}");
    assert_eq!(okta["unexpected"], Value::Null, "table retirée : jamais « inattendue » : {okta}");
    assert_eq!(lire(&sans_table, "portprobe")["expected"], json!(true), "table retirée : la source livrée garde son verdict");

    // LE SECOND APPELANT DE LA MÊME LECTURE, ET IL N'AVOUE PAS — IL REFUSE D'ÉCRIRE.
    // `source_settings_put` fait entrer ce verdict DANS LA BASE (l'`expected` de la ligne qui naît) et
    // DANS L'AUDIT (la sévérité 3 de `set_expected`, bruyante quand un humain reconnaît une source que
    // rien ne déclare). Aucun des deux booléens n'y est honnête : `true` ferait naître la ligne
    // « attendue » sans que personne ne l'ait dit ET ferait retomber l'audit bruyant à 2 ; `false` la
    // ferait naître `expected=0`, que `verdict_de_source` lit `Retiree` — « quelqu'un a dit non », alors
    // que personne n'a rien dit. Refuser est réversible (l'exploitant réessaie) ; écrire ne l'est pas.
    let refus = source_settings_put(
        State(st.clone()),
        Extension(au.clone()),
        Json(json!({ "source": "totally-new-thing", "action": "set_label", "value": "mon libellé" })),
    )
    .await;
    assert_eq!(refus.status(), StatusCode::SERVICE_UNAVAILABLE, "verdict de construction non lu : le réglage n'est PAS écrit");
    let (_, corps) = lde_corps(refus).await;
    assert!(corps.is_null(), "instrument : le corps du refus est du texte, pas un JSON (il n'est pas relu comme une donnée)");
    let ecrites: i64 = with_write(&st, &au, |conn| {
        conn.query_row("SELECT COUNT(*) FROM source_settings", [], |r| r.get(0)).unwrap()
    });
    assert_eq!(
        ecrites, 1,
        "et RIEN N'A ÉTÉ AJOUTÉ : la seule ligne est celle du contrôle positif. Une ligne née d'un verdict \
         non lu porterait un « attendu » que personne n'a décidé"
    );
}
