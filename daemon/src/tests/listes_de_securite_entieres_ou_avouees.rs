// =====================================================================================
// `P10.7-f` (rang 1) — LES HUIT LISTES DE SÉCURITÉ ET D'ADMINISTRATION SONT ENTIÈRES OU AVOUÉES.
//
// LE DÉFAUT MESURÉ (garde de famille `check_a_truncated_list_is_never_served_as_a_complete_one.py`,
// relevé du 2026-09-16) : huit sites de `daemon/src/handlers/` lisaient leur liste par un itérateur de
// lignes APLATI (`query_map(..).flatten()`, parfois précédé de deux `unwrap()`). Un itérateur de lignes
// rusqlite rend des `Result` UNE LIGNE À LA FOIS : le mappeur peut échouer sur une seule ligne sans que
// la requête ait échoué — cache de schéma périmé qui rend « no such table » au PREMIER pas (famille
// mesurée dans `flatten-avale-no-such-table-au-premier-pas`), colonne ajoutée par une migration que la
// connexion qui sert ne voit pas encore, valeur corrompue. L'aplatissement jetait CETTE ligne-là et
// rendait la suite, sous un corps rigoureusement identique à celui d'une liste complète.
//
// POURQUOI LE RANG UN EST LE RANG UN : ici « la liste est courte » se lit « il n'y a rien de plus », et
// cette lecture-là est une DÉCISION DE SÉCURITÉ. Un jeton absent de l'inventaire est un accès que
// personne ne révoque ; un compte absent est un accès que l'audit ne voit pas ; un rôle absent est une
// permission accordée devenue invisible ; un fournisseur SSO absent est une voie d'authentification
// ACTIVE qu'on croit fermée ; un ban absent fait décider l'opérateur sur une adresse qu'il croit libre ;
// une règle de masquage absente fait lire « ce champ n'est pas masqué » ; une action approuvée absente
// du TSV n'est pas remise à l'agent ; et une action absente de la liste de travail du responder local
// n'est jamais exécutée, sans que rien ne la compte.
//
// CE QUE CES TÉMOINS JOUENT, ET POURQUOI DEUX VOIES. La voie de la TABLE RETIRÉE (renommée sous les
// pieds du gestionnaire) fait échouer la PRÉPARATION : elle prouve que la route n'invente plus une
// liste vide ni ne panique. La voie de la LIGNE ILLISIBLE (un `BLOB` posé dans une colonne `TEXT` —
// SQLite conserve un blob tel quel quelle que soit l'affinité, et `get::<String>` le refuse) fait
// échouer le MAPPEUR sur UNE ligne, la requête restant saine : c'est LA voie que l'aplatissement
// avalait, et c'est elle qui tue la mutation. Chaque témoin porte son CONTRÔLE POSITIF (la liste
// complète, comptée) dans le même corps de test : sans lui, un aveu INCONDITIONNEL passerait pour un
// aveu.
//
// LA FORME DE L'AVEU EST CELLE DU DÉPÔT, PAS UNE FORME NEUVE. Cinq listes JSON passent par le fabricant
// unique `liste_bornee::corps_de_liste_illisible` (`P10.7-z`) : la clé de liste EXISTE, VIDE, et `error`
// porte `CAUSE_LISTE_ILLISIBLE` — un client qui lit `j.<cle>.length` continue de fonctionner, celui qui
// teste `error` apprend que ce vide n'est pas un fait. Les valeurs DÉRIVÉES de la liste non lue passent
// à `null` et jamais à zéro (`netban.active`, `field-filters.matrix`), exactement comme
// `TotalBorne::Illisible` rend `(null, null)`. La liste SSO, dont le corps est un TABLEAU NU sans
// aucune clé où poser un aveu, rend un 5xx NOMMÉ (la forme fail-closed de `client_case_get` et de
// `ledger_get`). La remise TSV aux agents rend un 503 nommé. Le responder local, qui ne sert aucun
// corps, SAUTE son tour et le compte (`metrics::compter_un_tick_aveugle`).
//
// CE QUE CE LOT NE TIENT PAS : le tableau VIDE que `corps_de_liste_illisible` conserve à côté d'`error`
// reste un corps qu'une console qui ne lit pas `error` peint « aucun jeton ». Le démon avoue ; que la
// console le PEIGNE se juge ailleurs (`check_a_refusal_is_not_rendered_as_an_absence.py`), et
// `web/admin_users.js:129` ne lit pas encore `error`. Aucun de ces témoins ne joue `respond_run`
// lui-même : il ouvre sa propre connexion depuis la configuration et n'a pas de couture de test — la
// même réserve que `P4.7-f` a déjà consignée.
// =====================================================================================

/// Statut + corps JSON d'une réponse.
async fn lsa_corps(r: Response) -> (u16, Value) {
    let statut = r.status().as_u16();
    let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
    (statut, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

/// Statut + corps TEXTE (la remise aux agents est un TSV, pas du JSON).
async fn lsa_texte(r: Response) -> (u16, String) {
    let statut = r.status().as_u16();
    let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
    (statut, String::from_utf8_lossy(&b).into_owned())
}

/// Écrit dans la base du tenant par la MÊME connexion que les gestionnaires (le writer de `AppState`).
fn lsa_ecrire(st: &AppState, sql: &str) {
    let conn = st.db.lock();
    conn.execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
}

/// Retire une table sous les pieds du gestionnaire sans toucher au code servi : renommée, elle n'est
/// plus sous le nom que le SQL servi attend (un renommage ne viole aucune clé étrangère).
fn lsa_retirer_la_table(st: &AppState, table: &str) {
    lsa_ecrire(st, &format!("ALTER TABLE {table} RENAME TO {table}_hors_d_atteinte;"));
}

/// LE JUGEMENT D'UN CORPS DE LISTE NON LUE, écrit une fois. La clé de liste existe et est VIDE (la forme
/// est conservée : `P10.7-z`), et `error` porte la cause du fabricant unique. Le point dur est le
/// PREMIER assert : une liste AMPUTÉE (ce que rendait `.flatten()`) n'est pas un tableau vide.
fn lsa_juger_l_aveu(corps: &Value, cle: &str) {
    assert_eq!(
        corps[cle],
        json!([]),
        "lecture ratée : `{cle}` ne doit porter AUCUNE ligne — une liste amputée servie sans un mot est le défaut : {corps}"
    );
    assert_eq!(
        corps["error"],
        json!(crate::handlers::liste_bornee::CAUSE_LISTE_ILLISIBLE),
        "lecture ratée : le corps doit DIRE que ce vide n'a pas été établi : {corps}"
    );
}

/// L'état file-backed du rang 1 : schéma + migrations complets, un admin.
fn lsa_etat(tag: &str) -> (AppState, AuthUser, crate::tmp_possede::TmpDb) {
    let (st, p) = sp_state(&format!("lsa-{tag}"));
    (st, sp_au("adm", "admin"), p)
}

/// Un jeton d'agent lié à un hôte (la seule identité que `actions_pending` accepte).
fn lsa_au_agent(hote: &str) -> AuthUser {
    AuthUser {
        name: hote.into(), role: "agent".into(), tenant: "default".into(), is_superadmin: false,
        method: "token".into(), csrf: String::new(), env: None,
    }
}

// -------------------------------------------------------------------------------------
// (1) LES JETONS D'ACCÈS
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `tokens_list` sert l'inventaire ENTIER (trois jetons, comptés) ; une ligne dont le
/// mappeur échoue rend la liste NON ÉTABLIE (`tokens: []` + `error`), jamais un inventaire amputé de
/// deux jetons servi comme complet ; et une table retirée ne fait plus PANIQUER la route (elle portait
/// deux `unwrap()`), elle avoue.
///
/// CE QU'IL NE TIENT PAS : il ne dit rien du mode multi-tenant (la route y refuse en 501 avant toute
/// lecture), ni de ce que la console peint de cet `error` (`web/admin_users.js:129` ne le lit pas).
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `rows.flatten().collect()` à la place du solde en bloc —
/// le corps redevient `{"tokens": [<deux jetons>]}` sans `error`, et les deux premiers asserts tombent.
#[tokio::test]
async fn p10_7f_listes_de_securite_les_jetons_sont_entiers_ou_avoues() {
    let (st, au, _p) = lsa_etat("tokens");
    lsa_ecrire(&st, "INSERT INTO token(name,token_hash,created,kind) VALUES('agent-a','h1',10,'agent');\
                     INSERT INTO token(name,token_hash,created,kind) VALUES('hec-b','h2',20,'hec');\
                     INSERT INTO token(name,token_hash,created,kind) VALUES('agent-c','h3',30,'agent');");
    let (statut, nominal) = lsa_corps(tokens_list(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200);
    assert_eq!(nominal["tokens"].as_array().map(Vec::len), Some(3), "contrôle positif : les trois jetons sont servis : {nominal}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET — un aveu inconditionnel n'est pas un aveu : {nominal}");

    // UNE LIGNE ILLISIBLE : `name` porte un BLOB, que `get::<String>` refuse. La requête, elle, est saine.
    lsa_ecrire(&st, "INSERT INTO token(name,token_hash,created,kind) VALUES(x'FF','h4',40,'agent');");
    let (statut, avoue) = lsa_corps(tokens_list(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200, "la forme du dépôt pour une liste JSON est `error` DANS le corps, pas un refus HTTP");
    lsa_juger_l_aveu(&avoue, "tokens");

    // LA TABLE RETIRÉE : la préparation échoue. Avant, deux `unwrap()` faisaient PANIQUER la route.
    lsa_retirer_la_table(&st, "token");
    let (_, sans_table) = lsa_corps(tokens_list(State(st.clone()), Extension(au.clone())).await).await;
    lsa_juger_l_aveu(&sans_table, "tokens");
}

// -------------------------------------------------------------------------------------
// (2) LES COMPTES
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `users_list` sert les trois comptes que la fixture crée ; un compte dont la ligne ne
/// se décode pas rend `users` NON ÉTABLIE avec sa cause, au lieu de retirer silencieusement une ligne de
/// « qui a accès » — la liste que l'audit lit ; et une table `user` retirée ne fait plus paniquer.
///
/// CE QU'IL NE TIENT PAS : il ne juge PAS l'inventaire `acces` servi à côté (autre lecture, autre
/// famille : il reste rendu tel quel, et c'est voulu — les deux listes ne mentent pas ensemble).
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `rows.flatten().collect()` — `users` reporte trois
/// comptes sur quatre sans un mot, et l'assert de l'aveu tombe.
#[tokio::test]
async fn p10_7f_listes_de_securite_les_comptes_sont_entiers_ou_avoues() {
    let (st, au, _p) = lsa_etat("users");
    let nominal = users_list(State(st.clone()), Extension(au.clone())).await.0;
    assert_eq!(nominal["users"].as_array().map(Vec::len), Some(3), "contrôle positif : alice, bob, adm : {nominal}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET : {nominal}");

    lsa_ecrire(&st, "INSERT INTO user(name,hash,role,created) VALUES(x'FF','h','viewer',1);");
    let avoue = users_list(State(st.clone()), Extension(au.clone())).await.0;
    lsa_juger_l_aveu(&avoue, "users");

    lsa_retirer_la_table(&st, "user");
    let sans_table = users_list(State(st.clone()), Extension(au.clone())).await.0;
    lsa_juger_l_aveu(&sans_table, "users");
}

// -------------------------------------------------------------------------------------
// (3) LE CATALOGUE DES RÔLES COMPOSABLES
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `roles_list` sert le catalogue ENTIER (deux rôles, comptés) avec `ok: true` ; un rôle
/// dont la ligne ne se décode pas rend `roles` NON ÉTABLIE, `error` posé ET `ok` retombé à `false` — le
/// défaut le plus grave de ce site était précisément un `ok: true` affirmant qu'un catalogue non lu
/// avait été lu.
///
/// CE QU'IL NE TIENT PAS : il ne joue pas la garde d'accès (mono-tenant -> 404, non super-admin -> 403),
/// tenue ailleurs ; et il ne dit rien du cache de rôles du RBAC, qui a sa propre voie de chargement.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.map(|it| it.flatten().collect()).unwrap_or_default()` —
/// le corps redevient `{"ok": true, "roles": [<un rôle>]}`, et les asserts de l'aveu et de `ok` tombent.
#[tokio::test]
async fn p10_7f_listes_de_securite_le_catalogue_des_roles_est_entier_ou_avoue() {
    let (cp, _tmp) = mk_test_control();
    let st = tenant_test_state("plume-admin", "plume-editor", "admins", Some(cp));
    let au = au_super("sa-lsa");
    {
        let c = st.tenants.control.as_ref().expect("mode 1").conn.lock();
        c.execute_batch(
            "INSERT INTO role_def(name,base_role,deny_perms,description,created) VALUES('auditeur','viewer','','lecture seule',1);\
             INSERT INTO role_def(name,base_role,deny_perms,description,created) VALUES('power','admin','raw_sql','admin sans SQL brut',2);",
        )
        .unwrap();
    }
    let (statut, nominal) = lsa_corps(roles_list(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200);
    assert_eq!(nominal["roles"].as_array().map(Vec::len), Some(2), "contrôle positif : deux rôles catalogués : {nominal}");
    assert_eq!(nominal["ok"], json!(true), "chemin nominal : le catalogue a bien été lu : {nominal}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET : {nominal}");

    {
        let c = st.tenants.control.as_ref().expect("mode 1").conn.lock();
        c.execute("INSERT INTO role_def(name,base_role,deny_perms,description,created) VALUES(x'FF','viewer','','',3)", []).unwrap();
    }
    let (_, avoue) = lsa_corps(roles_list(State(st.clone()), Extension(au.clone())).await).await;
    lsa_juger_l_aveu(&avoue, "roles");
    assert_eq!(avoue["ok"], json!(false), "un catalogue NON LU ne se sert pas avec `ok: true` : {avoue}");
}

// -------------------------------------------------------------------------------------
// (4) LES FOURNISSEURS D'IDENTITÉ (SSO)
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `idp_providers_list` sert les deux fournisseurs configurés ; une ligne illisible ou
/// une table retirée rendent un 5xx qui NOMME sa cause et dont le corps n'est PAS un tableau — donc
/// aucune façon de le lire « aucun fournisseur d'identité n'est configuré ».
///
/// CE QU'IL NE TIENT PAS : c'est la SEULE des six listes JSON de ce lot qui refuse en HTTP, parce que son
/// corps nominal est un tableau nu sans clé où poser un aveu ; le témoin ne juge pas ce que le module
/// `web/idp.js` affiche de ce refus (il le peint déjà, `api()` jetant sur non-2xx — mais cela se juge
/// dans la garde des refus non rendus comme des absences, pas ici). Il ne joue pas non plus la
/// non-fuite du secret, tenue par les témoins IdP existants.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.map(|rows| rows.flatten().collect())
/// .unwrap_or_default()` — la route rend 200 et un tableau d'UN fournisseur, et l'assert du statut tombe.
#[tokio::test]
async fn p10_7f_listes_de_securite_les_fournisseurs_didentite_sont_entiers_ou_avoues() {
    let (st, au, _p) = lsa_etat("idp");
    lsa_ecrire(&st, "INSERT INTO idp_provider(name,kind,enabled,config_json,secret,created,updated) VALUES('okta','oidc',1,'{}','s',1,1);\
                     INSERT INTO idp_provider(name,kind,enabled,config_json,secret,created,updated) VALUES('ldap-corp','ldap',0,'{}','',2,2);");
    let (statut, nominal) = lsa_corps(idp_providers_list(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200);
    assert_eq!(nominal.as_array().map(Vec::len), Some(2), "contrôle positif : les deux fournisseurs sont servis : {nominal}");

    lsa_ecrire(&st, "INSERT INTO idp_provider(name,kind,enabled,config_json,secret,created,updated) VALUES(x'FF','oidc',1,'{}','',3,3);");
    let (statut, avoue) = lsa_corps(idp_providers_list(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 500, "un tableau nu n'a aucune clé où poser un aveu : la liste SSO non lue est un 5xx NOMMÉ, jamais un tableau court : {avoue}");
    assert!(!avoue.is_array(), "le corps du refus n'est pas une liste : {avoue}");
    assert!(
        avoue["error"].as_str().unwrap_or("").contains("NON LUE"),
        "le refus NOMME sa cause : {avoue}"
    );

    lsa_retirer_la_table(&st, "idp_provider");
    let (statut, sans_table) = lsa_corps(idp_providers_list(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 500, "table retirée : refus nommé, pas un tableau vide : {sans_table}");
}

// -------------------------------------------------------------------------------------
// (5) LES BANS HTTP — ET LE COMPTE QUI EN DÉRIVE
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `netban_list` sert les deux bans et le compte `active` qui en dérive ; une ligne
/// illisible ou une table retirée rendent `bans` NON ÉTABLIE avec sa cause, ET `active` à `null` — le
/// point central de ce témoin, parce qu'un compte DÉRIVÉ d'une liste amputée est un nombre faux servi
/// comme un fait, et qu'un `0` se lirait « aucune adresse n'est bannie, c'est établi ».
///
/// CE QU'IL NE TIENT PAS : il ne juge ni `charges`/`cap`/`tronque` (la borne du store LIVE en mémoire,
/// une autre propriété, conservée telle quelle dans l'aveu), ni le fait qu'un ban soit effectivement
/// appliqué au gate HTTP.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.map(|m| m.flatten().collect()).unwrap_or_default()` —
/// le corps redevient `{"bans": [<un ban>], "active": 1}`, et les asserts de l'aveu et de `active`
/// tombent tous les deux.
#[tokio::test]
async fn p10_7f_listes_de_securite_les_bans_sont_entiers_ou_avoues() {
    let (st, au, _p) = lsa_etat("netban");
    lsa_ecrire(&st, "INSERT INTO net_ban(ip,reason,created_ts,expires_ts,created_by,env_id) VALUES('203.0.113.9','scan',10,NULL,'adm','prod');\
                     INSERT INTO net_ban(ip,reason,created_ts,expires_ts,created_by,env_id) VALUES('198.51.100.4','brute',20,NULL,'adm','prod');");
    let nominal = netban_list(State(st.clone()), Extension(au.clone())).await.0;
    assert_eq!(nominal["bans"].as_array().map(Vec::len), Some(2), "contrôle positif : les deux bans sont servis : {nominal}");
    assert_eq!(nominal["active"], json!(2), "contrôle positif : deux bans permanents sont actifs : {nominal}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET : {nominal}");

    lsa_ecrire(&st, "INSERT INTO net_ban(ip,reason,created_ts,expires_ts,created_by,env_id) VALUES(x'FF','blob',30,NULL,'adm','prod');");
    let avoue = netban_list(State(st.clone()), Extension(au.clone())).await.0;
    lsa_juger_l_aveu(&avoue, "bans");
    assert!(
        avoue.as_object().map(|o| o.contains_key("active")).unwrap_or(false) && avoue["active"].is_null(),
        "un compte DÉRIVÉ d'une liste non lue est `null`, jamais `0` : {avoue}"
    );

    lsa_retirer_la_table(&st, "net_ban");
    let sans_table = netban_list(State(st.clone()), Extension(au.clone())).await.0;
    lsa_juger_l_aveu(&sans_table, "bans");
    assert!(sans_table["active"].is_null(), "table retirée : le compte n'est pas `0` : {sans_table}");
}

// -------------------------------------------------------------------------------------
// (6) LES RÈGLES DE MASQUAGE DE CHAMPS — ET LA MATRICE QUI EN DÉRIVE
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `field_filters_list` sert les deux règles et la matrice champ×rôle qui en est
/// RECALCULÉE ; une ligne illisible ou une table retirée rendent `rules` NON ÉTABLIE avec sa cause, et
/// la matrice `null` — un objet VIDE se lirait « aucun champ n'est masqué, et c'est établi », ce qui est
/// précisément le contraire de ce que la politique PII doit pouvoir affirmer.
///
/// CE QU'IL NE TIENT PAS : il ne juge pas le MASQUAGE lui-même (le registre compilé, ses seuils de rôle
/// et son sel de hachage vivent ailleurs et ont leurs témoins) — seulement l'INVENTAIRE servi.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.map(|rows| rows.flatten().collect())
/// .unwrap_or_default()` — le corps redevient `{"rules": [<une règle>], "matrix": {...}}`, et les
/// asserts de l'aveu et de la matrice `null` tombent.
#[tokio::test]
async fn p10_7f_listes_de_securite_les_masques_de_champs_sont_entiers_ou_avoues() {
    let (st, au, _p) = lsa_etat("ff");
    lsa_ecrire(&st, "INSERT INTO field_filter(name,field,action,role,tenant,env,enabled,ord,created,updated) VALUES('m1','src_user','hash','','','',1,0,1,1);\
                     INSERT INTO field_filter(name,field,action,role,tenant,env,enabled,ord,created,updated) VALUES('m2','src_ip','mask','','','',1,1,1,1);");
    let (statut, nominal) = lsa_corps(field_filters_list(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200);
    assert_eq!(nominal["rules"].as_array().map(Vec::len), Some(2), "contrôle positif : les deux règles sont servies : {nominal}");
    assert!(nominal["matrix"].is_object(), "contrôle positif : la matrice est calculée : {nominal}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET : {nominal}");

    lsa_ecrire(&st, "INSERT INTO field_filter(name,field,action,role,tenant,env,enabled,ord,created,updated) VALUES(x'FF','message','mask','','','',1,2,1,1);");
    let (_, avoue) = lsa_corps(field_filters_list(State(st.clone()), Extension(au.clone())).await).await;
    lsa_juger_l_aveu(&avoue, "rules");
    assert!(avoue["matrix"].is_null(), "la matrice DÉRIVE des règles non lues : `null`, jamais un objet vide : {avoue}");

    lsa_retirer_la_table(&st, "field_filter");
    let (_, sans_table) = lsa_corps(field_filters_list(State(st.clone()), Extension(au.clone())).await).await;
    lsa_juger_l_aveu(&sans_table, "rules");
}

// -------------------------------------------------------------------------------------
// (7) LA REMISE D'ACTIONS À L'AGENT DE FLOTTE (TSV)
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `actions_pending` remet les DEUX actions approuvées de l'hôte en TSV et les marque
/// réclamées ; une ligne illisible ou une table retirée rendent un 503 qui NOMME sa cause, et — c'est le
/// point dur — AUCUNE action n'est alors réclamée (`claimed_ts` reste NULL partout), donc rien n'est
/// remis à moitié et le tour suivant relit tout.
///
/// POURQUOI UN STATUT ET NON UNE LIGNE D'AVEU, MESURÉ SUR LE CONSOMMATEUR : le seul lecteur de cette
/// route est `collectors/respond.sh:277-289`, qui appelle `curl -sS` SANS `--fail` puis ÉCARTE toute
/// ligne dont le premier champ n'est pas numérique (`case "$id" in *[!0-9]*) continue`). Une ligne
/// d'aveu y serait donc jetée en silence — un aveu que personne ne lit. Le corps du 503 subit le même
/// filtre sans dégât (aucune action fantôme n'en sort), et le statut, lui, est visible.
///
/// CE QU'IL NE TIENT PAS : il ne joue pas `respond.sh` (le témoin assert la propriété du CÔTÉ DÉMON :
/// statut, cause, et non-réclamation) ; il ne joue pas non plus l'anti-IDOR inter-agents, tenu ailleurs.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.map(|m| m.flatten().collect()).unwrap_or_default()` —
/// la route rend 200 avec DEUX lignes TSV sur trois actions et les réclame, et les trois asserts de la
/// branche « ligne illisible » (statut, cause, `claimed_ts`) tombent.
#[tokio::test]
async fn p10_7f_listes_de_securite_la_remise_dactions_a_lagent_est_entiere_ou_refusee() {
    let agent = lsa_au_agent("hote-a");

    // (b) CONTRÔLE POSITIF : deux actions approuvées sortent, et elles sont réclamées.
    let (st, _au, _p) = lsa_etat("pending-ok");
    lsa_ecrire(&st, "INSERT INTO action(ts,kind,target,status,dry_run,host) VALUES(1,'ban_ip','203.0.113.1','approved',1,'hote-a');\
                     INSERT INTO action(ts,kind,target,status,dry_run,host) VALUES(2,'unban_ip','203.0.113.2','approved',0,'hote-a');");
    let (statut, tsv) = lsa_texte(actions_pending(State(st.clone()), Extension(agent.clone())).await).await;
    assert_eq!(statut, 200);
    assert_eq!(tsv.lines().count(), 2, "contrôle positif : les deux actions sont remises : {tsv:?}");
    let reclamees: i64 = st.db.lock().query_row("SELECT COUNT(*) FROM action WHERE claimed_ts IS NOT NULL", [], |r| r.get(0)).unwrap();
    assert_eq!(reclamees, 2, "contrôle positif : la remise réclame ce qu'elle remet");

    // (a) UNE LIGNE ILLISIBLE parmi trois : la remise est REFUSÉE EN BLOC, et rien n'est réclamé.
    let (st2, _au2, _p2) = lsa_etat("pending-blob");
    lsa_ecrire(&st2, "INSERT INTO action(ts,kind,target,status,dry_run,host) VALUES(1,'ban_ip','203.0.113.1','approved',1,'hote-a');\
                      INSERT INTO action(ts,kind,target,status,dry_run,host) VALUES(2,'ban_ip','203.0.113.2','approved',1,'hote-a');\
                      INSERT INTO action(ts,kind,target,status,dry_run,host) VALUES(3,'ban_ip',x'FF','approved',1,'hote-a');");
    let (statut, corps) = lsa_texte(actions_pending(State(st2.clone()), Extension(agent.clone())).await).await;
    assert_eq!(statut, 503, "une file d'actions NON LUE n'est pas une file vide : {corps:?}");
    assert!(corps.contains("NON LUE"), "le refus NOMME sa cause : {corps:?}");
    let reclamees: i64 = st2.db.lock().query_row("SELECT COUNT(*) FROM action WHERE claimed_ts IS NOT NULL", [], |r| r.get(0)).unwrap();
    assert_eq!(reclamees, 0, "lecture ratée : AUCUNE action n'est réclamée — une remise partielle en sortirait deux");

    // LA TABLE RETIRÉE : avant, un TSV VIDE en 200 que l'agent lit « rien à faire » et abandonne.
    lsa_retirer_la_table(&st2, "action");
    let (statut, corps) = lsa_texte(actions_pending(State(st2.clone()), Extension(agent.clone())).await).await;
    assert_eq!(statut, 503, "table retirée : refus nommé, jamais un TSV vide en 200 : {corps:?}");
}

// -------------------------------------------------------------------------------------
// (8) LE RESPONDER LOCAL — LA SEULE LECTURE DU RANG QUI NE SERT AUCUN CORPS
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT (garde de FORME, sur la source de production) : dans `respond_run`, la liste de
/// travail (`ACTIONS_A_RECLAMER_ICI`) est lue EN BLOC (`collect::<rusqlite::Result<Vec<_>>>()`), aucune
/// écriture d'aplatissement ne subsiste dans le CODE de la fonction (commentaires exclus : ils
/// DÉCRIVENT le défaut fermé, et une garde qui les lirait interdirait de le raconter), et la branche
/// d'échec SAUTE le tour en le comptant — `compter_un_tick_aveugle("responder_local", ..)` suivi d'un
/// `return`, la forme que les quatre balayages de fond du dépôt emploient déjà. Il tient AUSSI que ce
/// compteur est réel : le témoin l'appelle et relit sa valeur et sa cause.
///
/// CE QU'IL NE TIENT PAS, ET C'EST DIT : `respond_run` n'est PAS exécuté ici. Il ouvre sa propre
/// connexion depuis la configuration (`load_config`, `PLUME_DB`) et n'a aucune couture de test — la
/// réserve que `P4.7-f` a déjà consignée pour le témoin de bout en bout de cette même fonction. La
/// propriété est donc tenue par la FORME de la source plus l'exercice du compteur, pas par une
/// exécution. Réserve supplémentaire, mesurée : `respond_run` est une INVOCATION (un processus par
/// déclenchement de la minuterie `plume-respond`), donc le compteur meurt avec le processus et
/// n'atteint jamais `/metrics` ; l'observable de terrain est la ligne de journal que
/// `compter_un_tick_aveugle` écrit sur la sortie d'erreur.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.map(|x| x.flatten().collect()).unwrap_or_default()` (ou
/// remplacer le comptage par un `return` nu) — l'assert du solde en bloc, celui de l'absence
/// d'aplatissement, ou celui du couple comptage+retour tombe.
#[test]
fn p10_7f_listes_de_securite_le_responder_local_saute_son_tour_au_lieu_dagir_sur_une_liste_tronquee() {
    let src = std::fs::read_to_string(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/handlers/actions.rs")).unwrap();
    let debut = src.find("pub(crate) fn respond_run() {").expect("le responder local existe");
    let fin = src[debut..].find("\n}\n").map(|x| debut + x + 3).unwrap_or(src.len());
    // Les commentaires sont RETIRÉS : ils racontent le défaut fermé, et une garde qui les lirait
    // interdirait de l'écrire — c'est l'anti-motif « démentir une phrase fausse en la reproduisant ».
    let code: String = src[debut..fin]
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        code.contains("ACTIONS_A_RECLAMER_ICI"),
        "instrument : la liste de travail du responder se lit encore par sa constante nommée"
    );
    assert!(
        code.contains("collect::<rusqlite::Result<Vec<_>>>()"),
        "la liste de travail est SOLDÉE EN BLOC : une ligne illisible ne la raccourcit plus en silence"
    );
    assert!(
        !code.contains(".flatten()") && !code.contains("filter_map(Result::ok)"),
        "aucune écriture d'aplatissement ne subsiste dans le CODE de `respond_run` :\n{}",
        code.lines().filter(|l| l.contains("flatten") || l.contains("filter_map")).collect::<Vec<_>>().join("\n")
    );
    let i_compte = code.find("compter_un_tick_aveugle(\"responder_local\"").expect("le tour sauté est COMPTÉ, avec le nom de ce balayage");
    assert!(
        code[i_compte..].lines().take(3).any(|l| l.contains("return")),
        "le tour compté est aussi SAUTÉ : le comptage est immédiatement suivi d'un retour, jamais d'une action sur une liste tronquée"
    );

    // LE COMPTEUR EST RÉEL, et il porte la cause. Le nom est celui que la source vient d'exiger.
    let avant = crate::metrics::tick_aveugle_de("responder_local").map(|(n, _)| n).unwrap_or(0);
    crate::metrics::compter_un_tick_aveugle("responder_local", "témoin : lecture de la liste de travail refusée");
    let (apres, cause) = crate::metrics::tick_aveugle_de("responder_local").expect("le balayage est désormais compté");
    assert_eq!(apres, avant + 1, "un tour aveugle de plus est compté");
    assert!(cause.contains("témoin"), "la DERNIÈRE cause est conservée avec le compte : {cause}");
}
