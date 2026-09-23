// =====================================================================================
// `P10.20-b` (rang 1) — UNE LECTURE D'UNE SEULE LIGNE QUI N'A PAS EU LIEU NE SE SERT PAS COMME UN FAIT,
// ET NE DÉCIDE RIEN.
//
// LE DÉFAUT MESURÉ LE 2026-09-16. Cinquante occurrences de `query_row(..).ok()` vivent dans
// `daemon/src/handlers/` (vingt fichiers, quarante-six fonctions, relevé rejoué avec les lecteurs de la
// garde de famille `check_a_truncated_list_is_never_served_as_a_complete_one.py`). `query_row` rend
// `Err(QueryReturnedNoRows)` quand il n'y a PAS DE LIGNE et `Err(..)` quand la lecture a ÉCHOUÉ ; `.ok()`
// écrase les deux en un `None` unique. Le code qui suit ne peut plus les distinguer, et il conclut — le
// plus souvent dans le sens rassurant : « aucune MFA », « version 1 », « aucune préférence », « aucun
// champ masqué », « aucune définition de bibliothèque ». La cause n'est pas exotique : un cache de
// schéma de pool périmé fait sortir « no such table » comme une erreur de LIGNE (famille mesurée dans
// la note `flatten-avale-no-such-table-au-premier-pas`), une colonne ajoutée par une migration n'est pas
// encore vue par la connexion qui sert, une valeur corrompue ne se convertit pas.
//
// POURQUOI CES SEPT-LÀ, ET PAS LES QUARANTE-TROIS AUTRES. Le rang un est ce qui entre dans une DÉCISION
// DE SÉCURITÉ ou dans la SANTÉ SERVIE. Trois lectures décidaient et penchaient du côté ouvert : le
// second facteur d'un compte (le mot de passe seul posait la session), la garde anti-écrasement de
// l'enrôlement (une panne de lecture DÉSARME la MFA du compte), la porte de masquage d'un dry-run (les
// échantillons repartaient en clair). Une quatrième jugeait la porte « SQL brut = admin » sur une
// définition qui n'est pas celle qui s'exécutera. Deux servaient un fait inventé : la version de schéma
// (`1`, la seule valeur qu'un opérateur ne peut pas reconnaître comme fausse) sur quatre surfaces, et
// le statut de double authentification. La dernière détruisait de l'état durable : un jeu de
// préférences VIDE servi en 200 fait vider le miroir du client, dont le PUT suivant écrase la ligne du
// compte. Les autres rangs sont CLASSÉS, pas corrigés.
//
// CE QUE CES TÉMOINS JOUENT, ET POURQUOI DEUX VOIES. La voie de la TABLE RETIRÉE (renommée sous les
// pieds du gestionnaire) fait échouer la PRÉPARATION. La voie de la LIGNE ILLISIBLE (un `BLOB` posé
// dans une colonne que le mappeur lit en `TEXT` ou en `INTEGER` — SQLite conserve un blob tel quel
// quelle que soit l'affinité) fait échouer le MAPPEUR, la requête restant saine : c'est la voie la plus
// proche des causes de terrain, et celle qu'aucune garde de forme ne verrait. Chaque témoin porte son
// CONTRÔLE POSITIF dans le même corps : sans lui, un refus INCONDITIONNEL passerait pour un refus
// fondé. LA VERSION DE SCHÉMA porte une TROISIÈME voie qui lui est propre — la ligne existe et n'est
// pas un entier —, parce que c'est la seule des trois que l'ancien `unwrap_or(1)` masquait aussi.
//
// LA FORME DES CORRECTIFS EST CELLE DU DÉPÔT.
//   * La lecture rend `Result<Option<_>>` (`rusqlite::OptionalExtension::optional`) : l'absence de
//     ligne reste un FAIT, l'échec remonte ;
//   * ce qui DÉCIDE refuse : 503 nommé (MFA, préférences, résolution de panneau), `error` nommé dans le
//     corps pour le dry-run dont la signature ne porte aucun code. 503 et non 403 ni 404 : ce n'est pas
//     un droit ni une absence, c'est une lecture — et un refus réessayable ne s'apprend pas comme une
//     interdiction ;
//   * ce qui SERT rend `null` et pose un aveu NOMMÉ à côté (`schema_version_non_etablie`), sur le
//     modèle de `TotalBorne::en_json` et de `corps_de_listes_illisibles` : rien n'est ajouté sur le
//     chemin nominal, donc le corps y ressort byte-identique.
//
// CE QUE CE LOT NE TIENT PAS, ET IL FAUT LE LIRE ICI : aucun de ces témoins ne juge ce que la CONSOLE
// peint. `web/system.js` affiche « schéma v? » sur un `null` (ambigu, pas faux) ; `web/idp.js` peint
// « erreur : <message> » sur un statut hors deux cents, ce qui suffit à ne plus écrire « double
// authentification inactive », mais n'est pas la forme à deux nœuds traduisible du dépôt. Et la lecture
// de la version de schéma du chemin d'OUVERTURE (`migrate::read_schema_version`) retombe toujours sur
// `1` : elle est hors du répertoire que ce lot mesure, et elle est NOMMÉE comme reste.
// =====================================================================================

/// Statut + corps JSON d'une réponse.
async fn lqo_corps(r: Response) -> (u16, Value) {
    let statut = r.status().as_u16();
    let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
    (statut, serde_json::from_slice(&b).unwrap_or(Value::Null))
}

/// Écrit dans la base du tenant par la MÊME connexion que les gestionnaires (le writer de `AppState`).
fn lqo_ecrire(st: &AppState, sql: &str) {
    let conn = st.db.lock();
    conn.execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
}

/// Retire une table sous les pieds du gestionnaire sans toucher au code servi : renommée, elle n'est
/// plus sous le nom que le SQL servi attend (un renommage ne viole aucune clé étrangère).
fn lqo_retirer_la_table(st: &AppState, table: &str) {
    lqo_ecrire(st, &format!("ALTER TABLE {table} RENAME TO {table}_hors_d_atteinte;"));
}

/// L'état file-backed du rang 1 : schéma + migrations complets, `adm` administrateur.
fn lqo_etat(tag: &str) -> (AppState, AuthUser, crate::tmp_possede::TmpDb) {
    let (st, p) = sp_state(&format!("lqo-{tag}"));
    (st, sp_au("adm", "admin"), p)
}

// -------------------------------------------------------------------------------------
// (1) LE STATUT DE DOUBLE AUTHENTIFICATION, SERVI
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `mfa_status` sert `{enrolled, enabled}` comme des FAITS quand la ligne a été lue
/// (contrôle positif compté sur les deux états : aucune ligne, puis une ligne active) ; une ligne dont
/// le mappeur échoue et une table retirée rendent un 503 NOMMÉ, jamais `{enrolled:false,
/// enabled:false}` — « ce compte n'a pas de second facteur », qui est l'affirmation exactement fausse.
///
/// CE QU'IL NE TIENT PAS : il ne juge pas ce que la console peint de ce 503 (`web/idp.js` affiche
/// « erreur : <message> », donc il n'écrit plus « inactive » — mais la phrase n'est pas traduisible).
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.ok()` à la place d'`.optional()` — la route redevient
/// 200 avec `enrolled:false`, et les deux derniers blocs tombent.
#[tokio::test]
async fn p10_20b_le_statut_de_double_authentification_est_lu_ou_avoue() {
    let (st, au, _p) = lqo_etat("mfa-status");

    // CONTRÔLE POSITIF (1/2) — aucune ligne : une absence ÉTABLIE, servie comme telle.
    let (statut, vierge) = lqo_corps(mfa_status(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200);
    assert_eq!(vierge["enrolled"], json!(false), "aucun enrôlement est un FAIT : {vierge}");
    assert_eq!(vierge["enabled"], json!(false), "aucune MFA active est un FAIT : {vierge}");

    // CONTRÔLE POSITIF (2/2) — une MFA ACTIVE est lue comme telle.
    lqo_ecrire(&st, "INSERT INTO user_mfa(user,secret,enabled,recovery,last_step,created,updated) \
                     VALUES('adm','SEED',1,'[]',-1,0,0);");
    let (statut, active) = lqo_corps(mfa_status(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200);
    assert_eq!(active["enabled"], json!(true), "la MFA active est servie active : {active}");

    // UNE LIGNE ILLISIBLE : `enabled` porte un BLOB, que `get::<i64>` refuse. La requête reste saine.
    lqo_ecrire(&st, "UPDATE user_mfa SET enabled=x'FF' WHERE user='adm';");
    let (statut, avoue) = lqo_corps(mfa_status(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 503, "lecture non faite : la route REFUSE au lieu de servir « non enrôlé » : {avoue}");
    assert_eq!(avoue["error"], json!(CAUSE_MFA_NON_LUE), "le refus NOMME sa cause : {avoue}");

    // LA TABLE RETIRÉE : la préparation échoue.
    lqo_retirer_la_table(&st, "user_mfa");
    let (statut, sans_table) = lqo_corps(mfa_status(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 503, "table hors d'atteinte : même refus : {sans_table}");
    assert_eq!(sans_table["error"], json!(CAUSE_MFA_NON_LUE));
}

// -------------------------------------------------------------------------------------
// (2) LA GARDE ANTI-ÉCRASEMENT DE L'ENRÔLEMENT
// -------------------------------------------------------------------------------------

/// `P10.23-b` — l'enrôlement exige le mot de passe du compte et l'adresse du client (verrou de la connexion) :
/// ce témoin juge la garde de LECTURE, il présente donc la preuve juste pour que seule elle puisse refuser.
fn lqo_pair() -> ConnectInfo<std::net::SocketAddr> {
    ConnectInfo("10.30.0.1:45454".parse().expect("adresse de test"))
}
fn lqo_avec_le_mot_de_passe() -> Json<Value> {
    Json(json!({ "password": "motdepasse12345" }))
}

/// CE QU'IL TIENT : `mfa_enroll` refuse en 409 quand une MFA est ACTIVE (contrôle positif), et REFUSE
/// en 503 quand il n'a pas pu LIRE `enabled` — au lieu de franchir sa garde et de reposer
/// `secret=<neuf>, enabled=0`, c'est-à-dire de DÉSARMER le second facteur du compte sur une panne de
/// lecture. Le témoin le prouve par l'ÉTAT : la graine d'origine est encore là après le refus.
///
/// CE QU'IL NE TIENT PAS : il ne joue pas l'enrôlement NOMINAL (un compte sans MFA) jusqu'à la
/// génération de graine — `rand_bytes` y dépend de l'entropie noyau, et ce n'est pas la propriété
/// jugée ici.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.ok()` — la garde ne voit plus la MFA active, la route
/// rend 200 avec une graine neuve, et l'assert d'état (`secret` toujours `SEED`) tombe avec le statut.
#[tokio::test]
async fn p10_20b_l_enrolement_mfa_ne_franchit_pas_sa_garde_sur_une_lecture_ratee() {
    let (st, au, _p) = lqo_etat("mfa-enroll");
    lqo_ecrire(&st, "INSERT INTO user_mfa(user,secret,enabled,recovery,last_step,created,updated) \
                     VALUES('adm','SEED',1,'[]',-1,0,0);");

    // CONTRÔLE POSITIF — la garde VOIT la MFA active et refuse en 409.
    let (statut, conflit) = lqo_corps(mfa_enroll(State(st.clone()), lqo_pair(), Extension(au.clone()), lqo_avec_le_mot_de_passe()).await).await;
    assert_eq!(statut, 409, "MFA active : l'enrôlement est refusé : {conflit}");

    // UNE LIGNE ILLISIBLE : la garde ne peut plus LIRE `enabled`.
    lqo_ecrire(&st, "UPDATE user_mfa SET enabled=x'FF' WHERE user='adm';");
    let (statut, avoue) = lqo_corps(mfa_enroll(State(st.clone()), lqo_pair(), Extension(au.clone()), lqo_avec_le_mot_de_passe()).await).await;
    assert_eq!(statut, 503, "lecture non faite : l'enrôlement REFUSE, il ne franchit pas sa garde : {avoue}");
    assert_eq!(avoue["error"], json!(CAUSE_MFA_NON_LUE));
    let reste: String = {
        let c = st.db.lock();
        c.query_row("SELECT secret FROM user_mfa WHERE user='adm'", [], |r| r.get(0)).expect("la ligne est là")
    };
    assert_eq!(reste, "SEED", "AUCUNE écriture : la graine du second facteur est intacte");

    // LA TABLE RETIRÉE : même refus, par l'autre voie.
    lqo_retirer_la_table(&st, "user_mfa");
    let (statut, sans_table) = lqo_corps(mfa_enroll(State(st.clone()), lqo_pair(), Extension(au.clone()), lqo_avec_le_mot_de_passe()).await).await;
    assert_eq!(statut, 503, "table hors d'atteinte : même refus : {sans_table}");
}

// -------------------------------------------------------------------------------------
// (3) LA DÉCISION DE CONNEXION — LE SEUL SITE OÙ « PAS LU » VALAIT « PAS DE SECOND FACTEUR »
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT, ET C'EST LE TÉMOIN LE PLUS DUR DU LOT : `login_post` ne pose PAS de session quand il
/// n'a pas pu lire si le compte exige un second facteur. Trois états sont joués sur la MÊME route, avec
/// le MÊME mot de passe valide : aucune MFA -> session posée (contrôle positif, `Set-Cookie` compté) ;
/// MFA active -> ticket de défi, jamais de session ; lecture ratée -> 503 nommé, jamais de session.
/// La propriété est jugée sur l'EN-TÊTE `Set-Cookie`, pas sur le statut seul : c'est la session qui est
/// l'enjeu, et un 200 sans cookie ne serait pas le défaut.
///
/// CE QU'IL NE TIENT PAS : il ne joue pas le second facteur lui-même (`/api/login/mfa`, qui refuse déjà
/// sur une lecture ratée — rang quatre), ni le mode multi-tenant (où la MFA est hors périmètre).
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rendre `mfa_enabled_for` à `unwrap_or(false)` — le troisième bloc
/// repasse en 200 AVEC un cookie de session, c'est-à-dire le mot de passe seul sur un compte protégé.
#[tokio::test]
async fn p10_20b_la_connexion_refuse_quand_le_second_facteur_n_a_pas_ete_lu() {
    let (st, _au, _p) = lqo_etat("mfa-login");
    let pair: std::net::SocketAddr = "127.0.0.1:44444".parse().expect("adresse de test");
    let identifiants = json!({ "user": "adm", "pass": "motdepasse12345" });
    let pose_une_session = |r: &Response| r.headers().get_all(header::SET_COOKIE).iter().count() > 0;

    // CONTRÔLE POSITIF (1/2) — aucune MFA : le mot de passe pose la session.
    let r = login_post(State(st.clone()), ConnectInfo(pair), Json(identifiants.clone())).await;
    assert_eq!(r.status().as_u16(), 200, "mot de passe valide, aucune MFA : la connexion aboutit");
    assert!(pose_une_session(&r), "contrôle positif : une session EST posée sur ce chemin");

    // CONTRÔLE POSITIF (2/2) — MFA active : défi, et AUCUNE session.
    lqo_ecrire(&st, "INSERT INTO user_mfa(user,secret,enabled,recovery,last_step,created,updated) \
                     VALUES('adm','SEED',1,'[]',-1,0,0);");
    let r = login_post(State(st.clone()), ConnectInfo(pair), Json(identifiants.clone())).await;
    assert!(!pose_une_session(&r), "MFA active : le 1er facteur ne pose JAMAIS la session");

    // LA LECTURE RATÉE : le second facteur EXISTE, mais la ligne ne se lit plus.
    lqo_ecrire(&st, "UPDATE user_mfa SET enabled=x'FF' WHERE user='adm';");
    let r = login_post(State(st.clone()), ConnectInfo(pair), Json(identifiants.clone())).await;
    assert_eq!(r.status().as_u16(), 503, "lecture non faite : la connexion est REFUSÉE");
    assert!(!pose_une_session(&r), "et SURTOUT : aucune session n'est posée sur le mot de passe seul");
    let (_, corps) = lqo_corps(r).await;
    assert_eq!(corps["error"], json!(CAUSE_MFA_NON_LUE), "le refus NOMME sa cause : {corps}");

    // LA TABLE RETIRÉE : même refus, par l'autre voie.
    lqo_retirer_la_table(&st, "user_mfa");
    let r = login_post(State(st.clone()), ConnectInfo(pair), Json(identifiants)).await;
    assert_eq!(r.status().as_u16(), 503, "table hors d'atteinte : même refus");
    assert!(!pose_une_session(&r));
}

// -------------------------------------------------------------------------------------
// (4) LA VERSION DE SCHÉMA — QUATRE SURFACES, TROIS CAUSES
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : la sonde de vivacité, l'exposition Prometheus et l'écran Système servent la version
/// LUE (contrôle positif : le maximum du code, compté), et servent `null` + un aveu NOMMÉ dans les
/// TROIS cas où rien n'est établi — table hors d'atteinte, valeur illisible (blob), valeur non entière.
/// L'étiquette Prometheus passe à `non_etablie` : une règle qui comparait `schema` à un numéro cesse de
/// matcher au lieu de matcher le mauvais. Le statut de `/healthz` reste 200, et c'est écrit sur la route
/// (un 503 de LIVENESS ferait tuer puis redémarrer le pod, ce qui ne rend pas `meta` lisible).
///
/// CE QU'IL NE TIENT PAS : il ne joue pas `/readyz` (qui ne lit PAS la version — décision écrite sur la
/// route), ni le paquet de diagnostic (admin-only, jugé par son propre témoin), ni ce que la console
/// peint d'un `null` (`web/system.js` affiche « schéma v? »).
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.ok().and_then(..).unwrap_or(1)` — les trois voies
/// servent `"schema": 1` sans aveu, et les trois derniers blocs tombent ensemble.
#[tokio::test]
async fn p10_20b_la_version_de_schema_non_etablie_est_avouee_par_la_sonde_et_l_ecran() {
    let (st, au, _p) = lqo_etat("schema");
    let cle_aveu = crate::handlers::system::CLE_VERSION_DE_SCHEMA_NON_ETABLIE;

    // CONTRÔLE POSITIF — la version est LUE, et aucun aveu n'est posé.
    let (statut, sain) = lqo_corps(healthz(State(st.clone())).await).await;
    assert_eq!(statut, 200);
    assert_eq!(sain["schema"], json!(CODE_SCHEMA_MAX), "la version lue est servie telle quelle : {sain}");
    assert!(sain.get(cle_aveu).is_none(), "chemin nominal MUET — un aveu inconditionnel n'est pas un aveu : {sain}");
    let ecran = system_metrics(State(st.clone()), Extension(au.clone())).await.0;
    assert_eq!(ecran["schema_version"], json!(CODE_SCHEMA_MAX), "écran Système : {ecran}");
    {
        let c = st.db.lock();
        let prom = crate::gather_prom(&c, "/nonexistent-spool", "", &schema_version(&c), 80);
        assert!(prom.contains(&format!("schema=\"{CODE_SCHEMA_MAX}\"")), "étiquette Prometheus lue");
    }

    // VOIE 1 — LA VALEUR N'EST PAS UN ENTIER : la ligne existe, elle ne porte rien d'exploitable.
    lqo_ecrire(&st, "UPDATE meta SET value='pas-un-entier' WHERE key='schema_version';");
    let (statut, texte) = lqo_corps(healthz(State(st.clone())).await).await;
    assert_eq!(statut, 200, "la LIVENESS reste verte : le process sert, et il le dit");
    assert_eq!(texte["schema"], Value::Null, "jamais « 1 » : {texte}");
    assert!(texte[cle_aveu].as_str().unwrap_or("").contains("NON ÉTABLIE"), "l'aveu NOMME l'absence : {texte}");

    // VOIE 2 — UNE LIGNE ILLISIBLE : `value` porte un BLOB, que `get::<String>` refuse.
    lqo_ecrire(&st, "UPDATE meta SET value=x'FF' WHERE key='schema_version';");
    let (_, blob) = lqo_corps(healthz(State(st.clone())).await).await;
    assert_eq!(blob["schema"], Value::Null, "jamais « 1 » : {blob}");
    assert!(blob[cle_aveu].as_str().unwrap_or("").contains("lecture a échoué"), "la cause distingue la lecture ratée : {blob}");
    let ecran = system_metrics(State(st.clone()), Extension(au.clone())).await.0;
    assert_eq!(ecran["schema_version"], Value::Null, "l'écran Système ne montre pas une version inventée : {ecran}");
    assert!(ecran.get(cle_aveu).is_some(), "et il dit pourquoi : {ecran}");
    {
        let c = st.db.lock();
        let prom = crate::gather_prom(&c, "/nonexistent-spool", "", &schema_version(&c), 80);
        assert!(prom.contains("schema=\"non_etablie\""), "l'étiquette Prometheus n'affirme aucune version : {prom}");
        assert!(!prom.contains("schema=\"1\""), "et SURTOUT pas « 1 » : {prom}");
    }

    // VOIE 3 — LA TABLE RETIRÉE : la préparation échoue.
    lqo_retirer_la_table(&st, "meta");
    let (_, sans_table) = lqo_corps(healthz(State(st.clone())).await).await;
    assert_eq!(sans_table["schema"], Value::Null, "table hors d'atteinte : rien n'est établi : {sans_table}");
    assert!(sans_table.get(cle_aveu).is_some(), "et le corps le dit : {sans_table}");
}

// -------------------------------------------------------------------------------------
// (5) LES PRÉFÉRENCES — LA SEULE LECTURE DU RANG QUI DÉTRUISAIT DE L'ÉTAT DURABLE
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `prefs_get` sert le blob du compte (contrôle positif) et sert `{}` quand aucune
/// ligne n'existe — une absence ÉTABLIE, le cas nominal d'un compte neuf ; mais il REFUSE en 503 nommé
/// quand la lecture n'a pas eu lieu, au lieu de servir le MÊME `{}`. La distinction est tout l'enjeu :
/// le client traite le blob du serveur comme la vérité COMPLÈTE (c'est écrit dans `web/prefs.js` et
/// c'est juste — l'absence d'une clé y EST sa suppression), donc un `{}` inventé lui fait vider son
/// miroir, puis son PUT suivant écrase la ligne du compte.
///
/// CE QU'IL NE TIENT PAS : il ne joue pas le client. Que la capture de `prefsInit()` garde bien le
/// miroir sur un statut hors deux cents est LU dans `web/prefs.js`, pas exercé ici.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.ok()` — les deux derniers blocs redeviennent
/// `200 {"prefs":{}}`, c'est-à-dire indiscernables du premier, qui est le défaut exact.
#[tokio::test]
async fn p10_20b_les_preferences_non_lues_refusent_au_lieu_de_servir_un_jeu_vide() {
    let (st, au, _p) = lqo_etat("prefs");

    // CONTRÔLE POSITIF (1/2) — aucune ligne : `{}` est un FAIT.
    let (statut, vierge) = lqo_corps(prefs_get(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200);
    assert_eq!(vierge["prefs"], json!({}), "compte neuf : aucune préférence, et c'est établi : {vierge}");

    // CONTRÔLE POSITIF (2/2) — le blob du compte est servi tel quel.
    lqo_ecrire(&st, "INSERT INTO user_pref(user,prefs,updated) VALUES('adm','{\"colw\":{\"event\":{\"ts\":120}}}',1);");
    let (statut, plein) = lqo_corps(prefs_get(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200);
    assert_eq!(plein["prefs"]["colw"]["event"]["ts"], json!(120), "les préférences lues sont servies : {plein}");

    // UNE LIGNE ILLISIBLE : `prefs` porte un BLOB, que `get::<String>` refuse.
    lqo_ecrire(&st, "UPDATE user_pref SET prefs=x'FF' WHERE user='adm';");
    let (statut, avoue) = lqo_corps(prefs_get(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 503, "lecture non faite : REFUS, et surtout pas un jeu vide en 200 : {avoue}");
    assert_eq!(avoue["error"], json!(CAUSE_PREFERENCES_NON_LUES), "le refus NOMME sa cause : {avoue}");
    assert!(avoue.get("prefs").is_none(), "aucun `prefs` servi : rien à prendre pour la vérité complète : {avoue}");

    // LA TABLE RETIRÉE : même refus, par l'autre voie.
    lqo_retirer_la_table(&st, "user_pref");
    let (statut, sans_table) = lqo_corps(prefs_get(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 503, "table hors d'atteinte : même refus : {sans_table}");
    assert_eq!(sans_table["error"], json!(CAUSE_PREFERENCES_NON_LUES));
}

// -------------------------------------------------------------------------------------
// (6) LA PORTE DE MASQUAGE D'UN DRY-RUN
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `baseline_test` ne rend PLUS « ligne de base introuvable » quand la pré-lecture qui
/// arme sa porte de masquage a échoué — il rend une cause qui DIT que la porte n'a pas pu être armée.
/// La distinction compte parce que la lecture COMPLÈTE, plus bas, est une SECONDE lecture sur une AUTRE
/// connexion : elle peut réussir là où la pré-lecture a échoué, et le dry-run repartait alors SANS
/// masque, en restituant les échantillons `(entité, valeur)` en clair.
///
/// CE QU'IL NE TIENT PAS, ET C'EST DIT : le contrôle positif est NÉGATIF sur la seule propriété jugée —
/// il vérifie qu'un dry-run dont la pré-lecture RÉUSSIT ne porte JAMAIS cette cause, quel que soit ce
/// que l'évaluation rend ensuite (elle dépend d'une base d'événements que ce témoin ne sème pas). Il ne
/// prouve pas non plus qu'un champ masqué serait effectivement refusé — c'est la propriété de
/// `caller_dryrun_guard`, tenue ailleurs ; ici on tient qu'on ne la SAUTE plus.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.ok()` — la pré-lecture rend `None`, le `if let Some`
/// enjambe la porte, la route poursuit et rend « ligne de base introuvable » : les deux derniers blocs
/// tombent.
#[tokio::test]
async fn p10_20b_le_dry_run_refuse_quand_sa_porte_de_masquage_n_a_pas_pu_etre_armee() {
    let (st, au, _p) = lqo_etat("baseline");
    lqo_ecrire(&st, "INSERT INTO ueba_baseline(name,query,entity_field,value_field,window_s) \
                     VALUES('b1','search *','src_ip','bytes',3600);");
    let id = {
        let c = st.db.lock();
        c.query_row("SELECT id FROM ueba_baseline WHERE name='b1'", [], |r| r.get::<_, i64>(0)).expect("la fixture est là")
    };

    // CONTRÔLE POSITIF — la pré-lecture RÉUSSIT : quoi que rende l'évaluation, ce n'est pas CETTE cause.
    let nominal = baseline_test(State(st.clone()), Extension(au.clone()), Path(id)).await.0;
    assert_ne!(
        nominal["error"], json!(CAUSE_PORTE_DRYRUN_NON_ARMEE),
        "chemin nominal : la porte a été armée, donc aucun refus de ce nom : {nominal}"
    );

    // UNE LIGNE ILLISIBLE : `query` porte un BLOB, que `get::<String>` refuse.
    lqo_ecrire(&st, "UPDATE ueba_baseline SET query=x'FF' WHERE id=?1;".replace("?1", &id.to_string()).as_str());
    let avoue = baseline_test(State(st.clone()), Extension(au.clone()), Path(id)).await.0;
    assert_eq!(
        avoue["error"], json!(CAUSE_PORTE_DRYRUN_NON_ARMEE),
        "pré-lecture ratée : le refus dit que la PORTE n'a pas pu être armée, pas que la ligne n'existe pas : {avoue}"
    );

    // LA TABLE RETIRÉE : la préparation échoue.
    lqo_retirer_la_table(&st, "ueba_baseline");
    let sans_table = baseline_test(State(st.clone()), Extension(au.clone()), Path(id)).await.0;
    assert_eq!(sans_table["error"], json!(CAUSE_PORTE_DRYRUN_NON_ARMEE), "table hors d'atteinte : même refus : {sans_table}");
}

// -------------------------------------------------------------------------------------
// (7) LA PORTE « SQL BRUT = ADMIN » — JUGER LA DÉFINITION QUI S'EXÉCUTERA, OU REFUSER
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `DefinitionExecutee::projetee` juge la définition de BIBLIOTHÈQUE quand la
/// référence est en place (contrôle positif : la bibliothèque porte du SQL brut, donc la porte REFUSE
/// l'editor, alors que le panneau, lui, porte du GXQL) ; et quand cette ligne ne se LIT plus, elle rend
/// un refus 503 NOMMÉ au lieu de retomber sur la définition du panneau. Le repli était le contournement
/// exact que `P7.13-a` avait fermé, rouvert par une panne de lecture : la porte jugeait le GXQL du
/// panneau pendant que l'exécuteur, qui relit la jointure, exécuterait le SQL brut de la bibliothèque.
/// La branche jouée est `Inchangee`, la plus exposée : elle ne passe par aucune des deux autres gardes.
///
/// CE QU'IL NE TIENT PAS : il ne joue pas les routes `panel_create`/`panel_update` de bout en bout
/// (elles reversent le couple (code, phrase) tel quel, ce que leur propre code montre), ni la branche
/// `Vers(n)`, dont la garde de lisibilité refusait déjà — autrement, il est vrai, avec une phrase
/// d'INTERDICTION là où il n'y avait qu'une lecture manquante.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.ok()` sur `ligne_bibliotheque` — les deux derniers
/// blocs rendent `Ok` avec la définition du PANNEAU, `permise_pour("editor")` redevient vrai, et un
/// panneau dont la bibliothèque porte du SQL brut passe la porte d'un editor.
#[test]
fn p10_20b_la_porte_sql_brut_refuse_quand_la_definition_de_bibliotheque_n_est_pas_lue() {
    let conn = test_db();
    let adm = sp_au("adm", "admin");
    conn.execute("INSERT INTO library_panel(name,title,query,is_soql,visibility) VALUES('L','T','SELECT * FROM user',0,'shared')", [])
        .expect("fixture : une définition de bibliothèque en SQL BRUT");
    let lid = conn.last_insert_rowid();
    // Ce que le panneau porte EN PROPRE : du GXQL, que la porte laisserait passer à un editor.
    let panneau_local = ("search *".to_string(), true);

    // CONTRÔLE POSITIF — la bibliothèque GAGNE : la porte juge son SQL brut, donc elle refuse l'editor.
    let jugee = DefinitionExecutee::projetee(&conn, &adm, Some(lid), &RefBibliotheque::Inchangee, panneau_local.clone())
        .expect("lecture faite : la résolution aboutit");
    assert!(!jugee.is_soql(), "la définition jugée est celle de la BIBLIOTHÈQUE (SQL brut)");
    assert!(!jugee.permise_pour("editor"), "contrôle positif : la porte refuse le SQL brut à un editor");
    assert!(jugee.permise_pour("admin"), "…et l'ouvre à l'admin");

    // `DefinitionExecutee` n'implémente PAS `Debug` — à dessein : son texte de requête ne doit pas
    // pouvoir fuir dans un message. Le refus se lit donc par `match`, jamais par `expect_err`.
    let juger_le_refus = |r: Result<DefinitionExecutee, (StatusCode, &'static str)>, voie: &str| match r {
        Ok(_) => panic!("{voie} : la résolution a ABOUTI — elle est retombée sur la définition du panneau"),
        Err((code, phrase)) => {
            assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE, "{voie} : 503 — ce n'est pas un droit qui manque, c'est une lecture");
            assert_eq!(phrase, panneau_resolu::CAUSE_DEFINITION_DE_BIBLIOTHEQUE_NON_LUE, "{voie} : le refus NOMME sa cause");
        }
    };

    // UNE LIGNE ILLISIBLE : `query` porte un BLOB, que `get::<String>` refuse.
    conn.execute("UPDATE library_panel SET query=x'FF' WHERE id=?1", params![lid]).expect("fixture");
    juger_le_refus(
        DefinitionExecutee::projetee(&conn, &adm, Some(lid), &RefBibliotheque::Inchangee, panneau_local.clone()),
        "ligne illisible",
    );

    // LA TABLE RETIRÉE : la préparation échoue.
    conn.execute_batch("ALTER TABLE library_panel RENAME TO library_panel_hors_d_atteinte;").expect("fixture");
    juger_le_refus(
        DefinitionExecutee::projetee(&conn, &adm, Some(lid), &RefBibliotheque::Inchangee, panneau_local),
        "table retirée",
    );
}
