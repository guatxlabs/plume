// ====================================================================================================
// `P10.20-b` — L'INVENTAIRE EST LU ENTIÈREMENT OU AVOUÉ ; UNE PROVENANCE NON LUE N'EST PAS DEVINÉE.
// ====================================================================================================
//
// Inclus par `comptes_qui_accedent.rs` (même module : ses aides `acces_routeur`, `acces_entetes_sso`,
// `test_db`, `sp_state` servent ici sans être recopiées).
//
// CE QUI ÉTAIT FAUX. `comptes_qui_accedent.rs` portait le témoin `une_base_sans_la_table_rend_un_inventaire_
// vide_et_jamais_une_erreur` : il POSAIT la prémisse « table absente -> liste vide, la console rend le reste »,
// au motif d'une base « non migrée ». La prémisse est réfutée par la porte de schéma (premier témoin
// ci-dessous) : `acces_observe` est dans `db/schema.sql`, donc dans la forme que `schema_gaps` exige, et
// `prepare_schema` refuse de servir une base qui ne la porte pas. Une table absente PENDANT le service est une
// anomalie, et la liste vide qu'elle rendait s'affichait « aucun accès observé pour le moment ».
//
// LES MUTATIONS QUI LES FONT ROUGIR (jouées sous `cfg!(test)` par la variable de mutation, puis retirées du
// source) : `err_vide` (préparation ratée -> liste vide), `flatten` (ligne indécodable sautée, pas raté -> fin
// de liste), `aveu_absent` (le corps sert `acces: []` sans la clé nommée), `provenance_devinee` (lecture ratée
// de `user` -> « identifiant d'amorçage »), `rien_ecrit` (lecture ratée -> aucune vue écrite), `chemin_is_ok`
// (`consigner_l_acces`, le point de passage qu'appelle `auth_guard`, revenu à l'ancien `.is_ok()` +
// `provenance_de` : une lecture ratée y redevient « identifiant d'amorçage » alors que `consigner_dans` reste
// juste), `plafond_unwrap0` (comptage raté -> borne sautée), `etape_confondue` (deux étapes ratées portent le
// même mot de journal).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS :
//   * le journal n'est pas capturé : que les `eprintln!` d'`existence_locale` et de
//     `corps_de_la_liste_des_comptes` portent la méthode, l'étape et la cause — et jamais le nom — tient à la
//     relecture. Le témoin d'étape ci-dessous fige les mots distincts d'`etape()`, pas leur emploi au journal ;
//   * la ligne « provenance non établie » écrite sur une lecture ratée reste dans la table à côté de la ligne
//     « compte local » d'une vue suivante (clé primaire (nom, provenance)) jusqu'à ce que le plafond la fasse
//     céder ;
//   * le comptage raté du plafond est témoigné par un autorisateur qui refuse le `SELECT` nu et laisse passer
//     le `DELETE` ; si le moteur refuse les deux, la borne n'est pas tenue et seul le journal le dit.

/// Une table d'inventaire absente est REFUSÉE par la porte de schéma — donc, vue pendant le service, une
/// anomalie — et sa lecture rend `Preparation`, jamais une liste vide. Les deux formes : base sans la table
/// du tout, table renommée après coup (la forme qu'une base servie peut prendre).
#[test]
fn iao_une_table_d_inventaire_absente_est_une_anomalie_et_jamais_une_liste_vide() {
    use crate::acces_observe::InventaireNonLu;
    let conn = test_db();
    conn.execute("ALTER TABLE acces_observe RENAME TO acces_observe_ecarte_iao", []).unwrap();
    let gaps = crate::migrate::schema_gaps(&conn).expect("le contrôle de schéma s'exécute");
    assert!(
        gaps.iter().any(|g| g == "table acces_observe"),
        "la porte de schéma doit NOMMER une base sans `acces_observe` (elle refuserait alors de la servir) : {gaps:?}"
    );
    match inventaire_des_acces(&conn) {
        Err(InventaireNonLu::Preparation(_)) => {}
        autre => panic!("table renommée : l'inventaire doit être NON LU à la préparation, pas {autre:?}"),
    }
    let nue = Connection::open_in_memory().unwrap();
    assert!(
        matches!(inventaire_des_acces(&nue), Err(InventaireNonLu::Preparation(_))),
        "base sans la table : NON LU à la préparation, jamais une liste vide servie comme complète"
    );
}

/// Une ligne dont une cellule ne se décode pas (un blob dans une colonne TEXT) refuse TOUT l'inventaire :
/// elle n'est ni sautée ni coupée. Témoin positif : sans elle, les deux voisines sont rendues dans l'ordre.
#[test]
fn iao_une_ligne_indecodable_refuse_l_inventaire_au_lieu_d_etre_sautee() {
    use crate::acces_observe::InventaireNonLu;
    let conn = test_db();
    let t = 1_700_000_000i64;
    ecrire_vue(&conn, "recente-iao", "annuaire externe", "admin", "groupes de l'annuaire", "sso", t + 20);
    ecrire_vue(&conn, "ancienne-iao", "compte local", "viewer", "table des comptes", "basic", t);
    let lues = inventaire_des_acces(&conn).expect("nominal : l'inventaire se lit");
    let noms: Vec<&str> = lues.iter().filter_map(|a| a["nom"].as_str()).collect();
    assert_eq!(noms, vec!["recente-iao", "ancienne-iao"], "nominal : plus récent d'abord");
    conn.execute(
        "INSERT INTO acces_observe(nom,provenance,role_effectif,origine_du_role,methode,premiere_vue,derniere_vue) \
         VALUES(X'00FF10',?1,'admin','groupes de l''annuaire','sso',?2,?2)",
        params!["annuaire externe", t + 10],
    )
    .unwrap();
    match inventaire_des_acces(&conn) {
        Err(InventaireNonLu::LigneIndecodable(_)) => {}
        autre => panic!("ligne au nom illisible : l'inventaire doit être NON LU (ligne indécodable), pas {autre:?}"),
    }
}

/// Un pas du moteur interrompu (gestionnaire de progression) refuse l'inventaire : ce qui était lu avant
/// l'interruption n'est pas une liste. Le gestionnaire est retiré, puis la même lecture aboutit.
#[test]
fn iao_un_pas_interrompu_refuse_l_inventaire() {
    use crate::acces_observe::InventaireNonLu;
    let conn = test_db();
    let t = 1_700_000_000i64;
    for i in 0..40i64 {
        ecrire_vue(&conn, &format!("vue-iao-{i}"), "annuaire externe", "viewer", "groupes de l'annuaire", "sso", t + i);
    }
    conn.progress_handler(1, Some(|| true));
    let interrompue = inventaire_des_acces(&conn);
    conn.progress_handler(1, None::<fn() -> bool>);
    match interrompue {
        Err(InventaireNonLu::Pas(_)) => {}
        autre => panic!("pas interrompu : l'inventaire doit être NON LU (pas du moteur), pas {:?}", autre.map(|v| v.len())),
    }
    assert_eq!(inventaire_des_acces(&conn).expect("sans interruption").len(), 40, "contrôle positif : quarante vues");
}

/// LE CORPS DE `GET /api/users`, QUATRE ISSUES. Nominal OCTET POUR OCTET la forme d'avant ; inventaire non lu
/// -> `acces: []` PLUS la clé nommée, sans `error` ; comptes non lus -> forme inchangée, sans la clé ; aucune
/// des deux -> les deux NOMMÉES dans `non_lus`, et la clé posée aussi.
#[test]
fn iao_le_corps_des_comptes_avoue_l_inventaire_non_lu_par_sa_cle() {
    use crate::acces_observe::{InventaireNonLu, CAUSE_INVENTAIRE_DES_ACCES_NON_LU, CLE_ACCES_NON_LU};
    use crate::handlers::users_lookups::corps_de_la_liste_des_comptes;
    let u = json!({ "id": 1, "name": "hugo", "role": "admin", "created": 1 });
    let a = json!({ "nom": "annuaire.iao", "provenance": "annuaire externe" });
    let rate = || InventaireNonLu::Preparation(rusqlite::Error::InvalidQuery);
    let nominal = corps_de_la_liste_des_comptes("hugo", Ok(vec![u.clone()]), Ok(vec![a.clone()]));
    assert_eq!(
        nominal.to_string(),
        json!({ "users": [u.clone()], "me": "hugo", "acces": [a.clone()] }).to_string(),
        "nominal : octet pour octet la forme d'avant"
    );
    assert!(nominal.get(CLE_ACCES_NON_LU).is_none(), "nominal : aucune clé d'aveu");
    let vide = corps_de_la_liste_des_comptes("hugo", Ok(vec![u.clone()]), Ok(vec![]));
    assert!(vide.get(CLE_ACCES_NON_LU).is_none(), "inventaire LU et vide : aucune clé d'aveu ({vide})");

    let sans_acces = corps_de_la_liste_des_comptes("hugo", Ok(vec![u.clone()]), Err(rate()));
    assert_eq!(sans_acces[CLE_ACCES_NON_LU], json!(CAUSE_INVENTAIRE_DES_ACCES_NON_LU), "{sans_acces}");
    assert_eq!(sans_acces["acces"], json!([]), "{sans_acces}");
    assert_eq!(sans_acces["users"], json!([u.clone()]), "les comptes lus restent servis : {sans_acces}");
    assert!(sans_acces.get("error").is_none(), "les comptes sont lus : aucun `error` global ({sans_acces})");

    let sans_users = corps_de_la_liste_des_comptes("hugo", Err(rusqlite::Error::InvalidQuery), Ok(vec![a.clone()]));
    assert_eq!(sans_users["error"], json!(crate::handlers::liste_bornee::CAUSE_LISTE_ILLISIBLE), "{sans_users}");
    assert_eq!(sans_users["acces"], json!([a.clone()]), "l'inventaire lu reste servi : {sans_users}");
    assert!(sans_users.get(CLE_ACCES_NON_LU).is_none(), "{sans_users}");

    let aucun = corps_de_la_liste_des_comptes("hugo", Err(rusqlite::Error::InvalidQuery), Err(rate()));
    assert_eq!(aucun["non_lus"], json!(["users", "acces"]), "{aucun}");
    assert_eq!(aucun[CLE_ACCES_NON_LU], json!(CAUSE_INVENTAIRE_DES_ACCES_NON_LU), "{aucun}");
    assert!(aucun["users"] == json!([]) && aucun["acces"] == json!([]), "{aucun}");
    assert!(aucun["error"].as_str().unwrap_or("").starts_with(crate::handlers::liste_bornee::CAUSE_LISTE_ILLISIBLE), "{aucun}");
}

/// DE BOUT EN BOUT, PAR LE ROUTEUR RÉEL : nominal, l'inventaire porte l'administrateur venu de l'annuaire et
/// aucune clé d'aveu ; la table renommée, `/api/users` sert toujours les comptes locaux, `acces: []` ET la
/// clé nommée — jamais « personne n'a accédé ».
#[tokio::test]
async fn iao_la_route_des_comptes_avoue_un_inventaire_non_lu() {
    use crate::acces_observe::{CAUSE_INVENTAIRE_DES_ACCES_NON_LU, CLE_ACCES_NON_LU};
    let (addr, dbp, db) = acces_routeur("acces-iao-non-lu").await;
    let h = acces_entetes_sso("annuaire.iao", "plume-admin");
    let hr = acces_emprunt(&h);
    let (code, corps) = acces_requete(addr, "GET", "/api/users", &hr, "").await;
    assert_eq!(code, 200, "{corps}");
    let nominal = acces_json(&corps);
    assert!(acces_entree(&nominal, "annuaire.iao").is_some(), "nominal : l'accès figure ({nominal})");
    assert!(nominal.get(CLE_ACCES_NON_LU).is_none(), "nominal : aucune clé d'aveu ({nominal})");

    db.lock().execute("ALTER TABLE acces_observe RENAME TO acces_observe_ecarte_iao", []).unwrap();
    let (code, corps) = acces_requete(addr, "GET", "/api/users", &hr, "").await;
    assert_eq!(code, 200, "{corps}");
    let non_lu = acces_json(&corps);
    assert_eq!(non_lu[CLE_ACCES_NON_LU], json!(CAUSE_INVENTAIRE_DES_ACCES_NON_LU), "inventaire NON LU avoué : {non_lu}");
    assert_eq!(non_lu["acces"], json!([]), "{non_lu}");
    let locaux: Vec<&str> = non_lu["users"].as_array().map(|v| v.iter().filter_map(|u| u["name"].as_str()).collect()).unwrap_or_default();
    assert!(locaux.contains(&ACCES_COMPTE_LOCAL), "les comptes locaux restent servis : {non_lu}");
    ff_rm(&dbp);
}

/// LA PROVENANCE D'UN ACCÈS PAR MOT DE PASSE, SUR LES TROIS ISSUES DE LA TABLE DES COMPTES. Une lecture
/// refusée (autorisateur) n'inscrit ni « compte local » ni « identifiant d'amorçage » : elle inscrit la
/// provenance NON ÉTABLIE — et la vue EST écrite (ne rien écrire sortirait l'accès de l'inventaire pour la
/// fenêtre de débounce). Contrôles positifs : un nom porté -> compte local ; un nom absent -> amorçage.
#[test]
fn iao_une_table_des_comptes_non_lue_inscrit_une_provenance_non_etablie() {
    use crate::acces_observe::{
        consigner_dans, existence_locale, ExistenceLocale, ORIGINE_NON_ETABLIE, PROVENANCE_NON_ETABLIE,
    };
    let conn = test_db();
    let t = 1_700_000_000i64;
    conn.execute("INSERT INTO user(name,hash,role) VALUES('local-iao','x','editor')", []).unwrap();
    assert_eq!(existence_locale(&conn, "local-iao", "basic"), ExistenceLocale::Connue);
    assert_eq!(existence_locale(&conn, "amorce-iao", "basic"), ExistenceLocale::Absente);
    consigner_dans(&conn, "local-iao", "editor", "basic", t);
    consigner_dans(&conn, "amorce-iao", "admin", "basic", t);

    conn.authorizer(Some(|ctx: rusqlite::hooks::AuthContext<'_>| match ctx.action {
        rusqlite::hooks::AuthAction::Read { table_name, .. } if table_name == "user" => rusqlite::hooks::Authorization::Deny,
        _ => rusqlite::hooks::Authorization::Allow,
    }));
    let existence = existence_locale(&conn, "local-iao", "cookie");
    consigner_dans(&conn, "local-iao", "editor", "cookie", t + 5);
    conn.authorizer(None::<fn(rusqlite::hooks::AuthContext<'_>) -> rusqlite::hooks::Authorization>);
    assert_eq!(existence, ExistenceLocale::NonEtablie, "lecture refusée : ni connue ni absente");

    let lire = |nom: &str| -> Vec<(String, String)> {
        let mut st = conn.prepare("SELECT provenance,origine_du_role FROM acces_observe WHERE nom=?1 ORDER BY provenance").unwrap();
        let v = st.query_map(params![nom], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        v
    };
    assert_eq!(lire("amorce-iao"), vec![("identifiant d'amorçage".to_string(), "configuration du démon (hors table des comptes)".to_string())]);
    let local = lire("local-iao");
    assert!(local.contains(&("compte local".to_string(), "table des comptes".to_string())), "{local:?}");
    assert!(
        local.contains(&(PROVENANCE_NON_ETABLIE.to_string(), ORIGINE_NON_ETABLIE.to_string())),
        "lecture refusée : la vue est ÉCRITE, sous la provenance non établie : {local:?}"
    );
    assert!(
        !local.iter().any(|(p, _)| p == "identifiant d'amorçage"),
        "un compte local dont la table n'a pas été lue n'est JAMAIS dit « identifiant d'amorçage » : {local:?}"
    );
    // La provenance d'une méthode qui ne dépend pas de la table ne bouge pas, lue ou non.
    assert_eq!(provenance_selon_iao("sso"), "annuaire externe");
}

fn provenance_selon_iao(methode: &str) -> &'static str {
    crate::acces_observe::provenance_selon(methode, crate::acces_observe::ExistenceLocale::NonEtablie).0
}

/// LE POINT DE PASSAGE RÉEL. `auth_guard` appelle `consigner_l_acces`, pas `consigner_dans` : une table des
/// comptes refusée doit inscrire la provenance NON ÉTABLIE par CE chemin-là — le témoin précédent ne regarde
/// que `consigner_dans`, et un `consigner_l_acces` revenu à l'ancien `.is_ok()` le laisserait vert. Contrôles
/// positifs sur le même état et le même chemin : un nom porté par la table -> « compte local » ; un nom
/// absent -> « identifiant d'amorçage ». Noms propres à ce test : le débounce est un état du processus.
#[test]
fn iao_le_point_de_passage_d_auth_guard_n_invente_pas_la_provenance_d_une_table_refusee() {
    use crate::acces_observe::{consigner_l_acces, ORIGINE_NON_ETABLIE, PROVENANCE_NON_ETABLIE};
    let (st, _p) = sp_state("iao-point-de-passage");
    for nom in ["local-iao-pdp", "refuse-iao-pdp"] {
        st.db.lock().execute("INSERT INTO user(name,hash,role) VALUES(?1,'x','editor')", params![nom]).unwrap();
    }
    consigner_l_acces(&st, "default", "local-iao-pdp", "editor", "basic");
    consigner_l_acces(&st, "default", "amorce-iao-pdp", "admin", "basic");

    st.db.lock().authorizer(Some(|ctx: rusqlite::hooks::AuthContext<'_>| match ctx.action {
        rusqlite::hooks::AuthAction::Read { table_name, .. } if table_name == "user" => rusqlite::hooks::Authorization::Deny,
        _ => rusqlite::hooks::Authorization::Allow,
    }));
    let lecture_sous_refus =
        st.db.lock().query_row("SELECT 1 FROM user WHERE name='refuse-iao-pdp'", [], |r| r.get::<_, i64>(0));
    consigner_l_acces(&st, "default", "refuse-iao-pdp", "editor", "basic");
    st.db.lock().authorizer(None::<fn(rusqlite::hooks::AuthContext<'_>) -> rusqlite::hooks::Authorization>);
    assert!(lecture_sous_refus.is_err(), "instrument : la table des comptes doit être REFUSÉE ({lecture_sous_refus:?})");

    let lire = |nom: &str| -> Vec<(String, String)> {
        let conn = st.db.lock();
        let mut q = conn.prepare("SELECT provenance,origine_du_role FROM acces_observe WHERE nom=?1 ORDER BY provenance").unwrap();
        let v = q.query_map(params![nom], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        v
    };
    let paire = |p: &str, o: &str| vec![(p.to_string(), o.to_string())];
    assert_eq!(
        lire("refuse-iao-pdp"),
        paire(PROVENANCE_NON_ETABLIE, ORIGINE_NON_ETABLIE),
        "par le point de passage d'`auth_guard`, une table des comptes refusée inscrit la provenance NON ÉTABLIE — \
         jamais « identifiant d'amorçage »"
    );
    assert_eq!(lire("local-iao-pdp"), paire("compte local", "table des comptes"), "contrôle positif : compte porté");
    assert_eq!(
        lire("amorce-iao-pdp"),
        paire("identifiant d'amorçage", "configuration du démon (hors table des comptes)"),
        "contrôle positif : nom absent de la table lue"
    );
}

/// UN COMPTAGE RATÉ NE SAUTE PAS LE PLAFOND. L'autorisateur refuse tout `SELECT` tant qu'aucun `DELETE` n'a
/// été préparé : le `COUNT(*)` du plafond échoue, le `DELETE … NOT IN (SELECT …)` passe (son action
/// `DELETE` est autorisée avant sa sous-requête). Avant, le comptage raté valait 0 et la table restait au-dessus
/// de la borne ; désormais elle y revient, et ce qui cède est le plus ancien.
#[test]
fn iao_un_comptage_rate_ne_saute_pas_le_plafond() {
    use crate::acces_observe::appliquer_le_plafond;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::sync::atomic::{AtomicBool, Ordering};
    let conn = test_db();
    let surplus = 7i64;
    conn.execute(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < ?1) \
         INSERT INTO acces_observe(nom,provenance,role_effectif,origine_du_role,methode,premiere_vue,derniere_vue) \
         SELECT 'vue-plafond-iao-'||i,'annuaire externe','viewer','groupes de l''annuaire','sso',i,i FROM n",
        params![ACCES_OBSERVE_PLAFOND + surplus],
    )
    .unwrap();
    let compter = |c: &Connection| c.query_row("SELECT COUNT(*) FROM acces_observe", [], |r| r.get::<_, i64>(0));
    assert_eq!(compter(&conn).unwrap(), ACCES_OBSERVE_PLAFOND + surplus, "fixture : au-dessus de la borne");

    let delete_vu = std::sync::Arc::new(AtomicBool::new(false));
    let d = delete_vu.clone();
    conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
        AuthAction::Delete { .. } => {
            d.store(true, Ordering::SeqCst);
            Authorization::Allow
        }
        AuthAction::Select if !d.load(Ordering::SeqCst) => Authorization::Deny,
        _ => Authorization::Allow,
    }));
    let comptage_refuse = compter(&conn);
    appliquer_le_plafond(&conn);
    conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
    assert!(comptage_refuse.is_err(), "instrument : le comptage doit être REFUSÉ ({comptage_refuse:?})");

    assert_eq!(
        compter(&conn).unwrap(),
        ACCES_OBSERVE_PLAFOND,
        "un comptage raté ne doit pas faire sauter la borne : le DELETE idempotent se joue quand même"
    );
    let plus_ancienne: i64 = conn.query_row("SELECT MIN(derniere_vue) FROM acces_observe", [], |r| r.get(0)).unwrap();
    assert_eq!(plus_ancienne, surplus + 1, "ce qui cède : les {surplus} vues les plus anciennes");
    assert!(delete_vu.load(Ordering::SeqCst), "le DELETE a bien été préparé sous l'autorisateur");
}

/// LE MOT DE JOURNAL DE CHAQUE ÉTAPE RATÉE. C'est le seul endroit, hors tests, où préparation, pas du moteur
/// et ligne indécodable se distinguent : deux étapes qui porteraient le même mot rendraient le journal
/// incapable de dire où la lecture a cédé. La cause rendue est celle du moteur, inchangée.
#[test]
fn iao_les_trois_etapes_ratees_portent_trois_mots_de_journal_distincts() {
    use crate::acces_observe::InventaireNonLu;
    let e = || rusqlite::Error::InvalidQuery;
    let issues = [InventaireNonLu::Preparation(e()), InventaireNonLu::Pas(e()), InventaireNonLu::LigneIndecodable(e())];
    let mots: Vec<&str> = issues.iter().map(|i| i.etape()).collect();
    assert_eq!(mots, vec!["préparation", "pas du moteur", "ligne indécodable"], "trois étapes, trois mots");
    for i in &issues {
        assert!(matches!(i.cause(), rusqlite::Error::InvalidQuery), "la cause du moteur est rendue telle quelle ({i:?})");
    }
}
