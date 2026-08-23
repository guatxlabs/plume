// P11.5-c — QUI A ACCÈS, ET CE QU'UN ADMINISTRATEUR PEUT VRAIMENT.
//
// DEUX SYMPTÔMES RELEVÉS SUR LE MÊME COMPTE, ET UNE HYPOTHÈSE QUE LA MESURE A RÉFUTÉE. Le compte par
// lequel la console est administrée vient d'un annuaire externe (SSO d'en-têtes) : il n'apparaissait dans
// aucune liste de comptes, et il était annoncé administrateur sans pouvoir éditer les règles. L'hypothèse
// écrite était que les deux tenaient à la MÊME cause — un rôle résolu depuis une table où le compte
// n'existe pas. MESURÉ le 2026-08-23 sur le routeur RÉEL (toutes ses couches, dialogue HTTP à la main) :
//
//   (a) le rôle d'un compte SSO n'est résolu par AUCUNE table : `sso_role` mappe l'en-tête de groupes vers
//       `admin|editor|viewer` en mémoire, et `rbac_gate` court-circuite sur `role == "admin"`. Un compte
//       SSO administrateur reçoit donc `200` sur la création, la modification et la bascule d'une règle ;
//   (b) sur les 302 couples (route, méthode) DÉRIVÉS de la table de routage, il ne reçoit AUCUN refus
//       d'autorisation lié à sa provenance — les seuls 401/403 sont des refus nommés, indépendants du SSO
//       (jeton d'agent requis, purge par API désactivée, code TOTP invalide, panneau inexistant).
//
// L'HYPOTHÈSE EST DONC RÉFUTÉE : les deux symptômes n'ont pas la même cause. Ce qui reste, mesuré :
//
//   (1) l'inventaire des comptes était `SELECT … FROM user` — la table des comptes que le produit CRÉE.
//       Un compte d'annuaire externe n'y a jamais de ligne : il accédait sans figurer nulle part. C'est un
//       trou de CONTRÔLE, pas un défaut d'autorisation, et il est fermé ici par un inventaire de CEUX QUI
//       ACCÈDENT, alimenté au point de passage unique de l'authentification ;
//   (2) une modification de règle d'OVERLAY (`managed=1`, fichier `config.d` versionné) est ACCEPTÉE (200)
//       puis SILENCIEUSEMENT réimposée par le fichier au démarrage suivant (`load_overlay_rules`). Ni un
//       refus nommé — la SUPPRESSION, elle, rend 409 avec sa raison — ni un changement durable : un succès
//       qui se défait tout seul, ce qui se lit « l'administrateur ne peut pas éditer les règles ». La
//       réponse le DIT désormais, et la console le dit AVANT l'édition.
//
// CE QUE CES TESTS NE PROUVENT PAS, dit franchement : ils montent le routeur en local. Si la production
// refuse là où ceci passe, l'écart est le constat, et la mesure manquante est le code et le message que
// la console reçoit RÉELLEMENT — la défense CSRF des mutations SSO (contrôle same-origin sur
// `Origin`/`Referer`, cf. `sso_same_origin_ok`) est le seul autre refus que ce fichier sait produire, et
// il est épinglé ci-dessous avec son message pour qu'on le reconnaisse s'il tombe.

use crate::acces_observe::{
    doit_consigner, ecrire_vue, inventaire_des_acces, provenance_de, ACCES_OBSERVE_DEBOUNCE_S, ACCES_OBSERVE_PLAFOND,
};

/// Requête HTTP/1.1 avec en-têtes libres ET corps -> (statut, corps de réponse). Même parti-pris que
/// `router_probe`/`onb_post` : on parle le protocole à la main pour traverser TOUTES les couches du
/// routeur (rate-limit, hôte, ban, authentification, RBAC, CSRF) — un appel direct au handler sauterait
/// précisément ce qu'on mesure.
async fn acces_requete(
    addr: std::net::SocketAddr,
    methode: &str,
    chemin: &str,
    entetes: &[(&str, &str)],
    corps: &str,
) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut req = format!(
        "{methode} {chemin} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        corps.len()
    );
    for (k, v) in entetes {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(corps);
    let fut = async {
        let mut s = tokio::net::TcpStream::connect(addr).await.ok()?;
        s.write_all(req.as_bytes()).await.ok()?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.ok()?;
        let txt = String::from_utf8_lossy(&buf).into_owned();
        let code = txt.split_whitespace().nth(1)?.parse::<u16>().ok()?;
        Some((code, txt.split("\r\n\r\n").nth(1).unwrap_or("").to_string()))
    };
    tokio::time::timeout(Duration::from_secs(20), fut).await.ok().flatten().unwrap_or((0, String::new()))
}

/// Le corps d'une réponse, en JSON. Le dialogue brut peut être découpé en `chunks` : on ne garde que le
/// premier objet JSON complet (accolade équilibrée) — sinon un test lirait un corps chunké comme illisible
/// et rendrait vert en étant aveugle.
fn acces_json(corps: &str) -> Value {
    let debut = match corps.find('{') {
        Some(i) => i,
        None => return Value::Null,
    };
    let bytes = corps.as_bytes();
    let (mut profondeur, mut dans_chaine, mut echappe) = (0i32, false, false);
    for i in debut..bytes.len() {
        let c = bytes[i] as char;
        if dans_chaine {
            if echappe {
                echappe = false;
            } else if c == '\\' {
                echappe = true;
            } else if c == '"' {
                dans_chaine = false;
            }
            continue;
        }
        match c {
            '"' => dans_chaine = true,
            '{' => profondeur += 1,
            '}' => {
                profondeur -= 1;
                if profondeur == 0 {
                    return serde_json::from_str(&corps[debut..=i]).unwrap_or(Value::Null);
                }
            }
            _ => {}
        }
    }
    Value::Null
}

const ACCES_SECRET_DE_BORD: &str = "secret-de-bord-partage-p115c";

/// Les en-têtes d'un compte venu de l'annuaire externe, tels que le proxy d'authentification les pose :
/// le secret partagé (sans lequel le bloc SSO est inerte), le nom, les groupes. `Origin` est joint parce
/// qu'une mutation SSO exige un contrôle same-origin (`sso_same_origin_ok`) — un navigateur l'émet
/// toujours sur une mutation, et son ABSENCE est épinglée par son propre témoin.
fn acces_entetes_sso(nom: &str, groupes: &str) -> Vec<(&'static str, String)> {
    vec![
        ("x-plume-sso-secret", ACCES_SECRET_DE_BORD.to_string()),
        ("x-authentik-username", nom.to_string()),
        ("x-authentik-groups", groupes.to_string()),
        ("Origin", "http://127.0.0.1".to_string()),
    ]
}

fn acces_emprunt<'a>(v: &'a [(&'static str, String)]) -> Vec<(&'a str, &'a str)> {
    v.iter().map(|(k, val)| (*k, val.as_str())).collect()
}

/// Le compte LOCAL et l'identifiant d'AMORÇAGE de ce fichier. Des noms qui n'appartiennent qu'à lui : le
/// registre de débounce est PROCESS-global (et le tenant vaut `default` partout en mode 0), donc un nom
/// partagé avec une autre famille de tests lui volerait son écriture — le témoin rougirait pour une raison
/// qui n'est pas la sienne.
const ACCES_COMPTE_LOCAL: &str = "compte-local-p115c";
const ACCES_MDP_LOCAL: &str = "motdepasse-local-p115c";
const ACCES_AMORCE: &str = "amorce-p115c";
const ACCES_MDP_AMORCE: &str = "motdepasse-amorce-p115c";

fn acces_basic(nom: &str, mdp: &str) -> String {
    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{nom}:{mdp}")))
}

/// Fixture : le routeur réel, avec le secret d'en-tête POSÉ (sinon le chemin SSO est entièrement inerte),
/// deux règles de détection — un OVERLAY `config.d` (`managed=1`) et un contenu ad-hoc d'interface
/// (`managed=2`) —, un compte LOCAL propre au fichier et un identifiant d'AMORÇAGE propre au fichier.
async fn acces_routeur(tag: &str) -> (std::net::SocketAddr, crate::tmp_possede::TmpDb, Arc<Mutex<Connection>>) {
    let (mut st, dbp) = router_test_state(tag);
    st.sso_secret = Arc::new(ACCES_SECRET_DE_BORD.to_string());
    st.user = Arc::new(ACCES_AMORCE.to_string());
    st.pass_hash = Arc::new(hash_pw(ACCES_MDP_AMORCE).unwrap());
    let db = st.db.clone();
    {
        let c = db.lock();
        c.execute(
            "INSERT INTO user(name,hash,role) VALUES(?1,?2,'editor')",
            params![ACCES_COMPTE_LOCAL, hash_pw(ACCES_MDP_LOCAL).unwrap()],
        ).unwrap();
    }
    {
        let c = db.lock();
        c.execute(
            "INSERT INTO rule(id,name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,managed) \
             VALUES(11,'overlay-config-d',1,'search | stats count',1,'>',0,2,300,3600,1)",
            [],
        ).unwrap();
        c.execute(
            "INSERT INTO rule(id,name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s,managed) \
             VALUES(12,'adhoc-interface',1,'search | stats count',1,'>',0,2,300,3600,2)",
            [],
        ).unwrap();
    }
    let addr = router_serve(st).await;
    (addr, dbp, db)
}

/// L'entrée d'inventaire d'un nom, dans le tableau `acces` rendu par `GET /api/users`.
fn acces_entree(corps: &Value, nom: &str) -> Option<Value> {
    corps["acces"].as_array()?.iter().find(|a| a["nom"].as_str() == Some(nom)).cloned()
}

// ====================================================================================================
// TÉMOIN 1 — UN COMPTE SSO ADMINISTRATEUR APPARAÎT DANS L'INVENTAIRE, ET PEUT CE QUE SON RÔLE ANNONCE.
// ====================================================================================================

/// L'administrateur venu de l'annuaire externe : il est ANNONCÉ admin (`/api/me`), il FIGURE dans
/// l'inventaire des accès avec sa provenance, l'origine de son rôle et sa date de vue — alors qu'il n'a
/// AUCUNE ligne dans la table des comptes — et il PEUT créer et modifier une règle de détection.
///
/// MUTATION QUI DOIT FAIRE ROUGIR CE TÉMOIN : retirer l'appel `acces_observe::consigner` du point de
/// passage `auth_guard`, ou retirer `acces` de la réponse de `users_list`. Dans les deux cas, la source
/// SSO disparaît de l'inventaire et l'assertion « le compte SSO administrateur figure dans l'inventaire »
/// tombe — c'est exactement le trou de contrôle d'avant le correctif.
#[tokio::test]
async fn un_administrateur_venu_de_l_annuaire_figure_dans_l_inventaire_et_peut_editer_une_regle() {
    let (addr, dbp, _db) = acces_routeur("acces-admin-sso").await;
    let h = acces_entetes_sso("annuaire.admin", "plume-admin");
    let hr = acces_emprunt(&h);

    // (a) ANNONCE : le rôle est admin, la méthode est le SSO d'en-têtes.
    let (code, corps) = acces_requete(addr, "GET", "/api/me", &hr, "").await;
    assert_eq!(code, 200, "compte SSO du groupe admin : authentifié ({corps})");
    let me = acces_json(&corps);
    assert_eq!(me["role"].as_str(), Some("admin"), "rôle ANNONCÉ administrateur : {me}");
    assert_eq!(me["auth_method"].as_str(), Some("sso"), "authentifié par l'annuaire externe : {me}");

    // (b) INVENTAIRE : le compte figure, avec d'OÙ il vient, CE QU'IL PEUT, d'où ce rôle est DÉRIVÉ, et QUAND.
    let (code, corps) = acces_requete(addr, "GET", "/api/users", &hr, "").await;
    assert_eq!(code, 200, "inventaire lisible par l'administrateur ({corps})");
    let inv = acces_json(&corps);
    let locaux: Vec<&str> = inv["users"].as_array().expect("liste des comptes locaux")
        .iter().filter_map(|u| u["name"].as_str()).collect();
    assert!(
        !locaux.contains(&"annuaire.admin"),
        "le compte d'annuaire n'a AUCUNE ligne dans la table des comptes — c'est le fait mesuré, pas un \
         défaut : {locaux:?}"
    );
    let e = acces_entree(&inv, "annuaire.admin").unwrap_or_else(|| panic!(
        "TROU DE CONTRÔLE : un compte qui ADMINISTRE la console n'apparaît dans aucun inventaire. \
         Réponse de /api/users : {inv}"
    ));
    assert_eq!(e["provenance"].as_str(), Some("annuaire externe"), "d'OÙ il vient : {e}");
    assert_eq!(e["role_effectif"].as_str(), Some("admin"), "CE QU'IL PEUT : {e}");
    assert_eq!(e["origine_du_role"].as_str(), Some("groupes de l'annuaire"), "d'où le rôle est DÉRIVÉ : {e}");
    assert_eq!(e["methode"].as_str(), Some("sso"), "méthode d'authentification : {e}");
    assert!(e["derniere_vue"].as_i64().unwrap_or(0) > 0, "QUAND il a été vu : {e}");
    assert!(
        e["premiere_vue"].as_i64().unwrap_or(0) <= e["derniere_vue"].as_i64().unwrap_or(0),
        "la première vue ne peut pas être postérieure à la dernière : {e}"
    );

    // (c) IL PEUT CE QUE SON RÔLE ANNONCE : créer une règle, puis modifier SON contenu ad-hoc.
    let corps_regle = r#"{"name":"regle-de-l-annuaire","query":"search | stats count","is_soql":true,"op":">","threshold":0,"severity":2,"interval_s":300,"window_s":3600,"enabled":true}"#;
    let (code, corps) = acces_requete(addr, "POST", "/api/rules", &hr, corps_regle).await;
    assert_eq!(code, 200, "un administrateur SSO CRÉE une règle : {corps}");
    let (code, corps) = acces_requete(addr, "POST", "/api/rules/12", &hr, r#"{"threshold":5}"#).await;
    assert_eq!(code, 200, "un administrateur SSO MODIFIE une règle ad-hoc : {corps}");
    let j = acces_json(&corps);
    assert_eq!(j["managed"].as_i64(), Some(2), "contenu ad-hoc : {j}");
    assert!(
        j.get("avertissement").is_none(),
        "un contenu ad-hoc est durable : aucun avertissement à donner ({j})"
    );

    ff_rm(&dbp);
}

// ====================================================================================================
// TÉMOIN 2 — UN COMPTE SSO NON-ADMINISTRATEUR APPARAÎT AUSSI, ET SON REFUS PORTE SA RAISON.
// ====================================================================================================

/// Le pendant NÉGATIF, sans lequel le témoin 1 ne prouverait que « l'inventaire n'est pas vide » : un
/// compte SSO sans groupe privilégié figure lui aussi dans l'inventaire, avec le rôle qu'il a RÉELLEMENT,
/// et sa mutation est refusée AVEC un motif lisible (jamais un refus muet, jamais un 200 sans effet).
#[tokio::test]
async fn un_compte_d_annuaire_sans_privilege_figure_aussi_et_son_refus_porte_sa_raison() {
    let (addr, dbp, _db) = acces_routeur("acces-viewer-sso").await;
    let hv = acces_entetes_sso("annuaire.lecteur", "groupe-sans-privilege");
    let hvr = acces_emprunt(&hv);

    let (code, corps) = acces_requete(addr, "GET", "/api/me", &hvr, "").await;
    assert_eq!(code, 200, "compte SSO sans privilège : authentifié tout de même ({corps})");
    assert_eq!(acces_json(&corps)["role"].as_str(), Some("viewer"), "groupe inconnu -> lecture seule");

    // LE REFUS PORTE SA RAISON — code ET message.
    let (code, corps) = acces_requete(addr, "POST", "/api/rules", &hvr, r#"{"name":"x","query":"search | stats count"}"#).await;
    assert_eq!(code, 403, "un lecteur ne crée pas de règle : {corps}");
    assert!(
        corps.contains("lecture seule"),
        "REFUS MUET : le refus doit NOMMER sa raison, pas se contenter d'un code. Corps reçu : {corps}"
    );

    // ... ET IL FIGURE À L'INVENTAIRE, lu par un administrateur (la route est réservée à l'administrateur).
    let ha = acces_entetes_sso("annuaire.controleur", "plume-admin");
    let (code, corps) = acces_requete(addr, "GET", "/api/users", &acces_emprunt(&ha), "").await;
    assert_eq!(code, 200, "inventaire lisible ({corps})");
    let inv = acces_json(&corps);
    let e = acces_entree(&inv, "annuaire.lecteur").unwrap_or_else(|| panic!(
        "un compte SANS privilège accède aussi : « qui a accès » ne se limite pas aux administrateurs. {inv}"
    ));
    assert_eq!(e["provenance"].as_str(), Some("annuaire externe"), "provenance : {e}");
    assert_eq!(e["role_effectif"].as_str(), Some("viewer"), "le rôle inventorié est le rôle RÉEL : {e}");

    ff_rm(&dbp);
}

// ====================================================================================================
// TÉMOIN 3 — UN COMPTE LOCAL RESTE INCHANGÉ (et se distingue d'un compte d'annuaire).
// ====================================================================================================

/// Ce qui existait ne bouge pas : un compte de la table des comptes est toujours rendu dans `users` avec
/// ses colonnes d'origine (id, nom, rôle, création) — et il apparaît EN PLUS dans l'inventaire des accès,
/// où sa provenance le distingue d'un compte d'annuaire. Un identifiant d'AMORÇAGE (celui de la
/// configuration, sans ligne dans la table) est nommé pour ce qu'il est, jamais confondu avec un compte local.
#[tokio::test]
async fn un_compte_local_reste_inchange_et_sa_provenance_le_distingue_de_l_annuaire() {
    let (addr, dbp, _db) = acces_routeur("acces-local").await;
    let local = acces_basic(ACCES_COMPTE_LOCAL, ACCES_MDP_LOCAL);
    let (code, _) = acces_requete(addr, "GET", "/api/me", &[("Authorization", local.as_str())], "").await;
    assert_eq!(code, 200, "compte local authentifié par mot de passe applicatif");

    // L'identifiant d'AMORÇAGE (posé par la configuration : aucune ligne dans la table des comptes).
    let amorce = acces_basic(ACCES_AMORCE, ACCES_MDP_AMORCE);
    let (code, _) = acces_requete(addr, "GET", "/api/me", &[("Authorization", amorce.as_str())], "").await;
    assert_eq!(code, 200, "identifiant d'amorçage authentifié");

    let (code, corps) = acces_requete(addr, "GET", "/api/users", &[("Authorization", amorce.as_str())], "").await;
    assert_eq!(code, 200, "inventaire lisible ({corps})");
    let inv = acces_json(&corps);

    // (a) `users` INCHANGÉ : les colonnes d'origine, pour le compte local, telles qu'elles étaient.
    let u = inv["users"].as_array().expect("liste des comptes locaux")
        .iter().find(|u| u["name"].as_str() == Some(ACCES_COMPTE_LOCAL)).cloned()
        .expect("le compte local est toujours rendu dans `users`");
    assert_eq!(u["role"].as_str(), Some("editor"), "rôle du compte local inchangé : {u}");
    assert!(u["id"].as_i64().is_some() && u["created"].as_i64().is_some(), "colonnes d'origine rendues : {u}");

    // (b) le compte local est AUSSI à l'inventaire, avec la provenance qui le distingue.
    let e = acces_entree(&inv, ACCES_COMPTE_LOCAL).expect("le compte local figure aussi à l'inventaire des accès");
    assert_eq!(e["provenance"].as_str(), Some("compte local"), "provenance d'un compte de la table : {e}");
    assert_eq!(e["origine_du_role"].as_str(), Some("table des comptes"), "origine du rôle : {e}");

    // (c) l'identifiant d'AMORÇAGE n'est pas maquillé en compte local : il n'est gérable NULLE PART ici.
    let a = acces_entree(&inv, ACCES_AMORCE).expect("l'identifiant d'amorçage figure à l'inventaire");
    assert_eq!(a["provenance"].as_str(), Some("identifiant d'amorçage"), "un identifiant sans ligne n'est pas un compte local : {a}");

    ff_rm(&dbp);
}

// ====================================================================================================
// TÉMOIN 4 — CE QU'UNE MODIFICATION D'OVERLAY DIT D'ELLE-MÊME (« la console dit pourquoi non »).
// ====================================================================================================

/// Le second symptôme, mesuré et nommé. Modifier une règle d'OVERLAY est ACCEPTÉ, mais le fichier
/// versionné réimpose son contenu au démarrage suivant : la réponse doit le DIRE. La SUPPRESSION, elle,
/// est refusée (409) et nommait déjà sa raison — on l'épingle pour qu'elle ne devienne pas muette.
/// Le contenu ad-hoc, lui, est durable : aucun avertissement (sinon la phrase deviendrait du bruit).
#[tokio::test]
async fn modifier_une_regle_d_overlay_est_accepte_mais_le_dit_et_la_supprimer_est_refuse_avec_sa_raison() {
    let (addr, dbp, _db) = acces_routeur("acces-overlay").await;
    let h = acces_entetes_sso("annuaire.editeur", "plume-admin");
    let hr = acces_emprunt(&h);

    // (a) MODIFICATION d'un overlay : acceptée, ET la réponse dit ce qu'il en adviendra.
    let (code, corps) = acces_requete(addr, "POST", "/api/rules/11", &hr, r#"{"threshold":42}"#).await;
    assert_eq!(code, 200, "modifier une règle d'overlay reste possible : {corps}");
    let j = acces_json(&corps);
    assert_eq!(j["managed"].as_i64(), Some(1), "la réponse dit de QUEL contenu il s'agit : {j}");
    let av = j["avertissement"].as_str().unwrap_or("");
    assert!(
        av.contains("config.d") && av.contains("démarrage"),
        "SUCCÈS QUI SE DÉFAIT TOUT SEUL : une modification d'overlay est réimposée par son fichier au \
         prochain démarrage ; la réponse doit le NOMMER. Reçu : {j}"
    );

    // (b) le contenu ad-hoc est DURABLE : pas d'avertissement (le témoin négatif de la phrase).
    let (_, corps) = acces_requete(addr, "POST", "/api/rules/12", &hr, r#"{"threshold":7}"#).await;
    assert!(
        acces_json(&corps).get("avertissement").is_none(),
        "un avertissement sur du contenu durable serait du bruit : {corps}"
    );

    // (c) SUPPRESSION d'un overlay : refusée, avec sa raison (comportement épinglé, pas modifié).
    let (code, corps) = acces_requete(addr, "DELETE", "/api/rules/11", &hr, "").await;
    assert_eq!(code, 409, "supprimer un overlay reste refusé : {corps}");
    assert!(corps.contains("overlay"), "le refus NOMME sa raison : {corps}");

    // (d) et la SUPPRESSION d'un contenu ad-hoc passe (sinon (c) ne prouverait qu'une route cassée).
    let (code, corps) = acces_requete(addr, "DELETE", "/api/rules/12", &hr, "").await;
    assert_eq!(code, 200, "un contenu ad-hoc se supprime : {corps}");

    ff_rm(&dbp);
}

// ====================================================================================================
// TÉMOIN 5 — LE SEUL AUTRE REFUS QU'UN ADMINISTRATEUR SSO PEUT RENCONTRER, ÉPINGLÉ AVEC SON MESSAGE.
// ====================================================================================================

/// Une session SSO n'a pas de jeton à double-soumettre : la défense CSRF de ses mutations est un contrôle
/// SAME-ORIGIN (`sso_same_origin_ok`), fail-closed. Sans `Origin` ni `Referer`, TOUTE mutation d'un
/// administrateur SSO est refusée. Épinglé ici parce que c'est le refus le plus facile à confondre avec
/// « l'administrateur ne peut pas éditer les règles » : si la production échoue là où les témoins ci-dessus
/// passent, c'est CE message qu'il faut chercher dans la réponse.
#[tokio::test]
async fn sans_origine_toute_mutation_d_un_administrateur_sso_est_refusee_et_le_refus_se_nomme() {
    let (addr, dbp, _db) = acces_routeur("acces-csrf-sso").await;
    let h = acces_entetes_sso("annuaire.sans-origine", "plume-admin");
    let sans_origine: Vec<(&str, &str)> =
        acces_emprunt(&h).into_iter().filter(|(k, _)| *k != "Origin").collect();

    let (code, corps) = acces_requete(addr, "POST", "/api/rules", &sans_origine, r#"{"name":"x","query":"search | stats count"}"#).await;
    assert_eq!(code, 403, "mutation SSO sans origine : refusée (fail-closed) — {corps}");
    assert!(corps.contains("CSRF"), "le refus se NOMME : {corps}");

    // La LECTURE, elle, passe sans origine (sinon le témoin ne mesurerait qu'une authentification cassée).
    let (code, _) = acces_requete(addr, "GET", "/api/me", &sans_origine, "").await;
    assert_eq!(code, 200, "une lecture SSO n'exige aucune origine");

    ff_rm(&dbp);
}

// ====================================================================================================
// GARDE DÉRIVÉE — TOUTE MÉTHODE D'AUTHENTIFICATION A UNE PROVENANCE NOMMÉE.
// ====================================================================================================

/// L'inventaire ne vaut que s'il sait NOMMER d'où vient chaque accès. Les méthodes ne sont pas énumérées
/// ici : elles sont LUES dans la source du point de passage (`auth_guard`/`resolve_identity`), à l'unique
/// endroit où elles sont posées (`auth_method = "…"`). Une méthode ajoutée demain — un nouveau seam de
/// jeton, une fédération de plus — entre dans le périmètre sans que personne ait à l'inscrire, et tombe
/// rouge si sa provenance n'est pas nommée.
///
/// L'INSTRUMENT SE VALIDE : il exige d'avoir retrouvé les méthodes qu'on SAIT présentes (`sso`, `basic`,
/// `cookie`, `bearer`) et un plancher de méthodes — un motif qui ne reconnaîtrait plus rien rendrait vert
/// en étant aveugle.
#[test]
fn toute_methode_d_authentification_a_une_provenance_nommee() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("auth.rs"),
    ).expect("la source du point de passage d'authentification est lisible");
    let mut methodes: Vec<String> = Vec::new();
    for ligne in src.lines() {
        let code = ligne.split("//").next().unwrap_or(""); // jamais une affectation en commentaire
        let mut reste = code;
        while let Some((_, apres)) = reste.split_once("auth_method = \"") {
            match apres.split_once('"') {
                Some((m, suite)) => {
                    if !m.is_empty() && !methodes.contains(&m.to_string()) {
                        methodes.push(m.to_string());
                    }
                    reste = suite;
                }
                None => break,
            }
        }
    }
    // (0) VALIDATION DE L'INSTRUMENT — sans quoi un motif cassé rendrait vert.
    for connue in ["sso", "basic", "cookie", "bearer"] {
        assert!(
            methodes.iter().any(|m| m == connue),
            "INSTRUMENT MUET : la méthode `{connue}`, qu'on SAIT posée par auth.rs, n'a pas été retrouvée. \
             Méthodes lues : {methodes:?}"
        );
    }
    assert!(methodes.len() >= 6, "plancher de méthodes lues dans la source : {methodes:?}");

    // (1) L'ÉTIQUETTE DE REPLI, dérivée en interrogeant la fonction avec une méthode qui n'existe pas —
    //     jamais recopiée : une garde qui répéterait la chaîne resterait verte si la chaîne changeait.
    let repli = provenance_de("methode-qui-n-existe-pas", false).0;
    // Les méthodes à MOT DE PASSE (`basic`/`cookie`) tombent LÉGITIMEMENT sur ce repli quand le nom n'a pas
    // de ligne : c'est la réponse juste (identifiant d'amorçage), pas un trou. Toute AUTRE méthode qui y
    // tombe est une provenance qu'on n'a pas nommée.
    let sans_nom: Vec<&String> = methodes
        .iter()
        .filter(|m| !matches!(m.as_str(), "basic" | "cookie"))
        .filter(|m| provenance_de(m, false).0 == repli)
        .collect();
    assert!(
        sans_nom.is_empty(),
        "MÉTHODE D'AUTHENTIFICATION SANS PROVENANCE NOMMÉE : {sans_nom:?}. Un accès par cette voie \
         apparaîtrait à l'inventaire sous l'étiquette de repli — donc « qui a accès » mentirait sur \
         d'où il vient. Nommez-la dans `acces_observe::provenance_de`."
    );
}

// ====================================================================================================
// LES PIÈCES PURES — provenance, avertissement, débounce, plafond, confidentialité.
// ====================================================================================================

/// La provenance est DÉRIVÉE de deux faits (la méthode, l'existence d'une ligne locale) et jamais devinée.
/// Le cas qui compte : un mot de passe applicatif authentifie AUSSI l'identifiant de configuration, qui
/// n'a pas de ligne — le confondre avec un compte local mentirait sur « d'où il vient ».
#[test]
fn la_provenance_distingue_l_annuaire_le_compte_local_et_l_identifiant_d_amorcage() {
    assert_eq!(provenance_de("sso", false), ("annuaire externe", "groupes de l'annuaire"));
    assert_eq!(provenance_de("sso", true).0, "annuaire externe", "un homonyme local ne change pas la provenance SSO");
    assert_eq!(provenance_de("basic", true).0, "compte local");
    assert_eq!(provenance_de("basic", false).0, "identifiant d'amorçage");
    assert_eq!(provenance_de("cookie", true).0, "compte local");
    assert_eq!(provenance_de("bearer", false).0, "jeton d'agent");
    assert_eq!(provenance_de("hec", false).0, "jeton d'agent");
    assert_eq!(provenance_de("datasource", false).0, "jeton de source de données");
    assert_eq!(provenance_de("client", false).0, "jeton client");
    assert_eq!(provenance_de("demo", false).0, "démonstration publique");
}

/// L'avertissement d'overlay ne se pose QUE sur `managed=1`. Un builtin (0) ou un ad-hoc (2) est durable :
/// une phrase posée partout serait ignorée partout.
#[test]
fn l_avertissement_d_overlay_ne_se_pose_que_sur_un_contenu_gouverne_par_un_fichier() {
    assert!(avertissement_overlay("Cette règle", "rule", 0).is_none(), "builtin : modification durable");
    assert!(avertissement_overlay("Cette règle", "rule", 2).is_none(), "ad-hoc : modification durable");
    let a = avertissement_overlay("Cette règle", "rule", 1).expect("overlay : la phrase existe");
    assert!(a.starts_with("Cette règle"), "la phrase s'accorde à l'objet nommé : {a}");
    assert!(a.contains("config.d") && a.contains("démarrage"), "elle nomme la cause ET le moment : {a}");
    assert!(
        avertissement_overlay("Ce playbook", "playbook", 1).expect("overlay").starts_with("Ce playbook"),
        "la même phrase sert les trois contenus de détection, accordée par l'appelant"
    );
}

/// LE COÛT — une identité qui martèle la console n'écrit pas à chaque requête. Le débounce laisse passer
/// la première vue, refuse dans la fenêtre, et rouvre au-delà.
#[test]
fn l_ecriture_de_l_inventaire_est_debouncee_par_identite() {
    let t0 = 1_700_000_000i64;
    let nom = "temoin-debounce-p115c";
    assert!(doit_consigner("default", nom, "annuaire externe", t0), "première vue : écrite");
    assert!(!doit_consigner("default", nom, "annuaire externe", t0 + 1), "dans la fenêtre : aucune écriture");
    assert!(
        !doit_consigner("default", nom, "annuaire externe", t0 + ACCES_OBSERVE_DEBOUNCE_S - 1),
        "juste avant la fin de fenêtre : toujours rien"
    );
    assert!(
        doit_consigner("default", nom, "annuaire externe", t0 + ACCES_OBSERVE_DEBOUNCE_S),
        "fenêtre écoulée : réécrite"
    );
    assert!(
        doit_consigner("default", nom, "compte local", t0 + ACCES_OBSERVE_DEBOUNCE_S),
        "une AUTRE provenance du même nom est une autre entrée : elle a sa propre fenêtre"
    );
    // L'inventaire vit dans la base DU TENANT : un compte vu sur un tenant n'a rien écrit sur un autre.
    assert!(
        doit_consigner("client-b", nom, "annuaire externe", t0 + 1),
        "même compte, AUTRE tenant : l'écriture est due (sa base ne l'a jamais vu)"
    );
}

/// LA BORNE — la table ne peut pas grossir sans fin, et ce qui cède est la vue la plus ANCIENNE. Mesuré en
/// écrivant le plafond plus dix : le compte retombe AU plafond, et la plus récente est toujours là.
#[test]
fn l_inventaire_est_plafonne_et_ce_qui_cede_est_la_vue_la_plus_ancienne() {
    let conn = test_db();
    let base = 1_700_000_000i64;
    for i in 0..(ACCES_OBSERVE_PLAFOND + 10) {
        ecrire_vue(&conn, &format!("compte-{i}"), "annuaire externe", "viewer", "groupes de l'annuaire", "sso", base + i);
    }
    let n: i64 = conn.query_row("SELECT COUNT(*) FROM acces_observe", [], |r| r.get(0)).unwrap();
    assert_eq!(n, ACCES_OBSERVE_PLAFOND, "la table est bornée au plafond, pas au flux");
    let recente: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM acces_observe WHERE nom=?1",
            params![format!("compte-{}", ACCES_OBSERVE_PLAFOND + 9)],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(recente, 1, "la vue la PLUS RÉCENTE survit");
    let ancienne: i64 = conn
        .query_row("SELECT COUNT(*) FROM acces_observe WHERE nom='compte-0'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(ancienne, 0, "la vue la plus ANCIENNE a cédé");

    // La première vue n'est JAMAIS écrasée par une vue suivante (sinon « depuis quand » serait faux).
    // Sur une base NEUVE : au plafond, c'est la vue la plus ancienne qui cède — la ré-écrire dans la base
    // saturée ci-dessus mesurerait l'éviction, pas la conservation.
    let conn = test_db();
    ecrire_vue(&conn, "revu", "annuaire externe", "viewer", "groupes de l'annuaire", "sso", base);
    ecrire_vue(&conn, "revu", "annuaire externe", "admin", "groupes de l'annuaire", "sso", base + 999);
    let (p, d, r): (i64, i64, String) = conn
        .query_row(
            "SELECT premiere_vue,derniere_vue,role_effectif FROM acces_observe WHERE nom='revu'",
            [],
            |x| Ok((x.get(0)?, x.get(1)?, x.get(2)?)),
        )
        .unwrap();
    assert_eq!(p, base, "la PREMIÈRE vue ne bouge plus");
    assert_eq!(d, base + 999, "la DERNIÈRE vue suit");
    assert_eq!(r, "admin", "le rôle inventorié est celui du DERNIER accès");

    // Un nom démesuré est TRONQUÉ, jamais REJETÉ : un compte qui accède doit apparaître, et l'octet écrit
    // reste borné. Le rejeter rouvrirait le trou de contrôle pour le seul cas d'un nom long.
    let tres_long = "n".repeat(crate::acces_observe::ACCES_OBSERVE_NOM_MAX * 3);
    ecrire_vue(&conn, &tres_long, "annuaire externe", "viewer", "groupes de l'annuaire", "sso", base);
    let borne: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM acces_observe WHERE length(nom)=?1",
            params![crate::acces_observe::ACCES_OBSERVE_NOM_MAX as i64],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(borne, 1, "nom démesuré : tronqué à la borne, et présent (jamais rejeté)");
}

/// CONFIDENTIALITÉ — dérivée, pas déclarée : on DEMANDE ses colonnes à la table et on refuse tout nom qui
/// désignerait un secret. Une colonne ajoutée demain pour « enrichir » l'inventaire (les groupes bruts de
/// l'annuaire, une empreinte, un jeton) rougit ici. La liste des racines refusées est le critère, pas une
/// liste de colonnes tolérées : une colonne innocente de plus n'a rien à déclarer.
#[test]
fn l_inventaire_ne_porte_aucune_colonne_qui_designe_un_secret() {
    let conn = test_db();
    let mut stmt = conn.prepare("SELECT name FROM pragma_table_xinfo('acces_observe')").unwrap();
    let colonnes: Vec<String> = stmt.query_map([], |r| r.get::<_, String>(0)).unwrap().flatten().collect();
    assert!(
        colonnes.len() >= 7,
        "INSTRUMENT MUET : la table `acces_observe` n'a pas été lue (colonnes : {colonnes:?})"
    );
    const RACINES_REFUSEES: &[&str] = &[
        "hash", "token", "jeton", "secret", "password", "mdp", "cle", "key", "groupe", "group", "cookie", "ip",
    ];
    let fautives: Vec<&String> = colonnes
        .iter()
        .filter(|c| {
            let b = c.to_ascii_lowercase();
            RACINES_REFUSEES.iter().any(|r| b.contains(r))
        })
        .collect();
    assert!(
        fautives.is_empty(),
        "L'INVENTAIRE EXPOSERAIT PLUS QUE NÉCESSAIRE : colonne(s) {fautives:?}. Cette table est servie à \
         l'administrateur pour répondre à « qui a accès » — elle n'a besoin d'aucun secret, et la valeur \
         brute des groupes d'un annuaire nommerait l'organisation interne du client."
    );
    // Et le témoin POSITIF : les colonnes attendues sont bien là (sinon le refus ci-dessus ne prouve rien).
    for attendue in ["nom", "provenance", "role_effectif", "origine_du_role", "methode", "premiere_vue", "derniere_vue"] {
        assert!(colonnes.iter().any(|c| c == attendue), "colonne `{attendue}` attendue parmi {colonnes:?}");
    }
}

/// L'inventaire d'une base qui n'a PAS la table (binaire plus récent ouvrant une base non migrée, ou une
/// migration à venir) rend une liste VIDE — jamais une erreur qui masquerait l'inventaire local. C'est la
/// branche d'échec du chemin de lecture, et elle ne doit pas être muette pour l'appelant : elle doit être
/// INOFFENSIVE.
#[test]
fn une_base_sans_la_table_rend_un_inventaire_vide_et_jamais_une_erreur() {
    let conn = Connection::open_in_memory().unwrap();
    assert!(inventaire_des_acces(&conn).is_empty(), "table absente -> liste vide, la console rend le reste");
}
