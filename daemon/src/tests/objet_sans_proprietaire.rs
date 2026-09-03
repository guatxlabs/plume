// =====================================================================================
// `P11.20-n` — UN OBJET SANS PROPRIÉTAIRE N'EST PAS À TOUT LE MONDE.
//
// LE DÉFAUT MESURÉ (2026-09-03, `9c2ae23`). Douze sites de production faisaient d'une colonne
// `owner` VIDE une CLAUSE D'OCTROI — `owner.is_empty()` en Rust, `COALESCE(owner,'')=''` en SQL —
// c'est-à-dire « cet objet appartient à quiconque le lit ». Le plus grave n'était pas la LISTE (un
// objet semé est déjà `shared`, donc déjà listé) mais l'AUTORITÉ : `PorteeLecture::du_dashboard`
// rendait `Proprietaire` à TOUT LE MONDE sur un dashboard semé, si bien qu'un panneau `private`
// posé là était servi à tous les comptes — par `dash_get`, par `panel_data`, et FIGÉ dans un
// snapshot partageable par jeton.
//
// POURQUOI IL A SURVÉCU : AUCUN TÉMOIN NE JOUAIT DEUX IDENTITÉS. Toute la suite `panneau_bibliotheque`
// éprouve `editor` contre `admin` sur des objets APPARTENANT à quelqu'un ; personne n'avait écrit
// « alice pose, bob lit » sur un objet que PERSONNE ne possède. C'est le couple qui manquait, et
// c'est lui qui ferme la clé.
//
// LA VOIE TRANCHÉE (deux étaient ouvertes ; celle-ci l'est PAR LA MESURE de
// `un_objet_seme_declare_son_etat_commun`). Les objets semés portent DÉJÀ un état commun explicite :
// `visibility='shared'`, colonne `NOT NULL DEFAULT 'shared'` au schéma, écrite par les semeurs. Le
// bien commun était donc déjà DÉCLARÉ, et la clause d'octroi ne lui apportait rien. On ne donne pas
// de propriétaire aux objets semés (ce serait attribuer un bien commun à un compte) : on retire à
// « sans propriétaire » le pouvoir qu'il n'aurait jamais dû avoir. AUCUN FRANCHISSEMENT DE SCHÉMA —
// la colonne qui nomme l'état commun existe déjà.
//
// LA PRESCRIPTION QU'ON N'A PAS SUIVIE. « Publiques ou à nous », appliquée telle quelle, RELÂCHERAIT
// le démon : `saved_query` ne rend aujourd'hui QUE ce qui nous appartient (aucun `shared` là-bas), et
// il n'en gagne pas ici.
//
// LE PRIX ASSUMÉ. Un panneau `private` posé sur un dashboard SANS propriétaire n'est plus servi à
// PERSONNE — pas même à celui qui l'a écrit. C'est cohérent : « privé » veut dire « au propriétaire
// seul », et il n'y a pas de propriétaire. Le témoin l'ÉNONCE au lieu de le subir.
// =====================================================================================

fn sp_state(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
    let path = ff_tmp_path(tag);
    {
        let conn = open_db(&path).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture P11.20-n : migrations complètes");
        for (n, r) in [("alice", "editor"), ("bob", "editor"), ("adm", "admin")] {
            conn.execute("INSERT INTO user(name,hash,role) VALUES(?1,?2,?3)", params![n, hash_pw("motdepasse12345").unwrap(), r]).unwrap();
        }
    }
    let st = ds_file_state(&path);
    (st, path)
}

fn sp_au(name: &str, role: &str) -> AuthUser {
    AuthUser {
        name: name.into(), role: role.into(), tenant: "default".into(), is_superadmin: false,
        method: "basic".into(), csrf: String::new(), env: None,
    }
}

/// L'OBJET SEMÉ, écrit par le SEMEUR RÉEL de production — jamais par une fixture qui pourrait dériver
/// de lui en silence. Rend son id et prouve au passage la forme qui fait le défaut : `owner` VIDE.
fn sp_dashboard_seme(st: &AppState) -> i64 {
    let conn = st.db.lock();
    seed_default_dashboard(&conn);
    let (did, owner, vis): (i64, String, String) = conn
        .query_row(
            "SELECT id,COALESCE(owner,''),COALESCE(visibility,'shared') FROM dashboard ORDER BY id LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .expect("le semeur a bien posé un dashboard");
    assert_eq!(owner, "", "fixture : le dashboard semé est SANS propriétaire (c'est tout le sujet)");
    assert_eq!(vis, "shared", "fixture : et son état commun est DÉCLARÉ");
    did
}

async fn sp_panneau(st: &AppState, au: &AuthUser, did: i64, titre: &str, visibilite: &str) -> (u16, i64) {
    let (c, v) = pb_json(
        panel_create(
            State(st.clone()),
            Extension(au.clone()),
            Json(json!({
                "dashboard_id": did, "title": titre, "query": "search source=web | table message",
                "is_soql": true, "viz": "table", "visibility": visibilite
            })),
        )
        .await,
    )
    .await;
    (c, v.get("id").and_then(|x| x.as_i64()).unwrap_or(0))
}

/// Les ids de panneaux que `dash_get` SERT à ce compte.
async fn sp_panneaux_servis(st: &AppState, au: &AuthUser, did: i64) -> (u16, Vec<i64>, bool) {
    let (c, v) = pb_json(dash_get(State(st.clone()), Extension(au.clone()), Path(did)).await).await;
    let ids = v
        .get("panels")
        .and_then(|p| p.as_array())
        .map(|a| a.iter().filter_map(|p| p.get("id").and_then(|x| x.as_i64())).collect())
        .unwrap_or_default();
    let editable = v.get("editable").and_then(|x| x.as_bool()).unwrap_or(false);
    (c, ids, editable)
}

// -------------------------------------------------------------------------------------
// (1) LA MESURE QUI TRANCHE — l'état commun est DÉJÀ déclaré, la clause d'octroi n'y servait à rien.
// -------------------------------------------------------------------------------------
/// Deux voies étaient ouvertes : donner un propriétaire aux objets semés, ou restreindre la clause à
/// ce qui est explicitement déclaré commun. CE TEST TRANCHE : sur une base fraîche peuplée par les
/// SEMEURS RÉELS, il existe bien des objets sans propriétaire (sinon la mesure serait vide), et
/// TOUS portent `visibility='shared'`. Le bien commun était donc déjà NOMMÉ par une colonne, et
/// `owner=''` ne pouvait rien lui apporter : la clause n'octroyait que de l'autorité indue.
/// Corollaire opérationnel : aucun franchissement de schéma n'est nécessaire.
#[test]
fn un_objet_seme_declare_son_etat_commun() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
    assert!(migrate(&conn), "migrations complètes");
    // LES SEMEURS RÉELS — pas une reconstitution.
    seed_default_dashboard(&conn);
    seed_security_dashboard(&conn);

    let compte = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap_or(-1) };
    // (a) LA POPULATION EXISTE — sans ce contrôle, (b) serait vrai par vacuité.
    let sans_proprio = compte("SELECT COUNT(*) FROM dashboard WHERE COALESCE(owner,'')=''");
    assert!(sans_proprio > 0, "la mesure serait vide : aucun dashboard semé sans propriétaire");
    let vues_sans_proprio = compte("SELECT COUNT(*) FROM view WHERE COALESCE(owner,'')=''");
    assert!(vues_sans_proprio > 0, "la mesure serait vide : aucune vue semée sans propriétaire");

    // (b) ET TOUS DÉCLARENT LEUR ÉTAT COMMUN. Un seul objet sans propriétaire ET non déclaré
    // `shared` rendrait la voie choisie insuffisante : il faudrait alors lui ATTRIBUER un
    // propriétaire (l'autre voie). Ce chiffre-là décide, et il vaut 0.
    for (table, quoi) in [("dashboard", "dashboard"), ("view", "vue"), ("playlist", "playlist"), ("library_panel", "définition de bibliothèque")] {
        let orphelins = compte(&format!(
            "SELECT COUNT(*) FROM {table} WHERE COALESCE(owner,'')='' AND COALESCE(visibility,'shared')<>'shared'"
        ));
        assert_eq!(orphelins, 0, "{quoi} : sans propriétaire ET sans état commun déclaré — la voie « la colonne `visibility` suffit » serait fausse");
    }

    // (c) ET AUCUN CHEMIN D'ÉCRITURE NE FABRIQUE UN ORPHELIN : les quatre créateurs posent `au.name`.
    // Prouvé par la SOURCE (une régression y serait invisible à toute fixture de base).
    let src = std::fs::read_to_string(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/handlers/dashboards.rs")).unwrap();
    assert!(src.contains("INSERT INTO dashboard(name,created,owner,visibility,view_id)"), "dash_create pose un propriétaire");
    assert!(src.contains("INSERT INTO view(name,owner,visibility)"), "view_create pose un propriétaire");
}

// -------------------------------------------------------------------------------------
// (2) LE TÉMOIN À DEUX IDENTITÉS — celui qui manquait, avec son CONTRÔLE POSITIF.
// -------------------------------------------------------------------------------------
/// DEUX COMPTES DISTINCTS. `alice` écrit un panneau PRIVÉ sur le dashboard SEMÉ (que personne ne
/// possède) ; `bob` ne doit pas le voir. Puis le CONTRÔLE POSITIF, sans lequel le correctif pourrait
/// n'être qu'un aveuglement général : sur le dashboard D'ALICE, alice VOIT son panneau privé et bob
/// ne le voit pas. Et le troisième bras : le BIEN COMMUN n'a pas été fermé — un panneau `shared` du
/// dashboard semé reste servi aux deux.
///
/// MESURÉ AVANT CORRECTIF (mêmes appels, assertions inversées) : `dash_get` de bob rendait le panneau
/// privé d'alice, `panel_data` -> 200 avec ses lignes, et `editable: true` pour bob.
#[tokio::test]
async fn deux_identites_un_objet_sans_proprietaire_ne_fuit_pas_le_panneau_prive() {
    let (st, dbp) = sp_state("p1120n-deux-identites");
    let (alice, bob) = (sp_au("alice", "editor"), sp_au("bob", "editor"));
    let seme = sp_dashboard_seme(&st);

    // --- BRAS A : l'objet SANS PROPRIÉTAIRE ---
    let (c, prive) = sp_panneau(&st, &alice, seme, "le mien, privé", "private").await;
    assert_eq!(c, 200, "alice peut poser un panneau sur un dashboard commun (il est `shared`)");
    let (c, partage) = sp_panneau(&st, &alice, seme, "pour tout le monde", "shared").await;
    assert_eq!(c, 200);

    let (code, vus_bob, editable_bob) = sp_panneaux_servis(&st, &bob, seme).await;
    assert_eq!(code, 200, "le dashboard commun reste LISIBLE — on n'a pas fermé le bien commun");
    assert!(!vus_bob.contains(&prive), "AVANT correctif : servi. Un objet sans propriétaire donnait à bob l'autorité du propriétaire");
    assert!(vus_bob.contains(&partage), "le panneau DÉCLARÉ commun reste servi à bob");
    // ET LE DRAPEAU N'A PAS ÉTÉ RESSERRÉ AVEC LA PORTÉE : le dashboard est DÉCLARÉ commun, donc la
    // porte d'écriture le laisse passer, donc la vue doit le dire. C'est un fait DISTINCT de la
    // portée de lecture, et le témoin `le_drapeau_editable_dit_ce_que_la_porte_fera` le tient.
    assert!(editable_bob, "le bien commun reste modifiable : le correctif ferme la CONFIDENTIALITÉ, pas l'ergonomie");

    let cd = panel_data(State(st.clone()), Extension(bob.clone()), Path(prive), pb_q()).await.status().as_u16();
    assert_eq!(cd, 403, "AVANT correctif : 200 — les DONNÉES du panneau privé, pas seulement son texte");
    let cd = panel_data(State(st.clone()), Extension(bob.clone()), Path(partage), pb_q()).await.status().as_u16();
    assert_eq!(cd, 200, "…et le panneau commun continue d'être servi : le correctif n'a rien éteint de commun");

    // LE PRIX ASSUMÉ, ÉNONCÉ : « privé » sur un objet que personne ne possède n'a pas de
    // destinataire — pas même son auteur. On le DIT plutôt que de le laisser surprendre.
    let (_, vus_alice, _) = sp_panneaux_servis(&st, &alice, seme).await;
    assert!(!vus_alice.contains(&prive), "un panneau privé sur un objet sans propriétaire n'est servi à personne — y compris à son auteur");

    // --- BRAS B : LE CONTRÔLE POSITIF, sur un objet QUI A un propriétaire ---
    let (_, v) = pb_json(dash_create(State(st.clone()), Extension(alice.clone()), Json(json!({ "name": "à alice", "visibility": "shared" }))).await.into_response()).await;
    let did_alice = v.get("id").and_then(|x| x.as_i64()).unwrap();
    let (c, prive_alice) = sp_panneau(&st, &alice, did_alice, "privé d'alice", "private").await;
    assert_eq!(c, 200);

    let (_, vus, editable) = sp_panneaux_servis(&st, &alice, did_alice).await;
    assert!(vus.contains(&prive_alice), "CONTRÔLE POSITIF : la propriétaire, elle, voit son panneau privé");
    assert!(editable, "CONTRÔLE POSITIF : et le tient pour éditable");
    let cd = panel_data(State(st.clone()), Extension(alice.clone()), Path(prive_alice), pb_q()).await.status().as_u16();
    assert_eq!(cd, 200, "CONTRÔLE POSITIF : et en lit les données");

    let (code, vus, editable) = sp_panneaux_servis(&st, &bob, did_alice).await;
    assert_eq!(code, 200, "le dashboard PARTAGÉ d'alice reste lisible par bob");
    assert!(!vus.contains(&prive_alice), "…mais pas son panneau privé : c'est la PORTÉE qui s'est fermée");
    // ET PAS L'ERGONOMIE : « partagé » veut dire modifiable par le partage, décision du produit
    // ANTÉRIEURE à ce lot (`dash_editable` a toujours ouvert sur `vis == \"shared\"`). Ce lot ne la
    // touche pas — et le drapeau continue de dire la vérité sur la porte.
    assert!(editable, "un dashboard PARTAGÉ reste modifiable par le partage — le drapeau annonce la porte");
    assert_eq!(
        dash_update(State(st.clone()), Extension(bob.clone()), Path(did_alice), Json(json!({ "name": "renommé" }))).await,
        StatusCode::NO_CONTENT,
        "…et la porte le confirme : drapeau et porte ne divergent pas"
    );
    let cd = panel_data(State(st.clone()), Extension(bob.clone()), Path(prive_alice), pb_q()).await.status().as_u16();
    assert_eq!(cd, 403);

    // --- BRAS C : l'ADMIN garde son autorité. Le correctif rend une capacité à son rôle, il ne la détruit pas.
    let _ = editable_bob;
    let (_, vus_adm, editable_adm) = sp_panneaux_servis(&st, &sp_au("adm", "admin"), seme).await;
    assert!(vus_adm.contains(&prive) && vus_adm.contains(&partage), "l'admin voit tout du dashboard commun");
    assert!(editable_adm);
    ff_rm(&dbp);
}

// -------------------------------------------------------------------------------------
// (3) LA CAPTURE — la 3e surface, celle qui FIGE et se partage par jeton.
// -------------------------------------------------------------------------------------
/// La portée de lecture est un paramètre OBLIGATOIRE de la capture (`P7.13-a`), donc corriger le
/// coffre corrige la capture — mais « donc » n'est pas une mesure. Ce témoin la fait.
#[tokio::test]
async fn un_snapshot_pris_par_un_tiers_ne_fige_pas_le_panneau_prive_d_un_objet_sans_proprietaire() {
    let (st, dbp) = sp_state("p1120n-snapshot");
    let (alice, bob) = (sp_au("alice", "editor"), sp_au("bob", "editor"));
    let seme = sp_dashboard_seme(&st);
    let (_, prive) = sp_panneau(&st, &alice, seme, "secret d'alice", "private").await;
    let (_, partage) = sp_panneau(&st, &alice, seme, "commun", "shared").await;

    let (c, v) = pb_json(snapshot_create(State(st.clone()), Extension(bob.clone()), Json(json!({ "dashboard_id": seme, "from": 0, "to": 100 }))).await).await;
    assert_eq!(c, 200, "un dashboard COMMUN reste capturable — on ne ferme pas le bien commun");
    let tok = v.get("token").and_then(|x| x.as_str()).unwrap_or_default().to_string();
    assert!(!tok.is_empty(), "la capture rend bien un jeton");

    let fige: String = { st.db.lock().query_row("SELECT data FROM dashboard_snapshot WHERE token=?1", params![tok], |r| r.get(0)).unwrap() };
    assert!(!fige.contains("secret d'alice"), "AVANT correctif : le panneau PRIVÉ entrait dans le snapshot d'un tiers, partageable par jeton");
    assert!(fige.contains("commun"), "…et le panneau commun y est bien : la capture n'a pas été vidée");
    let _ = (prive, partage);
    ff_rm(&dbp);
}

// -------------------------------------------------------------------------------------
// (4) LA LISTE — l'état atteignable que `visibility='shared'` ne couvrait PAS.
// -------------------------------------------------------------------------------------
/// Un dashboard sans propriétaire ET `private` n'est pas qu'une hypothèse : il s'atteint par le
/// produit (le dashboard semé est `shared`, donc éditable par tous, donc basculable en `private` par
/// n'importe quel compte). C'est le seul cas où la clause d'octroi FAISAIT quelque chose sur la
/// liste — et ce quelque chose était de le montrer à tout le monde.
#[tokio::test]
async fn un_objet_sans_proprietaire_et_prive_n_est_plus_liste_a_tous() {
    let (st, dbp) = sp_state("p1120n-liste");
    {
        let conn = st.db.lock();
        conn.execute("INSERT INTO dashboard(name,created,visibility) VALUES('hérité privé',0,'private')", []).unwrap();
        conn.execute("INSERT INTO playlist(name,visibility) VALUES('rotation héritée','private')", []).unwrap();
    }
    let noms = |v: &Value, cle: &str| -> Vec<String> {
        v.get(cle).and_then(|d| d.as_array()).map(|a| a.iter().filter_map(|d| d.get("name").and_then(|n| n.as_str()).map(String::from)).collect()).unwrap_or_default()
    };

    let v = dash_list(State(st.clone()), Extension(sp_au("bob", "editor")), Query(HashMap::new())).await.0;
    assert!(!noms(&v, "dashboards").iter().any(|n| n == "hérité privé"), "AVANT correctif : listé à tous");
    let v = dash_list(State(st.clone()), Extension(sp_au("adm", "admin")), Query(HashMap::new())).await.0;
    assert!(noms(&v, "dashboards").iter().any(|n| n == "hérité privé"), "CONTRÔLE POSITIF : l'admin, lui, le voit — rien n'a été effacé");

    let v = playlists_list(State(st.clone()), Extension(sp_au("bob", "editor"))).await.0;
    assert!(!noms(&v, "playlists").iter().any(|n| n == "rotation héritée"), "AVANT correctif : listée à tous (le MÊME défaut, 2e table)");
    let v = playlists_list(State(st.clone()), Extension(sp_au("adm", "admin"))).await.0;
    assert!(noms(&v, "playlists").iter().any(|n| n == "rotation héritée"), "CONTRÔLE POSITIF");
    ff_rm(&dbp);
}

// -------------------------------------------------------------------------------------
// (5) LA SECONDE MOITIÉ DU MÊME DÉFAUT, trouvée en écrivant la règle.
// -------------------------------------------------------------------------------------
/// `owner == au.name` SEUL apparie une colonne vide à une identité SANS NOM. Le dépôt en FABRIQUE
/// (`AuthUser { name: String::new(), .. }` pour un relais non lié, cf. `transport_liaison`) : sans le
/// `!owner.is_empty()` explicite du coffre, retirer la clause d'octroi aurait laissé le trou ouvert
/// pour exactement cette identité-là. Ce témoin est la MUTATION du correctif : il rougit si on écrit
/// la version « évidente » de la règle.
#[test]
fn une_identite_sans_nom_ne_s_apparie_pas_a_une_colonne_vide() {
    let sans_nom = sp_au("", "editor");
    let alice = sp_au("alice", "editor");
    assert!(!panneau_resolu::autorite_de_proprietaire("", &sans_nom), "une colonne vide n'appartient pas à une identité sans nom");
    assert!(!panneau_resolu::lisible_par("", "private", &sans_nom), "…et ne lui ouvre pas un objet privé");
    // LES DEUX CONTRÔLES POSITIFS : la règle n'est pas simplement « toujours faux ».
    assert!(panneau_resolu::autorite_de_proprietaire("alice", &alice), "alice possède ce qui porte son nom");
    assert!(panneau_resolu::lisible_par("", "shared", &sans_nom), "le bien commun DÉCLARÉ reste lisible par quiconque");
    assert!(panneau_resolu::autorite_de_proprietaire("", &sp_au("adm", "admin")), "l'admin garde l'autorité sur un objet sans propriétaire");
}

// -------------------------------------------------------------------------------------
// (6) LA VOIE UNIQUE — garde de SOURCE, auto-validée sur des entrées FABRIQUÉES.
// -------------------------------------------------------------------------------------
/// Les tokens d'octroi, tels qu'ils s'écrivaient aux douze sites. Le SQL est normalisé (espaces
/// retirés) avant recherche, pour qu'une réécriture cosmétique ne fasse pas passer la garde.
///
/// LES DEUX TOKENS SONT DES SUFFIXES, ET C'EST UNE CORRECTION MESURÉE. Écrits pleins
/// (`COALESCE(owner,'')=''`, `owner.is_empty()`), ils MANQUAIENT les formes QUALIFIÉES que le code
/// portait justement : `COALESCE(d.owner,'')=''` dans `dash_list` et `downer.is_empty()` dans
/// `panel_access`. La mutation M3 (remise de la clause SQL telle qu'elle était) a laissé cette garde
/// VERTE — un correctif qui aurait fermé une fausse accusation en faisant taire la vraie. Le suffixe
/// couvre l'alias de table comme le préfixe de variable, et le témoin positif fabriqué l'éprouve.
const SP_TOKENS_D_OCTROI: [&str; 2] = ["owner.is_empty()", "owner,'')=''"];

/// Retire les commentaires Rust d'une source. AFFIRMER N'EST PAS MENTIONNER : sans ce passage, la
/// garde accuserait le commentaire du coffre qui CITE le motif pour le démentir — et ce fichier-ci
/// le cite deux fois. `//` n'ouvre un commentaire que hors chaîne (compté sur les guillemets non
/// échappés qui le précèdent), sinon `"http://…"` serait tronqué.
fn sp_sans_commentaires(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut bloc = false;
    for ligne in src.lines() {
        let b = ligne.as_bytes();
        let (mut i, mut chaine, mut echap) = (0usize, false, false);
        let mut gardee = String::new();
        while i < b.len() {
            if bloc {
                if b[i] == b'*' && i + 1 < b.len() && b[i + 1] == b'/' {
                    bloc = false;
                    i += 2;
                    continue;
                }
                i += 1;
                continue;
            }
            if chaine {
                if echap {
                    echap = false;
                } else if b[i] == b'\\' {
                    echap = true;
                } else if b[i] == b'"' {
                    chaine = false;
                }
                gardee.push(b[i] as char);
                i += 1;
                continue;
            }
            if b[i] == b'"' {
                chaine = true;
                gardee.push('"');
                i += 1;
                continue;
            }
            if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'/' {
                break; // commentaire de fin de ligne, hors chaîne
            }
            if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
                bloc = true;
                i += 2;
                continue;
            }
            gardee.push(b[i] as char);
            i += 1;
        }
        out.push_str(&gardee);
        out.push('\n');
    }
    out
}

/// Un texte de source porte-t-il un OCTROI par colonne vide ? Espaces retirés pour que
/// `COALESCE( owner , '' ) = ''` ne se faufile pas.
fn sp_porte_un_octroi(src: &str) -> bool {
    let nu: String = sp_sans_commentaires(src).chars().filter(|c| !c.is_whitespace()).collect();
    SP_TOKENS_D_OCTROI.iter().any(|t| nu.contains(t))
}

/// LA GARDE, ET SA PROPRE VALIDATION. Un site de production ne peut plus faire d'une colonne `owner`
/// vide un octroi : la règle vit dans le SEUL coffre `handlers/panneau_resolu.rs`, où le motif
/// apparaît sous forme de REFUS (`!owner.is_empty() && …`) et non d'octroi. Toute autre occurrence
/// dans `src/` (hors `tests/`) est refusée.
///
/// L'AUTO-VALIDATION EST EXIGÉE : une garde à corpus est verte par construction si son détecteur ne
/// détecte rien. On lui donne donc quatre entrées FABRIQUÉES — deux qu'elle DOIT voir, deux qu'elle
/// ne doit PAS voir — et on éprouve enfin sa capacité à voir le coffre lui-même, dont on l'exempte
/// par CHEMIN et non par cécité.
#[test]
fn aucun_site_hors_du_coffre_ne_fait_d_une_colonne_vide_un_octroi() {
    // (a) TÉMOINS POSITIFS FABRIQUÉS — la garde voit ce qu'elle prétend voir.
    assert!(sp_porte_un_octroi("fn f() { if owner.is_empty() { return true; } false }"), "INSTRUMENT AVEUGLE : l'octroi Rust n'est pas vu");
    assert!(sp_porte_un_octroi("let s = \"WHERE COALESCE( owner , '' ) = ''\";"), "INSTRUMENT AVEUGLE : l'octroi SQL n'est pas vu, même espacé");
    // LES FORMES QUALIFIÉES — celles que le code portait, et que la première version de cette garde
    // laissait passer (mesuré par la mutation M3).
    assert!(sp_porte_un_octroi("let s = \"WHERE COALESCE(d.owner,'')=''\";"), "INSTRUMENT AVEUGLE : l'alias de table masque l'octroi SQL");
    assert!(sp_porte_un_octroi("fn f() { if downer.is_empty() { return true; } false }"), "INSTRUMENT AVEUGLE : un préfixe de variable masque l'octroi Rust");
    // (b) TÉMOINS NÉGATIFS FABRIQUÉS — elle n'accuse pas la PROSE qui cite le motif pour le démentir.
    assert!(!sp_porte_un_octroi("// jamais owner.is_empty() : une colonne vide n'octroie rien"), "la garde accuse un commentaire — c'est le piège du prédicat de sous-chaîne");
    assert!(!sp_porte_un_octroi("/// SQL refusé : COALESCE(d.owner,'')='' \nfn g() -> bool { false }"), "la garde accuse un commentaire de doc");
    // LE TÉMOIN NÉGATIF QUE LE SUFFIXE POURRAIT CASSER : `COALESCE(owner,'')` SANS comparaison est la
    // PROJECTION légitime, écrite dans une bonne dizaine de requêtes du dépôt. Elle ne doit pas être
    // accusée, sans quoi la garde serait ingérable et finirait exemptée partout.
    assert!(!sp_porte_un_octroi("let s = \"SELECT COALESCE(owner,'') FROM view WHERE id=?1\";"), "la garde accuse une PROJECTION, pas un octroi");
    assert!(!sp_porte_un_octroi("let u = \"http://exemple/owner\"; // rien ici"), "une URL en chaîne n'est pas un commentaire");

    // (c) LE PÉRIMÈTRE RÉEL.
    let racine = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let coffre = racine.join("handlers").join("panneau_resolu.rs");
    let (mut fautifs, mut lus) = (Vec::new(), 0usize);
    let mut pile = vec![racine.clone()];
    while let Some(d) = pile.pop() {
        for e in std::fs::read_dir(&d).expect("source du daemon lisible") {
            let p = e.expect("entrée lisible").path();
            if p.is_dir() {
                if p.file_name().map(|n| n == "tests").unwrap_or(false) {
                    continue;
                }
                pile.push(p);
                continue;
            }
            if p.extension().map(|x| x != "rs").unwrap_or(true) || p == coffre {
                continue;
            }
            lus += 1;
            if sp_porte_un_octroi(&std::fs::read_to_string(&p).expect("fichier lisible")) {
                fautifs.push(p.strip_prefix(&racine).unwrap().to_string_lossy().to_string());
            }
        }
    }
    assert!(lus > 100, "INSTRUMENT : {lus} fichiers seulement — le corpus n'a pas été parcouru");
    assert!(fautifs.is_empty(), "AVANT correctif : 11 sites hors coffre. Encore fautifs : {fautifs:?}");

    // (d) …ET LA GARDE VOIT BIEN LE COFFRE quand on lève l'exemption : l'exemption est un CHEMIN,
    // pas une cécité. Sans ceci, (c) serait vert même si le détecteur avait cessé de fonctionner.
    assert!(sp_porte_un_octroi(&std::fs::read_to_string(&coffre).expect("coffre lisible")), "INSTRUMENT : la garde ne voit plus le motif là où il vit encore");
}

// -------------------------------------------------------------------------------------
// (7) UN DRAPEAU NE MENT PAS SUR SA PROPRE PORTE — le défaut que ce lot a FAILLI introduire.
// -------------------------------------------------------------------------------------
/// PREMIER JET DE CE LOT, ET IL ÉTAIT FAUX : ayant remplacé la clause d'octroi partout par la même
/// expression, j'avais fait dire au drapeau `editable` ce que dit la PORTÉE DE LECTURE — donc
/// `false` sur un dashboard COMMUN que le serveur laisse pourtant modifier. La vue aurait masqué un
/// geste accepté. Ce sont DEUX faits distincts, que la clause d'octroi rendait égaux sur les objets
/// sans propriétaire et qui ont cessé de l'être : la portée est une décision de CONFIDENTIALITÉ,
/// le drapeau est l'annonce d'une PORTE. Ce témoin les oppose sur le cas où ils diffèrent.
#[tokio::test]
async fn le_drapeau_editable_dit_ce_que_la_porte_fera() {
    let (st, dbp) = sp_state("p1120n-drapeau");
    let bob = sp_au("bob", "editor");
    let seme = sp_dashboard_seme(&st);

    // (a) SUR LE BIEN COMMUN : la porte accepte, donc le drapeau l'annonce — et la PORTÉE, elle,
    //     refuse toujours le panneau privé (mesuré par le témoin à deux identités).
    let porte_reelle = dash_update(State(st.clone()), Extension(bob.clone()), Path(seme), Json(json!({ "name": "renommé par bob" }))).await;
    assert_eq!(porte_reelle, StatusCode::NO_CONTENT, "la porte d'écriture accepte : le dashboard est DÉCLARÉ commun");
    let (_, _, drapeau) = sp_panneaux_servis(&st, &bob, seme).await;
    assert!(drapeau, "…donc le drapeau doit l'annoncer. `false` ici masquerait un geste que le serveur accepte");
    let v = dash_list(State(st.clone()), Extension(bob.clone()), Query(HashMap::new())).await.0;
    let liste = v["dashboards"].as_array().unwrap().iter().find(|d| d["id"] == json!(seme)).cloned().unwrap();
    assert_eq!(liste["editable"], json!(true), "…et la LISTE dit la même chose que la fiche");

    // (b) SUR UN OBJET PRIVÉ D'AUTRUI : la porte refuse, et le drapeau ne promet rien.
    let (_, v) = pb_json(dash_create(State(st.clone()), Extension(sp_au("alice", "editor")), Json(json!({ "name": "privé d'alice", "visibility": "private" }))).await.into_response()).await;
    let prive_alice = v["id"].as_i64().unwrap();
    let porte = dash_update(State(st.clone()), Extension(bob.clone()), Path(prive_alice), Json(json!({ "name": "x" }))).await;
    assert_eq!(porte, StatusCode::FORBIDDEN, "la porte refuse");
    let v = dash_list(State(st.clone()), Extension(bob.clone()), Query(HashMap::new())).await.0;
    assert!(!v["dashboards"].as_array().unwrap().iter().any(|d| d["id"] == json!(prive_alice)), "…et l'objet n'est même pas listé");
    ff_rm(&dbp);
}

// -------------------------------------------------------------------------------------
// (8) LE RESSERREMENT DES GESTES D'ÉCRITURE, ASSERMENTÉ — avec son motif dans le message.
// -------------------------------------------------------------------------------------
/// LE MOTIF, ÉCRIT LÀ OÙ IL SERA LU : dans le message d'échec. Une décision non assermentée dérive en
/// silence — quelqu'un « rétablit » l'ancien comportement en croyant corriger une régression. Ce
/// texte est là pour que ce quelqu'un lise POURQUOI avant de le faire.
const SP_MOTIF_DU_RESSERREMENT: &str = "DÉCISION ASSERMENTÉE (`P11.20-n`, 2026-09-03) — CE N'EST PAS UNE RÉGRESSION. \
Supprimer ou renommer est un geste de PROPRIÉTAIRE. Une colonne `owner` vide n'est pas une propriété \
partagée, c'est une ABSENCE de propriétaire : elle n'octroie donc ce geste à personne, et l'objet semé \
redevient admin-seul à la suppression. Ce qui reste ouvert à tous sur ces objets, c'est ce que \
`visibility='shared'` DÉCLARE — les lire et les modifier. Avant ce lot, n'importe quel compte pouvait \
SUPPRIMER la vue « SOC » et le dashboard d'accueil du produit. Si tu veux rouvrir ce geste, ce n'est pas \
en retirant ce test : c'est en donnant un propriétaire aux objets semés, ou en déclarant explicitement \
que la suppression suit le partage.";

/// DEUX IDENTITÉS, ET NI L'UNE NI L'AUTRE NE POSSÈDE. Le geste d'écriture le plus destructeur —
/// supprimer — est tenté par les deux comptes sur les objets que les SEMEURS ont posés, puis par
/// l'admin. Le trou que M10 avait nommé : jusqu'ici SEULE une garde de source tenait ces trois portes,
/// et ce lot a lui-même démontré (M3) qu'une garde de source peut manquer la forme que le code porte.
#[tokio::test]
async fn un_objet_sans_proprietaire_ne_se_supprime_plus_qu_en_admin() {
    let (st, dbp) = sp_state("p1120n-suppression");
    let (alice, bob, admin) = (sp_au("alice", "editor"), sp_au("bob", "editor"), sp_au("adm", "admin"));
    let seme = sp_dashboard_seme(&st);
    // La vue SEMÉE, posée par `find_or_create_view` dans le même geste — sans propriétaire, déclarée commune.
    let (vue, vowner, vvis): (i64, String, String) = {
        let conn = st.db.lock();
        conn.query_row("SELECT id,COALESCE(owner,''),COALESCE(visibility,'shared') FROM view WHERE name='SOC'", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap()
    };
    assert_eq!((vowner.as_str(), vvis.as_str()), ("", "shared"), "fixture : la vue semée est sans propriétaire ET déclarée commune");

    // --- LES DEUX IDENTITÉS SONT REFUSÉES, sur les TROIS portes ---
    for (qui, au) in [("alice", &alice), ("bob", &bob)] {
        assert_eq!(
            dash_delete(State(st.clone()), Extension(au.clone()), Path(seme)).await,
            StatusCode::FORBIDDEN,
            "{qui} supprime le dashboard SEMÉ. AVANT ce lot : 204. {SP_MOTIF_DU_RESSERREMENT}"
        );
        assert_eq!(
            view_delete(State(st.clone()), Extension(au.clone()), Path(vue)).await,
            StatusCode::FORBIDDEN,
            "{qui} supprime la vue SEMÉE. AVANT ce lot : 204. {SP_MOTIF_DU_RESSERREMENT}"
        );
        assert_eq!(
            view_update(State(st.clone()), Extension(au.clone()), Path(vue), Json(json!({ "name": "renommée par un tiers" }))).await,
            StatusCode::FORBIDDEN,
            "{qui} renomme la vue SEMÉE. AVANT ce lot : 204. {SP_MOTIF_DU_RESSERREMENT}"
        );
    }
    // FAIL-CLOSED, PAS DRAPEAUTÉ : après trois refus, RIEN n'a bougé.
    {
        let conn = st.db.lock();
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM dashboard WHERE id=?1", params![seme], |r| r.get::<_, i64>(0)).unwrap(), 1, "le refus n'a rien supprimé à moitié");
        assert_eq!(conn.query_row("SELECT name FROM view WHERE id=?1", params![vue], |r| r.get::<_, String>(0)).unwrap(), "SOC", "le refus n'a rien renommé");
    }

    // --- CONTRÔLE POSITIF 1 : le resserrement n'est pas un blocage général. Alice dispose du SIEN. ---
    let (_, v) = pb_json(dash_create(State(st.clone()), Extension(alice.clone()), Json(json!({ "name": "à alice", "visibility": "private" }))).await.into_response()).await;
    let a_alice = v["id"].as_i64().unwrap();
    let (_, v) = pb_json(view_create(State(st.clone()), Extension(alice.clone()), Json(json!({ "name": "vue d'alice", "visibility": "private" }))).await.into_response()).await;
    let vue_alice = v["id"].as_i64().unwrap();
    assert_eq!(view_update(State(st.clone()), Extension(alice.clone()), Path(vue_alice), Json(json!({ "name": "vue d'alice, renommée" }))).await, StatusCode::NO_CONTENT, "alice renomme SA vue");
    assert_eq!(view_delete(State(st.clone()), Extension(alice.clone()), Path(vue_alice)).await, StatusCode::NO_CONTENT, "alice supprime SA vue");
    assert_eq!(dash_delete(State(st.clone()), Extension(alice.clone()), Path(a_alice)).await, StatusCode::NO_CONTENT, "alice supprime SON dashboard");
    // …et bob ne dispose pas de ce qui est à alice (le second bras des deux identités).
    let (_, v) = pb_json(view_create(State(st.clone()), Extension(alice.clone()), Json(json!({ "name": "encore à alice", "visibility": "private" }))).await.into_response()).await;
    let vue_alice2 = v["id"].as_i64().unwrap();
    assert_eq!(view_delete(State(st.clone()), Extension(bob.clone()), Path(vue_alice2)).await, StatusCode::FORBIDDEN, "bob ne supprime pas la vue d'alice");

    // --- CONTRÔLE POSITIF 2 : l'ADMIN, lui, peut. La capacité est rendue à un rôle, pas détruite. ---
    assert_eq!(view_update(State(st.clone()), Extension(admin.clone()), Path(vue), Json(json!({ "name": "SOC (admin)" }))).await, StatusCode::NO_CONTENT, "l'admin renomme la vue semée");
    assert_eq!(view_delete(State(st.clone()), Extension(admin.clone()), Path(vue)).await, StatusCode::NO_CONTENT, "l'admin supprime la vue semée");
    assert_eq!(dash_delete(State(st.clone()), Extension(admin.clone()), Path(seme)).await, StatusCode::NO_CONTENT, "l'admin supprime le dashboard semé");
    {
        let conn = st.db.lock();
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM view WHERE id=?1", params![vue], |r| r.get::<_, i64>(0)).unwrap(), 0, "…et le geste de l'admin a bien PORTÉ");
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM dashboard WHERE id=?1", params![seme], |r| r.get::<_, i64>(0)).unwrap(), 0);
    }
    ff_rm(&dbp);
}

// -------------------------------------------------------------------------------------
// (9) LES DEUX DRAPEAUX RESTANTS — bibliothèque et playlists — DISENT LEUR PORTE.
// -------------------------------------------------------------------------------------
/// LES QUATRE FORMES qu'un objet de cette famille peut prendre, telles que le SCHÉMA les autorise :
/// (propriétaire nommé | absent) × (`shared` | `private`). Les deux premières se posent par le
/// produit ; les deux dernières sont REPRÉSENTABLES (`owner` est nullable au schéma) sans chemin
/// d'écriture produit connu — c'est exactement la population sur laquelle la clause d'octroi
/// s'appliquait, et la règle doit y être fail-closed sans attendre qu'un semeur les fabrique.
async fn sp_population_ergo(st: &AppState, alice: &AuthUser) -> [(&'static str, i64, i64); 4] {
    let (_, v) = pb_json(library_panel_create(State(st.clone()), Extension(alice.clone()), Json(json!({ "name": "biblio-alice-partagee", "query": "search | stats count", "is_soql": true, "visibility": "shared" }))).await).await;
    let lib_as = v["id"].as_i64().unwrap();
    let (_, v) = pb_json(library_panel_create(State(st.clone()), Extension(alice.clone()), Json(json!({ "name": "biblio-alice-privee", "query": "search | stats count", "is_soql": true, "visibility": "private" }))).await).await;
    let lib_ap = v["id"].as_i64().unwrap();
    let (_, v) = pb_json(playlist_create(State(st.clone()), Extension(alice.clone()), Json(json!({ "name": "playlist-alice-partagee", "visibility": "shared" }))).await).await;
    let pl_as = v["id"].as_i64().unwrap();
    let (_, v) = pb_json(playlist_create(State(st.clone()), Extension(alice.clone()), Json(json!({ "name": "playlist-alice-privee", "visibility": "private" }))).await).await;
    let pl_ap = v["id"].as_i64().unwrap();
    let conn = st.db.lock();
    conn.execute("INSERT INTO library_panel(name,title,query,is_soql,viz,drill,visibility) VALUES('biblio-orpheline-partagee','T','search | stats count',1,'table','','shared')", []).unwrap();
    let lib_os = conn.last_insert_rowid();
    conn.execute("INSERT INTO library_panel(name,title,query,is_soql,viz,drill,visibility) VALUES('biblio-orpheline-privee','T','search | stats count',1,'table','','private')", []).unwrap();
    let lib_op = conn.last_insert_rowid();
    conn.execute("INSERT INTO playlist(name,visibility) VALUES('playlist-orpheline-partagee','shared')", []).unwrap();
    let pl_os = conn.last_insert_rowid();
    conn.execute("INSERT INTO playlist(name,visibility) VALUES('playlist-orpheline-privee','private')", []).unwrap();
    let pl_op = conn.last_insert_rowid();
    // (étiquette, id bibliothèque, id playlist) — les deux surfaces partagent la MÊME règle
    // (`ergo_editable` -> `lisible_par`), donc la MÊME population les éprouve toutes les deux.
    [("propriétaire nommé + partagé", lib_as, pl_as), ("propriétaire nommé + privé", lib_ap, pl_ap),
     ("SANS propriétaire + partagé", lib_os, pl_os), ("SANS propriétaire + privé", lib_op, pl_op)]
}

/// Les `(id, editable)` que la liste SERT à ce compte.
async fn sp_liste_ergo(st: &AppState, au: &AuthUser, quoi: &str) -> Vec<(i64, bool)> {
    let v = if quoi == "library_panels" {
        library_panels_list(State(st.clone()), Extension(au.clone())).await.0
    } else {
        playlists_list(State(st.clone()), Extension(au.clone())).await.0
    };
    v[quoi].as_array().map(|a| a.iter().map(|r| (r["id"].as_i64().unwrap_or(0), r["editable"].as_bool().unwrap_or(false))).collect()).unwrap_or_default()
}

/// LA PORTE RÉELLE, exercée : un `PATCH` vide passe la garde puis n'écrit que l'horodatage.
async fn sp_porte_ergo(st: &AppState, au: &AuthUser, quoi: &str, id: i64) -> StatusCode {
    if quoi == "library_panels" {
        library_panel_update(State(st.clone()), Extension(au.clone()), Path(id), Json(json!({}))).await
    } else {
        playlist_update(State(st.clone()), Extension(au.clone()), Path(id), Json(json!({}))).await
    }
}

/// LE TROU DE M10, FERMÉ PAR LE COMPORTEMENT. Ces deux drapeaux n'étaient tenus que par une garde de
/// SOURCE — et ce lot a prouvé (M3) qu'une garde de source peut manquer la forme que le code porte.
/// La propriété éprouvée est DÉRIVÉE, pas énumérée : pour CHAQUE ligne que la liste sert, à CHAQUE
/// identité, le drapeau `editable` vaut exactement ce que la porte d'écriture décidera. Une cinquième
/// forme d'objet, ou une identité de plus, entre dans la propriété sans qu'on la réécrive.
#[tokio::test]
async fn les_drapeaux_editable_de_la_bibliotheque_et_des_playlists_disent_leur_porte() {
    let (st, dbp) = sp_state("p1120n-drapeaux-ergo");
    let (alice, bob, admin) = (sp_au("alice", "editor"), sp_au("bob", "editor"), sp_au("adm", "admin"));
    let pop = sp_population_ergo(&st, &alice).await;

    for quoi in ["library_panels", "playlists"] {
        for (qui, au) in [("alice", &alice), ("bob", &bob), ("adm", &admin)] {
            let servies = sp_liste_ergo(&st, au, quoi).await;
            assert!(!servies.is_empty(), "INSTRUMENT : {qui} ne se voit servir aucune ligne de {quoi} — la propriété serait vide");
            for (id, drapeau) in servies {
                let porte = sp_porte_ergo(&st, au, quoi, id).await != StatusCode::FORBIDDEN;
                assert_eq!(drapeau, porte, "{quoi} #{id} vu par {qui} : le drapeau `editable` annonce {drapeau} et la porte décide {porte} — un drapeau qui ment sur sa propre porte");
            }
        }
    }

    // …ET LA PROPRIÉTÉ NE SUFFIT PAS SEULE : elle serait vraie si TOUT était refusé à tout le monde.
    // Voici donc les faits NOMMÉS, forme par forme.
    for (etiquette, lib, pl) in pop {
        for (quoi, id) in [("library_panels", lib), ("playlists", pl)] {
            let vu = |l: &Vec<(i64, bool)>| l.iter().any(|(i, _)| *i == id);
            let (la, lb, ladm) = (sp_liste_ergo(&st, &alice, quoi).await, sp_liste_ergo(&st, &bob, quoi).await, sp_liste_ergo(&st, &admin, quoi).await);
            assert!(vu(&ladm), "{quoi} « {etiquette} » : l'admin voit tout — sinon les refus ci-dessous ne prouveraient pas qu'il RESTE quelque chose");
            match etiquette {
                "propriétaire nommé + partagé" | "SANS propriétaire + partagé" => {
                    // DÉCISION DE PRODUIT ANTÉRIEURE À CE LOT, QUE JE NE DESSERRE NI NE RESSERRE :
                    // `visibility='shared'` vaut « modifiable par le partage » (`lisible_par`). Un
                    // tiers voit et modifie. Je la NOMME au lieu de plier l'assertion.
                    assert!(vu(&lb) && vu(&la), "{quoi} « {etiquette} » : DÉCLARÉ commun -> servi à tous (décision antérieure à `P11.20-n`)");
                    assert_ne!(sp_porte_ergo(&st, &bob, quoi, id).await, StatusCode::FORBIDDEN, "{quoi} « {etiquette} » : et modifiable par le partage — ce lot ne touche pas à ce geste");
                }
                "propriétaire nommé + privé" => {
                    assert!(vu(&la), "{quoi} « {etiquette} » : CONTRÔLE POSITIF — la propriétaire voit le sien");
                    assert!(!vu(&lb), "{quoi} « {etiquette} » : et le tiers ne le voit pas");
                    assert_eq!(sp_porte_ergo(&st, &bob, quoi, id).await, StatusCode::FORBIDDEN, "{quoi} « {etiquette} » : ni ne le modifie");
                }
                _ => {
                    // LE CŒUR DE `P11.20-n` SUR CETTE SURFACE : sans propriétaire ET non déclaré
                    // commun -> personne, PAS MÊME UN EDITOR QUELCONQUE, n'en hérite.
                    assert!(!vu(&la) && !vu(&lb), "{quoi} « {etiquette} » : AVANT correctif, servi à TOUS et modifiable par TOUS. {SP_MOTIF_DU_RESSERREMENT}");
                    for (qui, au) in [("alice", &alice), ("bob", &bob)] {
                        assert_eq!(sp_porte_ergo(&st, au, quoi, id).await, StatusCode::FORBIDDEN, "{quoi} « {etiquette} » : {qui} le modifie encore par son id");
                    }
                    assert_ne!(sp_porte_ergo(&st, &admin, quoi, id).await, StatusCode::FORBIDDEN, "{quoi} « {etiquette} » : CONTRÔLE POSITIF — l'admin, lui, peut");
                }
            }
        }
    }
    ff_rm(&dbp);
}
