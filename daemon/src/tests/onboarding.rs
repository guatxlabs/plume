// ONBOARDING (`/api/setup`) — la SEULE surface que plume expose à un anonyme, et la seule dont l'échec
// se paie en « l'exploitant croit son installation faite ». Avant ces tests, la suite ne touchait NI
// `setup_post` NI `setup_status` : 0 test sur les deux (mesuré le 2026-08-06 sur 6fc8c11).
//
// CE QUI EST MESURÉ ICI, et pas ailleurs :
//   (1) d'où sort le token d'installation — il n'y a pas de repli « presque aléatoire » ;
//   (2) comment il est comparé — fail-closed sur secret vide, temps constant ;
//   (3) ce que rend le serveur quand la POSE DE L'ADMIN N'A PAS ÉTÉ ÉCRITE — le cœur du sujet ;
//   (4) ce qu'une RAFALE sur le token laisse comme trace — un SIEM doit voir ses propres échecs ;
//   (5) ce que devient le fichier de token quand son effacement échoue ;
//   (6) la longueur de mot de passe que le web ANNONCE vs celle que le serveur IMPOSE.

const ONB_TOKEN: &str = "0123456789abcdef0123456789abcdef0123";

/// Fixture d'ONBOARDING : base file-backed schéma+migrations, AppState en MODE SETUP (aucun admin, aucun
/// `PLUME_PASS_HASH`) avec un token d'installation posé — c'est l'état exact d'un premier boot, celui où
/// `auth_guard` laisse `/api/setup[-status]` répondre à un anonyme.
fn onb_state(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
    let path = ff_tmp_path(tag);
    {
        let conn = open_db(&path).unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture onboarding : chaîne de migrations complète");
    }
    let mut st = ds_file_state(&path);
    st.user = Arc::new(String::new());
    st.pass_hash = Arc::new(String::new());
    *st.admin.lock() = None;
    st.setup_token = Arc::new(ONB_TOKEN.to_string());
    (st, path)
}

/// Le `setup-token.txt` voisin de la base — le chemin que `setup_post` efface et que `run()` écrit.
fn onb_token_path(db_path: &str) -> std::path::PathBuf {
    std::path::Path::new(db_path).with_file_name("setup-token.txt")
}

/// POST HTTP/1.1 avec CORPS -> (statut, corps de réponse). Même parti-pris que `router_probe` : on parle
/// le protocole à la main pour traverser TOUTES les couches du routeur (rate-limit, host, auth, RBAC),
/// et surtout pour que la SIGNATURE du handler puisse changer sans que le test ne mente.
async fn onb_post(addr: std::net::SocketAddr, path: &str, body: &str) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
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

/// (O-1) LE TOKEN D'INSTALLATION N'A PAS DE REPLI. Il ouvre le compte ADMIN du SIEM à un anonyme : sans
/// entropie il n'y a PAS de token (`/api/setup` refuse tout), et surtout pas un token DÉRIVÉ DE L'HORLOGE.
/// MESURÉ (6fc8c11, server/mod.rs) : le repli était `format!("setup{}", now())` — `setup1754…`, une dizaine de
/// chiffres autour de l'heure de boot, énumérable sous le budget d'auth (120 req/10 s) en quelques heures,
/// annoncé au journal EXACTEMENT comme un vrai token, sans un mot.
#[test]
fn onboarding_token_installation_sans_entropie_ne_produit_aucun_token() {
    assert!(
        setup_token_from_entropy(None).is_none(),
        "AUCUNE entropie -> AUCUN token (fail-closed). Tout repli dérivé d'une horloge/d'un pid est un \
         secret ÉNUMÉRABLE présenté comme un secret : c'est la porte admin du SIEM."
    );
    let t = setup_token_from_entropy(Some([0xab; SETUP_TOKEN_BYTES])).expect("entropie fournie -> token");
    assert_eq!(t.len(), SETUP_TOKEN_BYTES * 2, "token = hex des {SETUP_TOKEN_BYTES} octets fournis");
    assert!(t.chars().all(|c| c.is_ascii_hexdigit()), "token hex pur : {t}");
    assert_eq!(t, "ab".repeat(SETUP_TOKEN_BYTES), "le token EST la matière fournie, rien d'autre");
    // Et la source réelle rend bien de la matière sur cet hôte (sinon (a) ne mesurerait qu'un chemin mort).
    assert!(setup_token_entropy().is_some(), "l'hôte fournit de l'entropie -> le chemin nominal est vivant");
}

/// (O-2) LA COMPARAISON DU TOKEN EST FAIL-CLOSED. Hors mode setup `st.setup_token` est VIDE : un corps sans
/// champ `token` présente `""`, et `"" == ""` accorderait l'admin. La garde est portée par la fonction, pas
/// par la vigilance de l'appelant. (La constance en temps, elle, n'est PAS prouvée par ce test — cf. rapport.)
#[test]
fn onboarding_token_installation_compare_fail_closed() {
    assert!(!setup_token_matches("", ""), "secret attendu VIDE + token vide -> REFUS (jamais d'égalité vide)");
    assert!(!setup_token_matches("", "n'importe quoi"), "secret attendu VIDE -> rien ne matche");
    assert!(!setup_token_matches(ONB_TOKEN, ""), "token vide -> refus");
    assert!(!setup_token_matches(ONB_TOKEN, &ONB_TOKEN[..ONB_TOKEN.len() - 1]), "préfixe -> refus (longueur)");
    assert!(!setup_token_matches(ONB_TOKEN, &format!("{ONB_TOKEN}x")), "sur-longueur -> refus");
    assert!(setup_token_matches(ONB_TOKEN, ONB_TOKEN), "token exact -> accepté");
}

/// (O-3) LE CŒUR — UNE INSTALLATION NON ÉCRITE NE SE DÉCLARE PAS RÉUSSIE. `set_admin` posait l'admin EN
/// MÉMOIRE et exécutait ses trois écritures en `let _ =` : sur une base non inscriptible (disque plein,
/// volume RO, table absente), `/api/setup` répondait `200 {"ok":true}`, effaçait le token d'installation et
/// inscrivait « admin défini » au ledger — alors que RIEN n'était persisté. Au redémarrage suivant, l'admin
/// n'existe pas, plume repart en mode setup avec un NOUVEAU token, et l'exploitant croyait son SOC installé.
/// On rend la panne inécrivable ici en RETIRANT la table `user` (l'`INSERT` échoue, comme sur volume RO).
#[tokio::test]
async fn onboarding_persistance_echouee_ne_declare_pas_installation_reussie() {
    let (st, dbp) = onb_state("persist-ko");
    let db = st.db.clone();
    let admin = st.admin.clone();
    let tokfile = onb_token_path(&dbp);
    std::fs::write(&tokfile, ONB_TOKEN).unwrap();
    db.lock().execute_batch("DROP TABLE user").unwrap(); // base rendue NON INSCRIPTIBLE pour set_admin
    let addr = router_serve(st).await;

    let (code, body) = onb_post(addr, "/api/setup", &format!(
        r#"{{"token":"{ONB_TOKEN}","user":"root","password":"motdepasse-tres-long"}}"#
    )).await;

    assert_ne!(code, 200, "persistance IMPOSSIBLE -> le serveur NE DOIT PAS répondre 200 (corps: {body})");
    assert!(!body.contains("\"ok\":true"), "aucune déclaration de succès sur une écriture qui a échoué : {body}");
    // (a) rien de MOITIÉ écrit : `meta.admin_user` ne survit pas à l'échec de l'écriture du compte.
    let meta: i64 = db.lock()
        .query_row("SELECT COUNT(*) FROM meta WHERE key='admin_user'", [], |r| r.get(0)).unwrap();
    assert_eq!(meta, 0, "échec -> AUCUN état à moitié posé (meta.admin_user ne doit pas rester seul)");
    // (b) l'admin n'est pas posé EN MÉMOIRE non plus (sinon le process sert un admin que la base ignore).
    assert!(admin.lock().is_none(), "échec -> aucun admin en mémoire (le process ne doit pas diverger de la base)");
    // (c) le token d'installation reste UTILISABLE : l'exploitant peut réessayer après réparation.
    assert!(tokfile.exists(), "échec -> le token d'installation N'EST PAS effacé (sinon plus aucun moyen d'installer)");
    // (d) le ledger ne raconte pas une pose qui n'a pas eu lieu.
    let led: i64 = db.lock()
        .query_row("SELECT COUNT(*) FROM ledger WHERE kind='setup'", [], |r| r.get(0)).unwrap();
    assert_eq!(led, 0, "échec -> aucune entrée ledger 'setup' (le registre ne certifie pas une non-pose)");
    ff_rm(&dbp);
}

/// (O-4) UNE RAFALE SUR LE TOKEN D'INSTALLATION LAISSE UNE TRACE ET FINIT PAR ÊTRE FREINÉE. `/api/setup` est
/// la seule route qu'un anonyme peut atteindre au premier boot, et le seul secret qui la garde vaut le compte
/// admin. `login_post` compte, ingère (source=plume-auth) et VERROUILLE ses échecs depuis la Phase 3 ;
/// `setup_post` ne faisait RIEN : ni compteur, ni event, ni lockout. Un SIEM doit voir ses propres échecs.
#[tokio::test]
async fn onboarding_echec_de_token_est_trace_et_verrouille() {
    let (st, dbp) = onb_state("bruteforce");
    let db = st.db.clone();
    let seuil = st.lock_threshold;
    assert!(seuil > 0 && seuil < 20, "fixture : seuil de lockout exploitable ({seuil})");
    let addr = router_serve(st).await;

    let mut codes: Vec<u16> = Vec::new();
    for i in 0..(seuil + 2) {
        let (c, _) = onb_post(addr, "/api/setup", &format!(
            r#"{{"token":"mauvais-{i}","user":"root","password":"motdepasse-tres-long"}}"#
        )).await;
        codes.push(c);
    }
    assert_eq!(codes[0], 403, "1er mauvais token -> 403 (et pas 200/500) : {codes:?}");
    assert!(codes.iter().any(|&c| c == 429),
        "une RAFALE sur le token d'installation doit finir FREINÉE (429 + Retry-After), comme sur /api/login : {codes:?}");
    let evs: i64 = db.lock()
        .query_row("SELECT COUNT(*) FROM event WHERE source='plume-auth'", [], |r| r.get(0)).unwrap();
    assert!(evs >= seuil as i64,
        "chaque échec de token d'installation doit être AUTO-INGÉRÉ (source=plume-auth) — le SOC doit se \
         détecter lui-même ; mesuré {evs} event(s) pour {} tentatives", seuil + 2);
    ff_rm(&dbp);
}

/// (O-5) LE TOKEN D'INSTALLATION QUI SURVIT À L'INSTALLATION EST AVOUÉ. Le fichier contient le secret EN
/// CLAIR. `setup_post` faisait `let _ = remove_file(...)` : personne ne regardait le résultat, et la réponse
/// annonçait `{"ok":true}` même quand le fichier restait (volume RO, chemin non supprimable). On reproduit
/// « effacement impossible » en occupant le chemin par un répertoire NON VIDE (remove_file échoue, EISDIR).
#[tokio::test]
async fn onboarding_token_residuel_est_avoue() {
    let (st, dbp) = onb_state("residu");
    let db = st.db.clone();
    let tokfile = onb_token_path(&dbp);
    std::fs::create_dir_all(tokfile.join("occupe")).unwrap(); // chemin NON supprimable
    let addr = router_serve(st).await;

    let (code, body) = onb_post(addr, "/api/setup", &format!(
        r#"{{"token":"{ONB_TOKEN}","user":"root","password":"motdepasse-tres-long"}}"#
    )).await;

    assert_eq!(code, 200, "l'admin EST posé -> 200 (corps: {body})");
    assert!(tokfile.exists(), "fixture : le chemin du token est bien resté (sinon on ne mesure rien)");
    assert!(body.contains("\"setup_token_file_removed\":false"),
        "le token d'installation N'A PAS pu être effacé : la réponse DOIT le dire (un secret en clair reste \
         sur le disque) au lieu de rendre un succès nu — corps mesuré : {body}");
    // Le ledger porte l'aveu, pas seulement la réponse HTTP (la réponse, personne ne la relit).
    let led: String = db.lock()
        .query_row("SELECT detail FROM ledger WHERE kind='setup'", [], |r| r.get(0)).unwrap();
    assert!(led.contains("NON effacé"), "le registre doit porter le résidu : {led}");
    let _ = std::fs::remove_dir_all(&tokfile);
    ff_rm(&dbp);
}

/// Tous les `.rs` de PRODUCTION (`src/`, hors `src/tests/`) — partition FERMÉE parcourue récursivement :
/// un module ajouté demain est couvert sans qu'on ait à l'inscrire nulle part.
fn onb_sources_production() -> Vec<(String, String)> {
    fn descendre(d: &std::path::Path, out: &mut Vec<(String, String)>) {
        let Ok(entrees) = std::fs::read_dir(d) else { return };
        for e in entrees.flatten() {
            let p = e.path();
            if p.is_dir() {
                if p.file_name().and_then(|x| x.to_str()) != Some("tests") {
                    descendre(&p, out);
                }
            } else if p.extension().and_then(|x| x.to_str()) == Some("rs") {
                if let Ok(t) = std::fs::read_to_string(&p) {
                    out.push((p.display().to_string(), t));
                }
            }
        }
    }
    let mut out = Vec::new();
    descendre(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut out);
    out.sort();
    out
}

/// Corps textuel d'une fonction nommée (de sa signature à l'accolade fermante en colonne 0).
fn onb_corps_fn<'a>(src: &'a str, nom: &str) -> &'a str {
    let sig = format!("fn {nom}(");
    let deb = src.find(&sig).unwrap_or_else(|| panic!("fonction `{nom}` introuvable"));
    let reste = &src[deb..];
    let fin = reste.find("\n}").map(|i| i + 2).unwrap_or(reste.len());
    &reste[..fin]
}

/// (O-7) GARDE DÉRIVÉE — UN SEUL PRODUCTEUR, UN SEUL COMPARATEUR pour les secrets d'installation. Trois
/// correctifs ponctuels se re-cassent un par un ; ce qu'on veut interdire, c'est la FIGURE : fabriquer un
/// secret autrement que depuis la source d'entropie, ou le comparer autrement qu'à temps constant. La garde
/// balaie TOUT `src/` de production (hors tests) — donc le module qui n'existe pas encore.
#[test]
fn onboarding_secret_d_installation_un_producteur_un_comparateur() {
    // Identifiants COMPOSÉS qui contiennent `setup_token` sans désigner la VALEUR du secret : on les retire
    // avant d'examiner la ligne, sinon la garde se déclencherait sur son propre vocabulaire.
    const COMPOSES: [&str; 7] = [
        "setup_token_from_entropy", "setup_token_entropy", "setup_token_matches",
        "erase_setup_token_file", "setup_token_file_removed", "SETUP_TOKEN_BYTES", "SETUP_LOCK_PRINCIPAL",
    ];
    const INSPECTIONS: [&str; 6] = ["==", "!=", ".eq(", ".contains(", ".starts_with(", ".ends_with("];

    let sources = onb_sources_production();
    assert!(sources.len() > 20, "partition src/ parcourue : {} fichiers", sources.len());

    let mut fautes: Vec<String> = Vec::new();
    let mut lignes_brutes = 0usize;
    for (chemin, txt) in &sources {
        for (n, ligne) in txt.lines().enumerate() {
            // Un COMMENTAIRE ne fabrique ni ne compare rien — et on veut pouvoir DÉCRIRE le défaut retiré
            // à l'endroit où il vivait, sans que la garde prenne sa propre documentation pour une rechute.
            let code = ligne.trim_start();
            if code.starts_with("//") {
                continue;
            }
            // (1) FABRICATION : le repli horodaté qui produisait `setup1754…`, sous toutes ses formes.
            if ligne.contains("format!(\"setup{") || ligne.contains("plume-session-fallback") {
                fautes.push(format!("{chemin}:{} FABRIQUE un secret depuis l'horloge — {}", n + 1, ligne.trim()));
            }
            // (2) COMPARAISON : toute ligne qui touche la VALEUR du token et l'INSPECTE elle-même.
            let mut nu = ligne.to_string();
            for c in COMPOSES {
                nu = nu.replace(c, "");
            }
            if !nu.contains("setup_token") {
                continue;
            }
            lignes_brutes += 1;
            if let Some(op) = INSPECTIONS.iter().find(|o| nu.contains(**o)) {
                fautes.push(format!(
                    "{chemin}:{} INSPECTE le token d'installation avec `{op}` — {}", n + 1, ligne.trim()
                ));
            }
        }
    }
    assert!(lignes_brutes >= 4, "la garde a bien VU la valeur du token ({lignes_brutes} lignes) — un filtre \
        qui ne rend rien ne prouve rien");
    assert!(fautes.is_empty(),
        "SECRET D'INSTALLATION FABRIQUÉ OU COMPARÉ HORS DU CHEMIN UNIQUE : {fautes:#?}. Le token \
         d'installation vaut le compte admin : il se produit UNIQUEMENT via `os_entropy` (pas de repli \
         horodaté) et se vérifie UNIQUEMENT via `setup_token_matches` (temps constant).");

    // (3) Et le comparateur unique est bien le comparateur À TEMPS CONSTANT du dépôt (`ct_eq`, celui de la
    //     signature de session et du jeton de scrape /metrics) — pas un `==` réintroduit dans son corps.
    let session = &sources.iter().find(|(p, _)| p.ends_with("session.rs")).expect("src/session.rs").1;
    let cmp = onb_corps_fn(session, "setup_token_matches");
    assert!(cmp.contains("ct_eq"),
        "`setup_token_matches` doit comparer par `ct_eq` (temps constant, déjà dans le dépôt — aucune \
         dépendance à ajouter) ; corps mesuré : {cmp}");
    assert!(!cmp.contains("provided == expected") && !cmp.contains("provided != expected"),
        "aucune comparaison octet-à-octet à sortie anticipée dans le comparateur : {cmp}");
    // (4) Et les DEUX secrets d'installation tirent de la MÊME source d'entropie.
    for f in ["setup_token_entropy", "load_session_secret"] {
        let corps = onb_corps_fn(session, f);
        assert!(corps.contains("os_entropy"),
            "`{f}` doit tirer sa matière du producteur unique `os_entropy` ; corps mesuré : {corps}");
    }
}

/// (O-6) CE QUE LE WEB ANNONCE SUR LA LONGUEUR DE MOT DE PASSE EST CE QUE LE SERVEUR IMPOSE. Garde DÉRIVÉE :
/// on parcourt le RÉPERTOIRE `web/` (partition fermée — un fichier ajouté demain est couvert par
/// construction), on relève CHAQUE promesse chiffrée portée par une ligne qui parle de mot de passe, et on
/// la confronte à `PASSWORD_MIN_CHARS`. MESURÉ (6fc8c11) : 7 promesses, TOUTES à 6, dont le gate CLIENT du
/// wizard de 1re installation (`web/app.js`, `pw.length < 6`) — le serveur exige 12 depuis l'item 3.
#[test]
fn onboarding_politique_mdp_annoncee_par_le_web_egale_celle_du_serveur() {
    let racine = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("web");
    let mut fichiers: Vec<std::path::PathBuf> = std::fs::read_dir(&racine)
        .unwrap_or_else(|e| panic!("web/ illisible ({}) : {e}", racine.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| matches!(p.extension().and_then(|x| x.to_str()), Some("html") | Some("js")))
        .collect();
    fichiers.sort();
    assert!(fichiers.len() > 5, "partition web/ non vide : {} fichiers", fichiers.len());

    let mut promesses: Vec<String> = Vec::new();
    for f in &fichiers {
        let Ok(txt) = std::fs::read_to_string(f) else { continue };
        for (n, ligne) in txt.lines().enumerate() {
            let bas = ligne.to_lowercase();
            if !(bas.contains("mot de passe") || bas.contains("mdp") || bas.contains("password")) {
                continue;
            }
            // Toute borne chiffrée portée par cette ligne : `>= N`, `≥ N`, `< N`.
            for marqueur in [">=", "≥", "<"] {
                let mut reste = ligne;
                while let Some(i) = reste.find(marqueur) {
                    reste = &reste[i + marqueur.len()..];
                    let chiffres: String = reste.trim_start().chars().take_while(|c| c.is_ascii_digit()).collect();
                    if let Ok(v) = chiffres.parse::<usize>() {
                        if v != PASSWORD_MIN_CHARS {
                            promesses.push(format!(
                                "{}:{} annonce {v} — {}",
                                f.file_name().and_then(|x| x.to_str()).unwrap_or("?"),
                                n + 1,
                                ligne.trim()
                            ));
                        }
                    }
                }
            }
        }
    }
    assert!(
        promesses.is_empty(),
        "LE WEB PROMET UNE POLITIQUE DE MOT DE PASSE QUE LE SERVEUR N'APPLIQUE PAS (serveur = \
         {PASSWORD_MIN_CHARS}) : {promesses:#?}. Sur le wizard de 1re installation, la promesse trop basse \
         se paie en 400 sur le premier mot de passe saisi ; côté client, un gate plus permissif que le \
         serveur laisse l'exploitant croire sa saisie acceptée."
    );
}
