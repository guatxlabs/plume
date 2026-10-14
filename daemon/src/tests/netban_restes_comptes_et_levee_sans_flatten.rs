// `P10.20-b` / `P10.7-f` (restes de la vague P, hors handlers/ : cache des bans réseau).
//
// (1) `auth::netban_remove`, la valve anti-verrouillage, lisait la liste des écritures par `.flatten()` :
// un PAS raté du moteur tarissait l'itérateur (rusqlite 0.31 rend `Err` puis `None`), une écriture
// `::ffff:` de la même valeur restait en base et BLOQUAIT derrière une levée répondue ok. Désormais le pas
// raté rend `Err` AVANT tout `DELETE` ; une CELLULE non texte (BLOB) reste sautée, sinon une seule ligne
// abîmée rendrait la valve inutilisable pour toute adresse.
// (2) Les comptes de lignes jugées et les chargements refusés sont lus dans le CORPS de `/metrics`.
// (3) La recopie de `tronque` vers `NETBAN_TRONQUE` a enfin un témoin (plafond injecté par
// `netban_reload_cap`, plafond de production inchangé).
// (4) Le préchauffage du démarrage reprend, borné (`server::boucles_de_fond::netban_prechauffer`) ; son SITE
// (`netban_prechauffer_au_demarrage`, appelée par `spawn_netban_maintenance`) fait 5 essais ; la pause est
// INJECTÉE et le témoin y vérifie, sans horloge ni second fil, que le verrou de la base est libre ;
// l'épuisement, la reprise et le refus avant tout chargement sont dits JUSTES au journal, et le compte EXACT
// des refus est lu dans le corps `/metrics` (stderr et stdout d'un enfant : processus seul, aucun voisin).
// (5) Pose et levée corrigent le cache quand le rechargement qui les suit est refusé (lecture de
// `net_ban.expires_ts` refusée par un authorizer) : levée répondue = levée réelle, pose `Arme` = enforcée
// à SON échéance ; une écriture `::ffff:` est corrigée sous la clé repliée du chargement ; une pose PERMANENTE
// sur une adresse que le cache tient à échéance l'emporte (fusion dans les deux sens).
// (6) Un préchauffage appelé avec zéro essai en tente un ; le HELP du compte des refus dit le cas d'avant tout
// chargement réussi (aucun ban appliqué), pas seulement « dernier bon instantané ».
// Les deux jauges de lignes illisibles sont posées à des comptes DIFFÉRENTS (2 et 1) : échangées à
// l'enregistrement ou au service, elles rougissent.
// Le pas raté est FABRIQUÉ par un `progress_handler` qui interrompt la VM (même instrument que
// `purge_presence_de_table_non_lue_refuse.rs`). Les témoins qui touchent le cache global prennent
// `NETBAN_TEST_LOCK` (déclaré dans `netban.rs`).

fn nbr_poser(c: &Connection, ip: &str, exp: Option<i64>) {
    c.execute(
        "INSERT INTO net_ban(ip, reason, created_ts, expires_ts, created_by, env_id) VALUES (?1,'t',0,?2,'op','prod')",
        params![ip, exp],
    )
    .unwrap();
}

/// Arme UNE interruption : le prochain rappel de VM interrompt, les suivants laissent passer.
fn nbr_interrompre_une_fois(c: &Connection) {
    let arme = std::sync::atomic::AtomicBool::new(true);
    c.progress_handler(1, Some(move || arme.swap(false, std::sync::atomic::Ordering::Relaxed)));
}

fn nbr_desarmer(c: &Connection) {
    c.progress_handler(0, None::<fn() -> bool>);
}

fn nbr_lignes(c: &Connection) -> i64 {
    c.query_row("SELECT count(*) FROM net_ban", [], |r| r.get(0)).unwrap()
}

fn nbr_prom(c: &Connection) -> String {
    gather_prom(c, "/nonexistent-spool", "", &crate::handlers::system::VersionDeSchema::Lue(1), 80)
}

/// Valeur d'une série sans étiquette dans le corps `/metrics`.
fn nbr_serie(prom: &str, nom: &str) -> Option<String> {
    let tete = format!("{nom} ");
    prom.lines().find_map(|l| l.strip_prefix(tete.as_str()).map(str::to_string))
}

/// (1) LE TÉMOIN QUI ROUGIT : levée d'une adresse dont le store porte AUSSI l'écriture `::ffff:` de la
/// même valeur, avec un pas raté au premier pas de la lecture -> `Err`, RIEN retiré, ban toujours enforcé.
#[test]
fn netban_restes_levee_pas_rate_refuse_avant_tout_delete() {
    let _g = NETBAN_TEST_LOCK.lock();
    netban_cache().write().clear();
    let c = test_db();
    nbr_poser(&c, "203.0.113.71", None);
    nbr_poser(&c, "::ffff:203.0.113.71", None);
    netban_reload(&c);
    assert!(net_ban_is_blocked("203.0.113.71", now()), "contrôle positif : le ban est chargé");
    nbr_interrompre_une_fois(&c);
    let r = netban_remove(&c, "203.0.113.71");
    nbr_desarmer(&c);
    assert!(r.is_err(), "un pas raté pendant la lecture des écritures = levée REFUSÉE, jamais Ok : {r:?}");
    assert_eq!(nbr_lignes(&c), 2, "rien n'est retiré à moitié : les deux écritures sont en place");
    assert!(net_ban_is_blocked("203.0.113.71", now()), "et le ban reste enforcé, ce que l'Err dit");
}

/// Contre-épreuve sans panne : les DEUX écritures de la même valeur sont levées.
#[test]
fn netban_restes_levee_sans_panne_retire_les_deux_ecritures() {
    let _g = NETBAN_TEST_LOCK.lock();
    netban_cache().write().clear();
    let c = test_db();
    nbr_poser(&c, "203.0.113.72", None);
    nbr_poser(&c, "::ffff:203.0.113.72", None);
    netban_reload(&c);
    assert!(net_ban_is_blocked("203.0.113.72", now()), "contrôle positif");
    assert_eq!(netban_remove(&c, "203.0.113.72"), Ok(2), "les deux écritures sont levées et comptées");
    assert_eq!(nbr_lignes(&c), 0);
    assert!(!net_ban_is_blocked("203.0.113.72", now()), "la levée répondue est une levée réelle");
}

/// Une CELLULE non texte (BLOB) n'est pas un pas raté : la valve reste utilisable pour les autres adresses,
/// la ligne BLOB reste en place (aucun `ip=?1` texte ne la retire, le chargement ne la bloque pas).
#[test]
fn netban_restes_levee_cellule_blob_ne_prend_pas_la_valve_en_otage() {
    let _g = NETBAN_TEST_LOCK.lock();
    netban_cache().write().clear();
    let c = test_db();
    nbr_poser(&c, "198.51.100.81", None);
    nbr_poser(&c, "::ffff:198.51.100.81", None);
    c.execute(
        "INSERT INTO net_ban(ip, reason, created_ts, expires_ts, created_by, env_id) \
         VALUES (CAST('198.51.100.81' AS BLOB),'t',0,NULL,'op','prod')",
        [],
    )
    .unwrap();
    assert_eq!(netban_remove(&c, "198.51.100.81"), Ok(2), "les écritures texte sont levées malgré la cellule BLOB");
    let typ: String = c.query_row("SELECT typeof(ip) FROM net_ban", [], |r| r.get(0)).unwrap();
    assert_eq!((nbr_lignes(&c), typ.as_str()), (1, "blob"), "seule la ligne BLOB reste");
    assert!(!net_ban_is_blocked("198.51.100.81", now()), "l'adresse n'est plus bloquée");
}

/// (2) COMPTES LUS DANS LE CORPS DE `/metrics` : table saine = 0 ; IP illisible = 2 et échéance illisible = 1
/// (comptes DIFFÉRENTS : une jauge qui servirait l'autre se voit) ; un chargement refusé incrémente le compteur et LAISSE les jauges du dernier chargement
/// réussi ; retour à 0 au rechargement sain. Ni adresse ni valeur de cellule dans le corps.
#[test]
fn netban_restes_comptes_lus_dans_metrics() {
    let _g = NETBAN_TEST_LOCK.lock();
    netban_cache().write().clear();
    let c = test_db();
    nbr_poser(&c, "203.0.113.91", None);
    nbr_poser(&c, "203.0.113.92", Some(now() + 3600));
    assert!(netban_reload(&c), "table saine : chargement réussi");
    let prom = nbr_prom(&c);
    assert_eq!(nbr_serie(&prom, "plume_netban_lignes_ip_illisibles").as_deref(), Some("0"), "table saine");
    assert_eq!(nbr_serie(&prom, "plume_netban_lignes_echeance_illisible").as_deref(), Some("0"), "table saine");
    assert!(prom.contains("# TYPE plume_netban_chargements_refuses_total counter\n"));

    c.execute("UPDATE net_ban SET expires_ts='nbr-echeance-abimee' WHERE ip='203.0.113.92'", []).unwrap();
    c.execute_batch(
        "INSERT INTO net_ban(ip, reason, created_ts, expires_ts, created_by, env_id) \
         VALUES (CAST('203.0.113.93' AS BLOB),'t',0,NULL,'op','prod'), \
                (CAST('203.0.113.94' AS BLOB),'t',0,NULL,'op','prod');",
    )
    .unwrap();
    assert!(netban_reload(&c), "une cellule illisible n'est pas un refus");
    let prom = nbr_prom(&c);
    assert_eq!(nbr_serie(&prom, "plume_netban_lignes_ip_illisibles").as_deref(), Some("2"), "les DEUX IP illisibles comptées");
    assert_eq!(nbr_serie(&prom, "plume_netban_lignes_echeance_illisible").as_deref(), Some("1"), "échéance illisible comptée");
    assert!(!prom.contains("203.0.113.9") && !prom.contains("nbr-echeance-abimee"), "ni adresse ni valeur de cellule dans /metrics");

    let avant = netban_chargements_refuses();
    nbr_interrompre_une_fois(&c);
    let charge = netban_reload(&c);
    nbr_desarmer(&c);
    assert!(!charge, "le pas raté rend un chargement REFUSÉ");
    let prom = nbr_prom(&c);
    let servi: u64 = nbr_serie(&prom, "plume_netban_chargements_refuses_total")
        .and_then(|v| v.parse().ok())
        .expect("la série des refus est servie");
    // Borne basse seulement : sous `cargo test`, un voisin peut compter un refus ; le compte EXACT est lu dans
    // l'enfant de `netban_restes_prechauffage_epuise_dit_vrai_au_journal`.
    assert!(servi > avant, "le refus est COMPTÉ et servi ({avant} -> {servi})");
    assert_eq!(nbr_serie(&prom, "plume_netban_lignes_echeance_illisible").as_deref(), Some("1"), "un refus laisse le dernier compte réussi");
    assert_eq!(nbr_serie(&prom, "plume_netban_lignes_ip_illisibles").as_deref(), Some("2"), "un refus laisse AUSSI le compte des IP illisibles");
    assert!(net_ban_is_blocked("203.0.113.92", now()), "fail-static : le refus garde l'instantané");

    c.execute_batch("DELETE FROM net_ban WHERE typeof(ip)='blob'; UPDATE net_ban SET expires_ts=NULL WHERE ip='203.0.113.92';").unwrap();
    assert!(netban_reload(&c));
    let prom = nbr_prom(&c);
    assert_eq!(nbr_serie(&prom, "plume_netban_lignes_ip_illisibles").as_deref(), Some("0"), "retour à 0 au rechargement sain");
    assert_eq!(nbr_serie(&prom, "plume_netban_lignes_echeance_illisible").as_deref(), Some("0"), "retour à 0 au rechargement sain");
}

/// (3) RECOPIE DE `tronque` : plafond injecté à 2 sur 3 adresses -> `NETBAN_TRONQUE` vrai et servi à 1 ;
/// le rechargement au plafond de production le rabat à 0.
#[test]
fn netban_restes_troncature_recopiee_et_servie() {
    let _g = NETBAN_TEST_LOCK.lock();
    netban_cache().write().clear();
    let c = test_db();
    nbr_poser(&c, "192.0.2.101", None);
    nbr_poser(&c, "192.0.2.102", Some(now() + 3600));
    nbr_poser(&c, "192.0.2.103", Some(now() + 60));
    assert!(netban_reload_cap(&c, 2));
    assert_eq!(netban_cache().read().len(), 2, "contrôle : le plafond injecté a borné la map");
    assert!(netban_store_tronque(), "la troncature du chargement est RECOPIÉE dans le témoin global");
    assert_eq!(nbr_serie(&nbr_prom(&c), "plume_netban_store_tronque").as_deref(), Some("1"), "et servie par /metrics");
    assert!(netban_reload(&c));
    assert!(!netban_store_tronque(), "au plafond de production, 3 lignes ne tronquent pas");
    assert_eq!(nbr_serie(&nbr_prom(&c), "plume_netban_store_tronque").as_deref(), Some("0"));
}

/// (4) PRÉCHAUFFAGE REPRIS : un premier chargement refusé, le second réussit -> `Some(2)`, ban enforcé.
#[test]
fn netban_restes_prechauffage_reprend_apres_un_refus() {
    let _g = NETBAN_TEST_LOCK.lock();
    netban_cache().write().clear();
    let c = test_db();
    nbr_poser(&c, "198.51.100.111", None);
    nbr_interrompre_une_fois(&c);
    let db = Mutex::new(c);
    let r = crate::server::boucles_de_fond::netban_prechauffer(&db, 3, || {});
    nbr_desarmer(&db.lock());
    assert_eq!(r, Some(2), "un préchauffage refusé une fois est REPRIS et réussit au second essai");
    assert!(net_ban_is_blocked("198.51.100.111", now()), "le ban persisté est enforcé dès le préchauffage");
}

/// BORNÉ : un store toujours refusé -> exactement `essais` chargements tentés, puis `None` (pas de boucle).
#[test]
fn netban_restes_prechauffage_borne() {
    use std::sync::atomic::{AtomicU32, Ordering};
    let _g = NETBAN_TEST_LOCK.lock();
    let c = test_db();
    let tentes = std::sync::Arc::new(AtomicU32::new(0));
    let t = tentes.clone();
    c.progress_handler(
        1,
        Some(move || {
            t.fetch_add(1, Ordering::Relaxed);
            true
        }),
    );
    let db = Mutex::new(c);
    let r = crate::server::boucles_de_fond::netban_prechauffer(&db, 3, || {});
    nbr_desarmer(&db.lock());
    assert_eq!(r, None, "tous les essais refusés : None, le démarrage continue");
    assert_eq!(tentes.load(Ordering::Relaxed), 3, "exactement trois chargements tentés (un pas interrompu chacun)");
}

/// Ligne d'appel attendue du site : l'attente d'1 s entre deux essais, seule instruction avant la boucle.
const NBR_APPEL_DU_SITE: &str = "let _ = netban_prechauffer_au_demarrage(&db, || std::thread::sleep(Duration::from_secs(1)));";

/// Lecture du SITE dans le texte de `boucles_de_fond.rs` : dans le fil de `spawn_netban_maintenance`, la SEULE
/// instruction avant `loop {` est `NBR_APPEL_DU_SITE` (un `if false { … }`, un attribut `#[cfg(…)]` ou un
/// `let _ = if …` ajoutent ou changent une ligne et sont refusés) ; le corps n'appelle pas `netban_prechauffer(`
/// en direct ; le fichier ne définit `netban_prechauffer_au_demarrage` qu'une fois (pas d'homonyme local).
fn nbr_site_appelle_le_prechauffage(src: &str) -> Result<(), String> {
    let debut = src.find("fn spawn_netban_maintenance(").ok_or("site de démarrage absent")?;
    let corps = &src[debut..];
    let corps = &corps[..corps.find("\n}\n").ok_or("fin du site absente")?];
    let fil = &corps[corps.find("std::thread::spawn(move || {").ok_or("fil de maintenance absent")?..];
    let avant_boucle = &fil[..fil.find("loop {").ok_or("boucle des ticks absente")?];
    let instructions: Vec<&str> =
        avant_boucle.lines().skip(1).map(str::trim).filter(|l| !l.is_empty() && !l.starts_with("//")).collect();
    if instructions != [NBR_APPEL_DU_SITE] {
        return Err(format!("avant la boucle, attendu le seul appel du préchauffage, lu : {instructions:#?}"));
    }
    if corps.contains("netban_prechauffer(") {
        return Err("le site contourne le préchauffage du démarrage".into());
    }
    if src.matches("fn netban_prechauffer_au_demarrage").count() != 1 {
        return Err("une seule définition du préchauffage du démarrage".into());
    }
    Ok(())
}

/// (4 bis) LE SITE : le démarrage fait exactement `NETBAN_PRECHAUFFAGE_ESSAIS` = 5 chargements sur un store
/// toujours refusé, et le verrou est LIBRE dans chacune des 4 pauses. Sans horloge ni second fil :
/// `netban_prechauffer_au_demarrage` est jouée avec une pause qui ESSAIE le verrou (`try_lock`, sans attente ;
/// `parking_lot::Mutex` n'est pas réentrant, un verrou gardé rend `None`). `spawn_netban_maintenance`
/// l'appelle (lu dans son texte, contre-épreuve `if false` refusée par le même lecteur).
/// Ne tient pas : l'attente d'1 s du site n'est pas jouée (elle est lue) ; la lecture est TEXTUELLE — une
/// macro qui réécrirait l'appel, ou un fil qui ne serait jamais lancé, ne se voient pas ici.
#[test]
fn netban_restes_demarrage_prechauffe_en_cinq_essais() {
    use std::sync::atomic::{AtomicU32, Ordering};
    let _g = NETBAN_TEST_LOCK.lock();
    let c = test_db();
    let tentes = std::sync::Arc::new(AtomicU32::new(0));
    let t = tentes.clone();
    c.progress_handler(
        1,
        Some(move || {
            t.fetch_add(1, Ordering::Relaxed);
            true
        }),
    );
    assert_eq!(crate::server::boucles_de_fond::NETBAN_PRECHAUFFAGE_ESSAIS, 5, "la borne écrite au doc");
    let db = Mutex::new(c);
    let mut libre_pendant_la_pause: Vec<bool> = Vec::new();
    let r = crate::server::boucles_de_fond::netban_prechauffer_au_demarrage(&db, || {
        libre_pendant_la_pause.push(db.try_lock().is_some());
    });
    nbr_desarmer(&db.lock());
    assert_eq!(r, None, "contrôle : tous les essais refusés");
    assert_eq!(tentes.load(Ordering::Relaxed), 5, "le démarrage préchauffe en CINQ essais, ni moins ni plus");
    assert_eq!(libre_pendant_la_pause, [true; 4], "quatre pauses, le verrou de la base LIBRE dans chacune");
    let src = include_str!("../server/boucles_de_fond.rs");
    assert_eq!(nbr_site_appelle_le_prechauffage(src), Ok(()), "le site appelle le préchauffage du démarrage");
    let defait = src.replacen(NBR_APPEL_DU_SITE, &format!("if false {{ {NBR_APPEL_DU_SITE} }}"), 1);
    assert_ne!(defait, src, "contrôle : la contre-épreuve a bien réécrit la ligne d'appel");
    assert!(nbr_site_appelle_le_prechauffage(&defait).is_err(), "un appel mort `if false {{ … }}` est refusé");
}

/// (4 ter) LE VERROU EST RELÂCHÉ PENDANT LA PAUSE, au niveau du cœur `netban_prechauffer` : store toujours
/// refusé, 3 essais, la pause injectée essaie le verrou sans attendre. Un seul fil, aucune horloge : un
/// préchauffage qui garderait le verrou pendant ses pauses (ingest et API bloqués) rend `false`.
#[test]
fn netban_restes_prechauffage_relache_le_verrou_pendant_la_pause() {
    use std::sync::atomic::{AtomicU32, Ordering};
    let _g = NETBAN_TEST_LOCK.lock();
    let c = test_db();
    let tentes = std::sync::Arc::new(AtomicU32::new(0));
    let t = tentes.clone();
    c.progress_handler(
        1,
        Some(move || {
            t.fetch_add(1, Ordering::Relaxed);
            true
        }),
    );
    let db = Mutex::new(c);
    let mut vu: Vec<(u32, bool)> = Vec::new();
    let r = crate::server::boucles_de_fond::netban_prechauffer(&db, 3, || {
        vu.push((tentes.load(Ordering::Relaxed), db.try_lock().is_some()));
    });
    nbr_desarmer(&db.lock());
    assert_eq!(r, None, "contrôle : tous les essais refusés");
    assert_eq!(vu, [(1, true), (2, true)], "une pause ENTRE deux essais, le verrou libre dans chacune");
    assert_eq!(tentes.load(Ordering::Relaxed), 3, "contrôle : trois essais");
}

/// (4 quater) LE JOURNAL DIT VRAI. Enfant (processus neuf, aucun chargement réussi) : préchauffage épuisé en
/// 2 essais, puis un chargement réussi, puis un refus, puis un préchauffage repris à l'essai 2 sur 3. Le parent
/// lit son stderr : le refus AVANT tout chargement ne prétend pas garder un instantané qui n'existe pas ;
/// l'épuisement est dit ; le refus APRÈS un chargement réussi dit, lui, que l'instantané est gardé ; la reprise
/// dit son essai. Et le COMPTE des refus servi par `/metrics` dans l'enfant (processus seul, aucun voisin qui
/// compterait) vaut EXACTEMENT 4 : 2 + 1 + 1 — une série qui servirait un drapeau rendrait 1.
#[test]
fn netban_restes_prechauffage_epuise_dit_vrai_au_journal() {
    const ENFANT: &str = "NETBAN_RESTES_PRECHAUFFAGE_ENFANT";
    if std::env::var(ENFANT).is_ok() {
        let _g = NETBAN_TEST_LOCK.lock();
        let c = test_db();
        nbr_poser(&c, "198.51.100.121", None);
        c.progress_handler(1, Some(|| true));
        let db = Mutex::new(c);
        let r = crate::server::boucles_de_fond::netban_prechauffer(&db, 2, || {});
        println!("NBR-ENFANT-PRECHAUFFAGE={r:?}");
        let c = db.lock();
        nbr_desarmer(&c);
        assert!(netban_reload(&c), "enfant : premier chargement réussi");
        c.progress_handler(1, Some(|| true));
        assert!(!netban_reload(&c), "enfant : refus après un chargement réussi");
        nbr_interrompre_une_fois(&c);
        drop(c);
        let r2 = crate::server::boucles_de_fond::netban_prechauffer(&db, 3, || {});
        println!("NBR-ENFANT-REPRISE={r2:?}");
        let c = db.lock();
        nbr_desarmer(&c);
        let servi = nbr_serie(&nbr_prom(&c), "plume_netban_chargements_refuses_total");
        println!("NBR-ENFANT-REFUS-SERVIS={}", servi.as_deref().unwrap_or("absente"));
        println!("NBR-ENFANT-A-JOUE");
        return;
    }
    let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
        .args(["--exact", "--nocapture", "--test-threads=1", "tests::netban_restes_prechauffage_epuise_dit_vrai_au_journal"])
        .env(ENFANT, "1")
        .output()
        .expect("ré-exécution du binaire de test");
    let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
    assert!(stdout.contains("NBR-ENFANT-A-JOUE"), "contrôle : l'enfant a vraiment joué : {stdout}\n{stderr}");
    assert!(stdout.contains("NBR-ENFANT-PRECHAUFFAGE=None"), "contrôle : préchauffage épuisé : {stdout}");
    assert!(stdout.contains("NBR-ENFANT-REPRISE=Some(2)\n"), "contrôle : reprise à l'essai 2 : {stdout}");
    assert!(
        stdout.contains("NBR-ENFANT-REFUS-SERVIS=4\n"),
        "quatre refus (2 au préchauffage épuisé, 1 après chargement, 1 avant la reprise), servis tels quels : {stdout}"
    );
    let lignes: Vec<&str> = stderr.lines().filter(|l| l.starts_with("[plume] netban :")).collect();
    assert!(lignes.len() >= 5, "refus initial (dédupliqué), épuisement, rétabli, refus après chargement, reprise : {lignes:#?}");
    assert!(
        lignes[0].contains("refusé") && lignes[0].contains("aucun instantané encore chargé") && !lignes[0].contains("dernier bon instantané"),
        "avant tout chargement, aucun instantané à garder : {}",
        lignes[0]
    );
    assert!(lignes[1].contains("préchauffage du cache refusé 2 fois"), "l'épuisement est DIT : {}", lignes[1]);
    assert!(lignes[2].contains("rétabli"), "{}", lignes[2]);
    assert!(
        lignes[3].contains("refusé") && lignes[3].contains("dernier bon instantané") && !lignes[3].contains("aucun instantané"),
        "après un chargement réussi, l'instantané est gardé : {}",
        lignes[3]
    );
    assert_eq!(
        lignes[4..].iter().filter(|l| l.contains("préchauffage du cache réussi à l'essai 2/3")).count(),
        1,
        "la reprise dit son essai, une fois : {lignes:#?}"
    );
    for l in &lignes {
        assert!(!l.contains("198.51.100"), "ni IP au journal : {l}");
    }
}

/// Refuse la lecture de `net_ban.expires_ts` : le CHARGEMENT est refusé, la liste des écritures de la levée,
/// ses `DELETE` et l'upsert de la pose passent (aucun ne lit cette colonne).
fn nbr_refuser_le_rechargement(c: &Connection) {
    c.authorizer(Some(|ctx: rusqlite::hooks::AuthContext<'_>| match ctx.action {
        rusqlite::hooks::AuthAction::Read { table_name, column_name } if table_name == "net_ban" && column_name == "expires_ts" => {
            rusqlite::hooks::Authorization::Deny
        }
        _ => rusqlite::hooks::Authorization::Allow,
    }));
}

fn nbr_lever_le_refus(c: &Connection) {
    c.authorizer::<fn(rusqlite::hooks::AuthContext<'_>) -> rusqlite::hooks::Authorization>(None);
}

/// (5) LEVÉE RÉPONDUE = LEVÉE RÉELLE, MÊME RECHARGEMENT REFUSÉ : les deux écritures (`::ffff:` comprise) sont
/// retirées, `Ok(2)`, et l'adresse n'est plus bloquée ; le reste de l'instantané reste enforcé.
#[test]
fn netban_restes_levee_rechargement_refuse_leve_quand_meme() {
    let _g = NETBAN_TEST_LOCK.lock();
    netban_cache().write().clear();
    let c = test_db();
    nbr_poser(&c, "203.0.113.131", None);
    nbr_poser(&c, "::ffff:203.0.113.131", None);
    nbr_poser(&c, "198.51.100.131", None);
    assert!(netban_reload(&c));
    assert!(net_ban_is_blocked("203.0.113.131", now()), "contrôle positif");
    nbr_refuser_le_rechargement(&c);
    let chargement_refuse = netban_charger_cap(&c, 10).is_err();
    let r = netban_remove(&c, "203.0.113.131");
    nbr_lever_le_refus(&c);
    assert!(chargement_refuse, "contrôle : le rechargement qui suit la levée est bien refusé");
    assert_eq!(r, Ok(2), "les deux écritures sont levées");
    assert_eq!(nbr_lignes(&c), 1);
    assert!(!net_ban_is_blocked("203.0.113.131", now()), "la levée répondue ok n'est pas tenue bloquée par le cache");
    assert!(net_ban_is_blocked("198.51.100.131", now()), "le reste de l'instantané est gardé (fail-static)");
}

/// (5) POSE `Arme` = ENFORCÉE, MÊME RECHARGEMENT REFUSÉ, À SON ÉCHÉANCE : bloquée avant, LIBRE après (une pose
/// à échéance armée permanente tiendrait l'adresse bloquée tant que le store refuse) ; un ban permanent déjà
/// chargé n'est pas raccourci.
#[test]
fn netban_restes_pose_rechargement_refuse_armee_quand_meme() {
    let _g = NETBAN_TEST_LOCK.lock();
    netban_cache().write().clear();
    let c = test_db();
    nbr_poser(&c, "198.51.100.141", None);
    assert!(netban_reload(&c));
    nbr_refuser_le_rechargement(&c);
    let chargement_refuse = netban_charger_cap(&c, 10).is_err();
    let echeance = now() + 3600;
    let p = netban_upsert(&c, "203.0.113.141", Some(echeance), "t", "op", "prod");
    let p2 = netban_upsert(&c, "198.51.100.141", Some(now() - 10), "t", "op", "autre");
    nbr_lever_le_refus(&c);
    assert!(chargement_refuse, "contrôle : le rechargement qui suit la pose est bien refusé");
    assert!(matches!(p, PoseDeBan::Arme) && matches!(p2, PoseDeBan::Arme), "les poses sont écrites");
    assert_eq!(nbr_lignes(&c), 3);
    assert!(net_ban_is_blocked("203.0.113.141", now()), "une pose rendue Arme est enforcée sans attendre le tick");
    assert!(!net_ban_is_blocked("203.0.113.141", echeance + 1), "armée à SON échéance : libre une fois échue");
    assert!(net_ban_is_blocked("198.51.100.141", echeance + 1), "fusion : le permanent déjà chargé l'emporte");
}

/// (5) UNE SEULE RÈGLE DE CLÉ (`netban_cle_du_store`) pour le chargement et les deux corrections du cache :
/// sous rechargement refusé, une pose écrite `::ffff:` est armée sous la valeur REPLIÉE (celle que
/// `real_client_ip` présente), et la levée de cette même écriture la retire du cache.
#[test]
fn netban_restes_pose_et_levee_rechargement_refuse_cle_repliee() {
    let _g = NETBAN_TEST_LOCK.lock();
    netban_cache().write().clear();
    let c = test_db();
    nbr_poser(&c, "198.51.100.171", None);
    assert!(netban_reload(&c));
    nbr_refuser_le_rechargement(&c);
    let chargement_refuse = netban_charger_cap(&c, 10).is_err();
    let p = netban_upsert(&c, "::ffff:203.0.113.171", None, "t", "op", "prod");
    let arme_sous_la_valeur = net_ban_is_blocked("203.0.113.171", now());
    let r = netban_remove(&c, "::ffff:203.0.113.171");
    nbr_lever_le_refus(&c);
    assert!(chargement_refuse, "contrôle : le rechargement qui suit pose et levée est bien refusé");
    assert!(matches!(p, PoseDeBan::Arme), "contrôle : la pose est écrite");
    assert!(arme_sous_la_valeur, "la pose `::ffff:` est armée sous la clé repliée, celle que l'enforcement lit");
    assert_eq!(r, Ok(1), "contrôle : l'écriture est levée");
    assert!(!net_ban_is_blocked("203.0.113.171", now()), "la levée retire la clé repliée du cache");
    assert!(net_ban_is_blocked("198.51.100.171", now()), "le reste de l'instantané est gardé");
}

/// (5) FUSION DANS L'AUTRE SENS : le cache tient l'adresse à ÉCHÉANCE, le rechargement est refusé, une pose
/// PERMANENTE de la même adresse (autre `env_id`) est rendue `Arme` -> l'adresse reste bloquée APRÈS l'ancienne
/// échéance (permanent l'emporte). Une fusion qui garderait l'échéance la libérerait à l'heure dite.
#[test]
fn netban_restes_pose_permanente_sur_echeance_en_cache_rechargement_refuse() {
    let _g = NETBAN_TEST_LOCK.lock();
    netban_cache().write().clear();
    let c = test_db();
    let echeance = now() + 60;
    nbr_poser(&c, "203.0.113.151", Some(echeance));
    assert!(netban_reload(&c));
    assert!(net_ban_is_blocked("203.0.113.151", now()), "contrôle : l'échéance est chargée");
    assert!(!net_ban_is_blocked("203.0.113.151", echeance + 1), "contrôle : avant la pose, libre une fois échue");
    nbr_refuser_le_rechargement(&c);
    let chargement_refuse = netban_charger_cap(&c, 10).is_err();
    let p = netban_upsert(&c, "203.0.113.151", None, "t", "op", "autre");
    nbr_lever_le_refus(&c);
    assert!(chargement_refuse, "contrôle : le rechargement qui suit la pose est bien refusé");
    assert!(matches!(p, PoseDeBan::Arme), "contrôle : la pose permanente est écrite");
    assert_eq!(nbr_lignes(&c), 2);
    assert!(
        net_ban_is_blocked("203.0.113.151", echeance + 1),
        "fusion : la pose permanente l'emporte sur l'échéance déjà en cache"
    );
}

/// (6) ZÉRO ESSAI COMPTE POUR UN : sur une base saine, `netban_prechauffer(.., 0, ..)` charge au premier essai
/// et le ban persisté est enforcé ; la pause n'est jamais appelée.
#[test]
fn netban_restes_prechauffage_zero_essai_en_tente_un() {
    let _g = NETBAN_TEST_LOCK.lock();
    netban_cache().write().clear();
    let c = test_db();
    nbr_poser(&c, "198.51.100.161", None);
    let db = Mutex::new(c);
    let mut pauses = 0u32;
    let r = crate::server::boucles_de_fond::netban_prechauffer(&db, 0, || pauses += 1);
    assert_eq!(r, Some(1), "zéro essai demandé : un chargement tenté, réussi");
    assert_eq!(pauses, 0, "aucune pause pour un seul essai");
    assert!(net_ban_is_blocked("198.51.100.161", now()), "le ban persisté est enforcé");
}

/// (6) LE HELP DIT LES DEUX CAS : servi dans le corps `/metrics`, le HELP de
/// `plume_netban_chargements_refuses_total` nomme le cas d'avant tout chargement réussi (aucun ban appliqué).
#[test]
fn netban_restes_help_des_refus_dit_le_cas_d_avant_tout_chargement() {
    let c = test_db();
    let prom = nbr_prom(&c);
    let help = prom
        .lines()
        .find_map(|l| l.strip_prefix("# HELP plume_netban_chargements_refuses_total "))
        .expect("HELP du compte des refus servi");
    assert!(help.contains("avant, aucun ban n'est appliqué"), "HELP : {help}");
    assert!(help.contains("après un chargement réussi"), "HELP : {help}");
}
