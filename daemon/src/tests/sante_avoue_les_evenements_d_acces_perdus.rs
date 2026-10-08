// LA SANTÉ DE COMPOSANT AVOUE LES ÉVÉNEMENTS D'ACCÈS PERDUS (`P10.21-n`, volet santé).
//
// VU sur aa78ddd : `evenements_d_acces_non_ecrits` (échecs d'authentification, verrouillages, refus
// d'autorisation que la base a refusé d'écrire — la matière de la détection de force brute) et
// `acces_operateur_non_traces` n'étaient publiés que dans `/metrics` et `/api/metrics`. Le corps de
// `component_health` ne les lisait pas : le voyant « détection » restait VERT pendant qu'elle était
// aveugle à ses propres attaques.
//
// Les témoins n'écrivent RIEN dans les compteurs de processus (leçon `P11.24-e`) : ils INJECTENT un
// instantané `PertesDAcces`. Le câblage de production (un seul site, `PertesDAcces::du_processus`, appelé
// par `component_health`) est tenu par une garde de TEXTE, avec son témoin d'instrument fabriqué.
//
// CORRECTION (vérificateur indépendant) : le câblage de production n'avait AUCUN témoin de comportement
// (seule la garde de texte), le volet traces pouvait faire remonter un voyant rouge, et les comptes
// étaient vacants (« 2 » trouvé dans « 24h »). Le témoin de bout en bout ÉCRIT dans les compteurs de
// processus : c'est le sens robuste au parallélisme (une perte concurrente ne peut que renforcer le
// jaune, et il ne juge que SES genres) ; les autres témoins restent sur l'instantané injecté.
//
// CE QU'ILS NE TIENNENT PAS : que les sites qui COMPTENT une perte (auth.rs, rbac.rs, frein du second
// facteur) le fassent toujours — ce sont les témoins `P10.20-z` / `P10.21-g` qui le tiennent.

fn g7_pertes(genre: &str, cause: &str, n: u64, derniere: i64) -> crate::metrics::PertesDAcces {
    let mut p = crate::metrics::PertesDAcces::aucune();
    p.evenements.insert(genre.to_string(), (n, cause.to_string()));
    p.derniere_perte_evenement = derniere;
    p
}

#[test]
fn g7_une_perte_recente_jaunit_un_voyant_vert_et_nomme_genre_compte_cause() {
    use crate::metrics::etat_de_surface_pertes_d_acces as surface;
    let t = now();
    let p = g7_pertes("echec_auth", "database is locked", 3, t - 10);
    let (e, d) = surface("green", "scheduler de règles actif".into(), &p, t);
    assert_eq!(e, "yellow", "une perte d'événements d'accès n'est pas un état sain : {d}");
    assert!(d.starts_with("scheduler de règles actif ; "), "la phrase S'AJOUTE au détail : {d}");
    for attendu in [
        "3 événement(s) d'accès",
        "echec_auth : 3 (dernière cause du moteur : database is locked)",
        "depuis le démarrage",
        "la détection ne verra pas ces événements",
    ] {
        assert!(d.contains(attendu), "le détail doit nommer « {attendu} » : {d}");
    }
    // Inactif (démarrage) ne se lit pas « rien à signaler » non plus.
    assert_eq!(surface("idle", "x".into(), &p, t).0, "yellow");
}

#[test]
fn g7_l_etat_ne_peut_que_descendre_jamais_rouge_par_ce_seul_fait() {
    use crate::metrics::etat_de_surface_pertes_d_acces as surface;
    let t = now();
    let p = g7_pertes("verrouillage", "disk I/O error", 1, t);
    assert_eq!(surface("yellow", "jeu PÉRIMÉ".into(), &p, t).0, "yellow", "un voyant déjà jaune reste jaune");
    assert_eq!(surface("red", "tick AVEUGLE".into(), &p, t).0, "red", "un voyant ROUGE ne remonte JAMAIS au jaune");
    assert_ne!(surface("green", "x".into(), &p, t).0, "red", "la perte seule ne rougit pas : les règles tournent");
}

#[test]
fn g7_aucune_perte_rend_l_etat_d_avant_octet_pour_octet() {
    use crate::metrics::etat_de_surface_pertes_d_acces as surface;
    let t = now();
    let rien = crate::metrics::PertesDAcces::aucune();
    for (e, d) in [("green", "scheduler actif"), ("idle", "démarrage"), ("yellow", "jeu PÉRIMÉ"), ("red", "AVEUGLE")] {
        assert_eq!(surface(e, d.to_string(), &rien, t), (e, d.to_string()), "aucune perte : rien ne change");
    }
    // Horodatage récent mais table vide : atteignable, `du_processus` lit la table PUIS l'horodatage, et
    // le compteur pose l'horodatage AVANT d'écrire la table. Aucun « 0 événement » ne doit s'avouer.
    let mut course = crate::metrics::PertesDAcces::aucune();
    course.derniere_perte_evenement = t;
    course.derniere_perte_trace = t;
    assert_eq!(surface("green", "x".into(), &course, t), ("green", "x".to_string()), "table vide : rien à avouer");
}

#[test]
fn g7_l_aveu_est_borne_a_vingt_quatre_heures_apres_la_derniere_perte() {
    use crate::metrics::{etat_de_surface_pertes_d_acces as surface, FENETRE_D_AVEU_DES_PERTES_D_ACCES_S as F};
    let t = now();
    assert_eq!(F, 86_400, "la durée de l'aveu est une décision écrite, pas un accident");
    let dedans = g7_pertes("echec_auth", "c", 5, t - F + 60);
    assert_eq!(surface("green", "x".into(), &dedans, t).0, "yellow", "dans la fenêtre : avoué");
    let dehors = g7_pertes("echec_auth", "c", 5, t - F - 1);
    assert_eq!(
        surface("green", "x".into(), &dehors, t),
        ("green", "x".to_string()),
        "hors fenêtre : un incident unique ne jaunit pas le voyant jusqu'au redémarrage"
    );
}

#[test]
fn g7_une_trace_operateur_perdue_est_avouee_de_meme_sans_rougir() {
    use crate::metrics::etat_de_surface_pertes_d_acces as surface;
    let t = now();
    let mut p = crate::metrics::PertesDAcces::aucune();
    p.traces_operateur.insert("journal_de_controle".into(), (2, "database is full".into()));
    p.derniere_perte_trace = t - 5;
    let (e, d) = surface("green", "x".into(), &p, t);
    assert_eq!(e, "yellow", "{d}");
    for attendu in [
        "2 trace(s) d'accès opérateur cross-tenant",
        "journal_de_controle : 2 (dernière cause du moteur : database is full)",
        "depuis le démarrage",
    ] {
        assert!(d.contains(attendu), "« {attendu} » attendu : {d}");
    }
}

#[test]
fn g7_la_surface_de_detection_lit_l_instantane_injecte() {
    let c = day2_conn();
    let recente = FraicheurDesTicks { regles: now(), rollups: now() };
    let spool = crate::tmp_possede::TmpPossede::neuf("g7-pertes-spool");
    let spool = spool.to_str().unwrap();
    let dbp = "g7-pertes-d-acces";
    let detection = |p: &crate::metrics::PertesDAcces| {
        crate::metrics::component_health_avec_pertes(&c, spool, dbp, 80, recente, p)
            .into_iter()
            .find(|v| v["component"] == "detection")
            .expect("composant détection")
    };
    let sans = detection(&crate::metrics::PertesDAcces::aucune());
    assert!(
        !sans["detail"].as_str().unwrap_or_default().contains("NON ÉCRIT"),
        "instantané nul : aucun aveu — {sans}"
    );
    let avec = detection(&g7_pertes("refus_autorisation", "attempt to write a readonly database", 4, now()));
    let d = avec["detail"].as_str().unwrap_or_default();
    assert!(
        matches!(avec["state"].as_str(), Some("yellow") | Some("red")),
        "perte injectée : le voyant de détection n'est plus vert — {avec}"
    );
    assert!(
        d.contains("refus_autorisation") && d.contains("attempt to write a readonly database") && d.contains("la détection ne verra pas"),
        "le voyant NOMME la perte : {avec}"
    );
}

/// Le câblage de production : `component_health` passe ce que le PROCESSUS a compté. Garde de TEXTE
/// (lire l'ambiant depuis un témoin est ce que `P11.24-e` interdit), avec son témoin d'instrument : la
/// même source où la lecture est remplacée par `aucune()` doit être REFUSÉE.
#[test]
fn g7_component_health_de_production_derive_les_pertes_du_processus() {
    fn cable(src: &str) -> bool {
        let Some(i) = src.find("pub(crate) fn component_health(") else { return false };
        let corps = &src[i..];
        let fin = corps.find("\n}\n").unwrap_or(corps.len());
        let corps = &corps[..fin];
        corps.contains("component_health_avec_pertes(") && corps.contains("PertesDAcces::du_processus()")
    }
    let src = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/metrics.rs"))
        .expect("metrics.rs illisible : la garde refuse de conclure en silence");
    assert!(cable(&src), "`component_health` ne dérive plus les pertes d'accès du processus : le voyant redevient aveugle");
    let mutee = src.replacen("PertesDAcces::du_processus()", "PertesDAcces::aucune()", 1);
    assert!(mutee != src && !cable(&mutee), "INSTRUMENT : la garde ne voit pas un câblage retiré");
}

fn g7_traces(ventilation: &[(&str, u64, &str)], derniere: i64) -> crate::metrics::PertesDAcces {
    let mut p = crate::metrics::PertesDAcces::aucune();
    for (g, n, c) in ventilation {
        p.traces_operateur.insert(g.to_string(), (*n, c.to_string()));
    }
    p.derniere_perte_trace = derniere;
    p
}

#[test]
fn g7_une_trace_perdue_ne_fait_jamais_remonter_un_voyant_rouge() {
    use crate::metrics::etat_de_surface_pertes_d_acces as surface;
    let t = now();
    let p = g7_traces(&[("journal_de_controle", 1, "database is full")], t - 3);
    assert_eq!(surface("red", "tick AVEUGLE".into(), &p, t).0, "red", "un voyant ROUGE ne remonte JAMAIS au jaune");
    assert_eq!(surface("yellow", "x".into(), &p, t).0, "yellow");
    assert_eq!(surface("idle", "x".into(), &p, t).0, "yellow", "inactif ne se lit pas « rien à signaler »");
}

#[test]
fn g7_chaque_genre_est_nomme_avec_son_compte_et_le_total_est_leur_somme() {
    use crate::metrics::etat_de_surface_pertes_d_acces as surface;
    let t = now();
    let mut p = g7_pertes("echec_auth", "database is locked", 3, t - 2);
    p.evenements.insert("verrouillage".into(), (4, "disk I/O error".into()));
    let q = g7_traces(&[("journal_de_controle", 2, "database is full"), ("tenant_lecture", 5, "readonly database")], t - 2);
    p.traces_operateur = q.traces_operateur;
    p.derniere_perte_trace = q.derniere_perte_trace;
    let (e, d) = surface("green", "x".into(), &p, t);
    assert_eq!(e, "yellow", "{d}");
    for attendu in [
        "7 événement(s) d'accès",
        "echec_auth : 3 (dernière cause du moteur : database is locked)",
        "verrouillage : 4 (dernière cause du moteur : disk I/O error)",
        "7 trace(s) d'accès opérateur",
        "journal_de_controle : 2 (dernière cause du moteur : database is full)",
        "tenant_lecture : 5 (dernière cause du moteur : readonly database)",
    ] {
        assert!(d.contains(attendu), "« {attendu} » attendu : {d}");
    }
    assert!(!d.contains("non ventilé"), "ventilation complète : aucun écart à avouer — {d}");
    assert!(!d.contains("  "), "la phrase servie n'a pas de blancs perdus d'une continuation de chaîne : {d}");
}

#[test]
fn g7_le_total_atomique_qui_depasse_la_ventilation_s_avoue_non_ventile() {
    use crate::metrics::etat_de_surface_pertes_d_acces as surface;
    let t = now();
    let mut p = g7_pertes("echec_auth", "database is locked", 2, t - 1);
    p.total_evenements = 5;
    let (e, d) = surface("green", "x".into(), &p, t);
    assert_eq!(e, "yellow", "{d}");
    assert!(d.contains("5 événement(s) d'accès") && d.contains("non ventilé(s) : 3"), "{d}");
    // Table entière perdue (verrou empoisonné avant la première écriture) : le total suffit à avouer.
    let mut seul = crate::metrics::PertesDAcces::aucune();
    seul.total_traces = 4;
    seul.derniere_perte_trace = t;
    let (e, d) = surface("green", "x".into(), &seul, t);
    assert_eq!(e, "yellow", "{d}");
    assert!(d.contains("4 trace(s)") && d.contains("non ventilé(s) : 4"), "{d}");
}

#[test]
fn g7_une_table_au_verrou_empoisonne_n_est_pas_lue_vide() {
    let m = std::sync::Mutex::new(std::collections::BTreeMap::<String, (u64, String)>::new());
    m.lock().unwrap().insert("echec_auth".into(), (3, "database is locked".into()));
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _g = m.lock().unwrap();
        panic!("g7 : empoisonnement délibéré du verrou");
    }));
    assert!(m.is_poisoned(), "INSTRUMENT : le verrou doit être empoisonné");
    let t = crate::metrics::PertesDAcces::table(&m);
    assert_eq!(t.get("echec_auth"), Some(&(3, "database is locked".to_string())), "table lue malgré le poison : {t:?}");
}

/// LE CHEMIN DE PRODUCTION, DE BOUT EN BOUT : le compteur pose compte, cause et horodatage ;
/// `du_processus` les relit ; `component_health` (celui que servent /api/system/health et /metrics) les
/// passe à la surface. Les genres sont propres à ce témoin ; l'état attendu est « plus vert » (une
/// pollution concurrente ne peut que l'aggraver), le détail doit NOMMER ces genres-ci.
#[test]
fn g7_de_bout_en_bout_une_perte_comptee_atteint_le_voyant_de_production() {
    const GENRE: &str = "g7-genre-de-bout-en-bout";
    const TRACE: &str = "g7-trace-de-bout-en-bout";
    let avant = now();
    crate::metrics::compter_un_evenement_d_acces_non_ecrit(GENRE, "g7 cause evenement");
    crate::metrics::compter_un_acces_operateur_non_trace(TRACE, "g7 cause trace");

    let p = crate::metrics::PertesDAcces::du_processus();
    assert!(p.evenements.get(GENRE).is_some_and(|(n, c)| *n >= 1 && c == "g7 cause evenement"), "{p:?}");
    assert!(p.traces_operateur.get(TRACE).is_some_and(|(n, c)| *n >= 1 && c == "g7 cause trace"), "{p:?}");
    assert!(p.derniere_perte_evenement >= avant, "horodatage d'événement posé par le compteur : {p:?}");
    assert!(p.derniere_perte_trace >= avant, "horodatage de trace posé par le compteur : {p:?}");
    assert!(p.total_evenements >= 1 && p.total_traces >= 1, "totaux atomiques relus : {p:?}");

    let c = day2_conn();
    let spool = crate::tmp_possede::TmpPossede::neuf("g7-bout-en-bout-spool");
    let det = crate::metrics::component_health(&c, spool.to_str().unwrap(), "g7-bout-en-bout", 80)
        .into_iter()
        .find(|v| v["component"] == "detection")
        .expect("composant détection");
    let d = det["detail"].as_str().unwrap_or_default();
    assert!(matches!(det["state"].as_str(), Some("yellow") | Some("red")), "le voyant de production n'est plus vert : {det}");
    for attendu in [GENRE, "g7 cause evenement", TRACE, "g7 cause trace"] {
        assert!(d.contains(attendu), "le voyant de production NOMME « {attendu} » : {det}");
    }
}
