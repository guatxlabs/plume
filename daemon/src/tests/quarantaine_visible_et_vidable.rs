// `P4.1-v` — LA QUARANTAINE D'INGEST : NI PROFONDEUR, NI VIDANGE, NI GESTE.
//
// MESURÉ le 2026-09-03 pendant une panne réelle, et le chiffre n'existait nulle part avant d'être
// compté à la main : 760 lots, 24 028 événements — dont UN qui dormait là depuis VINGT-NEUF JOURS.
// Écarter un lot qu'on n'a pas su écrire est un BON geste, explicitement documenté « rejouable,
// aucune perte silencieuse ». LE DÉFAUT N'EST PAS L'ÉCART, C'EST QUE PERSONNE NE LE REGARDE : rien
// ne lisait ce répertoire, et le seul compte publié était celui des abandons du DERNIER PASSAGE,
// retombé à zéro dès la reprise pendant que 760 lots attendaient à côté.
//
// LES DEUX MOITIÉS SONT INDISSOCIABLES, ET C'EST LA RÈGLE ANTI-RANÇON : un compte sans geste de
// fermeture serait une accusation permanente qu'aucune action ne peut éteindre ; un geste sans
// compte laisserait le défaut invisible. Il faut les deux, ou aucun.

/// Un spool possédé, avec sa quarantaine peuplée de `n` lots.
fn spool_avec_quarantaine(nom: &str, n: usize) -> (crate::tmp_possede::TmpPossede, String) {
    let tmp = crate::tmp_possede::TmpPossede::neuf(nom);
    let spool = tmp.racine().chemin().to_str().unwrap().to_string();
    if n > 0 {
        let q = crate::state::repertoire_de_quarantaine(&spool);
        std::fs::create_dir_all(&q).unwrap();
        for i in 0..n {
            std::fs::write(format!("{q}/ingest-{i:04}.json"), b"{\"kind\":\"events\",\"events\":[]}").unwrap();
        }
    }
    (tmp, spool)
}

#[test]
fn une_quarantaine_absente_est_un_vrai_zero_une_illisible_ne_lest_pas() {
    // ABSENTE = VRAI ZÉRO, et la raison est écrite : le répertoire n'est créé qu'au premier écart,
    // donc son absence dit exactement « rien n'a jamais été écarté ». C'est la SEULE différence
    // voulue avec la profondeur de file, où un répertoire disparu est une CÉCITÉ.
    let (_t, spool) = spool_avec_quarantaine("quarantaine-absente", 0);
    assert_eq!(crate::metrics::spool_quarantine_depth(&spool).valeur(), Some(&0));

    // PRÉSENTE ET VIDE = zéro aussi, mais ce zéro-là a été COMPTÉ.
    let (_t2, spool2) = spool_avec_quarantaine("quarantaine-vide", 0);
    std::fs::create_dir_all(crate::state::repertoire_de_quarantaine(&spool2)).unwrap();
    assert_eq!(crate::metrics::spool_quarantine_depth(&spool2).valeur(), Some(&0));

    // PEUPLÉE : le compte est le compte.
    let (_t3, spool3) = spool_avec_quarantaine("quarantaine-peuplee", 7);
    assert_eq!(crate::metrics::spool_quarantine_depth(&spool3).valeur(), Some(&7));

    // ILLISIBLE : un répertoire remplacé par un FICHIER n'est pas « aucun lot écarté ».
    let (_t4, spool4) = spool_avec_quarantaine("quarantaine-illisible", 0);
    std::fs::write(crate::state::repertoire_de_quarantaine(&spool4), b"pas un repertoire").unwrap();
    let m = crate::metrics::spool_quarantine_depth(&spool4);
    assert_eq!(m.valeur(), None, "un répertoire illisible ne doit JAMAIS se lire comme un zéro");
    assert!(m.detail().is_some(), "et la cause est nommée");
}

#[test]
fn la_quarantaine_declasse_le_verdict_sans_effacer_ce_quil_disait() {
    let c = day2_conn();
    let recente = FraicheurDesTicks { regles: now(), rollups: now() };
    c.execute(
        "INSERT INTO event(ts,source,category,severity,message) VALUES(?1,'sshd','auth',1,'x')",
        params![now()],
    )
    .unwrap();

    // CONTRÔLE POSITIF D'ABORD : sans quarantaine, le composant est VERT. Sans cette moitié, le
    // témoin suivant serait vert sur un composant qui n'aurait jamais pu l'être.
    let (_t, spool) = spool_avec_quarantaine("quarantaine-surface-vide", 0);
    let sain = component_health_avec(&c, &spool, "", 80, recente);
    let ingest_sain = sain.iter().find(|v| v["component"] == "ingest").unwrap().clone();
    assert_eq!(ingest_sain["state"], "green", "événement frais + spool lisible -> vert");
    let detail_sain = ingest_sain["detail"].as_str().unwrap().to_string();

    // PUIS LE FAIT : 12 lots écartés. Le verdict DESCEND, et la phrase d'origine SUBSISTE.
    let (_t2, spool2) = spool_avec_quarantaine("quarantaine-surface-pleine", 12);
    let avec = component_health_avec(&c, &spool2, "", 80, recente);
    let ingest = avec.iter().find(|v| v["component"] == "ingest").unwrap();
    assert_eq!(ingest["state"], "yellow", "12 lots écartés : le composant ne peut plus être vert");
    let detail = ingest["detail"].as_str().unwrap();
    assert!(
        detail.starts_with(&detail_sain),
        "la quarantaine s'AJOUTE, elle n'écrase pas ce que le détail disait déjà :\n  avant : {detail_sain}\n  après : {detail}"
    );
    assert!(detail.contains("12 lot"), "le COMPTE est dans la phrase : {detail}");
    assert!(
        detail.contains("spool-requeue"),
        "et le GESTE qui la vide est nommé — un compte sans geste serait une rançon : {detail}"
    );
    // La valeur est SERVIE, pas seulement racontée.
    assert_eq!(ingest["quarantine_depth"], 12);
}

#[test]
fn le_geste_vide_la_quarantaine_et_la_simulation_ne_deplace_rien() {
    let (_t, spool) = spool_avec_quarantaine("quarantaine-geste", 5);
    let q = crate::state::repertoire_de_quarantaine(&spool);

    // SIMULATION : elle ANNONCE cinq lots et n'en bouge AUCUN.
    let blanc = crate::state::remettre_la_quarantaine_en_file(&spool, true).unwrap();
    assert_eq!(blanc.trouves.len(), 5);
    assert_eq!(blanc.remis, 0, "une simulation ne déplace rien");
    assert_eq!(crate::metrics::spool_quarantine_depth(&spool).valeur(), Some(&5), "et la quarantaine est intacte");

    // GESTE RÉEL : les cinq reviennent dans la file, la quarantaine retombe à zéro.
    let fait = crate::state::remettre_la_quarantaine_en_file(&spool, false).unwrap();
    assert_eq!(fait.remis, 5);
    assert!(fait.refuses.is_empty());
    assert_eq!(crate::metrics::spool_quarantine_depth(&spool).valeur(), Some(&0));
    assert_eq!(
        crate::metrics::spool_queue_depth(&spool).valeur(),
        Some(&5),
        "les lots sont dans la FILE, pas effacés — c'est la seule chose qui fasse du compte autre chose qu'une rançon"
    );
    assert!(std::fs::read_dir(&q).unwrap().next().is_none(), "plus rien en quarantaine");

    // Rejouer le geste sur une quarantaine vide ne rend ni erreur ni faux travail.
    let encore = crate::state::remettre_la_quarantaine_en_file(&spool, false).unwrap();
    assert!(encore.trouves.is_empty());
}

#[test]
fn un_ecart_impossible_avoue_la_destruction_au_lieu_de_promettre_une_mise_a_lecart() {
    // LE POINT : la branche de dernier recours EFFACE le lot, et la ligne annonçait pourtant
    // « quarantaine » — elle promettait un lot conservé et examinable là où il ne restait rien.
    // La fabrication rend le déplacement IMPOSSIBLE par construction : la quarantaine est un
    // FICHIER, donc ni sa création ni le renommage vers elle ne peuvent aboutir.
    let tmp = crate::tmp_possede::TmpPossede::neuf("quarantaine-impossible");
    let spool = tmp.racine().chemin().to_str().unwrap().to_string();
    std::fs::write(crate::state::repertoire_de_quarantaine(&spool), b"pas un repertoire").unwrap();
    let lot = format!("{spool}/ingest-perdu.json");
    std::fs::write(&lot, b"{}").unwrap();

    crate::state::quarantine_spool_file(&spool, std::path::Path::new(&lot), "ingest-perdu.json", "essai");

    // Le fichier a bien DISPARU — c'est le comportement, et il est délibéré (sans quoi la file
    // bouclerait dessus). Ce qui change, c'est que l'aveu ne le maquille plus en mise à l'écart.
    assert!(!std::path::Path::new(&lot).exists(), "le dernier recours efface, et c'est assumé");
    // Et il n'est nulle part ailleurs : rien ne l'a « mis à l'écart ».
    assert_eq!(
        crate::metrics::spool_quarantine_depth(&spool).valeur(),
        None,
        "la quarantaine est inutilisable — la mesure le dit au lieu de rendre zéro"
    );
}

#[test]
fn laveu_nomme_ce_qui_est_arrive_au_lot_et_ne_dit_quarantaine_que_sil_y_est() {
    use crate::state::{aveu_de_mise_a_lecart, Ecart};
    let q = "/data/spool/quarantine";

    // ÉCARTÉ : le mot « quarantaine » est JUSTE, et il reste.
    let ecarte = aveu_de_mise_a_lecart("events INSERT échoué", "lot.json", q, Ecart::Ecarte);
    assert!(ecarte.contains("quarantaine"), "un lot vraiment écarté le dit : {ecarte}");
    assert!(ecarte.contains("lot.json"));

    // DÉTRUIT : le lot n'existe plus. Le mot « quarantaine » y serait un MENSONGE — il promettrait
    // un contenu conservé et examinable là où il ne reste rien.
    let detruit = aveu_de_mise_a_lecart("events INSERT échoué", "lot.json", q, Ecart::Detruit);
    assert!(detruit.contains("DÉTRUIT"), "la destruction se NOMME : {detruit}");
    assert!(
        detruit.contains("n'est plus rejouable"),
        "et la conséquence est écrite, pas laissée à déduire : {detruit}"
    );
    assert!(
        !detruit.contains("-> quarantaine :"),
        "un lot détruit ne doit JAMAIS être annoncé comme mis en quarantaine : {detruit}"
    );

    // LAISSÉ EN PLACE : encore un autre cas, et il n'est ni l'un ni l'autre.
    let reste = aveu_de_mise_a_lecart("events INSERT échoué", "lot.json", q, Ecart::Reste);
    assert!(reste.contains("LAISSÉ EN PLACE"), "{reste}");
    assert!(!reste.contains("-> quarantaine :"), "{reste}");
    assert_ne!(reste, detruit, "les trois issues rendent trois phrases DISTINCTES");
}
