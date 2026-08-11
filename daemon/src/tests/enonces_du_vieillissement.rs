// `P10.13-a` — LA DÉRIVATION EST-ELLE VRAIMENT UNE DÉRIVATION ?
//
// L'instrument `cold-aging-plan` ne vaut que si les énoncés qu'il rejoue sont CEUX QUE LA PASSE
// EXÉCUTE. « Un développeur pensera à mettre à jour les deux » n'est pas une garantie : c'est
// exactement le genre de promesse que cette campagne remplace par des gardes. Le compilateur ferme la
// moitié du problème (un énoncé déplacé dans `cold_store::enonces` n'a plus qu'une définition, donc les
// deux consommateurs changent ensemble) ; il ne ferme PAS l'autre moitié — RIEN dans le langage
// n'empêche d'écrire un `SELECT` tout neuf en dur dans `aging.rs` demain.
//
// C'est cette moitié-là que ce fichier ferme, en LISANT LES SOURCES. Il n'ÉNUMÈRE aucun énoncé : il
// refuse la CATÉGORIE (« un littéral de chaîne contenant `SELECT` ») dans les trois modules du
// vieillissement. Un énoncé de lecture ajouté demain fait rougir la suite le jour où il est ajouté.
//
// CE TEST TOURNE DANS LE PROFIL PAR DÉFAUT, où `cold_store` n'est même pas compilé — comme
// `la_passe_ne_peut_pas_sortir_sans_publier`, et pour la même raison : la garde doit mordre dans la
// CI ordinaire, pas seulement dans le job `--features cold_tier`.

#[cfg(test)]
mod enonces_du_vieillissement_tests {
    use std::path::PathBuf;

    /// Les trois modules du vieillissement. Ce n'est PAS une liste d'énoncés (ce serait l'énumération
    /// qu'on refuse) : c'est le PÉRIMÈTRE de la règle, et il est vérifié — chacun doit exister et porter
    /// du code, sinon le scanner passerait sur du vide en rendant « vert ».
    const MODULES_DU_VIEILLISSEMENT: [&str; 3] =
        ["src/cold_store/aging.rs", "src/cold_store/seal.rs", "src/cold_store/writer.rs"];

    /// LE MODULE OÙ LES ÉNONCÉS DOIVENT VIVRE.
    const MODULE_DES_ENONCES: &str = "src/cold_store/enonces.rs";

    fn racine() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    /// LE DÉTECTEUR — PUR, donc validable sur des témoins avant d'être cru sur du vrai code. Une ligne
    /// « porte un énoncé » si elle contient un guillemet ET le mot-clé `SELECT`. La règle est TEXTUELLE
    /// (un scanner ne parse pas du SQL) et donc FAIL-CLOSED : elle attrape aussi une ÉCRITURE qui
    /// contient une sous-requête, et cet énoncé-là a déménagé dans `enonces` lui aussi.
    fn porte_un_enonce_de_lecture(ligne: &str) -> bool {
        ligne.contains('"') && ligne.contains("SELECT")
    }

    /// LA VALIDATION DE L'INSTRUMENT, avant de lui faire confiance sur 1 500 lignes de source. Sans
    /// elle, un détecteur cassé (qui ne trouverait jamais rien) rendrait ce fichier VERT pour toujours
    /// — la panne la plus silencieuse qu'un scanner puisse avoir.
    #[test]
    fn le_detecteur_denonces_voit_ce_quil_doit_voir_et_rien_dautre() {
        for temoin in [
            r#"    let sql = format!("SELECT env_id FROM event WHERE ts>=?1");"#,
            r#"    conn.prepare("SELECT COALESCE(MAX(id),0) FROM event")"#,
            r#"        "UPDATE cold_seal SET last_file=1 WHERE seq=(SELECT MAX(seq) FROM cold_seal)","#,
        ] {
            assert!(porte_un_enonce_de_lecture(temoin), "témoin POSITIF non détecté : {temoin}");
        }
        for innocent in [
            "    let sql = sql_decouverte_des_jours();",
            "    conn.execute(SQL_SCELLER_DERNIER_FICHIER, params![env_id, day]).map_err(pe)?;",
            r#"        let _ = conn.execute_batch("ALTER TABLE cold_seal ADD COLUMN dim_stats BLOB");"#,
            "    // la découverte fait un SELECT sur event — ceci est un commentaire, pas un énoncé",
        ] {
            assert!(!porte_un_enonce_de_lecture(innocent), "faux positif : {innocent}");
        }
    }

    /// AUCUN ÉNONCÉ DE LECTURE NE VIT HORS DU MODULE `enonces`. C'est LA garantie que la sonde de
    /// lecture seule mesure la passe et pas une copie : si un `SELECT` peut naître ailleurs, la sonde
    /// devient une fiction entretenue à la main.
    ///
    /// MUTATION (exécutée le 2026-08-11) : remettre le texte de la requête de découverte en dur dans
    /// `aging.rs` (`let sql = format!("SELECT env_id, ts/{SECS_PER_DAY} …")`) ⇒ ce test rougit en
    /// nommant `src/cold_store/aging.rs:<ligne>`, et il est le SEUL à rougir (le code compile et se
    /// comporte à l'identique — c'est précisément pourquoi seule une garde de SOURCE l'attrape).
    #[test]
    fn aucun_enonce_de_lecture_ne_vit_hors_du_module_enonces() {
        let racine = racine();
        // PRÉCONDITION : le module des énoncés existe ET porte bien des énoncés. Sinon la règle
        // ci-dessous serait satisfaite par un dépôt où plus personne n'interroge rien.
        let enonces = std::fs::read_to_string(racine.join(MODULE_DES_ENONCES))
            .unwrap_or_else(|e| panic!("{MODULE_DES_ENONCES} illisible ({e}) — la dérivation n'a plus de siège"));
        let portes = enonces.lines().filter(|l| porte_un_enonce_de_lecture(l)).count();
        assert!(
            portes >= 6,
            "seulement {portes} énoncé(s) dans {MODULE_DES_ENONCES} : soit ils ont fui ailleurs, soit \
             ce test ne regarde plus le bon fichier"
        );

        let mut fautifs: Vec<String> = Vec::new();
        let mut lignes_examinees = 0usize;
        for module in MODULES_DU_VIEILLISSEMENT {
            let chemin = racine.join(module);
            let src = std::fs::read_to_string(&chemin)
                .unwrap_or_else(|e| panic!("{module} illisible ({e}) — le périmètre de la règle a bougé"));
            // Commentaires et items `#[cfg(test)]` RETIRÉS par le même extracteur que la garde de LA
            // PORTE : la prose parle légitimement de `SELECT`, et un test n'est pas du code de passe.
            let production = crate::db_open::door_tests::texte_de_production(&chemin, &src);
            assert!(
                production.len() > 100,
                "{module} : seulement {} ligne(s) de production extraites -> l'extracteur a raté le \
                 fichier et ce test ne garderait rien",
                production.len()
            );
            lignes_examinees += production.len();
            for (no, ligne) in production {
                if porte_un_enonce_de_lecture(&ligne) {
                    fautifs.push(format!("{module}:{no} — {}", ligne.trim()));
                }
            }
        }
        assert!(
            fautifs.is_empty(),
            "{} énoncé(s) SQL écrits EN DUR dans les modules du vieillissement (sur {lignes_examinees} \
             lignes de production examinées). La sonde `cold-aging-plan` ne les rejouera JAMAIS : elle \
             mesurerait donc une passe qui n'est plus celle qui tourne. Les déplacer dans \
             {MODULE_DES_ENONCES} et les appeler des deux côtés.\n  {}",
            fautifs.len(),
            fautifs.join("\n  ")
        );
    }

    /// LES BORNES AUSSI SONT DÉRIVÉES. Un même SQL exécuté sur d'autres bornes ne mesure pas la même
    /// chose : si `balayer` recalculait sa fenêtre en ligne, la sonde pourrait planifier la bonne
    /// requête sur la mauvaise bande et rendre un plan qui n'a jamais eu lieu. On vérifie donc, DANS LE
    /// SOURCE, que le corps de `balayer` consomme la `Bande` partagée au lieu de refaire le calcul.
    ///
    /// MUTATION : remettre `let hot_cutoff = n - hot_window * SECS_PER_DAY; let hi_day_excl = …` dans
    /// `balayer` et boucler dessus ⇒ `bande.ouverte()` / `bande.bornes_de_decouverte()` disparaissent du
    /// corps et les assertions rougissent.
    #[test]
    fn la_passe_consomme_la_bande_partagee_au_lieu_de_recalculer_ses_bornes() {
        let src = std::fs::read_to_string(racine().join("src/cold_store/aging.rs")).expect("aging.rs lisible");
        let debut = src
            .find("fn balayer(")
            .expect("`balayer` a été renommée -> ce test ne garde plus rien, il doit être relu");
        let corps = &src[debut..];
        let fin = corps.find("\n}\n").expect("fin du corps de `balayer` introuvable");
        let corps = &corps[..fin];
        assert!(
            corps.len() > 1000 && corps.contains("PLUME_DB_KEY"),
            "extraction du corps de `balayer` ratée ({} octets) — ce test mentirait",
            corps.len()
        );
        for attendu in ["Bande::calculer(", "bande.ouverte()", "bande.bornes_de_decouverte()", "bande.retenu("] {
            assert!(
                corps.contains(attendu),
                "`balayer` n'utilise plus `{attendu}` -> la passe et la sonde peuvent diverger sur les \
                 BORNES sans qu'aucun compilateur ne s'en aperçoive"
            );
        }
    }
}
