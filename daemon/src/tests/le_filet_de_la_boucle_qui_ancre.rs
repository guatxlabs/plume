    // ================================================================================================
    // LE FILET DE LA BOUCLE QUI ANCRE — `P10.7-w`, mesuré le 2026-08-31.
    //
    // CE QUI A ÉTÉ MESURÉ SUR CET ARBRE, AVANT DE CORRIGER (`server/boucles_de_fond.rs`) :
    //   · `spawn_retention_loop` — la SEULE boucle qui appelle `retention_run_tenant`, donc la seule
    //     qui ANCRE la chaîne d'intégrité (`sign_checkpoint`) — ne publiait AUCUN bilan et ne portait
    //     AUCUN filet. Elle n'a même pas de compteur de tick : les seuls sont `SCHED_RULE_*` et
    //     `SCHED_ROLLUP_*`. Un panic dans la passe tuait le fil, et RIEN ne l'aurait dit ;
    //   · l'énoncé « ses trois voisines font les deux » est à moitié FAUX : connecteurs, destinations
    //     et rapports PUBLIENT bien un bilan (après la passe), mais AUCUNE ne porte de `catch_unwind`
    //     au niveau de sa boucle — leur protection est PAR ÉLÉMENT, à l'intérieur de l'appelé. Le seul
    //     filet de BOUCLE du fichier est celui de `spawn_rule_scheduler` (par tenant), et c'est lui
    //     qui a servi de forme : il REPREND, il avoue par le bilan, il continue les autres tenants.
    //
    // CE QUE CETTE GARDE TIENT, ET CE QU'ELLE NE TIENT PAS. Les témoins de comportement vivent dans
    // `server/boucles_de_fond.rs` (module `filet_de_l_ancrage`) parce que `mod boucles_de_fond;` est
    // PRIVÉ : ils exercent la passe avec un incident FABRIQUÉ. Ils ne peuvent RIEN dire du CÂBLAGE —
    // que la boucle de production passe bien par le filet. C'est ce que cette garde relit dans la
    // source. Elle ne prouve pas davantage que la boucle TOURNE : comme la garde de cadence de
    // `P10.7-v`, elle lit un texte, et c'est écrit ici pour que personne ne lui prête plus.
    //
    // L'INSTRUMENT EST VALIDÉ DANS LES DEUX SENS SUR DES CORPUS FABRIQUÉS — dont l'état EXACT de
    // l'arbre AVANT ce lot — avant d'être cru : un lecteur qui accepterait tout, ou qui refuserait
    // tout, serait vert par construction dans un des deux sens.
    // ================================================================================================

    /// La tranche de texte de `fn <nom>(`, jusqu'à la fonction suivante en colonne zéro. `Err` nomme ce
    /// qui manque — une tranche qu'on ne sait pas découper ne vaut JAMAIS « aucune contrainte ».
    fn flt_corps_de<'a>(source: &'a str, nom: &str) -> Result<&'a str, String> {
        let entete = format!("fn {nom}(");
        let debut = source.find(&entete).ok_or_else(|| format!("fonction `{nom}` introuvable"))?;
        let corps = &source[debut..];
        let fin = corps[1..].find("\nfn ").map(|i| i + 1).unwrap_or(corps.len());
        Ok(&corps[..fin])
    }

    /// LE VERDICT : le passage de rétention de ce corps est-il SOUS FILET ? Trois faits, et l'ordre
    /// compte — le premier est celui de l'arbre d'AVANT, et c'est celui qu'il faut nommer.
    fn flt_le_passage_est_sous_filet(corps: &str) -> Result<(), String> {
        if corps.contains("for_each_active_tenant(") {
            return Err(
                "la boucle parcourt les tenants ELLE-MÊME (`for_each_active_tenant(`) : le passage \
                 échappe au filet, et un panic dans la passe tue le fil qui ANCRE le journal"
                    .to_string(),
            );
        }
        if !corps.contains("passe_de_retention_sous_filet(") {
            return Err("la boucle ne passe plus par `passe_de_retention_sous_filet(` : ni filet, ni bilan".to_string());
        }
        if !corps.contains("retention_run_tenant(") {
            return Err("la boucle ne fait plus la passe de rétention : il n'y a plus rien à protéger, ni à ancrer".to_string());
        }
        Ok(())
    }

    /// LE CÂBLAGE — LA BOUCLE QUI ANCRE NE PARCOURT PLUS LES TENANTS ELLE-MÊME.
    ///
    /// Ce que la garde ferme : les témoins de comportement prouvent que `passe_de_retention_sous_filet`
    /// rattrape, avoue et reprend ; rien, chez eux, n'empêcherait la boucle de production de reprendre
    /// un jour son `for_each_active_tenant` nu et de redevenir mortelle en silence.
    #[test]
    fn le_passage_de_retention_ne_peut_plus_echapper_au_filet() {
        // ---- ① L'INSTRUMENT, SUR DES CORPUS FABRIQUÉS. ----
        let avant = "fn f() {\n    loop {\n        for_each_active_tenant(&t, |_a, h, p| { retention_run_tenant(h, p); });\n    }\n}\n";
        let refus = flt_le_passage_est_sous_filet(flt_corps_de(avant, "f").expect("tranche découpée"))
            .expect_err("L'ÉTAT DE L'ARBRE AVANT CE LOT doit être REFUSÉ, sinon la garde ne garde rien");
        assert!(
            refus.contains("for_each_active_tenant("),
            "le refus NOMME le site fautif — un refus sans le site ne se répare pas : {refus}"
        );

        let apres = "fn f() {\n    loop {\n        passe_de_retention_sous_filet(&t, |h, p| retention_run_tenant(h, p));\n    }\n}\n";
        assert!(
            flt_le_passage_est_sous_filet(flt_corps_de(apres, "f").expect("tranche découpée")).is_ok(),
            "un lecteur qui refuserait AUSSI la forme corrigée refuserait tout, et ne mesurerait rien"
        );

        let sans_passe = "fn f() {\n    loop {\n        passe_de_retention_sous_filet(&t, |_h, _p| {});\n    }\n}\n";
        assert!(
            flt_le_passage_est_sous_filet(flt_corps_de(sans_passe, "f").expect("tranche découpée")).is_err(),
            "un filet posé sur une passe VIDE n'ancre rien : la garde doit le dire"
        );

        assert!(flt_corps_de(apres, "g").is_err(), "une fonction absente est un refus, pas un vide");

        let voisine_apres = "fn f() {\n    loop {\n        passe_de_retention_sous_filet(&t, |h, p| retention_run_tenant(h, p));\n    }\n}\nfn g() {\n    for_each_active_tenant(&t, |_a, h, p| { autre(h, p); });\n}\n";
        assert!(
            flt_le_passage_est_sous_filet(flt_corps_de(voisine_apres, "f").expect("tranche découpée")).is_ok(),
            "la tranche s'arrête à la fonction SUIVANTE : déborder ferait accuser `f` du corps de `g`"
        );

        // ---- ② LA MESURE, SUR LE VRAI CORPS. ----
        let boucles = include_str!("../server/boucles_de_fond.rs");
        let corps = flt_corps_de(boucles, "spawn_retention_loop")
            .expect("la boucle qui ancre doit rester lisible : sinon son câblage n'est plus établi");
        if let Err(pourquoi) = flt_le_passage_est_sous_filet(corps) {
            panic!(
                "LA BOUCLE QUI ANCRE LE JOURNAL D'INTÉGRITÉ N'EST PLUS SOUS FILET — {pourquoi}. Un \
                 incident y tue le fil : l'ancrage s'arrête, et le seul verdict qui le verrait \
                 (`ledger::ancrage_en_retard`, `P10.7-v`) demande qu'on aille le LIRE."
            );
        }
    }
