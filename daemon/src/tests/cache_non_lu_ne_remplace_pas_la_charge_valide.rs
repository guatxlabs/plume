// =====================================================================================
// `P10.32-o` — UNE LIGNE DE CACHE NON LUE N'EST PAS UNE ABSENCE : LA CHARGE UTILE VALIDE QU'ELLE CACHE N'EST PAS ÉCRASÉE.
//
// LE DÉFAUT, RELEVÉ PAR LE VÉRIFICATEUR SUR 44c6fe39 (sonde rejouée ici) : `panneau_avoue::cache_lire` comptait et
// journalisait une lecture refusée, mais rendait encore `None`. Sur le chemin d'échec à la demande,
// `dashboards::joindre_l_echec_a_la_charge_valide` en faisait `Aucune`, puis `memoriser_l_echec_du_rafraichissement`
// écrivait le corps d'échec PAR-DESSUS une charge valide périmée (`{rows:[[42]]}` devenait
// `{classe_d_echec:moteur, error, rows:[]}`), contre le contrat « une charge utile VALIDE périmée n'est pas écrasée par un
// échec ». La ligne WARN disait « recalculée comme une absence » à un site où rien n'est recalculé.
//
// LE CORRECTIF : `cache_lire_dit` rend QUATRE issues (`Lue`, `Absente`, `Illisible` : ligne présente sans charge valide,
// `NonLue` : lecture refusée par le moteur). Sur `NonLue`, `joindre` rend `IssueDeLaChargeValide::NonLue` et RIEN n'est
// écrit (à la demande comme au pré-chauffage) ; `serve_swr` sert un MISS. Chaque site dit SA phrase.
//
// CE QUE CES TÉMOINS JUGENT, dans UN sous-processus (compte de PRODUCTION par processus, lignes de journal ENTIÈRES ou
// bornées début/fin quand la cause est un texte du moteur) ; l'autorisateur refuse `Read panel_cache.payload` sur la
// connexion de l'écrivain :
//  (A) à la demande, `consigner_l_issue_du_rafraichissement(Ok(Err(Moteur)))` sur une charge valide périmée : charge
//      INTACTE à l'octet, instant de calcul inchangé ; ligne `[panel] WARN … ligne de cache NON LUE : … — rien d'écrit` ;
//  (B) par la ROUTE `panel_data` : corps `warming` sans ligne, ligne `[panel] WARN ligne de cache NON LUE, panneau #… —
//      servie comme un MISS …` ; le rafraîchissement armé échoue (panneau en panne) et n'écrit rien non plus ;
//  (C) au pré-chauffage : ligne `[cache] WARN pré-chauffage … ligne de cache NON LUE : … — rien d'écrit`, charge intacte ;
//  contrôle : autorisateur retiré, le même échec à la demande JOINT l'aveu à la charge (le chemin n'est pas inerte) ;
//  compte : 0 puis 1, 2, 3, 4 après chaque lecture refusée.
// MUTANTS JOUÉS (`VERIF_MUT` sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE : `CNL_JOINDRE_ABSENCE`
// (`NonLue` tenue pour une absence dans `joindre`, le défaut), `CNL_NONLUE_ILLISIBLE` (lecture refusée classée
// `Illisible`), `CNL_MEMO_PHRASE` (phrase d'avant au site de l'échec), `CNL_SWR_MUET` (MISS servi sans ligne),
// `CNL_PRECH_MUET` (pré-chauffage sans ligne).
// CE QUE CES TÉMOINS NE TIENNENT PAS : une charge valide présente derrière une lecture refusée n'est pas servie (on ne
// peut pas la lire) : la route sert `warming` tant que la lecture est refusée ; le tenant n'est pas nommé par les lignes
// `[panel] … panneau #` et `[cache]` (ni `serve_swr` ni le pré-chauffage ne l'écrivent à ce site).
// =====================================================================================
mod cache_non_lu_ne_remplace_pas_la_charge_valide {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const CNL_TEXTE: &str = "cnl texte du moteur";
    const CNL_REFUS: &str = "access to panel_cache.payload is prohibited [code étendu 23]";

    fn cnl_charge() -> String {
        json!({ "columns": ["a"], "rows": [[42]] }).to_string()
    }

    fn cnl_refuser_la_lecture(st: &AppState) {
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name: "panel_cache", column_name: "payload" } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn cnl_permettre_la_lecture(st: &AppState) {
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    #[tokio::test]
    async fn cnl_lecture_refusee_n_ecrase_pas_la_charge_valide() {
        const ENFANT: &str = "CNL_ENFANT_CACHE_NON_LU";
        if std::env::var(ENFANT).is_ok() {
            let _env = VERROU_ENV_PROCESSUS.read(); // panel_data, panel_serve_cfg_de et le pré-chauffage lisent load_config()
            let (st, dbp, gxql, panne, sain) = t3c_state("cnl-non-lu");
            let au = t3c_admin();
            let from = t3c_from();
            let (rk, fp, ttl) = t3c_cle(&st, panne, from);
            assert!(ttl > 0, "prémisse : le cache des panneaux est actif");
            let (ttl_global, _) = panel_serve_cfg_de(&load_config());
            let calcule = now() - ttl - 5;
            {
                let conn = st.db.lock();
                conn.execute("UPDATE panel SET panel_cache_ttl_s=0 WHERE id IN (?1,?2)", params![gxql, sain]).unwrap();
                panneau_avoue::cache_ecrire(&conn, panne, &rk, &fp, calcule, &cnl_charge());
            }
            let echec = || crate::query_exec::EchecDeRequete::Moteur { nature: "cnl nature".into(), texte: CNL_TEXTE.into() };
            let mut comptes = vec![panneau_avoue::lectures_de_cache_refusees()];
            cnl_refuser_la_lecture(&st);
            eprintln!("CNL-DEBUT");
            // (A) à la demande
            consigner_l_issue_du_rafraichissement(&st.db, "default", panne, &rk, &fp, calcule + 1, from, ttl_global, Ok(Err(echec())));
            comptes.push(panneau_avoue::lectures_de_cache_refusees());
            // (B) par la route, puis le rafraîchissement armé (en panne)
            let (code, corps) = t3c_json(panel_data(State(st.clone()), Extension(au.clone()), Path(panne), t3c_q(from)).await).await;
            t3c_attendre_la_tache(&st).await;
            comptes.push(panneau_avoue::lectures_de_cache_refusees());
            // (C) pré-chauffage
            crate::rollups::cache_refresh_all_panels(&st.db, dbp.as_str(), &st.refresh_sem);
            comptes.push(panneau_avoue::lectures_de_cache_refusees());
            eprintln!("CNL-FIN");
            cnl_permettre_la_lecture(&st);
            let apres = panneau_avoue::cache_lire(&st.db.lock(), panne, &rk, &fp);
            // contrôle : lecture permise, le même échec JOINT l'aveu (le chemin n'est pas inerte).
            consigner_l_issue_du_rafraichissement(&st.db, "default", panne, &rk, &fp, calcule + 2, from, ttl_global, Ok(Err(echec())));
            let controle = panneau_avoue::cache_lire(&st.db.lock(), panne, &rk, &fp);
            println!("CNL-ID:{panne}");
            println!("CNL-CALCULE:{calcule}");
            println!("CNL-ROUTE:{code}|{corps}");
            println!("CNL-APRES:{apres:?}");
            println!("CNL-CONTROLE:{controle:?}");
            println!("CNL-COMPTES:{comptes:?}");
            ff_rm(&dbp);
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::cache_non_lu_ne_remplace_pas_la_charge_valide::cnl_lecture_refusee_n_ecrase_pas_la_charge_valide",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let lire = |cle: &str| stdout.split_once(cle).map(|(_, r)| r.lines().next().unwrap_or("")).unwrap_or("").to_string();
        let id = lire("CNL-ID:");
        let calcule: i64 = lire("CNL-CALCULE:").parse().unwrap_or_else(|_| panic!("contrôle : instant de calcul : {stdout}"));
        assert!(!id.is_empty(), "contrôle : panneau nommé : {stdout}");

        // Charge intacte à l'octet, instant de calcul inchangé, après (A), (B) et (C).
        assert_eq!(lire("CNL-APRES:"), format!("Some(({:?}, {calcule}))", cnl_charge()), "charge valide INTACTE : {stdout}");
        // (B) le corps servi : un MISS.
        let route = lire("CNL-ROUTE:");
        let (code, corps) = route.split_once('|').unwrap_or_else(|| panic!("contrôle : route : {stdout}"));
        assert_eq!(code, "200", "route : {route}");
        let corps: Value = serde_json::from_str(corps).unwrap_or_else(|_| panic!("contrôle : corps JSON : {route}"));
        assert_eq!(corps["warming"], json!(true), "servi comme un MISS : {corps}");
        assert_eq!(corps["rows"], json!([]), "aucune ligne servie : {corps}");
        // Contrôle : lecture permise, l'aveu est joint à la charge.
        let attendu_controle = json!({
            "columns": ["a"],
            "rows": [[42]],
            "stats": { "rafraichissement_en_echec": {
                "cause": "requête REFUSÉE par le moteur (ce n'est pas un résultat vide) : syntaxe, champ, motif ou accès rejeté — rien n'est rendu ; le détail est au journal de l'exploitant.",
                "echoue_a": calcule + 2
            } }
        });
        assert_eq!(
            lire("CNL-CONTROLE:"),
            format!("Some(({:?}, {calcule}))", attendu_controle.to_string()),
            "contrôle positif : lecture permise, l'aveu est joint : {stdout}"
        );
        assert_eq!(lire("CNL-COMPTES:"), "[0, 1, 3, 4]", "compte de production : une lecture refusée par site : {stdout}");

        let fenetre = stderr
            .split_once("CNL-DEBUT")
            .and_then(|(_, r)| r.split_once("CNL-FIN"))
            .map(|(c, _)| c)
            .unwrap_or_else(|| panic!("contrôle : fenêtre de journal : {stderr}"));
        let lignes: Vec<&str> = fenetre.lines().filter(|l| l.contains("NON LUE")).collect();
        assert_eq!(lignes.len(), 4, "quatre lignes NON LUE (A, B route, B rafraîchissement, C) : {fenetre}");
        let a = format!(
            "[panel] WARN rafraîchissement du panneau {id} en échec ({CNL_TEXTE}) — /api/panels/{{id}}/data, tenant 'default' \
             — ligne de cache NON LUE : {CNL_REFUS} (lecture de cache ratée n° 1 depuis le démarrage) — rien d'écrit, une \
             charge utile précédente y reste intacte"
        );
        assert_eq!(lignes[0], a, "(A) ligne entière");
        let b = format!(
            "[panel] WARN ligne de cache NON LUE, panneau #{id} : {CNL_REFUS} (lecture de cache ratée n° 2 depuis le \
             démarrage) — servie comme un MISS (corps `warming`, rafraîchissement armé si le panneau compile)"
        );
        assert_eq!(lignes[1], b, "(B) ligne de la route, entière");
        let b2_debut = format!("[panel] WARN rafraîchissement du panneau {id} en échec (");
        let b2_fin = format!(
            ") — /api/panels/{{id}}/data, tenant 'default' — ligne de cache NON LUE : {CNL_REFUS} (lecture de cache ratée \
             n° 3 depuis le démarrage) — rien d'écrit, une charge utile précédente y reste intacte"
        );
        assert!(lignes[2].starts_with(&b2_debut) && lignes[2].ends_with(&b2_fin), "(B) rafraîchissement armé : {}", lignes[2]);
        let c_debut = format!("[cache] WARN pré-chauffage du panneau {id} en échec (");
        let c_fin = format!(") — ligne de cache NON LUE : {CNL_REFUS} (lecture de cache ratée n° 4 depuis le démarrage) — rien d'écrit");
        assert!(lignes[3].starts_with(&c_debut) && lignes[3].ends_with(&c_fin), "(C) pré-chauffage : {}", lignes[3]);
        assert!(!fenetre.contains("corps d'échec servi"), "aucun corps d'échec écrit : {fenetre}");
    }
}
