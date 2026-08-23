    // ================================================================================================
    // P11.13-a — LA REQUÊTE D'UNE RÈGLE, RENDUE RÉUTILISABLE PAR UN PANNEAU.
    //
    // CE QUI A ÉTÉ MESURÉ (2026-08-23, par lecture du code servi) : la dérivation qui rend la requête
    // d'une règle exécutable telle quelle — retirer l'étage `stats` scalaire terminal, celui que le
    // moteur réduit à un nombre — EXISTE, elle est testée, elle est en production… et elle n'est servie
    // que sur `/api/alerts`. Elle n'est donc atteignable que depuis une alerte DÉJÀ levée ; la règle
    // elle-même n'offrait sa requête que dans une infobulle du catalogue. Rien à réécrire, un chemin à
    // ouvrir — et c'est le sens de la clé : composer À PARTIR de ce qui existe.
    //
    // CE QUE CE TEST TIENT :
    //   1. GXQL : l'étage scalaire terminal est retiré (le panneau rend les lignes, pas le nombre) ;
    //      sans étage scalaire terminal, la requête est rendue ENTIÈRE.
    //   2. SQL BRUT : la requête est rendue INTACTE, marqueurs de fenêtre compris — c'est ce qui la rend
    //      réutilisable, un panneau les substituant lui-même à chaque rendu. Le lien d'ALERTE, lui, les
    //      substitue : reprendre ce chemin-là aurait figé la fenêtre du panneau pour toujours. Le mutant
    //      qui le fait est joué ici.
    //   3. La charge utile de `/api/rules` porte le champ, À CÔTÉ de `query` et jamais à sa place.
    // ================================================================================================

    /// (1)(2) LA DÉRIVATION, SANS BASE — et la différence assumée avec le lien d'alerte.
    #[test]
    fn requete_reutilisable_retire_letage_scalaire_et_laisse_le_brut_intact() {
        // GXQL : `| stats count` terminal retiré -> l'ensemble que cet étage réduisait.
        assert_eq!(
            requete_reutilisable_de_regle("search source=sshd action=failure | stats count", true),
            "search source=sshd action=failure"
        );
        // Corrélation : seul le DERNIER étage part ; les groupes comptés restent.
        assert_eq!(
            requete_reutilisable_de_regle("search source=ufw | stats dc(dport) by src_ip | where dc > 15 | stats count", true),
            "search source=ufw | stats dc(dport) by src_ip | where dc > 15"
        );
        // `by` = pas un scalaire : rien à retirer, la requête est déjà celle d'un tableau.
        let par_cle = "search source=web | stats count by status";
        assert_eq!(requete_reutilisable_de_regle(par_cle, true), par_cle);
        // Sans pipe du tout : rendue entière.
        assert_eq!(requete_reutilisable_de_regle("search source=sudo", true), "search source=sudo");

        // SQL BRUT : INTACT, marqueurs compris. C'est l'écart mesuré avec le lien d'alerte, qui les
        // substitue par les bornes de l'évaluation — un panneau bâti dessus aurait une fenêtre figée.
        let brut = "SELECT COUNT(*) FROM event WHERE ts>=__FROM__ AND ts<=__TO__";
        assert_eq!(requete_reutilisable_de_regle(brut, false), brut);
        let lien = lien_de_recherche_de_regle(brut, false, 900, 10_000);
        assert!(
            !lien.query.contains("__FROM__") && lien.query.contains("9100"),
            "le lien d'alerte SUBSTITUE les bornes (c'est son rôle) : « {} »",
            lien.query
        );
        assert_ne!(
            requete_reutilisable_de_regle(brut, false),
            lien.query,
            "les deux dérivations ne peuvent pas être la même : l'une fige une fenêtre, l'autre la laisse au panneau"
        );
    }

    /// (3) LA CHARGE UTILE. Le champ est rendu par le vrai handler, À CÔTÉ de `query` — un lecteur qui
    /// veut la requête telle qu'elle COMPTE la trouve toujours, et celui qui compose a la sienne.
    #[tokio::test]
    async fn les_regles_servent_leur_requete_reutilisable_a_cote_de_la_leur() {
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        {
            let c = st.db.lock();
            c.execute("DELETE FROM rule", []).unwrap();
            c.execute(
                "INSERT INTO rule(id,name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s) \
                 VALUES(1,'Brute-force SSH',1,'search source=sshd action=failure | stats count',1,'>=',5,3,60,900)",
                [],
            )
            .unwrap();
            c.execute(
                "INSERT INTO rule(id,name,enabled,query,is_soql,op,threshold,severity,interval_s,window_s) \
                 VALUES(2,'Brute',1,'SELECT COUNT(*) FROM event WHERE ts>=__FROM__',0,'>=',1,2,60,900)",
                [],
            )
            .unwrap();
        }
        let au = AuthUser { name: "eve".into(), role: "editor".into(), tenant: "default".into(), is_superadmin: false, method: "cookie".into(), csrf: String::new(), env: None };
        let Json(v) = rules_list(State(st.clone()), Extension(au)).await;
        let r: Vec<&Value> = v["rules"].as_array().unwrap().iter().collect();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0]["query"].as_str(), Some("search source=sshd action=failure | stats count"), "la requête telle qu'elle COMPTE reste rendue");
        assert_eq!(r[0]["query_reutilisable"].as_str(), Some("search source=sshd action=failure"), "…et celle qui compose un panneau est rendue à côté");
        assert_eq!(r[1]["query_reutilisable"].as_str(), Some("SELECT COUNT(*) FROM event WHERE ts>=__FROM__"), "le SQL brut garde ses marqueurs de fenêtre");
        assert_eq!(r[1]["is_soql"].as_bool(), Some(false), "…et sa nature, que la console ne doit pas redeviner");
    }
