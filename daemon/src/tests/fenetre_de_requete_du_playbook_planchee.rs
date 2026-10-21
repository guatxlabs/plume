// =====================================================================================
// `P10.31-k` — LA REQUÊTE DE DÉTECTION D'UN PLAYBOOK PREND LA FENÊTRE PLANCHÉE.
//
// LE DÉFAUT. Le plancher de `P10.21-e` (`max(window_s, interval_s, TOUR_DE_DETECTION_S)`) est jugé à
// l'écriture, mais une ligne peut être ARMÉE sous lui sans qu'aucun geste la juge : overlay `config.d`
// coupé puis dérogation d'activation réappliquée au démarrage, ligne posée avant le plancher. À
// l'exécution, seule la déduplication était planchée ; `run_playbooks` compilait la requête avec
// `window_s` BRUT. Fenêtre 5 s, intervalle 300 s : un événement tombé 100 s avant le passage n'était
// vu par AUCUN passage.
//
// LE CORRECTIF (décision par défaut : pas de refus au démarrage). Une fonction pure partagée,
// `fenetre_effective_du_playbook`, rend la fenêtre planchée ; la déduplication
// (`debut_de_la_deduplication_du_playbook`) et la requête (`fenetre_de_requete_du_playbook`, passée à
// `rule_sql`) la lisent toutes deux. Une fenêtre nulle ou négative signifie « sans borne » pour
// `rule_sql` : elle n'est pas rétrécie.
//
// MUTANTS JOUÉS (sous cfg!(test), par VERIF_MUT, retirés avant le commit), chacun vu ROUGE :
// `k_fenetre_brute_dans_la_requete` (rule_sql reçoit `window_s` brut, l'appel d'avant le correctif),
// `k_sans_borne_planchee` (la branche « sans borne » retirée : une fenêtre 0 devient 300 s).
//
// CORRECTION (vérification indépendante) : la recherche des HÔTES d'un ban (`SELECT DISTINCT host FROM
// event WHERE src_ip=? AND ts>=?`) gardait `now_ts - window_s` BRUT. Fenêtre 5 s, intervalle 300 s,
// événement de 100 s : la cible était trouvée par la fenêtre planchée, mais la riposte partait au
// central (host NULL) au lieu de l'hôte qui avait vu l'IP. Elle lit maintenant `debut_des_hotes_du_ban`,
// même fenêtre que la requête ; fenêtre nulle ou négative = sans borne (début 0), comme `rule_sql` —
// avant, `now_ts - 0` ne trouvait aucun hôte. Mutants vus ROUGES puis retirés :
// `k_hotes_fenetre_brute` (l'appel d'avant), `k_hotes_sans_borne_brute` (sans borne rendu `now_ts - 0`).
// SECONDE CORRECTION : seule la borne BASSE était témoignée — passer 0 au site d'appel (recherche sans
// borne) laissait tout vert. Le témoin des hôtes ajoute un autre hôte vu à 1 000 s, hors de la fenêtre
// planchée : il ne doit recevoir aucune riposte. Mutant `M6d` (0 au site d'appel) vu ROUGE puis retiré.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : la route de dry-run (`playbook_test`) compile encore avec
// `window_s` brut — elle montre ce que la ligne enregistrée demande, pas ce que l'exécution planchée
// cherche ; rien n'est jugé côté console.
// =====================================================================================
mod fenetre_de_requete_du_playbook_planchee {
    use super::*;
    use crate::handlers::playbooks::{debut_des_hotes_du_ban, fenetre_de_requete_du_playbook, fenetre_effective_du_playbook, run_playbooks};
    use crate::mesure_environnement::Mesure;

    const FRP_CIBLE: &str = "203.0.113.81";
    const FRP_REQUETE: &str = "SELECT src_ip FROM event WHERE source='frp-capteur' AND ts>=__FROM__ GROUP BY src_ip";

    /// Une base, un playbook armé (`window_s`, `interval_s` tels quels, sans passer par le juge : l'état
    /// que laisse la dérogation du démarrage) et UN événement de la cible, vieux de `age_s` secondes.
    fn frp_base(tag: &str, interval_s: i64, window_s: i64, age_s: i64) -> (Arc<Mutex<Connection>>, String, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("frp-{tag}"));
        let p = chemin.to_string();
        let db = Arc::new(Mutex::new(open_db(&p).unwrap()));
        {
            let conn = db.lock();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture `P10.31-k` : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM action", []).unwrap();
            conn.execute("DELETE FROM playbook", []).unwrap();
            conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('plume_mode','observe')", []).unwrap();
            conn.execute(
                "INSERT INTO playbook(name,enabled,query,is_soql,action_kind,interval_s,window_s,managed,last_run,created_by_role) \
                 VALUES('frp-pb',1,?1,0,'ban_ip',?2,?3,0,NULL,'admin')",
                params![FRP_REQUETE, interval_s, window_s],
            ).unwrap();
            let ts = crate::now() - age_s;
            conn.execute(
                "INSERT INTO event(ts,source,category,severity,src_ip,message,dedup) VALUES(?1,'frp-capteur','auth',1,?2,'échec',?3)",
                params![ts, FRP_CIBLE, format!("frp-{tag}")],
            ).unwrap();
        }
        (db, p, chemin)
    }

    /// Comme `frp_base`, mais l'événement porte un hôte : rend aussi le lieu des ripostes.
    fn frp_base_avec_hote(tag: &str, interval_s: i64, window_s: i64, age_s: i64) -> (Arc<Mutex<Connection>>, String, crate::tmp_possede::TmpDb) {
        let (db, p, t) = frp_base(tag, interval_s, window_s, 1_000_000_000);
        {
            let conn = db.lock();
            conn.execute("DELETE FROM event", []).unwrap();
            conn.execute(
                "INSERT INTO event(ts,source,category,severity,src_ip,host,message,dedup) VALUES(?1,'frp-capteur','auth',1,?2,'frp-hote','échec',?3)",
                params![crate::now() - age_s, FRP_CIBLE, format!("frp-hote-{tag}")],
            ).unwrap();
        }
        (db, p, t)
    }

    fn frp_hotes_des_ripostes(db: &Arc<Mutex<Connection>>, p: &str) -> Vec<Option<String>> {
        crate::ledger::declarer_la_liste_pour_ce_temoin(); // `P4.7-e`
        assert_eq!(run_playbooks(db, p), Mesure::Lue(0), "le passage n'abandonne rien");
        let c = db.lock();
        let mut st = c.prepare("SELECT host FROM action WHERE target=?1 ORDER BY id").unwrap();
        let v: Vec<Option<String>> = st.query_map(params![FRP_CIBLE], |r| r.get(0)).unwrap().map(|x| x.unwrap()).collect();
        v
    }

    /// CE QU'IL TIENT : la recherche des hôtes d'un ban prend la fenêtre de la requête — sous le plancher
    /// (5 s / 300 s), l'hôte d'un événement de 100 s est trouvé et la riposte part chez lui ; au-dessus,
    /// inchangée ; sans borne (0), l'hôte d'un événement de 100 000 s est trouvé. Fonction pure comprise.
    /// Borne haute comprise : l'hôte qui n'a vu la cible qu'il y a 1 000 s (hors fenêtre planchée) ne reçoit rien.
    /// MUTATIONS QUI LE FONT ROUGIR : `k_hotes_fenetre_brute` (riposte au central, host NULL),
    /// `k_hotes_sans_borne_brute` (idem sur la fenêtre 0), `M6d` (début 0 au site d'appel : recherche sans
    /// borne, l'hôte vu à 1 000 s reçoit aussi une riposte).
    #[test]
    fn frp_les_hotes_d_un_ban_suivent_la_fenetre_planchee() {
        let hote = vec![Some("frp-hote".to_string())];
        let (db, p, _t1) = frp_base_avec_hote("hote-sous-plancher", 300, 5, 100);
        // Borne HAUTE : la même cible vue il y a 1 000 s par un AUTRE hôte, hors de la fenêtre planchée
        // (300 s). Cet hôte n'est pas un hôte du ban : aucune riposte chez lui (une recherche sans borne
        // le prendrait).
        db.lock().execute(
            "INSERT INTO event(ts,source,category,severity,src_ip,host,message,dedup) VALUES(?1,'frp-capteur','auth',1,?2,'frp-hote-ancien','échec','frp-hote-ancien')",
            params![crate::now() - 1000, FRP_CIBLE],
        ).unwrap();
        assert_eq!(frp_hotes_des_ripostes(&db, &p), hote, "sous le plancher : la riposte part sur l'hôte qui a vu l'IP dans la fenêtre planchée, pas sur celui vu à 1 000 s");
        let (db, p, _t2) = frp_base_avec_hote("hote-defaut", 300, 3600, 3000);
        assert_eq!(frp_hotes_des_ripostes(&db, &p), hote, "contrôle au-dessus du plancher");
        let (db, p, _t3) = frp_base_avec_hote("hote-sans-borne", 300, 0, 100_000);
        assert_eq!(frp_hotes_des_ripostes(&db, &p), hote, "fenêtre 0 = sans borne : l'hôte est trouvé");
        assert_eq!(debut_des_hotes_du_ban(10_000, 5, 300), 9_700);
        assert_eq!(debut_des_hotes_du_ban(10_000, 3600, 300), 6_400);
        assert_eq!(debut_des_hotes_du_ban(10_000, 0, 300), 0);
        assert_eq!(debut_des_hotes_du_ban(10_000, -1, 300), 0);
        assert_eq!(debut_des_hotes_du_ban(i64::MIN, i64::MAX, 0), i64::MIN, "pas de débordement");
    }

    /// Un passage de `run_playbooks` ; rend le nombre de ripostes posées sur la cible.
    fn frp_un_passage(db: &Arc<Mutex<Connection>>, p: &str) -> i64 {
        crate::ledger::declarer_la_liste_pour_ce_temoin(); // `P4.7-e` : ce témoin peut poser une riposte de ban
        assert_eq!(run_playbooks(db, p), Mesure::Lue(0), "le passage n'abandonne rien");
        db.lock().query_row("SELECT COUNT(*) FROM action WHERE target=?1", params![FRP_CIBLE], |r| r.get(0)).unwrap()
    }

    /// CE QU'IL TIENT, sur les fonctions pures : sous le plancher, la fenêtre effective vaut
    /// l'intervalle (ou le tour s'il est plus grand) ; au-dessus, elle est inchangée ; la fenêtre de
    /// requête suit la fenêtre effective sauf « sans borne » (0 ou négatif), laissée telle quelle ; des
    /// valeurs extrêmes ne débordent pas.
    /// MUTATION QUI LE FAIT ROUGIR : `k_sans_borne_planchee` (0 rendu en 300).
    #[test]
    fn frp_la_fenetre_effective_et_la_fenetre_de_requete() {
        assert_eq!(fenetre_effective_du_playbook(5, 300), 300, "sous le plancher : l'intervalle");
        assert_eq!(fenetre_effective_du_playbook(5, 0), 20, "intervalle nul : le tour");
        assert_eq!(fenetre_effective_du_playbook(3600, 300), 3600, "au-dessus : inchangée");
        assert_eq!(fenetre_effective_du_playbook(i64::MAX, i64::MAX), i64::MAX, "pas de débordement");
        assert_eq!(fenetre_de_requete_du_playbook(5, 300), 300, "requête : planchée");
        assert_eq!(fenetre_de_requete_du_playbook(3600, 300), 3600, "requête : inchangée au-dessus du plancher");
        assert_eq!(fenetre_de_requete_du_playbook(0, 300), 0, "requête sans borne : pas rétrécie");
        assert_eq!(fenetre_de_requete_du_playbook(-1, 300), -1, "requête sans borne (négative) : pas rétrécie");
    }

    /// CE QU'IL TIENT, sur `run_playbooks` (le point d'entrée de l'ordonnanceur) : une ligne ARMÉE sous
    /// le plancher (fenêtre 5 s, intervalle 300 s) voit un événement vieux de 100 s — tombé entre deux
    /// passages — et pose la riposte ; un événement plus vieux que la fenêtre planchée (400 s) n'est pas
    /// vu (le plancher ne devient pas « tout l'historique »).
    /// MUTATION QUI LE FAIT ROUGIR : `k_fenetre_brute_dans_la_requete` (0 riposte sur l'événement de 100 s).
    #[test]
    fn frp_une_ligne_sous_le_plancher_voit_l_evenement_tombe_entre_deux_passages() {
        let (db, p, _tmp) = frp_base("sous-plancher-vu", 300, 5, 100);
        assert_eq!(frp_un_passage(&db, &p), 1, "fenêtre 5 s planchée à 300 s : l'événement de 100 s est vu");
        let (db, p, _tmp2) = frp_base("sous-plancher-hors", 300, 5, 400);
        assert_eq!(frp_un_passage(&db, &p), 0, "contrôle : un événement de 400 s reste hors de la fenêtre planchée");
    }

    /// CE QU'IL TIENT : au-dessus du plancher, la fenêtre de requête est INCHANGÉE (3 600 s : un
    /// événement de 3 000 s est vu, un de 4 000 s ne l'est pas) ; une fenêtre 0 garde « sans borne »
    /// (un événement de 100 000 s est vu).
    /// MUTATION QUI LE FAIT ROUGIR : `k_sans_borne_planchee` (l'événement de 100 000 s n'est plus vu).
    #[test]
    fn frp_au_dessus_du_plancher_et_sans_borne_la_requete_est_inchangee() {
        let (db, p, _tmp) = frp_base("defaut-vu", 300, 3600, 3000);
        assert_eq!(frp_un_passage(&db, &p), 1, "fenêtre 3 600 s : l'événement de 3 000 s est vu");
        let (db, p, _tmp2) = frp_base("defaut-hors", 300, 3600, 4000);
        assert_eq!(frp_un_passage(&db, &p), 0, "fenêtre 3 600 s : l'événement de 4 000 s n'est pas vu");
        let (db, p, _tmp3) = frp_base("sans-borne", 300, 0, 100_000);
        assert_eq!(frp_un_passage(&db, &p), 1, "fenêtre 0 = sans borne : l'événement de 100 000 s est vu");
    }
}
