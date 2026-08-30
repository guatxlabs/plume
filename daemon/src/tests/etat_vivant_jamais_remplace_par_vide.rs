    // =========================================================================================
    // `P10.7-k` — UNE LECTURE RATÉE NE REMPLACE PAS UN ÉTAT VIVANT PAR UN ÉTAT VIDE.
    //
    // LA FAMILLE. Trois sites lisaient la base par `if let Ok(..)` / `.flatten()` puis SERVAIENT le
    // résultat comme s'il était la base. Le résultat d'une lecture ratée y était, à chaque fois, la
    // valeur la plus RASSURANTE : un ensemble d'indicateurs VIDE, un dénominateur d'hôtes à UN, une
    // politique de redaction PAR DÉFAUT. C'est la figure de `S32` et de `P4.1-r`, mais posée là où
    // aucune des gardes du dépôt ne pouvait la voir : leurs trois jambes cherchent un CORPS SERVI où
    // exiger un aveu, et le premier de ces sites n'en sert aucun — il écrit dans un cache mémoire.
    //
    // POURQUOI LE PREMIER EST D'UN AUTRE ORDRE. `ioc_cache_reload` tourne dans la boucle de rollup,
    // toutes les ~120 s, pour chaque tenant actif. Une lecture ratée y installait un `HashMap` vide
    // dans le cache de correspondance ; `ti_lookup` prend alors son fast-path `set.is_empty() -> None`
    // et le match-on-ingest devient un no-op. Aucune route ne ment, aucun corps n'est servi, aucune
    // alerte ne rougit : la détection par indicateurs est simplement ÉTEINTE jusqu'au prochain
    // rechargement réussi. Les deux autres sites trompent un ÉCRAN ; celui-ci arrête une DÉTECTION.
    //
    // CE QUE CES TÉMOINS TIENNENT, ET DANS LES DEUX SENS. Chaque propriété est exercée sur une source
    // SAINE puis sur la MÊME source rendue illisible, puis RENDUE À NOUVEAU SAINE :
    //   ① source saine -> la valeur lue, verdict `lu`, cause `aucune`, AUCUN détail. C'est le témoin
    //     qui interdit le correctif dégénéré « avouer toujours » : un composant qui avoue toujours
    //     n'avoue rien, et il passerait tout le reste de ce fichier ;
    //   ② source illisible -> l'aveu, sa cause dans l'ensemble fermé de `S32`, ET — c'est le fait qui
    //     porte tout — L'ÉTAT PRÉCÉDENT INTACT : le cache tient toujours ses indicateurs et la
    //     correspondance à l'ingest MATCHE TOUJOURS ;
    //   ③ source redevenue saine -> la valeur lue de nouveau, et le journal de bascule se tait.
    //
    // AUCUNE DURÉE N'EST MESURÉE ICI, et c'est délibéré : le répertoire temporaire de ce poste est en
    // mémoire, tout coût d'entrée-sortie y est des ordres de grandeur plus bas qu'en production, et un
    // témoin adossé à un chronomètre y serait vert par construction. Les propriétés tenues sont un
    // GESTE (l'ancien état est encore là), un COMPTE (combien d'indicateurs), et une propriété
    // STRUCTURELLE : `Mesure::valeur()` rend `Option`, donc AUCUN chemin ne peut tirer un nombre d'un
    // `Illisible` — le dénominateur inventé n'est pas interdit par convention, il est INATTEIGNABLE.
    // =========================================================================================

    /// Rend la table `ioc` INTROUVABLE sans perdre une seule ligne — la panne est ainsi EXACTEMENT
    /// réversible, ce qui est la condition du témoin ③ (une suppression ne se rejouerait pas à
    /// l'identique, et le retour au vert ne prouverait plus rien).
    fn masquer_table(conn: &Connection, nom: &str) {
        conn.execute_batch(&format!("ALTER TABLE {nom} RENAME TO {nom}_masquee_p107k")).unwrap();
    }
    fn rendre_table(conn: &Connection, nom: &str) {
        conn.execute_batch(&format!("ALTER TABLE {nom}_masquee_p107k RENAME TO {nom}")).unwrap();
    }

    /// Le jeu d'indicateurs RÉELLEMENT en service pour ce db_path — pas ce que la table contient, mais
    /// ce avec quoi `ti_lookup` compare. C'est la seule mesure qui dit si la détection tourne encore.
    fn indicateurs_en_service(db_path: &str) -> usize {
        crate::ioc_set().read().get(db_path).map_or(0, |m| m.len())
    }

    fn semer_ioc(conn: &Connection, kind: &str, value: &str) {
        conn.execute(
            "INSERT INTO ioc(type,value,source,confidence,severity,first_seen,last_seen,expires,env_id) \
             VALUES(?1,?2,'feed-p107k',80,3,?3,?3,NULL,'prod')",
            params![kind, value, now()],
        )
        .unwrap();
    }

    /// LE TÉMOIN QUI PORTE LE LOT. Un rechargement dont la lecture échoue CONSERVE le cache vivant, la
    /// correspondance à l'ingest continue de matcher, et l'échec est AVOUÉ. Le correctif retiré (l'ancien
    /// `if let Ok(..)` + installation inconditionnelle), l'assertion « le cache tient encore ses deux
    /// indicateurs » et celle « l'event est toujours enrichi » tombent toutes les deux.
    #[test]
    fn une_lecture_ratee_conserve_le_cache_d_indicateurs_et_le_dit() {
        use crate::mesure_environnement::{Mesure, CAUSES, CAUSE_AUCUNE, CAUSE_FORME_INCONNUE, VERDICT_ILLISIBLE, VERDICT_LU};

        let conn = test_db();
        let dbp = "p107k-conserve";

        // ① SOURCE SAINE — deux indicateurs, lus entièrement, et le chemin nominal est MUET.
        semer_ioc(&conn, "ip", "203.0.113.9");
        semer_ioc(&conn, "domain", "mauvais.example");
        ioc_cache_reload(&conn, dbp);
        let sain = ioc_reload_dernier(dbp).expect("un rechargement a eu lieu");
        assert_eq!(sain, Mesure::Lue(2), "deux indicateurs actifs, lus : {sain:?}");
        assert_eq!(sain.verdict(), VERDICT_LU);
        assert_eq!(sain.cause(), CAUSE_AUCUNE);
        assert_eq!(sain.detail(), None, "le chemin nominal n'avoue RIEN — sinon l'aveu ne veut plus rien dire");
        assert_eq!(indicateurs_en_service(dbp), 2);
        // et la détection MATCHE réellement (le cache n'est pas qu'un compte).
        let enrichi = ti_match_event(dbp, Some("203.0.113.9"), None, None, None);
        assert!(enrichi.as_deref().map(|f| f.contains("ti_match")).unwrap_or(false), "source saine : l'event est enrichi ({enrichi:?})");

        // ② SOURCE ILLISIBLE — la table devient introuvable SOUS le cache déjà chargé.
        masquer_table(&conn, "ioc");
        ioc_cache_reload(&conn, dbp);

        // LE FAIT QUI PORTE TOUT : l'état vivant n'a pas été remplacé par un état vide.
        assert_eq!(
            indicateurs_en_service(dbp), 2,
            "une lecture ratée a REMPLACÉ le cache de correspondance par un ensemble vide — la détection \
             par indicateurs est éteinte, et rien dans aucun corps servi ne le dit"
        );
        let apres = ti_match_event(dbp, Some("203.0.113.9"), None, None, None);
        assert!(
            apres.as_deref().map(|f| f.contains("ti_match")).unwrap_or(false),
            "après une lecture ratée, le match-on-ingest N'ENRICHIT PLUS : la détection s'est arrêtée en \
             silence ({apres:?})"
        );
        // ET IL LE DIT — un état conservé sans aveu serait un second silence.
        let aveu = ioc_reload_dernier(dbp).expect("l'issue est publiée");
        match &aveu {
            Mesure::Illisible { cause, detail } => {
                assert_eq!(*cause, CAUSE_FORME_INCONNUE, "table absente = forme inconnue (même clé que `run_due_rules`) : {detail}");
                assert!(CAUSES.contains(cause), "la cause reste dans l'ensemble fermé");
                assert!(detail.contains('2'), "l'aveu dit COMBIEN d'indicateurs sont conservés — sans ce nombre un exploitant ne sait pas si la détection tourne : {detail}");
                assert!(detail.contains(dbp), "l'aveu nomme la base concernée : {detail}");
            }
            Mesure::Lue(n) => panic!("une lecture ratée a rendu un compte ({n}) au lieu d'un aveu — c'est le défaut que cette clé ferme"),
        }
        assert_eq!(aveu.verdict(), VERDICT_ILLISIBLE);
        assert_eq!(aveu.valeur(), None, "STRUCTUREL : aucun nombre ne sort d'un aveu, donc aucun appelant ne peut publier « 0 indicateur »");

        // ③ SOURCE REDEVENUE SAINE — la mise à jour reprend, et le verdict repasse au vert. Sans ce
        // troisième temps, un correctif qui REFUSERAIT TOUJOURS de recharger passerait ① et ②.
        rendre_table(&conn, "ioc");
        semer_ioc(&conn, "ip", "198.51.100.7");
        ioc_cache_reload(&conn, dbp);
        let retabli = ioc_reload_dernier(dbp).expect("rechargement rétabli");
        assert_eq!(retabli, Mesure::Lue(3), "la mise à jour perdue est reprise au tick suivant : {retabli:?}");
        assert_eq!(retabli.detail(), None, "le retour au vert est MUET");
        assert_eq!(indicateurs_en_service(dbp), 3);
    }

    /// UN PARCOURS INTERROMPU N'EST PAS UN PARCOURS COMPLET. `.flatten()` sautait la ligne indécodable
    /// et rendait un jeu d'indicateurs PLUS PETIT que la table — de la détection en moins, sans ensemble
    /// vide pour la trahir. Une ligne dont `confidence` ne porte pas un entier suffit à le montrer.
    #[test]
    fn une_ligne_indecodable_n_ampute_plus_le_jeu_d_indicateurs_en_silence() {
        use crate::mesure_environnement::{Mesure, CAUSE_SOURCE_ILLISIBLE};

        let conn = test_db();
        let dbp = "p107k-parcours";
        semer_ioc(&conn, "ip", "203.0.113.11");
        semer_ioc(&conn, "ip", "203.0.113.12");
        ioc_cache_reload(&conn, dbp);
        assert_eq!(ioc_reload_dernier(dbp), Some(Mesure::Lue(2)));

        // Une ligne dont `confidence` porte du TEXTE : l'affinité INTEGER de SQLite ne convertit que ce
        // qui est convertible sans perte, la valeur reste donc du texte et `r.get::<_, i64>` la refuse.
        conn.execute(
            "INSERT INTO ioc(type,value,source,confidence,severity,first_seen,last_seen,expires,env_id) \
             VALUES('ip','203.0.113.13','feed-p107k','pas-un-entier',3,?1,?1,NULL,'prod')",
            params![now()],
        )
        .unwrap();
        // L'INSTRUMENT EST VALIDÉ AVANT D'ÊTRE CRU : si l'affinité avait converti, il n'y aurait plus de
        // ligne indécodable et ce témoin ne prouverait rien.
        let typeof_conf: String = conn
            .query_row("SELECT typeof(confidence) FROM ioc WHERE value='203.0.113.13'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(typeof_conf, "text", "instrument : la ligne doit réellement être indécodable");

        ioc_cache_reload(&conn, dbp);
        let aveu = ioc_reload_dernier(dbp).expect("issue publiée");
        match &aveu {
            Mesure::Illisible { cause, detail } => {
                assert_eq!(*cause, CAUSE_SOURCE_ILLISIBLE, "la ligne existe et se lit, c'est son CONTENU qui ne se décode pas : {detail}");
            }
            Mesure::Lue(n) => panic!(
                "un parcours interrompu a rendu un compte ({n}) : la ligne indécodable a été SAUTÉE et le \
                 jeu amputé s'est installé comme s'il était la table"
            ),
        }
        assert_eq!(indicateurs_en_service(dbp), 2, "le jeu de la dernière lecture ENTIÈRE est conservé");

        // TÉMOIN INVERSE : la ligne fautive retirée, la lecture redevient entière et le verdict repasse.
        conn.execute("DELETE FROM ioc WHERE value='203.0.113.13'", []).unwrap();
        ioc_cache_reload(&conn, dbp);
        assert_eq!(ioc_reload_dernier(dbp), Some(Mesure::Lue(2)), "source saine : un vrai compte, aucun aveu");
    }

    /// LE PANNEAU DE COUVERTURE DIT AVEC QUOI ON DÉTECTE, pas seulement ce que la table contient. Les
    /// deux divergent exactement quand un rechargement a échoué — et c'est là que l'ancien panneau
    /// annonçait « N indicateurs actifs » sans rien savoir du cache qui, lui, sert la détection.
    #[tokio::test]
    async fn le_panneau_de_couverture_dit_avec_quoi_on_detecte() {
        use crate::mesure_environnement::{CAUSE_AUCUNE, VERDICT_ILLISIBLE, VERDICT_LU};

        let mut st = sso_test_state("plume-admin", "plume-editor", "admins");
        // db_path PROPRE à ce témoin : les caches d'IOC sont process-globaux et keyés par db_path, et la
        // suite tourne en parallèle — un `db_path` partagé ferait de ce témoin un aléa.
        st.db_path = Arc::new("p107k-panneau".to_string());
        let dbp = "p107k-panneau";
        {
            let conn = st.db.lock();
            semer_ioc(&conn, "ip", "203.0.113.21");
            semer_ioc(&conn, "ip", "203.0.113.22");
            ioc_cache_reload(&conn, dbp);
        }

        // ① NOMINAL : la table et le cache disent la même chose, et le panneau est MUET sur l'axe aveu.
        let v = ti_coverage(State(st.clone()), Extension(tok_au("viewer"))).await.0;
        assert_eq!(v["active"], 2, "la TABLE porte deux indicateurs actifs");
        assert_eq!(v["cache_actifs"], 2, "et la DÉTECTION tourne sur les deux");
        assert_eq!(v["cache_actifs_verdict"], VERDICT_LU);
        assert_eq!(v["cache_actifs_cause"], CAUSE_AUCUNE);
        assert!(v.get("cache_actifs_detail").is_none(), "aucun détail sur le chemin nominal : {v}");

        // ② LECTURE RATÉE : le panneau ne peut plus faire croire que le magasin décrit la détection.
        {
            let conn = st.db.lock();
            masquer_table(&conn, "ioc");
            ioc_cache_reload(&conn, dbp);
        }
        let v = ti_coverage(State(st.clone()), Extension(tok_au("viewer"))).await.0;
        assert!(v.get("cache_actifs").is_none(), "la valeur DISPARAÎT quand elle n'a pas été lue (S32) : {v}");
        assert_eq!(v["cache_actifs_verdict"], VERDICT_ILLISIBLE, "le panneau AVOUE : {v}");
        assert!(v["cache_actifs_detail"].as_str().unwrap_or("").contains('2'), "et il dit sur combien d'indicateurs la détection continue : {v}");
        // CE QUE CE MÊME CORPS MONTRE ENCORE, ET QUE CE LOT NE FERME PAS : `total`/`active` sont lus avec
        // un `unwrap_or(0)`. Le magasin se lit donc « vide » alors que la détection tourne sur deux
        // indicateurs — même figure, même route, un site plus loin. Le témoin le CONSTATE plutôt que de
        // le taire, pour que la clé qui le fermera trouve la mesure déjà écrite.
        assert_eq!(v["active"], 0, "constat (non fermé par P10.7-k) : la lecture du magasin retombe encore sur zéro");
        assert_eq!(v["cache_actifs_verdict"], VERDICT_ILLISIBLE, "seul l'axe CACHE distingue aujourd'hui « vide » de « pas lu »");
    }

    /// LE DÉNOMINATEUR D'HÔTES EST LU OU AVOUÉ, JAMAIS REMPLACÉ PAR « 1 ». Le panneau des suppressions
    /// affiche « cette ligne est celle d'UN hôte sur N » ; un dénombrement en échec rendait N=1 pour
    /// CHAQUE source, c'est-à-dire « une seule machine revendique cette source » — la valeur la plus
    /// calme, et exactement l'affirmation qu'on ne pouvait pas faire.
    #[test]
    fn un_denombrement_d_hotes_qui_echoue_ne_dit_pas_un_seul_hote() {
        use crate::mesure_environnement::{Mesure, CAUSES, CAUSE_FORME_INCONNUE, VERDICT_LU};

        let conn = test_db();
        let depuis = now() - 14 * 86400;
        let ev = |source: &str, host: &str, dedup: &str| {
            conn.execute(
                "INSERT INTO event(ts,source,category,severity,host,message,origin,dedup) \
                 VALUES(?1,?2,'config',1,?3,'auto-report','collector',?4)",
                params![now(), source, host, dedup],
            )
            .unwrap();
        };
        ev("mail", "mx-01", "p107k-1");
        ev("mail", "mx-02", "p107k-2");
        ev("web", "web-01", "p107k-3");

        // ① SOURCE SAINE : le dénominateur RÉEL, par source.
        let lu = hotes_par_source(&conn, depuis);
        let par_source = lu.valeur().expect("dénombrement lu").clone();
        assert_eq!(par_source.get("mail").copied(), Some(2), "deux machines revendiquent `mail`");
        assert_eq!(par_source.get("web").copied(), Some(1));
        assert_eq!(lu.verdict(), VERDICT_LU);
        assert_eq!(lu.detail(), None, "le chemin nominal est MUET");

        // ② SOURCE ILLISIBLE : l'aveu, et AUCUN nombre — la propriété est STRUCTURELLE, pas conventionnelle.
        masquer_table(&conn, "event");
        let rate = hotes_par_source(&conn, depuis);
        match &rate {
            Mesure::Illisible { cause, detail } => {
                assert_eq!(*cause, CAUSE_FORME_INCONNUE, "table introuvable : {detail}");
                assert!(CAUSES.contains(cause), "cause dans l'ensemble fermé");
            }
            Mesure::Lue(m) => panic!("un dénombrement en échec a rendu une table de {} source(s) — chacune se lirait « 1 hôte, non contesté »", m.len()),
        }
        assert!(
            rate.valeur().is_none(),
            "STRUCTUREL : le site d'émission ne peut pas tirer `hosts_total` d'un aveu — la branche qui \
             publiait `unwrap_or(1)` est INATTEIGNABLE, pas seulement déconseillée"
        );

        // ③ SOURCE REDEVENUE SAINE : sans ce temps, un `hotes_par_source` qui échouerait TOUJOURS passerait ②.
        rendre_table(&conn, "event");
        let repris = hotes_par_source(&conn, depuis);
        assert_eq!(repris.valeur().and_then(|m| m.get("mail").copied()), Some(2), "le dénombrement reprend : {repris:?}");
        assert_eq!(repris.verdict(), VERDICT_LU);
    }

    /// LE PANNEAU DES SUPPRESSIONS SERT ENCORE LE DÉNOMINATEUR ET LE DRAPEAU sur le chemin nominal —
    /// le témoin qui interdit que la correction de la branche d'échec ait emporté la branche normale.
    #[tokio::test]
    async fn le_panneau_des_suppressions_sert_le_denominateur_reel() {
        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        {
            let conn = st.db.lock();
            for (h, d) in [("mx-01", "p107k-s1"), ("mx-02", "p107k-s2")] {
                conn.execute(
                    "INSERT INTO event(ts,source,category,severity,host,message,origin,dedup,fields) \
                     VALUES(?1,'mail','config',1,?2,'auto-report','collector',?3,'{\"type\":\"collection-reducing\"}')",
                    params![now(), h, d],
                )
                .unwrap();
            }
        }
        let (code, v) = tok_resp_json(suppressions_get(State(st.clone()), Extension(tok_au("admin"))).await).await;
        assert_eq!(code, StatusCode::OK, "{v}");
        let mail = v["collectors"]
            .as_array()
            .expect("le panneau sert ses collecteurs")
            .iter()
            .find(|e| e["source"] == "mail")
            .cloned()
            .expect("la source `mail` est servie");
        assert_eq!(mail["hosts_total"], 2, "le DÉNOMINATEUR réel, pas un 1 par défaut : {mail}");
        assert_eq!(mail["contested"], true, "deux hôtes pour une même source : le drapeau reste servi");
        assert!(mail.get("hosts_total_verdict").is_none(), "aucun verdict sur le chemin nominal : {mail}");
    }

    /// `P10.7-k` (3) — L'ÉCRAN DE POLITIQUE DE REDACTION DIT SI C'EST BIEN LA VÔTRE. Gated `ai` : le
    /// module n'est pas compilé dans les deux suites par défaut, ce témoin ne s'exécute que sous
    /// `--features ai` (miroir des autres tests IA).
    #[cfg(feature = "ai")]
    #[test]
    fn la_politique_de_redaction_dit_si_elle_est_celle_qui_est_stockee() {
        use crate::mesure_environnement::{Mesure, CAUSE_FORME_INCONNUE, VERDICT_ILLISIBLE, VERDICT_LU};

        let conn = test_db();

        // ① AUCUNE POLITIQUE STOCKÉE : le défaut EST la politique active. C'est un VRAI fait, et le seul
        // des trois cas qui méritait le silence — l'écran dit alors la vérité.
        let (p, prov) = active_redaction_policy(&conn);
        assert_eq!(p.version, 1);
        assert_eq!(prov, Mesure::Lue(1), "aucune ligne stockée : le défaut est bien ce qui s'applique");
        assert_eq!(prov.detail(), None, "chemin nominal MUET");

        // ② POLITIQUE STOCKÉE ET COMPRISE : c'est elle qui est servie, et le verdict reste au vert.
        conn.execute(
            "INSERT INTO meta(key,value) VALUES('ai_redaction_policy',?1) ON CONFLICT(key) DO UPDATE SET value=?1",
            params![r#"{"version":7,"deny_substr":["email"],"pii_allow":["user_name"]}"#],
        )
        .unwrap();
        let (p, prov) = active_redaction_policy(&conn);
        assert_eq!(p.version, 7);
        assert_eq!(p.deny_substr, vec!["email".to_string()], "la denylist STOCKÉE est celle qui s'applique");
        assert_eq!(prov, Mesure::Lue(7));
        assert_eq!(prov.verdict(), VERDICT_LU);

        // ③ POLITIQUE STOCKÉE ET INDÉCODABLE : le défaut s'applique (repli assumé) mais l'écran ne peut
        // plus le faire passer pour la politique stockée. Sans cet aveu, un aller-retour console —
        // lire, modifier la version, renvoyer — ÉCRASE la politique en place par le défaut.
        conn.execute("UPDATE meta SET value='{ pas du json' WHERE key='ai_redaction_policy'", []).unwrap();
        let (p, prov) = active_redaction_policy(&conn);
        assert_eq!(p.version, 1, "le repli reste celui d'avant : la couche IA continue de rédiger");
        match &prov {
            Mesure::Illisible { cause, detail } => {
                assert_eq!(*cause, CAUSE_FORME_INCONNUE, "une politique EST stockée, c'est sa FORME qui n'est pas comprise : {detail}");
                assert!(detail.contains("PUT"), "l'aveu dit le risque concret (renvoyer cet écran écrase la politique) : {detail}");
            }
            Mesure::Lue(v) => panic!("une politique indécodable a été servie comme la politique stockée (version {v}) — l'écran ment"),
        }

        // ④ POLITIQUE STOCKÉE, DÉCODABLE, MAIS SANS VERSION : lue, non comprise. Une politique sans
        // version ne peut pas être estampée au ledger `ai.call`.
        conn.execute("UPDATE meta SET value='{\"deny_substr\":[\"x\"]}' WHERE key='ai_redaction_policy'", []).unwrap();
        let (_, prov) = active_redaction_policy(&conn);
        assert_eq!(prov.verdict(), VERDICT_ILLISIBLE, "sans version, la forme n'est pas comprise : {prov:?}");
        assert_eq!(prov.cause(), CAUSE_FORME_INCONNUE);

        // ⑤ TÉMOIN INVERSE : la politique redevenue saine, le verdict repasse au vert. Sans lui, une
        // fonction qui avouerait TOUJOURS passerait ③ et ④.
        conn.execute("UPDATE meta SET value='{\"version\":9}' WHERE key='ai_redaction_policy'", []).unwrap();
        let (p, prov) = active_redaction_policy(&conn);
        assert_eq!((p.version, prov.clone()), (9, Mesure::Lue(9)), "source saine : lue, aucun aveu");
        assert_eq!(prov.detail(), None);
    }

    /// La ROUTE porte l'aveu jusqu'à l'administrateur — pas seulement la fonction interne.
    #[cfg(feature = "ai")]
    #[tokio::test]
    async fn la_route_de_politique_de_redaction_porte_l_aveu() {
        use crate::mesure_environnement::{CAUSE_AUCUNE, CAUSE_FORME_INCONNUE, VERDICT_ILLISIBLE, VERDICT_LU};

        let st = sso_test_state("plume-admin", "plume-editor", "admins");
        // ① nominal : rien de stocké -> le défaut, assumé, verdict au vert et AUCUN détail.
        let (code, v) = tok_resp_json(ai_redaction_policy_get(State(st.clone()), Extension(tok_au("admin"))).await).await;
        assert_eq!(code, StatusCode::OK, "{v}");
        assert_eq!(v["version"], 1);
        assert_eq!(v["stockee_verdict"], VERDICT_LU, "{v}");
        assert_eq!(v["stockee_cause"], CAUSE_AUCUNE);
        assert!(v.get("stockee_detail").is_none(), "chemin nominal MUET : {v}");

        // ② une politique stockée indécodable : la réponse porte toujours une politique applicable, et
        // dit qu'elle n'est PAS celle qui est stockée.
        {
            let conn = st.db.lock();
            conn.execute(
                "INSERT INTO meta(key,value) VALUES('ai_redaction_policy','{ casse') ON CONFLICT(key) DO UPDATE SET value='{ casse'",
                [],
            )
            .unwrap();
        }
        let (code, v) = tok_resp_json(ai_redaction_policy_get(State(st.clone()), Extension(tok_au("admin"))).await).await;
        assert_eq!(code, StatusCode::OK, "la route SERT toujours — planter n'est ni conserver ni mettre à jour : {v}");
        assert_eq!(v["stockee_verdict"], VERDICT_ILLISIBLE, "{v}");
        assert_eq!(v["stockee_cause"], CAUSE_FORME_INCONNUE);
        assert!(v["stockee_detail"].as_str().unwrap_or("").contains("stocké"), "{v}");
    }
