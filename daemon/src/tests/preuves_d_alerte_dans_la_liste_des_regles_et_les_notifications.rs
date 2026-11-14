// =====================================================================================
// `P11.25-g` — LA REQUÊTE DE PREUVES DANS LA LISTE DES RÈGLES, ET LES PREUVES FIGÉES DANS LES NOTIFICATIONS SORTANTES.
//
// MESURÉ SUR LA BASE : aucune route ne servait `rule.evidence_query` (il n'existe pas de route de lecture d'UNE règle ;
// `GET /api/rules` est la seule lecture d'une règle) ; `dispatch_notifications` envoyait titre, détail (la requête de la
// règle), hôte, sévérité et instant, sans les preuves écrites sur l'alerte.
//
// CE QUE CES TÉMOINS TIENNENT :
//   (A) `GET /api/rules`, par la route, pour le lecteur, l'éditeur et l'administrateur : corps entier à l'octet ; la
//       requête de preuves est servie sous `evidence_query` pour la règle qui en déclare une, la clé est ABSENTE pour une
//       règle à requête de preuves NULL ou vide. Les lecteurs sont ceux de `query` : la clé est posée dans le même objet,
//       par le même gestionnaire, et le corps entier est comparé pour chaque rôle (le refus d'un appelant non admis est
//       rendu par l'authentification avant le gestionnaire, il ne dit rien de ce changement et n'est pas témoigné ici) ;
//       une cellule de requête de preuves qui n'est pas un texte UTF-8 (BLOB en tête, texte mal encodé au milieu) : la
//       règle est servie avec `evidence_query` à `null` et la cause sous `evidence_query_non_lu`, les règles lisibles
//       qui suivent sont servies comme avant, corps entier à l'octet pour le lecteur et l'administrateur ;
//   (B) par `dispatch_notifications` dans un sous-processus dont le `curl` est un faux qui recopie ses arguments, son
//       entrée et le fichier téléversé : pour CHACUN des huit canaux réseau (ntfy, webhook, email, slack, pagerduty,
//       generic sans gabarit, generic à gabarit texte, generic à gabarit JSON au type de contenu par défaut), la charge
//       entière qui part ; le corps du gabarit JSON se relit en JSON ; l'objet de preuves joint est, champ pour
//       champ, celui que `/api/alerts` sert au lecteur ; une alerte dont la règle déclare des preuves sans en porter dit
//       « non figées » ; une alerte dont la règle n'en déclare pas part à l'identique ; le canal `lookup` ne reçoit rien
//       des preuves. Chaque sous-processus a son propre `TMPDIR` : le corps d'un courriel est écrit sous
//       `plume-mail-<ts>-<seq>.eml`, `seq` repart de 0 dans chaque processus, et deux témoins qui tournent en même temps
//       s'écrasaient ce fichier ; le fichier téléversé doit se trouver sous le `TMPDIR` de SON sous-processus ; le
//       sous-processus charge le registre des filtres de champs comme le démarrage du serveur (`field_filters_reload`,
//       ici sur une table vide) avant le dispatch ;
//   (B') un filtre de champs actif : `/api/alerts` sert au lecteur les preuves retenues, et aucune adresse des preuves ne
//       sort par aucun canal, la notification dit qu'elles sont retenues ; le sous-processus a chargé le registre avec
//       cette règle ;
//   (C) les bornes de l'objet joint (`texte_des_preuves_a_l_envoi`, appelé par le dispatch) : octets à la borne, borne-1
//       et borne+1 (matière ASCII, et multioctet au-delà de la borne), lignes à la borne-1, borne et borne+1, coupe par la fin et dite, objet
//       trop grand même vide ; chaque mention (non relues, non figées, retenues, registre non lu, illisibles, aucune
//       ligne, non établies avec une cause de l'ensemble fermé ou hors de lui, forme inconnue) et le texte vide d'une
//       alerte sans preuves déclarées ;
//   (D) la relecture de l'alerte à l'envoi (`lire_les_preuves_a_l_envoi`) : texte, NULL, cellule non texte, texte non
//       UTF-8, règle à requête vide, règle d'un autre identifiant, ligne absente, colonne absente ;
//   (E) le masquage vu par l'envoi (`masquage_a_l_envoi`) : table vide, règle active, éteinte (entier 0), d'activité
//       illisible (texte), portée sur un autre tenant et un autre environnement, règle encore armée dans le registre en
//       mémoire après son retrait de la table (sans portée, puis portée sur un autre tenant et un autre environnement),
//       règle armée sous un chemin de base qui passe par un lien, table absente ; registre chargé sur une table vide
//       (sous le chemin de la base, puis seul sous un lien) : aucun masquage ;
//   (F) le gabarit du canal generic (`render_template_pour_le_type`) : valeurs échappées pour un type de contenu JSON
//       (casse et paramètres ignorés, sous-type `+json`), littérales pour tout autre type (`text/plain`,
//       `application/jsonl`).
//
// MUTANTS JOUÉS (variable d'environnement de mutation, retirés avant le commit) : CI4_A_SANS_CLE, CI4_A_VIDE_SERVIE,
// CI4_A_NULL_SERVIE (A) ; CI4_B_DETAIL_BRUT, CI4_B_NON_FIGEES_TUES, CI4_B_SANS_DECLARATION_DIT (B) ; CI4_B_MASQUE_IGNORE
// (B') ; CI4_C_BORD, CI4_C_CHARS, CI4_C_COUPE_DEBUT, CI4_C_SERVED, CI4_C_TRUNCATED, CI4_C_PHRASE, CI4_C_MENTION,
// CI4_C_SANS_BORNE_DE_LIGNES, CI4_C_TROP_GRANDES, CI4_C_CAUSE_BRUTE, CI4_C_ILLISIBLES, CI4_C_INCONNUE, CI4_C_SANS_LIGNE,
// CI4_C_NON_RELUES, CI4_C_MASQUAGE_NON_LU (C) ; CI4_D_VIDE_DECLAREE, CI4_D_SANS_JOINTURE, CI4_D_BLOB_TEXTE, CI4_D_UTF8 (D) ;
// CI4_E_SANS_REGISTRE, CI4_E_TOUTES, CI4_E_EGAL_UN, CI4_E_ERREUR_AUCUN, CI4_E_PORTEE, CI4_E_CLE_BRUTE (E) ;
// CI4_F_SANS_ECHAPPEMENT, CI4_F_TOUJOURS, CI4_F_PARAMETRES, CI4_F_PLUS_JSON (F et B) ; CI4_G_TMPDIR_PARTAGE (B, B') ;
// CI4_H_REGISTRE_VIDE_COMPTE (E et B) ; CI4_I_LECTURE_STRICTE, CI4_I_ILLISIBLE_ABSENTE, CI4_I_ILLISIBLE_VIDE,
// CI4_I_CONTENU (A).
//
// ÉQUIVALENCE DITE (aucune observation ne la distingue) : la première estimation par la taille des lignes de
// `preuves_etablies_bornees` ne fait que choisir où la boucle commence. L'objet servi pèse au moins un octet de plus que
// la somme de ses lignes et de leurs séparateurs (accolades), donc tout nombre de lignes qui tient dans la borne passe
// aussi l'estimation : la boucle, qui décroît depuis l'estimation, rend le même plus grand nombre de lignes qui tient
// que si elle partait de toutes les lignes.
// =====================================================================================
mod preuves_d_alerte_dans_la_liste_des_regles_et_les_notifications {
    use super::*;
    use crate::handlers::notifiers::dispatch_notifications;
    use crate::preuves_d_alerte::{
        lire_les_preuves_a_l_envoi, masquage_a_l_envoi, texte_des_preuves_a_l_envoi, MasquageALEnvoi, Preuves, PreuvesDatees,
        PreuvesLuesALEnvoi,
    };

    const CI4_MENTION_JOINTES: &str = "Preuves figées à la levée de l'alerte, telles que /api/alerts les sert :";
    const CI4_MENTION_COUPEES: &str = "Preuves figées à la levée de l'alerte, COUPÉES pour tenir dans la notification \
(served lignes jointes) ; /api/alerts sert toutes les lignes écrites :";
    const CI4_MENTION_TROP_GRANDES: &str = "Preuves figées à la levée de l'alerte : trop grandes pour la notification même \
sans aucune ligne, rien n'en est joint ; /api/alerts les sert.";
    const CI4_MENTION_SANS_LIGNE: &str = "Preuves : aucune ligne à la levée de l'alerte (la lecture a réussi et n'a rien rendu).";
    const CI4_MENTION_NON_ETABLIES: &str = "Preuves : non établies, leur lecture a échoué à la levée de l'alerte, cause :";
    const CI4_MENTION_NON_FIGEES: &str = "Preuves : non figées pour cette alerte, aucune lecture n'a été faite à sa levée.";
    const CI4_MENTION_RETENUES: &str = "Preuves : retenues, un filtre de champs est actif ; elles ne sortent par aucune notification.";
    const CI4_MENTION_MASQUAGE_NON_LU: &str = "Preuves : retenues, le registre des filtres de champs n'a pas pu être lu.";
    const CI4_MENTION_ILLISIBLES: &str = "Preuves : écrites sur l'alerte mais illisibles en base, rien n'en est joint.";
    const CI4_MENTION_NON_RELUES: &str = "Preuves : non relues, la ligne de l'alerte n'a pas pu être lue à l'envoi.";
    const CI4_MENTION_FORME_INCONNUE: &str = "Preuves : forme inconnue, rien n'en est joint.";
    const CI4_PHRASE_COUPEES: &str = "Preuves établies à l'instant où l'alerte a été levée (at), sur la fenêtre de la règle, \
COUPÉES : served lignes servies sur total lues (total_exact faux : au moins autant, le plafond de lecture a coupé avant). \
Fait daté : elles ne sont pas réécrites aux tirs suivants.";
    const CI4_BORNE_OCTETS: usize = 2048;
    const CI4_BORNE_LIGNES: usize = 50;

    const CI4_DETAIL: &str = "DETAIL-CI4 SELECT count(*) FROM event";
    const CI4_HOTE: &str = "192.0.2.77";
    const CI4_TS: i64 = 1_700_000_000;
    const CI4_TITRE_ETABLIES: &str = "TITRE-CI4-A";
    const CI4_TITRE_NON_FIGEES: &str = "TITRE-CI4-B";
    const CI4_TITRE_SANS: &str = "TITRE-CI4-C";
    const CI4_IPS: [&str; 3] = ["198.51.100.20", "203.0.113.10", "192.0.2.30"];
    const CI4_DE: &str = "alerte-ci4@exemple.invalid";
    const CI4_A: &str = "astreinte-ci4@exemple.invalid";
    const CI4_CLE_DE_ROUTAGE: &str = "cle-de-routage-ci4";
    /// Le faux `curl` : chaque appel recopie ses arguments (séparés par NUL), son entrée et le fichier qu'il téléverse
    /// (le corps d'un courriel, effacé par le démon après l'envoi) dans le dossier de capture, puis sort en 0.
    const CI4_FAUX_CURL: &str = "#!/bin/sh\n\
f=\"$CI4_CAPTURE/$$\"\n\
for a in \"$@\"; do printf '%s\\000' \"$a\"; done > \"$f.args\"\n\
cat > \"$f.stdin\"\n\
prec=\"\"\n\
for a in \"$@\"; do if [ \"$prec\" = \"--upload-file\" ]; then cat \"$a\" > \"$f.fichier\"; fi; prec=\"$a\"; done\n\
exit 0\n";

    /// Les canaux réseau : (identifiant, genre, url, configuration, marque qui reconnaît son appel).
    const CI4_CANAUX: [(i64, &str, &str, &str, &str); 8] = [
        (51, "ntfy", "http://192.0.2.10/ci4-ntfy", "{}", "http://192.0.2.10/ci4-ntfy"),
        (52, "webhook", "http://192.0.2.10/ci4-webhook", "{}", "http://192.0.2.10/ci4-webhook"),
        (53, "email", "smtp://192.0.2.10:25", "{\"from\":\"alerte-ci4@exemple.invalid\",\"to\":\"astreinte-ci4@exemple.invalid\"}", "smtp://192.0.2.10:25"),
        (54, "slack", "", "{\"webhook_url\":\"https://192.0.2.10/ci4-slack\"}", "https://192.0.2.10/ci4-slack"),
        (55, "pagerduty", "", "{\"routing_key\":\"cle-de-routage-ci4\"}", "https://events.pagerduty.com/v2/enqueue"),
        (56, "generic", "http://192.0.2.10/ci4-generic", "{}", "http://192.0.2.10/ci4-generic"),
        (57, "generic", "http://192.0.2.10/ci4-gabarit", "{\"template\":\"{{title}}|{{detail}}\",\"content_type\":\"text/plain\"}", "http://192.0.2.10/ci4-gabarit"),
        (59, "generic", "http://192.0.2.10/ci4-json", "{\"template\":\"{\\\"text\\\":\\\"{{title}} : {{detail}}\\\"}\"}", "http://192.0.2.10/ci4-json"),
    ];

    fn ci4_corps(reponse: &str) -> String {
        let corps = reponse.split_once("\r\n\r\n").map(|(_, c)| c.to_string()).unwrap_or_default();
        match (corps.find('{'), corps.rfind('}')) {
            (Some(a), Some(b)) if a < b => corps[a..=b].to_string(),
            _ => corps,
        }
    }

    // ------------------------------------------------------------------------------------------------------- (A)

    fn ci4_regle_servie(id: i64, nom: &str, requete: &str, is_soql: bool, preuves: Option<&str>) -> Value {
        let mut r = json!({
            "id": id, "name": nom, "enabled": true,
            "query": requete, "is_soql": is_soql, "op": ">",
            "threshold": 0.0, "severity": 2, "interval_s": 300,
            "window_s": 3600, "last_run": null,
            "last_value": null, "last_fired": null,
            "mitre": "", "managed": 0, "compliance": "",
            "suppress_window_s": 0, "throttle_field": "", "per_result": false,
            "population": "", "population_vue": "",
            "query_reutilisable": crate::handlers::detection::requete_reutilisable_de_regle(requete, is_soql)
        });
        preuves.into_iter().for_each(|p| r["evidence_query"] = json!(p));
        r
    }

    #[tokio::test]
    async fn ci4_liste_des_regles_sert_la_requete_de_preuves_a_chaque_lecteur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, dbp) = router_test_state("ci4-regles");
        const REQUETE_BRUTE: &str = "SELECT COUNT(*) FROM event WHERE ts >= __FROM__";
        const REQUETE_GXQL: &str = "source=web | stats count";
        const PREUVES: &str = "SELECT src_ip, COUNT(*) AS activite FROM event WHERE ts >= __FROM__ GROUP BY src_ip";
        {
            let w = open_db(dbp.as_str()).unwrap();
            w.execute("INSERT INTO user(name,hash,role) VALUES('edt',?1,'editor')", params![hash_pw("editorpw12345").unwrap()]).unwrap();
            w.execute("DELETE FROM rule", []).unwrap();
            for (id, nom, requete, is_soql, preuves) in [
                (901, "ci4-avec", REQUETE_BRUTE, 0, Some(PREUVES)),
                (902, "ci4-sans", REQUETE_GXQL, 1, None),
                (903, "ci4-vide", REQUETE_BRUTE, 0, Some("")),
            ] {
                w.execute(
                    "INSERT INTO rule(id,name,query,is_soql,evidence_query) VALUES(?1,?2,?3,?4,?5)",
                    params![id, nom, requete, is_soql, preuves],
                )
                .unwrap();
            }
        }
        let attendu = json!({
            "rules": [
                ci4_regle_servie(901, "ci4-avec", REQUETE_BRUTE, false, Some(PREUVES)),
                ci4_regle_servie(902, "ci4-sans", REQUETE_GXQL, true, None),
                ci4_regle_servie(903, "ci4-vide", REQUETE_BRUTE, false, None),
            ],
            "avertissement_overlay": crate::handlers::detection::avertissement_overlay("Cette règle", "rule", 1),
        });
        let attendu = serde_json::to_string(&attendu).unwrap();
        assert!(attendu.contains(PREUVES), "contrôle : le corps attendu porte la requête de preuves");
        let addr = router_serve(st).await;
        let editeur = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("edt:editorpw12345"));
        let admin = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("root:rootpw1234567"));
        let lecteurs = [("lecteur", viewer_authz()), ("éditeur", editeur), ("administrateur", admin)];
        for (role, authz) in &lecteurs {
            let (code, reponse) = router_probe_corps(addr, "GET", "/api/rules", Some(authz), &[]).await;
            assert_eq!(code, 200, "{role} : {reponse}");
            assert_eq!(ci4_corps(&reponse), attendu, "{role} : corps entier à l'octet");
        }
    }

    const CI4_CAUSE_REQUETE_ILLISIBLE: &str = "REQUÊTE DE PREUVES ILLISIBLE : la valeur écrite pour cette règle n'est pas \
un texte UTF-8, elle n'est pas servie ; ce n'est pas une absence de requête de preuves.";

    #[tokio::test]
    async fn ci4_liste_des_regles_sert_une_requete_de_preuves_illisible_comme_telle() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let (st, dbp) = router_test_state("ci4-regles-illisibles");
        const REQUETE: &str = "SELECT COUNT(*) FROM event WHERE ts >= __FROM__";
        const PREUVES: &str = "SELECT src_ip FROM event WHERE ts >= __FROM__";
        {
            let w = open_db(dbp.as_str()).unwrap();
            w.execute("DELETE FROM rule", []).unwrap();
            // Une cellule illisible EN TÊTE et une AU MILIEU, chacune suivie d'une règle lisible.
            for (id, nom) in [(930, "ci4-blob"), (931, "ci4-saine"), (932, "ci4-mal-encodee"), (933, "ci4-sans")] {
                w.execute("INSERT INTO rule(id,name,query,is_soql) VALUES(?1,?2,?3,0)", params![id, nom, REQUETE]).unwrap();
            }
            w.execute("UPDATE rule SET evidence_query=X'00FF' WHERE id=930", []).unwrap();
            w.execute("UPDATE rule SET evidence_query=?1 WHERE id=931", params![PREUVES]).unwrap();
            w.execute("UPDATE rule SET evidence_query=CAST(X'FF' AS TEXT) WHERE id=932", []).unwrap();
            let mut s = w.prepare("SELECT typeof(evidence_query) FROM rule ORDER BY id").unwrap();
            let types: Vec<String> = s.query_map([], |r| r.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap();
            assert_eq!(types, ["blob", "text", "text", "null"], "fixture : natures des cellules");
        }
        let illisible = |id: i64, nom: &str| {
            let mut r = ci4_regle_servie(id, nom, REQUETE, false, None);
            r["evidence_query"] = Value::Null;
            r["evidence_query_non_lu"] = json!(CI4_CAUSE_REQUETE_ILLISIBLE);
            r
        };
        let attendu = json!({
            "rules": [
                illisible(930, "ci4-blob"),
                ci4_regle_servie(931, "ci4-saine", REQUETE, false, Some(PREUVES)),
                illisible(932, "ci4-mal-encodee"),
                ci4_regle_servie(933, "ci4-sans", REQUETE, false, None),
            ],
            "avertissement_overlay": crate::handlers::detection::avertissement_overlay("Cette règle", "rule", 1),
        });
        let attendu = serde_json::to_string(&attendu).unwrap();
        let addr = router_serve(st).await;
        let admin = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("root:rootpw1234567"));
        for (role, authz) in [("lecteur", viewer_authz()), ("administrateur", admin)] {
            let (code, reponse) = router_probe_corps(addr, "GET", "/api/rules", Some(&authz), &[]).await;
            assert_eq!(code, 200, "{role} : {reponse}");
            assert_eq!(ci4_corps(&reponse), attendu, "{role} : chaque règle servie, la requête de preuves illisible dite, corps entier à l'octet");
        }
    }

    // ------------------------------------------------------------------------------------------------------- (B)

    fn ci4_preuves_etablies_ecrites() -> String {
        PreuvesDatees {
            instant: CI4_TS,
            window_s: 3600,
            preuves: Preuves::Etablies {
                colonnes: vec![json!("src_ip"), json!("activite")],
                lignes: CI4_IPS.iter().zip([40, 30, 25]).map(|(ip, n)| json!([ip, n])).collect(),
                total_exact: true,
            },
        }
        .en_json()
        .to_string()
    }

    /// Une base de routeur : la règle 911 déclare des preuves, la 912 non ; trois alertes non notifiées (A : preuves
    /// établies, B : règle à preuves, aucune écrite, C : règle sans preuves) ; les sept canaux réseau et un lookup ;
    /// `masque` : une règle de filtre de champs active, chargée dans le registre.
    fn ci4_base_de_canaux(tag: &str, masque: bool) -> (AppState, crate::tmp_possede::TmpDb) {
        let (st, dbp) = router_test_state(tag);
        let w = open_db(dbp.as_str()).unwrap();
        w.execute_batch("DELETE FROM rule; DELETE FROM alert; DELETE FROM notifier;").unwrap();
        w.execute("INSERT INTO rule(id,name,query,is_soql,evidence_query) VALUES(911,'ci4-preuves','SELECT 1',0,'SELECT src_ip FROM event')", []).unwrap();
        w.execute("INSERT INTO rule(id,name,query,is_soql) VALUES(912,'ci4-sans-preuves','SELECT 1',0)", []).unwrap();
        let ecrites = ci4_preuves_etablies_ecrites();
        for (id, decalage, regle, titre, preuves) in [
            (9401, 0, "rule.911", CI4_TITRE_ETABLIES, Some(ecrites.as_str())),
            (9402, 1, "rule.911", CI4_TITRE_NON_FIGEES, None),
            (9403, 2, "rule.912", CI4_TITRE_SANS, None),
        ] {
            w.execute(
                "INSERT INTO alert(id,ts,rule,severity,title,detail,status,mitre,sources,host,evidence) VALUES(?1,?2,?3,3,?4,?5,'new','','',?6,?7)",
                params![id, CI4_TS + decalage, regle, titre, CI4_DETAIL, CI4_HOTE, preuves],
            )
            .unwrap();
        }
        for (id, genre, url, config, _) in CI4_CANAUX {
            w.execute(
                "INSERT INTO notifier(id,name,kind,enabled,url,min_severity,config) VALUES(?1,?2,?3,1,?4,0,?5)",
                params![id, format!("ci4-{id}"), genre, url, config],
            )
            .unwrap();
        }
        w.execute(
            "INSERT INTO notifier(id,name,kind,enabled,url,min_severity,config) VALUES(58,'ci4-58','lookup',1,'',0,'{\"lookup\":\"ci4_alertes\",\"key_field\":\"source\"}')",
            [],
        )
        .unwrap();
        if masque {
            w.execute("INSERT INTO field_filter(name,field,action,role) VALUES('ci4','src_ip','mask','')", []).unwrap();
            field_filters_reload(&w, dbp.as_str());
        }
        (st, dbp)
    }

    /// Les preuves que `/api/alerts` sert au LECTEUR, par alerte (absentes : `None`).
    async fn ci4_preuves_servies_au_lecteur(st: AppState) -> std::collections::HashMap<i64, Option<Value>> {
        let addr = router_serve(st).await;
        let (code, reponse) = router_probe_corps(addr, "GET", "/api/alerts", Some(&viewer_authz()), &[]).await;
        assert_eq!(code, 200, "{reponse}");
        let corps: Value = serde_json::from_str(&ci4_corps(&reponse)).unwrap_or_else(|e| panic!("corps JSON : {e} : {reponse}"));
        corps["alerts"]
            .as_array()
            .unwrap_or_else(|| panic!("liste d'alertes : {corps}"))
            .iter()
            .map(|a| (a["id"].as_i64().unwrap(), a.get("evidence").cloned()))
            .collect()
    }

    struct Ci4Appel {
        args: Vec<String>,
        stdin: String,
        fichier: Option<String>,
    }

    impl Ci4Appel {
        fn tout(&self) -> String {
            format!("{}\n{}\n{}", self.args.join("\n"), self.stdin, self.fichier.clone().unwrap_or_default())
        }
        fn apres(&self, option: &str) -> String {
            let i = self.args.iter().position(|a| a == option).unwrap_or_else(|| panic!("option {option} absente : {:?}", self.args));
            self.args[i + 1].clone()
        }
    }

    fn ci4_appels(dossier: &std::path::Path) -> Vec<Ci4Appel> {
        let mut appels = Vec::new();
        for entree in std::fs::read_dir(dossier).unwrap() {
            let chemin = entree.unwrap().path();
            let nom = chemin.file_name().unwrap().to_string_lossy().into_owned();
            let Some(base) = nom.strip_suffix(".args") else { continue };
            let lire = |suffixe: &str| std::fs::read_to_string(dossier.join(format!("{base}{suffixe}"))).ok();
            let brut = lire(".args").unwrap();
            appels.push(Ci4Appel {
                args: brut.split('\0').filter(|s| !s.is_empty()).map(str::to_string).collect(),
                stdin: lire(".stdin").unwrap_or_default(),
                fichier: lire(".fichier"),
            });
        }
        appels
    }

    /// L'inverse de l'échappement de la configuration curl (`\x` -> `x`).
    fn ci4_desechapper(s: &str) -> String {
        let mut sortie = String::new();
        let mut car = s.chars();
        while let Some(c) = car.next() {
            if c == '\\' {
                sortie.extend(car.next());
            } else {
                sortie.push(c);
            }
        }
        sortie
    }

    fn ci4_une_ligne(s: &str) -> String {
        s.replace(['\r', '\n'], " ")
    }

    /// Compare la charge ENTIÈRE de l'appel du canal `marque` à ce que ce canal envoie pour (`titre`, `detail`) ; rend le
    /// détail tel qu'il est parti (une seule ligne pour slack, pagerduty et le gabarit).
    fn ci4_charge_du_canal(appel: &Ci4Appel, genre: &str, marque: &str, titre: &str, detail: &str, ts: i64) -> String {
        let ctx = format!("{marque} / {titre}");
        match (genre, marque) {
            ("ntfy", _) => {
                assert!(appel.args.contains(&format!("Title: {titre}")), "{ctx} : {:?}", appel.args);
                let corps = appel.apres("--data-raw");
                assert_eq!(corps, format!("{detail}\n[{CI4_HOTE}]"), "{ctx} : corps ntfy entier");
                corps.strip_suffix(&format!("\n[{CI4_HOTE}]")).unwrap().to_string()
            }
            ("webhook", _) => {
                let corps: Value = serde_json::from_str(&appel.apres("-d")).unwrap();
                assert_eq!(corps, json!({ "ts": ts, "severity": 3, "title": titre, "detail": detail, "host": CI4_HOTE }), "{ctx}");
                corps["detail"].as_str().unwrap().to_string()
            }
            ("email", _) => {
                let fichier = appel.fichier.clone().unwrap_or_else(|| panic!("{ctx} : corps du courriel non capturé"));
                assert_eq!(
                    fichier,
                    format!("From: {CI4_DE}\r\nTo: {CI4_A}\r\nSubject: [Plume] {titre}\r\n\r\n{detail}\r\n[{CI4_HOTE}]\r\n"),
                    "{ctx} : courriel entier"
                );
                detail.to_string()
            }
            ("slack", _) => {
                let corps: Value = serde_json::from_str(&appel.apres("-d")).unwrap();
                assert_eq!(corps, crate::handlers::alerting::slack_payload(3, titre, detail, CI4_HOTE, ts), "{ctx}");
                let texte = corps["blocks"][1]["text"]["text"].as_str().unwrap().to_string();
                assert_eq!(texte, ci4_une_ligne(detail), "{ctx} : section du détail");
                texte
            }
            ("pagerduty", _) => {
                let brut = appel.stdin.strip_prefix("data = \"").and_then(|s| s.strip_suffix("\"\n")).unwrap_or_else(|| panic!("{ctx} : {}", appel.stdin));
                let corps: Value = serde_json::from_str(&ci4_desechapper(brut)).unwrap();
                assert_eq!(
                    corps,
                    crate::handlers::alerting::pagerduty_payload(CI4_CLE_DE_ROUTAGE, &ci4_une_ligne(titre), 3, titre, detail, CI4_HOTE, ts),
                    "{ctx}"
                );
                let texte = corps["payload"]["custom_details"]["detail"].as_str().unwrap().to_string();
                assert_eq!(texte, ci4_une_ligne(detail), "{ctx} : détail");
                texte
            }
            ("generic", m) if m.ends_with("ci4-gabarit") => {
                let corps = appel.apres("--data-raw");
                assert_eq!(corps, format!("{titre}|{}", ci4_une_ligne(detail)), "{ctx} : gabarit rendu");
                corps.split_once('|').unwrap().1.to_string()
            }
            ("generic", m) if m.ends_with("ci4-json") => {
                let brut = appel.apres("--data-raw");
                assert!(appel.args.contains(&"Content-Type: application/json".to_string()), "{ctx} : type par défaut : {:?}", appel.args);
                let corps: Value = serde_json::from_str(&brut).unwrap_or_else(|er| panic!("{ctx} : le gabarit JSON part en JSON valide : {er} : {brut}"));
                assert_eq!(corps, json!({ "text": format!("{titre} : {}", ci4_une_ligne(detail)) }), "{ctx} : gabarit JSON rendu");
                corps["text"].as_str().unwrap().strip_prefix(&format!("{titre} : ")).unwrap().to_string()
            }
            ("generic", _) => {
                let corps: Value = serde_json::from_str(&appel.apres("--data-raw")).unwrap();
                assert_eq!(corps, json!({ "ts": ts, "severity": 3, "title": titre, "detail": detail, "host": CI4_HOTE }), "{ctx}");
                corps["detail"].as_str().unwrap().to_string()
            }
            autre => panic!("canal inconnu du témoin : {autre:?}"),
        }
    }

    /// L'appel du canal `marque` pour l'alerte `titre` : exactement un.
    fn ci4_appel_de<'a>(appels: &'a [Ci4Appel], marque: &str, titre: &str) -> &'a Ci4Appel {
        let trouves: Vec<&Ci4Appel> = appels.iter().filter(|a| a.tout().contains(marque) && a.tout().contains(titre)).collect();
        assert_eq!(trouves.len(), 1, "un appel et un seul pour {marque} / {titre}");
        trouves[0]
    }

    /// Joue `commande` (le binaire de test, que le témoin `test` relance avec la variable de son bras d'enfant posée) :
    /// le témoin rejoué seul, avec le faux `curl` en tête de `PATH` et un `TMPDIR` à lui ; rend les appels capturés et
    /// la sortie d'erreur. Chaque fichier téléversé (corps d'un courriel) doit se trouver sous ce `TMPDIR`.
    fn ci4_dispatch_dans_un_enfant(mut commande: std::process::Command, test: &str, etiquette: &str) -> (Vec<Ci4Appel>, String) {
        let bac = crate::tmp_possede::TmpPossede::neuf(etiquette);
        let faux = bac.join("curl");
        std::fs::write(&faux, CI4_FAUX_CURL).expect("fixture : faux curl écrit");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&faux, std::fs::Permissions::from_mode(0o755)).expect("fixture : faux curl exécutable");
        }
        let capture = bac.join("capture");
        let tmp_de_l_enfant = bac.join("tmp");
        std::fs::create_dir_all(&capture).unwrap();
        std::fs::create_dir_all(&tmp_de_l_enfant).unwrap();
        let path = format!("{}:{}", bac.display(), std::env::var("PATH").unwrap_or_default());
        commande
            .args(["--exact", "--nocapture", "--test-threads=1", &format!("tests::preuves_d_alerte_dans_la_liste_des_regles_et_les_notifications::{test}")])
            .env("PATH", &path)
            .env("CI4_CAPTURE", &capture)
            .env("TMPDIR", &tmp_de_l_enfant)
            .stdin(std::process::Stdio::null());
        let sortie = commande.output().expect("ré-exécution du binaire de test");
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "l'enfant sort en 0 : {stderr}");
        let appels = ci4_appels(&capture);
        let televerses: Vec<String> = appels.iter().filter(|a| a.args.iter().any(|x| x == "--upload-file")).map(|a| a.apres("--upload-file")).collect();
        assert_eq!(televerses.len(), 3, "un courriel par alerte : {televerses:?}");
        for f in &televerses {
            assert!(
                std::path::Path::new(f).starts_with(&tmp_de_l_enfant),
                "le corps du courriel est écrit sous le TMPDIR de son sous-processus ({}) : {f}",
                tmp_de_l_enfant.display()
            );
        }
        (appels, stderr)
    }

    fn ci4_vals_du_lookup(dbp: &str) -> Vec<Value> {
        let c = open_db(dbp).unwrap();
        let mut s = c.prepare("SELECT val FROM lookup_kv WHERE name='ci4_alertes' ORDER BY key").unwrap();
        let vals: Vec<String> = s.query_map([], |r| r.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap();
        vals.iter().map(|v| serde_json::from_str(v).unwrap()).collect()
    }

    #[tokio::test]
    async fn ci4_chaque_canal_emporte_les_preuves_servies_au_lecteur() {
        const ENFANT: &str = "CI4_ENFANT_CANAUX";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            let chemin = std::env::var(ENFANT).unwrap();
            // Comme le démarrage du serveur (server/mod.rs : `field_filters_reload` de la base avant tout envoi) : le
            // registre est CHARGÉ, ici sur une table de filtres vide, et l'envoi doit quand même porter les preuves.
            let conn = open_db(&chemin).unwrap();
            let filtres: i64 = conn.query_row("SELECT COUNT(*) FROM field_filter", [], |r| r.get(0)).unwrap();
            assert_eq!(filtres, 0, "contrôle : table des filtres de champs vide");
            field_filters_reload(&conn, &chemin);
            assert!(crate::field_filter::field_deny_cols_cell().read().contains_key(&chemin), "contrôle : registre chargé");
            dispatch_notifications(&Arc::new(Mutex::new(conn)));
            return;
        }
        let (st, dbp) = ci4_base_de_canaux("ci4-canaux", false);
        let servies = ci4_preuves_servies_au_lecteur(st).await;
        let e = servies[&9401].clone().expect("l'alerte A porte ses preuves");
        assert_eq!(e["state"], json!("established"), "contrôle : la route sert les preuves au lecteur : {e}");
        assert_eq!(e["rows"].as_array().map(Vec::len), Some(3), "contrôle : trois lignes : {e}");
        assert_eq!(servies[&9402], None, "contrôle : l'alerte B ne porte pas de preuves");
        assert_eq!(servies[&9403], None, "contrôle : l'alerte C ne porte pas de preuves");
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande.env(ENFANT, dbp.as_str());
        let (appels, stderr) = ci4_dispatch_dans_un_enfant(commande, "ci4_chaque_canal_emporte_les_preuves_servies_au_lecteur", "ci4-faux-curl");
        assert_eq!(appels.len(), CI4_CANAUX.len() * 3, "huit canaux réseau, trois alertes : {stderr}");
        let attendus = [
            (CI4_TITRE_ETABLIES, CI4_TS, format!("{CI4_DETAIL}\n\n{CI4_MENTION_JOINTES}\n{e}")),
            (CI4_TITRE_NON_FIGEES, CI4_TS + 1, format!("{CI4_DETAIL}\n\n{CI4_MENTION_NON_FIGEES}")),
            (CI4_TITRE_SANS, CI4_TS + 2, CI4_DETAIL.to_string()),
        ];
        for (titre, ts, detail) in &attendus {
            for (_, genre, _, _, marque) in CI4_CANAUX {
                let parti = ci4_charge_du_canal(ci4_appel_de(&appels, marque, titre), genre, marque, titre, detail, *ts);
                if *titre == CI4_TITRE_ETABLIES {
                    // Champ pour champ : l'objet joint, relu du détail parti, est celui que la route sert au lecteur.
                    let (_, objet) = parti.split_once(CI4_MENTION_JOINTES).unwrap_or_else(|| panic!("{marque} : mention absente : {parti}"));
                    let objet: Value = serde_json::from_str(objet.trim_start()).unwrap_or_else(|er| panic!("{marque} : objet joint illisible : {er} : {objet}"));
                    assert_eq!(objet, e, "{marque} : l'objet joint est celui que /api/alerts sert au lecteur");
                    assert_eq!(objet.as_object().map(|o| o.len()), e.as_object().map(|o| o.len()), "{marque} : mêmes champs");
                }
            }
        }
        // Le lookup reçoit ce qu'il recevait : ni détail ni preuves.
        let vals = ci4_vals_du_lookup(dbp.as_str());
        assert_eq!(vals.len(), 2, "une clé par règle");
        for v in &vals {
            let mut cles: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
            cles.sort_unstable();
            assert_eq!(cles, vec!["host", "mitre", "severity", "source", "title", "ts"], "lookup : champs d'avant : {v}");
            for ip in CI4_IPS {
                assert!(!v.to_string().contains(ip), "lookup : aucune adresse des preuves : {v}");
            }
        }
    }

    #[tokio::test]
    async fn ci4_preuves_masquees_pour_le_lecteur_ne_sortent_par_aucun_canal() {
        const ENFANT: &str = "CI4_ENFANT_CANAUX_MASQUES";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        if std::env::var(ENFANT).is_ok() {
            let chemin = std::env::var(ENFANT).unwrap();
            // Comme le démarrage du serveur : le registre est chargé, ici avec la règle de filtre de la base.
            let conn = open_db(&chemin).unwrap();
            field_filters_reload(&conn, &chemin);
            assert!(crate::field_filter::registre_porte_une_regle(&chemin), "contrôle : registre chargé avec une règle");
            dispatch_notifications(&Arc::new(Mutex::new(conn)));
            return;
        }
        let (st, dbp) = ci4_base_de_canaux("ci4-canaux-masques", true);
        let servies = ci4_preuves_servies_au_lecteur(st).await;
        let e = servies[&9401].clone().expect("la route sert l'état des preuves de l'alerte A");
        assert_eq!(e["state"], json!("withheld"), "contrôle : au lecteur, la route retient les preuves : {e}");
        let mut commande = std::process::Command::new(std::env::current_exe().expect("binaire de test"));
        commande.env(ENFANT, dbp.as_str());
        let enfant = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ci4_dispatch_dans_un_enfant(commande, "ci4_preuves_masquees_pour_le_lecteur_ne_sortent_par_aucun_canal", "ci4-faux-curl-masques")
        }));
        crate::field_filter::field_filters_forget(dbp.as_str());
        let (appels, stderr) = enfant.unwrap_or_else(|p| std::panic::resume_unwind(p));
        assert_eq!(appels.len(), CI4_CANAUX.len() * 3, "huit canaux réseau, trois alertes : {stderr}");
        for (_, genre, _, _, marque) in CI4_CANAUX {
            let detail = format!("{CI4_DETAIL}\n\n{CI4_MENTION_RETENUES}");
            ci4_charge_du_canal(ci4_appel_de(&appels, marque, CI4_TITRE_ETABLIES), genre, marque, CI4_TITRE_ETABLIES, &detail, CI4_TS);
        }
        for appel in &appels {
            let tout = appel.tout();
            for ip in CI4_IPS {
                assert!(!tout.contains(ip), "aucune adresse des preuves ne sort : {tout}");
            }
            assert!(!tout.contains("rows"), "aucun objet de preuves ne sort : {tout}");
        }
        for v in ci4_vals_du_lookup(dbp.as_str()) {
            for ip in CI4_IPS {
                assert!(!v.to_string().contains(ip), "lookup : aucune adresse des preuves : {v}");
            }
        }
    }

    // ------------------------------------------------------------------------------------------------------- (C)

    fn ci4_lues(ecrites: &str) -> PreuvesLuesALEnvoi {
        PreuvesLuesALEnvoi::Lues { ecrites: Some(Some(ecrites.to_string())), declarees: true }
    }

    /// Des preuves établies de `n` lignes `["198.51.100.<i>", <i>]`, la dernière portant en plus `bourrage`.
    fn ci4_etablies(n: usize, bourrage: &str) -> Value {
        let lignes: Vec<Value> = (0..n)
            .map(|i| if i + 1 == n { json!([format!("198.51.100.{i}"), i, bourrage]) } else { json!([format!("198.51.100.{i}"), i]) })
            .collect();
        PreuvesDatees { instant: CI4_TS, window_s: 3600, preuves: Preuves::Etablies { colonnes: vec![json!("src_ip"), json!("n")], lignes, total_exact: true } }.en_json()
    }

    /// Le bourrage de la dernière ligne (des `x`) qui porte l'objet à `octets` octets exactement.
    fn ci4_bourrage_pour(n: usize, octets: usize) -> String {
        "x".repeat(octets - ci4_etablies(n, "").to_string().len())
    }

    #[test]
    fn ci4_borne_d_octets_aux_bords_et_coupe_par_la_fin() {
        for octets in [CI4_BORNE_OCTETS - 1, CI4_BORNE_OCTETS] {
            let objet = ci4_etablies(5, &ci4_bourrage_pour(5, octets));
            assert_eq!(objet.to_string().len(), octets, "fixture : taille en octets");
            assert_eq!(
                texte_des_preuves_a_l_envoi(&ci4_lues(&objet.to_string()), MasquageALEnvoi::Aucun),
                format!("\n\n{CI4_MENTION_JOINTES}\n{objet}"),
                "{octets} octets : sous la borne ou à la borne, l'objet est joint à l'identique"
            );
        }
        // Une ligne de trop : borne + 1 en octets (ASCII), puis une matière multioctet dont le nombre de caractères tient
        // sous la borne alors que ses octets la dépassent.
        let multioctet = {
            let vide = ci4_etablies(5, "").to_string().len();
            "é".repeat((CI4_BORNE_OCTETS + 2 - vide) / 2)
        };
        let deborde_ascii = ci4_etablies(5, &ci4_bourrage_pour(5, CI4_BORNE_OCTETS + 1));
        let deborde_multi = ci4_etablies(5, &multioctet);
        assert!(deborde_multi.to_string().len() > CI4_BORNE_OCTETS, "fixture : les octets dépassent");
        assert!(deborde_multi.to_string().chars().count() <= CI4_BORNE_OCTETS, "fixture : les caractères tiennent");
        for objet in [deborde_ascii, deborde_multi] {
            let texte = texte_des_preuves_a_l_envoi(&ci4_lues(&objet.to_string()), MasquageALEnvoi::Aucun);
            let joint = texte.strip_prefix(&format!("\n\n{CI4_MENTION_COUPEES}\n")).unwrap_or_else(|| panic!("mention de la coupe : {texte}"));
            assert!(joint.len() <= CI4_BORNE_OCTETS, "l'objet joint tient dans la borne");
            let mut attendu = objet.clone();
            attendu["rows"] = Value::Array(objet["rows"].as_array().unwrap()[..4].to_vec());
            attendu["served"] = json!(4);
            attendu["truncated"] = json!(true);
            attendu["phrase"] = json!(CI4_PHRASE_COUPEES);
            assert_eq!(serde_json::from_str::<Value>(joint).unwrap(), attendu, "coupé par la fin, la coupe dite (served, truncated, phrase)");
        }
    }

    #[test]
    fn ci4_borne_de_lignes_aux_bords() {
        for (n, servies) in [(CI4_BORNE_LIGNES - 1, CI4_BORNE_LIGNES - 1), (CI4_BORNE_LIGNES, CI4_BORNE_LIGNES), (CI4_BORNE_LIGNES + 1, CI4_BORNE_LIGNES)] {
            // L'objet est posé à la main : `en_json` coupe déjà à la borne à l'écriture, un objet de plus de lignes ne
            // vient que d'une base écrite autrement (édition, version future) ; l'envoi le borne quand même.
            let mut objet = ci4_etablies(1, "");
            objet["rows"] = Value::Array((0..n).map(|i| json!([i])).collect());
            objet["served"] = json!(n);
            objet["total"] = json!(n);
            assert!(objet.to_string().len() < CI4_BORNE_OCTETS, "fixture : la taille ne coupe pas");
            let texte = texte_des_preuves_a_l_envoi(&ci4_lues(&objet.to_string()), MasquageALEnvoi::Aucun);
            if servies == n {
                assert_eq!(texte, format!("\n\n{CI4_MENTION_JOINTES}\n{objet}"), "{n} lignes : jointes à l'identique");
            } else {
                let joint = texte.strip_prefix(&format!("\n\n{CI4_MENTION_COUPEES}\n")).unwrap_or_else(|| panic!("{n} lignes : coupe dite : {texte}"));
                let joint: Value = serde_json::from_str(joint).unwrap();
                assert_eq!(joint["rows"].as_array().map(Vec::len), Some(servies), "{n} lignes : bornées");
                assert_eq!((joint["served"].clone(), joint["truncated"].clone()), (json!(servies), json!(true)), "{n} lignes");
            }
        }
    }

    #[test]
    fn ci4_objet_trop_grand_meme_sans_ligne() {
        let objet = PreuvesDatees {
            instant: CI4_TS,
            window_s: 3600,
            preuves: Preuves::Etablies { colonnes: vec![json!("c".repeat(CI4_BORNE_OCTETS))], lignes: vec![json!(["198.51.100.1"])], total_exact: true },
        }
        .en_json();
        assert_eq!(
            texte_des_preuves_a_l_envoi(&ci4_lues(&objet.to_string()), MasquageALEnvoi::Aucun),
            format!("\n\n{CI4_MENTION_TROP_GRANDES}")
        );
    }

    #[test]
    fn ci4_chaque_issue_a_sa_mention() {
        let etablies = ci4_preuves_etablies_ecrites();
        let sans_ligne = PreuvesDatees { instant: CI4_TS, window_s: 3600, preuves: Preuves::SansLigne { colonnes: vec![json!("src_ip")] } }.en_json().to_string();
        let non_etablies = PreuvesDatees { instant: CI4_TS, window_s: 3600, preuves: Preuves::NonEtablies { cause: crate::detection_aveugle::CAUSE_BUDGET_DEPASSE } }
            .en_json()
            .to_string();
        let cause_hors_ensemble = json!({ "state": "not_established", "cause": "no such table: event (198.51.100.20)" }).to_string();
        let forme_inconnue = json!({ "state": "autre", "rows": [["198.51.100.20"]] }).to_string();
        let lues = |e: &str| ci4_lues(e);
        let cas: Vec<(&str, PreuvesLuesALEnvoi, MasquageALEnvoi, String)> = vec![
            ("ligne non relue", PreuvesLuesALEnvoi::NonLues, MasquageALEnvoi::Aucun, format!("\n\n{CI4_MENTION_NON_RELUES}")),
            ("règle sans preuves", PreuvesLuesALEnvoi::Lues { ecrites: None, declarees: false }, MasquageALEnvoi::Aucun, String::new()),
            ("règle sans preuves, masque", PreuvesLuesALEnvoi::Lues { ecrites: None, declarees: false }, MasquageALEnvoi::Actif, String::new()),
            ("non figées", PreuvesLuesALEnvoi::Lues { ecrites: None, declarees: true }, MasquageALEnvoi::Aucun, format!("\n\n{CI4_MENTION_NON_FIGEES}")),
            ("retenues", lues(&etablies), MasquageALEnvoi::Actif, format!("\n\n{CI4_MENTION_RETENUES}")),
            ("registre non lu", lues(&etablies), MasquageALEnvoi::NonLu, format!("\n\n{CI4_MENTION_MASQUAGE_NON_LU}")),
            ("cellule illisible", PreuvesLuesALEnvoi::Lues { ecrites: Some(None), declarees: true }, MasquageALEnvoi::Aucun, format!("\n\n{CI4_MENTION_ILLISIBLES}")),
            ("JSON illisible", lues("pas du JSON 198.51.100.20"), MasquageALEnvoi::Aucun, format!("\n\n{CI4_MENTION_ILLISIBLES}")),
            ("aucune ligne", lues(&sans_ligne), MasquageALEnvoi::Aucun, format!("\n\n{CI4_MENTION_SANS_LIGNE}")),
            ("non établies", lues(&non_etablies), MasquageALEnvoi::Aucun, format!("\n\n{CI4_MENTION_NON_ETABLIES} budget_depasse.")),
            ("cause hors ensemble", lues(&cause_hors_ensemble), MasquageALEnvoi::Aucun, format!("\n\n{CI4_MENTION_NON_ETABLIES} inconnue.")),
            ("forme inconnue", lues(&forme_inconnue), MasquageALEnvoi::Aucun, format!("\n\n{CI4_MENTION_FORME_INCONNUE}")),
            ("établies, jointes déclarées ou non", PreuvesLuesALEnvoi::Lues { ecrites: Some(Some(etablies.clone())), declarees: false }, MasquageALEnvoi::Aucun,
                format!("\n\n{CI4_MENTION_JOINTES}\n{}", serde_json::from_str::<Value>(&etablies).unwrap())),
        ];
        for (nom, l, m, attendu) in &cas {
            assert_eq!(&texte_des_preuves_a_l_envoi(l, *m), attendu, "{nom}");
        }
    }

    // ------------------------------------------------------------------------------------------------------- (D)

    #[test]
    fn ci4_relecture_de_l_alerte_a_l_envoi() {
        let c = test_db();
        c.execute_batch(
            "DELETE FROM rule; DELETE FROM alert;\
             INSERT INTO rule(id,name,evidence_query) VALUES(921,'ci4-d-avec','SELECT 1'),(922,'ci4-d-vide',''),(923,'ci4-d-null',NULL);\
             INSERT INTO alert(id,ts,rule,severity,title,evidence) VALUES\
               (9501,1,'rule.921',3,'t','{\"state\":\"no_rows\"}'),\
               (9502,1,'rule.922',3,'t',NULL),\
               (9503,1,'rule.923',3,'t',NULL),\
               (9504,1,'rule.921',3,'t',X'7B7D'),\
               (9505,1,'rule.921',3,'t',CAST(X'FF' AS TEXT)),\
               (9506,1,'heartbeat.ci4',3,'t',NULL);",
        )
        .unwrap();
        let lues = |id: i64| lire_les_preuves_a_l_envoi(&c, id);
        let l = |ecrites: Option<Option<&str>>, declarees: bool| PreuvesLuesALEnvoi::Lues { ecrites: ecrites.map(|e| e.map(str::to_string)), declarees };
        assert_eq!(lues(9501), l(Some(Some("{\"state\":\"no_rows\"}")), true), "texte, règle qui déclare");
        assert_eq!(lues(9502), l(None, false), "règle à requête de preuves vide : ne déclare pas");
        assert_eq!(lues(9503), l(None, false), "règle à requête NULL (une autre règle déclare) : ne déclare pas");
        assert_eq!(lues(9504), l(Some(None), true), "cellule BLOB : illisible");
        assert_eq!(lues(9505), l(Some(None), true), "texte non UTF-8 : illisible");
        assert_eq!(lues(9506), l(None, false), "alerte hors règle");
        assert_eq!(lues(9599), PreuvesLuesALEnvoi::NonLues, "ligne absente : non relue");
        c.execute_batch("ALTER TABLE alert DROP COLUMN evidence;").unwrap();
        assert_eq!(lues(9501), PreuvesLuesALEnvoi::NonLues, "colonne absente : non relue");
    }

    // ------------------------------------------------------------------------------------------------------- (E)

    #[test]
    fn ci4_masquage_vu_par_l_envoi() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let p = crate::tmp_possede::TmpDb::neuf("ci4-masquage");
        let c = open_db(p.as_str()).unwrap();
        c.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&c), "fixture : migrations");
        c.execute("DELETE FROM field_filter", []).unwrap();
        let m = || masquage_a_l_envoi(&c);
        assert_eq!(m(), MasquageALEnvoi::Aucun, "table vide");
        c.execute("INSERT INTO field_filter(name,field,action,role) VALUES('ci4-e','src_ip','mask','')", []).unwrap();
        assert_eq!(m(), MasquageALEnvoi::Actif, "règle active");
        c.execute("UPDATE field_filter SET enabled=0", []).unwrap();
        assert_eq!(m(), MasquageALEnvoi::Aucun, "règle éteinte (entier 0)");
        c.execute("UPDATE field_filter SET enabled='non'", []).unwrap();
        assert_eq!(m(), MasquageALEnvoi::Actif, "activité illisible : active, comme dans le registre");
        c.execute("UPDATE field_filter SET enabled=1, tenant='autre', env='prod'", []).unwrap();
        assert_eq!(m(), MasquageALEnvoi::Actif, "règle d'un autre tenant et d'un autre environnement : au plus large");
        // Armée dans le registre en mémoire, puis retirée de la table sans rechargement.
        c.execute("UPDATE field_filter SET tenant='', env=''", []).unwrap();
        field_filters_reload(&c, p.as_str());
        c.execute("DELETE FROM field_filter", []).unwrap();
        assert_eq!(m(), MasquageALEnvoi::Actif, "règle encore armée dans le registre");
        crate::field_filter::field_filters_forget(p.as_str());
        assert_eq!(m(), MasquageALEnvoi::Aucun, "contrôle : registre vide, table vide");
        // Armée dans le registre avec une portée (un autre tenant, un autre environnement), puis retirée de la table :
        // `/api/alerts` la retient pour le lecteur de ce tenant, l'envoi aussi.
        c.execute("INSERT INTO field_filter(name,field,action,role,tenant,env) VALUES('ci4-e','src_ip','mask','','autre','prod')", []).unwrap();
        field_filters_reload(&c, p.as_str());
        c.execute("DELETE FROM field_filter", []).unwrap();
        assert_eq!(m(), MasquageALEnvoi::Actif, "règle à portée encore armée dans le registre : au plus large");
        crate::field_filter::field_filters_forget(p.as_str());
        assert_eq!(m(), MasquageALEnvoi::Aucun, "contrôle : registre oublié");
        // Armée sous un chemin de base qui passe par un lien (le db_path configuré), alors que la connexion tient le
        // chemin de la base elle-même.
        let dossier = crate::tmp_possede::TmpPossede::neuf("ci4-masquage-lien");
        let lien = dossier.join("base-par-un-lien.db");
        std::os::unix::fs::symlink(p.as_str(), &lien).expect("fixture : lien vers la base");
        let lien = lien.to_str().expect("fixture : chemin UTF-8").to_string();
        assert_ne!(c.path(), Some(lien.as_str()), "contrôle : la connexion ne tient pas le chemin du lien");
        c.execute("INSERT INTO field_filter(name,field,action,role) VALUES('ci4-e','src_ip','mask','')", []).unwrap();
        field_filters_reload(&c, &lien);
        c.execute("DELETE FROM field_filter", []).unwrap();
        let sous_le_lien = m();
        crate::field_filter::field_filters_forget(&lien);
        assert_eq!(sous_le_lien, MasquageALEnvoi::Actif, "règle armée sous le chemin du lien : la base est reconnue");
        assert_eq!(m(), MasquageALEnvoi::Aucun, "contrôle : registre oublié");
        c.execute_batch("DROP TABLE field_filter;").unwrap();
        assert_eq!(m(), MasquageALEnvoi::NonLu, "table absente : non lue");
    }

    /// Le démarrage du serveur (server/mod.rs) appelle `field_filters_reload` sur la base même quand sa table de filtres est
    /// vide : le registre range alors un vecteur vide sous le db_path, ce qui n'est pas une règle.
    #[test]
    fn ci4_registre_charge_sur_une_table_vide_ne_retient_rien() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read();
        let p = crate::tmp_possede::TmpDb::neuf("ci4-registre-vide");
        let c = open_db(p.as_str()).unwrap();
        c.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&c), "fixture : migrations");
        c.execute("DELETE FROM field_filter", []).unwrap();
        field_filters_reload(&c, p.as_str());
        let charge = crate::field_filter::field_deny_cols_cell().read().contains_key(p.as_str());
        let sous_le_chemin = masquage_a_l_envoi(&c);
        crate::field_filter::field_filters_forget(p.as_str());
        // Le même chargement sous un chemin qui passe par un lien (reconnu par le chemin canonique), seul dans le registre.
        let dossier = crate::tmp_possede::TmpPossede::neuf("ci4-registre-vide-lien");
        let lien = dossier.join("base-par-un-lien.db");
        std::os::unix::fs::symlink(p.as_str(), &lien).expect("fixture : lien vers la base");
        let lien = lien.to_str().expect("fixture : chemin UTF-8").to_string();
        field_filters_reload(&c, &lien);
        let charge_lien = crate::field_filter::field_deny_cols_cell().read().contains_key(&lien);
        let sous_le_lien = masquage_a_l_envoi(&c);
        crate::field_filter::field_filters_forget(&lien);
        assert!(charge && charge_lien, "contrôle : registre chargé sous les deux chemins");
        assert_eq!(sous_le_chemin, MasquageALEnvoi::Aucun, "registre chargé sur une table vide : aucun masquage");
        assert_eq!(sous_le_lien, MasquageALEnvoi::Aucun, "registre chargé sur une table vide, sous un lien : aucun masquage");
    }

    // ------------------------------------------------------------------------------------------------------- (F)

    #[test]
    fn ci4_gabarit_du_canal_generic_selon_le_type_de_contenu() {
        use crate::handlers::alerting::render_template_pour_le_type;
        const GABARIT: &str = "{\"t\":\"{{title}}\",\"d\":\"{{detail}}\",\"h\":\"{{host}}\",\"s\":{{severity}},\"n\":\"{{sev_name}}\",\"ts\":{{ts}}}";
        let titre = "T \"guillemets\" \\ barre";
        let detail = "D\n\nPreuves : {\"rows\":[[\"198.51.100.20\",40]]}\ttab";
        let hote = "h\"1";
        for json in ["application/json", "Application/JSON ; charset=utf-8", "application/vnd.exemple+json"] {
            let rendu = render_template_pour_le_type(GABARIT, json, 3, titre, detail, hote, 99);
            let relu: Value = serde_json::from_str(&rendu).unwrap_or_else(|e| panic!("{json} : JSON valide : {e} : {rendu}"));
            assert_eq!(
                relu,
                json!({ "t": titre, "d": "D  Preuves : {\"rows\":[[\"198.51.100.20\",40]]}\ttab", "h": hote, "s": 3, "n": "high", "ts": 99 }),
                "{json} : chaque valeur relue à l'identique (sauts de ligne neutralisés)"
            );
        }
        for litteral in ["text/plain", "application/jsonl", "application/x-www-form-urlencoded"] {
            assert_eq!(
                render_template_pour_le_type("{{title}}|{{detail}}|{{host}}", litteral, 3, titre, detail, hote, 99),
                format!("{titre}|{}|{hote}", ci4_une_ligne(detail)),
                "{litteral} : rendu littéral"
            );
        }
        assert_eq!(
            render_template_pour_le_type(GABARIT, "application/json", 1, "titre", "detail", "hote", 7),
            crate::handlers::alerting::render_template(GABARIT, 1, "titre", "detail", "hote", 7),
            "valeurs sans caractère à échapper : rendu identique"
        );
    }
}
