// =====================================================================================
// `P10.20-l` (tranche de la vague AK) — TROIS ESSAIS À BLANC, UN ENVOI MANUEL ET LE MODE DES PLAYBOOKS confondaient
// « aucune ligne » et « lecture qui n'a pas eu lieu ». `P10.31-k` (reste) — l'essai d'un playbook compilait avec la
// fenêtre BRUTE quand le passage réel prend la fenêtre planchée.
//
// LE DÉFAUT, MESURÉ SUR 307d4dc3 AVANT LE CORRECTIF.
//   * `rule_test` (`detection.rs`), `correlation_test` (`detection_advanced.rs`) : la ligne lue par `.ok()` ; une
//     lecture ratée se servait 404 « règle introuvable » / « corrélation introuvable ».
//   * `destination_flush` (`destinations.rs`) : `.ok()` ; une lecture ratée se servait 404 « destination introuvable ou
//     désactivée ».
//   * `run_playbooks` (`playbooks.rs`) : `plume_mode` lu `.unwrap_or_else(|_| "observe")` — une lecture ratée valait
//     « observe », le tick évaluait tout et publiait `Lue(0)`, sans un mot.
//   * `playbook_test` : `rule_sql_for_caller(.., window_s)` BRUT, quand `run_playbooks` compile avec
//     `fenetre_de_requete_du_playbook(window_s, interval_s)`. Fenêtre 5 s, intervalle 300 s, événement de 100 s : le
//     passage le voit et pose la riposte, l'essai rendait `targets: []`.
//
// LE CORRECTIF (décisions par défaut des vagues AF à AJ). Trois issues par `.optional()` : présent, la suite ; absent,
// le 404 d'avant à l'octet ; lecture ratée, 503 nommé (`CAUSE_REGLE_NON_ESSAYEE_NON_LUE`,
// `CAUSE_CORRELATION_NON_ESSAYEE_NON_LUE`, `CAUSE_ENVOI_MANUEL_NON_FAIT_NON_LU`, corps `{error, id}`), rien n'est
// exécuté ni envoyé, la cause du moteur au journal seul avec l'identifiant servi, aucun 403 décidé (le 403 « réservé
// admin » de l'envoi manuel reste AVANT la lecture). Le mode : ligne absente = « observe » établi ; lecture ratée = tick
// AVEUGLE (`Mesure::Illisible`, cause de `cause_sql`, détail `DETAIL_DU_TICK_DE_PLAYBOOKS_MODE_NON_LU`), aucun playbook
// évalué, aucune riposte, le marqueur de passage non posé. L'essai d'un playbook lit `interval_s` et compile avec la
// fenêtre du passage.
//
// LES PANNES ÉPROUVÉES : autorisateur SQLite qui refuse la lecture d'une table (`rule`, `correlation`, `destination`,
// `meta`) sur l'écrivain du tenant visé ; valeur de mode en BLOB (forme inconnue). Lignes de journal lues sur le stderr
// d'un sous-processus, ENTIÈRES, par égalité ; corps de refus comparés EN ENTIER.
//
// MUTANTS (posés le temps de la preuve sous `cfg!(test)` par la variable de mutation, retirés avant le commit), chacun vu ROUGE :
// la forme d'avant au site (`AK2_REGLE`, `AK2_CORR`, `AK2_DEST`, `AK2_PB_MODE`, `AK2_PB_FENETRE_BRUTE`) ; l'absence
// servie en lecture ratée (`AK2_REGLE_ABSENT`, `AK2_CORR_ABSENT`, `AK2_DEST_ABSENT`, `AK2_PB_MODE_ABSENT`) ; la ligne de
// journal retirée (`AK2_REGLE_SANS_JOURNAL`, `AK2_CORR_SANS_JOURNAL`, `AK2_DEST_SANS_JOURNAL`) ; le 403 retiré de
// l'envoi manuel (`AK2_DEST_SANS_403`) ; le détail du tick rendu par `tick_aveugle` (`AK2_PB_TICK_AVEUGLE`).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : les masques #45 des essais (surface d'appelant) ne sont pas rejoués ici — le
// correctif ne touche ni `rule_sql_for_caller` ni `caller_dryrun_guard`, que tiennent les témoins `sec_ff_` ;
// « aucune requête exécutée » sur une lecture ratée tient par le retour anticipé, observé par le corps et la ligne.
// =====================================================================================
mod essais_a_blanc_et_mode_des_playbooks_en_trois_issues {
    use super::*;
    use crate::handlers::destinations::{destination_flush, CAUSE_ENVOI_MANUEL_NON_FAIT_NON_LU};
    use crate::handlers::detection::{rule_test, CAUSE_REGLE_NON_ESSAYEE_NON_LUE};
    use crate::handlers::detection_advanced::{correlation_test, CAUSE_CORRELATION_NON_ESSAYEE_NON_LUE};
    use crate::handlers::playbooks::{playbook_test, run_playbooks, DETAIL_DU_TICK_DE_PLAYBOOKS_MODE_NON_LU};
    use crate::mesure_environnement::{Mesure, CAUSE_FORME_INCONNUE, CAUSE_SOURCE_ILLISIBLE};
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const AK2_REQUETE_REGLE: &str = "search source=ak2 | stats count";
    const AK2_ETAPES: &str = r#"[{"query":"search source=ak2 | table ts,src_ip"}]"#;
    const AK2_CIBLE: &str = "203.0.113.82";
    const AK2_REQUETE_PB: &str = "SELECT src_ip FROM event WHERE source='ak2-pb' AND ts>=__FROM__ GROUP BY src_ip";
    const AK2_MDP_EDITEUR: &str = "ak2-editeur-pw-12345";

    fn ak2_sql(db: &Arc<Mutex<Connection>>, sql: &str) {
        db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` s'écrit ({e})"));
    }

    fn ak2_entier(db: &Arc<Mutex<Connection>>, sql: &str) -> i64 {
        db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    async fn ak2_reponse(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        let corps = if b.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned()))
        };
        (statut, corps)
    }

    /// Refuse toute lecture de `table` sur cet écrivain.
    fn ak2_refuser(db: &Arc<Mutex<Connection>>, table: &'static str) {
        db.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, .. } if table_name == table => Authorization::Deny,
            _ => Authorization::Allow,
        }));
    }

    fn ak2_lever(db: &Arc<Mutex<Connection>>) {
        db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// La cause du moteur que rend `sql` sous le refus posé (lue à part, pour comparer la ligne de journal).
    fn ak2_cause(db: &Arc<Mutex<Connection>>, sql: &str) -> String {
        db.lock().query_row(sql, [], |_| Ok(())).expect_err("fixture : lecture refusée").to_string()
    }

    /// Un 503 nommé : le corps ENTIER est `{error: <cause>, id: <identifiant>}` ; rend l'identifiant servi.
    fn ak2_cinq_cents(quoi: &str, (statut, corps): &(u16, Value), cause: &str) -> String {
        assert_eq!(*statut, 503, "{quoi} : statut : {corps}");
        let o = corps.as_object().unwrap_or_else(|| panic!("{quoi} : corps JSON objet : {corps}"));
        let mut cles: Vec<&str> = o.keys().map(String::as_str).collect();
        cles.sort_unstable();
        assert_eq!(cles, ["error", "id"], "{quoi} : ensemble exact des clés : {corps}");
        assert_eq!(corps["error"], json!(cause), "{quoi} : la phrase seule, sans texte du moteur : {corps}");
        corps["id"].as_str().filter(|s| s.starts_with("plume-e")).unwrap_or_else(|| panic!("{quoi} : identifiant : {corps}")).to_string()
    }

    fn ak2_au(name: &str, role: &str, tenant: &str) -> AuthUser {
        AuthUser {
            name: name.into(), role: role.into(), tenant: tenant.into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    /// `n` événements `source=ak2` récents, adresses distinctes.
    fn ak2_semer(db: &Arc<Mutex<Connection>>, n: i64, tag: &str) {
        let t = crate::now() - 30;
        for i in 0..n {
            db.lock()
                .execute(
                    "INSERT INTO event(ts,source,category,severity,src_ip,message,dedup) VALUES(?1,'ak2','auth',1,?2,'échec',?3)",
                    params![t, format!("203.0.113.{}", 10 + i), format!("ak2-{tag}-{i}")],
                )
                .expect("fixture : événement");
        }
    }

    fn ak2_regle(db: &Arc<Mutex<Connection>>, nom: &str) -> i64 {
        ak2_sql(db, &format!(
            "INSERT INTO rule(name,query,is_soql,op,threshold,severity,window_s,interval_s,enabled) VALUES('{nom}','{AK2_REQUETE_REGLE}',1,'>',0,3,86400,3600,0);"
        ));
        ak2_entier(db, &format!("SELECT id FROM rule WHERE name='{nom}'"))
    }

    fn ak2_correlation(db: &Arc<Mutex<Connection>>, nom: &str) -> i64 {
        ak2_sql(db, &format!(
            "INSERT INTO correlation(name,key_field,entity_type,steps,window_s,interval_s,severity,enabled) VALUES('{nom}','src_ip','ip','{AK2_ETAPES}',86400,3600,3,0);"
        ));
        ak2_entier(db, &format!("SELECT id FROM correlation WHERE name='{nom}'"))
    }

    /// Une destination à transport bouchon (`s3`, rien ne quitte le processus).
    fn ak2_destination(db: &Arc<Mutex<Connection>>, nom: &str, active: i64) -> i64 {
        ak2_sql(db, &format!("INSERT INTO destination(type,name,enabled,endpoint) VALUES('s3','{nom}',{active},'s3://{nom}');"));
        ak2_entier(db, &format!("SELECT id FROM destination WHERE name='{nom}'"))
    }

    /// LES TROIS SITES DE LECTURE D'EXISTENCE, joués dans un sous-processus dont le stderr est lu : chaque lecture
    /// ratée rend son 503 nommé (corps ENTIER) et écrit sa ligne ENTIÈRE au journal avec l'identifiant servi ;
    /// l'envoi manuel n'envoie rien (aucun passage, aucune trace) ; absences (et destination désactivée) gardent le 404
    /// d'avant à l'octet, nominaux leur deux cents, sans ligne ; le 403 « réservé admin » de l'envoi manuel précède la
    /// lecture (servi même quand elle est refusée). MUTATIONS : `AK2_{REGLE,CORR,DEST}`, `*_ABSENT`, `*_SANS_JOURNAL`,
    /// `AK2_DEST_SANS_403`.
    #[tokio::test]
    async fn ak2_essais_et_envoi_manuel_lus_en_trois_issues() {
        const ENFANT: &str = "AK2_ENFANT_JOURNAL";
        const PHASE: &str = "AK2-PHASE:";
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // ENFANT et les gestionnaires lisent l'environnement
        if std::env::var(ENFANT).is_ok() {
            let (st, _tmp) = sp_state("ak2-essais");
            let db = st.db.clone();
            let adm = sp_au("adm", "admin");
            let ed = sp_au("alice", "editor");
            ak2_semer(&db, 2, "mono");
            let mut sortie = serde_json::Map::new();
            let mut causes = serde_json::Map::new();

            // ---- detection.rs : essai d'une règle ----
            let regle = ak2_regle(&db, "ak2-regle");
            eprintln!("{PHASE}regle");
            ak2_refuser(&db, "rule");
            causes.insert("regle".into(), json!(ak2_cause(&db, &format!("SELECT query,is_soql,op,threshold,window_s FROM rule WHERE id={regle}"))));
            sortie.insert("regle".into(), json!(ak2_reponse(rule_test(State(st.clone()), Extension(ed.clone()), Path(regle)).await).await));
            ak2_lever(&db);
            eprintln!("{PHASE}regle_controles");
            let mut c: Vec<(u16, Value)> = Vec::new();
            c.push(ak2_reponse(rule_test(State(st.clone()), Extension(ed.clone()), Path(regle + 9_999)).await).await);
            c.push(ak2_reponse(rule_test(State(st.clone()), Extension(ed.clone()), Path(regle)).await).await);
            sortie.insert("regle_controles".into(), json!(c));

            // ---- detection_advanced.rs : essai d'une corrélation ----
            let corr = ak2_correlation(&db, "ak2-corr");
            eprintln!("{PHASE}corr");
            ak2_refuser(&db, "correlation");
            causes.insert("corr".into(), json!(ak2_cause(&db, &format!("SELECT name FROM correlation WHERE id={corr}"))));
            sortie.insert("corr".into(), json!(ak2_reponse(correlation_test(State(st.clone()), Extension(ed.clone()), Path(corr)).await).await));
            ak2_lever(&db);
            eprintln!("{PHASE}corr_controles");
            let mut c: Vec<(u16, Value)> = Vec::new();
            c.push(ak2_reponse(correlation_test(State(st.clone()), Extension(ed.clone()), Path(corr + 9_999)).await).await);
            c.push(ak2_reponse(correlation_test(State(st.clone()), Extension(ed.clone()), Path(corr)).await).await);
            sortie.insert("corr_controles".into(), json!(c));

            // ---- destinations.rs : envoi manuel ----
            let dest = ak2_destination(&db, "ak2-dest", 1);
            let coupee = ak2_destination(&db, "ak2-dest-coupee", 0);
            let traces = |db: &Arc<Mutex<Connection>>| ak2_entier(db, "SELECT COUNT(*) FROM ledger WHERE kind='config.destination.flush'");
            eprintln!("{PHASE}dest_403");
            ak2_refuser(&db, "destination");
            sortie.insert("dest_403".into(), json!(ak2_reponse(destination_flush(State(st.clone()), Extension(ed.clone()), Path(dest)).await).await));
            eprintln!("{PHASE}dest");
            causes.insert("dest".into(), json!(ak2_cause(&db, &format!("SELECT type FROM destination WHERE id={dest}"))));
            sortie.insert("dest".into(), json!(ak2_reponse(destination_flush(State(st.clone()), Extension(adm.clone()), Path(dest)).await).await));
            ak2_lever(&db);
            sortie.insert("dest_rien_envoye".into(), json!([
                ak2_entier(&db, &format!("SELECT COUNT(*) FROM destination WHERE id={dest} AND last_run IS NULL")),
                traces(&db),
            ]));
            eprintln!("{PHASE}dest_controles");
            let mut c: Vec<(u16, Value)> = Vec::new();
            c.push(ak2_reponse(destination_flush(State(st.clone()), Extension(adm.clone()), Path(dest + 9_999)).await).await);
            c.push(ak2_reponse(destination_flush(State(st.clone()), Extension(adm.clone()), Path(coupee)).await).await);
            c.push(ak2_reponse(destination_flush(State(st.clone()), Extension(adm.clone()), Path(dest)).await).await);
            sortie.insert("dest_controles".into(), json!(c));
            sortie.insert("dest_envoye".into(), json!([
                ak2_entier(&db, &format!("SELECT COUNT(*) FROM destination WHERE id={dest} AND last_run IS NOT NULL")),
                traces(&db),
            ]));
            eprintln!("{PHASE}fin");

            let ids = json!({ "regle": regle, "corr": corr, "dest": dest });
            println!("AK2-SORTIE:{}", Value::Object(sortie));
            println!("AK2-CAUSES:{}", Value::Object(causes));
            println!("AK2-IDS:{ids}");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args(["--exact", "--nocapture", "--test-threads=1", "tests::essais_a_blanc_et_mode_des_playbooks_en_trois_issues::ak2_essais_et_envoi_manuel_lus_en_trois_issues"])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        let marque = |m: &str| -> Value {
            let reste = stdout.split_once(m).unwrap_or_else(|| panic!("contrôle : {m} : {stdout}")).1;
            serde_json::from_str(reste.lines().next().unwrap_or("")).unwrap_or_else(|e| panic!("contrôle : {m} JSON ({e}) : {stdout}"))
        };
        let (s, causes, ids) = (marque("AK2-SORTIE:"), marque("AK2-CAUSES:"), marque("AK2-IDS:"));
        let cause = |k: &str| -> String { causes[k].as_str().unwrap_or_else(|| panic!("contrôle : cause {k} : {causes}")).to_string() };
        let id = |k: &str| -> i64 { ids[k].as_i64().unwrap_or_else(|| panic!("contrôle : identifiant {k} : {ids}")) };
        let reponse = |k: &str| -> (u16, Value) {
            let v = &s[k];
            (v[0].as_u64().unwrap_or_else(|| panic!("contrôle : statut de {k} : {v}")) as u16, v[1].clone())
        };
        let reponses = |k: &str| -> Vec<(u16, Value)> { serde_json::from_value(s[k].clone()).unwrap_or_else(|e| panic!("contrôle : {k} ({e}) : {s}")) };
        let phase = |nom: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}\n")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.starts_with("[detection]") || l.starts_with("[destinations]")).map(str::to_string).collect()
        };
        let aucune: Vec<String> = Vec::new();

        // ---- Les lectures ratées : 503 nommé, ligne ENTIÈRE ----
        let cid = ak2_cinq_cents("règle non lue", &reponse("regle"), CAUSE_REGLE_NON_ESSAYEE_NON_LUE);
        assert_eq!(phase("regle"), [format!("[detection] WARN règle #{} NON lue pour l'essai, aucune requête exécutée ({cid}) : {}", id("regle"), cause("regle"))]);
        let cid = ak2_cinq_cents("corrélation non lue", &reponse("corr"), CAUSE_CORRELATION_NON_ESSAYEE_NON_LUE);
        assert_eq!(phase("corr"), [format!("[detection] WARN corrélation #{} NON lue pour l'essai, rien n'est évalué ({cid}) : {}", id("corr"), cause("corr"))]);
        let cid = ak2_cinq_cents("destination non lue", &reponse("dest"), CAUSE_ENVOI_MANUEL_NON_FAIT_NON_LU);
        assert_eq!(phase("dest"), [format!("[destinations] WARN destination #{} NON lue pour l'envoi manuel, rien n'est envoyé ({cid}) : {}", id("dest"), cause("dest"))]);
        assert_eq!(s["dest_rien_envoye"], json!([1, 0]), "destination non lue : aucun passage (last_run NULL), aucune trace d'envoi");

        // ---- Le 403 précède la lecture : servi tel quel, même sous lecture refusée, sans ligne ----
        assert_eq!(reponse("dest_403"), (403, json!({ "error": "réservé admin" })), "le 403 d'avant, à l'octet");
        assert_eq!(phase("dest_403"), aucune, "le 403 n'écrit aucune ligne");

        // ---- Absences à l'octet, nominaux en deux cents, aucune ligne ----
        let c = reponses("regle_controles");
        assert_eq!(c[0], (404, json!({ "error": "règle introuvable" })), "règle absente : le 404 d'avant");
        assert_eq!(c[1].0, 200, "règle lue : l'essai suit : {:?}", c[1]);
        assert_eq!(c[1].1["value"].as_f64(), Some(2.0), "les deux événements semés sont comptés : {:?}", c[1]);
        assert_eq!(phase("regle_controles"), aucune);
        let c = reponses("corr_controles");
        assert_eq!(c[0], (404, json!({ "error": "corrélation introuvable" })), "corrélation absente : le 404 d'avant");
        assert_eq!(c[1].0, 200, "corrélation lue : l'essai suit : {:?}", c[1]);
        assert_eq!(c[1].1["ok"], json!(true), "{:?}", c[1]);
        assert_eq!(phase("corr_controles"), aucune);
        let c = reponses("dest_controles");
        assert_eq!(c[0], (404, json!({ "error": "destination introuvable ou désactivée" })), "destination absente : le 404 d'avant");
        assert_eq!(c[1], (404, json!({ "error": "destination introuvable ou désactivée" })), "destination désactivée : le 404 d'avant");
        assert_eq!(c[2].0, 200, "destination lue : l'envoi suit : {:?}", c[2]);
        assert!(c[2].1.get("etat_non_relu").is_none() && c[2].1.get("forwarded").is_some(), "l'état est relu après l'envoi : {:?}", c[2]);
        assert_eq!(phase("dest_controles"), aucune);
        assert_eq!(s["dest_envoye"], json!([1, 1]), "contrôle positif : l'envoi lu passe (last_run posé) et laisse UNE trace");
    }

    /// DEUX TENANTS RÉELS (mode 1) : la lecture d'existence des deux essais se fait sur la base DU TENANT de
    /// l'appelant. La table refusée chez `ak2-alpha` rend le 503 nommé à l'éditeur d'alpha, pendant que l'éditeur de
    /// `ak2-beta` est servi par SA base (trois événements, contre deux chez alpha) ; puis l'inverse. Un identifiant
    /// présent chez l'un seulement rend 404 chez l'autre, à l'octet.
    /// MUTATIONS : `AK2_REGLE`, `AK2_CORR` (le 404 d'avant servi sur la lecture refusée).
    #[tokio::test]
    async fn ak2_deux_tenants_chaque_essai_lit_la_base_de_son_tenant() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        let (st, _dir) = mk_mode1_state();
        let mut bases = Vec::new();
        for (t, n) in [("ak2-alpha", 2), ("ak2-beta", 3)] {
            let (statut, cree) = ak2_reponse(
                tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(au_super("op-ak2")), Json(json!({ "id": t, "name": t })))
                    .await,
            )
            .await;
            assert_eq!(statut, 201, "contrôle : tenant {t} créé : {cree}");
            let h = st.tenants.handle_for(t).expect("contrôle : base du tenant");
            ak2_semer(&h, n, t);
            bases.push((t, h));
        }
        let (alpha, beta) = (bases[0].1.clone(), bases[1].1.clone());
        assert!(!Arc::ptr_eq(&alpha, &beta), "contrôle : deux bases distinctes");
        let ra = ak2_regle(&alpha, "ak2-regle-a");
        let rb = ak2_regle(&beta, "ak2-regle-b");
        ak2_regle(&beta, "ak2-regle-b-seule");
        let seule_b = ak2_entier(&beta, "SELECT id FROM rule WHERE name='ak2-regle-b-seule'");
        let ca = ak2_correlation(&alpha, "ak2-corr-a");
        let cb = ak2_correlation(&beta, "ak2-corr-b");
        let ed_a = ak2_au("ed-a", "editor", "ak2-alpha");
        let ed_b = ak2_au("ed-b", "editor", "ak2-beta");
        let essai_regle = |au: AuthUser, id: i64| {
            let st = st.clone();
            async move { ak2_reponse(rule_test(State(st), Extension(au), Path(id)).await).await }
        };
        let essai_corr = |au: AuthUser, id: i64| {
            let st = st.clone();
            async move { ak2_reponse(correlation_test(State(st), Extension(au), Path(id)).await).await }
        };

        for (refusee, au_refuse, au_servi, r_refuse, r_servi, c_refuse, c_servi, valeur) in [
            (&alpha, &ed_a, &ed_b, ra, rb, ca, cb, 3.0),
            (&beta, &ed_b, &ed_a, rb, ra, cb, ca, 2.0),
        ] {
            ak2_refuser(refusee, "rule");
            ak2_cinq_cents("règle, tenant refusé", &essai_regle(au_refuse.clone(), r_refuse).await, CAUSE_REGLE_NON_ESSAYEE_NON_LUE);
            let (statut, corps) = essai_regle(au_servi.clone(), r_servi).await;
            assert_eq!(statut, 200, "règle, l'autre tenant est servi par SA base : {corps}");
            assert_eq!(corps["value"].as_f64(), Some(valeur), "la valeur est celle de la base du tenant servi : {corps}");
            ak2_lever(refusee);
            ak2_refuser(refusee, "correlation");
            ak2_cinq_cents("corrélation, tenant refusé", &essai_corr(au_refuse.clone(), c_refuse).await, CAUSE_CORRELATION_NON_ESSAYEE_NON_LUE);
            let (statut, corps) = essai_corr(au_servi.clone(), c_servi).await;
            assert_eq!(statut, 200, "corrélation, l'autre tenant est servi : {corps}");
            assert_eq!(corps["ok"], json!(true), "{corps}");
            ak2_lever(refusee);
        }
        // L'identifiant qui n'existe que chez beta : 404 à l'octet chez alpha, servi chez beta.
        assert_eq!(essai_regle(ed_a.clone(), seule_b).await, (404, json!({ "error": "règle introuvable" })), "absent chez alpha");
        assert_eq!(essai_regle(ed_b.clone(), seule_b).await.0, 200, "présent chez beta");
    }

    /// PAR LE ROUTEUR RÉEL, jeton du rôle le plus faible admis (éditeur pour les essais, administrateur pour l'envoi) :
    /// les 503 arrivent au client à l'octet (`{error, id}`) ; l'éditeur qui demande l'envoi manuel est refusé en 403
    /// par la couche RBAC, avant le gestionnaire, lecture refusée ou non.
    /// MUTATIONS : `AK2_REGLE`, `AK2_CORR`, `AK2_DEST`.
    #[tokio::test]
    async fn ak2_les_refus_traversent_le_routeur() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        let (st, _p) = router_test_state("ak2-routeur");
        let db = st.db.clone();
        db.lock()
            .execute("INSERT INTO user(name,hash,role) VALUES('edt-ak2',?1,'editor')", params![hash_pw(AK2_MDP_EDITEUR).unwrap()])
            .expect("fixture : compte éditeur");
        let regle = ak2_regle(&db, "ak2-r-regle");
        let corr = ak2_correlation(&db, "ak2-r-corr");
        let dest = ak2_destination(&db, "ak2-r-dest", 1);
        let addr = router_serve(st).await;
        let editeur = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("edt-ak2:{AK2_MDP_EDITEUR}")));
        let admin = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("root:rootpw1234567"));
        let poster = |chemin: String, authz: String| async move {
            let (code, brut) = router_probe_envoi(addr, "POST", &chemin, Some(&authz), &[("Content-Type", "application/json")], "").await;
            let corps = brut.split_once("\r\n\r\n").map(|(_, c)| c.to_string()).unwrap_or_default();
            // Corps éventuellement servi en `Transfer-Encoding: chunked` : l'objet JSON unique, de sa première accolade
            // à sa dernière (les tailles de tronçon sont hors de lui).
            let objet = match (corps.find('{'), corps.rfind('}')) {
                (Some(a), Some(b)) if a < b => corps[a..=b].to_string(),
                _ => corps.clone(),
            };
            (code, serde_json::from_str::<Value>(&objet).unwrap_or(Value::String(corps)))
        };
        ak2_refuser(&db, "rule");
        ak2_cinq_cents("route de l'essai d'une règle", &poster(format!("/api/rules/{regle}/test"), editeur.clone()).await, CAUSE_REGLE_NON_ESSAYEE_NON_LUE);
        ak2_lever(&db);
        ak2_refuser(&db, "correlation");
        ak2_cinq_cents("route de l'essai d'une corrélation", &poster(format!("/api/correlations/{corr}/test"), editeur.clone()).await, CAUSE_CORRELATION_NON_ESSAYEE_NON_LUE);
        ak2_lever(&db);
        ak2_refuser(&db, "destination");
        // Par le routeur, l'éditeur est refusé AVANT le gestionnaire, par la couche RBAC (corps texte) : la lecture
        // refusée ne change rien à ce refus. Le 403 du gestionnaire lui-même est joué par l'appel direct (sous-processus).
        let (code, corps) = poster(format!("/api/destinations/{dest}/flush"), editeur.clone()).await;
        assert_eq!(code, 403, "éditeur : refusé : {corps}");
        assert!(corps.as_str().is_some_and(|t| t.contains("\r\nréservé à l'administrateur\r\n")), "éditeur : la phrase de la couche RBAC : {corps}");
        ak2_cinq_cents("route de l'envoi manuel", &poster(format!("/api/destinations/{dest}/flush"), admin.clone()).await, CAUSE_ENVOI_MANUEL_NON_FAIT_NON_LU);
        ak2_lever(&db);
        // CONTRÔLES POSITIFS : la table relue, la route sert.
        assert_eq!(poster(format!("/api/rules/{regle}/test"), editeur.clone()).await.0, 200, "règle lue par la route");
        assert_eq!(poster(format!("/api/destinations/{dest}/flush"), admin).await.0, 200, "envoi lu par la route");
    }

    // -------------------------------------------------------------------------------------
    // `run_playbooks` et `playbook_test`
    // -------------------------------------------------------------------------------------

    /// Une base, un playbook armé (`window_s`, `interval_s` tels quels, l'état que laisse la dérogation du
    /// démarrage) et UN événement de la cible vieux de `age_s` secondes ; mode `observe`.
    fn ak2_base_pb(tag: &str, interval_s: i64, window_s: i64, age_s: i64) -> (AppState, crate::tmp_possede::TmpDb, i64) {
        let (st, tmp) = sp_state(&format!("ak2-pb-{tag}"));
        {
            let conn = st.db.lock();
            conn.execute("DELETE FROM action", []).unwrap();
            conn.execute("DELETE FROM playbook", []).unwrap();
            conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('plume_mode','observe')", []).unwrap();
            conn.execute(
                "INSERT INTO playbook(name,enabled,query,is_soql,action_kind,interval_s,window_s,managed,last_run,created_by_role) \
                 VALUES('ak2-pb',1,?1,0,'ban_ip',?2,?3,0,NULL,'admin')",
                params![AK2_REQUETE_PB, interval_s, window_s],
            ).unwrap();
            conn.execute(
                "INSERT INTO event(ts,source,category,severity,src_ip,message,dedup) VALUES(?1,'ak2-pb','auth',1,?2,'échec',?3)",
                params![crate::now() - age_s, AK2_CIBLE, format!("ak2-pb-{tag}")],
            ).unwrap();
        }
        let id = ak2_entier(&st.db, "SELECT id FROM playbook WHERE name='ak2-pb'");
        (st, tmp, id)
    }

    /// L'essai, puis le passage réel, sur la même base : (cibles de l'essai, ripostes posées par le passage).
    async fn ak2_essai_puis_passage(st: &AppState, id: i64) -> (Vec<String>, i64) {
        let (statut, corps) = ak2_reponse(playbook_test(State(st.clone()), Extension(sp_au("adm", "admin")), Path(id)).await).await;
        assert_eq!(statut, 200, "l'essai répond : {corps}");
        let cibles: Vec<String> = serde_json::from_value(corps["targets"].clone()).unwrap_or_else(|e| panic!("cibles ({e}) : {corps}"));
        crate::ledger::declarer_la_liste_pour_ce_temoin(); // `P4.7-e` : ce témoin peut poser une riposte de ban
        assert_eq!(run_playbooks(&st.db, st.db_path.as_str()), Mesure::Lue(0), "le passage n'abandonne rien");
        let ripostes = ak2_entier(&st.db, &format!("SELECT COUNT(*) FROM action WHERE target='{AK2_CIBLE}'"));
        (cibles, ripostes)
    }

    /// `P10.31-k` — CE QU'IL TIENT, par le point d'entrée de la route (`playbook_test`) contre celui de l'ordonnanceur
    /// (`run_playbooks`) : sous le plancher (fenêtre 5 s, intervalle 300 s, l'état d'une dérogation du démarrage),
    /// l'événement de 100 s est montré par l'essai ET vu par le passage ; un événement de 400 s n'est ni montré ni vu ;
    /// au-dessus du plancher (3 600 s) l'essai et le passage voient le même événement de 3 000 s et ignorent celui de
    /// 4 000 s ; une fenêtre 0 reste sans borne pour les deux (événement de 100 000 s).
    /// MUTATION QUI LE FAIT ROUGIR : `AK2_PB_FENETRE_BRUTE` (l'essai compile avec `window_s` brut : cibles vides sur
    /// l'événement de 100 s que le passage voit).
    #[tokio::test]
    async fn ak2_l_essai_d_un_playbook_voit_ce_que_le_passage_voit() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // les gestionnaires lisent l'environnement
        let cible = vec![AK2_CIBLE.to_string()];
        let cas: [(&str, i64, i64, i64, bool); 5] = [
            ("sous-plancher-vu", 300, 5, 100, true),
            ("sous-plancher-hors", 300, 5, 400, false),
            ("au-dessus-vu", 300, 3600, 3000, true),
            ("au-dessus-hors", 300, 3600, 4000, false),
            ("sans-borne", 300, 0, 100_000, true),
        ];
        for (tag, interval_s, window_s, age_s, vu) in cas {
            let (st, _tmp, id) = ak2_base_pb(tag, interval_s, window_s, age_s);
            let (cibles, ripostes) = ak2_essai_puis_passage(&st, id).await;
            let attendu: Vec<String> = if vu { cible.clone() } else { Vec::new() };
            assert_eq!(cibles, attendu, "{tag} : l'essai montre ce que le passage verra");
            assert_eq!(ripostes, i64::from(vu), "{tag} : le passage pose la riposte de la cible vue, et seulement elle");
        }
    }

    /// `P10.20-l` — CE QU'IL TIENT, sur `run_playbooks` (point d'entrée de l'ordonnanceur) : un mode NON LU (valeur
    /// BLOB : forme inconnue ; table `meta` refusée : source illisible) rend un tick AVEUGLE au bilan ENTIER (cause et
    /// détail par égalité), aucune riposte, le marqueur de passage non posé (le playbook reste dû) ; une ligne de mode
    /// ABSENTE est « observe » établi : `Lue(0)`, une riposte proposée (pending, dry_run) ; le mode `observe` lu, de
    /// même (contrôle).
    /// MUTATIONS QUI LE FONT ROUGIR : `AK2_PB_MODE` (repli « observe » d'avant : `Lue(0)` et une riposte),
    /// `AK2_PB_MODE_ABSENT` (ligne absente servie aveugle), `AK2_PB_TICK_AVEUGLE` (détail « liste des éléments dus
    /// illisible »).
    #[test]
    fn ak2_le_mode_des_playbooks_a_trois_issues() {
        let _env = crate::tests::VERROU_ENV_PROCESSUS.read(); // `run_playbooks` lit l'environnement
        let etat = |st: &AppState| -> (i64, i64) {
            (
                ak2_entier(&st.db, &format!("SELECT COUNT(*) FROM action WHERE target='{AK2_CIBLE}'")),
                ak2_entier(&st.db, "SELECT COUNT(*) FROM playbook WHERE name='ak2-pb' AND last_run IS NOT NULL"),
            )
        };

        // Valeur BLOB : forme inconnue.
        let (st, _t1, _) = ak2_base_pb("mode-blob", 300, 3600, 100);
        ak2_sql(&st.db, "UPDATE meta SET value=x'FF' WHERE key='plume_mode';");
        let e = st.db.lock().query_row("SELECT value FROM meta WHERE key='plume_mode'", [], |r| r.get::<_, String>(0)).expect_err("fixture : BLOB");
        crate::ledger::declarer_la_liste_pour_ce_temoin();
        assert_eq!(
            run_playbooks(&st.db, st.db_path.as_str()),
            Mesure::Illisible { cause: CAUSE_FORME_INCONNUE, detail: format!("{DETAIL_DU_TICK_DE_PLAYBOOKS_MODE_NON_LU} ({e})") },
            "mode en BLOB : tick aveugle, jamais `Lue(0)`"
        );
        assert_eq!(etat(&st), (0, 0), "mode en BLOB : aucune riposte, marqueur non posé (le playbook reste dû)");

        // Table `meta` refusée : source illisible.
        let (st, _t2, _) = ak2_base_pb("mode-refuse", 300, 3600, 100);
        ak2_refuser(&st.db, "meta");
        let e = ak2_cause(&st.db, "SELECT value FROM meta WHERE key='plume_mode'");
        crate::ledger::declarer_la_liste_pour_ce_temoin();
        let bilan = run_playbooks(&st.db, st.db_path.as_str());
        ak2_lever(&st.db);
        assert_eq!(
            bilan,
            Mesure::Illisible { cause: CAUSE_SOURCE_ILLISIBLE, detail: format!("{DETAIL_DU_TICK_DE_PLAYBOOKS_MODE_NON_LU} ({e})") },
            "mode refusé : tick aveugle"
        );
        assert_eq!(etat(&st), (0, 0), "mode refusé : aucune riposte, marqueur non posé");

        // Ligne absente : « observe » ÉTABLI.
        let (st, _t3, _) = ak2_base_pb("mode-absent", 300, 3600, 100);
        ak2_sql(&st.db, "DELETE FROM meta WHERE key='plume_mode';");
        crate::ledger::declarer_la_liste_pour_ce_temoin();
        assert_eq!(run_playbooks(&st.db, st.db_path.as_str()), Mesure::Lue(0), "mode absent : observe établi, tick lu");
        assert_eq!(etat(&st), (1, 1), "mode absent : une riposte proposée, marqueur posé");
        let (statut, dry): (String, i64) = st.db.lock()
            .query_row("SELECT status, dry_run FROM action WHERE target=?1", params![AK2_CIBLE], |r| Ok((r.get(0)?, r.get(1)?)))
            .expect("riposte lue");
        assert_eq!((statut.as_str(), dry), ("pending", 1), "observe : proposée, à blanc");

        // Contrôle : `observe` lu.
        let (st, _t4, _) = ak2_base_pb("mode-observe", 300, 3600, 100);
        crate::ledger::declarer_la_liste_pour_ce_temoin();
        assert_eq!(run_playbooks(&st.db, st.db_path.as_str()), Mesure::Lue(0), "observe lu : tick lu");
        assert_eq!(etat(&st), (1, 1), "observe lu : une riposte proposée");
    }
}
