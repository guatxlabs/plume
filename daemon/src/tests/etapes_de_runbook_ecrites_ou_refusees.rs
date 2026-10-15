// =====================================================================================
// `P10.20-w` (étapes de runbook) — LES ÉTAPES D'UN RUNBOOK SONT ÉCRITES, OU LE GESTE EST REFUSÉ.
//
// Trois écritures étaient avalées (`let _ =`) dans `incidents.rs` : l'INSERT de chaque étape (`insert_steps`, appelé
// par `create_custom_runbook` et `update_custom_runbook`), le retrait des étapes d'avant (`update_custom_runbook`) et
// la copie des étapes (`clone_runbook`). Un refus de statement ne fait pas avorter une transaction SQLite : le garde
// du geste validait un runbook amputé (ou vide, après un retrait réussi suivi d'INSERT refusés), un clone sans étapes
// rendu avec un identifiant, et la trace `config.runbook.*` affirmait le nombre d'étapes DEMANDÉ.
//
// LE GESTE QUI FAIT RATER UNE ÉCRITURE : un trigger posé sur l'écrivain partagé. `RAISE(ABORT)` refuse le statement
// (une étape d'ordinal 1, ou tout retrait d'étapes) ; `RAISE(IGNORE)` le fait réussir SANS écrire la ligne (`Ok(0)`,
// et une copie qui écrit moins de lignes que la source n'en compte). Chaque témoin passe par les handlers réels
// (garde du geste, ROLLBACK au Drop) et relit la base après coup : état d'avant intact, aucune ligne de registre
// `config.runbook.*`, 503 nommé (`CAUSE_ETAPES_DE_RUNBOOK_NON_ECRITES` en tête), jamais le 400 d'une saisie.
// Contre-épreuves nominales : la modification et le clonage écrivent les étapes et la trace d'avant, octet pour
// octet ; le clone d'une source sans étapes est rendu (zéro copiée sur zéro comptée est un fait).
//
// LES MUTATIONS QUI LES FONT ROUGIR (variable de mutation sous `cfg!(test)`, retirées avant le commit) : `t7_insert` (l'INSERT
// d'étape de nouveau avalé), `t7_ok0` (une étape à zéro ligne comptée écrite), `t7_delete` (le retrait avalé),
// `t7_clone` (la copie avalée), `t7_cmp` (la comparaison copiées/comptées retirée), `t7_statut` (400 au lieu de 503).
//
// CORRECTION (vérification 1) : chaque témoin asserte aussi la CAUSE DU MOTEUR portée par le refus (le message du
// trigger) et le site qui l'a rendue (« étapes d'avant non retirées », « étapes non copiées », « étapes de la source
// non comptées ») ; mutations `t7_cause_insert`, `t7_cause_delete`, `t7_cause_copie` (cause retirée du message),
// `t7_copie_avalee` (erreur de la copie lue comme zéro copiée — la comparaison rendrait le même préfixe),
// `t7_compte_avale` (lecture du compte de la source ratée lue comme zéro).
//
// CE QU'ILS NE TIENNENT PAS : `case_add_item` (posé APRÈS le commit d'`attach_runbook`, il avale encore son écriture ;
// `attach_runbook` compte déjà chaque INSERT `case_step` en transaction depuis `P10.21-t`) ; un refus de la base sur
// la ligne `runbook` elle-même ou une lecture ratée de `managed` (encore un 400) ; la face
// console (aucun module de `web/` ne lit encore cette cause) ; un refus réel (disque plein, base en lecture seule)
// plutôt que fabriqué par trigger — le déclenchement en exploitation n'est pas observé.
// =====================================================================================
mod etapes_de_runbook_ecrites_ou_refusees {
    use super::*;

    const ETR_REGISTRE: &str = "SELECT COUNT(*) FROM ledger WHERE kind LIKE 'config.runbook.%'";
    const ETR_CUSTOMS: &str = "SELECT COUNT(*) FROM runbook WHERE managed=0";

    async fn etr_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        let corps = serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned()));
        (statut, corps)
    }

    fn etr_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn etr_erreur(corps: &Value) -> String {
        corps["error"].as_str().unwrap_or_default().to_string()
    }

    fn etr_pas(titres: &[&str]) -> Vec<NewStep> {
        titres.iter().map(|t| ("triage".to_string(), t.to_string(), String::new(), "manual".to_string(), None, None)).collect()
    }

    fn etr_corps_rb(nom: &str, titres: &[&str]) -> Value {
        let steps: Vec<Value> = titres.iter().map(|t| json!({ "phase": "triage", "title": t, "step_kind": "manual" })).collect();
        json!({ "name": nom, "match_kind": "*", "steps": steps })
    }

    /// Les titres des étapes d'un runbook, dans l'ordre.
    fn etr_titres(st: &AppState, rb_id: i64) -> Vec<String> {
        let c = st.db.lock();
        let mut q = c.prepare("SELECT title FROM runbook_step WHERE runbook_id=?1 ORDER BY ordinal,id").expect("fixture : prepare");
        q.query_map(params![rb_id], |r| r.get(0)).expect("fixture : lecture").collect::<Result<Vec<String>, _>>().expect("fixture : lignes")
    }

    /// Un runbook custom écrit par le cœur réel, hors trigger ; rend son id.
    fn etr_runbook(st: &AppState, nom: &str, titres: &[&str]) -> i64 {
        let c = st.db.lock();
        create_custom_runbook(&c, nom, "*", "", "", &etr_pas(titres), true).expect("fixture : runbook écrit")
    }

    /// Pose un trigger sur `runbook_step` ; `corps` est l'action (`RAISE(ABORT, …)` ou `RAISE(IGNORE)`).
    fn etr_trigger(st: &AppState, evenement: &str, quand: &str, corps: &str) {
        st.db.lock().execute_batch(&format!(
            "CREATE TRIGGER etr_refus BEFORE {evenement} ON runbook_step {quand} BEGIN SELECT {corps}; END;"
        )).expect("fixture : trigger posé");
    }

    fn etr_lever(st: &AppState) {
        st.db.lock().execute_batch("DROP TRIGGER IF EXISTS etr_refus;").expect("fixture : trigger levé");
    }

    fn etr_refus_nomme(statut: u16, corps: &Value) {
        assert_eq!(statut, 503, "étape non écrite : 503, jamais un succès ni le 400 d'une saisie : {corps}");
        assert!(etr_erreur(corps).starts_with(CAUSE_ETAPES_DE_RUNBOOK_NON_ECRITES), "cause nommée en tête : {corps}");
    }

    /// CE QU'IL TIENT : création, deuxième étape refusée -> 503 nommé, aucun runbook écrit, aucune étape, rien tracé.
    /// MUTATIONS : `t7_insert`, `t7_statut`.
    #[tokio::test]
    async fn etr_creation_etape_refusee_n_ecrit_rien() {
        let (st, _p) = sp_state("etr-creation-abort");
        let adm = sp_au("adm", "admin");
        let (customs, registre) = (etr_compte(&st, ETR_CUSTOMS), etr_compte(&st, ETR_REGISTRE));
        etr_trigger(&st, "INSERT", "WHEN NEW.ordinal=1", "RAISE(ABORT, 'etape refusee')");
        let r = runbook_create(State(st.clone()), Extension(adm), Json(etr_corps_rb("etr-cree", &["un", "deux", "trois"]))).await;
        etr_lever(&st);
        let (statut, corps) = etr_corps(r).await;
        etr_refus_nomme(statut, &corps);
        assert!(etr_erreur(&corps).contains("étape 2 (ordinal 1)"), "l'étape refusée est nommée : {corps}");
        assert!(etr_erreur(&corps).contains("etape refusee"), "la cause du moteur est portée : {corps}");
        assert_eq!(etr_compte(&st, ETR_CUSTOMS), customs, "aucun runbook écrit");
        assert_eq!(etr_compte(&st, "SELECT COUNT(*) FROM runbook WHERE name='etr-cree'"), 0, "le runbook n'existe pas");
        assert_eq!(etr_compte(&st, ETR_REGISTRE), registre, "rien tracé");
    }

    /// CE QU'IL TIENT : une étape « réussie » à ZÉRO ligne n'est pas une étape écrite, et le refus la nomme avec son
    /// compte. MUTATIONS : `t7_ok0`, `t7_okn_msg` (le bras `Ok(n)` rend la cause nue, sans l'étape).
    #[tokio::test]
    async fn etr_creation_etape_a_zero_ligne_refuse() {
        let (st, _p) = sp_state("etr-creation-ignore");
        let adm = sp_au("adm", "admin");
        let registre = etr_compte(&st, ETR_REGISTRE);
        etr_trigger(&st, "INSERT", "WHEN NEW.ordinal=1", "RAISE(IGNORE)");
        let r = runbook_create(State(st.clone()), Extension(adm), Json(etr_corps_rb("etr-zero", &["un", "deux"]))).await;
        etr_lever(&st);
        let (statut, corps) = etr_corps(r).await;
        etr_refus_nomme(statut, &corps);
        assert!(etr_erreur(&corps).contains("étape 2 (ordinal 1) non écrite : 0 ligne écrite"), "l'étape sans effet est nommée avec son compte : {corps}");
        assert_eq!(etr_compte(&st, "SELECT COUNT(*) FROM runbook WHERE name='etr-zero'"), 0, "le runbook n'existe pas");
        assert_eq!(etr_compte(&st, ETR_REGISTRE), registre, "rien tracé");
    }

    /// CE QU'IL TIENT : modification, deuxième étape refusée -> 503 nommé, le runbook garde son nom et ses étapes
    /// d'avant, rien tracé. MUTATIONS : `t7_insert`, `t7_statut`.
    #[tokio::test]
    async fn etr_modification_etape_refusee_garde_les_etapes_d_avant() {
        let (st, _p) = sp_state("etr-maj-abort");
        let adm = sp_au("adm", "admin");
        let id = etr_runbook(&st, "etr-avant", &["a", "b"]);
        let registre = etr_compte(&st, ETR_REGISTRE);
        etr_trigger(&st, "INSERT", "WHEN NEW.ordinal=1", "RAISE(ABORT, 'etape refusee')");
        let r = runbook_update_handler(State(st.clone()), Extension(adm), Path(id), Json(etr_corps_rb("etr-apres", &["x", "y", "z"]))).await;
        etr_lever(&st);
        let (statut, corps) = etr_corps(r).await;
        etr_refus_nomme(statut, &corps);
        assert!(etr_erreur(&corps).contains("étape 2 (ordinal 1) non écrite : ") && etr_erreur(&corps).contains("etape refusee"),
            "l'étape et la cause du moteur sont portées : {corps}");
        assert_eq!(etr_titres(&st, id), vec!["a", "b"], "les étapes d'avant sont intactes");
        assert_eq!(etr_compte(&st, &format!("SELECT COUNT(*) FROM runbook WHERE id={id} AND name='etr-avant'")), 1, "nom d'avant");
        assert_eq!(etr_compte(&st, ETR_REGISTRE), registre, "rien tracé");
    }

    /// CE QU'IL TIENT : modification, retrait des étapes d'avant refusé -> 503 nommé, étapes d'avant intactes (la forme
    /// d'avant ajoutait les nouvelles aux anciennes), rien tracé. MUTATION : `t7_delete`.
    #[tokio::test]
    async fn etr_modification_retrait_refuse_garde_les_etapes_d_avant() {
        let (st, _p) = sp_state("etr-maj-delete");
        let adm = sp_au("adm", "admin");
        let id = etr_runbook(&st, "etr-avant", &["a", "b"]);
        let registre = etr_compte(&st, ETR_REGISTRE);
        etr_trigger(&st, "DELETE", "", "RAISE(ABORT, 'retrait refuse')");
        let r = runbook_update_handler(State(st.clone()), Extension(adm), Path(id), Json(etr_corps_rb("etr-apres", &["x", "y", "z"]))).await;
        etr_lever(&st);
        let (statut, corps) = etr_corps(r).await;
        etr_refus_nomme(statut, &corps);
        assert!(etr_erreur(&corps).contains("étapes d'avant non retirées : ") && etr_erreur(&corps).contains("retrait refuse"),
            "le retrait et la cause du moteur sont portés : {corps}");
        assert_eq!(etr_titres(&st, id), vec!["a", "b"], "les étapes d'avant sont intactes, rien d'ajouté");
        assert_eq!(etr_compte(&st, ETR_REGISTRE), registre, "rien tracé");
    }

    /// CE QU'IL TIENT : clonage, copie refusée -> 503 nommé, aucune copie écrite, rien tracé. MUTATIONS : `t7_clone`,
    /// `t7_statut`.
    #[tokio::test]
    async fn etr_clonage_copie_refusee_n_ecrit_pas_de_clone() {
        let (st, _p) = sp_state("etr-clone-abort");
        let adm = sp_au("adm", "admin");
        let source = etr_runbook(&st, "etr-source", &["a", "b", "c"]);
        let (customs, registre) = (etr_compte(&st, ETR_CUSTOMS), etr_compte(&st, ETR_REGISTRE));
        etr_trigger(&st, "INSERT", "WHEN NEW.ordinal=1", "RAISE(ABORT, 'copie refusee')");
        let r = runbook_clone_handler(State(st.clone()), Extension(adm), Path(source), Json(json!({ "name": "etr-copie" }))).await;
        etr_lever(&st);
        let (statut, corps) = etr_corps(r).await;
        etr_refus_nomme(statut, &corps);
        // Le bras Err de la copie, pas la comparaison : une erreur avalée en « 0 copiée » rendrait le même 503 et le
        // même préfixe (« étapes copiées : 0 sur 3 »), sans la cause du moteur.
        assert!(etr_erreur(&corps).contains("étapes non copiées : ") && etr_erreur(&corps).contains("copie refusee"),
            "la copie refusée et la cause du moteur sont portées : {corps}");
        assert!(!etr_erreur(&corps).contains("sur 3"), "pas le message de la comparaison : {corps}");
        assert_eq!(etr_compte(&st, ETR_CUSTOMS), customs, "aucune copie écrite");
        assert_eq!(etr_compte(&st, ETR_REGISTRE), registre, "rien tracé");
        // Garde-fou de fixture, vrai par construction (le clonage n'écrit jamais la source).
        assert_eq!(etr_titres(&st, source), vec!["a", "b", "c"], "la source est intacte");
    }

    /// CE QU'IL TIENT : clonage, copie AMPUTÉE (une ligne ignorée : le statement réussit) -> 503 nommé, aucune copie.
    /// MUTATIONS : `t7_cmp`, `t7_clone`.
    #[tokio::test]
    async fn etr_clonage_copie_amputee_refuse() {
        let (st, _p) = sp_state("etr-clone-ignore");
        let adm = sp_au("adm", "admin");
        let source = etr_runbook(&st, "etr-source", &["a", "b", "c"]);
        let (customs, registre) = (etr_compte(&st, ETR_CUSTOMS), etr_compte(&st, ETR_REGISTRE));
        etr_trigger(&st, "INSERT", "WHEN NEW.ordinal=1", "RAISE(IGNORE)");
        let r = runbook_clone_handler(State(st.clone()), Extension(adm), Path(source), Json(json!({ "name": "etr-copie" }))).await;
        etr_lever(&st);
        let (statut, corps) = etr_corps(r).await;
        etr_refus_nomme(statut, &corps);
        assert!(etr_erreur(&corps).contains("2 sur 3"), "le compte copié/compté est dit : {corps}");
        assert_eq!(etr_compte(&st, ETR_CUSTOMS), customs, "aucune copie écrite");
        assert_eq!(etr_compte(&st, ETR_REGISTRE), registre, "rien tracé");
    }

    /// CE QU'IL TIENT : clonage, lecture du COMPTE des étapes de la source refusée (un trigger ne peut pas faire rater
    /// un SELECT : l'autoriseur SQLite refuse la lecture de `runbook_step`, qui pour un `COUNT(*)` se demande avec une
    /// colonne vide) -> 503 nommé avec la vraie cause (« non comptées »), jamais « N copiées sur 0 », aucune copie,
    /// rien tracé. MUTATION : `t7_compte_avale`.
    #[tokio::test]
    async fn etr_clonage_compte_de_la_source_illisible_refuse() {
        use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
        let (st, _p) = sp_state("etr-clone-compte");
        let adm = sp_au("adm", "admin");
        let source = etr_runbook(&st, "etr-source", &["a", "b", "c"]);
        let (customs, registre) = (etr_compte(&st, ETR_CUSTOMS), etr_compte(&st, ETR_REGISTRE));
        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Read { table_name, .. } if table_name == "runbook_step" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let r = runbook_clone_handler(State(st.clone()), Extension(adm), Path(source), Json(json!({ "name": "etr-copie" }))).await;
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        let (statut, corps) = etr_corps(r).await;
        etr_refus_nomme(statut, &corps);
        assert!(etr_erreur(&corps).contains("étapes de la source non comptées : ") && etr_erreur(&corps).contains("is prohibited"),
            "la lecture refusée et la cause du moteur sont portées : {corps}");
        assert!(!etr_erreur(&corps).contains("sur 0"), "pas « N copiées sur 0 » : {corps}");
        assert_eq!(etr_compte(&st, ETR_CUSTOMS), customs, "aucune copie écrite");
        assert_eq!(etr_compte(&st, ETR_REGISTRE), registre, "rien tracé");
    }

    /// CONTRE-ÉPREUVE : sans trigger, la modification écrit les nouvelles étapes et la trace d'avant octet pour
    /// octet ; le clone copie toutes les étapes ; le clone d'une source SANS étapes est rendu (0 sur 0).
    #[tokio::test]
    async fn etr_nominal_etapes_et_trace_inchangees() {
        let (st, _p) = sp_state("etr-nominal");
        let adm = sp_au("adm", "admin");
        let id = etr_runbook(&st, "etr-avant", &["a", "b"]);
        let r = runbook_update_handler(State(st.clone()), Extension(adm.clone()), Path(id), Json(etr_corps_rb("etr-apres", &["x", "y", "z"]))).await;
        let (statut, corps) = etr_corps(r).await;
        assert_eq!(statut, 200, "modification nominale : {corps}");
        assert_eq!(corps, json!({ "ok": true }));
        assert_eq!(etr_titres(&st, id), vec!["x", "y", "z"], "étapes remplacées");
        let detail: String = st.db.lock().query_row("SELECT detail FROM ledger WHERE kind='config.runbook.update' ORDER BY id DESC LIMIT 1", [], |r| r.get(0))
            .expect("trace de modification");
        assert_eq!(detail, format!("runbook custom 'etr-apres' (#{id}, 3 étapes) mis à jour par adm"), "trace d'avant, octet pour octet");

        let r = runbook_clone_handler(State(st.clone()), Extension(adm.clone()), Path(id), Json(json!({ "name": "etr-copie" }))).await;
        let (statut, corps) = etr_corps(r).await;
        assert_eq!(statut, 200, "clonage nominal : {corps}");
        let cid = corps["id"].as_i64().expect("id du clone");
        assert_eq!(etr_titres(&st, cid), vec!["x", "y", "z"], "toutes les étapes copiées");

        let vide = etr_runbook(&st, "etr-vide", &[]);
        let r = runbook_clone_handler(State(st.clone()), Extension(adm), Path(vide), Json(json!({ "name": "etr-copie-vide" }))).await;
        let (statut, corps) = etr_corps(r).await;
        assert_eq!(statut, 200, "source vide : zéro copiée sur zéro comptée est un fait : {corps}");
        let cvide = corps["id"].as_i64().expect("id du clone vide");
        assert!(etr_titres(&st, cvide).is_empty(), "clone vide");
    }
}
