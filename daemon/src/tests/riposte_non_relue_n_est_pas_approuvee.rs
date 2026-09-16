// =====================================================================================
// `P10.20-q` — UNE RIPOSTE QU'ON N'A PAS PU RELIRE N'EST PAS APPROUVÉE, ET LE REGISTRE NE L'ATTESTE
// PAS.
//
// LE DÉFAUT, MESURÉ LE 2026-09-16 AVANT TOUT CORRECTIF. `action_approve` écrivait le statut
// `approved`, posait la ligne de registre `action.approved`, PUIS relisait `(kind, target, dry_run)`
// par `if let Ok(..) = query_row(` — la forme SANS branche d'échec, muette par construction. Sur une
// lecture ratée, le `if let` ne prenait pas, le miroir `net_ban` n'était pas armé, et la route
// rendait 204 : l'analyste lisait « approuvée » sur une riposte que rien n'avait armée.
//
// CE QUE L'ÉNONCÉ DE LA CLÉ AVAIT DE FAUX, ET L'ERREUR VA DANS LE MAUVAIS SENS. La clé écrit que
// « le registre ne reçoit aucune ligne ». Il en reçoit une : `action.approved id=N`, posée DEUX
// LIGNES AVANT la lecture, donc toujours. Ce qu'il ne reçoit pas, c'est la seule ligne qui aurait dit
// que l'armement n'a pas eu lieu. La trace non purgeable ATTESTE donc l'approbation d'une riposte
// inerte — ce n'est pas un silence qu'on pourrait interroger après coup, c'est une affirmation qui
// recouvre. C'est ce que le premier témoin d'ici JOUE, dans les deux sens.
//
// LA SECONDE ÉCRITURE AVALÉE AU MÊME ENDROIT, elle, n'était nommée nulle part : `let _ =
// conn.execute("UPDATE action SET status='approved' …")`. Table `action` hors d'atteinte et table
// `ledger` intacte, le statut ne change pas et la ligne de registre l'affirme quand même. Le témoin
// de la VUE TEMPORAIRE la joue : une vue ne se modifie pas, la lecture, elle, réussit — c'est la
// seule voie qui sépare l'échec d'ÉCRITURE de l'échec de LECTURE.
//
// LA FORME DU CORRECTIF EST CELLE DU DÉPÔT (`P10.20-k`, `P10.20-p`) : la riposte se relit AVANT toute
// écriture, en un seul énoncé rendu en `Result<Option<..>>` (`optional()`) — `Ok(None)` est une
// absence ÉTABLIE (404 nommé), `Err(..)` est une lecture NON FAITE et refuse par un 503 nommé
// (`CAUSE_RIPOSTE_NON_LUE`). L'échec de l'écriture du statut refuse de la même façon
// (`CAUSE_APPROBATION_NON_ENREGISTREE`), AVANT la ligne de registre.
//
// ET LE VERDICT CONSERVÉ DU RESPONDER, rang DEUX de la garde de forme
// (`check_a_single_row_read_that_failed_is_never_served_as_a_fact.py`) : `unwrap_or_default()`
// rendait `""`, et le registre portait « verdict `` déjà posé, conservé » aussi bien pour une ligne
// DISPARUE que pour une ligne NON LUE. `verdict_conserve_relu` distingue les trois issues et l'échec
// porte son propre `kind` (`action.exec.verdict-non-relu`), donc il se filtre.
//
// LES DEUX VOIES D'ILLISIBILITÉ, ET POURQUOI DEUX. La TABLE RETIRÉE (renommée sous les pieds du
// gestionnaire) fait échouer la PRÉPARATION ; la LIGNE ILLISIBLE (un `BLOB` posé dans `target`, que
// SQLite conserve tel quel quelle que soit l'affinité de la colonne) fait échouer le MAPPEUR, la
// requête restant saine — c'est la voie la plus proche des causes de terrain (cache de schéma de pool
// périmé, colonne migrée, valeur corrompue), et aucune garde de forme ne la verrait. Chaque témoin
// porte son CONTRÔLE POSITIF dans le même corps : sans lui, un refus INCONDITIONNEL passerait pour un
// refus fondé.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : aucun module de `web/` ne lit le 503 ni le 404 neufs
// (`web/detection_admin.js` appelle `apiSend` et recharge la liste) ; `respond_run` n'est joué qu'au
// niveau de sa relecture typée, jamais de bout en bout (il ouvre une base par chemin et lance des
// processus) ; approuver une riposte DÉJÀ TRANCHÉE reste un 204 muet qui pose quand même
// `action.approved`, comme avant ce lot ; et `action_create`, dans le même fichier, garde un INSERT
// avalé suivi d'un `action.queued` inconditionnel — mesuré, hors de cette clé.
// =====================================================================================
mod riposte_non_relue_n_est_pas_approuvee {
    use super::*;

    /// Pose une variable d'environnement LE TEMPS D'UNE PORTÉE et restaure l'état antérieur au `Drop`,
    /// y compris quand la portée se termine par un panic d'assertion. À construire sous
    /// `VERROU_ENV_PROCESSUS.write()` — l'environnement du processus est UNE ressource.
    struct VariablePoseeLeTempsDuTemoin {
        cle: &'static str,
        avant: Option<String>,
    }

    impl VariablePoseeLeTempsDuTemoin {
        fn neuve(cle: &'static str, valeur: &str) -> Self {
            let avant = std::env::var(cle).ok();
            std::env::set_var(cle, valeur);
            Self { cle, avant }
        }
    }

    impl Drop for VariablePoseeLeTempsDuTemoin {
        fn drop(&mut self) {
            match self.avant.take() {
                Some(v) => std::env::set_var(self.cle, v),
                None => std::env::remove_var(self.cle),
            }
        }
    }

    /// Une base plume COMPLÈTE, sur fichier (le renommage de table et la vue temporaire ont besoin
    /// d'une vraie connexion d'écriture, celle que le gestionnaire prend par `req_conn!`).
    fn rna_etat(tag: &str) -> (AppState, crate::tmp_possede::TmpDb) {
        let chemin = crate::tmp_possede::TmpDb::neuf(&format!("rna-{tag}"));
        {
            let conn = open_db(&chemin).unwrap();
            conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
            assert!(migrate(&conn), "fixture `P10.20-q` : la chaîne de migrations doit aller au bout");
            conn.execute("DELETE FROM action", []).unwrap();
        }
        let st = ds_file_state(&chemin);
        (st, chemin)
    }

    fn rna_au() -> AuthUser {
        AuthUser {
            name: "analyste".into(), role: "admin".into(), tenant: "default".into(), is_superadmin: false,
            method: "basic".into(), csrf: String::new(), env: None,
        }
    }

    fn rna_ecrire(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    /// Une riposte EN ATTENTE, telle qu'un analyste la trouve dans sa file.
    fn rna_riposte_en_attente(st: &AppState, kind: &str, target: &str, dry: i64) -> i64 {
        let conn = st.db.lock();
        conn.execute(
            "INSERT INTO action(ts,kind,target,status,dry_run,host) VALUES(1000,?1,?2,'pending',?3,'')",
            params![kind, target, dry],
        )
        .expect("fixture : la riposte s'insère");
        conn.last_insert_rowid()
    }

    fn rna_compte(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).expect("fixture : le compte se lit")
    }

    fn rna_lignes_de_registre(st: &AppState) -> i64 {
        rna_compte(st, "SELECT COUNT(*) FROM ledger")
    }

    fn rna_bans_armes(st: &AppState) -> i64 {
        rna_compte(st, "SELECT COUNT(*) FROM net_ban")
    }

    fn rna_statut(st: &AppState, id: i64) -> String {
        st.db
            .lock()
            .query_row("SELECT COALESCE(status,'') FROM action WHERE id=?1", params![id], |r| r.get(0))
            .expect("fixture : le statut se lit")
    }

    async fn rna_approuver(st: &AppState, id: i64) -> (u16, Value) {
        pb_json(action_approve(State(st.clone()), Extension(rna_au()), Path(id)).await).await
    }

    /// La phrase servie par le refus (`err_json` la pose sous `error`).
    fn rna_phrase(v: &Value) -> String {
        v.get("error").and_then(|e| e.as_str()).unwrap_or("").to_string()
    }

    // -------------------------------------------------------------------------------------
    // (1) LA LIGNE ILLISIBLE — le miroir `net_ban` armé, puis la même riposte non relue.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : avec l'auto-armement activé, l'approbation d'une riposte `ban_ip` réelle ARME
    /// le ban natif et pose sa ligne de registre (contrôle positif compté sur les trois quantités) ;
    /// sur une riposte dont `target` porte un BLOB, `action_approve` REFUSE par un 503 nommé — la
    /// riposte reste `pending`, le registre ne reçoit RIEN, et aucun ban n'est armé.
    ///
    /// CE QU'IL NE TIENT PAS : il ne juge pas ce que la console peint de ce 503, et il n'éprouve pas
    /// le chemin où l'armement échoue pour une autre raison (store live plein), qui a sa propre ligne.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : remettre l'ancienne forme — `let _ = conn.execute(UPDATE …)`
    /// puis `ledger_append("action.approved")` puis `if let Ok((kind, target, dry)) = conn.query_row(
    /// "SELECT kind, target, dry_run FROM action WHERE id=?1 AND status='approved'" …)`. La route
    /// redevient 204, la riposte passe à `approved`, le registre gagne sa ligne, et aucun ban n'est
    /// armé : les quatre dernières assertions tombent.
    #[tokio::test]
    async fn p10_20q_une_riposte_ban_ip_dont_la_ligne_est_illisible_n_est_ni_approuvee_ni_armee() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let _pose = VariablePoseeLeTempsDuTemoin::neuve("PLUME_NETBAN_FROM_ACTIONS", "1");
        let _g = NETBAN_TEST_LOCK.lock();
        netban_cache().write().clear();
        let (st, _tmp) = rna_etat("ligne-illisible");

        // CONTRÔLE POSITIF — une riposte lue s'approuve, s'inscrit au registre et ARME le miroir HTTP.
        let saine = rna_riposte_en_attente(&st, "ban_ip", "203.0.113.7", 0);
        let registre_avant = rna_lignes_de_registre(&st);
        let (statut, _) = rna_approuver(&st, saine).await;
        assert_eq!(statut, 204, "une riposte lue s'approuve");
        assert_eq!(rna_statut(&st, saine), "approved", "et son statut est écrit");
        assert_eq!(rna_lignes_de_registre(&st), registre_avant + 1, "le registre porte l'approbation");
        assert_eq!(rna_bans_armes(&st), 1, "et le ban natif est ARMÉ — c'est ce que la lecture sert");

        // LA LIGNE ILLISIBLE — `target` porte un BLOB, que `get::<String>` refuse. La requête reste
        // saine : seul le MAPPEUR échoue, comme sur une valeur corrompue en exploitation.
        let illisible = rna_riposte_en_attente(&st, "ban_ip", "203.0.113.8", 0);
        rna_ecrire(&st, &format!("UPDATE action SET target=x'FF' WHERE id={illisible};"));
        let registre_avant = rna_lignes_de_registre(&st);
        let (statut, avoue) = rna_approuver(&st, illisible).await;
        assert_eq!(statut, 503, "lecture non faite : la route REFUSE au lieu d'approuver en silence : {avoue}");
        assert!(
            rna_phrase(&avoue).starts_with(CAUSE_RIPOSTE_NON_LUE),
            "le refus NOMME sa cause : {avoue}"
        );
        assert_eq!(rna_statut(&st, illisible), "pending", "AUCUN statut d'approbation n'a été écrit");
        assert_eq!(rna_lignes_de_registre(&st), registre_avant, "et AUCUNE ligne de registre non plus");
        assert_eq!(rna_bans_armes(&st), 1, "aucun ban de plus : la riposte non lue n'a rien armé");
    }

    // -------------------------------------------------------------------------------------
    // (2) LA TABLE RETIRÉE — la PRÉPARATION échoue, même refus nommé.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `action` renommée sous les pieds du gestionnaire, l'approbation refuse par le
    /// même 503 nommé et n'écrit RIEN — ni registre (lisible pendant le refus), ni statut (relu une
    /// fois la table remise). Contrôle positif compté AVANT le retrait, sur la même base.
    ///
    /// CE QU'IL NE TIENT PAS : il ne dit rien de l'armement (l'auto-armement n'est pas activé ici, et
    /// c'est délibéré — le refus doit tenir SANS ce drapeau, sinon un réglage de déploiement
    /// déciderait si une lecture ratée est vue).
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : remettre `let _ = conn.execute(UPDATE …)` suivi de
    /// `ledger_append` avant la lecture — le refus devient un 204, et la ligne de registre apparaît
    /// pendant que la table des ripostes est hors d'atteinte.
    #[tokio::test]
    async fn p10_20q_une_table_de_ripostes_hors_d_atteinte_refuse_l_approbation_sans_rien_ecrire() {
        let (st, _tmp) = rna_etat("table-retiree");
        let cible = rna_riposte_en_attente(&st, "ban_ip", "203.0.113.9", 0);

        // CONTRÔLE POSITIF — sur la même base, une autre riposte s'approuve normalement.
        let temoin = rna_riposte_en_attente(&st, "kill_pid", "4242", 1);
        let registre_avant = rna_lignes_de_registre(&st);
        assert_eq!(rna_approuver(&st, temoin).await.0, 204);
        assert_eq!(rna_statut(&st, temoin), "approved");
        assert_eq!(rna_lignes_de_registre(&st), registre_avant + 1);

        // LA TABLE RETIRÉE — renommée, elle n'est plus sous le nom que le SQL servi attend.
        rna_ecrire(&st, "ALTER TABLE action RENAME TO action_hors_d_atteinte;");
        let registre_avant = rna_lignes_de_registre(&st);
        let (statut, sans_table) = rna_approuver(&st, cible).await;
        assert_eq!(statut, 503, "table hors d'atteinte : même refus : {sans_table}");
        assert!(rna_phrase(&sans_table).starts_with(CAUSE_RIPOSTE_NON_LUE), "{sans_table}");
        assert_eq!(rna_lignes_de_registre(&st), registre_avant, "le registre, lui, était lisible — et il ne reçoit RIEN");

        // LA TABLE REMISE : la riposte visée n'a pas bougé d'un cran.
        rna_ecrire(&st, "ALTER TABLE action_hors_d_atteinte RENAME TO action;");
        assert_eq!(rna_statut(&st, cible), "pending", "la riposte est restée EN ATTENTE, donc visible et rejouable");
    }

    // -------------------------------------------------------------------------------------
    // (3) L'ÉCRITURE DU STATUT QUI ÉCHOUE — séparée de la lecture par une VUE TEMPORAIRE.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : quand la LECTURE réussit et que l'ÉCRITURE du statut échoue, l'approbation
    /// refuse par son propre 503 nommé et le registre n'atteste RIEN. C'est la voie que la clé ne
    /// nommait pas : `let _ = conn.execute(..)` avalait cet échec, et la ligne `action.approved`
    /// partait quand même. La vue temporaire est le seul instrument qui sépare les deux échecs — la
    /// table est renommée, une vue de même nom la rend lisible, et une vue ne se modifie pas.
    ///
    /// CE QU'IL NE TIENT PAS : il n'éprouve pas une base réellement en lecture seule (la cause de
    /// terrain), seulement un objet non modifiable — le chemin de code refusé est le même.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : remettre `let _ = conn.execute("UPDATE action SET
    /// status='approved' …")`. Le refus devient un 204 et le registre gagne une ligne qui affirme une
    /// approbation que la base n'a pas prise.
    #[tokio::test]
    async fn p10_20q_une_approbation_que_la_base_refuse_d_ecrire_n_entre_pas_au_registre() {
        let (st, _tmp) = rna_etat("ecriture-refusee");
        let cible = rna_riposte_en_attente(&st, "ban_ip", "203.0.113.10", 0);

        // LA VUE TEMPORAIRE : lisible, non modifiable. Elle vit sur LA connexion du gestionnaire.
        rna_ecrire(
            &st,
            "ALTER TABLE action RENAME TO action_source;\
             CREATE TEMP VIEW action AS SELECT * FROM action_source;",
        );
        let registre_avant = rna_lignes_de_registre(&st);
        let (statut, avoue) = rna_approuver(&st, cible).await;
        assert_eq!(statut, 503, "l'écriture refusée REFUSE l'approbation : {avoue}");
        assert!(
            rna_phrase(&avoue).starts_with(CAUSE_APPROBATION_NON_ENREGISTREE),
            "et la cause est celle de l'ÉCRITURE, pas celle de la lecture : {avoue}"
        );
        assert_eq!(rna_lignes_de_registre(&st), registre_avant, "le registre n'atteste AUCUNE approbation");

        // CONTRÔLE POSITIF — la vue retirée, la même riposte s'approuve : le refus n'est pas inconditionnel.
        rna_ecrire(&st, "DROP VIEW action; ALTER TABLE action_source RENAME TO action;");
        assert_eq!(rna_statut(&st, cible), "pending", "rien n'avait été écrit pendant le refus");
        assert_eq!(rna_approuver(&st, cible).await.0, 204);
        assert_eq!(rna_statut(&st, cible), "approved");
        assert_eq!(rna_lignes_de_registre(&st), registre_avant + 1, "et le registre reçoit alors son unique ligne");
    }

    // -------------------------------------------------------------------------------------
    // (4) L'ABSENCE ÉTABLIE — elle ne se confond pas avec la lecture ratée, et elle n'atteste rien.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : approuver un identifiant qu'aucune riposte ne porte rend un 404 NOMMÉ et
    /// n'écrit aucune ligne de registre. Avant ce lot, la route rendait 204 et posait quand même
    /// `action.approved id=N` — le registre tamper-evident attestait l'approbation d'une riposte
    /// INEXISTANTE. Contrôle positif compté dans le même corps.
    ///
    /// CE QU'IL NE TIENT PAS : c'est un changement de contrat pour cet identifiant-là (204 -> 404) ;
    /// aucun module de `web/` ne le distingue aujourd'hui.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : traiter `Ok(None)` comme `Ok(Some(..))` (ou revenir au
    /// `let _ = conn.execute(..)` suivi du `ledger_append` inconditionnel) — le statut redevient 204
    /// et le registre gagne une ligne pour une riposte qui n'existe pas.
    #[tokio::test]
    async fn p10_20q_une_riposte_absente_est_un_quatre_cent_quatre_et_le_registre_n_en_atteste_aucune() {
        let (st, _tmp) = rna_etat("absente");
        let registre_avant = rna_lignes_de_registre(&st);
        let (statut, absente) = rna_approuver(&st, 4242).await;
        assert_eq!(statut, 404, "une absence ÉTABLIE n'est pas une lecture ratée : {absente}");
        assert_eq!(rna_phrase(&absente), CAUSE_RIPOSTE_INTROUVABLE, "{absente}");
        assert_eq!(rna_lignes_de_registre(&st), registre_avant, "et le registre n'atteste AUCUNE approbation");

        // CONTRÔLE POSITIF — le même geste sur une riposte qui existe passe et inscrit sa ligne.
        let vraie = rna_riposte_en_attente(&st, "ban_ip", "203.0.113.11", 1);
        assert_eq!(rna_approuver(&st, vraie).await.0, 204);
        assert_eq!(rna_lignes_de_registre(&st), registre_avant + 1);
    }

    // -------------------------------------------------------------------------------------
    // (5) LE VERDICT CONSERVÉ DU RESPONDER — rang DEUX de la garde de forme.
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : `verdict_conserve_relu` distingue les TROIS issues que `unwrap_or_default()`
    /// écrasait en une chaîne vide — un verdict LU, une ligne DISPARUE, et une lecture NON FAITE dont
    /// la cause est portée. Les trois sont jouées sur une vraie connexion, la troisième par la table
    /// retirée. Le témoin vérifie aussi que le responder écrit bien un `kind` de registre DISTINCT
    /// pour la lecture non faite : c'est ce qui la rend filtrable dans une trace non purgeable.
    ///
    /// CE QU'IL NE TIENT PAS : `respond_run` n'est pas joué de bout en bout (il ouvre une base par
    /// chemin, lit une configuration et lance des processus) ; c'est sa RELECTURE qui est éprouvée
    /// ici, et le fait que les deux `kind` existent dans son corps.
    ///
    /// LA MUTATION QUI LE FERAIT ROUGIR : remettre `.unwrap_or_default()` dans `verdict_conserve_relu`
    /// — « ligne disparue » et « lecture non faite » redeviennent la même chaîne vide, et les deux
    /// derniers blocs tombent.
    #[test]
    fn p10_20q_le_verdict_conserve_qui_n_a_pas_ete_relu_le_dit_au_registre() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        assert!(migrate(&conn), "fixture : la chaîne de migrations doit aller au bout");
        conn.execute("DELETE FROM action", []).unwrap();
        conn.execute(
            "INSERT INTO action(ts,kind,target,status,dry_run,host) VALUES(1000,'ban_ip','203.0.113.12','failed',0,'hote-a')",
            [],
        )
        .unwrap();
        let id = conn.last_insert_rowid();

        // CONTRÔLE POSITIF — le verdict posé par l'agent est LU, et c'est lui qui part au registre.
        match verdict_conserve_relu(&conn, id) {
            VerdictConserve::Lu(v) => assert_eq!(v, "failed", "le verdict conservé est celui de l'agent"),
            VerdictConserve::LigneDisparue => panic!("la ligne existe"),
            VerdictConserve::NonRelu(e) => panic!("la lecture doit avoir lieu : {e}"),
        }

        // L'ABSENCE ÉTABLIE — aucune ligne : c'est un fait, pas une panne.
        assert!(
            matches!(verdict_conserve_relu(&conn, 4242), VerdictConserve::LigneDisparue),
            "un identifiant sans ligne est une absence ÉTABLIE"
        );

        // LA LECTURE NON FAITE — la table retirée : la cause est portée, jamais une chaîne vide.
        conn.execute_batch("ALTER TABLE action RENAME TO action_hors_d_atteinte;").unwrap();
        match verdict_conserve_relu(&conn, id) {
            VerdictConserve::NonRelu(e) => assert!(!e.is_empty(), "la cause de la lecture ratée est PORTÉE"),
            VerdictConserve::Lu(v) => panic!("une table retirée ne rend pas un verdict : `{v}`"),
            VerdictConserve::LigneDisparue => {
                panic!("une lecture qui N'A PAS EU LIEU n'est pas une ligne disparue — c'est la confusion que cette clé ferme")
            }
        }

        // ET LE REGISTRE SAIT LA FILTRER : les deux `kind` existent dans le corps du responder.
        let src = std::fs::read_to_string(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/handlers/actions.rs"),
        )
        .unwrap();
        let debut = src.find("pub(crate) fn respond_run() {").expect("le responder local existe");
        let fin = src[debut..].find("\n}\n").map(|x| debut + x + 3).unwrap_or(src.len());
        let corps = &src[debut..fin];
        assert!(corps.contains("action.exec.verdict-conserve"), "le verdict LU garde son `kind` historique");
        assert!(
            corps.contains("action.exec.verdict-non-relu"),
            "et la lecture NON FAITE porte le sien — une trace non purgeable qui ne se filtre pas ne se relit pas"
        );
    }
}
