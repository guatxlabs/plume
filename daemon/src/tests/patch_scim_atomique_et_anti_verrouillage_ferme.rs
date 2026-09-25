// =====================================================================================
// `P10.21-o` — UN PATCH DE GROUPE SCIM EST ATOMIQUE ; L'ANTI-VERROUILLAGE DU DERNIER ADMINISTRATEUR FERME
// SUR UNE LECTURE RATÉE ; UNE LISTE OU UNE REPRÉSENTATION SCIM NON LUE N'EST PAS SERVIE COMME UN FAIT.
//
// LES DÉFAUTS, MESURÉS AVANT TOUT CORRECTIF (chaque témoin ci-dessous a été vu ROUGE sur la forme d'avant,
// par mutation — voir la ligne « LA MUTATION » de chacun) :
//  * `scim_group_patch` écrivait chaque opération en autocommit. Un refus à la N-ième — anti-lockout `409`,
//    écriture refusée `503`, lecture refusée `503` — laissait appliquées les N-1 précédentes. Le cas le
//    plus lourd ne demande AUCUNE panne : `add D, remove A, remove B, remove D` sur le groupe `admin`
//    rendait un `409` pendant que A et B avaient PERDU leur droit (D restait seul administrateur) ;
//  * l'anti-lockout lisait le rôle visé par `unwrap_or(false)` (PUT/DELETE, `tenants.rs::grant_set`) ou
//    `.is_ok()` (PATCH) : une lecture ratée suivie d'une écriture qui passe RETIRAIT le dernier
//    administrateur. Le compte d'administrateurs, lui, rendait `0` sur une lecture ratée : l'échec y
//    FERMAIT déjà (`<= 1`), mais en affirmant « dernier administrateur », un fait non lu ;
//  * `scim_user_resource` rendait `groups: []` donc `active: false` sur une lecture ratée (un utilisateur
//    en place servi comme désactivé, y compris dans le `201` d'un POST qui venait de poser son droit), et
//    `scim_users_list` servait en `200` une liste vide (lecture ratée) ou amputée (`.flatten()`).
//
// CE QUI ÉTAIT FAUX DANS L'ÉNONCÉ, ET QUE CES TÉMOINS FIXENT : « l'anti-verrouillage s'ouvre sur une base
// qui ne répond pas » — sur une base qui ne répond à RIEN (table retirée), les trois gestes SCIM refusaient
// déjà depuis `P10.21-l` (lecture d'existence ou écriture refusée). La garde ne s'ouvrait que sur une
// lecture ratée ISOLÉE, suivie d'une écriture qui passe ; c'est la panne que ces témoins fabriquent.
//
// LES VOIES D'ÉCHEC : (1) un AUTORISATEUR SQLite qui refuse les lectures de `"grant".role` faites par un
// `SELECT` — à partir de la première (« rôle illisible ») ou de la seconde (« compte illisible ») — et
// laisse passer toute écriture, même quand sa clause `WHERE` lit la colonne (même geste que le témoin de
// `migrate.rs` : un refus de LECTURE ne bloque aucune écriture) ; (2) un DÉCLENCHEUR TEMPORAIRE qui refuse
// l'`INSERT` d'UN membre (l'écriture de la N-ième opération tombe, les précédentes sont passées) ; (3) la
// table des droits retirée ; (4) une ligne d'identité illisible (nom stocké en blob).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : une base réellement en lecture seule ou un `SQLITE_BUSY` réel entre
// la lecture et l'écriture (l'autorisateur les simule) ; la course « un autre écrivain entre la lecture de
// l'anti-lockout et le `DELETE` » hors transaction (PUT et DELETE lisent puis écrivent sous deux verrous) ;
// le rejeu effectif d'un `503`/`500` par un fournisseur d'identité réel ; et `grant_delete`, dont la
// lecture d'EXISTENCE lit encore un échec comme « grant inconnu » (fermé, mais sous une fausse cause).
// =====================================================================================
mod patch_scim_atomique_et_anti_verrouillage_ferme {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    const PAFV_TENANT: &str = "pafv-t1";

    /// Un plan de contrôle, le tenant catalogué (sans lui `resolve_tenant_access` ne résout rien), et un
    /// utilisateur par `(nom, rôle)` — rôle `None` : une identité sans droit dans le tenant, à AJOUTER.
    fn pafv_etat(membres: &[(&str, Option<&str>)]) -> (AppState, crate::tmp_possede::TmpDb, Vec<String>) {
        let (cp, tmp) = mk_test_control();
        cp.conn
            .lock()
            .execute(
                "INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES(?1,'PAFV','','sans-base',?2,0)",
                params![PAFV_TENANT, now()],
            )
            .expect("fixture : tenant catalogué");
        let mut ids = Vec::new();
        for (nom, role) in membres {
            let id = ensure_platform_user(&cp, nom).expect("fixture : utilisateur créé");
            if let Some(role) = role {
                cp.conn
                    .lock()
                    .execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,?3)", params![id, PAFV_TENANT, role])
                    .expect("fixture : droit posé");
            }
            ids.push(id);
        }
        (tenant_test_state("admins", "editors", "supers", Some(cp)), tmp, ids)
    }

    fn pafv_plan(st: &AppState) -> &ControlPlane {
        st.tenants.control.as_ref().expect("fixture : mode 1")
    }

    fn pafv_executer(st: &AppState, sql: &str) {
        pafv_plan(st).conn.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` doit passer ({e})"));
    }

    /// L'ÉTAT, RELU EN BASE — jamais la réponse : les droits du tenant, `(nom, rôle)` triés par nom.
    fn pafv_droits(st: &AppState) -> Vec<(String, String)> {
        let c = pafv_plan(st).conn.lock();
        let mut s = c
            .prepare("SELECT p.name, g.role FROM \"grant\" g JOIN platform_user p ON p.id=g.user_id WHERE g.tenant_id=?1 ORDER BY p.name")
            .expect("fixture : droits");
        let lus = s
            .query_map(params![PAFV_TENANT], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .expect("fixture : droits")
            .collect::<Result<Vec<_>, _>>()
            .expect("fixture : droits lisibles");
        lus
    }

    fn pafv_attendus(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter().map(|(n, r)| (n.to_string(), r.to_string())).collect()
    }

    fn pafv_maillons(st: &AppState, genre: &str) -> i64 {
        pafv_plan(st)
            .conn
            .lock()
            .query_row("SELECT COUNT(*) FROM control_ledger WHERE kind=?1", params![genre], |r| r.get(0))
            .expect("fixture : le journal de contrôle se lit")
    }

    /// L'ACCÈS TEL QUE LE SERT `auth_guard` à chaque requête (identité Basic ou cookie, mode 1).
    fn pafv_acces(st: &AppState, nom: &str) -> Result<String, StatusCode> {
        resolve_tenant_access(st, nom, None, false, Some(PAFV_TENANT), false, None).map(|a| a.role).map_err(|(code, _)| code)
    }

    /// LA LECTURE RATÉE ISOLÉE. Les lectures de `"grant".role` faites par un `SELECT` sont REFUSÉES à partir
    /// de la `(laisser_passer + 1)`-ième ; `DELETE`, `INSERT`, `UPDATE` passent, même quand leur `WHERE` lit
    /// la colonne. `laisser_passer = 0` : le rôle visé est illisible ; `= 1` : il se lit, le COMPTE non.
    fn pafv_refuser_la_lecture_des_roles(st: &AppState, laisser_passer: usize) {
        let mut dans_un_select = false;
        let mut lues = 0usize;
        pafv_plan(st).conn.lock().authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Select => {
                dans_un_select = true;
                Authorization::Allow
            }
            AuthAction::Insert { .. } | AuthAction::Update { .. } | AuthAction::Delete { .. } => {
                dans_un_select = false;
                Authorization::Allow
            }
            AuthAction::Read { table_name, column_name } if dans_un_select && table_name == "grant" && column_name == "role" => {
                lues += 1;
                if lues > laisser_passer {
                    Authorization::Deny
                } else {
                    Authorization::Allow
                }
            }
            _ => Authorization::Allow,
        }));
    }

    fn pafv_lever_la_panne(st: &AppState) {
        pafv_plan(st).conn.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// Le refus SCIM attendu : `503`, corps d'erreur SCIM 2.0, cause nommée en tête, aucune table nommée.
    fn pafv_refus_scim(quoi: &str, statut: StatusCode, v: &Value, cause: &str) {
        assert_eq!(statut, StatusCode::SERVICE_UNAVAILABLE, "{quoi} : ce qui n'a pas été lu est REFUSÉ, jamais deviné : {v}");
        assert_eq!(v["schemas"], json!(["urn:ietf:params:scim:api:messages:2.0:Error"]), "{quoi} : corps d'erreur SCIM : {v}");
        assert_eq!(v["status"], json!("503"), "{quoi} : statut porté dans le corps (RFC 7644 §3.12) : {v}");
        let detail = v["detail"].as_str().unwrap_or("");
        assert!(detail.starts_with(cause), "{quoi} : la cause est nommée : {v}");
        assert!(!detail.contains("grant") && !detail.contains("authoriz"), "{quoi} : la cause du moteur ne part pas chez l'IdP : {v}");
    }

    fn pafv_ctx() -> ScimCtx {
        ScimCtx { tenant: PAFV_TENANT.into() }
    }

    async fn pafv_patch(st: &AppState, role: &str, corps: Value) -> (StatusCode, Value) {
        tok_resp_json(scim_group_patch(State(st.clone()), Extension(pafv_ctx()), Path(role.to_string()), Json(corps)).await).await
    }

    fn pafv_sans_transaction_pendante(st: &AppState, quoi: &str) {
        assert!(pafv_plan(st).conn.lock().is_autocommit(), "{quoi} : aucune transaction laissée ouverte sur le plan de contrôle");
    }

    // -------------------------------------------------------------------------------------
    // (1) VOLET UN — LE PATCH EST ATOMIQUE (RFC 7644 §3.5.2).
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, pour TROIS refus à la N-ième opération : (a) l'anti-lockout `409` à la QUATRIÈME
    /// (`add D, remove A, remove B, remove D` sur `admin`, sans aucune panne) ; (b) l'écriture refusée `503`
    /// à la TROISIÈME (`add E, remove C, add F` sur `editor`, l'`INSERT` de F refusé par un déclencheur) ;
    /// (c) la lecture de l'anti-lockout refusée `503` à la DEUXIÈME (`add D, remove A`). Dans les trois cas :
    /// l'état RELU est celui d'avant la demande (aucun ajout, aucun retrait), aucun `scim.group.patch`
    /// n'entre, l'accès des membres est inchangé, et aucune transaction ne reste ouverte. Contrôle positif :
    /// la même demande amputée de l'opération refusée passe entière, attestée UNE fois avec ses comptes.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : retirer la transaction (`Txn::begin` / `commit`) — (a) laisse D seul
    /// administrateur sous un `409`, (b) laisse E ajouté et C retiré sous un `503`, (c) laisse D ajouté.
    #[tokio::test]
    async fn pafv_un_patch_refuse_en_cours_de_route_n_applique_aucune_de_ses_operations() {
        // (a) L'ANTI-LOCKOUT À LA QUATRIÈME OPÉRATION.
        let (st, _tmp, ids) = pafv_etat(&[("pafv-anne", Some("admin")), ("pafv-bert", Some("admin")), ("pafv-dora", None)]);
        let (anne, bert, dora) = (ids[0].clone(), ids[1].clone(), ids[2].clone());
        let avant = pafv_attendus(&[("pafv-anne", "admin"), ("pafv-bert", "admin")]);
        let (statut, v) = pafv_patch(
            &st,
            "admin",
            json!({ "Operations": [
                { "op": "add", "value": [{ "value": dora }] },
                { "op": "remove", "value": [{ "value": anne }] },
                { "op": "remove", "value": [{ "value": bert }] },
                { "op": "remove", "value": [{ "value": dora }] },
            ] }),
        )
        .await;
        assert_eq!(statut, StatusCode::CONFLICT, "(a) la quatrième opération viderait le tenant : {v}");
        assert_eq!(pafv_droits(&st), avant, "(a) ÉTAT RELU : aucune des trois opérations précédentes n'est appliquée");
        assert_eq!(pafv_maillons(&st, "scim.group.patch"), 0, "(a) JOURNAL : rien d'attesté");
        assert_eq!(pafv_acces(&st, "pafv-bert"), Ok("admin".to_string()), "(a) ACCÈS : le retrait défait n'a rien retiré");
        assert_eq!(pafv_acces(&st, "pafv-dora"), Err(StatusCode::FORBIDDEN), "(a) ACCÈS : l'ajout défait n'a rien donné");
        pafv_sans_transaction_pendante(&st, "(a)");
        // CONTRÔLE POSITIF — la demande sans sa quatrième opération passe ENTIÈRE.
        let (statut, v) = pafv_patch(
            &st,
            "admin",
            json!({ "Operations": [
                { "op": "add", "value": [{ "value": dora }] },
                { "op": "remove", "value": [{ "value": anne }] },
                { "op": "remove", "value": [{ "value": bert }] },
            ] }),
        )
        .await;
        assert_eq!(statut, StatusCode::OK, "(a) contrôle positif : {v}");
        assert_eq!(pafv_droits(&st), pafv_attendus(&[("pafv-dora", "admin")]), "(a) contrôle positif : les trois opérations appliquées");
        assert_eq!(pafv_maillons(&st, "scim.group.patch"), 1, "(a) contrôle positif : attesté une fois");

        // (b) L'ÉCRITURE REFUSÉE À LA TROISIÈME OPÉRATION.
        let (st, _tmp, ids) = pafv_etat(&[("pafv-carl", Some("editor")), ("pafv-emma", None), ("pafv-fred", None)]);
        let (carl, emma, fred) = (ids[0].clone(), ids[1].clone(), ids[2].clone());
        let corps = json!({ "Operations": [
            { "op": "add", "value": [{ "value": emma }] },
            { "op": "remove", "value": [{ "value": carl }] },
            { "op": "add", "value": [{ "value": fred }] },
        ] });
        pafv_executer(
            &st,
            &format!(
                "CREATE TEMP TRIGGER pafv_refus_d_ecriture BEFORE INSERT ON \"grant\" WHEN NEW.user_id='{fred}' \
                 BEGIN SELECT RAISE(ABORT, 'ecriture refusee par le temoin'); END;"
            ),
        );
        let (statut, v) = pafv_patch(&st, "editor", corps.clone()).await;
        pafv_executer(&st, "DROP TRIGGER pafv_refus_d_ecriture;");
        pafv_refus_scim("(b) écriture refusée à la troisième opération", statut, &v, CAUSE_SCIM_OPERATION_DE_GROUPE_NON_ECRITE);
        assert_eq!(pafv_droits(&st), pafv_attendus(&[("pafv-carl", "editor")]), "(b) ÉTAT RELU : ni l'ajout d'emma ni le retrait de carl");
        assert_eq!(pafv_maillons(&st, "scim.group.patch"), 0, "(b) JOURNAL : rien d'attesté");
        assert_eq!(pafv_acces(&st, "pafv-carl"), Ok("editor".to_string()), "(b) ACCÈS : carl garde son droit — le refus le dit");
        pafv_sans_transaction_pendante(&st, "(b)");
        // CONTRÔLE POSITIF — la même demande, base saine.
        let (statut, v) = pafv_patch(&st, "editor", corps).await;
        assert_eq!(statut, StatusCode::OK, "(b) contrôle positif : {v}");
        assert_eq!(pafv_droits(&st), pafv_attendus(&[("pafv-emma", "editor"), ("pafv-fred", "editor")]), "(b) contrôle positif");
        let detail: String = pafv_plan(&st)
            .conn
            .lock()
            .query_row("SELECT detail FROM control_ledger WHERE kind='scim.group.patch'", [], |r| r.get(0))
            .expect("(b) un maillon");
        assert_eq!(detail, "role 'editor' +2/-1 membres", "(b) contrôle positif : chaque opération comptée telle qu'écrite");

        // (c) LA LECTURE DE L'ANTI-LOCKOUT REFUSÉE À LA DEUXIÈME OPÉRATION.
        let (st, _tmp, ids) = pafv_etat(&[("pafv-anne", Some("admin")), ("pafv-bert", Some("admin")), ("pafv-dora", None)]);
        let (anne, dora) = (ids[0].clone(), ids[2].clone());
        pafv_refuser_la_lecture_des_roles(&st, 0);
        let (statut, v) = pafv_patch(
            &st,
            "admin",
            json!({ "Operations": [{ "op": "add", "value": [{ "value": dora }] }, { "op": "remove", "value": [{ "value": anne }] }] }),
        )
        .await;
        pafv_lever_la_panne(&st);
        pafv_refus_scim("(c) lecture refusée à la deuxième opération", statut, &v, CAUSE_SCIM_DERNIER_ADMINISTRATEUR_NON_ETABLI);
        assert_eq!(pafv_droits(&st), avant, "(c) ÉTAT RELU : l'ajout de dora est défait");
        assert_eq!(pafv_maillons(&st, "scim.group.patch"), 0, "(c) JOURNAL : rien d'attesté");
        pafv_sans_transaction_pendante(&st, "(c)");
    }

    // -------------------------------------------------------------------------------------
    // (2) VOLET DEUX — SÉCURITÉ : L'ANTI-VERROUILLAGE SCIM FERME SUR UNE LECTURE RATÉE.
    // -------------------------------------------------------------------------------------

    async fn pafv_jouer_le_retrait(st: &AppState, geste: &str, id: &str) -> (StatusCode, Value) {
        match geste {
            "DELETE" => tok_resp_json(scim_user_delete(State(st.clone()), Extension(pafv_ctx()), Path(id.to_string())).await).await,
            "PUT active=false" => {
                tok_resp_json(scim_user_replace(State(st.clone()), Extension(pafv_ctx()), Path(id.to_string()), Json(json!({ "active": false }))).await)
                    .await
            }
            _ => pafv_patch(st, "admin", json!({ "Operations": [{ "op": "remove", "value": [{ "value": id }] }] })).await,
        }
    }

    /// CE QU'IL TIENT, pour CHACUN des trois retraits SCIM (PUT `active=false`, DELETE, PATCH `remove` sur
    /// `admin`) et CHACUNE des deux pannes (rôle illisible, compte illisible), sur un tenant dont le seul
    /// administrateur est visé : la réponse est le `503` SCIM `CAUSE_SCIM_DERNIER_ADMINISTRATEUR_NON_ETABLI` ;
    /// l'administrateur porte TOUJOURS son droit (relu) ; aucun maillon n'entre ; son accès est toujours
    /// servi. Contrôle positif : la panne levée, le même retrait rend le VRAI verdict, `409`.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : remettre `unwrap_or(false)` sur la lecture du rôle de
    /// `scim_would_orphan_last_admin` (PUT et DELETE, « rôle illisible » : `200`/`204`, le dernier
    /// administrateur RETIRÉ, le tenant orphelin) ; remettre `.is_ok()` sur la lecture d'appartenance du
    /// PATCH (même effet par `PATCH`) ; faire rendre `0` au compte sur une lecture ratée (« compte
    /// illisible » : `409` au lieu de `503`, la fausse cause « dernier administrateur »).
    #[tokio::test]
    async fn pafv_une_lecture_ratee_de_l_anti_verrouillage_refuse_au_lieu_de_retirer_le_dernier_administrateur() {
        for geste in ["PUT active=false", "DELETE", "PATCH remove"] {
            for (panne, laisser_passer) in [("rôle illisible", 0usize), ("compte illisible", 1usize)] {
                let (st, _tmp, ids) = pafv_etat(&[("pafv-seule", Some("admin"))]);
                let seule = ids[0].clone();
                pafv_refuser_la_lecture_des_roles(&st, laisser_passer);
                let (statut, v) = pafv_jouer_le_retrait(&st, geste, &seule).await;
                pafv_lever_la_panne(&st);
                pafv_refus_scim(&format!("{geste} ({panne})"), statut, &v, CAUSE_SCIM_DERNIER_ADMINISTRATEUR_NON_ETABLI);
                assert_eq!(
                    pafv_droits(&st),
                    pafv_attendus(&[("pafv-seule", "admin")]),
                    "ÉTAT RELU ({geste}, {panne}) : le dernier administrateur porte toujours son droit"
                );
                assert_eq!(
                    (pafv_maillons(&st, "scim.user.deprovision"), pafv_maillons(&st, "scim.group.patch")),
                    (0, 0),
                    "JOURNAL ({geste}, {panne}) : aucun retrait attesté"
                );
                assert_eq!(pafv_acces(&st, "pafv-seule"), Ok("admin".to_string()), "ACCÈS ({geste}, {panne}) : toujours servi");
                pafv_sans_transaction_pendante(&st, &format!("{geste} ({panne})"));
                // CONTRÔLE POSITIF — base saine : le verdict LU est rendu.
                let (statut, v) = pafv_jouer_le_retrait(&st, geste, &seule).await;
                assert_eq!(statut, StatusCode::CONFLICT, "{geste} (base saine) : dernier administrateur, lu cette fois : {v}");
            }
        }
    }

    // -------------------------------------------------------------------------------------
    // (3) VOLET DEUX — LES MÊMES LECTURES, CÔTÉ DROITS DE TENANT (`tenants.rs`), SEULS AUTRES APPELANTS.
    // -------------------------------------------------------------------------------------

    fn pafv_refus_console(quoi: &str, statut: StatusCode, v: &Value) {
        assert_eq!(statut, StatusCode::SERVICE_UNAVAILABLE, "{quoi} : ce qui n'a pas été lu est REFUSÉ : {v}");
        let erreur = v["error"].as_str().unwrap_or("");
        assert!(erreur.starts_with(CAUSE_DERNIER_ADMINISTRATEUR_NON_ETABLI), "{quoi} : la cause est nommée en tête : {v}");
    }

    /// CE QU'IL TIENT : `grant_set` — la seule administratrice du tenant se rétrograde en `viewer` (acteur
    /// admin de CE tenant, non super-administrateur). Rôle illisible comme compte illisible : `503` nommé,
    /// elle reste `admin`, aucun `grant.set`. `grant_delete` — elle retire son propre droit, compte
    /// illisible : `503` nommé, le droit reste. Contrôle positif : base saine, les deux gestes rendent le
    /// verdict LU, `400` « dernier administrateur ».
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `unwrap_or(false)` sur l'ancien rôle de `grant_set` (rôle
    /// illisible : `200`, la dernière administratrice RÉTROGRADÉE) ; un compte qui rend `0` sur une lecture
    /// ratée (compte illisible : `400` au lieu de `503`, pour les deux gestes).
    #[tokio::test]
    async fn pafv_l_anti_verrouillage_des_droits_de_tenant_refuse_sur_une_lecture_ratee() {
        let alix = au_tadmin("pafv-alix", PAFV_TENANT);
        for (panne, laisser_passer) in [("rôle illisible", 0usize), ("compte illisible", 1usize)] {
            let (st, _tmp, _ids) = pafv_etat(&[("pafv-alix", Some("admin"))]);
            pafv_refuser_la_lecture_des_roles(&st, laisser_passer);
            let (statut, v) = tok_resp_json(
                grant_set(State(st.clone()), Extension(alix.clone()), Path(PAFV_TENANT.into()), Json(json!({ "user": "pafv-alix", "role": "viewer" })))
                    .await,
            )
            .await;
            pafv_lever_la_panne(&st);
            pafv_refus_console(&format!("grant_set ({panne})"), statut, &v);
            assert_eq!(pafv_droits(&st), pafv_attendus(&[("pafv-alix", "admin")]), "ÉTAT RELU (grant_set, {panne}) : toujours administratrice");
            assert_eq!(pafv_maillons(&st, "grant.set"), 0, "JOURNAL (grant_set, {panne}) : rien d'attesté");
            let (statut, v) = tok_resp_json(
                grant_set(State(st.clone()), Extension(alix.clone()), Path(PAFV_TENANT.into()), Json(json!({ "user": "pafv-alix", "role": "viewer" })))
                    .await,
            )
            .await;
            assert_eq!(statut, StatusCode::BAD_REQUEST, "grant_set (base saine) : dernier administrateur, lu : {v}");
        }

        let (st, _tmp, _ids) = pafv_etat(&[("pafv-alix", Some("admin"))]);
        pafv_refuser_la_lecture_des_roles(&st, 1);
        let (statut, v) = tok_resp_json(grant_delete(State(st.clone()), Extension(alix.clone()), Path((PAFV_TENANT.into(), "pafv-alix".into()))).await).await;
        pafv_lever_la_panne(&st);
        pafv_refus_console("grant_delete (compte illisible)", statut, &v);
        assert_eq!(pafv_droits(&st), pafv_attendus(&[("pafv-alix", "admin")]), "ÉTAT RELU (grant_delete) : le droit reste");
        assert_eq!(pafv_maillons(&st, "grant.remove"), 0, "JOURNAL (grant_delete) : rien d'attesté");
        let (statut, v) = tok_resp_json(grant_delete(State(st.clone()), Extension(alix.clone()), Path((PAFV_TENANT.into(), "pafv-alix".into()))).await).await;
        assert_eq!(statut, StatusCode::BAD_REQUEST, "grant_delete (base saine) : dernier administrateur, lu : {v}");
    }

    // -------------------------------------------------------------------------------------
    // (4) VOLET TROIS — UNE LISTE OU UNE REPRÉSENTATION NON LUE N'EST PAS SERVIE COMME UN FAIT.
    // -------------------------------------------------------------------------------------

    async fn pafv_lister(st: &AppState) -> (StatusCode, Value) {
        tok_resp_json(scim_users_list(State(st.clone()), Extension(pafv_ctx()), axum::extract::Query(HashMap::new())).await).await
    }

    /// CE QU'IL TIENT : (a) la table des droits retirée, `GET /Users` rend le `503` SCIM de la liste
    /// illisible (avant : `200`, zéro utilisateur) ; (b) une identité dont le nom est illisible (blob), la
    /// liste n'est pas servie amputée (avant : `200`, l'identité retirée en silence, `totalResults` faux) ;
    /// (c) les droits illisibles, la liste, le `GET /Users/{id}` et le `PUT active=true` (rien d'écrit)
    /// rendent un `503` (avant : `200`, chacun `active: false`, `groups: []`) ; (d) `POST /Users` avec un
    /// groupe, droits illisibles à la relecture : `500` `CAUSE_SCIM_REPRESENTATION_NON_RELUE` — le droit EST
    /// posé et attesté, et la réponse le dit (avant : `201` qui servait l'utilisateur désactivé, sans droit).
    /// Contrôle positif : base saine, la liste entière, chacun actif avec son droit.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : remettre `.flatten()` / `unwrap_or_default()` sur la lecture de
    /// `scim_user_resource` ((c) et (d) : `200`/`201` `active: false`) ; remettre `.flatten()` sur la
    /// lecture de la liste ((b) : `200` amputé) ; remettre `if let Ok` sur sa préparation ((a) : `200` vide).
    #[tokio::test]
    async fn pafv_une_liste_ou_une_representation_non_lue_n_est_pas_servie_comme_un_fait() {
        let (st, _tmp, ids) = pafv_etat(&[("pafv-gina", Some("editor")), ("pafv-hugo", Some("viewer"))]);
        let gina = ids[0].clone();

        // (a) LA LISTE ELLE-MÊME NON LUE.
        pafv_executer(&st, "ALTER TABLE \"grant\" RENAME TO grant_hors_d_atteinte;");
        let (statut, v) = pafv_lister(&st).await;
        pafv_executer(&st, "ALTER TABLE grant_hors_d_atteinte RENAME TO \"grant\";");
        pafv_refus_scim("(a) liste, table des droits retirée", statut, &v, CAUSE_SCIM_LISTE_DES_UTILISATEURS_ILLISIBLE);

        // (b) UNE LIGNE ILLISIBLE N'EST PAS UNE LIGNE ABSENTE.
        pafv_executer(
            &st,
            &format!(
                "INSERT INTO platform_user(id,name,hash,is_superadmin,created) VALUES('pafv-illisible',X'696c6c6973696265',NULL,0,0); \
                 INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES('pafv-illisible','{PAFV_TENANT}','viewer');"
            ),
        );
        let (statut, v) = pafv_lister(&st).await;
        pafv_executer(&st, "DELETE FROM \"grant\" WHERE user_id='pafv-illisible'; DELETE FROM platform_user WHERE id='pafv-illisible';");
        pafv_refus_scim("(b) liste, une identité illisible", statut, &v, CAUSE_SCIM_LISTE_DES_UTILISATEURS_ILLISIBLE);

        // (c) LES DROITS NON LUS — trois lectures qui ne modifient rien.
        pafv_refuser_la_lecture_des_roles(&st, 0);
        let (statut_liste, v_liste) = pafv_lister(&st).await;
        let (statut_get, v_get) = tok_resp_json(scim_user_get(State(st.clone()), Extension(pafv_ctx()), Path(gina.clone())).await).await;
        let (statut_put, v_put) =
            tok_resp_json(scim_user_replace(State(st.clone()), Extension(pafv_ctx()), Path(gina.clone()), Json(json!({ "active": true }))).await).await;
        pafv_lever_la_panne(&st);
        pafv_refus_scim("(c) liste, droits illisibles", statut_liste, &v_liste, CAUSE_SCIM_LISTE_DES_UTILISATEURS_ILLISIBLE);
        pafv_refus_scim("(c) GET, droits illisibles", statut_get, &v_get, CAUSE_SCIM_UTILISATEUR_ILLISIBLE);
        pafv_refus_scim("(c) PUT active=true, droits illisibles", statut_put, &v_put, CAUSE_SCIM_UTILISATEUR_ILLISIBLE);

        // (d) LE GESTE FAIT, SA REPRÉSENTATION NON RELUE. ADAPTÉ PAR `P10.21-r` : `POST /Users` lit désormais, AVANT
        // d'écrire, le rôle actuel du membre (un droit qui écraserait celui du dernier administrateur est refusé) ; cette
        // première lecture refusée rendrait le 503 « non établi », rien d'écrit. La panne commence donc à la SECONDE
        // lecture des rôles — celle de la représentation, après l'écriture —, qui est la propriété de ce volet.
        pafv_refuser_la_lecture_des_roles(&st, 1);
        let (statut, v) = tok_resp_json(
            scim_user_create(State(st.clone()), Extension(pafv_ctx()), Json(json!({ "userName": "pafv-ines", "groups": [{ "value": "viewer" }] }))).await,
        )
        .await;
        pafv_lever_la_panne(&st);
        assert_eq!(statut, StatusCode::INTERNAL_SERVER_ERROR, "(d) le geste est fait, sa représentation non relue — ni 201 ni 503 : {v}");
        assert_eq!(v["status"], json!("500"), "(d) corps d'erreur SCIM : {v}");
        assert!(v["detail"].as_str().unwrap_or("").starts_with(CAUSE_SCIM_REPRESENTATION_NON_RELUE), "(d) la cause dit ce qui a eu lieu : {v}");
        assert_eq!(
            pafv_droits(&st),
            pafv_attendus(&[("pafv-gina", "editor"), ("pafv-hugo", "viewer"), ("pafv-ines", "viewer")]),
            "(d) ÉTAT RELU : le droit demandé EST posé — la réponse ne le nie pas"
        );
        assert_eq!(pafv_maillons(&st, "scim.user.provision"), 1, "(d) JOURNAL : le geste fait est attesté");

        // CONTRÔLE POSITIF — base saine : la liste ENTIÈRE, chacun actif avec son droit.
        let (statut, v) = pafv_lister(&st).await;
        assert_eq!(statut, StatusCode::OK, "{v}");
        assert_eq!(v["totalResults"], json!(3), "{v}");
        let lus: Vec<(String, bool, String)> = v["Resources"]
            .as_array()
            .expect("Resources")
            .iter()
            .map(|r| (r["userName"].as_str().unwrap_or("").to_string(), r["active"].as_bool().unwrap_or(false), r["groups"][0]["value"].as_str().unwrap_or("").to_string()))
            .collect();
        assert_eq!(
            lus,
            vec![("pafv-gina".to_string(), true, "editor".to_string()), ("pafv-hugo".to_string(), true, "viewer".to_string()), ("pafv-ines".to_string(), true, "viewer".to_string())],
            "contrôle positif : chacun actif, avec son droit"
        );
    }
}
