// =====================================================================================
// `P10.34-a` — UN RETRAIT SCIM NE DIT PLUS SI UNE IDENTITÉ EXISTE DANS UN AUTRE TENANT, ET UN ID ABSENT NE RETIENT
// JAMAIS LA RÉVOCATION DES MEMBRES RÉELS DE LA DEMANDE.
//
// CE QUI ÉTAIT FAUX (mesuré sur 32db17a8) : le PATCH de groupe jugeait l'existence d'un membre sur `platform_user`,
// table GLOBALE. `remove` d'un id présent sur la plateforme mais sans droit dans le tenant du jeton passait le
// contrôle, le `DELETE` ne trouvait aucune ligne, la demande rendait `200` ; un id inconnu rendait `400 noTarget`.
// Un jeton SCIM d'un tenant distinguait ainsi les comptes des autres tenants. La première correction (93c96845)
// rendait `400 noTarget` aux deux : plus d'oracle, mais un IdP qui renvoie le retrait d'un membre déjà retiré (cas
// courant) voyait refusée la demande ENTIÈRE, donc la révocation des AUTRES membres listés — régression de
// déprovisionnement relevée en revue.
//
// CE QUI EST FAIT : un RETRAIT (`remove`, sous ses quatre formes) juge l'appartenance sur le droit du tenant
// appelant ; un id ABSENT (inconnu de la plateforme, sans droit ici, ou déjà retiré) est un no-op silencieux,
// IDENTIQUE dans tous les cas : `200`, même corps, rien de compté au journal. Les membres réels de la même demande
// SONT TOUS retirés, que l'absent soit listé avant ou après eux. Une lecture ratée du droit reste un refus nommé
// (`503`, témoin `dsa_` de `deprovisionnement_scim_avoue`). Le retrait d'un `replace` (porteurs absents de
// l'ensemble servi) lit ses porteurs dans le droit du tenant : il ne touche jamais un autre tenant.
//
// LES MUTATIONS QUI LE FONT ROUGIR : `VERIF_MUT=Z1_absent_refuse` (le refus `400` rétabli sur un absent : la
// révocation du membre réel n'a pas lieu) ; `VERIF_MUT=Z1_reponse_differente_autre_tenant` (réponse distincte pour
// l'id d'un autre tenant) ; `VERIF_MUT=Z1_lecture_ratee_vaut_absence` (une lecture ratée du droit prise pour une
// absence : rouge sur `dsa_un_retrait_de_membre_que_la_base_refuse_est_refuse`) ; `VERIF_MUT=Z1_coupe_au_premier_absent`
// (la lecture des membres s'arrête au premier absent : le membre réel listé APRÈS lui garde son droit) ;
// `VERIF_MUT=Z1_premier_present_seul` (seul le premier membre réel d'une opération est retiré).
//
// CE QU'IL NE TIENT PAS : AJOUTER (et l'ensemble servi d'un `replace`, qui s'ajoute) reste jugé sur `platform_user`
// — un id d'un autre tenant y est accepté et reçoit un droit ici (rattachement : reste de `P10.34-a`, `platform_user`
// ne porte pas de tenant d'origine), un id jamais servi rend `noTarget`. Ce n'est pas un oracle par `userName` : la
// chaîne `POST /Users` puis `PATCH add` répond pareil pour un nom partagé et un nom neuf (témoins `saon_`) ; le refus
// d'un id d'un autre tenant en créerait un. Le temps de réponse n'est pas
// mesuré (une lecture de plus pour un membre présent). Seuls les ids ABSENTS sont tus : le refus d'un AUTRE id
// présent — `409` s'il est le dernier administrateur, `503` si son droit est illisible — défait toujours la demande
// entière, révocations comprises (atomicité RFC 7644 §3.5.2, `P10.21-o`).
// =====================================================================================
mod scim_patch_retrait_sans_oracle_entre_tenants {
    use super::*;

    const PSOE_TENANT: &str = "psoe-t1";
    const PSOE_AUTRE_TENANT: &str = "psoe-t2";
    const PSOE_INCONNU: &str = "psoe-id-qui-n-existe-pas";

    struct PsoeIds {
        anne: String,
        carl: String,
        bert_ailleurs: String,
    }

    /// anne admin et carl editor dans le tenant appelant ; bert editor dans l'AUTRE tenant seulement.
    fn psoe_etat() -> (AppState, crate::tmp_possede::TmpDb, PsoeIds) {
        let (cp, tmp) = mk_test_control();
        for (id, nom) in [(PSOE_TENANT, "PSOE1"), (PSOE_AUTRE_TENANT, "PSOE2")] {
            cp.conn
                .lock()
                .execute(
                    "INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES(?1,?2,'','sans-base',?3,0)",
                    params![id, nom, now()],
                )
                .expect("fixture : tenant catalogué");
        }
        let anne = ensure_platform_user(&cp, "psoe-anne").expect("fixture : utilisateur créé");
        let carl = ensure_platform_user(&cp, "psoe-carl").expect("fixture : utilisateur créé");
        let bert_ailleurs = ensure_platform_user(&cp, "psoe-bert").expect("fixture : utilisateur créé");
        for (id, tenant, role) in [(&anne, PSOE_TENANT, "admin"), (&carl, PSOE_TENANT, "editor"), (&bert_ailleurs, PSOE_AUTRE_TENANT, "editor")] {
            cp.conn
                .lock()
                .execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,?3)", params![id, tenant, role])
                .expect("fixture : droit posé");
        }
        (tenant_test_state("admins", "editors", "supers", Some(cp)), tmp, PsoeIds { anne, carl, bert_ailleurs })
    }

    /// TOUS les droits de la plateforme, bruts (sans jointure) : `(user_id, tenant, rôle)`.
    fn psoe_droits(st: &AppState) -> Vec<(String, String, String)> {
        let c = st.tenants.control.as_ref().expect("fixture : mode 1").conn.lock();
        let mut s = c.prepare("SELECT user_id, tenant_id, role FROM \"grant\" ORDER BY user_id, tenant_id, role").expect("fixture : droits");
        let lus = s
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))
            .expect("fixture : droits")
            .collect::<Result<Vec<_>, _>>()
            .expect("fixture : droits lisibles");
        lus
    }

    fn psoe_maillons(st: &AppState) -> Vec<String> {
        let c = st.tenants.control.as_ref().expect("fixture : mode 1").conn.lock();
        let mut s = c.prepare("SELECT detail FROM control_ledger WHERE kind='scim.group.patch' ORDER BY id").expect("fixture : journal");
        let lus = s.query_map([], |r| r.get::<_, String>(0)).expect("fixture : journal").collect::<Result<Vec<_>, _>>().expect("fixture : journal lisible");
        lus
    }

    async fn psoe_patch(st: &AppState, role: &str, corps: Value) -> (StatusCode, Value) {
        let ctx = ScimCtx { tenant: PSOE_TENANT.into() };
        tok_resp_json(scim_group_patch(State(st.clone()), Extension(ctx), Path(role.to_string()), Json(corps)).await).await
    }

    /// Les quatre formes d'un retrait qui nomme un membre.
    fn psoe_formes_du_retrait(id: &str) -> Vec<(&'static str, Value)> {
        vec![
            ("remove value liste", json!({ "op": "remove", "value": [{ "value": id }] })),
            ("remove path members", json!({ "op": "remove", "path": "members", "value": [{ "value": id }] })),
            ("remove par filtre", json!({ "op": "remove", "path": format!("members[value eq \"{id}\"]") })),
            ("remove value objet members", json!({ "op": "remove", "value": { "members": [{ "value": id }] } })),
        ]
    }

    /// CE QU'IL TIENT : sous chacune des quatre formes de `remove`, l'id INCONNU et l'id d'un AUTRE tenant rendent la
    /// même réponse — statut ET corps — `200` ; aucun droit écrit ni retiré (droits bruts de TOUTE la plateforme
    /// relus), chaque demande comptée `-0` au journal.
    #[tokio::test]
    async fn psoe_retrait_d_un_inconnu_et_d_un_id_d_un_autre_tenant_meme_reponse() {
        let (st, _tmp, ids) = psoe_etat();
        let avant = psoe_droits(&st);
        let mut demandes = 0usize;
        for (forme_inconnu, forme_ailleurs) in psoe_formes_du_retrait(PSOE_INCONNU).into_iter().zip(psoe_formes_du_retrait(&ids.bert_ailleurs)) {
            let quoi = forme_inconnu.0;
            let inconnu = psoe_patch(&st, "editor", json!({ "Operations": [forme_inconnu.1] })).await;
            let ailleurs = psoe_patch(&st, "editor", json!({ "Operations": [forme_ailleurs.1] })).await;
            demandes += 2;
            assert_eq!(inconnu.0, StatusCode::OK, "{quoi} : le retrait d'un inconnu est un no-op : {:?}", inconnu.1);
            assert_eq!(ailleurs, inconnu, "{quoi} : l'id d'un autre tenant rend EXACTEMENT la réponse d'un inconnu");
            assert_eq!(psoe_droits(&st), avant, "{quoi} : aucun droit écrit ni retiré, nulle part");
        }
        assert_eq!(psoe_maillons(&st), vec!["role 'editor' +0/-0 membres".to_string(); demandes], "chaque no-op compté -0, rien de plus");
    }

    /// La demande mixte : un membre réel (carl), un id déjà retiré (dina), puis `absents`, sous trois formes de retrait.
    fn psoe_demande_mixte(carl: &str, dina: &str, absents: &[&str]) -> Value {
        let mut liste = vec![json!({ "value": carl }), json!({ "value": dina })];
        liste.extend(absents.iter().map(|a| json!({ "value": a })));
        let mut ops = vec![json!({ "op": "remove", "value": liste })];
        for a in absents {
            ops.push(json!({ "op": "remove", "path": format!("members[value eq \"{a}\"]") }));
            ops.push(json!({ "op": "remove", "value": { "members": [{ "value": a }] } }));
        }
        json!({ "Operations": ops })
    }

    /// CE QU'IL TIENT : une demande `[membre réel, id déjà retiré, id inconnu, id d'un autre tenant]` rend `200`, le
    /// membre réel est RETIRÉ (`-1` au journal), le droit de l'autre tenant et celui de l'administratrice sont
    /// intacts ; la même demande avec SEULEMENT l'inconnu, ou SEULEMENT l'id de l'autre tenant, rend un corps
    /// IDENTIQUE et le même état final.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `Z1_absent_refuse` (`400`, carl garde son droit),
    /// `Z1_reponse_differente_autre_tenant` (réponse distincte pour l'id de l'autre tenant).
    #[tokio::test]
    async fn psoe_demande_mixte_retire_le_membre_reel_et_tait_les_absents() {
        let mut reponses = Vec::new();
        for absents in [vec![PSOE_INCONNU, "AUTRE"], vec![PSOE_INCONNU], vec!["AUTRE"]] {
            let (st, _tmp, ids) = psoe_etat();
            let dina = ensure_platform_user(st.tenants.control.as_ref().expect("fixture : mode 1"), "psoe-dina").expect("fixture : utilisateur créé");
            let absents: Vec<&str> = absents.iter().map(|a| if *a == "AUTRE" { ids.bert_ailleurs.as_str() } else { *a }).collect();
            let quoi = format!("absents {absents:?}");
            // dina a été membre, puis retirée : l'IdP la renvoie encore dans la demande suivante.
            psoe_patch(&st, "editor", json!({ "Operations": [{ "op": "add", "value": [{ "value": dina }] }] })).await;
            let (statut, v) = psoe_patch(&st, "editor", json!({ "Operations": [{ "op": "remove", "value": [{ "value": dina }] }] })).await;
            assert_eq!(statut, StatusCode::OK, "fixture : dina retirée : {v}");
            let (statut, v) = psoe_patch(&st, "editor", psoe_demande_mixte(&ids.carl, &dina, &absents)).await;
            assert_eq!(statut, StatusCode::OK, "{quoi} : la demande mixte passe : {v}");
            let mut attendus = vec![
                (ids.anne.clone(), PSOE_TENANT.to_string(), "admin".to_string()),
                (ids.bert_ailleurs.clone(), PSOE_AUTRE_TENANT.to_string(), "editor".to_string()),
            ];
            attendus.sort();
            assert_eq!(psoe_droits(&st), attendus, "{quoi} : carl RÉVOQUÉ, le droit de l'autre tenant et celui d'anne intacts");
            assert_eq!(
                psoe_maillons(&st).last().map(String::as_str),
                Some("role 'editor' +0/-1 membres"),
                "{quoi} : seul le retrait écrit est compté"
            );
            reponses.push((quoi, statut, v));
        }
        assert_eq!(reponses[1].1, reponses[2].1, "même statut entre l'inconnu seul et l'id d'un autre tenant seul");
        assert_eq!(reponses[1].2, reponses[2].2, "corps IDENTIQUE entre l'inconnu seul et l'id d'un autre tenant seul");
        assert_eq!(reponses[0].2, reponses[1].2, "corps identique avec les deux absents ensemble");
    }

    /// CE QU'IL TIENT (contrôle positif) : le retrait d'un VRAI membre du rôle rend `200`, sa ligne seule part,
    /// `-1` au journal ; un membre du tenant sous un AUTRE rôle reste une cible valide (`200`, `-0`, rien touché :
    /// le jeton voit déjà les membres de son tenant) ; le retrait d'un `replace` (ici `remove path members` sans
    /// value, puis `replace` par l'ensemble vide) ne touche jamais le droit de l'autre tenant.
    #[tokio::test]
    async fn psoe_retrait_d_un_vrai_membre_passe_et_ne_touche_que_le_tenant_appelant() {
        let (st, _tmp, ids) = psoe_etat();
        let (statut, v) = psoe_patch(&st, "editor", json!({ "Operations": [{ "op": "remove", "value": [{ "value": ids.carl }] }] })).await;
        assert_eq!(statut, StatusCode::OK, "retrait d'un vrai membre : {v}");
        let attendus = |v: &[(&String, &str, &str)]| -> Vec<(String, String, String)> {
            let mut l: Vec<_> = v.iter().map(|(u, t, r)| (u.to_string(), t.to_string(), r.to_string())).collect();
            l.sort();
            l
        };
        assert_eq!(
            psoe_droits(&st),
            attendus(&[(&ids.anne, PSOE_TENANT, "admin"), (&ids.bert_ailleurs, PSOE_AUTRE_TENANT, "editor")]),
            "carl retiré, rien d'autre"
        );
        let (statut, v) = psoe_patch(&st, "editor", json!({ "Operations": [{ "op": "remove", "value": [{ "value": ids.anne }] }] })).await;
        assert_eq!(statut, StatusCode::OK, "membre du tenant sous un autre rôle : {v}");
        // Le retrait d'un replace : les porteurs sont lus dans le tenant appelant, le droit de bert (autre tenant) reste.
        for corps in [json!({ "Operations": [{ "op": "remove", "path": "members" }] }), json!({ "Operations": [{ "op": "replace", "path": "members", "value": [] }] })] {
            psoe_patch(&st, "editor", json!({ "Operations": [{ "op": "add", "value": [{ "value": ids.carl }] }] })).await;
            let (statut, v) = psoe_patch(&st, "editor", corps.clone()).await;
            assert_eq!(statut, StatusCode::OK, "{corps} : {v}");
            assert_eq!(
                psoe_droits(&st),
                attendus(&[(&ids.anne, PSOE_TENANT, "admin"), (&ids.bert_ailleurs, PSOE_AUTRE_TENANT, "editor")]),
                "{corps} : carl retiré du tenant appelant, le droit de l'autre tenant intact"
            );
        }
        assert_eq!(psoe_maillons(&st)[..2], ["role 'editor' +0/-1 membres".to_string(), "role 'editor' +0/-0 membres".to_string()], "chaque retrait compté tel qu'écrit");
    }

    /// Pose `nom` editor dans le tenant appelant ; rend son id.
    fn psoe_membre_editor(st: &AppState, nom: &str) -> String {
        let cp = st.tenants.control.as_ref().expect("fixture : mode 1");
        let id = ensure_platform_user(cp, nom).expect("fixture : utilisateur créé");
        cp.conn
            .lock()
            .execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,'editor')", params![id, PSOE_TENANT])
            .expect("fixture : droit posé");
        id
    }

    /// CE QU'IL TIENT : un id ABSENT listé AVANT le membre réel — inconnu, ou id d'un autre tenant, dans une liste
    /// `value` comme dans une liste `members` — ne retient pas sa révocation : `200`, carl RÉVOQUÉ, `-1` au journal,
    /// le droit de l'autre tenant intact.
    /// LA MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=Z1_coupe_au_premier_absent` — la lecture s'arrête à l'absent, carl
    /// garde son droit.
    #[tokio::test]
    async fn psoe_un_absent_liste_avant_le_membre_reel_ne_retient_pas_sa_revocation() {
        for (absent_est_ailleurs, en_members) in [(false, false), (true, false), (false, true), (true, true)] {
            let (st, _tmp, ids) = psoe_etat();
            let absent = if absent_est_ailleurs { ids.bert_ailleurs.clone() } else { PSOE_INCONNU.to_string() };
            let liste = json!([{ "value": absent }, { "value": ids.carl }]);
            let op = if en_members { json!({ "op": "remove", "value": { "members": liste } }) } else { json!({ "op": "remove", "value": liste }) };
            let quoi = format!("absent {absent} avant carl, forme members={en_members}");
            let (statut, v) = psoe_patch(&st, "editor", json!({ "Operations": [op] })).await;
            assert_eq!(statut, StatusCode::OK, "{quoi} : {v}");
            let mut attendus = vec![
                (ids.anne.clone(), PSOE_TENANT.to_string(), "admin".to_string()),
                (ids.bert_ailleurs.clone(), PSOE_AUTRE_TENANT.to_string(), "editor".to_string()),
            ];
            attendus.sort();
            assert_eq!(psoe_droits(&st), attendus, "{quoi} : carl RÉVOQUÉ malgré l'absent listé avant lui");
            assert_eq!(psoe_maillons(&st), vec!["role 'editor' +0/-1 membres".to_string()], "{quoi} : le retrait écrit est compté");
        }
    }

    /// CE QU'IL TIENT : une même opération `remove` qui liste DEUX membres réels (carl, dora) les révoque TOUS LES DEUX
    /// (`-2` au journal), seuls ou avec un absent intercalé entre eux ; anne et le droit de l'autre tenant intacts.
    /// LA MUTATION QUI LE FAIT ROUGIR : `VERIF_MUT=Z1_premier_present_seul` — dora garde son droit.
    #[tokio::test]
    async fn psoe_deux_membres_reels_d_une_meme_operation_sont_tous_deux_revoques() {
        for intercale in [None, Some(PSOE_INCONNU), Some("AUTRE")] {
            let (st, _tmp, ids) = psoe_etat();
            let dora = psoe_membre_editor(&st, "psoe-dora");
            let mut liste = vec![json!({ "value": ids.carl })];
            if let Some(a) = intercale {
                liste.push(json!({ "value": if a == "AUTRE" { ids.bert_ailleurs.as_str() } else { a } }));
            }
            liste.push(json!({ "value": dora }));
            let quoi = format!("intercalé {intercale:?}");
            let (statut, v) = psoe_patch(&st, "editor", json!({ "Operations": [{ "op": "remove", "value": liste }] })).await;
            assert_eq!(statut, StatusCode::OK, "{quoi} : {v}");
            let mut attendus = vec![
                (ids.anne.clone(), PSOE_TENANT.to_string(), "admin".to_string()),
                (ids.bert_ailleurs.clone(), PSOE_AUTRE_TENANT.to_string(), "editor".to_string()),
            ];
            attendus.sort();
            assert_eq!(psoe_droits(&st), attendus, "{quoi} : carl ET dora RÉVOQUÉS");
            assert_eq!(psoe_maillons(&st), vec!["role 'editor' +0/-2 membres".to_string()], "{quoi} : deux retraits écrits, comptés");
        }
    }
}
