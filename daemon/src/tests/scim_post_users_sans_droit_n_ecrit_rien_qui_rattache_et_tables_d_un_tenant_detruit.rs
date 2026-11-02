// =====================================================================================
// `P10.34-h` (restes) — `POST /Users` SANS DROIT DEMANDÉ N'ÉCRIT RIEN QUI RATTACHE ; CHAQUE TABLE DU PLAN DE CONTRÔLE QUI
// PORTE UN TENANT EST RETIRÉE (OU SCELLÉE) À SA DESTRUCTION ET À SA CRÉATION, LE JOURNAL DE CONTRÔLE EXCEPTÉ.
//
// CE QUE DISAIT L'ÉNONCÉ, ET CE QUI EN TIENT (mesuré sur e0fb779a) :
//  * « `POST /Users` sans groupes ne rejuge pas le rattachement » : vrai à la lettre, sans défaut. Le chemin juge UNE
//    fois, sous le verrou où il relit le jeton (`rbac::poser_l_identite_scim_conn`, daemon/src/scim.rs `scim_user_create`).
//    Ce qu'il écrit, par classe d'identité : nom ÉTRANGER (droit dans un autre tenant, provenance d'un autre tenant,
//    provenance scellée d'un tenant détruit) -> le `409` nommé des autres chemins, RIEN d'écrit ni d'attesté ; identité
//    RATTACHABLE existante -> ni droit, ni provenance, ni identité, seulement le maillon `scim.user.provision` ; nom neuf ->
//    l'identité et la provenance du tenant appelant. Le chemin avec droits rejuge parce qu'il ÉCRIT un droit : sans
//    rejugement, deux tenants porteraient chacun un droit, ce qu'aucun ordre en série n'autorise. Sans droit demandé,
//    rien n'est écrit : un `PATCH add` d'un autre tenant tombé après le jugement donne l'état que donne l'ordre en série
//    « ce `POST`, puis ce `PATCH` » — l'identité est à l'autre tenant, et le tenant appelant ne peut pas l'ajouter
//    (`noTarget` d'un inconnu). Un rejugement après le point de course contredirait l'atomicité voulue de `P10.34-q`
//    (`jsrv_post_relu_et_pose_sous_le_meme_verrou` : la demande est servie avant une destruction qui attend le verrou) ;
//  * « la destruction ne retire pas tout ce qui la rattache » : ne tenait plus. `P10.34-q` (vague AZ) retire dans UNE
//    transaction jetons SCIM, jetons d'agent, droits et ligne du tenant, et SCELLE la provenance sur `(tenant détruit)`
//    (`tenants::EFFACEMENTS_DE_LA_DESTRUCTION`, et `RESTES_SOUS_UN_IDENTIFIANT_DE_TENANT` à la création), témoins `sjpd_*`.
//    Ce qui manquait : un témoin de COMPLÉTUDE contre le schéma. Mesuré par `sqlite_master` : les tables qui portent une
//    colonne de tenant sont `"grant"`, `token`, `scim_token`, `scim_provenance` et `control_ledger` (plus `tenant`, par son
//    `id`). Seul le journal de contrôle garde ses lignes : en ajout seul, chaîné et signé par points de contrôle
//    (`P10.7-r`), en retirer un maillon casserait sa vérification et effacerait la trace de la destruction elle-même ; il
//    ne rattache aucune identité.
//
// CE QUE CES TÉMOINS TIENNENT, avec DEUX tenants réels :
//  * `POST /Users` du tenant 1, sans `groups` et avec un `groups` sans rôle connu, d'un nom étranger de chaque classe
//    (bert : droit dans le tenant 2 ; eve : créée par le SCIM du tenant 2 ; scellee : provenance scellée) : le `409` EN
//    ENTIER, et le plan de contrôle (identités, provenance, droits, journal de contrôle) identique avant et après ;
//  * d'une identité rattachable (vieux : d'avant la provenance ; fred : créé par le SCIM du tenant 1) : `201`, la
//    représentation EN ENTIER, identités, provenance et droits identiques, un seul maillon de plus, exact ;
//  * un droit posé à vieux dans le tenant 2 au point de course (ce que son `PATCH add` écrit) : rien n'est écrit qui
//    rattache vieux au tenant 1 (droits, provenance), et son `PATCH add` par le tenant 1 rend la réponse d'un id inconnu,
//    à l'octet — exactement l'état et les réponses de l'ordre en série, joué en contrôle ;
//  * chaque table du plan de contrôle qui porte un tenant, LUE DU SCHÉMA (jamais une liste du témoin), semée sous A et
//    sous B : après la destruction de A par la route, seules les lignes de A du journal de contrôle restent, chaque
//    ligne de B reste À L'IDENTIQUE — y compris celles des identités PARTAGÉES (un droit dans A et un dans B ; une
//    identité créée par le SCIM de B avec un droit dans A), qui restent rattachables à B —, une identité créée par le
//    SCIM de A n'est plus « provisionnée par A » (provenance scellée, étrangère à A) ; semée de nouveau sous A (restes
//    d'une version antérieure), la recréation de A par la route n'en hérite de rien et l'identité reste étrangère au A
//    recréé. Une table SANS colonne `tenant_id`/`tenant` n'est admise que JUGÉE, colonnes comprises (catalogue,
//    identités, rôles globaux, points du journal) : un tenant porté sous un autre nom de colonne fait rougir le témoin.
//
// MUTANTS (choisis par la variable de mutation sous `cfg!(test)`, retirés avant le commit), chacun vu ROUGE : BG5_etrangere_servie (un nom
// étranger servi par `poser_l_identite_scim_conn` sans droit demandé), BG5_revendique (une identité rattachable existante
// reçoit la provenance du tenant qui la sert : le chemin écrirait un rattachement) ; BG5_table_neuve (une table à colonne
// `tenant_id` ajoutée au plan de contrôle, `rbac::migrate_control_provenance_scim`), BG5_table_a_tenant_ref (même lieu,
// le tenant sous la colonne `tenant_ref`), BG5_colonne_tenant_ref_sur_role_def (même lieu, colonne `tenant_ref` ajoutée à
// une table jugée sans tenant), BG5_destruction_sans_droits (`tenants::tenant_destroy` saute l'effacement des droits),
// BG5_droits_retires_ailleurs (il retire les droits des membres de A dans TOUS les tenants), BG5_provenance_scellee_ailleurs
// (il scelle aussi la provenance, d'un autre tenant, des membres de A), BG5_creation_sans_jetons_d_agent
// (`tenants::tenant_provision` saute celui des jetons d'agent).
//
// CE QU'ILS NE TIENNENT PAS (NON TRANCHÉ, décision de l'exploitant attendue, `P10.34-h`) : une identité sans droit ni
// provenance (née avant la provenance, par `grant_set` ou la création d'un tenant, ou déprovisionnée partout) reste
// rattachable par TOUT tenant SCIM, et `POST /Users` de son nom sert son id (`rbac::lire_le_rattachement_scim`, dernier
// bras) — rien n'y est changé, et c'est par elle que le tenant appelant apprend l'id de vieux dans la course ci-dessus.
// Le temps de réponse n'est pas mesuré.
// =====================================================================================
mod scim_post_users_sans_droit_n_ecrit_rien_qui_rattache_et_tables_d_un_tenant_detruit {
    use super::*;
    use crate::handlers::transaction_validee::poser_un_crochet_de_course;

    const SPSR_TENANT: &str = "spsr-t1";
    const SPSR_AUTRE_TENANT: &str = "spsr-t2";
    const SPSR_INCONNU: &str = "pu_spsr_qui_n_existe_pas";
    const SPSR_A: &str = "spsr-a";
    const SPSR_NOM_A: &str = "SpsrA";
    const SPSR_B: &str = "spsr-b";
    const SPSR_NOM_B: &str = "SpsrB";
    /// Le tenant de provenance scellé, RECOPIÉ.
    const SPSR_TOMBE: &str = "(tenant détruit)";
    /// La seule table qui garde les lignes d'un tenant détruit, RECOPIÉE (journal en ajout seul, signé).
    const SPSR_JOURNAL: &str = "control_ledger";
    /// La marque des lignes semées par le témoin de complétude.
    const SPSR_SEME: &str = "spsr-seme";
    /// Un `groups` dont aucun rôle n'est connu : aucun droit demandé, comme sans `groups`.
    const SPSR_ROLE_INCONNU: &str = "spsr-role-inconnu";

    /// Le `409 uniqueness`, EN ENTIER, phrase recopiée (jamais lue de la production).
    fn spsr_unicite() -> Value {
        json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "scimType": "uniqueness",
            "detail": "userName déjà pris sur la plateforme par une identité que ce tenant ne peut pas rattacher : l'utilisateur n'est ni créé ni modifié, aucun droit n'est posé",
            "status": "409",
        })
    }

    /// La représentation d'une identité sans droit dans le tenant, EN ENTIER.
    fn spsr_representation_sans_droit(id: &str, nom: &str) -> Value {
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "id": id,
            "userName": nom,
            "active": false,
            "groups": [],
            "meta": { "resourceType": "User" }
        })
    }

    struct SpsrIds {
        vieux: String,
        fred: String,
    }

    /// Deux tenants catalogués. anne admin du tenant 1 ; bert editor du tenant 2 seulement ; vieux posé par
    /// `ensure_platform_user` (aucune provenance), sans droit ; eve créée par le `POST /Users` du tenant 2, sans droit ;
    /// fred créé par le `POST /Users` du tenant 1, sans droit ; scellee : provenance scellée d'un tenant détruit.
    async fn spsr_etat() -> (AppState, crate::tmp_possede::TmpDb, SpsrIds) {
        let (cp, tmp) = mk_test_control();
        for (id, nom) in [(SPSR_TENANT, "SPSR1"), (SPSR_AUTRE_TENANT, "SPSR2")] {
            cp.conn
                .lock()
                .execute("INSERT INTO tenant(id,name,key_ref,db_path,created,suspended) VALUES(?1,?2,'','sans-base',?3,0)", params![id, nom, now()])
                .expect("fixture : tenant catalogué");
        }
        let anne = ensure_platform_user(&cp, "spsr-anne").expect("fixture");
        let bert = ensure_platform_user(&cp, "spsr-bert").expect("fixture");
        let vieux = ensure_platform_user(&cp, "spsr-vieux").expect("fixture");
        let scellee = ensure_platform_user(&cp, "spsr-scellee").expect("fixture");
        {
            let c = cp.conn.lock();
            c.execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,'admin')", params![anne, SPSR_TENANT]).expect("fixture : droit");
            c.execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,'editor')", params![bert, SPSR_AUTRE_TENANT]).expect("fixture : droit");
            c.execute("INSERT INTO scim_provenance(user_id,tenant_id,created) VALUES(?1,?2,0)", params![scellee, SPSR_TOMBE]).expect("fixture : provenance scellée");
        }
        let st = tenant_test_state("admins", "editors", "supers", Some(cp));
        let (statut, corps) = spsr_post(&st, SPSR_AUTRE_TENANT, json!({ "userName": "spsr-eve" })).await;
        assert_eq!(statut, StatusCode::CREATED, "fixture : eve créée par le tenant 2 : {corps}");
        let (statut, corps) = spsr_post(&st, SPSR_TENANT, json!({ "userName": "spsr-fred" })).await;
        assert_eq!(statut, StatusCode::CREATED, "fixture : fred créé par le tenant 1 : {corps}");
        let fred = spsr_json(&corps)["id"].as_str().expect("id servi").to_string();
        (st, tmp, SpsrIds { vieux, fred })
    }

    fn spsr_plan(st: &AppState) -> &ControlPlane {
        st.tenants.control.as_ref().expect("fixture : mode 1")
    }

    fn spsr_cle_de_course(st: &AppState) -> String {
        format!("scim-identite-avant-ses-droits:{}", spsr_plan(st).db_path)
    }

    async fn spsr_brut(r: Response) -> (StatusCode, String) {
        let statut = r.status();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, String::from_utf8(b.to_vec()).expect("corps UTF-8"))
    }

    async fn spsr_post(st: &AppState, tenant: &str, corps: Value) -> (StatusCode, String) {
        spsr_brut(scim_user_create(State(st.clone()), Extension(ScimCtx { tenant: tenant.into() }), Json(corps)).await).await
    }

    async fn spsr_patch_add(st: &AppState, tenant: &str, id: &str) -> (StatusCode, String) {
        let corps = json!({ "Operations": [{ "op": "add", "value": [{ "value": id }] }] });
        spsr_brut(scim_group_patch(State(st.clone()), Extension(ScimCtx { tenant: tenant.into() }), Path("editor".to_string()), Json(corps)).await).await
    }

    fn spsr_json(corps: &str) -> Value {
        serde_json::from_str(corps).unwrap_or_else(|e| panic!("corps JSON ({e}) : {corps}"))
    }

    fn spsr_lignes(st: &AppState, sql: &str) -> Vec<String> {
        let c = spsr_plan(st).conn.lock();
        let mut s = c.prepare(sql).expect("fixture");
        let lus = s.query_map([], |r| r.get::<_, String>(0)).expect("fixture").collect::<Result<Vec<_>, _>>().expect("fixture : lisible");
        lus
    }

    fn spsr_droits_de(st: &AppState, id: &str) -> Vec<String> {
        spsr_lignes(st, "SELECT user_id || '|' || tenant_id || '|' || role FROM \"grant\" ORDER BY 1").into_iter().filter(|l| l.starts_with(&format!("{id}|"))).collect()
    }

    fn spsr_provenance_de(st: &AppState, id: &str) -> Vec<String> {
        spsr_lignes(st, "SELECT user_id || '|' || tenant_id FROM scim_provenance ORDER BY 1").into_iter().filter(|l| l.starts_with(&format!("{id}|"))).collect()
    }

    /// Ce qui rattache une identité à un tenant, plus les identités : identités, provenance, droits.
    fn spsr_rattachements(st: &AppState) -> Vec<String> {
        let mut tout = spsr_lignes(st, "SELECT 'platform_user|' || id || '|' || name FROM platform_user");
        tout.extend(spsr_lignes(st, "SELECT 'scim_provenance|' || user_id || '|' || tenant_id FROM scim_provenance"));
        tout.extend(spsr_lignes(st, "SELECT 'grant|' || user_id || '|' || tenant_id || '|' || role FROM \"grant\""));
        tout.sort();
        tout
    }

    fn spsr_journal(st: &AppState) -> Vec<String> {
        spsr_lignes(st, "SELECT kind || '|' || tenant || '|' || detail FROM control_ledger ORDER BY id")
    }

    /// `POST /Users` du tenant 1 d'un nom étranger, sans droit demandé : le `409` EN ENTIER, et le plan de contrôle
    /// (rattachements et journal de contrôle) identique avant et après.
    async fn spsr_jouer_un_nom_etranger(st: &AppState, quoi: &str, corps: Value) {
        let (avant, journal) = (spsr_rattachements(st), spsr_journal(st));
        let (statut, rendu) = spsr_post(st, SPSR_TENANT, corps).await;
        assert_eq!((statut, spsr_json(&rendu)), (StatusCode::CONFLICT, spsr_unicite()), "{quoi} : le 409 EN ENTIER");
        assert_eq!(spsr_rattachements(st), avant, "{quoi} : ni identité, ni provenance, ni droit écrit");
        assert_eq!(spsr_journal(st), journal, "{quoi} : rien n'est attesté");
    }

    /// CE QU'IL TIENT : `POST /Users` du tenant 1, SANS droit demandé (sans `groups`, et avec un `groups` dont aucun rôle
    /// n'est connu), d'un nom étranger de chaque classe — bert (droit dans le tenant 2), eve (créée par le SCIM du tenant
    /// 2), scellee (provenance scellée d'un tenant détruit) : le `409` nommé des autres chemins, EN ENTIER, rien d'écrit.
    /// LA MUTATION QUI LE FAIT ROUGIR : `BG5_etrangere_servie` (`201` avec l'id du compte étranger, maillon écrit).
    #[tokio::test]
    async fn spsr_post_sans_droit_d_un_nom_etranger_rend_409_et_n_ecrit_rien() {
        let (st, _tmp, _ids) = spsr_etat().await;
        spsr_jouer_un_nom_etranger(&st, "bert sans groups", json!({ "userName": "spsr-bert" })).await;
        spsr_jouer_un_nom_etranger(&st, "bert, groups sans rôle connu", json!({ "userName": "spsr-bert", "groups": [{ "value": SPSR_ROLE_INCONNU }] })).await;
        spsr_jouer_un_nom_etranger(&st, "eve sans groups", json!({ "userName": "spsr-eve" })).await;
        spsr_jouer_un_nom_etranger(&st, "eve, groups sans rôle connu", json!({ "userName": "spsr-eve", "groups": [{ "value": SPSR_ROLE_INCONNU }] })).await;
        spsr_jouer_un_nom_etranger(&st, "scellee sans groups", json!({ "userName": "spsr-scellee" })).await;
        spsr_jouer_un_nom_etranger(&st, "scellee, groups sans rôle connu", json!({ "userName": "spsr-scellee", "groups": [{ "value": SPSR_ROLE_INCONNU }] })).await;
    }

    /// `POST /Users` du tenant 1 d'une identité rattachable existante, sans droit demandé : `201`, la représentation EN
    /// ENTIER avec son id, rattachements identiques, un seul maillon de plus, exact.
    async fn spsr_jouer_une_identite_rattachable(st: &AppState, quoi: &str, id: &str, nom: &str) {
        let (avant, journal) = (spsr_rattachements(st), spsr_journal(st));
        let (statut, rendu) = spsr_post(st, SPSR_TENANT, json!({ "userName": nom })).await;
        assert_eq!((statut, spsr_json(&rendu)), (StatusCode::CREATED, spsr_representation_sans_droit(id, nom)), "{quoi} : 201 EN ENTIER");
        assert_eq!(spsr_rattachements(st), avant, "{quoi} : ni identité, ni provenance, ni droit écrit");
        let mut attendu = journal;
        attendu.push(format!("scim.user.provision|{SPSR_TENANT}|user '{nom}' (id={id}) grants=[]"));
        assert_eq!(spsr_journal(st), attendu, "{quoi} : un seul maillon de plus, exact");
    }

    /// CE QU'IL TIENT : `POST /Users` du tenant 1 sans `groups` de vieux (d'avant la provenance, sans droit) et de fred
    /// (créé par le SCIM du tenant 1) : servi, et RIEN n'est écrit qui les rattache — ni droit, ni provenance.
    /// LA MUTATION QUI LE FAIT ROUGIR : `BG5_revendique` (vieux reçoit la provenance du tenant 1).
    #[tokio::test]
    async fn spsr_post_sans_droit_d_une_identite_rattachable_n_ecrit_rien_qui_la_rattache() {
        let (st, _tmp, ids) = spsr_etat().await;
        spsr_jouer_une_identite_rattachable(&st, "vieux", &ids.vieux, "spsr-vieux").await;
        spsr_jouer_une_identite_rattachable(&st, "fred", &ids.fred, "spsr-fred").await;
    }

    /// CE QU'IL TIENT : au point de course de `POST /Users` sans droit demandé (jugement fait, verrou relâché), le droit
    /// que le `PATCH add` du tenant 2 écrit est posé à vieux. Le `POST` du tenant 1 rend `201` (son jugement précède ce
    /// droit), mais rien n'est écrit qui rattache vieux au tenant 1 : son seul droit est celui du tenant 2, aucune
    /// provenance ; le `PATCH add` de vieux par le tenant 1 rend la réponse d'un id inconnu, à l'octet. CONTRÔLE : l'ordre
    /// en série (`POST`, puis le droit du tenant 2, puis le `PATCH add`) sur un état neuf donne les mêmes réponses et le
    /// même état.
    /// LA MUTATION QUI LE FAIT ROUGIR : `BG5_revendique` (vieux reçoit la provenance du tenant 1 : le `PATCH add` du tenant
    /// 1 rend `200`, droits dans les deux tenants).
    #[tokio::test]
    async fn spsr_droit_pose_ailleurs_pendant_un_post_sans_droit_ne_rattache_rien_comme_en_serie() {
        let (st, _tmp, ids) = spsr_etat().await;
        let (plan, cible) = (spsr_plan(&st).clone(), ids.vieux.clone());
        poser_un_crochet_de_course(&spsr_cle_de_course(&st), move || {
            plan.conn
                .lock()
                .execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,'editor')", params![cible, SPSR_AUTRE_TENANT])
                .expect("crochet : droit posé par le tenant 2");
        });
        let post_en_course = spsr_post(&st, SPSR_TENANT, json!({ "userName": "spsr-vieux" })).await;
        assert_eq!((post_en_course.0, spsr_json(&post_en_course.1)), (StatusCode::CREATED, spsr_representation_sans_droit(&ids.vieux, "spsr-vieux")), "course : le POST");
        assert_eq!(spsr_droits_de(&st, &ids.vieux), vec![format!("{}|{SPSR_AUTRE_TENANT}|editor", ids.vieux)], "course : son seul droit est celui du tenant 2");
        assert_eq!(spsr_provenance_de(&st, &ids.vieux), Vec::<String>::new(), "course : aucune provenance");
        let inconnu = spsr_patch_add(&st, SPSR_TENANT, SPSR_INCONNU).await;
        assert_eq!(inconnu.0, StatusCode::BAD_REQUEST, "contrôle : l'id inconnu : {inconnu:?}");
        let patch_en_course = spsr_patch_add(&st, SPSR_TENANT, &ids.vieux).await;
        assert_eq!(patch_en_course, inconnu, "course : le PATCH add de vieux par le tenant 1 rend la réponse d'un id inconnu");
        assert_eq!(spsr_droits_de(&st, &ids.vieux), vec![format!("{}|{SPSR_AUTRE_TENANT}|editor", ids.vieux)], "course : toujours rien ici");
        let etat_en_course = (spsr_droits_de(&st, &ids.vieux), spsr_provenance_de(&st, &ids.vieux));

        let (st, _tmp2, ids2) = spsr_etat().await;
        let post_en_serie = spsr_post(&st, SPSR_TENANT, json!({ "userName": "spsr-vieux" })).await;
        spsr_plan(&st)
            .conn
            .lock()
            .execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,'editor')", params![ids2.vieux, SPSR_AUTRE_TENANT])
            .expect("contrôle : droit posé par le tenant 2");
        let patch_en_serie = spsr_patch_add(&st, SPSR_TENANT, &ids2.vieux).await;
        assert_eq!(
            (post_en_serie.0, spsr_json(&post_en_serie.1)),
            (StatusCode::CREATED, spsr_representation_sans_droit(&ids2.vieux, "spsr-vieux")),
            "contrôle en série : le POST"
        );
        assert_eq!(patch_en_serie, spsr_patch_add(&st, SPSR_TENANT, SPSR_INCONNU).await, "contrôle en série : le PATCH add rend la réponse d'un inconnu");
        let etat_en_serie = (spsr_droits_de(&st, &ids2.vieux), spsr_provenance_de(&st, &ids2.vieux));
        let renomme = |(d, p): (Vec<String>, Vec<String>), id: &str| -> (Vec<String>, Vec<String>) {
            (d.into_iter().map(|l| l.replacen(id, "<vieux>", 1)).collect(), p.into_iter().map(|l| l.replacen(id, "<vieux>", 1)).collect())
        };
        assert_eq!(renomme(etat_en_course, &ids.vieux), renomme(etat_en_serie, &ids2.vieux), "la course laisse l'état de l'ordre en série");
    }

    // ------------------------------------------------------------------ destruction et création, contre le schéma

    /// Une table du plan de contrôle qui porte un tenant : son nom, sa colonne de tenant, ses colonnes (nom, type).
    struct SpsrTablePortee {
        table: String,
        colonne: String,
        colonnes: Vec<(String, String)>,
    }

    /// Les tables du plan de contrôle JUGÉES sans colonne de tenant, avec leurs colonnes, RECOPIÉES du schéma
    /// (`state::migrate_control`, `state::migrate_control_points_de_controle`). Le jugement porte sur les colonnes : une
    /// table neuve, ou une colonne ajoutée à l'une d'elles, n'est plus jugée et le témoin rougit en la nommant — un
    /// tenant porté sous un autre nom (`tenant_ref`, `tid`) ne passe donc pas inaperçu.
    ///  * `tenant` : le catalogue, le tenant est sa clé `id` ; la destruction retire la ligne (mesuré par le témoin) ;
    ///  * `platform_user` : les identités, rattachées à un tenant par `"grant"` et `scim_provenance` seulement ;
    ///  * `role_def` : le catalogue global des rôles composables, géré par le super-admin ;
    ///  * `control_checkpoint` : les points signés du journal de contrôle, par maillon (`ledger_id`).
    const SPSR_TABLES_JUGEES_SANS_COLONNE_DE_TENANT: [(&str, &[&str]); 4] = [
        ("control_checkpoint", &["id", "ts", "ledger_id", "ledger_hash", "sig", "pubkey"]),
        ("platform_user", &["id", "name", "hash", "is_superadmin", "created"]),
        ("role_def", &["name", "base_role", "deny_perms", "description", "created"]),
        ("tenant", &["id", "name", "key_ref", "db_path", "created", "suspended"]),
    ];

    /// LUES DU SCHÉMA : chaque table de la base de contrôle qui a une colonne `tenant_id` ou `tenant`. Toute AUTRE table
    /// doit être jugée, colonnes comprises (`SPSR_TABLES_JUGEES_SANS_COLONNE_DE_TENANT`) : sinon le témoin rougit en la
    /// nommant.
    fn spsr_tables_portant_un_tenant(st: &AppState) -> Vec<SpsrTablePortee> {
        let noms = spsr_lignes(st, "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name");
        let c = spsr_plan(st).conn.lock();
        let (mut portees, mut non_jugees) = (Vec::new(), Vec::new());
        for table in noms {
            let mut s = c.prepare(&format!("PRAGMA table_info(\"{table}\")")).expect("instrument : table_info");
            let colonnes = s
                .query_map([], |r| Ok((r.get::<_, String>(1)?, r.get::<_, String>(2)?)))
                .expect("instrument")
                .collect::<Result<Vec<_>, _>>()
                .expect("instrument : colonnes lisibles");
            if let Some((colonne, _)) = colonnes.iter().find(|(n, _)| n == "tenant_id" || n == "tenant") {
                portees.push(SpsrTablePortee { table: table.clone(), colonne: colonne.clone(), colonnes: colonnes.clone() });
                continue;
            }
            let lues: Vec<&str> = colonnes.iter().map(|(n, _)| n.as_str()).collect();
            if !SPSR_TABLES_JUGEES_SANS_COLONNE_DE_TENANT.iter().any(|(t, cols)| *t == table && *cols == lues.as_slice()) {
                non_jugees.push(format!("{table}({})", lues.join(",")));
            }
        }
        assert_eq!(non_jugees, Vec::<String>::new(), "table du plan de contrôle sans colonne `tenant_id`/`tenant` et NON jugée (porte-t-elle un tenant ?)");
        portees
    }

    /// TOUTES les lignes de `table` sous `tenant` (colonne `colonne`), chaque valeur rendue, triées.
    fn spsr_lignes_sous(st: &AppState, table: &str, colonne: &str, tenant: &str) -> Vec<String> {
        let c = spsr_plan(st).conn.lock();
        let mut s = c.prepare(&format!("SELECT * FROM \"{table}\" WHERE \"{colonne}\"=?1")).expect("instrument");
        let n = s.column_count();
        let mut lus = s
            .query_map(params![tenant], |r| {
                (0..n).map(|i| r.get::<_, rusqlite::types::Value>(i).map(|v| format!("{v:?}"))).collect::<Result<Vec<_>, _>>().map(|v| v.join("|"))
            })
            .expect("instrument")
            .collect::<Result<Vec<_>, _>>()
            .expect("instrument : lignes lisibles");
        lus.sort();
        lus
    }

    /// Ce que le plan de contrôle porte de `tenant`, ligne par ligne : chaque table qui porte un tenant, et sa ligne du
    /// catalogue.
    fn spsr_tout_de(st: &AppState, portees: &[SpsrTablePortee], tenant: &str) -> Vec<(String, Vec<String>)> {
        let mut tout: Vec<(String, Vec<String>)> = portees.iter().map(|t| (t.table.clone(), spsr_lignes_sous(st, &t.table, &t.colonne, tenant))).collect();
        tout.push(("tenant".into(), spsr_lignes_sous(st, "tenant", "id", tenant)));
        tout
    }

    /// Sème UNE ligne sous `tenant` dans `t` : la colonne de tenant reçoit `tenant`, chaque autre colonne une valeur
    /// marquée `SPSR_SEME` (texte) ou `0` (entière).
    fn spsr_semer(st: &AppState, t: &SpsrTablePortee, tenant: &str, tour: &str) {
        let (mut noms, mut valeurs) = (Vec::new(), Vec::<rusqlite::types::Value>::new());
        for (nom, genre) in &t.colonnes {
            noms.push(format!("\"{nom}\""));
            valeurs.push(if *nom == t.colonne {
                tenant.to_string().into()
            } else if genre.to_ascii_uppercase().contains("INT") {
                0i64.into()
            } else {
                format!("{SPSR_SEME}-{}-{nom}-{tenant}-{tour}", t.table).into()
            });
        }
        let marques = (1..=valeurs.len()).map(|i| format!("?{i}")).collect::<Vec<_>>().join(",");
        spsr_plan(st)
            .conn
            .lock()
            .execute(&format!("INSERT INTO \"{}\"({}) VALUES({marques})", t.table, noms.join(",")), rusqlite::params_from_iter(valeurs))
            .unwrap_or_else(|e| panic!("fixture : ligne semée dans {} : {e}", t.table));
    }

    fn spsr_compter_sous(st: &AppState, t: &SpsrTablePortee, tenant: &str) -> i64 {
        spsr_plan(st)
            .conn
            .lock()
            .query_row(&format!("SELECT COUNT(*) FROM \"{}\" WHERE \"{}\"=?1", t.table, t.colonne), params![tenant], |r| r.get(0))
            .expect("instrument : compte lisible")
    }

    /// Les lignes SEMÉES (marque `SPSR_SEME`) encore sous `tenant` dans `t`.
    fn spsr_semees_sous(st: &AppState, t: &SpsrTablePortee, tenant: &str) -> i64 {
        let texte = t
            .colonnes
            .iter()
            .find(|(n, g)| *n != t.colonne && !g.to_ascii_uppercase().contains("INT"))
            .unwrap_or_else(|| panic!("instrument : {} n'a aucune colonne texte hors du tenant", t.table));
        spsr_plan(st)
            .conn
            .lock()
            .query_row(
                &format!("SELECT COUNT(*) FROM \"{}\" WHERE \"{}\"=?1 AND \"{}\" LIKE ?2", t.table, t.colonne, texte.0),
                params![tenant, format!("{SPSR_SEME}%")],
                |r| r.get(0),
            )
            .expect("instrument : compte lisible")
    }

    async fn spsr_corps(r: Response) -> (u16, Value) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        (statut, serde_json::from_slice(&b).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&b).into_owned())))
    }

    async fn spsr_creer(st: &AppState, id: &str, nom: &str) {
        let (statut, v) = spsr_corps(
            tenant_create(State(st.clone()), crate::secret_des_gestes::presente_de_test(), Extension(au_super("spsr-op")), Json(json!({ "id": id, "name": nom, "admin": format!("{id}-adm") }))).await,
        )
        .await;
        assert_eq!(statut, 201, "fixture : tenant {id} créé : {v}");
    }

    /// Les membres partagés de A et B, et leur état attendu hors de A : `(droits, provenance)` de chacun, ligne par ligne.
    fn spsr_partages_hors_de_a(st: &AppState, commun: &str, de_b: &str) -> Vec<(Vec<String>, Vec<String>)> {
        vec![(spsr_droits_de(st, commun), spsr_provenance_de(st, commun)), (spsr_droits_de(st, de_b), spsr_provenance_de(st, de_b))]
    }

    /// CE QU'IL TIENT : deux tenants réels (route `tenant_create`, bases chiffrées). Chaque table du plan de contrôle qui
    /// porte un tenant, LUE DU SCHÉMA (au moins les cinq mesurées ; toute autre table est jugée, colonnes comprises), est
    /// semée sous A et sous B, et z est créée par le `POST /Users` de A. Deux identités sont PARTAGÉES : commun a un droit
    /// dans A et un dans B ; de_b, créée par le `POST /Users` de B, a un droit dans B et un dans A (posé hors SCIM). Après
    /// `tenant_delete` de A (route) : l'ensemble des tables qui portent ENCORE une ligne de A est exactement
    /// `{control_ledger}` (journal en ajout seul, gardé, ses lignes de A comprises) ; chaque table garde chacune de ses
    /// lignes de B, À L'IDENTIQUE (contenu, pas un compte), la ligne de B du catalogue comprise ; commun et de_b gardent
    /// leur droit de B et de_b sa provenance de B, et restent rattachables à B ; z n'est plus provisionnée par A
    /// (provenance scellée) et lui est étrangère. Semées de nouveau sous A (restes d'une version antérieure), la
    /// recréation de A (route) n'en garde AUCUNE, ne touche aucune ligne de B ; z reste étrangère au A recréé.
    /// LES MUTATIONS QUI LE FONT ROUGIR : `BG5_table_neuve` (table neuve à `tenant_id` jamais retirée) ;
    /// `BG5_table_a_tenant_ref` (table neuve dont le tenant s'appelle `tenant_ref`) ; `BG5_colonne_tenant_ref_sur_role_def`
    /// (colonne `tenant_ref` ajoutée à une table jugée sans tenant) ; `BG5_destruction_sans_droits` (les droits semés de A
    /// restent) ; `BG5_droits_retires_ailleurs` (la destruction retire à chaque membre de A ses droits dans TOUS les
    /// tenants) ; `BG5_provenance_scellee_ailleurs` (elle scelle aussi la provenance des membres de A créés par un autre
    /// tenant) ; `BG5_creation_sans_jetons_d_agent` (le jeton d'agent semé sous A passe au A recréé).
    #[tokio::test]
    async fn spsr_chaque_table_qui_porte_un_tenant_est_retiree_a_sa_destruction_et_a_sa_recreation() {
        let _env = VERROU_ENV_PROCESSUS.read();
        let (st, _dir) = mk_mode1_state();
        spsr_creer(&st, SPSR_A, SPSR_NOM_A).await;
        spsr_creer(&st, SPSR_B, SPSR_NOM_B).await;
        let portees = spsr_tables_portant_un_tenant(&st);
        assert!(portees.len() >= 5, "plancher : au moins les cinq tables mesurées portent un tenant : {:?}", portees.iter().map(|t| &t.table).collect::<Vec<_>>());
        assert!(portees.iter().any(|t| t.table == SPSR_JOURNAL), "instrument : le journal de contrôle est lu du schéma");
        let a_semer: Vec<&SpsrTablePortee> = portees.iter().filter(|t| t.table != SPSR_JOURNAL).collect();
        assert!(a_semer.len() >= 4, "plancher : au moins quatre tables à semer");
        for t in &a_semer {
            spsr_semer(&st, t, SPSR_A, "avant");
            spsr_semer(&st, t, SPSR_B, "avant");
        }
        let (statut, rendu) = spsr_post(&st, SPSR_A, json!({ "userName": "spsr-z" })).await;
        assert_eq!(statut, StatusCode::CREATED, "fixture : z créée par le SCIM de A : {rendu}");
        let z = spsr_json(&rendu)["id"].as_str().expect("id servi").to_string();
        let (statut, rendu) = spsr_post(&st, SPSR_B, json!({ "userName": "spsr-de-b" })).await;
        assert_eq!(statut, StatusCode::CREATED, "fixture : de_b créée par le SCIM de B : {rendu}");
        let de_b = spsr_json(&rendu)["id"].as_str().expect("id servi").to_string();
        let commun = ensure_platform_user(spsr_plan(&st), "spsr-commun").expect("fixture : commun");
        {
            let c = spsr_plan(&st).conn.lock();
            for (qui, tenant, role) in [(&commun, SPSR_A, "editor"), (&commun, SPSR_B, "viewer"), (&de_b, SPSR_A, "editor"), (&de_b, SPSR_B, "viewer")] {
                c.execute("INSERT INTO \"grant\"(user_id,tenant_id,role) VALUES(?1,?2,?3)", params![qui, tenant, role]).expect("fixture : droit partagé");
            }
        }
        let partages_hors_de_a = vec![
            (vec![format!("{commun}|{SPSR_B}|viewer")], Vec::<String>::new()),
            (vec![format!("{de_b}|{SPSR_B}|viewer")], vec![format!("{de_b}|{SPSR_B}")]),
        ];
        let tout_de_b_avant = spsr_tout_de(&st, &portees, SPSR_B);
        assert!(tout_de_b_avant.iter().all(|(_, l)| !l.is_empty()), "fixture : chaque table porte au moins une ligne de B : {tout_de_b_avant:?}");
        let droits_de_b = &tout_de_b_avant.iter().find(|(t, _)| t == "grant").expect("droits lus").1;
        for qui in [&commun, &de_b] {
            assert!(droits_de_b.iter().any(|l| l.contains(qui.as_str())), "fixture : {qui} a sa ligne de B dans les droits");
        }
        let journal = portees.iter().find(|t| t.table == SPSR_JOURNAL).expect("journal");
        let journal_de_a_avant = spsr_compter_sous(&st, journal, SPSR_A);
        assert!(journal_de_a_avant >= 1, "fixture : la création de A est au journal de contrôle");

        let (statut, v) = spsr_corps(tenant_delete(State(st.clone()), Extension(au_super("spsr-op")), Path(SPSR_A.into()), Json(json!({ "confirm": SPSR_NOM_A }))).await).await;
        assert_eq!(statut, 200, "destruction confirmée : {v}");
        let restantes: Vec<&str> = portees.iter().filter(|t| spsr_compter_sous(&st, t, SPSR_A) > 0).map(|t| t.table.as_str()).collect();
        assert_eq!(restantes, vec![SPSR_JOURNAL], "après la destruction, seul le journal de contrôle porte encore A");
        assert_eq!(spsr_lignes_sous(&st, "tenant", "id", SPSR_A), Vec::<String>::new(), "la ligne de A est retirée du catalogue");
        assert!(spsr_compter_sous(&st, journal, SPSR_A) > journal_de_a_avant, "le journal de A est gardé, la destruction y est inscrite");
        assert_eq!(spsr_partages_hors_de_a(&st, &commun, &de_b), partages_hors_de_a, "commun et de_b gardent leurs lignes de B, et rien de A");
        assert_eq!(spsr_tout_de(&st, &portees, SPSR_B), tout_de_b_avant, "rien de B ne bouge, ligne par ligne");
        {
            let c = spsr_plan(&st).conn.lock();
            for qui in [&commun, &de_b] {
                assert_eq!(rattachement_scim_conn(&c, SPSR_B, qui).expect("lue"), Some(RattachementScim::Rattachable), "{qui} reste rattachable à B");
            }
            let provenance: String = c.query_row("SELECT tenant_id FROM scim_provenance WHERE user_id=?1", params![z], |r| r.get(0)).expect("provenance de z lue");
            assert_eq!(provenance, SPSR_TOMBE, "z n'est plus provisionnée par A : provenance scellée");
            assert_eq!(rattachement_scim_conn(&c, SPSR_A, &z).expect("lue"), Some(RattachementScim::Etrangere), "z étrangère à A détruit");
        }

        for t in &a_semer {
            spsr_semer(&st, t, SPSR_A, "reste");
        }
        spsr_creer(&st, SPSR_A, SPSR_NOM_A).await;
        let heritees: Vec<&str> = a_semer.iter().filter(|t| spsr_semees_sous(&st, t, SPSR_A) > 0).map(|t| t.table.as_str()).collect();
        assert_eq!(heritees, Vec::<&str>::new(), "le A recréé n'hérite d'aucune ligne restée sous son identifiant");
        assert_eq!(spsr_tout_de(&st, &portees, SPSR_B), tout_de_b_avant, "la recréation de A ne touche rien de B, ligne par ligne");
        assert_eq!(spsr_partages_hors_de_a(&st, &commun, &de_b), partages_hors_de_a, "la recréation de A ne rend rien à commun ni à de_b");
        let c = spsr_plan(&st).conn.lock();
        assert_eq!(rattachement_scim_conn(&c, SPSR_A, &z).expect("lue"), Some(RattachementScim::Etrangere), "z reste étrangère au A recréé");
    }
}
