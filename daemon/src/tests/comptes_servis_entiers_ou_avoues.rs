// =====================================================================================
// `P10.7-f` (rang 3) — LES CINQ COMPTES SERVIS COMME DES FAITS SONT ENTIERS OU AVOUÉS.
//
// LE DÉFAUT MESURÉ (garde de famille `check_a_truncated_list_is_never_served_as_a_complete_one.py`,
// relevé du 2026-09-16) : cinq sites de `daemon/src/handlers/` lisaient leur liste par un itérateur de
// lignes APLATI (`.map(|x| x.flatten().collect())`, `for … in rows.flatten()`). Un itérateur de lignes
// rusqlite rend des `Result` UNE LIGNE À LA FOIS : le mappeur peut échouer sur une seule ligne sans que
// la requête ait échoué — cache de schéma périmé qui rend « no such table » au PREMIER pas (famille
// mesurée dans `flatten-avale-no-such-table-au-premier-pas`), colonne ajoutée par une migration que la
// connexion qui sert ne voit pas encore, valeur corrompue. L'aplatissement jetait CETTE ligne-là et
// rendait la suite.
//
// POURQUOI LE RANG TROIS EST UN RANG À PART. Aux rangs un et deux, la ligne avalée MANQUAIT dans une
// liste : le lecteur pouvait, en principe, s'apercevoir qu'il ne trouvait pas ce qu'il cherchait. Ici,
// la ligne avalée FAUSSE UN NOMBRE que le corps AFFIRME, et un nombre ne se cherche pas : on le lit. Un
// recensement d'entités à risque amputé d'une ligne rend `total`, `over_threshold_total` et
// `over_threshold_hors_parc` PLUS PETITS, et la console les peint tels quels sur un panneau de posture.
// Une étape de réponse à incident avalée fait dire « 4 étapes sur 4 » d'une procédure qui en portait
// cinq — la progression MENT AVEC la liste, parce qu'elle en DÉRIVE (`steps.len()`). Un `env_id` avalé
// fait afficher « 0 event » sur un index géré, ou fait DISPARAÎTRE un index non géré de la vue qui
// pilote sa purge DESTRUCTIVE. Une politique d'index avalée fait relire son index « hérite du global »
// (`has_policy: false`, `retention_days: 0`), c'est-à-dire lui applique en lecture une rétention qui
// n'est pas la sienne. Et un dossier avalé de la liste de recalcul SLA garde son ANCIENNE échéance
// pendant que la route répond `204` = « tout recalculé ».
//
// LA RÈGLE QUE CE RANG APPLIQUE, ET ELLE EST DÉJÀ ÉCRITE DANS LE DÉPÔT : un compte dont une ligne n'a
// pas pu être lue est NON ÉTABLI, pas un entier plus petit. C'est le mot à mot de `liste_bornee`
// (`TotalBorne::en_json` : « `(null, null)` quand rien n'a été lu — jamais `(0, false)`, qui se lirait
// “registre vide, et c'est établi” »), et c'est la forme que le rang un a posée sur `netban.active` et
// `field-filters.matrix`.
//
// CE QUE CES TÉMOINS JOUENT, ET POURQUOI DEUX VOIES. La voie de la TABLE RETIRÉE (renommée sous les
// pieds du lecteur) fait échouer la PRÉPARATION. La voie de la LIGNE ILLISIBLE (un `BLOB` posé dans une
// colonne `TEXT` — SQLite conserve un blob tel quel quelle que soit l'affinité, et `get::<String>` le
// refuse) fait échouer le MAPPEUR sur UNE ligne, la requête restant saine : c'est LA voie que
// l'aplatissement avalait, et c'est elle qui tue la mutation. UNE EXCEPTION, MESURÉE ET DITE : la liste
// de recalcul SLA lit `incident.id`, qui est un `INTEGER PRIMARY KEY` — c'est-à-dire le `rowid`, que
// SQLite REFUSE de laisser porter un blob. Sa voie « ligne illisible » passe donc par une VUE TEMPORAIRE
// de même nom, qui OMBRE la table dans le schéma `temp` et projette un blob sous `id` : la requête reste
// rigoureusement la même et réussit, seul le mappeur échoue. Chaque témoin porte son CONTRÔLE POSITIF
// dans le même corps : sans lui, un aveu INCONDITIONNEL passerait pour un aveu.
//
// LA FORME DES CORRECTIFS EST CELLE DU DÉPÔT, PAS UNE FORME NEUVE.
//   * les deux corps JSON servis (`case_steps_json`, `index_policies_list`) passent par le fabricant
//     unique `liste_bornee::corps_de_liste_illisible` (`P10.7-z`) : la clé de liste EXISTE, VIDE, et
//     `error` porte `CAUSE_LISTE_ILLISIBLE`. Les valeurs DÉRIVÉES de la liste non lue deviennent
//     `null` (`progress`) ou `false` (`ok`), jamais un zéro rassurant ;
//   * le recensement du risque n'avait RIEN à inventer : sa branche d'échec existait déjà
//     (`TotalBorne::sans_lecture()` + deux `null`) et ne couvrait que la PRÉPARATION. Le solde en bloc
//     y fait simplement tomber aussi l'erreur de LIGNE ;
//   * `index_stats` rend désormais un `rusqlite::Result` — le geste que la garde nomme pour une lecture
//     qui ne sert aucun corps : rendre le `Result` à l'appelant, qui, lui, en a un ;
//   * le recalcul SLA avait DÉJÀ son vocabulaire d'aveu (`RecalculDesEcheances::manque`, « ce qui n'a
//     pas été fait se dit ») : la ligne illisible y entre par la porte existante, et `reponse_de_
//     l_upsert_sla` la sert en `200` + `{recomputed, reason}` au lieu d'un `204` muet.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS, ET C'EST DIT PLUTÔT QUE SOUS-ENTENDU :
//   * sur `risk_entities_page`, la LISTE `entities` reste amputée d'une ligne illisible. Elle est lue
//     par `liste_bornee::lire`, dont l'aplatissement est un ARBITRAGE ASSUMÉ inscrit dans l'ensemble
//     nommé de la garde (perdre la liste entière pour une ligne échangerait une troncature contre une
//     indisponibilité). Ce lot ferme le COMPTE, pas la ligne : `total` à `null` avertit que le rollup
//     n'a pas pu être compté, et c'est tout ce qu'il promet ;
//   * aucun de ces témoins ne juge ce que la CONSOLE peint de ces aveux — cela se juge dans
//     `check_a_refusal_is_not_rendered_as_an_absence.py`. Mesuré en chemin : `web/risk.js` lit DÉJÀ les
//     deux comptes non établis et écrit « n'ont PAS pu être comptées — ce n'est pas un compte nul » ;
//     `web/cases.js:779` retombe sur `{total:0,done:0,skipped:0}` quand `progress` est `null` et
//     `web/index_policies.js:43` peint « aucun index » sur une liste vide : ces deux-là sont SOURDS ;
//   * la route `POST /api/sla-policies` n'est pas jouée ici de bout en bout — son corps est jugé par le
//     fabricant de réponse PUR (`reponse_de_l_upsert_sla`), qui est exactement ce que le handler appelle.
// =====================================================================================

/// L'état file-backed de ce rang. MÊME fixture que les rangs un et deux (`sp_state`) : trois fixtures
/// jumelles vieilliraient séparément. Seule la route des index a besoin d'un `AppState` ici — les
/// quatre autres sites sont des fonctions PURES sur `&Connection`.
fn lcs_etat(tag: &str) -> (AppState, AuthUser, crate::tmp_possede::TmpDb) {
    let (st, p) = sp_state(&format!("lcs-{tag}"));
    (st, sp_au("adm", "admin"), p)
}

/// VRAI si AUCUN des quatre chiffres du recensement n'est servi comme un fait. Écrit une fois : les
/// quatre tombent ENSEMBLE ou le correctif est faux, et un témoin qui n'en regarderait que trois
/// laisserait le quatrième être servi plus petit.
fn lcs_juger_le_recensement_non_etabli(page: &Value) {
    for cle in ["total", "total_capped", "over_threshold_total", "over_threshold_hors_parc"] {
        assert!(
            page.as_object().map(|o| o.contains_key(cle)).unwrap_or(false),
            "la clé `{cle}` doit RESTER dans le corps — un aveu qui retire la clé casse le lecteur : {page}"
        );
        assert!(
            page[cle].is_null(),
            "recensement non lu : `{cle}` doit être `null`, jamais un entier plus petit servi comme un fait : {page}"
        );
    }
}

// -------------------------------------------------------------------------------------
// (1) LE RECENSEMENT DES ENTITÉS À RISQUE — TROIS COMPTEURS, UNE SEULE LIGNE POUR LES FAUSSER
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `risk_entities_page` sert les trois chiffres du recensement quand il a pu le lire
/// (total, au-dessus du seuil, hors parc — comptés, et le `hors parc` discriminant) ; une LIGNE dont le
/// mappeur échoue les fait tomber TOUS LES QUATRE à `null`, et une table retirée y ajoute l'aveu du
/// fabricant de liste (`entities: []` + `error`). Le point dur est la ligne illisible : le `.ok()` qui
/// vivait déjà là couvrait la PRÉPARATION et l'EXÉCUTION, JAMAIS la ligne — mesuré, et c'est
/// précisément pour ça que des nombres FAUX pouvaient être servis sous un 200 sans une clé qui en
/// avertisse. Ils sont QUATRE et non trois : `total_capped` tombe avec eux, parce qu'un `false` s'y
/// lirait « le registre n'est pas plafonné, et c'est établi ».
///
/// CE QU'IL NE TIENT PAS : la LISTE `entities` reste amputée sur la voie de la ligne illisible — elle
/// passe par `liste_bornee::lire`, arbitrage ASSUMÉ de l'ensemble nommé. Le témoin l'ASSERTE plutôt que
/// de le taire : servies == 2 alors que le rollup en porte 3. Ce que ce lot ferme, c'est que ce 2-là ne
/// soit plus accompagné d'un `total: 2` qui le CONFIRMERAIT.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.map(|rows| rows.flatten().collect::<Vec<_>>())` à la
/// place du solde en bloc — le recensement redevient `(2, 2, 1)` sur trois lignes, et les quatre
/// asserts de `lcs_juger_le_recensement_non_etabli` tombent d'un coup.
#[test]
fn p10_7f_comptes_servis_le_recensement_des_entites_a_risque_est_entier_ou_avoue() {
    let conn = test_db();
    rd_entite(&conn, "host", "srv-a", 500);
    rd_entite(&conn, "host", "srv-retire", 500);
    rd_declare(&conn, "srv-retire", "retire");

    // CONTRÔLE POSITIF : les trois chiffres sont établis, et le troisième DISCRIMINE (1 sur 2).
    let nominal = risk_entities_page(&conn, 100, 3, 50);
    assert_eq!(rd_servies(&nominal), 2, "contrôle positif : les deux entités sont servies : {nominal}");
    assert_eq!(nominal["total"], json!(2), "contrôle positif : le recensement a été lu : {nominal}");
    assert_eq!(nominal["total_capped"], json!(false));
    assert_eq!(nominal["over_threshold_total"], json!(2), "contrôle positif : les deux franchissent le seuil : {nominal}");
    assert_eq!(nominal["over_threshold_hors_parc"], json!(1), "contrôle positif : une seule est déclarée hors parc : {nominal}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET — un aveu inconditionnel n'est pas un aveu : {nominal}");

    // UNE LIGNE ILLISIBLE : `entity_type` porte un BLOB, que `get::<String>` refuse. La requête est saine.
    conn.execute(
        "INSERT INTO risk_rollup(entity_type,entity,env_id,score,contrib,distinct_tactics,tactics,score_hot,contrib_hot,max_severity,first_ts,last_ts,updated) \
         VALUES(x'FF','srv-illisible','prod',500,1,1,'TA0001',0,0,3,10,20,20)",
        [],
    )
    .expect("fixture : la ligne illisible est écrite");
    let avoue = risk_entities_page(&conn, 100, 3, 50);
    lcs_juger_le_recensement_non_etabli(&avoue);
    assert_eq!(
        rd_servies(&avoue),
        2,
        "RÉSERVE ASSUMÉE, ASSERTÉE PLUTÔT QUE TUE : la LISTE reste amputée (arbitrage de `liste_bornee::lire`, \
         inscrit dans l'ensemble nommé de la garde). Ce lot ferme le COMPTE, pas la ligne : {avoue}"
    );

    // LA TABLE RETIRÉE : la préparation échoue des DEUX côtés — la liste avoue par son fabricant, et le
    // recensement reste non établi. Aucune des deux moitiés ne se rattrape sur l'autre.
    lcs_retirer_la_table_conn(&conn, "risk_rollup");
    let sans_table = risk_entities_page(&conn, 100, 3, 50);
    lsa_juger_l_aveu(&sans_table, "entities");
    lcs_juger_le_recensement_non_etabli(&sans_table);
}

// -------------------------------------------------------------------------------------
// (2) LA PROGRESSION D'UN CASE — LE COMPTE QUI MENT AVEC SA LISTE
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `case_steps_json` sert les trois étapes et la progression qui en DÉRIVE (3 au total,
/// 1 faite, 1 ignorée) ; une étape dont le mappeur échoue, ou une table retirée, rendent `steps` NON
/// ÉTABLIE (`[]` + `error`) et `progress` à `null` — jamais `{total:0,done:0,skipped:0}`, qui se lirait
/// « ce case n'a aucune étape, et c'est établi » et, pire, « 0 sur 0 = rien ne reste à faire ».
///
/// CE QU'IL TIENT AUSSI : `runbook` vient d'une AUTRE lecture et reste servi sous l'aveu de la ligne
/// illisible — un aveu qui couvrirait tout ne couvrirait rien. Sur la table retirée, il tombe à `null`
/// parce que cette lecture-là lit la MÊME table, et le témoin le distingue au lieu de le confondre.
///
/// CE QU'IL NE TIENT PAS : il ne joue pas `case_step_set` ni la résolution de gabarit `search` ; et il
/// ne dit rien de ce que la console peint (`web/cases.js:779` retombe sur `0/0` sur un `progress` nul —
/// elle est SOURDE, et c'est le lot suivant).
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.map(|x| x.flatten().collect()).unwrap_or_default()` —
/// le corps redevient `{"steps": [<deux étapes sur trois>], "progress": {"total": 2, …}}` sans `error`,
/// et les asserts de l'aveu comme celui de `progress` nul tombent.
#[test]
fn p10_7f_comptes_servis_la_progression_dun_case_ne_ment_plus_avec_sa_liste() {
    let conn = test_db();
    let (cas, rb) = lcs_case_avec_trois_etapes(&conn);

    // CONTRÔLE POSITIF : la liste ET le compte qui en dérive.
    let nominal = case_steps_json(&conn, cas);
    assert_eq!(nominal["steps"].as_array().map(Vec::len), Some(3), "contrôle positif : les trois étapes : {nominal}");
    assert_eq!(nominal["progress"]["total"], json!(3), "contrôle positif : le dénominateur est la liste : {nominal}");
    assert_eq!(nominal["progress"]["done"], json!(1));
    assert_eq!(nominal["progress"]["skipped"], json!(1));
    assert!(!nominal["runbook"].is_null(), "contrôle positif : le runbook attaché est servi : {nominal}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET : {nominal}");

    // UNE ÉTAPE ILLISIBLE : `phase` porte un BLOB. AVANT, elle disparaissait de `steps` ET du
    // dénominateur — « 2 étapes sur 2 » au-dessus d'une procédure qui en porte trois.
    conn.execute(
        "INSERT INTO case_step(incident_id,runbook_id,step_id,ordinal,phase,title,status) VALUES(?1,?2,99,9,x'FF','étape illisible','pending')",
        params![cas, rb],
    )
    .expect("fixture : l'étape illisible est écrite");
    let avoue = case_steps_json(&conn, cas);
    lsa_juger_l_aveu(&avoue, "steps");
    assert!(
        avoue.as_object().map(|o| o.contains_key("progress")).unwrap_or(false) && avoue["progress"].is_null(),
        "une progression DÉRIVÉE d'une liste non lue est `null`, jamais `0/0` : {avoue}"
    );
    assert_eq!(avoue["runbook"], nominal["runbook"], "l'autre lecture a abouti : elle reste servie telle quelle : {avoue}");

    // LA TABLE RETIRÉE : la préparation échoue, et la lecture du runbook attaché aussi (même table).
    lcs_retirer_la_table_conn(&conn, "case_step");
    let sans_table = case_steps_json(&conn, cas);
    lsa_juger_l_aveu(&sans_table, "steps");
    assert!(sans_table["progress"].is_null(), "table retirée : la progression n'est pas `0/0` : {sans_table}");
}

// -------------------------------------------------------------------------------------
// (3) LES STATISTIQUES PAR INDEX — UN `env_id` AVALÉ FAIT DISPARAÎTRE UN INDEX ENTIER
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : `index_policies_list` sert les deux index — celui qui a une politique et celui qui
/// n'en a pas —, chacun avec son volume compté ; une ligne d'`event_rollup` dont le mappeur échoue, ou
/// la table retirée, rendent `indexes` NON ÉTABLIE (`[]` + `error`) et `ok` retombé à `false`.
///
/// POURQUOI CE SITE EST LE PLUS DANGEREUX DES DEUX DE CE FICHIER : la liste des index NON GÉRÉS est
/// DÉRIVÉE DES CLÉS de cette map. Une seule ligne avalée ne faisait donc pas afficher un chiffre faux —
/// elle faisait DISPARAÎTRE un index entier de la vue qui pilote sa purge, sans un mot. Le témoin
/// vérifie les deux moitiés du défaut : aucun « 0 event » établi, et aucun index escamoté.
///
/// CE QU'IL NE TIENT PAS : il ne joue ni la borne `MAX_UNMANAGED_SHOWN` ni les mutations CRUD de
/// politiques ; et `web/index_policies.js:43` ne lit pas `error` — il peint « aucun index ».
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `for … in rows.flatten()` dans `index_stats` — la route
/// rend 200, `ok: true`, et une liste d'index AMPUTÉE d'un index, sans `error`.
#[tokio::test]
async fn p10_7f_comptes_servis_les_statistiques_dindex_sont_entieres_ou_avouees() {
    let (st, au, _p) = lcs_etat("index-stats");
    lcs_semer_les_index(&st);

    // CONTRÔLE POSITIF : deux index servis, le géré avec sa politique, le non géré avec son volume.
    let (statut, nominal) = lsa_corps(index_policies_list(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200);
    assert_eq!(nominal["ok"], json!(true), "contrôle positif : les deux lectures ont abouti : {nominal}");
    assert_eq!(nominal["indexes"].as_array().map(Vec::len), Some(2), "contrôle positif : `prod` (géré) et `lab` (non géré) : {nominal}");
    assert_eq!(lcs_index(&nominal, "lab")["events"], json!(3), "contrôle positif : le volume de l'index NON GÉRÉ est compté : {nominal}");
    assert!(nominal.get("error").is_none(), "chemin nominal MUET : {nominal}");

    // UNE LIGNE ILLISIBLE : `event_rollup.env_id` porte un BLOB. AVANT, cette ligne sortait de la map,
    // et l'index qu'elle décrit sortait de la LISTE.
    lsa_ecrire(
        &st,
        "INSERT INTO event_rollup(bucket,source,severity,action,src_ip,host,n,last_ts,env_id) VALUES(300,'s',1,'a','','',7,350,x'FF');",
    );
    let (statut, avoue) = lsa_corps(index_policies_list(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200, "la forme du dépôt pour une liste JSON est `error` DANS le corps, pas un refus HTTP");
    lsa_juger_l_aveu(&avoue, "indexes");
    assert_eq!(avoue["ok"], json!(false), "un inventaire NON LU ne se sert pas avec `ok: true` : {avoue}");
    lcs_aucun_fait_dindex(&avoue);

    // LA TABLE RETIRÉE : la préparation échoue.
    lsa_retirer_la_table(&st, "event_rollup");
    let (_, sans_table) = lsa_corps(index_policies_list(State(st.clone()), Extension(au.clone())).await).await;
    lsa_juger_l_aveu(&sans_table, "indexes");
    assert_eq!(sans_table["ok"], json!(false), "table retirée : `ok` retombe aussi : {sans_table}");
}

// -------------------------------------------------------------------------------------
// (4) LES POLITIQUES D'INDEX — UNE POLITIQUE PERDUE SE RELIT « HÉRITE DU GLOBAL »
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT : la seconde lecture du même corps avoue elle aussi. Le défaut propre à ce site n'est
/// pas une ligne en moins : c'est qu'une politique avalée sortait de `managed_names`, donc son index se
/// réaffichait par l'AUTRE branche d'`index_json` — `has_policy: false`, `retention_days: 0`,
/// c'est-à-dire « cet index hérite du global ». Une politique de rétention perdue se lisait comme une
/// rétention globale APPLIQUÉE, sur la vue qui pilote une purge destructive.
///
/// CE QU'IL NE TIENT PAS : il ne juge pas la purge elle-même (`retention_apply_caps` a ses témoins), ni
/// la validation d'écriture d'une politique.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `for … in rows.flatten()` sur la lecture d'`index_policy`
/// — la route rend 200 et sert `prod` avec `has_policy: false`, la phrase exacte que ce témoin refuse.
#[tokio::test]
async fn p10_7f_comptes_servis_les_politiques_dindex_sont_entieres_ou_avouees() {
    let (st, au, _p) = lcs_etat("index-policies");
    lcs_semer_les_index(&st);

    // CONTRÔLE POSITIF : `prod` PORTE sa politique — c'est exactement la phrase que l'aveu doit empêcher
    // de basculer en silence.
    let (_, nominal) = lsa_corps(index_policies_list(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(lcs_index(&nominal, "prod")["has_policy"], json!(true), "contrôle positif : la politique est lue : {nominal}");
    assert_eq!(lcs_index(&nominal, "prod")["retention_days"], json!(30), "contrôle positif : sa rétention propre, pas le global : {nominal}");
    assert_eq!(lcs_index(&nominal, "lab")["has_policy"], json!(false), "contrôle positif : `lab` hérite VRAIMENT du global : {nominal}");

    // UNE LIGNE ILLISIBLE : `index_policy.name` porte un BLOB.
    lsa_ecrire(&st, "INSERT INTO index_policy(name,retention_days,max_rows,max_bytes,description,enabled,managed) VALUES(x'FF',90,0,0,'',1,1);");
    let (statut, avoue) = lsa_corps(index_policies_list(State(st.clone()), Extension(au.clone())).await).await;
    assert_eq!(statut, 200);
    lsa_juger_l_aveu(&avoue, "indexes");
    assert_eq!(avoue["ok"], json!(false), "un inventaire NON LU ne se sert pas avec `ok: true` : {avoue}");
    lcs_aucun_fait_dindex(&avoue);

    // LA TABLE RETIRÉE.
    lsa_retirer_la_table(&st, "index_policy");
    let (_, sans_table) = lsa_corps(index_policies_list(State(st.clone()), Extension(au.clone())).await).await;
    lsa_juger_l_aveu(&sans_table, "indexes");
    lcs_aucun_fait_dindex(&sans_table);
}

// -------------------------------------------------------------------------------------
// (5) LE RECALCUL D'ÉCHÉANCES SLA — LA SEULE LECTURE DU RANG QUI NE SERT AUCUN CORPS
// -------------------------------------------------------------------------------------

/// CE QU'IL TIENT, EN TROIS FAITS : sur une ligne de la liste de travail qui ne se décode pas,
/// `sla_recalcule_la_priorite_bornee` (1) ne recalcule RIEN — aucune échéance n'est posée, donc rien
/// n'est marqué « recalculé » pour un dossier qu'on n'a pas lu ; (2) porte la raison dans `manque`, et
/// c'est « ILLISIBLE », jamais « plafond » (une seule des deux se répare en augmentant la borne) ; et
/// (3) la réponse SERVIE par `reponse_de_l_upsert_sla` est un `200` + `{recomputed: 0, reason: …}` —
/// jamais le `204` muet qui dit « tout recalculé », qui était le mensonge exact de ce site.
///
/// LE GESTE DE LA LIGNE ILLISIBLE, ET POURQUOI IL N'EST PAS UN BLOB DANS UNE COLONNE TEXTE : la lecture
/// ne projette que `incident.id`, un `INTEGER PRIMARY KEY` — le `rowid`, que SQLite refuse de laisser
/// porter un blob (l'insertion serait rejetée, donc le défaut serait INJOUABLE). Une VUE TEMPORAIRE de
/// même nom OMBRE la table dans le schéma `temp` et projette `x'FF'` sous `id` : l'énoncé servi est
/// inchangé, `prepare` et `query_map` réussissent, et seul le mappeur échoue — exactement la voie que
/// l'aplatissement avalait.
///
/// CE QU'IL NE TIENT PAS : il ne joue pas la route `POST /api/sla-policies` de bout en bout (elle exige
/// un `AppState` et le `with_write` ; le corps est jugé par le fabricant PUR que le handler appelle), et
/// il ne rejoue pas la borne ni la table absente — `ce_qui_n_a_pas_ete_fait_se_dit.rs:68-141` les tient
/// déjà, et ce témoin-ci ferme le TROISIÈME trou de la même fonction, pas les deux premiers.
///
/// LA MUTATION QUI LE FERAIT ROUGIR : rétablir `.map(|x| x.flatten().collect())` — la lecture rend une
/// liste VIDE (les deux lignes étant illisibles), `manque` reste `None`, `complet()` devient vrai, et la
/// réponse redevient un `204` : les trois faits tombent ensemble.
#[test]
fn p10_7f_comptes_servis_le_recalcul_decheances_dit_le_dossier_non_lu() {
    // CONTRÔLE POSITIF : deux dossiers actifs, recalculés, et la route reste MUETTE (204).
    let temoin = test_db();
    let ids = trois_cases_actifs(&temoin, 2, 2);
    let nominal = sla_recalcule_la_priorite_bornee(&temoin, 2, 10);
    assert_eq!(nominal.recalcules, 2, "contrôle positif : les deux dossiers sont recalculés");
    assert!(nominal.complet(), "contrôle positif : rien à avouer : {:?}", nominal.manque);
    for id in &ids {
        assert!(echeance_de(&temoin, *id).is_some(), "contrôle positif : l'échéance du case #{id} est POSÉE");
    }
    assert_eq!(
        reponse_de_l_upsert_sla(Ok(()), &nominal).status(),
        StatusCode::NO_CONTENT,
        "contrôle positif : le chemin nominal reste un 204 SANS CORPS — un aveu inconditionnel ne vaudrait rien"
    );

    // UNE LIGNE ILLISIBLE : la vue temporaire ombre `incident` et projette un blob sous `id`.
    let conn = test_db();
    let ids = trois_cases_actifs(&conn, 2, 2);
    conn.execute_batch(
        "CREATE TEMP VIEW incident AS SELECT x'FF' AS id, priority, merged_into, status FROM main.incident;",
    )
    .expect("fixture : la vue temporaire ombre la table");
    let r = sla_recalcule_la_priorite_bornee(&conn, 2, 10);

    assert_eq!(r.recalcules, 0, "AUCUN dossier n'est marqué recalculé quand un dossier n'a pas été lu");
    assert!(!r.complet(), "la route ne doit PAS pouvoir répondre « fait »");
    let raison = r.manque.clone().expect("une raison est portée");
    assert!(raison.contains("ILLISIBLE"), "la raison dit que la liste des dossiers n'a pas été lue : {raison}");
    assert!(!raison.contains("plafond"), "et surtout PAS le plafond — une seule des deux se répare en l'augmentant : {raison}");
    conn.execute_batch("DROP VIEW temp.incident;").expect("la vue est retirée");
    for id in &ids {
        assert_eq!(echeance_de(&conn, *id), None, "case #{id} : son échéance n'a PAS été touchée, et la réponse le dit");
    }

    // CE QUE LE CLIENT REÇOIT : un 200 qui PARLE, jamais le 204 qui dit « tout recalculé ».
    let servi = reponse_de_l_upsert_sla(Ok(()), &r);
    assert_eq!(servi.status(), StatusCode::OK, "politique posée, recalcul INCOMPLET : 200 + corps, ni 204 ni 5xx");
}

// -------------------------------------------------------------------------------------
// LES AIDES DE CE RANG — écrites après les témoins qu'elles servent, jamais recopiées d'un autre rang.
// -------------------------------------------------------------------------------------

/// Retire une table sous les pieds d'une lecture PURE (les quatre sites hors route n'ont pas
/// d'`AppState` : la sœur `lsa_retirer_la_table` prend l'écrivain de l'état, celle-ci la connexion).
fn lcs_retirer_la_table_conn(conn: &Connection, table: &str) {
    conn.execute_batch(&format!("ALTER TABLE {table} RENAME TO {table}_hors_d_atteinte;"))
        .unwrap_or_else(|e| panic!("fixture : la table `{table}` doit pouvoir être retirée ({e})"));
}

/// Un case porteur de TROIS étapes du même runbook (une faite, une ignorée, une en attente) : la
/// progression a alors trois valeurs DISTINCTES à servir, sans quoi un compte faux passerait inaperçu.
/// Le runbook est ÉCRIT ICI plutôt que cueilli par `pick_runbook_id` — mesuré : la chaîne de migrations
/// ne sème aucun runbook de repli `'*'` sur une base neuve, et un témoin qui dépendrait d'une semence
/// absente rougirait pour une raison ÉTRANGÈRE à ce qu'il prétend tenir. Rend `(case, runbook)`.
fn lcs_case_avec_trois_etapes(conn: &Connection) -> (i64, i64) {
    conn.execute(
        "INSERT INTO runbook(key,name,match_kind,match_key,description,managed,active,created) \
         VALUES('temoin-rang-3','Runbook du témoin','*','','procédure du témoin',0,1,1000)",
        [],
    )
    .expect("fixture : le runbook est écrit");
    let rb = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO incident(ts,updated,title,status,severity,priority) VALUES(1000,1000,'case de témoin','open',2,2)",
        [],
    )
    .expect("fixture : le case est écrit");
    let cas = conn.last_insert_rowid();
    for (ordinal, phase, statut) in [(1, "contain", "done"), (2, "eradicate", "skipped"), (3, "recover", "pending")] {
        conn.execute(
            "INSERT INTO case_step(incident_id,runbook_id,step_id,ordinal,phase,title,status) VALUES(?1,?2,?3,?3,?4,?5,?6)",
            params![cas, rb, ordinal, phase, format!("étape {ordinal}"), statut],
        )
        .expect("fixture : l'étape est écrite");
    }
    (cas, rb)
}

/// DEUX index : `prod` avec sa politique de rétention propre, `lab` sans politique (il hérite du
/// global). Les deux portent du volume — sans quoi un « 0 event » avalé ne se distinguerait de rien.
fn lcs_semer_les_index(st: &AppState) {
    lsa_ecrire(
        st,
        "INSERT INTO event_rollup(bucket,source,severity,action,src_ip,host,n,last_ts,env_id) VALUES(100,'agent',1,'a','','',5,150,'prod');\
         INSERT INTO event_rollup(bucket,source,severity,action,src_ip,host,n,last_ts,env_id) VALUES(200,'agent',1,'a','','',3,250,'lab');\
         INSERT INTO index_policy(name,retention_days,max_rows,max_bytes,description,enabled,managed) VALUES('prod',30,0,0,'index de production',1,1);",
    );
}

/// L'entrée d'index portant ce nom, ou `Value::Null` (jamais un `unwrap` : l'absence est précisément le
/// défaut que le témoin (3) traque, et elle doit produire un message, pas une panique).
fn lcs_index(corps: &Value, nom: &str) -> Value {
    corps["indexes"]
        .as_array()
        .and_then(|a| a.iter().find(|i| i["name"] == json!(nom)))
        .cloned()
        .unwrap_or(Value::Null)
}

/// AUCUN FAIT D'INDEX N'EST SERVI SOUS L'AVEU. Le point n'est pas que la liste soit vide — c'est
/// qu'aucune des deux phrases rassurantes ne subsiste : ni un volume établi (`events`), ni un « hérite
/// du global » (`has_policy`), qui sont les deux façons dont ce corps mentait.
fn lcs_aucun_fait_dindex(corps: &Value) {
    let texte = corps.to_string();
    assert!(!texte.contains("\"has_policy\""), "aucun « hérite du global » n'est servi sur une lecture ratée : {corps}");
    assert!(!texte.contains("\"events\""), "aucun volume d'index n'est servi comme un fait sur une lecture ratée : {corps}");
}
