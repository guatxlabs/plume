// =====================================================================================
// `P10.20-b` (reste hors `handlers/` : les trois `.flatten()` de `purge.rs`) — UNE LIGNE NON LUE PAR LA
// SIMULATION DE PURGE REFUSE LE PLAN AU LIEU D'EN ÊTRE SAUTÉE.
//
// LE DÉFAUT (mesuré sur 2e4fe6eb) : la ventilation par source de `purge_plan`, `purge_sample` (ASC et DESC) et
// les identifiants de `cited_by_case` étaient collectés par `query_map(..)?.flatten().collect()`. Une ligne dont
// le mappeur échoue (valeur qui ne se décode pas) ou dont le pas échoue (interruption par le rappel de
// progression que `armer_le_quota` pose sur TOUTE connexion de production, précisément pendant les tris qui
// déversent) disparaissait sans un mot, alors que `rows` (COUNT(*) exact) la comptait. La ventilation entre
// dans le JETON (`purge_digest`), dans `ConfirmedPurge` et dans l'inscription au registre inviolable : le plan,
// le jeton confirmé et la trace de la destruction décrivaient moins que ce que le DELETE détruit.
//
// CE QUE L'ÉNONCÉ DISAIT DE FAUX : « ref cité illisible » ne fait PAS échouer le mappeur de `cited_by_case` —
// il ne lit que `event.id`, clé entière, jamais `incident_item.ref`. La fabrication jouée ici est une vue
// temporaire `event` qui projette `id` en REAL : la jointure numérique trouve la citation (COUNT juste), seul le
// décodage de l'identifiant échoue. Et ce site-là n'était pas destructif : le refus `cited_by_case` tombait
// quand même (total > 0), avec une liste d'exemples tronquée servie comme complète.
//
// CE QUE CES TÉMOINS JUGENT, DANS LES DEUX SENS — chaque refus porte la CAUSE DU MOTEUR (texte de l'erreur
// rusqlite), pas seulement le site : une valeur qui ne se décode pas et une interruption ne rendent pas le
// même refus muet.
//  - source en blob (non UTF-8, puis UTF-8) sur une ligne du milieu de la fenêtre : refus `plan_row_unread`
//    qui nomme la ventilation et dit « Invalid column type Blob at index: 0 » ; `event` inchangé. Le jeton
//    d'avant N'EST PAS un témoin de régression pour cette variante : la ventilation entre dans l'empreinte, donc
//    sans le correctif il était déjà caduc (`stale_token`) — c'est l'assertion « `purge_plan` refuse » du même
//    corps qui attrape la régression ; la confirmation n'y juge que le fail-closed (même code, rien supprimé) ;
//  - message en blob sur la ligne la plus VIEILLE (côté ASC) puis la plus RÉCENTE (côté DESC) : même refus,
//    qui nomme l'échantillon et dit « Invalid column type Blob at index: 4 ». Ici le jeton d'avant EST un
//    témoin : l'échantillon n'entre pas dans l'empreinte, sans le correctif il restait valide ;
//  - identifiant cité lu en REAL : refus `plan_row_unread` qui nomme `cited_by_case`, dit « Invalid column
//    type Real at index: 0 » et garde le total ; contrôle positif dans le même corps (vue retirée ->
//    `cited_by_case` nomme l'id) ;
//  - chemin nominal octet pour octet : le jeton est l'empreinte recalculée ici par la formule de
//    `purge_digest`, ventilation et échantillon exacts ;
//  - INTERRUPTION à chaque instruction de la VM, une par passage, sur une base SANS citation : aucune ne rend
//    un plan différent du plan nominal (soit le plan nominal, soit un refus) ; tout `plan_row_unread` dit
//    « interrupted » ;
//  - INTERRUPTION à chaque instruction sur une base AVEC une citation : aucun `cited_by_case` ne sert une liste
//    d'exemples tronquée (l'id cité y est toujours), au moins un passage frappe la lecture des ids et refuse
//    `plan_row_unread` en nommant `cited_by_case` et « interrupted ».
// MUTATIONS (jouées sous VERIF_MUT, retirées du source) : `L2_FLATTEN_SOURCES` rougit le témoin de la
// ventilation et le balayage d'interruptions ; `L2_FLATTEN_ECHANTILLON` les deux témoins d'échantillon et le
// balayage ; `L2_FLATTEN_CITES` le témoin des citations et le balayage AVEC citation. Correction après
// vérification : `L2_CAUSE_SOURCES`, `L2_CAUSE_ECHANTILLON`, `L2_CAUSE_CITES` (cause du moteur retirée du
// refus, site gardé) et `L2_PAS_CITES` (erreur au pas avalée dans `cited_by_case`, liste partielle rendue,
// refus gardé sur les autres erreurs) rougissent. Le témoin nominal reste vert sous toutes.
// CE QUE CE LOT NE TIENT PAS :
//  - `table_exists_purge` (`table_present`) et `fts_delete_trigger_ok` rendent encore « absente » /
//    « désynchronisé » sur une lecture ratée du catalogue : une interruption sur `table_present("incident_item")`
//    SAUTE le contrôle de citation et rend un plan (le balayage AVEC citation le tolère à condition qu'il soit
//    le plan nominal, et l'affiche sous `--no-capture`) ; même chose pour le tier froid — hors de ces trois
//    sites, non touché ; `purge_apply` et son BEGIN (`P10.29-h`) ;
//  - une même cause, l'interruption par le quota, sort en 500 `db` quand elle frappe un `query_row` (COUNT,
//    bornes, citations comptées) et en 409 `plan_row_unread` quand elle frappe la ventilation, l'échantillon ou
//    la liste des ids cités (`handlers/purge.rs`, bras `_ => CONFLICT`). Impact borné : la console n'appelle pas
//    `/api/purge` (aucune occurrence dans `web/`), la CLI affiche le texte du refus (ou le JSON
//    `{refusal,message}`) et sort en code 3 sans traitement propre à un code.
// =====================================================================================

fn pli_ins(c: &Connection, ts: i64, source: &str, msg: &str) -> i64 {
    c.execute(
        "INSERT INTO event(ts,source,category,severity,message,host,env_id,origin,engagement_id) \
         VALUES(?1,?2,'test',1,?3,'h1','prod','','')",
        params![ts, source, msg],
    )
    .unwrap();
    c.last_insert_rowid()
}

fn pli_scope() -> PurgeScope {
    let v = vec![("env".to_string(), "prod".to_string())];
    purge_scope_from_args(&v, "0", "2000", now()).expect("périmètre valide")
}

/// Onze lignes dans la fenêtre : `flux-a` (ts 1000..1004, les cinq plus vieilles), `flux-b` (ts 1005, la seule
/// hors des deux extrémités de l'échantillon), `flux-c` (ts 1006..1010, les cinq plus récentes). Rend les ids
/// dans l'ordre des ts.
fn pli_base() -> (Connection, Vec<i64>) {
    let c = test_db();
    let mut ids = Vec::new();
    for ts in 1_000..1_011 {
        let src = match ts {
            1_000..=1_004 => "flux-a",
            1_005 => "flux-b",
            _ => "flux-c",
        };
        ids.push(pli_ins(&c, ts, src, &format!("message {ts}")));
    }
    (c, ids)
}

/// Empreinte de `event` ligne à ligne (types compris) : prouve que la simulation refusée n'a rien écrit.
fn pli_event_fingerprint(c: &Connection) -> String {
    c.query_row(
        "SELECT COUNT(*) || '#' || COALESCE(group_concat(id || ':' || quote(source) || ':' || quote(message), '|'), '') \
           FROM (SELECT id, source, message FROM event ORDER BY id)",
        [],
        |r| r.get(0),
    )
    .unwrap()
}

fn pli_ledger_purges(c: &Connection) -> i64 {
    c.query_row("SELECT COUNT(*) FROM ledger WHERE kind=?1", params![PURGE_LEDGER_KIND], |r| r.get(0)).unwrap()
}

/// Juge le refus fail-closed : aucun plan (donc aucun jeton), code, site et CAUSE DU MOTEUR nommés, `event`
/// inchangé ; puis la voie de confirmation avec le jeton qui était VALIDE avant l'altération : même refus, rien
/// de supprimé, rien d'inscrit.
fn pli_juger_refus(c: &Connection, voie: &str, site: &str, cause: &str, jeton_d_avant: &str) {
    let avant = pli_event_fingerprint(c);
    let e = match purge_plan(c, pli_scope()) {
        Ok(p) => panic!(
            "{voie} : la simulation a rendu un plan de {} ligne(s), ventilation {:?}, échantillon de {} ligne(s), \
             jeton {} — malgré une ligne NON LUE (plan partiel)",
            p.rows(),
            p.per_source(),
            p.sample().len(),
            p.digest()
        ),
        Err(e) => e,
    };
    assert_eq!(purge_refusal_code(&e), "plan_row_unread", "{voie} : refus nommé, pas `{e}`");
    let m = e.to_string();
    assert!(m.contains("SIMULATION NON LUE"), "{voie} : le texte dit NON LUE : {m}");
    assert!(m.contains(site), "{voie} : le refus nomme la lecture `{site}` : {m}");
    assert!(m.contains(cause), "{voie} : le refus porte la cause du moteur `{cause}` : {m}");
    assert_eq!(pli_event_fingerprint(c), avant, "{voie} : la simulation refusée n'a rien écrit");

    let e2 = purge_confirm_and_apply(c, pli_scope(), jeton_d_avant, "t", "raison").unwrap_err();
    assert_eq!(purge_refusal_code(&e2), "plan_row_unread", "{voie} : confirmation refusée par la même cause");
    assert_eq!(pli_event_fingerprint(c), avant, "{voie} : la confirmation refusée n'a rien supprimé");
    assert_eq!(pli_ledger_purges(c), 0, "{voie} : aucune purge inscrite au registre");
}

/// Ventilation par source : une ligne dont la source est un blob. Elle est DANS le périmètre (sélecteur `env`)
/// et compte dans `rows`, mais n'est dans aucune des deux extrémités de l'échantillon — seul le site de la
/// ventilation la lit.
#[test]
fn pli_source_illisible_refuse_la_ventilation_par_source() {
    for (voie, illisible) in [("blob non UTF-8", "X'FFFE'"), ("blob UTF-8", "CAST('flux-b' AS BLOB)")] {
        let (c, _) = pli_base();
        // Contrôle positif dans le même corps : la source lisible est ventilée, la somme fait `rows`.
        let p = purge_plan(&c, pli_scope()).expect("contrôle positif : plan nominal");
        assert_eq!(
            p.per_source(),
            &[("flux-a".to_string(), 5), ("flux-b".to_string(), 1), ("flux-c".to_string(), 5)][..],
            "{voie} : contrôle positif"
        );
        let jeton = p.digest().to_string();

        c.execute_batch(&format!("UPDATE event SET source={illisible} WHERE source='flux-b'")).unwrap();
        pli_juger_refus(&c, voie, "`purge_plan`", "Invalid column type Blob at index: 0", &jeton);
    }
}

/// Échantillon : un message en blob sur la ligne la plus VIEILLE (lue par le côté ASC seulement), puis sur la
/// plus RÉCENTE (côté DESC seulement). La ventilation ne lit pas le message : seul l'échantillon la voit.
#[test]
fn pli_message_illisible_refuse_l_echantillon_des_deux_cotes() {
    for (voie, rang) in [("côté ASC (plus vieille)", 0usize), ("côté DESC (plus récente)", 10usize)] {
        let (c, ids) = pli_base();
        let p = purge_plan(&c, pli_scope()).expect("contrôle positif : plan nominal");
        assert!(p.sample().iter().any(|r| r.id == ids[rang]), "{voie} : contrôle positif, la ligne est échantillonnée");
        let jeton = p.digest().to_string();

        c.execute("UPDATE event SET message=X'FFFE' WHERE id=?1", params![ids[rang]]).unwrap();
        pli_juger_refus(&c, voie, "`purge_sample`", "Invalid column type Blob at index: 4", &jeton);
    }
}

/// Citations : l'identifiant d'un event cité est lu au travers d'une vue temporaire `event` (elle ombre la
/// table) qui le projette en REAL. La jointure numérique trouve la citation, le COUNT est juste ; seul le
/// décodage de l'identifiant échoue. Sans le correctif : `cited_by_case` avec une liste d'ids VIDE.
#[test]
fn pli_identifiant_cite_illisible_refuse_au_lieu_d_une_liste_tronquee() {
    let (c, ids) = pli_base();
    c.execute("INSERT INTO incident(ts,updated,title) VALUES(1000,1000,'enquête')", []).unwrap();
    let inc = c.last_insert_rowid();
    c.execute(
        "INSERT INTO incident_item(incident_id,ts,kind,author,body,ref) VALUES(?1,1000,'evidence','a','b',?2)",
        params![inc, format!("event:{}", ids[5])],
    )
    .unwrap();
    // Contrôle positif : la table lue directement, le refus NOMME l'event cité.
    let e = purge_plan(&c, pli_scope()).unwrap_err();
    assert_eq!(purge_refusal_code(&e), "cited_by_case", "contrôle positif");
    assert!(e.to_string().contains(&format!("[{}]", ids[5])), "contrôle positif : l'id est nommé : {e}");

    let cols: Vec<String> = {
        let mut st = c.prepare("SELECT name FROM pragma_table_info('event') ORDER BY cid").unwrap();
        let lignes = st.query_map([], |r| r.get::<_, String>(0)).unwrap();
        lignes.collect::<Result<Vec<String>, _>>().unwrap()
    };
    assert!(cols.iter().any(|n| n == "id") && cols.len() > 5, "précondition : colonnes d'`event` lues");
    let proj: Vec<String> = cols
        .iter()
        .map(|n| if n == "id" { "CAST(id AS REAL) AS id".to_string() } else { format!("\"{n}\"") })
        .collect();
    c.execute_batch(&format!("CREATE TEMP VIEW event AS SELECT {} FROM main.event;", proj.join(", "))).unwrap();

    let avant = pli_event_fingerprint(&c);
    let e = purge_plan(&c, pli_scope()).unwrap_err();
    assert_eq!(
        purge_refusal_code(&e),
        "plan_row_unread",
        "un identifiant cité non lu refuse par une cause nommée, pas `{e}` (liste d'exemples tronquée)"
    );
    let m = e.to_string();
    assert!(m.contains("`cited_by_case`"), "le refus nomme la lecture : {m}");
    assert!(m.contains("Invalid column type Real at index: 0"), "le refus porte la cause du moteur : {m}");
    assert!(m.contains("1 event(s) du périmètre sont cités"), "le total cité reste dit : {m}");
    assert_eq!(pli_event_fingerprint(&c), avant, "la simulation refusée n'a rien écrit");
}

/// Chemin NOMINAL octet pour octet : le jeton est l'empreinte que `purge_digest` définit, recalculée ici depuis
/// la formule et les valeurs attendues (pas depuis le plan), ventilation et échantillon exacts.
#[test]
fn pli_plan_nominal_et_son_jeton_sont_inchanges() {
    let (c, ids) = pli_base();
    let scope = pli_scope();
    let canonique = scope.canonical();
    let p = purge_plan(&c, scope).expect("plan nominal");
    let somme: i64 = ids.iter().sum();
    let attendu = sha256_hex(
        format!(
            "plume-purge/v1|{canonique}|rows=11|id=[{},{}]|idsum={somme}|ts=[1000,1010]|src=flux-a:5,flux-b:1,flux-c:5",
            ids[0], ids[10]
        )
        .as_bytes(),
    );
    assert_eq!(p.digest(), attendu, "le jeton nominal est l'empreinte d'avant, octet pour octet");
    assert_eq!(p.rows(), 11);
    let echantillon: Vec<i64> = p.sample().iter().map(|r| r.id).collect();
    let mut attendus: Vec<i64> = ids[0..5].to_vec();
    attendus.extend_from_slice(&ids[6..11]);
    assert_eq!(echantillon, attendus, "échantillon : les cinq plus vieilles et les cinq plus récentes");
    assert!(p.sample().iter().all(|r| r.message.starts_with("message ")), "messages rendus tels quels");
}

/// INTERRUPTION — la voie que la production atteint : le rappel de progression (`armer_le_quota`) arrête
/// l'instruction EN COURS, et l'échec sort du pas comme une erreur de LIGNE. Balayage exhaustif : un passage
/// par instruction de la VM, interrompu à cette instruction-là. Aucun passage ne rend un plan différent du plan
/// nominal ; il rend le plan nominal ou un refus.
#[test]
fn pli_aucune_interruption_ne_rend_un_plan_partiel() {
    let (c, _) = pli_base();
    let reference = purge_plan(&c, pli_scope()).expect("plan nominal");
    let ref_sample: Vec<i64> = reference.sample().iter().map(|r| r.id).collect();

    // Nombre d'instructions d'une simulation complète (rappel compté, jamais vrai).
    use std::sync::atomic::{AtomicU64, Ordering};
    let compte = std::sync::Arc::new(AtomicU64::new(0));
    let k = compte.clone();
    c.progress_handler(
        1,
        Some(move || {
            k.fetch_add(1, Ordering::Relaxed);
            false
        }),
    );
    purge_plan(&c, pli_scope()).expect("plan nominal sous rappel inerte");
    let total = compte.load(Ordering::Relaxed);
    assert!(total > 100, "précondition : la simulation exécute des instructions ({total})");

    let mut refus = 0u64;
    for cible in 1..=total {
        let n = AtomicU64::new(0);
        c.progress_handler(1, Some(move || n.fetch_add(1, Ordering::Relaxed) + 1 == cible));
        match purge_plan(&c, pli_scope()) {
            Ok(p) => {
                let sample: Vec<i64> = p.sample().iter().map(|r| r.id).collect();
                assert!(
                    p.digest() == reference.digest()
                        && p.per_source() == reference.per_source()
                        && sample == ref_sample,
                    "interruption à l'instruction {cible}/{total} : plan PARTIEL rendu comme complet — \
                     ventilation {:?} (attendu {:?}), échantillon {sample:?} (attendu {ref_sample:?})",
                    p.per_source(),
                    reference.per_source()
                );
            }
            Err(e) => {
                if purge_refusal_code(&e) == "plan_row_unread" {
                    assert!(
                        e.to_string().contains("interrupted"),
                        "interruption à l'instruction {cible}/{total} : le refus porte la cause du moteur : {e}"
                    );
                }
                refus += 1;
            }
        }
    }
    c.progress_handler(0, None::<fn() -> bool>);
    assert!(refus > 0, "précondition : au moins une interruption a été jouée et refusée");
}

/// INTERRUPTION sur une base AVEC une citation — la voie de `cited_by_case` que le balayage précédent
/// n'atteint pas (sans citation, `total == 0` et la liste des ids n'est jamais lue). Aucun passage ne sert un
/// refus `cited_by_case` dont la liste d'exemples perd l'id cité ; au moins un passage interrompt la lecture
/// des ids et refuse `plan_row_unread` en le disant.
#[test]
fn pli_aucune_interruption_ne_tronque_la_liste_des_cites() {
    let (c, ids) = pli_base();
    // Plan de référence AVANT la citation : l'empreinte ne dépend pas des citations.
    let reference = purge_plan(&c, pli_scope()).expect("plan nominal");
    let ref_sample: Vec<i64> = reference.sample().iter().map(|r| r.id).collect();
    c.execute("INSERT INTO incident(ts,updated,title) VALUES(1000,1000,'enquête')", []).unwrap();
    let inc = c.last_insert_rowid();
    c.execute(
        "INSERT INTO incident_item(incident_id,ts,kind,author,body,ref) VALUES(?1,1000,'evidence','a','b',?2)",
        params![inc, format!("event:{}", ids[5])],
    )
    .unwrap();
    let cite = format!("[{}]", ids[5]);
    let e = purge_plan(&c, pli_scope()).unwrap_err();
    assert_eq!(purge_refusal_code(&e), "cited_by_case", "contrôle positif");
    assert!(e.to_string().contains(&cite), "contrôle positif : l'id est nommé : {e}");

    use std::sync::atomic::{AtomicU64, Ordering};
    let compte = std::sync::Arc::new(AtomicU64::new(0));
    let k = compte.clone();
    c.progress_handler(
        1,
        Some(move || {
            k.fetch_add(1, Ordering::Relaxed);
            false
        }),
    );
    let _ = purge_plan(&c, pli_scope());
    let total = compte.load(Ordering::Relaxed);
    assert!(total > 100, "précondition : la simulation exécute des instructions ({total})");

    let (mut cites_refuses, mut cites_complets, mut controle_saute, mut autres) = (0u64, 0u64, 0u64, 0u64);
    for cible in 1..=total {
        let n = AtomicU64::new(0);
        c.progress_handler(1, Some(move || n.fetch_add(1, Ordering::Relaxed) + 1 == cible));
        match purge_plan(&c, pli_scope()) {
            Ok(p) => {
                // Reste NOMMÉ (en-tête) : `table_present` interrompu saute le contrôle de citation. Toléré ici
                // seulement si le plan rendu est le plan nominal — ce témoin juge la liste des ids, pas ce reste.
                let sample: Vec<i64> = p.sample().iter().map(|r| r.id).collect();
                assert!(
                    p.digest() == reference.digest()
                        && p.per_source() == reference.per_source()
                        && sample == ref_sample,
                    "interruption à l'instruction {cible}/{total} : plan PARTIEL rendu comme complet"
                );
                controle_saute += 1;
            }
            Err(e) => {
                let m = e.to_string();
                match purge_refusal_code(&e) {
                    "cited_by_case" => {
                        assert!(
                            m.contains(&cite),
                            "interruption à l'instruction {cible}/{total} : liste des events cités TRONQUÉE servie comme complète : {m}"
                        );
                        cites_complets += 1;
                    }
                    "plan_row_unread" => {
                        assert!(
                            m.contains("interrupted"),
                            "interruption à l'instruction {cible}/{total} : le refus porte la cause du moteur : {m}"
                        );
                        if m.contains("`cited_by_case`") {
                            assert!(m.contains("1 event(s) du périmètre sont cités"), "le total cité reste dit : {m}");
                            cites_refuses += 1;
                        }
                    }
                    _ => autres += 1,
                }
            }
        }
    }
    c.progress_handler(0, None::<fn() -> bool>);
    println!(
        "balayage avec citation : {total} passages — liste des cités interrompue et refusée {cites_refuses}, \
         `cited_by_case` complet {cites_complets}, contrôle de citation sauté (reste `table_present`) \
         {controle_saute}, autres refus {autres}"
    );
    assert!(
        cites_refuses > 0,
        "précondition : au moins une interruption a frappé la lecture des ids cités et l'a refusée (passages : \
         {cites_complets} complets, {controle_saute} sautés, {autres} autres)"
    );
}
