// =====================================================================================
// `P10.26-s` — INTÉGRITÉ : UN `BEGIN` REFUSÉ N'ÉCRIT RIEN, NE VALIDE RIEN ET N'ANNULE RIEN QUI NE SOIT À LUI.
// `P10.26-t` — INTÉGRITÉ : CE QUI SORT DU REGISTRE VERS UNE COPIE EST LU LÀ OÙ SEUL LE VALIDÉ EXISTE.
// `P10.26-u` — LE CURSEUR D'UN PUITS DU REGISTRE AVANCE PAR UNE ÉCRITURE COMPTÉE, ET UN DOUBLON SE DIT.
//
// LA PRÉCONDITION COMMUNE : une transaction d'un AUTRE geste, ouverte sur l'écrivain partagé et laissée PENDANTE —
// l'état qu'un `COMMIT` refusé puis ignoré laisse derrière lui (forme d'avant `P10.26-c`, toujours celle des sites que
// `P10.25-g` recense). Elle est ouverte ici à la main : c'est la condition, pas le défaut sous témoin.
//
// LES DÉFAUTS, MESURÉS AVANT TOUT CORRECTIF le 2026-09-24 (témoin de mesure joué sur la forme d'avant, puis retiré ;
// « à froid » = une connexion neuve sur le même fichier, ce qu'un redémarrage relit) :
//  * `rollup_hosts` (pli définitif) : la levée d'un gel juridique pendante, la rétention qui purge la preuve gelée
//    DANS cette transaction, puis le `COMMIT` du pli après un `BEGIN` ignoré — gel inactif ET preuve purgée à froid ;
//    le rattrapage (`host_rollup_backfill_floor`) valide de même une écriture étrangère ;
//  * le reparse rétroactif rend 200 `updated: 1` et valide la transaction étrangère ;
//  * `metrics_prom` 200 `ingested: 1`, `metrics_write` 204, `loki_push` 204 : transaction étrangère validée ;
//  * spool journald et spool d'événements : `Lue(0)`, fichier SUPPRIMÉ, transaction étrangère validée ; spool de
//    métriques (garde `Txn`) : rien de validé, mais le lot est ÉCARTÉ en quarantaine sur un simple `BEGIN` refusé ;
//  * un `INSERT` refusé (ingestion d'événements, pli de `rollup_hosts`) : le `ROLLBACK` du geste ANNULE l'écriture
//    étrangère, qui disparaît même pour ce processus ;
//  * le téléchargement du registre rend 200 et DEUX lignes pour UN maillon validé ; l'envoi vers un puits écrit ces
//    deux lignes dans la copie et répond `exported: 2` ; la transaction annulée, le curseur revient à 0 et la copie
//    porte un maillon qui n'a jamais existé ;
//  * `UPDATE ledger_sink` refusé : 200 `exported: 1`, curseur à 0, et l'envoi suivant réécrit la même ligne — la
//    copie ne se vérifie plus (« rupture de chaîne » à la ligne répétée).
//
// CE QUI ÉTAIT IMPRÉCIS : le pli de `rollup_hosts` ne s'ouvre qu'au PREMIER passage de chaque heure (sur une base
// neuve, la migration pose `host_rollup_wm` à l'heure pleine précédente) ou sur un rattrapage noté ; la validation
// étrangère n'est donc pas « à chaque tick » mais une fois par heure au plus. L'énoncé de `P10.26-t` ne nommait que
// l'envoi ; le téléchargement avait le même défaut.
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : le mode multi-tenant (écrivain du tenant) n'est pas joué ; un `BEGIN` refusé par
// un verrou tenu par un AUTRE processus n'est pas fabriqué (le chemin de code est le même, le message diffère) ; la
// lecture de l'envoi sur le pool n'est pas éprouvable seule — le `BEGIN` qui la précède refuse déjà l'envoi quand
// l'écrivain porte une transaction étrangère ; aucun module de `web/` n'est exercé.
// =====================================================================================
mod begin_refuse_et_export_du_registre_valide {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};

    /// Ouvre la transaction d'un AUTRE geste sur l'écrivain partagé et la laisse pendante.
    fn brev_transaction_etrangere(st: &AppState, sql: &str) {
        let c = st.db.lock();
        c.execute_batch("BEGIN IMMEDIATE").expect("fixture : la transaction étrangère s'ouvre");
        c.execute_batch(sql).expect("fixture : ses écritures");
    }

    /// Le geste étranger ferme SA transaction (ce que fait `valider_la_transaction` sur un `COMMIT` refusé).
    fn brev_le_geste_etranger_annule(st: &AppState) {
        st.db.lock().execute_batch("ROLLBACK").expect("la transaction étrangère est toujours là pour être annulée par son geste");
    }

    fn brev_pendante(st: &AppState) -> bool {
        !st.db.lock().is_autocommit()
    }

    /// Ce que le processus lit, sur l'écrivain partagé (transaction pendante comprise).
    fn brev_ici(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    /// Ce qu'un redémarrage relirait : une connexion NEUVE sur le même fichier ne voit que ce qui est validé.
    fn brev_a_froid(p: &crate::tmp_possede::TmpDb, sql: &str) -> i64 {
        let c = open_db(p.as_str()).expect("relecture à froid");
        c.query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("relecture à froid de `{sql}` ({e})"))
    }

    fn brev_texte_a_froid(p: &crate::tmp_possede::TmpDb, sql: &str) -> Option<String> {
        let c = open_db(p.as_str()).expect("relecture à froid");
        c.query_row(sql, [], |r| r.get::<_, Option<String>>(0)).ok().flatten()
    }

    async fn brev_corps(r: Response) -> (u16, Value, String) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        let texte = String::from_utf8_lossy(&b).into_owned();
        (statut, serde_json::from_str(&texte).unwrap_or(Value::Null), texte)
    }

    fn brev_adm() -> AuthUser {
        sp_au("adm", "admin")
    }

    const BREV_ETRANGERE: &str = "SELECT COUNT(*) FROM meta WHERE key='brev-etrangere'";

    // -------------------------------------------------------------------------------------
    // (1) `P10.26-s` — LE GEL LEVÉ REFUSÉ, LA RÉTENTION, PUIS `rollup_hosts` : RIEN N'EST RENDU DURABLE
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : un gel juridique posé sur `sshd`, une preuve de quarante jours. La levée de ce gel est laissée
    /// PENDANTE sur l'écrivain ; la rétention purge la preuve DANS cette transaction (précondition relevée). Le pli
    /// définitif de `rollup_hosts` doit s'ouvrir (watermark retiré) : il ne la ferme PAS — toujours pendante, levée
    /// toujours visible pour ce processus (rien d'annulé), gel actif ET preuve présente à froid, aucun watermark validé.
    /// Le geste étranger annule sa transaction : la preuve revient ; le passage suivant de `rollup_hosts` fait son pli
    /// (le watermark est validé), et la rétention ne purge pas la preuve gelée.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `let _ = conn.execute_batch("BEGIN IMMEDIATE");` au pli définitif (la forme
    /// d'avant) — la transaction se ferme, gel inactif et preuve purgée à froid.
    #[tokio::test]
    async fn brev_un_begin_refuse_par_rollup_hosts_ne_rend_durables_ni_la_levee_du_gel_ni_la_purge_de_la_preuve() {
        // `retention_run` relit l'environnement du processus (`PLUME_COLD_TIER`) : même verrou que ses autres témoins.
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let (st, p) = sp_state("brev-gel");
        let vieux = now() - 40 * 86400;
        {
            let c = st.db.lock();
            c.execute("INSERT INTO setting(scope,key,value) VALUES('global','retention_days','7')", []).expect("fixture : rétention");
            c.execute("INSERT INTO event(ts,source,message,origin) VALUES(?1,'sshd','preuve brev','')", params![vieux]).expect("fixture : preuve");
            // Sur une base neuve la migration pose le watermark à l'heure pleine précédente : le pli ne s'ouvrirait qu'à
            // l'heure suivante. Retiré, il s'ouvre maintenant.
            c.execute("DELETE FROM meta WHERE key='host_rollup_wm'", []).expect("fixture : watermark retiré");
        }
        let (statut, corps, _) = brev_corps(
            legal_hold_create(State(st.clone()), Extension(brev_adm()), Json(json!({ "name": "litige-brev", "scope_source": "sshd" }))).await,
        )
        .await;
        assert_eq!(statut, 200, "fixture : le gel est posé : {corps}");
        let preuves = "SELECT COUNT(*) FROM event WHERE source='sshd'";

        brev_transaction_etrangere(&st, "UPDATE legal_hold SET active=0, released_ts=1, released_by='adm'");
        retention_run(&st.db);
        assert_eq!(brev_ici(&st, preuves), 0, "précondition : la rétention a purgé la preuve DANS la transaction pendante");

        rollup_hosts(&st.db.lock());
        let pendante = brev_pendante(&st);
        let levee_ici = brev_ici(&st, "SELECT COUNT(*) FROM legal_hold WHERE active=0");
        let gel_a_froid = brev_a_froid(&p, "SELECT COUNT(*) FROM legal_hold WHERE active=1");
        let preuve_a_froid = brev_a_froid(&p, preuves);
        let wm_a_froid = brev_texte_a_froid(&p, "SELECT value FROM meta WHERE key='host_rollup_wm'");
        assert!(pendante, "`rollup_hosts` n'a PAS fermé la transaction d'un autre geste");
        assert_eq!(levee_ici, 1, "et ne l'a pas annulée : la levée pendante est toujours là pour ce processus");
        assert_eq!(gel_a_froid, 1, "le gel est ACTIF au redémarrage : la levée refusée n'est pas devenue durable");
        assert_eq!(preuve_a_froid, 1, "la preuve gelée est là au redémarrage : la purge n'est pas devenue durable");
        assert_eq!(wm_a_froid, None, "rien du pli de `rollup_hosts` n'est validé");

        brev_le_geste_etranger_annule(&st);
        assert_eq!(brev_ici(&st, preuves), 1, "la transaction annulée par SON geste, la preuve revient");
        rollup_hosts(&st.db.lock());
        assert!(brev_texte_a_froid(&p, "SELECT value FROM meta WHERE key='host_rollup_wm'").is_some(), "le passage suivant fait son pli et le valide");
        assert!(!brev_pendante(&st), "et referme sa transaction");
        retention_run(&st.db);
        assert_eq!(brev_a_froid(&p, preuves), 1, "et la rétention ne purge pas la preuve d'un gel actif");
    }

    // -------------------------------------------------------------------------------------
    // (2) `P10.26-s` — LE RATTRAPAGE DE `rollup_hosts`
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : watermark dans le futur (le pli définitif ne s'ouvre pas), plancher de rattrapage noté à 0 (le
    /// rattrapage s'ouvre). Transaction étrangère pendante : elle le reste, son écriture est invisible à froid, le
    /// plancher ne bouge pas. Annulée par son geste, le passage suivant fait le rattrapage et remonte le plancher.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `let _ = conn.execute_batch("BEGIN IMMEDIATE");` au rattrapage — la transaction
    /// étrangère est validée.
    #[test]
    fn brev_le_rattrapage_de_rollup_hosts_ne_valide_rien_d_etranger() {
        let (st, p) = sp_state("brev-rattrapage");
        let futur = now() + 10 * 86400;
        {
            let c = st.db.lock();
            c.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('host_rollup_wm',?1)", params![futur.to_string()]).expect("fixture : watermark");
            c.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('host_rollup_backfill_floor','0')", []).expect("fixture : plancher");
        }
        let plancher = "SELECT value FROM meta WHERE key='host_rollup_backfill_floor'";
        brev_transaction_etrangere(&st, "INSERT INTO meta(key,value) VALUES('brev-etrangere','1')");

        rollup_hosts(&st.db.lock());
        let pendante = brev_pendante(&st);
        let etrangere_ici = brev_ici(&st, BREV_ETRANGERE);
        let etrangere_a_froid = brev_a_froid(&p, BREV_ETRANGERE);
        assert!(pendante, "le rattrapage n'a pas fermé la transaction d'un autre geste");
        assert_eq!(etrangere_ici, 1, "ni ne l'a annulée");
        assert_eq!(etrangere_a_froid, 0, "rien d'étranger n'est validé");
        assert_eq!(brev_texte_a_froid(&p, plancher).as_deref(), Some("0"), "le plancher est inchangé : le rattrapage est à reprendre");

        brev_le_geste_etranger_annule(&st);
        rollup_hosts(&st.db.lock());
        assert_eq!(brev_texte_a_froid(&p, plancher), Some(futur.to_string()), "le passage suivant fait le rattrapage");
    }

    // -------------------------------------------------------------------------------------
    // (3) `P10.26-s` — LE REPARSE RÉTROACTIF
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : un event dont l'adresse source n'est que dans `fields`. Transaction étrangère pendante : le
    /// reparse rend 503 `CAUSE_REPARSE_NON_APPLIQUE`, la transaction reste pendante, rien d'étranger à froid, l'event
    /// n'est pas modifié. Annulée par son geste, le reparse rend 200 `updated: 1`, adresse promue à froid.
    ///
    /// LA MUTATION QUI LE FAIT ROUGIR : `let _ = conn.execute_batch("BEGIN IMMEDIATE");` dans `parser_reparse` — 200.
    #[tokio::test]
    async fn brev_le_reparse_refuse_sans_rien_valider_d_etranger() {
        // Sous `cold_tier`, le reparse relit `PLUME_COLD_TIER` : même verrou que les autres lecteurs de l'environnement.
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let (st, p) = sp_state("brev-reparse");
        st.db
            .lock()
            .execute("INSERT INTO event(ts,source,message,fields,origin) VALUES(?1,'brevsrc','m','{\"src_ip\":\"198.51.100.7\"}','')", params![now() - 60])
            .expect("fixture : event");
        let promue = "SELECT COUNT(*) FROM event WHERE source='brevsrc' AND src_ip='198.51.100.7'";
        brev_transaction_etrangere(&st, "INSERT INTO meta(key,value) VALUES('brev-etrangere','1')");

        let (statut, corps, _) = brev_corps(parser_reparse(State(st.clone()), Extension(brev_adm()), Json(json!({}))).await).await;
        let pendante = brev_pendante(&st);
        assert_eq!(statut, 503, "un reparse dont la transaction n'est pas prise est refusé : {corps}");
        assert_eq!(corps["error"], json!(CAUSE_REPARSE_NON_APPLIQUE), "{corps}");
        assert!(pendante, "la transaction d'un autre geste n'est pas fermée par le reparse");
        assert_eq!(brev_a_froid(&p, BREV_ETRANGERE), 0, "rien d'étranger n'est validé");
        assert_eq!(brev_ici(&st, promue), 0, "aucun event n'est modifié, comme la cause le dit");

        brev_le_geste_etranger_annule(&st);
        let (statut, corps, _) = brev_corps(parser_reparse(State(st.clone()), Extension(brev_adm()), Json(json!({}))).await).await;
        assert_eq!(statut, 200, "l'écrivain libre, le reparse relancé s'applique : {corps}");
        assert_eq!(corps["updated"], json!(1), "{corps}");
        assert_eq!(brev_a_froid(&p, promue), 1, "et l'adresse promue est validée");
    }

    // -------------------------------------------------------------------------------------
    // (4) `P10.26-s` — LES TROIS RÉCEPTEURS DE BASE
    // -------------------------------------------------------------------------------------

    #[derive(prost::Message)]
    struct BrevEcriture {
        #[prost(message, repeated, tag = "1")]
        timeseries: Vec<BrevSerie>,
    }
    #[derive(prost::Message)]
    struct BrevSerie {
        #[prost(message, repeated, tag = "1")]
        labels: Vec<BrevEtiquette>,
        #[prost(message, repeated, tag = "2")]
        samples: Vec<BrevPoint>,
    }
    #[derive(prost::Message)]
    struct BrevEtiquette {
        #[prost(string, tag = "1")]
        name: String,
        #[prost(string, tag = "2")]
        value: String,
    }
    #[derive(prost::Message)]
    struct BrevPoint {
        #[prost(double, tag = "1")]
        value: f64,
        #[prost(int64, tag = "2")]
        timestamp: i64,
    }

    /// Un lot remote_write d'UN point (protobuf + snappy, la forme d'Alloy/Prometheus), fabriqué ici.
    fn brev_lot_remote_write(nom: &str) -> axum::body::Bytes {
        use prost::Message;
        let lot = BrevEcriture {
            timeseries: vec![BrevSerie {
                labels: vec![BrevEtiquette { name: "__name__".into(), value: nom.into() }],
                samples: vec![BrevPoint { value: 1.0, timestamp: now() * 1000 }],
            }],
        };
        let mut brut = Vec::new();
        lot.encode(&mut brut).expect("fixture : encodage protobuf");
        axum::body::Bytes::from(snap::raw::Encoder::new().compress_vec(&brut).expect("fixture : snappy"))
    }

    fn brev_lot_loki(ligne: &str) -> axum::body::Bytes {
        let ns = (now() as i128 * 1_000_000_000).to_string();
        axum::body::Bytes::from(json!({ "streams": [{ "stream": { "job": "brevloki" }, "values": [[ns, ligne]] }] }).to_string())
    }

    async fn brev_envoyer_au_recepteur(st: &AppState, recepteur: &str) -> (u16, Value, String) {
        let r = match recepteur {
            "prom" => metrics_prom(State(st.clone()), Extension(brev_adm()), Query(HashMap::new()), "brev_prom 1\n".to_string()).await,
            "rw" => metrics_write(State(st.clone()), Extension(brev_adm()), brev_lot_remote_write("brev_rw")).await,
            _ => loki_push(State(st.clone()), Extension(brev_adm()), axum::http::HeaderMap::new(), brev_lot_loki("ligne brev")).await,
        };
        brev_corps(r).await
    }

    /// CE QU'IL TIENT, POUR CHACUN DES TROIS : transaction étrangère pendante, le lot rend 503
    /// `CAUSE_LOT_D_INGESTION_NON_ECRIT`, la transaction reste pendante et son écriture visible pour ce processus, rien
    /// d'étranger à froid, rien du lot ici. Annulée par son geste, le MÊME lot réémis est acquitté et écrit UNE fois.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `let _ = conn.execute_batch("BEGIN IMMEDIATE");` dans `metrics_prom` (200),
    /// dans `metrics_write` (204), dans `ingest_events_batch_env` (`loki_push` 204).
    #[tokio::test]
    async fn brev_les_trois_recepteurs_de_base_refusent_un_lot_non_pris_sans_rien_valider_d_etranger() {
        let (st, p) = sp_state("brev-recepteurs");
        let recepteurs = [
            ("prom", "SELECT COUNT(*) FROM metric WHERE name='brev_prom'", 200u16),
            ("rw", "SELECT COUNT(*) FROM metric WHERE name='brev_rw'", 204),
            ("loki", "SELECT COUNT(*) FROM event WHERE message='ligne brev'", 204),
        ];
        for (recepteur, lignes, acquit) in recepteurs {
            brev_transaction_etrangere(&st, "INSERT INTO meta(key,value) VALUES('brev-etrangere','1')");
            let (statut, corps, texte) = brev_envoyer_au_recepteur(&st, recepteur).await;
            let pendante = brev_pendante(&st);
            assert_eq!(statut, 503, "{recepteur} : un lot dont la transaction n'est pas prise est refusé : {texte}");
            assert_eq!(corps["error"], json!(CAUSE_LOT_D_INGESTION_NON_ECRIT), "{recepteur} : {texte}");
            assert!(pendante, "{recepteur} : la transaction d'un autre geste n'est pas fermée par le lot");
            assert_eq!(brev_ici(&st, BREV_ETRANGERE), 1, "{recepteur} : ni annulée");
            assert_eq!(brev_ici(&st, lignes), 0, "{recepteur} : aucune ligne du lot n'est écrite, comme la cause le dit");
            assert_eq!(brev_a_froid(&p, BREV_ETRANGERE), 0, "{recepteur} : rien d'étranger n'est validé");

            brev_le_geste_etranger_annule(&st);
            let (statut, _, texte) = brev_envoyer_au_recepteur(&st, recepteur).await;
            assert_eq!(statut, acquit, "{recepteur} : l'écrivain libre, le lot réémis est acquitté : {texte}");
            assert_eq!(brev_a_froid(&p, lignes), 1, "{recepteur} : et écrit UNE fois — ni perdu, ni doublé");
        }
    }

    // -------------------------------------------------------------------------------------
    // (5) `P10.26-s` — LE SPOOL : UN LOT NON PRIS RESTE AU SPOOL, ET N'EST ÉCRIT QU'UNE FOIS
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT : quatre lots au spool — journald (`.ndjson`), événements, métriques, instantané. Transaction
    /// étrangère pendante : le passage compte QUATRE abandons, les quatre fichiers sont TOUJOURS au spool (ni supprimés,
    /// ni écartés : aucune quarantaine), rien des lots n'est écrit, la transaction reste pendante et son écriture
    /// visible pour ce processus, rien d'étranger à froid. Annulée par son geste, le passage suivant ingère les quatre,
    /// les retire du spool, et chacun est écrit UNE fois à froid.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : `let _ = conn.execute_batch("BEGIN IMMEDIATE");` dans `ingest_journal_lines`
    /// puis dans `ingest_events_batch_env` (le lot valide la transaction étrangère, fichier supprimé) ; la quarantaine
    /// rendue au `BEGIN` refusé du garde `Txn` (voie métriques : lot écarté).
    #[test]
    fn brev_un_lot_de_spool_non_pris_reste_au_spool_et_n_est_ecrit_qu_une_fois() {
        let (mut st, p) = sp_state("brev-spool");
        let spool = crate::tmp_possede::TmpPossede::neuf("brev-spool");
        st.spool = Arc::new(spool.to_string_lossy().to_string());
        let journald = json!({
            "__REALTIME_TIMESTAMP": (now() as i128 * 1_000_000).to_string(),
            "_HOSTNAME": "web01", "_COMM": "sshd",
            "MESSAGE": "Failed password for invalid user brev from 203.0.113.5 port 22",
            "PRIORITY": "5", "__CURSOR": "brev-curseur-1"
        });
        let lots = [
            (spool.join("jrnl-1-1.ndjson"), format!("{journald}\n"), "SELECT COUNT(*) FROM event WHERE message LIKE '%user brev%'"),
            (
                spool.join("ingest-1-2.json"),
                json!({ "kind": "events", "ts": now(), "data": { "events": [{ "source": "brevjson", "message": "m", "dedup": "brev-d1" }] } }).to_string(),
                "SELECT COUNT(*) FROM event WHERE source='brevjson'",
            ),
            (
                spool.join("ingest-1-3.json"),
                json!({ "kind": "metrics", "ts": now(), "data": { "metrics": [{ "name": "brev_spool", "value": 1.0 }] } }).to_string(),
                "SELECT COUNT(*) FROM metric WHERE name='brev_spool'",
            ),
            (
                spool.join("ingest-1-4.json"),
                json!({ "kind": "firewall", "ts": now(), "hash": "brev-h1", "data": { "control_docker_lockdown": { "ok": true } } }).to_string(),
                "SELECT COUNT(*) FROM snapshot WHERE hash='brev-h1'",
            ),
        ];
        for (chemin, contenu, _) in &lots {
            std::fs::write(chemin, contenu).expect("fixture : lot déposé");
        }
        brev_transaction_etrangere(&st, "INSERT INTO meta(key,value) VALUES('brev-etrangere','1')");

        let bilan = ingest_once(&st.tenants, &st.spool);
        let pendante = brev_pendante(&st);
        assert_eq!(bilan, crate::mesure_environnement::Mesure::Lue(4), "les quatre lots non pris sont des abandons COMPTÉS");
        for (chemin, _, lignes) in &lots {
            assert!(chemin.exists(), "{} : le lot RESTE au spool (ni supprimé, ni écarté)", chemin.display());
            assert_eq!(brev_ici(&st, lignes), 0, "{} : rien du lot n'est écrit", chemin.display());
        }
        assert!(!spool.join("quarantine").exists(), "aucun lot n'est écarté en quarantaine sur un BEGIN refusé");
        assert!(pendante, "la transaction d'un autre geste n'est pas fermée par l'ingestion");
        assert_eq!(brev_ici(&st, BREV_ETRANGERE), 1, "ni annulée");
        assert_eq!(brev_a_froid(&p, BREV_ETRANGERE), 0, "rien d'étranger n'est validé");

        brev_le_geste_etranger_annule(&st);
        assert_eq!(ingest_once(&st.tenants, &st.spool), crate::mesure_environnement::Mesure::Lue(0), "le passage suivant ingère tout");
        for (chemin, _, lignes) in &lots {
            assert!(!chemin.exists(), "{} : ingéré, retiré du spool", chemin.display());
            assert_eq!(brev_a_froid(&p, lignes), 1, "{} : écrit UNE fois — ni perdu, ni doublé", chemin.display());
        }
    }

    // -------------------------------------------------------------------------------------
    // (6) `P10.26-t` — CE QUI SORT DU REGISTRE EST LE VALIDÉ, ET L'ENVOI NE PART PAS SUR UN ÉCRIVAIN PRIS
    // -------------------------------------------------------------------------------------

    /// Un puits `file` déclaré dans la racine d'export posée par l'appelant (`PLUME_LEDGER_EXPORT_DIR`, sous
    /// `VERROU_ENV_PROCESSUS.write()`), un registre vidé puis UN maillon validé. Rend (état, base, puits, copie).
    fn brev_puits_fichier(etiquette: &str, racine: &std::path::Path) -> (AppState, crate::tmp_possede::TmpDb, i64, std::path::PathBuf) {
        let (st, p) = sp_state(etiquette);
        let copie = racine.join(format!("{etiquette}.jsonl"));
        let id = {
            let c = st.db.lock();
            c.execute("DELETE FROM ledger", []).expect("fixture : registre vidé");
            ledger_append(&c, "config.brev", "maillon validé 1");
            c.execute(
                "INSERT INTO ledger_sink(name,kind,target,enabled,last_id,last_hash) VALUES('worm','file',?1,1,0,'')",
                params![copie.to_string_lossy()],
            )
            .expect("fixture : puits déclaré");
            c.last_insert_rowid()
        };
        (st, p, id, copie)
    }

    fn brev_lignes_de_la_copie(copie: &std::path::Path) -> Vec<String> {
        std::fs::read_to_string(copie).unwrap_or_default().lines().filter(|l| !l.trim().is_empty()).map(String::from).collect()
    }

    async fn brev_envoyer(st: &AppState, id: i64) -> (u16, Value, String) {
        brev_corps(ledger_sink_flush(State(st.clone()), Extension(brev_adm()), axum::extract::Path(id)).await).await
    }

    /// CE QU'IL TIENT : un maillon validé, puis un maillon ajouté dans une transaction étrangère pendante. Le
    /// téléchargement rend 200 et UNE ligne, et la tête qu'il annonce est le maillon validé. L'envoi rend 503
    /// `CAUSE_ENVOI_DU_PUITS_NON_FAIT` : rien dans la copie, transaction étrangère toujours pendante et intacte.
    /// Annulée par son geste, l'envoi exporte UN maillon, la copie se vérifie, le curseur est validé à froid.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : le téléchargement relu sur l'écrivain (`with_write` + `ledger_export_lines`,
    /// la forme d'avant) — deux lignes ; l'envoi rendu à sa forme d'avant (lecture sur l'écrivain, aucune transaction à
    /// lui) — 200 et deux lignes dans la copie.
    #[tokio::test]
    async fn brev_l_export_du_registre_ne_sort_que_le_valide() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let racine = crate::tmp_possede::TmpPossede::neuf("brev-export");
        let _pose = ReglageBackupPose::neuf("PLUME_LEDGER_EXPORT_DIR", &racine.to_string_lossy());
        let (st, p, id, copie) = brev_puits_fichier("brev-registre", &racine);
        let valide = brev_ici(&st, "SELECT MAX(id) FROM ledger");
        {
            let c = st.db.lock();
            c.execute_batch("BEGIN IMMEDIATE").expect("fixture : transaction étrangère");
            ledger_append(&c, "config.brev", "maillon JAMAIS validé");
        }

        let r = ledger_export_get(State(st.clone()), Extension(brev_adm()), Query(HashMap::new())).await;
        let tete = r.headers().get("x-plume-ledger-last-id").and_then(|v| v.to_str().ok()).map(String::from);
        let (statut, _, texte) = brev_corps(r).await;
        assert_eq!(statut, 200, "le téléchargement se lit : {texte}");
        assert_eq!(texte.lines().count(), 1, "UNE ligne : le maillon jamais validé ne sort pas : {texte}");
        assert_eq!(tete, Some(valide.to_string()), "et la tête annoncée est le dernier maillon VALIDÉ");

        let (statut, corps, texte) = brev_envoyer(&st, id).await;
        let pendante = brev_pendante(&st);
        assert_eq!(statut, 503, "l'envoi ne part pas sur un écrivain pris par un autre geste : {texte}");
        assert_eq!(corps["error"], json!(CAUSE_ENVOI_DU_PUITS_NON_FAIT), "{texte}");
        assert!(brev_lignes_de_la_copie(&copie).is_empty(), "rien n'est écrit dans la copie, comme la cause le dit");
        assert!(pendante, "la transaction d'un autre geste n'est pas fermée par l'envoi");
        assert_eq!(brev_ici(&st, "SELECT COUNT(*) FROM ledger"), 2, "ni annulée");

        brev_le_geste_etranger_annule(&st);
        let (statut, corps, texte) = brev_envoyer(&st, id).await;
        assert_eq!(statut, 200, "l'écrivain libre, l'envoi part : {texte}");
        assert_eq!(corps["exported"], json!(1), "{texte}");
        let lignes = brev_lignes_de_la_copie(&copie);
        assert_eq!(ledger_verify_export(&lignes, ""), Ok(1), "la copie porte le seul maillon validé, et se vérifie");
        assert_eq!(brev_a_froid(&p, "SELECT last_id FROM ledger_sink WHERE name='worm'"), valide, "curseur validé sur ce maillon");
    }

    // -------------------------------------------------------------------------------------
    // (7) `P10.26-u` — LE CURSEUR EST POSÉ ET COMPTÉ AVANT LA COPIE, UN COMMIT REFUSÉ APRÈS ELLE SE DIT
    // -------------------------------------------------------------------------------------

    /// CE QU'IL TIENT, EN TROIS TEMPS :
    ///  * avance du curseur refusée (autorisateur : `UPDATE ledger_sink` interdit) — 503 `CAUSE_ENVOI_DU_PUITS_NON_FAIT`,
    ///    RIEN dans la copie, curseur à 0, transaction fermée ;
    ///  * `COMMIT` refusé — 503 `CAUSE_ENVOI_DU_PUITS_CURSEUR_NON_AVANCE`, la tranche EST dans la copie (une ligne), le
    ///    curseur n'a pas avancé ici ni à froid, transaction fermée ;
    ///  * levé — l'envoi réécrit la même tranche (200 `exported: 1`) : la copie porte la ligne DEUX fois et le
    ///    vérificateur y lit une « rupture de chaîne » (la copie ne tolère pas un doublon — c'est ce que la cause dit) ;
    ///    les lignes répétées écartées, elle se vérifie ; le curseur est validé, et l'envoi suivant n'exporte rien.
    ///
    /// LES MUTATIONS QUI LE FONT ROUGIR : l'avance avalée après la copie (la forme d'avant) — 200 et une ligne dans la
    /// copie au premier temps ; l'avance comptée mais écrite APRÈS la copie — une ligne dans la copie au premier temps
    /// (c'est la décision d'ordre qui est tenue) ; le `COMMIT` avalé — 200 au deuxième temps.
    #[tokio::test]
    async fn brev_l_avance_du_curseur_est_comptee_avant_la_copie_et_un_doublon_se_dit() {
        let _env = VERROU_ENV_PROCESSUS.write();
        let racine = crate::tmp_possede::TmpPossede::neuf("brev-curseur");
        let _pose = ReglageBackupPose::neuf("PLUME_LEDGER_EXPORT_DIR", &racine.to_string_lossy());
        let (st, p, id, copie) = brev_puits_fichier("brev-curseur", &racine);
        let curseur = "SELECT last_id FROM ledger_sink WHERE name='worm'";

        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Update { table_name, .. } if table_name == "ledger_sink" => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let (statut, corps, texte) = brev_envoyer(&st, id).await;
        let fermee = !brev_pendante(&st);
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert_eq!(statut, 503, "une avance de curseur refusée refuse l'envoi : {texte}");
        assert_eq!(corps["error"], json!(CAUSE_ENVOI_DU_PUITS_NON_FAIT), "{texte}");
        assert!(brev_lignes_de_la_copie(&copie).is_empty(), "RIEN dans la copie : le curseur est refusé AVANT qu'elle soit écrite");
        assert_eq!(brev_ici(&st, curseur), 0, "le curseur ne bouge pas");
        assert!(fermee, "la transaction de l'envoi est fermée");

        st.db.lock().authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Transaction { operation: TransactionOperation::Unknown } => Authorization::Deny,
            _ => Authorization::Allow,
        }));
        let (statut, corps, texte) = brev_envoyer(&st, id).await;
        let fermee = !brev_pendante(&st);
        st.db.lock().authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
        assert_eq!(statut, 503, "un COMMIT refusé après la copie ne rend pas `exported` : {texte}");
        assert_eq!(corps["error"], json!(CAUSE_ENVOI_DU_PUITS_CURSEUR_NON_AVANCE), "{texte}");
        assert_eq!(brev_lignes_de_la_copie(&copie).len(), 1, "la tranche EST dans la copie, comme la cause le dit");
        assert_eq!(brev_ici(&st, curseur), 0, "le curseur n'a pas avancé pour ce processus");
        assert_eq!(brev_a_froid(&p, curseur), 0, "ni au redémarrage");
        assert!(fermee, "la transaction de l'envoi est fermée");

        let (statut, corps, texte) = brev_envoyer(&st, id).await;
        assert_eq!(statut, 200, "levé, l'envoi part : {texte}");
        assert_eq!(corps["exported"], json!(1), "il réécrit la même tranche : {texte}");
        let lignes = brev_lignes_de_la_copie(&copie);
        assert_eq!(lignes.len(), 2, "la copie porte la ligne DEUX fois");
        let verdict = ledger_verify_export(&lignes, "");
        assert!(
            verdict.as_ref().is_err_and(|e| e.contains("rupture de chaîne")),
            "la copie ne tolère pas un doublon : le vérificateur y lit une rupture ({verdict:?})"
        );
        let mut vues = std::collections::HashSet::new();
        let sans_doublon: Vec<String> = lignes.into_iter().filter(|l| vues.insert(l.clone())).collect();
        assert_eq!(ledger_verify_export(&sans_doublon, ""), Ok(1), "les lignes répétées écartées, aucun maillon ne MANQUE");
        let tete = brev_ici(&st, "SELECT MAX(id) FROM ledger");
        assert_eq!(brev_a_froid(&p, curseur), tete, "le curseur est validé");
        let (statut, corps, _) = brev_envoyer(&st, id).await;
        assert_eq!((statut, corps["exported"].clone()), (200, json!(0)), "et l'envoi suivant n'a plus rien à exporter");
    }
}
