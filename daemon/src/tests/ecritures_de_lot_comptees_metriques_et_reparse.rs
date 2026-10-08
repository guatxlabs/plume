// =====================================================================================
// `P10.27-i` — LES ÉCRITURES D'UN LOT DE MÉTRIQUES ET DU REPARSE SONT COMPTÉES, ET UNE LIGNE REFUSÉE REFUSE LE GESTE.
//
// LE DÉFAUT, RE-MESURÉ SUR `af310b3` : `metrics_prom` et `metrics_write` jetaient le résultat de chaque `insert_metric`
// (`let _ =`) dans une transaction pourtant propre depuis `P10.26-s`, puis la validaient : un `INSERT` refusé rendait
// 200 `ingested: n` (n = séries LUES) ou 204 (le WAL de l'émetteur avance, sa copie disparaît). Le reparse jetait ses
// trois `UPDATE event` et servait `updated: changes.len()` — le compte de ce qu'il voulait écrire.
//
// LA FABRIQUE DU REFUS : un déclencheur `RAISE(ABORT)` sur UNE ligne du lot (la base refuse cette ligne, les autres
// passent) ; `RAISE(IGNORE)` fabrique un `Ok(0)`, écart voulu par la base, qui n'est PAS un refus mais n'est pas compté.
//
// MUTANTS (joués par `VERIF_MUT`, retirés avant le commit) : `F8_PROM`, `F8_RW`, `F8_REPARSE` — chacun rend au site la
// forme d'avant (le refus avalé et compté comme écrit).
//
// CE QUE CES TÉMOINS NE TIENNENT PAS : un refus par disque plein ou lecture seule n'est pas fabriqué (le moteur peut
// alors annuler lui-même la transaction, ce que `RAISE(ABORT)` ne fait pas — l'annulation par le moteur est jouée
// par `reparse_juge_chaque_update_et_compte_les_events.rs`) ; le mode multi-tenant n'est pas joué ; le comportement
// réel de réémission d'Alloy/Prometheus sur ce 503 n'est pas exercé.
// =====================================================================================
mod ecritures_de_lot_comptees_metriques_et_reparse {
    use super::*;

    async fn ecl_corps(r: Response) -> (u16, Value, String) {
        let statut = r.status().as_u16();
        let b = axum::body::to_bytes(r.into_body(), usize::MAX).await.expect("corps lisible");
        let texte = String::from_utf8_lossy(&b).into_owned();
        (statut, serde_json::from_str(&texte).unwrap_or(Value::Null), texte)
    }

    fn ecl_adm() -> AuthUser {
        sp_au("adm", "admin")
    }

    fn ecl_ici(st: &AppState, sql: &str) -> i64 {
        st.db.lock().query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("fixture : `{sql}` se lit ({e})"))
    }

    fn ecl_a_froid(p: &crate::tmp_possede::TmpDb, sql: &str) -> i64 {
        let c = open_db(p.as_str()).expect("relecture à froid");
        c.query_row(sql, [], |r| r.get(0)).unwrap_or_else(|e| panic!("relecture à froid de `{sql}` ({e})"))
    }

    fn ecl_sql(st: &AppState, sql: &str) {
        st.db.lock().execute_batch(sql).unwrap_or_else(|e| panic!("fixture : `{sql}` ({e})"));
    }

    #[derive(prost::Message)]
    struct EclEcriture {
        #[prost(message, repeated, tag = "1")]
        timeseries: Vec<EclSerie>,
    }
    #[derive(prost::Message)]
    struct EclSerie {
        #[prost(message, repeated, tag = "1")]
        labels: Vec<EclEtiquette>,
        #[prost(message, repeated, tag = "2")]
        samples: Vec<EclPoint>,
    }
    #[derive(prost::Message)]
    struct EclEtiquette {
        #[prost(string, tag = "1")]
        name: String,
        #[prost(string, tag = "2")]
        value: String,
    }
    #[derive(prost::Message)]
    struct EclPoint {
        #[prost(double, tag = "1")]
        value: f64,
        #[prost(int64, tag = "2")]
        timestamp: i64,
    }

    fn ecl_lot_remote_write(noms: &[&str]) -> axum::body::Bytes {
        use prost::Message;
        let lot = EclEcriture {
            timeseries: noms
                .iter()
                .map(|n| EclSerie {
                    labels: vec![EclEtiquette { name: "__name__".into(), value: (*n).into() }],
                    samples: vec![EclPoint { value: 1.0, timestamp: now() * 1000 }],
                })
                .collect(),
        };
        let mut brut = Vec::new();
        lot.encode(&mut brut).expect("fixture : encodage protobuf");
        axum::body::Bytes::from(snap::raw::Encoder::new().compress_vec(&brut).expect("fixture : snappy"))
    }

    const ECL_PROM: &str = "SELECT COUNT(*) FROM metric WHERE name IN ('ecl_prom_ok','ecl_prom_refusee')";
    const ECL_RW: &str = "SELECT COUNT(*) FROM metric WHERE name IN ('ecl_rw_ok','ecl_rw_refusee')";

    /// (1) `metrics_prom` — une ligne refusée : 503 `CAUSE_LIGNE_DU_LOT_REFUSEE`, AUCUNE ligne du lot (ni ici ni à froid),
    /// transaction fermée. INVERSE : sans refus, 200 et le corps exact `{"ingested":2,"durable":false}` ; une ligne
    /// ignorée par la base (`RAISE(IGNORE)`) : 200 `ingested: 1`, une ligne en base — le compte est celui des ÉCRITES.
    /// MUTATION : `F8_PROM` (refus avalé, compté) — 200 `ingested: 2`, une ligne validée.
    #[tokio::test]
    async fn ecl_metrics_prom_refuse_le_lot_a_la_ligne_refusee_et_compte_les_ecrites() {
        let (st, p) = sp_state("ecl-prom");
        let lot = "ecl_prom_ok 1\necl_prom_refusee 2\n".to_string();
        ecl_sql(&st, "CREATE TRIGGER ecl_refus_prom BEFORE INSERT ON metric WHEN NEW.name='ecl_prom_refusee' BEGIN SELECT RAISE(ABORT,'ecl refus'); END;");
        let (statut, corps, texte) = ecl_corps(metrics_prom(State(st.clone()), Extension(ecl_adm()), Query(HashMap::new()), lot.clone()).await).await;
        assert_eq!(statut, 503, "une ligne refusée refuse le lot : {texte}");
        assert_eq!(corps["error"], json!(CAUSE_LIGNE_DU_LOT_REFUSEE), "{texte}");
        assert!(st.db.lock().is_autocommit(), "la transaction du lot est fermée");
        assert_eq!(ecl_ici(&st, ECL_PROM), 0, "aucune ligne du lot n'est écrite, comme la cause le dit");
        assert_eq!(ecl_a_froid(&p, ECL_PROM), 0, "ni validée");

        ecl_sql(&st, "DROP TRIGGER ecl_refus_prom;");
        let (statut, corps, texte) = ecl_corps(metrics_prom(State(st.clone()), Extension(ecl_adm()), Query(HashMap::new()), lot.clone()).await).await;
        assert_eq!(statut, 200, "{texte}");
        assert_eq!(corps, json!({ "ingested": 2, "durable": false }), "chemin nominal : corps inchangé : {texte}");
        assert_eq!(ecl_a_froid(&p, ECL_PROM), 2);

        ecl_sql(&st, "DELETE FROM metric WHERE name IN ('ecl_prom_ok','ecl_prom_refusee');
                      CREATE TRIGGER ecl_ignore_prom BEFORE INSERT ON metric WHEN NEW.name='ecl_prom_refusee' BEGIN SELECT RAISE(IGNORE); END;");
        let (statut, corps, texte) = ecl_corps(metrics_prom(State(st.clone()), Extension(ecl_adm()), Query(HashMap::new()), lot).await).await;
        assert_eq!(statut, 200, "une ligne ignorée par la base n'est pas un refus : {texte}");
        assert_eq!(corps["ingested"], json!(1), "`ingested` compte les lignes ÉCRITES : {texte}");
        assert_eq!(ecl_a_froid(&p, ECL_PROM), 1);
    }

    /// (2) `metrics_write` — une ligne refusée : 503 `CAUSE_LIGNE_DU_LOT_REFUSEE` (l'émetteur réémet, son WAL garde le
    /// lot), aucune ligne écrite, transaction fermée. INVERSE : sans refus, 204 sans corps et deux lignes.
    /// MUTATION : `F8_RW` — 204, une ligne validée, l'autre perdue.
    #[tokio::test]
    async fn ecl_metrics_write_ne_rend_204_que_si_toutes_les_lignes_sont_ecrites() {
        let (st, p) = sp_state("ecl-rw");
        ecl_sql(&st, "CREATE TRIGGER ecl_refus_rw BEFORE INSERT ON metric WHEN NEW.name='ecl_rw_refusee' BEGIN SELECT RAISE(ABORT,'ecl refus'); END;");
        let lot = ecl_lot_remote_write(&["ecl_rw_ok", "ecl_rw_refusee"]);
        let (statut, corps, texte) = ecl_corps(metrics_write(State(st.clone()), Extension(ecl_adm()), lot.clone()).await).await;
        assert_eq!(statut, 503, "une ligne refusée : pas de 204 qui ferait jeter le lot à l'émetteur : {texte}");
        assert_eq!(corps["error"], json!(CAUSE_LIGNE_DU_LOT_REFUSEE), "{texte}");
        assert!(st.db.lock().is_autocommit(), "la transaction du lot est fermée");
        assert_eq!(ecl_ici(&st, ECL_RW), 0, "aucune ligne du lot n'est écrite");
        assert_eq!(ecl_a_froid(&p, ECL_RW), 0);

        ecl_sql(&st, "DROP TRIGGER ecl_refus_rw;");
        let (statut, _, texte) = ecl_corps(metrics_write(State(st.clone()), Extension(ecl_adm()), lot).await).await;
        assert_eq!(statut, 204, "{texte}");
        assert!(texte.is_empty(), "chemin nominal : 204 sans corps");
        assert_eq!(ecl_a_froid(&p, ECL_RW), 2, "le lot réémis est écrit UNE fois");
    }

    const ECL_PROMUS: &str = "SELECT COUNT(*) FROM event WHERE source IN ('eclok','eclrefus') AND src_ip='198.51.100.9'";

    /// (3) le reparse — un `UPDATE event` refusé : 503 `CAUSE_REPARSE_NON_APPLIQUE`, AUCUN event modifié (ni ici ni à
    /// froid), transaction fermée. INVERSE : sans refus, 200 `updated: 2` ; un `UPDATE` ignoré par la base : 200
    /// `matched: 2`, `updated: 1` — `updated` compte les events réellement modifiés, `matched` reste le compte d'entrée.
    /// MUTATION : `F8_REPARSE` — 200 `updated: 2`, un event promu validé.
    #[tokio::test]
    async fn ecl_le_reparse_compte_ses_mises_a_jour_et_refuse_sur_un_update_refuse() {
        let _reglages = VERROU_ENV_PROCESSUS.read();
        let (st, p) = sp_state("ecl-reparse");
        let inserer = "INSERT INTO event(ts,source,message,fields,origin) VALUES
            (strftime('%s','now')-60,'eclok','m','{\"src_ip\":\"198.51.100.9\"}',''),
            (strftime('%s','now')-60,'eclrefus','m','{\"src_ip\":\"198.51.100.9\"}','');";
        ecl_sql(&st, inserer);
        ecl_sql(&st, "CREATE TRIGGER ecl_refus_ev BEFORE UPDATE ON event WHEN NEW.source='eclrefus' BEGIN SELECT RAISE(ABORT,'ecl refus'); END;");
        let (statut, corps, texte) = ecl_corps(parser_reparse(State(st.clone()), Extension(ecl_adm()), Json(json!({}))).await).await;
        assert_eq!(statut, 503, "un UPDATE refusé refuse le reparse : {texte}");
        assert_eq!(corps["error"], json!(CAUSE_REPARSE_NON_APPLIQUE), "{texte}");
        assert!(st.db.lock().is_autocommit(), "la transaction du reparse est fermée");
        assert_eq!(ecl_ici(&st, ECL_PROMUS), 0, "aucun event modifié, comme la cause le dit");
        assert_eq!(ecl_a_froid(&p, ECL_PROMUS), 0);

        ecl_sql(&st, "DROP TRIGGER ecl_refus_ev;");
        let (statut, corps, texte) = ecl_corps(parser_reparse(State(st.clone()), Extension(ecl_adm()), Json(json!({}))).await).await;
        assert_eq!(statut, 200, "{texte}");
        assert_eq!(corps["updated"], json!(2), "{texte}");
        assert_eq!(ecl_a_froid(&p, ECL_PROMUS), 2);

        ecl_sql(&st, "DELETE FROM event WHERE source IN ('eclok','eclrefus');");
        ecl_sql(&st, inserer);
        ecl_sql(&st, "CREATE TRIGGER ecl_ignore_ev BEFORE UPDATE ON event WHEN NEW.source='eclrefus' BEGIN SELECT RAISE(IGNORE); END;");
        let (statut, corps, texte) = ecl_corps(parser_reparse(State(st.clone()), Extension(ecl_adm()), Json(json!({}))).await).await;
        assert_eq!(statut, 200, "un UPDATE ignoré par la base n'est pas un refus : {texte}");
        assert_eq!(corps["matched"], json!(2), "{texte}");
        assert_eq!(corps["updated"], json!(1), "`updated` compte les events réellement modifiés : {texte}");
        assert_eq!(ecl_a_froid(&p, ECL_PROMUS), 1);
    }
}
