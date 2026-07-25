// Shared test helpers and cross-area *_TEST_LOCK statics.
// Extracted verbatim from the former single-file main_tests.rs (pure move).

    static RBA_ENV_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    // Sérialise les tests qui mutent PLUME_OTLP_* (gate + caps handler) — env process-global.
    static OTLP_ENV_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    // FIX #18 — sérialise les tests qui mutent PLUME_COLD_TIER/PLUME_COLD_DIR (gate cold des plafonds #49) — env
    // process-global. Uniquement compilé sous la feature cold_tier (les seuls tests qui touchent ces vars).
    #[cfg(feature = "cold_tier")]
    static COLD_CAPS_ENV_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static ENGAGEMENT_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static AUTOINDEX_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static CUSTOM_ROLES_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    fn test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../../../db/schema.sql")).unwrap();
        migrate(&conn);
        conn
    }

    /// Helper : insère un event env-scopé au ts donné. env_id + origin par défaut ('' = purgeable).
    fn ins_ev(c: &Connection, ts: i64, env: &str, msg: &str) {
        c.execute("INSERT INTO event(ts,source,message,env_id,origin) VALUES(?1,'agent',?2,?3,'')", params![ts, msg, env]).unwrap();
    }

    fn ergo_au(role: &str) -> AuthUser {
        AuthUser { name: format!("{role}-u"), role: role.into(), tenant: "default".into(), is_superadmin: false, method: "basic".into(), csrf: String::new(), env: None }
    }
