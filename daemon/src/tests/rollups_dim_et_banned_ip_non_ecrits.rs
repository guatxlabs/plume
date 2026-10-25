// =====================================================================================
// `P10.32-a` (hors `handlers/` : `rollups.rs`) — LA BORNE `dim_at_id` NON LUE NE TOUCHE NI LA TABLE NI LA COUVERTURE
// DU ROLLUP PAR DIMENSION ; LA PURGE DE SA FENÊTRE CHAUDE ENTRE DANS `dim_ok` ; LE WATERMARK DE `banned_ip` N'AVANCE QUE
// SI TOUS LES UPSERTS ONT RÉUSSI.
//
// LES DÉFAUTS, LUS SUR aa19c5fa :
//  * `rollup_events`, phase 3a : `dim_at_id` était lu par `.unwrap_or(0)`. Une lecture ratée valait 0 : la couverture
//    était rétractée, les tranches purgées puis ré-agrégées sous `id <= 0` (rien), `dim_ok` restait vrai et la
//    couverture était PUBLIÉE avec `at_id = 0` sur des tranches vides — la route servait des dimensions vides au lieu
//    du brut ;
//  * la purge de la fenêtre chaude (`DELETE … WHERE bucket >= recent`) était un `let _` : refusée, elle laissait les
//    orphelins top-N sous une couverture publiée quand même ;
//  * `materialize_banned_ip` : `let _ = conn.execute(upsert)` puis le watermark `banned_ip_wm` réécrit à `recent` quoi
//    qu'il arrive : un upsert refusé sur les heures définitives n'était JAMAIS rejoué, les bans manquaient pour toujours.
//
// DÉSORMAIS (décision par défaut, vague AC) : `dim_at_id` non lu -> ni rétractation, ni purge, ni ré-agrégation
// (tranches et fenêtre chaude), ni publication, avertissement au journal ; la purge chaude refusée -> rien publié ;
// chaque upsert de `banned_ip` est lu, un refus est compté et dit (cause du moteur), le watermark reste en place et la
// tranche est rejouée au passage suivant.
//
// LES VOIES D'ÉCHEC FABRIQUÉES, par AUTORISATEUR :
//  * borne : refus des lectures d'`event.id` faites AVANT `event.ts`, SEULEMENT après le premier `DELETE` sur
//    `event_rollup` (la purge chaude d'`event_rollup`, jouée après la borne `new_cov` et avant `dim_at_id`) : la borne
//    `new_cov` est donc lue (prémisse : couverture d'`event_rollup` à `MAX(id)`), `dim_at_id` seule est refusée
//    (prémisse : exactement un refus) ;
//  * purge chaude : refus de tout `DELETE` sur `event_dim_rollup` en régime établi (aucune tranche : le seul `DELETE`
//    est celui de la fenêtre chaude ; prémisse : exactement un refus) ;
//  * tranche : refus du PREMIER `DELETE` sur `event_dim_rollup` quand deux tranches sont à reconstruire (tranche basse ;
//    la haute et la fenêtre chaude passent ; prémisses : trois `DELETE`, un refus) ;
//  * upserts : refus du k-ième `INSERT` préparé sur `banned_ip` (ordre : trois définitifs puis trois chauds).
//
// CE QUE CE TÉMOIN NE TIENT PAS : une lecture ratée par interruption réelle (même branche `Err`) ; le plancher
// `MIN(event.ts)` et la purge des tranches bornée aux groupes resservis par `event` (traités et témoignés à part :
// `rollups_buckets_resservis_et_retention_illisible.rs`) ; un refus d'upsert qui dure plus que la fenêtre de rattrapage de `banned_ip`
// (limite écrite dans `rollups.rs`) ; la bande volatile non rafraîchie pendant un passage à borne non lue (limite écrite).
//
// LES MUTATIONS QUI LE FONT ROUGIR (variable d'environnement de mutation sous `cfg!(test)`, puis retirées du source) :
//  * « AC4_DIM_ZERO » (la forme d'avant : borne non lue traitée comme lue à 0) : table, couverture ;
//  * « AC4_DIM_RETRACTE » (couverture rétractée malgré le non-lu) : couverture ;
//  * « AC4_DIM_TRANCHES » (tranches purgées et ré-agrégées malgré le non-lu) : table ;
//  * « AC4_DIM_CHAUDE » (fenêtre chaude purgée et ré-agrégée malgré le non-lu) : table ;
//  * « AC4_DIM_PUBLIE » (couverture publiée malgré le non-lu) : couverture ;
//  * « AC4_CHAUDE_HORS_DIMOK » (purge chaude refusée hors de `dim_ok`, la forme d'avant) : couverture publiée ;
//  * « AC4_CHAUDE_ECRASE » (`dim_ok = …` sur la purge chaude : une tranche refusée avant est effacée) : couverture publiée ;
//  * « AC4_WM_AVANCE » (watermark avancé malgré un refus, la forme d'avant) : watermark, ban non rejoué ;
//  * « AC4_REFUS_ECRASE » (un upsert réussi remet le compte de refus à zéro) : watermark ;
//  * « AC4_CHAUD_NON_COMPTE » (refus de la fenêtre chaude non comptés) : watermark ;
//  * « AC4_DIM_SANS_JOURNAL », « AC4_BAN_SANS_JOURNAL » (lignes de journal retirées) : capture du stderr.
// =====================================================================================
mod rollups_dim_et_banned_ip_non_ecrits {
    use super::*;
    use crate::rollup_coverage::{META_DIM_ROLLUP_COV, META_ROLLUP_COV_ID};
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const RDBI_IP_BANNIE: &str = "192.0.2.10";

    fn rdbi_recent() -> i64 {
        ((now() / 3600) * 3600 - 3600).max(0)
    }

    fn rdbi_meta(conn: &rusqlite::Connection, cle: &str) -> Option<String> {
        conn.query_row("SELECT CAST(value AS TEXT) FROM meta WHERE key=?1", params![cle], |r| r.get(0)).ok()
    }

    /// Image complète d'`event_dim_rollup` (ordre stable) : « la table n'a pas bougé » se juge par égalité.
    fn rdbi_table_dim(conn: &rusqlite::Connection) -> String {
        conn.query_row(
            "SELECT COALESCE(group_concat(l, ';'), '') FROM (SELECT bucket||'|'||source||'|'||dim||'|'||val||'|'||n||'|'||env_id AS l \
             FROM event_dim_rollup ORDER BY bucket, source, dim, val, env_id)",
            [],
            |r| r.get(0),
        )
        .unwrap()
    }

    fn rdbi_n_dim(conn: &rusqlite::Connection, bucket: i64, val: &str) -> i64 {
        conn.query_row(
            "SELECT COALESCE(SUM(n),0) FROM event_dim_rollup WHERE bucket=?1 AND source='web' AND dim='status' AND val=?2",
            params![bucket, val],
            |r| r.get(0),
        )
        .unwrap()
    }

    fn rdbi_web(conn: &rusqlite::Connection, ts: i64, status: &str) -> i64 {
        conn.execute(
            "INSERT INTO event(ts,host,source,severity,message,fields) VALUES(?1,'rdbi','web',1,'m',?2)",
            params![ts, format!("{{\"status\":\"{status}\"}}")],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    /// Fixture : un event `web` à `recent - 7200` (status 200) et un chaud (`now - 10`, status 500), un passage nominal
    /// (bande publiée), puis la couverture ramenée à une bande VIDE posée à `recent - 3600` : le passage suivant a une
    /// tranche à reconstruire (le front bas `[recent - 7200, recent - 3600)`, qui porte le bucket n=1). Enfin un second
    /// event chaud (status 500) : un rafraîchissement de la fenêtre chaude changerait son compte. Rend la couverture posée.
    fn rdbi_tranche_a_reconstruire(conn: &rusqlite::Connection, recent: i64) -> String {
        rdbi_web(conn, recent - 7200, "200");
        rdbi_web(conn, now() - 10, "500");
        rollup_events(conn);
        let id: i64 = conn.query_row("SELECT MAX(id) FROM event", [], |r| r.get(0)).unwrap();
        assert_eq!(rdbi_meta(conn, META_DIM_ROLLUP_COV), Some(format!("{}|{recent}|{recent}|{id}", recent - 7200)), "prémisse : bande publiée par le passage nominal");
        assert_eq!(rdbi_n_dim(conn, recent - 7200, "200"), 1, "prémisse : bucket agrégé");
        let cov = format!("{}|{}|{recent}|{id}", recent - 3600, recent - 3600);
        conn.execute("UPDATE meta SET value=?1 WHERE key=?2", params![cov, META_DIM_ROLLUP_COV]).unwrap();
        rdbi_web(conn, now() - 10, "500");
        cov
    }

    /// Autorisateur qui refuse les lectures d'`event.id` faites avant `event.ts`, seulement après le premier `DELETE` sur
    /// `event_rollup` : `dim_at_id` seule. Rend le nombre de refus.
    fn rdbi_refuser_dim_at_id(conn: &rusqlite::Connection) -> Arc<AtomicUsize> {
        let refus = Arc::new(AtomicUsize::new(0));
        let compteur = refus.clone();
        let mut ts_lu = false;
        let mut rollup_purge = false;
        conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Select => {
                ts_lu = false;
                Authorization::Allow
            }
            AuthAction::Delete { table_name: "event_rollup" } => {
                rollup_purge = true;
                Authorization::Allow
            }
            AuthAction::Read { table_name: "event", column_name: "ts" } => {
                ts_lu = true;
                Authorization::Allow
            }
            AuthAction::Read { table_name: "event", column_name: "id" } if !ts_lu && rollup_purge => {
                compteur.fetch_add(1, Ordering::Relaxed);
                Authorization::Deny
            }
            _ => Authorization::Allow,
        }));
        refus
    }

    fn rdbi_sans_autorisateur(conn: &rusqlite::Connection) {
        conn.authorizer::<fn(AuthContext<'_>) -> Authorization>(None);
    }

    /// `dim_at_id` NON LUE : la table `event_dim_rollup` est identique (avant : tranche purgée et ré-agrégée à vide), la
    /// couverture inchangée (avant : rétractée puis republiée avec `at_id = 0`). Contrôle : borne lue, la tranche est
    /// reconstruite et la couverture publiée à `MAX(id)`.
    #[test]
    fn rdbi_une_borne_dim_non_lue_ne_touche_ni_la_table_ni_la_couverture() {
        let _env = VERROU_ENV_PROCESSUS.read(); // rollup_events et materialize_banned_ip lisent cfg()
        let recent = rdbi_recent();
        {
            let (st, _p) = sp_state("rdbi-dim-lue");
            let conn = st.db.lock();
            rdbi_tranche_a_reconstruire(&conn, recent);
            rollup_events(&conn);
            let id: i64 = conn.query_row("SELECT MAX(id) FROM event", [], |r| r.get(0)).unwrap();
            assert_eq!(rdbi_meta(&conn, META_DIM_ROLLUP_COV), Some(format!("{}|{recent}|{recent}|{id}", recent - 7200)), "contrôle : couverture republiée à la borne");
            assert_eq!(rdbi_n_dim(&conn, recent - 7200, "200"), 1, "contrôle : la tranche est reconstruite");
        }
        let (st, _p) = sp_state("rdbi-dim-non-lue");
        let conn = st.db.lock();
        let cov = rdbi_tranche_a_reconstruire(&conn, recent);
        let avant = rdbi_table_dim(&conn);
        let refus = rdbi_refuser_dim_at_id(&conn);
        rollup_events(&conn);
        rdbi_sans_autorisateur(&conn);
        let id: i64 = conn.query_row("SELECT MAX(id) FROM event", [], |r| r.get(0)).unwrap();
        assert_eq!(refus.load(Ordering::Relaxed), 1, "prémisse : la lecture de dim_at_id (et elle seule) a été refusée");
        assert_eq!(rdbi_meta(&conn, META_ROLLUP_COV_ID), Some(id.to_string()), "prémisse : la borne d'event_rollup a été lue");
        assert_eq!(rdbi_meta(&conn, META_DIM_ROLLUP_COV), Some(cov), "borne non lue : la couverture n'est ni rétractée ni republiée");
        assert_eq!(rdbi_table_dim(&conn), avant, "borne non lue : event_dim_rollup n'est ni purgée ni ré-agrégée (tranches et fenêtre chaude)");
    }

    /// Régime établi (aucune tranche), purge de la fenêtre chaude REFUSÉE : la couverture n'est pas republiée (elle reste
    /// rétractée, la route sert le brut). Contrôle : sans refus, elle est republiée.
    #[test]
    fn rdbi_une_purge_chaude_refusee_ne_publie_pas() {
        let _env = VERROU_ENV_PROCESSUS.read(); // rollup_events et materialize_banned_ip lisent cfg()
        let recent = rdbi_recent();
        let etabli = |conn: &rusqlite::Connection| {
            rdbi_web(conn, recent - 7200, "200");
            rdbi_web(conn, now() - 10, "500");
            rollup_events(conn);
            assert!(rdbi_meta(conn, META_DIM_ROLLUP_COV).is_some(), "prémisse : couverture établie");
        };
        {
            let (st, _p) = sp_state("rdbi-chaude-ok");
            let conn = st.db.lock();
            etabli(&conn);
            rollup_events(&conn);
            assert!(rdbi_meta(&conn, META_DIM_ROLLUP_COV).is_some(), "contrôle : couverture republiée");
        }
        let (st, _p) = sp_state("rdbi-chaude-refusee");
        let conn = st.db.lock();
        etabli(&conn);
        let refus = Arc::new(AtomicUsize::new(0));
        let compteur = refus.clone();
        conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Delete { table_name: "event_dim_rollup" } => {
                compteur.fetch_add(1, Ordering::Relaxed);
                Authorization::Deny
            }
            _ => Authorization::Allow,
        }));
        rollup_events(&conn);
        rdbi_sans_autorisateur(&conn);
        assert_eq!(refus.load(Ordering::Relaxed), 1, "prémisse : un seul DELETE sur event_dim_rollup (la purge chaude), refusé");
        assert_eq!(rdbi_meta(&conn, META_DIM_ROLLUP_COV), None, "purge chaude refusée : aucune couverture publiée");
    }

    /// Tranche BASSE refusée (premier `DELETE` sur `event_dim_rollup`), tranche haute et purge chaude RÉUSSIES : rien
    /// n'est publié. Le refus d'une tranche reste dans `dim_ok` jusqu'à la publication : une purge chaude réussie ensuite
    /// ne l'efface pas. MUTATION : `AC4_CHAUDE_ECRASE` (`dim_ok = …` au lieu de `dim_ok &= …` sur la purge chaude).
    /// Contrôle (même fixture, sans refus) : `rdbi_une_borne_dim_non_lue_ne_touche_ni_la_table_ni_la_couverture`.
    #[test]
    fn rdbi_une_tranche_refusee_puis_une_purge_chaude_reussie_ne_publie_pas() {
        let _env = VERROU_ENV_PROCESSUS.read(); // rollup_events lit cfg()
        let recent = rdbi_recent();
        let (st, _p) = sp_state("rdbi-tranche-basse-refusee");
        let conn = st.db.lock();
        rdbi_tranche_a_reconstruire(&conn, recent);
        let refus = Arc::new(AtomicUsize::new(0));
        let purges = Arc::new(AtomicUsize::new(0));
        let (compteur, vus) = (refus.clone(), purges.clone());
        conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Delete { table_name: "event_dim_rollup" } => {
                if vus.fetch_add(1, Ordering::Relaxed) == 0 {
                    compteur.fetch_add(1, Ordering::Relaxed);
                    Authorization::Deny
                } else {
                    Authorization::Allow
                }
            }
            _ => Authorization::Allow,
        }));
        rollup_events(&conn);
        rdbi_sans_autorisateur(&conn);
        assert_eq!(purges.load(Ordering::Relaxed), 3, "prémisse : trois DELETE sur event_dim_rollup (tranche basse, tranche haute, fenêtre chaude)");
        assert_eq!(refus.load(Ordering::Relaxed), 1, "prémisse : seule la purge de la tranche basse est refusée");
        assert_eq!(rdbi_meta(&conn, META_DIM_ROLLUP_COV), None, "tranche refusée puis purge chaude réussie : aucune couverture publiée");
    }

    fn rdbi_ban(conn: &rusqlite::Connection, ts: i64) {
        conn.execute(
            "INSERT INTO event(ts,host,source,category,severity,message,src_ip,fields) VALUES(?1,'rdbi','fail2ban','ban',2,'ban',?2,'{\"jail\":\"sshd\"}')",
            params![ts, RDBI_IP_BANNIE],
        )
        .unwrap();
    }

    fn rdbi_bannie(conn: &rusqlite::Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM banned_ip WHERE src_ip=?1 AND source='fail2ban'", params![RDBI_IP_BANNIE], |r| r.get(0)).unwrap()
    }

    /// Refuse le `rang`-ième `INSERT` préparé sur `banned_ip` (1 = définitif fail2ban, 4 = chaud fail2ban). Rend le
    /// nombre de refus.
    fn rdbi_refuser_l_upsert(conn: &rusqlite::Connection, rang: usize) -> Arc<AtomicUsize> {
        let refus = Arc::new(AtomicUsize::new(0));
        let compteur = refus.clone();
        let mut vus = 0usize;
        conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
            AuthAction::Insert { table_name: "banned_ip" } => {
                vus += 1;
                if vus == rang {
                    compteur.fetch_add(1, Ordering::Relaxed);
                    Authorization::Deny
                } else {
                    Authorization::Allow
                }
            }
            _ => Authorization::Allow,
        }));
        refus
    }

    /// Un ban à `recent - 7200`, watermark à `recent - 7200` : la tranche définitive `[recent - 7200, recent)` le porte.
    fn rdbi_depart_ban(conn: &rusqlite::Connection, recent: i64) {
        rdbi_ban(conn, recent - 7200);
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('banned_ip_wm', ?1)", params![(recent - 7200).to_string()]).unwrap();
    }

    /// Upsert DÉFINITIF refusé : le watermark reste à `recent - 7200` (avant : `recent`), le ban manque ; au passage
    /// suivant (sans refus) la tranche est REJOUÉE : le ban entre, le watermark avance. Contrôle : sans refus, le ban
    /// entre et le watermark avance au premier passage.
    #[test]
    fn rdbi_un_upsert_definitif_refuse_laisse_le_watermark_et_la_tranche_est_rejouee() {
        let _env = VERROU_ENV_PROCESSUS.read(); // rollup_events et materialize_banned_ip lisent cfg()
        let recent = rdbi_recent();
        {
            let (st, _p) = sp_state("rdbi-ban-ok");
            let conn = st.db.lock();
            rdbi_depart_ban(&conn, recent);
            materialize_banned_ip(&conn);
            assert_eq!(rdbi_bannie(&conn), 1, "contrôle : le ban entre");
            assert_eq!(rdbi_meta(&conn, "banned_ip_wm"), Some(recent.to_string()), "contrôle : watermark avancé");
        }
        let (st, _p) = sp_state("rdbi-ban-definitif-refuse");
        let conn = st.db.lock();
        rdbi_depart_ban(&conn, recent);
        let refus = rdbi_refuser_l_upsert(&conn, 1);
        materialize_banned_ip(&conn);
        rdbi_sans_autorisateur(&conn);
        assert_eq!(refus.load(Ordering::Relaxed), 1, "prémisse : l'upsert définitif fail2ban (et lui seul) a été refusé");
        assert_eq!(rdbi_bannie(&conn), 0, "prémisse : le ban manque après le refus");
        assert_eq!(rdbi_meta(&conn, "banned_ip_wm"), Some((recent - 7200).to_string()), "upsert refusé : le watermark n'avance PAS");
        materialize_banned_ip(&conn);
        assert_eq!(rdbi_bannie(&conn), 1, "passage suivant : la tranche est rejouée, le ban entre");
        assert_eq!(rdbi_meta(&conn, "banned_ip_wm"), Some(recent.to_string()), "passage suivant : le watermark avance");
    }

    /// Upsert de la fenêtre CHAUDE refusé (les définitifs réussis) : le watermark reste aussi en place — « tous » veut dire
    /// tous ; le rejeu est idempotent (MIN/MAX).
    #[test]
    fn rdbi_un_upsert_chaud_refuse_laisse_aussi_le_watermark() {
        let _env = VERROU_ENV_PROCESSUS.read(); // rollup_events et materialize_banned_ip lisent cfg()
        let recent = rdbi_recent();
        let (st, _p) = sp_state("rdbi-ban-chaud-refuse");
        let conn = st.db.lock();
        rdbi_depart_ban(&conn, recent);
        let refus = rdbi_refuser_l_upsert(&conn, 4);
        materialize_banned_ip(&conn);
        rdbi_sans_autorisateur(&conn);
        assert_eq!(refus.load(Ordering::Relaxed), 1, "prémisse : l'upsert chaud fail2ban (et lui seul) a été refusé");
        assert_eq!(rdbi_bannie(&conn), 1, "prémisse : la tranche définitive est écrite");
        assert_eq!(rdbi_meta(&conn, "banned_ip_wm"), Some((recent - 7200).to_string()), "upsert chaud refusé : le watermark n'avance PAS");
    }

    /// LES LIGNES DE JOURNAL, lues sur le stderr d'un sous-processus : `dim_at_id` refusée écrit UNE ligne
    /// `[rollup] WARN borne d'identifiant du rollup par dimension NON lue (<moteur>)` ; un upsert refusé écrit UNE ligne
    /// `[rollup] WARN upsert de banned_ip NON écrit (<moteur>)` ; le nominal n'écrit aucune des deux. MUTATIONS :
    /// `AC4_DIM_SANS_JOURNAL`, `AC4_BAN_SANS_JOURNAL`.
    #[test]
    fn rdbi_lignes_de_journal_de_la_borne_dim_et_des_upserts() {
        let _env = VERROU_ENV_PROCESSUS.read(); // rollup_events et materialize_banned_ip lisent cfg()
        const ENFANT: &str = "RDBI_ENFANT_JOURNAL";
        const PHASE: &str = "RDBI-PHASE:";
        const LIGNE_DIM: &str = "[rollup] WARN borne d'identifiant du rollup par dimension NON lue (";
        const LIGNE_BAN: &str = "[rollup] WARN upsert de banned_ip NON écrit (";
        // Cause du moteur : un `Read` refusé rend « access to event.id is prohibited », un `Insert` refusé « not authorized ».
        const MOTEUR_DIM: &str = "access to event.id is prohibited";
        const MOTEUR_BAN: &str = "not authorized";
        if std::env::var(ENFANT).is_ok() {
            let recent = rdbi_recent();
            eprintln!("{PHASE}dim");
            let (st, _p) = sp_state("rdbi-journal-dim");
            let conn = st.db.lock();
            rdbi_tranche_a_reconstruire(&conn, recent);
            let refus = rdbi_refuser_dim_at_id(&conn);
            rollup_events(&conn);
            rdbi_sans_autorisateur(&conn);
            println!("RDBI-REFUS-DIM:{}", refus.load(Ordering::Relaxed));
            drop(conn);
            eprintln!("{PHASE}ban");
            let (st, _p) = sp_state("rdbi-journal-ban");
            let conn = st.db.lock();
            rdbi_depart_ban(&conn, recent);
            let refus = rdbi_refuser_l_upsert(&conn, 1);
            materialize_banned_ip(&conn);
            rdbi_sans_autorisateur(&conn);
            println!("RDBI-REFUS-BAN:{}", refus.load(Ordering::Relaxed));
            drop(conn);
            eprintln!("{PHASE}calme");
            let (st, _p) = sp_state("rdbi-journal-calme");
            let conn = st.db.lock();
            rdbi_tranche_a_reconstruire(&conn, recent);
            rollup_events(&conn);
            rdbi_depart_ban(&conn, recent);
            materialize_banned_ip(&conn);
            drop(conn);
            eprintln!("{PHASE}fin");
            return;
        }
        let sortie = std::process::Command::new(std::env::current_exe().expect("binaire de test"))
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "tests::rollups_dim_et_banned_ip_non_ecrits::rdbi_lignes_de_journal_de_la_borne_dim_et_des_upserts",
            ])
            .env(ENFANT, "1")
            .output()
            .expect("ré-exécution du binaire de test");
        let stdout = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&sortie.stderr).into_owned();
        assert_eq!(sortie.status.code(), Some(0), "contrôle : l'enfant sort en 0 : {stdout}\n{stderr}");
        for m in ["RDBI-REFUS-DIM:1", "RDBI-REFUS-BAN:1"] {
            assert!(stdout.contains(m), "contrôle : {m} : {stdout}");
        }
        let phase = |nom: &str, tete: &str| -> Vec<String> {
            let debut = stderr.split_once(&format!("{PHASE}{nom}")).unwrap_or_else(|| panic!("contrôle : phase {nom} : {stderr}")).1;
            let corps = debut.split_once(PHASE).map(|(c, _)| c).unwrap_or(debut);
            corps.lines().filter(|l| l.starts_with(tete)).map(str::to_string).collect()
        };
        let dim = phase("dim", LIGNE_DIM);
        assert_eq!(dim.len(), 1, "phase dim : une ligne et une seule : {dim:?}");
        assert!(dim[0].contains(MOTEUR_DIM), "phase dim : la cause du moteur : {}", dim[0]);
        let ban = phase("ban", LIGNE_BAN);
        assert_eq!(ban.len(), 1, "phase ban : une ligne par upsert refusé : {ban:?}");
        assert!(ban[0].contains(MOTEUR_BAN), "phase ban : la cause du moteur : {}", ban[0]);
        assert!(phase("calme", LIGNE_DIM).is_empty() && phase("calme", LIGNE_BAN).is_empty(), "le nominal n'écrit aucune des deux lignes");
    }
}
