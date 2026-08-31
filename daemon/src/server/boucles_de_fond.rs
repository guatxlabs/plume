//! server::boucles_de_fond — LE LANCEMENT DES BOUCLES DE SERVICE et les boucles elles-mêmes : ingest,
//! ordonnanceur des règles de détection, maintenance du ban natif, ticks connecteurs et destinations,
//! rétention, rapports programmés, rafraîchissement des rôles personnalisés, rollups et
//! rafraîchissement des panneaux. Chacune est un thread DÉDIÉ — un puits réseau lent ne retarde jamais
//! l'ingest local — et itère PAR TENANT (mode 0 = une seule itération sur la base primaire). L'ordre de
//! création des threads, les cadences et les clones AU SITE D'APPEL sont l'invariant de ce fichier.
//! `spawn_background_jobs` lance aussi, dans le même ordre qu'avant, l'ordonnanceur de sauvegarde
//! (`sauvegarde_planifiee`) et les travaux sur la base primaire (`travaux_sur_la_base`).
//! Sous-module de `server` (cf. `server/mod.rs`) ; `spawn_background_jobs` est `pub(super)`, appelé par
//! `run()` dans la façade.
use super::*;

/// Lance toutes les boucles de fond (ingest, ordonnanceur de règles, connecteurs, destinations,
/// rétention, rapports, rollups, refresh panneaux, ANALYZE/index en fond) + applique les toggles mis
/// en cache au boot (FTS/engagement/exclusions). MÊME ordre, MÊME cadence qu'avant.
pub(super) fn spawn_background_jobs(conf: HashMap<String, String>, spool: String, db_path: String, db: Arc<Mutex<Connection>>, tenants: TenantDbManager, refresh_sem: Arc<tokio::sync::Semaphore>, bound: Arc<std::sync::atomic::AtomicBool>) {
    {
        // ROUTING PER-TENANT de l'ingest (R8) : le manager résout la base cible PAR fichier spool (tenant
        // encodé dans le nom). Mode 0 -> toujours (st.db, st.db_path) = comportement identique.
        spawn_ingest_loop(tenants.clone(), spool.clone());
    }

    // planificateur des règles de détection (P4) — #2a-2c : PAR TENANT (mode 0 = 1 itération `default`=st.db).
    {
        spawn_rule_scheduler(tenants.clone());
    }

    // BAN NATIF PLUME (chantier ② Phase 1) — maintenance du store live `net_ban` : charge le cache AU DÉMARRAGE
    // (les bans persistés survivent au reboot) puis, périodiquement, (a) purge les lignes EXPIRÉES et (b) recharge
    // le cache (capte les écritures HORS-PROCESS du responder root). Mode 0 : table vide -> cache vide -> guard
    // passthrough, travail négligeable (tick 15 s sur une table minuscule).
    {
        spawn_netban_maintenance(db.clone());
    }

    // #3a — TICK CONNECTEURS : PAR TENANT (mode 0 = 1 itération default=st.db). INERTE si table `connector`
    // vide (état prod actuel) : run_due_connectors sélectionne les connecteurs DUS -> 0 ligne -> no-op strict
    // (aucun réseau, aucune écriture). Thread DÉDIÉ (séparé de l'ingest et des règles) -> un pull réseau lent
    // (10 s) ne retarde jamais l'ingest local ni les rollups. Séquentiel par tenant (for_each_active_tenant,
    // budget 2 Go). FAIL-SAFE : un connecteur cassé log dans connector.last_error et n'arrête pas les autres.
    {
        spawn_connector_tick(tenants.clone());
    }

    // #50 — TICK FORWARDER (OUTPUTS/DESTINATIONS) : PAR TENANT (mode 0 = 1 itération default=st.db). INERTE si
    // table `destination` vide (état prod actuel) : run_due_destinations sélectionne les destinations DUES ->
    // 0 ligne -> no-op strict (aucun réseau, aucune écriture, ZÉRO coût sur l'ingest). Thread DÉDIÉ (séparé de
    // l'ingest, des règles ET des connecteurs) -> un sink lent/mort (envoi réseau borné 10 s, lot borné) ne
    // retarde JAMAIS l'ingest local ni les autres tenants. Séquentiel par tenant (budget 2 Go). FAIL-SAFE :
    // une destination cassée log dans destination.last_error (watermark gelé, rejouable) sans arrêter les autres.
    {
        spawn_destination_tick(tenants.clone());
    }

    // rétention + purge + ledger (horaire). #2a-2c : PAR TENANT — chaque
    // NB (constat VÉRIFIÉ le 31/07) : ce commentaire annonçait un « filet » — que `retention_run` rappelait
    // `rollup_events`. C'est FAUX depuis #23 F3, qui a RETIRÉ ce re-run du plus long verrou writer parce que
    // la boucle dédiée (`spawn_rollup_loop`, ~120 s) l'appelle déjà à une cadence bien plus fine (cf.
    // `rollups.rs`, « les re-runs rollup_events / materialize_banned_ip / rollup_risk sont RETIRÉS »). Un
    // commentaire qui promet un filet inexistant est pire qu'aucun : il ferme la question qu'il faudrait poser.
    // tenant lit SES settings de rétention (#1b) depuis SA base (mode 0 = 1 itération `default`=st.db).
    {
        spawn_retention_loop(tenants.clone());
    }

    // #60 — TICK SCHEDULED REPORTS : PAR TENANT (mode 0 = 1 itération default=st.db). INERTE si table
    // `scheduled_report` vide : run_due_reports sélectionne 0 ligne -> no-op strict (aucun réseau, aucune
    // écriture). Thread DÉDIÉ (séparé de l'ingest/règles/connecteurs/destinations) -> un notifier lent/mort ne
    // retarde jamais l'ingest ni les autres tenants. Séquentiel par tenant. FAIL-SAFE : chaque rapport isolé
    // (catch_unwind + last_error). Le résultat est MASQUÉ #45 par le run_as du rapport (jamais par un rôle
    // supérieur). Granularité 30 s (le due se calcule sur interval_s du rapport).
    {
        spawn_report_tick(tenants.clone());
    }

    // #59 — RAFRAÎCHISSEMENT PÉRIODIQUE du cache de rôles COMPOSABLES (control-plane). Le cache
    // process (CUSTOM_ROLES) est chargé au boot + sur mutation LOCALE ; sur un déploiement MULTI-RÉPLICA, une
    // mutation faite sur une AUTRE réplica ne serait vue qu'au prochain boot -> fenêtre de staleness (un rôle
    // custom PLUS permissif honoré trop longtemps). Ce ticker borne la fenêtre à ~45 s (même pattern que le
    // scheduler de rétention). Mode 0 (control=None) -> thread INERTE (jamais de reload -> cache VIDE ->
    // tous les chemins RBAC byte-identiques). Cheap (un SELECT sur une petite table control-plane).
    {
        spawn_custom_roles_refresh(tenants.clone());
    }
    // rollup d'events FRÉQUENT -> faible latence sur « Vue d'ensemble (rapide) » + agrégats GROUP-BY plus
    // frais (SOC) : ré-agrège l'heure en cours + la précédente (incrémental/borné, JAMAIS de full-scan).
    // CHANGEMENT 2b : intervalle PLUME_ROLLUP_INTERVAL_S (défaut 120s, au lieu de 300s) pour des agrégats
    // plus frais sur un SOC. Séparé de la rétention horaire (qui purge + signe le ledger).
    {
        // #2a-2c : rollup + banlist + pré-chauffage panneaux PAR TENANT (mode 0 = 1 itération `default`=st.db).
        // intervalles/seuils lus depuis conf AU SITE D'APPEL (jamais de load_config dans le helper) et
        // passes par valeur ; warm_freshness = control-plane present (mode 1). Byte-identique.
        let rollup_interval: u64 = cfg(&conf, "PLUME_ROLLUP_INTERVAL_S", "120").parse().unwrap_or(120).max(1);
        let disk_warn_pct: u8 = cfg(&conf, "PLUME_DISK_WARN_PCT", "80").parse().unwrap_or(80);
        spawn_rollup_loop(tenants.clone(), rollup_interval, disk_warn_pct, tenants.control.is_some());
    }
    // PHASE 3b — boucle de refresh des panneaux DÉDIÉE (courte), DÉCORRÉLÉE du tick rollup : maintient
    // le cache SWR frais (computed_at avance) à intervalle PLUME_PANEL_REFRESH_S. CHANGEMENT 2a : défaut
    // 10s (au lieu de 20s) -> tuiles SOC quasi temps-réel. Bornée par refresh_sem.try_acquire (CHANGEMENT
    // 1 : sémaphore SÉPARÉ) -> ne prend AUCUN permit query_sem, ne bloque/affame jamais l'interactif.
    {
        // #2a-2c : boucle de refresh des panneaux DÉDIÉE, PAR TENANT (mode 0 = 1 itération `default`=st.db).
        let refresh_s: u64 = cfg(&conf, "PLUME_PANEL_REFRESH_S", "10").parse().unwrap_or(10).max(1);
        spawn_panel_refresh_loop(tenants.clone(), refresh_sem.clone(), refresh_s);
    }
    // OPS NATIVE #1 — SCHEDULER DE BACKUP IN-DAEMON (host-natif, Docker ET k3s : `deploy/k3s.yaml` pose
    // `PLUME_BACKUP_INTERVAL` dans son unique conteneur, il n'y a plus de sidecar shell). GATÉ sur
    // PLUME_BACKUP_INTERVAL (secondes ; 0/absent = DÉSACTIVÉ -> AUCUN thread spawné -> comportement
    // byte-identique). Sur host/Docker : monte un volume, pose la var -> self-backup. Chaque cycle qui publie
    // une archive émet les signaux SOC de posture qu'elle implique : sans destinataire d'escrow, la posture
    // symétrique (P8.25-a) ; exercice de restauration dû, l'exercice (P8.26-a).
    {
        annoncer_bascule_sauvegarde(&conf);
        spawn_backup_scheduler(conf.clone(), db_path.clone());
    }
    // OPS NATIVE #2 — AUTO-VACUUM INCRÉMENTAL IN-DAEMON (best-effort, NON-BLOQUANT). GATÉ sur
    // PLUME_AUTOVACUUM_INTERVAL (0/absent = DÉSACTIVÉ -> AUCUN thread -> byte-identique). INOPÉRANT (warn
    // honnête, jamais de VACUUM plein bloquant) si la base n'est pas en auto_vacuum=INCREMENTAL.
    {
        spawn_autovacuum_loop(conf.clone(), db.clone());
    }
    // P10.9-a — L'OBSERVATOIRE D'USAGE DES INDEX. Réglé ICI, depuis la configuration RÉSOLUE, et non
    // par une lecture d'environnement nue : sinon la clé écrite dans le fichier de configuration d'un
    // déploiement host-natif n'aurait aucun effet. `PLUME_INDEX_USAGE_SAMPLE_N=0` (défaut) -> aucun
    // plan lu, aucune série publiée, `/metrics` inchangé octet pour octet.
    {
        index_usage::configurer(&conf);
    }
    // LA SÉRIE DU BUDGET (P10.2-a suite) — la ventilation par poste, ÉCRITE DANS LE TEMPS au lieu
    // d'être relevée à la main. Tick lent (défaut horaire = la résolution de `metric_rollup`), parcours
    // `dbstat` sur le POOL DE LECTURE (jamais le mutex writer), publication dans `metric` -> lue par la
    // commande SOQL `metric`, qui UNIONNE `metric` et `metric_rollup` (90 j). Coût MESURÉ sur une base
    // réelle le 2026-08-09 : une vingtaine de secondes par Gio parcouru, soit moins de 1 % d'un cœur au
    // tick horaire sur une base de l'ordre du Gio, et borné à
    // 5 % par `prochain_sommeil` si la base grossit. `PLUME_VENTILATION_INTERVAL_S=0` -> aucun thread.
    {
        ventilation_serie::spawn_boucle(conf.clone(), db_path.clone(), db.clone(), bound.clone());
    }
    // #32 : ANALYZE COMPLET en TÂCHE DE FOND (jamais dans migrate()) -> boot non bloquant.
    // Le boot est désormais STRUCTURELLEMENT : migrate -> bind :7000 -> (fond) ANALYZE. On n'attend plus
    // un sleep « au jugé » (course : si le bind traînait, le ANALYZE fenêtrait quand même) : on ATTEND le
    // drapeau `bound` posé juste après que le listener écoute, PUIS une courte grâce (liveness passée), PUIS
    // le ANALYZE complet une seule fois (gardé par meta 'analyze_full_done'). Le ANALYZE prend le lock
    // writer (~3 min) mais les LECTURES sont servies par le pool read-only (query_exec) -> jamais bloquées ;
    // seules les écritures (ingest) attendent, et le spool les tamponne. Sur base déjà analysée : no-op.
    {
        spawn_analyze_full(db.clone(), bound.clone());
    }

    // PHASE 1 — toggle mis en cache AU BOOT (atomic lu sur le chemin chaud de compilation/recherche
    // sans load_config()). Défaut PRUDENT : FTS-fields OFF. cfg() couvre PLUME_* (canonical).
    FTS_FIELDS_ON.store(cfg(&conf, "PLUME_FTS_FIELDS", "0") == "1", std::sync::atomic::Ordering::Relaxed);
    // v75 — MODE ENGAGEMENT (pentest natif) : drapeau mis en cache AU BOOT (lu sur le chemin chaud ingest/ban
    // sans load_config). Défaut OFF -> tout le sous-système engagement INERTE (byte-identique).
    set_engagement_mode(engagement_enabled_in(&conf));
    // DEBRUITAGE self/opérateur — clauses d'exclusion (`__OPERATOR_EXCL__` / `__SELF_EXCL__`) compilées et
    // MISES EN CACHE AU BOOT (lues sur le chemin chaud de compilation sans load_config). Chantier
    // whitelists→webui : la valeur résout DÉSORMAIS un override `setting` éditable+audité (repli BYTE-IDENTIQUE
    // sur l'env quand aucun override) ; refresh depuis la base principale au boot. Configurable
    // PLUME_OPERATOR_IPS / PLUME_SELF_HOSTS + override setting excl_operator_ips / excl_self_hosts ; vide -> no-op.
    {
        {
            let conn = db.lock();
            excl_clauses_refresh(&conn, &conf);
        }
        let g = excl_clauses_cell().read();
        eprintln!(
            "[exclusion] self/opérateur — op(src_ip)=[{}] self(vhost)=[{}] (PLUME_OPERATOR_IPS / PLUME_SELF_HOSTS, override setting {EXCL_OP_SETTING}/{EXCL_SELF_SETTING})",
            g.op_sql, g.self_sql
        );
    }
    // CREATE des index expression (un par entrée d'EXPR_INDEX_FIELDS) EN FOND après le bind (jamais synchrone : un CREATE
    // INDEX sur 1,24M lignes bloquerait le bind -> liveness k8s -> CrashLoopBackOff). 1 index à la fois,
    // lock writer borné par index. No-op si PLUME_EXPRINDEX!=1 (le DROP est synchrone au boot) ou si
    // déjà créés. Réconcilie réellement le toggle ON à chaque boot (idempotent, IF NOT EXISTS).
    {
        spawn_reconcile_expr_indexes(db.clone());
    }

    // (v47) CREATE de l'index manquant idx_event_category EN FOND après le bind (jamais
    // synchrone : CREATE INDEX sur 2,39M lignes chiffrées bloquerait le bind). One-shot, idempotent.
    {
        spawn_ensure_event_category_index(db.clone());
    }

    // v110 (ALLÈGEMENT INDEX HOT — P5) — DROP EN FOND après le bind des index REDONDANTS idx_event_sev
    // (préfixe de idx_event_sev_srcip) et idx_event_src (préfixe de idx_event_src_ts) sur la base LIVE.
    // REMPLACE l'ancien spawn_ensure_event_source_index (CHANGE 4 v103) qui CRÉAIT idx_event_src, rendu
    // obsolète par le composite (source, ts) de v108. DROP INDEX = cheap (ne déchiffre pas la table) -> sûr en
    // fond. Gardé (source-seul droppé seulement quand idx_event_src_ts présent) -> zéro fenêtre de scan.
    {
        spawn_drop_redundant_event_indexes(db.clone());
    }

    // P10.2-d (ALLÈGEMENT INDEX, SUITE) — DROP EN FOND après le bind des NEUF index redondants que le schéma
    // migré posait encore, sur la base LIVE qui les porte déjà (les `CREATE INDEX` ont été retirés de
    // migrate.rs -> une base neuve ne les crée plus). Huit sont subsumés par l'AUTO-INDEX d'une contrainte
    // UNIQUE/PRIMARY KEY (présent par construction avec la table) -> DROP inconditionnel ; le neuvième
    // (idx_alert_mitre) est subsumé par un index EXPLICITE (idx_alert_mitre_ts, v72) -> DROP gardé par sa
    // présence confirmée, zéro fenêtre sans index de tête sur `mitre`. Même doctrine que v110 : DROP INDEX ne
    // déchiffre pas la table -> sûr en fond (un CREATE ne le serait pas).
    {
        spawn_drop_prefix_subsumed_indexes(db.clone());
    }

    // P6.8-b — DROP EN FOND après le bind des index `idx_ev_auto_*` ORPHELINS du mécanisme d'auto-index
    // adaptatif RETIRÉ. Son mainteneur était le SEUL code qui savait les dropper ; sans ceci ils seraient
    // des orphelins permanents (coût disque + un insert btree par ligne ingérée, que plus personne ne peut
    // retirer). La liste est DEMANDÉE à sqlite_master, jamais écrite en dur. En fond et NON en migration :
    // un bump de schéma rendrait la base illisible par le binaire précédent -> le rollback automatique de
    // la porte de déploiement deviendrait un cul-de-sac. Même doctrine que v110/P10.2-d.
    {
        spawn_drop_orphan_auto_field_indexes(db.clone());
    }

    // v108 (PERF recherche raw haut-volume) — CREATE de l'index COMPOSITE idx_event_src_ts(source,ts) EN FOND
    // après le bind (jamais synchrone : CREATE INDEX sur des millions de lignes chiffrées bloquerait le bind).
    // schema.sql le déclare (bases neuves) mais aucune migration ne le crée -> la base live en manque. Une fois
    // créé, `search source=X earliest=-Nd` range-prune ts (COUNT pagination index-only borné + page bornée) au
    // lieu de déchiffrer toute la table grasse. One-shot, idempotent (IF NOT EXISTS + court-circuit, même nom).
    {
        spawn_ensure_event_src_ts_index(db.clone());
    }

    // P3.7-a (PERF INGEST) — CREATE de l'index PARTIEL idx_event_health_beat(source,ts) WHERE
    // category='health' EN FOND après le bind (même doctrine anti-crashloop). Sans lui, les 8 sondes
    // dead-man's-switch de COLLECTORS remontent la plage de leur source ligne par ligne, sous le verrou
    // d'écriture, toutes les 20 s — coût mesuré `5 x (lignes depuis le dernier battement)`, donc O(N)
    // exactement quand le collecteur surveillé est mort. One-shot, idempotent (IF NOT EXISTS + court-circuit).
    {
        spawn_ensure_event_health_beat_index(db.clone());
    }

    // ANTI FULL-SCAN (rollup_hosts sur metric/snapshot) — CREATE des index ts-leading idx_metric_ts/idx_snapshot_ts
    // EN FOND après le bind (jamais synchrone : CREATE INDEX sur ~2M lignes metric chiffrées bloquerait le bind).
    // Une fois créés, rollup_hosts range-prune la fenêtre chaude/définitive (plus de full-scan+déchiffrement sous
    // le lock writer -> plus de famine ingest) et pipeline_is_fresh fait un MAX(ts) indexé O(1). One-shot, idempotent.
    {
        spawn_ensure_host_rollup_scan_indexes(db.clone());
    }

    // PHASE 1 — BACKFILL de event_fields_fts pour l'historique (1,24M lignes) EN FOND après bind.
    // No-op si PLUME_FTS_FIELDS!=1 ou backfill désactivé. Reprenable par watermark, gardé par meta.
    {
        spawn_fts_backfill(db.clone());
    }

    // #23 — PRÉ-CHAUFFAGE au boot (cold-read fix) : le 1er /api/integrations (~12 s FROID) / /api/overview
    // payait tout le déchiffrement SQLCipher à froid. On exécute UNE fois, APRÈS le bind + la liveness, un petit
    // lot BORNÉ de lectures (intégrations + fraîcheur + qq agrégats overview) sur le READ POOL pour peupler le
    // cache de pages 64 Mio AVANT le 1er clic (et remplir les caches SWR). Best-effort, jamais bloquant.
    {
        spawn_boot_prewarm(conf.clone(), db_path.clone(), bound.clone());
    }
}

// ---------- jobs de fond (refactor split #8) ----------
// Chaque std::thread::spawn de spawn_background_jobs() extrait en un helper spawn_<job>(...) prenant ses
// clones/valeurs PAR VALEUR. INVARIANT : ordre de creation des threads inchange, clone AU SITE D'APPEL
// (jamais dans le helper), intervalles/flags passes en parametres (aucun load_config re-lu), atomics de
// tick conserves DANS les closures, et les statements de boot synchrones (toggles/excl_clauses)
// restent inline dans spawn_background_jobs a leur place exacte.
fn spawn_ingest_loop(mgr: TenantDbManager, spool: String) {
        std::thread::spawn(move || {
            // ING-4 : balayage de démarrage des `.tmp` spool ORPHELINS (récepteur push crashé AVANT le rename ;
            // `ingest_once` les ignore -> fuite permanente sans ce sweep). Âge-gardé (épargne un POST en vol).
            let balayage = sweep_orphan_ingest_tmps(&spool, Duration::from_secs(INGEST_TMP_ORPHAN_MAX_AGE_SECS));
            let phrase = balayage.phrase("[ingest] .tmp spool au démarrage");
            if !phrase.is_empty() { eprintln!("{phrase}"); }
            loop {
                // P4.1-r — le passage rend son bilan (spool illisible, fichiers abandonnés) et la boucle le
                // PUBLIE : un spool qu'on ne sait plus énumérer n'est plus une boucle qui « tourne ».
                let mut bilan = crate::bilan_de_tick::BilanDuPlanificateur::default();
                bilan.absorber(ingest_once(&mgr, &spool));
                crate::bilan_de_tick::publier(crate::bilan_de_tick::BOUCLE_INGEST, bilan.mesure());
                std::thread::sleep(Duration::from_secs(5));
            }
        });
}

fn spawn_rule_scheduler(tenants: TenantDbManager) {
        std::thread::spawn(move || loop {
            // P4.1-r — LE BILAN DU TICK : chaque famille rend ce qu'elle a abandonné, ou l'aveu qu'elle n'a
            // pas pu lire sa liste ; le planificateur absorbe tout et PUBLIE avant de marquer son tick. Un
            // tick qui n'a rien évalué ne peut plus passer pour un tick calme sur la surface d'état.
            let mut bilan = crate::bilan_de_tick::BilanDuPlanificateur::default();
            for_each_active_tenant(&tenants, |tid, handle, db_path| {
                // CONC-2 : corps PAR TENANT isolé par catch_unwind (symétrie avec les boucles connecteurs/
                // destinations/rapports). Un panic dans l'évaluation d'une règle d'UN tenant est capturé -> les
                // autres tenants continuent ET le fil planificateur SURVIT (sans ce garde, un panic tuerait le
                // thread infini -> détection stoppée SILENCIEUSEMENT). Happy path INCHANGÉ.
                let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut b = crate::bilan_de_tick::BilanDuPlanificateur::default();
                    b.absorber(run_due_rules(handle, db_path));
                    // #48/#53 : règles « avancées » (fenêtre de suppression / throttle-by-field / per-result),
                    // EXCLUES de run_due_rules et traitées à part (comme run_risk_rules). INERTE mode 0 (0 ligne due).
                    b.absorber(run_advanced_rules(handle, db_path));
                    // #24 (RBA) : règles en MODE RISK (risk_score>0, exclues de run_due_rules) -> CONTRIBUENT du
                    // risque par entité au lieu de lever une alerte scalaire. INERTE mode 0 (aucune règle risk).
                    b.absorber(run_risk_rules(handle, db_path));
                    // #37 (DÉTECTION AVANCÉE) : corrélation multi-événements stateful (finding-groups de séquence)
                    // + baselining statistique UEBA (déviation z-score par entité). MÊMES garanties fail-closed que
                    // run_due_rules (erreur/timeout ne fabrique JAMAIS un « tout clair »). INERTE mode 0 (tables
                    // correlation/baseline vides -> 0 ligne due -> retour immédiat, tick byte-identique).
                    b.absorber(run_correlations(handle, db_path));
                    b.absorber(run_baselines(handle, db_path));
                    b.absorber(run_playbooks(handle, db_path));
                    b.absorber(check_heartbeats(handle));
                    dispatch_notifications(handle);
                    escalate_overdue_cases(handle); // #4a — escalade SLA des cases overdue (INERTE si aucun)
                    sla_multilevel_tick(handle); // #39 — breach SLA MULTI-NIVEAU (ack/resolve). EARLY-RETURN si 0 politique (mode 0 : ZÉRO travail)
                    // v75 (MODE ENGAGEMENT) : auto-expiry des engagements + recompilation de l'index scope actif
                    // (tag d'ingest + guard auto-ban). SELF-GATED sur engagement_enabled() -> mode off = 0 travail
                    // (pas de lock, pas de SELECT) = tick byte-identique.
                    expire_due_engagements(handle);
                    if engagement_enabled() {
                        let c = handle.lock();
                        engagement_scope_refresh(db_path, &c);
                    }
                    b
                }));
                match res {
                    Ok(b) => bilan.absorber(b.bilan_de_tick()),
                    Err(_) => {
                        bilan.panique(tid);
                        eprintln!("[detect] panic capturé dans le tick de détection (tenant isolé) — planificateur préservé, on continue");
                    }
                }
            });
            crate::bilan_de_tick::publier(crate::bilan_de_tick::BOUCLE_REGLES, bilan.mesure());
            // #51 DAY-2 OPS : marque le tick du scheduler de règles (santé « détection » = ce tick récent).
            SCHED_RULE_TICKS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            SCHED_RULE_LAST_TS.store(now(), std::sync::atomic::Ordering::Relaxed);
            std::thread::sleep(Duration::from_secs(20));
        });
}

/// BAN NATIF PLUME (chantier ② Phase 1) — thread de maintenance du store live `net_ban`. Charge le cache au
/// boot puis, toutes les 15 s : purge les bans EXPIRÉS de la table + recharge le cache in-mémoire (source de
/// vérité = la table ; capte les écritures du responder root séparé). Sur la base DEFAULT (l'enforcement HTTP
/// est GLOBAL, avant la résolution tenant -> Phase 1 = mono-base ; per-tenant = Phase 2). Fail-safe : base
/// illisible -> cache vidé (fail-open, aucune IP bloquée) au lieu d'un instantané figé.
fn spawn_netban_maintenance(db: Arc<Mutex<Connection>>) {
    std::thread::spawn(move || {
        {
            let c = db.lock();
            netban_reload(&c); // warm-up : bans persistés effectifs dès le bind
        }
        loop {
            std::thread::sleep(Duration::from_secs(15));
            let c = db.lock();
            let _ = c.execute("DELETE FROM net_ban WHERE expires_ts IS NOT NULL AND expires_ts <= ?1", params![now()]);
            netban_reload(&c);
        }
    });
}

fn spawn_connector_tick(tenants: TenantDbManager) {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(45)); // après le bind + le 1er rollup
            loop {
                let mut bilan = crate::bilan_de_tick::BilanDuPlanificateur::default();
                for_each_active_tenant(&tenants, |_tid, handle, db_path| {
                    bilan.absorber(run_due_connectors(handle, db_path));
                });
                crate::bilan_de_tick::publier(crate::bilan_de_tick::BOUCLE_CONNECTEURS, bilan.mesure());
                std::thread::sleep(Duration::from_secs(15)); // granularité du scheduler
            }
        });
}

fn spawn_destination_tick(tenants: TenantDbManager) {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(50)); // après le bind + le 1er rollup (post-connecteurs)
            loop {
                let mut bilan = crate::bilan_de_tick::BilanDuPlanificateur::default();
                for_each_active_tenant(&tenants, |_tid, handle, db_path| {
                    bilan.absorber(run_due_destinations(handle, db_path));
                });
                crate::bilan_de_tick::publier(crate::bilan_de_tick::BOUCLE_DESTINATIONS, bilan.mesure());
                std::thread::sleep(Duration::from_secs(15)); // granularité du scheduler de sortie
            }
        });
}

/// `P10.7-w` — LE NOM SOUS LEQUEL LA BOUCLE QUI ANCRE REND SON BILAN. Déclaré dans le module de la
/// boucle, comme `overlays_adossement::PASSE_OVERLAYS` l'est dans le module de sa passe.
///
/// CE QU'IL N'ATTEINT PAS ENCORE, ET C'EST ÉCRIT PARCE QUE C'EST VRAI : la table `bilan_de_tick::BOUCLES`
/// est ce que `/metrics` PARCOURT (objet `scheduler` et exposition Prometheus). Cette clé n'y figure pas
/// — l'ajouter demande une ligne dans `bilan_de_tick.rs`, hors du périmètre de ce lot. En l'état, l'aveu
/// est LISIBLE (`bilan_de_tick::dernier`) et il est sur stderr, mais il n'est pas encore SERVI.
pub(crate) const BOUCLE_RETENTION: &str = "retention";

/// `P10.7-w` — UNE PASSE DE RÉTENTION SOUS FILET, ET CE QU'ELLE AVOUE. Mesuré le 2026-08-31.
///
/// LE DÉFAUT FERMÉ. `spawn_retention_loop` est le SEUL ancrage PÉRIODIQUE de la chaîne d'intégrité :
/// c'est la seule boucle qui appelle `retention_run_tenant`, donc `sign_checkpoint` (RECOMPTÉ le
/// 2026-08-31 — `sign_checkpoint` a DEUX autres sites, tous deux NON périodiques : un au BOOT dans
/// `server/mod.rs`, un dans la sous-commande `retention` que l'exploitant lance à la main). Elle ne
/// publiait AUCUN bilan et ne portait AUCUN filet — un panic dans la passe tuait le fil, et avec lui
/// l'ancrage, la purge, la compaction plein-texte, le point de reprise WAL et le vieillissement froid.
/// Aucun compteur de tick n'existe pour elle (les seuls sont `SCHED_RULE_*` et `SCHED_ROLLUP_*`) : la
/// mort du fil ne se lisait NULLE PART, pas même à l'heure. Le fil mort, le démon continue de servir et
/// n'ancre plus RIEN jusqu'au prochain redémarrage. `P10.7-v` détecte l'EFFET (une chaîne non ancrée
/// depuis plus de deux cadences est accusée par `ledger::ancrage_en_retard`) — mais il faut aller le
/// LIRE, et un processus qui redémarre souvent ré-ancre à chaque boot, donc n'est jamais accusé.
///
/// REPRENDRE, ET NON MOURIR — LA RAISON EST MESURÉE, PAS CHOISIE :
///   1. c'est ce que fait le seul filet de boucle qui existe déjà ici (`spawn_rule_scheduler` : un
///      `catch_unwind` PAR TENANT, `bilan.panique(tid)`, `eprintln`, et on continue) ;
///   2. le verrou d'écriture est un `parking_lot::Mutex` (`main.rs`), qui N'EMPOISONNE PAS : un panic
///      tenu sous le verrou le rend proprement, donc la passe suivante peut écrire. Sous
///      `std::sync::Mutex`, reprendre fabriquerait une boucle qui panique à chaque `lock()` — c'est
///      pourquoi le témoin `la_reprise_retrouve_un_verrou_utilisable` panique VERROU EN MAIN ;
///   3. mourir emporterait la purge et le point de reprise WAL avec l'ancrage — sur un budget de 2 Go,
///      un disque qui ne se purge plus est une seconde panne greffée sur la première.
///
/// L'AVEU EST UN ÉTAT, PAS UN FLUX — ET C'EST LE PIÈGE ÉVITÉ. Les aveux VOISINS écrits en base
/// (`emit_ledger_health`, `emit_disk_health`) sont dédupliqués À L'HEURE (`dedup = …-{ts/3600}`).
/// Or la cadence de CETTE boucle est de 3600 s : la dédup n'y étouffe RIEN en régime permanent (au
/// plus un aveu par passe de toute façon) — elle protège du boot en crashloop, elle ne masque pas une
/// panne durable. Mais elle RENDRAIT une ligne par heure, indistinguable d'un incident isolé dans une
/// liste d'événements. Le bilan, lui, n'est PAS dédupliqué et il est LAST-WRITER-WINS : une passe qui
/// échoue à chaque tour laisse un `Illisible` en place, donc un ROUGE permanent sur la surface
/// (`bilan_de_tick::etat_de_surface`) — un état, qu'aucun lecteur ne peut prendre pour un incident isolé.
/// Corollaire assumé : une passe saine EFFACE l'aveu de la précédente. C'est déjà la sémantique des
/// quatre boucles voisines, et c'est ce qui rend le témoin négatif exigible.
///
/// `passe` est un paramètre pour que l'incident se FABRIQUE au lieu de s'attendre : la production y met
/// `retention_run_tenant`, les témoins y mettent une passe qui panique.
pub(crate) fn passe_de_retention_sous_filet(
    tenants: &TenantDbManager,
    passe: impl Fn(&Arc<Mutex<Connection>>, &str),
) -> crate::mesure_environnement::Mesure<u64> {
    let mut bilan = crate::bilan_de_tick::BilanDuPlanificateur::default();
    for_each_active_tenant(tenants, |tid, handle, db_path| {
        // MÊME grain que `spawn_rule_scheduler` : PAR TENANT. Un panic sur la base d'un tenant n'empêche
        // pas les autres d'être purgés ni leur chaîne d'être ancrée.
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| passe(handle, db_path)));
        if res.is_err() {
            bilan.panique(tid);
            eprintln!(
                "[retention] panic capturé dans la passe de rétention (tenant '{tid}' isolé) — la boucle \
                 qui ANCRE le journal d'intégrité SURVIT et le dit ; sans ce filet, le fil mourait et \
                 l'ancrage s'arrêtait sans aveu"
            );
        }
    });
    let mesure = bilan.mesure();
    // APRÈS la passe, comme les quatre boucles voisines (`BOUCLE_INGEST`, `BOUCLE_REGLES`,
    // `BOUCLE_CONNECTEURS`, `BOUCLE_DESTINATIONS`, `BOUCLE_RAPPORTS`) : le bilan publié est celui du
    // passage qui vient d'avoir lieu, jamais une intention.
    crate::bilan_de_tick::publier(BOUCLE_RETENTION, mesure.clone());
    mesure
}

fn spawn_retention_loop(tenants: TenantDbManager) {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(60));
            loop {
                // `P10.7-w` — LE PASSAGE EST SOUS FILET ET REND SON BILAN. Le corps par tenant est
                // INCHANGÉ : db_path threadé (#18 FIX #2) — le tier cold en dérive une racine DISJOINTE
                // par tenant (jamais le PLUME_COLD_DIR global partagé). Mode 0 : db_path==PLUME_DB ->
                // racine cold HISTORIQUE inchangée. Le reste de la rétention IGNORE db_path.
                passe_de_retention_sous_filet(&tenants, |handle, db_path| retention_run_tenant(handle, db_path));
                std::thread::sleep(Duration::from_secs(3600));
            }
        });
}

fn spawn_report_tick(tenants: TenantDbManager) {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(55)); // après le bind + le 1er rollup (post-destinations)
            loop {
                let mut bilan = crate::bilan_de_tick::BilanDuPlanificateur::default();
                for_each_active_tenant(&tenants, |_tid, handle, db_path| {
                    bilan.absorber(run_due_reports(handle, db_path));
                });
                crate::bilan_de_tick::publier(crate::bilan_de_tick::BOUCLE_RAPPORTS, bilan.mesure());
                std::thread::sleep(Duration::from_secs(30)); // granularité du scheduler de rapports
            }
        });
}

fn spawn_custom_roles_refresh(tenants: TenantDbManager) {
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(45));
            if let Some(cp) = tenants.control.as_ref() {
                reload_custom_roles(cp);
            }
        });
}

fn spawn_rollup_loop(tenants: TenantDbManager, rollup_interval: u64, disk_warn_pct: u8, warm_freshness: bool) {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(90));
            loop {
                // P4.1-r — les incidents de risque sont une DÉTECTION qui tourne dans cette boucle-ci :
                // leur bilan est publié à part, et la surface « détection » le lit avec celui des règles.
                let mut bilan_risque = crate::bilan_de_tick::BilanDuPlanificateur::default();
                for_each_active_tenant(&tenants, |_tid, handle, db_path| {
                    {
                        let c = handle.lock();
                        rollup_events(&c);
                        materialize_banned_ip(&c);   // banlist matérialisée (incrémentale, bornée) -> anti-join cheap
                        // #23 — rafraîchit le CACHE de match threat-intel de CE tenant (keyé db_path). Cheap
                        // (lit la petite table `ioc`, exclut les expirés). Vide en mode 0 -> no-op. Discipline
                        // host_rollup : le match-on-ingest lit ce cache O(1), JAMAIS un SELECT par event.
                        ioc_cache_reload(&c, db_path);
                        // #24 (RBA) : matérialise risk_rollup (agrégat par entité, reconstruit depuis la
                        // petite table risk_event -> DECAY fenêtré) + déclenche les alertes risk-based. Mode 0
                        // (aucun risk_event) -> fast-path retour immédiat. JAMAIS un scan de `event`.
                        bilan_risque.absorber(rollup_risk(&c));
                    }
                    // F5 : l'appel `cache_refresh_all_panels` a été RETIRÉ d'ici (boucle rollup 120 s) — la
                    // boucle DÉDIÉE de refresh (`spawn_panel_refresh_loop`, ~10 s) appelle EXACTEMENT la même
                    // fonction avec les mêmes args (même `handle`/`db_path` par-tenant, même `refresh_sem`) et
                    // dérive son ensemble de panneaux EN INTERNE (SELECT ... FROM panel) -> ensemble IDENTIQUE,
                    // à cadence plus fine. Refresh idempotent (INSERT OR REPLACE, borné par refresh_sem) : rien
                    // ne cesse d'être rafraîchi. Cette boucle n'a donc plus besoin du refresh_sem (retiré de sa
                    // signature) ; seule la boucle de refresh dédiée le porte.
                    if warm_freshness {
                        // pré-chauffage TOUS-ENV (#2d) : clé = db_path (env_range_key(None,..)) ; les vues
                        // par-env sont calculées à la demande dans le handler freshness.
                        let nv = compute_freshness(db_path, None);
                        freshness_map().lock().insert(db_path.to_string(), (Instant::now(), nv));
                    }
                });
                // GARDE-FOU #29 : alerte pré-saturation disque — UNE fois par tick (ressource HÔTE, pas
                // par-tenant ; dedup horaire = 1 warn/heure). Mesure le volume de la base par défaut (même
                // PVC que le spool). INERTE si seuil=0. Émis dans la base par défaut (posture host-wide).
                if disk_warn_pct != 0 {
                    let dir = std::path::Path::new(tenants.default_db_path.as_str())
                        .parent()
                        .filter(|d| !d.as_os_str().is_empty())
                        .map(|d| d.to_string_lossy().into_owned())
                        .unwrap_or_else(|| ".".to_string());
                    { let c = tenants.default_writer.lock();
                        emit_disk_health(&c, &dir, disk_warn_pct, now());
                    }
                }
                // P10.11-a — CE QUE LES REQUÊTES ONT ATTENDU PENDANT CE TICK, et quelle part du tick
                // une passe de vieillissement couvrait. UNE fois par tick (l'accumulateur est de
                // PROCESSUS, pas par-tenant) et dans la base par défaut : exactement la posture
                // host-wide de l'alerte de saturation disque ci-dessus, pour la même raison. Écrire
                // le même accumulateur dans chaque base compterait le même temps d'attente autant de
                // fois qu'il y a de tenants. Onze `INSERT` au plus, verrou tenu pour eux seuls.
                { let c = tenants.default_writer.lock();
                    crate::attente_serie::publier_fenetre(&c, now());
                }
                crate::bilan_de_tick::publier(crate::bilan_de_tick::BOUCLE_RISQUE, bilan_risque.mesure());
                // #51 DAY-2 OPS : marque le tick de rollup (santé « rollups » = ce tick récent).
                SCHED_ROLLUP_TICKS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                SCHED_ROLLUP_LAST_TS.store(now(), std::sync::atomic::Ordering::Relaxed);
                std::thread::sleep(Duration::from_secs(rollup_interval));
            }
        });
}

fn spawn_panel_refresh_loop(tenants: TenantDbManager, refresh_sem: Arc<tokio::sync::Semaphore>, refresh_s: u64) {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(35)); // après le bind + le 1er rollup
            loop {
                for_each_active_tenant(&tenants, |_tid, handle, db_path| {
                    cache_refresh_all_panels(handle, db_path, &refresh_sem);
                });
                std::thread::sleep(Duration::from_secs(refresh_s));
            }
        });
}

// ==================================================================================================
// `P10.7-w` — LE FILET DE LA BOUCLE QUI ANCRE, ÉPROUVÉ SUR UN INCIDENT FABRIQUÉ.
//
// POURQUOI CES TÉMOINS VIVENT ICI ET NON SOUS `src/tests/`. `mod boucles_de_fond;` est PRIVÉ dans
// `server/mod.rs`, qui n'en réexporte que `spawn_background_jobs` : depuis `crate::tests`, ni
// `passe_de_retention_sous_filet` ni `BOUCLE_RETENTION` ne sont NOMMABLES. Les y porter demanderait
// une ligne `pub(crate) use boucles_de_fond::{…};` dans `server/mod.rs` — un fichier hors du
// périmètre de ce lot. La garde DÉRIVÉE, elle, n'a besoin d'aucun item privé (elle lit la SOURCE) et
// vit donc bien sous `src/tests/le_filet_de_la_boucle_qui_ancre.rs`.
//
// AUCUN TÉMOIN CHRONOMÉTRIQUE : la boucle réelle dort 60 s puis 3600 s ; on ne l'attend pas, on
// exerce SA PASSE avec un incident FABRIQUÉ. AUCUN TÉMOIN ADOSSÉ À UN DÉFAUT VIVANT : chacun asserte
// l'état CORRIGÉ et nomme ce que l'arbre rendait avant.
// ==================================================================================================
#[cfg(test)]
mod filet_de_l_ancrage {
    use super::*;
    use crate::mesure_environnement::{Mesure, CAUSE_SOURCE_ILLISIBLE};
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Le bilan est un état de PROCESSUS publié sous UNE clé : deux témoins qui la lisent en parallèle
    /// se voleraient leur mesure. Ils prennent ce verrou. (`parking_lot` : pas d'empoisonnement, donc
    /// un témoin qui échoue ne fait pas échouer les autres pour une mauvaise raison.)
    static VERROU_DU_BILAN: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    /// Le chemin de la base du tenant `default`, RELU dans les assertions : une passe qui recevrait un
    /// autre chemin travaillerait sur une autre base, et le tier froid en dérive sa racine.
    const CHEMIN_DEFAULT: &str = "/base/du/tenant/default/plume.db";

    /// Un gestionnaire MODE 0 (`control: None`) : `for_each_active_tenant` y fait EXACTEMENT une
    /// itération, sur `default`. La table `trace` sert à prouver que la passe ÉCRIT vraiment.
    fn un_gestionnaire_mode_0() -> TenantDbManager {
        let conn = Connection::open_in_memory().expect("base mémoire");
        conn.execute_batch("CREATE TABLE trace(n INTEGER)").expect("table de trace");
        TenantDbManager {
            default_db_path: Arc::new(CHEMIN_DEFAULT.to_string()),
            default_writer: Arc::new(Mutex::new(conn)),
            control: None,
            writers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// (W1) LE TÉMOIN NÉGATIF — UNE PASSE SAINE RESTE MUETTE, ET SON BILAN EST UN VRAI ZÉRO.
    ///
    /// Sans lui, un filet qui avouerait TOUJOURS passerait (W2) et (W3) : un aveu inconditionnel n'est
    /// pas un aveu, c'est une alarme qu'on apprend à ne plus lire. Le CONTRÔLE POSITIF (`passages==1`)
    /// est là pour la même raison en sens inverse : un `Lue(0)` rendu par une passe JAMAIS APPELÉE
    /// serait la valeur la plus rassurante du monde.
    #[test]
    fn une_passe_de_retention_saine_reste_muette_et_son_bilan_est_un_vrai_zero() {
        let _v = VERROU_DU_BILAN.lock();
        let mgr = un_gestionnaire_mode_0();
        let passages = AtomicU32::new(0);
        let mesure = passe_de_retention_sous_filet(&mgr, |handle, db_path| {
            assert_eq!(db_path, CHEMIN_DEFAULT, "la passe reçoit le chemin de SA base");
            passages.fetch_add(1, Ordering::Relaxed);
            handle.lock().execute("INSERT INTO trace(n) VALUES(1)", []).expect("la passe écrit vraiment");
        });
        assert_eq!(passages.load(Ordering::Relaxed), 1, "CONTRÔLE POSITIF : sans passage, le zéro qui suit ne prouverait rien");
        assert_eq!(
            mesure,
            Mesure::Lue(0),
            "une passe de rétention SAINE n'a rien à avouer : son bilan est un VRAI zéro, comme celui \
             des quatre boucles voisines"
        );
        assert_eq!(
            crate::bilan_de_tick::dernier(BOUCLE_RETENTION),
            Some(Mesure::Lue(0)),
            "et il est PUBLIÉ — avant ce lot, cette boucle ne publiait RIEN, pas même un tick"
        );
        let (etat, detail) =
            crate::bilan_de_tick::etat_de_surface("green", "rétention à l'heure".to_string(), Some(&Mesure::Lue(0)));
        assert_eq!((etat, detail.as_str()), ("green", "rétention à l'heure"), "une passe saine ne teinte RIEN");
    }

    /// (W2) L'INCIDENT EST FABRIQUÉ, ET IL EST AVOUÉ — LA BOUCLE NE MEURT PLUS EN SILENCE.
    ///
    /// ATTEINDRE la première assertion EST déjà la moitié de la propriété : sans le `catch_unwind`,
    /// ce `panic!` déroulerait le fil de la boucle. Avant ce lot, en production, il l'aurait fait —
    /// l'ancrage du journal d'intégrité se serait arrêté sans qu'aucune surface ne le dise.
    #[test]
    fn une_passe_de_retention_qui_panique_est_avouee_et_la_passe_rend_la_main() {
        let _v = VERROU_DU_BILAN.lock();
        let mgr = un_gestionnaire_mode_0();
        let mesure = passe_de_retention_sous_filet(&mgr, |_handle, _db_path| {
            panic!("incident FABRIQUÉ dans la passe de rétention");
        });
        match &mesure {
            Mesure::Illisible { cause, detail } => {
                assert_eq!(*cause, CAUSE_SOURCE_ILLISIBLE, "la cause reste dans l'ensemble fermé de `S32`");
                assert!(detail.contains("default"), "l'aveu NOMME le tenant dont la passe est tombée : {detail}");
                assert!(detail.contains("paniqué"), "et il dit ce qui est arrivé : {detail}");
            }
            Mesure::Lue(n) => panic!("une passe qui a PANIQUÉ a rendu un compte ({n}) au lieu d'un aveu"),
        }
        assert_eq!(
            crate::bilan_de_tick::dernier(BOUCLE_RETENTION),
            Some(mesure.clone()),
            "l'aveu est PUBLIÉ, et c'est le MÊME que celui rendu à l'appelant"
        );
        let (etat, detail) =
            crate::bilan_de_tick::etat_de_surface("green", "rétention à l'heure".to_string(), Some(&mesure));
        assert_eq!(etat, "red", "une passe d'ancrage qui n'a pas eu lieu est ROUGE, pas une passe calme");
        assert!(detail.contains("AVEUGLE"), "et le détail porte le mot que la surface expose : {detail}");
    }

    /// (W3) LA REPRISE RETROUVE UN VERROU UTILISABLE — C'EST CE QUI REND « REPRENDRE » LÉGITIME ICI.
    ///
    /// LA QUESTION QUE CE TÉMOIN TRANCHE : reprendre après un panic n'est sûr que si le verrou
    /// d'écriture survit à un panic TENU EN MAIN. C'est vrai de `parking_lot::Mutex` (aucun
    /// empoisonnement) et FAUX de `std::sync::Mutex`, où la reprise fabriquerait une boucle qui
    /// panique à chaque `lock()`. Le témoin panique donc VERROU EN MAIN, et exige que la passe
    /// SUIVANTE prenne le verrou et écrive : le jour où quelqu'un échange le type du verrou, il
    /// rougit ici plutôt qu'en production.
    ///
    /// Il épingle aussi le corollaire assumé du canal choisi : le bilan est un ÉTAT last-writer-wins,
    /// donc une passe saine EFFACE l'aveu de la précédente — c'est la sémantique des quatre boucles
    /// voisines, et c'est ce qui interdit de confondre l'aveu avec un flux d'incidents.
    #[test]
    fn la_reprise_retrouve_un_verrou_utilisable_apres_un_panic_tenu_sous_le_verrou() {
        let _v = VERROU_DU_BILAN.lock();
        let mgr = un_gestionnaire_mode_0();
        let avoue = passe_de_retention_sous_filet(&mgr, |handle, _db_path| {
            let c = handle.lock();
            c.execute("INSERT INTO trace(n) VALUES(1)", []).expect("écriture AVANT l'incident");
            panic!("incident FABRIQUÉ, VERROU D'ÉCRITURE EN MAIN");
        });
        assert!(matches!(avoue, Mesure::Illisible { .. }), "le panic sous verrou est avoué comme les autres");

        let sain = passe_de_retention_sous_filet(&mgr, |handle, _db_path| {
            handle
                .lock()
                .execute("INSERT INTO trace(n) VALUES(2)", [])
                .expect("LA PROPRIÉTÉ : le verrou d'écriture est REPRENABLE après un panic tenu en main");
        });
        assert_eq!(sain, Mesure::Lue(0), "la passe suivante s'exécute normalement : la boucle a REPRIS");
        let n: i64 = mgr
            .default_writer
            .lock()
            .query_row("SELECT COUNT(*) FROM trace", [], |r| r.get(0))
            .expect("la base est toujours vivante");
        assert_eq!(n, 2, "les DEUX écritures ont eu lieu — celle d'avant l'incident et celle d'après");
        assert_eq!(
            crate::bilan_de_tick::dernier(BOUCLE_RETENTION),
            Some(Mesure::Lue(0)),
            "et l'aveu a été REMPLACÉ par le bilan de la passe saine : le canal est un ÉTAT, pas un \
             flux — un incident PERMANENT y reste rouge en permanence, un incident RÉSORBÉ s'efface"
        );
    }
}
