//! Exécuteur de lecture borné (data-plane) : pool de connexions read-only SQLCipher clé par db_path
//! (`ReadPool`/`READ_POOL`, LRU inter-bases), helpers `read_with`/`read_with_watchdog`, budgets
//! (`query_budget_ms`/`query_budget_interactive_ms`), registre d'annulation en vol clé (db_path,qid)
//! (`QUERY_CANCEL`/`CancelEntry`/`CancelGuard`/`cancel_register`) et exécuteurs `run_query`/`run_query_ex`
//! (watchdog + garde `stmt.readonly()`). Statics OnceLock + accesseurs. MT-KEY: par db_path.
//! Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

// Pool de connexions LECTURE (READ_ONLY, WAL) : evite d'ouvrir une connexion a chaque requete.
// Sur : chaque SELECT en autocommit lit un snapshot frais ; connexions reutilisables.
// MT-KEY: par db_path — une connexion ouverte (et déchiffrée) sur la base A n'est JAMAIS servie pour une
// lecture de la base B (R1, bug LATENT corrigé : l'ancien `Vec` global ignorait le db_path). Le CAP est
// GLOBAL (total de connexions idle TOUTES bases confondues, PAS par base : 6×8 handles chiffrés
// feraient exploser le budget 2 Go) avec éviction LRU INTER-bases au-delà du cap. En mono-tenant : une
// seule base -> exactement READ_POOL_CAP handles idle fongibles (identique à l'ancien plafond de 8).
pub(crate) const READ_POOL_CAP: usize = 8;
struct ReadPool {
    by_path: HashMap<String, Vec<(u64, Connection)>>, // db_path -> [(seq de rendu, connexion idle)]
    total: usize,                                     // nb total de connexions idle (toutes bases)
    seq: u64,                                         // horloge logique monotone (ordre LRU inter-bases)
}
impl ReadPool {
    fn new() -> Self { ReadPool { by_path: HashMap::new(), total: 0, seq: 0 } }
    /// Récupère une connexion idle DE CE db_path (jamais d'une autre base), ou None si aucune en pool.
    fn take(&mut self, db_path: &str) -> Option<Connection> {
        let v = self.by_path.get_mut(db_path)?;
        let c = v.pop().map(|(_, c)| c);
        if c.is_some() { self.total -= 1; }
        c
    }
    /// Rend une connexion au pool de SON db_path. Au-delà du CAP GLOBAL, éviction LRU inter-bases (la
    /// connexion idle la moins récemment rendue est fermée, quelle que soit sa base) -> total borné à CAP.
    fn put(&mut self, db_path: &str, conn: Connection) {
        if self.total >= READ_POOL_CAP {
            self.evict_lru();
        }
        self.seq += 1;
        let seq = self.seq;
        self.by_path.entry(db_path.to_string()).or_default().push((seq, conn));
        self.total += 1;
    }
    /// Ferme la connexion idle au `seq` le plus ANCIEN, toutes bases confondues (LRU inter-bases). Balayage
    /// O(nb idle) borné par CAP (≤8) -> négligeable. (Connexion retirée -> Drop la ferme proprement.)
    fn evict_lru(&mut self) {
        let mut best: Option<(String, usize, u64)> = None; // (db_path, index dans le Vec, seq)
        for (p, v) in self.by_path.iter() {
            for (i, (s, _)) in v.iter().enumerate() {
                if best.as_ref().map_or(true, |(_, _, bs)| *s < *bs) {
                    best = Some((p.clone(), i, *s));
                }
            }
        }
        if let Some((p, i, _)) = best {
            if let Some(v) = self.by_path.get_mut(&p) {
                if i < v.len() { v.remove(i); self.total -= 1; }
                if v.is_empty() { self.by_path.remove(&p); }
            }
        }
    }
}
static READ_POOL: std::sync::OnceLock<Mutex<ReadPool>> = std::sync::OnceLock::new();
fn read_conn_open(db_path: &str) -> Result<Connection, String> {
    let conn = Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(|e| e.to_string())?;
    apply_key_for(&conn, db_path);   // #2a-3 : clé DU TENANT (registre keyé db_path), pas db_key() global.
                                     // SQLCipher : la clé doit précéder toute requête. Non enregistré -> db_key() (mode 0).
    // Le BUDGET MÉMOIRE (temp_store/cache_size/mmap_size) est décidé par `sqlite_plafond` et NULLE PART
    // ailleurs : quatre sites le posaient, ils avaient déjà divergé, et sous `temp_store` en mémoire le
    // trieur de SQLite n'a AUCUN chemin de déversement (cf. la démonstration dans ce module).
    let _ = conn.execute_batch(&format!("PRAGMA query_only=ON; PRAGMA busy_timeout=3000; {}", sqlite_plafond::pragmas_memoire()));
    // WIRING SÉCU RÉUTILISABLE (#18 P3) — les UDF de requête, le HASH de masquage (#45) et l'AUTHORIZER DENY
    // sont installés par des helpers PARTAGÉS : le chemin HOT (ici) ET le chemin d'UNION hot∪cold du tier cold
    // (query_exec::run_on_conn via cold_store::open_cold_union) posent EXACTEMENT le même wiring -> le masquage
    // et le DENY s'appliquent aux lignes COLD par construction (même compilo, même authorizer). VERBATIM.
    install_query_udfs(&conn);
    install_fmask_udf(&conn);
    install_field_authorizer(&conn, db_path);
    Ok(conn)
}

/// #18 P3 — UDF de requête PURES (regexp / re_cap) : temps LINÉAIRE (pas de ReDoS), cap de longueur, cache
/// 1-motif. AUCUN état DB/salt/tenant -> installables sur N'IMPORTE quelle connexion de lecture (pool HOT ou
/// connexion d'UNION cold). Enregistrement inoffensif si jamais appelées (mode 0 byte-identique).
pub(crate) fn install_query_udfs(conn: &Connection) {
    // REGEXP : moteur regex de Rust (temps LINEAIRE garanti -> pas de ReDoS) + cap de longueur + cache 1-motif.
    // Le watchdog 3 s de run_query est un garde-fou supplementaire (defense en profondeur).
    use rusqlite::functions::FunctionFlags;
    let cache: std::cell::RefCell<Option<(String, regex::Regex)>> = std::cell::RefCell::new(None);
    let _ = conn.create_scalar_function(
        "regexp",
        2,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        move |ctx| {
            let pat = ctx.get::<String>(0)?;
            if pat.len() > 512 {
                return Err(rusqlite::Error::UserFunctionError("motif regex trop long (max 512)".into()));
            }
            let hay = match ctx.get_raw(1) {
                rusqlite::types::ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(),
                _ => return Ok(false), // NULL / non-texte -> pas de correspondance
            };
            let mut c = cache.borrow_mut();
            let re = match &*c {
                Some((p, r)) if *p == pat => r.clone(),
                _ => {
                    let r = regex::Regex::new(&pat).map_err(|e| rusqlite::Error::UserFunctionError(Box::new(e)))?;
                    *c = Some((pat.clone(), r.clone()));
                    r
                }
            };
            Ok(re.is_match(&hay))
        },
    );
    // re_cap(valeur, motif, groupe) -> texte du groupe nommé capturé (ou NULL). Sert à la commande | rex.
    let cap_cache: std::cell::RefCell<Option<(String, regex::Regex)>> = std::cell::RefCell::new(None);
    let _ = conn.create_scalar_function(
        "re_cap",
        3,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        move |ctx| {
            let hay = match ctx.get_raw(0) {
                rusqlite::types::ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(),
                _ => return Ok(None::<String>),
            };
            let pat = ctx.get::<String>(1)?;
            if pat.len() > 512 {
                return Err(rusqlite::Error::UserFunctionError("motif regex trop long (max 512)".into()));
            }
            let grp = ctx.get::<String>(2)?;
            let mut c = cap_cache.borrow_mut();
            let re = match &*c {
                Some((p, r)) if *p == pat => r.clone(),
                _ => {
                    let r = regex::Regex::new(&pat).map_err(|e| rusqlite::Error::UserFunctionError(Box::new(e)))?;
                    *c = Some((pat.clone(), r.clone()));
                    r
                }
            };
            Ok(re.captures(&hay).and_then(|caps| caps.name(&grp).map(|m| m.as_str().to_string())))
        },
    );
}

/// #18 P3 — HASH de masquage (#45) : fonction scalaire déterministe salée `plume_fmask_hash(v)` (émise par le
/// compilo GXQL quand un champ porte l'action HASH). Sel lu sur CETTE connexion depuis `meta.field_mask_salt`
/// (posé immuable par migrate_v86) -> stable = corrélation préservée. La connexion d'UNION cold ayant le HOT
/// en `main`, le sel se lit à L'IDENTIQUE (même `meta`). Enregistrée sur TOUTES les connexions de lecture
/// (inoffensif si jamais appelée -> mode 0 byte-identique).
pub(crate) fn install_fmask_udf(conn: &Connection) {
    use rusqlite::functions::FunctionFlags;
    let fmask_salt: String = conn
        .query_row("SELECT value FROM meta WHERE key='field_mask_salt'", [], |r| r.get(0))
        .unwrap_or_default();
    let _ = conn.create_scalar_function(
        "plume_fmask_hash",
        1,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        move |ctx| {
            let s = match ctx.get_raw(0) {
                rusqlite::types::ValueRef::Null => return Ok(None::<String>),
                rusqlite::types::ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(),
                rusqlite::types::ValueRef::Integer(n) => n.to_string(),
                rusqlite::types::ValueRef::Real(f) => f.to_string(),
                rusqlite::types::ValueRef::Blob(b) => format!("<blob {} o>", b.len()),
            };
            Ok(Some(crate::fmask_hash(&fmask_salt, &s)))
        },
    );
}

/// #18 P3 — AUTHORIZER DENY (#45 + secrets + v134 tables-miroirs) posé sur une connexion de lecture. Extrait
/// VERBATIM de `read_conn_open` -> le chemin HOT (pool) ET la connexion d'UNION hot∪cold du tier cold posent
/// EXACTEMENT le même authorizer : une règle DENY de champ (#45) ou la denylist de secrets s'applique donc aux
/// lignes COLD **automatiquement** (même préparateur, même set `field_deny_cols` keyé db_path). La table
/// ÉPHÉMÈRE `cold_event` (miroir EXACT de `event`, alimentée par l'hydratation cold) est traitée comme un
/// MIROIR de `event` : sans elle un `SELECT <col_déniée> FROM cold_event` échapperait au DENY qui frappe le
/// même `SELECT … FROM event`. VIDE (mode 0 / aucune règle) -> aucun déni ajouté -> lecture INCHANGÉE.
pub(crate) fn install_field_authorizer(conn: &Connection, db_path: &str) {
    // DURCISSEMENT 3 (défense en profondeur) — AUTHORIZER SQLite posé sur la connexion
    // read-pool : il REFUSE la LECTURE des colonnes de secrets (user.hash, token.token_hash) MÊME pour un
    // admin en SQL brut. Non contournable : il agit dans le préparateur SQLite (sqlite3_prepare), donc toute
    // requête qui référence ces colonnes échoue à `conn.prepare()` avec « not authorized » -> renvoyée en 400
    // par run_query_ex (aucun 500, aucune fuite, aucune ligne servie). Il ne casse NI le GXQL (qui ne lit
    // jamais ces colonnes), NI l'auth/login/token (portés par des connexions st.db distinctes, SANS
    // authorizer). Les autres colonnes de `user`/`token` (id, name, role, host, created…) et COUNT(*) restent
    // parfaitement lisibles. Closure capture `db_path` (String : Send + RefUnwindSafe + 'static) pour
    // consulter le set de colonnes réelles DENY de CE tenant (#45).
    let authz_db = db_path.to_string();
    conn.authorizer(Some(move |ctx: rusqlite::hooks::AuthContext<'_>| {
        use rusqlite::hooks::{AuthAction, Authorization};
        // FIELD FILTERS (#45) — une règle DENY sur une COLONNE RÉELLE de `event` (ex src_ip/message) est
        // enforcée ICI : déni de lecture au prepare() pour TOUS les rôles, admin compris, MÊME en SQL brut
        // (comme la denylist de secrets). Consulté dynamiquement -> une règle ajoutée après l'ouverture de la
        // connexion pooled prend effet immédiatement. VIDE (mode 0 / pas de règle DENY) -> aucun déni ajouté.
        if let AuthAction::Read { table_name, column_name } = ctx.action {
            // v134 (#9) — le DENY d'un champ (#45) doit couvrir NON SEULEMENT la colonne physique de `event`,
            // mais AUSSI les tables DÉRIVÉES/MIROIRS qui ré-exposent la même donnée en CLAIR (sinon un admin en
            // SQL brut lit `SELECT host FROM host_rollup` alors que `SELECT host FROM event` est DENY'd — même
            // fuite, autre table). ADDITIF & FAIL-SAFE : `deny_cols` VIDE (mode 0 / aucune règle DENY) -> AUCUN
            // déni ajouté -> lecture des rollups INCHANGÉE (le cas commun ; rollup-route intacte). Les denis ne
            // s'ajoutent QUE quand une règle DENY est active ET que la colonne lue est un miroir de la donnée
            // déniée. La granularité est PRÉCISE là où c'est possible (mêmes noms de colonnes) et CONSERVATRICE
            // là où la table mélange les valeurs de plusieurs champs (val des dims / contenu FTS -> déni dès
            // qu'UN champ est dénié, faute de savoir QUEL champ a produit la ligne).
            let deny = crate::field_deny_cols_cell().read();
            if let Some(cols) = deny.get(&authz_db) {
                if !cols.is_empty() {
                    let has = |c: &str| cols.iter().any(|x| x.eq_ignore_ascii_case(c));
                    let t = table_name;
                    let col = column_name;
                    let denied_mirror =
                        // `event` (colonne physique exacte) — comportement #45 EXISTANT, généralisé ici.
                        (t.eq_ignore_ascii_case("event") && has(col))
                        // #18 P3 — `cold_event` : table ÉPHÉMÈRE (hydratation cold) au SCHÉMA IDENTIQUE à `event`
                        // (colonnes physiques miroirs EXACTES). Une règle DENY d'un champ (#45) doit couvrir CE
                        // miroir SINON `SELECT src_ip FROM cold_event` (union hot∪cold) exfiltrerait EN COLD la
                        // colonne déniée EN HOT — même fuite, autre table. Scopé par colonne (miroir exact).
                        || (t.eq_ignore_ascii_case("cold_event") && has(col))
                        // `event_rollup(bucket,source,severity,action,n)` — source/severity miroirs (action
                        // n'est jamais un champ physique déniable -> jamais dans deny_cols -> pas de déni).
                        || (t.eq_ignore_ascii_case("event_rollup") && has(col))
                        // `host_rollup(host,...)` — la colonne host miroir de event.host.
                        || (t.eq_ignore_ascii_case("host_rollup") && col.eq_ignore_ascii_case("host") && has("host"))
                        // `event_dim_rollup(bucket,source,dim,val,n)` — source miroir exact ; `val` = VALEUR de
                        // dimension (peut être la valeur d'un champ physique dénié, ex. dim='src_ip') -> déni
                        // CONSERVATEUR dès qu'un champ est dénié (per-dim granularité indisponible ici). `dim`
                        // (NOM de dimension) n'est pas une valeur sensible -> reste lisible.
                        || (t.eq_ignore_ascii_case("event_dim_rollup") && col.eq_ignore_ascii_case("source") && has("source"))
                        || (t.eq_ignore_ascii_case("event_dim_rollup") && col.eq_ignore_ascii_case("val"))
                        // #28 PHASE A — SIDECAR ROLLUP COLD : `cold_rollup` (miroir EXACT d'event_rollup) et
                        // `cold_dim_rollup` (miroir d'event_dim_rollup) stockent des dims CIM en CLAIR dans la
                        // base tenant. Sans ces dénis, un admin en SQL brut lirait `SELECT src_ip FROM cold_rollup`
                        // (ou `val FROM cold_dim_rollup`) alors que `SELECT src_ip FROM event` est DENY'd — même
                        // fuite, autre table. Le rollup-route cold (try_cold_rollup_route) est de toute façon
                        // DÉSACTIVÉ dès qu'un masque/deny existe (comme le hot), mais ce miroir ferme AUSSI le
                        // chemin SQL brut (défense en profondeur, parité event_rollup/event_dim_rollup).
                        || (t.eq_ignore_ascii_case("cold_rollup") && has(col))
                        || (t.eq_ignore_ascii_case("cold_dim_rollup") && col.eq_ignore_ascii_case("source") && has("source"))
                        || (t.eq_ignore_ascii_case("cold_dim_rollup") && col.eq_ignore_ascii_case("val"))
                        // `event_fields_fts(v)` — `v` = group_concat de TOUTES les valeurs scalaires de `fields`
                        // (contient donc la valeur déniée) -> déni CONSERVATEUR du contenu FTS dès qu'un champ est
                        // dénié. Le chemin de recherche légitime (`... WHERE event_fields_fts MATCH ?`) projette
                        // `rowid` et matche sur la COLONNE-TABLE, PAS sur `v` -> non impacté.
                        || (t.eq_ignore_ascii_case("event_fields_fts") && col.eq_ignore_ascii_case("v"))
                        // `banned_ip(src_ip,source,label,...)` — table PLAINE matérialisée depuis `event`
                        // (`INSERT INTO banned_ip SELECT src_ip,'<source>',… FROM event`, rollups.rs). `src_ip`
                        // et `source` sont des miroirs EXACTS des colonnes de `event` : sans ces dénis, un admin
                        // en SQL brut lit `SELECT src_ip FROM banned_ip` alors que `SELECT src_ip FROM event`
                        // est DENY'd — même fuite, autre table. Scopé par colonne (granularité précise possible).
                        || (t.eq_ignore_ascii_case("banned_ip") && col.eq_ignore_ascii_case("src_ip") && has("src_ip"))
                        || (t.eq_ignore_ascii_case("banned_ip") && col.eq_ignore_ascii_case("source") && has("source"))
                        // `risk_rollup(entity_type,entity,...)` — `entity` porte la VALEUR d'entité (hostname pour
                        // entity_type='host', IP pour entity_type='ip' = défaut, cf. rule.risk_entity_type/field).
                        // Déni si host OU src_ip est dénié (miroir de event.host / event.src_ip) : cohérent avec le
                        // fait qu'un `by host`/`by src_ip` est déjà rejeté sur `event`. Scopé host+src_ip pour ne
                        // PAS casser les dashboards de risque par user/autre entité quand seul un autre champ est dénié.
                        || (t.eq_ignore_ascii_case("risk_rollup") && col.eq_ignore_ascii_case("entity") && has("host"))
                        || (t.eq_ignore_ascii_case("risk_rollup") && col.eq_ignore_ascii_case("entity") && has("src_ip"));
                    if denied_mirror {
                        return Authorization::Deny;
                    }
                }
            }
        }
        match ctx.action {
            AuthAction::Read { table_name, column_name }
                if (table_name.eq_ignore_ascii_case("user") && column_name.eq_ignore_ascii_case("hash"))
                    || (table_name.eq_ignore_ascii_case("token") && column_name.eq_ignore_ascii_case("token_hash"))
                    // #3a — le client_secret d'un connecteur externe (Defender/OAuth) est un CREDENTIAL :
                    // déni de lecture MÊME pour un admin en SQL brut (défense en profondeur, comme user.hash).
                    // Le poll (writer, hors authorizer) reste seul à pouvoir le lire ; la CRUD ne le sert jamais.
                    || (table_name.eq_ignore_ascii_case("connector") && column_name.eq_ignore_ascii_case("secret"))
                    // ANTI-FUITE PAR EXPORT — notifier.config porte le token ntfy / user:pass SMTP en CLAIR
                    // (blob JSON). notifiers_list ne projette JAMAIS `config` (has_auth seul) « même pour un admin » ;
                    // sans ce déni, `SELECT config FROM notifier` en SQL brut (/api/query, /api/export) ré-exfiltrait
                    // ces credentials. Déni de lecture MÊME admin, comme user.hash / token.token_hash / connector.secret.
                    || (table_name.eq_ignore_ascii_case("notifier") && column_name.eq_ignore_ascii_case("config"))
                    // #50 OUTPUTS/DESTINATIONS — `destination.config` porte le SECRET d'auth du sink externe
                    // (hec_token / auth_header webhook) en CLAIR (blob JSON). destinations_list ne projette
                    // JAMAIS `config` (has_auth seul) « même pour un admin » ; sans ce déni, `SELECT config FROM
                    // destination` en SQL brut (/api/query, /api/export) ré-exfiltrerait ces credentials. Déni de
                    // lecture MÊME admin, comme notifier.config / connector.secret. Le forwarder (writer, hors
                    // authorizer) reste seul à lire ce blob pour signer l'envoi.
                    || (table_name.eq_ignore_ascii_case("destination") && column_name.eq_ignore_ascii_case("config"))
                    // #44 IdP natif — le `secret` d'un fournisseur (client_secret OIDC / mot de passe de bind
                    // LDAP) est un CREDENTIAL : déni de lecture MÊME admin en SQL brut (comme connector.secret).
                    // Le login fédéré (writer/handler, hors authorizer) reste seul à pouvoir le lire ; la CRUD
                    // ne projette jamais `secret` (has_secret seul).
                    || (table_name.eq_ignore_ascii_case("idp_provider") && column_name.eq_ignore_ascii_case("secret"))
                    // #44 MFA — la GRAINE TOTP (`user_mfa.secret`) est le 2e facteur en clair : un admin (ou une
                    // session admin compromise) qui la lit peut CLONER la MFA d'un autre compte (contournement
                    // du 2e facteur). Les codes de secours (`user_mfa.recovery`, hachés) ne doivent pas fuiter
                    // non plus (surface d'énumération). Déni de lecture MÊME admin, comme user.hash. La vérif
                    // TOTP (handler, hors authorizer) reste seule à lire ces colonnes.
                    || (table_name.eq_ignore_ascii_case("user_mfa") && column_name.eq_ignore_ascii_case("secret"))
                    || (table_name.eq_ignore_ascii_case("user_mfa") && column_name.eq_ignore_ascii_case("recovery"))
                    // #16 AI — la clé/token du fournisseur d'inférence (`ai_provider.secret`, ex. `literal:sk-…`
                    // en clair) est un CREDENTIAL : déni de lecture MÊME admin en SQL brut, au même titre que
                    // toutes ses sœurs (connector/idp_provider/user_mfa/notifier/destination, également déniées). Gaté
                    // `#[cfg(feature=ai)]` (off défaut) ; le handler d'inférence (writer, hors authorizer) reste
                    // seul à la lire. Sans ce déni, `SELECT secret FROM ai_provider` en SQL brut ré-exfiltrait la clé.
                    || (table_name.eq_ignore_ascii_case("ai_provider") && column_name.eq_ignore_ascii_case("secret")) =>
            {
                Authorization::Deny
            }
            _ => Authorization::Allow,
        }
    }));
}
pub(crate) fn read_conn_get(db_path: &str) -> Result<Connection, String> {
    let pool = READ_POOL.get_or_init(|| Mutex::new(ReadPool::new()));
    if let Some(c) = pool.lock().take(db_path) {
        return Ok(c); // MT-KEY : uniquement une connexion ouverte sur CE db_path (jamais d'une autre base)
    }
    read_conn_open(db_path)
}
pub(crate) fn read_conn_put(db_path: &str, conn: Connection) {
    let pool = READ_POOL.get_or_init(|| Mutex::new(ReadPool::new()));
    pool.lock().put(db_path, conn); // CAP GLOBAL + éviction LRU inter-bases (cf. ReadPool)
}
/// Lecture sur une connexion read-only du pool (WAL) -> NE prend PAS le mutex d'écriture partagé,
/// donc les lectures fréquentes (dashboards/alertes/overview, x2 si 2 fenêtres) ne contendent plus
/// avec l'ingestion. La closure construit la valeur ; la connexion est rendue au pool. `default` si
/// la connexion échoue. (Snapshot WAL = lecture cohérente, légèrement décalée = OK pour de la lecture.)
pub(crate) fn read_with<T>(db_path: &str, default: T, f: impl FnOnce(&Connection) -> T) -> T {
    match read_conn_get(db_path) {
        Ok(conn) => {
            let out = f(&conn);
            read_conn_put(db_path, conn);
            out
        }
        Err(_) => default,
    }
}

/// M5a (refactor T1) — miroir ÉCRITURE de read_with : prend le mutex writer de la base du tenant courant
/// (req_db) et passe `&Connection` à la closure. Reproduit EXACTEMENT le boilerplate
/// `let __rc = req_db(&st, &au); let conn = __rc.lock();` puis usage de `conn` (même mutex,
/// même sémantique de garde relâchée en fin de closure). N'est SÛR mécaniquement que pour les corps sans
/// early-return/`?` (le reste des sites reste inline — la frontière closure croiserait le control-flow).
pub(crate) fn with_write<T>(st: &AppState, au: &AuthUser, f: impl FnOnce(&Connection) -> T) -> T {
    let rc = req_db(st, au);
    let conn = rc.lock();
    f(&conn)
}

// =====================================================================================
// GARDE DE BUDGET — LE SEUL MÉCANISME D'ARMEMENT D'UN BUDGET TEMPS SUR UNE LECTURE.
//
// CE QU'ELLE PROTÈGE (à ne pas perdre) : une requête folle (regex/FTS sans filtre, group-by sur
// des millions de lignes) monopoliserait un thread de lecture et un permit du sémaphore jusqu'à
// épuisement. La garde arme un fil qui appelle `interrupt()` sur la connexion au-delà du budget ;
// la requête remonte alors une erreur explicite au lieu de tourner sans fin. C'est un anti-DoS, et
// il est CONSERVÉ tel quel : même seuil, même interruption, même message.
//
// CE QUI CHANGE : l'ATTENTE. L'implémentation précédente SONDAIT un drapeau atomique
// (`sleep(50 ms)` en boucle) et le chemin de requête JOIGNAIT ce fil avant de rendre sa réponse.
// Conséquence MESURÉE : la latence de TOUTE lecture était arrondie au multiple de 50 ms supérieur
// (mesures p50 `server_ms` avant : SQL 0,76 ms -> 50,7 ms ; SQL 11,4 ms -> 50,8 ms ; SQL 20,5 ms ->
// 50,8 ms ; SQL 311 ms -> 351,9 ms). Ici l'attente est une CONDITION avec délai (condvar) : la fin
// de requête réveille la garde IMMÉDIATEMENT, donc le `join` ne coûte plus l'arrondi au tick suivant.
// Deux effets de bord, tous deux dans le bon sens :
//   * l'interruption tombe À l'échéance du budget, plus au multiple de 50 ms qui la suit (pour les
//     budgets livrés — 5 000 et 60 000 ms, multiples de 50 — l'échéance est INCHANGÉE) ;
//   * la décision d'interrompre est prise SOUS LE VERROU, donc une garde qui expire pendant que la
//     requête se termine n'interrompt plus (l'ancienne boucle sortait sur `waited >= budget` sans
//     relire le drapeau : elle pouvait interrompre une connexion déjà rendue au pool).
// =====================================================================================

/// Rendez-vous entre une lecture et sa garde de budget : `done` sous verrou + condvar de réveil.
struct BudgetGate {
    done: parking_lot::Mutex<bool>,
    woke: parking_lot::Condvar,
}

/// GARDE DE BUDGET, RAII. `budget_guard` l'arme ; son `Drop` signale la fin de requête et JOINT le
/// fil de garde. Il n'y a AUCUN chemin de sortie (retour, `?`, panique) qui évite ce `Drop`, donc
/// il est impossible d'oublier le signal, et impossible que l'interruption tombe après que la
/// connexion ait quitté la portée. Les champs sont privés et il n'existe pas d'autre constructeur :
/// un futur appelant qui veut un budget passe par ici — il ne peut pas re-fabriquer un sondage.
pub(crate) struct BudgetGuard {
    gate: Arc<BudgetGate>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Drop for BudgetGuard {
    fn drop(&mut self) {
        {
            let mut done = self.gate.done.lock();
            *done = true;
            self.gate.woke.notify_all(); // réveil IMMÉDIAT : plus d'arrondi au tick de sondage
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Arme la garde : au-delà de `budget_ms` sans fin de requête, `interrupt()` est appelé sur la
/// connexion dont vient `interrupt`. `budget_ms` est plancherisé à 1 ms (un budget nul serait une
/// interruption immédiate, pas une absence de garde).
pub(crate) fn budget_guard(interrupt: rusqlite::InterruptHandle, budget_ms: u64) -> BudgetGuard {
    let gate = Arc::new(BudgetGate { done: parking_lot::Mutex::new(false), woke: parking_lot::Condvar::new() });
    let g = gate.clone();
    let budget = Duration::from_millis(budget_ms.max(1));
    let thread = std::thread::spawn(move || {
        let mut done = g.done.lock();
        // `wait_while_for` re-teste la condition après chaque réveil -> immunise contre les réveils
        // spurieux (une condvar peut réveiller sans notification).
        let r = g.woke.wait_while_for(&mut done, |d| !*d, budget);
        if r.timed_out() && !*done {
            interrupt.interrupt();
        }
    });
    BudgetGuard { gate, thread: Some(thread) }
}

/// Budget des lectures de LISTE/PANNEAU passant par `read_with_watchdog` (alertes, cases, fraîcheur,
/// /api/search…). Nommé ici plutôt qu'en littéral au milieu de la fonction : c'est un seuil, pas une
/// constante de boucle.
const READ_WATCHDOG_BUDGET_MS: u64 = 5000;

// Comme read_with mais sous GARDE DE BUDGET (5 s) : interrompt un scan trop long (anti-DoS, cf
// /api/search : regex/FTS full-scan sans filtre = ~0.8s@1M, linéaire). À appeler depuis
// spawn_blocking (occupe le thread courant le temps de la requête ; n'occupe donc pas un worker
// async). Requête coupée -> default.
pub(crate) fn read_with_watchdog<T>(db_path: &str, default: T, f: impl FnOnce(&Connection) -> T) -> T {
    let conn = match read_conn_get(db_path) { Ok(c) => c, Err(_) => return default };
    let out = {
        // La garde est droppée à la SORTIE de ce bloc -> signal + join AVANT que la connexion ne
        // retourne au pool (ordre identique à l'ancien `done.store` + `join`).
        let _budget = budget_guard(conn.get_interrupt_handle(), READ_WATCHDOG_BUDGET_MS);
        f(&conn)
    };
    read_conn_put(db_path, conn);
    out
}

// =====================================================================================
// BUDGET DE REQUÊTE (CHANGEMENT 1) — seuil du watchdog PAR REQUÊTE, env-configurable.
//   - auto (panneaux / pagination / refresh / règles) : PLUME_QUERY_BUDGET_MS (défaut 5000) -> INCHANGÉ,
//     les tuiles restent protégées comme avant.
//   - interactif (analyste sur /api/query avec interactive:true) : PLUME_QUERY_BUDGET_INTERACTIVE_MS
//     (défaut 60000) -> une requête ad-hoc délibérée n'est plus coupée à 5 s.
// Le mécanisme d'interruption (watchdog + InterruptHandle) est INCHANGÉ ; seul le SEUIL devient un paramètre.
pub(crate) fn query_budget_ms() -> u64 {
    std::env::var("PLUME_QUERY_BUDGET_MS").ok().and_then(|v| v.parse().ok()).filter(|&n: &u64| n > 0).unwrap_or(5000)
}
pub(crate) fn query_budget_interactive_ms() -> u64 {
    std::env::var("PLUME_QUERY_BUDGET_INTERACTIVE_MS").ok().and_then(|v| v.parse().ok()).filter(|&n: &u64| n > 0).unwrap_or(60000)
}

// =====================================================================================
// ANNULATION SERVEUR (CHANGEMENT 2) — registre global des requêtes EN VOL, indexé par `qid` client.
// /api/query enregistre (sous le qid fourni) un handle d'interruption SQLite + un drapeau `cancelled` ;
// /api/cancel récupère le(s) handle(s) du qid, pose `cancelled` puis appelle interrupt() -> la requête en
// cours s'arrête proprement (message « annulé par l'utilisateur », pas un 500). RAII : chaque entrée est
// retirée au Drop du guard (succès, erreur OU timeout). InterruptHandle est Send+Sync. Un même qid peut
// porter plusieurs entrées (la page + le COUNT de pagination tournent en parallèle) : on les annule toutes.
pub(crate) struct CancelEntry {
    slot: u64,
    pub(crate) interrupt: rusqlite::InterruptHandle,
    pub(crate) cancelled: Arc<std::sync::atomic::AtomicBool>,
}
// MT-KEY: par (db_path, qid) — R5. Le qid est fourni par le CLIENT : deux bases (tenants) peuvent émettre
// le MÊME qid ; les clé par (db_path, qid) empêche que l'annulation d'une requête sur la base A interrompe
// une requête sans lien portant le même qid sur la base B (DoS/annulation croisée). En mono-tenant le
// db_path est unique -> exactement le même comportement qu'un registre clé par qid seul.
pub(crate) static QUERY_CANCEL: std::sync::OnceLock<Mutex<HashMap<(String, String), Vec<CancelEntry>>>> = std::sync::OnceLock::new();
static CANCEL_SLOT_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

// Guard RAII : retire SON entrée (par slot unique) du registre au Drop -> jamais de fuite, même en panic.
pub(crate) struct CancelGuard {
    db_path: String,
    qid: String,
    slot: u64,
}
impl Drop for CancelGuard {
    fn drop(&mut self) {
        if let Some(reg) = QUERY_CANCEL.get() {
            { let mut map = reg.lock();
                let key = (self.db_path.clone(), self.qid.clone());
                if let Some(vec) = map.get_mut(&key) {
                    vec.retain(|e| e.slot != self.slot);
                    if vec.is_empty() {
                        map.remove(&key);
                    }
                }
            }
        }
    }
}
pub(crate) fn cancel_register(db_path: &str, qid: &str, interrupt: rusqlite::InterruptHandle, cancelled: Arc<std::sync::atomic::AtomicBool>) -> CancelGuard {
    let slot = CANCEL_SLOT_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let reg = QUERY_CANCEL.get_or_init(|| Mutex::new(HashMap::new()));
    { let mut map = reg.lock();
        map.entry((db_path.to_string(), qid.to_string())).or_default().push(CancelEntry { slot, interrupt, cancelled });
    }
    CancelGuard { db_path: db_path.to_string(), qid: qid.to_string(), slot }
}

pub(crate) fn run_query(db_path: &str, sql: &str) -> Result<Value, String> {
    // budget AUTO par défaut (panneaux/pagination/refresh/règles) + aucune annulation client (pas de qid).
    run_query_ex(db_path, sql, query_budget_ms(), None)
}

/// Exécute un SELECT read-only avec un budget temps PARAMÉTRÉ (watchdog -> interrupt) et, si `qid` est
/// fourni, l'enregistre dans le registre d'annulation le temps de l'exécution (retiré au Drop du guard,
/// même en erreur/timeout). Distingue annulation utilisateur (message dédié) de dépassement de budget.
pub(crate) fn run_query_ex(db_path: &str, sql: &str, budget_ms: u64, qid: Option<&str>) -> Result<Value, String> {
    let conn = read_conn_get(db_path)?;
    let result = run_on_conn(&conn, db_path, sql, budget_ms, qid);
    read_conn_put(db_path, conn); // rend la connexion au pool de CE db_path (snapshot frais au prochain SELECT)
    result
}

/// #18 P3 — CŒUR d'exécution d'un SELECT read-only (watchdog+budget, registre d'annulation, garde
/// `stmt.readonly()`, plafond `PLUME_QUERY_MAX`) sur une connexion DÉJÀ construite. Extrait VERBATIM de
/// `run_query_ex` (corps INCHANGÉ, byte-identique pour le chemin HOT). Sépare l'ACQUISITION de connexion
/// (pool HOT dans `run_query_ex`) de l'EXÉCUTION -> la connexion d'UNION hot∪cold du tier cold (éphémère, NON
/// poolée) réutilise le MÊME cœur : même authorizer/masquage/budget que le HOT, appliqués aux lignes cold.
/// `cancel_key` = clé (db_path) du registre d'annulation. La connexion N'EST PAS rendue au pool ici
/// (l'appelant en gère le cycle de vie : le pool HOT via `run_query_ex`, la connexion cold via son Drop).
pub(crate) fn run_on_conn(conn: &Connection, cancel_key: &str, sql: &str, budget_ms: u64, qid: Option<&str>) -> Result<Value, String> {
    use std::sync::atomic::{AtomicBool, Ordering};
    let db_path = cancel_key;

    // ANNULATION SERVEUR : enregistre un handle sous `qid` si fourni (RAII, retiré au Drop). `cancelled`
    // distingue un interrupt() venu de /api/cancel d'un interrupt() venu du watchdog (budget).
    let cancelled = Arc::new(AtomicBool::new(false));
    let _cancel_guard = qid.map(|q| cancel_register(db_path, q, conn.get_interrupt_handle(), cancelled.clone()));

    // budget temps : la GARDE DE BUDGET interrompt la requête après `budget_ms` (anti-requête-folle).
    // SEUIL par requête (CHANGEMENT 1) ; mécanisme d'interruption inchangé. Le `Drop` de la garde
    // (fin de fonction, AVANT `_cancel_guard` qui est déclaré plus haut) signale la fin et joint le
    // fil : même ordonnancement que l'ancien `done.store(true)` + `watchdog.join()`, sans le sondage.
    let budget = budget_ms.max(1);
    let _budget_guard = budget_guard(conn.get_interrupt_handle(), budget);

    let result = (|| -> Result<Value, String> {
        let t0 = Instant::now();
        // TOUTE erreur de ce corps passe par `sqlite_plafond::message_erreur` : elle est rendue TELLE
        // QUELLE, sauf `SQLITE_NOMEM` — le seul code que le franchissement du budget mémoire peut
        // produire — qui devient un refus d'exploitant (ce qui s'est passé, ce qui n'a PAS été rendu, quoi
        // faire). Sans ça l'analyste lit « out of memory » et n'a aucune action.
        let mut stmt = conn.prepare(sql).map_err(|e| sqlite_plafond::message_erreur(&e))?;
        if !stmt.readonly() {
            return Err("seules les requêtes en lecture (SELECT/WITH) sont autorisées".into());
        }
        let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
        let ncol = cols.len();
        // plafond anti-DoS, CONFIGURABLE (PLUME_QUERY_MAX) -> "voir jusqu'où on peut". La pagination UI
        // affiche par tranches, donc le DOM tient même à 5000. Borné à 100k (garde-fou mémoire/transfert).
        let max_rows: usize = std::env::var("PLUME_QUERY_MAX").ok().and_then(|v| v.parse().ok()).filter(|&n| n > 0 && n <= 100_000).unwrap_or(5000);
        let mut out: Vec<Value> = Vec::new();
        let mut truncated = false;
        let mut rows = stmt.query([]).map_err(|e| sqlite_plafond::message_erreur(&e))?;
        loop {
            match rows.next() {
                Ok(Some(row)) => {
                    if out.len() >= max_rows {
                        truncated = true;
                        break;
                    }
                    let mut r = Vec::with_capacity(ncol);
                    for i in 0..ncol {
                        let v = match row.get_ref(i).map_err(|e| sqlite_plafond::message_erreur(&e))? {
                            rusqlite::types::ValueRef::Null => Value::Null,
                            rusqlite::types::ValueRef::Integer(n) => json!(n),
                            rusqlite::types::ValueRef::Real(f) => json!(f),
                            rusqlite::types::ValueRef::Text(t) => json!(String::from_utf8_lossy(t).into_owned()),
                            rusqlite::types::ValueRef::Blob(b) => json!(format!("<blob {} o>", b.len())),
                        };
                        r.push(v);
                    }
                    out.push(Value::Array(r));
                }
                Ok(None) => break,
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("interrupted") {
                        // interrupt() peut venir de /api/cancel (utilisateur) OU du watchdog (budget).
                        if cancelled.load(Ordering::Relaxed) {
                            return Err("requête annulée par l'utilisateur".into());
                        }
                        return Err(format!("requête interrompue (budget {} s dépassé)", budget / 1000));
                    }
                    // Le franchissement du budget MÉMOIRE tombe ici : c'est `rows.next()` qui porte le
                    // `SQLITE_NOMEM` d'un trieur/btree éphémère qui n'a plus le droit d'allouer. On sort en
                    // ERREUR — `out` est ABANDONNÉ, jamais rendu : un agrégat interrompu serait un chiffre
                    // faux présenté comme un total.
                    return Err(sqlite_plafond::message_erreur(&e));
                }
            }
        }
        let row_count = out.len();
        let elapsed_ms = (t0.elapsed().as_secs_f64() * 1_000_000.0).round() / 1000.0;
        Ok(json!({
            "columns": cols,
            "rows": out,
            "stats": { "elapsed_ms": elapsed_ms, "rows": row_count, "truncated": truncated }
        }))
    })();

    result
    // Droppés ICI, dans l'ordre inverse de déclaration : d'abord `_budget_guard` (signal + join de la
    // garde -> l'interruption ne peut plus tomber sur cette connexion), puis `_cancel_guard` (entrée
    // retirée du registre, même en erreur/timeout).
}
