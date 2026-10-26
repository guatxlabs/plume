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
    // `P10.29-l` (vague AR) — le texte rendu reste `e.to_string()` ; la CLASSE (support ou moteur, par le code) est
    // notée pour `en_classant`.
    let conn = Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| EchecDeRequete::par_le_code(&e, e.to_string()).noter())?;
    apply_key_for(&conn, db_path);   // #2a-3 : clé DU TENANT (registre keyé db_path), pas db_key() global.
                                     // SQLCipher : la clé doit précéder toute requête. Non enregistré -> db_key() (mode 0).
    // Le BUDGET MÉMOIRE (temp_store/cache_size/mmap_size) est décidé par `sqlite_plafond` et NULLE PART
    // ailleurs : quatre sites le posaient, ils avaient déjà divergé, et sous `temp_store` en mémoire le
    // trieur de SQLite n'a AUCUN chemin de déversement (cf. la démonstration dans ce module).
    let _ = conn.execute_batch("PRAGMA query_only=ON; PRAGMA busy_timeout=3000;");
    let _ = sqlite_plafond::armer(&conn);
    // WIRING SÉCU RÉUTILISABLE (#18 P3) — les UDF de requête, le HASH de masquage (#45) et l'AUTHORIZER DENY
    // sont installés par des helpers PARTAGÉS : le chemin HOT (ici) ET le chemin d'UNION hot∪cold du tier cold
    // (query_exec::run_on_conn via cold_store::open_cold_union) posent EXACTEMENT le même wiring -> le masquage
    // et le DENY s'appliquent aux lignes COLD par construction (même compilo, même authorizer). VERBATIM.
    install_query_udfs(&conn);
    install_fmask_udf(&conn);
    install_field_authorizer(&conn, db_path);
    Ok(conn)
}

/// #18 P3 — UDF de requête PURES (regexp / re_cap) : temps LINÉAIRE (pas de ReDoS), motif BORNÉ et cache à
/// plusieurs motifs servis par référence (`P10.32-q`, `regex_de_requete`). AUCUN état DB/salt/tenant ->
/// installables sur N'IMPORTE quelle connexion de lecture (pool HOT ou connexion d'UNION cold). Enregistrement
/// inoffensif si jamais appelées (mode 0 byte-identique).
pub(crate) fn install_query_udfs(conn: &Connection) {
    // REGEXP : moteur regex de Rust (temps LINEAIRE garanti -> pas de ReDoS). Longueur, taille du programme et
    // nombre de motifs gardés : `crate::regex_de_requete` (le MÊME constructeur que le tier froid).
    // Le watchdog 3 s de run_query est un garde-fou supplementaire (defense en profondeur).
    use crate::regex_de_requete::{motif_admissible, CacheDeMotifs};
    use rusqlite::functions::FunctionFlags;
    let cache = std::cell::RefCell::new(CacheDeMotifs::new());
    let _ = conn.create_scalar_function(
        "regexp",
        2,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        move |ctx| {
            let pat = ctx.get::<String>(0)?;
            motif_admissible(&pat).map_err(refus_du_motif_note)?;
            let hay = match ctx.get_raw(1) {
                rusqlite::types::ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(),
                _ => return Ok(false), // NULL / non-texte -> pas de correspondance
            };
            let mut c = cache.borrow_mut();
            let re = c.motif(&pat).map_err(refus_du_motif_note)?;
            Ok(re.correspond(&hay))
        },
    );
    // re_cap(valeur, motif, groupe) -> texte du groupe nommé capturé (ou NULL). Sert à la commande | rex.
    let cap_cache = std::cell::RefCell::new(CacheDeMotifs::new());
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
            motif_admissible(&pat).map_err(refus_du_motif_note)?;
            let grp = ctx.get::<String>(2)?;
            let mut c = cap_cache.borrow_mut();
            let re = c.motif(&pat).map_err(refus_du_motif_note)?;
            Ok(re.capture(&hay, &grp))
        },
    );
}

/// `P10.29-l` (vague AR) — LE REFUS D'UN MOTIF EST UNE PHRASE DU DÉMON (`regex_de_requete` : longueur, ou erreur de
/// la bibliothèque `regex` sur la saisie de l'analyste), pas un texte du moteur. L'UDF le rend à SQLite, qui ne le
/// classe pas (`SQLITE_ERROR`) : sa phrase exacte est donc notée ICI, sur le fil qui exécute, pour que le classeur
/// (`EchecDeRequete::du_moteur`) la range au PRODUIT quand l'échec rendu porte exactement ce texte.
fn refus_du_motif_note(refus: crate::regex_de_requete::MotifRefuse) -> rusqlite::Error {
    let e = refus.en_erreur_udf();
    PHRASE_DU_MOTIF_REFUSE.with(|p| *p.borrow_mut() = Some(e.to_string()));
    e
}

/// #18 P3 — HASH de masquage (#45) : fonction scalaire déterministe salée `plume_fmask_hash(v)` (émise par le
/// compilo GXQL quand un champ porte l'action HASH). Sel lu sur CETTE connexion depuis `meta.field_mask_salt`
/// (posé immuable par migrate_v86) -> stable = corrélation préservée. La connexion d'UNION cold ayant le HOT
/// en `main`, le sel se lit à L'IDENTIQUE (même `meta`). Enregistrée sur TOUTES les connexions de lecture
/// (inoffensif si jamais appelée -> mode 0 byte-identique).
///
/// `P10.33-r` — LE SEL EST RELU À LA DEMANDE, SEUL LE SUCCÈS EST MIS EN CACHE. Lu une seule fois à
/// l'installation, un échec TRANSITOIRE (« disk I/O error » d'un pod neuf) figeait le refus pour toute la
/// vie de la connexion, et les connexions vivent dans `READ_POOL`. Tant que le sel n'est pas établi,
/// chaque appel le relit SUR LA CONNEXION MÊME ; le premier échec arrête l'instruction (au plus une
/// relecture par instruction) ; un succès est gardé pour la vie de la connexion (un sel effacé ensuite ne
/// change pas le hash : la corrélation tient). Absent, vide ou illisible DURABLEMENT : refus à chaque
/// appel, comme avant.
pub(crate) fn install_fmask_udf(conn: &Connection) {
    use rusqlite::functions::FunctionFlags;
    // `P10.20-b` : un sel ABSENT ou ILLISIBLE n'est jamais "" — la fonction rend alors une ERREUR (la requête
    // HASH échoue fermé) au lieu d'un hash non salé de "\0"+valeur, attaquable au dictionnaire.
    let mut sel_etabli: Option<String> = match crate::read_field_mask_salt(conn) {
        Ok(Some(salt)) => Some(salt),
        Ok(None) => {
            eprintln!("[field_filter] sel de hachage ABSENT (meta.field_mask_salt) sur cette connexion — plume_fmask_hash le relira à chaque appel, et refusera tant qu'il manque");
            None
        }
        Err(e) => {
            eprintln!("[field_filter] sel de hachage ILLISIBLE sur cette connexion : {e} — plume_fmask_hash le relira à chaque appel, et refusera tant qu'il est illisible");
            None
        }
    };
    // SAFETY : l'adresse de la connexion sur laquelle la fonction est enregistrée. SQLite n'appelle la
    // fonction que sur CETTE connexion, ouverte (il la détruit à la fermeture) : la poignée est valide à
    // chaque appel. Elle n'est jamais fermée ni partagée par ce code.
    let poignee = PoigneeDeLaConnexion(unsafe { conn.handle() });
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
            if sel_etabli.is_none() {
                match relire_le_sel_sur(&poignee) {
                    Ok(Some(salt)) => sel_etabli = Some(salt),
                    Ok(None) => {
                        return Err(rusqlite::Error::UserFunctionError(
                            "sel de hachage (meta.field_mask_salt) absent : HASH refusé".into(),
                        ))
                    }
                    // Une INTERRUPTION de la relecture (annulation client, budget temps, quota de
                    // déversement : le rappel de progression vaut aussi pour l'instruction imbriquée) sort
                    // SOUS SON CODE, sans message (un message rabattrait le code sur `SQLITE_ERROR`) :
                    // l'instruction externe échoue en `SQLITE_INTERRUPT`, que `classer_l_echec` classe.
                    Err(EchecDeRelecture::Interrompue) => {
                        return Err(rusqlite::Error::SqliteFailure(
                            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_INTERRUPT),
                            None,
                        ))
                    }
                    Err(EchecDeRelecture::Illisible(e)) => {
                        // Le journal de l'hôte le dit aussi, avec le code étendu : le message rendu au
                        // client ne suffit pas à trancher un incident (au plus une ligne par instruction).
                        eprintln!("[field_filter] sel de hachage ILLISIBLE à la relecture : {e} — HASH refusé pour cette instruction");
                        return Err(rusqlite::Error::UserFunctionError(
                            format!("sel de hachage (meta.field_mask_salt) illisible : {e} — HASH refusé").into(),
                        ));
                    }
                }
            }
            match &sel_etabli {
                Some(salt) => Ok(Some(crate::fmask_hash(salt, &s))),
                None => Err(rusqlite::Error::UserFunctionError(
                    "sel de hachage (meta.field_mask_salt) absent ou illisible : HASH refusé".into(),
                )),
            }
        },
    );
}

/// La poignée brute de la connexion qui porte `plume_fmask_hash`, transportée dans la fermeture.
struct PoigneeDeLaConnexion(*mut rusqlite::ffi::sqlite3);
// SAFETY : la poignée n'est déréférencée que par SQLite, depuis la fonction scalaire, c'est-à-dire sur le
// fil qui exécute une instruction de CETTE connexion (rusqlite ne partage pas une `Connection` entre fils
// pendant une instruction). La fermeture n'est `Send` que parce que rusqlite l'exige à l'enregistrement.
unsafe impl Send for PoigneeDeLaConnexion {}

/// Pourquoi la relecture du sel n'a rien rendu : une interruption de l'instruction (elle sera classée
/// comme telle), ou une lecture ratée (le texte, avec le code étendu).
enum EchecDeRelecture {
    Interrompue,
    Illisible(String),
}

/// `P10.33-r` — RELIT `meta.field_mask_salt` SUR LA CONNEXION MÊME, depuis l'intérieur de la fonction
/// scalaire (SQLite admet qu'une fonction prépare et exécute une instruction sur sa propre connexion ;
/// l'authorizer et le rappel de progression de la connexion s'y appliquent). Mêmes issues que
/// `read_field_mask_salt` : `Ok(None)` = absent ou vide, `Err` = interruption ou lecture ratée (avec le code
/// étendu).
///
/// PAS `Context::get_connection` : en rusqlite 0.31, la `ConnectionRef` qu'elle rend, en tombant, passe par
/// `InnerConnection::close`, qui appelle `remove_hooks()` AVANT de tester `owned` — elle EFFACERAIT
/// l'authorizer DENY (secrets, champs déniés) et le rappel de progression (budget, quota de déversement) de
/// la connexion du pool. D'où les appels directs, sans objet rusqlite qui tombe.
fn relire_le_sel_sur(poignee: &PoigneeDeLaConnexion) -> Result<Option<String>, EchecDeRelecture> {
    use rusqlite::ffi;
    use rusqlite::types::{FromSql, ValueRef};
    const SQL: &[u8] = b"SELECT value FROM meta WHERE key='field_mask_salt'\0";
    let db = poignee.0;
    // Le code étendu et le message du moteur, mis en forme comme toute erreur SQLite du démon.
    let echec = |rc: std::os::raw::c_int| -> EchecDeRelecture {
        if rc & 0xff == ffi::SQLITE_INTERRUPT {
            return EchecDeRelecture::Interrompue;
        }
        // SAFETY : `db` est la connexion ouverte qui exécute cette fonction (cf. `install_fmask_udf`).
        let message = unsafe {
            let p = ffi::sqlite3_errmsg(db);
            (!p.is_null()).then(|| std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned())
        };
        let etendu = unsafe { ffi::sqlite3_extended_errcode(db) };
        let code = if etendu & 0xff == rc & 0xff { etendu } else { rc };
        EchecDeRelecture::Illisible(crate::sqlite_plafond::decrire_l_erreur(&rusqlite::Error::SqliteFailure(
            ffi::Error::new(code),
            message,
        )))
    };
    let mut st: *mut ffi::sqlite3_stmt = std::ptr::null_mut();
    // SAFETY : `db` est ouverte (cf. ci-dessus) ; `SQL` est terminée par NUL ; `st` est finalisée sur
    // TOUS les chemins qui l'ont obtenue (`sqlite3_finalize(NULL)` est sans effet).
    unsafe {
        let rc = ffi::sqlite3_prepare_v2(db, SQL.as_ptr().cast(), -1, &mut st, std::ptr::null_mut());
        if rc != ffi::SQLITE_OK {
            ffi::sqlite3_finalize(st);
            return Err(echec(rc));
        }
        let rendu = match ffi::sqlite3_step(st) {
            ffi::SQLITE_DONE => Ok(None),
            ffi::SQLITE_ROW => {
                // SAFETY (appelant) : `p`/`n` viennent de `sqlite3_column_*` sur la ligne courante ; la tranche
                // est consommée (copiée en `String`) avant tout autre appel sur `st`.
                unsafe fn octets<'a>(p: *const u8, n: std::os::raw::c_int) -> &'a [u8] {
                    if p.is_null() || n <= 0 { &[] } else { std::slice::from_raw_parts(p, n as usize) }
                }
                // La valeur telle que rusqlite la verrait (`r.get::<_, String>(0)`), convertie par le MÊME
                // `FromSql` : un BLOB, un nombre, un NULL ou un texte non UTF-8 sont « illisibles ».
                let valeur = match ffi::sqlite3_column_type(st, 0) {
                    ffi::SQLITE_NULL => ValueRef::Null,
                    ffi::SQLITE_INTEGER => ValueRef::Integer(ffi::sqlite3_column_int64(st, 0)),
                    ffi::SQLITE_FLOAT => ValueRef::Real(ffi::sqlite3_column_double(st, 0)),
                    ffi::SQLITE_TEXT => {
                        let p = ffi::sqlite3_column_text(st, 0);
                        ValueRef::Text(octets(p, ffi::sqlite3_column_bytes(st, 0)))
                    }
                    _ => {
                        let p = ffi::sqlite3_column_blob(st, 0).cast::<u8>();
                        ValueRef::Blob(octets(p, ffi::sqlite3_column_bytes(st, 0)))
                    }
                };
                match <String as FromSql>::column_result(valeur) {
                    Ok(sel) if sel.is_empty() => Ok(None),
                    Ok(sel) => Ok(Some(sel)),
                    Err(e) => Err(EchecDeRelecture::Illisible(format!(
                        "valeur de meta.field_mask_salt illisible en texte : {e}"
                    ))),
                }
            }
            rc => Err(echec(rc)),
        };
        ffi::sqlite3_finalize(st);
        rendu
    }
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
/// Rend une connexion de lecture au pool de SON db_path.
///
/// `P10.28-a` — UNE CONNEXION QUI REVIENT EN TRANSACTION EST FERMÉE, JAMAIS RECYCLÉE. Le pool ne sert une lecture
/// « fraîche » que parce que chaque `SELECT` en autocommit prend un instantané NEUF ; une connexion rendue avec un
/// instantané OUVERT (un `BEGIN` que son geste n'a pas fermé : `COMMIT` refusé, retour anticipé par `?`, panique
/// capturée) servirait à TOUTE lecture suivante, sur cette base, l'état figé de cet instant — et le point de reprise du
/// WAL ne peut pas franchir un lecteur qui tient un instantané. MESURÉ le 2026-09-25 sur la forme d'avant (témoin
/// `isdl_`, base en WAL) : la connexion rendue en transaction était remise au pool, la lecture suivante la recevait
/// toujours en transaction et ne voyait PAS une écriture validée entre-temps (compte 0 au lieu de 1). Elle est
/// désormais fermée (`drop`, qui annule l'instantané) avant même de prendre le verrou du pool, et le journal le dit :
/// c'est le geste qui l'a rendue ainsi qui est en faute, et rien d'autre ne le signalerait.
pub(crate) fn read_conn_put(db_path: &str, conn: Connection) {
    if !conn.is_autocommit() {
        eprintln!(
            "[lecture] ERREUR une connexion de lecture revient au pool EN TRANSACTION (un instantané que son geste n'a pas \
             fermé) : elle est FERMÉE, pas remise au pool — recyclée, elle aurait servi à toute lecture suivante un état \
             figé que le point de reprise du WAL ne peut pas franchir"
        );
        drop(conn);
        return;
    }
    let pool = READ_POOL.get_or_init(|| Mutex::new(ReadPool::new()));
    pool.lock().put(db_path, conn); // CAP GLOBAL + éviction LRU inter-bases (cf. ReadPool)
}
/// `P10.28-a` — le nombre de connexions de lecture AU REPOS pour CE db_path, lu par les témoins.
#[cfg(test)]
pub(crate) fn connexions_de_lecture_au_repos(db_path: &str) -> usize {
    READ_POOL.get().map_or(0, |pool| pool.lock().by_path.get(db_path).map_or(0, |v| v.len()))
}
/// Lecture sur une connexion read-only du pool (WAL) -> NE prend PAS le mutex d'écriture partagé,
/// donc les lectures fréquentes (dashboards/alertes/overview, x2 si 2 fenêtres) ne contendent plus
/// avec l'ingestion. La closure construit la valeur ; la connexion est rendue au pool. `default` si
/// la connexion échoue. (Snapshot WAL = lecture cohérente, légèrement décalée = OK pour de la lecture.)
/// LES DEUX CAUSES D'UN DÉFAUT GARDÉ (`P10.7-g`, lot 92), écrites une fois : aucune connexion de lecture (la valeur
/// par défaut de `read_with*` est servie), ou la tâche bloquante qui ne rend rien (jointure). Un défaut qui les porte
/// sous `error` n'est plus un corps rassurant : le consommateur lit la clé qu'il teste déjà.
pub(crate) const LECTURE_NON_FAITE_SANS_CONNEXION: &str = "lecture NON FAITE : aucune connexion de lecture disponible";
pub(crate) const LECTURE_NON_FAITE_TACHE_INTERROMPUE: &str = "lecture NON FAITE : la tâche de lecture ne s'est pas terminée";

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

/// État partagé entre une lecture et sa garde : `fini` (la requête a rendu la main, posé par le `Drop`)
/// et `annulee` (`P10.31-y` : `/api/cancel` a frappé cette requête, posé par `ReveilDeLaGarde`).
struct EtatDeLaGarde {
    fini: bool,
    annulee: bool,
}

/// Rendez-vous entre une lecture et sa garde de budget : état sous verrou + condvar de réveil.
struct BudgetGate {
    etat: parking_lot::Mutex<EtatDeLaGarde>,
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
            let mut etat = self.gate.etat.lock();
            etat.fini = true;
            self.gate.woke.notify_all(); // réveil IMMÉDIAT : plus d'arrondi au tick de sondage
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
impl BudgetGuard {
    /// La prise que le registre d'annulation garde sur CETTE garde (`P10.31-y`).
    pub(crate) fn reveil(&self) -> ReveilDeLaGarde {
        ReveilDeLaGarde(self.gate.clone())
    }
}

// `P10.31-y` — L'ANNULATION SUBIT LA MÊME PERTE QUE LE BUDGET : ELLE PASSE PAR LA MÊME GARDE.
// `/api/cancel` appelait `interrupt()` UNE fois. Tombée pendant la préparation ou avant le premier pas,
// cette interruption est effacée par SQLite exactement comme l'échéance de `P10.31-w`, et la requête
// annulée courait jusqu'à son budget (5 s, 60 s en interactif). Le registre garde désormais un RÉVEIL
// de la garde de la requête : l'annulation pose `annulee` sous le verrou de la garde et la réveille, et
// la garde entre dans la MÊME boucle de réitération que pour une échéance — jusqu'au signal de fin,
// sous le même verrou, donc rien n'interrompt la connexion après sa sortie de portée. Aucun budget ne
// change : sans annulation, la garde attend son échéance comme avant.
#[derive(Clone)]
pub(crate) struct ReveilDeLaGarde(Arc<BudgetGate>);
impl ReveilDeLaGarde {
    /// Fait réitérer la garde dès maintenant, jusqu'à la fin de la requête. Sous le verrou de la garde :
    /// une garde qui vient de tester sa condition ne peut pas manquer le réveil.
    pub(crate) fn annuler(&self) {
        let mut etat = self.0.etat.lock();
        etat.annulee = true;
        self.0.woke.notify_all();
    }
}

// `P10.31-w` — UNE INTERRUPTION UNIQUE PEUT ÊTRE PERDUE : LA GARDE LA RÉITÈRE JUSQU'À LA FIN.
// SQLite REMET À ZÉRO le drapeau d'interruption quand aucune instruction de la connexion n'est
// active, à DEUX endroits : au début de la préparation (`sqlite3RunParser`) et au premier pas
// (`sqlite3VdbeExec` via `sqlite3Step`, « prevents a call to sqlite3_interrupt from interrupting a
// statement that has not yet started »), lus dans `sqlcipher/sqlite3.c` de `libsqlite3-sys` 0.28
// (SQLite 3.39.4). Une échéance qui tombe AVANT le premier pas (préparation lente ou retenue,
// autorisateur, fil déprogrammé sous charge) était donc EFFACÉE, et la requête folle courait jusqu'au
// bout sans budget. Une fois l'échéance passée, la garde ne rend plus la main : elle réitère
// `interrupt()` tous les `REITERATION_DE_L_INTERRUPTION` jusqu'au signal de fin. Le PREMIER
// `interrupt()` tombe toujours À l'échéance (aucun délai élargi, aucun budget changé) ; la
// réitération ne fait que rendre l'échéance IMPOSSIBLE À EFFACER. Elle s'arrête sous le même verrou
// que le signal de fin, donc rien n'est interrompu après que la connexion a quitté la portée.
pub(crate) const REITERATION_DE_L_INTERRUPTION: Duration = Duration::from_millis(10);

// Instrument de TEST seulement : un témoin posé sur le fil appelant est emporté par la garde armée
// sur ce fil, qui y compte chaque `interrupt()` émis. Il permet à un témoin d'attendre que l'échéance
// soit PASSÉE (déterministe) au lieu de parier sur une durée. Absent du binaire livré.
#[cfg(test)]
thread_local! {
    static TEMOIN_DES_INTERRUPTIONS: std::cell::RefCell<Option<Arc<std::sync::atomic::AtomicUsize>>> =
        const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
pub(crate) fn temoin_des_interruptions_de_ce_fil(temoin: Option<Arc<std::sync::atomic::AtomicUsize>>) {
    TEMOIN_DES_INTERRUPTIONS.with(|t| *t.borrow_mut() = temoin);
}

// Instrument de TEST seulement (`P10.31-y`) : HORODATE, sur le fil de la garde, chaque `interrupt()`
// émis, au moment même où il est émis. Le témoin juge l'INTERVALLE entre deux interruptions successives,
// c'est-à-dire la période RÉELLE de la boucle, tout compris : ni la constante, ni l'argument d'une attente
// particulière, ni une attente isolée — tout ce que la boucle ferait entre deux interruptions y entre.
#[cfg(test)]
thread_local! {
    static TEMOIN_DE_LA_PERIODE: std::cell::RefCell<Option<Arc<parking_lot::Mutex<Vec<Instant>>>>> =
        const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
pub(crate) fn temoin_de_la_periode_de_ce_fil(temoin: Option<Arc<parking_lot::Mutex<Vec<Instant>>>>) {
    TEMOIN_DE_LA_PERIODE.with(|t| *t.borrow_mut() = temoin);
}

// Instrument de TEST seulement (`P10.32-c`) : le DÉROULÉ de la garde, sur son fil, pas à pas — chaque
// interruption émise et chaque attente DEMANDÉE avec la durée passée à l'attente. La période se juge alors
// sur ce que la boucle DEMANDE (une attente de `REITERATION_DE_L_INTERRUPTION`, et une seule, entre deux
// interruptions), sans chronomètre ; la garde statique `la_boucle_de_la_garde_n_attend_que_par_ses_deux_attentes`
// interdit toute autre attente bloquante dans `query_exec.rs`.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum PasDeLaGarde {
    Interruption,
    Attente(Duration),
}
#[cfg(test)]
thread_local! {
    static TEMOIN_DU_DEROULE: std::cell::RefCell<Option<Arc<parking_lot::Mutex<Vec<PasDeLaGarde>>>>> =
        const { std::cell::RefCell::new(None) };
    static TEMOIN_DE_L_ATTENTE: std::cell::RefCell<Option<Arc<std::sync::atomic::AtomicBool>>> =
        const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
pub(crate) fn temoin_du_deroule_de_ce_fil(temoin: Option<Arc<parking_lot::Mutex<Vec<PasDeLaGarde>>>>) {
    TEMOIN_DU_DEROULE.with(|t| *t.borrow_mut() = temoin);
}
/// `P10.32-c` — posé à `true` par le fil de la garde SOUS LE VERROU de la garde, juste avant sa première
/// attente. `ReveilDeLaGarde::annuler` prend ce verrou : une annulation lancée après avoir lu `true` ne
/// peut donc tomber qu'une fois la garde DANS son attente (l'attente seule rend le verrou) : le témoin du
/// réveil de `P10.32-c` n'attend aucun délai.
#[cfg(test)]
pub(crate) fn temoin_de_l_attente_de_ce_fil(temoin: Option<Arc<std::sync::atomic::AtomicBool>>) {
    TEMOIN_DE_L_ATTENTE.with(|t| *t.borrow_mut() = temoin);
}

/// La SEULE prise de la garde sur la connexion : une poignée d'interruption et, dans les tests seulement,
/// les instruments qui comptent et horodatent chaque interruption (`P10.31-y`). `interrompre` émet
/// l'interruption PUIS la note, dans la même fonction : une interruption notée est une interruption
/// émise par cette poignée. Ce n'est pas ce qui tient la période — une note posée sans émission reste
/// écrivable ici — : le témoin `la_periode_est_jugee_sur_les_interruptions_recues` juge l'EFFET (chaque
/// `SQLITE_INTERRUPT` rendu par le moteur), qu'aucune note ne fabrique.
struct Interrupteur {
    poignee: rusqlite::InterruptHandle,
    #[cfg(test)]
    compte: Option<Arc<std::sync::atomic::AtomicUsize>>,
    #[cfg(test)]
    periode: Option<Arc<parking_lot::Mutex<Vec<Instant>>>>,
    #[cfg(test)]
    deroule: Option<Arc<parking_lot::Mutex<Vec<PasDeLaGarde>>>>,
    #[cfg(test)]
    entree_dans_l_attente: Option<Arc<std::sync::atomic::AtomicBool>>,
}
impl Interrupteur {
    /// Emporte les instruments posés sur le fil APPELANT (celui qui arme la garde).
    fn du_fil_appelant(poignee: rusqlite::InterruptHandle) -> Self {
        Interrupteur {
            poignee,
            #[cfg(test)]
            compte: TEMOIN_DES_INTERRUPTIONS.with(|t| t.borrow().clone()),
            #[cfg(test)]
            periode: TEMOIN_DE_LA_PERIODE.with(|t| t.borrow().clone()),
            #[cfg(test)]
            deroule: TEMOIN_DU_DEROULE.with(|t| t.borrow().clone()),
            #[cfg(test)]
            entree_dans_l_attente: TEMOIN_DE_L_ATTENTE.with(|t| t.borrow().clone()),
        }
    }
    fn interrompre(&self) {
        self.poignee.interrupt();
        #[cfg(test)]
        {
            if let Some(d) = &self.deroule {
                d.lock().push(PasDeLaGarde::Interruption);
            }
            if let Some(p) = &self.periode {
                p.lock().push(Instant::now());
            }
            if let Some(t) = &self.compte {
                t.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
    }
    /// L'attente ENTRE DEUX interruptions (`P10.32-c`) : la durée notée est celle passée à l'attente,
    /// pas une variable voisine. La sortie est la même qu'avant : fin de requête, ou période écoulée.
    fn attendre_la_reiteration(
        &self,
        woke: &parking_lot::Condvar,
        etat: &mut parking_lot::MutexGuard<'_, EtatDeLaGarde>,
        demandee: Duration,
    ) {
        #[cfg(test)]
        if let Some(d) = &self.deroule {
            d.lock().push(PasDeLaGarde::Attente(demandee));
        }
        woke.wait_while_for(etat, |e| !e.fini, demandee);
    }
    #[cfg(test)]
    fn noter_l_entree_dans_l_attente(&self) {
        if let Some(a) = &self.entree_dans_l_attente {
            a.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

/// Arme la garde : au-delà de `budget_ms` sans fin de requête, ou dès une annulation reçue par
/// `ReveilDeLaGarde::annuler` (`P10.31-y`), `interrupt()` est appelé sur la connexion dont vient
/// `interrupt`, puis RÉITÉRÉ jusqu'à la fin de requête (`P10.31-w`). `budget_ms` est plancherisé à
/// 1 ms (un budget nul serait une interruption immédiate, pas une absence de garde).
pub(crate) fn budget_guard(interrupt: rusqlite::InterruptHandle, budget_ms: u64) -> BudgetGuard {
    let gate = Arc::new(BudgetGate {
        etat: parking_lot::Mutex::new(EtatDeLaGarde { fini: false, annulee: false }),
        woke: parking_lot::Condvar::new(),
    });
    let g = gate.clone();
    let budget = Duration::from_millis(budget_ms.max(1));
    let interrupteur = Interrupteur::du_fil_appelant(interrupt);
    let thread = std::thread::spawn(move || {
        let mut etat = g.etat.lock();
        #[cfg(test)]
        interrupteur.noter_l_entree_dans_l_attente();
        // `wait_while_for` re-teste la condition après chaque réveil -> immunise contre les réveils
        // spurieux (une condvar peut réveiller sans notification). Elle sort à l'échéance, à la fin
        // de requête, ou à l'annulation.
        g.woke.wait_while_for(&mut etat, |e| !e.fini && !e.annulee, budget);
        if etat.fini {
            return;
        }
        // Échéance passée ou annulation reçue : interrompre, puis réinterrompre tant que la requête
        // n'a pas signalé sa fin.
        while !etat.fini {
            interrupteur.interrompre();
            let periode = REITERATION_DE_L_INTERRUPTION;
            interrupteur.attendre_la_reiteration(&g.woke, &mut etat, periode);
        }
    });
    BudgetGuard { gate, thread: Some(thread) }
}

/// Budget des lectures de LISTE/PANNEAU passant par `read_with_watchdog` (alertes, cases, fraîcheur,
/// /api/search…). Nommé ici plutôt qu'en littéral au milieu de la fonction : c'est un seuil, pas une
/// constante de boucle.
pub(crate) const READ_WATCHDOG_BUDGET_MS: u64 = 5000;

// Comme read_with mais sous GARDE DE BUDGET (5 s) : interrompt un scan trop long (anti-DoS, cf
// /api/search : regex/FTS full-scan sans filtre = ~0.8s@1M, linéaire). À appeler depuis
// spawn_blocking (occupe le thread courant le temps de la requête ; n'occupe donc pas un worker
// async).
//
// CE QUE `default` COUVRE, ET CE QU'IL NE COUVRE PAS — MESURÉ LE 2026-08-30 (`P10.7-e`), parce que
// la phrase qui vivait ici affirmait l'inverse et qu'un correctif écrit sur sa foi manque sa cible.
// `default` est rendu sur UN SEUL chemin : `read_conn_get` n'a pas pu fournir de connexion. Quand la
// GARDE interrompt la requête, la closure `f` est DÉJÀ en cours ; c'est elle qui reçoit
// `SQLITE_INTERRUPT` de rusqlite, et c'est SA valeur qui remonte — `default` n'est pas consulté.
// Sonde jouée sur ce module : connexion impossible -> le `default` fabriqué est rendu ; budget épuisé
// à 5,004 s -> la valeur vient de la closure, et le `default` n'apparaît nulle part.
//
// POURQUOI L'ÉCART COMPTE. Les deux chemins n'ont pas la même fréquence. `read_conn_get` ne peut
// échouer que sur `Connection::open_with_flags` — fichier absent, descripteurs épuisés — et la
// CONCURRENCE ne le déclenche pas : aucun plafond ne borne les connexions EN COURS (`READ_POOL_CAP`
// ne borne que les connexions IDLE, et une prise sur pool vide OUVRE au lieu d'attendre).
// L'interruption, elle, est le chemin que la charge déclenche, par construction. Habiller `default`
// rend donc un appelant honnête sur le chemin RARE en le laissant muet sur le chemin FRÉQUENT : sur
// celui-là c'est la closure qui décide, et l'idiome livré la rend muette — `query_row(..).ok()` fait
// une absence d'un refus, et `query_map(..).flatten()` fait pire, une liste TRONQUÉE servie comme
// complète.
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
// `P10.7-f` — CE QU'UN PARCOURS DE LIGNES DOIT SAVOIR DIRE : LA FIN NORMALE OU L'INTERRUPTION.
//
// LE DÉFAUT. `stmt.query_map(..)` rend un itérateur de `Result`. L'idiome livré dans les
// gestionnaires est `.flatten().collect()` : il jette les `Err` et garde les `Ok`. Sur le chemin
// que la garde de budget déclenche PAR CONSTRUCTION, la valeur rendue est donc une liste PLUS
// COURTE, sans un mot — indiscernable d'un résultat complet. Ce n'est pas un refus rendu comme une
// absence (`P10.7-e`) : c'est un résultat PARTIEL rendu comme un TOTAL, et un analyste n'a rien à
// lire ni à compter qui puisse le lui apprendre.
//
// CE QUI A ÉTÉ MESURÉ LE 2026-08-30, sur une table de 200 lignes, avec une interruption rendue
// DÉTERMINISTE (fonction scalaire qui appelle `interrupt()` à la 51e ligne — pas un chronomètre) :
//   · `.flatten().collect()`                -> 51 lignes, AUCUNE erreur, aucune trace ;
//   · `.collect::<rusqlite::Result<Vec<_>>>()` -> `Err("interrupted")` ;
//   · sans interruption, le même parcours   -> 200 lignes (la troncature n'est pas un artefact).
//
// TROIS FAITS QUE CETTE MESURE A ÉTABLIS, ET QUI GOUVERNENT LA FORME CHOISIE ICI :
//
//   (1) APRÈS UNE ERREUR DE `step()`, L'ITÉRATEUR EST TARI. `Rows::advance` (rusqlite 0.31) appelle
//       `reset()` sur la branche `Err`, et `reset()` fait `self.stmt.take()` : l'appel suivant tombe
//       sur la branche `else`, rend `Ok(None)`, et `MappedRows` rend `None`. Le parcours s'ARRÊTE.
//       Une phrase qui vivait dans `handlers/search.rs` disait l'inverse — que l'idiome avalait
//       l'erreur puis REPRENAIT le pas, si bien que la garde ne coupait pas le balayage. La mesure
//       la réfute : la garde coupe bel et bien le balayage. Ce qu'elle ne fait pas, c'est le DIRE.
//
//   (2) UNE ERREUR DU MAPPEUR, ELLE, NE TARIT RIEN. `MappedRows::next` applique la closure APRÈS un
//       `step()` réussi : la ligne est SAUTÉE et le parcours continue (mesuré : 4 lignes rendues sur
//       5, la 3e — un texte là où un entier était demandé — évaporée). Un parcours qui s'arrêterait
//       à la première erreur échangerait donc une troncature contre une AUTRE troncature, sur un
//       chemin qui, lui, est nominal. D'où le choix : on VIDE l'itérateur exactement comme
//       `.flatten()` le fait, et on se contente de COMPTER ce qu'il jetait.
//
//   (3) UNE INTERRUPTION NE PORTE QUE SUR L'ÉNONCÉ EN VOL. Mesuré : l'énoncé interrompu rend 51
//       lignes, et l'énoncé SUIVANT de la même closure, sur la même connexion, en rend 200 ;
//       `interrupt()` appelé sans énoncé en vol est un no-op (200 lignes ensuite). Deux conséquences.
//       D'abord, dans une closure multi-énoncés, UNE seule liste du corps servi est tronquée pendant
//       que les autres sont complètes — la forme la plus indiscernable de toutes. Ensuite, « la garde
//       a tiré » N'EST PAS « une liste a été tronquée » : un aveu bâti sur le tir de la garde
//       avouerait à FAUX sur un corps complet. C'est pourquoi l'aveu est adossé à l'erreur que le
//       parcours VOIT, jamais à l'armement de la garde.
//
// CE QUE `Parcours` NE PRÉTEND PAS SAVOIR : COMBIEN de lignes manquent. Le nombre rendu est un
// nombre d'ERREURS, pas un nombre de lignes perdues — sur une interruption, une seule erreur solde
// un reste de cardinalité inconnue (l'énoncé est tari, personne n'a compté ce qu'il restait). Publier
// ce nombre comme un déficit de lignes serait la même faute d'un cran plus haut.
// =====================================================================================

/// Comment un parcours de lignes s'est terminé. `Complet` est le seul état dans lequel la liste
/// rendue EST la réponse de l'énoncé ; sinon elle n'en est qu'une partie, et la cause du moteur est
/// conservée telle qu'il l'a dite (`interrupted` pour la garde de budget comme pour /api/cancel).
pub(crate) enum FinDeParcours {
    Complet,
    /// `erreurs` = NOMBRE D'ERREURS RENCONTRÉES, jamais un nombre de lignes manquantes (cf. l'en-tête).
    Interrompu { erreurs: usize, cause: String },
    /// L'énoncé n'a jamais démarré (préparation ou liaison refusée) : la liste vide qui en sort n'est
    /// pas une absence de lignes, c'est une absence de LECTURE. Variante distincte parce que les deux
    /// n'apprennent pas la même chose — l'une dit « il en manque », l'autre « il n'y en a eu aucune ».
    NonCommence { cause: String },
}
impl FinDeParcours {
    /// La cause à publier, ou `None` si le parcours est allé au bout. Un appelant qui avoue
    /// INCONDITIONNELLEMENT n'avoue rien : cette porte est la seule qui existe.
    pub(crate) fn cause(&self) -> Option<&str> {
        match self {
            FinDeParcours::Complet => None,
            FinDeParcours::Interrompu { cause, .. } | FinDeParcours::NonCommence { cause } => Some(cause.as_str()),
        }
    }
    /// `P10.20-u` — LA FIN NOMMÉE, en clé stable : `interrompu` (le parcours a démarré et a été coupé : les lignes rendues
    /// sont un PRÉFIXE) ou `non_commence` (l'énoncé n'a jamais démarré : aucune ligne n'a été lue), `None` si complet.
    /// `cause()` rend le texte du moteur pour les deux, et c'est ce qui les confondait sur le fil : un relevé interrompu
    /// sans aucune ligne rendue se lisait « non commencé ».
    pub(crate) fn etat(&self) -> Option<&'static str> {
        match self {
            FinDeParcours::Complet => None,
            FinDeParcours::Interrompu { .. } => Some("interrompu"),
            FinDeParcours::NonCommence { .. } => Some("non_commence"),
        }
    }
    /// LE NOMBRE D'ERREURS RENCONTRÉES — jamais un nombre de lignes manquantes, et c'est la raison
    /// pour laquelle il n'est PAS publié tel quel dans un corps servi. Une interruption de `step()`
    /// vaut UNE erreur et solde un reste de cardinalité inconnue ; une erreur de mappeur vaut une
    /// erreur ET exactement une ligne sautée. Les deux comptes se ressemblent et ne s'additionnent
    /// pas : c'est la CAUSE qui les sépare.
    pub(crate) fn erreurs(&self) -> usize {
        match self {
            FinDeParcours::Complet => 0,
            FinDeParcours::Interrompu { erreurs, .. } => *erreurs,
            FinDeParcours::NonCommence { .. } => 0,
        }
    }
}

/// Ce qu'un parcours a rendu ET comment il s'est terminé.
pub(crate) struct Parcours<T> {
    pub(crate) lignes: Vec<T>,
    pub(crate) fin: FinDeParcours,
}

/// LE PARCOURS QUI DISTINGUE LA FIN NORMALE DE L'INTERRUPTION — remplaçant direct de
/// `.flatten().collect()`, et STRICTEMENT ADDITIF : l'itérateur est vidé de la même façon, dans le
/// même ordre, avec les mêmes lignes retenues. Sur un parcours sans erreur, `lignes` est le vecteur
/// que l'idiome précédent produisait, au même élément ; la seule chose qui s'ajoute est la
/// possibilité de dire que ce vecteur n'est PAS la réponse.
pub(crate) fn parcourir<T>(rows: impl Iterator<Item = rusqlite::Result<T>>) -> Parcours<T> {
    let mut lignes = Vec::new();
    let fin = parcourir_chaque(rows, |v| lignes.push(v));
    Parcours { lignes, fin }
}

/// LE MÊME PARCOURS, MAIS QUI NE MATÉRIALISE RIEN — remplaçant direct de `for x in rows.flatten() {…}`.
///
/// POURQUOI IL EXISTE, ET C'EST UNE MESURE QUI L'IMPOSE, PAS UN GOÛT. `parcourir` est un remplaçant
/// direct de `.flatten().collect()` — l'appelant voulait déjà le vecteur. Il n'en est PAS un pour la
/// BOUCLE : `for (srcs, detail) in rows.flatten() { … }` sur `alert WHERE status='new'` consomme les
/// lignes une par une et n'en garde AUCUNE ; y substituer `parcourir` matérialiserait toute la
/// sélection (ici : un `detail` complet par alerte active) avant la première itération. Ce dépôt tient
/// dans 2 Go par contrainte ; échanger une troncature muette contre un pic de mémoire serait payer
/// l'honnêteté avec la ressource qui manque. D'où cette forme : mêmes lignes, même ordre, même flux,
/// et rien de plus en mémoire qu'une cause.
///
/// Les DEUX règles de `parcourir` valent ici mot pour mot : on ne s'arrête PAS à la première erreur
/// (une erreur de mappeur ne tarit pas l'itérateur — s'arrêter troquerait une troncature contre une
/// autre, sur un chemin nominal), et la PREMIÈRE cause est celle qu'on garde (c'est elle qui a tari
/// l'énoncé). `chaque` n'est appelée que sur les lignes RÉELLEMENT lues : le corps de la boucle est
/// donc exécuté exactement comme avant.
pub(crate) fn parcourir_chaque<T>(
    rows: impl Iterator<Item = rusqlite::Result<T>>,
    mut chaque: impl FnMut(T),
) -> FinDeParcours {
    let mut erreurs = 0usize;
    let mut cause: Option<String> = None;
    for r in rows {
        match r {
            Ok(v) => chaque(v),
            Err(e) => {
                erreurs += 1;
                // La PREMIÈRE cause est gardée : c'est celle qui a tari l'énoncé, donc celle qui
                // explique le reste manquant. Les suivantes ne peuvent venir que du mappeur.
                if cause.is_none() {
                    cause = Some(e.to_string());
                }
            }
        }
    }
    match cause {
        None => FinDeParcours::Complet,
        Some(cause) => FinDeParcours::Interrompu { erreurs, cause },
    }
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
    /// `P10.31-y` — le réveil de la garde de la requête : l'annulation la fait réitérer jusqu'à la fin.
    /// `None` seulement pour une entrée posée sans garde (aucun chemin de lecture ne le fait).
    reveil: Option<ReveilDeLaGarde>,
    /// `P10.32-c` — l'identité qui a lancé la requête, lue dans le qid lié (`qid_d_annulation_de_la_requete`).
    proprietaire: ProprietaireDeLaRequete,
}
impl CancelEntry {
    /// LE GESTE DE `/api/cancel`, en un seul endroit (`P10.31-y`). Le drapeau d'abord (c'est lui qui
    /// classe l'interruption « annulée » et non « budget »), puis le réveil de la garde, qui réitère
    /// `interrupt()` jusqu'à la fin de la requête — une interruption UNIQUE tombée pendant la
    /// préparation ou avant le premier pas est effacée par SQLite —, puis une interruption immédiate,
    /// qui frappe la requête avant même que `/api/cancel` rende la main. `P10.32-c` : l'ordre et
    /// l'interruption immédiate sont témoignés (`annulation_proprietaire_et_ordre_structurel.rs`) ; les
    /// notes de test relisent le drapeau JUSTE APRÈS chaque geste.
    pub(crate) fn annuler(&self) {
        self.cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(r) = &self.reveil {
            r.annuler();
            #[cfg(test)]
            noter_le_geste_d_annulation(GesteDAnnulation::Reveil, &self.cancelled);
        }
        self.interrupt.interrupt();
        #[cfg(test)]
        noter_le_geste_d_annulation(GesteDAnnulation::Interruption, &self.cancelled);
    }
}

// Instrument de TEST seulement (`P10.32-c`) : sur le fil qui annule, chaque geste de `CancelEntry::annuler`
// et l'état du drapeau `cancelled` relu JUSTE APRÈS ce geste. Un drapeau posé après le réveil ou après
// l'interruption se lit `false` ici, sans fenêtre de temps à attraper.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum GesteDAnnulation {
    Reveil,
    Interruption,
}
#[cfg(test)]
thread_local! {
    static TEMOIN_DES_GESTES_D_ANNULATION: std::cell::RefCell<Option<Vec<(GesteDAnnulation, bool)>>> =
        const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
fn noter_le_geste_d_annulation(geste: GesteDAnnulation, cancelled: &std::sync::atomic::AtomicBool) {
    let pose = cancelled.load(std::sync::atomic::Ordering::SeqCst);
    TEMOIN_DES_GESTES_D_ANNULATION.with(|t| {
        if let Some(v) = t.borrow_mut().as_mut() {
            v.push((geste, pose));
        }
    });
}
/// Pose (`Some(vec![])`) ou retire (`None`) le témoin de ce fil ; rend ce qu'il avait noté.
#[cfg(test)]
pub(crate) fn temoin_des_gestes_d_annulation_de_ce_fil(
    temoin: Option<Vec<(GesteDAnnulation, bool)>>,
) -> Option<Vec<(GesteDAnnulation, bool)>> {
    TEMOIN_DES_GESTES_D_ANNULATION.with(|t| std::mem::replace(&mut *t.borrow_mut(), temoin))
}

// =====================================================================================
// `P10.32-c` — QUI PEUT ANNULER UNE REQUÊTE EN VOL.
// DÉCISION (la plus sûre, posée par l'orchestrateur de la vague X) : une annulation n'est honorée que pour
// l'identité qui a lancé la requête, ou pour un admin de la base ; sinon la réponse de `/api/cancel` est
// EXACTEMENT celle d'un qid inconnu (`cancelled: 0`) — elle ne révèle pas que le qid est en vol.
// Avant : sur une même base (mono-tenant = tous les comptes), quiconque connaissait un qid l'annulait.
//
// COMMENT L'IDENTITÉ VOYAGE. `/api/query` ne passe plus le qid du client tel quel : il le LIE à
// `au.name` (`qid_d_annulation_de_la_requete`), et c'est cette forme qui descend jusqu'au registre par
// `run_query_ex`, `run_on_conn` et les chemins du tier froid, sans changer leur signature. Le registre
// la DÉLIE (`delier_le_qid`) : la clé reste `(db_path, qid du client)`, le propriétaire va dans l'entrée.
// Forme liée : `\u{1}` + longueur en octets du nom + `:` + nom + qid du client. Le nom est lu par sa
// LONGUEUR, jamais par un séparateur : aucun qid choisi par un client ne peut se faire passer pour le
// nom d'un autre (le client ne contrôle que la queue).
//
// CE QUI N'EST PAS FERMÉ : une entrée posée avec un qid NU (non lié) reste annulable par tout appelant
// de la base — c'est la forme des témoins de `P10.31-y`. Aucune lecture de production ne la pose :
// `/api/query` lie toujours (témoin statique `la_route_query_lie_le_qid_a_son_proprietaire`).
const MARQUE_DU_QID_LIE: char = '\u{1}';

/// Le qid d'annulation de `/api/query` : celui du client (`qid`, rogné), LIÉ à l'identité de l'appelant.
/// `None` sans qid : la requête n'est pas annulable, comme avant.
pub(crate) fn qid_d_annulation_de_la_requete(body: &Value, au: &AuthUser) -> Option<String> {
    let qid = body.get("qid").and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty())?;
    Some(format!("{MARQUE_DU_QID_LIE}{}:{}{qid}", au.name.len(), au.name))
}

/// Le propriétaire d'une entrée du registre.
#[derive(Debug, PartialEq)]
enum ProprietaireDeLaRequete {
    /// Qid lié par `/api/query` : seule cette identité (ou un admin) l'annule.
    Lie(String),
    /// Qid nu (témoins de `P10.31-y`) : annulable par tout appelant de la base, comme avant.
    NonLie,
}

/// Délie un qid circulant : (propriétaire, qid du client). Un qid qui n'a pas la forme liée exacte est NU.
fn delier_le_qid(qid: &str) -> (ProprietaireDeLaRequete, &str) {
    let lie = qid.strip_prefix(MARQUE_DU_QID_LIE).and_then(|reste| {
        let (longueur, reste) = reste.split_once(':')?;
        let n: usize = longueur.parse().ok().filter(|_| longueur.bytes().all(|b| b.is_ascii_digit()))?;
        // `get` rend `None` hors bornes ou au milieu d'un caractère : la forme n'est alors pas liée.
        let nom = reste.get(..n)?;
        Some((nom.to_string(), &reste[n..]))
    });
    match lie {
        Some((nom, qid_client)) => (ProprietaireDeLaRequete::Lie(nom), qid_client),
        None => (ProprietaireDeLaRequete::NonLie, qid),
    }
}

/// Qui demande l'annulation (`/api/cancel`) : son nom et son autorité d'admin sur la base.
pub(crate) struct DemandeurDAnnulation<'a> {
    nom: &'a str,
    admin: bool,
}
impl<'a> DemandeurDAnnulation<'a> {
    pub(crate) fn de(au: &'a AuthUser) -> Self {
        DemandeurDAnnulation { nom: &au.name, admin: au.is_admin() }
    }
}
impl CancelEntry {
    /// `P10.32-c` — l'entrée est-elle annulable par ce demandeur ? Le propriétaire, un admin, ou tout
    /// appelant pour une entrée non liée.
    fn annulable_par(&self, d: &DemandeurDAnnulation<'_>) -> bool {
        match &self.proprietaire {
            ProprietaireDeLaRequete::Lie(nom) => d.admin || nom == d.nom,
            ProprietaireDeLaRequete::NonLie => true,
        }
    }
}
/// Ce que le registre retient d'une requête pour pouvoir l'annuler : son drapeau `cancelled` et, pour
/// une requête sous garde, le réveil de cette garde (`P10.31-y`).
pub(crate) struct DrapeauDAnnulation {
    cancelled: Arc<std::sync::atomic::AtomicBool>,
    reveil: Option<ReveilDeLaGarde>,
}
impl DrapeauDAnnulation {
    pub(crate) fn avec_reveil(cancelled: Arc<std::sync::atomic::AtomicBool>, reveil: ReveilDeLaGarde) -> Self {
        DrapeauDAnnulation { cancelled, reveil: Some(reveil) }
    }
}
// TESTS seulement : une entrée SANS réveil n'interrompt qu'une fois, c'est-à-dire le défaut d'avant
// `P10.31-y`. Hors des tests, la seule façon de bâtir l'entrée est `avec_reveil` : un appelant de
// production qui passerait un drapeau nu ne compile pas.
#[cfg(test)]
impl From<Arc<std::sync::atomic::AtomicBool>> for DrapeauDAnnulation {
    fn from(cancelled: Arc<std::sync::atomic::AtomicBool>) -> Self {
        DrapeauDAnnulation { cancelled, reveil: None }
    }
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
/// `qid` est le qid CIRCULANT : lié par `/api/query` (`qid_d_annulation_de_la_requete`) ou nu. La clé du
/// registre est `(db_path, qid du client)` ; le propriétaire lu dans la forme liée va dans l'entrée.
pub(crate) fn cancel_register(db_path: &str, qid: &str, interrupt: rusqlite::InterruptHandle, annulation: impl Into<DrapeauDAnnulation>) -> CancelGuard {
    let DrapeauDAnnulation { cancelled, reveil } = annulation.into();
    let (proprietaire, qid) = delier_le_qid(qid);
    let slot = CANCEL_SLOT_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let reg = QUERY_CANCEL.get_or_init(|| Mutex::new(HashMap::new()));
    { let mut map = reg.lock();
        map.entry((db_path.to_string(), qid.to_string())).or_default().push(CancelEntry { slot, interrupt, cancelled, reveil, proprietaire });
    }
    CancelGuard { db_path: db_path.to_string(), qid: qid.to_string(), slot }
}

/// `/api/cancel` : annule TOUTES les requêtes en vol de (db_path, qid) — la page et le COUNT de
/// pagination — que le demandeur a le droit d'annuler (`P10.32-c`), et rend leur nombre. Une requête
/// d'un autre compte n'est pas comptée : la réponse est celle d'un qid inconnu. Sous le verrou du
/// registre : une entrée dont le `CancelGuard` est déjà tombé n'est plus visible, donc rien n'est annulé
/// après la sortie de portée de la requête.
pub(crate) fn annuler_les_requetes_de(db_path: &str, qid: &str, demandeur: &DemandeurDAnnulation<'_>) -> u32 {
    let mut n = 0u32;
    if let Some(reg) = QUERY_CANCEL.get() {
        let map = reg.lock();
        if let Some(vec) = map.get(&(db_path.to_string(), qid.to_string())) {
            for e in vec.iter().filter(|e| e.annulable_par(demandeur)) {
                e.annuler();
                n += 1;
            }
        }
    }
    n
}

/// TESTS seulement : le geste d'un ADMIN de la base (toute entrée du qid), forme des témoins de `P10.31-y`.
#[cfg(test)]
pub(crate) fn annuler_les_requetes(db_path: &str, qid: &str) -> u32 {
    annuler_les_requetes_de(db_path, qid, &DemandeurDAnnulation { nom: "", admin: true })
}

/// `P10.31-y` — LA CAUSE D'UN ÉCHEC D'EXÉCUTION, la même aux trois sites (préparation, `stmt.query`,
/// pas). Une interruption n'était classée qu'au PAS : tombée pendant l'analyse, elle sortait avec le
/// texte brut du moteur (« interrupted »). Ordre conservé : le quota de déversement (seul à laisser une
/// note), puis l'annulation client, sinon le budget. Reconnue par son CODE et non par son texte : une
/// erreur de préparation recopie les identifiants de la requête, et une colonne nommée `interrupted`
/// ne doit pas devenir un dépassement de budget. Rend toujours `Err` (forme `Result` pour que chaque site
/// sorte par `return`, et que les phrases restent lisibles telles quelles par le harnais console).
#[allow(clippy::needless_return)]
fn classer_l_echec<T>(e: &rusqlite::Error, cancelled: &std::sync::atomic::AtomicBool, budget: u64) -> Result<T, String> {
    let interruption =
        matches!(e, rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::OperationInterrupted);
    if !interruption {
        // Le franchissement du budget MÉMOIRE tombe ici (`SQLITE_NOMEM`) : refus d'exploitant, sinon
        // le texte du moteur tel quel.
        return Err(EchecDeRequete::du_moteur(e).noter());
    }
    // `P10.29-l` (vague AR) — les trois phrases d'une interruption sont du PRODUIT.
    phrase_de_l_interruption(cancelled, budget).map_err(|phrase| EchecDeRequete::Produit(phrase).noter())
}

/// Les trois phrases d'une interruption (quota, annulation, budget), écrites telles que le harnais console les lit.
#[allow(clippy::needless_return)]
fn phrase_de_l_interruption<T>(cancelled: &std::sync::atomic::AtomicBool, budget: u64) -> Result<T, String> {
    // P10.1-b — TROIS CAUSES RENDENT LE MÊME CODE. Le franchissement du quota de déversement arrête
    // l'instruction par le rappel de progression, donc par une interruption ; il est reconnu D'ABORD
    // parce qu'il est le seul à laisser une note disant CE QUI a été mesuré. Sans lui, un volume qu'on
    // vient d'empêcher de se remplir serait rendu à l'analyste comme « budget dépassé ».
    if let Some(refus) = sqlite_plafond::refus_de_quota_de_deversement() {
        return Err(refus);
    }
    // interrupt() peut venir de /api/cancel (utilisateur) OU de la garde (budget).
    if cancelled.load(std::sync::atomic::Ordering::SeqCst) {
        return Err("requête annulée par l'utilisateur".into());
    }
    return Err(format!("requête interrompue (budget {} s dépassé)", budget / 1000));
}

/// `P10.29-l` (vague AR) — LA CLASSE D'UN ÉCHEC D'EXÉCUTION, DÉCIDÉE AU PRODUCTEUR ET PAR LE CODE DU MOTEUR.
///
/// `run_query_ex` et `run_on_conn` rendent un `String` à tous leurs appelants (rapports planifiés, alertes,
/// panneaux, sources de données) et ce texte ne change pas. Mais `/api/query` et `/api/export` servaient ce
/// texte TEL QUEL au client, au rôle lecteur : le refus de l'autorisateur cite l'énoncé compilé, l'UDF `regexp`
/// cite le motif, une erreur d'E/S se lisait comme une faute de l'analyste. La route a besoin de la CLASSE, et
/// le texte ne la porte pas : elle est décidée ICI, là où le code rusqlite est encore en main, et posée dans
/// `DERNIER_ECHEC_DU_FIL` (le fil de la tâche bloquante, celui qui exécute) ; la route la relit par
/// `en_classant`, sur le même fil.
///
/// TROIS CLASSES, ET RIEN D'AUTRE :
///  * `Support` — le code accuse le support de la base (`code_du_support`) : la route sert un 503 à phrase fixe ;
///  * `Occupee` — la base est occupée (`SQLITE_BUSY`, `SQLITE_LOCKED`, codes primaires) : ni le support ni la
///    requête ne sont en faute, la route sert un 503 à phrase fixe distincte (réessayer) ;
///  * `Produit` — une phrase écrite par le démon, par LISTE BLANCHE de ses producteurs : annulation, budget de
///    temps, lecture seule, refus du budget mémoire (`SQLITE_NOMEM` traduit par `sqlite_plafond`), quota de
///    déversement, refus d'un motif (`refus_du_motif_note` : trop long, ou invalide). Servie à l'octet ;
///  * `Moteur` — tout autre texte du moteur (syntaxe, colonne, autorisateur, motif, décodage d'une ligne), et
///    tout échec dont la classe n'a pas été notée (`en_classant`) : la route sert une phrase fixe.
///
/// `nature` est le code SQLite (étendu, puis son nom), jamais le message ; `texte` est le texte d'avant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EchecDeRequete {
    Support { nature: String, texte: String },
    Occupee { nature: String, texte: String },
    Produit(String),
    Moteur { nature: String, texte: String },
}

impl EchecDeRequete {
    /// Le texte que `run_query_ex` rend, INCHANGÉ, à ses autres appelants.
    pub(crate) fn texte(&self) -> &str {
        match self {
            EchecDeRequete::Support { texte, .. } | EchecDeRequete::Occupee { texte, .. } | EchecDeRequete::Moteur { texte, .. } => texte,
            EchecDeRequete::Produit(phrase) => phrase,
        }
    }

    /// Une erreur du moteur hors interruption, traduite par `sqlite_plafond::message_erreur` (texte d'avant) :
    /// le refus du budget mémoire et le refus d'un motif noté sur ce fil (texte ÉGAL) sont des phrases du produit,
    /// le reste est classé par son code.
    pub(crate) fn du_moteur(e: &rusqlite::Error) -> Self {
        let texte = sqlite_plafond::message_erreur(e);
        if matches!(e.sqlite_error_code(), Some(rusqlite::ErrorCode::OutOfMemory)) {
            return EchecDeRequete::Produit(texte);
        }
        let motif_refuse = PHRASE_DU_MOTIF_REFUSE.with(|p| p.borrow_mut().take());
        if motif_refuse.as_deref() == Some(texte.as_str()) {
            return EchecDeRequete::Produit(texte);
        }
        Self::par_le_code(e, texte)
    }

    /// Le support ou le moteur, par le CODE seul ; `texte` est celui que le site rendait.
    fn par_le_code(e: &rusqlite::Error, texte: String) -> Self {
        let nature = nature_de_l_echec(e);
        match code_de_l_echec(e) {
            Some(f) if code_du_support(f.code) => EchecDeRequete::Support { nature, texte },
            Some(f) if code_de_base_occupee(f.code) => EchecDeRequete::Occupee { nature, texte },
            _ => EchecDeRequete::Moteur { nature, texte },
        }
    }

    /// Pose la classe sur le fil courant pour `en_classant`, et rend le texte d'avant.
    fn noter(self) -> String {
        let texte = self.texte().to_string();
        DERNIER_ECHEC_DU_FIL.with(|d| *d.borrow_mut() = Some(self));
        texte
    }
}

thread_local! {
    /// Le dernier échec classé par le cœur d'exécution SUR CE FIL (`EchecDeRequete::noter`).
    static DERNIER_ECHEC_DU_FIL: std::cell::RefCell<Option<EchecDeRequete>> = const { std::cell::RefCell::new(None) };
    /// La phrase du dernier motif refusé par une UDF SUR CE FIL (`refus_du_motif_note`), remise à zéro à chaque
    /// énoncé (`run_on_conn`) et consommée par le classeur.
    static PHRASE_DU_MOTIF_REFUSE: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// `P10.29-l` (vague AR) — LES CODES D'UNE BASE OCCUPÉE (verrou tenu par un autre lecteur ou écrivain, au-delà du
/// délai d'attente) : un état passager, ni une faute de la requête ni une panne du support.
pub(crate) fn code_de_base_occupee(code: rusqlite::ErrorCode) -> bool {
    matches!(code, rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
}

/// `P10.29-l` (vague AR) — LES CODES QUI ACCUSENT LE SUPPORT DE LA BASE : E/S, ouverture, disque plein,
/// corruption, fichier qui n'est pas une base, protocole de verrou. MÊME ensemble que `est_erreur_du_support`
/// (`sqlite_plafond.rs`, privée) ; l'égalité des deux est jugée par un témoin qui lit la ligne `[sqlite]` que
/// celle-ci fait écrire, code par code.
pub(crate) fn code_du_support(code: rusqlite::ErrorCode) -> bool {
    use rusqlite::ErrorCode as C;
    matches!(
        code,
        C::SystemIoFailure | C::CannotOpen | C::DiskFull | C::DatabaseCorrupt | C::NotADatabase | C::FileLockingProtocolFailed
    )
}

/// La NATURE d'un échec, par liste blanche : le code SQLite (étendu, puis son nom) — celui d'un échec du moteur comme
/// celui d'une erreur de saisie (`SqlInputError`, dont le texte recopie l'énoncé) —, ou un libellé fixe pour une
/// erreur sans code. Jamais le message.
fn nature_de_l_echec(e: &rusqlite::Error) -> String {
    match code_de_l_echec(e) {
        Some(f) => format!("code SQLite {} ({:?})", f.extended_code, f.code),
        None => "erreur hors du code SQLite".to_string(),
    }
}

/// Le code SQLite d'un échec : celui d'un `SqliteFailure`, ou celui que porte une erreur de saisie (`SqlInputError`,
/// rendue à la préparation quand le moteur situe le jeton fautif), que `sqlite_error_code()` ne voit pas.
fn code_de_l_echec(e: &rusqlite::Error) -> Option<&rusqlite::ffi::Error> {
    e.sqlite_error().or_else(|| std::error::Error::source(e).and_then(|s| s.downcast_ref::<rusqlite::ffi::Error>()))
}

/// La nature d'un échec dont aucune classe n'a été notée sur le fil : il vient d'ailleurs que du cœur
/// d'exécution (hydratation du tier froid, noyaux vectorisés).
pub(crate) const NATURE_HORS_DU_COEUR: &str = "erreur hors du cœur d'exécution";

/// `P10.29-l` (vague AR) — EXÉCUTE `f` (un appel de `run_query_ex`, de `run_on_conn` ou d'une voie froide qui
/// l'emprunte) et rend la CLASSE de son échec. À appeler DANS la tâche bloquante, sur le fil qui exécute. La note
/// du fil est effacée AVANT l'appel ; elle n'est retenue que si son texte est EXACTEMENT celui de l'échec rendu
/// (sinon l'échec vient d'un autre producteur, après une note qu'il a ignorée). Toute autre issue est `Moteur`
/// sous `NATURE_HORS_DU_COEUR` : jamais servie telle quelle.
pub(crate) fn en_classant<T>(f: impl FnOnce() -> Result<T, String>) -> Result<T, EchecDeRequete> {
    DERNIER_ECHEC_DU_FIL.with(|d| *d.borrow_mut() = None);
    f().map_err(|texte| match DERNIER_ECHEC_DU_FIL.with(|d| d.borrow_mut().take()) {
        Some(note) if note.texte() == texte => note,
        _ => EchecDeRequete::Moteur { nature: NATURE_HORS_DU_COEUR.to_string(), texte },
    })
}

/// `P10.29-l` — la nature d'un échec de la voie froide qu'aucune note ne classe : la lecture du tier froid n'a pas été
/// faite. Liste blanche : jamais le texte rendu (il cite le chemin d'un fichier froid).
pub(crate) const NATURE_DE_LA_LECTURE_FROIDE: &str =
    "lecture du tier froid non faite (ouverture, horizon de lecture, hydratation ou décodage d'un fichier), hors du cœur d'exécution";

/// `P10.29-l` — les DEUX refus du produit que les voies froides rendent en `Err(String)` sans note, reconnus par leur
/// ouverture fixe : le plafond de groupes d'un agrégat froid (`refuse_group_explosion`, `cold_store/planner.rs`) et la
/// troncature impossible d'une part chaude (`ColdAnswer::expect_exact`, appelé par `hot_partial`). Ni l'un ni l'autre
/// n'est une base illisible : ils restent rangés comme avant (`Moteur`, phrase fixe en 400).
#[cfg_attr(not(feature = "cold_tier"), allow(dead_code))]
pub(crate) const REFUS_DU_PRODUIT_DANS_LE_FROID: [&str; 2] = [
    "refus de rendre un agrégat INCOMPLET : ce group-by dépasse ",
    "P4b hot_partial: troncature INATTENDUE sur un chemin sans hydratation froide (",
];

/// `P10.29-l` — `en_classant` POUR UNE VOIE FROIDE (`cold_union_query`, `cold_keyset_page`, `cold_vectorized_try`,
/// `cold_vectorized_merge_try`). Une note du fil dont le texte est celui de l'échec garde sa classe : le SQL de
/// l'appelant exécuté sur l'union par `run_on_conn` (refus du moteur en 400, support, base occupée, produit). Un refus
/// du produit (`REFUS_DU_PRODUIT_DANS_LE_FROID`) reste `Moteur` sous `NATURE_HORS_DU_COEUR`, comme `en_classant` le
/// rangeait. Tout autre échec sans note vient du tier froid lui-même — ouverture de la base, réglage de rétention non
/// lu (`HORIZON_FROID_NON_LU`), fichier sélectionné illisible, corrompu ou d'une autre identité, décodage colonnaire —
/// et devient `Support` : la route sert le 503 de la base illisible, plus un 400 qui accusait la requête.
/// HORS D'ATTEINTE, et rangé `Support` s'il arrivait : le refus du compilateur dans `hot_partial` (`planner.rs:1706` ;
/// le GXQL entier a déjà été compilé par la route, `hot_partial` n'en recompile que les deux premiers étages
/// (`planner.rs:1854`), que `map_soql` a acceptés (`planner.rs:1764`)) et les deux gardes défensives de l'hydratation froide
/// (environnement non conforme, écarté par `env_id_ok` avant l'appel, `reader.rs:1188` ; colonne hors `PARQUET_COLS`,
/// que `open_cold_union_avec` ne demande jamais, `reader.rs:1137`).
#[cfg_attr(not(feature = "cold_tier"), allow(dead_code))]
pub(crate) fn en_classant_la_voie_froide<T>(f: impl FnOnce() -> Result<T, String>) -> Result<T, EchecDeRequete> {
    DERNIER_ECHEC_DU_FIL.with(|d| *d.borrow_mut() = None);
    f().map_err(|texte| match DERNIER_ECHEC_DU_FIL.with(|d| d.borrow_mut().take()) {
        Some(note) if note.texte() == texte => note,
        _ if REFUS_DU_PRODUIT_DANS_LE_FROID.iter().any(|ouverture| texte.starts_with(ouverture)) => {
            EchecDeRequete::Moteur { nature: NATURE_HORS_DU_COEUR.to_string(), texte }
        }
        _ => EchecDeRequete::Support { nature: NATURE_DE_LA_LECTURE_FROIDE.to_string(), texte },
    })
}

/// `P10.29-w` — LE TEXTE D'UNE ERREUR SQLITE DE LA VOIE FROIDE (celui que `cold_store::pe` rendait), ET SA CLASSE
/// QUAND LA BASE EST OCCUPÉE. Les producteurs froids rendent `Err(String)` : le code de l'erreur était perdu, et
/// `en_classant_la_voie_froide` servait une base occupée (verrou tenu par un autre écrivain au-delà du délai d'attente)
/// sous le 503 de la base ILLISIBLE, qui dit « si le refus persiste, la base est illisible ». Ici la classe `Occupee`
/// est notée sur le fil, décidée par le CODE (`code_de_base_occupee`, jamais par le texte), et `en_classant_la_voie_froide`
/// la garde parce que le texte rendu est EXACTEMENT celui de la note. Toute autre erreur reste sans note : le classeur la
/// range au support, comme avant. `Moteur` n'est jamais noté ici : ces énoncés sont ceux du tier froid, pas le SQL de
/// l'appelant, et un 400 accuserait la requête. À appeler sur le fil qui exécute la voie froide, et seulement là où
/// l'erreur remonte TELLE QUELLE jusqu'au classeur (aucun `format!` entre les deux, sinon la note ne correspond plus).
#[cfg_attr(not(feature = "cold_tier"), allow(dead_code))]
pub(crate) fn texte_de_la_voie_froide(e: rusqlite::Error) -> String {
    let texte = e.to_string();
    match code_de_l_echec(&e) {
        Some(f) if code_de_base_occupee(f.code) => EchecDeRequete::Occupee { nature: nature_de_l_echec(&e), texte }.noter(),
        _ => texte,
    }
}

// Instrument de TEST seulement (`P10.31-y`) : un point d'arrêt juste avant la préparation, sur le fil
// appelant. Il place une annulation ou une échéance AVANT la préparation de façon déterministe.
#[cfg(test)]
thread_local! {
    static AVANT_LA_PREPARATION: std::cell::RefCell<Option<Box<dyn FnMut()>>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
pub(crate) fn avant_la_preparation_de_ce_fil(f: Option<Box<dyn FnMut()>>) {
    AVANT_LA_PREPARATION.with(|h| *h.borrow_mut() = f);
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
    use std::sync::atomic::AtomicBool;
    let db_path = cancel_key;

    // budget temps : la GARDE DE BUDGET interrompt la requête après `budget_ms` (anti-requête-folle).
    // SEUIL par requête (CHANGEMENT 1) ; mécanisme d'interruption inchangé.
    let budget = budget_ms.max(1);
    let budget_guard_de_la_requete = budget_guard(conn.get_interrupt_handle(), budget);

    // ANNULATION SERVEUR : enregistre un handle sous `qid` si fourni (RAII, retiré au Drop). `cancelled`
    // distingue un interrupt() venu de /api/cancel d'un interrupt() venu de la garde (budget). `P10.31-y` :
    // l'entrée porte le RÉVEIL de la garde, qui réitère l'interruption d'annulation jusqu'à la fin. Déclarée
    // APRÈS la garde, elle tombe AVANT elle : l'entrée quitte le registre (plus aucune annulation ne peut
    // atteindre cette connexion), PUIS la garde est signalée et jointe (plus aucune interruption).
    let cancelled = Arc::new(AtomicBool::new(false));
    let _cancel_guard = qid.map(|q| {
        let annulation = DrapeauDAnnulation::avec_reveil(cancelled.clone(), budget_guard_de_la_requete.reveil());
        cancel_register(db_path, q, conn.get_interrupt_handle(), annulation)
    });

    // P10.1-b — LA NOTE DE QUOTA DE DÉVERSEMENT EST REMISE À ZÉRO AVANT D'EXÉCUTER. Elle est posée par
    // le rappel de progression, sur CE fil ; une note qu'une requête précédente n'aurait pas consommée
    // ferait passer une annulation client ou un dépassement de budget pour un franchissement de quota,
    // c'est-à-dire un refus qui nomme la mauvaise cause.
    sqlite_plafond::oublier_refus_de_quota();
    // `P10.29-l` (vague AR) — même règle pour la phrase d'un motif refusé : une note laissée par un énoncé
    // précédent ne classe pas l'échec de celui-ci.
    PHRASE_DU_MOTIF_REFUSE.with(|p| *p.borrow_mut() = None);

    let result = (|| -> Result<Value, String> {
        let t0 = Instant::now();
        // TOUTE erreur de ce corps passe par `sqlite_plafond::message_erreur` : elle est rendue TELLE
        // QUELLE, sauf `SQLITE_NOMEM` — le seul code que le franchissement du budget mémoire peut
        // produire — qui devient un refus d'exploitant (ce qui s'est passé, ce qui n'a PAS été rendu, quoi
        // faire). Sans ça l'analyste lit « out of memory » et n'a aucune action.
        #[cfg(test)]
        AVANT_LA_PREPARATION.with(|h| {
            if let Some(f) = h.borrow_mut().as_mut() {
                f()
            }
        });
        #[cfg(test)]
        panne_de_test_au_coeur::armer_si_demandee(conn, db_path, sql);
        // `P10.31-y` — une interruption pendant l'analyse est CLASSÉE (annulation, quota ou budget).
        let mut stmt = match conn.prepare(sql) {
            Ok(stmt) => stmt,
            Err(e) => return classer_l_echec(&e, &cancelled, budget),
        };
        if !stmt.readonly() {
            return Err(EchecDeRequete::Produit("seules les requêtes en lecture (SELECT/WITH) sont autorisées".into()).noter());
        }
        let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
        let ncol = cols.len();
        // plafond anti-DoS, CONFIGURABLE (PLUME_QUERY_MAX) -> "voir jusqu'où on peut". La pagination UI
        // affiche par tranches, donc le DOM tient même à 5000. Borné à 100k (garde-fou mémoire/transfert).
        let max_rows: usize = std::env::var("PLUME_QUERY_MAX").ok().and_then(|v| v.parse().ok()).filter(|&n| n > 0 && n <= 100_000).unwrap_or(5000);
        let mut out: Vec<Value> = Vec::new();
        let mut truncated = false;
        // `stmt.query` ne fait que LIER (rusqlite 0.31 : aucun pas) ; classé quand même, par uniformité.
        let mut rows = match stmt.query([]) {
            Ok(rows) => rows,
            Err(e) => return classer_l_echec(&e, &cancelled, budget),
        };
        loop {
            match rows.next() {
                Ok(Some(row)) => {
                    if out.len() >= max_rows {
                        truncated = true;
                        break;
                    }
                    let mut r = Vec::with_capacity(ncol);
                    for i in 0..ncol {
                        // `P10.29-l` (vague AR) : même classeur qu'aux trois autres sites (une colonne n'est jamais
                        // interrompue : le texte rendu est celui de `message_erreur`, comme avant). HORS D'ATTEINTE :
                        // `get_ref` (rusqlite 0.31) n'échoue que sur un indice hors bornes, et `i < ncol`, le nombre
                        // de colonnes de CET énoncé (`stmt.column_names()` ci-dessus) ; aucun témoin ne peut l'armer.
                        let v = match row.get_ref(i).or_else(|e| classer_l_echec(&e, &cancelled, budget))? {
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
                // Le franchissement du budget MÉMOIRE tombe ici : c'est `rows.next()` qui porte le
                // `SQLITE_NOMEM` d'un trieur/btree éphémère qui n'a plus le droit d'allouer. On sort en
                // ERREUR — `out` est ABANDONNÉ, jamais rendu : un agrégat interrompu serait un chiffre
                // faux présenté comme un total. Interruption : quota, annulation ou budget.
                Err(e) => return classer_l_echec(&e, &cancelled, budget),
            }
        }
        let row_count = out.len();
        let elapsed_ms = (t0.elapsed().as_secs_f64() * 1_000_000.0).round() / 1000.0;
        // P10.9-a — L'OBSERVATOIRE D'USAGE DES INDEX, au POINT DE PASSAGE UNIQUE de toute lecture
        // (chemin chaud ET union chaud∪froid, qui empruntent tous deux ce cœur). ÉTEINT par défaut :
        // c'est alors un chargement atomique et rien d'autre. APRÈS `elapsed_ms`, délibérément — un
        // instrument de mesure ne doit pas gonfler la durée que l'analyste lit dans `stats`.
        index_usage::observatoire().observer(
            conn,
            sql,
            index_usage::Consommateur::deduit(budget_ms, qid, query_budget_interactive_ms()),
        );
        Ok(json!({
            "columns": cols,
            "rows": out,
            "stats": { "elapsed_ms": elapsed_ms, "rows": row_count, "truncated": truncated }
        }))
    })();

    result
    // Droppés ICI, dans l'ordre inverse de déclaration : d'abord `_cancel_guard` (entrée retirée du
    // registre, même en erreur/timeout : plus aucune annulation ne vise cette connexion), puis la garde
    // (signal + join -> l'interruption ne peut plus tomber sur cette connexion).
}

/// Instrument de TEST seulement (`P10.29-l`, vague AR) : arme la connexion d'exécution d'une base, au point de
/// passage de toute lecture (`run_on_conn`, connexion du pool comme connexion d'union du tier froid). Le compte de
/// pagination (`SELECT COUNT(*) AS n FROM (SELECT 1 FROM (…`) n'est pas visé : la panne tombe sur la PAGE, celle
/// dont la route sert l'échec. La demande est retirée quand elle arme (`encore_demandee` dit si elle a servi) ; la
/// connexion armée le reste : le témoin vide ensuite les connexions au repos de la base.
#[cfg(test)]
pub(crate) mod panne_de_test_au_coeur {
    use super::*;
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

    /// Le message que l'UDF `regexp` armée par `ErreurDuMoteur` écrit (il ne doit jamais atteindre un client).
    pub(crate) const MESSAGE_DE_LA_PANNE_DU_MOTEUR: &str = "panne de test du moteur";

    /// Une panne par classe : refus de l'autorisateur sur `event.message` (moteur), interruption par le rappel de
    /// progression (produit : budget de temps), erreur d'E/S rendue au pas par l'UDF `regexp` (support), base
    /// occupée rendue au pas par l'UDF `regexp` (`SQLITE_BUSY`), message d'erreur écrit par l'UDF `regexp` (moteur).
    #[derive(Clone, Copy, Debug, PartialEq)]
    pub(crate) enum PanneAuCoeur {
        RefusDeLAutorisateur,
        Interruption,
        ErreurDuSupport,
        BaseOccupee,
        #[cfg_attr(not(feature = "cold_tier"), allow(dead_code))]
        ErreurDuMoteur,
    }

    static DEMANDES: std::sync::OnceLock<Mutex<HashMap<String, PanneAuCoeur>>> = std::sync::OnceLock::new();

    fn demandes() -> &'static Mutex<HashMap<String, PanneAuCoeur>> {
        DEMANDES.get_or_init(|| Mutex::new(HashMap::new()))
    }

    pub(crate) fn demander(db_path: &str, panne: PanneAuCoeur) {
        demandes().lock().insert(db_path.to_string(), panne);
    }

    pub(crate) fn encore_demandee(db_path: &str) -> bool {
        demandes().lock().contains_key(db_path)
    }

    pub(crate) fn retirer(db_path: &str) {
        demandes().lock().remove(db_path);
    }

    pub(super) fn armer_si_demandee(conn: &Connection, db_path: &str, sql: &str) {
        if sql.starts_with("SELECT COUNT(*) AS n FROM (SELECT 1 FROM (") {
            return;
        }
        let Some(panne) = demandes().lock().remove(db_path) else {
            return;
        };
        let utf8 = rusqlite::functions::FunctionFlags::SQLITE_UTF8;
        match panne {
            PanneAuCoeur::RefusDeLAutorisateur => {
                conn.authorizer(Some(|ctx: AuthContext<'_>| match ctx.action {
                    AuthAction::Read { table_name, column_name } if table_name == "event" && column_name == "message" => Authorization::Deny,
                    _ => Authorization::Allow,
                }));
            }
            PanneAuCoeur::Interruption => {
                conn.progress_handler(1, Some(|| true));
            }
            PanneAuCoeur::ErreurDuSupport => {
                // Sans message : un message ferait rabattre le code sur SQLITE_ERROR (`sqlite3_result_error`).
                let _ = conn.create_scalar_function("regexp", 2, utf8, |_ctx| -> rusqlite::Result<bool> {
                    Err(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR_READ), None))
                });
            }
            PanneAuCoeur::BaseOccupee => {
                let _ = conn.create_scalar_function("regexp", 2, utf8, |_ctx| -> rusqlite::Result<bool> {
                    Err(rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY), None))
                });
            }
            PanneAuCoeur::ErreurDuMoteur => {
                let _ = conn.create_scalar_function("regexp", 2, utf8, |_ctx| -> rusqlite::Result<bool> {
                    Err(rusqlite::Error::UserFunctionError(MESSAGE_DE_LA_PANNE_DU_MOTEUR.into()))
                });
            }
        }
    }
}
