//! Intégrité + IP protégées. Ledger append-only à chaîne de hash tamper-evident (`ledger_append`),
//! double-audit fail-closed des mutations de config/source (`audit_config_change`/`audit_source_change`),
//! checkpoints signés Ed25519 (`ledger_key`/`sign_checkpoint`/`verify_run`, la concordance de ce qu'ils
//! attestent avec la chaîne qu'ils ancrent : `attestation_discordante`), et denylist d'IP protégées
//! (`PROTECTED_IP_MATCHERS`/`protected_ip_matchers`/`ip_is_protected` : loopback/RFC1918/opérateur ->
//! jamais bannies). Extrait de main.rs (refactor split #25 — byte-identique).
use crate::*;

// ---------- intégrité : ledger append-only à chaîne de hash + checkpoints Ed25519 (P3) ----------
/// `P10.7-m` — LE HACHAGE DU DERNIER MAILLON, celui auquel la prochaine entrée doit s'accrocher. Cette
/// fonction n'existe que pour DISCRIMINER SUR L'ERREUR, et c'est tout le correctif :
///  - `QueryReturnedNoRows` = journal VIERGE = l'ORIGINE LÉGITIME. La toute première écriture s'accroche à
///    la chaîne VIDE : c'est le chemin nominal, il réussit et il reste MUET ;
///  - TOUT autre échec (base illisible, clé SQLCipher absente, verrou, table absente, colonne d'un type
///    inattendu) = on ne SAIT PAS à quoi s'accrocher -> `Err`, et l'appelant REFUSE d'écrire.
///
/// CE QUE FAISAIENT LES DEUX APPELANTS AVANT LE 2026-08-31, ET POURQUOI C'ÉTAIT GRAVE : un
/// `unwrap_or_default()` confondait les deux cas. Une lecture ratée en MILIEU de chaîne écrivait donc un
/// maillon de `prev_hash` VIDE — un maillon ORPHELIN, parfaitement cohérent avec lui-même, en tête d'une
/// chaîne neuve que personne n'a déclarée.
///
/// POURQUOI REFUSER PLUTÔT QUE MARQUER LA RUPTURE OU DÉCLARER UNE CHAÎNE NEUVE — mesuré par MUTATION le
/// 2026-08-31 : le refus des vérificateurs est DOUBLEMENT ANCRÉ. Dans `verify_ledger_conn`, la comparaison
/// `prev_hash != prev` ET le RECALCUL `sha256(prev|ts|kind|detail)` sur le maillon COURANT attrapent
/// l'orphelin CHACUN SEUL (relâcher l'un laisse le témoin VERT ; il ne rougit qu'une fois les DEUX
/// relâchés) ; `ledger_verify_export` porte les deux mêmes ancrages. Les deux autres issues exigeraient
/// donc d'apprendre aux DEUX ancrages à laisser passer un chaînon vide — c'est-à-dire de CRÉER le chemin
/// par lequel une chaîne rompue devient verte. Fermer une fausse accusation en faisant taire une vraie.
///
/// ET LE COÛT DU REFUS EST CELUI QUE L'ON PAYAIT DÉJÀ : dans les cas où cette lecture échoue, l'INSERT qui
/// suit échoue lui aussi et il était avalé — l'événement était DÉJÀ perdu. Refuser ne perd que lui, au
/// lieu de lui ET de la chaîne.
pub(crate) fn ledger_prev_hash(conn: &Connection) -> rusqlite::Result<String> {
    match conn.query_row("SELECT hash FROM ledger ORDER BY id DESC LIMIT 1", [], |r| r.get::<_, String>(0)) {
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(String::new()), // journal vierge : origine légitime
        autre => autre,                                                // lu, ou illisible — jamais confondus
    }
}
/// Ajoute une entrée au journal d'intégrité (chaîne de hash, append-only, tamper-evident).
pub(crate) fn ledger_append(conn: &Connection, kind: &str, detail: &str) {
    let ts = now();
    // REFUS D'ÉCRIRE plutôt qu'un maillon ORPHELIN (cf. `ledger_prev_hash`) : une entrée manquante vaut
    // mieux qu'une chaîne rompue en silence. L'aveu est CONDITIONNEL — le chemin nominal ne dit rien — et
    // il ne porte que le `kind` : le `detail` peut nommer un compte ou une cible.
    let prev = match ledger_prev_hash(conn) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[ledger] WARN maillon '{kind}' NON écrit : hachage précédent ILLISIBLE ({e}) — l'écrire romprait la chaîne");
            return;
        }
    };
    let hash = sha256_hex(format!("{prev}|{ts}|{kind}|{detail}").as_bytes());
    let _ = conn.execute("INSERT INTO ledger(ts,kind,detail,prev_hash,hash) VALUES(?1,?2,?3,?4,?5)", params![ts, kind, detail, prev, hash]);
}
/// Double-audit d'une mutation de config (#1b), DANS la transaction courante (correctif M5, fail-closed) :
/// (1) ledger append-only tamper-evident ; (2) event source='plume-config' category='config' SOC-visible ET
/// alertable (c'est CE qui rend un admin malveillant — baisse de rétention / mute de source — visible dans la
/// durée). Renvoie Err si l'un des deux writes échoue -> l'appelant ROLLBACK (mutation JAMAIS persistée sans
/// audit). NE PAS remplacer par ledger_append (best-effort, avale l'erreur) : ici l'erreur DOIT remonter.
pub(crate) fn audit_config_change(conn: &Connection, ledger_kind: &str, ledger_detail: &str, severity: i64, msg: &str, fields: &str) -> rusqlite::Result<()> {
    audit_source_change(conn, "plume-config", ledger_kind, ledger_detail, severity, msg, fields)
}
/// GÉNÉRALISATION de `audit_config_change` avec `source` de contrôle paramétrable (le double-write reste
/// fail-closed transactionnel). Le `source` DOIT appartenir à la liste NON-PURGEABLE de retention_run (v72/v75 :
/// plume-config / plume-operator-access / plume-tenant-admin / plume-engagement) sinon l'event serait purgé. v75 :
/// `plume-engagement` (sev haute) = une DÉFENSE BAISSÉE (création d'un engagement pentest) -> le SOC alerte dessus.
pub(crate) fn audit_source_change(conn: &Connection, source: &str, ledger_kind: &str, ledger_detail: &str, severity: i64, msg: &str, fields: &str) -> rusqlite::Result<()> {
    let ts = now();
    // `P10.7-m` — le hachage précédent ILLISIBLE remonte comme n'importe quel autre échec de ce
    // double-write : l'appelant ROLLBACK. La mutation n'est pas persistée, et surtout la chaîne n'est pas
    // rompue. Journal vierge -> chaîne vide, c'est l'origine légitime (cf. `ledger_prev_hash`).
    let prev = ledger_prev_hash(conn)?;
    let hash = sha256_hex(format!("{prev}|{ts}|{ledger_kind}|{ledger_detail}").as_bytes());
    conn.execute("INSERT INTO ledger(ts,kind,detail,prev_hash,hash) VALUES(?1,?2,?3,?4,?5)", params![ts, ledger_kind, ledger_detail, prev, hash])?;
    conn.execute(
        // origin='daemon' (v72/M1) : SEUL le daemon pose ce marqueur -> cet audit est exclu de la purge
        // (retention_run) et un agent ne peut pas forger une ligne de contrôle non-purgeable équivalente.
        "INSERT INTO event(ts,source,category,severity,message,host,fields,origin) \
         VALUES(?1,?2,'config',?3,?4,'plume-daemon',?5,'daemon')",
        params![now(), source, severity, msg, fields],
    )?;
    Ok(())
}
/// v105 (CHANGE 2) — emplacement HISTORIQUE de la clé ledger, SUR le volume de données (co-localisée avec
/// la base). C'est le SEUL cas où une clé ABSENTE est AUTO-GÉNÉRÉE (compat ascendante : first-run d'une base
/// neuve). Un chemin de SECRET monté HORS /data (Vault->ESO, ex. /etc/plume/ledger/ledger.key) doit EXISTER :
/// s'il est absent/vide on REFUSE de générer (fail-closed) — sinon un restore sur volume neuf régénérerait une
/// clé DIFFÉRENTE et casserait EN SILENCE la vérification des checkpoints (continuité tamper-evidence perdue).
pub(crate) const LEDGER_KEY_LEGACY_DEFAULT: &str = "/var/lib/plume/db/ledger.key";

/// Un chemin est-il un emplacement LEGACY on-PVC (auto-génération d'une clé absente AUTORISÉE) ? Vrai pour le
/// défaut compilé ET tout chemin sous `/data/` (le manifest live pose `PLUME_LEDGER_KEY=/data/ledger.key`).
/// Un Secret monté HORS /data (ex. `/etc/plume/ledger/ledger.key`) -> FAUX -> la clé DOIT préexister (fail-closed).
pub(crate) fn ledger_key_path_is_legacy(path: &str) -> bool {
    path == LEDGER_KEY_LEGACY_DEFAULT || path.starts_with("/data/")
}

/// v105 — chemin ACTIF de la clé ledger, résolu comme `ledger_key` : `PLUME_LEDGER_KEY_PATH` (préféré, v105)
/// puis `PLUME_LEDGER_KEY` (compat) puis le défaut compilé. Une valeur VIDE de `PLUME_LEDGER_KEY_PATH`
/// n'écrase pas le fallback. Extrait pour que le backstop de cutover (server/mod.rs) et le signal SOC de
/// signature dégradée (retention_run) raisonnent EXACTEMENT sur le même chemin que le chargement de la clé.
pub(crate) fn ledger_key_active_path(conf: &HashMap<String, String>) -> String {
    let p = cfg(conf, "PLUME_LEDGER_KEY_PATH", "");
    if !p.trim().is_empty() { p } else { cfg(conf, "PLUME_LEDGER_KEY", LEDGER_KEY_LEGACY_DEFAULT) }
}

/// Charge (ou génère+persiste, 0600) la clé Ed25519 de signature des checkpoints. Chemin résolu par
/// `ledger_key_active_path`. La décision AUTO-GÉNÉRER vs FAIL-CLOSED dépend de `ledger_key_path_is_legacy`.
pub(crate) fn ledger_key(conf: &HashMap<String, String>) -> Option<ed25519_dalek::SigningKey> {
    let path = ledger_key_active_path(conf);
    let allow_generate = ledger_key_path_is_legacy(&path);
    ledger_key_load(&path, allow_generate)
}

/// v105 (CHANGE 2 backstop — HIGH d'audit) — verdict de la vérification d'ÉGALITÉ de clé au CUTOVER Vault.
/// La relocalisation de la clé (legacy on-PVC -> Secret Vault/ESO) suppose qu'un HUMAIN escrow la MÊME clé
/// hex dans Vault. Ce backstop CODE compare, quand les deux fichiers coexistent transitoirement, la clé
/// ACTIVE (Secret non-legacy) et la clé LEGACY résiduelle -> un écart = la clé Vault n'est PAS celle qui a
/// signé la chaîne existante -> fork SILENCIEUX de la tamper-evidence.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LedgerKeyCutover {
    /// Pas de fenêtre de cutover comparable : chemin actif legacy, OU un des deux fichiers absent/vide/illisible
    /// -> aucune décision (pas de faux positif : on ne bloque JAMAIS sur une simple absence).
    NotApplicable,
    /// Chemin actif non-legacy + legacy résiduel présent, MÊME clé -> continuité prouvée (cutover cohérent).
    Match,
    /// Chemin actif non-legacy + legacy résiduel présent, clés DIFFÉRENTES -> l'appelant REFUSE de démarrer.
    Mismatch,
}

/// v105 — cœur TESTABLE (aucun env, aucune génération, lecture pure de deux fichiers). Compare la clé
/// Ed25519 (32 o) à `active_path` (Secret Vault non-legacy) et à `legacy_path` (résidu on-PVC). Ne renvoie
/// `Mismatch` QUE si les DEUX décodent en 32 octets valides ET diffèrent (compare les OCTETS décodés, pas le
/// texte hex -> insensible casse/espaces). Chemin actif legacy, ou l'un des deux absent/vide/illisible/mal
/// formé -> `NotApplicable` (fail-open côté détection : ce backstop n'existe QUE pour attraper un ESCROW
/// DIVERGENT pendant la fenêtre de cutover, jamais pour bloquer un démarrage normal).
pub(crate) fn ledger_key_cutover_check(active_path: &str, legacy_path: &str) -> LedgerKeyCutover {
    if ledger_key_path_is_legacy(active_path) {
        return LedgerKeyCutover::NotApplicable; // pas de cutover Vault en cours
    }
    if active_path == legacy_path {
        return LedgerKeyCutover::NotApplicable; // même fichier -> rien à comparer
    }
    let read_key = |p: &str| -> Option<[u8; 32]> {
        let hex = std::fs::read_to_string(p).ok()?;
        let hex = hex.trim();
        if hex.is_empty() { return None; }
        hex_decode(hex)?.try_into().ok()
    };
    match (read_key(active_path), read_key(legacy_path)) {
        (Some(a), Some(l)) => if a == l { LedgerKeyCutover::Match } else { LedgerKeyCutover::Mismatch },
        _ => LedgerKeyCutover::NotApplicable, // un côté absent/vide/mal formé -> pas de fenêtre comparable
    }
}

/// SECRET-PROVIDER PHASE 1 (hygiène finale) — décision PURE et TESTABLE : le résidu legacy on-disque
/// (`/data/ledger.key`) est-il RETIRABLE en toute sécurité ? OUI (`true`) UNIQUEMENT si le cutover Vault est
/// PROUVÉ COHÉRENT — verdict `Match` de `ledger_key_cutover_check` : chemin actif NON-legacy + résidu présent
/// + MÊME clé Ed25519 décodée. Cette unique condition garantit :
///  - JAMAIS de retrait sur `Mismatch` (c'est tout l'intérêt du backstop : le résidu est alors la vérité, la
///    clé Vault a divergé -> on garde le résidu et on refuse de booter en amont) ;
///  - JAMAIS de retrait sur `NotApplicable` (résidu absent -> rien à faire ; OU chemin actif ENCORE legacy ->
///    le résidu POURRAIT être la clé active, on n'y touche pas).
/// Idempotent : une fois le résidu retiré, le prochain boot voit `NotApplicable` (résidu absent) -> no-op.
pub(crate) fn ledger_residue_removable(active_path: &str, residue_path: &str) -> bool {
    ledger_key_cutover_check(active_path, residue_path) == LedgerKeyCutover::Match
}

/// v105 (CHANGE 2 / STEP 2 — MED-HIGH) — émet UN signal SOC NON-PURGEABLE de SANTÉ DE SIGNATURE du ledger.
/// `source='plume-config'` + `origin='daemon'` -> déjà couvert par `RETENTION_NONPURGE` (JAMAIS purgé,
/// SOC-visible et alertable, comme l'audit de config). `category='health'`. DÉDUP HORAIRE (INSERT OR IGNORE
/// sur `dedup` UNIQUE) -> au plus 1 signal/heure par `kind` tant que la condition dure : un boot en
/// crashloop OU des ticks retention_run répétés ne tempêtent PAS (miroir de `emit_disk_health`). Renvoie
/// true si une ligne a été écrite. `now_ts` injecté pour la testabilité (comme emit_disk_health).
fn emit_ledger_health(conn: &Connection, now_ts: i64, kind: &str, severity: i64, msg: String, fields: String) -> bool {
    let bucket = now_ts / 3600; // dedup HORAIRE -> 1 signal/heure max (anti-tempête, y compris crashloop)
    let dedup = format!("plume-ledger-{kind}-{bucket}");
    let n = store().insert_event(conn, &EventRow {
        ts: now_ts,
        source: "plume-config".into(), // NON-PURGEABLE avec origin='daemon' (RETENTION_NONPURGE)
        category: "health".into(),
        severity,
        message: msg,
        host: Some("plume-daemon".into()),
        src_ip: None, dst_ip: None, url: None,
        dedup: Some(dedup),
        fields: Some(fields),
        engagement_id: String::new(),
        origin: "daemon".into(), // marqueur DAEMON -> exclut de la purge (un agent forgeur porte origin='')
        env_id: None,
    }).unwrap_or(0);
    n > 0
}

/// v105 (STEP 2) — signal SOC : la SIGNATURE des checkpoints est DÉGRADÉE (clé absente/vide sur un chemin
/// Secret NON-legacy -> `ledger_key()` a renvoyé None -> checkpoints NON signés). Fragilité Vault-reseal
/// oblige : l'opérateur DOIT le voir dans la console, pas seulement sur stderr. Sévérité 4 (P1).
pub(crate) fn emit_ledger_unsigned(conn: &Connection, now_ts: i64, active_path: &str) -> bool {
    let msg = format!(
        "SIGNATURE DU LEDGER DÉGRADÉE : clé absente/vide à '{active_path}' (chemin Secret non-legacy) — \
         checkpoints d'intégrité NON signés. Escrow/peuplement de la clé Vault requis (fail-closed : aucune \
         clé divergente générée). Vérifier ExternalSecret/Vault (reseal ?)."
    );
    let fields = json!({ "signing": "degraded", "reason": "key-absent-or-empty", "path": active_path }).to_string();
    emit_ledger_health(conn, now_ts, "unsigned", 4, msg, fields)
}

/// `P10.7-t` — signal SOC : LA SIGNATURE D'UN POINT DE CONTRÔLE A ÉTÉ REFUSÉE parce que la tête de chaîne
/// n'a pas pu être LUE. Sans lui, le correctif de `sign_checkpoint` ne vaudrait RIEN : ses deux appelants de
/// production ignorent la valeur de retour (un bras de `match` typé `()`), donc un refus muet remplacerait
/// un mensonge signé par une DISPARITION silencieuse des points de contrôle — le même défaut, déplacé.
///
/// MÊME CANAL QUE `emit_ledger_unsigned`, ET C'EST LA MÊME CLASSE DE PANNE : « les points de contrôle ne
/// s'écrivent plus ». `kind` DISTINCT (`checkpoint-refused` vs `unsigned`) parce que la CAUSE et le geste
/// de remédiation diffèrent — là, escrow la clé ; ici, la base ne se lit pas. Dédup HORAIRE partagée ->
/// un tick `retention_run` par heure plus un boot en crashloop ne font PAS de tempête.
///
/// CE QU'IL NE GARANTIT PAS, ET C'EST ÉCRIT PARCE QUE C'EST VRAI : l'aveu est un INSERT. Si la base est
/// illisible ET inécrivable, il échoue lui aussi et il ne reste que stderr (émis inconditionnellement par
/// l'appelant). Il MORD dans le cas mesuré — une lecture typée qui meurt sur une base par ailleurs vivante.
/// Sévérité 4 (P1) : une chaîne d'intégrité qui cesse d'être ancrée est une perte de preuve, pas un détail.
pub(crate) fn emit_ledger_checkpoint_refused(conn: &Connection, now_ts: i64, raison: &str) -> bool {
    let msg = format!(
        "POINT DE CONTRÔLE NON ÉCRIT : la tête de la chaîne d'intégrité n'a pas pu être lue ({raison}) — \
         AUCUNE signature n'est posée sur une chaîne qu'on n'a pas lue. La fenêtre en cours n'est PAS ancrée \
         (elle reste vérifiable par recalcul). Vérifier la lisibilité de la table `ledger` (clé SQLCipher, \
         restauration partielle, colonne d'un type inattendu)."
    );
    let fields = json!({ "signing": "refused", "reason": "ledger-head-unreadable", "detail": raison }).to_string();
    emit_ledger_health(conn, now_ts, "checkpoint-refused", 4, msg, fields)
}

/// v105 (STEP 1) — signal SOC : la clé Vault ACTIVE DIFFÈRE de la clé LEGACY résiduelle au cutover (fork
/// silencieux de la chaîne d'intégrité). Émis JUSTE AVANT le refus-de-boot (server/mod.rs) pour qu'une trace
/// non-purgeable subsiste malgré l'arrêt. Sévérité 4 (P1).
pub(crate) fn emit_ledger_key_mismatch(conn: &Connection, now_ts: i64, active_path: &str, legacy_path: &str) -> bool {
    let msg = format!(
        "CLÉ LEDGER INCOHÉRENTE AU CUTOVER : la clé Vault active '{active_path}' DIFFÈRE de la clé legacy \
         résiduelle '{legacy_path}'. La clé escrow dans Vault n'est PAS celle qui a signé la chaîne existante \
         -> fork d'intégrité. Escrow le BON hex avant le cutover, ou retirer le résidu legacy. Démarrage REFUSÉ."
    );
    let fields = json!({ "signing": "fork-risk", "reason": "vault-key-differs-from-legacy", "active": active_path, "legacy": legacy_path }).to_string();
    emit_ledger_health(conn, now_ts, "key-mismatch", 4, msg, fields)
}

/// Cœur TESTABLE (aucun env) : lit la clé Ed25519 (32 o hex) à `path`. Si absente :
///  - `allow_generate` (chemin legacy on-PVC) -> génère+persiste 0600 (comportement historique) ;
///  - sinon (Secret monté attendu) -> FAIL-CLOSED : `None` + log clair, JAMAIS de nouvelle clé silencieuse
///    (une clé divergente rendrait les checkpoints invérifiables sans le dire). Les appelants
///    (`sign_checkpoint` via `if let Some(k)`) sautent simplement la signature -> dégradation SÛRE.
///  - `path` présent mais VIDE (Secret pas encore peuplé par ESO) suit la MÊME règle que l'absence.
pub(crate) fn ledger_key_load(path: &str, allow_generate: bool) -> Option<ed25519_dalek::SigningKey> {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::read_to_string(path) {
        // clé PRÉSENTE et non vide : lecture normale (inchangée) — legacy comme Secret.
        Ok(hex) if !hex.trim().is_empty() => {
            let bytes: [u8; 32] = hex_decode(hex.trim())?.try_into().ok()?;
            Some(ed25519_dalek::SigningKey::from_bytes(&bytes))
        }
        // fichier PRÉSENT mais VIDE (Secret monté non encore peuplé par ESO, ou clé tronquée) : on NE régénère
        // JAMAIS par-dessus (ni legacy ni Secret) — écraser une clé possiblement corrompue romprait la
        // continuité de vérification. Fail-closed : None (comportement legacy historique préservé) + log si Secret.
        Ok(_) => {
            if !allow_generate {
                eprintln!(
                    "[ledger] clé VIDE à '{path}' — chemin NON-legacy (Secret escrow attendu, non peuplé ?) : \
                     fail-closed, checkpoints NON signés. NE PAS régénérer (romprait la vérification du ledger)."
                );
            }
            None
        }
        // fichier ABSENT : génération AUTORISÉE uniquement sur emplacement legacy on-PVC (first-run base neuve).
        Err(_) => {
            if !allow_generate {
                eprintln!(
                    "[ledger] clé ABSENTE à '{path}' — chemin NON-legacy (Secret escrow attendu) : REFUS de \
                     générer une nouvelle clé (fail-closed). Checkpoints NON signés jusqu'à provisionnement. \
                     NE PAS régénérer : une clé divergente romprait EN SILENCE la continuité de vérification."
                );
                return None;
            }
            use std::io::Read;
            let mut b = [0u8; 32];
            std::fs::File::open("/dev/urandom").ok()?.read_exact(&mut b).ok()?;
            let _ = std::fs::write(path, hex_encode(&b));
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            Some(ed25519_dalek::SigningKey::from_bytes(&b))
        }
    }
}
/// `P10.7-u` — LA VALEUR QU'ATTESTE UN POINT DE CONTRÔLE POSÉ SUR UN JOURNAL VIERGE. Elle est
/// HISTORIQUE et délibérément conservée (la changer ferait diverger les points de contrôle d'origine
/// anciens et neufs sans rien gagner) ; elle est nommée ici parce qu'elle est désormais lue par DEUX
/// sites — celui qui l'écrit et celui qui la reconnaît — et qu'un littéral recopié dans le second se
/// serait tu le jour où le premier aurait changé.
pub(crate) const ATTESTATION_ORIGINE: &str = "genesis";

/// Ce qu'on IMPRIME d'une attestation qu'on refuse. Un `ledger_hash` légitime est un sha256 de 64
/// caractères — publié tel quel dans l'export inaltérable, donc sans secret. Mais une attestation
/// DISCORDANTE est, par définition, une valeur que le produit n'a pas écrite : elle peut être de
/// n'importe quelle longueur et de n'importe quel contenu. On la borne donc avant de la rendre à un
/// flux, et on nomme le vide plutôt que d'imprimer rien du tout.
fn apercu_d_attestation(v: &str) -> String {
    if v.is_empty() {
        return "attestation VIDE".to_string();
    }
    let court: String = v.chars().take(16).collect();
    if v.chars().count() > 16 { format!("« {court}… »") } else { format!("« {court} »") }
}

/// `P10.7-u` — LE POINT DE CONTRÔLE CONCORDE-T-IL AVEC LA CHAÎNE QU'IL ANCRE ? Cœur PUR (aucune base,
/// aucun env, aucune horloge lue : les deux horodatages sont des DONNÉES, prises en argument).
///
/// LA QUESTION QUI DÉCIDE VIENT AVANT LE CODE, ET SA RÉPONSE EST LUE DANS `sign_checkpoint_result`,
/// PAS SUPPOSÉE : un point de contrôle atteste LA TÊTE DE LA CHAÎNE À L'INSTANT OÙ IL A ÉTÉ ÉCRIT —
/// le `hash` du dernier maillon d'alors, ou `ATTESTATION_ORIGINE` quand le journal était VIERGE.
/// MESURÉ le 2026-08-31 (trois maillons, un point de contrôle après chacun) : les trois attestations
/// occupent les positions 0, 1 et 2 de la chaîne. Ce n'est donc PAS la tête ACTUELLE.
///
/// D'OÙ LA MESURE QUI A CONDAMNÉ LA COMPARAISON NAÏVE, et elle est la raison d'être de cette fonction :
/// comparer `checkpoint.ledger_hash` à la tête COURANTE accuse **2 points de contrôle légitimes sur 3**
/// sur un journal parfaitement sain (mesuré le 2026-08-31 sur le vrai chemin d'écriture). Une fausse
/// accusation portée par un instrument d'intégrité est pire que l'angle mort qu'elle comble. La
/// vérification est donc un RATTACHEMENT à la chaîne, jamais une égalité.
///
/// LES DEUX SEULES LOIS QUE LE SCHÉMA PERMET DE TENIR SANS FAUSSE ACCUSATION :
///  1. RATTACHEMENT — l'attestation est `ATTESTATION_ORIGINE`, ou le `hash` d'un maillon de ce journal.
///     Rien d'autre n'a jamais été une tête de cette chaîne. Ferme le cas MESURÉ d'une valeur FABRIQUÉE
///     et correctement signée (`Ok((3, 1, 0, None))` avant ce lot), et le cas d'une attestation VIDE.
///  2. ORIGINE DATÉE — `ATTESTATION_ORIGINE` ne concorde que si la chaîne était encore VIDE à cet
///     instant. Le seul témoin de cet instant que le schéma porte est `checkpoint.ts` : un maillon
///     STRICTEMENT antérieur au point de contrôle prouve que la chaîne n'était pas vide. C'est CETTE
///     loi qui rattrape RÉTROACTIVEMENT ce qu'une base ayant connu `P10.7-t` porte DÉJÀ — un point de
///     contrôle attestant l'origine, écrit pendant une panne de lecture, resté en base après sa
///     résorption, et compté VALIDE jusqu'ici.
///
/// L'INÉGALITÉ EST STRICTE, ET C'EST CE QUI TIENT LA SECONDE LOI : `now()` est en SECONDES. Un point de
/// contrôle d'origine et le tout premier maillon peuvent parfaitement tomber dans la MÊME seconde
/// (base neuve : le tick d'ancrage et la première mutation de config). `<=` accuserait ce journal-là.
/// Et `sign_checkpoint_result` prélève désormais son horodatage AVANT d'observer la chaîne vide, si
/// bien qu'un maillon écrit ensuite ne peut pas porter un `ts` strictement plus petit.
///
/// UNE TROISIÈME LOI A ÉTÉ ÉCRITE PUIS RETIRÉE, ET C'EST UNE MESURE QUI L'A TRANCHÉE : « les positions
/// attestées ne décroissent jamais avec l'ordre d'écriture ». Elle est vraie tant qu'UN SEUL signataire
/// écrit — mais les deux voies de production (`rollups::retention_run` horaire et `server` au boot)
/// signent depuis des connexions distinctes. Deux signataires qui se chevauchent peuvent LIRE dans un
/// ordre et INSÉRER dans l'autre : la loi accuserait alors deux points de contrôle parfaitement
/// légitimes. Une loi qui dépend d'un entrelacement n'est pas une loi ; elle est REFUSÉE, et ce qu'elle
/// aurait attrapé (un ancrage RÉGRESSÉ sur une tête plus ancienne, la chaîne restant intacte) est écrit
/// dans le rapport plutôt que gardé par un instrument qui crierait à tort.
///
/// CE QU'ELLE NE PROUVE PAS, écrit pour être opposable : le rattachement dit que l'attestation A ÉTÉ une
/// tête de cette chaîne, pas qu'elle était LA tête à cette seconde-là. La distinction stricte n'est PAS
/// décidable — `ts` est en secondes, plusieurs maillons tiennent dans une seconde, et rien dans le
/// schéma ne relie un point de contrôle à un `ledger.id`. La tenir demanderait une colonne, donc une
/// MIGRATION : porte à sens unique, non franchie.
///
/// `maillons` : `(ts, hash)` dans l'ORDRE DE LA CHAÎNE. `points` : `(ts, ledger_hash)` dans l'ordre
/// d'écriture. Rend `Some(raison)` à la PREMIÈRE discordance, `None` si tout se rattache.
pub(crate) fn attestation_discordante(maillons: &[(i64, String)], points: &[(i64, String)]) -> Option<String> {
    use std::collections::HashSet;
    let connus: HashSet<&str> = maillons.iter().map(|(_, h)| h.as_str()).collect();
    // Le maillon le plus ANCIEN par l'horodatage, pas le premier de la chaîne : les deux coïncident sur
    // un journal sain, et prendre le minimum ne peut que RÉDUIRE l'accusation si l'horloge a reculé.
    let plus_ancien = maillons.iter().map(|(ts, _)| *ts).min();
    for (rang, (ts, atteste)) in points.iter().enumerate() {
        if atteste == ATTESTATION_ORIGINE {
            if let Some(t0) = plus_ancien {
                if t0 < *ts {
                    return Some(format!(
                        "point de contrôle #{} atteste l'ORIGINE d'une chaîne VIDE alors que ce journal portait \
                         déjà un maillon {} seconde(s) plus tôt — l'attestation ne concorde avec AUCUN état de \
                         cette chaîne : AUCUN verdict n'est rendu sur une attestation qu'on ne peut pas rattacher",
                        rang + 1,
                        ts - t0
                    ));
                }
            }
            continue;
        }
        if !connus.contains(atteste.as_str()) {
            return Some(format!(
                "point de contrôle #{} atteste une tête ({}) qui n'est le `hash` d'AUCUNE entrée de ce journal — \
                 l'attestation ne concorde pas avec la chaîne qu'elle ancre : AUCUN verdict n'est rendu sur une \
                 attestation qu'on ne peut pas rattacher",
                rang + 1,
                apercu_d_attestation(atteste)
            ));
        }
    }
    None
}

/// Signe la tête de chaîne du ledger -> checkpoint vérifiable avec la clé publique.
///
/// `P10.7-t` — ON NE SIGNE PAS CE QU'ON N'A PAS PU LIRE. Jusqu'au 2026-08-31 la lecture de la tête portait
/// un `unwrap_or_else(|_| "genesis")` qui confondait DEUX choses que `ledger_prev_hash` sépare depuis
/// `P10.7-m` : un journal VIERGE (aucune ligne — l'origine légitime, dont `genesis` EST la valeur juste) et
/// une lecture IMPOSSIBLE. Dans le second cas il écrivait un point de contrôle SIGNÉ attestant l'ORIGINE
/// d'une chaîne vide, sur un journal qui portait des maillons.
///
/// CE QUE ÇA COÛTAIT, MESURÉ (2026-08-31, trois maillons du vrai chemin, `hash` de la tête remplacé par un
/// blob puis REMIS) : le point de contrôle mensonger reste en base après la résorption de la panne, et
/// `verify_ledger_conn` rend alors `Ok((3, 1, 0, None))` — trois maillons intègres, **une signature comptée
/// OK**, aucune rupture. `plume-daemon verify` imprime « ledger OK … OK=1 KO=0 » et sort en 0. La signature
/// donne à l'attestation exactement l'autorité qu'elle ne mérite pas, et rien ne la reprend jamais : aucun
/// vérificateur ne compare `checkpoint.ledger_hash` à la tête réelle (il ne vérifie que la SIGNATURE de
/// cette valeur). Un mensonge signé, permanent, indistinguable d'un point de contrôle légitime.
///
/// LA DÉCISION, ET SA RAISON : entre une fenêtre NON ANCRÉE — visible, et par ailleurs toujours vérifiable
/// par recalcul de la chaîne, qui ne dépend d'aucun checkpoint — et un point de contrôle qui MENT avec
/// autorité, on choisit la première. Refuser ne retire aucune preuve : il retire une FAUSSE preuve.
///
/// CE QUE FONT LES APPELANTS QUAND ELLE REFUSE — MESURÉ AVANT D'ÉCRIRE LE REMÈDE, parce qu'un refus qui
/// disparaît ne vaut pas mieux qu'un mensonge. Les DEUX voies de production (`rollups::retention_run`,
/// horaire, et `server` au boot) appellent depuis un BRAS DE `match` TYPÉ `()` : elles ne bouclent pas,
/// n'alertent pas, et n'ont aucune valeur à examiner. Un `Result` rendu ici serait tombé dans le vide.
///
/// D'OÙ LA FORME : le cœur qui REFUSE (`sign_checkpoint_result`) est séparé du geste de production
/// (`sign_checkpoint`), qui AVOUE. La signature `()` est CONSERVÉE — et ce n'est pas qu'une commodité :
/// elle rend l'aveu INDÉTOURNABLE. Avec un `Result`, un appelant futur écrit `let _ =` et la confession
/// disparaît ; ici il n'a rien à jeter, et tout nouveau site hérite de l'aveu sans le savoir.
///
/// LE CHEMIN NOMINAL EST BYTE-IDENTIQUE : journal vierge -> `Ok("")` -> `genesis` (la valeur historique,
/// délibérément conservée : la changer ferait diverger les points de contrôle d'origine anciens et neufs
/// sans rien gagner) ; tête lue -> son `hash`. Aucun schéma ne bouge, aucun point de contrôle existant
/// n'est réécrit ni invalidé.
pub(crate) fn sign_checkpoint_result(conn: &Connection, key: &ed25519_dalek::SigningKey) -> Result<(), String> {
    use ed25519_dalek::Signer;
    // `P10.7-u` — L'HORODATAGE EST PRÉLEVÉ AVANT LA LECTURE DE LA TÊTE, ET CE N'EST PAS UN DÉTAIL DE
    // STYLE : c'est ce qui rend VÉRIFIABLE, sans fausse accusation, l'attestation d'ORIGINE. Un point de
    // contrôle qui atteste `genesis` ne concorde que si la chaîne était VIDE à cet instant ; le seul
    // témoin de cet instant que le schéma porte est `checkpoint.ts`. En le prélevant AVANT d'observer la
    // chaîne vide, on garantit que TOUT maillon écrit ensuite portera un `ts` >= celui-ci — donc que le
    // contrôle de concordance (`attestation_discordante`, comparaison STRICTE) ne peut pas accuser un
    // point de contrôle d'origine légitime, même si l'écriture attend une seconde sur un verrou.
    // Il ne change ni le schéma, ni la préimage signée (la signature porte la TÊTE, jamais l'horodatage).
    let ts = now();
    // `ledger_prev_hash` DISCRIMINE SUR L'ERREUR (cf. sa note) : `Ok("")` = journal vierge = origine
    // légitime ; `Err` = on ne sait pas à quoi la signature s'appliquerait -> on ne signe pas.
    let head = match ledger_prev_hash(conn) {
        Ok(h) if h.is_empty() => ATTESTATION_ORIGINE.to_string(), // journal vierge : l'origine, valeur historique
        Ok(h) => h,
        Err(e) => return Err(format!("tête de chaîne ILLISIBLE ({e})")),
    };
    let sig = key.sign(head.as_bytes());
    conn.execute(
        "INSERT INTO checkpoint(ts,ledger_hash,sig,pubkey) VALUES(?1,?2,?3,?4)",
        params![ts, head, hex_encode(&sig.to_bytes()), hex_encode(key.verifying_key().as_bytes())],
    )
    // L'INSERT était `let _ =` : un point de contrôle qui ne s'écrit PAS se lisait comme un point de
    // contrôle écrit. Le même mot manquant, sur l'autre moitié du geste.
    .map(|_| ())
    .map_err(|e| format!("écriture du point de contrôle refusée ({e})"))
}

/// LE GESTE DE PRODUCTION : signe, ou AVOUE. Enveloppe `sign_checkpoint_result` (cf. sa note pour la
/// décision et sa mesure). Deux canaux, pour deux lecteurs : stderr (l'exploitant qui suit le journal du
/// processus) et un event SOC non-purgeable, sévérité 4, dédupé à l'heure (la console, où l'on ALERTE).
/// Aucun des deux ne porte de `detail` de maillon : le message d'erreur rusqlite nomme une colonne et un
/// type, jamais une donnée. Chemin nominal : RIEN n'est émis — un instrument qui parle toujours ne dit rien.
pub(crate) fn sign_checkpoint(conn: &Connection, key: &ed25519_dalek::SigningKey) {
    if let Err(raison) = sign_checkpoint_result(conn, key) {
        eprintln!("[ledger] WARN point de contrôle NON écrit : {raison} — on ne signe pas ce qu'on n'a pas pu lire");
        let _ = emit_ledger_checkpoint_refused(conn, now(), &raison);
    }
}
/// `plume-daemon verify` : recalcule la chaîne + vérifie les signatures des checkpoints.
/// INVARIANT : ouvre la base par le chemin KEYÉ (READ-ONLY + `PRAGMA key` via apply_key, comme
/// `open_db`/`ledger-export`) — SANS quoi une base SQLCipher est illisible et un `.unwrap()`
/// PANIQUERAIT (l'outil de détection de falsification ne tournerait jamais sur une base chiffrée). Toute erreur (clé absente/
/// incorrecte, base absente, ledger illisible) remonte proprement en `exit(2)` — jamais de panic.
///
/// `P10.7-q` — TROIS CODES DE SORTIE, ET LE TROISIÈME EXISTAIT DÉJÀ : `0` = chaîne LUE ENTIÈREMENT et
/// intègre · `1` = rupture NOMMÉE (ou, PIN escrow posé, un checkpoint non signé par la clé épinglée) ·
/// `2` = REFUS DE CONCLURE. Ce lot n'INVENTE aucun code : il ÉLARGIT ce qui atteint le `2` — une ligne
/// que la lecture ne sait pas rendre y arrive maintenant, au lieu de quitter le scan en silence et de
/// produire un `0`. `P10.7-u` ÉLARGIT LE MÊME `2`, ET POUR LA MÊME RAISON : un point de contrôle dont
/// l'attestation ne se RATTACHE à aucun état de la chaîne y arrive aussi. Le `1` lui est refusé — son
/// unique vocabulaire nomme un `id` de MAILLON, et y router un point de contrôle ferait accuser une
/// entrée de journal intacte ; le compteur `sig_ko` lui est refusé aussi — sans clé épinglée il
/// n'entraîne aucun durcissement, donc « ledger OK » et une sortie 0 : c'est-à-dire RENDRE VÉRIFIÉ sur
/// une concordance qu'on n'a pas pu établir, le défaut d'origine exactement. C'EST LE SEUL ACHEMINEMENT JUSTE : confondre ce cas avec le `1` ferait croire à une
/// COMPROMISSION là où il n'y a qu'une lecture impossible ; le confondre avec le `0` EST le défaut
/// d'origine. Le voisin `verify-control` a choisi le même `2` le même jour, indépendamment.
///
/// ET LE REFUS PARLE DÉSORMAIS SUR LA MÊME SORTIE QUE LES DEUX AUTRES VERDICTS (stdout) : il partait sur
/// stderr, donc un `plume-daemon verify > journal.txt` rendait un fichier VIDE — un refus de conclure
/// qu'on ne peut pas lire ne vaut pas mieux qu'un verdict faux. Rien dans l'arbre (unité systemd,
/// manifeste k3s, sonde, script de bootstrap, tâche CI, documentation) ne lit ce flux ni ce code : la
/// SEULE ligne d'aide qui énonce des codes est celle de `verify-control`, et elle est inchangée.
pub(crate) fn verify_run() {
    let conf = load_config();
    let db_path = cfg(&conf, "PLUME_DB", "/var/lib/plume/db/plume.db");
    match verify_ledger(&db_path) {
        Ok((n, sig_ok, sig_bad, broken)) => match broken {
            Some(id) => {
                println!("INTÉGRITÉ COMPROMISE : rupture de chaîne à l'entrée #{id} ({n} entrées)");
                std::process::exit(1);
            }
            // v134 (#11) — avec un PIN escrow (PLUME_LEDGER_PUBKEY) configuré, un checkpoint KO signifie un
            // pubkey in-band NON de confiance (re-signature) ou une signature invalide -> ÉCHEC DUR (exit 1).
            // SANS pin, KO>0 reste un simple signalement (dégradation de signature, ex. Vault re-scellé).
            None if ledger_pinned_pubkey().is_some() && sig_bad > 0 => {
                println!("INTÉGRITÉ COMPROMISE (PIN) : {sig_bad} checkpoint(s) NON signé(s) par la clé escrow épinglée (OK={sig_ok}, {n} entrées) — re-signature possible");
                std::process::exit(1);
            }
            None => println!("ledger OK : {n} entrées chaînées intègres ; checkpoints signés OK={sig_ok} KO={sig_bad}"),
        },
        Err(e) => {
            // AUCUN VERDICT — clé manquante/incorrecte, base illisible, maillon ou checkpoint qu'on ne sait
            // pas lire, et depuis `P10.7-u` une attestation qu'on ne sait pas RATTACHER à la chaîne.
            // Jamais un panic, et jamais confondu avec « intègre » (0) ni avec « rompu » (1).
            // LA QUEUE FIXE « … sur une chaîne partiellement lue » A ÉTÉ GÉNÉRALISÉE, ET C'EST UN CORRECTIF
            // DE PHRASE FAUSSE : elle décrivait UNE des causes du refus comme si c'était la seule, et elle
            // était déjà fausse pour l'ouverture impossible (rien n'a été lu du tout) autant que pour une
            // attestation qu'on ne sait pas rattacher (tout a été lu). Elle n'est pas SUPPRIMÉE — un
            // exploitant a besoin de la phrase qui dit « ceci n'est pas un verdict » — mais ramenée à ce
            // qui est VRAI des quatre causes. Aucun manifeste, unité, sonde ni script ne lit ce flux
            // (revérifié le 2026-08-31 : la seule ligne d'aide qui énonce des codes est celle de
            // `verify-control`, et elle est inchangée).
            println!("VERDICT IMPOSSIBLE : {e} — aucun verdict n'est rendu sur ce que la vérification n'a pas pu établir");
            std::process::exit(2);
        }
    }
}
/// Ouvre la base en READ-ONLY + applique la clé SQLCipher (apply_key = PRAGMA key si PLUME_DB_KEY, sinon
/// no-op sur base en clair) puis délègue à `verify_ledger_conn`. FAIL-CLOSED : ouverture/lecture impossible
/// (clé absente/incorrecte -> `SELECT ... FROM ledger` échoue) -> `Err` (jamais un panic).
pub(crate) fn verify_ledger(db_path: &str) -> Result<(usize, i64, i64, Option<i64>), String> {
    let conn = Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| format!("ouverture {db_path}: {e}"))?;
    apply_key(&conn); // clé SQLCipher (PLUME_DB_KEY) — mirroir de open_db/ledger-export ; DOIT précéder toute requête
    let _ = sqlite_plafond::armer(&conn);
    // v134 (#11) — applique le PIN escrow (PLUME_LEDGER_PUBKEY) s'il est configuré (sinon None -> comportement
    // historique : on fait confiance au pubkey IN-BAND de chaque checkpoint).
    let pinned = ledger_pinned_pubkey();
    verify_ledger_conn(&conn, pinned.as_ref())
}
/// v134 (#11) — PUBKEY ESCROW ÉPINGLÉ (OPTIONNEL) : `PLUME_LEDGER_PUBKEY` (hex 64 chars, ou base64 standard)
/// = la clé PUBLIQUE ed25519 de confiance (escrow hors-bande). POSÉ -> la vérification REFUSE tout checkpoint
/// dont le pubkey IN-BAND diffère (un attaquant DB-write-SANS-ledger.key aurait re-signé avec SA clé, pubkey
/// in-band inclus -> auto-cohérent mais NON de confiance). NON POSÉ -> None -> comportement historique préservé.
pub(crate) fn ledger_pinned_pubkey() -> Option<[u8; 32]> {
    let raw = std::env::var("PLUME_LEDGER_PUBKEY").ok()?;
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    parse_ed25519_pubkey(raw)
}
/// Parse une clé publique ed25519 (32 o) depuis hex (64 chars — format des checkpoints en base, prioritaire)
/// ou base64 standard. `None` si non décodable / mauvaise longueur.
pub(crate) fn parse_ed25519_pubkey(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if let Some(b) = hex_decode(s) {
        if let Ok(a) = <[u8; 32]>::try_from(b) {
            return Some(a);
        }
    }
    use base64::Engine;
    if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(s) {
        if let Ok(a) = <[u8; 32]>::try_from(b) {
            return Some(a);
        }
    }
    None
}
/// Cœur testable (aucune ouverture de fichier ni env) : recalcule la chaîne de hash + vérifie les signatures
/// Ed25519 des checkpoints sur une connexion DÉJÀ ouverte+keyée. Renvoie (nb_entrées, sig_ok, sig_ko,
/// première_rupture). Aucun `unwrap` : une base illisible (clé incorrecte) -> `Err` propre.
/// v134 (#11) — PIN escrow OPTIONNEL : `pinned=Some(pk)` -> un checkpoint dont le pubkey in-band != `pk` FAIL
/// (compté en sig_ko) AVANT toute vérif de signature (on ne fait jamais confiance à un pubkey non-épinglé).
/// `pinned=None` -> comportement historique (confiance au pubkey in-band). Le RESTE est inchangé.
///
/// `P10.7-q` — TROIS ISSUES, ET LA TROISIÈME EST CE QUI DISTINGUE CE VERDICT D'UNE OPINION : `Ok(_, None)`
/// = chaîne LUE ENTIÈREMENT et intègre · `Ok(_, Some(id))` = rupture NOMMÉE · `Err` = AUCUN verdict. Toute
/// ligne que la lecture ne sait pas rendre ARRÊTE le scan.
///
/// CE QU'IL FAISAIT AVANT LE 2026-08-31, MESURÉ SUR CET ARBRE, ET C'EST LE DÉFAUT QUE CE VÉRIFICATEUR
/// AURAIT DÛ POURSUIVRE — logé DEUX FOIS dans ses propres lignes :
///  - `flatten()` sur le scan des MAILLONS : trois maillons en base, le `hash` du dernier remplacé par un
///    blob (`X'FF'` : SQLite range un BLOB tel quel dans une colonne d'affinité TEXT) -> la ligne quittait
///    le scan EN SILENCE et la réponse était `Ok((2, 0, 0, None))`, soit « deux entrées, aucune rupture »
///    rendu sur une chaîne AMPUTÉE dont les trois lignes étaient toujours là. Un verdict d'INTÉGRITÉ trop
///    OPTIMISTE, la pire direction pour un aveu ;
///  - `flatten()` sur le scan des CHECKPOINTS, et celui-là DÉSARMAIT LE PIN ESCROW : un checkpoint dont
///    le `pubkey` est un blob disparaissait des DEUX compteurs (mesuré : un checkpoint en base ->
///    `Ok((1, 0, 0, None))`, donc `sig_ok=0` ET `sig_ko=0`). Or `verify_run` ne durcit (exit 1) que sur
///    `sig_ko > 0` : ABÎMER un checkpoint au lieu de le RE-SIGNER faisait donc imprimer « ledger OK …
///    checkpoints signés OK=0 KO=0 » et sortir en 0, PIN posé ou non.
///
/// POURQUOI CE CORRECTIF NE PEUT PAS FAIRE ÉCHOUER UNE VÉRIFICATION LÉGITIME, ET C'EST STRUCTUREL, pas une
/// opinion : dans `ledger`, `ts`/`kind`/`prev_hash`/`hash` sont `NOT NULL` et `detail` est le SEUL nullable
/// — il est déjà lu en `Option`. Aucune valeur qu'un writer du produit puisse poser ne fait échouer cette
/// conversion ; seule une écriture SQL DIRECTE, une restauration partielle ou une corruption le peut. Dans
/// `checkpoint`, les trois colonnes de contenu sont nullables : elles sont donc lues en `Option` et un NULL
/// vaut chaîne VIDE — un checkpoint qu'on LIT et qui ne porte pas de signature valide est compté `sig_ko`,
/// pas un checkpoint qu'on ne sait pas lire. `Err` est réservé à ce que la lecture ne rend PAS.
///
/// LE MODÈLE EST `control_ledger_verify_conn` (`rbac.rs`), écrit le même jour EN CHERCHANT CE QU'IL NE
/// FALLAIT PAS TRANSPOSER D'ICI. Le voisin est arrivé juste : c'est celui-ci qui rattrape son retard.
///
/// `P10.7-u` — ET IL RESTAIT UNE MOITIÉ, MESURÉE LE 2026-08-31 : cette fonction contrôlait la SIGNATURE
/// d'un point de contrôle, jamais la CONCORDANCE entre ce qu'il ATTESTE et la chaîne qu'il ancre. Un
/// point de contrôle attestant `genesis` — ou une valeur entièrement FABRIQUÉE — sur un journal de trois
/// maillons, CORRECTEMENT SIGNÉ, rendait `Ok((3, 1, 0, None))` : une signature COMPTÉE VALIDE, donc
/// « ledger OK … OK=1 KO=0 » et une sortie 0. La signature prêtait son autorité à une valeur arbitraire.
/// La loi est dans `attestation_discordante` (cœur PUR), sa mesure et ses deux frontières avec elle ;
/// ici on ne décide que de son ACHEMINEMENT — la troisième sortie, et seulement quand la chaîne est
/// intègre, pour qu'une rupture NOMMÉE ne puisse jamais devenir un refus de conclure.
pub(crate) fn verify_ledger_conn(conn: &Connection, pinned: Option<&[u8; 32]>) -> Result<(usize, i64, i64, Option<i64>), String> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let mut stmt = conn.prepare("SELECT id,ts,kind,detail,prev_hash,hash FROM ledger ORDER BY id")
        .map_err(|e| format!("lecture ledger (clé SQLCipher manquante/incorrecte ?): {e}"))?;
    let maillons = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get::<_, Option<String>>(3)?.unwrap_or_default(), r.get(4)?, r.get(5)?)))
        .map_err(|e| format!("scan ledger: {e}"))?;
    // `P10.7-q` — UN MAILLON QU'ON NE SAIT PAS LIRE ARRÊTE TOUT. Le laisser tomber du scan (`flatten`)
    // rendait un verdict d'intégrité sur une chaîne AMPUTÉE — le pire endroit où loger cette tolérance.
    // Le rang est celui du SCAN, pas l'`id` : l'`id` de la ligne fautive est justement ce qu'on n'a pas su lire.
    let mut rows: Vec<(i64, i64, String, String, String, String)> = Vec::new();
    for (rang, maillon) in maillons.enumerate() {
        let maillon = maillon.map_err(|e| {
            format!("maillon #{} ILLISIBLE ({e}) — la chaîne n'a pas pu être lue entièrement : AUCUN verdict", rang + 1)
        })?;
        rows.push(maillon);
    }
    let mut prev = String::new();
    let mut broken: Option<i64> = None;
    for (id, ts, kind, detail, prev_hash, hash) in &rows {
        let h = sha256_hex(format!("{prev}|{ts}|{kind}|{detail}").as_bytes());
        if prev_hash != &prev || &h != hash {
            broken = Some(*id);
            break;
        }
        prev = hash.clone();
    }
    // `P10.7-u` — `ts` REJOINT LA LECTURE, et c'est la seule colonne ajoutée : sans elle, l'attestation
    // d'ORIGINE n'est comparable à RIEN (cf. `attestation_discordante`, loi 2). Elle est `INTEGER NOT
    // NULL` au schéma et les deux seuls écrivains y passent un entier -> aucune valeur que le produit
    // puisse poser ne fait échouer cette conversion, et une valeur qui la ferait échouer est une ligne
    // ILLISIBLE au sens exact des deux ancrages voisins.
    let mut cs = conn.prepare("SELECT ts,ledger_hash,sig,pubkey FROM checkpoint ORDER BY id")
        .map_err(|e| format!("lecture checkpoints: {e}"))?;
    let signatures = cs
        // Les TROIS colonnes de contenu sont nullables au schéma (`checkpoint(ledger_hash TEXT, sig TEXT,
        // pubkey TEXT)`) : un NULL se LIT, et vaut chaîne vide -> `hex_decode` échoue -> `sig_ko`. Seule une
        // valeur que la lecture ne sait pas rendre (blob) reste une ligne ILLISIBLE.
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                r.get::<_, Option<String>>(3)?.unwrap_or_default(),
            ))
        })
        .map_err(|e| format!("scan checkpoints: {e}"))?;
    // `P10.7-q` — MÊME LOI QUE POUR LES MAILLONS, et ici elle vaut aussi comme correctif de SÉCURITÉ : un
    // checkpoint tombé du scan disparaissait des DEUX compteurs, donc de la condition de durcissement du PIN.
    let mut cps: Vec<(i64, String, String, String)> = Vec::new();
    for (rang, signature) in signatures.enumerate() {
        let signature = signature.map_err(|e| {
            format!("checkpoint #{} ILLISIBLE ({e}) — les signatures n'ont pas pu être comptées entièrement : AUCUN verdict", rang + 1)
        })?;
        cps.push(signature);
    }
    // `P10.7-u` — LA CONCORDANCE, ET ELLE EST CONTRÔLÉE ICI PARCE QU'ICI SEULEMENT LES DEUX TABLES SONT
    // LUES ENTIÈREMENT. Vérifier la SIGNATURE d'une attestation sans jamais la RATTACHER à la chaîne,
    // c'est prêter l'autorité d'Ed25519 à une valeur arbitraire : mesuré le 2026-08-31, un point de
    // contrôle attestant `genesis` — ou une valeur FABRIQUÉE — sur un journal de trois maillons, signé
    // correctement, rendait `Ok((3, 1, 0, None))`, donc « ledger OK … OK=1 KO=0 » et une sortie 0.
    //
    // ELLE NE S'EXÉCUTE QUE SI LA CHAÎNE EST INTÈGRE, ET CE N'EST PAS UNE OPTIMISATION : « un correctif
    // qui ferme une fausse accusation peut faire TAIRE une vraie », et le signal d'alerte est exactement
    // un verdict qui passerait d'ACCUSE à REFUSE DE CONCLURE. Une rupture NOMMÉE (`Ok(_, Some(id))`) est
    // le verdict le plus fort que cet instrument sache rendre : elle sort D'ABORD, toujours, et aucun
    // contrôle de concordance ne peut la convertir en refus.
    //
    // ET LE REFUS EST LA TROISIÈME SORTIE, PAS UN COMPTEUR : une attestation discordante ne peut pas
    // aller dans `sig_ko` — sans clé épinglée, `verify_run` ne durcit pas dessus et imprimerait
    // « ledger OK » avec une sortie 0, c'est-à-dire rendrait VÉRIFIÉ sur une concordance qu'il n'a pas
    // pu établir. Elle ne peut pas non plus aller dans `broken`, dont tout le vocabulaire nomme un `id`
    // de MAILLON : y router un point de contrôle ferait accuser une entrée de journal intacte.
    if broken.is_none() {
        let ancrages: Vec<(i64, String)> = rows.iter().map(|(_, ts, _, _, _, h)| (*ts, h.clone())).collect();
        let attestations: Vec<(i64, String)> = cps.iter().map(|(ts, lh, _, _)| (*ts, lh.clone())).collect();
        if let Some(raison) = attestation_discordante(&ancrages, &attestations) {
            return Err(raison);
        }
    }
    let (mut sig_ok, mut sig_bad) = (0i64, 0i64);
    for (_ts, lh, sig, pk) in &cps {
        let ok = (|| {
            let pkb: [u8; 32] = hex_decode(pk)?.try_into().ok()?;
            // v134 (#11) — PIN escrow : si un pubkey est épinglé et que le pubkey IN-BAND diffère, ce
            // checkpoint FAIL AVANT toute vérif de signature (re-signature attaquant : la signature serait
            // valide vis-à-vis de SA clé, mais cette clé n'est pas la clé de confiance escrow).
            if let Some(p) = pinned {
                if &pkb != p {
                    return Some(false);
                }
            }
            let sgb: [u8; 64] = hex_decode(sig)?.try_into().ok()?;
            let vk = VerifyingKey::from_bytes(&pkb).ok()?;
            Some(vk.verify(lh.as_bytes(), &Signature::from_bytes(&sgb)).is_ok())
        })().unwrap_or(false);
        if ok { sig_ok += 1; } else { sig_bad += 1; }
    }
    Ok((rows.len(), sig_ok, sig_bad, broken))
}

/// DENYLIST d'IP PROTÉGÉES qu'un ban ne doit JAMAIS toucher : loopback
/// (127.0.0.0/8, ::1), link-local (169.254/16, fe80::/10), RFC1918 (10/8, 172.16-31/12, 192.168/16),
/// ULA IPv6 (fc00::/7), PLUS les préfixes opérateur/self configurés (PLUME_OPERATOR_IPS + PLUME_PROTECTED_IPS,
/// ex. passerelle/DNS). Empêche qu'un event forgé (src_ip=IP tierce/interne) — même s'il franchit la validation
/// de format — déclenche le ban d'une IP loopback/privée/opérateur (self-DoS ou coupure de l'infra). Sûr : les
/// IP à bannir sont des attaquants EXTERNES (publiques) ; les collecteurs/réponses légitimes ne visent pas ces
/// plages. Configurable via PLUME_OPERATOR_IPS / PLUME_PROTECTED_IPS (CSV, notation exacte ou CIDR/`*`).
/// LA DENYLIST CONFIGURÉE, ANALYSÉE PAR VALEUR (`P4.7-i`, `P4.7-j`) — RÉSEAUX ET REFUS.
///
/// CE QUE CETTE STRUCTURE REMPLACE, ET POURQUOI CE N'ÉTAIT PAS UN OUBLI. Jusqu'au 2026-08-28 cette
/// liste était un `Vec<(String, bool)>` produit par `parse_excl_item` — c'est-à-dire par l'analyseur
/// du RENDU D'AFFICHAGE, qui traduit un CIDR en PRÉFIXE TEXTUEL tronqué à la frontière d'octet (v4)
/// ou d'hextet (v6). Pour son consommateur d'origine — écrire `src_ip NOT LIKE 'préfixe%'` — un
/// préfixe textuel est la BONNE réponse, la seule qui se rende en SQL. Pour l'ENFORCEMENT c'est la
/// mauvaise, et l'écart va DANS LES DEUX SENS (mesuré) :
///   `172.16.0.0/12`   -> `"172."`       protégeait tout 172/8 (x16)  — SUR-protection = trou d'enforcement
///   `203.0.113.0/25`  -> `"203.0.113."` protégeait tout le /24 (x2)  — idem
///   `128.0.0.0/1`     -> égalité EXACTE (octets = 0) : UNE seule adresse — SOUS-protection
///   `fc00::/7`        -> `"fc00:"`      : `fd00::/8` échappait       — SOUS-protection
/// Les deux consommateurs sont donc SÉPARÉS : `parse_excl_item` reste CORPS INCHANGÉ et garde
/// l'affichage (`ExclClauses::build`, témoin `excl_v54_parse_and_clause_generation`) ; l'enforcement
/// prend des RÉSEAUX typés. LE TYPE EST LA GARDE : `low.starts_with(...)` devient INÉCRIVABLE pour
/// tout consommateur présent ET futur de cette liste, sans qu'aucun site soit nommé.
pub(crate) struct DenylistProtegee {
    /// Réseaux protégés, comparés par MASQUE (`ip_in_cidr`, qui normalise la forme mappée des deux côtés).
    pub(crate) reseaux: Vec<(std::net::IpAddr, u32)>,
    /// Items REFUSÉS à l'amorçage : `(item tel qu'écrit, raison)`. Un item inanalysable ne devient JAMAIS
    /// un matcher inerte — il est REFUSÉ ET NOMMÉ, et le registre never-ban le rend à l'exploitant.
    pub(crate) refuses: Vec<(String, String)>,
}

/// UN ITEM DE `PLUME_OPERATOR_IPS` / `PLUME_PROTECTED_IPS`, ANALYSÉ EN RÉSEAU (`P4.7-i`).
///
/// `None` = item VIDE (une virgule en trop, une liste vide) : rien n'est écrit, rien n'est refusé —
/// comportement INCHANGÉ. `Some(Err(raison))` = l'exploitant a écrit quelque chose que le produit ne
/// sait PAS honorer : on le REFUSE en le NOMMANT plutôt que de l'accepter DÉFORMÉ.
///
/// LES TROIS REFUS SONT UN DÉPLACEMENT, PAS UNE INVENTION : le refus du joker hors frontière et le
/// plancher de masque (/8 v4, /16 v6) sont DÉJÀ écrits dans `validate_engagement_scope`
/// (`handlers/engagement.rs`), avec leur mesure — « `8*` exempterait 8.x MAIS AUSSI 80-89.x + 8xxx::,
/// ~1,1 milliard d'IP ». Ils protégeaient le scope d'engagement et pas la denylist qui l'alimente.
/// SEULE PIÈCE NEUVE DU LOT : la traduction du joker EN CIDR sur la frontière. Elle n'a pas
/// d'antécédent dans l'arbre, donc pas de témoin existant pour la rattraper — c'est écrit ici.
pub(crate) fn parse_protected_item(raw: &str) -> Option<Result<(std::net::IpAddr, u32), String>> {
    let it = raw.trim().to_ascii_lowercase();
    if it.is_empty() { return None; }
    // `P4.7-i` (REPRISE 2026-08-29) — LES DEUX CONSOMMATEURS DU MÊME CSV DOIVENT ACCEPTER LES MÊMES
    // ITEMS. Mesuré : `parse_excl_item` (affichage) ROGNE autour du `/` (`base.trim()`,
    // `masklen.trim()`), `parse_ssrf_allow` (enforcement) NON. `PLUME_OPERATOR_IPS="172.16.0.0 /12"`
    // était donc HONORÉ côté panneau — l'exploitant VOYAIT son exclusion fonctionner — et REFUSÉ
    // côté denylist : plus AUCUNE protection never-ban sur ce réseau, alors que le refus se lisait
    // comme une faute de frappe isolée. On rogne ICI, exactement où l'affichage rogne ; aucun corps
    // d'analyseur n'est touché (empreintes T5 intactes).
    let it = match it.split_once('/') {
        Some((base, masque)) => format!("{}/{}", base.trim(), masque.trim()),
        None => it,
    };
    Some(protected_item_reseau(&it))
}

/// Plancher de masque par famille : au-dessous, l'item protégerait une part d'Internet que personne
/// n'a voulu protéger (`128.0.0.0/1` = la moitié de l'espace v4). MÊMES valeurs que le scope d'engagement.
fn plancher_de_masque(ip: std::net::IpAddr) -> u32 { if ip.is_ipv6() { 16 } else { 8 } }

fn protected_item_reseau(it: &str) -> Result<(std::net::IpAddr, u32), String> {
    // (a) JOKER `*` — ACCEPTÉ UNIQUEMENT SUR UNE FRONTIÈRE d'octet (v4) ou d'hextet (v6), traduit en
    //     CIDR. Hors frontière (`8*`, `203.0.113.7*`) il n'a AUCUNE traduction honnête : refusé.
    if let Some(p) = it.strip_suffix('*') {
        let p = p.trim();
        if p.is_empty() {
            return Err("joker seul « * » : protégerait tout l'espace d'adressage".into());
        }
        if p.contains(':') {
            if !p.ends_with(':') {
                return Err(format!("« {it} » : joker hors frontière d'hextet (attendu « 2001:db8:* »)"));
            }
            // UN SEUL séparateur de frontière est retiré, JAMAIS tous : `trim_end_matches` rendait
            // `2001:db8:::*` indiscernable de `2001:db8:*` — le contrôle de vacuité des composants
            // tournait alors sur un corps DÉJÀ rogné et ne pouvait plus voir le séparateur en trop.
            // Une faute de frappe devenait une protection SILENCIEUSE au lieu d'un refus NOMMÉ.
            let corps = &p[..p.len() - 1];
            let hextets: Vec<&str> = corps.split(':').collect();
            if hextets.iter().any(|h| h.is_empty()) || hextets.is_empty() || hextets.len() > 7 {
                return Err(format!("« {it} » : joker hors frontière d'hextet (1 à 7 hextets pleins attendus)"));
            }
            let bits = 16 * hextets.len() as u32;
            let base = format!("{corps}::");
            let ip = base.parse::<std::net::IpAddr>().map_err(|_| format!("« {it} » : base « {base} » non analysable"))?;
            return Ok((ip, bits));
        }
        if !p.ends_with('.') {
            return Err(format!("« {it} » : joker hors frontière d'octet (attendu « 203.0.113.* »)"));
        }
        // Idem v4 : UN SEUL point de frontière retiré -> `10..*` est REFUSÉ (il était accepté et
        // rendu `10.0.0.0/8`), `203.0.113.*` reste accepté.
        let corps = &p[..p.len() - 1];
        let octets: Vec<&str> = corps.split('.').collect();
        if octets.iter().any(|o| o.is_empty()) || octets.is_empty() || octets.len() > 3 {
            return Err(format!("« {it} » : joker hors frontière d'octet (1 à 3 octets pleins attendus)"));
        }
        let bits = 8 * octets.len() as u32;
        let base = format!("{corps}{}", ".0".repeat(4 - octets.len()));
        let ip = base.parse::<std::net::IpAddr>().map_err(|_| format!("« {it} » : base « {base} » non analysable"))?;
        return Ok((ip, bits));
    }
    // (b) CIDR `base/N` ou IP NUE — DÉPLACEMENT PUR : c'est `parse_ssrf_allow`, corps inchangé, qui
    //     rend déjà `Net(IpAddr, bits)` et une IP nue en /32|/128. Ici la variante `Host` est REFUSÉE :
    //     un nom d'hôte ne protège RIEN sur ce chemin (mesuré — le matcher chaîne qu'il produisait ne
    //     pouvait apparier AUCUNE adresse), il se lisait pourtant comme une protection.
    match parse_ssrf_allow(it) {
        None => Err(format!("« {it} » : ni CIDR, ni adresse, ni joker de frontière")),
        Some(SsrfAllow::Host(h)) => Err(format!(
            "« {h} » : un NOM D'HÔTE ne protège aucune adresse ici (la denylist ban compare des réseaux, pas des noms)"
        )),
        Some(SsrfAllow::Net(ip, bits)) => {
            // `P4.7-i` / `P4.7-j` (REPRISE 2026-08-29) — L'ITEM EST RANGÉ SOUS LA FORME OÙ IL SERA
            // APPLIQUÉ, SANS QUOI CE QUI EST PUBLIÉ N'EST PAS CE QUI EST PROTÉGÉ. `ip_in_cidr`
            // REPLIE la forme mappée des DEUX côtés puis applique `bits` TEL QUEL : un item
            // `::ffff:203.0.113.0/120` était donc appliqué comme un /120 sur une valeur v4, c'est-à-dire
            // masque PLEIN -> UNE seule adresse, pendant que le registre et le journal d'amorçage
            // publiaient « ::ffff:203.0.113.0 .. ::ffff:203.0.113.255 » (256 adresses annoncées
            // protégées, 255 bannissables). MESURÉ le 2026-08-29, rustc, copies verbatim.
            // On replie DONC ici, valeur ET masque : `/96+n` sur une base mappée décrit exactement le
            // réseau v4 `/n`, et c'est cette paire-là qui est stockée, comparée ET publiée.
            // DEUX DIRECTIONS, NOMMÉES : `::ffff:203.0.113.0/120` protège désormais ses 256 adresses
            // (il n'en protégeait qu'UNE) -> on protège PLUS ; `::ffff:203.0.113.0/24` — un masque
            // SOUS /96, qui ne décrit aucun réseau v4 — est REFUSÉ alors qu'il protégeait
            // accidentellement le /24 v4 -> on protège MOINS, mais BRUYAMMENT. Et l'asymétrie
            // mesurée disparaît : `::ffff:10.0.0.0/104` est accepté comme `10.0.0.0/8` l'est, là où
            // le plancher tranché sur `is_ipv6()` refusait `::ffff:10.0.0.0/8` pour le même réseau.
            let (ip, bits) = match ip {
                std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                    Some(v4) if bits >= 96 => (std::net::IpAddr::V4(v4), bits - 96),
                    Some(_) => return Err(format!(
                        "« {it} » : masque /{bits} sur une forme mappée « ::ffff: » — sous /96 il ne décrit AUCUN réseau IPv4 \
                         (écrire le réseau v4 lui-même « a.b.c.d/n », ou la forme mappée avec son masque v6 « ::ffff:a.b.c.d/(96+n) »)"
                    )),
                    None => (ip, bits),
                },
                v4 => (v4, bits),
            };
            let plancher = plancher_de_masque(ip);
            if bits < plancher {
                return Err(format!(
                    "« {it} » : masque /{bits} sous le plancher /{plancher} — protégerait une part d'Internet que personne n'a demandée"
                ));
            }
            Ok((ip, bits))
        }
    }
}

/// PREMIÈRE ET DERNIÈRE ADRESSE d'un réseau — l'ÉTENDUE NUMÉRIQUE, celle que l'exploitant doit
/// pouvoir LIRE (registre never-ban). Le seul endroit où il relisait sa liste lui montrait jusqu'ici
/// le motif tel qu'il avait été MAL compris (« 172. », préfixe), pas ce qu'il protège.
pub(crate) fn etendue_du_reseau(net: std::net::IpAddr, bits: u32) -> (std::net::IpAddr, std::net::IpAddr) {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    // CE QUI EST PUBLIÉ EST CE QUI EST APPLIQUÉ — TENU PAR CONSTRUCTION, PAS PAR CONVENTION
    // (REPRISE 2026-08-29). `ip_in_cidr`, le DÉCIDEUR, replie la forme mappée avant de masquer ;
    // cette fonction masquait SANS replier, et publiait donc une plage v6 pour un ensemble
    // réellement v4. `parse_protected_item` range désormais les items déjà repliés, mais cette
    // fonction est aussi appelée sur des paires venues d'ailleurs (message de refus de scope
    // d'engagement) : le repli est fait ICI aussi, si bien qu'AUCUNE entrée ne peut faire diverger
    // l'étendue publiée du verdict d'appartenance, quelle que soit son origine.
    let net = match net {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    };
    match net {
        IpAddr::V4(v4) => {
            let m: u32 = if bits >= 32 { u32::MAX } else if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            let base = u32::from(v4) & m;
            (IpAddr::V4(Ipv4Addr::from(base)), IpAddr::V4(Ipv4Addr::from(base | !m)))
        }
        IpAddr::V6(v6) => {
            let m: u128 = if bits >= 128 { u128::MAX } else if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            let base = u128::from(v6) & m;
            (IpAddr::V6(Ipv6Addr::from(base)), IpAddr::V6(Ipv6Addr::from(base | !m)))
        }
    }
}

static PROTECTED_IP_MATCHERS: std::sync::OnceLock<DenylistProtegee> = std::sync::OnceLock::new();
/// La denylist COMPLÈTE : réseaux retenus ET items refusés (avec leur raison).
pub(crate) fn protected_denylist() -> &'static DenylistProtegee {
    PROTECTED_IP_MATCHERS.get_or_init(|| {
        let conf = load_config();
        let mut d = DenylistProtegee { reseaux: Vec::new(), refuses: Vec::new() };
        // opérateur (défaut = l'opérateur plateforme) + liste additionnelle passerelle/DNS (défaut vide).
        for cle in ["PLUME_OPERATOR_IPS", "PLUME_PROTECTED_IPS"] {
            let defaut = if cle == "PLUME_OPERATOR_IPS" { PLUME_OPERATOR_IPS_DEFAULT } else { "" };
            for item in cfg(&conf, cle, defaut).split(',') {
                match parse_protected_item(item) {
                    None => {}
                    Some(Ok(net)) => d.reseaux.push(net),
                    Some(Err(raison)) => d.refuses.push((item.trim().to_string(), raison)),
                }
            }
        }
        d
    })
}
/// Les RÉSEAUX protégés seuls (le consommateur d'enforcement). Signature volontairement typée :
/// aucune chaîne n'en sort, donc aucune comparaison textuelle n'est écrivable en aval.
pub(crate) fn protected_ip_matchers() -> &'static Vec<(std::net::IpAddr, u32)> { &protected_denylist().reseaux }
/// Rabat une IPv4-mapped IPv6 (`::ffff:a.b.c.d`) sur son IPv4 embarqué -> FERME le contournement d'encodage
/// `[::ffff:169.254.169.254]` (et une résolution AAAA vers une mapped). `None` si la chaîne n'est pas une IP
/// (nom d'hôte : le verdict viendra de la résolution DNS, pas d'ici). Classification robuste par `IpAddr`.
pub(crate) fn ssrf_norm_ip(ip: &str) -> Option<std::net::IpAddr> {
    use std::net::IpAddr;
    match ip.trim().parse::<IpAddr>().ok()? {
        IpAddr::V6(v6) => Some(v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6))),
        v4 => Some(v4),
    }
}
/// Plages qui ne sont JAMAIS une cible d'égress légitime NI une IP à bannir : loopback (127/8, ::1),
/// link-local (169.254/16 = metadata cloud AWS/GCP/Azure ; fe80::/10), unspecified (0.0.0.0, :: -> résout
/// loopback sous Linux), ULA IPv6 (fc00::/7). Classification par `IpAddr` (pas de préfixe string fragile).
pub(crate) fn ip_never_egress(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    if ip.is_loopback() || ip.is_unspecified() { return true; }
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),                    // 169.254/16
        IpAddr::V6(v6) => {
            let s0 = v6.segments()[0];
            (s0 & 0xffc0) == 0xfe80 || (s0 & 0xfe00) == 0xfc00   // fe80::/10 (link-local) | fc00::/7 (ULA)
        }
    }
}
/// RFC1918 privé IPv4 (10/8, 172.16/12, 192.168/16). `Ipv4Addr::is_private` = EXACTEMENT ces 3 plages.
pub(crate) fn ip_is_rfc1918(ip: std::net::IpAddr) -> bool {
    matches!(ip, std::net::IpAddr::V4(v4) if v4.is_private())
}
/// PROTECTION BAN (anti self-DoS) : une IP loopback / link-local / unspecified / RFC1918 / ULA (IPv4-mapped
/// IPv6 incluse) + les préfixes opérateur/self configurés ne sont JAMAIS bannissables. NB : ici RFC1918 reste
/// TOUJOURS protégé (bannir sa passerelle interne = auto-DoS) — la garde SSRF, elle, a sa PROPRE politique où
/// RFC1918 est opt-in (cf. `ssrf_ipaddr_blocked`) : ne PAS confondre les deux usages.
pub(crate) fn ip_is_protected(ip: &str) -> bool {
    ip_is_protected_ctx(ip, protected_ip_matchers())
}

/// CŒUR PUR de `ip_is_protected` (denylist INJECTÉE) -> exerçable SANS `OnceLock` ni variable
/// d'environnement. DÉPLACEMENT du patron maison, déjà écrit deux fois : `ssrf_blocked_policy(ip,
/// block_private)` (« politique EXPLICITE, testable sans env », 20 lignes plus bas) et
/// `real_client_ip_ctx(req, trusted, …)` (« cœur PUR (config injectée) », `auth.rs`). Son absence
/// était la raison MÉCANIQUE pour laquelle la moitié CONFIGURÉE de cette protection — celle que
/// `P4.7-g` attaque — était la seule SANS aucun témoin positif : les deux seules assertions qui
/// existaient étaient NÉGATIVES et faites liste VIDE.
///
/// L'IDENTITÉ D'UNE ADRESSE EST SA VALEUR, JAMAIS SON ÉCRITURE (`P4.7-g`, `P4.7-j`). Les DEUX
/// moitiés tranchent désormais sur la valeur analysée `p` :
///   * la moitié DÉRIVÉE (plages réservées) le faisait DÉJÀ — c'est un TÉMOIN, pas une intention :
///     son comportement est INCHANGÉ, `ssrf_norm_ip` replie la forme mappée depuis toujours ;
///   * la moitié CONFIGURÉE comparait `low.starts_with(chaîne)`. Elle compare maintenant la MÊME
///     valeur `p`, par `ip_in_cidr` — qui vit 50 lignes plus bas, normalise la forme mappée DES DEUX
///     CÔTÉS, et était déjà exercée par un témoin. `p` était calculé, servait aux deux tests de
///     plage, puis était JETÉ à quatre lignes de là.
///
/// CE QUE VAUT UN REFUS D'ANALYSE, TRANCHÉ EXPLICITEMENT (`P4.7-h`) — et ce n'est PAS ici que ça se
/// tranche. Une chaîne dont on ne sait pas lire la valeur n'est pas une adresse, donc PAS UNE CIBLE :
/// le refus est un défaut de FORME, et il est prononcé EN AMONT par `cible_de_ban_acceptee` (Q1),
/// qui exige désormais que la cible s'analyse. Rendre `true` ICI aurait été la faute : `run_playbooks`
/// partage un refus de FORME (compté dans `abandonnes` — une riposte PERDUE) d'un refus de POLITIQUE
/// (non compté, délibéré) ; un « protégée » sur une chaîne inanalysable aurait rendu la perte
/// INVISIBLE et rouvert `P4.7-d`. Le contrat est donc : TOUTE CIBLE DE BAN S'ANALYSE, et un témoin
/// le tient (`une_cible_de_ban_est_toujours_analysable`) plutôt qu'une phrase.
pub(crate) fn ip_is_protected_ctx(ip: &str, protected: &[(std::net::IpAddr, u32)]) -> bool {
    let ip = ip.trim();
    if ip.is_empty() { return false; }
    let low = ip.to_ascii_lowercase();
    let p = match ssrf_norm_ip(&low) {
        Some(p) => p,
        // FORME, pas politique — la borne d'enforcement (Q1) a déjà refusé cette chaîne comme cible.
        None => return false,
    };
    if ip_never_egress(p) || ip_is_rfc1918(p) { return true; }
    // opérateur / self / passerelle-DNS configurés : appartenance au RÉSEAU, jamais préfixe de chaîne.
    protected.iter().any(|(net, bits)| ip_in_cidr(p, *net, *bits))
}

// ---------- garde SSRF applicative (défense en profondeur au-dessus du confinement réseau) ----------
/// Politique de blocage RFC1918 en SSRF : OPT-IN via `PLUME_SSRF_BLOCK_PRIVATE=1` (défaut OFF). RATIONALE
/// (produit) : un SOC ON-PREM cible LÉGITIMEMENT des ressources internes en 10/172.16/192.168 — relais SMTP
/// interne pour les notifiers email, webhook/ntfy/SIEM on-prem, endpoint OIDC d'un IdP interne. Bloquer TOUT
/// le RFC1918 par défaut casserait ces configs out-of-the-box. Un opérateur CLOUD durcit avec le flag ; le
/// never-egress (loopback/link-local=metadata/unspecified/ULA) reste TOUJOURS bloqué (jamais une cible légitime).
static SSRF_BLOCK_PRIVATE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
fn ssrf_block_private() -> bool {
    *SSRF_BLOCK_PRIVATE.get_or_init(|| {
        let conf = load_config();
        matches!(cfg(&conf, "PLUME_SSRF_BLOCK_PRIVATE", "").trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
    })
}
/// Politique SSRF EXPLICITE (testable sans env) : never-egress INCONDITIONNEL + RFC1918 SELON `block_private`.
pub(crate) fn ssrf_blocked_policy(ip: std::net::IpAddr, block_private: bool) -> bool {
    ip_never_egress(ip) || (block_private && ip_is_rfc1918(ip))
}
/// Cible interdite pour un ÉGRESS SSRF (applique le flag env). Distinct de `ip_is_protected` : le ban protège
/// TOUJOURS le RFC1918, l'égress non par défaut.
pub(crate) fn ssrf_ipaddr_blocked(ip: std::net::IpAddr) -> bool {
    ssrf_blocked_policy(ip, ssrf_block_private())
}

/// Entrée d'allowlist SSRF : hôte exact (nom DNS), ou réseau IP/CIDR (une IP nue = /32|/128).
pub(crate) enum SsrfAllow { Host(String), Net(std::net::IpAddr, u32) }
/// Parse une entrée `PLUME_SSRF_ALLOW` : `host.interne`, `10.0.0.5`, ou `10.20.0.0/16` (CIDR). None si vide/invalide.
pub(crate) fn parse_ssrf_allow(item: &str) -> Option<SsrfAllow> {
    let it = item.trim().to_ascii_lowercase();
    if it.is_empty() { return None; }
    if let Some((net, bits)) = it.split_once('/') {
        let ip = net.parse::<std::net::IpAddr>().ok()?;
        let bits = bits.parse::<u32>().ok()?;
        if bits > if ip.is_ipv4() { 32 } else { 128 } { return None; }
        Some(SsrfAllow::Net(ip, bits))
    } else if let Ok(ip) = it.parse::<std::net::IpAddr>() {
        Some(SsrfAllow::Net(ip, if ip.is_ipv4() { 32 } else { 128 }))
    } else {
        Some(SsrfAllow::Host(it))
    }
}
/// `ip` ∈ réseau `net/bits` ? (masque sur l'entier ; IPv4-mapped normalisée des deux côtés).
pub(crate) fn ip_in_cidr(ip: std::net::IpAddr, net: std::net::IpAddr, bits: u32) -> bool {
    use std::net::IpAddr;
    let norm = |a: IpAddr| match a { IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)), v4 => v4 };
    match (norm(ip), norm(net)) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let m: u32 = if bits >= 32 { u32::MAX } else if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            (u32::from(a) & m) == (u32::from(b) & m)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let m: u128 = if bits >= 128 { u128::MAX } else if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            (u128::from(a) & m) == (u128::from(b) & m)
        }
        _ => false,
    }
}
/// Échappatoire OPÉRATEUR : `PLUME_SSRF_ALLOW` (CSV d'hôtes EXACTS et/ou de CIDR, ex. `10.20.0.0/16` pour tout
/// un sous-réseau interne légitime) — court-circuite la garde SSRF POUR CES cibles. Vide par défaut (deny strict).
static SSRF_ALLOW: std::sync::OnceLock<Vec<SsrfAllow>> = std::sync::OnceLock::new();
fn ssrf_allowlist() -> &'static Vec<SsrfAllow> {
    SSRF_ALLOW.get_or_init(|| {
        let conf = load_config();
        cfg(&conf, "PLUME_SSRF_ALLOW", "").split(',').filter_map(parse_ssrf_allow).collect()
    })
}
/// L'hôte (nom OU IP littérale) est-il explicitement allowlisté ? (nom exact, ou IP littérale ∈ CIDR permis).
fn ssrf_host_allowed(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    let lit = ssrf_norm_ip(&h);
    ssrf_allowlist().iter().any(|a| match a {
        SsrfAllow::Host(x) => x == &h,
        SsrfAllow::Net(net, bits) => lit.map(|ip| ip_in_cidr(ip, *net, *bits)).unwrap_or(false),
    })
}
/// Une IP RÉSOLUE est-elle allowlistée par un CIDR/IP opérateur ? (les entrées `Host` nom ne matchent pas une IP.)
fn ssrf_ip_allowed(ip: std::net::IpAddr) -> bool {
    ssrf_allowlist().iter().any(|a| matches!(a, SsrfAllow::Net(net, bits) if ip_in_cidr(ip, *net, *bits)))
}
/// Extrait `(host, port)` de l'autorité d'une URL (déjà privée de son schéma et de son chemin), en gérant
/// l'`user:pass@` (userinfo) et le littéral IPv6 `[::1]:port`. `default_port` sert si aucun port explicite.
fn ssrf_split_authority(authority: &str, default_port: u16) -> (String, u16) {
    let authority = authority.rsplit('@').next().unwrap_or(authority); // retire un éventuel userinfo
    if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 littéral : [host]:port
        if let Some(end) = rest.find(']') {
            let host = rest[..end].to_string();
            let port = rest[end + 1..].strip_prefix(':').and_then(|p| p.parse().ok()).unwrap_or(default_port);
            return (host, port);
        }
    }
    match authority.rsplit_once(':') {
        // rsplit_once sur un host:port ; un IPv6 nu (plusieurs ':') est invalide sans crochets -> traité comme host
        Some((h, p)) if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() =>
            (h.to_string(), p.parse().unwrap_or(default_port)),
        _ => (authority.to_string(), default_port),
    }
}
/// GARDE SSRF réutilisable — appliquée à TOUTE URL sortante pilotée par un admin/utilisateur (notifiers,
/// destinations #50, connecteur http_pull + ses URL de pagination/`next`, endpoints IdP OIDC discovery/token/
/// jwks). REJETTE :
///  - un schéma hors `http(s)`/`smtp(s)` (donc `file://`, `gopher://`, `-flag`…) ;
///  - un hôte NEVER-EGRESS : loopback (127/8, ::1), link-local (169.254/16 = metadata cloud, fe80::/10),
///    unspecified (0.0.0.0, ::), ULA IPv6 (fc00::/7) — l'IPv4-mapped IPv6 (`::ffff:x.x.x.x`) est NORMALISÉE
///    d'abord (ferme `[::ffff:169.254.169.254]`). RFC1918 en SUS UNIQUEMENT si `PLUME_SSRF_BLOCK_PRIVATE=1`
///    (défaut OFF : on-prem cible ses ressources internes légitimement — cf. `ssrf_block_private`) ;
///  - un HÔTE dont la RÉSOLUTION DNS pointe vers une de ces plages (on re-vérifie CHAQUE IP résolue).
/// FAIL-CLOSED : hôte vide, schéma interdit, ou résolution DNS impossible -> `Err` (deny sur l'incertitude).
/// Échappatoire : `PLUME_SSRF_ALLOW` (hôtes exacts ET/OU CIDR). Cette garde s'applique aux URL d'égress
/// fixées via l'UI/API.
///
/// PORTÉE : la validation d'adresse a lieu AVANT la connexion. C'est une DÉFENSE EN PROFONDEUR, pas un
/// substitut au confinement réseau : en déploiement sans politique réseau, restreignez l'égress du service
/// au strict nécessaire (politique de sortie / pare-feu de votre plateforme).
pub(crate) fn ssrf_guard(url: &str) -> Result<(), String> {
    let low = url.trim().to_ascii_lowercase();
    let (rest, default_port) = if let Some(r) = low.strip_prefix("https://") {
        (r, 443u16)
    } else if let Some(r) = low.strip_prefix("http://") {
        (r, 80)
    } else if let Some(r) = low.strip_prefix("smtps://") {
        (r, 465)
    } else if let Some(r) = low.strip_prefix("smtp://") {
        (r, 25)
    } else {
        return Err("SSRF: schéma d'URL non autorisé (http/https/smtp attendu)".into());
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return Err("SSRF: hôte d'URL vide".into());
    }
    let (host, port) = ssrf_split_authority(authority, default_port);
    ssrf_check_host(&host, port)
}
/// Cœur réutilisable de la garde SSRF sur un couple (host, port) — permet aux transports NON-URL (le syslog
/// `tcp://` des destinations #50) de partager EXACTEMENT la même politique. Voir `ssrf_guard`.
pub(crate) fn ssrf_check_host(host: &str, port: u16) -> Result<(), String> {
    use std::net::ToSocketAddrs;
    let host = host.trim().to_ascii_lowercase();
    if host.is_empty() {
        return Err("SSRF: hôte d'URL vide".into());
    }
    // échappatoire opérateur explicite (nom exact OU IP littérale ∈ CIDR permis)
    if ssrf_host_allowed(&host) {
        return Ok(());
    }
    // littéral IP interne ? (rejet immédiat, avant toute résolution ; IPv4-mapped normalisée)
    if let Some(ip) = ssrf_norm_ip(&host) {
        if ssrf_ipaddr_blocked(ip) {
            return Err(format!("SSRF: cible interne interdite ({host})"));
        }
    }
    // résolution DNS + re-check de CHAQUE IP ; échec de résolution -> deny (fail-closed)
    let mut resolved = 0usize;
    let addrs = (host.as_str(), port).to_socket_addrs()
        .map_err(|e| format!("SSRF: résolution de '{host}' impossible (deny): {e}"))?;
    for a in addrs {
        resolved += 1;
        let ip = a.ip();
        if ssrf_ip_allowed(ip) { continue; } // CIDR/IP opérateur : exempte cette IP résolue
        if ssrf_ipaddr_blocked(ip) {
            return Err(format!("SSRF: '{host}' résout vers une adresse interne ({ip}) — refus"));
        }
    }
    if resolved == 0 {
        return Err(format!("SSRF: aucune IP résolue pour '{host}' (deny)"));
    }
    Ok(())
}
