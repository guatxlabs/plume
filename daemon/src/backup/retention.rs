//! backup::retention — RÉTENTION des archives. Le SEUL analyseur des noms (`classify_backup_name` / `ParsedBackup`),
//! les paramètres GFS (`GfsParams`), le plan de purge à paliers (`backup_prune_plan`, sous-commande
//! `backup-prune-plan`) et les helpers PURS de l'ordonnanceur natif (`fmt_backup_ts`, `backup_keep_recent_plan`).
//! Logique PURE `noms + now + params -> noms à supprimer`, sans I/O ni crédential : testable en isolation.
//! Sous-module de `backup` (cf. `backup/mod.rs`), qui ré-exporte sa surface `pub(crate)` sous les chemins d'origine.
use super::*;

// ============================================================================
// RÉTENTION GFS À PALIERS (grandfather-father-son) — sous-commande `backup-prune-plan`.
// ----------------------------------------------------------------------------
// LOGIQUE DE SÉLECTION PURE : lit une liste de NOMS d'objets (base-names ou clés complètes),
// calcule les noms à SUPPRIMER, ne touche JAMAIS S3/MinIO (le sidecar garde `mc`). Testable en
// isolation (fonction pure `names + now + params -> noms à supprimer`). Le rayon de souffle reste
// minuscule : ZÉRO capacité de suppression / crédential S3 dans le daemon.
//
// FORMAT DES NOMS (cf. scope) — UNE SEULE fonction les connaît tous : `classify_backup_name` :
//   - régulier   : `plume-<TS>.db.age`                   (sidecar `backup`, cadence PLUME_BACKUP_INTERVAL)
//   - premigrate : `premigrate-<sha>-<TS>.db.age`        (init `pre-migrate-backup`, automatique, par SHA
//                                                         d'image, sous le sous-préfixe `premigrate/`)
//   - preschema  : `plume-<TS>-preschema<N>.db.age`      (P4.4-l — pris À CHAUD par l'EXPLOITANT, avec
//                                                         `tools/plume-sauvegarde-a-chaud.sh --schema <N>`
//                                                         du dépôt des manifestes ; N = schéma de
//                                                         DESTINATION ; c'est l'objet que la porte de
//                                                         déploiement à sens unique exige en acquittement.
//                                                         Déposé À LA RACINE du préfixe, donc dans le
//                                                         MÊME listage que les réguliers : sans classe, il
//                                                         était `Unparseable` et restait pour toujours)
//   avec `<TS> = YYYYMMDDTHHMMSSZ` (UTC, `date -u +%Y%m%dT%H%M%SZ`) -> tri lexicographique ==
//   chronologique. Une clé COMPLÈTE (`premigrate/premigrate-...`) est routée par son BASE-NAME.
//
// ALGORITHME (par palier, sur le set RÉGULIER ; premigrate et preschema = keep-N, CHACUN SON QUOTA) :
//   age < DENSE_DAYS           -> KEEP tout           (granularité 2h)
//   DENSE_DAYS  <= age < DAILY  -> KEEP le DERNIER (max TS) par jour civil UTC
//   DAILY_DAYS  <= age < WEEKLY -> KEEP le DERNIER (max TS) par semaine ISO (lun-dim)
//   age >= WEEKLY_DAYS          -> DROP
//   premigrate                 -> KEEP les PREMIGRATE_KEEP plus récents (par TS), DROP le reste
//   preschema                  -> KEEP les PREMIGRATE_KEEP plus récents (par TS), DROP le reste —
//                                 MÊME réglage parce que c'est la MÊME question (« combien de points de
//                                 retour d'avant-migration garder ? »), quotas SÉPARÉS parce que les deux
//                                 classes ne sont jamais dans le même listage (le sidecar voit la racine,
//                                 l'init voit `premigrate/`) : les compter ensemble ne serait vrai pour
//                                 aucun des deux appelants. Le numéro de schéma n'ordonne RIEN (comme le
//                                 `<sha>` des premigrate) : l'horodatage seul décide.
//
// INVARIANTS DE SÛRETÉ (fail-safe / keep-if-unsure — tous testés) :
//   1. le régulier LE PLUS récent n'est JAMAIS supprimé (garde inconditionnelle, hors math paliers) ;
//   2. le premigrate LE PLUS récent n'est JAMAIS supprimé (keep-N borné à >= 1) — idem preschema ;
//   3. un nom NON parseable (format inconnu / TS invalide) est TOUJOURS gardé (jamais supprimé) ;
//   4. entrée vide -> sortie vide ;
//   5. idempotent : rejouer le plan sur (entrée - plan) -> sortie vide ;
//   6. déterministe : ordre d'entrée préservé, départage stable (TS puis nom).
// ============================================================================

/// Longueur exacte d'un horodatage `YYYYMMDDTHHMMSSZ` (UTC). 8 (date) + `T` + 6 (heure) + `Z`.
pub(crate) const BACKUP_TS_LEN: usize = 16;

/// Paramètres GFS (env-tunable, défauts validés par l'opérateur). Jours pour les paliers réguliers + nombre
/// de points de retour d'avant-migration à conserver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GfsParams {
    pub(crate) dense_days: i64,
    pub(crate) daily_days: i64,
    pub(crate) weekly_days: i64,
    /// `PLUME_BACKUP_PREMIGRATE_KEEP` — borne de CHACUNE des deux classes d'avant-migration, séparément :
    /// N `premigrate-<sha>-<TS>` (automatiques) ET N `plume-<TS>-preschema<M>` (pris par l'exploitant).
    pub(crate) premigrate_keep: usize,
}

impl GfsParams {
    /// Charge depuis la CONFIGURATION (`env > fichier PLUME_CONFIG > défaut`) avec les défauts validés
    /// par l'opérateur (DENSE=2j, DAILY=14j, WEEKLY=90j, PREMIGRATE_KEEP=2). Une valeur illisible/négative
    /// -> DÉFAUT (fail-safe : jamais de palier dégénéré silencieux).
    ///
    /// P8.7-a — ces quatre paliers lisaient l'environnement par un helper `env_i64`/`env_usize` : la clé
    /// n'y était pas un littéral passé à `env::var`, donc la première mesure du défaut (qui cherchait
    /// `env::var("PLUME_…")`) NE LES AVAIT PAS VUS. C'est la raison d'être du scanner `③` : il suit aussi
    /// les aiguilleurs indirects, pour qu'un réglage ne puisse pas se soustraire au fichier en passant par
    /// une fonction intermédiaire.
    pub(crate) fn depuis_la_configuration() -> Self {
        let conf = load_config();
        let i64_de = |k: &str, d: i64| {
            cfg(&conf, k, "").trim().parse::<i64>().ok().filter(|&n| n >= 0).unwrap_or(d)
        };
        let usize_de = |k: &str, d: usize| cfg(&conf, k, "").trim().parse::<usize>().unwrap_or(d);
        GfsParams {
            dense_days: i64_de("PLUME_BACKUP_DENSE_DAYS", 2),
            daily_days: i64_de("PLUME_BACKUP_DAILY_DAYS", 14),
            weekly_days: i64_de("PLUME_BACKUP_WEEKLY_DAYS", 90),
            premigrate_keep: usize_de("PLUME_BACKUP_PREMIGRATE_KEEP", 2),
        }
    }
}

/// Jours civils (UTC) depuis l'epoch Unix (1970-01-01) — algorithme de Howard Hinnant `days_from_civil`,
/// valide pour tout le calendrier grégorien proleptique. Aucune dépendance (chrono ABSENT du daemon).
pub(crate) fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;                                     // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 };                  // mars=0 ... février=11
    let doy = (153 * mp + 2) / 5 + d - 1;                        // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;             // [0, 146096]
    era * 146097 + doe - 719468
}

/// Parse un horodatage `YYYYMMDDTHHMMSSZ` (UTC) -> secondes Unix. `None` si le format ne colle PAS
/// EXACTEMENT (longueur, séparateurs `T`/`Z`, chiffres, bornes calendaires) -> l'appelant KEEP (fail-safe :
/// on ne supprime JAMAIS sur un TS ambigu).
pub(crate) fn parse_backup_ts(ts: &str) -> Option<i64> {
    let b = ts.as_bytes();
    if b.len() != BACKUP_TS_LEN { return None; }
    if b[8] != b'T' || b[15] != b'Z' { return None; }
    for (i, &c) in b.iter().enumerate() {
        if i == 8 || i == 15 { continue; }
        if !c.is_ascii_digit() { return None; }
    }
    let num = |s: &str| s.parse::<i64>().ok();
    let year = num(&ts[0..4])?;
    let mon = num(&ts[4..6])?;
    let day = num(&ts[6..8])?;
    let hour = num(&ts[9..11])?;
    let min = num(&ts[11..13])?;
    let sec = num(&ts[13..15])?;
    if !(1..=12).contains(&mon) || !(1..=31).contains(&day) { return None; }
    if hour > 23 || min > 59 || sec > 60 { return None; }        // 60 tolère une seconde intercalaire
    Some(days_from_civil(year, mon, day) * 86400 + hour * 3600 + min * 60 + sec)
}

/// Clé de JOUR civil UTC (numéro de jour depuis l'epoch) d'un timestamp Unix.
pub(crate) fn day_key(ts: i64) -> i64 { ts.div_euclid(86400) }

/// Clé de SEMAINE ISO (lun-dim) : numéro de jour du LUNDI de la semaine. 1970-01-01 (jour 0) est un
/// JEUDI (index 3 avec lundi=0) -> `days - (days+3) mod 7` donne le lundi. Deux TS de la même semaine
/// ISO partagent la même clé -> groupement exact par semaine ISO sans arithmétique année/semaine ISO.
pub(crate) fn week_key(ts: i64) -> i64 {
    let days = ts.div_euclid(86400);
    days - (days + 3).rem_euclid(7)
}

/// Classe d'un nom d'objet de backup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParsedBackup {
    /// `plume-<TS>.db.age` — backup régulier (secondes Unix parsées du TS).
    Regular(i64),
    /// `premigrate-<sha>-<TS>.db.age` — snapshot pré-migration (secondes Unix parsées du TS).
    Premigrate(i64),
    /// `plume-<TS>-preschema<N>.db.age` — point de retour pris À CHAUD par l'exploitant avant un
    /// franchissement de schéma vers `schema` (P4.4-l ; produit par `tools/plume-sauvegarde-a-chaud.sh`
    /// du dépôt des manifestes). `schema` est extrait pour être lisible ; la rétention n'ordonne que par `ts`.
    PreSchema { ts: i64, schema: u32 },
    /// Format inconnu OU TS non parseable -> KEEP inconditionnel (jamais supprimé).
    Unparseable,
}

/// Classe un nom d'objet (base-name OU clé complète `dir/...` — routé par le BASE-NAME). Tout format
/// inattendu ou TS invalide -> `Unparseable` (l'appelant ne le supprimera JAMAIS). C'est la SEULE fonction
/// qui connaît les formes de nom : un appelant qui en énumérerait une lui-même recréerait le défaut P4.4-l.
pub(crate) fn classify_backup_name(raw: &str) -> ParsedBackup {
    let name = raw.rsplit('/').next().unwrap_or(raw);           // base-name (route même une clé complète)
    if let Some(mid) = name.strip_prefix("plume-").and_then(|s| s.strip_suffix(".db.age")) {
        // `<TS>` seul = régulier ; `<TS>-preschema<N>` = preschema (N = chiffres ASCII, non vide, rien
        // après) ; toute autre marque après le tiret (`-a-chaud`, `-preschema` sans nombre, `-116` sans
        // mot) = Unparseable. L'horodatage est vérifié par le MÊME `parse_backup_ts` que les autres classes.
        return match mid.split_once('-') {
            None => match parse_backup_ts(mid) {
                Some(ts) => ParsedBackup::Regular(ts),
                None => ParsedBackup::Unparseable,
            },
            Some((ts_str, marque)) => match (parse_backup_ts(ts_str), marque.strip_prefix("preschema")) {
                (Some(ts), Some(n)) if !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit()) => {
                    match n.parse::<u32>() {
                        Ok(schema) => ParsedBackup::PreSchema { ts, schema },
                        Err(_) => ParsedBackup::Unparseable,        // au-delà de u32 : pas un schéma
                    }
                }
                _ => ParsedBackup::Unparseable,
            },
        };
    }
    if let Some(mid) = name.strip_prefix("premigrate-").and_then(|s| s.strip_suffix(".db.age")) {
        // le TS = le suffixe après le DERNIER '-' (le <sha> n'en contient pas). Ex : `82c168b-<TS>`.
        if let Some(ts_str) = mid.rsplit('-').next() {
            if let Some(ts) = parse_backup_ts(ts_str) { return ParsedBackup::Premigrate(ts); }
        }
        return ParsedBackup::Unparseable;
    }
    ParsedBackup::Unparseable
}

/// PLAN de suppression GFS. Fonction PURE : `names` (noms bruts, ordre libre) + `now_secs` (secondes Unix
/// INJECTÉES -> testable) + `p` -> liste des noms à SUPPRIMER, dans l'ORDRE D'ENTRÉE, noms bruts préservés
/// tels quels (le sidecar les repasse à `mc rm`). Voir les invariants 1-6 dans l'en-tête de section.
pub(crate) fn backup_prune_plan(names: &[String], now_secs: i64, p: &GfsParams) -> Vec<String> {
    use std::collections::{BTreeSet, HashMap, HashSet};

    // Partition en (idx, ts) réguliers / premigrate / preschema ; les non parseables sont IGNORÉS (donc gardés).
    let mut regular: Vec<(usize, i64)> = Vec::new();
    let mut premigrate: Vec<(usize, i64)> = Vec::new();
    let mut preschema: Vec<(usize, i64)> = Vec::new();
    for (i, raw) in names.iter().enumerate() {
        match classify_backup_name(raw) {
            ParsedBackup::Regular(ts) => regular.push((i, ts)),
            ParsedBackup::Premigrate(ts) => premigrate.push((i, ts)),
            ParsedBackup::PreSchema { ts, .. } => preschema.push((i, ts)),
            ParsedBackup::Unparseable => {}                     // INVARIANT 3 : jamais supprimé
        }
    }

    let mut delete_idx: BTreeSet<usize> = BTreeSet::new();

    // --- SET RÉGULIER : paliers GFS -------------------------------------------
    if !regular.is_empty() {
        let dense = p.dense_days.saturating_mul(86400);
        let daily = p.daily_days.saturating_mul(86400);
        let weekly = p.weekly_days.saturating_mul(86400);

        // Départage déterministe : (ts, nom) le plus GRAND gagne. `names[idx]` compare les chaînes brutes.
        let cand_wins = |c_ts: i64, c_idx: usize, w_ts: i64, w_idx: usize| -> bool {
            (c_ts, &names[c_idx]) > (w_ts, &names[w_idx])
        };

        // INVARIANT 1 : le régulier LE PLUS récent (max ts, départage nom) est TOUJOURS gardé.
        let newest = *regular.iter()
            .max_by(|a, b| a.1.cmp(&b.1).then_with(|| names[a.0].cmp(&names[b.0])))
            .unwrap();

        let mut keep: HashSet<usize> = HashSet::new();
        keep.insert(newest.0);

        // Groupes "dernier par jour" / "dernier par semaine" : clé -> (ts_gagnant, idx_gagnant).
        let mut day_win: HashMap<i64, (i64, usize)> = HashMap::new();
        let mut week_win: HashMap<i64, (i64, usize)> = HashMap::new();

        for &(idx, ts) in &regular {
            let age = now_secs - ts;
            if age < dense {
                keep.insert(idx);                              // palier DENSE : tout gardé
            } else if age < daily {
                let k = day_key(ts);
                match day_win.get(&k) {
                    Some(&(w_ts, w_idx)) if !cand_wins(ts, idx, w_ts, w_idx) => {}
                    _ => { day_win.insert(k, (ts, idx)); }
                }
            } else if age < weekly {
                let k = week_key(ts);
                match week_win.get(&k) {
                    Some(&(w_ts, w_idx)) if !cand_wins(ts, idx, w_ts, w_idx) => {}
                    _ => { week_win.insert(k, (ts, idx)); }
                }
            }
            // age >= weekly -> candidat à la suppression (sauf s'il EST le newest, déjà dans keep).
        }
        for (_, (_, idx)) in day_win { keep.insert(idx); }
        for (_, (_, idx)) in week_win { keep.insert(idx); }

        for &(idx, _) in &regular {
            if !keep.contains(&idx) { delete_idx.insert(idx); }
        }
    }

    // --- SETS PREMIGRATE et PRESCHEMA : keep-N plus récents, CHACUN SON QUOTA ----
    // Tri (ts, nom) DÉCROISSANT ; on garde les `premigrate_keep` premiers (borné à >= 1 : INVARIANT 2).
    let keep_n = p.premigrate_keep.max(1);
    for set in [&premigrate, &preschema] {
        let mut sorted = set.clone();
        sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| names[b.0].cmp(&names[a.0])));
        for &(idx, _) in sorted.iter().skip(keep_n) {
            delete_idx.insert(idx);
        }
    }

    // Sortie : noms bruts dans l'ORDRE D'ENTRÉE (BTreeSet<idx> itère croissant). INVARIANT 4 : vide -> vide.
    delete_idx.into_iter().map(|i| names[i].clone()).collect()
}

// ============================================================================
// OPS NATIVE — helpers du SCHEDULER DE BACKUP IN-DAEMON (portable host/Docker).
// ----------------------------------------------------------------------------
// Rendent `docker run` / le binaire host self-backup TURNKEY sans dépendre du sidecar shell k3s (mc/S3) :
//   - `fmt_backup_ts`            : nomme les backups `plume-<TS>.db.age` (inverse EXACT de `parse_backup_ts`)
//   - `backup_keep_recent_plan`  : rétention KEEP-N PURE (garde les N plus récents), fail-safe comme le GFS.
// L'orchestration (boucle intervalle, rename atomique, prune) vit dans `server/mod.rs` ; ici = logique PURE testable.
// ============================================================================

/// Formate des secondes Unix -> horodatage compact `YYYYMMDDTHHMMSSZ` (UTC) — INVERSE EXACT de
/// `parse_backup_ts` (miroir de `date -u +%Y%m%dT%H%M%SZ`, le format que le sidecar shell produit déjà).
/// Aucune dépendance (chrono absent du daemon) : `civil_from_days` de Howard Hinnant. Le tri lexicographique
/// du nom résultant == tri chronologique -> compatible tel quel avec `classify_backup_name` / la rétention.
pub(crate) fn fmt_backup_ts(secs: i64) -> String {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (h, mi, se) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}{m:02}{d:02}T{h:02}{mi:02}{se:02}Z")
}

/// PLAN de rétention KEEP-N pour le SCHEDULER natif in-daemon. Fonction PURE : garde les `keep` backups
/// RÉGULIERS (`plume-<TS>.db.age`) les plus RÉCENTS (par TS parsé) et renvoie les noms des PLUS ANCIENS à
/// SUPPRIMER, dans l'ORDRE D'ENTRÉE. C'est le pendant « simple » (KEEP-N host/Docker) du GFS à paliers
/// (`backup_prune_plan`, sidecar k3s/S3) : il REJOUE les MÊMES primitives de parsing (`classify_backup_name`)
/// et les MÊMES invariants fail-safe :
///   - un nom NON parseable (format inconnu / TS invalide, ex. le `.tmp` d'un backup en cours) n'est JAMAIS
///     supprimé -> jamais de course avec un rename atomique en vol ;
///   - un `premigrate-*` ou un `plume-<TS>-preschema<N>` n'est JAMAIS supprimé (hors périmètre du scheduler) ;
///   - `keep` est borné à >= 1 -> le répertoire n'est JAMAIS vidé (le plus récent survit toujours) ;
///   - entrée <= keep -> sortie vide ; déterministe (tri stable (TS puis nom brut)).
pub(crate) fn backup_keep_recent_plan(names: &[String], keep: usize) -> Vec<String> {
    let keep = keep.max(1); // garde-fou : au moins le plus récent survit (jamais tout supprimer).
    // (idx, ts) des SEULS backups réguliers ; premigrate, preschema + non-parseables IGNORÉS (donc gardés = fail-safe).
    let mut regular: Vec<(usize, i64)> = names.iter().enumerate()
        .filter_map(|(i, raw)| match classify_backup_name(raw) {
            ParsedBackup::Regular(ts) => Some((i, ts)),
            _ => None,
        })
        .collect();
    if regular.len() <= keep { return Vec::new(); } // rien de trop -> aucune suppression.
    // Tri (ts, nom brut) DÉCROISSANT : les `keep` premiers = les plus récents (gardés) ; le reste = à supprimer.
    regular.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| names[b.0].cmp(&names[a.0])));
    let mut del_idx: Vec<usize> = regular.iter().skip(keep).map(|&(i, _)| i).collect();
    del_idx.sort_unstable(); // ordre d'entrée (déterministe, indépendant du tri interne).
    del_idx.into_iter().map(|i| names[i].clone()).collect()
}
