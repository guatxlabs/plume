//! Sauvegarde compressée + chiffrée (CLI `backup --compress` / `restore`) + helpers d'ouverture
//! SQLCipher à clé explicite. Extrait de main.rs (refactor split #25 — byte-identique).
//! Sous-modules : `dump_restauration` (dump typé B1 streaming, dispatch `backup_compressed`, `restore_compressed`),
//! `retention` (classification des noms, GFS, plan de purge, helpers purs de l'ordonnanceur natif),
//! `verification` (en-tête age sans déchiffrer, restauration jetable et inventaire du contenu).
use crate::*;

// ============================================================================
// SAUVEGARDE COMPRESSÉE + CHIFFRÉE  (CLI : `backup --compress` / `restore`)
// ----------------------------------------------------------------------------
// PROBLÈME : la DB SQLCipher est chiffrée at-rest -> INCOMPRESSIBLE (~2 GiB).
// SOLUTION : compresser (zstd) puis chiffrer (age) EN FLUX. Reste la question de CE QU'ON
//   fait passer dans le flux, et c'est là que les DEUX chemins de ce module diffèrent.
//
// DEUX CHEMINS, UNE SEULE ENVELOPPE. Le fichier produit est TOUJOURS `age( zstd( charge ) )` :
//   - couche EXTERNE : conteneur age v1 (en-tête « age-encryption.org/v1 », destinataire
//     scrypt/passphrase ou X25519) -> chiffrement authentifié, streaming ;
//   - couche INTERNE : frame zstd (magic 28 B5 2F FD) ;
//   - CHARGE : c'est elle qui change, et le restore la RECONNAÎT à son marqueur de tête —
//     JAMAIS au nom du fichier (les deux s'appellent `plume-<TS>.db.age`) :
//       * `PLUMEDUMP1\n`      -> DUMP TYPÉ STREAMING (défaut depuis B1, cf. section B1)
//       * `SQLite format 3\0` -> copie SQLite EN CLAIR (chemin HISTORIQUE)
//     Les sauvegardes en séquestre produites avant B1 sont donc toujours restaurables : c'est
//     le marqueur, pas une convention de nom, qui aiguille (`restore_compressed`).
//   Propriété de secours, valable pour les DEUX : hors de ce binaire,
//   `age -d -p < dest | zstd -d` redonne la charge avec des outils standard ; c'est une DB
//   SQLite directement ouvrable pour l'ancien format, le dump typé pour le nouveau.
//
// CE QUE LE CHEMIN HISTORIQUE COÛTE, ET POURQUOI IL N'EST PLUS LE DÉFAUT. `sqlcipher_export`
//   réécrit la base ENTIÈRE EN CLAIR dans un fichier temporaire de staging avant de la
//   compresser : pendant toute la durée du backup, une copie déchiffrée de tout le SOC est
//   posée sur un disque. Un garde RAII l'efface à la sortie et un balayage réape les orphelins
//   d'un SIGKILL — mais la fenêtre existe, et c'est elle que le streaming supprime.
//   Il reste joignable pour deux raisons : (1) REPLI AUTOMATIQUE sur les schémas que le dump
//   typé ne peut pas représenter fidèlement (cf. section B1) ; (2) ÉCHAPPATOIRE opérateur
//   explicite `PLUME_BACKUP_FORCE_PLAINTEXT_EXPORT=1`.
//
// CLÉ : la passphrase age = la clé SQLCipher (db_key()/PLUME_DB_KEY). UN seul secret.
//   Le scrypt d'age dérive sa propre clé (KDF) à partir de cette passphrase -> pas de
//   réutilisation directe de la clé brute. Requise (non vide) pour backup ET restore.
//
// RAM BORNÉE PAR LA TAILLE DE LA BASE dans les deux cas : buffers de 1 MiB, pager SQLite à cache
//   borné — JAMAIS la base en heap. Le streaming n'ajoute au plus qu'UNE ligne à la fois (cf.
//   section B1). Le KDF scrypt du chiffrement PAR PASSPHRASE dominait ce pic tant qu'`age` en
//   choisissait la taille AU CHRONO ; il est désormais FIXÉ et BORNÉ ici — cf. la section
//   « FACTEUR DE TRAVAIL SCRYPT » juste en dessous, qui porte la mesure et le raisonnement.
// ============================================================================

/// Buffer de copie en flux (1 MiB) -> RAM bornée quelle que soit la taille de la DB.
pub(crate) const BACKUP_BUF: usize = 1 << 20;
/// Niveau zstd : compromis ratio/CPU/RAM (fenêtre modérée -> sûr sous la limite 2 GiB).
pub(crate) const BACKUP_ZSTD_LEVEL: i32 = 7;

/// Âge minimal (s) d'un plaintext temporaire orphelin avant réapage au démarrage. Seuil de
/// SÛRETÉ : on n'efface JAMAIS un temp plus récent (backup concurrent potentiellement en vol).
pub(crate) const BACKUP_ORPHAN_MAX_AGE_SECS: u64 = 3600; // 1 h

/// Marqueur STRICT du nom d'un plaintext temporaire de backup (cf. `plain_temp_path`). Sert de
/// filtre au balayage : ne matche JAMAIS la vraie DB (`plume.db`/`-wal`/`-shm`) ni un `.age`.
pub(crate) const BACKUP_TEMP_MARKER: &str = ".plain.tmp.";

/// Sidecars SQLite qu'un `sqlcipher_export` vers un fichier temporaire peut créer À CÔTÉ du
/// temp (journal de rollback / WAL / shm). Ils contiennent aussi des pages EN CLAIR : à effacer
/// avec le temp. (Le nom du sidecar contient le marqueur -> le balayage les capte aussi.)
pub(crate) const TEMP_SIDECARS: [&str; 3] = ["-journal", "-wal", "-shm"];

// ============================================================================
// FACTEUR DE TRAVAIL SCRYPT DU CHEMIN PAR PASSPHRASE (P8.6-b)
// ----------------------------------------------------------------------------
// CE QUI SE PASSAIT, MESURÉ. `Encryptor::with_user_passphrase` construit un `scrypt::Recipient`
// dont le facteur de travail est choisi par un ÉTALONNAGE AU CHRONOMÈTRE **à chaque sauvegarde**
// (`age-0.11.3/src/scrypt.rs::target_scrypt_work_factor` : chronomètre scrypt à log_n=10 puis
// EXTRAPOLE en doublant jusqu'à viser ~1 s de CPU). scrypt alloue alors `128·r·2^log_n` octets,
// r=8 chez age (`age-0.11.3/src/primitives.rs:65`), soit `2^(10+log_n)`.
//
// LA MESURE QUI TRANCHE (2026-08-09, 12 cœurs, MÊME machine, MÊME code, `age::Encryptor::
// with_user_passphrase` trois fois de suite, log_n RELU dans la strophe `-> scrypt <sel> <log_n>`
// de l'en-tête produit) :
//     compilé en `debug` (opt-level 0, = ce que compile `cargo test`) : log_n = 13, 14, 14
//                                                                       ->   8 Mio /  16 Mio
//     compilé en `release` (opt-level 3, = LA PRODUCTION)             : log_n = 19, 19, 20
//                                                                       -> 512 Mio / 1024 Mio
// Le facteur ne dépend donc pas seulement de la machine : il dépend du PROFIL DE COMPILATION, et
// il varie d'un appel à l'autre sur la MÊME machine. Sous un budget de 2 Gio, le chemin par
// DÉFAUT réclamait jusqu'à **1 073 741 824 octets — la moitié du budget — sur un coup de dé.**
// (Le « 256 Mio » qu'age documente comme « ~1 s sur une machine moderne » était une SOUS-estimation
// de deux crans ici.)
//
// POURQUOI LE BORNER N'EST PAS UN COMPROMIS DE SÉCURITÉ — l'argument est un PLANCHER, pas une
// opinion sur l'entropie. La passphrase de ce chemin n'est pas saisie par un humain au moment du
// backup : c'est `db_key()`, c'est-à-dire `PLUME_DB_KEY_FILE` sinon `PLUME_DB_KEY` — la clé
// SQLCipher — dans les DEUX seuls appelants de production (`main.rs` sous-commande `backup`, et
// `server::run_scheduled_backup`). Or ce MÊME secret est déjà protégé AILLEURS, sur PLUS de
// données, par un étirement PLUS FAIBLE :
//   * le TIER FROID chiffre ses jours-files avec `COLD_SCRYPT_LOG_N = 12` (4 Mio) sur une
//     passphrase HKDF-dérivée de `PLUME_DB_KEY` — HKDF ne CRÉE pas d'entropie, donc deviner
//     `PLUME_DB_KEY` casse ces fichiers au coût de scrypt-12 ;
//   * ces jours-files partent à l'escrow HORS-CLUSTER en **COPIE VERBATIM** (cf. l'en-tête de
//     `cold_store/backup.rs` : « escrow symétrique », le destinataire age ne les couvre pas) —
//     ils sont donc DÉJÀ hors du nœud, à log_n=12 ;
//   * la base CHAUDE elle-même est protégée par le KDF de SQLCipher (PBKDF2-HMAC-SHA512), qui
//     n'est PAS memory-hard et se parallélise sur GPU bien mieux que scrypt.
// Le coût d'attaque sur `PLUME_DB_KEY` est donc le MINIMUM sur tous ses porteurs, et ce minimum
// vaut au plus scrypt-12. Écrire un backup à log_n=15 ou 19 ne relève pas ce plancher d'un bit :
// l'attaquant vise le porteur le moins cher, qui n'est pas le backup. **Ce qu'on retire ici est
// un coût, pas une résistance.**
// EN OUTRE le mode par passphrase est, par définition dans plume, le mode NON séquestré : la
// passphrase « est présente sur le nœud » et le backup est « DÉCHIFFRABLE PAR LE NŒUD » (c'est
// mot pour mot ce que `emit_backup_symmetric_signal` écrit dans un événement SOC non-purgeable, et
// ce que `PLUME_BACKUP_REQUIRE_ASYMMETRIC=1` permet d'interdire). Le mode recommandé pour un
// backup qui VOYAGE est le destinataire x25519 — qui n'a aucun terme KDF.
//
// CE QUE CETTE DÉCISION SUPPOSE, ET QUI N'EST PAS VÉRIFIÉ PAR LE CODE : que `PLUME_DB_KEY` soit du
// MATÉRIEL DE CLÉ et non un mot de passe tapé. Rien dans plume ne mesure ni n'impose l'entropie de
// cette valeur — `deploy/k3s.yaml` se contente d'écrire « mets une passphrase forte ici ». Cette
// hypothèse est déjà celle du tier froid ; elle est ici NOMMÉE au lieu d'être tacite, et
// `PLUME_BACKUP_SCRYPT_LOG_N` existe précisément pour l'opérateur qui sait qu'elle est fausse chez
// lui (le message de refus lui chiffre le prix en octets).
//
// DÉTERMINISME — la seconde raison, indépendante de la mémoire. Un facteur choisi au chrono rend le
// fichier dépendant de la machine qui l'a écrit : `age::scrypt::Identity` refuse (`ExcessiveWork`)
// tout `log_n` supérieur à `target+4` recalculé sur la machine qui DÉCHIFFRE. Un backup produit en
// release sur ce poste (log_n=20) présenté à un binaire debug du même poste (target=13 -> plafond
// 17) est REFUSÉ. C'est exactement le piège que `cold_store` avait déjà nommé et fermé.
// ----------------------------------------------------------------------------

/// Facteur de travail scrypt (log2(N)) ÉCRIT par défaut sur le chemin par passphrase.
/// **12 = 4 194 304 octets de tampon** (`2^(10+12)`), 10,4 ms mesurés en release / 555 ms en debug
/// le 2026-08-09 sur 12 cœurs. La valeur est celle du tier froid (`COLD_SCRYPT_LOG_N`) parce que
/// c'est le PLANCHER réel d'attaque de `PLUME_DB_KEY` (cf. le raisonnement ci-dessus) : au-dessus,
/// on paie sans rien acheter. Ce n'est PAS le défaut d'age (13 à 20 mesurés selon le profil et le
/// tirage) : ici la valeur est FIXE, donc le fichier produit ne dépend plus de la machine.
pub(crate) const BACKUP_SCRYPT_LOG_N_DEFAUT: u8 = 12;

/// Plancher admis pour `PLUME_BACKUP_SCRYPT_LOG_N`. 10 = 1 Mio : c'est le point de départ de
/// l'étalonnage d'age lui-même, donc la plus petite valeur qu'un `age` non modifié ait jamais pu
/// écrire. En dessous, on ne parlerait plus le même dialecte que l'outil de secours.
pub(crate) const BACKUP_SCRYPT_MIN_LOG_N: u8 = 10;

/// Facteur de travail scrypt MAXIMAL **accepté à la lecture** — et par construction plafond de ce
/// qu'on accepte d'écrire, pour que plume relise toujours ce qu'il a écrit.
/// **20 = 1 073 741 824 octets** (`2^(10+20)`). Le chiffre n'est pas choisi pour la beauté :
///   - il faut couvrir TOUT ce que le défaut au chrono a pu produire avant ce correctif, sinon un
///     backup légitime devient illisible (perte de données) : **19, 19 et 20 MESURÉS en release le
///     2026-08-09**, contre 18 qu'age documente pour « une machine moderne » ;
///   - il faut refuser ce qui ne tient pas dans le budget : à log_n=21 le tampon vaut 2 147 483 648
///     octets, soit le budget de 2 Gio à lui seul -> un fichier hostile deviendrait un OOM.
/// L'écart de 8 crans avec `BACKUP_SCRYPT_LOG_N_DEFAUT` (là où `cold_store` s'impose <= 2) N'EST PAS
/// un relâchement : c'est exactement la dette historique qu'on ferme — on n'écrit plus que 12, on
/// doit encore SAVOIR LIRE jusqu'à 20.
pub(crate) const BACKUP_SCRYPT_MAX_LOG_N: u8 = 20;

/// Octets de tampon qu'un facteur `log_n` fait allouer à scrypt : `128 · r · 2^log_n` avec r=8
/// (age fixe r=8, p=1 — `age-0.11.3/src/primitives.rs:65`), soit `2^(10+log_n)`. DÉRIVÉ, jamais
/// écrit en dur : c'est ce qui permet à un message de refus de chiffrer son propre prix.
/// TOTALE : `age` accepte `log_n` jusqu'à 63 dans une strophe, et `2^(10+54)` ne tient plus dans un
/// `u64`. On SATURE plutôt que de déborder — un message de refus ne doit jamais paniquer sur la
/// valeur qu'il refuse (c'est justement la valeur la plus hostile qui l'atteint).
pub(crate) fn scrypt_tampon_octets(log_n: u8) -> u64 {
    1u64.checked_shl(10 + log_n as u32).unwrap_or(u64::MAX)
}

/// DÉCISION PURE du facteur à écrire, à partir de la valeur BRUTE du réglage. `PLUME_BACKUP_SCRYPT_LOG_N`
/// permet à l'opérateur qui SAIT que sa `PLUME_DB_KEY` est un mot de passe humain de racheter de
/// l'étirement ; il est BORNÉ à [`BACKUP_SCRYPT_MIN_LOG_N`, `BACKUP_SCRYPT_MAX_LOG_N`] pour que plume ne
/// puisse jamais écrire un fichier qu'il refuserait de relire, ni un tampon plus gros que son propre
/// budget. Une valeur hors bornes ou illisible n'est pas avalée en silence : elle est DITE, avec son prix
/// en octets.
///
/// PURE, ET C'EST DÉLIBÉRÉ : la décision se teste sans jamais TOUCHER à l'environnement du processus.
/// Un test qui poserait `PLUME_BACKUP_SCRYPT_LOG_N=20` pour éprouver la borne haute le poserait pour
/// TOUS les fils, y compris la trentaine de tests voisins qui appellent `backup_compressed` sans verrou
/// — ils paieraient un scrypt de 1 073 741 824 octets au lieu de 4 194 304. C'est la règle déjà apprise
/// le 2026-08-08 (P8.6-a), appliquée en amont : on ne met pas un réglage global dans un test, on rend la
/// fonction pure et on lui passe la chaîne.
pub(crate) fn scrypt_log_n_depuis(brut: &str) -> u8 {
    let brut = brut.trim();
    if brut.is_empty() {
        return BACKUP_SCRYPT_LOG_N_DEFAUT;
    }
    match brut.parse::<u8>() {
        Ok(n) if (BACKUP_SCRYPT_MIN_LOG_N..=BACKUP_SCRYPT_MAX_LOG_N).contains(&n) => n,
        Ok(n) => {
            eprintln!(
                "[backup] PLUME_BACKUP_SCRYPT_LOG_N={n} hors bornes [{BACKUP_SCRYPT_MIN_LOG_N}, \
                 {BACKUP_SCRYPT_MAX_LOG_N}] ({} octets de tampon scrypt demandés, plafond {} octets) \
                 -> valeur IGNORÉE, on garde {BACKUP_SCRYPT_LOG_N_DEFAUT} ({} octets).",
                scrypt_tampon_octets(n), scrypt_tampon_octets(BACKUP_SCRYPT_MAX_LOG_N),
                scrypt_tampon_octets(BACKUP_SCRYPT_LOG_N_DEFAUT));
            BACKUP_SCRYPT_LOG_N_DEFAUT
        }
        Err(_) => {
            eprintln!(
                "[backup] PLUME_BACKUP_SCRYPT_LOG_N={brut:?} n'est pas un entier -> valeur IGNORÉE, \
                 on garde {BACKUP_SCRYPT_LOG_N_DEFAUT} ({} octets de tampon scrypt).",
                scrypt_tampon_octets(BACKUP_SCRYPT_LOG_N_DEFAUT));
            BACKUP_SCRYPT_LOG_N_DEFAUT
        }
    }
}

// ============================================================================
// P8.7-a — LA VOIE UNIQUE DE LECTURE DES RÉGLAGES DE SAUVEGARDE
// ----------------------------------------------------------------------------
// CE QUI ÉTAIT CASSÉ, ET CE QUE ÇA COÛTAIT. L'ordonnanceur lit `PLUME_BACKUP_INTERVAL` / `DEST` /
// `KEEP` / `ON_START` par `cfg()` — donc `env > fichier PLUME_CONFIG > défaut`. Les réglages
// ci-dessous, eux, lisaient `std::env::var` : JAMAIS le fichier. Or `systemd/plume-daemon.service`
// ne porte AUCUN `EnvironmentFile` : sur un hôte, un opérateur qui écrit son destinataire d'escrow
// dans `/etc/plume/soc.conf` voyait l'ordonnanceur DÉMARRER depuis ce fichier puis produire des
// archives SYMÉTRIQUES — déchiffrables par quiconque tient la clé du nœud, l'exact contraire de ce
// que l'escrow existe pour garantir. Et `PLUME_BACKUP_REQUIRE_ASYMMETRIC=1`, le fail-closed prévu
// pour interdire ce cas, était muet pour la MÊME raison. MESURÉ le 2026-08-09, hors-processus, avec
// le binaire de `6afe2ce` : `soc.conf` portant `PLUME_DB` + `PLUME_BACKUP_AGE_RECIPIENT` +
// `PLUME_BACKUP_REQUIRE_ASYMMETRIC=1`, environnement vide -> la base est TROUVÉE (donc le fichier
// est bien lu) et l'archive sort en `-> scrypt` (`backup-verify … kind=Symmetric`), pendant que le
// démon affiche « PLUME_BACKUP_AGE_RECIPIENT non configuré ».
//
// L'ARBITRAGE : `cfg()` PARTOUT, PAS D'`EnvironmentFile`. `cfg()` interroge l'environnement AVANT le
// fichier — router ces lectures par `cfg()` est donc un SUR-ENSEMBLE STRICT : toute valeur posée en
// `env` continue de gagner, octet pour octet. Docker et k3s posent `PLUME_CONFIG=/nonexistent` et
// passent tout par `env:` -> la carte de fichier est VIDE et le résultat est inchangé par
// construction. La voie inverse (`EnvironmentFile=/etc/plume/soc.conf` dans l'unité) aurait corrigé
// UN SEUL des trois modes et RÉGRESSÉ la confidentialité : elle exporterait dans l'environnement du
// processus TOUT ce que porte `soc.conf` — `PLUME_PASS_HASH` et `PLUME_DB_KEY` compris — c'est-à-dire
// qu'elle rendrait lisibles via `/proc/<pid>/environ` des secrets qu'aujourd'hui seul le parseur
// in-process lit dans un fichier 0640. C'est précisément ce que le provider fichier (`_FILE`/`_REF`)
// a été construit pour éviter. Elle ajouterait en prime un SECOND parseur (les règles de
// guillemets/échappement de systemd ne sont pas celles de `load_config`) sur le même fichier.
//
// RELU À CHAQUE SAUVEGARDE (pas de `OnceLock`) : un opérateur qui corrige son réglage n'a pas à
// redémarrer le démon pour que le cycle suivant en tienne compte. Le coût est une lecture de fichier
// par sauvegarde — jamais par ligne.

/// Les réglages de sauvegarde qui, jusqu'au 2026-08-09, ne se lisaient QUE dans l'environnement.
/// Cette liste est la SOURCE des noms utilisés par les lecteurs ci-dessous ET par l'annonce de
/// bascule (`cles_sauvegarde_devenues_effectives`) : les deux ne peuvent pas diverger.
pub(crate) const CLE_BACKUP_AGE_RECIPIENT: &str = "PLUME_BACKUP_AGE_RECIPIENT";
pub(crate) const CLE_BACKUP_REQUIRE_ASYMMETRIC: &str = "PLUME_BACKUP_REQUIRE_ASYMMETRIC";
pub(crate) const CLE_BACKUP_FORCE_PLAINTEXT_EXPORT: &str = "PLUME_BACKUP_FORCE_PLAINTEXT_EXPORT";
pub(crate) const CLE_BACKUP_SCRYPT_LOG_N: &str = "PLUME_BACKUP_SCRYPT_LOG_N";
pub(crate) const CLE_BACKUP_STAGING_DIR: &str = "PLUME_BACKUP_STAGING_DIR";
pub(crate) const CLE_BACKUP_AGE_IDENTITY: &str = "PLUME_BACKUP_AGE_IDENTITY";
pub(crate) const CLE_BACKUP_AGE_IDENTITY_FILE: &str = "PLUME_BACKUP_AGE_IDENTITY_FILE";

/// Les réglages de sauvegarde repliés sur `cfg()` par P8.7-a, dans l'ordre où un opérateur les
/// rencontre. `PLUME_BACKUP_AGE_IDENTITY[_FILE]` en fait partie : c'est le seul du lot dont la
/// valeur est un SECRET (clé privée d'escrow) — elle ne doit JAMAIS être journalisée, seulement son
/// NOM (cf. `annonce_bascule_sauvegarde`).
pub(crate) const CLES_SAUVEGARDE_PAR_FICHIER: &[&str] = &[
    CLE_BACKUP_AGE_RECIPIENT,
    CLE_BACKUP_REQUIRE_ASYMMETRIC,
    CLE_BACKUP_FORCE_PLAINTEXT_EXPORT,
    CLE_BACKUP_SCRYPT_LOG_N,
    CLE_BACKUP_STAGING_DIR,
    CLE_BACKUP_AGE_IDENTITY,
    CLE_BACKUP_AGE_IDENTITY_FILE,
];

/// LA voie unique : `env > fichier PLUME_CONFIG > ""`, exactement la précédence de `cfg()`, la même
/// que celle de `PLUME_BACKUP_INTERVAL`. Aucun lecteur de ce module ne doit plus appeler
/// `std::env::var` sur une clé `PLUME_*` — c'est vérifié par un test qui SCANNE ce fichier
/// (`p87a_backup_ne_lit_plus_aucun_reglage_dans_l_environnement`), pas par relecture humaine.
pub(crate) fn reglage_sauvegarde(cle: &str) -> String {
    cfg(&load_config(), cle, "")
}

/// Les clés de sauvegarde qui étaient IGNORÉES et deviennent EFFECTIVES : présentes (non vides) dans
/// le fichier de configuration, absentes de l'environnement. PURE — l'environnement est injecté, donc
/// testable sans jamais toucher à un état global du processus.
pub(crate) fn cles_sauvegarde_devenues_effectives(
    fichier: &HashMap<String, String>,
    dans_env: impl Fn(&str) -> bool,
) -> Vec<&'static str> {
    CLES_SAUVEGARDE_PAR_FICHIER.iter().copied()
        .filter(|c| fichier.get(*c).is_some_and(|v| !v.trim().is_empty()))
        .filter(|c| !dans_env(c))
        .collect()
}

/// LE MESSAGE DE BASCULE — ce que ② exige : la transition ne doit pas se découvrir par un échec.
/// Nomme les clés concernées et DIT ce qui change pour chacune. Ne journalise JAMAIS de valeur (l'une
/// d'elles est une clé privée d'escrow). `None` = rien n'a changé pour cet hôte -> aucun bruit.
pub(crate) fn annonce_bascule_sauvegarde(cles: &[&str]) -> Option<String> {
    if cles.is_empty() { return None; }
    let mut s = String::from(
        "[backup] CHANGEMENT DE COMPORTEMENT (P8.7-a) : des réglages de sauvegarde écrits dans votre \
         fichier de configuration étaient jusqu'ici IGNORÉS (lus dans l'environnement seul) et \
         deviennent EFFECTIFS à partir de ce démarrage :");
    for c in cles {
        let effet = match *c {
            CLE_BACKUP_AGE_RECIPIENT =>
                "les archives passent du chiffrement SYMÉTRIQUE (passphrase = clé SQLCipher, présente \
                 sur ce nœud, donc déchiffrable ICI) au chiffrement ASYMÉTRIQUE vers ce destinataire \
                 (escrow hors-hôte). Les archives DÉJÀ produites restent symétriques.",
            CLE_BACKUP_REQUIRE_ASYMMETRIC =>
                "FAIL-CLOSED : si aucun destinataire age n'est résolu, la sauvegarde sera désormais \
                 REFUSÉE au lieu de retomber en symétrique. Vérifiez qu'un destinataire est bien posé, \
                 sinon les sauvegardes s'arrêteront.",
            CLE_BACKUP_FORCE_PLAINTEXT_EXPORT =>
                "la sauvegarde reprend le chemin HISTORIQUE : la base ENTIÈRE est réécrite EN CLAIR \
                 dans le staging le temps du cycle.",
            CLE_BACKUP_SCRYPT_LOG_N =>
                "le facteur de travail scrypt du chiffrement par passphrase change -> le tampon scrypt \
                 (RAM) change avec lui.",
            CLE_BACKUP_STAGING_DIR =>
                "le clair temporaire du chemin historique change de répertoire.",
            CLE_BACKUP_AGE_IDENTITY | CLE_BACKUP_AGE_IDENTITY_FILE =>
                "une identité age privée devient utilisable pour DÉCHIFFRER (restore/backup-verify). \
                 Sa valeur n'est pas journalisée.",
            _ => "devient effectif.",
        };
        s.push_str(&format!("\n  - {c} : {effet}"));
    }
    s.push_str(
        "\n  Ces clés suivent désormais la MÊME précédence que PLUME_BACKUP_INTERVAL : env > fichier \
         PLUME_CONFIG > défaut. Pour revenir au comportement précédent, retirez-les du fichier.");
    Some(s)
}

/// L'ADAPTATEUR de ② : confronte le fichier RÉEL à l'environnement RÉEL et journalise l'annonce si
/// quelque chose change pour cet hôte. Appelé au démarrage du démon (avant l'ordonnanceur) et sur le
/// chemin CLI `backup`, c'est-à-dire aux DEUX endroits où un opérateur pourrait sinon découvrir la
/// bascule par un échec. Silencieux quand rien ne change (Docker/k3s : tout est en `env` -> jamais
/// d'annonce). `stderr`, comme tous les autres logs d'exploitation du démon.
pub(crate) fn annoncer_bascule_sauvegarde(conf: &HashMap<String, String>) {
    let cles = cles_sauvegarde_devenues_effectives(conf, |c| std::env::var_os(c).is_some());
    if let Some(msg) = annonce_bascule_sauvegarde(&cles) {
        eprintln!("{msg}");
    }
}

/// L'EFFET : la même décision, appliquée à ce que porte la configuration. Seule couche qui lit
/// `PLUME_BACKUP_SCRYPT_LOG_N`.
pub(crate) fn backup_scrypt_log_n() -> u8 {
    scrypt_log_n_depuis(&reglage_sauvegarde(CLE_BACKUP_SCRYPT_LOG_N))
}

/// L'ENCRYPTEUR age des deux chemins de sauvegarde (streaming B1 ET repli legacy), écrit UNE fois.
/// ASYMÉTRIQUE (destinataire public `age1...`, escrow hors-cluster, AUCUN terme KDF) si un
/// destinataire est posé ; sinon SYMÉTRIQUE par passphrase (= clé SQLCipher) à facteur scrypt FIXÉ.
/// Les deux chemins partageaient jusqu'ici le MÊME `match` recopié : une borne posée sur l'un aurait
/// pu manquer l'autre.
pub(crate) fn backup_encryptor(pass: &str, recipient: Option<&str>) -> Result<age::Encryptor, String> {
    match recipient {
        Some(rcpt) if !rcpt.is_empty() => {
            let recipient = rcpt.parse::<age::x25519::Recipient>()
                .map_err(|e| format!("destinataire age invalide (clé publique age1... attendue) : {e}"))?;
            age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
                .map_err(|e| format!("age with_recipients : {e}"))
        }
        _ => {
            let mut rcpt = age::scrypt::Recipient::new(age::secrecy::SecretString::from(pass.to_string()));
            rcpt.set_work_factor(backup_scrypt_log_n());
            age::Encryptor::with_recipients(std::iter::once(&rcpt as &dyn age::Recipient))
                .map_err(|e| format!("age with_recipients (scrypt) : {e}"))
        }
    }
}

/// L'IDENTITÉ passphrase de la LECTURE, à plafond FIXE. `age::scrypt::Identity::new` pose sinon
/// `target_scrypt_work_factor() + 4`, donc un plafond RECALCULÉ sur la machine qui déchiffre : le
/// même fichier serait lisible ici et refusé là. Fixé -> la restaurabilité est une propriété du
/// FICHIER, plus de la machine.
pub(crate) fn backup_scrypt_identity(pass: &str) -> age::scrypt::Identity {
    let mut id = age::scrypt::Identity::new(age::secrecy::SecretString::from(pass.to_string()));
    id.set_max_work_factor(BACKUP_SCRYPT_MAX_LOG_N);
    id
}

/// CE QUE LE REFUS DIT quand age rend `ExcessiveWork` : le facteur EXIGÉ par le fichier, ce qu'il
/// coûterait en octets, notre plafond et son coût — puis le geste. Sans cela l'opérateur reçoit
/// « passphrase incorrecte ? » pour un fichier dont la passphrase est parfaitement bonne, et
/// cherche au mauvais endroit pendant un DR. Même doctrine que `limite_corps` (P4.1-o) : la limite
/// qui arrête doit dire ce qu'elle est.
fn message_dechiffrement_age(e: &age::DecryptError) -> String {
    if let age::DecryptError::ExcessiveWork { required, .. } = e {
        return format!(
            "déchiffrement age REFUSÉ : ce backup exige un facteur de travail scrypt log_n={required} \
             ({} octets de tampon) alors que plume plafonne à log_n={BACKUP_SCRYPT_MAX_LOG_N} ({} octets) \
             — au-delà, le KDF seul dépasse le budget mémoire du démon. La passphrase n'est PAS en cause. \
             Ce fichier a été produit par une version qui laissait `age` étalonner ce facteur au chrono \
             (cf. P8.6-b) : déchiffrez-le hors-ligne avec l'outil `age` sur une machine qui a la RAM, \
             puis re-sauvegardez avec cette version (qui écrit log_n={}).",
            scrypt_tampon_octets(*required), scrypt_tampon_octets(BACKUP_SCRYPT_MAX_LOG_N),
            backup_scrypt_log_n());
    }
    format!("déchiffrement age (passphrase / identité age incorrecte ou absente ?) : {e}")
}

/// Garde RAII : efface un plaintext temporaire ET ses sidecars SQLite (`-journal`/`-wal`/`-shm`)
/// sur N'IMPORTE quelle sortie de portée (succès, erreur, panique, early-return). Le plaintext
/// en clair ne doit jamais subsister. NB : Drop ne s'exécute PAS sur SIGKILL/OOM-kill — c'est
/// le balayage de démarrage (`sweep_orphan_temps`) qui réape ces fuites-là.
pub(crate) struct PlaintextTempGuard(pub(crate) std::path::PathBuf);
impl PlaintextTempGuard {
    pub(crate) fn path(&self) -> &std::path::Path { &self.0 }
}
impl Drop for PlaintextTempGuard {
    fn drop(&mut self) {
        secure_delete(&self.0);
        // sidecars SQLite laissés par un export interrompu (mêmes pages en clair).
        if let Some(base) = self.0.to_str() {
            for sfx in TEMP_SIDECARS {
                secure_delete(std::path::Path::new(&format!("{base}{sfx}")));
            }
        }
    }
}

/// BALAYAGE DE DÉMARRAGE (réape les fuites d'un crash/OOM antérieur, où Drop n'a PAS pu tourner).
/// Scanne `dir` pour les fichiers dont le nom contient le marqueur `.plain.tmp.` (donc AUSSI leurs
/// sidecars `-journal`/`-wal`/`-shm`, qui héritent du marqueur) et dont la mtime dépasse `max_age`.
/// GARDE-FOUS : (1) le filtre par marqueur n'efface JAMAIS `plume.db`/`-wal`/`-shm` ni les `.age` ;
/// (2) le seuil d'âge épargne un temp récent d'une invocation CONCURRENTE en vol. Renvoie le
/// nombre de fichiers effacés (observabilité + assertion de test).
///
/// REND UN `Balayage` (`P4.1-r`) : le compte des effacés, mais aussi ce que le balayage N'A PAS SU LIRE —
/// un répertoire illisible (rien balayé), des entrées ou des métadonnées illisibles (un temporaire en
/// clair qu'on ne sait pas examiner reste sur le disque, et avant rien ne le disait), et les effacés
/// dont le contenu n'a pas pu être écrasé avant suppression.
pub(crate) fn sweep_orphan_temps(dir: &std::path::Path, max_age: std::time::Duration) -> Balayage {
    let now = std::time::SystemTime::now();
    let mut b = Balayage::default();
    let rd = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return Balayage::repertoire_illisible(),
    };
    for ent in rd {
        let ent = match ent {
            Ok(e) => e,
            Err(_) => {
                b.illisibles += 1;
                continue;
            }
        };
        let name = ent.file_name();
        if !name.to_string_lossy().contains(BACKUP_TEMP_MARKER) { continue; }
        let meta = match ent.metadata() {
            Ok(m) => m,
            Err(_) => {
                b.illisibles += 1;
                continue;
            }
        };
        if !meta.is_file() { continue; }
        // trop récent -> on ÉPARGNE (ne jamais clobber un backup en vol) ; mtime ILLISIBLE -> épargné
        // aussi, mais COMPTÉ : ce n'est pas un temporaire récent, c'est un temporaire qu'on ne sait pas juger.
        match meta.modified().ok().and_then(|m| now.duration_since(m).ok()) {
            Some(age) if age >= max_age => {}
            Some(_) => continue,
            None => {
                b.illisibles += 1;
                continue;
            }
        }
        if !secure_delete(&ent.path()) {
            b.non_ecrases += 1;
        }
        b.effaces += 1;
    }
    b
}

/// CE QU'UN BALAYAGE DE TEMPORAIRES REND (`P4.1-r`). Partagé par le balayage du staging de sauvegarde et
/// celui du spool d'ingestion : même forme, même aveu. Le `u64` seul qu'ils rendaient comptait les effacés
/// et taisait tout le reste.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Balayage {
    pub(crate) effaces: u64,
    /// Entrées, métadonnées ou horodatages que le balayage n'a pas su lire : autant de temporaires
    /// toujours sur le disque, non jugés.
    pub(crate) illisibles: u64,
    /// Effacés dont le contenu N'A PAS été écrasé avant suppression (ouverture refusée, écriture en
    /// échec) : retirés de l'arborescence, mais pas de la surface du disque.
    pub(crate) non_ecrases: u64,
    /// `false` : le répertoire lui-même n'a pas pu être listé — RIEN n'a été balayé.
    pub(crate) repertoire_lisible: bool,
}

impl Balayage {
    pub(crate) fn repertoire_illisible() -> Self {
        Balayage { repertoire_lisible: false, ..Default::default() }
    }

    /// La phrase du journal de démarrage — VIDE quand il n'y a rien à dire (rien effacé, rien d'illisible),
    /// et toujours présente sinon, y compris quand rien n'a été effacé mais que quelque chose n'a pas pu
    /// être lu. Une chaîne plutôt qu'un `Option` : « rien à dire » est une valeur, pas une branche.
    pub(crate) fn phrase(&self, quoi: &str) -> String {
        if !self.repertoire_lisible {
            return format!("{quoi} : répertoire ILLISIBLE — aucun temporaire orphelin balayé");
        }
        if self.effaces == 0 && self.illisibles == 0 {
            return String::new();
        }
        let mut p = format!("{quoi} : {} temporaire(s) orphelin(s) balayé(s)", self.effaces);
        if self.non_ecrases > 0 {
            p.push_str(&format!(", dont {} NON écrasé(s) avant suppression", self.non_ecrases));
        }
        if self.illisibles > 0 {
            p.push_str(&format!(" ; {} entrée(s) ILLISIBLE(S) non jugée(s), toujours sur le disque", self.illisibles));
        }
        p
    }
}

impl Default for Balayage {
    fn default() -> Self {
        Balayage { effaces: 0, illisibles: 0, non_ecrases: 0, repertoire_lisible: true }
    }
}

/// Effacement best-effort d'un fichier sensible : écrase le contenu de zéros (1 passe,
/// buffers 1 MiB), fsync, puis supprime. NB : sur FS journalisé/CoW/SSD à wear-leveling
/// l'écrasement N'EST PAS une garantie cryptographique — la vraie protection reste le
/// chiffrement at-rest du volume. On réduit la fenêtre d'exposition + on garantit le retrait.
///
/// REND `true` si le contenu a été écrasé avant suppression (ou s'il n'y avait rien à écraser), `false`
/// sinon (`P4.1-r`) : un fichier qu'on n'a pas pu ouvrir ou écrire est retiré de l'arborescence mais pas
/// de la surface du disque, et l'appelant doit pouvoir le compter au lieu de l'ignorer.
pub(crate) fn secure_delete(path: &std::path::Path) -> bool {
    use std::io::{Seek, SeekFrom, Write};
    let ecrase = match std::fs::metadata(path) {
        Ok(meta) if meta.len() == 0 => true,
        Ok(meta) => match std::fs::OpenOptions::new().write(true).open(path) {
            Ok(mut f) => {
                let len = meta.len();
                let zeros = vec![0u8; BACKUP_BUF.min(len as usize)];
                let _ = f.seek(SeekFrom::Start(0));
                let mut remaining = len;
                let mut complet = true;
                while remaining > 0 {
                    let n = (remaining as usize).min(zeros.len());
                    if f.write_all(&zeros[..n]).is_err() {
                        complet = false;
                        break;
                    }
                    remaining -= n as u64;
                }
                let _ = f.flush();
                let _ = f.sync_all();
                complet
            }
            Err(_) => false,
        },
        // Absent ou illisible : rien n'a été écrasé, et `remove_file` ci-dessous dira s'il restait quelque chose.
        Err(_) => false,
    };
    let _ = std::fs::remove_file(path);
    ecrase
}

/// Copie en flux R -> W par buffers de 1 MiB. Renvoie le nombre d'octets copiés.
pub(crate) fn stream_copy<R: std::io::Read, W: std::io::Write>(r: &mut R, w: &mut W) -> std::io::Result<u64> {
    let mut buf = vec![0u8; BACKUP_BUF];
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 { break; }
        w.write_all(&buf[..n])?;
        total += n as u64;
    }
    Ok(total)
}

// L'ouverture à clé EXPLICITE (ex-`open_db_keyed`) a DÉMÉNAGÉ dans `db_open`. Sauvegarde et restore
// l'appellent par son nom SANS CONTRAT (`open_db_keyed_without_schema_contract`), et c'est délibéré :
// une base ABÎMÉE est exactement celle qu'il faut pouvoir sauvegarder/exporter. Refuser ici
// retirerait l'outil de diagnostic au moment précis où il sert — et la destination d'un backup n'est
// pas une base plume servie.

/// RÉPERTOIRE DE STAGING du plaintext temporaire. Priorité à `PLUME_BACKUP_STAGING_DIR` (lu
/// `env > fichier PLUME_CONFIG`, cf. P8.7-a ; orientez-le vers un volume ÉPHÉMÈRE, HORS du stockage
/// durable/sauvegardé, de sorte qu'un crash ne puisse JAMAIS laisser la DB EN CLAIR sur du stockage
/// persistant) ;
/// sinon repli sur le répertoire de `dest` (comportement historique, rétrocompat CLI/test). Découple
/// l'emplacement du CLEARTEXT (qui DOIT être éphémère) de celui du `.age` chiffré (indifférent).
pub(crate) fn staging_dir(dest: &str) -> std::path::PathBuf {
    let d = reglage_sauvegarde(CLE_BACKUP_STAGING_DIR);
    if !d.is_empty() { return std::path::PathBuf::from(d); }
    std::path::Path::new(dest).parent()
        .filter(|d| !d.as_os_str().is_empty())
        .map(|d| d.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

/// Chemin de plaintext temporaire dans le répertoire de STAGING (`staging_dir` : PLUME_BACKUP_STAGING_DIR
/// si posé — volume éphémère — sinon à côté de `beside`). Unique (pid + horodatage + compteur monotone)
/// -> pas de collision parallèle. Le NOM conserve le marqueur `.plain.tmp.` (cible du balayage/RAII).
pub(crate) fn plain_temp_path(beside: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = staging_dir(beside);
    let name = std::path::Path::new(beside)
        .file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "backup".into());
    dir.join(format!(".{name}.plain.tmp.{}.{}.{n}", std::process::id(), now()))
}

/// DESTINATAIRE age asymétrique (clé PUBLIQUE `age1...`) si `PLUME_BACKUP_AGE_RECIPIENT` est posé.
/// Une clé PUBLIQUE n'est PAS un secret : peut vivre en clair dans l'env/ConfigMap du pod, ou dans
/// `/etc/plume/soc.conf` sur un hôte (P8.7-a : `env > fichier PLUME_CONFIG`). Non posé ->
/// `None` -> repli sur le chiffrement SYMÉTRIQUE par passphrase (= clé SQLCipher) = comportement historique.
pub(crate) fn backup_age_recipient() -> Option<String> {
    Some(reglage_sauvegarde(CLE_BACKUP_AGE_RECIPIENT)).filter(|s| !s.is_empty())
}

/// v134 (#7) — EXIGENCE OPT-IN d'un backup ASYMÉTRIQUE (escrow hors-cluster). `PLUME_BACKUP_REQUIRE_ASYMMETRIC`
/// vrai (1/true/yes/on) -> `backup_compressed` REFUSE de produire un backup symétrique (node-déchiffrable).
/// DÉFAUT OFF -> warn-only (comportement historique préservé pour l'usage symétrique/dev intentionnel).
pub(crate) fn backup_require_asymmetric() -> bool {
    drapeau_sauvegarde(&reglage_sauvegarde(CLE_BACKUP_REQUIRE_ASYMMETRIC))
}

/// Lecture PURE d'un drapeau de sauvegarde (`1/true/yes/on`, insensible à la casse et aux espaces).
/// Extraite pour que les deux drapeaux partagent EXACTEMENT la même grammaire — elle était recopiée.
pub(crate) fn drapeau_sauvegarde(brut: &str) -> bool {
    matches!(brut.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

/// ÉCHAPPATOIRE OPÉRATEUR — `PLUME_BACKUP_FORCE_PLAINTEXT_EXPORT` vrai (1/true/yes/on) force le CHEMIN
/// HISTORIQUE (`sqlcipher_export` -> fichier SQLite EN CLAIR dans le staging, puis zstd+age) au lieu du dump
/// STREAMING. DÉFAUT OFF : le streaming est le défaut (cf. « DÉFAUT, PAS OPT-IN » dans l'en-tête de section B1).
/// Le nom dit le PRIX qu'on repaie en la posant : la base ENTIÈRE est réécrite EN CLAIR sur disque le temps du
/// backup. À ne poser que pour reproduire un incident sur le chemin historique, jamais en régime.
pub(crate) fn backup_force_plaintext_export() -> bool {
    drapeau_sauvegarde(&reglage_sauvegarde(CLE_BACKUP_FORCE_PLAINTEXT_EXPORT))
}

/// v134 (#7) — SIGNAL SOC NON-PURGEABLE : les backups tombent en SYMÉTRIQUE (déchiffrables par le nœud, aucun
/// escrow hors-cluster) car `PLUME_BACKUP_AGE_RECIPIENT` n'est pas configuré. Miroir EXACT du pattern
/// `emit_disk_health`/`emit_ledger_unsigned` : source managée `plume-config`, category=health, origin='daemon'
/// (-> RETENTION_NONPURGE : un opérateur ne peut pas l'effacer), dedup HORAIRE (au plus 1 signal/heure malgré
/// un crashloop de boot). Sévérité 4 (P1 posture). `now_ts` injecté pour la testabilité. Renvoie true si écrit.
pub(crate) fn emit_backup_symmetric_signal(conn: &Connection, now_ts: i64) -> bool {
    let bucket = now_ts / 3600; // dedup HORAIRE (anti-tempête, crashloop de boot inclus)
    let dedup = format!("plume-backup-symmetric-{bucket}");
    let msg = "POSTURE BACKUP DÉGRADÉE : PLUME_BACKUP_AGE_RECIPIENT (clé publique age1...) non configuré -> les \
               backups sont chiffrés SYMÉTRIQUEMENT (passphrase = clé SQLCipher, présente sur le nœud) et donc \
               DÉCHIFFRABLES PAR LE NŒUD : PAS d'escrow hors-cluster. Configurez un destinataire age asymétrique \
               (escrow hors-cluster), ou posez PLUME_BACKUP_REQUIRE_ASYMMETRIC=1 pour refuser ce repli."
        .to_string();
    let fields = json!({ "backup_encryption": "symmetric", "reason": "no-age-recipient", "node_decryptable": true }).to_string();
    let n = store().insert_event(conn, &EventRow {
        ts: now_ts,
        source: "plume-config".into(), // NON-PURGEABLE avec origin='daemon' (RETENTION_NONPURGE)
        category: "health".into(),
        severity: 4,
        message: msg,
        host: Some("plume-daemon".into()),
        src_ip: None, dst_ip: None, url: None,
        dedup: Some(dedup),
        fields: Some(fields),
        engagement_id: String::new(),
        origin: "daemon".into(),
        env_id: None,
    }).unwrap_or(0);
    n > 0
}

/// v135 (#7) — émet le signal SOC de posture backup symétrique DEPUIS LE CHEMIN QUI VIENT D'ÉCRIRE UNE ARCHIVE,
/// et UNIQUEMENT si le backup vient d'être produit SANS destinataire asymétrique (`recipient` None/"" ->
/// node-déchiffrable, pas d'escrow hors-cluster). Remplace le check de boot v134 mal placé dans `server::run`, qui
/// émettait un faux signal « posture dégradée » à chaque restart sans qu'aucun backup ait été produit. Destinataire
/// présent -> aucun signal (posture saine). `now_ts` injecté pour la testabilité. Renvoie true si un signal a été écrit.
///
/// DEUX APPELANTS, UN PAR CHEMIN QUI ÉCRIT UNE ARCHIVE — et c'est une propriété DÉRIVÉE, pas une liste : la garde
/// `toute_ecriture_d_archive_en_production_emet_tous_les_signaux_de_posture` relit les appelants de `backup_compressed`
/// et refuse qu'un chemin de production écrive une archive sans passer ici. (1) La sous-commande `backup`
/// (`main.rs`), sur une connexion ouverte avec la clé de l'environnement. (2) Le cycle NATIF
/// (`server::scheduled_backup_cycle`), celui que `deploy/k3s.yaml` active dans son unique conteneur, après le
/// rename qui PUBLIE l'archive et avec la clé EXPLICITE du cycle (P8.25-a ; avant ce branchement, lu le
/// 2026-08-22, ce chemin produisait des archives déchiffrables par le nœud avec pour seul témoin une ligne sur
/// la sortie d'erreur). Le retrait du check de boot reposait sur « le conteneur principal ne fait jamais de
/// backup » ; ce n'est plus vrai, et le signal suit désormais l'archive au lieu de supposer qui la produit.
pub(crate) fn signal_backup_symmetric_if_needed(conn: &Connection, recipient: Option<&str>, now_ts: i64) -> bool {
    let symmetric_fallback = recipient.map_or(true, |r| r.is_empty());
    symmetric_fallback && emit_backup_symmetric_signal(conn, now_ts)
}

/// IDENTITÉ age PRIVÉE (`AGE-SECRET-KEY-1...`) pour DÉCHIFFRER un backup asymétrique, fournie au
/// moment du DR depuis l'escrow HORS-cluster : fichier (`PLUME_BACKUP_AGE_IDENTITY_FILE`, prioritaire —
/// mount secret) puis valeur directe (`PLUME_BACKUP_AGE_IDENTITY`, DR ad-hoc). Normalement ABSENTE en
/// cluster (c'est tout l'intérêt : une compromission de pod ne donne pas la clé de déchiffrement).
/// P8.7-a — les deux se lisent `env > fichier PLUME_CONFIG` : au DR sur un hôte, l'identité peut donc
/// être déposée dans un `soc.conf` 0640 plutôt que dans l'environnement (lisible via `/proc/<pid>/environ`).
/// Sa VALEUR n'est jamais journalisée, ni ici ni par l'annonce de bascule.
pub(crate) fn backup_age_identity() -> Option<age::x25519::Identity> {
    let p = reglage_sauvegarde(CLE_BACKUP_AGE_IDENTITY_FILE);
    if !p.is_empty() {
        return std::fs::read_to_string(&p).ok().and_then(|s| parse_age_identity_str(&s));
    }
    parse_age_identity_str(&reglage_sauvegarde(CLE_BACKUP_AGE_IDENTITY))
}

/// Extrait et parse la 1re ligne `AGE-SECRET-KEY-...` (ignore les commentaires `# public key:` d'un fichier
/// d'identité age). `None` si aucune ligne d'identité valide.
pub(crate) fn parse_age_identity_str(s: &str) -> Option<age::x25519::Identity> {
    s.lines()
        .map(|l| l.trim())
        .filter(|l| l.starts_with("AGE-SECRET-KEY-"))
        .find_map(|l| l.parse::<age::x25519::Identity>().ok())
}

/// Ce qu'une sauvegarde compressée a réellement produit (log opérateur + assertions de test).
///
/// `plaintext_bytes` porte un nom HISTORIQUE, antérieur au chemin streaming, et il faut le lire pour ce
/// qu'il mesure aujourd'hui : la taille de la CHARGE SÉRIALISÉE avant zstd — la copie SQLite en clair sur
/// le chemin historique (où elle correspond bien à un fichier), le dump typé sur le chemin streaming (où
/// elle ne correspond à AUCUN fichier : rien n'est écrit en clair). Les deux valeurs ne se comparent donc
/// pas d'un chemin à l'autre sans savoir lequel a tourné — d'où le champ suivant.
///
/// `wrote_plaintext_to_disk` répond à la seule question que l'opérateur se pose vraiment : « ce cycle
/// a-t-il posé une copie EN CLAIR de la base sur un disque ? ». C'est lui, pas le nom du champ précédent,
/// qui porte la propriété.
///
/// Les deux tailles sont des `Mesure<u64>` (`P4.1-s`) : celle d'un fichier vient d'un `metadata` qui peut
/// échouer APRÈS que l'archive a été écrite, et un `unwrap_or(0)` à cet endroit publiait « dest=0 o » sur
/// une archive réelle — la grandeur la plus alarmante ET la plus fausse. Une taille qu'on n'a pas pu lire
/// est dite INCONNUE avec sa cause, jamais remplacée par un zéro ; et l'archive, elle, n'est pas retirée
/// pour autant (la rendre en échec ferait supprimer une sauvegarde valide par le cycle natif).
pub(crate) struct BackupStats {
    pub(crate) plaintext_bytes: crate::mesure_environnement::Mesure<u64>,
    pub(crate) dest_bytes: crate::mesure_environnement::Mesure<u64>,
    pub(crate) wrote_plaintext_to_disk: bool,
}

impl BackupStats {
    /// La charge sérialisée, si elle a été mesurée (les assertions de test la lisent ainsi).
    pub(crate) fn charge_octets(&self) -> Option<u64> {
        match self.plaintext_bytes {
            crate::mesure_environnement::Mesure::Lue(n) => Some(n),
            crate::mesure_environnement::Mesure::Illisible { .. } => None,
        }
    }

    /// La taille de l'archive produite, si elle a été lue.
    pub(crate) fn archive_octets(&self) -> Option<u64> {
        match self.dest_bytes {
            crate::mesure_environnement::Mesure::Lue(n) => Some(n),
            crate::mesure_environnement::Mesure::Illisible { .. } => None,
        }
    }

    /// `charge=… o  dest=… o  ratio=…x` pour la ligne opérateur : une taille inconnue est écrite
    /// `INCONNUE (cause)`, et le ratio n'est calculé que sur deux tailles lues.
    pub(crate) fn phrase_des_tailles(&self) -> String {
        use crate::mesure_environnement::Mesure;
        let dit = |m: &Mesure<u64>| match m {
            Mesure::Lue(n) => format!("{n} o"),
            Mesure::Illisible { cause, .. } => format!("INCONNUE ({cause})"),
        };
        let ratio = match (&self.plaintext_bytes, &self.dest_bytes) {
            (Mesure::Lue(p), Mesure::Lue(d)) if *d > 0 => format!("{:.1}x", *p as f64 / *d as f64),
            (Mesure::Lue(_), Mesure::Lue(_)) => "0.0x".to_string(),
            _ => "n/a".to_string(),
        };
        format!("charge={}  dest={}  ratio={ratio}", dit(&self.plaintext_bytes), dit(&self.dest_bytes))
    }
}

/// La taille d'un fichier sur le disque, LUE ou AVOUÉE — jamais zéro faute de savoir.
pub(crate) fn taille_sur_disque(chemin: &std::path::Path) -> crate::mesure_environnement::Mesure<u64> {
    use crate::mesure_environnement::{cause_io, Mesure};
    match std::fs::metadata(chemin) {
        Ok(m) => Mesure::Lue(m.len()),
        Err(e) => Mesure::Illisible { cause: cause_io(&e), detail: format!("{} : {e}", chemin.display()) },
    }
}

/// SAUVEGARDE COMPRESSÉE+CHIFFRÉE — **CHEMIN LEGACY** (repli de B1, cf. `backup_compressed`).
/// Étapes (toutes en RAM bornée) :
///  1. EXPORT plaintext : ouvre `db_path` (clé SQLCipher), `ATTACH <tmp> AS plain KEY ''`
///     (clair), `SELECT sqlcipher_export('plain')` -> DB SQLite EN CLAIR `<tmp_plain>`
///     (snapshot cohérent même si la DB de prod est ouverte ailleurs).
///  2. STREAM : `<tmp_plain>` -> zstd::Encoder -> age(passphrase=key) -> `<dest>` (buffers 1 MiB).
///  3. Le garde RAII efface `<tmp_plain>` (succès comme erreur/panique).
/// Requiert une clé non vide (passphrase age). Renvoie {plaintext_bytes, dest_bytes, wrote_plaintext_to_disk=true}.
/// NB : ce chemin MATÉRIALISE la DB entière EN CLAIR dans un fichier temporaire (~2,4 Gio) — c'est
/// PRÉCISÉMENT ce que B1 (`backup_compressed_stream`) élimine. Il reste comme REPLI pour les schémas
/// que le dump typé B1 ne peut pas représenter fidèlement (FTS contentless/régulière, etc.).
fn backup_compressed_legacy(db_path: &str, dest: &str, key: Option<&str>, recipient: Option<&str>) -> Result<BackupStats, String> {
    let pass = match key {
        Some(k) if !k.is_empty() => k.to_string(),
        _ => return Err("backup --compress : PLUME_DB_KEY requis (passphrase age)".into()),
    };

    // v134 (#7) — GATE FAIL-CLOSED **AVANT tout export plaintext** : si un backup ASYMÉTRIQUE est EXIGÉ
    // (PLUME_BACKUP_REQUIRE_ASYMMETRIC=1) mais qu'aucun destinataire age n'est configuré, REFUSE IMMÉDIATEMENT
    // — n'écris JAMAIS un plaintext temporaire (ni un backup) qu'on va rejeter. DÉFAUT OFF -> warn-only plus bas
    // (comportement historique préservé). `recipient` None/"" = repli symétrique (node-déchiffrable).
    let symmetric_fallback = recipient.map_or(true, |r| r.is_empty());
    if symmetric_fallback && backup_require_asymmetric() {
        return Err("backup REFUSÉ (PLUME_BACKUP_REQUIRE_ASYMMETRIC=1) : aucun PLUME_BACKUP_AGE_RECIPIENT \
                    (clé publique age1...) configuré -> un backup symétrique serait déchiffrable par le nœud \
                    (pas d'escrow hors-cluster). Configurez un destinataire age asymétrique, ou levez \
                    l'exigence pour un backup symétrique de dev.".into());
    }

    // Le BALAYAGE des orphelins vit chez l'appelant (`backup_compressed`) : il doit tourner à CHAQUE backup,
    // y compris quand le streaming réussit et que ce chemin-ci n'est jamais emprunté (sinon un plaintext
    // orphelin d'un crash antérieur ne serait plus JAMAIS réapé). Ici on se contente de créer le staging.
    let _ = std::fs::create_dir_all(staging_dir(dest));

    let tmp_guard = PlaintextTempGuard(plain_temp_path(dest));
    let tmp_plain = tmp_guard.path().to_string_lossy().into_owned();
    let _ = std::fs::remove_file(&tmp_plain);   // ATTACH exige un chemin neuf

    // 1) EXPORT en clair : SQLCipher chiffré (main) -> SQLite clair (attaché). sqlcipher_export
    //    copie schéma + données via le pager SQLite -> RAM bornée (pas de chargement 2 GiB).
    {
        let conn = open_db_keyed_without_schema_contract(db_path, Some(&pass)).map_err(|e| format!("ouverture DB source : {e}"))?;
        // garde-fou : la source doit être lisible AVEC la clé (sinon clé fausse / DB illisible).
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0))
            .map_err(|e| format!("DB source illisible (clé PLUME_DB_KEY incorrecte ?) : {e}"))?;
        crate::db_open::checkpoint_wal_tronque(&conn, "backup");
        let sql = format!(
            "ATTACH DATABASE '{}' AS plain KEY ''; SELECT sqlcipher_export('plain'); DETACH DATABASE plain;",
            tmp_plain.replace('\'', "''"));
        conn.execute_batch(&sql).map_err(|e| format!("export plaintext (sqlcipher_export) : {e}"))?;
    }
    let plaintext_bytes = taille_sur_disque(std::path::Path::new(&tmp_plain));

    // v134 (#7) — LOUD WARN à chaque repli symétrique (backup DÉCHIFFRABLE PAR LE NŒUD : passphrase = clé
    // SQLCipher, présente sur le pod ; PAS d'escrow hors-cluster). Non-cassant (warn-only) : l'exigence
    // fail-closed a déjà été évaluée EN TÊTE (avant l'export plaintext). Le signal SOC NON-PURGEABLE est émis
    // par l'APPELANT, une fois le backup symétrique effectivement produit — ici on n'a pas de conn writer
    // dédiée, et un signal posé avant l'écriture avouerait une posture sur une archive qui n'existe pas encore.
    // Les deux appelants de production l'émettent : la sous-commande `backup` (main.rs) et l'ordonnanceur NATIF
    // (`server::scheduled_backup_cycle`, après le rename qui publie l'archive — P8.25-a). Une garde dérivée des
    // appelants de `backup_compressed` refuse un troisième chemin qui écrirait sans émettre (cf. la note de
    // `signal_backup_symmetric_if_needed`).
    if symmetric_fallback {
        eprintln!(
            "[backup] ATTENTION : PLUME_BACKUP_AGE_RECIPIENT non configuré -> chiffrement SYMÉTRIQUE par \
             passphrase (= clé SQLCipher, présente sur le nœud). Ce backup est DÉCHIFFRABLE PAR LE NŒUD : PAS \
             d'escrow hors-cluster. Configurez une clé publique age (asymétrique, encrypt-only) pour un escrow \
             hors-cluster, ou posez PLUME_BACKUP_REQUIRE_ASYMMETRIC=1 pour refuser ce repli."
        );
    }
    // 2) STREAM : plaintext -> zstd -> age -> dest (chaîne de writers, buffers 1 MiB).
    let _ = std::fs::remove_file(dest);
    let out = std::fs::File::create(dest).map_err(|e| format!("création dest : {e}"))?;
    let out = std::io::BufWriter::with_capacity(BACKUP_BUF, out);
    // CHIFFREMENT : ASYMÉTRIQUE (destinataire public age1..., encrypt-only) si PLUME_BACKUP_AGE_RECIPIENT
    // est posé -> le pod ne détient PAS la clé de déchiffrement (escrow hors-cluster). Sinon SYMÉTRIQUE par
    // passphrase (= clé SQLCipher) à facteur scrypt FIXÉ (cf. section « FACTEUR DE TRAVAIL SCRYPT »).
    let encryptor = backup_encryptor(&pass, recipient)?;
    let age_w = encryptor.wrap_output(out).map_err(|e| format!("age wrap_output : {e}"))?;
    let mut z = zstd::Encoder::new(age_w, BACKUP_ZSTD_LEVEL).map_err(|e| format!("init zstd : {e}"))?;
    {
        let f = std::fs::File::open(&tmp_plain).map_err(|e| format!("ouverture plaintext : {e}"))?;
        let mut r = std::io::BufReader::with_capacity(BACKUP_BUF, f);
        stream_copy(&mut r, &mut z).map_err(|e| format!("flux zstd : {e}"))?;
    }
    let age_w = z.finish().map_err(|e| format!("finalisation zstd : {e}"))?;       // flush frame zstd
    age_w.finish().map_err(|e| format!("finalisation age : {e}"))?;                 // finalise le stream age

    let dest_bytes = taille_sur_disque(std::path::Path::new(dest));
    // tmp_guard est droppé ici -> efface le plaintext temporaire.
    Ok(BackupStats { plaintext_bytes, dest_bytes, wrote_plaintext_to_disk: true })
}

mod dump_restauration; // LA CHARGE : dump typé B1 streaming, dispatch `backup_compressed` (repli legacy), restauration
pub(crate) use dump_restauration::{backup_compressed, restore_compressed};
use dump_restauration::quote_ident; // consommé par `verification` (inventaire) via `use super::*`

mod retention; // RÉTENTION : classification des noms + GFS + plan de purge + helpers purs de l'ordonnanceur natif
// FAÇADE `pub(crate)` — surface consommée par les AUTRES modules du daemon (main, server, sink_s3) sous les chemins
// d'origine `crate::backup::X`. Les primitives de parsing/calendrier ne sont consommées que par les tests -> gatées.
pub(crate) use retention::{backup_keep_recent_plan, backup_prune_plan, fmt_backup_ts, GfsParams};
#[cfg(test)]
pub(crate) use retention::{classify_backup_name, day_key, days_from_civil, parse_backup_ts, week_key, ParsedBackup, BACKUP_TS_LEN};
mod verification; // VÉRIFICATION : en-tête age sans déchiffrer, puis restauration jetable + inventaire du contenu
pub(crate) use verification::{verify_backup, BackupKind};
