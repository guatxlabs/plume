//! server::sauvegarde_planifiee — L'ORDONNANCEUR DE SAUVEGARDE NATIF du démon (`OPS NATIVE #1`) : ce qui
//! rend `docker run` et le binaire host self-backup sans sidecar ni init-container. Porte le réglage
//! (`PLUME_BACKUP_*`, intervalle 0 = désactivé donc aucun thread), la résolution FAIL-CLOSED d'une
//! destination objet `s3://…` sous la fonctionnalité `s3_backup`, le CYCLE testable
//! `scheduled_backup_cycle` (backup B1 compressé -> fichier temporaire -> rename atomique -> rétention
//! KEEP-N) et le signal de posture que la publication d'une archive doit émettre.
//! Sous-module de `server` (cf. `server/mod.rs`), qui ré-exporte sa surface `pub(crate)` sous les
//! chemins d'origine — `crate::server::spawn_backup_scheduler` et `crate::server::scheduled_backup_cycle`
//! restent valides.
use super::*;

// OPS NATIVE #1 — SCHEDULER DE BACKUP IN-DAEMON. Rend `docker run` / le binaire host self-backup TURNKEY
// (zéro sidecar shell, zéro mc/S3, zéro init-container). Gaté sur `PLUME_BACKUP_INTERVAL` (secondes) :
//   - 0 / absent  -> DÉSACTIVÉ : aucun thread spawné -> comportement byte-identique. (`deploy/k3s.yaml` POSE
//     cette variable dans son unique conteneur — lu le 2026-08-22 ; il n'y a plus de sidecar shell mc/S3.)
//   - > 0         -> boucle : (optionnel backup-on-start) puis toutes les INTERVAL s : backup B1 compressé
//     (`backup_compressed`, MÊME code B1 que la CLI/sidecar -> fidélité round-trip prouvée ; streaming, RAM
//     bornée, 2 Go-safe) vers un fichier TEMP dans DEST puis RENAME ATOMIQUE en `plume-<TS>.db.age` -> rétention
//     KEEP-N (`backup_keep_recent_plan`) -> log. BEST-EFFORT : toute erreur logge + continue (jamais de crash).
// Sink LOCAL par défaut (`PLUME_BACKUP_DEST`, défaut `<dir(db)>/backups`) = le besoin host/Docker (monter un
// volume suffit). `s3://…` : voir le bloc « DESTINATION OBJET » ci-dessous — implémenté SOUS LA FEATURE
// `s3_backup` (OFF par défaut), refusé avec un log clair sans elle. Dans les deux cas, JAMAIS un faux backup
// local silencieux sous un nom de destination distante.
pub(crate) fn spawn_backup_scheduler(conf: HashMap<String, String>, db_path: String) {
        let interval: u64 = cfg(&conf, "PLUME_BACKUP_INTERVAL", "0").parse().unwrap_or(0);
        if interval == 0 { return; } // DÉSACTIVÉ (défaut) -> aucun thread -> byte-identique.

        // DEST par défaut = `<dir(db_path)>/backups` : À CÔTÉ de la base -> déjà sur le volume monté, zéro config.
        let default_dest = std::path::Path::new(&db_path).parent()
            .filter(|d| !d.as_os_str().is_empty())
            .map(|d| d.join("backups").to_string_lossy().into_owned())
            .unwrap_or_else(|| "backups".to_string());
        let dest = cfg(&conf, "PLUME_BACKUP_DEST", &default_dest);
        let keep: usize = cfg(&conf, "PLUME_BACKUP_KEEP", "24").parse().unwrap_or(24).max(1);
        let on_start = cfg(&conf, "PLUME_BACKUP_ON_START", "0") == "1";

        // ─── DESTINATION OBJET (`s3://…`) ────────────────────────────────────────────────────────────
        // SANS la feature `s3_backup` : le module `sink_s3` n'existe pas dans ce binaire, et la branche
        // ci-dessous est celle qui a toujours été là — refus explicite, scheduler désactivé. C'est ce qui
        // rend le profil par défaut inchangé (aucun `s3://` accepté, aucune socket, aucun thread).
        #[cfg(not(feature = "s3_backup"))]
        if dest.starts_with("s3://") {
            eprintln!(
                "[backup-sched] PLUME_BACKUP_DEST={dest} : sink S3 natif-Rust NON COMPILÉ dans ce binaire \
                 (feature `s3_backup`, OFF par défaut) ; utilisez un répertoire LOCAL (volume monté), \
                 recompilez avec `--features s3_backup`, ou passez par un dépôt objet externe \
                 -> scheduler DÉSACTIVÉ.");
            return;
        }
        // AVEC la feature : la destination objet est RÉSOLUE MAINTENANT, au démarrage, pas au premier cycle.
        // Une configuration incomplète arrête l'ordonnanceur ici avec sa cause NOMMÉE — elle ne le laisse
        // JAMAIS écrire en local sous un nom de destination distante, ce qui ferait croire à des sauvegardes
        // hors du nœud alors qu'il n'y en aurait aucune. Les identifiants passent par `cfg_secret` (donc
        // `_FILE`/`_REF` -> `vault:`/`file:`/`env:`) et aucune de leurs valeurs n'entre dans une ligne de
        // journal (cf. le type `Matiere` de `sink_s3`).
        #[cfg(feature = "s3_backup")]
        let sink_objet: Option<std::sync::Arc<sink_s3::CibleS3>> = if dest.starts_with("s3://") {
            match sink_s3::depuis_reglages(&conf, &dest) {
                Ok(c) => {
                    eprintln!("[backup-sched] destination OBJET résolue : {c:?}");
                    Some(std::sync::Arc::new(c))
                }
                Err(e) => {
                    eprintln!(
                        "[backup-sched] PLUME_BACKUP_DEST={dest} : {e} -> scheduler DÉSACTIVÉ (fail-closed ; \
                         aucune sauvegarde locale ne sera écrite sous ce nom).");
                    return;
                }
            }
        } else {
            None
        };
        // ZONE DE PRÉPARATION LOCALE : un dépôt objet envoie un FICHIER, il faut donc l'écrire quelque part
        // d'abord. Ce répertoire porte aussi la rétention KEEP-N locale, qui reste le filet quand le dépôt
        // distant échoue. La rétention DISTANTE, elle, n'est pas implémentée : c'est une règle de cycle de vie
        // du bucket, mécanisme natif de tous les fournisseurs (cf. l'en-tête de `sink_s3`).
        #[cfg(feature = "s3_backup")]
        let dest = if sink_objet.is_some() { cfg(&conf, sink_s3::CLE_S3_STAGING, &default_dest) } else { dest };

        std::thread::spawn(move || {
            eprintln!(
                "[backup-sched] ACTIF : intervalle={interval}s dest={dest} keep={keep} on_start={on_start} \
                 (B1 age(zstd), rename atomique, rétention KEEP-N, best-effort)");
            if let Err(e) = std::fs::create_dir_all(&dest) {
                eprintln!("[backup-sched] création DEST {dest} impossible : {e} — scheduler ABANDONNÉ (best-effort)");
                return;
            }
            std::thread::sleep(Duration::from_secs(90)); // laisse passer le bind + la liveness (comme les autres boucles)
            // UN SEUL point d'appel du cycle, quel que soit le sink -> le chemin local et le chemin objet ne
            // peuvent pas diverger sur la cadence, le démarrage à chaud ou la rétention.
            #[cfg(feature = "s3_backup")]
            let cycle = |db: &str, d: &str, k: usize| match sink_objet.as_deref() {
                Some(cible) => {
                    run_scheduled_backup_objet(db, d, k, cible);
                }
                None => run_scheduled_backup(db, d, k),
            };
            #[cfg(not(feature = "s3_backup"))]
            let cycle = |db: &str, d: &str, k: usize| run_scheduled_backup(db, d, k);
            if on_start { cycle(&db_path, &dest, keep); } // backup-on-start optionnel (comme le sidecar)
            loop {
                std::thread::sleep(Duration::from_secs(interval));
                cycle(&db_path, &dest, keep);
            }
        });
}

/// Un CYCLE du scheduler natif (résout clé+destinataire depuis l'ENV `PLUME_DB_KEY` / `PLUME_BACKUP_AGE_RECIPIENT`,
/// EXACTEMENT comme la CLI/sidecar) puis délègue au cœur testable `scheduled_backup_cycle`.
fn run_scheduled_backup(db_path: &str, dest_dir: &str, keep: usize) {
        let recipient = backup_age_recipient();
        scheduled_backup_cycle(db_path, dest_dir, keep, db_key().as_deref(), recipient.as_deref());
}

/// MÊME cycle, suivi du DÉPÔT sur la destination objet. Trois propriétés, toutes portées par le code et non
/// par cette phrase :
///   1. si le cycle ne PUBLIE rien (backup échoué, rename impossible), il n'y a rien à déposer et on le DIT —
///      on ne dépose surtout pas l'artefact d'un cycle PRÉCÉDENT, ce qui rendrait une ligne verte pour une
///      sauvegarde qui n'a pas été prise ;
///   2. le verdict du dépôt est celui du type `IssueDepot` (déposé et confirmé / refusé / impossible) — cette
///      fonction ne le résume pas, elle l'imprime ;
///   3. l'archive locale n'est PAS supprimée quand le dépôt n'aboutit pas : la rétention KEEP-N locale reste
///      le filet, et un dépôt raté ne coûte pas la sauvegarde.
///
/// REND le nom de l'artefact soumis au dépôt, `None` si ce cycle n'a rien publié (`P4.1-r` : la branche
/// « rien à déposer » rend une valeur et le journal la nomme ; elle ne se contente plus de rendre la main).
#[cfg(feature = "s3_backup")]
fn run_scheduled_backup_objet(db_path: &str, staging: &str, keep: usize, cible: &sink_s3::CibleS3) -> Option<String> {
        let recipient = backup_age_recipient();
        let Some(nom) = scheduled_backup_cycle(db_path, staging, keep, db_key().as_deref(), recipient.as_deref())
        else {
            eprintln!("[backup-sched-objet] aucun artefact publié par ce cycle -> RIEN n'est déposé \
                       (un dépôt annoncé sans sauvegarde prise serait un faux succès)");
            return None;
        };
        let chemin = std::path::Path::new(staging).join(&nom);
        let issue = sink_s3::deposer_fichier(cible, &nom, &chemin, &fmt_backup_ts(now()));
        eprintln!("[backup-sched-objet] {nom} -> {issue}");
        if !issue.est_depose() {
            eprintln!("[backup-sched-objet] l'archive locale {} est CONSERVÉE (rétention KEEP-N) — elle est \
                       la seule copie de ce cycle", chemin.display());
        }
        Some(nom)
}

/// P8.25-a + P8.26-a — CE QU'UNE ARCHIVE PUBLIÉE IMPLIQUE, DIT PAR LE CYCLE NATIF. Deux signaux de posture
/// ont le même moment juste — « une archive vient d'être publiée » — et la même condition d'écriture, une
/// connexion au contrat : (1) la posture SYMÉTRIQUE (`signal_backup_symmetric_if_needed` : destinataire
/// absent -> le nœud déchiffre ses propres archives, dédup horaire) ; (2) l'exercice de restauration DÛ
/// (`exercice_de_restauration::signal_apres_sauvegarde` : jamais éprouvée, périmée ou éprouvée sur un autre
/// chemin que celui du séquestre, dédup quotidienne). Une SEULE porte pour les deux : ouvrir la base deux fois
/// à côté de l'écrivain du démon serait un coût sans contrepartie.
///
/// Le cycle n'a pas de connexion sous la main : il reçoit un chemin et une clé EXPLICITE (`key`, jamais
/// l'environnement — c'est ce qui le rend testable hermétiquement), et `backup_compressed` ouvre et referme la
/// sienne. Les signaux, eux, ÉCRIVENT un événement SOC : ils passent donc par la porte (`PreparedDb`), avec la
/// clé du cycle et non celle de l'env, et avec `busy_timeout` posé en PRÉLUDE parce que ce fil tourne à côté de
/// l'écrivain du démon (le contrat, avant toute lecture, attendrait sinon zéro seconde sur un verrou
/// transitoire). Best-effort DANS LES DEUX SENS, comme dans `main.rs` : un contrat non satisfait ne casse pas
/// l'archive déjà publiée, mais il n'écrit rien non plus — il le DIT. Même sémantique que la sous-commande
/// `backup` : `escrow_asymetrique` est dérivé du destinataire de CETTE archive, pas de l'environnement.
fn signaler_ce_qu_implique_l_archive_publiee(db_path: &str, key: Option<&str>, recipient: Option<&str>) {
        match PreparedDb::open_keyed_with_prelude(db_path, key, |c| { let _ = c.busy_timeout(Duration::from_secs(5)); }) {
            Ok(conn) => {
                let maintenant = now();
                let _ = signal_backup_symmetric_if_needed(&conn, recipient, maintenant);
                let escrow_asymetrique = recipient.is_some_and(|r| !r.is_empty());
                let _ = exercice_de_restauration::signal_apres_sauvegarde(&conn, escrow_asymetrique, maintenant);
            }
            Err(e) => eprintln!("[backup-sched] signaux de posture NON émis (la base n'a pas passé le contrat de schéma : {e})"),
        }
}

/// `P9.4-b` — CE QU'UN CYCLE SANS ARCHIVE IMPLIQUE, DIT PAR LE CYCLE NATIF. JUMEAU EXACT de
/// `signaler_ce_qu_implique_l_archive_publiee`, à l'autre bout du cycle : la branche de SUCCÈS lève des
/// signaux de posture NON PURGEABLES, la branche d'ÉCHEC écrivait UNE ligne sur la sortie d'erreur et
/// rendait la main. Le produit savait donc parler d'une sauvegarde qui a eu lieu, et se taisait quand il
/// n'y en avait jamais eu — alors que `docker-compose.yml` et `deploy/k3s.yaml` ARMENT ce cycle en
/// laissant `PLUME_DB_KEY` vide, ce qui fait REFUSER `backup_compressed` à chaque passage.
///
/// LA PORTE EST LA MÊME, POUR LA MÊME RAISON : le signal ÉCRIT un événement SOC, il passe donc par
/// `PreparedDb`, avec la clé DU CYCLE (jamais celle de l'environnement — c'est ce qui rend le cycle
/// testable hermétiquement) et `busy_timeout` posé en PRÉLUDE, ce fil tournant à côté de l'écrivain du
/// démon. BEST-EFFORT DANS LES DEUX SENS : un contrat non satisfait n'invente pas de signal, il le DIT.
///
/// CE QUE CETTE PORTE NE PEUT PAS FAIRE, ÉCRIT ICI PLUTÔT QUE SOUS-ENTENDU : quand la cause de l'échec
/// est une clé FAUSSE, la base ne s'ouvre pas plus pour le signal que pour la sauvegarde, et il ne reste
/// que la ligne de journal. Ce n'est pas le cas visé : le cas visé est la clé VIDE, où la base est en
/// clair et s'ouvre sans clé — c'est précisément le déploiement conteneur/cluster par défaut.
fn signaler_qu_aucune_archive_n_a_ete_publiee(db_path: &str, key: Option<&str>, etape: &str, cause: &str) {
        match PreparedDb::open_keyed_with_prelude(db_path, key, |c| { let _ = c.busy_timeout(Duration::from_secs(5)); }) {
            Ok(conn) => { let _ = emit_backup_cycle_failed_signal(&conn, etape, cause, now()); }
            Err(e) => eprintln!("[backup-sched] cycle SANS ARCHIVE, et le signal n'a PAS pu être émis (la base n'a pas passé le contrat de schéma : {e}) — le seul témoin de ce cycle est cette ligne"),
        }
}

/// CŒUR d'un cycle du scheduler natif : backup B1 -> rename ATOMIQUE -> rétention KEEP-N. BEST-EFFORT de bout
/// en bout (tout échec logge + retourne ; JAMAIS de panic/crash daemon). Réutilise VERBATIM `backup_compressed`
/// (même code B1 que la CLI et le sidecar -> même fidélité round-trip, même chiffrement age asym/sym) et
/// `backup_keep_recent_plan` (rétention PURE testée). Le fichier TEMP porte un suffixe `.tmp.<pid>` (donc
/// `classify_backup_name`=Unparseable) -> il n'est NI servi NI pruné tant que le rename atomique n'a pas publié
/// le nom canonique `plume-<TS>.db.age` -> zéro backup partiel exposé. `key`/`recipient` passés explicitement
/// (testable hermétiquement, sans dépendance à l'env global).
///
/// REND LE NOM DE L'ARTEFACT PUBLIÉ par ce cycle, `None` si aucun ne l'a été. Ce n'est pas un ornement : un
/// consommateur en aval (le dépôt sur destination objet) doit pouvoir distinguer « ce cycle a produit CET
/// artefact » de « ce cycle n'a rien produit » sans relire le répertoire, où l'artefact d'un cycle PRÉCÉDENT
/// le ferait conclure au succès. Le chemin local ignore cette valeur, et son comportement — journaux
/// compris — est inchangé.
pub(crate) fn scheduled_backup_cycle(db_path: &str, dest_dir: &str, keep: usize, key: Option<&str>, recipient: Option<&str>) -> Option<String> {
        let ts = fmt_backup_ts(now());
        let final_path = format!("{dest_dir}/plume-{ts}.db.age");
        // TEMP dans le MÊME répertoire que la cible finale -> rename ATOMIQUE (même filesystem, jamais cross-device).
        let tmp_path = format!("{dest_dir}/.plume-{ts}.db.age.tmp.{}", std::process::id());
        match backup_compressed(db_path, &tmp_path, key, recipient) {
            Ok(st) => {
                if let Err(e) = std::fs::rename(&tmp_path, &final_path) {
                    eprintln!("[backup-sched] rename {tmp_path} -> {final_path} : {e} (cycle ABANDONNÉ)");
                    let _ = std::fs::remove_file(&tmp_path); // pas de temp orphelin.
                    // P9.4-b — la sauvegarde a été PRODUITE mais jamais PUBLIÉE : rien n'est servi, rien
                    // n'est prunable, ce cycle n'a donc rien laissé. Le dire là où la posture se dit.
                    signaler_qu_aucune_archive_n_a_ete_publiee(
                        db_path, key, CYCLE_SANS_ARCHIVE_PUBLICATION_IMPOSSIBLE,
                        &format!("rename {tmp_path} -> {final_path} : {e}"));
                    return None;
                }
                // P8.25-a + P8.26-a — L'ARCHIVE EST PUBLIÉE (le rename a réussi) : c'est ICI, et pas avant, que
                // ce cycle SAIT qu'une sauvegarde existe. Un `backup_compressed` réussi suivi d'un rename raté
                // n'a rien publié, et la branche ci-dessus sort sans passer ici. Même sémantique que la
                // sous-commande `backup` (`main.rs`) : destinataire absent -> signal SOC de posture non
                // purgeable, dédupliqué à l'heure ; exercice de restauration dû -> signal SOC non purgeable,
                // dédupliqué au jour. Les deux sur UNE porte.
                signaler_ce_qu_implique_l_archive_publiee(db_path, key, recipient);
                eprintln!(
                    "[backup-sched] écrit {final_path}  {}  clair-sur-disque={}",
                    st.phrase_des_tailles(),
                    if st.wrote_plaintext_to_disk { "OUI (chemin historique)" } else { "non" });
            }
            Err(e) => {
                eprintln!("[backup-sched] backup B1 échoué : {e} (best-effort -> on continue)");
                let _ = std::fs::remove_file(&tmp_path); // pas de temp partiel/orphelin.
                // P9.4-b — LE POINT DE SORTIE DU DÉFAUT : sans `PLUME_DB_KEY`, `backup_compressed` refuse
                // dès sa première instruction, et c'est ce que livrent les deux déploiements conteneurisés.
                // « best-effort » qualifie la SUITE du cycle (on ne casse pas le démon), pas le SILENCE.
                signaler_qu_aucune_archive_n_a_ete_publiee(
                    db_path, key, CYCLE_SANS_ARCHIVE_SAUVEGARDE_REFUSEE, &e);
                return None;
            }
        }
        // RÉTENTION KEEP-N : liste DEST, calcule les plus vieux à supprimer (fonction pure), supprime un par un.
        match std::fs::read_dir(dest_dir) {
            Ok(rd) => {
                // Un listing PARTIEL ne vaut pas un listing : une entrée illisible est une sauvegarde que le
                // plan ne verrait pas, et un plan keep-N calculé sur un inventaire tronqué peut supprimer une
                // sauvegarde qu'un inventaire complet aurait gardée. Sur la moindre entrée illisible, la
                // rétention de CE cycle est sautée et dite — ne rien effacer est toujours sûr, effacer sur une
                // connaissance partielle ne l'est jamais (même prudence que le garde-fou clock-skew ci-dessous).
                let mut names: Vec<String> = Vec::new();
                let mut listing_complet = true;
                for entree in rd {
                    match entree {
                        Ok(e) => match e.file_name().into_string() {
                            Ok(n) => names.push(n),
                            Err(brut) => {
                                eprintln!("[backup-sched] rétention : nom non-UTF8 dans {dest_dir} ({brut:?}) -> rétention de ce cycle SAUTÉE");
                                listing_complet = false;
                            }
                        },
                        Err(e) => {
                            eprintln!("[backup-sched] rétention : entrée illisible dans {dest_dir} : {e} -> rétention de ce cycle SAUTÉE");
                            listing_complet = false;
                        }
                    }
                }
                if !listing_complet {
                    return Some(format!("plume-{ts}.db.age"));
                }
                // GARDE-FOU CLOCK-SKEW : ne JAMAIS pruner le backup écrit CE cycle, même si le plan
                // l'inclut (un backup FUTUR-daté déjà présent — NTP reculé / import d'un host à horloge rapide —
                // aurait un TS plus grand -> notre frais aurait le plus petit TS et serait pruné avec un keep bas
                // = perte du snapshot le plus frais). Ce fichier est PUBLIÉ (rename ci-dessus réussi) -> intouchable.
                let just_written = format!("plume-{ts}.db.age");
                for name in &backup_keep_recent_plan(&names, keep) {
                    if *name == just_written {
                        eprintln!("[backup-sched] rétention : skip {name} (backup de ce cycle — garde-fou clock-skew)");
                        continue;
                    }
                    let p = format!("{dest_dir}/{name}");
                    match std::fs::remove_file(&p) {
                        Ok(_) => eprintln!("[backup-sched] rétention : supprimé {p}"),
                        Err(e) => eprintln!("[backup-sched] rétention : suppression {p} échouée : {e} (on continue)"),
                    }
                }
            }
            Err(e) => eprintln!("[backup-sched] rétention : lecture DEST {dest_dir} échouée : {e} (on continue)"),
        }
        // L'artefact a été PUBLIÉ (le rename a réussi) et le garde-fou clock-skew interdit à la rétention de
        // ce cycle de le supprimer -> le nommer ici ne peut pas désigner un fichier absent.
        Some(format!("plume-{ts}.db.age"))
}
