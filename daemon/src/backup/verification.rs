//! backup::verification — VÉRIFICATION d'une archive `.age` (sous-commande `backup-verify`, exercice de restauration).
//! Structurelle SANS déchiffrer (`inspect_age_header` -> `BackupKind`, taille plancher), puis COMPLÈTE quand la clé
//! est disponible : restauration vers une base jetable, réouverture avec sa clé et INVENTAIRE du contenu
//! (`inventaire_restaure` -> `ContenuRestaure`, dérivé de `sqlite_master`) — une restauration vide est un échec.
//! Sous-module de `backup` (cf. `backup/mod.rs`), qui ré-exporte sa surface `pub(crate)` sous les chemins d'origine.
use super::*;

// ============================================================================
// VÉRIFICATION STRUCTURELLE d'un backup `.age` (SANS déchiffrer).
// ----------------------------------------------------------------------------
// Le restore-test in-cluster ne peut PAS détenir l'identité PRIVÉE d'un backup asymétrique (la mettre en
// cluster ruinerait le modèle : une compromission de pod la volerait). Pour ces backups, la vérif DÉGRADE
// vers un contrôle STRUCTUREL : en-tête age v1 bien formé + type de stanza destinataire + taille plausible.
// La vérif COMPLÈTE (déchiffrer + ouvrir la DB) devient un DRILL DR périodique avec la clé escrow (runbook).
// ============================================================================

/// Type de chiffrement d'un backup `.age`, déduit du stanza destinataire de l'en-tête (sans déchiffrer).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum BackupKind {
    /// Passphrase (scrypt) = clé SQLCipher -> déchiffrable EN cluster (rétrocompat / pré-cutover asymétrique).
    Symmetric,
    /// x25519 (destinataire public) -> déchiffrement = identité PRIVÉE escrow, HORS cluster.
    Asymmetric,
}

/// Taille plancher plausible d'un `.age` (en-tête v1 + stanza + MAC + nonce STREAM) : rejette un fichier
/// tronqué/vide. Un vrai backup compressé fait des dizaines de Mo ; on reste conservateur (faux négatifs nuls).
pub(crate) const BACKUP_MIN_PLAUSIBLE_BYTES: u64 = 200;

/// Inspecte l'EN-TÊTE age v1 textuel (sans déchiffrer) : valide l'intro `age-encryption.org/v1`, énumère les
/// tags de stanza (`->  <tag> …`), exige une ligne MAC de clôture (`--- <b64>`), et classe le backup
/// (Symmetric=scrypt / Asymmetric=X25519). Erreur si en-tête absent/malformé ou stanza inconnu -> le
/// restore-test échoue bruyamment sur un objet corrompu. Lit au plus 64 KiB (l'en-tête age est petit).
pub(crate) fn inspect_age_header<R: std::io::BufRead>(mut r: R) -> Result<BackupKind, String> {
    let mut head = vec![0u8; 64 * 1024];
    let read = r.read(&mut head).map_err(|e| format!("lecture en-tête : {e}"))?;
    let text = String::from_utf8_lossy(&head[..read]);
    let mut lines = text.lines();
    match lines.next() {
        Some("age-encryption.org/v1") => {}
        _ => return Err("en-tête age absent/invalide (intro age-encryption.org/v1 manquante)".into()),
    }
    let mut kind: Option<BackupKind> = None;
    let mut saw_mac = false;
    for line in lines {
        if let Some(rest) = line.strip_prefix("-> ") {
            let tag = rest.split_whitespace().next().unwrap_or("");
            // age insère des stanzas "grease" à tag ALÉATOIRE (agilité protocolaire) -> on IGNORE tout tag
            // non reconnu ; on ne classe QUE sur les stanzas destinataires réels (scrypt / X25519).
            let k = match tag {
                "scrypt" => Some(BackupKind::Symmetric),
                "X25519" => Some(BackupKind::Asymmetric),
                _ => None,
            };
            if let Some(k) = k {
                match kind {
                    None => kind = Some(k),
                    Some(prev) if prev != k => return Err("stanzas destinataires mixtes (incohérent)".into()),
                    _ => {}
                }
            }
        } else if line.starts_with("--- ") {
            saw_mac = true;
            break; // fin de l'en-tête (ligne MAC)
        }
    }
    let kind = kind.ok_or("aucun stanza destinataire dans l'en-tête age")?;
    if !saw_mac { return Err("en-tête age tronqué (ligne MAC `---` absente dans 64 KiB)".into()); }
    Ok(kind)
}

/// CE QU'UNE RESTAURATION A RÉELLEMENT RENDU (P8.3-a). Compté DANS la base restaurée, après l'avoir
/// rouverte avec sa clé — pas déduit du code de retour de la restauration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContenuRestaure {
    /// Tables lues dans la base restaurée (hors tables internes `sqlite_%`).
    pub(crate) tables: usize,
    /// Lignes relues, toutes tables confondues.
    pub(crate) lignes: i64,
    /// La table la plus peuplée et son compte — la « valeur relue » qui distingue une base restaurée
    /// d'un fichier au bon schéma.
    pub(crate) plus_grande: Option<(String, i64)>,
    /// `meta.schema_version` de la base restaurée quand elle en porte une (une base plume en porte
    /// toujours une ; `verify_backup` sert aussi des bases hors-plume, d'où l'option).
    pub(crate) schema_version: Option<String>,
}

/// INVENTAIRE DE LA BASE RESTAURÉE — la preuve de CONTENU. DÉRIVÉ de `sqlite_master`, jamais d'une
/// liste de tables : une table ajoutée au schéma demain est comptée sans que personne y pense, et une
/// table absente de la restauration se voit par son absence du compte.
///
/// UNE RESTAURATION VIDE EST UN ÉCHEC, PAS UN SUCCÈS. Zéro table, ou zéro ligne, rend `Err` : c'est
/// exactement le cas qu'un contrôle « la restauration n'a pas rendu d'erreur » laisse passer, et c'est
/// le défaut que P8.3-a nomme — un vert qui porte le mot « restore » sans qu'une ligne ait bougé.
pub(crate) fn inventaire_restaure(conn: &Connection) -> Result<ContenuRestaure, String> {
    let mut stmt = conn
        .prepare("SELECT name, COALESCE(sql,'') FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .map_err(|e| format!("inventaire : lecture du schéma restauré : {e}"))?;
    let declarees: Vec<(String, String)> = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .map_err(|e| format!("inventaire : énumération des tables : {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("inventaire : énumération des tables : {e}"))?;
    // LES TABLES QUI PORTENT LES DONNÉES, DÉRIVÉES — pas énumérées. On écarte les tables VIRTUELLES et
    // leurs tables d'ombre (`<vtable>_…`) pour deux raisons distinctes : compter une table virtuelle
    // d'index plein-texte à contenu EXTERNE relit la table de contenu (un second parcours complet pour
    // un chiffre déjà obtenu), et le contenu des tables d'ombre dépend de la façon dont l'index a été
    // construit — reconstruit à la restauration, il ne se compare à rien. Ce qui reste est ce qu'un
    // exploitant appelle « ses données ».
    let virtuelles: Vec<&str> = declarees.iter()
        .filter(|(_, sql)| sql.trim_start().to_ascii_uppercase().starts_with("CREATE VIRTUAL TABLE"))
        .map(|(n, _)| n.as_str())
        .collect();
    let noms: Vec<String> = declarees.iter()
        .filter(|(n, _)| !virtuelles.contains(&n.as_str()) && !virtuelles.iter().any(|v| n.starts_with(&format!("{v}_"))))
        .map(|(n, _)| n.clone())
        .collect();
    let mut lignes = 0i64;
    let mut plus_grande: Option<(String, i64)> = None;
    for nom in &noms {
        // Un COUNT(*) qui échoue est un VERDICT, pas un détail à ignorer : une table shadow FTS5
        // absente ou un index plein-texte non reconstruit se manifeste ICI.
        let n: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {}", quote_ident(nom)), [], |r| r.get(0))
            .map_err(|e| format!("inventaire : table `{nom}` illisible dans la base restaurée : {e}"))?;
        lignes += n;
        if plus_grande.as_ref().map(|(_, m)| n > *m).unwrap_or(true) {
            plus_grande = Some((nom.clone(), n));
        }
    }
    if noms.is_empty() {
        return Err("restauration VIDE : la base restaurée ne porte aucune table de données".into());
    }
    if lignes == 0 {
        return Err(format!(
            "restauration VIDE : {} table(s) créée(s) mais AUCUNE ligne — le schéma seul n'est pas une \
             restauration",
            noms.len()
        ));
    }
    let schema_version = conn
        .query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get::<_, String>(0))
        .ok();
    Ok(ContenuRestaure { tables: noms.len(), lignes, plus_grande, schema_version })
}

/// VÉRIFICATION d'un backup `.age` pour le restore-test. Contrôle STRUCTUREL toujours (en-tête + taille) ;
/// puis vérif COMPLÈTE UNIQUEMENT si l'identité requise est disponible :
///   - Symmetric : clé SQLCipher (`key`) présente -> round-trip complet possible EN cluster (inchangé).
///   - Asymmetric : identité privée présente (PLUME_BACKUP_AGE_IDENTITY[_FILE]) -> round-trip ; SINON DÉGRADE
///     en structurel-seul et LOGue que la vérif complète exige la clé escrow (DRILL DR).
///
/// P8.3-a — CE QUE « COMPLÈTE » VEUT DIRE MAINTENANT. La vérif complète annonçait « déchiffre + ouvre la
/// DB » ; elle restaurait vers une base jetable et ne l'ouvrait JAMAIS. Elle prouvait donc le déchiffrement
/// et l'absence d'erreur de rejeu — pas qu'une ligne était revenue. Elle ROUVRE désormais la base restaurée
/// avec sa clé et en COMPTE le contenu (`inventaire_restaure`), et une restauration vide est un échec.
/// Renvoie `(BackupKind, Option<ContenuRestaure>)` : `None` = dégradé structurel-seul. Ne place JAMAIS
/// l'identité privée en cluster : c'est l'appelant/l'opérateur qui la fournit au moment du DR.
pub(crate) fn verify_backup(src: &str, key: Option<&str>, identity: Option<&age::x25519::Identity>) -> Result<(BackupKind, Option<ContenuRestaure>), String> {
    let meta = std::fs::metadata(src).map_err(|e| format!("backup introuvable {src} : {e}"))?;
    if meta.len() < BACKUP_MIN_PLAUSIBLE_BYTES {
        return Err(format!("backup {src} trop petit ({} o < {} o) — tronqué/vide", meta.len(), BACKUP_MIN_PLAUSIBLE_BYTES));
    }
    let f = std::fs::File::open(src).map_err(|e| format!("ouverture {src} : {e}"))?;
    let kind = inspect_age_header(std::io::BufReader::with_capacity(BACKUP_BUF, f))?;
    // Peut-on déchiffrer EN cluster ?
    let can_full = match kind {
        BackupKind::Symmetric => key.map(|k| !k.is_empty()).unwrap_or(false),
        BackupKind::Asymmetric => identity.is_some(),
    };
    if !can_full {
        eprintln!("[backup-verify] {src} : {kind:?} — vérif STRUCTURELLE OK (en-tête age v1 + stanza {} + taille {} o). \
Vérif COMPLÈTE (déchiffrer+ouvrir la DB) requiert l'identité age PRIVÉE escrow HORS-cluster (DRILL DR) — non tentée.",
            match kind { BackupKind::Symmetric => "scrypt", BackupKind::Asymmetric => "X25519" }, meta.len());
        return Ok((kind, None));
    }
    // Vérif COMPLÈTE : restore vers un dest_db JETABLE dans le staging, PUIS relecture de son contenu.
    // restore_compressed gère son propre plaintext temporaire (RAII) ; on efface ensuite le dest_db chiffré.
    let dest_probe = staging_dir(src)
        .join(format!(".verify.plain.tmp.{}.{}.db", std::process::id(), now()))
        .to_string_lossy().into_owned();
    let r = restore_compressed(src, &dest_probe, key, true, identity).and_then(|_| {
        // La base restaurée est ROUVERTE avec sa clé : c'est cette ouverture, et le comptage qui suit,
        // qui séparent « la restauration n'a pas renvoyé d'erreur » de « des lignes sont revenues ».
        // SANS CONTRAT de schéma, assumé : on vérifie une ARCHIVE, dont le schéma peut être plus ancien
        // que le binaire qui la vérifie — refuser à ce titre transformerait un exercice de restauration
        // réussi en échec, exactement quand il rend le plus service.
        let conn = open_db_keyed_without_schema_contract(&dest_probe, key)
            .map_err(|e| format!("base restaurée ILLISIBLE avec la clé fournie : {e}"))?;
        inventaire_restaure(&conn)
    });
    for ext in ["", "-wal", "-shm"] { let _ = std::fs::remove_file(format!("{dest_probe}{ext}")); }
    r.map(|contenu| (kind, Some(contenu)))
}
