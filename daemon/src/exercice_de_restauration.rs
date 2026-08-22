//! P8.3-a — L'EXERCICE DE RESTAURATION : CE QUI PROUVE QU'UNE SAUVEGARDE A DÉJÀ ÉTÉ REMISE EN SERVICE.
//! ============================================================================================
//! LE DÉFAUT QUE CE MODULE FERME. Une sauvegarde dont on n'a jamais restauré une ligne est une
//! garantie NON ÉPROUVÉE. Le pire n'est pas de ne pas restaurer — c'est de laisser croire que la
//! restauration est couverte parce qu'un contrôle vert porte le mot « restore ». Le contrôle
//! automatisé in-cluster (`plume-daemon backup-verify`) ne PEUT pas restaurer une archive
//! ASYMÉTRIQUE : l'identité privée d'escrow vit hors du cluster, et c'est toute la valeur du mode
//! destinataire — la placer à côté des sauvegardes ne protégerait plus de rien. Sur ce mode-là, il
//! dégrade donc en contrôle STRUCTUREL, et la restauration réelle reste un geste hors ligne.
//!
//! CE QUI MANQUAIT N'ÉTAIT DONC PAS LA RESTAURATION, C'ÉTAIT SA TRACE. Rien, dans le produit, ne
//! disait depuis combien de temps personne n'avait remis une archive en service — ni, surtout, que
//! personne ne l'avait JAMAIS fait. Une absence qui ne se voit pas se déduit, et une déduction ne se
//! fait pas : ce module rend l'absence LISIBLE là où un exploitant regarde déjà (santé par composant,
//! exposition Prometheus, panneau Système), et la fait VIEILLIR.
//!
//! CE QUE L'ATTESTATION EST, ET CE QU'ELLE N'EST PAS. Elle n'est produite que par une vérification
//! COMPLÈTE réussie (`backup::verify_backup` : déchiffrer, rejouer, puis COMPTER les lignes de la
//! base restaurée) — jamais par une déclaration d'intention. Elle porte les faits que seul cet
//! exercice produit : l'archive exercée, sa taille, son mode de chiffrement, le nombre de tables et
//! de lignes effectivement restaurées. Elle NE PROUVE PAS qu'un exploitant malveillant n'a pas
//! recopié à la main une ligne d'attestation : ce n'est pas la menace visée. La menace visée est
//! l'oubli, et un oubli ne se falsifie pas.
//!
//! POURQUOI L'ATTESTATION VOYAGE PAR UNE LIGNE DE TEXTE. L'exercice qui compte — celui du mode
//! destinataire — a lieu sur une machine ISOLÉE, avec l'identité d'escrow, souvent sans réseau vers
//! la production. Une ligne sur la sortie standard traverse cet isolement (copier-coller, clé USB,
//! `ssh`) sans qu'aucune clé n'ait à voyager EN SENS INVERSE. Aucune identité privée n'entre jamais
//! dans le dépôt, dans un test, ni dans l'environnement d'intégration continue.
use crate::*;
use crate::backup::BackupKind;

/// Clé `meta` du dernier exercice enregistré. Dans `meta` et non dans une table dédiée : une seule
/// ligne, lue à chaque calcul de santé, et qui doit survivre à une restauration (elle est donc DANS
/// la base — un exercice attesté sur une base restaurée d'hier reste vrai aujourd'hui).
pub(crate) const CLE_META_EXERCICE: &str = "restore_drill_last";

/// Marqueur de tête de la ligne d'attestation. Versionné : un format futur portera `-2`, et un
/// lecteur qui ne le connaît pas REFUSE au lieu de deviner.
pub(crate) const PREFIXE_ATTESTATION: &str = "PLUME-EXERCICE-RESTAURATION-1";

/// Âge maximal d'un exercice avant qu'il ne soit déclaré périmé, en JOURS. Le runbook de reprise
/// recommande un exercice mensuel : le défaut est 31 jours, c'est-à-dire la même chose écrite en
/// mécanisme. `0` -> suivi DÉSACTIVÉ, et cette désactivation se VOIT (composant `idle` qui nomme la
/// clé) plutôt que de ressembler à un exercice frais.
pub(crate) const CLE_AGE_MAX_JOURS: &str = "PLUME_RESTORE_DRILL_MAX_AGE_DAYS";
pub(crate) const AGE_MAX_JOURS_DEFAUT: i64 = 31;

/// Nom du composant de santé — le même dans `/api/system/health`, dans `plume_component_up` et dans
/// le bundle de diagnostic (une seule chaîne, jamais recopiée).
pub(crate) const COMPOSANT: &str = "restauration";

/// UN EXERCICE DE RESTAURATION RÉUSSI. Chaque champ est un FAIT produit par l'exercice lui-même ;
/// aucun n'est déclaratif.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Exercice {
    /// Instant de l'exercice (unix s) — celui de la machine qui a restauré.
    pub(crate) ts: i64,
    /// BASE-NAME de l'archive exercée (`plume-<TS>.db.age`). Jamais le chemin : un chemin de machine
    /// n'apprend rien à un lecteur et renseigne un attaquant.
    pub(crate) archive: String,
    /// Taille de l'archive exercée (octets).
    pub(crate) archive_octets: u64,
    /// Mode de chiffrement de l'archive exercée. C'est le champ qui empêche un exercice SYMÉTRIQUE
    /// (déchiffrable par le nœud) de tenir lieu d'exercice sur le chemin d'ESCROW.
    pub(crate) chiffrement: BackupKind,
    /// Tables portant des lignes dans la base restaurée.
    pub(crate) tables: usize,
    /// Lignes effectivement relues dans la base restaurée, toutes tables confondues.
    pub(crate) lignes: i64,
}

impl Exercice {
    /// LIGNE D'ATTESTATION : préfixe + un objet JSON sur UNE ligne. Une ligne, parce qu'elle doit
    /// survivre à un copier-coller depuis un terminal et à un `| ssh`.
    pub(crate) fn attestation(&self) -> String {
        format!(
            "{PREFIXE_ATTESTATION} {}",
            json!({
                "ts": self.ts,
                "archive": self.archive,
                "archive_octets": self.archive_octets,
                "chiffrement": mot_du_chiffrement(self.chiffrement),
                "tables": self.tables,
                "lignes": self.lignes,
            })
        )
    }

    /// Lit une attestation dans un TEXTE quelconque : on cherche la ligne au préfixe, on ignore le
    /// reste. C'est ce qui permet `backup-verify … | plume-daemon restore-drill record` sans que la
    /// sortie humaine de la vérification ait à être filtrée.
    ///
    /// REFUSE — et le dit — une attestation qui n'atteste rien : zéro table ou zéro ligne. Une
    /// restauration qui ne rend aucune ligne n'est pas un exercice réussi, quel que soit son code de
    /// sortie.
    pub(crate) fn depuis_texte(txt: &str) -> Result<Exercice, String> {
        let ligne = txt
            .lines()
            .map(str::trim)
            .find_map(|l| l.strip_prefix(PREFIXE_ATTESTATION))
            .ok_or_else(|| format!("aucune ligne d'attestation `{PREFIXE_ATTESTATION} {{…}}` dans l'entrée"))?;
        let v: Value = serde_json::from_str(ligne.trim())
            .map_err(|e| format!("attestation illisible (JSON) : {e}"))?;
        let champ_i64 = |k: &str| -> Result<i64, String> {
            v.get(k).and_then(Value::as_i64).ok_or_else(|| format!("attestation : champ `{k}` absent ou non entier"))
        };
        let archive = v.get("archive").and_then(Value::as_str).unwrap_or("").trim().to_string();
        if archive.is_empty() {
            return Err("attestation : champ `archive` absent ou vide".into());
        }
        let chiffrement = match v.get("chiffrement").and_then(Value::as_str).unwrap_or("") {
            "symmetric" => BackupKind::Symmetric,
            "asymmetric" => BackupKind::Asymmetric,
            autre => return Err(format!("attestation : chiffrement inconnu {autre:?} (symmetric|asymmetric)")),
        };
        let ex = Exercice {
            ts: champ_i64("ts")?,
            archive,
            archive_octets: champ_i64("archive_octets")?.max(0) as u64,
            chiffrement,
            tables: champ_i64("tables")?.max(0) as usize,
            lignes: champ_i64("lignes")?,
        };
        if ex.tables == 0 || ex.lignes <= 0 {
            return Err(format!(
                "attestation REFUSÉE : {} table(s), {} ligne(s) — une restauration qui ne rend aucune \
                 ligne n'atteste rien",
                ex.tables, ex.lignes
            ));
        }
        if ex.ts <= 0 {
            return Err("attestation : horodatage non plausible".into());
        }
        Ok(ex)
    }
}

/// Le mot publié pour un mode de chiffrement — un seul auteur pour l'attestation, le JSON de
/// métriques et les messages.
pub(crate) fn mot_du_chiffrement(k: BackupKind) -> &'static str {
    match k {
        BackupKind::Symmetric => "symmetric",
        BackupKind::Asymmetric => "asymmetric",
    }
}

/// L'ÉTAT DU SUIVI, tel qu'un exploitant doit le lire. Un type, pas un booléen : « jamais » et
/// « périmé » ne se disent pas de la même façon, et « le mode qui compte n'a pas été éprouvé » ne se
/// déduit d'aucun des deux.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Etat {
    /// Suivi désactivé explicitement (`PLUME_RESTORE_DRILL_MAX_AGE_DAYS=0`). Se voit, et nomme la clé.
    NonSuivi,
    /// Aucun exercice enregistré. La restauration n'a jamais été éprouvée sur cette installation.
    Jamais,
    /// Exercice enregistré et plus récent que l'âge maximal.
    Frais { age_s: i64 },
    /// Exercice enregistré mais plus vieux que l'âge maximal.
    Perime { age_s: i64 },
    /// Un exercice a bien eu lieu, mais sur une archive SYMÉTRIQUE alors que l'installation séquestre
    /// en ASYMÉTRIQUE : le chemin qui sera réellement emprunté au sinistre — l'identité d'escrow —
    /// n'a jamais servi. Un vert ici serait le mensonge exact que ce module existe pour empêcher.
    ModeNonEprouve { age_s: i64 },
}

impl Etat {
    /// La couleur du composant. AUCUN état n'est ROUGE, et c'est une décision : le rouge de ce
    /// produit dit « un sous-système est en panne MAINTENANT », alors qu'un exercice manquant est un
    /// défaut de POSTURE. Une garde qui peindrait en rouge toute installation neuve serait débranchée
    /// la première semaine — ce dépôt l'a déjà vécu. Le signal tranchant n'est pas la couleur : c'est
    /// `plume_restore_drill_overdue`, qui vaut 1 dès que l'exercice manque ou a vieilli.
    pub(crate) fn sante(&self) -> &'static str {
        match self {
            Etat::NonSuivi => "idle",
            Etat::Frais { .. } => "green",
            Etat::Jamais | Etat::Perime { .. } | Etat::ModeNonEprouve { .. } => "yellow",
        }
    }

    /// 1 = un exercice de restauration est DÛ (jamais fait, périmé, ou fait sur un autre chemin que
    /// celui du séquestre). C'est la jauge sur laquelle une alerte se câble.
    pub(crate) fn en_retard(&self) -> bool {
        !matches!(self, Etat::Frais { .. } | Etat::NonSuivi)
    }

    /// Le mot d'état publié en JSON (stable, indépendant de la formulation française du détail).
    pub(crate) fn mot(&self) -> &'static str {
        match self {
            Etat::NonSuivi => "non_suivi",
            Etat::Jamais => "jamais",
            Etat::Frais { .. } => "frais",
            Etat::Perime { .. } => "perime",
            Etat::ModeNonEprouve { .. } => "mode_non_eprouve",
        }
    }

    /// Âge de l'exercice quand il y en a un. `None` = jamais, et ce n'est PAS zéro : publier 0
    /// ferait lire « exercice à l'instant » là où il faut lire « aucun exercice ».
    pub(crate) fn age_s(&self) -> Option<i64> {
        match self {
            Etat::Frais { age_s } | Etat::Perime { age_s } | Etat::ModeNonEprouve { age_s } => Some(*age_s),
            Etat::NonSuivi | Etat::Jamais => None,
        }
    }

    /// La phrase que lit l'exploitant. Elle dit ce qui manque et ce qu'il faut faire, jamais « OK ».
    pub(crate) fn detail(&self) -> String {
        match self {
            Etat::NonSuivi => format!(
                "exercice de restauration NON SUIVI ({CLE_AGE_MAX_JOURS}=0) — l'ancienneté du dernier \
                 exercice n'est pas surveillée"),
            Etat::Jamais => format!(
                "AUCUN exercice de restauration enregistré — une sauvegarde jamais restaurée est une \
                 garantie non éprouvée (cf. docs/DR-plume-restore.md, `{PREFIXE_ATTESTATION}`)"),
            Etat::Frais { age_s } => format!("dernier exercice de restauration il y a {}", duree_lisible(*age_s)),
            Etat::Perime { age_s } => format!(
                "dernier exercice de restauration il y a {} — au-delà de l'âge maximal ({CLE_AGE_MAX_JOURS})",
                duree_lisible(*age_s)),
            Etat::ModeNonEprouve { age_s } => format!(
                "dernier exercice il y a {} sur une archive SYMÉTRIQUE, alors que les sauvegardes partent \
                 vers un destinataire age (escrow) : le chemin de reprise réel — l'identité privée hors \
                 cluster — n'a jamais été éprouvé",
                duree_lisible(*age_s)),
        }
    }
}

/// Durée en français, arrondie vers le bas, sans dépendance de formatage de date.
pub(crate) fn duree_lisible(s: i64) -> String {
    let s = s.max(0);
    match s {
        0..=119 => format!("{s} s"),
        120..=7199 => format!("{} min", s / 60),
        7200..=172_799 => format!("{} h", s / 3600),
        _ => format!("{} j", s / 86_400),
    }
}

/// L'ÉTAT, EN FONCTION PURE. Aucune base, aucun environnement, aucune horloge : tout est injecté,
/// donc tout est éprouvable — y compris le vieillissement, qui se prouve en avançant `now_ts` et non
/// en attendant un mois.
///
/// `escrow_asymetrique` = l'installation envoie-t-elle ses sauvegardes vers un destinataire age
/// (donc : la reprise passera par une identité privée hors cluster) ? Si oui, un exercice symétrique
/// ne clôt PAS l'obligation — c'est l'ordre de priorité retenu : le mode d'abord, l'âge ensuite, car
/// un exercice frais sur le mauvais chemin est plus trompeur qu'un exercice ancien sur le bon.
pub(crate) fn etat(
    dernier: Option<&Exercice>,
    escrow_asymetrique: bool,
    now_ts: i64,
    age_max_s: i64,
) -> Etat {
    if age_max_s <= 0 {
        return Etat::NonSuivi;
    }
    let Some(ex) = dernier else { return Etat::Jamais };
    // Horloge reculée / attestation d'une machine en avance : l'âge est borné à 0, jamais négatif.
    let age_s = (now_ts - ex.ts).max(0);
    if escrow_asymetrique && ex.chiffrement == BackupKind::Symmetric {
        return Etat::ModeNonEprouve { age_s };
    }
    if age_s > age_max_s {
        Etat::Perime { age_s }
    } else {
        Etat::Frais { age_s }
    }
}

/// Âge maximal configuré, en SECONDES. Voie unique `env > fichier PLUME_CONFIG > défaut` (P8.7-a) :
/// un exploitant d'hôte qui écrit la clé dans `soc.conf` obtient l'effet annoncé. Une valeur
/// illisible ou négative retombe sur le défaut (jamais un suivi dégénéré en silence).
pub(crate) fn age_max_s() -> i64 {
    let brut = cfg(&load_config(), CLE_AGE_MAX_JOURS, "");
    let jours = brut.trim().parse::<i64>().ok().filter(|&j| j >= 0).unwrap_or(AGE_MAX_JOURS_DEFAUT);
    jours * 86_400
}

/// LECTURE du dernier exercice enregistré. Une ligne `meta` illisible (format futur, corruption) est
/// traitée comme ABSENTE : mieux vaut afficher « jamais » que dater un exercice sur un contenu qu'on
/// ne comprend pas.
pub(crate) fn dernier_exercice(conn: &Connection) -> Option<Exercice> {
    let brut: String = conn
        .query_row("SELECT value FROM meta WHERE key=?1", params![CLE_META_EXERCICE], |r| r.get(0))
        .ok()?;
    Exercice::depuis_texte(&brut).ok()
}

/// ENREGISTREMENT d'un exercice. Deux refus, tous deux mécaniques :
///   1. une attestation DATÉE DANS LE FUTUR (au-delà d'une heure de tolérance d'horloge) est refusée
///      — sans quoi une seule ligne mal formée maintiendrait le suivi au vert pendant des mois ;
///   2. une attestation PLUS ANCIENNE que celle déjà enregistrée est refusée — rejouer une vieille
///      attestation ne doit pas pouvoir faire RECULER la date du dernier exercice.
/// La valeur stockée est la ligne d'attestation elle-même : ce qui est relu est exactement ce qui a
/// été attesté.
pub(crate) fn enregistrer(conn: &Connection, ex: &Exercice, now_ts: i64) -> Result<(), String> {
    const TOLERANCE_HORLOGE_S: i64 = 3600;
    if ex.ts > now_ts + TOLERANCE_HORLOGE_S {
        return Err(format!(
            "attestation REFUSÉE : datée dans le futur ({} s d'avance) — horloge de la machine \
             d'exercice à vérifier",
            ex.ts - now_ts
        ));
    }
    if let Some(p) = dernier_exercice(conn) {
        if ex.ts < p.ts {
            return Err(format!(
                "attestation REFUSÉE : plus ancienne ({} s) que l'exercice déjà enregistré — la date du \
                 dernier exercice ne recule pas",
                p.ts - ex.ts
            ));
        }
    }
    conn.execute(
        "INSERT INTO meta(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![CLE_META_EXERCICE, ex.attestation()],
    )
    .map(|_| ())
    .map_err(|e| format!("enregistrement de l'attestation : {e}"))
}

/// LE COMPOSANT DE SANTÉ, tel qu'il apparaît dans `/api/system/health`, `plume_component_up` et le
/// bundle de diagnostic. Lecture d'UNE ligne `meta` : jamais un scan.
pub(crate) fn composant(conn: &Connection, escrow_asymetrique: bool, now_ts: i64) -> Value {
    let dernier = dernier_exercice(conn);
    let e = etat(dernier.as_ref(), escrow_asymetrique, now_ts, age_max_s());
    json!({
        "component": COMPOSANT,
        "state": e.sante(),
        "detail": e.detail(),
        "drill_state": e.mot(),
        "overdue": e.en_retard(),
        // `null` (et non 0) quand aucun exercice n'a eu lieu : l'absence est l'information.
        "age_s": e.age_s(),
        "last_success_ts": dernier.as_ref().map(|x| x.ts),
        "archive": dernier.as_ref().map(|x| x.archive.clone()),
        "encryption": dernier.as_ref().map(|x| mot_du_chiffrement(x.chiffrement)),
        "rows_restored": dernier.as_ref().map(|x| x.lignes),
        "max_age_s": age_max_s(),
    })
}

/// SIGNAL SOC NON-PURGEABLE quand un exercice est DÛ. Miroir exact d'`emit_backup_symmetric_signal` :
/// source managée `plume-config`, category=health, origin='daemon' (donc non effaçable par un
/// exploitant), dédup QUOTIDIENNE.
///
/// ÉMIS DEPUIS LE CHEMIN DE SAUVEGARDE, PAS DEPUIS LE DÉMON. C'est au moment où une archive vient
/// d'être écrite que la question « et quand l'a-t-on restaurée pour la dernière fois ? » se pose ;
/// une installation qui ne sauvegarde pas n'a rien à éprouver et ne reçoit donc aucun signal. Le même
/// raisonnement que v135, qui avait retiré le signal de posture du boot du conteneur principal parce
/// qu'il n'y sauvegarde jamais rien. `now_ts` injecté pour la testabilité. Renvoie true si écrit.
pub(crate) fn signal_exercice_du(conn: &Connection, e: &Etat, now_ts: i64) -> bool {
    if !e.en_retard() {
        return false;
    }
    let bucket = now_ts / 86_400; // dédup QUOTIDIENNE : au plus un signal par jour, quel qu'en soit le rythme
    let dedup = format!("plume-restore-drill-{}-{bucket}", e.mot());
    let msg = format!(
        "RESTAURATION NON ÉPROUVÉE : {}. Une sauvegarde dont aucune ligne n'a été restaurée est une \
         garantie non vérifiée. Exercice hors ligne : `plume-daemon backup-verify <archive>` avec \
         l'identité d'escrow, puis `plume-daemon restore-drill record` sur ce nœud \
         (cf. docs/DR-plume-restore.md).",
        e.detail()
    );
    let fields = json!({
        "restore_drill": e.mot(),
        "restore_drill_age_s": e.age_s(),
        "restore_drill_max_age_s": age_max_s(),
    })
    .to_string();
    let n = store()
        .insert_event(
            conn,
            &EventRow {
                ts: now_ts,
                source: "plume-config".into(), // NON-PURGEABLE avec origin='daemon' (RETENTION_NONPURGE)
                category: "health".into(),
                severity: 3,
                message: msg,
                host: Some("plume-daemon".into()),
                src_ip: None,
                dst_ip: None,
                url: None,
                dedup: Some(dedup),
                fields: Some(fields),
                engagement_id: String::new(),
                origin: "daemon".into(),
                env_id: None,
            },
        )
        .unwrap_or(0);
    n > 0
}

/// Émet le signal DEPUIS LE VRAI CHEMIN DE SAUVEGARDE, une archive venant d'être produite : lit
/// l'état, l'émet s'il est dû. `escrow_asymetrique` est passé par l'appelant, qui vient justement de
/// choisir le mode de chiffrement de cette archive-là.
///
/// UN APPELANT PAR CHEMIN QUI ÉCRIT UNE ARCHIVE, et c'est une propriété DÉRIVÉE, pas une liste : la
/// garde `toute_ecriture_d_archive_en_production_emet_tous_les_signaux_de_posture` relit les appelants
/// de `backup_compressed` et refuse qu'un chemin de production écrive une archive sans atteindre ce
/// signal. (1) La sous-commande `backup` (`main.rs`). (2) Le cycle NATIF (`server::scheduled_backup_cycle`),
/// après le rename qui PUBLIE l'archive, sur la porte qu'il ouvre déjà pour la posture symétrique
/// (P8.26-a ; avant ce branchement, lu le 2026-08-22, le cycle que `deploy/k3s.yaml` active ne posait
/// jamais la question).
pub(crate) fn signal_apres_sauvegarde(conn: &Connection, escrow_asymetrique: bool, now_ts: i64) -> bool {
    let e = etat(dernier_exercice(conn).as_ref(), escrow_asymetrique, now_ts, age_max_s());
    signal_exercice_du(conn, &e, now_ts)
}
