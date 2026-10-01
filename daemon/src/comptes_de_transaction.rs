//! `P10.27-h`, `P10.26-d`, `P10.27-y` — LES REFUS DE TRANSACTION, COMPTÉS ET SERVIS.
//!
//! LE DÉFAUT, MESURÉ LE 2026-09-29 (lecture de `metrics.rs` : aucune série ni clé JSON sur ces trois faits) : un `BEGIN`
//! refusé, le geste dû d'une passe de fond que la base n'a pas validé, et la transaction orpheline vue par la sonde
//! n'étaient dits QU'AU JOURNAL. Aucune alerte Prometheus ne pouvait se câbler sur un écrivain bloqué par une transaction
//! étrangère (lots gardés au spool, 503), ni sur un engagement dont l'expiration est refusée tour après tour (les
//! révocations écrites des grants et des comptes `eng-cred-*` manquent en silence ; la fenêtre, elle, est revérifiée à
//! chaque usage). Le compte de la sonde existait, mais seuls les témoins le lisaient.
//!
//! LA FORME : des compteurs de PROCESSUS — tous tenants confondus, depuis le démarrage, jamais persistés —, servis par
//! `comptes_de_transaction_json` (objet `transactions` de `/api/system/metrics`) et `poser_les_gestes_de_fond_non_valides`
//! (sous `scheduler`), et exposés sous `/metrics` par `exposition_prom`. Chaque compteur est incrémenté au MÊME endroit
//! que la phrase du journal qui dit le refus (`handlers::transaction_validee`, les balayages d'engagement, les plis de
//! `rollup_hosts`, les semis) : la phrase reste, le compte s'y ajoute — rien n'est tu.
//!
//! POURQUOI UN MODULE À PART : ces compteurs ont d'abord été posés dans `handlers/transaction_validee.rs`, la forme commune
//! des transactions, qu'ils allongeaient de deux cents lignes de métriques. Ils vivent ici avec leur rendu JSON et leur
//! exposition Prometheus : le nommage, le `# HELP` et la cardinalité ont un seul auteur, le module qui TIENT les compteurs
//! (comme `semaphore_interactif`, `attente_serie`, `index_usage`) ; `metrics::gather_prom` ne réécrit rien.
//!
//! CARDINALITÉ : la cause d'un `BEGIN` refusé est un ensemble FERMÉ de trois valeurs ; les journaux sont des littéraux du
//! code (quarante-six comptés le 2026-09-30), ventilés sous un plafond (`BEGIN_REFUSES_PAR_JOURNAL_PLAFOND`, au-delà
//! `metrics::CLE_DES_AUTRES`) parce que le paramètre est un `&str` ; les gestes de fond sont des `&'static str` — fermés
//! par construction.
use crate::*;

/// `P10.27-h` — POURQUOI UN `BEGIN` A ÉTÉ REFUSÉ, lu sur l'écrivain et sur le code du moteur APRÈS le refus, comme la
/// phrase du journal le lit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CauseDuBeginRefuse {
    /// L'écrivain n'était dans aucune transaction et le moteur a rendu « occupé » ou « verrouillé » (`SQLITE_BUSY`,
    /// `SQLITE_LOCKED`) : le verrou d'écriture était tenu ailleurs. Un verrou passe : un nouvel essai peut aboutir.
    Verrou,
    /// L'écrivain n'était dans aucune transaction et le moteur a refusé pour une AUTRE raison qu'un verrou (base en
    /// lecture seule, disque plein, erreur d'E/S, autorisation) : un nouvel essai sera refusé de même tant que la cause
    /// demeure. Ces refus tombaient sous `Verrou` dans la première forme (lot R4), que le `# HELP` décrivait comme un
    /// refus que le passage suivant reprend : une base devenue en lecture seule n'y était pas discernable.
    HorsVerrou,
    /// L'écrivain porte une transaction qui n'est pas celle du geste : il reste BLOQUÉ tant que son geste ne la ferme pas.
    TransactionEtrangere,
}

impl CauseDuBeginRefuse {
    /// L'ensemble fermé, dans l'ordre de `rang` : c'est lui que l'exposition parcourt.
    pub(crate) const TOUTES: [CauseDuBeginRefuse; 3] =
        [CauseDuBeginRefuse::Verrou, CauseDuBeginRefuse::TransactionEtrangere, CauseDuBeginRefuse::HorsVerrou];

    /// La cause d'un `BEGIN` refusé : l'état de l'écrivain d'abord (une transaction pendante bloque, quel que soit le code
    /// rendu), puis le code du moteur (seuls « occupé » et « verrouillé » sont un verrou).
    pub(crate) fn du_refus(conn: &Connection, refus: &rusqlite::Error) -> Self {
        if !conn.is_autocommit() {
            CauseDuBeginRefuse::TransactionEtrangere
        } else if matches!(refus.sqlite_error_code(), Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)) {
            CauseDuBeginRefuse::Verrou
        } else {
            CauseDuBeginRefuse::HorsVerrou
        }
    }

    /// La clé JSON et la valeur de l'étiquette Prometheus `cause`.
    pub(crate) fn etiquette(self) -> &'static str {
        match self {
            CauseDuBeginRefuse::Verrou => "verrou",
            CauseDuBeginRefuse::TransactionEtrangere => "transaction_etrangere",
            CauseDuBeginRefuse::HorsVerrou => "hors_verrou",
        }
    }

    fn rang(self) -> usize {
        match self {
            CauseDuBeginRefuse::Verrou => 0,
            CauseDuBeginRefuse::TransactionEtrangere => 1,
            CauseDuBeginRefuse::HorsVerrou => 2,
        }
    }
}

static BEGIN_REFUSES: [std::sync::atomic::AtomicU64; 3] =
    [std::sync::atomic::AtomicU64::new(0), std::sync::atomic::AtomicU64::new(0), std::sync::atomic::AtomicU64::new(0)];
static BEGIN_REFUSES_PAR_JOURNAL: parking_lot::Mutex<std::collections::BTreeMap<String, [u64; 3]>> =
    parking_lot::Mutex::new(std::collections::BTreeMap::new());
/// Plafond de la ventilation par journal (même modèle que `metrics::CHAMPS_PREEMPTES_PLAFOND`) : au-dessus des
/// quarante-six journaux littéraux du code, pour qu'aucun ne tombe sous `(autres)` en régime.
pub(crate) const BEGIN_REFUSES_PAR_JOURNAL_PLAFOND: usize = 64;

/// `P10.27-h` — COMPTE UN `BEGIN` REFUSÉ SUR L'ÉCRIVAIN, par cause et par journal, et rend la cause. Appelée par
/// `transaction_validee::dire_la_transaction_non_ouverte` (donc par `ouvrir_sa_transaction`,
/// `ouvrir_la_transaction_du_geste`, `ouvrir_le_garde_du_geste`, `jouer_le_geste_garde`, les deux gardes du spool, la
/// purge confirmée et l'attache d'un runbook) et par les sites qui gardent leur propre phrase : `tracer_apres_coup`, les
/// balayages du cycle de vie des engagements, les semis (amorçage, provisionnement d'un tenant).
///
/// HORS DE CE COMPTE, ET POURQUOI : les migrations (`migrate_step`, avant que le démon ne serve, avec leur propre refus) ;
/// l'instantané de lecture de la ventilation (`BEGIN DEFERRED` sur une connexion du pool de LECTURE, pas l'écrivain) ;
/// la sauvegarde et la restauration en flux (connexions privées) ; le scellement du tier froid (`cold_store::writer`,
/// derrière `cold_tier`, éteint par défaut).
pub(crate) fn compter_un_begin_refuse(conn: &Connection, journal: &str, refus: &rusqlite::Error) -> CauseDuBeginRefuse {
    let cause = CauseDuBeginRefuse::du_refus(conn, refus);
    BEGIN_REFUSES[cause.rang()].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    crate::metrics::entree_sous_plafond(&mut BEGIN_REFUSES_PAR_JOURNAL.lock(), journal, BEGIN_REFUSES_PAR_JOURNAL_PLAFOND)[cause.rang()] += 1;
    #[cfg(test)]
    noter_pour_les_temoins(conn, format!("begin refusé {journal} {}", cause.etiquette()));
    cause
}

static GESTES_DE_FOND_NON_VALIDES_TOTAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static GESTES_DE_FOND_NON_VALIDES: parking_lot::Mutex<std::collections::BTreeMap<String, (u64, String)>> =
    parking_lot::Mutex::new(std::collections::BTreeMap::new());

/// `P10.26-d` — COMPTE LE GESTE DÛ D'UNE PASSE DE FOND QUE LA BASE N'A PAS VALIDÉ — `BEGIN`, écriture ou `COMMIT`
/// refusé —, par geste, avec l'étape et la cause du moteur du DERNIER refus (`metrics::consigner_avec_sa_derniere_cause`,
/// la forme des ticks aveugles). Rien n'est écrit, le geste reste dû, le passage suivant le reprend : ce compte est la
/// seule trace hors du journal. La clé est `« journal : geste »`, deux littéraux du code (jamais un identifiant
/// d'engagement ni une valeur de la base) ; la cause est celle du moteur.
///
/// `conn` ne sert qu'à l'instrument des témoins (`noter_pour_les_temoins`, par base) : hors `cfg(test)` il est inerte,
/// comme la clé de `transaction_validee::point_de_course`. Le retirer rendrait les égalités strictes des témoins
/// injugeables sous la suite parallèle (le compteur est de processus).
pub(crate) fn compter_un_geste_de_fond_non_valide(
    conn: &Connection,
    journal: &'static str,
    geste: &'static str,
    etape: &'static str,
    refus: &rusqlite::Error,
) {
    GESTES_DE_FOND_NON_VALIDES_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let cle = format!("{journal} : {geste}");
    crate::metrics::consigner_avec_sa_derniere_cause(&mut GESTES_DE_FOND_NON_VALIDES.lock(), &cle, format!("{etape} : {refus}"));
    #[cfg(test)]
    noter_pour_les_temoins(conn, format!("geste de fond non validé {cle} : {etape}"));
    #[cfg(not(test))]
    let _ = conn;
}

/// `P10.27-h`, `P10.27-y` — L'OBJET `transactions` DE `/api/system/metrics` : les `BEGIN` refusés (total, par cause, par
/// journal et par cause) et les transactions orphelines vues par la sonde (`transaction_validee`, `P10.27-g`).
/// `exposition_prom` en dérive ses séries.
pub(crate) fn comptes_de_transaction_json() -> Value {
    let par_cause: serde_json::Map<String, Value> = CauseDuBeginRefuse::TOUTES
        .iter()
        .map(|c| (c.etiquette().to_string(), json!(BEGIN_REFUSES[c.rang()].load(std::sync::atomic::Ordering::Relaxed))))
        .collect();
    let total: u64 = par_cause.values().filter_map(Value::as_u64).sum();
    let par_journal: serde_json::Map<String, Value> = BEGIN_REFUSES_PAR_JOURNAL
        .lock()
        .iter()
        .map(|(journal, n)| {
            let causes: serde_json::Map<String, Value> =
                CauseDuBeginRefuse::TOUTES.iter().map(|c| (c.etiquette().to_string(), json!(n[c.rang()]))).collect();
            (journal.clone(), Value::Object(causes))
        })
        .collect();
    json!({
        "begin_refuses_total": total,
        "begin_refuses_par_cause": par_cause,
        "begin_refuses_par_journal": par_journal,
        "orphelines_vues_total": crate::handlers::transaction_validee::transactions_ouvertes_hors_de_tout_geste(),
    })
}

/// `P10.26-d` — POSE SOUS `scheduler` le total des gestes de fond non validés et leur ventilation par geste
/// (`{ n, derniere_cause }`), à côté des ticks aveugles (`P10.7-f`) : un tick aveugle n'a pas LU sa liste, un geste non
/// validé l'a lue et n'a pas pu ÉCRIRE.
pub(crate) fn poser_les_gestes_de_fond_non_valides(scheduler: &mut serde_json::Map<String, Value>) {
    scheduler.insert(
        "gestes_de_fond_non_valides_total".into(),
        json!(GESTES_DE_FOND_NON_VALIDES_TOTAL.load(std::sync::atomic::Ordering::Relaxed)),
    );
    let ventilation: serde_json::Map<String, Value> = GESTES_DE_FOND_NON_VALIDES
        .lock()
        .iter()
        .map(|(geste, (n, cause))| (geste.clone(), json!({ "n": n, "derniere_cause": cause })))
        .collect();
    scheduler.insert("gestes_de_fond_non_valides".into(), Value::Object(ventilation));
}

/// Le `# HELP` de `plume_scheduler_gestes_de_fond_non_valides_total` : la documentation d'exploitation de la série.
const AIDE_GESTES_DE_FOND_NON_VALIDES: &str = "Gestes d'écriture DUS d'une passe de fond (balayages du cycle de vie des \
     engagements : activation, expiration ; pli définitif et rattrapage de l'inventaire de flotte) que la base n'a PAS \
     validés — BEGIN, écriture ou COMMIT refusé : rien n'est écrit, le geste reste dû et le passage suivant le reprend ; \
     une hausse continue dit un geste refusé tour après tour (P10.26-d ; ventilation par geste avec l'étape et la \
     dernière cause dans /api/system/metrics scheduler.gestes_de_fond_non_valides)";

/// Le `# HELP` de `plume_transaction_begin_refuses_total`.
const AIDE_BEGIN_REFUSES: &str = "BEGIN refusés sur l'écrivain partagé (routes, spool, passes de fond, gestes \
     d'opérateur) : rien n'est écrit — lot gardé au spool, 503 nommé, refus rendu ou passage repris. cause=verrou : \
     l'écrivain n'était dans aucune transaction et le moteur a rendu « occupé » ou « verrouillé » (verrou d'écriture tenu \
     ailleurs) : il passe, un nouvel essai peut aboutir ; cause=hors_verrou : l'écrivain était libre et le moteur a \
     refusé pour une autre raison (base en lecture seule, disque plein, E/S, autorisation ; la cause exacte est au \
     journal) : un nouvel essai sera refusé de même tant qu'elle demeure — alerter sur toute hausse ; \
     cause=transaction_etrangere : l'écrivain porte la transaction d'un autre geste et reste BLOQUÉ tant qu'elle n'est \
     pas fermée, voir plume_transactions_orphelines_vues_total (P10.27-h ; ventilation par journal et par cause dans \
     /api/system/metrics transactions.begin_refuses_par_journal)";

/// Le `# HELP` de `plume_transactions_orphelines_vues_total`.
const AIDE_ORPHELINES_VUES: &str = "Passages de la sonde (tick de détection, toutes les 20 s et par tenant ; compte de \
     processus, tous tenants confondus) qui ont trouvé l'écrivain dans une transaction OUVERTE hors de tout geste : \
     l'ingestion (lots gardés au spool, 503), le pli des hôtes, le reparse et l'envoi des puits sont BLOQUÉS jusqu'à sa \
     fermeture ou au redémarrage. La sonde ne la ferme pas : tant qu'elle reste ouverte, la série monte à chaque passage \
     — alerter sur toute hausse (P10.27-g, P10.27-y)";

/// `P10.26-d`, `P10.27-h`, `P10.27-y` — L'EXPOSITION PROMETHEUS DES TROIS SÉRIES, rendue ici (nommage, `# HELP`,
/// cardinalité fermée des causes) et DÉRIVÉE de l'objet que `metrics::gather_json` sert (`j`) : la série et la clé JSON
/// ne peuvent pas diverger. Comme `g()` de `gather_prom`, une valeur absente n'est pas imprimée.
pub(crate) fn exposition_prom(j: &Value) -> String {
    let mut o = String::with_capacity(2048);
    let serie = |o: &mut String, nom: &str, aide: &str, ptr: &str| {
        if let Some(v) = j.pointer(ptr) {
            o.push_str(&format!("# HELP {nom} {aide}\n# TYPE {nom} counter\n{nom} {v}\n"));
        }
    };
    serie(&mut o, "plume_scheduler_gestes_de_fond_non_valides_total", AIDE_GESTES_DE_FOND_NON_VALIDES, "/scheduler/gestes_de_fond_non_valides_total");
    o.push_str(&format!(
        "# HELP plume_transaction_begin_refuses_total {AIDE_BEGIN_REFUSES}\n# TYPE plume_transaction_begin_refuses_total counter\n"
    ));
    for cause in CauseDuBeginRefuse::TOUTES {
        if let Some(n) = j.pointer(&format!("/transactions/begin_refuses_par_cause/{}", cause.etiquette())) {
            o.push_str(&format!("plume_transaction_begin_refuses_total{{cause=\"{}\"}} {n}\n", cause.etiquette()));
        }
    }
    serie(&mut o, "plume_transactions_orphelines_vues_total", AIDE_ORPHELINES_VUES, "/transactions/orphelines_vues_total");
    o
}

// TÉMOINS SEULEMENT — LE MÊME COMPTE, PAR BASE. Les compteurs ci-dessus sont de PROCESSUS et la suite tourne en
// parallèle : un témoin qui jugerait leur valeur, même en delta, serait rougi par un autre témoin qui refuse un `BEGIN`
// au même instant. Chaque incrément est donc aussi noté ici sous le chemin de la base de la connexion (`conn.path()`,
// propre à chaque témoin) : les égalités strictes — y compris « rien n'est compté » — deviennent jugeables. Inerte hors
// `cfg(test)`. Les valeurs SERVIES, elles, sont jugées sur des clés propres au témoin (journaux `rtcm-*`, geste
// `rtcm : …`), que personne d'autre ne fait monter.
#[cfg(test)]
static COMPTES_DES_TEMOINS: std::sync::OnceLock<Mutex<HashMap<(String, String), u64>>> = std::sync::OnceLock::new();

#[cfg(test)]
pub(crate) fn noter_pour_les_temoins(conn: &Connection, quoi: String) {
    if let Some(chemin) = conn.path().filter(|c| !c.is_empty()) {
        *COMPTES_DES_TEMOINS.get_or_init(Default::default).lock().entry((chemin.to_string(), quoi)).or_default() += 1;
    }
}

/// TÉMOINS SEULEMENT — combien de fois `quoi` a été compté sur la base de `conn` (`quoi` : « begin refusé <journal>
/// <cause> », « geste de fond non validé <journal> : <geste> : <étape> », « orpheline vue »).
#[cfg(test)]
pub(crate) fn compte_des_temoins(conn: &Connection, quoi: &str) -> u64 {
    let Some(chemin) = conn.path().filter(|c| !c.is_empty()) else { return 0 };
    COMPTES_DES_TEMOINS.get_or_init(Default::default).lock().get(&(chemin.to_string(), quoi.to_string())).copied().unwrap_or(0)
}
