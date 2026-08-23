//! CE QU'ON ATTEND D'UN HÔTE — et qui l'a dit (`P11.10-a`).
//!
//! LE DÉFAUT. La vue de flotte range chaque machine `frais` / `en retard` / `muet` sur le seul âge de
//! son dernier signal (`fleet_status`), et la sonde de parc (`sonde_de_flotte.rs`) lève une alerte pour
//! CHAQUE machine muette. Or trois situations très différentes produisent le même mot : une machine
//! DÉCOMMISSIONNÉE (elle ne reviendra pas, et `host_rollup` n'étant jamais prunée elle reste muette pour
//! toujours), une machine de TEST ou de fixture (son silence est normal), et un AGENT TOMBÉ — seule la
//! dernière est un incident. Le résidu était DÉCLARÉ, en toutes lettres, dans l'en-tête de
//! `sonde_de_flotte.rs` (« une machine DÉCOMMISSIONNÉE reste comptée muette indéfiniment … celui-ci NE se
//! résorbe PAS tout seul ») : il était donc connu, écrit, et sans issue — rien dans la console ne
//! permettait de le combler.
//!
//! LA GRAMMAIRE EST CELLE DE `P11.3-c`, REPRISE ET NON RÉINVENTÉE. Sur les sources, « attendu » a cessé
//! de vouloir dire « livré dans ce dépôt » pour vouloir dire DÉCLARÉ PAR QUELQU'UN : un déclarant nommé,
//! une date, des colonnes PROPRES qui ne bougent que sur leur geste, et un état distinct pour « quelqu'un
//! a dit non » face à « personne n'a rien dit ». Les mêmes quatre exigences valent ici.
//!
//! CE QUI DIFFÈRE, ET POURQUOI — LE DÉFAUT PAR DÉFAUT EST INVERSÉ. Sur une source, ne rien déclarer donne
//! un SIGNAL à examiner (« personne ne l'a déclarée ») et le produit ne perd rien à attendre. Sur un
//! hôte, ne rien déclarer doit continuer d'ALERTER quand la machine se tait : un dead-man's-switch dont le
//! défaut serait « le silence est normal » s'éteindrait sur toute machine que personne n'a pensé à
//! déclarer, c'est-à-dire sur la totalité d'un parc découvert. `NonDeclare` vaut donc « un signal est
//! attendu », exactement comme `SignalAttendu` — et reste néanmoins un état DISTINCT, parce que la console
//! doit pouvoir dire « personne n'a rien dit » là où c'est le cas plutôt que d'inventer une déclaration.
//!
//! LES DÉCLARANTS, ET POURQUOI IL Y EN A DEUX ET NON CINQ. Les sources en ont cinq parce que quatre
//! surfaces du produit DÉRIVENT une déclaration (un fichier livré émet, une sonde observe, le produit
//! agrège, un connecteur est configuré). Pour un hôte, une seule dérivation existe dans ce dépôt :
//! l'ENRÔLEMENT — un jeton d'agent lié à cette machine (`token.host`) est la trace d'un humain qui l'a
//! mise en service et en attend donc des signaux. Aucune autre surface ne sait quoi que ce soit d'une
//! machine : l'inventaire de flotte est DÉCOUVERT, pas déclaré (`sonde_de_flotte.rs` le dit déjà). Le
//! second déclarant est l'exploitant, et c'est le seul qui puisse dire que le silence est normal.
//!
//! CE QUE CES DÉCLARATIONS CHANGENT, ET CE QU'ELLES NE CHANGENT PAS. Contrairement à celles des sources
//! (affichage seul), celles-ci PILOTENT UNE ALERTE : c'est leur raison d'être — « le compte affiché ne
//! mélange pas ce qui alerte et ce qui ne doit pas alerter ». Elles ne touchent ni l'ingestion, ni la
//! collecte, ni les règles, ni la rétention : une machine déclarée attendue-muette continue d'être
//! listée, ses signaux continuent d'être reçus et comptés, et la déclaration se retire d'un geste.
//! Parce qu'une déclaration ÉTEINT une alerte, elle est auditée à la sévérité que ce dépôt réserve à
//! l'étouffement d'un signal (3), et jamais silencieusement.
use crate::*;

/// Plafond du motif écrit par l'exploitant — bornage anti-abus avant écriture (même discipline que
/// `NOTE_MAX` côté sources).
const MOTIF_MAX: usize = 500;

/// Les trois valeurs qu'un humain peut déclarer, telles qu'elles sont STOCKÉES et telles qu'elles sont
/// PUBLIÉES. Enum fermé partagé par la lecture et par l'écriture : une valeur qui passe l'une passe
/// l'autre, et la console pivote sur le jeton du démon au lieu de le réécrire.
pub(crate) const ATTENTES_DECLARABLES: &[&str] = &["signal_attendu", "silence_attendu", "retire"];

/// CE QU'UN HUMAIN A DÉCLARÉ D'UN HÔTE. Le `motif` n'est pas décoratif : « attendu-muet » sans raison
/// écrite est une extinction d'alerte que personne ne saura relire dans six mois.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttenteDeclaree {
    /// Un signal est attendu de cette machine — son silence est un incident. Déclaration EXPLICITE,
    /// distincte de l'absence de déclaration : c'est ainsi qu'on RÉARME une machine qu'on avait tue.
    SignalAttendu,
    /// Le silence de cette machine est normal (fixture, banc de test, machine saisonnière) : elle reste
    /// dans le parc et dans la liste, mais elle n'alerte plus.
    SilenceAttendu,
    /// Cette machine ne fait plus partie du parc (décommissionnée). Elle reste VISIBLE — `host_rollup`
    /// garde sa trace et l'effacer serait perdre l'historique — mais elle sort du dénominateur.
    Retire,
}

impl AttenteDeclaree {
    /// Depuis la colonne `host_settings.attente`. `None` = aucune déclaration lisible (colonne vide, ou
    /// valeur hors de l'enum fermé écrite par une version future) -> la ligne retombe sur le défaut sûr.
    pub(crate) fn depuis_la_colonne(v: Option<&str>) -> Option<Self> {
        match v?.trim() {
            "signal_attendu" => Some(AttenteDeclaree::SignalAttendu),
            "silence_attendu" => Some(AttenteDeclaree::SilenceAttendu),
            "retire" => Some(AttenteDeclaree::Retire),
            _ => None,
        }
    }
    pub(crate) fn jeton(&self) -> &'static str {
        match self {
            AttenteDeclaree::SignalAttendu => "signal_attendu",
            AttenteDeclaree::SilenceAttendu => "silence_attendu",
            AttenteDeclaree::Retire => "retire",
        }
    }
}

/// QUI ATTEND UN SIGNAL DE CETTE MACHINE. Rendu tel quel dans l'inventaire : le lecteur voit d'où vient
/// le verdict au lieu de le deviner. Le premier déclarant est DÉRIVÉ (un jeton d'agent lié à l'hôte), le
/// second est un humain de cette installation — et lui seul porte un nom et une date, parce que lui seul
/// a fait un geste.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RaisonDAttente {
    /// Un jeton d'agent est lié à cette machine (`token.host`) : quelqu'un l'a enrôlée.
    Enrolement { nom: String, cree: Option<i64> },
    /// L'EXPLOITANT de cette installation a déclaré qu'un signal est attendu.
    Exploitant { par: Option<String>, le: Option<i64>, motif: Option<String> },
}

/// LE VERDICT D'UN HÔTE — une seule dérivation, lue par l'inventaire ET par la sonde de parc. Ce n'est
/// pas « depuis quand se tait-elle » (c'est `fleet_status`) mais « son silence est-il attendu, et qui
/// l'a dit ».
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VerdictDHote {
    /// Un signal est attendu, et voici par qui. Le silence ALERTE.
    SignalAttendu(RaisonDAttente),
    /// Quelqu'un a dit que le silence est normal ici. Distinct de « personne n'a rien dit » : ici un
    /// humain a pris la décision, et il la signe.
    SilenceAttendu { par: Option<String>, le: Option<i64>, motif: Option<String> },
    /// Quelqu'un a retiré cette machine du parc. Elle sort du dénominateur ET de l'alerte.
    Retire { par: Option<String>, le: Option<i64>, motif: Option<String> },
    /// Personne : ni un enrôlement, ni un humain. Le silence ALERTE quand même (défaut sûr), mais la
    /// console dit qu'aucune déclaration n'existe au lieu d'en inventer une.
    NonDeclare,
}

impl VerdictDHote {
    /// Le jeton d'API STABLE — la console pivote dessus et ne le réécrit pas (leçon de `P11.3-d` : un
    /// compte que la surface recalcule à sa façon finit par ne plus retrouver celui du démon).
    pub(crate) fn jeton(&self) -> &'static str {
        match self {
            VerdictDHote::SignalAttendu(_) => "signal_attendu",
            VerdictDHote::SilenceAttendu { .. } => "silence_attendu",
            VerdictDHote::Retire { .. } => "retire",
            VerdictDHote::NonDeclare => "non_declare",
        }
    }
    /// LE SILENCE DE CETTE MACHINE EST-IL UN INCIDENT ? L'unique question que la sonde de parc pose.
    /// `NonDeclare` répond OUI : cf. l'en-tête de ce module (le défaut par défaut est inversé).
    pub(crate) fn alerte_si_muet(&self) -> bool {
        !matches!(self, VerdictDHote::SilenceAttendu { .. } | VerdictDHote::Retire { .. })
    }
    /// CETTE MACHINE COMPTE-T-ELLE DANS LE PARC ? Seul un retrait explicite l'en sort — et il reste
    /// visible dans la liste, sans quoi « retirer » voudrait dire « effacer », ce qui n'est pas la même
    /// chose et perdrait un historique.
    pub(crate) fn dans_la_flotte(&self) -> bool {
        !matches!(self, VerdictDHote::Retire { .. })
    }
    /// D'OÙ vient la déclaration, en deux mots — la colonne du tableau.
    pub(crate) fn provenance(&self) -> Option<&'static str> {
        match self {
            VerdictDHote::SignalAttendu(RaisonDAttente::Enrolement { .. }) => Some("un enrôlement"),
            VerdictDHote::SignalAttendu(RaisonDAttente::Exploitant { .. })
            | VerdictDHote::SilenceAttendu { .. }
            | VerdictDHote::Retire { .. } => Some("l'exploitant"),
            VerdictDHote::NonDeclare => None,
        }
    }
    pub(crate) fn libelle(&self) -> Option<String> {
        match self {
            VerdictDHote::SignalAttendu(RaisonDAttente::Enrolement { nom, cree }) => Some(format!(
                "enrôlée sous le jeton « {} »{}",
                if nom.is_empty() { "agent" } else { nom.as_str() },
                cree.map(|t| format!(" (ts {t})")).unwrap_or_default()
            )),
            VerdictDHote::SignalAttendu(RaisonDAttente::Exploitant { par, le, motif }) => {
                Some(format!("un signal est attendu, déclaré par {}", signature(par, le, motif)))
            }
            VerdictDHote::SilenceAttendu { par, le, motif } => {
                Some(format!("silence attendu, déclaré par {}", signature(par, le, motif)))
            }
            VerdictDHote::Retire { par, le, motif } => {
                Some(format!("retirée du parc par {}", signature(par, le, motif)))
            }
            VerdictDHote::NonDeclare => None,
        }
    }
}

/// QUI, QUAND, POURQUOI — écrit une seule fois, pour que les trois libellés ne divergent pas.
fn signature(par: &Option<String>, le: &Option<i64>, motif: &Option<String>) -> String {
    format!(
        "{}{}{}",
        par.clone().filter(|p| !p.is_empty()).unwrap_or_else(|| "un compte non consigné".to_string()),
        le.map(|t| format!(" (ts {t})")).unwrap_or_default(),
        motif.clone().filter(|m| !m.is_empty()).map(|m| format!(" — {m}")).unwrap_or_default()
    )
}

/// CE QUE PORTE LA LIGNE `host_settings` D'UNE MACHINE, tel que la DÉRIVATION du verdict en a besoin.
/// `attente_par`/`attente_le` ne bougent QUE sur la déclaration — c'est la correction MESURÉE de
/// `P11.3-c`, appliquée ici dès la création de la table plutôt que rattrapée. La paire
/// `updated`/`updated_by` de la table (le dernier geste sur la ligne, quel qu'il soit) n'entre PAS dans
/// cette structure : aujourd'hui la déclaration est le seul geste possible, donc la recopier ici
/// donnerait deux champs toujours égaux dont un lecteur ne saurait plus lequel fait foi. Elle reste
/// écrite en base et rendue telle quelle par la liste brute.
#[derive(Debug, Clone, Default)]
pub(crate) struct MarquageHote {
    pub(crate) attente: Option<AttenteDeclaree>,
    pub(crate) motif: Option<String>,
    pub(crate) par: Option<String>,
    pub(crate) le: Option<i64>,
}

/// LA DÉRIVATION DU VERDICT — fonction PURE (aucun accès base : l'appelant fournit les deux faits).
///
/// LE GESTE HUMAIN L'EMPORTE SUR LA CONSTRUCTION, ET C'EST L'INVERSE DES SOURCES. Là-bas, la raison
/// dérivée l'emporte sur le geste qui la confirme, parce qu'elle est plus informative et que le geste ne
/// change rien. Ici le geste peut CONTREDIRE la construction — une machine enrôlée hier est
/// décommissionnée aujourd'hui, et l'enrôlement qui subsiste ne doit pas la ressusciter. Un ordre qui
/// ferait gagner la dérivation rendrait le retrait inopérant sur exactement les machines qui en ont
/// besoin.
pub(crate) fn verdict_dhote(construction: Option<RaisonDAttente>, m: Option<&MarquageHote>) -> VerdictDHote {
    match (m.and_then(|x| x.attente), m) {
        (Some(AttenteDeclaree::Retire), Some(x)) => {
            VerdictDHote::Retire { par: x.par.clone(), le: x.le, motif: x.motif.clone() }
        }
        (Some(AttenteDeclaree::SilenceAttendu), Some(x)) => {
            VerdictDHote::SilenceAttendu { par: x.par.clone(), le: x.le, motif: x.motif.clone() }
        }
        (Some(AttenteDeclaree::SignalAttendu), Some(x)) => VerdictDHote::SignalAttendu(RaisonDAttente::Exploitant {
            par: x.par.clone(),
            le: x.le,
            motif: x.motif.clone(),
        }),
        _ => match construction {
            Some(r) => VerdictDHote::SignalAttendu(r),
            None => VerdictDHote::NonDeclare,
        },
    }
}

/// LA DÉRIVATION PAR CONSTRUCTION, PURE : un jeton d'agent lié à cette machine. L'entrée est celle que
/// `fleet_scan_all` a DÉJÀ lue en une requête pour l'enrôlement — pas une lecture de plus par hôte, ce
/// qui ferait de l'inventaire un coût linéaire en requêtes sur la taille du parc.
pub(crate) fn attente_par_construction(enrol: Option<&(String, Option<i64>, Option<i64>)>) -> Option<RaisonDAttente> {
    enrol.map(|(nom, cree, _)| RaisonDAttente::Enrolement { nom: nom.clone(), cree: *cree })
}

/// LES DÉCLARATIONS DE L'EXPLOITANT, lues en UNE requête (`hôte -> MarquageHote`).
///
/// UNE TABLE ABSENTE REND UNE CARTE VIDE, ET C'EST LE BON SENS D'ÉCHEC. Sans déclaration lisible, chaque
/// machine retombe sur `NonDeclare`, c'est-à-dire sur « le silence alerte » : une lecture impossible
/// produit PLUS d'alertes, jamais moins. L'inverse — retomber sur « silence attendu » — éteindrait le
/// dead-man's-switch du parc sur une erreur de lecture, exactement le défaut que `sonde_de_flotte.rs`
/// ferme de son côté en refusant de résoudre ce qu'il n'a pas pu observer.
pub(crate) fn marquages_dhotes(conn: &Connection) -> HashMap<String, MarquageHote> {
    let mut out: HashMap<String, MarquageHote> = HashMap::new();
    let Ok(mut s) = conn.prepare("SELECT host,attente,attente_motif,attente_par,attente_le FROM host_settings WHERE scope='global'")
    else {
        return out;
    };
    let Ok(rows) = s.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            MarquageHote {
                attente: AttenteDeclaree::depuis_la_colonne(r.get::<_, Option<String>>(1)?.as_deref()),
                motif: r.get::<_, Option<String>>(2)?,
                par: r.get::<_, Option<String>>(3)?,
                le: r.get::<_, Option<i64>>(4)?,
            },
        ))
    }) else {
        return out;
    };
    for (h, m) in rows.flatten() {
        out.insert(h, m);
    }
    out
}

/// LES MACHINES DONT LE SILENCE EST DÉCLARÉ ATTENDU, et celles qui sont RETIRÉES — la seule chose dont la
/// sonde de parc a besoin, sans traîner les libellés. Rend `(silences attendus, retirées)`.
pub(crate) fn hotes_hors_alerte(conn: &Connection) -> (std::collections::HashSet<String>, std::collections::HashSet<String>) {
    let (mut silences, mut retires) = (std::collections::HashSet::new(), std::collections::HashSet::new());
    for (h, m) in marquages_dhotes(conn) {
        match m.attente {
            Some(AttenteDeclaree::SilenceAttendu) => {
                silences.insert(h);
            }
            Some(AttenteDeclaree::Retire) => {
                retires.insert(h);
            }
            _ => {}
        }
    }
    (silences, retires)
}

/// GET /api/hosts/settings -> liste brute `host_settings`. Lecture : tout rôle (rien ici n'est secret —
/// l'inventaire de flotte rend déjà ces colonnes), même règle que `/api/sources/settings`.
pub(crate) async fn host_settings_get(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {
    crate::req_conn!(st, au, conn);
    let mut stmt = match conn.prepare(
        "SELECT host,attente,attente_motif,attente_par,attente_le,updated,updated_by FROM host_settings \
         WHERE scope='global' ORDER BY host",
    ) {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("host_settings indisponible: {e}")).into_response(),
    };
    let settings: Vec<Value> = stmt
        .query_map([], |r| {
            Ok(json!({
                "host": r.get::<_, String>(0)?,
                "attente": r.get::<_, Option<String>>(1)?,
                "attente_motif": r.get::<_, Option<String>>(2)?,
                // La provenance PROPRE de la déclaration — jamais le dernier geste de la ligne.
                "attente_par": r.get::<_, Option<String>>(3)?,
                "attente_le": r.get::<_, Option<i64>>(4)?,
                "updated": r.get::<_, Option<i64>>(5)?,
                "updated_by": r.get::<_, Option<String>>(6)?,
            }))
        })
        .map(|it| it.flatten().collect())
        .unwrap_or_default();
    Json(json!({ "ok": true, "settings": settings })).into_response()
}

/// POST|PUT /api/hosts/settings {host, action, value?, motif?} -> LA DÉCLARATION D'ATTENTE d'un hôte.
/// Enum d'actions FERMÉ : `set_attente` (value ∈ `ATTENTES_DECLARABLES`) | `clear`. EDITOR+ (déclarer une
/// machine de son propre parc est un geste éditorial, comme déclarer une source) + double-audit
/// transactionnel fail-closed.
///
/// LA SÉVÉRITÉ DIT CE QUE LE GESTE FAIT. Déclarer « silence attendu » ou « retiré » ÉTEINT le
/// dead-man's-switch de parc sur cette machine : c'est un étouffement de signal, audité à 3 — la même
/// sévérité que `set_expected(true)` sur une source que rien ne déclarait. Réarmer ou effacer la
/// déclaration REND la couverture : 2. Le motif est EXIGÉ sur les deux gestes qui éteignent — une
/// extinction d'alerte sans raison écrite est illisible six mois plus tard, et le chemin est FERMÉ
/// (400) plutôt que drapeauté.
///
/// CE QUI N'EST PAS TOUCHÉ : l'ingestion, la collecte, les règles, la rétention. Une machine déclarée
/// attendue-muette reste listée, ses signaux restent reçus et comptés, et le geste se retire.
pub(crate) async fn host_settings_put(State(st): State<AppState>, Extension(au): Extension<AuthUser>, Json(b): Json<Value>) -> Response {
    if let Err(r) = require_editor(&au) {
        return r;
    }
    let host = b.trimmed("host");
    if host.is_empty() {
        return (StatusCode::BAD_REQUEST, "champ 'host' requis").into_response();
    }
    if host.chars().count() > 253 {
        return (StatusCode::BAD_REQUEST, "hôte trop long (max 253)").into_response();
    }
    let action = b.str_field("action");
    if !matches!(action, "set_attente" | "clear") {
        return (StatusCode::BAD_REQUEST, "action inconnue (enum fermé)").into_response();
    }
    // VALIDATION ENTIÈRE AVANT LA TRANSACTION (même posture que `source_settings_put`) : une écriture
    // acceptée puis ignorée est la famille de défauts que cette campagne poursuit.
    let motif: String = b.get("motif").and_then(|x| x.as_str()).unwrap_or("").trim().chars().take(MOTIF_MAX).collect();
    let attente: Option<AttenteDeclaree> = if action == "set_attente" {
        let v = b.trimmed("value");
        let Some(a) = AttenteDeclaree::depuis_la_colonne(Some(v.as_str())) else {
            return (
                StatusCode::BAD_REQUEST,
                format!("attente inconnue (enum fermé : {})", ATTENTES_DECLARABLES.join(", ")),
            )
                .into_response();
        };
        // Éteindre une alerte sans dire pourquoi : refusé. Le chemin est fermé, pas drapeauté.
        if matches!(a, AttenteDeclaree::SilenceAttendu | AttenteDeclaree::Retire) && motif.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                "un motif est requis : déclarer le silence attendu ou retirer une machine éteint l'alerte « hôtes muets » sur elle",
            )
                .into_response();
        }
        Some(a)
    } else {
        None
    };
    crate::req_conn!(st, au, conn);
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "verrou base indisponible").into_response();
    }
    let outcome: rusqlite::Result<()> = (|| {
        let ts = now();
        let (human, sev): (String, i64) = match attente {
            None => {
                conn.execute("DELETE FROM host_settings WHERE scope='global' AND host=?1", params![host])?;
                ("déclaration retirée (clear) — la machine reprend le défaut : son silence alerte".to_string(), 2)
            }
            Some(a) => {
                conn.execute(
                    "INSERT INTO host_settings(scope,host,attente,attente_motif,attente_par,attente_le,updated,updated_by) \
                     VALUES('global',?1,?2,?3,?4,?5,?5,?4) \
                     ON CONFLICT(scope,host) DO UPDATE SET attente=?2,attente_motif=?3,attente_par=?4,attente_le=?5,updated=?5,updated_by=?4",
                    params![host, a.jeton(), motif, au.name.as_str(), ts],
                )?;
                let human = match a {
                    AttenteDeclaree::SignalAttendu => format!("un signal est attendu de « {host} » (le silence alerte de nouveau)"),
                    AttenteDeclaree::SilenceAttendu => format!("silence déclaré ATTENDU sur « {host} » : l'alerte « hôtes muets » ne la compte plus — {motif}"),
                    AttenteDeclaree::Retire => format!("« {host} » RETIRÉE du parc : elle sort du dénominateur et de l'alerte — {motif}"),
                };
                // Étouffer un signal se dit fort (3) ; le rendre se dit normalement (2).
                let sev = if matches!(a, AttenteDeclaree::SignalAttendu) { 2 } else { 3 };
                (human, sev)
            }
        };
        audit_config_change(
            &conn,
            "host.settings",
            &format!("{host}: {human} par {}", au.name),
            sev,
            &format!("hôte {host}: {human} par {}", au.name),
            &json!({ "host": host, "action": action, "actor": au.name }).to_string(),
        )?;
        Ok(())
    })();
    match outcome {
        Ok(()) => {
            let _ = conn.execute_batch("COMMIT");
            // La flotte est servie en SWR : sans invalidation, la déclaration ne se verrait qu'au bout du
            // TTL et l'exploitant croirait son geste perdu.
            fleet_map().lock().remove(req_db_path(&st, &au).as_str());
            (StatusCode::OK, Json(json!({ "ok": true }))).into_response()
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK"); // fail-closed : rien de persisté sans audit
            (StatusCode::INTERNAL_SERVER_ERROR, format!("échec transaction audit (aucune modification appliquée): {e}")).into_response()
        }
    }
}
