//! `P10.22-y`, `P10.22-z` — LE FREIN DU SECOND FACTEUR, PAR COMPTE, DURABLE ET VU DU SIEM.
//!
//! Extrait de `idp.rs` (où `P10.22-m` l'avait posé en mémoire du processus), parce que son état change de nature :
//! il vit désormais dans la BASE, et les trois routes qui jugent un code (`login_mfa_post`, `mfa_disable`,
//! `mfa_verify`) le traversent par UNE forme — réserver l'essai, examiner, puis garder, rendre ou effacer.
//!
//! LE DÉFAUT, MESURÉ LE 2026-09-28 SUR LA FORME D'AVANT (témoin `fdsf_`, redémarrage simulé par un second état sur le
//! MÊME fichier sous un chemin écrit autrement — la clé de l'état de processus d'avant était le chemin écrit, un
//! processus neuf ne la connaît pas davantage) : dix codes faux freinaient le compte (le onzième rendait 429) ;
//! après le « redémarrage », DIX codes faux de plus étaient EXAMINÉS (401), puis le frein se reposait. Chaque
//! redémarrage — ou chaque réplique qui ne partage pas la mémoire — rouvrait une fenêtre entière de devinette : le
//! frein ne bornait plus les essais par compte, seulement les essais par vie de processus.
//!
//! LA DÉCISION, ÉCRITE : AUCUNE MIGRATION. L'état est une ligne de la table `setting` (créée par v65, présente dans
//! toute base à jour), portée `frein.second_facteur`, clé = le nom du compte, valeur = un objet JSON
//! `{consecutifs, freine_jusqu_a, dernier}` (secondes unix). Aucune colonne, aucune table, aucune version de schéma ne
//! change : rien n'est une porte à sens unique, et une base rendue à un binaire d'avant garde des lignes que celui-ci
//! ne lit pas (il n'en lit aucune de cette portée — toutes ses lectures de `setting` filtrent `scope='global'`).
//! Pourquoi `setting` et pas une colonne de `user_mfa` : la colonne était une migration ; `user_mfa` n'a de ligne que
//! pour un compte enrôlé, alors que l'état doit survivre à un réenrôlement ; et la ligne `setting` se retire dans la
//! transaction même qui supprime le compte (`oublier_dans_la_transaction`). Ce que la portée coûte : `setting` a été
//! écrite pour des réglages ; aucune route ne liste une portée autre que `global`, donc rien de ceci n'est servi.
//!
//! L'ESSAI EST COMPTÉ AVANT D'ÊTRE EXAMINÉ, ET IL N'EST EXAMINÉ QUE S'IL EST COMPTÉ. `reserver_un_essai` lit l'état,
//! refuse un compte freiné, et ÉCRIT l'échec possible — dans sa propre transaction, validée — AVANT que le code soit
//! jugé. Une écriture refusée rend un 503 nommé SANS examen : compter après coup aurait laissé, sur une base qui ne
//! prend plus l'écriture du frein, un oracle 401/200 sans borne. Ensuite : code faux -> l'échec RESTE (et l'appelant
//! le trace) ; code juste accepté -> `remettre_a_zero` ; refus nommé qui ne juge pas le code (liste illisible, pas
//! non consommé, enrôlement changé, écriture refusée) -> `rendre_l_essai`, qui retire l'échec réservé. Un `rendre`
//! ou une remise à zéro refusés laissent un échec DE TROP — le sens qui freine, jamais celui qui ouvre — et le disent.
//!
//! L'HORLOGE EST CELLE DU MUR (`now()`), pas l'horloge monotone : c'est ce qui se persiste. Un saut d'horloge en
//! arrière prolonge un frein (sens sûr) ; un saut en avant l'écourte (au plus `lock_max_s`, écrit ici). Elle rend aussi
//! la levée éprouvable : un témoin recule l'état stocké au lieu d'attendre (`faire_passer_le_temps`).
//!
//! CE QUI NE CHANGE PAS : les réglages (`lock_threshold`, `lock_base_s`, `lock_max_s` ; seuil 0 = frein coupé, rien
//! n'est lu ni écrit), la progression exponentielle bornée, l'oubli après un jour sans échec, la clé (le compte,
//! jamais l'adresse ni le ticket), et la règle de `P10.22-m` : sans le premier facteur (ticket signé ou session), on
//! ne l'atteint pas.
use crate::*;
use crate::handlers::transaction_validee::{jouer_le_geste_garde, IssueDuGesteGarde};
use rusqlite::OptionalExtension;

/// La portée des lignes `setting` qui portent l'état du frein — jamais `global`, donc jamais servie.
pub(crate) const PORTEE_DU_FREIN_DU_SECOND_FACTEUR: &str = "frein.second_facteur";

/// Un jour sans échec efface le compte des échecs consécutifs (`P10.22-m`).
const MEMOIRE_DES_ECHECS_S: i64 = 24 * 3600;

/// `P10.22-y` — l'écriture qui compte l'essai n'a pas eu lieu : le code n'est PAS examiné.
pub(crate) const CAUSE_ESSAI_DU_SECOND_FACTEUR_NON_COMPTE: &str = "SECOND FACTEUR NON EXAMINÉ : la base n'a pas \
     pris l'écriture qui compte cet essai au frein du compte (ou n'a pas pu relire ce frein). Un code n'est examiné \
     que si son échec possible est déjà compté : celui-ci n'est ni accepté ni refusé, aucune session n'est posée, \
     rien n'est modifié. Réessayez.";

/// L'état durable du frein d'un compte. `freine_jusqu_a` = 0 : pas de délai posé.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct EtatDuFrein {
    consecutifs: u32,
    freine_jusqu_a: i64,
    dernier: i64,
}

impl EtatDuFrein {
    fn en_json(&self) -> String {
        json!({ "consecutifs": self.consecutifs, "freine_jusqu_a": self.freine_jusqu_a, "dernier": self.dernier }).to_string()
    }

    /// Les trois champs, entiers, présents : sinon la valeur est CORROMPUE (jamais lue comme « zéro échec »).
    fn depuis_json(brut: &str) -> Result<Self, String> {
        let v: Value = serde_json::from_str(brut).map_err(|e| e.to_string())?;
        let entier = |champ: &str| v.get(champ).and_then(Value::as_i64).ok_or_else(|| format!("champ `{champ}` absent ou non entier"));
        Ok(Self {
            consecutifs: u32::try_from(entier("consecutifs")?).map_err(|e| e.to_string())?,
            freine_jusqu_a: entier("freine_jusqu_a")?,
            dernier: entier("dernier")?,
        })
    }
}

/// L'essai RÉSERVÉ : ce que l'appelant garde (code faux), rend (refus nommé) ou efface (code juste).
#[must_use]
#[derive(Debug, Clone, Copy)]
pub(crate) struct EssaiReserve {
    /// `false` quand le frein est coupé (seuil 0) : rien n'a été écrit, rien n'est à rendre.
    ecrit: bool,
    /// Les échecs consécutifs comptés, CET essai compris.
    pub(crate) consecutifs: u32,
    /// `Some(délai)` quand CET essai, s'il échoue, pose le frein (le seuil est atteint).
    pub(crate) arme_pour_s: Option<u64>,
}

/// Pourquoi un essai n'est pas réservé — donc pas examiné.
#[derive(Debug)]
pub(crate) enum EssaiRefuse {
    /// Le compte est freiné : secondes restantes (en-tête Retry-After).
    Freine(u64),
    /// L'état n'a pas été relu ou l'échec n'a pas été écrit : 503 nommé, rien d'examiné.
    NonCompte(String),
}

impl EssaiRefuse {
    /// La réponse de la route. Le 429 reprend la cause de `P10.22-m`, telle quelle.
    pub(crate) fn servir(self, user: &str) -> Response {
        match self {
            EssaiRefuse::Freine(attente) => refus_du_frein_du_second_facteur(attente),
            EssaiRefuse::NonCompte(cause) => {
                eprintln!("[mfa] WARN essai du second facteur de '{user}' NON compté, code non examiné : {cause}");
                err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_ESSAI_DU_SECOND_FACTEUR_NON_COMPTE)
            }
        }
    }
}

/// Le 429 du frein (cause de `P10.22-m`, Retry-After).
pub(crate) fn refus_du_frein_du_second_facteur(attente: u64) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, attente.to_string())],
        Json(json!({ "error": crate::handlers::idp::CAUSE_SECOND_FACTEUR_FREINE })),
    )
        .into_response()
}

/// TROIS issues : `Ok(None)` aucune ligne (compte neuf au frein), `Ok(Some)`, `Err` lecture refusée OU valeur corrompue
/// — jamais lue comme « aucun échec », qui rouvrirait la fenêtre.
fn lire_l_etat(conn: &Connection, user: &str) -> Result<Option<EtatDuFrein>, String> {
    let brut: Option<String> = conn
        .query_row(
            "SELECT value FROM setting WHERE scope=?1 AND key=?2",
            params![PORTEE_DU_FREIN_DU_SECOND_FACTEUR, user],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| format!("frein non relu : {e}"))?;
    brut.map(|v| EtatDuFrein::depuis_json(&v).map_err(|e| format!("frein corrompu : {e}"))).transpose()
}

fn ecrire_l_etat(conn: &Connection, user: &str, etat: &EtatDuFrein) -> Result<(), String> {
    let valeur = etat.en_json();
    match conn.execute(
        "INSERT INTO setting(scope,key,value,updated,updated_by) VALUES(?1,?2,?3,?4,'plume-daemon') \
         ON CONFLICT(scope,key) DO UPDATE SET value=excluded.value, updated=excluded.updated, updated_by=excluded.updated_by",
        params![PORTEE_DU_FREIN_DU_SECOND_FACTEUR, user, valeur, now()],
    ) {
        Ok(1) => Ok(()),
        Ok(n) => Err(format!("{n} ligne(s) écrite(s) au lieu d'une")),
        Err(e) => Err(e.to_string()),
    }
}

/// `P10.22-y` — RÉSERVE UN ESSAI : refuse un compte freiné, sinon COMPTE l'échec possible, dans une transaction
/// VALIDÉE avant que le code soit examiné (voir l'en-tête). `conn` est la connexion d'écriture, en autocommit.
pub(crate) fn reserver_un_essai(st: &AppState, conn: &Connection, user: &str) -> Result<EssaiReserve, EssaiRefuse> {
    if st.lock_threshold == 0 {
        return Ok(EssaiReserve { ecrit: false, consecutifs: 0, arme_pour_s: None });
    }
    let issue = jouer_le_geste_garde(conn, "mfa", &format!("réservation d'un essai du second facteur de '{user}'"), |c| {
        let maintenant = now();
        let mut etat = lire_l_etat(c, user).map_err(EssaiRefuse::NonCompte)?.unwrap_or_default();
        if etat.freine_jusqu_a > maintenant {
            return Err(EssaiRefuse::Freine((etat.freine_jusqu_a - maintenant) as u64));
        }
        if maintenant - etat.dernier > MEMOIRE_DES_ECHECS_S {
            etat = EtatDuFrein::default();
        }
        etat.consecutifs = etat.consecutifs.saturating_add(1);
        etat.dernier = maintenant;
        let mut arme_pour_s = None;
        if etat.consecutifs >= st.lock_threshold {
            // même progression que le verrou par couple : base * 2^(échecs au-delà du seuil), plafonnée.
            let au_dela = (etat.consecutifs - st.lock_threshold).min(20);
            let secondes = st.lock_base_s.saturating_mul(1u64 << au_dela).min(st.lock_max_s).max(1);
            etat.freine_jusqu_a = maintenant.saturating_add(secondes as i64);
            arme_pour_s = Some(secondes);
        }
        ecrire_l_etat(c, user, &etat).map_err(EssaiRefuse::NonCompte)?;
        Ok(EssaiReserve { ecrit: true, consecutifs: etat.consecutifs, arme_pour_s })
    });
    match issue {
        IssueDuGesteGarde::Valide(essai) => Ok(essai),
        IssueDuGesteGarde::Refuse(refus) => Err(refus),
        IssueDuGesteGarde::NonOuvert(e) | IssueDuGesteGarde::NonValide(e) => Err(EssaiRefuse::NonCompte(e.to_string())),
    }
}

/// `P10.22-y` — REND l'essai réservé : le code n'a pas été jugé (refus nommé). Retire UN échec ; sous le seuil, le délai
/// posé par cet essai tombe avec lui. Refusé, le compte garde un échec de trop (sens qui freine), et c'est dit.
pub(crate) fn rendre_l_essai(st: &AppState, conn: &Connection, user: &str, essai: EssaiReserve) {
    if !essai.ecrit {
        return;
    }
    let issue = jouer_le_geste_garde(conn, "mfa", &format!("retour d'un essai du second facteur de '{user}'"), |c| {
        let Some(mut etat) = lire_l_etat(c, user)? else { return Ok(()) };
        etat.consecutifs = etat.consecutifs.saturating_sub(1);
        if etat.consecutifs < st.lock_threshold {
            etat.freine_jusqu_a = 0;
        }
        if etat.consecutifs == 0 {
            return oublier_dans_la_transaction(c, user).map(|_| ()).map_err(|e| e.to_string());
        }
        ecrire_l_etat(c, user, &etat)
    });
    match issue {
        IssueDuGesteGarde::Valide(()) => {}
        IssueDuGesteGarde::Refuse(cause) => eprintln!("[mfa] WARN essai du second facteur de '{user}' NON rendu (un échec de trop reste compté) : {cause}"),
        IssueDuGesteGarde::NonOuvert(e) | IssueDuGesteGarde::NonValide(e) => {
            eprintln!("[mfa] WARN essai du second facteur de '{user}' NON rendu (un échec de trop reste compté) : {e}")
        }
    }
}

/// `P10.22-m` — un code juste ACCEPTÉ remet le compte à zéro ; le mot de passe, jamais. Refusée, la remise laisse les
/// échecs comptés (sens qui freine), et c'est dit.
pub(crate) fn remettre_a_zero(conn: &Connection, user: &str) {
    if let Err(e) = oublier_dans_la_transaction(conn, user) {
        eprintln!("[mfa] WARN frein du second facteur de '{user}' NON remis à zéro (ses échecs restent comptés) : {e}");
    }
}

/// `P10.24-o`, `P10.22-y` — retire l'état du frein d'un compte. Appelée par `user_delete` DANS la transaction qui
/// supprime le compte (validée ensemble, ou annulée ensemble), et par la remise à zéro.
pub(crate) fn oublier_dans_la_transaction(conn: &Connection, user: &str) -> rusqlite::Result<usize> {
    conn.execute("DELETE FROM setting WHERE scope=?1 AND key=?2", params![PORTEE_DU_FREIN_DU_SECOND_FACTEUR, user])
}

/// `P10.22-z` — la route qui a jugé le code : elle nomme l'événement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteDuSecondFacteur {
    Connexion,
    Activation,
    Desactivation,
}

impl RouteDuSecondFacteur {
    fn code(self) -> &'static str {
        match self {
            RouteDuSecondFacteur::Connexion => "connexion",
            RouteDuSecondFacteur::Activation => "activation",
            RouteDuSecondFacteur::Desactivation => "desactivation",
        }
    }
}

/// `P10.22-z` — UN CODE FAUX EST VU DU SIEM, ET LE DÉCLENCHEMENT DU FREIN AUSSI.
///
/// MESURÉ LE 2026-09-28 SUR LA FORME D'AVANT (témoin `fdsf_`) : trois codes faux à la désactivation, trois à
/// l'activation -> ZÉRO événement `plume-auth` ; le frein déclenché (désactivation ou connexion) -> aucun événement de
/// sévérité quatre. La connexion, elle, émettait déjà l'échec (`auth_record_failure`, action `failure`, sévérité
/// trois) : elle n'en reçoit pas un second ici.
///
/// CE QUI EST ÉMIS : à l'activation et à la désactivation, un `failure` de sévérité TROIS (celle des autres échecs
/// d'authentification, donc vu de la règle 37 qui compte les `failure` par adresse) ; sur les trois routes, un
/// `lockout` de sévérité QUATRE quand CET échec pose le frein. Une fois par fenêtre sans débounce à écrire : pendant
/// le délai, aucun code n'est examiné, donc aucun échec ni déclenchement n'est émis ; le suivant vient à la levée.
/// Les champs portent `facteur: "second"` et la route ; JAMAIS le code présenté, ni la graine, ni le ticket. Une
/// écriture refusée est comptée et avouée (`ingest.evenements_d_acces_non_ecrits`), jamais servie comme une panne.
/// L'appelant ne tient PAS le verrou de l'écrivain.
pub(crate) fn tracer_l_echec(st: &AppState, user: &str, ip: &str, route: RouteDuSecondFacteur, essai: &EssaiReserve) {
    if route != RouteDuSecondFacteur::Connexion {
        ecrire_l_evenement(st, "failure", 3, user, ip, route, essai.consecutifs, None);
    }
    if let Some(secondes) = essai.arme_pour_s {
        ecrire_l_evenement(st, "lockout", 4, user, ip, route, essai.consecutifs, Some(secondes));
    }
}

#[allow(clippy::too_many_arguments)]
fn ecrire_l_evenement(st: &AppState, action: &'static str, sev: i64, user: &str, ip: &str, route: RouteDuSecondFacteur, echecs: u32, freine_s: Option<u64>) {
    let message = match freine_s {
        Some(s) => format!("frein du second facteur : compte '{user}' freiné {s} s après {echecs} échecs consécutifs ({}) depuis {ip}", route.code()),
        None => format!("échec du second facteur : compte '{user}' ({}) depuis {ip}", route.code()),
    };
    let mut champs = json!({ "action": action, "facteur": "second", "route": route.code(), "username": user, "src_ip": ip, "fails": echecs });
    if let Some(s) = freine_s {
        champs["freine_s"] = json!(s);
    }
    let ipc: Option<&str> = if ip.is_empty() { None } else { Some(ip) };
    // `P10.20-z` — le genre du compteur de perte est un LITTÉRAL (cardinalité fermée).
    let genre = if action == "lockout" { "plume-auth.second-facteur.lockout" } else { "plume-auth.second-facteur.failure" };
    let ecriture = st.db.lock().execute(
        "INSERT INTO event(ts,source,category,severity,message,host,src_ip,fields,origin) \
         VALUES(?1,'plume-auth','auth',?2,?3,'plume-daemon',?4,?5,'daemon')",
        params![now(), sev, message, ipc, champs.to_string()],
    );
    match ecriture {
        Ok(1) => {}
        Ok(n) => crate::metrics::compter_un_evenement_d_acces_non_ecrit(genre, &format!("{n} ligne(s) écrite(s) au lieu d'une")),
        Err(e) => crate::metrics::compter_un_evenement_d_acces_non_ecrit(genre, &e.to_string()),
    }
}

/// TÉMOINS SEULEMENT — les échecs consécutifs comptés au frein de ce compte (0 : aucune ligne).
#[cfg(test)]
pub(crate) fn echecs_consecutifs(st: &AppState, user: &str) -> u32 {
    lire_l_etat(&st.db.lock(), user).expect("frein lisible").map_or(0, |e| e.consecutifs)
}

/// TÉMOINS SEULEMENT — secondes restantes du frein de ce compte (`None` : pas freiné, ou frein coupé).
#[cfg(test)]
pub(crate) fn attente_du_frein(st: &AppState, user: &str) -> Option<u64> {
    if st.lock_threshold == 0 {
        return None;
    }
    let jusqu_a = lire_l_etat(&st.db.lock(), user).expect("frein lisible")?.freine_jusqu_a;
    let maintenant = now();
    (jusqu_a > maintenant).then(|| (jusqu_a - maintenant) as u64)
}

/// TÉMOINS SEULEMENT — fait passer `secondes` sur l'état stocké (délai et dernier échec reculés) : la levée du frein et
/// sa progression se jouent sans attendre ni injecter d'horloge.
#[cfg(test)]
pub(crate) fn faire_passer_le_temps(st: &AppState, user: &str, secondes: i64) {
    let conn = st.db.lock();
    let mut etat = lire_l_etat(&conn, user).expect("frein lisible").expect("frein posé");
    etat.dernier -= secondes;
    if etat.freine_jusqu_a != 0 {
        etat.freine_jusqu_a -= secondes;
    }
    ecrire_l_etat(&conn, user, &etat).expect("frein écrit");
}
