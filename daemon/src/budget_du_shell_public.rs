//! budget_du_shell_public — `P4.13-a` (reprise) : CE QUE LA PORTE OUVERTE COÛTE, ET SA BORNE.
//!
//! LE DÉFAUT, MESURÉ AU BANC AVANT D'ÊTRE CORRIGÉ — poste de développement, binaire du dépôt lancé à la
//! main sous `env -i` sur une base neuve, sans mandataire, rafales FABRIQUÉES de 1 000 requêtes à 8
//! connexions, UC lue dans `/proc/<pid>/stat`. Aucune installation n'est décrite ici : l'objet mesuré est
//! le produit tel que cet arbre le construit (2026-08-29) :
//!
//! | ce qu'un ANONYME obtient      | octets rendus | UC du démon par requête |
//! |-------------------------------|---------------|-------------------------|
//! | avant `P4.13-a` (401)         | 12            | **0,21 ms**             |
//! | `/viz.js` sans compression    | 167 542       | 0,65 ms                 |
//! | `/viz.js` avec `gzip`         | 57 557        | **13,28 ms**            |
//!
//! Soit **63×** l'UC d'un 401 au banc, et la compression en est 95 %. Le facteur n'est pas un artefact de
//! la construction en debug : au même banc, `zlib` en C niveau 6 sur les mêmes 167 542 octets coûte
//! 6,49 ms — par arithmétique, ~6,5 ms restent donc dus PAR REQUÊTE en release, parce que
//! `cache_control_for` rend `no-cache` sur tout
//! le shell et que rien n'est pré-compressé. Un client légitime paie ce prix UNE fois par déploiement (il
//! présente `If-None-Match` et reçoit un 304 sans corps) ; un client qui OMET l'en-tête conditionnel le
//! fait payer à chaque requête. L'amplification est donc, très précisément, un coût d'ABUS.
//!
//! CE QUI N'AVAIT PAS ÉTÉ RECALIBRÉ. `rl_ip_max` (1 200 req/10 s par IP) et `rl_global_max` (6 000 req/10 s)
//! ont été dimensionnés quand un anonyme coûtait une constante de douze octets. Aux mêmes plafonds, après
//! `P4.13-a` : **92,7 Mo/s au banc** pour UNE IP sur `/viz.js` non compressé, et ~0,78 cœur de `gzip` par IP
//! (6,49 ms × 120 req/s), ~3,9 cœurs au plafond global — sur un produit dont la contrainte affichée est de
//! tenir dans 2 Gio. Le rapport du lot bornait l'échange aux DONNÉES (« aucune donnée exposée ») ; le
//! versant RESSOURCES n'était ni nommé ni mesuré. Il l'est ici.
//!
//! LA BORNE EST EXPRIMÉE DANS L'UNITÉ QUI A CHANGÉ : des OCTETS, pas des requêtes. C'est ce qui la rend
//! sans effet sur le trafic légitime — un 304 de revalidation ne porte aucun corps, donc ne consomme RIEN,
//! alors qu'un plafond en requêtes l'aurait compté comme une charge complète. Deux seaux à fenêtre
//! glissante de 10 s : un PAR IP RÉELLE et un GLOBAL, exactement le couple que `rate_limit` porte déjà.
//!
//! L'IP EST CELLE DE `real_client_ip` — le résolveur ANTI-USURPATION du ban natif (pair TCP seul, sauf si
//! le pair est un mandataire de confiance et, si `PLUME_EDGE_SECRET` est posé, qu'il présente le secret).
//! C'est ce qui évite une RÉGRESSION en `k3s`, où `client_ip` (le pair) rend l'unique IP de Traefik pour
//! TOUS les analystes : le budget y est par analyste réel, pas par grappe. Un auteur, pas deux.
//!
//! LES DÉFAUTS SONT DÉRIVÉS DE LA SURFACE MESURÉE, pas choisis : la surface publique complète pèse
//! 1 939 205 octets (63 chemins pour 62 fichiers, `/` et `/index.html` étant le même). Le budget par IP vaut
//! 64 Mio/10 s = **~34 chargements à froid par IP et par fenêtre** — inatteignable par un humain, et il
//! ramène le pire cas mesuré de 92,7 Mo/s à 6,7 Mo/s (14× moins) et ~0,78 cœur de `gzip` à ~0,26. Le budget
//! global vaut 256 Mio/10 s (4 × celui d'une IP), pour que N sources ne composent pas leurs budgets sans
//! limite. `0` désactive un seau — le mode 0 reste alors byte-identique.
//!
//! CE QUE ÇA NE TIENT PAS. (a) La facturation lit `content-length`, que `rate_limit` voit AVANT la couche
//! de compression : ce sont donc les octets BRUTS — ceux qui sont lus du disque et donnés à `gzip`, c'est-
//! à-dire ce qui coûte. Une réponse SANS `content-length` n'est pas facturée ; le témoin
//! `p4_13_a_chaque_reponse_publique_est_facturable` exige que les 63 chemins publics en portent un, donc le
//! trou est mesuré, pas supposé. (b) Un attaquant DANS le réseau privé peut, par défaut, se faire passer
//! pour plusieurs clients derrière un mandataire de confiance et échapper au seau PAR IP — c'est une
//! propriété PRÉEXISTANTE de `proxy_is_trusted`, partagée avec `net_ban`, et le seau GLOBAL le borne
//! quand même. (c) Rien ici ne supprime la re-compression : le levier mesuré (niveau 1 au lieu de 6 :
//! 2,14 ms au lieu de 6,49, +17 % d'octets) change les octets que TOUT client reçoit — c'est une décision
//! de produit, elle est écrite comme un reste, pas prise dans un correctif.
use crate::*;

/// Fenêtre glissante des deux seaux — la MÊME que celle de `rate_limit` (un seul rythme à comprendre).
pub(crate) const FENETRE: Duration = Duration::from_secs(10);

/// Défaut du seau PAR IP RÉELLE (octets/10 s). ~34 chargements à froid de la console par fenêtre.
pub(crate) const OCTETS_IP_MAX_DEFAUT: u64 = 64 * 1024 * 1024;

/// Défaut du seau GLOBAL (octets/10 s) — 4 × le budget d'une IP.
pub(crate) const OCTETS_GLOBAL_MAX_DEFAUT: u64 = 256 * 1024 * 1024;

/// Borne d'entrées du seau par IP (anti-OOM, même rôle et même valeur que la map de `rate_limit`).
const CAP_ENTREES: usize = 8192;

/// La dette de la fenêtre courante dépasse-t-elle un des deux plafonds ? Rendue AVANT de servir : on
/// refuse sur la dette DÉJÀ contractée, jamais sur une prédiction du corps qu'on n'a pas encore.
/// `Some(reponse)` = refus (429), `None` = on sert.
pub(crate) fn refuser(st: &AppState, ip: &str, maintenant: Instant) -> Option<Response> {
    if st.shell_octets_global_max > 0 {
        let mut g = st.shell_octets_global.lock();
        if maintenant.duration_since(g.0) > FENETRE {
            *g = (maintenant, 0);
        }
        if g.1 > st.shell_octets_global_max {
            return Some(refus("global"));
        }
    }
    if st.shell_octets_ip_max > 0 && !ip.is_empty() {
        let mut m = st.shell_octets_ip.lock();
        if m.len() > CAP_ENTREES {
            m.retain(|_, (t, _)| maintenant.duration_since(*t) <= FENETRE);
        }
        if let Some(e) = m.get_mut(ip) {
            if maintenant.duration_since(e.0) > FENETRE {
                *e = (maintenant, 0);
            }
            if e.1 > st.shell_octets_ip_max {
                return Some(refus("ip"));
            }
        }
    }
    None
}

/// Facture les octets BRUTS de la réponse (avant compression : `rate_limit` est SOUS cette couche).
/// Un corps absent ou sans `content-length` facture zéro — c'est ce que le témoin de facturabilité borne.
pub(crate) fn facturer(st: &AppState, ip: &str, maintenant: Instant, octets: u64) {
    if octets == 0 {
        return;
    }
    if st.shell_octets_global_max > 0 {
        let mut g = st.shell_octets_global.lock();
        if maintenant.duration_since(g.0) > FENETRE {
            *g = (maintenant, 0);
        }
        g.1 = g.1.saturating_add(octets);
    }
    if st.shell_octets_ip_max > 0 && !ip.is_empty() {
        let mut m = st.shell_octets_ip.lock();
        let e = m.entry(ip.to_string()).or_insert((maintenant, 0));
        if maintenant.duration_since(e.0) > FENETRE {
            *e = (maintenant, 0);
        }
        e.1 = e.1.saturating_add(octets);
    }
}

/// Les octets qu'une réponse va écrire, tels que cette couche les voit (donc NON compressés).
pub(crate) fn octets_de(res: &Response) -> u64 {
    res.headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0)
}

/// Le refus NOMME le seau et le geste — un `429` nu sur un fichier du shell rendrait, lui aussi, un écran
/// muet, et l'exploitant n'aurait rien à lire. `Retry-After` porte la fenêtre, qui est la seule attente utile.
fn refus(seau: &'static str) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(axum::http::header::RETRY_AFTER, "10")],
        format!(
            "budget d'octets de la console dépassé (seau {seau}, fenêtre de {} s). La console est servie \
             SANS authentification pour que l'écran de connexion puisse s'afficher ; ce budget borne ce que \
             cela coûte. Réessayez dans dix secondes, ou relevez PLUME_SHELL_OCTETS_{}_MAX (0 = désactivé).",
            FENETRE.as_secs(),
            seau.to_uppercase()
        ),
    )
        .into_response()
}
