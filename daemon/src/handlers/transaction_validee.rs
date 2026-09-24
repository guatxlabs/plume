//! `P10.24-x`, `P10.25-e`, `P10.25-f` — LE `COMMIT` D'UN GESTE D'ÉCRITURE EST JUGÉ, ET UN REFUS FERME LA
//! TRANSACTION. `valider_la_transaction` vivait dans `users_lookups.rs` (lot 193) ; déplacée ici telle quelle
//! (seule sa visibilité change) quand les jetons, les fournisseurs d'identité, les engagements, le mode, les
//! masques de champs et les sources push ont dû juger leur `COMMIT` à leur tour. `refuser_le_geste_non_valide`
//! s'y ajoute (`P10.26-a` à `P10.26-c`) : le 503 nommé des connecteurs, de l'IA et de la gouvernance.
//! `ouvrir_sa_transaction` (`P10.26-s`) juge l'autre bout : le `BEGIN`.
use crate::*;

/// `P10.26-s` — UN GESTE N'ÉCRIT QUE DANS SA PROPRE TRANSACTION, OU IL N'ÉCRIT RIEN.
///
/// LE DÉFAUT, MESURÉ LE 2026-09-24 SUR LA FORME D'AVANT (`let _ = conn.execute_batch("BEGIN IMMEDIATE")`, sept sites).
/// Quand l'écrivain partagé portait déjà la transaction d'un AUTRE geste — celle qu'un `COMMIT` refusé puis ignoré
/// laisse pendante —, le `BEGIN` échouait sans un mot, les écritures du geste entraient dans la transaction étrangère, et
/// le `COMMIT` du geste la VALIDAIT, son `ROLLBACK` l'ANNULAIT. Mesuré (transaction étrangère ouverte à la main, relecture
/// à froid sur une connexion neuve) : `rollup_hosts` a rendu durables la levée refusée d'un gel juridique ET la purge de
/// la preuve gelée que la rétention avait faite dans la transaction pendante ; le reparse rétroactif, les trois
/// récepteurs de base (Prometheus texte, remote_write, Loki) et les deux voies de spool (journald, événements) ont validé
/// la transaction étrangère en rendant leur succès ; un `INSERT` refusé dans l'ingestion et dans `rollup_hosts` a ANNULÉ
/// une écriture étrangère encore pendante.
///
/// Un `BEGIN` refusé — verrou tenu ailleurs, ou transaction étrangère — rend `Err` : l'appelant n'écrit RIEN, ne valide
/// rien, n'annule rien, et le tour suivant (tick, nouvel essai de l'émetteur, lot laissé au spool) reprend. Le journal
/// distingue les deux causes, parce qu'elles n'appellent pas la même suite : un verrou passe, une transaction étrangère
/// pendante BLOQUE l'écrivain jusqu'à ce que son geste la ferme — ce geste-ci ne la ferme pas à sa place.
pub(crate) fn ouvrir_sa_transaction(conn: &Connection, journal: &str, geste: &str) -> rusqlite::Result<()> {
    conn.execute_batch("BEGIN IMMEDIATE").map_err(|refus| {
        dire_la_transaction_non_ouverte(conn, journal, geste, &refus);
        refus
    })
}

/// `P10.26-s` — LA PHRASE D'UN `BEGIN` REFUSÉ, une seule, pour `ouvrir_sa_transaction` et pour les gestes qui ouvrent
/// leur transaction par le garde `Txn` (spool de métriques et d'instantanés). Elle est dite APRÈS le refus : c'est
/// l'état de l'écrivain à cet instant qui sépare le verrou passager de la transaction étrangère.
pub(crate) fn dire_la_transaction_non_ouverte(conn: &Connection, journal: &str, geste: &str, refus: &rusqlite::Error) {
    if conn.is_autocommit() {
        eprintln!("[{journal}] WARN {geste} NON pris(e) : BEGIN refusé ({refus}) — rien n'est écrit, repris au prochain passage");
    } else {
        eprintln!(
            "[{journal}] ERREUR {geste} NON pris(e) : l'écrivain porte une transaction qui n'est pas la sienne ({refus}) — \
             rien n'est écrit, validé ni annulé à sa place ; l'écrivain reste bloqué tant que son geste ne la ferme pas"
        );
    }
}

/// `P10.24-x` — LE `COMMIT` D'UN GESTE D'ÉCRITURE EST JUGÉ, ET UN REFUS FERME LA TRANSACTION.
///
/// LE DÉFAUT, MESURÉ LE 2026-09-24 SUR LA FORME D'AVANT (`COMMIT` refusé par un autorisateur SQLite) : `user_create`
/// rendait 200 et l'identifiant d'un compte qui n'a jamais existé ; `user_delete` rendait 204 et avait déjà oublié les
/// échecs de connexion du compte, toujours là ; `user_update` rendait 204, `lookup_upload` 200. L'énoncé sous-comptait :
/// dans les quatre cas la transaction restait OUVERTE sur la connexion d'écriture partagée, et le geste suivant
/// (une autre création) échouait à `BEGIN IMMEDIATE` — 500 « verrou base indisponible ».
///
/// Après un `COMMIT` refusé, SQLite peut avoir annulé la transaction de lui-même ou l'avoir laissée ouverte, selon
/// l'erreur : le `ROLLBACK` couvre les deux (dans le premier cas il échoue sans effet, et cet échec n'est pas une
/// information). S'il ne ferme pas la transaction, le journal le dit : l'écrivain est alors bloqué.
///
/// `P10.25-e`, `P10.25-f` — LE MÊME DÉFAUT, MESURÉ LE 2026-09-24 HORS DES COMPTES (même autorisateur) : un jeton frappé
/// rendait 200 et son secret, authentifiait tant que la transaction restait pendante, et n'existait plus au
/// redémarrage ; un jeton, un fournisseur d'identité, un engagement révoqués rendaient 204 ou 200 et revivaient dès
/// que la transaction était annulée ; un masque de champ était SERVI (registre rechargé dans la transaction pendante)
/// et perdu au redémarrage ; l'exemption d'auto-ban d'un engagement jamais écrit était posée en mémoire. Qui appelle
/// ce juge ne rend rien, ne montre aucun secret et ne recharge aucun état de processus avant son `Ok`.
pub(crate) fn valider_la_transaction(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch("COMMIT").map_err(|refus| {
        let _ = conn.execute_batch("ROLLBACK");
        if !conn.is_autocommit() {
            eprintln!("[transaction] ERREUR transaction toujours ouverte après un COMMIT refusé puis un ROLLBACK : l'écrivain est bloqué");
        }
        refus
    })
}

/// `P10.26-a`, `P10.26-b`, `P10.26-c` — LE REFUS D'UN GESTE D'ADMINISTRATION DONT `valider_la_transaction` A RENDU
/// `Err` : le journal dit quel geste la base n'a pas validé et pourquoi, la réponse est un 503 qui porte la CAUSE
/// NOMMÉE du geste (ce qui est toujours en place, ce qui ne l'est pas). Le 503 et non un 500 : rien n'est cassé dans
/// la demande, la base a refusé de la prendre et un nouvel essai peut aboutir. Les appelants de `P10.25-e` et `P10.25-f`
/// gardent leur fonction locale ; celle-ci sert les connecteurs, l'IA et la gouvernance, qui en auraient sinon écrit
/// trois de plus.
pub(crate) fn refuser_le_geste_non_valide(journal: &str, geste: &str, refus: &rusqlite::Error, cause: &'static str) -> Response {
    eprintln!("[{journal}] WARN {geste} NON validé(e) : {refus}");
    err_json(StatusCode::SERVICE_UNAVAILABLE, cause)
}
