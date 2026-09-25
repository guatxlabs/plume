//! `P10.24-x`, `P10.25-e`, `P10.25-f` — LE `COMMIT` D'UN GESTE D'ÉCRITURE EST JUGÉ, ET UN REFUS FERME LA
//! TRANSACTION. `valider_la_transaction` vivait dans `users_lookups.rs` (lot 193) ; déplacée ici telle quelle
//! (seule sa visibilité change) quand les jetons, les fournisseurs d'identité, les engagements, le mode, les
//! masques de champs et les sources push ont dû juger leur `COMMIT` à leur tour. `refuser_le_geste_non_valide`
//! s'y ajoute (`P10.26-a` à `P10.26-c`) : le 503 nommé des connecteurs, de l'IA et de la gouvernance.
//! `ouvrir_sa_transaction` (`P10.26-s`) juge l'autre bout : le `BEGIN`. `rendre_apres_validation`,
//! `rendre_apres_validation_du_garde`, `tracer_apres_coup` et `fermer_l_instantane_de_lecture` (`P10.25-g`, `P10.26-x`)
//! servent les derniers sites qui avalaient leur `COMMIT` ; `signaler_une_transaction_ouverte_hors_de_tout_geste`
//! (`P10.27-g`) est la sonde d'une transaction laissée ouverte ; `ouvrir_la_transaction_du_geste` (`P10.28-p`) est la
//! forme d'une ROUTE qui ouvre sa transaction : `ouvrir_sa_transaction`, et un refus en 503 nommé ;
//! `ouvrir_le_garde_du_geste` (`P10.28-d`) est la même forme pour une route qui l'ouvre par le garde `Txn`.
//! `jouer_le_geste_garde` (`P10.21-r`) est la forme d'un geste dont la GARDE (une lecture qui peut refuser) et
//! l'ÉCRITURE qu'elle autorise vivent dans UNE transaction, sous un seul verrou ; `point_de_course` est le lieu où un
//! témoin de course fait jouer le geste concurrent (inerte hors `cfg(test)`).
use crate::*;

/// `P10.21-r` — CE QUE REND UN GESTE GARDÉ (voir `jouer_le_geste_garde`). Le jeter serait taire un refus.
#[must_use]
#[derive(Debug)]
pub(crate) enum IssueDuGesteGarde<T, R> {
    /// La garde a permis, l'écriture est faite, la transaction est VALIDÉE.
    Valide(T),
    /// Le corps a refusé (la garde, ou une écriture qu'il a comptée) : la transaction est ANNULÉE, rien n'est écrit.
    Refuse(R),
    /// Le `BEGIN` refusé, dit au journal par `ouvrir_sa_transaction` : rien n'est lu ni écrit.
    NonOuvert(rusqlite::Error),
    /// Le `COMMIT` refusé : `valider_la_transaction` l'a annulé et l'a dit ; rien n'est écrit.
    NonValide(rusqlite::Error),
}

/// `P10.21-r` — LA GARDE ET L'ÉCRITURE QU'ELLE AUTORISE, DANS LA MÊME TRANSACTION.
///
/// LE DÉFAUT, MESURÉ LE 2026-09-25 SUR LA FORME D'AVANT (témoins `mpra_`). L'anti-verrouillage du dernier
/// administrateur d'un tenant (SCIM `PUT active=false` et `DELETE`, `grant_set`, `grant_delete`) lisait le rôle visé et
/// le compte des administrateurs sous un verrou du plan de contrôle, le RELÂCHAIT, puis écrivait sous un second : deux
/// retraits concurrents des deux derniers administrateurs lisaient chacun « il en reste deux » et passaient tous les
/// deux — le tenant n'avait plus d'administrateur. `user_update` (mode 0) avait la même fenêtre, ouverte pour la preuve
/// du mot de passe actuel.
///
/// LA FORME : `corps` reçoit la connexion DÉJÀ en transaction (`BEGIN IMMEDIATE` par `ouvrir_sa_transaction`) ; il lit
/// sa garde, écrit, et rend `Ok` (validé ici par `valider_la_transaction`) ou `Err` (annulé ici). L'appelant TIENT le
/// verrou de `conn` de l'appel au retour : aucune écriture d'un autre geste ne s'intercale entre la lecture de la garde
/// et l'écriture — ni de ce processus (le verrou), ni d'un autre (le verrou d'écriture de SQLite, pris au `BEGIN`).
/// Un `ROLLBACK` refusé n'est pas une information (voir `valider_la_transaction`).
pub(crate) fn jouer_le_geste_garde<T, R>(
    conn: &Connection,
    journal: &str,
    geste: &str,
    corps: impl FnOnce(&Connection) -> Result<T, R>,
) -> IssueDuGesteGarde<T, R> {
    if let Err(refus) = ouvrir_sa_transaction(conn, journal, geste) {
        return IssueDuGesteGarde::NonOuvert(refus);
    }
    match corps(conn) {
        Ok(fait) => match valider_la_transaction(conn) {
            Ok(()) => IssueDuGesteGarde::Valide(fait),
            Err(refus) => IssueDuGesteGarde::NonValide(refus),
        },
        Err(refus) => {
            let _ = conn.execute_batch("ROLLBACK");
            if !conn.is_autocommit() {
                eprintln!("[{journal}] ERREUR {geste} : transaction toujours ouverte après un ROLLBACK — l'écrivain est bloqué");
            }
            IssueDuGesteGarde::Refuse(refus)
        }
    }
}

/// `P10.21-r` — LE POINT DE COURSE : posé, dans un geste qui garde le dernier administrateur, ENTRE la lecture de la
/// garde et l'écriture qu'elle autorise. Hors `cfg(test)` il ne fait RIEN. Sous `cfg(test)`, il appelle — une seule
/// fois, puis l'oublie — le crochet qu'un témoin a posé pour la base `cle` (son chemin : deux témoins parallèles ne se
/// croisent pas). Le crochet y fait jouer le geste concurrent ; ce qu'il PEUT faire dépend de ce que le geste tient à
/// cet instant — c'est la propriété que le témoin mesure (voir `poser_un_crochet_de_course`).
#[inline]
pub(crate) fn point_de_course(cle: &str) {
    #[cfg(test)]
    {
        let crochet = CROCHETS_DE_COURSE.get_or_init(Default::default).lock().remove(cle);
        if let Some(crochet) = crochet {
            crochet();
        }
    }
    #[cfg(not(test))]
    let _ = cle;
}

#[cfg(test)]
type CrochetDeCourse = Box<dyn FnOnce() + Send>;

#[cfg(test)]
static CROCHETS_DE_COURSE: std::sync::OnceLock<Mutex<HashMap<String, CrochetDeCourse>>> = std::sync::OnceLock::new();

/// TÉMOINS SEULEMENT — pose le crochet que `point_de_course(cle)` appellera une fois.
#[cfg(test)]
pub(crate) fn poser_un_crochet_de_course(cle: &str, crochet: impl FnOnce() + Send + 'static) {
    CROCHETS_DE_COURSE.get_or_init(Default::default).lock().insert(cle.to_string(), Box::new(crochet));
}

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

/// `P10.28-p` — LA FORME COMMUNE D'UNE ROUTE QUI OUVRE SA TRANSACTION : `ouvrir_sa_transaction`, et un refus rendu en
/// 503 qui porte la CAUSE NOMMÉE du geste. La forme qu'elle remplace (`if conn.execute_batch("BEGIN IMMEDIATE").is_err()
/// { return server_err("verrou base indisponible"); }`) ne se trompait pas sur l'intégrité — elle n'écrivait rien —, mais
/// elle rendait un 500 GÉNÉRIQUE (« rien n'est cassé » y ressemble à « tout est cassé »), ne disait pas ce qui n'avait
/// pas eu lieu, et ne disait RIEN au journal : ni le verrou passager, ni la transaction d'un autre geste qui bloque
/// l'écrivain (`dire_la_transaction_non_ouverte` les sépare). Le 503 et non un 500, comme pour un `COMMIT` refusé
/// (`refuser_le_geste_non_valide`) : la base n'a pas pris la demande, un nouvel essai peut aboutir. Aucune écriture,
/// aucune validation, aucune annulation n'a lieu ici : la transaction d'un autre geste, s'il y en a une, reste la sienne.
pub(crate) fn ouvrir_la_transaction_du_geste(conn: &Connection, journal: &str, geste: &str, cause: &'static str) -> Result<(), Response> {
    ouvrir_sa_transaction(conn, journal, geste).map_err(|_refus_deja_dit| err_json(StatusCode::SERVICE_UNAVAILABLE, cause))
}

/// `P10.28-d` — LA MÊME FORME POUR UNE ROUTE QUI OUVRE SA TRANSACTION PAR LE GARDE `Txn` (les runbooks, l'envoi d'un
/// puits du registre) : un `BEGIN` refusé est dit au journal par `dire_la_transaction_non_ouverte` — verrou passager ou
/// transaction d'un autre geste qui bloque l'écrivain —, et rendu en 503 qui porte la cause nommée du geste. La forme
/// qu'elle remplace (`match Txn::begin(&conn) { Ok(t) => t, Err(_) => return server_err("verrou base indisponible") }`)
/// rendait un 500 générique et taisait les deux causes. Aucune écriture n'a lieu : le garde n'existe que si le `BEGIN` a
/// été pris, et c'est lui qui annule à sa destruction.
pub(crate) fn ouvrir_le_garde_du_geste<'c>(conn: &'c Connection, journal: &str, geste: &str, cause: &'static str) -> Result<Txn<'c>, Response> {
    Txn::begin(conn).map_err(|refus| {
        dire_la_transaction_non_ouverte(conn, journal, geste, &refus);
        err_json(StatusCode::SERVICE_UNAVAILABLE, cause)
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

/// `P10.25-g` — LE SUCCÈS D'UNE ROUTE N'EST RENDU QU'APRÈS LA VALIDATION DE SA TRANSACTION.
///
/// LA FORME QU'ELLE REMPLACE (`let _ = conn.execute_batch("COMMIT")` puis le succès : quarante-cinq sites dans vingt
/// fichiers au lot 197) ne jugeait pas le `COMMIT` : un refus rendait 200 ou 204 sur un geste que la base n'avait pas pris, laissait la
/// transaction OUVERTE sur l'écrivain partagé, et — depuis `P10.26-s`, où un `BEGIN` refusé n'écrit plus dans la
/// transaction d'un autre — cette transaction pendante BLOQUAIT l'ingestion, le pli des hôtes, le reparse et l'envoi
/// des puits jusqu'au redémarrage (`P10.27-g`). Ici `succes` — qui construit la réponse ET recharge ce que le
/// processus garde en mémoire (parseurs, processeurs, indicateurs, objets de savoir, flotte) — ne s'exécute qu'une
/// fois la transaction VALIDÉE ; un refus ferme la transaction (`valider_la_transaction`) et rend le 503 nommé du
/// geste (`refuser_le_geste_non_valide`), rien n'étant rechargé ni annoncé.
pub(crate) fn rendre_apres_validation(
    conn: &Connection,
    journal: &str,
    geste: &str,
    cause: &'static str,
    succes: impl FnOnce() -> Response,
) -> Response {
    match valider_la_transaction(conn) {
        Ok(()) => succes(),
        Err(refus) => refuser_le_geste_non_valide(journal, geste, &refus, cause),
    }
}

/// `P10.26-x` — LA MÊME RÈGLE POUR UN GESTE OUVERT PAR LE GARDE `Txn` : `Txn::commit` rend `Err` sur un `COMMIT`
/// refusé et son `Drop` annule. La forme remplacée (`let _ = tx.commit()`) fermait donc la transaction, mais rendait
/// le succès d'un geste que la base n'avait pas pris, et sa trace d'audit disparaissait sans aveu. `conn` est la
/// connexion du garde : elle sert à dire, après l'annulation, si l'écrivain est resté pris.
pub(crate) fn rendre_apres_validation_du_garde(
    tx: Txn<'_>,
    conn: &Connection,
    journal: &str,
    geste: &str,
    cause: &'static str,
    succes: impl FnOnce() -> Response,
) -> Response {
    match tx.commit() {
        Ok(()) => succes(),
        Err(refus) => {
            if !conn.is_autocommit() {
                eprintln!("[transaction] ERREUR transaction toujours ouverte après un COMMIT refusé puis un ROLLBACK : l'écrivain est bloqué");
            }
            refuser_le_geste_non_valide(journal, geste, &refus, cause)
        }
    }
}

/// `P10.26-x` — LA TRACE D'UN GESTE DÉJÀ ACCOMPLI, QUI NE SE DÉFAIT PAS : le poll manuel d'un connecteur, l'envoi
/// manuel d'une destination. Le réseau a eu lieu ; la trace s'écrit APRÈS COUP, dans sa propre transaction, et le
/// geste n'est pas refusé faute de trace (refuser n'annulerait rien). La forme remplacée
/// (`if let Ok(tx) = Txn::begin(..) { … if ok { let _ = tx.commit(); } }`) taisait les trois refus possibles : un
/// `BEGIN`, une écriture ou un `COMMIT` refusé laissaient la réponse IDENTIQUE à celle d'un geste tracé. Chacun est
/// désormais dit au journal, et `Err(cause)` rend à l'appelant la phrase qu'il joint à sa réponse. Aucune écriture
/// n'entre dans une transaction étrangère : `ecrire` n'est appelé que si le `BEGIN` a été pris.
pub(crate) fn tracer_apres_coup(
    conn: &Connection,
    journal: &str,
    geste: &str,
    cause: &'static str,
    ecrire: impl FnOnce() -> rusqlite::Result<()>,
) -> Result<(), &'static str> {
    let tx = match Txn::begin(conn) {
        Ok(tx) => tx,
        Err(refus) => {
            let etat = if conn.is_autocommit() { "verrou indisponible" } else { "l'écrivain porte une transaction qui n'est pas la sienne" };
            eprintln!("[{journal}] WARN trace de « {geste} » NON écrite : BEGIN refusé ({refus} ; {etat}) — le geste a eu lieu, sa trace manque");
            return Err(cause);
        }
    };
    if let Err(refus) = ecrire() {
        drop(tx);
        eprintln!("[{journal}] WARN trace de « {geste} » NON écrite : écriture refusée ({refus}), transaction annulée — le geste a eu lieu, sa trace manque");
        return Err(cause);
    }
    tx.commit().map_err(|refus| {
        let reste = if conn.is_autocommit() { "" } else { " ; transaction toujours ouverte : l'écrivain est bloqué" };
        eprintln!("[{journal}] WARN trace de « {geste} » NON validée : COMMIT refusé ({refus}), transaction annulée{reste} — le geste a eu lieu, sa trace manque");
        cause
    })
}

/// `P10.25-g` — LA FIN D'UN INSTANTANÉ DE LECTURE (`BEGIN` sans écriture) EST JUGÉE, et sa connexion est rendue FERMÉE.
/// Deux sites la tenaient par `let _ = conn.execute_batch("COMMIT")` : la ventilation de la base, sur une connexion du
/// POOL DE LECTURE qui y retourne ensuite, et la sauvegarde en flux, sur une connexion privée. LU, NON MESURÉ en
/// production : un `COMMIT` refusé y laissait l'instantané OUVERT, et `read_conn_put` rendait la connexion au pool sans
/// regarder son état — elle aurait servi à toute lecture suivante un instantané figé, que le point de reprise du WAL ne
/// peut pas franchir (MESURÉ depuis sous `P10.28-a`, et `read_conn_put` ferme désormais une connexion rendue en
/// transaction). Rien n'a été écrit, donc rien n'est perdu : un refus est annulé (`ROLLBACK`) et DIT. Rend `true`
/// quand la connexion est revenue en autocommit (le témoin `cjds_` joue les trois cas).
pub(crate) fn fermer_l_instantane_de_lecture(conn: &Connection, journal: &str, geste: &str) -> bool {
    if let Err(refus) = conn.execute_batch("COMMIT") {
        let _ = conn.execute_batch("ROLLBACK");
        if conn.is_autocommit() {
            eprintln!("[{journal}] WARN fin de l'instantané de lecture de « {geste} » refusée ({refus}) : annulé, rien n'était écrit");
        } else {
            eprintln!(
                "[{journal}] ERREUR l'instantané de lecture de « {geste} » reste OUVERT après un COMMIT refusé ({refus}) puis un \
                 ROLLBACK : cette connexion sert un état figé tant qu'elle vit"
            );
        }
    }
    conn.is_autocommit()
}

/// `P10.27-g` — LE COMPTE DES TRANSACTIONS TROUVÉES OUVERTES HORS DE TOUT GESTE, depuis le démarrage (jamais persisté).
static TRANSACTIONS_OUVERTES_HORS_DE_TOUT_GESTE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Le compte ci-dessus, lu par les témoins. Il n'est pas (encore) exposé sous `/metrics` : ce serait toucher le rendu
/// des compteurs et leur documentation d'exploitation, hors de ce lot.
#[cfg(test)]
pub(crate) fn transactions_ouvertes_hors_de_tout_geste() -> u64 {
    TRANSACTIONS_OUVERTES_HORS_DE_TOUT_GESTE.load(std::sync::atomic::Ordering::Relaxed)
}

/// `P10.27-g` — LA SONDE : UNE TRANSACTION OUVERTE SUR L'ÉCRIVAIN, VUE PAR QUI TIENT SON VERROU SANS ÊTRE DANS UN GESTE.
///
/// L'appelant vient de prendre le verrou de l'écrivain pour une boucle de fond : aucun geste n'est donc en cours sur
/// cette connexion (chaque geste tient ce verrou de son `BEGIN` à son `COMMIT`). Si elle n'est pas en autocommit, c'est
/// qu'une transaction a été laissée OUVERTE par un geste qui a rendu la main — un `COMMIT` refusé et ignoré, un
/// `ROLLBACK` refusé. Depuis `P10.26-s` une telle transaction n'est plus validée par accident : elle bloque
/// l'ingestion (503, lots gardés au spool), le pli des hôtes, le reparse et l'envoi des puits jusqu'au redémarrage.
/// La sonde le DIT au journal et le COMPTE ; elle ne ferme pas la transaction (ce choix — annuler un état qu'aucun
/// geste ne réclame plus — n'est pas tranché ici). Rend `true` quand elle en a vu une.
pub(crate) fn signaler_une_transaction_ouverte_hors_de_tout_geste(conn: &Connection, boucle: &str) -> bool {
    if conn.is_autocommit() {
        return false;
    }
    TRANSACTIONS_OUVERTES_HORS_DE_TOUT_GESTE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    eprintln!(
        "[transaction] ERREUR l'écrivain porte une transaction OUVERTE hors de tout geste (vue par la boucle « {boucle} ») : \
         l'ingestion, le pli des hôtes, le reparse et l'envoi des puits sont bloqués jusqu'à sa fermeture ou au redémarrage"
    );
    true
}
