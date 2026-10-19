// =================================================================================================
// `S31` (reste du temps 2) — TOUT GESTIONNAIRE QUI ÉCRIT LE SPOOL PASSE PAR `spool::publier`.
//
// VU (re-mesuré sur f54efa36) : SEPT fonctions construisent un chemin `.tmp` à partir de `st.spool`
// (otlp, minio ×2, hec, pubsub, firehose, journal) et publient par `crate::ingest::spool::publier`,
// seul point qui prend les deux barrières. Aucun témoin d'ensemble : une huitième surface qui
// recopierait l'ancien geste (`fs::write` du `.tmp` puis `fs::rename`) répondrait un accusé sans
// barrière, et rien ne rougissait.
//
// LA POPULATION EST DÉRIVÉE DU GESTE, PAS D'UN COMPTE. Corpus : tout `.rs` sous `src/` (récursif : un
// gestionnaire vit aussi à la racine, `scim.rs`, `sigma.rs`, ou dans `handlers/connectors/`), sauf `src/tests/`
// et `ingest/spool.rs`. Chaque fonction est jugée sur SA PLAGE (début du corps), jamais par son nom : deux
// homonymes d'un même fichier (`mod v2`, deux `impl`, fonction imbriquée) rendent deux sites, chacun jugé.
// Une fonction est un SITE si, dans son code (commentaires et chaînes retirés, `br"…"`/`cr"…"` compris : leur
// préfixe est neutralisé avant le blanchisseur partagé, qui ne reconnaît une chaîne brute qu'à un `r`
// isolé ; items `#[cfg(test)]` retirés, mais un `#[cfg(test)]` posé sur un champ, une variante, un bras ou une instruction ne retire
// que lui-même, jamais l'item qui suit) :
//   (A) un `format!(…)` référence `spool` — en argument (`st.spool`, `spool`) OU en capture dans le
//       littéral (`"{spool}/…"`) — ET son littéral contient `.tmp` ;
//   (A') ou un tel `format!` sans `.tmp` dans une fonction qui appelle `spool::publier` (site régressé
//       vers un chemin final) ;
//   (B) ou elle mentionne `spool` — corps OU signature, la liste de paramètres étant sautée pour
//       trouver le corps (`spool: &str`, `State(AppState { spool, .. })`)
//       — ET nomme un geste d'écriture direct, appelé OU NON (valeur `let w = std::fs::write;`, import
//       `use std::fs::write;`) : préfixes `fs::write`, `fs::rename`, `fs::copy`, `fs::hard_link`,
//       `fs::symlink`, `fs::soft_link`, `File::create` (`create_new`, `create_buffered`), `File::options`,
//       `OpenOptions` (`new`, `default`, le type) — blancs admis autour de `::` et `>` devant (`std::fs:: write`,
//       `File :: create`, `<std::fs::File>::create`) —, ou `fs` renommé / importé en groupe (`use std::fs as f;`,
//       `use std::fs::{…}`, `fs::*`), ou `File` renommé (`use std::fs::File as F;`) ; un `spawn…` non appelé
//       (valeur, `use tokio::spawn as lancer;`) dans un site le rend non conforme ;
//   (C) ou elle référence le MODULE `spool` (`spool` [blancs] `::` [blancs] …) — même si ses chemins passent
//       par un alias local du spool (`let sp = st.spool.clone()`) que (A) ne voit pas. Seuls sont admis
//       `spool::publier(` (appel, jugé ci-dessous) et `spool::<Capitale>` (type, variante, constante :
//       `EchecSpool`). Toute autre référence est refusée d'office : variante (`publier_bloquant`), autre
//       fonction (`spool::ecrire(`), valeur (`let f = …::spool::publier_bloquant;`), import
//       (`use …::spool::publier_bloquant;`, `spool::{…}`, `spool::*`), renommage (`spool as sp`). Un chemin
//       par métavariable de macro (`crate::ingest::$m::…`, hors `$crate`) est refusé de même, le module réel
//       n'étant écrit qu'à l'appel (`m!(spool, …)`).
// Deux fonctions HORS RÉCEPTION (`HORS_RECEPTION` : remise en file et mise à l'écart de la
// quarantaine) écrivent le spool par `fs::rename` sans qu'aucun émetteur externe n'efface sa
// copie sur un accusé : nommées, jugées dans les deux sens, leur liste de gestes directs épinglée ; une
// entrée couvre UN site (un homonyme du même fichier rend « hors réception ambigu », jamais l'exemption).
// HORS FONCTION, une référence interdite au module `spool` est refusée dans TOUT fichier du corpus ; un
// geste direct nommé, `fs` renommé ou groupé, et un `spawn… as` le sont dans tout fichier qui mentionne le
// spool. Le verdict nomme alors `(hors fonction)`.
// La signature est lue génériques `<…>` sautés, puis liste de paramètres sautée : sans ce saut, les
// accolades d'un extracteur sur une fonction générique seraient prises pour le corps.
// Un appel `spool::publier(` est CONFORME s'il prend un `.tmp` du spool lié par `let` en premier
// argument, un chemin `format!(… spool …)` lié par `let` en second, le réglage `….ingest_fsync` TEL QUEL
// en quatrième (chemin POINTÉ d'identifiants : un `false` en dur, un `!st.ingest_fsync` ou un
// `ingest_fsync` nu — liaison locale — saute les barrières), si son issue est ATTENDUE DANS LE GESTIONNAIRE
// (`.await` sur l'appel, hors de tout contexte qui détache ou enrobe, lu depuis le début du fichier et sur
// toute la pile — un bloc ordinaire ou une fonction imbriquée DANS un tel contexte en hérite : groupe
// `(`/`[` encore ouvert — argument de `spawn…(`, `drop(`, `std::mem::forget(`, d'un helper `detacher(` quel
// que soit son nom, d'une macro `m!(`, élément de `[_] = [ … ]` —, bloc ou fermeture `async` hors corps de
// fonction, la liste de paramètres `|…|` d'une fermeture `async` sautée (ouvrant derrière `move` / `async`) — un `{…}` ou un `;` qu'elle contient,
// `|S { a, .. }: S|`, `|_x: [u8; 2]|`, ne coupe pas la tête avant `async` —, macro à accolades `m! { … }`)
// et CONSOMMÉE : l'instruction, lue de son début (`;`, `{`, `}`
// précédent, retours à la ligne compris), attributs retirés, la tête du chemin (blancs autour de `::`
// compris) exclue, est dans une liste FERMÉE — vide et suivie de `?`, `return`, `match` / `if` en tête
// (seuls, après `return` ou après une affectation admise), ou une affectation `… =` hors comparaison dont
// le lieu ne commence pas par `_` (`let _ =`, `let [mut | ref | ref mut] _nom =`, `let (_nom) =`, `_ =`,
// `(_) =`, attribut ou bras de `match` devant sont des abandons) ; le lieu est celui de la DERNIÈRE
// affectation, lu après le dernier `let`, `=>`, `return` ou `=` intermédiaire (`return _ =`, `let r = _ =`,
// `x = _ =` sont des abandons ; `let _u = r =` lit l'issue dans `r`). Tout autre préfixe est refusé :
// instruction nue sans `?` (même derrière `#[allow(…)]` ou `#[cfg(…)]`), `&…`, comparaison, et tout préfixe
// qui nomme le mot `async` — fermeture `async` sans accolades dont le corps est l'instruction de l'appel
// (`let f = async move || r = …publier(…).await;` compris ; un corps `if … else { … }` est un reste LÂCHE,
// ci-dessous).
// Un site est CONFORME si : (A) lie le `.tmp` par `let` (`let mut` compris ; un `.tmp` non lié, passé
// tel quel à un helper, est refusé), aucune variante `spool::publier…(` n'y figure, CHAQUE appel
// `spool::publier(` de la fonction est conforme (verdict par APPEL : une seconde publication détachée
// dans un site qui publie déjà correctement rougit, qu'elle réutilise `tmp`/`dst` par masquage ou passe
// par un alias du spool), chaque `.tmp` est publié par un appel conforme, la fonction ne réécrit pas
// `ingest_fsync`, et AUCUN geste direct n'y figure. Réécriture : le nom NU (liaison, champ initialisé ou
// abrégé, motif de déstructuration, `ref mut`), le chemin pointé suivi de `=`, `&=`, `|=`, `^=` (y compris
// depuis un groupe : `(st.ingest_fsync, x) = …`, `S { f: st.ingest_fsync, .. } = …`), ou emprunté muable (`&mut …ingest_fsync` — `mem::take`,
// `mem::replace`, `*(&mut …) =` —, `&raw mut`, `addr_of_mut!`).
// L'ensemble NOMMÉ ci-dessous est jugé dans les deux sens : site non nommé -> « forme neuve » ;
// entrée sans site -> « sans objet » (c'est cette seconde branche qui tient l'anti-vacuité).
//
// CE QUE CE TÉMOIN NE TIENT PAS :
//   * un `.tmp` et un `dst` construits par un HELPER hors de la forme reconnue (fonction qui rend le
//     chemin sans `format!` sur `spool` dans le corps du gestionnaire, puis `fs::write` sans jamais
//     nommer `spool`) échappent à (A) et à (B) ;
//   * un geste d'écriture indirect (`tokio::io`, `std::io::copy` sur un descripteur, `File::from` un
//     descripteur brut, un crate tiers) n'est pas dans la liste de (B) ;
//   * un RÉ-EXPORT posé hors du jugement — dans `ingest/spool.rs` lui-même (exclu du corpus), sous `src/tests/`
//     (exclu), ou pour un geste direct dans un fichier du corpus qui ne mentionne pas le spool — puis appelé
//     sous son nouveau nom n'est pas vu : `pub(crate) use std::fs::write as ecrire;` dans un fichier sans
//     spool puis `crate::util::ecrire(&tmp, …)` échappe à (B) ; une fonction en capitales de `spool.rs`
//     (`#[allow(non_snake_case)]`) passerait pour un type ; de même une macro DÉFINIE hors corpus dont le
//     chemin passe par une métavariable, et un ALIAS DE TYPE (`type F = std::fs::File;` puis `F::create`),
//     que (B) ne lit pas ;
//   * l'issue « consommée » est lue sur l'instruction de l'appel : un `match` dont tous les bras ignorent
//     l'erreur passe (`if let Ok(_) = … .await {}` compris), et un `let r = … .await;` dont `r` n'est jamais
//     lu passe (seul un lieu en `_` est lu comme un abandon) ; à l'inverse toute issue passée en argument
//     d'un appel englobant, même un appel qui la lirait, et toute issue attendue dans un bloc `async` même
//     attendu sur place (`async { … .await }.await`) sont refusées (plus strict, aucune forme réelle ainsi),
//     de même tout préfixe hors de la liste fermée : bras `=>`, `else if`, `while`, `let r = &…`, `let ok = x ==
//     …`, `let r: T<U>= …` collé, un chemin absolu `match ::nom::…` (le `::` de tête fait lire `match` comme
//     un segment du chemin) ;
//   * « tel quel » est lu sur le NOM : un `st` re-lié à un état fabriqué ailleurs (`let st =
//     etat_sans_barriere();`) puis `st.ingest_fsync` passe ; seule une réécriture qui nomme
//     `ingest_fsync` est vue, et pas par une méthode à `&mut self` (`st.ingest_fsync.clone_from(&false)`)
//     ni par un pointeur brut fabriqué sans `mut` sur le lieu (`&st.ingest_fsync as *const bool as *mut
//     bool`, comportement indéfini) ;
//   * le `.tmp` est apparié au premier argument par NOM, dans SA fonction : sous masquage (`let tmp = …` deux fois), le
//     premier `.tmp` compte comme publié par l'appel qui prend le second. Sans effet tant que chaque
//     appel `spool::publier(` est jugé, qu'aucune autre référence au module `spool` ni aucun geste direct
//     nommé n'est admis : un `.tmp` jamais publié n'est jamais écrit (aux ré-exports près, ci-dessus) ;
//   * un détachement UN NIVEAU PLUS HAUT n'est pas vu : une fonction intermédiaire qui publie conformément
//     (`async fn aide(st: AppState, …) { … publier(tmp, dst, …, st.ingest_fsync).await … }`, site jugé et
//     conforme) puis que son appelant détache (`tokio::spawn(aide(st, corps))`) — l'appelant ne référence
//     pas le module `spool` ; nommer `aide` dans `SITES_NOMMES` reste exigé (forme neuve sinon) ;
//   * un helper qui recevrait le réglage en paramètre, sous quelque nom que ce soit (`ingest_fsync`
//     compris : nu, ce n'est plus un chemin pointé), serait refusé (plus strict, aucune forme réelle) ;
//   * tolérances du côté STRICT (les retirer refuse davantage) : bord gauche de `trouver`, bord droit de
//     `mentionne_spool` (`st.spool_dir` n'est pas le spool), portée de `spawn…(` (ordre et fin de
//     parenthèse), profondeur des arguments, `->` dans les génériques, `=>` après le chemin pointé du
//     réglage (bras de macro : une lecture), lieu après `mut` arrêté par `=` / `,` (`let mut copie =
//     st.ingest_fsync`) ou par `,` (`trace(&mut journal, st.ingest_fsync)`), bord droit du nom du réglage
//     (`ingest_fsync_compte` n'est pas lui), blancs entre `.` et ce nom (`st. ingest_fsync` reste une
//     lecture), `File :: open` (le dernier segment du geste compte), `br"x"` sans effet, `let (r) =` et
//     `let ref r =` (issue liée sous un nom), `let r =` suivi d'un retour à la ligne (l'instruction est lue de
//     son début), bloc ordinaire (`if c { … }`) hors contexte détaché et corps d'une fonction (accolade rendue
//     par `fonctions`, `async fn` comprise ; une tête sans `fn ` suivi d'un nom, `async fn\nnom`, reste lue comme
//     un bloc `async`) qui ne détachent pas, `$crate::` admis, `spool::<Capitale>`
//     admis, gestes et `spawn` hors fonction jugés seulement dans un fichier qui mentionne le spool, `use
//     tokio::spawn;` non renommé admis hors fonction — chacune épinglée par un témoin de
//     `les_tolerances_du_cote_strict_sont_epinglees`, de `les_reecritures_du_reglage_sont_vues` ou de
//     `les_gestes_ecrits_autrement_et_l_issue_abandonnee_par_motif_rougissent` ou de
//     `l_issue_abandonnee_par_affectation_ou_detachee_hors_spawn_rougit` ou de
//     `l_instruction_nue_et_le_detachement_sur_toute_la_pile_rougissent`. Blancs lus et capture avec format,
//     côté où les retirer laisserait passer : `$m :: `, `fs  as`, `fs` puis retour puis `as`, `fs ::{`,
//     `fs:: {`, `{spool:…}` — épinglés par `les_blancs_et_la_capture_avec_format_sont_lus`. Côté LÂCHE, le lieu qui suit
//     `mut` traverse tout groupe (`&mut (if c { &mut st } else { &mut st }).ingest_fsync`), témoin compris. Mutant
//     ÉQUIVALENT par redondance : exiger `conforme` dans la boucle par `.tmp` (un appel non conforme y est
//     déjà refusé par le verdict par appel, le motif seul change). Mutants ÉQUIVALENTS, qu'aucun Rust valide ne
//     distingue, donc sans témoin : bord droit de `.await` (`.awaitx` n'existe pas), longueur exacte des
//     quatre arguments (un appel à cinq ne compile pas), retrait du `&` sur le DERNIER argument
//     (`&st.ingest_fsync` ne compile pas pour un `bool`), exclusion de `ingest/spool.rs` (il ne rend
//     aucun site). Mutant ÉQUIVALENT par redondance : retirer `sans_attributs` devant une affectation (le
//     lieu est déjà lu après le dernier `let`) — il ne change que `match` / `if` / `return` / vide derrière
//     un attribut, épinglés. Les formes forcées qui distinguent trois mutants de lecture — parenthèses de
//     `sans_cfg_test` (`#[cfg(test)] static … = Lazy::new(|| { … });` dans un `spawn`), égalité stricte avec
//     `return` (`return n == …`, `return _ = …`), branche `#![` de `sans_attributs` (`#![allow(…)]` puis
//     `match`) —, les fermetures `async` à paramètres `{…}` / `;`, `'\''` collé et l'abandon derrière `return`
//     ou un `=` chaîné sont épinglés par `spool_publier_formes_forcees` (fichier voisin), avec leurs voisines
//     conformes : mot `async` borné (`async_r`), mot `return` borné à droite (`let return_code =`), lieu de la
//     dernière affectation (`let _u = r =`) lu après le `=` intermédiaire le plus à droite (`x = y = _ =`
//     refusé), et dans `ouverture_des_parametres` : `|` fermant jamais cherché au-delà d'un `;` (un `if c {`
//     qui suit une fermeture `async` à corps nu) ni d'un `{` / `}` (un `else {` qui suit, dans un champ de
//     structure, une fermeture `async move |a| a`), ni d'un `=>` (un bras qui rend une fermeture `async` à
//     paramètre motif de structure), `)` / `]` comptés en remontant (`|_x: [u8; 2]| -> Result<(), E>`), ouvrant
//     RETENU seulement précédé du mot `move` ou `async` — sans quoi le `|` d'un motif de bras (`K::A | K::B =>`,
//     `K::C | K::D => {`) ou d'un « ou » (`if a | b {` puis `if c | d {`) était lu comme une liste de
//     paramètres et un `async` d'un bras ou d'une condition précédents faisait refuser un `publier` conforme
//     (faux refus RÉALISTE, sondes FP1 à FP7, épinglées acceptées par
//     `les_bras_et_les_ou_qui_suivent_un_async_restent_acceptes`). Mutants ÉQUIVALENTS par redondance avec
//     cette exigence, sans témoin distinctif : l'arrêt de l'ouvrant sur un `;` à profondeur nulle et sur un `{`
//     non apparié (qu'il devienne transparent ou fasse baisser la profondeur) — un ouvrant qui suit `move` /
//     `async` et dont la paire franchit un `;` ou sort d'un bloc enfermerait dans la liste un `;` à profondeur
//     nulle ou un `}` sans ouvrant, ce qu'aucune liste de paramètres ne contient ; le `|` atteint d'abord est
//     alors un fermant, précédé d'un motif, et n'est pas retenu (leurs anciens témoins, `if a | b {` après une
//     fermeture `async` et `A | B =>` après un bloc, restent comme voisines acceptées). Mutant ÉQUIVALENT,
//     sans témoin : l'arrêt du `|` fermant sur un `(` / `[` ouvrant (ce groupe encore ouvert pose déjà un
//     cadre détachant dans `contexte_detache`, qui ne lit que `.is_some()` de la tête) ;
//   * côté STRICT, sans forme réelle : le refus du mot `async` vaut pour tout préfixe qui le nomme ; la tête
//     d'une accolade est lue jusqu'au `;`, `{` ou `}` précédent, donc un bras précédent qui nomme `async` sans
//     accolade (`K::A => run(async || trace().await),` puis `K::C => { … }`) fait lire le bloc du bras suivant
//     comme `async` (antérieur au saut des paramètres, qui ne l'aggrave plus) ; un `=`
//     dans une annotation de type suivi d'un `_` (`let r: Box<dyn Iterator<Item = _>> = …`) est lu comme une
//     affectation intermédiaire, donc comme un abandon ;
//   * côté LÂCHE, sans forme réelle connue, épinglés ACCEPTÉS par `les_restes_laches_declares_sont_encore_acceptes`
//     (fichier voisin) : une fermeture `async` dont le type de retour contient un `{` ou un `}` (bloc constant,
//     `-> Foo<{ 1 }>`) n'est pas reconnue — l'arrêt du `|` fermant sur `{` / `}` coupe sa tête avant `async`,
//     son corps n'est pas lu comme détaché, et un `publier` qu'elle attend puis qu'on détache
//     (`tokio::spawn(f(0))`) passe (la voisine `-> Foo<1>` est refusée) ; un `=` dans l'annotation de type
//     d'un lieu en `_` (`let _r: Box<dyn Iterator<Item = u8>> = …`) déplace le lieu après ce `=` (`u8>>`), et
//     l'abandon passe — aucune annotation à `=` connue ne compile pour l'issue de `publier` ; une fermeture
//     `async` sans accolades dont le corps est un `if c { … } else { …publier… }` (ou `else if d { … }`), détachée
//     (`tokio::spawn(f())`) : l'instruction de l'appel commence au `{` du `else`, son préfixe se réduit à
//     `match`, et le cadre `async` du `if c {` est déjà dépilé (antérieur au lot ; la voisine qui publie dans la
//     branche `if` est refusée) ;
//   * le blanchisseur partagé reste la source des positions : seuls les préfixes de chaîne brute (`br`, `cr`),
//     les littéraux de caractère à échappement long (`'\x..'`, `'\u{…}'`) et l'apostrophe échappée `'\''`
//     (qu'il lit `'\'`, laissant un `'` orphelin) sont neutralisés avant lui ; un autre littéral qu'il
//     apparierait mal (aucun connu à ce jour) déplacerait la pile de `contexte_detache` ;
//   * les deux sites `HORS_RECEPTION` ne sont pas jugés sur leur conformité : seule leur liste de gestes
//     directs est épinglée — un `spool::publier(…, false)` ou un `.tmp` ajouté dans l'une d'elles passerait,
//     et un site qui REMPLACE l'un d'eux sous le même nom dans le même fichier (l'original retiré, un seul
//     site restant) hérite de l'exemption, gestes épinglés compris ;
//   * le régime de base (trois gestionnaires qui écrivent la BASE, `durable:false`) reste hors lot.
// =================================================================================================

mod spool_toute_ecriture_passe_par_publier {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    /// Les sites connus, (fichier relatif à `src/`, fonction). Ensemble jugé dans les deux sens.
    const SITES_NOMMES: &[(&str, &str)] = &[
        ("ingest/firehose.rs", "firehose_ingest_post"),
        ("ingest/hec.rs", "hec_event_post"),
        ("ingest/minio.rs", "ingest_minio_post"),
        ("ingest/minio.rs", "ingest_post"),
        ("ingest/mod.rs", "ingest_journal_post"),
        ("ingest/otlp.rs", "otlp_traces_post"),
        ("ingest/pubsub.rs", "pubsub_ingest_post"),
    ];

    /// Sites HORS RÉCEPTION, (fichier, fonction, gestes directs attendus, raison) : ils écrivent le spool par
    /// un geste direct, mais aucun émetteur externe n'y efface sa copie sur un accusé. Exemptés du jugement de
    /// conformité, PAS de l'ensemble : jugés dans les deux sens comme `SITES_NOMMES` (un site exempté qui
    /// disparaît rend « sans objet »), et leur liste de gestes directs est ÉPINGLÉE (un geste ajouté rougit).
    const HORS_RECEPTION: &[(&str, &str, &[&str], &str)] = &[
        ("state.rs", "remettre_la_quarantaine_en_file", &["fs::rename"], "remise en file de la quarantaine vers le spool, `fs::rename` local d'un lot déjà reçu"),
        ("state.rs", "quarantine_spool_file", &["fs::rename"], "mise à l'écart d'un lot du spool vers la quarantaine"),
    ];

    /// Préfixes : `File::create` couvre `File::create_new`, `fs::symlink` couvre `fs::symlink_dir` ; `OpenOptions`
    /// couvre `new`, `default` (tokio) et le type nommé.
    const GESTES_DIRECTS: &[&str] = &["fs::write", "fs::rename", "fs::copy", "fs::hard_link", "fs::symlink", "fs::soft_link", "File::create", "File::options", "OpenOptions"];

    #[derive(Debug, Clone)]
    struct Site {
        fichier: String,
        fonction: String,
        ligne: usize,
        conforme: bool,
        motif: String,
        /// jetons des gestes directs de la fonction, triés (`fs::write`, `File::create_new`…)
        gestes: Vec<String>,
    }

    fn est_ident(c: char) -> bool {
        c.is_alphanumeric() || c == '_'
    }

    /// Fin (exclue) du groupe ouvert en `ouvre` (`(` ou `{`), par appariement.
    fn fermeture(b: &[char], ouvre: usize) -> Option<usize> {
        let (o, f) = (b[ouvre], if b[ouvre] == '(' { ')' } else { '}' });
        let mut prof = 0i32;
        for (j, &c) in b.iter().enumerate().skip(ouvre) {
            if c == o {
                prof += 1;
            } else if c == f {
                prof -= 1;
                if prof == 0 {
                    return Some(j + 1);
                }
            }
        }
        None
    }

    fn texte(b: &[char], d: usize, f: usize) -> String {
        b[d..f].iter().collect()
    }

    fn ligne_de(b: &[char], pos: usize) -> usize {
        b[..pos].iter().filter(|&&c| c == '\n').count() + 1
    }

    /// Occurrences de `motif` dans `b` (positions en caractères), bornées à gauche par un non-ident
    /// si le motif commence par un caractère d'identifiant.
    fn trouver(b: &[char], motif: &str) -> Vec<usize> {
        let m: Vec<char> = motif.chars().collect();
        let mut v = Vec::new();
        if m.is_empty() || b.len() < m.len() {
            return v;
        }
        for i in 0..=b.len() - m.len() {
            if b[i..i + m.len()] == m[..] && (i == 0 || !est_ident(m[0]) || !est_ident(b[i - 1])) {
                v.push(i);
            }
        }
        v
    }

    /// Mention de la liaison/champ `spool` (pas le chemin de module `spool::`).
    fn mentionne_spool(b: &[char]) -> bool {
        trouver(b, "spool").into_iter().any(|i| {
            let apres = i + 5;
            (apres >= b.len() || !est_ident(b[apres])) && !(apres + 1 < b.len() && b[apres] == ':' && b[apres + 1] == ':')
        })
    }

    /// Capture `{spool}` / `{spool:…}` dans un littéral de format (texte ORIGINAL, non blanchi).
    fn capture_spool(s: &str) -> bool {
        let c: Vec<char> = s.chars().collect();
        trouver(&c, "{spool").into_iter().any(|i| (i == 0 || c[i - 1] != '{') && matches!(c.get(i + 6), Some('}') | Some(':')))
    }

    /// Fin (exclue) du groupe `[…]` ouvert en `ouvre`.
    fn fin_crochet(b: &[char], ouvre: usize) -> usize {
        let mut prof = 0i32;
        for (j, &c) in b.iter().enumerate().skip(ouvre) {
            if c == '[' {
                prof += 1;
            } else if c == ']' {
                prof -= 1;
                if prof == 0 {
                    return j + 1;
                }
            }
        }
        b.len()
    }

    const MOTS_D_ITEM: &[&str] = &["fn", "mod", "struct", "enum", "union", "impl", "use", "const", "static", "type", "trait", "macro_rules", "extern", "async", "unsafe"];

    /// Retire (en blancs, retours conservés) chaque ITEM précédé de `#[cfg(test)]`. Posé sur autre chose
    /// qu'un item (champ, variante, bras, instruction), seul l'attribut est retiré : le code qui suit
    /// reste jugé.
    fn sans_cfg_test(b: &mut [char]) {
        const ATTR: &str = "#[cfg(test)]";
        for d in trouver(b, ATTR) {
            if b[d] != '#' {
                continue; // déjà blanchi par un item englobant
            }
            let mut k = d + ATTR.len();
            loop {
                while k < b.len() && b[k].is_whitespace() {
                    k += 1;
                }
                if k + 1 < b.len() && b[k] == '#' && b[k + 1] == '[' {
                    k = fin_crochet(b, k + 1);
                    continue;
                }
                break;
            }
            if texte(b, k, (k + 3).min(b.len())) == "pub" && !b.get(k + 3).map_or(false, |&c| est_ident(c)) {
                k += 3;
                while k < b.len() && b[k].is_whitespace() {
                    k += 1;
                }
                if k < b.len() && b[k] == '(' {
                    k = fermeture(b, k).unwrap_or(b.len());
                }
                while k < b.len() && b[k].is_whitespace() {
                    k += 1;
                }
            }
            let mot: String = b[k..].iter().take_while(|&&c| est_ident(c)).collect();
            if !MOTS_D_ITEM.contains(&mot.as_str()) {
                for c in &mut b[d..d + ATTR.len()] {
                    *c = ' ';
                }
                continue;
            }
            // fin de l'item : premier `{` ou `;` HORS de tout groupe `(`/`[` (`const A: [u8; 1] = [0];` finit au
            // dernier `;`, pas à celui du type : sinon le `]` laissé en place fermerait un groupe englobant)
            let mut j = d;
            let mut prof = 0i32;
            while j < b.len() && !(prof == 0 && (b[j] == '{' || b[j] == ';')) {
                match b[j] {
                    '(' | '[' => prof += 1,
                    ')' | ']' => prof -= 1,
                    _ => {}
                }
                j += 1;
            }
            let fin = if j < b.len() && b[j] == '{' { fermeture(b, j).unwrap_or(b.len()) } else { (j + 1).min(b.len()) };
            for c in &mut b[d..fin] {
                if *c != '\n' {
                    *c = ' ';
                }
            }
        }
    }

    /// Les fonctions (nom, début de la signature, début du corps, fin du corps) d'un texte blanchi.
    fn fonctions(b: &[char]) -> Vec<(String, usize, usize, usize)> {
        let mut v = Vec::new();
        for i in trouver(b, "fn ") {
            let mut j = i + 3;
            while j < b.len() && b[j].is_whitespace() {
                j += 1;
            }
            let d = j;
            while j < b.len() && est_ident(b[j]) {
                j += 1;
            }
            if d == j {
                continue;
            }
            let nom = texte(b, d, j);
            // la liste de paramètres est sautée : un extracteur `State(AppState { spool, .. })` porte des
            // accolades qui ne sont pas le corps.
            let mut k = j;
            while k < b.len() && b[k].is_whitespace() {
                k += 1;
            }
            if k < b.len() && b[k] == '<' {
                let mut prof = 0i32;
                while k < b.len() {
                    if b[k] == '<' {
                        prof += 1;
                    } else if b[k] == '>' && b[k - 1] != '-' {
                        prof -= 1;
                        if prof == 0 {
                            k += 1;
                            break;
                        }
                    }
                    k += 1;
                }
            }
            while k < b.len() && b[k].is_whitespace() {
                k += 1;
            }
            if k < b.len() && b[k] == '(' {
                k = fermeture(b, k).unwrap_or(b.len());
            }
            while k < b.len() && b[k] != '{' && b[k] != ';' {
                k += 1;
            }
            if k < b.len() && b[k] == '{' {
                if let Some(f) = fermeture(b, k) {
                    v.push((nom, i, k, f));
                }
            }
        }
        v
    }

    /// Nom lié par `let [mut] <nom> =` sur la ligne qui précède `pos`.
    fn liaison_avant(b: &[char], pos: usize) -> Option<String> {
        let mut d = pos;
        while d > 0 && b[d - 1] != '\n' && b[d - 1] != ';' && b[d - 1] != '{' {
            d -= 1;
        }
        let avant = texte(b, d, pos);
        let reste = avant.trim_start().strip_prefix("let ")?;
        let reste = reste.trim_start();
        let reste = reste.strip_prefix("mut ").unwrap_or(reste).trim_start();
        let nom: String = reste.chars().take_while(|&c| est_ident(c)).collect();
        let suite = reste[nom.len()..].trim();
        (!nom.is_empty() && suite == "=").then_some(nom)
    }

    /// Arguments de premier niveau de l'appel dont la parenthèse ouvre en `ouvre`.
    fn arguments(b: &[char], ouvre: usize) -> Vec<String> {
        let fin = fermeture(b, ouvre).unwrap_or(b.len());
        let (mut v, mut cour, mut prof) = (Vec::new(), String::new(), 0i32);
        for &c in &b[ouvre + 1..fin.saturating_sub(1)] {
            match c {
                '(' | '[' | '{' => prof += 1,
                ')' | ']' | '}' => prof -= 1,
                ',' if prof == 0 => {
                    v.push(cour.trim().trim_start_matches('&').trim().to_string());
                    cour.clear();
                    continue;
                }
                _ => {}
            }
            cour.push(c);
        }
        if !cour.trim().is_empty() {
            v.push(cour.trim().trim_start_matches('&').trim().to_string());
        }
        v
    }

    /// Positions (en caractères) du MOT `mot`, borné des deux côtés.
    fn mots(s: &[char], mot: &str) -> Vec<usize> {
        let n = mot.chars().count();
        trouver(s, mot).into_iter().filter(|&i| !s.get(i + n).map_or(false, |&c| est_ident(c))).collect()
    }

    /// Le `|` qui OUVRE la liste de paramètres d'une fermeture dont la tête finit en `k` (avant son `{`) : le
    /// `|` fermant est le premier à profondeur nulle en remontant (type de retour `-> T` traversé), sans
    /// franchir `;`, `{`, `}` ni `=>` (la tête d'un bras de `match` : son motif `K::C | K::D` n'est pas une
    /// liste de paramètres) ; l'ouvrant est le `|` précédent à profondeur nulle, groupes `(`, `[`, `{`
    /// appariés, sans franchir un `;` à profondeur nulle (instruction précédente), et il n'est RETENU que
    /// précédé du mot `move` ou `async` : seule la tête d'une fermeture `async` a besoin du saut, et un `|`
    /// précédé d'autre chose est un « ou » (`if a | b {`, motif `K::A | K::B`) ou le fermant d'une autre
    /// liste. Aucun : `None` (la tête est alors lue depuis `k`, comme sans saut).
    fn ouverture_des_parametres(b: &[char], k: usize) -> Option<usize> {
        let (mut prof, mut m) = (0i32, k);
        let ferme = loop {
            if m == 0 {
                return None;
            }
            m -= 1;
            match b[m] {
                ')' | ']' => prof += 1,
                '(' | '[' if prof == 0 => return None,
                '(' | '[' => prof -= 1,
                ';' | '{' | '}' if prof == 0 => return None,
                '>' if prof == 0 && m > 0 && b[m - 1] == '=' => return None,
                '|' if prof == 0 => break m,
                _ => {}
            }
        };
        let (mut prof, mut m) = (0i32, ferme);
        while m > 0 {
            m -= 1;
            match b[m] {
                ')' | ']' | '}' => prof += 1,
                '(' | '[' | '{' if prof == 0 => return None,
                '(' | '[' | '{' => prof -= 1,
                ';' if prof == 0 => return None,
                '|' if prof == 0 => {
                    let mut d = m;
                    while d > 0 && b[d - 1].is_whitespace() {
                        d -= 1;
                    }
                    let debut = b[..d].iter().rposition(|&c| !est_ident(c)).map_or(0, |i| i + 1);
                    let retenu = matches!(texte(b, debut, d).as_str(), "move" | "async");
                    return retenu.then_some(m);
                }
                _ => {}
            }
        }
        None
    }

    /// Contexte qui DÉTACHE ou ENROBE la position `p`, lu depuis le DÉBUT du fichier et sur TOUTE la pile, pas
    /// seulement sur le cadre le plus interne (un bloc ordinaire `if c { … }` ou `drop({ … })` posé dans un
    /// contexte détaché l'est aussi ; une fonction imbriquée dans un `spawn…(` est détachée aussi, son corps
    /// n'efface pas la pile) : un groupe `(` / `[` encore ouvert — argument d'un appel (`drop(`,
    /// `std::mem::forget(`, `spawn…(`, un helper `detacher(` quel que soit son nom), d'une macro (`m!(`, `m![`),
    /// élément d'un groupe (`[_] = [ … ]`) —, un bloc ou une fermeture `async` à accolades (l'avenir ne
    /// s'exécute que si quelqu'un l'attend : `let f = async move { … }; tokio::spawn(f)`), une macro à
    /// accolades (`m! { … }`). L'accolade qui ouvre le CORPS d'une fonction (`corps_de_fn` : débuts rendus par
    /// `fonctions`) n'en est pas un, `async fn` compris ; le seul MOT `fn` dans la tête n'exempte rien
    /// (`|g: fn()| async move { … }`, `aide as fn()`).
    fn contexte_detache(b: &[char], p: usize, corps_de_fn: &[usize]) -> Option<&'static str> {
        let mut pile: Vec<&'static str> = Vec::new();
        for j in 0..p.min(b.len()) {
            let c = b[j];
            if c == '(' {
                pile.push("argument d'un appel ou d'une macro");
            } else if c == '[' {
                pile.push("élément d'un groupe `[…]`");
            } else if c == '{' {
                let mut k = j;
                while k > 0 && b[k - 1].is_whitespace() {
                    k -= 1;
                }
                // tête d'une fermeture : sa liste de paramètres `|…|` est sautée, un `{…}` ou un `;` qu'elle
                // contient (`|S { a, .. }: S|`, `|_x: [u8; 2]|`) ne coupe pas la tête avant `async`
                let mut t = ouverture_des_parametres(b, k).unwrap_or(k);
                while t > 0 && !matches!(b[t - 1], ';' | '{' | '}') {
                    t -= 1;
                }
                let tete = &b[t..k];
                let mut genre = "";
                if k > 0 && b[k - 1] == '!' {
                    genre = "macro à accolades";
                }
                let corps_de_fonction = corps_de_fn.contains(&j);
                if !mots(tete, "async").is_empty() && !corps_de_fonction {
                    genre = "bloc ou fermeture `async`";
                }
                pile.push(genre);
            } else if matches!(c, ')' | ']' | '}') {
                pile.pop();
            }
        }
        pile.into_iter().rev().find(|g| !g.is_empty())
    }

    /// L'instruction qui précède l'appel (`prefixe`, blancs des bords retirés) ABANDONNE-t-elle l'issue ? Une
    /// affectation `… =` dont le lieu, lu après le dernier `=>` (bras de `match`) puis après le dernier mot
    /// `let` (un attribut peut le précéder), commence par `_` une fois `(`, `[`, `mut`, `ref` sautés :
    /// `let _ =`, `let _issue =`, `let mut _issue =`, `let ref mut _issue =`, `let (_issue) =`, `let _r: T =`,
    /// `_ =` et `(_) =` (affectation déstructurante, sans `let`), `0 => _ =`, `#[allow(…)] let _x =`. Le lieu
    /// est celui de la DERNIÈRE affectation : lu aussi après le dernier `return` et le dernier `=` (`return _ =`,
    /// `let r = _ =`, `x = _ =` abandonnent ; `let _u = r =` lit l'issue dans `r`).
    fn issue_abandonnee(prefixe: &[char]) -> bool {
        let Some((&'=', lieu)) = prefixe.split_last() else { return false };
        let bras = trouver(lieu, "=>").last().map_or(0, |i| i + 2);
        let apres_let = mots(&lieu[bras..], "let").last().map_or(bras, |i| bras + i + 3);
        // le lieu est celui de la DERNIÈRE affectation : lu aussi après `return` et après un `=` intermédiaire
        // (`return _ =`, `let r = _ =`, `x = _ =`) ; le `=` d'un `=>` reste en deçà du bras
        let apres_return = mots(lieu, "return").last().map_or(0, |i| i + 6);
        let apres_egal = lieu.iter().rposition(|&c| c == '=').map_or(0, |i| i + 1);
        let debut = apres_let.max(apres_return).max(apres_egal);
        let mut r: String = lieu[debut..].iter().collect::<String>().trim().to_string();
        loop {
            let avant = r.clone();
            r = r.trim_start_matches(|c: char| c == '(' || c == '[').trim_start().to_string();
            for mot in ["mut", "ref"] {
                if let Some(x) = r.strip_prefix(mot).filter(|x| !x.starts_with(est_ident)) {
                    r = x.trim_start().to_string();
                }
            }
            if r == avant {
                break;
            }
        }
        r.starts_with('_')
    }

    /// `s` privé de chaque attribut `#[…]` / `#![…]` (crochets appariés) : un attribut posé sur l'instruction
    /// (`#[allow(unused_must_use)]`, `#[cfg(not(test))]`, sur la même ligne ou la sienne) ne lit pas l'issue.
    fn sans_attributs(s: &[char]) -> String {
        let mut out = String::new();
        let mut i = 0;
        while i < s.len() {
            let ouvre = if s[i] == '#' && s.get(i + 1) == Some(&'[') {
                Some(i + 1)
            } else if s[i] == '#' && s.get(i + 1) == Some(&'!') && s.get(i + 2) == Some(&'[') {
                Some(i + 2)
            } else {
                None
            };
            match ouvre {
                Some(o) => i = fin_crochet(s, o),
                _ => {
                    out.push(s[i]);
                    i += 1;
                }
            }
        }
        out
    }

    /// L'instruction qui précède l'appel (`prefixe`, de son début jusqu'à la tête du chemin) CONSOMME-t-elle
    /// l'issue ? Liste FERMÉE, attributs retirés d'abord (`sans_attributs`) :
    ///   * rien : instruction nue, consommée seulement par `?` (`propagee`) ;
    ///   * `return` ;
    ///   * `match` ou `if` en tête de l'expression (l'issue y est scrutée ou testée), précédés de rien, de
    ///     `return`, ou d'une affectation admise ci-dessous (`let r = match … {`) ;
    ///   * une affectation `… =` dont le lieu n'est pas en `_` (`issue_abandonnee`) — ni comparaison (`==`,
    ///     `!=`, `<=`, `>=` : la valeur comparée est jetée).
    /// Tout le reste est refusé : `&…`, un opérateur, une tête de chemin, un bras `=>`, `else if`, `let r = &…`.
    fn issue_consommee(prefixe: &[char], propagee: bool) -> bool {
        let p = sans_attributs(prefixe);
        let p = p.trim();
        let affectation_qui_lit = |s: &str| -> bool {
            let comparaison = ["==", "!=", "<=", ">="].iter().any(|c| s.ends_with(c));
            s.ends_with('=') && !comparaison && !issue_abandonnee(&s.chars().collect::<Vec<char>>())
        };
        if p.is_empty() {
            return propagee;
        }
        // fermeture `async` sans accolades (`let f = async move || r = …publier(…).await;`) : l'appel n'est
        // attendu que si quelqu'un appelle la fermeture, et c'est elle qu'on détache (`tokio::spawn(f())`)
        if !mots(&p.chars().collect::<Vec<char>>(), "async").is_empty() {
            return false;
        }
        if p == "return" {
            return true;
        }
        for mot in ["match", "if"] {
            if let Some(reste) = p.strip_suffix(mot).filter(|r| !r.ends_with(est_ident)) {
                let reste = reste.trim_end();
                return reste.is_empty() || reste == "return" || affectation_qui_lit(reste);
            }
        }
        affectation_qui_lit(p)
    }

    /// Début de la tête du chemin qui mène à `spool` en `p` : identifiants et `::`, blancs AUTOUR de `::`
    /// compris (`crate :: ingest :: spool`) — sinon `crate::ingest::` resterait dans le préfixe de l'instruction.
    fn tete_du_chemin(b: &[char], p: usize) -> usize {
        let mut s = p;
        loop {
            while s > 0 && (est_ident(b[s - 1]) || b[s - 1] == ':') {
                s -= 1;
            }
            let mut w = s;
            while w > 0 && b[w - 1].is_whitespace() {
                w -= 1;
            }
            let sep_avant_les_blancs = w >= 2 && b[w - 1] == ':' && b[w - 2] == ':';
            let sep_apres_les_blancs = s + 1 < b.len() && b[s] == ':' && b[s + 1] == ':';
            if w < s && (sep_avant_les_blancs || sep_apres_les_blancs) {
                s = w;
                continue;
            }
            return s;
        }
    }

    /// L'issue de l'appel `spool::publier` (motif en `p`, arguments fermés en `fin_args`) est-elle
    /// attendue (`.await`) DANS le gestionnaire (hors de tout contexte détaché ou enrobant, cf.
    /// `contexte_detache`) et consommée (cf. `issue_consommee` : une fermeture `async` sans accolades, un
    /// attribut seul, un `&` devant ne consomment pas) ? L'instruction est lue de son début (`;`, `{` ou `}`
    /// précédent), retours à la ligne compris : `let _issue` suivi d'un retour avant `=` est vu.
    fn issue_attendue(b: &[char], p: usize, fin_args: usize, corps_de_fn: &[usize]) -> bool {
        let mut a = fin_args;
        while a < b.len() && b[a].is_whitespace() {
            a += 1;
        }
        if texte(b, a, (a + 6).min(b.len())) != ".await" || b.get(a + 6).map_or(false, |&c| est_ident(c)) {
            return false;
        }
        if contexte_detache(b, p, corps_de_fn).is_some() {
            return false;
        }
        let s = tete_du_chemin(b, p);
        let mut l = s;
        while l > 0 && !matches!(b[l - 1], ';' | '{' | '}') {
            l -= 1;
        }
        let prefixe: Vec<char> = texte(b, l, s).trim().chars().collect();
        let q = blancs(b, a + 6);
        issue_consommee(&prefixe, q < b.len() && b[q] == '?')
    }

    /// Le quatrième argument est-il le réglage TEL QUEL : un chemin pointé d'identifiants qui finit par
    /// `.ingest_fsync` (`st.ingest_fsync`) ? Un `ingest_fsync` nu est une liaison locale, pas le réglage.
    fn fsync_tel_quel(a: &str) -> bool {
        let segments: Vec<&str> = a.split('.').collect();
        segments.len() >= 2 && segments.last() == Some(&"ingest_fsync") && segments.iter().all(|s| !s.is_empty() && s.chars().all(est_ident))
    }

    fn blancs(b: &[char], mut k: usize) -> usize {
        while k < b.len() && b[k].is_whitespace() {
            k += 1;
        }
        k
    }

    /// Occurrences d'un geste de `GESTES_DIRECTS` (`fs::write`, `File::create`…), blancs admis autour de
    /// chaque `::` et `>` admis devant (`std::fs:: write`, `File :: create`, `<std::fs::File>::create`) :
    /// (position, jeton sans blancs). Le dernier segment est un PRÉFIXE, que le jeton complète
    /// (`File::create_new`).
    fn trouver_geste(b: &[char], motif: &str) -> Vec<(usize, String)> {
        let segments: Vec<Vec<char>> = motif.split("::").map(|s| s.chars().collect()).collect();
        let mut v = Vec::new();
        'occurrence: for p in trouver(b, motif.split("::").next().unwrap_or(motif)) {
            let mut k = p + segments[0].len();
            for s in &segments[1..] {
                k = blancs(b, k);
                if b.get(k) == Some(&'>') {
                    k = blancs(b, k + 1);
                }
                if texte(b, k, (k + 2).min(b.len())) != "::" {
                    continue 'occurrence;
                }
                k = blancs(b, k + 2);
                if k + s.len() > b.len() || b[k..k + s.len()] != s[..] {
                    continue 'occurrence;
                }
                k += s.len();
            }
            while k < b.len() && est_ident(b[k]) {
                k += 1;
            }
            v.push((p, texte(b, p, k).chars().filter(|&c| !c.is_whitespace() && c != '>').collect()));
        }
        v
    }

    /// `$m` [blancs] `::` hors `$crate` : un chemin de module passé à une macro (`crate::ingest::$m::…`
    /// appelé par `m!(spool, …)`) ; aucun des critères ne lit le chemin réel. Position du `$`.
    fn chemins_par_metavariable(b: &[char]) -> Vec<(usize, String)> {
        trouver(b, "$")
            .into_iter()
            .filter_map(|i| {
                let mut o = i + 1;
                while o < b.len() && est_ident(b[o]) {
                    o += 1;
                }
                let nom = texte(b, i + 1, o);
                let k = blancs(b, o);
                (o > i + 1 && nom != "crate" && texte(b, k, (k + 2).min(b.len())) == "::").then(|| (i, nom))
            })
            .collect()
    }

    /// `src` avec le `b` / `c` d'une chaîne brute `br"…"`, `br#"…"#`, `cr"…"` remplacé par une espace
    /// (positions conservées) : le blanchisseur partagé ne reconnaît une chaîne brute qu'à un `r` précédé
    /// d'un non-identifiant ; sans ce pas, `br"\"` y ouvre une chaîne ordinaire qui masque le code suivant
    /// jusqu'au prochain `"`.
    fn prefixes_bruts_neutralises(src: &str) -> String {
        let mut c: Vec<char> = src.chars().collect();
        for i in 0..c.len().saturating_sub(2) {
            if matches!(c[i], 'b' | 'c') && c[i + 1] == 'r' && matches!(c[i + 2], '"' | '#') && (i == 0 || !est_ident(c[i - 1])) {
                c[i] = ' ';
            }
        }
        c.into_iter().collect()
    }

    /// `src` avec chaque littéral de caractère à échappement long — `'\x29'`, `'\u{29}'` (préfixe `b` compris) —
    /// remplacé par des espaces (positions conservées) : le blanchisseur partagé ne reconnaît que `'x'` et
    /// `'\x'` ; sur un échappement long, il apparie le `'` fermant au suivant (`'\u{41}',')'` laisse le `)` en
    /// place), et un fermant orphelin dépilerait un contexte détaché dans `contexte_detache`.
    fn litteraux_d_echappement_neutralises(src: &str) -> String {
        let mut c: Vec<char> = src.chars().collect();
        let n = c.len();
        let mut i = 0;
        while i + 1 < n {
            if c[i] == '\'' && c[i + 1] == '\\' {
                let chiffres = |d: usize, max: usize, admis: &dyn Fn(char) -> bool| {
                    let mut j = d;
                    while j < n && j - d < max && admis(c[j]) {
                        j += 1;
                    }
                    j
                };
                let fin = match c.get(i + 2) {
                    Some('x') => {
                        let j = chiffres(i + 3, 2, &|x: char| x.is_ascii_hexdigit());
                        (j == i + 5 && c.get(j) == Some(&'\'')).then_some(j)
                    }
                    // `'\''` : le blanchisseur partagé le lit `'\'` et laisse le dernier `'` orphelin, qui apparie
                    // le littéral suivant de travers (`'\'',')'` libère le `)`)
                    Some('\'') => (c.get(i + 3) == Some(&'\'')).then_some(i + 3),
                    Some('u') if c.get(i + 3) == Some(&'{') => {
                        let j = chiffres(i + 4, 8, &|x: char| x.is_ascii_hexdigit() || x == '_');
                        (j > i + 4 && c.get(j) == Some(&'}') && c.get(j + 1) == Some(&'\'')).then_some(j + 1)
                    }
                    _ => None,
                };
                if let Some(f) = fin {
                    for x in &mut c[i..=f] {
                        *x = ' ';
                    }
                    i = f + 1;
                    continue;
                }
            }
            i += 1;
        }
        c.into_iter().collect()
    }

    /// `mot` (borné des deux côtés) suivi de `as`, ou de `::` puis `{` / `*` : renommage ou import groupé
    /// (`use std::fs as f;`, `use std::fs::{write as w};`, `use crate::ingest::spool as sp;`).
    fn alias_ou_groupe(b: &[char], mot: &str) -> Vec<(usize, &'static str)> {
        let n = mot.chars().count();
        trouver(b, mot)
            .into_iter()
            .filter_map(|i| {
                if b.get(i + n).map_or(false, |&c| est_ident(c)) {
                    return None;
                }
                let k = blancs(b, i + n);
                if texte(b, k, (k + 2).min(b.len())) == "as" && !b.get(k + 2).map_or(false, |&c| est_ident(c)) {
                    return Some((i, " as"));
                }
                if texte(b, k, (k + 2).min(b.len())) == "::" {
                    let suite = blancs(b, k + 2);
                    match b.get(suite) {
                        Some('{') => return Some((i, "::{")),
                        Some('*') => return Some((i, "::*")),
                        _ => {}
                    }
                }
                None
            })
            .collect()
    }

    /// Références au MODULE `spool` (`spool` [blancs] `::` [blancs] suite), où qu'elles soient : (position
    /// du mot, ce qui suit — identifiant, ou `{` / `*` —, parenthèse d'appel ouverte juste après).
    fn references_au_module_spool(b: &[char]) -> Vec<(usize, String, Option<usize>)> {
        trouver(b, "spool")
            .into_iter()
            .filter_map(|i| {
                if b.get(i + 5).map_or(false, |&c| est_ident(c)) {
                    return None;
                }
                let k = blancs(b, i + 5);
                if texte(b, k, (k + 2).min(b.len())) != "::" {
                    return None;
                }
                let d = blancs(b, k + 2);
                let mut o = d;
                while o < b.len() && est_ident(b[o]) {
                    o += 1;
                }
                let suite = if o > d { texte(b, d, o) } else { b.get(d).map(|c| c.to_string()).unwrap_or_default() };
                let a = blancs(b, o);
                Some((i, suite, (o > d && a < b.len() && b[a] == '(').then_some(a)))
            })
            .collect()
    }

    /// `spawn…` (`spawn`, `spawn_blocking`, …) NON suivi de `(` : (position, jeton, suivi de `as`). Une valeur
    /// (`let l = tokio::spawn;`) ou un renommage (`use tokio::spawn as lancer;`) : l'appel détaché qui
    /// suivrait sous un autre nom n'est plus vu par `contexte_detache`.
    fn spawn_hors_appel(b: &[char]) -> Vec<(usize, String, bool)> {
        trouver(b, "spawn")
            .into_iter()
            .filter_map(|i| {
                let mut o = i + 5;
                while o < b.len() && est_ident(b[o]) {
                    o += 1;
                }
                let a = blancs(b, o);
                let renomme = texte(b, a, (a + 2).min(b.len())) == "as" && !b.get(a + 2).map_or(false, |&c| est_ident(c));
                (a >= b.len() || b[a] != '(').then(|| (i, texte(b, i, o), renomme))
            })
            .collect()
    }

    /// Position d'une RÉÉCRITURE de `ingest_fsync` dans le corps `[d, f)` :
    ///   * le nom NU (non précédé de `.`) : liaison (`let ingest_fsync =`), champ initialisé ou abrégé
    ///     (`AppState { ingest_fsync: false, ..st }`, `AppState { ingest_fsync, ..st }`), motif de
    ///     déstructuration, `ref mut` — le réglage tel quel est toujours un chemin POINTÉ ;
    ///   * le chemin pointé affecté : `=`, affectation composée (`&=`, `|=`, `^=`), y compris
    ///     depuis un groupe (`(st.ingest_fsync, x) = …`, `(st.ingest_fsync) = …`, `S { f: st.ingest_fsync, .. } = …`) ;
    ///   * le chemin pointé emprunté MUABLE : `&mut st.ingest_fsync` (`mem::take`, `mem::replace`, `mem::swap`,
    ///     `*(&mut …) =`), `&raw mut …`, `addr_of_mut!(…)`.
    /// La lecture (`==`, `!=`, argument, `=>` dans une macro) n'en est pas une.
    fn reecriture_du_fsync(b: &[char], d: usize, f: usize) -> Option<usize> {
        const NOM: &str = "ingest_fsync";
        let n = NOM.len();
        let occurrences: Vec<usize> = trouver(&b[d..f], NOM).into_iter().map(|i| d + i).filter(|&p| !(p + n < f && est_ident(b[p + n]))).collect();
        let car = |j: usize| if j < f { b[j] } else { ' ' };
        let affectee = |p: usize| -> bool {
            let mut q = p;
            while q > d && b[q - 1].is_whitespace() {
                q -= 1;
            }
            if !(q > d && b[q - 1] == '.') {
                return true;
            }
            let mut k = blancs(b, p + n).min(f);
            // sortie des groupes qui enferment le chemin : `(st.ingest_fsync, x) = (false, 1)`, et l'affectation
            // déstructurante d'une structure `Rapport { fsync: st.ingest_fsync, .. } = r;`
            while k < f && matches!(b[k], ')' | ',' | ']' | '}') {
                let mut prof = 0i32;
                while k < f {
                    match b[k] {
                        '(' | '[' | '{' => prof += 1,
                        ')' | ']' | '}' => {
                            if prof == 0 {
                                break;
                            }
                            prof -= 1;
                        }
                        _ => {}
                    }
                    k += 1;
                }
                if k >= f {
                    return false;
                }
                k = blancs(b, k + 1).min(f);
            }
            // `&=`, `|=`, `^=` : les seules affectations composées d'un `bool`
            (car(k) == '=' && car(k + 1) != '=' && car(k + 1) != '>') || ("&|^".contains(car(k)) && car(k + 1) == '=')
        };
        // le LIEU qui suit `mut` / `addr_of_mut!` (identifiants, `.`, `*`, `::`, groupes) nomme-t-il le réglage ?
        let empruntee = |m: usize| -> Option<usize> {
            let mut prof = 0i32;
            for k in m..f {
                match b[k] {
                    '(' | '[' => prof += 1,
                    ')' | ']' => {
                        if prof == 0 {
                            return None;
                        }
                        prof -= 1;
                    }
                    _ if prof > 0 => {}
                    c if est_ident(c) || c.is_whitespace() || matches!(c, '.' | '*' | ':' | '&') => {}
                    _ => return None,
                }
                if occurrences.contains(&k) {
                    return Some(k);
                }
            }
            None
        };
        let par_mut = trouver(&b[d..f], "mut").into_iter().map(|i| d + i).filter(|&p| !(p + 3 < f && est_ident(b[p + 3]))).filter_map(|p| empruntee(p + 3));
        let par_macro = trouver(&b[d..f], "addr_of_mut!").into_iter().filter_map(|i| empruntee(d + i + 12));
        occurrences.iter().copied().filter(|&p| affectee(p)).chain(par_mut).chain(par_macro).min()
    }

    fn analyser(fichier: &str, src: &str) -> Vec<Site> {
        let orig: Vec<char> = src.chars().collect();
        let neutralise = litteraux_d_echappement_neutralises(&prefixes_bruts_neutralises(src));
        let mut b: Vec<char> = super::chemin_masque_sans_permis::blanchir_pub(&neutralise).chars().collect();
        assert_eq!(orig.len(), b.len(), "INSTRUMENT : le dépouilleur doit conserver les positions");
        sans_cfg_test(&mut b);
        let fns = fonctions(&b);
        let corps_de_fn: Vec<usize> = fns.iter().map(|(_, _, d, _)| *d).collect();
        // fonction la plus INTERNE qui contient une position
        let englobante = |pos: usize| {
            let dedans = fns.iter().filter(|(_, _, d, f)| *d <= pos && pos < *f);
            dedans.min_by_key(|(_, _, d, f)| f - d).cloned()
        };
        // un fichier qui mentionne le spool : ses imports et valeurs HORS fonction sont jugés aussi
        let fichier_concerne = mentionne_spool(&b);
        let mut hors_fonction: Vec<(usize, String)> = Vec::new();
        let refs_spool = references_au_module_spool(&b);
        // seuls `spool::publier(` (appel jugé) et `spool::<Capitale>` (type, variante, constante) sont admis
        let admise = |suite: &str| suite.chars().next().map_or(false, |c| c.is_uppercase());
        let motif_reference = |suite: &str, ouvre: Option<usize>, p: usize| match ouvre {
            Some(_) => format!("appel `spool::{suite}(` ligne {} : seul `spool::publier(…).await` est admis", ligne_de(&b, p)),
            None => format!("référence `spool::{suite}` ligne {} hors appel (import, valeur, groupe) : seul `spool::publier(…).await` est admis", ligne_de(&b, p)),
        };

        #[derive(Default)]
        struct Etat {
            tmp: Vec<(Option<String>, usize)>,
            dst: Vec<String>,
            gestes: Vec<(String, usize)>,
            publier: Vec<(Vec<String>, bool, usize)>,
            interdits: Vec<String>,
            fsync_reecrit: Option<usize>,
            nom: String,
            debut: usize,
        }
        /// L'état d'une fonction est rangé par sa PLAGE (début du corps), jamais par son nom : deux fonctions
        /// homonymes d'un même fichier (`mod v2`, deux `impl`, fonction imbriquée) sont jugées chacune sur
        /// leur propre plage, et un `.tmp` n'est apparié qu'aux appels de SA fonction.
        fn entree<'a>(m: &'a mut std::collections::BTreeMap<usize, Etat>, nom: &str, d: usize) -> &'a mut Etat {
            m.entry(d).or_insert_with(|| Etat { nom: nom.to_string(), debut: d, ..Default::default() })
        }
        let mut par_fn: std::collections::BTreeMap<usize, Etat> = Default::default();

        for p in trouver(&b, "format!") {
            let mut o = p + 7;
            while o < b.len() && b[o].is_whitespace() {
                o += 1;
            }
            if o >= b.len() || b[o] != '(' {
                continue;
            }
            let Some(f) = fermeture(&b, o) else { continue };
            if !mentionne_spool(&b[o..f]) && !capture_spool(&texte(&orig, o, f)) {
                continue;
            }
            let Some((nom, _, d, fin_fn)) = englobante(p) else { continue };
            let a_tmp = texte(&orig, o, f).contains(".tmp");
            if !a_tmp && !refs_spool.iter().any(|(q, s, o)| d <= *q && *q < fin_fn && s.starts_with("publier") && o.is_some()) {
                continue; // `format!` sans `.tmp` hors d'une fonction qui publie : diagnostic, pas une écriture
            }
            let e = entree(&mut par_fn, &nom, d);
            if a_tmp {
                e.tmp.push((liaison_avant(&b, p), p));
            } else if let Some(n) = liaison_avant(&b, p) {
                e.dst.push(n);
            }
        }
        // (B) gestes directs. Le motif est un PRÉFIXE (`File::create` couvre `File::create_new`), sans `(`
        // exigé : une valeur (`let w = std::fs::write;`) ou un import (`use std::fs::write;`) compte. `fs`
        // renommé ou importé en groupe (`use std::fs as f;`, `use std::fs::{…}`) compte aussi.
        let mut gestes: Vec<(usize, String)> = Vec::new();
        for g in GESTES_DIRECTS {
            gestes.extend(trouver_geste(&b, g));
        }
        for (p, forme) in alias_ou_groupe(&b, "fs") {
            gestes.push((p, format!("fs{forme}")));
        }
        // `File` renommé (`use std::fs::File as F;` puis `F::create`) : `File::create` n'est plus écrit
        for (p, _) in alias_ou_groupe(&b, "File").into_iter().filter(|(_, forme)| *forme == " as") {
            gestes.push((p, "File as".to_string()));
        }
        for (p, jeton) in gestes {
            match englobante(p) {
                Some((nom, sig, d, f)) => {
                    if mentionne_spool(&b[sig..f]) {
                        entree(&mut par_fn, &nom, d).gestes.push((jeton, p));
                    }
                }
                None if fichier_concerne => hors_fonction.push((p, format!("geste direct `{jeton}` ligne {} hors fonction (import, valeur)", ligne_de(&b, p)))),
                None => {}
            }
        }
        // (C) toute référence au module `spool` autre que `spool::publier(` et `spool::<Capitale>` : une
        // variante (`publier_bloquant`), une autre fonction, un import (`use …::spool::publier_bloquant;`,
        // `use …::spool::{…}`, `spool::*`), une valeur (`let f = …::spool::publier_bloquant;`), un renommage
        // (`spool as sp`). Dans une fonction, elle en fait un site non conforme ; hors fonction, elle est
        // refusée d'office, dans tout fichier du corpus. Tout appelant de `spool::publier(` est un site, même
        // si ses chemins passent par un alias local du spool (`let sp = st.spool.clone()`).
        for (p, suite, ouvre) in &refs_spool {
            if admise(suite.as_str()) {
                continue;
            }
            match englobante(*p) {
                Some((nom, _, d, _)) => {
                    entree(&mut par_fn, &nom, d);
                }
                None => hors_fonction.push((*p, motif_reference(suite.as_str(), *ouvre, *p))),
            }
        }
        for (p, _) in alias_ou_groupe(&b, "spool").into_iter().filter(|(_, forme)| *forme == " as") {
            let motif = format!("renommage `spool as` ligne {} : seul `spool::publier(…).await` est admis", ligne_de(&b, p));
            match englobante(p) {
                Some((nom, _, d, _)) => entree(&mut par_fn, &nom, d).interdits.push(motif),
                None => hors_fonction.push((p, motif)),
            }
        }
        // chemin de module par métavariable de macro (`crate::ingest::$m::publier_bloquant`, `m!(spool, …)`) :
        // refusé dans tout fichier du corpus, comme une référence interdite au module `spool`
        for (p, nom) in chemins_par_metavariable(&b) {
            let motif = format!("chemin par métavariable `${nom}::` ligne {} : un module passé à une macro n'est pas jugé", ligne_de(&b, p));
            match englobante(p) {
                Some((nom, _, d, _)) => entree(&mut par_fn, &nom, d).interdits.push(motif),
                None => hors_fonction.push((p, motif)),
            }
        }
        // `spawn…` renommé hors fonction, dans un fichier qui mentionne le spool
        if fichier_concerne {
            for (p, jeton, renomme) in spawn_hors_appel(&b) {
                if renomme && englobante(p).is_none() {
                    hors_fonction.push((p, format!("renommage `{jeton} as` ligne {} : un appel détaché sous un autre nom n'est pas vu", ligne_de(&b, p))));
                }
            }
        }
        for e in par_fn.values_mut() {
            let (_, _, d, f) = fns.iter().find(|(_, _, d, _)| *d == e.debut).cloned().expect("fonction connue");
            for (p, suite, ouvre) in refs_spool.iter().filter(|r| d <= r.0 && r.0 < f) {
                match (suite.as_str(), ouvre) {
                    (s, _) if admise(s) => {}
                    ("publier", Some(o)) => {
                        let fin_args = fermeture(&b, *o).unwrap_or(b.len());
                        e.publier.push((arguments(&b, *o), issue_attendue(&b, *p, fin_args, &corps_de_fn), *p));
                    }
                    // `publier_bloquant(…)`, toute autre fonction, import, valeur : seul `publier(…).await` est admis
                    _ => e.interdits.push(motif_reference(suite.as_str(), *ouvre, *p)),
                }
            }
            // `spawn…` en valeur ou renommé dans un site : l'appel détaché sous un autre nom ne serait pas vu
            for (p, jeton, _) in spawn_hors_appel(&b).into_iter().filter(|r| d <= r.0 && r.0 < f) {
                e.interdits.push(format!("`{jeton}` ligne {} hors appel (valeur, renommage) : un appel détaché sous un autre nom n'est pas vu", ligne_de(&b, p)));
            }
            e.fsync_reecrit = reecriture_du_fsync(&b, d, f);
        }

        let mut sites: Vec<Site> = par_fn
            .into_values()
            .map(|e| {
                let pos = e.tmp.first().map(|t| t.1).or(e.gestes.first().map(|g| g.1)).unwrap_or(e.debut);
                let mut motifs = Vec::new();
                if let Some((g, p)) = e.gestes.first() {
                    motifs.push(format!("geste direct `{g}` ligne {}", ligne_de(&b, *p)));
                }
                if e.tmp.is_empty() {
                    motifs.push("écrit vers le spool sans chemin `.tmp` reconnu".to_string());
                }
                if let Some(p) = e.fsync_reecrit {
                    motifs.push(format!("réglage `ingest_fsync` réécrit dans la fonction ligne {}", ligne_de(&b, p)));
                }
                let noms_tmp: Vec<&String> = e.tmp.iter().filter_map(|(t, _)| t.as_ref()).collect();
                // CHAQUE appel est jugé, pas seulement « un appel par `.tmp` » : une seconde publication
                // détachée ou sans barrière, dans un site qui publie déjà correctement, se juge elle-même.
                let conforme = |a: &Vec<String>, attendue: bool| -> Result<(), &'static str> {
                    if a.len() != 4 {
                        return Err("pas quatre arguments");
                    }
                    if !noms_tmp.contains(&&a[0]) {
                        return Err("premier argument qui n'est pas un `.tmp` du spool lié par `let`");
                    }
                    if !e.dst.contains(&a[1]) {
                        return Err("second argument qui n'est pas un chemin du spool lié par `let`");
                    }
                    if !fsync_tel_quel(&a[3]) {
                        return Err("quatrième argument qui n'est pas le réglage `….ingest_fsync` tel quel");
                    }
                    if !attendue {
                        return Err("issue non attendue dans le gestionnaire (argument d'un appel, `spawn…(`, bloc `async`, macro) ou abandonnée");
                    }
                    Ok(())
                };
                for (a, attendue, p) in &e.publier {
                    if let Err(raison) = conforme(a, *attendue) {
                        motifs.push(format!("appel `spool::publier(` ligne {} : {raison}", ligne_de(&b, *p)));
                    }
                }
                motifs.extend(e.interdits.iter().cloned());
                for (t, p) in &e.tmp {
                    let ok = match t {
                        None => false,
                        Some(t) => e.publier.iter().any(|(a, attendue, _)| a.len() >= 2 && &a[0] == t && conforme(a, *attendue).is_ok()),
                    };
                    if !ok {
                        motifs.push(format!(
                            "`.tmp` ligne {} ({}) non publié par `spool::publier(tmp, dst, _, …ingest_fsync).await` dont l'issue est consommée",
                            ligne_de(&b, *p),
                            t.as_deref().unwrap_or("non lié par let")
                        ));
                    }
                }
                Site {
                    fichier: fichier.to_string(),
                    fonction: e.nom.clone(),
                    ligne: ligne_de(&b, pos),
                    conforme: motifs.is_empty(),
                    motif: motifs.join(" ; "),
                    gestes: {
                        let mut g: Vec<String> = e.gestes.iter().map(|(j, _)| j.clone()).collect();
                        g.sort();
                        g
                    },
                }
            })
            .collect();
        if !hors_fonction.is_empty() {
            hors_fonction.sort();
            sites.push(Site {
                fichier: fichier.to_string(),
                fonction: "(hors fonction)".to_string(),
                ligne: ligne_de(&b, hors_fonction[0].0),
                conforme: false,
                motif: hors_fonction.into_iter().map(|(_, m)| m).collect::<Vec<_>>().join(" ; "),
                gestes: Vec::new(),
            });
        }
        sites
    }

    fn corpus() -> Vec<(String, String)> {
        let racine = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        fn marcher(dir: &Path, v: &mut Vec<PathBuf>) {
            let mut es: Vec<_> = std::fs::read_dir(dir)
                .unwrap_or_else(|e| panic!("INSTRUMENT : {} illisible : {e}", dir.display()))
                .map(|e| e.expect("INSTRUMENT : entrée illisible").path())
                .collect();
            es.sort();
            for p in es {
                if p.is_dir() {
                    marcher(&p, v);
                } else if p.extension().map_or(false, |x| x == "rs") {
                    v.push(p);
                }
            }
        }
        // tout `src/` : un gestionnaire axum vit aussi à la racine (`scim.rs`, `sigma.rs`), une huitième surface
        // posée là est jugée ; `tests/` (témoins, inclus sous `#[cfg(test)]`) et `ingest/spool.rs` exceptés
        let mut chemins = Vec::new();
        marcher(&racine, &mut chemins);
        let mut v = Vec::new();
        for p in chemins {
            let rel = p.strip_prefix(&racine).unwrap().to_string_lossy().replace('\\', "/");
            if rel == "ingest/spool.rs" || rel.starts_with("tests/") {
                continue;
            }
            let src = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("INSTRUMENT : {rel} illisible : {e}"));
            v.push((rel, src));
        }
        assert!(v.len() > 20, "INSTRUMENT : corpus anormalement petit ({} fichiers)", v.len());
        v
    }

    // ---------------------------------------------------------------------------------------------
    // ÉPREUVES DE L'INSTRUMENT, sur extraits FABRIQUÉS.
    // ---------------------------------------------------------------------------------------------

    pub(super) const NOMINAL: &str = r#"
pub(crate) async fn recu_post(st: AppState, corps: Vec<u8>) -> Response {
    let n = 1;
    let tmp = format!("{}/.r-{}-{}.tmp", st.spool, now(), n);
    let dst = format!("{}/r-{}-{}.json", st.spool, now(), n);
    match crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await {
        Ok(p) => ok(p),
        Err(_) => ko(),
    }
}
"#;

    #[test]
    fn la_forme_nominale_est_un_site_conforme() {
        let s = analyser("ingest/fab.rs", NOMINAL);
        assert_eq!(s.len(), 1, "{s:?}");
        assert_eq!(s[0].fonction, "recu_post");
        assert_eq!(s[0].ligne, 4, "le verdict nomme la ligne du `.tmp`");
        assert!(s[0].conforme, "{s:?}");
    }

    #[test]
    fn la_forme_en_commentaire_en_chaine_ou_sous_cfg_test_ne_compte_pas() {
        let commentaire = "fn a(st: AppState) {\n    // let tmp = format!(\"{}/.x.tmp\", st.spool); std::fs::write(&tmp, b\"\");\n    /* std::fs::rename(&tmp, &dst); */\n    let _ = st.spool.len();\n}\n";
        assert!(analyser("ingest/fab.rs", commentaire).is_empty(), "commentaire compté");
        let chaine = "fn b() {\n    let doc = \"let tmp = format!(\\\"{}/.x.tmp\\\", st.spool); std::fs::write(&tmp, x)\";\n    let r = r#\"std::fs::rename(&tmp, &st.spool)\"#;\n}\n";
        assert!(analyser("ingest/fab.rs", chaine).is_empty(), "chaîne comptée");
        let sous_test = "#[cfg(test)]\nmod t {\n    fn c(st: AppState) {\n        let tmp = format!(\"{}/.x.tmp\", st.spool);\n        std::fs::write(&tmp, b\"\").unwrap();\n    }\n}\n#[cfg(test)]\nfn d(st: AppState) { let tmp = format!(\"{}/.y.tmp\", st.spool); std::fs::write(&tmp, b\"\").unwrap(); }\n";
        assert!(analyser("ingest/fab.rs", sous_test).is_empty(), "item cfg(test) compté");
    }

    #[test]
    fn un_neuvieme_gestionnaire_sans_publier_rougit() {
        let neuf = "pub(crate) async fn neuf_post(st: AppState, body: String) {\n    let tmp = format!(\"{}/.neuf-{}.tmp\", st.spool, now());\n    let dst = format!(\"{}/neuf-{}.json\", st.spool, now());\n    let _ = std::fs::write(&tmp, body);\n    let _ = std::fs::rename(&tmp, &dst);\n}\n";
        let s = analyser("ingest/fab.rs", neuf);
        assert_eq!(s.len(), 1, "{s:?}");
        assert!(!s[0].conforme, "{s:?}");
        assert!(s[0].motif.contains("geste direct") && s[0].motif.contains("non publié"), "{}", s[0].motif);
    }

    #[test]
    fn publier_avec_d_autres_chemins_ou_un_geste_direct_en_plus_rougit() {
        let permute = NOMINAL.replace("publier(tmp, dst,", "publier(dst, tmp,");
        assert!(!analyser("ingest/fab.rs", &permute)[0].conforme, "arguments permutés acceptés");
        let autre = NOMINAL.replace("publier(tmp, dst,", "publier(autre, dst,");
        assert!(!analyser("ingest/fab.rs", &autre)[0].conforme, "autre `.tmp` accepté");
        let en_plus = NOMINAL.replace("    match crate", "    let _ = std::fs::rename(&tmp, &dst);\n    match crate");
        let s = analyser("ingest/fab.rs", &en_plus);
        assert!(!s[0].conforme && s[0].motif.contains("fs::rename"), "{s:?}");
        // geste direct vers le spool SANS chemin `.tmp` reconnu (forme (B))
        let direct = "fn e(st: AppState, c: &[u8]) { let p = chemin(&st.spool); std::fs::write(p, c).ok(); }\n";
        let s = analyser("handlers/fab.rs", direct);
        assert_eq!(s.len(), 1, "{s:?}");
        assert!(!s[0].conforme, "{s:?}");
        // lecture seule de `st.spool` (métriques) : pas un site
        assert!(analyser("handlers/fab.rs", "fn m(st: AppState) -> String { st.spool.as_str().to_string() }\n").is_empty());
    }

    /// Un gestionnaire fabriqué qui recopie l'ancien geste : `fs::write` du `.tmp` puis `fs::rename`.
    const ANCIEN_GESTE: &str = "pub(crate) async fn neuf_post(st: AppState, body: String) {\n    let tmp = format!(\"{}/.neuf-{}.tmp\", st.spool, now());\n    let dst = format!(\"{}/neuf-{}.json\", st.spool, now());\n    let _ = std::fs::write(&tmp, body);\n    let _ = std::fs::rename(&tmp, &dst);\n}\n";

    fn un_site_fautif(src: &str, nom: &str) -> Site {
        let s = analyser("ingest/fab.rs", src);
        let site = s.iter().find(|x| x.fonction == nom).cloned().unwrap_or_else(|| panic!("`{nom}` non vu comme site : {s:?}"));
        assert!(!site.conforme, "{site:?}");
        site
    }

    #[test]
    fn un_chemin_de_spool_en_capture_ou_un_spool_en_signature_est_vu() {
        // C3 : utilitaire, `spool` en paramètre, chemins par capture `{spool}` (forme de state.rs et ingest/mod.rs)
        let c3 = "fn ecrire_au_spool(spool: &str, n: u64, corps: &[u8]) {\n    let tmp = format!(\"{spool}/.neuf-{n}.tmp\");\n    let dst = format!(\"{spool}/neuf-{n}.json\");\n    std::fs::write(&tmp, corps).ok();\n    std::fs::rename(&tmp, &dst).ok();\n}\n";
        let s = un_site_fautif(c3, "ecrire_au_spool");
        assert!(s.motif.contains("non publié"), "capture `{{spool}}` non lue comme `.tmp` : {}", s.motif);
        assert!(s.motif.contains("geste direct"), "`spool` en signature non lu : {}", s.motif);
        // C3b : extracteur `State(AppState { spool, .. })`
        let c3b = "pub(crate) async fn neuf_post(State(AppState { spool, .. }): State<AppState>, n: u64, body: String) {\n    let tmp = format!(\"{spool}/.neuf-{n}.tmp\");\n    let dst = format!(\"{spool}/neuf-{n}.json\");\n    let _ = std::fs::write(&tmp, body);\n    let _ = std::fs::rename(&tmp, &dst);\n}\n";
        let s = un_site_fautif(c3b, "neuf_post");
        assert!(s.motif.contains("geste direct") && s.motif.contains("non publié"), "{}", s.motif);
        // forme nominale par capture : vue, et conforme
        let capture = NOMINAL
            .replace("format!(\"{}/.r-{}-{}.tmp\", st.spool, now(), n)", "format!(\"{spool}/.r-{n}.tmp\")")
            .replace("format!(\"{}/r-{}-{}.json\", st.spool, now(), n)", "format!(\"{spool}/r-{n}.json\")")
            .replace("st: AppState,", "st: AppState, spool: &str,");
        let s = analyser("ingest/fab.rs", &capture);
        assert_eq!(s.len(), 1, "forme nominale par capture non vue : {s:?}");
        assert!(s[0].conforme, "{s:?}");
        // diagnostic : `format!` sur `{spool}` sans `.tmp` dans une fonction qui ne publie pas (ingest/mod.rs, `ingest_once`)
        let diag = "fn ingest_once(spool: &str) -> String {\n    match std::fs::read_dir(spool) { Ok(_) => String::new(), Err(e) => format!(\"spool {spool} : {e}\") }\n}\n";
        assert!(analyser("ingest/fab.rs", diag).is_empty(), "diagnostic compté comme écriture");
    }

    #[test]
    fn un_cfg_test_sur_un_champ_ou_imbrique_ne_masque_pas_le_code_qui_suit() {
        // C10 : `#[cfg(test)]` sur un champ, puis un gestionnaire de production
        let champ = format!("struct Sonde {{\n    #[cfg(test)]\n    temoin: u8,\n}}\n{ANCIEN_GESTE}");
        un_site_fautif(&champ, "neuf_post");
        // sur un bras de `match` (forme de query_exec.rs)
        let bras = format!("fn choix(x: u8) -> u8 {{\n    match x {{\n        #[cfg(test)]\n        0 => 1,\n        _ => 2,\n    }}\n}}\n{ANCIEN_GESTE}");
        un_site_fautif(&bras, "neuf_post");
        // sur un champ public
        let public = format!("struct Sonde {{\n    #[cfg(test)] pub(crate) temoin: u8,\n}}\n{ANCIEN_GESTE}");
        un_site_fautif(&public, "neuf_post");
        // `#[cfg(test)]` IMBRIQUÉ dans un module `#[cfg(test)]` déjà retiré
        let imbrique = format!("#[cfg(test)]\nmod t {{\n    #[cfg(test)]\n    fn aide() {{}}\n}}\n{ANCIEN_GESTE}");
        un_site_fautif(&imbrique, "neuf_post");
        // l'item `#[cfg(test)]` lui-même reste retiré, attributs intercalés compris
        let item = "#[cfg(test)]\n#[allow(dead_code)]\npub(crate) fn d(st: AppState) { let tmp = format!(\"{}/.y.tmp\", st.spool); std::fs::write(&tmp, b\"\").unwrap(); }\n";
        assert!(analyser("ingest/fab.rs", item).is_empty(), "item cfg(test) compté");
    }

    #[test]
    fn chaque_geste_direct_et_chaque_condition_de_publier_est_exigee() {
        // les gestes de (B), un par un ; le jeton rendu est le chemin complet (le motif est un préfixe)
        for (g, appel) in [
            ("fs::write", "std::fs::write(&p, c).ok();"),
            ("fs::rename", "std::fs::rename(&p, &p).ok();"),
            ("fs::copy", "std::fs::copy(&p, &p).ok();"),
            ("fs::hard_link", "std::fs::hard_link(&p, &p).ok();"),
            ("fs::symlink", "std::os::unix::fs::symlink(&p, &p).ok();"),
            ("fs::soft_link", "std::fs::soft_link(&p, &p).ok();"),
            ("File::create", "std::fs::File::create(&p).ok();"),
            ("File::create_new", "std::fs::File::create_new(&p).ok();"),
            ("File::create_buffered", "std::fs::File::create_buffered(&p).ok();"),
            ("File::options", "std::fs::File::options().create(true).write(true).open(&p).ok();"),
            ("OpenOptions", "std::fs::OpenOptions::new().write(true).open(&p).ok();"),
            ("OpenOptions", "let _ = tokio::fs::OpenOptions::default().write(true).open(&p);"),
        ] {
            let src = format!("fn e(st: AppState, c: &[u8]) {{\n    let p = chemin(&st.spool);\n    {appel}\n}}\n");
            let s = un_site_fautif(&src, "e");
            assert!(s.motif.contains(&format!("geste direct `{g}` ligne 3")), "{g} : {}", s.motif);
        }
        // second argument : un chemin qui n'est pas un `format!(… spool …)` lié par `let`
        let dst_hors_spool = NOMINAL.replace("format!(\"{}/r-{}-{}.json\", st.spool, now(), n)", "format!(\"/var/lib/autre/r-{}.json\", n)");
        assert!(!analyser("ingest/fab.rs", &dst_hors_spool)[0].conforme, "dst hors spool accepté");
        let dst_appel = NOMINAL.replace("publier(tmp, dst,", "publier(tmp, chemin_final(),");
        assert!(!analyser("ingest/fab.rs", &dst_appel)[0].conforme, "dst non lié accepté");
        // site nommé régressé vers un chemin final sans `.tmp`
        let sans_tmp = NOMINAL.replace(".r-{}-{}.tmp", ".r-{}-{}.json");
        let s = un_site_fautif(&sans_tmp, "recu_post");
        assert!(s.motif.contains("sans chemin `.tmp`"), "{}", s.motif);
        // quatrième argument : `false` en dur saute les deux barrières
        let sans_fsync = NOMINAL.replace("st.ingest_fsync)", "false)");
        un_site_fautif(&sans_fsync, "recu_post");
        // issue non attendue ou ignorée
        let spawn = NOMINAL.replace(
            "    match crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await {\n        Ok(p) => ok(p),\n        Err(_) => ko(),\n    }\n",
            "    tokio::spawn(crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync));\n    ok(())\n",
        );
        assert_ne!(spawn, NOMINAL, "INSTRUMENT : substitution sans effet");
        un_site_fautif(&spawn, "recu_post");
        let ignoree = spawn.replace(
            "tokio::spawn(crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync));",
            "let _ = crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await;",
        );
        un_site_fautif(&ignoree, "recu_post");
        let nue = spawn.replace(
            "tokio::spawn(crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync));",
            "crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await;",
        );
        un_site_fautif(&nue, "recu_post");
        let propagee = spawn.replace(
            "tokio::spawn(crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync));",
            "crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await?;",
        );
        assert!(analyser("ingest/fab.rs", &propagee)[0].conforme, "`?` refusé");
        // l'issue attendue DANS un bloc `async` détaché par `spawn` : l'accusé part avant les barrières
        let appel = "    match crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await {\n        Ok(p) => ok(p),\n        Err(_) => ko(),\n    }\n";
        for (nom, forme) in [
            ("spawn async + if let", "    tokio::spawn(async move {\n        if let Err(e) = crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await { warn(e) }\n    });\n    ok(())\n"),
            ("spawn async + let r", "    tokio::spawn(async move {\n        let r = crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await;\n        trace(r);\n    });\n    ok(())\n"),
            ("spawn_local", "    tokio::task::spawn_local(async move {\n        let r = crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await;\n        trace(r);\n    });\n    ok(())\n"),
            // l'avenir lié sans `.await` : jamais exécuté
            ("let fut sans await", "    let fut = crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync);\n    ok(())\n"),
            // l'issue attendue puis jetée
            ("drop", "    drop(crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await);\n    ok(())\n"),
            ("let _issue", "    let _issue = crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await;\n    ok(())\n"),
            // quatrième argument qui n'est pas le réglage tel quel
            ("!ingest_fsync", "    match crate::ingest::spool::publier(tmp, dst, corps, !st.ingest_fsync).await {\n        Ok(p) => ok(p),\n        Err(_) => ko(),\n    }\n"),
        ] {
            let v = NOMINAL.replace(appel, forme);
            assert_ne!(v, NOMINAL, "INSTRUMENT : substitution sans effet ({nom})");
            let s = analyser("ingest/fab.rs", &v);
            assert!(s.iter().any(|x| x.fonction == "recu_post" && !x.conforme), "{nom} accepté : {s:?}");
        }
        // un `let` nommé qui consomme l'issue reste accepté
        let liee = NOMINAL.replace(appel, "    let r = crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await;\n    rendre(r)\n");
        assert_ne!(liee, NOMINAL, "INSTRUMENT : substitution sans effet");
        assert!(analyser("ingest/fab.rs", &liee)[0].conforme, "`let r =` refusé");
    }

    #[test]
    fn un_appelant_de_publier_par_alias_ou_un_gestionnaire_generique_est_vu() {
        // (C) alias local du spool, `false` en dur : aucun `format!` ne nomme `spool`
        let alias = "pub(crate) async fn alias_post(st: AppState, corps: Vec<u8>) -> Response {\n    let sp = st.spool.clone();\n    let tmp = format!(\"{}/.a.tmp\", sp);\n    let dst = format!(\"{}/a.json\", sp);\n    match crate::ingest::spool::publier(tmp, dst, corps, false).await {\n        Ok(p) => ok(p),\n        Err(_) => ko(),\n    }\n}\n";
        let s = un_site_fautif(alias, "alias_post");
        assert!(s.motif.contains("sans chemin `.tmp`"), "{}", s.motif);
        // (C) étendu aux variantes : alias du spool + `spool::publier_bloquant(…, false)` (pub(crate),
        // synchrone, réglage en dur) — sans l'extension, aucun des trois critères ne le voit
        let bloquant = alias.replace("alias_post", "bloquant_post").replace(
            "match crate::ingest::spool::publier(tmp, dst, corps, false).await {",
            "match crate::ingest::spool::publier_bloquant(&tmp, &dst, &corps, false) {",
        );
        assert_ne!(bloquant, alias, "INSTRUMENT : substitution sans effet");
        let s = un_site_fautif(&bloquant, "bloquant_post");
        assert!(s.motif.contains("appel `spool::publier_bloquant(` ligne 5"), "{}", s.motif);
        // la variante est refusée d'elle-même, même en seconde publication dans un site par ailleurs conforme
        let seconde = NOMINAL.replace("    match crate", "    let _r = crate::ingest::spool::publier_bloquant(&tmp, &dst, &corps, st.ingest_fsync);\n    match crate");
        assert_ne!(seconde, NOMINAL, "INSTRUMENT : substitution sans effet");
        let s = un_site_fautif(&seconde, "recu_post");
        assert!(s.motif == "appel `spool::publier_bloquant(` ligne 6 : seul `spool::publier(…).await` est admis", "{}", s.motif);
        // `File::create_new` vers un chemin FINAL du spool, en direct ou par alias
        let cree = "pub(crate) async fn x1_post(st: AppState, c: Vec<u8>) {\n    let dst = format!(\"{}/x1-{}.json\", st.spool, now());\n    let mut f = std::fs::File::create_new(&dst).unwrap();\n    f.write_all(&c).ok();\n}\n";
        let s = un_site_fautif(cree, "x1_post");
        assert!(s.motif.contains("geste direct `File::create_new` ligne 3"), "{}", s.motif);
        let cree_alias = cree.replace("    let dst = format!(\"{}/x1-{}.json\", st.spool, now());", "    let sp = st.spool.clone();\n    let dst = format!(\"{}/x1-{}.json\", sp, now());");
        assert_ne!(cree_alias, cree, "INSTRUMENT : substitution sans effet");
        let s = un_site_fautif(&cree_alias, "x1_post");
        assert!(s.motif.contains("geste direct `File::create_new` ligne 4"), "{}", s.motif);
        // gestionnaire GÉNÉRIQUE : `<…>` sauté avant la liste de paramètres, sinon les accolades de
        // l'extracteur sont prises pour le corps et le corps réel n'appartient à aucune fonction
        let generique = "pub(crate) async fn neuf_post<S: Clone + Send>(State(AppState { spool, .. }): State<AppState>, n: u64, body: String) {\n    let tmp = format!(\"{spool}/.neuf-{n}.tmp\");\n    let dst = format!(\"{spool}/neuf-{n}.json\");\n    let _ = std::fs::write(&tmp, body);\n    let _ = std::fs::rename(&tmp, &dst);\n}\n";
        let s = un_site_fautif(generique, "neuf_post");
        assert!(s.motif.contains("geste direct"), "{}", s.motif);
    }

    #[test]
    fn les_tolerances_de_l_instrument_sont_epinglees() {
        // le chemin de module `spool::` n'est pas une mention du champ
        let module = "fn lire(st: AppState) { let n = crate::ingest::spool::TAILLE_MAX; std::fs::write(\"/var/x\", n.to_string()).ok(); }\n";
        assert!(analyser("handlers/fab.rs", module).is_empty(), "`spool::` lu comme le champ");
        // la fonction la plus INTERNE porte le geste
        let imbriquee = NOMINAL.replace("    let n = 1;\n", "    let n = 1;\n    fn interne(st: &AppState) { std::fs::write(&st.spool, b\"\").ok(); }\n");
        let s = analyser("ingest/fab.rs", &imbriquee);
        assert!(s.iter().any(|x| x.fonction == "recu_post" && x.conforme), "{s:?}");
        assert!(s.iter().any(|x| x.fonction == "interne" && !x.conforme), "{s:?}");
        // `let tmp = f(format!(…))` n'est pas une liaison du `.tmp`
        let enrobee = NOMINAL.replace("let tmp = format!(\"{}/.r-{}-{}.tmp\", st.spool, now(), n);", "let tmp = enrobe(format!(\"{}/.r-{}-{}.tmp\", st.spool, now(), n));");
        assert_ne!(enrobee, NOMINAL, "INSTRUMENT : substitution sans effet");
        assert!(!analyser("ingest/fab.rs", &enrobee)[0].conforme, "liaison enrobée acceptée");
        // un `.tmp` du spool NON LIÉ par `let`, passé tel quel à un helper (aucun appel de `publier` dans
        // la fonction : seule la boucle par `.tmp` peut le refuser)
        let non_lie = "pub(crate) async fn x6_post(st: AppState, c: Vec<u8>) {\n    ecrire_ailleurs(format!(\"{}/.x6-{}.tmp\", st.spool, now()), c);\n}\n";
        let s = un_site_fautif(non_lie, "x6_post");
        assert!(s.motif.contains("(non lié par let) non publié"), "{}", s.motif);
        // `publier(&tmp, &dst, …)` : la référence ne change pas les chemins
        let refs = NOMINAL.replace("publier(tmp, dst,", "publier(&tmp, &dst,");
        assert!(analyser("ingest/fab.rs", &refs)[0].conforme, "`&tmp` refusé");
        // `let mut tmp =` est une liaison
        let muable = NOMINAL.replace("let tmp = format!", "let mut tmp = format!");
        assert_ne!(muable, NOMINAL, "INSTRUMENT : substitution sans effet");
        assert!(analyser("ingest/fab.rs", &muable)[0].conforme, "`let mut tmp` refusé");
        // `{{spool}}` (accolade échappée) et `{spool_dir}` ne sont pas une capture de `spool`
        let echappe = "fn f(n: u64) -> String { let p = format!(\"{{spool}}/.x-{n}.tmp\"); p }\n";
        assert!(analyser("ingest/fab.rs", echappe).is_empty(), "`{{{{spool}}}}` lu comme capture");
        let autre = "fn g(spool_dir: &str) -> String { let p = format!(\"{spool_dir}/.x.tmp\"); p }\n";
        assert!(analyser("ingest/fab.rs", autre).is_empty(), "`{{spool_dir}}` lu comme capture");
    }

    /// Verdict par APPEL, issue et réglage contournés, sur extraits fabriqués. Chaque variante est jugée
    /// et les acceptées sont TOUTES nommées (un seul passage dit lesquelles ont lâché).
    #[test]
    fn chaque_appel_de_publier_est_juge_et_l_issue_ou_le_reglage_contournes_rougissent() {
        let ancre = "    let tmp = format!(\"{}/.r-";
        let appel = "    match crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await {\n        Ok(p) => ok(p),\n        Err(_) => ko(),\n    }\n";
        let avant = |insertion: &str| NOMINAL.replacen(ancre, &format!("{insertion}{ancre}"), 1);
        let rouges: &[(&str, String, &str)] = &[
            // seconde publication détachée, `tmp`/`dst` réutilisés par MASQUAGE : le `.tmp` final est publié
            // correctement, l'appel détaché doit se juger lui-même
            (
                "masquage + spawn + false",
                avant("    let tmp = format!(\"{}/.r-copie-{}.tmp\", st.spool, n);\n    let dst = format!(\"{}/r-copie-{}.json\", st.spool, n);\n    tokio::spawn(crate::ingest::spool::publier(tmp, dst, Vec::new(), false));\n"),
                "ligne 6 : quatrième argument",
            ),
            (
                "masquage + false attendu",
                avant("    let tmp = format!(\"{}/.r-copie-{}.tmp\", st.spool, n);\n    let dst = format!(\"{}/r-copie-{}.json\", st.spool, n);\n    let r = crate::ingest::spool::publier(tmp, dst, Vec::new(), false).await;\n"),
                "quatrième argument",
            ),
            (
                "masquage + spawn avec le réglage",
                avant("    let tmp = format!(\"{}/.r-copie-{}.tmp\", st.spool, n);\n    let dst = format!(\"{}/r-copie-{}.json\", st.spool, n);\n    tokio::spawn(crate::ingest::spool::publier(tmp, dst, Vec::new(), st.ingest_fsync));\n"),
                "issue non attendue",
            ),
            // seconde publication par un ALIAS du spool
            (
                "alias + spawn + false",
                avant("    let sp = st.spool.clone();\n    let t2 = format!(\"{}/.r-b-{}.tmp\", sp, n);\n    let d2 = format!(\"{}/r-b-{}.json\", sp, n);\n    tokio::spawn(crate::ingest::spool::publier(t2, d2, Vec::new(), false));\n"),
                "premier argument",
            ),
            // l'issue abandonnée
            ("let mut _issue", NOMINAL.replace(appel, "    let mut _issue = crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await;\n    ok(())\n"), "issue non attendue"),
            ("std::mem::forget", NOMINAL.replace(appel, "    std::mem::forget(crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await);\n    ok(())\n"), "issue non attendue"),
            ("enrobage", NOMINAL.replace(appel, "    ignorer(crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await);\n    ok(())\n"), "issue non attendue"),
            // le réglage pas tel quel
            (
                "let ingest_fsync = false local",
                NOMINAL.replace("    let n = 1;\n", "    let n = 1;\n    let ingest_fsync = false;\n").replace("st.ingest_fsync).await", "ingest_fsync).await"),
                "quatrième argument",
            ),
            (
                "ingest_fsync nu reçu en paramètre",
                NOMINAL.replace("corps: Vec<u8>) -> Response", "corps: Vec<u8>, ingest_fsync: bool) -> Response").replace("st.ingest_fsync).await", "ingest_fsync).await"),
                "quatrième argument",
            ),
            ("st.ingest_fsync = false", NOMINAL.replace("    let n = 1;\n", "    let mut st = st;\n    st.ingest_fsync = false;\n    let n = 1;\n"), "réécrit"),
            ("AppState { ingest_fsync: false, ..st }", NOMINAL.replace("    let n = 1;\n", "    let st = AppState { ingest_fsync: false, ..st };\n    let n = 1;\n"), "réécrit"),
        ];
        let mut acceptees = Vec::new();
        for (nom, v, attendu) in rouges {
            assert_ne!(v, NOMINAL, "INSTRUMENT : substitution sans effet ({nom})");
            let s = analyser("ingest/fab.rs", v);
            match s.iter().find(|x| x.fonction == "recu_post") {
                Some(x) if !x.conforme && x.motif.contains(attendu) => {}
                autre => acceptees.push(format!("{nom} : {autre:?}")),
            }
        }
        assert!(acceptees.is_empty(), "variante(s) acceptée(s) ou refusée(s) pour une autre raison : {acceptees:#?}");
        // contrôles : une seconde publication CONFORME, une lecture du réglage, restent acceptées
        for (nom, v) in [
            (
                "seconde publication conforme",
                avant("    let t3 = format!(\"{}/.r-c-{}.tmp\", st.spool, n);\n    let d3 = format!(\"{}/r-c-{}.json\", st.spool, n);\n    if let Err(e) = crate::ingest::spool::publier(t3, d3, Vec::new(), st.ingest_fsync).await { return ko(e); }\n"),
            ),
            ("lecture du réglage", NOMINAL.replace("    let n = 1;\n", "    let n = 1;\n    if st.ingest_fsync == false { avertir(); }\n")),
        ] {
            assert_ne!(v, NOMINAL, "INSTRUMENT : substitution sans effet ({nom})");
            let s = analyser("ingest/fab.rs", &v);
            assert!(s.len() == 1 && s[0].conforme, "{nom} refusé : {s:?}");
        }
    }

    /// Les mêmes contournements, appliqués EN MÉMOIRE aux gestionnaires réels (corpus lu, rien d'écrit).
    /// Le gestionnaire intact est conforme d'abord : le rouge vient de la variante, pas du fichier.
    #[test]
    fn les_variantes_des_gestionnaires_reels_rougissent() {
        let racine = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let lire = |rel: &str| std::fs::read_to_string(racine.join(rel)).unwrap_or_else(|e| panic!("INSTRUMENT : {rel} illisible : {e}"));
        let jugement = |rel: &str, src: &str, fonction: &str| analyser(rel, src).into_iter().find(|x| x.fonction == fonction);
        // un import hors fonction rend le FICHIER fautif (site `(hors fonction)`), pas la fonction
        let fichier_fautif = |rel: &str, src: &str| analyser(rel, src).into_iter().filter(|x| !x.conforme).collect::<Vec<_>>();
        let pub_hec = "    let tmp = format!(\"{}/.hec-";
        let match_corps = "    match crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await {";
        let variantes: &[(&str, &str, &str, &[(&str, &str)])] = &[
            (
                "H_shadow",
                "ingest/hec.rs",
                "hec_event_post",
                &[(pub_hec, "    let tmp = format!(\"{}/.hec-copie-{}.tmp\", st.spool, n);\n    let dst = format!(\"{}/hec-copie-{}.json\", st.spool, n);\n    tokio::spawn(crate::ingest::spool::publier(tmp, dst, Vec::new(), false));\n    let tmp = format!(\"{}/.hec-")],
            ),
            (
                "H_alias2",
                "ingest/hec.rs",
                "hec_event_post",
                &[(pub_hec, "    let sp = st.spool.clone();\n    let t2 = format!(\"{}/.hec-b-{}.tmp\", sp, n);\n    let d2 = format!(\"{}/hec-b-{}.json\", sp, n);\n    tokio::spawn(crate::ingest::spool::publier(t2, d2, Vec::new(), false));\n    let tmp = format!(\"{}/.hec-")],
            ),
            (
                "H_letmut",
                "ingest/otlp.rs",
                "otlp_traces_post",
                &[(match_corps, "    let mut _issue = crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await;\n    match () {")],
            ),
            (
                "H_forget",
                "ingest/minio.rs",
                "ingest_minio_post",
                &[(match_corps, "    std::mem::forget(crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await);\n    match () {")],
            ),
            (
                "H_localfsync",
                "ingest/minio.rs",
                "ingest_post",
                &[
                    ("    let tmp = format!(\"{}/.ingest-", "    let ingest_fsync = false;\n    let tmp = format!(\"{}/.ingest-"),
                    ("body.into_bytes(), st.ingest_fsync).await", "body.into_bytes(), ingest_fsync).await"),
                ],
            ),
            (
                "H_hardlink",
                "ingest/minio.rs",
                "ingest_post",
                &[("    match crate::ingest::spool::publier(tmp, dst, body.into_bytes()", "    let _ = std::fs::hard_link(&tmp, &dst);\n    match crate::ingest::spool::publier(tmp, dst, body.into_bytes()")],
            ),
            // réglage désarmé par affectation composée
            ("H_etegal", "ingest/hec.rs", "hec_event_post", &[(pub_hec, "    let mut st = st;\n    st.ingest_fsync &= false;\n    let tmp = format!(\"{}/.hec-")]),
            ("H_memtake", "ingest/otlp.rs", "otlp_traces_post", &[(match_corps, "    let mut st = st;\n    let _ = std::mem::take(&mut st.ingest_fsync);\n    match crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await {")]),
            // seconde publication sans barrière par `publier_bloquant` IMPORTÉ, appel nu, aucun alias du spool
            (
                "H_bloquant_nu",
                "ingest/minio.rs",
                "ingest_post",
                &[
                    ("pub(crate) async fn ingest_post(", "use crate::ingest::spool::publier_bloquant;\npub(crate) async fn ingest_post("),
                    ("    match crate::ingest::spool::publier(tmp, dst, body.into_bytes()", "    let d2 = format!(\"{}/copie.json\", st.spool);\n    let _ = publier_bloquant(&tmp, &d2, body.as_bytes(), false);\n    match crate::ingest::spool::publier(tmp, dst, body.into_bytes()"),
                ],
            ),
            // geste direct écrit avec des blancs autour de `::`, ou `File` en chemin qualifié
            ("H_fs_blancs", "ingest/hec.rs", "hec_event_post", &[(pub_hec, "    let d2 = format!(\"{}/copie.json\", st.spool);\n    let _ = std::fs:: write(&d2, b\"\");\n    let tmp = format!(\"{}/.hec-")]),
            ("H_file_qualifie", "ingest/hec.rs", "hec_event_post", &[(pub_hec, "    let d2 = format!(\"{}/copie.json\", st.spool);\n    let _ = <std::fs::File>::create(&d2);\n    let tmp = format!(\"{}/.hec-")]),
            // `br"\"` qui désynchroniserait le blanchisseur et masquerait la variante qui suit
            ("H_br", "ingest/hec.rs", "hec_event_post", &[(pub_hec, "    let _sep = br\"\\\";\n    let _r = crate::ingest::spool::publier_bloquant(&tmp, &dst, &corps, false); // \"\n    let tmp = format!(\"{}/.hec-")]),
            // la même par valeur de fonction, dans la fonction
            (
                "H_bloquant_valeur",
                "ingest/minio.rs",
                "ingest_post",
                &[("    match crate::ingest::spool::publier(tmp, dst, body.into_bytes()", "    let f = crate::ingest::spool::publier_bloquant;\n    let _ = f(&tmp, &dst, body.as_bytes(), false);\n    match crate::ingest::spool::publier(tmp, dst, body.into_bytes()")],
            ),
        ];
        let mut acceptees = Vec::new();
        for (nom, rel, fonction, subs) in variantes {
            let mut src = lire(rel);
            let intact = jugement(rel, &src, fonction).unwrap_or_else(|| panic!("INSTRUMENT : {rel}::{fonction} n'est plus un site"));
            assert!(intact.conforme, "INSTRUMENT : {rel}::{fonction} intact déjà refusé : {intact:?}");
            assert!(fichier_fautif(rel, &src).is_empty(), "INSTRUMENT : {rel} intact déjà refusé : {:?}", fichier_fautif(rel, &src));
            for (ancre, nouveau) in subs.iter() {
                assert_eq!(src.matches(ancre).count(), 1, "INSTRUMENT : ancre {ancre:?} absente ou multiple dans {rel} ({nom})");
                src = src.replacen(ancre, nouveau, 1);
            }
            match jugement(rel, &src, fonction) {
                Some(x) if !x.conforme => {}
                _ if !fichier_fautif(rel, &src).is_empty() => {}
                autre => acceptees.push(format!("{nom} ({rel}::{fonction}) : {autre:?}")),
            }
        }
        assert!(acceptees.is_empty(), "variante(s) d'un gestionnaire réel acceptée(s) : {acceptees:#?}");
    }

    /// Tolérances du côté STRICT : les retirer refuserait davantage. Épinglées pour qu'un changement
    /// les déplace en le disant.
    #[test]
    fn les_tolerances_du_cote_strict_sont_epinglees() {
        // bord gauche de `trouver` : `st.monspool` n'est pas le spool
        assert!(analyser("handlers/fab.rs", "fn h(st: AppState) { let n = st.monspool.len(); std::fs::write(\"/var/x\", n.to_string()).ok(); }\n").is_empty(), "`monspool` lu comme `spool`");
        // bord droit de `mentionne_spool` : `st.spool_dir` n'est pas le spool
        assert!(analyser("handlers/fab.rs", "fn k(st: AppState) { std::fs::write(&st.spool_dir, b\"\").ok(); }\n").is_empty(), "`spool_dir` lu comme `spool`");
        // portée de `spawn…(` : un `spawn` FERMÉ avant l'appel, ou ouvert APRÈS, ne le détache pas
        let spawn_avant = NOMINAL.replace("    let n = 1;\n", "    tokio::spawn(trace());\n    let n = 1;\n");
        assert_ne!(spawn_avant, NOMINAL, "INSTRUMENT : substitution sans effet");
        assert!(analyser("ingest/fab.rs", &spawn_avant)[0].conforme, "spawn fermé avant l'appel lu comme englobant");
        let spawn_apres = NOMINAL.replace("        Err(_) => ko(),\n    }\n", "        Err(_) => ko(),\n    };\n    tokio::spawn(trace());\n");
        assert_ne!(spawn_apres, NOMINAL, "INSTRUMENT : substitution sans effet");
        assert!(analyser("ingest/fab.rs", &spawn_apres)[0].conforme, "spawn ouvert après l'appel lu comme englobant");
        // profondeur des arguments : une virgule DANS un argument ne coupe pas
        let imbrique = NOMINAL.replace("publier(tmp, dst, corps,", "publier(tmp, dst, concat(a, b),");
        assert_ne!(imbrique, NOMINAL, "INSTRUMENT : substitution sans effet");
        assert!(analyser("ingest/fab.rs", &imbrique)[0].conforme, "virgule imbriquée comptée comme séparateur");
        // `->` dans les génériques n'en ferme pas la liste
        let fleche = "pub(crate) async fn neuf_post<F: Fn() -> u8>(State(AppState { spool, .. }): State<AppState>, n: u64, body: String) {\n    let tmp = format!(\"{spool}/.neuf-{n}.tmp\");\n    let dst = format!(\"{spool}/neuf-{n}.json\");\n    let _ = std::fs::write(&tmp, body);\n    let _ = std::fs::rename(&tmp, &dst);\n}\n";
        let s = un_site_fautif(fleche, "neuf_post");
        assert!(s.motif.contains("geste direct"), "{}", s.motif);
    }

    /// Jugement d'un extrait : tous les verdicts non conformes, motifs joints (site de la fonction et
    /// `(hors fonction)` confondus).
    pub(super) fn refus(src: &str) -> String {
        analyser("ingest/fab.rs", src).into_iter().filter(|x| !x.conforme).map(|x| format!("[{}] {}", x.fonction, x.motif)).collect::<Vec<_>>().join(" | ")
    }

    /// Évasions par le MODULE `spool` sans chemin `spool::publier…(` qualifié, dans un site par ailleurs
    /// conforme : import puis appel nu, valeur de fonction, renommage du module, import groupé, glob, autre
    /// fonction du module. Chaque variante est jugée ; les acceptées sont TOUTES nommées.
    #[test]
    fn les_references_au_module_spool_hors_appel_de_publier_rougissent() {
        let appel = "    match crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await {";
        let seconde = |avant: &str, nu: &str| format!("{avant}{}", NOMINAL.replacen(appel, &format!("{nu}\n{appel}"), 1));
        let rouges: Vec<(&str, String, &str)> = vec![
            ("use publier_bloquant + appel nu", seconde("use crate::ingest::spool::publier_bloquant;\n", "    let _r = publier_bloquant(&tmp, &dst, &corps, false);"), "[(hors fonction)] référence `spool::publier_bloquant` ligne 1 hors appel"),
            ("use dans la fonction + appel nu", seconde("", "    use crate::ingest::spool::publier_bloquant;\n    let _r = publier_bloquant(&tmp, &dst, &corps, false);"), "[recu_post] référence `spool::publier_bloquant` ligne 6 hors appel"),
            (
                "masquage + appel nu",
                seconde("use crate::ingest::spool::publier_bloquant;\n", "    let tmp = format!(\"{}/.r-copie.tmp\", st.spool);\n    let _r = publier_bloquant(&tmp, &dst, &corps, false);"),
                "[(hors fonction)] référence `spool::publier_bloquant` ligne 1",
            ),
            ("use publier renommé", seconde("use crate::ingest::spool::publier as p;\n", "    let _r = p(tmp, dst, corps, false).await;"), "référence `spool::publier` ligne 1 hors appel"),
            ("valeur publier_bloquant", seconde("", "    let f = crate::ingest::spool::publier_bloquant;\n    let _r = f(&tmp, &dst, &corps, false);"), "[recu_post] référence `spool::publier_bloquant` ligne 6 hors appel"),
            ("valeur publier", seconde("", "    let f = crate::ingest::spool::publier;\n    let _r = f(tmp, dst, corps, false).await;"), "[recu_post] référence `spool::publier` ligne 6 hors appel"),
            ("renommage du module hors fonction", seconde("use crate::ingest::spool as sp;\n", "    let _r = sp::publier_bloquant(&tmp, &dst, &corps, false);"), "[(hors fonction)] renommage `spool as` ligne 1"),
            ("renommage du module dans la fonction", seconde("", "    use crate::ingest::spool as sp;\n    let _r = sp::publier_bloquant(&tmp, &dst, &corps, false);"), "[recu_post] renommage `spool as` ligne 6"),
            ("import groupé", seconde("use crate::ingest::spool::{publier_bloquant};\n", "    let _r = publier_bloquant(&tmp, &dst, &corps, false);"), "référence `spool::{` ligne 1"),
            ("glob", seconde("use crate::ingest::spool::*;\n", "    let _r = publier_bloquant(&tmp, &dst, &corps, false);"), "référence `spool::*` ligne 1"),
            ("blancs autour de ::", seconde("", "    let _r = crate::ingest::spool :: publier_bloquant(&tmp, &dst, &corps, false);"), "appel `spool::publier_bloquant(` ligne 6"),
            (
                "autre fonction du module vers un chemin final",
                "pub(crate) async fn x2_post(st: AppState, c: Vec<u8>) {\n    let dst = format!(\"{}/x2.json\", st.spool);\n    crate::ingest::spool::ecrire(&dst, &c);\n}\n".to_string(),
                "appel `spool::ecrire(` ligne 3 : seul",
            ),
        ];
        let mut acceptees = Vec::new();
        for (nom, v, attendu) in &rouges {
            let r = refus(v);
            if !r.contains(attendu) {
                acceptees.push(format!("{nom} : attendu {attendu:?}, rendu {r:?}"));
            }
        }
        assert!(acceptees.is_empty(), "référence(s) au module `spool` acceptée(s) : {acceptees:#?}");
        // contrôle : `spool::EchecSpool::…` (type, forme des gestionnaires réels) reste admis
        let type_admis = NOMINAL.replace("        Err(_) => ko(),", "        Err(crate::ingest::spool::EchecSpool::Ecriture) => ko(),\n        Err(_) => ko(),");
        assert_ne!(type_admis, NOMINAL, "INSTRUMENT : substitution sans effet");
        assert_eq!(refus(&type_admis), "", "`spool::EchecSpool` refusé");
    }

    /// Réécritures du réglage qui nomment `ingest_fsync`, et lectures qui n'en sont pas.
    #[test]
    fn les_reecritures_du_reglage_sont_vues() {
        let avant = |insertion: &str| NOMINAL.replace("    let n = 1;\n", &format!("    let mut st = st;\n{insertion}\n    let n = 1;\n"));
        let rouges = [
            ("&=", avant("    st.ingest_fsync &= false;")),
            ("^=", avant("    st.ingest_fsync ^= true;")),
            ("|=", avant("    st.ingest_fsync |= false;")),
            ("mem::take", avant("    let _ = std::mem::take(&mut st.ingest_fsync);")),
            ("mem::replace", avant("    let _ = std::mem::replace(&mut st.ingest_fsync, false);")),
            ("*(&mut …) =", avant("    *(&mut st.ingest_fsync) = false;")),
            ("mem::swap sur (*st)", avant("    let mut faux = false;\n    std::mem::swap(&mut (*st).ingest_fsync, &mut faux);")),
            ("&raw mut", avant("    unsafe { std::ptr::write(&raw mut st.ingest_fsync, false) };")),
            ("addr_of_mut!", avant("    unsafe { std::ptr::write(std::ptr::addr_of_mut!(st.ingest_fsync), false) };")),
            // le lieu traverse un groupe qui contient des caractères hors du lieu (`if`, accolades)
            ("&mut (if … { &mut st } …).ingest_fsync", avant("    let c = vrai();\n    let _ = std::mem::take(&mut (if c { &mut st } else { &mut st }).ingest_fsync);")),
            ("groupe = …", avant("    let mut x = 0;\n    (st.ingest_fsync, x) = (false, 1);")),
            ("(…) = …", avant("    (st.ingest_fsync) = false;")),
            ("déstructuration muable", avant("    let AppState { ingest_fsync, .. } = &mut st;\n    *ingest_fsync = false;")),
            ("ref mut", avant("    let AppState { ref mut ingest_fsync, .. } = st;\n    *ingest_fsync = false;")),
            ("affectation déstructurante d'une structure", avant("    Rapport { fsync: st.ingest_fsync, .. } = r;")),
            ("affectation déstructurante, dernier champ", avant("    Rapport { fsync: st.ingest_fsync } = r;")),
            ("champ abrégé", NOMINAL.replace("corps: Vec<u8>) -> Response", "corps: Vec<u8>, ingest_fsync: bool) -> Response").replace("    let n = 1;\n", "    let st = AppState { ingest_fsync, ..st };\n    let n = 1;\n")),
        ];
        let mut acceptees = Vec::new();
        for (nom, v) in &rouges {
            assert_ne!(v, NOMINAL, "INSTRUMENT : substitution sans effet ({nom})");
            let r = refus(v);
            if !r.contains("réglage `ingest_fsync` réécrit") {
                acceptees.push(format!("{nom} : {r:?}"));
            }
        }
        assert!(acceptees.is_empty(), "réécriture(s) du réglage acceptée(s) : {acceptees:#?}");
        // lectures, tolérances du côté STRICT : chacune reste conforme
        for (nom, v) in [
            ("== / !=", avant("    if st.ingest_fsync == false || st.ingest_fsync != true { avertir(); }")),
            ("& en lecture", avant("    let b = st.ingest_fsync & vrai();")),
            ("=> dans une macro", avant("    consigner!(st.ingest_fsync => \"barrières\");")),
            ("let mut copie =", avant("    let mut copie = st.ingest_fsync;\n    copie = !copie;")),
            ("&mut voisin", avant("    trace(&mut journal, st.ingest_fsync);")),
            ("tuple lu", avant("    let v = (st.ingest_fsync, 1);")),
            ("champ d'une structure littérale", avant("    let r = Rapport { fsync: st.ingest_fsync, n: 1 };")),
            // bord droit du nom : `ingest_fsync_compte` n'est pas le réglage
            ("ingest_fsync_compte", avant("    let ingest_fsync_compte = 0;")),
            // blancs entre `.` et le nom : toujours le chemin pointé, lu
            ("st. ingest_fsync", avant("    let lu = st. ingest_fsync;")),
        ] {
            assert_ne!(v, NOMINAL, "INSTRUMENT : substitution sans effet ({nom})");
            assert_eq!(refus(&v), "", "{nom} lu comme une réécriture");
        }
    }

    /// Gestes directs écrits autrement (import puis appel nu, `fs` renommé ou groupé, valeur de fonction,
    /// `OpenOptions::default`, `soft_link`) et `spawn` renommé ou en valeur.
    #[test]
    fn les_gestes_et_spawn_importes_renommes_ou_en_valeur_rougissent() {
        let appel = "    match crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await {";
        let ajout = |avant: &str, dans: &str| format!("{avant}{}", NOMINAL.replacen(appel, &format!("{dans}\n{appel}"), 1));
        let rouges = [
            ("use fs::write + appel nu", ajout("use std::fs::write;\n", "    let _ = write(&tmp, &corps);"), "[(hors fonction)] geste direct `fs::write` ligne 1 hors fonction"),
            ("use fs::write dans la fonction", ajout("", "    use std::fs::write;\n    let _ = write(&tmp, &corps);"), "[recu_post] geste direct `fs::write` ligne 6"),
            ("fs as hors fonction", ajout("use std::fs as f;\n", "    let _ = f::write(&tmp, &corps);"), "[(hors fonction)] geste direct `fs as` ligne 1"),
            ("fs as dans la fonction", ajout("", "    use tokio::fs as f;\n    let _ = f::write(&tmp, &corps).await;"), "[recu_post] geste direct `fs as` ligne 6"),
            ("fs::{…}", ajout("use std::fs::{rename as r};\n", "    let _ = r(&tmp, &dst);"), "[(hors fonction)] geste direct `fs::{` ligne 1"),
            ("fs::*", ajout("use std::fs::*;\n", "    let _ = rename(&tmp, &dst);"), "[(hors fonction)] geste direct `fs::*` ligne 1"),
            ("valeur fs::write", ajout("", "    let w = std::fs::write;\n    let _ = w(&tmp, &corps);"), "[recu_post] geste direct `fs::write` ligne 6"),
            ("OpenOptions::default", ajout("", "    let _ = tokio::fs::OpenOptions::default().write(true).open(&tmp).await;"), "[recu_post] geste direct `OpenOptions` ligne 6"),
            ("soft_link", ajout("", "    let _ = std::fs::soft_link(&tmp, &dst);"), "[recu_post] geste direct `fs::soft_link` ligne 6"),
            ("spawn renommé hors fonction", ajout("use tokio::spawn as lancer;\n", "    lancer(async move { let r = crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await; trace(r); });"), "[(hors fonction)] renommage `spawn as` ligne 1"),
            ("spawn en valeur", ajout("", "    let lancer = tokio::spawn;"), "[recu_post] `spawn` ligne 6 hors appel"),
            ("spawn_blocking renommé dans la fonction", ajout("", "    use tokio::task::spawn_blocking as b;"), "[recu_post] `spawn_blocking` ligne 6 hors appel"),
        ];
        let mut acceptees = Vec::new();
        for (nom, v, attendu) in &rouges {
            let r = refus(v);
            if !r.contains(attendu) {
                acceptees.push(format!("{nom} : attendu {attendu:?}, rendu {r:?}"));
            }
        }
        assert!(acceptees.is_empty(), "geste(s) ou spawn accepté(s) : {acceptees:#?}");
        // tolérances du côté STRICT : hors d'un fichier qui mentionne le spool, un import de geste n'est pas
        // jugé ; `use tokio::spawn;` non renommé est admis hors fonction
        assert!(analyser("handlers/fab.rs", "use std::fs::write;\nuse tokio::spawn as lancer;\nfn exporter(p: &str) { write(p, b\"\").ok(); }\n").is_empty(), "fichier sans spool jugé");
        let spawn_simple = format!("use tokio::spawn;\n{NOMINAL}");
        assert_eq!(refus(&spawn_simple), "", "`use tokio::spawn;` refusé");
    }

    /// Gestes directs écrits avec des blancs autour de `::`, `File` renommé ou qualifié, chaîne brute `br"…"`
    /// / `cr"…"` qui désynchroniserait le blanchisseur, module passé à une macro, issue abandonnée par un
    /// motif `ref` ou parenthésé. Chaque variante est jugée ; les acceptées sont TOUTES nommées.
    #[test]
    fn les_gestes_ecrits_autrement_et_l_issue_abandonnee_par_motif_rougissent() {
        let appel = "    match crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await {";
        let ajout = |avant: &str, dans: &str| format!("{avant}{}", NOMINAL.replacen(appel, &format!("{dans}\n{appel}"), 1));
        let appel_match = "    match crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await {\n        Ok(p) => ok(p),\n        Err(_) => ko(),\n    }\n";
        let issue = |motif: &str| NOMINAL.replace(appel_match, &format!("    let {motif} = crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await;\n    ok(())\n"));
        let rouges: Vec<(&str, String, &str)> = vec![
            ("std::fs:: write", ajout("", "    let _ = std::fs:: write(&tmp, &corps);"), "[recu_post] geste direct `fs::write` ligne 6"),
            ("std::fs ::write", ajout("", "    let _ = std::fs ::write(&tmp, &corps);"), "[recu_post] geste direct `fs::write` ligne 6"),
            ("File :: create", ajout("", "    let _ = std::fs::File :: create(&tmp);"), "[recu_post] geste direct `File::create` ligne 6"),
            ("use std::fs :: write hors fonction", ajout("use std::fs :: write;\n", "    let _ = write(&tmp, &corps);"), "[(hors fonction)] geste direct `fs::write` ligne 1"),
            ("File renommé hors fonction", ajout("use std::fs::File as F;\n", "    let _ = F::create(&tmp);"), "[(hors fonction)] geste direct `File as` ligne 1"),
            ("File renommé dans la fonction", ajout("", "    use std::fs::File as F;\n    let _ = F::create(&tmp);"), "[recu_post] geste direct `File as` ligne 6"),
            ("<std::fs::File>::create", ajout("", "    let _ = <std::fs::File>::create(&tmp);"), "[recu_post] geste direct `File::create` ligne 6"),
            ("br\"\\\" masque une variante", ajout("", "    let _sep = br\"\\\";\n    let _r = crate::ingest::spool::publier_bloquant(&tmp, &dst, &corps, false); // \""), "[recu_post] appel `spool::publier_bloquant(` ligne 7"),
            ("br#\"\\\"# masque une variante", ajout("", "    let _sep = br#\"\\\"#;\n    let _r = crate::ingest::spool::publier_bloquant(&tmp, &dst, &corps, false); // \""), "[recu_post] appel `spool::publier_bloquant(` ligne 7"),
            ("cr\"\\\" masque une variante", ajout("", "    let _sep = cr\"\\\";\n    let _r = crate::ingest::spool::publier_bloquant(&tmp, &dst, &corps, false); // \""), "[recu_post] appel `spool::publier_bloquant(` ligne 7"),
            (
                "module passé à une macro",
                ajout("macro_rules! m { ($m:ident, $($a:expr),*) => { crate::ingest::$m::publier_bloquant($($a),*) }; }\n", "    let _r = m!(spool, &tmp, &dst, &corps, false);"),
                "[(hors fonction)] chemin par métavariable `$m::` ligne 1",
            ),
            ("let ref _issue", issue("ref _issue"), "issue non attendue"),
            ("let ref mut _issue", issue("ref mut _issue"), "issue non attendue"),
            ("let (_issue)", issue("(_issue)"), "issue non attendue"),
            ("let (mut _issue)", issue("(mut _issue)"), "issue non attendue"),
        ];
        let mut acceptees = Vec::new();
        for (nom, v, attendu) in &rouges {
            assert_ne!(v, NOMINAL, "INSTRUMENT : substitution sans effet ({nom})");
            let r = refus(v);
            if !r.contains(attendu) {
                acceptees.push(format!("{nom} : attendu {attendu:?}, rendu {r:?}"));
            }
        }
        assert!(acceptees.is_empty(), "forme(s) acceptée(s) : {acceptees:#?}");
        // contrôles, côté STRICT : une lecture `File :: open`, un `br"…"` sans effet, `$crate::` et une
        // issue liée sous un motif nommé restent conformes
        for (nom, v) in [
            ("File :: open", ajout("", "    let _f = std::fs::File :: open(&tmp);")),
            ("br\"x\" seul", ajout("", "    let _sep = br\"x\";")),
            ("let (r)", NOMINAL.replace(appel_match, "    let (r) = crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await;\n    rendre(r)\n")),
            ("let ref r", NOMINAL.replace(appel_match, "    let ref r = crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await;\n    rendre(r)\n")),
            ("$crate::", format!("macro_rules! t {{ () => {{ $crate::trace() }}; }}\n{NOMINAL}")),
        ] {
            assert_ne!(v, NOMINAL, "INSTRUMENT : substitution sans effet ({nom})");
            assert_eq!(refus(&v), "", "{nom} refusé");
        }
    }

    /// Deux fonctions HOMONYMES d'un même fichier (`mod a` / `mod b`, `impl A` / `impl B`, fonction imbriquée,
    /// ordre inversé) : chacune est jugée sur SA plage, et son `.tmp` n'est apparié qu'aux appels de SA
    /// fonction. Chaque seconde moitié est refusée, accolée à une première conforme du même nom.
    #[test]
    fn les_fonctions_homonymes_sont_jugees_chacune() {
        let appel = "    match crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await {\n        Ok(p) => ok(p),\n        Err(_) => ko(),\n    }\n";
        let secondes = [
            ("publication détachée sans barrière", NOMINAL.replace(appel, "    tokio::spawn(crate::ingest::spool::publier(tmp, dst, corps, false));\n    ok(())\n")),
            ("publier_bloquant", NOMINAL.replace(appel, "    let r = crate::ingest::spool::publier_bloquant(&tmp, &dst, &corps, false);\n    rendre(r)\n")),
            ("réglage réécrit", NOMINAL.replace("    let n = 1;\n", "    let mut st = st;\n    st.ingest_fsync = false;\n    let n = 1;\n")),
            ("`.tmp` nommé tmp jamais publié", NOMINAL.replace(appel, "    ecrire_ailleurs(&tmp, &dst, corps);\n    ok(())\n")),
        ];
        let mut acceptees = Vec::new();
        for (nom, seconde) in &secondes {
            assert_ne!(seconde, NOMINAL, "INSTRUMENT : substitution sans effet ({nom})");
            assert!(refus(seconde).contains("[recu_post]"), "INSTRUMENT : {nom} seule n'est pas refusée : {:?}", refus(seconde));
            for (enveloppe, v) in [
                ("mod a / mod b", format!("mod a {{\n{NOMINAL}}}\nmod b {{\n{seconde}}}\n")),
                ("impl A / impl B", format!("impl A {{\n{NOMINAL}}}\nimpl B {{\n{seconde}}}\n")),
                ("imbriquée", format!("{NOMINAL}fn enveloppe() {{\n{seconde}}}\n")),
                ("seconde d'abord", format!("mod b {{\n{seconde}}}\n{NOMINAL}")),
            ] {
                if !refus(&v).contains("[recu_post]") {
                    acceptees.push(format!("{nom} / {enveloppe} : {:?}", analyser("ingest/fab.rs", &v)));
                }
            }
        }
        assert!(acceptees.is_empty(), "homonyme(s) accepté(s) : {acceptees:#?}");
        // contrôle : deux homonymes conformes rendent deux sites conformes
        let deux = format!("mod a {{\n{NOMINAL}}}\nmod b {{\n{NOMINAL}}}\n");
        let s = analyser("ingest/fab.rs", &deux);
        assert!(s.len() == 2 && s.iter().all(|x| x.fonction == "recu_post" && x.conforme), "{s:?}");
    }

    /// Issue abandonnée par affectation (sans `let`, motif, retour à la ligne, attribut, bras de `match`) ou
    /// attendue hors du gestionnaire (helper de détachement quel que soit son nom, macro, bloc ou fermeture
    /// `async`). Chaque variante est jugée ; les acceptées sont TOUTES nommées.
    #[test]
    fn l_issue_abandonnee_par_affectation_ou_detachee_hors_spawn_rougit() {
        let appel = "    match crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await {\n        Ok(p) => ok(p),\n        Err(_) => ko(),\n    }\n";
        let pb = "crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync)";
        let rouges = [
            ("_ = …", format!("    _ = {pb}.await;\n    ok(())\n")),
            ("(_) = …", format!("    (_) = {pb}.await;\n    ok(())\n")),
            ("[_] = [ … ]", format!("    [_] = [{pb}.await];\n    ok(())\n")),
            ("let _issue, retour, =", format!("    let _issue\n        = {pb}.await;\n    ok(())\n")),
            ("#[allow(…)] let _x =", format!("    #[allow(unused_variables)] let _x = {pb}.await;\n    ok(())\n")),
            ("bras 0 => _ =", format!("    match k {{\n        0 => _ = {pb}.await,\n        _ => {{}}\n    }}\n    ok(())\n")),
            ("helper detacher(async move {…})", format!("    detacher(async move {{\n        let r = {pb}.await;\n        trace(r);\n    }});\n    ok(())\n")),
            ("macro detacher!(…)", format!("    detacher!({pb}.await);\n    ok(())\n")),
            ("macro à accolades", format!("    detacher! {{\n        let r = {pb}.await;\n        trace(r);\n    }}\n    ok(())\n")),
            ("let f = async move {…}; spawn(f)", format!("    let f = async move {{\n        let r = {pb}.await;\n        trace(r);\n    }};\n    tokio::spawn(f);\n    ok(())\n")),
            ("fermeture async sans accolades", format!("    let f = async move || {pb}.await;\n    tokio::spawn(f());\n    ok(())\n")),
        ];
        let mut acceptees = Vec::new();
        for (nom, forme) in &rouges {
            let v = NOMINAL.replace(appel, forme);
            assert_ne!(v, NOMINAL, "INSTRUMENT : substitution sans effet ({nom})");
            let r = refus(&v);
            if !r.contains("[recu_post]") || !r.contains("issue non attendue") {
                acceptees.push(format!("{nom} : {r:?}"));
            }
        }
        assert!(acceptees.is_empty(), "issue(s) abandonnée(s) ou détachée(s) acceptée(s) : {acceptees:#?}");
        // contrôles : l'instruction est lue de son début (un `let r =` suivi d'un retour reste une liaison
        // nommée), un bloc ordinaire n'est pas un contexte détaché
        for (nom, forme) in [
            ("let r =, retour", format!("    let r =\n        {pb}.await;\n    rendre(r)\n")),
            ("dans un bloc if", format!("    if vrai() {{\n        let r = {pb}.await;\n        return rendre(r);\n    }}\n    ko()\n")),
        ] {
            let v = NOMINAL.replace(appel, &forme);
            assert_ne!(v, NOMINAL, "INSTRUMENT : substitution sans effet ({nom})");
            assert_eq!(refus(&v), "", "{nom} refusé");
        }
    }

    /// Blancs tolérés par la lecture, épinglés du côté où les retirer laisserait passer : avant `::` après une
    /// métavariable, avant `as` et avant / après `::` d'un `fs` renommé ou groupé, capture `{spool:…}`.
    #[test]
    fn les_blancs_et_la_capture_avec_format_sont_lus() {
        let rouges = [
            ("$m :: ", format!("macro_rules! m {{ ($m:ident, $($a:expr),*) => {{ crate::ingest::$m :: publier_bloquant($($a),*) }}; }}\n{NOMINAL}"), "[(hors fonction)] chemin par métavariable `$m::` ligne 1"),
            ("fs  as (deux blancs)", format!("use std::fs  as f;\n{NOMINAL}"), "[(hors fonction)] geste direct `fs as` ligne 1"),
            ("fs, retour, as", format!("use std::fs\n    as f;\n{NOMINAL}"), "[(hors fonction)] geste direct `fs as` ligne 1"),
            ("fs ::{", format!("use std::fs ::{{write}};\n{NOMINAL}"), "[(hors fonction)] geste direct `fs::{` ligne 1"),
            ("fs:: {", format!("use std::fs:: {{write}};\n{NOMINAL}"), "[(hors fonction)] geste direct `fs::{` ligne 1"),
            ("{spool:}", "fn x6(spool: &str, c: Vec<u8>) {\n    ecrire_ailleurs(format!(\"{spool:}/.x6.tmp\"), c);\n}\n".to_string(), "[x6] `.tmp` ligne 2 (non lié par let) non publié"),
        ];
        let mut acceptees = Vec::new();
        for (nom, v, attendu) in &rouges {
            let r = refus(v);
            if !r.contains(attendu) {
                acceptees.push(format!("{nom} : attendu {attendu:?}, rendu {r:?}"));
            }
        }
        assert!(acceptees.is_empty(), "forme(s) acceptée(s) : {acceptees:#?}");
    }

    #[test]
    fn le_corpus_descend_dans_les_sous_dossiers() {
        let c = corpus();
        assert!(c.iter().any(|(rel, _)| rel.starts_with("handlers/connectors/")), "marche non récursive : handlers/connectors/ non lu");
        // la racine de `src/` est lue (gestionnaires `scim.rs`, `sigma.rs`), `tests/` et `ingest/spool.rs` non
        for rel in ["scim.rs", "sigma.rs", "state.rs", "server/mod.rs"] {
            assert!(c.iter().any(|(r, _)| r == rel), "{rel} hors corpus");
        }
        assert!(!c.iter().any(|(r, _)| r.starts_with("tests/") || r == "ingest/spool.rs"), "tests/ ou ingest/spool.rs dans le corpus");
    }

    // ---------------------------------------------------------------------------------------------
    // LE CORPUS RÉEL.
    // ---------------------------------------------------------------------------------------------

    /// Verdict sur l'ensemble des sites d'un corpus, une ligne par faute (vide = vert) : forme neuve (site non
    /// nommé), site nommé non conforme, site hors réception dont les gestes directs ont changé, entrée sans
    /// site. Chaque site est jugé seul : deux fonctions homonymes d'un même fichier rendent deux sites.
    fn verdict_du_corpus(sites: &[Site]) -> Vec<String> {
        let nommes: BTreeSet<(String, String)> = SITES_NOMMES.iter().map(|(f, n)| (f.to_string(), n.to_string())).collect();
        let exemptes: BTreeSet<(String, String)> = HORS_RECEPTION.iter().map(|(f, n, _, _)| (f.to_string(), n.to_string())).collect();
        assert!(nommes.is_disjoint(&exemptes), "INSTRUMENT : un site est à la fois nommé et exempté");
        let tous: BTreeSet<(String, String)> = nommes.union(&exemptes).cloned().collect();
        let trouves: BTreeSet<(String, String)> = sites.iter().map(|s| (s.fichier.clone(), s.fonction.clone())).collect();
        let mut v = Vec::new();
        for s in sites {
            let exempte = HORS_RECEPTION.iter().find(|(f, n, _, _)| *f == s.fichier && *n == s.fonction);
            if !tous.contains(&(s.fichier.clone(), s.fonction.clone())) {
                v.push(format!("FORME NEUVE : {}:{} {} — site d'écriture du spool non nommé : le faire passer par `spool::publier` PUIS le nommer dans SITES_NOMMES ({})", s.fichier, s.ligne, s.fonction, s.motif));
            } else if let Some((_, _, gestes, _)) = exempte {
                let attendus: Vec<String> = gestes.iter().map(|g| g.to_string()).collect();
                if s.gestes != attendus {
                    v.push(format!("HORS RÉCEPTION ÉLARGI : {}:{} {} — gestes directs {:?}, attendus {attendus:?}", s.fichier, s.ligne, s.fonction, s.gestes));
                }
            } else if !s.conforme {
                v.push(format!("ÉCRITURE DU SPOOL HORS `spool::publier` (barrières perdues) : {}:{} {} — {}", s.fichier, s.ligne, s.fonction, s.motif));
            }
        }
        // une exemption couvre UN site : un homonyme (`mod v2`, `impl Autre`) d'un site hors réception ne
        // l'hérite pas, il rend l'entrée ambiguë
        for (f, n, _, _) in HORS_RECEPTION {
            let k = sites.iter().filter(|s| s.fichier == *f && s.fonction == *n).count();
            if k > 1 {
                v.push(format!("HORS RÉCEPTION AMBIGU : {f} {n} — {k} sites portent ce nom, une exemption couvre UN site : renommer l'homonyme et le faire passer par `spool::publier`"));
            }
        }
        for (f, n) in tous.difference(&trouves) {
            v.push(format!("SANS OBJET : {f} {n} — entrée nommée sans site dans le corpus : retirer ou suivre le déplacement"));
        }
        v
    }

    fn sites_du_corpus(variante: Option<(&str, &dyn Fn(String) -> String)>) -> Vec<Site> {
        let mut sites = Vec::new();
        for (rel, src) in corpus() {
            let src = match variante {
                Some((cible, f)) if cible == rel => f(src),
                _ => src,
            };
            sites.extend(analyser(&rel, &src));
        }
        sites
    }

    #[test]
    fn tout_gestionnaire_qui_ecrit_le_spool_passe_par_publier() {
        let v = verdict_du_corpus(&sites_du_corpus(None));
        assert!(v.is_empty(), "{v:#?}");
    }

    /// Le verdict du corpus RÉEL, sur deux variantes en mémoire : une fonction homonyme dans `mod v2` de
    /// `ingest/hec.rs` qui détache sa publication sans barrière, et un geste direct ajouté dans un site hors
    /// réception. Le corpus intact est vert (témoin précédent) : le rouge vient de la variante.
    #[test]
    fn le_corpus_reel_rougit_sur_un_homonyme_ou_un_site_hors_reception_elargi() {
        let v2 = |src: String| {
            format!(
                "{src}\nmod v2 {{\n    pub(crate) async fn hec_event_post(st: AppState, corps: Vec<u8>) -> Response {{\n        let tmp = format!(\"{{}}/.hec-v2.tmp\", st.spool);\n        let dst = format!(\"{{}}/hec-v2.json\", st.spool);\n        tokio::spawn(crate::ingest::spool::publier(tmp, dst, corps, false));\n        hec_ok(0)\n    }}\n}}\n"
            )
        };
        let v = verdict_du_corpus(&sites_du_corpus(Some(("ingest/hec.rs", &v2 as &dyn Fn(String) -> String))));
        assert!(v.iter().any(|l| l.contains("barrières perdues") && l.contains("ingest/hec.rs") && l.contains("hec_event_post")), "homonyme de `mod v2` accepté : {v:#?}");
        let ancre = "    let dst = format!(\"{qdir}/{name}\");\n";
        let elargi = |src: String| {
            assert_eq!(src.matches(ancre).count(), 1, "INSTRUMENT : ancre absente ou multiple dans state.rs");
            src.replacen(ancre, &format!("{ancre}    let _ = std::fs::write(&dst, b\"\");\n"), 1)
        };
        let v = verdict_du_corpus(&sites_du_corpus(Some(("state.rs", &elargi as &dyn Fn(String) -> String))));
        assert!(v.iter().any(|l| l.contains("HORS RÉCEPTION ÉLARGI") && l.contains("quarantine_spool_file")), "geste ajouté dans un site hors réception accepté : {v:#?}");
    }

    /// Instruction nue derrière un attribut, un `&` ou une tête de chemin à blancs ; comparaison jetée ;
    /// `let _ = match …` ; détachement lu sur TOUTE la pile (bloc ordinaire dans un `spawn`, `drop({ … })`,
    /// fonction imbriquée dans un `spawn`) ; formes forcées (fermeture à paramètre `fn()`, `as fn()`,
    /// `#[cfg(test)] const` à crochets, littéraux `'\u{…}'` / `'\x..'`). Chaque variante est jugée ; les
    /// acceptées sont TOUTES nommées.
    #[test]
    fn l_instruction_nue_et_le_detachement_sur_toute_la_pile_rougissent() {
        let appel = "    match crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync).await {\n        Ok(p) => ok(p),\n        Err(_) => ko(),\n    }\n";
        let pb = "crate::ingest::spool::publier(tmp, dst, corps, st.ingest_fsync)";
        let rouges = [
            ("#[allow(…)] devant une instruction nue", format!("    #[allow(unused_must_use)] {pb}.await;\n    ok(())\n")),
            ("#[allow(…)] seul sur sa ligne", format!("    #[allow(unused_must_use)]\n    {pb}.await;\n    ok(())\n")),
            ("#[cfg(not(test))] seul sur sa ligne", format!("    #[cfg(not(test))]\n    {pb}.await;\n    ok(())\n")),
            ("blanc avant spool", "    crate::ingest:: spool::publier(tmp, dst, corps, st.ingest_fsync).await;\n    ok(())\n".to_string()),
            ("blancs autour de chaque ::", "    crate :: ingest :: spool :: publier(tmp, dst, corps, st.ingest_fsync).await;\n    ok(())\n".to_string()),
            ("& devant", format!("    &{pb}.await;\n    ok(())\n")),
            ("comparaison jetée", format!("    let n = 0;\n    n == {pb}.await;\n    ok(())\n")),
            ("let _ = match", format!("    let _ = match {pb}.await {{\n        Ok(p) => p,\n        Err(_) => 0,\n    }};\n    ok(())\n")),
            ("spawn async + bloc if", format!("    tokio::spawn(async move {{\n        if vrai() {{\n            let r = {pb}.await;\n            trace(r);\n        }}\n    }});\n    ok(())\n")),
            ("drop({ … })", format!("    drop({{\n        let r = {pb}.await;\n        r\n    }});\n    ok(())\n")),
            ("fermeture à paramètre fn()", format!("    let fabrique = |_g: fn()| async move {{ let r = {pb}.await; trace(r); }};\n    tokio::spawn(fabrique(rien));\n    ok(())\n")),
            ("as fn() dans la tête", format!("    let t = Tache {{ rappel: aide as fn(), corps: async move {{ let r = {pb}.await; trace(r); }} }};\n    tokio::spawn(t.corps);\n    ok(())\n")),
            ("#[cfg(test)] const à crochets dans un spawn", format!("    tokio::spawn(async move {{\n        #[cfg(test)] const A: [u8; 1] = [0];\n        #[cfg(test)] const B: [u8; 1] = [0];\n        let r = {pb}.await;\n        trace(r);\n    }});\n    ok(())\n")),
            ("'\\u{41}' dans un spawn", format!("    tokio::spawn(async move {{\n        let _c = ['\\u{{41}}',')'];\n        let _d = ['\\u{{41}}',')'];\n        let r = {pb}.await;\n        trace(r);\n    }});\n    ok(())\n")),
            ("'\\x41' dans un spawn", format!("    tokio::spawn(async move {{\n        let _c = ['\\x41',')'];\n        let _d = ['\\x41',')'];\n        let r = {pb}.await;\n        trace(r);\n    }});\n    ok(())\n")),
        ];
        let mut acceptees = Vec::new();
        for (nom, forme) in &rouges {
            let v = NOMINAL.replace(appel, forme);
            assert_ne!(v, NOMINAL, "INSTRUMENT : substitution sans effet ({nom})");
            let r = refus(&v);
            if !r.contains("[recu_post]") || !r.contains("issue non attendue") {
                acceptees.push(format!("{nom} : {r:?}"));
            }
        }
        // fonction imbriquée DANS un `spawn` : son propre appel, conforme en soi, est détaché
        let imbriquee = NOMINAL.replace(appel, &format!("    tokio::spawn(async move {{\n        async fn aide(st: AppState, corps: Vec<u8>) {{\n            let tmp = format!(\"{{}}/.a.tmp\", st.spool);\n            let dst = format!(\"{{}}/a.json\", st.spool);\n            let r = {pb}.await;\n            trace(r);\n        }}\n        aide(st, corps).await;\n    }});\n    ok(())\n"));
        assert_ne!(imbriquee, NOMINAL, "INSTRUMENT : substitution sans effet (fonction imbriquée)");
        match analyser("ingest/fab.rs", &imbriquee).into_iter().find(|x| x.fonction == "aide") {
            Some(x) if !x.conforme && x.motif.contains("issue non attendue") => {}
            autre => acceptees.push(format!("fonction imbriquée dans un spawn : {autre:?}")),
        }
        assert!(acceptees.is_empty(), "forme(s) acceptée(s) : {acceptees:#?}");
        // contrôles : ce qui consomme reste accepté — attribut devant un `let` nommé ou un `match`, tête de
        // chemin à blancs liée, `if` qui teste l'issue, `let r = match`, `return`
        for (nom, forme) in [
            ("#[allow(…)] let r =", format!("    #[allow(unused_variables)] let r = {pb}.await;\n    rendre(r)\n")),
            ("#[allow(…)] seul sur sa ligne, puis match", format!("    #[allow(unreachable_patterns)]\n    match {pb}.await {{\n        Ok(p) => ok(p),\n        Err(_) => ko(),\n    }}\n")),
            ("let r = chemin à blancs", "    let r = crate :: ingest :: spool :: publier(tmp, dst, corps, st.ingest_fsync).await;\n    rendre(r)\n".to_string()),
            ("if … .is_err()", format!("    if {pb}.await.is_err() {{\n        return ko();\n    }}\n    ok(())\n")),
            ("let r = match", format!("    let r = match {pb}.await {{\n        Ok(p) => p,\n        Err(_) => return ko(),\n    }};\n    rendre(r)\n")),
            ("return", format!("    return {pb}.await.map(ok).unwrap_or_else(|_| ko());\n")),
        ] {
            let v = NOMINAL.replace(appel, &forme);
            assert_ne!(v, NOMINAL, "INSTRUMENT : substitution sans effet ({nom})");
            assert_eq!(refus(&v), "", "{nom} refusé");
        }
    }

    /// Une exemption `HORS_RECEPTION` couvre UN site, et sa disparition rougit : sur le corpus RÉEL, un homonyme
    /// d'un site exempté (`mod v2` / `impl Autre` dans `state.rs`) rend l'entrée
    /// ambiguë au lieu d'hériter de l'exemption ; un site exempté retiré du texte rend « sans objet ».
    #[test]
    fn une_exemption_hors_reception_couvre_un_seul_site_et_sa_disparition_rougit() {
        let homonymes: [(&str, &str, &str, &str); 2] = [
            ("state.rs", "quarantine_spool_file", "\nmod v2 {\n    pub(crate) async fn quarantine_spool_file(st: AppState, corps: Vec<u8>) -> Response {\n        let tmp = format!(\"{}/.v2.tmp\", st.spool);\n        let dst = format!(\"{}/v2.json\", st.spool);\n        tokio::spawn(crate::ingest::spool::publier(tmp, dst, corps, false));\n        let _ = std::fs::rename(\"/var/x\", \"/var/y\");\n        ok()\n    }\n}\n", "state.rs quarantine_spool_file"),
            ("state.rs", "remettre_la_quarantaine_en_file", "\nimpl Autre {\n    pub(crate) fn remettre_la_quarantaine_en_file(spool: &str, src: &str) {\n        let dst = format!(\"{spool}/final.json\");\n        let _ = std::fs::rename(src, &dst);\n    }\n}\n", "state.rs remettre_la_quarantaine_en_file"),
        ];
        let mut acceptees = Vec::new();
        for (rel, fonction, ajout, attendu) in homonymes {
            let f = |src: String| format!("{src}{ajout}");
            let sites = sites_du_corpus(Some((rel, &f as &dyn Fn(String) -> String)));
            assert!(sites.iter().filter(|s| s.fichier == rel && s.fonction == fonction).count() == 2, "INSTRUMENT : l'homonyme de {rel}::{fonction} n'est pas un second site");
            let v = verdict_du_corpus(&sites);
            if !v.iter().any(|l| l.contains("HORS RÉCEPTION AMBIGU") && l.contains(attendu)) {
                acceptees.push(format!("homonyme {rel}::{fonction} : {v:#?}"));
            }
        }
        assert!(acceptees.is_empty(), "homonyme(s) d'un site hors réception accepté(s) : {acceptees:#?}");
        // le site exempté disparaît : l'entrée reste, sans objet
        let couper = |src: String| {
            let d = src.find("pub(crate) fn quarantine_spool_file(").expect("INSTRUMENT : signature de quarantine_spool_file absente de state.rs");
            let o = d + src[d..].find('{').expect("INSTRUMENT : corps absent");
            let mut prof = 0i32;
            let mut fin = None;
            for (j, c) in src[o..].char_indices() {
                if c == '{' {
                    prof += 1;
                } else if c == '}' {
                    prof -= 1;
                    if prof == 0 {
                        fin = Some(o + j + 1);
                        break;
                    }
                }
            }
            format!("{}{}", &src[..d], &src[fin.expect("INSTRUMENT : accolades non appariées")..])
        };
        let v = verdict_du_corpus(&sites_du_corpus(Some(("state.rs", &couper as &dyn Fn(String) -> String))));
        assert!(v.iter().any(|l| l.contains("SANS OBJET : state.rs quarantine_spool_file")), "site hors réception disparu sans verdict : {v:#?}");
    }
}
