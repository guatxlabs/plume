#!/usr/bin/env python3
"""Une couverture qu'on n'a pas pu poser, une grandeur qu'on n'a pas pu lire : ça se DIT (`P4.1-q`).

LA FAMILLE : UNE DÉTECTION QUI S'ÉTEINT, SANS TRACE
---------------------------------------------------
Elle est DISTINCTE de « publier une valeur rassurante » (`S32`/`S33`/`S36`, où un chiffre faux part
quand même). Ici RIEN n'est publié du tout, et la couverture annoncée reste celle de la
configuration. Deux visages du même défaut :

  POSE. Le moniteur d'intégrité parcourt les racines déclarées pour y poser des watches noyau.
  Chaque repli d'erreur du parcours — un `stat` refusé, un `read_dir` refusé, une entrée illisible
  en cours d'énumération, un chemin non convertible, un watch refusé par le noyau — abandonnait la
  branche courante et rendait la main. Un SOUS-ARBRE ENTIER sortait ainsi de la surveillance : aucun
  événement, aucun avertissement, aucun aveu, et `fim_mode` continuait d'annoncer « realtime ».
  Ce qui rend ce défaut invisible à la relecture, c'est que la forme fautive est la forme IDIOMATIQUE
  de Rust : `Err(_) => continue`, `if let Ok(x) = …` sans `else`, `let Some(x) = … else { return }`,
  `entries.flatten()`. Aucune de ces lignes ne ressemble à une perte.

  SURFACE. La commande d'état de l'agent enveloppait ses lignes dans des `if let Ok(…)` sans `else` :
  une configuration illisible, un répertoire de spool non ouvrable, un répertoire d'état refusé
  faisaient DISPARAÎTRE la profondeur de file et les curseurs de l'affichage. L'opérateur ne lit pas
  une valeur fausse — il ne lit RIEN, et l'absence de ligne se lit comme une absence de problème.

LE CRITÈRE, ÉCRIT ET REJOUABLE (c'est lui qui définit la population, jamais une liste)
--------------------------------------------------------------------------------------
DEUX populations, dérivées de ce que le code EST, pas de son nom ni de son emplacement :

  COUVERTURE — une fonction qui POSE ou ÉNUMÈRE de la surveillance :
    (a) elle implémente `watch_root`, la méthode du contrat `FimBackend` dont la documentation dit
        « Pose un watch … sur `root` » — un backend écrit demain y tombe par construction ; ou
    (b) son corps ÉNUMÈRE un répertoire (`std::fs::read_dir`) ; ou
    (c) elle est appelée, directement ou transitivement, depuis (a) ou (b) ET son propre corps touche
        le système de fichiers ou une primitive noyau (`std::fs::`, `libc::`). La condition de touche
        écarte les auxiliaires purs (comparaison de glob, mise en forme) qui n'abandonnent rien.

  SURFACE — une fonction qui écrit sur la SORTIE STANDARD (`println!`). La sortie standard EST la
    surface d'état de la CLI ; la sortie d'erreur est un journal d'hôte et ne compte pas.

SITE FAUTIF — une alternative qui sépare le succès de l'échec, dont la branche d'ÉCHEC ABANDONNE
l'objet en cours (corps VIDE, ou simple transfert de contrôle : `return`/`continue`/`break`) sans
laisser de trace. Formes reconnues :
    bras `Err(…)` / `None` / `_` d'un `match` qui possède un bras de succès ;
    `if let Ok/Some/Lue(…)` SANS `else` (la branche d'échec est vide par construction) ;
    `let Ok/Some/Lue(…) = … else { … }` ;
    `.flatten()` sur une énumération — il jette les entrées illisibles SANS aucune branche où
    compter quoi que ce soit, il est donc refusé en bloc dans un parcours de couverture.
Ce qui vaut TRACE dépend de la population :
    COUVERTURE : COMPTER (`+=`), lever un drapeau (`= true`), ou PROPAGER (`?`, `bail!`, `panic!`,
        un `return` PORTEUR d'une valeur). Un `eprintln!` seul NE VAUT PAS : le contrat le dit
        lui-même — le trou remonte au lecteur pour marquer `fim_coverage`, « jamais juste un warning
        stderr d'hôte » ;
    SURFACE : IMPRIMER l'inconnu (`println!`), ou faire ÉCHOUER la commande (`?`, `bail!`, `panic!`,
        `return Err`). Un `return` muet ne vaut pas : la grandeur disparaît quand même.
Une branche qui rend une VALEUR n'abandonne rien et n'est pas un site : `None => name` choisit une
valeur, il ne renonce pas à un objet.

LA MESURE QUI A OUVERT CETTE CLÉ, ET CE QU'ELLE A RÉFUTÉ (2026-08-21, ce critère, ce dépôt)
-------------------------------------------------------------------------------------------
Population du crate `agent` : 8 fonctions de couverture, 5 fonctions de surface.
Sites fautifs : 16 — 11 dans le backend Linux (fanotify ET inotify), 3 dans la commande d'état
(trois enveloppes `if let Ok` imbriquées, donc trois grandeurs qui disparaissent), 2 dans le backend
Windows. LE CONSTAT D'ORIGINE EN ANNONÇAIT 3, il est donc RÉFUTÉ : il nommait « deux sites » dans le
backend Linux là où il y en a onze, « un site » dans la commande d'état là où trois grandeurs
s'effacent, et il ne voyait PAS le backend Windows, qui porte exactement la même forme.
La mesure se rejoue : `git show HEAD:<fichier>` dans la fonction `analyser` de cette garde.
Hors du crate `agent`, le MÊME critère rend 32 sites de plus (daemon, collecteurs). Ils ne sont PAS
triés à la main et cette garde ne les exige pas : sa portée est le crate `agent`, et c'est une limite
ÉCRITE, pas un angle mort.

HORS DU CRATE DE L'AGENT : LE DÉMON ET LES COLLECTEURS (`P4.1-r`, 2026-08-22)
--------------------------------------------------------------------------------
Le critère est le MÊME ; ce sont les POPULATIONS qui changent, parce que « poser de la surveillance »
n'est pas la même chose dans un démon que dans un agent. Elles restent DÉRIVÉES, jamais listées :

  COUVERTURE, en plus de (a)(b)(c) :
    (d) elle CONSOMME une énumération : son corps appelle une fonction qui ÉNUMÈRE — directement
        (`read_dir`) ou par délégation, c'est-à-dire une fonction qui atteint `read_dir` par appel ET
        dont le type de retour porte des chemins (`PathBuf`). C'est ainsi qu'un chargeur de règles qui
        itère sur un listing rendu par un autre module entre dans la population. Les appels NUS sont
        résolus dans le FICHIER (comme en (c)) ; les appels QUALIFIÉS (`Type::f(`, `module::f(`) dans le
        CRATE — une résolution crate-wide des noms nus avalerait tout par collision (`drop`, `etat`).
    (e) elle ÉVALUE ou ÉMET de la détection : son corps écrit `INSERT … INTO alert` ou avance le curseur
        d'un élément ordonnancé (`SET last_run=`). Ce sont les tickers de fond — règles, règles avancées,
        règles de risque, corrélations, lignes de base, playbooks, battements de capteurs, connecteurs,
        destinations, rapports — et c'est CE QU'ILS FONT qui les désigne, pas leur nom.

  SURFACE : inchangée (`println!`). Le panneau JSON et l'exposition Prometheus du démon sont tenus par le
    TYPE de `S32` (`Mesure<T>`, sans valeur par défaut) et par sa suite, pas par cette garde de forme ;
    c'est une limite ÉCRITE.

  FORMES, en plus : `.filter_map(Result::ok)` est `.flatten()` sous un autre nom — refusé de même ;
  `if let Err(e) = … { …; continue }` est la forme INVERSÉE, où le bloc `then` est la branche d'échec.
  Un `return Mesure::Lue(0)` (ou `Lue(0)` de tout chemin) sur une branche d'ÉCHEC est un retour NEUTRE
  au même titre que `return 0` : il dit « rien d'abandonné » là où quelque chose l'a été ; rendre une
  collection VIDE (`Vec::new()`, `vec![]`, `Lue(Vec::new())`…) sur un échec d'énumération l'est aussi.
  TRACE, en plus : CONSIGNER nominativement (`.push(`) vaut compter — c'est la forme de `S36`.

LA MESURE (2026-08-22, ce critère, ces populations) : 106 sites dans le démon et les collecteurs,
contre les « 32 » de la borne d'ampleur de `P4.1-q` — qui ne comptait ni les tickers (e) ni les
consommateurs (d) ; 3 d'entre eux étaient du code de TEST que l'instrument ne masquait pas
(`pub(crate) mod door_tests`, `#![cfg(test)]`), ce qui est corrigé ici. Les sites fermés rendent un
`Mesure<u32>` (`bilan_de_tick`), un `Chargement`, un `Balayage`, un `Inventaire` qui compte ses
illisibles, ou refusent (`RefusDePrune`). Après fermeture : 0 site.

L'ÉCHEC TESTÉ PAR COMPARAISON OU PAR MÉTHODE (`P4.1-s`, 2026-08-22)
----------------------------------------------------------------------
`P4.1-q` et `P4.1-r` écrivaient leur limite : la garde ne voyait une branche d'échec que si un MOTIF la
séparait (`Err`, `None`, `let … else`). Or le même abandon s'écrit sans motif, et ces trois formes sont
désormais reconnues — dans les MÊMES populations, jamais dans une population nouvelle :

  (i)  PRÉDICAT DE MÉTHODE. `if x.is_err()`, `if x.is_none()`, `if p.is_null()`, `if !x.is_ok()` : le
       bloc `then` EST la branche d'échec (la forme inversée de `if let Err`). `if x.is_ok()`,
       `if x.is_some()` : l'échec est le `else`, ou il est VIDE sans `else` — l'analogue exact de
       `if let Ok(…)` sans `else`. Exception : `if q.is_ok() { return }` SANS `else`, où c'est le SUCCÈS
       qui rend la main (« déjà fait ») et la suite de la fonction est le chemin de travail — rien n'y est
       perdu.
  (ii) COMPARAISON À UNE SENTINELLE, selon la convention C : `< 0`, `<= 0`, `== -1`, `!= 0` testent
       l'échec ; `>= 0`, `== 0` le succès. `if roots.len() == 0 { return }` compare une longueur : « rien
       à faire » n'est pas un échec.
  (iii) REPLI PAR VALEUR NEUTRE. `.unwrap_or(0)`, `.unwrap_or(false)`, `.unwrap_or(Vec::new())`,
       `.unwrap_or_default()`, `.unwrap_or_else(Vec::new)`, `.map_or(0, …)` : l'alternative est écrite en
       une méthode, et sa branche d'échec rend la valeur qui dit « rien » — c'est `return Lue(0)` sous un
       autre nom. Un `unwrap_or(valeur)` non neutre CHOISIT une valeur, comme `None => name` : pas un
       site. La trace possible vit dans la fermeture (`unwrap_or_else(|_| { perdus += 1; Vec::new() })`).

  LES TROIS FORMES N'ENTRENT EN POPULATION QUE SI L'OPÉRANDE LIT LE MONDE — et c'est la différence
  avec les formes à motif, dont le récepteur est libre. Un prédicat, une comparaison ou un repli
  s'appliquent à une VALEUR que la fonction tient ; ce n'en est un échec de couverture que si cette valeur
  est ce que le monde a rendu. Lit le monde : une chaîne dont la TÊTE est une primitive — énumération
  (`read_dir`), système de fichiers ou noyau (`std::fs::`, `libc::`, `unsafe`), verbe SQL (`query_row`,
  `query_map`, `prepare`, `execute`), verbe d'E/S (`write_all`, `read_to_string`…), appel à une fonction
  de couverture — ou un NOM LIÉ à une telle expression dans la fonction (`let fd = unsafe { … }`,
  `Ok(mut f) =>` sur un `open`, `if let Ok(x) = fs::…`), suivie UNIQUEMENT d'adaptateurs de
  `Result`/`Option` (`map`, `and_then`, `ok`…). Ne lit pas le monde, et c'est adjugé sur pièces :
  `action_valid(t).is_err()` (une DÉCISION de politique : la cible est refusée, rien n'est perdu),
  `config.get("url").….unwrap_or(false)` (une NAVIGATION dans un contenu déjà lu : l'échec testé est
  l'absence d'un champ, pas celui d'une lecture), `env::var(..).….unwrap_or(0)` (une grandeur qui n'arme
  rien). Le prix de cette frontière est écrit à la limite 2 : `let Some(c) = self.cfg else { return }`
  est accusé, `if self.cfg.is_none() { return }` ne l'est pas.
  Ce qui vaut ABANDON et ce qui vaut TRACE ne change pas — sauf qu'un drapeau se pose dans les deux sens
  (`complet = false` vaut `perdu = true`). En SURFACE, (i) et (ii) suivent la règle du `if let` (la
  jumelle imprime, l'échec se tait) ; (iii) n'y est pas un site — voir la limite 2.

LA MESURE (2026-08-22, ce critère, ces populations) : 15 alternatives des trois formes dans les quatre
crates, dont 11 dont la branche d'échec abandonne. SIX abandonnaient sans trace — toutes dans le démon, et
TOUTES de la forme (iii) `metadata(..).unwrap_or(0)` / `query_row(..).unwrap_or(0)` : la taille d'une
archive de sauvegarde (trois sites, publiée « dest=0 o » sur la ligne opérateur), la taille d'un
fichier-jour du tier froid (sommée pour zéro), la déduplication d'une réponse de playbook (posée à
l'aveugle), l'id d'un événement de démonstration (référencé `event:0`). Les cinq autres comptaient déjà
(`perdus += 1`, `illisibles += 1`, `complet = false`). Le filtre grossier qui a ouvert la clé annonçait
« une douzaine » de `if x < 0` et de `.is_err()` : ces sites-là sont soit comptés, soit HORS population
(le drainage des descripteurs de l'agent, voir la limite 3) — et la forme qui abandonnait vraiment,
`unwrap_or(0)`, il ne la comptait pas. Après fermeture : 0 site.

CE QUE CETTE GARDE NE PROUVE PAS
-------------------------------
1. Elle prouve une FORME, pas un trajet. Qu'un compte existe ne dit pas qu'il atteint le SOC ; c'est
   la suite du crate qui l'exerce (`pose_de_couverture_partielle_est_avouee_et_marque_les_events`,
   son témoin INVERSE `pose_de_couverture_complete_ne_dit_rien_de_particulier`, et
   `la_pose_noyau_compte_ce_qu_elle_abandonne` qui touche le vrai noyau).
2. Elle ne reconnaît une branche d'échec que lorsqu'elle est ÉCRITE — par un motif (`Err`, `None`,
   `let … else`), par un prédicat, par une comparaison à une sentinelle LIÉE à une primitive, ou par un
   repli neutre sur un récepteur qui LIT LE MONDE (`P4.1-s`). Lui échappent encore, et c'est dit :
     - `let _ = primitive(…)` : il n'y a AUCUNE alternative, donc aucune branche ; c'est la famille de
       la pose DÉGÉNÉRÉE, tenue par le témoin inverse de la suite, pas par une forme ;
     - une sentinelle STOCKÉE puis lue ailleurs : `let ok = r.is_ok(); … if !ok { return }`, ou un champ
       (`self.fd`) posé dans une autre fonction et testé dans celle-ci — le lien entre la primitive et le
       test n'est pas dans la fonction, un scanner textuel ne doit pas le deviner ;
     - une comparaison sur une grandeur qui n'est PAS le retour d'une primitive (`if n == 0 { return }`
       sur une longueur) : ce n'est pas un échec, c'est « rien à faire » — hors population ;
     - un repli par une chaîne vide (`unwrap_or("")`) : les littéraux sont blanchis par le scanner, et un
       nom de repli est une VALEUR choisie, pas un abandon ;
     - en SURFACE, `println!("{}", x.unwrap_or(0))` IMPRIME — un zéro rassurant, qui est la famille de
       `S32`/`S33` (valeur publiée fausse), pas celle-ci (grandeur disparue) ;
     - un prédicat ou une comparaison sur une valeur qui ne vient pas du monde (`if self.cfg.is_none()
       { return }`) : la forme à motif équivalente est accusée, celle-ci non — c'est le prix de ne pas
       accuser une validation refusée ; une écriture déléguée à un module (`store().insert_metric(..)
       .is_err()`) est un appel à DEUX sauts, que la tête de chaîne ne reconnaît pas comme primitive.
3. Sa portée est désormais les quatre crates compilés (`CRATES`). Ce qui lui échappe encore dans le
   démon : les consommateurs à DEUX sauts d'un énumérateur qui ne rendent pas de chemins (ils ne sont
   ni énumérateurs ni consommateurs au sens de (d)), et les fonctions qui traitent un contenu déjà lu
   (`ingest_journal_lines` saute une ligne NDJSON invalide par `continue` : hors population, parce
   qu'elle ne touche ni le système de fichiers ni la table des alertes). Et dans l'AGENT : le DRAINAGE
   des descripteurs — `read` sur le descripteur inotify/fanotify, `GetQueuedCompletionStatus` — n'est
   atteint par aucune dérivation (il n'est ni posé, ni énuméré, ni appelé depuis la pose). Les
   `if n < 0 { … break }` de ce drainage comptent `perdus` depuis `P4.1-q`, mais une régression qui les
   rendrait muets passerait cette garde : une population « écoute » serait une dérivation NOUVELLE, et
   elle n'est pas décidée ici.
4. Elle ne distingue pas un bilan rendu d'un bilan LU : un planificateur qui jetterait le `Mesure`
   rendu par ses tickers passerait. C'est la suite du démon qui le tient (`branche_d_echec_muette.rs`).
"""
import re
import subprocess
import sys

CONTRAT = "FimBackend"      # le contrat qui déclare la POSE de couverture
POSE = "watch_root"         # la méthode dont la doc dit « Pose un watch … sur `root` »

# PLANCHERS PAR CRATE, pas des comptes exacts : ajouter un backend, un ticker ou une sous-commande est
# de la routine. Ils ferment le seul mode de panne réel de la découverte — un motif cassé qui ne trouve
# RIEN et rend un vert joyeux. MESURÉS : agent 2026-08-21 (8 couverture, 5 surface) ; démon 2026-08-22
# (56 couverture, 4 surface) ; collector-mail 2026-08-22 (10 couverture, 1 surface) ; collector-syslog
# 2026-08-22 (3 couverture, 0 surface — il n'a pas de ligne de commande, et un plancher de surface à 0
# n'est pas une vérification : c'est dit).
# Et CE QUE « POSER DE LA SURVEILLANCE » VEUT DIRE dans chaque crate — la dérivation, pas une liste :
#   "pose"    (a) le contrat `FimBackend` ; (b) l'énumération d'un répertoire ; (c) la fermeture descendante ;
#   "charge"  (d) le CONSOMMATEUR d'une énumération (chargeur de règles, élagage, lecteur de spool) ;
#   "evalue"  (e) l'ÉVALUATEUR / l'ÉMETTEUR de détection (`INTO alert`, `SET last_run=`).
# L'agent pose ; le démon charge et évalue en plus ; un collecteur charge (il consomme des boîtes).
# (plancher couverture, plancher surface, dérivations)
CRATES = {
    "agent/src": (6, 3, ("pose",)),
    "daemon/src": (20, 2, ("pose", "charge", "evalue")),
    "collector-mail/src": (5, 1, ("pose", "charge")),
    "collector-syslog/src": (1, 0, ("pose", "charge")),
}

OUVR, FERM = "([{", ")]}"


# ==================================================================================================
# UN SCANNER RUST MINIMAL — le dépôt n'a pas de parseur Rust en CI ; celui-ci est VALIDÉ plus bas.
# ==================================================================================================
def denude(src: str) -> str:
    """Commentaires et littéraux -> espaces, positions CONSERVÉES (les numéros de ligne restent vrais)."""
    out = list(src)
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == "/" and src[i + 1:i + 2] == "/":
            j = src.find("\n", i)
            j = n if j < 0 else j
            out[i:j] = " " * (j - i)
            i = j
            continue
        if c == "/" and src[i + 1:i + 2] == "*":
            depth, j = 1, i + 2
            while j < n and depth:
                if src[j] == "/" and src[j + 1:j + 2] == "*":
                    depth += 1
                    j += 2
                elif src[j] == "*" and src[j + 1:j + 2] == "/":
                    depth -= 1
                    j += 2
                else:
                    j += 1
            for k in range(i, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j
            continue
        m = re.match(r'(b?r)(#*)"', src[i:])
        if m and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
            fin = '"' + m.group(2)
            j = src.find(fin, i + m.end())
            j = n if j < 0 else j + len(fin)
            for k in range(i, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j
            continue
        if c == '"':
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == '"':
                    j += 1
                    break
                j += 1
            for k in range(i, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j
            continue
        if c == "'":
            # littéral de caractère, ou DURÉE DE VIE (`'static`) : seule la première forme se blanchit.
            m = re.match(r"'(\\.|[^\\'])'", src[i:])
            if m:
                out[i:i + m.end()] = " " * m.end()
                i += m.end()
            else:
                i += 1
            continue
        i += 1
    return "".join(out)


def fin_bloc(s: str, i: int) -> int:
    """`i` désigne une ouvrante ; rend l'index APRÈS sa fermante."""
    pile = []
    while i < len(s):
        c = s[i]
        if c in OUVR:
            pile.append(FERM[OUVR.index(c)])
        elif c in FERM:
            if pile and pile[-1] == c:
                pile.pop()
                if not pile:
                    return i + 1
            else:
                return i + 1
        i += 1
    return len(s)


def jusqu_a(s: str, i: int, stops: str, aussi=()):
    """Premier caractère de `stops` (ou mot de `aussi`) à profondeur 0. Les stops sont testés AVANT
    l'ouverture d'un bloc, sans quoi un `{` ne pourrait jamais être un stop."""
    depth = 0
    while i < len(s):
        c = s[i]
        if depth == 0:
            if c in stops:
                return i, c
            for mot in aussi:
                avant = s[i - 1:i]
                apres = s[i + len(mot):i + len(mot) + 1]
                if s.startswith(mot, i) and not (avant.isalnum() or avant == "_") \
                   and not (apres.isalnum() or apres == "_"):
                    return i, mot
        if c in OUVR:
            depth += 1
        elif c in FERM:
            if depth == 0:
                return i, c
            depth -= 1
        i += 1
    return len(s), None


def bloc_du_corps(s: str, i: int):
    """Le `{` qui ouvre le CORPS (bras d'un `match`, `then` d'un `if let`), en SAUTANT les blocs
    d'expression du scrutin. `match unsafe { … } { … }` en porte DEUX : prendre le premier fait lire
    les bras dans le mauvais bloc et rend la garde AVEUGLE là où elle croit voir."""
    while True:
        j, quoi = jusqu_a(s, i, "{")
        if quoi != "{":
            return None
        fin = fin_bloc(s, j)
        k = fin
        while k < len(s) and s[k] in " \t\n":
            k += 1
        if k < len(s) and s[k] == "{":
            i = k
            continue
        return j


class Fonction:
    def __init__(self, nom, retour, corps, debut, src):
        self.nom, self.retour, self.corps, self.debut, self.src = nom, retour, corps, debut, src

    def ligne(self, off=0):
        return self.src.count("\n", 0, self.debut + off) + 1


def fonctions(nu: str):
    out = []
    for m in re.finditer(r"\bfn\s+([A-Za-z_]\w*)", nu):
        i = m.end()
        if nu[i:i + 1] == "<":                      # génériques
            prof = 0
            while i < len(nu):
                if nu[i] == "<":
                    prof += 1
                elif nu[i] == ">":
                    prof -= 1
                    if prof == 0:
                        i += 1
                        break
                i += 1
        i = nu.find("(", i)
        if i < 0:
            continue
        j = fin_bloc(nu, i)
        k, quoi = jusqu_a(nu, j, "{;")
        if quoi != "{":
            continue                                # déclaration de trait, sans corps
        out.append(Fonction(m.group(1), nu[j:k].strip(), nu[k:fin_bloc(nu, k)], m.start(), nu))
    return out


def bras_de_match(corps: str):
    res = []
    for m in re.finditer(r"\bmatch\b", corps):
        i = bloc_du_corps(corps, m.end())
        if i is None:
            continue
        interieur = corps[i + 1:fin_bloc(corps, i) - 1]
        base, bras, p = i + 1, [], 0
        while p < len(interieur):
            if interieur[p] in " \t\n,":
                p += 1
                continue
            q, quoi = jusqu_a(interieur, p, "", aussi=("=>",))
            if quoi != "=>":
                break
            motif = interieur[p:q]
            r = q + 2
            while r < len(interieur) and interieur[r] in " \t\n":
                r += 1
            if r < len(interieur) and interieur[r] == "{":
                s = fin_bloc(interieur, r)
            else:
                s, _ = jusqu_a(interieur, r, ",")
                s += 1
            bras.append((motif, interieur[r:min(s, len(interieur))], base + r))
            p = s
        if bras:
            res.append(bras)
    return res


def si_let(corps: str):
    res = []
    for m in re.finditer(r"\bif\s+let\b", corps):
        i, j, quoi = m.end(), m.end(), None
        while True:
            j, quoi = jusqu_a(corps, j, "=")
            if quoi == "=" and (corps[j + 1:j + 2] == "=" or corps[j - 1:j] in "=!<>"):
                j += 2
                continue
            break
        if quoi != "=":
            continue
        k = bloc_du_corps(corps, j + 1)
        if k is None:
            continue
        fin = fin_bloc(corps, k)
        mm = re.match(r"\s*else\b", corps[fin:])
        els = ""
        if mm:
            r = fin + mm.end()
            while r < len(corps) and corps[r] in " \t\n":
                r += 1
            if r < len(corps) and corps[r] == "{":
                els = corps[r:fin_bloc(corps, r)]
            else:
                els = corps[r:r + 200]
        res.append((m.start(), corps[i:j], corps[k:fin], bool(mm), els))
    return res


def let_sinon(corps: str):
    res = []
    for m in re.finditer(r"\blet\b", corps):
        if corps[max(0, m.start() - 3):m.start()].strip().endswith("if"):
            continue
        i, j, quoi = m.end(), m.end(), None
        while True:
            j, quoi = jusqu_a(corps, j, "=;")
            if quoi == "=" and (corps[j + 1:j + 2] == "=" or corps[j - 1:j] in "=!<>"):
                j += 2
                continue
            break
        if quoi != "=":
            continue
        k, quoi = jusqu_a(corps, j + 1, ";", aussi=("else",))
        if quoi != "else":
            continue
        r = k + 4
        while r < len(corps) and corps[r] in " \t\n":
            r += 1
        if r >= len(corps) or corps[r] != "{":
            continue
        res.append((m.start(), corps[i:j], corps[r:fin_bloc(corps, r)]))
    return res


# ==================================================================================================
# LA RÈGLE
# ==================================================================================================
# COMPTER (`+=`), CONSIGNER nominativement (`.push(` — c'est la forme de `S36` : un compte sauté est
# poussé dans la liste des comptes sautés, que l'aveu nomme), lever un drapeau, PROPAGER.
# Un drapeau se POSE dans les deux sens : `perdu = true` et `complet = false` portent la même information à
# celui qui lit le drapeau ensuite (mesuré le 2026-08-22 sur `secure_delete`, dont `complet` est RENDU).
TRACE_COMPTE = re.compile(r"\+=|\.push\(|=\s*(?:true|false)\b|bail!|panic!|unreachable!|todo!|\?")
RETOUR_PORTEUR = re.compile(r"\breturn\s+([A-Za-z0-9_&*(\[][^;]*)")
# `return 0` (aucune perte) et `return Ok(())` (tout va bien) sur une branche d'ÉCHEC NIENT la perte
# au lieu de la porter : ce sont des retours NEUTRES, et ils ne valent pas trace. C'est la forme
# dégénérée la plus tentante d'un correctif — rendre le bon type, et mentir dedans.
# Et la forme dégénérée d'un ÉNUMÉRATEUR : rendre une collection VIDE sur un échec d'énumération, c'est
# dire « il n'y a rien là » précisément là où l'on n'a pas su regarder — `Vec::new()`, `vec![]`,
# `Default::default()`, nus ou sous `Ok(…)`/`Lue(…)`. MESURÉ le 2026-08-22 : la mutation `Err(_) =>
# return Mesure::Lue(Vec::new())` dans `lister` passait la garde avant cette ligne.
VIDE = r"(?:Vec::new\(\)|vec!\[\s*\]|Default::default\(\)|String::new\(\))"
RETOUR_NEUTRE = re.compile(
    r"^(?:0|Ok\(\(\)\)|(?:[A-Za-z_][\w:]*::)?Lue\(0\)|" + VIDE + r"|(?:[A-Za-z_][\w:]*::)?(?:Lue|Ok|Some)\(" + VIDE + r"\))\s*$"
)
# Ce qu'un ÉVALUATEUR ou un ÉMETTEUR de détection FAIT — lu sur la source NON dénudée (c'est du SQL) :
# il écrit une alerte, ou il avance le curseur d'un élément ordonnancé.
SQL_EVALUE_OU_EMET = re.compile(r"INTO\s+alert\b|SET\s+last_run\s*=")
# Un énumérateur PAR DÉLÉGATION rend des chemins.
REND_DES_CHEMINS = re.compile(r"\bPathBuf\b")
# La PROPRIÉTÉ : un adaptateur d'itération qui jette le bras d'erreur sans aucune branche — `.flatten()`,
# `.filter_map`/`.flat_map` sur `Result::ok`, ou sur une fermeture `|x| x.ok()` (mesuré le 2026-08-22 : la
# forme fermeture passait quand seules les deux orthographes nommées étaient refusées).
JETTE_LES_ERREURS = re.compile(
    r"\.flatten\(\)|\.(?:filter_map|flat_map)\(\s*(?:Result::ok|\|\s*(\w+)\s*\|\s*\1\.ok\(\))\s*\)"
)
TRACE_DIT = re.compile(r"\bprintln!|bail!|panic!|\?|\breturn\s+Err\b")
FS_OU_NOYAU = re.compile(r"\bstd::fs::|\blibc::|\bfs::\w")
PRINTLN = re.compile(r"\bprintln!")
ABANDON = re.compile(r"\breturn\b|\bcontinue\b|\bbreak\b")


def bloc_de_condition(s: str, i: int):
    """Le `{` qui ouvre le corps d'un `if <condition>` SANS motif. Un bloc d'expression dans la condition
    (`if unsafe { libc::x() } < 0 {`) est suivi d'un OPÉRATEUR, d'un `.`, d'un `as` ou d'un autre `{` ;
    le bloc du corps, lui, est suivi d'un `else`, d'une instruction, ou de la fin du bloc englobant."""
    while True:
        j, quoi = jusqu_a(s, i, "{")
        if quoi != "{":
            return None
        k = fin_bloc(s, j)
        while k < len(s) and s[k] in " \t\n":
            k += 1
        if k < len(s) and (s[k] in "{<>=!.&|)+-*/%,?" or s.startswith("as ", k)):
            i = k if s[k] == "{" else k + 1
            continue
        return j


def sinon_de(corps: str, fin: int):
    """Le `else` qui suit un bloc fermé en `fin` : (présent ?, texte de TOUTE la chaîne `else …`)."""
    mm = re.match(r"\s*else\b", corps[fin:])
    if not mm:
        return False, ""
    r = fin + mm.end()
    while r < len(corps) and corps[r] in " \t\n":
        r += 1
    if r < len(corps) and corps[r] == "{":
        return True, corps[r:fin_bloc(corps, r)]
    # `else if …` : la branche est toute la chaîne qui suit, jusqu'à son dernier bloc.
    k = bloc_de_condition(corps, r) if corps.startswith("if", r) else None
    if k is None:
        return True, corps[r:r + 200]
    fin2 = fin_bloc(corps, k)
    _, suite = sinon_de(corps, fin2)
    return True, corps[r:fin2] + suite


def clauses(cond: str):
    """Les clauses d'une condition, séparées aux `&&` / `||` de profondeur 0, parenthèses externes ôtées."""
    out, i, depth, debut = [], 0, 0, 0
    while i < len(cond):
        c = cond[i]
        if c in OUVR:
            depth += 1
        elif c in FERM:
            depth -= 1
        elif depth == 0 and cond[i:i + 2] in ("&&", "||"):
            out.append(cond[debut:i])
            i += 2
            debut = i
            continue
        i += 1
    out.append(cond[debut:])
    res = []
    for cl in out:
        cl = cl.strip()
        while cl.startswith("(") and fin_bloc(cl, 0) == len(cl):
            cl = cl[1:-1].strip()
        res.append(cl)
    return res


# (i) prédicat de méthode — sur un récepteur qui LIT LE MONDE (voir `lecteur_du_monde`).
PREDICAT_ECHEC = re.compile(r"^(?P<neg>!\s*)?(?P<recv>.+)\.(?P<m>is_err|is_none|is_null|is_ok|is_some)\(\)$", re.S)
# (ii) comparaison à une sentinelle de la convention C.
SENTINELLE = re.compile(r"^(?P<recv>.+?)\s*(?P<op><=|>=|==|!=|<|>)\s*(?P<val>-?\d+)$", re.S)
SENTINELLE_ECHEC = {("<", "0"), ("<=", "0"), ("==", "-1"), ("!=", "0")}
SENTINELLE_SUCCES = {(">=", "0"), ("==", "0"), ("!=", "-1"), (">", "-1")}


def sens_de_la_clause(cl: str, lit_le_monde):
    """`echec` si la clause est vraie sur l'ÉCHEC, `succes` si elle l'est sur le succès, sinon None.
    `lit_le_monde(expr)` dit si l'opérande comparé est le retour d'une primitive (ou un nom qui y est lié)."""
    m = PREDICAT_ECHEC.match(cl)
    if m:
        if not lit_le_monde(m.group("recv")):
            return None                             # `action_valid(t).is_err()` : une DÉCISION, pas une lecture
        echec = m.group("m") in ("is_err", "is_none", "is_null")
        return "succes" if bool(m.group("neg")) == echec else "echec"
    m = SENTINELLE.match(cl)
    if m and lit_le_monde(m.group("recv")):
        cle = (m.group("op"), m.group("val"))
        if cle in SENTINELLE_ECHEC:
            return "echec"
        if cle in SENTINELLE_SUCCES:
            return "succes"
    return None


def si_test(corps: str, lit_le_monde):
    """`if <prédicat ou comparaison> { … } [else …]` — jamais un `if let`, jamais une garde de `match`.
    Rend (décalage, sens, condition, bloc then, a_else, bloc else)."""
    res = []
    for m in re.finditer(r"\bif\b", corps):
        if re.match(r"\s*let\b", corps[m.end():]):
            continue
        k = bloc_de_condition(corps, m.end())
        if k is None:
            continue
        cond = corps[m.end():k]
        if "=>" in cond:
            continue                                # `Some(x) if x < 0 => …` : une garde de match
        sens = None
        for cl in clauses(cond):
            sens = sens_de_la_clause(cl, lit_le_monde)
            if sens:
                break
        if not sens:
            continue
        fin = fin_bloc(corps, k)
        a_else, els = sinon_de(corps, fin)
        res.append((m.start(), sens, cond.strip(), corps[k:fin], a_else, els))
    return res


def recepteur(s: str, pos: int) -> str:
    """La chaîne d'appels qui PRÉCÈDE le `.` en `pos` : `std::fs::read_dir(d).map(|e| e.count())` devant
    `.unwrap_or(0)`. Remonte les groupes équilibrés, les turbofish, les noms et chemins, et les `.`/`?`."""
    i = pos
    while i > 0:
        j = i - 1
        while j >= 0 and s[j] in " \t\n":
            j -= 1
        if j < 0:
            break
        c = s[j]
        if c in ")]}":
            depth, k = 0, j
            while k >= 0:
                if s[k] in ")]}":
                    depth += 1
                elif s[k] in "([{":
                    depth -= 1
                    if depth == 0:
                        break
                k -= 1
            i = max(k, 0)
            continue
        if c == ">":
            if s[j - 1:j] == "=":
                break                               # `=>` : un bras de match, pas un turbofish
            depth, k = 0, j
            while k >= 0:
                if s[k] == ">":
                    depth += 1
                elif s[k] == "<":
                    depth -= 1
                    if depth == 0:
                        break
                k -= 1
            if s[k - 2:k] != "::":
                break                               # un `<` qui n'est pas `::<` est un opérateur
            i = max(k, 0)
            continue
        if c.isalnum() or c in "_:":
            k = j
            while k >= 0 and (s[k].isalnum() or s[k] in "_:"):
                k -= 1
            i = k + 1
            continue
        if c in ".?":
            i = j
            continue
        break
    return s[i:pos].strip()


# (iii) la valeur NEUTRE : celle qui dit « rien » — zéro, faux, vide, défaut, `Lue(0)`.
NEUTRE = r"(?:0(?:_?[ui](?:8|16|32|64|size))?|false|" + VIDE + r"|(?:[A-Za-z_][\w:]*::)?Lue\(0\)|Vec::new|String::new|Default::default)"
REPLI_NEUTRE = re.compile(
    r"\.(?:unwrap_or_default\(\)|(?:unwrap_or|map_or)\(\s*" + NEUTRE + r"\s*[,)]|unwrap_or_else\()"
)


def replis_neutres(corps: str, lit_le_monde):
    """Les `.unwrap_or(neutre)` / `.unwrap_or_default()` / `.map_or(neutre, …)` / `.unwrap_or_else(…)` dont
    le récepteur LIT LE MONDE. Rend (décalage, forme, branche d'échec — le corps de la fermeture, s'il y
    en a un, où une trace peut vivre)."""
    res = []
    for m in REPLI_NEUTRE.finditer(corps):
        forme = m.group(0)
        branche = ""
        if forme.startswith(".unwrap_or_else("):
            fin = fin_bloc(corps, m.end() - 1)
            arg = corps[m.end():fin - 1].strip()
            mm = re.match(r"\|[^|]*\|\s*", arg)
            expr = arg[mm.end():].strip() if mm else arg
            if expr.startswith("{"):
                interieur = expr[1:fin_bloc(expr, 0) - 1]
                if TRACE_COMPTE.search(interieur):
                    continue                        # la fermeture compte : c'est une trace
                dernier = interieur.strip().rstrip(";").split(";")[-1].strip()
                if not re.fullmatch(NEUTRE, dernier):
                    continue
                branche = interieur
            elif not re.fullmatch(NEUTRE, expr):
                continue                            # `unwrap_or_else(|e| calcule(e))` choisit une valeur
            forme = ".unwrap_or_else(%s)" % expr[:30]
        if not lit_le_monde(recepteur(corps, m.start())):
            continue
        res.append((m.start(), "`%s`" % forme.strip(), branche))
    return res


# Les adaptateurs de `Result`/`Option` : ils TRANSPORTENT l'échec d'une lecture sans le décider. Tout autre
# appel après la tête (`.get(`, `.len(`, `.as_str(`) travaille sur le CONTENU lu, et l'échec qu'on teste
# ensuite n'est plus celui de la lecture.
ADAPTATEURS = "map|and_then|ok|as_ref|as_deref|as_mut|map_err|cloned|copied|filter|flatten|ok_or|ok_or_else|or_else|or|inspect|inspect_err|by_ref"
# Ce qui LIT LE MONDE : une énumération, le système de fichiers, le noyau, la base — ou un appel à une
# fonction de couverture, ajouté par `analyser_crate` une fois la population dérivée.
LIT_LE_MONDE = re.compile(
    r"read_dir|std::fs::|\bfs::\w|libc::|\bunsafe\b|\bmetadata\(|File::open|"
    # les verbes SQL et les verbes d'E/S de `std::io` : la primitive est la MÉTHODE (`conn.query_row(…)`,
    # `f.write_all(…)`), lue SANS son point parce que la chaîne est découpée en segments.
    r"\b(?:query_row|query_map|prepare(?:_cached)?|execute(?:_batch)?|query|batch)\(|"
    r"\b(?:write_all|read_to_string|read_to_end|read_exact|flush|sync_all|sync_data|set_len)\("
)


def noms_lies(corps: str, lit):
    """Les noms qu'une fonction LIE à une expression qui lit le monde : `let fd = unsafe { … };`,
    `let (a, b) = …;`, `self.fd = libc::…;`. C'est ce qui fait d'un `if fd < 0` un test d'échec."""
    noms = set()
    for m in re.finditer(r"\blet\s+(?:mut\s+)?(\(?[\w\s,]+\)?)\s*(?::[^=;]+)?=\s*([^;]*);", corps):
        if lit(m.group(2)):
            noms |= set(re.findall(r"[A-Za-z_]\w*", m.group(1))) - {"mut"}
    for m in re.finditer(r"(?:^|[;{}\s])((?:self\.)?\w+)\s*=\s*([^;=][^;]*);", corps):
        if lit(m.group(2)):
            noms.add(m.group(1))
    # Une liaison par MOTIF lie aussi : `Ok(mut f) =>` sur un scrutin qui lit le monde, `if let Ok(x) = …`,
    # `let Ok(x) = … else`. C'est ainsi qu'un `f.write_all(…).is_err()` sait que `f` vient d'un `open`.
    motif = r"\b(?:Ok|Some|Lue)\(\s*(?:mut\s+)?(\w+)\s*\)"
    for m in re.finditer(r"\bmatch\b", corps):
        k = bloc_du_corps(corps, m.end())
        if k is None or not lit(corps[m.end():k]):
            continue
        noms |= set(re.findall(motif + r"\s*(?:if\b[^=]*)?=>", corps[k:fin_bloc(corps, k)]))
    for m in re.finditer(r"\blet\s+" + motif + r"\s*=\s*([^{;]+?)\s*(?:\{|\belse\b)", corps):
        if lit(m.group(2)):
            noms.add(m.group(1))
    return noms


def lecteur_du_monde(corps: str, noms_de_couverture):
    """Le prédicat « cette expression lit le monde » d'UNE fonction : la forme, ou un nom lié à la forme."""
    appel_couvert = re.compile(r"\b(?:%s)\s*\(" % "|".join(sorted(noms_de_couverture))) \
        if noms_de_couverture else None

    def forme(expr):
        return bool(LIT_LE_MONDE.search(expr)) or bool(appel_couvert and appel_couvert.search(expr))

    lies = noms_lies(corps, forme)

    def lit(expr):
        """Une expression lit le monde si sa chaîne d'appels a une TÊTE qui le lit — une primitive, ou un nom
        lié à une primitive — suivie UNIQUEMENT d'adaptateurs de `Result`/`Option` (`map`, `and_then`, `ok`…).
        `config.get("url")…` NAVIGUE dans un contenu déjà lu : ce n'est plus le monde, c'est sa forme."""
        segments, i, depth, debut = [], 0, 0, 0
        expr = expr.strip()
        while i < len(expr):
            c = expr[i]
            if c in OUVR:
                depth += 1
            elif c in FERM:
                depth -= 1
            elif c == "." and depth == 0 and expr[i + 1:i + 2] != ".":
                segments.append(expr[debut:i])
                debut = i + 1
            i += 1
        segments.append(expr[debut:])
        segments = [t.strip() for t in segments]
        if len(segments) > 1 and segments[0] in ("self", "*self", "&self"):
            segments[:2] = [segments[0].lstrip("*&") + "." + segments[1]]
        # La tête est la DERNIÈRE primitive de la chaîne (`f.write_all(…)` : la primitive est la méthode, pas
        # le nom), ou le nom lié en position 0 s'il n'y a pas de primitive écrite.
        primitives = [k for k, seg in enumerate(segments) if forme(seg)]
        nom = re.fullmatch(r"[*&]*\s*((?:self\.)?[A-Za-z_]\w*)", segments[0])
        if primitives:
            tete = primitives[-1]
        elif nom and (nom.group(1) in lies or nom.group(1).removeprefix("self.") in lies):
            tete = 0
        else:
            return False
        return all(re.match(r"(?:%s)\s*(?:::<[^>]*>)?\s*\(" % ADAPTATEURS, seg) for seg in segments[tete + 1:])
    return lit


def motif_d_echec(m):
    m = m.strip()
    return m.startswith("Err") or m == "_" or m.startswith("None") or "Illisible" in m


def motif_de_succes(m):
    return re.search(r"\b(Ok|Some|Lue)\s*\(", m) is not None


def compte_la_perte(branche):
    """La branche laisse-t-elle une trace EXPLOITABLE : un compte, un drapeau, une propagation ?"""
    if TRACE_COMPTE.search(branche):
        return True
    m = RETOUR_PORTEUR.search(branche)
    # Un bras de `match` se termine par une virgule, pas un point-virgule : `return Lue(0),` est le
    # même retour neutre que `return Lue(0);`. MESURÉ le 2026-08-22 : sans ce rognage, la mutation
    # `Err(_) => return Mesure::Lue(0),` dans `run_due_rules` passait la garde.
    # Même chose pour l'accolade qui ferme un `else { return Lue(0) }` sans point-virgule (mesuré sur
    # `verifier_flotte_muette`, même jour).
    return bool(m) and not RETOUR_NEUTRE.match(m.group(1).strip().rstrip(",;} \t\n").strip())


def abandonne(branche, sans_else):
    """La branche d'échec RENONCE-t-elle à l'objet en cours ? (vide, ou transfert de contrôle nu)"""
    if sans_else:
        return True
    corps = branche.strip().strip("{}").strip()
    return corps == "" or ABANDON.search(corps) is not None


def masque_les_tests(nu):
    """Un module `#[cfg(test)]` (quelle que soit sa visibilité : `pub`, `pub(crate)`…) et un FICHIER qui
    commence par `#![cfg(test)]` sont du code de test : ils n'entrent dans aucune population. MESURÉ le
    2026-08-22 : sans `pub(crate)`, trois « sites » du démon étaient un helper de test ; sans
    `#![cfg(test)]`, la garde de lisibilité du collecteur mail comptait parmi la couverture."""
    if re.match(r"\s*#!\[cfg\(test\)\]", nu):
        return " " * len(nu)
    out = list(nu)
    for m in re.finditer(r"#\[cfg\(test\)\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{", nu):
        i = nu.index("{", m.end() - 1)
        for k in range(m.start(), fin_bloc(nu, i)):
            if out[k] != "\n":
                out[k] = " "
    return "".join(out)


def fonctions_de_pose(nu):
    """Les `fn watch_root` d'un `impl <CONTRAT> for X` (ou du trait). DÉRIVÉ DU CONTRAT, jamais d'une
    liste de backends : un backend écrit demain doit implémenter ce contrat pour être branché."""
    noms = set()
    for m in re.finditer(r"\b(?:impl\s+%s\s+for\b|trait\s+%s\b)" % (CONTRAT, CONTRAT), nu):
        i = nu.find("{", m.end())
        if i < 0:
            continue
        bloc = nu[i:fin_bloc(nu, i)]
        noms |= {n for n in re.findall(r"\bfn\s+([a-z_]\w*)", bloc) if n == POSE}
    return noms


def appels(corps):
    """Appels LIBRES et appels sur `self` — jamais une méthode d'un autre objet (`v.len()`), sans quoi
    la fermeture d'appel avalerait tout le fichier par collision de noms."""
    return set(re.findall(r"(?:^|[^.\w])([a-z_]\w*)\s*\(", corps)) \
        | set(re.findall(r"\bself\.([a-z_]\w*)\s*\(", corps))


def appels_qualifies(corps):
    """Appels par CHEMIN (`Type::f(`, `crate::module::f(`) : résolus dans le crate entier, parce que le
    chemin lève l'ambiguïté qu'un nom nu n'a pas."""
    return set(re.findall(r"::([a-z_]\w*)\s*\(", corps))


def noms_importes(nu):
    """Les noms qu'un fichier IMPORTE d'un autre module du crate (`use crate::m::{a, b}`, `use super::c;`,
    y compris un `use` posé dans un corps de fonction). Un appel nu à l'un d'eux est un appel QUALIFIÉ
    dont le chemin est écrit plus haut : il se résout dans le crate, pas dans le fichier."""
    noms = set()
    for m in re.finditer(r"\buse\s+(?:crate|super|self)(?:::\w+)*::\{([^}]*)\}", nu):
        for partie in m.group(1).split(","):
            partie = partie.strip().split(" as ")[0].strip()
            if re.fullmatch(r"[a-z_]\w*", partie):
                noms.add(partie)
    for m in re.finditer(r"\buse\s+(?:crate|super|self)(?:::\w+)*::([a-z_]\w*)\s*;", nu):
        noms.add(m.group(1))
    return noms


def sites_de(f, est_c, lit_le_monde=lambda expr: bool(LIT_LE_MONDE.search(expr))):
    """Les alternatives d'une fonction dont la branche d'échec abandonne — avec, pour chacune, la branche
    d'échec (vide pour un `if let` sans else), son décalage et si une branche JUMELLE imprime."""
    sites = []
    for bras in bras_de_match(f.corps):
        a_succes = any(motif_de_succes(m) for m, _, _ in bras)
        jumelle = any(PRINTLN.search(c) for _, c, _ in bras)
        for motif, corps_bras, off in bras:
            if a_succes and motif_d_echec(motif) and abandonne(corps_bras, False):
                sites.append(("bras `%s =>` d'un match" % motif.strip()[:26], corps_bras, off, jumelle))
    for off, motif, alors, a_else, els in si_let(f.corps):
        if motif_de_succes(motif) and abandonne(els, not a_else):
            forme = "`if let %s` %s" % (motif.strip()[:24], "SANS else" if not a_else else "/ else")
            sites.append((forme, els if a_else else "", off, bool(PRINTLN.search(alors))))
        elif motif_d_echec(motif) and abandonne(alors, False):
            # `if let Err(e) = … { …; continue }` : la forme INVERSÉE, où le bloc `then` EST la branche
            # d'échec. MESURÉ le 2026-08-22 : la mutation qui retire `ch.ignores += 1` de ce bloc dans
            # `load_overlay_rules` passait la garde, qui ne lisait que `if let Ok/Some`.
            forme = "`if let %s` (bloc d'échec)" % motif.strip()[:24]
            sites.append((forme, alors, off, bool(PRINTLN.search(els)) if a_else else False))
    for off, motif, els in let_sinon(f.corps):
        if motif_de_succes(motif) and abandonne(els, False):
            sites.append(("`let %s … else`" % motif.strip()[:24], els, off, False))
    # `P4.1-s` : l'échec testé par PRÉDICAT ou par COMPARAISON — le bloc `then` est la branche d'échec
    # quand la condition est vraie sur l'échec ; c'est le `else` (ou le vide) quand elle l'est sur le succès.
    for off, sens, cond, alors, a_else, els in si_test(f.corps, lit_le_monde):
        if sens == "echec" and abandonne(alors, False):
            sites.append(("`if %s` (bloc d'échec)" % cond[:28], alors, off,
                          bool(PRINTLN.search(els)) if a_else else False))
        elif sens == "succes" and abandonne(els, not a_else) and not (not a_else and abandonne(alors, False)):
            # `if q.is_ok() { return }` SANS else : le succès abandonne (« déjà fait »), la suite de la fonction
            # est le chemin de travail sur l'échec — rien n'est perdu. Sinon le `else` vide est la branche d'échec.
            forme = "`if %s` %s" % (cond[:28], "SANS else" if not a_else else "/ else")
            sites.append((forme, els if a_else else "", off, bool(PRINTLN.search(alors))))
    if est_c:
        for m in JETTE_LES_ERREURS.finditer(f.corps):
            sites.append(("`%s`" % m.group(0), "", m.start(), False))
        # `P4.1-s` (iii) : le repli NEUTRE sur un récepteur qui lit le monde est `return Lue(0)` en une méthode.
        for off, forme, branche in replis_neutres(f.corps, lit_le_monde):
            sites.append((forme, branche, off, False))
    return sites


class Unite:
    """Une fonction, avec son fichier et son corps NON dénudé (le SQL y est lisible)."""
    def __init__(self, chemin, f, nu, brut):
        self.chemin, self.f, self.nu = chemin, f, nu
        k = nu.find(f.corps, f.debut)
        self.brut = brut[k:k + len(f.corps)]
        importes = noms_importes(nu)
        nus = appels(f.corps)
        self.appels_nus = nus - importes
        self.appels_qualifies = appels_qualifies(f.corps) | (nus & importes)


def analyser_crate(fichiers, derivations=("pose", "charge", "evalue")):
    """`fichiers` : liste de (chemin, texte). Les populations sont dérivées sur le CRATE entier — les
    appels nus résolus dans le fichier, les appels qualifiés dans le crate. `derivations` dit ce que
    « poser de la surveillance » veut dire dans ce crate (cf. `CRATES`)."""
    unites = []
    for chemin, texte in fichiers:
        nu = masque_les_tests(denude(texte))
        for f in fonctions(nu):
            unites.append(Unite(chemin, f, nu, texte))
    par_fichier = {}
    par_nom = {}
    for u in unites:
        par_fichier.setdefault(u.chemin, {}).setdefault(u.f.nom, []).append(u)
        par_nom.setdefault(u.f.nom, []).append(u)

    def cibles(u):
        """Les unités que `u` appelle : nues dans son fichier, qualifiées dans le crate."""
        out = []
        for n in u.appels_nus:
            out += par_fichier[u.chemin].get(n, [])
        for n in u.appels_qualifies:
            out += par_nom.get(n, [])
        return out

    # (a) la POSE du contrat, (b) l'ÉNUMÉRATION directe
    enum = set()
    for u in unites:
        if u.f.nom in fonctions_de_pose(u.nu) or "read_dir(" in u.f.corps:
            enum.add(id(u))
    # (b, par délégation) : atteint un énumérateur par appel ET rend des chemins. C'est la dérivation
    # « charge » : elle fait entrer un listing rendu par un autre module, et les chargeurs qui le
    # consomment. Le crate de l'agent garde la population de `P4.1-q` telle quelle.
    if "charge" in derivations:
        change = True
        while change:
            change = False
            for u in unites:
                if id(u) in enum or not REND_DES_CHEMINS.search(u.f.retour):
                    continue
                if any(id(c) in enum for c in cibles(u)):
                    enum.add(id(u))
                    change = True
    couverture = set(enum)
    # (d) le CONSOMMATEUR d'une énumération
    if "charge" in derivations:
        for u in unites:
            if id(u) not in couverture and any(id(c) in enum for c in cibles(u)):
                couverture.add(id(u))
    # (e) l'ÉVALUATEUR / l'ÉMETTEUR de détection
    if "evalue" in derivations:
        for u in unites:
            if SQL_EVALUE_OU_EMET.search(u.brut):
                couverture.add(id(u))
    # (c) fermeture descendante : appelé depuis la couverture ET touche le système de fichiers / le noyau
    change = True
    while change:
        change = False
        for u in unites:
            if id(u) not in couverture:
                continue
            for c in cibles(u):
                if id(c) not in couverture and FS_OU_NOYAU.search(c.f.corps):
                    couverture.add(id(c))
                    change = True
    surface = {id(u) for u in unites if PRINTLN.search(u.f.corps)}
    noms_de_couverture = {u.f.nom for u in unites if id(u) in couverture}

    fautes = []
    for u in unites:
        est_c, est_s = id(u) in couverture, id(u) in surface
        if not (est_c or est_s):
            continue
        for forme, branche, off, jumelle in sites_de(u.f, est_c, lecteur_du_monde(u.f.corps, noms_de_couverture)):
            if est_c and not compte_la_perte(branche):
                fautes.append((u.chemin, u.f.ligne(off + 1), u.f.nom, "COUVERTURE", forme))
            elif est_s and jumelle and not TRACE_DIT.search(branche):
                fautes.append((u.chemin, u.f.ligne(off + 1), u.f.nom, "SURFACE", forme))
    # Comptées PAR FICHIER ET PAR NOM : deux backends qui implémentent la même méthode sont deux
    # fonctions de couverture, pas une (c'est ainsi que la mesure de `P4.1-q` les comptait).
    noms_c = {(u.chemin, u.f.nom) for u in unites if id(u) in couverture}
    noms_s = {(u.chemin, u.f.nom) for u in unites if id(u) in surface}
    return fautes, noms_c, noms_s


def analyser(chemin, texte):
    """Un seul fichier — la forme historique, conservée pour les témoins et pour rejouer la mesure."""
    return analyser_crate([(chemin, texte)])


# ==================================================================================================
# VALIDATION DE L'INSTRUMENT — témoin POSITIF et témoin NÉGATIF, avant de croire un seul verdict
# ==================================================================================================
POSE_MUETTE = """
impl FimBackend for X {
    fn watch_root(&mut self, root: &Path) -> usize { self.descendre(root); 0 }
}
impl X {
    fn descendre(&mut self, root: &Path) {
        let entries = match std::fs::read_dir(root) { Ok(e) => e, Err(_) => return };
        for ent in entries.flatten() { let _ = libc::x(ent); }
    }
}
"""
POSE_QUI_COMPTE = """
impl FimBackend for X {
    fn watch_root(&mut self, root: &Path) -> usize { self.descendre(root); 0 }
}
impl X {
    fn descendre(&mut self, root: &Path) {
        let entries = match std::fs::read_dir(root) {
            Ok(e) => e,
            Err(_) => { self.perdus += 1; return; }
        };
        for ent in entries {
            let ent = match ent { Ok(e) => e, Err(_) => { self.perdus += 1; continue; } };
            let _ = libc::x(ent);
        }
    }
}
"""
POSE_DEGENEREE = """
impl FimBackend for X {
    fn watch_root(&mut self, _root: &Path) -> usize { 0 }
}
impl X {
    fn descendre(&mut self, root: &Path) {
        let _ = std::fs::read_dir(root);
        let _ = libc::x(root);
    }
}
"""
POSE_MUETTE_SOUS_UNSAFE = """
impl FimBackend for X {
    fn watch_root(&mut self, root: &Path) -> usize {
        let _ = std::fs::read_dir(root);
        let h = match unsafe { libc::open_it(root) } { Ok(h) => h, _ => return 0 };
        let _ = h;
        0
    }
}
"""
SURFACE_MUETTE = """
fn cmd_status(p: &Path) -> Result<()> {
    if let Ok(cfg) = Config::load(p) { println!("file: {}", cfg.n); }
    Ok(())
}
"""
SURFACE_QUI_DIT = """
fn cmd_status(p: &Path) -> Result<()> {
    match Config::load(p) {
        Ok(cfg) => println!("file: {}", cfg.n),
        Err(e) => println!("file: profondeur INCONNUE ({e})"),
    }
    Ok(())
}
"""
SURFACE_QUI_ECHOUE = """
fn cmd_status(p: &Path) -> Result<()> {
    let cfg = match Config::load(p) { Ok(c) => c, Err(e) => anyhow::bail!("{e}") };
    println!("file: {}", cfg.n);
    Ok(())
}
"""

EVALUATEUR_MUET = """
fn run_due_rules(db: &Db) {
    let due = match conn.prepare("SELECT id FROM rule WHERE last_run IS NULL") { Ok(s) => s, Err(_) => return };
    for r in due.query_map([], |r| r.get(0)).unwrap().flatten() {
        let _ = conn.execute("UPDATE rule SET last_run=?1 WHERE id=?2", params![now, r]);
        let _ = conn.execute("INSERT OR IGNORE INTO alert(ts,rule) VALUES(?1,?2)", params![now, r]);
    }
}
"""
EVALUATEUR_QUI_REND_SON_BILAN = """
fn run_due_rules(db: &Db) -> Mesure<u32> {
    let mut abandonnees = 0u32;
    let due = match conn.prepare("SELECT id FROM rule WHERE last_run IS NULL") {
        Ok(s) => s,
        Err(e) => return tick_aveugle("règles", &e),
    };
    for r in due.query_map([], |r| r.get(0)).unwrap() {
        let r = match r { Ok(r) => r, Err(_) => { abandonnees += 1; continue; } };
        let _ = conn.execute("UPDATE rule SET last_run=?1 WHERE id=?2", params![now, r]);
        let _ = conn.execute("INSERT OR IGNORE INTO alert(ts,rule) VALUES(?1,?2)", params![now, r]);
    }
    Mesure::Lue(abandonnees)
}
"""
EVALUATEUR_QUI_MENT = """
fn run_due_rules(db: &Db) -> Mesure<u32> {
    let due = match conn.prepare("SELECT id FROM rule") { Ok(s) => s, Err(_) => return Mesure::Lue(0) };
    let _ = conn.execute("UPDATE rule SET last_run=?1 WHERE id=?2", params![now, 1]);
    Mesure::Lue(0)
}
"""
# Un chargeur qui CONSOMME un listing rendu par un AUTRE fichier : c'est (d) avec la résolution qualifiée.
LISTING_DELEGUE = """
pub(crate) fn lister(dir: &Path) -> Mesure<Vec<PathBuf>> {
    let entrees = match std::fs::read_dir(dir) { Ok(e) => e, Err(e) => return Mesure::Illisible { cause: cause_io(&e), detail: String::new() } };
    let mut v = Vec::new();
    for e in entrees { match e { Ok(e) => v.push(e.path()), Err(_) => return Mesure::Illisible { cause: "x", detail: String::new() } } }
    Mesure::Lue(v)
}
impl Chargement {
    pub(crate) fn ouvrir(dir: &Path) -> (Vec<PathBuf>, Chargement) {
        match crate::adossement::lister(dir) { Mesure::Lue(v) => (v, Chargement::default()), Mesure::Illisible { .. } => (Vec::new(), Chargement::default()) }
    }
}
"""
CHARGEUR_MUET = """
fn load_overlay_rules(conn: &Connection, dir: &Path) -> u32 {
    let mut n = 0;
    let (fichiers, _ch) = crate::adossement::Chargement::ouvrir(dir);
    for path in fichiers {
        let v = match lire(&path) { Some(v) => v, None => continue };
        n += 1;
    }
    n
}
"""
CHARGEUR_QUI_COMPTE = """
fn load_overlay_rules(conn: &Connection, dir: &Path) -> Chargement {
    let (fichiers, mut ch) = crate::adossement::Chargement::ouvrir(dir);
    for path in fichiers {
        let v = match lire(&path) { Some(v) => v, None => { ch.ignores += 1; continue; } };
        ch.charges += 1;
    }
    ch
}
"""
CHARGEUR_ERR_INVERSE = """
fn load_overlay_rules(conn: &Connection, dir: &Path) -> u32 {
    let mut n = 0;
    for path in std::fs::read_dir(dir).unwrap().flatten().map(|e| e.path()) {
        if let Err(e) = compile(&path) { eprintln!("{e}"); continue; }
        n += 1;
    }
    n
}
"""
SONDE_LET_ELSE_QUI_MENT = """
fn verifier_flotte_muette(conn: &Connection) -> Mesure<u32> {
    let Some(f) = flotte(conn) else { return Mesure::Lue(0) };
    let _ = conn.execute("INSERT OR IGNORE INTO alert(ts,rule) VALUES(?1,?2)", params![1, f]);
    Mesure::Lue(0)
}
"""
ENUMERATEUR_QUI_REND_VIDE = """
fn lister(dir: &Path) -> Mesure<Vec<PathBuf>> {
    let entrees = match std::fs::read_dir(dir) { Ok(e) => e, Err(_) => return Mesure::Lue(Vec::new()) };
    let mut v = Vec::new();
    for e in entrees { match e { Ok(e) => v.push(e.path()), Err(_) => return Mesure::Lue(vec![]) } }
    Mesure::Lue(v)
}
"""
INVENTAIRE_FILTER_MAP_FERMETURE = """
fn inventaire(racine: &Path) -> usize {
    let Ok(entrees) = std::fs::read_dir(racine) else { return 0 };
    entrees.filter_map(|e| e.ok()).count()
}
"""
INVENTAIRE_FILTER_MAP = """
fn inventaire(racine: &Path) -> usize {
    let Ok(entrees) = std::fs::read_dir(racine) else { return 0 };
    entrees.filter_map(Result::ok).count()
}
"""
TEST_SOUS_PUB_CRATE = """
#[cfg(test)]
pub(crate) mod door_tests {
    pub(crate) fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() { let Some(n) = e.path().to_str() else { continue }; out.push(n.into()); }
    }
}
fn sans_rapport() -> usize { 0 }
"""
FICHIER_DE_TEST = """
#![cfg(test)]
fn executer(dir: &Path) -> usize {
    let Ok(e) = std::fs::read_dir(dir) else { return 0 };
    e.flatten().count()
}
"""

# `P4.1-s` — L'ÉCHEC TESTÉ PAR COMPARAISON OU PAR MÉTHODE. Un témoin positif et un négatif PAR FORME, plus
# les trois négatifs qui bornent la population : le repli sur une grandeur qui n'arme rien, la longueur
# comparée, la validation refusée — et le drapeau ABAISSÉ qui vaut trace.
SENTINELLE_MUETTE = """
impl FimBackend for X {
    fn watch_root(&mut self, root: &Path) -> usize {
        for ent in std::fs::read_dir(root).unwrap() {
            let Ok(ent) = ent else { self.perdus += 1; continue };
            let wd = unsafe { libc::inotify_add_watch(self.fd, ent.path().as_ptr(), 0) };
            if wd < 0 {
                continue;
            }
            self.wds.insert(wd, ent.path());
        }
        self.perdus
    }
}
"""
SENTINELLE_QUI_COMPTE = """
impl FimBackend for X {
    fn watch_root(&mut self, root: &Path) -> usize {
        for ent in std::fs::read_dir(root).unwrap() {
            let Ok(ent) = ent else { self.perdus += 1; continue };
            let wd = unsafe { libc::inotify_add_watch(self.fd, ent.path().as_ptr(), 0) };
            if wd < 0 {
                self.perdus += 1;
                continue;
            }
            self.wds.insert(wd, ent.path());
        }
        self.perdus
    }
}
"""
PREDICAT_MUET = """
impl FimBackend for X {
    fn watch_root(&mut self, root: &Path) -> usize {
        let md = std::fs::symlink_metadata(root);
        if md.is_err() {
            return 0;
        }
        let _ = libc::x(root);
        0
    }
}
"""
PREDICAT_QUI_PROPAGE = """
impl FimBackend for X {
    fn watch_root(&mut self, root: &Path) -> usize {
        let md = std::fs::symlink_metadata(root);
        if md.is_err() {
            return 1;
        }
        let _ = libc::x(root);
        0
    }
}
"""
SUCCES_SANS_ELSE_MUET = """
impl FimBackend for X {
    fn watch_root(&mut self, root: &Path) -> usize {
        if std::fs::read_dir(root).is_ok() {
            let _ = libc::x(root);
        }
        0
    }
}
"""
REPLI_NEUTRE_SUR_ENUMERATION = """
impl FimBackend for X {
    fn watch_root(&mut self, root: &Path) -> usize {
        let n = std::fs::read_dir(root).map(|e| e.count()).unwrap_or(0);
        let _ = libc::x(root, n);
        0
    }
}
"""
REPLI_DEFAUT_SUR_LECTURE = """
fn inventaire(racine: &Path) -> usize {
    let Ok(entrees) = std::fs::read_dir(racine) else { return 1 };
    let mut n = 0;
    for e in entrees {
        let Ok(e) = e else { n += 1; continue };
        n += std::fs::metadata(e.path()).map(|m| m.len() as usize).unwrap_or_default();
    }
    n
}
"""
REPLI_DONT_LA_FERMETURE_COMPTE = """
impl FimBackend for X {
    fn watch_root(&mut self, root: &Path) -> usize {
        let n = std::fs::read_dir(root).map(|e| e.count()).unwrap_or_else(|_| { self.perdus += 1; 0 });
        let _ = libc::x(root, n);
        self.perdus
    }
}
"""
# Un `unwrap_or(0)` sur une grandeur qui N'ARME RIEN : une variable d'environnement, un champ de configuration
# déjà lu, une conversion. La fonction est de couverture ; ces replis ne sont pas des sites.
REPLI_HORS_POPULATION = """
impl FimBackend for X {
    fn watch_root(&mut self, root: &Path) -> usize {
        let profondeur = std::env::var("PLUME_FIM_DEPTH").ok().and_then(|v| v.parse::<u32>().ok()).unwrap_or(0);
        let cfg = std::fs::read_to_string(root).unwrap();
        let plafond = cfg.get("max").and_then(|v| v.as_u64()).unwrap_or(0);
        let nom = root.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        let _ = libc::x(root, profondeur, plafond, nom);
        0
    }
}
"""
# `roots.len() == 0` compare une LONGUEUR, pas le retour d'une primitive : « rien à faire », pas un échec.
LONGUEUR_COMPAREE = """
impl FimBackend for X {
    fn watch_root(&mut self, root: &Path) -> usize {
        let roots = self.roots.clone();
        if roots.len() == 0 {
            return 0;
        }
        let _ = std::fs::read_dir(root);
        let _ = libc::x(root);
        0
    }
}
"""
# Une VALIDATION refusée est une décision, pas une lecture du monde qui a échoué.
VALIDATION_REFUSEE = """
fn run_playbooks(conn: &Connection) -> Mesure<u32> {
    let mut abandonnes = 0u32;
    for cible in cibles(conn) {
        if cible.is_empty() || action_valid(&cible).is_err() {
            continue;
        }
        let _ = conn.execute("INSERT INTO alert(ts,rule) VALUES(?1,?2)", params![1, cible]);
    }
    Mesure::Lue(abandonnes)
}
"""
DRAPEAU_ABAISSE = """
fn effacer(dir: &Path) -> usize {
    let mut non_ecrases = 0;
    for ent in std::fs::read_dir(dir).unwrap() {
        let Ok(ent) = ent else { non_ecrases += 1; continue };
        let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(ent.path()) else { non_ecrases += 1; continue };
        let mut complet = true;
        for _ in 0..3 {
            if f.write_all(&[0u8; 8]).is_err() {
                complet = false;
                break;
            }
        }
        if !complet { non_ecrases += 1; }
    }
    non_ecrases
}
"""
DEJA_FAIT_QUI_REND_LA_MAIN = """
fn seed(conn: &Connection) {
    if conn.query_row("SELECT 1 FROM meta WHERE key='seeded'", [], |r| r.get::<_, i64>(0)).is_ok() { return; }
    let _ = conn.execute("INSERT INTO alert(ts,rule) VALUES(1,2)", []);
}
"""
SURFACE_PREDICAT_MUET = """
fn cmd_status(p: &Path) -> Result<()> {
    let spool = std::fs::read_dir(p).map(|e| e.count());
    if spool.is_ok() { println!("spool: {}", spool.unwrap()); }
    Ok(())
}
"""
SURFACE_PREDICAT_QUI_DIT = """
fn cmd_status(p: &Path) -> Result<()> {
    let spool = std::fs::read_dir(p).map(|e| e.count());
    if spool.is_ok() { println!("spool: {}", spool.unwrap()); } else { println!("spool: INCONNU"); }
    Ok(())
}
"""

TEMOINS = [
    ("pose qui abandonne un sous-arbre en silence", POSE_MUETTE, True),
    ("pose qui COMPTE ce qu'elle abandonne", POSE_QUI_COMPTE, False),
    ("pose DÉGÉNÉRÉE qui ne surveille plus rien", POSE_DEGENEREE, False),
    ("pose muette dont le scrutin est un bloc `unsafe`", POSE_MUETTE_SOUS_UNSAFE, True),
    ("surface où une grandeur DISPARAÎT", SURFACE_MUETTE, True),
    ("surface qui dit INCONNU", SURFACE_QUI_DIT, False),
    ("surface qui fait ÉCHOUER la commande", SURFACE_QUI_ECHOUE, False),
    ("évaluateur de règles qui rend la main sans rien dire", EVALUATEUR_MUET, True),
    ("évaluateur qui rend son bilan", EVALUATEUR_QUI_REND_SON_BILAN, False),
    ("évaluateur qui MENT (`Lue(0)` sur une liste illisible)", EVALUATEUR_QUI_MENT, True),
    ("inventaire qui jette les entrées illisibles par `filter_map(Result::ok)`", INVENTAIRE_FILTER_MAP, True),
    ("inventaire qui jette les entrées illisibles par une FERMETURE `filter_map(|e| e.ok())`", INVENTAIRE_FILTER_MAP_FERMETURE, True),
    ("chargeur dont le bloc d'échec `if let Err(e)` abandonne sans compter", CHARGEUR_ERR_INVERSE, True),
    ("énumérateur qui rend une liste VIDE sur un dossier refusé", ENUMERATEUR_QUI_REND_VIDE, True),
    ("sonde dont le `let … else` rend `Lue(0)` sans point-virgule", SONDE_LET_ELSE_QUI_MENT, True),
    # `P4.1-s`
    ("pose dont le `if wd < 0 { continue }` jette un watch refusé", SENTINELLE_MUETTE, True),
    ("pose dont le `if wd < 0` COMPTE le watch refusé", SENTINELLE_QUI_COMPTE, False),
    ("pose dont le `if md.is_err() { return 0 }` abandonne la racine", PREDICAT_MUET, True),
    ("pose dont le `if md.is_err()` rend le compte", PREDICAT_QUI_PROPAGE, False),
    ("pose dont le `if read_dir(..).is_ok() { … }` SANS else tait le refus", SUCCES_SANS_ELSE_MUET, True),
    ("pose dont `read_dir(..).map(count).unwrap_or(0)` compte zéro entrée sur un dossier refusé", REPLI_NEUTRE_SUR_ENUMERATION, True),
    ("inventaire dont `metadata(..).unwrap_or_default()` compte zéro octet sur un fichier illisible", REPLI_DEFAUT_SUR_LECTURE, True),
    ("pose dont la fermeture de `unwrap_or_else` COMPTE", REPLI_DONT_LA_FERMETURE_COMPTE, False),
    ("`unwrap_or(0)` sur une variable d'environnement, un champ lu, un nom : HORS population", REPLI_HORS_POPULATION, False),
    ("`roots.len() == 0` compare une longueur, pas une primitive", LONGUEUR_COMPAREE, False),
    ("`action_valid(..).is_err()` est une validation refusée, pas une lecture", VALIDATION_REFUSEE, False),
    ("drapeau ABAISSÉ (`complet = false`) sur un `write_all(..).is_err()`", DRAPEAU_ABAISSE, False),
    ("`if query_row(..).is_ok() { return }` : déjà fait, la suite est le chemin de travail", DEJA_FAIT_QUI_REND_LA_MAIN, False),
    ("surface dont le `if spool.is_ok()` SANS else fait disparaître la grandeur", SURFACE_PREDICAT_MUET, True),
    ("surface dont le `else` dit INCONNU", SURFACE_PREDICAT_QUI_DIT, False),
]
# Témoins à PLUSIEURS fichiers : la résolution des appels qualifiés à travers le crate, et le masquage du
# code de test. Chacun est une liste de (chemin, texte) et un verdict attendu (rougir ?) ; un témoin dont la
# population serait VIDE est un instrument cassé, sauf quand le vide est précisément ce qu'on attend.
TEMOINS_CRATE = [
    ("chargeur qui consomme un listing DÉLÉGUÉ à un autre fichier, et abandonne en silence",
     [("adossement.rs", LISTING_DELEGUE), ("overlays.rs", CHARGEUR_MUET)], True, False),
    ("chargeur qui consomme un listing délégué et COMPTE ce qu'il ignore",
     [("adossement.rs", LISTING_DELEGUE), ("overlays.rs", CHARGEUR_QUI_COMPTE)], False, False),
    ("module de test `pub(crate) mod` : hors population",
     [("db_open.rs", TEST_SOUS_PUB_CRATE)], False, True),
    ("fichier `#![cfg(test)]` : hors population",
     [("garde.rs", FICHIER_DE_TEST)], False, True),
]


def valider_l_instrument(errs):
    for nom, texte, doit_rougir in TEMOINS:
        fautes, couv, surf = analyser("<témoin>", texte)
        if not couv and not surf:
            errs.append("INSTRUMENT : le témoin « %s » n'entre dans AUCUNE population — le critère "
                        "de découverte est cassé, aucun vert de cette garde ne vaut." % nom)
            continue
        if bool(fautes) is not doit_rougir:
            errs.append("INSTRUMENT : le témoin « %s » devrait %s et ne le fait pas (%d faute(s)). "
                        "La règle ne mesure pas ce qu'elle annonce." %
                        (nom, "ROUGIR" if doit_rougir else "PASSER", len(fautes)))
    for nom, fichiers, doit_rougir, population_vide_attendue in TEMOINS_CRATE:
        fautes, couv, surf = analyser_crate(fichiers)
        if (not couv and not surf) != population_vide_attendue:
            errs.append("INSTRUMENT : le témoin « %s » %s — le critère de découverte ne fait pas ce qu'il "
                        "annonce." % (nom, "n'entre dans AUCUNE population" if population_vide_attendue is False
                                      else "entre dans une population alors qu'il est du code de TEST"))
            continue
        if bool(fautes) is not doit_rougir:
            errs.append("INSTRUMENT : le témoin « %s » devrait %s et ne le fait pas (%d faute(s))." %
                        (nom, "ROUGIR" if doit_rougir else "PASSER", len(fautes)))
    # LE TÉMOIN DÉGÉNÉRÉ, EXPLICITEMENT : « ne surveille plus jamais rien » ne doit pas devenir la
    # façon la plus simple de rendre vert. La garde statique ne peut pas l'attraper — elle mesure une
    # forme — donc elle EXIGE que la suite du crate porte le témoin inverse qui, lui, l'attrape.
    return errs


def fichiers_du_crate(crate):
    suivis = subprocess.run(["git", "ls-files", crate + "/*.rs"],
                            capture_output=True, text=True, check=True).stdout.split()
    # Un fichier écrit et pas encore suivi est du code du crate au même titre : on le lit aussi (sinon un
    # module neuf échapperait à la garde jusqu'à son premier commit).
    suivis += subprocess.run(["git", "ls-files", "--others", "--exclude-standard", crate + "/*.rs"],
                             capture_output=True, text=True, check=True).stdout.split()
    return sorted({p for p in suivis if not p.endswith("tests.rs") and "/tests/" not in p})


def main() -> int:
    errs = []
    valider_l_instrument(errs)

    bilan = []
    for crate, (plancher_c, plancher_s, derivations) in CRATES.items():
        suivis = fichiers_du_crate(crate)
        if not suivis:
            errs.append("aucun fichier Rust du crate `%s` n'a été trouvé : cette garde ne vérifierait RIEN." % crate)
            continue
        fichiers = []
        for chemin in suivis:
            with open(chemin, encoding="utf-8") as f:
                fichiers.append((chemin, f.read()))
        fautes, couv, surf = analyser_crate(fichiers, derivations)
        nc, ns = len(couv), len(surf)
        bilan.append((crate, nc, ns))

        for chemin, ligne, nom, pop, forme in fautes:
            if pop == "COUVERTURE":
                errs.append(
                    "%s:%d dans `%s()` — %s : la branche d'ÉCHEC ABANDONNE sans rien COMPTER.\n"
                    "      Cette fonction POSE, ÉNUMÈRE, CHARGE ou ÉVALUE de la surveillance : ce qu'elle "
                    "abandonne ici sort de la couverture — un chemin, un sous-arbre, un fichier de règles, "
                    "ou TOUTES les règles d'un tick — sans erreur, sans avertissement et sans événement, "
                    "pendant que la couverture annoncée reste celle de la configuration.\n"
                    "      Deux issues, jamais le silence : COMPTER l'abandon (`abandonnes += 1`, "
                    "`ch.ignores += 1`, et la fonction rend le compte — `Mesure<u32>`, `Chargement`, "
                    "`Balayage` — que le planificateur publie et que la surface avoue), ou PROPAGER l'échec "
                    "à l'appelant (`?`, `return tick_aveugle(..)`, `RefusDePrune`). Un `eprintln!` seul ne "
                    "suffit pas, et `return Mesure::Lue(0)` sur un échec est un mensonge, pas une trace."
                    % (chemin, ligne, nom, forme))
            else:
                errs.append(
                    "%s:%d dans `%s()` — %s : la branche jumelle IMPRIME, celle-ci se TAIT.\n"
                    "      La grandeur DISPARAÎT de la surface d'état au lieu d'être dite INCONNUE. "
                    "L'opérateur ne lit pas une valeur fausse, il ne lit RIEN — et une ligne absente se "
                    "lit comme une absence de problème.\n"
                    "      Deux issues : imprimer l'inconnu en NOMMANT la cause, ou faire ÉCHOUER la "
                    "commande. Ne rien imprimer n'en est pas une."
                    % (chemin, ligne, nom, forme))

        # --- La POSE doit rendre un COMPTE : sans type porteur, aucun backend ne PEUT rien dire --------
        for chemin, texte in fichiers:
            nu = masque_les_tests(denude(texte))
            if not fonctions_de_pose(nu):
                continue
            for fn in fonctions(nu):
                if fn.nom != POSE:
                    continue
                if "usize" not in fn.retour:
                    errs.append(
                        "%s:%d `%s()` rend `%s` : le contrat `%s` veut un COMPTE des points de "
                        "couverture abandonnés.\n"
                        "      Une pose qui rend `()` ne PEUT rien dire — c'est exactement ainsi qu'un "
                        "sous-arbre entier sortait de la surveillance sans une ligne. Si un autre type "
                        "porte désormais la perte, DITES-LE dans cette garde au lieu de la contourner."
                        % (chemin, fn.ligne(), fn.nom, fn.retour or "()", CONTRAT))

        if nc < plancher_c or ns < plancher_s:
            errs.append(
                "`%s` : population trouvée : %d fonction(s) de couverture (plancher %d) et %d de surface "
                "(plancher %d). Sous le plancher, soit la découverte est cassée — cette garde ne "
                "vérifierait alors RIEN —, soit le crate a légitimement rétréci : dans ce cas baissez "
                "le plancher DEPUIS VOTRE PROPRE MESURE." % (crate, nc, plancher_c, ns, plancher_s))

    if errs:
        for e in errs:
            print("::error::%s" % e)
        print("\n%d défaut(s) : une couverture qu'on n'a pas pu poser, une règle qu'on n'a pas pu charger "
              "ou évaluer, ou une grandeur qu'on n'a pas pu lire, s'éteint sans trace." % len(errs))
        return 1
    for crate, nc, ns in bilan:
        print("`%s` : %d fonction(s) qui POSENT, ÉNUMÈRENT, CHARGENT ou ÉVALUENT de la surveillance et %d "
              "qui écrivent la surface d'état : aucune branche d'échec n'abandonne en silence."
              % (crate, nc, ns))
    print("Témoins de l'instrument : %d + %d (positifs ET négatifs, dont la pose dégénérée, le scrutin "
          "sous bloc `unsafe`, l'évaluateur qui ment, le listing délégué, le code de test masqué, et l'échec "
          "testé par comparaison, par prédicat ou par repli neutre)."
          % (len(TEMOINS), len(TEMOINS_CRATE)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
