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

CE QUE CETTE GARDE NE PROUVE PAS
-------------------------------
1. Elle prouve une FORME, pas un trajet. Qu'un compte existe ne dit pas qu'il atteint le SOC ; c'est
   la suite du crate qui l'exerce (`pose_de_couverture_partielle_est_avouee_et_marque_les_events`,
   son témoin INVERSE `pose_de_couverture_complete_ne_dit_rien_de_particulier`, et
   `la_pose_noyau_compte_ce_qu_elle_abandonne` qui touche le vrai noyau).
2. Elle ne reconnaît une branche d'échec que lorsqu'elle est ÉCRITE comme telle. Un échec de syscall
   testé par COMPARAISON (`if fd < 0 { break }`, `if handle.is_err() { return }`) lui échappe. Les
   sites de ce genre ont été comptés dans le code — le drainage inotify/fanotify distingue désormais
   EAGAIN d'un descripteur mort — mais une régression qui les réécrirait passerait cette garde.
3. Sa portée est le crate `agent` (cf. les 30 sites mesurés ailleurs, non exigés ici).
"""
import re
import subprocess
import sys

CRATE = "agent/src"
CONTRAT = "FimBackend"      # le contrat qui déclare la POSE de couverture
POSE = "watch_root"         # la méthode dont la doc dit « Pose un watch … sur `root` »

# PLANCHERS, pas des comptes exacts : ajouter un backend ou une sous-commande est de la routine. Ils
# ferment le seul mode de panne réel de la découverte — un motif cassé qui ne trouve RIEN et rend un
# vert joyeux. MESURÉS le 2026-08-21 : 8 fonctions de couverture, 5 de surface.
PLANCHER_COUVERTURE = 6
PLANCHER_SURFACE = 3

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
TRACE_COMPTE = re.compile(r"\+=|=\s*true\b|bail!|panic!|unreachable!|todo!|\?")
RETOUR_PORTEUR = re.compile(r"\breturn\s+([A-Za-z0-9_&*(\[][^;]*)")
# `return 0` (aucune perte) et `return Ok(())` (tout va bien) sur une branche d'ÉCHEC NIENT la perte
# au lieu de la porter : ce sont des retours NEUTRES, et ils ne valent pas trace. C'est la forme
# dégénérée la plus tentante d'un correctif — rendre le bon type, et mentir dedans.
RETOUR_NEUTRE = re.compile(r"^(?:0|Ok\(\(\)\))\s*$")
TRACE_DIT = re.compile(r"\bprintln!|bail!|panic!|\?|\breturn\s+Err\b")
FS_OU_NOYAU = re.compile(r"\bstd::fs::|\blibc::|\bfs::\w")
PRINTLN = re.compile(r"\bprintln!")
ABANDON = re.compile(r"\breturn\b|\bcontinue\b|\bbreak\b")


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
    return bool(m) and not RETOUR_NEUTRE.match(m.group(1).strip())


def abandonne(branche, sans_else):
    """La branche d'échec RENONCE-t-elle à l'objet en cours ? (vide, ou transfert de contrôle nu)"""
    if sans_else:
        return True
    corps = branche.strip().strip("{}").strip()
    return corps == "" or ABANDON.search(corps) is not None


def masque_les_tests(nu):
    out = list(nu)
    for m in re.finditer(r"#\[cfg\(test\)\]\s*(?:pub\s+)?mod\s+\w+\s*\{", nu):
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


def analyser(chemin, texte):
    nu = masque_les_tests(denude(texte))
    fns = fonctions(nu)
    noms = {f.nom for f in fns}
    couverture = {f.nom for f in fns if f.nom in fonctions_de_pose(nu) or "read_dir(" in f.corps}
    change = True
    while change:
        change = False
        for f in fns:
            if f.nom not in couverture:
                continue
            for a in appels(f.corps) & noms:
                if a not in couverture and any(FS_OU_NOYAU.search(x.corps) for x in fns if x.nom == a):
                    couverture.add(a)
                    change = True
    surface = {f.nom for f in fns if PRINTLN.search(f.corps)}

    fautes = []
    for f in fns:
        est_c, est_s = f.nom in couverture, f.nom in surface
        if not (est_c or est_s):
            continue
        sites = []
        for bras in bras_de_match(f.corps):
            a_succes = any(motif_de_succes(m) for m, _, _ in bras)
            jumelle = any(PRINTLN.search(c) for _, c, _ in bras)
            for motif, corps_bras, off in bras:
                if a_succes and motif_d_echec(motif) and abandonne(corps_bras, False):
                    sites.append(("bras `%s =>` d'un match" % motif.strip()[:26], corps_bras, off, jumelle))
        for off, motif, alors, a_else, els in si_let(f.corps):
            if motif_de_succes(motif) and abandonne(els, not a_else):
                forme = "`if let %s` %s" % (motif.strip()[:24],
                                            "SANS else" if not a_else else "/ else")
                sites.append((forme, els if a_else else "", off, bool(PRINTLN.search(alors))))
        for off, motif, els in let_sinon(f.corps):
            if motif_de_succes(motif) and abandonne(els, False):
                sites.append(("`let %s … else`" % motif.strip()[:24], els, off, False))
        for m in re.finditer(r"\.flatten\(\)", f.corps):
            if est_c:
                sites.append(("`.flatten()`", "", m.start(), False))
        for forme, branche, off, jumelle in sites:
            if est_c and not compte_la_perte(branche):
                fautes.append((chemin, f.ligne(off + 1), f.nom, "COUVERTURE", forme))
            elif est_s and jumelle and not TRACE_DIT.search(branche):
                fautes.append((chemin, f.ligne(off + 1), f.nom, "SURFACE", forme))
    return fautes, couverture, surface


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

TEMOINS = [
    ("pose qui abandonne un sous-arbre en silence", POSE_MUETTE, True),
    ("pose qui COMPTE ce qu'elle abandonne", POSE_QUI_COMPTE, False),
    ("pose DÉGÉNÉRÉE qui ne surveille plus rien", POSE_DEGENEREE, False),
    ("pose muette dont le scrutin est un bloc `unsafe`", POSE_MUETTE_SOUS_UNSAFE, True),
    ("surface où une grandeur DISPARAÎT", SURFACE_MUETTE, True),
    ("surface qui dit INCONNU", SURFACE_QUI_DIT, False),
    ("surface qui fait ÉCHOUER la commande", SURFACE_QUI_ECHOUE, False),
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
    # LE TÉMOIN DÉGÉNÉRÉ, EXPLICITEMENT : « ne surveille plus jamais rien » ne doit pas devenir la
    # façon la plus simple de rendre vert. La garde statique ne peut pas l'attraper — elle mesure une
    # forme — donc elle EXIGE que la suite du crate porte le témoin inverse qui, lui, l'attrape.
    return errs


def main() -> int:
    errs = []
    valider_l_instrument(errs)

    suivis = subprocess.run(["git", "ls-files", CRATE + "/*.rs"],
                            capture_output=True, text=True, check=True).stdout.split()
    suivis = [p for p in suivis if not p.endswith("tests.rs") and "/tests/" not in p]
    if not suivis:
        print("::error::aucun fichier Rust du crate `%s` n'a été trouvé : cette garde ne "
              "vérifierait RIEN." % CRATE)
        return 1

    fautes, nc, ns = [], 0, 0
    for chemin in suivis:
        with open(chemin, encoding="utf-8") as f:
            texte = f.read()
        f_, couv, surf = analyser(chemin, texte)
        fautes += f_
        nc += len(couv)
        ns += len(surf)

    for chemin, ligne, nom, pop, forme in fautes:
        if pop == "COUVERTURE":
            errs.append(
                "%s:%d dans `%s()` — %s : la branche d'ÉCHEC ABANDONNE sans rien COMPTER.\n"
                "      Cette fonction POSE ou ÉNUMÈRE de la surveillance : ce qu'elle abandonne ici "
                "sort de la couverture — un chemin, souvent un SOUS-ARBRE ENTIER — sans erreur, sans "
                "avertissement et sans événement, pendant que la couverture annoncée reste celle de "
                "la configuration.\n"
                "      Deux issues, jamais le silence : COMPTER l'abandon (`self.perdus += 1`, et "
                "`watch_root` rend le compte, que le lecteur avoue), ou PROPAGER l'échec à l'appelant. "
                "Un `eprintln!` seul ne suffit pas : le contrat veut que le trou remonte au lecteur "
                "pour marquer `fim_coverage`, jamais un warning d'hôte."
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
    for chemin in suivis:
        with open(chemin, encoding="utf-8") as f:
            nu = masque_les_tests(denude(f.read()))
        pose = fonctions_de_pose(nu)
        if not pose:
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

    if nc < PLANCHER_COUVERTURE or ns < PLANCHER_SURFACE:
        errs.append(
            "population trouvée : %d fonction(s) de couverture (plancher %d) et %d de surface "
            "(plancher %d). Sous le plancher, soit la découverte est cassée — cette garde ne "
            "vérifierait alors RIEN —, soit le crate a légitimement rétréci : dans ce cas baissez "
            "le plancher DEPUIS VOTRE PROPRE MESURE." % (nc, PLANCHER_COUVERTURE, ns, PLANCHER_SURFACE))

    if errs:
        for e in errs:
            print("::error::%s" % e)
        print("\n%d défaut(s) : une couverture qu'on n'a pas pu poser, ou une grandeur qu'on n'a pas "
              "pu lire, s'éteint sans trace." % len(errs))
        return 1
    print("%d fonction(s) qui POSENT ou ÉNUMÈRENT de la surveillance et %d qui écrivent la surface "
          "d'état, dans `%s` : aucune branche d'échec n'abandonne en silence, et toute pose rend le "
          "compte de ce qu'elle a abandonné." % (nc, ns, CRATE))
    print("Témoins de l'instrument : %d (positifs ET négatifs, dont la pose dégénérée et le scrutin "
          "sous bloc `unsafe`)." % len(TEMOINS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
