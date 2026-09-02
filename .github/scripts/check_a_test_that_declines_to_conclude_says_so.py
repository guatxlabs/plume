#!/usr/bin/env python3
"""Un test qui REND LA MAIN SANS CONCLURE le DIT par le canal, et n'est jamais muet (`P11.23-b`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
=============================================
Un test qui ne peut pas voir — plate-forme sans `/proc`, levier de configuration éteint, clé
SQLCipher posée dans l'environnement — a le droit de ne rien prouver. Il n'a PAS le droit de se
présenter comme un test qui a prouvé. Or c'est exactement ce qu'il fait : il sort en 0, et le
portail de déploiement comme les jobs Rust de `ci.yml` ne lisent que ce 0.

MESURÉ SUR CET ARBRE LE 2026-08-31, avant correction — la population est DÉRIVÉE, pas listée :
QUATORZE chemins de `daemon/src/tests/` rendaient la main sans exercer l'assertion qui justifie
leur test. NEUF n'imprimaient rien du tout. Et les CINQ qui imprimaient ne valaient pas mieux :
`libtest` détourne les sorties du fil de chaque test et ne les rend que pour les tests qui
ÉCHOUENT (mesuré sur une caisse d'essai : 0 occurrence sous `cargo test` nu, 3 sous `--nocapture`,
3 sous `--show-output`). Un aveu imprimé depuis un test VERT part dans le vide.

CE QU'ELLE EXIGE, ET POURQUOI PAS PLUS
=======================================
Elle n'exige PAS qu'un test échoue sur un environnement aveugle : ce serait une RANÇON — un rouge
qu'aucun geste ne pourrait refermer sur un conteneur durci ou une machine non-Linux. Elle exige
que le refus EMPRUNTE LE CANAL, c'est-à-dire qu'il atteigne celui qui décide pendant que la suite
reste verte.

ELLE NE CHERCHE PAS UN MOT D'AVEU DANS UN CORPS, et c'est le cœur de sa conception. Un piège
mesuré le 2026-08-31 sur une autre garde : un mot trop générique compté comme un aveu la rendait
VERTE sur le site le plus grave. Ici le critère est POSITIONNEL, pas lexical — l'appel au canal
doit se trouver DANS LE BLOC du `return`, au même niveau d'accolades. Un aveu écrit ailleurs dans
le même test ne blanchit donc rien. Ce n'est pas une subtilité : `vieillissement_serie.rs` porte
DEUX sorties de refus dans LE MÊME test, et un critère d'appartenance au corps aurait laissé la
seconde muette pour toujours.

TROIS CANAUX
============
  0  tenu.
  1  violé — le site est NOMMÉ (fichier, ligne, test, et ce qui manque).
  2  l'instrument ne peut pas voir — il REFUSE DE CONCLURE, il n'accuse pas.

LA SECONDE FAMILLE, MESURÉE LE 2026-09-02 (`P11.23-e`)
=======================================================
Un refus peut s'écrire SANS sortie anticipée : les assertions vivent dans une branche que
l'environnement peut ne pas prendre, et la jumelle ne porte aucun verdict. Rien ne sort, donc
l'analyse ci-dessus ne voyait rien.

LA POPULATION A ÉTÉ DÉRIVÉE, PAS ESTIMÉE. Sur 1 847 fonctions de test de la caisse, 82 ne portent
AUCUNE assertion sur un chemin d'exécution garanti ; 64 d'entre elles bouclent sur un corpus
LITTÉRAL non vide (leur chemin muet n'existe pas) ou délèguent leur verdict à un auxiliaire ; des
18 restantes, celles dont le chemin muet s'ouvre sans toucher une ligne de Rust sont SEPT — cinq
branches conditionnées par une lecture d'environnement ou par un levier du produit, et deux dont
la jumelle n'est pas vide mais ne fait que du ménage. Toutes empruntent désormais le canal.

CE QUE CETTE GARDE AJOUTE, ET SON CRITÈRE RESTE POSITIONNEL : un `if` dont la CONDITION lit
l'environnement, dont la branche prise porte une assertion et ne sort pas, et dont la JUMELLE ne
porte aucun verdict, doit appeler le canal DANS le bloc de cette jumelle, à sa profondeur. Une
jumelle absente est refusée avec le geste écrit (`else { … }`).

CE QU'ELLE NE TIENT PAS — DIT PLUTÔT QUE SOUS-ENTENDU
======================================================
  · UNE CONDITION QUI CACHE SA LECTURE. Le critère de population reconnaît les lectures
    d'environnement ÉCRITES DANS LA CONDITION. MESURÉ : deux sites réels de
    `branche_d_echec_muette.rs` passent par un auxiliaire (`priver_de_lecture(&rules)`) et
    échappent donc à cette garde — ils empruntent le canal parce qu'un humain les y a mis, pas
    parce qu'elle les y oblige.
  · LES AUTRES CONSTRUITS. `match` sur l'environnement et boucles sur une collection dérivée de
    l'environnement ne sont pas analysés. MESURÉ le 2026-09-02 : zéro `match` de cette forme, et
    les trois boucles trouvées portent déjà leur propre plancher de non-vacuité.
  · UNE CHAÎNE `else if`. Le site est laissé hors population : sa jumelle n'est pas un bloc.
  · UN CORPUS QUI PERD SA MATIÈRE. Un test qui boucle sur un corpus lu d'un fichier de données ne
    sort pas et ne branche pas : il itère zéro fois. Ce qui tient cette forme est un PLANCHER dans
    l'instrument qui produit le corpus, pas cette garde.
  · UNE SEULE CAISSE. La population est celle de la caisse qui PORTE le canal (dérivée : on remonte
    de `canal_de_refus.rs` jusqu'au `Cargo.toml`). Les caisses jumelles ne peuvent pas appeler le
    canal d'une autre — l'exiger serait une rançon. MESURÉ le 2026-08-31 : `agent`,
    `collector-syslog` et `collector-mail` portent ZÉRO chemin de retour anticipé dans leurs tests,
    donc cette borne est aujourd'hui VIDE. Le jour où l'une en écrit un, il faudra y porter le
    canal, et cette garde ne le dira pas.
  · LE TEXTE, PAS L'EXÉCUTION. Elle établit que chaque chemin de refus APPELLE le canal ; que le
    canal ait vraiment écrit, seule l'exécution le montre — c'est le rôle du mode `--lire`.
  · LE PROTOCOLE DE RÉ-EXÉCUTION. Un test qui relance SON PROPRE binaire (`current_exe()`) avec un
    environnement modifié (`.env(`) définit un protocole à deux bras ; le bras de l'enfant sort tôt
    et c'est sa fonction, pas un aveuglement. Ces tests sont hors population, et le critère est une
    PROPRIÉTÉ de la source, pas une liste de noms. MESURÉ : un seul test y entre aujourd'hui
    (`migrate.rs::reference_build_writes_nothing_to_stderr`). Un test qui écrirait `current_exe()`
    et `.env(` sans s'en servir échapperait à la garde — la borne est dite.
"""

import os
import re
import sys

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.realpath(os.path.join(ICI, "..", ".."))
CANAL = os.path.join(RACINE, "daemon", "src", "tests", "canal_de_refus.rs")

CODE_TENU = 0
CODE_VIOLE = 1
CODE_INSTRUMENT = 2

# L'APPEL EST RECONNU PAR SON CHEMIN QUALIFIÉ, jamais par le seul nom de la fonction : la caisse
# porte déjà un `qb_refuser_de_conclure` (le banc de `query_verify.rs`, qui PANIQUE au lieu de
# rendre la main) et un motif court les confondrait.
APPEL = "canal_de_refus::refuser_de_conclure"
VARIABLE_DECL = re.compile(r'const\s+VARIABLE_DU_CANAL\s*:\s*&str\s*=\s*"([^"]+)"\s*;')
ATTR_TEST = re.compile(r"#\[\s*(?:tokio::)?test\s*[\](]")

# CE QUI FAIT D'UNE CONDITION UNE LECTURE D'ENVIRONNEMENT. Sur-approximation ASSUMÉE : elle
# reconnaît l'appel ÉCRIT DANS LA CONDITION, jamais un mot d'aveu dans un corps. Ses faux négatifs
# sont NOMMÉS dans le bandeau — une condition qui délègue à un auxiliaire lui échappe.
LECTURES_D_ENVIRONNEMENT = (
    "env::var", "env::var_os", "cfg!(", ".exists()", "fs::read", "fs::metadata",
    "fs::read_dir", "fs::read_to_string", "fs::symlink_metadata", "libc::",
    "Command::new", "available_parallelism", "target_os",
)
ASSERTION = re.compile(r"\b(assert|assert_eq|assert_ne|debug_assert|panic|unreachable)\s*!")


# =================================================================================================
# L'ANALYSEUR — c'est LUI que les témoins fabriqués exercent, pas une copie.
# =================================================================================================
def sans_chaines_ni_commentaires(s):
    """Copie de `s` où chaînes, caractères et commentaires sont remplacés par des espaces.

    Les longueurs et les retours à la ligne sont PRÉSERVÉS : les positions calculées sur la copie
    valent sur l'original, donc un numéro de ligne reste juste. Sans ce blanchiment, une accolade
    dans une chaîne (« {annonce:?} ») décalerait tout l'appariement de blocs."""
    out = list(s)
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == "/" and i + 1 < n and s[i + 1] == "/":
            j = s.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif c == "/" and i + 1 < n and s[i + 1] == "*":
            prof, j = 0, i
            while j < n:
                if s[j] == "/" and j + 1 < n and s[j + 1] == "*":
                    prof += 1
                    j += 2
                elif s[j] == "*" and j + 1 < n and s[j + 1] == "/":
                    prof -= 1
                    j += 2
                    if prof == 0:
                        break
                else:
                    j += 1
            for k in range(i, min(j, n)):
                if s[k] != "\n":
                    out[k] = " "
            i = j
        elif c == "r" and i + 1 < n and s[i + 1] in '#"':
            j, d = i + 1, 0
            while j < n and s[j] == "#":
                d += 1
                j += 1
            if j < n and s[j] == '"':
                fin = s.find('"' + "#" * d, j + 1)
                fin = n if fin < 0 else fin + 1 + d
                for k in range(i, fin):
                    if s[k] != "\n":
                        out[k] = " "
                i = fin
            else:
                i += 1
        elif c == '"':
            j = i + 1
            while j < n:
                if s[j] == "\\":
                    j += 2
                    continue
                if s[j] == '"':
                    j += 1
                    break
                j += 1
            for k in range(i, min(j, n)):
                if s[k] != "\n":
                    out[k] = " "
            i = j
        elif c == "'":
            m = re.match(r"'(\\.|[^\\'])'", s[i:])
            if m:
                for k in range(i, i + m.end()):
                    out[k] = " "
                i += m.end()
            else:
                i += 1
        else:
            i += 1
    return "".join(out)


def fin_de_bloc(net, ouvrante):
    prof = 0
    for j in range(ouvrante, len(net)):
        if net[j] == "{":
            prof += 1
        elif net[j] == "}":
            prof -= 1
            if prof == 0:
                return j
    return None


def zones_a_ignorer(net, deb, fin):
    """Les intervalles du corps qui ne sont PAS le flot du test : closures, `fn` imbriquées,
    blocs `async`. Un `return` y sort de la closure, pas du test."""
    zones = []
    for m in re.finditer(r"(\|\s*[^|{}\n]*\||\|\|)\s*(->\s*[^{;]+)?\{", net[deb:fin]):
        a = deb + m.end() - 1
        b = fin_de_bloc(net, a)
        if b:
            zones.append((deb + m.start(), b))
    for m in re.finditer(r"\bfn\s+\w+", net[deb + 1:fin]):
        a0 = deb + 1 + m.start()
        acc = net.find("{", a0)
        if acc == -1 or acc > fin:
            continue
        b = fin_de_bloc(net, acc)
        if b:
            zones.append((a0, b))
    for m in re.finditer(r"\basync\s*(move\s*)?\{", net[deb:fin]):
        a = deb + m.end() - 1
        b = fin_de_bloc(net, a)
        if b:
            zones.append((deb + m.start(), b))
    return zones


def est_terminal(net, pos, fin):
    """Ce `return` est-il la DERNIÈRE instruction du corps du test ?

    Un `return` terminal ne saute rien : le test est déjà allé au bout. L'accuser serait une
    sur-accusation — pas une rançon (le geste est de retirer un mot), mais une garde qui accuse à
    tort finit par être désarmée. Le point-virgule qui clôt l'instruction est cherché à PROFONDEUR
    0, pour que `return Ok(());` soit reconnu comme une seule instruction."""
    prof = 0
    j = pos
    while j < fin:
        c = net[j]
        if c in "([{":
            prof += 1
        elif c in ")]}":
            prof -= 1
        elif c == ";" and prof == 0:
            return net[j + 1:fin].strip() == ""
        j += 1
    return False


def ouvrante_du_bloc(net, deb, pos):
    """L'accolade qui ouvre le bloc le plus INTÉRIEUR contenant `pos`, en remontant depuis `deb`."""
    pile = []
    for j in range(deb, pos):
        if net[j] == "{":
            pile.append(j)
        elif net[j] == "}":
            if pile:
                pile.pop()
    return pile[-1] if pile else deb


def arguments(brut, apres_parenthese):
    """Les arguments d'un appel, découpés aux virgules de PROFONDEUR 0. `apres_parenthese` pointe
    juste après la `(` ouvrante. Rend None si les parenthèses ne ferment pas."""
    prof, args, courant = 0, [], []
    i = apres_parenthese
    while i < len(brut):
        c = brut[i]
        if c in "([{":
            prof += 1
        elif c in ")]}":
            if prof == 0:
                args.append("".join(courant).strip())
                return [a for a in args if a != ""]
            prof -= 1
        elif c == "," and prof == 0:
            args.append("".join(courant).strip())
            courant = []
            i += 1
            continue
        courant.append(c)
        i += 1
    return None


def faute_des_arguments(brut, trouve, nom):
    """L'appel trouvé à l'offset `trouve` porte-t-il ses trois arguments, et nomme-t-il SON test ?
    Rend la faute, ou None. Une seule rédaction pour les deux familles."""
    par = brut.find("(", trouve + len(APPEL))
    args = arguments(brut, par + 1) if par != -1 else None
    if args is None or len(args) < 3:
        return ("l'appel au canal n'a pas ses trois arguments "
                "(`module_path!()`, le nom du test, la cause).")
    if args[0] != "module_path!()":
        return (f"le 1er argument du canal est `{args[0]}` et non `module_path!()` : "
                "un chemin de module écrit à la main dérive au premier déplacement.")
    if args[1] != f'"{nom}"':
        return (f"le canal est appelé avec {args[1]} alors que le test s'appelle "
                f"`{nom}` : l'aveu enverrait chercher au mauvais endroit.")
    return None


def appel_dans_le_bloc(net, ouvrante, borne):
    """L'offset du dernier `APPEL` écrit DANS le bloc ouvert en `ouvrante`, à SA profondeur, avant
    `borne`. C'est LE critère positionnel : un appel niché dans un sous-bloc ne compte pas."""
    trouve, prof, j = None, 0, ouvrante + 1
    while j < borne:
        if net[j] == "{":
            prof += 1
        elif net[j] == "}":
            prof -= 1
        elif prof == 0 and net.startswith(APPEL, j):
            trouve = j
        j += 1
    return trouve


def branches_muettes(net, brut, acc, fin, zones, nom, chemin):
    """LA SECONDE FAMILLE (`P11.23-e`) : une branche conditionnée par une lecture d'environnement,
    qui porte l'assertion et ne sort pas, dont la JUMELLE ne porte aucun verdict."""
    sites = []
    for m in re.finditer(r"\bif\b", net[acc:fin]):
        pos = acc + m.start()
        if any(a <= pos <= b for a, b in zones):
            continue
        # LA CONDITION : de `if` à l'accolade ouvrante, à profondeur nulle de parenthèses.
        j, prof = pos + 2, 0
        while j < fin:
            c = net[j]
            if c in "([":
                prof += 1
            elif c in ")]":
                prof -= 1
            elif c == "{" and prof == 0:
                break
            j += 1
        if j >= fin:
            continue
        cond = net[pos + 2:j]
        if not any(lecture in cond for lecture in LECTURES_D_ENVIRONNEMENT):
            continue
        f_then = fin_de_bloc(net, j)
        if f_then is None:
            continue
        corps_then = net[j:f_then + 1]
        # La branche doit PORTER un verdict, et ne pas SORTIR (cette forme-là est déjà tenue).
        if not ASSERTION.search(corps_then):
            continue
        if re.search(r"\breturn\b", corps_then):
            continue
        ligne = brut[:pos].count("\n") + 1
        site = {"fichier": chemin, "ligne": ligne, "test": nom,
                "hors_population": False, "famille": "branche", "faute": None}
        m_else = re.match(r"\s*else\b", net[f_then + 1:])
        if not m_else:
            site["faute"] = ("cette branche est conditionnée par une lecture d'ENVIRONNEMENT, elle "
                             "porte l'assertion du test, et elle n'a PAS de jumelle : quand la "
                             "condition est fausse, le test rend la main sans rien avoir prouvé et "
                             "sans le dire. Écrire la jumelle : `else { "
                             "crate::tests::canal_de_refus::refuser_de_conclure(module_path!(), "
                             f'"{nom}", "<pourquoi rien n\'a pu être mesuré ici>") }}`.')
            sites.append(site)
            continue
        apres = f_then + 1 + m_else.end()
        if re.match(r"\s*if\b", net[apres:]):
            continue  # chaîne `else if` : hors population, borne dite dans le bandeau
        k = net.find("{", apres)
        if k == -1 or k > fin:
            continue
        f_else = fin_de_bloc(net, k)
        if f_else is None:
            continue
        if ASSERTION.search(net[k:f_else + 1]):
            continue  # la jumelle porte SON propre verdict : rien n'est muet
        trouve = appel_dans_le_bloc(net, k, f_else)
        if trouve is None:
            site["faute"] = ("la jumelle de cette branche d'environnement ne porte AUCUN verdict et "
                             "n'appelle PAS le canal : la propriété que ce test nomme n'est pas "
                             "exercée, et rien ne le dit. Écrire, dans CE bloc `else` : "
                             "`crate::tests::canal_de_refus::refuser_de_conclure(module_path!(), "
                             f'"{nom}", "<pourquoi rien n\'a pu être mesuré ici>")`.')
        else:
            site["faute"] = faute_des_arguments(brut, trouve, nom)
        sites.append(site)
    return sites


def analyser(brut, chemin="<fabriqué>"):
    """Rend (sites, tests_vus). Un site = un dict décrivant UN `return` de test et son verdict.

    C'est la SEULE fonction de jugement : les témoins fabriqués et l'arbre réel passent par elle."""
    net = sans_chaines_ni_commentaires(brut)
    sites, tests_vus = [], 0
    for m in ATTR_TEST.finditer(net):
        mf = re.search(r"\bfn\s+(\w+)\s*(?:<[^>]*>)?\s*\(", net[m.end():])
        if not mf:
            continue
        nom = mf.group(1)
        acc = net.find("{", m.end() + mf.end())
        if acc == -1:
            continue
        fin = fin_de_bloc(net, acc)
        if fin is None:
            continue
        tests_vus += 1
        corps_net = net[acc:fin]
        # HORS POPULATION — protocole de ré-exécution : le test relance SON PROPRE binaire avec un
        # environnement modifié ; le bras de l'enfant sort tôt par construction.
        protocole = "current_exe()" in corps_net and ".env(" in corps_net
        zones = zones_a_ignorer(net, acc, fin)
        for r in re.finditer(r"\breturn\b", corps_net):
            pos = acc + r.start()
            if any(a <= pos <= b for a, b in zones):
                continue
            if est_terminal(net, pos, fin):
                continue
            ligne = brut[:pos].count("\n") + 1
            site = {"fichier": chemin, "ligne": ligne, "test": nom,
                    "hors_population": protocole, "famille": "sortie", "faute": None}
            if protocole:
                sites.append(site)
                continue
            # ── LE CRITÈRE EST POSITIONNEL : l'appel doit être dans LE BLOC du `return`, au même
            #    niveau d'accolades. Un aveu ailleurs dans le test ne blanchit pas ce chemin-ci.
            ouv = ouvrante_du_bloc(net, acc, pos)
            trouve = appel_dans_le_bloc(net, ouv, pos)
            if trouve is None:
                site["faute"] = ("ce `return` sort du test SANS passer par le canal. Écrire, dans "
                                 "CE bloc et juste avant lui : "
                                 "`crate::tests::canal_de_refus::refuser_de_conclure(module_path!(), "
                                 f'"{nom}", "<pourquoi rien n\'a pu être mesuré ici>")`.')
                sites.append(site)
                continue
            site["faute"] = faute_des_arguments(brut, trouve, nom)
            sites.append(site)
        # LA SECONDE FAMILLE — jugée sur les MÊMES zones à ignorer, et hors du protocole de
        # ré-exécution (dont le bras de l'enfant n'est pas un aveuglement).
        if not protocole:
            sites.extend(branches_muettes(net, brut, acc, fin, zones, nom, chemin))
    return sites, tests_vus


# =================================================================================================
# LES TÉMOINS — FABRIQUÉS ICI, jamais lus du dépôt. Ils s'exercent sur `analyser` elle-même.
# =================================================================================================
def temoins():
    """Rend None si l'instrument est sain, sinon la faute constatée."""
    A = 'crate::tests::canal_de_refus::refuser_de_conclure'
    cas = []

    cas.append(("POSITIF — retour NU, aucun aveu", """
        #[test]
        fn t_muet() {
            if !cfg!(target_os = "linux") { return; }
            assert!(true);
        }
    """, [("t_muet", True)]))

    cas.append(("NÉGATIF — retour précédé de l'appel, dans le bon bloc", """
        #[test]
        fn t_avoue() {
            if !cfg!(target_os = "linux") {
                %s(module_path!(), "t_avoue", "rien à mesurer ici");
                return;
            }
            assert!(true);
        }
    """ % A, [("t_avoue", False)]))

    # LE TÉMOIN QUI INTERDIT LA FAUSSE CORRECTION : un aveu AILLEURS dans le même test ne blanchit
    # pas un second chemin muet. Une garde qui chercherait le mot dans le CORPS passerait ce cas.
    cas.append(("POSITIF — un aveu dans le test, un SECOND chemin muet", """
        #[test]
        fn t_deux_sorties() {
            if a {
                %s(module_path!(), "t_deux_sorties", "porte A");
                return;
            }
            if b { return; }
            assert!(true);
        }
    """ % A, [("t_deux_sorties", False), ("t_deux_sorties", True)]))

    # ET SON JUMEAU : l'appel niché DANS un sous-bloc n'est pas sur le chemin du `return`.
    cas.append(("POSITIF — appel niché dans un sous-bloc, hors du chemin", """
        #[test]
        fn t_niche() {
            if a {
                if b { %s(module_path!(), "t_niche", "…"); }
                return;
            }
        }
    """ % A, [("t_niche", True)]))

    cas.append(("NÉGATIF — `return` dans une closure : ce n'est pas une sortie de test", """
        #[test]
        fn t_closure() {
            let f = |x: u8| { if x == 0 { return 1; } x };
            assert_eq!(f(0), 1);
        }
    """, []))

    cas.append(("NÉGATIF — protocole de ré-exécution : hors population", """
        #[test]
        fn t_reexec() {
            if std::env::var("MARQUEUR").is_ok() { assert!(true); return; }
            let exe = std::env::current_exe().unwrap();
            std::process::Command::new(exe).env("MARQUEUR", "1").output().unwrap();
        }
    """, [("t_reexec", False)]))

    cas.append(("POSITIF — le canal nomme un AUTRE test que celui qui l'appelle", """
        #[test]
        fn t_mal_nomme() {
            if a {
                %s(module_path!(), "t_le_voisin", "…");
                return;
            }
        }
    """ % A, [("t_mal_nomme", True)]))

    cas.append(("POSITIF — chemin de module écrit à la main au lieu de `module_path!()`", """
        #[test]
        fn t_module_en_dur() {
            if a {
                %s("plume_daemon::tests", "t_module_en_dur", "…");
                return;
            }
        }
    """ % A, [("t_module_en_dur", True)]))

    cas.append(("NÉGATIF — `return` TERMINAL : il ne saute rien", """
        #[test]
        fn t_return_terminal() {
            assert!(true);
            return;
        }
    """, []))

    cas.append(("NÉGATIF — `return Ok(());` terminal, point-virgule à profondeur 0", """
        #[test]
        fn t_return_ok_terminal() -> Result<(), ()> {
            assert!(true);
            return Ok(());
        }
    """, []))

    # PIÈGE D'ACCOLADE : une accolade DANS une chaîne ne doit pas décaler l'appariement de blocs.
    cas.append(("POSITIF — accolade dans une chaîne, l'appariement tient", """
        #[test]
        fn t_accolade_en_chaine() {
            let s = "{ ceci n'ouvre rien }";
            if a { return; }
            assert!(s.len() > 0);
        }
    """, [("t_accolade_en_chaine", True)]))

    # ── LA SECONDE FAMILLE (`P11.23-e`) : une branche d'environnement dont la jumelle est muette.
    cas.append(("POSITIF — branche d'environnement, AUCUNE jumelle", """
        #[test]
        fn t_branche_nue() {
            if std::env::var("PLUME_X").is_ok() {
                assert!(quelque_chose);
            }
            assert!(autre_chose);
        }
    """, [("t_branche_nue", True)]))

    cas.append(("NÉGATIF — branche d'environnement, jumelle qui AVOUE", """
        #[test]
        fn t_branche_avouee() {
            if std::env::var("PLUME_X").is_ok() {
                assert!(quelque_chose);
            } else {
                %s(module_path!(), "t_branche_avouee", "levier posé : rien mesuré");
            }
        }
    """ % A, [("t_branche_avouee", False)]))

    # LE TÉMOIN QUI INTERDIT LA FAUSSE CORRECTION, DEUXIÈME FAMILLE : un aveu dans LA PREMIÈRE
    # jumelle ne blanchit pas la SECONDE. C'est la transposition exacte de `t_deux_sorties`, et un
    # critère d'appartenance au corps laisserait la seconde muette pour toujours.
    cas.append(("POSITIF — deux branches d'environnement, la seconde jumelle MUETTE", """
        #[test]
        fn t_deux_branches() {
            if std::env::var("A").is_ok() {
                assert!(un);
            } else {
                %s(module_path!(), "t_deux_branches", "porte A");
            }
            if std::env::var("B").is_ok() {
                assert!(deux);
            } else {
                let _ = 1;
            }
        }
    """ % A, [("t_deux_branches", False), ("t_deux_branches", True)]))

    cas.append(("POSITIF — l'aveu de la jumelle est NICHÉ dans un sous-bloc", """
        #[test]
        fn t_jumelle_nichee() {
            if cfg!(target_os = "linux") {
                assert!(un);
            } else {
                if bavard { %s(module_path!(), "t_jumelle_nichee", "…"); }
            }
        }
    """ % A, [("t_jumelle_nichee", True)]))

    cas.append(("NÉGATIF — la jumelle porte SON PROPRE verdict", """
        #[test]
        fn t_jumelle_qui_juge() {
            if std::env::var("A").is_ok() {
                assert!(un);
            } else {
                assert!(deux);
            }
        }
    """, []))

    cas.append(("NÉGATIF — condition qui ne lit PAS l'environnement : hors population", """
        #[test]
        fn t_condition_ordinaire() {
            if compte > 3 {
                assert!(un);
            }
            assert!(deux);
        }
    """, []))

    cas.append(("NÉGATIF — branche d'environnement DANS une closure", """
        #[test]
        fn t_branche_en_closure() {
            let f = || { if std::env::var("A").is_ok() { assert!(un); } };
            f();
            assert!(deux);
        }
    """, []))

    # ET LA FRONTIÈRE ENTRE LES DEUX FAMILLES : une branche qui SORT est jugée UNE fois, par la
    # règle du `return` — pas deux, ce qui doublerait l'accusation sur un site déjà conforme.
    cas.append(("NÉGATIF — branche d'environnement qui SORT avec son aveu : jugée UNE fois", """
        #[test]
        fn t_branche_qui_sort() {
            if !std::env::var("A").is_ok() {
                %s(module_path!(), "t_branche_qui_sort", "levier éteint");
                return;
            }
            assert!(un);
        }
    """ % A, [("t_branche_qui_sort", False)]))

    cas.append(("POSITIF — la jumelle avoue au nom d'un AUTRE test", """
        #[test]
        fn t_jumelle_mal_nommee() {
            if std::env::var("A").is_ok() {
                assert!(un);
            } else {
                %s(module_path!(), "t_le_voisin", "…");
            }
        }
    """ % A, [("t_jumelle_mal_nommee", True)]))

    for nom, source, attendu in cas:
        sites, _ = analyser(source, "<témoin>")
        obtenu = [(s["test"], s["faute"] is not None) for s in sites if not s["hors_population"]]
        # un site hors population est un site VU mais non jugé : on l'atteste séparément
        if nom.startswith("NÉGATIF — protocole"):
            hp = [s for s in sites if s["hors_population"]]
            if len(hp) != 1:
                return f"témoin « {nom} » : {len(hp)} site hors population, attendu 1"
            if obtenu:
                return f"témoin « {nom} » : {obtenu} jugé alors que le test est hors population"
            continue
        if obtenu != attendu:
            return f"témoin « {nom} » : l'analyseur rend {obtenu}, attendu {attendu}"

    # ÉPREUVE DE L'INSTRUMENT LUI-MÊME : un analyseur qui ne reconnaîtrait plus aucun test rendrait
    # « zéro violation » sur tout, et aucun témoin ci-dessus ne bougerait s'ils étaient vides.
    _, vus = analyser("#[test]\nfn a() { return; }\n#[test]\nfn b() { assert!(true); }", "<témoin>")
    if vus != 2:
        return f"l'analyseur ne reconnaît que {vus} fonction(s) de test sur 2 fabriquées"
    return None


# =================================================================================================
# LA CAISSE ET LE CANAL — dérivés, jamais recopiés.
# =================================================================================================
def variable_du_canal():
    try:
        source = open(CANAL, encoding="utf-8").read()
    except OSError:
        return None, None
    m = VARIABLE_DECL.search(source)
    return (m.group(1) if m else None), source


def caisse_du_canal():
    d = os.path.dirname(CANAL)
    while d.startswith(RACINE) and len(d) > len(RACINE):
        if os.path.exists(os.path.join(d, "Cargo.toml")):
            return d
        d = os.path.dirname(d)
    return None


def ecrivain_est_vivant(source):
    """Le canal ÉCRIT-il vraiment ? Un écrivain vidé laisserait tous les sites conformes et le
    canal mort : le lecteur ne saurait pas distinguer « personne n'a refusé » de « rien n'écrit »."""
    corps = re.search(r"pub\(crate\) fn refuser_de_conclure\b.*?\n    \}", source, re.S)
    if not corps:
        return "`refuser_de_conclure` INTROUVABLE dans le canal"
    c = corps.group(0)
    if "VARIABLE_DU_CANAL" not in c:
        return "le canal n'ouvre rien : sa fonction ne lit pas `VARIABLE_DU_CANAL`"
    if ".append(true)" not in c:
        return "le canal n'ouvre pas en AJOUT : deux refus s'écraseraient"
    if "write_all" not in c:
        return "le canal n'écrit rien : aucun `write_all` dans sa fonction"
    return None


# =================================================================================================
def mode_lire():
    """Le canal est RELU et SERVI, bruyamment. Il ne fait jamais échouer : un environnement aveugle
    n'a aucun geste pour refermer un rouge, ce serait une rançon."""
    variable, source = variable_du_canal()
    if variable is None:
        print("::error::le canal est introuvable ou `VARIABLE_DU_CANAL` a changé de forme "
              f"({os.path.relpath(CANAL, RACINE)}) : le lecteur REFUSE DE CONCLURE.", file=sys.stderr)
        return CODE_INSTRUMENT
    faute = ecrivain_est_vivant(source)
    if faute:
        print(f"::error::l'écrivain du canal est cassé ({faute}) : un journal vide ne voudrait rien "
              "dire, le lecteur REFUSE DE CONCLURE.", file=sys.stderr)
        return CODE_INSTRUMENT
    chemin = os.environ.get(variable, "")
    if not chemin:
        print(f"::error::`{variable}` n'est pas posée dans l'environnement de ce pas : le canal "
              "n'a pas été armé, donc « aucun refus » ne voudrait rien dire. Le lecteur REFUSE DE "
              "CONCLURE. Poser la variable dans le MÊME `run:` que la suite.", file=sys.stderr)
        return CODE_INSTRUMENT
    if not os.path.exists(chemin):
        print(f"canal relu ({variable}={chemin}) : AUCUN test n'a refusé de conclure. "
              "Chaque test de la suite a exercé son assertion.")
        return CODE_TENU
    try:
        lignes = [l for l in open(chemin, encoding="utf-8", errors="replace").read().splitlines() if l.strip()]
    except OSError as e:
        print(f"::error::journal des refus illisible ({chemin} : {e}) : le lecteur REFUSE DE CONCLURE.",
              file=sys.stderr)
        return CODE_INSTRUMENT
    if not lignes:
        print(f"canal relu ({variable}={chemin}) : AUCUN test n'a refusé de conclure.")
        return CODE_TENU
    print(f"::warning::{len(lignes)} test(s) ont REFUSÉ DE CONCLURE dans cette suite. Ils sont VERTS "
          "et ne prouvent RIEN : ce que la suite établit est plus étroit que ce que le compte de "
          "tests laisse croire.")
    for l in lignes:
        site, _, cause = l.partition("\t")
        print(f"::warning::REFUS DE CONCLURE — {site} : {cause}")
        print(f"  REFUS  {site}\n         {cause}")
    print(f"\n{len(lignes)} refus consigné(s). La suite reste VERTE À DESSEIN : un environnement "
          "aveugle n'a aucun geste pour refermer un rouge, et un rouge inrefermable est une rançon.")
    return CODE_TENU


def mode_garde():
    variable, source = variable_du_canal()
    if variable is None:
        print(f"::error::`VARIABLE_DU_CANAL` INTROUVABLE dans {os.path.relpath(CANAL, RACINE)} — la "
              "garde jugerait des sites contre un canal qui n'existe plus : elle REFUSE DE CONCLURE.",
              file=sys.stderr)
        return CODE_INSTRUMENT
    faute = ecrivain_est_vivant(source)
    if faute:
        print(f"::error::l'écrivain du canal est cassé ({faute}) : exiger que les sites l'empruntent "
              "n'achèterait rien. La garde REFUSE DE CONCLURE.", file=sys.stderr)
        return CODE_INSTRUMENT
    faute = temoins()
    if faute:
        print(f"::error::instrument INVALIDE ({faute}) : la garde REFUSE DE CONCLURE.", file=sys.stderr)
        return CODE_INSTRUMENT
    caisse = caisse_du_canal()
    if caisse is None:
        print("::error::la caisse du canal n'a pas pu être dérivée (aucun `Cargo.toml` au-dessus de "
              f"{os.path.relpath(CANAL, RACINE)}) : la garde REFUSE DE CONCLURE.", file=sys.stderr)
        return CODE_INSTRUMENT

    sources = os.path.join(caisse, "src")
    fichiers = []
    for d, _, fs in os.walk(sources):
        for f in sorted(fs):
            if f.endswith(".rs"):
                fichiers.append(os.path.join(d, f))
    if not fichiers:
        print(f"::error::aucun `.rs` sous {os.path.relpath(sources, RACINE)} : la garde REFUSE DE "
              "CONCLURE.", file=sys.stderr)
        return CODE_INSTRUMENT

    tous, tests, hors = [], 0, 0
    for chemin in sorted(fichiers):
        try:
            brut = open(chemin, encoding="utf-8").read()
        except OSError as e:
            print(f"::error::{os.path.relpath(chemin, RACINE)} illisible ({e}) : la garde REFUSE DE "
                  "CONCLURE.", file=sys.stderr)
            return CODE_INSTRUMENT
        sites, vus = analyser(brut, os.path.relpath(chemin, RACINE))
        tests += vus
        for s in sites:
            if s["hors_population"]:
                hors += 1
            else:
                tous.append(s)
    if tests == 0:
        print(f"::error::AUCUNE fonction de test reconnue dans {os.path.relpath(sources, RACINE)} : "
              "l'instrument ne voit rien, il REFUSE DE CONCLURE.", file=sys.stderr)
        return CODE_INSTRUMENT

    fautifs = [s for s in tous if s["faute"]]
    if fautifs:
        for s in fautifs:
            print(f"::error file={s['fichier']},line={s['ligne']}::{s['fichier']}:{s['ligne']} — "
                  f"test `{s['test']}` : {s['faute']}")
        print(f"::error::{len(fautifs)} chemin(s) de refus sur {len(tous)} n'empruntent pas le canal. "
              "Un test qui rend la main sans conclure et sans le dire se présente au portail comme un "
              "test qui a prouvé.", file=sys.stderr)
        return CODE_VIOLE

    sorties = len([s for s in tous if s.get("famille") == "sortie"])
    branches = len(tous) - sorties
    print(f"TENU — les {len(tous)} chemin(s) qui rendent la main sans conclure ({sorties} sortie(s) "
          f"anticipée(s), {branches} branche(s) d'environnement à jumelle muette), sur {tests} "
          f"fonctions de test de `{os.path.relpath(caisse, RACINE)}`, empruntent tous le canal "
          f"(`{variable}`), nomment leur propre test et prennent `module_path!()`. "
          f"{hors} site(s) hors population (protocole de ré-exécution).")
    print("POURQUOI CETTE GARDE EXISTE : `libtest` détourne la sortie d'un test qui RÉUSSIT — un "
          "refus imprimé depuis un test vert part dans le vide, et le portail comme la CI ne lisent "
          "que le code de sortie. Le critère est POSITIONNEL (l'appel doit être dans LE BLOC du "
          "`return`), jamais lexical : un aveu ailleurs dans le même test ne blanchit rien.")
    print("CE QU'ELLE N'ACCUSE PAS : un `return` TERMINAL (dernière instruction du corps) ne saute "
          "rien et reste hors population.")
    print("CE QU'ELLE NE TIENT PAS : une condition qui CACHE sa lecture d'environnement derrière un "
          "auxiliaire (deux sites réels de `branche_d_echec_muette.rs` sont dans ce cas) ; le `match` "
          "et les boucles sur une collection dérivée de l'environnement (mesurés : zéro et trois, ces "
          "trois-là portant déjà leur plancher) ; une chaîne `else if` ; un corpus qui perd sa matière "
          "(c'est un plancher dans l'instrument qui tient cette forme) ; une seule caisse, celle qui "
          "porte le canal ; le TEXTE, pas l'exécution (que le canal ait écrit, seul `--lire` le montre).")
    return CODE_TENU


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--lire":
        return mode_lire()
    if len(sys.argv) > 1:
        print(f"::error::usage : {os.path.basename(__file__)} [--lire]", file=sys.stderr)
        return CODE_INSTRUMENT
    return mode_garde()


if __name__ == "__main__":
    sys.exit(main())
