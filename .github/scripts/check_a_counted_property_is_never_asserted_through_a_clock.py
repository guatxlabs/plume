#!/usr/bin/env python3
"""Un témoin qui ANNONCE un compte ne le tient pas avec une HORLOGE — garde de CI.

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
Deux témoins de ce dépôt, écrits le même jour et de la même main, ont porté la MÊME construction :
une constante nommant un NOMBRE D'OPÉRATIONS, un commentaire disant que le plafond en est dérivé
« pas d'une durée », et sous ces deux lignes une assertion sur un RAPPORT DE MÉDIANES DE DURÉES. Le
texte décrivait un compte, le code chronométrait. Ce ne sont pas la même grandeur : une durée mesure
aussi la machine qui l'observe.

Le premier a rougi le 2026-08-31 sur le portail de déploiement — qui rejoue la suite sur la machine
de build PENDANT qu'elle compile — en annonçant 13,50 lectures de `/proc` là où la composition en
vaut 4, sur un arbre INTACT. Une accusation FAUSSE, contre un code juste, par un témoin vert au
repos sur le poste de développement. Le second n'avait jamais rougi (clé `P11.23-d`).

ET L'ARGUMENT D'EXPOSITION QUI A LANCÉ CE LOT ÉTAIT FAUX DANS SA FORME — il est écrit ici pour que
personne ne le reprenne : opposer les 2,05 fois de marge du second à l'excursion de 3,2 constatée
sur le premier est un TRANSFERT PAR ANALOGIE, pas un relevé. Le pire chiffre du second n'a jamais
été mesuré sur la machine de build. Ce qui EST mesuré est bien pire, et c'est le paragraphe suivant.

ET LE PRIX DE CETTE FORME A ÉTÉ MESURÉ UNE SECONDE FOIS, EN LA CORRIGEANT : COMPTER, avec cinq
`Cell<u64>` de fil, ce que le second témoin prétendait déjà borner suffisait à faire passer son
repère de 8,1 à 15,1 puis (première rédaction, un `Cell` de 40 octets recopié à chaque geste) à
19,0 — AU-DESSUS de son plafond de 18. Une grandeur qu'on ne peut pas instrumenter sans la faire
sortir de ses bornes n'était pas la bonne grandeur.

LA PROPRIÉTÉ TENUE, EN UNE PHRASE
----------------------------------
Aucune assertion ne compare une grandeur CHRONOMÉTRÉE pendant que la prose ATTACHÉE à cette grandeur
annonce un COMPTE D'OPÉRATIONS. Un compte se compte ; une durée se chronomètre ; on n'asserte pas
l'un par l'autre.

DEUX JAMBES, ET LEUR CONJONCTION EST CHOISIE POUR LA DIRECTION DE L'ERREUR
--------------------------------------------------------------------------
(A) STRUCTURELLE, SANS AUCUN LEXIQUE. L'expression COMPARÉE par l'assertion (le 1er argument ; les
    deux premiers pour `assert_eq!`/`assert_ne!`) dépend d'une grandeur née d'une HORLOGE —
    `Instant::now()` ou `.elapsed()` — dans la MÊME fonction. Le flot est propagé à travers les
    liaisons, y compris les motifs de tuple (`let (r, o) = …`) et les accumulations (`v.push(…)`,
    `v[i].push(…)`), jusqu'à saturation.

(B) LEXICALE, ÉTROITE, ET APPLIQUÉE À LA SEULE PROSE ATTACHÉE À LA GRANDEUR : le MESSAGE de
    l'assertion, et les commentaires de doc des CONSTANTES que l'expression comparée nomme. Elle
    cherche des noms d'OPÉRATIONS — des choses qu'on FAIT, jamais des durées.

L'ACCUSATION EXIGE LES DEUX, et ce n'est pas une précaution de style : c'est le choix de la
DIRECTION de l'erreur résiduelle. La jambe (B) ne peut que faire MANQUER un défaut (prose muette =
silence) ; elle ne peut jamais faire accuser un témoin dont la propriété EST une durée — un budget
de latence, une temporisation, un filet, une comparaison de deux mesures. Ces formes existent dans
ce dépôt, elles sont légitimes, et une garde qui les accuserait finirait désarmée — ce qui coûterait
tout.

CE QUE LA GARDE NE LIT PAS, ET C'EST DÉLIBÉRÉ
----------------------------------------------
Elle ne lit PAS le commentaire de doc de la FONCTION, ni la prose alentour : uniquement le message
de l'assertion et la doc des constantes comparées. Un fichier doit pouvoir DÉCRIRE ce défaut — le
raconter, citer la phrase fautive, expliquer pourquoi il ne le commet plus — sans être accusé de le
commettre. C'est exactement le cas de
`daemon/src/tests/attente_serie.rs::une_observation_ne_fait_que_six_gestes_atomiques_et_n_alloue_rien`,
dont la doc cite la phrase d'origine mot pour mot pour dire pourquoi elle est fausse.

CE QU'ELLE NE TIENT PAS, ÉCRIT POUR ÊTRE OPPOSABLE
---------------------------------------------------
  * elle ne dit RIEN de la JUSTESSE du compte annoncé : « quatre lectures » peut être faux, elle ne
    vérifie que le fait qu'on ne l'asserte pas par une horloge ;
  * son flot de données est TEXTUEL et par fonction, et il ne connaît que `Instant::now()` et
    `.elapsed()`. Une horloge atteinte à travers une fonction de production
    (`getrusage`, `db_lock_wait_ms`, une durée rendue par le produit) lui est INVISIBLE ;
  * le découpage en fonctions est un motif sur `fn` en début de ligne : une fonction imbriquée
    profondément, ou une fermeture qui traverse la frontière, peut faire fuiter une liaison d'une
    fonction à la suivante — dans le sens qui fait MANQUER (la liaison meurt à la borne suivante),
    jamais dans celui qui accuse un innocent ;
  * elle ne regarde que le Rust, et seulement les macros `assert!`/`assert_eq!`/`assert_ne!` : un
    `if … { panic!(…) }` lui échappe ;
  * un défaut dont la prose ne nomme aucune opération est MANQUÉ. C'est la contrepartie assumée de
    (B), et le sens de l'erreur est choisi.

L'INSTRUMENT SE VALIDE AVANT DE RENDRE UN VERDICT, SUR DES ENTRÉES FABRIQUÉES ICI — jamais sur
l'état de l'arbre. Aucun plancher du type « au moins N occurrences dans le dépôt » : ce plancher
rougirait le jour où le travail est FINI, et une garde qui exige que le défaut survive est une
rançon, pas une garde. Les témoins sont donc six sources Rust construites en mémoire : une que la
garde DOIT accuser, cinq qu'elle NE DOIT PAS accuser.

Codes de sortie :
  0  la propriété est tenue
  1  la propriété est VIOLÉE — le site est NOMMÉ (fichier, ligne, fonction, grandeur, mots trouvés)
  2  l'instrument REFUSE DE CONCLURE (auto-épreuve en échec, racine inutilisable, rien à lire)
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_every_style_selector_has_a_target import (  # noqa: E402  (GESTES PARTAGÉS, source unique — `P11.8-m`, `P11.8-n`)
    parcours_des_sources, racine_designee)

# LA RACINE PAR DÉFAUT est celle de CE fichier, DÉSIGNÉE à la fonction partagée plutôt que devinée
# par elle : `jouer-la-batterie-de-gardes.sh` lance chaque garde SANS se placer dans le dépôt, et la
# retombée « répertoire courant » ferait alors refuser sur un arbre sain (`P11.8-n`).
DEPOT_DE_CETTE_GARDE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Renseignée par `main()` : une racine ne se devine pas à l'IMPORT (ce module est importable, et lire
# `sys.argv` à l'import ferait juger l'argument d'un AUTRE programme).
RACINE = None

# ── (A) L'HORLOGE, RECONNUE PAR SA FORME — aucun mot de vocabulaire métier ici ─────────────────
HORLOGE = re.compile(r"\.elapsed\(\)|Instant::now\(\)")
# `let <motif> = <valeur>` : le motif peut être une liaison simple, un tuple, un `mut`.
LIAISON = re.compile(r"\blet\s+(.+?)\s*=\s*([^=].*)")
# `v.push(x)` et `v[i].push(x)` : une durée accumulée dans un vecteur voyage par lui.
ACCUMULATION = re.compile(r"(\w+)\s*(?:\[[^\]]*\])?\s*\.push\((.+)\)")
MOT = re.compile(r"\w+")
DEBUT_DE_FONCTION = re.compile(r"^\s{0,12}(pub(\([^)]*\))?\s+)?(async\s+)?(unsafe\s+)?fn\s+\w+")
ASSERTION = re.compile(r"\bassert(_eq|_ne)?!")
DECLARATION_DE_CONSTANTE = re.compile(r"^\s*(pub(\([^)]*\))?\s+)?const\s+([A-Z_0-9]+)\s*:")
# Ce qu'un motif de liaison n'est pas : des mots-clés, jamais des noms de grandeurs.
NON_LIAISONS = {"mut", "let", "ref", "Some", "Ok", "None", "Err"}

# ── (B) LA PROSE QUI ANNONCE UN COMPTE ────────────────────────────────────────────────────────
# DES NOMS D'OPÉRATIONS — des choses qu'on FAIT, dénombrables, et dont aucune n'est une durée. La
# liste est COURTE et le restera : chaque entrée est un mot qu'on ne peut pas employer pour décrire
# un délai. Les bornes de mot excluent les mots composés (« double-compte » nomme un défaut de
# comptabilité, pas un nombre d'opérations) et les formes verbales accentuées (« a compté »).
COMPTE = [
    r"atomiques?",
    r"op[ée]rations?",
    r"lectures?",
    r"[ée]critures?",
    r"acc[èe]s",
    r"appels?",
    r"allocations?",
    r"instructions?",
    r"gestes?",
    r"composition",
    r"nombre\s+d",
    r"compte\s+d",
]
PROSE_DE_COMPTE = re.compile(
    "|".join(r"(?<![-\w])(?:" + m + r")(?![-\w])" for m in COMPTE), re.IGNORECASE)


def fonctions(lignes):
    """Découpe un fichier en (nom, première ligne, corps) sur les débuts de `fn`. Grossier, et dit
    comme tel dans l'en-tête : une liaison ne peut que MOURIR trop tôt, jamais migrer vers une
    fonction voisine où elle accuserait un innocent."""
    bornes = [i for i, l in enumerate(lignes) if DEBUT_DE_FONCTION.match(l)]
    bornes.append(len(lignes))
    for i in range(len(bornes) - 1):
        debut, fin = bornes[i], bornes[i + 1]
        nom = re.search(r"fn\s+(\w+)", lignes[debut])
        yield (nom.group(1) if nom else "?"), debut, lignes[debut:fin]


def grandeurs_chronometrees(corps):
    """Les noms dont la valeur DÉRIVE d'une horloge, par saturation du flot dans ce corps."""
    connues = set()
    for _ in range(4):  # saturation : quatre passes suffisent aux chaînes de ce dépôt
        for l in corps:
            if l.lstrip().startswith("//"):
                continue  # une liaison COMMENTÉE n'existe pas
            m = LIAISON.search(l)
            if m:
                motif, valeur = m.group(1), m.group(2)
                if HORLOGE.search(valeur) or any(re.search(r"\b" + re.escape(c) + r"\b", valeur) for c in connues):
                    connues.update(w for w in MOT.findall(motif) if w not in NON_LIAISONS)
            a = ACCUMULATION.search(l)
            if a and (HORLOGE.search(a.group(2))
                      or any(re.search(r"\b" + re.escape(c) + r"\b", a.group(2)) for c in connues)):
                connues.add(a.group(1))
    return connues


def arguments_de_macro(texte):
    """Les arguments de premier niveau d'une invocation de macro, à partir de son `!`.

    Rend `None` si l'invocation n'est pas refermée dans la fenêtre reçue — un argument tronqué serait
    lu de travers, et on préfère ne rien dire."""
    debut = texte.index("!")
    ouvrant = texte.find("(", debut)
    if ouvrant < 0:
        return None
    prof, args, courant, chaine, echappe = 0, [], [], False, False
    for c in texte[ouvrant:]:
        if chaine:
            if echappe:
                echappe = False
            elif c == "\\":
                echappe = True
            elif c == '"':
                chaine = False
            courant.append(c)
            continue
        if c == '"':
            chaine = True
            courant.append(c)
            continue
        if c in "([{":
            prof += 1
            if prof == 1:
                continue
        elif c in ")]}":
            prof -= 1
            if prof == 0:
                args.append("".join(courant))
                return args
        if c == "," and prof == 1:
            args.append("".join(courant))
            courant = []
            continue
        courant.append(c)
    return None


def docs_des_constantes(corps, expression):
    """Les commentaires de doc des `const` DÉCLARÉES dans ce corps et NOMMÉES dans l'expression."""
    prose = []
    for i, l in enumerate(corps):
        d = DECLARATION_DE_CONSTANTE.match(l)
        if not d:
            continue
        nom = d.group(3)
        if not re.search(r"\b" + re.escape(nom) + r"\b", expression):
            continue
        j = i - 1
        while j >= 0 and corps[j].lstrip().startswith("///"):
            prose.append(corps[j])
            j -= 1
        # la valeur elle-même peut nommer une autre constante : on suit d'un cran.
        for autre in MOT.findall(l):
            if autre.isupper() and autre != nom and len(autre) > 2:
                prose.extend(docs_des_constantes(corps, autre))
    return prose


def sites_accuses(chemin, source):
    """Les assertions de ce fichier qui comparent une grandeur chronométrée en annonçant un compte."""
    trouves = []
    lignes = source.split("\n")
    for nom_fn, decalage, corps in fonctions(lignes):
        chronos = grandeurs_chronometrees(corps)
        if not chronos:
            continue
        for i, l in enumerate(corps):
            if not ASSERTION.search(l) or l.lstrip().startswith("//"):
                continue
            args = arguments_de_macro("\n".join(corps[i:i + 24]))
            if not args:
                continue
            combien = 2 if re.search(r"assert_(eq|ne)!", l) else 1
            compare = ",".join(args[:combien])
            message = ",".join(args[combien:])
            vus = sorted(c for c in chronos if re.search(r"\b" + re.escape(c) + r"\b", compare))
            if not vus and not HORLOGE.search(compare):
                continue
            prose = message + "\n" + "\n".join(docs_des_constantes(corps, compare))
            mots = sorted({m.group(0) for m in PROSE_DE_COMPTE.finditer(prose)})
            if mots:
                trouves.append((chemin, decalage + i + 1, nom_fn, vus or ["<horloge lue sur place>"], mots))
    return trouves


# ── L'AUTO-ÉPREUVE — six sources FABRIQUÉES ICI, jamais l'état de l'arbre ──────────────────────
POSITIF = '''
fn un_temoin_qui_annonce_un_compte_et_chronometre() {
    /// Le nombre d'opérations atomiques que fait UNE observation.
    const ATOMIQUES_PAR_OBSERVATION: f64 = 6.0;
    /// Le plafond est dérivé de CE nombre, pas d'une durée.
    const RAPPORT_MAX: f64 = 3.0 * ATOMIQUES_PAR_OBSERVATION;
    let mut refs = Vec::new();
    let t = Instant::now();
    refs.push(t.elapsed());
    let (r, o) = (mediane(&mut refs), mediane(&mut obs));
    let rapport = o.as_secs_f64() / r.as_secs_f64();
    assert!(rapport <= RAPPORT_MAX, "ce n'est plus la composition attendue ({ATOMIQUES_PAR_OBSERVATION} atomiques)");
}
'''

NEGATIFS = [
    ("un budget de latence : la propriété EST une durée", '''
fn la_garde_interrompt_une_requete_qui_s_emballe() {
    const QB_FILET_MS: f64 = 9600.0;
    let t0 = Instant::now();
    let attente = t0.elapsed().as_secs_f64() * 1000.0;
    assert!(attente < QB_FILET_MS, "FILET : la garde n'a pas tiré — {attente} ms pour un budget de {budget} ms");
}
'''),
    ("un compte asserté SANS horloge — la forme corrigée", '''
fn une_observation_ne_fait_que_six_gestes_atomiques() {
    const AJOUTS_PAR_OBSERVATION: u64 = 4;
    let t = Instant::now();
    let repere = t.elapsed();
    let vue = temoin_de_composition::releve();
    assert_eq!(vue.ajouts, AJOUTS_PAR_OBSERVATION * N, "{N} observations ont fait {} ajouts d'atomique", vue.ajouts);
    eprintln!("repère {repere:?}");
}
'''),
    ("deux durées comparées entre elles : aucun compte annoncé", '''
fn le_rollup_n_est_pas_plus_lent_que_le_scan_brut() {
    let t0 = Instant::now();
    let d_roll = t0.elapsed();
    let t1 = Instant::now();
    let d_raw = t1.elapsed();
    assert!(d_roll <= d_raw, "le group-by via rollup NE DOIT PAS être plus lent que le scan brut");
}
'''),
    ("la forme fautive, mais en COMMENTAIRE", '''
fn un_fichier_qui_decrit_le_defaut_sans_le_commettre() {
    // const ATOMIQUES: f64 = 6.0;
    // let rapport = o.as_secs_f64() / r.as_secs_f64();
    // assert!(rapport <= 3.0 * ATOMIQUES, "ce n'est plus la composition attendue ({ATOMIQUES} atomiques)");
    assert_eq!(vue.ajouts, 4, "quatre ajouts");
}
'''),
    ("un mot composé n'est pas un compte d'opérations", '''
fn la_composition_ne_double_compte_pas() {
    let mural = Instant::now();
    let mural_ms = mural.elapsed().as_secs_f64() * 1000.0;
    assert!(verrou + permis <= mural_ms + 1.0, "leur somme ne serait plus un coût, ce serait un double-compte");
}
'''),
]


def auto_epreuve():
    """Rend la première faute constatée sur les témoins fabriqués, ou `None`."""
    vus = sites_accuses("<positif>", POSITIF)
    if len(vus) != 1:
        return (f"témoin POSITIF : {len(vus)} accusation(s) au lieu d'une — la garde ne reconnaît plus "
                f"la forme qu'elle existe pour refuser ({vus})")
    if "atomiques" not in " ".join(vus[0][4]).lower():
        return f"témoin POSITIF : l'accusation ne nomme pas le mot de compte trouvé ({vus[0][4]})"
    for nom, source in NEGATIFS:
        vus = sites_accuses("<négatif>", source)
        if vus:
            return (f"témoin NÉGATIF « {nom} » : accusé à tort ({vus}). Une garde qui accuse un témoin "
                    f"dont la propriété EST une durée finit désarmée")
    if PROSE_DE_COMPTE.search("double-compte") or PROSE_DE_COMPTE.search("il a compté"):
        return "témoin de lexique : les bornes de mot ne tiennent pas (composé ou forme verbale accepté)"
    if not PROSE_DE_COMPTE.search("quatre lectures de /proc"):
        return "témoin de lexique : un compte d'opérations écrit en toutes lettres n'est plus reconnu"
    return None


def main():
    global RACINE
    RACINE = racine_designee(sys.argv if len(sys.argv) > 1 else [sys.argv[0], DEPOT_DE_CETTE_GARDE])

    faute = auto_epreuve()
    if faute:
        print("REFUS DE CONCLURE — l'auto-épreuve de la garde échoue, donc son verdict sur l'arbre ne "
              f"vaudrait rien :\n  {faute}", file=sys.stderr)
        return 2

    fichiers, illisibles = [], []
    for base, noms in parcours_des_sources(RACINE):
        for n in noms:
            if n.endswith(".rs"):
                fichiers.append(os.path.join(base, n))
    if not fichiers:
        print(f"REFUS DE CONCLURE — aucun fichier `.rs` sous « {RACINE} » : l'instrument n'a rien à "
              "lire, et un vert ici n'attesterait rien.", file=sys.stderr)
        return 2

    accuses = []
    for f in sorted(fichiers):
        try:
            source = open(f, encoding="utf-8").read()
        except (OSError, UnicodeDecodeError) as e:
            illisibles.append(f"{os.path.relpath(f, RACINE)} ({e.__class__.__name__})")
            continue
        accuses.extend(sites_accuses(os.path.relpath(f, RACINE), source))
    if illisibles:
        print(f"REFUS DE CONCLURE — {len(illisibles)} source(s) illisible(s), donc une partie de l'arbre "
              f"n'a pas été jugée : {', '.join(illisibles[:5])}", file=sys.stderr)
        return 2

    if accuses:
        print(f"UN TÉMOIN ANNONCE UN COMPTE ET MESURE UNE DURÉE — {len(accuses)} site(s) :", file=sys.stderr)
        for chemin, ligne, fn, grandeurs, mots in accuses:
            print(f"  {chemin}:{ligne}  [{fn}]", file=sys.stderr)
            print(f"      la grandeur comparée dérive d'une horloge : {', '.join(grandeurs)}", file=sys.stderr)
            print(f"      et sa prose annonce un compte : {', '.join(mots)}", file=sys.stderr)
        print("\n  Une durée mesure aussi la machine : le même code rend un autre nombre sur un portail "
              "de build qui compile. COMPTEZ ce que vous annoncez (compteurs `#[cfg(test)]` par fil, "
              "`assert_eq!` exacts), ou dites que le chiffre est un REPÈRE et n'assertez rien dessus. "
              "N'ÉLARGISSEZ PAS LE PLAFOND : il se supprime avec la grandeur qu'il bornait.", file=sys.stderr)
        return 1

    print(f"OK — {len(fichiers)} source(s) Rust : aucune assertion ne tient un compte annoncé par une "
          f"horloge (racine « {RACINE} »).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
