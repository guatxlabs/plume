#!/usr/bin/env python3
"""Un contrôle cité entre accents graves EXISTE dans l'arbre suivi de ce dépôt.

VU le 2026-08-30 (clé `P7.20-g`, corrigé à la main, RIEN ne le tenait). La recette conteneur ET le
document de reprise renvoyaient chacun à une « garde de capacités » comme au CONTRÔLE DE RÉFÉRENCE.
Les deux noms étaient DIFFÉRENTS — `tools/plume-capacites.sh` dans le `Dockerfile`,
`bootstrap/plume-deploy.sh` dans `docs/DR-plume-restore.md` — et TOUS DEUX ABSENTS, comme les deux
répertoires qui les porteraient. Ce dépôt est PUBLIC : un lecteur extérieur lisait « contrôle : … »
et croyait qu'une garde existait là où il n'y en avait aucune, sans aucun moyen de s'en apercevoir.

ATTENDU. Tout jeton entre accents graves ayant la forme d'un chemin RELATIF vers un exécutable
(`.sh`, `.py`, `.ps1`) ou vers un flux d'intégration (`.yml`, `.yaml`) désigne un fichier que
l'arbre SUIVI porte réellement.

CE QUE LA GARDE JUGE, ET CE QU'ELLE NE JUGE PAS. Elle juge l'EXISTENCE du fichier désigné. Elle ne
juge NI ce que ce fichier fait, NI que la phrase qui le cite le décrit correctement : un renvoi vers
un script qui existe mais ne contrôle rien lui échappe par construction.

L'ASSERTION PORTE SUR L'INDEX, JAMAIS SUR LE DISQUE. C'est un piège déjà payé ici : une garde
validée sur un fichier NON SUIVI a rendu l'intégration continue rouge (2026-08-22). Un fichier
présent sur la machine de l'auteur et absent du dépôt est, pour un lecteur extérieur, ABSENT.
`analyser()` ne reçoit que l'ensemble suivi et le texte du corpus — aucun accès au système de
fichiers — et une auto-validation exerce ce cas pour que l'ajout futur d'un tel accès rougisse.

LE DOMAINE EST RESTREINT AUX EXÉCUTABLES ET AUX FLUX, ET C'EST MESURÉ. Le 2026-08-30, sur cet arbre :
663 chemins distincts sont cités entre accents graves ; l'appartenance NUE à l'index en accuse 239,
et 45 subsistent une fois la résolution appliquée. Poser un cliquet à 45 accusations que personne ne
fermera serait une rançon. Restreint aux exécutables et aux flux — la forme même du défaut vu, les
deux noms morts étaient des `.sh` — le compte est de 120 chemins cités et de ZÉRO absent. Un cliquet
posé à zéro est un cliquet qu'on peut tenir. Les 45 restants ne sont PAS oubliés : ils sont NOMMÉS
dans le rapport de la clé `P7.20-i`, et ils sont d'une autre nature (fichiers EXTERNES au dépôt —
`eve.json` de Suricata, `nginx.service`, le dépôt frère `core/src/…` —, chemins d'exemple dans le
dépôt de configuration du lecteur, artefacts engendrés, et deux renvois RÉELLEMENT PÉRIMÉS vers des
modules Rust depuis découpés en répertoires — l'un dans un document et un script de banc, l'autre
dans une notice de connecteurs).

CES DEUX-LÀ NE SONT PAS NOMMÉS ICI, ET C'EST DÉLIBÉRÉ. Les écrire entre accents graves les ferait
compter comme des citations vivantes : ce fichier est hors de son propre corpus aujourd'hui, mais la
règle vaut quand même — ON DÉCRIT LE SITE, ON NE RECOPIE PAS LE NOM. Le piège s'est rejoué trois fois
dans ce dépôt le 2026-08-30, dont une fois sur l'édition de l'auteur de cette garde même. La clé qui les tient les décrit
de la même façon, par leur SITE et leur devenir — un module de serveur et un module de connecteurs,
tous deux découpés en répertoires depuis. Qui veut les retrouver joue cette garde sur un arbre
antérieur : c'est elle qui les nomme, et elle seule, à l'instant où elle accuse.

LA RÉSOLUTION N'EST PAS L'APPARTENANCE NUE, ET C'EST DÉLIBÉRÉ. La prose de ce dépôt cite un contrôle
par son nom seul (`ship.sh`), relativement au fichier qui le cite (`../agent/CI.md`), ou par un
suffixe de son chemin (`handlers/query.rs`). Exiger l'appartenance nue produirait 239 accusations
dont la quasi-totalité serait FAUSSE — et une garde qui accuse à tort est pire que l'angle mort
qu'elle comble. Un jeton est donc résolu s'il l'est par l'une des trois voies, du plus précis au
plus permissif. LE PRIX DE CETTE PERMISSIVITÉ EST NOMMÉ : un chemin mort dont le NOM DE BASE existe
ailleurs dans l'arbre passe. C'est un angle mort assumé, choisi contre le bruit.

ANGLE MORT NOMMÉ, ET MESURÉ CONTRE LE DÉFAUT DE RÉFÉRENCE LUI-MÊME — UN CHEMIN SANS ACCENTS GRAVES
ÉCHAPPE. Éprouvée par mutation le 2026-08-30 contre l'arbre `378f29e~1`, c'est-à-dire AVANT le
correctif manuel, cette garde n'accuse QU'UN des deux renvois morts : `bootstrap/plume-deploy.sh`,
cité entre accents graves dans `docs/DR-plume-restore.md`. Le second, `tools/plume-capacites.sh`,
était écrit entre PARENTHÈSES dans le `Dockerfile` et lui échappe PAR CONSTRUCTION. Élargir
l'extraction aux parenthèses a été MESURÉ plutôt que supposé : elle rattrape bien ce second nom, mais
accuse EN PLUS deux fois à tort sur la tête — `(Traefik/web.sh)`, où la barre oblique veut dire « ou »
et non un chemin, et `(deployment.yaml)`, qui désigne le manifeste k8s en général. Deux fausses
accusations pour une vraie prise : c'est le mauvais côté du marché, une garde qui accuse à tort étant
pire que l'angle mort qu'elle comble. La garde tient donc la CONVENTION DE CITATION de ce dépôt — un
contrôle se cite entre accents graves — et elle ne prétend pas tenir plus.

ANGLE MORT NOMMÉ — `.github/scripts/` EST HORS CORPUS. Les gardes de ce dépôt FABRIQUENT des chemins
absents : c'est leur discipline d'auto-validation qui l'exige, et ce fichier-ci en fabrique lui aussi.
Les balayer reviendrait à accuser la discipline. Ce que cette exclusion laisse passer est déjà tenu
par ailleurs : `check_every_guard_written_is_a_guard_wired.py` tient le lien entre les gardes et leur
câblage. `.github/workflows/` reste DANS le corpus.

VIOLATION = sortie 1. REFUS DE CONCLURE = sortie 2 (racine non dérivable, index illisible ou vide,
corpus vide, ou auto-validation démentie) : la garde ne rend jamais vert en étant aveugle.
"""
import os
import posixpath
import re
import subprocess
import sys
import tempfile
from collections import defaultdict

# La racine se dérive de la POSITION DE CE FICHIER, jamais d'un chemin écrit : un chemin absolu
# codé en dur n'existe que sur la machine de son auteur (mesuré le 2026-08-30, clé `P11.21-d`).
ICI = os.path.dirname(os.path.abspath(os.path.realpath(__file__)))
RACINE = os.path.realpath(os.path.join(ICI, os.pardir, os.pardir))

# Domaine de l'assertion : ce qu'un lecteur est invité à JOUER.
EXTENSIONS_JUGEES = ("sh", "py", "ps1", "yml", "yaml")

# Corpus : documents, recettes et scripts porteurs de prose.
SUFFIXES_CORPUS = (".md", ".sh", ".yml", ".yaml", ".py")
BASES_CORPUS = ("Dockerfile", "Makefile")
PREFIXE_EXCLU = ".github/scripts/"

JETON = re.compile(r"`([^`\n]{1,200})`")
FORME_CHEMIN = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._/+-]*\.([A-Za-z0-9]+)$")


class Refus(Exception):
    """La garde ne sait pas conclure. Sortie 2, jamais un vert."""


def est_du_corpus(chemin):
    if chemin.startswith(PREFIXE_EXCLU):
        return False
    base = posixpath.basename(chemin)
    return chemin.endswith(SUFFIXES_CORPUS) or base.startswith(BASES_CORPUS)


def index_par_suffixe(suivis):
    """Un chemin cité par un suffixe ALIGNÉ SUR LES COMPOSANTS résout vers le fichier entier."""
    index = defaultdict(set)
    for chemin in suivis:
        parts = chemin.split("/")
        for i in range(len(parts)):
            index["/".join(parts[i:])].add(chemin)
    return index


def resout(jeton, citant, suivis, par_suffixe):
    """Rend le chemin suivi désigné, ou None. NE TOUCHE PAS AU SYSTÈME DE FICHIERS."""
    dossier = posixpath.dirname(citant)
    if dossier:
        relatif = posixpath.normpath(posixpath.join(dossier, jeton))
        if not relatif.startswith(os.pardir) and relatif in suivis:
            return relatif
    depuis_racine = posixpath.normpath(jeton)
    if depuis_racine in suivis:
        return depuis_racine
    candidats = par_suffixe.get(depuis_racine)
    if candidats:
        return sorted(candidats)[0]
    return None


def analyser(suivis, textes):
    """(ensemble suivi, {chemin: texte}) -> liste d'accusations (chemin, ligne, jeton).

    Fonction PURE : aucun accès au disque, aucune lecture de l'environnement. C'est ce qui rend
    l'auto-validation sur un tampon FABRIQUÉ probante, et non une vérification de l'état du dépôt
    contre lui-même.
    """
    par_suffixe = index_par_suffixe(suivis)
    accusations = []
    for citant in sorted(textes):
        for numero, ligne in enumerate(textes[citant].splitlines(), start=1):
            for trouve in JETON.finditer(ligne):
                jeton = trouve.group(1).strip()
                if not jeton or jeton.startswith("/") or "<" in jeton or ">" in jeton:
                    continue
                if " " in jeton:
                    continue
                forme = FORME_CHEMIN.match(jeton)
                if not forme or forme.group(1).lower() not in EXTENSIONS_JUGEES:
                    continue
                if resout(jeton, citant, suivis, par_suffixe) is None:
                    accusations.append((citant, numero, jeton))
    return accusations


def compter_cites(suivis, textes):
    """Le DÉNOMINATEUR du cliquet : sans lui, un corpus devenu vide se lirait comme un vert."""
    vus = set()
    for citant, texte in textes.items():
        for trouve in JETON.finditer(texte):
            jeton = trouve.group(1).strip()
            if not jeton or jeton.startswith("/") or "<" in jeton or ">" in jeton or " " in jeton:
                continue
            forme = FORME_CHEMIN.match(jeton)
            if forme and forme.group(1).lower() in EXTENSIONS_JUGEES:
                vus.add(jeton)
    return len(vus)


# ── AUTO-VALIDATION SUR DES ENTRÉES FABRIQUÉES ────────────────────────────────────────────────
# Jouée AVANT tout verdict, et sur des entrées construites ICI — jamais sur l'état du dépôt. Un
# témoin adossé au dépôt rougirait le jour où le travail est fini : ce serait une rançon.

def _exiger(condition, quoi):
    if not condition:
        raise Refus("auto-validation démentie : %s" % quoi)


def auto_valider():
    suivis = {
        "bootstrap.sh",
        "collectors/ship.sh",
        "docs/GUIDE.md",
        "a/b/tools/construire.sh",
        "bench/run.sh",
        ".github/workflows/ci.yml",
        "daemon/src/server/mod.rs",
    }

    # 1. LE CAS NOMINAL : un chemin PRÉSENT et un chemin ABSENT, exactement UNE accusation.
    tampon = {
        "docs/GUIDE.md": (
            "Le contrôle de reference est `bootstrap.sh`.\n"
            "La garde de capacites est `tools/plume-capacites.sh`.\n"
        )
    }
    trouve = analyser(suivis, tampon)
    _exiger(len(trouve) == 1, "cas nominal : %d accusations au lieu d'une (%r)" % (len(trouve), trouve))
    _exiger(trouve[0][2] == "tools/plume-capacites.sh", "cas nominal : accuse %r" % (trouve[0],))
    _exiger(trouve[0][1] == 2, "cas nominal : ligne %d au lieu de 2" % trouve[0][1])

    # 2. LES DEUX NOMS MORTS DU DÉFAUT DE RÉFÉRENCE sont accusés, et ils sont DIFFÉRENTS.
    tampon = {
        "Dockerfile": "La garde de capacites du deploiement (`tools/plume-capacites.sh`) refuse.\n",
        "docs/DR.md": "Controle : la garde de capacites de `bootstrap/plume-deploy.sh`.\n",
    }
    trouve = analyser(suivis, tampon)
    _exiger(
        sorted(a[2] for a in trouve) == ["bootstrap/plume-deploy.sh", "tools/plume-capacites.sh"],
        "les deux renvois morts du defaut de reference ne sont pas accuses : %r" % (trouve,),
    )

    # 3. LES TROIS VOIES DE RÉSOLUTION N'ACCUSENT PAS. Si l'une régresse, elle accuse à tort —
    #    c'est le mode d'échec le plus coûteux de cette garde, il est donc exercé nommément.
    _exiger(
        analyser(suivis, {"docs/GUIDE.md": "voir `../bootstrap.sh`\n"}) == [],
        "voie RELATIVE au fichier citant : accuse a tort",
    )
    _exiger(
        analyser(suivis, {"README.md": "voir `collectors/ship.sh`\n"}) == [],
        "voie RACINE : accuse a tort",
    )
    _exiger(
        analyser(suivis, {"README.md": "voir `tools/construire.sh` et `run.sh`\n"}) == [],
        "voie SUFFIXE / nom de base : accuse a tort",
    )

    # 4. L'ASSERTION PORTE SUR L'INDEX, PAS SUR LE DISQUE. Le chemin cité EXISTE réellement sur
    #    cette machine et n'est PAS suivi : il doit être accusé. Ce témoin ne prouve rien sur le
    #    code d'aujourd'hui — `analyser()` ne reçoit aucune racine — il rougira le jour où
    #    quelqu'un y ajoutera une lecture du système de fichiers pour « réduire le bruit ».
    with tempfile.TemporaryDirectory(prefix="controle_cite_") as bac:
        reel = os.path.join(bac, "outil")
        os.makedirs(reel)
        with open(os.path.join(reel, "present_sur_le_disque.sh"), "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\n")
        precedent = os.getcwd()
        try:
            os.chdir(bac)
            trouve = analyser(suivis, {"docs/GUIDE.md": "jouez `outil/present_sur_le_disque.sh`\n"})
        finally:
            os.chdir(precedent)
    _exiger(
        [a[2] for a in trouve] == ["outil/present_sur_le_disque.sh"],
        "un fichier PRESENT SUR LE DISQUE mais NON SUIVI n'est pas accuse : %r" % (trouve,),
    )

    # 5. LE DOMAINE EST BIEN RESTREINT. Un `.rs`, un `.md`, un `.json` absents ne sont PAS accusés :
    #    la restriction est le fondement du cliquet à zéro, elle doit échouer si elle s'élargit.
    _exiger(
        analyser(suivis, {"README.md": "`fantome.rs` `absent/ailleurs.md` `x/y.json`\n"}) == [],
        "le domaine s'est elargi hors des executables et des flux",
    )
    _exiger(
        [a[2] for a in analyser(suivis, {"R.md": "`f.rs` `absent/ailleurs.yml`\n"})]
        == ["absent/ailleurs.yml"],
        "un flux d'integration absent n'est pas accuse",
    )

    # 6. CE QUI N'EST PAS UN CHEMIN NE DOIT JAMAIS ÊTRE ACCUSÉ.
    _exiger(
        analyser(
            suivis,
            {"R.md": "`--features` `/usr/local/bin/absent.sh` `<votre>.sh` `deux mots.sh` `1.2.3`\n"},
        )
        == [],
        "un jeton qui n'est pas un chemin relatif est accuse",
    )

    # 7. LE CORPUS EXCLUT LES GARDES, ET RIEN D'AUTRE.
    _exiger(not est_du_corpus(".github/scripts/check_x.py"), "les gardes ne sont pas exclues du corpus")
    _exiger(est_du_corpus(".github/workflows/ci.yml"), "les flux sont exclus du corpus a tort")
    _exiger(est_du_corpus("Dockerfile") and est_du_corpus("collector-mail/Dockerfile"),
            "les recettes conteneur sont exclues du corpus a tort")
    _exiger(est_du_corpus("docs/README.md") and est_du_corpus("bootstrap.sh"),
            "les documents ou les scripts sont exclus du corpus a tort")
    _exiger(not est_du_corpus("daemon/src/main.rs"), "le corpus deborde sur les sources Rust")


# ── LECTURE DU DÉPÔT ──────────────────────────────────────────────────────────────────────────

def lire_index():
    try:
        sommet = subprocess.run(
            ["git", "-C", RACINE, "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as erreur:
        raise Refus("`git rev-parse` a echoue depuis %s (%s)" % (RACINE, erreur))
    if os.path.realpath(sommet) != RACINE:
        raise Refus(
            "la racine derivee de la position de ce fichier (%s) n'est pas le sommet du depot (%s)"
            % (RACINE, os.path.realpath(sommet))
        )
    try:
        brut = subprocess.run(
            ["git", "-C", RACINE, "ls-files", "-z"],
            capture_output=True, text=True, check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as erreur:
        raise Refus("`git ls-files` a echoue depuis %s (%s)" % (RACINE, erreur))
    suivis = {chemin for chemin in brut.split("\0") if chemin}
    if not suivis:
        raise Refus("l'index est vide depuis %s : rien a juger" % RACINE)
    return suivis


def lire_corpus(suivis):
    textes = {}
    for chemin in sorted(suivis):
        if not est_du_corpus(chemin):
            continue
        absolu = os.path.join(RACINE, chemin)
        try:
            with open(absolu, encoding="utf-8", errors="replace") as fichier:
                textes[chemin] = fichier.read()
        except OSError as erreur:
            raise Refus("fichier suivi illisible : %s (%s)" % (chemin, erreur))
    if not textes:
        raise Refus("le corpus est vide : aucun document, recette ni script suivi")
    return textes


def main():
    try:
        auto_valider()
    except Refus as refus:
        print("REFUS DE CONCLURE — %s" % refus, file=sys.stderr)
        return 2

    try:
        suivis = lire_index()
        textes = lire_corpus(suivis)
    except Refus as refus:
        print("REFUS DE CONCLURE — %s" % refus, file=sys.stderr)
        return 2

    accusations = analyser(suivis, textes)
    cites = compter_cites(suivis, textes)

    if accusations:
        print(
            "%d contrôle(s) cité(s) n'existe(nt) dans AUCUN chemin de l'arbre suivi.\n"
            "Un lecteur extérieur croit qu'une garde existe là où il n'y en a aucune.\n"
            % len(accusations),
            file=sys.stderr,
        )
        for chemin, ligne, jeton in accusations:
            print("  %s:%d  `%s`" % (chemin, ligne, jeton), file=sys.stderr)
        print(
            "\nREMÈDE : citer un chemin que l'arbre porte, ou dire en toutes lettres que le contrôle\n"
            "n'existe pas et nommer le geste qui le remplace. Ne PAS créer un fichier vide pour\n"
            "verdir la garde : le lecteur y perdrait deux fois.",
            file=sys.stderr,
        )
        return 1

    print(
        "OK — %d fichier(s) suivi(s) au corpus, %d chemin(s) d'exécutable ou de flux cité(s) entre "
        "accents graves, 0 absent de l'arbre suivi." % (len(textes), cites)
    )
    print(
        "   Domaine jugé : %s. Hors domaine et hors corpus (.github/scripts/), voir la clé `P7.20-i`."
        % ", ".join("." + e for e in EXTENSIONS_JUGEES)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
