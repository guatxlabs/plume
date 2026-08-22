#!/usr/bin/env python3
"""Un chiffre d'EXPLOITATION ne se publie pas — garde de CI (`P7.17-a`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
`AGENTS.md` §4 : un chiffre de CONCEPTION se publie (un plafond, une borne, un ordre de grandeur qui
décrit le produit) ; un chiffre d'EXPLOITATION ne se publie pas (une taille de base, un débit, un
compteur, un horodatage d'incident, un nom d'objet RELEVÉS sur une installation réelle). Il
renseigne sur une cible et n'apprend rien à un lecteur du code. La roadmap publique avait été
expurgée ; les commentaires du code, la documentation et les scripts, non — un filtre grossier en
rendait déjà des dizaines (taille exacte de la base, durée d'un parcours sur cette base, compteur
d'un collecteur « depuis le <horodatage> », deux services Kubernetes morts nommés par leur forme).

LE CRITÈRE, ÉCRIT UNE FOIS, ET REJOUABLE
----------------------------------------
Ce qui sépare les deux classes n'est pas le chiffre, c'est L'OBJET MESURÉ. Mesurer le PRODUIT (un
banc sur données synthétiques, un harnais, une VM jetable, l'arbre du dépôt, la suite de tests)
donne un chiffre de conception ; mesurer UNE INSTALLATION (sa base, ses compteurs, ses incidents,
ses hôtes) donne un chiffre d'exploitation. La garde ne lit donc pas une liste de mots interdits :
elle reconnaît la FORME d'un relevé et exige qu'il dise d'où il vient.

Une ligne est ACCUSÉE quand elle porte une GRANDEUR RELEVÉE et que l'une des deux attestations
suivantes est présente :

  (R) l'attestation d'une INSTALLATION RÉELLE, sur la ligne ou sur celle qui la précède (un relevé
      replié) — « en production », « sur la production », « en prod », « en exploitation », « sur le
      central », « l'instance de référence », « une base réelle », un incident d'installation (une
      RÉPLIQUE locale est un banc : ce qu'on y mesure décrit le moteur, pas la cible ; l'adjectif
      seul, « la base de prod », nomme un rôle et n'atteste rien) ; ou un NOM D'OBJET d'infrastructure
      réel : un hôte sous le domaine de l'éditeur (DÉRIVÉ de l'identité canonique du dépôt, jamais
      écrit ici), un service Kubernetes nommé `<svc>.<ns>.svc` hors gabarit, un pod portant le hash
      de son ReplicaSet. L'attestation EXPLICITE prime sur le chemin et sur un contexte de banc
      voisin : un chiffre « relevé en production » cité dans un test reste un relevé.
      Toute grandeur absolue compte ici : une taille, une durée, un compteur. Pas un pourcentage —
      un rapport est la forme que prend la connaissance une fois la valeur absolue retirée — ni
      une BORNE (« budget de 2 Gio », « plafond 512 Mio ») : un budget n'est pas une mesure.

  (D) une DATE dans le paragraphe et un VOLUME À L'ÉCHELLE D'UNE INSTALLATION sur la ligne — des
      méga-octets ou plus, des milliers de lignes ou d'événements, un horodatage à la seconde —
      SANS contexte de banc ou d'arbre déclaré dans le paragraphe, ni chemin de test ou de banc. On
      ne date pas un plafond : une taille datée est un relevé, et un relevé qui ne dit pas venir
      d'un banc est présumé venir d'une installation. Sont écartés les petits comptes d'une
      expérience (« 4 événements »), les puissances de deux exactes (une base ne pèse jamais 2^30
      octets : c'est une constante) et les bornes. Une DURÉE datée sans attribution n'est pas
      accusée par cette jambe : c'est le coût d'un outil sur un poste, il décrit l'outil, pas une
      cible. Elle l'est par (R) dès qu'elle est attribuée à une installation.

Le CONTEXTE DÉCLARÉ qui lève l'accusation est de deux familles, et c'est la RÈGLE D'ÉCRITURE que
cette garde tient : « tout chiffre daté dit d'où il vient ». BANC : banc, bench, synthétique,
harnais, fixture, témoin, VM, jeu de test, profil de banc, `cargo test`, poste de développement,
une assertion de test. ARBRE : sur l'arbre, dans le dépôt, fichiers suivis, capteurs livrés, la
suite, en release/debug, sur le binaire, en CI, une extrapolation, un pire cas. Un fichier de test
ou de banc (chemin `tests/`, `tests.rs`, `bench/`, `BENCHMARK`) est un contexte de banc par
construction. Un faux positif se corrige en DISANT le contexte (« au banc », « sur l'arbre »), ce
qui rend le texte plus exact — jamais en retirant un mot à la garde. Le paragraphe est la fenêtre :
quelques lignes de part et d'autre, sans franchir une ligne vide, et une ligne de tableau Markdown
est un paragraphe à elle seule.

Le mot « production » désigne une installation réelle. Pour le mode d'exécution d'un binaire on
écrit « à l'exécution » ou « hors tests » : c'est l'emploi du même mot pour deux choses qui rendait
ces phrases indécidables.

CE QUE LA GARDE NE VOIT PAS — dit pour qu'on ne s'en réclame pas trop
----------------------------------------------------------------------
Un chiffre d'exploitation SANS forme reconnaissable lui échappe : « la base est grosse », un nombre
sans unité, une grandeur avec une unité qu'elle ne connaît pas, un relevé ni daté ni attribué. Les
FICHIERS DE DONNÉES (`.json`, `.jsonl`, `.csv`) ne sont pas lus : un profil distillé d'une
installation est un artefact d'exploitation par construction, et c'est une décision d'opérateur,
pas de garde, de le garder comme entrée de banc ou de le neutraliser. Les lignes déjà poussées
restent dans l'HISTORIQUE public : cette garde tient la version servie, elle ne réécrit pas le
passé. Enfin elle juge des FORMES : une relecture reste nécessaire, et c'est écrit dans `AGENTS.md`.

L'INSTRUMENT SE VALIDE AVANT DE RENDRE UN VERDICT
--------------------------------------------------
Une garde d'extraction rend vert de deux façons : parce que tout va bien, ou parce que son motif ne
reconnaît plus rien. Avant tout verdict elle exécute un corpus de contrôle dans les DEUX sens
(des lignes qu'on sait d'exploitation DOIVENT être vues ; un plafond de conception, un chiffre de
banc, un chiffre dans un fichier de test, une date de constat sans grandeur, une durée d'outil
datée NE DOIVENT PAS l'être), puis vérifie des PLANCHERS sur l'arbre réel (fichiers lus, grandeurs
reconnues, dates reconnues, attestations reconnues) : un dépouillement qui ne trouve plus rien
ÉCHOUE au lieu de se taire. Rendre la garde tautologique la fait REFUSER DE CONCLURE.
"""
import os
import re
import subprocess
import sys

# --- Corpus --------------------------------------------------------------------------------------

# Extensions binaires ou de DONNÉES : non lues (limite écrite dans l'en-tête).
EXT_EXCLUES = (".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".lock",
               ".json", ".jsonl", ".csv")

# Fichiers de banc ou de test PAR CONSTRUCTION : tout chiffre y est un chiffre de banc.
CHEMIN_BANC = re.compile(r"(^|/)(tests?|bench|benchmarks?)(/|$)|(^|/)tests?\.rs$|BENCHMARK", re.I)

# Fenêtre de contexte autour d'une ligne (un paragraphe de commentaire replié).
FENETRE = 2

# Planchers de non-dégénérescence. En dessous, c'est le dépouillement qui est cassé, pas l'arbre
# qui a maigri. Relevés sur l'arbre le 2026-08-22 : 630 fichiers lus, ~5 000 lignes à grandeur,
# ~750 lignes datées, ~2 500 lignes à attestation ou mot « production ».
MIN_FICHIERS = 300
MIN_GRANDEURS = 1000
MIN_DATES = 200
MIN_ATTESTATIONS = 40

# --- Formes reconnues ----------------------------------------------------------------------------

NOMBRE = r"[~≈<>≤≥+−-]?\s?\d(?:[\d  _]*\d)?(?:[,.]\d+)?"
UNITE_VOLUME_D = (r"Kio|Mio|Gio|Tio|Ko|Mo|Go|To|KiB|MiB|GiB|TiB|KB|MB|GB|TB|o\b|octets?|"
                  r"lignes?|rows?|événements?|evts?|events?|pages?|passes?|fois|balayages?|objets?")
# Les pas de machine virtuelle de SQLite ne comptent que sous attestation (R) : c'est la lecture d'un
# instrument, pas l'échelle d'une installation, et un pire cas extrapolé s'écrit avec la même unité.
UNITE_VOLUME = UNITE_VOLUME_D + r"|pas\s+de\s+machine|pas\b"
# Un multiplicateur et un « de » facultatifs : « 1,5 M de lignes », « 536 k lignes ».
MULT = r"(?:\s?[kKM]\s?)?(?:d'|de\s+)?"
UNITE_DUREE = r"µs|ms|ns|s\b|min\b|h\b|heures?|jours?|s/Gio|s/Mio"
# Ni pourcentage ni cœurs : un pourcentage est un RAPPORT — la forme que prend la connaissance une fois la
# valeur absolue retirée — et un nombre de cœurs décrit le profil de dimensionnement du produit.
# Ni collée à un mot par un tiret ni suivie d'une extension : « echelle-2go.md » est un nom de fichier.
GRANDEUR = re.compile(rf"(?<![\w.-])({NOMBRE})\s?(?:{MULT}(?:{UNITE_VOLUME})|(?:{UNITE_DUREE}))(?![\w]|\.\w)", re.I)
# Un volume À L'ÉCHELLE D'UNE INSTALLATION : des méga-octets ou plus, ou des milliers de lignes. Les
# petits comptes d'une expérience (« 4 événements », « 101 octets ») décrivent l'expérience, pas une cible.
UNITE_GROS_VOLUME = re.compile(r"^(Mio|Gio|Tio|Mo|Go|To|MiB|GiB|TiB|MB|GB|TB)$", re.I)
_VOLUME = re.compile(rf"(?<![\w.-])({NOMBRE})(\s?[kKM])?\s?(?:d'|de\s+)?({UNITE_VOLUME_D})(?![\w]|\.\w)", re.I)


# Une BORNE n'est pas un relevé : « budget de 2 Gio », « plafond 512 Mio », « tenir sous 2 Go ».
BORNE = re.compile(r"(budget|plafond|limite|borne|contrainte|quota|cgroup|tenir\s+sous|sous\s+(les|un|le)|"
                   r"au\s+plus|jusqu'[àa]|max\w*|cap\w*)(\s+\w+)?\s*(de\s+|des\s+|d')?\s*$", re.I)
BORNE_APRES = re.compile(r"^\s*(de\s+(budget|RAM|plafond)|[-–]safe|max)", re.I)


def hors_borne(ligne, m):
    """Vrai si la grandeur `m` n'est pas une BORNE (« budget de 2 Gio », « plafond 512 Mio »)."""
    return not (BORNE.search(ligne[max(0, m.start() - 40):m.start()])
                or BORNE_APRES.match(ligne[m.end():m.end() + 16]))


def grandeur_relevee(ligne):
    """La première grandeur de la ligne qui n'est pas une borne, ou None."""
    for m in GRANDEUR.finditer(ligne):
        if hors_borne(ligne, m):
            return m
    return None


def volume_d_installation(ligne):
    """Le premier volume À L'ÉCHELLE D'UNE INSTALLATION sur la ligne, ou None. Sont écartés : une
    BORNE (un budget n'est pas une mesure) et une PUISSANCE DE DEUX exacte (une base ne pèse jamais
    exactement 2^30 octets : c'est une constante de conception — un tampon, un facteur de travail)."""
    for m in _VOLUME.finditer(ligne):
        entier = re.sub(r"\D", "", m.group(1).split(",")[0].split(".")[0])
        if not (UNITE_GROS_VOLUME.match(m.group(3)) or m.group(2) or len(entier) >= 4):
            continue
        n = int(entier) if entier else 0
        if n >= 1024 and n & (n - 1) == 0:
            continue
        if not hors_borne(ligne, m):
            continue
        return m
    return None


# Un horodatage à la SECONDE : la signature d'un incident, pas d'une date de constat.
HORODATAGE = re.compile(r"\b20\d\d-[01]\d-[0-3]\d[T ][0-2]\d:[0-5]\d:[0-5]\d")
DATE = re.compile(r"\b20\d\d-[01]\d-[0-3]\d(?!\d)")

# (R) attestation d'une installation réelle — les formes ATTRIBUTIVES (« en production », « sur la
# production », « la production a mesuré »). L'adjectif seul (« la base de prod », « le profil de
# production ») désigne un RÔLE, pas un relevé, et n'atteste rien ; un « incident » n'atteste que s'il
# est celui d'une installation.
ATTESTATION = re.compile(
    r"\ben\s+(production|prod)\b|\b(sur|dans)\s+(la|une|cette)\s+(production|prod)\b|"
    r"\b(de\s+)?la\s+production\s*[(,]?\s*(a\b|la\b|le\b|les\b|l'|mesur|relev|observ|contredi|planifi|actuelle)|"
    r"\b(base|fichier|table|instance|d[ée]ploiement|pod|n[oœ]ud)\s+de\s+(production|prod)\b|"
    r"\bproduction\s*[(,]?\s*(mesur|relev|observ|actuelle)|\bprod,?\s+(mesur|relev)|"
    r"\ben\s+exploitation\b|\bsur\s+le\s+central\b|"
    r"\bl'instance\s+de\s+(production|r[ée]f[ée]rence)\b|\bincident\s+(vps|r[ée]el|de\s+prod)|"
    r"\b(base|installation|d[ée]ploiement|instance|pod|n[oœ]ud|machine|h[ôo]te)\s+r[ée]el(le)?s?\b", re.I)
# Un OBJET Kubernetes NOMMÉ : un service `<svc>.<ns>.svc` à deux étiquettes DNS concrètes (hors gabarit
# `<svc>.<ns>`), ou un pod portant le hash de son ReplicaSet (`<deploy>-<hash hex>-<5 car.>`).
SERVICE_K8S = re.compile(r"(?<![\w<.-])[a-z0-9][a-z0-9-]*\.[a-z0-9][a-z0-9-]*\.svc\b|"
                         r"(?<![\w<.-])[a-z][a-z0-9-]*-[0-9a-f]{8,10}-[a-z0-9]{5}(?![\w-])")

# Contexte déclaré : l'objet mesuré est le PRODUIT, pas une installation.
CONTEXTE_BANC = re.compile(
    r"\bbancs?\b|\bbench|\bsynth[ée]tique|\bharnais\b|\bfixture|\bt[ée]moin|\bVM\b|jeu\s+de\s+test|"
    r"\bprofil\s+de\s+banc|cargo\s+test|\bsimul|\bfabriqu|\bg[ée]n[ée]r[ée]s?\b|\bmaquette|"
    r"poste\s+de\s+(d[ée]veloppement|travail)|\bassert(_eq|_ne)?!|#\[(cfg\()?test\)?\]|base\s+de\s+test", re.I)
# ARBRE : l'objet mesuré est le dépôt, son binaire, sa CI — ou un calcul (une extrapolation, un pire
# cas) qui ne relève rien.
CONTEXTE_ARBRE = re.compile(
    r"sur\s+(l'|cet\s+)arbre|dans\s+le\s+d[ée]p[oô]t|fichiers?\s+suivis|capteurs?\s+livr|\bla\s+suite\b|"
    r"scripts?\s+suivis|tracked|sur\s+les\s+\w+\s+manifestes|\ben\s+[*_`]*release\b|\ben\s+[*_`]*debug\b|"
    r"\bbinaire\s+release\b|sur\s+le\s+binaire|\ben\s+CI\b|\bla\s+CI\b|"
    r"\bextrapol|\barithm[ée]tique|\bpire\s+cas\b", re.I)


def domaine_editeur(racine):
    """Le domaine de l'éditeur, DÉRIVÉ de l'identité canonique — pas écrit ici."""
    chemin = os.path.join(racine, ".github", "scripts", "verifier-identite.sh")
    with open(chemin, encoding="utf-8") as fh:
        m = re.search(r'CANONIQUE_MEL="[^"@]+@([^"]+)"', fh.read())
    if not m:
        raise RuntimeError("identité canonique introuvable dans verifier-identite.sh")
    return m.group(1).lower()


def motif_hote(domaine):
    """Un HÔTE sous le domaine de l'éditeur (`x.domaine`), jamais l'adresse de courriel elle-même."""
    return re.compile(r"(?<![\w@.-])[a-z0-9][a-z0-9-]*\." + re.escape(domaine) + r"(?![\w-])", re.I)


# Préfixe de commentaire ou de citation, retiré avant de joindre les lignes d'un paragraphe : une
# attestation repliée (« sur la\n//! production ») doit se lire d'un seul tenant.
PREFIXE = re.compile(r"^\s*(?:(?://[/!]?|#+|--|\*|>)\s?)+")


def sans_prefixe(ligne):
    return PREFIXE.sub("", ligne)


def paragraphe(lignes, i):
    """La fenêtre de contexte d'une ligne — (indice de début, lignes) : ±FENETRE lignes, sans
    franchir une ligne vide ni sortir d'une ligne de tableau Markdown (une ligne de tableau est un paragraphe à elle seule — sinon, dans
    un index d'une entrée par ligne, l'entrée voisine attesterait pour celle-ci)."""
    if lignes[i].lstrip().startswith("|"):
        return i, [lignes[i]]
    a = i
    while a > max(0, i - FENETRE) and lignes[a - 1].strip():
        a -= 1
    b = i
    while b < min(len(lignes) - 1, i + FENETRE) and lignes[b + 1].strip():
        b += 1
    return a, lignes[a: b + 1]


class Instrument:
    def __init__(self, domaine):
        self.domaine = domaine
        self.hote = motif_hote(domaine)

    def accuser(self, lignes, chemin=""):
        """Rend [(numéro, raison)] pour les lignes d'exploitation d'un fichier. Compte aussi ce
        qu'il a reconnu, pour les planchers."""
        banc_par_chemin = bool(CHEMIN_BANC.search(chemin))
        out = []
        stats = {"grandeurs": 0, "dates": 0, "attestations": 0}
        for i, ligne in enumerate(lignes):
            if GRANDEUR.search(ligne):
                stats["grandeurs"] += 1
            if DATE.search(ligne):
                stats["dates"] += 1
            if ATTESTATION.search(ligne):
                stats["attestations"] += 1

            nom = self.hote.search(ligne) or SERVICE_K8S.search(ligne)
            grandeur = grandeur_relevee(ligne)
            volume = volume_d_installation(ligne) or HORODATAGE.search(ligne)
            if not (nom or grandeur):
                continue

            debut, para = paragraphe(lignes, i)
            para = [sans_prefixe(l) for l in para]
            texte = "\n".join(para)
            # L'attestation vaut pour la ligne qui la porte et pour la ligne SUIVANTE (un relevé
            # replié : « … en production : 35 s\n pour 1 500 Mio ») — pas pour la ligne précédente, où
            # une constante de conception voisine n'a rien à voir avec le relevé qui suit.
            amont = "\n".join(para[max(0, i - 1 - debut): i - debut + 1])
            if nom:
                # Un objet d'infrastructure NOMMÉ reste un objet réel, même cité dans un test.
                out.append((i + 1, f"nom d'objet d'infrastructure réel `{nom.group(0)}`"))
            elif ATTESTATION.search(amont):
                # L'attestation EXPLICITE prime sur le chemin et sur un contexte de banc voisin : un
                # chiffre « relevé en production » cité dans un test ou à côté d'un banc reste un relevé.
                out.append((i + 1, f"grandeur `{grandeur.group(0).strip()}` attribuée à une "
                                   f"installation réelle"))
            elif (volume and DATE.search(texte) and not banc_par_chemin
                  and not CONTEXTE_BANC.search(texte) and not CONTEXTE_ARBRE.search(texte)):
                out.append((i + 1, f"volume `{volume.group(0).strip()}` daté, sans contexte de "
                                   f"banc ni d'arbre déclaré"))
        return out, stats


def valider_instrument(inst):
    """TÉMOIN POSITIF ET TÉMOIN NÉGATIF, sur un corpus de contrôle — avant tout verdict."""
    errs = []

    positifs = {
        "taille et débit attribués à l'installation":
            ["// parcours complet de la base : 35,4 s sur 1 586,8 Mio en production, soit 22,9 s/Gio"],
        "compteur d'un collecteur avec horodatage d'incident":
            ["//! le collecteur a échoué 9 364 fois depuis le 2026-08-06T06:11:42Z sans joindre sa cible"],
        "volume daté sans contexte déclaré":
            ["// relevé le 2026-08-09 : la table fait 1 554 295 lignes"],
        "attestation sur la ligne voisine (paragraphe replié)":
            ["// MESURÉ sur la production le 2026-08-05 : l'index de dédup",
             "// pèse 46,9 Mio pour une table de cette taille."],
        "hôte sous le domaine de l'éditeur":
            [f'endpoint = "https://soc.{inst.domaine}"'],
        "service Kubernetes nommé":
            ["# cible : plume-ingest.soc-prod.svc:7000"],
        "durée attribuée à une installation":
            ["/// la production la planifie en 10,1 ms"],
    }
    for nom, lignes in positifs.items():
        acc, _ = inst.accuser(lignes, "daemon/src/x.rs")
        if not acc:
            errs.append(f"témoin POSITIF « {nom} » en échec : ligne d'exploitation NON vue — "
                        f"le motif ne reconnaît plus la forme qu'il doit attraper.")

    negatifs = {
        "plafond de conception, sans date ni attestation":
            ["// le budget mémoire du démon est de 2 Gio, appliqué par le cgroup"],
        "borne citée à côté d'une attestation (un budget n'est pas un relevé)":
            ["// sur une base réelle le démon reste sous son budget de 2 Gio, et sous le plafond de 512 Mio du cache"],
        "chiffre de banc déclaré":
            ["// MESURÉ le 2026-08-01 sur la base de banc (1 440 007 événements) : 10,2 s"],
        "chiffre dans un fichier de test":
            (["// mesuré le 2026-08-09 : 5 730 304 o avant, 5 656 576 o après"], "daemon/src/tests/x.rs"),
        "date de constat sans grandeur":
            ["// le défaut a été constaté le 2026-08-10 ; la correction a suivi le jour même"],
        "durée d'outil datée, non attribuée":
            ["# CE QU'IL COÛTE, MESURÉ LE 2026-08-09 : ~2 s quand le cache est chaud"],
        "mesure sur l'arbre":
            ["# MESURÉ le 2026-08-20 sur l'arbre : 11 des 45 documents suivis, 3 929 lignes"],
        "nom de fichier qui ressemble à une grandeur":
            ["// voir `docs/DESIGN-P10-echelle-2go.md` §5.4 (relevé du 2026-08-09) et le profil mesuré"],
        "gabarit de service, pas un nom":
            ["# pousser au ClusterIP `<svc>.<ns>.svc:7000`"],
        "adresse de courriel de l'éditeur (pas un hôte)":
            [f"# identité : noreply@{inst.domaine}"],
        "ordre de grandeur de conception, attribué à aucune installation":
            ["// une table de plusieurs millions de lignes se parcourt en dizaines de secondes"],
    }
    for nom, spec in negatifs.items():
        lignes, chemin = (spec if isinstance(spec, tuple) else (spec, "daemon/src/x.rs"))
        acc, _ = inst.accuser(lignes, chemin)
        if acc:
            errs.append(f"témoin NÉGATIF « {nom} » en échec : accusé à tort ({acc[0][1]}) — "
                        f"la garde confond conception et exploitation.")
    return errs


def main():
    racine = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                            capture_output=True, text=True, check=True).stdout.strip()
    try:
        inst = Instrument(domaine_editeur(racine))
    except Exception as e:  # noqa: BLE001 — tout défaut d'instrument refuse de conclure
        print(f"::error::instrument non constructible : {e}")
        return 2

    errs = valider_instrument(inst)
    if errs:
        for e in errs:
            print(f"::error::{e}")
        print("\nl'INSTRUMENT est faux : aucun verdict n'est rendu (un vert l'aurait été pour de "
              "mauvaises raisons).")
        return 2

    suivis = subprocess.run(["git", "ls-files"], cwd=racine, capture_output=True, text=True,
                            check=True).stdout.split("\n")
    total = {"fichiers": 0, "grandeurs": 0, "dates": 0, "attestations": 0}
    accusations = []
    for f in suivis:
        if not f or f.lower().endswith(EXT_EXCLUES):
            continue
        chemin = os.path.join(racine, f)
        if not os.path.isfile(chemin):
            continue
        with open(chemin, "rb") as fh:
            brut = fh.read()
        if b"\0" in brut:
            continue  # binaire sans extension connue : hors corpus
        try:
            lignes = brut.decode("utf-8").split("\n")
        except UnicodeDecodeError:
            print(f"::error::{f} : non décodable en UTF-8 — le dépouillement est cassé, "
                  f"aucun verdict n'est rendu.")
            return 2
        total["fichiers"] += 1
        acc, stats = inst.accuser(lignes, f)
        for k, v in stats.items():
            total[k] += v
        accusations.extend((f, n, raison) for n, raison in acc)

    planchers = (("fichiers", MIN_FICHIERS), ("grandeurs", MIN_GRANDEURS), ("dates", MIN_DATES),
                 ("attestations", MIN_ATTESTATIONS))
    for cle, mini in planchers:
        if total[cle] < mini:
            print(f"::error::seulement {total[cle]} {cle} reconnu(e)s, plancher {mini} : les témoins "
                  f"passent mais l'arbre réel n'est plus reconnu — soit le dépouillement est cassé "
                  f"(cette garde ne vérifierait alors RIEN), soit l'arbre a vraiment changé de forme ; "
                  f"dans ce cas baissez le plancher depuis votre propre compte.")
            return 2

    if accusations:
        for f, n, raison in accusations:
            print(f"::error file={f},line={n}::{raison}")
        print(f"\n{len(accusations)} ligne(s) portent un chiffre ou un nom d'EXPLOITATION dans la "
              f"version servie (AGENTS.md §4). Gardez la CONNAISSANCE (la cause, l'ordre de grandeur de "
              f"conception, la date du constat), retirez ce qui identifie une installation (valeur "
              f"relevée, nom d'objet, horodatage d'incident) — ou DITES le contexte si c'est un banc.")
        return 1

    print(f"{total['fichiers']} fichiers lus, {total['grandeurs']} grandeurs, {total['dates']} dates, "
          f"{total['attestations']} attestations reconnues : aucun chiffre ni nom d'exploitation "
          f"dans la version servie.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
