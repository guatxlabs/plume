#!/usr/bin/env python3
"""L'ensemble fermé qu'un capteur déclare pour un champ qu'il émet reste DÉRIVABLE, ATTACHÉ, et de
PORTÉE DITE (`P11.19-a`, `P11.19-b`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
Un exploitant lit à l'écran des valeurs abrégées — `collection-reducing`, `subsystem-absent`,
`illisible` — qu'aucune surface n'explique. L'explication ne peut PAS être écrite à la main :
mesuré le 2026-08-26 sur cet arbre, ONZE fichiers livrés de la surface inventoriée écrivent
`fields.type`, avec CINQ espaces de valeurs DISJOINTS (réduction de collecte, disponibilité d'un
capteur, couverture de règles, genre d'hôte, genre de fichier) — une explication indexée par le NOM
du champ serait donc fausse pour dix producteurs sur onze. La clé minimale est le couple
(source, champ), et le seul lieu qui puisse la porter est le PRODUCTEUR lui-même.

Or le geste EXISTE déjà, et il n'est ni dérivable ni tenu de la même façon partout : cinq fichiers
livrés déclarent l'ensemble fermé de `fields.reason` — et ils déclarent TROIS ensembles différents
(six mots côté shell et PowerShell, cinq côté agent, deux côté collecteurs mail/syslog). Ce qui
manquait n'est donc pas la déclaration : c'est qu'elle soit un OBJET DE MACHINE, tenu au même
niveau d'exigence dans les cinq langages, avant qu'un jour le démon puisse la servir.

CE QUE LA GARDE TIENT — TROIS PROPRIÉTÉS, TOUTES DÉRIVÉES
----------------------------------------------------------
(1) DÉRIVABLE. La portée n'est pas listée : elle est l'ensemble des fichiers de `collectors/` et des
    caisses Rust de PRODUCTION du dépôt (toute racine portant un `Cargo.toml`, moins le démon, qui
    n'est pas un capteur — c'est le SECOND volet de `P11.19-a`, et il n'est pas tenu ici). Une
    déclaration se reconnaît à SA FORME dans le langage du producteur, jamais à son nom.
(2) LA PORTÉE DU CONTRÔLE EST DITE, ET ELLE EST DÉRIVÉE DE CE QUI EST LIVRÉ. C'est la propriété
    RÉÉCRITE le 2026-08-26, et l'ancienne était FAUSSE. Elle affirmait « un contrôle d'appartenance
    REFUSE le mot étranger » sur le seul critère de la présence, N'IMPORTE OÙ dans le fichier, de la
    sous-chaîne `NOM.contains(&x)`. MUTATION QUI LE PROUVE, quatre corpus : `.contains` dans un
    COMMENTAIRE -> tenu ; `.contains` seulement sous `#[cfg(test)]` -> tenu ; `debug_assert!` ->
    tenu ; `assert!` réel -> tenu. Les quatre rendaient le même verdict, donc le critère ne mesurait
    RIEN. Et la mesure du 2026-08-26 sur l'arbre réel : les SIX déclarations Rust sont tenues par
    `debug_assert!`, que `cargo build --release` EFFACE — les trois `[profile.release]` des caisses
    productrices ne posent pas `debug-assertions`. Le binaire LIVRÉ n'a aucun contrôle. La garde
    n'affirme donc plus « c'est tenu » : elle DÉRIVE la portée de chaque contrôle et la NOMME.
      · `livrée`        — le contrôle est dans l'artefact livré (`assert!`, ou un `if` dont le bloc
                          échoue ; en PowerShell, un `-notcontains` dont le bloc `throw`).
      · `développement` — le contrôle est sous `debug_assertions` et le profil de release de SA
                          caisse ne le garde pas. Dérivé du `Cargo.toml` de la caisse : si quelqu'un
                          y pose `debug-assertions = true` demain, la garde reclasse toute seule.
      · non concluante  — un contrôle existe mais son site d'échec ne se lit pas. REFUSÉ, pas ignoré.
(3) ATTACHÉE À UN CHAMP RÉELLEMENT ÉMIS. Un ensemble fermé qui ne borne aucune valeur écrite dans le
    sac `fields` n'explique rien. Le champ est DÉRIVÉ : on suit la variable que le contrôle
    d'appartenance borne jusqu'à la clé du sac qui la publie — au plus UN saut d'affectation, et
    cette borne est dite : une déclaration qu'il faudrait suivre plus loin est REFUSÉE, pas ignorée.

DEUX CLIQUETS, DISJOINTS, ET AUCUN NE SE RELÈVE
------------------------------------------------
· `PROSE_MAX` = 1. La forme shell (`# VOCABULAIRE FERMÉ de `champ` :` suivi des mots) est RECONNUE
  mais n'a aucun site d'échec : un script POSIX n'en offre pas de bon marché. Son nombre ne peut pas
  CROÎTRE. Ce plafond n'a pas bougé le 2026-08-26 : il mesurait le shell, il mesure toujours le
  shell, et la valeur est la même.
· `PORTEE_DEVELOPPEMENT_MAX` = 6. Cliquet NEUF, sur une grandeur que rien ne mesurait avant :
  les déclarations d'un langage qui OFFRE un site d'échec, mais dont le contrôle n'atteint pas
  l'artefact livré. Mesuré le 2026-08-26 : 6 (les deux tables de chacun des trois `lisibilite.rs`).
  Il est posé À la mesure du jour et ne peut que DESCENDRE. La dette qu'il compte est ASSUMÉE et
  porte sa propre clé OUVERTE, `P11.19-b` : la fermer demande de décider ce qu'un producteur FAIT
  d'un mot étranger en production (tomber ? le remplacer ? l'avouer dans un champ ?), et c'est une
  décision de produit dans les caisses Rust, pas dans cette garde.

L'INSTRUMENT SE VALIDE AVANT DE RENDRE UN VERDICT
--------------------------------------------------
Une garde d'extraction rend vert de deux façons : parce que tout va bien, ou parce que son motif ne
reconnaît plus rien. Avant tout verdict, celle-ci exécute un corpus de contrôle portant ses DEUX
témoins — des formes qu'elle DOIT reconnaître, avec LA PORTÉE ATTENDUE, dans les trois langages, et
des formes qu'elle NE DOIT PAS compter (un contrôle en commentaire, un contrôle qui ne vit que dans
la suite de tests, une table ouverte sans contrôle, un `@(...)` qui n'est pas un ensemble fermé, une
ligne de commentaire qui parle d'un vocabulaire sans le donner). La lecture du profil de release est
elle aussi témoignée dans les deux sens. Elle exige ensuite un PLANCHER par FORME sur l'arbre réel :
perdre une forme entière — un reformatage, une bascule de langage — la fait ÉCHOUER au lieu de la
faire taire.

CE QU'ELLE NE TIENT PAS, ET IL FAUT LE LIRE
--------------------------------------------
· Elle ne tient PAS que le contrôle S'EXÉCUTE : elle lit un texte, elle ne lance pas le producteur.
  Un contrôle `livrée` placé après l'écriture du sac serait compté comme un contrôle.
· Elle ne tient PAS que les déclarations d'un MÊME champ s'accordent entre producteurs : elles ne
  s'accordent pas, délibérément (l'agent exclut `disabled`, qui désigne un interrupteur d'opérateur
  qu'aucune de ses sources ne porte). C'est précisément pourquoi la clé est le couple.
· Elle ne tient PAS que chaque VALEUR porte son SENS. Le sens existe côté Rust (une ligne de
  documentation par constante) et nulle part ailleurs ; l'exiger partout demanderait d'écrire dans
  les producteurs, ce que ce lot ne fait pas.
· Elle ne lit du profil de release QUE la clé `debug-assertions` de la section `[profile.release]`
  du `Cargo.toml` le plus proche : un profil hérité d'un espace de travail, un `[profile.release.
  package.X]` ou un drapeau passé en ligne de commande lui échappent. Aucune de ces formes n'existe
  dans les caisses productrices au 2026-08-26 ; le jour où l'une apparaîtra, ce verdict la ratera.
· Elle ne tient RIEN sur l'arrivée à l'écran : aucune de ces déclarations n'atteint le fil. La route
  de schéma sert un objet de valeurs indexé par le NOM du champ, jamais par le couple. Tant que ce
  chemin n'existe pas, la console ne peut expliquer aucune de ces valeurs — et c'est ce qui reste
  OUVERT sous `P11.19-a`.
· Elle ne tient rien sur les clés que l'INGESTION estampille elle-même dans le sac (`fields.cim` est
  posé sur CHAQUE événement par le démon) : c'est le second volet de la clé, hors de cette garde.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_every_style_selector_has_a_target import (  # noqa: E402  (GESTES PARTAGÉS, source unique — `P11.8-m`, `P11.8-n`)
    hors_arbre, parcours_des_sources, racine_designee)

# ── LA RACINE EXAMINÉE — GESTE PARTAGÉ, PAS UNE QUATRIÈME COPIE (`P11.8-n`) ───────────────
# LE DÉFAUT QUE CECI FERME, MESURÉ LE 2026-08-31. Cette garde ACCEPTAIT un argument — lui passer une
# racine ne provoquait aucune plainte — et elle l'AVALAIT : sa racine venait de la POSITION DE CE
# FICHIER. Pointée sur un répertoire VIDE, elle rendait un verdict VERT sur le dépôt réel, sortie
# identique OCTET POUR OCTET à celle du dépôt réel. C'est la famille exacte que `P8.27-a` a déjà
# payée : un outil qui mesure un arbre que personne ne lui a désigné et présente son verdict comme
# portant sur celui qu'on lui montrait — son rouge accuse un innocent, et son vert, plus grave parce
# que silencieux, n'atteste rien. La validation (nombre d'arguments, racine inutilisable, refus code
# 2, message) n'est donc PAS réécrite ici : c'est celle de `racine_designee()`, importée.
#
# CE QUI RESTE PROPRE À CETTE GARDE, ET C'EST TOUT : LA RACINE RETENUE QUAND ON N'EN DÉSIGNE AUCUNE.
# Sans argument, `racine_designee()` retombe sur le `git rev-parse` du RÉPERTOIRE COURANT. Adopter
# cette retombée ICI serait une PERTE DE PORTÉE, mesurée le 2026-08-31 : jouée depuis un répertoire
# courant situé HORS de tout arbre git, la garde sœur du style REFUSE (code 2) sur un arbre SAIN,
# tandis que les trois gardes ralliées ici rendaient 0 — et `jouer-la-batterie-de-gardes.sh` lance
# chaque garde SANS se placer dans le dépôt (ligne 264). La racine par défaut reste donc celle-ci,
# calculée EXACTEMENT comme avant ce correctif, et elle est DÉSIGNÉE à la fonction partagée plutôt
# que devinée par elle : ce qui pouvait diverger (la validation) est unique, ce qui reste écrit ici
# (un défaut connu valide) ne peut pas mentir sur l'arbre mesuré.
DEPOT_DE_CETTE_GARDE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Renseignée par `main()` : une racine ne se devine pas à l'IMPORT — et ce module-ci EST importé
# (`check_operator_surface_is_documented.py` lui emprunte ses aides de lecture Rust), si bien que
# lire `sys.argv` à l'import ferait juger à cette garde l'argument d'une AUTRE.
RACINE = None

# ── PORTÉE, DÉRIVÉE ─────────────────────────────────────────────────────────────────────────────
# Un PRODUCTEUR est ce qui écrit un sac `fields` chez l'hôte : les capteurs de `collectors/` et les
# caisses Rust de production du dépôt. Le démon est exclu — il n'observe rien, il INGÈRE (son propre
# estampillage est le second volet de la clé). Rien n'est énuméré : une caisse ajoutée demain entre
# d'office, un capteur retiré sort d'office.
CAISSE_HORS_CAPTEUR = "daemon"

LIVREE, DEBUG, NON_CONCLUANTE, PROSE, DEVELOPPEMENT = (
    "livrée", "debug", "non concluante", "prose", "développement")


def racines_producteurs():
    """Les répertoires BALAYÉS : `collectors/`, plus le `src/` de chaque caisse Rust livrée.

    EXTRAIT de `fichiers_producteurs()` sous `P11.8-n` pour une seule raison : quand la population
    rendue est VIDE, la garde doit NOMMER ce qu'elle a cherché et où. Un refus qui ne dit pas ce qui
    manque oblige le lecteur à relire l'instrument pour savoir ce que l'instrument n'a pas trouvé."""
    racines = [os.path.join(RACINE, "collectors")]
    for nom in sorted(os.listdir(RACINE)):
        chemin = os.path.join(RACINE, nom)
        if nom == CAISSE_HORS_CAPTEUR or hors_arbre(nom) or not os.path.isdir(chemin):
            continue
        if os.path.isfile(os.path.join(chemin, "Cargo.toml")):
            racines.append(os.path.join(chemin, "src"))
    return racines


def fichiers_producteurs():
    """Tout fichier de production d'un producteur livré, hors suites de test.

    LA DÉCOUVERTE PART DE LA RACINE DU DÉPÔT, et l'élagage est le geste PARTAGÉ (`P11.8-m`), pas une
    liste écrite ici. Deux portes s'ouvraient : un répertoire de premier niveau portant un `Cargo.toml`
    n'était filtré QUE par ce manifeste (`vendor/`, `target/package/` en portent un), et le parcours de
    `collectors/` ne filtrait RIEN — un environnement virtuel ou un `node_modules` posé là gonflerait la
    population de milliers de `.py`, et AUCUN plancher ne rougirait : un plancher ne garde que la BAISSE."""
    out = []
    for base in racines_producteurs():
        for dossier, noms in parcours_des_sources(base):
            for n in noms:
                if n.endswith((".sh", ".ps1", ".rs", ".py")) and n != "tests.rs":
                    out.append(os.path.join(dossier, n))
    return out


# ── OÙ LE TEXTE EST DU CODE ─────────────────────────────────────────────────────────────────────
# Le critère fautif du 2026-08-26 cherchait une sous-chaîne n'importe où. Tout ce qui suit part donc
# de la seule question qui rende un verdict possible : ce caractère est-il du CODE, ou du commentaire,
# ou l'intérieur d'un littéral ? Deux masques de la longueur du texte, et tout le reste s'y appuie.
def _zones(texte, suffixe):
    """Rend (commentaire[], chaine[]) : deux masques booléens de la longueur du texte."""
    n = len(texte)
    com = [False] * n
    cha = [False] * n
    i = 0
    while i < n:
        c = texte[i]
        if suffixe == ".rs":
            if c == "/" and texte.startswith("//", i):
                j = texte.find("\n", i)
                j = n if j < 0 else j
                for k in range(i, j):
                    com[k] = True
                i = j
                continue
            if c == "/" and texte.startswith("/*", i):
                prof, j = 0, i
                while j < n:
                    if texte.startswith("/*", j):
                        prof += 1
                        j += 2
                    elif texte.startswith("*/", j):
                        prof -= 1
                        j += 2
                        if prof == 0:
                            break
                    else:
                        j += 1
                for k in range(i, min(j, n)):
                    com[k] = True
                i = j
                continue
            if c == "r" and re.match(r"r(#*)\"", texte[i:i + 8] or ""):
                m = re.match(r"r(#*)\"", texte[i:])
                diese = m.group(1)
                fin = texte.find('"' + diese, i + len(m.group(0)))
                fin = n if fin < 0 else fin + 1 + len(diese)
                for k in range(i, fin):
                    cha[k] = True
                i = fin
                continue
            if c == '"':
                j = i + 1
                while j < n:
                    if texte[j] == "\\":
                        j += 2
                        continue
                    if texte[j] == '"':
                        j += 1
                        break
                    j += 1
                for k in range(i, min(j, n)):
                    cha[k] = True
                i = j
                continue
            # `'` n'ouvre PAS un littéral en Rust : `&'static` est une durée de vie. Seul le
            # littéral de caractère qui porte un guillemet (`'"'`) pourrait tromper la suite.
            if c == "'" and texte[i:i + 3] == "'\"'":
                cha[i + 1] = True
                i += 3
                continue
            i += 1
            continue
        if suffixe == ".ps1":
            if texte.startswith("<#", i):
                j = texte.find("#>", i)
                j = n if j < 0 else j + 2
                for k in range(i, j):
                    com[k] = True
                i = j
                continue
            if c == "#":
                j = texte.find("\n", i)
                j = n if j < 0 else j
                for k in range(i, j):
                    com[k] = True
                i = j
                continue
            if c in "'\"":
                q = c
                j = i + 1
                while j < n:
                    if q == '"' and texte[j] == "`":
                        j += 2
                        continue
                    if texte[j] == q:
                        if j + 1 < n and texte[j + 1] == q:  # '' et "" = le guillemet lui-même
                            j += 2
                            continue
                        j += 1
                        break
                    j += 1
                for k in range(i, min(j, n)):
                    cha[k] = True
                i = j
                continue
            i += 1
            continue
        return [False] * n, [False] * n
    return com, cha


def _code(texte, com, cha):
    """Le texte où commentaires ET littéraux sont blanchis — les offsets sont préservés."""
    return "".join(" " if (com[i] or cha[i]) else c for i, c in enumerate(texte))


def _hors_commentaire(texte, com):
    """Le texte où seuls les commentaires sont blanchis (les littéraux restent lisibles)."""
    return "".join(" " if com[i] else c for i, c in enumerate(texte))


def _bloc(code, depart):
    """Le bloc `{...}` équilibré qui suit `depart` dans du CODE blanchi. Rend (debut, fin) ou None."""
    i = code.find("{", depart)
    if i < 0:
        return None
    prof = 0
    for j in range(i, len(code)):
        if code[j] == "{":
            prof += 1
        elif code[j] == "}":
            prof -= 1
            if prof == 0:
                return (i, j + 1)
    return None


def _spans_attribut(code, attribut):
    """Les intervalles couverts par un attribut Rust : l'item entier qui le suit."""
    spans = []
    for m in re.finditer(re.escape(attribut), code):
        suite = code[m.end():]
        pv = suite.find(";")
        ac = suite.find("{")
        if ac >= 0 and (pv < 0 or ac < pv):
            b = _bloc(code, m.end())
            if b:
                spans.append((m.start(), b[1]))
        elif pv >= 0:
            spans.append((m.start(), m.end() + pv + 1))
    return spans


def _dans(spans, i):
    return any(a <= i < b for a, b in spans)


# ── LES TROIS FORMES ────────────────────────────────────────────────────────────────────────────
# Rust : une table de mots + un contrôle d'appartenance dont la PORTÉE se lit.
RUST_TABLE = re.compile(r"pub const (\w+)\s*:\s*\[&(?:'static\s+)?str;\s*(\d+)\]\s*=\s*(\[[^\]]*\])\s*;", re.S)
RUST_CONST = re.compile(r"pub const (\w+)\s*:\s*&(?:'static\s+)?str\s*=\s*\"([^\"]*)\"\s*;")
# Un site d'échec : ce qui, atteint, empêche la valeur d'être émise.
RUST_ECHEC = re.compile(r"\b(return|panic!|unreachable!|todo!|unimplemented!|Err\s*\(|continue|break|process::exit)\b|Err\s*\(")
# PowerShell : une table `$script:X = @('a','b')` + `-notcontains` dont le bloc échoue.
PS_TABLE = re.compile(r"\$script:(\w+)\s*=\s*@\(([^)]*)\)")
PS_MOT = re.compile(r"'([^']*)'")
PS_ECHEC = re.compile(r"\bthrow\b|\bexit\b|-ErrorAction\s+Stop\b")
# Shell : la forme PROSE, reconnue mais sans site d'échec (cliquet).
SH_ANCRE = re.compile(r"^#\s*VOCABULAIRE FERMÉ de `(\w+)`[^\n]*:\s*$\n^#\s+(\S.*)$", re.M)
SH_SEP = re.compile(r"\s*[·|,]\s*")


def _mots_rust(bloc, consts):
    """Les mots d'une table Rust : littéraux ou constantes du même fichier."""
    mots = []
    for brut in re.split(r",", bloc.strip()[1:-1]):
        brut = brut.strip()
        if not brut:
            continue
        lit = re.fullmatch(r"\"([^\"]*)\"", brut)
        if lit:
            mots.append(lit.group(1))
        elif brut in consts:
            mots.append(consts[brut])
        else:
            mots.append(None)  # membre non résolu -> refusé plus bas
    return mots


def _portee_rust(code, nom, hors_portee, dev_spans):
    """La PORTÉE du contrôle d'appartenance sur `nom`, et la variable qu'il borne.

    On ne cherche plus une sous-chaîne : on lit le SITE. Le début de l'instruction est le dernier
    `;`, `{` ou `}` du code qui précède ; c'est sa tête qui dit ce que le contrôle fait quand il
    refuse. La portée la plus forte l'emporte — un `debug_assert!` ne retire rien à un `assert!`.
    """
    rang = {NON_CONCLUANTE: 0, DEBUG: 1, LIVREE: 2}
    meilleure, variable = None, None
    for m in re.finditer(re.escape(nom) + r"\.contains\(&(\w+)\)", code):
        if _dans(hors_portee, m.start()):
            continue  # ne vit que dans la suite de tests : le producteur livré ne le porte pas
        debut = max(code.rfind(c, 0, m.start()) for c in ";{}")
        tete = code[debut + 1:m.start()].strip()
        if re.match(r"^debug_assert(_eq|_ne)?!\s*\(", tete) or _dans(dev_spans, m.start()):
            p = DEBUG
        elif re.match(r"^assert(_eq|_ne)?!\s*\(", tete):
            p = LIVREE
        elif re.match(r"^(if|while)\b", tete):
            b = _bloc(code, m.end())
            p = LIVREE if (b and RUST_ECHEC.search(code[b[0]:b[1]])) else NON_CONCLUANTE
        else:
            p = NON_CONCLUANTE
        if meilleure is None or rang[p] > rang[meilleure]:
            meilleure, variable = p, m.group(1)
    return meilleure, variable


def _champ_ps(texte, bornees):
    """La clé du sac `fields` que borne un contrôle PowerShell — au plus UN saut d'affectation.

    Deux sites de publication existent dans le langage du producteur : la table littérale passée à
    `-Fields @{ champ=$V }` et l'écriture indexée `$fields['champ'] = $V`. La variable publiée est
    soit celle que borne le contrôle, soit celle qui en dérive en une affectation — au-delà, la
    garde REFUSE plutôt que de deviner.
    """
    vus = list(bornees)
    for var in list(bornees):
        for m in re.finditer(r"\$(\w+)\s*=\s*[^\n]*\$" + re.escape(var) + r"\b", texte):
            if m.group(1) not in vus:
                vus.append(m.group(1))
    # Le SAC, pas n'importe quelle table : seule une clé publiée dans `fields` est un champ émis.
    sacs = [m.group(1) for m in re.finditer(r"-Fields\s*@\{(.*?)\}", texte, re.S)]
    sacs += [m.group(1) for m in re.finditer(r"\$fields\s*=\s*@\{(.*?)\}", texte, re.S | re.I)]
    for var in vus:
        for sac in sacs:
            direct = re.search(r"(\w+)\s*=\s*\$" + re.escape(var) + r"\b", sac)
            if direct:
                return direct.group(1)
        indexe = re.search(r"\$fields\[['\"](\w+)['\"]\]\s*=\s*\$" + re.escape(var) + r"\b", texte, re.I)
        if indexe:
            return indexe.group(1)
    return None


def declarations(texte, suffixe):
    """Les ensembles fermés déclarés dans UN fichier. Rend (nom, champ, mots, portée, taille).

    La `portée` est celle du SITE, pas encore celle de l'ARTEFACT : `debug` devient `développement`
    ou `livrée` selon le profil de release de la caisse, ce que seul `main` peut savoir.
    """
    out = []
    if suffixe == ".rs":
        com, cha = _zones(texte, suffixe)
        code = _code(texte, com, cha)
        lisible = _hors_commentaire(texte, com)
        hors_portee = _spans_attribut(code, "#[cfg(test)]")
        dev_spans = _spans_attribut(code, "#[cfg(debug_assertions)]")
        consts = {m.group(1): m.group(2) for m in RUST_CONST.finditer(lisible)}
        for m in RUST_TABLE.finditer(lisible):
            if _dans(hors_portee, m.start()):
                continue
            nom, taille, bloc = m.group(1), int(m.group(2)), m.group(3)
            portee, var = _portee_rust(code, nom, hors_portee, dev_spans)
            if portee is None:
                continue  # aucun contrôle DANS LE CODE : ce n'est pas une déclaration tenue, c'est une table
            # ATTACHÉE : la variable bornée est publiée sous une clé du sac `fields`.
            champ = re.search(r"\"(\w+)\"\s*:\s*" + re.escape(var) + r"\s*[,}]", lisible) if var else None
            out.append((nom, champ.group(1) if champ else None, _mots_rust(bloc, consts), portee, taille))
    elif suffixe == ".ps1":
        com, cha = _zones(texte, suffixe)
        code = _code(texte, com, cha)
        lisible = _hors_commentaire(texte, com)
        for m in PS_TABLE.finditer(lisible):
            nom, bloc = m.group(1), m.group(2)
            # La borne s'arrête AVANT l'accolade : c'est ce bloc-là, et pas le suivant, qui dit ce
            # qui se passe quand le mot est étranger.
            borne = re.search(r"\$script:" + re.escape(nom) + r"\s+-notcontains\s+([^\n{]*)", code)
            if not borne:
                continue
            b = _bloc(code, borne.end())
            portee = LIVREE if (b and PS_ECHEC.search(lisible[b[0]:b[1]])) else NON_CONCLUANTE
            champ = _champ_ps(lisible, re.findall(r"\$(\w+)", borne.group(1)))
            mots = PS_MOT.findall(bloc)
            out.append((nom, champ, mots, portee, len(mots)))
    elif suffixe == ".sh":
        for m in SH_ANCRE.finditer(texte):
            mots = [w for w in SH_SEP.split(m.group(2).strip()) if w]
            out.append(("VOCABULAIRE " + m.group(1), m.group(1), mots, PROSE, len(mots)))
    return out


# ── CE QUE LE PROFIL DE RELEASE GARDE ───────────────────────────────────────────────────────────
def profil_release_tient_debug_assertions(cargo_toml):
    """`[profile.release]` de CE texte pose-t-il `debug-assertions = true` ?

    Fonction PURE : elle prend le texte, pas un chemin, pour être témoignée dans les deux sens sans
    écrire sur le disque. Sans la clé, cargo laisse `debug-assertions = false` en release, et
    `debug_assert!` disparaît du binaire.
    """
    m = re.search(r"^\[profile\.release\]\s*$", cargo_toml, re.M)
    if not m:
        return False
    suite = cargo_toml[m.end():]
    fin = re.search(r"^\[", suite, re.M)
    section = suite[:fin.start()] if fin else suite
    return bool(re.search(r"^\s*debug-assertions\s*=\s*true\b", section, re.M))


def _caisse_tient_debug_assertions(chemin):
    """Le `Cargo.toml` le plus proche EN REMONTANT — la caisse qui livre ce fichier."""
    d = os.path.dirname(os.path.abspath(chemin))
    while d.startswith(RACINE):
        c = os.path.join(d, "Cargo.toml")
        if os.path.isfile(c):
            try:
                return profil_release_tient_debug_assertions(open(c, encoding="utf-8", errors="replace").read())
            except OSError:
                return False
        if d == RACINE:
            break
        d = os.path.dirname(d)
    return False


# ── PLANCHERS ET PLAFONDS, MESURÉS LE 2026-08-26 SUR CET ARBRE ──────────────────────────────────
# Planchers PAR FORME : perdre une forme entière fait ÉCHOUER la garde au lieu de la faire taire.
PLANCHER_PAR_FORME = {".rs": 6, ".ps1": 2, ".sh": 1}
# CLIQUET 1 — INCHANGÉ le 2026-08-26 : la forme shell, qui n'a aucun site d'échec, ne peut croître.
PROSE_MAX = 1
# CLIQUET 2 — NEUF le 2026-08-26, sur une grandeur que rien ne mesurait : un contrôle écrit dans un
# langage QUI OFFRE un site d'échec, mais qui n'atteint pas l'artefact livré. Il est posé À la
# mesure du jour, il ne peut que DESCENDRE, et la dette qu'il compte porte sa clé OUVERTE
# `P11.19-b` — décider ce qu'un producteur fait d'un mot étranger EN PRODUCTION est une décision de
# produit dans les caisses Rust, pas un nombre à écrire ici.
PORTEE_DEVELOPPEMENT_MAX = 6


def temoins():
    """Corpus de contrôle : ce que la garde DOIT reconnaître, AVEC SA PORTÉE, et ce qu'elle NE DOIT
    PAS compter. Chaque discrimination neuve du 2026-08-26 y a son témoin dans les deux sens."""
    base = 'pub const A: &str = "un";\npub const B: &str = "deux";\npub const T: [&str; 2] = [A, B];\n'
    emis = 'let _ = json!({ "champ": mot, });'
    positifs = [
        (".rs", base + "fn f(){ assert!(T.contains(&mot)); " + emis + "}",
         [("T", "champ", ["un", "deux"], LIVREE)]),
        (".rs", base + "fn f(){ debug_assert!(T.contains(&mot)); " + emis + "}",
         [("T", "champ", ["un", "deux"], DEBUG)]),
        (".rs", base + "fn f(){ if !T.contains(&mot) { return None; } " + emis + "}",
         [("T", "champ", ["un", "deux"], LIVREE)]),
        # un `if` qui CONSTATE sans échouer n'est pas un contrôle : la garde refuse de conclure.
        (".rs", base + "fn f(){ if !T.contains(&mot) { log(\"bof\"); } " + emis + "}",
         [("T", "champ", ["un", "deux"], NON_CONCLUANTE)]),
        # `assert!` réel, mais sous `#[cfg(debug_assertions)]` : le site est de développement.
        (".rs", base + "#[cfg(debug_assertions)]\nfn v(){ assert!(T.contains(&mot)); }\nfn f(){ " + emis + "}",
         [("T", "champ", ["un", "deux"], DEBUG)]),
        (".ps1",
         "$script:T = @('un','deux')\nif ($script:T -notcontains $Mot) { throw 'hors' }\n"
         "Add-Event -Fields @{ champ=$Mot; autre=1 }",
         [("T", "champ", ["un", "deux"], LIVREE)]),
        # `-notcontains` dont le bloc n'échoue pas : reconnu, mais REFUSÉ, pas pris pour un contrôle.
        (".ps1",
         "$script:T = @('un','deux')\nif ($script:T -notcontains $Mot) { Write-Verbose 'bof' }\n"
         "Add-Event -Fields @{ champ=$Mot }",
         [("T", "champ", ["un", "deux"], NON_CONCLUANTE)]),
        (".sh",
         "# VOCABULAIRE FERMÉ de `champ` (requêtable) :\n#   un · deux\n",
         [("VOCABULAIRE champ", "champ", ["un", "deux"], PROSE)]),
    ]
    negatifs = [
        # table Rust SANS contrôle d'appartenance -> de la prose, pas une déclaration
        (".rs", 'pub const A: &str = "un";\npub const T: [&str; 1] = [A];\n'),
        # LE DÉFAUT MESURÉ LE 2026-08-26 : un contrôle qui n'est qu'un COMMENTAIRE
        (".rs", base + "fn f(){ // T.contains(&mot) serait bien\n " + emis + "}"),
        # LE DÉFAUT MESURÉ LE 2026-08-26 : un contrôle qui ne vit que dans la suite de tests
        (".rs", base + "fn f(){ " + emis + "}\n#[cfg(test)]\nmod tests { fn t(){ assert!(T.contains(&mot)); } }\n"),
        # un contrôle qui n'existe que dans un littéral (message d'erreur, requête, documentation)
        (".rs", base + 'fn f(){ let _ = "T.contains(&mot)"; ' + emis + "}"),
        # table PowerShell qui n'est pas un ensemble fermé (aucun -notcontains)
        (".ps1", "$script:T = @('un','deux')\nWrite-Output $script:T\n"),
        # LE DÉFAUT MESURÉ LE 2026-08-26 : un `-notcontains` qui n'est qu'un commentaire
        (".ps1", "$script:T = @('un','deux')\n# if ($script:T -notcontains $Mot) { throw 'hors' }\n"),
        # un commentaire qui PARLE d'un vocabulaire sans le donner
        (".sh", "# le vocabulaire fermé de `champ` est décrit ailleurs\n"),
    ]
    for suf, texte, attendu in positifs:
        vu = [(n, c, m, p) for (n, c, m, p, _) in declarations(texte, suf)]
        if vu != attendu:
            return f"témoin POSITIF {suf} non reconnu : {vu!r} ≠ {attendu!r}"
    for suf, texte in negatifs:
        vu = declarations(texte, suf)
        if vu:
            return f"témoin NÉGATIF {suf} compté à tort : {vu!r}"
    # La lecture du profil de release, dans les DEUX sens — c'est elle qui décide `développement`.
    profils = [
        ('[profile.release]\nopt-level = "z"\nlto = true\n', False),
        ('[profile.release]\ndebug-assertions = true\n', True),
        ('[profile.dev]\ndebug-assertions = true\n\n[profile.release]\nlto = true\n', False),
        ("", False),
    ]
    for texte, attendu in profils:
        if profil_release_tient_debug_assertions(texte) is not attendu:
            return f"témoin de PROFIL faux : {texte!r} devrait rendre {attendu}"
    return None


def main():
    global RACINE
    RACINE = racine_designee(sys.argv if len(sys.argv) > 1 else [sys.argv[0], DEPOT_DE_CETTE_GARDE])

    faute = temoins()
    if faute:
        print("INSTRUMENT INVALIDE — " + faute)
        return 2

    par_forme = {".rs": 0, ".ps1": 0, ".sh": 0}
    compte = {LIVREE: 0, DEVELOPPEMENT: 0, PROSE: 0}
    dette = []
    erreurs = []
    refus = []

    # ── UN CORPUS VIDE N'EST PAS UNE FAUTE DU DÉPÔT : C'EST UNE MESURE IMPOSSIBLE (`P11.8-n`) ──
    # MESURÉ LE 2026-08-31, ET PRÉEXISTANT. Privée des répertoires qu'elle balaie, cette garde rendait
    # UNE VIOLATION (code 1) : « FORME .rs : 0 déclaration(s) trouvée(s), plancher 6 ». Trois formes
    # d'amputation, trois fois le même code 1 — corpus entier retiré, `collectors/` seul, caisses Rust
    # seules. Or son propre texte disait déjà l'inverse (« rend la garde muette ») : le CODE accusait
    # un coupable pendant que le TEXTE avouait une cécité. C'est précisément la contradiction que
    # `jouer-la-batterie-de-gardes.sh` traque (`texte_refuse`, ligne 126), et elle lui échappait faute
    # du mot exact. Un exploitant lisait « le dépôt a perdu ses déclarations » là où il fallait lire
    # « je n'ai rien à mesurer » — deux causes opposées derrière un seul rouge.
    corpus = fichiers_producteurs()
    if not [c for c in corpus if os.path.splitext(c)[1] in par_forme]:
        balayees = racines_producteurs()
        nommer = lambda ds: ", ".join(os.path.relpath(d, RACINE) for d in ds) or "aucun"
        print("CORPUS VIDE — la garde REFUSE DE CONCLURE ; elle n'accuse pas.\n"
              "  Racine examinée      : {}\n"
              "  Répertoires balayés  : {}\n"
              "  ABSENTS du disque    : {}\n"
              "  Aucun fichier `.rs`, `.ps1` ni `.sh` de producteur n'y a été trouvé. Un corpus vide "
              "n'explique RIEN sur les ensembles fermés de ce dépôt : rendre 1 ici désignerait un "
              "coupable à la place d'un instrument privé de ce qu'il mesure.".format(
                  RACINE, nommer(balayees), nommer([b for b in balayees if not os.path.isdir(b)])))
        return 2

    for chemin in corpus:
        suf = os.path.splitext(chemin)[1]
        if suf not in par_forme:
            continue
        try:
            texte = open(chemin, encoding="utf-8", errors="replace").read()
        except OSError as e:
            erreurs.append(f"{chemin} : illisible ({e})")
            continue
        rel = os.path.relpath(chemin, RACINE)
        for nom, champ, mots, portee, taille in declarations(texte, suf):
            par_forme[suf] += 1
            ou = f"{rel} : `{nom}`"
            # LA PORTÉE DU SITE DEVIENT CELLE DE L'ARTEFACT — dérivée du profil de la caisse.
            if portee == DEBUG:
                portee = LIVREE if _caisse_tient_debug_assertions(chemin) else DEVELOPPEMENT
            if portee == NON_CONCLUANTE:
                erreurs.append(
                    f"{ou} — CONTRÔLE NON CONCLUANT : un contrôle d'appartenance existe, mais rien "
                    f"n'échoue quand il refuse. La garde ne devine pas ce que devient le mot "
                    f"étranger ; écrivez le site d'échec, ou retirez le contrôle.")
            elif portee == DEVELOPPEMENT:
                dette.append(ou)
            if portee in compte:
                compte[portee] += 1
            if not mots:
                erreurs.append(f"{ou} — ensemble fermé VIDE : il n'explique aucune valeur.")
                continue
            if any(m is None for m in mots):
                erreurs.append(f"{ou} — un membre n'est pas résolvable en mot : la table n'est pas dérivable.")
            reels = [m for m in mots if m is not None]
            if len(reels) != taille:
                erreurs.append(f"{ou} — {len(reels)} mot(s) pour une taille déclarée de {taille}.")
            if len(set(reels)) != len(reels):
                erreurs.append(f"{ou} — mot en double : un ensemble fermé ne compte pas deux fois la même valeur.")
            proses = [m for m in reels if (not m) or re.search(r"\s", m)]
            if proses:
                erreurs.append(f"{ou} — membre(s) en prose {proses!r} : une valeur requêtable ne porte pas d'espace.")
            if champ is None:
                erreurs.append(
                    f"{ou} — ATTACHÉ À RIEN : le contrôle d'appartenance ne se suit pas jusqu'à une "
                    f"clé du sac `fields`. Un ensemble fermé qui ne borne aucun champ ÉMIS n'explique rien.")

    # LE MÊME CANAL QUE CI-DESSUS, POUR LA MÊME RAISON (`P11.8-n`). Un plancher de non-dégénérescence
    # ne dit JAMAIS qu'une déclaration est fautive : il dit qu'une forme entière a disparu du champ de
    # l'instrument, donc que l'ensemble des accusations rendues est lui-même incomplet. Le plancher et
    # sa date sont INCHANGÉS (mesurés le 2026-08-26) ; seul le canal change, et il rejoint celui que
    # ce texte réclamait déjà. Les vraies fautes — non dérivable, attaché à rien, prose, doublon,
    # taille — et les deux cliquets restent en code 1 : eux portent sur un corpus que l'on a bien lu.
    for suf, plancher in PLANCHER_PAR_FORME.items():
        if par_forme[suf] < plancher:
            refus.append(
                f"FORME {suf} : {par_forme[suf]} déclaration(s) trouvée(s), plancher {plancher} "
                f"(mesuré le 2026-08-26). Une forme perdue rend la garde muette — elle REFUSE DE "
                f"CONCLURE plutôt.")
    if compte[PROSE] > PROSE_MAX:
        erreurs.append(
            f"CLIQUET : {compte[PROSE]} déclaration(s) en PROSE (aucun site d'échec dans le langage) "
            f"pour un plafond de {PROSE_MAX} (mesuré le 2026-08-26). Un ensemble fermé neuf se TIENT, "
            f"il ne s'écrit pas en commentaire.")
    if compte[DEVELOPPEMENT] > PORTEE_DEVELOPPEMENT_MAX:
        erreurs.append(
            f"CLIQUET : {compte[DEVELOPPEMENT]} contrôle(s) de portée DÉVELOPPEMENT pour un plafond de "
            f"{PORTEE_DEVELOPPEMENT_MAX} (mesuré le 2026-08-26, dette assumée sous `P11.19-b`). Ce "
            f"plafond ne DESCEND que : un contrôle neuf s'écrit dans l'artefact LIVRÉ, il ne s'ajoute "
            f"pas à ce qui s'efface au build de release.")

    if refus:
        print("La garde REFUSE DE CONCLURE — sa mesure est dégénérée, et ce n'est pas un verdict "
              "sur le dépôt :\n")
        for r in refus:
            print("  · " + r)
        print("\nCe qui suit N'EST PAS rendu : une forme perdue rend incomplète la liste des fautes "
              "elle-même, donc aucune accusation n'est publiée sur ce corpus-là.")
        return 2

    if erreurs:
        print("Un ensemble fermé déclaré par un capteur n'est plus dérivable, attaché, ou de portée lisible :\n")
        for e in erreurs:
            print("  · " + e)
        print("\nCe que cette garde NE tient PAS : que le contrôle s'EXÉCUTE (elle lit un texte) ; que "
              "deux producteurs d'un même champ s'accordent (ils ne s'accordent pas, et c'est pourquoi "
              "la clé est le couple source+champ) ; que chaque valeur porte son sens ; que ces "
              "déclarations atteignent l'écran — aucune ne l'atteint aujourd'hui (`P11.19-a`).")
        return 1
    print(
        "OK — {} ensemble(s) fermé(s) déclaré(s) par les producteurs livrés (Rust {}, PowerShell {}, "
        "shell {}), tous dérivables et attachés à un champ émis.\nPORTÉE DES CONTRÔLES, DÉRIVÉE DE CE "
        "QUI EST LIVRÉ : {} tenu(s) dans l'artefact livré ; {} tenu(s) SEULEMENT EN DÉVELOPPEMENT "
        "(plafond {}, `P11.19-b` OUVERTE — le binaire de release n'a AUCUN contrôle sur ces "
        "valeurs-là) ; {} en PROSE, sans aucun site d'échec (plafond {}).{}\nNON TENU ici : que le "
        "contrôle s'exécute, l'accord entre producteurs, le sens de chaque valeur, et l'arrivée à "
        "l'écran (aucune déclaration n'atteint le fil — `P11.19-a`).".format(
            sum(par_forme.values()), par_forme[".rs"], par_forme[".ps1"], par_forme[".sh"],
            compte[LIVREE], compte[DEVELOPPEMENT], PORTEE_DEVELOPPEMENT_MAX,
            compte[PROSE], PROSE_MAX,
            ("\n  DETTE NOMMÉE, PAS TUE : " + " · ".join(dette)) if dette else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
