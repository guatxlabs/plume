#!/usr/bin/env python3
"""Un déploiement n'ARME jamais une tâche dont une précondition n'est pas satisfaite CHEZ LUI — garde de CI (`P9.4-b`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
Mesuré sur les sources le 2026-08-25, bout à bout :
  * `backup_compressed` REFUSE dès sa première instruction quand la clé de base est vide, et son
    refus NOMME la clé requise (`PLUME_DB_KEY`) ;
  * l'ordonnanceur natif appelle exactement ce chemin, et il est GATÉ sur `PLUME_BACKUP_INTERVAL`
    (0 = aucun thread) ;
  * `docker-compose.yml` et `deploy/k3s.yaml` posent tous deux cet intervalle à 21600 — donc ARMENT
    l'ordonnanceur — en livrant `PLUME_DB_KEY` VIDE.
Conséquence : toutes les 6 h, un cycle part, échoue, et AUCUNE archive n'est jamais écrite. La
rétention KEEP-N était annoncée en toutes lettres à côté (« 24 × 6 h ≈ 6 jours ») : un exploitant qui
lit ces manifestes croit disposer de plusieurs jours d'archives et n'en a aucune.

Le défaut n'est PAS dans le démon, qui refuse correctement et le dit. Il est dans la CONJONCTION,
écrite dans un seul fichier : armer une tâche + ne pas lui donner de quoi aboutir. C'est cette
conjonction que la garde interdit — et elle est vérifiable sans exécuter quoi que ce soit.

LA RÈGLE, ÉCRITE COMME UNE PROPRIÉTÉ
------------------------------------
    Si un déploiement pose une variable qui ARME une tâche du démon, alors, DANS LE MÊME FICHIER,
    toute variable dont cette tâche a besoin pour aboutir doit être LIVRÉE au conteneur avec une
    valeur NON VIDE.

RIEN N'EST ÉNUMÉRÉ — NI D'UN CÔTÉ NI DE L'AUTRE. C'est le point : une garde qui porterait une liste
de noms de variables écrite à la main laisserait passer la PROCHAINE tâche, et le dépôt s'est déjà
fait mordre par une garde bornée à un emplacement plutôt qu'à une propriété (`P11.13-d`).
  1. LES TÂCHES ARMÉES sont dérivées de la FORME DU GATE dans le démon : une variable `PLUME_*` lue
     avec « 0 » pour défaut, dont la valeur 0 provoque un `return` immédiat. C'est ce que le démon
     appelle « intervalle 0 -> aucun thread -> byte-identique ».
  2. LES PRÉCONDITIONS sont dérivées des REFUS que la tâche armée peut atteindre : point fixe des
     appels de fonctions LIBRES depuis l'entrée armée, puis, dans cet ensemble, les refus dont
     l'unique condition est qu'une valeur soit VIDE, et dont le message NOMME une variable `PLUME_*`.
     Un refus CONDITIONNÉ à autre chose (un drapeau opt-in : `PLUME_BACKUP_REQUIRE_ASYMMETRIC`) n'est
     PAS une précondition — il ne mord que si l'exploitant l'a demandé, et l'exiger de tout le monde
     rendrait la garde bruyante puis désarmée.
  3. LES ÉQUIVALENCES entre variables sont dérivées des TABLEAUX DE CONSTANTES du démon : quand il
     écrit `CLES_AT_REST = [CLE_DB_KEY_FILE, CLE_DB_KEY]`, il dit que ces deux noms se substituent
     l'un à l'autre. Un déploiement qui monte un fichier de clé satisfait donc la précondition.
  4. LES DÉPLOIEMENTS sont dérivés eux aussi : tout fichier YAML du dépôt qui ARME une des tâches
     ci-dessus. Un manifeste écrit demain entre dans la population sans être nommé ici.

CE QUE CETTE GARDE NE PROUVE PAS, ET C'EST ÉCRIT PLUTÔT QUE SOUS-ENTENDU
------------------------------------------------------------------------
  * Qu'une valeur non vide soit une valeur JUSTE : une passphrase par défaut partagée par toutes les
    installations passerait ici. C'est une autre propriété, tenue ailleurs
    (`allegations_d_environnement` refuse une clé SQLCipher non vide LIVRÉE dans `deploy/k3s.yaml`).
  * Que la tâche aboutisse : un disque plein, une destination illisible, une clé FAUSSE restent des
    échecs d'exécution. Ceux-là sont dits à l'exécution par le signal de posture non purgeable
    « aucune archive publiée » (`P9.4-b`, `emit_backup_cycle_failed_signal`) — la garde statique et
    le signal d'exécution ferment deux moitiés différentes.
  * Ce qu'un `.env` d'exploitant fournit : la garde juge ce que le dépôt LIVRE, c'est-à-dire la
    valeur par DÉFAUT d'une substitution `${VAR:-…}`. C'est le bon niveau : un manifeste qui ne
    fonctionne qu'avec un fichier non livré doit le dire, pas le supposer.

L'INSTRUMENT SE VALIDE AVANT DE RENDRE UN VERDICT
-------------------------------------------------
Chaque lecture (gate, refus, manifeste, équivalence) est exercée DANS LES DEUX SENS sur un corpus de
contrôle : des formes qu'elle DOIT voir, et des formes qu'elle NE DOIT PAS voir — dont, à chaque
fois, la même écrite en COMMENTAIRE. Puis des PLANCHERS sur l'arbre réel : sous eux, la dérivation
est cassée et la garde REFUSE DE CONCLURE (sortie 2) au lieu de rendre vert en étant aveugle.
Sortie 0 = rien trouvé, 1 = une conjonction interdite, 2 = je refuse de conclure.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_every_style_selector_has_a_target import (  # noqa: E402  (ÉLAGAGE PARTAGÉ, source unique — `P11.8-m`)
    parcours_des_sources)

RACINE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC = os.path.join(RACINE, "daemon", "src")
ETIQUETTE = "P9.4-b"

# --- PLANCHERS DE NON-DÉGÉNÉRESCENCE ------------------------------------------------------------
# Deux tâches armées sont connues : l'ordonnanceur de sauvegarde et l'auto-vacuum incrémental.
MIN_TACHES_ARMEES = 2
# Une précondition au moins doit être dérivée quelque part : sinon la lecture des refus est morte.
MIN_PRECONDITIONS = 1
# Une classe d'équivalence au moins : `CLES_AT_REST` en est une.
MIN_EQUIVALENCES = 1
# Un déploiement au moins doit ARMER : sinon la découverte des manifestes est morte.
MIN_DEPLOIEMENTS = 1

CLE = r"PLUME_[A-Z0-9_]+"


def echec(msg):
    print(f"::error::[{ETIQUETTE}] {msg}")
    sys.exit(1)


def refuse(msg):
    print(f"::error::[{ETIQUETTE}] {msg}")
    sys.exit(2)


# ================================================================================================
# LECTURES — chacune est une fonction PURE sur du texte, pour être exerçable dans les deux sens.
# ================================================================================================

def sans_commentaire_rust(ligne):
    """Retire un `//` de fin de ligne hors chaîne. Une directive commentée n'est pas une directive."""
    hors, echap, i = True, False, 0
    while i < len(ligne):
        c = ligne[i]
        if echap:
            echap = False
        elif c == "\\":
            echap = True
        elif c == '"':
            hors = not hors
        elif hors and c == "/" and i + 1 < len(ligne) and ligne[i + 1] == "/":
            return ligne[:i]
        i += 1
    return ligne


def sans_commentaire_yaml(ligne):
    """Retire un `#` de fin de ligne hors chaîne (guillemets simples ou doubles)."""
    quote, i = None, 0
    while i < len(ligne):
        c = ligne[i]
        if quote:
            if c == quote:
                quote = None
        elif c in "\"'":
            quote = c
        elif c == "#":
            return ligne[:i]
        i += 1
    return ligne


def unites_rust(src):
    """Les unités d'indentation 0 d'un fichier de production : (nom, corps sans sa ligne d'en-tête).
    Même découpe que la garde dérivée de `posture_de_sauvegarde_native.rs` — une règle de lecture
    écrite deux fois finirait par diverger, celle-ci est donc la MÊME."""
    out = []
    for l in src.splitlines():
        t = l.lstrip()
        entete = len(l) == len(t) and any(
            t.startswith(p) for p in ("fn ", "pub fn ", "pub(crate) fn ", "async fn ", "pub(crate) async fn "))
        if entete:
            nom = re.match(r"\w+", t[t.index("fn ") + 3:])
            out.append([nom.group(0) if nom else "", ""])
        elif out:
            out[-1][1] += l + "\n"
    return [(n, c) for n, c in out if n]


APPEL_LIBRE = re.compile(r"(?<![\w.])([A-Za-z_]\w*)\s*\(")


def appelle(corps, nom):
    """APPEL de la fonction LIBRE `nom` : borne de mot à gauche, et pas un appel de MÉTHODE
    (`next.run(` ferait entrer `run` — et tout ce qui l'appelle — dans le point fixe)."""
    return nom in appels_du_corps(corps)


def appels_du_corps(corps, noms=None):
    """TOUS les appels de fonctions LIBRES d'un corps, en UNE passe (commentaires retirés). Le graphe
    d'appel est ainsi construit une fois pour toutes : le calculer par recherche de sous-chaîne à
    chaque itération du point fixe rend la garde inutilisable, donc contournée."""
    code = "\n".join(sans_commentaire_rust(l) for l in corps.splitlines())
    vus = {m.group(1) for m in APPEL_LIBRE.finditer(code)}
    return vus & noms if noms is not None else vus


GATE_LECTURE = re.compile(r"let\s+(\w+)\s*(?::[^=]+)?=\s*cfg\([^,]+,\s*\"(" + CLE + r")\"\s*,\s*\"0\"\s*\)")


def gates_du_corps(corps):
    """LA FORME DU GATE : une variable lue par `cfg(…, "PLUME_X", "0")` dont la valeur 0 provoque un
    `return` immédiat. Rend les clés d'ARMEMENT trouvées dans ce corps."""
    lignes = [sans_commentaire_rust(l) for l in corps.splitlines()]
    trouves = []
    for i, l in enumerate(lignes):
        m = GATE_LECTURE.search(l)
        if not m:
            continue
        var, cle = m.group(1), m.group(2)
        sortie = re.compile(r"\bif\s+" + re.escape(var) + r"\s*==\s*0\s*\{\s*return\b")
        if any(sortie.search(x) for x in lignes[i:i + 6]):
            trouves.append(cle)
    return trouves


# Deux formes de REFUS dont l'unique condition est qu'une valeur soit VIDE. La chaîne du refus est
# capturée sur la MÊME ligne ou les suivantes (continuations `\` d'un littéral Rust).
REFUS_OPTION = re.compile(
    r"Some\(\s*(\w+)\s*\)\s+if\s+!\s*\1\s*\.is_empty\(\)\s*=>.*?\n\s*_\s*=>\s*return\s+Err\(", re.S)
REFUS_SI_VIDE = re.compile(r"\bif\s+([^\n{&|]*?\.is_empty\(\))\s*\{[^{}]*?return\s+Err\(", re.S)


def preconditions_du_corps(corps):
    """Les clés `PLUME_*` NOMMÉES par un refus dont l'unique condition est une valeur VIDE."""
    code = "\n".join(sans_commentaire_rust(l) for l in corps.splitlines())
    cles = set()
    for rx in (REFUS_OPTION, REFUS_SI_VIDE):
        for m in rx.finditer(code):
            # le message du refus : ce qui suit `Err(` jusqu'à la fin du littéral (continuations incluses)
            reste = code[m.end():m.end() + 600]
            fin = reste.find('".')
            message = reste[: fin if fin != -1 else 400]
            cles.update(re.findall(CLE, message))
    return cles


AFFECT_YAML = re.compile(r"^\s*-?\s*\{?\s*(?:name:\s*)?(" + CLE + r")\s*[:,]\s*(?:value:\s*)?(.*)$")
SUBSTITUTION = re.compile(r"^\$\{" + CLE + r"(?::-(.*))?\}$")


def valeur_effective(brut):
    """La valeur que le dépôt LIVRE : littéral, ou le DÉFAUT d'une substitution `${VAR:-defaut}`
    (une substitution sans défaut livre du vide)."""
    v = brut.strip().rstrip("}").strip().rstrip(",").strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1]
    m = SUBSTITUTION.match(v)
    if m:
        return (m.group(1) or "").strip()
    return v


def affectations_du_manifeste(texte):
    """(livrées, toutes) : les clés `PLUME_*` du fichier avec leur valeur effective. « livrée » =
    posée là où le CONTENEUR la reçoit (mapping `environment:` de compose, entrée `env:` de k8s) ;
    « toutes » inclut les valeurs qui ne font que RÉSIDER dans le fichier (`stringData` d'un Secret,
    qui n'atteint un conteneur que par un montage ou un `valueFrom` explicite)."""
    livrees, toutes = {}, {}
    porteur = None          # dernier en-tête de bloc rencontré
    for brut in texte.splitlines():
        l = sans_commentaire_yaml(brut)
        nu = l.strip()
        if nu.endswith(":") and not nu.startswith("-"):
            porteur = nu[:-1].strip()
        m = AFFECT_YAML.match(l)
        if not m:
            continue
        cle, v = m.group(1), valeur_effective(m.group(2))
        toutes[cle] = v
        # une entrée `- { name: X, value: … }` ou `- name: X` EST une entrée d'environnement k8s ;
        # sinon c'est le mapping du porteur qui décide.
        entree_k8s = nu.startswith("-") or "name:" in l
        if entree_k8s or porteur in ("environment", "env"):
            livrees[cle] = v
    return livrees, toutes


CONST_STR = re.compile(r"const\s+(\w+)\s*:\s*&\s*str\s*=\s*\"(" + CLE + r")\"")
CONST_TAB = re.compile(r"const\s+(\w+)\s*:\s*\[\s*&\s*str\s*;\s*\d+\s*\]\s*=\s*\[([^\]]*)\]", re.S)


def equivalences(code):
    """Les classes de variables INTERCHANGEABLES, dérivées des tableaux de constantes du démon :
    `CLES_AT_REST = [CLE_DB_KEY_FILE, CLE_DB_KEY]` dit que ces deux noms se substituent l'un à
    l'autre. Rend une liste d'ensembles de clés `PLUME_*`."""
    noms = {i: c for i, c in CONST_STR.findall(code)}
    classes = []
    for _, membres in CONST_TAB.findall(code):
        cles = {noms[x.strip()] for x in membres.split(",") if x.strip() in noms}
        if len(cles) >= 2:
            classes.append(cles)
    return classes


# ================================================================================================
# TÉMOINS — chaque lecture dans les DEUX sens, avant tout verdict sur l'arbre.
# ================================================================================================

def temoins_des_lectures():
    # --- le GATE ---------------------------------------------------------------------------------
    arme = '    let interval: u64 = cfg(&conf, "PLUME_BACKUP_INTERVAL", "0").parse().unwrap_or(0);\n' \
           '    if interval == 0 { return; }\n'
    sans_sortie = '    let n: u64 = cfg(&conf, "PLUME_ROLLUP_INTERVAL", "0").parse().unwrap_or(0);\n' \
                  '    eprintln!("{n}");\n'
    autre_defaut = '    let f = cfg(&conf, "PLUME_FTS_FIELDS", "1");\n    if f == 0 { return; }\n'
    en_commentaire = '    // let interval: u64 = cfg(&conf, "PLUME_X_INTERVAL", "0").parse().unwrap_or(0);\n' \
                     '    // if interval == 0 { return; }\n'
    assert gates_du_corps(arme) == ["PLUME_BACKUP_INTERVAL"], "témoin : la forme du gate n'est pas vue"
    assert gates_du_corps(sans_sortie) == [], "témoin INVERSE : une lecture SANS sortie anticipée n'arme rien"
    assert gates_du_corps(autre_defaut) == [], "témoin INVERSE : un réglage dont le défaut n'est pas « 0 » n'est pas un gate d'armement"
    assert gates_du_corps(en_commentaire) == [], "témoin INVERSE : un gate écrit en COMMENTAIRE n'arme rien"

    # --- le REFUS --------------------------------------------------------------------------------
    vide_seul = '    let pass = match key {\n' \
                '        Some(k) if !k.is_empty() => k.to_string(),\n' \
                '        _ => return Err("backup --compress : PLUME_DB_KEY requis (passphrase age)".into()),\n' \
                '    };\n'
    vide_seul_si = '    if dest.is_empty() {\n        return Err("PLUME_BACKUP_DEST requis".into());\n    }\n'
    conditionnel = '    let symmetric = recipient.map_or(true, |r| r.is_empty());\n' \
                   '    if symmetric && backup_require_asymmetric() {\n' \
                   '        return Err("backup REFUSÉ : aucun PLUME_BACKUP_AGE_RECIPIENT configuré".into());\n    }\n'
    refus_commente = '    // _ => return Err("PLUME_DB_KEY requis".into()),\n'
    assert preconditions_du_corps(vide_seul) == {"PLUME_DB_KEY"}, "témoin : le refus sur valeur vide n'est pas lu"
    assert preconditions_du_corps(vide_seul_si) == {"PLUME_BACKUP_DEST"}, "témoin : la forme `if …is_empty() { return Err }` n'est pas lue"
    assert preconditions_du_corps(conditionnel) == set(), \
        "témoin INVERSE : un refus CONDITIONNÉ à un drapeau opt-in n'est pas une précondition"
    assert preconditions_du_corps(refus_commente) == set(), "témoin INVERSE : un refus en COMMENTAIRE ne conditionne rien"

    # --- l'APPEL ---------------------------------------------------------------------------------
    assert appelle("    scheduled_backup_cycle(a, b);", "scheduled_backup_cycle"), "témoin : un appel libre n'est pas vu"
    assert not appelle("    next.run(req).await", "run"), "témoin INVERSE : un appel de MÉTHODE n'est pas un appel libre"
    assert not appelle("    // backup_compressed(a, b)", "backup_compressed"), "témoin INVERSE : un appel en COMMENTAIRE"

    # --- le MANIFESTE ----------------------------------------------------------------------------
    compose = 'services:\n  soc:\n    environment:\n' \
              '      PLUME_BACKUP_INTERVAL: "${PLUME_BACKUP_INTERVAL:-21600}"\n' \
              '      PLUME_DB_KEY: "${PLUME_DB_KEY:-}"\n' \
              '      PLUME_BACKUP_DEST: "${PLUME_BACKUP_DEST:-/data/backups}"\n' \
              '      # PLUME_COMMENTEE: "1"\n'
    livrees, toutes = affectations_du_manifeste(compose)
    assert livrees.get("PLUME_BACKUP_INTERVAL") == "21600", f"témoin : le défaut d'une substitution n'est pas lu ({livrees})"
    assert livrees.get("PLUME_DB_KEY") == "", "témoin : une substitution SANS défaut doit valoir du vide"
    assert livrees.get("PLUME_BACKUP_DEST") == "/data/backups", "témoin : un défaut littéral n'est pas lu"
    assert "PLUME_COMMENTEE" not in toutes, "témoin INVERSE : une affectation COMMENTÉE n'affecte rien"

    k8s = 'stringData:\n  PLUME_DB_KEY: ""\n---\n          env:\n' \
          '            - { name: PLUME_BACKUP_INTERVAL, value: "21600" }\n' \
          '            # - { name: PLUME_DB_KEY_FILE, value: "/etc/plume/secrets/PLUME_DB_KEY" }\n'
    livrees, toutes = affectations_du_manifeste(k8s)
    assert livrees.get("PLUME_BACKUP_INTERVAL") == "21600", f"témoin : l'entrée `env:` k8s n'est pas lue ({livrees})"
    assert "PLUME_DB_KEY" in toutes, "témoin : une valeur de `stringData` doit être VUE"
    assert "PLUME_DB_KEY" not in livrees, \
        "témoin : une valeur qui RÉSIDE dans un Secret sans être injectée n'est pas LIVRÉE au conteneur"
    assert "PLUME_DB_KEY_FILE" not in toutes, "témoin INVERSE : une entrée `env:` COMMENTÉE ne livre rien"

    # --- l'ÉQUIVALENCE ---------------------------------------------------------------------------
    code = 'pub(crate) const CLE_A: &str = "PLUME_DB_KEY_FILE";\npub(crate) const CLE_B: &str = "PLUME_DB_KEY";\n' \
           'pub(crate) const CLES_AT_REST: [&str; 2] = [CLE_A, CLE_B];\n' \
           'pub(crate) const SEULE: [&str; 1] = [CLE_A];\n'
    cls = equivalences(code)
    assert cls == [{"PLUME_DB_KEY_FILE", "PLUME_DB_KEY"}], f"témoin : la classe d'équivalence n'est pas dérivée ({cls})"


# ================================================================================================
def fichiers_rust(racine):
    for d, fs in parcours_des_sources(racine):
        for f in fs:
            if f.endswith(".rs"):
                yield os.path.join(d, f)


def manifestes(racine):
    """LES MANIFESTES DE DÉPLOIEMENT, PARCOURUS DEPUIS LA RACINE DU DÉPÔT — donc élagués par le geste
    PARTAGÉ, et plus par la liste privée de trois noms qui vivait ici (`P11.8-m`).

    Mesuré le 2026-08-31 : hors la garde du lexique, c'est le SEUL parcours RÉCURSIF depuis la racine du
    dépôt de tout `.github/scripts/` (les deux autres balayages de racine s'arrêtent au premier niveau).
    Sa copie privée avait les deux défauts du modèle avant correction : elle n'élaguait que des
    RÉPERTOIRES — un `.git` de `git worktree` est un FICHIER (`P11.8-l`) — et elle ignorait `.venv`,
    `venv`, `vendor`, `site-packages`. Prouvé par mutation le 2026-08-31 : un `.venv/lib/
    docker-compose.poison.yml` posé à la racine faisait passer la population de 12 manifestes à 13 sans
    qu'aucun plancher ne rougisse (un plancher ne garde que la BAISSE) ; avec l'élagage partagé, 12."""
    for d, fs in parcours_des_sources(racine):
        for f in fs:
            if f.endswith((".yml", ".yaml")) or f.startswith("docker-compose"):
                yield os.path.join(d, f)


def main():
    temoins_des_lectures()

    if not os.path.isdir(SRC):
        refuse(f"{SRC} introuvable — la dérivation est cassée, aucun verdict rendu")

    # --- ① LA PRODUCTION, LUE UNE FOIS -----------------------------------------------------------
    production, tout_le_code = [], []
    for f in fichiers_rust(SRC):
        # hors suites de tests : ce qui tourne en production est seul à armer et à refuser.
        if os.sep + "tests" + os.sep in f or os.path.basename(f) == "tests.rs":
            continue
        src = open(f, encoding="utf-8").read()
        tout_le_code.append(src)
        production.extend(unites_rust(src))
    if len(production) < 200:
        refuse(f"{len(production)} unité(s) de production lues sous {SRC} : la découpe est cassée, la garde refuse de conclure")

    # --- ② LES TÂCHES ARMÉES ----------------------------------------------------------------------
    armees = {}          # clé d'armement -> nom de la fonction gatée
    for nom, corps in production:
        for cle in gates_du_corps(corps):
            armees[cle] = nom
    if len(armees) < MIN_TACHES_ARMEES:
        refuse(f"{len(armees)} tâche(s) armée(s) dérivée(s) ({sorted(armees)}), plancher {MIN_TACHES_ARMEES} : "
               "la forme du gate a changé ou la lecture ne voit plus les corps — la garde refuse de conclure")

    # --- ③ LES PRÉCONDITIONS, PAR POINT FIXE DES APPELS -------------------------------------------
    par_nom = {}
    for nom, corps in production:
        par_nom.setdefault(nom, "")
        par_nom[nom] += corps

    # LE GRAPHE D'APPEL, CONSTRUIT UNE FOIS : nom -> noms de production qu'il appelle.
    noms = set(par_nom)
    graphe = {nom: appels_du_corps(corps, noms) for nom, corps in par_nom.items()}

    def joignables(depart):
        vus, pile = {depart}, [depart]
        while pile:
            for suivant in graphe.get(pile.pop(), ()):
                if suivant not in vus:
                    vus.add(suivant)
                    pile.append(suivant)
        return vus

    preconditions = {}   # clé d'armement -> ensemble de clés requises
    for cle, entree in sorted(armees.items()):
        requises = set()
        for nom in joignables(entree):
            requises |= preconditions_du_corps(par_nom[nom])
        requises.discard(cle)          # une tâche n'est pas sa propre précondition
        preconditions[cle] = requises
    total = sum(len(v) for v in preconditions.values())
    if total < MIN_PRECONDITIONS:
        refuse(f"aucune précondition dérivée sur {len(armees)} tâche(s) armée(s) : la lecture des refus est morte "
               f"(plancher {MIN_PRECONDITIONS}) — la garde refuse de conclure")

    # --- ④ LES ÉQUIVALENCES ------------------------------------------------------------------------
    classes = equivalences("\n".join(tout_le_code))
    if len(classes) < MIN_EQUIVALENCES:
        refuse(f"{len(classes)} classe(s) d'équivalence dérivée(s), plancher {MIN_EQUIVALENCES} : "
               "les tableaux de constantes ne sont plus lus — un déploiement qui emploie la variante "
               "d'une variable serait accusé à tort ; la garde refuse de conclure")

    def substituts(cle):
        s = {cle}
        for c in classes:
            if cle in c:
                s |= c
        return s

    # --- ⑤ LES DÉPLOIEMENTS, ET LE VERDICT ---------------------------------------------------------
    fautes, vus = [], 0
    for f in sorted(manifestes(RACINE)):
        rel = os.path.relpath(f, RACINE)
        try:
            texte = open(f, encoding="utf-8").read()
        except (OSError, UnicodeDecodeError) as e:
            refuse(f"{rel} illisible ({e}) — un manifeste non lu est un manifeste non contrôlé")
        livrees, _ = affectations_du_manifeste(texte)
        for cle, entree in sorted(armees.items()):
            valeur = livrees.get(cle)
            if valeur is None or valeur.strip() in ("", "0"):
                continue                      # ce fichier n'arme pas cette tâche
            vus += 1
            for requise in sorted(preconditions[cle]):
                if any(livrees.get(s, "").strip() for s in substituts(requise)):
                    continue
                fautes.append((rel, cle, valeur, entree, requise, sorted(substituts(requise))))
    if vus < MIN_DEPLOIEMENTS:
        refuse(f"aucun déploiement n'arme aucune des {len(armees)} tâche(s) dérivée(s) : la lecture des "
               f"manifestes est morte (plancher {MIN_DEPLOIEMENTS}) — la garde refuse de conclure")

    print(f"[{ETIQUETTE}] tâches armées dérivées : { {k: v for k, v in sorted(armees.items())} }")
    print(f"[{ETIQUETTE}] préconditions dérivées : { {k: sorted(v) for k, v in sorted(preconditions.items()) if v} }")
    print(f"[{ETIQUETTE}] classes d'équivalence : {[sorted(c) for c in classes]}")
    print(f"[{ETIQUETTE}] {vus} armement(s) trouvé(s) dans les manifestes du dépôt")

    for rel, cle, valeur, entree, requise, subs in fautes:
        print(f"::error file={rel}::ce déploiement ARME `{cle}={valeur}` (gate `{entree}`) sans livrer au "
              f"conteneur, DANS CE MÊME FICHIER, de valeur non vide pour `{requise}` — la tâche armée "
              f"REFUSE sans elle, et chaque cycle se terminera sans rien produire. Variables acceptées "
              f"pour cette précondition : {', '.join(subs)}. Deux issues, et une seule d'entre elles est "
              f"honnête : livrer la précondition, ou ne pas armer — mais un armement retiré doit être DIT "
              f"à l'exploitant, sinon le défaut change seulement de forme.")
    if fautes:
        print(f"[{ETIQUETTE}] {len(fautes)} armement(s) sans précondition.")
        sys.exit(1)

    print(f"[{ETIQUETTE}] {vus} armement(s) contrôlé(s) : aucun déploiement n'arme une tâche dont une "
          f"précondition manque chez lui. Ce que cette garde NE tient PAS : la JUSTESSE d'une valeur non "
          f"vide, l'aboutissement réel du cycle (dit à l'exécution par le signal non purgeable « aucune "
          f"archive publiée »), et ce qu'un `.env` d'exploitant ajouterait hors du dépôt.")


if __name__ == "__main__":
    main()
