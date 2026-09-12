#!/usr/bin/env python3
"""Chaque capteur `collectors/*.sh` déclare, en tête, les CHAMPS qu'il émet — dérivés, tenus dans les
DEUX sens contre l'autorité, jamais contre le texte (`P11.19-a`, volet 1).

MIROIR EXACT de `P11.16-a` (« # plume-source: »). Là où `P11.16-a` déclare la SOURCE d'un capteur et la
tient contre la forme du code, ce volet déclare les CHAMPS ÉTENDUS qu'un capteur écrit dans le sac
`fields` et les tient contre l'autorité qui les recense déjà.

L'AUTORITÉ DE DÉRIVATION — ET POURQUOI C'EST UN MIROIR, PAS UNE LISTE
--------------------------------------------------------------------
`daemon/src/collected.rs` porte `COLLECTED_EXTENDED_FIELDS: &[(&str, &str)]` — 168 couples
(champ, fichier_émetteur) mesurés sur l'arbre. Cette constante n'est PAS tenue à la main : le témoin
`daemon/src/tests/detection.rs` la tient == au balayage réel `collected_extract_shipped` DANS LES DEUX
SENS (y ajouter un couple que l'extracteur ne dérive pas rougit ; en retirer un qu'il dérive rougit
aussi). Elle est donc l'autorité dérivable : les champs d'un capteur `X.sh` = tous les champs dont la
2e colonne est le basename `X.sh`.

Cette garde ne réécrit pas cette autorité — elle la LIT, la groupe par basename, et exige que l'en-tête
`# plume-emits: fields=…` de chaque `collectors/*.sh` en soit le miroir exact :
  · un champ dérivé absent de l'en-tête    -> ROUGE « champ émis non déclaré »     (sens A) ;
  · un champ de l'en-tête absent du dérivé -> ROUGE « déclaré mais non émis » (fantôme, sens B).

LE `kind` D'ENVELOPPE — DÉRIVÉ DU CAPTEUR LUI-MÊME
--------------------------------------------------
Un capteur de métriques ou de contrôles n'écrit AUCUN champ d'événement, mais il n'émet pas rien : il
pose une enveloppe non-événement (`{"kind":"metrics"}`, `{"kind":"controls"}`, `{"kind":"firewall"}`).
Un `fields=` vide seul se lirait « n'émet rien » ; l'annotation `kind=` le distingue de « émet une
enveloppe sans champ ». Elle est dérivée du corps du capteur (les littéraux `"kind":"X"`, `events`
étant l'enveloppe d'événement par défaut et donc omise), et tenue dans les deux sens comme les champs :
un capteur qui émet une enveloppe `metrics` sans la déclarer rougit ; un `kind=` déclaré qu'aucune
enveloppe n'émet rougit (fantôme). C'est la même dérivation que `P11.16-a` fait de la FORME du code.

L'INSTRUMENT SE VALIDE AVANT DE RENDRE UN VERDICT
-------------------------------------------------
Une garde d'extraction verdit de deux façons : parce que tout va bien, ou parce que son motif ne
reconnaît plus rien. Avant tout verdict, celle-ci joue un ANTI-CORPUS in-memory portant ses témoins —
un en-tête conforme (0 faute), un champ dérivé retiré (manquant), un champ fantôme, un kind dérivé
retiré, un kind fantôme, un en-tête absent, et le cas piégeux `integrity.sh` (un champ NOMMÉ « kind »
dans `fields=` n'est pas l'annotation `kind=`). L'extraction du `kind` depuis le corps est elle aussi
témoignée (un `"kind":"metrics"` en COMMENTAIRE ne compte pas ; un réel compte). Un témoin faux fait
REFUSER DE CONCLURE (code 2), jamais verdir. Elle exige ensuite un PLANCHER sur l'arbre réel : moins de
100 couples lus, ou moins de 30 capteurs vus, et elle refuse — un reformatage qui casse un motif
échoue au lieu de se taire.

PORTÉE DÉRIVÉE, ET LES LIMITES SONT DITES
-----------------------------------------
La population est l'ENSEMBLE `collectors/*.sh` du répertoire (jamais une liste écrite) : un capteur
neuf est vu dès qu'il existe. Hors périmètre, et c'est ASSUMÉ :
  · `collectors/plume-collector.ps1` (PowerShell) — le balayage de `collected.rs` le cite comme
    émetteur, mais il n'a pas d'en-tête `#` de cette forme et n'est pas un `*.sh` ; sa tenue est celle
    de `check_windows_collector_is_honest.py`.
  · `collectors/minio-audit-relay.py` (Python) — émetteur cité, mais `*.py`, hors de ce volet `*.sh`.
  · les fichiers Rust cités (`fim/mod.rs`, `source/windows.rs`, `source/linux.rs`, `macos.rs`) et les
    exemples `*.json` — ce ne sont pas des `collectors/*.sh`.

CE QU'ELLE NE TIENT PAS, ET IL FAUT LE LIRE
-------------------------------------------
· Elle tient QUELS champs sont émis, pas leur SENS ni l'ensemble de VALEURS qu'ils prennent — c'est
  `check_a_producer_declares_the_values_it_emits.py` (`P11.19-a`/`b`, valeurs), une autre garde.
· Elle ne tient pas la route ni la console qui SERVIRAIENT cette déclaration — c'est le reste 2 de la
  cellule, entier.
· Elle ne tient pas le SECOND volet démon de `P11.19-a`.
· Elle lit un texte : elle ne lance pas le capteur et n'atteste pas qu'il écrit réellement le champ à
  l'exécution — c'est `detection.rs` qui tient l'autorité == l'extracteur, ici seulement supposée juste.

Sortie : 0 tenu · 1 au moins un capteur ment ou oublie · 2 l'instrument REFUSE DE CONCLURE (autorité
illisible, plancher non atteint, témoin faux) — jamais un vert par défaut.
"""
import glob
import os
import re
import sys

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.realpath(os.path.join(ICI, "..", ".."))
COLLECTED = os.path.join(RACINE, "daemon", "src", "collected.rs")
COLLECTEURS = os.path.join(RACINE, "collectors")
ETIQUETTE = "P11.19-a"

# Un couple `("champ", "fichier")` de la table d'autorité.
PAIRE = re.compile(r'\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)')
# La déclaration en tête d'un capteur.
DECL = re.compile(r'(?m)^#\s*plume-emits:\s*(.*?)\s*$')
# Un jeton `clé=valeur` de la déclaration (valeur sans espace : une liste séparée par des virgules).
JETON = re.compile(r'(\w+)=(\S*)')
# Un littéral d'enveloppe `"kind":"X"` dans le corps du capteur.
KIND_LIT = re.compile(r'"kind"\s*:\s*"([a-zA-Z0-9_]+)"')

CLES_CONNUES = {"fields", "kind"}


def refus(msg):
    print(f"::error::{ETIQUETTE} : {msg} — RIEN N'A ÉTÉ MESURÉ.", file=sys.stderr)
    sys.exit(2)


def kinds_du_corps(txt):
    """Enveloppes non-événement émises par le corps (lignes de commentaire retirées ; `events` omis,
    c'est l'enveloppe d'événement par défaut)."""
    corps = "\n".join(l for l in txt.splitlines() if not l.lstrip().startswith("#"))
    return {k for k in KIND_LIT.findall(corps) if k != "events"}


def lire_entete(txt):
    """(présente, fields:set, kinds:set, cles_inconnues:list). Une déclaration sans jeton `fields=` est
    tenue pour absente (la forme minimale exige `fields=`, même vide)."""
    m = DECL.search(txt)
    if not m:
        return (False, set(), set(), [])
    fields, kinds, inconnues, a_fields = set(), set(), [], False
    for cle, val in JETON.findall(m.group(1)):
        vals = {x for x in val.split(",") if x}
        if cle == "fields":
            fields |= vals
            a_fields = True
        elif cle == "kind":
            kinds |= vals
        else:
            inconnues.append(cle)
    return (a_fields, fields, kinds, inconnues)


def comparer(nom, derive_fields, derive_kinds, txt):
    """Les fautes d'UN capteur, dans les deux sens, champs ET kind. Liste vide = tenu."""
    fautes = []
    presente, decl_fields, decl_kinds, inconnues = lire_entete(txt)
    if not presente:
        return [f"{nom} : AUCUN en-tête `# plume-emits: fields=…` — la dérivation y voit "
                f"fields={sorted(derive_fields)} kind={sorted(derive_kinds)}"]
    for c in inconnues:
        fautes.append(f"{nom} : clé inconnue `{c}=` dans `# plume-emits:` (attendu : `fields=`, `kind=`)")
    for f in sorted(derive_fields - decl_fields):
        fautes.append(f"{nom} : champ émis `{f}` non déclaré (dérivé de COLLECTED_EXTENDED_FIELDS)")
    for f in sorted(decl_fields - derive_fields):
        fautes.append(f"{nom} : champ `{f}` déclaré mais non émis (fantôme — absent de COLLECTED_EXTENDED_FIELDS)")
    for k in sorted(derive_kinds - decl_kinds):
        fautes.append(f"{nom} : enveloppe `kind={k}` émise mais non déclarée")
    for k in sorted(decl_kinds - derive_kinds):
        fautes.append(f"{nom} : `kind={k}` déclaré mais aucune enveloppe de ce genre n'est émise (fantôme)")
    return fautes


def anti_corpus():
    """Témoins positifs ET négatifs, in-memory, hors de l'arbre. Renvoie None si tout est cohérent."""
    df, dk = {"a", "b"}, {"metrics"}
    cas = [
        ("conforme", df, dk, "#!/bin/sh\n# plume-emits: fields=a,b kind=metrics\n", 0),
        ("champ manquant", df, dk, "# plume-emits: fields=a kind=metrics\n", 1),
        ("champ fantôme", df, dk, "# plume-emits: fields=a,b,z kind=metrics\n", 1),
        ("kind manquant", df, dk, "# plume-emits: fields=a,b\n", 1),
        ("kind fantôme", df, dk, "# plume-emits: fields=a,b kind=metrics,controls\n", 1),
        ("en-tête absent", df, dk, "#!/bin/sh\n# plume-source: x\n", 1),
        ("clé inconnue", df, dk, "# plume-emits: fields=a,b kind=metrics category=ban\n", 1),
        # `integrity.sh` : un champ NOMMÉ « kind » dans fields= n'est pas l'annotation kind=.
        ("champ nommé kind", {"change", "kind"}, set(), "# plume-emits: fields=change,kind\n", 0),
        # fields= vide + une enveloppe non-événement, sans champ (resources/controls/firewall).
        ("enveloppe sans champ", set(), {"controls"}, "# plume-emits: fields= kind=controls\n", 0),
    ]
    for nom, f, k, txt, attendu in cas:
        vu = len(comparer("t.sh", f, k, txt))
        if vu != attendu:
            return f"témoin « {nom} » : {vu} faute(s), attendu {attendu}"
    # L'extraction du kind depuis le corps : un commentaire ne compte pas, un littéral réel compte.
    if kinds_du_corps('# "kind":"metrics"\n') != set():
        return "témoin kind-en-commentaire : un `\"kind\":\"metrics\"` commenté a été compté"
    if kinds_du_corps('printf \'{"kind":"metrics"}\'\n') != {"metrics"}:
        return "témoin kind-réel : un `\"kind\":\"metrics\"` émis n'a pas été vu"
    if kinds_du_corps('printf \'{"kind":"events"}\'\n') != set():
        return "témoin kind-events : l'enveloppe d'événement par défaut a été comptée comme non-événement"
    return None


def derivation_par_fichier():
    """{basename.sh -> set(champs)} groupé depuis COLLECTED_EXTENDED_FIELDS ; + le compte total de couples."""
    try:
        src = open(COLLECTED, encoding="utf-8").read()
    except OSError as e:
        refus(f"autorité illisible ({COLLECTED} : {e})")
    m = re.search(r"COLLECTED_EXTENDED_FIELDS\s*:\s*&\[\s*\(\s*&str\s*,\s*&str\s*\)\s*\]\s*=\s*&\[(.*?)\];", src, re.S)
    if not m:
        refus("le bloc `COLLECTED_EXTENDED_FIELDS` n'a pas été trouvé dans collected.rs")
    couples = PAIRE.findall(m.group(1))
    par_fichier = {}
    for champ, fichier in couples:
        par_fichier.setdefault(fichier, set()).add(champ)
    return par_fichier, len(couples)


def main():
    faute = anti_corpus()
    if faute:
        refus(f"instrument INVALIDE ({faute})")

    par_fichier, n_couples = derivation_par_fichier()
    if n_couples < 100:
        refus(f"seulement {n_couples} couple(s) lus dans COLLECTED_EXTENDED_FIELDS (attendu >= 100) : "
              "le motif ne reconnaît plus la table")

    capteurs = sorted(glob.glob(os.path.join(COLLECTEURS, "*.sh")))
    if len(capteurs) < 30:
        refus(f"seulement {len(capteurs)} capteur(s) `collectors/*.sh` vus (attendu >= 30) : "
              "la surface a cessé d'être vue")

    fautes, avec_champs = [], 0
    for chemin in capteurs:
        nom = os.path.basename(chemin)
        try:
            txt = open(chemin, encoding="utf-8").read()
        except OSError as e:
            refus(f"capteur illisible ({nom} : {e})")
        derive_fields = par_fichier.get(nom, set())
        if derive_fields:
            avec_champs += 1
        derive_kinds = kinds_du_corps(txt)
        for f in comparer(nom, derive_fields, derive_kinds, txt):
            fautes.append(f)

    if avec_champs < 15:
        refus(f"seulement {avec_champs} capteur(s) avec au moins un champ dérivé (attendu >= 15) : "
              "la dérivation ne se rattache plus aux basenames de `collectors/`")

    if fautes:
        for f in fautes:
            nom = f.split(" : ", 1)[0]
            print(f"::error file=collectors/{nom}::{ETIQUETTE} : {f}")
        print(f"\n{len(fautes)} déclaration(s) `# plume-emits:` qui manquent ou contredisent la dérivation. "
              "L'en-tête est le MIROIR de COLLECTED_EXTENDED_FIELDS (tenue == l'extracteur par "
              "detection.rs) : un capteur qui écrit un champ sans le déclarer, ou déclare un champ qu'il "
              "n'écrit pas, est nommé ici.", file=sys.stderr)
        sys.exit(1)

    print(f"{ETIQUETTE} : {len(capteurs)} capteur(s) `collectors/*.sh` — chacun déclare en tête, "
          f"`# plume-emits: fields=…`, les champs dérivés de COLLECTED_EXTENDED_FIELDS "
          f"({n_couples} couples, {avec_champs} capteurs porteurs de champ), et l'enveloppe `kind=` "
          "quand il en émet une non-événement. Tenu DANS LES DEUX SENS, contre l'autorité et non le "
          "texte. Population dérivée du répertoire ; PS1, .py, .rs et .json cités par l'autorité sont "
          "hors périmètre de ce volet, et c'est dit dans l'en-tête du script.")
    sys.exit(0)


if __name__ == "__main__":
    main()
