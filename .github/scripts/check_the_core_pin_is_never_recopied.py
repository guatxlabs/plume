#!/usr/bin/env python3
"""L'étiquette du cœur ne vit qu'à UN endroit : recopiée, elle vieillit — et c'est mesuré.

LE DÉFAUT, RELEVÉ LE 2026-08-27. `daemon/Cargo.toml` épingle `guatx-core` sur un tag ; `daemon/
Cargo.lock` porte le même tag et la révision résolue. NEUF autres lignes du dépôt — deux dans
`ARCHITECTURE.md`, deux dans `CONTRIBUTING.md`, une dans `deny.toml`, quatre dans `ci.yml` —
RÉÉCRIVAIENT ce tag au présent, et toutes les neuf annonçaient encore `v0.2.1` alors que le
manifeste était passé à `v0.2.4`. Un lecteur qui vérifie « quel cœur ce dépôt compile-t-il ? » sur
la documentation obtenait la mauvaise réponse, et l'entrée `allow-git` de `deny.toml` justifiait son
exception par une mesure périmée.

CE N'EST PAS UNE FAUTE DE FRAPPE, C'EST UNE FORME. La correction ligne à ligne a déjà été faite au
moins une fois — `Dockerfile` et `docker-compose.yml` ont cessé de citer le nombre, ils nomment le
manifeste — et la dérive est revenue ailleurs, parce que rien n'interdisait la recopie. C'est
exactement la doctrine que `check_no_duplicated_test_count.py` tient déjà pour le compte de tests :
une valeur qui a une source unique ne doit pas exister ailleurs, et aucune liste d'exceptions n'est
tenable.

LA GARDE EST DÉRIVÉE, PAS ÉNUMÉRÉE. Elle ne porte AUCUNE liste de fichiers tolérés et ne connaît
aucun numéro de version : elle cherche la FORME d'un épinglage — une version accrochée à la syntaxe
qui épingle (`tag = "vX"`, `?tag=vX`, `core@vX`) — et refuse qu'elle apparaisse hors des deux
fichiers qui FONT FOI. Un fichier créé demain est couvert par construction.

DEUX FICHIERS SONT HORS PORTÉE, et ce ne sont pas des exceptions : ce sont les fichiers
AUTO-RÉFÉRENTS. `daemon/Cargo.toml` DÉCLARE l'épinglage — c'est tout l'objet de la garde — et
`daemon/Cargo.lock` en est la résolution, écrite par cargo et jamais à la main. Une règle ne peut
pas être sa propre violation. Ce script est également hors portée : il contient forcément des
exemples de ce qu'il détecte.

CE QUE LA GARDE NE TIENT PAS, ET C'EST DIT :
  · elle ne juge PAS une version de cœur citée SANS la syntaxe d'épinglage (« mesuré sur le cœur
    v0.2.1 », « fermée dans core (v0.2.4) »). Ce sont des mesures DATÉES qui disent ce qui était
    vrai à leur date, et les « corriger » vers la valeur du jour serait falsifier une mesure. Le
    motif exige donc l'ADJACENCE à `tag`/`@`, ce qui a été calibré sur l'arbre réel : sans cette
    adjacence, sept citations historiques légitimes (dont une cellule de la feuille de route et
    quatre commentaires de tests qui datent un durcissement du compilateur) auraient rougi ;
  · elle ne vérifie pas que le manifeste dit VRAI. Elle interdit la SECONDE copie, pas l'erreur
    dans la première — c'est la même borne que pour le compte de tests.
"""
import os
import re
import subprocess
import sys

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.realpath(os.path.join(ICI, "..", ".."))
MOI = os.path.relpath(os.path.abspath(__file__), RACINE)

# Les deux fichiers AUTO-RÉFÉRENTS : la déclaration et sa résolution.
FONT_FOI = ("daemon/Cargo.toml", "daemon/Cargo.lock")

# LA FORME D'UN ÉPINGLAGE : une version accrochée à la syntaxe qui épingle. `tag = "v…"`,
# `tag: v…`, «  tag `v…` », `?tag=v…`, `core@v…`. Une version citée SANS cette adjacence
# (« le cœur v0.2.1 ») n'est pas un épinglage : c'est une mesure, et elle porte sa date.
EPINGLAGE = re.compile(r"(?:\?tag=|tag\s*[:=]\s*[\"'`]?|tag\s+[\"'`]|core@)\s*(v\d+\.\d+\.\d+)")


def fichiers_suivis():
    r = subprocess.run(
        ["git", "-C", RACINE, "ls-files"], capture_output=True, text=True, check=False
    )
    if r.returncode != 0:
        return None
    return [l for l in r.stdout.splitlines() if l]


def epreuves():
    """L'INSTRUMENT AVANT LE VERDICT — témoins positifs ET négatifs, hors du disque.

    Un motif qui ne reconnaît plus rien rendrait « aucune recopie » sur un dépôt qui en est plein.
    """
    doivent_mordre = [
        'guatx-core = { git = "https://github.com/guatxlabs/core", tag = "v0.2.4" }',
        "# `guatxlabs/core@v0.2.1` must be reachable by the runner",
        "source = \"git+https://github.com/guatxlabs/core?tag=v0.2.4#07b13cf\"",
        "`guatx-core` est résolu via une git-dep publique (tag `v0.2.1`, récupérée au build)",
        "cargo fetches the guatx-core git-dep (core@v0.2.1) from GitHub.",
    ]
    doivent_se_taire = [
        "CONSÉQUENCES MESURÉES (lecture du cœur v0.2.1, pas une supposition)",
        "FERMÉE le 2026-08-22 dans `core` (v0.2.4), plume ré-épinglé sur le commit exact du tag.",
        "Ces deux formes compilaient jusqu'à guatx-core v0.2.0 : dans `champ [not] in (…)`",
        "warning: patch `guatx-core v0.2.2 (/path/to/core)` was not used in the crate graph",
        "guatx-core = { git = \"https://github.com/guatxlabs/core\" }  # le tag vit au manifeste",
        "le tag est lu dans `daemon/Cargo.toml`, jamais recopié ici",
    ]
    for l in doivent_mordre:
        if not EPINGLAGE.search(l):
            return f"témoin POSITIF manqué (le motif ne reconnaît plus un épinglage) : {l!r}"
    for l in doivent_se_taire:
        if EPINGLAGE.search(l):
            return f"témoin NÉGATIF mordu (une citation datée n'est pas un épinglage) : {l!r}"
    return None


def main():
    faute = epreuves()
    if faute:
        print(f"check_the_core_pin_is_never_recopied: INSTRUMENT INVALIDE — {faute}", file=sys.stderr)
        return 2

    suivis = fichiers_suivis()
    if suivis is None:
        print(
            "check_the_core_pin_is_never_recopied: `git ls-files` a échoué — aucun verdict rendu "
            "(un corpus vide se lirait comme un dépôt propre)",
            file=sys.stderr,
        )
        return 2

    # LE TÉMOIN DE CORPUS : le manifeste DOIT porter un épinglage, sinon la garde ne juge rien.
    manifeste = os.path.join(RACINE, "daemon", "Cargo.toml")
    try:
        vivant = EPINGLAGE.search(open(manifeste, encoding="utf-8").read())
    except OSError:
        vivant = None
    if not vivant:
        print(
            "check_the_core_pin_is_never_recopied: aucun épinglage trouvé dans daemon/Cargo.toml — "
            "la garde ne peut pas juger des recopies d'une valeur qu'elle ne voit pas",
            file=sys.stderr,
        )
        return 2
    tag_vivant = vivant.group(1)

    recopies = []
    for rel in suivis:
        if rel in FONT_FOI or rel == MOI:
            continue
        chemin = os.path.join(RACINE, rel)
        try:
            texte = open(chemin, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        if "\x00" in texte[:4096]:
            continue  # binaire : rien à lire
        for n, ligne in enumerate(texte.splitlines(), 1):
            m = EPINGLAGE.search(ligne)
            if m:
                recopies.append((rel, n, m.group(1), ligne.strip()[:120]))

    if recopies:
        print(
            f"check_the_core_pin_is_never_recopied: {len(recopies)} recopie(s) de l'épinglage du cœur "
            f"(vivant : {tag_vivant} dans daemon/Cargo.toml).",
            file=sys.stderr,
        )
        for rel, n, tag, ligne in recopies:
            etat = "PÉRIMÉE" if tag != tag_vivant else "à jour AUJOURD'HUI"
            print(f"  {rel}:{n}  [{tag} — {etat}]  {ligne}", file=sys.stderr)
        print(
            "  -> Une étiquette recopiée vieillit : nommez le manifeste (`daemon/Cargo.toml`) au lieu "
            "d'écrire le tag. Une version citée SANS la syntaxe d'épinglage — une mesure datée — ne "
            "déclenche pas cette garde.",
            file=sys.stderr,
        )
        return 1

    print(
        f"check_the_core_pin_is_never_recopied: OK — l'épinglage du cœur ({tag_vivant}) ne vit que "
        f"dans {', '.join(FONT_FOI)} ; {len(suivis)} fichier(s) suivis relus."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
