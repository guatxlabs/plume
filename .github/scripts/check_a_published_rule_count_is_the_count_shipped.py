#!/usr/bin/env python3
"""Un compte de règles publié dans la documentation est le compte des règles livrées.

LE DÉFAUT, CONSTATÉ SUR L'ARBRE. La page d'accueil annonçait « 3 règles d'exemple » dans
`config.d/sigma/` quand l'arbre en suivait 4, et `docs/DETECTION-CATALOG.md` annonçait 35 règles de
catalogue quand `config.d/rules/catalog/` en suivait 37. Les deux chiffres avaient été justes un jour ;
rien ne les reliait à l'arbre, donc rien n'a rougi quand des règles ont été ajoutées. Le premier avait
un effet de plus : c'était le SEUL compte de détection de la page d'accueil, et un lecteur pressé en
concluait que Plume livrait trois règles.

LA GARDE. Chaque phrase de la table `ANNONCES` porte un nombre ; la garde relit ce nombre et le compare
au compte DÉRIVÉ de l'arbre suivi (`git ls-files`, donc ni artefact ni fichier local non suivi). Le
compte n'est écrit qu'à un endroit — la phrase publiée — et c'est cet endroit qui est jugé.

CODES DE SORTIE. `0` tous les comptes concordent ; `1` un compte publié diffère de l'arbre ; `2` rien n'a
été mesuré : épreuve interne en échec, `git ls-files` illisible, ou phrase introuvable (ou trouvée
plusieurs fois). Une phrase introuvable n'est pas un compte juste : si la phrase est reformulée, son
motif se met à jour ici, dans le même changement.

CE QU'ELLE NE TIENT PAS. Les règles semées par le binaire (`daemon/src/seeds.rs`) ne sont pas comptées :
aucune phrase publiée n'en donne le nombre, et ce n'est pas un compte de fichiers. Les autres comptes du
catalogue (techniques, tactiques, règles décrites) ne sont pas jugés ici.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import parite_des_langues as pdl  # noqa: E402

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.realpath(os.path.join(ICI, "..", ".."))


def suivis(racine: str) -> list[str] | None:
    try:
        sortie = subprocess.run(["git", "-C", racine, "ls-files", "-z"], capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    return [p.decode("utf-8", "surrogateescape") for p in sortie.split(b"\0") if p]


def sigma_exemples(fichiers, lire):
    return sum(1 for f in fichiers if f.startswith("config.d/sigma/") and f.endswith((".yml", ".yaml", ".json")))


def catalogue(fichiers, lire):
    return sum(1 for f in fichiers if f.startswith("config.d/rules/catalog/") and f.endswith(".json"))


def overlays_racine(fichiers, lire):
    return [f for f in fichiers if re.fullmatch(r"config\.d/rules/[^/]+\.json", f)]


def overlays_racine_compte(fichiers, lire):
    return len(overlays_racine(fichiers, lire))


def active_au_demarrage(texte: str) -> bool:
    """La valeur que le chargeur du démon donne à `enabled`, et non une lecture à soi.

    `load_overlay_rules` (`daemon/src/overlays.rs`) lit `v.get("enabled").and_then(as_bool).unwrap_or(true)` :
    une règle SANS champ `enabled`, ou dont le champ n'est pas un booléen, démarre ACTIVE. Une version
    antérieure de cette garde ne comptait que `enabled` égal à `true` ; une règle livrée sans le champ
    démarrait active sans être comptée. Le catalogue (`rules/catalog/`) passe par le MÊME chargeur, donc
    par la même valeur par défaut. Un fichier qui n'est pas un objet JSON lève : la garde refuse de conclure.
    """
    valeur = json.loads(texte).get("enabled")
    return valeur if isinstance(valeur, bool) else True


def overlays_racine_actives(fichiers, lire):
    return sum(1 for f in overlays_racine(fichiers, lire) if active_au_demarrage(lire(f)))


def catalogue_actives(fichiers, lire):
    return sum(1 for f in fichiers
               if f.startswith("config.d/rules/catalog/") and f.endswith(".json") and active_au_demarrage(lire(f)))


# (fichier publié, motif à UN groupe qui capture le nombre, compte dérivé de l'arbre, ce que c'est)
# Chaque document existe en deux langues (`X.md` anglais, `X.fr.md` français) : la phrase de chaque langue
# porte le même compte, et chacune est jugée, pour qu'une langue ne garde pas un nombre que l'autre a perdu.
ANNONCES = [
    ("README.fr.md", r"\*\*(\d+) règles Sigma d'exemple\*\*", sigma_exemples, "règles Sigma d'exemple (config.d/sigma/)"),
    ("README.fr.md", r"\*\*(\d+) règles de catalogue\*\*", catalogue, "règles de catalogue (config.d/rules/catalog/)"),
    ("README.fr.md", r"\*\*(\d+) règles overlay\*\*", overlays_racine_compte, "règles overlay à la racine de config.d/rules/"),
    ("README.fr.md", r"\*\*dont (\d+) actives\*\*", overlays_racine_actives,
     "règles overlay racine actives au démarrage (enabled absent ou vrai)"),
    ("README.fr.md", r"\*\*sauf (\d+) règles? actives?\*\*", catalogue_actives,
     "règles de catalogue actives au démarrage (enabled absent ou vrai)"),
    ("README.md", r"\*\*(\d+) sample Sigma rules\*\*", sigma_exemples, "règles Sigma d'exemple (config.d/sigma/)"),
    ("README.md", r"\*\*(\d+) catalog rules\*\*", catalogue, "règles de catalogue (config.d/rules/catalog/)"),
    ("README.md", r"\*\*(\d+) overlay rules\*\*", overlays_racine_compte, "règles overlay à la racine de config.d/rules/"),
    ("README.md", r"\*\*of which (\d+) are active\*\*", overlays_racine_actives,
     "règles overlay racine actives au démarrage (enabled absent ou vrai)"),
    ("README.md", r"\*\*except (\d+) active rules?\*\*", catalogue_actives,
     "règles de catalogue actives au démarrage (enabled absent ou vrai)"),
    ("docs/DETECTION-CATALOG.fr.md", r"\*\*(\d+) règles LIVRÉES\*\*", catalogue, "règles de catalogue (config.d/rules/catalog/)"),
    ("docs/DETECTION-CATALOG.md", r"\*\*(\d+) SHIPPED rules\*\*", catalogue, "règles de catalogue (config.d/rules/catalog/)"),
    # Le test qui charge le catalogue lit TOUT `config.d/rules/catalog/` (`read_dir`, sans filtre) : le
    # nombre de règles qu'il « exige » de compiler est donc le compte du catalogue, pas celui des tables.
    ("docs/DETECTION-CATALOG.fr.md", r"exige que les (\d+) compilent", catalogue,
     "règles de catalogue que le test de chargement exige de compiler"),
    ("docs/DETECTION-CATALOG.md", r"requires all (\d+) to compile", catalogue,
     "règles de catalogue que le test de chargement exige de compiler"),
]


def juger(annonces, fichiers, lire):
    """Rend (desaccords, introuvables). Pur : le disque n'est lu qu'à travers `lire`."""
    desaccords, introuvables = [], []
    for publie, motif, compter, quoi in annonces:
        trouves = re.findall(motif, lire(publie))
        if len(trouves) != 1:
            introuvables.append(f"{publie} : motif {motif!r} trouvé {len(trouves)} fois (attendu : 1)")
            continue
        annonce, reel = int(trouves[0]), compter(fichiers, lire)
        if annonce != reel:
            desaccords.append(f"{publie} annonce {annonce} {quoi}, l'arbre suivi en porte {reel}")
    return desaccords, introuvables


def epreuves() -> list[str]:
    """Témoins positifs et négatifs, hors du disque."""
    fichiers = ["README.md", "config.d/sigma/a.yml", "config.d/sigma/b.yml",
                "config.d/rules/x.json", "config.d/rules/y.json", "config.d/rules/catalog/c.json"]
    contenus = {"config.d/rules/x.json": '{"enabled": true}', "config.d/rules/y.json": '{"enabled": false}',
                "config.d/rules/catalog/c.json": '{"enabled": true}'}
    # La valeur par défaut du chargeur : champ absent ou non booléen -> active.
    for texte, attendu in [('{"enabled": true}', True), ('{"enabled": false}', False), ('{"name": "r"}', True),
                           ('{"enabled": "false"}', True), ('{"enabled": null}', True)]:
        if active_au_demarrage(texte) is not attendu:
            return [f"épreuve « défaut du chargeur » : {texte} -> {not attendu}, attendu {attendu}"]
    sans_champ = dict(contenus, **{"config.d/rules/y.json": '{"name": "y"}'})
    d, _ = juger([("README.md", r"\*\*dont (\d+) actives\*\*", overlays_racine_actives, "a")], fichiers,
                 lambda f: "**dont 1 actives**" if f == "README.md" else sans_champ[f])
    if len(d) != 1:
        return [f"épreuve « règle sans champ enabled » : {len(d)} désaccord(s), attendu 1"]
    annonces = [("README.md", r"\*\*(\d+) règles Sigma d'exemple\*\*", sigma_exemples, "s"),
                ("README.md", r"\*\*(\d+) règles overlay\*\*", overlays_racine_compte, "o"),
                ("README.md", r"\*\*dont (\d+) actives\*\*", overlays_racine_actives, "a")]
    cas = [
        ("concordant", "**2 règles Sigma d'exemple** **2 règles overlay** **dont 1 actives**", 0, 0),
        ("compte périmé", "**3 règles Sigma d'exemple** **2 règles overlay** **dont 1 actives**", 1, 0),
        ("catalogue hors racine", "**2 règles Sigma d'exemple** **3 règles overlay** **dont 2 actives**", 2, 0),
        ("phrase disparue", "**2 règles Sigma d'exemple** **dont 1 actives**", 0, 1),
        ("phrase en double", "**2 règles Sigma d'exemple** **2 règles Sigma d'exemple** **2 règles overlay** **dont 1 actives**", 0, 1),
    ]
    echecs = []
    for nom, readme, att_d, att_i in cas:
        lire = lambda f, r=readme: r if f == "README.md" else contenus[f]
        d, i = juger(annonces, fichiers, lire)
        if (len(d), len(i)) != (att_d, att_i):
            echecs.append(f"épreuve « {nom} » : {len(d)} désaccord(s), {len(i)} introuvable(s) ; attendu {att_d}, {att_i}")
    # Les décisions de sortie, éprouvées par `trancher` : sans elles, un `main` qui rendrait 0 sur une
    # phrase introuvable ou sur une lecture impossible rendrait vert un arbre cassé.
    def lire_ok(f, r="**2 règles Sigma d'exemple** **2 règles overlay** **dont 1 actives**"):
        return r if f == "README.md" else contenus[f]

    def lire_oserror(f):
        raise OSError("absent")

    def lire_json_casse(f):
        return "{" if f.endswith(".json") else lire_ok(f)

    sorties = [
        ("concordant", fichiers, lire_ok, 0),
        ("compte périmé", fichiers, lambda f: lire_ok(f, "**3 règles Sigma d'exemple** **2 règles overlay** **dont 1 actives**"), 1),
        ("phrase introuvable", fichiers, lambda f: lire_ok(f, "**2 règles Sigma d'exemple**"), 2),
        ("fichier publié illisible", fichiers, lire_oserror, 2),
        ("règle JSON illisible", fichiers, lire_json_casse, 2),
        ("aucun fichier suivi", [], lire_ok, 2),
        ("git ls-files illisible", None, lire_ok, 2),
    ]
    for nom, fich, lire, attendu in sorties:
        code, _ = trancher(annonces, fich, lire)
        if code != attendu:
            echecs.append(f"épreuve de sortie « {nom} » : code {code}, attendu {attendu}")
    echecs += epreuves_des_deux_langues()
    return echecs


def epreuves_des_deux_langues() -> list[str]:
    """UN TÉMOIN PAR LANGUE, et la couverture de la table : chaque document publié l'est dans ses deux
    langues, avec le même jeu de comptes ; un compte faux dans la phrase anglaise, puis dans la
    française, est vu."""
    echecs = []
    publies = sorted({publie for publie, _, _, _ in ANNONCES})
    manquants = pdl.langues_manquantes(publies)
    if manquants:
        echecs.append(f"ANNONCES ne juge pas les deux langues : {manquants}")
    for publie in publies:
        autre = publie[:-len(".fr.md")] + ".md" if publie.endswith(".fr.md") else publie[:-3] + ".fr.md"
        ici = sorted(compter.__name__ for p, _, compter, _ in ANNONCES if p == publie)
        la = sorted(compter.__name__ for p, _, compter, _ in ANNONCES if p == autre)
        if la and ici != la:
            echecs.append(f"ANNONCES : {publie} juge {ici}, {autre} juge {la} — une langue garde un compte que "
                          f"l'autre ne publie plus")
    fichiers = ["config.d/sigma/a.yml", "config.d/sigma/b.yml"]
    deux = [("README.md", r"\*\*(\d+) sample Sigma rules\*\*", sigma_exemples, "s"),
            ("README.fr.md", r"\*\*(\d+) règles Sigma d'exemple\*\*", sigma_exemples, "s")]
    justes = {"README.md": "**2 sample Sigma rules**", "README.fr.md": "**2 règles Sigma d'exemple**"}
    for fautif, texte in (("README.md", "**3 sample Sigma rules**"), ("README.fr.md", "**3 règles Sigma d'exemple**")):
        lus = dict(justes, **{fautif: texte})
        d, i = juger(deux, fichiers, lambda f, l=lus: l[f])
        if len(d) != 1 or i or fautif not in d[0]:
            echecs.append(f"épreuve « compte faux dans {fautif} » : {d} {i} — la faute de cette langue n'est pas vue")
    if juger(deux, fichiers, lambda f: justes[f]) != ([], []):
        echecs.append("épreuve « deux langues justes » : accusées à tort")
    return echecs


def trancher(annonces, fichiers, lire) -> tuple[int, list[str]]:
    """Le code de sortie et les lignes à imprimer. Pur : c'est cette fonction, et non `main`, qui décide,
    pour que ses décisions soient éprouvées comme le reste."""
    if not fichiers:
        return 2, ["[comptes-de-regles] REFUSE DE CONCLURE — `git ls-files` n'a rien rendu."]
    try:
        desaccords, introuvables = juger(annonces, fichiers, lire)
    except (OSError, ValueError) as e:
        return 2, [f"[comptes-de-regles] REFUSE DE CONCLURE — lecture impossible : {e}"]
    if introuvables:
        return 2, ["[comptes-de-regles] REFUSE DE CONCLURE — phrase publiée introuvable ; mettre son motif à jour ici :"] \
            + [f"    - {e}" for e in introuvables]
    if desaccords:
        return 1, ["[comptes-de-regles] ÉCHEC — un compte publié n'est plus celui de l'arbre :"] \
            + [f"    - {e}" for e in desaccords]
    return 0, [f"[comptes-de-regles] OK — {len(annonces)} comptes publiés, tous égaux au compte de l'arbre suivi"]


def main() -> int:
    echecs = epreuves()
    if echecs:
        print("[comptes-de-regles] REFUSE DE CONCLURE — épreuve interne en échec :")
        for e in echecs:
            print(f"    - {e}")
        return 2

    def lire(chemin):
        with open(os.path.join(RACINE, chemin), encoding="utf-8") as fh:
            return fh.read()

    code, lignes = trancher(ANNONCES, suivis(RACINE), lire)
    for ligne in lignes:
        print(ligne)
    return code


if __name__ == "__main__":
    sys.exit(main())
