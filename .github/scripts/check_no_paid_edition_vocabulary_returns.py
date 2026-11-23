#!/usr/bin/env python3
"""Le vocabulaire d'une édition payante ne revient dans aucun fichier suivi.

LA DÉCISION QUE CETTE GARDE TIENT. Plume est entièrement open source sous AGPL-3.0 : pas d'édition
payante, pas de module réservé, pas de licence vendue à côté. Les capacités d'échelle, d'équipe et de
stockage sont des modules avancés OUVERTS, séparables et éteints par défaut (`ADVANCED_MODULES.md`) ; le
seul commercial est la prestation de service.

LE DÉFAUT QU'ELLE EMPÊCHE DE REVENIR. La page d'accueil renvoyait vers des « Modules Enterprise », sa
section de licence décrivait un cœur « open core » flanqué d'une « licence commerciale (disponible
séparément) », et un document entier opposait une édition communautaire à des modules vendus. Ce
vocabulaire se réécrit par habitude, dans un README, un commentaire, une page de documentation :
une règle seulement écrite ne l'en empêche pas.

LE CORPUS EST DÉRIVÉ. Tous les fichiers suivis (`git ls-files`), sans liste de répertoires : un fichier
ajouté demain est couvert par construction. Les binaires (octet NUL) sont écartés.

LA LISTE BLANCHE EST NOMMÉE ET JUGÉE DANS LES DEUX SENS. Le mot « enterprise » / « entreprise » a des
emplois légitimes — l'édition Windows d'un banc de mesure, la matrice MITRE ATT&CK Enterprise, un nom de
produit tiers, le nom d'un domaine fonctionnel livré dans le cœur. Chacun est une entrée de `ADMIS`, avec
un nom stable, le chemin où il vit, le motif de la ligne et sa raison :
  - une occurrence qu'aucune entrée ne couvre fait rougir (code 1) ;
  - une entrée qui ne couvre plus aucune occurrence fait rougir aussi (code 1) : une entrée morte
    élargit la liste sans rien admettre, et finirait par admettre ce qu'elle n'a jamais visé.

CODES DE SORTIE. `0` aucun emploi non admis, aucune entrée morte ; `1` un emploi non admis ou une entrée
morte ; `2` rien n'a été mesuré (épreuve interne en échec, `git ls-files` illisible, corpus sous le
plancher).

CE QU'ELLE NE TIENT PAS. Elle juge des mots, pas des idées : une phrase qui décrirait une fonction
bridée sans aucun de ces mots passerait. L'interface web ne porte aujourd'hui ni édition ni palier ; ce
n'est vérifié qu'à travers ce vocabulaire.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.realpath(os.path.join(ICI, "..", ".."))
CE_FICHIER = ".github/scripts/" + os.path.basename(__file__)

# Le vocabulaire d'un modèle à édition payante. Pas de borne de mot sur « enterprise » / « entreprise » :
# `COMMUNITY_VS_ENTERPRISE` ou `FOO_ENTERPRISE_BAR` doivent être vus, et `_` est un caractère de mot.
VOCABULAIRE = re.compile(
    r"enterprise|entreprise"
    r"|\bopen[ -]?core\b"
    r"|\bcommunity[ _-]?(?:edition|vs)\b|édition communautaire"
    r"|\bcommercial[ -]licen[cs]e|\blicences? commerciales?"
    r"|\bpremium connectors?|\bconnecteurs? premium"
    r"|\bpaid edition|\bédition payante\b",
    re.IGNORECASE,
)

# (nom stable, chemin (regex pleine), motif de la ligne, raison)
ADMIS = [
    ("la-garde-elle-meme", re.escape(CE_FICHIER), r".",
     "cette garde doit écrire le vocabulaire qu'elle refuse"),
    ("negation-de-l-edition-payante", r"README\.md|ADVANCED_MODULES\.md", r"sans édition payante",
     "la phrase qui dit que ce modèle n'existe pas"),
    ("windows-11-enterprise-24h2", r".+", r"Enterprise 24H2",
     "édition de Windows du banc de mesure du collecteur et de l'agent"),
    ("mitre-attack-enterprise", r"daemon/src/attack_names\.rs", r"MITRE ATT&CK \(Enterprise\)",
     "nom de la matrice MITRE ATT&CK"),
    ("splunk-enterprise-security", r"CAHIER-DES-CHARGES\.md", r"Splunk Enterprise Security",
     "nom d'un produit tiers comparé"),
    ("gouvernance-entreprise-chantier-59",
     r"daemon/src/(?:governance|handlers/governance|main|migrate|tests/governance)\.rs",
     r"#59 GOUVERNANCE ENTREPRISE",
     "nom du domaine fonctionnel #59 (legal-hold, export du ledger, rôles composables), livré dans le cœur ouvert"),
    ("gain-enterprise-elagage-froid", r"daemon/src/cold_store/(?:crypto|tests)\.rs",
     r"×10-100 enterprise|gain enterprise",
     "vocabulaire de performance d'un commentaire : le gain sur un gros volume"),
    ("profil-de-navigateur-d-entreprise",
     r"web/state\.js|\.github/scripts/web_esm_harnais\.mjs|\.github/scripts/check_no_naked_site_storage_write\.py",
     r"d'entreprise\)",
     "profil de navigateur géré par une organisation, qui interdit le stockage local"),
    ("urn-d-extension-scim-entreprise", r"daemon/src/tests/scim_patch_de_groupe_refus_temoignes\.rs",
     r"d'entreprise\) restent refusées",
     "l'extension « enterprise user » du schéma SCIM 2.0"),
    ("parc-windows-en-entreprise", r"\.github/workflows/ci\.yml", r"DOMINANTE en entreprise",
     "parc de postes d'une organisation"),
    ("public-du-collecteur-windows", r"README\.md|collectors/windows/README\.md",
     r"\(poste, entreprise, Windows Server\)|perso comme entreprise",
     "public visé par le collecteur Windows"),
    ("ca-interne-d-une-organisation", r"collectors/windows/README\.md", r"chemin d'entreprise est de poser la CA interne",
     "autorité de certification interne d'une organisation"),
    ("reseau-d-une-organisation-ia", r"docs/AI-ML-DIRECTION\.md", r"enterprise network",
     "réseau d'une organisation, qui interdit l'inférence dans le nuage"),
    ("installation-d-une-organisation-sauvegarde", r"docs/ROADMAP\.md", r"installation d'entreprise",
     "installation d'une organisation qui emploie sa propre réplication"),
]

PLANCHER_FICHIERS = 200


def suivis(racine: str) -> list[str] | None:
    try:
        sortie = subprocess.run(["git", "-C", racine, "ls-files", "-z"], capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    return [p.decode("utf-8", "surrogateescape") for p in sortie.split(b"\0") if p]


def lire_texte(racine: str, chemin: str) -> str | None:
    """Le texte d'un fichier suivi, ou None pour un binaire ou un fichier absent du disque."""
    try:
        with open(os.path.join(racine, chemin), "rb") as fh:
            octets = fh.read()
    except (IsADirectoryError, FileNotFoundError, PermissionError):
        return None
    if b"\x00" in octets:
        return None
    return octets.decode("utf-8", "replace")


def juger(textes: dict[str, str], admis) -> tuple[list[str], list[str], int]:
    """Rend (emplois non admis, entrées mortes, emplois admis). Pur."""
    compilees = [(nom, re.compile(chemin), re.compile(ligne)) for nom, chemin, ligne, _ in admis]
    servies = {nom: 0 for nom, _, _ in compilees}
    refuses, n_admis = [], 0
    for chemin, texte in sorted(textes.items()):
        for numero, ligne in enumerate(texte.splitlines(), 1):
            if not VOCABULAIRE.search(ligne):
                continue
            couvrante = next((nom for nom, rc, rl in compilees if rc.fullmatch(chemin) and rl.search(ligne)), None)
            if couvrante is None:
                refuses.append(f"{chemin}:{numero}: {ligne.strip()[:160]}")
            else:
                servies[couvrante] += 1
                n_admis += 1
    mortes = [nom for nom, n in servies.items() if n == 0]
    return refuses, mortes, n_admis


def epreuves() -> list[str]:
    """Témoins positifs et négatifs, hors du disque."""
    admis = [("w", r".+", r"Enterprise 24H2", "r"), ("m", r"a\.rs", r"ATT&CK \(Enterprise\)", "r")]
    base = {"x.md": "Windows 11 Enterprise 24H2", "a.rs": "MITRE ATT&CK (Enterprise)"}
    cas = [
        ("tout admis", {}, 0, 0),
        ("modules enterprise", {"README.md": "Modules Enterprise → doc"}, 1, 0),
        ("identifiant en majuscules", {"README.md": "[`COMMUNITY_VS_ENTERPRISE.md`]"}, 1, 0),
        ("open core", {"README.md": "Le modèle open-core"}, 1, 0),
        ("licence commerciale", {"README.md": "Licence commerciale disponible"}, 1, 0),
        ("bon motif, mauvais chemin", {"b.rs": "MITRE ATT&CK (Enterprise)"}, 1, 0),
        ("entrée morte", {"a.rs": "rien"}, 0, 1),
        ("mot sans rapport", {"c.md": "communauté, commercialement neutre"}, 0, 0),
    ]
    echecs = []
    for nom, ajout, att_r, att_m in cas:
        textes = dict(base, **ajout)
        r, m, _ = juger(textes, admis)
        if (len(r), len(m)) != (att_r, att_m):
            echecs.append(f"épreuve « {nom} » : {len(r)} refusé(s), {len(m)} morte(s) ; attendu {att_r}, {att_m}")
    return echecs


def main() -> int:
    echecs = epreuves()
    if echecs:
        print("[edition-payante] REFUSE DE CONCLURE — épreuve interne en échec :")
        for e in echecs:
            print(f"    - {e}")
        return 2
    fichiers = suivis(RACINE)
    if fichiers is None or len(fichiers) < PLANCHER_FICHIERS:
        print(f"[edition-payante] REFUSE DE CONCLURE — corpus suivi illisible ou sous le plancher "
              f"({0 if fichiers is None else len(fichiers)} < {PLANCHER_FICHIERS}).")
        return 2
    textes = {}
    for f in fichiers:
        t = lire_texte(RACINE, f)
        if t is not None:
            textes[f] = t
    refuses, mortes, n_admis = juger(textes, ADMIS)
    print(f"[edition-payante] {len(textes)} fichiers texte suivis lus, {n_admis} emploi(s) admis par "
          f"{len(ADMIS)} entrée(s) nommée(s)")
    if refuses:
        print("[edition-payante] ÉCHEC — vocabulaire d'édition payante dans un fichier suivi. Plume est "
              "entièrement AGPL, sans édition payante : reformuler (voir ADVANCED_MODULES.md), ou, pour un "
              "emploi qui n'a rien de commercial, ajouter une entrée NOMMÉE à ADMIS avec sa raison :")
        for r in refuses:
            print(f"    - {r}")
    if mortes:
        print("[edition-payante] ÉCHEC — entrée(s) de la liste blanche qui ne couvrent plus rien ; les retirer :")
        for m in mortes:
            print(f"    - {m}")
    if refuses or mortes:
        return 1
    print("[edition-payante] OK — aucun emploi non admis, aucune entrée morte")
    return 0


if __name__ == "__main__":
    sys.exit(main())
