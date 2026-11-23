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
un nom stable, le chemin où il vit, le motif de la portion admise et sa raison. Une entrée admet sa
PORTION, jamais la ligne entière : la portion est retirée, puis le vocabulaire est recherché à nouveau
dans le reste de la ligne.
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
# LE SÉPARATEUR ENTRE DEUX MOTS N'EST PAS SEULEMENT L'ESPACE ET LE TIRET ASCII : ce dépôt écrit avec le
# tiret insécable U+2011 (« AGPL‑3.0 », « add‑ons ») et l'espace insécable. Une version antérieure de cette
# garde ne voyait que l'espace et le tiret ASCII, et laissait passer « open‑core » tel que l'ancien document
# l'écrivait. `\s` couvre les espaces Unicode (U+00A0, U+202F…), la classe ajoute les tirets U+2010–U+2015
# et le signe moins U+2212.
# LE SÉPARATEUR EST UNE SUITE, PAS UN CARACTÈRE. Une version antérieure n'en admettait qu'un : « open  core »
# (deux espaces, ou espace + tiret) passait. `*` couvre zéro (« opencore »), un ou plusieurs séparateurs ;
# les lignes sont jugées une à une, donc la suite ne traverse jamais un saut de ligne.
SEP = r"[\s_\-\u2010-\u2015\u2212]*"
VOCABULAIRE = re.compile(
    r"enterprise|entreprise"
    rf"|\bopen{SEP}core\b"
    rf"|\bcommunity{SEP}(?:edition|vs)\b|[ée]ditions?{SEP}communautaires?"
    # « commercial licen » couvre license, licence, licensing, licensed ; l'ordre inverse aussi
    # (« licensed commercially », « commercially licensed »). Une version antérieure n'exigeait que
    # `licen[cs]e` et laissait passer « commercial licensing ».
    rf"|\bcommercial(?:ly)?{SEP}(?:licen|edition)|\blicen[cs](?:ed|ing){SEP}commercially\b"
    rf"|\bcommercial{SEP}(?:layer|tier|plan|version|module|feature|add{SEP}on|offering)s?\b"
    rf"|\blicences?{SEP}commerciales?|[ée]ditions?{SEP}commerciales?|\bcouches?{SEP}commerciales?"
    rf"|\b(?:pro|business|plus|professional){SEP}(?:edition|tier|plan|version)s?\b"
    rf"|[ée]ditions?{SEP}(?:pro|professionnelle|business)\b"
    rf"|\bpremium{SEP}(?:connector|module|feature|edition|tier)s?|\b(?:connecteurs?|modules?){SEP}premium"
    rf"|\bpaid{SEP}(?:edition|tier|plan|version|module|feature|add{SEP}on|licen)"
    rf"|[ée]ditions?{SEP}payantes?|\bversions?{SEP}payantes?|\blicences?{SEP}payantes?"
    rf"|\bmodules?{SEP}payants?|\bfonction(?:nalité)?s?{SEP}payantes?|\boffres?{SEP}payantes?"
    rf"|\badd{SEP}ons?{SEP}payants?|\bfreemium"
    rf"|\b(?:double|dual){SEP}licen|\blicences?{SEP}propriétaires?|\bproprietary{SEP}licen",
    re.IGNORECASE,
)

# (nom stable, chemin (regex pleine), motif de la ligne, raison)
ADMIS = [
    ("la-garde-elle-meme", re.escape(CE_FICHIER), r".+",
     "cette garde doit écrire le vocabulaire qu'elle refuse"),
    ("negation-de-l-edition-payante", r"README\.md|ADVANCED_MODULES\.md", r"sans édition payante",
     "la phrase qui dit que ce modèle n'existe pas"),
    ("negation-de-l-edition-payante-traduite", r"README\.en\.md|ADVANCED_MODULES\.en\.md", r"without a paid edition",
     "la même phrase, dans la traduction anglaise : elle nie l'édition payante"),
    ("windows-11-enterprise-24h2", r".+", r"Enterprise 24H2",
     "édition de Windows du banc de mesure du collecteur et de l'agent"),
    ("mitre-attack-enterprise", r"daemon/src/attack_names\.rs", r"MITRE ATT&CK \(Enterprise\)",
     "nom de la matrice MITRE ATT&CK"),
    ("splunk-enterprise-security", r"CAHIER-DES-CHARGES\.md", r"Splunk Enterprise Security",
     "nom d'un produit tiers comparé"),
    ("splunk-enterprise-security-traduit", r"CAHIER-DES-CHARGES\.en\.md", r"Splunk Enterprise Security",
     "le même produit tiers, dans la traduction anglaise"),
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
    ("public-du-collecteur-windows-traduit", r"README\.en\.md", r"\(desktop, enterprise, Windows Server\)",
     "le même public dans la traduction anglaise : « enterprise » y désigne un parc d'organisation, "
     "à côté des éditions de Windows, et n'a rien d'une édition de plume"),
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
    """Rend (emplois non admis, entrées mortes, emplois admis). Pur.

    UNE ENTRÉE ADMET SA PORTION, PAS LA LIGNE. La portion que son motif couvre est retirée de la ligne,
    puis le vocabulaire est recherché À NOUVEAU dans ce qui reste : un terme refusé posé sur une ligne qui
    porte aussi un emploi admis (« sans édition payante, … licence commerciale … ») reste refusé. Une
    entrée n'est comptée servie que si son retrait a fait disparaître au moins un emploi.
    """
    compilees = [(nom, re.compile(chemin), re.compile(ligne)) for nom, chemin, ligne, _ in admis]
    servies = {nom: 0 for nom, _, _ in compilees}
    refuses, n_admis = [], 0
    for chemin, texte in sorted(textes.items()):
        for numero, ligne in enumerate(texte.splitlines(), 1):
            if not VOCABULAIRE.search(ligne):
                continue
            reste = ligne
            for nom, rc, rl in compilees:
                if not rc.fullmatch(chemin):
                    continue
                avant = len(VOCABULAIRE.findall(reste))
                apres_retrait = rl.sub(lambda m: "\x00" * len(m.group(0)), reste)
                if len(VOCABULAIRE.findall(apres_retrait)) < avant:
                    servies[nom] += 1
                    n_admis += 1
                    reste = apres_retrait
            if VOCABULAIRE.search(reste):
                refuses.append(f"{chemin}:{numero}: {ligne.strip()[:160]}")
    mortes = [nom for nom, n in servies.items() if n == 0]
    return refuses, mortes, n_admis


def trancher(fichiers, lire, admis, plancher: int) -> tuple[int, list[str]]:
    """Le code de sortie et les lignes à imprimer, à partir du corpus. Pur : le disque n'est lu qu'à
    travers `lire` ; c'est cette fonction, et non `main`, qui décide, pour que ses décisions soient
    éprouvées comme le reste."""
    if fichiers is None or len(fichiers) < plancher:
        return 2, [f"[edition-payante] REFUSE DE CONCLURE — corpus suivi illisible ou sous le plancher "
                   f"({0 if fichiers is None else len(fichiers)} < {plancher})."]
    textes = {}
    for f in fichiers:
        t = lire(f)
        if t is not None:
            textes[f] = t
    refuses, mortes, n_admis = juger(textes, admis)
    lignes = [f"[edition-payante] {len(textes)} fichiers texte suivis lus, {n_admis} emploi(s) admis par "
              f"{len(admis)} entrée(s) nommée(s)"]
    if refuses:
        lignes.append("[edition-payante] ÉCHEC — vocabulaire d'édition payante dans un fichier suivi. Plume est "
                      "entièrement AGPL, sans édition payante : reformuler (voir ADVANCED_MODULES.md), ou, pour un "
                      "emploi qui n'a rien de commercial, ajouter une entrée NOMMÉE à ADMIS avec sa raison :")
        lignes += [f"    - {r}" for r in refuses]
    if mortes:
        lignes.append("[edition-payante] ÉCHEC — entrée(s) de la liste blanche qui ne couvrent plus rien ; les retirer :")
        lignes += [f"    - {m}" for m in mortes]
    if refuses or mortes:
        return 1, lignes
    lignes.append("[edition-payante] OK — aucun emploi non admis, aucune entrée morte")
    return 0, lignes


def epreuves() -> list[str]:
    """Témoins positifs et négatifs, hors du disque."""
    admis = [("w", r".+", r"Enterprise 24H2", "r"), ("m", r"a\.rs", r"ATT&CK \(Enterprise\)", "r")]
    base = {"x.md": "Windows 11 Enterprise 24H2", "a.rs": "MITRE ATT&CK (Enterprise)"}
    cas = [
        ("tout admis", {}, 0, 0),
        ("modules enterprise", {"README.md": "Modules Enterprise → doc"}, 1, 0),
        ("identifiant en majuscules", {"README.md": "[`COMMUNITY_VS_ENTERPRISE.md`]"}, 1, 0),
        ("open core", {"README.md": "Le modèle open-core"}, 1, 0),
        ("open core, tiret insécable U+2011", {"README.md": "a copyleft open\u2011core model"}, 1, 0),
        ("open core, espace insécable", {"README.md": "an open\u00a0core model"}, 1, 0),
        ("community edition, tiret insécable", {"README.md": "the community\u2011edition"}, 1, 0),
        ("commercial license, tiret insécable", {"README.md": "a commercial\u2011license"}, 1, 0),
        ("commercial licensing", {"README.md": "can obtain commercial licensing."}, 1, 0),
        ("licensed commercially", {"README.md": "The advanced modules are licensed commercially."}, 1, 0),
        ("commercially licensed", {"README.md": "a commercially licensed module"}, 1, 0),
        ("commercial layer", {"README.md": "the commercial layer adds SSO"}, 1, 0),
        ("couche commerciale", {"README.md": "la couche commerciale ajoute le SSO"}, 1, 0),
        ("Pro edition", {"README.md": "A Pro edition adds SSO."}, 1, 0),
        ("édition Pro", {"README.md": "l'édition Pro ajoute le SSO"}, 1, 0),
        ("open core, deux espaces", {"README.md": "an open  core model"}, 1, 0),
        ("open core, espace et tiret", {"README.md": "an open -core model"}, 1, 0),
        ("open core, soudé", {"README.md": "an opencore model"}, 1, 0),
        ("licence commerciale", {"README.md": "Licence commerciale disponible"}, 1, 0),
        ("version payante", {"README.md": "La version payante ajoute le SSO"}, 1, 0),
        ("double licence", {"README.md": "double licence AGPL ou autre"}, 1, 0),
        ("dual licensing", {"README.md": "offered under dual licensing"}, 1, 0),
        ("licence propriétaire", {"README.md": "sous licence propriétaire"}, 1, 0),
        ("modules payants", {"README.md": "des modules payants"}, 1, 0),
        ("terme refusé sur une ligne admise", {"x.md": "Windows 11 Enterprise 24H2, modules Enterprise sous licence"}, 1, 0),
        ("deux termes refusés sur une ligne admise", {"x.md": "Enterprise 24H2 ; licence commerciale"}, 1, 0),
        ("bon motif, mauvais chemin", {"b.rs": "MITRE ATT&CK (Enterprise)"}, 1, 0),
        ("entrée morte", {"a.rs": "rien"}, 0, 1),
        ("bon chemin, terme refusé hors du motif", {"a.rs": "ATT&CK (Enterprise) mais open core"}, 1, 0),
        ("mot sans rapport", {"c.md": "communauté, commercialement neutre, propriétaire du fichier"}, 0, 0),
        # « offre commerciale » n'est pas refusé : c'est le nom de la prestation de service, seul commercial réel.
        ("mots voisins sans rapport",
         {"c.md": "a production version, a provisioning plan, licensed under AGPL, l'offre commerciale de service"}, 0, 0),
    ]
    echecs = []
    for nom, ajout, att_r, att_m in cas:
        textes = dict(base, **ajout)
        r, m, _ = juger(textes, admis)
        if (len(r), len(m)) != (att_r, att_m):
            echecs.append(f"épreuve « {nom} » : {len(r)} refusé(s), {len(m)} morte(s) ; attendu {att_r}, {att_m}")
    # Les décisions de sortie, éprouvées par `trancher` : sans elles, un `main` qui oublierait les entrées
    # mortes ou le plancher rendrait vert un arbre cassé.
    corpus = dict(base)
    lire = lambda f: corpus.get(f)
    sorties = [
        ("arbre propre", list(base), 1, 0),
        ("emploi refusé", list(base) + ["r.md"], 1, 1),
        ("entrée morte seule", ["x.md"], 1, 1),
        ("corpus sous le plancher", list(base), 3, 2),
        ("corpus illisible", None, 1, 2),
    ]
    corpus["r.md"] = "open core"
    for nom, fichiers, plancher, attendu in sorties:
        code, _ = trancher(fichiers, lire, admis, plancher)
        if code != attendu:
            echecs.append(f"épreuve de sortie « {nom} » : code {code}, attendu {attendu}")
    return echecs


def main() -> int:
    echecs = epreuves()
    if echecs:
        print("[edition-payante] REFUSE DE CONCLURE — épreuve interne en échec :")
        for e in echecs:
            print(f"    - {e}")
        return 2
    code, lignes = trancher(suivis(RACINE), lambda f: lire_texte(RACINE, f), ADMIS, PLANCHER_FICHIERS)
    for ligne in lignes:
        print(ligne)
    return code


if __name__ == "__main__":
    sys.exit(main())
