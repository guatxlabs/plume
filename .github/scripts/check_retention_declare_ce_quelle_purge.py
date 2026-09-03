#!/usr/bin/env python3
"""`P4.9-a` — UN LEVIER DE RÉTENTION DÉCLARE TOUTES LES TABLES QU'IL PURGE.

CE QUI A ÉTÉ MESURÉ. Un lot a lu les NOMS des leviers de bonne foi et publié un horizon optimiste
d'un facteur quarante-cinq ; son témoin était vert parce qu'il vérifiait une constante contre
elle-même. Recensement dérivé du 2026-09-04, en suivant les instructions de suppression et jamais
les noms : TROIS des cinq leviers déclaraient moins qu'ils ne gouvernent — un nom qui porte
« metric » et purge le PRÉ-AGRÉGÉ (la table brute étant purgée par un voisin, en HEURES), un levier
qui purge TROIS tables en n'en nommant qu'une, un autre qui n'atteint que les alertes déjà traitées.

LA PROPRIÉTÉ TENUE, ET POURQUOI ELLE N'EST PAS CELLE QU'ON ÉCRIT D'ABORD. « Un levier nomme une
table qu'il gouverne » est trop faible : le levier des événements la satisferait tout en taisant deux
tables sur trois. La propriété est donc : **l'ensemble des tables purgées par la passe de rétention
est EXACTEMENT l'ensemble déclaré**, dans les deux sens — une purge ajoutée sans déclaration fait
rougir, une déclaration devenue fausse aussi.

CE QUI EST DÉRIVÉ, ET DE QUOI. Les clés viennent de `RETENTION_FIELDS`, les tables purgées viennent
du CORPS de la passe de rétention (les appels de purge et les instructions de suppression), et la
déclaration est ce qu'on compare aux deux. Aucun nom de table n'est écrit dans cette garde.

CE QUE CETTE GARDE NE TIENT PAS, ÉCRIT POUR ÊTRE OPPOSABLE :
  - elle voit les purges ÉCRITES DANS LE CORPS de la passe ; ce qu'une fonction APPELÉE supprime de
    son côté (le vieillissement vers le tier froid, par exemple) lui échappe — c'est une autre
    propriété, et la confondre ferait accuser à tort ;
  - elle ne vérifie pas QUEL levier gouverne QUELLE table, seulement que l'union coïncide : rattacher
    chaque table à son levier demanderait de suivre les variables de borne, et une garde qui se
    tromperait de rattachement serait pire que pas de garde ;
  - elle ne dit rien des UNITÉS ni des prédicats (« seulement les alertes déjà traitées ») : ceux-là
    vivent dans la déclaration et dans la documentation, à la lecture d'un humain.

Sorties : 0 = déclaration exacte · 1 = REFUS nommé · 2 = REFUS DE CONCLURE.
"""
import re
import sys
from pathlib import Path

MAIN = Path("daemon/src/main.rs")
PASSE = Path("daemon/src/rollups.rs")
FONCTION = "fn retention_run_tenant"


def sans_commentaire(src: str) -> str:
    """Les lignes de commentaire sont RETIRÉES : une purge citée dans une explication n'est pas une
    purge, et une garde qui les confond accuse le texte qui la documente."""
    return "\n".join(re.sub(r"//.*$", "", l) for l in src.split("\n"))


def cles_declarees(src: str) -> list:
    bloc = re.search(r"RETENTION_FIELDS[^=]*=\s*\[(.*?)\n\];", src, re.S)
    return re.findall(r'\(\s*"([a-z_][a-z0-9_]*)"', bloc.group(1)) if bloc else []


def portee_declaree(src: str) -> dict:
    bloc = re.search(r"RETENTION_PORTEE[^=]*=\s*\[(.*?)\n\];", src, re.S)
    if not bloc:
        return {}
    out = {}
    for cle, tables in re.findall(r'\(\s*"([a-z_][a-z0-9_]*)"\s*,\s*&\[([^\]]*)\]\s*\)', bloc.group(1)):
        out[cle] = sorted(set(re.findall(r'"([a-z_][a-z0-9_]*)"', tables)))
    return out


def corps_de_la_passe(src: str) -> str:
    """Le CORPS de la passe de rétention, borné à sa propre fonction : une purge écrite ailleurs dans
    le fichier n'est pas de la rétention."""
    i = src.find(FONCTION)
    if i < 0:
        return ""
    j = src.find("\npub(crate) fn ", i + 1)
    k = src.find("\nfn ", i + 1)
    fins = [x for x in (j, k) if x > 0]
    return src[i : min(fins)] if fins else src[i:]


def tables_purgees(corps: str) -> list:
    """Les tables que la passe supprime, DÉRIVÉES de ses appels de purge et de ses instructions."""
    t = set()
    t |= set(re.findall(r'chunked_purge\(\s*db\s*,\s*"([a-z_][a-z0-9_]*)"', corps))
    t |= set(re.findall(r'retention_prune_table\(\s*db\s*,\s*"([a-z_][a-z0-9_]*)"', corps))
    t |= set(re.findall(r'DELETE\s+FROM\s+([a-z_][a-z0-9_]*)', corps))
    return sorted(t)


def valider_linstrument() -> list:
    faux = []
    if cles_declarees('const RETENTION_FIELDS: [x; 1] = [\n    ("a_days", "E", 1, 2, 3),\n];') != ["a_days"]:
        faux.append("lecture des clés cassée")
    p = portee_declaree('const RETENTION_PORTEE: [x; 1] = [\n    ("a_days", &["t1", "t2"]),\n];')
    if p != {"a_days": ["t1", "t2"]}:
        faux.append(f"lecture de la portée cassée : {p!r}")
    if portee_declaree("rien") != {}:
        faux.append("une source sans portée devrait rendre un dictionnaire vide")

    corps = 'fn retention_run_tenant() {\n  chunked_purge(db, "alpha", ..);\n  retention_prune_table(db, "beta", ..);\n  conn.execute("DELETE FROM gamma WHERE ts < ?1");\n}\nfn autre() {\n  chunked_purge(db, "hors_passe", ..);\n}\n'
    vus = tables_purgees(corps_de_la_passe(corps))
    if vus != ["alpha", "beta", "gamma"]:
        faux.append(f"extraction des purges cassée : {vus!r}")
    if "hors_passe" in vus:
        faux.append("une purge HORS de la passe ne doit pas être comptée")
    commente = 'fn retention_run_tenant() {\n  // chunked_purge(db, "citee_en_commentaire", ..);\n  chunked_purge(db, "vraie", ..);\n}\n'
    vus2 = tables_purgees(corps_de_la_passe(sans_commentaire(commente)))
    if vus2 != ["vraie"]:
        faux.append(f"une purge CITÉE en commentaire est comptée à tort : {vus2!r}")
    return faux


def main() -> int:
    faux = valider_linstrument()
    if faux:
        for f in faux:
            print(f"::error::instrument invalide — {f}")
        print("\nLa garde ne peut pas conclure : elle ne se croit pas elle-même.")
        return 2

    for f in (MAIN, PASSE):
        if not f.exists():
            print(f"::error::{f} est introuvable — aucun verdict possible.")
            return 2

    src_main = MAIN.read_text(encoding="utf-8")
    cles = cles_declarees(src_main)
    portee = portee_declaree(src_main)
    if not cles or not portee:
        print("::error::`RETENTION_FIELDS` ou `RETENTION_PORTEE` n'est plus lisible dans la source.")
        return 2

    corps = corps_de_la_passe(sans_commentaire(PASSE.read_text(encoding="utf-8")))
    if not corps:
        print(f"::error::le corps de `{FONCTION}` est introuvable — la garde ne juge rien.")
        return 2
    purgees = tables_purgees(corps)
    if not purgees:
        print("::error::aucune purge trouvée dans la passe de rétention — l'extraction est aveugle.")
        return 2

    defauts = []
    for c in cles:
        if c not in portee:
            defauts.append(f"::error::le levier `{c}` n'a AUCUNE portée déclarée : ajoutez les tables qu'il purge à `RETENTION_PORTEE`.")
    for c in portee:
        if c not in cles:
            defauts.append(f"::error::`RETENTION_PORTEE` déclare `{c}`, qui n'est pas un levier de `RETENTION_FIELDS`.")

    declarees = sorted({t for ts in portee.values() for t in ts})
    for t in purgees:
        if t not in declarees:
            defauts.append(f"::error::la passe de rétention purge `{t}`, qu'AUCUN levier ne déclare. Le périmètre déclaré doit couvrir TOUTES les tables purgées.")
    for t in declarees:
        if t not in purgees:
            defauts.append(f"::error::`{t}` est déclarée gouvernée, mais la passe de rétention ne la purge plus : la déclaration est devenue fausse.")

    if defauts:
        for d in defauts:
            print(d)
        print(f"\n{len(defauts)} divergence(s) entre ce qu'un levier DÉCLARE et ce que la rétention PURGE.")
        return 1

    print(
        f"{len(cles)} levier(s) de rétention, {len(declarees)} table(s) déclarée(s), "
        f"{len(purgees)} table(s) réellement purgée(s) par la passe : les deux ensembles coïncident."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
