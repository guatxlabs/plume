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

# LA DÉCLARATION VIT DANS UN SEUL FICHIER, ET C'EST LE PLUS RICHE (il porte aussi les UNITÉS).
# Une seconde table disant la même chose a existé quelques heures dans `main.rs` le 2026-09-04 : elle a
# été retirée, parce que deux déclarations d'une même relation dérivent — le défaut de `P8.9-n`.
DECLARATION = Path("daemon/src/handlers/panneau_avoue.rs")

# LES DEUX SITES QUI SUPPRIMENT DES LIGNES AU TITRE DU CYCLE DE VIE, mesurés le 2026-09-04 : la passe
# de rétention, et le vieillissement vers le tier froid — qui purge `event` depuis une fonction APPELÉE,
# donc invisible à un balayage borné à la passe. La liste sert de CONTRAT : un troisième site qui
# appellerait une aide de purge fait rougir tant qu'il n'est pas nommé ici et sa table déclarée.
SITES_DU_CYCLE_DE_VIE = [PASSE, Path("daemon/src/cold_store/aging.rs")]


def sans_commentaire(src: str) -> str:
    """Les lignes de commentaire sont RETIRÉES : une purge citée dans une explication n'est pas une
    purge, et une garde qui les confond accuse le texte qui la documente."""
    return "\n".join(re.sub(r"//.*$", "", l) for l in src.split("\n"))


def cles_declarees(src: str) -> list:
    bloc = re.search(r"RETENTION_FIELDS[^=]*=\s*\[(.*?)\n\];", src, re.S)
    return re.findall(r'\(\s*"([a-z_][a-z0-9_]*)"', bloc.group(1)) if bloc else []


def portee_declaree(src: str) -> dict:
    """La déclaration UNIQUE, lue telle qu'elle est écrite — `(table, clé, unité)` — et INVERSÉE en
    `clé -> [tables]`. L'inversion se fait ici et nulle part ailleurs : c'est ce qui évite d'entretenir
    une seconde table dans l'autre sens."""
    bloc = re.search(r"FAMILLES_DE_RETENTION[^=]*=\s*&\[(.*?)\n\];", src, re.S)
    if not bloc:
        return {}
    out = {}
    for table, cle in re.findall(r'\(\s*"([a-z_][a-z0-9_]*)"\s*,\s*"([a-z_][a-z0-9_]*)"\s*,', bloc.group(1)):
        out.setdefault(cle, []).append(table)
    return {c: sorted(set(t)) for c, t in out.items()}


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


def tables_par_les_aides(src: str) -> list:
    """Les tables supprimées par les AIDES DE PURGE — le canal du cycle de vie. Mesuré le 2026-09-04 :
    ces aides ne sont appelées que depuis deux fichiers, ce qui en fait une population sûre."""
    t = set()
    t |= set(re.findall(r'chunked_purge\(\s*\n?\s*db\s*,\s*\n?\s*"([a-z_][a-z0-9_]*)"', src))
    t |= set(re.findall(r'retention_prune_table\(\s*\n?\s*db\s*,\s*\n?\s*"([a-z_][a-z0-9_]*)"', src))
    return sorted(t)


def tables_par_instruction(corps: str) -> list:
    """Les tables supprimées par une instruction ÉCRITE À LA MAIN, cherchées UNIQUEMENT dans le corps de
    la passe. Les élargir au fichier entier accuserait des suppressions qui ne relèvent pas du cycle de
    vie — mesuré : plus de soixante-dix instructions de suppression dans le démon, presque toutes des
    gestes légitimes d'utilisateur. Une garde qui les compterait serait une rançon."""
    return sorted(set(re.findall(r'DELETE\s+FROM\s+([a-z_][a-z0-9_]*)', corps)))


def fichiers_qui_purgent(racine: Path) -> list:
    """Quels fichiers de PRODUCTION appellent une aide de purge — la population, DÉRIVÉE de l'arbre."""
    out = []
    for f in sorted(racine.rglob("*.rs")):
        if "/tests/" in str(f) or f.name == "tests.rs":
            continue
        # LE MÊME PRÉDICAT QUE L'EXTRACTION, et pas un autre : un fichier « purge » s'il en résulte une
        # TABLE. Écarter les fichiers qui DÉFINISSENT une aide était trop grossier — la passe de
        # rétention définit l'une d'elles ET l'appelle douze fois, et se serait exclue elle-même.
        src = sans_commentaire(f.read_text(encoding="utf-8", errors="replace"))
        if tables_par_les_aides(src):
            out.append(f)
    return out


def valider_linstrument() -> list:
    faux = []
    if cles_declarees('const RETENTION_FIELDS: [x; 1] = [\n    ("a_days", "E", 1, 2, 3),\n];') != ["a_days"]:
        faux.append("lecture des clés cassée")
    # LES NOMS FABRIQUÉS NE RESSEMBLENT PAS AUX NOMS RÉELS, ET C'EST DÉLIBÉRÉ : le 2026-09-04, un
    # fixture portant des chiffres (`t1`, `t2`) a révélé que la classe de caractères de cette garde
    # excluait les chiffres — invisible sur les tables du produit, qui n'en portent aucun. Un corpus
    # calqué sur l'existant valide l'accord avec l'existant, pas la correction.
    p = portee_declaree(
        'pub(crate) const FAMILLES_DE_RETENTION: &[(&str, &str, i64)] = &[\n'
        '    ("t1", "a_days", 86_400),\n    ("t2", "a_days", 86_400),\n    ("t3", "b_hours", 3_600),\n];'
    )
    if p != {"a_days": ["t1", "t2"], "b_hours": ["t3"]}:
        faux.append(f"lecture de la portée cassée : {p!r}")
    if portee_declaree("rien") != {}:
        faux.append("une source sans portée devrait rendre un dictionnaire vide")

    src = 'fn retention_run_tenant() {\n  chunked_purge(db, "alpha", ..);\n  retention_prune_table(db, "beta", ..);\n  conn.execute("DELETE FROM gamma WHERE ts < ?1");\n}\nfn autre() {\n  chunked_purge(db, "ailleurs", ..);\n  conn.execute("DELETE FROM geste_utilisateur WHERE id=?1");\n}\n'
    aides = tables_par_les_aides(src)
    if aides != ["ailleurs", "alpha", "beta"]:
        faux.append(f"extraction par les AIDES cassée : {aides!r}")
    instr = tables_par_instruction(corps_de_la_passe(src))
    if instr != ["gamma"]:
        faux.append(f"extraction par INSTRUCTION cassée : {instr!r}")
    if "geste_utilisateur" in instr:
        faux.append("une suppression HORS de la passe est comptée comme rétention")
    commente = 'fn retention_run_tenant() {\n  // chunked_purge(db, "citee_en_commentaire", ..);\n  chunked_purge(db, "vraie", ..);\n}\n'
    if tables_par_les_aides(sans_commentaire(commente)) != ["vraie"]:
        faux.append("une purge CITÉE en commentaire est comptée à tort")
    # UN APPEL ÉCRIT SUR PLUSIEURS LIGNES DOIT ÊTRE VU : c'est la forme du site du tier froid.
    multi = 'chunked_purge(\n    db,\n    "sur_plusieurs_lignes",\n    &format!("..."),\n);'
    if tables_par_les_aides(multi) != ["sur_plusieurs_lignes"]:
        faux.append("un appel de purge écrit sur plusieurs lignes échappe à l'extraction")
    return faux


def main() -> int:
    faux = valider_linstrument()
    if faux:
        for f in faux:
            print(f"::error::instrument invalide — {f}")
        print("\nLa garde ne peut pas conclure : elle ne se croit pas elle-même.")
        return 2

    for f in [MAIN, DECLARATION] + SITES_DU_CYCLE_DE_VIE:
        if not f.exists():
            print(f"::error::{f} est introuvable — aucun verdict possible.")
            return 2

    cles = cles_declarees(MAIN.read_text(encoding="utf-8"))
    portee = portee_declaree(DECLARATION.read_text(encoding="utf-8"))
    if not cles or not portee:
        print(f"::error::les leviers ({MAIN}) ou leur portée ({DECLARATION}) ne sont plus lisibles.")
        return 2

    # LA POPULATION DES SITES EST DÉRIVÉE DE L'ARBRE, PAS RECOPIÉE : un troisième fichier qui se
    # mettrait à purger fait rougir tant qu'il n'est pas nommé et sa table déclarée.
    trouves = fichiers_qui_purgent(Path("daemon/src"))
    attendus = sorted(str(f) for f in SITES_DU_CYCLE_DE_VIE)
    if sorted(str(f) for f in trouves) != attendus:
        for f in trouves:
            if str(f) not in attendus:
                print(f"::error::{f} appelle une aide de purge et n'est pas un site du cycle de vie déclaré. "
                      "Nommez-le dans la garde ET déclarez la table qu'il purge, ou n'employez pas ces aides.")
        for a in attendus:
            if a not in [str(f) for f in trouves]:
                print(f"::error::{a} est déclaré site du cycle de vie mais n'appelle plus aucune aide de purge.")
        print("\nLa population des sites qui suppriment a changé.")
        return 1

    purgees = set()
    for f in SITES_DU_CYCLE_DE_VIE:
        purgees |= set(tables_par_les_aides(sans_commentaire(f.read_text(encoding="utf-8"))))
    corps = corps_de_la_passe(sans_commentaire(PASSE.read_text(encoding="utf-8")))
    if not corps:
        print(f"::error::le corps de `{FONCTION}` est introuvable — la garde ne juge rien.")
        return 2
    purgees |= set(tables_par_instruction(corps))
    purgees = sorted(purgees)
    if not purgees:
        print("::error::aucune purge trouvée — l'extraction est aveugle.")
        return 2

    defauts = []
    for c in cles:
        if c not in portee:
            defauts.append(f"::error::le levier `{c}` n'a AUCUNE portée déclarée dans {DECLARATION}.")
    for c in portee:
        if c not in cles:
            defauts.append(f"::error::{DECLARATION} déclare `{c}`, qui n'est pas un levier de `RETENTION_FIELDS`.")

    declarees = sorted({t for ts in portee.values() for t in ts})
    for t in purgees:
        if t not in declarees:
            defauts.append(f"::error::le cycle de vie purge `{t}`, qu'AUCUN levier ne déclare. Le périmètre "
                           "déclaré doit couvrir TOUTES les tables purgées.")
    for t in declarees:
        if t not in purgees:
            defauts.append(f"::error::`{t}` est déclarée gouvernée, mais plus aucun site ne la purge : "
                           "la déclaration est devenue fausse.")

    if defauts:
        for d in defauts:
            print(d)
        print(f"\n{len(defauts)} divergence(s) entre ce qu'un levier DÉCLARE et ce que le cycle de vie PURGE.")
        return 1

    print(
        f"{len(cles)} levier(s), {len(declarees)} table(s) déclarée(s) dans {DECLARATION.name}, "
        f"{len(purgees)} table(s) réellement purgée(s) par {len(SITES_DU_CYCLE_DE_VIE)} site(s) du cycle "
        "de vie : les deux ensembles coïncident."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
