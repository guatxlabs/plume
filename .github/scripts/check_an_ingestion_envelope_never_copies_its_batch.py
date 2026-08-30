#!/usr/bin/env python3
"""Une enveloppe d'ingestion qui RECOPIE son lot le paie au pire moment, et rien ne le dit.

LE DÉFAUT, MESURÉ LE 2026-08-30 (`P6.9-c`). Cinq surfaces d'ingestion décodent un lot d'événements
puis le publient au spool. Chacune construisait son enveloppe par la macro de sérialisation de
`serde_json`. Le bras de repli de cette macro emprunte son opérande et le rend par `to_value` : l'arbre
est RECOPIÉ EN PROFONDEUR, et l'original — emprunté, donc jamais consommé — reste vivant à côté de sa
copie. Le lot existait en deux exemplaires.

CE QUI REND LA RECOPIE COÛTEUSE EST L'INSTANT, PAS LA TAILLE. Elle tombe là où l'empreinte de la
requête est maximale : le corps décompressé et l'arbre décodé sont encore vivants (vérifié par une
sonde de compilation qui les lit APRÈS le point de suspension de la publication). Le second exemplaire
s'AJOUTE au pic ; il ne le remplace pas.

CE QUE CETTE GARDE REFUSE, ET SUR QUELLE POPULATION.
  * LE CRITÈRE DE POPULATION EST ÉCRIT, PAS ÉNUMÉRÉ. Une SURFACE DE SPOOL est un fichier source du
    démon qui appelle le point de publication du spool. Aucune liste de noms de fichiers : un
    récepteur poussé neuf entre dans la population le jour où il publie, sans qu'on pense à l'y
    inscrire. Si ce critère cesse de désigner quoi que ce soit, la garde REFUSE DE CONCLURE au lieu
    d'afficher un vert vide.
  * LE REFUS. Dans une telle surface, trois constructions recopient un lot et sont refusées :
      1. une invocation de la macro de sérialisation qui porte À LA FOIS le marqueur de régime
         (le champ `kind` valué au littéral des events) ET un champ `events` dont la valeur est un
         BINDING NOMMÉ — c'est-à-dire un lot déjà construit ailleurs, que la macro va dupliquer ;
      2. un champ `events` dont la valeur est obtenue par duplication explicite ;
      3. un champ `events` dont la valeur repasse par la conversion empruntante de `serde_json`.
  * CE QUI N'EST PAS REFUSÉ, DÉLIBÉRÉMENT : un tableau LITTÉRAL dans la macro. Il est construit sur
    place, il n'y a rien à dupliquer, et le refuser ferait de cette garde une règle de style.

CE QU'ELLE NE TIENT PAS — lire avant de lui faire confiance :
  * elle lit la FORME DE LA SOURCE, pas le comportement : elle ne mesure aucune allocation. La
    propriété elle-même (identité d'adresse du lot entre l'avant et l'enveloppe) est épinglée par un
    témoin Rust, pas ici ;
  * elle ne voit qu'un lot passé par un NOM. Un lot passé par un appel de fonction lui échappe ;
  * elle ne distingue pas le code de production d'un bloc de test à l'intérieur d'une surface de
    spool ;
  * elle ne dit rien des enveloppes construites dans un fichier qui ne publie pas lui-même.
"""
import os, re, sys

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.realpath(os.path.join(ICI, "..", ".."))
SOURCE = os.path.join(RACINE, "daemon", "src")

# Le point de publication du spool : ce qui FAIT d'un fichier une surface de spool.
POINT_DE_PUBLICATION = re.compile(r"\bspool\s*::\s*publier\b")
# La macro de sérialisation de serde_json, nommée sans être recopiée en exemple.
MACRO = re.compile(r"\bjson\s*!\s*")
# Le régime d'enveloppe visé, et le champ qui porte le lot.
CLE_REGIME = "kind"
LITTERAL_REGIME = "events"
CLE_LOT = "events"
# Un binding nommé : identifiant simple ou chemin de champs, sans appel ni indexation.
NOM = re.compile(r"^&?\s*[A-Za-z_][A-Za-z0-9_]*(\s*\.\s*[A-Za-z_][A-Za-z0-9_]*)*$")
# Les deux autres formes de recopie, nommées par leur GESTE.
DUPLICATION = re.compile(r"\.\s*(clone|to_vec|to_owned)\s*\(")
CONVERSION_EMPRUNTANTE = re.compile(r"\bto_value\s*\(\s*&")

OUVRANTS = {"(": ")", "[": "]", "{": "}"}
FERMANTS = {")": "(", "]": "[", "}": "{"}


def sans_commentaires(src):
    """Neutralise les commentaires Rust en préservant la LONGUEUR et les sauts de ligne.

    Préserver la longueur est ce qui permet de rendre un numéro de ligne exact ; neutraliser au lieu
    de supprimer est ce qui empêche une garde de compter une CITATION comme un site : un bandeau qui
    décrit le défaut ne doit pas le déclencher.
    """
    out = list(src)
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c == '"':
            # chaîne (brute ou non) : on la traverse sans y voir de commentaire
            if i >= 1 and src[i - 1] == 'r' or (i >= 2 and src[i - 2] == 'r' and src[i - 1] == '#'):
                pass
            i += 1
            while i < n:
                if src[i] == "\\":
                    i += 2
                    continue
                if src[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        if c == "'":
            # littéral de caractère OU durée de vie : on n'avale que la forme 'x' / '\x'
            m = re.match(r"'(\\.|[^\\'])'", src[i:])
            if m:
                i += m.end()
                continue
            i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            prof = 0
            while i < n:
                if src[i] == "/" and i + 1 < n and src[i + 1] == "*":
                    prof += 1
                    out[i] = out[i + 1] = " "
                    i += 2
                    continue
                if src[i] == "*" and i + 1 < n and src[i + 1] == "/":
                    prof -= 1
                    out[i] = out[i + 1] = " "
                    i += 2
                    if prof == 0:
                        break
                    continue
                if src[i] != "\n":
                    out[i] = " "
                i += 1
            continue
        i += 1
    return "".join(out)


def groupe_equilibre(src, debut):
    """Depuis l'ouvrant à `debut`, rend l'index APRÈS le fermant apparié (chaînes traversées)."""
    pile = [src[debut]]
    i = debut + 1
    n = len(src)
    while i < n and pile:
        c = src[i]
        if c == '"':
            i += 1
            while i < n:
                if src[i] == "\\":
                    i += 2
                    continue
                if src[i] == '"':
                    break
                i += 1
            i += 1
            continue
        if c in OUVRANTS:
            pile.append(c)
        elif c in FERMANTS:
            if pile and pile[-1] == FERMANTS[c]:
                pile.pop()
            else:
                return None
        i += 1
    return i if not pile else None


def paires(interieur):
    """Rend les couples (clé, expression de valeur) au niveau SUPÉRIEUR d'un corps d'objet."""
    txt = interieur.strip()
    if txt.startswith("{"):
        fin = groupe_equilibre(txt, 0)
        if fin is None:
            return []
        txt = txt[1:fin - 1]
    morceaux, prof, debut, i, n = [], 0, 0, 0, len(txt)
    while i < n:
        c = txt[i]
        if c == '"':
            i += 1
            while i < n:
                if txt[i] == "\\":
                    i += 2
                    continue
                if txt[i] == '"':
                    break
                i += 1
            i += 1
            continue
        if c in OUVRANTS:
            prof += 1
        elif c in FERMANTS:
            prof -= 1
        elif c == "," and prof == 0:
            morceaux.append(txt[debut:i])
            debut = i + 1
        i += 1
    morceaux.append(txt[debut:])
    out = []
    for m in morceaux:
        s = m.strip()
        if not s.startswith('"'):
            continue
        fin = s.find('"', 1)
        if fin < 0:
            continue
        cle = s[1:fin]
        reste = s[fin + 1:].lstrip()
        if not reste.startswith(":"):
            continue
        out.append((cle, reste[1:].strip()))
    return out


def refus_du_fichier(src):
    """Rend les refus d'un fichier DÉJÀ neutralisé : liste de (decalage, motif)."""
    trouves = []
    # 1) macro de sérialisation portant le marqueur de régime ET un lot NOMMÉ
    for m in MACRO.finditer(src):
        j = m.end()
        while j < len(src) and src[j].isspace():
            j += 1
        if j >= len(src) or src[j] not in OUVRANTS:
            continue
        fin = groupe_equilibre(src, j)
        if fin is None:
            continue
        p = paires(src[j + 1:fin - 1])
        regime = any(c == CLE_REGIME and v.strip() == f'"{LITTERAL_REGIME}"' for c, v in p)
        if not regime:
            continue
        for c, v in p:
            if c != CLE_LOT:
                continue
            if NOM.match(v.strip()):
                trouves.append((m.start(), "la macro de sérialisation EMPRUNTE puis RECOPIE le lot nommé qu'on lui confie"))
    # 2) et 3) le champ du lot alimenté par une duplication, ou par la conversion empruntante
    for m in re.finditer(r'\.\s*insert\s*\(', src):
        fin = groupe_equilibre(src, m.end() - 1)
        if fin is None:
            continue
        arg = src[m.end():fin - 1]
        if f'"{CLE_LOT}"' not in arg.split(",")[0]:
            continue
        if DUPLICATION.search(arg):
            trouves.append((m.start(), "le champ du lot est alimenté par une DUPLICATION explicite"))
        elif CONVERSION_EMPRUNTANTE.search(arg):
            trouves.append((m.start(), "le champ du lot repasse par la conversion EMPRUNTANTE de serde_json"))
    return trouves


def ligne_de(src, decalage):
    return src.count("\n", 0, decalage) + 1


# ---------------------------------------------------------------------------------------------------
# AUTO-VALIDATION — entrées FABRIQUÉES ICI, jamais l'état du dépôt.
# ---------------------------------------------------------------------------------------------------
_PUBLIE = "    crate::ingest::spool::publier(tmp, dst, corps, f).await\n"

_DEPLACE = '''fn surface() {
''' + _PUBLIE + '''    let mut e = serde_json::Map::new();
    e.insert("kind".to_string(), Value::String("events".to_string()));
    e.insert("events".to_string(), Value::Array(lot));
}
'''
_MACRO_LOT_NOMME = '''fn surface() {
''' + _PUBLIE + '''    let e = ''' + 'json' + '''!({ "ts": now(), "kind": "events", "events": lot });
}
'''
_MACRO_LOT_EMPRUNTE = '''fn surface() {
''' + _PUBLIE + '''    let e = ''' + 'json' + '''!({ "kind": "events", "events": &lot });
}
'''
_DUPLIQUE = '''fn surface() {
''' + _PUBLIE + '''    e.insert("events".to_string(), Value::Array(lot.clone()));
}
'''
_CONVERTI = '''fn surface() {
''' + _PUBLIE + '''    e.insert("events".to_string(), serde_json::to_value(&lot).unwrap());
}
'''
_LITTERAL = '''fn surface() {
''' + _PUBLIE + '''    let e = ''' + 'json' + '''!({ "kind": "events", "events": [un, deux] });
}
'''
_AUTRE_CHAMP = '''fn surface() {
''' + _PUBLIE + '''    let accuse = ''' + 'json' + '''!({ "queued": true, "events": compte });
}
'''
_HORS_POPULATION = '''fn temoin() {
    let e = ''' + 'json' + '''!({ "kind": "events", "events": lot });
}
'''
_EN_COMMENTAIRE = '''fn surface() {
''' + _PUBLIE + '''    // autrefois : la macro recevait ''' + 'json' + '''!({ "kind": "events", "events": lot })
    /* et le bandeau le redisait : ''' + 'json' + '''!({ "kind": "events", "events": lot }) */
    e.insert("events".to_string(), Value::Array(lot));
}
'''
_CHAINE_AVEC_DEUX_BARRES = '''fn surface() {
''' + _PUBLIE + '''    let u = "https://exemple/x";
    e.insert("events".to_string(), Value::Array(lot));
}
'''

EPREUVES = [
    ("déplacement (forme visée)", _DEPLACE, True, 0),
    ("macro + lot nommé", _MACRO_LOT_NOMME, True, 1),
    ("macro + lot emprunté", _MACRO_LOT_EMPRUNTE, True, 1),
    ("duplication explicite", _DUPLIQUE, True, 1),
    ("conversion empruntante", _CONVERTI, True, 1),
    ("tableau littéral dans la macro", _LITTERAL, True, 0),
    ("champ homonyme hors enveloppe", _AUTRE_CHAMP, True, 0),
    ("même défaut hors population", _HORS_POPULATION, False, 0),
    ("le défaut seulement en commentaire", _EN_COMMENTAIRE, True, 0),
    ("deux barres dans une chaîne", _CHAINE_AVEC_DEUX_BARRES, True, 0),
]


def epreuves():
    for nom, texte, dans_population, attendu in EPREUVES:
        neutre = sans_commentaires(texte)
        if len(neutre) != len(texte):
            return f"témoin « {nom} » : la neutralisation des commentaires a changé la LONGUEUR du texte"
        vue = bool(POINT_DE_PUBLICATION.search(neutre))
        if vue != dans_population:
            return f"témoin « {nom} » : population={vue}, attendu {dans_population}"
        obtenu = len(refus_du_fichier(neutre)) if vue else 0
        if obtenu != attendu:
            return f"témoin « {nom} » : {obtenu} refus, attendu {attendu}"
    if not NOM.match("lot") or not NOM.match("&lot") or NOM.match("lot.clone()") or NOM.match("[a, b]"):
        return "témoin de forme : le motif de binding nommé ne discrimine pas"
    return None


def sources(rep):
    out = []
    for dossier, _, fichiers in os.walk(rep):
        for f in sorted(fichiers):
            if f.endswith(".rs"):
                out.append(os.path.join(dossier, f))
    return sorted(out)


def main():
    faute = epreuves()
    if faute:
        print(f"::error::instrument INVALIDE, la garde REFUSE DE CONCLURE — {faute}", file=sys.stderr)
        return 2

    fichiers = sources(SOURCE)
    if not fichiers:
        print(f"::error::aucune source Rust sous {os.path.relpath(SOURCE, RACINE)} : la garde REFUSE DE CONCLURE",
              file=sys.stderr)
        return 2

    population, refus = [], []
    for chemin in fichiers:
        try:
            brut = open(chemin, encoding="utf-8").read()
        except (OSError, UnicodeDecodeError):
            print(f"::error::{os.path.relpath(chemin, RACINE)} illisible : la garde REFUSE DE CONCLURE", file=sys.stderr)
            return 2
        neutre = sans_commentaires(brut)
        if not POINT_DE_PUBLICATION.search(neutre):
            continue
        population.append(chemin)
        for decalage, motif in refus_du_fichier(neutre):
            refus.append((chemin, ligne_de(neutre, decalage), motif))

    if not population:
        print("::error::le critère de population — un fichier qui appelle le point de publication du spool — "
              "ne désigne plus aucun fichier du démon. Le critère a dérivé du code : la garde REFUSE DE "
              "CONCLURE plutôt que de rendre un vert qui ne mesure rien.", file=sys.stderr)
        return 2

    for chemin, ligne, motif in refus:
        rel = os.path.relpath(chemin, RACINE)
        print(f"::error file={rel},line={ligne}::{motif} — le lot se retrouve en DEUX exemplaires, et le "
              "second s'ajoute au pic de la requête (le corps décompressé et l'arbre décodé sont encore "
              "vivants à cet instant). Construire l'enveloppe en DÉPLAÇANT le lot.", file=sys.stderr)

    if refus:
        print(f"\n{len(refus)} enveloppe(s) d'ingestion recopie(nt) leur lot, sur {len(population)} surface(s) de "
              "spool. Le coût n'est pas la copie mais son INSTANT : elle tombe là où l'empreinte de la requête "
              "est maximale, et elle s'y AJOUTE.", file=sys.stderr)
        return 1

    print(f"check_an_ingestion_envelope_never_copies_its_batch : {len(population)} surface(s) de spool "
          "dérivée(s) du critère « ce fichier appelle le point de publication du spool » — aucune liste de noms — "
          "et aucune n'y construit une enveloppe qui recopie son lot.\n"
          "CE QU'ELLE NE TIENT PAS : elle lit la FORME de la source, jamais une allocation ; elle ne voit un lot "
          "que s'il est passé par un NOM (un lot rendu par un appel lui échappe) ; elle ne sépare pas un bloc de "
          "test d'une surface de production ; et elle ne juge pas les enveloppes bâties dans un fichier qui ne "
          "publie pas lui-même.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
