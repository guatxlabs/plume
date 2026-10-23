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

# LA DÉCOUPE PAR VIRGULE EST CELLE DU LECTEUR PARTAGÉ, IMPORTÉE ET JAMAIS RECOPIÉE (`P10.21-f`) : ce
# fichier coupait le corps de la macro sur la virgule d'un GÉNÉRIQUE, et le premier argument d'un
# `.insert(` par un `split(",")` qui ne connaissait AUCUNE profondeur. Le module importé évalue sa
# propre racine À L'IMPORT (un `git rev-parse` sans argument) : on lui passe celle de cette garde, pour
# qu'il ne cherche aucun dépôt git. Ses témoins sont JOUÉS par `epreuves()` : un import n'exécute
# aucun témoin.
sys.path.insert(0, ICI)
_ARGV = sys.argv
sys.argv = [_ARGV[0], RACINE]
try:
    from check_a_read_that_did_not_happen_is_never_served_as_a_fact import (  # noqa: E402
        apparier, arguments, temoins_des_lecteurs_de_forme)
finally:
    sys.argv = _ARGV
# `P10.21-k` — LE DÉPOUILLEMENT ET L'APPARIEMENT SONT CEUX DU LECTEUR PARTAGÉ, IMPORTÉS ET JAMAIS RECOPIÉS.
# Ce fichier portait deux copies locales : `sans_commentaires` (qui ne connaissait ni la chaîne BRUTE, ni le
# littéral de caractère échappé `'\u{…}'`/`'\x..'`) et `groupe_equilibre` (qui ne connaissait AUCUN littéral
# de caractère : le `(` de `'('` ouvrait un groupe, le `"` de `'"'` une fausse chaîne). Le lecteur partagé
# n'offre pas de dépouilleur qui garde la longueur ET les littéraux (`sans_commentaires_rust` retire la ligne
# commentée, `aveugler_litteraux_rust` blanchit aussi les littéraux) : les sites sont donc REPÉRÉS et
# APPARIÉS sur le texte aveuglé (même longueur, un commentaire ou un littéral n'y porte plus rien), et les
# morceaux LUS sur le brut aux mêmes positions, commentaires retirés par `sans_commentaires_rust`.
# MESURÉ le 2026-10-23 sur 1011ec9f, avant -> après : population 8 -> 6 surfaces — deux fichiers de témoins
# (`tests/spool_publier_formes_forcees.rs`, `tests/spool_toute_ecriture_passe_par_publier.rs`) n'y entraient
# que par le point de publication CITÉ dans une chaîne (brute pour le second, que la copie lisait comme du
# code) ; 4 034 macros d'objet et 698 `.insert(` de `daemon/src` lus à l'identique (deux macros portent un
# commentaire, blanchi avant, retiré après : mêmes valeurs aux espaces près) ; aucun refus avant ni après,
# même en jugeant CHAQUE fichier comme une surface ; aucun aveu du lecteur.
from check_every_help_trigger_has_a_section import (  # noqa: E402  (source unique de vérité)
    aveugler_litteraux_rust, refuser_sur_aveu, sans_commentaires_rust)

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

OUVRANTS = "([{"


def aveugler(src, journal=None):
    """MÊME LONGUEUR que `src`, commentaires ET littéraux blanchis : c'est le texte sur lequel les sites sont
    repérés et appariés. Préserver la longueur rend un numéro de ligne exact ; neutraliser au lieu de
    supprimer empêche une garde de compter une CITATION comme un site : un bandeau qui décrit le défaut ne
    doit pas le déclencher, une chaîne qui le cite non plus."""
    return aveugler_litteraux_rust(src, journal)


def fin_du_groupe(neutre, debut):
    """Depuis l'ouvrant à `debut` du texte aveuglé, l'index APRÈS le fermant apparié, ou None. `apparier`
    du lecteur partagé : un littéral, déjà blanchi, n'y ouvre ni ne ferme plus rien."""
    f = apparier(neutre, debut)
    return None if f < 0 else f + 1


def lu(brut, debut, fin):
    """Le morceau `[debut, fin)` du texte BRUT (littéraux intacts), commentaires retirés par le lecteur
    partagé. `debut` est une frontière de code du texte aveuglé : le dépouillement y part synchronisé."""
    return sans_commentaires_rust(brut[debut:fin])


def paires(interieur):
    """Rend les couples (clé, expression de valeur) au niveau SUPÉRIEUR d'un corps d'objet.

    Les morceaux sont découpés par `arguments`, le lecteur PARTAGÉ, sur le corps remis entre
    parenthèses : une virgule écrite dans une chaîne, un littéral de caractère ou une liste de
    GÉNÉRIQUES ne coupe pas une valeur. MESURÉ le 2026-09-23 sur l'instantané 69284b7 : 74 des 2 364
    macros d'objet de `daemon/src` se découpaient autrement pour un chevron (`"n": r.get::<_, i64>(0)`
    lu `r.get::<_`), aucune dans une surface de spool, et aucun refus ne change même si CHAQUE fichier
    de `daemon/src` était jugé comme une surface. Armé, et incapable de mordre sur ce verdict-ci : la
    valeur tronquée garde son `<` et ne passe jamais pour un NOM, et le morceau coupé ne commence pas
    par un guillemet, il ne fabrique aucune clé. La découpe est ralliée pour qu'une valeur lue soit
    une valeur ENTIÈRE, pas pour un verdict."""
    txt = interieur.strip()
    if txt.startswith("{"):
        fin = apparier(txt, 0)
        if fin < 0:
            return []
        txt = txt[1:fin]
    code = "(" + txt + ")"
    tranches, _fermante = arguments(code, 0)
    if tranches is None:
        return []
    morceaux = [code[deb:fin] for deb, fin in tranches]
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


def refus_du_fichier(brut, neutre):
    """Rend les refus d'un fichier : liste de (decalage, motif). `neutre` est `aveugler(brut)` (même
    longueur) : les sites y sont repérés et appariés, les morceaux lus sur `brut`."""
    trouves = []
    # 1) macro de sérialisation portant le marqueur de régime ET un lot NOMMÉ
    for m in MACRO.finditer(neutre):
        j = m.end()
        while j < len(neutre) and neutre[j].isspace():
            j += 1
        if j >= len(neutre) or neutre[j] not in OUVRANTS:
            continue
        fin = fin_du_groupe(neutre, j)
        if fin is None:
            continue
        p = paires(lu(brut, j + 1, fin - 1))
        regime = any(c == CLE_REGIME and v.strip() == f'"{LITTERAL_REGIME}"' for c, v in p)
        if not regime:
            continue
        for c, v in p:
            if c != CLE_LOT:
                continue
            if NOM.match(v.strip()):
                trouves.append((m.start(), "la macro de sérialisation EMPRUNTE puis RECOPIE le lot nommé qu'on lui confie"))
    # 2) et 3) le champ du lot alimenté par une duplication, ou par la conversion empruntante
    for m in re.finditer(r'\.\s*insert\s*\(', neutre):
        fin = fin_du_groupe(neutre, m.end() - 1)
        if fin is None:
            continue
        # LA CLÉ EST LE PREMIER ARGUMENT, LA VALEUR CE QUI LE SUIT, découpés par le lecteur partagé
        # (`P10.21-f`). La découpe d'origine prenait `arg.split(",")[0]` : sans profondeur, une clé
        # calculée (`format!("{}", "events")`) était coupée avant son littéral et le lot DUPLIQUÉ passait
        # (défaut MANQUÉ) ; et la duplication était cherchée dans TOUS les arguments, clé comprise, si
        # bien qu'une clé écrite `"events".to_owned()` accusait un lot DÉPLACÉ. MESURÉ le 2026-09-23 sur
        # l'instantané 69284b7 : 3 des 610 `.insert(` de `daemon/src` avaient un premier argument lu
        # autrement, aucun dans une surface, aucun refus changé ; aucune clé `"events"` n'y porte de
        # duplication. Armé dans les deux sens, pas mordant ; deux témoins fabriqués le tiennent.
        tranches, fermante = arguments(neutre, m.end() - 1)
        if not tranches:
            continue
        cle, valeur = lu(brut, tranches[0][0], tranches[0][1]), lu(brut, tranches[0][1], fermante)
        if f'"{CLE_LOT}"' not in cle:
            continue
        if DUPLICATION.search(valeur):
            trouves.append((m.start(), "le champ du lot est alimenté par une DUPLICATION explicite"))
        elif CONVERSION_EMPRUNTANTE.search(valeur):
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

# LA DÉCOUPE (`P10.21-f`) : une clé CALCULÉE dont la virgule précède le littéral, une clé qui porte
# elle-même un geste de duplication, et une valeur à GÉNÉRIQUE.
_CLE_CALCULEE_DUPLIQUE = '''fn surface() {
''' + _PUBLIE + '''    e.insert(format!("{}", "events"), Value::Array(lot.clone()));
}
'''
_CLE_POSSEDEE_DEPLACE = '''fn surface() {
''' + _PUBLIE + '''    e.insert("events".to_owned(), Value::Array(lot));
}
'''
_VALEUR_A_GENERIQUE = '''fn surface() {
''' + _PUBLIE + '''    let e = ''' + 'json' + '''!({ "n": r.get::<_, i64>(0), "kind": "events", "events": lot });
}
'''

# LE LECTEUR PARTAGÉ (`P10.21-k`) : un littéral de caractère qui porte un ouvrant DANS la macro (la copie
# `groupe_equilibre` n'appariait plus rien et la macro sortait du jugement), une chaîne BRUTE qui porte `//`
# avant l'enveloppe sur la même ligne (la copie `sans_commentaires` y voyait un commentaire et blanchissait
# l'enveloppe), un commentaire DANS le corps de la macro (lu sur le brut, il doit être retiré), et le point de
# publication seulement CITÉ dans une chaîne (ce n'est pas une surface).
_CARACTERE_DANS_LA_MACRO = '''fn surface() {
''' + _PUBLIE + '''    let e = ''' + 'json' + '''!({ "c": '(', "kind": "events", "events": lot });
}
'''
_CHAINE_BRUTE_AVANT_L_ENVELOPPE = '''fn surface() {
''' + _PUBLIE + '''    let motif = r#"x"//"#; let e = ''' + 'json' + '''!({ "kind": "events", "events": lot });
}
'''
_COMMENTAIRE_DANS_LA_MACRO = '''fn surface() {
''' + _PUBLIE + '''    let e = ''' + 'json' + '''!({ "kind": "events", // le lot, déplacé ?
        "events": lot });
}
'''
_PUBLICATION_CITEE_EN_CHAINE = '''fn temoin() {
    let cite = "crate::ingest::spool::publier(tmp, dst, corps, f)";
    let e = ''' + 'json' + '''!({ "kind": "events", "events": lot });
}
'''

# OÙ LES SITES SONT APPARIÉS ET DÉCOUPÉS (`P10.21-k`, correction) : un commentaire qui porte un OUVRANT dans la macro
# (apparié sur le brut, le groupe ne se referme plus et la macro sort du jugement), le même dans un `.insert(` (découpé
# sur le brut, la clé et la valeur sont perdues), et le marqueur de régime écrit EN DERNIER, collé à l'accolade (un
# corps lu un caractère trop court perd le guillemet fermant du littéral, et le régime n'est plus reconnu).
_COMMENTAIRE_OUVRANT_DANS_LA_MACRO = '''fn surface() {
''' + _PUBLIE + '''    let e = ''' + 'json' + '''!({ "kind": "events", // lot (copie ?
        "events": lot });
}
'''
_COMMENTAIRE_OUVRANT_DANS_L_INSERT = '''fn surface() {
''' + _PUBLIE + '''    e.insert("events".to_string(), // (copie
        Value::Array(lot.clone()));
}
'''
_REGIME_EN_DERNIER = '''fn surface() {
''' + _PUBLIE + '''    let e = ''' + 'json' + '''!({"events": lot, "kind": "events"});
}
'''
# L'AVEU DU LECTEUR (`P10.21-k`, correction) : une chaîne brute jamais refermée dans une surface. Le lecteur avoue ; la
# garde doit REFUSER DE CONCLURE sur ce corpus, pas sauter le fichier et rendre le verdict des autres.
_CHAINE_BRUTE_JAMAIS_REFERMEE = '''fn surface() {
''' + _PUBLIE + '''    let motif = r#"jamais refermée;
}
'''

EPREUVES = [
    ("commentaire portant un ouvrant dans la macro", _COMMENTAIRE_OUVRANT_DANS_LA_MACRO, True, 1),
    ("commentaire portant un ouvrant dans l'insert", _COMMENTAIRE_OUVRANT_DANS_L_INSERT, True, 1),
    ("marqueur de régime en dernier, collé à l'accolade", _REGIME_EN_DERNIER, True, 1),
    ("littéral de caractère ouvrant dans la macro", _CARACTERE_DANS_LA_MACRO, True, 1),
    ("chaîne brute portant `//` avant l'enveloppe", _CHAINE_BRUTE_AVANT_L_ENVELOPPE, True, 1),
    ("commentaire dans le corps de la macro", _COMMENTAIRE_DANS_LA_MACRO, True, 1),
    ("point de publication seulement cité en chaîne", _PUBLICATION_CITEE_EN_CHAINE, False, 0),
    ("déplacement (forme visée)", _DEPLACE, True, 0),
    ("clé calculée, lot dupliqué", _CLE_CALCULEE_DUPLIQUE, True, 1),
    ("clé possédée par `to_owned`, lot déplacé", _CLE_POSSEDEE_DEPLACE, True, 0),
    ("valeur à générique avant le lot nommé", _VALEUR_A_GENERIQUE, True, 1),
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


def juger(corpus, sur_aveu=refuser_sur_aveu):
    """Le jugement d'un corpus `[(chemin affiché, texte brut)]` : `(population, refus)`, ou None quand le lecteur a
    AVOUÉ sur un fichier (`sur_aveu` l'a dit) — la garde refuse alors de conclure. C'est la fonction que `main` appelle
    sur `daemon/src` et que les épreuves appellent sur leurs textes fabriqués : le critère de population, l'aveu et le
    refus y sont joués tels qu'ils jugent le dépôt."""
    population, refus, aveux = [], [], {}
    for chemin, brut in corpus:
        journal = []
        neutre = aveugler(brut, journal)
        if journal:
            # Le lecteur a ouvert une région qui ne se referme pas : tout ce qu'il a lu depuis est faux.
            aveux[chemin] = [f"ligne {ligne_de(brut, o)} : {m}" for m, o in journal]
            continue
        if not POINT_DE_PUBLICATION.search(neutre):
            continue
        population.append(chemin)
        for decalage, motif in refus_du_fichier(brut, neutre):
            refus.append((chemin, ligne_de(neutre, decalage), motif))
    if aveux and sur_aveu("check_an_ingestion_envelope_never_copies_its_batch", aveux, "Rust"):
        return None
    return population, refus


def epreuves():
    # LES LECTEURS PARTAGÉS D'ABORD : `arguments` est importé, et ses témoins ne vivent pas ici.
    try:
        temoins_des_lecteurs_de_forme()
    except AssertionError as e:
        return f"lecteurs de forme Rust partagés (`arguments`, `apparier`) : {e}"
    valeurs = dict(paires('{ "n": r.get::<_, i64>(0), "c": \',\', "s": "a,b" }'))
    if valeurs != {"n": "r.get::<_, i64>(0)", "c": "\',\'", "s": '"a,b"'}:
        return (f"témoin de DÉCOUPE : les valeurs lues sont {valeurs} — une virgule de générique, de "
                "littéral de caractère ou de chaîne coupe une valeur, qui n'est plus lue ENTIÈRE")
    muet = lambda *_args: True  # noqa: E731  (l'aveu d'une épreuve n'est pas imprimé)
    for nom, texte, dans_population, attendu in EPREUVES:
        if len(aveugler(texte)) != len(texte):
            return f"témoin « {nom} » : la neutralisation des commentaires a changé la LONGUEUR du texte"
        jugement = juger([(nom, texte)], muet)
        if jugement is None:
            return f"témoin « {nom} » : le lecteur avoue sur un texte qu'il doit lire"
        population, refus = jugement
        if bool(population) != dans_population:
            return f"témoin « {nom} » : population={bool(population)}, attendu {dans_population}"
        if len(refus) != attendu:
            return f"témoin « {nom} » : {len(refus)} refus, attendu {attendu}"
    if juger([("chaîne brute jamais refermée", _CHAINE_BRUTE_JAMAIS_REFERMEE), ("macro + lot nommé", _MACRO_LOT_NOMME)],
             muet) is not None:
        return ("témoin « chaîne brute jamais refermée » : le lecteur a avoué sur un fichier, et la garde a rendu un "
                "verdict au lieu de refuser de conclure")
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

    corpus = []
    for chemin in fichiers:
        try:
            corpus.append((os.path.relpath(chemin, RACINE), open(chemin, encoding="utf-8").read()))
        except (OSError, UnicodeDecodeError):
            print(f"::error::{os.path.relpath(chemin, RACINE)} illisible : la garde REFUSE DE CONCLURE", file=sys.stderr)
            return 2

    jugement = juger(corpus)
    if jugement is None:
        return 2
    population, refus = jugement

    if not population:
        print("::error::le critère de population — un fichier qui appelle le point de publication du spool — "
              "ne désigne plus aucun fichier du démon. Le critère a dérivé du code : la garde REFUSE DE "
              "CONCLURE plutôt que de rendre un vert qui ne mesure rien.", file=sys.stderr)
        return 2

    for rel, ligne, motif in refus:
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
