#!/usr/bin/env python3
"""Toute liste CHERCHABLE de la console déclare une identité littérale et unique — instrument de mesure
et garde de CI (`P11.18-z`).

LE DÉFAUT, MESURÉ LE 2026-08-26. Le mécanisme de mémoire de recherche existait et était prouvé sur une
liste FABRIQUÉE par le banc : la fabrique repose la recherche d'un rendu à l'autre sous l'IDENTITÉ de la
liste, et sans identité elle ne retient rien — ce qui est le défaut sûr. Sur l'arbre réel, UNE seule des
huit listes cherchables déclarait une identité (`detection_admin.js`, qui en portait déjà une pour son
pli) : les sept autres se comportaient exactement comme avant, et l'exploitant qui travaillait sur une
liste filtrée retrouvait la liste entière après avoir déclaré un hôte, levé un silence ou révoqué un
jeton. Un mécanisme posé et non armé n'est pas un constat clos.

CE QUE CETTE GARDE TIENT, ET RIEN D'AUTRE. Elle DÉRIVE de `web/` les appels à la fabrique de liste
partagée et n'en énumère aucun :
  (1) le texte de chaque module est AVEUGLÉ par le lecteur partagé (contenu des chaînes, gabarits,
      expressions régulières et commentaires remplacé par des blancs, à longueur égale) : un
      `pagedList(` cité dans une chaîne ou dans un commentaire n'est pas un appel, et les accolades d'un
      littéral ne déplacent plus la fin d'un objet d'options ;
  (2) de chaque appel on tire les clés de PREMIER NIVEAU de son objet d'options ;
  (3) une liste qui déclare `recherche` DOIT déclarer une identité — `storeKey`, ou le `storeKey` de son
      `group`, qui est la clé de rangement que le dépôt porte déjà ;
  (4) cette identité doit être un LITTÉRAL de chaîne : une identité calculée ne serait pas stable d'un
      rendu à l'autre, et une identité instable ne retient rien ou retient pour une autre liste ;
  (5) deux appels ne peuvent pas déclarer la MÊME identité : deux listes qui la partagent partagent leur
      recherche ET leur pli — une recherche appliquée à la mauvaise liste est pire que pas de mémoire.

CE QUE CETTE GARDE NE TIENT PAS, ÉCRIT PLUTÔT QUE TU.
  · Elle ne prouve pas que la mémoire FONCTIONNE : elle lit du texte. Ce que la recherche devient à
    travers un rechargement de vue et un geste éditorial est tenu par le harnais ESM
    (`web_esm_harnais.mjs`, témoins 37 et 40), qui exerce les modules réels et leurs chargeurs.
  · Elle ne voit que les listes rendues par la fabrique partagée. Cinq panneaux câblent un champ de
    recherche à la main (mesuré le 2026-08-26) ; leur champ vit dans `index.html` ou est câblé une seule
    fois, il survit donc déjà — mais rien ici ne le vérifie.
  · Elle ne juge pas si une identité est BIEN CHOISIE, seulement qu'elle est littérale et unique.
  · Elle ne regarde pas les autres clés de `localStorage` : une identité qui collisionnerait avec une clé
    de rangement écrite ailleurs qu'à un appel de la fabrique ne serait pas vue.

ELLE REFUSE UNE RÉGRESSION, PAS UN ÉTAT, ET SANS AUCUN PLAFOND À RELEVER : la propriété est absolue (une
liste cherchable sans identité est un défaut, quel qu'en soit le nombre). Le seul nombre écrit ici est un
PLANCHER d'instrument — sous lui, la dérivation est cassée et la garde REFUSE DE CONCLURE au lieu de rendre
un vert sur un corpus qu'elle n'a pas lu.
"""
import os, re, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_every_help_trigger_has_a_section import (  # noqa: E402  (LECTEUR PARTAGÉ, source unique — `P11.8-f`)
    aveugler_litteraux_js, refuser_sur_aveu, temoins_du_lecteur)
from check_every_style_selector_has_a_target import racine_designee  # noqa: E402  (racine désignée, source unique)

FABRIQUE = "pagedList("
# PLANCHER D'INSTRUMENT. Mesuré le 2026-08-26 : 38 appels à la fabrique dans `web/`, dont 8 cherchables.
# Sous ce plancher, ce n'est plus le même corpus qui est lu — la garde ne conclut pas.
PLANCHER_APPELS = 20
RE_APPEL = re.compile(r"\bpagedList\s*\(")
RE_DEFINITION = re.compile(r"function\s+$")
RE_CLE = re.compile(r"^\s*([A-Za-z_$][\w$]*)\s*(?::(.*))?$", re.S)
RE_LITTERAL = re.compile(r"^(['\"])([^'\"\\\n]+)\1$", re.S)


def portee(aveugle, depart, ouvrant, fermant):
    """Index APRÈS le fermant du bloc ouvert au caractère `depart - 1`, ou None s'il n'est jamais refermé.
    Le texte reçu est AVEUGLÉ : aucun délimiteur de littéral n'y porte plus d'accolade, donc l'appariement
    est purement structurel."""
    prof, i, n = 1, depart, len(aveugle)
    while i < n and prof:
        c = aveugle[i]
        if c == ouvrant: prof += 1
        elif c == fermant: prof -= 1
        i += 1
    return None if prof else i


def objet_doptions(aveugle, deb, fin):
    """(début après `{`, index du `}`) du PREMIER objet littéral passé à l'appel, ou None (une fabrique
    appelée sans objet d'options ne déclare rien)."""
    i = aveugle.find("{", deb, fin)
    if i < 0: return None
    f = portee(aveugle, i + 1, "{", "}")
    return None if f is None or f > fin + 1 else (i + 1, f - 1)


def segments_de_premier_niveau(aveugle, deb, fin):
    """Les tranches (début, fin) séparées par les virgules de PREMIER NIVEAU de l'objet [deb, fin)."""
    tranches, prof, depart, i = [], 0, deb, deb
    while i < fin:
        c = aveugle[i]
        if c in "([{": prof += 1
        elif c in ")]}": prof -= 1
        elif c == "," and prof == 0:
            tranches.append((depart, i)); depart = i + 1
        i += 1
    tranches.append((depart, fin))
    return [t for t in tranches if aveugle[t[0]:t[1]].strip()]


def cles(aveugle, deb, fin):
    """{nom de clé: (début, fin) de sa VALEUR} au premier niveau. Une propriété abrégée (`storeKey,`)
    rend sa propre tranche comme valeur : elle n'est pas un littéral, et c'est ce que la garde en dira."""
    table = {}
    for a, b in segments_de_premier_niveau(aveugle, deb, fin):
        m = RE_CLE.match(aveugle[a:b])
        if not m: continue
        valeur = m.group(2)
        table[m.group(1)] = (a + m.start(2), b) if valeur is not None else (a, b)
    return table


def identite(brut, aveugle, deb, fin):
    """(texte de l'identité, d'où elle vient) — `storeKey` de tête, sinon celui du `group`. None si aucune.
    Le texte est lu dans le SOURCE, l'aveuglement conservant les offsets."""
    t = cles(aveugle, deb, fin)
    if "storeKey" in t:
        a, b = t["storeKey"]; return brut[a:b].strip(), "storeKey"
    if "group" in t:
        ga, gb = t["group"]
        sous = objet_doptions(aveugle, ga, gb)
        if sous:
            tg = cles(aveugle, *sous)
            if "storeKey" in tg:
                a, b = tg["storeKey"]; return brut[a:b].strip(), "group.storeKey"
    return None


def sites(nom, brut, aveugle):
    """[{fichier, ligne, cherchable, identite, origine}] pour chaque appel à la fabrique du module."""
    trouves = []
    for m in RE_APPEL.finditer(aveugle):
        if RE_DEFINITION.search(aveugle[max(0, m.start() - 12):m.start()]):
            continue                                    # la DÉFINITION de la fabrique n'est pas un appel
        f = portee(aveugle, m.end(), "(", ")")
        if f is None: continue
        opts = objet_doptions(aveugle, m.end(), f - 1)
        ligne = aveugle.count("\n", 0, m.start()) + 1
        if not opts:
            trouves.append({"fichier": nom, "ligne": ligne, "cherchable": False, "identite": None, "origine": ""})
            continue
        t = cles(aveugle, *opts)
        ident = identite(brut, aveugle, *opts)
        trouves.append({"fichier": nom, "ligne": ligne, "cherchable": "recherche" in t,
                        "identite": ident[0] if ident else None, "origine": ident[1] if ident else ""})
    return trouves


def juger(tous):
    """[messages] — un par défaut constaté. Vide = la propriété tient."""
    defauts, vues = [], {}
    for s in tous:
        ou = f"web/{s['fichier']}:{s['ligne']}"
        if s["cherchable"] and not s["identite"]:
            defauts.append(f"{ou} — cette liste déclare `recherche` sans déclarer d'identité (`storeKey`, ou le "
                           f"`storeKey` de son `group`) : sa recherche repart à zéro à chaque rechargement de la "
                           f"vue, donc à chaque geste éditorial de son panneau. Déclarer une clé littérale, "
                           f"stable et propre à cette liste — c'est la clé de rangement que le dépôt emploie déjà.")
            continue
        if not s["identite"]:
            continue
        m = RE_LITTERAL.match(s["identite"])
        if not m:
            defauts.append(f"{ou} — l'identité `{s['origine']}` vaut « {s['identite']} », qui n'est pas un littéral "
                           f"de chaîne : une identité calculée n'est pas stable d'un rendu à l'autre, et une "
                           f"identité instable ne retient rien — ou retient pour une autre liste.")
            continue
        cle = m.group(2)
        if cle in vues:
            defauts.append(f"{ou} — l'identité « {cle} » est DÉJÀ déclarée par {vues[cle]} : deux listes qui la "
                           f"partagent partagent leur recherche et leur pli. Une recherche appliquée à la mauvaise "
                           f"liste est pire que pas de mémoire du tout.")
            continue
        vues[cle] = ou
    return defauts


def temoins():
    """L'INSTRUMENT SE VALIDE DANS LES DEUX SENS AVANT DE JUGER. Un banc qui ne verrait plus une liste sans
    identité rendrait un vert qui n'atteste rien ; un banc qui accuserait une liste bien déclarée ferait
    rougir un arbre sain."""
    def lus(src):
        return sites("temoin.js", src, aveugler_litteraux_js(src))

    nue = lus("pagedList(h, { mode: 'client', rows, columns, emptyText: 'aucun', recherche: true });")
    assert len(nue) == 1 and nue[0]["cherchable"] and not nue[0]["identite"], f"témoin : une liste cherchable NUE n'est plus lue comme telle ({nue})"
    assert juger(nue), "témoin POSITIF : une liste cherchable sans identité ne rougit plus — la garde n'atteste rien"

    tete = lus("pagedList(h, { mode: 'client', rows, columns, storeKey: 'temoin_de_tete', recherche: true });")
    assert tete[0]["identite"] == "'temoin_de_tete'" and tete[0]["origine"] == "storeKey", f"témoin : l'identité de tête n'est plus lue ({tete})"
    assert not juger(tete), "témoin NÉGATIF : une liste correctement déclarée est accusée"

    groupe = lus("pagedList(h, { mode: 'client', rows, renderRow: r, group: { storeKey: 'temoin_de_groupe' }, recherche: true });")
    assert groupe[0]["origine"] == "group.storeKey", f"témoin : l'identité héritée du regroupement n'est plus lue ({groupe})"
    assert not juger(groupe), "témoin NÉGATIF : une identité héritée du `group` est refusée"

    muette = lus("pagedList(h, { mode: 'client', rows, columns, emptyText: 'aucun' });")
    assert muette[0]["cherchable"] is False and not juger(muette), "témoin NÉGATIF : une liste SANS recherche se voit exiger une identité"

    calculee = lus("pagedList(h, { mode: 'client', rows, columns, storeKey: cleDeLaVue, recherche: true });")
    assert juger(calculee), "témoin POSITIF : une identité CALCULÉE passe pour stable"

    partagee = lus("pagedList(a, { rows, columns, storeKey: 'meme_cle', recherche: true });\n"
                   "pagedList(b, { rows, columns, storeKey: 'meme_cle', recherche: true });")
    assert len(partagee) == 2 and len(juger(partagee)) == 1, f"témoin POSITIF : deux listes qui PARTAGENT une identité ne rougissent plus ({partagee})"

    citee = lus("const aide = 'appeler pagedList(h, { recherche: true }) sans identité';\n// pagedList(h, { recherche: true });\n")
    assert not citee, f"témoin NÉGATIF : un appel CITÉ dans une chaîne ou un commentaire est compté comme un appel ({citee})"

    definition = lus("function pagedList(host, opts) { return { reload, state }; }")
    assert not definition, f"témoin NÉGATIF : la DÉFINITION de la fabrique est comptée comme un appel ({definition})"


def main():
    web = os.path.join(racine_designee(), "web")
    temoins_du_lecteur()      # le lecteur partagé se valide avant de servir (`P11.8-f`)
    temoins()                 # et le banc de CETTE garde, dans les deux sens, avant tout verdict
    aveux, tous, fichiers = {}, [], 0
    for f in sorted(os.listdir(web)):
        if not f.endswith(".js"): continue
        chemin = os.path.join(web, f)
        if not os.path.isfile(chemin): continue
        journal, brut = [], open(chemin, encoding="utf-8").read()
        aveugle = aveugler_litteraux_js(brut, journal)
        if journal:
            aveux[f] = [f"ligne {brut.count(chr(10), 0, o) + 1} : {motif}" for motif, o in journal]
        fichiers += 1
        tous.extend(sites(f, brut, aveugle))
    # LE LECTEUR AVOUE, LA GARDE REFUSE DE CONCLURE : une région mal lue déplace la fin d'un objet
    # d'options, donc les clés qu'on croit y voir. Un compte amputé rendu en vert est pire qu'une absence.
    if aveux and refuser_sur_aveu("recherche-liste", aveux): return 2
    cherchables = [s for s in tous if s["cherchable"]]
    identifiees = [s for s in tous if s["identite"]]
    print(f"[recherche-liste] {len(tous)} appel(s) à la fabrique de liste dans {fichiers} module(s) de web/ ; "
          f"{len(cherchables)} liste(s) cherchable(s) ; {len(identifiees)} identité(s) déclarée(s).")
    for s in sorted(cherchables, key=lambda s: (s["fichier"], s["ligne"])):
        print(f"    {'·' if s['identite'] else '!'} web/{s['fichier']}:{s['ligne']}  "
              f"{s['identite'] or 'AUCUNE IDENTITÉ'}{'  (' + s['origine'] + ')' if s['origine'] else ''}")
    if len(tous) < PLANCHER_APPELS:
        print(f"[recherche-liste] REFUS DE CONCLURE — {len(tous)} appel(s) lus, plancher {PLANCHER_APPELS} : "
              f"la dérivation est cassée, la garde ne rend pas un verdict sur un corpus qu'elle n'a pas lu.")
        return 2
    defauts = juger(tous)
    for d in defauts:
        print(f"::error::{d}")
    if defauts:
        print(f"[recherche-liste] ÉCHEC — {len(defauts)} liste(s) dont la recherche ne survit pas à un rendu de "
              f"leur vue, ou dont l'identité n'est ni littérale ni propre.")
        return 1
    print("[recherche-liste] OK — chaque liste cherchable déclare une identité littérale, et aucune n'est "
          "partagée. CE QUE CE VERT NE DIT PAS : que la mémoire fonctionne (c'est le harnais ESM, témoins 37 "
          "et 40, qui l'exerce sur les modules réels), ni rien des champs de recherche câblés hors de cette "
          "fabrique.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
