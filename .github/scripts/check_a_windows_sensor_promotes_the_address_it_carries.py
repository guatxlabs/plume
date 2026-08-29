#!/usr/bin/env python3
"""Aucun capteur Windows livré ne laisse passer une adresse que l'autre écarte (`P4.12-a`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
Mesuré le 2026-08-29. Un lecteur d'Event Log adopte le vocabulaire de Windows : `extract_event_data`
(agent) et `Get-EventData` (PowerShell) recopient VERBATIM chaque `<Data Name='…'>` dans le sac
`fields`. Windows nomme `IpAddress` l'adresse d'un échec d'ouverture de session ; la colonne
`event.src_ip` du central, elle, n'est peuplée que depuis les noms que le contrat CIM déclare
(`config.d/cim/cim.v1.json`, `promoted_fields`). Les deux vocabulaires ne se rencontrent nulle part.

Des deux capteurs LIVRÉS, un seul faisait la jonction. `collectors/windows/plume-collector.ps1`
posait l'adresse dans la colonne depuis le 2026-08-02 ; `agent/src/source/windows.rs` ne l'a jamais
fait. Le MÊME enregistrement 4625 produisait donc une entité par un capteur et AUCUNE par l'autre, et
les deux règles livrées qui détectent par entité (« Brute-force auth par IP », `stats count by
src_ip` ; « RBA : brute-force d'authentification », entité `src_ip`) rendaient un verdict qui
dépendait du capteur installé — sans que rien ne le dise.

CE QUE LA VERSION PRÉCÉDENTE DE CETTE GARDE MESURAIT, ET CE QU'ELLE NE MESURAIT PAS
------------------------------------------------------------------------------------
RÉFUTÉE le 2026-08-29, sur son propre titre. Elle comparait l'ÉGALITÉ de deux ensembles de valeurs
sentinelles, et elle dérivait l'ensemble PowerShell des seules variables qui atteignent `-SrcIp` —
c'est-à-dire du chemin d'AUTHENTIFICATION, et de lui seul. Or le capteur PowerShell n'appliquait
AUCUNE frontière à son site WFP (`-SrcIp $d['SourceAddress']`, lecture directe). La garde comparait
donc l'ensemble AUTH d'un capteur à l'ensemble GLOBAL de l'autre et concluait « même frontière »,
VERTE, sur un tri où un 5157 en boucle locale rendait `src_ip=127.0.0.1` d'un côté et rien de
l'autre. Deux corrections, et ce sont des corrections de PROPRIÉTÉ, pas de seuil :

  · le PÉRIMÈTRE est désormais mesuré : la garde énumère CHAQUE site de promotion de chaque capteur
    et EXIGE que tous passent par la frontière ; un site en lecture directe est un ÉCHEC nommé ;
  · l'ÉGALITÉ devient une CONTENANCE. Exiger l'égalité INTERDISAIT d'élargir la frontière : ajouter
    `0.0.0.0` d'un seul côté faisait rougir la CI. Une garde qui interdit la correction du trou
    qu'elle nomme défend le trou. La garde exige maintenant que l'agent écarte AU MOINS tout ce que
    le capteur PowerShell écarte, et elle IMPRIME le surplus au lieu de le taire.

CE QUE LA GARDE TIENT — CINQ PROPRIÉTÉS, TOUTES DÉRIVÉES DES FICHIERS LIVRÉS
-----------------------------------------------------------------------------
(P1) CONTENANCE DES NOMS. Tout nom de champ Event Log que le capteur PowerShell traite comme une
     adresse SOURCE (resp. DESTINATION), l'agent le traite aussi, dans le MÊME sens. À SENS UNIQUE,
     et c'est délibéré : l'agent lit des canaux que le PowerShell ne lit pas (Sysmon), donc il PEUT
     connaître des noms de plus ; il ne peut pas en connaître de moins.
(P2) CONTENANCE DE LA FRONTIÈRE. Toute écriture que le capteur PowerShell refuse de promouvoir est
     aussi refusée par l'agent. Le surplus de l'agent est IMPRIMÉ (c'est un écart assumé, pas un
     silence). L'inverse — le PowerShell écarte une valeur que l'agent laisse passer — est un ÉCHEC :
     c'est une entité qui existe d'un côté et pas de l'autre.
(P2b) PÉRIMÈTRE. Chaque site de promotion d'adresse issu d'un Event Log passe par la frontière de son
     capteur : une fonction UNIQUE côté PowerShell, un lecteur UNIQUE côté agent, et côté agent une
     garde « l'émetteur gagne » qui tranche sur une VALEUR et non sur la PRÉSENCE de la clé. Un site
     en lecture directe, ou deux frontières concurrentes, sont un ÉCHEC : c'est ainsi que le trou
     précédent s'était écrit.
(P3) LE NOM PROMU EST CELUI DU CONTRAT. Les clés sous lesquelles l'agent range l'adresse sont LUES
     dans `promoted_fields` du CIM. Promouvoir sous `source_ip` ou `client_ip` compilerait, passerait
     tous les témoins Rust, et ne peuplerait aucune colonne.
(P4) ANTI-VACUITÉ, DANS LES DEUX SENS. Chaque extraction doit rendre quelque chose. Une expression
     rationnelle qui cesse d'apparier — parce qu'on a reformaté le PowerShell ou renommé une
     constante Rust — rendrait un ensemble VIDE, et un ensemble vide satisfait (P1) et (P2)
     trivialement : la garde serait verte en ne mesurant RIEN. Elle REFUSE de conclure à la place.
     Le corpus déclaré de l'agent doit en outre être EXERCÉ ailleurs dans son fichier : une liste que
     personne n'éprouve n'est pas une frontière, c'est une décoration, et (P2) comparerait alors du
     texte à du texte.

CE QUI EST DÉCLARÉ IGNORÉ, ET POURQUOI CE N'EST PAS UN SILENCE
---------------------------------------------------------------
Le capteur PowerShell passe aussi des adresses qui NE VIENNENT PAS d'un Event Log : `-SrcIp
$_.LocalAddress` / `-DstIp $_.RemoteAddress` viennent de `Get-NetTCPConnection` (un instantané de
socket, pas un enregistrement de journal). L'agent n'a pas de source équivalente ; exiger la parité
sur ces noms demanderait un capteur qui n'existe pas. Ces sites sont donc écartés — mais ils sont
RECONNUS, comptés, et le compte est imprimé : une expression qui cesserait de les reconnaître
tomberait dans la branche « forme non lue », qui REFUSE.

UN SEUL SAUT D'AFFECTATION, ET CETTE BORNE EST DITE
----------------------------------------------------
Dans le PowerShell, l'adresse d'authentification passe par une variable (`$sip = <frontière> $d[…]`)
avant d'atteindre `-SrcIp`. La garde suit AU PLUS UN saut d'affectation. Une valeur qu'il faudrait
suivre plus loin n'est pas devinée : elle est REFUSÉE, comme une forme non lue.

CE QUE LA GARDE NE TIENT PAS, ET IL FAUT LE LIRE ICI
-----------------------------------------------------
Elle compare des FRONTIÈRES, pas des FORMES CANONIQUES. L'agent replie `::ffff:203.0.113.7` sur
`203.0.113.7` (analyse par `IpAddr`, même sémantique que `ssrf_norm_ip` côté démon) ; le capteur
PowerShell rend l'écriture reçue. Les deux capteurs écartent donc le même corpus mais ne rendent pas
toujours la même CHAÎNE pour la même machine. C'est mesuré, assumé, et porté par `P4.12-c` — cette
garde ne prétend pas le couvrir.
"""
import json
import os
import re
import sys

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.realpath(os.path.join(ICI, "..", ".."))
POWERSHELL = os.path.join(RACINE, "collectors", "windows", "plume-collector.ps1")
AGENT = os.path.join(RACINE, "agent", "src", "source", "windows.rs")
CIM = os.path.join(RACINE, "config.d", "cim", "cim.v1.json")

# --- les formes LUES (jamais un nom d'adresse écrit ici) -------------------------------------------
# PowerShell : `-SrcIp <expr>` / `-DstIp <expr>`, où <expr> est soit `(Frontière $d['NOM'])` (le site
# DISCIPLINÉ), soit `$d['NOM']` (lecture DIRECTE — le défaut), soit `$var` (un saut à suivre), soit
# `$_.Membre` (hors Event Log).
PS_PASSAGE = re.compile(
    r"-(?P<sens>SrcIp|DstIp)\s+(?P<expr>"
    r"\(\s*[A-Za-z][-A-Za-z0-9_]*\s+\$[A-Za-z_][A-Za-z_0-9]*\[[^\]]*\]\s*\)"
    r"|\$[A-Za-z_][A-Za-z_0-9]*(?:\[[^\]]*\]|\.[A-Za-z_0-9]+)?"
    r")"
)
PS_APPEL = re.compile(
    r"^\(\s*(?P<fn>[A-Za-z][-A-Za-z0-9_]*)\s+\$[A-Za-z_][A-Za-z_0-9]*\[(?P<q>['\"])(?P<nom>[A-Za-z_0-9]+)(?P=q)\]\s*\)$"
)
PS_LECTURE = re.compile(r"^\$(?P<var>[A-Za-z_][A-Za-z_0-9]*)\[(?P<q>['\"])(?P<nom>[A-Za-z_0-9]+)(?P=q)\]$")
PS_MEMBRE = re.compile(r"^\$_\.[A-Za-z_0-9]+$")
PS_VARIABLE = re.compile(r"^\$(?P<var>[A-Za-z_][A-Za-z_0-9]*)$")
# `$sip = Frontière $d['IpAddress']` — le seul saut suivi, dans sa forme DISCIPLINÉE.
PS_AFFECTATION_FRONTIERE = re.compile(
    r"\$(?P<var>[A-Za-z_][A-Za-z_0-9]*)\s*=\s*(?P<fn>[A-Za-z][-A-Za-z0-9_]*)\s+\$[A-Za-z_][A-Za-z_0-9]*\[['\"](?P<nom>[A-Za-z_0-9]+)['\"]\]"
)
# `$sip = $d['IpAddress']` — le même saut SANS frontière : c'est la forme qui portait le défaut.
PS_AFFECTATION_BRUTE = re.compile(
    r"\$(?P<var>[A-Za-z_][A-Za-z_0-9]*)\s*=\s*\$[A-Za-z_][A-Za-z_0-9]*\[['\"](?P<nom>[A-Za-z_0-9]+)['\"]\]"
)
# Le corps d'une fonction PowerShell (un niveau d'imbrication d'accolades suffit à la frontière).
PS_FONCTION = re.compile(r"function\s+(?P<nom>[A-Za-z][-A-Za-z0-9_]*)\s*\{(?P<corps>(?:[^{}]|\{[^{}]*\})*)\}", re.S)
# Ce qu'une frontière REFUSE : `-in @('a','b')` et/ou une chaîne de `-eq 'a'`.
PS_REJET_IN = re.compile(r"-in\s+@\((?P<corps>[^)]*)\)")
PS_REJET_EQ = re.compile(r"-eq\s+'(?P<val>[^']*)'")
PS_LITTERAL = re.compile(r"'([^']*)'")

# Rust : les trois tableaux nommés du lecteur, lus par leur FORME (`const NOM: [&str; N] = [...]`).
RS_TABLEAU = re.compile(
    r"const\s+(?P<nom>ADRESSE_SOURCE|ADRESSE_DESTINATION|PAS_UNE_ADRESSE)\s*:\s*\[&str;\s*\d+\]\s*=\s*\[(?P<corps>[^\]]*)\]"
)
RS_MOT = re.compile(r'"((?:[^"\\]|\\.)*)"')
# La boucle de promotion : `("src_ip", &ADRESSE_SOURCE[..])`.
RS_PROMOTION = re.compile(r'\(\s*"(?P<cle>[a-z_]+)"\s*,\s*&(?P<tableau>ADRESSE_SOURCE|ADRESSE_DESTINATION)\[\.\.\]\s*\)')
# Le LECTEUR unique de la boucle : `if let Some(v) = <fn>(&fields, noms)`.
RS_LECTEUR = re.compile(r"if\s+let\s+Some\(\s*\w+\s*\)\s*=\s*(?P<fn>[a-z_][a-z_0-9]*)\(&fields,\s*noms\)")
# La garde « l'émetteur gagne », TRANCHÉE SUR UNE VALEUR : `fields.get(cle)…and_then(<fn>)`.
RS_GARDE_VALEUR = re.compile(r"fields\.get\(cle\)[^;\n]*\.and_then\((?P<fn>[a-z_][a-z_0-9]*)\)")
# La garde tranchée sur la PRÉSENCE — la forme qui portait le défaut, nommée pour être refusée.
RS_GARDE_PRESENCE = re.compile(r"fields\.contains_key\(cle\)")
# Le corpus déclaré doit être EXERCÉ : une mention hors de sa propre déclaration — et dans du CODE.
# MESURÉ le 2026-08-29 : la première écriture de cette propriété appariait aussi la PROSE, et la
# mutation « le témoin n'itère plus le corpus » la laissait VERTE parce que deux commentaires
# nommaient encore la constante. Les deux fichiers sont donc lus SANS leurs lignes de commentaire :
# une garde ne peut pas être satisfaite par une phrase.
RS_CORPUS_EXERCE = re.compile(r"(?<!const )\bPAS_UNE_ADRESSE\b")
RS_COMMENTAIRE = re.compile(r"^\s*//")
PS_COMMENTAIRE = re.compile(r"^\s*#")


def sans_prose(texte, marqueur):
    """Le texte PRIVÉ de ses lignes de commentaire — une propriété de code ne s'écrit pas en prose."""
    return "\n".join(l for l in texte.split("\n") if not marqueur.match(l))


def lire(chemin):
    try:
        return open(chemin, encoding="utf-8").read()
    except OSError:
        return None


def powershell_frontiere(texte):
    """(noms par sens, frontières nommées, rejets, sites hors Event Log, sites bruts, formes non lues).

    Tout est DÉRIVÉ du fichier : le nom de la fonction-frontière n'est pas écrit ici, il est LU dans
    les sites de promotion eux-mêmes.
    """
    texte = sans_prose(texte, PS_COMMENTAIRE)
    frontiere_de_var = {m.group("var"): (m.group("fn"), m.group("nom")) for m in PS_AFFECTATION_FRONTIERE.finditer(texte)}
    brute_de_var = {
        m.group("var"): m.group("nom")
        for m in PS_AFFECTATION_BRUTE.finditer(texte)
        if m.group("var") not in frontiere_de_var
    }
    noms = {"SrcIp": set(), "DstIp": set()}
    frontieres = set()
    hors_journal = 0
    sites_bruts = []
    non_lues = []
    for m in PS_PASSAGE.finditer(texte):
        sens, expr = m.group("sens"), m.group("expr")
        appel = PS_APPEL.match(expr)
        if appel:
            noms[sens].add(appel.group("nom"))
            frontieres.add(appel.group("fn"))
            continue
        directe = PS_LECTURE.match(expr)
        if directe:                                     # `-SrcIp $d['NOM']` : AUCUNE frontière
            noms[sens].add(directe.group("nom"))
            sites_bruts.append(f"-{sens} {expr}")
            continue
        if PS_MEMBRE.match(expr):
            hors_journal += 1
            continue
        var = PS_VARIABLE.match(expr)
        if var and var.group("var") in frontiere_de_var:  # UN saut, discipliné
            fn, nom = frontiere_de_var[var.group("var")]
            noms[sens].add(nom)
            frontieres.add(fn)
            continue
        if var and var.group("var") in brute_de_var:      # UN saut, SANS frontière
            noms[sens].add(brute_de_var[var.group("var")])
            sites_bruts.append(f"-{sens} {expr} (= ${var.group('var')} lu directement)")
            continue
        non_lues.append(expr)

    rejets = set()
    for m in PS_FONCTION.finditer(texte):
        if m.group("nom") not in frontieres:
            continue
        corps = m.group("corps")
        for r in PS_REJET_IN.finditer(corps):
            rejets |= {v for v in PS_LITTERAL.findall(r.group("corps")) if v}
        rejets |= {m2.group("val") for m2 in PS_REJET_EQ.finditer(corps) if m2.group("val")}
    return noms, frontieres, rejets, hors_journal, sites_bruts, non_lues


def agent_frontiere(texte):
    """(promotion par clé, corpus déclaré, lecteurs, gardes de précédence, formes non lues)."""
    texte = sans_prose(texte, RS_COMMENTAIRE)
    tableaux = {}
    for m in RS_TABLEAU.finditer(texte):
        tableaux[m.group("nom")] = [RS_MOT.sub(lambda x: x.group(1), s) for s in RS_MOT.findall(m.group("corps"))]
    non_lues = []
    for attendu in ("ADRESSE_SOURCE", "ADRESSE_DESTINATION", "PAS_UNE_ADRESSE"):
        if attendu not in tableaux:
            non_lues.append(f"tableau {attendu} introuvable")
    promotion = {}
    for m in RS_PROMOTION.finditer(texte):
        promotion[m.group("cle")] = tableaux.get(m.group("tableau"), [])
    lecteurs = {m.group("fn") for m in RS_LECTEUR.finditer(texte)}
    gardes_valeur = {m.group("fn") for m in RS_GARDE_VALEUR.finditer(texte)}
    garde_presence = bool(RS_GARDE_PRESENCE.search(texte))
    corpus_exerce = bool(RS_CORPUS_EXERCE.search(texte))
    return promotion, set(tableaux.get("PAS_UNE_ADRESSE", [])), lecteurs, gardes_valeur, garde_presence, corpus_exerce, non_lues


def cim_champs_promus(texte):
    """Les noms de `fields` qui peuplent chaque colonne — LUS dans le contrat, jamais écrits ici."""
    try:
        spec = json.loads(texte)
    except (ValueError, TypeError):
        return None
    brut = spec.get("promoted_fields")
    if not isinstance(brut, dict):
        return None
    out = {}
    for colonne, sources in brut.items():
        if colonne.startswith("_") or not isinstance(sources, list):
            continue
        out[colonne] = {s.split(".", 1)[1] for s in sources if isinstance(s, str) and s.startswith("fields.")}
    return out or None


def epreuves():
    """Témoins POSITIFS et NÉGATIFS des trois lecteurs, hors du disque."""
    ps_sain = (
        "function Frontiere-Test {\n"
        "  param([string]$Valeur)\n"
        "  if ($v -in @('-', '::1')) { return $null }\n"
        "  return $v\n"
        "}\n"
        "$sip = Frontiere-Test $d['IpAddress']\n"
        "Add-Event -SrcIp $sip -Dedup x\n"
        "Add-Event -SrcIp (Frontiere-Test $d['SourceAddress']) -DstIp (Frontiere-Test $d['DestAddress'])\n"
        "Add-Event -SrcIp $_.LocalAddress -DstIp $_.RemoteAddress\n"
    )
    noms, fr, rejets, hors, bruts, non_lues = powershell_frontiere(ps_sain)
    if noms["SrcIp"] != {"IpAddress", "SourceAddress"} or noms["DstIp"] != {"DestAddress"}:
        return f"témoin POSITIF PowerShell : noms lus {noms}"
    if fr != {"Frontiere-Test"}:
        return f"témoin POSITIF PowerShell : frontières lues {fr}"
    if rejets != {"-", "::1"}:
        return f"témoin POSITIF PowerShell : rejets lus {rejets}"
    if hors != 2 or bruts or non_lues:
        return f"témoin POSITIF PowerShell : hors-journal={hors}, bruts={bruts}, non lues={non_lues}"
    # NÉGATIF (a) — un site en LECTURE DIRECTE doit être VU comme tel (c'est le défaut de 2026-08-29).
    if not powershell_frontiere("Add-Event -SrcIp $d['SourceAddress']\n")[4]:
        return "témoin NÉGATIF PowerShell : un site en lecture directe devrait être signalé"
    # NÉGATIF (b) — un saut d'affectation SANS frontière est un site brut, pas un site discipliné.
    if not powershell_frontiere("$sip = $d['IpAddress']\nAdd-Event -SrcIp $sip\n")[4]:
        return "témoin NÉGATIF PowerShell : un saut sans frontière devrait être signalé"
    # NÉGATIF (c) — une variable sans aucune affectation est une forme NON LUE.
    if not powershell_frontiere("Add-Event -SrcIp $inconnu\n")[5]:
        return "témoin NÉGATIF PowerShell : une variable SANS affectation devrait être refusée"
    # NÉGATIF (d) — un texte vide ne peut rendre ni nom ni rejet.
    vide = powershell_frontiere("")
    if vide[0]["SrcIp"] or vide[2]:
        return "témoin NÉGATIF PowerShell : un texte vide ne peut rien rendre"
    # NÉGATIF (e) — les rejets d'une fonction qui n'est PAS une frontière ne comptent pas.
    autre = powershell_frontiere("function Rien {\n  if ($v -in @('X')) { return $null }\n}\n")
    if autre[2]:
        return f"témoin NÉGATIF PowerShell : rejets lus hors d'une frontière {autre[2]}"

    rs_sain = (
        'const ADRESSE_SOURCE: [&str; 2] = ["IpAddress", "SourceIp"];\n'
        'const ADRESSE_DESTINATION: [&str; 1] = ["DestAddress"];\n'
        'const PAS_UNE_ADRESSE: [&str; 2] = ["-", "::1"];\n'
        '("src_ip", &ADRESSE_SOURCE[..]),\n("dst_ip", &ADRESSE_DESTINATION[..]),\n'
        "if fields.get(cle).and_then(|v| v.as_str()).and_then(valeur_exploitable).is_some() {\n"
        "if let Some(v) = adresse_lisible(&fields, noms) {\n"
        "for e in PAS_UNE_ADRESSE.iter() {}\n"
    )
    promo, corpus, lecteurs, gardes, presence, exerce, non_lues = agent_frontiere(rs_sain)
    if promo != {"src_ip": ["IpAddress", "SourceIp"], "dst_ip": ["DestAddress"]} or non_lues:
        return f"témoin POSITIF agent : {promo}, non lues={non_lues}"
    if corpus != {"-", "::1"}:
        return f"témoin POSITIF agent : corpus {corpus}"
    if lecteurs != {"adresse_lisible"} or gardes != {"valeur_exploitable"}:
        return f"témoin POSITIF agent : lecteurs {lecteurs}, gardes {gardes}"
    if presence or not exerce:
        return f"témoin POSITIF agent : présence={presence}, corpus exercé={exerce}"
    # NÉGATIF (a) — la garde « présence » (le défaut corrigé) doit être VUE.
    if not agent_frontiere("if fields.contains_key(cle) { continue }\n")[4]:
        return "témoin NÉGATIF agent : une garde sur la PRÉSENCE devrait être signalée"
    # NÉGATIF (b) — un corpus qui n'est mentionné QUE dans sa déclaration n'est pas exercé.
    if agent_frontiere('const PAS_UNE_ADRESSE: [&str; 1] = ["-"];\n')[5]:
        return "témoin NÉGATIF agent : un corpus jamais mentionné ailleurs devrait être dit non exercé"
    # NÉGATIF (b bis) — une mention en PROSE n'est pas un exercice (la mutation qui a réfuté la
    # première écriture de cette propriété le 2026-08-29).
    if agent_frontiere('const PAS_UNE_ADRESSE: [&str; 1] = ["-"];\n/// on parle de PAS_UNE_ADRESSE ici\n')[5]:
        return "témoin NÉGATIF agent : une mention en commentaire ne doit pas valoir un exercice"
    # NÉGATIF (b ter) — une promotion écrite en COMMENTAIRE ne doit pas compter comme une promotion.
    if agent_frontiere('// ("src_ip", &ADRESSE_SOURCE[..]),\n')[0]:
        return "témoin NÉGATIF agent : une promotion en commentaire ne doit pas être lue"
    # NÉGATIF (b quater) — côté PowerShell non plus.
    if powershell_frontiere("# Add-Event -SrcIp $d['IpAddress']\n")[0]["SrcIp"]:
        return "témoin NÉGATIF PowerShell : un site en commentaire ne doit pas être lu"
    # NÉGATIF (c) — un texte sans tableau doit refuser.
    if not agent_frontiere("")[6]:
        return "témoin NÉGATIF agent : un texte sans tableau devrait être refusé"

    c = cim_champs_promus('{"promoted_fields": {"_comment": "x", "src_ip": ["fields.src_ip", "fields.rhost"]}}')
    if c != {"src_ip": {"src_ip", "rhost"}}:
        return f"témoin POSITIF CIM : {c}"
    if cim_champs_promus("{}") is not None or cim_champs_promus("pas du json") is not None:
        return "témoin NÉGATIF CIM : un contrat absent ou illisible devrait refuser"
    return None


def main():
    faute = epreuves()
    if faute:
        print(f"REFUS — l'instrument lui-même est faux ({faute}). Rien n'a été mesuré.")
        return 2

    manquants = [c for c in (POWERSHELL, AGENT, CIM) if lire(c) is None]
    if manquants:
        for c in manquants:
            print(f"REFUS — illisible : {os.path.relpath(c, RACINE)}")
        print("Les deux capteurs et le contrat CIM sont le corpus ; il en manque un, rien n'a été mesuré.")
        return 2

    ps_noms, ps_frontieres, ps_rejets, hors_journal, ps_bruts, ps_non_lues = powershell_frontiere(lire(POWERSHELL))
    (ag_promotion, ag_corpus, ag_lecteurs, ag_gardes, ag_presence, ag_exerce, ag_non_lues) = agent_frontiere(lire(AGENT))
    cim = cim_champs_promus(lire(CIM))

    if cim is None:
        print("REFUS — `promoted_fields` illisible dans config.d/cim/cim.v1.json : le contrat des")
        print("        colonnes est la source de (P3), sans lui rien n'est mesuré.")
        return 2
    if ps_non_lues or ag_non_lues:
        for e in ps_non_lues:
            print(f"REFUS — forme non lue côté PowerShell : « {e} » (plus d'un saut d'affectation ?)")
        for e in ag_non_lues:
            print(f"REFUS — forme non lue côté agent : {e}")
        print("La garde ne devine pas une forme qu'elle ne sait pas lire : rien n'a été mesuré.")
        return 2

    # (P4) ANTI-VACUITÉ — avant toute comparaison.
    vides = []
    if not ps_noms["SrcIp"]:
        vides.append("le capteur PowerShell ne promeut AUCUNE adresse source")
    if not ag_promotion:
        vides.append("l'agent ne promeut AUCUNE adresse")
    if not ps_rejets:
        vides.append("le capteur PowerShell n'écarte AUCUNE écriture")
    if not ag_corpus:
        vides.append("l'agent ne déclare AUCUNE écriture à écarter")
    if not ag_exerce:
        vides.append(
            "le corpus déclaré de l'agent n'est mentionné NULLE PART ailleurs dans son fichier : "
            "aucun témoin ne l'éprouve, (P2) comparerait du texte à du texte"
        )
    if vides:
        for v in vides:
            print(f"REFUS — {v} : un ensemble vide satisferait tout, la garde mentirait.")
        return 2

    colonne_de = {"SrcIp": "src_ip", "DstIp": "dst_ip"}
    echecs = []

    # (P2b) PÉRIMÈTRE — aucun site de promotion ne contourne la frontière de son capteur.
    for site in ps_bruts:
        echecs.append(
            f"(P2b) `{site}` promeut une adresse d'Event Log SANS passer par la frontière du capteur : "
            f"`-`, `0.0.0.0` et `127.0.0.1` sont VRAIS pour `if ($SrcIp)` et deviendraient une entité "
            f"partagée par tout le parc, que l'agent, lui, écarte"
        )
    if len(ps_frontieres) > 1:
        echecs.append(
            f"(P2b) le capteur PowerShell a DEUX frontières concurrentes {sorted(ps_frontieres)} : "
            f"la frontière comparée par (P2) n'est alors pas celle que tous les sites appliquent"
        )
    if len(ag_lecteurs) != 1:
        echecs.append(
            f"(P2b) la promotion de l'agent ne passe pas par UN lecteur unique (lecteurs lus : "
            f"{sorted(ag_lecteurs)}) — deux lecteurs, deux frontières"
        )
    if ag_presence or not ag_gardes:
        echecs.append(
            "(P2b) la garde « une clé déjà posée gagne » de l'agent tranche sur la PRÉSENCE de la clé "
            "et non sur sa VALEUR : `extract_event_data` insère les `<Data Name='…'></Data>` VIDES, et "
            "une clé vide annulerait la promotion d'une adresse réelle (le défaut mesuré le 2026-08-29)"
        )

    # (P3) les clés promues par l'agent sont celles que le contrat déclare.
    for cle in ag_promotion:
        if cle not in cim or cle not in cim[cle]:
            echecs.append(
                f"(P3) l'agent range l'adresse sous `fields.{cle}`, que `promoted_fields` du CIM ne "
                f"déclare pas comme peuplant la colonne `{cle}` — la colonne resterait vide"
            )

    # (P1) contenance des NOMS, PowerShell -> agent, sens par sens.
    for sens, colonne in colonne_de.items():
        connus_agent = set(ag_promotion.get(colonne, []))
        for nom in sorted(ps_noms[sens] - connus_agent):
            echecs.append(
                f"(P1) `{nom}` est une adresse {colonne} pour collectors/windows/plume-collector.ps1 et "
                f"pour personne dans agent/src/source/windows.rs — le même enregistrement Windows rend "
                f"une entité par un capteur livré et aucune par l'autre"
            )

    # (P2) contenance de la FRONTIÈRE : l'agent écarte au moins tout ce que le PowerShell écarte.
    for val in sorted(ps_rejets - ag_corpus):
        echecs.append(
            f"(P2) « {val} » est écarté par collectors/windows/plume-collector.ps1 et n'est pas dans le "
            f"corpus déclaré de agent/src/source/windows.rs — cette écriture deviendrait une entité "
            f"chez l'un et pas chez l'autre"
        )

    if echecs:
        print("ÉCHEC — un capteur Windows livré laisse passer une adresse que l'autre écarte :")
        for e in echecs:
            print(f"  · {e}")
        return 1

    print("OK — les deux capteurs Windows livrés promeuvent la même adresse, sous le nom du contrat.")
    for sens, colonne in colonne_de.items():
        print(f"  {colonne} : PowerShell {sorted(ps_noms[sens])} ⊆ agent {sorted(ag_promotion.get(colonne, []))}")
    print(f"  frontière PowerShell (fonction unique {sorted(ps_frontieres)}) écarte : {sorted(ps_rejets)}")
    surplus = sorted(ag_corpus - ps_rejets)
    print(f"  écritures que l'AGENT écarte EN PLUS (écart assumé, jamais tu) : {surplus if surplus else '—'}")
    print(f"  sites hors Event Log écartés (instantané de socket, sans équivalent côté agent) : {hors_journal}")
    print("  NON MESURÉ ICI, et c'est `P4.12-c` : l'agent rend une forme CANONIQUE (repli de la forme")
    print("  IPv4-mappée), le capteur PowerShell rend l'écriture reçue — même frontière, chaînes différentes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
