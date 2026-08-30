#!/usr/bin/env python3
"""Une lecture qui N'A PAS EU LIEU n'est jamais servie comme un FAIT — garde de CI (`P10.7-g`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
Le démon a deux voies pour lire des lignes derrière une route : la lecture gardée par chien de garde
(`read_with_watchdog`, `daemon/src/query_exec.rs`) et l'exécution de requête (`run_query`/`run_query_ex`,
même module). Les deux peuvent ÉCHOUER — connexion de lecture indisponible, budget de 5 s épuisé sous
charge, table absente, colonne refusée par l'authorizer. Quand elles échouent, ce que la route servait
jusqu'ici avait la FORME d'un résultat : `controls: []`, `totals: {}`, `rows: []`, `total: 0`. Un
lecteur ne peut pas distinguer ce corps d'une mesure RÉELLEMENT à zéro, et sur une route de posture il
se lit « aucun contrôle en échec » — la valeur la plus rassurante, servie précisément quand rien n'a
été mesuré.

`P10.7-e` a fermé DEUX routes le 2026-08-30 et a dit lui-même ce qui le condamnerait : « son correctif
est honnête sur une route et muet ailleurs ». Cette garde-ci est la dérivation qui manquait. Elle ne
nomme aucune route : elle DÉCOUVRE la population et la juge sur une forme.

LES DEUX VOIES NE SONT PAS SYMÉTRIQUES, ET C'EST LE CŒUR DE CETTE GARDE
-----------------------------------------------------------------------
La mesure du 2026-08-30, inscrite dans le commentaire de `read_with_watchdog`, réfute l'intuition :

  * la valeur par DÉFAUT n'est rendue que sur UN chemin — `read_conn_get` n'a pas pu fournir de
    connexion. Rien dans la CONCURRENCE ne le déclenche : aucun plafond ne borne les connexions en
    cours ;
  * quand la garde de budget INTERROMPT, la closure est DÉJÀ en cours ; c'est elle qui reçoit
    `SQLITE_INTERRUPT`, et c'est SA valeur qui remonte. Le défaut n'apparaît nulle part.

Donc habiller le seul défaut rend un appelant honnête sur le chemin RARE en le laissant muet sur le
chemin que la CHARGE déclenche. C'est exactement la forme du défaut que `P10.7-e` a failli reproduire.
D'où DEUX JAMBES, et une règle qui les sépare :

  (A) LA VALEUR PAR DÉFAUT. Quand elle s'écoule vers une réponse de la MÊME fonction, elle doit porter
      un aveu, ou passer par un constructeur d'aveu DÉRIVÉ.
  (B) LA CLOSURE. Aucune lecture de lignes avalée (`.ok()`, `.unwrap_or*()`, `.flatten()`) sans qu'une
      BRANCHE de la closure construise un aveu.
  (Q) L'EXÉCUTION DE REQUÊTE. Le bras d'erreur ne peut pas être JETÉ : il propage, devient un statut
      d'échec, ou entre dans le corps sous un aveu.

  **(B) NE PEUT PAS ÊTRE SATISFAITE PAR (A), ET LA GARDE LE REFUSE EXPLICITEMENT.** L'aveu de la
  jambe B est cherché DANS LA RÉGION DE LA CLOSURE SEULEMENT — le deuxième argument (le défaut) est
  découpé de la recherche par construction, pas par convention. Sans ce refus, la garde ENTÉRINERAIT
  le défaut mesuré : elle laisserait un défaut habillé excuser la voie que la charge déclenche. Un
  mutant fabriqué le prouve dans les deux sens (`temoin 7`), et l'arbre réel le prouve aussi :
  `daemon/src/handlers/search.rs` porte un défaut HONNÊTE depuis `P10.7-a` et sa closure reste
  accusée par la jambe B.

CE QU'EST UN AVEU, AU SENS DE CETTE GARDE
------------------------------------------
La clé `error` — celle que posent `bad_req`/`server_err` (`daemon/src/main.rs`), le refus de portillon
(`handlers::portillon::corps_de_refus`) et le corps de lecture non faite de `P10.7-e`. C'est donc la clé
que les consommateurs testent DÉJÀ. Une expression porte un aveu si son texte pose cette clé, ou si
elle appelle une fonction dont le corps PROPRE la pose — liste DÉRIVÉE de `daemon/src`, jamais écrite
ici. Cette dérivation ramasse aussi des handlers qui posent `error` en ligne ; c'est sans effet, un
handler prend des extracteurs et ne s'écrit dans aucune expression de défaut.

LA POPULATION EST DÉCOUVERTE, JAMAIS ÉNUMÉRÉE
----------------------------------------------
Tout appel, dans `daemon/src/handlers/` (texte DÉPOUILLÉ DE SES COMMENTAIRES), à l'une des deux voies.
Une route neuve est couverte sans être nommée ici. Une occurrence en COMMENTAIRE n'est JAMAIS comptée —
il en existe une sur l'arbre (`daemon/src/handlers/alerts.rs`, dans le commentaire de la vue « tous
statuts ») et c'est la forme sous laquelle un site « connu » cesse d'exister sans qu'un `grep` le voie.

L'INSTRUMENT SE VALIDE AVANT DE RENDRE UN VERDICT, DANS LES DEUX SENS
----------------------------------------------------------------------
Sept mutants fabriqués, joués à chaque exécution : un corps par défaut nu DOIT accuser, le même avec un
aveu NE DOIT PAS ; une lecture de ligne avalée DOIT accuser, la même sous une branche qui avoue NE DOIT
PAS ; une exécution de requête dont la cause est jetée DOIT accuser, son branchement NE DOIT PAS ; et le
commentaire qui NOMME la fonction ne doit JAMAIS être compté. Le septième est le cœur : un défaut qui
AVOUE au-dessus d'une closure qui AVALE doit rester accusé par la jambe B.

PLANCHER SUR LA POPULATION, PAS SUR LES VIOLATIONS
---------------------------------------------------
Sous un nombre minimal de SITES DÉCOUVERTS, la lecture est cassée et la garde REFUSE DE CONCLURE
(code 2), ce qui n'est pas une violation (code 1). Le compte d'accusations, lui, A LE DROIT D'ATTEINDRE
ZÉRO : un témoin qui exigerait que le défaut survive serait une RANÇON, verte tant que le travail n'est
pas fait et rouge le jour où il l'est. Les plafonds sont des CLIQUETS : ils ne montent jamais, et
descendre est une note, pas un échec.
"""
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_every_help_trigger_has_a_section import sans_commentaires_rust  # noqa: E402

RACINE = (sys.argv[1] if len(sys.argv) > 1
          else subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True,
                              text=True, check=True).stdout.strip())
DEMON = os.path.join(RACINE, "daemon", "src")
HANDLERS = os.path.join(DEMON, "handlers")

ETIQUETTE = "lecture-non-faite"

# --- LES DEUX VOIES, NOMMÉES PAR LEUR SITE DE DÉFINITION ----------------------------------------
# Elles sont définies dans `daemon/src/query_exec.rs` ; la garde EXIGE de les y trouver (témoin
# d'ancrage) avant de compter quoi que ce soit dans les handlers.
VOIE_GARDEE = "read_with_watchdog"
VOIES_REQUETE = ("run_query_ex", "run_query")
APPEL = re.compile(r"\b(read_with_watchdog|run_query_ex|run_query)\s*\(")

# Une fonction dont la sortie EST une réponse : ce qu'elle calcule s'écoule vers son corps servi.
RETOUR_REPONSE = re.compile(r"->\s*(?:Response\b|Json\s*<|impl\s+IntoResponse\b|\(\s*StatusCode\b)")
RETOUR_RESULTAT = re.compile(r"->\s*Result\s*<")

FN = re.compile(r"(?:pub(?:\(crate\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[(<]")
# La clé `error`, posée comme clé d'objet JSON ou par affectation.
POSE_AVEU = re.compile(r'"error"\s*(?::|\.into\(\))|\[\s*"error"\s*\]\s*=')
# Une fonction dont la sortie peut s'écrire DANS une expression (défaut, bras de match).
RETOUR_CORPS = re.compile(r"->\s*(?:Value|Json\s*<\s*Value\s*>|Response|String)\s*$")
# Une lecture de LIGNES sur une connexion.
LECTURE = re.compile(r"\.\s*(?:query_row|query_map|query|prepare|prepare_cached)\s*\(")
# Les trois formes qui font d'un refus une absence.
AVALE = re.compile(r"^(?:ok|unwrap_or|unwrap_or_default|unwrap_or_else|flatten)$")
# Un statut d'échec explicite, ou un abandon COMPTÉ (le démon publie ses abandons par tick).
STATUT_ECHEC = re.compile(r"\bStatusCode::|\+=\s*1\b|\breturn\s+Err\s*\(|\bErr\s*\(")
# Un identifiant d'échec PRÉ-CONSTRUIT (`let mut fail = CorrEval { …, ok: false }`) : rendre cette
# valeur-là EST un statut d'échec, pas une valeur rassurante.
MARQUE_ECHEC = re.compile(r"\bok\s*:\s*false\b")

# --- PLANCHERS DE NON-DÉGÉNÉRESCENCE (relevé du 2026-08-30) --------------------------------------
# Arbre du jour : 44 sites (21 gardés + 23 requêtes) sur 20 fichiers de `daemon/src/handlers/`.
# SOUS ces planchers, c'est la LECTURE qui est cassée, pas le démon qui aurait cessé d'appeler : la
# garde refuse de conclure (code 2) au lieu de rendre vert en étant aveugle.
PLANCHER_SITES = 30
PLANCHER_FICHIERS = 12

# --- CLIQUETS (relevé du 2026-08-30) — ILS NE MONTENT JAMAIS -------------------------------------
# Chacun vaut le compte d'accusations DU JOUR. Descendre est une NOTE imprimée, pas un échec ; le
# compte a le droit d'atteindre zéro (c'est ce qui évite la rançon).
PLAFOND_DEFAUT_NU = 16          # jambe A : défauts servis sans aveu
PLAFOND_CLOSURE_SOURDE = 13     # jambe B : closures qui avalent une lecture de lignes sans aveu
PLAFOND_CAUSE_JETEE = 3         # jambe Q : bras d'erreur jetés


def apparier(code, i):
    """Index de la fermante appariée de l'ouvrante en `i` (-1 si le texte s'épuise). Les chaînes Rust
    sont sautées : une parenthèse dans un littéral ne compte pas."""
    paires = {"(": ")", "[": "]", "{": "}"}
    if code[i] not in paires:
        return -1
    pile, j = [paires[code[i]]], i + 1
    while j < len(code):
        c = code[j]
        if c == '"':
            j += 1
            while j < len(code) and code[j] != '"':
                j += 2 if code[j] == "\\" else 1
        elif c in paires:
            pile.append(paires[c])
        elif c in ")]}":
            if not pile or pile[-1] != c:
                return -1
            pile.pop()
            if not pile:
                return j
        j += 1
    return -1


def arguments(code, i):
    """Tranches `(début, fin)` des arguments de tête de l'appel dont la `(` est en `i`, et l'index de
    la `)` fermante. Les virgules de GÉNÉRIQUES (`HashMap<K, V>`) ne sont PAS suivies — c'est dit dans
    « ce qu'elle ne tient pas » ; aucun site de l'arbre n'en porte en position d'argument."""
    f = apparier(code, i)
    if f < 0:
        return None, -1
    out, prof, deb, j = [], 0, i + 1, i + 1
    while j < f:
        c = code[j]
        if c == '"':
            j += 1
            while j < f and code[j] != '"':
                j += 2 if code[j] == "\\" else 1
        elif c in "([{":
            prof += 1
        elif c in ")]}":
            prof -= 1
        elif c == "," and prof == 0:
            out.append((deb, j))
            deb = j + 1
        j += 1
    out.append((deb, f))
    return out, f


def coupe_tests(code):
    """Un module de test EN LIGNE est coupé : un test peut écrire n'importe quelle forme sans qu'une
    route la serve."""
    m = re.search(r"#\[cfg\(test\)\]\s*(?:pub(?:\(crate\))?\s+)?mod\s", code)
    return code[:m.start()] if m else code


def fonctions(code):
    """[(nom, signature, début du corps, fin du corps)] pour chaque `fn`/`async fn`."""
    out = []
    for m in FN.finditer(code):
        i = code.find("{", m.end())
        if i < 0:
            continue
        f = apparier(code, i)
        if f < 0:
            continue
        out.append((m.group(1), code[m.end() - 1:i].replace("\n", " "), i, f))
    return out


def fichiers_rust(rep):
    for dossier, sous, noms in os.walk(rep):
        sous[:] = [d for d in sous if d != "tests"]
        for nom in sorted(noms):
            if nom.endswith(".rs") and nom != "tests.rs":
                yield os.path.join(dossier, nom)


def sources(rep):
    for chemin in fichiers_rust(rep):
        with open(chemin, encoding="utf-8", errors="replace") as fh:
            yield chemin, fh.read()


# ================================================================================================
# CE QU'EST UN AVEU — DÉRIVÉ, JAMAIS ÉNUMÉRÉ
# ================================================================================================
def definitions(src):
    """{nom: [(fichier, ligne, corps)]} pour tout `fn` du démon, hors tests."""
    out = {}
    for chemin, texte in src:
        code = coupe_tests(sans_commentaires_rust(texte))
        for nom, sig, b, f in fonctions(code):
            out.setdefault(nom, []).append((chemin, code.count("\n", 0, b) + 1, code[b:f + 1], sig))
    return out


def constructeurs_d_aveu(defs):
    """Les fonctions dont le corps PROPRE pose la clé `error` ET qui rendent une valeur écrivable dans
    une expression. Aucun point fixe : suivre les appelants ferait de tout handler un constructeur
    (mesuré le 2026-08-30 : 298 noms au lieu de 36), et un critère qui reconnaît tout ne refuse rien."""
    out = set()
    for nom, sites in defs.items():
        for _chemin, _ligne, corps, sig in sites:
            if POSE_AVEU.search(corps) and RETOUR_CORPS.search(sig.strip()):
                out.add(nom)
    # UNE SEULE passe, et seulement pour les ENVELOPPES MINCES — un corps qui n'est QU'UN appel
    # (`fn bad_req(msg) -> Response { err_json(StatusCode::BAD_REQUEST, msg) }`). Sans elle, `bad_req`
    # et `server_err` ne sont pas des aveux et la garde accuse un bras qui rend un 400 nommé ; avec un
    # POINT FIXE au lieu d'une passe minces-seulement, tout handler appelant `bad_req` deviendrait un
    # constructeur (mesuré le 2026-08-30 : 298 noms au lieu de 40) — un critère qui reconnaît tout ne
    # refuse rien.
    minces = set()
    for nom, sites in defs.items():
        for _chemin, _ligne, corps, sig in sites:
            interieur = corps.strip()[1:-1].strip()
            m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_:]*)\s*\(.*\)", interieur, re.S)
            if m and m.group(1).split("::")[-1] in out and RETOUR_CORPS.search(sig.strip()):
                minces.add(nom)
    return out | minces


def porte_un_aveu(texte, constructeurs):
    """Le texte pose la clé `error`, ou appelle un constructeur d'aveu dérivé."""
    if POSE_AVEU.search(texte):
        return True
    return any(re.search(r"\b" + re.escape(n) + r"\s*\(", texte) for n in constructeurs)


# ================================================================================================
# LA CHAÎNE D'APPELS QUI SUIT UNE EXPRESSION
# ================================================================================================
def chaine_apres(code, fin):
    """Les méthodes chaînées après la fermante en `fin` : `['await', 'ok', 'and_then']`, `'?'` compris.
    Rend `(jetons, index de fin de l'expression)`."""
    jetons, k = [], fin + 1
    while k < len(code):
        c = code[k]
        if c in " \t\n":
            k += 1
            continue
        if c == "?":
            jetons.append("?")
            k += 1
            continue
        if c == ".":
            m = re.match(r"\.\s*([a-z_][a-z0-9_]*)\s*", code[k:])
            if not m:
                break
            jetons.append(m.group(1))
            k += m.end()
            if k < len(code) and code[k] == "(":
                e = apparier(code, k)
                if e < 0:
                    break
                jetons[-1] += "()" if e == k + 1 else "(…)"
                k = e + 1
            continue
        break
    return jetons, k


def sort_des_enveloppes(code, deb, fin):
    """Si l'appel est le corps d'une closure passée à un lanceur (`spawn_blocking(move || …)`), l'appel
    REMONTE aux bornes du LANCEUR : la cause se traite là, pas dans la closure. Rend `(début, fin)`.
    Sans la remontée du DÉBUT, `match spawn_blocking(move || run_query(…)).await { … }` n'est pas vu
    comme un branchement — le texte qui précède l'appel interne finit par `move ||` et non par `match`."""
    for _ in range(3):
        prof, i = 0, deb - 1
        while i >= 0:
            c = code[i]
            if c in ")]}":
                prof += 1
            elif c in "([{":
                if prof == 0:
                    break
                prof -= 1
            i -= 1
        if i < 0 or code[i] != "(":
            return deb, fin
        entre = code[i + 1:deb]
        if not re.fullmatch(r"\s*(?:move\s*)?\|\s*\|\s*", entre):
            return deb, fin
        f = apparier(code, i)
        if f < 0 or f < fin:
            return deb, fin
        # Le lanceur commence à son NOM, pas à sa parenthèse.
        n = re.search(r"[A-Za-z_][A-Za-z0-9_:]*\s*$", code[max(0, i - 80):i])
        fin, deb = f, (max(0, i - 80) + n.start() if n else i)
    return deb, fin


def bras_du_match(code, ouvrante):
    """[(motif, corps)] pour chaque bras de tête du bloc de `match` ouvert en `ouvrante`."""
    f = apparier(code, ouvrante)
    if f < 0:
        return []
    corps, out, prof, deb, j = code[ouvrante + 1:f], [], 0, 0, 0
    while j < len(corps):
        c = corps[j]
        if c == '"':
            j += 1
            while j < len(corps) and corps[j] != '"':
                j += 2 if corps[j] == "\\" else 1
        elif c in "([{":
            prof += 1
        elif c in ")]}":
            prof -= 1
        elif c == "," and prof == 0:
            out.append(corps[deb:j])
            deb = j + 1
        j += 1
        # UN BRAS À CORPS DE BLOC N'EST PAS SUIVI D'UNE VIRGULE : `Ok(v) => { … } Err(e) => { … }`.
        # Sans cette coupure, les deux bras n'en font qu'un et le bras d'erreur devient invisible —
        # mesuré le 2026-08-30 : SIX sites innocents accusés, dont `alerting.rs` qui COMPTE son abandon.
        if c == "}" and prof == 0 and corps[deb:j].count("=>") >= 1:
            out.append(corps[deb:j])
            deb = j
            while deb < len(corps) and corps[deb] in " \t\n,":
                deb += 1
            j = deb
        continue
    if corps[deb:].strip():
        out.append(corps[deb:])
    rendus = []
    for bras in out:
        i = bras.find("=>")
        if i > 0:
            rendus.append((bras[:i], bras[i + 2:]))
    return rendus


# ================================================================================================
# JAMBE Q — LE BRAS D'ERREUR NE PEUT PAS ÊTRE JETÉ
# ================================================================================================
GARDE, JETE, PROPAGE, NON_CLASSE = "gardé", "jeté", "propagé", "non classé"


def bras_derreur_garde(motif, corps, constructeurs, portee):
    """Un bras d'erreur est GARDÉ s'il porte la cause, avoue, propage, ou devient un statut d'échec."""
    lie = re.search(r"Err\s*\(\s*(?:Ok\s*\(\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\)", motif)
    if lie and re.search(r"\b" + re.escape(lie.group(1)) + r"\b", corps):
        return True
    if porte_un_aveu(corps, constructeurs) or STATUT_ECHEC.search(corps):
        return True
    # `Err(_) => return fail` où `fail` a été construit AVEC sa marque d'échec (`ok: false`).
    for m in re.finditer(r"\b(?:return\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*[,;}\s]*$", corps.strip()):
        d = re.search(r"let\s+(?:mut\s+)?" + re.escape(m.group(1)) + r"\s*(?::[^=]*)?=\s*", portee)
        if d and MARQUE_ECHEC.search(portee[d.end():d.end() + 600]):
            return True
    return False


def juger_le_match(code, apres, constructeurs, portee):
    """`apres` pointe juste après l'expression : le bloc de `match` doit y commencer."""
    i = apres
    while i < len(code) and code[i] in " \t\n":
        i += 1
    if i >= len(code) or code[i] != "{":
        return NON_CLASSE, "le bloc de bras est introuvable"
    bras = bras_du_match(code, i)
    err = [(m, c) for m, c in bras if re.search(r"\bErr\s*\(|\bJoinError\b", m)]
    fourre = [(m, c) for m, c in bras if m.strip() in ("_", "&_")]
    if not err and not fourre:
        return JETE, "aucun bras ne nomme l'erreur : la cause n'est écrite nulle part"
    for m, c in err + fourre:
        if not bras_derreur_garde(m, c, constructeurs, portee):
            return JETE, f"le bras `{re.sub(r'\\s+', ' ', m.strip())[:60]}` rend une valeur sans sa cause"
    return GARDE, ""


def juger_la_cause(code, deb, fin, portee_deb, portee_fin, sig, constructeurs, profondeur=0):
    """Le sort de la cause d'un `run_query`/`run_query_ex`. Rend `(verdict, raison)`."""
    portee = code[portee_deb:portee_fin]
    deb, fin = sort_des_enveloppes(code, deb, fin)
    jetons, apres = chaine_apres(code, fin)
    if "?" in jetons:
        return PROPAGE, ""
    avales = [j for j in jetons if AVALE.match(j.split("(")[0])]
    if avales:
        # `unwrap_or_else(|e| <aveu>)` porte la cause ; `.ok()` ne la porte jamais.
        bloc = code[fin:apres]
        if porte_un_aveu(bloc, constructeurs):
            return GARDE, ""
        return JETE, f"la cause est avalée par `.{avales[0]}`"
    # L'appel est-il le scrutateur d'un `match` / d'un `if let` ?
    avant = code[max(portee_deb, deb - 120):deb].rstrip()
    if avant.endswith("match") or avant.endswith("match &"):
        return juger_le_match(code, apres, constructeurs, portee)
    mif = re.search(r"if\s+let\s+([^=]{1,60})=\s*$", avant)
    if mif:
        i = apres
        while i < len(code) and code[i] in " \t\n":
            i += 1
        if i < len(code) and code[i] == "{":
            f = apparier(code, i)
            if f > 0 and not re.match(r"\s*else\b", code[f + 1:f + 12]):
                return JETE, "un `if let` sans `else` : le chemin d'échec n'est écrit nulle part"
        return GARDE, ""
    # Expression FINALE d'une fonction qui rend un `Result` : la cause remonte à l'appelant.
    reste = code[apres:portee_fin].strip()
    if reste in ("", "}") and RETOUR_RESULTAT.search(sig):
        return PROPAGE, ""
    # Liaison : `let <motif> = <expression>;` -> on suit le nom lié.
    if profondeur >= 2:
        return NON_CLASSE, "la liaison est relayée plus de deux fois"
    debut_instr = code.rfind(";", portee_deb, deb)
    debut_instr = max(debut_instr + 1, portee_deb + 1)
    tete = code[debut_instr:deb]
    mlet = re.search(r"let\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*|\([^)]*\))\s*(?::[^=]*)?=\s*[^=]*$", tete)
    if not mlet:
        return NON_CLASSE, "ni chaîne, ni branchement, ni liaison reconnus"
    noms = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", mlet.group(1))
    if not noms:
        return NON_CLASSE, "la liaison n'a pas de nom"
    return suivre_la_liaison(code, noms[0], apres, portee_deb, portee_fin, constructeurs, profondeur)


def suivre_la_liaison(code, nom, depuis, portee_deb, portee_fin, constructeurs, profondeur):
    """La première consommation du nom lié décide du sort de la cause."""
    portee = code[portee_deb:portee_fin]
    for m in re.finditer(r"(?<![\w.])" + re.escape(nom) + r"\b", code[depuis:portee_fin]):
        pos = depuis + m.start()
        avant = code[max(portee_deb, pos - 140):pos].rstrip()
        jetons, apres = chaine_apres(code, pos + len(nom) - 1)
        if avant.endswith("match") or avant.endswith("match &"):
            return juger_le_match(code, apres, constructeurs, portee)
        if re.search(r"if\s+let\s+[^=]{1,60}=\s*$", avant) or re.search(r"while\s+let\s+[^=]{1,60}=\s*$", avant):
            i = apres
            while i < len(code) and code[i] in " \t\n":
                i += 1
            if i < len(code) and code[i] == "{":
                f = apparier(code, i)
                if f > 0 and not re.match(r"\s*else\b", code[f + 1:f + 12]):
                    return JETE, "un `if let` sans `else` : le chemin d'échec n'est écrit nulle part"
            return GARDE, ""
        if "?" in jetons:
            return PROPAGE, ""
        avales = [j for j in jetons if AVALE.match(j.split("(")[0])]
        if avales:
            if porte_un_aveu(code[pos:apres], constructeurs):
                return GARDE, ""
            return JETE, f"la cause est avalée par `.{avales[0]}` sur `{nom}`"
        # RELAIS : `let (a, b) = tokio::join!(x, y)` -> on suit la position de `nom` dans les arguments.
        debut_instr = max(code.rfind(";", portee_deb, pos) + 1, portee_deb + 1)
        tete = code[debut_instr:pos]
        mlet = re.search(r"let\s+(?:mut\s+)?(\([^)]*\)|[A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]*)?=\s*", tete)
        if mlet:
            cibles = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", mlet.group(1))
            # LE RANG EST CELUI DE L'APPEL QUI CONTIENT LA POSITION, pas du premier `(` de l'instruction :
            # `let (count_res, page) = tokio::join!(count_fut, page_fut)` commence par le `(` du MOTIF, et
            # le prendre pour le macro-appel range TOUT en position 0 — mesuré le 2026-08-30, `page_fut`
            # était accusé sous le nom de `count_res`.
            rang, meilleure = None, -1
            for mo in re.finditer(r"([A-Za-z_][A-Za-z0-9_:]*)\s*!?\s*\(", code[debut_instr:pos + 1]):
                i0 = debut_instr + mo.end() - 1
                a, f0 = arguments(code, i0)
                if not a or not (i0 < pos < f0) or i0 <= meilleure:
                    continue
                for r, (d0, ff) in enumerate(a):
                    if d0 <= pos < ff:
                        rang, meilleure = r, i0
            if cibles and rang is not None and rang < len(cibles):
                return suivre_la_liaison(code, cibles[rang], max(apres, debut_instr), portee_deb,
                                         portee_fin, constructeurs, profondeur + 1)
        continue
    return NON_CLASSE, "aucune consommation du nom lié n'a été reconnue"


# ================================================================================================
# JAMBE B — UNE LECTURE DE LIGNES AVALÉE
# ================================================================================================
def lectures_avalees(texte):
    """[(ligne relative, chaîne)] pour chaque lecture de lignes dont la chaîne AVALE le refus."""
    out = []
    for r in LECTURE.finditer(texte):
        fin = apparier(texte, r.end() - 1)
        if fin < 0:
            continue
        jetons, _ = chaine_apres(texte, fin)
        if any(AVALE.match(j.split("(")[0]) for j in jetons):
            out.append((texte.count("\n", 0, r.start()) + 1, ".".join(jetons)))
    return out


def corps_de_la_closure(code, tranches, fin, defs):
    """La RÉGION DE LA CLOSURE : le troisième argument et au-delà, PLUS le corps des fonctions qu'elle
    appelle directement — un niveau, et seulement les noms qui ont UNE définition dans l'arbre.

    LE DEUXIÈME ARGUMENT — LE DÉFAUT — N'EN FAIT PAS PARTIE, ET C'EST LE POINT : la jambe B ne peut
    pas être satisfaite par la jambe A. La coupure est STRUCTURELLE (l'index de départ est celui du
    troisième argument), pas une convention qu'un correctif pourrait contourner."""
    texte = code[tranches[2][0]:fin]
    corps = [("<closure>", texte)]
    for nom in sorted(set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", texte))):
        sites = defs.get(nom)
        if sites and len(sites) == 1:
            corps.append((nom, sites[0][2]))
    return corps


# ================================================================================================
# L'INSTRUMENT SE VALIDE — SEPT MUTANTS, DANS LES DEUX SENS
# ================================================================================================
MUTANTS = [
    # (nom, source Rust, jambe attendue en accusation ou None)
    ("1. un corps par défaut NU",
     'pub(crate) async fn r1() -> Json<Value> {\n'
     '    let v = read_with_watchdog(&db, json!({ "rows": [] }), move |conn| lit(conn));\n'
     '    Json(v)\n}\n', "A"),
    ("2. le même défaut, AVEC son aveu",
     'pub(crate) async fn r2() -> Json<Value> {\n'
     '    let v = read_with_watchdog(&db, json!({ "rows": [], "error": "lecture NON FAITE" }), move |conn| lit(conn));\n'
     '    Json(v)\n}\n', None),
    ("3. une lecture de ligne AVALÉE dans la closure",
     'pub(crate) async fn r3() -> Json<Value> {\n'
     '    let v = read_with_watchdog(&db, json!({ "rows": [], "error": "x" }), move |conn| {\n'
     '        let n: i64 = conn.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0)).unwrap_or(0);\n'
     '        json!({ "n": n })\n    });\n    Json(v)\n}\n', "B"),
    ("4. la même lecture, sous une branche qui AVOUE",
     'pub(crate) async fn r4() -> Json<Value> {\n'
     '    let v = read_with_watchdog(&db, json!({ "rows": [], "error": "x" }), move |conn| {\n'
     '        let n: i64 = conn.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0)).unwrap_or(0);\n'
     '        json!({ "n": n, "error": "compte NON ÉTABLI : la lecture n\'a pas abouti" })\n    });\n'
     '    Json(v)\n}\n', None),
    ("5. une exécution de requête dont la CAUSE EST JETÉE",
     'pub(crate) async fn r5() -> Json<Value> {\n'
     '    let res = match run_query(&db, &sql) {\n'
     '        Ok(v) => v,\n'
     '        Err(_) => json!({ "columns": [], "rows": [] }),\n'
     '    };\n    Json(res)\n}\n', "Q"),
    ("6. la même exécution, BRANCHÉE sur sa cause",
     'pub(crate) async fn r6() -> Json<Value> {\n'
     '    let res = match run_query(&db, &sql) {\n'
     '        Ok(v) => v,\n'
     '        Err(e) => json!({ "columns": [], "rows": [], "error": format!("NON LU : {e}") }),\n'
     '    };\n    Json(res)\n}\n', None),
    ("7. LE CŒUR — un défaut qui AVOUE au-dessus d'une closure qui AVALE",
     'pub(crate) async fn r7() -> Json<Value> {\n'
     '    let v = read_with_watchdog(&db, corps_de_refus(json!({ "rows": [] })), move |conn| {\n'
     '        let n: i64 = conn.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0)).unwrap_or(0);\n'
     '        json!({ "n": n })\n    });\n    Json(v)\n}\n', "B"),
]

COMMENTAIRE_QUI_NOMME = (
    "// read_with_watchdog = pool read-only + interruption anti-scan-trop-long\n"
    "/* run_query(&db, &sql) y vivait avant P10.7-e */\n"
    "//! la closure passe par read_with_watchdog(&db, json!({}), |conn| lit(conn))\n"
)


def analyser(chemin, texte, defs, constructeurs, aveux):
    """Rend (sites, accusations) pour UN fichier. `aveux` recueille les pertes de lecture."""
    code = coupe_tests(sans_commentaires_rust(texte))
    fns = fonctions(code)
    sites, accusations = [], []
    for m in APPEL.finditer(code):
        voie = m.group(1)
        ligne = code.count("\n", 0, m.start()) + 1
        ou = f"{os.path.relpath(chemin, RACINE)}:{ligne}"
        tranches, fin = arguments(code, m.end() - 1)
        if tranches is None:
            aveux.append(f"{ou} — parenthèse d'appel non appariée")
            continue
        englobantes = sorted([f for f in fns if f[2] < m.start() < f[3]], key=lambda f: f[3] - f[2])
        if not englobantes:
            aveux.append(f"{ou} — appel hors de toute fonction : la portée est introuvable")
            continue
        nom_fn, sig, pdeb, pfin = englobantes[0]
        sites.append((ou, voie, nom_fn))
        if voie == VOIE_GARDEE:
            if len(tranches) < 3:
                aveux.append(f"{ou} — `{VOIE_GARDEE}` lu avec {len(tranches)} argument(s) au lieu de 3")
                continue
            # --- JAMBE A : le défaut, s'il s'écoule vers une réponse de la MÊME fonction.
            defaut = code[tranches[1][0]:tranches[1][1]].strip()
            if RETOUR_REPONSE.search(sig) and not porte_un_aveu(defaut, constructeurs):
                accusations.append(("A", ou, nom_fn,
                                    f"le défaut `{re.sub(r'\\s+', ' ', defaut)[:70]}` est servi par une "
                                    f"fonction qui rend une réponse, et il n'avoue pas"))
            # --- JAMBE B : la closure, et ELLE SEULE (le défaut est hors de la région).
            for nom_corps, corps in corps_de_la_closure(code, tranches, fin, defs):
                av = lectures_avalees(corps)
                if av and not porte_un_aveu(corps, constructeurs):
                    accusations.append(("B", ou, nom_fn,
                                        f"{len(av)} lecture(s) de lignes avalée(s) dans "
                                        f"`{nom_corps}` (`{av[0][1][:44]}`) sans qu'aucune branche "
                                        f"n'y construise un aveu"))
                    break
        else:
            verdict, raison = juger_la_cause(code, m.start(), fin, pdeb, pfin, sig, constructeurs)
            if verdict == JETE:
                accusations.append(("Q", ou, nom_fn, f"{raison} — un refus du moteur devient une absence"))
            elif verdict == NON_CLASSE:
                accusations.append(("?", ou, nom_fn, raison))
    return sites, accusations


def valider_instrument(defs, constructeurs):
    errs = []
    for nom, src, attendu in MUTANTS:
        _s, acc = analyser("/mutant.rs", src, defs, constructeurs, [])
        jambes = {j for j, *_ in acc if j != "?"}
        if attendu is None and jambes:
            errs.append(f"témoin « {nom} » : accusé sur {sorted(jambes)} alors qu'il est HONNÊTE — "
                        "la garde accuse une forme qui avoue déjà")
        if attendu is not None and attendu not in jambes:
            errs.append(f"témoin « {nom} » : NON accusé (jambes vues : {sorted(jambes) or 'aucune'}), "
                        f"attendu la jambe {attendu} — la garde laisse passer le défaut qu'elle nomme")
    # LE COMMENTAIRE QUI NOMME LA FONCTION N'EST JAMAIS UN SITE.
    s, _a = analyser("/commentaire.rs", COMMENTAIRE_QUI_NOMME, defs, constructeurs, [])
    if s:
        errs.append(f"témoin du COMMENTAIRE : {len(s)} site(s) comptés dans un texte qui n'est fait que "
                    "de commentaires — le dépouillement ne retire plus les commentaires")
    # Le dépouillement doit, dans l'autre sens, laisser le CODE intact.
    s, _a = analyser("/code.rs", "fn f() -> Json<Value> { Json(read_with_watchdog(&d, json!({}), |c| lit(c))) }",
                     defs, constructeurs, [])
    if len(s) != 1:
        errs.append(f"témoin INVERSE du dépouillement : {len(s)} site(s) au lieu de 1 — le lecteur a "
                    "cessé de voir un appel réel")
    # L'aveu se reconnaît, et son absence aussi.
    if not porte_un_aveu('json!({ "rows": [], "error": "x" })', constructeurs):
        errs.append("témoin d'AVEU : la clé `error` n'est plus reconnue")
    if porte_un_aveu('json!({ "rows": [], "errors": 0, "err": 1 })', constructeurs):
        errs.append("témoin d'AVEU (négatif) : `errors`/`err` sont comptés comme la clé `error`")
    if "corps_de_refus" not in constructeurs:
        errs.append("témoin d'ANCRAGE : `corps_de_refus` n'est plus dérivé comme constructeur d'aveu — "
                    "la dérivation ne lit plus `daemon/src/handlers/portillon.rs`")
    return errs


def ce_qui_n_est_pas_tenu(non_classes=0):
    print(f"\n[{ETIQUETTE}] CE QUE CETTE GARDE NE TIENT PAS :\n"
          "  * qu'un aveu soit VRAI. Elle juge qu'une cause atteint le corps servi, pas que la phrase "
          "qui l'accompagne dise quelque chose. Un `error: \"\"` la satisferait.\n"
          "  * la JAMBE EXÉCUTÉE. Rien ici ne lance le routeur sous un budget épuisé : la garde lit du "
          "texte. Ce qu'elle prouve, c'est qu'une forme est absente du dépôt, jamais qu'une réponse "
          "réelle avoue. Le levier EXISTE (`PLUME_QUERY_BUDGET_MS`, lu par `query_budget_ms`) et aucun "
          "levier neuf n'est à inventer ; ce qui manque est un point d'entrée qui monte le routeur sans "
          "réseau — le poser DÉPLACERAIT un compteur déclaré ailleurs, il n'est donc pas posé ici.\n"
          "  * le DÉFAUT d'une fonction qui ne rend PAS de réponse (`-> Value`, `-> Vec<_>`). La règle "
          "dit « vers une réponse de la MÊME fonction » ; un défaut qui traverse deux fonctions avant "
          "d'être servi lui échappe. Trois sites de l'arbre sont dans ce cas au 2026-08-30.\n"
          "  * les lectures faites à DEUX niveaux d'appel. La jambe B suit UN niveau, et seulement les "
          "noms qui ont une définition UNIQUE dans l'arbre ; un homonyme n'est pas suivi.\n"
          "  * les virgules de GÉNÉRIQUES en position d'argument (`HashMap<K, V>` non tourné en "
          "turbofish) découperaient mal un appel. Aucun site de l'arbre n'en porte ; le jour où il y en "
          "aura un, c'est un aveu de lecture qu'il faudra poser, pas un compte amputé rendu en vert.\n"
          "  * ce que l'ANALYSTE voit. Le démon avoue ; qu'une console lise `error` se juge ailleurs "
          "(`check_a_refusal_is_not_rendered_as_an_absence.py`).\n"
          "  * un ÉCHANGE. Les cliquets portent sur un COMPTE : rendre un site honnête et en casser un "
          "autre laisse le compte immobile et le verdict vert. C'est pourquoi CHAQUE site accusé est "
          "imprimé à chaque exécution — l'échange est visible dans le journal, il n'est pas refusé par "
          "le code de sortie.\n"
          f"  * {non_classes} site(s) d'exécution de requête dont le sort de la cause n'a PAS été "
          "classé : ils ne sont pas accusés, et ils ne sont pas innocentés.")


def main():
    src_demon = list(sources(DEMON))
    ancre = next((t for c, t in src_demon if c.endswith(os.path.join("daemon", "src", "query_exec.rs"))), "")
    manquantes = [v for v in (VOIE_GARDEE,) + VOIES_REQUETE if f"fn {v}" not in ancre]
    if manquantes:
        print(f"::error::les voies {manquantes} ne sont plus DÉFINIES dans daemon/src/query_exec.rs : "
              "la population de cette garde n'a plus d'ancrage.")
        ce_qui_n_est_pas_tenu()
        return 2

    defs = definitions(src_demon)
    constructeurs = constructeurs_d_aveu(defs)

    errs = valider_instrument(defs, constructeurs)
    if errs:
        for e in errs:
            print(f"::error::{e}")
        print(f"\n[{ETIQUETTE}] l'INSTRUMENT est faux : aucun verdict n'est rendu.")
        ce_qui_n_est_pas_tenu()
        return 2

    sites, accusations, aveux = [], [], []
    fichiers = set()
    for chemin, texte in sources(HANDLERS):
        s, a = analyser(chemin, texte, defs, constructeurs, aveux)
        if s:
            fichiers.add(os.path.relpath(chemin, RACINE))
        sites += s
        accusations += a

    if aveux:
        for a in aveux:
            print(f"::error::{a}")
        print(f"\n[{ETIQUETTE}] REFUS DE CONCLURE — le lecteur avoue avoir perdu un appel ; il ne rend "
              "pas un compte amputé en vert.")
        ce_qui_n_est_pas_tenu()
        return 2

    gardes = [s for s in sites if s[1] == VOIE_GARDEE]
    requetes = [s for s in sites if s[1] != VOIE_GARDEE]
    if len(sites) < PLANCHER_SITES or len(fichiers) < PLANCHER_FICHIERS:
        print(f"::error::{len(sites)} site(s) découvert(s) sur {len(fichiers)} fichier(s), planchers "
              f"{PLANCHER_SITES}/{PLANCHER_FICHIERS} : la DÉCOUVERTE est cassée, pas le démon. La garde "
              "REFUSE DE CONCLURE plutôt que de rendre vert en étant aveugle.")
        ce_qui_n_est_pas_tenu()
        return 2
    if not gardes or not requetes:
        print(f"::error::une des deux voies n'est plus appelée nulle part ({len(gardes)} gardée(s), "
              f"{len(requetes)} requête(s)) : la lecture ne voit plus qu'une moitié de la famille.")
        ce_qui_n_est_pas_tenu()
        return 2

    # TÉMOIN D'ANTI-TAUTOLOGIE, ET IL N'EST PAS UNE RANÇON : il exige qu'un aveu EXISTE quelque part
    # sur l'arbre, jamais qu'un défaut survive. Le jour où tout avoue, il reste vert.
    a_par_jambe = {}
    for jambe, ou, fn, raison in accusations:
        a_par_jambe.setdefault(jambe, []).append((ou, fn, raison))
    if len(a_par_jambe.get("A", [])) >= len(gardes):
        print(f"::error::AUCUN des {len(gardes)} défauts de lecture gardée ne porte d'aveu : le "
              "reconnaisseur d'aveu ne reconnaît plus rien. La garde REFUSE DE CONCLURE.")
        ce_qui_n_est_pas_tenu()
        return 2

    for jambe in ("A", "B", "Q"):
        for ou, fn, raison in a_par_jambe.get(jambe, []):
            fichier, ligne = ou.rsplit(":", 1)
            print(f"::error file={fichier},line={ligne}::[{jambe}] `{fn}` — {raison}")
    for ou, fn, raison in a_par_jambe.get("?", []):
        print(f"::notice file={ou.rsplit(':', 1)[0]},line={ou.rsplit(':', 1)[1]}::[?] `{fn}` — "
              f"sort de la cause NON CLASSÉ ({raison})")

    na, nb, nq = (len(a_par_jambe.get(j, [])) for j in ("A", "B", "Q"))
    nc = len(a_par_jambe.get("?", []))
    print(f"\n[{ETIQUETTE}] POPULATION DÉCOUVERTE le jour de l'exécution : {len(sites)} site(s) sur "
          f"{len(fichiers)} fichier(s) de daemon/src/handlers — {len(gardes)} lecture(s) gardée(s), "
          f"{len(requetes)} exécution(s) de requête. Commentaires DÉPOUILLÉS : une occurrence citée en "
          "commentaire n'est jamais un site.")
    print(f"[{ETIQUETTE}] ACCUSATIONS : jambe A (défaut nu) {na}/{PLAFOND_DEFAUT_NU} · jambe B "
          f"(closure sourde) {nb}/{PLAFOND_CLOSURE_SOURDE} · jambe Q (cause jetée) "
          f"{nq}/{PLAFOND_CAUSE_JETEE} · non classés {nc}.")

    depasse = [(j, n, p) for j, n, p in (("A", na, PLAFOND_DEFAUT_NU), ("B", nb, PLAFOND_CLOSURE_SOURDE),
                                         ("Q", nq, PLAFOND_CAUSE_JETEE)) if n > p]
    if depasse:
        for j, n, p in depasse:
            print(f"::error::jambe {j} : {n} accusation(s) pour un cliquet à {p}. Ce cliquet NE MONTE "
                  "PAS : la forme neuve doit avouer, ou l'aveu doit entrer dans la branche.")
        ce_qui_n_est_pas_tenu(nc)
        return 1

    dessous = [(j, n, p) for j, n, p in (("A", na, PLAFOND_DEFAUT_NU), ("B", nb, PLAFOND_CLOSURE_SOURDE),
                                         ("Q", nq, PLAFOND_CAUSE_JETEE)) if n < p]
    if dessous:
        print(f"[{ETIQUETTE}] LE CLIQUET PEUT DESCENDRE : " + ", ".join(f"jambe {j} à {n} (au lieu de {p})"
                                                                       for j, n, p in dessous)
              + ". Un cliquet refuse une hausse ; il ne force aucune baisse, et ZÉRO est une valeur "
                "atteignable — un témoin qui exigerait que le défaut survive serait une rançon.")
    ce_qui_n_est_pas_tenu(nc)
    return 0


if __name__ == "__main__":
    sys.exit(main())
