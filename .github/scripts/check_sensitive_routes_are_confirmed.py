#!/usr/bin/env python3
"""Toute action sensible confirme, et la liste des actions sensibles vient des ROUTES du démon (`P11.5-b`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
Une rétention enregistrée sans confirmation, un rôle changé d'un clic : la console laissait partir vers
le démon des mutations qui détruisent des données, élèvent un droit ou arment une réponse automatique,
sans que l'utilisateur ait vu la conséquence. Une liste de « routes à confirmer » écrite à la main
aurait le défaut de toute liste : la route suivante ne s'y ajoute pas. Ici, la liste est DÉRIVÉE du
code du démon à chaque exécution, et c'est la surface web qui doit la rattraper.

CE QUI REND UNE ROUTE SENSIBLE — trois familles, chacune lue dans le code du démon
-------------------------------------------------------------------------------------
Le périmètre est l'ensemble des routes MUTANTES du routeur (`daemon/src/server/`, méthodes post/put/
patch/delete), moins les POST de lecture que le démon déclare lui-même (`is_readonly_post`, auth.rs) et
les routes sans session (login, setup, SAML, LDAP, MFA de connexion). Chaque route est résolue vers le
corps de son handler (le symbole nommé dans `.route(...)`), et une route est sensible si :

  DÉTRUIT DES DONNÉES  — verbe HTTP `delete` ; ou le handler applique une purge
                          (`purge_confirm_and_apply`), élague (`prune`), pose le drapeau `"destructive"`
                          dans son audit, ou rend une portée « purgeable » (levée de legal-hold).
                          Un DELETE que le démon audite lui-même au niveau informatif (sévérité 1, le
                          bulletin) n'est pas une destruction : c'est le démon qui le dit.
  ÉLÈVE UN DROIT       — le handler lit un `role` dans le corps de la requête, ou insère un jeton
                          (`INSERT INTO token`) : identité, crédence d'accès.
  ARME UNE RÉPONSE     — les deux déclarations d'armement de `rbac.rs` (`/api/mode` en mutation ;
                          suffixe `/enabled` sur règles/parseurs/playbooks, et tout `/enabled` mutant),
                          un handler qui touche le ban natif (`netban`), ou un handler que le démon
                          audite à sa sévérité maximale (4 : « défense baissée », compte créé).

CE QUE LA SURFACE DOIT FAIRE
----------------------------
Pour chaque route sensible, chaque APPELANT web (un `apiSend(` ou `fetch(` de `web/*.js` dont le chemin
et la méthode correspondent à la route) doit se trouver dans une fonction qui passe par une confirmation
PARTAGÉE — une fonction `confirm*` exportée par `web/core.js` (la liste est lue dans l'export, jamais
écrite ici) — soit directement, soit par un appelant à au plus trois niveaux (le chemin `bouton ->
fonction nommée -> apiSend`). Un appel placé dans une fonction qui ne confirme pas et que personne ne
confirme en amont est un défaut. Une route sensible SANS appelant web n'est pas un défaut (machine-to-
machine, contrôle par API) : elle est listée, et le jour où un appelant apparaît il est tenu.

LES ENVELOPPES PARTAGÉES SONT SUIVIES, ET ELLES SONT DÉRIVÉES (`P11.13-h` (a))
------------------------------------------------------------------------------
Un appel ne se lit pas toujours chez celui qui l'émet : `web/core.js` expose des fonctions qui reçoivent
le CHEMIN EN ARGUMENT et le passent à `apiSend`, et la console édite et supprime règles, parseurs,
playbooks et lookups par elles. Le motif d'appel ne cherchait que `apiSend(`/`fetch(` : MESURÉ le
2026-08-29, quatre routes DESTRUCTRICES de ces quatre familles étaient déclarées « sans appelant web »,
c'est-à-dire contrôlées par l'interface de programmation seule, alors que la console les atteint — et,
vérifié une à une, les confirme toutes. La garde ne disait pas « non confirmée » : elle disait « la
console ne va pas là », ce qui est faux, et c'est la forme la plus dangereuse de l'erreur parce qu'elle
se lit comme une garantie. Ces enveloppes sont DÉRIVÉES (`enveloppes_de_core`) par la relation « un
paramètre part comme chemin d'`apiSend` », jamais énumérées par leur nom ; sans elles la garde refuse de
conclure, parce qu'une dérivation muette reclasserait ces routes en silence. Le suivi n'a rien desserré :
64 -> 68 confirmées, 29 -> 25 sans appelant web, et AUCUN cliquet n'a bougé.

CE QUE LA GARDE LAISSE TOMBER EST AVOUÉ ET COMPTÉ (`P11.13-h` (b))
------------------------------------------------------------------
Les sorties de la boucle des appelants passaient au suivant sans rien inscrire : la garde ne publiait ni
combien d'appels elle avait laissés de côté, ni lesquels. Un instrument qui abandonne sans le dire rend
un verdict amputé sous la forme d'un vert — la route qu'un appel abandonné atteint peut rester « sans
appelant web ». Tout abandon est désormais INSCRIT, COMPTÉ et tenu par un plancher (`PLAFOND_ABANDONS`)
qui ne se relève pas. Deux formes : un chemin porté par une VARIABLE (indérivable au site d'appel), et un
chemin écrit en TERNAIRE — la forme ordinaire d'un enregistrement, « créer ou mettre à jour selon qu'un
identifiant est en cours d'édition ». Les deux branches d'un ternaire sont dérivables et désignent deux
routes réelles ; elles sont NOMMÉES dans l'aveu pour que la dette soit payable, mais elles ne sont pas
APPRÉCIÉES : mesuré le 2026-08-29, les apprécier ferait passer le cliquet des asymétries de 12 à 20,
c'est-à-dire ferait loger huit dettes de surface dans le cliquet même qui doit les attraper. L'ordre
juste est écrit dans `P11.13-h` (c) et il vaut au-delà de cette garde : payer la dette D'ABORD, resserrer
ENSUITE, le cliquet ne bougeant JAMAIS vers le haut. Ne pas les apprécier n'ôte rien : le motif que
l'ancienne dérivation recollait bout à bout (`/api/rules//rules`) n'existe dans aucune table, et le
verdict est IDENTIQUE avec et sans lui — vérifié état par état.

LA GARDE SE LIT DANS LES DEUX SENS (`P11.13-b`)
-----------------------------------------------
Les trois familles ci-dessus disent ce qui est sensible ; elles ne disaient rien de ce qu'elles RATENT.
Mesuré le 2026-08-24 sur ce dépôt : 23 routes mutantes que les DEUX surfaces traitent déjà comme
sensibles — le démon inscrit le changement à son journal (`audit_config_change` / `audit_source_change`)
et TOUS les appelants web passent par une confirmation partagée — n'entraient dans aucune des trois
familles. Vingt-trois n'est pas un accident, c'est un motif : le critère était plus étroit que le
traitement réel, et une garde qui rate une route déjà confirmée ratera la suivante, qui elle ne le sera
pas. D'où un SECOND SENS de lecture, et une famille de plus :

  DÉCLARE               — le démon AUDITE le changement et la console le CONFIRME partout. La famille
                          n'ajoute aucune exigence à ces routes (elles sont confirmées par définition) ;
                          elle les fait ENTRER dans la liste dérivée, pour que l'écart entre le critère
                          et le traitement des surfaces soit nul et le reste.

  ANGLE MORT            — une route que les deux surfaces traitent comme sensible et que la dérivation
                          ne reconnaît pas est une ERREUR : c'est la cécité que `P11.13-b` nomme. Après
                          l'élargissement il n'en reste aucune ; retirer la famille les fait toutes
                          reparaître, et c'est la mutation qui prouve ce sens de lecture.

  ASYMÉTRIE             — le démon audite, la console ATTEINT la route, et tous ses appelants ne
                          confirment pas : les deux surfaces ne disent pas la même chose. Ce n'est pas la
                          cécité de la garde mais une dette de la surface, et elle est tenue par un
                          CLIQUET (`PLAFOND_ASYMETRIE`) : une route auditée appelée sans confirmation de
                          plus fait rougir. C'est ce cliquet qui attrape « la suivante ».

CE QUE « CONFIRMÉE » VAUT AU JUSTE — limite MESURÉE À CHAQUE EXÉCUTION, valable dans les DEUX sens
La remontée d'appelants répond à « UN appelant confirme-t-il ? », pas à « TOUS les chemins
confirment-ils ? » : un existentiel, là où la propriété visée est universelle. Cette limite était écrite
ici avec un chiffre relevé un jour donné, que plus rien ne suivait. Elle est maintenant DÉRIVÉE : chaque
appel confirmé retient l'ORIGINE de sa confirmation — `propre` (écrite dans la fonction qui envoie),
`ancetre` (une portée qui la CONTIENT), `appelant` (une portée qui la NOMME). Seule la troisième est
faible : la portée qui confirme peut appartenir à un geste VOISIN. Le compte des `appelant` est PUBLIÉ
et tenu par un plancher (`PLAFOND_CONFIRME_PAR_APPELANT`) qui ne se relève pas. C'est un COMPTE, pas un
resserrement : aucune de ces routes n'est accusée, et la garde ne rend ni plus ni moins de « confirmée »
qu'avant ce compte.
MESURÉ le 2026-08-29 sur `web/destinations.js`, et c'est la forme la plus nette : une SEULE fonction du
module portait une confirmation, celle qui SUPPRIME — et pourtant les trois appels mutants du module
étaient déclarés confirmés, dont le déclencheur de SORTIE DE DONNÉES vers un puits externe, qui n'en
avait aucune. Le lien n'est même pas une portée ancêtre : les trois fonctions appellent la même fonction
de RAFRAÎCHISSEMENT, ce qui suffit à faire de celle qui supprime un « appelant » des deux autres.
Resserrer produirait toujours une FAUSSE accusation — le motif `/api/connectors/*` d'un appel destiné à
`/api/connectors/{id}` recouvre `/api/connectors/push-source`, que la console n'appelle pas là — et les
deux imprécisions se corrigent ensemble ou pas du tout. Le second sens de lecture LIT LE MÊME signal que
le premier, délibérément : deux lectures divergentes de « confirmée » vaudraient moins qu'une seule
lecture dont la limite est écrite — et, désormais, comptée.

Ce que la garde ne fait PAS : traiter la seule confirmation de la console comme une déclaration de
sensibilité. Une confirmation est un choix d'ergonomie (un formulaire dont on relit le contenu) ; le
démon, lui, engage un journal. Le compte des routes confirmées que le démon n'audite pas est IMPRIMÉ,
jamais compté comme défaut — sans quoi `POST /api/rules/{id}/test` deviendrait « sensible ».

L'INSTRUMENT SE VALIDE AVANT DE RENDRE UN VERDICT
--------------------------------------------------
Témoins sur un corpus de contrôle : une route DELETE avec un appelant confirmé (doit passer), la même
sans confirmation (doit rougir), une route de création ordinaire (ne doit pas être sensible), un
appelant confirmé par sa fonction APPELANTE (doit passer), un appel en commentaire (ne compte pas).
Pour le second sens : une route auditée et confirmée partout est un ANGLE MORT tant que la famille
`DÉCLARE` ne la reprend pas, et cesse de l'être une fois reprise ; une route auditée appelée SANS
confirmation est une ASYMÉTRIE ; une route auditée sans appelant web et une route confirmée que le démon
n'audite pas ne sont NI l'un NI l'autre. Pour les enveloppes : deux à dériver et deux LEURRES (une
fonction au chemin littéral, une qui n'envoie rien) ; puis une route que la console ne DÉTRUIT qu'au
travers d'une enveloppe, exigée « sans appelant web » quand on ne les suit pas et « confirmée » quand on
les suit — les deux sens, sans quoi le témoin ne mesure rien. Pour le ternaire : positif (deux branches
lues séparément) ET négatif (`?.`, `??` et un ternaire imbriqué dans une parenthèse ne se scindent pas),
plus l'exigence qu'aucune branche ne produise de site apparié. Pour les abandons : les deux formes sont
avouées, et une DÉCLARATION du même nom qu'une enveloppe n'est pas comptée comme un site — sans quoi le
compte serait gonflé d'un aveu faux. Pour les origines : `propre`, `ancetre` et `appelant` doivent se
distinguer. Puis des planchers sur l'arbre réel : un nombre minimal de routes sensibles, une route témoin
trouvée sensible ET confirmée (`/api/users/{id}`, le changement de rôle), sans quoi la garde refuse de
conclure.

LES TROIS PLANCHERS SE RE-MESURENT EN UNE EXÉCUTION
---------------------------------------------------
`PLAFOND_ABANDONS` et `PLAFOND_CONFIRME_PAR_APPELANT` portent des nombres relevés sur l'arbre. Quand la
garde en trouve MOINS elle le dit et invite à descendre le plancher ; quand elle en trouve PLUS elle
rougit et imprime le compte. Aucun des deux ne se relève : les faire monter ferait de la place au lieu
d'en reprendre.
"""
import os
import re
import subprocess
import sys

RACINE = (sys.argv[1] if len(sys.argv) > 1
          else subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True,
                              text=True, check=True).stdout.strip())
DEMON = os.path.join(RACINE, "daemon", "src")
WEB = os.path.join(RACINE, "web")

MIN_ROUTES_SENSIBLES = 12
ROUTE_TEMOIN = ("POST", "/api/users/{id}")
# CLIQUET DU SECOND SENS (`P11.13-b`) : routes que le démon AUDITE, que la console ATTEINT, et dont tous les
# appelants ne confirment pas. 12 mesurées le 2026-08-24 ; ce nombre ne se relève pas sans raison écrite ici —
# une route auditée appelée sans confirmation de plus est exactement le défaut que la garde doit attraper.
PLAFOND_ASYMETRIE = 12
# PLANCHER DES ABANDONS (`P11.13-h` (b)) : appels mutants que la dérivation ne sait pas apparier (chemin
# porté par une variable, méthode indéterminée). Chacun est un trou : la route qu'il atteint peut rester
# « sans appelant web », et ce silence se lit comme une garantie. Il ne se relève JAMAIS.
PLAFOND_ABANDONS = 11
# PLANCHER DES « CONFIRMÉE PAR APPELANT » (`P11.13-b`) : appels dont la confirmation n'est ni dans leur
# propre portée ni dans une portée qui les CONTIENT, mais dans une portée qui les NOMME. Cette forme est la
# plus faible : la portée qui confirme peut appartenir à un geste VOISIN — mesuré sur `web/destinations.js`,
# le déclencheur de sortie de données et l'interrupteur d'activation empruntaient tous deux la confirmation
# du bouton qui SUPPRIME, seule fonction du module à en porter une. Compté, jamais accusé ; ne se relève pas.
PLAFOND_CONFIRME_PAR_APPELANT = 30
# PLANCHER DES SITES OBTENUS PAR UNE ENVELOPPE (`P11.13-h` (a)) : atteste que le suivi des enveloppes est
# BRANCHÉ sur le verdict, pas seulement validé en témoin. Mesuré sur l'arbre ; il ne descend pas.
PLANCHER_SITES_PAR_ENVELOPPE = 4

# LE DÉPOUILLEMENT ET L'AVEUGLEMENT DES LITTÉRAUX SONT IMPORTÉS, PLUS RECOPIÉS (`P11.8-f`). « Même
# dépouillement que les gardes voisines » était vrai du texte et faux du RÉSULTAT : quatre copies, quatre
# fois la même cécité au littéral d'expression régulière. Le geste est celui de `sans_commentaires_css`,
# que la garde du chrome importe de la garde des sélecteurs.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_every_help_trigger_has_a_section import (  # noqa: E402  (source unique de vérité)
    aveugler_litteraux_js, refuser_sur_aveu, sans_commentaires_js, sans_commentaires_rust,
    temoins_du_lecteur)


# --- démon : routes, handlers, déclarations --------------------------------------------------------
ROUTE = re.compile(r'\.route\(\s*"([^"]+)"\s*,\s*((?:[a-z]+\([^()]*\)\.?)+)\s*\)')
VERBE = re.compile(r'\b(get|post|put|patch|delete)\(\s*([A-Za-z_][A-Za-z0-9_:]*)\s*\)')
FN = re.compile(r'(?:pub(?:\(crate\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[(<]')
READONLY_POST = re.compile(r'fn\s+is_readonly_post\s*\([^)]*\)\s*->\s*bool\s*\{(.*?)\n\}', re.S)
LITTERAUX = re.compile(r'"(/[^"]*)"')
# Écriture d'une IDENTITÉ ou d'un DROIT : une ligne `user` créée ou son rôle changé, un `grant` posé, un jeton
# porteur d'accès inséré. Lire un `role` ne suffit pas : un field filter lit un rôle pour délimiter sa portée.
ECRIT_IDENTITE = re.compile(r'INSERT\s+(?:OR\s+REPLACE\s+)?INTO\s+(?:user\b|\\?"?grant\\?"?\b)|UPDATE\s+user\s+SET\s+role', re.I)
INSERT_TOKEN = re.compile(r'INSERT\s+(?:OR\s+REPLACE\s+)?INTO\s+token\b', re.I)
AUDIT_SEV = re.compile(r'audit_(?:config|source)_change\([^;]*?,\s*(\d)\s*,', re.S)
# LE DÉMON DÉCLARE LUI-MÊME QU'IL S'AGIT D'UN CHANGEMENT en l'inscrivant à son journal. `audit_bulk_read`
# n'en est pas : c'est une LECTURE tracée, elle ne change rien et ne dit rien de la sensibilité d'une mutation.
AUDIT_CHANGEMENT = re.compile(r'\baudit_(?:config_change|source_change|tenant_event)\s*\(')
MODE_ARME = re.compile(r'path\s*==\s*"(/api/mode)"[^}]*?mutating\s*\{\s*MinRole::Admin')
ENABLED_ARME = re.compile(r'path\.ends_with\(\s*"(/enabled)"\s*\)')


def fichiers_rust():
    for dossier, sous, noms in os.walk(DEMON):
        sous[:] = [d for d in sous if d != "tests"]
        for nom in sorted(noms):
            if nom.endswith(".rs") and nom != "tests.rs":
                yield os.path.join(dossier, nom)


def corps_des_fonctions(code):
    """{nom: corps} pour chaque `fn` / `async fn` (corps = texte jusqu'à l'accolade fermante appariée)."""
    out = {}
    for m in FN.finditer(code):
        i = code.find("{", m.end())
        if i < 0:
            continue
        depth, j = 0, i
        while j < len(code):
            if code[j] == "{":
                depth += 1
            elif code[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        out.setdefault(m.group(1), code[i:j + 1])
    return out


def deriver_routes(sources):
    """`sources` : [(chemin, texte Rust)]. Rend (routes, handlers, readonly_posts, armement, erreurs)."""
    routes, handlers, readonly, armement, erreurs = [], {}, set(), {"mode": None, "enabled": None}, []
    for chemin, texte in sources:
        code = sans_commentaires_rust(texte)
        # Un MODULE de test en ligne est coupé ; un simple item `#[cfg(test)] fn` au milieu d'un fichier de
        # production ne l'est pas (mesuré : soql_meta.rs et sigma.rs en portent, avant leurs handlers).
        coupe = re.search(r"#\[cfg\(test\)\]\s*(?:pub(?:\(crate\))?\s+)?mod\s", code)
        if coupe:
            code = code[:coupe.start()]
        for nom, corps in corps_des_fonctions(code).items():
            handlers.setdefault(nom, corps)
        for m in ROUTE.finditer(code):
            path = m.group(1)
            for v in VERBE.finditer(m.group(2)):
                verbe, handler = v.group(1).upper(), v.group(2).split("::")[-1]
                if verbe == "GET":
                    continue
                routes.append((verbe, path, handler, os.path.relpath(chemin, RACINE)))
        rp = READONLY_POST.search(code)
        if rp:
            readonly.update(LITTERAUX.findall(rp.group(1)))
        mm = MODE_ARME.search(code)
        if mm:
            armement["mode"] = mm.group(1)
        em = ENABLED_ARME.search(code)
        if em:
            armement["enabled"] = em.group(1)
    if not routes:
        erreurs.append("aucune route mutante dérivée du routeur")
    return routes, handlers, readonly, armement, erreurs


# Routes sans session (bootstrap, connexion) : aucune confirmation n'a de sens AVANT d'être connecté.
# Dérivé de la forme du chemin, pas d'une liste de routes : tout ce qui est sous /api/auth/, /api/login*,
# /api/logout, /api/setup.
SANS_SESSION = re.compile(r'^/api/(?:auth/|login|logout|setup)')


def corps_etendu(handler, handlers):
    """Le corps du handler PLUS celui des fonctions qu'il appelle directement (un niveau) — une insertion de
    jeton ou d'utilisateur, comme un appel au journal, vit souvent dans un helper (`token_insert`,
    `scim_upsert`). Rend None quand le symbole n'est pas résolu."""
    propre = handlers.get(handler)
    if propre is None:
        return None
    appelees = set(re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', propre)) - {handler}
    return propre + "".join(handlers.get(n, "") for n in appelees if n in handlers)


def dans_le_perimetre(path, readonly):
    """Une route mutante est jugée sauf si le démon la déclare en lecture, ou si elle précède la session."""
    return path not in readonly and not SANS_SESSION.match(path)


def classer(routes, handlers, readonly, armement):
    """Rend {(verbe, path): (familles, handler, fichier)} pour les routes sensibles, + erreurs."""
    sensibles, erreurs = {}, []
    for verbe, path, handler, fichier in routes:
        if not dans_le_perimetre(path, readonly):
            continue
        corps = corps_etendu(handler, handlers)
        if corps is None:
            erreurs.append(f"{fichier} : handler `{handler}` de {verbe} {path} introuvable — la garde ne peut pas lire ce qu'il fait")
            continue
        familles = []
        sevs = [int(s) for s in AUDIT_SEV.findall(corps)]
        # DÉTRUIT
        if verbe == "DELETE" and not (sevs and max(sevs) <= 1):
            familles.append("détruit (DELETE)")
        if "purge_confirm_and_apply" in corps or re.search(r'\bprune\w*\(', corps):
            familles.append("détruit (purge/élagage)")
        if '"destructive"' in corps or "purgeable" in corps:
            familles.append("détruit (audité destructif / rend purgeable)")
        # ÉLÈVE
        if ECRIT_IDENTITE.search(corps):
            familles.append("élève (identité / rôle / grant)")
        if INSERT_TOKEN.search(corps):
            familles.append("élève (jeton)")
        # ARME
        if armement["mode"] and path == armement["mode"]:
            familles.append("arme (mode)")
        if armement["enabled"] and path.endswith(armement["enabled"]):
            familles.append("arme (activation)")
        if "netban" in corps:
            familles.append("arme (ban natif)")
        if sevs and max(sevs) >= 4:
            familles.append("arme/défense (audit sévérité 4)")
        if familles:
            sensibles[(verbe, path)] = (familles, handler, fichier)
    return sensibles, erreurs


# --- surface web : appelants et confirmations ---------------------------------------------------------
EXPORT_CORE = re.compile(r'\bexport\s*\{([^}]*)\}', re.S)
APPEL = re.compile(r'\b(apiSend|fetch)\(')


def confirmations_de_core(core_src):
    m = EXPORT_CORE.search(sans_commentaires_js(core_src))
    noms = [x.strip() for x in (m.group(1) if m else "").split(",")]
    return sorted(n for n in noms if n.startswith("confirm"))


def argument_chemin(src, i):
    """Texte du premier argument d'un appel dont la parenthèse ouvrante est en `i`, et le second."""
    depth, j, args, cur = 0, i, [], []
    while j < len(src):
        c = src[j]
        if c in "\"'`":
            k = j + 1
            while k < len(src) and src[k] != c:
                k += 2 if src[k] == "\\" else 1
            cur.append(src[j:k + 1]); j = k + 1; continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                args.append("".join(cur)); break
        if c == "," and depth == 1:
            args.append("".join(cur)); cur = []
        else:
            if not (c == "(" and depth == 1 and not cur):
                cur.append(c)
        j += 1
    return [a.strip() for a in args]


def scinder_ternaire(arg):
    """Découpe une expression au niveau SUPÉRIEUR sur `cond ? a : b` et rend ses branches (sinon `[arg]`).

    `P11.13-h` (b) — LA FORME ORDINAIRE D'UN ENREGISTREMENT EST UN TERNAIRE : créer ou mettre à jour selon
    qu'un identifiant est en cours d'édition (`S.editingRule ? '/rules/' + S.editingRule : '/rules'`).
    MESURÉ : `motif_de_chemin` recollait les deux branches bout à bout (`/api/rules//rules`) et rendait un
    motif qui n'existe dans AUCUNE table de routes — l'appel n'était donc apparié à rien, en silence. Les
    deux branches atteignent deux routes RÉELLES et différentes ; elles sont rendues séparément.
    Les parenthèses, crochets et littéraux sont traversés pour que seul le `?` de tête compte, et `?.`
    comme `??` ne sont pas des ternaires."""
    depth, i, q, c = 0, 0, None, None
    while i < len(arg):
        ch = arg[i]
        if ch in "\"'`":
            k = i + 1
            while k < len(arg) and arg[k] != ch:
                k += 2 if arg[k] == "\\" else 1
            i = k + 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif depth == 0 and ch == "?":
            # `?.` et `??` portent un `?` qui n'ouvre AUCUN ternaire : il faut les ENJAMBER, pas seulement
            # refuser d'y poser `q` — sinon le second `?` de `??` était pris pour le ternaire, et la
            # première branche commençait un caractère trop loin. Mesuré par mutation le 2026-08-29.
            if arg[i:i + 2] in ("?.", "??"):
                i += 2
                continue
            if q is None:
                q = i
        elif depth == 0 and ch == ":" and q is not None and c is None:
            c = i
        i += 1
    if q is None or c is None:
        return [arg]
    return [arg[q + 1:c].strip(), arg[c + 1:].strip()]


def motif_de_chemin(arg):
    """Transforme l'expression JS du chemin en motif : littéraux gardés, expressions -> un segment joker."""
    parts = re.findall(r"""'([^']*)'|"([^"]*)"|`([^`]*)`""", arg)
    if not parts:
        return None
    s = ""
    for a, b, c in parts:
        s += a or b or c.replace("${", "\x00${").replace("}", "}\x00")
    # `${...}` -> joker ; concaténations hors littéraux -> joker entre les morceaux
    s = re.sub(r"\x00\$\{[^}]*\}\x00", "*", s)
    # morceaux séparés par `+ expr +` : un joker est inséré là où deux littéraux se suivent sans slash
    out, prev = [], None
    for a, b, c in parts:
        lit = a or b or re.sub(r"\$\{[^}]*\}", "*", c)
        if prev is not None and not prev.endswith("/") and not lit.startswith("/") and not prev.endswith("*"):
            out.append("*")
        out.append(lit); prev = lit
    s = "".join(out)
    if "+" in arg and not s.endswith("*") and not re.search(r"'\s*\)?$|\"\s*\)?$|`\s*\)?$", arg.strip()):
        s += "*"
    s = s.split("?")[0]
    if not s.startswith("/api/"):
        s = "/api" + s
    return s


def methode_de(nom, args):
    if nom == "apiSend":
        if len(args) >= 2:
            m = re.match(r"""['"]([A-Z]+)['"]""", args[1])
            return m.group(1) if m else "?"
        return "POST"
    m = re.search(r"""method\s*:\s*['"]([A-Z]+)['"]""", args[1] if len(args) >= 2 else "")
    return m.group(1) if m else "GET"


def motif_correspond(motif, route):
    """`motif` = chemin côté web (`*` = segment inconnu) ; `route` = gabarit axum (`{id}`).

    LA SYNTAXE DU GABARIT EST CELLE DU ROUTEUR, ET ELLE A CHANGÉ (axum 0.7 `:id` -> axum 0.8 `{id}`).
    Une seule syntaxe est reconnue, celle du présent : accepter les deux laisserait vivre côte à côte
    une forme que la table ne produit plus.

    CE QUE CETTE LIGNE COÛTE QUAND ELLE EST FAUSSE — MESURÉ le 2026-08-26 en laissant l'appariement
    sur `:` alors que la table déclare `{…}` : la garde reste VERTE (`rc=0`), le plancher
    `ROUTE_TEMOIN` la laisse passer (son appelant web porte un `*`, jamais un segment concret), et
    pourtant 12 routes sensibles basculent de « confirmée » à « sans appelant web » (64 -> 52) et le
    cliquet d'asymétrie se desserre tout seul de 12 à 10. C'est-à-dire : verte en étant aveugle.
    Ce sont donc les DEUX témoins de `valider_instrument()` — un segment concret qui DOIT s'apparier
    à `{id}`, et `:id` qui ne DOIT PLUS s'apparier — qui tiennent cette ligne, pas le plancher.
    """
    mp, rp = motif.strip("/").split("/"), route.strip("/").split("/")
    if len(mp) != len(rp):
        return False
    for a, b in zip(mp, rp):
        if (b.startswith("{") and b.endswith("}")) or a == "*":
            continue
        if "*" in a:
            if not re.fullmatch(re.escape(a).replace(r"\*", ".*"), b):
                return False
        elif a != b:
            return False
    return True


SCOPE = re.compile(r'(?:async\s+)?function\s*(?:[A-Za-z_$][\w$]*)?\s*\([^()]*\)\s*\{|(?:async\s*)?(?:\([^()]*\)|[A-Za-z_$][\w$]*)\s*=>\s*\{')
NOM_AVANT = re.compile(r'(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?$|function\s+([A-Za-z_$][\w$]*)\s*$')


def scopes_js(code):
    """[(nom|None, début, fin)] pour chaque fonction (déclarée, expression, flèche) — nom = celui de la
    déclaration ou de la variable qui la reçoit ; une flèche posée sur un `onclick` reste anonyme."""
    aveugle = aveugler_litteraux_js(code)
    out = []
    for m in SCOPE.finditer(aveugle):
        i = m.end() - 1
        depth, j = 0, i
        while j < len(aveugle):
            if aveugle[j] == "{":
                depth += 1
            elif aveugle[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        tete = aveugle[max(0, m.start() - 80):m.start()]
        nm = re.search(r'function\s+([A-Za-z_$][\w$]*)\s*\(', aveugle[m.start():m.end()])
        nom = nm.group(1) if nm else None
        if nom is None:
            av = NOM_AVANT.search(tete)
            nom = (av.group(1) or av.group(2)) if av else None
        out.append((nom, i, j))
    return out


def fonction_englobante(scopes, pos):
    """Le scope le plus intérieur qui contient `pos`."""
    meilleur = None
    for sc in scopes:
        if sc[1] <= pos <= sc[2] and (meilleur is None or sc[1] > meilleur[1]):
            meilleur = sc
    return meilleur


DECLARATION = re.compile(r'\bfunction\s+$')
SIGNATURE_JS = re.compile(r'(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(([^()]*)\)\s*\{')


def enveloppes_de_core(core_src):
    """`P11.13-h` (a) — LES ENVELOPPES PARTAGÉES SONT DÉRIVÉES, JAMAIS ÉNUMÉRÉES.

    Le motif d'appel ne cherchait que `apiSend(`/`fetch(` dans le module qui les appelle. Or la console
    édite et supprime règles, parseurs, playbooks et lookups par des fonctions de `web/core.js` qui
    prennent le CHEMIN EN ARGUMENT et le passent à `apiSend` : chez l'appelant, le chemin ne se lit plus
    dans un `apiSend`. MESURÉ le 2026-08-29 : quatre routes DESTRUCTRICES de ces quatre familles étaient
    déclarées « sans appelant web » — c'est-à-dire contrôlées par l'interface de programmation seule —
    alors que la console les atteint. La garde ne disait pas « non confirmée », elle disait « la console
    ne va pas là », ce qui est faux et se lit comme une garantie.

    Une enveloppe est ici une fonction de `core.js` dont un PARAMÈTRE est passé tel quel comme premier
    argument à `apiSend` : c'est cette relation qui est cherchée dans le code, pas un nom. Rend
    {nom: (indice du paramètre chemin, méthode, ligne de l'appel interne)}."""
    code = sans_commentaires_js(core_src)
    aveugle = aveugler_litteraux_js(code)
    env = {}
    for m in SIGNATURE_JS.finditer(aveugle):
        nom, params = m.group(1), m.group(2)
        noms = [p.split("=")[0].strip() for p in params.split(",") if p.strip()]
        i = code.find("{", m.end() - 1)
        if i < 0:
            continue
        depth, j = 0, i
        while j < len(code):
            if code[j] == "{":
                depth += 1
            elif code[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        corps = code[i:j + 1]
        for a in re.finditer(r'\bapiSend\(', corps):
            args = argument_chemin(corps, a.end() - 1)
            if args and args[0] in noms:
                env[nom] = (noms.index(args[0]), methode_de("apiSend", args),
                            code[:i + a.start()].count("\n") + 1)
                break
    return env


def appelants_web(sources_js, confirmations, aveux=None, enveloppes=None, abandons=None, compteurs=None):
    """[(fichier, ligne, méthode, motif, confirmé, fonction, origine)] pour chaque appel mutant.
    `origine` dit COMMENT la confirmation a été obtenue : `propre` (écrite dans la fonction qui appelle),
    `ancetre` (une portée qui la CONTIENT), `appelant` (une portée qui la nomme) ou `` (non confirmée).

    `aveux` (facultatif) recueille les pertes de synchronisation du lecteur, PAR FICHIER : un appelant
    perdu dans une région avalée passerait autrement pour un appelant absent, donc pour un vert.
    `enveloppes` (facultatif) : les fonctions de `core.js` qui reçoivent le chemin en argument ; leurs
    sites d'appel comptent comme des appels mutants, au chemin qu'ils leur passent.
    `abandons` (facultatif) : `P11.13-h` (b) — tout appel mutant que la dérivation LAISSE DE CÔTÉ y est
    inscrit. Les deux sorties de cette boucle passaient au suivant sans rien dire ; un instrument qui
    abandonne sans l'avouer rend un verdict amputé sous la forme d'un vert."""
    out = []
    enveloppes = enveloppes or {}
    conf_re = re.compile(r"\b(?:" + "|".join(map(re.escape, confirmations)) + r")\(") if confirmations else None
    appel_re = re.compile(r'\b(apiSend|fetch|' + "|".join(map(re.escape, sorted(enveloppes))) + r')\('
                          if enveloppes else APPEL.pattern)
    # L'apiSend INTERNE d'une enveloppe n'est pas un abandon : son chemin est résolu à chaque site d'appel.
    lignes_internes = {l for _, _, l in enveloppes.values()}
    for chemin, texte in sources_js:
        journal = []
        code = sans_commentaires_js(texte, journal)
        base = os.path.basename(chemin)
        if journal and aveux is not None:
            aveux[base] = [f"ligne {texte.count(chr(10), 0, o) + 1} : {m}" for m, o in journal]
        scopes = scopes_js(code)
        for m in appel_re.finditer(code):
            nom_appel = m.group(1)
            ligne = code[:m.start()].count("\n") + 1
            # une DÉCLARATION (`function apiSend(path, …)`) n'est pas un appel : son paramètre nu passerait
            # pour un chemin indérivable, et gonflerait le compte des abandons d'un aveu faux.
            if DECLARATION.search(code[max(0, m.start() - 24):m.start()]):
                continue
            if base == "core.js" and nom_appel == "apiSend" and ligne in lignes_internes:
                continue
            args = argument_chemin(code, m.end() - 1)
            if nom_appel in enveloppes:
                idx, methode, _ = enveloppes[nom_appel]
                brut = args[idx] if len(args) > idx else None
            else:
                brut = args[0] if args else None
                methode = methode_de(nom_appel, args) if args else "?"
            if brut is None:
                if abandons is not None:
                    abandons.append((base, ligne, "argument de chemin illisible", nom_appel))
                continue
            if methode == "GET":
                continue
            if methode == "?":
                if abandons is not None:
                    abandons.append((base, ligne, "méthode indéterminée", brut[:48]))
                continue
            # `P11.13-h` (b) — LE TERNAIRE EST AVOUÉ, PAS APPRÉCIÉ. Les deux branches sont DÉRIVABLES et
            # désignent deux routes réelles ; les apprécier révélerait huit dettes de surface que le cliquet
            # des asymétries devrait loger (mesuré le 2026-08-29 : 12 -> 20). L'ordre juste est de payer
            # d'abord, resserrer ensuite, sans que le cliquet monte : l'appel est donc laissé de côté — mais
            # il est INSCRIT, COMPTÉ, et les routes qu'il atteint sont NOMMÉES pour que la dette soit
            # payable. Ne pas les recoller bout à bout n'ôte rien : le motif recollé (`/api/rules//rules`)
            # n'existe dans aucune table, et l'avoir mesuré ici ne change AUCUN état de route.
            branches = scinder_ternaire(brut)
            if len(branches) > 1:
                if abandons is not None:
                    vues = [x for x in (motif_de_chemin(b) for b in branches) if x]
                    abandons.append((base, ligne, "chemin en ternaire — non apprécié",
                                     " ou ".join(vues) if vues else brut[:48]))
                continue
            motif = motif_de_chemin(brut)
            if not motif:
                if abandons is not None:
                    abandons.append((base, ligne, "motif de chemin indérivable", brut[:48]))
                continue
            env = fonction_englobante(scopes, m.start())
            origine, nom_fn = "", (env[0] or "<anonyme>") if env else "<module>"
            if conf_re and env:
                # le scope englobant confirme, ou une portée qui le CONTIENT, ou une portée qui l'appelle
                # par son nom, à <= 3 niveaux. Le CHEMIN emprunté est retenu : `P11.13-b` mesure que le
                # dernier n'est pas sûr, et le compte de ce qu'il accorde est publié plus bas.
                vus, front = set(), [(env, "propre")]
                for _ in range(4):
                    suivant = []
                    for sc, bord in front:
                        cle = (sc[1], sc[2])
                        if cle in vus:
                            continue
                        vus.add(cle)
                        if conf_re.search(code[sc[1]:sc[2] + 1]):
                            origine = bord; break
                        parent = fonction_englobante([x for x in scopes if x[1] < sc[1] and x[2] >= sc[2]], sc[1])
                        if parent:
                            suivant.append((parent, "appelant" if bord == "appelant" else "ancetre"))
                        if sc[0]:
                            for x in scopes:
                                if (x[1], x[2]) not in vus and re.search(r"\b" + re.escape(sc[0]) + r"\b", code[x[1]:x[2] + 1]) and not (x[1] <= sc[1] and x[2] >= sc[2]):
                                    suivant.append((x, "appelant"))
                    if origine:
                        break
                    front = suivant
            if compteurs is not None and nom_appel in enveloppes:
                compteurs["sites_par_enveloppe"] = compteurs.get("sites_par_enveloppe", 0) + 1
            out.append((os.path.relpath(chemin, RACINE), ligne, methode, motif, bool(origine), nom_fn, origine))
    return out


# --- second sens de lecture : ce que les SURFACES traitent comme sensible (`P11.13-b`) ----------------
def signaux_des_surfaces(routes, handlers, readonly, appels):
    """{(verbe, path): (audite, atteinte, confirmee_partout, handler, fichier)} pour chaque route mutante du
    périmètre. Deux surfaces, chacune lue chez elle et sans rien emprunter à l'autre :
      démon   — le handler inscrit le changement au journal (`AUDIT_CHANGEMENT`) ;
      console — la route a au moins un appelant web (`atteinte`), et tous passent par une confirmation
                partagée (`confirmee_partout`). Une route qu'aucun appelant n'atteint n'est pas « confirmée » :
                le silence de la console n'est pas une déclaration."""
    signaux = {}
    for verbe, path, handler, fichier in routes:
        if not dans_le_perimetre(path, readonly):
            continue
        corps = corps_etendu(handler, handlers)
        if corps is None:
            continue
        sites = [a for a in appels if a[2] == verbe and motif_correspond(a[3], path)]
        signaux[(verbe, path)] = (bool(AUDIT_CHANGEMENT.search(corps)), bool(sites),
                                  bool(sites) and all(a[4] for a in sites), handler, fichier)
    return signaux


FAMILLE_DECLARE = "déclare (auditée par le démon, confirmée par la console)"


def elargir_par_les_surfaces(sensibles, signaux):
    """Fait ENTRER dans la liste dérivée les routes que les deux surfaces traitent déjà comme sensibles.
    Rend la liste des clés ajoutées. La famille n'exige rien de plus de ces routes — elle supprime l'écart
    entre le critère et le traitement réel, que le second sens de lecture mesure juste après."""
    ajoutees = []
    for cle, (audite, _atteinte, confirmee, handler, fichier) in sorted(signaux.items()):
        if cle in sensibles or not (audite and confirmee):
            continue
        sensibles[cle] = ([FAMILLE_DECLARE], handler, fichier)
        ajoutees.append(cle)
    return ajoutees


def relire_a_lenvers(signaux, sensibles):
    """L'AUTRE SENS : partir des surfaces et revenir au critère. Rend (angles_morts, asymetries, console_seule).
      angles_morts  — les deux surfaces la traitent comme sensible, la dérivation ne la reconnaît pas : la
                      cécité de la garde elle-même, donc une erreur.
      asymetries    — le démon audite, la console atteint la route mais ne confirme pas partout : les deux
                      surfaces se contredisent. Dette de la surface, tenue par un cliquet.
      console_seule — la console confirme, le démon n'inscrit rien : une ergonomie, pas une déclaration de
                      sensibilité. Compté et imprimé, jamais un défaut."""
    angles, asymetries, console_seule = [], [], []
    for cle, (audite, atteinte, confirmee, _h, _f) in sorted(signaux.items()):
        if cle in sensibles:
            continue
        if audite and confirmee:
            angles.append(cle)
        elif audite and atteinte:
            asymetries.append(cle)
        elif confirmee:
            console_seule.append(cle)
    return angles, asymetries, console_seule


def verdict(sensibles, appels):
    """Rend (defauts, couverts, sans_appelant)."""
    defauts, couverts, sans = [], {}, []
    for (verbe, path), (familles, handler, fichier) in sorted(sensibles.items()):
        sites = [a for a in appels if a[2] == verbe and motif_correspond(a[3], path)]
        if not sites:
            sans.append((verbe, path, familles))
            continue
        mauvais = [a for a in sites if not a[4]]
        if mauvais:
            defauts.append((verbe, path, familles, mauvais))
        else:
            couverts[(verbe, path)] = sites
    return defauts, couverts, sans


# --- validation de l'instrument ----------------------------------------------------------------------
def valider_instrument():
    errs = []
    # LE LECTEUR PARTAGÉ SE VALIDE ICI AUSSI (`P11.8-f`). Il est IMPORTÉ, donc ses témoins ne tournent pas
    # à l'import : sans cet appel, un lecteur privé de sa reconnaissance des expressions régulières ou de
    # son aveu de perte de synchronisation ne serait épinglé que par la garde qui le PORTE, et cette
    # garde-ci rendrait un compte amputé en vert.
    try:
        temoins_du_lecteur()
    except AssertionError as e:
        errs.append(f"lecteur JavaScript partagé : {e}")
    rust = [("s.rs",
             'fn r() { Router::new()\n'
             '  .route("/api/things", get(things_list).post(thing_create))\n'
             '  .route("/api/things/{id}", post(thing_update).delete(thing_delete))\n'
             '  .route("/api/users/{id}", post(user_update))\n'
             '  .route("/api/mode", get(mode_get).post(mode_set))\n'
             '  .route("/api/bulletin", delete(bulletin_clear))\n'
             '  .route("/api/query", post(query))\n'
             '  .route("/api/login", post(login_post))\n'
             '  .route("/api/rules/{id}/enabled", post(rule_set_enabled))\n'
             '  .route("/api/purge/plan", post(purge_plan_route))\n'
             '  .route("/api/purge/apply", post(purge_apply_route))\n'
             '  .route("/api/declarations", post(declaration_upsert))\n'
             '  .route("/api/notes", post(note_create))\n'
             '  .route("/api/silences", post(silence_create))\n'
             '  .route("/api/widgets/{id}", delete(widget_delete)) }\n'
             'pub(crate) fn is_readonly_post(path: &str) -> bool {\n    matches!(path, "/api/query" | "/api/search")\n}\n'
             'pub(crate) async fn thing_create(Json(b): Json<Value>) -> Response { conn.execute("INSERT INTO thing(name) VALUES(?1)", params![n]); audit_config_change(&conn, "config.thing.create", "d", 2, "m", "f"); ok() }\n'
             'pub(crate) async fn thing_update() -> Response { ok() }\n'
             'pub(crate) async fn thing_delete() -> Response { conn.execute("DELETE FROM thing WHERE id=?1", params![id]); audit_config_change(&conn, "config.thing.delete", "d", 2, "m", "f"); ok() }\n'
             'pub(crate) async fn user_update(Json(b): Json<Value>) -> Response { let new_role = b.get("role").and_then(|v| v.as_str()); conn.execute("UPDATE user SET role=?1 WHERE id=?2", params![role, id]); ok() }\n'
             'pub(crate) async fn mode_set() -> Response { ok() }\n'
             'pub(crate) async fn mode_get() -> Response { ok() }\n'
             'pub(crate) async fn bulletin_clear() -> Response { audit_config_change(&conn, "bulletin.clear", "d", 1, "m", "f"); ok() }\n'
             'pub(crate) async fn query() -> Response { ok() }\n'
             'pub(crate) async fn login_post() -> Response { ok() }\n'
             'pub(crate) async fn rule_set_enabled() -> Response { ok() }\n'
             'pub(crate) async fn purge_plan_route() -> Response { purge_plan(&conn) }\n'
             'pub(crate) async fn purge_apply_route() -> Response { purge_confirm_and_apply(&conn, scope, &token) }\n'
             # `P11.13-b` — la route de DÉCLARATION : le démon inscrit le changement à son journal, rien d'autre.
             'pub(crate) async fn declaration_upsert(Json(b): Json<Value>) -> Response { conn.execute("INSERT INTO declaration(name) VALUES(?1)", params![n]); audit_config_change(&conn, "config.declaration", "d", 2, "m", "f"); ok() }\n'
             'pub(crate) async fn silence_create(Json(b): Json<Value>) -> Response { conn.execute("INSERT INTO silence(m) VALUES(?1)", params![m]); audit_source_change(&conn, "s", "config.silence", "d", 3, "m", "f"); ok() }\n'
             'pub(crate) async fn note_create(Json(b): Json<Value>) -> Response { conn.execute("INSERT INTO note(t) VALUES(?1)", params![t]); ok() }\n'
             # `P11.13-h` (a) — la route que la console n'atteint QUE par une enveloppe partagée.
             'pub(crate) async fn widget_delete() -> Response { conn.execute("DELETE FROM widget WHERE id=?1", params![id]); ok() }\n'
             '// .route("/api/commentee", delete(commentee))\n'
             'fn route_min_role(path: &str, mutating: bool) -> MinRole {\n'
             '  if path == "/api/mode" { return if mutating { MinRole::Admin } else { MinRole::Read }; }\n'
             '  if mutating && path.ends_with("/enabled") && path.starts_with("/api/rules/") { return MinRole::Admin; }\n'
             '  MinRole::Read }\n')]
    routes, handlers, readonly, armement, derr = deriver_routes(rust)
    sensibles, cerr = classer(routes, handlers, readonly, armement)
    attendu = {("DELETE", "/api/things/{id}"), ("POST", "/api/users/{id}"), ("POST", "/api/mode"),
               ("POST", "/api/rules/{id}/enabled"), ("POST", "/api/purge/apply"), ("DELETE", "/api/widgets/{id}")}
    if derr or cerr:
        errs.append(f"témoin de DÉRIVATION : erreurs inattendues {derr + cerr}")
    if set(sensibles) != attendu:
        errs.append(f"témoin de CLASSEMENT en échec : attendu {sorted(attendu)}, obtenu {sorted(sensibles)} — "
                    "une création ordinaire, un POST de lecture, une route de connexion, un DELETE audité "
                    "informatif ou une simulation de purge ne doivent pas être sensibles ; un DELETE, un rôle "
                    "lu, le mode, une activation et une purge appliquée doivent l'être.")
    # TÉMOINS DE LA SYNTAXE DE GABARIT (`P7.19-d`) — la seule chose qui empêche l'appariement de rester
    # sur une syntaxe que le routeur ne produit plus. Positif ET négatif : sans le négatif, reconnaître
    # les deux formes passerait pour correct, et personne ne saurait laquelle la table écrit.
    if not motif_correspond("/api/users/7", "/api/users/{id}"):
        errs.append("témoin de GABARIT (positif) en échec : un segment concret côté web ne s'apparie plus à un "
                    "paramètre `{…}` de la table. L'appariement est resté sur une syntaxe que le routeur ne "
                    "produit plus : la couverture se réduit EN SILENCE, verdict vert compris.")
    if motif_correspond("/api/users/7", "/api/users/:id"):
        errs.append("témoin de GABARIT (négatif) en échec : `:id` s'apparie encore alors que le routeur (axum 0.8) "
                    "ne l'accepte plus — il paniquerait à la construction. Deux syntaxes reconnues, aucune preuve "
                    "de celle que la table porte vraiment.")
    core = ("export { a, confirmModal, b, confirmWithConsequence, modal };\n"
            # `P11.13-h` (a) — DEUX ENVELOPPES à dériver, une POST et une DELETE, plus deux LEURRES : une
            # fonction qui appelle `apiSend` sur un chemin LITTÉRAL (ce n'est pas une enveloppe : son chemin
            # se lit chez elle) et une qui ne l'appelle pas du tout.
            "async function contentSubmit(path, body, resSel) { const j = await apiSend(path, 'POST', body); return !!j; }\n"
            "async function contentDelete(path, label) { const j = await apiSend(path, 'DELETE'); return !!j; }\n"
            "async function pingLeurre() { return apiSend('/ping', 'POST'); }\n"
            "function formMsg(sel, msg) { return sel + msg; }\n")
    confs = confirmations_de_core(core)
    if confs != ["confirmModal", "confirmWithConsequence"]:
        errs.append(f"témoin des CONFIRMATIONS : {confs} au lieu des deux exports `confirm*`")
    env = enveloppes_de_core(core)
    if {n: (i, m) for n, (i, m, _) in env.items()} != {"contentSubmit": (0, "POST"), "contentDelete": (0, "DELETE")}:
        errs.append(f"témoin des ENVELOPPES en échec : {sorted(env)} — une enveloppe est une fonction dont un "
                    "PARAMÈTRE part comme chemin d'`apiSend` ; une fonction au chemin littéral et une fonction "
                    "qui n'envoie rien n'en sont pas, et le rang du paramètre comme la méthode doivent être lus.")
    # TÉMOINS DU TERNAIRE (`P11.13-h` (b)) — positif ET négatif. Sans le négatif, un découpage qui scinde
    # AUSSI `?.` ou `??` passerait pour correct et amputerait des chemins ordinaires.
    # Les trois expressions portent un `?` qui n'ouvre PAS le ternaire (`?.`, `??`) AVANT celui qui l'ouvre :
    # c'est le seul cas où l'enjambement est chargé. Un témoin qui n'assurerait que « ça se scinde en deux »
    # passerait dans les deux sens — mesuré : il passait, et cachait un `??` mal enjambé. On exige donc les
    # BRANCHES, pas leur nombre.
    for expr, branches_attendues in [("e ? '/rules/' + e : '/rules'", ["'/rules/' + e", "'/rules'"]),
                                     ("o?.id ? '/rules/' + o.id : '/rules'", ["'/rules/' + o.id", "'/rules'"]),
                                     ("a ?? b ? '/rules/' + a : '/rules'", ["'/rules/' + a", "'/rules'"])]:
        obtenues = scinder_ternaire(expr)
        if obtenues != branches_attendues:
            errs.append(f"témoin de TERNAIRE (découpage) en échec sur `{expr}` : {obtenues} au lieu de "
                        f"{branches_attendues}. Le témoin porte sur le TEXTE des branches, pas sur les motifs "
                        "qu'on en tire : mesuré le 2026-08-29, un `??` enjambé de travers décale la première "
                        "branche d'un caractère et le joker de `motif_de_chemin` ravale le décalage — deux "
                        "découpages différents rendaient le MÊME motif, et le témoin ne mesurait rien.")
        if [motif_de_chemin(b) for b in obtenues] != ["/api/rules/*", "/api/rules"]:
            errs.append(f"témoin de TERNAIRE (motifs) en échec sur `{expr}` : les deux branches ne rendent plus "
                        "deux routes réelles. Recollées, elles rendent `/api/rules//rules`, qui n'existe dans "
                        "aucune table, et l'appel disparaît du compte sans un mot.")
    for nonternaire in ["o?.id + '/b'", "a ?? '/b'", "'/a/' + (x ? 1 : 2) + '/b'"]:
        if len(scinder_ternaire(nonternaire)) != 1:
            errs.append(f"témoin de TERNAIRE (négatif) en échec : `{nonternaire}` a été scindé — un `?.`, un `??` "
                        "ou un ternaire IMBRIQUÉ dans une parenthèse ne sont pas un chemin à deux branches.")
    js = [("v.js",
           "async function delThing(t) { if (!await confirmWithConsequence('x', 'y')) return; await apiSend('/things/' + t.id, 'DELETE'); }\n"
           "async function saveRole(u) { await apiSend('/users/' + u.id, 'POST', { role: r }); }\n"
           "async function armMode() { await apiSend('/mode', 'POST', { active: true }); }\n"
           "async function armModeBtn() { if (!await confirmModal('?')) return; armMode(); }\n"
           "async function toggleRule(r) { await apiSend(`/rules/${r.id}/enabled`, 'POST', { enabled: true }); }\n"
           "const creer = async () => { await apiSend('/things', 'POST', { name }); };\n"
           "btn.onclick = async () => { if (!await confirmModal('x')) return; await apiSend('/things/' + id, 'DELETE'); };\n"
           "other.onclick = async () => { await apiSend(`/rules/${id}/enabled`, 'POST', {}); };\n"
           "// async function fantome() { await apiSend('/purge/apply', 'POST', {}); }\n"
           "async function saveDeclaration() { if (!await confirmWithConsequence('x', 'y')) return; await apiSend('/declarations', 'POST', { name }); }\n"
           "async function saveNote() { if (!await confirmModal('?')) return; await apiSend('/notes', 'POST', { t }); }\n"
           "async function saveSilence() { await apiSend('/silences', 'POST', { m }); }\n"
           # `P11.13-h` (a) — une route que la console n'atteint QUE par une enveloppe partagée.
           "async function delWidget(w) { if (!await confirmModal('?')) return; if (await contentDelete('/widgets/' + w.id, 'widget')) recharger(); }\n"
           # `P11.13-h` (b) — les deux formes d'abandon, qui doivent être AVOUÉES et non silencieuses.
           "async function saveVar() { const u = '/things'; await apiSend(u, 'POST', {}); }\n"
           "async function saveGizmo(g) { await contentSubmit(g.id ? '/gizmos/' + g.id : '/gizmos', {}, '#r'); }\n"
           # une DÉCLARATION du même nom qu'une enveloppe n'est pas un site d'appel.
           "function contentSubmit(cheminDeclare, body, res) { return 1; }\n"
           # `P11.13-b` — les trois origines de « confirmée » doivent se distinguer.
           "async function delAncetre(x) { if (!await confirmModal('?')) return; [1].forEach(() => { apiSend('/gadgets/' + x, 'DELETE'); }); }\n")]
    abandons_temoins = []
    appels = appelants_web(js, confs, None, env, abandons_temoins)
    # ORIGINES : `propre` (dans la fonction qui envoie), `ancetre` (une portée qui la contient), `appelant`
    # (une portée qui la NOMME — la forme faible, celle qui peut appartenir à un geste voisin).
    origines = {(a[3], a[6]) for a in appels}
    for motif, attendue in [("/api/things/*", "propre"), ("/api/gadgets/*", "ancetre"), ("/api/mode", "appelant")]:
        if (motif, attendue) not in origines:
            errs.append(f"témoin d'ORIGINE en échec : l'appel vers `{motif}` devait tenir sa confirmation par "
                        f"`{attendue}` — obtenu {sorted(o for o in origines if o[0] == motif)}. Sans cette "
                        "distinction, le compte publié des « confirmée par appelant » ne mesure plus la forme "
                        "faible : une portée qui NOMME l'appelant peut porter la confirmation d'un geste VOISIN.")
    vus_abandons = {(a[2], a[3]) for a in abandons_temoins}
    if ("motif de chemin indérivable", "u") not in vus_abandons:
        errs.append(f"témoin d'ABANDON (chemin en variable) en échec : {sorted(vus_abandons)} — un appel dont le "
                    "chemin est porté par une variable doit être AVOUÉ, pas passé au suivant en silence.")
    if ("chemin en ternaire — non apprécié", "/api/gizmos/* ou /api/gizmos") not in vus_abandons:
        errs.append(f"témoin d'ABANDON (ternaire) en échec : {sorted(vus_abandons)} — un chemin ternaire doit être "
                    "avoué et ses DEUX routes nommées, pour que la dette soit payable.")
    if any(a[3] == "cheminDeclare" for a in abandons_temoins):
        errs.append("témoin de DÉCLARATION en échec : `function contentSubmit(cheminDeclare, …)` a été compté comme "
                    "un site d'appel — le compte des abandons serait gonflé d'un aveu faux.")
    if any(a[3].startswith("/api/gizmos") for a in appels):
        errs.append("témoin de NON-APPRÉCIATION en échec : une branche de ternaire a produit un site apparié. Le "
                    "resserrement ne se livre qu'APRÈS le paiement des dettes qu'il révèle (`P11.13-h` (c)).")
    # MUTATION QUI PROUVE LE SENS DES ENVELOPPES : sans elles, la route de widget n'est atteinte par personne
    # et la garde la déclare « sans appelant web » — c'est-à-dire contrôlée par l'interface de programmation
    # seule, alors que la console la supprime. C'est la forme la plus dangereuse de l'erreur : elle se lit
    # comme une garantie. Avec elles, la même route est CONFIRMÉE. Les deux sens sont exigés ici.
    TEMOIN_ENVELOPPE = ("DELETE", "/api/widgets/{id}")
    sans_env = verdict(sensibles, appelants_web(js, confs))
    if TEMOIN_ENVELOPPE not in {(s[0], s[1]) for s in sans_env[2]}:
        errs.append("témoin d'ENVELOPPE (négatif) en échec : sans le suivi des enveloppes, une route atteinte par "
                    "la SEULE enveloppe devrait rester « sans appelant web » — le témoin ne mesure donc rien.")
    defauts, couverts, sans = verdict(sensibles, appels)
    if ("DELETE", "/api/things/{id}") not in couverts:
        errs.append("témoin POSITIF en échec : un DELETE confirmé dans sa fonction n'est pas reconnu couvert")
    if ("POST", "/api/mode") not in couverts:
        errs.append("témoin d'APPELANT en échec : une confirmation portée par la fonction appelante n'est pas reconnue")
    if TEMOIN_ENVELOPPE not in couverts:
        errs.append("témoin d'ENVELOPPE (positif) en échec : une route DÉTRUITE par la console au travers d'une "
                    "enveloppe partagée n'est pas vue atteinte — la garde dirait « sans appelant web », c'est-à-dire "
                    "« la console ne va pas là », ce qui est faux et se lit comme une garantie.")
    mauvais = {(d[0], d[1]) for d in defauts}
    if ("POST", "/api/users/{id}") not in mauvais or ("POST", "/api/rules/{id}/enabled") not in mauvais:
        errs.append(f"témoin NÉGATIF en échec : un changement de rôle ou une activation SANS confirmation doit rougir (défauts : {sorted(mauvais)})")
    if ("POST", "/api/purge/apply") not in {(s[0], s[1]) for s in sans}:
        errs.append("témoin de SILENCE en échec : un appel en commentaire a été compté comme appelant")

    # SECOND SENS DE LECTURE (`P11.13-b`) — quatre témoins sur le même corpus.
    signaux = signaux_des_surfaces(routes, handlers, readonly, appels)
    avant, _asy_avant, _cs_avant = relire_a_lenvers(signaux, sensibles)
    if ("POST", "/api/declarations") not in avant:
        errs.append(f"témoin d'ANGLE MORT en échec : une route que le démon audite et que la console confirme partout, "
                    f"hors des trois familles, doit être vue comme non reconnue par la dérivation (angles : {avant})")
    reprises = elargir_par_les_surfaces(sensibles, signaux)
    apres, asymetries, console_seule = relire_a_lenvers(signaux, sensibles)
    if ("POST", "/api/declarations") not in reprises or apres:
        errs.append(f"témoin de FERMETURE en échec : la famille des surfaces doit reprendre la route de déclaration et "
                    f"ne laisser aucun angle mort (reprises : {reprises}, restants : {apres})")
    # Les deux appels du journal sont couverts : `/api/things` par `audit_config_change`, `/api/silences` par
    # `audit_source_change` — l'un et l'autre appelés par la console sans confirmation.
    if asymetries != [("POST", "/api/silences"), ("POST", "/api/things")]:
        errs.append(f"témoin d'ASYMÉTRIE en échec : les routes auditées appelées SANS confirmation doivent être "
                    f"relevées, et elles seules — obtenu {asymetries} (une route auditée SANS appelant web n'en est pas)")
    if ("POST", "/api/notes") not in console_seule or ("POST", "/api/notes") in sensibles:
        errs.append(f"témoin INVERSE en échec : une route que la console confirme et que le démon n'audite PAS ne doit "
                    f"être ni sensible ni un angle mort, seulement comptée ({console_seule})")
    if ("DELETE", "/api/bulletin") in {c for c in avant} | {c for c in asymetries}:
        errs.append("témoin de SILENCE du second sens en échec : une route auditée SANS appelant web est comptée comme "
                    "angle mort ou asymétrie — le silence de la console n'est pas une déclaration")
    return errs


def main():
    errs = valider_instrument()
    if errs:
        for e in errs:
            print(f"::error::{e}")
        print("\nl'INSTRUMENT est faux : aucun verdict n'est rendu.")
        return 2

    sources_rs = []
    for chemin in fichiers_rust():
        with open(chemin, encoding="utf-8", errors="replace") as fh:
            sources_rs.append((chemin, fh.read()))
    routes, handlers, readonly, armement, derr = deriver_routes(sources_rs)
    sensibles, cerr = classer(routes, handlers, readonly, armement)
    for e in derr + cerr:
        print(f"::error::{e}")
    if derr or cerr:
        print("\nla DÉRIVATION est incomplète : aucun verdict n'est rendu.")
        return 2
    if not readonly or not armement["mode"] or not armement["enabled"]:
        print(f"::error::déclarations du démon non retrouvées (POST de lecture : {len(readonly)}, armement : {armement}) "
              "— la garde ne peut pas délimiter le périmètre, elle refuse de conclure.")
        return 2
    if len(sensibles) < MIN_ROUTES_SENSIBLES:
        print(f"::error::seulement {len(sensibles)} route(s) sensible(s) dérivée(s), plancher {MIN_ROUTES_SENSIBLES} : "
              "la dérivation est cassée, la garde refuse de conclure.")
        return 2
    if ROUTE_TEMOIN not in sensibles:
        print(f"::error::la route témoin {ROUTE_TEMOIN} (changement de rôle) n'est plus dérivée sensible : soit le "
              "démon a changé, soit la dérivation ne voit plus son site.")
        return 2

    with open(os.path.join(WEB, "core.js"), encoding="utf-8") as fh:
        core_src = fh.read()
    confs = confirmations_de_core(core_src)
    enveloppes = enveloppes_de_core(core_src)
    if not enveloppes:
        print("::error::aucune enveloppe partagée dérivée de web/core.js (une fonction qui reçoit le chemin en "
              "argument et le passe à `apiSend`) : soit core.js a changé de forme, soit la dérivation ne la voit "
              "plus — et la garde reclasserait en silence des routes atteintes par la console en « sans appelant "
              "web ». Elle refuse de conclure.")
        return 2
    if not confs:
        print("::error::aucune fonction `confirm*` exportée par web/core.js : il n'existe pas de confirmation partagée.")
        return 2
    sources_js = []
    for nom in sorted(os.listdir(WEB)):
        if nom.endswith(".js") and nom != "sw.js":
            with open(os.path.join(WEB, nom), encoding="utf-8", errors="replace") as fh:
                sources_js.append((os.path.join(WEB, nom), fh.read()))
    aveux, abandons, compteurs = {}, [], {}
    appels = appelants_web(sources_js, confs, aveux, enveloppes, abandons, compteurs)
    if aveux and refuser_sur_aveu("routes sensibles", aveux):
        return 2

    # LE CÂBLAGE ENTRE LE MÉCANISME ET LE VERDICT EST TENU, PAS SEULEMENT LE MÉCANISME. Mesuré par mutation
    # le 2026-08-29 : débrancher les enveloppes ICI laissait les témoins passer (ils les reçoivent en propre)
    # et la garde rendre un VERT, quatre routes destructrices redevenant « sans appelant web ». Un mécanisme
    # validé qu'on n'a pas branché ne garde rien : c'est le compte des sites RÉELLEMENT obtenus par une
    # enveloppe qui l'atteste, et il ne descend pas.
    if compteurs.get("sites_par_enveloppe", 0) < PLANCHER_SITES_PAR_ENVELOPPE:
        print(f"::error::{compteurs.get('sites_par_enveloppe', 0)} site(s) d'appel obtenu(s) par une enveloppe "
              f"partagée, plancher {PLANCHER_SITES_PAR_ENVELOPPE} : soit la console a cessé de passer par elles, "
              "soit le suivi des enveloppes n'est plus branché sur le verdict — et des routes que la console "
              "atteint seraient déclarées « sans appelant web », ce qui se lit comme une garantie.")
        return 2

    # `P11.13-h` (b) — CE QUE LA GARDE A LAISSÉ TOMBER EST DIT AVANT TOUT VERDICT, ET IL EST TENU PAR UN
    # PLANCHER. Un appel dont le chemin n'est pas dérivable n'est pas apparié : la route qu'il atteint peut
    # rester « sans appelant web », et ce silence-là se lit comme une garantie. Le plancher ne monte JAMAIS.
    print(f"enveloppes partagées dérivées de core.js : {', '.join(f'{n}(#{i}, {m})' for n, (i, m, _) in sorted(enveloppes.items()))}")
    print(f"appels mutants laissés de côté par la dérivation : {len(abandons)} (plancher {PLAFOND_ABANDONS})")
    for f, ligne, motif, extrait in abandons:
        print(f"  abandon   {f}:{ligne} — {motif} : `{extrait}`")
    if len(abandons) > PLAFOND_ABANDONS:
        print(f"::error::{len(abandons)} appel(s) mutant(s) abandonné(s) par la dérivation, plancher {PLAFOND_ABANDONS} : "
              "un appel de plus que la garde ne sait pas lire. Elle rendrait un verdict amputé sous la forme d'un vert — "
              "écris le chemin de façon dérivable, ou apprends-le à la dérivation ; ce plancher ne se relève pas.")
        return 1
    if len(abandons) < PLAFOND_ABANDONS:
        print(f"note : le plancher des abandons peut descendre à {len(abandons)} (`PLAFOND_ABANDONS`).")

    # SECOND SENS (`P11.13-b`) : partir des surfaces et revenir au critère, AVANT de rendre le verdict habituel.
    signaux = signaux_des_surfaces(routes, handlers, readonly, appels)
    reprises = elargir_par_les_surfaces(sensibles, signaux)
    angles, asymetries, console_seule = relire_a_lenvers(signaux, sensibles)
    for verbe, path in angles:
        print(f"::error::{verbe} {path} — le démon inscrit ce changement à son journal et TOUS ses appelants web "
              "confirment, mais aucune famille de la dérivation ne la reconnaît : la garde est aveugle à une route "
              "que les deux surfaces traitent déjà comme sensible.")
    if angles:
        print(f"\n{len(angles)} angle(s) mort(s) de la dérivation.")
        return 1

    defauts, couverts, sans = verdict(sensibles, appels)
    if ROUTE_TEMOIN not in couverts:
        print(f"::error::la route témoin {ROUTE_TEMOIN} n'a pas d'appelant web confirmé : soit la surface a régressé, "
              "soit l'analyse des appelants ne reconnaît plus la forme du code.")
        return 1

    print(f"routes sensibles dérivées du démon : {len(sensibles)} (sur {len(routes)} routes mutantes), dont "
          f"{len(reprises)} reprises par les surfaces")
    for (verbe, path), (familles, handler, fichier) in sorted(sensibles.items()):
        etat = "confirmée" if (verbe, path) in couverts else ("SANS CONFIRMATION" if (verbe, path) in {(d[0], d[1]) for d in defauts} else "sans appelant web")
        print(f"  {verbe:6} {path:44} {etat:18} {'; '.join(familles)}")
    for verbe, path, familles, sites in defauts:
        for f, ligne, _m, motif, _c, fn, _o in sites:
            print(f"::error::{f}:{ligne} — `{fn}` appelle {verbe} {path} ({'; '.join(familles)}) sans passer par une "
                  f"confirmation partagée ({', '.join(confs)}) : l'utilisateur ne voit pas la conséquence avant d'agir.")
    if defauts:
        print(f"\n{len(defauts)} route(s) sensible(s) appelée(s) sans confirmation.")
        return 1
    print(f"\nsecond sens de lecture : 0 angle mort ; {len(asymetries)} asymétrie(s) (le démon audite, la console "
          f"atteint la route sans confirmer partout), plafond {PLAFOND_ASYMETRIE} ; {len(console_seule)} route(s) que "
          "la console confirme sans que le démon inscrive de changement — une ergonomie, pas une déclaration.")
    for verbe, path in asymetries:
        print(f"  asymétrie  {verbe:6} {path}")
    if len(asymetries) > PLAFOND_ASYMETRIE:
        print(f"::error::{len(asymetries)} route(s) auditée(s) par le démon sont appelées par la console sans que tous "
              f"leurs appelants confirment, plafond {PLAFOND_ASYMETRIE} : une de plus que le cliquet. Faites passer "
              "l'appelant par une confirmation partagée — ce cliquet ne se relève pas sans raison écrite dans la garde.")
        return 1
    # `P11.13-b` — CE QUE « CONFIRMÉE » VAUT AU JUSTE CESSE D'ÊTRE UNE PHRASE ET DEVIENT UN COMPTE TENU.
    # La limite était ÉCRITE dans l'en-tête avec un chiffre relevé un jour donné, que plus rien ne suivait.
    # Elle est maintenant DÉRIVÉE à chaque exécution et bornée par un plancher qui ne monte pas : un appel de
    # plus déclaré confirmé par une portée qui le NOMME (et non par la sienne ni par une portée qui le
    # CONTIENT) fait rougir. C'est un compte, pas un resserrement : aucune de ces routes n'est accusée ici,
    # et la garde ne rend ni plus ni moins de « confirmée » qu'avant ce compte. Le resserrement, lui, ne
    # peut être livré qu'APRÈS le paiement des dettes qu'il révèle (`P11.13-h` (c)).
    par_appelant = sorted({(a[0], a[1], a[5]) for a in appels if a[6] == "appelant"})
    print(f"\nconfirmations accordées par une portée qui NOMME l'appelant (ni la sienne, ni une portée qui la "
          f"contient) : {len(par_appelant)} appel(s), plancher {PLAFOND_CONFIRME_PAR_APPELANT} — la portée qui "
          "confirme peut appartenir à un geste VOISIN, et cette forme de « confirmée » n'est pas une preuve.")
    for f, ligne, fn in par_appelant:
        print(f"  par-appelant  {f}:{ligne} dans `{fn}`")
    if len(par_appelant) > PLAFOND_CONFIRME_PAR_APPELANT:
        print(f"::error::{len(par_appelant)} appel(s) mutant(s) tiennent leur « confirmée » d'une portée qui les "
              f"NOMME, plancher {PLAFOND_CONFIRME_PAR_APPELANT} : un de plus. Écris la confirmation dans la fonction "
              "qui envoie, ou dans une portée qui la contient — ce plancher ne se relève pas.")
        return 1
    if len(par_appelant) < PLAFOND_CONFIRME_PAR_APPELANT:
        print(f"note : le plancher des « confirmée par appelant » peut descendre à {len(par_appelant)} "
              "(`PLAFOND_CONFIRME_PAR_APPELANT`).")
    if len(asymetries) < PLAFOND_ASYMETRIE:
        print(f"note : le cliquet peut descendre à {len(asymetries)} (`PLAFOND_ASYMETRIE`).")
    print(f"\nOK — {len(couverts)} route(s) sensible(s) confirmée(s) par la surface, {len(sans)} sans appelant web "
          f"(contrôle par API) ; confirmations partagées : {', '.join(confs)}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
