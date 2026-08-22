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
Le périmètre est l'ensemble des routes MUTANTES du routeur (`daemon/src/server.rs`, méthodes post/put/
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

L'INSTRUMENT SE VALIDE AVANT DE RENDRE UN VERDICT
--------------------------------------------------
Témoins sur un corpus de contrôle : une route DELETE avec un appelant confirmé (doit passer), la même
sans confirmation (doit rougir), une route de création ordinaire (ne doit pas être sensible), un
appelant confirmé par sa fonction APPELANTE (doit passer), un appel en commentaire (ne compte pas).
Puis des planchers sur l'arbre réel : un nombre minimal de routes sensibles, une route témoin trouvée
sensible ET confirmée (`/api/users/:id`, le changement de rôle), sans quoi la garde refuse de conclure.
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
ROUTE_TEMOIN = ("POST", "/api/users/:id")

CHAINES_RUST = '"'
CHAINES_JS = "\"'`"


def sans_commentaires(src, delimiteurs=CHAINES_JS):
    """Retire `//` et `/* */` en respectant les chaînes (même dépouillement que les gardes voisines)."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if c in delimiteurs:
            j = i + 1
            while j < n and src[j] != c:
                j += 2 if src[j] == "\\" else 1
            out.append(src[i:j + 1])
            i = j + 1
        elif src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


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
        code = sans_commentaires(texte, CHAINES_RUST)
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


def classer(routes, handlers, readonly, armement):
    """Rend {(verbe, path): (familles, handler, fichier)} pour les routes sensibles, + erreurs."""
    sensibles, erreurs = {}, []
    for verbe, path, handler, fichier in routes:
        if path in readonly or SANS_SESSION.match(path):
            continue
        propre = handlers.get(handler)
        if propre is None:
            erreurs.append(f"{fichier} : handler `{handler}` de {verbe} {path} introuvable — la garde ne peut pas lire ce qu'il fait")
            continue
        # Corps ÉTENDU : le handler plus les fonctions qu'il appelle directement (un niveau) — une insertion
        # de jeton ou d'utilisateur vit souvent dans un helper (`token_insert`, `scim_upsert`).
        appelees = set(re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(', propre)) - {handler}
        corps = propre + "".join(handlers.get(n, "") for n in appelees if n in handlers)
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
    m = EXPORT_CORE.search(sans_commentaires(core_src))
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
    """`motif` = chemin côté web (`*` = segment inconnu) ; `route` = gabarit axum (`:id`)."""
    mp, rp = motif.strip("/").split("/"), route.strip("/").split("/")
    if len(mp) != len(rp):
        return False
    for a, b in zip(mp, rp):
        if b.startswith(":") or a == "*":
            continue
        if "*" in a:
            if not re.fullmatch(re.escape(a).replace(r"\*", ".*"), b):
                return False
        elif a != b:
            return False
    return True


SCOPE = re.compile(r'(?:async\s+)?function\s*(?:[A-Za-z_$][\w$]*)?\s*\([^()]*\)\s*\{|(?:async\s*)?(?:\([^()]*\)|[A-Za-z_$][\w$]*)\s*=>\s*\{')
NOM_AVANT = re.compile(r'(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?$|function\s+([A-Za-z_$][\w$]*)\s*$')


def aveugler_chaines(src):
    """Même longueur que `src`, le contenu des chaînes remplacé par des espaces : les accolades d'un
    littéral ne comptent pas dans l'appariement des blocs."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if c in CHAINES_JS:
            j = i + 1
            while j < n and src[j] != c:
                j += 2 if src[j] == "\\" else 1
            out.append(c + " " * (j - i - 1) + c); i = j + 1
        else:
            out.append(c); i += 1
    return "".join(out)[:n]


def scopes_js(code):
    """[(nom|None, début, fin)] pour chaque fonction (déclarée, expression, flèche) — nom = celui de la
    déclaration ou de la variable qui la reçoit ; une flèche posée sur un `onclick` reste anonyme."""
    aveugle = aveugler_chaines(code)
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


def appelants_web(sources_js, confirmations):
    """[(fichier, ligne, méthode, motif, confirmé, fonction)] pour chaque apiSend/fetch mutant."""
    out = []
    conf_re = re.compile(r"\b(?:" + "|".join(map(re.escape, confirmations)) + r")\(") if confirmations else None
    for chemin, texte in sources_js:
        code = sans_commentaires(texte)
        scopes = scopes_js(code)
        nommes = {}
        for nom, i, j in scopes:
            if nom:
                nommes.setdefault(nom, (i, j))
        for m in APPEL.finditer(code):
            args = argument_chemin(code, m.end() - 1)
            if not args:
                continue
            methode = methode_de(m.group(1), args)
            if methode in ("GET", "?"):
                continue
            motif = motif_de_chemin(args[0])
            if not motif:
                continue
            ligne = code[:m.start()].count("\n") + 1
            env = fonction_englobante(scopes, m.start())
            confirme, nom_fn = False, (env[0] or "<anonyme>") if env else "<module>"
            if conf_re and env:
                # le scope englobant confirme, ou un scope qui l'appelle (par son nom) à <= 3 niveaux
                vus, front = set(), [env]
                for _ in range(4):
                    suivant = []
                    for sc in front:
                        cle = (sc[1], sc[2])
                        if cle in vus:
                            continue
                        vus.add(cle)
                        if conf_re.search(code[sc[1]:sc[2] + 1]):
                            confirme = True; break
                        # un scope englobant (la flèche est dans une fonction nommée qui confirme avant)
                        parent = fonction_englobante([x for x in scopes if x[1] < sc[1] and x[2] >= sc[2]], sc[1])
                        if parent:
                            suivant.append(parent)
                        # les scopes qui appellent ce scope par son nom
                        if sc[0]:
                            for x in scopes:
                                if (x[1], x[2]) not in vus and re.search(r"\b" + re.escape(sc[0]) + r"\b", code[x[1]:x[2] + 1]) and not (x[1] <= sc[1] and x[2] >= sc[2]):
                                    suivant.append(x)
                    if confirme:
                        break
                    front = suivant
            out.append((os.path.relpath(chemin, RACINE), ligne, methode, motif, confirme, nom_fn))
    return out


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
    rust = [("s.rs",
             'fn r() { Router::new()\n'
             '  .route("/api/things", get(things_list).post(thing_create))\n'
             '  .route("/api/things/:id", post(thing_update).delete(thing_delete))\n'
             '  .route("/api/users/:id", post(user_update))\n'
             '  .route("/api/mode", get(mode_get).post(mode_set))\n'
             '  .route("/api/bulletin", delete(bulletin_clear))\n'
             '  .route("/api/query", post(query))\n'
             '  .route("/api/login", post(login_post))\n'
             '  .route("/api/rules/:id/enabled", post(rule_set_enabled))\n'
             '  .route("/api/purge/plan", post(purge_plan_route))\n'
             '  .route("/api/purge/apply", post(purge_apply_route)) }\n'
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
             '// .route("/api/commentee", delete(commentee))\n'
             'fn route_min_role(path: &str, mutating: bool) -> MinRole {\n'
             '  if path == "/api/mode" { return if mutating { MinRole::Admin } else { MinRole::Read }; }\n'
             '  if mutating && path.ends_with("/enabled") && path.starts_with("/api/rules/") { return MinRole::Admin; }\n'
             '  MinRole::Read }\n')]
    routes, handlers, readonly, armement, derr = deriver_routes(rust)
    sensibles, cerr = classer(routes, handlers, readonly, armement)
    attendu = {("DELETE", "/api/things/:id"), ("POST", "/api/users/:id"), ("POST", "/api/mode"),
               ("POST", "/api/rules/:id/enabled"), ("POST", "/api/purge/apply")}
    if derr or cerr:
        errs.append(f"témoin de DÉRIVATION : erreurs inattendues {derr + cerr}")
    if set(sensibles) != attendu:
        errs.append(f"témoin de CLASSEMENT en échec : attendu {sorted(attendu)}, obtenu {sorted(sensibles)} — "
                    "une création ordinaire, un POST de lecture, une route de connexion, un DELETE audité "
                    "informatif ou une simulation de purge ne doivent pas être sensibles ; un DELETE, un rôle "
                    "lu, le mode, une activation et une purge appliquée doivent l'être.")
    core = ("export { a, confirmModal, b, confirmWithConsequence, modal };\n")
    confs = confirmations_de_core(core)
    if confs != ["confirmModal", "confirmWithConsequence"]:
        errs.append(f"témoin des CONFIRMATIONS : {confs} au lieu des deux exports `confirm*`")
    js = [("v.js",
           "async function delThing(t) { if (!await confirmWithConsequence('x', 'y')) return; await apiSend('/things/' + t.id, 'DELETE'); }\n"
           "async function saveRole(u) { await apiSend('/users/' + u.id, 'POST', { role: r }); }\n"
           "async function armMode() { await apiSend('/mode', 'POST', { active: true }); }\n"
           "async function armModeBtn() { if (!await confirmModal('?')) return; armMode(); }\n"
           "async function toggleRule(r) { await apiSend(`/rules/${r.id}/enabled`, 'POST', { enabled: true }); }\n"
           "const creer = async () => { await apiSend('/things', 'POST', { name }); };\n"
           "btn.onclick = async () => { if (!await confirmModal('x')) return; await apiSend('/things/' + id, 'DELETE'); };\n"
           "other.onclick = async () => { await apiSend(`/rules/${id}/enabled`, 'POST', {}); };\n"
           "// async function fantome() { await apiSend('/purge/apply', 'POST', {}); }\n")]
    appels = appelants_web(js, confs)
    defauts, couverts, sans = verdict(sensibles, appels)
    if ("DELETE", "/api/things/:id") not in couverts:
        errs.append("témoin POSITIF en échec : un DELETE confirmé dans sa fonction n'est pas reconnu couvert")
    if ("POST", "/api/mode") not in couverts:
        errs.append("témoin d'APPELANT en échec : une confirmation portée par la fonction appelante n'est pas reconnue")
    mauvais = {(d[0], d[1]) for d in defauts}
    if ("POST", "/api/users/:id") not in mauvais or ("POST", "/api/rules/:id/enabled") not in mauvais:
        errs.append(f"témoin NÉGATIF en échec : un changement de rôle ou une activation SANS confirmation doit rougir (défauts : {sorted(mauvais)})")
    if ("POST", "/api/purge/apply") not in {(s[0], s[1]) for s in sans}:
        errs.append("témoin de SILENCE en échec : un appel en commentaire a été compté comme appelant")
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
        confs = confirmations_de_core(fh.read())
    if not confs:
        print("::error::aucune fonction `confirm*` exportée par web/core.js : il n'existe pas de confirmation partagée.")
        return 2
    sources_js = []
    for nom in sorted(os.listdir(WEB)):
        if nom.endswith(".js") and nom != "sw.js":
            with open(os.path.join(WEB, nom), encoding="utf-8", errors="replace") as fh:
                sources_js.append((os.path.join(WEB, nom), fh.read()))
    appels = appelants_web(sources_js, confs)
    defauts, couverts, sans = verdict(sensibles, appels)
    if ROUTE_TEMOIN not in couverts:
        print(f"::error::la route témoin {ROUTE_TEMOIN} n'a pas d'appelant web confirmé : soit la surface a régressé, "
              "soit l'analyse des appelants ne reconnaît plus la forme du code.")
        return 1

    print(f"routes sensibles dérivées du démon : {len(sensibles)} (sur {len(routes)} routes mutantes)")
    for (verbe, path), (familles, handler, fichier) in sorted(sensibles.items()):
        etat = "confirmée" if (verbe, path) in couverts else ("SANS CONFIRMATION" if (verbe, path) in {(d[0], d[1]) for d in defauts} else "sans appelant web")
        print(f"  {verbe:6} {path:44} {etat:18} {'; '.join(familles)}")
    for verbe, path, familles, sites in defauts:
        for f, ligne, _m, motif, _c, fn in sites:
            print(f"::error::{f}:{ligne} — `{fn}` appelle {verbe} {path} ({'; '.join(familles)}) sans passer par une "
                  f"confirmation partagée ({', '.join(confs)}) : l'utilisateur ne voit pas la conséquence avant d'agir.")
    if defauts:
        print(f"\n{len(defauts)} route(s) sensible(s) appelée(s) sans confirmation.")
        return 1
    print(f"\nOK — {len(couverts)} route(s) sensible(s) confirmée(s) par la surface, {len(sans)} sans appelant web "
          f"(contrôle par API) ; confirmations partagées : {', '.join(confs)}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
