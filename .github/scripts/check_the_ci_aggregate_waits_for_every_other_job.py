#!/usr/bin/env python3
r"""Le check requis `CI` attend le verdict de TOUS les autres travaux de `ci.yml` — garde de CI (`P10.31-t`).

LE DÉFAUT
---------
Le ruleset de `main` n'exige qu'un contexte : `CI`, le nom du travail d'agrégation `ci-ok` de
`.github/workflows/ci.yml`. C'est lui, et lui seul, qui traduit le rouge de `security` (cargo-audit,
gitleaks), de `test` ou de `collectors` en refus de fusion. Avant cette garde, aucun instrument ne
lisait cet agrégat (la garde de l'appel unique gitleaks l'avouait en toutes lettres) : retirer
`security` de ses `needs`, lui ôter son `if: always()`, retirer `skipped` de la condition du pas de
verdict, ou poser `continue-on-error: true` sur un travail requis rendait le check requis VERT devant
un scan de secrets ROUGE, sans qu'aucun vert ne bouge.

CE QUI EST TENU (lu par PyYAML, chargeur sûr)
---------------------------------------------
  (i)   l'ensemble des `needs` de `ci-ok` est EXACTEMENT l'ensemble des AUTRES travaux de `ci.yml`,
        DÉRIVÉ du fichier, jamais écrit ici : un travail neuf non attendu est refusé, un travail retiré
        des `needs` aussi ; une chaîne (`ci-ok` n'attend qu'un travail qui attend les autres) aussi ;
  (ii)  `ci-ok.if` vaut exactement `always()` (sinon un travail amont en échec SAUTE l'agrégat, et un
        check requis sauté passe pour satisfait) ;
  (iii) `ci-ok` a UN pas, dont la condition est exactement la disjonction de
        `contains(needs.*.result, '<v>')` pour `failure`, `cancelled` et `skipped` (chacun une fois :
        ni terme répété, ni terme illisible comme une négation `!(…)`), et dont le `run` n'est que des
        `echo "…"` inertes puis `exit 1` ; le `run` est découpé sur `\n` SEUL, comme bash le découpe, et
        tout caractère hors ASCII imprimable et `\n` y est refusé (`\r`, `\v`, `\x1c`, U+0085, U+2028 :
        `str.splitlines()` y voit une fin de ligne, bash un caractère du mot — `echo "x"\rexit 1` est UN
        `echo` qui sort 0) ; un message `echo` ne contient ni guillemet, ni barre inverse (`echo "x\"`
        puis `echo "; exit 0 #"` forment UNE chaîne et `exit 0` s'exécute), ni `$` hors de
        `${{ join(needs.*.result, ', ') }}` (toute autre expression — un titre de PR substitué par
        `${{ github.event.pull_request.title }}` — y est refusée), ni backquote ; chaque terme de la
        condition lit `needs.*.result` (pas un seul travail) par `contains` (pas `startsWith`) ;
        le pas n'a ni `shell:`, ni `env:`, ni
        `continue-on-error` (clés admises : `name`, `if`, `run`) ;
  (iv)  ni `ci-ok` ni aucun travail requis ne porte `continue-on-error` ou un `if:` de travail ;
        `ci-ok` n'a que les clés `name`, `if`, `needs`, `runs-on`, `timeout-minutes`, `steps` (pas de
        `strategy` qui renommerait le contexte, pas de `defaults`/`env` qui changeraient l'interprète) ;
        le flux n'a pas de `defaults`, et son `env:` ne pose ni `BASH_ENV`, ni `ENV`, ni `SHELLOPTS`,
        ni `BASHOPTS`, ni `PATH`, ni aucun nom de fonction exportée (préfixe `BASH_FUNC_` ou
        `__BASH_FUNC`, nom qui contient `%%` ou finit par `()`), ni une valeur qui commence par `()` :
        `BASH_FUNC_exit%%` ou `BASH_FUNC_echo%%` = `() { builtin exit 0; }` font sortir en 0 le `run`
        substitué sous `bash --noprofile --norc -eo pipefail` (bash 5.2) ;
  (v)   le nom de `ci-ok` est exactement `CI`, et AUCUN autre travail d'aucun flux de
        `.github/workflows/` ne peut porter le nom effectif `CI` (nom littéral, ou clé du travail sans
        `name:` ; un nom à expression `${{ … }}` n'est admis que si son texte littéral de tête ou de
        queue, blancs retirés, exclut `CI`, sinon la garde refuse de conclure ; un `name:` nul, ou non
        chaîne, ne s'exclut pas). Les flux lus sont les `*.yml` et `*.yaml` du répertoire du `ci.yml`
        jugé, extension lue SANS égard à la casse, plus le fichier jugé lui-même quelle que soit son
        extension ; le nom effectif est `name:` s'il est posé, sinon la clé ; seul le `ci-ok` du fichier
        jugé est exclu ; un flux lu sans mapping `jobs` rend 2.

UNE FORME QUE LA GARDE NE SAIT PAS LIRE EST REFUSÉE, JAMAIS ADMISE : ancre, alias, clé de fusion
`<<`, étiquette explicite (`!!…`), clé répétée — dans n'importe quel flux lu — rendent 2.

AUTO-ÉPREUVE DANS LES DEUX SENS, avant tout verdict : un flux fabriqué conforme passe ; chacune de
ses mutations (`mutations()` : une par propriété et par exclusion — needs, `if`, condition, `run`,
`env:` de flux, nom) est refusée ; chaque forme YAML illisible est refusée par le chargeur. La LECTURE
des autres flux est éprouvée sur de VRAIS fichiers temporaires, par `noms_des_autres_travaux` même,
un essai par site (`epreuve_lecture_des_flux`) : un `ci.yml` seul passe, un autre flux sans `CI`
passe ; un travail `name: CI` dans un `.yml`, un `.yaml`, un `.YML`, un travail de CLÉ `CI` sans
`name:` ou à `name:` nul, un `ci-ok` nommé `CI` dans un autre flux, un AUTRE travail du ci.yml jugé
nommé `CI` (y compris quand le fichier jugé n'a pas l'extension `.yml`) sont refusés ; un flux sans
`jobs` rend 2. Puis les MÊMES mutations sont rejouées sur le `ci.yml` RÉEL (s'il passe) et
doivent toutes y être refusées. Un témoin qui ne rougit pas : la garde refuse de conclure (2).

CE QUE LA GARDE NE TIENT PAS
-----------------------------
  - Le RULESET lui-même (côté GitHub, hors dépôt) n'est pas lu : que le contexte requis soit bien
    `CI`, qu'il soit exigé sur `main`, qu'aucun contournement ne soit accordé, rien ici ne le prouve.
  - Un écart de lecture entre PyYAML (YAML 1.1) et le lecteur de GitHub : une forme que les deux
    acceptent mais lisent différemment échappe ; les formes connues pour diverger (ancres, fusion,
    étiquettes, clés répétées) sont refusées, pas jugées.
  - Les autres flux (`agent-ci.yml`, `agent-cross.yml`, `message-public.yml`) ne sont lus que pour le
    nom `CI` : s'ils fournissent un check requis, leur agrégation n'est pas jugée.
  - Le contenu des travaux requis : qu'un pas de `security` avale son code (`|| true`, `continue-on-
    error` de PAS) relève des gardes de ces pas (`check_every_gitleaks_scan_takes_the_single_call.py`
    pour gitleaks) ; cette garde ne juge que l'AGRÉGATION des verdicts de travaux.
  - Ce qui agit hors du texte du flux (variables d'organisation, coureur compromis) n'est pas lu.
  - Ce que le coureur GitHub fait d'un `\r` ou d'un U+2028 dans un `run` n'est pas mesuré : la garde
    les refuse, elle ne prouve pas qu'ils seraient exploitables sur GitHub (ils le sont sous bash).
    De même, que le coureur transmette au processus un nom `BASH_FUNC_…%%` posé dans `env:` n'est
    pas mesuré : la garde le refuse parce que bash, lui, l'importe.
  - Les autres variables que bash lit au démarrage (`IFS`, `PS4`, `GLOBIGNORE`, `POSIXLY_CORRECT`,
    `BASH_COMPAT`, `BASH_XTRACEFD`) ne sont pas refusées : posées à des valeurs hostiles, aucune ne
    change le code de sortie du `run` substitué (mesuré sous bash 5.2, `rc=1` pour chacune) ; une
    variable que bash lirait à l'avenir n'est pas suivie.
  - Le `env:` d'un AUTRE travail, ou une variable écrite dans `$GITHUB_ENV` par un pas, n'est pas
    lu : `ci-ok` n'a qu'un pas et ni `env:` de travail ni `env:` de pas ne lui sont admis.
  - Contrôles sans témoin qui les isole, DÉCLARÉS : le découpage sur `\n` seul est redondant avec le
    refus des caractères hors ASCII imprimable (le remettre à `splitlines()` seul ne change aucun
    verdict) ; le refus de l'alias est redondant avec celui de l'ancre (un alias sans ancre est une
    erreur YAML) ; le refus de la clé `<<` est redondant avec le constructeur (aucun constructeur pour
    l'étiquette de fusion : erreur YAML).
  - PRUDENCES au-delà d'un contournement connu, chacune avec une mutation de `mutations()` ou un essai
    de `epreuve_lecture_des_flux` qui la rougit : le refus de `ci` (casse), de ` CI ` (blancs), d'un
    `needs` qui cite un travail inexistant ou répété, d'un terme de condition répété, d'une backquote
    dans un `echo` (sous-shell : `exit 0` n'y sort pas du pas, mesuré `rc=1`), d'un nom à expression
    dont la tête ou la queue littérale n'exclut `CI` qu'une fois ses blancs comptés, d'un `name:` nul,
    d'un flux `.YML`, d'un flux sans `jobs`. Que GitHub lise `name:` nul comme la clé, rogne les blancs
    d'un nom, ou exécute un flux `.YML`, n'est PAS mesuré : ces refus peuvent être plus stricts que
    nécessaire, jamais plus laxistes.
  - Retirer une auto-épreuve (`epreuve`, `epreuve_lecture_des_flux`) ne rougit pas seul : il faut aussi
    affaiblir le contrôle qu'elle éprouve, ET un flux réel qui l'exerce, pour qu'un verdict change.

Usage : python3 .github/scripts/check_the_ci_aggregate_waits_for_every_other_job.py [CHEMIN/ci.yml]
        (par défaut `.github/workflows/ci.yml` ; les autres flux lus sont ceux du MÊME répertoire)
Sortie : 0 = tenu ; 1 = propriété violée ; 2 = instrument invalide, PyYAML absent ou forme illisible.
"""
from __future__ import annotations

import copy
import os
import re
import sys
import tempfile

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.realpath(os.path.join(ICI, "..", ".."))
FLUX = os.path.join(RACINE, ".github", "workflows")
CI_YML = os.path.join(FLUX, "ci.yml")

AGREGAT = "ci-ok"
NOM_REQUIS = "CI"
CLES_AGREGAT = {"name", "if", "needs", "runs-on", "timeout-minutes", "steps"}
CLES_PAS = {"name", "if", "run"}
ISSUES_REFUSEES = {"failure", "cancelled", "skipped"}
ENV_INTERDITES = {"BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "PATH"}
# bash importe une FONCTION depuis l'environnement : `BASH_FUNC_<nom>%%` (bash amont >= 4.3 corrigé),
# `BASH_FUNC_<nom>()` et `__BASH_FUNC<<nom>>` (correctifs de distributions), et toute valeur `() {…`
# (bash sans correctif). `BASH_FUNC_exit%%=() { builtin exit 0; }` fait sortir le pas de verdict en 0.
PREFIXES_FONCTION_EXPORTEE = ("BASH_FUNC_", "__BASH_FUNC")
TERME = re.compile(r"^contains\(needs\.\*\.result, '([a-z]+)'\)$")
ECHO = re.compile(r"""^echo "(?:[^"`$\\]|\$\{\{ join\(needs\.\*\.result, ', '\) \}\})*"$""")
# bash ne coupe une commande que sur `\n` ; `str.splitlines()` coupe aussi sur `\r`, `\v`, `\f`, `\x1c`-`\x1e`,
# U+0085, U+2028, U+2029. Le `run` du verdict n'admet donc que l'ASCII imprimable et `\n`.
HORS_ALPHABET_DU_RUN = re.compile(r"[^\x20-\x7e\n]")


class FormeIllisible(Exception):
    """Forme YAML que la garde refuse de lire (rend 2)."""


def charger(texte, yaml):
    """Chargeur sûr qui REFUSE ancres, alias, fusion, étiquettes explicites et clés répétées."""
    try:
        for ev in yaml.parse(texte, Loader=yaml.SafeLoader):
            if isinstance(ev, yaml.AliasEvent):
                raise FormeIllisible("alias YAML (`*…`)")
            if getattr(ev, "anchor", None) is not None:
                raise FormeIllisible(f"ancre YAML (`&{ev.anchor}`)")
            if getattr(ev, "tag", None) is not None:
                raise FormeIllisible(f"étiquette YAML explicite (`{ev.tag}`)")
            if isinstance(ev, yaml.ScalarEvent) and ev.value == "<<" and ev.implicit[0]:
                raise FormeIllisible("clé de fusion YAML (`<<`)")
    except yaml.YAMLError as e:
        raise FormeIllisible(f"YAML illisible : {e}".splitlines()[0])

    class Chargeur(yaml.SafeLoader):
        pass

    def mapping(loader, node):
        vues = set()
        for k_node, _ in node.value:
            k = loader.construct_object(k_node, deep=True)
            if k in vues:
                raise FormeIllisible(f"clé répétée `{k}` (ligne {k_node.start_mark.line + 1})")
            vues.add(k)
        return loader.construct_mapping(node, deep=True)

    Chargeur.add_constructor("tag:yaml.org,2002:map", mapping)
    try:
        return yaml.load(texte, Loader=Chargeur)
    except yaml.YAMLError as e:
        raise FormeIllisible(f"YAML illisible : {e}".splitlines()[0])


def nom_peut_valoir_ci(nom):
    """Vrai si le nom effectif PEUT rendre `CI` ; None si la garde ne sait pas le dire."""
    if not isinstance(nom, str):
        return None
    if "${{" not in nom:
        return nom.strip().casefold() == NOM_REQUIS.casefold()
    tete = nom.split("${{", 1)[0].casefold()
    queue = nom.rsplit("}}", 1)[-1].casefold() if "}}" in nom else ""
    cible = NOM_REQUIS.casefold()
    if tete.strip() and not cible.startswith(tete.lstrip()):
        return False
    if queue.strip() and not cible.endswith(queue.rstrip()):
        return False
    return None


def juger(ci, autres):
    """Violations de (i)…(v) sur le flux `ci` (dict) ; `autres` = [(flux, clé, nom effectif)] hors `ci-ok`."""
    v = []
    if not isinstance(ci, dict):
        return ["ci.yml n'est pas un mapping"]
    if "defaults" in ci:
        v.append("le flux pose `defaults` (interprète des pas de l'agrégat modifiable)")
    env = ci.get("env") or {}
    if not isinstance(env, dict):
        v.append("`env` de flux n'est pas un mapping")
    else:
        for k, val in env.items():
            if str(k) in ENV_INTERDITES:
                v.append(f"`env` de flux pose `{k}` (agit avant le pas de verdict)")
            elif str(k).startswith(PREFIXES_FONCTION_EXPORTEE) or "%%" in str(k) or str(k).endswith("()"):
                v.append(f"`env` de flux pose `{k}`, nom de fonction exportée que bash importe au démarrage")
            elif isinstance(val, str) and val.lstrip().startswith("()"):
                v.append(f"`env` de flux pose `{k}` à une valeur `() …` qu'un bash sans correctif importe comme fonction")
    jobs = ci.get("jobs")
    if not isinstance(jobs, dict) or AGREGAT not in jobs:
        return v + [f"travail `{AGREGAT}` absent de ci.yml"]
    agr = jobs[AGREGAT]
    if not isinstance(agr, dict):
        return v + [f"`{AGREGAT}` n'est pas un mapping"]
    # (v) nom
    if agr.get("name") != NOM_REQUIS:
        v.append(f"(v) `{AGREGAT}.name` vaut {agr.get('name')!r}, attendu {NOM_REQUIS!r}")
    for flux, cle, nom in autres:
        r = nom_peut_valoir_ci(nom)
        if r is True:
            v.append(f"(v) `{flux}` : le travail `{cle}` porte aussi le nom effectif `CI` ({nom!r})")
        elif r is None:
            v.append(f"(v) `{flux}` : le nom du travail `{cle}` ({nom!r}) peut rendre `CI` — la garde ne sait pas l'exclure")
    # (iv) clés de l'agrégat
    for k in sorted(set(agr) - CLES_AGREGAT, key=str):
        v.append(f"(iv) `{AGREGAT}` porte la clé `{k}` (admises : {', '.join(sorted(CLES_AGREGAT))})")
    # (ii)
    if agr.get("if") != "always()":
        v.append(f"(ii) `{AGREGAT}.if` vaut {agr.get('if')!r}, attendu 'always()'")
    # (i) needs == autres travaux, dérivé
    needs = agr.get("needs")
    if isinstance(needs, str):
        needs = [needs]
    if not isinstance(needs, list) or not all(isinstance(n, str) for n in needs):
        v.append(f"(i) `{AGREGAT}.needs` n'est pas une liste de noms : {needs!r}")
        needs = []
    attendus = {str(k) for k in jobs if k != AGREGAT}
    lus = set(needs)
    for k in sorted(attendus - lus):
        v.append(f"(i) le travail `{k}` n'est pas dans `{AGREGAT}.needs` : son rouge ne fait pas échouer `CI`")
    for k in sorted(lus - attendus):
        v.append(f"(i) `{AGREGAT}.needs` cite `{k}`, qui n'est pas un travail de ci.yml")
    if len(needs) != len(lus):
        v.append(f"(i) `{AGREGAT}.needs` répète un nom")
    # (iv) travaux requis
    for k in sorted(attendus):
        j = jobs[k]
        if not isinstance(j, dict):
            v.append(f"(iv) le travail `{k}` n'est pas un mapping")
            continue
        if "continue-on-error" in j:
            v.append(f"(iv) le travail requis `{k}` porte `continue-on-error` de travail")
        if "if" in j:
            v.append(f"(iv) le travail requis `{k}` porte un `if:` de travail ({j['if']!r})")
    # (iii) le pas de verdict
    pas = agr.get("steps")
    if not isinstance(pas, list) or len(pas) != 1 or not isinstance(pas[0], dict):
        v.append(f"(iii) `{AGREGAT}` doit avoir UN seul pas (lu : {len(pas) if isinstance(pas, list) else pas!r})")
        return v
    p = pas[0]
    for k in sorted(set(p) - CLES_PAS, key=str):
        v.append(f"(iii) le pas de verdict porte la clé `{k}` (admises : {', '.join(sorted(CLES_PAS))})")
    cond = p.get("if")
    issues = []
    if isinstance(cond, str):
        for t in cond.split("||"):
            m = TERME.match(t.strip())
            if not m:
                issues = None
                break
            issues.append(m.group(1))
    else:
        issues = None
    if issues is None or set(issues) != ISSUES_REFUSEES or len(issues) != len(ISSUES_REFUSEES):
        v.append(f"(iii) condition du pas de verdict {cond!r} : attendu la disjonction exacte de "
                 f"contains(needs.*.result, …) pour {sorted(ISSUES_REFUSEES)}")
    run = p.get("run")
    if isinstance(run, str) and HORS_ALPHABET_DU_RUN.search(run):
        c = HORS_ALPHABET_DU_RUN.search(run).group(0)
        v.append(f"(iii) le `run` du pas de verdict porte U+{ord(c):04X}, hors ASCII imprimable et `\\n` : "
                 "bash ne découpe que sur `\\n`, la garde refuse de juger un autre séparateur")
    lignes = [l.strip() for l in run.split("\n") if l.strip()] if isinstance(run, str) else []
    if not lignes or lignes[-1] != "exit 1" or not all(ECHO.match(l) for l in lignes[:-1]):
        v.append(f"(iii) le `run` du pas de verdict doit être des `echo \"…\"` inertes puis `exit 1` : {run!r}")
    return v


def mutations(ci):
    """(nom, flux muté, autres ajoutés) : chaque mutation viole UNE propriété."""
    def m(f):
        d = copy.deepcopy(ci)
        f(d)
        return d
    A = AGREGAT
    requis = sorted(k for k in ci["jobs"] if k != A)
    un = "security" if "security" in requis else requis[0]

    def chaine(d):
        d["jobs"][A]["needs"] = [requis[0]]
        for a, b in zip(requis, requis[1:]):
            d["jobs"][a]["needs"] = [b]

    def pas2(d):
        d["jobs"][A]["steps"].append({"run": "true"})

    def cond(texte):
        return lambda d: d["jobs"][A]["steps"][0].__setitem__("if", texte)

    def run(texte):
        return lambda d: d["jobs"][A]["steps"][0].__setitem__("run", texte)

    def env(cle, valeur="/x"):
        return lambda d: d.setdefault("env", {}).__setitem__(cle, valeur)

    F, C, S = (f"contains(needs.*.result, '{x}')" for x in ("failure", "cancelled", "skipped"))

    return [
        ("security retiré des needs", m(lambda d: d["jobs"][A].__setitem__("needs", [n for n in d["jobs"][A]["needs"] if n != un])), []),
        ("travail neuf absent des needs", m(lambda d: d["jobs"].__setitem__("travail-neuf", {"runs-on": "x", "steps": [{"run": "true"}]})), []),
        ("if: always() retiré", m(lambda d: d["jobs"][A].pop("if")), []),
        ("if: success()", m(lambda d: d["jobs"][A].__setitem__("if", "success()")), []),
        ("skipped retiré de la condition", m(lambda d: d["jobs"][A]["steps"][0].__setitem__("if", "contains(needs.*.result, 'failure') || contains(needs.*.result, 'cancelled')")), []),
        ("&& dans la condition", m(lambda d: d["jobs"][A]["steps"][0].__setitem__("if", "contains(needs.*.result, 'failure') && contains(needs.*.result, 'cancelled') || contains(needs.*.result, 'skipped')")), []),
        ("continue-on-error sur l'agrégat", m(lambda d: d["jobs"][A].__setitem__("continue-on-error", True)), []),
        ("continue-on-error sur un travail requis", m(lambda d: d["jobs"][un].__setitem__("continue-on-error", True)), []),
        ("if: sur un travail requis", m(lambda d: d["jobs"][un].__setitem__("if", "false")), []),
        ("needs en chaîne", m(chaine), []),
        ("nom changé", m(lambda d: d["jobs"][A].__setitem__("name", "CI (agrégat)")), []),
        ("needs cite un travail inexistant", m(lambda d: d["jobs"][A]["needs"].append("inexistant")), []),
        ("needs répète un travail", m(lambda d: d["jobs"][A]["needs"].append(un)), []),
        ("terme répété à la place de skipped", m(cond(f"{F} || {F} || {C}")), []),
        ("terme répété en plus", m(cond(f"{F} || {C} || {S} || {S}")), []),
        ("négation de la disjonction", m(cond(f"!({F} || {F} || {C} || {S} || {S})")), []),
        ("condition sur un seul travail", m(cond(" || ".join(f"contains(needs.{un}.result, '{x}')" for x in ("failure", "cancelled", "skipped")))), []),
        ("startsWith au lieu de contains", m(cond(" || ".join(f"startsWith(needs.*.result, '{x}')" for x in ("failure", "cancelled", "skipped")))), []),
        ("second travail CI dans un autre flux", ci, [("autre.yml", "faux", "CI")]),
        ("second travail ci en casse différente", ci, [("autre.yml", "faux", "ci")]),
        ("second travail CI entouré de blancs", ci, [("autre.yml", "faux", " CI ")]),
        ("nom à expression de tête littérale C", ci, [("autre.yml", "x", "C${{ github.ref }}")]),
        ("nom à expression de queue littérale I", ci, [("autre.yml", "x", "${{ github.ref }}I")]),
        ("nom à expression, tête C précédée de blancs", ci, [("autre.yml", "x", "  C${{ github.ref }}")]),
        ("nom à expression, queue I suivie de blancs", ci, [("autre.yml", "x", "${{ github.ref }}I  ")]),
        ("nom à expression qui peut rendre CI", ci, [("autre.yml", "x", "${{ 'CI' }}")]),
        ("exit 0", m(lambda d: d["jobs"][A]["steps"][0].__setitem__("run", "exit 0\n")), []),
        ("|| true", m(lambda d: d["jobs"][A]["steps"][0].__setitem__("run", "exit 1 || true\n")), []),
        ("substitution dans echo", m(lambda d: d["jobs"][A]["steps"][0].__setitem__("run", 'echo "$(exit 0)"\nexit 1\n')), []),
        ("guillemet dans echo", m(run('echo "a"; exit 0; echo "b"\nexit 1\n')), []),
        ("barre inverse dans echo", m(run('echo "x\\"\necho "; exit 0 #"\nexit 1\n')), []),
        ("backquote dans echo", m(run('echo "`true`"\nexit 1\n')), []),
        ("autre expression dans echo", m(run('echo "::error::${{ github.event.pull_request.title }}"\nexit 1\n')), []),
        ("join d'un autre champ dans echo", m(run("echo \"${{ join(github.event.commits.*.message, ', ') }}\"\nexit 1\n")), []),
        ("\\r comme séparateur du run", m(run('echo "::error::x"\rexit 1\n')), []),
        ("\\r dans un message echo", m(run('echo "a\rb"\nexit 1\n')), []),
        ("U+2028 comme séparateur du run", m(run('echo "::error::x"\u2028exit 1\n')), []),
        ("shell: sur le pas", m(lambda d: d["jobs"][A]["steps"][0].__setitem__("shell", "true {0}")), []),
        ("continue-on-error sur le pas", m(lambda d: d["jobs"][A]["steps"][0].__setitem__("continue-on-error", True)), []),
        ("second pas", m(pas2), []),
        ("defaults de flux", m(lambda d: d.__setitem__("defaults", {"run": {"shell": "true {0}"}})), []),
        ("BASH_ENV de flux", m(env("BASH_ENV")), []),
        ("ENV de flux", m(env("ENV")), []),
        ("SHELLOPTS de flux", m(env("SHELLOPTS")), []),
        ("BASHOPTS de flux", m(env("BASHOPTS")), []),
        ("PATH de flux", m(env("PATH")), []),
        ("BASH_FUNC_exit%% de flux", m(env("BASH_FUNC_exit%%", "() { builtin exit 0; }")), []),
        ("BASH_FUNC_echo%% de flux", m(env("BASH_FUNC_echo%%", "() { builtin exit 0; }")), []),
        ("préfixe BASH_FUNC_ seul, valeur neutre", m(env("BASH_FUNC_exit")), []),
        ("préfixe __BASH_FUNC seul, valeur neutre", m(env("__BASH_FUNC<exit>")), []),
        ("nom exit%% de flux, valeur neutre", m(env("exit%%")), []),
        ("nom exit() de flux, valeur neutre", m(env("exit()")), []),
        ("valeur () { de flux sous un nom neutre", m(env("exit", "() { builtin exit 0; }")), []),
        ("strategy sur l'agrégat", m(lambda d: d["jobs"][A].__setitem__("strategy", {"matrix": {"x": [1]}})), []),
    ]


FLUX_FABRIQUE = """\
name: ci
on: [push]
env:
  X: "1"
jobs:
  test:
    runs-on: u
    steps:
      - run: "true"
  security:
    runs-on: u
    steps:
      - run: "true"
  lint:
    runs-on: u
    steps:
      - run: "true"
  ci-ok:
    name: CI
    if: always()
    needs: [test, security, lint]
    runs-on: u
    timeout-minutes: 5
    steps:
      - name: verdict
        if: contains(needs.*.result, 'failure') || contains(needs.*.result, 'cancelled') || contains(needs.*.result, 'skipped')
        run: |
          echo "::error::a CI job did not succeed: ${{ join(needs.*.result, ', ') }}"
          exit 1
"""

FORMES_ILLISIBLES = [
    ("ancre et alias", "a: &n [x]\nb: *n\n"),
    ("ancre seule", "a: &n [x]\n"),
    ("clé de fusion", "a:\n  <<: {x: 1}\n"),
    ("étiquette explicite", "a: !!str x\n"),
    ("clé répétée", "jobs:\n  ci-ok: {}\n  ci-ok: {}\n"),
    ("YAML cassé", "a: [\n"),
]


def epreuve(base, autres, yaml, etiquette):
    """Base conforme -> 0 violation ; chaque mutation -> au moins une. Rend la faute, ou None."""
    if juger(base, autres):
        return f"{etiquette} : la base conforme est refusée : {juger(base, autres)[0]}"
    for nom, d, ajout in mutations(base):
        if not juger(d, autres + ajout):
            return f"{etiquette} : la mutation « {nom} » n'est PAS refusée"
    return None


def epreuves_instrument(yaml):
    for nom, texte in FORMES_ILLISIBLES:
        try:
            charger(texte, yaml)
        except FormeIllisible:
            continue
        return f"forme « {nom} » ADMISE par le chargeur"
    try:
        base = charger(FLUX_FABRIQUE, yaml)
    except FormeIllisible as e:
        return f"le flux fabriqué conforme est illisible : {e}"
    if not isinstance(base.get("jobs"), dict) or "ci-ok" not in base["jobs"]:
        return "le flux fabriqué n'est pas lu comme attendu"
    autres = [("autre.yml", "agent", "agent (${{ matrix.os }})"), ("autre.yml", "verifier", "verifier"),
              ("autre.yml", "lot", "${{ matrix.os }} build"), ("autre.yml", "bot", "build ${{ matrix.os }}")]
    faute = epreuve(base, autres, yaml, "flux fabriqué")
    return faute or epreuve_lecture_des_flux(yaml)


AUTRE_FLUX = """\
name: autre
on: [push]
jobs:
  {cle}:
{nom}    runs-on: u
    steps:
      - run: "true"
"""


def epreuve_lecture_des_flux(yaml):
    """(v) éprouvé sur de VRAIS fichiers, par `noms_des_autres_travaux` même : rend la faute, ou None.

    Chaque essai isole un site de la lecture : extensions `.yml`/`.yaml` et leur casse, nom effectif
    `name:` puis clé à défaut, exclusion du SEUL `ci-ok` du ci.yml jugé (pas des autres travaux du
    ci.yml, pas d'un `ci-ok` d'un autre flux), `name:` nul, flux sans `jobs`, ci.yml jugé hors des
    extensions lues."""
    sans_ci = AUTRE_FLUX.format(cle="agent", nom="    name: verifier\n")
    nomme_ci = AUTRE_FLUX.format(cle="faux", nom="    name: CI\n")
    cle_ci_sans_nom = AUTRE_FLUX.format(cle="CI", nom="")
    cle_ci_nom_nul = AUTRE_FLUX.format(cle="CI", nom="    name:\n")
    agregat_ailleurs = AUTRE_FLUX.format(cle=AGREGAT, nom="    name: CI\n")
    sans_jobs = "name: autre\non: [push]\n"
    ci_lint_nomme_ci = FLUX_FABRIQUE.replace("  lint:\n", "  lint:\n    name: CI\n", 1)
    if ci_lint_nomme_ci == FLUX_FABRIQUE:
        return "lecture des flux : le flux fabriqué n'a pas de travail `lint` à renommer"
    ILLISIBLE = "illisible"
    essais = [  # (nom, fichier jugé, son texte, autres fichiers, attendu : False admis / True refusé / ILLISIBLE)
        ("ci.yml seul dans son répertoire", "ci.yml", FLUX_FABRIQUE, {}, False),
        ("autre flux .yml sans travail CI", "ci.yml", FLUX_FABRIQUE, {"autre.yml": sans_ci}, False),
        ("autre flux .yml, travail `name: CI`", "ci.yml", FLUX_FABRIQUE, {"autre.yml": nomme_ci}, True),
        ("autre flux .yaml, travail `name: CI`", "ci.yml", FLUX_FABRIQUE, {"autre.yaml": nomme_ci}, True),
        ("autre flux .YML (casse), travail `name: CI`", "ci.yml", FLUX_FABRIQUE, {"autre.YML": nomme_ci}, True),
        ("autre flux, travail de clé `CI` sans `name:`", "ci.yml", FLUX_FABRIQUE, {"autre.yml": cle_ci_sans_nom}, True),
        ("autre flux, travail de clé `CI` à `name:` nul", "ci.yml", FLUX_FABRIQUE, {"autre.yml": cle_ci_nom_nul}, True),
        (f"autre flux, travail de clé `{AGREGAT}` nommé `CI`", "ci.yml", FLUX_FABRIQUE, {"autre.yml": agregat_ailleurs}, True),
        ("ci.yml jugé, un AUTRE de ses travaux nommé `CI`", "ci.yml", ci_lint_nomme_ci, {}, True),
        ("ci jugé hors des extensions lues, un autre de ses travaux nommé `CI`", "ci-copie.txt", ci_lint_nomme_ci, {}, True),
        ("autre flux sans mapping `jobs`", "ci.yml", FLUX_FABRIQUE, {"autre.yml": sans_jobs}, ILLISIBLE),
    ]
    for nom, juge, texte, fichiers, attendu in essais:
        with tempfile.TemporaryDirectory(prefix="garde-ci-ok-") as rep:
            ci_chemin = os.path.join(rep, juge)
            for f, t in [(juge, texte), *fichiers.items()]:
                with open(os.path.join(rep, f), "w", encoding="utf-8") as fh:
                    fh.write(t)
            with open(ci_chemin, encoding="utf-8") as fh:
                ci = charger(fh.read(), yaml)
            try:
                lu = bool(juger(ci, noms_des_autres_travaux(yaml, ci_chemin)))
            except FormeIllisible:
                lu = ILLISIBLE
            if lu != attendu:
                return f"lecture des flux : « {nom} » rend {lu!r}, attendu {attendu!r}"
    return None


def noms_des_autres_travaux(yaml, ci_chemin):
    """[(flux, clé, nom effectif)] de tous les travaux des flux du répertoire de `ci_chemin`, hors son `ci-ok`."""
    out = []
    repertoire = os.path.dirname(os.path.abspath(ci_chemin))
    fichiers = sorted(f for f in os.listdir(repertoire) if f.lower().endswith((".yml", ".yaml")))
    chemins = [os.path.join(repertoire, f) for f in fichiers]
    if os.path.realpath(ci_chemin) not in {os.path.realpath(c) for c in chemins}:
        chemins.append(ci_chemin)
    for c in chemins:
        with open(c, encoding="utf-8") as fh:
            d = charger(fh.read(), yaml)
        jobs = d.get("jobs") if isinstance(d, dict) else None
        if not isinstance(jobs, dict):
            raise FormeIllisible(f"{os.path.basename(c)} : pas de mapping `jobs`")
        est_ci = os.path.realpath(c) == os.path.realpath(ci_chemin)
        for k, j in jobs.items():
            if est_ci and k == AGREGAT:
                continue
            nom = j.get("name", str(k)) if isinstance(j, dict) else str(k)
            out.append((os.path.basename(c), str(k), nom))
    return out


def main(argv):
    try:
        import yaml
    except ImportError:
        print("::error::PyYAML absent : la garde REFUSE DE CONCLURE (paquet python3-yaml)", file=sys.stderr)
        return 2
    faute = epreuves_instrument(yaml)
    if faute:
        print(f"::error::instrument INVALIDE, la garde REFUSE DE CONCLURE — {faute}", file=sys.stderr)
        return 2
    ci_chemin = argv[1] if len(argv) > 1 else CI_YML
    try:
        with open(ci_chemin, encoding="utf-8") as fh:
            ci = charger(fh.read(), yaml)
        autres = noms_des_autres_travaux(yaml, ci_chemin)
    except (OSError, FormeIllisible) as e:
        print(f"::error::flux illisible, la garde REFUSE DE CONCLURE — {e}", file=sys.stderr)
        return 2
    violations = juger(ci, autres)
    if violations:
        for x in violations:
            print(f"::error file={os.path.relpath(ci_chemin, RACINE)}::{x}", file=sys.stderr)
        print(f"{len(violations)} violation(s) : le check requis `CI` n'attend pas le verdict de tous les travaux.",
              file=sys.stderr)
        return 1
    faute = epreuve(ci, autres, yaml, "ci.yml réel")
    if faute:
        print(f"::error::instrument INVALIDE, la garde REFUSE DE CONCLURE — {faute}", file=sys.stderr)
        return 2
    requis = sorted(k for k in ci["jobs"] if k != AGREGAT)
    nb_mutations = len(mutations(ci))
    print(f"OK : `{AGREGAT}` (nom `CI`, if: always()) attend les {len(requis)} autres travaux de ci.yml "
          f"({', '.join(requis)}) et échoue sur failure/cancelled/skipped ; {nb_mutations} mutations "
          f"refusées sur le flux fabriqué et sur le flux réel, {len(FORMES_ILLISIBLES)} formes illisibles refusées, "
          f"lecture des flux éprouvée sur fichiers.")
    return 0


def principal(argv):
    """Une exception de l'instrument n'est JAMAIS rendue comme une propriété violée (1) : elle rend 2."""
    try:
        return main(argv)
    except Exception as e:  # noqa: BLE001 — refuser de conclure plutôt que de laisser Python sortir en 1
        print(f"::error::instrument en ÉCHEC ({type(e).__name__}: {e}), la garde REFUSE DE CONCLURE", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(principal(sys.argv))
