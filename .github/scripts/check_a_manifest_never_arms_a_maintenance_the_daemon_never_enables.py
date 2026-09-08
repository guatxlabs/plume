#!/usr/bin/env python3
"""Un manifeste n'ARME jamais un entretien dont la précondition est un mode que le démon ne pose JAMAIS — garde de CI (`P7.20-d`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
Mesuré le 2026-08-30 puis le 2026-09-03 : `deploy/k3s.yaml` et `docker-compose.yml` posaient tous deux
`PLUME_AUTOVACUUM_INTERVAL=86400`, donc ARMAIENT la passe d'entretien incrémental de la base. Or cette
passe n'opère que si la base est en `auto_vacuum=INCREMENTAL` — la boucle du démon le vérifie elle-même
(`PRAGMA auto_vacuum`, et `continue` quand la valeur n'est pas 2) — et le schéma ne pose ce mode NULLE
PART. Le réglage était livré sans effet dans les deux manifestes, avec un avertissement au démarrage
que personne ne lit, et l'espace libéré par toute suppression ne retournait jamais au système.

Le démon n'est pas en cause : il vérifie, prévient et ne bloque rien. Le défaut est la CONJONCTION,
lisible sans rien exécuter : un manifeste arme une tâche + le code ne pose jamais l'état dont elle a
besoin. Même famille que `P9.4-b` (une tâche armée sans sa précondition), mais la précondition n'est
pas une variable livrée : c'est un PRAGMA que seul le code peut poser.

LA RÈGLE, ÉCRITE COMME UNE PROPRIÉTÉ
------------------------------------
    Si une tâche du démon est GATÉE par une variable `PLUME_*` (lue avec « 0 » pour défaut, 0 = return
    immédiat) ET que son corps se rend inerte (`continue`) quand un `PRAGMA p` ne vaut pas N, alors
    aucun fichier de déploiement ne livre cette variable avec une valeur non nulle tant que le démon
    n'ASSIGNE `PRAGMA p` nulle part.

RIEN N'EST ÉNUMÉRÉ : ni le nom de la variable, ni celui du PRAGMA, ni la valeur attendue. Les trois sont
lus dans le corps de la tâche (la forme du gate est CELLE de `P9.4-b`, importée, pas recopiée). Les
fichiers de déploiement sont ceux du geste partagé (`manifestes`), plus les fichiers d'environnement
d'exemple (`.env.example`) qui nourrissent compose : le 2026-09-03 il était établi que ce fichier n'arme
rien PAR LUI-MÊME — mais copié en `.env`, il réarme la passe à la première substitution.

CE QUE LA GARDE NE TIENT PAS : elle ne sait pas si une base EXISTANTE est en INCREMENTAL (cela se lit
avec `plume-daemon db-stats`, pas dans l'arbre) ; elle interdit seulement au dépôt de LIVRER l'armement
tant que le code ne pose pas le mode. Le jour où le schéma le pose, elle se tait d'elle-même.

Sortie : 0 rien à signaler · 1 défaut · 2 rien n'a été mesuré (dérivation vide : la garde serait inerte).
"""
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_every_style_selector_has_a_target import parcours_des_sources, racine_designee  # noqa: E402
from check_a_deployment_never_arms_a_task_it_cannot_run import (  # noqa: E402  (la forme du gate : source unique)
    CLE, affectations_du_manifeste, gates_du_corps, manifestes, sans_commentaire_rust, unites_rust)

DEPOT_DE_CETTE_GARDE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ETIQUETTE = "P7.20-d"

LECTURE_PRAGMA = re.compile(r"let\s+(\w+)\s*(?::\s*\w+)?\s*=\s*\w+\.query_row\(\s*\"PRAGMA\s+(\w+)\"")
AFFECT_ENV = re.compile(r"^\s*(" + CLE + r")\s*=\s*(.*)$")


def fichiers_rust_de_production(racine):
    """Les sources du démon hors tests : `daemon/src/**` sans les répertoires `tests` ni les `*tests.rs`."""
    src = os.path.join(racine, "daemon", "src")
    for d, fs in parcours_des_sources(src):
        if os.path.basename(d) == "tests" or "/tests/" in d.replace(os.sep, "/") + "/":
            continue
        for f in fs:
            if f.endswith(".rs") and not f.endswith("tests.rs"):
                yield os.path.join(d, f)


def preconditions_de_pragma(corps):
    """(pragma, valeur) : un `PRAGMA p` lu dans une variable, puis `if var != N { continue; }` dans ce corps."""
    lignes = [sans_commentaire_rust(l) for l in corps.splitlines()]
    code = "\n".join(lignes)
    trouves = set()
    for m in LECTURE_PRAGMA.finditer(code):
        var, pragma = m.group(1), m.group(2)
        inerte = re.compile(r"\bif\s+" + re.escape(var) + r"\s*!=\s*(\d+)\s*\{\s*continue\b")
        for k in inerte.finditer(code):
            trouves.add((pragma, k.group(1)))
    return trouves


def taches_armables(racine):
    """{clé PLUME_* : {(pragma, N)}} — les tâches gatées dont le corps se rend inerte sur un PRAGMA."""
    out = {}
    for f in fichiers_rust_de_production(racine):
        try:
            src = open(f, encoding="utf-8").read()
        except OSError:
            continue
        for _nom, corps in unites_rust(src):
            gates = gates_du_corps(corps)
            if not gates:
                continue
            pre = preconditions_de_pragma(corps)
            if not pre:
                continue
            for cle in gates:
                out.setdefault(cle, set()).update(pre)
    return out


def pragmas_assignes(racine):
    """Les PRAGMA que le code de production ASSIGNE (`PRAGMA p = …`), commentaires retirés."""
    vus = set()
    rx = re.compile(r"PRAGMA\s+(\w+)\s*=\s*\S")
    for f in fichiers_rust_de_production(racine):
        try:
            src = open(f, encoding="utf-8").read()
        except OSError:
            continue
        code = "\n".join(sans_commentaire_rust(l) for l in src.splitlines())
        vus.update(m.group(1) for m in rx.finditer(code))
    return vus


def fichiers_d_environnement(racine):
    for d, fs in parcours_des_sources(racine):
        for f in fs:
            if f == ".env.example" or f.endswith(".env.example"):
                yield os.path.join(d, f)


def armements(racine, cles):
    """[(fichier, ligne, clé, valeur)] : chaque livraison d'une clé d'armement avec une valeur non nulle."""
    out = []
    for m in manifestes(racine):
        try:
            texte = open(m, encoding="utf-8").read()
        except OSError:
            continue
        livrees, _ = affectations_du_manifeste(texte)
        for cle in cles:
            v = livrees.get(cle, "")
            if v not in ("", "0"):
                ligne = next((i + 1 for i, l in enumerate(texte.splitlines()) if cle in l and not l.lstrip().startswith("#")), 0)
                out.append((m, ligne, cle, v))
    for e in fichiers_d_environnement(racine):
        try:
            lignes = open(e, encoding="utf-8").read().splitlines()
        except OSError:
            continue
        for i, l in enumerate(lignes):
            a = AFFECT_ENV.match(l)
            if a and a.group(1) in cles and a.group(2).strip().strip("\"'") not in ("", "0"):
                out.append((e, i + 1, a.group(1), a.group(2).strip()))
    return out


def verdict(racine):
    """(code, messages) — 0 sain, 1 défaut, 2 dérivation vide."""
    taches = taches_armables(racine)
    if not taches:
        return 2, [f"{ETIQUETTE} : AUCUNE tâche gatée par une variable PLUME_* ne se rend inerte sur un PRAGMA dans "
                   f"{os.path.join(racine, 'daemon', 'src')} — la dérivation est vide, cette garde serait INERTE. "
                   "Rien n'a été mesuré."]
    assignes = pragmas_assignes(racine)
    manquants = {cle: {(p, n) for (p, n) in pre if p not in assignes} for cle, pre in taches.items()}
    manquants = {c: p for c, p in manquants.items() if p}
    if not manquants:
        return 0, [f"{ETIQUETTE} : {len(taches)} tâche(s) armable(s), toutes leurs préconditions de PRAGMA sont posées par le code."]
    msgs = []
    for f, ligne, cle, v in armements(racine, set(manquants)):
        pre = ", ".join(f"PRAGMA {p} = {n}" for p, n in sorted(manquants[cle]))
        rel = os.path.relpath(f, racine)
        msgs.append(f"::error file={rel},line={ligne}::`{cle}={v}` arme une tâche que le démon rend inerte tant que "
                    f"{pre} — et le code n'assigne ce PRAGMA nulle part : l'armement est sans effet, désarmer (0) "
                    f"ou poser le mode dans le schéma (`{ETIQUETTE}`).")
    if msgs:
        return 1, msgs
    return 0, [f"{ETIQUETTE} : {len(taches)} tâche(s) armable(s) dont {len(manquants)} sans précondition posée — "
               "aucun fichier de déploiement ne les arme."]


RUST_TEMOIN = '''pub(crate) fn spawn_entretien(conf: HashMap<String, String>) {
        let interval: u64 = cfg(&conf, "PLUME_ENTRETIEN_INTERVAL", "0").parse().unwrap_or(0);
        if interval == 0 { return; }
        std::thread::spawn(move || {
            loop {
                let av: i64 = c.query_row("PRAGMA mode_x", [], |r| r.get(0)).unwrap_or(-1);
                if av != 2 { continue; } // inerte
            }
        });
}
'''
K3S_ARME = "        env:\n            - { name: PLUME_ENTRETIEN_INTERVAL, value: \"86400\" }\n"
K3S_DESARME = "        env:\n            - { name: PLUME_ENTRETIEN_INTERVAL, value: \"0\" }\n"
COMPOSE_DEFAUT_ARME = "services:\n  d:\n    environment:\n      PLUME_ENTRETIEN_INTERVAL: \"${PLUME_ENTRETIEN_INTERVAL:-3600}\"\n"


def arbre(base, rust, k3s=None, compose=None, env=None, pose=False):
    os.makedirs(os.path.join(base, "daemon", "src"), exist_ok=True)
    os.makedirs(os.path.join(base, "deploy"), exist_ok=True)
    open(os.path.join(base, "daemon", "src", "entretien.rs"), "w").write(rust)
    if pose:
        open(os.path.join(base, "daemon", "src", "db_open.rs"), "w").write(
            'fn ouvrir() { c.execute_batch("PRAGMA mode_x = 2;").ok(); }\n')
    if k3s is not None:
        open(os.path.join(base, "deploy", "k3s.yaml"), "w").write(k3s)
    if compose is not None:
        open(os.path.join(base, "docker-compose.yml"), "w").write(compose)
    if env is not None:
        open(os.path.join(base, ".env.example"), "w").write(env)


def temoins():
    """La garde est éprouvée dans les DEUX sens sur des arbres fabriqués, avant de lire le dépôt."""
    cas = [
        ("armé sans mode posé -> rouge", dict(k3s=K3S_ARME), 1),
        ("armé par le défaut de substitution compose -> rouge", dict(compose=COMPOSE_DEFAUT_ARME), 1),
        ("armé par le fichier d'environnement d'exemple -> rouge", dict(k3s=K3S_DESARME, env="PLUME_ENTRETIEN_INTERVAL=86400\n"), 1),
        ("désarmé -> vert", dict(k3s=K3S_DESARME, env="PLUME_ENTRETIEN_INTERVAL=0\n"), 0),
        ("armé ET mode posé par le code -> vert", dict(k3s=K3S_ARME, pose=True), 0),
    ]
    for libelle, kw, attendu in cas:
        with tempfile.TemporaryDirectory() as d:
            arbre(d, RUST_TEMOIN, **kw)
            code, _ = verdict(d)
            if code != attendu:
                print(f"::error::TÉMOIN « {libelle} » : code {code}, attendu {attendu} — la garde ne mesure pas ce qu'elle dit.")
                return False
    with tempfile.TemporaryDirectory() as d:
        arbre(d, "pub(crate) fn rien() { let x = 1; }\n", k3s=K3S_ARME)
        code, _ = verdict(d)
        if code != 2:
            print(f"::error::TÉMOIN « dérivation vide » : code {code}, attendu 2 (refus de conclure).")
            return False
    return True


def main():
    racine = racine_designee(sys.argv if len(sys.argv) > 1 else [sys.argv[0], DEPOT_DE_CETTE_GARDE])
    if not temoins():
        sys.exit(2)
    code, msgs = verdict(racine)
    for m in msgs:
        print(m)
    sys.exit(code)


if __name__ == "__main__":
    main()
