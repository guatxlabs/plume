#!/usr/bin/env python3
"""Aucune version RETIRÉE (yanked) dans daemon/Cargo.lock, hors l'ensemble NOMMÉ des exceptions admises.

POURQUOI CETTE GARDE EXISTE. `cargo audit --deny warnings` refuse un crate retiré, et c'est voulu : une version
retirée par son auteur est un signal de chaîne d'approvisionnement. Mais `cargo-audit` n'admet AUCUNE exception
par crate pour ce contrôle — seulement `[yanked] enabled = false`, qui l'éteint pour TOUS. Le 2026-10-16,
l'amont de `zip` a retiré toutes ses versions sauf la dernière, sans motif publié, et `libduckdb-sys` (feature
`duckdb`, désactivée par défaut, dépendance de BUILD) exige `zip ^6` dans toutes ses versions : la mise à jour
est impossible. Décision de l'exploitant (2026-10-16) : couper le contrôle dans `daemon/.cargo/audit.toml`,
justifié et daté, ET le rejouer ici avec une exception NOMMÉE — pour qu'un AUTRE crate retiré ne passe jamais
en silence.

COMMENT. `cargo-audit` lit sa configuration dans le `.cargo/audit.toml` du répertoire COURANT. Lancé depuis la
racine du dépôt avec `-f daemon/Cargo.lock`, il juge donc le verrou du démon SANS le relevé. La garde lit la
sortie JSON (`warnings.yanked`) et compare à l'ensemble admis, dans les deux sens :
  * un crate retiré hors de l'ensemble -> ROUGE (rc 1) ;
  * une exception qui n'est plus retirée ou plus dans le verrou -> ROUGE (« EXEMPTION SANS OBJET ») : il faut
    alors retirer l'entrée ET rallumer le contrôle dans `daemon/.cargo/audit.toml`.
Les AVIS de sécurité (RUSTSEC) ne sont pas jugés ici : `cargo audit --deny warnings` les juge toujours, avec
la configuration du démon.

REFUSE DE CONCLURE (rc 2) — jamais un vert : `cargo-audit` absent, sortie illisible, champ `warnings` absent,
ou un `.cargo/audit.toml` à la RACINE (il pourrait éteindre le contrôle que cette garde rejoue).

CE QU'ELLE NE TIENT PAS : elle a besoin de l'index de crates.io et de la base d'avis (réseau) ; elle ne lit que
`daemon/Cargo.lock` (les verrous des crates collector-* ont leur propre audit) ; elle ne dit pas POURQUOI un
crate a été retiré — l'amont ne le publie pas toujours.
"""
import json
import os
import subprocess
import sys

RACINE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
VERROU = "daemon/Cargo.lock"

# (crate, version) -> raison ÉCRITE, date et condition de levée. Toute entrée est une dette : elle se retire
# dès que sa condition est remplie, et la garde rougit si elle reste alors qu'elle n'a plus d'objet.
ADMIS = {
    ("zip", "6.0.0"): (
        "dépendance de BUILD de libduckdb-sys (feature `duckdb`, OFF par défaut, jamais compilée en prod) ; "
        "toutes les versions de libduckdb-sys exigent zip ^6 et 6.0.0 est la seule 6.x ; retirée en amont le "
        "2026-10-16 sans motif publié. Lever quand libduckdb-sys accepte zip >= 9 ou qu'une 6.x non retirée paraît."
    ),
}


def retires_du_rapport(rapport):
    """L'ensemble (crate, version) des versions retirées que rapporte un JSON de cargo-audit, ou None."""
    if not isinstance(rapport, dict) or not isinstance(rapport.get("warnings"), dict):
        return None
    vus = set()
    for w in rapport["warnings"].get("yanked", []) or []:
        p = (w or {}).get("package") or {}
        if isinstance(p.get("name"), str) and isinstance(p.get("version"), str):
            vus.add((p["name"], p["version"]))
        else:
            return None
    return vus


def juger(retires, admis):
    """(hors_ensemble, sans_objet) : deux listes triées, vides si tout est en ordre."""
    return sorted(retires - set(admis)), sorted(set(admis) - retires)


def epreuves():
    """L'instrument éprouvé dans les deux sens sur des rapports FABRIQUÉS, à chaque exécution."""
    admis = {("zip", "6.0.0"): "x"}
    sain = {"warnings": {"yanked": [{"package": {"name": "zip", "version": "6.0.0"}}]}}
    assert juger(retires_du_rapport(sain), admis) == ([], []), "un rapport sain doit passer"
    neuf = {"warnings": {"yanked": [{"package": {"name": "zip", "version": "6.0.0"}},
                                    {"package": {"name": "serde", "version": "1.0.0"}}]}}
    assert juger(retires_du_rapport(neuf), admis) == ([("serde", "1.0.0")], []), "un crate retiré neuf doit rougir"
    vide = {"warnings": {"yanked": []}}
    assert juger(retires_du_rapport(vide), admis) == ([], [("zip", "6.0.0")]), "une exception sans objet doit rougir"
    assert retires_du_rapport({"vulnerabilities": {}}) is None, "un rapport sans `warnings` ne conclut pas"
    assert retires_du_rapport({"warnings": {"yanked": [{"package": {}}]}}) is None, "une entrée informe ne conclut pas"


def main():
    epreuves()
    if os.path.exists(os.path.join(RACINE, ".cargo", "audit.toml")):
        print("::error::REFUSE DE CONCLURE : un .cargo/audit.toml existe à la racine du dépôt — il pourrait "
              "éteindre le contrôle que cette garde rejoue.")
        return 2
    try:
        sortie = subprocess.run(["cargo", "audit", "-f", VERROU, "--json"], cwd=RACINE,
                                capture_output=True, text=True, timeout=600)
    except (OSError, subprocess.TimeoutExpired) as e:
        print(f"::error::REFUSE DE CONCLURE : cargo-audit n'a pas pu tourner ({e}).")
        return 2
    try:
        rapport = json.loads(sortie.stdout)
    except ValueError:
        print(f"::error::REFUSE DE CONCLURE : sortie de cargo-audit illisible (code {sortie.returncode}) : "
              f"{(sortie.stderr or sortie.stdout)[-400:]}")
        return 2
    retires = retires_du_rapport(rapport)
    if retires is None:
        print("::error::REFUSE DE CONCLURE : le rapport de cargo-audit ne porte pas `warnings.yanked` lisible.")
        return 2
    hors, sans_objet = juger(retires, ADMIS)
    rc = 0
    for nom, version in hors:
        print(f"::error::VERSION RETIRÉE hors de l'ensemble admis : {nom} {version} — mettre à jour, ou l'admettre "
              "NOMMÉMENT dans ADMIS avec sa raison, sa date et sa condition de levée.")
        rc = 1
    for nom, version in sans_objet:
        print(f"::error::EXEMPTION SANS OBJET : {nom} {version} n'est plus retiré ou plus dans {VERROU} — retirer "
              "l'entrée d'ADMIS et rallumer le contrôle des versions retirées dans daemon/.cargo/audit.toml.")
        rc = 1
    if rc == 0:
        admis = ", ".join(f"{n} {v}" for n, v in sorted(ADMIS))
        print(f"check_only_the_admitted_crates_are_yanked : {len(retires)} version(s) retirée(s) dans {VERROU}, "
              f"toutes admises nommément ({admis or 'aucune'}) ; instrument éprouvé dans les deux sens.")
    return rc


if __name__ == "__main__":
    sys.exit(main())
