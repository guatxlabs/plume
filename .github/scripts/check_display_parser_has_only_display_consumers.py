#!/usr/bin/env python3
"""`P4.7-g` — L'ANALYSEUR DU RENDU D'AFFICHAGE N'A QUE DES CONSOMMATEURS D'AFFICHAGE.

LE DÉFAUT, ET CE N'ÉTAIT PAS UN OUBLI. `parse_excl_item` répond à DEUX questions dont les bonnes
réponses DIFFÈRENT :
  (Q_affichage)   « comment rendre cette exclusion en `NOT LIKE 'préfixe%'` / en terme soql
                  `champ!=val*` ? » — pour laquelle un PRÉFIXE TEXTUEL est la BONNE réponse, et même
                  la SEULE qui se rende en SQL ;
  (Q_enforcement) « cette adresse appartient-elle à l'ensemble protégé ? » — pour laquelle c'est la
                  mauvaise, et l'écart va DANS LES DEUX SENS (mesuré : `172.16.0.0/12` protégeait
                  tout 172/8, `128.0.0.0/1` une SEULE adresse, `fc00::/7` laissait échapper fd00::/8).
La sémantique de chaîne est HÉRITÉE du rendu SQL. Le remède n'est donc PAS de remplacer l'analyseur —
« analyser les deux côtés en valeurs » CASSERAIT le débruitage des panneaux — c'est de SÉPARER LES
DEUX CONSOMMATEURS. Le fichier avait déjà fait la moitié du travail en séparant la SOURCE éditable
(invariant §4 : l'override d'affichage ne pilote JAMAIS l'enforcement) ; il manquait la moitié
SYNTAXIQUE, et c'est elle que cette garde tient.

ÉTAT MESURÉ AVANT LE LOT : QUATRE appels d'enforcement — `daemon/src/ledger.rs` (x2, la denylist
never-ban) et `daemon/src/handlers/engagement.rs` (x2, le scope d'exemption de pentest). La garde
était donc ROUGE avant, elle est VERTE après.

POPULATION DÉCOUVERTE, JAMAIS ÉNUMÉRÉE : tous les appels de l'analyseur d'affichage, trouvés par
parcours. Le MODULE D'AFFICHAGE lui-même est DÉRIVÉ — c'est le fichier qui définit `ExclClauses`,
la structure des clauses de panneau — et non un chemin écrit ici.

CE QUE CETTE GARDE NE PROUVE PAS, ÉCRIT DANS SON PROPRE EN-TÊTE : elle tient la SÉPARATION
SYNTAXIQUE des deux politiques, RIEN de plus. Elle ne dit rien des comparaisons d'adresse par chaîne
qui subsistent ailleurs — la corrélation, la détection et le tier froid tranchent TOUJOURS l'identité
sur la chaîne, et une garde syntaxique ne sait pas distinguer une comparaison d'IDENTITÉ (deux
écritures, la même machine) d'une comparaison de FIDÉLITÉ (une valeur a-t-elle survécu à un
aller-retour Parquet). Mesuré le 2026-08-28 : une telle garde rendait 31 sites dont 25 légitimes, et
la resserrer laissait 3 sites dont 2 sont un contrôle de fidélité. La séparer de l'identité aurait
demandé une LISTE DE FICHIERS, c'est-à-dire une énumération. La garde SANS angle mort de cette
famille est le TYPE : `protected_ip_matchers()` et les matchers d'engagement rendent `(IpAddr, u32)`,
donc `starts_with` y est INÉCRIVABLE pour tout consommateur présent et futur, sans qu'aucun soit nommé.

Codes de sortie : 0 conforme · 1 violation · 2 l'instrument REFUSE DE CONCLURE.
"""
import os, re, sys

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.realpath(os.path.join(ICI, "..", ".."))

ANALYSEUR = "parse_excl_item"
DEF = re.compile(r"fn\s+" + ANALYSEUR + r"\s*\(")
APPEL = re.compile(r"\b" + ANALYSEUR + r"\s*\(")
# Le module d'AFFICHAGE est DÉRIVÉ : c'est celui qui porte la structure des clauses de panneau.
MARQUE_AFFICHAGE = re.compile(r"struct\s+ExclClauses\b")


def sans_bruit(ligne):
    l = re.sub(r'"(?:[^"\\]|\\.)*"', ' "" ', ligne)
    l = re.sub(r"//.*$", "", l)
    return l


def fichiers_rust():
    out = []
    for base, _, noms in os.walk(os.path.join(RACINE, "daemon", "src")):
        for n in sorted(noms):
            if n.endswith(".rs"):
                out.append(os.path.join(base, n))
    return sorted(out)


def est_un_test(chemin):
    rel = os.path.relpath(chemin, RACINE)
    return (os.sep + "tests" + os.sep) in (os.sep + rel) or rel.endswith("tests.rs")


def epreuves():
    """TÉMOINS POSITIF ET NÉGATIF sur l'apparieur, hors du disque."""
    if not APPEL.search("if let Some(m) = parse_excl_item(item) { v.push(m); }"):
        return "témoin POSITIF : un appel de l'analyseur n'est pas apparié"
    if not DEF.search("pub(crate) fn parse_excl_item(raw: &str) -> Option<(String, bool)> {"):
        return "témoin POSITIF : la définition de l'analyseur n'est pas appariée"
    if APPEL.search(sans_bruit('let doc = "voir parse_excl_item(x) dans la doc";')):
        return "témoin NÉGATIF : un littéral de chaîne entre dans la population"
    if APPEL.search(sans_bruit("// parse_excl_item(x) est l'analyseur d'affichage")):
        return "témoin NÉGATIF : un commentaire entre dans la population"
    if not MARQUE_AFFICHAGE.search("pub(crate) struct ExclClauses {"):
        return "témoin POSITIF : le module d'affichage n'est plus dérivable"
    return None


def main():
    faute = epreuves()
    if faute:
        print(f"::error::instrument INVALIDE, la garde REFUSE DE CONCLURE — {faute}", file=sys.stderr)
        return 2

    fichiers = fichiers_rust()
    if not fichiers:
        print("::error::aucun source Rust lisible — la garde REFUSE DE CONCLURE", file=sys.stderr)
        return 2

    defini_dans, affichage, appels = None, None, []
    for f in fichiers:
        texte = open(f, encoding="utf-8").read()
        if DEF.search(texte):
            defini_dans = f
        if MARQUE_AFFICHAGE.search(texte):
            affichage = f
        for i, brute in enumerate(texte.split("\n"), 1):
            ligne = sans_bruit(brute)
            if DEF.search(ligne):
                continue  # la définition n'est pas un appel
            if APPEL.search(ligne):
                appels.append((f, i, brute.strip()[:120]))

    # --- VALIDATION DE L'INSTRUMENT SUR L'ARBRE ---
    if defini_dans is None:
        print(f"::error::`{ANALYSEUR}` introuvable : l'analyseur d'affichage a disparu ou changé de nom, "
              f"la garde REFUSE DE CONCLURE", file=sys.stderr)
        return 2
    if affichage is None:
        print("::error::`struct ExclClauses` introuvable : le module d'AFFICHAGE n'est plus dérivable, "
              "la garde REFUSE DE CONCLURE", file=sys.stderr)
        return 2
    if defini_dans != affichage:
        print(f"::error::`{ANALYSEUR}` ({os.path.relpath(defini_dans, RACINE)}) ne vit plus dans le module "
              f"d'affichage ({os.path.relpath(affichage, RACINE)}) — la garde REFUSE DE CONCLURE",
              file=sys.stderr)
        return 2
    legitimes = [a for a in appels if a[0] == affichage]
    if not legitimes:
        print(f"::error::AUCUN appel d'affichage de `{ANALYSEUR}` trouvé dans "
              f"{os.path.relpath(affichage, RACINE)} : la garde ne regarde plus au bon endroit, "
              f"elle REFUSE DE CONCLURE", file=sys.stderr)
        return 2

    violations = [a for a in appels if a[0] != affichage and not est_un_test(a[0])]
    if violations:
        for (f, i, txt) in violations:
            print(f"::error file={os.path.relpath(f, RACINE)},line={i}::`{ANALYSEUR}` est l'analyseur du RENDU "
                  f"D'AFFICHAGE (préfixe TEXTUEL) — un consommateur d'ENFORCEMENT doit passer par "
                  f"`parse_protected_item` (réseaux typés) : {txt}", file=sys.stderr)
        print(f"analyseur d'affichage : {len(violations)} consommateur(s) d'enforcement sur "
              f"{len(appels)} appel(s) trouvé(s)", file=sys.stderr)
        return 1

    tests = [a for a in appels if est_un_test(a[0])]
    print(f"analyseur d'affichage : OK — {len(legitimes)} appel(s) d'affichage dans "
          f"{os.path.relpath(affichage, RACINE)}, {len(tests)} dans les témoins, 0 en enforcement.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
