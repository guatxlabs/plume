#!/usr/bin/env bash
# P8.5-a — LE COMPTE DE TESTS, MESURÉ EN 2 SECONDES AU LIEU DE 47 MINUTES.
#
# CE QU'ON A CRU, ET CE QUI EST VRAI. Le commit `8618753` (2026-08-08) a consigné que la garde
# `EXPECTED_TESTS` de `ci.yml` « ne s'exécute qu'à l'ouverture d'une PR », et que pousser
# directement sur `main` la laissait donc endormie. C'EST FAUX, et c'est vérifiable dans le dépôt :
# `ci.yml` porte `on: push: branches: ["**"]` DEPUIS SA CRÉATION (le bloc `on:` n'a jamais été
# modifié — `git log -p --follow .github/workflows/ci.yml` ne montre qu'UNE apparition, dans le
# commit qui crée le fichier), et `git rev-list --count github/main..main` vaut 0 : tout est poussé.
# La garde a donc BIEN tourné sur chaque push, et elle a BIEN vu la dérive 937 -> 945.
#
# LE VRAI TROU N'EST PAS LE DÉCLENCHEUR, C'EST LA BOUCLE DE RETOUR : le résultat arrive sur une page
# GitHub qu'on ne lit pas au moment où l'on commite. Aucun déclencheur supplémentaire ne peut fermer
# ça — un `push` de plus produirait le même rouge, au même endroit, ignoré de la même façon. Il faut
# que la mesure revienne LÀ où la décision se prend : la machine, avant le commit.
#
# POURQUOI CE SCRIPT EST UTILISABLE ALORS QUE LES SUITES NE LE SONT PAS. Il ne LANCE aucun test : il
# demande au harnais d'ÉNUMÉRER les siens (`cargo test -- --list`). MESURÉ le 2026-08-09 sur cette
# machine (12 cœurs) :
#     lancer les deux suites  : 187 s (défaut) + 2627 s (cold_tier)  = ~47 min
#     énumérer les deux       : ~2 s à chaud, jusqu'à ~46 s si le répertoire `target/` doit
#                               rebasculer d'un jeu de features à l'autre (les deux profils se
#                               chassent mutuellement du même `target/` ; la CI l'évite avec deux
#                               runners et deux caches).
# Un garde à 2 secondes se subit ; un garde à 47 minutes se contourne.
#
# CE QU'IL NE PROUVE PAS, ET IL FAUT LE DIRE : que les tests PASSENT. Il compte des tests DÉCLARÉS,
# pas des tests verts. C'est exactement ce que la garde de `ci.yml` compare (un compte), et c'est
# tout ce que celle-ci prétend faire ici ; la CI, elle, continue de les EXÉCUTER.
#
# SOURCE UNIQUE : les deux attentes sont LUES dans `.github/workflows/ci.yml`. Les recopier ici
# aurait recréé exactement le défaut que `ci.yml` a fermé en n'écrivant `EXPECTED_TESTS` qu'une fois.
#
# Usage :
#   .github/scripts/compter-les-tests.sh              # les deux suites
#   .github/scripts/compter-les-tests.sh --defaut     # la suite par défaut seule (le cas rapide)
set -euo pipefail

racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ci="$racine/.github/workflows/ci.yml"
[ -f "$ci" ] || { echo "compter-les-tests : $ci introuvable" >&2; exit 2; }

# --- LES ATTENTES, LUES À LA SOURCE -------------------------------------------------------------
attendu_defaut="$(sed -n 's/^ *EXPECTED_TESTS: *"\([0-9]\+\)".*/\1/p' "$ci" | head -1)"
attendu_cold="$(sed -n 's/^ *EXPECTED_COLD_TESTS: *"\([0-9]\+\)".*/\1/p' "$ci" | head -1)"
# VALIDATION DE L'INSTRUMENT DE LECTURE : un filtre qui ne rend rien se lit « je n'ai pas mesuré ».
[ -n "$attendu_defaut" ] || { echo "compter-les-tests : EXPECTED_TESTS introuvable dans $ci — le format a changé, ce script mentirait" >&2; exit 2; }
[ -n "$attendu_cold" ]   || { echo "compter-les-tests : EXPECTED_COLD_TESTS introuvable dans $ci — le format a changé, ce script mentirait" >&2; exit 2; }

# --- LE COMPTE ----------------------------------------------------------------------------------
# `cargo test -- --list` imprime une ligne « <chemin::du::test>: test » par test, puis un pied
# « N tests, 0 benchmarks ». On compte les lignes ET on relit le pied : deux lectures indépendantes
# de la même sortie, qui doivent coïncider. Si elles divergent, le format a changé et le compte ne
# vaut rien — on le DIT au lieu de rendre un nombre inventé.
compter() {
    local libelle="$1"; shift
    local sortie
    if ! sortie="$(cd "$racine/daemon" && cargo test --offline --locked "$@" -- --list 2>/dev/null)"; then
        echo "compter-les-tests : 'cargo test -- --list' a échoué pour la suite $libelle (compilation ?)" >&2
        return 2
    fi
    local n_lignes n_pied
    n_lignes="$(printf '%s\n' "$sortie" | grep -c ': test$' || true)"
    n_pied="$(printf '%s\n' "$sortie" | sed -n 's/^\([0-9]\+\) tests, [0-9]\+ benchmarks$/\1/p' | tail -1)"
    if [ -z "$n_pied" ] || [ "$n_lignes" != "$n_pied" ]; then
        echo "compter-les-tests : les deux lectures divergent pour $libelle (lignes=$n_lignes, pied=${n_pied:-absent}) — format inattendu, aucun verdict rendu" >&2
        return 2
    fi
    printf '%s' "$n_lignes"
}

ecart=0
verdict() {
    local libelle="$1" obtenu="$2" attendu="$3" ou="$4"
    if [ "$obtenu" = "$attendu" ]; then
        echo "  $libelle : $obtenu tests (attendu $attendu) — OK"
    else
        echo "  $libelle : $obtenu tests, ATTENDU $attendu — DÉRIVE de $((obtenu - attendu))"
        echo "      -> si le changement ajoute/retire légitimement des tests, mettez $ou à jour"
        echo "         dans .github/workflows/ci.yml, DEPUIS VOTRE PROPRE MESURE, et nulle part ailleurs."
        ecart=1
    fi
}

echo "compte de tests DÉCLARÉS (aucun test n'est exécuté) :"
n="$(compter "défaut" )" || exit 2
verdict "défaut   " "$n" "$attendu_defaut" "EXPECTED_TESTS"

if [ "${1:-}" != "--defaut" ]; then
    n="$(compter "cold_tier" --features cold_tier)" || exit 2
    verdict "cold_tier" "$n" "$attendu_cold" "EXPECTED_COLD_TESTS"
fi

if [ "$ecart" -ne 0 ]; then
    echo "compter-les-tests : DÉRIVE — la CI refusera ce commit (elle exécute vraiment les suites)." >&2
    exit 1
fi
echo "compter-les-tests : aucun écart."
