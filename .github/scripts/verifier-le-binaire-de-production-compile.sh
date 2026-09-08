#!/usr/bin/env bash
# verifier-le-binaire-de-production-compile.sh — LE BINAIRE DE PRODUCTION COMPILE, HORS cfg(test).
#
# CE QUI S'EST PASSÉ (2026-09-08, P8.5-d). Une fonction de production, `server::premiere_attente_derivee`,
# consommait deux symboles (`classify_backup_name`, `ParsedBackup`) que la façade `backup` ne réexportait
# que sous `#[cfg(test)]`. La suite par défaut (1 563 verts), la suite froide (verte en CI) et le crochet
# de pré-commit — qui ne construit que le HARNAIS DE TESTS pour l'énumérer — ont tous vu un arbre qui
# compile. Le binaire de production, lui, ne compilait pas : `cargo build --release` a rougi sur le nœud
# (porte de déploiement, au bout d’un build complet) puis dans la CI (E0425/E0433). RIEN, sur le poste, ne compilait
# jamais le démon hors cfg(test) : la suite verte n'est pas un témoin de ce que la production construit.
#
# CE QUE CE SCRIPT FAIT. `cargo check --offline --locked --features <jeu de production>` depuis `daemon/` :
# la compilation du binaire SANS le cfg `test`, avec le jeu de features que l'image de production
# construit. Ce jeu n'est PAS écrit ici : il est LU dans le `Dockerfile` (`ARG PLUME_FEATURES=…`), la
# seule ligne qui décide de ce que la production compile. Si elle disparaît ou change de forme, le
# script REFUSE DE CONCLURE (2) plutôt que de vérifier un jeu inventé.
#
# CE QU'IL COÛTE. Un `cargo check` ne génère pas de code : peu de mémoire. Première exécution sur un
# clone : les métadonnées de toutes les dépendances (quelques minutes) ; ensuite, quelques secondes sur
# un arbre peu changé. Il prend le même verrou d'artefacts que le comptage et passe par la MÊME sonde :
# il REFUSE (3) si une construction ou une suite de tests tourne déjà, et dit laquelle.
#
# CODES DE SORTIE :
#   0  le binaire de production compile
#   1  il ne compile pas — le texte de cargo est rendu (erreurs et imports inutilisés hors test)
#   2  rien n'a été mesuré (Dockerfile sans `ARG PLUME_FEATURES=`, sonde introuvable, cargo en panne
#      pour une raison qui n'est pas une erreur de compilation)
#   3  refus : une construction ou une suite tourne déjà
#
#   COMPTER_ATTENDRE=1  — attendre l'occupation au lieu de refuser (le même levier que le comptage,
#                         puisque le crochet enchaîne les deux et que git ne lui passe aucun argument).
set -u

moi="verifier-le-binaire-de-production"
racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

dockerfile="$racine/Dockerfile"
features="$(sed -n 's/^ARG PLUME_FEATURES=\(.*\)$/\1/p' "$dockerfile" 2>/dev/null | head -1)"
if [ -z "$features" ]; then
    echo "$moi : « ARG PLUME_FEATURES=… » introuvable dans $dockerfile — le jeu de features de production" >&2
    echo "$moi   n'est pas dérivable, ce script vérifierait un jeu inventé. RIEN N'A ÉTÉ MESURÉ." >&2
    exit 2
fi

sonde="$racine/.github/scripts/sonde-construction-ou-suite-en-cours.sh"
if [ ! -r "$sonde" ]; then
    echo "$moi : la sonde « $sonde » est INTROUVABLE ou illisible — RIEN N'A ÉTÉ MESURÉ." >&2
    exit 2
fi
# shellcheck source=sonde-construction-ou-suite-en-cours.sh
source "$sonde"

attendre=0
[ "${COMPTER_ATTENDRE:-0}" = 1 ] && attendre=1

sonde_eprouver "$moi" || true
rc_sonde=0
sonde_refuser_ou_attendre "$moi" "$attendre" "${COMPTER_ATTENTE_MAX:-900}" \
    "Ce script CONSTRUIT (métadonnées) ; en lancer un second mettrait les deux en" \
    "file sur le même répertoire d'artefacts. RIEN N'A ÉTÉ MESURÉ." \
    "Relancer après, ou COMPTER_ATTENDRE=1, ou « git commit --no-verify »." \
    -- \
    "Ce script CONSTRUIT ; compiler pendant une suite lui dispute les cœurs" \
    "et la mémoire, et fausse les témoins de crête. RIEN N'A ÉTÉ MESURÉ." \
    "Relancer après, ou COMPTER_ATTENDRE=1, ou « git commit --no-verify »." || rc_sonde=$?
[ "$rc_sonde" -eq 0 ] || exit "$rc_sonde"

rc_jeton=0
sonde_jeton_prendre "$moi" || rc_jeton=$?
case "$rc_jeton" in
    0) : ;;
    1) echo "$moi : REFUS — un autre travail lourd de ce dépôt a pris le jeton entre la question et" >&2
       echo "$moi   le geste ($(head -1 "$sonde_jeton" 2>/dev/null || true)). RIEN N'A ÉTÉ MESURÉ." >&2
       exit 3 ;;
    *) echo "$moi : AVEU — le jeton de travail lourd n'a pas pu être OUVERT (« $sonde_jeton ») :" >&2
       echo "$moi   cette construction reste INVISIBLE aux autres outils." >&2 ;;
esac

journal="$(mktemp "${TMPDIR:-/tmp}/$moi.XXXXXX")" || { echo "$moi : mktemp impossible — RIEN N'A ÉTÉ MESURÉ." >&2; exit 2; }
trap 'rm -f "$journal"' EXIT

echo "$moi : cargo check hors cfg(test), features de production « $features » (lues dans Dockerfile)…"
rc_cargo=0
(cd "$racine/daemon" && cargo check --offline --locked --features "$features") >"$journal" 2>&1 || rc_cargo=$?

if [ "$rc_cargo" -eq 0 ]; then
    # Un import qui n'existe qu'en test et que la production ne consomme plus est la MÊME famille de
    # défaut, à l'envers : il est rendu, mais il ne rougit pas — cargo ne le compte pas comme une erreur.
    inutiles="$(grep -c '^warning: unused import' "$journal" || true)"
    echo "$moi : le binaire de production COMPILE (features « $features »${inutiles:+, $inutiles import(s) inutilisé(s) hors test})."
    exit 0
fi
if grep -qE '^error(\[E[0-9]+\])?: ' "$journal"; then
    echo "$moi : le binaire de PRODUCTION NE COMPILE PAS (features « $features », cargo $rc_cargo)." >&2
    echo "$moi   La suite de tests peut être verte : elle compile sous cfg(test), pas la production." >&2
    grep -nE -A4 '^error(\[E[0-9]+\])?: ' "$journal" | head -80 >&2
    exit 1
fi
echo "$moi : cargo a échoué (code $rc_cargo) SANS erreur de compilation — RIEN N'A ÉTÉ MESURÉ :" >&2
tail -20 "$journal" >&2
exit 2
