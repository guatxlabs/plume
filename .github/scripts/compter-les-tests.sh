#!/usr/bin/env bash
# P8.5-a — LE COMPTE DE TESTS, MESURÉ EN QUELQUES SECONDES AU LIEU DE 47 MINUTES.
# P8.9-e — ET CE SCRIPT DIT QU'IL CONSTRUIT, PARCE QU'IL CONSTRUIT.
#
# ┌──────────────────────────────────────────────────────────────────────────────────────────────┐
# │ CE SCRIPT COMPILE. Il n'EXÉCUTE aucun test — c'est vrai, et ce n'est pas ce qui compte : pour │
# │ ÉNUMÉRER les tests il demande à cargo de CONSTRUIRE le harnais. Il prend donc le verrou du    │
# │ répertoire d'artefacts, il consomme de la mémoire et des cœurs, et sur un `target/` froid son │
# │ coût est celui d'une construction complète.                                                   │
# └──────────────────────────────────────────────────────────────────────────────────────────────┘
#
# POURQUOI CET ENCADRÉ EXISTE (P8.9-e, trouvé le 2026-08-25). L'en-tête précédent disait vrai —
# « il ne LANCE aucun test » — et laissait croire autre chose : que le script était en LECTURE. Un
# lot à qui la compilation était interdite l'a lancé en croyant ne rien construire. Une phrase vraie
# qui laisse croire le contraire est exactement la famille de défaut que ce dépôt poursuit ; la
# correction n'est pas de retirer la phrase, c'est de dire ce que le script COÛTE avant de dire ce
# qu'il ne fait pas. La même phrase est donc imprimée à l'exécution, AVANT le premier appel à cargo.
#
# CE QUE ÇA COÛTE, RE-MESURÉ LE 2026-08-27 (12 cœurs, `target/` déjà peuplé, cargo 1.97.0) :
#     rien n'a changé dans l'arbre        : 1 s pour les DEUX suites
#     un fichier de `daemon/src/` touché  : 17 s pour `--defaut`, 34 s pour les deux suites
#     `target/` froid (clone frais)       : une CONSTRUCTION COMPLÈTE — non mesurée ici, mais c'est
#                                           l'ordre de grandeur d'un `cargo build` de zéro.
# LE CHIFFRE QUI CIRCULAIT — « 2 s » — EST MESURÉ DANS L'ÉTAT OÙ LE CROCHET DE PRÉ-COMMIT NE TOMBE
# PRESQUE JAMAIS : le crochet ne se déclenche QUE si le commit touche `daemon/src/`, `daemon/Cargo.*`
# ou le compteur dans `ci.yml`. Des trois, seul le dernier laisse `target/` intact. Le cas courant du
# crochet est donc 17 s ou 34 s, pas 2 s.
# RÉFUTÉ le 2026-08-27, et c'était écrit ici : « les deux profils se chassent mutuellement du même
# target/ ». Ils ne se chassent pas — cargo garde une empreinte et des artefacts DISTINCTS par jeu de
# features, et les deux énumérations se sont enchaînées en 1 s au total sur un arbre inchangé. Le
# coût réel n'est pas une bascule de profil, c'est la recompilation de ce qui a changé.
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
# POURQUOI CE SCRIPT RESTE UTILISABLE ALORS QUE LES SUITES NE LE SONT PAS. Construire le harnais et
# l'énumérer coûte une compilation ; l'EXÉCUTER coûte, MESURÉ le 2026-08-09 sur 12 cœurs, 187 s
# (profil par défaut) + 2627 s (`cold_tier`), soit ~47 min. Un garde à 34 s se subit ; un garde à
# 47 min se contourne. Le gain est réel — il n'est simplement pas gratuit, et ce n'est pas la même
# chose.
#
# CE QU'IL NE PROUVE PAS, ET IL FAUT LE DIRE : que les tests PASSENT. Il compte des tests DÉCLARÉS,
# pas des tests verts. C'est exactement ce que la garde de `ci.yml` compare (un compte), et c'est
# tout ce que celle-ci prétend faire ici ; la CI, elle, continue de les EXÉCUTER.
#
# UNE SEULE CONSTRUCTION À LA FOIS — CE QUE CE SCRIPT FAIT DÉSORMAIS AVANT DE CONSTRUIRE.
# Cargo sérialise les constructions par un verrou `flock` sur le répertoire d'artefacts. MESURÉ le
# 2026-08-27, verrou tenu par un autre processus : `cargo test -- --list` écrit UNE ligne sur
# stderr — « Blocking waiting for file lock on artifact directory » — puis attend sans limite. Or ce
# script redirigeait stderr vers `/dev/null` : il restait donc MUET ET FIGÉ, sans que rien ne dise
# pourquoi. Deux corrections : (1) le verrou est SONDÉ avant de construire, et le script REFUSE
# (`--attendre` pour attendre à la place) plutôt que de mettre une seconde construction en file ;
# (2) stderr n'est plus jeté — ce que cargo a dit est rendu, y compris la ligne d'attente.
# RÉSIDU NOMMÉ, ET IL EST INHÉRENT : entre la sonde et la prise du verrou par cargo il reste une
# fenêtre. Si une construction s'y glisse, cargo attend — et cette fois la ligne d'attente est
# rendue au lieu d'être avalée. La sonde réduit la fenêtre, elle ne l'annule pas.
#
# SOURCE UNIQUE : les deux attentes sont LUES dans `.github/workflows/ci.yml`. Les recopier ici
# aurait recréé exactement le défaut que `ci.yml` a fermé en n'écrivant `EXPECTED_TESTS` qu'une fois.
#
# Usage :
#   .github/scripts/compter-les-tests.sh              # les deux suites
#   .github/scripts/compter-les-tests.sh --defaut     # la suite par défaut seule (le cas rapide)
#   .github/scripts/compter-les-tests.sh --attendre   # attendre une construction en cours au lieu
#                                                     # de refuser (plafond : COMPTER_ATTENTE_MAX,
#                                                     # 900 s par défaut)
# Codes de sortie :
#   0  aucun écart          1  dérive du compte
#   2  rien n'a été mesuré (format inattendu, cargo en échec)
#   3  rien n'a été mesuré : une construction était déjà en cours
set -euo pipefail

racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ci="$racine/.github/workflows/ci.yml"
[ -f "$ci" ] || { echo "compter-les-tests : $ci introuvable" >&2; exit 2; }

les_deux_suites=1
attendre=0
for arg in "$@"; do
    case "$arg" in
        --defaut)   les_deux_suites=0 ;;
        --attendre) attendre=1 ;;
        -h|--aide|--help)
            sed -n 's/^# \{0,1\}//p' "${BASH_SOURCE[0]}" | sed -n '/^Usage :/,/^ *3 /p'
            exit 0 ;;
        *) echo "compter-les-tests : option inconnue « $arg » (voir --aide)" >&2; exit 2 ;;
    esac
done

# --- LES ATTENTES, LUES À LA SOURCE -------------------------------------------------------------
attendu_defaut="$(sed -n 's/^ *EXPECTED_TESTS: *"\([0-9]\+\)".*/\1/p' "$ci" | head -1)"
attendu_cold="$(sed -n 's/^ *EXPECTED_COLD_TESTS: *"\([0-9]\+\)".*/\1/p' "$ci" | head -1)"
# VALIDATION DE L'INSTRUMENT DE LECTURE : un filtre qui ne rend rien se lit « je n'ai pas mesuré ».
[ -n "$attendu_defaut" ] || { echo "compter-les-tests : EXPECTED_TESTS introuvable dans $ci — le format a changé, ce script mentirait" >&2; exit 2; }
[ -n "$attendu_cold" ]   || { echo "compter-les-tests : EXPECTED_COLD_TESTS introuvable dans $ci — le format a changé, ce script mentirait" >&2; exit 2; }

# --- LA SONDE DE CONSTRUCTION CONCURRENTE -------------------------------------------------------
# DÉRIVÉE, PAS ÉNUMÉRÉE : cargo pose un `.cargo-lock` dans le répertoire d'artefacts de CHAQUE
# profil qu'il a déjà construit. On lit ceux qui EXISTENT, sans en créer aucun — sonder un verrou
# absent le ferait naître, et un profil jamais construit ne porte par définition aucune
# construction en cours.
cible="${CARGO_TARGET_DIR:-$racine/daemon/target}"

verrous_existants() {
    [ -d "$cible" ] || return 0
    find "$cible" -maxdepth 3 -name .cargo-lock -type f 2>/dev/null
}

verrou_tenu() { ! flock -n "$1" -c true 9>&- 2>/dev/null; }

# VALIDATION DE L'INSTRUMENT, DANS LES DEUX SENS, À CHAQUE EXÉCUTION. Une sonde qui rendrait
# toujours « libre » laisserait passer exactement ce qu'elle prétend arrêter, et son silence se
# lirait comme une garantie. On la met donc à l'épreuve sur un verrou jetable : libre, elle doit
# dire libre ; tenu, elle doit dire tenu.
epreuve_de_la_sonde() {
    local t
    t="$(mktemp "${TMPDIR:-/tmp}/compter-les-tests.sonde.XXXXXX")" || { echo "mktemp a échoué"; return 1; }
    if verrou_tenu "$t"; then rm -f "$t"; echo "témoin NÉGATIF : un verrou LIBRE est vu tenu"; return 1; fi
    exec 9>"$t"
    if ! flock -n 9 2>/dev/null; then exec 9>&-; rm -f "$t"; echo "témoin POSITIF : le verrou jetable n'a pas pu être pris"; return 1; fi
    if ! verrou_tenu "$t"; then exec 9>&-; rm -f "$t"; echo "témoin POSITIF : un verrou TENU est vu libre"; return 1; fi
    exec 9>&-
    rm -f "$t"
    return 0
}

sonde_utilisable=0
if ! command -v flock >/dev/null 2>&1; then
    echo "compter-les-tests : AVEU — « flock » est absent, la présence d'une construction concurrente" >&2
    echo "                    N'A PAS ÉTÉ VÉRIFIÉE. Ce script va construire ; si une construction" >&2
    echo "                    tourne déjà, cargo attendra sans limite." >&2
elif faute="$(epreuve_de_la_sonde)"; then
    sonde_utilisable=1
else
    echo "compter-les-tests : AVEU — la sonde de verrou est INVALIDE ($faute), la présence d'une" >&2
    echo "                    construction concurrente N'A PAS ÉTÉ VÉRIFIÉE." >&2
fi

if [ "$sonde_utilisable" -eq 1 ]; then
    occupe=""
    while IFS= read -r v; do
        [ -n "$v" ] || continue
        if verrou_tenu "$v"; then occupe="$v"; break; fi
    done < <(verrous_existants)

    if [ -n "$occupe" ]; then
        if [ "$attendre" -eq 0 ]; then
            echo "compter-les-tests : REFUS — une construction tient déjà « $occupe »." >&2
            echo "                    Ce script CONSTRUIT ; en lancer une seconde mettrait les deux en" >&2
            echo "                    file sur le même répertoire d'artefacts. RIEN N'A ÉTÉ MESURÉ." >&2
            echo "                    Relancer après, ou « --attendre », ou « git commit --no-verify »." >&2
            exit 3
        fi
        plafond="${COMPTER_ATTENTE_MAX:-900}"
        debut=$(date +%s)
        tour=0
        echo "compter-les-tests : une construction tient « $occupe » — attente (plafond ${plafond} s)."
        while verrou_tenu "$occupe"; do
            sleep 5
            tour=$(( tour + 1 ))
            ecoule=$(( $(date +%s) - debut ))
            if [ "$ecoule" -ge "$plafond" ]; then
                echo "compter-les-tests : ${ecoule} s d'attente, plafond atteint — RIEN N'A ÉTÉ MESURÉ." >&2
                exit 3
            fi
            # Une attente muette se lit comme un blocage : on donne signe de vie toutes les ~30 s.
            if [ $(( tour % 6 )) -eq 0 ]; then echo "compter-les-tests : toujours en attente depuis ${ecoule} s…"; fi
        done
        echo "compter-les-tests : verrou libéré après $(( $(date +%s) - debut )) s."
    fi
fi

# --- LE COMPTE ----------------------------------------------------------------------------------
# `cargo test -- --list` CONSTRUIT le harnais puis imprime une ligne « <chemin::du::test>: test »
# par test, puis un pied « N tests, 0 benchmarks ». On compte les lignes ET on relit le pied : deux
# lectures indépendantes de la même sortie, qui doivent coïncider. Si elles divergent, le format a
# changé et le compte ne vaut rien — on le DIT au lieu de rendre un nombre inventé.
compter() {
    local libelle="$1"; shift
    local sortie journal
    journal="$(mktemp "${TMPDIR:-/tmp}/compter-les-tests.cargo.XXXXXX")"
    if ! sortie="$(cd "$racine/daemon" && cargo test --offline --locked "$@" -- --list 2>"$journal")"; then
        echo "compter-les-tests : 'cargo test -- --list' a échoué pour la suite $libelle (construction ?)" >&2
        # STDERR N'EST PLUS JETÉ : c'est là que cargo écrit et l'erreur, et l'attente sur le verrou.
        sed 's/^/      cargo: /' "$journal" >&2
        rm -f "$journal"
        return 2
    fi
    # Même en cas de succès, une ATTENTE sur le verrou doit être dite : elle signifie qu'une seconde
    # construction s'est glissée dans la fenêtre laissée par la sonde.
    if grep -qi 'waiting for file lock' "$journal"; then
        grep -i 'waiting for file lock' "$journal" | sed 's/^ *//; s/^/      cargo: /' >&2
        echo "      (une construction concurrente s'est glissée après la sonde — l'attente a eu lieu)" >&2
    fi
    rm -f "$journal"
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

# CE QU'IL FAIT, DIT AVANT DE LE FAIRE — pas après, et pas seulement dans l'en-tête.
echo "compter-les-tests : CE SCRIPT CONSTRUIT. Aucun test n'est EXÉCUTÉ, mais les ÉNUMÉRER demande à"
echo "                    cargo de compiler le harnais : verrou du répertoire d'artefacts pris, cœurs"
echo "                    et mémoire consommés. Mesuré le 2026-08-27 (12 cœurs) : 1 s si rien n'a"
echo "                    changé, 17 s après un fichier de daemon/src/ touché (--defaut), 34 s pour"
echo "                    les deux suites ; sur un target/ froid, une construction complète."
echo "compte de tests DÉCLARÉS :"
n="$(compter "défaut" )" || exit 2
verdict "défaut   " "$n" "$attendu_defaut" "EXPECTED_TESTS"

if [ "$les_deux_suites" -eq 1 ]; then
    n="$(compter "cold_tier" --features cold_tier)" || exit 2
    verdict "cold_tier" "$n" "$attendu_cold" "EXPECTED_COLD_TESTS"
fi

if [ "$ecart" -ne 0 ]; then
    echo "compter-les-tests : DÉRIVE — la CI refusera ce commit (elle exécute vraiment les suites)." >&2
    exit 1
fi
echo "compter-les-tests : aucun écart."
