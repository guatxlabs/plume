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
# ET RIEN PENDANT UNE SUITE (`P8.27-h`, 2026-08-29). Le verrou d'artefacts ne dit RIEN d'une suite
# en cours : MESURÉ sur une suite complète, vingt-deux relevés à dix secondes d'intervalle, il est
# LIBRE du premier au dernier. Compiler pendant qu'une suite tourne lui dispute les cœurs et la
# mémoire, et fait échouer les témoins qui mesurent une crête — le test refuse alors de conclure,
# ce qui est son bon comportement et un rouge illisible pour qui l'a provoqué. La sonde porte donc
# maintenant TROIS signaux — construction, suite en cours, et un JETON de travail lourd que ce
# script PREND pour rendre sa propre construction visible aux autres outils du dépôt — et ce script
# refuse sur les trois.
#
# SOURCE UNIQUE : les deux attentes sont LUES dans `.github/workflows/ci.yml`. Les recopier ici
# aurait recréé exactement le défaut que `ci.yml` a fermé en n'écrivant `EXPECTED_TESTS` qu'une fois.
#
# Usage :
#   .github/scripts/compter-les-tests.sh              # les deux suites
#   .github/scripts/compter-les-tests.sh --defaut     # la suite par défaut seule (le cas rapide)
#   .github/scripts/compter-les-tests.sh --attendre   # attendre que la machine se libère au lieu
#                                                     # de refuser (plafond : COMPTER_ATTENTE_MAX,
#                                                     # 900 s par défaut)
#   COMPTER_ATTENDRE=1 git commit …                   # LA MÊME CHOSE DEPUIS LE CROCHET. Git ne
#                                                     # passe AUCUN argument à un pre-commit : sans
#                                                     # cette porte, le crochet annonçait un
#                                                     # « --attendre » qu'aucun geste `git commit`
#                                                     # ne pouvait fournir (mesuré le 2026-08-29).
# Codes de sortie :
#   0  aucun écart          1  dérive du compte
#   2  rien n'a été mesuré (format inattendu, cargo en échec)
#   3  rien n'a été mesuré : une construction, une suite de tests, ou un autre travail lourd de ce
#      dépôt était déjà en cours
set -euo pipefail

# `pwd -P` : la sonde compare ce chemin à ce que rend `/proc/<pid>/exe`, qui est PHYSIQUE. Un
# chemin logique (dépôt atteint par un lien symbolique) rendait la sonde muette — mesuré.
racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
ci="$racine/.github/workflows/ci.yml"
[ -f "$ci" ] || { echo "compter-les-tests : $ci introuvable" >&2; exit 2; }

les_deux_suites=1
# LA PORTE D'ENVIRONNEMENT EXISTE PARCE QUE LE CROCHET NE PEUT PAS PASSER D'ARGUMENT. Git n'en
# passe aucun à un `pre-commit`, et le crochet appelle ce script par `exec` sans `"$@"` : la ligne
# « « --attendre » attend à la place » qu'il imprimait ne désignait donc AUCUN geste faisable
# depuis `git commit`. Mesuré le 2026-08-29. Une variable d'environnement, elle, traverse.
attendre=0
# Un `if`, pas une liste `&&` : sous `set -e`, « [ … ] && x=1 » dont le test est FAUX fait sortir
# le shell — le script mourrait silencieusement chaque fois que la porte n'est PAS ouverte.
if [ "${COMPTER_ATTENDRE:-0}" = 1 ]; then attendre=1; fi
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

# --- LA SONDE : « LA MACHINE EST-ELLE DÉJÀ PRISE ? » SOURCÉE, PAS RECOPIÉE ---------------------
# ELLE VIVAIT ICI ; ELLE VIT MAINTENANT À CÔTÉ, ET C'EST LA MÊME. Le corps de la sonde de verrou —
# la dérivation des `.cargo-lock` existants, le test de prise, et son épreuve dans les deux sens —
# a été DÉPLACÉ tel quel dans `sonde-construction-ou-suite-en-cours.sh` : mêmes octets, empreinte
# vérifiée. Il n'en reste AUCUNE copie ici. Deux définitions de la même question finissent par
# diverger, et c'est le défaut que ce dépôt trouve tous les jours.
#
# ET ELLE A GAGNÉ UN SECOND SIGNAL, QUI CONCERNE CE SCRIPT AUTANT QUE L'AUTRE APPELANT : une SUITE
# DE TESTS en cours. Le verrou d'artefacts ne le dit pas — MESURÉ, il est LIBRE pendant TOUTE
# l'exécution d'une suite, cargo ne le tenant que pendant qu'il CONSTRUIT. Or construire pendant
# qu'une suite tourne lui dispute les cœurs et la mémoire, et fait échouer les témoins qui mesurent
# une crête : c'est le même appauvrissement que celui qui a fondé `P8.27-h`, vu par l'autre bout.
# Ce script REFUSE donc désormais aussi dans ce cas-là, avec le même « --attendre » pour l'autre
# choix.
#
# LA DÉPENDANCE EST VÉRIFIÉE AVANT D'ÊTRE SOURCÉE, ET SON ABSENCE SORT EN 2 — CORRIGÉ LE
# 2026-08-29. Sous `set -e`, un `source` introuvable rend le code du shell, soit **1** : dans la
# table ci-dessus, « dérive du compte ». C'était une accusation FAUSSE là où il fallait dire « rien
# n'a été mesuré », et c'est exactement la distinction que ce lot a été écrit pour établir. Le cas
# n'est pas théorique : ce dépôt commite par fichiers nommés (`git commit -o`), et un commit qui
# emporte ce script sans la sonde produit un arbre où CHAQUE commit du démon est bloqué par un
# message bash brut.
sonde="$racine/.github/scripts/sonde-construction-ou-suite-en-cours.sh"
if [ ! -r "$sonde" ]; then
    echo "compter-les-tests : la sonde « $sonde » est INTROUVABLE ou illisible — RIEN N'A ÉTÉ MESURÉ." >&2
    exit 2
fi
source "$sonde"

# Un signal qui ne s'éprouve pas est DÉSARMÉ et son absence est DITE ; on continue quand même, comme
# avant — ce script n'est pas une frontière, c'est une boucle de retour.
sonde_eprouver "compter-les-tests" || true

# L'AVEU DIT AUSSI SA CONSÉQUENCE, ET C'EST L'APPELANT QUI LA CONNAÎT. `HEAD` disait, quand `flock`
# manquait : « Ce script va construire ; si une construction tourne déjà, cargo attendra sans
# limite. » Le déplacement de la sonde avait PERDU cette troisième ligne — celle qui disait ce qui
# allait ARRIVER à l'opérateur —, et le rapport de pose affirmait le contraire. Elle est rétablie
# ici, où elle est vraie, et elle couvre désormais les DEUX causes de désarmement, pas seulement
# l'absence de `flock`.
if [ "$sonde_construction_utilisable" -eq 0 ]; then
    echo "                    Ce script va construire ; si une construction tourne déjà, cargo" >&2
    echo "                    attendra sans limite." >&2
fi
if [ "$sonde_execution_utilisable" -eq 0 ]; then
    echo "                    Ce script va construire ; si une suite tourne déjà, il lui disputera" >&2
    echo "                    les cœurs et la mémoire, et faussera ses témoins de crête." >&2
fi

rc_sonde=0
sonde_refuser_ou_attendre "compter-les-tests" "$attendre" "${COMPTER_ATTENTE_MAX:-900}" \
    "Ce script CONSTRUIT ; en lancer une seconde mettrait les deux en" \
    "file sur le même répertoire d'artefacts. RIEN N'A ÉTÉ MESURÉ." \
    "Relancer après, ou « --attendre », ou « git commit --no-verify »." \
    -- \
    "Ce script CONSTRUIT ; compiler pendant une suite lui dispute les cœurs" \
    "et la mémoire, et fausse les témoins de crête. RIEN N'A ÉTÉ MESURÉ." \
    "Relancer après, ou « --attendre », ou « git commit --no-verify »." || rc_sonde=$?
[ "$rc_sonde" -eq 0 ] || exit "$rc_sonde"

# LE JETON DE TRAVAIL LOURD, PRIS AVANT DE CONSTRUIRE. Il rend cette construction VISIBLE à la
# batterie de gardes (qui ne construit pas et n'exécutait donc aucun signal), et il referme la
# fenêtre entre la question et le geste pour les outils de ce dépôt qui le prennent. Un échec de
# prise n'est pas un incident : c'est quelqu'un qui s'est glissé dans cette fenêtre.
rc_jeton=0
sonde_jeton_prendre "compter-les-tests" || rc_jeton=$?
case "$rc_jeton" in
    0) : ;;
    1) echo "compter-les-tests : REFUS — un autre travail lourd de ce dépôt a pris le jeton entre la" >&2
       echo "                    question et le geste ($(head -1 "$sonde_jeton" 2>/dev/null || true))." >&2
       echo "                    RIEN N'A ÉTÉ MESURÉ." >&2
       exit 3 ;;
    *) echo "compter-les-tests : AVEU — le jeton de travail lourd n'a pas pu être OUVERT" >&2
       echo "                    (« $sonde_jeton ») : cette construction reste INVISIBLE aux autres outils." >&2 ;;
esac


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
