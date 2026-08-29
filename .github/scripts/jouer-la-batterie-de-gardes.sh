#!/usr/bin/env bash
# P8.27-h — LA BATTERIE DEMANDE LA PERMISSION AVANT DE PRENDRE LA MACHINE, ET SE REND VISIBLE.
#
# ┌──────────────────────────────────────────────────────────────────────────────────────────────┐
# │ CE LANCEUR SERT LE POSTE DE TRAVAIL, PAS L'INTÉGRATION. Il n'est câblé dans AUCUN flux, et il │
# │ ne doit pas l'être : là-bas chaque garde est un PAS NOMMÉ — un rouge dit lequel a échoué sans │
# │ qu'on lise un journal — et les travaux sont isolés, donc la question « la machine est-elle    │
# │ déjà prise ? » n'y a pas de sens. Ici elle en a un, et c'est tout ce que ce fichier ajoute.   │
# └──────────────────────────────────────────────────────────────────────────────────────────────┘
#
# CE QU'IL CORRIGE, ET C'ÉTAIT MOI. Jouer la batterie pendant qu'une suite de tests tourne fait
# échouer le témoin de crête mémoire : il mesure ce que la machine LUI LAISSE, et sous la charge
# d'une quarantaine de scripts concurrents les octets alloués dans sa fenêtre n'apparaissent plus.
# Le test n'est pas fautif — sous famine il REFUSE au lieu de rendre un chiffre faux. Vu QUATRE FOIS
# les 2026-08-28 et 2026-08-29, dont DEUX sur le même témoin. La règle « rien de lourd pendant une
# suite » était écrite en toutes lettres la veille de la dernière occurrence : écrire une règle ne
# l'applique pas. Le crochet de pré-commit, lui, REFUSE depuis longtemps de compter les tests si une
# construction tourne ; la batterie ne demandait rien à personne. Ce lanceur pose la MÊME question,
# à la MÊME sonde, et il est le seul chemin qui la pose pour la batterie.
#
# ET IL SE REND VISIBLE, CE QU'IL NE FAISAIT PAS — CORRIGÉ LE 2026-08-29. La batterie ne construit
# pas et n'exécute aucun binaire de `deps/` : elle était INVISIBLE aux deux signaux de la sonde,
# donc invisible à ELLE-MÊME. MESURÉ : deux lanceurs lancés à une seconde d'intervalle recevaient
# tous deux « libre » et jouaient EN MÊME TEMPS — la situation exacte que cette clé prétend fermer.
# Il PREND donc maintenant le jeton de travail lourd de la sonde, ce qui (a) exclut deux batteries
# simultanées, (b) rend la batterie visible à `compter-les-tests.sh`, et (c) referme, pour les
# outils de ce dépôt, la fenêtre entre la question et le geste.
#
# UNE GARDE À LA FOIS, EN SÉRIE, ET C'EST LE CŒUR DU CORRECTIF. La cause mesurée n'est pas qu'une
# garde soit lourde — aucune n'invoque cargo, elles n'engendrent que `git` — c'est qu'elles étaient
# une quarantaine EN MÊME TEMPS. Les jouer en série coûte plus de temps de mur et rend la machine
# prévisible ; c'est l'échange voulu.
#
# LA SONDE EST RE-POSÉE AVANT CHAQUE GARDE, PAS SEULEMENT AU DÉPART. Une suite lancée au milieu de
# la batterie est exactement le cas qui a fait mal. Le relevé coûte quelques dizaines de
# millisecondes ; la batterie s'arrête net et DIT combien de gardes n'ont pas été jouées.
# RÉSIDU NOMMÉ : la garde DÉJÀ en vol n'est pas interrompue.
#
# CE N'EST PAS UNE GARDE, ET C'EST VÉRIFIABLE PLUTÔT QUE DÉCLARÉ. La garde de câblage
# (`check_every_guard_written_is_a_guard_wired.py`) construit sa population sur le motif
# `^check_[a-z0-9_]+\.py$` du répertoire `.github/scripts/` : un `.sh` n'en fait pas partie, ni comme
# garde orpheline, ni comme garde fantôme. Ce fichier n'a donc pas à être cité dans un flux, et
# l'exiger de lui serait exiger un pas d'intégration que l'encadré ci-dessus refuse.
#
# LA POPULATION DES GARDES EST LE RÉPERTOIRE, comme pour la garde de câblage, et pour la même
# raison : une garde neuve existe sur le disque avant d'être suivie, et c'est précisément à ce
# moment-là qu'on veut la jouer. Aucune liste à tenir ici — deux listes de la même population
# finissent par diverger.
#
# CLASSER UN ROUGE : « PROPRIÉTÉ VIOLÉE » N'EST PAS « RIEN N'A ÉTÉ MESURÉ », ET LE CRITÈRE EST LE
# CODE DE SORTIE — CORRIGÉ LE 2026-08-29, C'ÉTAIT UN DÉFAUT BLOQUANT. La version précédente classait
# « refus » toute garde dont le JOURNAL contenait la formule « REFUSE DE CONCLURE », où qu'elle
# soit. Or seize gardes de ce dépôt portent cette formule, et l'une au moins l'IMPRIME SUR SON
# CHEMIN DE VIOLATION : `check_a_bench_refusal_is_a_distinct_channel.py` accuse un pas de CI de
# laisser « un banc qui REFUSE DE CONCLURE sortir par le même canal qu'une propriété violée », puis
# sort en 1. Une VRAIE propriété violée était donc BLANCHIE en « rien mesuré », et le verdict
# imprimait « AUCUNE PROPRIÉTÉ VIOLÉE » en rendant 2 au lieu de 1 — le défaut même que `P7.19-b` a
# fermé, réintroduit un étage plus haut. L'auto-épreuve d'alors ne pouvait pas l'attraper : son
# témoin ROUGE était un journal fabriqué qui ne contenait jamais la formule, si bien que les deux
# traits étaient DISJOINTS dans les témoins et COEXISTANTS dans le dépôt. Le critère est désormais
# le CODE DE SORTIE, que chaque garde déclare elle-même (`0 conforme · 1 violation · 2 l'instrument
# REFUSE DE CONCLURE`), et rien d'autre. La direction de l'erreur résiduelle est CHOISIE : une
# garde qui refuse en sortant en 1 — il y en a, c'est mesuré, et c'est une incohérence de ce dépôt,
# pas de ce fichier — est classée ROUGE, donc BRUYANTE. Jamais l'inverse : rien ne peut plus faire
# lire « aucune propriété violée » là où une propriété l'est.
# ET LA CONTRADICTION EST DITE : quand le code annonce une violation et que le texte porte la
# formule du refus, la ligne le NOMME au lieu de trancher en silence.
#
# Usage :
#   .github/scripts/jouer-la-batterie-de-gardes.sh              # joue tout, refuse si la machine est prise
#   .github/scripts/jouer-la-batterie-de-gardes.sh --attendre   # attend qu'elle se libère. Le plafond
#                                                               # (BATTERIE_ATTENTE_MAX, 900 s par
#                                                               # défaut) est GLOBAL : c'est le temps
#                                                               # total d'attente de toute la batterie,
#                                                               # pas celui de chaque garde.
#   .github/scripts/jouer-la-batterie-de-gardes.sh --forcer     # joue SANS demander : à n'employer
#                                                               # que si aucune mesure n'est en jeu
# Codes de sortie :
#   0  toutes les gardes sont vertes
#   1  au moins une PROPRIÉTÉ est violée
#   2  aucune propriété violée, mais au moins une garde a REFUSÉ DE CONCLURE
#   3  rien n'a été mesuré : la machine était prise, ou n'a pas pu être consultée
set -euo pipefail

racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
scripts="$racine/.github/scripts"

attendre=0
forcer=0
for arg in "$@"; do
    case "$arg" in
        --attendre) attendre=1 ;;
        --forcer)   forcer=1 ;;
        -h|--aide|--help)
            sed -n 's/^# \{0,1\}//p' "${BASH_SOURCE[0]}" | sed -n '/^Usage :/,/^ *3 /p'
            exit 0 ;;
        *) echo "jouer-la-batterie : option inconnue « $arg » (voir --aide)" >&2; exit 2 ;;
    esac
done

# LA DÉPENDANCE EST VÉRIFIÉE AVANT D'ÊTRE SOURCÉE, ET SON ABSENCE SORT EN 2. Sans ce contrôle,
# `set -e` sur un `source` introuvable rend le code du shell — c'est-à-dire, dans la table
# ci-dessus, « une propriété est violée » : une accusation fausse là où il faut dire « rien n'a été
# mesuré ». Le cas n'est pas théorique : ce dépôt commite par fichiers nommés (`git commit -o`), et
# un commit qui emporte l'appelant sans la sonde produit exactement cet arbre.
sonde="$scripts/sonde-construction-ou-suite-en-cours.sh"
if [ ! -r "$sonde" ]; then
    echo "jouer-la-batterie : la sonde « $sonde » est INTROUVABLE ou illisible — RIEN N'A ÉTÉ MESURÉ." >&2
    exit 2
fi
source "$sonde"

# --- LE CLASSEMENT D'UN ROUGE, ÉPROUVÉ DANS LES DEUX SENS AVANT TOUT VERDICT ---------------------
# LE CODE DE SORTIE DÉCIDE, LE TEXTE NE FAIT QUE SIGNALER UNE CONTRADICTION. Voir l'en-tête : c'est
# la correction d'un défaut BLOQUANT mesuré, où une propriété violée était blanchie en refus parce
# que son message d'accusation citait la formule du refus.
classer() {   # classer <rc> -> vert | refus | rouge
    local rc="$1"
    if [ "$rc" -eq 0 ]; then echo vert; return 0; fi
    if [ "$rc" -eq 2 ]; then echo refus; return 0; fi
    echo rouge
}

# La contradiction, DÉRIVÉE du vocabulaire des gardes et jamais d'une liste de noms : un code qui
# accuse et un texte qui refuse ne peuvent pas être vrais tous les deux.
texte_refuse() { grep -q 'REFUSE DE CONCLURE' "$1" 2>/dev/null; }

epreuve_du_classement() {
    local d j vu
    d="$(mktemp -d "${TMPDIR:-/tmp}/batterie-epreuve.XXXXXX")" || { echo "mktemp -d a échoué"; return 1; }
    j="$d/journal"

    : > "$j"
    vu="$(classer 0)"
    if [ "$vu" != vert ]; then rm -rf "$d"; echo "témoin VERT : un rc=0 est classé « $vu »"; return 1; fi

    vu="$(classer 2)"
    if [ "$vu" != refus ]; then rm -rf "$d"; echo "témoin REFUS par le code 2 : classé « $vu »"; return 1; fi

    vu="$(classer 1)"
    if [ "$vu" != rouge ]; then rm -rf "$d"; echo "témoin ROUGE : un rc=1 est classé « $vu »"; return 1; fi

    # LE TÉMOIN QUI MANQUAIT, ET QUI EST LE DÉFAUT LUI-MÊME : une garde qui ACCUSE (rc=1) en citant
    # la formule du refus dans son accusation. Elle doit rester ROUGE, et la contradiction doit être
    # VUE. Le texte est de la forme que ce dépôt emploie réellement ; aucun nom de garde n'y figure.
    printf '%s\n' "::error::flux.yml:12 — ce pas lance \`cargo test\` sans passer son journal au tri. Un banc qui REFUSE DE CONCLURE y sortirait par le même canal qu'une propriété violée." > "$j"
    vu="$(classer 1)"
    if [ "$vu" != rouge ]; then rm -rf "$d"; echo "témoin ACCUSATION-QUI-CITE-LE-REFUS : classé « $vu », une propriété violée serait BLANCHIE"; return 1; fi
    if ! texte_refuse "$j"; then rm -rf "$d"; echo "témoin ACCUSATION-QUI-CITE-LE-REFUS : la contradiction n'est pas VUE"; return 1; fi

    : > "$j"
    if texte_refuse "$j"; then rm -rf "$d"; echo "témoin SANS CONTRADICTION : une contradiction est vue là où il n'y en a pas"; return 1; fi

    rm -rf "$d"
    return 0
}

if ! faute="$(epreuve_du_classement)"; then
    echo "jouer-la-batterie : le classement des rouges est INVALIDE ($faute) — RIEN N'A ÉTÉ MESURÉ." >&2
    exit 2
fi

# --- LA POPULATION, DÉRIVÉE DU RÉPERTOIRE -------------------------------------------------------
gardes=()
while IFS= read -r g; do
    [ -n "$g" ] || continue
    gardes+=("$g")
done < <(cd "$scripts" && ls -1 | grep -E '^check_[a-z0-9_]+\.py$' | sort)

if [ "${#gardes[@]}" -eq 0 ]; then
    echo "jouer-la-batterie : AUCUNE garde trouvée dans $scripts — RIEN N'A ÉTÉ MESURÉ." >&2
    exit 2
fi

# --- LA PERMISSION ------------------------------------------------------------------------------
# LE PLAFOND EST GLOBAL, PAS PAR GARDE — CORRIGÉ LE 2026-08-29. La question est reposée avant
# chacune des 43 gardes ; en repassant le plafond entier à chaque tour, « --attendre » pouvait
# attendre 43 × 900 s, soit près de onze heures, alors que l'aide se lit comme un plafond unique.
# On calcule ici une ÉCHÉANCE, une seule fois, et chaque tour ne reçoit que ce qu'il en reste.
plafond="${BATTERIE_ATTENTE_MAX:-900}"
debut_batterie=$(date +%s)
conseils=(
    "Cette batterie ne construit rien, mais elle prend la machine :"
    "${#gardes[@]} scripts à la file lui disputent les cœurs et la mémoire."
    "Relancer après, ou « --attendre », ou « --forcer » si aucune mesure n'est en jeu."
    --
    "Cette batterie ne construit rien, mais elle prend la machine. Une suite qui"
    "mesure une crête n'y survit pas — elle REFUSE, et son rouge est illisible — et"
    "deux batteries à la fois se font exactement ce qu'on cherche à éviter."
    "Relancer après, ou « --attendre », ou « --forcer » si aucune mesure n'est en jeu."
)

demander_la_permission() {
    local rc=0 restant
    [ "$forcer" -eq 0 ] || return 0
    restant=$(( plafond - ( $(date +%s) - debut_batterie ) ))
    [ "$restant" -gt 0 ] || restant=0
    sonde_refuser_ou_attendre "jouer-la-batterie" "$attendre" "$restant" "${conseils[@]}" || rc=$?
    return "$rc"
}

if [ "$forcer" -eq 1 ]; then
    echo "jouer-la-batterie : « --forcer » — la machine n'a PAS été consultée. Toute mesure qui"
    echo "                    tourne en ce moment est susceptible d'être faussée par cette batterie."
else
    # UNE SONDE DÉSARMÉE N'EST PAS UNE MACHINE LIBRE — CORRIGÉ LE 2026-08-29. La version précédente
    # jetait ce verdict (`|| true`) puis appelait `sonde_occupation`, qui rend VIDE quand aucun
    # signal n'est utilisable : indistinguable de « libre ». MESURÉ, `PATH` privé de `flock` et de
    # `sleep` avec une suite bien en cours : deux AVEUX, puis « toutes vertes », rc=0. Un agent qui
    # lit le code de sortie en concluait que la batterie avait joué sur une machine libre. Ici, ne
    # pas pouvoir demander est « RIEN N'A ÉTÉ MESURÉ » ; « --forcer » reste l'échappatoire, et le
    # refus la nomme.
    if ! sonde_eprouver "jouer-la-batterie"; then
        echo "jouer-la-batterie : AUCUN signal utilisable — la machine n'a pas pu être CONSULTÉE," >&2
        echo "                    donc RIEN N'A ÉTÉ MESURÉ. « --forcer » joue quand même, en le disant." >&2
        exit 3
    fi
    rc_permission=0
    demander_la_permission || rc_permission=$?
    [ "$rc_permission" -eq 0 ] || exit "$rc_permission"

    # LE JETON, PRIS APRÈS LA PERMISSION ET AVANT LA PREMIÈRE GARDE. Un échec ici n'est pas un
    # incident : c'est quelqu'un qui a pris la machine dans la fenêtre entre la question et le
    # geste — précisément le résidu que ce jeton referme pour les outils de ce dépôt.
    rc_jeton=0
    sonde_jeton_prendre "jouer-la-batterie" || rc_jeton=$?
    case "$rc_jeton" in
        0) : ;;
        1) echo "jouer-la-batterie : REFUS — un autre travail lourd de ce dépôt a pris le jeton entre" >&2
           echo "                    la question et le geste ($(head -1 "$sonde_jeton" 2>/dev/null || true))." >&2
           echo "                    RIEN N'A ÉTÉ MESURÉ." >&2
           exit 3 ;;
        *) echo "jouer-la-batterie : AVEU — le jeton de travail lourd n'a pas pu être OUVERT" >&2
           echo "                    (« $sonde_jeton ») : une batterie concurrente NE SERAIT PAS VUE." >&2 ;;
    esac
fi

# --- LA BATTERIE, EN SÉRIE ----------------------------------------------------------------------
echo "jouer-la-batterie : ${#gardes[@]} gardes, EN SÉRIE, une à la fois."
journal="$(mktemp "${TMPDIR:-/tmp}/batterie.XXXXXX")"
trap 'rm -f "$journal"' EXIT

n_vert=0
rouges=()
refus=()
non_jouees=()
contradictions=()
arret=""

for i in "${!gardes[@]}"; do
    g="${gardes[$i]}"
    if [ -n "$arret" ]; then non_jouees+=("$g"); continue; fi
    if [ "$forcer" -eq 0 ]; then
        rc_permission=0
        demander_la_permission || rc_permission=$?
        if [ "$rc_permission" -ne 0 ]; then
            arret="la machine a été prise pendant la batterie"
            non_jouees+=("$g")
            continue
        fi
    fi
    debut=$(date +%s)
    rc=0
    python3 "$scripts/$g" > "$journal" 2>&1 || rc=$?
    duree=$(( $(date +%s) - debut ))
    case "$(classer "$rc")" in
        vert)  n_vert=$(( n_vert + 1 )); printf '  [%2d/%2d] %-70s OK      %3d s\n' "$(( i + 1 ))" "${#gardes[@]}" "$g" "$duree" ;;
        refus) refus+=("$g")
               printf '  [%2d/%2d] %-70s REFUSE DE CONCLURE (rc=%d) %3d s\n' "$(( i + 1 ))" "${#gardes[@]}" "$g" "$rc" "$duree"
               sed 's/^/          /' "$journal" ;;
        rouge) rouges+=("$g")
               if texte_refuse "$journal"; then
                   contradictions+=("$g")
                   printf '  [%2d/%2d] %-70s ROUGE (rc=%d, ET SON TEXTE DIT « REFUSE DE CONCLURE ») %3d s\n' "$(( i + 1 ))" "${#gardes[@]}" "$g" "$rc" "$duree"
               else
                   printf '  [%2d/%2d] %-70s ROUGE (rc=%d) %3d s\n' "$(( i + 1 ))" "${#gardes[@]}" "$g" "$rc" "$duree"
               fi
               sed 's/^/          /' "$journal" ;;
    esac
done

# --- LE VERDICT ---------------------------------------------------------------------------------
echo
echo "jouer-la-batterie : ${n_vert} verte(s), ${#rouges[@]} rouge(s), ${#refus[@]} qui refuse(nt) de conclure, ${#non_jouees[@]} non jouée(s)."
for g in ${rouges[@]+"${rouges[@]}"};      do echo "    ROUGE               $g"; done
for g in ${refus[@]+"${refus[@]}"};        do echo "    REFUSE DE CONCLURE  $g"; done
for g in ${non_jouees[@]+"${non_jouees[@]}"}; do echo "    NON JOUÉE           $g"; done

# LA CONTRADICTION EST DITE, PAS TRANCHÉE EN SILENCE. Le code de sortie décide (voir l'en-tête) ;
# ce paragraphe existe pour que personne n'aille chercher un défaut sans savoir que la garde
# elle-même se contredit.
if [ "${#contradictions[@]}" -ne 0 ]; then
    echo
    echo "jouer-la-batterie : ${#contradictions[@]} garde(s) SE CONTREDISENT — leur code annonce une propriété"
    echo "                    violée et leur texte dit « REFUSE DE CONCLURE ». Elles sont comptées ROUGES"
    echo "                    parce qu'un refus lu comme un vert est le pire des deux sens ; lisez leur"
    echo "                    journal avant de chercher un défaut."
    for g in "${contradictions[@]}"; do echo "    SE CONTREDIT        $g"; done
fi

if [ -n "$arret" ]; then
    echo "jouer-la-batterie : ARRÊT — $arret. ${#non_jouees[@]} garde(s) NON MESURÉE(S)." >&2
    exit 3
fi
if [ "${#rouges[@]}" -ne 0 ]; then
    echo "jouer-la-batterie : au moins une PROPRIÉTÉ est violée." >&2
    exit 1
fi
if [ "${#refus[@]}" -ne 0 ]; then
    echo "jouer-la-batterie : aucune propriété violée, mais ${#refus[@]} garde(s) n'ont RIEN MESURÉ." >&2
    exit 2
fi
echo "jouer-la-batterie : toutes vertes."
