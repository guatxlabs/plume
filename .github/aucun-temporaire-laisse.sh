#!/usr/bin/env bash
# P7.1-a — GARDE MESURABLE : une suite de tests ne laisse RIEN derrière elle.
#
# MESURÉ le 2026-08-03 sur `01a5cf0`, avant correction : la suite daemon laissait
# 136 fichiers / 38,4 Mio PAR EXÉCUTION, dont 53 `-wal` + 53 `-shm` ORPHELINS — les
# fixtures effaçaient le chemin qu'elles avaient NOMMÉ, et SQLite en crée deux autres
# à côté que personne n'avait nommés. La correction POSSÈDE le répertoire contenant
# (`daemon/src/tmp_possede.rs`) ; ce script est la garde qui empêche le retour du trou.
#
# ⚠ LA GARDE LIT $TMPDIR, JAMAIS `/tmp` EN DUR. C'est le piège exact qui a failli faire
# conclure « pas de fuite » : mesurer `/tmp` alors qu'on détourne soi-même $TMPDIR
# renvoie zéro quoi qu'il arrive. Le job cold_tier de cette même CI détourne $TMPDIR —
# une garde codée en dur y serait verte en permanence, sans jamais rien vérifier.
#
# ─────────────────────────────────────────────────────────────────────────────────────
# `P8.9-m` — CE SCRIPT NOMMAIT UN JUMEAU SANS Y ÊTRE CÂBLÉ. La ligne juste au-dessus cite
# le job cold_tier depuis toujours ; MESURÉ le 2026-08-30, ce script n'était appelé qu'à UN
# seul endroit — après la suite par défaut du démon — sur les SIX pas qui lancent `cargo
# test` dans cette CI (démon par défaut, démon cold_tier, démon s3_backup, collector-syslog,
# collector-mail, et `agent` dans agent-ci.yml). L'auteur avait donc pensé au jumeau et ne
# l'avait pas branché : la garde P7.1-a ne couvrait qu'un sixième de ce qu'elle décrit.
#
# CE QUI EST CÂBLÉ DEPUIS, ET POURQUOI PAS LE RESTE — la décision est mesurée, pas frileuse.
#   · CÂBLÉ : les TROIS pas du démon (défaut, cold_tier, s3_backup). C'est la caisse qui
#     POSSÈDE ses temporaires (`daemon/src/tmp_possede.rs`, la correction même de P7.1-a),
#     les trois pas exportent déjà un $TMPDIR ISOLÉ (`$RUNNER_TEMP/plume-tmp-*`), et le
#     mécanisme est déjà prouvé vert par le pas par défaut. Mesurer les deux autres profils
#     ne pose aucun cliquet sur du code non mesuré : c'est le MÊME code de test.
#   · PAS CÂBLÉ, collector-syslog / collector-mail / agent : ces caisses n'ont PAS la
#     discipline de possession. RELEVÉ le 2026-08-30 — huit sites y créent un temporaire
#     `plume-*` nettoyé en FIN DE CORPS (`let _ = remove_dir_all(...)`) et non par un `Drop` :
#     collector-syslog/src/spool.rs:46, collector-syslog/src/main.rs:798,
#     agent/src/source/generic.rs:591 et :627, agent/src/source/fim/tests.rs:332, :382, :628,
#     agent/src/{durable,buffer,ship}.rs. Un test qui panique y laisse son résidu. Câbler la
#     garde là-bas AVANT de porter `tmp_possede` dans ces caisses poserait un cliquet sur du
#     code que ce lot n'a pas le droit de corriger, et dont personne n'a mesuré la sortie.
#   · PAS CÂBLABLE TEL QUEL dans agent-ci.yml : ce workflow tourne en matrice
#     ubuntu/windows/macOS, et `find -printf` est une extension GNU que le `find` de macOS
#     n'a pas. Le pas échouerait sur deux jambes sur trois pour une raison qui n'a RIEN à voir
#     avec un résidu : une garde qui accuse à tort est pire que l'angle mort qu'elle comble.
#
# Usage : aucun-temporaire-laisse.sh "<nom de la suite>"   (à lancer DANS le step de test,
#         pour hériter du même $TMPDIR que la suite qu'on vient de faire tourner).
#         aucun-temporaire-laisse.sh --verifier-le-cablage
#         (ne mesure aucun temporaire : vérifie que le câblage ci-dessus ne peut pas être
#          défait en silence. Sorties : 0 = sain, 1 = un pas non câblé, 2 = refus de conclure.)
set -euo pipefail

# ══════════════════════════════════════════════════════════════════════════════════════
# MODE « CÂBLAGE » — `P8.9-m`. LE CÂBLAGE DE CETTE GARDE NE DOIT PAS POUVOIR SE DÉFAIRE
# EN SILENCE. Le défaut mesuré n'était pas que le script soit faux : c'est qu'il n'était
# APPELÉ qu'à un pas sur six, et rien ne le disait. Une garde dont le branchement est un
# geste à la main dans un YAML se débranche le jour où l'on ajoute un pas.
#
# LA POPULATION EST DÉRIVÉE DEUX FOIS, JAMAIS ÉCRITE :
#   · les pas qui lancent une suite : tout `cargo test …` en TÊTE DE COMMANDE dans un
#     fichier de `.github/workflows/` (nu, ou derrière `run:`) ;
#   · les caisses qui DOIVENT prouver leur absence de résidu : celles qui portent
#     `src/tmp_possede.rs`, c'est-à-dire celles qui ont pris l'engagement de POSSÉDER
#     leurs temporaires (la correction de P7.1-a). Aujourd'hui : `daemon`, et elle seule.
#     Une caisse qui adopte `tmp_possede` demain entre par construction, sans édition ici.
#
# CE QUE CE MODE NE VOIT PAS, dit plutôt que caché : un `cargo test` écrit ailleurs qu'en
# tête de commande (après `&&`, dans un sous-shell, derrière une variable) lui échappe.
# C'est un faux NÉGATIF, jamais une accusation à tort — et le plancher ci-dessous rougit
# si la reconnaissance se dégrade au point de ne plus rien trouver.
# ══════════════════════════════════════════════════════════════════════════════════════

pas_qui_lancent_une_suite() {
    # Rend une ligne par pas qui lance une suite : `<fichier>:<ligne>\t<caisse>\t<CABLE|NU>`.
    local fichier="$1"
    local etiquette="${2:-$1}"
    awk -v F="$etiquette" '
        function vider() {
            if (cmd > 0)
                printf "%s:%d\t%s\t%s\n", F, cmd, (wd == "" ? "(racine)" : wd), (cable ? "CABLE" : "NU")
            cmd = 0; wd = ""; cable = 0
        }
        # Un nouveau pas commence : on clôt le précédent AVANT de lire cette ligne.
        /^[ \t]*-[ \t]*(name:|uses:|run:|\{)/ { vider() }
        {
            nu = $0; sub(/^[ \t]*/, "", nu)
            if (nu ~ /^#/) next                     # une commande CITEE en commentaire nest pas une commande
            if (nu ~ /^working-directory:[ \t]*/) { wd = nu; sub(/^working-directory:[ \t]*/, "", wd) }
            c = nu; sub(/^run:[ \t]*/, "", c)       # `run: cargo test …` comme `cargo test …` nu
            if (c ~ /^cargo[ \t]+test([ \t]|$)/) cmd = FNR
            if (nu ~ /aucun-temporaire-laisse\.sh/) cable = 1
        }
        END { vider() }
    ' "$fichier"
}

verifier_le_cablage() {
    local racine
    racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

    # ── L'INSTRUMENT SE VALIDE SUR UNE ENTRÉE FABRIQUÉE ICI, avant de juger l'arbre. Une
    #    reconnaissance cassée rendrait « rien à signaler » et serait indiscernable d'un vrai 0.
    local bac temoin vu attendu
    bac="$(mktemp -d)"
    trap 'rm -rf "${bac}"' RETURN
    temoin="${bac}/temoin.yml"
    cat > "${temoin}" <<'FABRIQUE'
jobs:
  x:
    steps:
      - name: un pas CÂBLÉ
        working-directory: caisse-a
        run: |
          cargo test --locked
          "$GITHUB_WORKSPACE/.github/aucun-temporaire-laisse.sh" "sa suite"
      - name: un pas NU
        working-directory: caisse-b
        run: |
          cargo test --features x
      - name: cargo test cité dans un NOM de pas, mais non lancé
        run: echo "je ne lance rien"
      - name: un pas dont le cargo test est en COMMENTAIRE
        run: |
          # cargo test --locked  (et .github/aucun-temporaire-laisse.sh cité aussi)
          echo rien
      - name: forme `run:` sur une seule ligne, NUE
        working-directory: caisse-c
        run: cargo test --locked
FABRIQUE
    vu="$(pas_qui_lancent_une_suite "${temoin}" | awk -F'\t' '{print $2 "=" $3}' | paste -sd, -)"
    attendu="caisse-a=CABLE,caisse-b=NU,caisse-c=NU"
    if [ "${vu}" != "${attendu}" ]; then
        echo "::error::[câblage] INSTRUMENT CASSÉ — sur une entrée FABRIQUÉE il lit « ${vu} »"
        echo "::error::[câblage] au lieu de « ${attendu} ». Il ne sait plus reconnaître ni un pas de"
        echo "::error::[câblage] suite ni son câblage : son verdict sur l'arbre ne vaudrait rien."
        return 2
    fi
    echo "   contrôle positif : OK (la reconnaissance lit juste sur une entrée fabriquée)"

    # ── LES CAISSES QUI ONT PRIS L'ENGAGEMENT, DÉRIVÉES.
    local caisses
    caisses="$(cd "${racine}" && find . -mindepth 3 -maxdepth 3 -path './*/src/tmp_possede.rs' \
               -printf '%h\n' 2>/dev/null | sed 's|^\./||; s|/src$||' | sort -u)"
    if [ -z "${caisses}" ]; then
        echo "::error::[câblage] aucune caisse ne porte \`src/tmp_possede.rs\` : soit la discipline de"
        echo "::error::[câblage] possession a disparu, soit la découverte est cassée. Refus de conclure."
        return 2
    fi
    echo "   caisses qui doivent prouver leur absence de résidu (dérivées de src/tmp_possede.rs) :"
    echo "${caisses}" | sed 's/^/     /'

    # ── LA MESURE.
    local pas total cables nus rc
    pas=""
    for f in "${racine}"/.github/workflows/*.yml "${racine}"/.github/workflows/*.yaml; do
        [ -e "${f}" ] || continue
        # Le chemin annoncé est RELATIF À LA RACINE, dérivée de la position de ce script : une
        # annotation GitHub portant un chemin absolu ne désigne aucun fichier chez le lecteur, et un
        # chemin de machine dans un instrument est le défaut que `P11.21-d` a fermé ailleurs.
        pas="${pas}$(pas_qui_lancent_une_suite "${f}" "${f#"${racine}"/}")
"
    done
    pas="$(printf '%s' "${pas}" | sed '/^$/d')"
    total="$(printf '%s\n' "${pas}" | sed '/^$/d' | wc -l)"
    cables="$(printf '%s\n' "${pas}" | grep -c 'CABLE$' || true)"
    if [ "${total}" -lt 4 ]; then
        echo "::error::[câblage] ${total} pas de suite reconnus dans les workflows, plancher 4"
        echo "::error::[câblage] (MESURÉ le 2026-08-30 : 6). La reconnaissance s'est dégradée — refus de conclure."
        return 2
    fi
    if [ "${cables}" -lt 1 ]; then
        echo "::error::[câblage] aucun pas câblé reconnu : le motif d'appel ne correspond plus."
        echo "::error::[câblage] Un « tout est nu » d'un instrument aveugle ne vaut rien. Refus de conclure."
        return 2
    fi
    echo "   ${total} pas lancent une suite, ${cables} appellent cette garde :"
    printf '%s\n' "${pas}" | sed 's/^/     /'

    rc=0
    while IFS=$'\t' read -r ou caisse etat; do
        [ -n "${ou}" ] || continue
        [ "${etat}" = "NU" ] || continue
        if printf '%s\n' "${caisses}" | grep -qx -- "${caisse}"; then
            echo "::error file=${ou%%:*},line=${ou##*:}::[câblage] ce pas lance une suite de \`${caisse}\`,"
            echo "::error::une caisse qui a pris l'engagement de POSSÉDER ses temporaires"
            echo "::error::(\`${caisse}/src/tmp_possede.rs\`), et il ne le PROUVE pas : ajouter, à la fin du"
            echo "::error::même \`run:\` — pour hériter du même \$TMPDIR que la suite —"
            echo "::error::  \"\$GITHUB_WORKSPACE/.github/aucun-temporaire-laisse.sh\" \"<nom de la suite>\""
            rc=1
        else
            echo "   (hors portée, dit et non caché) ${ou} — caisse \`${caisse}\` : pas de"
            echo "   \`${caisse}/src/tmp_possede.rs\`, donc pas d'engagement de possession à prouver."
            echo "   Porter \`tmp_possede\` dans cette caisse ARME ce pas automatiquement."
        fi
    done <<< "${pas}"

    if [ "${rc}" -eq 0 ]; then
        echo "   câblage : sain — chaque suite d'une caisse qui possède ses temporaires le prouve"
    fi
    return "${rc}"
}

if [ "${1:-}" = "--verifier-le-cablage" ]; then
    echo "── garde « aucun temporaire laissé » — vérification du CÂBLAGE (P8.9-m)"
    verifier_le_cablage
    exit $?
fi

suite="${1:-suite}"
: "${TMPDIR:=/tmp}"
motif='plume-*'

echo "── garde « aucun temporaire laissé » — ${suite}"
echo "   TMPDIR observé : ${TMPDIR}"

# `-mindepth 1` N'EST PAS UN DETAIL. Sans lui, `find <rep>` rend AUSSI le repertoire
# lui-meme, et le job nomme son TMPDIR avec le prefixe que ce motif cherche : la garde se
# comptait donc elle-meme comme residu, a chaque execution. Le defaut est reste invisible
# tant qu'un echec anterieur empechait d'atteindre cette etape.
#
# ET LE CONTROLE POSITIF CHERCHE SON TEMOIN PAR SON NOM, au lieu de compter les
# correspondances : le comptage le faisait passer grace au meme faux positif, si bien que
# l'instrument se validait avec le defaut qu'il devait justement exclure.
# VALIDER L'INSTRUMENT AVANT DE CROIRE SA SORTIE. Sans contrôle positif, un « 0 » d'une
# sonde cassée (mauvais chemin, mauvais motif, find muet) est indiscernable d'un vrai 0.
temoin="${TMPDIR}/plume-temoin-instrument-$$"
: > "${temoin}"
vus=$(find "${TMPDIR}" -mindepth 1 -maxdepth 1 -name "$(basename "${temoin}")" | wc -l)
rm -f "${temoin}"
if [ "${vus}" -lt 1 ]; then
  echo "::error::sonde CASSÉE : elle ne voit pas son propre témoin dans ${TMPDIR} — le résultat ne veut rien dire"
  exit 1
fi
echo "   contrôle positif : OK (la sonde voit ce qu'elle doit voir)"

# LA MESURE.
restes=$(find "${TMPDIR}" -mindepth 1 -maxdepth 1 -name "${motif}" | wc -l)
if [ "${restes}" -ne 0 ]; then
  octets=$(find "${TMPDIR}" -mindepth 1 -maxdepth 1 -name "${motif}" -printf '%s\n' | awk '{s+=$1} END{print s+0}')
  echo "::error::${suite} : ${restes} temporaire(s) laissé(s) dans \$TMPDIR (${octets} octets) — attendu 0"
  echo "::error::un temporaire de test doit être POSSÉDÉ (daemon/src/tmp_possede.rs) : il naît dans un"
  echo "::error::répertoire à lui, effacé récursivement à la destruction du garde — sidecars compris."
  find "${TMPDIR}" -mindepth 1 -maxdepth 1 -name "${motif}" -printf '  %10s  %f\n' | sort -k2 | head -40
  exit 1
fi
echo "   résidu : 0 — ${suite} ne laisse rien derrière elle"
