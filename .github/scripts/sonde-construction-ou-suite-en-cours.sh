#!/usr/bin/env bash
# P8.27-h — LA MACHINE EST-ELLE DÉJÀ PRISE ? UNE SEULE RÉPONSE, POUR TOUS CEUX QUI LA DEMANDENT.
#
# ┌──────────────────────────────────────────────────────────────────────────────────────────────┐
# │ CE FICHIER NE FAIT RIEN TOUT SEUL. Il se SOURCE. Il porte TROIS signaux — une construction    │
# │ cargo, une SUITE DE TESTS en cours, un TRAVAIL LOURD déclaré par un outil de ce dépôt — et il │
# │ s'éprouve DANS LES DEUX SENS à chaque exécution avant de rendre le moindre verdict.           │
# └──────────────────────────────────────────────────────────────────────────────────────────────┘
#
# POURQUOI IL EXISTE. Le crochet de pré-commit REFUSE de compter les tests si une construction
# tourne déjà ; la batterie de gardes, elle, ne demandait la permission à personne. Jouée pendant
# une suite de tests, une quarantaine de scripts concurrents affament le témoin de crête mémoire,
# qui mesure ce que la machine LUI LAISSE : il REFUSE alors de conclure — c'est le bon
# comportement du test, et un rouge illisible pour qui l'a provoqué. Vu QUATRE FOIS les 2026-08-28
# et 2026-08-29, dont DEUX sur le même témoin. La règle était écrite et n'a rien tenu ; ce fichier
# est le mécanisme qui la tient.
#
# LES MESURES QUI LE FONDENT, ET TROIS D'ENTRE ELLES SONT DES RÉFUTATIONS.
#
#  1. AUCUNE garde de la batterie n'invoque cargo. Les sept `check_*.py` dont le texte contient
#     « cargo » n'engendrent que `git` ; les occurrences sont des littéraux cherchés dans le flux
#     d'intégration. La batterie ne CONSTRUIT donc pas — elle CONSOMME la machine, ce qui suffit à
#     fausser une mesure de crête.
#
#  2. LE VERROU D'ARTEFACTS SEUL EST INSUFFISANT — RÉFUTÉ PAR LA MESURE. Le `.cargo-lock` que
#     `compter-les-tests.sh` sondait déjà est LIBRE pendant TOUTE l'exécution d'une suite : mesuré
#     sur une suite complète, vingt-deux relevés à dix secondes d'intervalle, verrou libre du
#     premier au dernier, zéro `rustc`, trois binaires de test en vie. Cargo tient ce verrou
#     pendant qu'il CONSTRUIT, pas pendant qu'il EXÉCUTE.
#
#  3. LA SONDE PAR LIGNE DE COMMANDE EST RÉFUTÉE AUSSI. `pgrep -cf 'target/debug/deps/plume'` rend
#     2 alors qu'AUCUNE suite ne tourne : elle s'apparie sur sa PROPRE ligne de commande, et sur
#     celle du shell qui la lance. Une sonde qui dit « occupé » quand rien ne tourne refuserait la
#     batterie en permanence, donc serait désarmée le jour même.
#
#  4. UN SEUL RÉPERTOIRE D'ARTEFACTS ÉTAIT UNE PORTÉE FAUSSE — RÉFUTÉ LE 2026-08-29. Ce dépôt porte
#     QUATRE crates (`daemon`, `agent`, `collector-mail`, `collector-syslog`), donc quatre `target/`
#     et ONZE `.cargo-lock` mesurés. La version précédente ne regardait que `daemon/target` : deux
#     verrous sur onze, et un `cargo test` dans `agent/` était INVISIBLE alors qu'il prend les mêmes
#     cœurs. La population des répertoires est désormais DÉRIVÉE des `Cargo.toml` du dépôt.
#
#  5. UN CHEMIN NON CANONIQUE RENDAIT LA SONDE MUETTE, EN S'ATTESTANT VERTE — MESURÉ LE 2026-08-29.
#     `readlink /proc/<pid>/exe` rend le chemin PHYSIQUE ; `cd … && pwd` rendait le chemin LOGIQUE.
#     Dépôt atteint par un lien symbolique, ou `CARGO_TARGET_DIR` avec une barre oblique finale :
#     une suite BIEN EN COURS était lue « LIBRE », rc=0, avec « signal exécution = 1 » imprimé
#     juste au-dessus. Tout chemin regardé est maintenant CANONICALISÉ, et la canonicité de ce que
#     la sonde va réellement interroger est un TÉMOIN, pas une supposition.
#
#  6. L'EXISTENCE D'UN PROCESSUS N'EST PAS SA CONSOMMATION — MESURÉ LE 2026-08-29. Un binaire de
#     test ARRÊTÉ (SIGSTOP, ou arrêté sous un débogueur) est à l'état `T`, ne consomme rien, et
#     bloquait pourtant tout commit sans échappatoire autre que `--no-verify` : `--attendre` brûlait
#     son plafond puis sortait en 3, comme le refus. Les états `T`/`t` (arrêté, tracé) et `Z`/`X`
#     (mort) sont désormais EXCLUS, et le refus NOMME LE GESTE (`kill <pid>`).
#
#  7. CE QUI MARCHE, VALIDÉ DANS LES DEUX SENS : compter les processus dont l'EXÉCUTABLE RÉSOLU —
#     `readlink /proc/<pid>/exe`, jamais la ligne de commande — tombe sous `<cible>/*/deps/`.
#     Mesuré 0 sans suite, >= 1 pendant l'exécution, 0 après. Elle ne PEUT PAS s'auto-apparier :
#     l'exécutable de ce script est `bash`.
#
# CE QU'IL NE TIENT PAS, ET IL FAUT LE DIRE :
#   — `/proc/<pid>/exe` d'un processus d'un AUTRE utilisateur n'est pas lisible. MESURÉ SUR CE
#     POSTE le 2026-08-29 : 433 processus, 131 exécutables lisibles, 302 INVISIBLES — 70 %. Le
#     chiffre n'est plus une note de bas de page : il est RELEVÉ à chaque sonde et IMPRIMÉ dans le
#     verdict, qui dit « que je puisse voir » et non « aucune ».
#   — Dans un espace de noms PID (conteneur de développement), la sonde ne voit que les processus
#     de cet espace. Une suite qui tourne sur l'hôte est invisible, et le compte d'illisibles
#     ci-dessus ne la signale pas non plus.
#   — Entre la sonde et le geste qui suit il reste une FENÊTRE. Le JETON (signal 3) la referme pour
#     les outils de ce dépôt qui le prennent ; elle reste ouverte pour tout le reste.
#   — Le signal d'exécution ne voit que ce qui tourne SOUS un répertoire d'artefacts du dépôt. Un
#     binaire de test COPIÉ ailleurs puis lancé n'est pas vu ; c'est assumé, et c'est ce qui rend
#     l'épreuve positive ci-dessous possible sans perturber le vrai signal.
#   — Le JETON est nommé d'après la RACINE du dépôt : deux clones distincts ne se voient pas.
#
# CE QU'IL EXPOSE (tout le reste est privé par convention de préfixe) :
#   sonde_eprouver <appelant>            éprouve les TROIS signaux dans les DEUX sens ; rend 0 si au
#                                        moins un signal est utilisable, et écrit ses AVEUX sur la
#                                        sortie d'erreur pour ceux qui ne le sont pas.
#   sonde_occupation                     écrit « <cause> \t <détail> \t <geste> » si la machine est
#                                        prise, rien sinon. cause = construction | suite | travail.
#   sonde_refuser_ou_attendre <appelant> <attendre 0|1> <plafond_s>
#                             [conseil_construction...] -- [conseil_autres...]
#                                        rend 0 si la voie est libre, 3 si RIEN N'A ÉTÉ MESURÉ.
#                                        Les deux groupes de conseils sont séparés par « -- » :
#                                        ce qu'on dit d'une construction n'est pas ce qu'on dit
#                                        d'une suite, et un texte unique aurait menti sur l'une.
#   sonde_jeton_prendre <nom>            déclare un travail lourd et le REND VISIBLE aux autres
#                                        outils ; rend 1 si quelqu'un l'a pris entre-temps.
#   sonde_illisibles / sonde_processus   dernier recensement de `/proc` (voir le verdict).
#
# ÉPROUVÉ AUSSI EN DIRECT : exécuté au lieu d'être sourcé, ce fichier joue ses épreuves et dit
# l'état de la machine. C'est le geste de diagnostic, et il ne coûte rien.
#
# Codes de sortie (exécution directe) :
#   0  la machine est libre        2  aucun signal utilisable (RIEN N'A ÉTÉ MESURÉ)
#   3  la machine est prise

# `racine` est respectée si l'appelant l'a déjà fixée : les deux appelants de ce dépôt la calculent
# de la même façon, et l'écraser en la sourçant serait un effet de bord silencieux. Elle est
# CANONICALISÉE (`pwd -P`) : `/proc/<pid>/exe` rend un chemin physique, et comparer un chemin
# logique à un chemin physique rendait la sonde muette (mesure 5 de l'en-tête).
racine="${racine:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)}"
racine="$(cd "$racine" 2>/dev/null && pwd -P || printf '%s' "$racine")"

sonde_processus=0
sonde_illisibles=0
_sonde_appelant=sonde

_sonde_aveu() { printf '%s : AVEU — %s\n' "$_sonde_appelant" "$1" >&2; }

# --- LES RÉPERTOIRES D'ARTEFACTS REGARDÉS : DÉRIVÉS, CANONIQUES, JAMAIS ÉNUMÉRÉS ----------------
# `CARGO_TARGET_DIR` écrase tout, c'est la règle de cargo. Sinon la population est dérivée des
# `Cargo.toml` du dépôt : un crate a un `target/` à côté de son manifeste. Quatre crates ici,
# mesurés — et la version précédente n'en regardait qu'un (mesure 4 de l'en-tête).
# CHAQUE chemin est canonicalisé, et sa canonicité est ensuite VÉRIFIÉE : un `target/` déporté par
# lien symbolique sur un autre disque est une pratique courante sur un poste à faible marge, et
# c'est exactement ce qui aveuglait les deux signaux à la fois.
_sonde_canonique() {
    local p="$1"
    [ -n "$p" ] || return 1
    if [ -d "$p" ]; then (cd "$p" 2>/dev/null && pwd -P) && return 0; fi
    readlink -f -- "$p" 2>/dev/null || printf '%s' "$p"
}

sonde_cibles=()
if [ -n "${CARGO_TARGET_DIR:-}" ]; then
    # UNE RELATIVE NE PEUT PAS ÊTRE RÉSOLUE SANS MENTIR : cargo la résout depuis SON répertoire de
    # travail, que cette sonde ne connaît pas. On la résout depuis le nôtre et ON LE DIT.
    case "$CARGO_TARGET_DIR" in
        /*) : ;;
        *)  _sonde_cible_relative="$PWD" ;;
    esac
    sonde_cibles=("$(_sonde_canonique "$CARGO_TARGET_DIR")")
else
    while IFS= read -r _m; do
        [ -n "$_m" ] || continue
        sonde_cibles+=("$(_sonde_canonique "$(dirname "$_m")/target")")
    done < <(find "$racine" -mindepth 2 -maxdepth 2 -name Cargo.toml -type f 2>/dev/null | sort)
fi

# --- LA SONDE DE CONSTRUCTION CONCURRENTE -------------------------------------------------------
# DÉRIVÉE, PAS ÉNUMÉRÉE : cargo pose un `.cargo-lock` dans le répertoire d'artefacts de CHAQUE
# profil qu'il a déjà construit. On lit ceux qui EXISTENT, sans en créer aucun — sonder un verrou
# absent le ferait naître, et un profil jamais construit ne porte par définition aucune
# construction en cours. La profondeur 3 n'est pas un chiffre choisi : elle est celle des verrous
# de cible croisée mesurés ici (`agent/target/x86_64-pc-windows-gnu/debug/.cargo-lock`), et
# l'épreuve ci-dessous la PIN sur un arbre jetable de cette forme.
# LA DÉCOUVERTE SE FAIT PAR GLOBS, PAS PAR `find` — ET C'EST UNE MESURE, PAS UN GOÛT. `find … 
# -maxdepth 3` DESCEND dans `<target>/<profil>/deps/`, qui compte ici 10 469 entrées à profondeur
# ≤ 3 : 137 ms par relevé sur les quatre cibles, et ce relevé est REFAIT avant chacune des 43
# gardes. Les deux formes que cargo emploie sont `<target>/<profil>/.cargo-lock` et
# `<target>/<triplet>/<profil>/.cargo-lock` : deux globs les rendent SANS lister le contenu de
# `deps/`. MESURÉ : population IDENTIQUE (les 11 verrous de ce dépôt), 13 ms au lieu de 137. Le
# répertoire est entre guillemets — seul le `*` écrit ici est un motif —, donc un chemin portant un
# caractère de globbing ne peut pas élargir la population.
verrous_existants() {
    local d f
    for d in "$@"; do
        [ -n "$d" ] || continue
        [ -d "$d" ] || continue
        for f in "$d"/*/.cargo-lock "$d"/*/*/.cargo-lock; do
            [ -f "$f" ] || continue
            printf '%s\n' "$f"
        done
    done
    return 0
}

# TROIS ÉTATS, PAS DEUX — CORRIGÉ LE 2026-08-29. `flock` rend 0 si le verrou est LIBRE, 1 s'il est
# TENU, et 66 s'il n'a pas pu OUVRIR le fichier (droits, montage en lecture seule, refus MAC) —
# mesuré sur util-linux 2.42.2. La version précédente lisait « non-zéro » = « tenu » : un
# `.cargo-lock` en mode 000 produisait un REFUS PERMANENT que rien ne débloquait, et l'instrument
# se déclarait valide. Un défaut d'OUVERTURE est un AVEU, pas un verrou.
#   0 = TENU        1 = LIBRE        2 = JE N'AI PAS PU OUVRIR
verrou_tenu() {
    local rc=0
    flock -n "$1" -c true 9>&- 2>/dev/null || rc=$?
    case "$rc" in
        0) return 1 ;;
        1) return 0 ;;
        *) return 2 ;;
    esac
}

# VALIDATION DE L'INSTRUMENT, DANS LES DEUX SENS, À CHAQUE EXÉCUTION. Une sonde qui rendrait
# toujours « libre » laisserait passer exactement ce qu'elle prétend arrêter, et son silence se
# lirait comme une garantie.
# ELLE ÉPROUVE MAINTENANT LA CHAÎNE ENTIÈRE, PAS SEULEMENT LE PRÉDICAT. La version précédente
# n'exerçait que `verrou_tenu` sur un fichier qu'elle créait elle-même : la moitié qui décide OÙ
# l'on regarde (`verrous_existants`, son motif, sa profondeur) était HORS ÉPREUVE, et une mutation
# du nom cherché passait au vert. Quatre témoins :
#   DÉCOUVERTE   un `.cargo-lock` posé à la profondeur des verrous de cible croisée doit être TROUVÉ ;
#   INVENTION    un arbre sans verrou ne doit en rendre AUCUN ;
#   LIBRE/TENU   le prédicat doit distinguer les deux sens sur ce MÊME fichier ;
#   ILLISIBLE    un verrou qu'on ne peut pas ouvrir doit rendre 2, jamais « tenu ».
epreuve_de_la_sonde() {
    local d fd vus
    d="$(mktemp -d "${TMPDIR:-/tmp}/sonde-verrou.XXXXXX")" || { echo "mktemp -d a échoué"; return 1; }

    # TÉMOIN INVENTION
    mkdir -p "$d/cible/debug" || { rm -rf "$d"; echo "l'arbre jetable n'a pas pu être fabriqué"; return 1; }
    vus="$(verrous_existants "$d/cible" | wc -l)"
    if [ "$vus" -ne 0 ]; then rm -rf "$d"; echo "témoin INVENTION : $vus verrou(s) vu(s) là où il n'y en a aucun"; return 1; fi

    # TÉMOIN DÉCOUVERTE, à la profondeur des verrous de cible croisée mesurés dans ce dépôt
    mkdir -p "$d/cible/x86_64-pc-windows-gnu/debug"
    : > "$d/cible/x86_64-pc-windows-gnu/debug/.cargo-lock"
    vus="$(verrous_existants "$d/cible" | wc -l)"
    if [ "$vus" -ne 1 ]; then rm -rf "$d"; echo "témoin DÉCOUVERTE : un .cargo-lock posé à la profondeur mesurée est vu $vus fois, attendu 1"; return 1; fi

    local v="$d/cible/x86_64-pc-windows-gnu/debug/.cargo-lock"
    # TÉMOIN LIBRE
    verrou_tenu "$v"; case $? in 1) : ;; 2) rm -rf "$d"; echo "témoin LIBRE : le verrou jetable n'a pas pu être ouvert"; return 1 ;; *) rm -rf "$d"; echo "témoin LIBRE : un verrou libre est vu tenu"; return 1 ;; esac
    # TÉMOIN TENU — descripteur ALLOUÉ par bash, jamais le 9 en dur : ce fichier est SOURCÉ, et
    # écraser un descripteur de l'appelant serait un effet de bord silencieux.
    exec {fd}>"$v"
    if ! flock -n "$fd" 2>/dev/null; then exec {fd}>&-; rm -rf "$d"; echo "témoin TENU : le verrou jetable n'a pas pu être pris"; return 1; fi
    verrou_tenu "$v"; case $? in 0) : ;; *) exec {fd}>&-; rm -rf "$d"; echo "témoin TENU : un verrou TENU est vu libre"; return 1 ;; esac
    exec {fd}>&-

    # TÉMOIN ILLISIBLE — il ne peut pas s'exercer sous un compte qui outrepasse les droits ; on le
    # DIT au lieu de le compter vert.
    chmod 000 "$v" 2>/dev/null || true
    verrou_tenu "$v"
    case $? in
        2) : ;;
        1) _sonde_aveu "le témoin ILLISIBLE ne s'exerce pas ici (les droits sont outrepassés) : la distinction « verrou tenu » / « verrou illisible » N'A PAS ÉTÉ VÉRIFIÉE." ;;
        *) chmod 644 "$v" 2>/dev/null || true; rm -rf "$d"; echo "témoin ILLISIBLE : un verrou qu'on ne peut pas ouvrir est vu TENU"; return 1 ;;
    esac
    chmod 644 "$v" 2>/dev/null || true
    rm -rf "$d"
    return 0
}

# --- LA SONDE D'EXÉCUTION DE SUITE ---------------------------------------------------------------
# ELLE LIT L'EXÉCUTABLE, JAMAIS LA LIGNE DE COMMANDE, et c'est TOUTE la différence. Cargo range les
# harnais de test sous `<cible>/<profil>/deps/` ; un processus dont `/proc/<pid>/exe` résout là-
# dedans EST une suite en train de tourner. La variante par ligne de commande a été mesurée et
# réfutée : elle s'apparie sur elle-même (voir l'en-tête, mesure 3). Celle-ci ne le peut pas —
# l'exécutable de ce script est `bash`, qui ne tombe sous aucun `deps/`.
#
# LES RÉPERTOIRES SONT DES PARAMÈTRES, ET CE N'EST PAS DE LA GÉNÉRALITÉ GRATUITE : c'est ce qui
# permet à l'épreuve ci-dessous de fabriquer un arbre JETABLE, d'y faire tourner un vrai processus,
# et de vérifier le témoin POSITIF sans jamais lancer de suite ni toucher aux vrais artefacts.
#
# UN SEUL PROCESSUS, PAS QUATRE CENTS — ET LA DÉCISION RESTE EXACTE. Un `readlink` par entrée de
# `/proc` engendrait 422 processus, MESURÉ à 1,57 s par relevé sur ce poste ; `find … -printf` fait
# le même travail en UN processus, MESURÉ à 0,027 s sur 433 processus. Le tri d'`awk` est un
# PRÉ-FILTRE littéral (`index`, pas une expression rationnelle) : un sur-ensemble de ce qu'on
# cherche. La décision est prise par le `case` de bash sur le chemin LITTÉRAL du répertoire — une
# variable entre guillemets n'y est pas un motif —, de sorte qu'un chemin portant un caractère de
# globbing ne peut pas élargir la population jugée.
#
# LE MÊME RELEVÉ RECENSE LES INVISIBLES. `%l` est VIDE quand le lien n'est pas lisible : c'est le
# cas des processus d'un autre utilisateur, 302 sur 433 mesurés ici. Ce chiffre est rendu au
# verdict, qui dit « que je puisse voir ».
#
# L'EXISTENCE N'EST PAS LA CONSOMMATION. Un processus ARRÊTÉ (`T`, `t`) ou MORT (`Z`, `X`) ne
# dispute ni cœur ni mémoire : le compter bloquait tout commit sans geste de sortie. L'état est lu
# dans `/proc/<pid>/stat`, après le DERNIER `)` — le nom du programme peut contenir des espaces et
# des parenthèses, et découper sur le premier séparateur est le piège classique de ce fichier.
executions_sous() {
    local marque pid exe etat reste lu sous garde
    sonde_processus=0
    sonde_illisibles=0
    while IFS=$'\t' read -r marque pid exe; do
        if [ "$marque" = C ]; then sonde_processus="$pid"; sonde_illisibles="$exe"; continue; fi
        [ -n "$exe" ] || continue
        garde=0
        for sous in "$@"; do
            [ -n "$sous" ] || continue
            case "$exe" in "$sous"/*/deps/*) garde=1; break ;; esac
        done
        [ "$garde" -eq 1 ] || continue
        pid="${pid#/proc/}"
        lu="$(cat "/proc/$pid/stat" 2>/dev/null)" || continue
        [ -n "$lu" ] || continue
        reste="${lu##*) }"
        etat="${reste%% *}"
        case "$etat" in
            T|t|Z|X) continue ;;
        esac
        printf '%s\t%s\t%s\n' "$pid" "$exe" "$etat"
    done < <(find /proc -mindepth 2 -maxdepth 2 -name exe -printf '%h\t%l\n' 2>/dev/null \
             | awk -F'\t' 'BEGIN{OFS="\t"}
                           {n++; if ($2=="") i++; else if (index($2,"/deps/")>0) print "P", $1, $2}
                           END{print "C", n+0, i+0}')
    return 0
}

# Ces auxiliaires ne servent qu'à l'épreuve ci-dessous. Elles sont écrites avec des `if` et non des
# listes `&&` : sous `set -e`, une liste `a && b` dont le `a` est faux fait sortir le shell, et
# l'épreuve mourrait au lieu de rendre son verdict — exactement le genre d'instrument qui se tait.
_epreuve_menage() {
    if [ -n "${pid_leurre:-}" ]; then kill "$pid_leurre" 2>/dev/null || true; wait "$pid_leurre" 2>/dev/null || true; fi
    if [ -n "${pid_temoin:-}" ]; then kill "$pid_temoin" 2>/dev/null || true; wait "$pid_temoin" 2>/dev/null || true; fi
    rm -rf "${tmp:-}"
    return 0
}

# Attend que la sonde rende EXACTEMENT `$1` sous l'arbre jetable, cinq secondes au plus. Rend 1 si
# la condition n'est jamais atteinte, en laissant `vu` sur le dernier relevé — c'est ce chiffre que
# le message d'échec cite, pour ne pas accuser sans dire ce qui a été VU.
_epreuve_patiente() {
    local voulu="$1" depart
    depart=$SECONDS
    while :; do
        vu="$(executions_sous "$faux" | wc -l)"
        if [ "$vu" -eq "$voulu" ]; then return 0; fi
        if [ $(( SECONDS - depart )) -ge 5 ]; then return 1; fi
        sleep 0.05 2>/dev/null || sleep 1
    done
}

# VALIDATION DE L'INSTRUMENT, DANS LES DEUX SENS, À CHAQUE EXÉCUTION — et une troisième fois CONTRE
# la sonde réfutée. Les témoins, dans cet ordre :
#   INSTRUMENT       `find -printf` est la seule extension GNU dont dépend ce fichier ; sans elle,
#                    l'aveu est IMMÉDIAT. La version précédente laissait le témoin POSITIF brûler
#                    son plafond de 5 s à chaque appel — 4,6 s ajoutées à chaque commit du démon,
#                    sans que rien n'en dise la cause ;
#   CHEMINS          les répertoires que la sonde va RÉELLEMENT interroger doivent être CANONIQUES.
#                    L'épreuve validait le MÉCANISME sur un arbre neuf, jamais le CHEMIN sur lequel
#                    on allait l'interroger : c'est ce trou qui rendait un `target/` déporté par
#                    lien symbolique invisible tout en imprimant « signal exécution = 1 » ;
#   NÉGATIF          un arbre jetable où rien n'a jamais tourné doit rendre ZÉRO ;
#   ADVERSE          un processus dont la LIGNE DE COMMANDE porte le chemin d'un binaire de test et
#                    dont l'exécutable n'en est pas un ne doit PAS être compté — c'est exactement ce
#                    que `pgrep -f` comptait ; le leurre est vérifié BIEN FORMÉ avant de conclure,
#                    sinon le témoin serait vide et son vert se lirait comme une garantie ;
#   POSITIF          une COPIE d'un vrai exécutable, lancée sous `<jetable>/debug/deps/`, doit être
#                    comptée, et comptée SEULE — le leurre est toujours en vie pendant ce relevé ;
#   ARRÊTÉ           le MÊME processus, une fois SIGSTOP'é, ne doit PLUS être compté : il ne
#                    consomme rien, et le compter était le refus permanent mesuré le 2026-08-29 ;
#   NÉGATIF APRÈS    une fois tué, il ne doit plus l'être.
# Les processus jetables ont leurs sorties fermées vers /dev/null : sans cela ils tiendraient
# ouverte l'extrémité d'écriture de la substitution de commande qui appelle cette fonction, et
# l'épreuve BLOQUERAIT jusqu'à leur mort au lieu de rendre son verdict.
# `grep -a` sur `/proc/<pid>/cmdline` : ce flux est séparé par des octets NUL, et sans `-a` grep le
# traite en binaire et ne rend rien — le témoin adverse serait alors toujours « vert ».
# LES PROCESSUS SONT TUÉS PAR PID, jamais par motif : un `pkill -f` s'apparie sur le shell qui le
# lance, et ce dépôt l'a déjà payé.
# UN `trap` COUVRE L'INTERRUPTION : sans lui, un Ctrl-C au milieu laissait deux processus jetables
# en vie et un arbre temporaire derrière, pendant que la sonde se disait propre.
epreuve_de_la_sonde_d_execution() {
    local binaire tmp faux vu pid_temoin="" pid_leurre="" depart d
    if ! find "${TMPDIR:-/tmp}" -maxdepth 0 -printf '' >/dev/null 2>&1; then
        echo "« find » ne sait pas « -printf » : le relevé de /proc est impossible"; return 1
    fi
    for d in ${sonde_cibles[@]+"${sonde_cibles[@]}"}; do
        [ -n "$d" ] || continue
        [ -d "$d" ] || continue
        if [ "$d" != "$( (cd "$d" && pwd -P) 2>/dev/null )" ]; then
            echo "le répertoire interrogé n'est pas canonique (« $d ») : /proc rend des chemins physiques, la comparaison serait muette"; return 1
        fi
    done
    binaire="$(command -v sleep 2>/dev/null || true)"
    if [ -z "$binaire" ] || [ ! -x "$binaire" ]; then
        echo "aucun exécutable jetable (« sleep » introuvable)"; return 1
    fi
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/sonde-execution.XXXXXX")" || { echo "mktemp -d a échoué"; return 1; }
    faux="$(cd "$tmp" && pwd -P)/cible"
    trap '_epreuve_menage' INT TERM

    if ! mkdir -p "$faux/debug/deps" || ! cp "$binaire" "$faux/debug/deps/plume-epreuve"; then
        _epreuve_menage; trap - INT TERM; echo "l'arbre jetable n'a pas pu être fabriqué"; return 1
    fi

    # TÉMOIN NÉGATIF
    vu="$(executions_sous "$faux" | wc -l)"
    if [ "$vu" -ne 0 ]; then
        _epreuve_menage; trap - INT TERM; echo "témoin NÉGATIF : $vu processus vu(s) là où rien ne tourne"; return 1
    fi

    # TÉMOIN ADVERSE — la sonde réfutée, mise en échec ici même
    ( exec -a "$faux/debug/deps/plume-leurre" "$binaire" 30 ) >/dev/null 2>&1 &
    pid_leurre=$!
    depart=$SECONDS
    until grep -qa 'plume-leurre' "/proc/$pid_leurre/cmdline" 2>/dev/null; do
        if [ $(( SECONDS - depart )) -ge 5 ]; then
            _epreuve_menage; trap - INT TERM; echo "le leurre n'a jamais porté sa ligne de commande — témoin ADVERSE vide"; return 1
        fi
        sleep 0.05 2>/dev/null || sleep 1
    done
    vu="$(executions_sous "$faux" | wc -l)"
    if [ "$vu" -ne 0 ]; then
        _epreuve_menage; trap - INT TERM; echo "témoin ADVERSE : un LEURRE de ligne de commande a été compté ($vu)"; return 1
    fi

    # TÉMOIN POSITIF — et compté SEUL, le leurre étant toujours en vie
    "$faux/debug/deps/plume-epreuve" 30 >/dev/null 2>&1 &
    pid_temoin=$!
    if ! _epreuve_patiente 1; then
        _epreuve_menage; trap - INT TERM; echo "témoin POSITIF : un exécutable qui tourne sous l'arbre jetable est vu $vu fois, attendu 1"; return 1
    fi

    # TÉMOIN ARRÊTÉ — même processus, zéro consommation, il ne doit plus compter
    kill -STOP "$pid_temoin" 2>/dev/null || true
    if ! _epreuve_patiente 0; then
        kill -CONT "$pid_temoin" 2>/dev/null || true
        _epreuve_menage; trap - INT TERM; echo "témoin ARRÊTÉ : un processus SIGSTOP'é, qui ne consomme rien, est encore compté ($vu)"; return 1
    fi
    kill -CONT "$pid_temoin" 2>/dev/null || true
    if ! _epreuve_patiente 1; then
        _epreuve_menage; trap - INT TERM; echo "témoin ARRÊTÉ : relancé, le processus n'est pas recompté ($vu)"; return 1
    fi

    # TÉMOIN NÉGATIF APRÈS
    kill "$pid_temoin" 2>/dev/null || true
    wait "$pid_temoin" 2>/dev/null || true
    pid_temoin=""
    if ! _epreuve_patiente 0; then
        _epreuve_menage; trap - INT TERM; echo "témoin NÉGATIF APRÈS : le processus tué est encore compté ($vu)"; return 1
    fi

    _epreuve_menage
    trap - INT TERM
    return 0
}

# --- LE JETON DE TRAVAIL LOURD -------------------------------------------------------------------
# CE QUE LES DEUX AUTRES SIGNAUX NE PEUVENT PAS VOIR. La batterie de gardes ne construit pas et
# n'exécute aucun binaire de `deps/` : elle était INVISIBLE à sa propre sonde. MESURÉ le
# 2026-08-29 : deux lanceurs lancés à une seconde d'intervalle demandaient la permission, la
# recevaient tous les deux, et jouaient EN MÊME TEMPS — c'est-à-dire exactement la situation que
# cette clé prétend fermer. Symétriquement, `compter-les-tests.sh` construisait sans jamais voir
# qu'une batterie tournait.
# Le jeton est un verrou `flock` — le MÊME prédicat que le signal 1, donc déjà éprouvé dans les
# deux sens — que tout outil lourd de ce dépôt PREND avant de commencer. Il referme aussi, pour
# ceux qui le prennent, la fenêtre entre la sonde et le geste : c'est le SEUL des trois résidus
# nommés qui se laisse fermer.
# IL EST NOMMÉ D'APRÈS LA RACINE : deux clones ne se gênent pas. C'est un choix, et sa limite est
# dite dans l'en-tête.
sonde_jeton="${TMPDIR:-/tmp}/plume-travail-lourd.$(printf '%s' "$racine" | cksum | tr -d ' ').lock"
sonde_jeton_a_moi=0
_sonde_jeton_fd=

# Rend 0 si le jeton est PRIS par nous, 1 si quelqu'un d'autre l'a, 2 s'il n'a pas pu être ouvert.
sonde_jeton_prendre() {
    local nom="${1:-travail}"
    [ "$sonde_jeton_a_moi" -eq 0 ] || return 0
    exec {_sonde_jeton_fd}>"$sonde_jeton" 2>/dev/null || return 2
    if ! flock -n "$_sonde_jeton_fd" 2>/dev/null; then
        exec {_sonde_jeton_fd}>&-
        _sonde_jeton_fd=
        return 1
    fi
    printf '%s pid %s\n' "$nom" "$$" >&"$_sonde_jeton_fd" 2>/dev/null || true
    sonde_jeton_a_moi=1
    return 0
}

# L'épreuve du jeton, dans les deux sens, sur un fichier JETABLE — jamais sur le vrai jeton, qui
# serait alors pris puis relâché à chaque sonde, c'est-à-dire un signal qui se ment à lui-même.
epreuve_du_jeton() {
    local d f fd
    d="$(mktemp -d "${TMPDIR:-/tmp}/sonde-jeton.XXXXXX")" || { echo "mktemp -d a échoué"; return 1; }
    f="$d/jeton"; : > "$f"
    verrou_tenu "$f"; case $? in 1) : ;; *) rm -rf "$d"; echo "témoin LIBRE : un jeton jamais pris est vu tenu"; return 1 ;; esac
    exec {fd}>"$f"
    if ! flock -n "$fd" 2>/dev/null; then exec {fd}>&-; rm -rf "$d"; echo "témoin PRIS : le jeton jetable n'a pas pu être pris"; return 1; fi
    verrou_tenu "$f"; case $? in 0) : ;; *) exec {fd}>&-; rm -rf "$d"; echo "témoin PRIS : un jeton TENU est vu libre"; return 1 ;; esac
    exec {fd}>&-
    verrou_tenu "$f"; case $? in 1) : ;; *) rm -rf "$d"; echo "témoin RELÂCHÉ : un jeton relâché est encore vu tenu"; return 1 ;; esac
    rm -rf "$d"
    return 0
}

# --- L'ÉPREUVE DES TROIS SIGNAUX, PUIS LA LECTURE, PUIS LA DÉCISION ------------------------------
# Un signal qui échoue à s'éprouver est DÉSARMÉ et son absence est DITE. Il n'est jamais remplacé
# par un « libre » muet : c'est l'aveu qui distingue « j'ai regardé, rien » de « je n'ai pas pu
# regarder ».
sonde_construction_utilisable=0
sonde_execution_utilisable=0
sonde_jeton_utilisable=0

sonde_eprouver() {
    local appelant="${1:-sonde}" marge faute
    _sonde_appelant="$appelant"
    marge="$(printf '%*s' $(( ${#appelant} + 3 )) '')"
    sonde_construction_utilisable=0
    sonde_execution_utilisable=0
    sonde_jeton_utilisable=0

    if [ "${#sonde_cibles[@]}" -eq 0 ]; then
        echo "$appelant : AVEU — aucun répertoire d'artefacts n'a pu être DÉRIVÉ sous « $racine » :" >&2
        echo "${marge}ni construction ni suite N'ONT ÉTÉ VÉRIFIÉES." >&2
    fi
    if [ -n "${_sonde_cible_relative:-}" ]; then
        echo "$appelant : AVEU — « CARGO_TARGET_DIR » est RELATIF : cargo le résout depuis SON" >&2
        echo "${marge}répertoire de travail, celui-ci depuis « ${_sonde_cible_relative} ». Si les deux" >&2
        echo "${marge}diffèrent, la sonde regarde AILLEURS que cargo." >&2
    fi

    if ! command -v flock >/dev/null 2>&1; then
        echo "$appelant : AVEU — « flock » est absent : la présence d'une CONSTRUCTION concurrente" >&2
        echo "${marge}N'A PAS ÉTÉ VÉRIFIÉE." >&2
    elif faute="$(epreuve_de_la_sonde)"; then
        sonde_construction_utilisable=1
    else
        echo "$appelant : AVEU — la sonde de verrou est INVALIDE ($faute) : la présence d'une" >&2
        echo "${marge}CONSTRUCTION concurrente N'A PAS ÉTÉ VÉRIFIÉE." >&2
    fi

    if faute="$(epreuve_de_la_sonde_d_execution)"; then
        sonde_execution_utilisable=1
    else
        echo "$appelant : AVEU — la sonde d'exécution est INVALIDE ($faute) : la présence d'une" >&2
        echo "${marge}SUITE DE TESTS en cours N'A PAS ÉTÉ VÉRIFIÉE." >&2
    fi

    # LA CAUSE EST NOMMÉE JUSTE. Le jeton emploie le MÊME prédicat de verrou que le signal 1 : si
    # celui-ci est désarmé, l'aveu doit le DIRE, et non recycler la faute du témoin précédent — ce
    # que faisait une première écriture de ce bloc, qui imprimait « flock indisponible » alors que
    # `flock` était là.
    if [ "$sonde_construction_utilisable" -eq 0 ]; then
        echo "$appelant : AVEU — le jeton de travail lourd repose sur le MÊME prédicat de verrou, lui-même" >&2
        echo "${marge}DÉSARMÉ : la présence d'un AUTRE TRAVAIL LOURD de ce dépôt N'A PAS ÉTÉ VÉRIFIÉE." >&2
    elif faute="$(epreuve_du_jeton)"; then
        sonde_jeton_utilisable=1
    else
        echo "$appelant : AVEU — le jeton de travail lourd est INVALIDE ($faute) :" >&2
        echo "${marge}la présence d'un AUTRE TRAVAIL LOURD de ce dépôt N'A PAS ÉTÉ VÉRIFIÉE." >&2
    fi

    [ "$sonde_construction_utilisable" -eq 1 ] || [ "$sonde_execution_utilisable" -eq 1 ] \
        || [ "$sonde_jeton_utilisable" -eq 1 ]
}

# L'ORDRE EST DÉLIBÉRÉ : la construction d'abord. Elle est le signal qui existait, et son refus est
# rendu MOT POUR MOT comme avant ce déplacement ; les autres signaux ne font qu'AJOUTER des causes
# de refus, ils n'en retouchent aucune.
# TROIS CHAMPS, SÉPARÉS PAR DES TABULATIONS : cause, détail lisible, GESTE. Le geste est vide quand
# il n'y en a pas ; il ne l'est pas pour une suite en cours, où c'est le SEUL moyen de sortir d'un
# processus qui ne finit jamais.
sonde_occupation() {
    local v ligne pid exe etat geste_jeton
    if [ "$sonde_construction_utilisable" -eq 1 ]; then
        while IFS= read -r v; do
            [ -n "$v" ] || continue
            verrou_tenu "$v"
            case $? in
                0) printf 'construction\t%s\t\n' "$v"; return 0 ;;
                2) _sonde_aveu "le verrou « $v » n'a pas pu être OUVERT : ce n'est PAS un verrou tenu, et cette construction-là N'A PAS ÉTÉ VÉRIFIÉE." ;;
            esac
        done < <(verrous_existants ${sonde_cibles[@]+"${sonde_cibles[@]}"})
    fi
    if [ "$sonde_execution_utilisable" -eq 1 ]; then
        while IFS=$'\t' read -r pid exe etat; do
            [ -n "$pid" ] || continue
            printf 'suite\tpid %s, état %s (« %s »)\tkill %s\n' "$pid" "$etat" "$exe" "$pid"
            return 0
        done < <(executions_sous ${sonde_cibles[@]+"${sonde_cibles[@]}"})
    fi
    if [ "$sonde_jeton_utilisable" -eq 1 ] && [ "$sonde_jeton_a_moi" -eq 0 ]; then
        # LE JETON VIT DANS `TMPDIR`, QUE PLUSIEURS COMPTES PARTAGENT. Un jeton déposé par un autre
        # utilisateur peut être INOUVRABLE : c'est un AVEU, jamais « libre » ni « tenu ».
        local etat_jeton=0
        verrou_tenu "$sonde_jeton" || etat_jeton=$?
        if [ "$etat_jeton" -eq 2 ]; then
            _sonde_aveu "le jeton « $sonde_jeton » n'a pas pu être OUVERT (il appartient sans doute à un autre compte) : la présence d'un autre travail lourd N'A PAS ÉTÉ VÉRIFIÉE."
        elif [ "$etat_jeton" -eq 0 ]; then
            v="$(head -1 "$sonde_jeton" 2>/dev/null || true)"
            # LE GESTE N'EST DONNÉ QUE S'IL EST DÉRIVABLE : le jeton porte « <nom> pid <N> ». S'il
            # ne porte pas cette forme, on ne nomme AUCUN pid plutôt qu'un pid inventé.
            geste_jeton=""
            case "$v" in *' pid '[0-9]*) geste_jeton="kill ${v##* pid }" ;; esac
            printf 'travail\t%s\t%s\n' "${v:-un outil de ce dépôt}" "$geste_jeton"
            return 0
        fi
    fi
    return 0
}

# LE REFUS DIT CE QU'IL ATTEND, ET IL DIT LE GESTE. Les lignes de conseil sont passées par
# l'appelant — ce qu'il coûte et comment s'en sortir n'appartient qu'à lui —, et elles sont
# alignées sur la largeur de son nom. DEUX GROUPES, SÉPARÉS PAR « -- » : ce qu'un appelant doit
# dire d'une CONSTRUCTION concurrente n'est pas ce qu'il doit dire d'une machine occupée autrement,
# et un texte unique aurait forcé l'un des deux à mentir. Le groupe « construction » vient en
# premier parce qu'il est celui qui EXISTAIT : son rendu doit rester mot pour mot celui d'avant.
# LE GESTE EST IMPRIMÉ AVANT LES CONSEILS quand il y en a un : sur un processus qui ne finit jamais
# — suite interbloquée, binaire orphelin d'un `cargo test` interrompu — « --attendre » brûle son
# plafond puis sort en 3 comme le refus, et tuer le processus est la SEULE issue autre que
# désarmer la garde entière.
# Rend 0 si la voie est libre, 3 si RIEN N'A ÉTÉ MESURÉ.
sonde_refuser_ou_attendre() {
    local appelant="$1" attendre="$2" plafond="$3"; shift 3
    local marge occ cause detail geste debut tour ecoule l groupe=construction
    local -a conseils_construction=() conseils_autres=() conseils=()
    for l in "$@"; do
        if [ "$l" = "--" ]; then groupe=autres; continue; fi
        if [ "$groupe" = construction ]; then conseils_construction+=("$l"); else conseils_autres+=("$l"); fi
    done
    marge="$(printf '%*s' $(( ${#appelant} + 3 )) '')"
    occ="$(sonde_occupation)"
    [ -n "$occ" ] || return 0
    cause="${occ%%$'\t'*}"
    l="${occ#*$'\t'}"
    detail="${l%%$'\t'*}"
    geste="${l#*$'\t'}"

    if [ "$attendre" -eq 0 ] || [ "$plafond" -le 0 ]; then
        if [ "$cause" = construction ]; then
            echo "$appelant : REFUS — une construction tient déjà « $detail »." >&2
            conseils=(${conseils_construction[@]+"${conseils_construction[@]}"})
        elif [ "$cause" = suite ]; then
            echo "$appelant : REFUS — une suite de tests tourne déjà ($detail)." >&2
            conseils=(${conseils_autres[@]+"${conseils_autres[@]}"})
        else
            echo "$appelant : REFUS — un travail lourd de ce dépôt est déjà en cours ($detail)." >&2
            conseils=(${conseils_autres[@]+"${conseils_autres[@]}"})
        fi
        if [ -n "$geste" ]; then
            if [ "$cause" = suite ]; then
                echo "${marge}S'il ne finit jamais — suite interbloquée, binaire orphelin d'un « cargo test »" >&2
                echo "${marge}interrompu, harnais arrêté sous un débogueur — « --attendre » n'en sortira PAS" >&2
                echo "${marge}non plus : il brûle son plafond puis rend 3, comme ce refus. Le geste est : $geste" >&2
            else
                echo "${marge}Si c'est le reste d'un outil interrompu, « --attendre » n'en sortira PAS non plus :" >&2
                echo "${marge}il brûle son plafond puis rend 3, comme ce refus. Le geste est : $geste" >&2
            fi
        fi
        for l in ${conseils[@]+"${conseils[@]}"}; do echo "${marge}$l" >&2; done
        return 3
    fi

    debut=$(date +%s)
    tour=0
    if [ "$cause" = construction ]; then
        echo "$appelant : une construction tient « $detail » — attente (plafond ${plafond} s)."
    elif [ "$cause" = suite ]; then
        echo "$appelant : une suite de tests tourne ($detail) — attente (plafond ${plafond} s)."
    else
        echo "$appelant : un travail lourd de ce dépôt est en cours ($detail) — attente (plafond ${plafond} s)."
    fi
    while [ -n "$(sonde_occupation)" ]; do
        sleep 5
        tour=$(( tour + 1 ))
        ecoule=$(( $(date +%s) - debut ))
        if [ "$ecoule" -ge "$plafond" ]; then
            echo "$appelant : ${ecoule} s d'attente, plafond atteint — RIEN N'A ÉTÉ MESURÉ." >&2
            if [ -n "$geste" ]; then echo "${marge}Si c'est un reste qui ne finira jamais, le geste est : $geste" >&2; fi
            return 3
        fi
        # Une attente muette se lit comme un blocage : on donne signe de vie toutes les ~30 s.
        if [ $(( tour % 6 )) -eq 0 ]; then echo "$appelant : toujours en attente depuis ${ecoule} s…"; fi
    done
    if [ "$cause" = construction ]; then
        echo "$appelant : verrou libéré après $(( $(date +%s) - debut )) s."
    else
        echo "$appelant : la machine s'est libérée après $(( $(date +%s) - debut )) s."
    fi
    return 0
}

# --- EXÉCUTÉ AU LIEU D'ÊTRE SOURCÉ : LE GESTE DE DIAGNOSTIC --------------------------------------
# `${BASH_SOURCE[0]}` != `$0` quand le fichier est sourcé. C'est la seule dérivation fiable, et elle
# ne dépend d'aucun nom de fichier.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    set -euo pipefail
    if ! sonde_eprouver "sonde-machine"; then
        echo "sonde-machine : AUCUN signal utilisable — RIEN N'A ÉTÉ MESURÉ." >&2
        exit 2
    fi
    for d in ${sonde_cibles[@]+"${sonde_cibles[@]}"}; do
        echo "sonde-machine : répertoire d'artefacts = $d$( [ -d "$d" ] || printf ' (absent)' )"
    done
    echo "sonde-machine : signal construction = $sonde_construction_utilisable, signal exécution = $sonde_execution_utilisable, jeton = $sonde_jeton_utilisable"
    occupation="$(sonde_occupation)"
    if [ -n "$occupation" ]; then
        reste="${occupation#*$'\t'}"
        echo "sonde-machine : PRISE — ${occupation%%$'\t'*} : ${reste%%$'\t'*}"
        exit 3
    fi
    # LE VERDICT EST QUALIFIÉ, ET LE CHIFFRE EST RELEVÉ, PAS ESTIMÉ : « aucune » aurait été une
    # garantie que ce fichier ne peut pas donner (voir l'en-tête, ce qu'il ne tient pas).
    # LE RECENSEMENT EST REFAIT ICI, ET C'EST DÉLIBÉRÉ : `sonde_occupation` lit `executions_sous`
    # à travers une substitution de processus, donc dans un SOUS-SHELL — ses compteurs n'en
    # remontent pas. Un chiffre pris là aurait affiché « 0 des 0 », c'est-à-dire un instrument qui
    # se tait en ayant l'air de parler. Un relevé de plus coûte 27 ms, mesurés.
    if [ "$sonde_execution_utilisable" -eq 1 ]; then
        executions_sous ${sonde_cibles[@]+"${sonde_cibles[@]}"} >/dev/null
        echo "sonde-machine : LIBRE — aucune construction ni suite de tests QUE JE PUISSE VOIR" \
             "(${sonde_illisibles} des ${sonde_processus} processus ont un exécutable illisible)."
    else
        echo "sonde-machine : LIBRE — aucune construction, et la sonde d'exécution est DÉSARMÉE :" \
             "une suite en cours N'AURAIT PAS ÉTÉ VUE."
    fi
    exit 0
fi
