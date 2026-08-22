#!/usr/bin/env bash
# P3.8-a — LE CAPTEUR D'INTÉGRITÉ VOIT UN DROP-IN SYSTEMD, ET IL LE DIT AVEC LE NOM DE L'UNITÉ PARENTE.
#
# LE DÉFAUT QUE CE TÉMOIN REND NON-RÉINTRODUISIBLE. `collectors/integrity.sh` ne hachait que
# `/etc/systemd/system/*.service` et `*.timer`. Ni `/run/systemd/system`, ni `/usr/local/lib/systemd/system`,
# ni les drop-ins `*.d/*.conf`, ni les `.socket`/`.path`. Un drop-in qui ajoute un `ExecStartPre=` à une
# unité existante est une persistance ordinaire ; il ne produisait AUCUN événement, et la règle livrée
# « vecteur de persistance ajouté » (T1543) tournait sur une liste qui ne contenait pas le fichier. C'est un
# silence complet : un SOC sans cette alerte a exactement l'apparence d'un SOC sain.
#
# CE QUE CE TÉMOIN EXERCE — LE CAPTEUR TEL QU'IL EST LIVRÉ, CONTRE UN RÉPERTOIRE D'UNITÉS TEMPORAIRE.
# `PLUME_UNIT_ROOT` préfixe chaque répertoire dérivé : rien de l'hôte n'est lu par la famille `unit`, rien
# n'y est écrit. Le chemin de recherche est DÉRIVÉ par le capteur (`systemd-analyze unit-paths`) et relayé
# ici par un bouchon qui rend, en plus des répertoires documentés, un répertoire que la table de
# `systemd.unit(5)` NE CONTIENT PAS : une unité posée là n'est vue QUE si la dérivation a servi. C'est le
# témoin positif de la dérivation, et son négatif est le même fichier sous un PATH sans l'outil.
#   (a) drop-in `x.service.d/zz.conf`  -> événement `kind=unit change=ajout severity=3`, `unit=x.service`,
#                                         `unit_form=drop-in`, et il satisfait la REQUÊTE de la règle T1543
#                                         LUE dans `daemon/src/seeds.rs` (jamais recopiée ici) ;
#   (b) `y.socket` sous `/run/systemd/system` -> événement, `unit=y.socket` ;
#       `v.path` sous le répertoire dérivé-seulement -> événement (la dérivation a servi) ;
#       un `.target` -> AUCUN événement (type qui n'exécute rien : témoin négatif du type) ;
#       un drop-in hors du chemin de recherche -> AUCUN événement (témoin négatif du chemin) ;
#   (c) un répertoire d'unités PRÉSENT MAIS ILLISIBLE -> un AVEU (`source_refusee`, le répertoire nommé),
#       la référence N'EST PAS promue, et le capteur continue (le drop-in posé ailleurs est signalé) ;
#   (d) la VOIE est dite : `unit_dirs_from=systemd-analyze` avec l'outil, `systemd.unit(5)` sans lui — et
#       sans lui, le répertoire dérivé-seulement n'est plus vu ; l'outil PRÉSENT mais en échec, ou rendu
#       sans chemin, produit un aveu `missing-dependency` qui nomme la cause.
#
# CE QU'IL NE PROUVE PAS, ET C'EST DIT : que la liste documentée de repli est à jour vis-à-vis d'un systemd
# futur (elle porte sa date et sa source dans le capteur) ; que la règle semée est ACTIVÉE sur une instance
# donnée (c'est une ligne de base de données, hors de portée d'un témoin de fichier). Le témoin (c) exige
# un utilisateur NON root : root lit un répertoire en mode 000, et le témoin refuse alors de conclure
# plutôt que de rendre un vert qui n'aurait rien mesuré.
#
# Usage : .github/scripts/verifier-fim-couvre-les-unites-systemd.sh
set -euo pipefail

racine="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
capteur="$racine/collectors/integrity.sh"
lib="$racine/collectors/lib.sh"
seeds="$racine/daemon/src/seeds.rs"
[ -f "$capteur" ] && [ -f "$lib" ] && [ -f "$seeds" ] || { echo "::error::capteur, bibliothèque ou seeds.rs introuvable sous $racine" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "::error::python3 absent — les enveloppes JSON ne peuvent pas être lues, le témoin refuse de conclure" >&2; exit 2; }

T="$(mktemp -d)"
nettoyer() { chmod -R u+rwx "$T" 2>/dev/null || true; rm -rf "$T"; }
trap nettoyer EXIT

echecs=0
rouge() { echo "::error::$*"; echecs=$((echecs + 1)); }
vert()  { echo "   ok — $*"; }

# --- La requête de la règle livrée, LUE dans seeds.rs ----------------------------------------------
# Le prédicat n'est pas recopié : si la règle change de forme, c'est contre la nouvelle forme que
# l'événement est jugé. Le nom de la règle est ce qui l'identifie dans le seed.
requete="$(grep -A1 -F '("Hôte: vecteur de persistance ajouté' "$seeds" | sed -n 's/^ *"\(search [^"]*\)".*/\1/p' | head -1)"
[ -n "$requete" ] || { echo "::error::la requête de la règle « vecteur de persistance ajouté » est introuvable dans seeds.rs — le témoin refuse de conclure" >&2; exit 2; }
echo "règle T1543 lue dans seeds.rs : $requete"

# --- Le PATH SANS `systemd-analyze`, dérivé du PATH réel (jamais une liste d'outils) -----------------
sans="$T/bin-sans"; mkdir -p "$sans"
IFS=: read -r -a dirs <<<"$PATH"
for d in "${dirs[@]}"; do
  [ -d "$d" ] || continue
  for f in "$d"/*; do
    b="${f##*/}"
    [ "$b" = systemd-analyze ] && continue
    [ -x "$f" ] && [ ! -e "$sans/$b" ] && ln -s "$f" "$sans/$b" 2>/dev/null || true
  done
done
# Le PATH AVEC un bouchon `systemd-analyze` : il rend des chemins ABSOLUS comme l'outil réel, et UN
# répertoire que la table documentée ne contient pas (`/opt/plume-temoin-seulement/units`).
avec="$T/bin-avec"; mkdir -p "$avec"; ln -s "$sans"/* "$avec"/ 2>/dev/null || true
cat > "$avec/systemd-analyze" <<'STUB'
#!/bin/sh
[ "$1" = unit-paths ] || exit 1
printf '%s\n' /etc/systemd/system /run/systemd/system /usr/local/lib/systemd/system /opt/plume-temoin-seulement/units
STUB
chmod 0755 "$avec/systemd-analyze"
# Le PATH avec un bouchon qui ÉCHOUE, et un autre qui rend 0 sans aucun chemin.
echoue="$T/bin-echoue"; mkdir -p "$echoue"; ln -s "$sans"/* "$echoue"/ 2>/dev/null || true
printf '#!/bin/sh\nexit 1\n' > "$echoue/systemd-analyze"; chmod 0755 "$echoue/systemd-analyze"
vide="$T/bin-vide"; mkdir -p "$vide"; ln -s "$sans"/* "$vide"/ 2>/dev/null || true
printf '#!/bin/sh\nprintf "%%s\\n" "bavardage sans chemin"\nexit 0\n' > "$vide/systemd-analyze"; chmod 0755 "$vide/systemd-analyze"

# --- Un bac : racine d'unités, spool, état ; un fichier critique à soi pour ne rien lire de l'hôte -----
bac() {  # $1=nom -> pose $racine_u $spool $etat
  racine_u="$T/$1/root"; spool="$T/$1/spool"; etat="$T/$1/state"
  mkdir -p "$racine_u/etc/systemd/system" "$racine_u/run/systemd/system" "$racine_u/opt/plume-temoin-seulement/units" "$spool" "$etat"
  printf '[Service]\nExecStart=/bin/true\n' > "$racine_u/etc/systemd/system/x.service"
  printf '[Socket]\nListenStream=1\n'     > "$racine_u/run/systemd/system/y.socket"
  printf '[Service]\nExecStart=/bin/true\n' > "$racine_u/opt/plume-temoin-seulement/units/w.service"
  printf 'temoin\n' > "$racine_u/critique"
}
passe() {  # $1=PATH — exécute le capteur TEL QU'IL EST LIVRÉ ; une exécution qui échoue est un rouge
  if ! env -i PATH="$1" HOME="$T" PLUME_LIB="$lib" PLUME_SPOOL="$spool" PLUME_STATE="$etat" \
       PLUME_UNIT_ROOT="$racine_u" PLUME_FIM_FILES="$racine_u/critique" PLUME_FIM_PRUNE="/" \
       sh "$capteur" >"$T/sortie" 2>"$T/erreur"; then
    rouge "le capteur sort non nul : $(head -c 400 "$T/erreur")"
  fi
  sleep 1   # la clé d'identité porte le mtime à la seconde ; deux passes dans la même seconde se confondent
}
# Les événements `integrity` et les aveux du spool, en JSON lignes : {kind,path,...} / {aveu:detail}
lire() {
  python3 - "$spool" <<'PY'
import json, os, sys
spool = sys.argv[1]
for nom in sorted(os.listdir(spool)):
    if nom.startswith('.') or not nom.endswith('.json'):
        continue
    doc = json.load(open(os.path.join(spool, nom), encoding='utf-8'))
    for ev in doc.get('events', []):
        f = ev.get('fields', {})
        if f.get('type') == 'collector-availability':
            print(json.dumps({'aveu': f.get('reason', ''), 'detail': f.get('detail', '')}))
        elif ev.get('category') == 'integrity':
            print(json.dumps({'source': ev.get('source'), 'severity': ev.get('severity'), 'message': ev.get('message'), **f}))
PY
}
# satisfait <json-ligne> <requête> : l'événement satisfait-il chaque terme `k=v` / `k>=n` de la requête ?
satisfait() {
  python3 - "$1" "$2" <<'PY'
import json, sys
ev, req = json.loads(sys.argv[1]), sys.argv[2]
termes = req.split('|')[0].split()
assert termes[0] == 'search', req
ok = True
for t in termes[1:]:
    if '>=' in t:
        k, v = t.split('>=', 1); ok &= float(ev.get(k, -1e9)) >= float(v)
    elif '=' in t:
        k, v = t.split('=', 1); ok &= str(ev.get(k)) == v
    else:
        sys.exit(2)
sys.exit(0 if ok else 1)
PY
}
compter() { lire | grep -c "$1" || true; }

# ==================================================================================================
echo "— (a)(b) drop-in, socket, path dérivé-seulement, .target, drop-in hors chemin — avec l'outil"
bac a
passe "$avec"
base="$etat/integrity.base"
[ -f "$base" ] || rouge "aucune référence posée au premier passage"
# INSTRUMENT : la première passe DOIT avoir vu les trois unités semées, sinon le bac n'est pas lu.
for u in etc/systemd/system/x.service run/systemd/system/y.socket opt/plume-temoin-seulement/units/w.service; do
  grep -qF "unit|$racine_u/$u|" "$base" || rouge "INSTRUMENT : la référence ne contient pas $u — le capteur ne lit pas le bac"
done
mkdir -p "$racine_u/etc/systemd/system/x.service.d" "$racine_u/srv/hors-chemin/q.service.d"
printf '[Service]\nExecStartPre=/tmp/persistance\n' > "$racine_u/etc/systemd/system/x.service.d/zz.conf"
printf '[Socket]\nListenStream=2\n'                > "$racine_u/run/systemd/system/n.socket"
printf '[Path]\nPathExists=/tmp/x\n'               > "$racine_u/opt/plume-temoin-seulement/units/v.path"
printf '[Unit]\nDescription=cible\n'               > "$racine_u/etc/systemd/system/t.target"
printf '[Service]\nExecStartPre=/tmp/x\n'          > "$racine_u/srv/hors-chemin/q.service.d/a.conf"
passe "$avec"
evts="$(lire)"
dropin="$(printf '%s\n' "$evts" | grep -F '"path": "'"$racine_u"'/etc/systemd/system/x.service.d/zz.conf"' || true)"
[ -n "$dropin" ] || rouge "(a) le drop-in x.service.d/zz.conf n'a produit AUCUN événement — la règle T1543 n'a rien à lire"
if [ -n "$dropin" ]; then
  printf '%s' "$dropin" | grep -q '"unit": "x.service"'     || rouge "(a) l'événement du drop-in ne porte pas le nom de l'unité PARENTE (unit=x.service) : $dropin"
  printf '%s' "$dropin" | grep -q '"unit_form": "drop-in"'  || rouge "(a) l'événement du drop-in ne se dit pas drop-in : $dropin"
  printf '%s' "$dropin" | grep -q '"kind": "unit"'          || rouge "(a) kind != unit : $dropin"
  printf '%s' "$dropin" | grep -q '"change": "ajout"'       || rouge "(a) change != ajout : $dropin"
  printf '%s' "$dropin" | grep -q '"unit_dirs_from": "systemd-analyze"' || rouge "(d) la voie dite n'est pas systemd-analyze alors que l'outil est là : $dropin"
  printf '%s' "$dropin" | grep -q 'sur x.service (drop-in)' || rouge "(a) le message ne nomme pas l'unité parente : $dropin"
  if satisfait "$dropin" "$requete"; then vert "(a) drop-in signalé, unit=x.service, et il satisfait la requête de la règle T1543"; else rouge "(a) l'événement du drop-in NE satisfait PAS la requête livrée « $requete » : $dropin"; fi
fi
sock="$(printf '%s\n' "$evts" | grep -F "/run/systemd/system/n.socket\"" || true)"
if [ -n "$sock" ] && printf '%s' "$sock" | grep -q '"unit": "n.socket"' && satisfait "$sock" "$requete"; then vert "(b) .socket sous /run/systemd/system signalé, unit=n.socket, requête satisfaite"; else rouge "(b) le .socket n'est pas signalé avec son nom d'unité : ${sock:-<rien>}"; fi
chemin="$(printf '%s\n' "$evts" | grep -F "/opt/plume-temoin-seulement/units/v.path\"" || true)"
if [ -n "$chemin" ] && printf '%s' "$chemin" | grep -q '"unit": "v.path"'; then vert "(b) .path sous le répertoire DÉRIVÉ-SEULEMENT signalé : la liste vient bien de l'outil"; else rouge "(b)/(d) le .path du répertoire dérivé-seulement n'est pas signalé — la dérivation n'a pas servi : ${chemin:-<rien>}"; fi
if printf '%s\n' "$evts" | grep -qF "/t.target\""; then rouge "(b) témoin NÉGATIF du type : un .target est signalé alors qu'il n'exécute rien"; else vert "(b) témoin négatif du type : le .target n'est pas signalé"; fi
if printf '%s\n' "$evts" | grep -qF "/srv/hors-chemin/"; then rouge "(b) témoin NÉGATIF du chemin : un drop-in HORS du chemin de recherche est signalé"; else vert "(b) témoin négatif du chemin : le drop-in hors chemin n'est pas signalé"; fi
if printf '%s\n' "$evts" | grep -q '"aveu": "missing-dependency"'; then rouge "(d) un aveu missing-dependency part alors que l'outil a rendu des chemins"; fi

# ==================================================================================================
echo "— (d) sans l'outil : repli systemd.unit(5), dit ; le répertoire dérivé-seulement n'est plus vu"
bac d
passe "$sans"
grep -qF "unit|$racine_u/etc/systemd/system/x.service|" "$etat/integrity.base" || rouge "INSTRUMENT (d) : la référence de repli ne contient pas x.service"
if grep -qF "plume-temoin-seulement" "$etat/integrity.base"; then rouge "(d) sans l'outil, le répertoire dérivé-seulement est hashé : la liste n'est pas celle de repli"; else vert "(d) sans l'outil, le répertoire dérivé-seulement n'est pas lu (repli sur la table documentée)"; fi
mkdir -p "$racine_u/etc/systemd/system/x.service.d"
printf '[Service]\nExecStartPre=/tmp/p\n' > "$racine_u/etc/systemd/system/x.service.d/yy.conf"
passe "$sans"
evts="$(lire)"
repli="$(printf '%s\n' "$evts" | grep -F "/x.service.d/yy.conf\"" || true)"
if [ -n "$repli" ] && printf '%s' "$repli" | grep -q '"unit_dirs_from": "systemd.unit(5)"'; then vert "(d) drop-in signalé par la voie de repli, et la voie est dite : systemd.unit(5)"; else rouge "(d) sans l'outil, le drop-in n'est pas signalé avec unit_dirs_from=systemd.unit(5) : ${repli:-<rien>}"; fi
if printf '%s\n' "$evts" | grep -q '"aveu": "missing-dependency"'; then rouge "(d) l'outil ABSENT produit un aveu : un hôte sans systemd crierait à chaque passage"; else vert "(d) outil absent : aucun aveu (ce n'est pas un défaut)"; fi

echo "— (d) l'outil PRÉSENT mais en échec, puis rendu sans chemin : repli AVOUÉ"
for variante in echoue vide; do
  bac "d-$variante"
  passe "$T/bin-$variante"
  aveu="$(lire | grep '"aveu": "missing-dependency"' || true)"
  attendu=source_illisible; [ "$variante" = vide ] && attendu=forme_inconnue
  if [ -n "$aveu" ] && printf '%s' "$aveu" | grep -q "$attendu" && printf '%s' "$aveu" | grep -q 'systemd.unit(5)'; then vert "(d) outil $variante : aveu missing-dependency ($attendu), repli nommé"; else rouge "(d) outil $variante : aucun aveu nommant $attendu — le repli est silencieux : ${aveu:-<rien>}"; fi
  grep -qF "unit|$racine_u/etc/systemd/system/x.service|" "$etat/integrity.base" || rouge "(d) outil $variante : le repli n'a pas hashé /etc/systemd/system"
done

# ==================================================================================================
echo "— (c) répertoire d'unités présent mais ILLISIBLE : aveu, référence non promue, capteur continue"
if [ "$(id -u)" = 0 ]; then
  rouge "(c) NON EXERÇABLE sous root : root lit un répertoire en mode 000, le témoin refuse de conclure"
else
  bac c
  passe "$avec"
  avant="$(sha256sum "$etat/integrity.base" | cut -d' ' -f1)"
  mkdir -p "$racine_u/etc/systemd/system/x.service.d"
  printf '[Service]\nExecStartPre=/tmp/c\n' > "$racine_u/etc/systemd/system/x.service.d/cc.conf"
  chmod 000 "$racine_u/run/systemd/system"
  passe "$avec"
  chmod 0755 "$racine_u/run/systemd/system"
  evts="$(lire)"
  apres="$(sha256sum "$etat/integrity.base" | cut -d' ' -f1)"
  aveu="$(printf '%s\n' "$evts" | grep '"aveu"' | grep -F "unit:$racine_u/run/systemd/system" || true)"
  if [ -n "$aveu" ] && printf '%s' "$aveu" | grep -q source_refusee; then vert "(c) le répertoire illisible est AVOUÉ (source_refusee), nommé"; else rouge "(c) répertoire illisible : aucun aveu qui le nomme — c'est un silence : $(printf '%s\n' "$evts" | grep '"aveu"' || echo '<aucun aveu>')"; fi
  [ "$avant" = "$apres" ] && vert "(c) la référence n'est PAS promue (ce que personne n'a lu n'entre pas dans le connu)" || rouge "(c) la référence a été promue malgré un répertoire non lu"
  if printf '%s\n' "$evts" | grep -qF "/x.service.d/cc.conf\""; then vert "(c) le capteur continue : le drop-in posé ailleurs est signalé"; else rouge "(c) le capteur s'est tu sur le drop-in posé dans un répertoire lisible"; fi
  if printf '%s\n' "$evts" | grep -qF "/run/systemd/system/y.socket\""; then rouge "(c) le contenu du répertoire illisible est signalé en ajout — c'est un constat fabriqué"; fi
fi

# ==================================================================================================
if [ "$echecs" -gt 0 ]; then
  echo "::error::$echecs écart(s) : le capteur d'intégrité ne couvre pas le chemin de recherche systemd comme il l'annonce (P3.8-a)."
  exit 1
fi
echo "OK — le capteur d'intégrité voit les drop-ins et les types d'unités du chemin de recherche dérivé, dit la voie, et avoue un répertoire illisible."
