#!/usr/bin/env bash
# L'IDENTITE CANONIQUE, ECRITE UNE SEULE FOIS, ET VERIFIEE LA OU CA LIE.
# Appele par `.githooks/pre-commit` (boucle de retour locale, contournable) ET par la CI
# sur la plage poussee (non contournable). Un hook seul ne suffit pas : il se contourne
# avec --no-verify et il est absent de tout clone frais, or c'est justement un clone frais
# qui herite de la configuration git GLOBALE de la station.
# Usage : verifier-identite.sh <plage git>   (ex. HEAD~5..HEAD)  ou  --index (avant commit)
# Sorties : 0 = canonique · 1 = REFUS (identite non canonique) · 2 = REFUS DE CONCLURE.
set -uo pipefail
CANONIQUE_NOM="guatxlabs"
CANONIQUE_MEL="noreply@guatx.com"

refuse() { printf 'REFUS — identite non canonique.\n  attendu : %s <%s>\n%s\n' \
  "$CANONIQUE_NOM" "$CANONIQUE_MEL" "$1" >&2; exit 1; }

if [ "${1:-}" = "--index" ]; then
  n="$(git config user.name  || true)"; m="$(git config user.email || true)"
  [ "$n" = "$CANONIQUE_NOM" ] && [ "$m" = "$CANONIQUE_MEL" ] || refuse \
"  configure : $n <$m>
  poser LOCALEMENT dans ce clone :
    git config user.name  \"$CANONIQUE_NOM\"
    git config user.email \"$CANONIQUE_MEL\""
  exit 0
fi

plage="${1:?usage: verifier-identite.sh <plage>|--index}"

# P7.19-a — UNE PLAGE ILLISIBLE EST UN REFUS DE CONCLURE, PAS UN ACQUITTEMENT.
# Mesure du 2026-08-26 : appele sur une plage inexistante, ce script ecrivait
# « fatal: Invalid revision range » et rendait 0. Le `|| true` — necessaire, lui, car `grep -v`
# rend 1 quand il ne trouve RIEN, c'est-a-dire dans le cas SAIN — avalait aussi l'echec de
# `git log`. La garde acquittait donc ce qu'elle n'avait pas pu lire, et c'est le hook local
# qui en heritait. Le code de sortie de `git log` est desormais lu AVANT le filtre, separement.
# Une plage VIDE mais valide (« HEAD..HEAD ») reste un succes : elle se distingue d'une plage
# invalide par le code de sortie de `git log`, pas par la vacuite de sa sortie.
#
# LA SORTIE D'ERREUR N'EST FONDUE QUE SUR LE CHEMIN D'ECHEC, et c'est un correctif mesure.
# Tant que `2>&1` valait aussi sur le chemin de SUCCES, tout ce que git ecrivait la devenait une
# ligne de « commit fautif ». Mesure du 2026-08-26, temoin POSITIF : sur une branche et une
# etiquette portant le meme nom, `git log <nom>` rend 0 en ecrivant « warning: refname … is
# ambiguous. » ; ce script rendait alors 1 et designait cette ligne d'avertissement comme un
# commit fautif — un coupable FABRIQUE, sur lequel l'exploitant qui debogue un rouge perd son
# temps. Temoin NEGATIF : la meme plage sans ambiguite rendait 0. L'avertissement n'est plus
# perdu pour autant : il est REPETE tel quel, comme avertissement, sans devenir un verdict.
#
# CODES DE SORTIE : 0 = canonique · 1 = REFUS (identite non canonique) · 2 = REFUS DE CONCLURE
# (la plage n'a pas pu etre lue). Les confondre reviendrait a lire « rien de fautif » la ou il
# faut lire « rien n'a ete lu ».
erreurs="$(mktemp)"
trap 'rm -f "$erreurs"' EXIT
if ! journal="$(git log --format='%h %an <%ae> | %cn <%ce>' "$plage" 2>"$erreurs")"; then
  printf 'REFUS DE CONCLURE — plage « %s » illisible : aucune identite lue.\n' "$plage" >&2
  sed 's/^/  /' "$erreurs" >&2
  printf '  Une garde qui ne peut pas LIRE ne doit pas ACQUITTER.\n' >&2
  exit 2
fi
if [ -s "$erreurs" ]; then
  printf 'AVERTISSEMENT — git a ecrit ceci en lisant la plage « %s » :\n' "$plage" >&2
  sed 's/^/  /' "$erreurs" >&2
  printf '  La plage a ete lue malgre tout ; ces lignes ne sont PAS des commits.\n' >&2
fi
mauvais="$(printf '%s\n' "$journal" | grep -v '^$' \
  | grep -v "^[0-9a-f]* $CANONIQUE_NOM <$CANONIQUE_MEL> | $CANONIQUE_NOM <$CANONIQUE_MEL>$" || true)"
[ -z "$mauvais" ] || refuse "  commits fautifs (auteur | committer) :
$mauvais"
