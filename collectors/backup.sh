#!/bin/sh
# plume-source: aucune
# Backup compact de la base SOC (VACUUM INTO via le binaire) + rotation (garde 7).
set -eu
DIR="${PLUME_BACKUP_DIR:-/var/lib/plume/backups}"
mkdir -p "$DIR"
/usr/local/bin/plume-daemon backup "$DIR/plume-$(date +%Y%m%d-%H%M%S).db"
# rotation : ne garde que les 7 plus récents
ls -1t "$DIR"/plume-*.db 2>/dev/null | tail -n +8 | xargs -r rm -f
# P7.20-f — les jours froids scellés (tier froid) sont mis à l'abri À CÔTÉ des archives, sous $DIR/cold/…,
# par le binaire lui-même : copie verbatim incrémentale, jamais de suppression. Un binaire bâti sans
# --features cold_tier n'a pas cette sous-commande (son aide la dit INDISPONIBLE) : il n'y a alors aucun
# jour froid à mettre à l'abri, et la ligne ci-dessous le dit au journal au lieu de se taire.
if /usr/local/bin/plume-daemon --help 2>/dev/null | grep -q 'cold-escrow <destination>'; then
  /usr/local/bin/plume-daemon cold-escrow "$DIR"
else
  echo "cold-escrow : tier froid absent de ce binaire (bâti sans --features cold_tier) -> aucun jour froid à mettre à l'abri"
fi
