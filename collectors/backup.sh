#!/bin/sh
# Backup compact de la base SOC (VACUUM INTO via le binaire) + rotation (garde 7).
set -eu
DIR="${PLUME_BACKUP_DIR:-/var/lib/plume/backups}"
mkdir -p "$DIR"
/usr/local/bin/plume-daemon backup "$DIR/plume-$(date +%Y%m%d-%H%M%S).db"
# rotation : ne garde que les 7 plus récents
ls -1t "$DIR"/plume-*.db 2>/dev/null | tail -n +8 | xargs -r rm -f
