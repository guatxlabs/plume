# Confidentialité (P4)

## Transport — TLS
Le daemon sert en HTTP (localhost par défaut, bind configurable). Pour le réseau, mets-le derrière une terminaison TLS :
- **Caddy** : `soc.tondomaine.tld { reverse_proxy 127.0.0.1:7000 }` (TLS auto Let's Encrypt).
- **nginx / traefik** : `proxy_pass http://127.0.0.1:7000;` + certificat.
- **k3s** : Ingress TLS (cf. `deploy/k3s.yaml`), `Host` = `PLUME_HOST`.
- Cert auto-signé rapide : `openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj /CN=soc.local`.

## Auth des agents — tokens (recommandé)
Sur le central, crée un token par machine (révocable, ≠ mot de passe partagé) :
```
plume-daemon token example-host      # affiche le token UNE fois
```
Puis sur l'agent : `PLUME_TOKEN=<token>` (bootstrap-agent.sh).

**Portée réelle d'un token d'agent** — un Bearer d'agent n'établit une identité que sur les **9 chemins
machine** ci-dessous (défaut fermé : partout ailleurs → 401, jamais d'accès UI/admin) — cf.
`agent_bearer_path`, `daemon/src/auth.rs` :

| Usage | Chemins |
|---|---|
| Ingestion | `/api/ingest` · `/api/ingest/minio` · `/api/ingest/journal` |
| Métriques / logs / traces | `/api/metrics/prom` · `/api/metrics/write` · `/loki/api/v1/push` · `/v1/traces` |
| Responder (actions) | `/api/actions/pending` · `/api/actions/result` |
| Mode Engagement (pull enforcer) | `/api/engagements/active` |

S'authentifier n'est pas être autorisé : l'autorisation reste `route_min_role` **plus** un re-contrôle
`role=='agent'` **lié à l'hôte** dans le handler (un agent ne peut agir que sur les actions de son hôte).

## Au repos — chiffrement de la base
- **Natif (SQLCipher) — aucune recompilation nécessaire.** SQLCipher est **déjà compilé** dans le binaire
  livré (`rusqlite` avec `bundled-sqlcipher-vendored-openssl`, cf. `daemon/Cargo.toml`) ; il ne manque
  que la **clé**. Posez `PLUME_DB_KEY_FILE=/chemin/vers/la/cle` (préféré : fichier monté en lecture seule,
  **fail-closed** si absent → le daemon refuse de démarrer plutôt que d'ouvrir la base en clair) ou
  `PLUME_DB_KEY=<passphrase>` (lisible via `/proc/<pid>/environ`). Une base neuve est créée chiffrée
  d'office ; une base en clair existante est convertie au boot (idempotent).
  **Sans clé, la base est EN CLAIR** — c'est le défaut. **Perte de la clé = perte de la base.**
- **Complémentaire** : placer `/var/lib/plume` sur un volume chiffré (LUKS, gocryptfs) protège aussi les
  fichiers *autour* de la base (spool, backups en clair, journaux). Les deux se combinent.

> ⚠️ **Le backup compressé écrit un export EN CLAIR transitoire.** `plume-daemon backup --compress` et le
> scheduler natif produisent `age(zstd(SQLite en clair))` : ils passent par un `sqlcipher_export` vers un
> fichier temporaire **en clair, sur disque**, à côté de la destination (effacé par *shred* en fin de
> cycle, avec balayage des orphelins au démarrage). Conséquence : le répertoire de destination
> (`PLUME_BACKUP_DEST`) doit être considéré aussi sensible que la base elle-même. Le mode
> `plume-daemon backup <fichier>` (sans `--compress`, celui du timer hôte) fait un `VACUUM INTO` et reste
> chiffré de bout en bout si la base l'est.

## Secrets
Creds notifier / tokens stockés en base ou config `0640`. En multi-hôte : tokens révocables + volume chiffré. La clé de signature du ledger est en `0600` (hors base).
