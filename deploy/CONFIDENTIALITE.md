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
Puis sur l'agent : `PLUME_TOKEN=<token>` (bootstrap-agent.sh). Le token n'est accepté que sur `/api/ingest`.

## Au repos — chiffrement de la base
- **Simple (recommandé ici)** : place `/var/lib/plume` sur un volume chiffré (LUKS, ou gocryptfs comme `/home`). Zéro modif de code, transparent.
- **Fort (option lourde)** : recompiler avec SQLCipher (`rusqlite` feature `bundled-sqlcipher-vendored-openssl`) + clé via `PRAGMA key` au démarrage. Non activé par défaut (build + OpenSSL + gestion de clé).

## Secrets
Creds notifier / tokens stockés en base ou config `0640`. En multi-hôte : tokens révocables + volume chiffré. La clé de signature du ledger est en `0600` (hors base).
