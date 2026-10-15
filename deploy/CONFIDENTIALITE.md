# Confidentialité (P4)

## Transport — TLS
Le daemon sert en HTTP sur la boucle locale par défaut (bind configurable par `PLUME_ADDR`). Pour le réseau, deux voies :
- **TLS natif** : `PLUME_TLS_CERT` + `PLUME_TLS_KEY` (chemins PEM lisibles par l'utilisateur du démon). Un PEM illisible
  arrête le démon au lieu de le faire retomber en HTTP ; HSTS et l'attribut `Secure` des cookies ne sont émis qu'avec ce TLS.
  Aucun certificat client n'est vérifié : un mTLS se pose sur un mandataire.
- **une terminaison TLS devant** (le cookie de session n'y est alors pas marqué `Secure` : ne servez pas le même nom en clair) :
  - **Caddy** : `soc.tondomaine.tld { reverse_proxy 127.0.0.1:7000 }` (TLS auto Let's Encrypt).
  - **nginx / traefik** : `proxy_pass http://127.0.0.1:7000;` + certificat.
- **k3s** : l'Ingress livré est en TLS seul (entrée `websecure`, certificat du `Secret` `soc-tls`, cf. `deploy/k3s.yaml`), `Host` = `PLUME_HOST`.
- Cert auto-signé rapide : `openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj /CN=soc.local`.

## Auth des agents — tokens (recommandé)
Sur le central, crée un token par machine (révocable, ≠ mot de passe partagé). **La portée se DÉCLARE** :
```
sudo env PLUME_CONFIG=/etc/plume/soc.conf /usr/local/bin/plume-daemon token agent-example agent.example.org   # MACHINE : lié à cet hôte (hôte attesté à l'écriture)
sudo env PLUME_CONFIG=/etc/plume/soc.conf /usr/local/bin/plume-daemon token relais-siem --relais             # RELAIS  : forwarder multi-hôtes (hôte NON attesté)
```
C'est la forme hôte natif : `sudo` ne transmet pas le `PLUME_CONFIG` de l'unité, et sans lui le jeton
s'écrit dans une autre base que celle du démon. En Docker et en k3s, la sous-commande se lance dans le
conteneur du démon (`docker compose exec soc plume-daemon token …`,
`kubectl -n soc exec deploy/soc -- plume-daemon token …`). Sur un central neuf, le démon démarre **avant** toute sous-commande
([`../docs/INSTALLER-SANS-OUVRIR-DE-BRECHE.md` §1.1](../docs/INSTALLER-SANS-OUVRIR-DE-BRECHE.md#11-démarrer-le-démon-une-fois-avant-toute-sous-commande-qui-écrit-dans-la-base)).
La forme à deux arguments (`plume-daemon token <nom>`) est **refusée** : elle produisait un jeton non lié,
avec lequel une enveloppe `{"host":"CONTROLEUR-DE-DOMAINE-USURPE"}` était acceptée (202) et stockée sous ce
nom-là (mesuré le 2026-08-02). Le token s'affiche **une seule fois**.

Puis sur l'agent, dans `/etc/plume/plume.conf` : `PLUME_TOKEN=<token>`. **Ne le passez jamais sur une ligne
de commande** : `sudo` journalise sa commande complète, et le capteur `journal` expédie ces lignes au SOC —
le jeton y arriverait en clair (cf. l'avertissement du `README.md`).

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
  `PLUME_DB_KEY=<passphrase>` (lisible via `/proc/<pid>/environ`), **avant le premier démarrage**.
  **Sans clé fournie, une base NEUVE naît chiffrée quand même** (`P9.6-a`) : le démon engendre une clé
  `0600` à `PLUME_DB_KEY_AUTO_PATH`, sinon `<PLUME_DB>.key`, et l'annonce ; à mettre à l'abri hors de la
  machine, puis `PLUME_DB_KEY_ESCROWED=1`. Elle protège du vol du disque, pas d'une machine compromise.
  **Une base EXISTANTE en clair n'est jamais convertie par un démarrage** : une clé posée dessus fait
  refuser le démarrage, qui nomme le geste explicite `plume-daemon chiffrer-au-repos` (irréversible) ; une
  base mise en service avant `P9.6-a` sans clé reste donc en clair tant que ce geste n'a pas eu lieu.
  **Perte de la clé = perte de la base.**
  Les deux variables se lisent **dans l'environnement OU dans `PLUME_CONFIG`** (`/etc/plume/soc.conf`,
  0640, sur un hôte systemd) — l'environnement gagne. **P8.7-b, 2026-08-09** : avant cette date la voie
  qui OUVRE la base ne lisait que l'environnement, alors que le tier froid lisait aussi le fichier ; une
  clé posée dans `soc.conf` seul chiffrait donc les jours-files Parquet et laissait la base chaude — les
  derniers jours, donc les incidents récents — **en clair sur le disque, sans un mot**. Une seule voie
  désormais, et la bascule est annoncée au démarrage sur les hôtes concernés.
- **Complémentaire** : placer `/var/lib/plume` sur un volume chiffré (LUKS, gocryptfs) protège aussi les
  fichiers *autour* de la base (spool, backups en clair, journaux). Les deux se combinent.

> **Le backup compressé n'écrit PAS de clair sur disque.** `plume-daemon backup --compress` et le
> scheduler natif sérialisent un **dump typé** directement dans `zstd` → `age` → fichier `.age` : la base
> est déchiffrée **en mémoire** par SQLCipher, ligne par ligne, et aucun fichier intermédiaire n'est créé.
> Le répertoire de staging reste vide pendant toute la sauvegarde — c'est une garde **mesurée**, pas une
> intention (`backup_streaming_leaves_the_staging_dir_empty_under_watch` surveille le répertoire en continu
> pendant un backup réel, et le même test échoue si on force le chemin historique).
>
> ⚠️ **Deux cas rouvrent la fenêtre de clair transitoire**, et il faut les connaître : (1) un **schéma hors
> périmètre** du dump typé (FTS5 *contentless* — donc `PLUME_FTS_FIELDS=1` — ou toute autre table virtuelle
> non représentable) déclenche un **repli automatique** sur `sqlcipher_export`, qui matérialise la base
> **entière en clair** dans le staging le temps du cycle ; (2) l'échappatoire explicite
> `PLUME_BACKUP_FORCE_PLAINTEXT_EXPORT=1`. Dans ces deux cas le clair est effacé par un garde RAII en fin de
> cycle (avec balayage des orphelins au backup suivant), mais la fenêtre existe : orientez alors
> `PLUME_BACKUP_STAGING_DIR` vers un volume **éphémère**, hors stockage durable.
>
> Dans tous les cas, le répertoire de destination (`PLUME_BACKUP_DEST`) contient des sauvegardes chiffrées
> mais doit rester aussi protégé que la base. Le mode `plume-daemon backup <fichier>` (sans `--compress`,
> celui du timer hôte) fait un `VACUUM INTO` et reste chiffré de bout en bout si la base l'est.

## Secrets
Creds notifier / tokens stockés en base ou config `0640`. En multi-hôte : tokens révocables + volume chiffré. La clé de signature du ledger est en `0600` (hors base).
