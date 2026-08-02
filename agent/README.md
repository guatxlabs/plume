# plume-agent — cross-OS endpoint agent (#16)

Binaire **autonome** installé **sur le poste** (endpoint), pas dans le pod SOC. Il lit les sources
d'événements **natives** de l'OS, les tamponne sur disque (spool borné, *at-least-once*), et les POST
vers le endpoint d'ingest Plume — le même contrat de fil que les collecteurs `.sh` et l'émetteur HEC.

## Statut d'implémentation

| Brique | État |
| --- | --- |
| CLI `run/install/uninstall/status/test-ship` | **complet** |
| Config TOML + chemins par-OS | **complet** |
| Contrat d'enveloppe (`ts/host/kind/events[]`, event `ts/source/category/severity/message/fields/dedup`) | **complet** |
| Source **journald** (Linux) | **PLEINEMENT implémentée** (`journalctl -o json --after-cursor`, curseur persisté, `to_event`) |
| Spool disque en anneau borné + backoff (503-aware) + curseurs post-ack | **complet** |
| Expédition HTTP/1.1 (TCP + rustls, Bearer/Basic, CA interne, mTLS, insecure) | **complet** |
| Service **systemd** (Linux) install/enable/start + durcissement | **complet** |
| Source **Windows Event Log** (`EvtQuery/EvtNext/EvtRender` + `EvtCreateBookmark`) | **implémentée** — *validation runtime FAITE : Windows 11 24H2 (2026‑08‑02) **et** Windows Server 2022 build 20348, en **Server Core** comme en Desktop Experience, y compris promue contrôleur de domaine* |
| Source **macOS unified log** (`log show --style ndjson`) | **implémentée** (sous-processus `cfg(macos)` ; mapping CIM pur testé sur Linux) — *validation runtime : hôte macOS* |
| Service **launchd** (macOS) install/enable/start (`launchctl bootstrap`) | **implémenté** (plist testé) — *validation runtime : hôte macOS* |
| Service **Windows SCM** (`create_service`/dispatcher) via `windows-service` | **implémenté** — *validation runtime FAITE : `install` crée et démarre le service (Running, StartMode Auto) sur Windows 11, sur Server 2022 **Server Core** (aucune dépendance à l'interface graphique) et sur un contrôleur de domaine* |
| Source **FIM natif** (#58 : `type = "fim"`) | **implémentée** — Linux `fanotify`→`inotify` (réel) ; repli **scan planifié** sur les autres OS ; Windows `ReadDirectoryChangesW` **stubbé** (feature `fim_windows_native`). Cœur diff/baseline/CIM **testé** ; chemin syscall fanotify/inotify → *validation runtime : hôte Linux root* |
| Sources **génériques DÉCLARATIVES** (#66/#67 : `file` / `command` / `http`) + parseur `regex`/`delimiter` | **implémentées** — tail à curseur d'offset (rotation gérée), poll de commande/URL cadencé, extraction de champs à groupes nommés. Mapping ligne→event + tail + parseur **testés**. Voir [`examples/sources.toml`](examples/sources.toml) |

### Mapping CIM des sources natives

- **Windows Event Log** (`WinEventLog:<canal>`, catégories `auth`/`exec`/`network`/`dns`/`endpoint`) :
  `4625`→`auth` (échec, sévérité 3), `4624/4634/4672/…`→`auth`, `4688`→**`exec`**, `1102`/`7045`→`endpoint` ;
  **Sysmon** ID `3`→`network`, `22`→`dns`, sinon `endpoint`. Curseur = signet XML `<BookmarkList>` (multi-canal).
  *(`4688`→`process` était écrit ici : c'est faux depuis le 2026‑07‑23. `map_cim` émet `exec`, le nom
  canonique CIM v1.3 ; `process` n'appartient pas à `CIM_CATEGORIES`. Mesuré le 2026‑08‑02 sur Windows 11
  Enterprise 24H2 (build 26100) : les 4688 remontés par l'agent arrivent en `category=exec`.)*
  **Tout ce qui n'est pas listé ci-dessus part avec une catégorie VIDE** — ce n'est pas marginal :
  *mesuré le 2026‑08‑02, 1 572 des 5 189 événements Windows (30 %) sont arrivés sans catégorie*, dont
  834 du canal `Security` et 604 du canal `System`. Le champ CIM `action` (vocabulaire neutre,
  `docs/CIM.md` §4c) n'est **jamais** posé par ce lecteur : **0 / 5 189** événements Windows le portent.
  *Les deux lacunes ont été **reconfirmées le 2026‑08‑02 sur deux Windows Server 2022** (Server Core +
  Desktop Experience promue contrôleur de domaine), donc sur un autre OS et un autre profil de machine :
  **2 552 / 6 962 (36,7 %)** sans catégorie — `Application` **100 %**, `Security` **43,6 %**, `System`
  **41,8 %**, Sysmon **0 %** — et **0 / 6 962** avec `action`. Ce ne sont pas des accidents de poste : ce
  sont deux défauts produit.* Le collecteur PowerShell, lui, pose toujours une catégorie (0 / 1 505 vide)
  mais **jamais** `action` non plus (0 / 1 505) : la lacune `action` est commune aux deux émetteurs.
  **Clé `dedup`** : `win-<hôte>-<canal>-<EventRecordID>`. *Le nom de l'hôte y est entré le 2026‑08‑02 : sans
  lui, deux machines s'écrasaient mutuellement (`event.dedup` est UNIQUE au niveau de la base) — 45
  enregistrements Sysmon perdus en silence sur 311, mesuré, corrigé, revérifié. Détail complet et preuve
  dans `collectors/windows/README.md`, « le piège de la flotte ».*
- **macOS unified log** (`source=subsystem`) : `sshd/sudo/su/authd/…` ou subsystem `*auth*`/`*ssh*`→`auth` ;
  subsystem `*network*`→`network` ; sinon catégorie vide (le dparser serveur tranche). `messageType`
  `Error`/`Fault`→sévérité 3. Curseur = dernier `timestamp` (`log show --start`), dédup via `traceID`.
- **FIM natif** (`source=integrity`, `category=integrity`) : émet EXACTEMENT le contrat CIM de l'ingest
  endpoint #57 (mêmes champs `fim_*`) — le panneau `search source=integrity`, le rollup santé `integrity`
  et les vues #57 s'allument à l'identique, SANS changement daemon. `fim_event` ∈ `added|modified|deleted`
  (sévérité `1|2|3`), `fim_mode` = `realtime` (fanotify/inotify) ou `scheduled` (repli scan), + `fim_sha256`
  (/`_before`), `fim_size`, `action` (`modify|delete`), `fim_change` (`created|content|attrs|deleted`) et un
  miroir `path`/`sha256`/`change` (style `integrity.sh`). Empreinte SHA-256 pure-Rust, bornée par
  `hash_max_bytes`. Baseline chemin→hash **persistée** (`<state_dir>/fim-<id>.baseline.json`) → pas de
  ré-alarme au reboot ; 1er run = seed silencieux. **Observationnel STRICT** (aucune écriture/remédiation).

## Contrat de fil

- Envelope events → `POST {endpoint}/api/ingest` :
  `{"ts":<epoch>,"host":"<h>","kind":"events","events":[{ "ts","source","category","severity","message","fields"[,"dedup"] }]}`
- journald **brut** (ndjson, 1 objet/ligne) → `POST {endpoint}/api/ingest/journal` (le **daemon** parse).
- ACK = **HTTP 202** (204 pour un journal vide). Auth : `Authorization: Bearer <token>` ou Basic.
- mTLS optionnel : CA interne (`[tls].ca_cert`) + cert client (`[tls].client_cert/client_key`).

## Configuration (TOML)

```toml
endpoint = "https://soc.guatx.com"
token = "…"                 # Bearer (recommandé) ; ou username/password (Basic)
# host = "web01"            # override (défaut = hostname machine)
# host_header = "soc.guatx.com"
batch_size = 500
flush_interval_secs = 10
spool_cap = 10000
# spool_dir / state_dir : défaut par-OS

[tls]
# ca_cert = "/etc/plume/ca.pem"        # CA interne à ajouter aux racines publiques
# client_cert = "/etc/plume/agent.crt" # mTLS
# client_key  = "/etc/plume/agent.key"
# insecure = false                     # DANGER dev only : ne pas vérifier le cert serveur

[[source]]
type = "journald"
id = "journald-auth"
comm = ["sshd", "sshd-session", "sudo", "su"]
since = "15min"

[[source]]
type = "fim"                       # FIM natif (#58) — surveillance d'intégrité de fichiers
# id = "integrity"                 # défaut ; -> source=integrity (panneau `search source=integrity`)
paths = ["/etc", "/usr/local/bin"] # ALLOWLIST des racines. VIDE = source INERTE (mode 0, aucun accès disque)
# recursive = true                 # descente dans les sous-répertoires
# exclude = ["*/.git/*", "*.swp"]  # globs (* / ?) exclus, matchés sur le chemin absolu
# hash_max_bytes = 10485760        # 10 MiB : au-delà, taille seule (borne le CPU/RAM)
# max_watches = 8192               # plafond de watches noyau / marks (anti-ENOSPC & anti-OOM)
# max_files = 200000               # plafond d'entrées baseline (anti-OOM arbre profond)
# debounce_ms = 200                # coalescence anti-rafale par chemin
# min_rescan_interval_secs = 60    # cadence MIN entre rescans complets forcés (anti-amplification CPU/I/O)
```

Sans AUCUN `[[source]]`, une source journald auth par défaut est injectée (le bloc `fim` n'est JAMAIS
implicite). Une source `fim` sans `paths` est **inerte** — invariant mode 0.

**Privilèges FIM** : sur Linux, le backend préféré `fanotify` requiert **CAP_SYS_ADMIN** ; à défaut,
l'agent **dégrade proprement** en `inotify` (aucune capability) — jamais de crash. Les autres OS (macOS,
Windows sans la feature native) retombent en **scan planifié** borné. Le FIM est **observationnel
strict** : il lit/hashe/rapporte, ne modifie/quarantaine/supprime JAMAIS un fichier (charte plume :
aucune action live sur l'hôte). Il ne suit pas les symlinks hors des racines (anti-évasion) : la probe
OUVRE chaque chemin en `O_NOFOLLOW` et `fstat` le descripteur (pas le chemin) — aucune fenêtre TOCTOU,
un lien substitué juste avant l'open ne peut pas faire hasher une cible arbitraire ; seuls les fichiers
réguliers sont hashés (fifos/devices/sockets ignorés), la lecture est bornée EN DUR à `hash_max_bytes`
(aucune lecture non bornée sur un fichier qui grossit / un flux sans fin). Si un plafond
(`max_watches`/`max_files`) est atteint, la couverture partielle est remontée au SOC via `fim_coverage=partial`
sur les events (pas seulement un warning d'hôte).

## Sources DÉCLARATIVES (#66/#67) — envoyer des logs SANS écrire de script

Un technicien qui doit expédier des logs au SOC **déclare** ses sources dans le TOML (`[[source]]`) —
il n'a **pas besoin d'écrire un `.ps1` / `.sh`**. Les collecteurs script **restent pleinement
supportés** (voir plus bas) : c'est l'alternative pour qui préfère scripter. Les deux **coexistent**.

> **Format = TOML `[[source]]`**, pas un fichier YAML séparé. Le tableau de tables TOML **est déjà un
> format déclaratif**, et le technicien édite **le même fichier** que le reste de sa config (`endpoint`,
> `[tls]`…) — friction minimale, zéro nouveau format à apprendre. On **n'ajoute pas** de dépendance YAML :
> `serde_yaml` est **non maintenu** (il ferait rougir le gate `cargo audit --deny warnings`) et l'agent
> est délibérément **léger**. La seule dépendance ajoutée est `regex` (déjà utilisée/auditée par le
> daemon) pour le parseur à groupes nommés.

Cinq types génériques, une forme uniforme (`name` → `source=`, `category`, `severity` 0–4, `parser`
optionnel) :

| `type` | Ce qu'il fait | Champs spécifiques |
| --- | --- | --- |
| `file` | tail d'un fichier de log (curseur = offset ; rotation gérée) | `path`, `from_start` |
| `command` | exécute une commande toutes les `interval` s ; 1 ligne stdout = 1 event | `cmd`, `args`, `interval`, `max_lines` |
| `http` | GET d'une URL toutes les `interval` s ; 1 ligne du corps = 1 event (réutilise le TLS de `[tls]`) | `url`, `interval`, `max_lines` |
| `journald` | backend natif journald ; suit des `_COMM=` **et/ou** des unités systemd | `comm`, `units`, `since` |
| `wineventlog` | backend natif Windows Event Log (se charge aussi sur Linux, où il no-op-e) | `channels`, `query` |

**Parseur de champs** (`[source.parser]`, optionnel — le `message` reste toujours la ligne brute, les
champs sont **additifs**) :
- `regex` = une regex à **groupes nommés** `(?P<champ>…)` → chaque groupe capturé devient un champ ;
- ou `delimiter` + `fields` = découpe la ligne et **nomme les colonnes** (mode **zéro-dépendance**,
  pour du CSV/espacé/pipé).

**Résilience** : une entrée **malformée** (type inconnu, champ obligatoire manquant, regex invalide) est
**ignorée avec un warning** — elle n'emporte jamais les autres sources ni ne fait planter l'agent. Si
**aucun** `[[source]]` n'est déclaré, la source journald auth par défaut est injectée.

Exemple minimal (tail d'un access-log nginx avec extraction de champs) :

```toml
[[source]]
type = "file"
name = "nginx-access"
path = "/var/log/nginx/access.log"
category = "web"
[source.parser]
regex = '^(?P<ip>\S+) \S+ \S+ \[[^\]]+\] "(?P<method>\S+) (?P<path>\S+)[^"]*" (?P<status>\d{3})'
```

👉 **Exemples prêts à copier** (les 5 types + parseur regex et parseur découpe) :
[`examples/sources.toml`](examples/sources.toml).

### L'alternative script reste supportée

Rien n'est retiré. Qui préfère scripter garde :

- **Linux** — `collectors/*.sh` et surtout le générique **`collectors/custom.sh`** qui lit
  `/etc/plume/inputs.d/*.input` (fichiers `KEY=value` : `SOURCE=`, `CMD=`, `SEVERITY=`, `CATEGORY=`,
  `FILTER=`, `MAX=`, `MAXLEN=`) et expédie chaque ligne stdout comme event.
- **Windows** — `collectors/windows/plume-collector.ps1`.

Même **contrat de fil** que l'agent (enveloppe `kind:events` → `/api/ingest`) : script et agent
déclaratif produisent des events **indistinguables** côté SOC.

## Utilisation

```bash
# 1. poser le binaire et la config HORS de /home (voir l'avertissement ci-dessous)
cargo build --release
sudo install -m0755 target/release/plume-agent /usr/local/bin/plume-agent
sudo install -d -m0750 /etc/plume
umask 077; printf 'endpoint = "https://soc.example.com"\ntoken = "%s"\n' '<token>' \
  | sudo tee /etc/plume/agent.toml >/dev/null      # token par STDIN, jamais en argv

# 2. tester, installer, vérifier
plume-agent test-ship --config /etc/plume/agent.toml   # connectivité/auth/TLS (1 event de santé)
sudo /usr/local/bin/plume-agent install --config /etc/plume/agent.toml
systemctl is-active plume-agent                        # <- VÉRIFIEZ : `install` sort 0 sans le faire
plume-agent status
sudo plume-agent uninstall
```

> ### ⚠️ Deux pièges d'installation (mesurés le 2026‑08‑01, Ubuntu 24.04.4 amd64)
> **1. Ne lancez pas `install` sur un binaire resté dans `/home`.** `install` écrit un `ExecStart=`
> pointant sur le **chemin courant** du binaire, sans le copier — et la même unité pose
> `ProtectHome=yes`. Un binaire fraîchement compilé dans `~/plume/agent/target/release/` donne donc une
> unité **en boucle de redémarrage** (`status=203/EXEC`). *Mesuré : `install` affiche
> « service installé et démarré » et sort **0** alors que le service échoue — d'où le
> `systemctl is-active` ci‑dessus.* Copiez le binaire dans `/usr/local/bin` et la config dans
> `/etc/plume` d'abord.
> **2. `--token TOK` met le secret dans l'argv de `sudo`**, que `sudo` journalise et que le collecteur
> `journal` (ou la source `journald` de cet agent) expédie **en clair** au central. Écrivez le TOML par
> STDIN comme ci‑dessus, puis `install --config`.

## Déploiement (service auto-installé)

`install` ne se contente PAS d'écrire la config : il **auto-installe et démarre le service** de l'OS —
c'est le comportement par défaut, pensé pour un agent endpoint (démarrage au boot, redémarrage auto).

| OS | Ce que `sudo plume-agent install` fait | Retrait |
|----|----------------------------------------|---------|
| **Linux (systemd)** | écrit l'unité durcie `/etc/systemd/system/plume-agent.service` (`NoNewPrivileges`, `SystemCallFilter`, répertoires dédiés), `daemon-reload`, puis **`enable --now`** → démarre **maintenant ET au boot** | `sudo plume-agent uninstall` = `disable --now` + suppression de l'unité + reload |
| **macOS (launchd)** | pose le `LaunchDaemon` plist + `launchctl bootstrap` (démarre + au boot) | `plume-agent uninstall` = `bootout` + suppression du plist |
| **Windows (SCM)** | `CreateService` (start=auto) + démarrage | `plume-agent uninstall` = `stop` + `DeleteService` |

> ### `uninstall` dit ce qu'il a fait — et ce qu'il n'a pas fait (corrigé le 2026‑08‑02)
> *Mesuré ce jour‑là sur une machine où **rien** n'était installé : `plume-agent uninstall` affichait
> « Failed to disable unit: … », puis « Reload daemon failed: … », puis **« service retiré :
> plume-agent.service »**, et sortait **0**. Zéro fichier supprimé, deux commandes en échec, un succès
> annoncé.* Chaque étape était un `let _ = …status();` : l'échec n'était ni vérifié ni remonté.
> Le retrait est désormais **OBSERVÉ** — chaque artefact est sondé, agi, puis **re‑sondé** — et le
> rapport nomme les trois issues sans les confondre :
> ```
>   retiré   : service plume-agent.service (arrêté et désactivé)
>   absent   : /etc/systemd/system/plume-agent.service (rien à retirer)
>   ÉCHEC    : … — toujours ACTIF après `systemctl disable --now` (droits root ?)
> ```
> Un artefact qui **résiste** fait sortir la commande **non nul** (c'est le cas qui était avalé) ;
> « rien n'était installé » sort 0 mais ne prétend **jamais** avoir retiré quoi que ce soit.
> *Vérifié à l'exécution sur Linux uniquement ; les backends launchd/SCM ont la même structure et sont
> compilés par `agent-ci` sur `macos-latest`/`windows-latest`, non exécutés.*

> **Auto-start = voulu.** Un endpoint doit collecter en continu, y compris après reboot. Si tu veux
> **installer sans démarrer**, pose l'unité toi-même (ou `install` puis `sudo systemctl disable --now
> plume-agent`). Pour un déploiement **sans service** (cron/timer/foreground), n'utilise pas `install` :
> lance `plume-agent run --config agent.toml` (boucle) ou `--once` (un cycle, pour cron/systemd-timer).

Les sources (natives ET les [`[[source]]` déclaratives](#sources-déclaratives-6667--envoyer-des-logs-sans-écrire-de-script))
sont lues par ce même service — aucune étape supplémentaire côté OS.

## Build

```bash
cargo build --release          # Linux (dev box) — cible native
cargo test                     # tests unitaires (aucun réseau requis)
```

## Cross-compilation (Win/Mac)

Le code natif Win/macOS est **implémenté** et `cfg`-gated : un build Linux compile les parties PURES
(mapping CIM, construction requête/plist/binPath, parsing epoch — toutes **testées**) et ignore la FFI.
Un `Makefile` fournit la matrice de build ; `.cargo/config.toml` documente les linkers.

> ### ⚠️ Le binaire MSVC par défaut NE DÉMARRE PAS sur un Windows neuf (mesuré le 2026‑08‑02)
> `cargo xwin build --release --target x86_64-pc-windows-msvc` produit un exécutable qui importe
> `VCRUNTIME140.dll` — **absente d'un Windows 11 Enterprise 24H2 fraîchement installé** (le
> redistribuable Visual C++ n'est pas livré avec l'OS). *Mesuré : l'exe se termine immédiatement avec
> `0xC0000135` (STATUS_DLL_NOT_FOUND), y compris pour `--help` ; la lecture de la table d'imports PE
> donne `VCRUNTIME140.dll` comme seule DLL réellement manquante (les `api-ms-win-crt-*` sont des
> apisets résolus par le chargeur).* **Compilez avec la CRT statique** — aucun redistribuable à
> déployer, et c'est ce qu'on attend d'un agent endpoint :
> ```bash
> RUSTFLAGS="-C target-feature=+crt-static" cargo xwin build --release --target x86_64-pc-windows-msvc
> ```
> *Vérifié : binaire 3 350 528 octets, `--help` sort 0, `test-ship` → HTTP 202, `install` crée et démarre
> le service SCM sur la même VM où le binaire dynamique refusait de démarrer.*

| Cible | Triple | Outil de build depuis Linux |
| --- | --- | --- |
| Windows x64 (MSVC) | `x86_64-pc-windows-msvc` | `cargo xwin build --target …` (`make win-msvc`) — headers/libs MSVC auto, pas de VM ; **ajouter `RUSTFLAGS="-C target-feature=+crt-static"`** (cf. avertissement ci-dessus) |
| Windows x64 (GNU) | `x86_64-pc-windows-gnu` | MinGW-w64 + `cargo build --target …` (`make win-gnu`) |
| macOS x64 | `x86_64-apple-darwin` | `cargo zigbuild --target …` (`make mac-x64`) — Zig comme linker + SDK Apple |
| macOS ARM | `aarch64-apple-darwin` | `cargo zigbuild --target …` (`make mac-arm`) |
| Linux statique | `x86_64-unknown-linux-musl` | `cargo build --target …` (`make linux-musl`) |

### Cross-CHECK (valide le code cfg-gated SANS linker)

`cargo check` **type-vérifie** la cible sans lier — donc **ni MinGW ni SDK Apple requis**, seulement la
std de la cible via `rustup` :

```bash
rustup target add x86_64-pc-windows-msvc aarch64-apple-darwin
cargo check --target x86_64-pc-windows-msvc   # compile source/windows.rs + service/windows_scm.rs
cargo check --target aarch64-apple-darwin     # compile la partie cfg(macos)
# ou : make check-all   (cross-check Win+Mac, puis build+test natif)
```

> **Dépendances natives** (dans `Cargo.toml`, `[target.'cfg(windows)'.dependencies]`) : `windows` 0.58
> (features `Win32_Foundation` + `Win32_System_EventLog`) et `windows-service` 0.8 — tirées **uniquement**
> par la cible Windows. macOS n'a **aucune** crate native (sous-processus `log` + `launchctl`).
> `rustls` reste sur le provider **ring** (comme le daemon) — pas de cmake/nasm requis.

> **Note d'environnement (remplacée — mesuré le 2026‑08‑02)** : cette note disait que le cross-check
> n'avait « pas pu être exécuté ici » faute de `rustup`. Ce n'est plus vrai : la cible MSVC a été
> **entièrement CROSS-COMPILÉE** depuis Linux avec `cargo xwin` (51 s avec le SDK MSVC déjà en cache
> local ; **le premier build d'une machine neuve doit d'abord télécharger ce SDK — ~1,2 Gio dans
> `~/.cache/cargo-xwin` — durée NON mesurée ici, le cache préexistait**), puis le binaire a été
> **exécuté sur un vrai Windows 11 Enterprise 24H2** : FFI Event Log (`wevtapi.dll` bien dans la table
> d'imports), service SCM, ship TLS — tout fonctionne. La cible **`x86_64-pc-windows-gnu`, elle, échoue
> sans MinGW-w64** : `error calling dlltool 'x86_64-w64-mingw32-dlltool': No such file or directory`
> (mesuré, en 16 s, sur une machine où seul `rustup target add` avait été fait). MSVC + `cargo xwin`
> est donc bien le chemin à recommander, mais il n'est pas « sans prérequis ».

## Sémantique at-least-once

Le curseur d'une source n'est persisté sur disque **qu'après** ship+ACK. Un crash rejoue le dernier
lot non acké ; la déduplication côté daemon (`dedup` / `__CURSOR` journald, `INSERT OR IGNORE`) absorbe
les doublons. Le spool est un **anneau borné** : si le central est indisponible, les entrées les plus
vieilles sont évincées au-delà de `spool_cap` (le poste ne peut pas saturer son disque).
