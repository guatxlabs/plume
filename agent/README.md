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
| Source **FIM natif** (#58 : `type = "fim"`) | **implémentée** — Linux `fanotify`→`inotify` (réel) ; repli **scan planifié** sur les autres OS ; Windows `ReadDirectoryChangesW` **écrit, compilé en CI (`agent-cross`, `--features fim_windows_native`), non validé à l'exécution** — éteint par défaut tant qu'un hôte Windows ne l'a pas exercé. Cœur diff/baseline/CIM **testé** ; chemin syscall fanotify/inotify → *validation runtime : hôte Linux root* |
| Sources **génériques DÉCLARATIVES** (#66/#67 : `file` / `command` / `http`) + parseur `regex`/`delimiter` | **implémentées** — tail à curseur d'offset (rotation gérée), poll de commande/URL cadencé, extraction de champs à groupes nommés. Mapping ligne→event + tail + parseur **testés**. Voir [`examples/sources.toml`](examples/sources.toml) |

### Mapping CIM des sources natives

- **Windows Event Log** (`WinEventLog:<canal>`, catégories `auth`/`exec`/`network`/`dns`/`endpoint`) :
  `4625`→`auth` (échec, sévérité 3), `4624/4634/4672/…`→`auth`, `4688`→**`exec`**, `1102`/`7045`→`endpoint` ;
  **Sysmon** ID `3`→`network`, `22`→`dns`, sinon `endpoint`. Curseur = signet XML `<BookmarkList>` (multi-canal).
  *(`4688`→`process` était écrit ici : c'est faux depuis le 2026‑07‑23. la classification de l'agent (`classer`) émet `exec`, le nom
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

> ### Certificat du central refusé — ce qui marche, mesuré (2026‑08‑02)
> `test-ship` disait `io: invalid peer certificate: Other(OtherError(CaUsedAsEndEntity))` : ni le mot
> « certificat » en clair, ni le réglage qui corrige. Le message **nomme désormais le remède**, et
> celui-ci a été **exécuté** contre un `openssl s_server` avant d'être écrit :
> | Configuration du central | `[tls]` de l'agent | Résultat mesuré |
> | --- | --- | --- |
> | CA interne (CA:TRUE) signant une **feuille** (CA:FALSE) | `ca_cert = /chemin/ca.pem` | **accepté** |
> | feuille **auto‑signée** (CA:FALSE) | `ca_cert = /chemin/de/cette/feuille.pem` | **accepté** |
> | feuille auto‑signée, rien de déclaré | — | refusé (`UnknownIssuer`) |
> | certificat **de CA** servi comme certificat serveur | `ca_cert` = ce même fichier | **toujours refusé** (`CaUsedAsEndEntity`) — c'est le CENTRAL qu'il faut corriger (servir une feuille signée par la CA) |
> | n'importe laquelle | `insecure = true` | accepté — **dev uniquement**, aucune vérification |

## Configuration (TOML)

```toml
endpoint = "https://soc.example.com"
token = "…"                 # Bearer (recommandé) ; ou username/password (Basic)
# host = "web01"            # override (défaut = hostname machine)
# host_header = "soc.example.com"
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
plume-agent status
sudo plume-agent uninstall
```

> ### `install` dit ce qu'il a posé — et refuse ce qui ne pourrait pas marcher (corrigé le 2026‑08‑02)
> **1. Un binaire resté dans `/home` (ou `/root`, ou `/tmp`) est désormais REFUSÉ, avant toute
> écriture.** `install` écrit un `ExecStart=` pointant sur le **chemin courant** du binaire, sans le
> copier — et la même unité pose `ProtectHome=yes` / `PrivateTmp=yes`. *Mesuré le 2026‑08‑02 (systemd
> 261, sonde différentielle à une seule variable) : même exécutable, sans `ProtectHome` le service
> tourne (`ExecMainStatus=0`) ; avec, il meurt en `status=203/EXEC` — le service ne peut pas lire son
> propre binaire — et `systemctl enable --now` rend quand même **0**, si bien que `install` affichait
> « service installé et démarré » et sortait 0 sur une machine qui ne collectait rien et redémarrait
> en boucle toutes les 5 s.* La commande refuse maintenant d'écrire une unité qui se contredit, et dit
> quoi faire (copier le binaire dans `/usr/local/bin`, la config dans `/etc/plume`).
> **1 bis. Le refus vaut pour les QUATRE chemins, et il est MESURÉ sur l'hôte (2026‑08‑20).** Le spool
> et l'état étaient exemptés, sur la foi d'un commentaire daté affirmant que le `ReadWritePaths=` de
> l'unité les re‑exposait malgré `ProtectHome=`. *Re‑mesuré le 2026‑08‑20 (systemd 261, unités
> transitoires, une seule variable) : cela ne se reproduit pas — ni `ReadWritePaths=`, ni `BindPaths=`,
> ni `BindReadOnlyPaths=`, ni `ReadOnlyPaths=` ne ramènent un chemin ainsi protégé. Pire que 203 :
> l'unité DÉMARRE (`ExecMainStatus=0`, aucun 203, aucun 226) et le service reçoit « Permission
> denied » à la première écriture dans son spool.* Un spool ou un état sous `/home`, `/root` ou
> `/run/user` est donc refusé comme le binaire. Et parce qu'aucune table écrite d'avance ne peut
> décrire le bac à sable de tous les hôtes, `install` **monte réellement** ce bac à sable avant
> d'écrire l'unité (une unité transitoire portant le même durcissement) et y teste chaque chemin dans
> le mode dont le service a besoin. Si cette mesure ne peut pas être faite, elle le **dit** au lieu de
> passer pour un feu vert.
> **2. Ce qu'`install` affirme est RE‑OBSERVÉ, et sur une DURÉE.** *Mesuré le 2026‑08‑02, 3 fois sur
> 3 : l'échantillon pris juste après le démarrage d'une unité dont l'`ExecStart` est injoignable dit
> `active/running/ExecMainStatus=0` — le SUCCÈS —, et la même unité est en `auto-restart/203` 1,2 s
> plus tard.* Une sonde instantanée validerait donc exactement le défaut qu'elle doit attraper :
> `install` exige que `active/running` tienne **2,5 s d'affilée** (budget 12 s), traite `auto-restart`
> et `NRestarts>0` comme des ÉCHECS, et vérifie séparément `is-enabled` (l'artefact dit « au boot »).
> Répertoires et unité sont relus après écriture. Un service qui ne tient pas fait sortir la commande
> **non nul** — plus besoin d'un `systemctl is-active` de vérification derrière.
> ```
>   posé     : /etc/systemd/system/plume-agent.service
>   ÉCHEC    : service plume-agent.service (actif au boot et maintenant) — le service NE TOURNE PAS
>              après `systemctl enable --now` (ActiveState=activating SubState=auto-restart
>              Result=exit-code ExecMainStatus=203) — 203/EXEC : l'ExecStart est INJOIGNABLE depuis
>              le bac à sable de l'unité…
> ```
> **3. `--token TOK` met le secret dans l'argv de `sudo`**, que `sudo` journalise et que le collecteur
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
Un `Makefile` fournit la matrice de build ; [`.cargo/config.toml`](.cargo/config.toml) porte les réglages
PAR CIBLE (aujourd'hui : la CRT statique de Windows/MSVC, cf. ci-dessous).

> ### La CRT statique est désormais IMPOSÉE pour Windows/MSVC (corrigé le 2026‑08‑02)
> Sans elle, `cargo xwin build --release --target x86_64-pc-windows-msvc` produit un exécutable qui
> importe `VCRUNTIME140.dll` — **absente d'un Windows 11 Enterprise 24H2 fraîchement installé** (le
> redistribuable Visual C++ n'est pas livré avec l'OS). *Mesuré : l'exe se termine immédiatement avec
> `0xC0000135` (STATUS_DLL_NOT_FOUND), y compris pour `--help`.* **Aucun diagnostic n'est possible
> depuis le programme** : le chargeur échoue avant la première instruction de notre code — la seule
> correction est de SUPPRIMER la dépendance, pas de la détecter.
> Le drapeau vit dans [`.cargo/config.toml`](.cargo/config.toml) (donc `make win-msvc`, `cargo xwin
> build`, `cargo check` et la CI l'appliquent tous), et un test le garde contre une suppression
> silencieuse. *Mesuré le 2026‑08‑02 en lisant la table d'imports PE des deux binaires produits ici :
> sans le drapeau **3 259 392 o avec `VCRUNTIME140.dll`** + 5 apisets `api-ms-win-crt-*` ; avec,
> **3 359 744 o, aucune des deux** (et `wevtapi.dll` toujours importée — c'est bien l'agent complet).*
> Ne posez pas de `RUSTFLAGS=` pour cette cible : la variable d'environnement **écrase** le fichier.

| Cible | Triple | Outil de build depuis Linux |
| --- | --- | --- |
| Windows x64 (MSVC) | `x86_64-pc-windows-msvc` | `cargo xwin build --target …` (`make win-msvc`) — headers/libs MSVC auto, pas de VM ; CRT statique **déjà imposée** par `.cargo/config.toml` |
| Windows x64 (GNU) | `x86_64-pc-windows-gnu` | **MinGW-w64 REQUIS** (`x86_64-w64-mingw32-gcc`, paquet `mingw-w64-gcc`) + `cargo build --target …` (`make win-gnu`, qui vérifie le prérequis et le dit) — cible **non vérifiée ici**, préférez MSVC |
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

### Ce que « publié » veut dire, exactement

Deux propriétés se confondent souvent, et la promesse ci-dessus a besoin des deux :

- **Atomicité du contenu** — après le renommage, un lecteur voit l'ancien fichier ou le nouveau,
  jamais un fichier à moitié écrit. Le renommage la donne, seul.
- **Durabilité** — après une coupure d'alimentation ou du noyau, la publication survit. Le renommage
  ne la donne **pas** : il faut que les octets du temporaire soient sur le disque **avant**, et que
  l'entrée de répertoire y soit **après**. Sans le second point, le fichier peut exister sans que son
  **nom** existe : les octets sont là, personne ne les trouvera, et rien ne comptera ce qui manque.

Toute publication de ce binaire — entrée de spool, curseur de source, base de référence FIM — passe
par une **voie unique** (`src/durable.rs`) qui fait les deux synchronisations, et un test dérivé
refuse qu'un nouveau site réinvente le motif à la main.

**Ce que cela garantit, par cible** — une promesse non bornée est une promesse fausse :

| Cible | Contenu synchronisé avant | Répertoire synchronisé après |
|---|---|---|
| Linux, macOS | oui | oui |
| Windows | oui | **non** — un descripteur de répertoire n'y est pas ouvrable par la bibliothèque standard ; la publication y est atomique et son contenu durable, sans garantie sur l'entrée de répertoire |

**Ce que les tests prouvent, et ce qu'ils ne prouvent pas** : ils prouvent que les appels de
synchronisation sont **faits**, au bon endroit du chemin de publication (compteur par fil
d'exécution, plus une preuve par mutation : retirer un appel fait échouer un test qui nomme la
surface). Ils ne prouvent **pas** la survie à une coupure d'alimentation — cela demanderait de
couper le courant d'une vraie machine à l'instant exact. Le défaut réellement fermé est qu'aucun
appel n'existait ; un matériel qui ment sur son propre *flush* reste hors de portée.
