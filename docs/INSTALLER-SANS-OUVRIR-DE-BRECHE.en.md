# Installing plume without opening a breach — step by step, in all three modes

[Français](INSTALLER-SANS-OUVRIR-DE-BRECHE.md) | [English](INSTALLER-SANS-OUVRIR-DE-BRECHE.en.md)

This page is for the person who installs plume at home, on a machine they administer, and
who wants to **expose nothing more than what they have chosen**. It follows the order of operations: what is
open by default, the installation of each mode, where the secrets live, what each sensor brings
into the SIEM, the transport, the risks the product accepts, and the proof that everything reports in.

It does not repeat the pages that exist: the same operation in all three modes is in
[`TROIS-MODES.md`](TROIS-MODES.en.md), the agents' wire contract in
[`AGENTS-PROTOCOLE.md`](AGENTS-PROTOCOLE.md), at-rest encryption in
[`CHIFFREMENT-COMPRESSION.md`](CHIFFREMENT-COMPRESSION.md), the syslog receiver in
[`../deploy/SYSLOG.md`](../deploy/SYSLOG.en.md), the mailbox sensor in
[`../deploy/MAIL.md`](../deploy/MAIL.en.md), the search language in [`GXQL.md`](GXQL.en.md).

> **What has not been executed.** The commands on this page are taken from the shipped installers and
> manifests (`bootstrap.sh`, `bootstrap-agent.sh`, `docker-compose.yml`, `deploy/k3s.yaml`) and
> every announced behaviour has been reread in the code that holds it. No installation sequence has
> been run on a machine to write this page. An operation that fails on your side is a defect to
> report.

The host names in the examples are `soc.example.org` (the central) and `agent.example.org` (an agent).

---

## 1. What is open by default, mode by mode

| | native host (`bootstrap.sh`) | Docker (`docker-compose.yml`) | k3s (`deploy/k3s.yaml`) |
|---|---|---|---|
| daemon listener | `127.0.0.1:7000` and `[::1]:7000`, HTTP | `0.0.0.0:7000` **inside** the container, published on the host's `127.0.0.1:7000` only | `0.0.0.0:7000` in the pod, reachable by the `Ingress` and the `soc` namespace |
| TLS | none: to be set up (§2.1) | none: to be set up (§2.3) | **active** on the `Ingress`, `websecure` entrypoint only, certificate from the `Secret` `soc-tls` |
| admin account | hash set, otherwise **SETUP mode** (single-use installation token) | same | hash from the `Secret` `soc-auth` |
| database at rest | **new = encrypted** (key generated as `0600` next to the database), if the daemon opens it first (§1.1) | same, key on the `soc-data` volume | same, key on the PVC |
| daemon network egress | the host's | the Docker bridge's | **refused** except the cluster DNS (`NetworkPolicy`), if the CNI enforces it |
| sensitive operations (creating an account, minting a token…) | **refused** as long as the gesture secret is not set | same | same |

A database **already in service and left in plaintext** is never converted by a start: setting a key
on it makes the start **refuse**, with the name of the explicit operation (`plume-daemon chiffrer-au-repos`).
The details, and how to store the generated key safely, are in
[`CHIFFREMENT-COMPRESSION.md` §1](CHIFFREMENT-COMPRESSION.md#1-la-base-au-repos--neuve--chiffrée--existante--jamais-touchée-par-un-démarrage).
**Losing the key means losing the database and all its backups**: copy it off the machine from the
first start, then set `PLUME_DB_KEY_ESCROWED=1`.

### 1.1 Start the daemon once before any subcommand that writes to the database

"New = encrypted" is only true if the **daemon** is the first to open the database: the key is only
generated at its start, and only on a database that does not exist yet. The subcommands
that open the database to write to it — `token`, `sigma-import` (without `--dry-run`), `retention`,
`fts-compact`, `purge`, `restore-drill record`, and `backup` once its backup is written — **create**
the database if it is missing,
with only the key already set (`PLUME_DB_KEY`, `PLUME_DB_KEY_FILE` or a key file already generated).
Without any, the database is born **in plaintext**. The next start finds it existing, without a key, and does not
touch it: it stays in plaintext, and the start does not refuse it, until the operation
`plume-daemon chiffrer-au-repos`. That the subcommand itself should refuse a missing database is an open key
on the daemon side (`P10.33-g`): until then, the order below is the only protection. Two
read subcommands do not give birth to a database: `verify` opens read-only and creates nothing;
`ledger-export` creates at most an empty file, which the next start still treats as a new
database.

The safe order, in all three modes: install, **start the daemon once** — `bootstrap.sh` does it
at the end of installation, `docker compose up -d`, `kubectl apply` —, check that the key exists
(`/var/lib/plume/db/soc.db.key` on a host, `/data/plume-at-rest.key` in a container), and only
then run a subcommand. The forms `docker compose exec soc …` and `kubectl -n soc exec
deploy/soc -- …` go through the container where the daemon is already running: they respect this order by
construction. `docker compose run --rm soc <sous-commande>` starts a container **without** the daemon: as the
first operation, it gives birth to the database in plaintext on the volume.

---

## 2. Installing, step by step

### 2.1 Native host — the central (`bootstrap.sh`)

**Prerequisites**: a systemd distribution, root access, a stable Rust (`cargo`) and network access for the
first build (no binary is published). `auditd` is optional but without it the execution sensor
collects nothing (and says so).

1. **Compile.** `cd daemon && cargo build --release && cd ..` — add `--features cold_tier,ldap`
   for the cold tier and the directory (both forms are legitimate, the installer says which one it has set up).
2. **Install WITHOUT a secret on the command line.** `sudo bash bootstrap.sh`. Without a hash, the file
   `/etc/plume/soc.conf` (`0640 root:soc`) is written with an empty hash, and the daemon starts in **SETUP
   mode**. Do not write `sudo env PLUME_PASS_HASH=… bash bootstrap.sh`, the form the script's header
   still shows: `sudo` logs its full line, and the `journal` sensor, which this same
   script enables, brings it into the SIEM, where any reader would see the hash — enough to attack the
   password offline.
3. **Set the hash through a pipe.** `hashpw` reads standard input when the argument is missing:
   ```sh
   read -rs PW && printf '%s' "$PW" | ./daemon/target/release/plume-daemon hashpw \
     | sed 's/^/PLUME_PASS_HASH=/' | sudo tee -a /etc/plume/soc.conf >/dev/null; unset PW
   sudo systemctl restart plume-daemon
   ```
   The appended line wins over the empty line (the configuration reader keeps the **last**
   occurrence of a key). A `$` in the hash is not interpreted there: this file is not read by a shell.
   Without this operation, the web wizard does the same thing: the installation token is in
   `sudo journalctl -u plume-daemon` and in `/var/lib/plume/db/setup-token.txt` (`0600`); whoever
   reaches the console **and** holds this token creates the admin account — do not leave SETUP mode open.
4. **Set the gesture secret** (otherwise, minting an agent token from the console is refused):
   [`TROIS-MODES.md` §3.11](TROIS-MODES.en.md#311-setting-the-gesture-secret).
5. **Choose the exposure.** By default nothing leaves the loopback. For the network, two ways:
   - **a TLS proxy in front** (Caddy, nginx, Traefik — examples in
     [`../deploy/CONFIDENTIALITE.md`](../deploy/CONFIDENTIALITE.en.md)), the daemon staying on `127.0.0.1`;
     set `PLUME_HOST` to the served name, `PLUME_TRUSTED_PROXIES` to the exact address of the proxy, and
     `PLUME_TLS_TERMINATED_UPSTREAM=1` in `/etc/plume/soc.conf` if the proxy only serves that name over
     HTTPS (§6.2);
   - **native TLS**: `PLUME_TLS_CERT` and `PLUME_TLS_KEY` (PEM paths readable by the `soc`
     user), `PLUME_ADDR` on the desired interface, `PLUME_HOST` on the certificate's name. The daemon's unit
     has **no capability**: choose a port above 1024. An unreadable certificate **stops** the
     daemon instead of letting it fall back to HTTP. With this TLS active, the daemon sets HSTS and the
     `Secure` attribute of its cookies.
6. **Prove**:
   ```sh
   systemctl is-active plume-daemon                 # active
   ss -ltn | grep ':7000'                           # 127.0.0.1 and [::1] only, as long as nothing is opened
   curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:7000/readyz   # 200
   curl -sS -u admin http://127.0.0.1:7000/api/me   # curl PROMPTS for the password: nothing in the history
   ```
   The last response must carry `"role":"admin"`. With native TLS, the same thing at
   `https://soc.example.org:<port>/readyz`, and `curl -sv` must show your certificate.

### 2.2 Native host — an agent (`bootstrap-agent.sh`)

**Prerequisites**: root, systemd, `curl`. The central must be reachable over `https://` (see §5).

1. **On the central, mint a host-bound token**, after the daemon's first start (§2.1):
   ```sh
   sudo env PLUME_CONFIG=/etc/plume/soc.conf /usr/local/bin/plume-daemon token agent-web agent.example.org
   ```
   It is displayed **once**; only its SHA-256 is kept in the database. `PLUME_CONFIG` is only set by
   the `plume-daemon.service` unit, and `sudo` does not pass it on. Without it, the subcommand reads
   `/etc/plume/plume.conf` and writes to `/var/lib/plume/db/plume.db`, not to the daemon's `soc.db`:
   it displays a token and returns 0, then the central refuses the agent. The order matters too: on a missing
   database, the subcommand creates the database without generating a key, hence in plaintext (§1.1).
2. **On the agent, write the configuration through standard input**, never through an argument:
   ```sh
   umask 077
   printf 'PLUME_CENTRAL=%s\nPLUME_TOKEN=%s\n' 'https://soc.example.org' '<jeton>' \
     | sudo tee /etc/plume/plume.conf >/dev/null
   sudo chmod 0600 /etc/plume/plume.conf
   sudo bash bootstrap-agent.sh       # conf present -> kept, tightened to 0600 root:root
   ```
   To install more sensors, with the conf staying in place:
   `sudo env PLUME_EXTRA_COLLECTORS="journal auditd" bash bootstrap-agent.sh` — no secret value
   on the line. The installer **installs without enabling**, except `resources`, `integrity` and `ship`.
3. **Prove**: `sudo systemctl start plume-ship.service && journalctl -u plume-ship -n 20` must
   carry neither `REFUS` nor an HTTP error code; on the central, `search host=agent.example.org
   source=integrity | stats count` returns a non-zero count once the first FIM run has been shipped.

### 2.3 Docker (`docker-compose.yml`)

**Prerequisites**: Docker with BuildKit and Compose; no Rust toolchain on the host.

1. **Build first**, then set the hash: the recipe, its quotes and its filter are in the
   [`README`](../README.en.md#a-docker-the-simplest). If `docker` is called through `sudo`, the line `hashpw
   '<mot de passe>'` goes to the `sudo` log as in §2.1: run `docker` without `sudo`, or pass the
   password through standard input (`hashpw` without an argument reads it; this pipe through `docker compose run`
   has not been tested here).
2. **Start**: `docker compose up -d` — before any subcommand (§1.1). The port is only published
   on the host's `127.0.0.1:7000`, over HTTP.
3. **Choose the exposure.** In both ways, set `PLUME_HOST` in `.env` to the served name
   (`PLUME_HOST=soc.example.org`): the default is `soc.localhost`, and a request that arrives under a name other
   than those of `PLUME_HOST` or the loopback receives `421`.
   - **a TLS proxy in front**, on the host: the `ports:` line stays `127.0.0.1:7000:7000`, the
     proxy targets `http://127.0.0.1:7000`. `PLUME_TRUSTED_PROXIES` is not listed by the service:
     the daemon keeps its default, which trusts private and loopback peers.
     `PLUME_TLS_TERMINATED_UPSTREAM`, on the other hand, is: set it to `1` in `.env` if the proxy only serves
     that name over HTTPS (§6.2);
   - **native TLS**: `PLUME_TLS_CERT` and `PLUME_TLS_KEY` are **listed** in the
     `environment:` block (otherwise `.env` would be of no use); uncomment the mount
     `./tls:/etc/plume/tls:ro` and set **container** paths, the key readable by the image's `soc`
     user (uid `10001`). The daemon then serves **HTTPS only** on its port — but as long as the
     `ports:` line is `127.0.0.1:7000:7000`, it only offers it to the host itself. To expose it,
     publish the port on the desired interface, for example `"192.0.2.10:7000:7000"`, and nothing broader
     than what you need.
4. **Store the generated key safely**: `docker compose exec soc cat /data/plume-at-rest.key`, kept
   off the machine, then `PLUME_DB_KEY_ESCROWED=1` in `.env`.
5. **Prove**: `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:7000/readyz` (200),
   `ss -ltn | grep ':7000'` (`127.0.0.1` only, as long as the `ports:` line has not changed), and
   `docker compose exec soc cat /sys/fs/cgroup/memory.swap.max` (`0`, the swap bound holds). With
   native TLS, the first command becomes `curl -sS --resolve soc.example.org:7000:127.0.0.1
   https://soc.example.org:7000/readyz`, and `curl -sv` must show your certificate.

The containerized central **is not its own agent**: no shell sensor is in the image. The
sensors run on the Docker host, installed by `bootstrap-agent.sh`, and push to
`http://127.0.0.1:7000` — plaintext is allowed towards the loopback, and towards it alone (§5).

### 2.4 k3s (`deploy/k3s.yaml`)

**Prerequisites**: a k3s cluster (Traefik is the shipped `Ingress` controller), Docker to build
the image, `kubectl`.

1. **Build and import the image**: `docker build -t soc:latest . && docker save soc:latest | sudo k3s
   ctr images import -`.
2. **Fill in a local copy of the manifest** (not versioned): the hash in the `Secret` `soc-auth`
   (`hashpw` reads standard input, as in §2.1), and `soc.tondomaine.tld` replaced **in both
   places** — `PLUME_HOST` and the `Ingress`; a mismatch returns `421`. A hash left at
   `REMPLACER_PAR_LE_HASH` does **not** arm SETUP mode (it only requires an empty value): nobody
   gets in, without a message.
3. **Set the certificate** before applying: `kubectl -n soc create secret tls soc-tls --cert=<crt>
   --key=<key>`, or a cert-manager `Certificate` whose `secretName` is `soc-tls`. As long as it is missing,
   Traefik presents its self-signed certificate: the browser warns, nothing goes through in plaintext. Another
   `Ingress` controller ignores the Traefik annotations: its HTTP to HTTPS redirect then has to be
   set up, and `kube-system` has to be replaced by its namespace in the `NetworkPolicy`.
4. **Apply**: `kubectl apply -f <copie>.yaml`. The pod runs non-root (uid `10001`), root filesystem
   read-only, with no capability, seccomp profile `RuntimeDefault`, **with no service account token**
   mounted.
5. **Store the key safely**: `kubectl -n soc exec deploy/soc -- cat /data/plume-at-rest.key`, then
   uncomment `PLUME_DB_KEY_ESCROWED`.
6. **Prove**:
   ```sh
   kubectl -n soc rollout status deploy/soc
   curl -sv https://soc.example.org/readyz 2>&1 | grep -E 'subject:|HTTP/'   # your certificate, then 200
   kubectl -n soc exec deploy/soc -- curl -sS --max-time 5 https://example.com   # MUST fail
   ```
   If the third command succeeds, the CNI does not enforce the `NetworkPolicy` (cluster started with
   `--disable-network-policy`, or a CNI without support): egress is not cut off.

The cluster's agents push **through the `Ingress`** (`PLUME_CENTRAL=https://soc.example.org`): it is the
path that the shipped `NetworkPolicy` lets in (controller in `kube-system`, or pods of the `soc`
namespace). The Kubernetes sensors run on the **node**, not in the pod (§4, §6.1).

### 2.5 Windows — the collector (`plume-collector.ps1`)

A Windows desktop or server is not a mode of the central: it is an **emitter** that pushes to a
central installed by one of the three modes above. The collector is a single file,
[`../collectors/windows/plume-collector.ps1`](../collectors/windows/plume-collector.ps1), launched by a
scheduled task; it reads the Windows logs and **posts directly** to `/api/ingest`, without a disk
spool. Its detailed instructions, its measurements and its limits are in
[`../collectors/windows/README.md`](../collectors/windows/README.en.md). What follows is the order of operations.

> **What has been tested, and what has not.** The README records the real execution of
> `auditpol /set` (English subcategory names, on an English-language Windows), of `Import-Certificate`
> and of `schtasks /Create` on Windows test machines. Everything else on this page is made of
> standard Windows commands **not run** to write it: `auditpol /set` by GUID, `auditpol /backup`
> and `/restore`, `icacls`, `Get-Acl`, `schtasks /Run`, `Get-ScheduledTaskInfo` and uninstallation. The script's transport gate is executed in
> continuous integration under `pwsh` 7 only: **Windows PowerShell 5.1, the one the task launches,
> is executed nowhere there** (`.github/scripts/check_windows_collector_is_honest.py`).

**Prerequisites**

- **Windows PowerShell 5.1** (`powershell.exe`, present on every supported Windows). It is the one
  the task launches, and the script carries `#Requires -Version 5.1`. `pwsh` 7 runs it too, but two
  of the script's settings have no effect there, because they go through `ServicePointManager`, which
  PowerShell 7's web commands do not use (read from the code, not run): `PLUME_TLS_INSECURE` (step 5)
  and enforcing TLS 1.2 (below).
- An **elevated** console (administrator) for the installation; the task runs as **SYSTEM**: reading
  the *Security* log requires it.
- The audit policies: without them, `category=exec` is misleading and the firewall reports no
  block ([README, Prerequisites](../collectors/windows/README.en.md#prerequisites)). Record the prior state to
  be able to restore it at uninstallation. Subcategory names are **localized** (a French-language
  Windows refuses `"Process Creation"`); their GUIDs are not:
  ```powershell
  auditpol /backup /file:$env:USERPROFILE\auditpol-avant-plume.csv
  auditpol /set /subcategory:"{0CCE9226-69AE-11D9-BED3-505054503030}" /success:disable /failure:enable  # Filtering Platform Connection
  auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable                  # Process Creation
  auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable  # Logon
  ```
  `auditpol /get /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}"` reads the state back; the GUIDs are
  the ones Microsoft publishes for these subcategories (GUID form not tested here).
- The central reachable over `https://`, under a name its `PLUME_HOST` lists (otherwise `421` to everything), and which
  accepts **TLS 1.2**: the script forces `Tls12` on .NET's security protocol, which, under 5.1,
  rules out TLS 1.3 (reading of the script). Under `pwsh` 7, this enforcement has no effect: the version is
  negotiated according to the system.

1. **On the central, mint a token BOUND to this machine.** The second argument is the token's host;
   give it the exact value of `$env:COMPUTERNAME` on the desktop, the name the collector declares:
   ```sh
   sudo env PLUME_CONFIG=/etc/plume/soc.conf /usr/local/bin/plume-daemon token poste-win01 POSTE-WIN01   # native host
   docker compose exec soc plume-daemon token poste-win01 POSTE-WIN01                                   # Docker
   kubectl -n soc exec deploy/soc -- plume-daemon token poste-win01 POSTE-WIN01                         # k3s
   ```
   The token is displayed **once**. A bound token **rewrites** the host of each row to its own: the
   events are stored under the name given here, whatever `host` the envelope declares. A
   `--relais` token would let the desktop write under any name: it is not meant for a
   machine ([`AGENTS-PROTOCOLE.md` §3](AGENTS-PROTOCOLE.md#3-lauthentification-et-ce-que--lié-à-lhôte--veut-dire)).
2. **Create the directory, and cut down its permissions BEFORE writing the token into it.** The script reads
   `C:\ProgramData\plume\plume.conf` and writes its watermarks under `C:\ProgramData\plume\state`:
   ```powershell
   New-Item -ItemType Directory -Force -Path C:\ProgramData\plume | Out-Null
   (Get-Acl C:\ProgramData\plume).Owner      # Administrators or SYSTEM (localized names), nothing else
   icacls C:\ProgramData\plume /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"
   icacls C:\ProgramData\plume               # two entries: SYSTEM and Administrators, none inherited
   ```
   `*S-1-5-18` is SYSTEM and `*S-1-5-32-544` the Administrators group: SIDs do not depend on the
   system's language, their names do. `/inheritance:r` removes the permissions inherited from `C:\ProgramData`, which
   by default gives local users read and create access in its subdirectories (verifiable with
   `icacls C:\ProgramData`); `/grant:r` replaces the explicit permissions of these two accounts. **If the directory already existed**
   (reinstallation, earlier attempt), delete it and recreate it rather than tightening it: `icacls`
   without `/T` only touches the root, and a subdirectory such as `state` created or owned by another
   account would keep its explicit permissions — an owner can always rewrite their own. The
   recreation erases the watermarks: the first run then catches up `-MaxAgeMinutes` (step 6).
   **Why nobody else must read this directory.** The token is in plaintext there. Whoever reads it
   identifies as this desktop on the central's machine paths (§3): they write events that the
   central files under the desktop's name — fake logons, or enough noise to drown
   the real ones. Whoever can **write** to the directory does worse: advancing a watermark makes the
   collector blind to earlier events, and replacing `plume-collector.ps1` gets their
   code executed as SYSTEM at the next trigger.
3. **Write `plume.conf` without the token going through a command line**, then copy the script:
   ```powershell
   notepad C:\ProgramData\plume\plume.conf
   Copy-Item .\plume-collector.ps1 C:\ProgramData\plume\
   icacls C:\ProgramData\plume\plume.conf    # same two entries, inherited from the directory
   ```
   The content, pasted into the editor:
   ```ini
   PLUME_CENTRAL=https://soc.example.org:7000
   PLUME_TOKEN=<le-jeton>
   ```
   The token is **never** typed into a console or on a command line, for two separate
   reasons. Passed as an argument to a process (the script's `-Token` parameter no longer exists, but
   `powershell -Command "…"` or `cmd /c echo … >` create one), it is written into the `4688` as soon as
   the `Process Creation` audit includes the command line — and this collector itself ships that `4688`
   to the SIEM ([README](../collectors/windows/README.en.md#configuration)); Sysmon, if it runs, also writes it
   into its own channel. Typed into a PowerShell console, a `Set-Content … PLUME_TOKEN=…` creates
   no process, but the line stays in the PSReadLine history
   (`%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`) and, if
   script block logging is active, in event `4104` of the
   *Microsoft-Windows-PowerShell/Operational* log (read from the code, not run). The editor has neither.
   `plume.conf` only carries three keys: `PLUME_CENTRAL`, `PLUME_TOKEN` and
   `PLUME_SHIP_ALLOW_PLAINTEXT`. An environment variable wins over the file, and under SYSTEM only
   **machine** variables are seen; but **`PLUME_TOKEN` is never set as a machine variable**:
   it is readable by every local user (key
   `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, and environment inherited by
   every process), which undoes step 2. The token lives in `plume.conf`, and nowhere else.
4. **`PLUME_CENTRAL` over `https://`.** An `http://` address towards anything other than the loopback
   (`127.0.0.0/8`, `::1`, `localhost`) is **refused**: `REFUS` message on standard error,
   **code 2**, before any log read and any send — nothing is read, no watermark advances.
   An address without `schéma://` is refused too, loopback included. `PLUME_SHIP_ALLOW_PLAINTEXT=1`
   (environment or `plume.conf`) accepts plaintext with a warning at every run; **the risk is
   whole**: the token and each event (accounts, command lines, addresses) go through readable, and
   whoever listens on the path replays the token and writes under this desktop's name. Only on an already
   encrypted link or a network you answer for (§5).
5. **Certificate.** TLS verification is **active by default**. For a central signed by an internal
   authority, put the authority in the machine store before the first run, failing which every run fails
   (`LastTaskResult` at `1`) without committing anything: the events wait in the Windows log and
   leave at the first run that succeeds, as long as log rotation has not carried them away (step 7):
   ```powershell
   Import-Certificate -FilePath C:\ProgramData\plume\ca.crt -CertStoreLocation Cert:\LocalMachine\Root
   ```
   `PLUME_TLS_INSECURE=1` turns verification off. It is read **only from the environment** — set
   in `plume.conf`, it has no effect —, hence for the task as SYSTEM, as a machine variable:
   `[Environment]::SetEnvironmentVariable('PLUME_TLS_INSECURE','1','Machine')`. The risk is that of
   plaintext against an active intermediary: it presents any certificate, receives the token and the
   events, and answers in place of the central. Reserved for a test central with a self-signed certificate;
   remove it with `[Environment]::SetEnvironmentVariable('PLUME_TLS_INSECURE',$null,'Machine')`.
   Under `pwsh` 7, this setting goes through `ServicePointManager`, which PowerShell 7's web commands
   do not use: verification stays active there (read from the code, not run).
6. **Scheduled task, every 5 minutes, as SYSTEM.** Typed into an elevated **Windows PowerShell 5.1** —
   `$PSHOME` is the folder of the console where the command is typed, and that of `pwsh` 7 does not contain
   a `powershell.exe`:
   ```powershell
   $ps  = "$PSHOME\powershell.exe"
   $arg = "-NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\plume\plume-collector.ps1"
   schtasks /Create /TN "Plume Collector" /SC MINUTE /MO 5 /RU SYSTEM /RL HIGHEST `
     /TR "`"$ps`" $arg" /F
   ```
   `-ExecutionPolicy Bypass` only applies to this process; it gets an unsigned script executed, hence
   the requirement that only SYSTEM and the Administrators can write it (step 2). The script accepts
   `-MaxAgeMinutes` (default `60`, the catch-up depth of the **first** run, without a watermark) and
   `-BatchSize` (default `400` events per send); neither is necessary. **Only the
   SYSTEM account has been tested.** A dedicated service account has been tested nowhere: it would need
   read access to `plume.conf`, write access under `state` (two more entries in the `icacls` above), and
   whatever it cannot read, the collector will admit (`collect_status=unavailable`) rather than stay
   silent.
7. **Prove.** A first run, then its return code:
   ```powershell
   schtasks /Run /TN "Plume Collector"
   Get-ScheduledTaskInfo -TaskName "Plume Collector"    # once the run is over: LastTaskResult : 0
   ```
   Queried while the run is in progress, the task returns `267009` (running); `267011` says it has
   never run. Wait until `(Get-ScheduledTask -TaskName "Plume Collector").State` returns to `Ready`.
   `LastTaskResult` is `2` for a transport refusal (nothing read or shipped), `1` for a missing key or an
   unacknowledged send (central unreachable, token refused, certificate not recognized): the watermark does not advance and
   the next run rereads. On the central, for the host given to the token:
   ```text
   search host=POSTE-WIN01 source=windows-security | stats count
   search host=POSTE-WIN01 source=windows-agent category=health | stats count
   search host=POSTE-WIN01 category=config collect_status=unavailable | table host, source, reason, detail
   ```
   The first count must be non-zero. The health heartbeat is bucketed by the **hour**: one per hour at
   most, whatever the task's cadence. The third query must be empty; a row there names
   a blind source and its reason (log refused, cmdlet missing).
8. **Uninstall.**
   ```powershell
   schtasks /Delete /TN "Plume Collector" /F
   Remove-Item -Recurse -Force C:\ProgramData\plume
   auditpol /restore /file:$env:USERPROFILE\auditpol-avant-plume.csv
   ```
   Then, on the central, **revoke the token** by its name: token management in the console (admin), or
   `DELETE /api/tokens/poste-win01`, which revokes all tokens of that name. Also remove
   `PLUME_TOKEN` and `PLUME_TLS_INSECURE` if they were set as machine variables
   (`[Environment]::SetEnvironmentVariable('PLUME_TOKEN',$null,'Machine')`: the environment wins over
   `plume.conf`, and a machine variable is readable by every local user), and the authority imported into `Cert:\LocalMachine\Root` if
   nothing else uses it. The events already received stay at the central, subject to its retention.

**What the collector does not do**

- **No disk spool.** The Windows log stands in for it as long as the watermark does not advance; a
  central unreachable for longer than the *Security* log rotation loses what has rotated out (reading). The
  samples of a lost run (firewall profiles, connections, heartbeat) are not replayed.
- **Not a service.** Nothing runs between two triggers, and the hourly heartbeat is not a
  sign of life at the task's granularity.
- **No action.** It neither receives nor executes any response action, opens no port and reads
  no file content.
- **It masks nothing.** The `CommandLine` field of the `4688` goes out as is: a secret typed on a command
  line of the desktop arrives in the SIEM.
- **It does not read Sysmon** (the Rust agent does, [`../agent/README.md`](../agent/README.en.md)). It does, on the other hand,
  set the CIM field `action` (`failure`, `success`, `session_open`, `blocked`…) on
  authentication, execution, accounts, system, Defender and the firewall, from the outcome
  table of each log: a rule `category=auth action=failure` sees the `4625` (reading of the
  script; the README measurement that said otherwise predates this table).
- **Under Windows PowerShell 5.1, nothing is executed in continuous integration**: neither the syntax of the
  transport gate, nor .NET Framework's address parsing. Under `pwsh` 7, `PLUME_TLS_INSECURE` and
  enforcing TLS 1.2 have no effect (*Prerequisites*, step 5).

---

## 3. Where the secrets live, and what they allow

| Secret | Where | Permissions | What it allows |
|---|---|---|---|
| agent token | the agent's `/etc/plume/plume.conf` | `0600 root:root`, tightened at every run of the installer | identifying on the **closed list** of machine paths (ingestion, metrics, traces, response channel, active engagements) — never the interface; a host-bound token writes **under that host**, whatever `host` is declared |
| the same token, copied | `/etc/plume/responder.conf`, `/etc/plume/engagement-adapter.conf` (optional modules) | `0600` | claiming the actions **of its host** on the response channel |
| Windows collector token | `C:\ProgramData\plume\plume.conf` | SYSTEM and Administrators only, inheritance cut (§2.5, step 2); never as a machine variable | the same machine paths as the agent token, under the host it is bound to; whoever can **write** to the directory also gets their code executed as SYSTEM (replaced script) |
| MinIO relay token | `/etc/plume/minio-audit.token` | `0640 root:soc` (the relay runs as `soc`) | dropping object audit events into the host's spool |
| Cloudflare tokens | `/etc/plume/cloudflare.conf` | `0600` | reading the zone's analytics (set a read-only token) |
| Prometheus scrape token (or username and password) | `/etc/plume/prom.conf` (central, native mode) | `0600 root:root`, tightened at every run of `bootstrap.sh`; sole reader `plume-prom-scrape`, which runs as root | pushing series to the central; a `--relais` token has no bound host, the declared host goes through as is: it **impersonates any host** on the machine paths ([`AGENTS-PROTOCOLE.md` §3](AGENTS-PROTOCOLE.md#3-lauthentification-et-ce-que--lié-à-lhôte--veut-dire)); with username and password, those of a console account |
| URL parameters of the scraped targets | `/etc/plume/prom-targets` (central, native mode) | `0600 root:root`, tightened at every run | reading the `/metrics` of a target that authenticates by URL parameter |
| admin hash, explicit database key | `/etc/plume/soc.conf` (host) · `.env` (Docker) · `Secret` `soc-auth` (k3s) | `0640 root:soc` on the host | opening the console as admin (hash to be attacked offline); opening the database |
| generated database key | `<PLUME_DB>.key` (host) · `/data/plume-at-rest.key` (Docker, k3s) | `0600`, reread after creation | **decrypting the database and all its archives** |
| installation token | `setup-token.txt` next to the database, and the daemon's log | `0600`, erased as soon as an admin exists | creating the first admin account |

A file is better than a variable for a secret: a process's environment can be read in
`/proc/<pid>/environ`. The details of an agent token's permissions, and why "host-bound" is a
rewrite and not a refusal, are in [`AGENTS-PROTOCOLE.md` §3](AGENTS-PROTOCOLE.md#3-lauthentification-et-ce-que--lié-à-lhôte--veut-dire).

---

## 4. The sensors, one by one

**In all three modes, a sensor is a HOST artifact.** The container image embeds no script
from `collectors/`: in Docker they run on the Docker host, in k3s on the node, installed by
`bootstrap-agent.sh` (or by `bootstrap.sh` on a native central). Those that read the machine
(journald, `auditd`, FIM, firewall…) therefore read the Docker host or the node, never the inside of the
central's container. `backup` only makes sense on a native host: in a container, the daemon's internal scheduler
replaces it.

Unless stated otherwise, a sensor's systemd unit runs as **root with no capability bound**; "root, capabilities
bounded to …" means that the unit restricts its capability set to the ones named. The common hardening
drop-in (system call filter `@system-service`, `ProtectSystem=strict`, writes
limited to the spool and the state) is installed, **the same file** on the central and on the agent, on the twelve
sensors of the central by `bootstrap.sh`, and on the agent on those that `install_collector` installs — the three
of the default and those of `PLUME_EXTRA_COLLECTORS`. The `PLUME_WITH_*` modules of `bootstrap-agent.sh` install
their unit **without** this drop-in: they only have their own unit's sandbox.
Two settings are **not** in it, and each unit carries its own: `PrivateTmp=` (a private `/tmp`, except
for `yara`, which must see the real `/tmp` to scan it) and `RestrictAddressFamilies=` (the socket
families the unit may open: AF_INET/AF_INET6 for whoever talks to the network — `ship`, `kubectl`,
`cscli`, `curl` —, AF_NETLINK for whoever reads the kernel — `nft`, `auditctl`, `ss` —, AF_UNIX for all).
A scalar setting in the drop-in would overwrite the unit's, a list would be added to it: that is how
`yara` had lost `/tmp` on the agent when it was installed by `PLUME_EXTRA_COLLECTORS=yara` (installed
by `PLUME_WITH_YARA=1`, without the drop-in, it saw it), and how the sensors the agent installed with the
drop-in received all four families. CI derives each unit's families from what its script
calls and refuses any deviation; `controls` and `custom`, which execute the operator's commands
(`/etc/plume/controls.d/*.check`, `/etc/plume/custom.d`), keep all four: a `kubectl`,
`nft` or `ss` check must be able to open its socket. The tool → family table is read from the tools' code,
not measured under systemd.
For `yara`, `PrivateTmp=true` or `PrivateTmp=disconnected`, and `DynamicUser=yes` (which forces a private `/tmp`
whatever the value of `PrivateTmp=`), take `/tmp` and `/var/tmp` away from it: CI refuses this
in the shipped files (unit and drop-in), a drop-in you install after the installation escapes it.

The **Proof** column gives the query that shows the source reports in. ♥ marks a sensor that emits a
**heartbeat** (`category=health`) at every run, even when the source is quiet: its silence is
then abnormal. Two do so only after a read: `auditd` (no heartbeat when the audit log
has not grown) and `web` (none when the run has read no new request: empty log,
or frozen because Traefik no longer writes). For sensors without ♥,
a quiet source produces nothing, and the proof is to run the sensor by hand (exit code 0, then
a file in `/var/lib/plume/spool/`), as the
[`README`](../README.en.md#end-to-end-assuming-nothing-is-known) does for `custom`.

| Sensor (`source`) | Reads · prerequisites | Privileges | What enters the SIEM | Risk · safe setting | Proof |
|---|---|---|---|---|---|
| `resources` (metrics) | `/proc`, `/sys`, `df` | root, **no** capability | CPU, memory, disk, temperature, network → `metric` table | no secret | `metric cpu_pct \| timechart avg(value)` |
| `integrity` | sensitive files, systemd units, persistence | root, capabilities bounded to `CAP_DAC_READ_SEARCH` | paths, SHA-256 digests, nature of the change | the paths say what the machine carries | `search source=integrity \| stats count` ♥ |
| `ship` | the spool | root, reads `/etc/plume/plume.conf` | *(emits nothing: it ships)* | refuses remote plaintext (§5) | `journalctl -u plume-ship` |
| `journal` (`sshd`, `sudo`, `su`) | journald | root, **no** capability | authentication lines, **full `sudo` command line** in `message` | any secret typed into a `sudo` command enters the SIEM: never pass a secret as an argument | `search source=journal category=health \| table ts, host, message` ♥ |
| `auditd` | `/var/log/audit/audit.log` · `auditd` + loaded rules (§6.4) | root | executions (`exe`, `comm`, `auid` — not the arguments), accounts, authentication failures, accesses to the `plume_*` keys | volume; ceiling `PLUME_AUDIT_MAX` (§6.3) | `search source=auditd category=health \| table ts, host, message` ♥ |
| `audit` | `ausearch` | root, capabilities bounded to `CAP_AUDIT_READ CAP_DAC_READ_SEARCH` | *(replaced by `auditd`; `bootstrap.sh` disables it)* | do not enable together with `auditd` | — |
| `controls` | `systemctl`, `sysctl`, catalogues `/etc/plume/controls.d` | root, capabilities bounded to `CAP_NET_ADMIN CAP_NET_RAW` | a **snapshot**: are the expected defences running | no secret | snapshot, shown by the overview: `search` does not see it |
| `firewall` | `nft` / `iptables` ruleset | root, capabilities bounded to `CAP_NET_ADMIN CAP_NET_RAW` | a **snapshot**: digest of the ruleset | — | snapshot, shown by the overview: `search` does not see it |
| `nft` | counters of the `nft` sets · `nft`, `jq` | root | counters → `metric` | — | `metric nft_blocked_total \| timechart avg(value)` |
| `ufw` | `ufw` | root | blocks seen, allowed rules | — | `search source=ufw category=health \| table ts, message` ♥ |
| `conntrack` | `ss` | root | inbound and outbound flows: addresses, ports, processes | map of the host's traffic | `search source=conntrack \| stats count by dir` |
| `origin-drop` | `journalctl -k`, prefix `ORIGIN-DROP:` that you set | root | packets dropped at the origin | — | `search source=origin-drop category=health \| table ts, message` ♥ |
| `portscan` · `portprobe` | `nft` table `plume-portscan` · `nft`, `jq` | root | sweeping addresses, ports | — | `search source=portscan category=health \| table ts, message` ♥ |
| `bans` (`fail2ban`) | `cscli`, `fail2ban-client` (or in a pod) | root; **kubeconfig** if the engines are in the cluster | active bans, `category=ban` | `kubectl exec` in the engine's pod (§6.1) | `search source=fail2ban category=health \| table ts, message` ♥ |
| `crowdsec` | `cscli` (or in the LAPI pod) · `jq` | root; **kubeconfig** in k3s | alerts, and a heartbeat that says what the engine **reads** | behind a proxy, the whitelist of private addresses blinds the engine; the cause follows the breakdown per whitelist, the refusal waits for `PLUME_CROWDSEC_SANS_SCENARIO_MAX_HEURES` (24); a refused mTLS handshake is not seen (§6.5) | `search source=crowdsec category=health \| table ts, acq_verdict, message` ♥ |
| `falco` | Falco's JSON output | root, capabilities bounded to `CAP_DAC_READ_SEARCH` | eBPF detections | — | `search source=falco \| stats count` |
| `suricata` | `eve.json` | root | IDS alerts | — | `search source=suricata \| stats count` |
| `clamav` | `clamscan` / `clamdscan` on new files | root | file, signature | file names escaped | `search source=clamav \| stats count` |
| `yara` | `yara` + your rules in `/etc/plume/yara.d`; scans `/home /tmp /var/tmp /dev/shm` by default | root, `/home` read-only, **host `/tmp` visible** (`PrivateTmp=false`, its temporary files go under `/var/lib/plume/state`) | file, rule, SHA-256 | without `yara` or without a rule, scans nothing and says so (`unavailable`) | `search source=yara \| stats count` |
| `vuln` | `trivy`, `crictl` | root | CVEs of the deployed images (`category=vuln`) | — | `search source=vuln \| stats count by severity` |
| `imgdrift` (`update`) | `skopeo`, `crictl` | root | new digest on the same tag | — | `search source=update \| stats count` |
| `containerd` | `crictl`, `jq` | root | images pulled, containers started | — | `search source=containerd \| stats count` |
| `kube-state` (`k8s`) | `kubectl` | root; the unit sets `KUBECONFIG` to k3s's **administration** file | cluster state → `metric` + events | cluster admin permissions (§6.1) | `metric kube_pods_running \| timechart avg(value)` |
| `kube-audit` | API audit file | root | verb, resource, user, decision | — | `search source=kube-audit \| stats count by verb` |
| `kube-rbac` | `kubectl` | root; **kubeconfig** | who can do what (bindings, roles) | — | `search source=kube-rbac \| stats count` |
| `pod-logs` (`k8s-log`) | `/var/log/pods` | root, capabilities bounded to `CAP_DAC_READ_SEARCH` | pod log lines **filtered** (threshold `PLUME_POD_LOG_MIN_SEV`, default 3) | an application log line can carry personal data or a secret; exclusions through a local drop-in (§6.6) | `search source=k8s-log category=health \| table ts, message` ♥ |
| `web` | Traefik access log (`kubectl logs` or file) | root; **kubeconfig** in k3s mode | requests: method, path as Traefik writes it, status, address | a token passed as a URL parameter enters with the path; read bound `PLUME_WEB_MAX` (§6.2) | `search source=web category=health \| table ts, message` ♥ |
| `mail` | mail server log (file, Docker container or pod; source detected in the order k3s, Docker, file when `PLUME_MAIL_SRC` is not set, a set value taking precedence) | root; **kubeconfig** if the server is in the cluster | connections, DKIM/DMARC/SPF verdicts, outbound, queue, ClamAV | **local parts masked** everywhere (`*@domaine`), except the sender of a sending **originating** from this server (mass-sending rule); the **local** recipient of a virus or a banned attachment stays masked unless `PLUME_MAIL_DEMASQUER_DESTINATAIRE_LOCAL=1` with `PLUME_MAIL_DOMAINES_LOCAUX` (risk and setting: `deploy/CONFIDENTIALITE.md`) | `search source=mail \| stats count by category` |
| `collector-mail` | the host's maildir | root, reads `/etc/plume/mail.conf` | account, folder, sender's domain, pattern found; URL **cut** at the path (query, fragment, credentials removed); **subject not emitted** unless `PLUME_MAIL_EMIT_SUBJECT=1`; a mailbox named in `PLUME_MAIL_EXCLURE_COMPTES` is **never opened** (exact comparison, count of excluded mailboxes in the heartbeat, `deploy/MAIL.md`) | a URL path can carry a token (`/reset/<jeton>`): it goes out bounded, not removed | `search source=mail \| stats count` |
| `collector-syslog` | UDP/TCP 514 | **user `soc`**, sole capability `CAP_NET_BIND_SERVICE` | syslog lines from devices (FortiGate, generic) | syslog is authenticated by **nothing** (§5) | `search source=fortigate \| stats count` |
| `minio-audit-relay.py` (`minio-audit`) | MinIO audit webhook | **user `soc`** | bucket, object, operation, access key, address | refuses to start without a token (§5) | `search source=minio-audit \| stats count` |
| `minio` | `mc` | root; **kubeconfig** | policies, public buckets, users | — | `search source=minio \| stats count by kind` |
| `dataaccess` | access audit rules | root, capabilities bounded to `CAP_AUDIT_READ CAP_DAC_READ_SEARCH` | user, action, path | without `CAP_AUDIT_CONTROL`, `auditctl -l` is refused to it: the heartbeat names the keys **proven by the log** (loading or access since the last start of `auditd`), and says "couverture INCONNUE" (severity 1) when neither `plume_data` nor `plume_creds` is proven there | `search source=dataaccess category=health \| table ts, message` ♥ |
| `dataacl` | permissions of the watched paths | root, capabilities bounded to `CAP_DAC_READ_SEARCH` | owner, mode, risk | the default paths target a k3s node: elsewhere, set `PLUME_ACL_PATHS`. No path present → admission `unavailable` (an empty map does not say "healthy permissions"); path present but unreadable or not traversable → admitted, only its head is mapped; absent paths next to a present one → admitted if `PLUME_ACL_PATHS` is set (a path under `/home` or `/root` looks absent under `ProtectHome`), kept silent for the default list | `search source=dataacl \| stats count` · `search source=dataacl category=config \| table ts, message` |
| `cloudflare` · `cloudflare-http` | Cloudflare's GraphQL API · `curl`, `jq` | root, reads `/etc/plume/cloudflare.conf` | WAF events, 4xx/5xx requests seen at the edge | read-only token on the zone | `search source=cloudflare-http \| stats count` |
| `prom-scrape` | your `/metrics` targets | root, reads `/etc/plume/prom.conf` | series → `metric` | a target authenticated by URL parameter exposes that parameter; refuses remote plaintext towards the central (§5) | `metric <une de vos séries> \| timechart avg(value)` |
| `custom` | your `CMD`, as root | root | one output line = one event | `/etc/plume/inputs.d` **must** be `0700 root`: writing there means executing as root | `search source=<SOURCE> \| stats count` |
| `respond`, `engagement-adapter`, `backup` | *(not sensors: they act or back up)* | central `respond` (`plume-daemon respond`): root, capabilities bounded to `CAP_NET_ADMIN CAP_KILL`; agent `respond` (`respond.sh`) and `engagement-adapter`: root; `backup`: `soc` | action results | the agent responder acts as root with no bound: dry-run by default; `respond.sh` and `engagement-adapter` refuse remote plaintext towards the central (§5) | — |
| `windows/` | Windows logs, firewall, Defender | scheduled task | §2.5, and [`../collectors/windows/README.md`](../collectors/windows/README.en.md) | refuses remote plaintext towards the central (code 2, nothing read or shipped) unless `PLUME_SHIP_ALLOW_PLAINTEXT=1`, which leaves the token readable on the network (§5); writes, as judged in CI, only commands, parameters, types and methods from a closed list, sends only through `Invoke-RestMethod`, and no literal UNC path (a name or path built at run time escapes this check); source in UTF-8 with BOM, without which Windows PowerShell 5.1 would read it in the ANSI code page; Windows PowerShell 5.1 compatibility judged by static analysis, not executed | `search source=windows-security \| stats count` |

**A sensor that cannot collect says so**, instead of staying silent: a `category=config` event,
`collect_status=unavailable` and a `reason` (`missing-dependency`, `missing-source`, `missing-config`,
`subsystem-absent`, `unreachable`). A collection cut off by a bound says so too
(`reason=collection-capped`). The two queries:

```
search category=config collect_status=unavailable | table ts, host, source, reason, detail
search category=config reason=collection-capped | table ts, host, source, detail
```

> ⚠️ **The alert on these admissions is not active by default.** The rule
> `config.d/rules/catalog/de-collector-unavailable.json` ships `enabled: false`, like almost all of the
> catalogue. Enable it in the console (admin role): the activation is recorded separately and **survives**
> a restart, which the file would otherwise reimpose. As long as it is off, a blind sensor raises
> nothing. Another limit, open under `P10.32-s`: an unavailability admission keeps its source's flow
> probe fresh, so the source looks alive.

---

## 5. Transport

- **The scripts that talk to the central refuse plaintext towards a remote host**: `ship.sh`,
  `respond.sh`, `prom-scrape.sh`, `engagement-adapter.sh` and the Windows collector. `PLUME_CENTRAL` over `http://` (or without
  a scheme) towards anything other than the loopback (`127.0.0.0/8`, `::1`, `localhost`) is **refused**,
  code 2, before any call to the central: `ship.sh` neither ships nor evicts anything (the spool stays),
  `respond.sh` neither fetches nor executes any action, `prom-scrape.sh` scrapes no target,
  `engagement-adapter.sh` revokes its ban exemptions for this cycle (its `revert-expired` mode
  does not call the central and is not affected). `PLUME_SHIP_ALLOW_PLAINTEXT=1` accepts it, with a
  warning at every run — **the token then travels readable on the network**, whoever listens to it
  can replay it, and an intermediary can answer in place of the central (actions executed as
  root by `respond.sh`, exemptions set by `engagement-adapter.sh`). Only set it on an already
  encrypted link (tunnel) or a network you answer for, and **in each unit's environment
  file**: each one reads its own (`plume.conf` for `ship`, `responder.conf`, `prom.conf`,
  `engagement-adapter.conf`). The Windows collector (`plume-collector.ps1`) applies the same gate,
  code 2 before any log read, and additionally refuses any address that does not start with
  `schéma://`, loopback included (`Invoke-RestMethod` would read it otherwise); its opt-in is set
  in its environment or in `C:\ProgramData\plume\plume.conf`.
- **Agent-side TLS**: `PLUME_TLS_CACERT` for a central with a private authority; `PLUME_TLS_CERT` and
  `PLUME_TLS_KEY` for a client certificate, if the central's proxy requires it. The daemon, for its part,
  verifies no client certificate: mandatory mTLS is set up on the proxy. Same variable name,
  opposite role on the daemon side ([`AGENTS-PROTOCOLE.md` §7](AGENTS-PROTOCOLE.md#7-tls-et-mtls)).
- **MinIO relay**: it **refuses to start** without a token (file `PLUME_MINIO_AUDIT_TOKEN_FILE` absent,
  empty or unreadable: code 2), answers `401` to a request without the right token (constant-time
  comparison) and `503` if the token becomes unreadable while running. Its default listener is the address of the
  pod bridge (`PLUME_MINIO_AUDIT_BIND`), not all interfaces.
- **Syslog**: the configuration installed by `bootstrap-agent.sh` listens on **`127.0.0.1:514`**. A listener
  outside the loopback **without** `PLUME_SYSLOG_ALLOW` makes the **start refuse** (code 2); a listener
  set **empty** cuts off its transport; an **absent** listener means `0.0.0.0:514` — and then falls under
  the same refusal without a list. To open it to your devices: the list, then a default-deny
  firewall, then only the listener. In a container, the loopback is the container's: the procedure
  to follow is in [`../deploy/SYSLOG.md`](../deploy/SYSLOG.en.md#container-docker-and-the-receiver-of-deployment-b--the-image-starts-refused).

---

## 6. The risks the product accepts, and how to reduce them

### 6.1 Root sensors, and the cluster administration file

The Kubernetes sensors (`kube-state`, `kube-rbac`, `web` in k3s mode, `mail`, `bans`, `crowdsec`,
`minio`, and the agent responder) call `kubectl` or `k3s kubectl` **as root** on the node. The `kube-state` unit sets
`KUBECONFIG` to k3s's administration file; the others take whatever `kubectl` resolves, and
`k3s kubectl` run as root uses that same file. **A flaw in one of these scripts is therefore worth the
cluster's administration permissions.** To reduce this:

- give each unit a dedicated kubeconfig, through a **local** drop-in
  (`sudo systemctl edit plume-kube-state.service`, then `[Service]` and
  `Environment=KUBECONFIG=/etc/plume/kube-lecture.yaml`, file `0600`);
- bind that kubeconfig to a service account with **only the useful verbs**: read (`get`, `list`) for
  `kube-state` and `kube-rbac`; `pods/log` on Traefik's namespace for `web`; `pods/exec` — reading
  a log or running `mc`/`cscli` **inside** the pod — on the targeted namespace only for `mail`, `minio`,
  `bans`, `crowdsec` and the responder. `pods/exec` amounts to executing code in that pod: grant it
  nowhere else;
- only enable the sensors whose output you read. *This split has not been tested here: check
  each sensor with its proof query after the change.*

The **daemon**'s pod, for its part, has neither a Kubernetes client nor a mounted service account token.

### 6.2 The k3s `Ingress`, and what can be seen behind a proxy

The shipped `Ingress` is restricted to the `websecure` entrypoint; another controller ignores these annotations and
may also serve the plaintext entrypoint (§2.4). Behind any proxy, three facts:

- **the native ban** reads the client's real address from the headers, **but only** from a trusted
  peer: by default any private or loopback peer; with `PLUME_TRUSTED_PROXIES`, only the
  listed addresses. A pod on the private network that reaches the daemon directly can therefore, by default,
  rewrite its own address: set `PLUME_TRUSTED_PROXIES`, and seal the headers with `PLUME_EDGE_SECRET`;
- **rate limiting and anti-brute-force lockout** count per **TCP peer**, hence by
  the proxy's address: all clients share the same bucket. Repeated failures against the admin
  account from outside lock that account **for everyone** behind that proxy, for the duration
  of the *backoff*;
- **the session cookie and HSTS**: the daemon sets the `Secure` attribute on its cookies and the HSTS header
  on its responses with **native TLS**, or when `PLUME_TLS_TERMINATED_UPSTREAM=1` tells it that a
  proxy serves HTTPS in front of it ("1" alone enables it; empty by default). It takes this setting at its
  word. Failing this setting, it reads `X-Forwarded-Proto` from a peer listed in
  `PLUME_TRUSTED_PROXIES` (explicit list, never the "private peers" default): `https` on every
  value also sets `Secure` and HSTS. A list set for the client's real address therefore enables HSTS
  if that proxy announces `https`. `deploy/k3s.yaml` sets `PLUME_TLS_TERMINATED_UPSTREAM` to `1`, its `Ingress`
  serving only `websecure`; on a native host, it is set in `/etc/plume/soc.conf`; in Docker, in `.env`
  (the service passes it on). Once set, a **direct** HTTP access to the daemon (tunnel, `port-forward`) loses its
  session cookie, and the daemon mentions it again in its log at startup. Without this setting or a
  listed proxy announcing `https`, the cookie goes out without `Secure` and without HSTS: do not then serve the
  same name in plaintext.

`PLUME_WEB_MAX` (default 10000) bounds the lines the `web` sensor reads per run. What a longer
stream does beyond that depends on the source:

- **`PLUME_WEB_SRC=file`**: the log is read by byte offset. Beyond the bound, the rest is read
  on the following runs: nothing is skipped. Only the first run (no read state) reads the last
  `PLUME_WEB_MAX` lines, and the heartbeat says how many earlier bytes it has not read. After
  a rotation, the end of the previous log is resumed from `<journal>.1`; after two rotations between
  two runs, from `<journal>.2` (or `<journal>.2.gz` if `gzip` is installed), then `.1`, then the
  current log, each line once. An empty log has no identity: when the current log
  is empty after a rotation, the state points to the end of the rotated log, and that empty log, filled then
  rotated in turn, is read from `.1`. Previous log not found (compressed rotation without
  `delaycompress`, or three rotations): the rotated logs modified since the previous run
  (dated marker `web.lecture` in the state, compared by `find -newer`) are read; the loss is admitted
  (`missing-source`, "nombre inconnu", "peut-être nul" for the remainder of the previous log only),
  including when nothing had been read from it yet, with the names of the modified logs that cannot be read.
  A `.1` absent or unreadable between `.2` and the current log is admitted as lost, whether `.2` was complete at the
  start of a run or at its end. Limit: a log written then rotated within the same second as the
  marker is not recognized as later where `find` only compares to the second;
- **`PLUME_WEB_SRC=k3s`** (the default): `kubectl logs --tail` only returns the last lines of the
  window. The oldest ones are not read, but a second `kubectl logs` **counts** them, and the
  number is admitted in the heartbeat and by a `collection-capped`, in total and **per named pod**: exact
  for a pod whose count (10 × `PLUME_WEB_MAX` lines per pod) goes back before the window, "au
  moins N" otherwise, or "nombre inconnu" when the count fails, sees fewer requests than the
  read, or no longer returns a pod that was read. It requires a `kubectl` 1.17 or more
  recent (`--prefix`).

The heartbeat carries the value in force ("borne de lecture PLUME_WEB_MAX=10000 atteinte" at the default):
search for `PLUME_WEB_MAX=`. In k3s, raise it if this message comes back.

### 6.3 The `auditd` ceiling

`PLUME_AUDIT_MAX` (default 4000) bounds the events emitted per run. Beyond it, the events of the
**tampering** keys (TAMPER) are kept first, then the others by decreasing severity; what remains is
**counted** and admitted in the heartbeat (`… au-delà du plafond PLUME_AUDIT_MAX`) and by a
`collection-capped`. Raise the bound if the admission repeats.

### 6.4 Audit rules that duplicate plume's

`augenrules --load` concatenates the files of `/etc/audit/rules.d/` and **stops at the first failing
rule** without rolling back. A rule from **another** file identical to a rule in
`plume.rules` makes that duplicate fail ("Rule exists"), and everything after it is not loaded — at
loading as well as at the start of `auditd`, which replays the same assembly.

Both installers go through **a single loader**, `plume-audit-rules-load.sh`: `bootstrap.sh`
calls it when `auditd` is installed, `bootstrap-agent.sh` installs it without running it and displays the operation.
It comments out, in the installed copy, each line of the template already declared **identically** by another file
(`## plume-doublon : déjà déclarée par <fichier> …`), runs `augenrules --load`, counts per key what
`auditctl -l` reports, catches up rule by rule on what is missing, and returns:

| Code | What the kernel holds | Message |
|---|---|---|
| `0` | everything, through the assembly itself | `>> OK — toutes les règles déclarées sont chargées.` |
| `1` | **not everything**: each missing key is named, and the refused line with `auditctl`'s message if there is one — or the loader could not work (template not found, `auditd` absent, not root), message in `!!` | `!! CHARGEMENT PARTIEL — REFUSÉ`; if it has caught up rules, it says how many will be lost at the next start |
| `2` | everything **now**, but through the catch-up alone: the next start of `auditd` will stop at the same place | `!! RÈGLES PLUME COMPLÈTES MAINTENANT, MAIS PAR LE SEUL RATTRAPAGE` |

`bootstrap.sh` installs everything else then ends with code `3` if the loader did not return `0`, with a message
specific to each case ("RÈGLES D'AUDIT INCOMPLÈTES MAINTENANT" for `1`, "RÈGLES D'AUDIT COMPLÈTES
MAINTENANT, MAIS PAS AU PROCHAIN DÉMARRAGE" for `2`). A duplicate written differently (order of the fields)
is not recognized as identical: it ends with code `2`. The details are in
[`ENDPOINT-SECURITY.md` §4ter](ENDPOINT-SECURITY.md#4ter-charger-les-règles-et-vérifier-ce-qui-tourne).

**Check, read-only** — modifies nothing:

```sh
sudo auditctl -l | grep -oE '(-k |key=)[a-z_]+' | sort | uniq -c  # count per key: `-k` for watches, `key=` for system calls
sudo grep -E '^[[:space:]]*-' /etc/audit/rules.d/plume.rules | grep -oE -- '-k [a-z_]+' | sort | uniq -c  # what the file declares
```

Each key of the second count must have at least as many rules in the first — a line commented out
`## plume-doublon` does not count in the second, the rule being held by the other file. The list must
carry
`exec_tracking` (two `execve` rules, 64 and 32 bits): without it, `category=exec` stays empty.
`svc_exec` only appears if you have uncommented its rules in the template.

**Reload** — this is not a check: `plume-audit-rules-load.sh` **reinstalls** the template,
deduplicated, over `/etc/audit/rules.d/plume.rules`, then loads and counts as above.
**A locally modified copy of `plume.rules` is overwritten**: carry your changes over into the template
you pass to it, or back up the file beforehand. Also rerun it after any change to another
file of `/etc/audit/rules.d`: a rule commented out in plume's file because another file carried it
disappears along with that file.

```sh
sudo sh systemd/plume-audit-rules-load.sh                        # central, from the repository: template systemd/plume-audit.rules
sudo sh /usr/local/lib/plume/plume-audit-rules-load.sh /usr/local/share/plume/plume-audit.rules   # agent
```

Without an argument, the loader takes `plume-audit.rules` next to itself (the repository), otherwise
`../../share/plume/plume-audit.rules` from its directory: once installed, `/usr/local/share/plume/`, where
both installers put the template. Passing it as an argument, as above, leaves no doubt.

### 6.5 CrowdSec behind a proxy

Behind a proxy or a tunnel, the address CrowdSec reads in the log is that of the **relay**,
a private address, and the whitelist of private addresses discards it before the scenarios: the engine reads
and cannot detect anything. The heartbeat says so (`acq_verdict` at `tout_en_liste_blanche` or
`surtout_liste_blanche`, threshold `PLUME_CROWDSEC_WHITELIST_SHARE_MAX`, default 90). The remedy is to make
the log record **the real client address** (the proxy's real-address header, an access log
that carries it), not to remove the whitelist.

**Which whitelist discards.** The sensor reads `cscli metrics show whitelists -o json` (fallback: the
`whitelists` section of `cscli metrics -o json`; absent before the 1.6.x versions that carry it) and names, in the
heartbeat and in the admission, the lines discarded by each list over the window (on the first run, or without a readable
state: since the agent's start, and it says so). The cause "private address of a proxy" is only stated
if **all** of them went to `crowdsecurity/whitelists`. If another list has discarded some (for example a
list of the responses served to an SSO session), the engine reads the real addresses; and, when **no** line has
reached the scenarios (`tout_en_liste_blanche` or `en_liste_blanche_sous_le_seuil`), nothing anonymous has reached
the origin over the window (filtered upstream, or site unreachable) — on `surtout_liste_blanche`, lines did get
through and this sentence is not said. Unreadable breakdown: "répartition inconnue", and no cause is asserted.

**A duration, not a cry per run.** As long as no line has reached the scenarios for less than
`PLUME_CROWDSEC_SANS_SCENARIO_MAX_HEURES` hours (default 24; `0` = immediate refusal, the old behaviour;
unreadable = fallback to 24, stated), the verdict is `en_liste_blanche_sous_le_seuil`: severity 1, duration and threshold in
the message, no admission. At the threshold, `tout_en_liste_blanche` refuses to conclude (severity 3, admission), duration stated. The
duration runs from the last run in which lines reached the scenarios (`crowdsec-scenarios-atteints.ts`
in the sensor's state); after an upgrade, it starts from the first run that notices the absence of this
timestamp, and says so. Price: during this delay, an engine truly blinded by a proxy does not refuse — it
says so at severity 1, with the breakdown that names the private list. If this timestamp is absent or unreadable
and cannot be written (sensor state not writable), the duration cannot run: the sensor refuses without
waiting for the threshold, says so in the message, and admits the write failure (`etat/horodatage`). A valid timestamp
already set keeps counting the duration, even if the state has become not writable.

**Limit: a route served by a relay without an address header, or protected by mTLS.** In a deployment where
a relay or a tunnel adds no real-address header, the lines of that route carry the address of the
relay, and the list of private addresses rightly discards them. A refused mTLS handshake produces **no**
access line: CrowdSec therefore does not see these attempts. It is mTLS that refuses them, not CrowdSec that sees them.

### 6.6 `pod-logs`: its exclusions go in a LOCAL drop-in

The unit reads no configuration file. `PLUME_POD_LOG_SKIP` (pods already covered by a dedicated
sensor) and `PLUME_POD_LOG_MIN_SEV` are set through `sudo systemctl edit plume-pod-logs.service` — never
in the shipped file, which an update overwrites.

### 6.7 What cannot be seen at a glance

- A `.env` setting that the service's `environment:` block does not list does not reach the container.
- `PLUME_QUERY_MAX` is read from the **environment only**: on a host, writing it in
  `/etc/plume/soc.conf` has no effect — set it through a drop-in of `plume-daemon.service`.
- SETUP mode stays open as long as no admin exists.

---

## 7. The dashboards, and the sensor that feeds them

A dashboard seeded empty is not a broken dashboard: it is often an absent producer. Taken from
`daemon/src/seeds.rs`:

| Seeded dashboard | Shipped producer | Good to know |
|---|---|---|
| SOC — Vue d'ensemble | all; `resources` for the curves | — |
| Sécurité & détection | `vuln`, `clamav`, `conntrack`, `auditd`, `suricata`, `mail` | one panel per sensor: empty if the sensor is not enabled |
| Réseau sortant (egress) | `conntrack`, `resources` (`net_tx_bps`) | — |
| Trafic web | `web`, `cloudflare` | — |
| Mail — flux & verdicts | `mail` | senders and recipients appear masked there (`*@domaine`), except the sender of a sending originating from the server |
| Accès données (Varonis) | `dataaccess` | — |
| Carte d'accès (Varonis) | `dataacl` | — |
| RBAC k8s (Varonis) | `kube-rbac` | — |
| MinIO / S3 (Varonis) | `minio` | — |
| Vault — accès secrets (Varonis) | `custom`, with the example declaration [`../deploy/vault-audit.input.example`](../deploy/vault-audit.input.example) | nothing without this declaration |
| Infra & logs (OBS) | `resources`, `kube-state` | — |
| Posture de configuration (SCA/CIS) | **none** | fed by a third-party agent (Wazuh, source `wazuh`) normalized at ingestion |
| Vulnérabilités (CVE endpoint) | `vuln` (images scanned by trivy) | also fed by a third-party agent (Wazuh, source `wazuh`) normalized at ingestion; `vuln` puts in `fields` the same names as the Wazuh normalizer — `cve`, `vuln_package`, `vuln_package_version` (installed version), `vuln_severity` (lowercase), `vuln_cvss` (v3 `nvd` score when trivy has it), `agent_name` (the scanning host) — plus `vuln_fixed` (fixed version) and `image`, which are its own; `vuln_title` and `vuln_status` only come from Wazuh |
| Conformité — `<cadre>` | **none** | same source as the posture |

That the two dashboards without a shipped producer (posture, compliance) should themselves say they have no source is carried by `P10.32-p`.

---

## 8. Search: what is capped, and how to read everything

In short, detailed in [`GXQL.md` §6.4](GXQL.en.md#64-what-the-ceiling-cuts-and-how-to-read-everything):
`PLUME_QUERY_MAX` (default 5000) **is not a limit on what plume queries nor on what it counts**:
it is the number of **rows returned** in a table. Without the cold tier, a `stats` is computed over all
the events of the window, and a `stats … by` that produces more groups than the ceiling returns the
first groups and says so. **With the cold tier active** (binary built with `cold_tier`, `PLUME_COLD_TIER=1`) and a window that reaches
the cold data, 5000 is also the number of cold rows that one of the read paths copies before
computing: when that copy has reached the ceiling, a query that computes a value over the whole set
is **refused** (`422`, `"reason": "cold_truncated_aggregate"`) rather than returning a wrong number. The way
out is to narrow the window, or to raise `PLUME_QUERY_MAX` up to `100000` at the cost of
memory. A regular expression cannot contain an alternation
today ([`GXQL.md` §2.4](GXQL.en.md#24-known-limitation-a-vertical-bar-inside-a-regular-expression)).
Its pattern is bounded, hot as well as cold and at Sigma import: 512 bytes (refusal `400`,
"motif regex trop long (max 512)"), 1 MiB of compiled program (refusal `400`, the engine's message),
1 MiB of lazy DFA cache (once exceeded, the search slows down without refusal). What remains open: the
interactive queries share a semaphore (`PLUME_QUERY_CONCURRENCY`, default 3), and a few
heavy queries launched together make all the others wait.
