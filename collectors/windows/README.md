# Windows collector

[English](README.md) | [Français](README.fr.md)

Monitors a **Windows desktop or server** (home or organization alike) and ships the
events to the Plume central — the native PowerShell equivalent of the Linux collectors
(`collectors/*.sh`). A single file: [`plume-collector.ps1`](plume-collector.ps1).
No agent/spool required: it **POSTs directly** to `/api/ingest` (same contract
as `ship.sh`, `Authorization: Bearer <token>`).

## What it collects (each source degrades cleanly if unavailable)

| Plume source        | content                                                        | category |
|---------------------|----------------------------------------------------------------|-----------|
| `windows-security`  | logons 4624/4625, logoff 4634, privileges 4672, lockout 4740, **Kerberos/NTLM 4768/4769/4771/4776**, process creation 4688, account management | auth · exec · account |
| `windows-firewall`  | connections **blocked** by the firewall (WFP 5152/5157) + profile state | firewall |
| `windows-system`    | unexpected shutdowns 6008, service failures 7000/7031/7034     | system |
| `windows-defender`  | Microsoft Defender detections 1006/1015/1116/1117              | malware |
| `windows-network`   | established (remote) TCP connections + listening ports         | network |

Idempotent (per-source watermark + `dedup` on the central side): running it often does not
create duplicates. Read-only, TLS verified by default, ships only event
metadata.

## Prerequisites

1. **Windows PowerShell 5.1** (`powershell.exe`, built into Windows): it is the one the scheduled task
   below launches, and the script requires `#Requires -Version 5.1`. PowerShell 7 (`pwsh`) runs it too,
   but it is **the only one** continuous integration runs: under 5.1, nothing is executed in CI. 5.1
   compatibility is **judged there without being executed** (`.github/scripts/check_windows_collector_is_honest.py`):
   PSScriptAnalyzer, at a pinned version, checks the script against the Windows PowerShell 5.1 profiles it
   ships (Windows 10 1809, Windows Server 2016 and 2019: syntax, commands, parameters, types), and
   the syntax tree refuses `??`, the ternary, `&&`, `?.`/`?[`, `clean`, the background `… &`,
   `` `u{…} ``, `` `e ``, `-replace` with a written script block, `$IsWindows` and its kin, any type
   missing from even one of those profiles and any static member missing there. This judgement does not prove the
   **behaviour** of .NET Framework: the parsing of an address by `[System.Uri]` and by
   `Invoke-RestMethod` 5.1 (proxy, TLS) is only tested under PowerShell 7. Redirects are
   followed under neither version: the send carries `-MaximumRedirection 0` (see below).
   **The file is UTF-8 with a BOM, and must stay so**: without a BOM, Windows PowerShell 5.1 reads a
   script in the ANSI code page, and the collector no longer parsed (a "—" becomes a closing
   quotation mark there). An editor that re-saves without a BOM breaks the scheduled task; the guard refuses it.
   The script sends only through `Invoke-RestMethod`: the guard admits only the commands, parameters,
   types and methods it uses, WRITTEN in the source (closed list; a module-qualified name, a
   path to an `.exe`, a computed command name, an abbreviated parameter, the table of an `@p` splat
   judged by its keys, the member of `ForEach-Object`, any string literal starting with `\\` or
   `//` are refused). It does not see a name built at runtime and passed to an admitted command, nor a
   UNC path concatenated or read from configuration.
2. **Run as the SYSTEM account or an administrator** (the *Security* log requires it).
3. **Enable the audit policies** to populate some of the events.

> **What Windows 11 ALREADY audits, and what it does not.** *Measured on 2026‑08‑02 on a freshly installed Windows 11
> Enterprise 24H2 (build 26100), before any change:*
>
> | subcategory | by default | consequence without the commands below |
> |---|---|---|
> | `Logon` | **Success AND Failure** | `4624`/`4625` arrive **out-of-the-box** → `category=auth` is fed |
> | `Process Creation` | **No Auditing** | **`category=exec` stays EMPTY** — no `4688` is written |
> | `Filtering Platform Connection` | **No Auditing** | **`category=firewall` only receives the profile state**, no `5152`/`5157` |
>
> In other words: without line 2, process execution monitoring does not exist; without
> line 1, the firewall reports no block. The three commands were run **as is**
> and work (`The command was successfully executed.`, 0.16 s in total).
>
> **A SERVER does NOT audit more than a desktop — measured, and it is counter-intuitive.** *On 2026‑08‑02, on
> a freshly installed Windows Server 2022 Standard Evaluation (build 20348.587), the **59** subcategories
> returned by `auditpol /get /category:*` were compared between **Server Core** and **Desktop Experience**:
> **no difference**, and the three rows above are **exactly** what they are on Windows 11 —
> `Logon` = Success and Failure, `Process Creation` = **No Auditing**, `Filtering Platform Connection` =
> **No Auditing**. The three commands therefore remain **mandatory** on a server.* What the server
> additionally enables by default (and what a client desktop was not measured as having): `Credential Validation`,
> `Kerberos Authentication Service`, `Kerberos Service Ticket Operations`, `Directory Service Access`,
> `Computer/Security Group/User Account Management`, `Audit Policy Change` — **all on Success only**.
>
> **`category=exec` is not EMPTY without line 2: it is MISLEADING.** *Measured: with `Process Creation` audit
> at "No Auditing", Windows still writes **~23 `4688` on EVERY boot** (the processes created before
> LSASS applies the policy: `wininit`, `csrss`, `winlogon`, `services`, `lsass`…), all with an
> **empty** `CommandLine`, then nothing more. A dashboard that counts `exec` events therefore sees a figure that is
> non-zero and stable — and monitors nothing.*
   ```powershell
   auditpol /set /subcategory:"Filtering Platform Connection" /success:disable /failure:enable   # 5152/5157 (firewall)
   auditpol /set /subcategory:"Process Creation" /success:enable                                  # 4688
   auditpol /set /subcategory:"Logon" /success:enable /failure:enable                             # 4624/4625
   ```
   These names are **localized**: measured on an English-language Windows, they fail on a French-language
   Windows. The GUIDs do not depend on the language (form not tested here) — `Filtering Platform
   Connection` = `{0CCE9226-69AE-11D9-BED3-505054503030}`, `Process Creation` =
   `{0CCE922B-69AE-11D9-BED3-505054503030}`, `Logon` = `{0CCE9215-69AE-11D9-BED3-505054503030}`, to be passed
   as is: `auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable`.

## Configuration

Create a token on the central — **with the machine name as the 2nd argument**, otherwise the token is
bound to **no** host:

```sh
plume-daemon token poste-win01 POSTE-WIN01      # 2nd argument = the host the token is bound TO
```

> **The host-less form (`plume-daemon token poste-win01`) let anyone impersonate any machine, and
> it no longer exists.** It was written here until 2026‑08‑02. *Measured that day: with the token
> produced by the host-less command, an envelope carrying `"host":"CONTROLEUR-DE-DOMAINE-USURPE"` is
> accepted (**HTTP 202**) and the event is **stored under that name**. With a **bound** token, the same
> envelope is accepted but the `host` is **rewritten** to the token's host (`WS22-LAB`): the binding BITES.*
> The binding is also what authorizes the responder to act on that host. A token's scope is now
> a **declaration**: `plume-daemon token <nom> <HOTE>` (machine) or `plume-daemon token <nom> --relais`
> (multi-host forwarder, whose host is **not** attested). The two-argument form is **refused**.
>
> *The binding has been checked on **all** ingestion surfaces since 2026‑08‑02. Before that it was
> only checked on `/api/ingest` and `/loki/api/v1/push` — measured as spoofable with a bound token on
> `/api/metrics/prom` (200), `/api/metrics/write` (204) and `/services/collector` (200). See `docs/CIM.md`.*

Then fill in `C:\ProgramData\plume\plume.conf`. The script also reads `PLUME_CENTRAL` and `PLUME_TOKEN` from the
**environment**, and the environment **wins** over the file: a `PLUME_TOKEN` set as a machine variable
(which an earlier version of this README suggested) silently keeps priority and is readable by any
local user. Put the token in `plume.conf` only, and remove such a variable:
`[Environment]::SetEnvironmentVariable('PLUME_TOKEN',$null,'Machine')`.

```ini
PLUME_CENTRAL=https://soc.example.org:7000
PLUME_TOKEN=<le-jeton>
# PLUME_SHIP_ALLOW_PLAINTEXT=1   # http:// to a REMOTE central — token readable on the network, see below
```

`plume.conf` carries only these three keys: the script reads nothing else from it. **`PLUME_TLS_INSECURE` is not
read from it** (it only comes from the environment): set in this file, it has no effect, and
TLS verification stays active. The file carries the token: its permissions (SYSTEM and Administrators only,
inheritance disabled) and how to write it without the token going through a command line are in
[`docs/INSTALLER-SANS-OUVRIR-DE-BRECHE.md` §2.5](../../docs/INSTALLER-SANS-OUVRIR-DE-BRECHE.md#25-windows--the-collector-plume-collectorps1).
An environment variable wins over the file; under the scheduled task running as SYSTEM, only
**machine** variables are seen. **`PLUME_TOKEN` is never set as a machine variable**: it is
readable by any local user (key `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`,
and environment inherited by every process), which defeats the file's permissions. The token lives in
`plume.conf`, and nowhere else.

> ### Clear text to a remote central is refused
> `PLUME_CENTRAL` as `http://` to anything other than the loopback (`127.0.0.0/8`,
> `::1`, `localhost`) is **refused**: a `REFUS` message on standard error, **exit code 2**
> (visible in the scheduled task's `LastTaskResult`; a central outage exits with 1), and this happens
> **before** any log read and any send — nothing is read, nothing is shipped, no watermark
> moves: once the address is fixed, the next run resumes where the last acknowledged send
> stopped (within the limit of `-MaxAgeMinutes` on the first run). `https://` and `http://` to the loopback
> are unchanged. The address must start with `schéma://`: without it (`central.example.org:7000`,
> `127.0.0.1:7000`, `http:\\central.example.org`, `1http://central.example.org`) it is refused, opt-in or not, because
> `Invoke-RestMethod` reads it as relative, differently from the gate (measured: `http:\\central.example.org` and
> `1http://central.example.org` went out in clear text to a remote host). With `schéma://` at the start, the host is the one
> that `[System.Uri]` extracts, which is the one `Invoke-RestMethod` calls (measured under PowerShell 7;
> Windows PowerShell 5.1 is not tested): `http://127.0.0.1.example.org`, `http://localhost.example.org`
> or `http://127.0.0.1@example.org` target a remote host and are refused. Any other scheme is refused,
> opt-in or not.
>
> **No redirect is followed.** The gate judges the address written in `PLUME_CENTRAL`, not the one
> a `3xx` response would send to. Without `-MaximumRedirection 0`, an admitted central that
> answered `307`/`308` towards another host over `http://` sent all the events there in clear text, and
> on `301`/`302` the batch was counted as delivered when it had arrived nowhere (measured under
> PowerShell 7.6.3). From now on no redirect is followed (`-MaximumRedirection 0`), under 5.1 as
> under 7, and a redirect is a **send failure**: exit code 1, no watermark moves, the
> next run re-reads. It is not the exception that decides: Windows PowerShell 5.1, the one the
> scheduled task launches, only throws on `301`/`302` and returns a `303`, `307` or `308` as a normal response
> with an empty body. The collector therefore only treats a batch as delivered if the response carries
> `"queued":true`, the central's acknowledgement (`202`); an empty response, a proxy's HTML page or the JSON
> of another service are send failures. Tested under PowerShell 7 (including the empty-body response
> that 5.1 returns); Windows PowerShell 5.1 itself is not executed. **Effect on an already installed desktop**: if `PLUME_CENTRAL`
> names an address that redirects (an `http://` that a front end sends on to `https://`, a path that the
> front end rewrites, a login page of an authentication proxy), the scheduled task goes
> into failure (`LastTaskResult` = 1) instead of silently losing the batch: put in `PLUME_CENTRAL`
> the final address, the one that answers without a redirect.
>
> `PLUME_SHIP_ALLOW_PLAINTEXT=1` (environment variable or `plume.conf`, same reading as
> `PLUME_CENTRAL`) accepts clear text, with a warning on every run. **The risk is total**:
> the `Authorization: Bearer` token and every event (accounts, command lines, addresses) travel
> readable on the network; anyone listening on the path can replay the token and inject events
> under this desktop's name. Only set it on a link that is already encrypted (tunnel) or a network you
> answer for. It is the same gate, and the same variable, as `ship.sh` on the Linux side.

> ### ⚠️ The token NEVER goes on the command line — and the parameter has been removed
> The script used to accept `-Token` as a parameter, with the instruction not to use it. An instruction
> is not a guard: **the parameter no longer exists** (the token comes from `PLUME_TOKEN` or from
> `plume.conf`). What follows explains why, and what remains your responsibility.
> If `Process Creation` audit is active — that is, as soon as you have followed the prerequisites above —
> **and** the GPO *"Include command line in process creation events"* is enabled, or simply
> **Sysmon** is running (Sysmon puts the command line in its ID 1 **without any GPO**), then the token
> passed in argv is written in clear text into the *Security* log… **which this collector itself ships to the
> central**. *Measured on 2026‑08‑02: a bait token passed via `-Token` ended up readable in the SOC
> through **three** independent paths — `windows-security`/`exec` (this script), `WinEventLog:Security`/`exec`
> (Rust agent) and `WinEventLog:Microsoft-Windows-Sysmon/Operational`/`endpoint` (Sysmon ID 1).* This is the
> Windows counterpart of the `sudo` leak measured on Ubuntu, but **wider**: the mechanism is not
> the elevation tool, it is execution auditing itself. **Write the token into `plume.conf`, never
> in argv** — and if you have already done so, revoke it.
>
> **What has been closed, and what cannot be closed here.** Closed on the product side: the `-Token` parameter of
> this script (removed) and the Rust agent's `--token <valeur>` (replaced by `--token-stdin`, which reads the
> token from standard input). What remains open, and is NOT fixed in this repository: if an
> operator types a secret themselves on **any** command line, execution auditing
> captures it. It is a property of Windows (Sysmon ID 1 without a GPO; 4688 with the *"Include command
> line"* GPO), not of these scripts. The countermeasure is organizational — and, if the exposure has happened,
> revoking the token.

> ### The central uses TLS: set up trust BEFORE the first run
> With a certificate issued by a CA the desktop does not know, the run fails on
> `Could not establish trust relationship for the SSL/TLS secure channel`, exits with `1` and commits
> no watermark: the events wait in the Windows log and leave on the first run that gets through
> (limitation 1 below). What is not replayed is the samples of the failed run (profiles, network, heartbeat),
> nor what log rotation has carried away in the meantime. In an organization, the path is to install the internal CA in the
> machine store, once, before scheduling the task:
> ```powershell
> Import-Certificate -FilePath C:\ProgramData\plume\ca.crt -CertStoreLocation Cert:\LocalMachine\Root
> ```
> *Measured: after this import, `https://soc.central:7000/healthz` answers 200 with TLS verification
> ACTIVE; `PLUME_TLS_INSECURE=1` is then no longer needed.* Also remember `PLUME_HOST` on the central side:
> it must list the name the desktop calls, otherwise the anti-rebinding guard returns **421** to everything
> (see `deploy/k3s.yaml`).

## Installing as a scheduled task (every 5 min, as SYSTEM)

```powershell
$ps  = "$PSHOME\powershell.exe"
$arg = "-NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\plume\plume-collector.ps1"
# copy plume-collector.ps1 into C:\ProgramData\plume\ first
schtasks /Create /TN "Plume Collector" /SC MINUTE /MO 5 /RU SYSTEM /RL HIGHEST `
  /TR "`"$ps`" $arg" /F
```

`$PSHOME` is the folder of the console **where the command is typed**: typed in Windows PowerShell 5.1,
it targets `powershell.exe` 5.1; typed in `pwsh` 7, it targets a `powershell.exe` that does not exist
in the `pwsh` folder, and the task fails on every trigger (read from the code, not run). Type it
in Windows PowerShell 5.1, or write the full path
(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`).

Manual test (watch the events arrive in Plume):
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\plume-collector.ps1
```

*The `schtasks` command above was run **literally** on 2026‑08‑02: it works
(`SUCCESS`, 0.14 s) and the task survives a reboot.*

## What it costs, and how long it takes to report (measured on 2026‑08‑02)

*Windows 11 Enterprise 24H2 (build 26100), VM 2 vCPU / 4 GiB, plume central compiled from this repository,
private network path.*

| | measured value |
|---|---|
| duration of a full run | **35 s** (312 samples at 100 ms) |
| peak memory of the run | **191.5 MiB** (`WorkingSet` of `powershell.exe`) |
| CPU of a run | 17.4 s, i.e. **49% of one core during the run** |
| CPU **amortized** over the 5 min period | **5.8% of one core** |
| reboot → 1st event in the SOC | **240 s** |

**The 191 MiB peak is the real figure to remember**: it is ~17× that of the Linux collector
(11.1 MiB) and ~20× that of the Rust agent on the same desktop (9.6 MiB for a **permanent** service, at
**0.05% of one core**). It is the price of the PowerShell host, not of the work done. On an office
desktop it is absorbable; on a loaded server or a dense VDI, prefer the Rust agent
(`agent/README.md`), which also reports **much** faster: **24.6 s** after the reboot versus
240 s here, on the same machine and the same boot.

> **Is the 1st event a security one?** Yes, here — unlike Ubuntu, where the first one to arrive
> was a health heartbeat. The batch is sent in packets of 400 (`BatchSize`) and the heartbeat is
> added **last**: the first POST therefore already contains `auth`. *Measured: first event
> received = `windows-security`/`auth` ("An account was successfully logged on.").*
>
> **On the other hand, the health heartbeat is NOT a sign of life at the task's granularity.** Its `dedup`
> is bucketed by the **hour** (`windows-agent-health-<heure>`): a task scheduled every 5 min therefore produces
> **at most one heartbeat per hour**. *Measured: 6 consecutive runs → only 1 `category=health` event
> stored.* A dead-man's switch set to "no heartbeat for 10 min" would raise false positives.

## Windows Server 2022: what the server changes (measured on 2026‑08‑02)

*Two QEMU VMs, 2 vCPU / 4 GiB, Windows Server 2022 Standard Evaluation build 20348.587: `WS22-LAB` as
**Server Core** (no graphical interface) and `WS22-GUI` as **Desktop Experience**, promoted to **domain
controller** at the end of the campaign. Plume central compiled from this repository, private network path.*

| | Server Core | Desktop Experience | Windows 11 (previous sheet) |
|---|---|---|---|
| installation without TPM or Secure Boot | **yes** — VM started on bare OVMF, no `swtpm` | **yes** | no: `swtpm` missing = friction |
| unattended installation duration | **216 s** (power-on → 1st contact from the harness in the guest) | same order — **not timed to the same precision** (probe read at intervals: between 250 s and 341 s) | not quantified |
| default `auditpol` (59 subcategories) | *(identical, see the prerequisites box)* | **identical to Core** | identical on the 3 measured rows |
| PowerShell collector | **works fully** | works | works |
| duration of a run | 6.7 s to 11.2 s | **9.3 s** | 35 s |
| peak memory of the run | **177.3 MiB** | **176.8 MiB** | 191.5 MiB |
| CPU of a run | 9.5 s (141% of one core: PowerShell is multi-threaded) | 8.4 s (90%) | 17.4 s (49%) |
| Rust agent as a service | **7.9 MiB** | 7.8 MiB | 9.6 MiB |
| power-on → 1st event, Rust agent | **8.6 s** (2nd measurement: 11.1 s) | — | 24.6 s *(convention not recorded)* |
| power-on → 1st event, ps1 collector | **138.4 s** | — | 240.2 s *(same)* |

> **Convention for the "power-on" rows**: t0 = **VM start, machine powered off beforehand**.
> A first attempt timed from the **restart command** gave 17.6 s / 112.9 s — figures
> **discarded**: Windows' clean shutdown produces events that the agent ships *during* the shutdown,
> so they do not measure the recovery delay. The Windows 11 sheet does not record which of the two
> conventions it uses: the 24.6 s / 240.2 s are **not** directly comparable to the figures
> above; only the order of magnitude and the agent/collector ratio are.
>
> **The server's 1st event is neither health nor categorized.** *Measured: the agent's first event
> after power-on comes from the `Application` channel (Core) and arrives with an **EMPTY**
> category — see below the 36.7% of events without a category. The PowerShell collector's first event,
> for its part, is indeed `windows-security`/`auth`, as on Windows 11.*

**Server Core costs the collector NOTHING.** *Measured: `Import-Certificate` (0.41 s), `schtasks /Create`
(0.06 s), `Get-NetFirewallProfile`, `Get-MpComputerStatus` (Defender **is** present and active by default),
`Get-WinEvent`, `Expand-Archive` — everything responds on Core. The Rust agent installs and starts its SCM service there
(`install` → `Running`), and `test-ship` answers **202**.* No dependency on the graphical interface was
found, in the collector or in the agent.

> ### On a domain controller, the collector was BLIND to Kerberos — fixed, and the next gap declares itself
> *Measured after promoting `WS22-GUI` to controller of the `lab.plume` domain
> (`Install-WindowsFeature AD-Domain-Services` **43.4 s**, `Install-ADDSForest` **54.9 s**, +1 reboot,
> DC operational **70 s** later): creating one account and two authentications produced **2 × 4768**
> (TGT ticket) and **8 × 4769** (service ticket) in the `Security` log. On the SOC side, these events
> existed ONLY through the Rust agent (`WinEventLog:Security`, `category=auth`): the PowerShell collector had
> reported **0** of them, because its list of identifiers contained neither `4768`, nor `4769`, nor `4771`, nor
> `4776`.*
>
> **What changed, and why it is not "four more identifiers".** The four are there. But
> adding to a list leaves the NEXT gap to the next reviewer, so:
> - the list of identifiers is now **DERIVED from an `identifiant → issue` table** — an identifier can no longer
>   be collected without saying whether it means `success`, `failure`, `session_open`… (or `'-'`, "no
>   outcome", which is a declaration that has to be written). A CI guard refuses any bare `-Ids` call;
> - on every run the collector **CENSUSES** what the channel produced and it does not collect, and emits it as
>   `category=config type=collector-coverage` (`uncollected_ids`, `uncollected_events`, `census_capped`).
>   The gap no longer waits for a code review: it is **measurable from the SOC, on every host**.
>   That day, it would have displayed `Security : 10 événement(s) non collecté(s), identifiants [4768,4769]`.
>
> The census is bounded (at most a few thousand records per run) and **says when it has been
> bounded**: a census that believed itself complete would be lying in turn.
>
> **Promotion to DC adds NO audit coverage.** *Measured: the 59 subcategories before/after
> `dcpromo` differ only by the 2 rows enabled by hand by the commands in the prerequisites. The
> "Default Domain Controllers" policy therefore wakes up nothing that Plume expects — and, the symmetric
> good news, it does not overwrite the `auditpol` settings made before the promotion either.*

> ### Sysmon on a server: 2 s to install, 11 MiB — and it yields the command line without ANY GPO
> *Measured: `Sysmon64.exe -accepteula -i` (v15.21) = **2.11 s** on Core, **1.6 s** on Desktop
> (uninstall with `-u`: 3.5 s); the service runs at **11.0 MiB** and 0.03 s of cumulative CPU after start.
> On `WS22-LAB`, a machine whose audit policy has **never** been touched (`Process Creation` =
> "No Auditing", command line GPO **absent**), the bait `APPAT-CORE-SYSMON-…` passed in the argv of a
> `cmd.exe` produced **no** `4688` — but **2 Sysmon ID 1 events carrying it in clear text**.*
> In other words: **installing Sysmon is enough to send every command line up to the SOC**, secrets
> in argv included, without any audit setting having been made. With the *"Include command line…"* GPO
> enabled (and `gpupdate /force` — *measured: without it the setting does not take effect*), the bait came out through
> **two** independent paths: `windows-security`/`exec` (this script) and `WinEventLog:Security`/`exec`
> (Rust agent); without it, **0** of the `4688` events carried a non-empty command line.
>
> **An `exec` without a command line looks complete, and is not — the collector now says so.**
> This was the exact form of the defect: the event arrived whole (user, image, host), a search
> on `CommandLine` returned zero, and nothing explained why. On every run, the collector COUNTS the
> `4688` events collected without a command line and emits, if the count is not zero, a
> `category=config type=collector-coverage gap=exec-cmdline` carrying `cmdline_absent` / `cmdline_present`.
> No value is invented: a command line is not fabricated, its absence is declared.
>
> ⚠️ **Sysmon installed AFTER the agent**: its events are indeed read (the channel is in the agent's default
> list, and the bookmark includes it from the next run) — it was the fleet trap below, and
> not a channel problem, that made them disappear.

> ### The FLEET trap: two servers were stealing each other's events (fixed on 2026‑08‑02)
> `event.dedup` is **UNIQUE at the level of the central's database**, not per host, and the Windows log
> record identifiers **start again from 1 on each machine**. The keys produced here
> (`windows-security-<record_id>`, `windows-agent-health-<heure>`, `windows-fwprofile-<profil>-<heure>`…)
> did **not** carry the host name: the 2nd enrolled machine saw its events discarded **silently**
> by the central's `INSERT OR IGNORE`.
> *Measured with two servers on the same central: of the **311** records of the Sysmon channel of
> `WS22-LAB`, **266 arrived and 45 disappeared** — exactly the 45 that `WS22-GUI` had already shipped;
> and `WS22-GUI`'s hourly health heartbeat was **never** stored, the key being already taken.*
> **Fix (step 1, emitter side)**: the host name is prefixed once and for all in
> `Add-Event` (and in `winxml_to_event` on the agent side) — impossible to forget the host when adding a source.
>
> **Fix (step 2, central side — 2026‑08‑02)**: the trap was not specific to Windows. Measured on the
> Linux side the same day, by running the **36 shipped sensors** on two hosts missing the
> same prerequisites: **36 keys produced per machine, 26 of them identical**, and at ingestion **78
> events sent → 52 stored, 26 lost**, all on the 2nd machine (39 rows for the 1st, **13** for
> the 2nd). Fixing emitter by emitter was therefore not a fix: 40 keys built in 30
> shipped files, 5 languages, plus the sensors that customers will write. The central **now partitions
> `event.dedup` by the row's host** on write (`dedup_scoped_by_host`,
> `daemon/src/ingest/store.rs`): two rows whose `host` column differs can no longer delete
> each other, whatever key the emitter built. The prefixes set here become
> **redundant and are kept** (a collector must stay correct against an older central).
> *Verified AFTER the fix, on the same machines: `WS22-LAB` now carries **323 Sysmon keys
> continuous from 1 to 323** (no gap left), and `WS22-GUI` finally has its heartbeat
> (`WS22-GUI-windows-agent-health-…`).* **Upgrade consequence**: the keys change shape, so
> the first run after the upgrade re-ships once the events still within the watermark window
> (one-off duplicates, never a loss).
> ⚠️ **The same trap applies to any emitter** whose key does not include the host: it is a property of the
> central, not of the Windows collector. *Code reading (NOT measured): several Linux collectors
> (`update-<image>-<digest>`, `ban-<jail>-<ip>-<heure>`, `clamav-<fichier>-<signature>`…) form keys
> that are identical from one machine to the next and are therefore exposed to the same silent erasure — to be checked by
> measurement before concluding.*

## Known limitations, measured — read before deploying to a fleet

1. ~~**No spool: a POST that fails loses the batch.**~~ **FIXED on 2026‑08‑02.** The defect was real and
   measured: `Flush-Events` caught the failure, wrote a `Write-Warning` (which, under a scheduled task, goes
   **nowhere**), emptied the buffer **unconditionally**, and `Set-Watermark` had **already** moved the
   watermark. *Measured (pwsh harness running this script AS IS, simulated Windows log and central):
   central unavailable for ONE run, **42** eligible events → **0 arrived**, watermark moved anyway
   → **42 PERMANENTLY lost**, 0 recovered when it came back. Same harness, central available:
   0 lost / 42 arrived.*
   **What changes**: the watermark is no longer written where it is computed — it is **staged**
   (`Stage-Watermark`) and only **committed** after an **acknowledged** POST, by `Complete-Run`, the only place
   in the file that writes to the state disk. **The Windows log IS the spool**: as long as the watermark
   does not move, the next run re-reads exactly what did not get through (at‑least‑once; re-emissions
   are absorbed by the `dedup`, partitioned per host on the central side). *Re‑measured after the fix, same
   scenario: **0 lost, 42 recovered**.*
   > ⚠️ **Behaviour change to know before deploying**: an unacknowledged POST **THROWS** and the
   > run exits **non-zero** (the silent `Write-Warning` is gone). Under `schtasks`, this shows up in
   > `LastTaskResult` — an unavailable central becomes **visible** instead of silent. This is
   > intended: it is the only channel left when the central is unreachable.
   >
   > **What is NOT replayed**: the SAMPLES of a lost run (firewall profiles, network snapshot,
   > heartbeat) are not in a log — they are **recomputed** on the next run. No HISTORY
   > is lost; a sampling point is. For a proper disk spool,
   > the Rust agent remains the answer (`spool_cap`, at‑least‑once on disk).
2. ~~**A sensor that cannot collect does not say so.**~~ **FIXED on 2026‑08‑02.** *Measured before:
   `Security` log with **access denied** (the case of a technician running the script outside SYSTEM) → **12**
   events expected, **0 arrived, 0 admissions**, return code **0**, and the health heartbeat still announced
   "plume windows collector ok".*
   The script now carries the PowerShell mirror of the closed partition of `collectors/lib.sh`:
   `Plume-Unavailable` (inability) · `Plume-Disabled` (switched off by the operator) · `Plume-NoData` (nothing
   new — **legitimate** silence, no byte). The discriminant between "nothing new" and "blind" is the
   `FullyQualifiedErrorId` of `Get-WinEvent`, **never** the message: Windows messages are
   **localized**, and a test on the text would classify a real blindness as "calm" as soon as the machine
   is not English-language. The partition leans to the safe side: **only** `NoMatchingEventsFound` counts as silence.
   *Re‑measured after the fix, same scenario: **5 admissions** `collect_status=unavailable`
   (3 × `windows-security`, 1 × `windows-firewall`, 1 × `windows-defender`).*
   The admissions have the format of `plume_report_availability` (`category=config`,
   `collect_status=unavailable`, `reason` from the **same closed vocabulary** as the shell sensors), so the
   **existing** rule `config.d/rules/catalog/de-collector-unavailable.json` covers them without being touched.
   See who is blind: `search category=config collect_status=unavailable | table host, source, reason, detail`.
   **CI guard**: `.github/scripts/check_windows_collector_is_honest.py` (real PowerShell AST) requires that
   every `catch` classifies or rethrows, that no error is swallowed (`-ErrorAction SilentlyContinue` forbidden),
   and that no watermark is written before an acknowledged send. *Proved by mutation: 11 mutations, 11 red.*
3. **The field inventory does not cover this collector.** `daemon/src/collected.rs` declares 12 fields
   for `plume-collector.ps1`; *measured, this collector actually emitted **55 distinct ones*** (all
   the log's `EventData`: `SubjectUserName`, `NewProcessName`, `LogonType`, `CommandLine`…). The gap
   is not a forgotten declaration: the names come from the XML **at runtime**
   (`foreach ($k in $d.Keys)`), so the guard's **static** extractor cannot see them. The
   guard stays green while under-covering this path — it is a limitation of method, not a drift.
4. **Sysmon is not read.** This script does not touch the `Microsoft-Windows-Sysmon/Operational` channel.
   For Sysmon telemetry, you need the Rust agent (`agent/README.md`).
5. ~~**The CIM field `action` is NEVER set.**~~ **Outdated** (reading of the script, not re-measured):
   `Collect-Log` now takes an `identifiant -> issue` table and sets `fields.action` (`failure` for
   `4625`/`4771`, `success` for `4688` and accounts, `session_open`…), and the firewall sets `blocked`;
   the "0 of 1,505" count below is the one from **before** this fix. *Measured on 2026‑08‑02 on the two Windows Server 2022 machines:
   **0 of the 1,505** events from this collector carry `action` — like the **0 / 6,962** of the Rust agent
   (even though `docs/CIM.md` §4c makes it the neutral composition vocabulary).* On the other hand this collector
   **always** sets a `category` (**0 / 1,505** without a category), where the agent leaves 36.7% empty:
   on this precise point, the PowerShell collector is the more complete of the two.
6. ~~**Kerberos is missing on a domain controller**~~ **Outdated**: `4768`/`4769`/`4771`/`4776` are
   in the outcome table of `win-auth` (reading of the script) — see the Windows Server 2022 section
   above, which states the measured gap and its fix.

## Extending

Need a specific source (an application log, a registry key, a
counter)? Add a `Collect-Log` call (for an event log) or a
small `Add-Event` block in the script — or, without touching the script, use a generic
**scripted input** on the Linux side that queries the Windows machine remotely
(see the "Adding your sources" section of the main README).
