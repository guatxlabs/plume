# collector-mail — host-native mail detection

[Français](MAIL.md) | [English](MAIL.en.md)

The SOC treats mail as **one more collector** (agent collects -> SOC ingests), instead of a
separate service. `collector-mail` reads the **maildir on the host FS**, applies **curated
patterns** (IOC / phishing / URL), and emits **MINIMAL events** (account, folder, sender
domain, message-id, IOC/URL sample) -> spool -> `ship.sh` -> central SOC (`source=mail` + FTS).
The sample of a URL keeps only its scheme, host, port and path (query, fragment and credentials
cut, and the cut is stated); a decoded parameter comes out by its NAME; the local part of an address
comes out as `*@domaine`. The subject only comes out with `PLUME_MAIL_EMIT_SUBJECT=1`, capped at 80 characters.

**NEVER a plaintext body** in the spool / the SOC DB (minimization = "security >= existing").
The **full body** remains a **pull gated by `role=admin` + audited**, a **distinct** agent-side capability
— NOT in this binary (see the `body` subcommand below).

## Where does it run
Host-native (not in-cluster): the maildir is on the **node FS** (local-path PVC), hence readable
directly. Same model as `audit.sh` / `falco.sh` / `pod-logs.sh`.

## Config `/etc/plume/mail.conf`
```sh
PLUME_MAIL_ROOT=/var/lib/<provisioner>/<pvc>_<ns>_<claim>-0   # volume path = /var/mail in the pod
PLUME_MAIL_DOMAIN=example.tld          # for the FLAT (single-domain) layout -> builds user@domain
PLUME_MAIL_FOLDER=*                  # all folders (default)
PLUME_MAIL_LIMIT=2000               # message cap per account on the 1st pass (incremental afterwards)
PLUME_MAIL_MAX_EVENTS=1000          # alert cap per run (anti-flood)
# PLUME_MAIL_PATTERNS=/etc/plume/mail-patterns.json   # overrides the default set (optional)
# PLUME_MAIL_EMIT_SUBJECT=0          # 1 = emits the subject (80 characters); 0 or nothing = no; anything else = refusal
# PLUME_MAIL_STATE=/var/lib/plume/spool/.mail-seen    # incremental state (default)
# PLUME_MAIL_EXCLURE_COMPTES=          # accounts NEVER opened (empty = all read); see below
```
> The default of the k3s local-path provisioner is `/var/lib/rancher/k3s/storage`; if your cluster
> mounts it elsewhere, put the REAL path here **and** set `PLUME_K3S_STORAGE` (kube-state collector) to
> the same path, otherwise the storage% metric is mute.

## Removing a mailbox from the scan — `PLUME_MAIL_EXCLURE_COMPTES`
A hosted mailbox that must not be analyzed is named here; the collector NEVER opens it: no
`stat` in its directory, no `read_dir`, no message read, no line in the incremental state, and
the `body` subcommand refuses to read it (see further down what it reads to know this). The "no
`stat`" rests on the order of the code (the decision on the name comes before any probe); the witnesses
(`collector-mail/tests/compte_exclu_jamais_ouvert.rs`, mailboxes with permissions 000) see a `read_dir` or
a read, not an isolated `stat`.
- **Form**: entries separated by commas and/or whitespace. With an `@` (`alice@example.test`):
  the full address, that account only. Without `@` (`alice`): the local part, in **every**
  domain of the maildir (flat layout: the domain is `PLUME_MAIL_DOMAIN`; nested: that of the directory).
- **EXACT comparison** of the name as the layout gives it, after ASCII lowercasing on both
  sides: `alice` excludes neither `alic` nor `alicex`. A non-ASCII account name matches no entry.
- **Refusal**: an empty entry (`a,,b`, trailing comma), a pattern (`*?[]{}`), a character outside the class
  (local part `a-z 0-9 . _ + -`, domain `a-z 0-9 . -`) or a malformed address STOPS the
  pass before any read; the admission (error output + `collect_status=unavailable` in the spool)
  names the RANK of the entry and the cause, never its value.
- **What the pass says about it**: the heartbeat (`journalctl -u plume-collector-mail`) carries
  `N compte(s) dont M ouvert(s), K exclu(s) par PLUME_MAIL_EXCLURE_COMPTES` — a COUNT, never a name.
  `0 exclu(s)` while a list is set: the entry targets no account (typo?).
- **Nested layout**: a top-level directory whose name equals an entry (local part, or
  `<nom>@PLUME_MAIL_DOMAIN`) is removed whole, without being probed to find out whether it is an account or a
  domain.
- **Three modes**: the collector runs on the HOST in all three (the maildir is on its disk); the
  setting goes in `/etc/plume/mail.conf` (read by `plume-collector-mail.service`), whether the mail
  server is native, in a Docker container or in k3s. Run by hand, the environment variable
  is added to the file's list (it does not replace it).
- **The scan and `body` reread `mail.conf` themselves, with ONE single rule**: `body`, launched by the
  daemon (`PLUME_MAIL_BODY_CMD`), inherits the DAEMON's environment, which does not load this file. Both
  paths therefore read `/etc/plume/mail.conf` (other path: `PLUME_MAIL_CONF`) through the same
  function:
  - the file's list is JOINED with the environment's (an entry from one OR the other excludes);
  - the flat-layout domain follows the service's precedence (`EnvironmentFile=` wins): the file
    that CARRIES `PLUME_MAIL_DOMAIN` decides, even with an empty value (which then means `localhost`, as for
    the service); otherwise the environment; otherwise `localhost`;
  - file ABSENT: the environment alone;
  - file present but UNREADABLE for the user running the command: REFUSAL, at the scan (admission
    `collect_status=unavailable`) as at `body`, whether or not the environment carries a list, and even if
    no list is set — the file's list cannot be judged. **Practical consequence**:
    `body` run as a user who cannot read `mail.conf` (`root:soc 0640` from
    `bootstrap-agent.sh`) no longer returns anything; run it as the scan's user (root), which already reads
    the maildir and this file.
- **A folder does not leave the account**: the `folder` of `body` (and `PLUME_MAIL_FOLDER`) is refused if it
  is empty, carries `/`, `\`, `..` or a control character; a folder or a linked `cur/`/`new/` that
  resolves outside the account is refused without entering it. Before, `Sent/../../bob` read the `bob`
  mailbox.
- **`body` judges the mailbox, not the written address**: the path the address resolves to (links and `.`
  followed) decides. In flat layout, `alice@autre.test` or `alice@example.test.` open the same mailbox
  `alice`: they are refused like `alice@example.test`. A folder of a removed account
  (`.Sent@alice`) is too; a path that leaves the root, or that designates no account the
  scan names, is refused as soon as a list is set.
- **What is not erased**: the incremental-state lines written BEFORE the exclusion remain in
  `.mail-seen` (file identifiers, no content).

## Activation (OPT-IN, golden rule)
Installed but **not enabled** by default. When you want it:
```sh
sudo systemctl enable --now plume-collector-mail.timer
```
Incremental state: each message is scanned only once (`.mail-seen`); the SOC-side `dedup`
(`mail:<compte>:<dossier>:<fileid>`) guarantees idempotence even if the envelope is re-shipped.

## Default patterns
`phishing-account-action` (subject), `phishing-urgent` (subject), `raw-ip-url`, `punycode-url`,
`credential-url`, `executable-link`, `decoded-credential` (decoded base64 params). `regex` engine
(finite automaton = linear time, no ReDoS) + cap on length/compiled size. Override possible
via `PLUME_MAIL_PATTERNS` (JSON `[{id,category,severity,target,regex}]`;
target = subject|from|text_body|html_body|url|decoded_url|headers).

## Full body fetch (gated + audited) — `body` subcommand
Reads the **full mail** of ONE message, on demand (forensics). It is the ONLY path that returns
the body; it remains **gated + audited**, and lives agent-side (no plaintext body shipped by the scan).
```sh
PLUME_MAIL_ROOT=... PLUME_ACTOR=<qui> plume-collector-mail body <account> <id> [folder]
# -> stdout: JSON {account,folder,subject,from,to,date,headers,text,html}
# rereads /etc/plume/mail.conf (or PLUME_MAIL_CONF) like the scan (list AND domain, same rule):
# an account removed from the scan is refused here too, before any search for the message
```
- **Gate**: invocation is reserved for the central (agent/SSH access through the agent role); the central
  checks `role=admin` BEFORE calling, and passes `PLUME_ACTOR` (who triggers it).
- **Audit**: each read writes a `source=mail-audit` event ("body read: acct/folder/id by actor")
  into the spool -> SOC (searchable + integrity chain on the central side).
- **Rendering**: the central displays the `html` in an `<iframe sandbox>` + CSP `default-src 'none'`
  (anti-XSS + anti-tracking).
- The binary does NOT serve HTTP continuously (no permanent surface): on-demand call.

## Parity before removal (NON negotiable)
If you already have a mail scanner (dedicated service, tab of an existing console), **do not remove it**
until the SOC's mail search has reached **parity** (see the switchover order in
`deploy/K8S.md`). Sequence: build -> verify parity -> then remove.

## The `collectors/mail.sh` log sensor: where it reads from (`PLUME_MAIL_SRC`)
Not to be confused with `collector-mail` (the maildir, above): `mail.sh` reads the mail server's LOG
(`mail.log`, ClamAV). It applies in all **three** deployment **modes**, and its source is set or
detected:
- **Set** (`PLUME_MAIL_SRC=k3s|docker|file`): taken as is, **takes priority**, never guessed and
  without any probe. `k3s` reads through `kubectl exec` (or `k3s kubectl`) in the pod of `PLUME_MAIL_SELECTOR`
  (default `app=mailserver`) in the namespace `PLUME_MAIL_NS` (default `mail`); `docker` through `docker exec` in
  the container `PLUME_MAIL_CONTAINER` (default `mailserver`); `file` reads `PLUME_MAIL_LOG` on the host
  (default `/var/log/mail/mail.log`, the docker-mailserver one; with source set to `file`, no other path is
  tried: a native Debian/Ubuntu postfix writes `/var/log/mail.log`, to be set). If the tool is missing, the read
  failure is admitted, nothing is attempted instead.
- **Not set**: detection, in this order, each probe read-only and bounded by `timeout`
  (`PLUME_MAIL_DETECTION_DELAI`, 5 s by default; an integer >= 1 without a leading zero, `0`/`00` would remove the
  bound: set and unreadable, it is admitted as `unreadable-config` and 5 applies): (a) `k3s` if `kubectl` or `k3s` is present AND a pod
  of the selector exists in the namespace; (b) `docker` if `docker` is present AND the named container
  is running (`docker inspect`); (c) `file` if `PLUME_MAIL_LOG` is a readable file, and, with `PLUME_MAIL_LOG`
  not set, the first readable file among `/var/log/mail/mail.log` (docker-mailserver) then `/var/log/mail.log`
  (native Debian/Ubuntu postfix), which becomes the log that is read. Native host (systemd, local log): (c);
  mail server in a Docker container: (b); in k3s: (a). The default ClamAV paths follow the
  RETAINED source, set or detected: `/var/log/clamav/` for `file`, `/var/log/mail/` (in the container) otherwise.
- **None**: admission `collect_status=unavailable`, `reason=missing-source`, detail `aucune source de journal
  mail detectee …`, which says what was tried and that `PLUME_MAIL_SRC` must be set; the sensor exits.
- **Retained, read failed** (set or detected): ANOTHER admission, that of a failed read, under the same
  reason `missing-source` but with the detail `LECTURE DE LA SOURCE IMPOSSIBLE (source_illisible) : …` which names the
  source and its origin; no marker is acknowledged, the slice will be reread.
- **Under a constrained unit** (`plume-mail.service`: `CPUQuota=25%`, `HOME=/tmp` in `PrivateTmp`, so the
  discovery cache of `k3s kubectl` starts cold on every pass): a k3s probe that exceeds the timeout
  makes a blind pass (admitted as `missing-source`, nothing acknowledged). **Set** `PLUME_MAIL_SRC` in
  `/etc/plume/plume.conf` when the source is known; detection is the fallback, not the operating setting.

The RETAINED source and its origin are stated in the sensor's config envelope (event
`source=mail category=config`, `type=collection-reducing`, under `filters`: `source`, and `source_origine`
which is `posee` or `detectee`). Witness: `.github/scripts/check_mail_sensor_reads_sender_checks_outbound_queue_and_clamav.py`.
