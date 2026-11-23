# collector-syslog — syslog receiver + vendor parsers (1st = FortiGate)

[English](SYSLOG.md) | [Français](SYSLOG.fr.md)

The SOC treats a network appliance (**FortiGate**, switch, router, any syslog device) as **one more
collector**: the appliance sends syslog to this receiver, which **deframes** (RFC5424 + legacy RFC3164,
UDP+TCP), **dispatches** to a **pluggable vendor parser**, **normalizes** into Plume events and
writes them to the **spool** -> `ship.sh` -> central (`/api/ingest`, mTLS + token). **Exactly the same
path as `conntrack.sh`.** The **daemon's data plane is NOT touched**: ONE source is added.

Before this collector, the only external source path was the Defender connector (PULL). There was
**no** way to onboard a FortiGate. That is now the case — and the FortiGate parser is the
**first of a pluggable family**: adding a vendor = implementing `VendorParser` + registering it.

## Source -> category taxonomy (CROSS-VENDOR composition)

- `source = "fortigate"`: identity of the **vendor**.
- `category`: **NEUTRAL semantics** shared by all vendors, so that rules compose:
  `firewall | malware | ids | web | dns | application | vpn | auth | mail | dlp | endpoint | system | utm | network`.
  (FortiGate `type=traffic` -> `firewall`; `type=utm subtype=virus` -> `malware`; `subtype=ips` -> `ids`; ...)
- `fields.log_type` / `fields.subtype`: the **raw** FortiGate `type`/`subtype` (drilldown).
- `fields.action`: normalized action = the daemon's **CIM rollup dimension** (`json_extract(fields,'$.action')`).
- `src_ip`/`dst_ip`/`url`: **promoted to indexed columns** by `ingest_events_batch` (top level of the event).

A rule `search category=malware | stats count` therefore matches FortiGate **and** any future
vendor that maps its threats onto `malware`: **zero Fortinet coupling**. Two shipped overlay rules,
**both OPT-IN (`enabled:false`)** so as NOT to change the detection of a stack without FortiGate:
`config.d/rules/fw-malware-blocked-any-vendor.json` (composes on `category=malware action=blocked` -> the
perimeter block, EXCLUDES the existing mail AV/yara) and `fw-denied-portscan-any-vendor.json` (threshold to
calibrate). Enable them (UI or file) **after** onboarding an appliance.

---

## Deployment A — host-native (systemd), the common case (host / VPS)  [PRIMARY]

Like the other host collectors (audit/falco/conntrack): runs **on the node**, the FortiGate points
at the node's :514, and the `ship.sh` already in place (which already ships conntrack & co) forwards to the
in-cluster daemon. **No pod, no image to build for this case.**

### 1. Install (OPT-IN — golden rule: installed but NOT enabled)
```sh
# build the binary on a Rust machine if the host has no cargo (see collector-mail):
( cd plume/collector-syslog && cargo build --release )
# then, from the plume source, as an agent:
sudo PLUME_WITH_SYSLOG=1 ./bootstrap-agent.sh
```
This installs `/usr/local/lib/plume/collectors/plume-collector-syslog`, the unit
`plume-collector-syslog.service` and a default `/etc/plume/syslog.conf`.

### 2. Config `/etc/plume/syslog.conf`
Every comment on **its own line**: systemd (`EnvironmentFile=`) keeps an end-of-line comment
**in the value** (`PLUME_SYSLOG_ALLOW=   # ex` means `# ex`, which the receiver refuses: it
stops at startup). An **absent** listener takes the receiver's default, `0.0.0.0:514`; set
**empty**, it **cuts** its transport (`env_ecoute`, `collector-syslog/src/main.rs`). The conf installed
by `bootstrap-agent.sh` listens on the loopback only:
```sh
PLUME_SPOOL=/var/lib/plume/spool
# parser: fortigate | auto (per-message sniff) | generic
PLUME_SYSLOG_PARSER=fortigate
PLUME_SYSLOG_SOURCE=fortigate
# loopback by default; 0.0.0.0:514 ONLY after the list AND the firewall (section 3)
PLUME_SYSLOG_UDP=127.0.0.1:514
PLUME_SYSLOG_TCP=127.0.0.1:514
# source-IP allowlist (comma-separated CIDR/IP).
# EMPTY = refuses to start as soon as a listener is off the loopback
PLUME_SYSLOG_ALLOW=
# events per envelope (<= the daemon's PLUME_INGEST_MAX_EVENTS)
PLUME_SYSLOG_BATCH_MAX=500
# spool flush cadence (bounds latency and the number of files)
PLUME_SYSLOG_FLUSH_MS=2000
# default tz if the device does NOT emit a tz field (otherwise UTC)
# PLUME_SYSLOG_TZ=+0100
# hard cap on TCP frame / UDP datagram (anti-DoS)
# PLUME_SYSLOG_MAX_FRAME=65536
# max concurrent TCP connections (global), then PER IP (anti-slowloris)
# PLUME_SYSLOG_MAX_CONNS=128
# PLUME_SYSLOG_MAX_CONNS_PER_IP=16
# TCP idle timeout (s); TCP_MAXLIFE=3600 = max lifetime of a connection
# PLUME_SYSLOG_TCP_IDLE=60
# spool disk budget: beyond it -> shed (backpressure)
# PLUME_SYSLOG_SPOOL_MAX_BYTES=536870912
# memory buffer cap (beyond it -> counted drop: avoids OOM)
# PLUME_SYSLOG_QUEUE_MAX=20000
```
A conf **already in place** is kept as is when `bootstrap-agent.sh` is rerun, which nevertheless NAMES
each key whose value carries a comment, and each listener off the loopback (absent
included) with an empty list: the receiver will refuse to start, and the message says what to set.

### 3. Harden the source (MANDATORY — syslog is NOT authenticated)

`:514` accepts any sender: without restriction, anyone who routes to the node can **inject
fake events** (spoofing a FortiGate). BEFORE enabling, apply **two layers**:

1. **Application allowlist** (`PLUME_SYSLOG_ALLOW` in `/etc/plume/syslog.conf`) = CIDR/IP of your
   appliances. Empty -> the service REFUSES to start if a listener leaves the loopback (code 2,
   the message says what to set); on loopback only, any source on this host is accepted (warning
   at boot). Deliberately accepting any source is written: `PLUME_SYSLOG_ALLOW=0.0.0.0/0,::/0`.
2. **Default-deny host firewall** towards `:514` (the only line of defense if the source IP is SNATed):
   ```sh
   sudo ufw allow from <CIDR-FortiGate> to any port 514
   sudo ufw deny 514                     # everything else is refused
   # (or in nft: a rule `tcp/udp dport 514 ip saddr != <cidr-appareils> drop`)
   ```

Provenance: each event carries `fields.receiver_peer` (the real TRANSPORT IP, unforgeable over TCP) —
useful in forensics even if a sender lies about its `srcip=`.

### 4. Enable
```sh
sudo systemctl enable --now plume-collector-syslog.service
```
> **Bind :514 without root**: the unit carries `AmbientCapabilities=CAP_NET_BIND_SERVICE` (User=soc). The
> **daemon**'s sandbox stays byte-identical — this capability is carried ONLY by this collector.

### 5. FortiGate side (FortiOS CLI example)
```
config log syslogd setting
    set status enable
    set server "<IP-du-node-plume>"
    set port 514
    set mode reliable        # = TCP (recommended: no UDP truncation at the MTU on large logs)
    set format default       # key=value (what this parser expects)
    set facility local7
end
```
UDP works too (`set mode udp`) but can **truncate** long UTM lines > MTU. For a high-volume
feed: **TCP**.

### 6. Verify
```sh
journalctl -u plume-collector-syslog -f          # "parser=fortigate source=fortigate udp=... tcp=..."
ls -l /var/lib/plume/spool/syslog-*.json          # envelopes waiting to be shipped
# on the SOC side: the search bar
search source=fortigate | stats count by category
```

---

## Deployment B — k3s pod (100 % in-cluster customer, no host access)  [OPTIONAL]

**Same binary, different packaging** (see the "one artifact, two packagings" design). This repository does not ship a
ready-made manifest for this case: write it in **your GitOps repository**, with the following shape.

- a **`Deployment`** with 2 containers, **same image**: the `receiver` (this binary) + a `shipper`
  (`curl` sidecar) that POSTs the shared spool (`emptyDir`) to the daemon's Service
  (`<svc>.<ns>.svc:7000/api/ingest`), with the `Host` header expected by `PLUME_HOST` and a **Bearer
  token** mounted from a `Secret`;
- a **`Service`** exposing `514/udp` + `514/tcp` to the sending appliance (type `LoadBalancer` or
  `NodePort` depending on your cluster);
- a **`ConfigMap`** carrying the `PLUME_SYSLOG_*` variables from section 2.

To be applied **deliberately**, during an in-cluster onboarding — not as always-on.

> **Hardening (MANDATORY)**: this manifest must NOT expose `:514` to the Internet. Plan for the
> **three** layers:
> 1. `loadBalancerSourceRanges` (or the equivalent of your LB / cloud firewall) on the `Service`;
> 2. an ingress `NetworkPolicy` in **default-deny** (`ingress: []`) that you open to the sole CIDR of
>    your appliances. **Check that your CNI actually enforces NetworkPolicy** — some default CNIs
>    (including k3s's flannel) do not enforce them, and the rule would then be decorative;
> 3. `PLUME_SYSLOG_ALLOW` (application allowlist) — the only portable layer if your LB SNATs the source IP.
>
> Also bound the spool on the pod side (`emptyDir sizeLimit` + `ephemeral-storage` + the application shed
> `PLUME_SYSLOG_SPOOL_MAX_BYTES`): an eviction then stays LOCAL to the pod, without disk pressure on the node.

---

## Container (Docker, and the `receiver` of deployment B) — the image starts REFUSED

In a container, the loopback is the CONTAINER's: no sender reaches it, so the listener is
necessarily off the loopback (`0.0.0.0:514`, the default of the `runtime` image). With
`PLUME_SYSLOG_ALLOW` empty, the receiver **refuses to start** (code 2) and its message says what to set.
This is intended: the image opens nothing silently, and no variable lifts this gate without a WRITTEN list.
Step by step:

1. **List the senders AS THE CONTAINER SEES THEM.** In bridge networking, Docker keeps the real source IP
   of a remote sender (DNAT). A sender on the HOST itself that targets a port published on
   `127.0.0.1` arrives through `docker-proxy`, hence from the bridge gateway (`docker network inspect
   bridge`, `Gateway` field, often `172.17.0.1`). In k3s, a `Service` with
   `externalTrafficPolicy: Cluster` replaces the source IP with that of a node; `Local` keeps it.
2. **Set the list** in the container's environment (`-e`, or the `ConfigMap` of deployment B):
   `PLUME_SYSLOG_ALLOW=<CIDR ou IP, separes par des virgules>`. Accepting any source remains possible,
   WRITTEN (`0.0.0.0/0,::/0`), and only behind the filtering of step 3.
3. **Restrict publication on the host side.** Only the host relays (local rsyslog -> container):
   `-p 127.0.0.1:514:514/udp -p 127.0.0.1:514:514/tcp`. Remote appliances: publish on the IP of
   the interface that receives them, AND set up the firewall from section 3 of deployment A — in the
   `DOCKER-USER` chain, because Docker's publication rules come before `ufw`.
4. **Verify**: `docker logs <conteneur>` shows `collector-syslog: parser=... allow=N cidr`. Without a list,
   it shows `ARRET. PLUME_SYSLOG_ALLOW est vide ...` and the container exits with code 2.

```sh
# remote appliances (here a FortiGate 203.0.113.10), published on the host's 198.51.100.5 interface
docker run -d --name plume-syslog -e PLUME_SYSLOG_ALLOW=203.0.113.10/32 \
  -p 198.51.100.5:514:514/udp -p 198.51.100.5:514:514/tcp \
  -v plume-spool:/var/lib/plume/spool <image-runtime>
# host relay only: the source seen is the bridge gateway
docker run -d --name plume-syslog -e PLUME_SYSLOG_ALLOW=172.17.0.1/32 \
  -p 127.0.0.1:514:514/udp -p 127.0.0.1:514:514/tcp \
  -v plume-spool:/var/lib/plume/spool <image-runtime>
```

---

## Accepted syslog formats

| Transport | Framing | Note |
|:--|:--|:--|
| UDP :514 | 1 datagram = 1 message | truncation possible on the sender side (MTU) |
| TCP :514 | **RFC6587 octet-counting** (`MSGLEN SP MSG`) | auto-detected |
| TCP :514 | **non-transparent** (LF, CRLF tolerated) | auto-detected |

Header: `<PRI>` -> facility/severity (provenance); **RFC5424** (`1 TIMESTAMP HOST APP PROCID MSGID SD MSG`,
SD folded into `fields.sd_*`); **RFC3164** (`Mmm dd hh:mm:ss HOST MSG`). FortiGate emits `<PRI>date=... time=...`
directly (neither 5424 nor 3164) -> everything goes **intact** to the vendor parser. The parser **always prefers** the
vendor fields (`eventtime`, `level`) over the syslog header (lossy).

## Robustness

The FortiGate parser **never panics**: missing/extra fields and quotes tolerated; an unreadable
line -> **fallback event** (`source=fortigate`, `category=network`, `fields.parse_status=unparsed`,
message = truncated raw) — never a silent drop. Syslog deframing is **UTF-8-safe** (the bytes
are decoded with replacement: an invalid sequence, including a character cut by the `MAX_FRAME` bound,
becomes U+FFFD; the header and the truncated message are never cut in the middle of a character) and each dispatch is isolated under `catch_unwind`: **a single
malformed datagram cannot kill the receiving thread**. Hard bounds: `MAX_FRAME` (anti-DoS),
`MAX_FIELDS=64` (cardinality/RAM), `MAX_CONNS`/`MAX_CONNS_PER_IP` + idle/max-lifetime timeout
(anti-slowloris), bounded memory buffer (`QUEUE_MAX` -> no OOM), bounded spool (`SPOOL_MAX_BYTES` ->
**shed** rather than disk pressure), batch `<= PLUME_INGEST_MAX_EVENTS`. Every loss is **counted and
logged** (never silent). Provenance: `fields.receiver_peer` (real transport IP),
`fields.observer` (identity of the sending appliance: `devname`/`devid`/syslog hostname — for
`stats ... by observer` when several appliances point at the same collector).

## Adding a vendor (extensibility)

1. `plume/collector-syslog/src/<vendeur>.rs`: `struct X; impl VendorParser for X { ... }`.
2. `parser.rs`: wire it into `select()` + `default_source()`.
3. `PLUME_SYSLOG_PARSER=<vendeur>` (or `auto` + a signature in `Auto::sniff_*`).

The contract: `source` = vendor, `category` = neutral semantics, `src_ip`/`dst_ip`/`url` top-level,
`action` in `fields.action`, **never a panic**. That is all — the daemon ingests without change.
