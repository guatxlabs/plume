# eBPF (Falco / Tetragon) + Sigma (P5)

[Français](EBPF-SIGMA.md) | [English](EBPF-SIGMA.en.md)

## Falco — eBPF runtime detection (exec, files, network, containers)
1. Install Falco (https://falco.org) with the modern driver: `falco --modern-bpf`.
2. Enable JSON file output in `/etc/falco/falco.yaml`:
   ```yaml
   json_output: true
   file_output:
     enabled: true
     filename: /var/log/falco/events.txt
   ```
3. The **plume-falco** sensor (every 2 min) reads this file (incremental offset) and pushes the
   detections → events `source=falco` (search: `source:falco`, or a detection rule on it).
   Path override: `PLUME_FALCO_LOG`.

> Falco uses <5% CPU in eBPF and brings real-time exec/privesc/network — an ideal complement to auditd.

## Tetragon — k8s alternative (+ enforcement)
Tetragon emits its events as JSON (`tetra getevents -o json`). A collector of the same kind (read the stream →
`/api/ingest`) plugs it into the SOC; relevant in the k3s cluster (DaemonSet).

## Sigma — community rules
**SigmaHQ** rules translate into `GXQL` queries. The **Sigma → GXQL** translator (YAML parser →
`search … | stats … | where …` conditions) is the next building block. In the meantime, recreate the key
detections by hand in **⚙️ Rules** (the engine is already there). **MITRE ATT&CK** mapping = tag in the name/reason.
