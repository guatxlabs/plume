# eBPF (Falco / Tetragon) + Sigma (P5)

## Falco — détection runtime eBPF (exec, fichiers, réseau, conteneurs)
1. Installer Falco (https://falco.org) avec le driver moderne : `falco --modern-bpf`.
2. Activer la sortie JSON fichier dans `/etc/falco/falco.yaml` :
   ```yaml
   json_output: true
   file_output:
     enabled: true
     filename: /var/log/falco/events.txt
   ```
3. Le capteur **plume-falco** (toutes les 2 min) lit ce fichier (offset incrémental) et pousse les
   détections → events `source=falco` (recherche : `source:falco`, ou règle de détection dessus).
   Override du chemin : `PLUME_FALCO_LOG`.

> Falco fait <5% CPU en eBPF et apporte exec/privesc/réseau temps-réel — complément idéal d'auditd.

## Tetragon — alternative k8s (+ enforcement)
Tetragon émet ses events en JSON (`tetra getevents -o json`). Un collecteur du même type (lire le flux →
`/api/ingest`) le branche au SOC ; pertinent dans le cluster k3s (DaemonSet).

## Sigma — règles communautaires
Les règles **SigmaHQ** se traduisent en requêtes `soql`. Le traducteur **Sigma → soql** (parser YAML →
conditions `search … | stats … | where …`) est la prochaine brique. En attendant, recrée les détections
clés à la main dans **⚙️ Règles** (le moteur est déjà là). Mapping **MITRE ATT&CK** = tag dans le nom/raison.
