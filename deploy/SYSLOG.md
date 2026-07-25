# collector-syslog — recepteur syslog + parsers vendeur (1er = FortiGate)

Le SOC traite un appareil reseau (**FortiGate**, switch, routeur, tout equipement syslog) comme **un
collecteur de plus** : l'appareil emet du syslog vers ce recepteur, qui **decadre** (RFC5424 + RFC3164
legacy, UDP+TCP), **dispatche** vers un **parser vendeur pluggable**, **normalise** en events Plume et
les ecrit dans le **spool** -> `ship.sh` -> central (`/api/ingest`, mTLS + token). **Exactement le meme
chemin que `conntrack.sh`.** Le **data-plane du daemon n'est PAS touche** : on ajoute UNE source.

Avant ce collecteur, la seule voie source externe etait le connecteur Defender (PULL). Il n'existait
**aucun** moyen d'onboarder un FortiGate. C'est desormais le cas — et le parser FortiGate est le
**premier d'une famille pluggable** : ajouter un vendeur = implementer `VendorParser` + l'enregistrer.

## Taxonomie source -> category (composition INTER-VENDEUR)

- `source = "fortigate"` : identite du **vendeur**.
- `category` : **semantique NEUTRE** partagee par tous les vendeurs, pour que les regles composent :
  `firewall | malware | ids | web | dns | application | vpn | auth | mail | dlp | endpoint | system | utm | network`.
  (FortiGate `type=traffic` -> `firewall` ; `type=utm subtype=virus` -> `malware` ; `subtype=ips` -> `ids` ; ...)
- `fields.log_type` / `fields.subtype` : le `type`/`subtype` FortiGate **bruts** (drilldown).
- `fields.action` : action normalisee = **dimension de rollup CIM** du daemon (`json_extract(fields,'$.action')`).
- `src_ip`/`dst_ip`/`url` : **promus en colonnes** indexees par `ingest_events_batch` (top-level de l'event).

Une regle `search category=malware | stats count` matche donc FortiGate **et** n'importe quel futur
vendeur qui mappe ses menaces sur `malware` : **zero couplage Fortinet**. Deux regles overlay livrees,
**toutes deux OPT-IN (`enabled:false`)** pour ne PAS changer la detection d'une stack sans FortiGate :
`config.d/rules/fw-malware-blocked-any-vendor.json` (compose sur `category=malware action=blocked` -> le
blocage perimetre, EXCLUT l'AV mail/yara existant) et `fw-denied-portscan-any-vendor.json` (seuil a
calibrer). Les activer (UI ou fichier) **apres** onboarding d'un appareil.

---

## Deploiement A — host-natif (systemd), le cas courant (hote / VPS)  [PRIMAIRE]

Comme les autres collecteurs hote (audit/falco/conntrack) : tourne **sur le node**, le FortiGate pointe
sur le :514 du node, et le `ship.sh` deja en place (qui expedie deja conntrack & co) forwarde au daemon
in-cluster. **Aucun pod, aucune image a builder pour ce cas.**

### 1. Installer (OPT-IN — regle d'or : installe mais NON active)
```sh
# build du binaire sur une machine Rust si l'hote n'a pas cargo (cf. collector-mail) :
( cd plume/collector-syslog && cargo build --release )
# puis, depuis la source plume, en tant qu'agent :
sudo PLUME_WITH_SYSLOG=1 ./bootstrap-agent.sh
```
Cela pose `/usr/local/lib/plume/collectors/plume-collector-syslog`, l'unit
`plume-collector-syslog.service` et un `/etc/plume/syslog.conf` par defaut.

### 2. Config `/etc/plume/syslog.conf`
```sh
PLUME_SPOOL=/var/lib/plume/spool
PLUME_SYSLOG_PARSER=fortigate     # fortigate | auto (sniff par message) | generic
PLUME_SYSLOG_SOURCE=fortigate
PLUME_SYSLOG_UDP=0.0.0.0:514      # vider ("") = desactiver l'UDP
PLUME_SYSLOG_TCP=0.0.0.0:514      # vider ("") = desactiver le TCP
PLUME_SYSLOG_ALLOW=              # allowlist source-IP (CIDR/IP virgule). VIDE = tout accepte (WARN au boot)
PLUME_SYSLOG_BATCH_MAX=500        # events/enveloppe (<= PLUME_INGEST_MAX_EVENTS du daemon)
PLUME_SYSLOG_FLUSH_MS=2000        # cadence de flush spool (borne la latence + le nb de fichiers)
# PLUME_SYSLOG_TZ=+0100           # tz par defaut si le device n'emet PAS de champ tz (sinon UTC)
# PLUME_SYSLOG_MAX_FRAME=65536    # cap dur trame TCP / datagramme UDP (anti-DoS)
# PLUME_SYSLOG_MAX_CONNS=128      # connexions TCP concurrentes max (global)
# PLUME_SYSLOG_MAX_CONNS_PER_IP=16  # connexions TCP concurrentes max PAR IP (anti-slowloris)
# PLUME_SYSLOG_TCP_IDLE=60        # timeout inactivite TCP (s) ; TCP_MAXLIFE=3600 = vie max d'une connexion
# PLUME_SYSLOG_SPOOL_MAX_BYTES=536870912  # budget disque du spool : au-dela -> shed (backpressure)
# PLUME_SYSLOG_QUEUE_MAX=20000    # cap du tampon memoire (au-dela -> drop compte : evite l'OOM)
```

### 3. Durcir la source (OBLIGATOIRE — syslog n'est PAS authentifie)

`:514` accepte n'importe quel emetteur : sans restriction, quiconque route vers le node peut **injecter
de faux events** (spoof d'un FortiGate). AVANT d'activer, applique **deux couches** :

1. **Allowlist applicative** (`PLUME_SYSLOG_ALLOW` dans `/etc/plume/syslog.conf`) = CIDR/IP de tes
   appareils. Vide -> tout accepte (le service LOG un avertissement au boot).
2. **Pare-feu hote default-deny** vers `:514` (le seul rempart si l'IP source est SNAT) :
   ```sh
   sudo ufw allow from <CIDR-FortiGate> to any port 514
   sudo ufw deny 514                     # tout le reste est refuse
   # (ou en nft : une regle `tcp/udp dport 514 ip saddr != <cidr-appareils> drop`)
   ```

Provenance : chaque event porte `fields.receiver_peer` (l'IP TRANSPORT reelle, non falsifiable en TCP) —
utile en forensic meme si un emetteur ment sur son `srcip=`.

### 4. Activer
```sh
sudo systemctl enable --now plume-collector-syslog.service
```
> **Bind :514 sans root** : l'unit porte `AmbientCapabilities=CAP_NET_BIND_SERVICE` (User=soc). Le
> sandbox du **daemon** reste byte-identique — cette capability est portee UNIQUEMENT par ce collecteur.

### 5. Cote FortiGate (exemple CLI FortiOS)
```
config log syslogd setting
    set status enable
    set server "<IP-du-node-plume>"
    set port 514
    set mode reliable        # = TCP (recommande : pas de troncature UDP au MTU sur les gros logs)
    set format default       # key=value (ce que ce parser attend)
    set facility local7
end
```
UDP marche aussi (`set mode udp`) mais peut **tronquer** les lignes UTM longues > MTU. Pour un feed
volumineux : **TCP**.

### 6. Verifier
```sh
journalctl -u plume-collector-syslog -f          # "parser=fortigate source=fortigate udp=... tcp=..."
ls -l /var/lib/plume/spool/syslog-*.json          # enveloppes en attente d'expedition
# cote SOC : la barre de recherche
search source=fortigate | stats count by category
```

---

## Deploiement B — pod k3s (client 100 % in-cluster, sans acces hote)  [OPTIONNEL]

**Meme binaire, autre packaging** (cf. design "one artifact, two packagings"). Ce depot ne livre pas de
manifeste tout fait pour ce cas : ecris-le dans **ton depot GitOps**, avec la forme suivante.

- un **`Deployment`** a 2 conteneurs, **meme image** : le `receiver` (ce binaire) + un `shipper`
  (sidecar `curl`) qui POST le spool partage (`emptyDir`) vers le Service du daemon
  (`<svc>.<ns>.svc:7000/api/ingest`), avec l'en-tete `Host` attendu par `PLUME_HOST` et un **Bearer
  token** monte depuis un `Secret` ;
- un **`Service`** exposant `514/udp` + `514/tcp` vers l'appareil emetteur (type `LoadBalancer` ou
  `NodePort` selon ton cluster) ;
- une **`ConfigMap`** portant les variables `PLUME_SYSLOG_*` de la section 2.

A appliquer **deliberement**, lors d'un onboarding in-cluster — pas en always-on.

> **Durcissement (OBLIGATOIRE)** : ce manifeste ne doit PAS exposer `:514` a l'Internet. Prevois les
> **trois** couches :
> 1. `loadBalancerSourceRanges` (ou l'equivalent de ton LB / cloud firewall) sur le `Service` ;
> 2. une `NetworkPolicy` d'ingress en **default-deny** (`ingress: []`) que tu ouvres au seul CIDR de
>    tes appareils. **Verifie que ton CNI applique bien les NetworkPolicy** — certains CNI par defaut
>    (dont le flannel de k3s) ne les appliquent pas, la regle serait alors decorative ;
> 3. `PLUME_SYSLOG_ALLOW` (allowlist applicative) — la seule couche portable si ton LB SNAT l'IP source.
>
> Borne aussi le spool cote pod (`emptyDir sizeLimit` + `ephemeral-storage` + le shed applicatif
> `PLUME_SYSLOG_SPOOL_MAX_BYTES`) : une eviction reste alors LOCALE au pod, sans disk-pressure du node.

---

## Formats syslog acceptes

| Transport | Cadrage | Note |
|:--|:--|:--|
| UDP :514 | 1 datagramme = 1 message | truncation possible cote emetteur (MTU) |
| TCP :514 | **RFC6587 octet-counting** (`MSGLEN SP MSG`) | auto-detecte |
| TCP :514 | **non-transparent** (LF, tolere CRLF) | auto-detecte |

En-tete : `<PRI>` -> facility/severity (provenance) ; **RFC5424** (`1 TIMESTAMP HOST APP PROCID MSGID SD MSG`,
SD replie en `fields.sd_*`) ; **RFC3164** (`Mmm dd hh:mm:ss HOST MSG`). FortiGate emet `<PRI>date=... time=...`
directement (ni 5424 ni 3164) -> tout part **intact** au parser vendeur. Le parser **prefere toujours** les
champs vendeur (`eventtime`, `level`) a l'en-tete syslog (lossy).

## Robustesse

Le parser FortiGate **ne panique jamais** : champs manquants/en trop/quotes toleres ; une ligne
illisible -> **event de repli** (`source=fortigate`, `category=network`, `fields.parse_status=unparsed`,
message = brut tronque) — jamais un drop silencieux. Le decadrage syslog est **UTF-8-safe** (pas de coupe
a l'octet sur une frontiere de caractere) et chaque dispatch est isole sous `catch_unwind` : **un seul
datagramme malforme ne peut pas tuer le thread de reception**. Bornes dures : `MAX_FRAME` (anti-DoS),
`MAX_FIELDS=64` (cardinalite/RAM), `MAX_CONNS`/`MAX_CONNS_PER_IP` + timeout inactivite/vie-max
(anti-slowloris), tampon memoire borne (`QUEUE_MAX` -> pas d'OOM), spool borne (`SPOOL_MAX_BYTES` ->
**shed** plutot que disk-pressure), batch `<= PLUME_INGEST_MAX_EVENTS`. Toute perte est **comptee et
journalisee** (jamais silencieuse). Provenance : `fields.receiver_peer` (IP transport reelle),
`fields.observer` (identite de l'appareil emetteur : `devname`/`devid`/hostname syslog — pour
`stats ... by observer` quand plusieurs appareils pointent le meme collecteur).

## Ajouter un vendeur (extensibilite)

1. `plume/collector-syslog/src/<vendeur>.rs` : `struct X; impl VendorParser for X { ... }`.
2. `parser.rs` : brancher dans `select()` + `default_source()`.
3. `PLUME_SYSLOG_PARSER=<vendeur>` (ou `auto` + une signature dans `Auto::sniff_*`).

Le contrat : `source` = vendeur, `category` = semantique neutre, `src_ip`/`dst_ip`/`url` top-level,
`action` dans `fields.action`, **jamais de panic**. C'est tout — le daemon ingere sans changement.
