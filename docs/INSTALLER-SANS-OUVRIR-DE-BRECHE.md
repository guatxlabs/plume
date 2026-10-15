# Installer plume sans ouvrir de brèche — pas à pas, dans les trois modes

Cette page s'adresse à la personne qui installe plume chez elle, sur une machine qu'elle administre, et
qui ne veut **rien exposer de plus que ce qu'elle a choisi**. Elle suit l'ordre des gestes : ce qui est
ouvert par défaut, l'installation de chaque mode, où vivent les secrets, ce que chaque capteur fait
entrer dans le SIEM, le transport, les risques que le produit assume, et la preuve que tout remonte.

Elle ne répète pas les pages qui existent : le même geste dans les trois modes est dans
[`TROIS-MODES.md`](TROIS-MODES.md), le contrat de fil des agents dans
[`AGENTS-PROTOCOLE.md`](AGENTS-PROTOCOLE.md), le chiffrement au repos dans
[`CHIFFREMENT-COMPRESSION.md`](CHIFFREMENT-COMPRESSION.md), le récepteur syslog dans
[`../deploy/SYSLOG.md`](../deploy/SYSLOG.md), le capteur de boîtes aux lettres dans
[`../deploy/MAIL.md`](../deploy/MAIL.md), le langage de recherche dans [`GXQL.md`](GXQL.md).

> **Ce qui n'a pas été exécuté.** Les commandes de cette page sont reprises des installateurs et des
> manifestes livrés (`bootstrap.sh`, `bootstrap-agent.sh`, `docker-compose.yml`, `deploy/k3s.yaml`) et
> chaque comportement annoncé a été relu dans le code qui le tient. Aucune séquence d'installation n'a
> été jouée sur une machine pour écrire cette page. Un geste qui échoue chez vous est un défaut à
> signaler.

Les noms d'hôte des exemples sont `soc.example.org` (le central) et `agent.example.org` (un agent).

---

## 1. Ce qui est ouvert par défaut, mode par mode

| | hôte natif (`bootstrap.sh`) | Docker (`docker-compose.yml`) | k3s (`deploy/k3s.yaml`) |
|---|---|---|---|
| écoute du démon | `127.0.0.1:7000` et `[::1]:7000`, HTTP | `0.0.0.0:7000` **dans** le conteneur, publié sur `127.0.0.1:7000` de l'hôte seulement | `0.0.0.0:7000` dans le pod, joignable par l'`Ingress` et le namespace `soc` |
| TLS | aucun : à poser (§2.1) | aucun : à poser (§2.3) | **actif** sur l'`Ingress`, entrée `websecure` seule, certificat du `Secret` `soc-tls` |
| compte admin | hash posé, sinon **mode SETUP** (jeton d'installation à usage unique) | idem | hash du `Secret` `soc-auth` |
| base au repos | **neuve = chiffrée** (clé engendrée en `0600` à côté de la base), si le démon l'ouvre le premier (§1.1) | idem, clé sur le volume `soc-data` | idem, clé sur le PVC |
| sortie réseau du démon | celle de l'hôte | celle du pont Docker | **refusée** sauf DNS du cluster (`NetworkPolicy`), si le CNI l'applique |
| gestes sensibles (créer un compte, frapper un jeton…) | **refusés** tant que le secret des gestes n'est pas posé | idem | idem |

Une base **déjà en service et restée en clair** n'est jamais convertie par un démarrage : poser une clé
dessus fait **refuser** le démarrage, avec le nom du geste explicite (`plume-daemon chiffrer-au-repos`).
Le détail, et la façon de mettre la clé engendrée à l'abri, sont dans
[`CHIFFREMENT-COMPRESSION.md` §1](CHIFFREMENT-COMPRESSION.md#1-la-base-au-repos--neuve--chiffrée--existante--jamais-touchée-par-un-démarrage).
**Perdre la clé, c'est perdre la base et toutes ses sauvegardes** : copiez-la hors de la machine dès le
premier démarrage, puis posez `PLUME_DB_KEY_ESCROWED=1`.

### 1.1 Démarrer le démon une fois avant toute sous-commande qui écrit dans la base

« Neuve = chiffrée » n'est vrai que si le **démon** est le premier à ouvrir la base : la clé n'est
engendrée qu'à son démarrage, et seulement sur une base qui n'existe pas encore. Les sous-commandes
qui ouvrent la base pour y écrire — `token`, `sigma-import` (sans `--dry-run`), `retention`,
`fts-compact`, `purge`, `restore-drill record`, et `backup` une fois sa sauvegarde écrite — **créent**
la base si elle manque,
avec la seule clé déjà posée (`PLUME_DB_KEY`, `PLUME_DB_KEY_FILE` ou un fichier de clé déjà engendré).
Sans aucune, la base naît **en clair**. Le démarrage suivant la trouve existante, sans clé, et n'y
touche pas : elle reste en clair, et le démarrage ne le refuse pas, jusqu'au geste
`plume-daemon chiffrer-au-repos`. Que la sous-commande refuse elle-même une base absente est une clé
ouverte côté démon (`P10.33-g`) : d'ici là, l'ordre ci-dessous est la seule protection. Deux
sous-commandes de lecture ne font pas naître de base : `verify` ouvre en lecture seule et ne crée rien ;
`ledger-export` crée au plus un fichier vide, que le démarrage suivant traite encore comme une base
neuve.

L'ordre sûr, dans les trois modes : installer, **démarrer le démon une fois** — `bootstrap.sh` le fait
en fin d'installation, `docker compose up -d`, `kubectl apply` —, vérifier que la clé existe
(`/var/lib/plume/db/soc.db.key` sur un hôte, `/data/plume-at-rest.key` en conteneur), et seulement
ensuite lancer une sous-commande. Les formes `docker compose exec soc …` et `kubectl -n soc exec
deploy/soc -- …` passent par le conteneur où le démon tourne déjà : elles respectent cet ordre par
construction. `docker compose run --rm soc <sous-commande>` lance un conteneur **sans** démon : en
premier geste, il fait naître la base en clair sur le volume.

---

## 2. Installer, pas à pas

### 2.1 Hôte natif — le central (`bootstrap.sh`)

**Prérequis** : une distribution systemd, un accès root, un Rust stable (`cargo`) et un accès réseau au
premier build (aucun binaire n'est publié). `auditd` est facultatif mais sans lui le capteur d'exécution
ne collecte rien (et le dit).

1. **Compiler.** `cd daemon && cargo build --release && cd ..` — ajoutez `--features cold_tier,ldap`
   pour le tier froid et l'annuaire (les deux formes sont légitimes, l'installateur dit laquelle il a posée).
2. **Installer SANS secret dans la ligne de commande.** `sudo bash bootstrap.sh`. Sans hash, le fichier
   `/etc/plume/soc.conf` (`0640 root:soc`) est écrit avec un hash vide, et le démon démarre en **mode
   SETUP**. N'écrivez pas `sudo env PLUME_PASS_HASH=… bash bootstrap.sh`, la forme que l'en-tête du
   script montre encore : `sudo` journalise sa ligne complète, et le capteur `journal`, que ce même
   script active, la fait entrer dans le SIEM, où tout lecteur verrait le hash — de quoi tenter le mot de
   passe hors ligne.
3. **Poser le hash par un tube.** `hashpw` lit l'entrée standard quand l'argument manque :
   ```sh
   read -rs PW && printf '%s' "$PW" | ./daemon/target/release/plume-daemon hashpw \
     | sed 's/^/PLUME_PASS_HASH=/' | sudo tee -a /etc/plume/soc.conf >/dev/null; unset PW
   sudo systemctl restart plume-daemon
   ```
   La ligne ajoutée gagne sur la ligne vide (le lecteur de configuration garde la **dernière**
   occurrence d'une clé). Un `$` du hash n'y est pas interprété : ce fichier n'est pas lu par un shell.
   Sans ce geste, l'assistant web fait la même chose : le jeton d'installation est dans
   `sudo journalctl -u plume-daemon` et dans `/var/lib/plume/db/setup-token.txt` (`0600`) ; quiconque
   joint la console **et** détient ce jeton crée le compte admin — ne laissez pas le mode SETUP ouvert.
4. **Poser le secret des gestes** (sinon, frapper un jeton d'agent par la console est refusé) :
   [`TROIS-MODES.md` §3.11](TROIS-MODES.md#311-poser-le-secret-des-gestes).
5. **Choisir l'exposition.** Par défaut rien ne sort de la boucle locale. Pour le réseau, deux voies :
   - **un mandataire TLS devant** (Caddy, nginx, Traefik — exemples dans
     [`../deploy/CONFIDENTIALITE.md`](../deploy/CONFIDENTIALITE.md)), le démon restant sur `127.0.0.1` ;
     posez `PLUME_HOST` sur le nom servi, `PLUME_TRUSTED_PROXIES` sur l'adresse exacte du mandataire, et
     `PLUME_TLS_TERMINATED_UPSTREAM=1` dans `/etc/plume/soc.conf` si le mandataire ne sert ce nom qu'en
     HTTPS (§6.2) ;
   - **le TLS natif** : `PLUME_TLS_CERT` et `PLUME_TLS_KEY` (chemins PEM lisibles par l'utilisateur
     `soc`), `PLUME_ADDR` sur l'interface voulue, `PLUME_HOST` sur le nom du certificat. L'unité du démon
     n'a **aucune capacité** : choisissez un port au-dessus de 1024. Un certificat illisible **arrête** le
     démon au lieu de le faire retomber en HTTP. Avec ce TLS actif, le démon pose HSTS et l'attribut
     `Secure` de ses cookies.
6. **Prouver** :
   ```sh
   systemctl is-active plume-daemon                 # active
   ss -ltn | grep ':7000'                           # 127.0.0.1 et [::1] seulement, tant que rien n'est ouvert
   curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:7000/readyz   # 200
   curl -sS -u admin http://127.0.0.1:7000/api/me   # curl DEMANDE le mot de passe : rien dans l'historique
   ```
   La dernière réponse doit porter `"role":"admin"`. Avec le TLS natif, la même chose en
   `https://soc.example.org:<port>/readyz`, et `curl -sv` doit montrer votre certificat.

### 2.2 Hôte natif — un agent (`bootstrap-agent.sh`)

**Prérequis** : root, systemd, `curl`. Le central doit être joignable en `https://` (voir §5).

1. **Sur le central, frapper un jeton lié à l'hôte**, après le premier démarrage du démon (§2.1) :
   ```sh
   sudo env PLUME_CONFIG=/etc/plume/soc.conf /usr/local/bin/plume-daemon token agent-web agent.example.org
   ```
   Il s'affiche **une fois** ; seul son SHA-256 est gardé en base. `PLUME_CONFIG` n'est posé que par
   l'unité `plume-daemon.service`, et `sudo` ne le transmet pas. Sans lui, la sous-commande lit
   `/etc/plume/plume.conf` et écrit dans `/var/lib/plume/db/plume.db`, pas dans la `soc.db` du démon :
   elle affiche un jeton et rend 0, puis le central refuse l'agent. L'ordre compte aussi : sur une base
   absente, la sous-commande crée la base sans engendrer de clé, donc en clair (§1.1).
2. **Sur l'agent, écrire la configuration par l'entrée standard**, jamais par argument :
   ```sh
   umask 077
   printf 'PLUME_CENTRAL=%s\nPLUME_TOKEN=%s\n' 'https://soc.example.org' '<jeton>' \
     | sudo tee /etc/plume/plume.conf >/dev/null
   sudo chmod 0600 /etc/plume/plume.conf
   sudo bash bootstrap-agent.sh       # conf présente -> conservée, resserrée en 0600 root:root
   ```
   Pour installer des capteurs de plus, la conf restant en place :
   `sudo env PLUME_EXTRA_COLLECTORS="journal auditd" bash bootstrap-agent.sh` — aucune valeur secrète
   dans la ligne. L'installateur **installe sans activer**, sauf `resources`, `integrity` et `ship`.
3. **Prouver** : `sudo systemctl start plume-ship.service && journalctl -u plume-ship -n 20` ne doit
   porter ni `REFUS` ni code HTTP d'erreur ; sur le central, `search host=agent.example.org
   source=integrity | stats count` rend un compte non nul une fois le premier passage du FIM expédié.

### 2.3 Docker (`docker-compose.yml`)

**Prérequis** : Docker avec BuildKit et Compose ; aucune chaîne Rust sur l'hôte.

1. **Construire d'abord**, puis poser le hash : la recette, ses apostrophes et son filtre sont dans le
   [`README`](../README.md#a-docker-le-plus-simple). Si `docker` s'appelle par `sudo`, la ligne `hashpw
   '<mot de passe>'` part au journal `sudo` comme au §2.1 : lancez `docker` sans `sudo`, ou passez le mot
   de passe par l'entrée standard (`hashpw` sans argument la lit ; ce tube à travers `docker compose run`
   n'a pas été joué ici).
2. **Démarrer** : `docker compose up -d` — avant toute sous-commande (§1.1). Le port n'est publié que
   sur `127.0.0.1:7000` de l'hôte, en HTTP.
3. **Choisir l'exposition.** Dans les deux voies, posez `PLUME_HOST` dans `.env` sur le nom servi
   (`PLUME_HOST=soc.example.org`) : le défaut est `soc.localhost`, et une requête qui arrive sous un autre
   nom que ceux de `PLUME_HOST` ou que la boucle locale reçoit `421`.
   - **un mandataire TLS devant**, sur l'hôte : la ligne `ports:` reste `127.0.0.1:7000:7000`, le
     mandataire vise `http://127.0.0.1:7000`. `PLUME_TRUSTED_PROXIES` n'est pas énumérée par le service :
     le démon garde son défaut, qui fait confiance aux pairs privés et de boucle locale.
     `PLUME_TLS_TERMINATED_UPSTREAM`, elle, l'est : posez-la à `1` dans `.env` si le mandataire ne sert
     ce nom qu'en HTTPS (§6.2) ;
   - **le TLS natif** : `PLUME_TLS_CERT` et `PLUME_TLS_KEY` sont **énumérées** dans le bloc
     `environment:` (sans quoi `.env` ne servirait à rien) ; décommentez le montage
     `./tls:/etc/plume/tls:ro` et posez des chemins **du conteneur**, la clé lisible par l'utilisateur
     `soc` de l'image (uid `10001`). Le démon sert alors **HTTPS seul** sur son port — mais tant que la
     ligne `ports:` vaut `127.0.0.1:7000:7000`, il ne l'offre qu'à l'hôte lui-même. Pour l'exposer,
     publiez le port sur l'interface voulue, par exemple `"192.0.2.10:7000:7000"`, et rien de plus large
     que ce dont vous avez besoin.
4. **Mettre la clé engendrée à l'abri** : `docker compose exec soc cat /data/plume-at-rest.key`, rangée
   hors de la machine, puis `PLUME_DB_KEY_ESCROWED=1` dans `.env`.
5. **Prouver** : `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:7000/readyz` (200),
   `ss -ltn | grep ':7000'` (`127.0.0.1` seulement, tant que la ligne `ports:` n'a pas changé), et
   `docker compose exec soc cat /sys/fs/cgroup/memory.swap.max` (`0`, la borne d'échange tient). Avec le
   TLS natif, la première commande devient `curl -sS --resolve soc.example.org:7000:127.0.0.1
   https://soc.example.org:7000/readyz`, et `curl -sv` doit montrer votre certificat.

Le central en conteneur **n'est pas son propre agent** : aucun capteur shell n'est dans l'image. Les
capteurs tournent sur l'hôte Docker, installés par `bootstrap-agent.sh`, et poussent vers
`http://127.0.0.1:7000` — le clair est admis vers la boucle locale, et vers elle seule (§5).

### 2.4 k3s (`deploy/k3s.yaml`)

**Prérequis** : un cluster k3s (Traefik est le contrôleur d'`Ingress` livré), Docker pour construire
l'image, `kubectl`.

1. **Construire et importer l'image** : `docker build -t soc:latest . && docker save soc:latest | sudo k3s
   ctr images import -`.
2. **Remplir une copie locale du manifeste** (non versionnée) : le hash dans le `Secret` `soc-auth`
   (`hashpw` lit l'entrée standard, comme au §2.1), et `soc.tondomaine.tld` remplacé **aux deux
   endroits** — `PLUME_HOST` et l'`Ingress` ; un écart rend `421`. Un hash laissé à
   `REMPLACER_PAR_LE_HASH` n'arme **pas** le mode SETUP (il n'exige qu'une valeur vide) : personne
   n'entre, sans message.
3. **Poser le certificat** avant d'appliquer : `kubectl -n soc create secret tls soc-tls --cert=<crt>
   --key=<key>`, ou un `Certificate` cert-manager dont `secretName` vaut `soc-tls`. Tant qu'il manque,
   Traefik présente son certificat auto-signé : le navigateur avertit, rien ne passe en clair. Un autre
   contrôleur d'`Ingress` ignore les annotations Traefik : sa redirection HTTP vers HTTPS est alors à
   poser, et `kube-system` est à remplacer par son namespace dans la `NetworkPolicy`.
4. **Appliquer** : `kubectl apply -f <copie>.yaml`. Le pod tourne non-root (uid `10001`), racine en
   lecture seule, sans capacité, profil seccomp `RuntimeDefault`, **sans jeton de compte de service**
   monté.
5. **Mettre la clé à l'abri** : `kubectl -n soc exec deploy/soc -- cat /data/plume-at-rest.key`, puis
   décommentez `PLUME_DB_KEY_ESCROWED`.
6. **Prouver** :
   ```sh
   kubectl -n soc rollout status deploy/soc
   curl -sv https://soc.example.org/readyz 2>&1 | grep -E 'subject:|HTTP/'   # votre certificat, puis 200
   kubectl -n soc exec deploy/soc -- curl -sS --max-time 5 https://example.com   # DOIT échouer
   ```
   Si la troisième commande aboutit, le CNI n'applique pas la `NetworkPolicy` (cluster démarré avec
   `--disable-network-policy`, ou CNI sans support) : l'egress n'est pas coupé.

Les agents du cluster poussent **par l'`Ingress`** (`PLUME_CENTRAL=https://soc.example.org`) : c'est le
chemin que la `NetworkPolicy` livrée laisse entrer (contrôleur dans `kube-system`, ou pods du namespace
`soc`). Les capteurs Kubernetes tournent sur le **nœud**, pas dans le pod (§4, §6.1).

---

## 3. Où vivent les secrets, et ce qu'ils permettent

| Secret | Où | Droits | Ce qu'il permet |
|---|---|---|---|
| jeton d'agent | `/etc/plume/plume.conf` de l'agent | `0600 root:root`, resserré à chaque passage de l'installateur | s'identifier sur la **liste fermée** des chemins machine (ingestion, métriques, traces, canal de réponse, engagements actifs) — jamais l'interface ; un jeton lié à l'hôte écrit **sous cet hôte**, quel que soit le `host` déclaré |
| le même jeton, recopié | `/etc/plume/responder.conf`, `/etc/plume/engagement-adapter.conf` (modules optionnels) | `0600` | réclamer les actions **de son hôte** sur le canal de réponse |
| jeton du relais MinIO | `/etc/plume/minio-audit.token` | `0640 root:soc` (le relais tourne sous `soc`) | déposer des événements d'audit objet dans le spool de l'hôte |
| jetons Cloudflare | `/etc/plume/cloudflare.conf` | `0600` | lecture d'analytique de la zone (posez un jeton en lecture seule) |
| hash admin, clé de base explicite | `/etc/plume/soc.conf` (hôte) · `.env` (Docker) · `Secret` `soc-auth` (k3s) | `0640 root:soc` sur l'hôte | ouvrir la console en admin (hash à attaquer hors ligne) ; ouvrir la base |
| clé de base engendrée | `<PLUME_DB>.key` (hôte) · `/data/plume-at-rest.key` (Docker, k3s) | `0600`, relue après création | **déchiffrer la base et toutes ses archives** |
| jeton d'installation | `setup-token.txt` à côté de la base, et le journal du démon | `0600`, effacé dès qu'un admin existe | créer le premier compte admin |

Le fichier vaut mieux que la variable pour un secret : l'environnement d'un processus se lit dans
`/proc/<pid>/environ`. Le détail des droits d'un jeton d'agent, et pourquoi « lié à l'hôte » est une
réécriture et non un refus, est dans [`AGENTS-PROTOCOLE.md` §3](AGENTS-PROTOCOLE.md#3-lauthentification-et-ce-que--lié-à-lhôte--veut-dire).

---

## 4. Les capteurs, un par un

**Dans les trois modes, un capteur est un artefact d'HÔTE.** L'image conteneur n'embarque aucun script
de `collectors/` : en Docker ils tournent sur l'hôte Docker, en k3s sur le nœud, installés par
`bootstrap-agent.sh` (ou par `bootstrap.sh` sur un central natif). Ceux qui lisent la machine
(journald, `auditd`, FIM, pare-feu…) lisent donc l'hôte Docker ou le nœud, jamais l'intérieur du
conteneur du central. `backup` n'a de sens qu'en hôte natif : en conteneur, le planificateur interne du
démon le remplace.

Sauf mention, l'unité systemd d'un capteur tourne en **root sans borne de capacités** ; « root, capacités
bornées à … » veut dire que l'unité restreint son ensemble de capacités à celles nommées. Le drop-in
de durcissement commun (filtre d'appels système `@system-service`, `ProtectSystem=strict`, écriture
limitée au spool et à l'état) est posé, **le même fichier** sur le central et sur l'agent, sur les douze
capteurs du central par `bootstrap.sh`, et sur l'agent sur ceux que pose `install_collector` — les trois
du défaut et ceux de `PLUME_EXTRA_COLLECTORS`. Les modules `PLUME_WITH_*` de `bootstrap-agent.sh` posent
leur unité **sans** ce drop-in : ils n'ont que le bac à sable de leur propre unité.
Deux réglages n'y sont **pas**, et chaque unité porte le sien : `PrivateTmp=` (un `/tmp` privé, sauf
pour `yara`, qui doit voir le vrai `/tmp` pour le scanner) et `RestrictAddressFamilies=` (les familles
de sockets que l'unité peut ouvrir : AF_INET/AF_INET6 pour qui parle au réseau — `ship`, `kubectl`,
`cscli`, `curl` —, AF_NETLINK pour qui lit le noyau — `nft`, `auditctl`, `ss` —, AF_UNIX pour tous).
Un réglage scalaire du drop-in écraserait celui de l'unité, une liste s'y ajouterait : c'est ainsi
que `yara` avait perdu `/tmp` sur l'agent quand il était posé par `PLUME_EXTRA_COLLECTORS=yara` (posé
par `PLUME_WITH_YARA=1`, sans drop-in, il le voyait), et que les capteurs que l'agent posait avec le
drop-in recevaient les quatre familles. La CI dérive les familles de chaque unité de ce que son script
appelle et refuse tout écart ; `controls` et `custom`, qui exécutent les commandes de l'exploitant
(`/etc/plume/controls.d/*.check`, `/etc/plume/custom.d`), gardent les quatre : un contrôle `kubectl`,
`nft` ou `ss` doit pouvoir ouvrir son socket. La table outil → famille est lue dans le code des outils,
pas mesurée sous systemd.

La colonne **Preuve** donne la requête qui montre que la source remonte. ♥ marque un capteur qui émet un
**battement** (`category=health`) à chaque passage, même quand la source est calme : son silence est
alors anormal. Deux le font seulement après une lecture : `auditd` (aucun battement quand le journal
d'audit n'a pas grandi) et `web` (aucun quand le passage n'a lu aucune requête neuve : journal vide,
ou figé parce que Traefik n'écrit plus). Pour les capteurs sans ♥,
une source calme ne produit rien, et la preuve est de jouer le capteur à la main (code de sortie 0, puis
fichier dans `/var/lib/plume/spool/`), comme le fait le
[`README`](../README.md#de-bout-en-bout-sans-rien-supposer-de-connu) pour `custom`.

| Capteur (`source`) | Lit · prérequis | Privilèges | Ce qui entre dans le SIEM | Risque · réglage sûr | Preuve |
|---|---|---|---|---|---|
| `resources` (métriques) | `/proc`, `/sys`, `df` | root, **aucune** capacité | CPU, mémoire, disque, température, réseau → table `metric` | aucun secret | `metric cpu_pct \| timechart avg(value)` |
| `integrity` | fichiers sensibles, unités systemd, persistance | root, capacités bornées à `CAP_DAC_READ_SEARCH` | chemins, empreintes SHA-256, nature du changement | les chemins disent ce que la machine porte | `search source=integrity \| stats count` ♥ |
| `ship` | le spool | root, lit `/etc/plume/plume.conf` | *(n'émet rien : il expédie)* | refuse le clair distant (§5) | `journalctl -u plume-ship` |
| `journal` (`sshd`, `sudo`, `su`) | journald | root, **aucune** capacité | lignes d'authentification, **ligne de commande `sudo` complète** dans `message` | tout secret tapé dans une commande `sudo` entre dans le SIEM : ne passez jamais de secret en argument | `search source=journal category=health \| table ts, host, message` ♥ |
| `auditd` | `/var/log/audit/audit.log` · `auditd` + règles chargées (§6.4) | root | exécutions (`exe`, `comm`, `auid` — pas les arguments), comptes, échecs d'authentification, accès des clés `plume_*` | volume ; plafond `PLUME_AUDIT_MAX` (§6.3) | `search source=auditd category=health \| table ts, host, message` ♥ |
| `audit` | `ausearch` | root, capacités bornées à `CAP_AUDIT_READ CAP_DAC_READ_SEARCH` | *(remplacé par `auditd` ; `bootstrap.sh` le désactive)* | ne pas activer avec `auditd` | — |
| `controls` | `systemctl`, `sysctl`, catalogues `/etc/plume/controls.d` | root, capacités bornées à `CAP_NET_ADMIN CAP_NET_RAW` | un **instantané** : les défenses attendues tournent-elles | aucun secret | instantané, affiché par la vue d'ensemble : `search` ne le voit pas |
| `firewall` | ruleset `nft` / `iptables` | root, capacités bornées à `CAP_NET_ADMIN CAP_NET_RAW` | un **instantané** : empreinte du ruleset | — | instantané, affiché par la vue d'ensemble : `search` ne le voit pas |
| `nft` | compteurs des sets `nft` · `nft`, `jq` | root | compteurs → `metric` | — | `metric nft_blocked_total \| timechart avg(value)` |
| `ufw` | `ufw` | root | blocages vus, règles autorisées | — | `search source=ufw category=health \| table ts, message` ♥ |
| `conntrack` | `ss` | root | flux entrants et sortants : adresses, ports, processus | cartographie du trafic de l'hôte | `search source=conntrack \| stats count by dir` |
| `origin-drop` | `journalctl -k`, préfixe `ORIGIN-DROP:` que vous posez | root | paquets rejetés à l'origine | — | `search source=origin-drop category=health \| table ts, message` ♥ |
| `portscan` · `portprobe` | table `nft` `plume-portscan` · `nft`, `jq` | root | adresses qui balaient, ports | — | `search source=portscan category=health \| table ts, message` ♥ |
| `bans` (`fail2ban`) | `cscli`, `fail2ban-client` (ou dans un pod) | root ; **kubeconfig** si les moteurs sont dans le cluster | bans actifs, `category=ban` | `kubectl exec` dans le pod du moteur (§6.1) | `search source=fail2ban category=health \| table ts, message` ♥ |
| `crowdsec` | `cscli` (ou dans le pod LAPI) · `jq` | root ; **kubeconfig** en k3s | alertes, et un battement qui dit ce que le moteur **lit** | derrière un mandataire, la liste blanche des adresses privées aveugle le moteur (§6.5) | `search source=crowdsec category=health \| table ts, acq_verdict, message` ♥ |
| `falco` | sortie JSON de Falco | root, capacités bornées à `CAP_DAC_READ_SEARCH` | détections eBPF | — | `search source=falco \| stats count` |
| `suricata` | `eve.json` | root | alertes IDS | — | `search source=suricata \| stats count` |
| `clamav` | `clamscan` / `clamdscan` sur les fichiers nouveaux | root | fichier, signature | noms de fichiers échappés | `search source=clamav \| stats count` |
| `yara` | `yara` + vos règles dans `/etc/plume/yara.d` ; scanne par défaut `/home /tmp /var/tmp /dev/shm` | root, `/home` en lecture seule, **`/tmp` de l'hôte visible** (`PrivateTmp=false`, ses temporaires vont sous `/var/lib/plume/state`) | fichier, règle, SHA-256 | sans `yara` ou sans règle, ne scanne rien et le dit (`unavailable`) | `search source=yara \| stats count` |
| `vuln` | `trivy`, `crictl` | root | CVE des images déployées (`category=vuln`) | — | `search source=vuln \| stats count by severity` |
| `imgdrift` (`update`) | `skopeo`, `crictl` | root | nouveau digest sur un même tag | — | `search source=update \| stats count` |
| `containerd` | `crictl`, `jq` | root | images tirées, conteneurs démarrés | — | `search source=containerd \| stats count` |
| `kube-state` (`k8s`) | `kubectl` | root ; l'unité pose `KUBECONFIG` sur le fichier **d'administration** de k3s | état du cluster → `metric` + events | droits d'admin du cluster (§6.1) | `metric kube_pods_running \| timechart avg(value)` |
| `kube-audit` | fichier d'audit de l'API | root | verbe, ressource, utilisateur, décision | — | `search source=kube-audit \| stats count by verb` |
| `kube-rbac` | `kubectl` | root ; **kubeconfig** | qui peut quoi (liaisons, rôles) | — | `search source=kube-rbac \| stats count` |
| `pod-logs` (`k8s-log`) | `/var/log/pods` | root, capacités bornées à `CAP_DAC_READ_SEARCH` | lignes de journaux de pods **filtrées** (seuil `PLUME_POD_LOG_MIN_SEV`, défaut 3) | une ligne de journal d'application peut porter une donnée personnelle ou un secret ; exclusions par drop-in local (§6.6) | `search source=k8s-log category=health \| table ts, message` ♥ |
| `web` | journal d'accès Traefik (`kubectl logs` ou fichier) | root ; **kubeconfig** en mode k3s | requêtes : méthode, chemin tel que Traefik l'écrit, statut, adresse | un jeton passé en paramètre d'URL entre avec le chemin ; borne de lecture `PLUME_WEB_MAX` (§6.2) | `search source=web category=health \| table ts, message` ♥ |
| `mail` | journal du serveur mail (fichier ou pod) | root ; **kubeconfig** si le serveur est dans le cluster | connexions, verdicts DKIM/DMARC/SPF, sortant, file, ClamAV | **parties locales masquées** partout (`*@domaine`), sauf l'expéditeur d'un envoi **originaire** de ce serveur (règle d'envoi massif) | `search source=mail \| stats count by category` |
| `collector-mail` | maildir de l'hôte | root, lit `/etc/plume/mail.conf` | compte, dossier, domaine de l'expéditeur, motif trouvé ; URL **coupée** au chemin (requête, fragment, identifiants retirés) ; **objet non émis** sauf `PLUME_MAIL_EMIT_SUBJECT=1` | un chemin d'URL peut porter un jeton (`/reset/<jeton>`) : il sort borné, pas retiré | `search source=mail \| stats count` |
| `collector-syslog` | UDP/TCP 514 | **utilisateur `soc`**, seule capacité `CAP_NET_BIND_SERVICE` | lignes syslog d'équipements (FortiGate, générique) | syslog n'est authentifié par **rien** (§5) | `search source=fortigate \| stats count` |
| `minio-audit-relay.py` (`minio-audit`) | webhook d'audit MinIO | **utilisateur `soc`** | seau, objet, opération, clé d'accès, adresse | refuse de démarrer sans jeton (§5) | `search source=minio-audit \| stats count` |
| `minio` | `mc` | root ; **kubeconfig** | politiques, seaux publics, utilisateurs | — | `search source=minio \| stats count by kind` |
| `dataaccess` | règles d'audit d'accès | root, capacités bornées à `CAP_AUDIT_READ CAP_DAC_READ_SEARCH` | utilisateur, action, chemin | sans `CAP_AUDIT_CONTROL`, `auditctl -l` lui est refusé : le battement nomme les clés **prouvées par le journal** (chargement ou accès depuis le dernier démarrage d'`auditd`), et dit « couverture INCONNUE » (sévérité 1) quand ni `plume_data` ni `plume_creds` n'y est prouvée | `search source=dataaccess category=health \| table ts, message` ♥ |
| `dataacl` | droits des chemins surveillés | root, capacités bornées à `CAP_DAC_READ_SEARCH` | propriétaire, mode, risque | — | `search source=dataacl \| stats count` |
| `cloudflare` · `cloudflare-http` | API GraphQL de Cloudflare · `curl`, `jq` | root, lit `/etc/plume/cloudflare.conf` | événements WAF, requêtes 4xx/5xx vues au bord | jeton en lecture seule sur la zone | `search source=cloudflare-http \| stats count` |
| `prom-scrape` | vos cibles `/metrics` | root, lit `/etc/plume/prom.conf` | séries → `metric` | une cible authentifiée par paramètre d'URL expose ce paramètre ; refuse le clair distant vers le central (§5) | `metric <une de vos séries> \| timechart avg(value)` |
| `custom` | votre `CMD`, en root | root | une ligne de sortie = un événement | `/etc/plume/inputs.d` **doit** être `0700 root` : y écrire, c'est exécuter en root | `search source=<SOURCE> \| stats count` |
| `respond`, `engagement-adapter`, `backup` | *(pas des capteurs : ils agissent ou sauvegardent)* | `respond` du central (`plume-daemon respond`) : root, capacités bornées à `CAP_NET_ADMIN CAP_KILL` ; `respond` d'agent (`respond.sh`) et `engagement-adapter` : root ; `backup` : `soc` | résultats d'actions | le responder d'agent agit en root sans borne : dry-run par défaut ; `respond.sh` et `engagement-adapter` refusent le clair distant vers le central (§5) | — |
| `windows/` | journaux Windows, pare-feu, Defender | tâche planifiée | voir [`../collectors/windows/README.md`](../collectors/windows/README.md) | — | `search source=windows-security \| stats count` |

**Un capteur qui ne peut pas collecter le dit**, au lieu de se taire : un événement `category=config`,
`collect_status=unavailable` et une `reason` (`missing-dependency`, `missing-source`, `missing-config`,
`subsystem-absent`, `unreachable`). Une collecte coupée par une borne le dit aussi
(`reason=collection-capped`). Les deux requêtes :

```
search category=config collect_status=unavailable | table ts, host, source, reason, detail
search category=config reason=collection-capped | table ts, host, source, detail
```

> ⚠️ **L'alerte sur ces aveux n'est pas active par défaut.** La règle
> `config.d/rules/catalog/de-collector-unavailable.json` est livrée `enabled: false`, comme la quasi-totalité du
> catalogue. Activez-la dans la console (rôle admin) : l'activation est enregistrée à part et **survit**
> au redémarrage, que le fichier réimpose sinon. Tant qu'elle est éteinte, un capteur aveugle ne lève
> rien. Autre limite, ouverte sous `P10.32-s` : un aveu d'indisponibilité tient fraîche la sonde de
> flux de sa source, qui paraît donc vivante.

---

## 5. Le transport

- **Les scripts qui parlent au central refusent le clair vers un hôte distant** : `ship.sh`,
  `respond.sh`, `prom-scrape.sh` et `engagement-adapter.sh`. `PLUME_CENTRAL` en `http://` (ou sans
  schéma) vers autre chose que la boucle locale (`127.0.0.0/8`, `::1`, `localhost`) est **refusé**,
  code 2, avant tout appel au central : `ship.sh` n'expédie ni n'évince rien (le spool reste),
  `respond.sh` ne récupère ni n'exécute aucune action, `prom-scrape.sh` ne scrape aucune cible,
  `engagement-adapter.sh` révoque ses exemptions de ban pour ce cycle (son mode `revert-expired`
  n'appelle pas le central et n'est pas concerné). `PLUME_SHIP_ALLOW_PLAINTEXT=1` l'accepte, avec un
  avertissement à chaque passage — **le jeton passe alors lisible sur le réseau**, quiconque l'écoute
  peut le rejouer, et un intermédiaire peut répondre à la place du central (des actions exécutées en
  root par `respond.sh`, des exemptions posées par `engagement-adapter.sh`). Ne le posez que sur un lien
  déjà chiffré (tunnel) ou un réseau dont vous répondez, et **dans le fichier d'environnement de chaque
  unité** : chacune lit le sien (`plume.conf` pour `ship`, `responder.conf`, `prom.conf`,
  `engagement-adapter.conf`). Le collecteur Windows (`plume-collector.ps1`) ne refuse pas encore le
  clair.
- **TLS côté agent** : `PLUME_TLS_CACERT` pour un central à autorité privée ; `PLUME_TLS_CERT` et
  `PLUME_TLS_KEY` pour un certificat client, si le mandataire du central l'exige. Le démon, lui, ne
  vérifie aucun certificat client : un mTLS obligatoire se pose sur le mandataire. Même nom de variable,
  rôle opposé côté démon ([`AGENTS-PROTOCOLE.md` §7](AGENTS-PROTOCOLE.md#7-tls-et-mtls)).
- **Relais MinIO** : il **refuse de démarrer** sans jeton (fichier `PLUME_MINIO_AUDIT_TOKEN_FILE` absent,
  vide ou illisible : code 2), répond `401` à une requête sans le bon jeton (comparaison à temps
  constant) et `503` si le jeton devient illisible en marche. Son écoute par défaut est l'adresse du pont
  des pods (`PLUME_MINIO_AUDIT_BIND`), pas toutes les interfaces.
- **Syslog** : la configuration posée par `bootstrap-agent.sh` écoute **`127.0.0.1:514`**. Une écoute
  hors boucle locale **sans** `PLUME_SYSLOG_ALLOW` fait **refuser le démarrage** (code 2) ; une écoute
  posée **vide** coupe son transport ; une écoute **absente** vaut `0.0.0.0:514` — et tombe alors sous
  le même refus sans liste. Pour l'ouvrir à vos équipements : la liste, puis un pare-feu en refus par
  défaut, puis seulement l'écoute. En conteneur, la boucle locale est celle du conteneur : la marche à
  suivre est dans [`../deploy/SYSLOG.md`](../deploy/SYSLOG.md#conteneur-docker-et-le-receiver-du-deploiement-b--limage-demarre-refusee).

---

## 6. Les risques que le produit assume, et comment les réduire

### 6.1 Des capteurs root, et le fichier d'administration du cluster

Les capteurs Kubernetes (`kube-state`, `kube-rbac`, `web` en mode k3s, `mail`, `bans`, `crowdsec`,
`minio`, et le responder d'agent) appellent `kubectl` ou `k3s kubectl` **en root** sur le nœud. L'unité de `kube-state` pose
`KUBECONFIG` sur le fichier d'administration de k3s ; les autres prennent ce que `kubectl` résout, et
`k3s kubectl` lancé en root emploie ce même fichier. **Une faille d'un de ces scripts vaut donc les
droits d'administration du cluster.** Pour réduire :

- donnez à chaque unité un kubeconfig dédié, par un drop-in **local**
  (`sudo systemctl edit plume-kube-state.service`, puis `[Service]` et
  `Environment=KUBECONFIG=/etc/plume/kube-lecture.yaml`, fichier `0600`) ;
- liez ce kubeconfig à un compte de service aux **seuls verbes utiles** : lecture (`get`, `list`) pour
  `kube-state` et `kube-rbac` ; `pods/log` sur le namespace de Traefik pour `web` ; `pods/exec` — lire
  un journal ou lancer `mc`/`cscli` **dans** le pod — sur le seul namespace visé pour `mail`, `minio`,
  `bans`, `crowdsec` et le responder. `pods/exec` revient à exécuter du code dans ce pod : ne l'accordez
  nulle part ailleurs ;
- n'activez que les capteurs dont vous lisez la sortie. *Ce découpage n'a pas été joué ici : vérifiez
  chaque capteur par sa requête de preuve après le changement.*

Le pod du **démon**, lui, n'a ni client Kubernetes ni jeton de compte de service monté.

### 6.2 L'`Ingress` k3s, et ce qui se voit derrière un mandataire

L'`Ingress` livré est restreint à l'entrée `websecure` ; un autre contrôleur ignore ces annotations et
peut servir aussi l'entrée en clair (§2.4). Derrière tout mandataire, trois faits :

- **le ban natif** lit l'adresse réelle du client dans les en-têtes, **mais seulement** d'un pair de
  confiance : par défaut tout pair privé ou de boucle locale ; avec `PLUME_TRUSTED_PROXIES`, les seules
  adresses listées. Un pod du réseau privé qui joint le démon en direct peut donc, par défaut, se
  réécrire une adresse : posez `PLUME_TRUSTED_PROXIES`, et scellez les en-têtes par `PLUME_EDGE_SECRET` ;
- **la limitation de débit et le verrouillage anti-force-brute** comptent par **pair TCP**, donc par
  l'adresse du mandataire : tous les clients partagent le même seau. Des échecs répétés contre le compte
  admin depuis l'extérieur verrouillent ce compte **pour tout le monde** derrière ce mandataire, le temps
  du *backoff* ;
- **le cookie de session et HSTS** : le démon pose l'attribut `Secure` sur ses cookies et l'en-tête HSTS
  sur ses réponses avec le **TLS natif**, ou quand `PLUME_TLS_TERMINATED_UPSTREAM=1` lui dit qu'un
  mandataire sert le HTTPS devant lui (« 1 » seul l'active ; vide par défaut). Il croit ce réglage sur
  parole : il ne lit aucun en-tête du mandataire. `deploy/k3s.yaml` le pose à `1`, son `Ingress` ne
  servant que `websecure` ; en hôte natif, il se pose dans `/etc/plume/soc.conf` ; en Docker, dans `.env`
  (le service le transmet). Posé, un accès **direct** en HTTP au démon (tunnel, `port-forward`) perd son
  cookie de session, et le démon le rappelle dans son journal au démarrage. Non posé derrière un
  mandataire TLS, le cookie part sans `Secure` et sans HSTS : ne servez pas alors le même nom en clair.

`PLUME_WEB_MAX` (défaut 10000) borne les lignes que le capteur `web` lit par passage. Ce qu'un flot plus
long fait au-delà dépend de la source :

- **`PLUME_WEB_SRC=file`** : le journal se lit par offset d'octets. Au-delà de la borne, le reste est lu
  aux passages suivants : rien n'est sauté. Seul le premier passage (aucun état de lecture) lit les
  `PLUME_WEB_MAX` dernières lignes, et le battement dit combien d'octets antérieurs il n'a pas lus. Après
  une rotation, la fin du journal précédent est reprise dans `<journal>.1` ; si celui-ci est introuvable
  (rotation compressée sans `delaycompress`), la perte est avouée (`missing-source`, nombre inconnu) ;
- **`PLUME_WEB_SRC=k3s`** (le défaut) : `kubectl logs --tail` ne rend que les dernières lignes de la
  fenêtre. Les plus anciennes ne sont pas lues, mais un second `kubectl logs` les **compte**, et le
  nombre est avoué dans le battement et par un `collection-capped` : exact, « au moins N » quand le flot
  dépasse aussi la borne du comptage (10 × `PLUME_WEB_MAX` lignes par pod), ou « nombre inconnu » quand
  le comptage échoue.

Le battement porte la valeur en vigueur (« borne de lecture PLUME_WEB_MAX=10000 atteinte » au défaut) :
cherchez `PLUME_WEB_MAX=`. En k3s, montez-la si ce message revient.

### 6.3 Le plafond d'`auditd`

`PLUME_AUDIT_MAX` (défaut 4000) borne les événements émis par passage. Au-delà, les événements des clés
de **sabotage** (TAMPER) sont gardés d'abord, puis les autres par gravité décroissante ; ce qui reste est
**compté** et avoué dans le battement (`… au-delà du plafond PLUME_AUDIT_MAX`) et par un
`collection-capped`. Relevez la borne si l'aveu se répète.

### 6.4 Des règles d'audit qui doublonnent celles de plume

`augenrules --load` concatène les fichiers de `/etc/audit/rules.d/` et **s'arrête à la première règle
en échec** sans revenir en arrière. Une règle d'un **autre** fichier identique à une règle de
`plume.rules` fait échouer ce doublon (« Rule exists »), et tout ce qui suit n'est pas chargé — au
chargement comme au démarrage d'`auditd`, qui rejoue le même assemblage.

Les deux installateurs passent par **un seul chargeur**, `plume-audit-rules-load.sh` : `bootstrap.sh`
l'appelle quand `auditd` est installé, `bootstrap-agent.sh` le pose sans le lancer et affiche le geste.
Il commente dans la copie posée chaque ligne du gabarit déjà déclarée **à l'identique** par un autre fichier
(`## plume-doublon : déjà déclarée par <fichier> …`), lance `augenrules --load`, compte par clé ce que
`auditctl -l` rapporte, rattrape règle par règle ce qui manque, et rend :

| Code | Ce que le noyau tient | Message |
|---|---|---|
| `0` | tout, par l'assemblage lui-même | `>> OK — toutes les règles déclarées sont chargées.` |
| `1` | **pas tout** : chaque clé manquante est nommée, et la ligne refusée avec le message d'`auditctl` s'il y en a une — ou le chargeur n'a pas pu travailler (gabarit introuvable, `auditd` absent, pas root), message en `!!` | `!! CHARGEMENT PARTIEL — REFUSÉ` ; s'il a rattrapé des règles, il dit combien seront perdues au prochain démarrage |
| `2` | tout **maintenant**, mais par le seul rattrapage : le prochain démarrage d'`auditd` s'arrêtera au même endroit | `!! RÈGLES PLUME COMPLÈTES MAINTENANT, MAIS PAR LE SEUL RATTRAPAGE` |

`bootstrap.sh` pose tout le reste puis finit en code `3` si le chargeur n'a pas rendu `0`, avec un message
propre à chaque cas (« RÈGLES D'AUDIT INCOMPLÈTES MAINTENANT » pour `1`, « RÈGLES D'AUDIT COMPLÈTES
MAINTENANT, MAIS PAS AU PROCHAIN DÉMARRAGE » pour `2`). Un doublon écrit autrement (ordre des champs)
n'est pas reconnu à l'identique : il finit en code `2`. Le détail est dans
[`ENDPOINT-SECURITY.md` §4ter](ENDPOINT-SECURITY.md#4ter-charger-les-règles-et-vérifier-ce-qui-tourne).

**Vérifier, en lecture seule** — ne modifie rien :

```sh
sudo auditctl -l | grep -oE '(-k |key=)[a-z_]+' | sort | uniq -c  # compte par clé : `-k` pour les watches, `key=` pour les appels système
sudo grep -E '^[[:space:]]*-' /etc/audit/rules.d/plume.rules | grep -oE -- '-k [a-z_]+' | sort | uniq -c  # ce que le fichier déclare
```

Chaque clé du second compte doit avoir au moins autant de règles dans le premier — une ligne commentée
`## plume-doublon` ne compte pas dans le second, la règle étant tenue par l'autre fichier. La liste doit
porter
`exec_tracking` (deux règles `execve`, 64 et 32 bits) : sans elle, `category=exec` reste vide.
`svc_exec` n'y figure que si vous avez décommenté ses règles dans le gabarit.

**Recharger** — ce n'est pas une vérification : `plume-audit-rules-load.sh` **réinstalle** le gabarit,
dédoublonné, par-dessus `/etc/audit/rules.d/plume.rules`, puis charge et compte comme ci-dessus.
**Une copie locale modifiée de `plume.rules` est écrasée** : reportez vos changements dans le gabarit
que vous lui passez, ou sauvegardez le fichier avant. Relancez-le aussi après tout changement d'un autre
fichier de `/etc/audit/rules.d` : une règle commentée chez plume parce qu'un autre fichier la portait
disparaît avec ce fichier.

```sh
sudo sh systemd/plume-audit-rules-load.sh                        # central, depuis le dépôt : gabarit systemd/plume-audit.rules
sudo sh /usr/local/lib/plume/plume-audit-rules-load.sh /usr/local/share/plume/plume-audit.rules   # agent
```

Sans argument, le chargeur prend `plume-audit.rules` à côté de lui (le dépôt), sinon
`../../share/plume/plume-audit.rules` depuis son répertoire : installé, `/usr/local/share/plume/`, où les
deux installateurs posent le gabarit. Le passer en argument, comme ci-dessus, ne laisse aucun doute.

### 6.5 CrowdSec derrière un mandataire

Derrière un mandataire ou un tunnel, l'adresse que CrowdSec lit dans le journal est celle du **relais**,
une adresse privée, et la liste blanche des adresses privées l'écarte avant les scénarios : le moteur lit
et ne peut rien détecter. Le battement le dit (`acq_verdict` à `tout_en_liste_blanche` ou
`surtout_liste_blanche`, seuil `PLUME_CROWDSEC_WHITELIST_SHARE_MAX`, défaut 90). Le remède est de faire
écrire au journal **la vraie adresse cliente** (en-tête d'adresse réelle du mandataire, journal d'accès
qui la porte), pas de retirer la liste blanche.

### 6.6 `pod-logs` : ses exclusions se posent dans un drop-in LOCAL

L'unité ne lit aucun fichier de configuration. `PLUME_POD_LOG_SKIP` (pods déjà couverts par un capteur
dédié) et `PLUME_POD_LOG_MIN_SEV` se posent par `sudo systemctl edit plume-pod-logs.service` — jamais
dans le fichier livré, qu'une mise à jour écrase.

### 6.7 Ce qui ne se voit pas d'un coup d'œil

- Un réglage de `.env` que le bloc `environment:` du service n'énumère pas n'atteint pas le conteneur.
- `PLUME_QUERY_MAX` est lu dans l'**environnement seul** : sur un hôte, l'écrire dans
  `/etc/plume/soc.conf` est sans effet — posez-le par un drop-in de `plume-daemon.service`.
- Le mode SETUP reste ouvert tant qu'aucun admin n'existe.

---

## 7. Les tableaux de bord, et le capteur qui les nourrit

Un tableau semé vide n'est pas un tableau cassé : c'est souvent un producteur absent. Relevé dans
`daemon/src/seeds.rs` :

| Tableau semé | Producteur livré | À savoir |
|---|---|---|
| SOC — Vue d'ensemble | tous ; `resources` pour les courbes | — |
| Sécurité & détection | `vuln`, `clamav`, `conntrack`, `auditd`, `suricata`, `mail` | un panneau par capteur : vide si le capteur n'est pas activé |
| Réseau sortant (egress) | `conntrack`, `resources` (`net_tx_bps`) | — |
| Trafic web | `web`, `cloudflare` | — |
| Mail — flux & verdicts | `mail` | expéditeurs et destinataires y apparaissent masqués (`*@domaine`), hors expéditeur d'un envoi originaire du serveur |
| Accès données (Varonis) | `dataaccess` | — |
| Carte d'accès (Varonis) | `dataacl` | — |
| RBAC k8s (Varonis) | `kube-rbac` | — |
| MinIO / S3 (Varonis) | `minio` | — |
| Vault — accès secrets (Varonis) | `custom`, avec la déclaration d'exemple [`../deploy/vault-audit.input.example`](../deploy/vault-audit.input.example) | rien sans cette déclaration |
| Infra & logs (OBS) | `resources`, `kube-state` | — |
| Posture de configuration (SCA/CIS) | **aucun** | nourri par un agent tiers (Wazuh, source `wazuh`) normalisé à l'ingestion |
| Vulnérabilités (CVE endpoint) | **aucun** pour les champs groupés | `vuln` pose `category=vuln` mais ni `cve`, ni `vuln_severity`, ni `vuln_package`, ni `agent_name` : les panneaux groupés restent vides, et seul le détail (gravité ≥ 3) liste des lignes, aux colonnes vides |
| Conformité — `<cadre>` | **aucun** | même source que la posture |

Que ces trois tableaux disent eux-mêmes qu'ils n'ont pas de source est porté par `P10.32-p`.

---

## 8. La recherche : ce qui est plafonné, et comment tout lire

En bref, détaillé dans [`GXQL.md` §6.4](GXQL.md#64-ce-que-le-plafond-coupe-et-comment-tout-lire) :
`PLUME_QUERY_MAX` (défaut 5000) **n'est pas une limite de ce que plume interroge ni de ce qu'il compte** :
c'est le nombre de **lignes rendues** dans un tableau. Sans tier froid, un `stats` est calculé sur tous
les événements de la fenêtre, et un `stats … by` qui produit plus de groupes que le plafond rend les
premiers groupes et le dit. **Avec le tier froid actif** (binaire construit avec `cold_tier`, `PLUME_COLD_TIER=1`) et une fenêtre qui atteint
le froid, 5000 est aussi le nombre de lignes froides qu'un des chemins de lecture recopie avant de
calculer : quand cette recopie a atteint le plafond, une requête qui calcule une valeur sur l'ensemble
est **refusée** (`422`, `"reason": "cold_truncated_aggregate"`) plutôt que de rendre un nombre faux. On
s'en sort en resserrant la fenêtre, ou en relevant `PLUME_QUERY_MAX` jusqu'à `100000` au prix de la
mémoire. Une expression régulière ne peut pas contenir d'alternance
aujourd'hui ([`GXQL.md` §2.4](GXQL.md#24-limite-connue--une-barre-verticale-dans-une-expression-régulière)).
Son motif est borné, au chaud comme au froid et à l'import Sigma : 512 octets (refus `400`,
« motif regex trop long (max 512) »), 1 Mio de programme compilé (refus `400`, message du moteur),
1 Mio de cache du DFA paresseux (dépassé, la recherche ralentit sans refus). Ce qui reste ouvert : les
requêtes interactives se partagent un sémaphore (`PLUME_QUERY_CONCURRENCY`, défaut 3), et quelques
requêtes lourdes lancées ensemble font attendre toutes les autres.
