# Les agents et leur protocole

Ce que fait un agent tient en une phrase : **il lit une source, il tamponne sur disque, il POSTe au
central, et il n'oublie ce qu'il a lu qu'une fois la publication acquittée.** Tout le reste de cette
page est le détail de cette phrase, et surtout **ce qu'elle ne promet pas**.

Chaque affirmation est établie par lecture des sources et porte la commande qui la redonne.
Ce document décrit le **protocole** ; l'agent d'endpoint lui-même est documenté dans
[`../agent/README.md`](../agent/README.md), sa validation dans [`../agent/CI.md`](../agent/CI.md), et
les points d'extension dans [`SDK.md`](SDK.md).

---

## 1. Trois familles, un seul contrat de fil

Le mot « agent » recouvre trois choses différentes dans ce produit. Les confondre est la première
source de malentendu.

| Famille | Ce que c'est | Où elle tourne | Tampon |
|---|---|---|---|
| **collecteurs shell** | `collectors/*.sh` + timers systemd, posés par `bootstrap-agent.sh` ; un expéditeur séparé (`ship.sh`) vide le spool | hôte Linux | fichiers dans `PLUME_SPOOL` |
| **agent d'endpoint** | un binaire Rust multi-OS (`agent/`) qui lit, tamponne et expédie lui-même | Linux, Windows, macOS | anneau borné sur disque |
| **sans agent** | collecteur PowerShell Windows, récepteur syslog, HEC, OTLP, connecteurs en PULL | la source, ou le central | variable |

**Elles finissent toutes sur le même contrat de fil.** C'est ce qui permet d'en ajouter une sans
toucher au central — et c'est pourquoi ce document décrit le contrat avant les familles.

---

## 2. Le contrat de fil

### 2.1 L'enveloppe

`POST /api/ingest`, `Authorization: Bearer <jeton>`, corps JSON :

```json
{
  "kind": "events",
  "ts": 1756000000,
  "host": "ws22-lab",
  "env_id": "prod",
  "events": [
    { "ts": 1756000000, "source": "sshd", "category": "auth", "severity": 2,
      "message": "Failed password for root", "host": "ws22-lab",
      "dedup": "sshd:1756000000:root", "fields": { "user": "root", "src_ip": "192.0.2.10" } }
  ]
}
```

Seul **`kind`** est obligatoire, et c'est le seul champ vérifié au moment du POST. Les valeurs
`events`, `metrics` et les instantanés (`firewall`, `controls`, …) sont dispatchées à la relecture.

| Champ d'enveloppe | Si absent |
|---|---|
| `kind` | **refus `400`** |
| `ts` | l'instant de la relecture |
| `host` | **écrasé** par l'hôte du jeton s'il est lié (§3) |
| `env_id` | `prod` |
| `events` | liste vide |

| Champ d'événement | Si absent |
|---|---|
| `ts` | celui de l'enveloppe |
| `source` | `agent` |
| `severity` | `0` |
| `category`, `message` | chaîne vide |
| `dedup` | `NULL` → **aucune déduplication** pour cette ligne |
| `fields` | `NULL` ; `src_ip`, `dst_ip` et `url` en sont promus s'ils s'y trouvent |

La forme canonique est écrite trois fois à l'identique — dans la bibliothèque shell
(`collectors/lib.sh`), dans l'agent Rust (`agent/src/source/`) et dans `agent/README.md`.

### 2.2 Ce que le POST vérifie — et ce qu'il ne vérifie pas

**MESURÉ SUR L'ARBRE le 2026-08-25 : il n'existe aucune structure Rust désérialisée pour cette
enveloppe.** Le corps est pris en `String`, parsé en JSON générique, et **écrit verbatim dans le
spool du central** après un seul contrôle : la présence de `kind`.

```sh
grep -rn 'derive(Deserialize' daemon/src/ingest    # rien
```

Conséquence à connaître avant de déboguer une intégration : **un événement mal formé rend `202`, pas
une erreur.** Ce qui est refusé synchroniquement est court :

| Code | Quand |
|---|---|
| `202 {"queued":true,"durable":true}` | le corps est du JSON et porte `kind` — sur `durable`, voir §2.5 |
| `400` | JSON invalide, ou `kind` absent |
| `413` | trop d'événements dans un lot, ou corps trop gros — le message **nomme le plafond qui a mordu et le levier qui le change** |
| `503` + `Retry-After: 60` | plancher d'espace libre franchi (`PLUME_INGEST_MIN_FREE_MB`) |
| `429` + `Retry-After` | limitation de débit (globale, par IP, ou d'authentification) |
| `401` / `403` | jeton inconnu, ou rôle insuffisant |
| `500` | écriture du spool impossible |

Il n'y a **pas de `507`** dans ce produit : la pression disque parle en `503`.

### 2.3 Les autres portes d'entrée

| Route | Format | Succès | Particularité |
|---|---|---|---|
| `/api/ingest` | enveloppe ci-dessus | `202` | la porte de référence |
| `/api/ingest/journal` | NDJSON journald brut | `202`, `204` si vide | pas d'enveloppe englobante |
| `/api/ingest/minio` | audit MinIO natif | `202`, `204` si le lot est entièrement filtré | plafond de route **plus bas** que le plafond configurable |
| `/services/collector[/event]` | Splunk HEC | **`200`** `{"text":"Success","code":0}` | compatible fil : pointez vos *forwarders* existants |
| `/services/collector/health` | — | `200` | **route publique**, sans authentification |
| `/v1/traces` | OTLP/HTTP JSON, gzip accepté | — | **`404` tant que `PLUME_OTLP_TRACES` n'est pas à `1`** |
| `/api/ingest/firehose`, `/api/ingest/pubsub` | AWS Firehose, push GCP | — | **les seules routes d'ingestion qui s'authentifient dans leur propre gestionnaire**, hors du contrôle commun |

Toutes héritent du plafond de corps **par construction** : la borne est posée sur le sous-routeur, pas
route par route, de sorte qu'une route ajoutée demain l'hérite sans qu'on y pense.

**Le syslog n'est pas une route HTTP.** Le récepteur écoute en UDP/TCP, écrit dans le spool local, et
c'est l'expéditeur qui POSTe. Il appartient au transport de la famille shell.

### 2.4 Les plafonds, et lequel mord vraiment

| Levier | Défaut |
|---|---|
| `PLUME_INGEST_MIN_FREE_MB` | `512` (Mo) ; `0` désactive la garde |
| `PLUME_INGEST_MAX_EVENTS` | `50000` |
| `PLUME_INGEST_MAX_BODY_MB` | `8` (Mio) |
| `PLUME_RL_GLOBAL_MAX` / `_IP_MAX` / `_AUTH_MAX` | `6000` / `1200` / `120` par fenêtre de 10 s |

Deux subtilités que le code porte et publie lui-même, et qu'il vaut mieux lire avant de relever un
levier qui ne mordra pas :

- **quand deux plafonds gardent la même route, le refus DÉRIVE lequel a lié** au lieu de nommer un
  levier en dur. Sur la route MinIO, c'est le plafond **de route** qui lie : relever
  `PLUME_INGEST_MAX_EVENTS` n'y change rien. Sur HEC, OTLP et Firehose, les deux sont ex æquo ;
- **le plafond d'octets mord bien avant le plafond d'événements** pour tout profil réaliste. Le
  message d'erreur du plafond d'événements était donc du code mort, et un intégrateur recevait à la
  place le message générique du cadriciel. C'est écrit et daté dans `daemon/src/limite_corps.rs`.

La garde disque **échoue en OUVERT** : si la mesure d'espace libre est impossible, l'ingestion passe.
C'est un choix — refuser sur une mesure absente ferait tomber l'ingestion pour une raison qui n'est
pas la bonne.

### 2.5 Ce que l'accusé de réception atteste — et ce qu'il n'atteste pas

**MESURÉ SUR L'ARBRE le 2026-08-29 : aucune surface de réception ne synchronise ce qu'elle vient
d'écrire.** Un 2xx rendu par le central atteste que le corps a été **reçu et remis au système**. Il
n'atteste **pas** qu'il survivrait à une coupure d'alimentation.

```sh
# le motif cherche un APPEL, pas une mention — sinon cette page se contredirait elle-même
grep -rn '\.sync_all()\|\.sync_data()' daemon/src/ingest                              # rien
grep -rn '\.sync_all()\|\.sync_data()' daemon/src/cold_store daemon/src/crypto daemon/src/backup   # six appels
```

La seconde commande est là parce qu'une commande qui ne rend rien ne prouve rien tant qu'on ne l'a pas
vue rendre quelque chose. Ce n'est donc **pas** une capacité qui manque au produit — le même geste est
appelé dans l'écrivain du tier froid, à l'écriture d'une clé de chiffrement et dans la sauvegarde. Il
est absent **là où la promesse est faite**.

Deux régimes, qu'il vaut mieux ne pas confondre :

| Régime | Routes | Ce qu'une coupure peut emporter |
|---|---|---|
| **spool** — un fichier écrit, **synchronisé**, renommé, puis dont le **répertoire** est synchronisé | `/api/ingest`, `/api/ingest/journal`, `/api/ingest/minio`, `/services/collector[/event]`, `/v1/traces`, `/api/ingest/firehose`, `/api/ingest/pubsub` | **rien de ce qui a été acquitté** : les deux barrières sont prises **avant** que l'accusé ne parte |
| **base** — une transaction validée en `journal_mode=WAL` + `synchronous=NORMAL` | `/api/metrics/prom`, `/api/metrics/write`, `/loki/api/v1/push` | les dernières transactions validées : le `COMMIT` survit à la mort du **processus**, pas à celle de la **machine** |

**Ce que cela change pour un expéditeur.**

*Sur les sept routes de spool*, l'accusé vous autorise à oublier, et il tient : quand le `2xx` part, le
corps est sur le disque, sous son nom définitif, les deux barrières prises. L'écriture est **déportée**
sur un fil bloquant, donc l'attente ne bloque pas le récepteur ; elle se paie en latence, pas en débit
perdu — le coût d'une barrière est celui de la **barrière**, pas de la taille du lot, et il s'amortit
dès que plusieurs expéditeurs poussent en parallèle. Un exploitant dont le stockage rend cette barrière
trop chère peut la désarmer avec `PLUME_INGEST_FSYNC=0` ; le champ `durable` retombe alors à `false` de
lui-même, et le paragraphe suivant redevient vrai pour lui.

*Sur les trois routes de base*, l'accusé ne couvre toujours que la mort du **processus**. Si votre
source est rejouable — un journal conservé, un flux à filigrane, un abonnement qui redélivre — gardez
de quoi rejouer une fenêtre : la déduplication du central (§4.4) absorbe le rejeu dès que vos
événements portent une clé. Si elle ne l'est pas, cette fenêtre est une perte que rien ne rattrape.

**Où c'est écrit dans la réponse, et où ça ne l'est pas.** Les quatre routes dont le corps appartient à
plume portent le champ **`durable`**, et ce n'est pas une constante : c'est la valeur que la
publication a **obtenue**.

| Route | `durable` | Pourquoi |
|---|---|---|
| `/api/ingest`, `/api/ingest/journal`, `/api/ingest/minio` | `true` | les deux barrières sont prises avant l'accusé (`false` si `PLUME_INGEST_FSYNC=0`, ou si le noyau refuse la barrière de répertoire après le renommage — auquel cas le lot est publié mais pas garanti) |
| `/api/metrics/prom` | `false` | régime **base** : rien n'a changé pour lui |

Les six autres accusés ont une forme dictée par un contrat **étranger** (Splunk HEC, OTLP, AWS
Firehose, GCP Pub/Sub, Loki push, Prometheus `remote_write`), quand ils ont un corps : y ajouter un
champ modifierait le protocole d'un tiers. Pour les quatre d'entre eux qui sont des routes de spool, le
témoin est côté exploitant, dans `/metrics` : `plume_spool_barriere_fichier_total`,
`plume_spool_barriere_repertoire_total`, `plume_spool_barriere_echec_total`. Les deux premiers montent
ensemble ; un écart, ou le troisième qui grimpe, dit qu'un `2xx` a cessé d'être adossé à une barrière.

> **Ce qui est prouvé, et ce qui ne l'est pas.** Ce qui est démontré est que les deux barrières sont
> **demandées au noyau et rendues sans erreur**, dans cet ordre, avant l'accusé. La survie à une
> coupure d'alimentation réelle ne se démontre pas depuis le processus : au-delà de l'appel, elle
> dépend du système de fichiers et du matériel.

> ⚠️ **Le régime « base » reste ouvert.** La perte y demeure un **défaut** ; elle est écrite en
> attendant d'être supprimée. C'est le solde de la clé `S31` de [`ROADMAP.md`](ROADMAP.md).

---

## 3. L'authentification, et ce que « lié à l'hôte » veut dire

### 3.1 Le jeton

```sh
plume-daemon token <nom> <hôte-lié>     # jeton de MACHINE
plume-daemon token <nom> --relais       # jeton de RELAIS (forwarder multi-hôtes)
```

La forme sans hôte **et** sans `--relais` est **refusée** : la portée d'un jeton se déclare, elle ne
se déduit pas d'une omission. Poser les deux à la fois est refusé aussi.

Le secret fait 32 octets d'entropie du système, s'affiche **une seule fois**, et **seul son SHA-256
est en base** — il n'est pas re-dérivable. Perdu, il se recrée ; il ne se relit pas.

Un jeton n'établit une identité que sur une **liste blanche de chemins** (ingestion, métriques,
traces, canal de réponse). Hors de cette liste, le porteur d'un jeton d'agent n'est personne : le
défaut est fermé.

### 3.2 La liaison n'est pas un refus, c'est une réécriture

**C'est le point le plus contre-intuitif du protocole, et il est mesuré dans le dépôt.** Un agent qui
déclare un `host` différent de celui auquel son jeton est lié **reçoit `202`** — et l'événement est
enregistré **sous l'hôte du jeton**, pas sous celui qu'il a déclaré.

Autrement dit : la liaison protège l'intégrité de l'inventaire, **elle n'avertit pas l'émetteur**. Ne
comptez pas sur un code d'erreur pour détecter une machine mal configurée ; comparez ce que vous
envoyez à ce que la console affiche.

Un jeton **de relais**, lui, n'a pas d'hôte lié : **l'hôte déclaré passe inchangé et n'est pas
attesté**. Le message affiché à sa création le dit en toutes lettres — quiconque tient ce jeton peut
écrire sous n'importe quel nom d'hôte. C'est le prix d'un forwarder, et c'est pourquoi un jeton de
relais est **refusé** sur le canal de réponse (§6).

### 3.3 Les rôles

| Rôle minimal | Routes |
|---|---|
| `Ingest` — satisfait par `editor` **ou** `agent`, **jamais** `viewer` | ingestion, métriques, HEC, traces |
| `Agent` — satisfait par `agent` **seul** | canal de réponse, engagements actifs |

Un jeton d'un autre genre (source de données, client, Firehose, Pub/Sub) **ne peut pas** s'authentifier
sur la surface d'agent : les genres sont cloisonnés dans la requête elle-même.

---

## 4. Le tampon disque, et ce qu'il garantit

### 4.1 Publier veut dire deux synchronisations, pas un renommage

La bibliothèque shell publie en quatre gestes, dans cet ordre : mettre les droits, **synchroniser le
contenu**, renommer, **synchroniser l'entrée de répertoire**. Le renommage seul donne l'atomicité du
*contenu* et rien d'autre : après une coupure, les octets peuvent exister sans que leur **nom**
existe — et l'expéditeur parcourt le spool **par nom**. Les deux synchronisations sont ce qui ferme
cette fenêtre ; leur coût est mesuré et écrit à côté du code.

L'agent Rust tient le même contrat par une **voie unique** de publication, et un test refuse tout
`rename(` écrit ailleurs dans la caisse. **Sa limite est écrite plutôt qu'affirmée** : sous Windows,
le répertoire n'est pas synchronisé, faute d'un geste équivalent dans la bibliothèque standard.

**Le central, lui, ne tient pas ce contrat sur ses propres écritures.** Ses récepteurs poussés écrivent
puis renomment sans synchroniser — c'est-à-dire exactement la forme que cette section décrit comme
insuffisante, mais du côté qui *reçoit*. Ce que l'accusé couvre alors, et ce qu'il ne couvre pas, est
en §2.5.

### 4.2 La borne du tampon — et son absence

| Famille | Borne | Politique quand c'est plein |
|---|---|---|
| agent Rust | `spool_cap`, défaut **10 000** entrées | éviction des **plus vieilles** |
| récepteur syslog | `PLUME_SYSLOG_SPOOL_MAX_BYTES` (défaut 512 Mio), `PLUME_SYSLOG_SPOOL_MAX_FILES` (défaut 20 000) ; `0` = illimité | le lot est **abandonné** |
| **collecteurs shell** | **aucune** | — |

**MESURÉ SUR L'ARBRE le 2026-08-25 : le spool de la famille shell n'a ni plafond de taille, ni
plafond de fichiers, ni éviction, ni purge.**

```sh
grep -nE 'SPOOL_MAX|MAX_FILES|MAX_BYTES' collectors/lib.sh collectors/ship.sh bootstrap-agent.sh   # rien
```

Ce n'est pas un défaut de recherche : les deux autres familles en ont une, ce qui rend l'absence
lisible. Le seul plafond du côté shell est **par passage de collecteur** (nombre de lignes lues en une
fois), pas sur le spool.

### 4.3 La conséquence à connaître : seul `202` acquitte

L'expéditeur shell supprime un fichier **si et seulement si** la réponse est `202`. Tout le reste est
« conservé pour réessai » — y compris un `204` (corps vide, ou lot entièrement filtré) et y compris
une **erreur permanente** comme `400` ou `413`. Ce `202` n'atteste que la **réception** : ce qu'il
laisse ouvert est en §2.5.

```sh
sed -n '/^ship_glob/,/^}/p' collectors/ship.sh
```

Combiné à l'absence de borne (§4.2), cela veut dire qu'**une erreur permanente fait croître le spool
sans fin**. Surveillez `PLUME_SPOOL` sur un agent shell, et lisez la sortie d'erreur de l'unité
d'expédition : elle nomme le fichier et le code.

L'agent Rust ne se comporte pas ainsi, et c'est délibéré : il acquitte sur tout `2xx`, réessaie sur
`429` et `5xx`, et **abandonne en le journalisant** sur un `4xx` définitif.

### 4.4 La déduplication est côté central, et elle est cloisonnée

`event.dedup` est unique, et l'insertion ignore les doublons. La clé est **cloisonnée par hôte** par
un encodage préfixé de longueur — deux machines qui produiraient la même clé ne s'effacent pas l'une
l'autre. **Une ligne sans `dedup` n'est jamais dédupliquée** : SQLite tient deux `NULL` pour
distincts.

C'est ce qui rend le rejeu absorbable, et le coût exact du rejeu **par capteur** est écrit dans
`collectors/lib.sh` : certains portent une clé d'identité de contenu (rejeu absorbé intégralement),
d'autres un seau de temps (absorbé dans le seau seulement).

---

## 5. Les filigranes : ce qui empêche de perdre ou de répéter

Un filigrane (`PLUME_STATE`, défaut `/var/lib/plume/state`) mémorise où un capteur en était. **Il
n'est jamais expédié.**

**La règle tient par construction, pas par discipline : un capteur n'a pas les deux gestes à sa
disposition.** Il peut *mettre en attente* un filigrane, mais l'écriture n'a lieu que dans les
fonctions qui publient d'abord. L'ordre est donc toujours : **publier, puis acquitter le filigrane.**
Deux gardes de CI le tiennent (`check_watermark_follows_publication.py`,
`check_publication_is_durable.py`).

L'écriture du filigrane est **délibérément non durable**, et le code interdit explicitement d'y
« corriger » l'absence de synchronisation : un filigrane perdu coûte un rejeu, que la déduplication
absorbe ; un filigrane qui survivrait aux événements les ferait disparaître **définitivement**.

Le même ordre est tenu par les trois familles. Côté Windows, le filigrane est en plus **borné au
présent** dans les deux sens, après un cas mesuré d'horloge en avance qui avait rendu trois sources
aveugles de façon irrécupérable.

---

## 6. Le canal retour : réclamer une action

Le central ne pousse rien vers un agent. C'est l'agent qui **tire**.

```
GET  /api/actions/pending    -> réclame ; réponse en TSV : id \t kind \t target \t dry_run
POST /api/actions/result     -> rend compte : {"id":…, "status":"done|dryrun|failed", "result":"…"}
```

| Propriété | Détail |
|---|---|
| **rôle** | `agent` **et** jeton lié à un hôte — un jeton de relais est refusé en `403` |
| **l'hôte vient du jeton** | jamais d'un paramètre de requête ; le paramètre `?host=` qu'envoie le collecteur shell est **ignoré** par le démon — c'est ce qui ferme la porte à la réclamation de l'action d'autrui |
| **vocabulaire réclamable** | `ban_ip` et `unban_ip` **seuls** ; `kill_pid` et `stop_service` ne se réclament pas par ce canal |
| **remise en jeu** | une action réclamée sans résultat est re-remise après quelques minutes |
| **clôture** | ne porte que sur une action *approuvée* **et** assignée au même hôte ; idempotente |
| **format** | TSV, pas JSON — pour que la boucle shell le lise sans dépendance |

En amont, la chaîne est : création → **approbation par un administrateur** → réclamation → résultat.
Côté agent, le moteur est **coupé par défaut** (`PLUME_RESPONDER=0`) et, une fois allumé, il est en
**simulation** tant que `PLUME_RESPONDER_APPLY=1` n'est pas posé. Chaque résultat entre au journal
d'audit.

> ⚠️ Le fichier d'allowlist du responder porte **deux significations incompatibles** selon
> l'installateur qui l'a semé. Voir l'avertissement du [`README`](../README.md#configuration--les-variables-plume_)
> et les clés `P4.7-a`, `P4.7-b` et `P4.7-c` de [`ROADMAP.md`](ROADMAP.md).
> **Les deux lecteurs n'ont pas le même critère d'adresse** (`P4.7-b`) : ce qui est tenu — et mesuré
> sur les deux — est que le démon en reconnaît **strictement plus** de formes que l'agent, donc
> qu'aucune ligne n'est acceptée en silence par les deux. Ce n'est **pas** l'égalité, et le rejet de
> chaque lecteur n'est **pas** dérivé du prédicat qui décide ce qu'on sait bannir.
> **Et la liste d'épargne ne vaut que côté agent** (`P4.7-c`, ouverte) : le responder du central ne
> la consulte pas.

---

## 7. TLS et mTLS

| Famille | Comment on le pose | Si c'est absent |
|---|---|---|
| collecteurs shell | `PLUME_TLS_CACERT`, `PLUME_TLS_CERT`, `PLUME_TLS_KEY` — concaténés en options du client HTTP | magasin de confiance du système, **aucun certificat client, aucun avertissement** |
| agent Rust | des clés **TOML**, pas des variables : `[tls] ca_cert / client_cert / client_key / insecure` | racines publiques seules, aucun certificat client, aucune erreur |
| collecteur Windows | `PLUME_TLS_INSECURE=1` pour un central auto-signé de test | vérification normale |

**Il n'existe aucun mode « mTLS obligatoire » côté agent.** L'exigence ne peut être posée que **côté
central**, par le point d'entrée qui expose la route d'ingestion. Un agent sans certificat client ne
s'en plaindra pas.

**Collision de noms à connaître** : `PLUME_TLS_CERT` et `PLUME_TLS_KEY` désignent le certificat
**serveur** côté démon et le certificat **client** côté agent. Même nom, deux rôles opposés.

Ce qui se passe quand la chaîne ne se vérifie pas est **mesuré et publié** dans
[`../agent/README.md`](../agent/README.md), cas par cas — y compris le cas contre-intuitif d'un
certificat **de CA** servi comme certificat serveur, qui reste refusé quoi que l'agent déclare, et
dont le remède est de corriger le **central**. Le remède affiché est dérivé du **type** de l'erreur
de vérification, pas de son texte.

---

## 8. Pourquoi c'est ainsi

**Le contrat de fil est mince pour qu'on puisse en écrire un émetteur en trente lignes de shell.**
C'est la raison d'être du produit : brancher une source sans rebuild et sans SDK. Le prix est celui
décrit en §2.2 — la validation est tardive, et un `202` ne prouve pas qu'un événement était bien
formé.

**Le tampon est côté émetteur, pas côté central.** Un central qui refuse (garde disque, limitation de
débit) rend un code qui invite au réessai ; c'est l'agent qui garde les octets. Cela déplace le risque
de saturation vers l'agent — d'où l'importance de §4.2. Et cela a un second prix, moins visible :
l'instant où le central acquitte est l'instant où la **seule autre copie** disparaît, alors que la
sienne n'est pas encore durable (§2.5).

**L'hôte est attesté par le jeton, pas par l'émetteur.** Un inventaire dont les noms d'hôte sont
déclarés par la machine elle-même n'est pas un inventaire. La liaison réécrit plutôt que de refuser
parce qu'un refus ferait perdre les événements d'une machine mal configurée — mais cela se paie par le
silence décrit en §3.2.

**On publie avant d'acquitter, toujours.** C'est la seule invariance qui permet de promettre « au
moins une fois » sans jamais promettre « exactement une fois ». La déduplication côté central
transforme le rejeu en coût, pas en faux.

---

## 9. Ce qui n'a pas été vérifié

- **Aucun agent n'a été enrôlé, et aucun événement n'a été envoyé dans ce lot.** Tout ce qui précède
  est établi par lecture des sources ; les codes, les défauts et les comportements cités sont ceux
  que le code écrit, pas ceux d'une session observée.
- La ligne d'événement stockée est construite dans une **caisse externe** au dépôt (`guatx-core`,
  résolue par étiquette git) : ses champs ne sont observables ici que par la façon dont ils sont
  remplis.
- **Ce qui est réellement exercé par l'intégration continue** de l'agent, et ce qui n'est que compilé,
  est écrit sans fard dans [`../agent/CI.md`](../agent/CI.md) — notamment que **l'installation du
  service n'est exercée sur aucun système d'exploitation**. Lisez-le avant de traiter la
  compilation comme une preuve.
