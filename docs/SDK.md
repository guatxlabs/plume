# Plume SDK — le modèle *bring-your-own-vendor*

> **Statut : document ombrelle.** Il ne définit PAS un nouveau mécanisme : il rend **cohérents et
> découvrables** les *seams* d'extension qui existent déjà. Chaque seam a sa page de référence détaillée
> (liens ci-dessous) ; ici on donne **l'unique modèle mental**, la règle de décision, et un exemple concret
> par seam. **Aucun comportement runtime n'est modifié par ce document.**

Le SDK de Plume, ce sont **les seams**, pas une bibliothèque à lier. La promesse produit est celle de la
directive *vendor-agnostic / sur-ensemble* (mémoire projet) : **zéro vendeur codé en dur**, et **ajouter un
vendeur ne doit jamais exiger de toucher au cœur** (`guatx-core`) ni, dans le cas nominal, de **recompiler**.

---

## 0. Le pivot — le contrat CIM (`core::cim`)

Tout part du **CIM** (Common Information Model, [`docs/CIM.md`](CIM.md), miroir machine
[`config.d/cim/cim.v1.json`](../config.d/cim/cim.v1.json)). C'est le **vocabulaire neutre** sur lequel toute
la chaîne compose. Deux champs portent toute la charge de l'agnosticisme vendeur :

| champ | rôle | exemple |
|---|---|---|
| `source` | identité du **PRODUCTEUR / vendeur** — **jamais** la sémantique | `fortigate`, `defender`, `suricata` |
| `category` | **sémantique INTER-vendeur** — le contrat sur lequel les règles composent | `firewall`, `malware`, `ids`, `web`, `auth` |

> **Règle d'or.** Une détection filtre sur `category` (`search category=firewall action=blocked …`),
> **jamais** sur un `source` vendeur particulier. Conséquence : une règle écrite une fois marche pour
> **tout** vendeur qui *mappe* sa `category` — c'est ça, le sur-ensemble. Le rôle de chaque seam ci-dessous
> est **exactement** de traduire un dialecte vendeur vers cette ligne canonique (`EventRow`), en
> **ENRICHISSANT jamais en supprimant** (une `category` hors-taxonomie est acceptée telle quelle + signalée,
> jamais rejetée — cf. CIM §0).

---

## 1. Les seams en un coup d'œil

Trois **idiomes** seulement, par ordre de préférence :

1. **Overlay déclaratif** (config, *aucun rebuild*) — le cas nominal. Un fichier JSON/YAML posé dans
   `config.d/`, ou une `config` de connecteur. C'est le chemin par défaut pour 90 % des vendeurs.
2. **Adaptateur hors-process** (config + processus tiers) — pour *agir* sur des systèmes externes
   (enforcers réseau, IdP) sans coupler leur code au daemon.
3. **Trait Rust compilé** (*rebuild*) — réservé aux formats que le déclaratif ne peut pas exprimer
   (binaire/positionnel haut débit). Contrat minimal, un point d'enregistrement unique.

| Seam | Ce qu'on ajoute | Idiome | Emplacement / point d'enregistrement | Rebuild ? | Référence |
|---|---|---|---|:--:|---|
| **Parser** (log vendeur → `EventRow`) | extraction de champs | overlay déclaratif (DSL) | `config.d/parsers/*.json` → tables `parser`/`dparser` | **non** | [PARSER-DSL.md](PARSER-DSL.md) |
| **Parser** haut débit | dialecte binaire/positionnel | trait compilé | `collector-syslog` : `impl VendorParser` + `parser::select()` | oui | code |
| **Source pull** (API REST/JSON) | une source d'events | descripteur connecteur | `POST /api/connectors` type `http_pull`, champ `config` | **non** | [connector-presets](connector-presets/README.md) |
| **Source push** (SIEM/agent) | flux entrant | endpoint HTTP | `POST /services/collector` (HEC), `/api/ingest*` | **non** | code (`server/groupes_de_routes.rs`) |
| **Détection** | règle | overlay déclaratif | `config.d/rules/*.json` (GXQL) + `config.d/sigma/*.yml` | **non** | [SIGMA-IMPORTER.md](SIGMA-IMPORTER.md) |
| **Threat-intel** | flux d'IOC | descripteur connecteur / import | connecteur `taxii2`, `POST /api/threat-intel/import` (STIX 2.1) | **non** | `core::ti` |
| **Réponse / enforcer** | exécuteur d'action | adaptateur hors-process | `PLUME_BAN_BACKEND` (nft/fail2ban/…), engagement `adapter` | **non** | code (`actions.rs`) |
| **Dimensions de rollup** | pré-agrégat requêtable | variable d'env | `PLUME_ROLLUP_DIMS` | **non** | [config.d/README](../config.d/README.md) |

Point d'entrée commun des overlays `config.d/` : `load_overlays` (au boot, après migrations/seeds) fait un
**UPSERT keyé par `name`**, posé `managed=1`. Idempotent et durable (survit au re-seed des builtins). Le
chemin est `PLUME_CONFIG_DIR` (défaut baké dans l'image), donc l'overlay est **agnostique au runtime**
(k3s ConfigMap / bind-mount docker / répertoire hôte).

---

## 2. Ajouter un **parser** de vendeur (sans toucher au cœur)

**Cas nominal — overlay déclaratif (aucun rebuild).** On dépose un fichier dans `config.d/parsers/`. Un
parser regex nommé, ou un parser DSL déclaratif (voir [PARSER-DSL.md](PARSER-DSL.md)) qui **mappe vers la
`category` CIM**. Exemple (extraction + mapping firewall) :

```json
{
  "name": "acme-fw — connexions bloquées",
  "source": "acme-fw",
  "pattern": "src=(?P<src_ip>\\S+) dst=(?P<dst_ip>\\S+) act=(?P<action>\\w+)",
  "enabled": true
}
```

> Registration : le fichier est chargé au boot par `load_overlays`, UPSERT sur `name`, `managed=1`.
> **Garantie no-rebuild** : rien à recompiler ni redéployer d'image — un `git commit` dans `config.d/` (ou
> une ConfigMap) suffit ; un CRUD UI (`managed=2`) fait la même chose à chaud. Un fichier invalide est
> **ignoré avec un warning**, jamais un crash de boot.

**Cas haut débit — trait compilé (rebuild).** Pour un dialecte binaire/positionnel où le regex/DSL ne
suffit pas (ex. syslog structuré Fortinet), le collecteur syslog expose un trait :

```rust
// collector-syslog/src/parser.rs
pub trait VendorParser: Send + Sync {
    fn name(&self) -> &'static str;
    fn parse(&self, frame: &SyslogFrame, source: &str, host: &str, default_ts: i64) -> Value;
}
```

> Registration : `impl VendorParser for MonVendeur` puis **une ligne** dans `parser::select()` (sélection
> par `PLUME_SYSLOG_PARSER`). C'est tout. Contrat : `source`=vendeur, `category`=sémantique CIM, `src_ip`/
> `dst_ip` en top-level, le reste dans `fields` ; **ne panique jamais** (ligne malformée → event de repli).

---

## 3. Ajouter une **source** (faire entrer les events)

**Pull — descripteur `http_pull` (aucun rebuild).** N'importe quelle API REST/JSON devient une source **par
configuration seule** : URL, auth, pagination, watermark, et un `field_map` qui projette la réponse vendeur
vers les champs `EventRow`/`fields`. Exemple (squelette) :

```json
{
  "url": "https://api.acme.example/v1/alerts",
  "records_path": "data.items",
  "auth":  { "kind": "oauth2_client_credentials", "token_url": "https://api.acme.example/oauth/token", "client_id": "…" },
  "pagination": { "kind": "cursor", "cursor_path": "meta.next" },
  "watermark":  { "field_path": "created_at", "param": "since", "format": "iso8601" },
  "sourcetype_map": { "acme.alert": "malware" },
  "field_map": { "ts": "created_at", "src_ip": "network.src", "message": "title", "category": "=malware" }
}
```

> Registration : `POST /api/connectors` (type `http_pull`), coller la `config`, le **credential dans le
> champ `secret`** (jamais dans `config`), **Tester** (`/api/connectors/:id/test` — 1 page, n'ingère pas,
> renvoie un échantillon mappé), puis activer. Le poll périodique (`run_due_connectors` →
> `poll_one_connector` → `poll_http_pull`) ingère et avance le watermark.
> **Garantie no-rebuild** : ajouter un vendeur = écrire un JSON comme ceux de
> [`docs/connector-presets`](connector-presets/README.md) (Falcon, SentinelOne, REST générique sont de
> *pures docs*, pas du code par-vendeur). Les events pullés passent par **le même pipeline
> d'enrichissement** que le natif (parsers, extracteur générique, **match TI on-ingest**).

**Presets compilés (defender / taxii2).** Deux `ctype` ont un normaliseur dédié (`poll_defender`,
`poll_taxii`) parce que leur schéma (Graph Security, TAXII 2.1) est stable et vaut un adaptateur de première
classe — mais ils restent dispatchés par `ctype` dans `poll_one_connector`, sans rien coder « en dur » côté
détection (ils convergent sur `EventRow`/`Ioc`).

**Push — endpoints HTTP (aucun rebuild).** Un SIEM/agent externe pousse directement :
`POST /services/collector` (**HEC** — compatible Splunk), `/api/ingest`, `/api/ingest/journal`,
`/api/ingest/minio`. Tous convergent sur le même `EventRow` + `EVENT_INSERT_SQL` figé.

---

## 4. Ajouter une **détection** (règle)

Overlay déclaratif, aucun rebuild. Deux formats, **une** table `rule` :

- **GXQL natif** — `config.d/rules/*.json` : `{"name","query":"search category=firewall action=blocked | stats count","op":">","threshold":0,"mitre":"T1190",…}`.
- **Sigma** (standard ouvert) — `config.d/sigma/*.yml` : traduit en règle GXQL au boot (`load_overlay_sigma`),
  mapping `logsource → category` **via le CIM**. Un construit non exprimable en GXQL est **signalé + ignoré**
  (jamais une règle silencieusement fausse) — cf. matrice dans [SIGMA-IMPORTER.md](SIGMA-IMPORTER.md).

> Registration : `load_overlays`/`load_overlay_sigma`, UPSERT sur `name`, `managed=1` ; validation au boot
> (la `query` doit **compiler**). Import ponctuel hors-git : `plume-daemon sigma-import <path> [--dry-run]`
> ou `POST /api/sigma/import` (admin). **Écris la règle par `category`**, elle marchera pour tout vendeur.

---

## 5. Ajouter un **flux threat-intel**

Le parse/normalize STIX est **pur** dans `core::ti` (`stix_bundle_to_iocs`, `normalize_ioc`) — vendor-agnostic,
partagé. Trois entrées, aucune touchant le cœur :

- **TAXII 2.1** — un connecteur `ctype=taxii2` PULL périodiquement la collection, traduit les objets STIX en
  IOC (`taxii_upsert_iocs`).
- **Import STIX ponctuel** — `POST /api/threat-intel/import` (bundle STIX 2.1) ; un pattern non supporté est
  *skippé-avec-raison*, jamais un IOC qui sous/sur-matche en silence.
- **Ajout manuel / bulk** — `POST /api/threat-intel/iocs`.

Les IOC alimentent le **match-on-ingest** (`ti_match_event`) : un `src_ip`/`dst_ip`/hash qui matche reçoit
`fields.threat_intel` + `ti_match=1` et contribue au risk-based alerting. (Le pré-filtre d'appartenance
`IocIndex` — #30 — passe ce match à l'échelle sans changer le contrat.)

---

## 6. Ajouter un **enforcer / une réponse** (agir vers l'extérieur)

Idiome **adaptateur hors-process** : Plume ne réimplémente pas les enforcers, il **délègue** à ceux qui
existent déjà chez le client, sélectionnés par configuration.

- **Backend de ban** — `PLUME_BAN_BACKEND` (`auto` par défaut) route `ban_ip`/`unban_ip` vers
  `fail2ban` / `nft` (fallback) / CrowdSec. Ajouter un enforcer = ajouter une branche de **commande**
  (l'action reste `ban_ip`, agnostique au backend) ; le vocabulaire d'action (`ban_ip | unban_ip |
  kill_pid | stop_service`) est le contrat stable (`action_kind_valid`).
- **Mode Engagement** — chaque engagement porte un champ **`adapter`** (l'IdP/enforcer hors-process qui
  applique le périmètre du pentest) : l'enforcement vit **hors du daemon**, le daemon ne fait que publier le
  scope compilé (`ENGAGEMENT_SCOPE`, byte-identique quand aucun engagement actif).

> **Garantie** : l'exécuteur est une **frontière de processus** (une `Command` / un adaptateur), pas un
> couplage de code. Un nouveau backend n'entre jamais dans le chemin chaud d'ingest.

---

## 7. Règle de décision (quel idiome ?)

```
Le vendeur expose-t-il ses données via un log texte ou une API REST/JSON ?
  ├─ oui, et regex/DSL suffit à extraire+mapper  → OVERLAY DÉCLARATIF (config.d ou http_pull)   [no rebuild]
  └─ non, format binaire/positionnel haut débit  → TRAIT COMPILÉ (VendorParser + select())      [rebuild]

Faut-il AGIR sur un système externe (bloquer, révoquer, isoler) ?
  → ADAPTATEUR HORS-PROCESS (backend d'action / engagement adapter)                             [no rebuild]

Faut-il une sémantique nouvelle non couverte par la taxonomie CIM ?
  → proposer une évolution du CONTRAT CIM (docs/CIM.md, SemVer) — c'est le SEUL cas « cœur »
```

**Le fil rouge** : le cœur (`guatx-core`) porte le *contrat* (CIM, GXQL, TI pur) ; les seams portent la
*traduction* de chaque vendeur vers ce contrat. Tant qu'un vendeur peut être **décrit** (parser/connecteur/
règle par `category`) plutôt que **codé**, l'ajout est un fichier de config, pas un rebuild — et Plume reste
un **sur-ensemble** de l'existant client, jamais une perte de capacité.
