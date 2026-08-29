# OTLP Traces — récepteur OpenTelemetry (#41)

> **Statut : additif, INERTE par défaut.** Plume peut ingérer des **traces distribuées**
> OpenTelemetry via le protocole **standard OTLP/HTTP**. Chaque `span` devient une ligne CIM
> (`category=trace`), requêtable en GXQL et **corrélable aux logs par `trace_id`**. Le récepteur
> est **OFF** tant que `PLUME_OTLP_TRACES=1` n'est pas posé (mode 0 byte-identique).

C'est le choix **vendor-agnostic / souverain** : n'importe quel SDK OpenTelemetry ou OTel
Collector existant exporte vers Plume **sans nouvel agent** et **sans lock-in vendeur**.

---

## 1. Endpoint

```
POST /v1/traces
Content-Type: application/json          # OTLP/JSON (ExportTraceServiceRequest)
Content-Encoding: gzip                  # optionnel (décompression bornée, anti-bombe)
Authorization: Bearer <token-agent>     # OBLIGATOIRE (ingest authentifié)
```

- **Signal** : `traces` uniquement. `metrics`/`logs` OTLP → différés (voir §7).
- **Encodage** : **JSON** (`application/json`). Le **protobuf binaire** OTLP → différé (415 renvoyé) ;
  JSON couvre les SDK/collectors qui savent parler OTLP/JSON. Configurer l'exporteur en
  `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL=http/json`.
- **Réponse** : `200` + `ExportTraceServiceResponse` (`{}` = zéro rejet ; `{"partialSuccess":…}`
  si des spans ont dépassé le plafond par requête). Ce `200` atteste la **réception**, pas la
  **durabilité** — §6.

### Activation

```bash
# daemon (env ou PLUME_CONFIG)
PLUME_OTLP_TRACES=1
```

Sans ce drapeau, `/v1/traces` renvoie `404` (surface absente) — **aucun** changement de
comportement au repos.

### Auth (ingest authentifié, jamais une surface ouverte)

`/v1/traces` est un chemin d'**INGEST machine** (`agent_bearer_path` + `route_min_role = Ingest`),
exactement comme `/api/ingest`, HEC ou Loki push. Un `Authorization: Bearer <token>` résout une
identité `agent` **host-bound, ingest-only** (jamais UI/admin). Provisionner un token agent :

```
POST /api/tokens   { "name": "otel-collector", "kind": "agent" }   # admin-only
```

Un token `datasource`/`client` (lecture) **ne peut pas** s'authentifier ici (seam disjoint).

### Pointer un OTel Collector vers Plume

```yaml
# otel-collector-config.yaml
exporters:
  otlphttp/plume:
    traces_endpoint: https://plume.example.com/v1/traces
    encoding: json
    compression: gzip           # ou "none"
    headers:
      Authorization: "Bearer ${PLUME_AGENT_TOKEN}"
service:
  pipelines:
    traces:
      exporters: [otlphttp/plume]
```

SDK direct (variables d'env standard) :

```bash
export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://plume.example.com/v1/traces
export OTEL_EXPORTER_OTLP_TRACES_PROTOCOL=http/json
export OTEL_EXPORTER_OTLP_TRACES_HEADERS="Authorization=Bearer ${PLUME_AGENT_TOKEN}"
```

---

## 2. Mapping span → CIM

Un `span` OTLP (`resourceSpans[] → scopeSpans[] → spans[]`) est mappé sur la **ligne canonique
`EventRow`** et ingéré par le **même** chemin que tout autre event (`ingest_events_batch`, via le
spool) → **masquage (#45), rollups et détection s'appliquent uniformément** (une trace n'est
qu'un event).

| Champ CIM (colonne) | Source OTLP |
|---------------------|-------------|
| `category`          | **`trace`** (fixe) |
| `ts`                | `span.startTimeUnixNano` / 1e9 (epoch secondes) |
| `source`            | resource `service.name` (défaut `otlp`) — namespace `plume-*` réservé |
| `severity`          | `status.code == ERROR` → `3` (error) ; sinon `0` |
| `message`           | `span.name` (l'opération) |
| `host`              | resource `host.name` \| `k8s.node.name` \| `host.id` \| `container.name` |
| `dedup`             | `otel-<trace_id>-<span_id>` (idempotent : ré-export = pas de doublon) |

### Champs de trace de première classe (dans `fields`, searchable)

| `fields.*` | Sens |
|------------|------|
| `trace_id`        | ID de trace (hex minuscule) — **la clé de corrélation** |
| `span_id`         | ID du span (hex) |
| `parent_span_id`  | span parent (absent = span racine) |
| `span_name`       | nom de l'opération |
| `span_kind`       | `server` \| `client` \| `producer` \| `consumer` \| `internal` \| `unspecified` |
| `trace_status`    | `ok` \| `error` \| `unset` |
| `status_message`  | message de statut (si erreur) |
| `service`         | `service.name` |
| `scope_name` / `scope_version` | instrumentation scope |
| `duration_ms`     | `(end - start)` en millisecondes (latence) |
| `otel.<attr>`     | attributs span **et** resource aplatis, préfixe `otel.` (ex. `otel.http.method`) |

Les `AnyValue` OTLP (`stringValue`/`intValue`/`doubleValue`/`boolValue`/`arrayValue`/`kvlistValue`)
sont convertis en JSON scalaire/structuré ; `intValue` (string proto3-JSON) → nombre.

---

## 3. Corrélation logs ↔ traces par `trace_id`

L'intérêt SOC : **joindre une trace applicative aux logs de sécurité** qui portent le même
`trace_id`. Toute source de logs qui émet `trace_id` (via un parser, un attribut Loki, un champ
HEC…) atterrit dans `fields.trace_id` — **le même champ** que les spans. Une requête corrèle donc
les deux surfaces :

```sql
-- tous les events (spans + logs) d'une trace, ordre chronologique
search trace_id=5b8efff798038103d269b633813fc60c | sort ts

-- spans en erreur d'un service, puis pivot sur leur trace_id
search category=trace trace_status=error service=checkout
```

---

## 4. GXQL / requêtes d'exemple

Les traces étant des events `category=trace`, elles sont immédiatement requêtables :

```sql
-- opérations les plus lentes (P… par tri sur la durée)
search category=trace | sort duration_ms desc | head 20

-- taux d'erreur par service
search category=trace | stats count, count(eval(trace_status="error")) by service

-- volume de spans par kind
search category=trace | stats count by span_kind
```

> Panneaux natifs (slowest-ops, error-rate-by-service, trace-explorer groupé par `trace_id`) :
> **différés** en follow-up UI. Les requêtes GXQL ci-dessus couvrent l'usage dès aujourd'hui et
> peuvent être sauvegardées comme recherches/panneaux ad-hoc.

---

## 5. Garde-fous DoS (le décodeur = nouvelle surface d'attaque externe)

Le corps `/v1/traces` est **attaquant-contrôlé**. Bornes dures :

| Garde-fou | Valeur | Effet au-delà |
|-----------|--------|---------------|
| Taille du corps HTTP | `8 Mio` (DefaultBodyLimit global) | rejet en amont |
| Décompression gzip (OTLP) | `OTLP_MAX_DECOMPRESS = 16 Mio` (env `PLUME_OTLP_MAX_DECOMPRESS`) | `413` (anti-bombe, borné **avant** allocation) |
| Forme OTLP (pré-parse) | objet racine `{` + clé `"resourceSpans"` (scan O(n)) | `400` **avant** le parse complet (tue le JSON non-OTLP qui gonfle jusqu'au cap) |
| Concurrence d'ingest | `PLUME_OTLP_INGEST_CONCURRENCY = 4` permits (sémaphore `ingest_sem`, séparé de l'interactif) | `503` si saturé (le client OTLP rejoue) — borne le pic mémoire à N arbres `Value` |
| Spans / requête | `min(OTLP_MAX_SPANS=50 000, PLUME_INGEST_MAX_EVENTS)` | `413` (jamais de troncature muette) |
| Attributs / span | `OTLP_MAX_ATTRS_PER_SPAN = 256` | attributs excédentaires ignorés (anti-cardinalité) |
| Profondeur de valeur | `OTLP_MAX_VALUE_DEPTH = 6` | valeur imbriquée → `Null` (serde borne déjà le parse à 128) |

Le cap de décompression OTLP (**16 Mio**) est volontairement PLUS PETIT que le cap partagé metrics/loki
(`INGEST_MAX_DECOMPRESS = 64 Mio`) : OTLP/JSON n'amortit pas le coût par un decode protobuf structuré —
`serde_json::from_slice` matérialise l'arbre `Value` **entier** (plusieurs× la taille texte) avant que les
caps span/attr ne s'appliquent. Défense en couches : (1) cap 16 Mio, (2) vérif de forme pré-parse, (3)
borne de concurrence. Résidu assumé : au plus `PLUME_OTLP_INGEST_CONCURRENCY` arbres `Value` (≤16 Mio de
texte source chacun) matérialisés simultanément.

JSON malformé → `400` **sans panic**. Aucun SQL n'est construit à partir de la donnée de span :
attributs et noms traversent le **même** chemin CIM→event→GXQL **masqué** que tout champ ingéré.

---

## 6. Chemin d'ingestion (identique aux autres récepteurs)

`POST /v1/traces` → décode JSON (+gzip) → mappe chaque span → écrit une enveloppe `{kind:"events"}`
dans le **spool** (atomique, `0600`) → la boucle de fond appelle `ingest_events_batch`. **Aucun**
travail DB sur le worker tokio (une rafale ne sature pas le runtime). Pas de host-marker : un
collector OTel relaie légitimement plusieurs services/hôtes (host autoritatif = attribut resource).

**« Atomique » n'est pas « durable » — et depuis `S31` (temps 2), le `200` couvre les deux.**
L'enveloppe est écrite, **synchronisée**, renommée, puis son **répertoire** est synchronisé, le tout
**avant** que le `200` ne parte. L'exporteur OTel qui vide sa file sur cet accusé ne perd donc plus la
fenêtre qui existait ici : les octets et leur entrée de répertoire sont l'un et l'autre passés par une
barrière. L'écriture est **déportée** sur un fil bloquant — la barrière ne bloque aucun worker tokio,
ce qui reste vrai de tout ce paragraphe.

Le corps de la réponse ne le dit toujours pas, et ne le dira pas : un décodeur protobuf-JSON strict
refuse les champs inconnus d'un `ExportTraceServiceResponse`. Le témoin est donc dans `/metrics` —
`plume_spool_barriere_fichier_total` et `plume_spool_barriere_repertoire_total` montent ensemble à
chaque export accepté, `plume_spool_barriere_echec_total` dit qu'une barrière a été refusée. Un
exploitant peut désarmer la barrière (`PLUME_INGEST_FSYNC=0`) ; le régime d'avant `S31` revient alors
tel quel, et les compteurs cessent de monter.

**Ce qui n'est pas prouvé :** la survie à une coupure d'alimentation réelle. Ce qui est démontré est
que les deux barrières sont demandées au noyau, rendues sans erreur, et dans cet ordre. Le régime de
la **base** (`/api/metrics/prom`, `/api/metrics/write`, `/loki/api/v1/push`) reste, lui, **ouvert** —
voir [`AGENTS-PROTOCOLE.md`](AGENTS-PROTOCOLE.md) (§2.5) et la clé `S31` de
[`ROADMAP.md`](ROADMAP.md).

---

## 7. Différé (non-goals de cette itération)

- **OTLP/gRPC** (`OTLP/gRPC`, port 4317) — seul **OTLP/HTTP** (`/v1/traces`, 4318-style) est servi.
  gRPC exigerait tonic/h2 sur un port séparé ; l'exporteur OTLP standard sait parler HTTP.
- **Protobuf binaire** OTLP — JSON only (`application/x-protobuf` → `415`).
- **Signaux `metrics` et `logs` OTLP** (`/v1/metrics`, `/v1/logs`) — Plume a déjà des récepteurs
  Prometheus remote_write et Loki push (cf. `ingest/obs.rs`) ; l'unification sous OTLP est un
  chantier ultérieur.
- **Panneaux natifs traces** (trace-explorer) — GXQL couvre l'usage ; UI en follow-up.
