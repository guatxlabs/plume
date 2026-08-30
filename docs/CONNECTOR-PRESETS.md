# Presets de connecteurs cloud (`http_pull`)

> **Statut : documentation + descriptors déclaratifs.** Un « preset » n'est **pas** du code
> vendeur : c'est un fichier JSON dans [`docs/connector-presets/`](connector-presets/) à **copier
> dans le champ `config`** d'un connecteur `http_pull` (aucun rebuild). Le connecteur générique
> `http_pull` (#20/#22) transforme n'importe quelle API REST/JSON en source d'events *par
> configuration seule* — voir [`docs/SDK.md`](SDK.md) et
> [`connector-presets/README.md`](connector-presets/README.md). Ce document décrit, **par vendeur** :
> l'API pullée, l'auth + les scopes, le `field_map` → CIM, et le **secret-ref** à poser.

## Principe (vendor-agnostic / sur-ensemble)

- **Zéro code par-vendeur.** Chaque preset est une `config` `http_pull` (URL, auth, pagination,
  `field_map`, watermark). Ajouter un vendeur = écrire un JSON comme ceux-ci — jamais une ligne de
  Rust. Un utilisateur peut toujours **bring-his-own** via un `http_pull` vierge.
- **Inerte par défaut (mode-0).** Aucun preset n'est actif tant qu'un **admin** ne crée pas un
  connecteur avec des credentials. Table `connector` vide ⇒ comportement **byte-identique**.
- **CIM en pivot.** Chaque `field_map` mappe les champs du vendeur vers le
  [CIM](CIM.md) (`ts, src_ip, dst_ip, url, host, severity, message` + `category` dérivée du
  `sourcetype` via `sourcetype_map`, et `fields.*` pour les dimensions étendues comme
  `user`/`action`).

## Sécurité (invariants, valables pour TOUS les presets)

| Invariant | Mécanisme |
|---|---|
| **Secrets = secret-ref, jamais en git** | Le credential (client_secret OAuth, jeton API…) va **exclusivement** dans le champ **`secret`** du connecteur (non renvoyé, non loggé). Les descriptors ne contiennent que des identifiants **non-secrets** (`client_id`, `token_url`, `scope`) — un test CI (`cloud_presets_parse_load_and_are_secret_free`) échoue si un descriptor contient `client_secret`/`api_key`/`password`/… |
| **SSRF-guard à l'égress** | L'URL sortante passe par `ssrf_guard(u)` au **point d'égress réel** (`fetch` de production, `connectors/mod.rs`) — pour le poll **et** le dry-run `Tester`. Les cibles internes (loopback / link-local metadata `169.254.169.254` / unspecified ; RFC1918 si `PLUME_SSRF_BLOCK_PRIVATE=1`) sont refusées. Un preset ne contourne **rien** : il emprunte le même choke-point. |
| **CRUD admin-gaté** | Créer / modifier / tester / poll un connecteur exige `is_admin()` (`forbidden` sinon). |
| **Créé désactivé** | Un connecteur est `enabled:false` à la création : l'admin **teste** (dry-run 1 page, n'ingère pas) avant d'activer. |
| **Extraction injection-safe** | Le `field_map` s'appuie sur un **sous-ensemble JSONPath sûr** (clé/index/`[*]`) — indexation pure, zéro eval. |

## Comment utiliser un preset

1. **Données → Connecteurs de sources** (ou `POST /api/connectors`, admin) → nouveau connecteur
   `http_pull`.
2. **Copiez le JSON du preset** dans le champ `config`, puis adaptez les `REPLACE_*` /
   `{placeholders}` (host régional, tenant, `client_id`, account_id…).
3. Mettez le **credential** dans le champ **`secret`** (jamais dans `config`).
4. **Tester** (`POST /api/connectors/{id}/test`) : 1 page, **n'ingère pas**, renvoie un échantillon
   des events **mappés** — vérifiez que le `field_map` produit le CIM attendu.
5. **Activez** quand la prévisualisation est correcte.

Les events pullés passent par le **même pipeline d'enrichissement** que l'ingest natif (parsers
déclaratifs, extracteur générique, **match-on-ingest threat-intel**).

---

## Matrice des presets

| Vendeur | Fichier | API | Auth | Pagination | CIM `category` | Statut |
|---|---|---|---|---|---|---|
| Okta | `okta.json` | System Log `GET /api/v1/logs` | `SSWS` header (secret) | `Link` RFC5988 | `auth` | **fit direct** |
| Entra ID sign-ins | `m365-entra-signin.json` | Graph `GET /v1.0/auditLogs/signIns` | OAuth2 client-creds | watermark asc. | `auth` | **fit direct** |
| Entra ID / M365 audit | `m365-entra-audit.json` | Graph `GET /v1.0/auditLogs/directoryAudits` | OAuth2 client-creds | watermark asc. | `audit` | **fit direct** |
| Google Workspace | `google-workspace.json` | Admin SDK Reports `activities` | Bearer (token court) | `nextPageToken` | `auth` | fit + **sidecar token** |
| Cloudflare (audit) | `cloudflare-audit.json` | `GET /client/v4/accounts/{id}/audit_logs` | Bearer API token | `page`/`per_page` | `audit` | **fit direct** |
| AWS CloudTrail | `aws-cloudtrail.json` | Records CloudTrail (S3/Firehose) | via gateway/push | selon livraison | `audit` | **field_map** + livraison |
| AWS GuardDuty | `aws-guardduty.json` | Findings (EventBridge/SigV4) | via gateway/push | selon livraison | `ids` | **field_map** + livraison |
| GCP Cloud Audit | `gcp-audit.json` | Logging `LogEntry` (Pub/Sub/gateway) | Bearer (token court) | `nextPageToken` | `audit` | **field_map** + livraison |
| CrowdStrike Falcon | `crowdstrike-falcon.json` | Alerts API v2 | OAuth2 client-creds | `offset`/`limit` | `malware` | fit direct (préexistant) |
| SentinelOne | `sentinelone.json` | Threats API v2.1 | `ApiToken` header | `cursor` | `malware` | fit direct (préexistant) |
| Générique | `generic-rest.json` | — | bearer | `page` | (au choix) | squelette |

> **« field_map + livraison »** = l'API native du vendeur exige une signature/flow que le puller
> générique ne fait pas (AWS **SigV4**, GCP **service-account JWT**). La pièce **durable et
> réutilisable** est le `field_map` → CIM ; les events arrivent via un mode de livraison adapté
> (S3-pull, Firehose/EventBridge → HEC, Pub/Sub → HEC, ou une passerelle signante). Voir chaque
> section.

---

## Okta — System Log API

- **API** : `GET https://{yourOktaDomain}/api/v1/logs?sortOrder=ASCENDING` — racine = tableau
  d'events (`records_path:""`).
- **Auth** : jeton API Okta **SSWS** → en-tête `Authorization: SSWS <token>` (`auth.kind=header`,
  `prefix:"SSWS "`). **Secret-ref** : le token dans le champ `secret`.
- **Pagination** : Okta renvoie un en-tête `Link` RFC5988 `rel="next"` → `pagination.kind=link_header`
  (natif). `size`→`limit` (max 1000).
- **Incrément** : `sortOrder=ASCENDING` + watermark sur `published` (`param:"since"`, ISO8601) —
  chaque tick reprend **après** le dernier `published` vu, **sans perte**.
- **field_map → CIM** : `uuid→id`, `published→ts`, `displayMessage→message`,
  `client.ipAddress→src_ip`, `actor.alternateId→fields.user`, `outcome.result→fields.action`,
  `eventType→fields.event_type`, geo → `fields.city/country`. `sourcetype=okta:system → category auth`.
- **Note sévérité** : `severity` Okta est en **MAJUSCULES** (`INFO/WARN/ERROR`), non reconnue par
  `sev_num` (défaut **0**). Affinez via un parseur déclaratif si un tri par sévérité est requis.

## Microsoft 365 / Entra ID — Microsoft Graph

Même patron **OAuth2 client-credentials** que le connecteur **Defender** (réutilisé, pas réinventé).

- **App Entra** : enregistrez une application, **permission d'application** `AuditLog.Read.All`
  (+`Directory.Read.All` pour les audits), consentement admin. `token_url` =
  `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`, `scope` =
  `https://graph.microsoft.com/.default`. **Secret-ref** : le *client secret* de l'app dans le champ
  `secret` ; `client_id`/`token_url`/`scope` restent dans `config` (non-secrets).
- **Sign-ins** (`m365-entra-signin.json`) : `GET /v1.0/auditLogs/signIns`, `records_path:"value"`,
  `category auth`. `field_map` : `createdDateTime→ts`, `userPrincipalName→fields.user`,
  `ipAddress→src_ip`, `appDisplayName→message`, `status.errorCode→fields.action`,
  `riskLevelDuringSignIn→severity` (low/medium/high reconnus), `location.*→fields.city/country`.
- **Directory audits** (`m365-entra-audit.json`) : `GET /v1.0/auditLogs/directoryAudits`,
  `category audit`. `activityDisplayName→message`, `initiatedBy.user.userPrincipalName→fields.user`,
  `result→fields.action`, `targetResources[0].*→fields.target`.
- **Pagination** : le lien de page suivante Graph est la clé `@odata.nextLink` (point **dans** la
  clé, non adressable par le JSONPath sûr). On **ne pagine pas** par nextLink mais par **watermark
  ascendant** : `?$orderby=createdDateTime` + `watermark.template:"createdDateTime gt {value}"`
  (param `$filter`) + `size→$top`. Chaque tick reprend chronologiquement, **sans perte**. Pour un
  backfill plus rapide : augmentez `$top` ou la fréquence de poll.

## Google Workspace — Admin SDK Reports

- **API** : `GET https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/{app}`
  (`app` = `login`|`admin`|`drive`|`token`|`saml`|`groups`…). `records_path:"items"`.
- **Scope** : `https://www.googleapis.com/auth/admin.reports.audit.readonly`.
- **Auth** : l'API exige un **access_token OAuth2** obtenu par un **compte de service** avec
  **délégation à l'échelle du domaine** (JWT-bearer RS256) — flow **non** réalisé par le puller
  générique. **Secret-ref** : posez un **access_token court (~1 h)** dans le champ `secret`
  (`auth.kind=bearer`) et **rafraîchissez-le via un sidecar** (workload-identity /
  `gcloud auth print-access-token` impersoné). → *statut : documenté, nécessite un sidecar de token.*
- **Pagination** : `nextPageToken` (query) → `pagination.kind=cursor` (`param:"pageToken"`,
  `cursor_path:"nextPageToken"`). Watermark `startTime` (RFC3339).
- **field_map → CIM** : `id.time→ts`, `id.uniqueQualifier→id`, `actor.email→fields.user`,
  `ipAddress→src_ip`, `events[0].name→message`, `id.applicationName→fields.application`.
  `sourcetype=gsuite:login → category auth` (utilisez `admin`→`audit`, `drive`→`data` selon l'app).

## Cloudflare — Audit Logs

- **API** : `GET https://api.cloudflare.com/client/v4/accounts/{account_id}/audit_logs?direction=asc`
  — `records_path:"result"`.
- **Auth** : **API token** Cloudflare avec la permission *Account Audit Logs: Read* → Bearer
  (`auth.kind=bearer`). **Secret-ref** : le token dans le champ `secret`.
- **Pagination** : `pagination.kind=page` (`param:"page"`, `size→per_page`). Watermark `when`
  (`param:"since"`, RFC3339).
- **field_map → CIM** : `id→id`, `when→ts`, `action.type→message`, `actor.email→fields.user`,
  `actor.ip→src_ip`, `action.result→fields.action`, `resource.type→fields.resource_type`.
  `sourcetype=cloudflare:audit → category audit`.
- **Requêtes HTTP (WAF/proxy)** : elles ne sont **pas** exposées par une API de pull paginée →
  utilisez **Logpush → R2 / endpoint HTTP** vers l'ingest **HEC** de Plume (source `cloudflare-http`,
  déjà présente, `category web`).

## AWS CloudTrail

- **Enjeu de livraison** : l'API native (`LookupEvents`) signe en **SigV4**, que le puller ne fait
  pas. Deux voies (même `field_map`) :
  1. **S3-pull** — CloudTrail dépose des `.json.gz` `{"Records":[...]}` dans un bucket S3 ; un
     forwarder/gateway les expose en HTTP (`records_path:"Records"`), ou le collecteur objet-store.
  2. **Push** — EventBridge / Kinesis **Firehose** → endpoint HTTP → **ingest HEC** de Plume
     (Firehose injecte un header `X-Amz-Firehose-Access-Key`, **secret-ref**).
- **field_map → CIM** (record CloudTrail) : `eventID→id`, `eventTime→ts`, `eventName→message`,
  `sourceIPAddress→src_ip`, `userIdentity.arn→fields.user`, `eventSource→fields.event_source`,
  `awsRegion→fields.aws_region`, `errorCode→fields.action`, `userAgent→fields.user_agent`.
  `sourcetype=cloudtrail → category audit` (S3 data-events → `data` via `sourcetype_map`).
- **Statut** : documenté ; le `field_map` est vérifiable hors-ligne, la **livraison** demande une
  passerelle/push (pas de creds live requis pour valider le mapping).

## AWS GuardDuty

- **Livraison** : `ListFindings`/`GetFindings` signent en SigV4. Voie recommandée : **EventBridge**
  (règle *GuardDuty Finding*) → Firehose / endpoint HTTP → **ingest HEC** ; le `detail` EventBridge
  **est** un finding GuardDuty (le `field_map` s'y applique). Sinon une passerelle signant SigV4.
- **field_map → CIM** : `Id→id`, `UpdatedAt→ts`, `Title→message`, `Type→fields.finding_type`,
  `Service.Action.NetworkConnectionAction.RemoteIpDetails.IpAddressV4→src_ip` (varie selon
  `ActionType`), `Region/AccountId→fields.*`. `sourcetype=guardduty → category ids`.
- **Note sévérité** : GuardDuty note **1.0–8.9** ; le puller borne **0..4** (High 7–8.9→4,
  Medium 4–6.9→4, Low 1–3.9→1–3). Approximation acceptable, affinable via parseur déclaratif.
- **Statut** : documenté ; mapping vérifiable hors-ligne, livraison via push.

## GCP Cloud Audit Logs

- **Livraison** : l'API Logging `entries:list` est en **POST** avec `pageToken` **dans le corps** et
  exige un access_token de **compte de service (JWT-bearer RS256)** — mal adaptée au puller GET/param.
  Voies :
  1. **Push** — log sink → **Pub/Sub** → abonnement push → endpoint HTTP → **ingest HEC** (le message
     Pub/Sub encapsule la `LogEntry`).
  2. **Pull best-effort** — un sidecar dépose un **access_token court** (scope `logging.read`) dans le
     champ `secret` (`auth.kind=bearer`), derrière une passerelle GET paginée
     (`records_path:"entries"`, cursor `nextPageToken`).
- **field_map → CIM** (`LogEntry`/`protoPayload` AuditLog) : `insertId→id`, `timestamp→ts`,
  `protoPayload.methodName→message`, `protoPayload.authenticationInfo.principalEmail→fields.user`,
  `protoPayload.requestMetadata.callerIp→src_ip`, `protoPayload.serviceName→fields.service`,
  `resource.type→fields.resource_type`, `protoPayload.status.code→fields.action`.
  `sourcetype=gcp:audit → category audit` (Data Access logs → `data`).
- **Note sévérité** : `severity` GCP est en **MAJUSCULES** (`INFO/WARNING/ERROR`…) → non normalisée
  (défaut 0). **Statut** : documenté, nécessite sidecar de token / push.

## CrowdStrike Falcon & SentinelOne (préexistants)

Voir [`connector-presets/crowdstrike-falcon.json`](connector-presets/crowdstrike-falcon.json)
(OAuth2 client-creds, Alerts API v2, `category malware`) et
[`connector-presets/sentinelone.json`](connector-presets/sentinelone.json) (`ApiToken` header,
Threats API v2.1, cursor, `category malware`). Mêmes invariants secret-ref / SSRF / admin-gate.

---

## Tests

- `cloud_presets_parse_load_and_are_secret_free` — tous les descriptors PARSENT via
  `HttpPullCfg::from_json`, `field_map` non vide, `sourcetype_map` → categories CIM valides, **aucun
  secret en clair**.
- `okta_preset_normalizes_sample_payload_to_cim` — le preset Okta **réel** normalise une charge
  System-Log en event CIM (`category auth`, `src_ip`/`user`/`action` mappés, dedup idempotent).

(Module `daemon/src/tests/connectors.rs`.)
