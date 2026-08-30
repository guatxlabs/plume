# Presets de connecteurs `http_pull` (exemples de config, PAS du code vendeur)

Ces fichiers sont des **exemples de configuration documentés** — des points de départ à
**copier/adapter**, pas des intégrations embarquées ni maintenues dans le daemon.

Principe (directive *vendor-agnostic / sur-ensemble*) : Plume **ne code AUCUN vendeur en dur**.
Le connecteur générique `http_pull` (#20/#22) transforme n'importe quelle API REST/JSON en source
d'events *par configuration seule*. Ces presets ne font que **démontrer** la forme d'une `config`
`http_pull` pour des API réelles (auth, pagination, `field_map`, watermark) — CrowdStrike Falcon,
SentinelOne, un REST générique. Il n'y a **pas une ligne de code par-vendeur** derrière eux ; ce
sont de la documentation. Ajouter un nouveau vendeur = écrire un JSON comme ceux-ci, sans rebuild.

## Utilisation

1. Créez un connecteur de type `http_pull` dans l'UI (Données → Connecteurs de sources) ou via
   `POST /api/connectors` (admin).
2. **Copiez le contenu d'un preset dans le champ `config`** du connecteur, puis **adaptez-le** :
   URL/host régional, `client_id`, chemins `field_map` (selon le schéma réel de VOTRE tenant/API),
   pagination, watermark.
3. Mettez le **credential** (client_secret OAuth, jeton API…) dans le champ **`secret`** du
   connecteur — **JAMAIS dans `config`**. Le `secret` n'est jamais renvoyé ni journalisé.
4. Utilisez le bouton **Tester** (`POST /api/connectors/{id}/test`) : il fait 1 page, **n'ingère
   pas**, et renvoie un ÉCHANTILLON des events mappés pour vérifier que le `field_map` produit ce que
   vous attendez.
5. Activez le connecteur quand la prévisualisation est correcte (créé **désactivé** par défaut).

Les champs `_comment` sont ignorés par le parseur de config (`HttpPullCfg::from_json`) ; ils ne
servent qu'à documenter le preset.

## Enrichissement à l'ingestion

Depuis #1, les events **pullés** passent par le **même pipeline d'enrichissement** qu'un event
ingéré nativement : parsers déclaratifs, extracteur générique, et **match-on-ingest threat-intel**
(un `src_ip`/`dst_ip`/hash qui matche un IOC connu reçoit `fields.threat_intel` + `ti_match=1`, et
contribue au risk-based alerting). Aucune config supplémentaire nécessaire.

## Référence des champs de `config` (`HttpPullCfg`)

| Champ | Rôle |
|---|---|
| `method` | `GET` (défaut) ou `POST`. |
| `url` **ou** `api_root`+`path` | URL complète, ou racine + chemin recomposés. |
| `body` | Corps statique optionnel (POST). |
| `records_path` | JSONPath (sous-ensemble sûr) du tableau d'enregistrements dans la réponse (`""` = la racine est le tableau). |
| `source` | Libellé `source` par défaut (sinon `http:{id}`). |
| `sourcetype` / `sourcetype_map` | `sourcetype` constant + table `sourcetype -> catégorie CIM` inline (bring-your-own CIM, sans rebuild). |
| `field_map` | Objet `champ_event: <JSONPath \| "=const">`. Clés `fields.<X>` -> objet `fields` (searchable en GXQL). Clés reconnues : `ts, severity, message, host, src_ip, dst_ip, url, category, sourcetype, source, id, dedup, entity`. |
| `auth.kind` | `none` \| `basic` \| `bearer` \| `token`/`header` (avec `header_name`+`prefix`) \| `oauth2_client_credentials` (avec `token_url`, `client_id`, `scope`). Le credential est TOUJOURS le champ `secret` du connecteur. |
| `pagination.kind` | `none` \| `offset` \| `page` \| `cursor` (avec `cursor_path`) \| `link_header` (avec fallback `next_path`). Params : `param`, `size`, `size_param`, `start`. |
| `watermark` | Incrémental : `field_path` (dans chaque record), `param` (envoyé au serveur), `format` (`epoch`\|`iso8601`), `template` (`{value}`), `lookback_days` (cold-start). |

Voir aussi le code : `daemon/src/handlers/connectors.rs` (`HttpPullCfg`, `poll_http_pull`).
