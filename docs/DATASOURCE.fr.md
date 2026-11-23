# plume COMME DATASOURCE (#52) — rendre des requêtes à Grafana/Prometheus

[English](DATASOURCE.md) | [Français](DATASOURCE.fr.md)

Jusqu'ici, plume ne faisait que **recevoir** de la télémétrie (`POST /api/ingest`, `remote_write` de
Prometheus, Loki push, Splunk HEC). Il n'exposait **aucune API de lecture** vers laquelle une datasource
Grafana/Prometheus/Loki aurait pu diriger un panneau. C'est le levier d'adoption Grafana n° 1 — « aller là
où sont les gens » : un Grafana existant dirige un panneau vers plume au lieu de changer de plateforme.

Trois surfaces de lecture (2 construites, 1 conçue) :

| Levier | Point(s) d'entrée | Datasource Grafana | Statut |
|-------|-------------|--------------------|--------|
| 1. GXQL sur HTTP-JSON | `GET/POST /api/ds/query` | Infinity / JSON | **construit** |
| 2. Lecture Prometheus | `/api/v1/query`, `/api/v1/query_range`, `/api/v1/label/__name__/values`, `/api/v1/labels`, `/api/v1/series` | Prometheus | **construit (sous-ensemble honnête)** |
| 3. Lecture Loki (LogQL) | `/loki/api/v1/query_range` | Loki | **bouchon (501) + conception ci-dessous** |

Tout ici est **en lecture seule** et **additif** — les points d'entrée existants d'ingestion et d'interface
sont byte-identiques (mode 0).

---

## Modèle de sécurité (le critère n° 1 de la revue)

C'est une **nouvelle surface de lecture externe**. Elle ne **contourne pas** le masquage par filtres de
champ de #45 ni le RBAC :

- L'appelant est résolu par le point de passage unique `auth_guard` habituel (jeton → rôle/tenant),
  exactement comme pour toute autre route. **L'anonyme est refusé** (401), sauf si la démonstration publique
  est *servie* : l'exploitant a choisi `PLUME_PUBLIC_DEMO` **et** le démon l'a activée au démarrage — elle
  n'est pas activée quand le nom `demo` appartient déjà à quelqu'un (`P10.28-j` : le refus est écrit dans le
  journal de démarrage et dans le ledger, et le paquet de diagnostic rapporte `public_demo_served` à côté de
  la valeur configurée). Servie, la démonstration est en lecture seule (viewer, et aucune écriture d'aucune
  sorte sous son identité partagée, `P10.28-i`).
- **GXQL-HTTP** fait passer chaque lecture par
  `soql_to_sql_masked_x(soql, from, to, env, effective_masks(role,…))` — le *même* compilateur masqué que
  celui qu'utilise `/api/query` pour l'interface. Le masque est émis **dans le SQL** (avant toute
  agrégation/tout renommage), et les règles DENY sur de vraies colonnes arment aussi l'autorizer du pool de
  lecture SQLite. Un jeton de datasource limité à viewer voit masqués les champs masqués/refusés ; une requête
  qui *filtre* sur un champ masqué est refusée de la même façon que dans l'interface.
- **Prometheus** respecte rôle/tenant de deux façons : (a) un matcher sur un label/hôte **masqué** est
  **refusé** (un matcher d'égalité est un oracle — reflet de `search_mask_guard`) ; (b) les **valeurs** de
  label/hôte en sortie sont caviardées via `mask_named_row`. Fail-closed : si un masque ne peut pas être
  appliqué, la requête est refusée, jamais servie en clair. Le SQL des métriques est construit à l'abri de
  l'injection (nom de métrique + clés de label strictement validés, valeurs échappées par apostrophe) et
  exécuté par le pool en lecture seule (`run_query_ex` refuse tout ce qui n'est pas `SELECT`).
- **Aucun SQL brut** n'est jamais accepté d'un appelant de datasource — seulement `soql` (compilé) ou un
  sélecteur de métrique.
- **Débit limité** par le limiteur existant global + par IP (`PLUME_RL_IP_MAX`, défaut 1200 req/10 s), plus
  le sémaphore de concurrence par requête (`query_sem`) et le budget de temps par requête
  (`PLUME_QUERY_BUDGET_MS`, ~5 s).

### Modèle d'authentification / de jeton

Une datasource s'authentifie avec **n'importe quel** identifiant valide que le point de passage unique
comprend déjà (compte Basic, en-tête de confiance SSO, cookie de session) **ou** avec un **jeton
`datasource` dédié limité à la lecture** (Bearer) :

- Frapper via `POST /api/tokens {name, kind:"datasource", role:"viewer"|"editor"}` (admin seulement,
  mode 0). Le secret en clair est affiché une seule fois. Le rôle vaut `viewer` par défaut (moindre
  privilège) et est **borné dur à viewer|editor** — jamais admin/agent, si bien qu'un jeton de datasource ne
  peut jamais atteindre le SQL brut ni l'ingestion.
- Le jeton n'est accepté **que** sur les chemins de lecture de datasource (`datasource_bearer_path`, fermé
  par défaut) et se résout en `(role, tenant)` → `effective_masks(role,…)` → masquage/RBAC hérités
  automatiquement.
- Branchement Grafana : datasource Prometheus → *Authorization: Bearer <token>* (en-tête personnalisé) ;
  Infinity → authentification par jeton Bearer, URL `https://plume/api/ds/query`.

Schéma : la migration **v87** ajoute `token.role` (nullable). Les jetons d'agent/HEC gardent `role = NULL`
(inchangé). Les jetons de datasource sont **réservés au mode 0** (comme le provisionnement de jetons par
l'interface) ; en mode multi-tenant, utiliser Basic/SSO.

---

## Levier 1 — GXQL sur HTTP-JSON (`/api/ds/query`)

Le levier le plus général : exécuter n'importe quelle lecture GXQL et récupérer du JSON tabulaire.

```
GET  /api/ds/query?soql=<soql>&from=<epoch>&to=<epoch>&limit=<n>&format=records|table
POST /api/ds/query   {"soql":"search category=auth | stats count by host", "from":0, "to":0, "limit":500}
```

- `format=records` (défaut) → `[{col: val, …}, …]` (la forme naturelle de Grafana Infinity).
- `format=table` → `{ "columns": [...], "rows": [[...], …] }`.
- `from`/`to` = secondes epoch (0 = sans borne). `limit` plafonné à 10 000.
- La compilation est byte-identique au chemin GXQL de `/api/query` (masques appliqués). Aucun champ `sql`
  (brut) n'est accepté.

## Levier 2 — Lecture compatible Prometheus

Diriger une datasource **Prometheus** de Grafana vers `https://plume` (elle appellera `/api/v1/*`).

**Sous-ensemble supporté (honnête) :**

- Instantané `GET/POST /api/v1/query?query=<selector>&time=<epoch>` → `resultType: vector` (dernier
  échantillon ≤ `time` par série, dans une fenêtre de rétrospection bornée `PLUME_PROM_LOOKBACK_S`, défaut
  3600 s).
- Plage `GET/POST /api/v1/query_range?query=<selector>&start=&end=&step=` → `resultType: matrix`
  (échantillons **bruts** dans `[start,end]` ; `step` n'est **pas** rééchantillonné — Grafana sous-échantillonne
  côté client).
- `GET /api/v1/label/__name__/values` → noms de métriques distincts. `GET /api/v1/label/<label>/values` →
  valeurs distinctes (refusé si le label est masqué pour l'appelant).
- `GET/POST /api/v1/labels` → clés de label connues (`__name__`, `host`, clés JSON échantillonnées), moins les
  clés masquées.
- `GET/POST /api/v1/series?match[]=<selector>` → ensembles de labels des séries correspondantes (masqués).

**Grammaire du sélecteur (minimale) :** `metric_name`, `metric_name{label="v",…}`, ou
`{__name__="metric_name",…}`. **Seul le matcher `=` (égalité) est supporté.** `!=`, `=~`, `!~` ne sont **pas**
supportés (400 clair).

**Non-objectifs explicites (suite documentée) :** pas de fonctions PromQL (`rate`, `sum`,
`histogram_quantile`, `irate`, …), pas d'opérateurs/d'agrégations, pas de modificateurs `@`/offset, pas de
matchers par regex, pas d'historique adossé aux rollups (seule la table brute `metric` est servie). C'est une
**cale de compatibilité** pour tracer une métrique *stockée*, pas un moteur PromQL — cohérent avec le
principe de sur-ensemble (ne pas surpromettre).

## Levier 3 — Lecture Loki (LogQL) — conception + bouchon

`GET/POST /loki/api/v1/query_range` rend aujourd'hui **501** (point de configuration `PLUME_LOKI_QUERY`,
désactivé par défaut).

**Conception prévue (suite) :** les journaux vivent dans la table `event` (Loki push y atterrit avec
`category='log'`). Un sélecteur de flux LogQL `{source="…", host="…"} |= "needle"` se transpose proprement en
GXQL :

```
{job="sshd"} |= "Failed password"   →   search source="plume-sshd" "Failed password" | table ts, host, message
```

Le chemin de lecture réutilisera le **même compilateur masqué** (`soql_to_sql_masked_x` sur `event`), si bien
que masquage/RBAC seront hérités à l'identique du levier 1 — y compris le refus d'oracle de
`search_mask_guard` pour les filtres sur des champs masqués. Le format de ligne/de label et les requêtes de
métriques (`count_over_time`, `rate`) sont des étapes ultérieures. Le bouchon + le point de configuration
existent pour qu'une datasource Loki puisse être *dirigée* vers plume dès aujourd'hui et s'allumer quand le
drapeau sera livré.

---

## Ce qui ne change PAS

L'ingestion existante (`/api/ingest`, `/api/metrics/*`, `/loki/api/v1/push`, HEC), l'interface, la détection
et toutes les routes qui modifient l'état ne sont pas touchées. Les nouveaux points d'entrée sont purement
additifs et en lecture seule ; sans filtre de champ configuré (mode 0), ils se comportent comme une fine cale
de lecture au-dessus du chemin de requête masqué existant.
