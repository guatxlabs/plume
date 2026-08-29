# La console, espace par espace et onglet par onglet

La console de plume est une application web servie par le démon lui-même — du JavaScript à modules,
sans étape de construction, sans dépendance à installer. Elle se navigue à **deux niveaux** : des
**espaces** dans la barre latérale, et des **onglets** à l'intérieur d'un espace.

Ce document dit **ce que chaque onglet fait, qui peut le voir, et ce qu'il ne fait pas**. Il ne
remplace pas l'aide intégrée — l'espace *Aide* de la console, entièrement statique et hors réseau —
mais il est ce qu'on lit **avant** d'avoir une instance sous la main.

---

## 1. Ce qu'un lecteur doit savoir avant le tableau

### 1.1 Y accéder, dans les trois modes

L'adresse dépend du mode de déploiement : voir [`TROIS-MODES.md`](TROIS-MODES.md#31-atteindre-la-console).
Dans les trois cas, le nom demandé doit correspondre à `PLUME_HOST`, sans quoi la garde
anti-détournement de DNS rend `421`.

Sans `PLUME_PASS_HASH`, le central démarre en **mode SETUP** : un jeton d'installation à usage unique
paraît dans les journaux, et l'assistant web prend le relais.

### 1.2 Trois rôles, et un défaut fermé

`viewer` · `editor` · `admin`. Le contrôle qui compte est **côté serveur** : une route non listée est
refusée, pas autorisée. Ce que la console masque est un confort, pas une sécurité — un onglet caché
dont on forcerait l'adresse buterait sur un `403` de l'API.

Trois formes de restriction se lisent dans le tableau ci-dessous :

| Marque | Sens |
|---|---|
| **espace admin** | l'espace entier est réservé aux administrateurs (c'est le cas d'*Administration*) |
| **onglet admin** | l'onglet seul est réservé, l'espace reste visible |
| **multi-tenant** | l'onglet n'apparaît qu'en mode multi-tenant (`PLUME_MULTI_TENANT=1`), invisible sinon |

Plusieurs onglets sont **en lecture pour tous, en écriture pour éditeur ou administrateur** : la
liste est visible, les boutons de modification ne le sont pas.

### 1.3 Un onglet est une adresse

Le fragment d'URL **est** l'identifiant de l'onglet, unique tous espaces confondus : `#explore`,
`#ledger`, `#datamodels`. Les liens profonds fonctionnent donc, et se partagent. Quelques anciens
fragments de premier niveau restent acceptés comme alias, pour ne pas casser les liens existants.

Un espace qui n'a qu'un seul onglet n'affiche pas de barre d'onglets.

### 1.4 D'où vient ce tableau

**Il est dérivé de la structure de navigation de la console, pas recopié.** Relevé sur l'arbre suivi
le 2026-08-25 : **8 espaces, 37 onglets**. La commande qui redonne les comptes :

```sh
python3 - <<'PY'
import re
src = open('web/navigation.js', encoding='utf-8').read()
bloc = src[src.index('const SPACES = ['):src.index('\n];', src.index('const SPACES = ['))]
esp = re.findall(r"\{\s*id:\s*'([a-z0-9-]+)'\s*,(?:\s*admin:\s*true\s*,)?\s*tabs:", bloc)
ong = re.findall(r"\{\s*id:\s*'([a-zA-Z0-9-]+)'\s*,\s*label:", bloc)
print(len(esp), "espaces,", len(ong), "onglets")
PY
```

---

## 2. Les huit espaces

### 2.1 `overview` — Vue d'ensemble

Un seul onglet. C'est la page d'atterrissage : elle répond à « est-ce que ça va ? » avant qu'on
sache quoi demander.

| Onglet | Libellé | Rôle | Ce qu'on y voit |
|---|---|---|---|
| `overview` | Vue d'ensemble | viewer+ | pare-feu, catalogue de contrôles, intégrations, et un pouls compact de la **fraîcheur** des sources |

Elle est **en direct** : elle ignore le sélecteur de plage temporelle de la barre, contrairement aux
tableaux de bord. Le détail complet de la fraîcheur a son propre onglet (`freshness-view`), pour que
cette page reste lisible.

### 2.2 `search` — Recherche

Un seul onglet, et c'est le cœur du produit.

| Onglet | Libellé | Rôle | Ce qu'on y fait |
|---|---|---|---|
| `explore` | Recherche | viewer+ | écrire une requête GXQL, la valider pendant la frappe, lire les résultats, l'histogramme temporel et les facettes de champs, déplier un événement, exporter |

C'est le **seul** onglet où la barre de requête est affichée, et il porte son propre sélecteur de
plage, distinct de celui des tableaux de bord. Le langage lui-même est décrit dans
[`GXQL.md`](GXQL.md) ; les gabarits livrés s'y chargent en un clic.

### 2.3 `cases` — le flux alerte → cas

| Onglet | Libellé | Rôle | Ce qu'on y fait |
|---|---|---|---|
| `alerts` | Alertes | viewer+ | la file des alertes levées par les règles, groupées, à trier |
| `cases` | Cas | viewer+ | un cas d'incident : chronologie, événements et alertes liés, échéances |

La séparation est délibérée : *Alertes* est ce qui arrive, *Cas* est ce qu'on en fait.

### 2.4 `dashboards` — Tableaux de bord

| Onglet | Libellé | Rôle | Ce qu'on y fait |
|---|---|---|---|
| `dashboards` | Dashboards | viewer+ | composer et lire des tableaux de bord ; **chaque panneau affiche la requête qui le produit** |

C'est le seul espace piloté par le **sélecteur de plage de la barre** ; il se rafraîchit
automatiquement.

### 2.5 `detresp` — Détection et réponse

Sept onglets : de la règle qui détecte à l'action qui répond.

| Onglet | Libellé | Rôle | Ce qu'on y fait |
|---|---|---|---|
| `detection` | Détection | viewer+ lecture · éditeur+ écriture | les règles livrées et les vôtres, et le panneau de couverture |
| `attack` | ATT&CK | viewer+ | la matrice de couverture MITRE ATT&CK — chaque manqué devient un angle mort visible |
| `playbooks` | Playbooks | viewer+ lecture · **rédaction de runbooks réservée aux administrateurs** | détection → réponse automatique, et l'interrupteur du **Mode Engagement** |
| `actions` | Actions | viewer+ | la file de riposte : ce qui est proposé, approuvé, appliqué, refusé |
| `risk` | Risque | viewer+ | score de risque par entité (alerting basé sur le risque) |
| `detadv` | Avancée | viewer+ lecture · éditeur+ écriture | corrélations de séquence et lignes de base comportementales |
| `routing` | Politiques de notification | viewer+ lecture · éditeur+ écriture | à qui part une notification, et ce qu'on met en sourdine |

Une action n'est **jamais** appliquée sans passer par cette chaîne : proposition, **approbation d'un
administrateur**, réclamation par l'agent, résultat au journal d'audit. Le détail du canal retour est
dans [`AGENTS-PROTOCOLE.md`](AGENTS-PROTOCOLE.md#6-le-canal-retour--réclamer-une-action).

### 2.6 `data` — Les données et leur tuyauterie

Le plus gros espace : treize onglets, de la source brute jusqu'à la couche sémantique.

| Onglet | Libellé | Rôle | Ce qu'on y fait |
|---|---|---|---|
| `sources` | Sources | viewer+ | l'inventaire des flux déclarés : attendu contre réel |
| `freshness-view` | Fraîcheur | viewer+ | la santé de collecte, flux par flux, en détail |
| `system` | Système | viewer+ lecture · outils d'administration réservés | auto-métriques du démon, santé par composant, bulletin et diagnostic |
| `fleet` | Flotte | viewer+ | l'inventaire des hôtes et des points d'accès : dernier contact, statut, enrôlement |
| `connectors` | Connecteurs | **admin** | les sources externes en **PULL** — le chemin d'ajout de source qui existe dans les trois modes |
| `destinations` | Destinations | **admin** | le renvoi d'événements vers un puits externe (syslog, HEC, webhook) — surface d'exfiltration, d'où la restriction |
| `processors` | Processeur d'ingest | **admin** | filtrer, masquer, router, échantillonner **à l'ingestion** |
| `indexes` | Indexes & rétention | **admin** | des index logiques nommés, avec leur rétention et leurs plafonds propres |
| `parsers` | Parseurs | viewer+ lecture · éditeur+ écriture | les extracteurs de champs, livrés et personnels |
| `lookups` | Lookups | viewer+ lecture · éditeur+ écriture | les tables de correspondance qu'utilise la commande `lookup` |
| `knowledge` | Savoir | viewer+ lecture · éditeur+ écriture | objets de savoir résolus au moment de la recherche : alias, champs calculés, types d'événement, étiquettes |
| `datamodels` | Modèles & Pivot | viewer+ lecture et exécution · éditeur+ écriture | la couche sémantique et le constructeur de rapports par pivot |
| `dataaccess` | Accès données (DLP) | viewer+ | la gouvernance d'accès aux données, en lecture seule |

> **À noter pour les modes conteneur et cluster.** Déposer un parseur ou une règle **par fichier** y
> est difficile ou impossible (racine en lecture seule). Les onglets `parsers`, `detection` et
> `lookups` sont donc le chemin normal dans ces deux modes — et ce qu'on y crée porte une marque
> distincte de ce qui vient d'un fichier versionné. Voir
> [`TROIS-MODES.md`](TROIS-MODES.md#34-ajouter-un-parseur-une-règle-un-playbook).

### 2.7 `admin` — Administration

**Espace entièrement réservé aux administrateurs.** Onze onglets.

| Onglet | Libellé | Rôle | Ce qu'on y fait |
|---|---|---|---|
| `settings` | Compte | son propre compte | mot de passe, préférences, et l'inscription d'un second facteur TOTP |
| `users` | Users | admin | les comptes et leurs rôles |
| `tokens` | Jetons | **admin** | provisionner un jeton d'agent ou HEC — le secret ne s'affiche **qu'une fois** |
| `idp` | Identité fédérée (SSO) | **admin** | fournisseurs OIDC et LDAP — voir [`NATIVE-IDP.md`](NATIVE-IDP.md) |
| `fieldfilters` | Field filters | **admin** | masquage par champ ; c'est une configuration qui **contraint** les autres rôles |
| `tenants` | Tenants | **multi-tenant seulement** | les tenants et les habilitations ; invisible en mono-tenant |
| `notifiers` | Canaux | admin | où partent les notifications |
| `threatintel` | Threat Intel | admin | le magasin d'IOC : couverture, liste, ajout, import STIX |
| `suppressions` | Suppressions | admin | ce qu'on choisit de ne plus voir, et pourquoi |
| `retention` | Rétention | admin | combien de temps on garde — voir aussi [`PURGE.md`](PURGE.md) |
| `ledger` | Audit | admin | le journal d'audit en chaîne de hachage, vérifiable hors ligne par `plume-daemon verify` |

Le masquage par champ mérite d'être compris avant d'être posé : il agit **à la compilation de la
requête**, et une requête qui porterait sur un champ masqué est **refusée** plutôt que de rendre une
valeur creuse — voir [`GXQL.md`](GXQL.md#53-le-masquage-se-fait-à-la-compilation).

### 2.8 `help` — Aide

| Onglet | Libellé | Rôle | Ce qu'on y trouve |
|---|---|---|---|
| `help` | Aide | tous | le guide intégré : sommaire des espaces et glossaire, **entièrement statique, aucun appel réseau** |

Les boutons « ? » disséminés dans la console ouvrent une section de ce même guide. Une garde de CI
(`check_every_help_trigger_has_a_section.py`) refuse qu'un bouton d'aide ouvre une section qui
n'existe pas — le défaut avait vécu des semaines sans que rien le dise.

---

## 3. Comment la console est faite, et pourquoi

**Pas d'étape de construction.** Du JavaScript à modules, servi tel quel depuis le disque. Un
opérateur peut lire ce qui tourne chez lui sans outillage — c'est cohérent avec un produit qui
promet un seul binaire et aucune dépendance externe. Le prix est réel : pas de typage, pas de
transpilation, et un import cassé se voit à l'exécution — d'où un harnais de modules dans la CI, qui
charge la console hors navigateur pour attraper ces liens rompus.

**La navigation est une donnée, pas du code.** Espaces et onglets sont déclarés dans une seule
structure ; les index (onglet → espace, fragment → onglet) en sont **dérivés**. C'est ce qui permet à
ce document — et à sa garde — de s'appuyer sur une source unique plutôt que sur une liste tenue à la
main.

**Ce qui écrit se distingue de ce qui lit.** Un onglet qui expose une surface d'exfiltration
(*Destinations*), qui manipule des secrets (*Jetons*, *Identité*) ou qui contraint les autres rôles
(*Field filters*) est réservé à l'administrateur — et l'API le refuse aussi, indépendamment de ce que
la console montre. Les routes sensibles passent par une confirmation partagée, elle-même **dérivée du
routeur** par une garde de CI plutôt qu'énumérée.

**Le contenu porte son origine.** Une règle, un parseur ou un tableau de bord affiche s'il vient du
produit, d'un overlay de fichier versionné, ou d'une création faite dans la console. Sans cette
marque, un opérateur ne saurait pas ce qu'un redémarrage peut réécrire — et un homonyme personnel
fait **ignorer** l'overlay de fichier, avec un avertissement, plutôt que d'écraser silencieusement
son travail.

**Chaque panneau montre sa requête.** Un graphique dont on ne peut pas lire la question est une
boîte noire ; dans un outil de sécurité, c'est un défaut, pas un choix d'ergonomie.

---

## 4. Ce que ce document ne couvre pas

- **L'ergonomie fine** — raccourcis clavier, préférences, thème clair et sombre, bilinguisme et
  fuseaux horaires — n'est pas décrite ici : elle vit dans le guide intégré, au plus près de l'écran.
- **Aucune capture de ce document n'a été prise dans ce lot**, et **aucune instance n'a été
  ouverte** : les onglets, leurs libellés, leurs restrictions de rôle et leur regroupement sont
  **dérivés de la structure de navigation** de la console, pas observés à l'écran. Un écart entre ce
  tableau et votre instance est un défaut à signaler.
- **Les onglets adossés à une fonctionnalité optionnelle** peuvent se comporter différemment selon la
  compilation ou la configuration — SAML absent de l'image livrée, tier analytique expérimental,
  multi-tenant désactivé par défaut. L'état de chaque sujet est porté par
  [`README.md`](README.md), l'index de cette documentation.
