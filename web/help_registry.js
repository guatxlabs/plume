// help_registry.js — REGISTRE des SECTIONS d'aide in-app, une par panneau de la console : elles, et elles
// seules. L'ouvreur `openHelp`, les modales et l'aveu sur clé inconnue — la mécanique — vivent dans
// help.js, qui importe ce module ; ce module n'importe rien de la console (P11.4-e : le registre
// pesait près des deux tiers de help.js, mêlé à la mécanique — extrait tel quel, sans réindentation, car un
// corps d'aide est un gabarit multiligne à la colonne zéro dont chaque espace est du texte rendu).
//
// Forme : { clé : {fr:{title,body}, en:{title,body}} }. `body` est une chaîne multiligne rendue en <pre>
// (textContent). TOUTES les sections vivent ici, y compris les deux panneaux ouverts hors du bouton « ? »
// d'un en-tête — `freshness` (bouton de la carte Fraîcheur) et `syntax` (bouton « ? Aide » de la barre de
// requête) — qui étaient des tableaux de lignes dans la mécanique (P11.8-b : la mécanique ne porte plus
// aucun texte long, la garde du lexique la juge comme n'importe quel module ; seul cet objet est exempt,
// par sa forme {fr, en}). Le sens de dépendance reste mécanique -> registre : ce module n'importe rien.
//
// CE QUI NE VIT PAS ICI, ET POURQUOI — la frontière le DIT au lieu de le laisser croire (P11.4-k). Le
// sommaire du guide, le glossaire et les raccourcis sont du CONTENU et sont restés dans help.js. Le
// déplacement a été tenté et mesuré le 2026-08-24 : il est PUR (rendu identique dans les deux langues) et
// deux gardes le refusent. Ce module est tenu à ZÉRO littéral hors-regard par la garde du lexique — un
// plafond DÉRIVÉ, posé sur le porteur du registre quel qu'il soit — donc il n'accueille que du contenu
// BILINGUE PAR CONSTRUCTION ({fr, en}) ; un terme de glossaire ou un nom de touche est mono-forme et y
// tomberait hors-regard. Et le sommaire est l'ancre, PAR NOM DE FICHIER, de la garde des déclencheurs
// d'aide : l'y déplacer rendrait cette garde aveugle à 27 déclencheurs sans la faire rougir. Le détail
// mesuré, avec ses codes de sortie, est écrit en tête de help.js, à côté du contenu qui reste.
//
// 100 % statique, WEB-ONLY : aucun appel réseau, aucun daemon. Les sections sont lues par la garde de CI
// `check_every_help_trigger_has_a_section.py` (clés de premier niveau de `const HELP`, localisé sous web/
// par sa définition), exemptées de la garde du lexique sur cette même portée (`check_i18n_lexicon_covers_
// displayed_strings.py`), et rendues clé par clé, langue par langue, par le harnais ESM (témoin 13).
export const HELP = {
  freshness: {
    fr: { title: `Aide — Fraîcheur des sources`, body:
`ÉTAT = SANTÉ DE COLLECTE (pas l'activité), dérivé par le démon de la cadence DÉCLARÉE :
  ● frais      donnée reçue il y a < 15 min
  ● calme      collecte OK mais source peu active — PAS un retard
  ● en retard  une sonde DÉCLARE une cadence continue pour cette source et le silence
               dépasse 3 cycles — la même observation qu'Intégrations montre « muet » sur le
               capteur ; l'alerte « Capteur muet » part deux cycles plus tard
  ● muet       INGESTION EN PANNE : plus aucune donnée (toutes sources) depuis > 10 min

Les alertes actives d'une source sont un COMPTE (cloche à côté du nom), jamais un état de collecte.

CE QUE LA CLOCHE COUVRE, ET CE QU'ELLE NE COUVRE PAS. Une cloche compte les alertes IMPUTÉES à
une source, toutes dates confondues. Le bandeau répartit donc toutes les alertes actives en trois :
  imputées à un flux         leur cloche est allumée dans la liste
  sans flux                  elles DISENT ne se rapporter à aucune source : une alerte d'hôte, de
                             règle éteinte ou de seuil n'en a pas. Ce n'est PAS un défaut de
                             collecte. Le compte est cliquable : il ouvre exactement ces alertes.
  sans imputation enregistrée  levées avant l'imputation, ou par un producteur qui ne l'écrit
                             pas : le compte par source les ignore, et c'est dit plutôt que tu.
Les trois font le total : c'est ce qui permet de vérifier qu'aucune alerte ne se perd.

CADENCE DÉCLARÉE (affichée à côté du nom) — par une sonde du démon OU par l'exploitant :
  continu · N     un point est attendu tous les N → peut être « en retard »
  événementiel    pas de cadence PAR NATURE, le débit dépend de l'activité → jamais « en retard »
  aucune cadence déclarée   personne ne l'a dite (ni sonde, ni humain) : un blanc, pas un défaut
                            → l'âge ne dit que l'activité, jamais « en retard »
Une cadence déclarée par un humain porte son nom et sa date (survol). Elle se déclare depuis
l'Inventaire (Données → Sources). Le rythme observé sur 24 h (~1 donnée / N) est donné au survol :
c'est une observation, pas une attente, et il ne juge rien.

L'âge = temps depuis la dernière DONNÉE, pas depuis le dernier passage du collecteur (qui, lui,
tourne sur un timer et vérifie ; il n'émet que s'il y a du nouveau). Une source peut être « calme »
des heures sans problème : un IPS n'émet rien sans attaque, un collecteur périodique n'émet qu'au changement.` },
    en: { title: `Help — Source freshness`, body:
`STATE = COLLECTION HEALTH (not activity), derived by the daemon from the DECLARED cadence :
  ● fresh   data received < 15 min ago
  ● quiet   collecting OK but low-activity source — NOT a delay
  ● late    a probe DECLARES a continuous cadence for this source and the silence exceeds
            3 cycles — the same observation Integrations shows as a "mute" probe; the
            "Mute probe" alert fires two cycles later
  ● down    INGESTION BROKEN: no data (any source) for > 10 min

Active alerts on a source are a COUNT (bell next to the name), never a collection state.

WHAT THE BELL COVERS, AND WHAT IT DOES NOT. A bell counts the alerts IMPUTED to a source, across
all dates. The banner therefore splits every active alert into three:
  imputed to a flow      their bell is lit in the list below
  no flow                they SAY they refer to no source: a host, dead-rule or threshold alert
                         has none. This is NOT a collection fault. The count is clickable: it
                         opens exactly those alerts.
  no recorded imputation raised before imputation existed, or by a producer that does not write
                         it: the per-source count ignores them, and that is said rather than hidden.
The three add up to the total: that is what lets you check no alert goes missing.

DECLARED CADENCE (shown next to the name) — by a daemon probe OR by the operator :
  continuous · N     a datum is expected every N                         → can be "late"
  event-driven       no cadence BY NATURE, the rate depends on activity  → never "late"
  no declared cadence  nobody stated one (no probe, no human): a blank, not a fault
                       → age only tells activity, never "late"
A human-declared cadence carries its author and date (on hover). It is declared from the
Inventory (Data → Sources). The 24 h observed rhythm (~1 datum / N) is shown on hover; it is an
observation, not an expectation, and it judges nothing.

Age = time since the last DATA, not since the collector last ran (which runs on a timer and
checks; it only emits if there is something new). A source can be "quiet" for hours with no
problem: an IPS emits nothing without an attack, a periodic collector emits on change.` },
  },
  syntax: {
    fr: { title: `Aide — requêtes (GXQL)`, body:
`PIPELINE :  search <filtres>  | stats …  | where …  | sort …  | head N  | table *

FILTRES (search) :
  field=val   field:val          égalité        source=ufw   dport=993   proto=TCP
  field=val*                     joker          src_ip=203.0.113*
  field=~regex                   regex          message=~"BLOCK"
  field>v  field<v  >=  <=        comparaison    severity>=3   dport>1000
  un_mot                         plein-texte sur le message

TRANSFORMATIONS (après un |) :
  | stats count [by f1,f2]       compte, groupé    by dport   by dir   by src_ip
  | stats sum(f)|avg(f)|min(f)|max(f)|dc(f)
  | timechart span=1h count [by f]   série temporelle (buckets)
  | where f op v                 filtre APRÈS agrégat   where count>50
  | rex <champ> "(?<nom>…)"       extrait des groupes nommés en COLONNES (regex)
       ex: search source=mail | rex message "rip=(?<ip>[\\d.]+).*user=<(?<u>[^>]+)>" | table u, ip
  | sort [-]f                    tri ( - = décroissant )   sort -count
  | head N      | fields a,b      | table *

CHAMPS groupables (qui/où/quoi/quand) :
  src_ip dst_ip dport lport proto dir proc user action jail scope host source category severity ts

EXEMPLES (corrélation) :
  search source=ufw | stats count by src_ip | sort -count | head 10
  search source=conntrack dir=inbound scope=external | stats count by dport
  search src_ip=203.0.113.7 | sort -ts        (tout sur une IP : ufw + conntrack + bans…)

Heure : stockée en UTC ; l’affichage suit le sélecteur 🕓 (Navigateur / Europe-Paris / UTC).` },
    en: { title: `Help — queries (GXQL)`, body:
`PIPELINE :  search <filters>  | stats …  | where …  | sort …  | head N  | table *

FILTERS (search) :
  field=val   field:val          equals         source=ufw   dport=993   proto=TCP
  field=val*                     wildcard       src_ip=203.0.113*
  field=~regex                   regex          message=~"BLOCK"
  field>v  field<v  >=  <=        comparison     severity>=3   dport>1000
  a_word                         full-text on the message

TRANSFORMS (after a |) :
  | stats count [by f1,f2]       count, grouped    by dport   by dir   by src_ip
  | stats sum(f)|avg(f)|min(f)|max(f)|dc(f)
  | timechart span=1h count [by f]   time series (buckets)
  | where f op v                 filter AFTER aggregate   where count>50
  | rex <field> "(?<name>…)"      extract named groups into COLUMNS (regex)
       e.g. search source=mail | rex message "rip=(?<ip>[\\d.]+).*user=<(?<u>[^>]+)>" | table u, ip
  | sort [-]f                    sort ( - = descending )   sort -count
  | head N      | fields a,b      | table *

GROUPABLE fields (who/where/what/when) :
  src_ip dst_ip dport lport proto dir proc user action jail scope host source category severity ts

EXAMPLES (correlation) :
  search source=ufw | stats count by src_ip | sort -count | head 10
  search source=conntrack dir=inbound scope=external | stats count by dport
  search src_ip=203.0.113.7 | sort -ts        (everything on one IP: ufw + conntrack + bans…)

Time: stored in UTC; display follows the time-zone selector (Browser / Europe-Paris / UTC).` },
  },
  firewall: {
    fr: { title: `Firewall — pare-feu de l'hôte`, body:
`Vue LIVE (indépendante de la fenêtre temporelle) de l'état du pare-feu.
• Contrôle docker-lockdown : chaînes DOCKER-USER (v4) et INPUT (v4/v6) en place.
• Empreinte du ruleset (sha256) + heure du dernier relevé du capteur (~2 min).
OK = règle présente ; ABSENT / MANQUANT = trou de configuration à corriger.
n/a = pas d'interface concernée sur cet hôte (ce n'est pas une panne).` },
    en: { title: `Firewall — host firewall`, body:
`LIVE view (ignores the time window) of the host firewall state.
• docker-lockdown control: DOCKER-USER (v4) and INPUT (v4/v6) chains in place.
• Ruleset fingerprint (sha256) + time of the sensor's last scan (~2 min).
OK = rule present ; ABSENT / MISSING = a config gap to fix.
n/a = no matching interface on this host (not a failure).` },
  },
  controls: {
    fr: { title: `Contrôles (zéro-trou)`, body:
`Contrôles de durcissement attendus sur l'hôte, vérifiés en continu.
• OK = contrôle en place ; MANQUANT = écart à corriger.
• Le compteur « manquant(s) » résume le nombre de trous.
Vue LIVE, rafraîchie par le capteur (~5 min).` },
    en: { title: `Controls (zero-gap)`, body:
`Host-hardening controls expected on the host, checked continuously.
• OK = control in place ; MISSING = gap to fix.
• The "missing" counter sums up the number of gaps.
LIVE view, refreshed by the sensor (~5 min).` },
  },
  integrations: {
    fr: { title: `Intégrations & hôtes`, body:
`État des capteurs (collecteurs) et des hôtes qui envoient des données.
• Capteur actif = émet ; MUET = plus aucune donnée (à investiguer) ; en attente.
• Hôtes : chaque machine reliée + heure de son dernier signal.
• « Non branché » = capteur prévu mais pas encore raccordé (ex. YARA).` },
    en: { title: `Integrations & hosts`, body:
`State of sensors (collectors) and of the hosts sending data.
• Sensor active = emitting ; MUTE = no more data (investigate) ; pending.
• Hosts: each connected machine + time of its last signal.
• "Not wired" = a planned sensor not yet connected (e.g. YARA).` },
  },
  fleet: {
    fr: { title: `Flotte d'agents`, body:
`Inventaire des HÔTES qui remontent des données (endpoints où un agent pousse).
• Statut = fraîcheur du DERNIER signal de l'hôte :
   frais (<15 min) · en retard (15 min–1 h) · muet (>1 h, agent probablement tombé).
   Un hôte muet ≠ une source calme : ici, plus AUCUN signal = l'agent a décroché.
• Signaux = volume total reçu (events + métriques + snapshots, dans la rétention).
• Enrôlement = token d'agent lié à l'hôte (nom + date) ; Dernier push agent = dernier
   appel authentifié du token (mono-tenant).
• Version / OS de l'agent : non transmis par le collecteur -> non affichés (différé).
Affichage SEUL : la console ne pilote pas l'hôte (enrôlement/config = lecture).` },
    en: { title: `Agent fleet`, body:
`Inventory of HOSTS that report data (endpoints where an agent pushes).
• Status = freshness of the host's LAST signal :
   fresh (<15 min) · stale (15 min–1 h) · silent (>1 h, agent likely down).
   A silent host ≠ a quiet source : here, NO more signal = the agent dropped off.
• Signals = total volume received (events + metrics + snapshots, within retention).
• Enrollment = agent token bound to the host (name + date) ; Last agent push = the
   token's last authenticated call (single-tenant).
• Agent version / OS : not sent by the collector -> not shown (deferred).
Display ONLY : the console never controls the host (enrollment/config are read-only).` },
  },
  explore: {
    fr: { title: `Recherche (éditeur de requête, Plume panel)`, body:
`L'espace Recherche : une requête = une recherche dans les logs. La barre de l'en-tête est un raccourci : son texte est recopié dans l'éditeur, puis exécuté — il n'y a qu'un seul moteur de résultats.
• Champ requête : GXQL (search … | … ) ou SQL brut (admin). Bouton « ? Aide ».
• Fenêtre temporelle propre (presets jusqu'à 1 an + intervalle précis).
• Visualisation : Table / Barres / Courbe / Stat ; pagination (n/page).
• Résultats (vue événements) : timeline, « champs intéressants » (à gauche), liste d'événements dépliables.
• Drilldown : cliquer une valeur relance la recherche filtrée (fil d'Ariane).
• Sur une IP : puce bannir (action en attente d'approbation). Le flux alerte -> cas vit dans l'espace Cas.
• « Modèles » : mes modèles (enregistrés par « Enregistrer », modifiables, supprimables) et les modèles livrés (copiables) ; charger remplit la barre sans exécuter.
• « Récentes » : les dernières requêtes exécutées dans ce navigateur.
• Feuilleter : ◀ / ▶ parcourent tout le résultat par curseur ; un saut direct à un numéro de page lointain peut rendre une page PARTIELLE (le badge le dit) — revenir avec ◀ rétablit le parcours complet.
• « Panneau » enregistre la requête (réutilisable dans un Dashboard).` },
    en: { title: `Search (query editor, Plume panel)`, body:
`The Search space: one query = one search across the logs. The header bar is a shortcut: its text is copied into the editor, then run — there is a single results engine.
• Query box: GXQL (search … | … ) or raw SQL (admin). "? Help" button.
• Its own time window (presets up to 1 year + precise interval).
• Visualization: Table / Bar / Line / Stat ; pagination (n/page).
• Results (events view): timeline, "interesting fields" (left), expandable event list.
• Drilldown: click a value to re-run the search filtered (breadcrumb).
• On an IP: a ban chip (action pending approval). The alert -> case flow lives in the Cases space.
• "Templates": my templates (saved with "Save", editable, deletable) and the shipped templates (copyable); loading fills the bar without running.
• "Recent": the last queries run in this browser.
• Paging: ◀ / ▶ walk the whole result by cursor; a direct jump to a far page number can render a PARTIAL page (the badge says so) — going back with ◀ restores the complete walk.
• "Panel" saves the query (reusable inside a Dashboard).` },
  },
  soql: {
    fr: { title: `GXQL — référence des requêtes`, body:
`Le langage de requête s'appelle GXQL (GuatX Query Language), anciennement SOQL.
Même langage, même syntaxe : une requête, un lien ou un panneau écrit du temps
de « SOQL » fonctionne tel quel, rien à réécrire.

PIPELINE :  search <filtres>  | transform  | transform  | …

FILTRES (search) — champs : source, category|cat, severity|sev,
  src_ip|ip, dst_ip, host, message|msg|event, url, xff, fields|field
  champ=val / champ:val   égalité         source=ufw   dport=993
  champ=val*              joker (LIKE)    src_ip=203.0.113*
  champ=~regex            regex           message=~BLOCK
  champ> < >= <=          comparaison     severity>=3
  un_mot                  plein-texte (FTS) sur le message
  limit:N / max:N         borne le nombre de lignes
  (base alternative : metric … pour les séries de métriques)

TRANSFORMATIONS (après un |) :
  stats / timechart   agréger : count, sum, avg, min, max, dc,
                      values, list  [by champs]
                      by n'accepte qu'un champ en portée (colonne, label
                      déclaré par metric … by, clé JSON de fields) ; « par
                      heure / par jour » = timechart span=1h / span=1d
  where               filtrer APRÈS agrégat (gère in / not in)
  sort [-]f           trier ( - = décroissant )
  head N / limit N    garder les N premières lignes
  fields a,b / table  choisir / ordonner les colonnes
  rex "(?<nom>…)"     extraire des groupes nommés en colonnes
  rename a as b       renommer une colonne
  dedup f             supprimer les doublons sur f
  top / rare f        valeurs les plus / moins fréquentes
  eventstats          agrégat AJOUTÉ à chaque ligne (sans réduire)
  rate                taux par unité de temps
  eval x = expr       colonne calculée
  append [ … ]        concatène une seconde recherche
  join f [ … ]        jointure sur un champ
  mvexpand f          éclate une valeur multiple en lignes
  lookup <t> <clé> OUTPUT cols   enrichit (LEFT JOIN)

EXEMPLES RÉELS :
  search source=ufw | stats count by src_ip | sort -count | head 10
  search source=sshd severity>=3 | stats count by src_ip | where count > 10
  search source=web | lookup geoip src_ip OUTPUT country

Heure stockée en UTC ; l'affichage suit le sélecteur de fuseau.` },
    en: { title: `GXQL — query reference`, body:
`The query language is called GXQL (GuatX Query Language), formerly SOQL.
Same language, same syntax: a query, a link or a panel written back when it
was called "SOQL" still works as-is — nothing to rewrite.

PIPELINE :  search <filters>  | transform  | transform  | …

FILTERS (search) — fields: source, category|cat, severity|sev,
  src_ip|ip, dst_ip, host, message|msg|event, url, xff, fields|field
  field=val / field:val   equals          source=ufw   dport=993
  field=val*              wildcard (LIKE) src_ip=203.0.113*
  field=~regex            regex           message=~BLOCK
  field> < >= <=          comparison      severity>=3
  a_word                  full-text (FTS) on the message
  limit:N / max:N         cap the number of rows
  (alternative base: metric … for metric series)

TRANSFORMS (after a |) :
  stats / timechart   aggregate: count, sum, avg, min, max, dc,
                      values, list  [by fields]
                      by only takes a field in scope (column, label declared
                      by metric … by, JSON key of fields); "per hour / per
                      day" is timechart span=1h / span=1d
  where               filter AFTER aggregate (supports in / not in)
  sort [-]f           sort ( - = descending )
  head N / limit N    keep the first N rows
  fields a,b / table  pick / order columns
  rex "(?<name>…)"    extract named groups into columns
  rename a as b       rename a column
  dedup f             drop duplicates on f
  top / rare f        most / least frequent values
  eventstats          aggregate ADDED to each row (without reducing)
  rate                rate per unit of time
  eval x = expr       computed column
  append [ … ]        concatenate a second search
  join f [ … ]        join on a field
  mvexpand f          explode a multi-value into rows
  lookup <t> <key> OUTPUT cols   enrich (LEFT JOIN)

REAL EXAMPLES :
  search source=ufw | stats count by src_ip | sort -count | head 10
  search source=sshd severity>=3 | stats count by src_ip | where count > 10
  search source=web | lookup geoip src_ip OUTPUT country

Time stored in UTC ; display follows the time-zone selector.` },
  },
  alerts: {
    fr: { title: `Alertes`, body:
`File des alertes déclenchées par les règles de détection.
• Une alerte a un statut : « nouveau » puis « acquittée » (jamais supprimée).
• UNE liste, plusieurs TRIS (Plate / Règle / Hôte / Technique), une PORTÉE (actives / tous statuts), un filtre sur CE QUI EST AFFICHÉ (« Pas encore dans un cas » — le défaut — ou « Toutes les alertes »), des FACETTES (technique, source). La barre d'actions est la même sur tous les tris ; une action impossible reste visible, désactivée, avec sa raison.
• CHERCHER : le champ de l'en-tête cherche dans le titre (qui porte le nom de la règle), la règle et la source imputée. Il se COMBINE avec la portée, le filtre d'affichage, les facettes et le tri. Portée large : la recherche porte sur les alertes SERVIES — la page affichée sous « Tous statuts », qui est paginée. Le résumé le dit à chaque fois. Sous une recherche la liste est plate : un tri groupé ne charge pas les occurrences de ses groupes, une correspondance y serait introuvable ; le groupement revient dès que la recherche est vidée (Échap).
• Acquitter : sans facette ni recherche, « Tout acquitter » acquitte TOUTES les alertes actives (au-delà de la page) ; sous une facette ou une recherche, seules les alertes affichées.
• Cliquer le titre d'une alerte ouvre la Recherche sur CE QUE LA RÈGLE A COMPTÉ : la requête de la règle sans son agrégat final, sur la fenêtre exacte de l'évaluation — le nombre de lignes reproduit le compte de l'alerte (règle en SQL brut : le SQL lui-même, réservé à l'administrateur).
• La cloche d'une source (Données → Fraîcheur) mène ici avec la facette source : ses alertes non acquittées, cases comprises, toutes dates — sans lien avec la fraîcheur de la source. Le filtre est appliqué par le serveur sur l'imputation exacte de chaque alerte (« k8s » ne retient pas « k8s-audit ») ; il se combine avec tous les tris et les deux portées. Limite : une alerte levée avant que l'imputation soit enregistrée n'y figure pas, alors que la cloche la compte encore d'après le texte de sa règle.
• Le titre « Alertes » ramène à la liste plate sans filtre.
• Puces : ouvrir un case depuis l'alerte, ou bannir l'IP en cause.` },
    en: { title: `Alerts`, body:
`Queue of alerts raised by the detection rules.
• An alert has a status: "new" then "acknowledged" (never deleted).
• ONE list, several SORTS (Flat / Rule / Host / Technique), one SCOPE (active / all statuses), a filter on WHAT IS SHOWN ("Not yet in a case" — the default — or "All alerts"), FACETS (technique, source). The action bar is the same on every sort; an impossible action stays visible, disabled, with its reason.
• SEARCH: the header field searches the title (which carries the rule name), the rule and the imputed source. It COMBINES with the scope, the display filter, the facets and the sort. Broad scope: the search covers the alerts SERVED — the page shown under "All statuses", which is paginated. The summary says so every time. Under a search the list is flat: a grouped sort does not load its groups' occurrences, a match would be unreachable there; grouping returns as soon as the search is cleared (Esc).
• Acknowledge: without a facet or a search, "Ack all" acknowledges EVERY active alert (beyond the page); under a facet or a search, only the alerts shown.
• Clicking an alert title opens Search on WHAT THE RULE COUNTED: the rule query without its final aggregate, on the exact evaluation window — the row count reproduces the alert count (raw-SQL rule: the SQL itself, admin only).
• A source bell (Data → Freshness) lands here with the source facet: its unacknowledged alerts, cases included, all dates — unrelated to the source freshness. The filter is applied by the server on each alert's exact attribution ("k8s" does not match "k8s-audit"); it combines with every sort and both scopes. Limit: an alert raised before attribution was recorded is not listed, while the bell still counts it from its rule text.
• The "Alerts" title goes back to the flat, unfiltered list.
• Chips: open a case from the alert, or ban the offending IP.` },
  },
  cases: {
    fr: { title: `Cases (gestion d'incident)`, body:
`Dossiers d'incident pour suivre une investigation de bout en bout.
• Statuts : nouveau, triage, en cours, résolu, clos (+ anciens : ouvert…).
• Priorité P1 (critique) à P4 (basse) ; échéance SLA + badge « RETARD ».
• Assignation à une personne ; timeline horodatée (notes, actions, events).
• Filtres : statut, priorité, assigné, tri (SLA…), En retard, Archivés.
• Résoudre / clore / archiver. Édition = éditeur ou admin.` },
    en: { title: `Cases (incident management)`, body:
`Incident folders to track an investigation end to end.
• Statuses: new, triage, in progress, resolved, closed (+ legacy: open…).
• Priority P1 (critical) to P4 (low) ; SLA due date + "OVERDUE" badge.
• Assignment to a person ; timestamped timeline (notes, actions, events).
• Filters: status, priority, assignee, sort (SLA…), Overdue, Archived.
• Resolve / close / archive. Editing = editor or admin.` },
  },
  dashboards: {
    fr: { title: `Dashboards`, body:
`Tableaux de bord composés de panneaux (une requête GXQL enregistrée).
• Vue = un regroupement de dashboards (créer / renommer / supprimer une vue).
• + Dashboard ajoute un tableau ; + Panneau (depuis la Recherche) ajoute une tuile.
• Édition : glisser / redimensionner les panneaux ; Rafraîchir recharge tout.` },
    en: { title: `Dashboards`, body:
`Boards made of panels (a saved GXQL query).
• View = a grouping of dashboards (create / rename / delete a view).
• + Dashboard adds a board ; + Panel (from Search) adds a tile.
• Edit: drag / resize panels ; Refresh reloads everything.` },
  },
  coverage: {
    fr: { title: `Couverture ATT&CK`, body:
`Techniques MITRE ATT&CK effectivement détectées (issues des alertes taguées).
• Chaque ligne : technique Txxxx + nom, nombre de détections, 1re détection.
• Cliquer une technique = pivot vers ses alertes.
• Sert à visualiser les angles morts de la détection (purple-team).` },
    en: { title: `ATT&CK coverage`, body:
`MITRE ATT&CK techniques actually detected (from MITRE-tagged alerts).
• Each row: technique Txxxx + name, detection count, first detection.
• Click a technique = pivot to its alerts.
• Helps visualize detection blind spots (purple-team).` },
  },
  attack: {
    fr: { title: `Matrice ATT&CK (couverture)`, body:
`Matrice de couverture MITRE ATT&CK : tactiques en COLONNES, techniques en CELLULES.
• Cellule verte = technique COUVERTE (règles / alertes) ; teinte d'autant plus soutenue que la couverture est dense.
• Cellule grisée = ANGLE MORT (aucune détection) -> les trous de couverture ressortent (purple-team).
• Le compteur « r/a » = nombre de règles / d'alertes de la technique.
• Chaque cellule porte l'identifiant ET le nom de la technique ; « nom inconnu » = identifiant hors du catalogue connu (technique retirée, personnalisée ou mal saisie).
• Cliquer une technique = pivot vers ses alertes.
• Lecture seule. Si la matrice est « indisponible », l'endpoint de couverture n'est pas encore déployé.` },
    en: { title: `ATT&CK matrix (coverage)`, body:
`MITRE ATT&CK coverage matrix: tactics as COLUMNS, techniques as CELLS.
• Green cell = COVERED technique (rules / alerts); deeper tint = denser coverage.
• Muted cell = BLIND SPOT (no detection) -> coverage gaps stand out (purple-team).
• The "r/a" counter = number of rules / alerts for the technique.
• Each cell carries the technique identifier AND its name; "unknown name" = identifier outside the known catalog (retired, custom or mistyped technique).
• Click a technique = pivot to its alerts.
• Read-only. If the matrix is "unavailable", the coverage endpoint is not deployed yet.` },
  },
  rules: {
    fr: { title: `Règles de détection`, body:
`Une règle exécute une requête qui renvoie UN nombre, à intervalle régulier.
• Condition + Seuil (ex. count > 10) : si vraie -> alerte à la Sévérité choisie.
• Sévérité : 1 low, 2 medium, 3 high, 4 critical.
• Type : GXQL (tous) ou SQL brut (réservé admin).
• Intervalle = fréquence d'exécution ; Fenêtre = plage de temps analysée.
• MITRE = technique Txxxx[.yyy] taguée (nourrit la Couverture ATT&CK).
• « Tester » évalue la requête sans créer d'alerte.
• L'interrupteur ON / OFF dit l'état et, à côté, ce qu'il arme ; il est réservé à l'administrateur.
• Où ça arrive : ses alertes dans l'onglet Alertes (ou Risque si la règle est en mode risque). Le formulaire et la liste le rappellent avec le lien.` },
    en: { title: `Detection rules`, body:
`A rule runs a query returning ONE number, on a regular interval.
• Condition + Threshold (e.g. count > 10): if true -> alert at chosen Severity.
• Severity: 1 low, 2 medium, 3 high, 4 critical.
• Type: GXQL (everyone) or raw SQL (admin only).
• Interval = run frequency ; Window = analyzed time span.
• MITRE = tagged technique Txxxx[.yyy] (feeds ATT&CK Coverage).
• "Test" evaluates the query without creating an alert.
• The ON / OFF switch shows the state and, next to it, what it arms; admin only.
• Where it lands: its alerts in the Alerts tab (or Risk when the rule is in risk mode). The form and the list say so, with the link.` },
  },
  response: {
    fr: { title: `Réponse (playbooks, runbooks & actions)`, body:
`Automatiser ou déclencher des ripostes. Enum FERMÉ des actions :
  ban_ip, unban_ip, kill_pid, stop_service.
• Deux familles sous l'onglet Playbooks, nommées dans leur en-tête : « Playbooks — règles de réponse » (une condition, une action, un interrupteur) et « Runbooks — guides d'incident » (des étapes, attachées à un cas). Un playbook se déclenche seul ; un runbook jamais.
• Mode Observation (vert) = propositions seulement, rien n'est exécuté.
• Mode ACTIF (rouge) = les playbooks exécutent la riposte automatiquement.
• Playbook = une règle de réponse : condition (requête dont la 1re colonne = la cible) -> action (ban / kill / stop), évaluée à intervalle régulier. Pas besoin d'un runbook autour. Le choix d'action dit ce qu'il fait, et la durée du ban est celle que posent les exécuteurs (servie, jamais écrite dans l'interface).
• L'interrupteur de chaque playbook dit ON ou OFF et, à côté, ce qu'il arme (ex. « bannit l'IP source pendant N h … ») ; l'activation demande confirmation, car elle touche le réseau ou un processus. Repasser sur OFF arrête les nouvelles actions.
• Où ça arrive : les actions posées dans l'onglet Actions (en attente / dry-run en Observation ; exécutées en Actif).
• Runbook = guide d'incident (checklist phasée, manuelle), proposé dans un Cas élevé en incident ; ses étapes « response » préparent une action soumise à approbation. Les livrés se lisent (« Étapes ») et se clonent ; seuls les custom s'éditent.
• Action manuelle : cible (IP / PID / service) + dry-run (simulation) ou RÉEL.
• dry-run coché par défaut ; les actions passent par une file d'approbation.` },
    en: { title: `Response (playbooks, runbooks & actions)`, body:
`Automate or trigger responses. CLOSED enum of actions:
  ban_ip, unban_ip, kill_pid, stop_service.
• Two families under the Playbooks tab, named in their header: "Playbooks — response rules" (a condition, an action, a switch) and "Runbooks — incident guides" (steps, attached to a case). A playbook fires on its own; a runbook never does.
• Observe mode (green) = proposals only, nothing is executed.
• ACTIVE mode (red) = playbooks run the response automatically.
• Playbook = a response rule: condition (a query whose 1st column = the target) -> action (ban / kill / stop), evaluated on an interval. No runbook needed around it. The action choice says what it does, and the ban duration is the one the executors set (served, never written in the interface).
• Each playbook's switch reads ON or OFF and, next to it, what it arms (e.g. "bans the source IP for N h …"); enabling asks for confirmation, since it touches the network or a process. Switching back to OFF stops new actions.
• Where it lands: the actions it posts in the Actions tab (pending / dry-run in Observe; executed in Active).
• Runbook = incident guide (phased manual checklist), proposed in a Case raised to incident; its "response" steps prepare an action subject to approval. Shipped ones can be read ("Steps") and cloned; only custom ones are edited.
• Manual action: target (IP / PID / service) + dry-run (simulation) or REAL.
• dry-run on by default ; actions go through an approval queue.` },
  },
  sources: {
    fr: { title: `Sources d'ingestion`, body:
`Inventaire de toutes les sources de données ingérées.
• Colonnes : Déclarée (par qui), Cadence, Dernier vu, volume 24 h, Statut, Catégorie, Note.
• « Déclarée » veut dire VOULUE PAR QUELQU'UN, pas « livrée dans le dépôt ». Cinq déclarants,
  et la colonne dit lequel : ce dépôt (un fichier livré l'émet), le démon (une sonde l'observe),
  le produit (il l'agrège), un connecteur configuré, ou L'EXPLOITANT de cette installation.
• Badge « non déclarée » = personne ne l'a voulue, pas même un humain d'ici : un signal à
  examiner, PAS un défaut de collecte. Une sonde installée hors de ce dépôt est aussi légitime
  qu'une autre — un éditeur la déclare (persistant, réversible, audité), et l'inventaire dit
  ensuite QUI l'a déclarée et QUAND. Cette provenance ne bouge plus : poser une note ou un
  libellé ne réécrit pas le nom du déclarant.
• CADENCE — trois réponses distinctes, jamais confondues :
  continu · N     un point est attendu tous les N → au-delà de 3 cycles, « en retard »
  événementiel    pas de cadence PAR NATURE (le débit dépend d'une activité extérieure)
  aucune cadence déclarée   personne ne l'a dite : un blanc, pas un défaut → jamais « en retard »
  Là où AUCUNE sonde du démon ne déclare de cadence, un éditeur peut la déclarer (Actions →
  « déclarer la cadence »), et la retirer. Là où une sonde en déclare une, elle fait foi et le
  geste est refusé plutôt qu'accepté puis ignoré.
• Déclarer une cadence ne crée AUCUNE alerte : elle change le mot affiché ici et dans Fraîcheur.
  Le dead-man's-switch (« Capteur muet ») reste celui des sondes du démon.
• Statut = même dérivation que Fraîcheur (frais / calme / en retard / muet).
• Les métadonnées d'affichage sont éditables (editor+), sans effet sur la collecte.` },
    en: { title: `Ingestion sources`, body:
`Inventory of every ingested data source.
• Columns: Declared (by whom), Cadence, Last seen, 24h volume, Status, Category, Note.
• "Declared" means WANTED BY SOMEONE, not "shipped in the repository". Five declarers, and the
  column says which one: this repository (a shipped file emits it), the daemon (a probe observes
  it), the product (it aggregates it), a configured connector, or THIS DEPLOYMENT'S OPERATOR.
• "not declared" badge = nobody wanted it, not even a human here: a signal to review, NOT a
  collection fault. A probe installed outside this repository is as legitimate as any other —
  an editor declares it (persistent, reversible, audited), and the inventory then says WHO
  declared it and WHEN. That provenance no longer moves: setting a note or a label does not
  rewrite the declarer's name.
• CADENCE — three distinct answers, never conflated:
  continuous · N   a datum is expected every N → beyond 3 cycles, "late"
  event-driven     no cadence BY NATURE (the rate depends on outside activity)
  no declared cadence   nobody stated one: a blank, not a fault → never "late"
  Where NO daemon probe declares a cadence, an editor may declare one (Actions → "declare the
  cadence") and withdraw it. Where a probe does declare one, it prevails and the gesture is
  refused rather than accepted then ignored.
• Declaring a cadence creates NO alert: it changes the word shown here and in Freshness. The
  dead-man's-switch ("Mute probe") remains the daemon probes'.
• Status = same derivation as Freshness (fresh / quiet / late / mute).
• Display metadata is editable (editor+), no effect on collection.` },
  },
  connectors: {
    fr: { title: `Connecteurs de sources (PULL)`, body:
`Sources externes interrogées périodiquement (réservé à l'administrateur).
• Microsoft Defender (Graph Security API, OAuth2) : 1er connecteur.
• Le daemon PULL les alertes et les normalise au schéma event.
• Le client secret est un credential chiffré, JAMAIS réaffiché (•••).
• Intervalle plancher 60 s ; Cold-start = fenêtre initiale au 1er pull.
• Créé désactivé : « Tester » la connexion, puis activer.` },
    en: { title: `Source connectors (PULL)`, body:
`External sources polled periodically (admin only).
• Microsoft Defender (Graph Security API, OAuth2): first connector.
• The daemon PULLs alerts and normalizes them to the event schema.
• The client secret is an encrypted credential, NEVER shown again (•••).
• Interval floor 60 s ; Cold-start = initial window on the first pull.
• Created disabled: "Test" the connection, then enable.` },
  },
  parsers: {
    fr: { title: `Parsers (extraction de champs)`, body:
`Extraient des champs du message via des groupes nommés regex (?<nom>…).
• Appliqués à l'ingestion, pour toutes les sources ; source=* = toutes.
• Effectifs sur les NOUVEAUX events ; rétroactif via ↻ Réappliquer.
• Ou à la volée dans une recherche : | rex message "(?<x>…)".
• Sens des IP : src_ip = initiateur (attaquant), dst_ip = cible.
• « Tester » vérifie le motif sur une ligne d'exemple.` },
    en: { title: `Parsers (field extraction)`, body:
`Extract fields from the message via named regex groups (?<name>…).
• Applied at ingestion, for all sources ; source=* = all.
• Effective on NEW events ; retroactive via ↻ Re-apply.
• Or on the fly in a search: | rex message "(?<x>…)".
• IP direction: src_ip = initiator (attacker), dst_ip = target.
• "Test" checks the pattern against a sample line.` },
  },
  processors: {
    fr: { title: `Processeur d'ingest`, body:
`Des règles ORDONNÉES évaluées AVANT l'indexation : décider ce que l'on n'indexe PAS
(premier levier de rétention). Réservé admin.
• Une règle = un prédicat « champ opérateur valeur » (champs : category, source,
  severity, host, src_ip, dst_ip, url, message, fields.<clé> ; opérateurs : eq, ne,
  contains, regex, any = tout événement) → une action :
  - drop : n'indexe pas (compté « non-indexé (policy) ») ;
  - mask : masque un champ (argument = le champ, ex. message ou fields.<clé>) ;
  - route : pose l'environnement / la classe de rétention (argument = la cible) ;
  - sample : garde 1 événement sur N (argument = N).
• L'ordre (#) est l'ordre d'évaluation ; chaque règle a son interrupteur « active ».
• NON-SILENCE : la barre compte non-indexés, droppés, masqués, routés, échantillonnés ;
  chaque règle porte ses compteurs (matched / drop / mask / route / sample-out).
• Une règle invalide est IGNORÉE et signalée (fail-safe : les événements concernés sont
  indexés inchangés). Supprimer une règle est confirmé : ce qu'elle filtrait revient.
• Sans règle, l'ingestion est inchangée (tout événement est indexé).` },
    en: { title: `Ingest processor`, body:
`ORDERED rules evaluated BEFORE indexing: decide what NOT to index (the first
retention lever). Admin only.
• A rule = a predicate "field operator value" (fields: category, source, severity,
  host, src_ip, dst_ip, url, message, fields.<key>; operators: eq, ne, contains,
  regex, any = every event) → an action:
  - drop: do not index (counted "not indexed (policy)");
  - mask: mask a field (argument = the field, e.g. message or fields.<key>);
  - route: set the environment / retention class (argument = the target);
  - sample: keep 1 event out of N (argument = N).
• The order (#) is the evaluation order; each rule has its own "active" switch.
• NON-SILENCE: the bar counts not-indexed, dropped, masked, routed, sampled-out;
  each rule carries its counters (matched / drop / mask / route / sample-out).
• An invalid rule is IGNORED and flagged (fail-safe: the events it targets are indexed
  unchanged). Deleting a rule is confirmed: what it filtered comes back.
• Without any rule, ingest is unchanged (every event is indexed).` },
  },
  lookups: {
    fr: { title: `Lookups (tables d'enrichissement)`, body:
`Table de référence nommée : clé -> colonnes, pour enrichir les events.
• Utilisée en GXQL : lookup <nom> <champ-clé> [OUTPUT cols] (LEFT JOIN).
• Ex : lookup geoip src_ip OUTPUT country ajoute le pays à chaque event.
• Lignes = collage JSON (tableau d'objets) OU CSV (en-têtes + lignes) ; l'upload REMPLACE tout le contenu.
• Lecture pour tous ; création / suppression = éditeur ou admin.` },
    en: { title: `Lookups (enrichment tables)`, body:
`Named reference table: key -> columns, to enrich events.
• Used in GXQL: lookup <name> <key-field> [OUTPUT cols] (LEFT JOIN).
• E.g. lookup geoip src_ip OUTPUT country adds the country to each event.
• Rows = paste as JSON (array of objects) OR CSV (headers + rows) ; upload REPLACES the whole content.
• Read for everyone ; create / delete = editor or admin.` },
  },
  dataaccess: {
    fr: { title: `Accès données (DLP / gouvernance)`, body:
`Gouvernance d'accès en LECTURE SEULE (style Varonis) — pas de DLP de contenu.
• « Qui touche quoi » : accès aux données (source dataaccess).
• « Fichiers sensibles / tamper » : événements auditd critiques.
• « Intégrité (FIM) » : changements de fichiers surveillés.
• « ACL » et « RBAC Kubernetes » : droits fichiers et cluster.
• Aucune action possible ici (fenêtre d'analyse : 30 j).` },
    en: { title: `Data access (DLP / governance)`, body:
`READ-ONLY access governance (Varonis style) — not content DLP.
• "Who touches what": data access (source dataaccess).
• "Sensitive files / tamper": critical auditd events.
• "Integrity (FIM)": changes to watched files.
• "ACL" and "Kubernetes RBAC": file and cluster permissions.
• No action is possible here (analysis window: 30 days).` },
  },
  settings: {
    fr: { title: `Compte / Réglages`, body:
`Configuration initiale et gestion de votre compte.
• 1re installation : coller le token d'installation (log du daemon /
  setup-token.txt) puis définir l'utilisateur admin + mot de passe (≥ 12).
• Ensuite : changer votre mot de passe.` },
    en: { title: `Account / Settings`, body:
`Initial setup and management of your account.
• First install: paste the install token (daemon log / setup-token.txt)
  then set the admin user + password (≥ 12).
• Afterwards: change your password.` },
  },
  users: {
    fr: { title: `Comptes & accès (RBAC)`, body:
`Gestion des comptes (admin uniquement). Trois rôles :
• admin  : tout + gestion des comptes (+ SQL brut, connecteurs, rétention…).
• editor : lecture + écriture du contenu (détection, cases, lookups…).
• viewer : lecture seule.
Principe fail-closed : un rôle inconnu est traité en lecture seule.` },
    en: { title: `Accounts & access (RBAC)`, body:
`Account management (admin only). Three roles:
• admin  : everything + account mgmt (+ raw SQL, connectors, retention…).
• editor : read + write content (detection, cases, lookups…).
• viewer : read only.
Fail-closed: an unknown role is treated as read-only.` },
  },
  tokens: {
    fr: { title: `Jetons (agent & HEC)`, body:
`Un jeton authentifie une MACHINE (Bearer) sans mot de passe partagé. Réservé admin :
la garde est serveur (GET/POST/DELETE /api/tokens), la console n'est qu'un pendant
du CLI « plume-daemon token ».
• Créer (« + Nouveau jeton ») : la fenêtre nomme la conséquence AVANT les champs —
  une crédence d'accès naît, tout porteur du secret pourra écrire des événements.
  - nom : lettres, chiffres, . _ - uniquement ;
  - type : agent (ingestion + réponse, Bearer) ou HEC (forwarder compatible Splunk
    HTTP Event Collector → POST /services/collector, en-tête « Authorization: Splunk <jeton> ») ;
  - portée : machine = lié à UN hôte attesté (le responder n'agit que sur lui) ;
    relais = forwarder multi-hôtes, l'hôte est DÉCLARÉ par l'émetteur, NON attesté,
    et le jeton peut écrire sous n'importe quel nom d'hôte — à choisir les yeux ouverts ;
  - hôte lié : requis pour « machine », vide pour « relais » (le serveur refuse
    « ni hôte ni relais »).
• Le SECRET est montré UNE SEULE FOIS, à la création (boîte de copie ; pour HEC, un
  extrait curl prêt à coller). Seule son empreinte SHA-256 est conservée : la fenêtre
  fermée, il est irrécupérable — il faut alors créer un autre jeton.
• La liste montre nom, type, hôte lié (ou « relais — hôte non attesté »), création et
  dernier usage.
• Révoquer (✕, confirmé) : l'agent ou le forwarder porteur perd l'accès immédiatement ;
  un jeton révoqué ne se réactive pas, on en provisionne un autre.` },
    en: { title: `Tokens (agent & HEC)`, body:
`A token authenticates a MACHINE (Bearer) without a shared password. Admin only:
the guard is server-side (GET/POST/DELETE /api/tokens); the console mirrors the
« plume-daemon token » CLI.
• Create ("+ New token"): the dialog names the consequence BEFORE the fields —
  an access credential is born, any holder of the secret can write events.
  - name: letters, digits, . _ - only;
  - kind: agent (ingest + response, Bearer) or HEC (Splunk-compatible HTTP Event
    Collector forwarder → POST /services/collector, header "Authorization: Splunk <token>");
  - scope: machine = bound to ONE attested host (the responder only acts on it);
    relay = multi-host forwarder, the host is DECLARED by the sender, NOT attested,
    and the token may write under any host name — choose it with open eyes;
  - bound host: required for "machine", empty for "relay" (the server refuses
    "neither host nor relay").
• The SECRET is shown ONCE, at creation (copy box; for HEC, a ready-to-paste curl
  snippet). Only its SHA-256 fingerprint is stored: once the dialog is closed it is
  unrecoverable — create another token instead.
• The list shows name, kind, bound host (or "relay — host not attested"), creation
  and last use.
• Revoke (✕, confirmed): the agent or forwarder holding it loses access immediately;
  a revoked token is never re-enabled, provision another one.` },
  },
  notifiers: {
    fr: { title: `Canaux de notification`, body:
`Où envoyer les alertes qui atteignent une sévérité minimale.
• Types : ntfy, webhook, email (SMTP).
• Sévérité min = seuil à partir duquel le canal notifie.
• URL + config JSON selon le type (ex. SMTP : from / to / user / pass).` },
    en: { title: `Notification channels`, body:
`Where to send alerts that reach a minimum severity.
• Types: ntfy, webhook, email (SMTP).
• Min severity = threshold above which the channel notifies.
• URL + JSON config per type (e.g. SMTP: from / to / user / pass).` },
  },
  retention: {
    fr: { title: `Rétention des données`, body:
`Durées de conservation (admin). RÉDUIRE une durée est DESTRUCTIF :
les données plus anciennes sont purgées au prochain cycle horaire.
• 5 durées : Événements, Snapshots, Alertes closes, Rollups, Métriques brutes.
• Chaque durée est bornée par un plancher et un plafond.
• Chaque enregistrement confirme en nommant la conséquence : une baisse purge
  (compte + ancienneté affichés), une hausse retient plus longtemps (disque).
• Tout changement est inscrit au journal d'audit.
• Les alertes ouvertes ne sont JAMAIS purgées.` },
    en: { title: `Data retention`, body:
`Retention durations (admin). REDUCING a duration is DESTRUCTIVE:
older data is purged on the next hourly cycle.
• 5 durations: Events, Snapshots, Closed alerts, Rollups, Raw metrics.
• Each duration is bounded by a floor and a ceiling.
• Every save confirms by naming the consequence: a decrease purges (count +
  age shown), an increase retains longer (disk).
• Every change is written to the audit ledger.
• Open alerts are NEVER purged.` },
  },
  suppressions: {
    fr: { title: `Suppressions & whitelists`, body:
`Un seul écran pour TOUT ce qui filtre, mute ou exclut (admin).
• Registre du démon : chaque exclusion avec son type — display-only (de-bruite un
  panneau), collection-reducing (réduit l'ingestion, lecture seule ici), host
  (frontière hôte, lecture seule). Opérateur / self se modifient et se réinitialisent.
• Silences d'alertes : l'administrateur les CRÉE, les MODIFIE et les LÈVE ici.
  Un silence mute les notifications des alertes qui correspondent à ses matchers
  (severity, mitre, host, source, env, tag) jusqu'à son expiration ; les alertes
  restent stockées et visibles. Durée bornée : jamais permanent. Chaque geste est audité.
• Collecteurs hôte et firewall : filtres auto-reportés, lecture seule (le contrôle
  reste à la frontière hôte — surfacer n'est pas piloter).` },
    en: { title: `Suppressions & whitelists`, body:
`One screen for EVERYTHING that filters, mutes or excludes (admin).
• Daemon registry: each exclusion with its type — display-only (declutters a panel),
  collection-reducing (reduces ingest, read-only here), host (host boundary,
  read-only). Operator / self can be edited and reset.
• Alert silences: the administrator CREATES, EDITS and LIFTS them here. A silence
  mutes notifications for alerts matching its matchers (severity, mitre, host,
  source, env, tag) until it expires; alerts stay stored and visible. Bounded
  duration: never permanent. Every gesture is audited.
• Host collectors and firewall: self-reported filters, read-only (control stays at
  the host boundary — surfacing is not steering).` },
  },
  ledger: {
    fr: { title: `Journal d'audit`, body:
`Chaîne d'audit inviolable (hash chaîné) des changements de config / rétention.
• Lecture seule : aucune entrée ne peut être modifiée ni supprimée ici.
• Choisir le nombre d'entrées affichées.
• (Multi-tenant) sous-bloc : accès opérateur super-admin + admin de tenant.` },
    en: { title: `Audit ledger`, body:
`Tamper-evident audit chain (hash-chained) of config / retention changes.
• Read-only: no entry can be edited or deleted here.
• Choose the number of entries displayed.
• (Multi-tenant) sub-block: super-admin operator access + tenant admin.` },
  },
  tenants: {
    fr: { title: `Tenants (multi-tenant)`, body:
`Espaces clients isolés (une base chiffrée dédiée par tenant).
• Créer / suspendre / détruire = super-admin plateforme.
• La destruction est une DESTRUCTION CRYPTOGRAPHIQUE irréversible
  (retaper le nom pour confirmer).
• Un admin de tenant gère uniquement les accès de son tenant.
• Onglet visible en mode multi-tenant seulement (masqué en mode 0).` },
    en: { title: `Tenants (multi-tenant)`, body:
`Isolated client spaces (a dedicated encrypted DB per tenant).
• Create / suspend / destroy = platform super-admin.
• Destruction is an irreversible CRYPTOGRAPHIC ERASURE
  (retype the name to confirm).
• A tenant admin manages only their own tenant's access.
• Tab visible in multi-tenant mode only (hidden in mode 0).` },
  },
};
