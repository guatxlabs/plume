// help.js — AIDE IN-APP (documentation contextuelle) extraite de app.js (audit H1 : 1re découpe, triviale).
// 100% statique, WEB-ONLY : aucun appel réseau, aucun daemon. Contient les registres bilingues
// (HELP / HELP_INDEX / GLOSSARY / HELP_SHORTCUTS), les modales d'aide (openHelpBox / openHelpModal /
// openFreshnessHelp), la page « Aide » (renderHelpGuide) et le handler délégué .vhelp. Code relocalisé
// VERBATIM depuis app.js -> comportement identique. app.js importe renderHelpGuide + openHelpModal +
// openFreshnessHelp (le câblage #qhelp / #fresh-help et la route 'help' restent dans app.js).
import { $, LANG, ic } from './core.js';
import { uiIsAdmin, multiTenantMode } from './multitenant.js';

function openHelpBox(title, body) {
  const ov = document.createElement('div'); ov.className = 'modal-ov';
  const box = document.createElement('div'); box.className = 'modal helpmodal';
  const h = document.createElement('h3'); h.textContent = title;
  const pre = document.createElement('pre'); pre.className = 'helpref'; pre.textContent = body;   // textContent -> anti-XSS
  const act = document.createElement('div'); act.className = 'modal-act';
  const btn = document.createElement('button'); btn.type = 'button'; btn.className = 'm-cancel'; btn.textContent = LANG === 'en' ? 'Close' : 'Fermer';
  act.appendChild(btn); box.append(h, pre, act); ov.appendChild(box); document.body.appendChild(ov);
  const close = () => { document.removeEventListener('keydown', onKey); ov.remove(); };
  const onKey = e => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', onKey);
  ov.onclick = e => { if (e.target === ov) close(); };
  btn.onclick = close;
}
// registre statique { clé : {fr:{title,body}, en:{title,body}} | {fn} }. body = string multiligne (pre).
const HELP = {
  freshness: { fn: () => openFreshnessHelp() },
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
    fr: { title: `Recherche & Explore (Plume panel)`, body:
`Le cœur de l'investigation : une requête = une recherche dans les logs.
• Champ requête : SOQL (search … | … ) ou SQL brut (admin). Bouton « ? Aide ».
• Fenêtre temporelle propre (presets jusqu'à 1 an + intervalle précis).
• Visualisation : Table / Barres / Courbe / Stat ; pagination (n/page).
• Résultats : timeline, « champs intéressants » (à gauche), liste d'events.
• Drilldown : cliquer une valeur relance la recherche filtrée (fil d'Ariane).
• Sur une IP : puces bannir / débannir ; sur un event : ouvrir un case.
• « Panneau » enregistre la requête (réutilisable dans un Dashboard).` },
    en: { title: `Search & Explore (Plume panel)`, body:
`The heart of investigation: one query = one search across the logs.
• Query box: SOQL (search … | … ) or raw SQL (admin). "? Help" button.
• Its own time window (presets up to 1 year + precise interval).
• Visualization: Table / Bar / Line / Stat ; pagination (n/page).
• Results: timeline, "interesting fields" (left), event list.
• Drilldown: click a value to re-run the search filtered (breadcrumb).
• On an IP: ban / unban chips ; on an event: open a case.
• "Panel" saves the query (reusable inside a Dashboard).` },
  },
  soql: {
    fr: { title: `SOQL — référence des requêtes`, body:
`PIPELINE :  search <filtres>  | transform  | transform  | …

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
    en: { title: `SOQL — query reference`, body:
`PIPELINE :  search <filters>  | transform  | transform  | …

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
• Acquitter (une, ou « Tout acquitter ») = marquer comme vue / traitée.
• Filtres par technique MITRE et par source.
• Puces : ouvrir un case depuis l'alerte, ou bannir l'IP en cause.` },
    en: { title: `Alerts`, body:
`Queue of alerts raised by the detection rules.
• An alert has a status: "new" then "acknowledged" (never deleted).
• Acknowledge (one, or "Ack all") = mark as seen / handled.
• Filters by MITRE technique and by source.
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
`Tableaux de bord composés de panneaux (une requête SOQL enregistrée).
• Vue = un regroupement de dashboards (créer / renommer / supprimer une vue).
• + Dashboard ajoute un tableau ; + Panneau (depuis Explore) ajoute une tuile.
• Édition : glisser / redimensionner les panneaux ; Rafraîchir recharge tout.` },
    en: { title: `Dashboards`, body:
`Boards made of panels (a saved SOQL query).
• View = a grouping of dashboards (create / rename / delete a view).
• + Dashboard adds a board ; + Panel (from Explore) adds a tile.
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
• Cliquer une technique = pivot vers ses alertes.
• Lecture seule. Si la matrice est « indisponible », l'endpoint de couverture n'est pas encore déployé.` },
    en: { title: `ATT&CK matrix (coverage)`, body:
`MITRE ATT&CK coverage matrix: tactics as COLUMNS, techniques as CELLS.
• Green cell = COVERED technique (rules / alerts); deeper tint = denser coverage.
• Muted cell = BLIND SPOT (no detection) -> coverage gaps stand out (purple-team).
• The "r/a" counter = number of rules / alerts for the technique.
• Click a technique = pivot to its alerts.
• Read-only. If the matrix is "unavailable", the coverage endpoint is not deployed yet.` },
  },
  rules: {
    fr: { title: `Règles de détection`, body:
`Une règle exécute une requête qui renvoie UN nombre, à intervalle régulier.
• Condition + Seuil (ex. count > 10) : si vraie -> alerte à la Sévérité choisie.
• Sévérité : 1 low, 2 medium, 3 high, 4 critical.
• Type : SOQL (tous) ou SQL brut (réservé admin).
• Intervalle = fréquence d'exécution ; Fenêtre = plage de temps analysée.
• MITRE = technique Txxxx[.yyy] taguée (nourrit la Couverture ATT&CK).
• « Tester » évalue la requête sans créer d'alerte. « actif » (dés)active.` },
    en: { title: `Detection rules`, body:
`A rule runs a query returning ONE number, on a regular interval.
• Condition + Threshold (e.g. count > 10): if true -> alert at chosen Severity.
• Severity: 1 low, 2 medium, 3 high, 4 critical.
• Type: SOQL (everyone) or raw SQL (admin only).
• Interval = run frequency ; Window = analyzed time span.
• MITRE = tagged technique Txxxx[.yyy] (feeds ATT&CK Coverage).
• "Test" evaluates the query without creating an alert. "active" toggles it.` },
  },
  response: {
    fr: { title: `Réponse (playbooks & actions)`, body:
`Automatiser ou déclencher des ripostes. Enum FERMÉ des actions :
  ban_ip, unban_ip, kill_pid, stop_service.
• Mode Observation (vert) = propositions seulement, rien n'est exécuté.
• Mode ACTIF (rouge) = les playbooks exécutent la riposte automatiquement.
• Playbook : requête dont la 1re colonne = la cible + action (ban / kill / stop).
• Action manuelle : cible (IP / PID / service) + dry-run (simulation) ou RÉEL.
• dry-run coché par défaut ; les actions passent par une file d'approbation.` },
    en: { title: `Response (playbooks & actions)`, body:
`Automate or trigger responses. CLOSED enum of actions:
  ban_ip, unban_ip, kill_pid, stop_service.
• Observe mode (green) = proposals only, nothing is executed.
• ACTIVE mode (red) = playbooks run the response automatically.
• Playbook: a query whose 1st column = the target + action (ban / kill / stop).
• Manual action: target (IP / PID / service) + dry-run (simulation) or REAL.
• dry-run on by default ; actions go through an approval queue.` },
  },
  sources: {
    fr: { title: `Sources d'ingestion`, body:
`Inventaire (lecture seule) de toutes les sources de données ingérées.
• Colonnes : Attendu, Type, Dernier vu, volume 24 h, Statut, Catégorie, Note.
• Badge « inattendu » = source non déclarée dans les collecteurs connus
  (un signal à examiner, pas forcément un défaut).
• Les métadonnées d'affichage sont éditables par l'admin (sans effet sur la collecte).` },
    en: { title: `Ingestion sources`, body:
`Read-only inventory of every ingested data source.
• Columns: Expected, Type, Last seen, 24h volume, Status, Category, Note.
• "unexpected" badge = a source not declared among known collectors
  (a signal to review, not necessarily a fault).
• Display metadata is editable by admin (no effect on collection).` },
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
  lookups: {
    fr: { title: `Lookups (tables d'enrichissement)`, body:
`Table de référence nommée : clé -> colonnes, pour enrichir les events.
• Utilisée en SOQL : lookup <nom> <champ-clé> [OUTPUT cols] (LEFT JOIN).
• Ex : lookup geoip src_ip OUTPUT country ajoute le pays à chaque event.
• Lignes = collage JSON (tableau d'objets) OU CSV (en-têtes + lignes) ; l'upload REMPLACE tout le contenu.
• Lecture pour tous ; création / suppression = éditeur ou admin.` },
    en: { title: `Lookups (enrichment tables)`, body:
`Named reference table: key -> columns, to enrich events.
• Used in SOQL: lookup <name> <key-field> [OUTPUT cols] (LEFT JOIN).
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
  setup-token.txt) puis définir l'utilisateur admin + mot de passe (≥ 6).
• Ensuite : changer votre mot de passe.` },
    en: { title: `Account / Settings`, body:
`Initial setup and management of your account.
• First install: paste the install token (daemon log / setup-token.txt)
  then set the admin user + password (≥ 6).
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
• Toute baisse exige confirmation et est inscrite au journal d'audit.
• Les alertes ouvertes ne sont JAMAIS purgées.` },
    en: { title: `Data retention`, body:
`Retention durations (admin). REDUCING a duration is DESTRUCTIVE:
older data is purged on the next hourly cycle.
• 5 durations: Events, Snapshots, Closed alerts, Rollups, Raw metrics.
• Each duration is bounded by a floor and a ceiling.
• Any decrease needs confirmation and is written to the audit ledger.
• Open alerts are NEVER purged.` },
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
function openHelp(key) {
  const e = HELP[key]; if (!e) return;
  if (e.fn) { e.fn(); return; }
  const d = (LANG === 'en' && e.en) ? e.en : e.fr;
  openHelpBox(d.title, d.body);
}
// handler délégué unique : tout bouton .vhelp (dans n'importe quel en-tête) ouvre l'aide de sa vue.
// N'interfère pas avec #fresh-help / #qhelp (qui gardent leur onclick dédié et n'ont pas la classe .vhelp).
document.addEventListener('click', e => {
  const b = e.target.closest ? e.target.closest('.vhelp') : null;
  if (b) { e.preventDefault(); openHelp(b.dataset.help); }
});

// --- Espace « Aide » : sommaire des espaces (respecte admin/mtOnly) + référence SOQL + glossaire ---
// C9 — `icon` = clé ic() IDENTIQUE à l'icône de la sidebar de l'espace (cohérence visuelle nav <-> guide).
const HELP_INDEX = [
  { fr: "Vue d'ensemble", en: 'Overview', icon: 'home', items: [
    { k: 'firewall', fr: 'Firewall', en: 'Firewall' },
    { k: 'controls', fr: 'Contrôles', en: 'Controls' },
    { k: 'integrations', fr: 'Intégrations & hôtes', en: 'Integrations & hosts' },
    { k: 'freshness', fr: 'Fraîcheur des sources', en: 'Source freshness' },
  ] },
  { fr: 'Investigation', en: 'Investigation', icon: 'search', items: [
    { k: 'explore', fr: 'Recherche & Explore', en: 'Search & Explore' },
    { k: 'soql', fr: 'SOQL (référence)', en: 'SOQL (reference)' },
    { k: 'alerts', fr: 'Alertes', en: 'Alerts' },
    { k: 'cases', fr: 'Cases', en: 'Cases' },
  ] },
  { fr: 'Dashboards', en: 'Dashboards', icon: 'layout', items: [
    { k: 'dashboards', fr: 'Dashboards', en: 'Dashboards' },
  ] },
  { fr: 'Détection & Réponse', en: 'Detection & Response', icon: 'activity', items: [
    { k: 'coverage', fr: 'Couverture ATT&CK', en: 'ATT&CK coverage' },
    { k: 'attack', fr: 'Matrice ATT&CK', en: 'ATT&CK matrix' },
    { k: 'rules', fr: 'Règles de détection', en: 'Detection rules' },
    { k: 'response', fr: 'Réponse (playbooks & actions)', en: 'Response (playbooks & actions)' },
  ] },
  { fr: 'Données', en: 'Data', icon: 'database', items: [
    { k: 'sources', fr: 'Sources', en: 'Sources' },
    { k: 'fleet', fr: "Flotte d'agents", en: 'Agent fleet' },
    { k: 'connectors', fr: 'Connecteurs', en: 'Connectors', admin: true },
    { k: 'processors', fr: "Processeur d'ingest", en: 'Ingest processor', admin: true },
    { k: 'parsers', fr: 'Parsers', en: 'Parsers' },
    { k: 'lookups', fr: 'Lookups', en: 'Lookups' },
    { k: 'dataaccess', fr: 'Accès données (DLP)', en: 'Data access (DLP)' },
  ] },
  { fr: 'Administration', en: 'Administration', admin: true, icon: 'gear', items: [
    { k: 'settings', fr: 'Compte', en: 'Account' },
    { k: 'users', fr: 'Users', en: 'Users' },
    { k: 'notifiers', fr: 'Canaux', en: 'Channels' },
    { k: 'retention', fr: 'Rétention', en: 'Retention' },
    { k: 'ledger', fr: 'Audit', en: 'Audit' },
    { k: 'tenants', fr: 'Tenants', en: 'Tenants', mtOnly: true },
  ] },
];
// glossaire : { t: terme, fr, en }. Rendu en textContent ; définitions vérifiées contre le code.
const GLOSSARY = [
  { t: 'SOQL', fr: `Langage de recherche à pipeline (search … | transform …) compilé en SQL.`, en: `Pipeline search language (search … | transform …) compiled to SQL.` },
  { t: 'pipeline', fr: `Enchaînement search puis transformations séparées par des barres |.`, en: `Chain of search then transforms separated by | pipes.` },
  { t: 'search / filtre', fr: `1re étape : sélectionne les events (champ=valeur, joker*, =~regex, comparaisons).`, en: `First stage: selects events (field=value, wildcard*, =~regex, comparisons).` },
  { t: 'stats', fr: `Agrège (count, sum, avg, min, max, dc, values, list), éventuellement by champs.`, en: `Aggregates (count, sum, avg, min, max, dc, values, list), optionally by fields.` },
  { t: 'timechart', fr: `Comme stats mais par tranches de temps (série temporelle).`, en: `Like stats but per time bucket (time series).` },
  { t: 'where', fr: `Filtre APRÈS agrégation ; gère in / not in.`, en: `Filters AFTER aggregation ; supports in / not in.` },
  { t: 'rex', fr: `Extrait des champs du message via des groupes nommés regex (?<nom>…).`, en: `Extracts fields from the message via named regex groups (?<name>…).` },
  { t: 'eval', fr: `Crée une colonne calculée (eval x = expression).`, en: `Creates a computed column (eval x = expression).` },
  { t: 'lookup', fr: `Enrichit via une table de référence (LEFT JOIN) : lookup <nom> <clé> OUTPUT cols.`, en: `Enriches via a reference table (LEFT JOIN): lookup <name> <key> OUTPUT cols.` },
  { t: 'agrégat', fr: `Fonction de stats : count, sum, avg, min, max, dc (distinct), values, list.`, en: `Stats function: count, sum, avg, min, max, dc (distinct), values, list.` },
  { t: 'FTS / plein-texte', fr: `Recherche d'un mot nu dans le message (index plein-texte).`, en: `Bare-word search in the message (full-text index).` },
  { t: 'MITRE ATT&CK', fr: `Référentiel de techniques d'attaque ; une technique = Txxxx[.yyy].`, en: `Catalog of attack techniques ; a technique = Txxxx[.yyy].` },
  { t: 'couverture', fr: `Vue des techniques ATT&CK effectivement détectées (angles morts).`, en: `View of ATT&CK techniques actually detected (blind spots).` },
  { t: 'managed', fr: `Origine d'un contenu : builtin (seed), overlay (fichier), perso (créé dans l'UI).`, en: `Content origin: builtin (seed), overlay (file), custom (created in the UI).` },
  { t: 'builtin', fr: `Contenu par défaut non supprimable ; se désactive via « actif ».`, en: `Default content, not deletable ; disable via "active".` },
  { t: 'overlay', fr: `Contenu géré par fichier (config.d), réimposé au démarrage.`, en: `File-managed content (config.d), re-applied at boot.` },
  { t: 'event', fr: `Ligne de log normalisée et ingérée (schéma event).`, en: `Normalized, ingested log line (event schema).` },
  { t: 'alerte', fr: `Déclenchée par une règle ; statut nouveau -> acquittée (jamais supprimée).`, en: `Raised by a rule ; status new -> acknowledged (never deleted).` },
  { t: 'acquitter', fr: `Marquer une alerte comme vue / traitée (sans la supprimer).`, en: `Mark an alert as seen / handled (without deleting it).` },
  { t: 'case', fr: `Dossier d'incident : statut, priorité, SLA, assignation, timeline.`, en: `Incident folder: status, priority, SLA, assignment, timeline.` },
  { t: 'priorité (P1–P4)', fr: `P1 critique, P2 haute, P3 moyenne, P4 basse.`, en: `P1 critical, P2 high, P3 medium, P4 low.` },
  { t: 'SLA / RETARD', fr: `Échéance de traitement ; « RETARD » = échéance dépassée.`, en: `Handling due date ; "OVERDUE" = past due.` },
  { t: 'sévérité', fr: `0 info, 1 low, 2 medium, 3 high, 4 critical (règles : 1 à 4).`, en: `0 info, 1 low, 2 medium, 3 high, 4 critical (rules: 1 to 4).` },
  { t: 'règle de détection', fr: `Requête renvoyant un nombre + condition/seuil -> alerte, à intervalle régulier.`, en: `Query returning a number + condition/threshold -> alert, on a regular interval.` },
  { t: 'seuil / condition', fr: `Comparaison (>, >=, <, <=, ==, !=) du résultat au seuil.`, en: `Comparison (>, >=, <, <=, ==, !=) of the result to the threshold.` },
  { t: 'intervalle / fenêtre', fr: `Intervalle = fréquence d'exécution ; fenêtre = plage de temps analysée.`, en: `Interval = run frequency ; window = analyzed time span.` },
  { t: 'playbook', fr: `Détection -> réponse automatique (1re colonne = cible).`, en: `Detection -> automatic response (1st column = target).` },
  { t: 'action', fr: `Riposte : ban_ip, unban_ip, kill_pid, stop_service (enum fermé).`, en: `Response: ban_ip, unban_ip, kill_pid, stop_service (closed enum).` },
  { t: 'dry-run / RÉEL', fr: `dry-run = simulation (rien n'est exécuté) ; RÉEL = exécuté.`, en: `dry-run = simulation (nothing runs) ; REAL = executed.` },
  { t: 'approbation', fr: `File d'attente : une action doit être approuvée avant exécution.`, en: `Queue: an action must be approved before it runs.` },
  { t: 'mode observe/active', fr: `Observation = propositions seulement ; ACTIF = ripostes automatiques.`, en: `Observe = proposals only ; ACTIVE = automatic responses.` },
  { t: 'RBAC', fr: `Rôles : admin (tout), editor (écriture contenu), viewer (lecture seule).`, en: `Roles: admin (all), editor (write content), viewer (read only).` },
  { t: 'SQL brut', fr: `Requête SQL directe, réservée à l'admin (les autres utilisent SOQL).`, en: `Direct SQL query, admin only (others use SOQL).` },
  { t: 'tenant', fr: `Espace client isolé (base chiffrée dédiée).`, en: `Isolated client space (dedicated encrypted DB).` },
  { t: 'environnement', fr: `prod / staging… filtrant les vues d'un tenant.`, en: `prod / staging… filtering a tenant's views.` },
  { t: 'mode 0 / mode 1', fr: `Mode 0 = mono-tenant (switchers cachés) ; mode 1 = multi-tenant.`, en: `Mode 0 = single-tenant (switchers hidden) ; mode 1 = multi-tenant.` },
  { t: 'rétention', fr: `Durée de conservation des données ; réduire = purge destructive.`, en: `Data keep duration ; reducing = destructive purge.` },
  { t: 'snapshot / rollup', fr: `Snapshot = état capturé ; rollup = métrique agrégée pré-calculée.`, en: `Snapshot = captured state ; rollup = pre-aggregated metric.` },
  { t: 'fraîcheur', fr: `Santé de collecte d'une source : frais, calme, dégradé, muet.`, en: `A source's collection health: fresh, quiet, degraded, mute.` },
  { t: 'type de source', fr: `continu, périodique, événement, dormant (cadence attendue).`, en: `stream, periodic, event, dormant (expected cadence).` },
  { t: 'source inattendue', fr: `Source non déclarée dans les collecteurs connus (à examiner).`, en: `Source not declared among known collectors (to review).` },
  { t: 'parseur', fr: `Extraction de champs par regex à groupes nommés, à l'ingestion.`, en: `Field extraction via named-group regex, at ingestion.` },
  { t: 'src_ip / dst_ip', fr: `src_ip = initiateur (attaquant) ; dst_ip = cible.`, en: `src_ip = initiator (attacker) ; dst_ip = target.` },
  { t: 'connecteur (PULL)', fr: `Source externe interrogée périodiquement (ex. Defender).`, en: `External source polled periodically (e.g. Defender).` },
  { t: 'credential', fr: `Secret chiffré au repos, jamais réaffiché (•••).`, en: `Secret encrypted at rest, never shown again (•••).` },
  { t: 'audit / ledger', fr: `Journal inviolable (hash chaîné) des changements, lecture seule.`, en: `Tamper-evident (hash-chained) change log, read-only.` },
  { t: 'DLP / gouvernance', fr: `Qui accède à quoi + intégrité + droits, en lecture seule.`, en: `Who accesses what + integrity + permissions, read-only.` },
  { t: 'dashboard / panneau', fr: `Panneau = requête SOQL enregistrée ; vue = regroupement de dashboards.`, en: `Panel = saved SOQL query ; view = grouping of dashboards.` },
  { t: 'fuseau / UTC', fr: `Stockage toujours en UTC ; affichage selon le fuseau choisi.`, en: `Always stored in UTC ; displayed per the chosen timezone.` },
  { t: 'notifier / canal', fr: `Destination d'alerte : ntfy, webhook, email.`, en: `Alert destination: ntfy, webhook, email.` },
];
// C9 — raccourcis clavier/UI RÉELS (vérifiés dans le code : #q Enter, #sql Ctrl/⌘+Enter, Échap ferme les
// modales, bouton ? d'en-tête). Statique — documente le comportement existant, n'ajoute aucune fonctionnalité.
const HELP_SHORTCUTS = [
  { key: 'Entrée', fr: `Barre de recherche (en-tête) : lance la recherche dans l'Explore.`, en: `Header search bar: run the search in Explore.` },
  { key: 'Ctrl / ⌘ + Entrée', fr: `Dans l'éditeur de requête (Explore) : exécute la requête.`, en: `In the query editor (Explore): run the query.` },
  { key: 'Échap', fr: `Ferme la fenêtre d'aide, une modale ou un formulaire ouvert.`, en: `Close the help window, a modal or an open form.` },
  { key: '?', fr: `Bouton dans chaque en-tête de vue : ouvre l'aide de cette vue.`, en: `Button in each view header: opens that view's help.` },
];
function renderHelpGuide() {
  const host = $('#help-body'); if (!host) return;
  const en = LANG === 'en';
  host.replaceChildren();
  // C9 — mini-sommaire COLLANT (Espaces · SOQL · Glossaire · Raccourcis) : ancres internes, aucun réseau.
  const toc = document.createElement('nav'); toc.className = 'hg-toc'; toc.setAttribute('aria-label', en ? 'Guide contents' : 'Sommaire du guide');
  [['hg-espaces', en ? 'Spaces' : 'Espaces'], ['hg-soql', 'SOQL'], ['hg-gloss', en ? 'Glossary' : 'Glossaire'], ['hg-raccourcis', en ? 'Shortcuts' : 'Raccourcis']]
    .forEach(([id, lbl]) => {
      const a = document.createElement('button'); a.type = 'button'; a.className = 'hg-toclink'; a.textContent = lbl;
      a.onclick = () => { const t = document.getElementById(id); if (t) t.scrollIntoView({ behavior: 'smooth', block: 'start' }); };
      toc.appendChild(a);
    });
  host.appendChild(toc);
  const intro = document.createElement('p'); intro.className = 'muted'; intro.style.cssText = 'margin:0 0 16px;font-size:13px;line-height:1.5';
  intro.textContent = en
    ? "In-app guide to Plume. Click a topic to open its help, or use the “?” on any view header. Everything below is static — no query is run."
    : "Guide intégré de Plume. Cliquez un sujet pour ouvrir son aide, ou utilisez le “?” dans l'en-tête de chaque vue. Tout ici est statique — aucune requête n'est exécutée.";
  host.appendChild(intro);
  // ESPACES — sommaire groupé par les 6 espaces, avec l'ICÔNE de la sidebar (respecte admin/mtOnly, comme la nav)
  const idxT = document.createElement('div'); idxT.className = 'fldname hg-anchor'; idxT.id = 'hg-espaces'; idxT.textContent = en ? 'Spaces & views' : 'Espaces & vues';
  host.appendChild(idxT);
  const idx = document.createElement('div'); idx.className = 'hg-idx hg-sec';
  HELP_INDEX.forEach(sp => {
    if (sp.admin && !uiIsAdmin()) return;
    const items = sp.items.filter(it => !(it.admin && !uiIsAdmin()) && !(it.mtOnly && !multiTenantMode()));
    if (!items.length) return;
    const box = document.createElement('div'); box.className = 'hg-space';
    const nm = document.createElement('div'); nm.className = 'fldname hg-spacehd';
    nm.innerHTML = ic(sp.icon || 'home') + '<span></span>';   // icône sidebar + nom (nom en textContent, anti-XSS)
    nm.querySelector('span').textContent = en ? sp.en : sp.fr;
    box.appendChild(nm);
    const links = document.createElement('div'); links.className = 'hg-links';
    items.forEach(it => {
      const b = document.createElement('button'); b.type = 'button'; b.className = 'hg-link'; b.textContent = en ? it.en : it.fr;
      b.onclick = () => openHelp(it.k); links.appendChild(b);
    });
    box.appendChild(links); idx.appendChild(box);
  });
  host.appendChild(idx);
  // SOQL — bloc COLLAPSIBLE « Référence » (exemples réels + accès à la référence complète)
  const ref = document.createElement('details'); ref.className = 'hg-ref hg-anchor hg-sec'; ref.id = 'hg-soql'; ref.open = true;
  const sum = document.createElement('summary'); sum.className = 'hg-refsum'; sum.textContent = en ? 'SOQL — Reference' : 'SOQL — Référence';
  ref.appendChild(sum);
  const sP = document.createElement('p'); sP.className = 'muted'; sP.style.cssText = 'margin:8px 0 8px;font-size:13px;line-height:1.5';
  sP.textContent = en ? 'Search language. Examples:' : 'Langage de recherche. Exemples :'; ref.appendChild(sP);
  const ex = document.createElement('pre'); ex.className = 'helpref'; ex.style.margin = '0 0 8px';
  ex.textContent = [
    'search source=ufw | stats count by src_ip | sort -count | head 10',
    'search source=sshd severity>=3 | stats count by src_ip | where count > 10',
    'search source=web | lookup geoip src_ip OUTPUT country',
  ].join('\n'); ref.appendChild(ex);
  const sBtn = document.createElement('button'); sBtn.type = 'button'; sBtn.className = 'hg-link'; sBtn.style.marginBottom = '4px';
  sBtn.textContent = en ? 'Open the full SOQL reference' : 'Ouvrir la référence SOQL complète';
  sBtn.onclick = () => openHelp('soql'); ref.appendChild(sBtn);
  host.appendChild(ref);
  // GLOSSAIRE filtrable
  const gT = document.createElement('div'); gT.className = 'fldname hg-anchor'; gT.id = 'hg-gloss'; gT.style.marginTop = '18px'; gT.textContent = en ? 'Glossary' : 'Glossaire'; host.appendChild(gT);
  const filter = document.createElement('input'); filter.className = 'hg-filter'; filter.type = 'search';
  filter.placeholder = en ? 'Filter terms…' : 'Filtrer les termes…'; host.appendChild(filter);
  const gl = document.createElement('div'); gl.className = 'hg-gloss';
  GLOSSARY.forEach(g => {
    const row = document.createElement('div'); row.className = 'hg-term';
    const t = document.createElement('b'); t.textContent = g.t;
    const d = document.createElement('span'); d.textContent = en ? g.en : g.fr;
    row.append(t, d); gl.appendChild(row);
  });
  host.appendChild(gl);
  filter.addEventListener('input', () => {
    const q = filter.value.trim().toLowerCase();
    gl.querySelectorAll('.hg-term').forEach(r => { r.hidden = !!q && !r.textContent.toLowerCase().includes(q); });
  });
  // RACCOURCIS — interactions réelles (statique, même chrome que le glossaire)
  const rT = document.createElement('div'); rT.className = 'fldname hg-anchor'; rT.id = 'hg-raccourcis'; rT.style.marginTop = '18px'; rT.textContent = en ? 'Shortcuts' : 'Raccourcis'; host.appendChild(rT);
  const rl = document.createElement('div'); rl.className = 'hg-gloss';
  HELP_SHORTCUTS.forEach(s => {
    const row = document.createElement('div'); row.className = 'hg-term';
    const t = document.createElement('b'); t.textContent = s.key;
    const d = document.createElement('span'); d.textContent = en ? s.en : s.fr;
    row.append(t, d); rl.appendChild(row);
  });
  host.appendChild(rl);
}

// aide SOQL (modal) — référence des requêtes directement dans l'UI
function openHelpModal() {
  const ov = document.createElement('div'); ov.className = 'modal-ov';
  const box = document.createElement('div'); box.className = 'modal helpmodal';
  const en = LANG === 'en';
  const h = document.createElement('h3'); h.textContent = en ? 'Help — queries (SOQL)' : 'Aide — requêtes (SOQL)';
  const pre = document.createElement('pre'); pre.className = 'helpref';
  pre.textContent = (en ? [
    'PIPELINE :  search <filters>  | stats …  | where …  | sort …  | head N  | table *',
    '',
    'FILTERS (search) :',
    '  field=val   field:val          equals         source=ufw   dport=993   proto=TCP',
    '  field=val*                     wildcard       src_ip=203.0.113*',
    '  field=~regex                   regex          message=~"BLOCK"',
    '  field>v  field<v  >=  <=        comparison     severity>=3   dport>1000',
    '  a_word                         full-text on the message',
    '',
    'TRANSFORMS (after a |) :',
    '  | stats count [by f1,f2]       count, grouped    by dport   by dir   by src_ip',
    '  | stats sum(f)|avg(f)|min(f)|max(f)|dc(f)',
    '  | timechart span=1h count [by f]   time series (buckets)',
    '  | where f op v                 filter AFTER aggregate   where count>50',
    '  | rex <field> "(?<name>…)"      extract named groups into COLUMNS (regex)',
    '       e.g. search source=mail | rex message "rip=(?<ip>[\\d.]+).*user=<(?<u>[^>]+)>" | table u, ip',
    '  | sort [-]f                    sort ( - = descending )   sort -count',
    '  | head N      | fields a,b      | table *',
    '',
    'GROUPABLE fields (who/where/what/when) :',
    '  src_ip dst_ip dport lport proto dir proc user action jail scope host source category severity ts',
    '',
    'EXAMPLES (correlation) :',
    '  search source=ufw | stats count by src_ip | sort -count | head 10',
    '  search source=conntrack dir=inbound scope=external | stats count by dport',
    '  search src_ip=203.0.113.7 | sort -ts        (everything on one IP: ufw + conntrack + bans…)',
    '',
    'Time: stored in UTC; display follows the time-zone selector (Browser / Europe-Paris / UTC).',
  ] : [
    'PIPELINE :  search <filtres>  | stats …  | where …  | sort …  | head N  | table *',
    '',
    'FILTRES (search) :',
    '  field=val   field:val          égalité        source=ufw   dport=993   proto=TCP',
    '  field=val*                     joker          src_ip=203.0.113*',
    '  field=~regex                   regex          message=~"BLOCK"',
    '  field>v  field<v  >=  <=        comparaison    severity>=3   dport>1000',
    '  un_mot                         plein-texte sur le message',
    '',
    'TRANSFORMATIONS (après un |) :',
    '  | stats count [by f1,f2]       compte, groupé    by dport   by dir   by src_ip',
    '  | stats sum(f)|avg(f)|min(f)|max(f)|dc(f)',
    '  | timechart span=1h count [by f]   série temporelle (buckets)',
    '  | where f op v                 filtre APRÈS agrégat   where count>50',
    '  | rex <champ> "(?<nom>…)"       extrait des groupes nommés en COLONNES (regex)',
    '       ex: search source=mail | rex message "rip=(?<ip>[\\d.]+).*user=<(?<u>[^>]+)>" | table u, ip',
    '  | sort [-]f                    tri ( - = décroissant )   sort -count',
    '  | head N      | fields a,b      | table *',
    '',
    'CHAMPS groupables (qui/où/quoi/quand) :',
    '  src_ip dst_ip dport lport proto dir proc user action jail scope host source category severity ts',
    '',
    'EXEMPLES (corrélation) :',
    '  search source=ufw | stats count by src_ip | sort -count | head 10',
    '  search source=conntrack dir=inbound scope=external | stats count by dport',
    '  search src_ip=203.0.113.7 | sort -ts        (tout sur une IP : ufw + conntrack + bans…)',
    '',
    'Heure : stockée en UTC ; l’affichage suit le sélecteur 🕓 (Navigateur / Europe-Paris / UTC).',
  ]).join('\n');
  const act = document.createElement('div'); act.className = 'modal-act';
  const btn = document.createElement('button'); btn.type = 'button'; btn.className = 'm-cancel'; btn.textContent = 'Fermer';
  act.appendChild(btn); box.append(h, pre, act); ov.appendChild(box); document.body.appendChild(ov);
  const close = () => { document.removeEventListener('keydown', onKey); ov.remove(); };
  const onKey = e => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', onKey);
  ov.onclick = e => { if (e.target === ov) close(); };
  btn.onclick = close;
}

// aide in-app de la carte Fraîcheur : explique état (frais/calme/muet) + TYPE de source -> pourquoi
// certaines sources sont "calme" des heures sans que ce soit une panne (documenté aussi dans le README).
function openFreshnessHelp() {
  const ov = document.createElement('div'); ov.className = 'modal-ov';
  const box = document.createElement('div'); box.className = 'modal helpmodal';
  const en = LANG === 'en';
  const h = document.createElement('h3'); h.textContent = en ? 'Help — Source freshness' : 'Aide — Fraîcheur des sources';
  const pre = document.createElement('pre'); pre.className = 'helpref';
  pre.textContent = (en ? [
    'STATE = COLLECTION HEALTH (not activity) :',
    '  ● fresh   data received < 15 min ago',
    '  ● quiet   collecting OK but low-activity source — NOT a delay',
    '  ● down    INGESTION BROKEN: no data (any source) for > 10 min',
    '            └─ the only alert state (network / corruption / collection stopped).',
    '',
    'A source can be "quiet" for hours with no problem: it depends on its NATURE.',
    'Age = time since the last DATA, not since the collector last ran',
    '(which runs on a timer and checks; it only emits if there is something new).',
    '',
    'Source TYPE (shown next to the name) :',
    '  stream     constant flow (s)          k8s-log, kube-audit, metrics, auditd, sshd-session, web',
    '  periodic   collector on a timer (min) firewall, controls, conntrack, k8s (state), mail',
    '             Varonis (data governance)  dataaccess, dataacl, kube-rbac, minio, vault-audit',
    '  event      when something happens     crowdsec, fail2ban, ufw, nft  → no threat = no event',
    '  dormant    rare / on-demand           integrity (AIDE), su, containerd (container start)',
    '',
    'Ex. stable cluster: container runtime and cluster-state feeds emit a few dozen events/day, and an',
    'IPS emits none at all without an attack = sparse BY NATURE -> "quiet" is correct. Pod logs and',
    'audit feeds are streams (easily tens of thousands of events/day) -> always fresh.',
  ] : [
    'ÉTAT = SANTÉ DE COLLECTE (pas l\'activité) :',
    '  ● frais   donnée reçue il y a < 15 min',
    '  ● calme   collecte OK mais source peu active — PAS un retard',
    '  ● muet    INGESTION EN PANNE : plus aucune donnée (toutes sources) depuis > 10 min',
    '            └─ seul état d\'alerte (réseau / corruption / collecte arrêtée).',
    '',
    'Une source peut être « calme » des heures sans problème : ça dépend de sa NATURE.',
    'L\'âge = temps depuis la dernière DONNÉE, pas depuis le dernier passage du collecteur',
    '(qui, lui, tourne sur un timer et vérifie ; il n\'émet que s\'il y a du nouveau).',
    '',
    'TYPE de source (affiché à côté du nom) :',
    '  continu      flux constant (s)          k8s-log, kube-audit, métriques, auditd, sshd-session, web',
    '  périodique   collecteur sur timer (min) firewall, controls, conntrack, k8s (état), mail',
    '               Varonis (gouvernance)     dataaccess, dataacl, kube-rbac, minio, vault-audit',
    '  événement    quand il se passe qqch     crowdsec, fail2ban, ufw, nft  → pas de menace = pas d\'event',
    '  dormant      rare / à la demande        integrity (AIDE), su, containerd (démarrage conteneur)',
    '',
    'Ex. cluster stable : le runtime conteneur et l\'état du cluster émettent quelques dizaines',
    'd\'événements/jour, et un IPS n\'émet RIEN sans attaque = sparse PAR NATURE -> « calme » est correct.',
    'Les logs de pods et les pistes d\'audit sont continus (facilement quelques dizaines de milliers',
    'd\'événements/jour) -> toujours frais.',
  ]).join('\n');
  const act = document.createElement('div'); act.className = 'modal-act';
  const btn = document.createElement('button'); btn.type = 'button'; btn.className = 'm-cancel'; btn.textContent = 'Fermer';
  act.appendChild(btn); box.append(h, pre, act); ov.appendChild(box); document.body.appendChild(ov);
  const close = () => { document.removeEventListener('keydown', onKey); ov.remove(); };
  const onKey = e => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', onKey);
  ov.onclick = e => { if (e.target === ov) close(); };
  btn.onclick = close;
}

export { renderHelpGuide, openHelpModal, openFreshnessHelp };
