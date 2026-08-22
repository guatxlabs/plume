// help.js — AIDE IN-APP (documentation contextuelle) extraite de app.js (audit H1 : 1re découpe, triviale).
// 100% statique, WEB-ONLY : aucun appel réseau, aucun daemon. Contient la MÉCANIQUE de l'aide : l'ouvreur
// `openHelp` (registre des sections importé de help_registry.js — le contenu vit là, P11.4-e), les modales
// (openHelpBox / openHelpModal / openFreshnessHelp), le sommaire et la page « Aide » (HELP_INDEX / GLOSSARY /
// HELP_SHORTCUTS, renderHelpGuide) et le handler délégué .vhelp. Code relocalisé VERBATIM depuis app.js ->
// comportement identique. app.js importe renderHelpGuide + openHelpModal + openFreshnessHelp (le câblage
// #qhelp / #fresh-help et la route 'help' restent dans app.js) ; openHelp est exporté pour le harnais ESM,
// qui vérifie qu'une clé sans section rend un aveu et non le silence, et que chaque section rend le même
// texte que le registre, dans les deux langues.
import { $, LANG, ic } from './core.js';
import { uiIsAdmin, multiTenantMode } from './multitenant.js';
import { HELP } from './help_registry.js';

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
// Une clé sans section ouvre un AVEU qui la nomme — jamais le silence, jamais un panneau vide (P11.4-e) :
// le bouton existe, la page qu'il promet n'a pas été écrite, et c'est un défaut de la console, pas du geste.
function aveuSansSection(key) {
  return LANG === 'en'
    ? `No help section exists for "${key}".\nThe button is there, the page it promises was never written — a console defect, not yours.\nThe build guard refuses this state; report it with that key name.`
    : `Aucune section d'aide n'existe pour « ${key} ».\nLe bouton existe, la page qu'il promet n'a pas été écrite — défaut de la console, pas de votre geste.\nLa garde de construction refuse cet état ; le signaler avec ce nom de clé.`;
}
function openHelp(key) {
  const e = HELP[key];
  if (!e) { openHelpBox(LANG === 'en' ? 'Help unavailable' : 'Aide indisponible', aveuSansSection(String(key))); return; }
  if (e.fn) { e.fn({ openFreshnessHelp }); return; }   // modale dédiée : l'ouvreur est passé, le registre ne l'importe pas
  const d = (LANG === 'en' && e.en) ? e.en : e.fr;
  openHelpBox(d.title, d.body);
}
// handler délégué unique : tout bouton .vhelp (dans n'importe quel en-tête) ouvre l'aide de sa vue.
// N'interfère pas avec #fresh-help / #qhelp (qui gardent leur onclick dédié et n'ont pas la classe .vhelp).
document.addEventListener('click', e => {
  const b = e.target.closest ? e.target.closest('.vhelp') : null;
  if (b) { e.preventDefault(); openHelp(b.dataset.help); }
});

// --- Espace « Aide » : sommaire des espaces (respecte admin/mtOnly) + référence GXQL + glossaire ---
// C9 — `icon` = clé ic() IDENTIQUE à l'icône de la sidebar de l'espace (cohérence visuelle nav <-> guide).
const HELP_INDEX = [
  { fr: "Vue d'ensemble", en: 'Overview', icon: 'home', items: [
    { k: 'firewall', fr: 'Firewall', en: 'Firewall' },
    { k: 'controls', fr: 'Contrôles', en: 'Controls' },
    { k: 'integrations', fr: 'Intégrations & hôtes', en: 'Integrations & hosts' },
    { k: 'freshness', fr: 'Fraîcheur des sources', en: 'Source freshness' },
  ] },
  // P11.7-a — deux espaces : Recherche (l'éditeur de requête) et Cas (le flux alerte -> cas).
  { fr: 'Recherche', en: 'Search', icon: 'search', items: [
    { k: 'explore', fr: 'Recherche (éditeur de requête)', en: 'Search (query editor)' },
    { k: 'soql', fr: 'GXQL (référence)', en: 'GXQL (reference)' },
  ] },
  { fr: 'Cas', en: 'Cases', icon: 'folder', items: [
    { k: 'alerts', fr: 'Alertes', en: 'Alerts' },
    { k: 'cases', fr: 'Cas', en: 'Cases' },
  ] },
  { fr: 'Dashboards', en: 'Dashboards', icon: 'layout', items: [
    { k: 'dashboards', fr: 'Dashboards', en: 'Dashboards' },
  ] },
  { fr: 'Détection & Réponse', en: 'Detection & Response', icon: 'activity', items: [
    { k: 'coverage', fr: 'Couverture ATT&CK', en: 'ATT&CK coverage' },
    { k: 'attack', fr: 'Matrice ATT&CK', en: 'ATT&CK matrix' },
    { k: 'rules', fr: 'Règles de détection', en: 'Detection rules' },
    { k: 'response', fr: 'Réponse (playbooks, runbooks & actions)', en: 'Response (playbooks, runbooks & actions)' },
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
    { k: 'suppressions', fr: 'Suppressions', en: 'Suppressions' },
    { k: 'retention', fr: 'Rétention', en: 'Retention' },
    { k: 'ledger', fr: 'Audit', en: 'Audit' },
    { k: 'tenants', fr: 'Tenants', en: 'Tenants', mtOnly: true },
  ] },
];
// glossaire : { t: terme, fr, en }. Rendu en textContent ; définitions vérifiées contre le code.
const GLOSSARY = [
  { t: 'GXQL', fr: `Langage de recherche à pipeline (search … | transform …) compilé en SQL.`, en: `Pipeline search language (search … | transform …) compiled to SQL.` },
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
  { t: 'playbook', fr: `Règle de réponse : condition (requête, 1re colonne = cible) -> action, automatique en mode Actif.`, en: `Response rule: condition (query, 1st column = target) -> action, automatic in Active mode.` },
  { t: 'runbook', fr: `Guide d'incident : checklist phasée manuelle, proposée dans un cas élevé en incident.`, en: `Incident guide: phased manual checklist, proposed in a case raised to incident.` },
  { t: 'action', fr: `Riposte : ban_ip, unban_ip, kill_pid, stop_service (enum fermé).`, en: `Response: ban_ip, unban_ip, kill_pid, stop_service (closed enum).` },
  { t: 'dry-run / RÉEL', fr: `dry-run = simulation (rien n'est exécuté) ; RÉEL = exécuté.`, en: `dry-run = simulation (nothing runs) ; REAL = executed.` },
  { t: 'approbation', fr: `File d'attente : une action doit être approuvée avant exécution.`, en: `Queue: an action must be approved before it runs.` },
  { t: 'mode observe/active', fr: `Observation = propositions seulement ; ACTIF = ripostes automatiques.`, en: `Observe = proposals only ; ACTIVE = automatic responses.` },
  { t: 'RBAC', fr: `Rôles : admin (tout), editor (écriture contenu), viewer (lecture seule).`, en: `Roles: admin (all), editor (write content), viewer (read only).` },
  { t: 'SQL brut', fr: `Requête SQL directe, réservée à l'admin (les autres utilisent GXQL).`, en: `Direct SQL query, admin only (others use GXQL).` },
  { t: 'tenant', fr: `Espace client isolé (base chiffrée dédiée).`, en: `Isolated client space (dedicated encrypted DB).` },
  { t: 'environnement', fr: `prod / staging… filtrant les vues d'un tenant.`, en: `prod / staging… filtering a tenant's views.` },
  { t: 'mode 0 / mode 1', fr: `Mode 0 = mono-tenant (switchers cachés) ; mode 1 = multi-tenant.`, en: `Mode 0 = single-tenant (switchers hidden) ; mode 1 = multi-tenant.` },
  { t: 'rétention', fr: `Durée de conservation des données ; réduire = purge destructive.`, en: `Data keep duration ; reducing = destructive purge.` },
  { t: 'snapshot / rollup', fr: `Snapshot = état capturé ; rollup = métrique agrégée pré-calculée.`, en: `Snapshot = captured state ; rollup = pre-aggregated metric.` },
  { t: 'fraîcheur', fr: `Santé de collecte d'une source : frais, calme, en retard, muet.`, en: `A source's collection health: fresh, quiet, late, mute.` },
  { t: 'cadence déclarée', fr: `Ce que la sonde du démon attend : continue (intervalle), événementielle, ou non déclarée.`, en: `What the daemon's probe expects: continuous (interval), event-driven, or undeclared.` },
  { t: 'en retard', fr: `Cadence déclarée continue dépassée (3 cycles) — le « muet » du capteur dans Intégrations.`, en: `Declared continuous cadence exceeded (3 cycles) — the probe's "mute" in Integrations.` },
  { t: 'source inattendue', fr: `Source que rien ne déclare (fichier livré, sonde, agrégat, connecteur) ; acquittable par un éditeur.`, en: `Source nothing declares (shipped file, probe, aggregate, connector); an editor can acknowledge it.` },
  { t: 'parseur', fr: `Extraction de champs par regex à groupes nommés, à l'ingestion.`, en: `Field extraction via named-group regex, at ingestion.` },
  { t: 'src_ip / dst_ip', fr: `src_ip = initiateur (attaquant) ; dst_ip = cible.`, en: `src_ip = initiator (attacker) ; dst_ip = target.` },
  { t: 'connecteur (PULL)', fr: `Source externe interrogée périodiquement (ex. Defender).`, en: `External source polled periodically (e.g. Defender).` },
  { t: 'credential', fr: `Secret chiffré au repos, jamais réaffiché (•••).`, en: `Secret encrypted at rest, never shown again (•••).` },
  { t: 'audit / ledger', fr: `Journal inviolable (hash chaîné) des changements, lecture seule.`, en: `Tamper-evident (hash-chained) change log, read-only.` },
  { t: 'DLP / gouvernance', fr: `Qui accède à quoi + intégrité + droits, en lecture seule.`, en: `Who accesses what + integrity + permissions, read-only.` },
  { t: 'dashboard / panneau', fr: `Panneau = requête GXQL enregistrée ; vue = regroupement de dashboards.`, en: `Panel = saved GXQL query ; view = grouping of dashboards.` },
  { t: 'fuseau / UTC', fr: `Stockage toujours en UTC ; affichage selon le fuseau choisi.`, en: `Always stored in UTC ; displayed per the chosen timezone.` },
  { t: 'notifier / canal', fr: `Destination d'alerte : ntfy, webhook, email.`, en: `Alert destination: ntfy, webhook, email.` },
];
// C9 — raccourcis clavier/UI RÉELS (vérifiés dans le code : #q Enter, #sql Ctrl/⌘+Enter, Échap ferme les
// modales, bouton ? d'en-tête). Statique — documente le comportement existant, n'ajoute aucune fonctionnalité.
const HELP_SHORTCUTS = [
  { key: 'Entrée', fr: `Barre de recherche (en-tête) : recopie le texte dans l'éditeur de l'espace Recherche et exécute.`, en: `Header search bar: copies the text into the Search space editor and runs it.` },
  { key: 'Ctrl / ⌘ + Entrée', fr: `Dans l'éditeur de requête (Recherche) : exécute la requête.`, en: `In the query editor (Search): run the query.` },
  { key: 'Échap', fr: `Ferme la fenêtre d'aide, une modale ou un formulaire ouvert.`, en: `Close the help window, a modal or an open form.` },
  { key: '?', fr: `Bouton dans chaque en-tête de vue : ouvre l'aide de cette vue.`, en: `Button in each view header: opens that view's help.` },
];
function renderHelpGuide() {
  const host = $('#help-body'); if (!host) return;
  const en = LANG === 'en';
  host.replaceChildren();
  // C9 — mini-sommaire COLLANT (Espaces · GXQL · Glossaire · Raccourcis) : ancres internes, aucun réseau.
  const toc = document.createElement('nav'); toc.className = 'hg-toc'; toc.setAttribute('aria-label', en ? 'Guide contents' : 'Sommaire du guide');
  [['hg-espaces', en ? 'Spaces' : 'Espaces'], ['hg-soql', 'GXQL'], ['hg-gloss', en ? 'Glossary' : 'Glossaire'], ['hg-raccourcis', en ? 'Shortcuts' : 'Raccourcis']]
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
  // ESPACES — sommaire groupé par espace, avec l'ICÔNE de la sidebar (respecte admin/mtOnly, comme la nav)
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
  // GXQL — bloc COLLAPSIBLE « Référence » (exemples réels + accès à la référence complète)
  const ref = document.createElement('details'); ref.className = 'hg-ref hg-anchor hg-sec'; ref.id = 'hg-soql'; ref.open = true;
  const sum = document.createElement('summary'); sum.className = 'hg-refsum'; sum.textContent = en ? 'GXQL — Reference' : 'GXQL — Référence';
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
  sBtn.textContent = en ? 'Open the full GXQL reference' : 'Ouvrir la référence GXQL complète';
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

// aide GXQL (modal) — référence des requêtes directement dans l'UI
function openHelpModal() {
  const ov = document.createElement('div'); ov.className = 'modal-ov';
  const box = document.createElement('div'); box.className = 'modal helpmodal';
  const en = LANG === 'en';
  const h = document.createElement('h3'); h.textContent = en ? 'Help — queries (GXQL)' : 'Aide — requêtes (GXQL)';
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

// aide in-app de la carte Fraîcheur : explique l'état (frais/calme/en retard/muet) et la CADENCE DÉCLARÉE
// -> pourquoi certaines sources sont « calme » des heures sans que ce soit une panne, et quand « en retard » s'applique.
function openFreshnessHelp() {
  const ov = document.createElement('div'); ov.className = 'modal-ov';
  const box = document.createElement('div'); box.className = 'modal helpmodal';
  const en = LANG === 'en';
  const h = document.createElement('h3'); h.textContent = en ? 'Help — Source freshness' : 'Aide — Fraîcheur des sources';
  const pre = document.createElement('pre'); pre.className = 'helpref';
  pre.textContent = (en ? [
    'STATE = COLLECTION HEALTH (not activity), derived by the daemon from the DECLARED cadence :',
    '  ● fresh   data received < 15 min ago',
    '  ● quiet   collecting OK but low-activity source — NOT a delay',
    '  ● late    a probe DECLARES a continuous cadence for this source and the silence exceeds',
    '            3 cycles — the same observation Integrations shows as a "mute" probe; the',
    '            "Mute probe" alert fires two cycles later',
    '  ● down    INGESTION BROKEN: no data (any source) for > 10 min',
    '',
    'Active alerts on a source are a COUNT (bell next to the name), never a collection state.',
    '',
    'DECLARED CADENCE (shown next to the name) :',
    '  continuous · N     a probe expects a regular flow or heartbeat every N  → can be "late"',
    '  event-driven       a probe observes it but its rate depends on activity → never "late"',
    '  undeclared         no probe declares anything: age only tells activity  → never "late"',
    'The 24 h observed rhythm (~1 datum / N) is shown on hover; it is an observation, not an',
    'expectation, and it judges nothing.',
    '',
    'Age = time since the last DATA, not since the collector last ran (which runs on a timer and',
    'checks; it only emits if there is something new). A source can be "quiet" for hours with no',
    'problem: an IPS emits nothing without an attack, a periodic collector emits on change.',
  ] : [
    'ÉTAT = SANTÉ DE COLLECTE (pas l\'activité), dérivé par le démon de la cadence DÉCLARÉE :',
    '  ● frais      donnée reçue il y a < 15 min',
    '  ● calme      collecte OK mais source peu active — PAS un retard',
    '  ● en retard  une sonde DÉCLARE une cadence continue pour cette source et le silence',
    '               dépasse 3 cycles — la même observation qu\'Intégrations montre « muet » sur le',
    '               capteur ; l\'alerte « Capteur muet » part deux cycles plus tard',
    '  ● muet       INGESTION EN PANNE : plus aucune donnée (toutes sources) depuis > 10 min',
    '',
    'Les alertes actives d\'une source sont un COMPTE (cloche à côté du nom), jamais un état de collecte.',
    '',
    'CADENCE DÉCLARÉE (affichée à côté du nom) :',
    '  continu · N     une sonde attend un flux ou un battement régulier tous les N → peut être « en retard »',
    '  événementiel    une sonde l\'observe mais son débit dépend de l\'activité → jamais « en retard »',
    '  non déclarée    aucune sonde ne déclare rien : l\'âge ne dit que l\'activité → jamais « en retard »',
    'Le rythme observé sur 24 h (~1 donnée / N) est donné au survol : c\'est une observation, pas une',
    'attente, et il ne juge rien.',
    '',
    'L\'âge = temps depuis la dernière DONNÉE, pas depuis le dernier passage du collecteur (qui, lui,',
    'tourne sur un timer et vérifie ; il n\'émet que s\'il y a du nouveau). Une source peut être « calme »',
    'des heures sans problème : un IPS n\'émet rien sans attaque, un collecteur périodique n\'émet qu\'au changement.',
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

export { renderHelpGuide, openHelpModal, openFreshnessHelp, openHelp };
