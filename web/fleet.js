// fleet.js — extracted from app.js (DEEP state-container split). Behaviour-preserving.
// Flotte d'agents (P0 UI): inventaire des hotes/endpoints (GET /api/fleet, lecture seule).
import { $, api, exportBar, fetchInto, fmtTs, humanAge, ic, muted, pagedList } from './core.js';

// =================================================================================================
// FLOTTE D'AGENTS (P0 UI) — inventaire des HÔTES/endpoints qui remontent des données. LECTURE (viewer+) :
// 100% GET /api/fleet (même redaction/RBAC que le reste ; l'authorizer read-pool ne laisse JAMAIS fuir
// token.token_hash). AFFICHAGE SEUL : la console ne pilote pas l'hôte (invariant #3) — l'enrôlement et la
// config de push sont montrés, jamais commandés d'ici. Statut = fraîcheur du dernier signal de l'hôte : un
// hôte muet = son agent est probablement tombé (≠ une SOURCE calme, qui reste normale). VERSION / OS de
// l'agent : NON disponibles côté daemon (le shipper ne les transmet pas) -> non affichés (suivi différé).
const FLEET_DOT  = { fresh: 'frais', stale: 'warn', silent: 'muet' };   // pastille (réutilise .fdot existants)

const FLEET_TXT  = { fresh: 'ok',    stale: 'fwarn', silent: 'bad'  };   // couleur du libellé (classes existantes)

const FLEET_LBL  = { fresh: 'frais', stale: 'en retard', silent: 'muet' };

const FLEET_RANK = { silent: 0, stale: 1, fresh: 2 };                    // tri : problèmes d'abord

// export (client) des lignes DÉJÀ chargées (aucune colonne secrète : host/statut/timestamps/nom d'enrôlement).
const FLEET_EXPORT_COLS = [
  { key: 'host', label: 'host' }, { key: 'status', label: 'status' }, { key: 'last_seen', label: 'last_seen' },
  { key: 'signals', label: 'signals' }, { key: 'first_seen', label: 'first_seen' }, { key: 'enrolled', label: 'enrolled' },
  { key: 'enroll_name', label: 'enroll_name' }, { key: 'enroll_created', label: 'enroll_created' }, { key: 'token_last_used', label: 'token_last_used' },
];

function fleetExportRow(h) {
  return {
    host: h.host || '', status: h.status || '', last_seen: h.last_seen ? fmtTs(h.last_seen) : '',
    signals: h.signals == null ? 0 : h.signals, first_seen: h.first_seen ? fmtTs(h.first_seen) : '',
    enrolled: h.enrolled ? 'oui' : 'non', enroll_name: h.enroll_name || '',
    enroll_created: h.enroll_created ? fmtTs(h.enroll_created) : '', token_last_used: h.token_last_used ? fmtTs(h.token_last_used) : '',
  };
}

function fleetExportBar(hosts) {
  return exportBar('flotte', () => ({ cols: FLEET_EXPORT_COLS, rows: hosts.map(fleetExportRow) }), 'fleet');
}

// Inventaire de la flotte : GET /api/fleet (borné à 500 hôtes = plafond serveur ; une flotte réelle en compte
// bien moins) puis pagedList mode CLIENT -> tri par colonne + pagination locale + export du jeu complet chargé,
// exactement comme l'inventaire des Sources (loadSourcesView). Statut server-side (fresh/stale/silent) mappé au
// vocabulaire UI (frais / en retard / muet).
async function loadFleetView() {
  const wrap = $('#fleet-body'); if (!wrap) return;
  const d = await fetchInto(wrap, '/fleet?limit=500&sort=status&dir=asc'); if (!d) return;
  const hosts = (d.hosts || []).slice();
  const srvNow = d.now || Math.floor(Date.now() / 1000);
  wrap.replaceChildren();
  const banner = document.createElement('div');
  banner.className = d.pipeline_fresh ? 'muted' : 'bad';
  banner.style.cssText = 'margin:0 0 9px;font-size:12px';
  banner.textContent = d.pipeline_fresh
    ? "Une ligne par hôte/machine (endpoint où un agent pousse) — statut de l'agent, dernier signal, enrôlement. Statut = fraîcheur du dernier signal de l'hôte : un hôte « muet » = son agent est probablement tombé. Affichage seul — aucune commande d'hôte depuis la console (version/OS de l'agent non transmis par le collecteur, non affichés). → Pour les sources par type de donnée, voir Inventaire des sources."
    : 'Ingestion en panne — aucune donnée reçue récemment (tous les hôtes apparaîtront « en retard » / « muets »).';
  wrap.appendChild(banner);
  if (!hosts.length) { wrap.appendChild(muted("aucun hôte distant n'a encore poussé de données — hôte local uniquement.")); return; }
  // en-tête : compteurs par statut + barre d'export (CSV / JSON / PDF sur la flotte chargée).
  const counts = { fresh: 0, stale: 0, silent: 0 };
  hosts.forEach(h => { counts[h.status] = (counts[h.status] || 0) + 1; });
  const total = typeof d.total === 'number' ? d.total : hosts.length;
  const head = document.createElement('div'); head.className = 'alerthead';
  const sub = document.createElement('span');
  sub.innerHTML = `${total} hôte(s) · <b class="ok">${counts.fresh}</b> frais · <b class="fwarn">${counts.stale}</b> en retard · <b class="bad">${counts.silent}</b> muet(s)`
    + (total > hosts.length ? ` <span class="muted">(affichage borné à ${hosts.length})</span>` : '');
  head.appendChild(sub);
  head.appendChild(fleetExportBar(hosts));
  wrap.appendChild(head);
  const tblHost = document.createElement('div'); wrap.appendChild(tblHost);
  const ageTxt = s => 'il y a ' + humanAge(s);
  const columns = [
    { key: 'host', label: 'Hôte', sortable: true, sortVal: h => h.host || '', render: h => {
      const f = document.createDocumentFragment();
      const ico = document.createElement('span'); ico.innerHTML = ic('server'); ico.style.cssText = 'margin-right:6px;color:var(--mut)'; f.appendChild(ico);
      const nm = document.createElement('span'); nm.textContent = h.host || ''; f.appendChild(nm); return f;
    } },
    { key: 'status', label: 'Statut', sortable: true, sortVal: h => (FLEET_RANK[h.status] ?? 9), render: h => {
      const f = document.createDocumentFragment();
      const dot = document.createElement('span'); dot.className = 'fdot ' + (FLEET_DOT[h.status] || 'calme');
      const lbl = document.createElement('b'); lbl.className = FLEET_TXT[h.status] || 'calm'; lbl.textContent = FLEET_LBL[h.status] || h.status || '—';
      f.append(dot, lbl); return f;
    } },
    { key: 'last_seen', label: 'Dernier signal', sortable: true, sortVal: h => h.last_seen || 0, render: h => {
      const sp = document.createElement('span'); sp.textContent = h.last_seen ? ageTxt(h.age_s) : '—'; if (h.last_seen) sp.title = fmtTs(h.last_seen); return sp;
    } },
    { key: 'signals', label: 'Signaux', sortable: true, align: 'r', sortVal: h => h.signals || 0, render: h => {
      const sp = document.createElement('span'); sp.textContent = String(h.signals == null ? 0 : h.signals); sp.title = 'Total des signaux reçus (événements + métriques + snapshots, dans la fenêtre de rétention)'; return sp;
    } },
    { key: 'first_seen', label: 'Premier vu', sortable: true, sortVal: h => h.first_seen || 0, render: h => {
      const sp = document.createElement('span'); sp.textContent = h.first_seen ? fmtTs(h.first_seen) : '—'; return sp;
    } },
    { key: 'enroll', label: 'Enrôlement', sortable: true, sortVal: h => h.enrolled ? (h.enroll_name || '~') : '', render: h => {
      if (!h.enrolled) { const sp = document.createElement('span'); sp.className = 'muted'; sp.textContent = 'non enrôlé'; sp.title = "Aucun token d'agent lié à cet hôte (ingest via token partagé, ou hôte local)."; return sp; }
      const b = document.createElement('span'); b.className = 'badge'; b.textContent = h.enroll_name || 'agent';
      b.style.cssText = 'color:var(--ok);border-color:color-mix(in srgb,var(--ok) 40%,transparent)';
      b.title = "Token d'agent lié à cet hôte" + (h.enroll_created ? ' — créé le ' + fmtTs(h.enroll_created) : '');
      return b;
    } },
    { key: 'token_last_used', label: 'Dernier push agent', sortable: true, sortVal: h => h.token_last_used || 0, render: h => {
      const sp = document.createElement('span');
      if (h.token_last_used) { sp.textContent = ageTxt(Math.max(0, srvNow - h.token_last_used)); sp.title = fmtTs(h.token_last_used); }
      else { sp.textContent = '—'; sp.className = 'muted'; sp.title = 'Non disponible (hôte non enrôlé, ou mode multi-tenant où le token ne suit pas le dernier push).'; }
      return sp;
    } },
  ];
  pagedList(tblHost, { mode: 'client', pageSize: 50, rows: hosts, columns, emptyText: 'aucun hôte' });
  const legend = document.createElement('div'); legend.className = 'muted'; legend.style.cssText = 'margin-top:8px;font-size:11px';
  legend.textContent = 'Statut = fraîcheur du dernier signal de l\'hôte : frais (<15 min) · en retard (15 min–1 h) · muet (>1 h, agent probablement tombé). « Signaux » = volume total reçu (rétention). « Enrôlement » = token d\'agent lié à l\'hôte (nom + date de création) ; « Dernier push agent » = dernier appel authentifié du token (mode mono-tenant). Version et OS de l\'agent ne sont pas transmis par le collecteur (différés).';
  wrap.appendChild(legend);
}


export { loadFleetView };
