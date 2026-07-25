// risk.js — panneau Risque par entité (RBA #24). ADDITIF, comportement-préservant.
// Vit dans l'espace DÉTECTION & RÉPONSE. LECTURE seule, viewer+ (donnée de posture, pas un secret).
// Endpoints (déjà LIVE, vérifiés 200) — servis du ROLLUP (zéro scan d'events) :
//   GET /api/risk/entities                 -> {entities:[{entity_type,entity,env_id,score,contrib,distinct_tactics,tactics,score_hot,contrib_hot,max_severity,first_ts,last_ts,over_threshold}], thresholds:{score,distinct_tactics,velocity,window_s}}
//   GET /api/risk/entity/:etype/:entity    -> {entity_type,entity,summary:{…}|null, timeline:[{ts,score,contrib}], contributions:[{ts,risk_score,source,rule_id,reason,mitre,severity}]}
// SÉCU UI : tout en textContent/esc (anti-XSS). Aucune mutation (aucun apiSend).
import { $, api, fetchInto, fmtTs, humanAge, muted, pagedList, sev } from './core.js';

let _thresholds = null;   // seuils courants (pour la légende) — repeuplés à chaque chargement.

// ---- vue liste : top-risque (table triable/paginée) ----
async function loadRiskView() {
  const host = $('#risk-list'); if (!host) return;
  const det = $('#risk-detail'); if (det) det.replaceChildren();   // on repart de la liste à chaque (re)chargement
  const d = await fetchInto(host, '/risk/entities'); if (!d) return;
  const entities = (d && Array.isArray(d.entities)) ? d.entities : [];
  _thresholds = (d && d.thresholds) || null;
  const nowS = Math.floor(Date.now() / 1000);
  const columns = [
    { key: 'entity', label: 'Entité', sortable: true, sortVal: r => r.entity || '', render: r => {
      const f = document.createDocumentFragment();
      const s = document.createElement('span'); s.textContent = r.entity == null ? '' : r.entity; s.title = s.textContent; f.appendChild(s);
      if (r.over_threshold) { const b = document.createElement('span'); b.className = 'badge'; b.textContent = 'seuil'; b.title = 'Au-dessus d\'un seuil de risque (score / tactiques / vélocité)'; b.style.cssText = 'margin-left:6px;color:var(--sev4);border-color:color-mix(in srgb,var(--sev4) 45%,transparent)'; f.appendChild(b); }
      return f;
    } },
    { key: 'entity_type', label: 'Type', sortable: true, sortVal: r => r.entity_type || '', render: r => { const c = document.createElement('code'); c.textContent = r.entity_type || '?'; return c; } },
    { key: 'score', label: 'Score', sortable: true, align: 'r', sortVal: r => r.score || 0, render: r => { const b = document.createElement('b'); b.textContent = String(r.score == null ? 0 : r.score); if (r.over_threshold) b.style.color = 'var(--sev4)'; return b; } },
    { key: 'score_hot', label: 'Vélocité', sortable: true, align: 'r', sortVal: r => r.score_hot || 0, render: r => String(r.score_hot == null ? 0 : r.score_hot), },
    { key: 'contrib', label: 'Contrib.', sortable: true, align: 'r', sortVal: r => r.contrib || 0, render: r => String(r.contrib == null ? 0 : r.contrib) },
    { key: 'distinct_tactics', label: 'Tactiques', sortable: true, align: 'r', sortVal: r => r.distinct_tactics || 0, render: r => { const s = document.createElement('span'); s.textContent = String(r.distinct_tactics == null ? 0 : r.distinct_tactics); if (r.tactics) s.title = r.tactics; return s; } },
    { key: 'max_severity', label: 'Sév. max', sortable: true, sortVal: r => r.max_severity || 0, render: r => { const s = document.createElement('span'); s.className = 'sev'; s.textContent = sev(r.max_severity); return s; } },
    { key: 'last_ts', label: 'Dernier', sortable: true, sortVal: r => r.last_ts || 0, render: r => { const s = document.createElement('span'); s.textContent = r.last_ts ? 'il y a ' + humanAge(nowS - r.last_ts) : '—'; if (r.last_ts) s.title = fmtTs(r.last_ts); return s; } },
  ];
  pagedList(host, { mode: 'client', pageSize: 50, rows: entities, columns, sort: { key: 'score', dir: -1 }, emptyText: 'aucune entité à risque — le moteur de risque (RBA) n\'a pas encore attribué de contribution.', onRowClick: r => openEntity(r.entity_type, r.entity) });
  // légende des seuils courants (aide à lire « seuil »).
  const leg = $('#risk-legend');
  if (leg) {
    leg.replaceChildren();
    if (_thresholds) {
      const t = _thresholds;
      leg.className = 'muted'; leg.style.cssText = 'margin-top:8px;font-size:11px';
      leg.textContent = 'Seuils courants — score ≥ ' + (t.score != null ? t.score : '?')
        + (t.distinct_tactics ? ' · tactiques distinctes ≥ ' + t.distinct_tactics : '')
        + (t.velocity ? ' · vélocité ≥ ' + t.velocity : '')
        + (t.window_s ? ' · fenêtre ' + humanAge(t.window_s) : '')
        + '. « Score » = risque cumulé attribué à l\'entité ; « Vélocité » = score sur la fenêtre récente. Clique une ligne pour la timeline + les contributions.';
    }
  }
}

// ---- vue détail d'UNE entité : synthèse + timeline horaire + contributions ----
async function openEntity(etype, entity) {
  const det = $('#risk-detail'); if (!det) return;
  det.replaceChildren(muted('chargement…'));
  det.scrollIntoView({ behavior: 'smooth', block: 'start' });
  const d = await fetchInto(det, '/risk/entity/' + encodeURIComponent(etype) + '/' + encodeURIComponent(entity)); if (!d) return;
  det.replaceChildren();
  // en-tête + bouton retour (referme le détail).
  const head = document.createElement('div'); head.className = 'panelhead';
  const h = document.createElement('h3'); h.className = 'subh'; h.style.margin = '0';
  h.textContent = (d.entity_type || etype) + ' : ' + (d.entity || entity);
  const back = document.createElement('button'); back.type = 'button'; back.className = 'picon'; back.textContent = 'Fermer';
  back.onclick = () => det.replaceChildren();
  head.append(h, back); det.appendChild(head);
  // synthèse (tuiles) depuis le rollup.
  const sm = d.summary;
  if (sm) {
    const tiles = document.createElement('div'); tiles.className = 'ti-tiles';
    const tile = (label, val, cls) => { const b = document.createElement('div'); b.className = 'ti-tile' + (cls ? ' ' + cls : ''); const n = document.createElement('div'); n.className = 'ti-tile-n'; n.textContent = String(val == null ? 0 : val); const l = document.createElement('div'); l.className = 'ti-tile-l'; l.textContent = label; b.append(n, l); return b; };
    tiles.append(
      tile('Score', sm.score, 'warn'),
      tile('Vélocité', sm.score_hot, ''),
      tile('Contributions', sm.contrib, ''),
      tile('Tactiques', sm.distinct_tactics, ''),
    );
    det.appendChild(tiles);
    const meta = document.createElement('div'); meta.className = 'muted'; meta.style.cssText = 'margin:6px 0 10px;font-size:12px';
    meta.textContent = 'Sévérité max : ' + sev(sm.max_severity)
      + (sm.tactics ? ' · tactiques : ' + sm.tactics : '')
      + (sm.first_ts ? ' · première : ' + fmtTs(sm.first_ts) : '')
      + (sm.last_ts ? ' · dernière : ' + fmtTs(sm.last_ts) : '');
    det.appendChild(meta);
  } else {
    det.appendChild(muted('aucune synthèse (entité hors rollup).'));
  }
  // timeline horaire (mini barres) — score cumulé par bucket d'1 h.
  const tl = Array.isArray(d.timeline) ? d.timeline : [];
  if (tl.length) {
    const tlh = document.createElement('div'); tlh.className = 'fldname'; tlh.style.cssText = 'margin:10px 0 4px'; tlh.textContent = 'Timeline (score / heure)';
    det.appendChild(tlh);
    const max = Math.max(1, ...tl.map(p => p.score || 0));
    const bars = document.createElement('div'); bars.className = 'risk-spark';
    tl.forEach(p => {
      const bar = document.createElement('div'); bar.className = 'risk-bar';
      const h2 = Math.max(2, Math.round(((p.score || 0) / max) * 40));
      bar.style.height = h2 + 'px';
      bar.title = fmtTs(p.ts) + ' — score ' + (p.score || 0) + ' · ' + (p.contrib || 0) + ' contrib.';
      bars.appendChild(bar);
    });
    det.appendChild(bars);
  }
  // contributions récentes (table paginée).
  const ch = document.createElement('div'); ch.className = 'fldname'; ch.style.cssText = 'margin:12px 0 4px'; ch.textContent = 'Contributions récentes';
  det.appendChild(ch);
  const clist = document.createElement('div'); det.appendChild(clist);
  const contribs = Array.isArray(d.contributions) ? d.contributions : [];
  pagedList(clist, {
    mode: 'client', pageSize: 25, rows: contribs,
    sort: { key: 'ts', dir: -1 },
    columns: [
      { key: 'ts', label: 'Horodatage', sortable: true, sortVal: r => r.ts || 0, render: r => { const s = document.createElement('span'); s.textContent = fmtTs(r.ts); s.title = String(r.ts); return s; } },
      { key: 'risk_score', label: 'Score', sortable: true, align: 'r', sortVal: r => r.risk_score || 0, render: r => String(r.risk_score == null ? 0 : r.risk_score) },
      { key: 'source', label: 'Source', sortable: true, sortVal: r => r.source || '', render: r => { const c = document.createElement('code'); c.textContent = r.source || '?'; return c; } },
      { key: 'severity', label: 'Sévérité', sortable: true, sortVal: r => r.severity || 0, render: r => { const s = document.createElement('span'); s.className = 'sev'; s.textContent = sev(r.severity); return s; } },
      { key: 'mitre', label: 'MITRE', sortable: true, sortVal: r => r.mitre || '', render: r => { const c = document.createElement('code'); c.textContent = r.mitre || '—'; return c; } },
      { key: 'reason', label: 'Motif', render: r => { const s = document.createElement('span'); s.textContent = r.reason || ''; if (r.reason) s.title = r.reason; return s; } },
    ],
    emptyText: 'aucune contribution enregistrée pour cette entité.',
  });
}

export { loadRiskView };
