// risk.js — panneau Risque par entité (RBA #24). ADDITIF, comportement-préservant.
// Vit dans l'espace DÉTECTION & RÉPONSE. LECTURE seule, viewer+ (donnée de posture, pas un secret).
// Endpoints (déjà LIVE, vérifiés 200) — servis du ROLLUP (zéro scan d'events) :
//   GET /api/risk/entities                 -> {entities:[{entity_type,entity,env_id,score,contrib,distinct_tactics,tactics,score_hot,contrib_hot,max_severity,first_ts,last_ts,over_threshold}], served, window, total, total_capped, over_threshold_total, thresholds:{score,distinct_tactics,velocity,window_s}}
//   GET /api/risk/entity/{etype}/{entity}    -> {entity_type,entity,summary:{…}|null, timeline:[{ts,score,contrib}], contributions:[{ts,risk_score,source,rule_id,reason,mitre,severity}]}
// SÉCU UI : tout en textContent/esc (anti-XSS). Aucune mutation (aucun apiSend).
import { $, api, fetchInto, fmtTs, humanAge, LANG, muted, pagedList, sev } from './core.js';

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
  host.replaceChildren();
  const phrase = document.createElement('div');
  phrase.className = 'muted';
  phrase.style.cssText = 'margin-bottom:6px;font-size:11px';
  phrase.appendChild(document.createTextNode(motDeLaCoupeDuClassement(d)));
  phrase.appendChild(document.createElement('br'));
  phrase.appendChild(document.createTextNode(motDesEntitesAuDessusDunSeuil(d)));
  host.appendChild(phrase);
  const liste = document.createElement('div');
  host.appendChild(liste);
  // `P11.18-m` — LA RECHERCHE PORTE SUR LE CLASSEMENT SERVI, ET LE DIT. La route rend une COUPE DE RANG
  // (`risk_rollup ORDER BY score DESC LIMIT`) : les lignes tenues ici sont une fenêtre du cumul de risque,
  // ce que les deux phrases au-dessus de la liste énoncent déjà en chiffres. Une entité sous la coupe est
  // introuvable d'ici, et le résumé de la recherche doit le dire au lieu de conclure « elle n'existe pas ».
  pagedList(liste, { mode: 'client', pageSize: 50, rows: entities, columns, sort: { key: 'score', dir: -1 }, emptyText: MOT_RISQUE_AUCUNE_ENTITE, onRowClick: r => openEntity(r.entity_type, r.entity), recherche: { fenetre: true } });
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


// `P11.17-f` — CE QUE LA VUE AFFICHE QUAND LA COUPE MORD, ET POURQUOI DEUX PHRASES SONT NÉCESSAIRES.
// La borne de cette route est DÉLIBÉRÉE : l'ordre étant `score DESC`, la coupe retient les entités les
// plus à risque, ce qui est la question d'un panneau de triage — et `risk_rollup` est reconstruite à
// blanc à chaque tick, donc elle ne grossit pas avec le temps. Une borne délibérée n'a pas à être
// corrigée, elle a à se DIRE : le démon rend le rang de coupe (`window`), le nombre servi (`served`) et
// le total des entités à risque borné par le plafond de comptage partagé (`total`, `total_capped`).
// Fonction PURE (une réponse -> une phrase), quatre états de connaissance, aucun qui présente une coupe
// comme un inventaire.
function motDeLaCoupeDuClassement(d) {
  const servies = d && d.entities ? d.entities.length : 0;
  if (!laCoupeMordLeClassement(d)) return servies + MOT_RISQUE_TOUTE_LA_FLOTTE;
  if (!d || typeof d.total !== 'number') return servies + MOT_RISQUE_SERVIES_A + (d && d.window ? d.window : servies) + MOT_RISQUE_SERVIES_B;
  if (d.total_capped) return servies + MOT_RISQUE_PLUS_HAUTES + MOT_RISQUE_PLUS_DE + d.total + MOT_RISQUE_A_RISQUE;
  return servies + MOT_RISQUE_PLUS_HAUTES + d.total + MOT_RISQUE_A_RISQUE;
}
// LA SECONDE PHRASE, ET LE DANGER PROPRE À UNE COUPE DE RANG. La pastille « seuil » est une DISJONCTION
// (score OU tactiques distinctes OU vélocité) ; l'ordre du classement, lui, ne connaît que le SCORE. Une
// entité qui franchit un seuil par les TACTIQUES avec un score modeste tombe donc sous le rang de coupe
// et disparaît du panneau qui existe pour la montrer. Le total seul ne le dirait pas : le démon rend
// aussi le nombre d'entités au-dessus d'un seuil, compté par le MÊME prédicat que les pastilles et que
// le moteur d'alerte, et cette phrase le compare à ce qui est visible.
function motDesEntitesAuDessusDunSeuil(d) {
  const total = d ? d.over_threshold_total : null;
  if (typeof total !== 'number') return MOT_RISQUE_SEUIL_NON_COMPTE;
  const visibles = (d && Array.isArray(d.entities) ? d.entities : []).filter(e => e && e.over_threshold).length;
  if (total <= visibles) return total + MOT_RISQUE_SEUIL_TOUTES;
  return total + MOT_RISQUE_SEUIL_DONT + visibles + MOT_RISQUE_SEUIL_SOUS_LA_COUPE;
}
// LA COUPE MORD-ELLE ? UNE SEULE LECTURE — l'écrire deux fois la laisserait diverger. Le classement ne
// couvre TOUTE la flotte à risque que lorsqu'elle a été comptée (`total` numérique), que le comptage n'a
// pas lui-même été plafonné, et qu'il ne dépasse pas les lignes rendues. Un total absent n'est PAS un zéro.
function laCoupeMordLeClassement(d) {
  const servies = d && d.entities ? d.entities.length : 0;
  return !(d && typeof d.total === 'number' && !d.total_capped && d.total <= servies);
}
// Le vocabulaire de la coupe, écrit EN ENTIER dans les deux langues à l'endroit du rendu : une phrase
// recollée à l'exécution ne serait jamais égale à une clé du lexique et resterait en français.
const MOT_RISQUE_PLUS_HAUTES = LANG === 'en' ? ' highest-risk entities out of ' : ' entités les plus à risque sur ';
const MOT_RISQUE_PLUS_DE = LANG === 'en' ? 'more than ' : 'plus de ';
const MOT_RISQUE_A_RISQUE = LANG === 'en'
  ? ' carrying risk — this is a rank cut, not the whole list: the ranking is ordered by cumulative score.'
  : " porteuses de risque — c'est une coupe de rang, pas la liste entière : le classement est ordonné par score cumulé.";
const MOT_RISQUE_TOUTE_LA_FLOTTE = LANG === 'en' ? ' entities carrying risk — that is all of them.' : " entités porteuses de risque — c'est la totalité.";
const MOT_RISQUE_SERVIES_A = LANG === 'en' ? ' entities served (rank cut of ' : ' entités servies (coupe de rang de ';
const MOT_RISQUE_SERVIES_B = LANG === 'en'
  ? ') — the risk rollup could NOT be counted, so it may hold more.'
  : ") — le cumul de risque n'a PAS pu être compté, il peut donc en contenir davantage.";
const MOT_RISQUE_SEUIL_TOUTES = LANG === 'en'
  ? ' entity(ies) cross a threshold, and every one of them is shown here.'
  : ' entité(s) franchissent un seuil, et toutes sont affichées ici.';
const MOT_RISQUE_SEUIL_DONT = LANG === 'en' ? ' entity(ies) cross a threshold, of which ' : ' entité(s) franchissent un seuil, dont ';
const MOT_RISQUE_SEUIL_SOUS_LA_COUPE = LANG === 'en'
  ? ' are shown here — the others sit below the rank cut, because a threshold can be crossed on distinct tactics or on velocity while the score stays low. Alerting reads the whole rollup and does not miss them.'
  : " sont affichées ici — les autres sont sous le rang de coupe, un seuil pouvant être franchi par les tactiques distinctes ou par la vélocité avec un score modeste. Le moteur d'alerte, lui, lit le cumul entier et ne les manque pas.";
const MOT_RISQUE_SEUIL_NON_COMPTE = LANG === 'en'
  ? 'The entities crossing a threshold could NOT be counted — this is not a count of zero.'
  : "Les entités qui franchissent un seuil n'ont PAS pu être comptées — ce n'est pas un compte nul.";
const MOT_RISQUE_AUCUNE_ENTITE = LANG === 'en'
  ? 'No entity carries risk — the risk engine (RBA) has not attributed any contribution yet.'
  : "Aucune entité à risque — le moteur de risque (RBA) n'a pas encore attribué de contribution.";

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
