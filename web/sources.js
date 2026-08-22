// sources.js — extracted from app.js (DEEP state-container split).
// Sources (inventaire + métadonnées d'affichage) + mutations de métadonnées (editor+, auditées).
import { $, apiSend, confirmModal, fetchInto, fmtTs, humanAge, ic, modal, pagedList, socRole, toast } from './core.js';

// ============ SOURCES (inventaire + métadonnées d'affichage) ============
// Vocabulaire d'état CANONIQUE partagé avec Fraîcheur (même dérivation côté démon, `statut_de_source`) :
// muet(rouge) > en_retard(orange) > en_attente(gris, déclaré jamais vu) > frais(vert) > calme(bleu).
// `dormant` = ligne de réglage sans aucune donnée sur 7 j (repeint calme).
const SRC_DOT = { frais: 'frais', calme: 'calme', muet: 'muet', en_retard: 'warn', dormant: 'calme', attente: 'attente', en_attente: 'attente' };
const SRC_TXT = { frais: 'ok', calme: 'calm', muet: 'bad', en_retard: 'fwarn', dormant: 'calm', attente: 'mut', en_attente: 'mut' };
const SRC_LBL = { frais: 'frais', calme: 'calme', muet: 'muet', en_retard: 'en retard', dormant: 'dormant', attente: 'en attente', en_attente: 'en attente' };
const SRANK_SRC = { muet: 0, en_retard: 1, attente: 2, en_attente: 2, frais: 3, calme: 4, dormant: 4 };

// Libellé de la cadence DÉCLARÉE (sonde du démon) — jamais la moyenne observée, qui est rendue à part.
function cadenceLabel(s) {
  if (s.cadence_declaree === 'continue') return 'continu' + (s.cadence_interval_s ? ' · ' + humanAge(s.cadence_interval_s) : '');
  if (s.cadence_declaree === 'evenementielle') return 'événementiel';
  return 'non déclarée';
}

// Le marquage / acquittement est un geste ÉDITORIAL : editor et admin (miroir du path-guard RBAC editor+).
const canEditSources = () => { const r = socRole(); return r === 'admin' || r === 'editor'; };

// RENDU PUR de l'inventaire à partir de la charge utile de /api/sources (exercé par le harnais ESM sur des
// objets fabriqués ; `loadSourcesView` ne fait que l'appeler après le fetch).
function renderSourcesInventory(wrap, d) {
  const sources = (d.sources || []).slice();
  // tri INITIAL : inattendues d'abord (signal), puis par statut, puis nom. Le tri par colonne (clic
  // en-tête) prend ensuite le relais via pagedList (mode client).
  sources.sort((a, c) => (Number(c.unexpected) - Number(a.unexpected))
    || ((SRANK_SRC[a.status] ?? 9) - (SRANK_SRC[c.status] ?? 9))
    || String(a.source).localeCompare(String(c.source)));
  wrap.replaceChildren();
  const banner = document.createElement('div');
  banner.className = d.pipeline_fresh ? 'muted' : 'bad';
  banner.style.cssText = 'margin:0 0 9px;font-size:12px';
  banner.textContent = d.pipeline_fresh
    ? 'Inventaire des sources d\'ingestion. Les métadonnées ci-dessous (attendue, libellé, catégorie, note) sont d\'AFFICHAGE uniquement — la collecte et les règles ne sont jamais modifiées depuis cette console. La configuration des collecteurs hôte est hors périmètre.'
    : 'Ingestion en panne — aucune donnée reçue récemment.';
  wrap.appendChild(banner);
  const tblHost = document.createElement('div'); wrap.appendChild(tblHost);
  const editable = canEditSources();
  const nUnexpected = sources.filter(s => s.unexpected).length;
  if (nUnexpected) {
    const hint = document.createElement('div'); hint.className = 'fwarn'; hint.style.cssText = 'margin:0 0 8px;font-size:12px';
    hint.textContent = nUnexpected + ' source(s) que rien ne déclare (ni collecteur livré, ni sonde, ni agrégat, ni connecteur). '
      + (editable ? 'Si elle est légitime : Actions → « marquer attendue » (persistant, réversible, audité).'
                  : 'Un éditeur ou un administrateur peut la marquer « attendue » (persistant, réversible, audité).');
    wrap.insertBefore(hint, tblHost);
  }
  // colonnes : render -> NŒUD (badges/pastilles/boutons survivent) ; sortVal -> clé de tri par colonne.
  const columns = [
    { key: 'source', label: 'Source', sortable: true, sortVal: s => s.source == null ? '' : s.source, render: s => {
      const f = document.createDocumentFragment();
      const nm = document.createElement('span'); nm.textContent = s.source == null ? '' : s.source; f.appendChild(nm);
      if (s.unexpected) {
        const bad = document.createElement('span'); bad.className = 'badge srcbadge-unexpected'; bad.textContent = 'inattendu';
        bad.style.cssText = 'margin-left:6px;color:var(--warn);border-color:color-mix(in srgb,var(--warn) 40%,transparent)';
        bad.title = 'Source que rien ne déclare — signal à examiner. Si elle est légitime, un éditeur la marque « attendue » (Actions).';
        f.appendChild(bad);
      }
      return f;
    } },
    { key: 'expected', label: 'Attendue', sortable: true, sortVal: s => s.expected ? 1 : 0, render: s => {
      const f = document.createDocumentFragment();
      const exp = document.createElement('span'); exp.className = 'badge srcbadge-expected';
      exp.textContent = s.expected ? 'attendue' : 'non'; exp.style.color = s.expected ? 'var(--ok)' : 'var(--warn)';
      f.appendChild(exp);
      // D'OÙ VIENT LE VERDICT : la raison de construction, ou le marquage (qui / quand), en clair.
      const why = document.createElement('span'); why.className = 'muted srcwhy'; why.style.cssText = 'display:block;font-size:10px';
      const mark = s.marquage;
      if (mark && mark.updated_by && ((mark.expected && !s.in_collectors) || !mark.expected)) {
        why.textContent = (mark.expected ? 'marquée attendue' : 'marquée inattendue') + ' par ' + mark.updated_by + (mark.updated ? ' le ' + fmtTs(mark.updated) : '');
      } else if (s.raison_attendue) {
        why.textContent = s.raison_attendue;
      } else {
        why.textContent = 'non déclarée';
      }
      f.appendChild(why);
      return f;
    } },
    { key: 'cadence', label: 'Cadence', sortable: true, sortVal: s => cadenceLabel(s), render: s => {
      const sp = document.createElement('span'); sp.textContent = cadenceLabel(s);
      sp.title = (s.cadence_capteur ? 'déclarée par la sonde « ' + s.cadence_capteur + ' »' : 'aucune sonde ne déclare de cadence pour cette source')
        + (s.observed_interval_s ? ' · rythme observé sur 24 h : ~1 donnée / ' + humanAge(s.observed_interval_s) : '');
      return sp;
    } },
    { key: 'age', label: 'Dernier vu', sortable: true, sortVal: s => s.last_seen || 0, render: s => {
      const sp = document.createElement('span'); sp.textContent = s.last_seen ? 'il y a ' + humanAge(s.age_s) : '—'; if (s.last_seen) sp.title = fmtTs(s.last_seen); return sp;
    } },
    { key: 'n_24h', label: '24 h', sortable: true, align: 'r', sortVal: s => s.n_24h || 0, render: s => s.n_24h != null ? String(s.n_24h) : '0' },
    { key: 'status', label: 'Statut', sortable: true, sortVal: s => (SRANK_SRC[s.status] ?? 9), render: s => {
      const f = document.createDocumentFragment();
      const dot = document.createElement('span'); dot.className = 'fdot ' + (SRC_DOT[s.status] || 'calme');
      const lbl = document.createElement('b'); lbl.className = SRC_TXT[s.status] || 'calm'; lbl.textContent = SRC_LBL[s.status] || s.status || '—';
      f.append(dot, lbl); return f;
    } },
    { key: 'category', label: 'Catégorie', sortable: true, sortVal: s => s.category || '', render: s => s.category || '—' },
    { key: 'note', label: 'Note', render: s => { const sp = document.createElement('span'); sp.textContent = s.note || ''; if (s.note) sp.title = s.note; return sp; } },
  ];
  if (editable) columns.push({ key: 'actions', label: 'Actions', render: s => {
    const box = document.createElement('span'); box.style.whiteSpace = 'nowrap';
    const edit = document.createElement('button'); edit.type = 'button'; edit.className = 'picon'; edit.innerHTML = ic('pencil');
    edit.title = 'Éditer libellé / catégorie / note'; edit.onclick = e => { e.stopPropagation(); editSourceMeta(s); };
    const tog = document.createElement('button'); tog.type = 'button';
    tog.className = 'picon srctoggle ' + (s.expected ? 'on' : 'off'); tog.style.marginLeft = '6px';
    tog.textContent = s.expected ? 'marquer inattendue' : 'marquer attendue';
    tog.title = s.expected ? 'Rétablir le signal « inattendu » sur cette source (persistant, audité)' : 'Acquitter : déclarer cette source attendue (persistant, réversible, audité)';
    tog.onclick = e => { e.stopPropagation(); toggleExpected(s); };
    const clr = document.createElement('button'); clr.type = 'button'; clr.className = 'picon'; clr.style.marginLeft = '6px'; clr.innerHTML = ic('x');
    clr.title = 'Réinitialiser les métadonnées d\'affichage (retour au verdict de construction)'; clr.onclick = e => { e.stopPropagation(); clearSourceMeta(s); };
    box.append(edit, tog, clr); return box;
  } });
  pagedList(tblHost, { mode: 'client', pageSize: 50, rows: sources, columns, emptyText: 'aucune source' });
  if (sources.length) {
    const legend = document.createElement('div'); legend.className = 'muted'; legend.style.cssText = 'margin-top:8px;font-size:11px';
    legend.textContent = 'Statut = santé de collecte (même dérivation que Données → Fraîcheur) : frais (donnée < 15 min) · calme (collecte saine, source peu active) · en retard (cadence DÉCLARÉE par sa sonde dépassée — c\'est le « muet » du capteur dans Intégrations) · en attente (déclarée, pas encore de donnée) · muet (plus rien n\'arrive, toutes sources confondues). Une source sans cadence déclarée ou événementielle n\'est jamais « en retard ». « inattendu » = source que rien ne déclare (collecteur livré, sonde, agrégat, connecteur) et que personne n\'a marquée : un signal à examiner, acquittable par un éditeur.';
    wrap.appendChild(legend);
  }
}

async function loadSourcesView() {
  const wrap = $('#sources-body'); if (!wrap) return;
  const d = await fetchInto(wrap, '/sources'); if (!d) return;
  renderSourcesInventory(wrap, d);
}

async function sourcePut(source, action, value) {
  const b = { source, action };
  if (value !== undefined) b.value = value;
  try { await apiSend('/sources/settings', 'PUT', b); }
  catch (e) { toast((e && e.message) || 'échec', 'bad'); return false; }
  return true;
}

async function editSourceMeta(s) {
  const r = await modal({
    title: 'Éditer : ' + s.source, okText: 'Enregistrer', danger: false, fields: [
      { name: 'label', label: 'Libellé', value: s.label || '', placeholder: 'nom lisible (affichage)' },
      { name: 'category', label: 'Catégorie', value: s.category || '', placeholder: 'ex: réseau, auth, système' },
      { name: 'note', label: 'Note', type: 'textarea', value: s.note || '', placeholder: 'note libre (affichage)' },
    ],
  });
  if (!r) return;
  const ops = [];
  if ((r.label || '') !== (s.label || '')) ops.push(['set_label', r.label || '']);
  if ((r.category || '') !== (s.category || '')) ops.push(['set_category', r.category || '']);
  if ((r.note || '') !== (s.note || '')) ops.push(['set_note', r.note || '']);
  if (!ops.length) { toast('aucune modification', 'info'); return; }
  for (const [action, value] of ops) { if (!await sourcePut(s.source, action, value)) return; }
  toast('métadonnées mises à jour', 'ok'); loadSourcesView();
}

async function toggleExpected(s) {
  const target = !s.expected;
  const suppressing = target && s.unexpected;   // acquitter un signal « inattendu » = plus sensible (audité sév. 3 côté démon)
  const msg = target
    ? `Marquer « ${s.source} » comme ATTENDUE ?` + (s.unexpected ? ' Cela acquitte le signal « source inattendue ». La collecte et les règles ne sont PAS modifiées (affichage seul). Geste persistant, réversible, audité.' : ' (affichage seul, geste audité)')
    : `Marquer « ${s.source} » comme INATTENDUE ? (rétablit le signal ; affichage seul, geste audité)`;
  if (!await confirmModal(msg, { danger: suppressing, okText: target ? 'Marquer attendue' : 'Marquer inattendue' })) return;
  if (await sourcePut(s.source, 'set_expected', target)) { toast('mis à jour', 'ok'); loadSourcesView(); }
}

async function clearSourceMeta(s) {
  if (!await confirmModal(`Réinitialiser les métadonnées d'affichage de « ${s.source} » (libellé, catégorie, note, marquage) ? La source reprend le verdict de construction. La collecte n'est pas touchée.`, { danger: true, okText: 'Réinitialiser' })) return;
  if (await sourcePut(s.source, 'clear')) { toast('réinitialisé', 'ok'); loadSourcesView(); }
}


export { loadSourcesView, renderSourcesInventory };
