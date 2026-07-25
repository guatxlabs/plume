// sources.js — extracted from app.js (DEEP state-container split). Behaviour-preserving.
// Sources (inventaire + metadonnees display-only) + mutations meta (admin, audite).
import { $, api, apiSend, confirmModal, fetchInto, fmtTs, humanAge, ic, modal, muted, pagedList, toast } from './core.js';
import { S } from './state.js';

// ============ SOURCES (inventaire + métadonnées display-only) ============
// batch-2 item 1 — vocabulaire d'état CANONIQUE partagé avec Fraîcheur/Intégrations : muet(rouge) >
// en_attente(gris, déclaré jamais vu) > dégradé(orange) > frais(vert) > calme(bleu, inclut dormant).
// `dormant` reste repeint calme (variante « peu active »). `attente`/`en_attente` ajoutés (data-driven :
// affichés dès que le daemon émet ces statuts — cf. build_feeds recommandé ; sinon inertes, aucun régression).
const SRC_DOT = { frais: 'frais', calme: 'calme', muet: 'muet', dormant: 'calme', attente: 'attente', en_attente: 'attente' };

const SRC_TXT = { frais: 'ok', calme: 'calm', muet: 'bad', dormant: 'calm', attente: 'mut', en_attente: 'mut' };

const SRANK_SRC = { muet: 0, attente: 1, en_attente: 1, warn: 2, frais: 3, calme: 4, dormant: 4 };

async function loadSourcesView() {
  const wrap = $('#sources-body'); if (!wrap) return;
  const d = await fetchInto(wrap, '/sources'); if (!d) return;
  const sources = (d.sources || []).slice();
  // tri INITIAL : inattendues d'abord (signal), puis muettes, frais, calmes, dormantes ; puis nom. Le tri par
  // colonne (clic en-tête, BATCH 1) prend ensuite le relais via pagedList (mode client).
  sources.sort((a, c) => (Number(c.unexpected) - Number(a.unexpected))
    || ((SRANK_SRC[a.status] ?? 9) - (SRANK_SRC[c.status] ?? 9))
    || String(a.source).localeCompare(String(c.source)));
  wrap.replaceChildren();
  const banner = document.createElement('div');
  banner.className = d.pipeline_fresh ? 'muted' : 'bad';
  banner.style.cssText = 'margin:0 0 9px;font-size:12px';
  banner.textContent = d.pipeline_fresh
    ? 'Inventaire des sources d\'ingestion. Les métadonnées ci-dessous (attendu, libellé, catégorie, note) sont d\'AFFICHAGE uniquement — la collecte et les règles ne sont jamais modifiées depuis cette console. La configuration des collecteurs hôte est hors périmètre.'
    : 'Ingestion en panne — aucune donnée reçue récemment.';
  wrap.appendChild(banner);
  const tblHost = document.createElement('div'); wrap.appendChild(tblHost);
  // colonnes : render -> NŒUD (badges/pastilles/boutons survivent) ; sortVal -> clé de tri par colonne.
  const columns = [
    { key: 'source', label: 'Source', sortable: true, sortVal: s => s.source == null ? '' : s.source, render: s => {
      const f = document.createDocumentFragment();
      const nm = document.createElement('span'); nm.textContent = s.source == null ? '' : s.source; f.appendChild(nm);
      if (s.unexpected) { const bad = document.createElement('span'); bad.className = 'badge'; bad.textContent = 'inattendu'; bad.style.cssText = 'margin-left:6px;color:var(--warn);border-color:color-mix(in srgb,var(--warn) 40%,transparent)'; bad.title = 'Source non déclarée dans les collecteurs connus — signal à examiner. Si elle est légitime, clique Actions → « attendu » pour la déclarer.'; f.appendChild(bad); }
      return f;
    } },
    { key: 'expected', label: 'Attendu', sortable: true, sortVal: s => s.expected ? 1 : 0, render: s => {
      const exp = document.createElement('span'); exp.className = 'badge'; exp.textContent = s.expected ? 'attendu' : 'non'; exp.style.color = s.expected ? 'var(--ok)' : 'var(--warn)'; return exp;
    } },
    { key: 'type', label: 'Type', sortable: true, sortVal: s => s.type || '', render: s => s.type || '—' },
    { key: 'age', label: 'Dernier vu', sortable: true, sortVal: s => s.last_seen || 0, render: s => {
      const sp = document.createElement('span'); sp.textContent = s.last_seen ? 'il y a ' + humanAge(s.age_s) : '—'; if (s.last_seen) sp.title = fmtTs(s.last_seen); return sp;
    } },
    { key: 'n_24h', label: '24 h', sortable: true, align: 'r', sortVal: s => s.n_24h || 0, render: s => s.n_24h != null ? String(s.n_24h) : '0' },
    { key: 'status', label: 'Statut', sortable: true, sortVal: s => (SRANK_SRC[s.status] ?? 9), render: s => {
      const f = document.createDocumentFragment();
      const dot = document.createElement('span'); dot.className = 'fdot ' + (SRC_DOT[s.status] || 'calme');
      const lbl = document.createElement('b'); lbl.className = SRC_TXT[s.status] || 'calm'; lbl.textContent = s.status || '—';
      f.append(dot, lbl); return f;
    } },
    { key: 'category', label: 'Catégorie', sortable: true, sortVal: s => s.category || '', render: s => s.category || '—' },
    { key: 'note', label: 'Note', render: s => { const sp = document.createElement('span'); sp.textContent = s.note || ''; if (s.note) sp.title = s.note; return sp; } },
  ];
  if (S.isAdmin) columns.push({ key: 'actions', label: 'Actions', render: s => {
    const box = document.createElement('span'); box.style.whiteSpace = 'nowrap';
    const edit = document.createElement('button'); edit.type = 'button'; edit.className = 'picon'; edit.innerHTML = ic('pencil');
    edit.title = 'Éditer libellé / catégorie / note'; edit.onclick = e => { e.stopPropagation(); editSourceMeta(s); };
    // batch-2 item 4 : le toggle « attendu » n'avait AUCUNE classe -> rendu <button> natif dans la cellule
    // pagedList (.qtable td). On lui donne le chrome .picon (comme edit/clr) + un état on/off coloré.
    const tog = document.createElement('button'); tog.type = 'button';
    tog.className = 'picon srctoggle ' + (s.expected ? 'on' : 'off'); tog.style.marginLeft = '6px';
    tog.textContent = s.expected ? 'attendu' : 'inattendu';
    tog.title = s.expected ? 'Basculer : marquer comme inattendu' : 'Basculer : marquer comme attendu';
    tog.onclick = e => { e.stopPropagation(); toggleExpected(s); };
    const clr = document.createElement('button'); clr.type = 'button'; clr.className = 'picon'; clr.style.marginLeft = '6px'; clr.innerHTML = ic('x');
    clr.title = 'Réinitialiser les métadonnées d\'affichage'; clr.onclick = e => { e.stopPropagation(); clearSourceMeta(s); };
    box.append(edit, tog, clr); return box;
  } });
  pagedList(tblHost, { mode: 'client', pageSize: 50, rows: sources, columns, emptyText: 'aucune source' });
  if (sources.length) {
    const legend = document.createElement('div'); legend.className = 'muted'; legend.style.cssText = 'margin-top:8px;font-size:11px';
    // « dégradé / en retard » RETIRÉ de cette légende — le serveur n'émet JAMAIS `warn` pour
    // /sources (cet état est DÉRIVÉ côté client, propre à Fraîcheur). Renvoi vers l'onglet Données → Fraîcheur.
    legend.textContent = 'Statut = santé de collecte (même vocabulaire que Données → Fraîcheur) : frais (<15 min) · calme (peu active, OK) · en attente (déclarée, pas encore de donnée) · muet (collecte en panne) · dormant (rare/à la demande, variante de calme). L\'état « dégradé / en retard » est dérivé côté Fraîcheur (alertes actives ou retard au-delà de la cadence) : une source peut donc être « calme » ici et « dégradé » dans Fraîcheur, par conception (voir Données → Fraîcheur). « inattendu » = source non déclarée dans les collecteurs connus (signal à examiner, pas un défaut).';
    wrap.appendChild(legend);
  }
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
  const suppressing = target && s.unexpected;   // masquer un signal « inattendu » = plus sensible (audité sev 3 côté daemon)
  const msg = target
    ? `Marquer « ${s.source} » comme ATTENDU ?` + (s.unexpected ? ' Cela masque le signal « source inattendue ». La collecte et les règles ne sont PAS modifiées (affichage seul). Action auditée.' : ' (affichage seul, action auditée)')
    : `Marquer « ${s.source} » comme INATTENDU ? (rétablit le signal ; affichage seul, action auditée)`;
  if (!await confirmModal(msg, { danger: suppressing, okText: target ? 'Marquer attendu' : 'Marquer inattendu' })) return;
  if (await sourcePut(s.source, 'set_expected', target)) { toast('mis à jour', 'ok'); loadSourcesView(); }
}

async function clearSourceMeta(s) {
  if (!await confirmModal(`Réinitialiser les métadonnées d'affichage de « ${s.source} » (libellé, catégorie, note, attendu) ? La collecte n'est pas touchée.`, { danger: true, okText: 'Réinitialiser' })) return;
  if (await sourcePut(s.source, 'clear')) { toast('réinitialisé', 'ok'); loadSourcesView(); }
}


export { loadSourcesView };
