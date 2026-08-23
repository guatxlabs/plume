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

// Libellé de la cadence DÉCLARÉE (par une sonde du démon OU par l'exploitant) — jamais la moyenne
// observée, qui est rendue à part. P11.3-c : « non déclarée » n'est PAS un défaut et ne se dit plus comme
// tel — c'est un blanc que personne n'a comblé, et l'événementiel est une RÉPONSE, pas un trou.
function cadenceLabel(s) {
  if (s.cadence_declaree === 'continue') return 'continu' + (s.cadence_interval_s ? ' · ' + humanAge(s.cadence_interval_s) : '');
  if (s.cadence_declaree === 'evenementielle') return 'événementiel — pas de cadence par nature';
  return 'aucune cadence déclarée';
}
// D'OÙ vient la cadence affichée, en clair : la sonde du démon, l'exploitant (avec sa date), ou personne.
function cadenceTitre(s) {
  if (s.cadence_declaree === 'evenementielle') {
    return (s.cadence_par ? 'déclarée événementielle par ' + s.cadence_par + (s.cadence_le ? ' le ' + fmtTs(s.cadence_le) : '') : s.cadence_declarant || '')
      + ' — le débit dépend d\'une activité extérieure : un silence ne prouve rien, cette source ne sera jamais « en retard ».';
  }
  if (s.cadence_declaree === 'continue') {
    return (s.cadence_par ? 'déclarée par ' + s.cadence_par + (s.cadence_le ? ' le ' + fmtTs(s.cadence_le) : '') : s.cadence_declarant || '')
      + ' — au-delà de trois cycles sans donnée, le statut passe « en retard ».'
      + (s.observed_interval_s ? ' Rythme observé sur 24 h : ~1 donnée / ' + humanAge(s.observed_interval_s) + '.' : '');
  }
  return 'Personne ne l\'a déclarée : ni une sonde du démon, ni l\'exploitant. Ce n\'est pas un défaut de collecte — la console ignore simplement le rythme attendu, donc cette source ne peut pas être « en retard ».'
    + (s.observed_interval_s ? ' Rythme observé sur 24 h : ~1 donnée / ' + humanAge(s.observed_interval_s) + '.' : '');
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
    ? 'Inventaire des sources d\'ingestion. Les déclarations et métadonnées ci-dessous (déclarée, cadence attendue, libellé, catégorie, note) ne changent que ce qui est AFFICHÉ — la collecte, les règles et les alertes ne sont jamais modifiées depuis cette console. La configuration des collecteurs hôte est hors périmètre.'
    : 'Ingestion en panne — aucune donnée reçue récemment.';
  wrap.appendChild(banner);
  const tblHost = document.createElement('div'); wrap.appendChild(tblHost);
  const editable = canEditSources();
  const nUnexpected = sources.filter(s => s.unexpected).length;
  if (nUnexpected) {
    const hint = document.createElement('div'); hint.className = 'fwarn'; hint.style.cssText = 'margin:0 0 8px;font-size:12px';
    hint.textContent = nUnexpected + ' source(s) que personne n\'a déclarée(s) — ni ce dépôt, ni le démon, ni le produit, ni un connecteur, ni l\'exploitant. '
      + (editable ? 'Une source installée hors de ce dépôt se déclare ici : Actions → « déclarer attendue » (persistant, réversible, audité).'
                  : 'Une source installée hors de ce dépôt se déclare ici ; il faut le rôle éditeur ou administrateur (geste persistant, réversible, audité).');
    wrap.insertBefore(hint, tblHost);
  }
  // colonnes : render -> NŒUD (badges/pastilles/boutons survivent) ; sortVal -> clé de tri par colonne.
  const columns = [
    { key: 'source', label: 'Source', sortable: true, sortVal: s => s.source == null ? '' : s.source, render: s => {
      const f = document.createDocumentFragment();
      const nm = document.createElement('span'); nm.textContent = s.source == null ? '' : s.source; f.appendChild(nm);
      if (s.unexpected) {
        const bad = document.createElement('span'); bad.className = 'badge srcbadge-unexpected'; bad.textContent = 'non déclarée';
        bad.style.cssText = 'margin-left:6px;color:var(--warn);border-color:color-mix(in srgb,var(--warn) 40%,transparent)';
        bad.title = 'Personne n\'a déclaré cette source — un signal à examiner, pas un défaut de collecte. Si elle est voulue (une sonde installée hors de ce dépôt l\'est autant qu\'une autre), un éditeur la déclare depuis Actions.';
        f.appendChild(bad);
      }
      return f;
    } },
    { key: 'expected', label: 'Déclarée', sortable: true, sortVal: s => s.expected ? 1 : 0, render: s => {
      const f = document.createDocumentFragment();
      const exp = document.createElement('span'); exp.className = 'badge srcbadge-expected';
      // « attendu » veut dire DÉCLARÉ PAR QUELQU'UN : le badge nomme le déclarant plutôt qu'un oui/non nu.
      exp.textContent = s.expected ? (s.declaree_par || 'oui') : 'personne';
      exp.style.color = s.expected ? 'var(--ok)' : 'var(--warn)';
      exp.title = s.expected
        ? 'Cette source est DÉCLARÉE : quelqu\'un l\'a voulue. Le détail dit qui.'
        : 'Personne ne l\'a déclarée — ni ce dépôt, ni le démon, ni le produit, ni un connecteur, ni un humain de cette installation.';
      f.appendChild(exp);
      // QUI l'a déclarée et QUAND : la provenance PROPRE du geste, jamais le dernier compte qui a touché
      // la ligne (le démon écrit `marquage.updated_by` seulement quand `set_expected` est joué).
      const why = document.createElement('span'); why.className = 'muted srcwhy'; why.style.cssText = 'display:block;font-size:10px';
      const mark = s.marquage;
      if (mark && mark.updated_by && ((mark.expected && !s.in_collectors) || !mark.expected)) {
        why.textContent = (mark.expected ? 'déclarée par ' : 'déclarée NON attendue par ') + mark.updated_by + (mark.updated ? ' le ' + fmtTs(mark.updated) : '');
      } else if (s.raison_attendue) {
        why.textContent = s.raison_attendue;
      } else {
        why.textContent = 'aucune déclaration';
      }
      f.appendChild(why);
      return f;
    } },
    { key: 'cadence', label: 'Cadence', sortable: true, sortVal: s => cadenceLabel(s), render: s => {
      const f = document.createDocumentFragment();
      const sp = document.createElement('span'); sp.textContent = cadenceLabel(s); sp.title = cadenceTitre(s);
      f.appendChild(sp);
      const qui = document.createElement('span'); qui.className = 'muted srccadwho'; qui.style.cssText = 'display:block;font-size:10px';
      qui.textContent = s.cadence_par ? 'déclarée par ' + s.cadence_par + (s.cadence_le ? ' le ' + fmtTs(s.cadence_le) : '')
        : s.cadence_capteur ? 'déclarée par la sonde « ' + s.cadence_capteur + ' »'
        : 'personne ne l\'a déclarée';
      f.appendChild(qui);
      return f;
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
    tog.textContent = s.expected ? 'retirer la déclaration' : 'déclarer attendue';
    tog.title = s.expected ? 'Retirer la déclaration : la source redevient un signal à examiner (persistant, audité)' : 'Déclarer cette source voulue par cette installation (persistant, réversible, audité)';
    tog.onclick = e => { e.stopPropagation(); toggleExpected(s); };
    box.append(edit, tog);
    // LA CADENCE NE SE DÉCLARE QUE LÀ OÙ AUCUNE SONDE N'EN DÉCLARE : ailleurs, la sonde fait foi et le
    // démon REFUSE l'écriture — offrir le geste serait promettre un réglage qui n'aurait aucun effet.
    if (s.cadence_declarable) {
      const cad = document.createElement('button'); cad.type = 'button'; cad.className = 'picon srccadence'; cad.style.marginLeft = '6px';
      cad.textContent = 'déclarer la cadence';
      cad.title = 'Dire le rythme attendu de cette source (affichage seul : aucune alerte n\'en dérive)';
      cad.onclick = e => { e.stopPropagation(); declareCadence(s); };
      box.append(cad);
    }
    const clr = document.createElement('button'); clr.type = 'button'; clr.className = 'picon'; clr.style.marginLeft = '6px'; clr.innerHTML = ic('x');
    clr.title = 'Réinitialiser les déclarations et les métadonnées d\'affichage de cette source'; clr.onclick = e => { e.stopPropagation(); clearSourceMeta(s); };
    box.append(clr); return box;
  } });
  pagedList(tblHost, { mode: 'client', pageSize: 50, rows: sources, columns, emptyText: 'aucune source' });
  if (sources.length) {
    const legend = document.createElement('div'); legend.className = 'muted'; legend.style.cssText = 'margin-top:8px;font-size:11px';
    legend.textContent = 'Statut = santé de collecte (même dérivation que Données → Fraîcheur) : frais (donnée < 15 min) · calme (collecte saine, source peu active) · en retard (cadence DÉCLARÉE continue dépassée — c\'est le « muet » du capteur dans Intégrations) · en attente (déclarée, pas encore de donnée) · muet (plus rien n\'arrive, toutes sources confondues). « Déclarée » veut dire voulue par QUELQU\'UN : ce dépôt (un fichier livré l\'émet), le démon (une sonde l\'observe), le produit (il l\'agrège), un connecteur configuré, ou l\'exploitant — une source installée hors de ce dépôt se déclare ici, et la colonne dit qui l\'a fait et quand. La cadence attendue se déclare de la même façon là où aucune sonde n\'en déclare : « aucune cadence déclarée » est un blanc, pas un défaut, et une source événementielle ou sans cadence n\'est jamais « en retard ».';
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
  const suppressing = target && s.unexpected;   // déclarer une source que rien ne déclarait = étouffer un signal (audité sév. 3 côté démon)
  const msg = target
    ? `Déclarer « ${s.source} » attendue ?` + (s.unexpected ? ' Le signal « personne ne l\'a déclarée » disparaît, et l\'inventaire dira que vous l\'avez déclarée, avec la date. La collecte et les règles ne sont PAS modifiées (affichage seul). Geste persistant, réversible, audité.' : ' (affichage seul, geste audité)')
    : `Retirer la déclaration de « ${s.source} » ? (elle redevient un signal à examiner ; affichage seul, geste audité)`;
  if (!await confirmModal(msg, { danger: suppressing, okText: target ? 'Déclarer attendue' : 'Retirer la déclaration' })) return;
  if (await sourcePut(s.source, 'set_expected', target)) { toast('mis à jour', 'ok'); loadSourcesView(); }
}

// DÉCLARER LA CADENCE d'une source que ce dépôt n'observe pas. Trois réponses possibles, dont le RETRAIT :
// sans lui, un exploitant pourrait déclarer et jamais se dédire. Le démon refuse le geste là où une sonde
// déclare déjà — la question n'est donc pas posée dans ce cas (le bouton n'est pas rendu).
async function declareCadence(s) {
  const r = await modal({
    title: 'Cadence attendue : ' + s.source, okText: 'Déclarer', danger: false,
    message: 'La cadence attendue sert au STATUT affiché (ici et dans Fraîcheur). Elle ne crée aucune alerte : le dead-man\'s-switch reste celui des sondes du démon.',
    validate: v => (v.nature === 'continue' && !(Number(v.interval_s) > 0)) ? 'Une cadence continue demande un intervalle en secondes.' : null,
    fields: [
      { name: 'nature', label: 'Nature', type: 'select', value: s.cadence_declaree === 'non_declaree' ? 'inconnue' : (s.cadence_declaree || 'inconnue'), options: [
        { value: 'continue', label: 'continue — un point est attendu à intervalle régulier' },
        { value: 'evenementielle', label: 'événementielle — pas de cadence par nature' },
        { value: 'inconnue', label: 'retirer la déclaration — la console ignore le rythme' },
      ] },
      { name: 'interval_s', label: 'Intervalle attendu (secondes, si continue)', value: s.cadence_interval_s ? String(s.cadence_interval_s) : '' },
    ],
  });
  if (!r) return;
  const b = { source: s.source, action: 'set_cadence', value: r.nature };
  if (r.nature === 'continue') b.interval_s = Number(r.interval_s || 0);
  try { await apiSend('/sources/settings', 'PUT', b); }
  catch (e) { toast((e && e.message) || 'échec', 'bad'); return; }
  toast('cadence déclarée', 'ok'); loadSourcesView();
}

async function clearSourceMeta(s) {
  if (!await confirmModal(`Réinitialiser « ${s.source} » (libellé, catégorie, note, déclaration attendue, cadence déclarée) ? La source reprend le verdict que ce dépôt en dérive. La collecte n'est pas touchée.`, { danger: true, okText: 'Réinitialiser' })) return;
  if (await sourcePut(s.source, 'clear')) { toast('réinitialisé', 'ok'); loadSourcesView(); }
}


export { loadSourcesView, renderSourcesInventory };
