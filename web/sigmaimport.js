// sigmaimport.js — import Sigma EN MASSE (admin) : la boucle « fermer les angles morts » de la matrice
// ATT&CK. Bouton « Importer un ruleset Sigma » -> modale (upload d'archive / collage multi-docs YAML ou
// tableau JSON de docs Sigma) -> POST /api/sigma/import-bulk -> rendu du SUMMARY renvoyé :
//   { imported, updated, skipped:[{ref,reason}], coverage_before, coverage_after, techniques_newly_covered }
// On met en avant le DELTA de couverture (« X techniques nouvellement couvertes », angles morts avant->après)
// et on liste les rejets (ref + raison) dans un tableau.
//
// SÉCU : ADMIN uniquement côté UI (socIsAdmin) ; la VRAIE garde reste serveur (route /api/sigma/* =
//   default-deny=admin). Tout en textContent/attributs (anti-XSS). Les règles importées arrivent DÉSACTIVÉES
//   (comportement backend) -> on le signale + lien vers la liste des règles pour relire/activer.
// DÉGRADATION : si /api/sigma/import-bulk 404 (daemon concurrent pas encore déployé), message clair, aucune
//   erreur dure. ADDITIF : ce module n'écrit rien tout seul (une mutation = un import explicite de l'admin).
import { $, esc, ic, muted, toast, apiSend, closeModals, withBusy, pagedList, socIsAdmin } from './core.js';

// Rafraîchisseur post-import (injecté par app.js via initSigmaImport) : recharge règles/couverture/matrice.
// `var` (hoisté, PAS de TDZ) et non `let` : app.js appelle initSigmaImport au top-level et le graphe est
// CIRCULAIRE (sigmaimport <-> app) -> selon l'ordre d'évaluation, initSigmaImport peut tourner AVANT que la
// ligne de déclaration ne s'exécute ; un `let` lèverait une ReferenceError (TDZ). `var` -> undefined, sûr.
var _onImported = null;

// dataURL -> base64 pur (sans le préfixe « data:...;base64, »).
function readFileBase64(file) {
  return new Promise((resolve, reject) => {
    const fr = new FileReader();
    fr.onload = () => { const s = String(fr.result || ''); const i = s.indexOf(','); resolve(i >= 0 ? s.slice(i + 1) : s); };
    fr.onerror = () => reject(new Error('lecture du fichier impossible'));
    fr.readAsDataURL(file);
  });
}

// coverage_before/after peut être un nombre (nb de techniques couvertes) OU un objet
// ({covered,total} / {techniques,blindspots} / {count}) -> on en extrait {covered, total} au mieux.
function covShape(v) {
  if (v == null) return null;
  if (typeof v === 'number') return { covered: v, total: null };
  if (typeof v === 'object') {
    const covered = firstNum(v.covered, v.covered_techniques, v.techniques, v.count, v.n);
    const total = firstNum(v.total, v.total_techniques, v.techniques_total);
    const blind = firstNum(v.blindspots, v.blind_spots, v.uncovered);
    return { covered, total: total != null ? total : (covered != null && blind != null ? covered + blind : null) };
  }
  return null;
}
function firstNum() { for (const a of arguments) if (typeof a === 'number' && !isNaN(a)) return a; return null; }

// techniques_newly_covered : tableau (de tid string ou {tid,name}) OU nombre -> {count, ids[]}.
function newlyCovered(v) {
  if (Array.isArray(v)) {
    const ids = v.map(x => (typeof x === 'string' ? x : (x && (x.tid || x.technique || x.mitre) || ''))).filter(Boolean);
    return { count: v.length, ids };
  }
  if (typeof v === 'number') return { count: v, ids: [] };
  return { count: 0, ids: [] };
}

// Rendu du SUMMARY dans le conteneur `host`. Défensif sur la forme (le daemon est construit en concurrence).
function renderSummary(host, sum) {
  host.replaceChildren();
  sum = sum || {};
  const imported = firstNum(sum.imported) != null ? firstNum(sum.imported) : (Array.isArray(sum.imported) ? sum.imported.length : 0);
  const updated = firstNum(sum.updated) || 0;
  const skipped = Array.isArray(sum.skipped) ? sum.skipped : [];
  const before = covShape(sum.coverage_before);
  const after = covShape(sum.coverage_after);
  const nc = newlyCovered(sum.techniques_newly_covered);

  // --- bandeau de comptes (importées / mises à jour / ignorées) ---
  const errors = firstNum(sum.errors) || 0;
  const counts = document.createElement('div'); counts.className = 'sigma-counts';
  const chip = (label, val, cls) => { const s = document.createElement('span'); s.className = 'sigma-chip' + (cls ? ' ' + cls : ''); const b = document.createElement('b'); b.textContent = String(val); s.append(b, document.createTextNode(' ' + label)); return s; };
  counts.append(chip('importée(s)', imported, 'ok'), chip('mise(s) à jour', updated), chip('ignorée(s)', skipped.length, skipped.length ? 'warn' : ''));
  if (errors > 0) counts.appendChild(chip('erreur(s) de traduction', errors, 'warn'));
  host.appendChild(counts);
  // note serveur éventuelle (ex. « bundle vide : no-op »)
  if (sum.note) { const n = document.createElement('div'); n.className = 'sigma-servernote'; n.textContent = String(sum.note); host.appendChild(n); }

  // --- DELTA de couverture MIS EN AVANT ---
  // Emphase conditionnelle (peaufinage) : gain -> accent succès ; aucun gain -> carte neutre (muet).
  const delta = document.createElement('div'); delta.className = 'sigma-delta' + (nc.count > 0 ? ' pos' : ' none');
  const dh = document.createElement('div'); dh.className = 'sigma-delta-h';
  dh.textContent = nc.count > 0 ? (nc.count + ' technique(s) nouvellement couverte(s)') : 'aucune nouvelle technique couverte';
  delta.appendChild(dh);
  if (before && after && before.covered != null && after.covered != null) {
    const line = document.createElement('div'); line.className = 'sigma-delta-line';
    const cov = document.createElement('span');
    cov.textContent = 'Techniques couvertes : ' + before.covered + (before.total != null ? '/' + before.total : '') + ' → ' + after.covered + (after.total != null ? '/' + after.total : '');
    line.appendChild(cov);
    if (before.total != null && after.total != null) {
      const bBlind = before.total - before.covered, aBlind = after.total - after.covered;
      const bs = document.createElement('span'); bs.className = 'sigma-blind';
      bs.textContent = ' · angles morts : ' + bBlind + ' → ' + aBlind + (aBlind < bBlind ? ' (−' + (bBlind - aBlind) + ')' : '');
      line.appendChild(bs);
    }
    delta.appendChild(line);
  }
  if (nc.ids.length) {
    const chips = document.createElement('div'); chips.className = 'sigma-tids';
    nc.ids.slice(0, 60).forEach(id => { const c = document.createElement('span'); c.className = 'mitrechip'; c.textContent = id; chips.appendChild(c); });
    if (nc.ids.length > 60) chips.appendChild(muted('+' + (nc.ids.length - 60) + '…'));
    delta.appendChild(chips);
  }
  host.appendChild(delta);

  // --- note : règles importées DÉSACTIVÉES (défaut backend) + lien vers la liste des règles ---
  // On honore le drapeau serveur `disabled_on_import` (défaut true) plutôt que de le présumer.
  if (sum.disabled_on_import !== false && (imported || updated)) {
    const note = document.createElement('div'); note.className = 'sigma-note';
    note.appendChild(document.createTextNode('Les règles importées arrivent '));
    const strong = document.createElement('b'); strong.textContent = 'désactivées'; note.appendChild(strong);
    note.appendChild(document.createTextNode(' — relisez-les puis activez celles voulues dans '));
    const link = document.createElement('a'); link.href = '#detection'; link.className = 'sigma-link'; link.textContent = 'la liste des règles';
    link.onclick = () => { closeModals(); location.hash = 'detection'; };
    note.appendChild(link); note.appendChild(document.createTextNode('.'));
    host.appendChild(note);
  }

  // --- tableau des rejets (ref + raison) ---
  if (skipped.length) {
    const cap = document.createElement('div'); cap.className = 'sigma-skip-h'; cap.textContent = 'Ignorées (' + skipped.length + ')';
    host.appendChild(cap);
    // BATCH #13 — un bulk-import volumineux peut rejeter beaucoup de règles : liste paginée (pattern canonique).
    const skHost = document.createElement('div'); host.appendChild(skHost);
    pagedList(skHost, {
      mode: 'client', pageSize: 50, rows: skipped,
      columns: [
        { key: 'ref', label: 'Règle', sortable: true, sortVal: s => (s && (s.ref || s.title || s.name)) || '', render: s => (s && (s.ref || s.title || s.name)) || '(sans nom)' },
        { key: 'reason', label: 'Raison', sortable: true, sortVal: s => (s && s.reason) || '', render: s => { const d = document.createElement('span'); d.style.whiteSpace = 'normal'; d.textContent = (s && s.reason) || '—'; return d; } },
      ],
    });
  }

  if (_onImported && (imported || updated)) { try { _onImported(); } catch (e) { /* refresh best-effort */ } }
}

// Construit le corps de requête (contrat backend : {content} | {content_b64} | {rules:[…]}). Un fichier est
// envoyé en `content_b64` (voie « upload » du daemon : ses octets bruts base64, décodés côté serveur ; sûr
// pour n'importe quel bundle texte YAML/JSON multi-docs). Un collage part en `content` (texte). Renvoie
// {body} ou {err}. NB : le backend n'extrait PAS d'archive compressée (.zip/.gz) — il attend un bundle TEXTE ;
// un binaire compressé retombe proprement sur une erreur serveur (« non-UTF8 ») gérée à l'appel.
async function buildBody(file, pasted) {
  if (file) {
    const name = file.name || 'ruleset';
    const b64 = await readFileBase64(file);
    if (!b64) return { err: 'le fichier est vide.' };
    return { body: { content_b64: b64, filename: name } };
  }
  const txt = (pasted || '').trim();
  if (!txt) return { err: 'collez des règles Sigma (multi-docs YAML séparés par « --- » ou tableau JSON) ou choisissez un fichier.' };
  return { body: { content: txt } };
}

// Ouvre la modale d'import. Admin-only côté UI (garde serveur = vraie garde).
export function openSigmaImport() {
  if (!socIsAdmin()) { toast("Import Sigma réservé à l'administrateur.", 'bad'); return; }
  closeModals();
  const ov = document.createElement('div'); ov.className = 'modal-ov';
  const box = document.createElement('div'); box.className = 'modal sigma-modal';
  const form = document.createElement('form');
  form.innerHTML =
    '<h3>Importer un ruleset Sigma</h3>' +
    '<p class="modal-msg">Absorbez une bibliothèque de détection <b>Sigma</b> (standard ouvert) pour combler les angles morts ATT&amp;CK. ' +
    'Déposez un <b>fichier bundle</b> Sigma (<code>.yml</code>/<code>.yaml</code>/<code>.json</code>, multi-documents) <b>ou</b> collez du <b>YAML multi-documents</b> (séparés par <code>---</code>) ou un <b>tableau JSON</b> de docs Sigma. ' +
    'Les règles importées arrivent <b>désactivées</b> — vous les relirez avant activation.</p>' +
    '<label class="modal-f"><span>Fichier bundle Sigma (YAML/JSON multi-docs)</span>' +
    '<input type="file" data-n="file" accept=".yml,.yaml,.json,.txt"></label>' +
    '<label class="modal-f"><span>… ou coller (YAML multi-docs / tableau JSON)</span>' +
    '<textarea data-n="paste" rows="7" spellcheck="false" placeholder="title: ...\nlogsource: ...\ndetection:\n  ...\n---\ntitle: ..."></textarea></label>' +
    '<div class="modal-err" hidden></div>' +
    '<div class="sigma-result" hidden></div>' +
    '<div class="modal-act"><button type="button" class="m-cancel">Fermer</button><button type="submit" class="m-ok">Importer</button></div>';
  box.appendChild(form); ov.appendChild(box); document.body.appendChild(ov);

  const errEl = form.querySelector('.modal-err');
  const resEl = form.querySelector('.sigma-result');
  const okBtn = form.querySelector('.m-ok');
  const fileEl = form.querySelector('[data-n="file"]');
  const pasteEl = form.querySelector('[data-n="paste"]');
  const showErr = m => { errEl.textContent = m; errEl.hidden = false; };
  const close = () => { ov.classList.add('out'); document.removeEventListener('keydown', onKey); setTimeout(() => ov.remove(), 160); };
  const onKey = e => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', onKey);
  form.querySelector('.m-cancel').onclick = close;
  ov.onclick = e => { if (e.target === ov) close(); };

  form.onsubmit = e => {
    e.preventDefault();
    errEl.hidden = true;
    return withBusy(okBtn, async () => {
      const file = fileEl.files && fileEl.files[0];
      const { body, err } = await buildBody(file, pasteEl.value);
      if (err) { showErr(err); return; }
      let sum;
      try {
        sum = await apiSend('/sigma/import-bulk', 'POST', body);
      } catch (ex) {
        const msg = (ex && ex.message) || String(ex);
        if (/(^|\s)404(\s|$)/.test(msg)) { showErr("Import en masse indisponible : l'endpoint /api/sigma/import-bulk n'est pas encore déployé (daemon en cours). Réessayez après le déploiement."); return; }
        if (/(^|\s)403(\s|$)/.test(msg)) { showErr("Refusé (403) : l'import Sigma est réservé à l'administrateur."); return; }
        if (/UTF-?8|base64/i.test(msg)) { showErr("Fichier non reconnu comme bundle Sigma TEXTE. Les archives compressées (.zip/.gz) ne sont pas prises en charge — fournissez un bundle YAML/JSON (multi-docs) ou collez le texte."); return; }
        showErr('Échec de l’import : ' + msg);
        return;
      }
      // apiSend renvoie null sur corps vide ; on rend quand même (comptes à 0) sans casser.
      resEl.hidden = false;
      renderSummary(resEl, sum || {});
      okBtn.textContent = 'Ré-importer';
      const imp = firstNum((sum || {}).imported);
      toast(imp != null ? (imp + ' règle(s) Sigma importée(s) (désactivées)') : 'Import Sigma traité', 'ok');
    });
  };
  setTimeout(() => { if (pasteEl) pasteEl.focus(); }, 30);
}

// Câble le bouton d'ouverture (#sigma-import-btn) + mémorise le rafraîchisseur post-import.
export function initSigmaImport(opts) {
  _onImported = (opts && opts.onImported) || null;
  const btn = $('#sigma-import-btn');
  if (btn) btn.onclick = openSigmaImport;
}
