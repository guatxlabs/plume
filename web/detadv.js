// detadv.js — #37 Détection avancée : corrélations multi-événements (finding-groups) + baselines UEBA.
// Vit dans l'espace DÉTECTION & RÉPONSE. Lecture viewer+ ; CRUD éditeur+ (le viewer voit en lecture seule,
// boutons masqués via CSS role-viewer + garde SERVEUR editor+). Endpoints :
//   GET  /api/correlations            -> {correlations:[{id,name,enabled,key_field,entity_type,steps,window_s,interval_s,severity,mitre,risk_score,last_run,last_fired,managed}]}
//   POST /api/correlations            -> crée ; POST /api/correlations/{id} -> édite ; DELETE -> supprime
//   POST /api/correlations/{id}/test   -> backtest {ok,matched,entities:[{entity,detail}]}
//   GET  /api/baselines / POST … /{id} / DELETE … / POST …/{id}/test (aperçu {ok,bucket,observed,anomalies,hits})
// SÉCU UI : tout en textContent/esc (anti-XSS). Mutations via apiSend (CSRF auto).
import { $, api, apiSend, effacerLeRefusDUnGeste, esc, faceDansLaLangue, fetchInto, fmtTs, humanAge, muted, pagedList, peindreLeRefusDUnEssai, peindreLeRefusDUnGeste, puitsDuRefusDUnGeste, sev, toast, modal, confirmModal, ilYA, unEssaiSansResultat, unRefusServiEnDeuxCents } from './core.js';
// P11.1-e : où arrive ce qu'une corrélation / une baseline produit (Alertes, ou Risque si risk_score > 0).
import { announceCreated, takePendingNote, detectionDestination, destinationSentence, suiteDUnProducteurCree } from './producer_ui.js';

// ---- helpers ----
// `P10.27-d` — LES PUITS DES GESTES DE LA DÉTECTION AVANCÉE, un par liste (corrélations, lignes de base), posés juste
// avant elle, hors de ce qu'elle repeint : création, modification, retrait, essai. La forme est celle du point commun
// (`peindreLeRefusDUnGeste`, core.js). MESURÉ AVANT CE LOT (témoin 118) : « erreur : 503 {"error":"CORRÉLATION NON CRÉÉE :
// … » dans un avis qui s'efface, coupé avant ce qui reste vrai.
const puitsAvantLaListe = (sel, surface) => { const liste = $(sel); return liste && liste.parentNode ? puitsDuRefusDUnGeste(liste.parentNode, surface, liste) : null; };
const puitsDesCorrelations = () => puitsAvantLaListe('#detadv-corr-list', 'correlations');
const puitsDesLignesDeBase = () => puitsAvantLaListe('#detadv-base-list', 'lignes_de_base');
function stepCount(stepsJson) {
  try { const a = JSON.parse(stepsJson || '[]'); return Array.isArray(a) ? a.length : 0; } catch { return 0; }
}
function actionsCell(onTest, onEdit, onDel) {
  const wrap = document.createElement('span'); wrap.className = 'row-actions';
  const mk = (label, title, cls, fn) => { const b = document.createElement('button'); b.type = 'button'; b.className = 'picon' + (cls ? ' ' + cls : ''); b.textContent = label; b.title = title; b.onclick = e => { e.stopPropagation(); fn(); }; return b; };
  wrap.appendChild(mk('Test', 'Backtest / aperçu sur la fenêtre courante', '', onTest));
  const ed = mk('Éditer', 'Modifier', 'crud-btn', onEdit);   // masqué au viewer (CSS body.role-viewer .crud-btn)
  const dl = mk('Suppr.', 'Supprimer', 'crud-btn', onDel);
  wrap.append(ed, dl);
  return wrap;
}

// ============================ CORRÉLATIONS ============================

async function loadCorrelations() {
  const host = $('#detadv-corr-list'); if (!host) return;
  const d = await fetchInto(host, '/correlations'); if (!d) return;
  // `P10.20-a` — DES CORRÉLATIONS NON LUES NE SONT PAS « AUCUNE CORRÉLATION ». `correlations_list`
  // (daemon/src/handlers/detection_advanced.rs) sert, en 200, `{correlations: null, error: <cause>,
  // lecture_non_faite: true}` quand la lecture échoue EN BLOC ; `api()` ne jette que sur `!r.ok`, et le
  // repli `Array.isArray(...) ? ... : []` transformait exactement cet aveu en liste vide. Le texte de vide
  // rendu plus bas invite alors à « créer une séquence » sur un moteur de corrélation dont personne ne sait
  // s'il en porte déjà : la cause SERVIE est écrite à la place, et aucune ligne n'est peinte sous elle.
  if (d.error) {
    const aveu = document.createElement('div'); aveu.className = 'bad'; aveu.style.cssText = 'margin:0;font-size:12px';
    const dit = document.createElement('span');
    dit.textContent = 'Corrélations NON LUES : le démon a refusé et en nomme la cause —';
    aveu.append(dit, ' « ' + String(d.error).trim() + ' »');
    host.replaceChildren(aveu);
    return;
  }
  const rows = (d && Array.isArray(d.correlations)) ? d.correlations : [];
  const nowS = Math.floor(Date.now() / 1000);
  pagedList(host, {
    mode: 'client', pageSize: 25, rows,
    sort: { key: 'id', dir: 1 },
    columns: [
      { key: 'name', label: 'Nom', sortable: true, sortVal: r => r.name || '', render: r => { const s = document.createElement('span'); s.textContent = r.name || ''; if (!r.enabled) { s.style.opacity = '.5'; s.title = 'désactivée'; } return s; } },
      { key: 'entity_type', label: 'Entité', sortable: true, sortVal: r => r.entity_type || '', render: r => { const c = document.createElement('code'); c.textContent = (r.entity_type || '?') + ' (' + (r.key_field || '?') + ')'; return c; } },
      { key: 'steps', label: 'Étapes', align: 'r', render: r => String(stepCount(r.steps)) },
      { key: 'window_s', label: 'Fenêtre', align: 'r', sortable: true, sortVal: r => r.window_s || 0, render: r => humanAge(r.window_s || 0) },
      { key: 'severity', label: 'Sév.', sortable: true, sortVal: r => r.severity || 0, render: r => { const s = document.createElement('span'); s.className = 'sev'; s.textContent = sev(r.severity); return s; } },
      { key: 'mode', label: 'Mode', render: r => (r.risk_score > 0 ? 'RBA +' + r.risk_score : 'alerte') },
      { key: 'mitre', label: 'MITRE', sortable: true, sortVal: r => r.mitre || '', render: r => { const c = document.createElement('code'); c.textContent = r.mitre || '—'; return c; } },
      { key: 'last_fired', label: 'Dernier tir', sortable: true, sortVal: r => r.last_fired || 0, render: r => { const s = document.createElement('span'); s.textContent = r.last_fired ? ilYA(nowS - r.last_fired) : '—'; if (r.last_fired) s.title = fmtTs(r.last_fired); return s; } },
      { key: 'act', label: '', render: r => actionsCell(() => testCorrelation(r), () => editCorrelation(r), () => deleteCorrelation(r)) },
    ],
    emptyText: 'aucune corrélation définie — crée une séquence (ex. « échec auth ×N puis succès même IP ») pour lever des finding-groups.',
  });
  const note = takePendingNote('correlations'); if (note) host.insertBefore(note, host.firstChild);
}

function corrFields(c) {
  c = c || {};
  return [
    { name: 'name', label: 'Nom', value: c.name || '', required: true },
    { name: 'key_field', label: 'Champ de clé (entité)', value: c.key_field || 'src_ip', placeholder: 'src_ip | user | host' },
    { name: 'entity_type', label: "Type d'entité", value: c.entity_type || 'ip', placeholder: 'ip | user | host' },
    { name: 'steps', label: 'Étapes (JSON ordonné)', type: 'textarea', value: c.steps || '[{"name":"échec","query":"search source=auth outcome=fail","min_count":3},{"name":"succès","query":"search source=auth outcome=success","min_count":1}]', placeholder: '[{"name":"…","query":"search …","min_count":1}]' },
    { name: 'window_s', label: 'Fenêtre (s)', type: 'number', value: c.window_s == null ? 3600 : c.window_s },
    { name: 'interval_s', label: 'Intervalle éval (s)', type: 'number', value: c.interval_s == null ? 300 : c.interval_s },
    { name: 'severity', label: 'Sévérité (0-4)', type: 'number', value: c.severity == null ? 3 : c.severity },
    { name: 'mitre', label: 'MITRE (Txxxx)', value: c.mitre || '' },
    { name: 'risk_score', label: 'Score RBA (0 = alerte directe)', type: 'number', value: c.risk_score == null ? 0 : c.risk_score },
    { name: 'enabled', label: 'Activée', type: 'checkbox', value: c.enabled == null ? true : !!c.enabled },
  ];
}
function corrPayload(v) {
  let steps; try { steps = JSON.parse(v.steps || '[]'); } catch { steps = null; }
  return {
    name: v.name, key_field: (v.key_field || '').trim(), entity_type: (v.entity_type || '').trim(),
    steps: steps == null ? v.steps : steps, // laisse le serveur rejeter un JSON invalide avec un message clair
    window_s: Number(v.window_s) || 3600, interval_s: Number(v.interval_s) || 300,
    severity: Number(v.severity) || 0, mitre: (v.mitre || '').trim(), risk_score: Number(v.risk_score) || 0,
    enabled: !!v.enabled,
  };
}
async function editCorrelation(c) {
  const isNew = !c;
  const v = await modal({ title: isNew ? 'Nouvelle corrélation' : 'Éditer la corrélation', okText: isNew ? 'Créer' : 'Enregistrer', message: faceDansLaLangue(MOTS_DES_NOTES_DE_DETECTION_AVANCEE.bascule_vers_risque, { destination: destinationSentence(detectionDestination(c && c.risk_score)) }), fields: corrFields(c) });
  if (!v) return;
  const puits = puitsDesCorrelations(); effacerLeRefusDUnGeste(puits);
  try {
    const payload = corrPayload(v);
    await apiSend(isNew ? '/correlations' : '/correlations/' + c.id, 'POST', payload);
    announceCreated('correlations', detectionDestination(payload.risk_score), payload.name, suiteDUnProducteurCree(payload.enabled, payload.interval_s, MOTS_DES_NOTES_DE_DETECTION_AVANCEE.desactivee));
    loadCorrelations();
  } catch (e) { peindreLeRefusDUnGeste(puits, e); }
}
async function deleteCorrelation(c) {
  if (!(await confirmModal(faceDansLaLangue({ fr: 'Supprimer la corrélation « {nom} » ?', en: 'Delete the correlation “{nom}”?' }, { nom: c.name }), { okText: 'Supprimer', danger: true }))) return;
  const puits = puitsDesCorrelations(); effacerLeRefusDUnGeste(puits);
  try { await apiSend('/correlations/' + c.id, 'DELETE'); toast('corrélation supprimée', 'ok'); loadCorrelations(); }
  catch (e) { peindreLeRefusDUnGeste(puits, e); }
}
// `P10.29-f` — L'ESSAI D'UNE CORRÉLATION OU D'UNE LIGNE DE BASE QUE LE DÉMON REFUSE EN DEUX CENTS, DANS LES DEUX LANGUES.
// `P10.29-q` — ET PAR LA FACE NOMMÉE D'UN ESSAI, DANS LE PUITS DE SA LISTE, QUI RESTE. MESURÉ AVANT CE LOT (témoin 121qe) : le
// `{error}` servi en deux cents et le corps sans résultat partaient dans un AVIS qui s'efface au bout de six secondes, et un
// refus en statut d'erreur (rôle, passerelle, demande non aboutie) prenait la forme d'un GESTE — « rien ici n'établit s'il a
// été pris — vérifier son effet avant de le rejouer » prêtait un effet à un essai qui n'en a aucun. Désormais les trois se
// disent par `peindreLeRefusDUnEssai` (web/core.js), cause entière, dans le puits de la corrélation ou de la ligne de base.
// `P10.29-c` — la phrase d'un score de risque et la suite d'une création, dans les deux langues (témoin 120c).
const MOTS_DES_NOTES_DE_DETECTION_AVANCEE = {
  bascule_vers_risque: { fr: '{destination} Un score RBA > 0 la bascule vers Risque.', en: '{destination} An RBA score > 0 moves it to Risk.' },
  desactivee: { fr: "désactivée : cochez « Activée » pour qu'elle tourne", en: 'disabled: tick “Enabled” for it to run' },
};
async function testCorrelation(c) {
  const puits = puitsDesCorrelations(); effacerLeRefusDUnGeste(puits);
  let d;
  try { d = await apiSend('/correlations/' + c.id + '/test', 'POST', {}); } catch (e) { peindreLeRefusDUnEssai(puits, e); return; }
  const refuse = d && d.error != null ? unRefusServiEnDeuxCents(d) : null;
  if (refuse) { peindreLeRefusDUnEssai(puits, refuse); return; }
  if (!d) { peindreLeRefusDUnEssai(puits, unEssaiSansResultat()); return; }
  const ents = Array.isArray(d.entities) ? d.entities : [];
  const body = document.createElement('div');
  const h = document.createElement('p'); h.textContent = faceDansLaLangue({ fr: '{n} entité(s) complètent la séquence sur la fenêtre courante.', en: '{n} entity(ies) complete the sequence over the current window.' }, { n: d.matched }); body.appendChild(h);
  const list = document.createElement('div');
  pagedList(list, { mode: 'client', pageSize: 15, rows: ents, columns: [
    { key: 'entity', label: 'Entité', render: r => { const c2 = document.createElement('code'); c2.textContent = r.entity || ''; return c2; } },
    { key: 'detail', label: 'Séquence', render: r => { const s = document.createElement('span'); s.textContent = r.detail || ''; return s; } },
  ], emptyText: 'aucune entité ne complète la séquence (rien à lever).' });
  body.appendChild(list);
  showResultModal('Backtest — ' + c.name, body);
}

// ============================ BASELINES (UEBA) ============================

async function loadBaselines() {
  const host = $('#detadv-base-list'); if (!host) return;
  const d = await fetchInto(host, '/baselines'); if (!d) return;
  // `P10.7-f` — DES LIGNES DE BASE NON LUES NE SONT PAS « AUCUNE LIGNE DE BASE DÉFINIE ». `fetchInto` ne
  // capte qu'une EXCEPTION ; l'aveu du démon arrive en 200, forme intacte : `{baselines: [], error:
  // <cause>}` (`corps_de_liste_illisible`, daemon/src/handlers/detection_advanced.rs). Le test
  // `Array.isArray(d.baselines)` est VRAI sur ce corps-là — un tableau vide EST un tableau —, si bien que
  // le repli ne se déclenchait même pas : la table se peignait avec son `emptyText`, « aucune baseline
  // définie — crée une métrique par entité », c'est-à-dire une INVITATION À CRÉER ce qui existe peut-être
  // déjà, sur la détection comportementale (UEBA) dont l'exploitant conclurait qu'elle ne tourne pas.
  if (d.error) {
    const aveu = document.createElement('div'); aveu.className = 'bad'; aveu.style.cssText = 'margin:0;font-size:12px';
    const dit = document.createElement('span');
    dit.textContent = 'Lignes de base NON LUES : le démon a refusé et en nomme la cause —';
    aveu.append(dit, ' « ' + String(d.error).trim() + ' »');
    host.replaceChildren(aveu);
    return;
  }
  const rows = (d && Array.isArray(d.baselines)) ? d.baselines : [];
  pagedList(host, {
    mode: 'client', pageSize: 25, rows, sort: { key: 'id', dir: 1 },
    columns: [
      { key: 'name', label: 'Nom', sortable: true, sortVal: r => r.name || '', render: r => { const s = document.createElement('span'); s.textContent = r.name || ''; if (!r.enabled) { s.style.opacity = '.5'; s.title = 'désactivée'; } return s; } },
      { key: 'entity_type', label: 'Entité', render: r => { const c = document.createElement('code'); c.textContent = (r.entity_type || '?') + ' (' + (r.entity_field || '?') + ')'; return c; } },
      { key: 'bucket_s', label: 'Bucket', align: 'r', render: r => humanAge(r.bucket_s || 0) },
      { key: 'z_threshold', label: 'Seuil z', align: 'r', sortable: true, sortVal: r => r.z_threshold || 0, render: r => String(r.z_threshold) },
      { key: 'min_samples', label: 'Min éch.', align: 'r', render: r => String(r.min_samples) },
      { key: 'mode', label: 'Mode', render: r => (r.risk_score > 0 ? 'RBA +' + r.risk_score : 'alerte') },
      { key: 'mitre', label: 'MITRE', render: r => { const c = document.createElement('code'); c.textContent = r.mitre || '—'; return c; } },
      { key: 'act', label: '', render: r => actionsCell(() => testBaseline(r), () => editBaseline(r), () => deleteBaseline(r)) },
    ],
    emptyText: 'aucune baseline définie — crée une métrique par entité (ex. « volume auth par hôte ») pour détecter les déviations (z-score).',
  });
  const note = takePendingNote('baselines'); if (note) host.insertBefore(note, host.firstChild);
}

function baseFields(b) {
  b = b || {};
  return [
    { name: 'name', label: 'Nom', value: b.name || '', required: true },
    { name: 'query', label: 'Requête GXQL (entité + valeur)', type: 'textarea', value: b.query || 'search source=auth | stats count by host', placeholder: 'search … | stats count by host' },
    { name: 'entity_field', label: "Champ d'entité", value: b.entity_field || 'host', required: true },
    { name: 'value_field', label: 'Champ de valeur (vide = dernière colonne)', value: b.value_field || '' },
    { name: 'entity_type', label: "Type d'entité", value: b.entity_type || 'host' },
    { name: 'bucket_s', label: 'Bucket (s)', type: 'number', value: b.bucket_s == null ? 3600 : b.bucket_s },
    { name: 'min_samples', label: 'Échantillons min.', type: 'number', value: b.min_samples == null ? 5 : b.min_samples },
    { name: 'z_threshold', label: 'Seuil de déviation (z)', type: 'number', value: b.z_threshold == null ? 3 : b.z_threshold },
    { name: 'window_s', label: 'Horizon baseline (s)', type: 'number', value: b.window_s == null ? 604800 : b.window_s },
    { name: 'interval_s', label: 'Intervalle éval (s)', type: 'number', value: b.interval_s == null ? 3600 : b.interval_s },
    { name: 'severity', label: 'Sévérité (0-4)', type: 'number', value: b.severity == null ? 2 : b.severity },
    { name: 'mitre', label: 'MITRE (Txxxx)', value: b.mitre || '' },
    { name: 'risk_score', label: 'Score RBA (0 = alerte directe)', type: 'number', value: b.risk_score == null ? 0 : b.risk_score },
    { name: 'enabled', label: 'Activée', type: 'checkbox', value: b.enabled == null ? true : !!b.enabled },
  ];
}
function basePayload(v) {
  return {
    name: v.name, query: v.query, entity_field: (v.entity_field || '').trim(), value_field: (v.value_field || '').trim(),
    entity_type: (v.entity_type || '').trim(), bucket_s: Number(v.bucket_s) || 3600, min_samples: Number(v.min_samples) || 5,
    z_threshold: Number(v.z_threshold) || 3, window_s: Number(v.window_s) || 604800, interval_s: Number(v.interval_s) || 3600,
    severity: Number(v.severity) || 0, mitre: (v.mitre || '').trim(), risk_score: Number(v.risk_score) || 0, enabled: !!v.enabled,
  };
}
async function editBaseline(b) {
  const isNew = !b;
  const v = await modal({ title: isNew ? 'Nouvelle baseline' : 'Éditer la baseline', okText: isNew ? 'Créer' : 'Enregistrer', message: faceDansLaLangue(MOTS_DES_NOTES_DE_DETECTION_AVANCEE.bascule_vers_risque, { destination: destinationSentence(detectionDestination(b && b.risk_score)) }), fields: baseFields(b) });
  if (!v) return;
  const puits = puitsDesLignesDeBase(); effacerLeRefusDUnGeste(puits);
  try {
    const payload = basePayload(v);
    await apiSend(isNew ? '/baselines' : '/baselines/' + b.id, 'POST', payload);
    announceCreated('baselines', detectionDestination(payload.risk_score), payload.name, suiteDUnProducteurCree(payload.enabled, payload.interval_s, MOTS_DES_NOTES_DE_DETECTION_AVANCEE.desactivee));
    loadBaselines();
  } catch (e) { peindreLeRefusDUnGeste(puits, e); }
}
async function deleteBaseline(b) {
  if (!(await confirmModal(faceDansLaLangue({ fr: 'Supprimer la baseline « {nom} » ?', en: 'Delete the baseline “{nom}”?' }, { nom: b.name }), { okText: 'Supprimer', danger: true }))) return;
  const puits = puitsDesLignesDeBase(); effacerLeRefusDUnGeste(puits);
  try { await apiSend('/baselines/' + b.id, 'DELETE'); toast('baseline supprimée', 'ok'); loadBaselines(); }
  catch (e) { peindreLeRefusDUnGeste(puits, e); }
}
// `P10.20-b` — CE QUI DISTINGUE UNE PORTE NON ARMÉE D'UNE LIGNE DE BASE ABSENTE, ET CE QUE ÇA COÛTE. La
// route du dry-run ne porte AUCUN code : tous ses refus vivent dans `error` à 200 (« baseline introuvable »,
// « évaluation échouée », et depuis `P10.20-b` la porte de masquage qu'une pré-lecture ratée n'a pas pu
// armer — daemon/src/handlers/detection_advanced.rs, `CAUSE_PORTE_DRYRUN_NON_ARMEE`). Elle n'offre pas non
// plus de CHAMP qui les sépare : le seul discriminant est l'OUVERTURE de la phrase servie, et c'est dit
// plutôt que caché. Le témoin 96 du harnais ESM ANCRE ce motif dans l'arbre du démon — il extrait la
// constante Rust et exige qu'elle s'ouvre ainsi ; une reformulation côté démon fait REFUSER DE CONCLURE au
// lieu de laisser cette console reclasser un refus de sécurité en « introuvable ».
const OUVERTURE_DU_REFUS_DE_LA_PORTE_DRYRUN = /^DRY-RUN\s+REFUS/;

async function testBaseline(b) {
  const puits = puitsDesLignesDeBase(); effacerLeRefusDUnGeste(puits);
  let d;
  try { d = await apiSend('/baselines/' + b.id + '/test', 'POST', {}); } catch (e) { peindreLeRefusDUnEssai(puits, e); return; }
  const causeServie = (d && typeof d.error === 'string') ? d.error.trim() : '';
  if (OUVERTURE_DU_REFUS_DE_LA_PORTE_DRYRUN.test(causeServie)) {
    // LE REFUS DE LA PORTE NE S'EFFACE PAS AU BOUT DE SIX SECONDES. Ce n'est pas un échec d'évaluation :
    // c'est la garde qui interdit de restituer en clair des échantillons (entité, valeur) que le rôle
    // appelant n'a peut-être pas le droit de voir. Il prend la place de l'aperçu, dans la MÊME modale, et
    // il porte l'aveu à DEUX NŒUDS — la phrase seule est un nœud texte entier (donc traduisible), la cause
    // SERVIE est collée dans un second nœud, telle quelle.
    const boite = document.createElement('div');
    const aveu = document.createElement('div'); aveu.className = 'bad'; aveu.style.cssText = 'margin:0;font-size:12px';
    const dit = document.createElement('span');
    dit.textContent = 'Aperçu de ligne de base REFUSÉ : la porte de masquage n\'a pas pu être armée, et le démon en nomme la cause —';
    aveu.append(dit, ' « ' + causeServie + ' »');
    boite.appendChild(aveu);
    showResultModal('Aperçu baseline — ' + b.name, boite);
    return;
  }
  if (causeServie) { peindreLeRefusDUnEssai(puits, unRefusServiEnDeuxCents(d)); return; }   // `P10.29-q`
  if (!d) { peindreLeRefusDUnEssai(puits, unEssaiSansResultat()); return; }
  const hits = Array.isArray(d.hits) ? d.hits : [];
  const body = document.createElement('div');
  const h = document.createElement('p'); h.textContent = faceDansLaLangue({ fr: 'Bucket {bucket} — {n} entité(s) observée(s), {a} anomalie(s) (aucune écriture).', en: 'Bucket {bucket} — {n} entity(ies) observed, {a} anomaly(ies) (nothing written).' }, { bucket: d.bucket, n: d.observed, a: d.anomalies }); body.appendChild(h);
  const list = document.createElement('div');
  pagedList(list, { mode: 'client', pageSize: 15, rows: hits, sort: { key: 'z', dir: -1 }, columns: [
    { key: 'entity', label: 'Entité', render: r => { const c = document.createElement('code'); c.textContent = r.entity || ''; return c; } },
    { key: 'value', label: 'Valeur', align: 'r', sortable: true, sortVal: r => r.value || 0, render: r => String(r.value) },
    { key: 'z', label: 'Déviation z', align: 'r', sortable: true, sortVal: r => r.z || 0, render: r => { const s = document.createElement('b'); s.textContent = (r.z == null ? '' : r.z.toFixed(2)); s.style.color = 'var(--sev4)'; return s; } },
  ], emptyText: 'aucune anomalie au dernier bucket clos (les valeurs restent dans la baseline).' });
  body.appendChild(list);
  showResultModal('Aperçu baseline — ' + b.name, body);
}

// ---- petite modale de résultat (lecture seule) réutilisée par les deux "Test" ----
function showResultModal(title, bodyEl) {
  const ov = document.createElement('div'); ov.className = 'modal-ov';
  const box = document.createElement('div'); box.className = 'modal'; box.style.maxWidth = '640px';
  const h = document.createElement('h3'); h.textContent = title; box.appendChild(h);
  box.appendChild(bodyEl);
  const act = document.createElement('div'); act.className = 'modal-act';
  const ok = document.createElement('button'); ok.type = 'button'; ok.className = 'm-ok'; ok.textContent = 'Fermer';
  const close = () => { ov.classList.add('out'); setTimeout(() => ov.remove(), 160); };
  ok.onclick = close; act.appendChild(ok); box.appendChild(act);
  ov.onclick = e => { if (e.target === ov) close(); };
  ov.appendChild(box); document.body.appendChild(ov);
}

// ---- entrée : charge les deux listes + branche les boutons "Nouveau" ----
function loadDetAdv() {
  const nc = $('#detadv-corr-new'); if (nc) nc.onclick = () => editCorrelation(null);
  const nb = $('#detadv-base-new'); if (nb) nb.onclick = () => editBaseline(null);
  loadCorrelations();
  loadBaselines();
}

// `loadBaselines` est exposé pour le harnais ESM (témoin 93 : l'aveu de lecture de la liste, rendu par SON
// chargeur réel et non par une copie) ; aucun usage applicatif hors de ce module.
// `testBaseline` est exposée pour le harnais ESM (témoin 96 : le refus de la porte de masquage rendu par
// sa fabrique réelle, distinct d'un « introuvable ») ; son seul appelant applicatif est le bouton « Test »
// d'une ligne de la table des lignes de base.
export { loadDetAdv, loadBaselines, testBaseline, editCorrelation, deleteCorrelation, testCorrelation, editBaseline, deleteBaseline };
