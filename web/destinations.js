// destinations.js — #50 OUTPUTS / DESTINATIONS (admin-only) : forward des events normalisés vers un SINK
// EXTERNE (syslog / HEC-out / webhook ; S3 & Kafka = design/stub). Plume devient une couche COLLECTE +
// NORMALISATION devant un autre SIEM, ou un forwarder d'archive froide. Complète #40 (routage INTERNE par
// env_id) : ici la donnée SORT du périmètre (surface de data-exfil) -> admin-only, send-only, ledgerisé.
//
// API admin-only : GET /api/destinations (JAMAIS le secret d'auth -> has_auth:bool) ; POST /api/destinations
// (create) ; POST /api/destinations/{id} (update PARTIEL) ; DELETE /api/destinations/{id} ; POST
// /api/destinations/{id}/flush (forward+avance immédiat, fail-safe, ne renvoie NI la réponse du sink NI le
// secret). SÉCU UI : rendu textContent (anti-XSS) ; l'auth (jeton HEC / en-tête webhook) est un CREDENTIAL
// -> champ password, JAMAIS réaffiché, ré-envoyé UNIQUEMENT s'il est re-saisi (vide = conservé côté serveur).
// La VRAIE garde reste serveur (403 hors admin + route_min_role Admin) ; ceci est la défense en profondeur.
import { $, api, apiSend, confirmModal, confirmWithConsequence, effacerLeRefusDUnGeste, fetchInto, fmtTs, humanAge, ic, laTraceNonEcriteServieEnDeuxCents, muted, pagedList, peindreLeRefusDUnGeste, puitsDuRefusDUnGeste, toast, unRefusServiEnDeuxCents, withBusy, faceDansLaLangue } from './core.js';
import { enabledSwitch } from './producer_ui.js';
import { uiIsAdmin } from './multitenant.js';

const DEST_TYPES = { syslog: 'Syslog (RFC5424/TCP)', hec: 'HEC-out (Splunk)', webhook: 'Webhook (POST JSON)', s3: 'S3 (design/stub)', kafka: 'Kafka (design/stub)' };
const DEST_IMPLEMENTED = { syslog: 1, hec: 1, webhook: 1 };
let editing = null; // id de la destination en édition (null = création)

// `P10.27-d` / `P10.27-e` — LE PUITS DES GESTES SUR LES DESTINATIONS, juste avant la liste : création et modification
// par le formulaire, bascule, envoi manuel, retrait. Hors de ce que `loadDestinations` repeint, il survit au
// rechargement ; la forme est celle du point commun (`peindreLeRefusDUnGeste`, core.js). MESURÉ AVANT CE LOT (témoin
// 118) : un avis qui s'efface — « échec suppression : 503 {"error":"DESTINATION NON SUPPRIMÉE : … », « Bascule refusée :
// 503 {… », « échec : 503 {… », « flush : Failed to fetch » —, le JSON brut coupé à deux cents caractères, avant ce
// qui oblige à agir : la destination est toujours là et ENVOIE TOUJOURS les données hors du périmètre.
function puitsDesDestinations() { const liste = $('#destination-list'); return liste ? puitsDuRefusDUnGeste(liste.parentNode, 'destinations', liste) : null; }

export async function loadDestinations() {
  const wrap = $('#destination-list'); if (!wrap) return;
  // admin-only : court-circuit client (le serveur renvoie 403 de toute façon). Vraie garde = serveur.
  if (!uiIsAdmin()) { wrap.replaceChildren(muted("réservé à l'administrateur.")); return; }
  let list = await fetchInto(wrap, '/destinations'); if (!list) return;
  if (!Array.isArray(list)) list = [];
  if (!list.length) {
    wrap.replaceChildren(muted("aucune destination — clique « + Destination » pour forwarder les events vers un sink externe. Tant qu'aucune destination n'est activée, rien ne sort (comportement inchangé)."));
    return;
  }
  pagedList(wrap, { mode: 'client', pageSize: 50, rows: list, renderRow: destinationRow });
}

function badge(text, title, tone) {
  const b = document.createElement('span'); b.className = 'badge'; b.textContent = text; if (title) b.title = title;
  if (tone) b.style.cssText = 'color:var(--' + tone + ');border-color:color-mix(in srgb,var(--' + tone + ') 42%,transparent)';
  return b;
}

function destinationRow(d) {
  const row = document.createElement('div'); row.className = 'rulerow';
  // enable/disable (POST /api/destinations/{id} {enabled}) — COMMUTATEUR PARTAGÉ (`P11.13-c`) : une SORTIE DE
  // DONNÉES s'ouvre ici ; la case nue ne nommait pas ce qui part, ni vers où. `enabledSwitch` l'écrit à côté de
  // l'interrupteur dans les deux états, et remet la case en place si le serveur refuse.
  const en = enabledSwitch({
    enabled: !!d.enabled, name: d.name || '(sans nom)', allowed: true, confirmOnEnable: false,
    consequence: 'les events retenus par le filtre SORTENT de plume vers ' + (d.endpoint || DEST_TYPES[d.type] || d.type || '?') + ' ; OFF, plus rien ne sort et le retard ne se rattrape pas',
    // Le refus d'avant s'efface au geste ; la flèche reste une EXPRESSION (la garde des routes sensibles rattache cet
    // envoi à `destinationRow`). « DESTINATION INCHANGÉE » : une destination qu'on désactivait envoie toujours.
    onToggle: (next) => (effacerLeRefusDUnGeste(puitsDesDestinations()), apiSend('/destinations/' + d.id, 'POST', { enabled: next })),
    onRefus: (e) => peindreLeRefusDUnGeste(puitsDesDestinations(), e),
  });
  const name = document.createElement('span'); name.className = 'rulename'; name.textContent = d.name || '(sans nom)';
  const type = document.createElement('code'); type.className = 'rulecond'; type.textContent = DEST_TYPES[d.type] || d.type || '?';
  const ep = document.createElement('code'); ep.className = 'rulecond'; ep.textContent = d.endpoint || '(endpoint vide)'; ep.title = 'Endpoint du sink';
  // filtre (allowlisté) résumé.
  const f = d.filter || {};
  const parts = [];
  if (f.category) parts.push('cat=' + f.category);
  if (f.source) parts.push('src=' + f.source);
  if (f.env_id) parts.push('env=' + f.env_id);
  if (f.min_severity) parts.push('sev>=' + f.min_severity);
  const filt = document.createElement('code'); filt.className = 'rulecond'; filt.textContent = parts.length ? parts.join(' ') : 'tous les events'; filt.title = 'Filtre de sélection (allowlisté, jamais du SQL libre)';
  // auth : JAMAIS affichée — badge masqué / avertissement selon le type.
  const authNeeded = d.type === 'hec' || d.type === 'webhook';
  const sec = d.has_auth ? badge('••• auth', "credential du sink configuré (chiffré au repos, jamais réaffiché)", 'ok')
    : badge(authNeeded ? 'auth manquante' : 'sans auth', authNeeded ? "aucun credential — édite la destination pour saisir le jeton/en-tête" : "ce type n'exige pas d'auth", authNeeded ? 'warn' : null);
  // état de forward : watermark (curseur), volume du dernier lot, âge du dernier run/ok, erreurs.
  const meta = document.createElement('span'); meta.className = 'rulemeta muted';
  const wm = 'watermark #' + (d.watermark || 0);
  const last = d.last_ok ? ('ok ' + humanAge(d.last_ok)) : (d.last_run ? ('run ' + humanAge(d.last_run)) : 'jamais forwardé');
  meta.textContent = wm + ' · ' + last + ' · dernier lot ' + (d.last_count || 0);
  if (d.error_count) meta.textContent += ' · ' + d.error_count + ' err';
  // stub -> badge d'avertissement.
  const stub = !DEST_IMPLEMENTED[d.type];
  // dernière erreur (motif seul, jamais le corps du sink).
  const err = document.createElement('div'); err.className = 'muted'; err.style.cssText = 'font-size:11px;margin-top:2px';
  if (d.last_error) { err.textContent = '⚠ ' + d.last_error; err.style.color = 'var(--warn)'; }

  // actions : Flush (forward immédiat), Éditer, Supprimer.
  const flush = document.createElement('button'); flush.type = 'button'; flush.className = 'btn btn-sm'; flush.textContent = 'Flush'; // P11.4-b
  flush.title = "Déclenche UN forward+avance immédiat (admin-only, fail-safe). Ne renvoie ni la réponse du sink ni le secret.";
  flush.disabled = !d.enabled || stub;
  flush.onclick = () => withBusy(flush, () => flushDestination(d));
  const edit = document.createElement('button'); edit.type = 'button'; edit.className = 'btn btn-sm'; edit.textContent = 'Éditer'; edit.onclick = () => openDestinationForm(d);
  const del = document.createElement('button'); del.type = 'button'; del.className = 'picon'; del.innerHTML = ic('x'); del.title = 'Supprimer la destination'; del.onclick = () => deleteDestination(d);

  const top = document.createElement('div'); top.className = 'rulerow-top';
  top.append(en, name, type, ep, filt, sec);
  if (stub) top.append(badge('non implémenté', 'S3/Kafka = design/stub : aucun forward, watermark jamais avancé', 'warn'));
  top.append(meta);
  const actions = document.createElement('span'); actions.className = 'ruleactions'; actions.append(flush, edit, del);
  top.append(actions);
  row.append(top);
  if (d.last_error) row.append(err);
  return row;
}

// `P11.13-c` — CONSÉQUENCE DU FLUSH, DÉRIVÉE DE LA DESTINATION, ET DITE DANS LES DEUX SENS.
// Le flush n'est pas un dry-run : il rejoue le chemin de production `forward_one_destination`, donc les
// events SORTENT vraiment. La phrase est construite à partir du filtre, du lot max et de l'endpoint de CETTE
// destination — jamais un texte générique — et elle borne ce qu'un REFUS obtient : refuser n'envoie rien
// maintenant, mais n'arrête pas le forward périodique d'une destination active, qui enverra le même lot au
// prochain tick. Promettre l'inverse serait promettre une protection que ce bouton n'a pas.
function consequenceDuFlush(d) {
  const f = d.filter || {};
  const sel = [f.category && 'cat=' + f.category, f.source && 'src=' + f.source,
    f.env_id && 'env=' + f.env_id, f.min_severity && 'sev>=' + f.min_severity].filter(Boolean).join(' ');
  const cible = d.endpoint || DEST_TYPES[d.type] || d.type || '(endpoint vide)';
  return 'jusqu\'à ' + (d.batch_max || 500) + ' event(s) ' + (sel ? 'retenus par le filtre (' + sel + ')' : 'de TOUT le flux')
    + ' quittent plume MAINTENANT vers ' + cible + ', bruts et non masqués (feed machine). Ce qui est parti ne se '
    + 'rappelle pas ; en cas de succès le watermark avance et ce lot ne sera plus jamais renvoyé. Refuser '
    + 'n\'envoie rien maintenant et n\'arrête PAS le forward périodique de cette destination active.';
}

// `P10.28-t` — LES AVIS DE L'ENVOI MANUEL, DANS LES DEUX LANGUES. MESURÉ AVANT CE LOT (témoin 119t) : « forward OK : N
// event(s), watermark #M » restait français sous `LANG='en'`. `{cause}` est la phrase servie, telle quelle.
const MOTS_DES_AVIS_DE_L_ENVOI = {
  reussi: { fr: 'forward OK : {n} event(s), watermark #{w}', en: 'forward OK: {n} event(s), watermark #{w}' },
  echoue: { fr: 'forward échoué : {cause}', en: 'forward failed: {cause}' },
  cause_inconnue: { fr: 'erreur', en: 'error' },
};
// flush : POST /api/destinations/{id}/flush -> {ok,forwarded,watermark,last_error} (jamais la réponse du sink).
export async function flushDestination(d) {
  if (!await confirmWithConsequence('Forwarder maintenant « ' + (d.name || d.id) + ' » ?', consequenceDuFlush(d))) return;
  const puits = puitsDesDestinations(); effacerLeRefusDUnGeste(puits);
  let j;
  try { j = await apiSend('/destinations/' + d.id + '/flush', 'POST'); }
  catch (e) { peindreLeRefusDUnGeste(puits, e); return; }
  j = j || {};
  // `P10.28-o` — L'ENVOI A EU LIEU, SA TRACE D'AUDIT MANQUE PEUT-ÊTRE. `destination_flush` le dit sous `trace_non_ecrite`
  // (ce qui est parti est parti, le registre ne dit ni qui ni combien) ; mesuré avant ce lot, ce champ n'était pas lu.
  const traceAbsente = laTraceNonEcriteServieEnDeuxCents(j); if (traceAbsente) peindreLeRefusDUnGeste(puits, traceAbsente);
  // `P10.28-t` — l'avis de l'envoi, dans les deux langues (composé : un nombre s'y colle, le lexique ne l'atteignait pas).
  if (j.ok) toast(faceDansLaLangue(MOTS_DES_AVIS_DE_L_ENVOI.reussi, { n: j.forwarded || 0, w: j.watermark || 0 }), 'ok');
  else toast(faceDansLaLangue(MOTS_DES_AVIS_DE_L_ENVOI.echoue, { cause: j.last_error || faceDansLaLangue(MOTS_DES_AVIS_DE_L_ENVOI.cause_inconnue) }), 'bad');
  loadDestinations();
}

export async function deleteDestination(d) {
  const ok = await confirmModal("Supprimer la destination « " + (d.name || d.id) + " » ? La sortie de données vers ce sink cessera. (Action journalisée / ledgerisée.)");
  if (!ok) return;
  const puits = puitsDesDestinations(); effacerLeRefusDUnGeste(puits);
  try { await apiSend('/destinations/' + d.id, 'DELETE'); }
  catch (e) { peindreLeRefusDUnGeste(puits, e); return; }
  toast('destination supprimée', 'ok'); loadDestinations();
}

// ---- FORMULAIRE (construit en JS : type -> champs d'auth conditionnels + filtre allowlisté) ----------
function field(label, node) {
  const l = document.createElement('label'); l.append(document.createTextNode(label + ' '), node); return l;
}
function input(id, ph, val, type) {
  const i = document.createElement('input'); i.id = id; if (ph) i.placeholder = ph; if (val != null) i.value = val;
  if (type) i.type = type; i.autocomplete = 'off'; i.spellcheck = false; return i;
}

export function openDestinationForm(d) {
  editing = d ? d.id : null;
  const host = $('#destination-form-host'); if (!host) return;
  const form = document.createElement('form'); form.className = 'ruleform'; form.id = 'destination-form';
  if (d) form.dataset.editing = String(d.id); // le dépli partagé (app.js) distingue « création ouverte » d'« édition ouverte »

  const name = input('df-name', 'Nom (ex: Splunk cold-archive)', d ? d.name : '');
  const type = document.createElement('select'); type.id = 'df-type';
  for (const [k, v] of Object.entries(DEST_TYPES)) { const o = document.createElement('option'); o.value = k; o.textContent = v; if (d && d.type === k) o.selected = true; type.append(o); }
  const endpoint = input('df-endpoint', 'webhook/hec: https://… · syslog: tcp://host:514', d ? d.endpoint : '');
  const interval = input('df-interval', '30', d ? d.interval_s : 30, 'number'); interval.min = 5; interval.title = 'Fréquence de forward (s) — plancher 5 s';
  const batch = input('df-batch', '500', d ? d.batch_max : 500, 'number'); batch.min = 1; batch.max = 5000; batch.title = 'Taille max d\'un lot forwardé par tick (borne le débit)';
  const enabled = document.createElement('input'); enabled.id = 'df-enabled'; enabled.type = 'checkbox'; enabled.checked = d ? !!d.enabled : false;

  const row1 = document.createElement('div'); row1.className = 'rf-row';
  row1.append(field('Type', type), field('Intervalle(s)', interval), field('Lot max', batch), field('actif', enabled));

  // AUTH conditionnelle (secret). Placeholder « ••• » si déjà configuré (édition) -> vide = conservé.
  const authPh = d && d.has_auth ? '•••• (laisser vide pour conserver)' : '';
  const hecTok = input('df-hectoken', 'jeton HEC (Authorization: Splunk <token>)', '', 'password'); hecTok.placeholder = authPh || hecTok.placeholder;
  const whHdr = input('df-authheader', 'en-tête d\'auth (ex: Authorization: Bearer xxx)', '', 'password'); whHdr.placeholder = authPh || whHdr.placeholder;
  const authRow = document.createElement('div'); authRow.className = 'rf-row';
  const hecWrap = field('Jeton HEC', hecTok); const whWrap = field('En-tête d\'auth', whHdr);
  authRow.append(hecWrap, whWrap);

  // FILTRE allowlisté (jamais du SQL libre) : catégorie CIM / source / environnement / sévérité min.
  const f = (d && d.filter) || {};
  const fCat = input('df-fcat', 'catégorie CIM (ex: auth, network) — vide = toutes', f.category || '');
  const fSrc = input('df-fsrc', 'source (ex: sshd) — vide = toutes', f.source || '');
  const fEnv = input('df-fenv', 'environnement/index (#49) — vide = tous', f.env_id || '');
  const fSev = document.createElement('select'); fSev.id = 'df-fsev';
  for (const [v, t] of [['0', 'toutes'], ['1', '>=1'], ['2', '>=2'], ['3', '>=3'], ['4', '=4 (max)']]) { const o = document.createElement('option'); o.value = v; o.textContent = t; if (String(f.min_severity || 0) === v) o.selected = true; fSev.append(o); }
  const fRow = document.createElement('div'); fRow.className = 'rf-row';
  fRow.append(field('Filtre catégorie', fCat), field('Filtre source', fSrc), field('Filtre env', fEnv), field('Sévérité min', fSev));
  const fHelp = muted('Filtre de SÉLECTION allowlisté (bound params, jamais du SQL libre). Vide sur toute la ligne = feed COMPLET. La destination reçoit des events BRUTS non masqués (feed machine).');
  fHelp.style.cssText = 'font-size:11px;margin:2px 0';

  // affiche/masque les champs d'auth selon le type.
  const applyType = () => {
    const t = type.value;
    hecWrap.hidden = t !== 'hec';
    whWrap.hidden = t !== 'webhook';
    authRow.hidden = t !== 'hec' && t !== 'webhook';
  };
  type.onchange = applyType; applyType();

  // P11.4-b : barre d'actions `.rf-actions` (contexte partagé : submit = primaire accent, le reste = secondaire).
  const save = document.createElement('button'); save.type = 'submit'; save.className = 'btn-primary'; save.textContent = d ? 'Enregistrer' : 'Créer la destination';
  const cancel = document.createElement('button'); cancel.type = 'button'; cancel.className = 'btn'; cancel.textContent = 'Annuler'; cancel.onclick = () => { host.replaceChildren(); };
  const actions = document.createElement('div'); actions.className = 'rf-actions'; actions.append(save, cancel);

  form.append(field('Nom', name), field('Endpoint', endpoint), row1, authRow, fRow, fHelp, actions);
  form.onsubmit = (e) => { e.preventDefault(); withBusy(save, () => saveDestination(d)); };
  host.replaceChildren(form);
  name.focus();
}

export async function saveDestination(d) {
  const type = $('#df-type').value;
  const filter = {};
  const cat = $('#df-fcat').value.trim(); if (cat) filter.category = cat;
  const src = $('#df-fsrc').value.trim(); if (src) filter.source = src;
  const env = $('#df-fenv').value.trim(); if (env) filter.env_id = env;
  const sev = parseInt($('#df-fsev').value, 10); if (sev) filter.min_severity = sev;
  const body = {
    name: $('#df-name').value.trim() || 'Destination',
    type,
    endpoint: $('#df-endpoint').value.trim(),
    interval_s: parseInt($('#df-interval').value, 10) || 30,
    batch_max: parseInt($('#df-batch').value, 10) || 500,
    enabled: $('#df-enabled').checked,
    filter,
  };
  // AUTH (secret) : envoyée UNIQUEMENT si re-saisie -> vide = conservée côté serveur (jamais écrasée par vide).
  const config = {};
  if (type === 'hec') { const t = $('#df-hectoken').value; if (t) config.hec_token = t; }
  if (type === 'webhook') { const h = $('#df-authheader').value; if (h) config.auth_header = h; }
  if (Object.keys(config).length) body.config = config;

  const url = editing ? '/destinations/' + editing : '/destinations';
  // Le formulaire refusé reste ouvert, sa saisie gardée ; le refus s'écrit dans le puits des destinations.
  const puits = puitsDesDestinations(); effacerLeRefusDUnGeste(puits);
  let j;
  try { j = await apiSend(url, 'POST', body); }
  catch (e) { peindreLeRefusDUnGeste(puits, e); return; }
  j = j || {};
  if (j.error) { peindreLeRefusDUnGeste(puits, unRefusServiEnDeuxCents(j)); return; }
  toast(editing ? 'destination enregistrée' : 'destination créée (désactivée — teste avec Flush puis active)', 'ok');
  editing = null;
  const host = $('#destination-form-host'); if (host) host.replaceChildren();
  loadDestinations();
}
