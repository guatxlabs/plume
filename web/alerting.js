// alerting.js — #53 UI : politiques de notification (arbre de routage) + silences (mute temporisé).
// Admin/éditeur : create/delete ; viewer : lecture seule. Les secrets des canaux ne transitent JAMAIS ici
// (les politiques ne référencent les canaux QUE par id). Miroir de style des autres modules (connectors.js).
import { $, api, apiSend, confirmModal, fetchInto, fmtTs, ic, muted, sev, toast } from './core.js';

const MATCHER_FIELDS = ['severity', 'mitre', 'host', 'source', 'env', 'tag'];

// parse un mini-DSL "champ=valeur, champ=valeur" -> objet matchers (validé côté serveur aussi).
function parseMatchers(raw) {
  const out = {};
  raw.split(',').map(s => s.trim()).filter(Boolean).forEach(pair => {
    const i = pair.indexOf('=');
    if (i < 0) throw new Error('matcher invalide (attendu champ=valeur): ' + pair);
    const k = pair.slice(0, i).trim(), v = pair.slice(i + 1).trim();
    if (!MATCHER_FIELDS.includes(k)) throw new Error("champ non autorisé: '" + k + "' (autorisés: " + MATCHER_FIELDS.join(',') + ')');
    if (!v) throw new Error('valeur vide pour ' + k);
    out[k] = v;
  });
  return out;
}
function matchersText(obj) {
  const keys = Object.keys(obj || {});
  if (!keys.length) return '(défaut : tout)';
  return keys.sort().map(k => k + '=' + obj[k]).join(', ');
}

// `P10.7-f` (rang 4) — LES DEUX DRAPEAUX, posés par les charges et LUS par les deux formulaires, qui vivent
// hors d'elles : la marque accessible de l'inertie se VOIT sur le bouton d'envoi, seul le point de
// soumission EMPÊCHE l'écriture. LA PHRASE D'UN AVEU EST TOUJOURS ÉCRITE AU PUITS QUI LA REND (`dit.
// textContent = …`, `envoi.title = …`) et jamais passée en argument : le lexique ne regarde que le puits,
// et une phrase qui n'y est pas ne se traduit pas.
let POLITIQUES_NON_LUES = false, SILENCES_NON_LUS = false;
// Le bouton d'envoi d'un formulaire, pour y poser la marque d'inertie (grammaire de `P11.4-l`).
function envoiDuFormulaire(selecteur) {
  const form = $(selecteur);
  // `button` seul : les deux formulaires n'en portent qu'UN, celui de l'envoi (index.html). Un sélecteur
  // plus précis y écrirait un littéral que le lexique compte comme un libellé possible, sans en être un.
  return form && form.querySelector('button');
}
function rendreLEnvoiVif(selecteur) {
  const envoi = envoiDuFormulaire(selecteur);
  if (envoi) { envoi.removeAttribute('aria-disabled'); envoi.removeAttribute('title'); }
}

async function loadRouting() {
  await loadPolicies();
  await loadSilences();
}

// ---------- politiques de notification ----------
async function loadPolicies() {
  const wrap = $('#policies-body'); if (!wrap) return;
  wrap.replaceChildren(muted('chargement…'));
  const d = await fetchInto(wrap, '/notification-policies'); if (!d) return;
  // `P10.7-f` — UN ARBRE DE ROUTAGE NON LU N'EST PAS « AUCUNE POLITIQUE ». Le démon sert, en 200,
  // `{policies: [], error: <cause>}` (`corps_de_liste_illisible`, daemon/src/handlers/alerting.rs) ;
  // `fetchInto` ne capte qu'une EXCEPTION et ce corps-là le traverse, `Array.isArray([])` étant VRAI. La
  // phrase de vide rendue plus bas — « aucune politique — fan-out plat vers TOUS les canaux (mode par
  // défaut) » — est la plus fausse que ce panneau puisse écrire : elle GARANTIT à l'exploitant que chaque
  // alerte part vers TOUS ses canaux, au moment précis où l'on ignore ce que la table de routage contient.
  if (d.error) {
    POLITIQUES_NON_LUES = true;
    const aveu = document.createElement('div'); aveu.className = 'bad'; aveu.style.cssText = 'margin:0;font-size:12px';
    const dit = document.createElement('span');
    dit.textContent = 'Politiques de notification NON LUES : le démon a refusé et en nomme la cause —';
    aveu.append(dit, ' « ' + String(d.error).trim() + ' »');
    wrap.replaceChildren(aveu);
    const envoi = envoiDuFormulaire('#policy-form');
    if (envoi) { envoi.setAttribute('aria-disabled', 'true'); envoi.title = "L'arbre de routage n'a PAS été lu : ajouter une route ici, c'est peut-être doubler une route que cette lecture n'a pas pu rendre — et rien n'établit ici vers quels canaux les alertes partent."; }
    return;
  }
  POLITIQUES_NON_LUES = false;
  rendreLEnvoiVif('#policy-form');
  const rows = Array.isArray(d.policies) ? d.policies : [];
  wrap.replaceChildren();
  if (!rows.length) { wrap.appendChild(muted('aucune politique — fan-out plat vers TOUS les canaux (mode par défaut).')); return; }
  rows.forEach(p => {
    const row = document.createElement('div'); row.className = 'rulerow';
    const desc = document.createElement('div'); desc.className = 'rulemain';
    const m = document.createElement('code'); m.className = 'rulecond'; m.textContent = matchersText(p.matchers);
    const arrow = document.createElement('span'); arrow.textContent = ' → canaux [' + (p.contact_points || []).join(', ') + ']' + (p.continue ? ' + continue' : '') + (p.enabled ? '' : ' (désactivée)');
    desc.append(m, arrow);
    const del = document.createElement('button'); del.type = 'button'; del.className = 'btn btn-sm'; del.innerHTML = ic('x'); del.title = 'Supprimer la route'; // P11.4-b : classe partagée
    del.onclick = async () => { if (await confirmModal('Supprimer la politique #' + p.id + ' ?', { danger: true })) { try { await apiSend('/notification-policies/' + p.id, 'DELETE'); toast('route supprimée', 'ok'); loadPolicies(); } catch (e) { toast('échec : ' + e.message, 'bad'); } } };
    row.append(desc, del);
    wrap.appendChild(row);
  });
}

// ---------- silences ----------
async function loadSilences() {
  const wrap = $('#silences-body'); if (!wrap) return;
  wrap.replaceChildren(muted('chargement…'));
  const d = await fetchInto(wrap, '/silences'); if (!d) return;
  // `P10.7-f` — UNE LISTE DE SILENCES NON LUE N'EST PAS « AUCUN SILENCE ». Même corps, même fabrique
  // (`corps_de_liste_illisible`, daemon/src/handlers/alerting.rs). « aucun silence. » affirme qu'AUCUNE
  // alerte n'est muette — sur une console de sécurité, c'est la direction dangereuse de l'erreur.
  if (d.error) {
    SILENCES_NON_LUS = true;
    const aveu = document.createElement('div'); aveu.className = 'bad'; aveu.style.cssText = 'margin:0;font-size:12px';
    const dit = document.createElement('span');
    dit.textContent = 'Silences NON LUS : le démon a refusé et en nomme la cause —';
    aveu.append(dit, ' « ' + String(d.error).trim() + ' »');
    wrap.replaceChildren(aveu);
    const envoi = envoiDuFormulaire('#silence-form');
    if (envoi) { envoi.setAttribute('aria-disabled', 'true'); envoi.title = "Les silences n'ont PAS été lus : en créer un ici, c'est peut-être doubler un silence déjà posé que cette lecture n'a pas pu rendre — et rien n'établit ici quelles alertes sont déjà muettes."; }
    return;
  }
  SILENCES_NON_LUS = false;
  rendreLEnvoiVif('#silence-form');
  const rows = Array.isArray(d.silences) ? d.silences : [];
  wrap.replaceChildren();
  if (!rows.length) { wrap.appendChild(muted('aucun silence.')); return; }
  rows.forEach(s => {
    const row = document.createElement('div'); row.className = 'rulerow';
    const desc = document.createElement('div'); desc.className = 'rulemain';
    const m = document.createElement('code'); m.className = 'rulecond'; m.textContent = matchersText(s.matchers);
    const meta = document.createElement('span');
    meta.textContent = (s.active ? ' actif' : ' expiré') + ' · expire ' + fmtTs(s.expires_at) + (s.reason ? ' · ' + s.reason : '') + (s.created_by ? ' · par ' + s.created_by : '');
    meta.className = s.active ? '' : 'muted';
    desc.append(m, meta);
    const del = document.createElement('button'); del.type = 'button'; del.className = 'btn btn-sm'; del.innerHTML = ic('x'); del.title = 'Lever le silence'; // P11.4-b : classe partagée
    del.onclick = async () => { if (await confirmModal('Lever le silence #' + s.id + ' ?', { danger: true })) { try { await apiSend('/silences/' + s.id, 'DELETE'); toast('silence levé', 'ok'); loadSilences(); } catch (e) { toast('échec : ' + e.message, 'bad'); } } };
    row.append(desc, del);
    wrap.appendChild(row);
  });
}

function wireAlertingForms() {
  const pf = $('#policy-form');
  if (pf) pf.addEventListener('submit', async e => {
    e.preventDefault();
    // La MÊME phrase qu'au survol du bouton d'envoi, jamais deux formulations du même refus.
    if (POLITIQUES_NON_LUES) { toast("L'arbre de routage n'a PAS été lu : ajouter une route ici, c'est peut-être doubler une route que cette lecture n'a pas pu rendre — et rien n'établit ici vers quels canaux les alertes partent.", 'bad', 9000); return; }
    let matchers;
    try { matchers = parseMatchers($('#pol-matchers').value); } catch (err) { $('#pol-result').textContent = err.message; return; }
    const contacts = $('#pol-contacts').value.split(',').map(s => Number(s.trim())).filter(n => Number.isInteger(n) && n > 0);
    if (!contacts.length) { $('#pol-result').textContent = 'au moins un id de canal requis'; return; }
    const body = { matchers, contact_points: contacts, continue: $('#pol-continue').checked, enabled: true };
    try { await apiSend('/notification-policies', 'POST', body); $('#pol-result').textContent = ''; $('#pol-matchers').value = ''; $('#pol-contacts').value = ''; loadPolicies(); }
    catch (err) { $('#pol-result').textContent = err.message; }
  });
  const sf = $('#silence-form');
  if (sf) sf.addEventListener('submit', async e => {
    e.preventDefault();
    if (SILENCES_NON_LUS) { toast("Les silences n'ont PAS été lus : en créer un ici, c'est peut-être doubler un silence déjà posé que cette lecture n'a pas pu rendre — et rien n'établit ici quelles alertes sont déjà muettes.", 'bad', 9000); return; }
    let matchers;
    try { matchers = parseMatchers($('#sil-matchers').value); } catch (err) { $('#sil-result').textContent = err.message; return; }
    if (!Object.keys(matchers).length) { $('#sil-result').textContent = 'au moins un matcher requis'; return; }
    const body = { matchers, duration_s: Number($('#sil-duration').value) * 60, reason: $('#sil-reason').value.trim() };
    try { await apiSend('/silences', 'POST', body); $('#sil-result').textContent = ''; $('#sil-matchers').value = ''; $('#sil-reason').value = ''; loadSilences(); }
    catch (err) { $('#sil-result').textContent = err.message; }
  });
}
wireAlertingForms();

export { loadRouting, loadPolicies, loadSilences };
