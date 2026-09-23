// retention.js — rétention (durées éditables + aperçu destructif). Le panneau « Suppressions & whitelists »
// vit dans suppressions.js (extrait d'ici : même patron, un concern par module).
// Extrait d'app.js (decoupe par concern — meme patron que freshness.js).
// PURE MOVE : corps de fonctions IDENTIQUES au monolithe, seuls les import/export sont ajoutes.
// Le cycle app<->module est benin : les fonctions importees d'app.js ne sont appelees qu'a
// l'EXECUTION (handlers/async apres await), jamais a l'evaluation du module.
import { $, muted, api, apiSend, cleDeLaSuiteDuRegistre, fmtTs, confirmWithConsequence, toast, LANG, LOC, tzOpts } from './core.js';
import { S } from './state.js';
// `P10.20-y` — LE GENRE D'UNE LIGNE DE REGISTRE SE REND PAR LA FABRIQUE DE L'ONGLET AUDIT, pas par une
// seconde. Les deux seules vues qui lisent `GET /api/ledger` sont celle-ci et `web/audit.js` ; écrire ici
// une deuxième traduction des genres les laisserait diverger, et c'est celle-ci qui vieillirait, faute
// d'être la vue du registre. L'ARÊTE A ÉTÉ MESURÉE AVANT D'ÊTRE POSÉE (famille `P11.21-f`, l'écran mort
// d'une porte d'entrée qui jette) : le harnais ESM ouvre le graphe par CHACUN de ses modules dans un
// processus neuf, et le relevé est le MÊME avec et sans cet import — une seule porte jette, la même
// qu'avant. `audit.js` n'exécute rien à son premier niveau, il n'y a donc aucun câblage à rejouer.
import { celluleDeGenre } from './audit.js';

const fmtDate = ts => ts ? new Date(ts * 1000).toLocaleDateString(LOC, tzOpts()) : '—';

// ============ RÉTENTION ============
const RET_KEYS = ['retention_days', 'snapshot_days', 'alert_days', 'metric_days', 'metric_raw_hours'];
const RET_LABEL = {
  retention_days: 'Événements', snapshot_days: 'Snapshots', alert_days: 'Alertes closes',
  metric_days: 'Rollups métriques', metric_raw_hours: 'Métriques brutes',
};
const RET_HINT = {
  retention_days: 'logs bruts + rollups horaires',
  snapshot_days: 'instantanés (firewall, contrôles…)',
  alert_days: 'alertes non-ouvertes (les alertes actives sont conservées)',
  metric_days: 'agrégats de métriques',
  metric_raw_hours: 'points de métriques bruts (avant agrégation)',
};
// libellés FR de deleted_kind renvoyé par le preview (events/snapshots/alerts_closed/metric_rollups/metrics_raw)
const DELETED_KIND_LABEL = {
  events: 'événements', snapshots: 'snapshots', alerts_closed: 'alertes closes',
  metric_rollups: 'rollups métriques', metrics_raw: 'points métriques bruts',
};
const unitAbbr = u => u === 'hours' ? 'h' : 'j';
const unitWord = u => u === 'hours' ? 'heures' : 'jours';
/* state: RET_STATE -> S (state.js) */           // {values:{clé:n effectif}, bounds:{clé:{min,max,default,unit}}}
const _retTimers = {};          // debounce du preview par champ

async function loadRetention() {
  const wrap = $('#retention-fields'); if (!wrap) return;
  let d;
  try { d = await api('/retention'); } catch (e) { wrap.replaceChildren(muted('accès refusé ou erreur : ' + e.message)); return; }
  S.RET_STATE = { values: {}, bounds: d.bounds || {}, provenance: d.provenance || {}, reglage_illisible: d.reglage_illisible || {} };
  RET_KEYS.forEach(k => { S.RET_STATE.values[k] = Number(d[k]); });
  wrap.replaceChildren(...RET_KEYS.map(retentionField));
  // `P10.20-a` — LA PHRASE DU DÉMON EST ÉCRITE, PAS RECOPIÉE À LA MAIN. `retention_settings_get`
  // (daemon/src/handlers/admin_ui.rs) sert, en 200, la forme entière — chaque clé, ses bornes, sa
  // provenance — et, quand au moins une valeur ÉCRITE n'a pas pu être lue, `reglage_illisible` PAR CLÉ
  // plus la cause commune sous `error`. La ligne par champ, plus bas, dit bien QUELLE clé ; ce que seul
  // `error` dit, c'est ce que la valeur affichée VAUT ALORS — celle que la purge appliquera, pas la valeur
  // enregistrée. Cette phrase-là ne vivait ici que dans une infobulle recopiée, donc invisible et
  // vieillissante. Les champs RESTENT peints : ils décrivent ce que la purge fera, ce qui est vrai.
  if (d.error) {
    const aveu = document.createElement('div'); aveu.className = 'bad'; aveu.style.cssText = 'margin:0 0 8px;font-size:12px';
    const dit = document.createElement('span');
    dit.textContent = 'Réglage de rétention NON LU : le démon a refusé et en nomme la cause —';
    aveu.append(dit, ' « ' + String(d.error).trim() + ' »');
    wrap.prepend(aveu);
  }
  loadRetentionLast();
}
function retentionField(k) {
  const b = S.RET_STATE.bounds[k] || {};
  const unit = b.unit || (k === 'metric_raw_hours' ? 'hours' : 'days');
  const row = document.createElement('div');
  row.style.cssText = 'display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:8px 4px;border-bottom:1px solid var(--bd)';
  const lab = document.createElement('label'); lab.style.cssText = 'display:flex;flex-direction:column;gap:2px;min-width:210px';
  const strong = document.createElement('span'); strong.style.fontWeight = '600'; strong.textContent = RET_LABEL[k] || k;
  const sub = document.createElement('span'); sub.className = 'muted'; sub.style.cssText = 'font-size:11px;margin-top:0'; sub.textContent = RET_HINT[k] || '';
  // `P10.7-g` (lot 101) — D'OÙ VIENT LA VALEUR AFFICHÉE (le démon la sert par clé), et si la valeur ÉCRITE n'a pas pu
  // être lue : la valeur reste celle que la purge appliquera, mais elle n'est plus présentée comme la valeur enregistrée.
  const prov = document.createElement('span'); prov.className = 'muted'; prov.style.cssText = 'font-size:11px;margin-top:0';
  const origine = (S.RET_STATE.provenance || {})[k];
  if (origine === 'setting') prov.textContent = 'valeur enregistrée';
  else if (origine === 'environment') prov.textContent = "variable d'environnement";
  else if (origine === 'configuration') prov.textContent = 'fichier de configuration';
  else if (origine === 'default') prov.textContent = 'défaut du binaire';
  else prov.textContent = '';
  const illisible = (S.RET_STATE.reglage_illisible || {})[k];
  if (illisible) { prov.className = 'bad'; prov.textContent = 'réglage NON LU : ' + String(illisible); prov.title = "La valeur affichée est celle que la purge appliquera (environnement, configuration ou défaut), pas la valeur enregistrée, qui n'a pas pu être lue."; }
  lab.append(strong, sub, prov);
  const inp = document.createElement('input'); inp.type = 'number'; inp.dataset.key = k; inp.step = '1'; inp.className = 'field'; // P11.4-b : chrome partagé
  inp.value = String(S.RET_STATE.values[k]); inp.style.width = '110px';
  if (b.min != null) inp.min = String(b.min);
  if (b.max != null) inp.max = String(b.max);
  const u = document.createElement('span'); u.className = 'muted'; u.textContent = unitWord(unit);
  const note = document.createElement('span'); note.className = 'muted'; note.dataset.note = k; note.style.cssText = 'font-size:12px;flex:1 1 260px;margin-top:0';
  if (b.min != null && b.max != null) note.title = `plancher ${b.min} · plafond ${b.max} ${unitWord(unit)}`;
  inp.addEventListener('input', () => retPreview(k, inp, note));
  row.append(lab, inp, u, note);
  return row;
}
// aperçu par champ : hausse -> message local (0 purge) ; baisse -> GET /api/retention/preview (compte + ancienneté)
function retPreview(k, inp, note) {
  const cur = S.RET_STATE.values[k];
  const val = parseInt(inp.value, 10);
  const unit = (S.RET_STATE.bounds[k] || {}).unit;
  note.className = 'muted';
  if (!Number.isFinite(val)) { note.textContent = ''; return; }
  if (val === cur) { note.textContent = 'inchangé'; return; }
  if (val > cur) { note.className = 'ok'; note.textContent = `+${val - cur} ${unitAbbr(unit)} · aucune purge`; return; }
  note.textContent = 'calcul de l\'aperçu…';
  clearTimeout(_retTimers[k]);
  _retTimers[k] = setTimeout(async () => {
    let p;
    try { p = await api(`/retention/preview?key=${encodeURIComponent(k)}&value=${val}`); }
    catch (e) { note.className = 'muted'; note.textContent = 'aperçu indisponible'; return; }
    note.className = 'fwarn'; note.textContent = retPreviewText(p);
  }, 300);
}
function retPreviewText(p) {
  const kind = DELETED_KIND_LABEL[p.deleted_kind] || p.deleted_kind || 'entrées';
  const approx = p.approx ? '~' : '';
  const when = p.oldest ? ` (les plus anciens depuis ${fmtDate(p.oldest)})` : '';
  return `supprimera ${approx}${p.deleted} ${kind}${when}`;
}
// =================================================================================================
// `P10.20-y` — CE PANNEAU DISAIT « DERNIER CHANGEMENT AUDITÉ » D'UNE LIGNE QUI N'EN ÉTAIT PAS UN.
//
// CE QUE LE DÉMON ÉCRIT. Un changement de rétention laisse au registre un genre et un seul :
// `config.retention.<clé>` (`retention_settings_put`, daemon/src/handlers/admin_ui.rs, une ligne par
// clé changée). Rien d'autre du produit n'écrit ce préfixe.
//
// CE QUE CETTE VUE EN FAISAIT. Elle cherchait par un motif LARGE — `/retention|config|setting/i` —,
// qui attrape TOUT genre de configuration : `config.mode`, `config.user.create`, `config.overlay.*`,
// `config.sigma.import`, et jusqu'à `config.purge.events` — le DÉROULEMENT d'une purge, qui n'est pas un
// changement du réglage et que ce panneau annonçait pourtant comme tel ; et, ne trouvant rien, elle
// prenait la PREMIÈRE entrée servie, quelle qu'elle soit, pour l'annoncer sous le titre « Dernier
// changement audité » du panneau de rétention. Cinquante
// entrées se remplissent vite sur un registre vivant : le cas ordinaire n'est pas celui où la ligne
// trouvée est la bonne, c'est celui où il n'y en a aucune. L'exploitant lisait alors un acquittement
// d'alerte, ou un `action.exec.verdict-non-relu` — le seul genre que le démon ait créé pour dire qu'il
// NE SAIT PAS —, rendu en jeton nu et gras, comme si quelqu'un venait de changer la purge.
//
// CE QUE LA VUE EN FAIT MAINTENANT. Le discriminant est ANCRÉ sur l'ouverture du genre que le démon
// écrit. La ligne trouvée est annoncée pour ce qu'elle est ; SANS ligne trouvée, la phrase DIT qu'il
// n'y a aucun changement de rétention dans les entrées relues, en les comptant, et ce qui suit est
// présenté comme la dernière entrée du registre, tous genres confondus. Le genre lui-même passe par la
// fabrique de l'onglet Audit : un genre que la console sait nommer y rend sa phrase dans le registre de
// l'alarme, le jeton du démon gardé à côté ; tout autre genre reste le jeton, tel quel, comme avant.
// =================================================================================================
const OUVERTURE_DU_CHANGEMENT_DE_RETENTION = /^config\.retention\./;
// Les deux faces côte à côte : aucune langue ne peut partir sans l'autre. `{nombre}` est la borne de ce
// qui a été RELU — la vue ne demande que les cinquante dernières entrées, et une phrase qui tairait ce
// nombre affirmerait de TOUT le registre ce qui n'est vrai que de sa dernière page.
const MOTS_DU_DERNIER_CHANGEMENT_AUDITE = {
  changement_de_retention: {
    fr: 'Dernier changement de rétention audité : ',
    en: 'Last audited retention change: ' },
  aucun_changement_de_retention: {
    fr: "AUCUN changement de rétention parmi les {nombre} dernières entrées du registre ; ci-dessous la dernière entrée, tous genres confondus, qui ne règle PAS la purge : ",
    en: 'NO retention change among the last {nombre} ledger entries; below is the latest entry, all kinds included, which does NOT set the purge: ' },
};
const motDuDernierChangementAudite = (cle, nombre) =>
  (LANG === 'en' ? MOTS_DU_DERNIER_CHANGEMENT_AUDITE[cle].en : MOTS_DU_DERNIER_CHANGEMENT_AUDITE[cle].fr).replace('{nombre}', String(nombre));

// =================================================================================================
// `P10.21-a` — CE PANNEAU NOMMAIT SA BORNE PAR LE SEUL NOMBRE D'ENTRÉES RELUES.
//
// CE QUE LE DÉMON SERT, ET CE QUE ÇA VEUT DIRE EXACTEMENT. `ledger_page`
// (daemon/src/handlers/admin_ui.rs) pose `next_cursor` quand la page rend EXACTEMENT autant de lignes
// qu'elle en demandait, et `has_more` vaut alors `!next_cursor.is_null()` — « la page est PLEINE et un
// curseur de suite est servi », ce que le démon écrit lui-même « il reste PROBABLEMENT des lignes ».
// CE N'EST DONC PAS « d'autres entrées EXISTENT » : un registre de cinquante entrées exactement rend
// `has_more` vrai sans qu'aucune ligne ne soit derrière. La phrase ci-dessous dit ce que la clé dit, et
// pas un mot de plus — affirmer l'existence ferait chercher ce qui n'est peut-être pas là.
//
// CE QUE CETTE VUE EN FAISAIT. Elle ne lisait pas la clé du tout : « AUCUN changement de rétention
// parmi les {nombre} dernières entrées » se lisait comme une absence bornée à un nombre, sans dire si
// ce nombre était TOUT le registre ou seulement sa première page. Les deux se lisent pareil, et
// l'ordinaire du registre vivant est le second.
//
// LES TROIS ISSUES SONT DISTINCTES, ET LE SILENCE EN EST UNE, ÉCRITE. La clé absente n'est pas « c'est
// tout » : elle est avouée, parce qu'une console qui prend un silence pour une fin refait ici le défaut
// que `P10.20-a` a fermé une ligne plus haut sur la lecture ratée.
// CETTE BORNE NE SE DIT QUE SOUS L'ABSENCE. Quand un changement de rétention EST trouvé, la page est
// rendue par identifiant DÉCROISSANT : ce qui est derrière est plus ANCIEN, donc la ligne trouvée est
// bien la dernière, et la suite du registre ne change rien à ce qui est annoncé.
// =================================================================================================
// LE DISCRIMINANT DE CES TROIS ISSUES EST AU POINT COMMUN (`web/core.js`, `cleDeLaSuiteDuRegistre`) depuis
// `P10.21-x` : le fabricant de pager le lit pour armer sa flèche, et il ne pouvait pas l'importer d'ici.
const MOTS_DE_LA_SUITE_DU_REGISTRE = {
  il_en_existe_peut_etre_d_autres: {
    fr: " Ces {nombre} entrées REMPLISSENT la page demandée et le démon sert un curseur de suite : rien n'établit que le registre s'arrête là, et un changement de rétention plus ancien peut exister sans être atteignable depuis ce panneau — l'onglet Audit, lui, le parcourt en entier.",
    en: ' These {nombre} entries FILL the requested page and the daemon serves a continuation cursor: nothing establishes that the ledger stops there, and an older retention change may exist without being reachable from this panel — the Audit tab does walk it in full.' },
  // RIEN N'EST DIT quand le démon dit qu'il n'y a pas de suite : la page n'était pas pleine, donc ces
  // entrées sont TOUT ce que le registre porte, et la phrase d'absence au-dessus se suffit. Les deux
  // faces sont vides À DESSEIN — l'entrée existe pour que ce silence soit un choix écrit, pas un oubli.
  aucune_suite: { fr: '', en: '' },
  suite_non_dite: {
    fr: " Le démon n'a PAS dit s'il existe d'autres entrées au-delà de ces {nombre} : l'absence ci-dessus ne vaut donc que pour elles, et rien ici n'établit qu'il n'y en a pas d'autres.",
    en: ' The daemon did NOT say whether entries exist beyond these {nombre}: the absence above therefore holds for them only, and nothing here establishes that there are no others.' },
};
const motDeLaSuiteDuRegistre = (cle, nombre) =>
  (LANG === 'en' ? MOTS_DE_LA_SUITE_DU_REGISTRE[cle].en : MOTS_DE_LA_SUITE_DU_REGISTRE[cle].fr).replace('{nombre}', String(nombre));

// dernier changement audité (rend l'audit visible côté rétention) — lu dans le ledger, textContent (B7)
async function loadRetentionLast() {
  const el = $('#retention-last'); if (!el) return;
  let j;
  try { j = await api('/ledger?limit=50'); } catch (e) { el.textContent = ''; return; }
  // `P10.20-a` — « AUCUN CHANGEMENT AUDITÉ » EST UN VERDICT, ET IL SE RENDAIT SUR UNE LECTURE RATÉE.
  // `ledger_page` (daemon/src/handlers/admin_ui.rs) sert, en 200, la forme entière de la page avec
  // `entries: []`, `ok: false`, `lecture_non_faite: true` et la cause sous `error` ; `api()` ne jette que
  // sur `!r.ok`, donc `j.entries || []` en refaisait une absence et cette ligne écrivait « Aucun changement
  // audité pour l'instant » — sur le panneau qui RÈGLE la purge des données, c'est affirmer que personne
  // n'y a touché. La cause SERVIE est écrite à sa place, dans le ton de l'aveu.
  if (j && j.error) {
    el.replaceChildren();
    const dit = document.createElement('span'); dit.className = 'bad';
    dit.textContent = 'Journal d\'audit NON LU : le démon a refusé et en nomme la cause —';
    el.append(dit, ' « ' + String(j.error).trim() + ' »');
    return;
  }
  const entries = j.entries || [];
  if (!entries.length) { el.textContent = 'Aucun changement audité pour l\'instant.'; return; }
  // Le repli sur la PREMIÈRE entrée est conservé — il porte une information vraie, la dernière ligne
  // écrite au registre — mais il ne parle plus sous le titre de ce panneau : ce qu'il montre alors
  // n'est PAS un changement de rétention, et l'annoncer comme tel envoyait chercher une purge là où
  // quelqu'un venait d'acquitter une alerte.
  const ent = entries.find(x => OUVERTURE_DU_CHANGEMENT_DE_RETENTION.test(x.kind || ''));
  const dernier = ent || entries[0];
  el.replaceChildren();
  const pre = document.createElement('span'); pre.className = 'muted';
  pre.textContent = ent ? motDuDernierChangementAudite('changement_de_retention', entries.length)
    : motDuDernierChangementAudite('aucun_changement_de_retention', entries.length);
  const rest = document.createElement('span'); rest.className = 'muted';
  rest.textContent = (dernier.detail ? ' — ' + dernier.detail : '') + ' · ' + fmtTs(dernier.ts) + ' (voir onglet Audit)';
  el.append(pre, celluleDeGenre(dernier.kind || ''), rest);
  // `P10.21-a` — SOUS UNE ABSENCE, LA BORNE DE LA PAGE SE DIT. La phrase est posée au puits
  // (`textContent`), dans le registre de l'alarme quand c'est un aveu : un silence du démon sur la
  // suite ne doit pas se lire comme la fin du registre.
  if (!ent) {
    const cleDeLaSuite = cleDeLaSuiteDuRegistre(j);
    const motDeLaSuite = motDeLaSuiteDuRegistre(cleDeLaSuite, entries.length);
    if (motDeLaSuite) {
      const suite = document.createElement('span');
      suite.className = cleDeLaSuite === 'suite_non_dite' ? 'bad' : 'muted';
      suite.textContent = motDeLaSuite;
      el.append(suite);
    }
  }
}
if ($('#retention-refresh')) $('#retention-refresh').onclick = loadRetention;
if ($('#retention-form')) $('#retention-form').addEventListener('submit', async e => {
  e.preventDefault();
  if (!S.RET_STATE) return;
  const res = $('#retention-result');
  const body = {}, decreases = [];
  RET_KEYS.forEach(k => {
    const inp = $(`#retention-fields input[data-key="${k}"]`); if (!inp) return;
    const val = parseInt(inp.value, 10);
    if (!Number.isFinite(val) || val === S.RET_STATE.values[k]) return;
    body[k] = val;
    if (val < S.RET_STATE.values[k]) decreases.push(k);
  });
  if (!Object.keys(body).length) { toast('aucune modification', 'info'); return; }
  // P11.5-b : la rétention est une route SENSIBLE (le démon audite « destructive » quand elle baisse) ->
  // la confirmation partagée est posée À CHAQUE enregistrement et NOMME la conséquence dans les deux sens :
  // une BAISSE purge (aperçu compte + ancienneté, irréversible) ; une HAUSSE ne purge rien mais retient plus
  // longtemps (disque, taille de base). Avant : seule la baisse confirmait, et une hausse partait d'un clic.
  const previews = await Promise.all(decreases.map(k =>
    api(`/retention/preview?key=${encodeURIComponent(k)}&value=${body[k]}`).catch(() => null)));
  const fmtChange = k => { const ua = unitAbbr((S.RET_STATE.bounds[k] || {}).unit); return `${RET_LABEL[k]} ${S.RET_STATE.values[k]}${ua} → ${body[k]}${ua}`; };
  const baisses = decreases.map((k, i) => `${fmtChange(k)} (${previews[i] ? retPreviewText(previews[i]) : 'purge de données anciennes'})`);
  const hausses = Object.keys(body).filter(k => !decreases.includes(k)).map(fmtChange);
  const consequence = (baisses.length ? `PURGE IRRÉVERSIBLE au prochain cycle horaire — ${baisses.join(' ; ')}. ` : '')
    + (hausses.length ? `Conservation allongée, aucune purge — ${hausses.join(' ; ')} : plus d'espace disque et une base plus grande.` : '');
  if (!await confirmWithConsequence('Enregistrer la rétention', consequence.trim(), { danger: baisses.length > 0, okText: baisses.length ? 'Réduire (destructif)' : 'Enregistrer' })) return;
  res.textContent = '...';
  let j;
  try { j = await apiSend('/retention', 'PUT', body); }
  catch (e) { res.textContent = ''; toast((e && e.message) || 'échec', 'bad'); return; }
  j = j || {};
  res.textContent = '';
  toast(`rétention mise à jour (${j.changed != null ? j.changed : Object.keys(body).length} champ(s))`, 'ok');
  loadRetention();
});

// `P10.20-y` — `loadRetentionLast` et son vocabulaire partent pour le harnais ESM (témoin 102) : ce que
// ce panneau ANNONCE d'une ligne de registre ne se mesure qu'en le faisant RENDRE une page servie, et le
// discriminant du genre de rétention se juge dans les deux sens sur le littéral LU dans l'arbre du démon.
// `P10.21-a` — le vocabulaire de la SUITE part nu (témoin 103) : « la page est pleine », « la page ne
// l'est pas » et « le démon n'a rien dit » sont trois issues, et elles ne se distinguent qu'en jugeant
// la fonction qui les sépare sur les trois corps que la route peut servir. Cette fonction-là vit au point
// commun depuis `P10.21-x` et s'importe de `web/core.js`.
export { loadRetention, loadRetentionLast, motDeLaSuiteDuRegistre, motDuDernierChangementAudite, OUVERTURE_DU_CHANGEMENT_DE_RETENTION };
