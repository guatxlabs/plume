// Accès données (DLP, gouvernance d'accès en lecture seule) : cinq panneaux sur des requêtes GXQL existantes,
// sélecteur de fenêtre d'analyse, note de périmètre, réordonnancement des cartes persisté localement. Extrait
// d'`app.js` par déplacement pur ; le seul consommateur est la navigation (`showView`). N'importe pas `app.js`.
import { $, fmtTs, ic, muted, LANG } from './core.js';
import { S } from './state.js';
import { runQ, tableEl, truncationBadge } from './viz.js';
// `P11.18-c` — LE CHOIX DE DATES EST PARTAGÉ, ET IL VIT DANS `audit.js`. Il n'est pas écrit deux fois,
// et il n'est pas non plus au point commun (`web/core.js`), qui serait sa place : ce lot ne pouvait
// toucher que ces deux vues, alors la vue dont la ROUTE est la plus pauvre le porte et celle-ci
// l'importe. La raison du sens est écrite en tête du bloc `P11.18-c` de `web/audit.js`, avec la forme
// recommandée si le point commun s'ouvre.
import { plageActive, poserLaPlage, poserLeChoixDeDates } from './audit.js';

// --- DLP / gouvernance d'accès (style Varonis) — onglet LECTURE SEULE (Phase 1) -------------------
// "Qui touche quoi", intégrité (FIM) et droits (ACL/RBAC). Chaque panneau s'appuie sur une requête
// EXISTANTE (runQ -> /api/query, scan toute la fenêtre), AUCUN nouvel endpoint, AUCUNE mutation hôte.
// Ce n'est PAS du DLP de contenu : c'est de la gouvernance d'accès en lecture seule.
const DATA_PANELS = [
  { id: 'whoami', title: 'Qui touche quoi (accès données)', queries: [{ soql: 'search source=dataaccess | stats count by path,user | sort -count | head 30' }] },
  { id: 'tamper', title: 'Fichiers sensibles / tamper', queries: [{ soql: 'search source=auditd severity>=4 | sort -ts | head 30' }] },
  { id: 'fim', title: 'Intégrité (FIM)', queries: [{ soql: 'search source=integrity | sort -ts | head 30' }] },
  { id: 'acl',  title: 'ACL fichiers (dataacl)',      queries: [{ soql: 'search source=dataacl | sort -ts | head 20' }] },
  { id: 'rbac', title: 'RBAC Kubernetes (kube-rbac)', queries: [{ soql: 'search source=kube-rbac | sort -ts | head 20' }] },
];
// chemins surveillés côté hôte (clés de watch auditd) — affichage informatif, édition = Phase 2
const DATA_WATCHED = ['/etc', '/etc/rancher/k3s', '/opt/local-path-provisioner', '/etc/shadow', '/etc/sudoers', 'binaires SUID', 'unités systemd'];
// D12 — fenêtre d'analyse des panneaux DLP. Défaut 'all' (from=0 = toute la rétention, cappé top-N par head).
// Le sélecteur câble fromOverride (3e arg de runQ). Libellés VISIBLES au-dessus des panneaux.
// Le libellé de 'all' ne CHIFFRE plus la rétention : le panneau ne l'a jamais lue (elle est réglable par
// déploiement, servie par le démon), et « ~30 j » était donc un nombre sans source affiché à l'analyste.
/* state: daWin -> S (state.js) */
const DA_WINLBL = { all: 'toute la rétention', '7d': '7 derniers jours', '24h': 'dernières 24 h' };
// `P11.18-c` — LA PLAGE DE DATES PRIME SUR LE PALIER. Les deux répondent à la même question ; choisir
// l'un retire l'autre. Seule la borne BASSE part d'ici : `runQ` la porte par son 3e argument (`from`).
function daFromValue() {
  const plage = plageActive();
  if (plage) return plage.debut;
  return S.daWin === 'all' ? 0 : Math.floor(Date.now() / 1000) - (S.daWin === '7d' ? 604800 : 86400);
}

// =================================================================================================
// `P11.18-c` — LA BORNE HAUTE DE CE PANNEAU : CE QU'IL ENVOIE, ET CE QU'IL HÉRITE SANS L'AVOIR CHOISI.
//
// MESURÉ le 2026-08-25, en lisant le fabricant partagé. `runQ` (`web/viz.js`) pose
// `body.to = exploreTo()`, c'est-à-dire `S.zoomRange ? S.zoomRange.to : 0` — l'intervalle ABSOLU réglé
// dans l'Explore ou les Dashboards (`openRangeModal`, `setZoom`). Ce panneau ne le règle pas, ne
// l'affichait pas, et sa barre annonçait « Fenêtre : toute la rétention » pendant que ses cinq
// requêtes partaient bornées EN HAUT par une valeur venue d'une autre vue. C'est une fenêtre héritée
// en douce, et la contradiction est de la même famille que celle relevée sous `P11.14-c`.
//
// CE QUE CE LOT PEUT ET NE PEUT PAS. La route accepte `to` (`POST /api/query` ; `guatx_core::soql`
// émet `ts <= to`) — c'est le fabricant CLIENT qui n'offre aucun moyen de le poser, et `web/viz.js`
// est hors de ce lot. Deux gestes en découlent, tous deux dans le périmètre :
//   * une plage dont la FIN est antérieure à maintenant est REFUSÉE, en nommant cette raison-là ;
//   * la borne haute HÉRITÉE, quand il y en a une, est NOMMÉE au-dessus des cartes. Une borne qu'on ne
//     peut pas retirer se dit ; c'est la taire qui fabrique la contradiction.
// =================================================================================================
function borneHauteHeritee() { return S.zoomRange ? S.zoomRange.to : 0; }

// =================================================================================================
// `P11.14-c` — TROIS ISSUES DISTINCTES, LÀ OÙ CE PANNEAU N'EN RENDAIT QU'UNE.
//
// LE DÉFAUT, ET CE QU'IL FABRIQUAIT. Une seule condition — `!j || j.error || !Array.isArray(j.rows)
// || !j.rows.length` — envoyait QUATRE situations sur la MÊME phrase : « Aucun changement récent
// (<fenêtre>) — ou capteur inactif ». Un REFUS du serveur, une réponse illisible, une panne réseau et
// un VRAI vide devenaient indiscernables, et la phrase choisie AFFIRMAIT une absence (et suggérait
// une panne de collecte) dans les trois cas où rien n'avait été établi.
//
// C'EST CE QUI FABRIQUAIT LA CONTRADICTION relevée le 2026-08-25 : « toute la rétention » rendait
// « aucun changement récent » tandis que « 7 jours » rendait des lignes — un sur-ensemble affichant
// moins que son sous-ensemble. MESURÉ le 2026-08-25, aucun chemin de REQUÊTE ne rend moins quand la
// fenêtre s'élargit :
//   * COMPILATION — pour les cinq requêtes de ce panneau, le SQL émis avec `from=0` est EXACTEMENT
//     celui émis avec `from=maintenant-7j` MOINS le seul conjoint `ts >= <borne>` (émission par
//     `guatx_core::soql`, celle que traverse `/api/query`). Une relaxation, pas une autre requête.
//   * EXÉCUTION — les deux SQL joués sur une base de 6 000 lignes réparties sur 30 jours rendent
//     30 lignes contre 30 sur les panneaux de liste, et 60 contre 15 sur le panneau agrégé. Le
//     sur-ensemble rend toujours au moins autant.
// Ce que la fenêtre large rend de DIFFÉRENT, c'est un REFUS — nommé, et actionnable :
//   * 422 « refus de rendre un nombre FAUX … » quand la valeur porterait sur un historique froid
//     tronqué (`daemon/src/cold_store/exactness.rs`) — le cas que ces cinq requêtes déclenchent,
//     puisqu'elles portent toutes un `| sort`, donc un classement sur l'ENSEMBLE ;
//   * 400 « requête interrompue (budget N s dépassé) » (`daemon/src/query_exec.rs`).
// Le démon dit donc la vérité dans les deux fenêtres ; la contradiction naissait ICI, à l'affichage.
//
// LA RÈGLE : un composant qui ne sait pas conclure REFUSE en le disant. Il ne rend pas un vide, parce
// qu'un vide se lit comme un fait — et un fait faux coûte plus cher qu'un refus.
// Fonction PURE (une réponse -> un élément) : c'est ce qui la rend tenable par le harnais ESM, dans
// les deux sens (un refus ne doit jamais rendre une absence ; un vrai vide doit rester une absence).
// =================================================================================================
// `win` : une CLÉ de palier (`all`/`7d`/`24h`) ou, depuis `P11.18-c`, le libellé d'une plage de dates
// (« AAAA-MM-JJ → AAAA-MM-JJ »). Le repli `String(win)` porte donc les deux sans changer de signature ;
// et une plage n'est PAS `all`, ce qui suffit à ce qu'un vide y invite à élargir plutôt qu'à accuser un
// capteur — la conclusion « rien sur toute la rétention » ne vaut que sur toute la rétention.
function daRenduDeReponse(j, win, soql) {
  const lbl = DA_WINLBL[win] || String(win);
  // (1) RIEN N'A ÉTÉ ÉTABLI — refus du serveur, réponse illisible, ou promesse rejetée (réseau).
  // Le REFUS et le VIDE sont décidés par DEUX tests séparés : un `error` posé par le démon (quelle
  // qu'en soit la forme), ou une réponse qui ne porte pas de tableau de lignes. Les fondre en une
  // seule condition serait perdre la distinction ici même — c'est ce que la garde de CI
  // `check_a_refusal_is_not_rendered_as_an_absence.py` rend désormais non-écrivable dans web/.
  const brut = (j && j.error != null) ? String(j.error) : '';
  const refus = !j || brut !== '' || !Array.isArray(j.rows);
  if (refus) {
    // La cause est rendue TELLE QUELLE : celle du démon nomme le plafond franchi ET les voies exactes.
    const cause = brut.trim();
    const box = document.createElement('div');
    box.className = 'bad';
    box.textContent = 'Résultat INCONNU (' + lbl + ") — le serveur n'a pas rendu de réponse à cette question, ce n'est donc PAS une absence de données : "
      + (cause ? cause : 'réponse illisible du serveur');
    box.title = cause ? cause : lbl;
    return box;
  }
  // (2) ABSENCE ÉTABLIE — le serveur a répondu, et la fenêtre est vide. On ne conclut à un capteur
  // muet que là où l'observation le porte : sur TOUTE la rétention. Sur une fenêtre plus étroite,
  // l'absence est celle de la fenêtre, et l'invitation est de l'élargir — pas d'accuser la collecte.
  if (!j.rows.length) {
    return muted('Aucun événement (' + lbl + ')' + (win === 'all'
      ? " — rien sur toute la rétention : vérifier que le capteur de cette source l'alimente."
      : ' — élargir la fenêtre avant de conclure à un capteur inactif.'));
  }
  // (3) DES LIGNES — conteneur scrollable (comme l'Explore) : les tables larges (dataacl : ~17
  // colonnes, chemins /opt/local-path-provisioner/pvc-… longs) défilent DANS la card au lieu de
  // déborder la mise en page. Un ensemble INCOMPLET (plafond serveur) porte le badge partagé de
  // troncature — les lignes affichées sont vraies, il en manque, et le badge le dit.
  const wrap = document.createElement('div');
  wrap.className = 'qresult daresult';
  if (j.stats && j.stats.truncated) {
    const [cls, text, title] = truncationBadge(j.stats, null);
    const b = document.createElement('span');
    b.className = 'qb ' + cls; b.textContent = text; b.title = title;
    wrap.appendChild(b);
  }
  wrap.appendChild(tableEl(j.columns, j.rows, soql));
  return wrap;
}
async function renderDataAccess() {
  const host = $('#da-body'); if (!host) return;
  host.replaceChildren();
  const intro = document.createElement('p'); intro.className = 'muted'; intro.style.margin = '0 0 12px';
  intro.textContent = "Gouvernance d'accès (style Varonis) : qui touche quoi, intégrité et droits. Lecture seule — pas de DLP de contenu, aucune action depuis cet onglet.";
  // BATCH 2 (B6) : le ? d'aide est désormais dans l'en-tête visible (index.html, .panelhead > h2 > .ihelp.vhelp)
  // au lieu d'être collé dans ce paragraphe d'intro. Handler .vhelp toujours délégué.
  host.appendChild(intro);
  // D12 — indicateur de fenêtre VISIBLE + sélecteur (24 h / 7 j / tout) câblant fromOverride.
  const bar = document.createElement('div'); bar.className = 'da-winbar';
  const plage = plageActive();
  const wlbl = document.createElement('span'); wlbl.className = 'muted';
  // Une plage active REMPLACE le libellé du palier : afficher les deux laisserait croire à deux
  // fenêtres superposées. Sans plage, la phrase est EXACTEMENT celle d'avant.
  wlbl.textContent = plage
    ? ((LANG === 'en' ? 'Window: from ' : 'Fenêtre : du ') + plage.texteDebut + (LANG === 'en' ? ' to ' : ' au ') + plage.texteFin + (LANG === 'en' ? ' · top N per panel' : ' · top N par panneau'))
    : ('Fenêtre : ' + DA_WINLBL[S.daWin] + ' · top N par panneau');
  const wsel = document.createElement('select'); wsel.className = 'k-theme'; wsel.setAttribute('aria-label', "Fenêtre d'analyse (DLP)");
  wsel.title = "Fenêtre d'analyse : borne le `from` des requêtes (le nombre de lignes reste cappé par panneau)";
  [['24h', '24 h'], ['7d', '7 j'], ['all', 'Tout']].forEach(([v, t]) => { const o = document.createElement('option'); o.value = v; o.textContent = t; if (v === S.daWin) o.selected = true; wsel.appendChild(o); });
  // Choisir un PALIER retire la plage — même règle que sur le journal d'audit, par le même écrivain.
  wsel.onchange = () => { S.daWin = wsel.value; poserLaPlage(null); renderDataAccess(); };
  bar.append(wlbl, wsel);
  // Le choix de dates PARTAGÉ. Sa raison de refus est propre à CE chemin : la route accepte `to`, c'est
  // `runQ` qui ne laisse pas le poser. Écrite ici parce que c'est ici qu'elle est vraie.
  bar.appendChild(poserLeChoixDeDates('dataaccess', () => renderDataAccess(), choisie => (LANG === 'en'
    ? 'Range refused: the upper bound does not leave from here. The shared query builder (runQ, web/viz.js) takes `to` from the Explore interval (S.zoomRange) and offers no way to set it, so the end you chose (' + choisie.texteFin + ') cannot be sent — the route POST /api/query does accept `to`. What this panel can send: from ' + choisie.texteDebut + ' up to now.'
    : "Plage refusée : la borne HAUTE ne part pas d'ici. Le fabricant de requête partagé (runQ, web/viz.js) prend `to` de l'intervalle de l'Explore (S.zoomRange) et n'offre aucun moyen de le poser, donc la fin choisie (" + choisie.texteFin + ") ne peut pas être envoyée — la route POST /api/query, elle, accepte bien `to`. Ce que ce panneau sait envoyer : du " + choisie.texteDebut + " jusqu'à maintenant.")).barre);
  // LA BORNE HAUTE HÉRITÉE, DITE. Elle vient d'une AUTRE vue et ce panneau ne peut pas la retirer ; la
  // taire, c'est annoncer une fenêtre que les requêtes n'ont pas. Rien n'est affiché quand il n'y en a
  // pas : une phrase permanente se lirait comme une borne permanente.
  const heritee = borneHauteHeritee();
  if (heritee > 0) {
    const h = document.createElement('span'); h.className = 'muted';
    h.textContent = (LANG === 'en' ? '· upper bound INHERITED from the Explore/Dashboards interval: nothing after ' : "· borne haute HÉRITÉE de l'intervalle Explore/Dashboards : rien après ")
      + fmtTs(heritee)
      + (LANG === 'en' ? ' is queried, and this panel cannot lift it.' : " n'est interrogé, et ce panneau ne peut pas la lever.");
    h.title = String(heritee);
    bar.appendChild(h);
  }
  host.appendChild(bar);
  const daFrom = daFromValue();
  // Figé pour ce rendu : le sélecteur comme les dates peuvent changer pendant les requêtes en vol. Une
  // plage se nomme par ses deux jours ; un palier par sa clé (voir `daRenduDeReponse`).
  const daWin = plage ? (plage.texteDebut + ' → ' + plage.texteFin) : S.daWin;
  for (const p of DATA_PANELS) {
    const card = document.createElement('section'); card.className = 'card'; card.dataset.da = p.id;
    const h = document.createElement('h2'); h.textContent = p.title; card.appendChild(h);
    const slots = p.queries.map(q => {
      if (q.label) { const lab = document.createElement('div'); lab.className = 'fldname'; lab.textContent = q.label; card.appendChild(lab); }
      const slot = document.createElement('div'); slot.className = 'body'; slot.textContent = '...'; card.appendChild(slot); return slot;
    });
    host.appendChild(card);
    // requêtes EN PARALLÈLE (placeholder déjà rendu) ; from=daFrom (0 = toute la rétention ; head N borne le coût)
    p.queries.forEach((q, i) => {
      const slot = slots[i];
      // `P11.14-c` — les DEUX issues passent par la MÊME fonction : une promesse rejetée (réseau,
      // réponse tronquée par un proxy) est une cause NOMMÉE, pas un vide. Une seule porte de rendu,
      // donc aucune branche ne peut ré-inventer une absence dans son coin.
      runQ(q.soql, true, daFrom)
        .then(j => slot.replaceChildren(daRenduDeReponse(j, daWin, q.soql)))
        .catch(e => slot.replaceChildren(daRenduDeReponse({ error: (e && e.message) || '' }, daWin, q.soql)));
    });
  }
  // note de gouvernance : périmètre surveillé (auditd) + cap sur la Phase 2
  const note = document.createElement('section'); note.className = 'card da-note';
  const nh = document.createElement('h2'); nh.textContent = 'Périmètre surveillé (hôte)'; note.appendChild(nh);
  const chips = document.createElement('div'); chips.style.cssText = 'display:flex;flex-wrap:wrap;gap:6px;margin-bottom:4px';
  DATA_WATCHED.forEach(w => { const c = document.createElement('span'); c.className = 'plugchip'; c.textContent = w; chips.appendChild(c); });
  note.appendChild(chips);
  note.appendChild(muted("Configuration côté hôte (auditd). Édition depuis l'UI = Phase 2 (à venir)."));
  host.appendChild(note);
  initDaLayout();
}

// réorganisation par glisser-déposer des cards d'accès données (grille 2×2), ordre persisté localement
const DA_DT = 'text/soc-da';
function daOrder(){ try { return JSON.parse(localStorage.getItem('soc_da_order')) || []; } catch(e){ return []; } }
function applyDaOrder(){ const host=$('#da-body'); if(!host) return; const note=host.querySelector('.da-note'); const cards=[...host.querySelectorAll('.card[data-da]')]; const ord=daOrder(); cards.sort((a,b)=>{const ia=ord.indexOf(a.dataset.da),ib=ord.indexOf(b.dataset.da); return (ia<0?99:ia)-(ib<0?99:ib);}); cards.forEach(c=>host.insertBefore(c,note)); }
function saveDaDrop(from,to){ const ids=[...$('#da-body').querySelectorAll('.card[data-da]')].map(c=>c.dataset.da); let o=daOrder().filter(x=>ids.includes(x)); ids.forEach(x=>{if(!o.includes(x))o.push(x);}); o.splice(o.indexOf(from),1); o.splice(o.indexOf(to),0,from); localStorage.setItem('soc_da_order',JSON.stringify(o)); applyDaOrder(); }
function initDaLayout(){ $('#da-body').querySelectorAll('.card[data-da]').forEach(card=>{ const id=card.dataset.da; const grip=document.createElement('span'); grip.className='ovgrip'; grip.title='Glisser pour réorganiser'; grip.innerHTML=ic('grip'); grip.draggable=true; grip.addEventListener('dragstart',e=>{e.dataTransfer.setData(DA_DT,id); e.dataTransfer.effectAllowed='move'; card.classList.add('ovdragging');}); grip.addEventListener('dragend',()=>card.classList.remove('ovdragging')); card.addEventListener('dragover',e=>{ if(e.dataTransfer.types.includes(DA_DT)){e.preventDefault(); card.classList.add('ovdragover');} }); card.addEventListener('dragleave',()=>card.classList.remove('ovdragover')); card.addEventListener('drop',e=>{ if(!e.dataTransfer.types.includes(DA_DT))return; e.preventDefault(); card.classList.remove('ovdragover'); const from=e.dataTransfer.getData(DA_DT); if(from&&from!==id) saveDaDrop(from,id); }); card.appendChild(grip); }); applyDaOrder(); }

export { daRenduDeReponse, renderDataAccess };
