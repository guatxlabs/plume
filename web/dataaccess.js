// Accès données (DLP, gouvernance d'accès en lecture seule) : cinq panneaux sur des requêtes GXQL existantes,
// sélecteur de fenêtre d'analyse, note de périmètre, réordonnancement des cartes persisté localement. Extrait
// d'`app.js` par déplacement pur ; le seul consommateur est la navigation (`showView`). N'importe pas `app.js`.
import { $, ic, muted } from './core.js';
import { S } from './state.js';
import { runQ, tableEl } from './viz.js';

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
/* state: daWin -> S (state.js) */
const DA_WINLBL = { all: 'toute la rétention (~30 j)', '7d': '7 derniers jours', '24h': 'dernières 24 h' };
function daFromValue() { return S.daWin === 'all' ? 0 : Math.floor(Date.now() / 1000) - (S.daWin === '7d' ? 604800 : 86400); }
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
  const wlbl = document.createElement('span'); wlbl.className = 'muted';
  wlbl.textContent = 'Fenêtre : ' + DA_WINLBL[S.daWin] + ' · top N par panneau';
  const wsel = document.createElement('select'); wsel.className = 'k-theme'; wsel.setAttribute('aria-label', "Fenêtre d'analyse (DLP)");
  wsel.title = "Fenêtre d'analyse : borne le `from` des requêtes (le nombre de lignes reste cappé par panneau)";
  [['24h', '24 h'], ['7d', '7 j'], ['all', 'Tout']].forEach(([v, t]) => { const o = document.createElement('option'); o.value = v; o.textContent = t; if (v === S.daWin) o.selected = true; wsel.appendChild(o); });
  wsel.onchange = () => { S.daWin = wsel.value; renderDataAccess(); };
  bar.append(wlbl, wsel); host.appendChild(bar);
  const daFrom = daFromValue();
  const emptyTxt = 'Aucun changement récent (' + DA_WINLBL[S.daWin] + ') — ou capteur inactif';
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
      runQ(q.soql, true, daFrom).then(j => {
        if (!j || j.error || !Array.isArray(j.rows) || !j.rows.length) { slot.replaceChildren(muted(emptyTxt)); return; }
        // conteneur scrollable (comme l'Explore) -> les tables larges (dataacl : ~17 colonnes, chemins
        // /opt/local-path-provisioner/pvc-… longs) défilent DANS la card au lieu de déborder la mise en page.
        const wrap = document.createElement('div'); wrap.className = 'qresult daresult';
        wrap.appendChild(tableEl(j.columns, j.rows, q.soql));
        slot.replaceChildren(wrap);
      }).catch(() => slot.replaceChildren(muted(emptyTxt)));
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

export { renderDataAccess };
