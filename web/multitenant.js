// multitenant.js — extracted from app.js (DEEP state-container split). Behaviour-preserving.
// #2c multi-tenant : switcher tenant/env (header) + vue Tenants + grants + audit acces operateur.
import { $, LOC, api, apiSend, confirmModal, fmtTs, ic, modal, muted, pagedList, toast } from './core.js';
import { S } from './state.js';
import { runQ, tableEl } from './viz.js';
import { ROLE_LABEL, applyRoleClass, currentTab, fetchMe, loadUsers, refresh, refreshCurrentView, refreshPanels, renderNav, route, setAuthUI } from './app.js';

// ============ #2c MULTI-TENANT : switcher + vue Tenants + grants + audit accès opérateur ============
// La VRAIE garde reste SERVEUR (le daemon renvoie 400/403/404/409 ; le path-guard + le re-check handler
// enforcent super-admin/admin-de-tenant). Ici : gating UI (défense en profondeur), rendu textContent
// (anti-XSS), confirmations sur destructif. INVARIANT ABSOLU : en mode 0, multiTenantMode()===false ->
// aucune vue/route/entête tenant -> comportement STRICTEMENT identique.

// admin EFFECTIF pour la nav : admin per-tenant (isAdmin, via GET /api/users) OU super-admin plateforme
// (is_superadmin, /api/me). En mode 0, AUTH.is_superadmin est TOUJOURS false -> uiIsAdmin()===isAdmin
// (aucun changement). Le super-admin garde l'accès à l'espace Administration même cross-tenant.
function uiIsAdmin() { return S.isAdmin || !!(S.AUTH && S.AUTH.is_superadmin); }

// Détection FIABLE du mode 1 (multi-tenant). Fail-CLOSED côté mode 0 : chaque signal reste faux en mode 0
// (is_superadmin=false, tenant='default', my-tenants=[{id:'default',role}] sans name/suspended).
function multiTenantMode() {
  if (S.AUTH && S.AUTH.is_superadmin) return true;
  if (S.AUTH && S.AUTH.tenant && S.AUTH.tenant !== 'default') return true;
  if (Array.isArray(S.MY_TENANTS)) {
    if (S.MY_TENANTS.length > 1) return true;
    if (S.MY_TENANTS.some(t => t && (t.name !== undefined || t.suspended !== undefined))) return true;
  }
  return false;
}

// --- switcher de tenant (header) : sélectionne le contexte client de TOUTES les vues data-plane ----------
async function initTenants() {
  let tenants = null;
  try { tenants = await api('/my-tenants'); } catch (e) { tenants = null; }
  S.MY_TENANTS = Array.isArray(tenants) ? tenants : [];
  const box = $('#tenantbox'), sel = $('#tenant-switch');
  if (!multiTenantMode()) {           // mode 0 / mono-tenant : AUCUNE UI tenant, CURRENT_TENANT reste '' (invariant)
    S.CURRENT_TENANT = '';
    if (box) box.hidden = true;
    renderNav(currentTab());
    return;
  }
  // Tenants UTILISABLES pour le switcher : un super-admin voit TOUT ; un admin de tenant ne voit que ses
  // grants matérialisés (name présent) + son tenant courant. (Sur la route /api/my-tenants, le serveur force
  // au.tenant='default' -> il ajoute une entrée `default` sans `name` même à un non-membre : on l'écarte ici
  // pour ne pas proposer un tenant inaccessible.)
  const usable = S.MY_TENANTS.filter(t => (S.AUTH && S.AUTH.is_superadmin) || (t && (t.name !== undefined || t.id === (S.AUTH && S.AUTH.tenant))));
  // mode 1 : résout le tenant courant (storage validé -> AUTH.tenant -> 1er de la liste utilisable).
  const ids = usable.map(t => t.id);
  let cur = '';
  try { cur = localStorage.getItem('plume_tenant') || ''; } catch (e) {}
  if (!ids.includes(cur)) cur = (S.AUTH && ids.includes(S.AUTH.tenant)) ? S.AUTH.tenant : (ids[0] || (S.AUTH && S.AUTH.tenant) || '');
  const differed = !!(S.AUTH && cur && cur !== S.AUTH.tenant);
  S.CURRENT_TENANT = cur;
  // switcher visible SEULEMENT si super-admin OU strictement plus d'un tenant utilisable (sinon mono-tenant -> caché).
  const show = !!(S.AUTH && S.AUTH.is_superadmin) || usable.length > 1;
  if (box) box.hidden = !show;
  if (sel && show) {
    sel.replaceChildren(...usable.map(t => {
      const o = document.createElement('option');
      o.value = t.id;
      let lbl = (t.name || t.id);
      if (t.suspended) lbl += ' (suspendu)';
      if (t.role) lbl += ' · ' + t.role;
      o.textContent = lbl;                 // textContent -> anti-XSS
      if (t.id === cur) o.selected = true;
      return o;
    }));
    sel.onchange = () => switchTenant(sel.value);
  }
  if (differed) { await reloadForTenant(); }   // resync identité + vues pour le tenant restauré (storage)
  else { renderNav(currentTab()); route(); }   // révèle l'onglet Tenants + (re)charge le loader courant
}

async function switchTenant(tid) {
  if (!tid || tid === S.CURRENT_TENANT) return;
  S.CURRENT_TENANT = tid;
  try { localStorage.setItem('plume_tenant', tid); } catch (e) {}
  toast('Tenant courant : ' + tid, 'info');
  await reloadForTenant();
  const sel = $('#tenant-switch'); if (sel && sel.value !== tid) sel.value = tid;
}

// Rechargement complet pour le nouveau contexte tenant : /api/me (rôle PER-TENANT) + isAdmin + toutes les vues.
async function reloadForTenant() {
  // #2d : re-résout les environnements du NOUVEAU tenant AVANT toute charge de données (les env sont
  // cloisonnés par tenant : un env du tenant précédent peut ne plus exister ici). reloadOnChange=false :
  // reloadForTenant recharge lui-même les vues juste après -> CURRENT_ENV est prêt, pas de double charge.
  try { await initEnvironments(false); } catch (e) {}
  try { const me = await fetchMe(); if (me && me.user) { S.AUTH = me; setAuthUI(); applyRoleClass(me.role); } } catch (e) {}
  try { await loadUsers(); } catch (e) {}   // met à jour isAdmin (per-tenant) puis route() (recharge le loader d'onglet)
  refresh(); refreshPanels();
}

// --- #2d sélecteur d'environnement (header, à côté du switcher de tenant) --------------------------------
// Axe d'ORGANISATION (pas une frontière de sécurité : même tenant) : filtre les vues par env_id (prod/staging/
// site…). GET /api/environments -> {environments:[{env,n}…], current}. Règles :
//   - <= 1 env (le serveur renvoie un unique `prod` en mode 0, ou tenant mono-env) -> sélecteur CACHÉ,
//     CURRENT_ENV='' , AUCUN entête posé -> INVARIANT : rien ne change.
//   - > 1 env -> « Tous » (value vide, aucun filtre) + un item par env (avec son volume). Sélection persistée
//     dans localStorage('plume_env') et restaurée SI l'env existe toujours dans ce tenant (sinon -> « Tous »).
// reloadOnChange : quand true (boot), si la résolution change CURRENT_ENV (env persisté restauré), on recharge
// la vue courante pour appliquer le filtre. Quand false (appelé depuis reloadForTenant), l'appelant recharge.
async function initEnvironments(reloadOnChange = true) {
  const prev = S.CURRENT_ENV;
  let data = null;
  try { data = await api('/environments'); } catch (e) { data = null; }
  const envs = (data && Array.isArray(data.environments)) ? data.environments : [];
  const box = $('#envbox'), sel = $('#env-switch');
  // mono-env (ou échec de résolution) : aucun sélecteur, aucun filtre, invariant préservé.
  if (envs.length <= 1) {
    S.CURRENT_ENV = '';
    if (sel) sel.onchange = null;
    if (box) box.hidden = true;
    if (reloadOnChange && prev !== '') refreshCurrentView();   // on retombe de « env X » à « Tous »
    return;
  }
  // > 1 env : résout la sélection (storage validé contre la liste réelle de CE tenant).
  const ids = envs.map(e => e.env);
  let cur = '';
  try { cur = localStorage.getItem('plume_env') || ''; } catch (e) {}
  if (cur && !ids.includes(cur)) { cur = ''; try { localStorage.removeItem('plume_env'); } catch (e) {} }
  S.CURRENT_ENV = cur;
  if (box) box.hidden = false;
  if (sel) {
    const opts = [];
    const all = document.createElement('option');
    all.value = ''; all.textContent = 'Tous';                 // « Tous » = aucun filtre (agrégat multi-env)
    opts.push(all);
    envs.forEach(e => {
      const o = document.createElement('option');
      o.value = e.env;
      const n = Number.isFinite(e.n) ? ' (' + e.n.toLocaleString(LOC) + ')' : '';
      o.textContent = e.env + n;                               // textContent -> anti-XSS
      opts.push(o);
    });
    sel.replaceChildren(...opts);
    sel.value = cur;
    sel.onchange = () => switchEnv(sel.value);
  }
  if (reloadOnChange && cur !== prev) refreshCurrentView();    // env persisté restauré au boot -> applique le filtre
}

// Changement d'environnement : pose/retire l'entête X-Plume-Env (via CURRENT_ENV), persiste, recharge la vue.
async function switchEnv(env) {
  const v = env || '';
  if (v === S.CURRENT_ENV) return;
  S.CURRENT_ENV = v;
  try { if (v) localStorage.setItem('plume_env', v); else localStorage.removeItem('plume_env'); } catch (e) {}
  toast('Environnement : ' + (v || 'Tous'), 'info');
  refreshCurrentView();                                        // overview + panneaux + loader de la vue courante
  const sel = $('#env-switch'); if (sel && sel.value !== v) sel.value = v;
}

// --- Vue « Tenants » (Administration) : liste + CRUD (super-admin) OU accès de son tenant (admin de tenant) --
async function loadTenantsView() {
  const sec = $('#tenants-panel'); if (!sec) return;
  const list = $('#tenant-list'); if (!list) return;
  const sa = !!(S.AUTH && S.AUTH.is_superadmin);
  const onboard = $('#tenant-onboard'); if (onboard) onboard.hidden = !sa;   // onboarding = super-admin only
  if (!sa) { const f = $('#tenant-form'); if (f) f.classList.add('hidden'); }
  if (!multiTenantMode()) { list.replaceChildren(muted('Mode mono-tenant : aucune gestion de tenants.')); return; }
  if (sa) {
    let j;
    try { j = await api('/tenants'); }        // GET /api/tenants -> {tenants:[...]} (super-admin, re-check serveur)
    catch (e) { list.replaceChildren(muted('accès refusé ou erreur : ' + e.message)); return; }
    renderTenantList(j.tenants || []);
  } else {
    renderTenantAdminSelf(list);              // admin de tenant : accès de SON tenant courant uniquement
  }
}

function renderTenantList(tenants) {
  const list = $('#tenant-list'); if (!list) return;
  if (!tenants.length) { list.replaceChildren(muted('aucun tenant provisionné')); return; }
  // BATCH #13 — parc de tenants growable (ESN/multi-client) : liste paginée (pattern canonique), carte par tenant.
  pagedList(list, { mode: 'client', pageSize: 50, rows: tenants, renderRow: t => tenantCard(t, true) });
}

function renderTenantAdminSelf(list) {
  list.replaceChildren();
  const tid = (S.AUTH && S.AUTH.tenant) || S.CURRENT_TENANT || 'default';
  const t = (S.MY_TENANTS || []).find(x => x.id === tid) || { id: tid };
  const card = tenantCard(t, false);          // sa=false -> ni suspend ni destroy (admin de tenant borné)
  list.appendChild(card);
  const gb = card.querySelector('.tnt-grants');  // ouvre directement les accès (seule capacité de l'admin de tenant)
  if (gb) { gb.classList.remove('hidden'); loadGrants(tid, gb); }
}

function tenantCard(t, sa) {
  const card = document.createElement('div'); card.className = 'tnt-card';
  const head = document.createElement('div'); head.className = 'tnt-head';
  const title = document.createElement('div'); title.className = 'tnt-title';
  const nm = document.createElement('b'); nm.textContent = t.name || t.id;                 // textContent (anti-XSS)
  title.appendChild(nm);
  if (t.name && t.name !== t.id) { const idb = document.createElement('span'); idb.className = 'muted tnt-id'; idb.textContent = t.id; title.appendChild(idb); }
  const st = document.createElement('span'); st.className = 'badge ' + (t.suspended ? 'tnt-susp' : 'tnt-active');
  st.textContent = t.suspended ? 'suspendu' : 'actif'; title.appendChild(st);
  head.appendChild(title);
  if (t.created !== undefined || t.nb_users !== undefined) {
    const meta = document.createElement('span'); meta.className = 'muted tnt-meta';
    const parts = [];
    if (t.created) parts.push('créé ' + fmtTs(t.created));
    if (t.nb_users !== undefined) parts.push((t.nb_users || 0) + ' accès');
    meta.textContent = parts.join(' · '); head.appendChild(meta);
  }
  const act = document.createElement('div'); act.className = 'tnt-act';
  const grantsBox = document.createElement('div'); grantsBox.className = 'tnt-grants hidden';
  const gbtn = document.createElement('button'); gbtn.type = 'button'; gbtn.textContent = 'Accès';
  gbtn.title = 'Gérer les accès (grants) de ce tenant';
  gbtn.onclick = () => { grantsBox.classList.toggle('hidden'); if (!grantsBox.classList.contains('hidden')) loadGrants(t.id, grantsBox); };
  act.appendChild(gbtn);
  if (sa && t.id !== 'default') {              // suspend/destroy = super-admin ; jamais sur 'default' (protégé serveur)
    const susp = document.createElement('button'); susp.type = 'button';
    susp.textContent = t.suspended ? 'Réactiver' : 'Suspendre';
    susp.onclick = () => toggleSuspend(t);
    const del = document.createElement('button'); del.type = 'button'; del.className = 'danger'; del.textContent = 'Supprimer';
    del.title = 'Destruction cryptographique irréversible';
    del.onclick = () => destroyTenant(t);
    act.append(susp, del);
  }
  head.appendChild(act);
  card.append(head, grantsBox);
  return card;
}

async function toggleSuspend(t) {
  const suspend = !t.suspended;
  const msg = suspend
    ? `Suspendre le tenant « ${t.name || t.id} » ? Ses utilisateurs perdront l'accès (fail-closed) et les traitements de fond seront ignorés. Action auditée.`
    : `Réactiver le tenant « ${t.name || t.id} » ? L'accès est rétabli.`;
  if (!await confirmModal(msg, { okText: suspend ? 'Suspendre' : 'Réactiver', danger: suspend })) return;
  const path = '/tenants/' + encodeURIComponent(t.id) + (suspend ? '/suspend' : '/unsuspend');
  try { await apiSend(path, 'POST'); }
  catch (e) { toast((e && e.message) || 'échec', 'bad'); return; }
  toast('tenant ' + (suspend ? 'suspendu' : 'réactivé'), 'ok');
  loadTenantsView();
}

async function destroyTenant(t) {
  const label = t.name || t.id;
  const r = await modal({
    title: 'Supprimer le tenant', danger: true, okText: 'Détruire définitivement', cancelText: 'Annuler',
    message: `DESTRUCTION CRYPTOGRAPHIQUE IRRÉVERSIBLE du tenant « ${label} » : la clé est oubliée et la base chiffrée supprimée (aucune restauration possible). Pour confirmer, retape EXACTEMENT le nom du tenant : ${t.name || t.id}`,
    fields: [{ name: 'confirm', label: 'Nom du tenant', placeholder: t.name || t.id, required: true }],
    validate: v => (String(v.confirm || '').trim() !== (t.name || t.id)) ? 'Le nom saisi ne correspond pas.' : null,
  });
  if (!r) return;
  try { await apiSend('/tenants/' + encodeURIComponent(t.id), 'DELETE', { confirm: String(r.confirm || '').trim() }); }
  catch (e) { toast((e && e.message) || 'échec', 'bad'); return; }
  toast('tenant détruit', 'ok');
  // si le tenant courant vient d'être détruit : bascule sur un tenant encore accessible.
  if (S.CURRENT_TENANT === t.id) {
    const fallback = (S.AUTH && S.AUTH.tenant && S.AUTH.tenant !== t.id) ? S.AUTH.tenant : 'default';
    S.CURRENT_TENANT = fallback; try { localStorage.setItem('plume_tenant', fallback); } catch (e) {}
  }
  loadTenantsView();
}

// --- gestion des grants d'un tenant (super-admin : tous ; admin de tenant : le sien) — le serveur enforce ---
async function loadGrants(tid, host) {
  if (!host) return;
  host.replaceChildren(muted('chargement…'));
  let j;
  try { j = await api('/tenants/' + encodeURIComponent(tid) + '/grants'); }
  catch (e) { host.replaceChildren(muted('accès refusé ou erreur : ' + e.message)); return; }
  host.replaceChildren();
  const grants = j.grants || [];
  const cap = document.createElement('div'); cap.className = 'muted'; cap.style.marginBottom = '6px';
  cap.textContent = 'Accès du tenant ' + (j.tenant || tid) + ' — rôle ∈ admin | editor | viewer';
  host.appendChild(cap);
  if (!grants.length) host.appendChild(muted('aucun accès matérialisé (les grants SSO sont résolus à la volée).'));
  grants.forEach(g => {
    const row = document.createElement('div'); row.className = 'grow';
    const info = document.createElement('span');
    const b = document.createElement('b'); b.textContent = g.user;                          // textContent (anti-XSS)
    const rb = document.createElement('span'); rb.className = 'badge role-' + g.role; rb.textContent = ROLE_LABEL[g.role] || g.role;
    info.append(b, document.createTextNode(' '), rb);
    const rm = document.createElement('button'); rm.type = 'button'; rm.className = 'picon'; rm.innerHTML = ic('x'); rm.title = "Retirer l'accès";
    rm.onclick = () => removeGrant(tid, g.user, host);
    row.append(info, rm); host.appendChild(row);
  });
  const form = document.createElement('form'); form.className = 'grantadd';
  const uinp = document.createElement('input'); uinp.placeholder = 'utilisateur (a-z, . _ -)'; uinp.spellcheck = false; uinp.autocomplete = 'off'; uinp.setAttribute('aria-label', 'Utilisateur à autoriser');
  const rsel = document.createElement('select'); rsel.setAttribute('aria-label', 'Rôle');
  ['admin', 'editor', 'viewer'].forEach(role => { const o = document.createElement('option'); o.value = role; o.textContent = role; if (role === 'viewer') o.selected = true; rsel.appendChild(o); });
  const add = document.createElement('button'); add.type = 'submit'; add.textContent = 'Ajouter';
  const res = document.createElement('span'); res.className = 'muted';
  form.append(uinp, rsel, add, res);
  form.onsubmit = async e => {
    e.preventDefault();
    const user = uinp.value.trim(), role = rsel.value;
    if (!user) { res.textContent = 'utilisateur requis'; res.className = 'bad'; return; }
    res.textContent = '…'; res.className = 'muted';
    try { await apiSend('/tenants/' + encodeURIComponent(tid) + '/grants', 'POST', { user, role }); }
    catch (err) { res.textContent = (err && err.message) || 'échec'; res.className = 'bad'; return; }
    uinp.value = ''; res.textContent = ''; res.className = 'muted'; toast('accès accordé', 'ok');
    loadGrants(tid, host);
  };
  host.appendChild(form);
}

async function removeGrant(tid, user, host) {
  if (!await confirmModal(`Retirer l'accès de « ${user} » au tenant ${tid} ?`, { okText: 'Retirer', danger: true })) return;
  try { await apiSend('/tenants/' + encodeURIComponent(tid) + '/grants/' + encodeURIComponent(user), 'DELETE'); }  // 204 -> null
  catch (e) { toast((e && e.message) || 'échec', 'bad'); return; }
  toast('accès retiré', 'ok'); loadGrants(tid, host);
}

// --- Audit accès opérateur (item 4) : événements plume-operator-access / plume-tenant-admin du tenant courant.
// Interroge la base du TENANT COURANT via /api/query (SOQL) -> réutilise le rendu tableEl. Multi-tenant only.
async function loadOperatorAudit() {
  const block = $('#opaccess-block'), body = $('#opaccess-body');
  if (!block || !body) return;
  if (!multiTenantMode()) { block.hidden = true; return; }   // mode 0 : bloc inerte -> vue Audit identique
  block.hidden = false;
  const src = ($('#opaccess-src') && $('#opaccess-src').value) || 'plume-operator-access';
  body.replaceChildren(muted('chargement…'));
  let j;
  try { j = await runQ('search source=' + src + ' | sort -ts | head 200', true, 0); }
  catch (e) { body.replaceChildren(muted('erreur : ' + ((e && e.message) || e))); return; }
  if (j && j.error) { body.replaceChildren(muted('erreur : ' + j.error)); return; }
  const cols = j.columns || j.cols || [], rows = j.rows || [];
  if (!rows.length) { body.replaceChildren(muted('aucun événement (' + src + ') sur le tenant courant')); return; }
  body.replaceChildren(tableEl(cols, rows, 'search source=' + src));
}


export { initEnvironments, initTenants, loadOperatorAudit, loadTenantsView, multiTenantMode, uiIsAdmin };
