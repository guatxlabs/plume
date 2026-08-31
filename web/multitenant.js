// multitenant.js — extracted from app.js (DEEP state-container split). Behaviour-preserving.
// #2c multi-tenant : switcher tenant/env (header) + vue Tenants + grants + audit acces operateur.
import { $, LANG, LOC, api, apiSend, applyRoleClass, confirmWithConsequence, fmtTs, ic, muted, pagedList, toast } from './core.js';
import { S, ecrireDansLeStockageDuSite, ecrireSansDireLeRefus, lireLeStockageDuSite } from './state.js';
import { runQ, tableEl } from './viz.js';
import { ROLE_LABEL, currentTab, fetchMe, loadUsers, refresh, refreshCurrentView, refreshPanels, renderNav, route, setAuthUI } from './app.js';

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
  // `P4.13-d` — NAVIGATION : RÉCONCILIATION AU CHARGEMENT, AUCUN CHOIX À ANNONCER. Cette lecture n'est pas
  // un geste d'exploitant : elle RESTAURE une position, et la ligne suivante la VALIDE contre la liste réelle
  // des tenants — un refus du stockage rend exactement ce que rend une clé absente ou périmée, et le repli
  // écrit juste en dessous s'applique alors mot pour mot. Le lecteur gardé DÉCLARE ce silence par son nom
  // (`P4.13-a`), là où la capture au corps VIDE qu'il remplace ne le distinguait pas d'un oubli.
  let cur = lireLeStockageDuSite('plume_tenant') || '';
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
  // `P4.13-d` — PRÉFÉRENCE : UNE BASCULE DE TENANT QUI NE SE RETIENT PAS EST UNE PERTE QUE L'EXPLOITANT DOIT
  // LIRE. C'est un choix qu'on pose puis qu'on quitte, et il porte plus loin que les autres : au chargement
  // suivant, `initTenants` retombe sur `AUTH.tenant` — la console repart donc SUR UN AUTRE TENANT que
  // celui qu'on croyait avoir laissé. La capture au corps VIDE d'avant avalait ce refus, et l'avis de succès
  // juste en dessous (« Tenant courant : … ») le rendait PIRE : il confirmait un état que rien n'avait retenu.
  const retenu = ecrireDansLeStockageDuSite('plume_tenant', tid);
  toast('Tenant courant : ' + tid, 'info');
  if (!retenu) toast(LANG === 'en' ? 'Tenant switched for this session only: this browser refuses site storage, so the next load will start on your home tenant.' : "Tenant basculé pour cette session seulement : ce navigateur refuse le stockage de site, le prochain chargement repartira sur votre tenant d'origine.", 'info', 5000);
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
  // `P4.13-d` — NAVIGATION, DEUX FOIS, ET AUCUN CHOIX D'EXPLOITANT N'EST EN CAUSE ICI. (1) La lecture est une
  // RÉCONCILIATION AU CHARGEMENT, validée à la ligne même contre la liste réelle des environnements de CE
  // tenant : un refus rend ce que rend une clé absente, et le repli « Tous » s'applique. (2) L'effacement est
  // un REPLI APRÈS DISPARITION — l'environnement retenu n'existe plus, on retire une clé devenue fausse. Il
  // n'y a rien à annoncer : l'exploitant n'a rien réglé, et le sélecteur montre déjà « Tous ».
  let cur = lireLeStockageDuSite('plume_env') || '';
  if (cur && !ids.includes(cur)) { cur = ''; ecrireSansDireLeRefus('plume_env', null); }
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
  // `P4.13-d` — PRÉFÉRENCE : LE SECOND DES DEUX SITES DE CE MODULE OÙ UN CHOIX EST EN JEU. L'exploitant règle
  // un axe d'organisation puis le quitte ; s'il n'est pas retenu, le prochain chargement repart sur « Tous »
  // et les vues ne portent plus le filtre qu'il croyait posé. `null` EFFACE la clé — c'est la forme que la
  // ligne d'avant écrivait à la main, et l'écrivain partagé la porte déjà (`P4.13-b`).
  const retenu = ecrireDansLeStockageDuSite('plume_env', v || null);
  toast('Environnement : ' + (v || 'Tous'), 'info');
  if (!retenu) toast(LANG === 'en' ? 'Environment applied for this session only: this browser refuses site storage, so the next load will start on « All ».' : "Environnement appliqué pour cette session seulement : ce navigateur refuse le stockage de site, le prochain chargement repartira sur « Tous ».", 'info', 5000);
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
  const gbtn = document.createElement('button'); gbtn.type = 'button'; gbtn.className = 'btn btn-sm'; gbtn.textContent = 'Accès'; // P11.4-b : classes partagées
  gbtn.title = 'Gérer les accès (grants) de ce tenant';
  gbtn.onclick = () => { grantsBox.classList.toggle('hidden'); if (!grantsBox.classList.contains('hidden')) loadGrants(t.id, grantsBox); };
  act.appendChild(gbtn);
  if (sa && t.id !== 'default') {              // suspend/destroy = super-admin ; jamais sur 'default' (protégé serveur)
    const susp = document.createElement('button'); susp.type = 'button'; susp.className = 'btn btn-sm';
    susp.textContent = t.suspended ? 'Réactiver' : 'Suspendre';
    susp.onclick = () => toggleSuspend(t);
    const del = document.createElement('button'); del.type = 'button'; del.className = 'btn btn-sm btn-danger'; del.textContent = 'Supprimer';
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
  const consequence = suspend
    ? `ses utilisateurs perdent l'accès immédiatement (fail-closed) et les traitements de fond de ce tenant sont ignorés jusqu'à réactivation. Action auditée.`
    : `l'accès de ses utilisateurs et ses traitements de fond reprennent. Action auditée.`;
  if (!await confirmWithConsequence(`${suspend ? 'Suspendre' : 'Réactiver'} le tenant « ${t.name || t.id} »`, consequence, { okText: suspend ? 'Suspendre' : 'Réactiver', danger: suspend })) return;
  const path = '/tenants/' + encodeURIComponent(t.id) + (suspend ? '/suspend' : '/unsuspend');
  try { await apiSend(path, 'POST'); }
  catch (e) { toast((e && e.message) || 'échec', 'bad'); return; }
  toast('tenant ' + (suspend ? 'suspendu' : 'réactivé'), 'ok');
  loadTenantsView();
}

async function destroyTenant(t) {
  const label = t.name || t.id;
  // P11.5-b : confirmation partagée qui nomme la conséquence, renforcée par la ressaisie du nom.
  const r = await confirmWithConsequence(`Supprimer le tenant « ${label} »`, 'destruction cryptographique IRRÉVERSIBLE : la clé est oubliée et la base chiffrée supprimée, aucune restauration possible.', {
    danger: true, okText: 'Détruire définitivement', cancelText: 'Annuler',
    message: `Pour confirmer, retape EXACTEMENT le nom du tenant : ${t.name || t.id}`,
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
    // `P4.13-d` — NAVIGATION : REPLI APRÈS DESTRUCTION, PAS UNE BASCULE CHOISIE. Le tenant courant vient
    // d'être DÉTRUIT ; ce que l'on pose n'est pas une préférence mais la seule position encore tenable. Il
    // n'y a aucun choix à annoncer — la destruction a déjà été dite juste au-dessus (« tenant détruit ») —
    // et si le stockage refuse, le chargement suivant retombera de toute façon sur `AUTH.tenant`, qui est
    // précisément ce repli. Le silence est donc DÉCLARÉ, là où la capture VIDE d'avant le laissait nu.
    S.CURRENT_TENANT = fallback; ecrireSansDireLeRefus('plume_tenant', fallback);
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
  const add = document.createElement('button'); add.type = 'submit'; add.className = 'btn-primary btn-sm'; add.textContent = 'Ajouter'; // P11.4-b
  const res = document.createElement('span'); res.className = 'muted';
  uinp.className = 'field'; rsel.className = 'field';
  form.append(uinp, rsel, add, res);
  form.onsubmit = async e => {
    e.preventDefault();
    const user = uinp.value.trim(), role = rsel.value;
    if (!user) { res.textContent = 'utilisateur requis'; res.className = 'bad'; return; }
    // P11.5-b : un grant ÉLÈVE un droit (accès à un tenant avec un rôle) -> confirmation partagée.
    if (!await confirmWithConsequence(`Accorder l'accès au tenant ${tid}`, `« ${user} » obtient le rôle ${role} sur ce tenant` + (role === 'admin' ? ' — accès complet à sa configuration, ses secrets et ses suppressions' : '') + '.', { okText: 'Accorder', danger: role === 'admin' })) return;
    res.textContent = '…'; res.className = 'muted';
    try { await apiSend('/tenants/' + encodeURIComponent(tid) + '/grants', 'POST', { user, role }); }
    catch (err) { res.textContent = (err && err.message) || 'échec'; res.className = 'bad'; return; }
    uinp.value = ''; res.textContent = ''; res.className = 'muted'; toast('accès accordé', 'ok');
    loadGrants(tid, host);
  };
  host.appendChild(form);
}

async function removeGrant(tid, user, host) {
  if (!await confirmWithConsequence(`Retirer l'accès de « ${user} » au tenant ${tid}`, 'cet utilisateur ne pourra plus ouvrir ce tenant ni y lire quoi que ce soit dès sa prochaine requête.', { okText: 'Retirer' })) return;
  try { await apiSend('/tenants/' + encodeURIComponent(tid) + '/grants/' + encodeURIComponent(user), 'DELETE'); }  // 204 -> null
  catch (e) { toast((e && e.message) || 'échec', 'bad'); return; }
  toast('accès retiré', 'ok'); loadGrants(tid, host);
}

// --- Audit accès opérateur (item 4) : événements plume-operator-access / plume-tenant-admin du tenant courant.
// Interroge la base du TENANT COURANT via /api/query (GXQL) -> réutilise le rendu tableEl. Multi-tenant only.
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
