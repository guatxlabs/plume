// Écran de connexion (form-login), déconnexion et état d'authentification. Extrait d'`app.js` par déplacement
// pur ; la porte d'entrée — câblage du formulaire, du bouton de déconnexion, et le `GET /api/me` qui décide
// entre l'application et l'overlay — est exposée par `initAuthGate()`, appelée par `app.js` au point où ce bloc
// vivait (un module s'exécute à l'import, avant l'enveloppe `fetch` d'`app.js` qui pose CSRF et tenant).
// `multitenant.js` continue de lire `fetchMe` / `setAuthUI` via le ré-export d'`app.js`. N'importe pas `app.js`.
import { $, api, apiSend, applyRoleClass, confirmModal } from './core.js';
import { S } from './state.js';
import { initAiAssist } from './ai.js';
import { initEnvironments, initTenants } from './multitenant.js';
import { prefsInit } from './prefs.js';
import { loadBulletin } from './system.js';

// ============ AUTH : écran de login (form-login), logout, état d'auth =============================
// Contrat daemon :
//   GET  /api/me     -> 200 {user,role,auth_method,csrf_token} si authentifié ; 401 sinon.
//   POST /api/login  {user,pass} -> 200 {ok,user,role} (pose plume_session HttpOnly + plume_csrf JS) ;
//                                     401 {error} (identifiants) ; 429 {error}+Retry-After (lockout).
//   POST /api/logout -> 200 (efface les cookies).
// FLUX SSO k3s INTACT : derrière le forward-auth Authentik, /api/me répond 200 (auth_method="sso")
// -> AUTH renseigné, overlay JAMAIS affiché, l'app charge normalement. Idem mode démo (auth_method
// ="demo"). L'écran de login ne s'affiche QU'au 401 (accès direct/standalone sans session cookie).
const $login = () => $('#login-ov');
function setAuthUI() {
  const box = $('#authbox'), id = $('#auth-id');
  if (!box) return;
  if (S.AUTH && S.AUTH.user) {
    if (id) {
      const role = S.AUTH.role ? ' · ' + S.AUTH.role : '';
      // auth_method affiché seulement s'il n'est pas la session cookie (sso/basic/bearer/demo) -> contexte
      const am = (S.AUTH.auth_method && S.AUTH.auth_method !== 'cookie') ? ' (' + S.AUTH.auth_method + ')' : '';
      id.textContent = S.AUTH.user + role + am;
      id.title = 'Connecté : ' + S.AUTH.user + (S.AUTH.role ? ' (' + S.AUTH.role + ')' : '') + (S.AUTH.auth_method ? ' — ' + S.AUTH.auth_method : '');
    }
    box.hidden = false;
  } else {
    box.hidden = true;
  }
}
function showLogin(show) {
  const ov = $login(); if (!ov) return;
  ov.hidden = !show;
  document.body.classList.toggle('login-locked', !!show);
  if (show) {
    // coupe l'auto-refresh : inutile de marteler l'API en 401 derrière l'overlay (le reload post-login réarme)
    if (typeof S.autoTimer !== 'undefined' && S.autoTimer) { clearInterval(S.autoTimer); S.autoTimer = null; }
    const u = $('#login-user'); if (u) setTimeout(() => { try { u.focus(); } catch (e) {} }, 40);
  }
}
async function fetchMe() {
  // api() jette sur 401/non-2xx/réseau -> on retombe sur null (= non authentifié), comme l'ancien !r.ok.
  try { return await api('/me'); }
  catch (e) { return null; }
}
async function doLogin(user, pass) {
  // /api/login est PUBLIC + exempté de CSRF (pas encore de session). Retourne {ok:true,...} sur succès.
  const r = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ user, pass }),
  });
  if (r.ok) return { ok: true };
  if (r.status === 429) {
    const ra = parseInt(r.headers.get('Retry-After') || '', 10);
    return { ok: false, status: 429, retry: Number.isFinite(ra) && ra > 0 ? ra : 0 };
  }
  if (r.status === 401) return { ok: false, status: 401 };
  let msg = ''; try { msg = (await r.text()).slice(0, 160); } catch (e) {}
  return { ok: false, status: r.status, msg };
}
function bindLoginForm() {
  const f = $('#login-form'); if (!f || f._bound) return; f._bound = true;
  const err = $('#login-err'), btn = $('#login-submit');
  const fail = m => { if (err) { err.textContent = m; err.hidden = false; } };
  f.addEventListener('submit', async e => {
    e.preventDefault();
    if (err) err.hidden = true;
    const user = ($('#login-user') ? $('#login-user').value : '').trim();
    const pass = $('#login-pass') ? $('#login-pass').value : '';
    if (!user || !pass) { fail('Renseigne identifiant et mot de passe.'); return; }
    if (btn) { btn.disabled = true; btn.dataset._t = btn.textContent; btn.textContent = '...'; }
    let res;
    try { res = await doLogin(user, pass); }
    catch (ex) { res = { ok: false, status: 0, msg: ex && ex.message }; }
    if (btn) { btn.disabled = false; btn.textContent = btn.dataset._t || 'Se connecter'; }
    if (res.ok) {
      // succès : cookies plume_session + plume_csrf posés -> rechargement = boot AUTHENTIFIÉ propre
      // (route()/refresh()/loaders re-exécutés avec une session valide, zéro état partiel résiduel).
      location.reload();
      return;
    }
    if (res.status === 429) fail(res.retry ? `Trop de tentatives, réessaie dans ${res.retry}s.` : 'Trop de tentatives, réessaie plus tard.');
    else if (res.status === 401) fail('Identifiants invalides.');
    else fail('Échec de connexion' + (res.msg ? ' : ' + res.msg : '') + (res.status ? ' (' + res.status + ')' : ''));
    const p = $('#login-pass'); if (p) { p.value = ''; try { p.focus(); } catch (e) {} }
  });
}
async function doLogout() {
  if (!await confirmModal('Se déconnecter de Plume ?', { okText: 'Déconnexion', danger: false })) return;
  try { await apiSend('/logout', 'POST'); } catch (e) {}
  S.AUTH = null;
  // reload -> /api/me 401 (cookie effacé) -> écran de login. En SSO, l'identité vient de l'amont
  // (forward-auth) : /api/me reste 200 -> l'app recharge (la déconnexion SSO se fait côté Authentik).
  location.reload();
}
function initAuthGate() {
    bindLoginForm();
    const lo = $('#logout'); if (lo && !lo._bound) { lo._bound = true; lo.onclick = doLogout; }
    fetchMe().then(me => {
      if (me && me.user) {
        S.AUTH = me; setAuthUI(); applyRoleClass(me.role); showLogin(false);   // SSO/cookie/démo : app directe
        prefsInit();      // #62 — charge les préférences self-scoped du compte (favoris + réglages par vue) puis rejoue les callbacks
        loadBulletin();   // #51 DAY-2 OPS — bandeau MOTD (aucun bulletin -> reste caché ; invariant mode 0)
        initAiAssist();   // #16 — assistant IA (NL→GXQL) dans Explore : révélé UNIQUEMENT si /api/ai/status = enabled (feature off -> reste caché)
        // #2c switcher tenant, PUIS #2d sélecteur d'environnement (résolu APRÈS le tenant : les env sont
        // cloisonnés par tenant). initEnvironments(true) : si un env persisté est restauré, il recharge la vue.
        initTenants().then(() => initEnvironments(true)).catch(() => { try { initEnvironments(true); } catch (e) {} });
      } else { S.AUTH = null; setAuthUI(); showLogin(true); document.documentElement.classList.add('app-ready'); }   // 401 : écran de login (overlay au-dessus ; on révèle <main> pour ne pas le laisser bloqué masqué)
    });
}

export { initAuthGate, fetchMe, setAuthUI, showLogin };
