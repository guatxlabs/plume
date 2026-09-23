// Écran de connexion (form-login), déconnexion et état d'authentification. Extrait d'`app.js` par déplacement
// pur ; la porte d'entrée — câblage du formulaire, du bouton de déconnexion, et le `GET /api/me` qui décide
// entre l'application et l'overlay — est exposée par `initAuthGate()`, appelée par `app.js` au point où ce bloc
// vivait (un module s'exécute à l'import, avant l'enveloppe `fetch` d'`app.js` qui pose CSRF et tenant).
// `multitenant.js` continue de lire `fetchMe` / `setAuthUI` via le ré-export d'`app.js`. N'importe pas `app.js`.
import { $, LANG, api, apiSend, applyRoleClass, causeNommeeParLeDemon, confirmModal, motDuRefusDuSecondFacteur, natureDuRefusDuSecondFacteur } from './core.js';
import { S } from './state.js';
import { initAiAssist } from './ai.js';
import { initEnvironments, initTenants } from './multitenant.js';
import { prefsInit } from './prefs.js';
import { loadBulletin } from './system.js';
import { chargerLeCatalogueAttack } from './catalogue_attack.js'; // `P11.6-c` : le catalogue des noms ATT&CK, chargé une fois par session

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
  // `P10.22-n` — UN PREMIER FACTEUR ACCEPTÉ N'EST PAS UNE SESSION. Sur un compte à MFA active, `login_post`
  // rend deux cents `{mfa_required: true, ticket}` SANS poser de session (daemon/src/session.rs). Cet écran
  // lisait tout deux cents comme un succès et rechargeait : `/api/me` rendait quatre cent un, l'écran
  // revenait, VIDE et sans un mot — le second facteur n'était jamais demandé, et un compte à MFA ne pouvait
  // pas ouvrir de session par ce formulaire. Le corps du succès est donc LU.
  if (r.ok) {
    let corps = null; try { corps = JSON.parse(await r.text()); } catch (e) {}
    if (corps && corps.mfa_required === true && typeof corps.ticket === 'string' && corps.ticket) return { ok: false, ticketDuSecondFacteur: corps.ticket };
    return { ok: true };
  }
  if (r.status === 429) {
    const ra = parseInt(r.headers.get('Retry-After') || '', 10);
    return { ok: false, status: 429, retry: Number.isFinite(ra) && ra > 0 ? ra : 0 };
  }
  if (r.status === 401) return { ok: false, status: 401 };
  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // `P10.20-b` — UN REFUS QUE LE DÉMON NOMME N'EST PAS UN « ÉCHEC DE CONNEXION » ANONYME.
  //
  // CE QUE LE DÉMON FAIT MAINTENANT. `login_post` (daemon/src/session.rs) REFUSE la connexion en cinq
  // cent trois, `error` = `CAUSE_MFA_NON_LUE`, quand la ligne `user_mfa` du compte n'a pas été lue :
  // avant cette clé, le mot de passe SEUL posait la session d'un compte à MFA peut-être ACTIVE. Ce
  // refus est RÉESSAYABLE, et c'est précisément ce que la personne devant l'écran doit apprendre.
  //
  // CE QUI ÉTAIT FAUX DANS L'ÉNONCÉ, MESURÉ ICI : cet écran ne montrait PAS le message de passerelle.
  // Il n'emprunte ni `api()` ni `apiSend()` — c'est sa propre requête, `fetch` nu —, donc le repli
  // « Service momentanément indisponible » de `core.js` ne l'atteint jamais. Ce qu'il montrait est
  // autre chose, et pas meilleur : « Échec de connexion : » suivi du CORPS JSON BRUT coupé à 160
  // caractères, c'est-à-dire `{"error":"STATUT DE DOUBLE AUTHENTIFICATION NON LU : la lecture de…` —
  // une phrase tranchée au milieu, dans une syntaxe de machine, sous un titre qui dit « échec » là où
  // le démon dit « refus, réessayez ».
  //
  // CE QUI EST SERVI, ET RIEN D'AUTRE. La cause est extraite par le lecteur PARTAGÉ de `core.js`
  // (`causeNommeeParLeDemon`), qui rend '' dès que le corps n'est pas un objet JSON nommant sa cause :
  // une vraie panne de passerelle (HTML, corps vide) retombe donc mot pour mot sur l'ancien message.
  // Cet écran ne compose aucune phrase sur l'état du compte — il colle ce que le démon a écrit.
  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  let corps = ''; try { corps = await r.text(); } catch (e) {}
  const cause = causeNommeeParLeDemon(corps);
  if (cause) return { ok: false, status: r.status, cause };
  return { ok: false, status: r.status, msg: corps.slice(0, 160) };
}
// `P10.22-n` — LE SECOND FACTEUR : LA ROUTE QUE CET ÉCRAN N'APPELAIT PAS, ET LES DEUX REFUS QU'IL DOIT SÉPARER.
//
// CE QUE LE DÉMON SERT. `login_mfa_post` (daemon/src/handlers/idp.rs) échange le ticket et un code contre la
// session : deux cents `{ok}` et les cookies ; quatre cent un quand le ticket ou le code est refusé
// (« code MFA invalide », « ticket MFA invalide ou expiré (recommencez la connexion) », « aucune MFA active
// pour ce compte ») ; quatre cent vingt-neuf au verrou d'échecs par adresse, ou au FREIN du second facteur
// par compte (`CAUSE_SECOND_FACTEUR_FREINE`, `P10.22-m`, que se reconnecter par mot de passe ne lève pas) ;
// cinq cent trois quand le code est JUSTE mais que la base n'a pas pris l'écriture qui le consomme
// (`CAUSE_PAS_TOTP_NON_CONSOMME`, `CAUSE_CODE_DE_SECOURS_NON_CONSOMME`, `P10.21-s`) — aucune session, et le code
// n'est PAS brûlé — ; cinq cent trois encore quand la liste des codes de secours n'a pas été lue
// (`CAUSE_CODES_DE_SECOURS_ILLISIBLES`, `P10.22-r`) — code ni accepté ni refusé.
//
// CES REFUS NE DISENT PAS LA MÊME CHOSE DE LA PERSONNE DEVANT L'ÉCRAN. Le quatre cent un accuse son code (ou
// un ticket périmé) : la connexion reprend depuis le mot de passe, ce qui couvre les trois phrases d'un
// geste. Les cinq cent trois ne l'accusent PAS : le code reste dans son champ, et la phrase dit qu'il peut
// être soumis de nouveau — ou, liste illisible, qu'un code TOTP le peut. Le frein ramène au mot de passe et
// dit que cela ne le lève pas. Le partage est le STATUT, puis la CAUSE lue au point commun
// (`natureDuRefusDuSecondFacteur`, web/core.js) ; le témoin 108 relit chaque cause dans l'arbre du démon.
const MOTS_DU_SECOND_FACTEUR = {
  code_manquant: {
    fr: "Ce compte exige un second facteur : saisis le code de ton application d'authentification, ou un code de secours.",
    en: 'This account requires a second factor: enter the code from your authenticator app, or a recovery code.' },
  code_refuse: {
    fr: "Code REFUSÉ : aucune session n'est ouverte. Reprends la connexion depuis le mot de passe. Le démon a répondu —",
    en: 'Code REFUSED: no session is open. Start the sign-in again from the password. The daemon answered —' },
  code_non_en_cause: {
    fr: "Connexion REFUSÉE, et ton code n'est PAS en cause : le démon n'a ouvert aucune session. Le même code peut être soumis de nouveau tant qu'il est valable. Le démon en nomme la cause —",
    en: 'Sign-in REFUSED, and your code is NOT at fault: the daemon opened no session. The same code can be submitted again while it is valid. The daemon names the cause —' },
  second_facteur_refuse: {
    fr: "Connexion REFUSÉE au second facteur : le démon n'a ouvert aucune session. Il a répondu —",
    en: 'Sign-in REFUSED at the second factor: the daemon opened no session. It answered —' },
};
// Les clés propres à cet écran viennent de sa table ; les deux clés communes aux deux écrans du second
// facteur (`codes_de_secours_illisibles`, `second_facteur_freine`), du point commun.
const motDuSecondFacteur = (cle, delai) => (Object.prototype.hasOwnProperty.call(MOTS_DU_SECOND_FACTEUR, cle)
  ? (LANG === 'en' ? MOTS_DU_SECOND_FACTEUR[cle].en : MOTS_DU_SECOND_FACTEUR[cle].fr)
  : motDuRefusDuSecondFacteur(cle, delai));
// Le verrou d'échecs PAR ADRESSE n'est pas une clé ici : il garde la phrase que l'écran a déjà pour lui.
function cleDuRefusDuSecondFacteur(res) {
  const nature = natureDuRefusDuSecondFacteur(res.cause);
  if (res.status === 401) return 'code_refuse';
  if (res.status === 429) return nature === 'second_facteur_freine' ? 'second_facteur_freine' : '';
  if (res.status === 503 && nature === 'code_juste_non_consomme') return 'code_non_en_cause';
  if (res.status === 503 && nature === 'codes_de_secours_illisibles') return 'codes_de_secours_illisibles';
  if (res.cause) return 'second_facteur_refuse';
  return '';
}
async function doLoginMfa(ticket, code) {
  // Même forme de requête que `/api/login` : route PUBLIQUE, exemptée de CSRF (daemon/src/auth.rs).
  const r = await fetch('/api/login/mfa', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ ticket, code }),
  });
  if (r.ok) return { ok: true };
  let corps = ''; try { corps = await r.text(); } catch (e) {}
  const cause = causeNommeeParLeDemon(corps);
  if (r.status === 429) {
    // Le frein du second facteur et le verrou par adresse partagent le statut : la cause les sépare.
    const ra = parseInt(r.headers.get('Retry-After') || '', 10);
    return { ok: false, status: 429, retry: Number.isFinite(ra) && ra > 0 ? ra : 0, cause };
  }
  if (cause) return { ok: false, status: r.status, cause };
  return { ok: false, status: r.status, msg: corps.slice(0, 160) };
}
function bindLoginForm() {
  const f = $('#login-form'); if (!f || f._bound) return; f._bound = true;
  const err = $('#login-err'), btn = $('#login-submit');
  const fail = m => { if (err) { err.textContent = m; err.hidden = false; } };
  // `P10.20-b` — L'AVEU À DEUX NŒUDS DE CET ÉCRAN. La phrase est un nœud texte ENTIER (la seule forme
  // que le lexique sait traduire), la cause SERVIE par le démon est collée dans un SECOND nœud, telle
  // quelle : c'est la grammaire des quatre aveux du rang un, et elle ne s'écrit pas autrement ici sous
  // prétexte que la boîte est celle d'un message d'erreur.
  const avouerLeRefusNomme = cause => {
    if (!err) return;
    const dit = document.createElement('span');
    dit.textContent = 'Connexion REFUSÉE : le démon n\'a pas lu ce dont la décision dépend, et il en nomme la cause —';
    err.replaceChildren(dit, document.createTextNode(' « ' + String(cause).trim() + ' »'));
    err.hidden = false;
  };
  // `P10.22-n` — L'ÉTAPE DU CODE. Le ticket vit dans cette fermeture, jamais dans un stockage : il ne vaut
  // que pour cette page et cinq minutes. Identifiant et mot de passe sont DÉSACTIVÉS pendant l'étape — un
  // champ requis vide bloquerait l'envoi du formulaire — et rendus au retour vers le mot de passe.
  let ticketDuSecondFacteur = '';
  const aveuADeuxNoeuds = (mot, cause) => {
    if (!err) return;
    const dit = document.createElement('span');
    dit.textContent = mot;
    if (cause) err.replaceChildren(dit, document.createTextNode(' « ' + String(cause).trim() + ' »'));
    else err.replaceChildren(dit);
    err.hidden = false;
  };
  const poserLEtapeDuCode = (ticket) => {
    ticketDuSecondFacteur = ticket;
    const bloc = $('#login-code-lbl'), code = $('#login-code');
    ['#login-user', '#login-pass'].forEach(sel => { const c = $(sel); if (c) c.disabled = !!ticket; });
    if (bloc) bloc.style.display = ticket ? '' : 'none';
    if (code && !ticket) code.value = '';
    const cible = ticket ? code : $('#login-pass');
    if (cible) { try { cible.focus(); } catch (e) {} }
  };
  const direTropDeTentatives = res => fail(res.retry ? `Trop de tentatives, réessaie dans ${res.retry}s.` : 'Trop de tentatives, réessaie plus tard.');
  const soumettreLeCode = async () => {
    const code = ($('#login-code') ? $('#login-code').value : '').trim();
    if (!code) { aveuADeuxNoeuds(motDuSecondFacteur('code_manquant'), ''); return; }
    if (btn) { btn.disabled = true; btn.dataset._t = btn.textContent; btn.textContent = '...'; }
    let res;
    try { res = await doLoginMfa(ticketDuSecondFacteur, code); }
    catch (ex) { res = { ok: false, status: 0, msg: ex && ex.message }; }
    if (btn) { btn.disabled = false; btn.textContent = btn.dataset._t || 'Se connecter'; }
    if (res.ok) { location.reload(); return; }
    const cle = cleDuRefusDuSecondFacteur(res);
    // Le verrou, le frein et le code refusé ramènent au mot de passe : le ticket ne sert plus.
    if (res.status === 429 || cle === 'code_refuse') { poserLEtapeDuCode(''); const p = $('#login-pass'); if (p) p.value = ''; }
    if (cle) aveuADeuxNoeuds(motDuSecondFacteur(cle, res.retry), res.cause || '');
    else if (res.status === 429) direTropDeTentatives(res);
    else fail('Échec de connexion' + (res.msg ? ' : ' + res.msg : '') + (res.status ? ' (' + res.status + ')' : ''));
  };
  f.addEventListener('submit', async e => {
    e.preventDefault();
    if (err) err.hidden = true;
    if (ticketDuSecondFacteur) { await soumettreLeCode(); return; }
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
    // `P10.22-n` — le mot de passe est accepté et AUCUNE session n'est posée : l'étape du code s'ouvre.
    if (res.ticketDuSecondFacteur) { poserLEtapeDuCode(res.ticketDuSecondFacteur); return; }
    if (res.status === 429) direTropDeTentatives(res);
    else if (res.status === 401) fail('Identifiants invalides.');
    // `P10.20-b` — le refus NOMMÉ passe avant le message générique : les deux autres issues ci-dessus
    // sont des faits ÉTABLIS (trop de tentatives, identifiants faux), celle-ci ne l'est pas.
    else if (res.cause) avouerLeRefusNomme(res.cause);
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
    // `P11.6-c` — le catalogue des noms ATT&CK part EN MÊME TEMPS que /api/me (même identité de session) et
    // est attendu avant d'ouvrir l'app : chaque surface qui nomme une technique le trouve posé, sans second
    // rendu. En échec il ne bloque rien — le registre porte l'état, et les surfaces le disent à la place du nom.
    const catalogueAttack = chargerLeCatalogueAttack(api);
    fetchMe().then(async me => {
      if (me && me.user) {
        await catalogueAttack;
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

// `bindLoginForm` est exposée pour le harnais ESM (témoin 97 : le refus nommé du second facteur rendu
// par le chemin RÉEL de l'écran — le formulaire d'`index.html`, `doLogin`, et la boîte `#login-err` —
// et non par une copie). Elle est idempotente (`f._bound`) et n'a d'autre appelant applicatif
// qu'`initAuthGate`, juste au-dessus.
// `P10.22-n` — `motDuSecondFacteur` et `cleDuRefusDuSecondFacteur` partent pour le même harnais (témoin
// 108) : les faces se jugent sous les deux instances de langue, le discriminant dans les deux sens sur les
// statuts que le démon sert. Aucun usage applicatif hors de ce module.
export { initAuthGate, bindLoginForm, fetchMe, setAuthUI, showLogin, motDuSecondFacteur, cleDuRefusDuSecondFacteur };
