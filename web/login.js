// Écran de connexion (form-login), déconnexion et état d'authentification. Extrait d'`app.js` par déplacement
// pur ; la porte d'entrée — câblage du formulaire, du bouton de déconnexion, et le `GET /api/me` qui décide
// entre l'application et l'overlay — est exposée par `initAuthGate()`, appelée par `app.js` au point où ce bloc
// vivait (un module s'exécute à l'import, avant l'enveloppe `fetch` d'`app.js` qui pose CSRF et tenant).
// `multitenant.js` continue de lire `fetchMe` / `setAuthUI` via le ré-export d'`app.js`. N'importe pas `app.js`.
import { $, LANG, api, apiSend, applyRoleClass, causeNommeeParLeDemon, confirmModal, motDuRefusDuSecondFacteur, natureDeLaReponseHorsDemon, natureDuRefusDuSecondFacteur, phraseDuRefusDuDemon } from './core.js';
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
// `P10.25-p` — L'OUVERTURE REFUSÉE PAR LE DÉMON SE DIT : ELLE N'EST PAS UNE INVITE DE CONNEXION MUETTE.
// CE QUE LE DÉMON SERT (`P10.25-d`, daemon/src/auth.rs, `RefusDeLAnnuaire`) : derrière le SSO d'en-têtes, un nom que
// l'annuaire présente et que le démon ne prend pas est refusé sur TOUTE route gardée, `/api/me` comprise — 403 JSON
// `CAUSE_ANNUAIRE_NOM_DE_L_ADMINISTRATEUR_DE_CONFIGURATION` ou `CAUSE_ANNUAIRE_NOM_D_UN_COMPTE_A_MOT_DE_PASSE`, 503 JSON
// `CAUSE_ANNUAIRE_NOM_NON_VERIFIE`. CE QUE LA CONSOLE EN FAISAIT, MESURÉ AVANT CE LOT : `fetchMe` avale tout refus,
// et l'amorçage montrait l'écran de connexion SANS UN MOT — une invite trompeuse pour une personne que l'annuaire
// venait d'authentifier, et la cause (qui nomme le remède) jamais lue ; le 503, après ses deux réessais, finissait
// de même. La connexion par mot de passe EST un remède pour les deux 403 (le cookie de session est jugé AVANT les
// en-têtes de l'annuaire, `resolve_identity_ou_refus`) : l'écran reste donc offert, et le refus est dit AU-DESSUS,
// cause entière. Les ouvertures s'ancrent en tête, bornées par Unicode ; un autre refus nommé garde une face
// générique ; un 401 (texte nu) et une panne de transport gardent l'écran d'avant, sans phrase.
const OUVERTURES_DES_REFUS_DE_L_OUVERTURE = [
  ['annuaire_refuse', /^IDENTITÉ DE L'ANNUAIRE REFUSÉE(?![\p{L}\p{N}])/u],
  ['annuaire_non_verifie', /^IDENTITÉ DE L'ANNUAIRE NON VÉRIFIÉE(?![\p{L}\p{N}])/u],
];
// `P10.25-w` — la nature d'un refus de l'ANNUAIRE, nue : lue à l'ouverture (ci-dessous) et en cours de session (plus
// bas, `lireUneReponseDuTransport`). Rend '' pour toute autre cause, et pour l'absence de cause.
function natureDuRefusDeLAnnuaire(cause) {
  const c = String(cause || '').trim();
  const trouvee = OUVERTURES_DES_REFUS_DE_L_OUVERTURE.find(([, ouverture]) => ouverture.test(c));
  return trouvee ? trouvee[0] : '';
}
function cleDuRefusDeLOuverture(e) {
  const cause = e && e.causeDuDemon ? String(e.causeDuDemon).trim() : '';
  if (!cause) return '';
  return natureDuRefusDeLAnnuaire(cause) || 'ouverture_refusee';
}
// Un nœud À PART, posé au-dessus de `#login-err` : la boîte des refus du formulaire se réécrit à chaque essai, alors
// que ce refus-ci reste vrai tant qu'aucune session n'est ouverte. `data-refus-de-l-ouverture` porte la clé (marque
// de POSE pour le harnais).
// `P10.25-w` — `enCoursDeSession` : la session était ouverte, et c'est un refus de l'annuaire qui l'interrompt ; la
// face le dit (clé `session_interrompue_<nature>`), le nœud et sa cause entière sont les mêmes.
// `P10.26-n` — `sessionTerminee` : la session était ouverte, et `/api/me` la refuse en quatre cent un (cookie expiré,
// session révoquée) ; le refus est un TEXTE (`auth_guard`, « auth requise »), sans objet nommé : la cause est lue par
// `phraseDuRefusDuDemon`, qui tient les deux moules.
function peindreLeRefusDeLOuverture(e, enCoursDeSession, sessionTerminee) {
  const nature = sessionTerminee ? 'session_terminee' : cleDuRefusDeLOuverture(e);
  const cle = enCoursDeSession && (nature === 'annuaire_refuse' || nature === 'annuaire_non_verifie') ? 'session_interrompue_' + nature : nature;
  const err = $('#login-err'); if (!err || !err.parentNode) return;
  let noeud = $('#login-form [data-refus-de-l-ouverture]');
  if (!cle) { if (noeud) noeud.remove(); return; }
  if (!noeud) {
    noeud = document.createElement('div'); noeud.className = 'login-err'; noeud.setAttribute('role', 'alert');
    err.parentNode.insertBefore(noeud, err);
  }
  const dit = document.createElement('span'); dit.textContent = motDeLaConnexion(cle);
  const cause = sessionTerminee ? phraseDuRefusDuDemon(e) : String(e.causeDuDemon);
  noeud.replaceChildren(dit, document.createTextNode(' « ' + cause.trim() + ' »'));
  noeud.dataset.refusDeLOuverture = cle;
}
// `P10.23-c` — LES PHRASES PROPRES À CET ÉCRAN, FR ET EN CÔTE À CÔTE : aucune des deux langues ne part sans
// l'autre. Elles étaient écrites en français nu, hors du lexique — « Renseigne identifiant… », « Identifiants
// invalides. », « Trop de tentatives… » (deux formes, dont un gabarit que la garde du lexique ne pouvait pas
// voir) et « Échec de connexion : … », composée, qu'aucun relevé ne portait — et s'affichaient en français sous
// `LANG='en'`. Même mécanisme que `MOTS_DU_SECOND_FACTEUR` ci-dessous : la table, choisie par `LANG` au rendu.
// Les libellés FIXES de l'écran (`index.html`) restent au lexique, comme toute la page.
const MOTS_DE_LA_CONNEXION = {
  identifiants_manquants: {
    fr: 'Renseigne identifiant et mot de passe.',
    en: 'Enter your username and password.' },
  identifiants_invalides: {
    fr: 'Identifiants invalides.',
    en: 'Invalid credentials.' },
  trop_de_tentatives: {
    fr: 'Trop de tentatives, réessaie dans {delai}s.',
    en: 'Too many attempts, try again in {delai}s.' },
  trop_de_tentatives_sans_delai: {
    fr: 'Trop de tentatives, réessaie plus tard.',
    en: 'Too many attempts, try again later.' },
  echec_de_connexion: {
    fr: 'Échec de connexion',
    en: 'Sign-in failed' },
  echec_de_connexion_detaille: {
    fr: 'Échec de connexion : {detail}',
    en: 'Sign-in failed: {detail}' },
  bouton_se_connecter: {
    fr: 'Se connecter',
    en: 'Sign in' },
  // `P10.22-b`, sur la requête propre de cet écran : une réponse qui ne vient pas (lisiblement) du démon. Elle
  // collait le HTML d'une page de passerelle sous « Échec de connexion », et un deux cents sans le corps de
  // succès RECHARGEAIT l'écran, qui revenait vide.
  connexion_par_une_passerelle: {
    fr: "Connexion NON ÉTABLIE : une passerelle a répondu, pas le démon (service momentanément injoignable ?). Aucune session n'est confirmée — réessaie dans un instant.",
    en: 'Sign-in NOT ESTABLISHED: a gateway answered, not the daemon (service momentarily unreachable?). No session is confirmed — try again in a moment.' },
  connexion_sans_reponse_lisible: {
    fr: "Connexion NON ÉTABLIE : la réponse ne porte pas le succès de la connexion (corps illisible, vide ou incomplet). Aucune session n'est confirmée — réessaie ; si cela revient, un intermédiaire sert autre chose que la réponse du démon.",
    en: 'Sign-in NOT ESTABLISHED: the answer does not carry the sign-in success (unreadable, empty or incomplete body). No session is confirmed — try again; if this comes back, an intermediary serves something other than the daemon answer.' },
  // `P10.23-d` — l'échéance du ticket, dite PENDANT l'étape du code, et son expiration.
  echeance_du_ticket: {
    fr: 'Mot de passe accepté. Ce ticket de connexion expire dans {reste} : passé ce délai, il faudra reprendre depuis le mot de passe.',
    en: 'Password accepted. This sign-in ticket expires in {reste}: after that, you will have to start again from the password.' },
  ticket_expire: {
    fr: "Le ticket de connexion a EXPIRÉ : aucun code n'a été accepté dans le délai, et aucune session n'est ouverte. Reprends depuis le mot de passe.",
    en: 'The sign-in ticket has EXPIRED: no code was accepted in time, and no session is open. Start again from the password.' },
  // `P10.25-p` — l'ouverture de la console refusée par le démon, dite au-dessus du formulaire (voir `cleDuRefusDeLOuverture`).
  annuaire_refuse: {
    fr: "Identité de l'annuaire REFUSÉE par le démon : rien n'est servi sous ce nom. Si ce nom a un mot de passe (compte local ou administrateur de configuration), ce formulaire ouvre sa session. Le démon en nomme la cause —",
    en: 'Directory identity REFUSED by the daemon: nothing is served under this name. If this name has a password (local account or configuration administrator), this form opens its session. The daemon names the cause —' },
  annuaire_non_verifie: {
    fr: "Identité de l'annuaire NON VÉRIFIÉE : le démon n'a rien servi sous ce nom. Recharger la page pour réessayer. Le démon en nomme la cause —",
    en: 'Directory identity NOT VERIFIED: the daemon served nothing under this name. Reload the page to try again. The daemon names the cause —' },
  ouverture_refusee: {
    fr: 'Console NON ouverte : le démon a refusé et en nomme la cause —',
    en: 'Console NOT opened: the daemon refused and names the cause —' },
  // `P10.25-w` — la session ouverte, interrompue par un refus de l'annuaire (voir `lireUneReponseDuTransport`).
  session_interrompue_annuaire_refuse: {
    fr: "Session INTERROMPUE : l'identité que présente l'annuaire est REFUSÉE par le démon, et plus rien n'est servi sous ce nom — la console est masquée. Si ce nom a un mot de passe (compte local ou administrateur de configuration), ce formulaire ouvre sa session. Le démon en nomme la cause —",
    en: 'Session INTERRUPTED: the identity the directory presents is REFUSED by the daemon, and nothing more is served under this name — the console is hidden. If this name has a password (local account or configuration administrator), this form opens its session. The daemon names the cause —' },
  session_interrompue_annuaire_non_verifie: {
    fr: "Session INTERROMPUE : l'identité que présente l'annuaire n'a pas pu être VÉRIFIÉE, et le démon ne sert plus rien sous ce nom — la console est masquée. Recharger la page pour réessayer. Le démon en nomme la cause —",
    en: 'Session INTERRUPTED: the identity the directory presents could not be VERIFIED, and the daemon serves nothing more under this name — the console is hidden. Reload the page to try again. The daemon names the cause —' },
  // `P10.26-n` — la session ouverte, que le démon ne reconnaît plus (voir `lireUneReponseDuTransport`).
  session_terminee: {
    fr: "Session TERMINÉE : le démon ne reconnaît plus la session de ce navigateur (cookie expiré, ou session révoquée — il ne distingue pas les deux) et ne sert plus rien sous elle — la console est masquée. Ce formulaire ouvre une nouvelle session. Le démon en nomme la cause —",
    en: 'Session ENDED: the daemon no longer recognises the session of this browser (expired cookie, or revoked session — it does not tell the two apart) and serves nothing more under it — the console is hidden. This form opens a new session. The daemon names the cause —' },
};
// Les valeurs se posent par une fonction de remplacement : un détail servi qui contiendrait `$&` ou une accolade
// n'est jamais réinterprété.
function motDeLaConnexion(cle, valeurs = {}) {
  const face = LANG === 'en' ? MOTS_DE_LA_CONNEXION[cle].en : MOTS_DE_LA_CONNEXION[cle].fr;
  return face.replace(/\{(\w+)\}/g, (brut, nom) => (Object.prototype.hasOwnProperty.call(valeurs, nom) ? String(valeurs[nom]) : brut));
}
// `P10.23-d` — LA DURÉE DU TICKET, ET CE QUE CET ÉCRAN EN TIENT. `mfa_challenge_response` (daemon/src/handlers/
// idp.rs) signe le ticket pour trois cents secondes (le témoin 109 relit ce nombre dans le démon et rougit s'il
// change) ; la vérification le tient pour expiré dès que `now() >= exp`, `now()` en secondes ENTIÈRES — la durée
// réelle va donc de deux cent quatre-vingt-dix-neuf à trois cents secondes. L'écran compte depuis l'ENVOI du mot
// de passe (le ticket est signé après) et retire cette seconde : l'échéance qu'il dit n'est jamais plus tardive
// que celle du démon, elle la devance au plus d'un aller-retour et d'une seconde.
const DUREE_DU_TICKET_DU_SECOND_FACTEUR_S = 300;
const ECHEANCE_TENUE_APRES_L_ENVOI_MS = (DUREE_DU_TICKET_DU_SECOND_FACTEUR_S - 1) * 1000;
function resteLisible(ms) {
  const s = Math.max(0, Math.ceil(ms / 1000));
  const minutes = Math.floor(s / 60), secondes = s % 60;
  return minutes > 0 ? minutes + ' min ' + String(secondes).padStart(2, '0') + ' s' : secondes + ' s';
}
// `P10.22-b` — le corps d'un deux cents est LU, et un succès exige le corps de succès de la route : `{ok: true}`
// (`login_post`, `login_mfa_post`) ou `{mfa_required, ticket}`. Rend la nature du manque, jamais un succès.
const natureDuDeuxCentsSansSucces = (statut, corps) => natureDeLaReponseHorsDemon(statut, corps) || 'corps_sans_succes';
async function doLogin(user, pass) {
  // /api/login est PUBLIC + exempté de CSRF (pas encore de session). Retourne {ok:true,...} sur succès.
  // `P10.23-d` — l'instant de l'ENVOI : le ticket éventuel est signé après lui, son échéance ne le précède pas.
  const envoiDuPremierFacteur = Date.now();
  const r = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ user, pass }),
  });
  let corps = ''; try { corps = await r.text(); } catch (e) {}
  // `P10.22-n` — UN PREMIER FACTEUR ACCEPTÉ N'EST PAS UNE SESSION. Sur un compte à MFA active, `login_post`
  // rend deux cents `{mfa_required: true, ticket}` SANS poser de session (daemon/src/session.rs). Cet écran
  // lisait tout deux cents comme un succès et rechargeait : `/api/me` rendait quatre cent un, l'écran
  // revenait, VIDE et sans un mot — le second facteur n'était jamais demandé, et un compte à MFA ne pouvait
  // pas ouvrir de session par ce formulaire. Le corps du succès est donc LU.
  if (r.ok) {
    let lu = null; try { lu = JSON.parse(corps); } catch (e) {}
    if (lu && lu.mfa_required === true && typeof lu.ticket === 'string' && lu.ticket) return { ok: false, ticketDuSecondFacteur: lu.ticket, envoiDuPremierFacteur };
    if (lu && lu.ok === true) return { ok: true };
    return { ok: false, status: r.status, horsDemon: natureDuDeuxCentsSansSucces(r.status, corps) };
  }
  if (r.status === 429) {
    const ra = parseInt(r.headers.get('Retry-After') || '', 10);
    return { ok: false, status: 429, retry: Number.isFinite(ra) && ra > 0 ? ra : 0 };
  }
  // `P10.22-b` — une page de passerelle n'est ni un refus d'identifiants ni une cause : elle se nomme.
  const horsDemon = natureDeLaReponseHorsDemon(r.status, corps);
  if (horsDemon) return { ok: false, status: r.status, horsDemon };
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
  // (`causeNommeeParLeDemon`), qui rend '' dès que le corps n'est pas un objet JSON nommant sa cause.
  // Cet écran ne compose aucune phrase sur l'état du compte — il colle ce que le démon a écrit.
  // `P10.22-b` — la vraie panne de passerelle (HTML, cinq cent deux ou quatre, cinq cent trois vide) ne
  // retombe plus sur l'ancien message, qui collait son HTML : elle est nommée juste au-dessus.
  // `P10.24-f` — LE MÊME CHEMIN PORTE `CAUSE_EPOQUE_DU_COMPTE_NON_LUE` (`P10.23-l`, daemon/src/session.rs) : le
  // cinq cent trois que `/api/login` sert quand l'époque de révocation du compte n'a pas été lue — aucune session ni
  // ticket frappé, aucun échec compté. Il se peint en refus NOMMÉ, jamais en « Identifiants invalides » : le mot de
  // passe n'y est pas en cause. Aucune face propre n'est écrite pour lui ; le témoin 110 tient ce chemin pour lui.
  // ═══════════════════════════════════════════════════════════════════════════════════════════════
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
  // `P10.22-x` (démon) — même statut que le code refusé, autre fait : le TICKET est refusé (invalide, expiré ou
  // révoqué depuis l'acceptation du mot de passe) et le code n'a pas été examiné. La phrase ne l'accuse pas.
  ticket_refuse: {
    fr: "Ticket de connexion REFUSÉ, et ton code n'est PAS en cause : le ticket est invalide, expiré ou révoqué depuis l'acceptation du mot de passe. Aucune session n'est ouverte — reprends depuis le mot de passe. Le démon en nomme la cause —",
    en: 'Sign-in ticket REFUSED, and your code is NOT at fault: the ticket is invalid, expired or revoked since the password was accepted. No session is open — start again from the password. The daemon names the cause —' },
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
  if (res.status === 401) return nature === 'ticket_refuse' ? 'ticket_refuse' : 'code_refuse';
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
  let corps = ''; try { corps = await r.text(); } catch (e) {}
  // `P10.22-b` — tout deux cents rechargeait, corps lu ou non : une page de passerelle servie en deux cents
  // ramenait l'écran de connexion, vide. Le succès exige `{ok: true}`, le seul corps de succès de la route.
  if (r.ok) {
    let lu = null; try { lu = JSON.parse(corps); } catch (e) {}
    if (lu && lu.ok === true) return { ok: true };
    return { ok: false, status: r.status, horsDemon: natureDuDeuxCentsSansSucces(r.status, corps) };
  }
  const cause = causeNommeeParLeDemon(corps);
  if (r.status === 429) {
    // Le frein du second facteur et le verrou par adresse partagent le statut : la cause les sépare.
    const ra = parseInt(r.headers.get('Retry-After') || '', 10);
    return { ok: false, status: 429, retry: Number.isFinite(ra) && ra > 0 ? ra : 0, cause };
  }
  const horsDemon = natureDeLaReponseHorsDemon(r.status, corps);
  if (horsDemon) return { ok: false, status: r.status, horsDemon };
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
  // `P10.23-d` — L'ÉCHÉANCE, DITE AVANT QU'ELLE NE MORDE, ET UNE SEULE MINUTERIE, QUI NE SURVIT À RIEN. L'étape
  // n'annonçait pas l'expiration : un code présenté après elle revenait en « Code REFUSÉ », qui accusait le
  // code pour un ticket périmé. Le décompte est RECALCULÉ à chaque battement depuis l'horloge (un onglet en
  // arrière-plan espace ses battements, il ne les décale pas) ; il s'arrête à TOUTE sortie de l'étape — code
  // accepté (avant le rechargement), refus qui ramène au mot de passe, retour demandé, échéance, nouveau ticket.
  let echeanceDuTicket = 0;
  let minuterieDeLEcheance = null;
  const arreterLeDecompte = () => { if (minuterieDeLEcheance !== null) { clearInterval(minuterieDeLEcheance); minuterieDeLEcheance = null; } };
  const aveuADeuxNoeuds = (mot, cause) => {
    if (!err) return;
    const dit = document.createElement('span');
    dit.textContent = mot;
    if (cause) err.replaceChildren(dit, document.createTextNode(' « ' + String(cause).trim() + ' »'));
    else err.replaceChildren(dit);
    err.hidden = false;
  };
  const poserLEtapeDuCode = (ticket, envoiDuPremierFacteur) => {
    arreterLeDecompte();
    ticketDuSecondFacteur = ticket;
    const bloc = $('#login-code-lbl'), code = $('#login-code'), echeance = $('#login-code-echeance'), retour = $('#login-code-retour');
    ['#login-user', '#login-pass'].forEach(sel => { const c = $(sel); if (c) c.disabled = !!ticket; });
    if (bloc) bloc.style.display = ticket ? '' : 'none';
    if (retour) retour.hidden = !ticket;
    if (echeance && !ticket) { echeance.hidden = true; echeance.textContent = ''; }
    if (code && !ticket) code.value = '';
    echeanceDuTicket = ticket ? (Number.isFinite(envoiDuPremierFacteur) ? envoiDuPremierFacteur : Date.now()) + ECHEANCE_TENUE_APRES_L_ENVOI_MS : 0;
    const cible = ticket ? code : $('#login-pass');
    if (cible) { try { cible.focus(); } catch (e) {} }
    if (!ticket) return;
    direLEcheance();
    if (ticketDuSecondFacteur === ticket) minuterieDeLEcheance = setInterval(direLEcheance, 1000);
  };
  // Le ticket est tenu pour expiré à l'échéance : l'étape se referme d'elle-même, et le dit.
  const expirerLeTicket = () => {
    poserLEtapeDuCode('');
    const p = $('#login-pass'); if (p) p.value = '';
    fail(motDeLaConnexion('ticket_expire'));
  };
  const direLEcheance = () => {
    const reste = echeanceDuTicket - Date.now();
    if (reste <= 0) { expirerLeTicket(); return; }
    const echeance = $('#login-code-echeance');
    if (echeance) { echeance.textContent = motDeLaConnexion('echeance_du_ticket', { reste: resteLisible(reste) }); echeance.hidden = false; }
  };
  // `P10.23-d` — LE RETOUR EXPLICITE AU MOT DE PASSE. Hors d'un refus, l'étape du code n'offrait aucune sortie
  // (un compte erroné, un appareil d'authentification absent : il fallait recharger la page). Posé en propriété
  // et non en écouteur : un second câblage le REMPLACE au lieu de l'empiler.
  const retour = $('#login-code-retour');
  if (retour) retour.onclick = () => {
    poserLEtapeDuCode('');
    const p = $('#login-pass'); if (p) p.value = '';
    if (err) { err.hidden = true; err.replaceChildren(); }
  };
  const direTropDeTentatives = res => fail(res.retry ? motDeLaConnexion('trop_de_tentatives', { delai: res.retry }) : motDeLaConnexion('trop_de_tentatives_sans_delai'));
  const direLEchec = res => fail((res.msg ? motDeLaConnexion('echec_de_connexion_detaille', { detail: res.msg }) : motDeLaConnexion('echec_de_connexion')) + (res.status ? ' (' + res.status + ')' : ''));
  const direLaReponseHorsDemon = res => fail(motDeLaConnexion(res.horsDemon === 'page_de_passerelle' ? 'connexion_par_une_passerelle' : 'connexion_sans_reponse_lisible'));
  const rendreLeBouton = () => { if (btn) { btn.disabled = false; btn.textContent = btn.dataset._t || motDeLaConnexion('bouton_se_connecter'); } };
  const soumettreLeCode = async () => {
    // `P10.23-d` — une échéance passée (un onglet endormi n'a pas battu) ne part pas au démon : elle se dit.
    if (echeanceDuTicket && Date.now() >= echeanceDuTicket) { expirerLeTicket(); return; }
    const code = ($('#login-code') ? $('#login-code').value : '').trim();
    if (!code) { aveuADeuxNoeuds(motDuSecondFacteur('code_manquant'), ''); return; }
    if (btn) { btn.disabled = true; btn.dataset._t = btn.textContent; btn.textContent = '...'; }
    const ticketEnvoye = ticketDuSecondFacteur;
    let res;
    try { res = await doLoginMfa(ticketDuSecondFacteur, code); }
    catch (ex) { res = { ok: false, status: 0, msg: ex && ex.message }; }
    rendreLeBouton();
    if (res.ok) { arreterLeDecompte(); location.reload(); return; }
    // L'étape a été quittée pendant le vol (retour demandé, échéance) : ce qu'elle disait est déjà peint.
    if (ticketDuSecondFacteur !== ticketEnvoye) return;
    // `P10.22-b` — une réponse qui ne vient pas du démon n'accuse pas le code, et le ticket reste valable.
    if (res.horsDemon) { direLaReponseHorsDemon(res); return; }
    const cle = cleDuRefusDuSecondFacteur(res);
    // Le verrou, le frein, le code refusé et le ticket refusé ramènent au mot de passe : le ticket ne sert plus.
    if (res.status === 429 || cle === 'code_refuse' || cle === 'ticket_refuse') { poserLEtapeDuCode(''); const p = $('#login-pass'); if (p) p.value = ''; }
    if (cle) aveuADeuxNoeuds(motDuSecondFacteur(cle, res.retry), res.cause || '');
    else if (res.status === 429) direTropDeTentatives(res);
    else direLEchec(res);
  };
  f.addEventListener('submit', async e => {
    e.preventDefault();
    if (err) err.hidden = true;
    if (ticketDuSecondFacteur) { await soumettreLeCode(); return; }
    const user = ($('#login-user') ? $('#login-user').value : '').trim();
    const pass = $('#login-pass') ? $('#login-pass').value : '';
    if (!user || !pass) { fail(motDeLaConnexion('identifiants_manquants')); return; }
    if (btn) { btn.disabled = true; btn.dataset._t = btn.textContent; btn.textContent = '...'; }
    let res;
    try { res = await doLogin(user, pass); }
    catch (ex) { res = { ok: false, status: 0, msg: ex && ex.message }; }
    rendreLeBouton();
    if (res.ok) {
      // succès : cookies plume_session + plume_csrf posés -> rechargement = boot AUTHENTIFIÉ propre
      // (route()/refresh()/loaders re-exécutés avec une session valide, zéro état partiel résiduel).
      location.reload();
      return;
    }
    // `P10.22-n` — le mot de passe est accepté et AUCUNE session n'est posée : l'étape du code s'ouvre.
    if (res.ticketDuSecondFacteur) { poserLEtapeDuCode(res.ticketDuSecondFacteur, res.envoiDuPremierFacteur); return; }
    if (res.status === 429) direTropDeTentatives(res);
    // `P10.22-b` — une réponse de passerelle, ou un deux cents sans le succès de la route, n'est pas un refus
    // d'identifiants : elle se nomme, sans coller son corps.
    else if (res.horsDemon) direLaReponseHorsDemon(res);
    else if (res.status === 401) fail(motDeLaConnexion('identifiants_invalides'));
    // `P10.20-b` — le refus NOMMÉ passe avant le message générique : les deux autres issues ci-dessus
    // sont des faits ÉTABLIS (trop de tentatives, identifiants faux), celle-ci ne l'est pas.
    else if (res.cause) avouerLeRefusNomme(res.cause);
    else direLEchec(res);
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
// `P10.25-w` — UN REFUS DE L'ANNUAIRE EN COURS DE SESSION : UNE FACE, PAS UN PANNEAU PAR REQUÊTE.
// CE QUE LE DÉMON SERT (`P10.25-d`, daemon/src/auth.rs) : le jugement du nom que présente l'annuaire est relu à
// CHAQUE requête, sans cache. Une session ouverte par l'annuaire (SSO d'en-têtes, sans cookie) est donc refusée en
// COURS de route dès que le nom devient celui d'un compte à mot de passe (un administrateur pose un mot de passe sur
// sa ligne) ; une session par cookie l'est à l'expiration du cookie, derrière le même mandataire ; la lecture qui
// juge peut aussi échouer (503). Toute route gardée rend alors le même refus.
// CE QUE LA CONSOLE EN FAISAIT, MESURÉ AVANT CE LOT (témoin 114) : chaque surface peignait SA copie — `fetchInto`
// le JSON brut coupé à deux cents caractères, un panneau de tableau de bord la cause entière derrière « Erreur : »,
// la liste des comptes se repliait EN SILENCE sur « non administrateur » (la section disparaissait) ; le cinq cent
// trois n'était dit NULLE PART : `api()` et les panneaux le remplacent par « Service momentanément indisponible »,
// et la cause — qui dit que rien n'est servi — ne sortait pas.
// LE GESTE : l'enveloppe du transport (`web/app.js`) passe ici chaque réponse ; un 403 ou un 503 dont la cause
// NOMMÉE ouvre sur un refus de l'annuaire, reçu PENDANT une session, fait REJUGER la session par `/api/me` — une
// seule fois à la fois, quel que soit le nombre de requêtes refusées. `/api/me` refusé à son tour par l'annuaire
// (après les deux réessais d'`api()` pour un 503) : la session est close côté console et l'écran de connexion
// revient, recouvrant la console, avec la cause ENTIÈRE et le remède au-dessus du formulaire — la connexion par mot
// de passe est un remède réel, le cookie étant jugé avant les en-têtes. `/api/me` servi : un refus passager, rien
// n'est dit ici (chaque surface garde son propre aveu). La face est unique parce que l'écran l'est : il recouvre
// toute la console.
// `P10.26-n` — UN QUATRE CENT UN EN COURS DE SESSION : LA MÊME FACE UNIQUE, PAR LE MÊME MÉCANISME.
// CE QUE LE DÉMON SERT (`auth_guard`, daemon/src/auth.rs) : une requête dont le cookie de session n'est plus reconnu
// (expiré, révoqué par un changement de mot de passe ou une suppression de compte) rend quatre cent un en TEXTE,
// « auth requise », sur TOUTE route gardée. CE QUE LA CONSOLE EN FAISAIT, MESURÉ AVANT CE LOT (témoin 119n) : chaque
// surface peignait sa copie (« erreur : 401 auth requise » dans chaque `fetchInto`, le panneau et la liste chacun la
// sienne), l'auto-rafraîchissement continuait de frapper, et l'écran de connexion n'était offert qu'au rechargement.
// UN QUATRE CENT UN N'EST PAS TOUJOURS LA SESSION : `mfa_disable` et l'activation du second facteur rendent quatre
// cent un sur un CODE refusé, session intacte (daemon/src/handlers/idp.rs). Le quatre cent un ne décide donc rien
// seul : il fait rejuger la session par `/api/me`, une seule fois à la fois, comme un refus de l'annuaire ; seul un
// quatre cent un de `/api/me` CLÔT la session. Hors session (le premier chargement, l'écran de connexion), rien n'est
// rejugé : c'est `initAuthGate` qui dit ce qu'il lit, inchangé. Le rejugement passe lui-même par l'enveloppe, et ne se
// relance pas (`rejugementDeLaSessionEnCours`) : aucune boucle.
let rejugementDeLaSessionEnCours = false;
// Une session que `/api/me` vient de CONFIRMER n'est pas rejugée aussitôt par les refus encore en vol (les réessais
// d'un cinq cent trois passager, qui arrivent après la confirmation) : sans ce délai, chacun relirait `/api/me`.
const DELAI_SANS_REJUGEMENT_APRES_UNE_SESSION_CONFIRMEE_MS = 5000;
let sessionConfirmeeA = 0;
function rejugerLaSessionApresUnRefus() {
  // Une copie lue APRÈS la face posée ne rejuge plus rien : la session est déjà close côté console.
  if (rejugementDeLaSessionEnCours || !(S.AUTH && S.AUTH.user)) return;
  if (Date.now() - sessionConfirmeeA < DELAI_SANS_REJUGEMENT_APRES_UNE_SESSION_CONFIRMEE_MS) return;
  rejugementDeLaSessionEnCours = true;
  api('/me').then(() => { rejugementDeLaSessionEnCours = false; sessionConfirmeeA = Date.now(); }, refus => {
    rejugementDeLaSessionEnCours = false;
    const deLAnnuaire = !!natureDuRefusDeLAnnuaire(refus && refus.causeDuDemon);
    const sessionTerminee = !deLAnnuaire && !!refus && refus.statutDuRefus === 401;   // `P10.26-n`
    if (!deLAnnuaire && !sessionTerminee) return;                           // une panne, un autre refus : la session n'est pas jugée close
    if (!(S.AUTH && S.AUTH.user)) return;                                  // l'écran est déjà revenu
    S.AUTH = null; setAuthUI(); showLogin(true);
    peindreLeRefusDeLOuverture(refus, true, sessionTerminee);
  });
}
// Lue par l'enveloppe du transport pour CHAQUE réponse, avant qu'elle ne soit rendue à son appelant : ne lit qu'une
// COPIE du corps (l'appelant garde le sien), ne jette jamais, et ne fait rien hors d'une session ouverte — à
// l'ouverture, c'est `initAuthGate` qui dit le refus de `/api/me`.
function lireUneReponseDuTransport(reponse) {
  if (!reponse) return;
  if (!(S.AUTH && S.AUTH.user) || rejugementDeLaSessionEnCours) return;
  // `P10.26-n` — un quatre cent un fait rejuger la session ; son corps n'est pas lu (le jugement est celui de `/api/me`).
  if (reponse.status === 401) { rejugerLaSessionApresUnRefus(); return; }
  if (reponse.status !== 403 && reponse.status !== 503) return;
  if (typeof reponse.clone !== 'function') return;
  let copie;
  try { copie = reponse.clone(); } catch (e) { return; }
  Promise.resolve().then(() => copie.text()).then(corps => {
    if (natureDuRefusDeLAnnuaire(causeNommeeParLeDemon(corps))) rejugerLaSessionApresUnRefus();
  }, () => {});
}
function initAuthGate() {
    bindLoginForm();
    const lo = $('#logout'); if (lo && !lo._bound) { lo._bound = true; lo.onclick = doLogout; }
    // `P11.6-c` — le catalogue des noms ATT&CK part EN MÊME TEMPS que /api/me (même identité de session) et
    // est attendu avant d'ouvrir l'app : chaque surface qui nomme une technique le trouve posé, sans second
    // rendu. En échec il ne bloque rien — le registre porte l'état, et les surfaces le disent à la place du nom.
    const catalogueAttack = chargerLeCatalogueAttack(api);
    // `P10.25-p` — le refus éventuel de `/api/me` est GARDÉ (`fetchMe` le jette), pour être dit au-dessus du formulaire.
    api('/me').then(me => ({ me, refus: null }), refus => ({ me: null, refus })).then(async ({ me, refus }) => {
      if (me && me.user) {
        await catalogueAttack;
        S.AUTH = me; setAuthUI(); applyRoleClass(me.role); showLogin(false);   // SSO/cookie/démo : app directe
        prefsInit();      // #62 — charge les préférences self-scoped du compte (favoris + réglages par vue) puis rejoue les callbacks
        loadBulletin();   // #51 DAY-2 OPS — bandeau MOTD (aucun bulletin -> reste caché ; invariant mode 0)
        initAiAssist();   // #16 — assistant IA (NL→GXQL) dans Explore : révélé UNIQUEMENT si /api/ai/status = enabled (feature off -> reste caché)
        // #2c switcher tenant, PUIS #2d sélecteur d'environnement (résolu APRÈS le tenant : les env sont
        // cloisonnés par tenant). initEnvironments(true) : si un env persisté est restauré, il recharge la vue.
        initTenants().then(() => initEnvironments(true)).catch(() => { try { initEnvironments(true); } catch (e) {} });
      } else { S.AUTH = null; setAuthUI(); showLogin(true); peindreLeRefusDeLOuverture(refus); document.documentElement.classList.add('app-ready'); }   // 401 : écran de login (overlay au-dessus ; on révèle <main> pour ne pas le laisser bloqué masqué)
    });
}

// `bindLoginForm` est exposée pour le harnais ESM (témoin 97 : le refus nommé du second facteur rendu
// par le chemin RÉEL de l'écran — le formulaire d'`index.html`, `doLogin`, et la boîte `#login-err` —
// et non par une copie). Elle est idempotente (`f._bound`) et n'a d'autre appelant applicatif
// qu'`initAuthGate`, juste au-dessus.
// `P10.22-n` — `motDuSecondFacteur` et `cleDuRefusDuSecondFacteur` partent pour le même harnais (témoin
// 108) : les faces se jugent sous les deux instances de langue, le discriminant dans les deux sens sur les
// statuts que le démon sert. Aucun usage applicatif hors de ce module.
// `P10.23-c` — `motDeLaConnexion` part pour le témoin 109, au même titre : les phrases de l'écran s'y jugent
// sous les deux instances de langue, contre ce que le formulaire réel peint.
// `P10.25-p` — `cleDuRefusDeLOuverture` part pour le témoin 113 : la nature d'un refus de l'ouverture, dans les deux sens.
// `P10.25-w` — `lireUneReponseDuTransport` part pour l'enveloppe du transport (`web/app.js`), son seul appelant
// applicatif ; `natureDuRefusDeLAnnuaire` pour le témoin 114.
export { initAuthGate, bindLoginForm, fetchMe, setAuthUI, showLogin, motDuSecondFacteur, cleDuRefusDuSecondFacteur, motDeLaConnexion, cleDuRefusDeLOuverture, natureDuRefusDeLAnnuaire, lireUneReponseDuTransport };
