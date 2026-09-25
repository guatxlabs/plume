// idp.js — IdP natif (#44) : UI admin des fournisseurs fédérés (OIDC/LDAP) + MFA TOTP self-service.
// Comportement additif : tant qu'aucun fournisseur n'est activé et qu'aucune MFA n'est enrôlée, rien ne
// change côté auth. Anti-XSS : tout texte via textContent/esc ; le secret (client_secret / bind pw) est un
// champ password, JAMAIS réaffiché, ré-envoyé UNIQUEMENT s'il est re-saisi (omis = conservé côté serveur).
// La vraie garde reste SERVEUR (/api/idp/* admin-only ; /api/mfa/* borné à au.name).
import { $, LANG, api, apiSend, unDeuxCentsSansCorpsLisible, confirmWithConsequence, disclosure, effacerLeRefusDUnGeste, fmtTs, modal, motDuRefusDuSecondFacteur, muted, natureDuRefusDuSecondFacteur, peindreLeRefusDUnGeste, phraseDuRefusDuDemon, puitsDuRefusDUnGeste, noeudDuRefusDUneLecture, phraseDuRefusDUneLecture, toast, withBusy, faceDansLaLangue } from './core.js';
import { enabledSwitch } from './producer_ui.js';
import { uiIsAdmin } from './multitenant.js';

// ---------------------------------------------------------------------------------------------------
// Fournisseurs d'identité (OIDC / LDAP) — admin-only.
// ---------------------------------------------------------------------------------------------------

const KIND_LABEL = { oidc: 'OIDC', ldap: 'LDAP / AD', saml: 'SAML (à venir)' };
const MOTS_DE_LA_MISE_A_JOUR_D_UN_FOURNISSEUR = { fr: '  · maj ', en: '  · updated ' };
const motDeLaMiseAJourDUnFournisseur = () => (LANG === 'en' ? MOTS_DE_LA_MISE_A_JOUR_D_UN_FOURNISSEUR.en : MOTS_DE_LA_MISE_A_JOUR_D_UN_FOURNISSEUR.fr);

// `P10.26-q` — LE REFUS D'UN GESTE SUR UN FOURNISSEUR D'IDENTITÉ RESTE SOUS LES YEUX. « FOURNISSEUR D'IDENTITÉ
// INCHANGÉ » (le `COMMIT` refusé, `P10.25-e`) dit que celui qui était actif l'est toujours et AUTHENTIFIE ENCORE —
// une porte d'entrée qu'on croyait fermée. Mesuré avant ce lot : le formulaire écrivait « erreur : 503 {"error":… »
// coupé à deux cents caractères dans sa ligne d'actions ; le retrait, un avis qui s'efface ; la bascule, « Bascule
// refusée : 503 {"error":… ». Le puits, UN pour ce panneau, est posé avant la liste — sous le formulaire ouvert —,
// hors de ce que `loadIdpProviders` repeint ; la forme est celle du point commun (`peindreLeRefusDUnGeste`, core.js).
function puitsDesFournisseurs() { const liste = $('#idp-list'); return liste ? puitsDuRefusDUnGeste(liste.parentNode, 'fournisseurs_d_identite', liste) : null; }

export async function loadIdpProviders() {
  const wrap = $('#idp-list'); if (!wrap) return;
  // P11.4-a : « + Fournisseur » passe par le dépli partagé (second clic = repli, état visible sur le bouton).
  const btn = $('#idp-new'); const fh = $('#idp-form-host');
  if (btn && fh && !btn.dataset.wired) { btn.dataset.wired = '1'; disclosure(btn, fh, { isOpen: () => !!fh.querySelector('#idp-form') && !fh.querySelector('#idp-form').dataset.editing, open: () => openIdpForm(null), close: () => fh.replaceChildren() }); }
  if (!uiIsAdmin()) { wrap.replaceChildren(muted('réservé à l\'administrateur.')); return; }
  let list = [];
  try { list = await api('/idp/providers'); }
  catch (e) {
    // api() porte le statut à côté du message (`statutDuRefus`) : le 501 (mode multi-tenant) garde son message dédié.
    // `P10.29-g` — tout autre refus, la face nommée d'une lecture non servie (plus « erreur : » + le message brut).
    if (e && e.statutDuRefus === 501) { wrap.replaceChildren(muted('IdP réservé au mode mono-tenant.')); return; }
    wrap.replaceChildren(noeudDuRefusDUneLecture(e)); return;
  }
  if (!Array.isArray(list) || !list.length) {
    wrap.replaceChildren(muted('aucun fournisseur — clique « + Fournisseur » pour brancher un IdP OIDC ou LDAP. Tant qu\'aucun n\'est activé, l\'auth existante est inchangée.'));
    return;
  }
  const frag = document.createDocumentFragment();
  for (const p of list) frag.appendChild(providerRow(p));
  wrap.replaceChildren(frag);
}

function providerRow(p) {
  const row = document.createElement('div');
  row.className = 'idp-row'; row.style.cssText = 'display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--bd)';
  const name = document.createElement('b'); name.textContent = p.name;
  const kind = document.createElement('span'); kind.className = 'muted'; kind.style.fontSize = '12px';
  kind.textContent = KIND_LABEL[p.kind] || p.kind;
  const meta = document.createElement('span'); meta.className = 'muted'; meta.style.cssText = 'font-size:11px;margin-left:auto';
  const issuer = (p.config && (p.config.issuer || p.config.url)) || '';
  // `P10.27-s` — l'émetteur est posé TEL QUEL dans un texte : `esc()` y affichait `&amp;`, `&quot;`, `&lt;` (témoin 117s),
  // un texte n'étant jamais analysé comme du balisage. `P10.27-t` — la date de mise à jour a ses deux faces.
  meta.textContent = (p.has_secret ? '🔑 ' : '') + issuer + (p.updated ? motDeLaMiseAJourDUnFournisseur() + fmtTs(p.updated) : '');
  // COMMUTATEUR PARTAGÉ (`P11.13-c`) : ce que la bascule arme, c'est une PORTE D'ENTRÉE — des comptes
  // extérieurs peuvent ouvrir une session par ce fournisseur. Le bouton « Activer / Désactiver » ne le
  // disait pas. `enabledSwitch` écrit la conséquence à côté de l'interrupteur dans les deux états, porte
  // l'état par le mot (ON / OFF) — ce que la pastille disait — et rétablit la case si le serveur refuse.
  const toggle = enabledSwitch({
    enabled: !!p.enabled, name: p.name, allowed: true, confirmOnEnable: true,
    consequence: 'les comptes de cet annuaire ' + (KIND_LABEL[p.kind] || p.kind) + ' peuvent ouvrir une session sur plume, avec le rôle que leur groupe leur donne ; OFF, plus aucune session ne s\'ouvre par ce fournisseur',
    onToggle: (next) => { effacerLeRefusDUnGeste(puitsDesFournisseurs()); return apiSend('/idp/providers/' + p.id, 'POST', { enabled: next }); },
    onRefus: (e) => peindreLeRefusDUnGeste(puitsDesFournisseurs(), e),
  });
  const edit = mkBtn('Éditer', () => openIdpForm(p));
  const del = mkBtn('Supprimer', async () => {
    // P11.5-b : DELETE = route sensible -> la confirmation partagée nomme la conséquence.
    if (!(await confirmWithConsequence('Supprimer le fournisseur « ' + p.name + ' »', 'les comptes qui se connectent par ce fournisseur ne pourront plus ouvrir de session ; le secret associé est effacé et ne se restaure pas.', { okText: 'Supprimer' }))) return;
    const puits = puitsDesFournisseurs(); effacerLeRefusDUnGeste(puits);
    try { await apiSend('/idp/providers/' + p.id, 'DELETE'); }
    catch (e) { peindreLeRefusDUnGeste(puits, e); return; }
    toast('supprimé', 'ok'); loadIdpProviders();
  });
  del.classList.add('btn-danger');
  row.append(toggle, name, kind, meta, edit, del);
  return row;
}

function mkBtn(label, fn) {
  const b = document.createElement('button'); b.type = 'button'; b.className = 'btn btn-sm'; b.textContent = label; b.onclick = fn; return b; // P11.4-b : classe partagée
}

// Formulaire dynamique de fournisseur (create ou edit). Les champs changent selon le kind.
function openIdpForm(existing) {
  const host = $('#idp-form-host'); if (!host) return;
  const cfg = (existing && existing.config) || {};
  const form = document.createElement('form'); form.className = 'ruleform'; form.id = 'idp-form'; // P11.4-b : le cadre est celui de .ruleform (la bordure en dur citait une variable inexistante)
  if (existing) form.dataset.editing = String(existing.id);
  const mkInput = (id, ph, val, type) => {
    const l = document.createElement('label'); l.style.cssText = 'display:block;margin:4px 0';
    l.append(document.createTextNode(ph + ' '));
    const i = document.createElement('input'); i.id = id; i.placeholder = ph; if (type) i.type = type;
    i.autocomplete = 'off'; i.spellcheck = false; if (val != null) i.value = val;
    i.style.cssText = 'width:100%;box-sizing:border-box'; l.appendChild(i); return { l, i };
  };
  const title = document.createElement('h3'); title.style.cssText = 'margin:0 0 6px;font-size:14px';
  title.textContent = existing ? faceDansLaLangue({ fr: 'Éditer {nom}', en: 'Edit {nom}' }, { nom: existing.name }) : 'Nouveau fournisseur';   // `P10.29-c`
  form.appendChild(title);

  // nom + kind (non modifiables en édition).
  const nameF = mkInput('idpf-name', 'nom (a-z, . _ -)', existing ? existing.name : '');
  if (existing) nameF.i.disabled = true;
  const kindSel = document.createElement('select'); kindSel.id = 'idpf-kind';
  for (const k of ['oidc', 'ldap']) { const o = document.createElement('option'); o.value = k; o.textContent = KIND_LABEL[k]; kindSel.appendChild(o); }
  kindSel.value = existing ? existing.kind : 'oidc';
  if (existing) kindSel.disabled = true;
  const kindLbl = document.createElement('label'); kindLbl.style.cssText = 'display:block;margin:4px 0'; kindLbl.append('type ', kindSel);
  form.append(nameF.l, kindLbl);

  const fields = document.createElement('div');
  form.appendChild(fields);
  const renderFields = () => {
    fields.replaceChildren();
    if (kindSel.value === 'oidc') {
      fields.append(
        mkInput('idpf-issuer', 'issuer (ex https://accounts.google.com)', cfg.issuer || '').l,
        mkInput('idpf-client', 'client_id', cfg.client_id || '').l,
        mkInput('idpf-redirect', 'redirect_uri (…/api/auth/oidc/callback)', cfg.redirect_uri || '').l,
        mkInput('idpf-scopes', 'scopes (défaut: openid profile email groups)', cfg.scopes || '').l,
        mkInput('idpf-groupclaim', 'group_claim (défaut: groups)', cfg.group_claim || '').l,
        mkInput('idpf-secret', 'client_secret (laisser vide = inchangé)', '', 'password').l,
      );
    } else {
      fields.append(
        mkInput('idpf-url', 'url (ldap://host:389 ou ldaps://host:636)', cfg.url || '').l,
        mkInput('idpf-userdn', 'user_dn_template (ex uid={user},ou=people,dc=ex,dc=com)', cfg.user_dn_template || '').l,
        mkInput('idpf-userbase', 'user_base_dn (si recherche)', cfg.user_base_dn || '').l,
        mkInput('idpf-userfilter', 'user_filter (ex (sAMAccountName={user}))', cfg.user_filter || '').l,
        mkInput('idpf-binddn', 'bind_dn (compte de service, optionnel)', cfg.bind_dn || '').l,
        mkInput('idpf-groupattr', 'group_attr (défaut: memberOf)', cfg.group_attr || '').l,
        mkInput('idpf-admingrp', 'admin_group (DN/nom)', cfg.admin_group || '').l,
        mkInput('idpf-editgrp', 'editor_group', cfg.editor_group || '').l,
        mkInput('idpf-viewgrp', 'viewer_group', cfg.viewer_group || '').l,
        mkInput('idpf-bindpw', 'bind password (laisser vide = inchangé)', '', 'password').l,
      );
    }
  };
  kindSel.onchange = renderFields; renderFields();

  const enLbl = document.createElement('label'); enLbl.style.cssText = 'display:block;margin:6px 0';
  const en = document.createElement('input'); en.type = 'checkbox'; en.id = 'idpf-enabled'; en.checked = existing ? !!existing.enabled : false;
  enLbl.append(en, ' activé');
  form.appendChild(enLbl);

  const actions = document.createElement('div'); actions.className = 'rf-actions';
  const save = document.createElement('button'); save.type = 'submit'; save.className = 'btn-primary'; save.textContent = existing ? 'Enregistrer' : 'Créer'; // P11.4-b
  const cancel = document.createElement('button'); cancel.type = 'button'; cancel.className = 'btn'; cancel.textContent = 'Annuler'; cancel.onclick = () => host.replaceChildren();
  actions.append(save, cancel); form.appendChild(actions);

  form.onsubmit = async (e) => {
    e.preventDefault();
    const v = (id) => { const el = $('#' + id); return el ? el.value.trim() : ''; };
    const kind = kindSel.value;
    let config, secret;
    if (kind === 'oidc') {
      config = { issuer: v('idpf-issuer'), client_id: v('idpf-client'), redirect_uri: v('idpf-redirect'), scopes: v('idpf-scopes'), group_claim: v('idpf-groupclaim') };
      secret = v('idpf-secret');
    } else {
      config = {
        url: v('idpf-url'), user_dn_template: v('idpf-userdn'), user_base_dn: v('idpf-userbase'), user_filter: v('idpf-userfilter'),
        bind_dn: v('idpf-binddn'), group_attr: v('idpf-groupattr'), admin_group: v('idpf-admingrp'), editor_group: v('idpf-editgrp'), viewer_group: v('idpf-viewgrp'),
      };
      secret = v('idpf-bindpw');
    }
    // n'inclut le secret QUE s'il est saisi (vide = conserver côté serveur).
    const body = { config, enabled: en.checked };
    if (secret) body.secret = secret;
    // `P11.13-c` : CE FORMULAIRE ARME. `body.enabled` part avec l'enregistrement — un fournisseur d'identité
    // enregistré « activé » est une porte d'entrée ouverte, et l'utilisateur ne le voyait qu'après coup. La
    // conséquence est donc nommée AVANT le geste, dans les deux sens ; le formulaire reste ouvert si on refuse.
    if (!(await confirmWithConsequence(
      existing ? 'Enregistrer le fournisseur « ' + existing.name + ' »' : 'Créer le fournisseur « ' + v('idpf-name') + ' »',
      en.checked
        ? 'ce fournisseur sera ACTIF : les comptes de son annuaire pourront ouvrir une session sur plume, avec le rôle que leur groupe leur donne.'
        : 'ce fournisseur sera enregistré INACTIF : personne ne pourra ouvrir de session par lui tant qu\'il n\'est pas activé depuis la liste.',
      { okText: 'Enregistrer' }))) return;
    const puits = puitsDesFournisseurs(); effacerLeRefusDUnGeste(puits);
    try {
      await withBusy(save, async () => {
        if (existing) { await apiSend('/idp/providers/' + existing.id, 'POST', body); }
        else { body.name = v('idpf-name'); body.kind = kind; await apiSend('/idp/providers', 'POST', body); }
      });
    } catch (err) { peindreLeRefusDUnGeste(puits, err); return; }   // le formulaire reste ouvert, sa saisie gardée
    toast('enregistré', 'ok'); host.replaceChildren(); loadIdpProviders();
  };
  host.replaceChildren(form);
}

// ---------------------------------------------------------------------------------------------------
// MFA TOTP self-service — tout compte authentifié (opère sur au.name côté serveur).
// ---------------------------------------------------------------------------------------------------

// `P10.20-b` — LE STATUT DU SECOND FACTEUR N'A PAS ÉTÉ LU, ET AUCUN GESTE NE S'Y APPUIE. Depuis que
// `mfa_status` et `mfa_enroll` refusent en 503 nommé au lieu de servir `{enrolled:false, enabled:false}`
// (daemon/src/handlers/idp.rs), la console ne peut plus lire « inactive » sur une panne de lecture — mais
// « erreur : <message> » ne le disait pas non plus, et laissait « Activer la MFA » cliquable. Le drapeau
// est posé par la charge et LU par le geste d'enrôlement, qui vit hors d'elle : c'est le seul lien entre
// un statut non lu et l'écriture qu'on poserait par-dessus (grammaire de `P11.4-l`).
let STATUT_MFA_NON_LU = false;
// LE MOTIF DU REFUS EST ÉCRIT DEUX FOIS, EN TOUTES LETTRES, AU SURVOL DU BOUTON ET AU CLIC REFUSÉ — le
// MÊME littéral aux deux endroits, jamais deux formulations d'un même refus. Il est écrit AU PUITS et non
// derrière une constante : une phrase passée en argument d'un aide tombe hors du regard de la garde du
// lexique, donc hors de l'anglais. Il dit ce que le geste FERAIT, pas seulement qu'il est refusé.

// L'aveu à deux nœuds du statut : la phrase est un nœud texte ENTIER (donc traduisible), la cause SERVIE
// par le démon est collée dans un SECOND nœud. `hote` est `#mfa-status` à la charge, `#mfa-enroll` au
// geste refusé — le même aveu, jamais deux rédactions.
function avouerLeStatutMfaNonLu(hote, cause) {
  const aveu = document.createElement('div'); aveu.className = 'bad'; aveu.style.cssText = 'margin:0;font-size:12px';
  const dit = document.createElement('span');
  dit.textContent = 'Statut de double authentification NON LU : le démon a refusé et en nomme la cause —';
  aveu.append(dit, ' « ' + String(cause || '').trim() + ' »');
  hote.replaceChildren(aveu);
}

export async function loadMfa() {
  const status = $('#mfa-status'); const actions = $('#mfa-actions'); const enroll = $('#mfa-enroll');
  if (!status || !actions) return;
  actions.replaceChildren(); if (enroll) { enroll.hidden = true; enroll.replaceChildren(); }
  STATUT_MFA_NON_LU = false;
  let st;
  try { st = await api('/mfa/status'); }
  catch (e) {
    if (e && e.statutDuRefus === 501) { status.textContent = 'MFA réservée au mode mono-tenant.'; return; }
    // `P10.20-b` — LE REFUS NOMMÉ EST RENDU COMME UN REFUS NOMMÉ. `api()` porte la phrase du démon à côté
    // de son message (`causeDuDemon`, core.js) : sans elle, un 503 se peignait « Service momentanément
    // indisponible », c'est-à-dire une panne de passerelle là où le démon dit précisément QUOI n'a pas été
    // lu. Le bouton d'enrôlement reste offert mais INERTE et motivé : l'absence du bouton se lirait comme
    // « ce compte ne peut pas enrôler », qui est encore une affirmation que personne n'a établie.
    const cause = (e && e.causeDuDemon) || '';
    if (cause) {
      STATUT_MFA_NON_LU = true;
      avouerLeStatutMfaNonLu(status, cause);
      const refuse = mkBtn('Activer la MFA', () => startEnroll());
      refuse.setAttribute('aria-disabled', 'true');
      refuse.title = "Le statut de double authentification de ce compte n'a PAS été lu : lancer un enrôlement ici reposerait une graine TOTP neuve avec le second facteur désarmé, par-dessus la MFA peut-être ACTIVE que cette lecture n'a pas pu rendre — le démon refuse déjà l'écriture, et ce bouton ne doit pas la promettre.";
      actions.replaceChildren(refuse);
      return;
    }
    status.textContent = phraseDuRefusDUneLecture(e); return;   // `P10.29-g`
  }
  if (st && st.enabled) {
    status.textContent = '✓ Double authentification ACTIVE sur ce compte.';
    const dis = mkBtn('Désactiver la MFA', () => disableMfa());
    actions.replaceChildren(dis);
  } else {
    status.textContent = 'Double authentification inactive. Active-la pour exiger un code TOTP à la connexion.';
    const start = mkBtn('Activer la MFA', () => startEnroll());
    actions.replaceChildren(start);
  }
}

async function startEnroll() {
  const enroll = $('#mfa-enroll'); if (!enroll) return;
  // `P10.20-b` — LE GESTE PROMIS EST REFUSÉ, ET IL LE DIT. Le bouton porte déjà la marque accessible de
  // l'inertie et sa raison ; seul ce point-ci peut EMPÊCHER l'appel, et la MÊME phrase est écrite aux deux
  // endroits. Le démon refuserait de toute façon (503 nommé) : ce qui se joue ici est de ne pas présenter
  // comme applicable un geste qui désarmerait un second facteur si la garde tombait.
  if (STATUT_MFA_NON_LU) { toast("Le statut de double authentification de ce compte n'a PAS été lu : lancer un enrôlement ici reposerait une graine TOTP neuve avec le second facteur désarmé, par-dessus la MFA peut-être ACTIVE que cette lecture n'a pas pu rendre — le démon refuse déjà l'écriture, et ce bouton ne doit pas la promettre.", 'bad', 9000); return; }
  // `P10.23-b` (démon) — LE MOT DE PASSE DU COMPTE, DEMANDÉ AVANT TOUTE GRAINE, ET JAMAIS GARDÉ. `mfa_enroll`
  // (daemon/src/handlers/idp.rs) exige `{password}` : une session ouverte ne prouve pas que c'est le titulaire qui
  // enrôle, et une graine activée verrouille la connexion du compte derrière elle. Cette console envoyait `{}`, et
  // peignait TOUT refus nommé comme « Statut de double authentification NON LU » — le mot de passe exigé, refusé,
  // freiné, le compte sans mot de passe local et le compte non lu compris. Le champ est CELUI DE CE GESTE (posé
  // dans la modale partagée, lu puis VIDÉ dès qu'elle se referme) ; la valeur ne vit que dans cette fonction, le
  // temps de la requête, et n'atteint ni un état du module ni le stockage du site.
  const champ = document.createElement('input');
  champ.type = 'password'; champ.autocomplete = 'current-password'; champ.required = true;
  champ.dataset.motDePasseDEnrolement = '1';   // marque de POSE (harnais) : aucune règle CSS ne la vise
  const etiquette = document.createElement('label'); etiquette.className = 'modal-f';
  const libelle = document.createElement('span'); libelle.textContent = 'Mot de passe du compte';
  etiquette.append(libelle, champ);
  const choix = await modal({ title: 'Enrôler un second facteur', message: "Le démon exige le mot de passe de ce compte avant de poser une graine TOTP : une session ouverte ne prouve pas que c'est son titulaire qui enrôle.", okText: 'Continuer', body: etiquette });
  let motDePasse = champ.value;
  champ.value = '';
  if (choix === null) return;
  if (!motDePasse) { await avouerLeRefusDEnrolement('mot_de_passe_manquant', '', 0); return; }
  let data;
  try { data = await apiSend('/mfa/enroll', 'POST', { password: motDePasse }); }
  catch (e) {
    // L'enrôlement refusé s'écrit DANS le panneau, pas dans un avis qui s'efface : la cause dit pourquoi le
    // second facteur n'a pas été touché. Le statut non lu garde son aveu et son drapeau — la garde du démon peut
    // tomber entre la charge et le clic — ; les cinq refus de la preuve du mot de passe ont chacun leur face.
    if (unDeuxCentsSansCorpsLisible(e)) data = null;
    else {
      const cle = cleDuRefusDEnrolement(e);
      if (cle === 'statut_mfa_non_lu') { STATUT_MFA_NON_LU = true; enroll.hidden = false; avouerLeStatutMfaNonLu(enroll, e.causeDuDemon); return; }
      await avouerLeRefusDEnrolement(cle, phraseDuRefusDuDemon(e), e.delaiDuRefus);
      return;
    }
  } finally { motDePasse = ''; }
  // Un deux cents sans la graine n'ouvre pas de carte vide : il se dit, après relecture du statut.
  if (!(data && typeof data.secret === 'string' && data.secret && typeof data.otpauth_uri === 'string')) { await avouerLeRefusDEnrolement('enrolement_non_etabli', '', 0); return; }
  enroll.hidden = false;
  // La carte reprend le chrome .ruleform (comme openIdpForm) -> l'input #mfa-code et le panneau
  // sont stylés au lieu des défauts navigateur.
  const box = document.createElement('div'); box.className = 'ruleform';
  const p1 = document.createElement('p'); p1.style.cssText = 'font-size:12px;margin:0 0 6px';
  p1.textContent = 'Ajoute cette clé dans ton app d\'authentification (Google Authenticator, Authy…) :';
  // P11.4-c : la clé se lit dans LES DEUX thèmes — classe partagée `.secretbox` (fond carte + texte fg), plus
  // aucune couleur en dur : `--bg2` n'existait dans aucun thème et son repli sombre rendait la clé invisible en clair.
  const sec = document.createElement('code'); sec.className = 'secretbox'; sec.textContent = data.secret; sec.title = 'Clé TOTP — cliquer sélectionne tout';
  const uri = document.createElement('div'); uri.className = 'muted'; uri.style.cssText = 'font-size:11px;margin:6px 0;word-break:break-all';
  uri.textContent = data.otpauth_uri;
  const lbl = document.createElement('label'); lbl.style.cssText = 'display:block;margin:6px 0';
  const inp = document.createElement('input'); inp.id = 'mfa-code'; inp.placeholder = 'code à 6 chiffres'; inp.inputMode = 'numeric'; inp.autocomplete = 'one-time-code';
  lbl.append('Vérifie un premier code : ', inp);
  // `P10.22-n` — LE PUITS DU GESTE « VÉRIFIER & ACTIVER », DANS LA CARTE : un refus qui laisse l'enrôlement
  // valable s'y écrit sans détruire le champ du code, pour que le geste se rejoue.
  const resultat = document.createElement('div');
  const btn = mkBtn('Vérifier & activer', async () => {
    const code = inp.value.trim();
    let r;
    try { r = await apiSend('/mfa/verify', 'POST', { code }); }
    catch (e) {
      // `P10.22-b` — un deux cents sans corps lisible n'est pas un refus : « activation non établie », ci-dessous.
      if (!unDeuxCentsSansCorpsLisible(e)) { await avouerLeRefusDActivation(cleDuRefusDActivation(e), phraseDuRefusDuDemon(e), e.delaiDuRefus, resultat); return; }
      r = null;
    }
    if (!(r && r.ok === true && Array.isArray(r.recovery_codes))) { await avouerLeRefusDActivation('activation_non_etablie', '', 0, resultat); return; }
    toast('MFA activée', 'ok');
    showRecovery(enroll, r.recovery_codes);
  });
  // Le bouton « Vérifier & activer » est enveloppé dans .rf-actions (comme openIdpForm) -> stylé.
  const actions = document.createElement('div'); actions.className = 'rf-actions'; actions.appendChild(btn);
  box.append(p1, sec, uri, lbl, actions, resultat);
  enroll.replaceChildren(box);
}

function showRecovery(enroll, codes) {
  // Même chrome .ruleform + .rf-actions que startEnroll (cohérence visuelle du bouton).
  const box = document.createElement('div'); box.className = 'ruleform';
  const h = document.createElement('p'); h.style.cssText = 'font-size:12px;margin:0 0 6px';
  const hb = document.createElement('b'); hb.textContent = 'Codes de secours (usage unique)';
  h.append(hb, document.createTextNode(' — note-les maintenant, ils ne seront plus affichés :'));
  const ul = document.createElement('div'); ul.className = 'secretbox'; // P11.4-c : même boîte lisible que la clé
  ul.textContent = codes.join('   ');
  const done = mkBtn('J\'ai noté mes codes', () => { enroll.hidden = true; enroll.replaceChildren(); loadMfa(); });
  const actions = document.createElement('div'); actions.className = 'rf-actions'; actions.appendChild(done);
  box.append(h, ul, actions); enroll.replaceChildren(box);
}

// `P10.22-n` — LE REFUS DE DÉSACTIVER DIT QUI EST EN CAUSE : LE CODE, OU LA BASE.
//
// CE QUE LE DÉMON SERT DEPUIS `P10.21-s` ET `P10.22-k`. `mfa_disable` (daemon/src/handlers/idp.rs) juge,
// consomme et supprime dans une transaction : quatre cent un quand aucun facteur valide n'accompagne la
// demande (un pas déjà consommé compris, compté comme un échec) ; quatre cent quatre quand aucune MFA n'est
// enrôlée ; cinq cent trois `CAUSE_MFA_NON_DESACTIVEE` quand la base n'a pas pris la transaction — le compte
// exige TOUJOURS son second facteur ; cinq cent trois `CAUSE_CODES_DE_SECOURS_ILLISIBLES` (`P10.22-r`) quand la
// liste de secours n'a pas été lue — code ni accepté ni refusé ; quatre cent vingt-neuf quand le compte est
// freiné (`P10.22-m`) ; `{ok:true}` sur le succès, seul corps de succès que la route serve.
//
// CE QUE LA CONSOLE EN FAISAIT, MESURÉ. Le même avis pour les trois refus : « erreur : » suivi du message
// composé par `apiSend` — « 401 {"error":"code MFA requis pour désactiver"} » ou « 503 {"error":"DOUBLE
// AUTHENTIFICATION TOUJOURS ACTIVE : … désactivati » coupé à deux cents caractères —, trois secondes, en
// français. Rien ne distinguait « votre code est refusé » de « votre code est bon, la base a refusé ». Et le
// succès était annoncé sur TOUT deux cents, corps vide et page de passerelle compris.
//
// LE DISCRIMINANT EST LE STATUT (`statutDuRefus`, porté par `apiSend`), PUIS LA CAUSE : le statut sépare
// l'accusation du code (quatre cent un) de tout le reste ; deux cinq cent trois différents se séparent par la
// cause servie, lue au point commun (`natureDuRefusDuSecondFacteur`). Le témoin 108 relit chaque cause dans
// l'arbre du démon. La phrase s'écrit DANS le panneau (`#mfa-enroll`, le puits du geste refusé depuis
// `P10.20-b`), à deux nœuds : la face choisie par `LANG`, puis la cause servie, entière.
const MOTS_DE_LA_DESACTIVATION_MFA = {
  code_refuse: {
    fr: "Code REFUSÉ : la double authentification reste ACTIVE sur ce compte. Le démon a répondu —",
    en: 'Code REFUSED: two-factor authentication stays ACTIVE on this account. The daemon answered —' },
  desactivation_non_ecrite: {
    fr: "Désactivation NON ENREGISTRÉE, et ton code n'est PAS en cause : la double authentification reste ACTIVE — le compte exige toujours un code à la connexion. Le geste peut être rejoué. Le démon en nomme la cause —",
    en: 'Deactivation NOT RECORDED, and your code is NOT at fault: two-factor authentication stays ACTIVE — the account still requires a code at sign-in. The gesture can be replayed. The daemon names the cause —' },
  desactivation_refusee: {
    fr: "Désactivation REFUSÉE : le démon ne l'a pas confirmée. Il a répondu —",
    en: 'Deactivation REFUSED: the daemon did not confirm it. It answered —' },
  desactivation_non_etablie: {
    fr: "Le démon a répondu sans confirmer la désactivation : rien ici n'établit que la double authentification est désactivée. Son statut, relu, est affiché ci-dessus.",
    en: 'The daemon answered without confirming the deactivation: nothing here establishes that two-factor authentication is disabled. Its status, read again, is shown above.' },
};
// LE STATUT D'ABORD, LA CAUSE ENSUITE. Le quatre cent un est le code refusé (y compris un pas déjà consommé,
// `P10.22-k`) ; les cinq cent trois se séparent par la cause servie — écriture refusée ou liste de secours
// illisible, deux faits différents — ; le quatre cent vingt-neuf freiné aussi. Une cause que le point commun
// ne connaît pas retombe sur le refus générique, qui colle la phrase sans rien en affirmer.
function cleDuRefusDeDesactivation(e) {
  const statut = e && e.statutDuRefus;
  const nature = natureDuRefusDuSecondFacteur(e && e.causeDuDemon);
  if (statut === 401) return 'code_refuse';
  if (statut === 503 && nature === 'mfa_non_desactivee') return 'desactivation_non_ecrite';
  if (statut === 503 && nature === 'codes_de_secours_illisibles') return 'codes_de_secours_illisibles';
  if (statut === 429 && nature === 'second_facteur_freine') return 'second_facteur_freine';
  return 'desactivation_refusee';
}
// Les clés propres au panneau viennent de ses tables ; les deux clés communes aux deux écrans du second
// facteur, du point commun (`web/core.js`).
const faceDuPanneau = (table, cle, delai) => (Object.prototype.hasOwnProperty.call(table, cle)
  ? (LANG === 'en' ? table[cle].en : table[cle].fr)
  : motDuRefusDuSecondFacteur(cle, delai));
const motDeLaDesactivationMfa = (cle, delai) => faceDuPanneau(MOTS_DE_LA_DESACTIVATION_MFA, cle, delai);
// L'aveu à deux nœuds ; `cause` vide = la face se suffit (aucune cause servie). L'appelant y pose la marque du
// geste refusé (`dataset.refusDe…`, marque de POSE, pas de style : aucune règle CSS ne la vise).
function aveuDuPanneau(mot, cause) {
  const aveu = document.createElement('div'); aveu.className = 'bad'; aveu.style.cssText = 'margin:0;font-size:12px';
  const dit = document.createElement('span');
  dit.textContent = mot;
  aveu.append(dit);
  if (cause) aveu.append(' « ' + String(cause).trim() + ' »');
  return aveu;
}
// Au puits du geste refusé (`#mfa-enroll`, depuis `P10.20-b`).
function avouerLaDesactivation(cle, cause, delai) {
  const hote = $('#mfa-enroll');
  const mot = motDeLaDesactivationMfa(cle, delai);
  if (!hote) { toast(cause ? mot + ' « ' + cause + ' »' : mot, 'bad', 9000); return; }
  const aveu = aveuDuPanneau(mot, cause);
  aveu.dataset.refusDeDesactivation = cle;
  hote.hidden = false;
  hote.replaceChildren(aveu);
}

// `P10.23-b` (démon) — L'ENRÔLEMENT ET LA PREUVE DU PREMIER FACTEUR : UNE FACE PAR FAIT. `mfa_enroll` refuse en
// quatre cent trois le mot de passe absent (`CAUSE_MOT_DE_PASSE_EXIGE_POUR_ENROLER`), refusé
// (`CAUSE_MOT_DE_PASSE_REFUSE_A_L_ENROLEMENT`, échec COMPTÉ au verrou de la connexion) et le compte sans mot de
// passe local (`CAUSE_ENROLEMENT_SANS_MOT_DE_PASSE_LOCAL` : fédéré ou SSO — rien à accuser, son second facteur est
// celui de son fournisseur) ; en quatre cent vingt-neuf, avec son délai, le verrou du mot de passe
// (`CAUSE_MOT_DE_PASSE_VERROUILLE_A_L_ENROLEMENT`) ; en cinq cent trois le compte non lu
// (`CAUSE_COMPTE_NON_LU_A_L_ENROLEMENT`, ni accepté ni refusé) et le statut non lu (`CAUSE_MFA_NON_LUE`) ; en
// quatre cent neuf la MFA déjà active — lue avant, ou devenue active PENDANT l'enrôlement. Les causes sont lues
// au point commun (`natureDuRefusDuSecondFacteur`) ; le témoin 109 les relit dans le démon.
const MOTS_DE_L_ENROLEMENT_MFA = {
  mot_de_passe_manquant: {
    fr: "Enrôlement NON LANCÉ : le mot de passe du compte est requis, et rien n'a été envoyé au démon.",
    en: 'Enrollment NOT STARTED: the account password is required, and nothing was sent to the daemon.' },
  mot_de_passe_exige: {
    fr: "Enrôlement REFUSÉ : le démon n'a reçu aucun mot de passe. Aucune graine n'est posée, aucun échec n'est compté. Le démon en nomme la cause —",
    en: 'Enrollment REFUSED: the daemon received no password. No seed is set, no failure is counted. The daemon names the cause —' },
  mot_de_passe_refuse: {
    fr: "Mot de passe REFUSÉ : aucune graine n'est enrôlée, et l'échec est compté comme à la connexion. Le démon en nomme la cause —",
    en: 'Password REFUSED: no seed is enrolled, and the failure is counted as at sign-in. The daemon names the cause —' },
  mot_de_passe_verrouille: {
    fr: "Enrôlement FREINÉ : trop d'échecs du mot de passe sur ce compte depuis cette adresse — réessaie dans {delai} s. Le mot de passe n'a pas été examiné, aucune graine n'est posée. Le démon en nomme la cause —",
    en: 'Enrollment THROTTLED: too many password failures on this account from this address — try again in {delai} s. The password was not examined, no seed is set. The daemon names the cause —' },
  mot_de_passe_verrouille_sans_delai: {
    fr: "Enrôlement FREINÉ : trop d'échecs du mot de passe sur ce compte depuis cette adresse, jusqu'à la fin du délai. Le mot de passe n'a pas été examiné, aucune graine n'est posée. Le démon en nomme la cause —",
    en: 'Enrollment THROTTLED: too many password failures on this account from this address, until the delay ends. The password was not examined, no seed is set. The daemon names the cause —' },
  sans_mot_de_passe_local: {
    fr: "Pas de double authentification plume pour ce compte : il n'a pas de mot de passe local (compte fédéré ou SSO), et son second facteur est celui de son fournisseur d'identité. Rien n'est posé. Le démon en nomme la cause —",
    en: 'No plume two-factor authentication for this account: it has no local password (federated or SSO account), and its second factor is the one of its identity provider. Nothing is set. The daemon names the cause —' },
  compte_non_lu: {
    fr: "Enrôlement ni accepté ni refusé : le compte n'a pas pu être lu. Aucune graine n'est posée, aucun échec n'est compté — réessaie. Le démon en nomme la cause —",
    en: 'Enrollment neither accepted nor refused: the account could not be read. No seed is set, no failure is counted — try again. The daemon names the cause —' },
  deja_active: {
    fr: "Rien n'est enrôlé : la double authentification est DÉJÀ ACTIVE sur ce compte (elle a pu l'être pendant l'enrôlement). Son statut, relu, est affiché ci-dessus. Le démon a répondu —",
    en: 'Nothing is enrolled: two-factor authentication is ALREADY ACTIVE on this account (it may have become so during the enrollment). Its status, read again, is shown above. The daemon answered —' },
  enrolement_refuse: {
    fr: "Enrôlement REFUSÉ : le démon ne l'a pas confirmé. Il a répondu —",
    en: 'Enrollment REFUSED: the daemon did not confirm it. It answered —' },
  enrolement_non_etabli: {
    fr: "Le démon a répondu sans servir de graine : rien ici n'établit qu'un enrôlement est en attente. Son statut, relu, est affiché ci-dessus.",
    en: 'The daemon answered without serving a seed: nothing here establishes that an enrollment is pending. Its status, read again, is shown above.' },
};
// LE STATUT D'ABORD, LA CAUSE ENSUITE — la forme des deux discriminants voisins. `statut_mfa_non_lu` n'a pas de
// face ici : il garde l'aveu et le drapeau du statut non lu (`avouerLeStatutMfaNonLu`).
function cleDuRefusDEnrolement(e) {
  const statut = e && e.statutDuRefus;
  const nature = natureDuRefusDuSecondFacteur(e && e.causeDuDemon);
  if (statut === 503 && nature === 'statut_mfa_non_lu') return 'statut_mfa_non_lu';
  if (statut === 503 && nature === 'compte_non_lu') return 'compte_non_lu';
  if (statut === 403 && nature === 'mot_de_passe_exige') return 'mot_de_passe_exige';
  if (statut === 403 && nature === 'mot_de_passe_refuse') return 'mot_de_passe_refuse';
  if (statut === 403 && nature === 'sans_mot_de_passe_local') return 'sans_mot_de_passe_local';
  if (statut === 429 && nature === 'mot_de_passe_verrouille') return 'mot_de_passe_verrouille';
  if (statut === 409) return 'deja_active';
  return 'enrolement_refuse';
}
function motDeLEnrolementMfa(cle, delai) {
  const cleServie = cle === 'mot_de_passe_verrouille' && !(delai > 0) ? 'mot_de_passe_verrouille_sans_delai' : cle;
  const mots = MOTS_DE_L_ENROLEMENT_MFA[cleServie];
  return (LANG === 'en' ? mots.en : mots.fr).replace('{delai}', String(delai));
}
// Au puits du geste (`#mfa-enroll`). La MFA déjà active et l'enrôlement non établi décrivent un état qui n'est
// pas celui du panneau : le statut est RELU d'abord — la relecture vide le panneau —, l'aveu posé ensuite.
const ENROLEMENT_A_RELIRE = new Set(['deja_active', 'enrolement_non_etabli']);
async function avouerLeRefusDEnrolement(cle, cause, delai) {
  const mot = motDeLEnrolementMfa(cle, delai);
  if (ENROLEMENT_A_RELIRE.has(cle)) await loadMfa();
  const hote = $('#mfa-enroll');
  if (!hote) { toast(cause ? mot + ' « ' + cause + ' »' : mot, 'bad', 9000); return; }
  const aveu = aveuDuPanneau(mot, cause);
  aveu.dataset.refusDEnrolement = cle;
  hote.hidden = false;
  hote.replaceChildren(aveu);
}

// `P10.22-n` — L'ACTIVATION (`/api/mfa/verify`) LIT SES REFUS NEUFS (`P10.22-l`, `-m`). Le démon refuse une
// MFA DÉJÀ ACTIVE en quatre cent neuf AVANT tout examen du code, et un enrôlement changé pendant la
// vérification en quatre cent neuf nommé (`CAUSE_ENROLEMENT_CHANGE_PENDANT_LA_VERIFICATION`) ; l'écriture
// refusée en cinq cent trois (`CAUSE_MFA_NON_ACTIVEE`) ; le compte freiné en quatre cent vingt-neuf ; le code
// en quatre cent un. La console écrivait « code invalide : » suivi du message composé sur TOUS ces refus —
// elle accusait le code sur une MFA déjà active, sur une course et sur une écriture refusée —, et « MFA
// activée » avec une boîte de codes VIDE sur un deux cents sans `recovery_codes`.
const MOTS_DE_L_ACTIVATION_MFA = {
  code_refuse: {
    fr: "Code REFUSÉ : la double authentification n'est PAS activée. Le démon a répondu —",
    en: 'Code REFUSED: two-factor authentication is NOT enabled. The daemon answered —' },
  deja_active: {
    fr: "Rien n'est activé : la double authentification est DÉJÀ ACTIVE sur ce compte, le code n'a pas été examiné et aucun code de secours n'est servi. Son statut, relu, est affiché ci-dessus. Le démon a répondu —",
    en: 'Nothing is enabled: two-factor authentication is ALREADY ACTIVE on this account, the code was not examined and no recovery code is served. Its status, read again, is shown above. The daemon answered —' },
  enrolement_change: {
    fr: "Rien n'est activé : l'enrôlement a changé pendant la vérification, et aucun code de secours n'est servi. Son état, relu, est affiché ci-dessus. Le démon en nomme la cause —",
    en: 'Nothing is enabled: the enrolment changed during the verification, and no recovery code is served. Its state, read again, is shown above. The daemon names the cause —' },
  activation_non_ecrite: {
    fr: "Activation NON ENREGISTRÉE, et ton code n'est PAS en cause : le compte reste SANS second facteur et aucun code de secours n'est servi. Le geste peut être rejoué. Le démon en nomme la cause —",
    en: 'Activation NOT RECORDED, and your code is NOT at fault: the account stays WITHOUT a second factor and no recovery code is served. The gesture can be replayed. The daemon names the cause —' },
  activation_refusee: {
    fr: "Activation REFUSÉE : le démon ne l'a pas confirmée. Il a répondu —",
    en: 'Activation REFUSED: the daemon did not confirm it. It answered —' },
  activation_non_etablie: {
    fr: "Le démon a répondu sans servir de codes de secours : rien ici n'établit que la double authentification est activée. Son statut, relu, est affiché ci-dessus.",
    en: 'The daemon answered without serving recovery codes: nothing here establishes that two-factor authentication is enabled. Its status, read again, is shown above.' },
};
function cleDuRefusDActivation(e) {
  const statut = e && e.statutDuRefus;
  const nature = natureDuRefusDuSecondFacteur(e && e.causeDuDemon);
  if (statut === 401) return 'code_refuse';
  if (statut === 409) return nature === 'enrolement_change' ? 'enrolement_change' : 'deja_active';
  if (statut === 503 && nature === 'mfa_non_activee') return 'activation_non_ecrite';
  if (statut === 429 && nature === 'second_facteur_freine') return 'second_facteur_freine';
  return 'activation_refusee';
}
const motDeLActivationMfa = (cle, delai) => faceDuPanneau(MOTS_DE_L_ACTIVATION_MFA, cle, delai);
// UN ENRÔLEMENT QUI N'EST PLUS CELUI DE LA CARTE SE RELIT. Sur une MFA déjà active, un enrôlement changé ou un
// succès non établi, la carte (graine, champ du code) décrit un état qui n'est plus : le statut est relu —
// la relecture vide le panneau — et l'aveu est posé ENSUITE, au puits du panneau. Sur les autres refus
// l'enrôlement reste valable : l'aveu se pose dans la carte, sous le bouton, et le geste se rejoue.
const ACTIVATION_A_RELIRE = new Set(['deja_active', 'enrolement_change', 'activation_non_etablie']);
async function avouerLeRefusDActivation(cle, cause, delai, puitsDeLaCarte) {
  const mot = motDeLActivationMfa(cle, delai);
  const aveu = aveuDuPanneau(mot, cause);
  aveu.dataset.refusDActivation = cle;
  if (ACTIVATION_A_RELIRE.has(cle)) {
    await loadMfa();
    const hote = $('#mfa-enroll');
    if (!hote) { toast(cause ? mot + ' « ' + cause + ' »' : mot, 'bad', 9000); return; }
    hote.hidden = false;
    hote.replaceChildren(aveu);
    return;
  }
  puitsDeLaCarte.replaceChildren(aveu);
}

async function disableMfa() {
  // P11.5-b : désactiver la MFA ABAISSE une protection du compte -> confirmation partagée qui nomme la
  // conséquence, puis saisie du code dans la modale partagée (plus de prompt() natif).
  if (!await confirmWithConsequence('Désactiver la double authentification', 'ce compte se connectera de nouveau avec le seul mot de passe ; les codes de secours émis deviennent caducs.', { okText: 'Désactiver' })) return;
  const r = await modal({ title: 'Code de vérification', message: 'Entre un code TOTP courant, ou un code de secours, pour confirmer la désactivation.', okText: 'Désactiver', fields: [{ name: 'code', label: 'Code', value: '', required: true, placeholder: 'code à 6 chiffres ou code de secours' }] });
  if (!r) return;
  const code = String(r.code || '');
  let j;
  try { j = await apiSend('/mfa/disable', 'POST', { code: code.trim() }); }
  catch (e) {
    // `P10.22-b` — un deux cents sans corps lisible n'est pas un refus : « désactivation non établie », ci-dessous.
    if (!unDeuxCentsSansCorpsLisible(e)) { avouerLaDesactivation(cleDuRefusDeDesactivation(e), phraseDuRefusDuDemon(e), e.delaiDuRefus); return; }
    j = null;
  }
  if (j && j.ok === true) { toast('MFA désactivée', 'ok'); loadMfa(); return; }
  // Un deux cents qui ne porte pas le succès de la route : le statut est RELU d'abord — la relecture vide
  // le puits —, l'aveu est posé ensuite.
  await loadMfa();
  avouerLaDesactivation('desactivation_non_etablie', '');
}

// `startEnroll` est exposé pour le harnais ESM (témoin 96 : le refus du geste d'enrôlement et l'aveu écrit
// dans le panneau, rendus par leur fabrique réelle et non par une copie) ; il n'a aucun usage applicatif
// hors de ce module, où seul le bouton « Activer la MFA » l'appelle.
// `P10.22-n` — `disableMfa`, `cleDuRefusDeDesactivation`, `motDeLaDesactivationMfa`, `cleDuRefusDActivation`
// et `motDeLActivationMfa` partent pour le même harnais (témoin 108) : les refus de désactiver et d'activer
// se mesurent en JOUANT les gestes, modales comprises, et les discriminants se jugent dans les deux sens sur
// les statuts et les causes que le démon sert. Aucun usage applicatif hors de ce module.
// `P10.23-b` — `cleDuRefusDEnrolement` et `motDeLEnrolementMfa` partent pour le témoin 109, au même titre.
// `P10.26-q` — le formulaire d'un fournisseur (création et modification) part pour le témoin 115, qui le joue sous
// chaque instance de langue : « + Fournisseur » ne l'ouvre que par l'instance qui l'a câblé la première.
export { startEnroll, disableMfa, cleDuRefusDeDesactivation, motDeLaDesactivationMfa, cleDuRefusDActivation, motDeLActivationMfa, cleDuRefusDEnrolement, motDeLEnrolementMfa, openIdpForm as ouvrirLeFormulaireDuFournisseur };
