// idp.js — IdP natif (#44) : UI admin des fournisseurs fédérés (OIDC/LDAP) + MFA TOTP self-service.
// Comportement additif : tant qu'aucun fournisseur n'est activé et qu'aucune MFA n'est enrôlée, rien ne
// change côté auth. Anti-XSS : tout texte via textContent/esc ; le secret (client_secret / bind pw) est un
// champ password, JAMAIS réaffiché, ré-envoyé UNIQUEMENT s'il est re-saisi (omis = conservé côté serveur).
// La vraie garde reste SERVEUR (/api/idp/* admin-only ; /api/mfa/* borné à au.name).
import { $, api, apiSend, confirmWithConsequence, disclosure, esc, fmtTs, modal, muted, toast, withBusy } from './core.js';
import { enabledSwitch } from './producer_ui.js';
import { uiIsAdmin } from './multitenant.js';

// ---------------------------------------------------------------------------------------------------
// Fournisseurs d'identité (OIDC / LDAP) — admin-only.
// ---------------------------------------------------------------------------------------------------

const KIND_LABEL = { oidc: 'OIDC', ldap: 'LDAP / AD', saml: 'SAML (à venir)' };

export async function loadIdpProviders() {
  const wrap = $('#idp-list'); if (!wrap) return;
  // P11.4-a : « + Fournisseur » passe par le dépli partagé (second clic = repli, état visible sur le bouton).
  const btn = $('#idp-new'); const fh = $('#idp-form-host');
  if (btn && fh && !btn.dataset.wired) { btn.dataset.wired = '1'; disclosure(btn, fh, { isOpen: () => !!fh.querySelector('#idp-form') && !fh.querySelector('#idp-form').dataset.editing, open: () => openIdpForm(null), close: () => fh.replaceChildren() }); }
  if (!uiIsAdmin()) { wrap.replaceChildren(muted('réservé à l\'administrateur.')); return; }
  let list = [];
  try { list = await api('/idp/providers'); }
  catch (e) {
    // api() jette « <statut> <corps> » sur non-2xx : le 501 (mode multi-tenant) garde son message dédié.
    if (String((e && e.message) || '').startsWith('501')) { wrap.replaceChildren(muted('IdP réservé au mode mono-tenant.')); return; }
    wrap.replaceChildren(muted('erreur : ' + ((e && e.message) || e))); return;
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
  meta.textContent = (p.has_secret ? '🔑 ' : '') + (issuer ? esc(issuer) : '') + (p.updated ? '  · maj ' + fmtTs(p.updated) : '');
  // COMMUTATEUR PARTAGÉ (`P11.13-c`) : ce que la bascule arme, c'est une PORTE D'ENTRÉE — des comptes
  // extérieurs peuvent ouvrir une session par ce fournisseur. Le bouton « Activer / Désactiver » ne le
  // disait pas. `enabledSwitch` écrit la conséquence à côté de l'interrupteur dans les deux états, porte
  // l'état par le mot (ON / OFF) — ce que la pastille disait — et rétablit la case si le serveur refuse.
  const toggle = enabledSwitch({
    enabled: !!p.enabled, name: p.name, allowed: true, confirmOnEnable: true,
    consequence: 'les comptes de cet annuaire ' + (KIND_LABEL[p.kind] || p.kind) + ' peuvent ouvrir une session sur plume, avec le rôle que leur groupe leur donne ; OFF, plus aucune session ne s\'ouvre par ce fournisseur',
    onToggle: (next) => apiSend('/idp/providers/' + p.id, 'POST', { enabled: next }),
  });
  const edit = mkBtn('Éditer', () => openIdpForm(p));
  const del = mkBtn('Supprimer', async () => {
    // P11.5-b : DELETE = route sensible -> la confirmation partagée nomme la conséquence.
    if (!(await confirmWithConsequence('Supprimer le fournisseur « ' + p.name + ' »', 'les comptes qui se connectent par ce fournisseur ne pourront plus ouvrir de session ; le secret associé est effacé et ne se restaure pas.', { okText: 'Supprimer' }))) return;
    try { await apiSend('/idp/providers/' + p.id, 'DELETE'); toast('supprimé', 'ok'); loadIdpProviders(); }
    catch (e) { toast('erreur : ' + e.message, 'bad'); }
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
  title.textContent = existing ? ('Éditer ' + existing.name) : 'Nouveau fournisseur';
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
  const res = document.createElement('span'); res.className = 'muted';
  actions.append(save, cancel, res); form.appendChild(actions);

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
    try {
      await withBusy(save, async () => {
        if (existing) { await apiSend('/idp/providers/' + existing.id, 'POST', body); }
        else { body.name = v('idpf-name'); body.kind = kind; await apiSend('/idp/providers', 'POST', body); }
      });
      toast('enregistré', 'ok'); host.replaceChildren(); loadIdpProviders();
    } catch (err) { res.textContent = 'erreur : ' + err.message; }
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
    if (String((e && e.message) || '').startsWith('501')) { status.textContent = 'MFA réservée au mode mono-tenant.'; return; }
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
    status.textContent = 'erreur : ' + ((e && e.message) || e); return;
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
  let data;
  try { data = await apiSend('/mfa/enroll', 'POST', {}); }
  catch (e) {
    // L'enrôlement refusé par une lecture ratée s'écrit DANS le panneau, pas dans un avis qui s'efface :
    // la cause dit pourquoi le second facteur n'a pas été touché, et elle doit rester lisible le temps de
    // la lire. Le drapeau est posé ici aussi — la garde du démon peut tomber entre la charge et le clic.
    const cause = (e && e.causeDuDemon) || '';
    if (cause) {
      STATUT_MFA_NON_LU = true;
      enroll.hidden = false;
      avouerLeStatutMfaNonLu(enroll, cause);
      return;
    }
    toast('erreur : ' + e.message, 'bad'); return;
  }
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
  const btn = mkBtn('Vérifier & activer', async () => {
    const code = inp.value.trim();
    try {
      const r = await apiSend('/mfa/verify', 'POST', { code });
      toast('MFA activée', 'ok');
      showRecovery(enroll, (r && r.recovery_codes) || []);
    } catch (e) { toast('code invalide : ' + e.message, 'bad'); }
  });
  // Le bouton « Vérifier & activer » est enveloppé dans .rf-actions (comme openIdpForm) -> stylé.
  const actions = document.createElement('div'); actions.className = 'rf-actions'; actions.appendChild(btn);
  box.append(p1, sec, uri, lbl, actions);
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

async function disableMfa() {
  // P11.5-b : désactiver la MFA ABAISSE une protection du compte -> confirmation partagée qui nomme la
  // conséquence, puis saisie du code dans la modale partagée (plus de prompt() natif).
  if (!await confirmWithConsequence('Désactiver la double authentification', 'ce compte se connectera de nouveau avec le seul mot de passe ; les codes de secours émis deviennent caducs.', { okText: 'Désactiver' })) return;
  const r = await modal({ title: 'Code de vérification', message: 'Entre un code TOTP courant, ou un code de secours, pour confirmer la désactivation.', okText: 'Désactiver', fields: [{ name: 'code', label: 'Code', value: '', required: true, placeholder: 'code à 6 chiffres ou code de secours' }] });
  if (!r) return;
  const code = String(r.code || '');
  try { await apiSend('/mfa/disable', 'POST', { code: code.trim() }); toast('MFA désactivée', 'ok'); loadMfa(); }
  catch (e) { toast('erreur : ' + e.message, 'bad'); }
}

// `startEnroll` est exposé pour le harnais ESM (témoin 96 : le refus du geste d'enrôlement et l'aveu écrit
// dans le panneau, rendus par leur fabrique réelle et non par une copie) ; il n'a aucun usage applicatif
// hors de ce module, où seul le bouton « Activer la MFA » l'appelle.
export { startEnroll };
