// idp.js — IdP natif (#44) : UI admin des fournisseurs fédérés (OIDC/LDAP) + MFA TOTP self-service.
// Comportement additif : tant qu'aucun fournisseur n'est activé et qu'aucune MFA n'est enrôlée, rien ne
// change côté auth. Anti-XSS : tout texte via textContent/esc ; le secret (client_secret / bind pw) est un
// champ password, JAMAIS réaffiché, ré-envoyé UNIQUEMENT s'il est re-saisi (omis = conservé côté serveur).
// La vraie garde reste SERVEUR (/api/idp/* admin-only ; /api/mfa/* borné à au.name).
import { $, api, apiSend, confirmModal, esc, fmtTs, muted, toast, withBusy } from './core.js';
import { uiIsAdmin } from './multitenant.js';

// ---------------------------------------------------------------------------------------------------
// Fournisseurs d'identité (OIDC / LDAP) — admin-only.
// ---------------------------------------------------------------------------------------------------

const KIND_LABEL = { oidc: 'OIDC', ldap: 'LDAP / AD', saml: 'SAML (à venir)' };

export async function loadIdpProviders() {
  const wrap = $('#idp-list'); if (!wrap) return;
  const btn = $('#idp-new'); if (btn) btn.onclick = () => openIdpForm(null);
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
  row.className = 'idp-row'; row.style.cssText = 'display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--line,#2c3550)';
  const dot = document.createElement('span');
  dot.textContent = p.enabled ? '●' : '○'; dot.style.color = p.enabled ? 'var(--ok,#4ade80)' : 'var(--muted,#8b93a7)';
  dot.title = p.enabled ? 'activé' : 'désactivé';
  const name = document.createElement('b'); name.textContent = p.name;
  const kind = document.createElement('span'); kind.className = 'muted'; kind.style.fontSize = '12px';
  kind.textContent = KIND_LABEL[p.kind] || p.kind;
  const meta = document.createElement('span'); meta.className = 'muted'; meta.style.cssText = 'font-size:11px;margin-left:auto';
  const issuer = (p.config && (p.config.issuer || p.config.url)) || '';
  meta.textContent = (p.has_secret ? '🔑 ' : '') + (issuer ? esc(issuer) : '') + (p.updated ? '  · maj ' + fmtTs(p.updated) : '');
  const toggle = mkBtn(p.enabled ? 'Désactiver' : 'Activer', async () => {
    await withBusy(toggle, async () => {
      try { await apiSend('/idp/providers/' + p.id, 'POST', { enabled: !p.enabled }); toast('mis à jour', 'ok'); loadIdpProviders(); }
      catch (e) { toast('erreur : ' + e.message, 'bad'); }
    });
  });
  const edit = mkBtn('Éditer', () => openIdpForm(p));
  const del = mkBtn('Supprimer', async () => {
    if (!(await confirmModal('Supprimer le fournisseur « ' + p.name + ' » ?'))) return;
    try { await apiSend('/idp/providers/' + p.id, 'DELETE'); toast('supprimé', 'ok'); loadIdpProviders(); }
    catch (e) { toast('erreur : ' + e.message, 'bad'); }
  });
  del.style.color = 'var(--bad,#f87171)';
  row.append(dot, name, kind, meta, toggle, edit, del);
  return row;
}

function mkBtn(label, fn) {
  const b = document.createElement('button'); b.type = 'button'; b.textContent = label; b.style.fontSize = '12px'; b.onclick = fn; return b;
}

// Formulaire dynamique de fournisseur (create ou edit). Les champs changent selon le kind.
function openIdpForm(existing) {
  const host = $('#idp-form-host'); if (!host) return;
  const cfg = (existing && existing.config) || {};
  const form = document.createElement('form'); form.className = 'ruleform'; form.style.cssText = 'margin:10px 0;padding:10px;border:1px solid var(--line,#2c3550);border-radius:8px';
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
  const save = document.createElement('button'); save.type = 'submit'; save.textContent = existing ? 'Enregistrer' : 'Créer';
  const cancel = document.createElement('button'); cancel.type = 'button'; cancel.textContent = 'Annuler'; cancel.onclick = () => host.replaceChildren();
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

export async function loadMfa() {
  const status = $('#mfa-status'); const actions = $('#mfa-actions'); const enroll = $('#mfa-enroll');
  if (!status || !actions) return;
  actions.replaceChildren(); if (enroll) { enroll.hidden = true; enroll.replaceChildren(); }
  let st;
  try { st = await api('/mfa/status'); }
  catch (e) {
    if (String((e && e.message) || '').startsWith('501')) { status.textContent = 'MFA réservée au mode mono-tenant.'; return; }
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
  let data;
  try { data = await apiSend('/mfa/enroll', 'POST', {}); }
  catch (e) { toast('erreur : ' + e.message, 'bad'); return; }
  enroll.hidden = false;
  // La carte reprend le chrome .ruleform (comme openIdpForm) -> l'input #mfa-code et le panneau
  // sont stylés au lieu des défauts navigateur.
  const box = document.createElement('div'); box.className = 'ruleform';
  const p1 = document.createElement('p'); p1.style.cssText = 'font-size:12px;margin:0 0 6px';
  p1.textContent = 'Ajoute cette clé dans ton app d\'authentification (Google Authenticator, Authy…) :';
  const sec = document.createElement('code'); sec.textContent = data.secret; sec.style.cssText = 'display:block;padding:6px;background:var(--bg2,#161c2e);border-radius:6px;word-break:break-all';
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
  const ul = document.createElement('div'); ul.style.cssText = 'font-family:monospace;padding:6px;background:var(--bg2,#161c2e);border-radius:6px';
  ul.textContent = codes.join('   ');
  const done = mkBtn('J\'ai noté mes codes', () => { enroll.hidden = true; enroll.replaceChildren(); loadMfa(); });
  const actions = document.createElement('div'); actions.className = 'rf-actions'; actions.appendChild(done);
  box.append(h, ul, actions); enroll.replaceChildren(box);
}

async function disableMfa() {
  const code = prompt('Entre un code TOTP (ou un code de secours) pour désactiver la MFA :');
  if (code == null) return;
  try { await apiSend('/mfa/disable', 'POST', { code: code.trim() }); toast('MFA désactivée', 'ok'); loadMfa(); }
  catch (e) { toast('erreur : ' + e.message, 'bad'); }
}
