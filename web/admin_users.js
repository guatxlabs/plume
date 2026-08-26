// admin_users.js — comptes & acces (admin) + jetons agent/HEC (provisioning, show-once)
// Extrait d'app.js (decoupe par concern — meme patron que freshness.js).
// PURE MOVE : corps de fonctions IDENTIQUES au monolithe, seuls les import/export sont ajoutes.
// Le cycle app<->module est benin : les fonctions importees d'app.js ne sont appelees qu'a
// l'EXECUTION (handlers/async apres await), jamais a l'evaluation du module.
import { $, esc, fmtTs, ic, muted, api, apiSend, confirmWithConsequence, disclosure, toast, pagedList, closeModals } from './core.js';
import { S } from './state.js';
// P11.4-h : LE geste de copie de la console (mécanisme partagé).
import { boutonDeCopie } from './copie_et_selection.js';
import { route } from './app.js';

// --- Comptes & accès (réservé admin ; vit sous Réglages : la VISIBILITE est pilotee par le routeur) ---
const ROLE_LABEL = { admin: 'admin', editor: 'editor', viewer: 'viewer' };
/* state: isAdmin -> S (state.js) */ // /api/users 200 => admin ; sinon la section reste masquee partout
async function loadUsers() {
  const sec = $('#users'), list = $('#user-list'); if (!sec || !list) return;
  let d;
  // api() jette sur 403 (non-admin) comme sur une erreur réseau -> isAdmin=false dans les deux cas (inchangé).
  try { d = await api('/users'); } catch (e) { S.isAdmin = false; route(); return; }
  S.isAdmin = true; route(); // ne PAS forcer hidden ici : laisser le routeur n'afficher #users que sous Reglages
  const { users, me } = d;
  renderAcces(d.acces);   // P11.5-c : QUI A ACCÈS — l'inventaire des comptes VUS, à côté des comptes gérés ici
  list.replaceChildren();
  // #17 team — RÉCAPITULATIF ÉQUIPE : composition par rôle en un coup d'œil + raccourci vers le provisioning
  // de jetons (Administration → Jetons) pour équiper un coéquipier d'un agent/forwarder HEC.
  const uarr = users || [];
  const counts = uarr.reduce((a, u) => { a[u.role] = (a[u.role] || 0) + 1; return a; }, {});
  const summary = document.createElement('div'); summary.className = 'muted';
  summary.style.cssText = 'margin:0 0 10px;display:flex;gap:14px;flex-wrap:wrap;align-items:center';
  summary.appendChild(Object.assign(document.createElement('span'), { textContent: `${uarr.length} compte(s) · ` + ['admin', 'editor', 'viewer'].map(r => `${counts[r] || 0} ${ROLE_LABEL[r]}`).join(' · ') }));
  const tokLink = document.createElement('button'); tokLink.type = 'button'; tokLink.textContent = "Provisionner un jeton d'agent →";
  tokLink.title = 'Aller à Administration → Jetons'; tokLink.className = 'btn-link'; // P11.4-b : classe partagée (lien)
  tokLink.onclick = () => { location.hash = 'tokens'; };
  summary.appendChild(tokLink);
  list.appendChild(summary);
  uarr.forEach(u => {
    const row = document.createElement('div'); row.className = 'urow';
    const info = document.createElement('span');
    info.innerHTML = `<b>${esc(u.name)}</b> <span class="badge role-${esc(u.role)}">${esc(ROLE_LABEL[u.role] || u.role)}</span>` + (u.name === me ? ' <span class="muted">(vous)</span>' : '') + (u.created ? ` <span class="muted" style="font-size:11px">· créé ${esc(fmtTs(u.created))}</span>` : '');
    // éditeur inline (rôle + reset mot de passe) — révélé au clic sur ✎ ; POST /api/users/{id}
    const editor = document.createElement('div'); editor.className = 'ueditor hidden';
    const rsel = document.createElement('select'); rsel.className = 'ue-role';
    ['admin', 'editor', 'viewer'].forEach(r => { const o = document.createElement('option'); o.value = r; o.textContent = r; if (r === u.role) o.selected = true; rsel.appendChild(o); });
    const pw = document.createElement('input'); pw.type = 'password'; pw.className = 'ue-pw'; pw.placeholder = 'nouveau mdp (optionnel, ≥12)'; pw.autocomplete = 'new-password';
    const save = document.createElement('button'); save.type = 'button'; save.className = 'btn btn-sm'; save.textContent = 'Enregistrer';
    save.onclick = async () => {
      const body = { role: rsel.value }; if (pw.value) body.password = pw.value;
      // P11.5-b : changer un RÔLE élève ou retire un droit ; réinitialiser un MOT DE PASSE remplace une
      // crédence. Les deux passent par la confirmation partagée, qui nomme ce qui change.
      const parts = [];
      if (rsel.value !== u.role) parts.push(`le rôle de « ${u.name} » passe de ${ROLE_LABEL[u.role] || u.role} à ${ROLE_LABEL[rsel.value] || rsel.value}` + (rsel.value === 'admin' ? ' — accès complet à la configuration, aux secrets et aux suppressions' : u.role === 'admin' ? ' — ce compte perd l\'accès administrateur' : ''));
      if (pw.value) parts.push(`le mot de passe de « ${u.name} » est remplacé immédiatement (l\'ancien cesse de fonctionner)`);
      if (!parts.length) { toast('aucune modification', 'info'); return; }
      if (!await confirmWithConsequence(`Modifier le compte « ${u.name} »`, parts.join(' ; ') + '.', { okText: 'Appliquer', danger: rsel.value === 'admin' || u.role === 'admin' || !!pw.value })) return;
      try { await apiSend('/users/' + u.id, 'POST', body); }
      catch (err) { toast((err && err.message) || 'échec', 'bad'); return; }
      toast('compte mis à jour', 'ok'); loadUsers();
    };
    editor.append(rsel, pw, save);
    const ed = document.createElement('button'); ed.className = 'picon'; ed.title = 'Éditer (rôle / mot de passe)'; ed.textContent = '✎';
    ed.onclick = () => editor.classList.toggle('hidden');
    const del = document.createElement('button'); del.className = 'picon'; del.innerHTML = ic('x'); del.title = 'Supprimer le compte';
    if (u.name === me) del.disabled = true;
    del.onclick = async () => {
      if (!await confirmWithConsequence(`Supprimer le compte « ${u.name} »`, 'ses sessions et jetons de session cessent de fonctionner et le compte ne se restaure pas ; ses actions passées restent dans le journal d\'audit.', { okText: 'Supprimer' })) return;
      try { await apiSend('/users/' + u.id, 'DELETE'); }
      catch (err) { toast((err && err.message) || 'échec', 'bad'); }
      loadUsers();
    };
    // BATCH 2 (B3b) : ✎ + ✕ groupés à droite (sinon space-between les écarte) -> un span .urow-actions.
    const actions = document.createElement('span'); actions.className = 'urow-actions'; actions.append(ed, del);
    row.append(info, actions); list.appendChild(row); list.appendChild(editor);
  });
}
// --- P11.5-c — QUI A ACCÈS : l'inventaire des comptes que l'AUTHENTIFICATION a vus -----------------
// La liste `users` ci-dessus est la table des comptes que le produit CRÉE. Un compte d'annuaire externe
// (SSO d'en-têtes : le proxy pose le nom et les groupes) n'y a jamais de ligne — il administrait sans
// figurer nulle part, et personne ne pouvait répondre à « qui a accès ». `acces` (GET /api/users) porte
// chaque compte VU par le point de passage d'authentification, avec sa provenance, son rôle effectif,
// l'origine de ce rôle et sa dernière vue. LECTURE SEULE par nature : on n'administre pas ici un compte
// dont l'autorité vient d'ailleurs — la phrase le dit plutôt que de proposer un bouton qui échouerait.
function renderAcces(acces) {
  const host = $('#acces-list'); if (!host) return;
  const arr = acces || [];
  host.replaceChildren();
  if (!arr.length) { host.appendChild(muted('aucun accès observé pour le moment')); return; }
  arr.forEach(a => {
    const row = document.createElement('div'); row.className = 'urow';
    const info = document.createElement('span');
    const role = document.createElement('span'); role.className = 'badge role-' + a.role_effectif; role.textContent = a.role_effectif;
    role.title = 'rôle effectif au dernier accès, dérivé de : ' + a.origine_du_role;
    const nom = document.createElement('b'); nom.textContent = a.nom;
    const prov = document.createElement('span'); prov.className = 'muted'; prov.style.fontSize = '11px';
    prov.textContent = ' · ' + a.provenance;
    info.append(nom, document.createTextNode(' '), role, prov);
    const vu = document.createElement('span'); vu.className = 'muted'; vu.style.fontSize = '11px';
    vu.textContent = 'vu ' + fmtTs(a.derniere_vue);
    vu.title = "première vue : " + fmtTs(a.premiere_vue) + " · méthode : " + a.methode;
    row.append(info, vu); host.appendChild(row);
  });
}

if ($('#user-new') && $('#user-form')) disclosure($('#user-new'), $('#user-form')); // P11.4-a — dépli partagé
if ($('#uf-cancel')) $('#uf-cancel').onclick = () => $('#user-form').classList.add('hidden');
if ($('#user-form')) $('#user-form').addEventListener('submit', async e => {
  e.preventDefault();
  const res = $('#uf-result');
  const body = { name: $('#uf-name').value.trim(), password: $('#uf-pw').value, role: $('#uf-role').value };
  // P11.5-b : créer un compte ÉLÈVE un droit (un nouvel accès naît, avec un rôle) -> confirmation partagée.
  if (!await confirmWithConsequence(`Créer le compte « ${body.name || '?'} »`, `un accès ${ROLE_LABEL[body.role] || body.role} à cette console est ouvert immédiatement` + (body.role === 'admin' ? ' — accès complet à la configuration, aux secrets et aux suppressions' : '') + '.', { okText: 'Créer', danger: body.role === 'admin' })) return;
  res.textContent = '...';
  try { await apiSend('/users', 'POST', body); }
  catch (err) { res.textContent = '' + ((err && err.message) || err); return; }
  res.textContent = 'compte créé'; $('#uf-name').value = ''; $('#uf-pw').value = ''; $('#user-form').classList.add('hidden'); loadUsers();
});
loadUsers();

// --- Jetons (agent + HEC) : provisioning UI, pendant du CLI `plume-daemon token`. Réservé admin (isAdmin ;
// la vraie garde reste SERVEUR : GET/POST/DELETE /api/tokens sont admin-only). Le secret CLAIR n'est renvoyé
// QU'UNE fois à la création (show-once) : jamais re-affichable (seul son SHA-256 est stocké). Un jeton `hec`
// s'authentifie sur /services/collector (`Authorization: Splunk <tok>`) ; un jeton `agent` host-lié sert le
// responder. Mutations via apiSend (X-CSRF-Token auto) ; tout rendu en textContent (anti-XSS). -------------
const TOK_NAME_RE = /^[A-Za-z0-9_.-]+$/;          // miroir de token_name_ok côté daemon
const TOK_HOST_RE = /^[A-Za-z0-9_.-]{1,253}$/;    // miroir de token_host_ok (chaîne vide = non lié, autorisée)
const TOK_KIND_LABEL = { agent: 'agent', hec: 'HEC' };
async function loadTokens() {
  const host = $('#token-list'); if (!host) return;
  let tokens = [];
  try { ({ tokens } = await api('/tokens')); } catch (e) { host.replaceChildren(muted('réservé admin (' + esc(e.message) + ')')); return; }
  const columns = [
    { key: 'name', label: 'Nom', sortable: true, render: t => { const b = document.createElement('b'); b.textContent = t.name; return b; } },
    { key: 'kind', label: 'Type', sortable: true, render: t => { const s = document.createElement('span'); s.className = 'badge'; s.textContent = TOK_KIND_LABEL[t.kind] || t.kind; return s; } },
    { key: 'host', label: 'Hôte lié', render: t => { const c = document.createElement('span'); if (t.host) { c.textContent = t.host; } else { c.className = 'muted'; c.textContent = 'relais — hôte non attesté'; } return c; } },
    { key: 'created', label: 'Créé', sortable: true, sortVal: t => t.created || 0, render: t => t.created ? fmtTs(t.created) : '—' },
    { key: 'last_used', label: 'Dern. usage', sortable: true, sortVal: t => t.last_used || 0, render: t => t.last_used ? fmtTs(t.last_used) : '—' },
    { key: '_act', label: '', align: 'r', render: t => {
        const del = document.createElement('button'); del.className = 'picon'; del.innerHTML = ic('x'); del.title = 'Révoquer le jeton';
        del.onclick = async () => {
          if (!await confirmWithConsequence(`Révoquer le jeton « ${t.name} »`, 'l\'agent ou le forwarder porteur perd l\'accès immédiatement ; un jeton révoqué ne se réactive pas, il faut en provisionner un autre.', { okText: 'Révoquer' })) return;
          try { await apiSend('/tokens/' + encodeURIComponent(t.name), 'DELETE'); toast('jeton révoqué', 'ok'); loadTokens(); }
          catch (e) { toast(e.message || 'échec de la révocation', 'bad'); }
        };
        return del;
      } },
  ];
  // `P11.18-m` — LA RECHERCHE PORTE SUR TOUS LES JETONS : `/api/tokens` rend la table entière, sans borne ni
  // pagination. Le texte cherché est celui des cellules RENDUES — nom, type, hôte lié, dates — jamais le
  // secret, qui n'est ni servi ni affiché (seul son empreinte est stockée).
  // `P11.18-z` — IDENTITÉ DE CETTE LISTE (littérale, stable, propre à elle) : révoquer un jeton et en
  // provisionner un rappellent `loadTokens()`, qui refabrique l'hôte de la liste. La clé ne nomme que la
  // LISTE : aucun secret n'y entre, et rien de cette mémoire n'est écrit hors de la page.
  pagedList(host, { mode: 'client', pageSize: 50, rows: tokens, columns, sort: { key: 'created', dir: -1 }, emptyText: 'aucun jeton — clique « + Nouveau jeton » pour provisionner un agent ou un forwarder HEC.', storeKey: 'soc_admin_tokens', recherche: true });
}
async function newTokenFlow() {
  // P11.5-b : créer un jeton ÉLÈVE un droit (une crédence d'ingest/responder naît) -> la fenêtre de saisie est
  // la confirmation partagée elle-même : elle nomme la conséquence au-dessus des champs.
  const vals = await confirmWithConsequence('Nouveau jeton', 'une crédence d\'accès machine est créée ; son secret n\'est montré qu\'une seule fois, et tout porteur de ce secret pourra écrire des événements sous l\'hôte choisi (un relais : sous n\'importe quel nom d\'hôte).', {
    danger: false,
    okText: 'Créer le jeton',
    fields: [
      { name: 'name', label: 'Nom', placeholder: 'ex: forwarder-siem-01', required: true },
      { name: 'kind', label: 'Type', type: 'select', value: 'agent', options: [
        { value: 'agent', label: 'agent — Bearer (ingest + responder host-lié)' },
        { value: 'hec', label: 'HEC — forwarder Splunk (/services/collector)' },
      ] },
      // P5.2-b — la PORTÉE est une DÉCLARATION, plus une case laissée vide. La vraie garde est SERVEUR
      // (POST /api/tokens refuse « ni hôte ni relais » — même règle que le CLI, même table) ; ce champ
      // existe pour que le choix soit posé ICI, pas subi. Un jeton relais laisse écrire sous N'IMPORTE
      // quel nom d'hôte : c'est le prix d'un forwarder, il doit être choisi les yeux ouverts.
      { name: 'portee', label: 'Portée', type: 'select', value: 'machine', options: [
        { value: 'machine', label: 'machine — lié à un hôte (hôte attesté, responder autorisé sur lui)' },
        { value: 'relais', label: 'relais — forwarder multi-hôtes (hôte DÉCLARÉ par l\'émetteur, NON attesté)' },
      ] },
      { name: 'host', label: 'Hôte lié', placeholder: 'ex: web01.internal — requis pour la portée « machine »' },
    ],
    validate: v => {
      if (!TOK_NAME_RE.test((v.name || '').trim())) return 'nom invalide (alphanumérique, . _ - uniquement)';
      const host = (v.host || '').trim();
      if (v.portee === 'relais' && host) return 'portée « relais » : laissez l\'hôte vide (un relais n\'est lié à aucune machine)';
      if (v.portee !== 'relais' && !host) return 'portée « machine » : l\'hôte est requis (sinon choisissez « relais »)';
      if (host && !TOK_HOST_RE.test(host)) return 'hôte invalide (alphanumérique, . _ - ; ≤ 253 car.)';
      return null;
    },
  });
  if (!vals) return;
  const body = { name: vals.name.trim(), kind: vals.kind };
  if (vals.portee === 'relais') body.relay = true;
  else body.host = vals.host.trim();
  let res;
  try { res = await apiSend('/tokens', 'POST', body); }
  catch (e) { toast(e.message || 'échec de création du jeton', 'bad'); return; }
  loadTokens();
  showTokenOnce(res || {});
}
// SHOW-ONCE : affiche le secret CLAIR une seule fois (copy-box + extrait forwarder HEC prêt à coller). Le
// secret n'existe QUE dans cette réponse -> une fois cette boîte fermée, il n'est plus récupérable.
function showTokenOnce(res) {
  const tok = res.token || '';
  closeModals();
  const ov = document.createElement('div'); ov.className = 'modal-ov';
  const box = document.createElement('div'); box.className = 'modal';
  const h = document.createElement('h3'); h.textContent = `Jeton « ${res.name || ''} » créé`; box.appendChild(h);
  const warn = document.createElement('p'); warn.className = 'modal-msg'; warn.style.color = 'var(--warn)'; warn.style.fontWeight = '600';
  warn.textContent = 'Copie-le maintenant : il ne sera plus jamais affiché (seule son empreinte SHA-256 est stockée).';
  box.appendChild(warn);
  // copy-box (input readonly + bouton copier) ---------------------------------------------------------------
  const cbrow = document.createElement('div'); cbrow.style.cssText = 'display:flex;gap:6px;align-items:stretch;margin:8px 0';
  const inp = document.createElement('input'); inp.readOnly = true; inp.value = tok; inp.className = 'mono'; inp.style.cssText = 'flex:1;font-size:12px'; inp.setAttribute('aria-label', 'Jeton (secret) — à copier maintenant');
  inp.onclick = () => inp.select();
  // P11.4-h : LE geste de copie partagé remplace celui qui était écrit ici. Un secret montré une seule
  // fois est exactement la valeur pour laquelle un échec de presse-papier doit se DIRE : le geste partagé
  // le dit, l'écriture locale se contentait de reprendre son mot.
  const cp = boutonDeCopie(tok, { titre: 'Copier le jeton — il ne sera plus jamais affiché' });
  cbrow.append(inp, cp); box.appendChild(cbrow);
  // extrait prêt à coller ----------------------------------------------------------------------------------
  if (res.kind === 'hec') {
    const lbl = document.createElement('div'); lbl.className = 'muted'; lbl.style.cssText = 'margin:10px 0 4px;font-size:12px'; lbl.textContent = 'Extrait forwarder (HTTP Event Collector, compatible Splunk) :';
    box.appendChild(lbl);
    const snippet = `curl -k https://${location.host}${res.hec_path || '/services/collector'}/event \\\n  -H "Authorization: Splunk ${tok}" \\\n  -d '{"event":"hello depuis mon forwarder","sourcetype":"mon:source"}'`;
    const pre = document.createElement('pre'); pre.className = 'mono'; pre.style.cssText = 'white-space:pre-wrap;word-break:break-all;background:var(--card2);border:1px solid var(--bd);padding:8px;border-radius:6px;font-size:11px;margin:0';
    pre.textContent = snippet;
    box.appendChild(pre);
    const cp2 = boutonDeCopie(snippet, { libelle: 'Copier l\'extrait', titre: 'Copier la commande prête à coller' });
    cp2.style.marginTop = '6px';
    box.appendChild(cp2);
  } else {
    const hint = document.createElement('p'); hint.className = 'muted'; hint.style.fontSize = '12px';
    hint.textContent = res.host
      ? `Jeton agent lié à l'hôte « ${res.host} » : pose PLUME_TOKEN=<jeton> sur cet hôte (ingest + responder).`
      : 'Jeton agent NON lié : ingestion uniquement (pour le responder, recrée un jeton en renseignant un hôte).';
    box.appendChild(hint);
  }
  const act = document.createElement('div'); act.className = 'modal-act';
  const ok = document.createElement('button'); ok.type = 'button'; ok.className = 'm-ok'; ok.textContent = 'J\'ai copié — fermer';
  ok.onclick = () => { ov.remove(); };
  act.appendChild(ok); box.appendChild(act);
  ov.appendChild(box); document.body.appendChild(ov);
  ov.onclick = e => { if (e.target === ov) ov.remove(); };
  setTimeout(() => { inp.focus(); inp.select(); }, 30);
}
if ($('#token-new')) $('#token-new').onclick = newTokenFlow;

export { ROLE_LABEL, loadUsers, loadTokens };
