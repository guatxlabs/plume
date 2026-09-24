// admin_users.js — comptes & acces (admin) + jetons agent/HEC (provisioning, show-once)
// Extrait d'app.js (decoupe par concern — meme patron que freshness.js).
// PURE MOVE : corps de fonctions IDENTIQUES au monolithe, seuls les import/export sont ajoutes.
// Le cycle app<->module est benin : les fonctions importees d'app.js ne sont appelees qu'a
// l'EXECUTION (handlers/async apres await), jamais a l'evaluation du module.
import { $, LANG, esc, fmtTs, ic, muted, api, apiSend, confirmWithConsequence, disclosure, phraseDuRefusDuDemon, toast, pagedList, closeModals } from './core.js';
import { S } from './state.js';
// P11.4-h : LE geste de copie de la console (mécanisme partagé).
import { boutonDeCopie } from './copie_et_selection.js';
import { route } from './app.js';

// --- Comptes & accès (réservé admin ; vit sous Réglages : la VISIBILITE est pilotee par le routeur) ---
const ROLE_LABEL = { admin: 'admin', editor: 'editor', viewer: 'viewer' };
// `P10.24-a` (démon) — SON PROPRE MOT DE PASSE SE CHANGE PAR LE MOT DE PASSE ACTUEL. `user_update`
// (daemon/src/handlers/users_lookups.rs) exige `current` quand la cible est l'APPELANT et que le corps change le mot
// de passe : même preuve, même verrou (compte, adresse) et mêmes refus nommés que `/api/password`. Cet éditeur
// envoyait `{role, password}` sur la seule session ; il demande désormais le mot de passe actuel sur la ligne de
// l'appelant, dans un champ PROPRE À CETTE LIGNE, lu puis VIDÉ à chaque geste — la valeur ne vit que le temps de la
// requête, dans la fonction du geste, et n'atteint ni un état du module ni le stockage du site. Le mot de passe
// d'un AUTRE compte se réinitialise toujours sans le vôtre (geste d'administration, attesté au registre).
// Tout refus — nommé par le démon, local, ou venu d'une passerelle — s'écrit dans le PUITS de la ligne, qui reste
// sous les yeux, au lieu d'un avis qui s'efface. Les phrases, FR et EN côte à côte.
const MOTS_DE_LA_MODIFICATION_DE_COMPTE = {
  mot_de_passe_actuel: {
    fr: 'votre mot de passe actuel (exigé pour changer le vôtre)',
    en: 'your current password (required to change yours)' },
  mot_de_passe_actuel_manquant: {
    fr: "Mot de passe NON changé : votre mot de passe actuel est exigé pour changer le vôtre. Rien n'a été envoyé.",
    en: 'Password NOT changed: your current password is required to change yours. Nothing was sent.' },
  refus_nomme: {
    fr: 'Compte NON modifié : le démon a refusé et en nomme la cause —',
    en: 'Account NOT changed: the daemon refused and names the cause —' },
  refus_nomme_avec_delai: {
    fr: 'Compte NON modifié : trop d\'échecs depuis cette adresse, réessayez dans {delai} s. Le démon en nomme la cause —',
    en: 'Account NOT changed: too many failures from this address, try again in {delai} s. The daemon names the cause —' },
  consequence_de_son_propre_mot_de_passe: {
    fr: 'votre propre mot de passe est remplacé immédiatement : vos sessions sont révoquées, et il faudra vous reconnecter avec le nouveau',
    en: 'your own password is replaced immediately: your sessions are revoked, and you will have to sign in again with the new one' },
};
// Les valeurs se posent par une fonction de remplacement : un détail servi n'est jamais réinterprété.
function motDeLaModificationDeCompte(cle, valeurs = {}) {
  const face = LANG === 'en' ? MOTS_DE_LA_MODIFICATION_DE_COMPTE[cle].en : MOTS_DE_LA_MODIFICATION_DE_COMPTE[cle].fr;
  return face.replace(/\{(\w+)\}/g, (brut, nom) => (Object.prototype.hasOwnProperty.call(valeurs, nom) ? String(valeurs[nom]) : brut));
}
// Le puits d'une ligne : la phrase dans un nœud texte ENTIER (traduisible), la cause servie dans un SECOND nœud,
// telle quelle. `data-refus-de-modification` porte la clé de la face (marque de POSE pour le harnais).
function peindreLeRefusDeModification(puits, cle, cause, delai) {
  if (!puits) return;
  const dit = document.createElement('span');
  dit.textContent = motDeLaModificationDeCompte(cle, { delai });
  if (cause) puits.replaceChildren(dit, document.createTextNode(' « ' + String(cause).trim() + ' »'));
  else puits.replaceChildren(dit);
  puits.dataset.refusDeModification = cle;
  puits.hidden = false;
}
// Un refus JETÉ par `apiSend` : une réponse de passerelle se dit par sa propre phrase (le démon n'a rien refusé) ;
// tout autre porte la phrase que le démon a écrite, en JSON ou en texte brut, et le délai d'un verrou.
function peindreLeRefusJete(puits, e) {
  if (!puits) return;
  if (e && e.reponseHorsDemon) {
    const dit = document.createElement('span'); dit.textContent = String(e.message || '');
    puits.replaceChildren(dit); puits.dataset.refusDeModification = 'reponse_hors_demon'; puits.hidden = false;
    return;
  }
  if (e && e.statutDuRefus === 429 && e.delaiDuRefus) { peindreLeRefusDeModification(puits, 'refus_nomme_avec_delai', phraseDuRefusDuDemon(e), e.delaiDuRefus); return; }
  peindreLeRefusDeModification(puits, 'refus_nomme', phraseDuRefusDuDemon(e) || ((e && e.message) || String(e)), 0);
}
// `P10.24-v` — LA SUPPRESSION D'UN COMPTE DIT CE QU'ELLE FAIT DE SES OBJETS, ET SON REFUS A UNE FACE.
// CE QUE LE DÉMON FAIT, RELU DANS `user_delete` (daemon/src/handlers/users_lookups.rs) : dans SA transaction, il
// retire le second facteur et les préférences (`P10.24-c`), SUPPRIME les requêtes enregistrées et les instantanés de
// tableau de bord (`OBJETS_PURGES_AVEC_LE_COMPTE`), RÉATTRIBUE à l'auteur de la suppression tableaux de bord, vues,
// panneaux de bibliothèque et playlists, visibilité inchangée (`OBJETS_REATTRIBUES_A_L_AUTEUR`, `P10.24-p`), avance
// l'époque du compte (ses sessions tombent) et atteste chaque objet à l'audit. Il ne touche pas aux jetons d'agent
// et HEC : la table n'a aucune colonne d'auteur (`P10.24-w`). La confirmation d'avant disait seulement « ses
// sessions et jetons de session cessent de fonctionner… » : rien du sort des objets (sa phrase était au lexique ; son
// titre, composé du nom du compte, restait français sous `LANG='en'`).
// CE QUE LA CONSOLE FAISAIT DU REFUS, MESURÉ AVANT CE LOT : le quatre cents du compte de l'administrateur de
// l'installation (`CAUSE_COMPTE_DE_L_ASSISTANT_NON_SUPPRIMABLE`, `P10.24-n`) partait dans un AVIS qui s'efface,
// « 400 {"error":"COMPTE NON SUPPRIMÉ… » — le corps JSON brut, coupé à deux cents caractères sur une cause qui en
// compte plus de cinq cents, si bien que le remède qu'elle nomme (réinitialiser le mot de passe) n'atteignait
// jamais l'écran — puis la liste se rechargeait. Le refus s'écrit désormais dans le PUITS de la ligne, phrase
// ENTIÈRE, sans accuser l'utilisateur (c'est le démon qui refuse), et la liste n'est pas rechargée : un refus
// n'a rien écrit. CE QUE LA CONSOLE NE PEUT PAS DIRE : quel compte est celui de l'assistant — `/api/users` ne le
// sert pas, aucune autre route non plus ; le signaler dans la liste exige un champ servi.
const MOTS_DE_LA_SUPPRESSION_DE_COMPTE = {
  titre: {
    fr: 'Supprimer le compte « {nom} »',
    en: 'Delete the account “{nom}”' },
  consequence: {
    fr: "le compte ne se restaure pas : ses sessions cessent de fonctionner, son second facteur et ses préférences sont retirés. Ses tableaux de bord, vues, panneaux de bibliothèque et playlists vous sont RÉATTRIBUÉS, visibilité inchangée ; ses requêtes enregistrées et ses instantanés de tableau de bord sont SUPPRIMÉS. Les jetons d'agent et HEC, rattachés à aucun compte, ne sont PAS révoqués par ce geste. Ses actions passées restent dans le journal d'audit, qui atteste aussi chaque objet réattribué ou supprimé.",
    en: 'the account cannot be restored: its sessions stop working, its second factor and preferences are removed. Its dashboards, views, library panels and playlists are REASSIGNED to you, visibility unchanged; its saved queries and dashboard snapshots are DELETED. Agent and HEC tokens, tied to no account, are NOT revoked by this action. Its past actions stay in the audit journal, which also records every object reassigned or deleted.' },
  refus_nomme: {
    fr: 'Compte NON supprimé : le démon a refusé et en nomme la cause —',
    en: 'Account NOT deleted: the daemon refused and names the cause —' },
};
function motDeLaSuppressionDeCompte(cle, valeurs = {}) {
  const face = LANG === 'en' ? MOTS_DE_LA_SUPPRESSION_DE_COMPTE[cle].en : MOTS_DE_LA_SUPPRESSION_DE_COMPTE[cle].fr;
  return face.replace(/\{(\w+)\}/g, (brut, nom) => (Object.prototype.hasOwnProperty.call(valeurs, nom) ? String(valeurs[nom]) : brut));
}
// Le puits du refus de suppression d'une ligne : une réponse de passerelle garde sa propre phrase (rien n'y établit ce
// que le démon a fait) ; tout autre refus porte la phrase que le démon a écrite, ENTIÈRE, dans un second nœud.
// `data-refus-de-suppression` porte la clé de la face (marque de POSE pour le harnais).
function peindreLeRefusDeSuppression(puits, e) {
  if (!puits) return;
  const dit = document.createElement('span');
  if (e && e.reponseHorsDemon) {
    dit.textContent = String(e.message || '');
    puits.replaceChildren(dit); puits.dataset.refusDeSuppression = 'reponse_hors_demon';
  } else {
    dit.textContent = motDeLaSuppressionDeCompte('refus_nomme');
    const cause = phraseDuRefusDuDemon(e) || ((e && e.message) || String(e));
    puits.replaceChildren(dit, document.createTextNode(' « ' + String(cause).trim() + ' »'));
    puits.dataset.refusDeSuppression = 'refus_nomme';
  }
  puits.hidden = false;
}
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
  // `P10.7-f` — UNE LISTE DE COMPTES NON LUE N'EST PAS « ZÉRO COMPTE ». Le démon sert, en 200,
  // `{users: [], me, acces, error: <cause>}` quand la lecture de la table a échoué
  // (`corps_de_liste_illisible`, daemon/src/handlers/users_lookups.rs) : la forme est intacte et toutes
  // ses clés sont vides. Le récapitulatif « 0 compte(s) · 0 admin · … » est un COMPTE, c'est-à-dire un
  // fait — le peindre sur une lecture jamais faite affirme, sur l'inventaire des accès, que personne
  // n'a de compte. La cause servie est écrite telle quelle, et rien d'autre n'est peint ici.
  // `acces` ci-dessus, lui, est LU dans le même corps : c'est un constat, il reste rendu.
  if (d.error) {
    const aveu = document.createElement('div'); aveu.className = 'bad'; aveu.style.cssText = 'margin:0 0 10px;font-size:12px';
    const dit = document.createElement('span');
    dit.textContent = 'Comptes NON LUS : le démon a refusé et en nomme la cause —';
    aveu.append(dit, ' « ' + String(d.error).trim() + ' »');
    list.appendChild(aveu);
    return;
  }
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
    // `P10.24-a` — la ligne de l'APPELANT porte le champ du mot de passe actuel ; aucune autre ne le porte.
    const soi = u.name === me;
    const actuel = soi ? document.createElement('input') : null;
    if (actuel) {
      actuel.type = 'password'; actuel.className = 'ue-pw'; actuel.autocomplete = 'current-password';
      actuel.placeholder = motDeLaModificationDeCompte('mot_de_passe_actuel');
      actuel.dataset.motDePasseActuel = '1';   // marque de POSE (harnais) : aucune règle CSS ne la vise
    }
    const puits = document.createElement('div'); puits.className = 'bad'; puits.hidden = true;
    puits.style.cssText = 'margin:6px 0 0;font-size:12px;flex-basis:100%';
    const save = document.createElement('button'); save.type = 'button'; save.className = 'btn btn-sm'; save.textContent = 'Enregistrer';
    save.onclick = async () => {
      puits.hidden = true; puits.replaceChildren(); delete puits.dataset.refusDeModification;
      // Le mot de passe actuel est LU puis VIDÉ ici, quelle que soit l'issue du geste (envoi, refus, annulation).
      let motDePasseActuel = actuel ? actuel.value : '';
      if (actuel) actuel.value = '';
      const sonPropreMotDePasse = soi && !!pw.value;
      const body = { role: rsel.value }; if (pw.value) body.password = pw.value;
      // P11.5-b : changer un RÔLE élève ou retire un droit ; réinitialiser un MOT DE PASSE remplace une
      // crédence. Les deux passent par la confirmation partagée, qui nomme ce qui change.
      const parts = [];
      if (rsel.value !== u.role) parts.push(`le rôle de « ${u.name} » passe de ${ROLE_LABEL[u.role] || u.role} à ${ROLE_LABEL[rsel.value] || rsel.value}` + (rsel.value === 'admin' ? ' — accès complet à la configuration, aux secrets et aux suppressions' : u.role === 'admin' ? ' — ce compte perd l\'accès administrateur' : ''));
      if (pw.value) parts.push(sonPropreMotDePasse ? motDeLaModificationDeCompte('consequence_de_son_propre_mot_de_passe') : `le mot de passe de « ${u.name} » est remplacé immédiatement (l\'ancien cesse de fonctionner)`);
      if (!parts.length) { motDePasseActuel = ''; toast('aucune modification', 'info'); return; }
      // Un mot de passe actuel absent ne part pas : le démon le refuserait, et rien ne serait appris de plus.
      if (sonPropreMotDePasse && !motDePasseActuel) { peindreLeRefusDeModification(puits, 'mot_de_passe_actuel_manquant', '', 0); return; }
      if (!await confirmWithConsequence(`Modifier le compte « ${u.name} »`, parts.join(' ; ') + '.', { okText: 'Appliquer', danger: rsel.value === 'admin' || u.role === 'admin' || !!pw.value })) { motDePasseActuel = ''; return; }
      if (sonPropreMotDePasse) body.current = motDePasseActuel;
      try { await apiSend('/users/' + u.id, 'POST', body); }
      catch (err) { peindreLeRefusJete(puits, err); return; }
      finally { motDePasseActuel = ''; delete body.current; }
      // Son propre mot de passe changé, ses sessions sont révoquées (`P10.23-l`) : la console ne prétend pas le
      // contraire — le rechargement ramène à l'écran de connexion, que la confirmation vient d'annoncer.
      if (sonPropreMotDePasse) { location.reload(); return; }
      toast('compte mis à jour', 'ok'); loadUsers();
    };
    if (actuel) editor.append(rsel, pw, actuel, save, puits);
    else editor.append(rsel, pw, save, puits);
    const ed = document.createElement('button'); ed.className = 'picon'; ed.title = 'Éditer (rôle / mot de passe)'; ed.textContent = '✎';
    ed.onclick = () => editor.classList.toggle('hidden');
    const del = document.createElement('button'); del.className = 'picon'; del.innerHTML = ic('x'); del.title = 'Supprimer le compte';
    if (u.name === me) del.disabled = true;
    // `P10.24-v` — le puits du refus de suppression suit l'éditeur de la ligne, hors de lui : l'éditeur est replié.
    const puitsDeSuppression = document.createElement('div'); puitsDeSuppression.className = 'bad'; puitsDeSuppression.hidden = true;
    puitsDeSuppression.style.cssText = 'margin:0 0 8px;font-size:12px';
    del.onclick = async () => {
      puitsDeSuppression.hidden = true; puitsDeSuppression.replaceChildren(); delete puitsDeSuppression.dataset.refusDeSuppression;
      if (!await confirmWithConsequence(motDeLaSuppressionDeCompte('titre', { nom: u.name }), motDeLaSuppressionDeCompte('consequence'), { okText: 'Supprimer' })) return;
      try { await apiSend('/users/' + u.id, 'DELETE'); }
      catch (err) { peindreLeRefusDeSuppression(puitsDeSuppression, err); return; }
      loadUsers();
    };
    // BATCH 2 (B3b) : ✎ + ✕ groupés à droite (sinon space-between les écarte) -> un span .urow-actions.
    const actions = document.createElement('span'); actions.className = 'urow-actions'; actions.append(ed, del);
    row.append(info, actions); list.appendChild(row); list.appendChild(editor); list.appendChild(puitsDeSuppression);
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
  // `P10.7-f` — L'INVENTAIRE DES JETONS EST ENTIER OU AVOUÉ, ET LA CONSOLE LIT L'AVEU. Le démon sert, en
  // 200, `{tokens: [], error: <cause>}` quand la lecture a échoué (`corps_de_liste_illisible`,
  // daemon/src/handlers/tokens.rs) : le corps garde sa forme, et le texte de vide ci-dessous offrirait
  // « + Nouveau jeton » comme remède à une absence que personne n'a établie — sur l'inventaire des ACCÈS
  // MACHINE, c'est-à-dire là où un jeton qu'on ne voit pas est un jeton qu'on ne révoque pas.
  // LA RÉPONSE EST LIÉE, ELLE N'EST PLUS DÉCONSTRUITE : `({tokens} = await api(…))` jetait le corps, et
  // l'aveu partait avec lui — aucune ligne du module ne pouvait plus le lire.
  let rep;
  try { rep = await api('/tokens'); } catch (e) { host.replaceChildren(muted('réservé admin (' + esc(e.message) + ')')); return; }
  if (rep.error) {
    const aveu = document.createElement('div'); aveu.className = 'bad'; aveu.style.cssText = 'margin:0;font-size:12px';
    const dit = document.createElement('span');
    dit.textContent = 'Jetons NON LUS : le démon a refusé et en nomme la cause —';
    aveu.append(dit, ' « ' + String(rep.error).trim() + ' »');
    host.replaceChildren(aveu);
    return;
  }
  const tokens = rep.tokens || [];
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

// `P10.24-a` — `motDeLaModificationDeCompte` part pour le harnais ESM (témoin 110) : les faces s'y jugent sous les deux
// instances de langue, contre ce que l'éditeur réel peint. Aucun usage applicatif hors de ce module.
// `P10.24-v` — `motDeLaSuppressionDeCompte` de même (témoin 112).
export { ROLE_LABEL, loadUsers, loadTokens, motDeLaModificationDeCompte, motDeLaSuppressionDeCompte };
