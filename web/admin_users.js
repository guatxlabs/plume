// admin_users.js — comptes & acces (admin) + jetons agent/HEC (provisioning, show-once)
// Extrait d'app.js (decoupe par concern — meme patron que freshness.js).
// PURE MOVE : corps de fonctions IDENTIQUES au monolithe, seuls les import/export sont ajoutes.
// Le cycle app<->module est benin : les fonctions importees d'app.js ne sont appelees qu'a
// l'EXECUTION (handlers/async apres await), jamais a l'evaluation du module.
import { $, LANG, esc, fmtTs, ic, muted, api, apiSend, confirmWithConsequence, disclosure, laDemandeNAPasAbouti, leRefusEstCeluiDuRole, phraseDuRefusDuDemon, puitsDuRefusDUnGeste, effacerLeRefusDUnGeste, peindreLeRefusDUnGeste, toast, pagedList, closeModals } from './core.js';
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
  // `P10.25-x` — la demande n'a pas abouti (aucune réponse lue) : le démon n'a rien refusé, et rien ici ne dit s'il a
  // pris la modification avant que la réponse ne se perde.
  demande_non_aboutie: {
    fr: "Modification NON confirmée : la demande n'a pas abouti, et rien ici n'établit si le compte a été modifié — vérifier la liste des comptes avant de la rejouer. Cause —",
    en: 'Change NOT confirmed: the request did not complete, and nothing here establishes whether the account was changed — check the account list before replaying it. Cause —' },
};
// Les valeurs se posent par une fonction de remplacement : un détail servi n'est jamais réinterprété.
function motDeLaModificationDeCompte(cle, valeurs = {}) {
  const face = LANG === 'en' ? MOTS_DE_LA_MODIFICATION_DE_COMPTE[cle].en : MOTS_DE_LA_MODIFICATION_DE_COMPTE[cle].fr;
  return face.replace(/\{(\w+)\}/g, (brut, nom) => (Object.prototype.hasOwnProperty.call(valeurs, nom) ? String(valeurs[nom]) : brut));
}
// `P10.25-y` — LES CONFIRMATIONS DES COMPTES, DANS LES DEUX LANGUES. Mesuré avant ce lot : le titre et la conséquence
// de la confirmation de création (« Créer le compte « carol » », « un accès viewer à cette console est ouvert
// immédiatement. »), comme le titre de la confirmation de modification, la conséquence du changement de rôle et celle
// de la réinitialisation du mot de passe d'un AUTRE compte, étaient des chaînes COMPOSÉES (un nom, un rôle s'y
// collent) : le lexique ne remplace qu'un nœud texte ENTIER, il ne les atteignait pas, et elles restaient françaises
// sous `LANG='en'`. Les faces sont côte à côte, `{…}` posés par une fonction de remplacement (un nom servi qui
// contiendrait `$&` ou une accolade n'est jamais réinterprété). Les rôles se disent par leur nom technique, le même
// dans les deux langues (`ROLE_LABEL`).
const MOTS_DES_CONFIRMATIONS_DE_COMPTE = {
  titre_de_la_creation: {
    fr: 'Créer le compte « {nom} »',
    en: 'Create the account “{nom}”' },
  consequence_de_la_creation: {
    fr: 'un accès {role} à cette console est ouvert immédiatement',
    en: 'access to this console with the {role} role is opened immediately' },
  acces_complet: {
    fr: ' — accès complet à la configuration, aux secrets et aux suppressions',
    en: ' — full access to configuration, secrets and deletions' },
  titre_de_la_modification: {
    fr: 'Modifier le compte « {nom} »',
    en: 'Change the account “{nom}”' },
  changement_de_role: {
    fr: 'le rôle de « {nom} » passe de {avant} à {apres}',
    en: 'the role of “{nom}” changes from {avant} to {apres}' },
  perte_de_l_acces_administrateur: {
    fr: " — ce compte perd l'accès administrateur",
    en: ' — this account loses administrator access' },
  mot_de_passe_d_un_autre_compte: {
    fr: "le mot de passe de « {nom} » est remplacé immédiatement (l'ancien cesse de fonctionner)",
    en: 'the password of “{nom}” is replaced immediately (the old one stops working)' },
  separateur_des_consequences: {
    fr: ' ; ',
    en: '; ' },
};
function motDUneConfirmationDeCompte(cle, valeurs = {}) {
  const face = LANG === 'en' ? MOTS_DES_CONFIRMATIONS_DE_COMPTE[cle].en : MOTS_DES_CONFIRMATIONS_DE_COMPTE[cle].fr;
  return face.replace(/\{(\w+)\}/g, (brut, nom) => (Object.prototype.hasOwnProperty.call(valeurs, nom) ? String(valeurs[nom]) : brut));
}
const nomDuRole = (role) => ROLE_LABEL[role] || role;
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
  // `P10.25-x` — sans réponse lue, ce n'est pas un refus : la face le dit, avec ce que le transport a rendu.
  if (laDemandeNAPasAbouti(e)) { peindreLeRefusDeModification(puits, 'demande_non_aboutie', (e && e.message) || String(e), 0); return; }
  if (e && e.statutDuRefus === 429 && e.delaiDuRefus) { peindreLeRefusDeModification(puits, 'refus_nomme_avec_delai', phraseDuRefusDuDemon(e), e.delaiDuRefus); return; }
  peindreLeRefusDeModification(puits, 'refus_nomme', phraseDuRefusDuDemon(e) || ((e && e.message) || String(e)), 0);
}
// `P10.24-v` — LA SUPPRESSION D'UN COMPTE DIT CE QU'ELLE FAIT DE SES OBJETS, ET SON REFUS A UNE FACE.
// CE QUE LE DÉMON FAIT, RELU DANS `user_delete` (daemon/src/handlers/users_lookups.rs) : dans SA transaction, il
// retire le second facteur et les préférences (`P10.24-c`), SUPPRIME les requêtes enregistrées et les instantanés de
// tableau de bord (`OBJETS_PURGES_AVEC_LE_COMPTE`), RÉATTRIBUE à l'auteur de la suppression tableaux de bord, vues,
// panneaux de bibliothèque et playlists, visibilité inchangée (`OBJETS_REATTRIBUES_A_L_AUTEUR`, `P10.24-p`), avance
// l'époque du compte (ses sessions tombent) et atteste chaque objet à l'audit. (Les jetons : voir `P10.25-p`
// ci-dessous — la phrase de `P10.24-v`, « jetons NON révoqués », est devenue fausse.) La confirmation d'avant
// disait seulement « ses sessions et jetons de session cessent de fonctionner… » : rien du sort des objets (sa phrase était au lexique ; son
// titre, composé du nom du compte, restait français sous `LANG='en'`).
// CE QUE LA CONSOLE FAISAIT DU REFUS, MESURÉ AVANT CE LOT : le quatre cents du compte de l'administrateur de
// l'installation (`CAUSE_COMPTE_DE_L_ASSISTANT_NON_SUPPRIMABLE`, `P10.24-n`) partait dans un AVIS qui s'efface,
// « 400 {"error":"COMPTE NON SUPPRIMÉ… » — le corps JSON brut, coupé à deux cents caractères sur une cause qui en
// compte plus de cinq cents, si bien que le remède qu'elle nomme (réinitialiser le mot de passe) n'atteignait
// jamais l'écran — puis la liste se rechargeait. Le refus s'écrit désormais dans le PUITS de la ligne, phrase
// ENTIÈRE, sans accuser l'utilisateur (c'est le démon qui refuse), et la liste n'est pas rechargée : un refus
// n'a rien écrit. CE QUE LA CONSOLE NE PEUT PAS DIRE : quel compte est celui de l'assistant — `/api/users` ne le
// sert pas, aucune autre route non plus ; le signaler dans la liste exige un champ servi.
// `P10.25-p` — LES JETONS DU COMPTE SUPPRIMÉ, ET LE COMPTE RENDU DE LA SUPPRESSION. `user_delete` traite désormais,
// dans SA transaction, les jetons que le compte a FRAPPÉS (`JetonsDuCompteSupprime`, daemon/src/handlers/tokens.rs,
// décision `DECISION_SUR_LES_JETONS_DU_COMPTE_SUPPRIME`) : ceux de LECTURE (source de données, client) et ceux
// d'ingestion JAMAIS SERVIS sont RÉVOQUÉS ; ceux d'ingestion déjà servis (agent, HEC) sont CONSERVÉS — les révoquer
// ferait taire un capteur — et nommés « secret connu d'un compte supprimé », avec le geste : les révoquer et en
// refrapper un ; ceux d'auteur NON ÉTABLI (ligne de commande, clé de livraison, frappe antérieure à la colonne) ne
// sont pas touchés, et leur nombre est dit. Il rend deux cents et ce compte rendu (le même objet que son audit), là
// où il rendait deux cent quatre sans corps. MESURÉ AVANT CE LOT, sur l'arbre qui porte ce démon : la confirmation
// disait « les jetons d'agent et HEC … ne sont PAS révoqués » — FAUX pour les jetons de lecture et ceux jamais
// servis, et muette sur ceux qu'il conserve —, et le compte rendu servi était jeté : la liste se rechargeait en
// silence, le compte disparaissait sans que rien ne dise quel jeton était tombé ni lequel restait à refrapper.
// La confirmation dit la décision ; APRÈS la suppression, le compte rendu est PEINT en tête de la liste rechargée.
const MOTS_DE_LA_SUPPRESSION_DE_COMPTE = {
  titre: {
    fr: 'Supprimer le compte « {nom} »',
    en: 'Delete the account “{nom}”' },
  consequence: {
    fr: "le compte ne se restaure pas : ses sessions cessent de fonctionner, son second facteur et ses préférences sont retirés. Ses tableaux de bord, vues, panneaux de bibliothèque et playlists vous sont RÉATTRIBUÉS, visibilité inchangée ; ses requêtes enregistrées et ses instantanés de tableau de bord sont SUPPRIMÉS. Les jetons qu'il a frappés : ceux de LECTURE (source de données, client) et ceux d'ingestion JAMAIS SERVIS sont RÉVOQUÉS ; ceux d'ingestion déjà servis (agent, HEC) sont CONSERVÉS pour ne pas faire taire un capteur, mais leur secret reste connu d'un compte supprimé — le compte rendu les nommera, pour les révoquer et en refrapper. Les jetons d'auteur non établi (ligne de commande, clé de livraison, frappe antérieure) ne sont pas touchés. Ses actions passées restent dans le journal d'audit, qui atteste aussi chaque objet et chaque jeton traité.",
    en: 'the account cannot be restored: its sessions stop working, its second factor and preferences are removed. Its dashboards, views, library panels and playlists are REASSIGNED to you, visibility unchanged; its saved queries and dashboard snapshots are DELETED. The tokens it minted: READ tokens (data source, client) and ingestion tokens NEVER USED are REVOKED; ingestion tokens already in use (agent, HEC) are KEPT so that no sensor goes silent, but their secret is still known to a deleted account — the report will name them, to revoke and mint new ones. Tokens with no established author (command line, delivery key, earlier mint) are not touched. Its past actions stay in the audit journal, which also records every object and every token handled.' },
  refus_nomme: {
    fr: 'Compte NON supprimé : le démon a refusé et en nomme la cause —',
    en: 'Account NOT deleted: the daemon refused and names the cause —' },
  // `P10.25-x` — la demande n'a pas abouti : ni refus ni suppression établis.
  demande_non_aboutie: {
    fr: "Suppression NON confirmée : la demande n'a pas abouti, et rien ici n'établit si le compte a été supprimé — recharger la liste des comptes avant de la rejouer. Cause —",
    en: 'Deletion NOT confirmed: the request did not complete, and nothing here establishes whether the account was deleted — reload the account list before replaying it. Cause —' },
};
// Les mots du compte rendu, FR et EN côte à côte ; `{…}` posés par une fonction de remplacement.
const MOTS_DU_COMPTE_RENDU_DE_SUPPRESSION = {
  titre: {
    fr: 'Compte « {nom} » supprimé — ce que le démon en a fait :',
    en: 'Account “{nom}” deleted — what the daemon did with it:' },
  sans_compte_rendu: {
    fr: "Compte « {nom} » supprimé ; le démon n'a pas servi de compte rendu lisible — le journal d'audit atteste ce qui a été fait de ses objets et de ses jetons.",
    en: 'Account “{nom}” deleted; the daemon served no readable report — the audit journal records what was done with its objects and tokens.' },
  objets_reattribues: {
    fr: 'objets réattribués à {auteur} : {liste}',
    en: 'objects reassigned to {auteur}: {liste}' },
  objets_purges: {
    fr: 'objets supprimés : {liste}',
    en: 'objects deleted: {liste}' },
  aucun_objet: {
    fr: 'aucun',
    en: 'none' },
  second_facteur_retire: {
    fr: 'second facteur retiré',
    en: 'second factor removed' },
  jeton_revoque: {
    fr: 'jeton RÉVOQUÉ : {jeton} — {raison}',
    en: 'token REVOKED: {jeton} — {raison}' },
  raison_lecture_des_donnees: {
    fr: 'il donnait la lecture des données',
    en: 'it granted reading the data' },
  raison_jamais_servi: {
    fr: "jamais servi, aucun capteur n'en dépendait",
    en: 'never used, no sensor depended on it' },
  jeton_conserve: {
    fr: "jeton CONSERVÉ, secret connu d'un compte supprimé : {jeton} — le révoquer et en refrapper un pour son capteur",
    en: 'token KEPT, secret known to a deleted account: {jeton} — revoke it and mint a new one for its sensor' },
  aucun_jeton: {
    fr: 'aucun jeton frappé par ce compte',
    en: 'no token minted by this account' },
  auteur_non_etabli: {
    fr: "jetons d'auteur non établi, non touchés : {liste}",
    en: 'tokens with no established author, not touched: {liste}' },
};
// Le genre d'un jeton, dans les deux langues ; un genre que le démon ajouterait est dit par son NOM.
const GENRES_DE_JETON = {
  agent: { fr: 'agent', en: 'agent' },
  hec: { fr: 'HEC', en: 'HEC' },
  datasource: { fr: 'source de données', en: 'data source' },
  client: { fr: 'client', en: 'client' },
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
  } else if (laDemandeNAPasAbouti(e)) {
    // `P10.25-x` — aucune réponse lue : « le démon a refusé » serait faux, « NON supprimé » ne serait pas établi.
    dit.textContent = motDeLaSuppressionDeCompte('demande_non_aboutie');
    puits.replaceChildren(dit, document.createTextNode(' « ' + String((e && e.message) || e).trim() + ' »'));
    puits.dataset.refusDeSuppression = 'demande_non_aboutie';
  } else {
    dit.textContent = motDeLaSuppressionDeCompte('refus_nomme');
    const cause = phraseDuRefusDuDemon(e) || ((e && e.message) || String(e));
    puits.replaceChildren(dit, document.createTextNode(' « ' + String(cause).trim() + ' »'));
    puits.dataset.refusDeSuppression = 'refus_nomme';
  }
  puits.hidden = false;
}
// `P10.25-p` — LE COMPTE RENDU DE LA SUPPRESSION, PEINT. Rien n'est inventé : chaque ligne vient d'un champ servi, et
// un champ absent ou d'une autre forme ne produit pas de ligne — sauf le corps entier, dont l'absence se DIT.
function motDuCompteRendu(cle, valeurs = {}) {
  const face = LANG === 'en' ? MOTS_DU_COMPTE_RENDU_DE_SUPPRESSION[cle].en : MOTS_DU_COMPTE_RENDU_DE_SUPPRESSION[cle].fr;
  return face.replace(/\{(\w+)\}/g, (brut, nom) => (Object.prototype.hasOwnProperty.call(valeurs, nom) ? String(valeurs[nom]) : brut));
}
const genreDeJeton = (genre) => (Object.prototype.hasOwnProperty.call(GENRES_DE_JETON, genre)
  ? (LANG === 'en' ? GENRES_DE_JETON[genre].en : GENRES_DE_JETON[genre].fr) : String(genre));
// Un jeton nommé : son nom, son genre, et son hôte lié s'il en a un.
const jetonNomme = (j) => String(j.name) + ' (' + genreDeJeton(j.kind) + (j.host ? ' · ' + String(j.host) : '') + ')';
const estUnObjet = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
// `{table: [identifiants]}` -> « 2 tableau(x) de bord, 1 vue(s) » ; les tables sans objet ne sont pas dites.
function listeDObjets(parTable) {
  const morceaux = Object.keys(parTable).filter(t => Array.isArray(parTable[t]) && parTable[t].length > 0)
    .map(t => motDUneLigneTenueParUnNom(t, parTable[t].length));
  return morceaux.length ? morceaux.join(', ') : motDuCompteRendu('aucun_objet');
}
function noeudDuCompteRenduDeSuppression(nom, compteRendu) {
  const bloc = document.createElement('div'); bloc.style.cssText = 'margin:0 0 10px;font-size:12px';
  bloc.dataset.compteRenduDeSuppression = nom;
  if (!estUnObjet(compteRendu)) {
    bloc.className = 'muted'; bloc.textContent = motDuCompteRendu('sans_compte_rendu', { nom });
    bloc.dataset.compteRenduLu = 'non';
    return bloc;
  }
  const titre = document.createElement('b'); titre.textContent = motDuCompteRendu('titre', { nom });
  const liste = document.createElement('ul'); liste.style.cssText = 'margin:2px 0 0;padding-left:18px';
  const ligne = (texte, genre, alarme) => {
    const li = document.createElement('li'); li.textContent = texte; li.dataset.ligneDuCompteRendu = genre;
    if (alarme) li.className = 'bad';
    liste.appendChild(li);
  };
  if (estUnObjet(compteRendu.objets_reattribues)) ligne(motDuCompteRendu('objets_reattribues', { auteur: compteRendu.objets_reattribues_a || '?', liste: listeDObjets(compteRendu.objets_reattribues) }), 'objets_reattribues');
  if (estUnObjet(compteRendu.objets_purges)) ligne(motDuCompteRendu('objets_purges', { liste: listeDObjets(compteRendu.objets_purges) }), 'objets_purges');
  if (compteRendu.second_facteur_retire === true) ligne(motDuCompteRendu('second_facteur_retire'), 'second_facteur_retire');
  const jetons = compteRendu.jetons;
  if (estUnObjet(jetons)) {
    const revoques = Array.isArray(jetons.revoques) ? jetons.revoques.filter(estUnObjet) : [];
    const conserves = Array.isArray(jetons.conserves_secret_connu) ? jetons.conserves_secret_connu.filter(estUnObjet) : [];
    revoques.forEach(j => {
      const raison = j.raison === 'lecture_des_donnees' ? motDuCompteRendu('raison_lecture_des_donnees')
        : j.raison === 'jamais_servi' ? motDuCompteRendu('raison_jamais_servi') : String(j.raison);
      ligne(motDuCompteRendu('jeton_revoque', { jeton: jetonNomme(j), raison }), 'jeton_revoque');
    });
    // Un jeton CONSERVÉ dont le secret reste connu d'un compte supprimé est dans le registre de l'alarme : il appelle un geste.
    conserves.forEach(j => ligne(motDuCompteRendu('jeton_conserve', { jeton: jetonNomme(j) }), 'jeton_conserve', true));
    if (!revoques.length && !conserves.length) ligne(motDuCompteRendu('aucun_jeton'), 'aucun_jeton');
    if (estUnObjet(jetons.auteur_non_etabli)) {
      const parGenre = Object.keys(jetons.auteur_non_etabli).map(g => String(jetons.auteur_non_etabli[g]) + ' ' + genreDeJeton(g));
      if (parGenre.length) ligne(motDuCompteRendu('auteur_non_etabli', { liste: parGenre.join(', ') }), 'auteur_non_etabli');
    }
  }
  bloc.append(titre, liste);
  bloc.dataset.compteRenduLu = 'oui';
  return bloc;
}
// Posé en TÊTE de la liste rechargée : la ligne du compte n'existe plus, et le compte rendu doit rester sous les yeux.
function peindreLeCompteRenduDeSuppression(nom, compteRendu) {
  const list = $('#user-list'); if (!list) return;
  list.prepend(noeudDuCompteRenduDeSuppression(nom, compteRendu));
}
// `P10.26-o` — UNE LECTURE DES COMPTES REFUSÉE N'EST PAS UN RÔLE REFUSÉ.
// CE QUE LA CONSOLE EN FAISAIT, MESURÉ AVANT CE LOT (témoin 115) : TOUT refus de `/api/users` — le quatre cent trois
// du rôle, mais aussi un refus de l'annuaire, un cinq cent trois nommé, un cinq cents, une page de passerelle, une
// demande qui n'aboutit pas — posait `S.isAdmin = false` et relançait le routeur : l'espace Administration ENTIER
// disparaissait (`uiIsAdmin`, web/multitenant.js), un onglet d'administration ouvert retombait sur la vue
// d'ensemble, et RIEN ne disait pourquoi. Seul le refus du rôle (`leRefusEstCeluiDuRole`, core.js) le pose
// désormais. Un quatre cent un (aucune session) garde le chemin d'avant : l'écran de connexion le dit à
// l'ouverture, et le quatre cent un EN COURS de session est `P10.26-n`. Tout autre refus laisse `S.isAdmin` tel
// qu'il était — il ne dit rien du rôle — et se DIT : dans la liste, et dans un avis quand la section n'est pas
// montrée (le rôle n'a encore jamais été établi, typiquement à l'ouverture).
const MOTS_DE_LA_LECTURE_DES_COMPTES = {
  lecture_non_servie: {
    fr: "Comptes NON LUS : la lecture n'a pas été servie, et ce n'est pas le refus du rôle — rien ici n'établit que ce compte n'administre pas cette console. Réponse reçue —",
    en: 'Accounts NOT READ: the read was not served, and this is not the role refusal — nothing here establishes that this account does not administer this console. Answer received —' },
  demande_non_aboutie: {
    fr: "Comptes NON LUS : la demande n'a pas abouti — rien ici n'établit que ce compte n'administre pas cette console. Cause —",
    en: 'Accounts NOT READ: the request did not complete — nothing here establishes that this account does not administer this console. Cause —' },
};
const motDeLaLectureDesComptes = (cle) => (LANG === 'en' ? MOTS_DE_LA_LECTURE_DES_COMPTES[cle].en : MOTS_DE_LA_LECTURE_DES_COMPTES[cle].fr);
// L'aveu remplace la liste (rien d'elle n'est établi) ; `data-lecture-des-comptes-refusee` porte la clé (marque de
// POSE pour le harnais). Rend la clé peinte.
function peindreLaLectureDesComptesRefusee(list, e) {
  const cle = laDemandeNAPasAbouti(e) ? 'demande_non_aboutie' : 'lecture_non_servie';
  const reponse = String(cle === 'demande_non_aboutie' ? ((e && e.message) || e) : phraseDuRefusDuDemon(e)).trim();
  const aveu = document.createElement('div'); aveu.className = 'bad'; aveu.style.cssText = 'margin:0 0 10px;font-size:12px';
  aveu.setAttribute('role', 'alert');
  const dit = document.createElement('span'); dit.textContent = motDeLaLectureDesComptes(cle);
  aveu.append(dit, ' « ' + reponse + ' »');
  aveu.dataset.lectureDesComptesRefusee = cle;
  list.replaceChildren(aveu);
  if (!S.isAdmin) toast(motDeLaLectureDesComptes(cle) + ' « ' + reponse + ' »', 'bad', 12000);
  return cle;
}
/* state: isAdmin -> S (state.js) */ // /api/users 200 => admin ; refus du RÔLE => non admin ; tout autre refus : inchangé, et dit
async function loadUsers() {
  const sec = $('#users'), list = $('#user-list'); if (!sec || !list) return;
  let d;
  try { d = await api('/users'); }
  catch (e) {
    if (leRefusEstCeluiDuRole(e) || (e && e.statutDuRefus === 401)) { S.isAdmin = false; route(); return; }
    peindreLaLectureDesComptesRefusee(list, e);
    return;
  }
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
      // `P10.25-y` — chaque conséquence vient de sa face, dans la langue de l'écran.
      if (rsel.value !== u.role) parts.push(motDUneConfirmationDeCompte('changement_de_role', { nom: u.name, avant: nomDuRole(u.role), apres: nomDuRole(rsel.value) })
        + (rsel.value === 'admin' ? motDUneConfirmationDeCompte('acces_complet') : u.role === 'admin' ? motDUneConfirmationDeCompte('perte_de_l_acces_administrateur') : ''));
      if (pw.value) parts.push(sonPropreMotDePasse ? motDeLaModificationDeCompte('consequence_de_son_propre_mot_de_passe') : motDUneConfirmationDeCompte('mot_de_passe_d_un_autre_compte', { nom: u.name }));
      if (!parts.length) { motDePasseActuel = ''; toast('aucune modification', 'info'); return; }
      // Un mot de passe actuel absent ne part pas : le démon le refuserait, et rien ne serait appris de plus.
      if (sonPropreMotDePasse && !motDePasseActuel) { peindreLeRefusDeModification(puits, 'mot_de_passe_actuel_manquant', '', 0); return; }
      if (!await confirmWithConsequence(motDUneConfirmationDeCompte('titre_de_la_modification', { nom: u.name }), parts.join(motDUneConfirmationDeCompte('separateur_des_consequences')) + '.', { okText: 'Appliquer', danger: rsel.value === 'admin' || u.role === 'admin' || !!pw.value })) { motDePasseActuel = ''; return; }
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
      let compteRendu;
      try { compteRendu = await apiSend('/users/' + u.id, 'DELETE'); }
      catch (err) { peindreLeRefusDeSuppression(puitsDeSuppression, err); return; }
      // `P10.25-p` — la liste rechargée, puis le compte rendu servi peint en tête (au lieu d'un rechargement muet).
      await loadUsers();
      peindreLeCompteRenduDeSuppression(u.name, compteRendu);
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

// `P10.25-i` — LES REFUS DE LA CRÉATION D'UN COMPTE ONT LEURS FACES, ET CE QUE LE NOM TIENT EST LU.
// CE QUE LE DÉMON SERT, RELU DANS `user_create` (daemon/src/handlers/users_lookups.rs, `P10.24-u` et `P10.24-x`) :
//   · 409 JSON `CAUSE_NOM_DE_L_ADMINISTRATEUR_DE_CONFIGURATION` — le nom de l'administrateur que pose la configuration ;
//   · 409 JSON `CAUSE_NOM_TENU_PAR_UNE_IDENTITE_SANS_COMPTE`, avec `ce_que_le_nom_tient` : `vu_par_l_annuaire`
//     (booléen) et `lignes` (nombre de lignes par table, pour les seules tables où le nom en tient) ;
//   · 503 JSON `CAUSE_NOM_NON_VERIFIE_COMPTE_NON_CREE` — la vérification du nom n'a pas eu lieu ;
//   · 503 JSON `CAUSE_COMPTE_NON_CREE_COMMIT_REFUSE` — le COMMIT refusé ;
//   · 409 TEXTE « ce nom de compte existe déjà », et les quatre cents TEXTE de forme (nom, préfixe, mot de passe).
// CE QUE LE FORMULAIRE EN FAISAIT, MESURÉ AVANT CE LOT : la ligne d'actions (`#uf-result`, encre neutre) recevait le
// message composé par `apiSend` — « 409 {"error":"NOM RÉSERVÉ, C'EST L'ADMINISTRATEUR DE CONFIGURATION : ce nom est
// celui… » —, du JSON brut coupé à deux cents caractères sur des causes de 460, 558, 250 et 224 caractères, si bien
// qu'aucune n'atteignait son remède ; `ce_que_le_nom_tient` n'était lu nulle part (il n'atteignait même pas la
// console : `apiSend` ne le portait pas) ; le « 409 » et le « 400 » précédaient les refus en texte brut.
// LES OUVERTURES S'ANCRENT EN TÊTE, BORNÉES PAR UNICODE, comme celles des refus du second facteur (web/core.js) : le
// témoin 113 relit chaque constante du démon et exige qu'elle soit reconnue ICI. Une cause qui n'ouvre sur aucune
// garde la face générique, qui colle la phrase sans rien en affirmer. Aucune face n'accuse la personne qui crée :
// c'est le démon qui refuse, et chaque face dit ce qui n'est PAS écrit.
const OUVERTURES_DES_REFUS_DE_CREATION_DE_COMPTE = [
  ['nom_de_l_administrateur_de_configuration', /^NOM RÉSERVÉ, C'EST L'ADMINISTRATEUR DE CONFIGURATION(?![\p{L}\p{N}])/u],
  ['nom_tenu_par_une_identite_sans_compte', /^NOM TENU PAR UNE IDENTITÉ SANS COMPTE LOCAL(?![\p{L}\p{N}])/u],
  ['nom_non_verifie', /^COMPTE NON CRÉÉ, NOM NON VÉRIFIÉ(?![\p{L}\p{N}])/u],
  ['commit_refuse', /^COMPTE NON CRÉÉ : la base n'a pas validé la transaction \(COMMIT refusé\)/u],
];
function natureDuRefusDeCreationDeCompte(phrase) {
  const p = String(phrase || '').trim();
  const trouvee = OUVERTURES_DES_REFUS_DE_CREATION_DE_COMPTE.find(([, ouverture]) => ouverture.test(p));
  return trouvee ? trouvee[0] : '';
}
const MOTS_DE_LA_CREATION_DE_COMPTE = {
  refus_nomme: {
    fr: 'Compte NON créé : le démon a refusé et en nomme la cause —',
    en: 'Account NOT created: the daemon refused and names the cause —' },
  nom_de_l_administrateur_de_configuration: {
    fr: "Compte NON créé : ce nom est celui de l'administrateur que pose la configuration du démon, et il est réservé — un compte de ce nom le masquerait. Rien n'est écrit ; choisir un autre nom. Le démon en nomme la cause —",
    en: "Account NOT created: this name is the administrator set by the daemon's configuration, and it is reserved — an account of this name would mask it. Nothing is written; pick another name. The daemon names the cause —" },
  nom_tenu_par_une_identite_sans_compte: {
    fr: "Compte NON créé : ce nom est déjà tenu par une identité sans compte local, et un compte à mot de passe en hériterait. Rien n'est écrit ; choisir un autre nom — une identité de l'annuaire devient un compte par la fédération (OIDC, SAML, LDAP). Le démon en nomme la cause —",
    en: 'Account NOT created: this name is already held by an identity without a local account, and a password account would inherit it. Nothing is written; pick another name — a directory identity becomes an account through federation (OIDC, SAML, LDAP). The daemon names the cause —' },
  nom_non_verifie: {
    fr: "Compte NON créé : le démon n'a pas pu vérifier si ce nom est déjà tenu, et ne crée pas de compte sur un nom non vérifié. Rien n'est écrit ; réessayer. Le démon en nomme la cause —",
    en: 'Account NOT created: the daemon could not check whether this name is already held, and creates no account on an unchecked name. Nothing is written; try again. The daemon names the cause —' },
  commit_refuse: {
    fr: "Compte NON créé : la base n'a pas validé l'écriture et l'a annulée — ni le compte ni sa trace d'audit ne sont écrits. Réessayer. Le démon en nomme la cause —",
    en: 'Account NOT created: the database did not commit the write and rolled it back — neither the account nor its audit trace is written. Try again. The daemon names the cause —' },
  // Une demande qui n'a pas abouti (réseau coupé, requête abandonnée) : le démon n'a rien refusé, et rien ici ne dit
  // s'il a créé le compte avant que la réponse ne se perde.
  demande_non_aboutie: {
    fr: "Création NON confirmée : la demande n'a pas abouti, et rien ici n'établit si le compte a été créé — vérifier la liste des comptes avant de la rejouer. Cause —",
    en: 'Creation NOT confirmed: the request did not complete, and nothing here establishes whether the account was created — check the account list before replaying it. Cause —' },
  ce_que_le_nom_tient: {
    fr: 'Ce que ce nom tient sans compte local :',
    en: 'What this name holds without a local account:' },
  vu_par_l_annuaire: {
    fr: "vu par l'annuaire externe (SSO d'en-têtes) à l'inventaire des accès",
    en: 'seen by the external directory (header SSO) in the access inventory' },
  non_vu_par_l_annuaire: {
    fr: "pas vu par l'annuaire externe à l'inventaire des accès",
    en: 'not seen by the external directory in the access inventory' },
  detail_illisible: {
    fr: "le démon n'a pas servi ce que ce nom tient sous une forme lisible",
    en: 'the daemon did not serve what this name holds in a readable form' },
};
function motDeLaCreationDeCompte(cle) {
  return LANG === 'en' ? MOTS_DE_LA_CREATION_DE_COMPTE[cle].en : MOTS_DE_LA_CREATION_DE_COMPTE[cle].fr;
}
// LES TABLES QUE LE DÉMON COMPTE POUR UN NOM (`colonnes_d_autorite_par_nom` : objets purgés avec un compte, objets
// réattribués à l'auteur de sa suppression, second facteur et préférences), une ligne par table, `{n}` le nombre
// servi. Une table que le démon ajouterait sans mot ici est dite par son NOM, jamais tue (et le témoin 113 refuse
// de conclure tant qu'elle n'a pas de mot).
const MOTS_DES_LIGNES_TENUES_PAR_UN_NOM = {
  dashboard: { fr: '{n} tableau(x) de bord', en: '{n} dashboard(s)' },
  view: { fr: '{n} vue(s)', en: '{n} view(s)' },
  library_panel: { fr: '{n} panneau(x) de bibliothèque', en: '{n} library panel(s)' },
  playlist: { fr: '{n} playlist(s)', en: '{n} playlist(s)' },
  saved_query: { fr: '{n} requête(s) enregistrée(s)', en: '{n} saved query(ies)' },
  dashboard_snapshot: { fr: '{n} instantané(s) de tableau de bord', en: '{n} dashboard snapshot(s)' },
  user_mfa: { fr: '{n} graine(s) du second facteur', en: '{n} second-factor seed(s)' },
  user_pref: { fr: '{n} préférence(s)', en: '{n} preference(s)' },
  table_sans_mot: { fr: '{n} ligne(s) de la table {table}', en: '{n} row(s) of the {table} table' },
};
function motDUneLigneTenueParUnNom(table, n) {
  const mots = Object.prototype.hasOwnProperty.call(MOTS_DES_LIGNES_TENUES_PAR_UN_NOM, table) && table !== 'table_sans_mot'
    ? MOTS_DES_LIGNES_TENUES_PAR_UN_NOM[table] : MOTS_DES_LIGNES_TENUES_PAR_UN_NOM.table_sans_mot;
  const valeurs = { n, table };
  return (LANG === 'en' ? mots.en : mots.fr).replace(/\{(\w+)\}/g, (brut, nom) => (Object.prototype.hasOwnProperty.call(valeurs, nom) ? String(valeurs[nom]) : brut));
}
// La forme servie, jugée pièce par pièce : un détail qu'on ne sait pas lire se DIT, il ne se tait pas.
function ceQueLeNomTientEstLisible(tenue) {
  if (!tenue || typeof tenue !== 'object' || Array.isArray(tenue)) return false;
  if (typeof tenue.vu_par_l_annuaire !== 'boolean') return false;
  const lignes = tenue.lignes;
  return !!lignes && typeof lignes === 'object' && !Array.isArray(lignes);
}
// Le bloc « ce que le nom tient » : l'annuaire d'abord, puis une ligne par table, dans l'ordre servi. Chaque ligne
// porte sa table (`data-table`) : marque de POSE pour le harnais, aucune règle CSS ne la vise.
function noeudDeCeQueLeNomTient(tenue) {
  const bloc = document.createElement('div'); bloc.style.cssText = 'margin:4px 0 0';
  if (!ceQueLeNomTientEstLisible(tenue)) {
    bloc.textContent = motDeLaCreationDeCompte('detail_illisible');
    bloc.dataset.ceQueLeNomTient = 'illisible';
    return bloc;
  }
  const titre = document.createElement('span'); titre.textContent = motDeLaCreationDeCompte('ce_que_le_nom_tient');
  const liste = document.createElement('ul'); liste.style.cssText = 'margin:2px 0 0;padding-left:18px';
  const annuaire = document.createElement('li');
  annuaire.textContent = motDeLaCreationDeCompte(tenue.vu_par_l_annuaire ? 'vu_par_l_annuaire' : 'non_vu_par_l_annuaire');
  annuaire.dataset.vuParLAnnuaire = tenue.vu_par_l_annuaire ? 'oui' : 'non';
  liste.appendChild(annuaire);
  Object.keys(tenue.lignes).forEach(table => {
    const ligne = document.createElement('li'); ligne.dataset.table = table;
    ligne.textContent = motDUneLigneTenueParUnNom(table, tenue.lignes[table]);
    liste.appendChild(ligne);
  });
  bloc.append(titre, liste);
  bloc.dataset.ceQueLeNomTient = 'lu';
  return bloc;
}
// Le puits du refus de création : un seul, sous les champs du formulaire, posé au premier geste. La cause servie
// est ENTIÈRE dans un second nœud ; `data-refus-de-creation` porte la clé de la face (marque de POSE pour le harnais).
function puitsDuRefusDeCreation() {
  const form = $('#user-form'); if (!form) return null;
  let puits = form.querySelector('[data-puits-du-refus-de-creation]');
  if (!puits) {
    puits = document.createElement('div'); puits.className = 'bad'; puits.hidden = true;
    puits.style.cssText = 'margin:0;font-size:12px';
    puits.dataset.puitsDuRefusDeCreation = '1';
    form.appendChild(puits);
  }
  return puits;
}
function peindreLeRefusDeCreation(puits, e) {
  if (!puits) return;
  const dit = document.createElement('span');
  if (e && e.reponseHorsDemon) {
    dit.textContent = String(e.message || '');
    puits.replaceChildren(dit); puits.dataset.refusDeCreation = 'reponse_hors_demon'; puits.hidden = false;
    return;
  }
  // Sans statut, le démon n'a rien répondu : l'erreur vient du transport (`fetch` rejeté), pas d'un refus.
  // `P10.25-x` — le prédicat est désormais celui du point commun, lu aussi par la modification et la suppression.
  const servi = !laDemandeNAPasAbouti(e);
  const cause = servi ? phraseDuRefusDuDemon(e) : String((e && e.message) || e);
  const cle = servi ? (natureDuRefusDeCreationDeCompte(cause) || 'refus_nomme') : 'demande_non_aboutie';
  dit.textContent = motDeLaCreationDeCompte(cle);
  puits.replaceChildren(dit, document.createTextNode(' « ' + String(cause).trim() + ' »'));
  const objet = servi && e.objetDuRefus ? e.objetDuRefus : null;
  if (cle === 'nom_tenu_par_une_identite_sans_compte' || (objet && Object.prototype.hasOwnProperty.call(objet, 'ce_que_le_nom_tient'))) {
    puits.appendChild(noeudDeCeQueLeNomTient(objet ? objet.ce_que_le_nom_tient : undefined));
  }
  puits.dataset.refusDeCreation = cle;
  puits.hidden = false;
}

if ($('#user-new') && $('#user-form')) disclosure($('#user-new'), $('#user-form')); // P11.4-a — dépli partagé
if ($('#uf-cancel')) $('#uf-cancel').onclick = () => $('#user-form').classList.add('hidden');
async function creerLeCompteDuFormulaire(e) {
  e.preventDefault();
  const res = $('#uf-result');
  // `P10.25-i` — un refus précédent s'efface au geste suivant : il ne décrit plus la demande en cours.
  const puits = puitsDuRefusDeCreation();
  if (puits) { puits.hidden = true; puits.replaceChildren(); delete puits.dataset.refusDeCreation; }
  const body = { name: $('#uf-name').value.trim(), password: $('#uf-pw').value, role: $('#uf-role').value };
  // P11.5-b : créer un compte ÉLÈVE un droit (un nouvel accès naît, avec un rôle) -> confirmation partagée.
  // `P10.25-y` — titre et conséquence dans la langue de l'écran.
  if (!await confirmWithConsequence(motDUneConfirmationDeCompte('titre_de_la_creation', { nom: body.name || '?' }),
    motDUneConfirmationDeCompte('consequence_de_la_creation', { role: nomDuRole(body.role) }) + (body.role === 'admin' ? motDUneConfirmationDeCompte('acces_complet') : '') + '.',
    { okText: 'Créer', danger: body.role === 'admin' })) return;
  res.textContent = '...';
  try { await apiSend('/users', 'POST', body); }
  catch (err) { res.textContent = ''; peindreLeRefusDeCreation(puits, err); return; }
  res.textContent = 'compte créé'; $('#uf-name').value = ''; $('#uf-pw').value = ''; $('#user-form').classList.add('hidden'); loadUsers();
}
if ($('#user-form')) $('#user-form').addEventListener('submit', creerLeCompteDuFormulaire);
loadUsers();

// --- Jetons (agent + HEC) : provisioning UI, pendant du CLI `plume-daemon token`. Réservé admin (isAdmin ;
// la vraie garde reste SERVEUR : GET/POST/DELETE /api/tokens sont admin-only). Le secret CLAIR n'est renvoyé
// QU'UNE fois à la création (show-once) : jamais re-affichable (seul son SHA-256 est stocké). Un jeton `hec`
// s'authentifie sur /services/collector (`Authorization: Splunk <tok>`) ; un jeton `agent` host-lié sert le
// responder. Mutations via apiSend (X-CSRF-Token auto) ; tout rendu en textContent (anti-XSS). -------------
const TOK_NAME_RE = /^[A-Za-z0-9_.-]+$/;          // miroir de token_name_ok côté daemon
const TOK_HOST_RE = /^[A-Za-z0-9_.-]{1,253}$/;    // miroir de token_host_ok (chaîne vide = non lié, autorisée)
const TOK_KIND_LABEL = { agent: 'agent', hec: 'HEC' };
// `P10.26-q` — le puits des gestes sur les jetons (frappe, révocation), juste avant la liste : hors de ce que
// `loadTokens` repeint, il survit au rechargement. La forme est celle du point commun (`peindreLeRefusDUnGeste`).
function puitsDesJetons() { const liste = $('#token-list'); return liste ? puitsDuRefusDUnGeste(liste.parentNode, 'jetons', liste) : null; }
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
          const puits = puitsDesJetons(); effacerLeRefusDUnGeste(puits);
          // `P10.26-q` — un refus (« JETON NON RÉVOQUÉ » : le jeton authentifie TOUJOURS) reste sous les yeux, cause entière.
          try { await apiSend('/tokens/' + encodeURIComponent(t.name), 'DELETE'); }
          catch (e) { peindreLeRefusDUnGeste(puits, e); return; }
          toast('jeton révoqué', 'ok'); loadTokens();
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
  const puits = puitsDesJetons(); effacerLeRefusDUnGeste(puits);
  let res;
  // `P10.26-q` — « JETON NON FRAPPÉ » : aucun secret n'est montré, et la face le dit à côté de la liste.
  try { res = await apiSend('/tokens', 'POST', body); }
  catch (e) { peindreLeRefusDUnGeste(puits, e); return; }
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
// `P10.25-i` — le geste de création (joué par le harnais sous chaque instance de langue : les deux instances
// écoutent le même formulaire, un envoi du formulaire les réveillerait ensemble), la nature d'un refus et ses faces
// (témoin 113).
// `P10.25-p` — les faces du compte rendu de la suppression (témoin 113).
// `P10.25-y` — les faces des confirmations (témoin 114).
// `P10.26-q` / `P10.26-o` — le geste de frappe d'un jeton (joué sous chaque instance de langue : le bouton
// `#token-new` n'écoute que la dernière importée) et les faces de la lecture des comptes refusée (témoin 115).
export { ROLE_LABEL, loadUsers, loadTokens, newTokenFlow, motDeLaModificationDeCompte, motDeLaSuppressionDeCompte, creerLeCompteDuFormulaire, natureDuRefusDeCreationDeCompte, motDeLaCreationDeCompte, motDUneLigneTenueParUnNom, motDuCompteRendu, motDUneConfirmationDeCompte, motDeLaLectureDesComptes };
