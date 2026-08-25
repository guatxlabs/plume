// alerts.js — file d'alertes : rendu, triage groupe, drill, export, filtres MITRE/source
// Extrait d'app.js (decoupe par concern — meme patron que freshness.js).
// Extrait d'app.js en PURE MOVE ; depuis P11.1 : lien de recherche servi par le démon, barre d'actions unique.
// Le cycle app<->module est benin : les fonctions importees d'app.js ne sont appelees qu'a
// l'EXECUTION (handlers/async apres await), jamais a l'evaluation du module.
import { $, esc, sev, fmtTs, ic, withBusy, api, apiSend, makePager, exportBar, confirmModal, mitreName, LANG, toast } from './core.js';
import { S } from './state.js';
import { banIp, runQuery, updateZoomBadge } from './viz.js';
import { canEditCases, addToCase, openCase } from './cases.js';
import { refresh, updateRangeBtn } from './app.js';
// P11.1-f : LE champ de recherche partagé des listes (`P11.12-a`) — normalisation, prédicat ET multi-mots,
// filtre sur des lignes déjà en mémoire, câblage du champ, résumé. Aucun second mécanisme n'est écrit ici.
import { champDeRecherche, filtrerParRecherche, resumeDeRecherche, texteCherchable } from './recherche_de_liste.js';
// P11.4-h : LE clic qui respecte une sélection (mécanisme partagé).
import { clicQuiRespecteLaSelection } from './copie_et_selection.js';

// clic sur une alerte -> ouvre l'Explore sur ce que la règle a COMPTÉ.
// P11.1-a — LE LIEN EST CONSTRUIT PAR LE DÉMON (`search_link` sur /api/alerts : requête dont la règle a
// agrégé le résultat + fenêtre EXACTE de l'évaluation, cf. lien_de_recherche_de_regle). Le navigateur ne
// dérive plus rien pour une alerte de règle : une seule construction, la même que celle que le test
// `le_lien_de_chaque_regle_livree_reproduit_la_valeur_de_la_regle` exécute contre chaque règle livrée.
// Sans lien (alerte d'un collecteur, heartbeat, alerte écrite sur un instantané, règle supprimée) : le seul
// repli qui subsiste est l'ADRESSE lue dans le texte, sur la fenêtre de l'alerte ; ce repli n'est PAS un lien
// de recherche exact, et il ne concerne que les alertes qui ne viennent pas d'une règle (la propriété P11.1-a
// porte sur les règles). Le repli « sinon le titre » a été RETIRÉ (`P11.14-b`, ci-dessous).
// LIMITE CONNUE (hors de ce module) : la barre Explore ne reconnaît le GXQL que par `search` ou un `|`
// (viz.js runQuery) ; un lien `metric <nom>` nu — règle `metric … | stats max(value)` — y est pris pour du
// SQL brut. Le remède est dans viz.js (`looksLikeSoql` de soql_complete.js reconnaît `metric`).
// P11.14-b — DE QUOI CETTE ALERTE PERMET-ELLE DE PIVOTER ? La question porte sur ce que l'alerte PORTE,
// jamais sur le nom de sa règle : une liste de noms vieillirait en silence, une propriété non. Trois
// réponses, et la troisième est un REFUS.
//   'exact'   — le démon a construit le lien (`search_link`) : la requête telle qu'elle a COMPTÉ, sur la
//               fenêtre EXACTE de l'évaluation. C'est le seul pivot dont le VIDE prouverait quelque chose.
//   'adresse' — pas de lien, mais le texte de l'alerte porte une ADRESSE : un OBSERVABLE, que les
//               événements peuvent réellement contenir. Repli historique, conservé au caractère près
//               (même requête, même fenêtre) ; son survol dit seulement qu'il n'est pas la requête exacte.
//   'aucun'   — ni l'un ni l'autre : la console REFUSE de pivoter, et dit pourquoi.
// CE QUE LA TROISIÈME BRANCHE REMPLACE (mesuré le 2026-08-25) : la console prenait le TITRE, le coupait au
// premier deux-points et lançait une recherche plein texte sur ce fragment. Pour une alerte écrite à partir
// d'un INSTANTANÉ — ni règle, ni fenêtre, donc aucun lien (cf. `daemon/src/ingest/mod.rs`, voie snapshot) —
// cela revenait à chercher dans les événements une phrase que le produit venait de composer POUR L'ÉCRAN :
// aucun événement ne la porte, et le vide rendu se lit comme une panne de collecte. Le démon écrit
// d'ailleurs, à l'endroit même où il renonce au lien (`daemon/src/handlers/alerts.rs`), que le front
// « n'a alors rien d'exact à proposer et le dit » : c'est ce contrat-là que cette branche tient enfin.
// CE QUE CETTE BRANCHE NE PEUT PAS FAIRE, ET POURQUOI ELLE NE LE FEINT PAS : renvoyer vers l'instantané qui
// FONDE l'alerte. Rien dans ce que /api/alerts sert ne DÉCLARE cette fondation ni ne nomme une destination ;
// la deviner d'un jeton de règle serait refaire, un étage plus haut, la fabrication qu'on retire ici.
// LES TROIS PHRASES SONT BILINGUES PAR CONSTRUCTION (`{fr, en}` choisi par LANG) : elles sont écrites UNE
// fois et servent au survol du titre COMME au refus dit au clic — deux formulations divergeraient.
const PIVOT_MOTS = {
  exact: { fr: 'Cliquer → voir les événements déclencheurs', en: 'Click → see the triggering events' },
  adresse: { fr: "Cliquer → chercher cette adresse (src_ip) dans les événements ; l'alerte ne porte pas la requête exacte d'une règle.", en: 'Click → search this address (src_ip) in the events; this alert carries no exact rule query.' },
  aucun: { fr: "Aucun pivot exact : cette alerte n'a ni règle ni fenêtre d'évaluation, elle n'a donc pas été levée par une recherche d'événements. La console refuse d'en fabriquer une — chercher son libellé rendrait un vide qui ne prouverait rien, alors que sa justification est l'état qu'elle porte.", en: 'No exact pivot: this alert has neither rule nor evaluation window, so it was not raised by an event search. The console refuses to make one up — searching its wording would return an emptiness that proves nothing, whereas its justification is the state it carries.' },
};
const motDuPivot = (mode) => (LANG === 'en' ? PIVOT_MOTS[mode].en : PIVOT_MOTS[mode].fr);
function pivotDUneAlerte(a) {
  a = a || {};
  const lien = a.search_link && a.search_link.query ? a.search_link : null;
  // La fenêtre du lien est celle de l'évaluation : [ts - window_s, ts], sans marge — une marge rendait
  // le lien PLUS LARGE que le compte sur toutes les règles (mesuré P11.1-a).
  if (lien) return { mode: 'exact', query: lien.query, from: lien.from, to: lien.to, survol: motDuPivot('exact') };
  const ipm = ((a.title || '') + ' ' + (a.detail || '')).match(ALERT_IP_RE);
  if (ipm) {
    const w = (a.window_s || 3600);
    return {
      mode: 'adresse', query: 'search src_ip:' + ipm[0], adresse: ipm[0],
      from: a.ts ? Math.floor(a.ts - w) : null, to: a.ts ? Math.ceil(a.ts) : null,
      survol: motDuPivot('adresse'),
    };
  }
  return { mode: 'aucun', query: '', from: null, to: null, survol: motDuPivot('aucun') };
}
// Rend true si le pivot a EU LIEU, false s'il a été refusé — l'appelant n'a pas à redériver la réponse.
function alertDrill(a) {
  if (!a) return false;
  const pivot = pivotDUneAlerte(a);
  // LE REFUS EST UN GESTE, PAS UN SILENCE — même grammaire que le refus d'écriture partagé (core.js,
  // `P11.4-l`) : la raison est écrite UNE fois, portée par le survol du contrôle, et le clic la DIT.
  // RIEN d'autre ne bouge : ni l'onglet courant, ni le champ de requête, ni la fenêtre de zoom partagée.
  if (pivot.mode === 'aucun') { toast(pivot.survol, 'bad', 6000); return false; }
  if (pivot.from != null && pivot.to != null) {
    S.zoomRange = { from: pivot.from, to: pivot.to };
    updateZoomBadge(); if (typeof updateRangeBtn === 'function') updateRangeBtn();
  }
  location.hash = 'explore';
  if ($('#sql')) { $('#sql').value = pivot.query; runQuery(); }
  return true;
}
// PURPLE — filtre actif sur les alertes par technique MITRE (pivot depuis le panneau couverture ou un
// chip d'alerte). '' = aucun filtre (toutes les alertes). Cf. ?mitre= côté daemon (index idx_alert_mitre_ts,
// dont `mitre` est la colonne de TÊTE ; le idx_alert_mitre(mitre) seul, préfixe strict, a été retiré P10.2-d).
/* state: alertMitreFilter -> S (state.js) */
// BATCH 1 : la vue MITRE « tous statuts » (historique de détection, potentiellement grande) est PAGINÉE
// côté serveur (LIMIT/OFFSET + total). Page courante remise à 0 dès qu'un filtre change.
const ALERT_HIST_PS = 50;
/* state: alertHistPage -> S (state.js) */
// TRIAGE GROUPÉ (« 1 groupe = N occurrences ») — rend la file gérable au volume (10^4/j). Axe de
// regroupement de la file d'alertes : '' = vue PLATE (backlog classique, comportement historique inchangé) ;
// 'rule'|'host'|'mitre' = liste de GROUPES paginée serveur (/api/alerts/groups), chaque groupe REPLIABLE et
// expansé à la demande (occurrences paginées via le chemin plat gkey/gval). N'affecte QUE la file par défaut
// (jamais les drills mitre/source). alertGroupAll : groupes des alertes ACTIVES (status=new) vs TOUS statuts.
/* state: alertGroupBy -> S (state.js) */
/* state: alertGroupAll -> S (state.js) */
/* state: alertGroupPage -> S (state.js) */
const ALERT_GROUP_PS = 25;   // groupes par page
const ALERT_OCC_PS = 25;     // occurrences par page dans un groupe déplié
function setAlertGroupBy(g) { S.alertGroupBy = alert_group_axis(g) ? g : ''; S.alertGroupPage = 0; S.alertHistPage = 0; location.hash = 'alerts'; renderAlerts(true); }
function alert_group_axis(g) { return g === 'rule' || g === 'host' || g === 'mitre'; }
// le pivot MITRE amène vers Investigation -> Alertes (onglet #alerts, où vivent les Alertes actives, cf. SPACES).
// P11.1-b — un pivot MITRE pose une FACETTE sur la même liste : portée « tous statuts » (l'historique de
// détection de la technique, comportement historique), sans le filtre d'affichage, tri inchangé.
function setAlertMitreFilter(m) {
  S.alertMitreFilter = (m || '').trim().toUpperCase(); S.alertSourceFilter = ''; S.alertHistPage = 0; S.alertGroupPage = 0;
  if (S.alertMitreFilter) { S.alertGroupAll = true; S.alertUncased = false; }
  location.hash = 'alerts'; renderAlerts(true);
}
// FIX 2 / P11.1-b — filtre actif sur les alertes par SOURCE (pivot depuis la cloche d'un feed « chaud » de
// la fraîcheur). '' = aucun filtre. Le filtre est SERVI par le démon (`?source=` sur /api/alerts et
// /api/alerts/groups) : un prédicat d'imputation EXACT sur `alert.sources`, l'imputation DÉRIVÉE DE LA
// DONNÉE à la levée de l'alerte — exactement ce qui fabrique le compteur `active_alerts` du feed dont on
// vient de cliquer la cloche. Les deux surfaces lisent le MÊME verdict, et la facette se combine avec tous
// les tris et les deux portées. Limite nommée : une alerte levée AVANT que l'imputation soit stockée (colonne
// vide) n'est appariée à aucune source par ce filtre, alors que la cloche la compte encore par le texte de
// sa règle.
/* state: alertSourceFilter -> S (state.js) */
// P11.1-c — la cloche d'une source pose la facette SOURCE sur la liste, avec la portée EXACTE du compteur de
// la cloche : alertes ACTIVES (status=new), cases comprises, TOUTES DATES (le compteur `active_alerts` de
// /api/freshness n'a pas de fenêtre de temps : il compte toute alerte non acquittée imputée à la source, quel
// que soit son âge — et il est indépendant de la fraîcheur de la source). La vue cible le DIT (cf. le chip
// de facette) et montre l'étendue réelle des dates des alertes listées. Le tri courant est conservé, comme
// pour le pivot technique.
function setAlertSourceFilter(src) {
  S.alertSourceFilter = (src || '').trim(); S.alertMitreFilter = ''; S.alertHistPage = 0; S.alertGroupPage = 0;
  if (S.alertSourceFilter) { S.alertGroupAll = false; S.alertUncased = false; }
  location.hash = 'alerts'; renderAlerts(true);
}
// « voir les events » d'une technique sans alerte : recherche plein-texte du tag MITRE (best-effort, les
// events ne portent pas toujours de champ mitre) -> l'analyste investigue depuis l'Explore.
function mitreEventsDrill(m) {
  m = (m || '').trim(); if (!m) return;
  location.hash = 'explore';
  if ($('#sql')) { $('#sql').value = 'search ' + m; runQuery(); }
}
const ALERT_IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
// ======================================================================================================
// P11.18-v — SUR QUELLE MACHINE PORTE CETTE ALERTE. La colonne était STOCKÉE par les quatre voies de levée
// et jamais SERVIE : la console ne pouvait pas le dire, et un lot voisin avait contourné en écrivant la
// machine dans le TITRE d'une alerte particulière — ce qui vaut pour celle-là et pour aucune autre.
// QUATRE ÉTATS, ET LE QUATRIÈME NE PRÉTEND RIEN. Le démon sert la colonne NUE (aucun `COALESCE`), donc :
//   · un nom            -> la machine ;
//   · `""`              -> une machine est attachée mais l'émetteur ne l'a pas NOMMÉE : machine INCONNUE ;
//   · `null`            -> l'alerte n'est liée à AUCUNE machine (la voie de levée n'était pas keyée sur un
//                          hôte : règle groupée autrement, corrélation sur une autre entité). C'est un FAIT
//                          sur l'alerte, pas une ignorance — les confondre avec le cas précédent est
//                          exactement la famille de défaut que ce dépôt poursuit ;
//   · clé ABSENTE       -> personne ne nous a rien dit. On n'AFFIRME rien : aucun chip. La branche est
//                          DÉRIVÉE de la présence de la clé, jamais d'une version ou d'un nom de route.
// Les mots sont bilingues PAR CONSTRUCTION (`{fr, en}` choisi par LANG), écrits UNE fois et partagés entre
// le chip, son survol et la colonne d'export — trois formulations divergeraient.
// Un ÉTAT par entrée, ses mots dessous : la structure porte la même distinction que le corps servi, donc
// un état de plus ne peut pas arriver sans ses deux formulations. L'état `nommee` n'a pas de `texte` —
// le texte, c'est le nom de la machine, et l'inventer serait précisément l'escamotage qu'on retire.
const MACHINE_MOTS = {
  nommee: {
    survol: { fr: 'Machine sur laquelle porte cette alerte', en: 'Machine this alert bears on' },
  },
  inconnue: {
    texte: { fr: 'hôte NON DÉCLARÉ', en: 'host NOT DECLARED' },
    survol: {
      fr: "Une machine est attachée à cette alerte, mais l'émetteur ne l'a pas nommée : la machine est INCONNUE. Ce n'est pas « aucune machine ».",
      en: 'A machine is attached to this alert, but the emitter did not name it: the machine is UNKNOWN. This is not "no machine".',
    },
  },
  aucune: {
    texte: { fr: 'aucune machine', en: 'no machine' },
    survol: {
      fr: "Cette alerte n'est liée à AUCUNE machine : la voie qui l'a levée ne portait pas d'hôte (règle groupée sur autre chose qu'un hôte, corrélation sur une autre entité). Ce n'est pas une machine inconnue.",
      en: 'This alert is attached to NO machine: the path that raised it carried no host (rule grouped on something other than a host, correlation on another entity). This is not an unknown machine.',
    },
  },
};
const motDeLaMachine = (etat, quoi) => (LANG === 'en' ? MACHINE_MOTS[etat][quoi].en : MACHINE_MOTS[etat][quoi].fr);
// Rend `{ etat, texte, survol }` — ou `null` quand la clé n'a pas été servie, seul cas où la console se tait.
function machineDUneAlerte(a) {
  a = a || {};
  if (!('host' in a) || a.host === undefined) return null;
  const nom = a.host === null ? '' : String(a.host).trim();
  const etat = a.host === null ? 'aucune' : (nom ? 'nommee' : 'inconnue');
  return { etat, texte: etat === 'nommee' ? nom : motDeLaMachine(etat, 'texte'), survol: motDeLaMachine(etat, 'survol') };
}
// Le chip, dans le MÊME slot pour les trois états rendus : une absence de chip se lirait comme « la console
// ne montre pas les machines », c'est-à-dire le défaut qu'on ferme. `.hostchip` existe déjà (style.css) et
// porte le même vêtement qu'aux lignes d'événement -> aucune règle de feuille de style n'est ajoutée.
function machineChipHtml(a) {
  const m = machineDUneAlerte(a);
  return m ? ` <span class="hostchip" data-machine="${m.etat}" title="${esc(m.survol)}">${esc(m.texte)}</span>` : '';
}
// TEMPLATE d'une ligne d'alerte — PARTAGÉ entre la vue plate et les occurrences d'un groupe déplié. `i` =
// index dans le tableau passé à wireAlertRows (drill). Reprend TEL QUEL les conventions existantes
// (.alert/.sev/.mitrechip.mitrepivot/.casechip/.casebtn/.banbtn/.ackdone) -> zéro divergence de rendu.
function alertRowHtml(a, i) {
  const ipm = ((a.title || '') + ' ' + (a.detail || '')).match(ALERT_IP_RE);
  // P11.14-b — LE TITRE N'ANNONCE QUE CE QU'IL TIENDRA. Le survol est DÉRIVÉ du pivot de l'alerte, par la
  // MÊME fonction que le clic : un contrôle qui ne mène nulle part ne peut plus se présenter comme un
  // contrôle qui mène quelque part. `aria-disabled` — et NON `disabled`, qui couperait le survol et
  // rendrait la raison illisible (le choix est celui de core.js, `P11.4-l`) — dit l'inertie aux aides
  // techniques ; le clic, lui, reste écouté pour DIRE le refus au lieu de le laisser sans effet.
  const pivot = pivotDUneAlerte(a);
  const ban = ipm ? `<button class="banbtn" data-ip="${esc(ipm[0])}" title="Bannir ${esc(ipm[0])} (action en attente, dry-run)">${ic('ban')}</button>` : '';
  const cas = a.case_id
    ? `<button class="casechip" data-cid="${a.case_id}" title="Rattachée au case #${a.case_id} - cliquer pour ouvrir">${ic('case')} #${a.case_id}</button>`
    : (canEditCases() ? `<button class="casebtn" data-t="${esc(a.title)}" data-d="${esc(a.detail || '')}" data-id="${a.id}" title="Ajouter à un case">${ic('case')}</button>` : '');
  const mt = a.mitre ? ` <span class="mitrechip mitrepivot" data-m="${esc(a.mitre)}" title="${esc(a.mitre)}${mitreName(a.mitre) ? ' — ' + esc(mitreName(a.mitre)) : ''} · filtrer les alertes par cette technique (MITRE ATT&CK, héritée de la règle)">${esc(a.mitre)}</span>` : '';
  return `
    <div class="alert sev-${a.severity}">
      <span class="sev">${sev(a.severity)}</span>
      <span class="title"><span class="alertdrill" data-idx="${i}" data-pivot="${pivot.mode}"${pivot.mode === 'aucun' ? ' aria-disabled="true"' : ''} title="${esc(pivot.survol)}">${esc(a.title)}</span>${mt}${machineChipHtml(a)}</span>
      <time>${fmtTs(a.ts)}</time>
      <span class="alertact">${cas}${ban}${a.status === 'new' ? `<button data-ack="${a.id}" title="Acquitter : marquer comme vue (retire de la file active, sans la supprimer)">Acquitter</button>` : `<span class="ackdone" title="Acquittée${a.acked_at ? ' · ' + fmtTs(a.acked_at) : ''}${a.acked_by ? ' par ' + esc(a.acked_by) : ''}">${ic('check')} Acquittée</span>`}</span>
    </div>`;
}
// ======================================================================================================
// P11.18-k — TOUT GESTE QUI RETIRE UNE ALERTE DE LA FILE ACTIVE SE CONFIRME. La propriété est DÉRIVÉE, pas
// posée bouton par bouton : `acquitter` est le SEUL endroit d'où partent `/alerts/ack-all` et
// `/alerts/<id>/ack`, et il confirme AVANT d'envoyer. Un geste d'acquittement de plus ne peut donc pas
// rouvrir l'écart — écrit ailleurs, il n'acquitterait rien du tout.
// CE QUE LA MESURE DU 2026-08-25 A PRÉCISÉ : le bouton d'une LIGNE n'a jamais rien demandé — un clic
// acquittait sur-le-champ — alors que les deux gestes de masse portaient chacun leur confirmation. C'est
// l'ASYMÉTRIE qui était le défaut : qui a appris que ce produit confirme avant d'acquitter clique sans se
// méfier là où rien ne confirme.
// POURQUOI CELA NE REND PAS DIX ACQUITTEMENTS INSUPPORTABLES : la barre porte DÉJÀ la forme groupée de ce
// geste répété — « Acquitter les N affichée(s) » sous un filtre, « Tout acquitter » sans — et chacune ne
// demande QU'UNE confirmation en nommant son compte ou sa portée. Dix alertes s'acquittent donc d'un geste
// et d'une confirmation, et la question par ligne ne coûte qu'au geste réellement unitaire. Aucun mécanisme
// neuf n'est introduit pour cela : ni « ne plus demander », ni annulation différée — le dépôt n'en a aucun,
// et en inventer un ici poserait une surface de plus pour un geste qui ne détruit rien.
// LA CONFIRMATION EST CELLE DU POINT COMMUN (`confirmModal`), la MÊME que les deux gestes de masse
// employaient déjà : `confirmWithConsequence` est réservée à ce qui ne se défait pas, et un acquittement ne
// supprime rien — l'alerte quitte la file active et reste lisible sous la portée « tous statuts ».
// `portee` : { phrase, ids } — les identifiants acquittés un à un — ou { phrase, toutes: true } pour
// l'acquittement global, qui a sa propre route parce qu'il dépasse la page.
// Rend true si l'acquittement a été confirmé ET envoyé, false s'il a été refusé — l'appelant n'a pas à
// redériver la réponse pour savoir s'il doit rafraîchir.
async function acquitter(portee) {
  if (!await confirmModal(portee.phrase, { okText: 'Acquitter', danger: false })) return false;
  if (portee.toutes) await apiSend('/alerts/ack-all');
  else for (const id of portee.ids) await apiSend('/alerts/' + id + '/ack');
  return true;
}
// WIRING partagé des lignes d'alerte présentes dans `host` pour le tableau `alerts` (index-aligné avec
// data-idx). `afterAck` = callback exécuté après un acquittement (vue plate: renderAlerts/refresh ; groupe:
// recharge les occurrences du groupe). Les sélecteurs sont SCOPÉS à `host` -> deux groupes dépliés ne se
// marchent pas dessus.
function wireAlertRows(host, alerts, afterAck) {
  host.querySelectorAll('.mitrepivot').forEach(el => el.onclick = (e) => { e.stopPropagation(); setAlertMitreFilter(el.dataset.m); });
  // P11.18-k — le bouton d'une ligne ne connaît pas la route : il nomme ce qu'il retire de la file, et la
  // porte partagée confirme puis envoie. Le titre est retrouvé par l'IDENTIFIANT porté par le bouton, jamais
  // par une position : seules les alertes ACTIVES portent ce bouton, le rang d'un bouton n'est donc pas
  // celui de son alerte dans le tableau servi.
  host.querySelectorAll('[data-ack]').forEach(btn => btn.onclick = () => withBusy(btn, async () => {
    const id = btn.dataset.ack;
    const a = (alerts || []).find(x => String(x.id) === String(id));
    if (!await acquitter({ ids: [id], phrase: `Acquitter l'alerte #${id}${a && a.title ? ` « ${a.title} »` : ''} ? Elle quitte la file active, sans être supprimée.` })) return;
    await afterAck();
  }));
  host.querySelectorAll('.banbtn').forEach(btn => btn.onclick = () => banIp(btn.dataset.ip));
  // P11.4-h — le TITRE d'une alerte est ce qu'on veut le plus souvent coller dans un ticket, et c'est aussi
  // ce qui ouvrait la Recherche au relâchement du glisser : le clic se retire devant une sélection.
  // P11.14-b — le voile `.drilling` accuse un DÉPART ; il ne se pose que si le pivot a bien eu lieu.
  host.querySelectorAll('.alertdrill').forEach(el => clicQuiRespecteLaSelection(el, () => { if (!alertDrill(alerts[Number(el.dataset.idx)])) return; el.classList.add('drilling'); setTimeout(() => el.classList.remove('drilling'), 1200); }));
  host.querySelectorAll('.casebtn').forEach(btn => btn.onclick = () => withBusy(btn, () => addToCase('alert', btn.dataset.t + (btn.dataset.d ? ' - ' + btn.dataset.d : ''), 'alert:' + btn.dataset.id)));
  host.querySelectorAll('.casechip').forEach(btn => btn.onclick = () => withBusy(btn, () => openCase(Number(btn.dataset.cid))));
}
// ======================================================================================================
// P11.1-b — UNE LISTE, DES FACETTES, LES MÊMES ACTIONS PARTOUT. Plate / Règle / Hôte / Technique sont des
// TRIS d'une même liste, pas des écrans. MESURÉ avant correctif (web/alerts.js) : « Tous statuts » n'existait
// qu'en vue groupée, « Tout acquitter » qu'en vue plate sans filtre, le toggle de vue disparaissait sous un
// filtre, et le filtre « hors case » (uncased) variait en silence selon le chemin (plate : oui ; MITRE : non ;
// source : non ; groupes : selon la portée). Le modèle ci-dessous est UNIQUE et la barre est rendue par UNE
// fonction, quelle que soit la vue. Une action impossible n'est pas ABSENTE : elle est rendue désactivée avec
// sa raison (attribut `title`), pour qu'un lecteur sache ce qui manque et pourquoi.
// ======================================================================================================
// Le modèle de la liste : UN tri, UNE portée, UN filtre sur ce qui est AFFICHÉ (déjà repris par un cas ou
// non — `uncased` côté démon), des FACETTES.
function alertListModel() {
  return {
    view: S.alertGroupBy || '',               // '' plate | 'rule' | 'host' | 'mitre' (tri)
    scopeAll: !!S.alertGroupAll,              // false = actives (status=new) | true = tous statuts
    uncased: S.alertUncased !== false,        // n'affiche que les alertes qu'aucun cas n'a reprises (défaut : oui)
    mitre: S.alertMitreFilter || '',          // facette technique (serveur, `?mitre=`)
    source: S.alertSourceFilter || '',        // facette source (serveur, `?source=`, imputation exacte)
    // P11.1-f — la recherche fait partie du MODÈLE, pas d'un état à part : la barre en dérive ce qu'elle
    // peut promettre (un acquittement global dépasserait la recherche). Elle n'entre dans AUCUNE URL :
    // /api/alerts n'offre pas de recherche plein-texte, le filtrage est local aux lignes déjà servies.
    recherche: rechercheDesAlertes(),
  };
}
// P11.7-b — LA PORTÉE EN TOUTES LETTRES, ÉCRITE UNE FOIS. Le compte affiché doit dire ce que le bouton dit
// (« hors case » y survivait en double écriture, vue plate et vue groupée) : un seul auteur, donc un seul
// vocabulaire, et un renommage qui ne peut plus n'atteindre qu'une des deux vues.
function porteeEnMots(m) {
  return (m.scopeAll ? 'tous statuts' : 'actives') + (m.uncased ? ' · pas encore dans un cas' : ' · cas compris');
}
// Les deux facettes sont servies par le démon et s'appliquent à tous les tris et aux deux portées : aucune
// action n'est désactivée au motif d'une facette. L'URL d'une vue est dérivée du modèle par UNE fonction.
function alertFacetParams(m) {
  const p = [];
  if (m.mitre) p.push('mitre=' + encodeURIComponent(m.mitre));
  if (m.source) p.push('source=' + encodeURIComponent(m.source));
  return p;
}
const ALERT_VIEWS = [
  ['', 'Plate', 'Liste plate (chaque alerte)'],
  ['rule', 'Règle', 'Trier par règle — 1 groupe = N occurrences'],
  ['host', 'Hôte', 'Trier par hôte / entité'],
  ['mitre', 'Technique', 'Trier par technique MITRE ATT&CK'],
];
// Ce que la barre propose, DÉRIVÉ du modèle `m` et de ce qui est chargé (`loaded`) :
//   loaded.count / loaded.countLabel  — le compte affiché et sa portée en toutes lettres ;
//   loaded.ackableIds                 — les ids ACTIFS chargés (vue plate) ; vide en vue groupée ;
//   loaded.sourceSpan                 — {from,to} des alertes listées sous une facette source (P11.1-c).
// Rendu PUR (chaîne HTML) : le harnais ESM le juge sur des objets fabriqués.
function alertActionBarHtml(m, loaded) {
  loaded = loaded || {};
  const dis = (cond, reason) => cond ? ` disabled aria-disabled="true" title="${esc(reason)}"` : '';
  // P11.4-i — L'ÉTAT « CHOISI » PASSE PAR `aria-pressed`, ET PLUS PAR LA GRAISSE DU MOT. Le gras portait
  // déjà « alarme / valeur remarquable » ailleurs dans la console ; le réemployer ici faisait lire un tri
  // choisi comme une alerte. La marque visuelle est désormais le liseré réservé (`--sel-ring`, style.css)
  // et l'état lui-même est DIT : `aria-pressed` est le seul canal qu'une aide technique lit, et il ne
  // dépend d'aucune couleur. Il est posé sur les DEUX états — `false` compte autant que `true` : un
  // bouton bascule sans attribut se présente comme un simple bouton d'action.
  const views = ALERT_VIEWS.map(([g, label, title]) => `<button type="button" class="agseg${m.view === g ? ' on' : ''}" aria-pressed="${m.view === g}" data-g="${g}" title="${esc(title)}">${label}</button>`).join('');
  const scope = `<button type="button" class="agscope${m.scopeAll ? ' on' : ''}" aria-pressed="${m.scopeAll}" data-act="scope" title="${m.scopeAll ? 'Tous statuts (historique) — cliquer pour ne voir que les alertes actives' : 'Alertes actives (status=new) — cliquer pour voir tous les statuts'}">${m.scopeAll ? 'Tous statuts' : 'Actives'}</button>`;
  // P11.7-b — CE FILTRE SE NOMME PAR CE QU'IL MONTRE. Il disait « hors case » / « cases comprises » : une
  // RELATION (dedans ou dehors), dans un vocabulaire qui n'est celui d'aucun autre panneau — l'exploitant
  // rapporte ne pas savoir à quoi elle correspond. Ce qu'il choisit, en réalité, c'est LA LISTE : soit les
  // alertes qu'aucun cas n'a encore reprises, soit toutes. Les deux mots le disent maintenant, et le
  // préfixe « Affiche » les rattache à la liste comme « Tri » et « Portée » rattachent les leurs.
  const uncased = `<span class="muted">Affiche</span><button type="button" class="agscope${m.uncased ? ' on' : ''}" aria-pressed="${m.uncased}" data-act="uncased" title="${m.uncased ? 'Seules les alertes qu\'aucun cas n\'a encore reprises sont listées — cliquer pour lister aussi celles déjà rattachées à un cas' : 'Toutes les alertes sont listées, celles déjà rattachées à un cas comprises — cliquer pour ne garder que celles qu\'aucun cas n\'a encore reprises'}">${m.uncased ? 'Pas encore dans un cas' : 'Toutes les alertes'}</button>`;
  const facets = [];
  if (m.mitre) facets.push(`<span class="mitrefilter">Technique : <span class="mitrechip">${esc(m.mitre)}</span><button type="button" data-act="clear-mitre" title="Retirer le filtre technique">${ic('x')}</button></span>`);
  if (m.source) {
    const span = loaded.sourceSpan && loaded.sourceSpan.from ? ` (du ${fmtTs(loaded.sourceSpan.from)} au ${fmtTs(loaded.sourceSpan.to)})` : '';
    const n = typeof loaded.count === 'number' ? loaded.count : 0;
    // L'objet compté suit le tri et la portée : alertes en vue plate, groupes sinon ; actives ou tous statuts.
    const objet = m.view ? `${n} groupe(s) d'alertes ${m.scopeAll ? '(tous statuts)' : 'actives'}` : `${n} alerte(s) ${m.scopeAll ? '(tous statuts)' : 'active(s)'}`;
    facets.push(`<span class="mitrefilter" title="Le compteur de la cloche d'une source compte ses alertes non acquittées, cases comprises, sans fenêtre de temps — il ne dépend pas de la fraîcheur de la source.">Source : <span class="mitrechip">${esc(m.source)}</span> <span class="muted">${objet} imputée(s) à cette source, toutes dates${span} — sans lien avec sa fraîcheur</span><button type="button" data-act="clear-source" title="Retirer le filtre source">${ic('x')}</button></span>`);
  }
  // ACQUITTER — même bouton partout, sémantique DÉRIVÉE : sans facette et sur les actives, l'acquittement
  // GLOBAL (/alerts/ack-all acquitte TOUTE alerte active, y compris hors de la page) ; sinon, les alertes
  // actives AFFICHÉES, une à une (jamais un ack-all global sous un filtre : il dépasserait le filtre).
  // P11.1-f — une recherche RESTREINT ce qui est affiché : « Tout acquitter », qui dépasse la page, la
  // dépasserait aussi. Sous une recherche, l'acquittement porte donc sur les alertes AFFICHÉES, comme sous
  // une facette. C'est la même règle, appliquée à un filtre de plus, et non une exception.
  const filtered = !!(m.mitre || m.source || m.recherche) || m.scopeAll;
  const nAck = (loaded.ackableIds || []).length;
  let ack;
  if (!filtered) ack = `<button type="button" class="btn btn-sm" data-act="ack-all"${dis(!(loaded.count > 0), 'aucune alerte active')} title="Acquitter TOUTES les alertes actives (y compris celles hors de cette page)">${ic('check')} Tout acquitter</button>`;
  else if (nAck > 0) ack = `<button type="button" class="btn btn-sm" data-act="ack-shown" title="Acquitter les ${nAck} alerte(s) active(s) affichée(s) — et seulement celles-là">${ic('check')} Acquitter les ${nAck} affichée(s)</button>`;
  else ack = `<button type="button" class="btn btn-sm" data-act="ack-shown"${dis(true, m.view ? 'acquittement par liste : dépliez un groupe (acquittement par occurrence) ou passez en vue plate' : 'aucune alerte active affichée')}>${ic('check')} Acquitter</button>`;
  return `<div class="alertview alertbar" role="toolbar" aria-label="Liste des alertes : tri, portée, filtres, actions">`
    + `<span class="muted">Tri</span>${views}<span class="muted">Portée</span>${scope}${uncased}${facets.join('')}</div>`
    + `<div class="alerthead"><span>${esc(loaded.countLabel || '')}</span><span class="alertbar-actions">${ack}<span class="alertbar-export"></span></span></div>`;
}
// Câblage de la barre : chaque action écrit le MODÈLE (état partagé) puis re-rend la liste par le même chemin.
// P11.18-j — L'INERTIE D'UN CONTRÔLE SE LIT AVANT `withBusy`, JAMAIS DANS SON RAPPEL. `withBusy` (core.js)
// DÉSACTIVE le bouton pour la durée du geste : un `if (btn.disabled) return` écrit À L'INTÉRIEUR de son
// rappel lit donc toujours vrai, et le geste s'annule LUI-MÊME — sans confirmation, sans requête, sans un
// mot. REPRODUIT le 2026-08-25 sur l'état exact du relevé — quarante-neuf alertes actives, aucune facette,
// aucune recherche : « Tout acquitter » est bien RENDU et bien ACTIF (il ne porte pas `disabled`), le clic
// est bien REÇU, la confirmation ne s'ouvre pas et AUCUNE requête ne quitte le navigateur. Le démon n'a
// donc rien refusé : il n'a rien reçu. « Acquitter les N affichée(s) » était atteint par la même ligne.
// LA LECTURE EST DÉRIVÉE, PAS RECOPIÉE SUR CHAQUE BOUTON : tous les gestes de cette barre passent par
// `siActif`, qui lit l'inertie au seul moment où elle veut dire « ce contrôle est inerte » et non « ce
// geste est en cours ». Un geste de plus câblé ici en hérite ; réécrire le test à la main le rouvrirait.
const siActif = (btn, faire) => () => (btn.disabled ? undefined : faire());
function wireAlertActionBar(host, loaded) {
  const rerender = () => renderAlerts(true);
  host.querySelectorAll('.alertbar .agseg').forEach(btn => btn.onclick = siActif(btn, () => setAlertGroupBy(btn.dataset.g)));
  host.querySelectorAll('[data-act]').forEach(btn => {
    const act = btn.dataset.act;
    if (act === 'scope') btn.onclick = siActif(btn, () => { S.alertGroupAll = !S.alertGroupAll; S.alertGroupPage = 0; S.alertHistPage = 0; rerender(); });
    else if (act === 'uncased') btn.onclick = siActif(btn, () => { S.alertUncased = !(S.alertUncased !== false); S.alertGroupPage = 0; S.alertHistPage = 0; rerender(); });
    else if (act === 'clear-mitre') btn.onclick = siActif(btn, () => setAlertMitreFilter(''));
    else if (act === 'clear-source') btn.onclick = siActif(btn, () => setAlertSourceFilter(''));
    else if (act === 'ack-all') btn.onclick = siActif(btn, () => withBusy(btn, async () => {
      // La portée est NOMMÉE dans la question, parce que ce geste dépasse la page affichée.
      if (!await acquitter({ toutes: true, phrase: `Acquitter TOUTES les alertes actives ? (liste courante : ${loaded.countLabel || loaded.count} ; l'acquittement global porte aussi sur celles hors de la page)` })) return;
      await refresh();
    }));
    else if (act === 'ack-shown') btn.onclick = siActif(btn, () => withBusy(btn, async () => {
      const ids = loaded.ackableIds || [];
      if (!ids.length) return;
      if (!await acquitter({ ids, phrase: `Acquitter les ${ids.length} alerte(s) active(s) affichée(s) ?` })) return;
      await rerender();
    }));
  });
}
// P11.1-d — LE TITRE « Alertes » EST UNE PORTE : comme tout en-tête qui nomme une page (liens `#onglet`
// de la navigation, `capsum-link` des cartes), il mène à la liste des alertes — tri plat, facettes retirées.
// Le bouton d'aide « ? » qu'il contient garde son propre comportement.
function wireAlertsTitle() {
  const h = $('#alerts-h'); if (!h || h.dataset.porte) return;
  h.dataset.porte = '1'; h.setAttribute('role', 'link'); h.tabIndex = 0; h.style.cursor = 'pointer';
  h.title = 'Liste des alertes (tri plat, filtres retirés)';
  const go = (e) => {
    if (e && e.target && typeof e.target.closest === 'function' && e.target.closest('.ihelp')) return;
    S.alertMitreFilter = ''; S.alertSourceFilter = ''; S.alertGroupBy = ''; S.alertGroupAll = false; S.alertUncased = true; S.alertHistPage = 0; S.alertGroupPage = 0;
    // P11.1-f — « filtres retirés » comprend la recherche : la laisser posée rendrait une liste que le
    // titre annonce comme non filtrée et qui cacherait pourtant des lignes.
    videLaRechercheSansRedessiner();
    location.hash = 'alerts'; renderAlerts(true);
  };
  h.onclick = go;
  h.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(e); } };
}

// EXPORT ALERTES (client) : sérialise les alertes DÉJÀ chargées (vue courante / page). Aucune colonne
// secrète (le schéma alert = id/ts/rule/severity/title/status/detail/mitre/host/case_id/acked_*). ts en clair.
// P11.18-v — la MACHINE y entre par le MÊME auteur que le chip (`machineDUneAlerte`) : un export qui
// écrirait `''` pour « aucune machine » comme pour « machine inconnue » rendrait au fichier la confusion
// que l'écran vient de lever. Colonne VIDE = la clé n'a pas été servie, et rien n'est affirmé.
const ALERT_EXPORT_COLS = [
  { key: 'id', label: 'id' }, { key: 'ts', label: 'ts' }, { key: 'severity', label: 'severity' },
  { key: 'title', label: 'title' }, { key: 'status', label: 'status' }, { key: 'rule', label: 'rule' },
  { key: 'mitre', label: 'mitre' }, { key: 'host', label: 'host' }, { key: 'case_id', label: 'case_id' },
  { key: 'detail', label: 'detail' },
  { key: 'acked_at', label: 'acked_at' }, { key: 'acked_by', label: 'acked_by' },
];
function alertExportRow(a) {
  const machine = machineDUneAlerte(a);
  return {
    id: a.id, ts: fmtTs(a.ts), severity: sev(a.severity), title: a.title || '', status: a.status || '',
    rule: a.rule || '', mitre: a.mitre || '', host: machine ? machine.texte : '',
    case_id: a.case_id || '', detail: a.detail || '',
    acked_at: a.acked_at ? fmtTs(a.acked_at) : '', acked_by: a.acked_by || '',
  };
}
function alertsExportBar(alerts, total) {
  // `total` connu (vue MITRE paginée) et > page affichée -> prévenir que l'export ne porte que la page courante.
  const opts = (typeof total === 'number' && total > alerts.length) ? { partial: { shown: alerts.length, total } } : undefined;
  return exportBar('alertes', () => ({ cols: ALERT_EXPORT_COLS, rows: alerts.map(alertExportRow) }), 'alerts', opts);
}
// EXPORT GROUPES d'alertes (« 1 groupe = N occurrences ») : le résumé des groupes affichés (déjà chargés).
const ALERT_GROUP_EXPORT_COLS = [
  { key: 'key', label: 'key' }, { key: 'count', label: 'count' }, { key: 'open', label: 'open' },
  { key: 'severity', label: 'severity' }, { key: 'sample', label: 'sample' }, { key: 'mitre', label: 'mitre' },
  { key: 'last_ts', label: 'last_ts' },
];
function alertGroupExportRow(g) {
  return { key: g.gkey || '', count: g.n, open: g.open_n || 0, severity: sev(g.severity), sample: g.sample_title || '', mitre: g.mitre || '', last_ts: g.last_ts ? fmtTs(g.last_ts) : '' };
}
function alertGroupsExportBar(groups, total) {
  // `total` = nb de groupes serveur ; > page affichée -> export = page courante de groupes uniquement.
  const opts = (typeof total === 'number' && total > groups.length) ? { partial: { shown: groups.length, total } } : undefined;
  return exportBar('alertes-groupes', () => ({ cols: ALERT_GROUP_EXPORT_COLS, rows: groups.map(alertGroupExportRow) }), 'alerts', opts);
}

// P11.1-f — CE QU'UNE ALERTE OFFRE À LA RECHERCHE : ce qu'un analyste connaît d'elle.
//   · son TITRE — pour une alerte de règle, le démon l'écrit « <nom de la règle> : <valeur> <op> <seuil> »,
//     donc chercher le nom de la règle passe par là ;
//   · sa RÈGLE — le jeton qui l'a levée (`rule.<id>`, `heartbeat.<capteur>`) : c'est ce que porte un lien
//     profond et ce par quoi le tri « Règle » groupe ; chercher « heartbeat » sort les capteurs muets ;
//   · son IMPUTATION — les noms de source auxquels elle se rapporte, tels que le démon les a DÉRIVÉS de la
//     donnée à la levée (`alert.sources`, séparés par des sauts de ligne : ils sont rendus au plat, sinon
//     deux noms voisins se colleraient en un mot que rien ne trouve). L'inconnu nommé « (source
//     indéterminée) » est un nom comme un autre : on peut le chercher.
// PAS la technique : elle a DÉJÀ sa facette servie par le démon (`?mitre=`) et son chip pivote depuis
// chaque ligne — la remettre ici ferait remonter tout un pan du catalogue sur un identifiant que le geste
// existant filtre exactement. Pas la gravité ni le statut : ce sont un tri et une portée.
function texteCherchableDUneAlerte(a) {
  const imputation = String((a && a.sources) || '').split('\n').filter(Boolean);
  return texteCherchable([a && a.title, a && a.rule, ...imputation]);
}
// La recherche courante du panneau, et l'autre bout de la même poignée. Sans champ dans le document (test,
// rendu partiel), la recherche vaut la chaîne vide et la liste rend exactement comme avant.
let rechercheDesAlertes = () => '';
let poserLaRechercheDesAlertes = () => {};
// Dernier lot servi par `/api/alerts`, avec le modèle sous lequel il a été demandé. La frappe REDESSINE, elle
// ne recharge pas : filtrer est une comparaison de chaînes sur des lignes déjà en mémoire, et une requête
// HTTP par caractère serait un coût réseau pour un travail local (même partage que les règles).
let alertesChargees = null;
// CE QUE LA RECHERCHE COUVRE, DIT SANS L'ARRONDIR. Elle porte sur les alertes SERVIES, pas sur la base :
// sous « Actives » le démon sert le backlog borné en une fois, sous « Tous statuts » il pagine. Le démon
// n'offre aucun paramètre de recherche plein-texte sur /api/alerts (mesuré le 2026-08-23 : `status`,
// `mitre`, `uncased`, `source`, `gkey/gval`, `limit/offset` — rien d'autre), donc une recherche qui
// prétendrait couvrir tout l'historique mentirait. Le résumé le dit à chaque fois.
// Les deux phrases sont ÉCRITES EN ENTIER, jamais composées : `i18nWalk` compare un nœud texte à une clé du
// lexique, et une phrase recollée à l'exécution n'est jamais égale à une clé — elle resterait en français.
// ÉCRIRE LA PHRASE ENTIÈRE NE SUFFIT PAS : il faut que la clé existe, signe pour signe. Ces deux valeurs sont
// posées sous des clés d'objet (`page:`, `servies:`) que la garde d'i18n ne compte pas comme puits, donc rien
// ne vérifiait la correspondance ; la variante « page » a dérivé du texte du lexique et serait restée en
// français sous `LANG='en'`. Elle est réalignée sur la clé existante, qui n'était plus écrite par personne.
const RECHERCHE_COUVERTURE = {
  page: 'alerte(s) de cette page — la recherche porte sur la page affichée, pas sur tout l\'historique ; les filtres et le tri restent posés',
  servies: 'alerte(s) — la recherche porte sur les alertes actives servies ; les filtres et le tri restent posés',
};
const RECHERCHE_SANS_RESULTAT = {
  page: 'Aucune alerte de cette page ne porte ces mots dans son titre, sa règle ou sa source imputée — et la recherche ne descend pas dans les pages suivantes. Échap efface la recherche.',
  servies: 'Aucune alerte affichée ne porte ces mots dans son titre, sa règle ou sa source imputée. Échap efface la recherche.',
};
const clefDeCouverture = (m) => (m.scopeAll ? 'page' : 'servies');

async function renderAlerts(loading) {
  wireAlertsTitle();
  const m = alertListModel();
  const requete = m.recherche;
  // Un TRI groupé est servi par /api/alerts/groups, facettes comprises.
  // P11.1-f — SOUS UNE RECHERCHE, LA LISTE EST PLATE. Même choix que le panneau des règles, et pour une
  // raison de plus : un groupe n'est pas seulement REPLIÉ ici, ses occurrences ne sont même pas chargées
  // (chaque dépli est une requête). Une correspondance tombée dedans serait donc invisible ET introuvable.
  // Le groupement n'est pas remplacé, il est mis de côté : il revient dès que la recherche est vidée.
  if (m.view && !requete) return renderAlertGroups(loading);
  // LA MÊME URL DÉRIVÉE DU MÊME MODÈLE : portée (status=new | all), le filtre d'affichage (uncased=1 —
  // « pas encore dans un cas »), facettes
  // (mitre=, source=). La portée « tous statuts » est PAGINÉE serveur (limit/offset + total) ; la portée
  // « actives » reste bornée (200, sans total) — contrat inchangé de /api/alerts.
  const params = [];
  params.push(m.scopeAll ? 'status=all' : 'status=new');
  if (m.uncased) params.push('uncased=1');
  params.push(...alertFacetParams(m));
  if (m.scopeAll) params.push('limit=' + ALERT_HIST_PS + '&offset=' + (S.alertHistPage * ALERT_HIST_PS));
  const url = '/alerts?' + params.join('&');
  const b = $('#alerts .body'); if (!b) return;
  if (loading) { let prog = b.querySelector(':scope > .tableprog'); if (!prog) { prog = document.createElement('div'); prog.className='tableprog'; b.insertBefore(prog, b.firstChild); } prog.hidden=false; b.classList.add('reloading'); }
  let alerts, alertTotal;
  try { const resp = await api(url); alerts = resp.alerts || []; alertTotal = resp.total; } catch (e) { b.classList.remove('reloading'); b.innerHTML = '<div class="bad">alertes indisponibles : ' + esc(e.message) + '</div>'; return; }
  b.classList.remove('reloading');
  // P11.1-f — LE LOT SERVI EST MÉMORISÉ, et le dessin en est séparé : une frappe REDESSINE, elle ne
  // recharge pas. Sans cette scission, chercher coûterait une requête HTTP par caractère pour un travail
  // qui est une comparaison de chaînes sur des lignes déjà en mémoire.
  alertesChargees = { alerts, alertTotal };
  dessinerLaListePlate(b, alertListModel(), alerts, alertTotal);
}

// LE DESSIN de la vue plate, sur un lot DÉJÀ servi. Séparé du chargement pour la recherche (`P11.1-f`),
// et c'est aussi ce qui le rend jugeable par le harnais sans réseau.
function dessinerLaListePlate(b, m, alerts, alertTotal) {
  const requete = m.recherche;
  const portee = porteeEnMots(m);
  // LA RECHERCHE SE COMPOSE : elle s'applique APRÈS le serveur (portée, filtre d'affichage,
  // facettes) et n'en retire aucun. Elle est calculée ICI, avant la barre, pour que TOUT ce que la barre
  // promet sur « ce qui est affiché » — l'acquittement par liste, l'étendue des dates, l'export — porte
  // sur les mêmes lignes que celles qui sont rendues. Le COMPTE de la barre, lui, reste celui du serveur :
  // c'est la portée, et le résumé de recherche dit juste en dessous combien de lignes sur combien.
  const affichees = requete ? filtrerParRecherche(alerts, requete, texteCherchableDUneAlerte) : alerts;
  // Facette SOURCE : filtrée par le serveur ; l'étendue des dates des alertes LISTÉES (la page courante sous
  // la portée « tous statuts ») est affichée à côté du chip.
  let sourceSpan = null;
  if (m.source && affichees.length) { const ts = affichees.map(a => a.ts).filter(Boolean); sourceSpan = { from: Math.min(...ts), to: Math.max(...ts) }; }
  const count = (m.scopeAll && typeof alertTotal === 'number') ? alertTotal : alerts.length;
  const loaded = {
    count,
    countLabel: `${count} alerte(s) · ${portee}${m.mitre ? ' · technique ' + m.mitre : ''}${m.source ? ' · source ' + m.source : ''}`,
    ackableIds: affichees.filter(a => a.status === 'new').map(a => a.id),
    sourceSpan,
  };
  const bar = alertActionBarHtml(m, loaded);
  if (!alerts.length) {
    let vide;
    if (m.mitre) {
      // 0 alerte même TOUS statuts -> on propose de voir les events de la technique (pas de cul-de-sac)
      vide = `<div class="muted">Aucune alerte (${esc(portee)}) pour cette technique. <button id="mitre-events" type="button" class="linklike">Voir les events ${esc(m.mitre)}</button></div>`;
    } else if (m.source) {
      vide = `<div class="muted">Aucune alerte (${esc(portee)}) imputée à la source <b>${esc(m.source)}</b>.</div>`;
    } else {
      vide = `<div class="ok">Aucune alerte ${m.scopeAll ? '' : 'active '}${m.uncased ? 'pas encore dans un cas' : ''}</div>`;
    }
    b.innerHTML = bar + vide;
    const ev = b.querySelector('#mitre-events'); if (ev) ev.onclick = () => mitreEventsDrill(m.mitre);
    wireAlertActionBar(b, loaded);
    return;
  }
  b.innerHTML = bar + affichees.map((a, i) => alertRowHtml(a, i)).join('');
  if (requete) {
    // Une liste qui cache des lignes le DIT, et quand elle ne trouve rien elle nomme ce qu'elle a cherché.
    const k = clefDeCouverture(m);
    b.insertBefore(resumeDeRecherche(affichees.length, alerts.length, {
      filtre: document.createTextNode(RECHERCHE_COUVERTURE[k]),
      vide: document.createTextNode(RECHERCHE_SANS_RESULTAT[k]),
    }), b.querySelector('.alert'));
  }
  wireAlertActionBar(b, loaded);
  // WIRING des lignes (drill/ack/ban/case) : ack -> re-render de la liste filtrée, ou refresh global (backlog).
  wireAlertRows(b, affichees, () => (m.mitre || m.source || m.scopeAll) ? renderAlerts() : refresh());
  // EXPORT : barre CSV/JSON/PDF dans l'emplacement de la barre d'actions (sur les alertes AFFICHÉES).
  { const slot = b.querySelector('.alertbar-export'); if (slot) slot.appendChild(alertsExportBar(affichees, m.scopeAll && !requete ? alertTotal : undefined)); }
  // pager (haut+bas) sur la portée « tous statuts » (serveur limit/offset) ; auto-caché si <=1 page. Il reste
  // sous une recherche : chaque page reste cherchable, et c'est ce que le résumé annonce.
  if (m.scopeAll && typeof alertTotal === 'number') {
    const pgState = { page: S.alertHistPage, pageSize: ALERT_HIST_PS, total: alertTotal, shown: alerts.length };
    const go = p => { S.alertHistPage = p; renderAlerts(true); };
    const top = makePager(pgState, go), bot = makePager(pgState, go);
    const firstAlert = b.querySelector('.alert');
    if (top && firstAlert) b.insertBefore(top, firstAlert);
    if (bot) b.appendChild(bot);
  }
}

// TRIAGE GROUPÉ — vue de GROUPES repliables (« 1 groupe = N occurrences »). Groupes paginés serveur
// (/api/alerts/groups) ; chaque groupe déplié charge ses occurrences à la demande (chemin plat gkey/gval,
// paginé). Le modèle (portée / filtre d'affichage / facettes technique et source) est le MÊME que celui de la vue plate, et
// s'applique À LA FOIS au groupement et à l'expansion -> le compteur `n` du groupe et le `total` des
// occurrences restent COHÉRENTS.
async function renderAlertGroups(loading) {
  const b = $('#alerts .body'); if (!b) return;
  const m = alertListModel();
  const url = '/alerts/groups?group=' + encodeURIComponent(m.view) + '&status=' + (m.scopeAll ? 'all' : 'new')
            + (m.uncased ? '&uncased=1' : '')
            + alertFacetParams(m).map(p => '&' + p).join('')
            + '&limit=' + ALERT_GROUP_PS + '&offset=' + (S.alertGroupPage * ALERT_GROUP_PS);
  if (loading) { let prog = b.querySelector(':scope > .tableprog'); if (!prog) { prog = document.createElement('div'); prog.className='tableprog'; b.insertBefore(prog, b.firstChild); } prog.hidden=false; b.classList.add('reloading'); }
  let groups, total;
  try { const r = await api(url); groups = r.groups || []; total = r.total; }
  catch (e) { b.classList.remove('reloading'); b.innerHTML = alertActionBarHtml(m, { count: 0, countLabel: 'groupes indisponibles' }) + '<div class="bad">groupes indisponibles : ' + esc(e.message) + '</div>'; wireAlertActionBar(b, { count: 0 }); return; }
  b.classList.remove('reloading');
  const axisLabel = { rule: 'règle', host: 'hôte', mitre: 'technique' }[m.view] || m.view;
  const count = typeof total === 'number' ? total : groups.length;
  const portee = porteeEnMots(m);
  const loaded = { count, countLabel: `${count} groupe(s) · par ${axisLabel} · ${portee}${m.mitre ? ' · technique ' + m.mitre : ''}${m.source ? ' · source ' + m.source : ''}`, ackableIds: [] };
  const bar = alertActionBarHtml(m, loaded);
  if (!groups.length) {
    b.innerHTML = bar + `<div class="ok">Aucune alerte ${m.scopeAll ? '' : 'active '}à trier${m.source ? ` pour la source ${esc(m.source)}` : ''}</div>`;
    wireAlertActionBar(b, loaded); return;
  }
  // ui-regression — l'auto-refresh (30 s) reconstruit ce conteneur : on MÉMORISE les groupes
  // DÉPLIÉS + leur page d'occurrences AVANT le rebuild pour les RÉTABLIR après (sinon l'analyste perd sa place à
  // chaque tick : collapse + page 0, ce qui rend un groupe bruyant intravaillable). Clé = gkey (data-gkey).
  const prevOpen = {};
  b.querySelectorAll('.agroup.open').forEach(el => {
    const body = el.querySelector('.agbody');
    prevOpen[el.dataset.gkey || ''] = (body && body.dataset.opage) ? Number(body.dataset.opage) : 0;
  });
  b.innerHTML = bar + groups.map(g => alertGroupHtml(g)).join('');
  wireAlertActionBar(b, loaded);
  { const slot = b.querySelector('.alertbar-export'); if (slot) slot.appendChild(alertGroupsExportBar(groups, total)); }
  // pager de la LISTE de groupes (haut + bas), inséré autour des groupes.
  if (typeof total === 'number') {
    const pgState = { page: S.alertGroupPage, pageSize: ALERT_GROUP_PS, total, shown: groups.length };
    const go = p => { S.alertGroupPage = p; renderAlertGroups(true); };
    const top = makePager(pgState, go), bot = makePager(pgState, go);
    const first = b.querySelector('.agroup');
    if (top && first) b.insertBefore(top, first);
    if (bot) b.appendChild(bot);
  }
  // expand/collapse par groupe (chargement paresseux des occurrences au 1er dépli).
  b.querySelectorAll('.agroup').forEach((el, idx) => {
    const g = groups[idx];
    const sum = el.querySelector('.agsum');
    if (sum) sum.onclick = () => toggleAlertGroup(el, g);
    // RÉTABLIT l'état déplié + la page d'occurrences mémorisés avant le rebuild (cf. prevOpen ci-dessus).
    const gk = g.gkey || '';
    if (Object.prototype.hasOwnProperty.call(prevOpen, gk)) {
      const body = el.querySelector('.agbody');
      body.hidden = false; el.classList.add('open'); if (sum) sum.setAttribute('aria-expanded', 'true');
      loadGroupOccurrences(body, g, prevOpen[gk]);
    }
  });
}
// carte d'un GROUPE : en-tête cliquable (caret + sévérité + compte + clé + aperçu + activités + dernier ts) et
// un corps `.agbody` (occurrences) initialement replié/vide.
function alertGroupHtml(g) {
  const view = S.alertGroupBy || '';
  const emptyLabel = view === 'host' ? '(sans hôte)' : view === 'mitre' ? '(sans technique)' : '(sans clé)';
  const key = g.gkey ? esc(g.gkey) : `<span class="muted">${emptyLabel}</span>`;
  const mt = (g.mitre && view !== 'mitre') ? ` <span class="mitrechip" title="${esc(g.mitre)}${mitreName(g.mitre) ? ' — ' + esc(mitreName(g.mitre)) : ''}">${esc(g.mitre)}</span>` : '';
  // cellule « actives » TOUJOURS émise (vide si 0) pour garder l'alignement de la grille .agsum stable.
  const open = g.open_n > 0 ? `<span class="agopen" title="${g.open_n} encore active(s) (status=new)">${g.open_n} active(s)</span>` : `<span class="agopen" style="visibility:hidden"></span>`;
  return `
  <div class="agroup sev-${g.severity}" data-gkey="${g.gkey ? esc(g.gkey) : ''}">
    <button type="button" class="agsum" aria-expanded="false">
      <span class="agcaret">${ic('chevright')}</span>
      <span class="sev">${sev(g.severity)}</span>
      <span class="agcount" title="${g.n} occurrence(s) dans ce groupe">${g.n}</span>
      <span class="agkey">${key}${mt}</span>
      <span class="agsample">${esc(g.sample_title || '')}</span>
      ${open}
      <time>${fmtTs(g.last_ts)}</time>
    </button>
    <div class="agbody" hidden></div>
  </div>`;
}
function toggleAlertGroup(el, g) {
  const body = el.querySelector('.agbody'), sum = el.querySelector('.agsum');
  if (!body.hidden) { body.hidden = true; el.classList.remove('open'); sum.setAttribute('aria-expanded', 'false'); return; }
  body.hidden = false; el.classList.add('open'); sum.setAttribute('aria-expanded', 'true');
  if (!body.dataset.loaded) loadGroupOccurrences(body, g, 0);
}
// OCCURRENCES d'un groupe (chemin plat, SCOPÉ au groupe via gkey/gval, MÊME scope statut que le groupement ->
// `total` cohérent avec `n`). Réutilise alertRowHtml + wireAlertRows + makePager. Après ack : recharge la même
// page d'occurrences (le groupe reste déplié).
async function loadGroupOccurrences(body, g, opage) {
  const m = alertListModel();
  // MÊME modèle que le groupement (renderAlertGroups) -> `total` des occurrences cohérent avec `n`.
  const url = '/alerts?status=' + (m.scopeAll ? 'all' : 'new') + (m.uncased ? '&uncased=1' : '')
            + alertFacetParams(m).map(p => '&' + p).join('')
            + '&gkey=' + encodeURIComponent(m.view)
            + '&gval=' + encodeURIComponent(g.gkey || '') + '&limit=' + ALERT_OCC_PS + '&offset=' + (opage * ALERT_OCC_PS);
  body.innerHTML = '<div class="tableprog"></div>';
  let occ, total;
  try { const r = await api(url); occ = r.alerts || []; total = r.total; }
  catch (e) { body.innerHTML = '<div class="bad">occurrences indisponibles : ' + esc(e.message) + '</div>'; return; }
  body.dataset.loaded = '1';
  body.dataset.opage = String(opage); // ui-regression : mémorise la page pour la restaurer après un rebuild (auto-refresh)
  body.innerHTML = occ.map((a, i) => alertRowHtml(a, i)).join('') || '<div class="muted">aucune occurrence</div>';
  if (typeof total === 'number') {
    const pgState = { page: opage, pageSize: ALERT_OCC_PS, total, shown: occ.length };
    const go = p => loadGroupOccurrences(body, g, p);
    const top = makePager(pgState, go), bot = makePager(pgState, go);
    const first = body.querySelector('.alert');
    if (top && first) body.insertBefore(top, first);
    if (bot) body.appendChild(bot);
  }
  wireAlertRows(body, occ, () => loadGroupOccurrences(body, g, opage));
}

// Vider le champ SANS redessiner : l'appelant enchaîne sur un rechargement complet, et un dessin
// intermédiaire sur le lot mémorisé (servi sous l'ancien modèle) montrerait un état qui n'existe plus.
function videLaRechercheSansRedessiner() {
  const champ = $('#alert-search'); if (champ) champ.value = '';
}
// P11.1-f — CÂBLAGE DU CHAMP DE RECHERCHE. Le champ vit dans l'en-tête du panneau, PAS dans son corps :
// le corps est réécrit en entier à chaque rendu (`b.innerHTML = …`), un champ posé dedans perdrait le
// curseur à chaque frappe. La frappe REDESSINE le dernier lot servi ; si rien n'a encore été servi (frappe
// avant le premier chargement), elle demande un chargement normal.
function redessinerLesAlertes() {
  const b = $('#alerts .body'); if (!b) return;
  const m = alertListModel();
  // Recherche VIDÉE alors qu'un tri groupé était choisi : le groupement revient, et il se recharge (ses
  // groupes viennent d'une autre route que la liste plate — le lot mémorisé ne les contient pas).
  if (m.view && !m.recherche) return renderAlerts(true);
  if (!alertesChargees) return renderAlerts(true);
  dessinerLaListePlate(b, m, alertesChargees.alerts, alertesChargees.alertTotal);
}
(() => {
  const champ = $('#alert-search'); if (!champ) return;
  const poignee = champDeRecherche(champ, { auChangement: () => redessinerLesAlertes() });
  rechercheDesAlertes = poignee.valeur; poserLaRechercheDesAlertes = poignee.poser;
})();

export { renderAlerts, setAlertMitreFilter, setAlertSourceFilter, alertActionBarHtml, alertListModel,
  dessinerLaListePlate, redessinerLesAlertes, poserLaRechercheDesAlertes, texteCherchableDUneAlerte,
  pivotDUneAlerte, alertDrill, machineDUneAlerte };
