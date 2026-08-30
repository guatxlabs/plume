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
// `P11.14-h` — ET LE REFUS LUI-MÊME FABRIQUAIT, MESURÉ LE 2026-08-26. Sa formulation d'origine affirmait
// deux choses qu'aucune valeur servie ne porte, et la seconde est exactement le défaut que `P11.14-h`
// nomme :
//   · « cette alerte n'a ni règle ni fenêtre d'évaluation, elle n'a donc pas été levée par une recherche
//     d'événements » — FAUX pour toute une classe d'alertes. `search_link` est nul dès que la JOINTURE
//     `('rule.'||r.id)=alert.rule` ne trouve pas de ligne (`daemon/src/handlers/alerts.rs`, `base`), ce qui
//     inclut le cas d'une RÈGLE SUPPRIMÉE — le démon l'écrit noir sur blanc au même endroit (« Absent pour
//     une alerte sans règle (heartbeat.*, règle supprimée) »). Une telle alerte A une règle et A BIEN été
//     levée par une recherche d'événements ; ce qui manque est la LIGNE de règle, pas la recherche.
//   · « alors que sa justification est l'état qu'elle porte » — la console DÉCLARAIT le fondement de
//     l'alerte, sans qu'aucun champ servi ne le déclare. C'est la fabrication d'un étage plus haut, dans la
//     phrase même qui annonce refuser de fabriquer.
// LA PHRASE NE DIT PLUS QUE CE QUI EST DÉRIVÉ : aucune fenêtre d'évaluation n'a été servie, donc la console
// n'a pas la requête qui a compté ; elle refuse d'en inventer une ; et elle AVOUE la seconde impasse au lieu
// de la combler — rien de ce qui est servi ne déclare sur quoi l'alerte est FONDÉE. C'est un rétrécissement
// de ce que la console affirme, jamais un élargissement.
// `P11.20-t` — ET CETTE PHRASE-LÀ NOMMAIT ENCORE UN CHAMP QUE LA FONCTION NE LISAIT PAS. Elle affirmait
// « aucune fenêtre d'évaluation servie » alors que le SEUL test posé porte sur `search_link.query` :
// `window_s` est servi à côté, et n'était consulté nulle part. Une phrase co-extensive par accident n'est
// pas une phrase dérivée — elle devient fausse le jour où le démon change, et rien ici ne le verrait.
// CE QUE LA MESURE DU 2026-08-29 RÉFUTE DANS LE CONSTAT DE CETTE CLÉ. Le cas qu'il décrit — « la fenêtre EST
// servie mais le lien est ABSENT » — n'est PAS producible par ce démon : dans `alerts_query_page`
// (`daemon/src/handlers/alerts.rs`) `search_link` vaut `window_s.map(…)`, donc lien absent ⟹ fenêtre absente.
// Le second cas RÉELLEMENT atteignable est plus étroit : la fenêtre est servie, le lien AUSSI, et c'est sa
// `query` qui est vide — ce qui suppose une alerte de règle dont la requête recopiée à la levée est vide.
// La phrase servie n'était donc pas fausse « la plupart du temps » (la question ouverte de la clé) ; elle
// était INDÉRIVÉE. Les deux branches ci-dessous lisent chacune ce qu'elles nomment, et rien d'autre.
// CE QUE CELA NE TIENT PAS : la seconde branche n'est pas atteinte par le démon d'aujourd'hui, elle garde
// une frontière plutôt qu'elle ne décrit un cas vu en service ; et aucune des deux ne dit COMBIEN d'alertes
// y tombent — cela se compte sur une base, jamais dans un module.
// CE QUI RESTE OUVERT SOUS `P11.14-h`, ET QUE CE MODULE NE PEUT PAS FERMER : que le fondement soit ÉCRIT à
// la levée, là où le démon sait ce qu'il fait, puis servi. Tant qu'il ne l'est pas, la troisième branche
// reste un refus honnête et non le pivot que le constat décrit.
// LES TROIS PHRASES SONT BILINGUES PAR CONSTRUCTION (`{fr, en}` choisi par LANG) : elles sont écrites UNE
// fois et servent au survol du titre COMME au refus dit au clic — deux formulations divergeraient.
const PIVOT_MOTS = {
  exact: { fr: 'Cliquer → voir les événements déclencheurs', en: 'Click → see the triggering events' },
  adresse: { fr: "Cliquer → chercher cette adresse (src_ip) dans les événements ; l'alerte ne porte pas la requête exacte d'une règle.", en: 'Click → search this address (src_ip) in the events; this alert carries no exact rule query.' },
  aucun_sans_requete: { fr: "Aucun pivot exact : le démon a bien servi une fenêtre d'évaluation pour cette alerte, mais le lien de recherche qui l'accompagne ne porte AUCUNE requête — la console n'a donc pas la requête qui l'a comptée. Elle refuse d'en fabriquer une — chercher son libellé rendrait un vide qui ne prouverait rien. Elle ne peut pas davantage renvoyer vers ce qui FONDE l'alerte : rien de ce qui est servi ne le déclare, et la console ne le devinera pas.", en: 'No exact pivot: the daemon did serve an evaluation window for this alert, but the search link that comes with it carries NO query, so the console does not have the query that counted it. It refuses to make one up — searching its wording would return an emptiness that proves nothing. Nor can it point to what the alert is FOUNDED on: nothing that is served declares it, and the console will not guess.' },
  aucun: { fr: "Aucun pivot exact : le démon n'a servi AUCUNE fenêtre d'évaluation pour cette alerte, la console n'a donc pas la requête qui l'a comptée. Elle refuse d'en fabriquer une — chercher son libellé rendrait un vide qui ne prouverait rien. Elle ne peut pas davantage renvoyer vers ce qui FONDE l'alerte : rien de ce qui est servi ne le déclare, et la console ne le devinera pas.", en: 'No exact pivot: the daemon served NO evaluation window for this alert, so the console does not have the query that counted it. It refuses to make one up — searching its wording would return an emptiness that proves nothing. Nor can it point to what the alert is FOUNDED on: nothing that is served declares it, and the console will not guess.' },
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
  // `P11.20-t` — LE REFUS NOMME CE QU'IL A LU. Deux impasses distinctes mènent ici, et la fenêtre
  // d'évaluation est le seul champ qui les sépare : servie, l'alerte a bien une ligne de règle et c'est le
  // lien qui ne porte pas de requête ; absente, le démon n'a joint aucune règle. Le MODE reste le même —
  // le pivot est refusé dans les deux cas, et l'inertie de la ligne ne dépend pas de la cause.
  const fenetreServie = a.window_s != null;
  return { mode: 'aucun', query: '', from: null, to: null, survol: motDuPivot(fenetreServie ? 'aucun_sans_requete' : 'aucun') };
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
// ======================================================================================================
// P11.1-g — CE QUE L'ACQUITTEMENT PAR LISTE COUVRE, ET CE QU'IL NE COUVRE PAS.
// MESURÉ le 2026-08-26 : la SEULE route d'acquittement en masse du démon, `POST /api/alerts/ack-all`,
// ne prend AUCUN paramètre — ni facette, ni portée, ni filtre d'affichage. Elle pose `status='ack'` sur
// TOUTE alerte `status='new'` (`daemon/src/handlers/cases.rs`, `ack_all` ; la route est déclarée sans
// extracteur de requête ni corps dans `daemon/src/server/groupes_de_routes.rs`). LE GESTE QUE L'ANALYSTE
// CROIT POSER SOUS UNE FACETTE — « acquitter tout ce qui relève de cette source » — N'EXISTE DONC PAS
// dans le produit, et aucune surface ne le disait.
// LA BRANCHE PRISE, PARMI LES DEUX QUE LE CONSTAT OFFRAIT : « la console cesse de l'offrir sous facette
// ET DIT POURQUOI ». L'autre — le démon porte la facette par le MÊME prédicat exact que `?source=` — est
// hors de ce module ; elle n'a pas été prise, et ce commentaire ne la remplace pas.
// CE QUI NE CHANGE PAS : sous un filtre, la console n'envoyait déjà jamais `ack-all` ; elle acquitte les
// alertes AFFICHÉES, une à une, par identifiant, derrière la confirmation partagée (`acquitter`,
// `P11.18-k`). Aucun câblage, aucune route, aucune confirmation ne bouge ici.
// CE QUI MANQUAIT, ET QUI EST AJOUTÉ : LES MOTS. « Acquitter les 12 affichée(s) » se lit comme « vider la
// source » tant que rien ne dit ni que le geste global n'a pas de facette, ni ce qui reste hors d'atteinte.
// LA PHRASE DE CE QUI RESTE EST DÉRIVÉE DE LA RÉPONSE DU DÉMON, JAMAIS D'UNE BORNE RECOPIÉE. /api/alerts
// ne rend `total` QUE sur les vues qu'il pagine (portée « tous statuts », occurrences d'un groupe) ; sur
// le backlog des actives il rend une liste BORNÉE et AUCUN total. L'absence de `total` est donc l'aveu,
// par le démon, qu'il a borné sans déclarer la population — et la console en tire qu'elle NE PEUT PAS
// savoir s'il reste des alertes sous ce filtre. Recopier ici la borne du démon ferait de la console
// l'auteur d'un chiffre qui n'est pas le sien, et un changement côté démon la rendrait fausse en silence.
// CE QUE CES MOTS NE TIENNENT PAS : ils ne rendent pas le geste complet, et ils ne disent pas COMBIEN
// d'alertes lui échappent — le démon ne le déclare pas. Ils disent qu'on ne le sait pas.
// Bilingues PAR CONSTRUCTION (`{fr, en}` choisi par LANG), écrits UNE fois et partagés entre le survol du
// bouton et la QUESTION DE LA CONFIRMATION : deux formulations divergeraient, et c'est la question de la
// confirmation que l'analyste lit vraiment au moment d'engager le geste.
// LA PHRASE ENTIÈRE, PAS SES SEULES BRIBES. MESURÉ le 2026-08-26, avant correctif, en important ce module
// dans une seconde instance du graphe sous `LANG='en'` : seuls les mots ci-dessous étaient bilingues, et la
// TÊTE de la phrase comme les NOMS des filtres étaient des littéraux français interpolés hors de tout
// mécanisme de langue. La question rendue sous `LANG='en'` était donc à moitié française — « Acquitter les 3
// alerte(s) active(s) affichée(s) sous la source « sudo » ? This gesture only covers… » — exactement à
// l'endroit dont ce commentaire dit qu'il est celui que l'analyste lit. Le lexique (`web/i18n.js`) ne pouvait
// pas la rattraper : `i18nWalk` ne remplace que sur une ÉGALITÉ EXACTE, et une phrase interpolée n'est jamais
// égale à une clé. Tout ce qui compose la phrase entre donc ici, TROUS COMPRIS : `{n}`, `{v}`, `{sous}`,
// `{filtres}`, `{restrictions}` sont remplis par le seul appelant qui les nomme, et la valeur passe telle
// quelle (un nom de source, une technique, une recherche, un compte ne se traduisent pas).
const ACQUITTEMENT_MOTS = {
  affichees: {
    fr: 'Ce geste ne porte que sur les alertes actives AFFICHÉES, une à une.',
    en: 'This gesture only covers the DISPLAYED active alerts, one by one.',
  },
  aucun_geste_a_filtre: {
    fr: 'Aucun geste « acquitter tout ce qui relève de ce filtre » n\'existe : l\'unique acquittement en masse du démon ne prend aucun filtre — il acquitterait TOUTES les alertes actives, bien au-delà de ce qui est filtré ici. La console ne l\'offre donc pas sous un filtre.',
    en: 'No "acknowledge everything under this filter" gesture exists: the daemon\'s single bulk acknowledgement takes no filter — it would acknowledge ALL active alerts, far beyond what is filtered here. The console therefore does not offer it under a filter.',
  },
  reste_autres_pages: {
    fr: 'Les alertes des autres pages de cette liste ne sont pas touchées.',
    en: 'Alerts on the other pages of this list are not touched.',
  },
  reste_indeterminable: {
    fr: 'Le démon borne cette liste sans en déclarer le total : la console ne peut pas savoir s\'il reste des alertes actives sous ce filtre, et elle ne le prétend pas.',
    en: 'The daemon bounds this list without declaring its total: the console cannot know whether active alerts remain under this filter, and does not claim to.',
  },
  // LA TÊTE DE LA PHRASE ET LES NOMS DES FILTRES — ce qui manquait, et sans quoi tout le reste était
  // décoratif : c'est cette tête que l'analyste lit d'abord.
  tete: {
    fr: 'Acquitter les {n} alerte(s) active(s) affichée(s){sous}',
    en: 'Acknowledge the {n} DISPLAYED active alert(s){sous}',
  },
  sous_les_filtres: { fr: ' sous {filtres}', en: ' under {filtres}' },
  la_source: { fr: 'la source « {v} »', en: 'the source “{v}”' },
  la_technique: { fr: 'la technique {v}', en: 'the {v} technique' },
  la_recherche: { fr: 'la recherche « {v} »', en: 'the search “{v}”' },
  // Le filtre d'affichage de `alertListModel` : il RESTREINT la liste comme une facette, mais la console ne
  // retire pas le geste global sous lui (voir `restrictionsDeLaListe`) — elle le NOMME dans la question.
  hors_cas: { fr: 'les alertes déjà reprises dans un cas', en: 'alerts already taken up in a case' },
  // LA QUESTION DU GESTE GLOBAL, du même auteur : elle était le SEUL texte d'acquittement encore écrit en
  // français en dur, et c'est celui qui engage le geste le plus large du panneau.
  tete_globale: { fr: 'Acquitter TOUTES les alertes actives ?', en: 'Acknowledge ALL active alerts?' },
  global_hors_page: {
    fr: 'Ce geste porte aussi sur les alertes actives qui ne sont pas sur cette page.',
    en: 'This gesture also covers active alerts that are not on this page.',
  },
  global_franchit: {
    fr: 'Il ne prend AUCUN filtre : il franchit aussi ce que cette liste écarte et annonce dans son compte — {restrictions}.',
    en: 'It takes NO filter: it also crosses what this list leaves out and announces in its count — {restrictions}.',
  },
  liste_courante: { fr: 'Liste courante : {n}.', en: 'Current list: {n}.' },
  // LA PONCTUATION EST DE LA LANGUE, ELLE AUSSI. Le français pose une espace devant le point
  // d'interrogation, l'anglais non : la coller en dur rendait « … the search “web-01” ? This gesture… ».
  // C'est le SEUL séparateur qui distingue la QUESTION du survol — d'où sa place ici, avec les mots.
  avant_la_question: { fr: ' ? ', en: '? ' },
};
// Un mot de l'acquittement dans la langue de la console, trous remplis par l'appelant qui les nomme.
const motDeLAcquittement = (k, valeurs) => {
  const mot = LANG === 'en' ? ACQUITTEMENT_MOTS[k].en : ACQUITTEMENT_MOTS[k].fr;
  return valeurs ? mot.replace(/\{(\w+)\}/g, (_, nom) => String(valeurs[nom])) : mot;
};
// LES RESTRICTIONS DE LA LISTE, DÉRIVÉES DU MODÈLE — UN SEUL PARCOURS, et les deux usages en découlent.
// MESURÉ le 2026-08-26, avant correctif : il y en avait DEUX, écrites à côté du modèle et tenues d'accorder
// — `filtresDeLaListe` (source, technique, recherche) et le test `!!(m.mitre || m.source || m.recherche)`
// de la barre — et TOUTES DEUX oubliaient le quatrième discriminant que `alertListModel` déclare, le filtre
// d'affichage `uncased`, celui qui est ARMÉ PAR DÉFAUT (`S.alertUncased !== false`). Une restriction de plus
// n'a désormais qu'à être nommée ICI pour entrer d'un coup dans le survol, dans les deux questions de
// confirmation et dans le motif du bouton inerte.
// La PORTÉE (« tous statuts ») n'est pas une restriction : elle n'exclut aucune alerte, elle en ajoute —
// mais elle PAGINE, ce dont la phrase du reste tient compte par la présence d'un `total`.
// CHAQUE RESTRICTION DIT SI L'ANALYSTE L'A POSÉE, parce que la console en fait deux choses différentes :
//   `posee: true`  — une facette servie par le démon ou une recherche locale : l'analyste l'a demandée.
//     Sous elle, « Tout acquitter » se lirait « acquitter tout ce qui relève de ce filtre », geste qui
//     N'EXISTE PAS côté démon : la console le RETIRE, et le dit (`aucun_geste_a_filtre`).
//   `posee: false` — le filtre d'affichage, forme PAR DÉFAUT de la liste. Le geste global le franchit LUI
//     AUSSI : `POST /api/alerts/ack-all` ne prend aucun paramètre et acquitte donc les alertes déjà reprises
//     dans un cas, que cette liste écarte et NOMME juste au-dessus (`countLabel`, `porteeEnMots`). Ce que
//     la console fait ici n'est pas de retirer le geste — il ne partirait alors plus d'AUCUN écran, celui
//     d'arrivée étant le seul où aucune facette n'est posée — mais de le NOMMER dans la QUESTION de sa
//     confirmation (`questionDuGesteGlobal`), la seule surface que l'analyste lit au moment d'engager.
//   CE QUE CE CHOIX NE TIENT PAS : le geste global reste plus large que la liste sous laquelle il est
//     offert. Il le DIT désormais, il ne le corrige pas. Les deux façons de le corriger sortent de ce
//     module — que le démon porte le filtre d'affichage sur `ack-all`, ou que la console retire le geste
//     sous ce filtre comme sous une facette (ce qui change ce que la barre offre à l'arrivée) — et elles
//     sont portées par `P11.1-h`, ouverte.
function restrictionsDeLaListe(m) {
  const r = [];
  if (m.source) r.push({ posee: true, nom: motDeLAcquittement('la_source', { v: m.source }) });
  if (m.mitre) r.push({ posee: true, nom: motDeLAcquittement('la_technique', { v: m.mitre }) });
  if (m.recherche) r.push({ posee: true, nom: motDeLAcquittement('la_recherche', { v: m.recherche }) });
  if (m.uncased) r.push({ posee: false, nom: motDeLAcquittement('hors_cas') });
  return r;
}
// Les restrictions que l'analyste a POSÉES, nommées : ce que la phrase de l'acquittement par liste énonce.
const filtresDeLaListe = (m) => restrictionsDeLaListe(m).filter(r => r.posee).map(r => r.nom);
// LE GESTE GLOBAL EST OFFERT OU NON PAR LA MÊME DÉRIVATION, ET NON PAR UNE SECONDE ÉNUMÉRATION : aucune
// restriction POSÉE, et la portée « actives » (« tous statuts » PAGINE, le geste dépasserait la page sans
// que le démon déclare de quoi).
const gesteGlobalOffert = (m) => !filtresDeLaListe(m).length && !m.scopeAll;
// `{ survol, phrase, sansObjet }` de l'acquittement PAR LISTE, écrits par un SEUL auteur.
// `loaded.total` = la population que le démon DÉCLARE pour cette liste, ou `undefined` quand il n'en
// déclare aucune (c'est la seule façon dont la console apprend qu'une liste est bornée).
function porteeDeLAcquittement(m, loaded) {
  loaded = loaded || {};
  const filtres = filtresDeLaListe(m);
  const dits = [motDeLAcquittement('affichees')];
  if (filtres.length) dits.push(motDeLAcquittement('aucun_geste_a_filtre'));
  dits.push(motDeLAcquittement(typeof loaded.total === 'number' ? 'reste_autres_pages' : 'reste_indeterminable'));
  const n = (loaded.ackableIds || []).length;
  const sous = filtres.length ? motDeLAcquittement('sous_les_filtres', { filtres: filtres.join(' + ') }) : '';
  const tete = motDeLAcquittement('tete', { n, sous });
  return {
    survol: `${tete}. ${dits.join(' ')}`,
    phrase: `${tete}${motDeLAcquittement('avant_la_question')}${dits.join(' ')}`,
    // LE MOTIF D'UN BOUTON INERTE PORTE LA MÊME RAISON : un lecteur qui trouve le bouton gris apprend au
    // même endroit que « Tout acquitter » n'aurait pas porté ce filtre non plus.
    sansObjet: filtres.length ? motDeLAcquittement('aucun_geste_a_filtre') : '',
  };
}
// LA QUESTION DU GESTE GLOBAL — MÊME AUTEUR que le survol et la question de l'acquittement par liste.
// `POST /api/alerts/ack-all` ne prend aucun paramètre : le geste franchit TOUTE restriction que la liste
// pose. Ce qu'il franchit est donc DÉRIVÉ de `restrictionsDeLaListe` au lieu d'être nommé en dur — là où la
// console l'offre, les restrictions POSÉES sont vides par construction (`gesteGlobalOffert`), et ce qui
// reste est exactement ce que la question doit avouer. Une restriction de plus qui ne retirerait pas le
// geste y entrerait d'elle-même.
// LE COMPTE VIENT DE `loaded.count`, PAS DE `countLabel` : `countLabel` est une phrase française composée
// par la vue (`porteeEnMots`), l'interpoler ici rendrait sous `LANG='en'` la phrase mi-anglaise que ce
// module vient de fermer ailleurs.
function questionDuGesteGlobal(m, loaded) {
  loaded = loaded || {};
  const franchies = restrictionsDeLaListe(m).map(r => r.nom);
  const dits = [motDeLAcquittement('global_hors_page')];
  if (franchies.length) dits.push(motDeLAcquittement('global_franchit', { restrictions: franchies.join(' + ') }));
  dits.push(motDeLAcquittement('liste_courante', { n: typeof loaded.count === 'number' ? loaded.count : 0 }));
  return `${motDeLAcquittement('tete_globale')} ${dits.join(' ')}`;
}
// Ce que la barre propose, DÉRIVÉ du modèle `m` et de ce qui est chargé (`loaded`) :
//   loaded.count / loaded.countLabel  — le compte affiché et sa portée en toutes lettres ;
//   loaded.ackableIds                 — les ids ACTIFS chargés (vue plate) ; vide en vue groupée ;
//   loaded.sourceSpan                 — {from,to} des alertes listées sous une facette source (P11.1-c) ;
//   loaded.total                      — la population DÉCLARÉE par le démon, ou absente (P11.1-g).
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
  const filtered = !gesteGlobalOffert(m);
  const nAck = (loaded.ackableIds || []).length;
  // P11.1-g — LE SURVOL ET LA CONFIRMATION ONT LE MÊME AUTEUR : ce que le bouton promet au survol est
  // MOT POUR MOT ce que la question de la confirmation engage.
  const acq = porteeDeLAcquittement(m, loaded);
  let ack;
  if (!filtered) ack = `<button type="button" class="btn btn-sm" data-act="ack-all"${dis(!(loaded.count > 0), 'aucune alerte active')} title="Acquitter TOUTES les alertes actives (y compris celles hors de cette page)">${ic('check')} Tout acquitter</button>`;
  else if (nAck > 0) ack = `<button type="button" class="btn btn-sm" data-act="ack-shown" title="${esc(acq.survol)}">${ic('check')} Acquitter les ${nAck} affichée(s)</button>`;
  else ack = `<button type="button" class="btn btn-sm" data-act="ack-shown"${dis(true, (m.view ? 'acquittement par liste : dépliez un groupe (acquittement par occurrence) ou passez en vue plate' : 'aucune alerte active affichée') + (acq.sansObjet ? ' — ' + acq.sansObjet : ''))}>${ic('check')} Acquitter</button>`;
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
// P11.1-g — LE MODÈLE SOUS LEQUEL LA BARRE A ÉTÉ DESSINÉE EST PASSÉ ICI, il n'est pas RELU au clic. La
// question de la confirmation doit nommer les filtres que le lecteur AVAIT sous les yeux ; les relire dans
// l'état partagé au moment du clic ferait engager un geste sous des mots décrivant un autre écran.
function wireAlertActionBar(host, loaded, m) {
  const rerender = () => renderAlerts(true);
  host.querySelectorAll('.alertbar .agseg').forEach(btn => btn.onclick = siActif(btn, () => setAlertGroupBy(btn.dataset.g)));
  host.querySelectorAll('[data-act]').forEach(btn => {
    const act = btn.dataset.act;
    if (act === 'scope') btn.onclick = siActif(btn, () => { S.alertGroupAll = !S.alertGroupAll; S.alertGroupPage = 0; S.alertHistPage = 0; rerender(); });
    else if (act === 'uncased') btn.onclick = siActif(btn, () => { S.alertUncased = !(S.alertUncased !== false); S.alertGroupPage = 0; S.alertHistPage = 0; rerender(); });
    else if (act === 'clear-mitre') btn.onclick = siActif(btn, () => setAlertMitreFilter(''));
    else if (act === 'clear-source') btn.onclick = siActif(btn, () => setAlertSourceFilter(''));
    else if (act === 'ack-all') btn.onclick = siActif(btn, () => withBusy(btn, async () => {
      // La portée est NOMMÉE dans la question, parce que ce geste dépasse la page affichée ET le filtre
      // d'affichage sous lequel la liste est rendue. MÊME auteur que le reste (`questionDuGesteGlobal`).
      if (!await acquitter({ toutes: true, phrase: questionDuGesteGlobal(m, loaded) })) return;
      await refresh();
    }));
    else if (act === 'ack-shown') btn.onclick = siActif(btn, () => withBusy(btn, async () => {
      const ids = loaded.ackableIds || [];
      if (!ids.length) return;
      // P11.1-g — la question NOMME les filtres posés, dit que le geste ne les franchit pas, et dit ce
      // qui reste hors d'atteinte. MÊME auteur que le survol du bouton (`porteeDeLAcquittement`).
      if (!await acquitter({ ids, phrase: porteeDeLAcquittement(m, loaded).phrase })) return;
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

// `P10.7-d` — UN REFUS DU DÉMON ARRIVE EN 200, ET IL DOIT ÊTRE LU.
//
// CE QUI ÉCHAPPAIT À CE MODULE, MESURÉ LE 2026-08-29 EN EXERÇANT `renderAlerts` SUR UN CORPS FABRIQUÉ.
// `api()` (core.js) ne jette que sur `!r.ok`, sur un corps vide ou sur un corps non-JSON. Depuis
// `P10.7-c`, le portillon de concurrence CLOS rend un corps 200 qui garde la forme attendue
// (`{"alerts":[]}`, `{"groups":[],"group":…}`) et y AJOUTE sa cause sous `error`. Ce module ne lisait
// `error` nulle part : il en tirait `resp.alerts || []`, donc une liste vide, et la vue rendait
// « 0 alerte(s) … Aucune alerte active pas encore dans un cas ». Une lecture NON EXÉCUTÉE se lisait comme
// une absence ÉTABLIE — c'est-à-dire comme un fait, et le seul fait dont un analyste tire une conclusion.
//
// LE TEST EST SÉPARÉ DE CELUI DU VIDE, et ce n'est pas un style : les fondre est exactement ce que
// `check_a_refusal_is_not_rendered_as_an_absence.py` rend non-écrivable dans `web/`. Cette garde ne
// pouvait pas voir le défaut d'ici — elle juge les conditions qui TESTENT un échec, et ce module n'en
// portait aucune sur ces routes. Une condition absente n'est pas une condition fautive.
//
// LA CAUSE EST RENDUE TELLE QUELLE. Elle est écrite UNE seule fois, dans le démon
// (`daemon/src/handlers/portillon.rs`) ; la recopier ici en ferait un second porteur qui vieillirait sans
// le dire. Ce module n'ajoute que ce que le démon ne peut pas savoir : QUELLE vue a été demandée.
//
// `P11.21-h` — IL Y A TROIS ÉTATS, PAS DEUX, ET LE TROISIÈME EST NÉ LE 2026-08-30.
//
// CE QUE CE BLOC AFFIRMAIT ET QUI EST DEVENU FAUX LE JOUR MÊME : que le refus pouvait l'emporter sur les
// lignes servies à côté, parce qu'aucun corps du démon ne portait les deux. Depuis `P10.7-f`, la voie
// unique du corps de `/api/alerts` (`corps_de_liste_d_alertes`, `daemon/src/handlers/alerts.rs`) ajoute une
// cause à un corps qui porte des lignes RÉELLES quand le parcours a été coupé : la page servie est un
// PRÉFIXE. La règle « le refus l'emporte » jetait alors les lignes reçues et annonçait que rien n'avait
// été lu — MOINS que ce qui est su, donc prudent, mais faux.
//
// LES TROIS ÉTATS SONT DÉRIVÉS DU CORPS, JAMAIS DE LA ROUTE. Une cause SANS aucune ligne est un REFUS
// (rien n'a été lu) ; une cause AVEC des lignes est une page INCOMPLÈTE (un préfixe a été lu) ; pas de
// cause est une lecture entière. Rien ici n'énumère les routes qui savent tronquer : une route qui
// l'apprendra demain entre dans le troisième état sans qu'un nom soit ajouté ici, et une route qui ne
// sert jamais les deux reste dans les deux premiers sans qu'un cas mort soit écrit.
//
// LE SENS DE L'ERREUR NE S'INVERSE PAS. Le troisième état MONTRE PLUS qu'avant, il ne promet pas plus :
// l'aveu est rendu AVANT les lignes, et le compte de la barre cesse de se présenter comme une population.
// Ce qu'un lecteur ne doit jamais tirer d'un préfixe — un compte, ou l'absence de ce qu'il y cherchait —
// est dit par la cause du démon elle-même, qui est collée telle quelle.
//
// L'ÉTAT D'UNE LECTURE SERVIE : `{ cause, refus, incomplet }`, dérivé du corps et du lot de
// lignes que l'appelant en a tiré. Écrit UNE fois pour les trois chargements de ce module.
//
// LA CAUSE EST LUE ICI MÊME, ET CE N'EST PAS UN CHOIX D'ÉCRITURE — C'EST UNE MESURE DU 2026-08-30. Ce
// module portait un `causeDuRefusServi(r)` que ce corps-ci appelait ; `check_a_refusal_is_not_rendered_as_an_absence.py`
// (jambe B) est alors passé de 0 à 3 accusations sur `alerts.js`. Sa lecture des lecteurs va d'UN cran :
// elle reconnaît une fonction du module dont le corps PROPRE porte `.error`, et ne suit aucune
// indirection. Interposer une fonction de plus entre l'appel et le champ AVEUGLE donc la garde — un
// remaniement qui ne casse rien, ne fait rougir personne à l'exécution, et RÉTRÉCIT le canal de
// détection. Les deux fonctions sont fondues en une : un seul lecteur du champ servi, et la garde le voit.
function etatDeLaLectureServie(r, lignes) {
  const cause = (r && r.error != null) ? String(r.error).trim() : '';
  const servies = (lignes && lignes.length) ? lignes.length : 0;
  return { cause, refus: !!cause && servies === 0, incomplet: !!cause && servies > 0 };
}
// La phrase du refus : bilingue par construction, et la cause du démon collée telle quelle.
function motDuRefusServi(quoi, cause) {
  return LANG === 'en'
    ? quoi + ' NOT READ: the daemon declined and names the cause — "' + cause
      + '" This is NOT an absence: nothing was read, so nothing here is established.'
    : quoi + " NON LUES : le démon a refusé et en nomme la cause — « " + cause
      + " » Ce n'est PAS une absence : rien n'a été lu, donc rien ici n'est établi.";
}
// `P11.21-h` — LA PHRASE DE LA PAGE INCOMPLÈTE. Elle n'est PAS celle du refus, et la différence n'est pas
// de ton : « rien n'a été lu » serait FAUX ici, et ce module rendrait une absence là où il tient un
// préfixe. Elle n'ajoute que ce que le démon ne peut pas savoir — QUELLE vue a été demandée, et que ce
// qui suit à l'écran est ce préfixe. Ce qu'un préfixe interdit de conclure est déjà dans la cause servie,
// écrite une seule fois côté démon : la redire ici en ferait un second porteur qui vieillirait sans le dire.
function motDeLaPageIncomplete(quoi, cause) {
  return LANG === 'en'
    ? quoi + ' PARTIALLY READ — the daemon served rows AND names a cause: "' + cause
      + '" What is displayed below is that partial read, and nothing more.'
    : quoi + " PARTIELLEMENT LUES — le démon a servi des lignes ET en nomme la cause : « " + cause
      + " » Ce qui est affiché ci-dessous est cette lecture partielle, et rien de plus.";
}
// `P11.21-h` — LE COMPTE DE LA BARRE CESSE D'ÊTRE UNE POPULATION SUR UN PRÉFIXE. Sans ce mot, le seul
// endroit où l'exploitant lit un nombre continuerait d'annoncer « N alerte(s) · <portée> » comme un fait,
// et montrer les lignes RETOURNERAIT le sens de l'erreur : il croirait tenir la liste.
function motDuCompteIncomplet() {
  return LANG === 'en'
    ? ' · INCOMPLETE READ: this number counts the rows read, not those that exist'
    : ' · LECTURE INCOMPLÈTE : ce nombre compte les lignes lues, pas celles qui existent';
}
// L'aveu d'une page incomplète, rendu AVANT les lignes. Vide — donc byte-neutre — sur une lecture entière.
function bandeauDePageIncomplete(quoi, etat) {
  return etat.incomplet ? '<div class="bad">' + esc(motDeLaPageIncomplete(quoi, etat.cause)) + '</div>' : '';
}

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
  let etat = { cause: '', refus: false, incomplet: false };
  try { const resp = await api(url); alerts = resp.alerts || []; alertTotal = resp.total; etat = etatDeLaLectureServie(resp, alerts); } catch (e) { b.classList.remove('reloading'); b.innerHTML = '<div class="bad">alertes indisponibles : ' + esc(e.message) + '</div>'; return; }
  b.classList.remove('reloading');
  // `P10.7-d` — LE REFUS, AVANT TOUTE LECTURE DE LA FORME. Il ne passe pas par `alertesChargees` : une
  // frappe de recherche redessine le dernier lot SERVI, et un lot qui n'existe pas ne se redessine pas.
  // `P11.21-h` — C'EST BIEN LE REFUS, ET PLUS TOUTE CAUSE SERVIE : une page incomplète porte une cause ET
  // des lignes, et elle passe par le chemin du dessin, avec son aveu.
  if (etat.refus) { b.innerHTML = '<div class="bad">' + esc(motDuRefusServi(LANG === 'en' ? 'Alerts' : 'Alertes', etat.cause)) + '</div>'; return; }
  // P11.1-f — LE LOT SERVI EST MÉMORISÉ, et le dessin en est séparé : une frappe REDESSINE, elle ne
  // recharge pas. Sans cette scission, chercher coûterait une requête HTTP par caractère pour un travail
  // qui est une comparaison de chaînes sur des lignes déjà en mémoire.
  // `P11.21-h` — L'ÉTAT EST MÉMORISÉ AVEC LE LOT, et pour la même raison : une frappe de recherche
  // redessine ce lot sans redemander, et un aveu qui ne survivrait pas au redessin disparaîtrait au
  // premier caractère tapé — l'exploitant tiendrait alors un préfixe présenté comme une page.
  alertesChargees = { alerts, alertTotal, etat };
  dessinerLaListePlate(b, alertListModel(), alerts, alertTotal, etat);
}

// LE DESSIN de la vue plate, sur un lot DÉJÀ servi. Séparé du chargement pour la recherche (`P11.1-f`),
// et c'est aussi ce qui le rend jugeable par le harnais sans réseau.
function dessinerLaListePlate(b, m, alerts, alertTotal, etat) {
  // `P11.21-h` — L'ÉTAT EST FACULTATIF : un appelant qui n'en passe pas dessine une lecture ENTIÈRE, ce
  // qui est exactement ce que faisaient les appelants d'avant. Le troisième état s'ajoute, il ne déplace rien.
  etat = etat || { cause: '', refus: false, incomplet: false };
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
    countLabel: `${count} alerte(s) · ${portee}${m.mitre ? ' · technique ' + m.mitre : ''}${m.source ? ' · source ' + m.source : ''}${etat.incomplet ? motDuCompteIncomplet() : ''}`,
    ackableIds: affichees.filter(a => a.status === 'new').map(a => a.id),
    sourceSpan,
    // P11.1-g — la population TELLE QUE LE DÉMON LA DÉCLARE, transmise NUE : `undefined` quand il n'en
    // déclare aucune. `count` ne peut pas en tenir lieu — il retombe sur la taille du lot servi, donc il
    // vaut un nombre y compris là où le démon n'a rien déclaré, et ce nombre serait pris pour une population.
    total: alertTotal,
  };
  // `P11.21-h` — L'AVEU PRÉCÈDE LA BARRE ET LES LIGNES : c'est la première chose lue, et il l'est avant
  // le compte qu'il qualifie. Sur une lecture entière il vaut la chaîne vide, donc le balisage rendu est
  // byte-identique à celui d'avant cette clé.
  const aveu = bandeauDePageIncomplete(LANG === 'en' ? 'Alerts' : 'Alertes', etat);
  const bar = aveu + alertActionBarHtml(m, loaded);
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
    wireAlertActionBar(b, loaded, m);
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
  wireAlertActionBar(b, loaded, m);
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
  let etat = { cause: '', refus: false, incomplet: false };
  try { const r = await api(url); groups = r.groups || []; total = r.total; etat = etatDeLaLectureServie(r, groups); }
  catch (e) { b.classList.remove('reloading'); b.innerHTML = alertActionBarHtml(m, { count: 0, countLabel: 'groupes indisponibles' }) + '<div class="bad">groupes indisponibles : ' + esc(e.message) + '</div>'; wireAlertActionBar(b, { count: 0 }, m); return; }
  b.classList.remove('reloading');
  // `P10.7-d` — même geste que la vue plate : le refus est rendu là où l'échec l'était déjà, et la barre
  // d'actions y reste inerte (aucun compte n'a été lu, donc aucun geste de masse n'a de portée connue).
  // `P11.21-h` — LA MÊME DÉRIVATION QU'AILLEURS, ET « LE JOUR OÙ » A DURÉ UNE HEURE. Cette vue a d'abord
  // été relevée INERTE — au moment de la mesure, le seul aveu de `/api/alerts/groups` était le corps de
  // refus du portillon, qui sert une forme VIDE. La phrase était vraie et a cessé de l'être PENDANT que
  // cette clé était payée : `corps_de_liste_de_groupes` (`daemon/src/handlers/alerts.rs`) sert désormais
  // des GROUPES RÉELS avec leur cause quand le parcours a été coupé, et cette route atteint donc bien le
  // troisième état. Rien n'a eu à être ajouté ici pour cela : l'état est dérivé du CORPS et non de la
  // route, et c'est exactement ce que cette dérivation achetait. L'écrire route par route aurait rouvert
  // le défaut de cette clé sur la vue groupée, le jour même.
  if (etat.refus) {
    b.innerHTML = alertActionBarHtml(m, { count: 0, countLabel: LANG === 'en' ? 'groups NOT READ' : 'groupes NON LUS' })
      + '<div class="bad">' + esc(motDuRefusServi(LANG === 'en' ? 'Alert groups' : "Groupes d'alertes", etat.cause)) + '</div>';
    wireAlertActionBar(b, { count: 0 }, m); return;
  }
  const aveuDesGroupes = bandeauDePageIncomplete(LANG === 'en' ? 'Alert groups' : "Groupes d'alertes", etat);
  const axisLabel = { rule: 'règle', host: 'hôte', mitre: 'technique' }[m.view] || m.view;
  const count = typeof total === 'number' ? total : groups.length;
  const portee = porteeEnMots(m);
  // `total` = nombre de GROUPES déclaré par le démon ; `ackableIds` est vide en vue groupée (rien n'est
  // acquittable depuis la liste de groupes), la phrase de P11.1-g ne sert donc ici qu'au bouton inerte.
  const loaded = { count, countLabel: `${count} groupe(s) · par ${axisLabel} · ${portee}${m.mitre ? ' · technique ' + m.mitre : ''}${m.source ? ' · source ' + m.source : ''}${etat.incomplet ? motDuCompteIncomplet() : ''}`, ackableIds: [], total };
  const bar = aveuDesGroupes + alertActionBarHtml(m, loaded);
  if (!groups.length) {
    b.innerHTML = bar + `<div class="ok">Aucune alerte ${m.scopeAll ? '' : 'active '}à trier${m.source ? ` pour la source ${esc(m.source)}` : ''}</div>`;
    wireAlertActionBar(b, loaded, m); return;
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
  wireAlertActionBar(b, loaded, m);
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
  let etat = { cause: '', refus: false, incomplet: false };
  try { const r = await api(url); occ = r.alerts || []; total = r.total; etat = etatDeLaLectureServie(r, occ); }
  catch (e) { body.innerHTML = '<div class="bad">occurrences indisponibles : ' + esc(e.message) + '</div>'; return; }
  // `P10.7-d` — `body.dataset.loaded` N'EST PAS POSÉ SUR UN REFUS, et c'est la moitié qui compte : ce
  // drapeau dit « ce groupe porte ses occurrences ». Le poser sur un refus figerait l'aveu, et le dépli
  // suivant ne redemanderait rien.
  if (etat.refus) { body.innerHTML = '<div class="bad">' + esc(motDuRefusServi(LANG === 'en' ? 'Occurrences' : 'Occurrences', etat.cause)) + '</div>'; return; }
  // `P11.21-h` — UNE PAGE D'OCCURRENCES INCOMPLÈTE EST BIEN CHARGÉE, elle : `dataset.loaded` est posé
  // parce que ce groupe porte réellement des occurrences. Ce qui manque est DIT au-dessus d'elles, et le
  // pager qui suit reste dérivé du `total` que le démon déclare, jamais de la longueur du préfixe.
  body.dataset.loaded = '1';
  body.dataset.opage = String(opage); // ui-regression : mémorise la page pour la restaurer après un rebuild (auto-refresh)
  body.innerHTML = bandeauDePageIncomplete(LANG === 'en' ? 'Occurrences' : 'Occurrences', etat)
    + (occ.map((a, i) => alertRowHtml(a, i)).join('') || '<div class="muted">aucune occurrence</div>');
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
  dessinerLaListePlate(b, m, alertesChargees.alerts, alertesChargees.alertTotal, alertesChargees.etat);
}
(() => {
  const champ = $('#alert-search'); if (!champ) return;
  const poignee = champDeRecherche(champ, { auChangement: () => redessinerLesAlertes() });
  rechercheDesAlertes = poignee.valeur; poserLaRechercheDesAlertes = poignee.poser;
})();

export { renderAlerts, setAlertMitreFilter, setAlertSourceFilter, alertActionBarHtml, alertListModel,
  dessinerLaListePlate, redessinerLesAlertes, poserLaRechercheDesAlertes, texteCherchableDUneAlerte,
  pivotDUneAlerte, alertDrill, machineDUneAlerte, porteeDeLAcquittement, questionDuGesteGlobal };
