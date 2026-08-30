// attack.js — matrice de couverture MITRE ATT&CK (espace Détection & Réponse, onglet « ATT&CK »).
// ADDITIF, comportement-préservant. LECTURE seule, viewer+ (donnée de posture, pas un secret).
//
// P11.6-b — UNE TECHNIQUE EST UNE PORTE, PAS UNE CASE DE TABLEAU. La matrice disait la couverture et
// laissait l'analyste repartir de zéro dans un autre panneau. MESURÉ le 2026-08-23 sur les routes servies
// et sur cette surface : la sortie « alertes » EXISTAIT DÉJÀ (le clic posait la facette de la technique
// sur la file d'alertes, `setAlertMitreFilter`, cf. `P11.1-b`), et de là le lien exact vers l'Explore est
// celui que le démon sert AVEC chaque alerte (`search_link`, `P11.1-a`). Ce module ne fabrique donc AUCUNE
// requête : la sortie « détections » reste ce même appel, inchangé. Ce qui manquait, ce sont les deux
// autres sorties — les RÈGLES qui couvrent la technique, et le geste qui la couvrirait quand rien ne la
// couvre. `/api/coverage/attack` ne sert que des COMPTES par technique (aucun identifiant de règle) : la
// porte des règles n'invente pas une jointure côté console, elle ouvre le panneau des règles SUR la
// technique, par la recherche partagée (`P11.12-a`) — l'identifiant d'une cellule est la technique PARENTE,
// et l'inclusion de chaîne y retrouve aussi les règles taguées par une sous-technique.
// Endpoint (construit par le daemon — item concurrent) :
//   GET /api/coverage/attack -> { tactics:[{ tactic, rule_count, covered,
//                                            techniques:[{ tid, name|null, rule_count, alert_count, covered }] }],
//                                 totals }
// Rendu : tactiques en COLONNES, techniques en CELLULES colorées par couverture (couvert = échelle verte
// selon rule/alert_count ; non couvert = grisé -> les ANGLES MORTS ressortent). Clic technique -> ses alertes.
// DÉGRADATION : si l'endpoint 404 (daemon non déployé), message « couverture indisponible » (pas d'erreur dure).
// SÉCU UI : tout en textContent/attributs (anti-XSS). Aucune mutation (aucun apiSend).
import { $, LANG, api, muted, socIsAdmin, socRole, closeModals } from './core.js';
import { setAlertMitreFilter } from './app.js';
import { openSigmaImport } from './sigmaimport.js';

// P11.6-a — LE NOM D'UNE TECHNIQUE EST DÉRIVÉ, JAMAIS LAISSÉ VIDE. MESURÉ le 2026-08-22 : le démon
// n'émettait aucun `name` et cette matrice rendait `t.name || ''` -> TOUTES les cellules (183 techniques
// du catalogue) n'avaient qu'un numéro. Le nom servi par le démon (`attack_names`, sous-technique résolue
// par son parent côté serveur) est la SEULE source ; sinon le MOT « nom inconnu » — un identifiant hors
// catalogue (retiré, personnalisé, mal saisi) se DIT, il ne se tait pas. `null` = inconnu ; jamais vide.
//
// P11.6-c — CETTE MATRICE N'A PLUS DE SECONDE SOURCE. Elle repliait sur la table de `core.js` quand le
// démon ne nommait pas ; cette table était un second porteur du même savoir, et un repli recopié à la main
// n'est pas un repli mais une source qui vieillit sans le dire. MESURÉ le 2026-08-24, sur les deux textes :
// la route `/api/coverage/attack` émet un nom pour CHACUNE des techniques qu'elle énumère (elle parcourt
// tout le catalogue, tactique par tactique) et ne rend jamais de sous-technique — les tags y sont repliés
// sur leur technique parente. Le repli ne pouvait donc s'appliquer qu'à ce que la route ne sert pas : rien.
// Il ne couvrait en pratique qu'un démon ANTÉRIEUR au nom servi, et dans ce cas la console n'a jamais à
// deviner : l'absence est DITE (« nom inconnu ») et l'infobulle en donne la raison. Une console qui connaît
// 14 libellés par cœur sur 183 ne rend pas ce cas meilleur, elle le rend inégal.
const NOM_INCONNU = 'nom inconnu';
function techniqueDisplayName(t) {
  const servi = t && typeof t.name === 'string' ? t.name.trim() : '';
  return servi || null;
}

// Intensité de couverture d'une technique : max(rule_count, alert_count). Sert l'échelle de couleur.
function techWeight(t) { return Math.max(Number(t && t.rule_count) || 0, Number(t && t.alert_count) || 0); }

// P9.5-a — LE TROISIÈME ÉTAT D'UNE TECHNIQUE, LU UNE SEULE FOIS.
//
// CE QUE CETTE SURFACE DISAIT ET QUI ÉTAIT FAUX, RETIRÉ LE 2026-08-27. Le démon avait cessé de compter
// couvertes les techniques dont la seule règle est activée mais qu'aucun producteur ne nourrit — la
// correction juste. Il ne servait pourtant que DEUX états, et cette surface rendait donc la règle affamée
// avec le vocabulaire de l'absence : « ANGLE MORT : aucune règle activée ne couvre cette technique »,
// la sortie vers la règle INERTE (« il n'y a rien à ouvrir »), et « Créer la règle qui la couvrira » mis
// en avant. Les trois étaient FAUX pour cette population : la règle EXISTE, elle est ACTIVÉE, et le geste
// prescrit est nuisible — une seconde règle qui n'épingle aucune source rendrait la technique de nouveau
// « couverte » sans que rien ne tire davantage. Un mensonge en remplaçait un autre.
//
// LE DÉMON SERT MAINTENANT LA RAISON (`rules_en_attente_de_source`, `sources_manquantes`), et c'est elle
// qui rend ce cas ACTIONNABLE : brancher le producteur suffit, aucune règle à écrire. `enAttente` ne se
// confond ni avec le premier état (elle ne couvre pas : `covered` reste faux, ce qui est vrai — rien ne
// peut la déclencher) ni avec le dernier (une règle la porte, et la console doit y MENER).
//
// DEUX BORNES, ÉCRITES : un démon ANTÉRIEUR ne sert aucune des deux clés — `enAttente` vaut alors 0 et la
// technique retombe dans « angle mort », c'est-à-dire le comportement d'avant, jamais une affirmation
// neuve ; et la liste des sources peut être VIDE alors que le compte ne l'est pas (le démon a compté sans
// pouvoir nommer) — la porte le DIT plutôt que d'afficher une énumération vide.
function reglesEnAttente(t) { return Math.max(0, Number(t && t.rules_en_attente_de_source) || 0); }
function sourcesManquantes(t) {
  const v = t && t.sources_manquantes;
  return Array.isArray(v) ? v.filter(x => typeof x === 'string' && x.trim()).map(x => x.trim()) : [];
}
// Une technique est EN ATTENTE DE SOURCE quand rien ne peut la déclencher ET qu'une règle la porte déjà.
function enAttenteDeSource(t) { return !(t && t.covered) && reglesEnAttente(t) > 0; }

// Teinte d'une cellule couverte : color-mix de --ok, d'autant plus soutenu que la couverture est dense.
// `w` = poids de la technique, `max` = poids max observé -> pourcentage 16..58 %.
// PLAFOND 58 % (peaufinage lisibilité) : au-delà le vert sature et le texte (--fg) décroche du contraste
// dans les DEUX thèmes (sombre : le vert s'éclaircit vers le fg clair ; clair : le vert fonce vers le fg
// sombre). Le dégradé de densité reste lisible ; la légende ci-dessous reflète les mêmes bornes.
function coveredBg(w, max) {
  const t = max > 0 ? Math.min(1, w / max) : 0;
  const pct = Math.round(16 + t * 42);
  return 'color-mix(in srgb, var(--ok) ' + pct + '%, transparent)';
}

// `P11.21-j` — LE SOUS-COMPTE SE DIT SUR LA CELLULE, PAS SEULEMENT EN TÊTE DE PAGE.
//
// LE CONSTAT EST À L'ÉCHELLE DE LA CELLULE, ET `P11.21-i` NE L'A FERMÉ QU'À CELLE DE LA PAGE. L'aveu ouvre
// le rendu, au-dessus de la matrice. Un lecteur qui survole une cellule sans avoir lu ce bandeau lit
// `1r/0a` comme un COMPTE ; sur une matrice de couverture purple, un compte d'alertes trop bas se lit
// « angle mort de détection », et c'est le verdict le plus coûteux que cette surface puisse rendre.
//
// LA QUESTION TRANCHÉE, ET LE CHIFFRE QUI LA TRANCHE (mesuré le 2026-08-30). Descendre le mot dans la
// FABRIQUE DE CELLULE, ou faire REFUSER à la page les ratios qu'elle sait partiels ? La seconde branche
// est écartée pour deux raisons, l'une mesurée, l'autre lue dans le démon :
//   * LA TAILLE — une matrice réelle compte 183 cellules, pas « beaucoup ». C'est le nombre d'entrées du
//     catalogue partagé (`guatx_core::attack::CATALOG`, épinglé par `daemon/Cargo.lock` sur v0.2.4,
//     07b13cf), chacune rendue UNE fois puisque `techniques_for_tactic` filtre sur la tactique unique de
//     l'entrée. Un booléen évalué 183 fois ne pèse rien devant les quatre `createElement`, la fermeture de
//     clic et l'infobulle que chaque cellule construit déjà. Le « chemin très chaud » n'existe pas ici :
//     c'est mesuré, pas supposé, et l'argument de coût qui poussait vers l'autre branche tombe.
//   * LE SENS DE L'ERREUR — refuser les ratios ferait voir MOINS à l'exploitant, et moins que ce qui est
//     ÉTABLI : la cause servie sur cette route dit que seuls les comptes d'ALERTES sont des sous-comptes,
//     et que la couverture (`covered`, `rule_count`) ne vient pas de cette lecture. Effacer un compte de
//     règles au motif qu'un compte d'alertes est incertain serait un second verdict faux, en sens inverse.
//
// LA MARQUE EST DONC LA PLUS PETITE QUI RESTE VRAIE : un signe « au moins » collé au SEUL nombre qui est
// un minorant. Elle ne touche ni le compte de règles ni l'état de couverture. Elle ne crie pas — une
// matrice dont chaque cellule porterait un avertissement ne se lirait plus, donc n'avertirait plus. Le
// POURQUOI vit dans l'infobulle, bilingue par construction ; la cause du démon, elle, reste écrite UNE
// fois en tête de la vue — la redire par cellule en ferait 183 porteurs qui vieilliraient ensemble.
//
// ET LA MARQUE EST CONDITIONNELLE : sur une lecture entière, cette cellule est byte-identique à celle
// d'avant cette clé. Une cellule qui porterait toujours le signe ne dirait plus rien.
//
// LE MOT DE L'INFOBULLE EST DÉRIVÉ, PAS RECOPIÉ. Il dit ce que le démon établit de CETTE route — un
// minorant sur les alertes, une couverture qui n'en dépend pas — sans reprendre sa phrase, qui
// vieillirait ici en second porteur.
function motDuSousCompteDAlertes() {
  return LANG === 'en'
    ? 'INCOMPLETE READ: this alert count is a LOWER BOUND — what was read, not what exists. The rule count and the coverage state do not come from that read and stand.'
    : "LECTURE INCOMPLÈTE : ce nombre d'alertes est un MINORANT — ce qui a été lu, pas ce qui existe. Le compte de règles et l'état de couverture ne viennent pas de cette lecture et tiennent.";
}

// Une cellule = une technique, en TROIS états : couverte -> fond vert (échelle) ; règle activée mais rien
// pour la nourrir -> classe .attente (trait plein, encre d'avertissement) ; aucune règle -> .uncovered (grisé
// pointillé). Les deux derniers partagent `covered:false`, et c'est vrai des deux — rien ne tire.
// `comptesDAlertesNonEtablis` (`P11.21-j`) : la lecture des alertes par technique n'est pas allée au bout,
// donc `alert_count` est un MINORANT. Absent ou faux -> rendu inchangé.
function techniqueCell(t, max, comptesDAlertesNonEtablis) {
  const tid = (t && t.tid) || '?';
  const covered = !!(t && t.covered);
  const attente = enAttenteDeSource(t);
  // Le signe ne paraît QUE là où un nombre d'alertes est affiché, c'est-à-dire sur une cellule couverte :
  // les deux autres états ne rendent que des mots de COUVERTURE, et la couverture reste établie.
  const minorant = !!comptesDAlertesNonEtablis && covered;
  const cell = document.createElement('button');
  cell.type = 'button';
  // TROIS classes pour TROIS états : une cellule en attente de source n'est pas grisée comme un angle
  // mort — la règle existe, et le grisé du vide dirait le contraire.
  cell.className = 'attack-cell' + (covered ? '' : attente ? ' attente' : ' uncovered');
  if (covered) cell.style.background = coveredBg(techWeight(t), max);
  const rc = Number(t && t.rule_count) || 0;
  const ac = Number(t && t.alert_count) || 0;
  const manquantes = sourcesManquantes(t);
  const idEl = document.createElement('span'); idEl.className = 'attack-tid'; idEl.textContent = tid;
  const cnt = document.createElement('span'); cnt.className = 'attack-cnt' + (covered ? '' : ' none');
  cnt.textContent = covered ? (rc + 'r/' + (minorant ? '≥' : '') + ac + 'a') : attente ? 'source manquante' : 'aucune règle';
  const nom = techniqueDisplayName(t);
  const nameEl = document.createElement('span'); nameEl.className = 'attack-tname' + (nom ? '' : ' attack-tname-inconnu');
  nameEl.textContent = nom || NOM_INCONNU;
  cell.append(cnt, idEl, nameEl);
  // Le clic OUVRE LA PORTE de la technique (`P11.6-b`) : la sortie vers ses alertes y est le même appel
  // qu'avant, à côté de celles qui manquaient. Le raccourci d'import en masse reste sur la légende (admin),
  // et il ne s'offre qu'aux VRAIS angles morts : importer un ruleset ne branche aucun producteur.
  const etatEnInfobulle = covered
    ? (rc + ' règle(s) · ' + (minorant ? '≥' : '') + ac + ' alerte(s)')
    : attente
      ? ("EN ATTENTE DE SOURCE — " + reglesEnAttente(t) + " règle(s) activée(s) portent cette technique, mais rien sur cette base ne produit ce qu'elles interrogent"
         + (manquantes.length ? '. Source(s) à brancher : ' + manquantes.join(', ') : ''))
      : 'ANGLE MORT — aucune règle ne couvre cette technique. Importez un ruleset Sigma pour la couvrir (bouton « Importer un ruleset Sigma »).';
  cell.title = tid + ' — ' + (nom || (NOM_INCONNU + " : identifiant hors du catalogue ATT&CK connu de la console (technique retirée, personnalisée ou mal saisie)"))
    + '\n' + etatEnInfobulle
    + (minorant ? '\n' + motDuSousCompteDAlertes() : '')
    + '\n' + 'Clic : ses règles, ses alertes, et le geste qui la couvrirait';
  cell.onclick = () => ouvrirLaPorteDeLaTechnique(t);
  return cell;
}

// --- P11.6-b : LA PORTE D'UNE TECHNIQUE ------------------------------------------------------------
// Les deux sorties qui quittent CE panneau sont posées par le panneau des règles lui-même (il seul sait
// ouvrir son formulaire et sa recherche). Elles arrivent ici par injection plutôt que par un import :
// `detection_admin.js` importe déjà ce module, l'importer en retour ferait un cycle dont l'un des deux
// bouts s'évaluerait à moitié.
const PORTES = { regles: null, creer: null };
function poserLesPortesDeTechnique(p) { PORTES.regles = (p && p.regles) || null; PORTES.creer = (p && p.creer) || null; }

// Un bouton de sortie. Une sortie impraticable est RENDUE, inerte, et son `title` DIT POURQUOI : une sortie
// absente ne se distingue pas d'une sortie oubliée. Le motif n'est pas collé au bout d'une phrase — chaque
// cas porte sa phrase ENTIÈRE, parce qu'un libellé composé à l'exécution n'a plus d'entrée exacte au
// lexique et ne se traduit donc jamais. `label:` et `title:` sont le vocabulaire d'option des fabriques de
// bouton de la console (`rowButton`), et les puits que la garde du lexique sait lire.
function sortieDePorte(o) {
  const b = document.createElement('button');
  b.type = 'button';
  b.className = 'btn' + (o.principal && !o.inerte ? ' btn-primary' : '');
  b.textContent = o.label;
  b.title = o.title;
  if (o.inerte) b.disabled = true; else b.onclick = o.onClick;
  return b;
}

// Le contenu de la porte, en un élément — construit sans toucher au document, donc jugeable tel quel.
// `fermer` referme l'enveloppe ; il vaut une fonction vide quand la porte est rendue hors overlay.
function porteDeLaTechnique(t, fermer = () => {}) {
  const tid = (t && t.tid) || '?';
  const nom = techniqueDisplayName(t);
  const couverte = !!(t && t.covered);
  const attente = enAttenteDeSource(t);
  const rc = Number(t && t.rule_count) || 0;
  const ac = Number(t && t.alert_count) || 0;
  const nAttente = reglesEnAttente(t);
  const manquantes = sourcesManquantes(t);
  const box = document.createElement('div');
  box.className = 'attack-porte';
  const h = document.createElement('h3');
  h.textContent = tid + ' — ' + (nom || NOM_INCONNU);
  const etat = document.createElement('p');
  etat.className = 'modal-msg';
  // LA PHRASE D'ÉTAT EST ENTIÈRE ET STATIQUE (donc au lexique), et le DÉTAIL — des comptes et des noms de
  // source — vit dans un nœud texte à côté : une phrase qui porterait le nombre dans son corps n'aurait
  // plus d'entrée exacte au lexique et ne se traduirait jamais.
  if (attente) {
    const phrase = document.createElement('span');
    phrase.textContent = "RIEN NE PEUT LA DÉCLENCHER : la ou les règles qui portent cette technique sont ACTIVÉES, mais aucune source de cette base ne produit ce qu'elles interrogent. Brancher le producteur suffit — il n'y a pas de règle à écrire.";
    const detail = manquantes.length
      ? ' ' + nAttente + " règle(s) en attente · source(s) à brancher : " + manquantes.join(', ') + '.'
      : ' ' + nAttente + " règle(s) en attente ; la matrice ne nomme aucune source, cette surface n'en invente pas.";
    etat.append(phrase, document.createTextNode(detail));
  } else {
    etat.textContent = couverte
      ? rc + ' règle(s) la couvrent · ' + ac + ' alerte(s) sur la fenêtre de la matrice.'
      : "ANGLE MORT : aucune règle activée ne couvre cette technique. Rien ne la détectera tant qu'aucune ne la porte.";
  }
  const sorties = document.createElement('div');
  sorties.className = 'attack-porte-sorties';

  // 1. LA SORTIE VERS LES RÈGLES — ouvre le panneau des règles sur cette technique (recherche partagée).
  //    ELLE EST PRATICABLE DANS LES DEUX CAS OÙ UNE RÈGLE EXISTE : couverte, et en attente de source. La
  //    rendre inerte sur le second était le défaut — la règle est là, activée, et c'est vers elle qu'il
  //    faut mener. Chaque cas porte sa phrase ENTIÈRE : un libellé composé à l'exécution n'aurait plus
  //    d'entrée exacte au lexique.
  sorties.appendChild(sortieDePorte({
    label: attente ? 'Voir les règles qui attendent leur source' : 'Voir les règles qui la couvrent',
    title: !PORTES.regles ? "Le panneau des règles n'est pas chargé."
      : attente ? "Ouvre le panneau des règles, la recherche posée sur cette technique : la ou les règles existent et sont activées — c'est leur source qui manque."
      : couverte ? "Ouvre le panneau des règles, la recherche posée sur cette technique (elle y retrouve aussi les règles taguées par une sous-technique)."
      : "Aucune règle ne couvre cette technique : il n'y a rien à ouvrir. C'est la sortie de création qui s'applique.",
    inerte: !PORTES.regles || !(couverte || attente),
    principal: couverte || attente,
    onClick: () => { fermer(); if (PORTES.regles) PORTES.regles(tid); },
  }));
  // 2. LES DÉTECTIONS QU'ELLE A NOURRIES — le pivot qui existait déjà, inchangé.
  sorties.appendChild(sortieDePorte({
    label: 'Voir les détections de cette technique',
    title: ac ? "Pose la facette de cette technique sur la file d'alertes ; de là, chaque alerte ouvre la recherche sur ce que sa règle a compté."
      : "Aucune alerte ne porte cette technique sur la fenêtre de la matrice.",
    inerte: !ac,
    onClick: () => { fermer(); setAlertMitreFilter(tid); },
  }));
  // 3. LE GESTE QUI LA COUVRIRAIT — formulaire de règle, technique pré-remplie. EN ATTENTE DE SOURCE, ce
  //    n'est PAS le geste utile : une seconde règle qui n'épingle aucune source rendrait la technique de
  //    nouveau « couverte » sans que rien ne tire davantage. Elle reste offerte — un exploitant peut
  //    vouloir écrire une règle sur une autre source — mais elle n'est ni mise en avant ni libellée
  //    « créer la règle qui la couvrira », qui serait faux.
  const peutEcrire = socRole() === 'admin' || socRole() === 'editor';
  sorties.appendChild(sortieDePorte({
    label: (couverte || attente) ? 'Ajouter une règle sur cette technique' : 'Créer la règle qui la couvrira',
    title: !PORTES.creer ? "Le panneau des règles n'est pas chargé."
      : !peutEcrire ? "Écrire une règle demande le rôle éditeur ; ce compte est en lecture seule."
      : attente ? "Ouvre le formulaire de règle avec cette technique déjà renseignée. Une règle de plus ne remplace pas le producteur qui manque : sans lui, elle ne tirera pas davantage."
      : "Ouvre le formulaire de règle avec cette technique déjà renseignée.",
    inerte: !PORTES.creer || !peutEcrire,
    principal: !couverte && !attente,
    onClick: () => { fermer(); if (PORTES.creer) PORTES.creer(tid); },
  }));
  // 4. COMBLER EN MASSE — l'affordance de la légende, à portée de la technique regardée (admin). Réservée
  //    aux VRAIS angles morts : importer une bibliothèque n'a jamais branché un producteur, et la proposer
  //    ici enverrait l'exploitant écrire des règles là où il lui faut poser une entrée.
  if (!couverte && !attente && socIsAdmin()) {
    sorties.appendChild(sortieDePorte({
      label: 'Importer un ruleset Sigma',
      title: 'Combler les angles morts en masse : importer une bibliothèque de détection Sigma.',
      onClick: () => { fermer(); openSigmaImport(); },
    }));
  }
  sorties.appendChild(sortieDePorte({ label: 'Fermer', title: 'Refermer sans quitter la matrice.', onClick: () => fermer() }));
  box.append(h, etat, sorties);
  return box;
}

// L'enveloppe : même chrome de modale que le reste de la console (`.modal-ov` / `.modal`), et les trois
// fermetures que les autres modales offrent déjà — le bouton, le fond, Échap (cf. `help.js`,
// `sigmaimport.js`). Le harnais juge la fermeture par le BOUTON : son document factice n'appelle aucun
// écouteur, donc ni le fond ni Échap n'y sont observables.
function ouvrirLaPorteDeLaTechnique(t) {
  closeModals();
  const ov = document.createElement('div'); ov.className = 'modal-ov';
  const box = document.createElement('div'); box.className = 'modal';
  const surTouche = e => { if (e.key === 'Escape') fermer(); };
  const fermer = () => { document.removeEventListener('keydown', surTouche); ov.remove(); };
  box.appendChild(porteDeLaTechnique(t, fermer));
  ov.appendChild(box);
  document.body.appendChild(ov);
  ov.onclick = e => { if (e.target === ov) fermer(); };
  document.addEventListener('keydown', surTouche);
}

// Une colonne = une tactique + ses techniques (couvertes triées en tête, angles morts ensuite).
// `comptesDAlertesNonEtablis` (`P11.21-j`) descend jusqu'à la cellule : c'est elle qui porte le nombre.
function tacticColumn(tac, max, comptesDAlertesNonEtablis) {
  const col = document.createElement('div'); col.className = 'attack-col';
  const techs = Array.isArray(tac && tac.techniques) ? tac.techniques.slice() : [];
  const covered = techs.filter(t => t && t.covered).length;
  const h = document.createElement('div'); h.className = 'attack-col-h';
  h.textContent = (tac && tac.tactic) || '(tactique ?)';
  const sub = document.createElement('span'); sub.className = 'attack-col-sub';
  // Le troisième état se voit AU NIVEAU DE LA COLONNE, et il est LU sur ce que le démon sert plutôt
  // que recompté ici : sans cela, il faudrait ouvrir une cellule pour apprendre qu'une tactique entière
  // n'attend qu'un producteur.
  const attCol = Math.max(0, Number(tac && tac.techniques_en_attente_de_source) || 0);
  sub.textContent = covered + ' / ' + techs.length + ' couverte(s)' + (attCol ? ' · ' + attCol + ' en attente de source' : '');
  h.appendChild(sub); col.appendChild(h);
  // couvertes d'abord (poids décroissant), puis angles morts -> les cellules vertes remontent.
  // Couvertes en tête, puis les techniques dont la règle attend sa source, puis les vrais angles morts :
  // l'ordre suit ce que l'exploitant peut FAIRE — regarder, brancher, écrire.
  const rang = x => (x && x.covered ? 2 : enAttenteDeSource(x) ? 1 : 0);
  techs.sort((a, b) => (rang(b) - rang(a)) || (techWeight(b) - techWeight(a)));
  techs.forEach(t => col.appendChild(techniqueCell(t, max, comptesDAlertesNonEtablis)));
  return col;
}

// Légende (échelle de couverture) + synthèse (couverture globale, angles morts).
function renderLegend(tactics) {
  const leg = $('#attack-legend'); if (!leg) return;
  leg.replaceChildren();
  leg.className = 'attack-legend';
  let tech = 0, cov = 0, att = 0;
  tactics.forEach(tac => { (tac.techniques || []).forEach(t => { tech++; if (t && t.covered) cov++; else if (enAttenteDeSource(t)) att++; }); });
  const mk = (bg, label, cls) => {
    const s = document.createElement('span');
    const sw = document.createElement('span'); sw.className = 'swatch' + (cls ? ' ' + cls : ''); if (bg) sw.style.background = bg;
    s.append(sw, document.createTextNode(label)); return s;
  };
  // LES PASTILLES NE RECOPIENT PLUS AUCUNE COULEUR, ET C'EST UNE CORRECTION EN PASSANT. Les deux teintes
  // de couverture sont DÉRIVÉES de l'échelle elle-même (`coveredBg`, aux deux bouts de son domaine) au
  // lieu d'être deux `color-mix` écrits à la main qui vieillissaient dès qu'on touchait aux bornes ; et
  // les deux autres empruntent la classe DE LA CELLULE, dont la feuille donne le fond aux deux à la fois.
  // Mesuré en le faisant : la pastille « angle mort » annonçait 12 % là où la cellule en peint 10.
  leg.append(
    mk(coveredBg(1, 6), 'couverte (peu de règles)'),
    mk(coveredBg(6, 6), 'couverte (dense)'),
    mk(null, 'règle activée, source manquante', 'attente'),
    mk(null, 'angle mort (aucune détection)', 'uncovered'),
  );
  // LA SYNTHÈSE SÉPARE LES DEUX FAÇONS DE N'ÊTRE PAS COUVERT : les techniques dont la règle attend son
  // producteur se ferment SANS écrire une ligne. Les confondre reviendrait à prescrire le mauvais geste
  // sur le compte global, comme la porte le faisait sur une cellule.
  const summary = document.createElement('span');
  summary.textContent = 'Couverture : ' + cov + ' / ' + tech + ' technique(s) · ' + (tech - cov - att) + ' angle(s) mort(s) · ' + att + ' en attente de source';
  leg.appendChild(summary);
  // AFFORDANCE « fermer les angles morts » : raccourci vers l'import Sigma en masse. Admin only (la modale
  // re-garde de toute façon, serveur = vraie garde). N'apparaît que s'il RESTE de VRAIS angles morts —
  // un import ne branche aucun producteur, donc il ne ferme rien de ce qui attend une source.
  if ((tech - cov - att) > 0 && socIsAdmin()) {
    const btn = document.createElement('button');
    btn.type = 'button'; btn.className = 'attack-fill'; btn.textContent = 'Importer un ruleset Sigma →';
    btn.title = 'Combler les angles morts : importer une bibliothèque de détection Sigma';
    btn.onclick = openSigmaImport;
    leg.appendChild(btn);
  }
}

// UNE MATRICE VIDE N'EST PAS UNE MATRICE SANS COUVERTURE — MAIS CETTE SURFACE NE SAIT PAS POURQUOI.
// Mesuré le 2026-08-26 en lisant le démon : `build_attack_matrix` empile UNE entrée par tactique du
// catalogue, sans aucune condition sur les données, et le test LIVRÉ `attack_matrix_empty_rules_all_uncovered`
// l'exige explicitement sur zéro règle et zéro alerte (« chaque tactique canonique est présente et non
// couverte »). Une réponse CALCULÉE porte donc TOUJOURS ses tactiques, et écrire « aucune tactique dans la
// matrice » présentait un non-calcul comme une ABSENCE : l'exploitant lisait « rien n'est couvert » là où le
// démon n'avait rien lu.
//
// CE QUE CE MODULE AFFIRMAIT ET QUI ÉTAIT FAUX, RETIRÉ LE 2026-08-26. Il nommait DEUX causes — « permis de
// requête saturé » et « chien de garde de lecture » — et la lecture des trois sorties de `coverage_attack`
// (daemon/src/handlers/alerts.rs) les RÉFUTE toutes les deux. (a) `acquire_query_permit`
// (daemon/src/query_timing.rs) ne rend PAS d'erreur quand les permis manquent : sur `NoPermits` il ATTEND
// (`acquire_owned().await`). Son seul `Err` est `Closed`, c'est-à-dire le sémaphore FERMÉ — l'arrêt du démon.
// La saturation ne produit donc JAMAIS de matrice vide. (b) `read_with_watchdog` (daemon/src/query_exec.rs)
// ne rend son `default` que si `read_conn_get` échoue ; le chien de garde, lui, interrompt la CONNEXION et la
// closure s'exécute quand même, avale les erreurs SQLite (`if let Ok(...)`, `rows.flatten()`) et appelle
// `build_attack_matrix` avec ce qu'elle a lu. Une lecture interrompue rend donc une matrice PLEINE et
// SOUS-COMPTÉE, jamais un tableau vide. (c) Une troisième sortie n'était pas nommée : le `spawn_blocking`
// tombé (`.await.unwrap_or_else`).
//
// CE QUI EST DÉRIVÉ, ET CE QUI EST AVOUÉ. Dérivé de ce que le démon rend : les trois sorties dégradées portent
// `tactics: []`, une réponse d'une AUTRE forme (pas de liste de tactiques du tout) n'en vient donc pas — les
// deux cas reçoivent deux phrases distinctes, et la seconde n'impute rien au démon.
//
// `P10.7-d` — « LES SÉPARER DEMANDE UN MARQUEUR CÔTÉ DÉMON » A CESSÉ D'ÊTRE VRAI, MESURÉ LE 2026-08-29.
// Ce module écrivait que les trois sorties rendent le même corps et qu'aucune ne se nomme. Le marqueur
// EXISTE depuis `P10.7-c` : la sortie du sémaphore fermé passe par `handlers/portillon.rs` et pose sa cause
// sous `error`, dans un corps 200 — donc `api()` ne jette pas et le champ arrivait ici SANS ÊTRE LU. Les
// deux autres sorties (`read_with_watchdog` sur échec de connexion, tâche de lecture tombée) rendent
// toujours `{tactics:[], totals:{}}` NU : c'est `P10.7-e`, et ce module ne peut pas les séparer. La phrase
// servie dit donc maintenant CE QUE LE DÉMON A DIT quand il l'a dit, et n'avoue son ignorance que là où
// elle est réelle — sur un corps muet, dont il ne peut savoir s'il vient des deux autres sorties ou d'un
// démon antérieur à cet aveu. C'est un RÉTRÉCISSEMENT de ce que la surface affirme.
//
// CE QUI RESTE OUVERT ET QUE CETTE SURFACE NE PEUT PAS VOIR (`P11.6-e`) : la lecture interrompue par le chien
// de garde rend une matrice ENTIÈREMENT DESSINÉE à couverture sous-comptée. C'est le même défaut — un résultat
// incomplet présenté comme complet — sous une forme que le tableau vide ne trahit pas. Seul le démon peut le
// dire ; la console ne peut pas le deviner, et ne le devine pas.
//
// Rend null quand la matrice est SERVIE — que le corps porte une cause ou non : dans le premier cas ce
// n'est pas « rien à dire », c'est `loadAttackMatrix` qui le dit, au-dessus de la matrice (`P11.21-i`).
// Sinon, la phrase de refus qui convient, dans la langue.
//
// `P11.21-i` — IL Y A TROIS ÉTATS SUR CETTE ROUTE AUSSI, ET LE TROISIÈME EST NÉ LE 2026-08-30.
//
// CE QUE CE MODULE AFFIRMAIT ET QUI EST DEVENU FAUX LE JOUR MÊME — corrigé ICI, à la place où la phrase
// se lisait, et non démenti plus bas : il écrivait qu'aucun corps du démon ne portait à la fois une
// cause et des tactiques. Depuis `P10.7-f`, `corps_de_matrice_attack` (`daemon/src/handlers/alerts.rs`)
// AJOUTE une cause à une matrice ENTIÈREMENT DESSINÉE dès que `lire_les_alertes_par_technique` n'est
// pas allé au bout. Les deux arrivent donc ensemble, et c'est le cas NOMINAL de la troncature ici.
//
// ET C'ÉTAIT FAUX UNE SECONDE FOIS, SUR UN VERDICT DE COUVERTURE PURPLE. La cause que le démon sert sur
// cette route (`CAUSE_COMPTES_D_ALERTES_NON_ETABLIS`) déclare EXPLICITEMENT que la couverture ne vient
// pas de cette lecture et reste ÉTABLIE — seuls les comptes d'alertes sont des sous-comptes. La règle
// « la cause l'emporte » jetait pourtant la matrice ENTIÈRE et annonçait qu'aucune technique n'avait
// été lue : l'exploitant concluait à une absence de détection là où la détection est mesurée et connue.
// C'est l'inverse exact du service que cette surface rend, et le sens le plus coûteux de l'erreur.
//
// LES TROIS ÉTATS SONT DÉRIVÉS DU CORPS, JAMAIS DE LA ROUTE. Une cause SANS aucune tactique est un REFUS
// (les trois sorties dégradées rendent `tactics: []`, et rien n'a été construit) ; une cause AVEC des
// tactiques est une matrice INCOMPLÈTE (elle est dessinée, et ses comptes d'alertes sont trop BAS) ; pas
// de cause est une lecture entière. Rien ici n'énumère les sorties qui savent tronquer.
//
// LE SENS DE L'ERREUR NE S'INVERSE PAS : le troisième état MONTRE la matrice, il ne la donne pas pour
// juste. L'aveu est rendu AVANT elle, et ce qu'un sous-compte interdit de conclure est dit par la cause
// du démon elle-même, collée telle quelle — la redire ici en ferait un second porteur qui vieillirait
// sans le dire (c'est exactement le défaut que la phrase ci-dessus a coûté).
//
// UN SEUL LECTEUR DU CHAMP SERVI, À UN CRAN, ET C'EST UNE MESURE DU 2026-08-30 : la jambe B de
// `check_a_refusal_is_not_rendered_as_an_absence.py` dérive ses lecteurs des fonctions du MÊME module
// dont le corps PROPRE porte `.error`, et ne suit AUCUNE indirection. Interposer une fonction de plus
// entre l'appel et le champ AVEUGLERAIT la garde — un remaniement qui ne casse rien, ne fait rougir
// personne à l'exécution, et RÉTRÉCIT le canal de détection. `loadAttackMatrix` appelle donc CETTE
// fonction-ci, directement, avec le corps qu'`api()` lui a rendu. La factorisation vers le point commun
// est INTERDITE par la même forme, et c'est mesuré, pas supposé : chaque vue porte sa propre copie.
function etatDeLaMatriceServie(d) {
  const cause = (d && d.error != null) ? String(d.error).trim() : '';
  const tactiques = (d && Array.isArray(d.tactics)) ? d.tactics : null;
  const servies = (tactiques && tactiques.length) ? tactiques.length : 0;
  return { cause, tactiques, servies, refus: !!cause && servies === 0, incomplet: !!cause && servies > 0 };
}

// LA PHRASE DE LA MATRICE INCOMPLÈTE. Elle n'est PAS celle du refus, et la différence n'est pas de ton :
// « aucune technique n'a été lue » serait FAUX ici, et cette surface rendrait une absence là où elle tient
// une matrice. Elle n'ajoute que ce que le démon ne peut pas savoir — QUELLE vue a été demandée, et que
// ce qui suit à l'écran est cette lecture-là. Bilingue par construction.
function motDeLaMatriceIncomplete(cause) {
  return LANG === 'en'
    ? 'ATT&CK coverage PARTIALLY READ — the daemon served the matrix AND names a cause: "' + cause
      + '" What is displayed below is that partial read, and nothing more.'
    : "couverture ATT&CK PARTIELLEMENT LUE — le démon a servi la matrice ET en nomme la cause : « " + cause
      + " » Ce qui est affiché ci-dessous est cette lecture partielle, et rien de plus.";
}

function refusDeMatrice(d) {
  // `P10.7-d` — LA CAUSE SERVIE PASSE AVANT LA FORME, ET ELLE EST RENDUE TELLE QUELLE. Depuis
  // `P10.7-c` le démon écrit sa cause sous `error` DANS UN CORPS 200 : `api()` ne jette pas, et une
  // surface qui ne lit que la forme repeint l'aveu en déduction. Le test est SÉPARÉ de celui du vide —
  // c'est la propriété que tient `check_a_refusal_is_not_rendered_as_an_absence.py`.
  const etat = etatDeLaMatriceServie(d);
  // `P11.21-i` — UNE MATRICE SERVIE AVEC UNE CAUSE N'EST PAS UN REFUS. Elle est rendue, et l'aveu
  // l'accompagne (`loadAttackMatrix`) : prononcer le refus ici jetterait la matrice.
  if (etat.incomplet) return null;
  const cause = etat.cause;
  if (cause) {
    return LANG === 'en'
      ? 'ATT&CK coverage NOT COMPUTED: the daemon DECLINED the read and NAMES the cause — "' + cause
        + '" No technique was read, so this is NOT an absence of coverage and nothing here is declared uncovered.'
      : 'couverture ATT&CK NON CALCULÉE : le démon a REFUSÉ la lecture et en NOMME la cause — « ' + cause
        + ' » Aucune technique n\'a été lue : ce n\'est PAS une absence de couverture, et rien ici n\'est déclaré non couvert.';
  }
  const tactics = etat.tactiques;
  if (tactics && etat.servies) return null;
  if (tactics) {
    return LANG === 'en'
      ? "ATT&CK coverage NOT COMPUTED: the response carries no tactic, which a computed matrix never does — it carries one per catalogue tactic even when no rule covers anything. The daemon therefore declined or failed the read, through one of its three degraded exits: query semaphore closed (shutdown under way), read database unreachable, or the read task died. WHICH of the three, this surface cannot say: the daemon named NO cause in this body. One of the three — the closed semaphore — now names itself when it plays; a silent body therefore comes from the two others, or from a daemon older than that admission, and this surface does not choose between them. This is NOT an absence of coverage; try again."
      : "couverture ATT&CK NON CALCULÉE : la réponse ne porte aucune tactique, ce qu'une matrice calculée ne fait jamais — elle en porte une par tactique du catalogue, même quand aucune règle ne couvre rien. Le démon a donc refusé ou manqué la lecture, par l'une de ses trois sorties dégradées : sémaphore de requête fermé (arrêt en cours), base de lecture injoignable, ou tâche de lecture tombée. LAQUELLE des trois, cette surface ne peut pas le dire : le démon n'a nommé AUCUNE cause dans ce corps. L'une des trois — le sémaphore fermé — se nomme désormais elle-même quand elle joue ; un corps muet vient donc des deux autres, ou d'un démon antérieur à cet aveu, et cette surface ne tranche pas entre les deux. Ce n'est PAS une absence de couverture ; réessayer.";
  }
  return LANG === 'en'
    ? "ATT&CK coverage UNREADABLE: the response does not even carry a tactic list, which this route always serves — including when it declines. This surface therefore cannot say whether the daemon refused the read or the response was altered on the way, and it does not guess. This is NOT an absence of coverage; try again."
    : "couverture ATT&CK ILLISIBLE : la réponse ne porte même pas de liste de tactiques, ce que cette route sert toujours — y compris quand elle refuse. Cette surface ne peut donc pas dire si le démon a refusé la lecture ou si la réponse a été altérée en route, et elle ne le devine pas. Ce n'est PAS une absence de couverture ; réessayer.";
}

async function loadAttackMatrix() {
  const host = $('#attack-body'); if (!host) return;
  const leg = $('#attack-legend'); if (leg) leg.replaceChildren();
  host.replaceChildren(muted('chargement…'));
  let d;
  try { d = await api('/coverage/attack'); }
  catch (e) {
    // dégrade proprement : 404 (daemon pas encore déployé) -> indisponible ; autre -> message d'erreur.
    const msg = (e && e.message) || String(e);
    host.replaceChildren(muted(/(^|\s)404(\s|$)/.test(msg) ? 'couverture ATT&CK indisponible (endpoint non déployé).' : 'couverture indisponible : ' + msg));
    return;
  }
  // `P11.21-i` — L'ÉTAT DE LA LECTURE EST LU ICI, À UN CRAN DE L'APPEL, ET SUR LE CORPS SERVI.
  const etat = etatDeLaMatriceServie(d);
  const tactics = etat.tactiques || [];
  const refus = refusDeMatrice(d);
  if (refus) { host.replaceChildren(muted(refus)); return; }
  // poids max sur TOUTES les techniques -> échelle de couleur commune (comparaison inter-tactiques honnête).
  let max = 0;
  tactics.forEach(tac => (tac.techniques || []).forEach(t => { const w = techWeight(t); if (w > max) max = w; }));
  renderLegend(tactics);
  const matrix = document.createElement('div'); matrix.className = 'attack-matrix';
  // `P11.21-j` — L'ÉTAT LU PLUS HAUT DESCEND JUSQU'À LA CELLULE. Le bandeau ne suffit pas : un lecteur qui
  // survole une case sans l'avoir lu prendrait un sous-compte pour un compte.
  tactics.forEach(tac => matrix.appendChild(tacticColumn(tac, max, etat.incomplet)));
  // `P11.21-i` — L'AVEU EST RENDU AVANT LA MATRICE, ET C'EST LA SEULE POSITION HONNÊTE : un démenti posé
  // SOUS le tableau serait rencontré APRÈS lui par un lecteur qui va de haut en bas, c'est-à-dire après
  // qu'il a compté des alertes qui sont des sous-comptes. Sur une lecture entière, ce tableau est vide et
  // le rendu est byte-identique à celui d'avant cette clé.
  const noeuds = [];
  if (etat.incomplet) {
    const aveu = document.createElement('div');
    aveu.className = 'bad';
    aveu.textContent = motDeLaMatriceIncomplete(etat.cause);
    noeuds.push(aveu);
  }
  noeuds.push(matrix);
  host.replaceChildren(...noeuds);
}

export { loadAttackMatrix, techniqueCell, techniqueDisplayName, porteDeLaTechnique, poserLesPortesDeTechnique, refusDeMatrice, etatDeLaMatriceServie, motDeLaMatriceIncomplete, motDuSousCompteDAlertes, NOM_INCONNU };
