// sources.js — extracted from app.js (DEEP state-container split).
// Sources (inventaire + métadonnées d'affichage) + mutations de métadonnées (editor+, auditées).
import { $, LANG, apiSend, confirmModal, fetchInto, fmtTs, humanAge, ic, modal, pagedList, socRole, toast } from './core.js';

// ============ SOURCES (inventaire + métadonnées d'affichage) ============
// ═════════════════════════════════════════════════════════════════════════════════════════════════
// `P11.18-f` — LE STATUT DE L'INVENTAIRE ET CELUI DE LA FRAÎCHEUR : LA MESURE D'ABORD, LE VERDICT ENSUITE.
//
// LA QUESTION POSÉE. « Le statut porté par l'inventaire fait-il doublon avec la vue de fraîcheur ? »
// Elle ne se tranche ni au goût ni au coup d'œil : elle se tranche en lisant D'OÙ chacun des deux
// affichages dérive.
//
// CE QUE LA LECTURE DONNE. Les deux dérivent de la MÊME grandeur, par la MÊME fonction :
// `daemon/src/handlers/sources.rs` et `daemon/src/handlers/freshness.rs` appellent tous deux
// `statut_de_source(age_s, pipeline_fresh, cadence)` — âge du dernier point d'`event_rollup`, fraîcheur
// du pipeline, cadence DÉCLARÉE — et cette fonction rend quatre mots : muet, en_retard, frais, calme.
// Sur ces quatre mots, la colonne « Statut » de l'inventaire est donc un MIROIR de la fraîcheur, et un
// miroir finit toujours par diverger : c'est la famille de défaut que ce dépôt poursuit.
//
// CE QUI N'EST PAS UN MIROIR, ET POURQUOI LA COLONNE RESTE. L'inventaire rend un CINQUIÈME mot que la
// fraîcheur ne peut pas rendre : `dormant`, posé par le démon quand aucune donnée n'a été observée sur
// la fenêtre de l'inventaire. Une source dans cet état n'a AUCUN flux dans `/api/freshness` — elle n'y
// figure pas du tout. Retirer la colonne ferait donc perdre une information que l'autre vue ne porte
// pas ; c'est ce que la mesure évite, et c'est pourquoi rien n'est retiré ici.
//
// CE QUE LE MIROIR COÛTAIT DÉJÀ, MESURÉ. Le mot `dormant` était rendu tel quel dans la colonne, et la
// légende de cette même vue ne le définissait nulle part : elle définissait « en attente » — un mot que
// le démon ne rend JAMAIS pour une source. Un lecteur voyait donc un état sans définition à côté d'une
// définition sans état. La table ci-dessous est désormais l'UNIQUE vocabulaire d'état de source de la
// console (pastille, couleur, rang de tri, mot court) ; `freshness.js` la LIT au lieu d'en tenir une
// copie, et la légende nomme `dormant` pour ce qu'il est.
// ═════════════════════════════════════════════════════════════════════════════════════════════════
// muet(rouge) > en_retard(orange) > attente(gris) > frais(vert) > calme(bleu) ; `dormant` prend le ton
// calme (la collecte n'est pas en cause) mais garde son mot, parce qu'il dit autre chose.
const ETAT_DE_SOURCE = {
  muet:      { dot: 'muet',    txt: 'bad',   rang: 0, court: 'muet' },
  en_retard: { dot: 'warn',    txt: 'fwarn', rang: 1, court: 'en retard' },
  attente:   { dot: 'attente', txt: 'mut',   rang: 2, court: 'en attente' },
  frais:     { dot: 'frais',   txt: 'ok',    rang: 3, court: 'frais' },
  calme:     { dot: 'calme',   txt: 'calm',  rang: 4, court: 'calme' },
  dormant:   { dot: 'calme',   txt: 'calm',  rang: 4, court: 'dormant' },
};
// Les mots que le démon a rendus sous d'autres noms, ramenés au vocabulaire ci-dessus ; un mot INCONNU
// retombe sur `calme`, le repli que les deux surfaces tenaient déjà chacune de leur côté.
const ALIAS_D_ETAT_DE_SOURCE = { inconnu: 'attente', en_attente: 'attente' };
function etatDeSource(status) {
  const e = ALIAS_D_ETAT_DE_SOURCE[status] || status;
  return Object.prototype.hasOwnProperty.call(ETAT_DE_SOURCE, e) ? e : 'calme';
}
const rangDEtatDeSource = (etat) => (ETAT_DE_SOURCE[etat] ? ETAT_DE_SOURCE[etat].rang : 9);
// UN STATUT ABSENT N'EST PAS UN STATUT CALME. Le repli `calme` d'`etatDeSource` vaut pour un MOT que
// la console ne connaît pas, jamais pour l'ABSENCE de mot : une ligne sans verdict prendrait sinon le
// ton d'une collecte saine. Sans statut, pas de vocabulaire — la ligne le dit (tiret) et ferme la liste.
const vocDeSource = (s) => (s && s.status ? ETAT_DE_SOURCE[etatDeSource(s.status)] : null);
const rangDeSource = (s) => { const v = vocDeSource(s); return v ? v.rang : 9; };

// Libellé de la cadence DÉCLARÉE (par une sonde du démon OU par l'exploitant) — jamais la moyenne
// observée, qui est rendue à part. P11.3-c : « non déclarée » n'est PAS un défaut et ne se dit plus comme
// tel — c'est un blanc que personne n'a comblé, et l'événementiel est une RÉPONSE, pas un trou.
function cadenceLabel(s) {
  if (s.cadence_declaree === 'continue') return 'continu' + (s.cadence_interval_s ? ' · ' + humanAge(s.cadence_interval_s) : '');
  if (s.cadence_declaree === 'evenementielle') return 'événementiel — pas de cadence par nature';
  return 'aucune cadence déclarée';
}
// D'OÙ vient la cadence affichée, en clair : la sonde du démon, l'exploitant (avec sa date), ou personne.
function cadenceTitre(s) {
  if (s.cadence_declaree === 'evenementielle') {
    return (s.cadence_par ? 'déclarée événementielle par ' + s.cadence_par + (s.cadence_le ? ' le ' + fmtTs(s.cadence_le) : '') : s.cadence_declarant || '')
      + ' — le débit dépend d\'une activité extérieure : un silence ne prouve rien, cette source ne sera jamais « en retard ».';
  }
  if (s.cadence_declaree === 'continue') {
    return (s.cadence_par ? 'déclarée par ' + s.cadence_par + (s.cadence_le ? ' le ' + fmtTs(s.cadence_le) : '') : s.cadence_declarant || '')
      + ' — au-delà de trois cycles sans donnée, le statut passe « en retard ».'
      + (s.observed_interval_s ? ' Rythme observé sur 24 h : ~1 donnée / ' + humanAge(s.observed_interval_s) + '.' : '');
  }
  return 'Personne ne l\'a déclarée : ni une sonde du démon, ni l\'exploitant. Ce n\'est pas un défaut de collecte — la console ignore simplement le rythme attendu, donc cette source ne peut pas être « en retard ».'
    + (s.observed_interval_s ? ' Rythme observé sur 24 h : ~1 donnée / ' + humanAge(s.observed_interval_s) + '.' : '');
}

// Le marquage / acquittement est un geste ÉDITORIAL : editor et admin (miroir du path-guard RBAC editor+).
const canEditSources = () => { const r = socRole(); return r === 'admin' || r === 'editor'; };

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// `P11.18-y` — CE QUE L'INVENTAIRE ÉCARTE SE DIT, ET CE QU'IL NE PEUT PAS COMPTER SE DIT AUSSI.
//
// LA MESURE, LE 2026-08-26. La route ne rend pas « les sources » : elle rend celles que DEUX bornes
// laissent passer. `daemon/src/handlers/sources.rs` lit `event_rollup` sous
// `WHERE bucket>=now-FENETRE_INVENTAIRE_S` (la fenêtre, déclarée dans `daemon/src/handlers/freshness.rs`)
// ET `HAVING SUM(n)>=3` (le volume) — une source qui a poussé une ou deux lignes sur la fenêtre n'est
// donc PAS dans la charge utile. La fenêtre était nommée à l'écran ; le seuil ne l'était NULLE PART.
// Sur une console de sécurité, « cette source n'existe pas » et « cette source est trop discrète pour
// mon seuil » sont deux faits opposés : une vue qui écarte en silence fait conclure au premier.
//
// CE QUE CETTE VUE NE PEUT PAS DIRE, ET POURQUOI ELLE NE L'INVENTE PAS. Le COMBIEN — le nombre de
// sources écartées — n'est dérivable d'AUCUNE charge utile servie à la console : la route ne rend que
// les lignes RETENUES, jamais leur complément, et aucune autre route ne porte la mesure (mesuré :
// `/api/freshness` applique les deux MÊMES bornes sur la même table — plus, le cas échéant, un filtre
// d'environnement — donc son compte de flux ne peut pas servir de complément). Le publier demande une
// écriture côté démon, hors de ce fichier ; ici, la vue DIT qu'elle ne le sait pas, ce qui vaut mieux
// que de laisser lire un inventaire complet.
//
// POURQUOI LES DEUX BORNES SONT ÉCRITES ICI. La route ne les publie pas : les nommer à l'écran demande
// de les recopier, et une copie finit toujours par diverger. Elle n'est donc pas laissée seule — le
// harnais ESM (témoin 41) DÉRIVE les deux valeurs du démon (la clause `HAVING` de la requête
// d'inventaire, la constante de fenêtre) et exige que le texte rendu les nomme : le jour où le démon
// bouge une borne sans que cette vue suive, le témoin rougit. C'est le même geste que la table
// `SOURCES_LIVREES` du démon, miroir dérivé tenu par une garde, jamais une liste libre.
const FENETRE_INVENTAIRE_JOURS = 7;
const SEUIL_EVENEMENTS_INVENTAIRE = 3;

// LE PÉRIMÈTRE EST RENDU MÊME SUR UNE LISTE VIDE — c'est le seul cas où le lecteur pourrait conclure
// « il n'y a rien » alors que la réponse est « rien n'a franchi les bornes ». Il est donc posé avant le
// tableau, et non dans la légende, qui ne paraît qu'avec des lignes.
function noteDePerimetreDeLInventaire() {
  const el = document.createElement('div'); el.className = 'muted srcperimetre';
  el.style.cssText = 'margin:0 0 9px;font-size:11px';
  el.textContent = LANG === 'en'
    ? 'What this inventory holds, and what it cannot count. The daemon only lets a source in once it has pushed at least '
      + SEUIL_EVENEMENTS_INVENTAIRE + ' event(s) over the last ' + FENETRE_INVENTAIRE_JOURS + ' days; below that, the source EXISTS and pushes, but is not in this list — unless someone has already put a declaration or a piece of metadata on it, in which case it does appear, with no retained data at all (« dormant »). HOW MANY sources are set aside this way: the route only returns the rows it kept, never their count — so this view cannot say, and does not make it up. A source missing from here is looked up in the events themselves by its name (source=…): finding it there proves it pushes.'
    : 'Ce que cet inventaire tient, et ce qu\'il ne peut pas compter. Le démon n\'y fait entrer une source qu\'à partir d\'au moins '
      + SEUIL_EVENEMENTS_INVENTAIRE + ' événement(s) poussé(s) sur les ' + FENETRE_INVENTAIRE_JOURS + ' derniers jours ; en dessous, la source EXISTE et pousse, mais ne figure pas dans cette liste — sauf si quelqu\'un a déjà posé une déclaration ou une métadonnée sur elle, auquel cas elle y entre sans aucune donnée retenue (« dormant »). COMBIEN de sources sont ainsi écartées : la route ne rend que les lignes qu\'elle a gardées, jamais leur compte — cette vue ne peut donc pas le dire, et ne l\'invente pas. Une source absente d\'ici se cherche dans les événements eux-mêmes par son nom (source=…) : l\'y trouver prouve qu\'elle pousse.';
  return el;
}

// CE QUE « dormant » DIT VRAIMENT, à côté du mot. MESURÉ dans `sources.rs` : une source n'entre avec
// `last_seen` nul QUE par la porte des marquages (`obs.entry(src).or_insert((0, 0))`), qui ne sait pas si
// la source n'a rien poussé ou si son volume est resté sous le seuil — les deux arrivent ici sous le même
// mot, avec « dernier vu » à blanc. La légende affirmait « aucune donnée n'a été observée » : c'est FAUX
// pour une source qui a poussé une ou deux lignes. Le mot reste (le démon le rend), sa raison est dite.
const raisonDUnDormant = () => (LANG === 'en'
  ? 'No data RETAINED by the inventory over its ' + FENETRE_INVENTAIRE_JOURS + '-day window. Two different facts land on this same word, and it cannot tell them apart: either nothing arrived, or what arrived stays below the volume threshold ('
    + SEUIL_EVENEMENTS_INVENTAIRE + ' event(s)) — in which case « last seen » is blank while the source did push.'
  : 'Aucune donnée RETENUE par l\'inventaire sur sa fenêtre de ' + FENETRE_INVENTAIRE_JOURS + ' jours. Deux faits différents arrivent sous ce même mot, et il ne les distingue pas : soit rien n\'est arrivé, soit ce qui est arrivé reste sous le seuil de volume ('
    + SEUIL_EVENEMENTS_INVENTAIRE + ' événement(s)) — auquel cas « dernier vu » est à blanc alors que la source a bien poussé.');

// RENDU PUR de l'inventaire à partir de la charge utile de /api/sources (exercé par le harnais ESM sur des
// objets fabriqués ; `loadSourcesView` ne fait que l'appeler après le fetch).
function renderSourcesInventory(wrap, d) {
  const sources = (d.sources || []).slice();
  // tri INITIAL : inattendues d'abord (signal), puis par statut, puis nom. Le tri par colonne (clic
  // en-tête) prend ensuite le relais via pagedList (mode client).
  sources.sort((a, c) => (Number(c.unexpected) - Number(a.unexpected))
    || (rangDeSource(a) - rangDeSource(c))
    || String(a.source).localeCompare(String(c.source)));
  wrap.replaceChildren();
  const banner = document.createElement('div');
  banner.className = d.pipeline_fresh ? 'muted' : 'bad';
  banner.style.cssText = 'margin:0 0 9px;font-size:12px';
  banner.textContent = d.pipeline_fresh
    ? 'Inventaire des sources d\'ingestion. Les déclarations et métadonnées ci-dessous (déclarée, cadence attendue, libellé, catégorie, note) ne changent que ce qui est AFFICHÉ — la collecte, les règles et les alertes ne sont jamais modifiées depuis cette console. La configuration des collecteurs hôte est hors périmètre.'
    : 'Ingestion en panne — aucune donnée reçue récemment.';
  wrap.appendChild(banner);
  // `P11.18-y` — LE PÉRIMÈTRE AVANT LA LISTE, ET MÊME QUAND ELLE EST VIDE (voir l'en-tête du module).
  wrap.appendChild(noteDePerimetreDeLInventaire());
  const tblHost = document.createElement('div'); wrap.appendChild(tblHost);
  const editable = canEditSources();
  const nUnexpected = sources.filter(s => s.unexpected).length;
  if (nUnexpected) {
    const hint = document.createElement('div'); hint.className = 'fwarn'; hint.style.cssText = 'margin:0 0 8px;font-size:12px';
    hint.textContent = nUnexpected + ' source(s) que personne n\'a déclarée(s) — ni ce dépôt, ni le démon, ni le produit, ni un connecteur, ni l\'exploitant. '
      + (editable ? 'Une source installée hors de ce dépôt se déclare ici : Actions → « déclarer attendue » (persistant, réversible, audité).'
                  : 'Une source installée hors de ce dépôt se déclare ici ; il faut le rôle éditeur ou administrateur (geste persistant, réversible, audité).');
    wrap.insertBefore(hint, tblHost);
  }
  // colonnes : render -> NŒUD (badges/pastilles/boutons survivent) ; sortVal -> clé de tri par colonne.
  const columns = [
    { key: 'source', label: 'Source', sortable: true, sortVal: s => s.source == null ? '' : s.source, render: s => {
      const f = document.createDocumentFragment();
      const nm = document.createElement('span'); nm.textContent = s.source == null ? '' : s.source; f.appendChild(nm);
      if (s.unexpected) {
        const bad = document.createElement('span'); bad.className = 'badge srcbadge-unexpected'; bad.textContent = 'non déclarée';
        bad.style.cssText = 'margin-left:6px;color:var(--warn);border-color:color-mix(in srgb,var(--warn) 40%,transparent)';
        bad.title = 'Personne n\'a déclaré cette source — un signal à examiner, pas un défaut de collecte. Si elle est voulue (une sonde installée hors de ce dépôt l\'est autant qu\'une autre), un éditeur la déclare depuis Actions.';
        f.appendChild(bad);
      }
      // P11.16-a — LE PRODUCTEUR EST ÉCRIT SOUS LE NOM. Relevé en usage réel le 2026-08-25 : une source
      // figure à l'inventaire et celui-là même qui a installé le produit ne sait ni d'où elle vient ni où
      // on la déclare. LE NOM D'UNE SOURCE NE NOMME PAS SON PRODUCTEUR : les deux diffèrent souvent, et
      // aucune lecture de l'écran ne permettait de les rapprocher.
      //
      // LE RAPPROCHEMENT N'EST PAS ÉCRIT ICI, ET IL NE PEUT PAS L'ÊTRE. Une table nom-de-capteur ->
      // nom-de-source recopiée dans la console serait fausse au premier capteur ajouté, et donnerait
      // l'illusion d'une couverture. Le démon la DÉRIVE déjà (`raison_attendue` nomme le fichier livré, la
      // sonde, le produit ou le connecteur qui émet la source, et une garde tient cette dérivation contre
      // les fichiers livrés) ; elle n'était rendue que sous la colonne « Déclarée », en 10 px, là où un
      // lecteur cherche un oui/non et non une provenance. Elle est désormais SOUS LE NOM, où la question
      // se pose.
      //
      // CE QUI DÉCIDE EST DÉRIVÉ DE DEUX BOOLÉENS PUBLIÉS, jamais d'une liste : `in_collectors` dit que le
      // démon connaît un producteur PAR CONSTRUCTION, et `expected` que ce verdict-là n'a pas été remplacé
      // par un geste humain (un retrait rend le geste à la place du producteur — le nom du producteur
      // n'est alors plus dans la charge utile, et l'inventer serait une devinette). Là où la console ne
      // peut pas nommer, elle le DIT : un blanc se lirait comme une origine évidente.
      const prod = document.createElement('span'); prod.className = 'muted srcprod'; prod.style.cssText = 'display:block;font-size:10px';
      // P11.16-a — LE QUATRIÈME CAS, QUI RENDAIT UN BLANC. Les deux booléens décidaient de trois cas, mais
      // le premier posait `s.raison_attendue || ''` : une charge utile qui déclare le producteur connu par
      // construction SANS en rendre le nom (un démon antérieur au champ, un champ renommé) laissait une
      // ligne VIDE sous le nom de la source — exactement le blanc que le reste de ce bloc refuse, et qui se
      // lit comme une origine évidente. La règle que ce bloc énonce vaut maintenant sur ses quatre chemins.
      if (s.in_collectors && s.expected && !s.raison_attendue) {
        prod.textContent = LANG === 'en' ? 'producer known by construction, but this route did not name it' : 'producteur connu par construction, mais cette route ne l\'a pas nommé';
        prod.title = LANG === 'en' ? 'The daemon says a shipped producer emits this source, yet the payload carries no name for it — an older daemon, or a renamed field. The console does not guess one: it says what it received.' : 'Le démon dit qu\'un producteur livré émet cette source, mais la charge utile n\'en porte aucun nom — démon antérieur au champ, ou champ renommé. La console n\'en devine pas : elle dit ce qu\'elle a reçu.';
      } else if (s.in_collectors && s.expected) {
        prod.textContent = s.raison_attendue;
        prod.title = LANG === 'en' ? 'Where this source comes from: the producer that emits it, derived from what this repository ships, observes, aggregates or configures — never from a hand-written table. A source name and its producer name often differ. A sensor is enabled or removed on the host (its collector and its timer), not from this console.' : 'D\'où vient cette source : le producteur qui l\'émet, dérivé de ce que ce dépôt livre, observe, agrège ou configure — jamais d\'une table écrite à la main. Le nom d\'une source et celui de son producteur diffèrent souvent. Un capteur s\'active ou se retire sur l\'hôte (son collecteur et son minuteur), pas depuis cette console.';
      } else if (s.in_collectors) {
        prod.textContent = LANG === 'en' ? 'producer known by construction, not named here while the declaration is withdrawn' : 'producteur connu par construction, non nommé ici tant que la déclaration est retirée';
        prod.title = LANG === 'en' ? 'A producer of this repository does emit this source, but the inventory renders the withdrawal gesture in place of its name. Restoring the declaration (Actions) brings the producer back.' : 'Un producteur de ce dépôt émet bien cette source, mais l\'inventaire rend le geste de retrait à la place de son nom. Rétablir la déclaration (Actions) fait réapparaître le producteur.';
      } else {
        prod.textContent = LANG === 'en' ? 'no producer named — the console does not know what emits this source' : 'aucun producteur nommé — la console ne sait pas ce qui émet cette source';
        prod.title = LANG === 'en' ? 'Matching a source with its producer is DERIVED from what the shipped producers declare: a probe installed outside this repository does not enter that derivation. Declaring a source expected says it is WANTED, never what EMITS it — so this blank is said rather than left to be guessed.' : 'Le rapprochement entre une source et son producteur est DÉRIVÉ de ce que les producteurs livrés déclarent : une sonde installée hors de ce dépôt n\'y entre pas. Déclarer une source attendue dit qu\'on la VEUT, jamais ce qui l\'ÉMET — ce blanc est donc dit, plutôt que laissé à deviner.';
      }
      f.appendChild(prod);
      return f;
    } },
    { key: 'expected', label: 'Déclarée', sortable: true, sortVal: s => s.expected ? 1 : 0, render: s => {
      const f = document.createDocumentFragment();
      const exp = document.createElement('span'); exp.className = 'badge srcbadge-expected';
      // « attendu » veut dire DÉCLARÉ PAR QUELQU'UN : le badge nomme le déclarant plutôt qu'un oui/non nu.
      exp.textContent = s.expected ? (s.declaree_par || 'oui') : 'personne';
      exp.style.color = s.expected ? 'var(--ok)' : 'var(--warn)';
      exp.title = s.expected
        ? 'Cette source est DÉCLARÉE : quelqu\'un l\'a voulue. Le détail dit qui.'
        : 'Personne ne l\'a déclarée — ni ce dépôt, ni le démon, ni le produit, ni un connecteur, ni un humain de cette installation.';
      f.appendChild(exp);
      // QUI l'a déclarée et QUAND : la provenance PROPRE du geste, jamais le dernier compte qui a touché
      // la ligne (le démon écrit `marquage.updated_by` seulement quand `set_expected` est joué).
      // P11.16-a — CETTE COLONNE NE RÉPÈTE PLUS LE PRODUCTEUR : il est écrit sous le nom (colonne Source),
      // et la même phrase rendue deux fois dans une ligne serait du bruit. Elle ne porte donc que ce qui
      // relève de la DÉCLARATION — le geste humain quand il existe, la déclaration que le producteur ne
      // porte pas, ou l'absence de toute déclaration. Une case vide dit alors : « rien de plus que ce que
      // la colonne Source vient de nommer ».
      const why = document.createElement('span'); why.className = 'muted srcwhy'; why.style.cssText = 'display:block;font-size:10px';
      const mark = s.marquage;
      const producteurSousLeNom = !!(s.in_collectors && s.expected);
      if (mark && mark.updated_by && ((mark.expected && !s.in_collectors) || !mark.expected)) {
        why.textContent = (mark.expected ? 'déclarée par ' : 'déclarée NON attendue par ') + mark.updated_by + (mark.updated ? ' le ' + fmtTs(mark.updated) : '');
      } else if (s.raison_attendue && !producteurSousLeNom) {
        why.textContent = s.raison_attendue;
      } else if (!s.raison_attendue && !s.expected) {
        // P11.16-a — « aucune déclaration » NE SE DIT QUE LÀ OÙ PERSONNE N'A DÉCLARÉ. Sans la seconde
        // condition, une ligne DÉCLARÉE dont la route n'a pas rendu la raison (le quatrième cas traité
        // sous le nom) portait un badge nommant son déclarant À CÔTÉ de « aucune déclaration » : la
        // cellule démentait le badge de la même ligne. Une absence de RAISON n'est pas une absence de
        // DÉCLARATION, et l'inventaire ne peut pas dire les deux à la fois.
        why.textContent = 'aucune déclaration';
      }
      if (why.textContent) f.appendChild(why);
      return f;
    } },
    { key: 'cadence', label: 'Cadence', sortable: true, sortVal: s => cadenceLabel(s), render: s => {
      const f = document.createDocumentFragment();
      const sp = document.createElement('span'); sp.textContent = cadenceLabel(s); sp.title = cadenceTitre(s);
      f.appendChild(sp);
      const qui = document.createElement('span'); qui.className = 'muted srccadwho'; qui.style.cssText = 'display:block;font-size:10px';
      qui.textContent = s.cadence_par ? 'déclarée par ' + s.cadence_par + (s.cadence_le ? ' le ' + fmtTs(s.cadence_le) : '')
        : s.cadence_capteur ? 'déclarée par la sonde « ' + s.cadence_capteur + ' »'
        : 'personne ne l\'a déclarée';
      f.appendChild(qui);
      return f;
    } },
    { key: 'age', label: 'Dernier vu', sortable: true, sortVal: s => s.last_seen || 0, render: s => {
      const sp = document.createElement('span'); sp.textContent = s.last_seen ? 'il y a ' + humanAge(s.age_s) : '—'; if (s.last_seen) sp.title = fmtTs(s.last_seen); return sp;
    } },
    { key: 'n_24h', label: '24 h', sortable: true, align: 'r', sortVal: s => s.n_24h || 0, render: s => s.n_24h != null ? String(s.n_24h) : '0' },
    { key: 'status', label: 'Statut', sortable: true, sortVal: s => rangDeSource(s), render: s => {
      const f = document.createDocumentFragment();
      const voc = vocDeSource(s);
      const dot = document.createElement('span'); dot.className = 'fdot ' + (voc ? voc.dot : 'calme');
      const lbl = document.createElement('b'); lbl.className = voc ? voc.txt : 'calm'; lbl.textContent = voc ? voc.court : '—';
      // `P11.18-y` — SEUL `dormant` porte sa raison, et il la porte parce qu'il RECOUVRE deux faits (voir
      // `raisonDUnDormant`). Les quatre autres mots dérivent d'un âge et d'une cadence, que la ligne montre
      // déjà : leur coller une phrase de plus n'apprendrait rien.
      if (s && s.status && etatDeSource(s.status) === 'dormant') lbl.title = raisonDUnDormant();
      f.append(dot, lbl); return f;
    } },
    { key: 'category', label: 'Catégorie', sortable: true, sortVal: s => s.category || '', render: s => s.category || '—' },
    { key: 'note', label: 'Note', render: s => { const sp = document.createElement('span'); sp.textContent = s.note || ''; if (s.note) sp.title = s.note; return sp; } },
  ];
  if (editable) columns.push({ key: 'actions', label: 'Actions', render: s => {
    const box = document.createElement('span'); box.style.whiteSpace = 'nowrap';
    const edit = document.createElement('button'); edit.type = 'button'; edit.className = 'picon'; edit.innerHTML = ic('pencil');
    edit.title = 'Éditer libellé / catégorie / note'; edit.onclick = e => { e.stopPropagation(); editSourceMeta(s); };
    const tog = document.createElement('button'); tog.type = 'button';
    tog.className = 'picon srctoggle ' + (s.expected ? 'on' : 'off'); tog.style.marginLeft = '6px';
    tog.textContent = s.expected ? 'retirer la déclaration' : 'déclarer attendue';
    tog.title = s.expected ? 'Retirer la déclaration : la source redevient un signal à examiner (persistant, audité)' : 'Déclarer cette source voulue par cette installation (persistant, réversible, audité)';
    tog.onclick = e => { e.stopPropagation(); toggleExpected(s); };
    box.append(edit, tog);
    // LA CADENCE NE SE DÉCLARE QUE LÀ OÙ AUCUNE SONDE N'EN DÉCLARE : ailleurs, la sonde fait foi et le
    // démon REFUSE l'écriture — offrir le geste serait promettre un réglage qui n'aurait aucun effet.
    if (s.cadence_declarable) {
      const cad = document.createElement('button'); cad.type = 'button'; cad.className = 'picon srccadence'; cad.style.marginLeft = '6px';
      cad.textContent = 'déclarer la cadence';
      cad.title = 'Dire le rythme attendu de cette source (affichage seul : aucune alerte n\'en dérive)';
      cad.onclick = e => { e.stopPropagation(); declareCadence(s); };
      box.append(cad);
    }
    const clr = document.createElement('button'); clr.type = 'button'; clr.className = 'picon'; clr.style.marginLeft = '6px'; clr.innerHTML = ic('x');
    clr.title = 'Réinitialiser les déclarations et les métadonnées d\'affichage de cette source'; clr.onclick = e => { e.stopPropagation(); clearSourceMeta(s); };
    box.append(clr); return box;
  } });
  // `P11.18-m` — LA RECHERCHE PORTE SUR TOUT L'INVENTAIRE. `/api/sources` ne pagine pas et ne tronque pas :
  // ce que la vue reçoit est l'inventaire entier, dont la fenêtre de sept jours est déjà nommée dans la
  // légende ci-dessous. Le texte cherché est celui des cellules RENDUES — une source se cherche donc aussi
  // par le PRODUCTEUR écrit sous son nom, par le mot de son statut et par son déclarant.
  // `P11.18-z` — IDENTITÉ DE CETTE LISTE (littérale, stable, propre à elle) : éditer les métadonnées
  // d'une source, déclarer ou retirer « voulue par cette installation », déclarer une cadence ou
  // réinitialiser une source rappellent tous `loadSourcesView()`, qui refabrique l'hôte de la liste.
  pagedList(tblHost, { mode: 'client', pageSize: 50, rows: sources, columns, emptyText: 'aucune source', storeKey: 'soc_sources_inventory', recherche: true });
  if (sources.length) {
    const legend = document.createElement('div'); legend.className = 'muted'; legend.style.cssText = 'margin-top:8px;font-size:11px';
    legend.textContent = 'Statut = santé de collecte (même dérivation que Données → Fraîcheur) : frais (donnée < 15 min) · calme (collecte saine, source peu active) · en retard (cadence DÉCLARÉE continue dépassée — c\'est le « muet » du capteur dans Intégrations) · en attente (déclarée, pas encore de donnée) · muet (plus rien n\'arrive, toutes sources confondues). « Déclarée » veut dire voulue par QUELQU\'UN : ce dépôt (un fichier livré l\'émet), le démon (une sonde l\'observe), le produit (il l\'agrège), un connecteur configuré, ou l\'exploitant — une source installée hors de ce dépôt se déclare ici, et la colonne dit qui l\'a fait et quand. La cadence attendue se déclare de la même façon là où aucune sonde n\'en déclare : « aucune cadence déclarée » est un blanc, pas un défaut, et une source événementielle ou sans cadence n\'est jamais « en retard ».';
    wrap.appendChild(legend);
    // P11.16-a — CE QUE LA COLONNE « Source » DIT MAINTENANT, ET CE QU'ELLE NE PEUT PAS DIRE. Écrit dans
    // son PROPRE nœud, à côté de la légende existante : ajouté au même texte, il aurait rendu cette
    // légende-là intraduisible (le lexique apparie un nœud entier).
    const prov = document.createElement('div'); prov.className = 'muted'; prov.style.cssText = 'margin-top:6px;font-size:11px';
    prov.textContent = LANG === 'en' ? 'Under each source name: the PRODUCER that emits it. A source name does not name its producer — the two often differ — and this match is DERIVED from what the shipped producers declare, never from a hand-written table that would be wrong the day a sensor is added. A source installed outside this repository has no producer the console can name, and the screen says so instead of suggesting an obvious origin. Enabling or removing a sensor happens on the host (its collector and its timer): this console only ever changes what is DISPLAYED.' : 'Sous chaque nom de source : le PRODUCTEUR qui l\'émet. Le nom d\'une source ne nomme pas son producteur — les deux diffèrent souvent — et ce rapprochement est DÉRIVÉ de ce que les producteurs livrés déclarent, jamais d\'une table écrite à la main, qui serait fausse le jour où un capteur s\'ajoute. Une source installée hors de ce dépôt n\'a aucun producteur que la console sache nommer, et l\'écran le dit au lieu de laisser croire à une origine évidente. Activer ou retirer un capteur se fait sur l\'hôte (son collecteur et son minuteur) : cette console ne change jamais que ce qui est AFFICHÉ.';
    wrap.appendChild(prov);
    // `P11.18-f` — CE QUE CE STATUT PORTE DE PLUS QUE LA FRAÎCHEUR, dans son PROPRE nœud (ajouté au
    // texte ci-dessus, il l'aurait rendu intraduisible : le lexique apparie un nœud entier).
    const doublon = document.createElement('div'); doublon.className = 'muted'; doublon.style.cssText = 'margin-top:6px;font-size:11px';
    // `P11.18-y` — LA DÉFINITION DE « dormant » ÉTAIT FAUSSE dans un cas que le démon produit : elle
    // affirmait qu'aucune donnée n'avait été OBSERVÉE, alors que le mot couvre aussi une source qui a
    // poussé sous le seuil de volume (mesuré : `sources.rs`, la porte des marquages insère `(0, 0)` sans
    // regarder ce que la source a poussé). Ce qu'il dit vraiment est dit — ici, et au survol du mot.
    doublon.textContent = LANG === 'en'
      ? 'Four of these words come from the SAME derivation as Data → Source freshness, on the same measure: they say the same thing, seen from the inventory. The fifth belongs to this view alone — « dormant » : a source declared here of which the inventory RETAINED no data over its '
        + FENETRE_INVENTAIRE_JOURS + '-day window, either because nothing arrived or because the volume stays below the threshold named above — the word does not tell the two apart. Such a source has no feed at all in Source freshness (same two bounds), so it does not appear there.'
      : 'Quatre de ces mots viennent de la MÊME dérivation que Données → Fraîcheur des sources, sur la même mesure : ils disent la même chose, vue depuis l\'inventaire. Le cinquième n\'appartient qu\'à cette vue — « dormant » : une source déclarée ici dont l\'inventaire n\'a RETENU aucune donnée sur sa fenêtre de '
        + FENETRE_INVENTAIRE_JOURS + ' jours, soit qu\'il ne soit rien arrivé, soit que le volume reste sous le seuil nommé plus haut — le mot ne distingue pas les deux. Une telle source n\'a aucun flux dans Fraîcheur des sources (mêmes deux bornes), elle n\'y figure donc pas.';
    wrap.appendChild(doublon);
  }
}

async function loadSourcesView() {
  const wrap = $('#sources-body'); if (!wrap) return;
  const d = await fetchInto(wrap, '/sources'); if (!d) return;
  renderSourcesInventory(wrap, d);
}

async function sourcePut(source, action, value) {
  const b = { source, action };
  if (value !== undefined) b.value = value;
  try { await apiSend('/sources/settings', 'PUT', b); }
  catch (e) { toast((e && e.message) || 'échec', 'bad'); return false; }
  return true;
}

async function editSourceMeta(s) {
  const r = await modal({
    title: 'Éditer : ' + s.source, okText: 'Enregistrer', danger: false, fields: [
      { name: 'label', label: 'Libellé', value: s.label || '', placeholder: 'nom lisible (affichage)' },
      { name: 'category', label: 'Catégorie', value: s.category || '', placeholder: 'ex: réseau, auth, système' },
      { name: 'note', label: 'Note', type: 'textarea', value: s.note || '', placeholder: 'note libre (affichage)' },
    ],
  });
  if (!r) return;
  const ops = [];
  if ((r.label || '') !== (s.label || '')) ops.push(['set_label', r.label || '']);
  if ((r.category || '') !== (s.category || '')) ops.push(['set_category', r.category || '']);
  if ((r.note || '') !== (s.note || '')) ops.push(['set_note', r.note || '']);
  if (!ops.length) { toast('aucune modification', 'info'); return; }
  for (const [action, value] of ops) { if (!await sourcePut(s.source, action, value)) return; }
  toast('métadonnées mises à jour', 'ok'); loadSourcesView();
}

async function toggleExpected(s) {
  const target = !s.expected;
  const suppressing = target && s.unexpected;   // déclarer une source que rien ne déclarait = étouffer un signal (audité sév. 3 côté démon)
  const msg = target
    ? `Déclarer « ${s.source} » attendue ?` + (s.unexpected ? ' Le signal « personne ne l\'a déclarée » disparaît, et l\'inventaire dira que vous l\'avez déclarée, avec la date. La collecte et les règles ne sont PAS modifiées (affichage seul). Geste persistant, réversible, audité.' : ' (affichage seul, geste audité)')
    : `Retirer la déclaration de « ${s.source} » ? (elle redevient un signal à examiner ; affichage seul, geste audité)`;
  if (!await confirmModal(msg, { danger: suppressing, okText: target ? 'Déclarer attendue' : 'Retirer la déclaration' })) return;
  if (await sourcePut(s.source, 'set_expected', target)) { toast('mis à jour', 'ok'); loadSourcesView(); }
}

// DÉCLARER LA CADENCE d'une source que ce dépôt n'observe pas. Trois réponses possibles, dont le RETRAIT :
// sans lui, un exploitant pourrait déclarer et jamais se dédire. Le démon refuse le geste là où une sonde
// déclare déjà — la question n'est donc pas posée dans ce cas (le bouton n'est pas rendu).
async function declareCadence(s) {
  const r = await modal({
    title: 'Cadence attendue : ' + s.source, okText: 'Déclarer', danger: false,
    message: 'La cadence attendue sert au STATUT affiché (ici et dans Fraîcheur). Elle ne crée aucune alerte : le dead-man\'s-switch reste celui des sondes du démon.',
    validate: v => (v.nature === 'continue' && !(Number(v.interval_s) > 0)) ? 'Une cadence continue demande un intervalle en secondes.' : null,
    fields: [
      { name: 'nature', label: 'Nature', type: 'select', value: s.cadence_declaree === 'non_declaree' ? 'inconnue' : (s.cadence_declaree || 'inconnue'), options: [
        { value: 'continue', label: 'continue — un point est attendu à intervalle régulier' },
        { value: 'evenementielle', label: 'événementielle — pas de cadence par nature' },
        { value: 'inconnue', label: 'retirer la déclaration — la console ignore le rythme' },
      ] },
      { name: 'interval_s', label: 'Intervalle attendu (secondes, si continue)', value: s.cadence_interval_s ? String(s.cadence_interval_s) : '' },
    ],
  });
  if (!r) return;
  const b = { source: s.source, action: 'set_cadence', value: r.nature };
  if (r.nature === 'continue') b.interval_s = Number(r.interval_s || 0);
  try { await apiSend('/sources/settings', 'PUT', b); }
  catch (e) { toast((e && e.message) || 'échec', 'bad'); return; }
  toast('cadence déclarée', 'ok'); loadSourcesView();
}

async function clearSourceMeta(s) {
  if (!await confirmModal(`Réinitialiser « ${s.source} » (libellé, catégorie, note, déclaration attendue, cadence déclarée) ? La source reprend le verdict que ce dépôt en dérive. La collecte n'est pas touchée.`, { danger: true, okText: 'Réinitialiser' })) return;
  if (await sourcePut(s.source, 'clear')) { toast('réinitialisé', 'ok'); loadSourcesView(); }
}


export { loadSourcesView, renderSourcesInventory, ETAT_DE_SOURCE, etatDeSource, rangDEtatDeSource };
