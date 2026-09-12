// plage_de_dates.js — le CHOIX DE DATES de la console, sa fenêtre temporelle et son analyse de texte.
// Déplacement PUR depuis `core.js` (`P7.18-a`, modularité) : zéro ligne de logique réécrite. Le module
// central `core.js` était réclamé par neuf lots ouverts qui devaient donc se suivre en file indienne ;
// ce bloc n'a AUCUN retour de dépendance vers le reste de `core.js` (le seul symbole partagé qu'il lit
// est `LANG`, importé ci-dessous), il en sort donc RÉELLEMENT et cesse d'élargir la surface partagée.
// jourEnSecondes/instantEnSecondes/lireUnePlage lisent un texte de date ; poserLaPlageSurLaCible,
// poserLeChoixDeDates et ouvrirLaModaleDePlage posent le contrôle et la modale. Consommé par
// `audit.js`, `dataaccess.js` et `app.js` ; le harnais ESM le lie comme tout module servi sous web/.
import { LANG } from './core.js';

// Un jour du calendrier, tel qu'un champ `type=date` le rend (« AAAA-MM-JJ »), en secondes epoch à
// l'heure LOCALE de l'analyste : il choisit un jour de SON calendrier, pas un instant UTC.
// `finDeJournee` -> la DERNIÈRE seconde du jour choisi (la fin d'un jour INCLUT ce jour).
// `null` = illisible. Un jour inexistant (2026-02-31) est REPORTÉ par `Date` sur le mois suivant : on
// le refuse au lieu de laisser cette correction silencieuse passer pour un choix.
function jourEnSecondes(texte, finDeJournee) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(texte == null ? '' : texte).trim());
  if (!m) return null;
  const a = Number(m[1]), mo = Number(m[2]), j = Number(m[3]);
  const d = new Date(a, mo - 1, j, 0, 0, 0, 0);
  if (d.getFullYear() !== a || d.getMonth() !== mo - 1 || d.getDate() !== j) return null;
  if (!finDeJournee) return Math.floor(d.getTime() / 1000);
  d.setDate(d.getDate() + 1);
  return Math.floor(d.getTime() / 1000) - 1;
}

// Un INSTANT, tel qu'un champ `type=datetime-local` le rend (« AAAA-MM-JJThh:mm »), en secondes epoch
// à l'heure LOCALE. Même contrat que `jourEnSecondes` — `null` = illisible — pour que le lecteur
// n'ait qu'une seule forme de réponse à traiter, quel que soit le grain. Le report silencieux d'une
// date inexistante est refusé ici aussi, et pour la même raison.
function instantEnSecondes(texte) {
  const m = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?$/.exec(String(texte == null ? '' : texte).trim());
  if (!m) return null;
  const a = Number(m[1]), mo = Number(m[2]), j = Number(m[3]), h = Number(m[4]), mi = Number(m[5]);
  const d = new Date(a, mo - 1, j, h, mi, Number(m[6] || 0), 0);
  if (d.getFullYear() !== a || d.getMonth() !== mo - 1 || d.getDate() !== j || d.getHours() !== h || d.getMinutes() !== mi) return null;
  return Math.floor(d.getTime() / 1000);
}

// LE GRAIN D'UNE CIBLE — ce que l'état où la plage se pose sait TENIR, et rien d'autre. Tout ce qui
// diffère entre un choix de JOURS et un choix d'INSTANTS est ici, dérivé de cette seule question :
// le type du champ, la lecture des deux bornes, la forme attendue nommée dans un refus, et les mots
// des deux champs de la barre. Le grain `minute` n'a aujourd'hui aucun consommateur EN BARRE (sa
// vue l'offre en modale) ; ses mots sont écrits pour qu'une barre posée demain sur une cible
// d'instants ne rende pas un libellé vide.
const GRAINS = {
  jour: {
    typeDeChamp: 'date',
    lireDebut: t => jourEnSecondes(t, false),
    lireFin: t => jourEnSecondes(t, true),
    motDebut: LANG === 'en' ? 'From (day)' : 'Du (jour)',
    motFin: LANG === 'en' ? 'To (day)' : 'Au (jour)',
    motAttendu: LANG === 'en' ? '. A calendar day is expected, written YYYY-MM-DD. Nothing was sent.' : ". Un jour du calendrier est attendu, écrit AAAA-MM-JJ. Rien n'a été envoyé.",
  },
  minute: {
    typeDeChamp: 'datetime-local',
    lireDebut: instantEnSecondes,
    lireFin: instantEnSecondes,
    motDebut: LANG === 'en' ? 'From (instant)' : "Du (instant)",
    motFin: LANG === 'en' ? 'To (instant)' : "Au (instant)",
    motAttendu: LANG === 'en' ? '. An instant is expected, written YYYY-MM-DD hh:mm. Nothing was sent.' : ". Un instant est attendu, écrit AAAA-MM-JJ hh:mm. Rien n'a été envoyé.",
  },
};

// LE SEUL LECTEUR d'une plage choisie — fonction PURE (deux textes + un instant + un grain -> une
// plage OU un refus), ce qui la rend éprouvable sans document ni réseau. Elle ne CORRIGE jamais :
// chaque saisie qu'elle ne sait pas lire produit un REFUS qui dit POURQUOI, et aucune fenêtre ne
// part. Rendre une plage « la plus proche » d'une saisie fautive serait répondre à une question que
// personne n'a posée.
function lireUnePlage(texteDebut, texteFin, maintenant, grain) {
  const g = GRAINS[grain] || GRAINS.jour;
  const td = String(texteDebut == null ? '' : texteDebut).trim();
  const tf = String(texteFin == null ? '' : texteFin).trim();
  if (!td || !tf) {
    return { refus: (LANG === 'en' ? 'A range needs TWO dates — a start and an end. Missing: ' : 'Une plage demande DEUX dates — un début et une fin. Manque : ')
      + (!td ? (LANG === 'en' ? 'the start' : 'le début') : '') + (!td && !tf ? (LANG === 'en' ? ' and ' : ' et ') : '')
      + (!tf ? (LANG === 'en' ? 'the end' : 'la fin') : '') + '.' };
  }
  const debut = g.lireDebut(td), fin = g.lireFin(tf);
  if (debut == null || fin == null) {
    return { refus: (LANG === 'en' ? 'Unreadable date: ' : 'Date illisible : ')
      + (debut == null ? td : tf) + g.motAttendu };
  }
  if (debut > fin) {
    return { refus: (LANG === 'en' ? 'Reversed range: the start (' : 'Plage inversée : le début (') + td
      + (LANG === 'en' ? ') is AFTER the end (' : ') est APRÈS la fin (') + tf
      + (LANG === 'en' ? '). The two dates are kept as typed and nothing was sent — swapping them here would answer a question nobody asked.' : "). Les deux dates restent telles qu'elles ont été saisies et rien n'a été envoyé — les échanger ici répondrait à une question que personne n'a posée.") };
  }
  // DURÉE NULLE — atteignable au seul grain des instants : au grain du jour, la fin est la dernière
  // seconde de son jour, donc deux jours égaux font une fenêtre d'un jour entier. Une fenêtre sans
  // durée ne peut être que vide, et un vide se lit comme une absence : c'est la même raison que
  // celle du début dans le futur, et le refus le dit de la même façon.
  if (debut === fin) {
    return { refus: (LANG === 'en' ? 'Range with no duration: the start and the end are the SAME instant (' : 'Plage sans durée : le début et la fin sont le MÊME instant (') + td
      + (LANG === 'en' ? '). Such a window can only be empty — and an empty window reads as an absence. Nothing was sent.' : "). Une telle fenêtre ne peut être que vide — et une fenêtre vide se lit comme une absence. Rien n'a été envoyé.") };
  }
  if (debut > maintenant) {
    return { refus: (LANG === 'en' ? 'Start date in the future: ' : 'Date de début dans le futur : ') + td
      + (LANG === 'en' ? '. Nothing has been recorded after now, so this range can only be empty — and an empty window reads as an absence. Nothing was sent.' : ". Rien n'est enregistré après maintenant, donc cette plage ne peut être que vide — et une fenêtre vide se lit comme une absence. Rien n'a été envoyé.") };
  }
  return { debut, fin, texteDebut: td, texteFin: tf };
}

// La borne HAUTE choisie couvre-t-elle l'instant présent ? C'est la SEULE question qui décide si une
// plage est exprimable par une route qui ne borne qu'en bas. Une fin posée au jour courant la
// couvre : au grain du jour, la fin est la DERNIÈRE seconde du jour choisi.
function borneHauteCouvreMaintenant(plage, maintenant) { return plage.fin >= maintenant; }

// LES CONTRÔLES POSÉS, par clé de vue — une vue repeinte REMPLACE le sien (aucune accumulation). Ils
// servent à REFLÉTER la plage de LEUR cible : un changement fait dans une autre vue posée sur la
// MÊME cible ne doit pas laisser des dates affichées que la fenêtre envoyée n'a plus.
const controlesDePlage = new Map();

// LE SEUL ÉCRIVAIN de la plage d'une cible. Écrire ailleurs laisserait un contrôle afficher autre
// chose que ce qui part au démon. Les contrôles posés sur CETTE cible se remettent au reflet ; ceux
// d'une autre cible ne bougent pas — deux cibles sont deux fenêtres, pas une.
function poserLaPlageSurLaCible(cible, plage) {
  cible.poser(plage);
  const p = cible.lire();
  controlesDePlage.forEach(c => {
    if (c.cible !== cible) return;
    c.debut.value = p ? p.texteDebut : '';
    c.fin.value = p ? p.texteFin : '';
    // Le reflet porte sur TOUT ce que le contrôle montre, le bouton de retrait compris. L'oublier ici
    // rendrait le remède complice du défaut qu'il corrige : une vue voisine peut retirer la plage,
    // et le bouton resterait alors offert sur un contrôle qui n'a plus rien à retirer.
    c.refleterLeRetrait();
  });
}

// LE CONTRÔLE EN BARRE : deux champs, un bouton qui APPLIQUE, un bouton qui RETIRE, et UNE ligne qui
// porte le refus. Rien ne part tant qu'une saisie est refusée, et la plage précédente reste intacte
// — un refus ne modifie pas la fenêtre, il explique pourquoi elle n'a pas bougé.
// `cle` : la vue qui pose (une seule inscription par vue). `cible` : où la plage se pose (a).
// `porte.borneHaute` : ce que la route de l'appelant sait porter (b) ; `porte.refus(plage)` : la
// phrase, propre à la vue appelante, qui dit pourquoi SON chemin ne porte pas de borne haute —
// écrite là où elle est vraie, pas ici. `surChangement` n'est rappelé QUE lorsque la plage a
// effectivement changé.
function poserLeChoixDeDates(cle, cible, porte, surChangement) {
  const g = GRAINS[cible.grain] || GRAINS.jour;
  const barre = document.createElement('div');
  barre.className = 'rmabs';
  barre.setAttribute('role', 'group');
  barre.setAttribute('aria-label', LANG === 'en' ? 'Exact dates (start and end)' : 'Dates exactes (début et fin)');
  const champ = texte => {
    const l = document.createElement('label');
    const i = document.createElement('input');
    i.type = g.typeDeChamp;
    l.append(texte, i);
    barre.appendChild(l);
    return i;
  };
  const debut = champ(g.motDebut);
  const fin = champ(g.motFin);
  const appliquer = document.createElement('button');
  appliquer.type = 'button';
  appliquer.className = 'btn btn-sm';
  appliquer.textContent = LANG === 'en' ? 'Apply these dates' : 'Appliquer ces dates';
  const retirer = document.createElement('button');
  retirer.type = 'button';
  retirer.className = 'linklike';
  // `P11.20-f` — CE BOUTON NOMME CE QU'IL FAIT, À CE QUE L'EXPLOITANT A SOUS LES YEUX. Il s'appelait
  // « Revenir au raccourci » : mesuré le 2026-08-29, le mot « raccourci » ne nomme RIEN sur les deux
  // écrans qui posent cette barre (0 occurrence affichée dans `web/dataaccess.js`, 0 dans
  // `web/audit.js` hors commentaire), pendant que la console le SERT déjà pour autre chose à quatre
  // endroits — la section « Raccourcis » du guide (`web/help.js`), les « Raccourcis clavier »
  // (`web/keys.js`) et la barre d'en-tête décrite comme un raccourci (`web/help_registry.js`) — avec
  // une entrée de lexique qui le traduit en « Shortcuts », c'est-à-dire en raccourcis CLAVIER. Le mot
  // renvoyait donc l'exploitant vers un objet qui n'existe pas ici. Le nouveau libellé ne désigne que
  // les deux champs de CETTE barre, qui sont à côté de lui ; ce vers quoi le retrait ramène est dit
  // par le motif ci-dessous, où il peut l'être en toutes lettres.
  retirer.textContent = LANG === 'en' ? 'Clear these dates' : 'Effacer ces dates';
  // La ligne de refus occupe toute la largeur de la barre : une phrase qui explique un refus ne se lit
  // pas coincée entre deux champs. `hidden` tant qu'il n'y a rien à dire — jamais un vide qui se
  // confondrait avec un espace réservé.
  const refus = document.createElement('div');
  refus.className = 'bad';
  refus.setAttribute('role', 'alert');
  refus.style.cssText = 'flex-basis:100%;margin:4px 0 0';
  refus.hidden = true;
  // `P11.20-f` — CE QU'IL Y A À RETIRER EST UNE QUESTION POSÉE À L'ÉTAT, PAS UNE LISTE TENUE À JOUR.
  // MESURÉ le 2026-08-29 : exercé à l'ARRIVÉE — aucune plage posée, deux champs vides, aucun refus —
  // ce bouton ne changeait RIEN (0 re-rendu, 0 écriture, pas un caractère déplacé), tout en restant
  // offert et cliquable ; il n'agissait qu'une fois une plage posée. Il était donc inerte EXACTEMENT
  // là où l'exploitant le rencontre en premier, ce qui lui apprend que l'interface répond à côté.
  // Le remède n'est pas de lui inventer un effet à l'arrivée — il n'y en a aucun de juste — mais de
  // DÉRIVER sa présence de ce qu'il aurait à retirer : il paraît quand il a quelque chose, il n'est
  // pas là quand il n'a rien, et il DIT dans les deux cas ce qu'il fait. Rien ne se cache pour autant :
  // ce que le retrait rendrait — la fenêtre du sélecteur — est déjà à l'écran et n'a pas bougé.
  // La garde est dérivée et non énumérée : les trois termes sont les trois seules choses que ce
  // contrôle porte, et un quatrième qui apparaîtrait sans passer par là ne serait pas retirable non
  // plus. `refus.hidden` en fait partie : une phrase de refus affichée EST quelque chose à retirer,
  // même quand rien n'est saisi ni posé.
  const rienARetirer = () => !cible.lire() && !debut.value && !fin.value && refus.hidden;
  // IL SE RETIRE AU LIEU DE SE GRISER, ET LA FEUILLE DE STYLE EN DÉCIDE — MESURÉ, PAS SUPPOSÉ. Le
  // réflexe serait de le rendre inerte avec son motif, ce que fait le reste de la console. Il ne tient
  // PAS ici : mesuré le 2026-08-29, `web/style.css` porte une règle `:disabled` pour `.btn`, `.picon`,
  // `.evpager button`, `.alertbar button` et le bouton de connexion, et AUCUNE pour `.linklike`, qui
  // est la classe de ce bouton-ci (l. 954 : `color:var(--acc)`, `text-decoration:underline`,
  // `cursor:pointer`, tous inconditionnels). Un `.linklike` grisé garderait donc la couleur d'accent,
  // le soulignement ET le curseur de main : il paraîtrait cliquable, avalerait le clic sans un mot, et
  // ce serait le MÊME mensonge qu'on retire, en plus difficile à voir. La même feuille écrit d'ailleurs
  // (l. 915-918) qu'elle évite `disabled` là où l'infobulle doit rester lisible. `hidden`, lui, ne
  // demande rien de neuf : cette même feuille le TIENT DÉJÀ pour toute la console (l. 163,
  // `[hidden]{display:none!important}`), aucune règle ne le contredit sur `.rmabs` ni sur ses boutons
  // (mesuré le 2026-08-29), et le constat lui-même range l'ABSENT au-dessus du visible-et-inerte.
  // Le jour où `.linklike:disabled` existera, ce choix se rediscute.
  // `disabled` est posé AVEC, pour qu'aucun chemin (clic programmé, règle qui le rendrait visible)
  // ne rallume un geste que rien n'attend ; les deux sortent du MÊME prédicat, jamais de deux avis.
  // Le motif est écrit dans les DEUX cas, pas seulement dans l'inerte : un bouton qui n'explique que
  // son refus laisse deviner ce qu'il fait quand il marche. Ce à quoi le retrait rend la main est nommé
  // ici en toutes lettres — la « fenêtre » du sélecteur — parce que c'est le mot que les deux vues
  // affichent réellement à côté (`Fenêtre : …` / `Window: …`, mesuré le 2026-08-29).
  const refleterLeRetrait = () => {
    const rien = rienARetirer();
    retirer.hidden = rien;
    retirer.disabled = rien;
    retirer.title = rien
      ? (LANG === 'en'
        ? 'Nothing to clear: no date is typed and no range is set — the window is already the one from the selector.'
        : "Rien à effacer : aucune date n'est saisie et aucune plage n'est posée — la fenêtre est déjà celle du sélecteur.")
      : (LANG === 'en'
        ? 'Clears both dates and drops the range: the window goes back to the one from the selector.'
        : 'Efface les deux dates et retire la plage : la fenêtre redevient celle du sélecteur.');
  };
  const direLeRefus = texte => { refus.textContent = texte; refus.hidden = !texte; refleterLeRetrait(); };
  // Retoucher une date EFFACE le refus : il porte sur ce qui était saisi, pas sur ce qui l'est. Et le
  // MÊME geste remet le retrait à son reflet : sans quoi le bouton resterait inerte devant une date
  // qui vient d'être saisie. `change` accompagne `input` parce qu'un champ de date se remplit aussi
  // par le calendrier du navigateur et par le remplissage automatique.
  [debut, fin].forEach(champ => ['input', 'change'].forEach(nom => champ.addEventListener(nom, () => direLeRefus(''))));
  appliquer.addEventListener('click', () => {
    const maintenant = Math.floor(Date.now() / 1000);
    const lue = lireUnePlage(debut.value, fin.value, maintenant, cible.grain);
    if (lue.refus) { direLeRefus(lue.refus); return; }
    if (!porte.borneHaute && !borneHauteCouvreMaintenant(lue, maintenant)) { direLeRefus(porte.refus(lue)); return; }
    direLeRefus('');
    poserLaPlageSurLaCible(cible, lue);
    surChangement();
  });
  retirer.addEventListener('click', () => {
    debut.value = ''; fin.value = ''; direLeRefus('');
    if (cible.lire()) { poserLaPlageSurLaCible(cible, null); surChangement(); }
  });
  barre.append(appliquer, retirer, refus);
  const controle = { barre, debut, fin, appliquer, retirer, refus, direLeRefus, refleterLeRetrait, cible };
  controlesDePlage.set(cle, controle);
  const posee = cible.lire();
  debut.value = posee ? posee.texteDebut : '';
  fin.value = posee ? posee.texteFin : '';
  // À LA POSE, et pas seulement au premier geste : c'est l'état d'ARRIVÉE que l'exploitant voit, donc
  // celui où l'aveu doit déjà être juste. Une barre posée sur une cible qui porte DÉJÀ une plage
  // (l'autre vue l'y a mise) arrive avec son retrait offert, ce que le même appel décide.
  refleterLeRetrait();
  return controle;
}

// LE CONTRÔLE EN MODALE : les paliers de la cible (raccourcis relatifs) ET l'intervalle absolu, dans
// la même fenêtre — les deux répondent à la même question, et choisir l'un retire l'autre. Le
// gabarit est celui qui vivait dans `web/app.js`, inchangé ; ce qui change est ce qu'il APPELLE :
// le lecteur partagé et l'écrivain de la cible, au lieu de son propre couple.
function ouvrirLaModaleDePlage(cible, porte, surChangement) {
  const ov = document.createElement('div'); ov.className = 'modal-ov';
  const box = document.createElement('div'); box.className = 'modal rangemodal';
  const plage = cible.lire();
  const cur = cible.palier ? cible.palier() : 0;
  const toLocal = d => new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  const now = new Date();
  const f0 = plage ? new Date(plage.debut * 1000) : new Date(now.getTime() - 3600000);
  const t0 = plage ? new Date(plage.fin * 1000) : now;
  box.innerHTML = `
    <h3>Plage temporelle</h3>
    <div class="rmsub">Relatif — depuis maintenant (suit l'heure courante)</div>
    <div class="rmgrid">${(cible.paliers || []).map(([s, l]) => `<button type="button" class="rmp${!plage && s === cur ? ' on' : ''}" data-s="${s}">${l}</button>`).join('')}</div>
    <div class="rmsub">Absolu — intervalle précis (figé)</div>
    <div class="rmabs">
      <label>Début<input type="datetime-local" id="rm-from" value="${toLocal(f0)}"></label>
      <label>Fin<input type="datetime-local" id="rm-to" value="${toLocal(t0)}"></label>
      <button type="button" id="rm-abs">Appliquer l'intervalle</button>
    </div>
    <div class="modal-err" hidden></div>
    <div class="modal-act"><button type="button" class="m-cancel">Fermer</button></div>`;
  ov.appendChild(box); document.body.appendChild(ov);
  const close = () => { ov.classList.add('out'); document.removeEventListener('keydown', onKey); setTimeout(() => ov.remove(), 160); };
  const onKey = e => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', onKey);
  ov.onclick = e => { if (e.target === ov) close(); };
  box.querySelector('.m-cancel').onclick = close;
  box.querySelectorAll('.rmp').forEach(b => b.onclick = () => {
    cible.poserLePalier(b.dataset.s);   // relatif -> retire la plage + recharge (le geste est celui de la vue)
    surChangement(); close();
  });
  box.querySelector('#rm-abs').onclick = () => {
    const err = box.querySelector('.modal-err');
    const maintenant = Math.floor(Date.now() / 1000);
    // LE MÊME LECTEUR QUE LA BARRE, ET LES MÊMES REFUS. Ce chemin n'en avait que deux (« Dates
    // invalides. », « Le début doit précéder la fin. ») et laissait passer en silence les trois
    // autres familles — début dans le futur, durée nulle, borne haute que la route ne porte pas.
    const lue = lireUnePlage(box.querySelector('#rm-from').value, box.querySelector('#rm-to').value, maintenant, cible.grain);
    if (lue.refus) { err.textContent = lue.refus; err.hidden = false; return; }
    if (!porte.borneHaute && !borneHauteCouvreMaintenant(lue, maintenant)) { err.textContent = porte.refus(lue); err.hidden = false; return; }
    err.hidden = true;
    poserLaPlageSurLaCible(cible, lue); surChangement(); close();
  };
  return { ov, box, close };
}

export {
  jourEnSecondes, instantEnSecondes, lireUnePlage, borneHauteCouvreMaintenant,
  poserLaPlageSurLaCible, poserLeChoixDeDates, ouvrirLaModaleDePlage
};
