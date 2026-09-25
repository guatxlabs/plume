// system.js — #51 DAY-2 OPS : console d'opérabilité « Système ».
//  - self-métriques (CPU/RSS, ingest, latence recherche p50/p95, scheduler, DB, alertes)  -> GET /api/system/metrics
//  - santé R/J/V par composant (ingest/détection/rollups/store/forwarder)                  -> GET /api/system/health
//  - (admin) bulletin/MOTD (setting global, bandeau pour TOUS)                             -> /api/bulletin
//  - (admin) bundle de diagnostic NON-SECRET (support hand-off, téléchargé)               -> GET /api/system/diag
// LECTURE viewer+. Additif : aucun bulletin -> aucun bandeau (invariant mode 0).
import { $, LANG, api, apiSend, muted, prefixeDUnEchecRenduTelQuel, toast, fmtTs, downloadText, humanAge, socIsAdmin, puitsDuRefusDUnGeste, effacerLeRefusDUnGeste, peindreLeRefusDUnGeste } from './core.js';
// P11.4-g : la référence documentaire d'un avertissement est une VALEUR qu'on transporte — geste de copie
// partagé (`copie_et_selection.js`, `P11.4-h`).
import { valeurTransportee } from './copie_et_selection.js';

// état V/J/R -> classe pastille .fdot (réutilise le vocabulaire de sources.js : frais/warn/muet/calme) + libellé.
const STATE_DOT = { green: 'frais', yellow: 'warn', red: 'muet', idle: 'calme' };
const STATE_LBL = { green: 'OK', yellow: 'attention', red: 'panne', idle: 'inactif' };

function fmtBytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + ' o';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' Ko';
  if (n < 1073741824) return (n / 1048576).toFixed(1) + ' Mo';
  return (n / 1073741824).toFixed(2) + ' Go';
}

// S32 / S37 — UNE MESURE NON LISIBLE N'EST PAS UN ZÉRO, ET LE PANNEAU NE DOIT PAS LA RENDRE COMME TEL.
// Le serveur OMET le nombre quand sa source n'a pas pu être lue et pose à côté `<clé>_verdict`,
// `<clé>_cause` et `<clé>_detail` (convention d'un seul auteur : `mesure_environnement::Mesure`). Un
// `?? 0` ou un `fmtBytes(undefined)` reconstruirait ici, côté client, exactement le zéro rassurant que
// le serveur vient de retirer. Toute lecture d'une grandeur à verdict passe donc par `lireMesure`, et
// le verdict y est LU, jamais déduit de l'absence du nombre : un verdict autre que `lu` l'emporte sur
// une valeur qui serait tout de même présente, et l'absence des deux est un TROISIÈME état (« non
// publié » : pas encore de tick, serveur qui ne publie pas cette clé) distinct de « non lisible ».
const CAUSE_LBL = {
  aucune: '',
  source_absente: 'source absente',
  source_refusee: 'accès refusé',
  source_illisible: 'source illisible',
  forme_inconnue: 'forme non reconnue',
};
const VERDICT_LU = 'lu';
const VERDICT_ILLISIBLE = 'illisible';

// `P10.20-b` — LA VERSION DE SCHÉMA EST LA SEULE VALEUR QU'UN OPÉRATEUR NE PEUT PAS RECONNAÎTRE COMME
// FAUSSE. Le démon ne sert plus « 1 » sur une lecture ratée : il sert `schema_version: null` et POSE À
// CÔTÉ une clé nommée qui porte la cause (`CLE_VERSION_DE_SCHEMA_NON_ETABLIE`, daemon/src/handlers/
// system.rs), absente du chemin nominal — donc sa PRÉSENCE est le fait, pas la nullité du nombre. Cette
// clé est le point unique de lecture : l'en-tête du panneau écrivait « schéma v? » sur le `null`, ce qui
// se lit « la console ne sait pas l'afficher » et non « personne ne l'a lue », et le paquet de diagnostic
// partait au support sans un mot alors que c'est le PREMIER chiffre qu'une reprise d'incident regarde.
const CLE_VERSION_DE_SCHEMA_NON_ETABLIE = 'schema_version_non_etablie';
function causeDeLaVersionDeSchemaNonEtablie(corps) {
  const cause = corps && corps[CLE_VERSION_DE_SCHEMA_NON_ETABLIE];
  return typeof cause === 'string' ? cause.trim() : '';
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════
// `P10.20-b` (rang 2) — UN BULLETIN QUI DISPARAÎT SANS UN MOT EST LE SEUL CANAL DE L'EXPLOITANT QUI SE
// TAIT TOUT SEUL.
//
// LE DÉFAUT. Ce bandeau est le seul endroit par lequel un exploitant parle à TOUS les comptes de
// l'instance à la fois — « maintenance en cours », « incident majeur, suivez la procédure X ». La
// console le cachait sur `!b || !b.message`, c'est-à-dire sur « aucun bandeau posé » ET sur « la ligne
// n'a pas pu être lue », qui ne sont pas le même fait. Un message DÉLIBÉRÉMENT posé s'effaçait donc de
// tous les écrans sans que ni le lecteur, ni celui qui l'a posé, ne puisse s'en apercevoir — l'auteur,
// lui, voit son bulletin dans la réponse de son propre POST. Le démon sert maintenant `bulletin: null`
// PLUS une clé nommée qui porte la cause (`CLE_BULLETIN_NON_ETABLI`, daemon/src/handlers/system.rs),
// ABSENTE du chemin nominal : sa PRÉSENCE est le fait, pas la nullité du bulletin.
// ═════════════════════════════════════════════════════════════════════════════════════════════════
const CLE_BULLETIN_NON_ETABLI = 'bulletin_non_etabli';
function causeDuBulletinNonEtabli(corps) {
  const cause = corps && corps[CLE_BULLETIN_NON_ETABLI];
  return typeof cause === 'string' ? cause.trim() : '';
}
// L'aveu à DEUX NŒUDS du bulletin, écrit une seule fois pour ses deux surfaces : le bandeau que TOUS
// les comptes voient, et l'éditeur que l'administrateur rouvre. La phrase est un nœud texte ENTIER (la
// seule forme que le lexique sait traduire), la cause SERVIE est collée dans un SECOND nœud.
function avouerLeBulletinNonEtabli(hote, cause) {
  const aveu = document.createElement('div'); aveu.className = 'bad'; aveu.style.cssText = 'margin:0;font-size:12px';
  const dit = document.createElement('span');
  dit.textContent = 'Bulletin d\'exploitation NON ÉTABLI : le démon a refusé et en nomme la cause —';
  aveu.append(dit, ' « ' + String(cause).trim() + ' »');
  hote.appendChild(aveu);
}

// Le verdict est cherché d'abord PAR CLÉ (`queue_depth_verdict`), puis SUR L'OBJET (`verdict`) : une
// même lecture peut porter plusieurs valeurs — le couple processeur/mémoire vient d'une seule lecture
// de `/proc`, et son verdict est celui de l'objet entier.
// Rend { verdict, valeur, cause, detail } où `verdict` vaut `lu`, `illisible`, un mot inconnu du
// serveur (traité comme NON lu : un verdict ajouté demain est bruyant par défaut, jamais rangé du bon
// côté par inadvertance), ou `null` quand rien n'est publié.
function lireMesure(obj, cle) {
  const verdict = obj[cle + '_verdict'] ?? obj.verdict ?? null;
  const valeur = obj[cle];
  const brute = obj[cle + '_cause'] ?? obj.cause;
  const cause = CAUSE_LBL[brute] ?? (brute || 'cause non dite');
  const detail = obj[cle + '_detail'] ?? obj.detail ?? '';
  if (verdict === VERDICT_LU) return { verdict, valeur, cause, detail };
  if (verdict !== null) return { verdict, valeur: undefined, cause: cause || 'cause non dite', detail };
  // Pas de verdict : un serveur qui ne le publie pas. La valeur seule vaut « lue » ; rien = « non publié ».
  if (valeur != null) return { verdict: VERDICT_LU, valeur, cause: '', detail: '' };
  return { verdict: null, valeur: undefined, cause: '', detail: '' };
}

// Le mot d'état affiché à la place du nombre — jamais un zéro, jamais une case vide.
function motDeVerdict(verdict) {
  return verdict === VERDICT_ILLISIBLE ? 'NON LISIBLE' : verdict === null ? 'non publié' : String(verdict).toUpperCase();
}

// Tuile d'une grandeur à verdict. `fmt` ne reçoit la valeur que si le verdict est `lu` (elle peut
// alors être absente : l'identité de l'hôte publie son verdict SANS sa valeur).
function mesureTile(label, obj, cle, fmt, sub) {
  const m = lireMesure(obj, cle);
  if (m.verdict === VERDICT_LU) return tile(label, fmt(m.valeur), sub);
  const t = tile(label, motDeVerdict(m.verdict), m.verdict === null ? 'aucune mesure publiée' : m.cause, m.detail);
  t.classList.add(m.verdict === null ? 'sys-absent' : 'sys-illisible');
  return t;
}

function tile(label, value, sub, title) {
  const d = document.createElement('div');
  d.className = 'sys-tile';
  const v = document.createElement('div'); v.className = 'sys-tile-v'; v.textContent = value;
  const l = document.createElement('div'); l.className = 'sys-tile-l'; l.textContent = label;
  d.append(v, l);
  if (sub) { const s = document.createElement('div'); s.className = 'sys-tile-s muted'; s.textContent = sub; d.appendChild(s); }
  if (title) d.title = title;
  return d;
}

// P4.1-r / S37 — LE BILAN DU DERNIER TICK DE CHAQUE BOUCLE DE FOND : n abandons, ou un tick AVEUGLE.
// Les boucles sont DÉCOUVERTES dans ce que le serveur publie (`<boucle>_abandons_verdict`), jamais
// énumérées ici : une boucle ajoutée au démon paraît d'office. Un zéro est un VRAI zéro (tout ce qui
// était dû a été évalué) et se lit comme tel ; des abandons sont en alerte ; un tick aveugle est en
// panne, avec sa cause. Aucun bilan publié = démarrage, et c'est dit.
const SUFFIXE_BILAN = '_abandons_verdict';
function bilansDeTicks(sc) {
  const box = document.createElement('div'); box.className = 'sys-bilans';
  const h = document.createElement('div'); h.className = 'sys-tile-l'; h.textContent = 'Abandons au dernier tick, par boucle de fond'; box.appendChild(h);
  const cles = Object.keys(sc).filter(k => k.endsWith(SUFFIXE_BILAN)).sort();
  if (!cles.length) { box.appendChild(muted('aucun bilan publié (pas encore de tick)')); return box; }
  for (const k of cles) {
    const base = k.slice(0, -'_verdict'.length);
    const m = lireMesure(sc, base);
    const row = document.createElement('div'); row.className = 'kv';
    const nom = document.createElement('span'); nom.textContent = base.slice(0, -'_abandons'.length);
    const val = document.createElement('b');
    if (m.verdict === VERDICT_LU) {
      const n = Number(m.valeur) || 0;
      val.textContent = n ? `${n} abandon(s)` : '0';
      val.className = n ? 'warn' : 'ok';
    } else {
      val.textContent = 'TICK AVEUGLE — ' + m.cause;
      val.className = 'bad';
      if (m.detail) val.title = m.detail;
    }
    row.append(nom, val);
    box.appendChild(row);
  }
  return box;
}

// `P10.21-h` — CE QUE LA BASE N'A PAS PRIS, PAR GENRE : DEUX COMPTEURS, UNE MÊME LECTURE.
// CE QUE LE DÉMON SERT (daemon/src/metrics.rs, `gather_json`), sous `ingest` :
//   · `evenements_d_acces_non_ecrits[_total]` (`P10.20-z`) — l'auto-ingestion d'un échec
//     d'authentification, d'un verrouillage, d'un refus d'autorisation (daemon/src/auth.rs) que la base n'a
//     pas pris : la MATIÈRE d'une détection qui manque ;
//   · `acces_operateur_non_traces[_total]` (`P10.21-g`) — un accès cross-tenant d'un super-admin dont le
//     maillon du journal de contrôle ou l'événement posé chez le tenant visité (daemon/src/rbac.rs,
//     `TRACE_OPERATEUR_*`) n'a pas été écrit : l'accès a eu lieu, sa PREUVE manque.
// Chacun est un total et un objet `{ <genre>: { n, derniere_cause } }`. Rien ne les lisait.
// LES GENRES SONT DES ENSEMBLES FERMÉS écrits par le démon ; le harnais relit leurs littéraux dans son
// arbre. Un genre que cette console ne connaît pas est RENDU quand même, sous son nom brut et dit tel :
// jamais écarté. LE COMPTE EST CELUI DU PROCESSUS — il repart de zéro au redémarrage, et c'est écrit.
const GENRES_D_ACCES = {
  'plume-auth.failure': { fr: "échecs d'authentification", en: 'authentication failures' },
  'plume-auth.lockout': { fr: 'verrouillages de compte', en: 'account lockouts' },
  'plume-authz.denied': { fr: "refus d'autorisation", en: 'authorization denials' },
};
const TRACES_D_ACCES_OPERATEUR = {
  'control_ledger.superadmin.read': { fr: 'lectures cross-tenant sans maillon au journal de contrôle', en: 'cross-tenant reads without a control-ledger link' },
  'control_ledger.superadmin.write': { fr: 'écritures cross-tenant sans maillon au journal de contrôle', en: 'cross-tenant writes without a control-ledger link' },
  'tenant.plume-operator-access.read': { fr: "lectures cross-tenant sans événement chez le tenant visité", en: 'cross-tenant reads without an event in the visited tenant' },
  'tenant.plume-operator-access.write': { fr: "écritures cross-tenant sans événement chez le tenant visité", en: 'cross-tenant writes without an event in the visited tenant' },
};
const MOTS_DES_PERTES_PAR_GENRE = {
  titre_acces: { fr: "Événements d'accès que la base n'a PAS pris, depuis le démarrage du démon", en: 'Access events the database did NOT take, since the daemon started' },
  aucun_acces: { fr: "aucun : chaque échec d'authentification, verrouillage et refus d'autorisation a été écrit", en: 'none: every authentication failure, lockout and authorization denial was written' },
  consequence_acces: { fr: "La détection ne verra jamais ces événements. Dernière cause servie —", en: 'Detection will never see these events. Last cause served —' },
  titre_operateur: { fr: "Accès opérateur cross-tenant dont une trace n'a PAS été écrite, depuis le démarrage du démon", en: 'Cross-tenant operator accesses with a trace NOT written, since the daemon started' },
  aucun_operateur: { fr: 'aucun : chaque accès opérateur cross-tenant a laissé ses deux traces', en: 'none: every cross-tenant operator access left both of its traces' },
  consequence_operateur: { fr: "L'accès a eu lieu, sa preuve manque. Dernière cause servie —", en: 'The access happened, its proof is missing. Last cause served —' },
  non_publie: { fr: 'non publié par ce démon : la perte ne peut pas être dite ici', en: 'not published by this daemon: the loss cannot be shown here' },
  genre_inconnu: { fr: 'genre non nommé par cette console', en: 'kind not named by this console' },
  sans_ventilation: { fr: "pertes comptées, mais le démon n'en a pas servi la ventilation par genre :", en: 'losses counted, but the daemon did not serve their breakdown by kind:' },
};
const motDesPertesParGenre = (cle) => (LANG === 'en' ? MOTS_DES_PERTES_PAR_GENRE[cle].en : MOTS_DES_PERTES_PAR_GENRE[cle].fr);
// Les deux familles, décrites une fois : la clé servie, ses noms, et les mots qui lui sont propres.
const FAMILLES_DE_PERTES = [
  { cle: 'evenements_d_acces_non_ecrits', noms: GENRES_D_ACCES, titre: 'titre_acces', aucun: 'aucun_acces', consequence: 'consequence_acces' },
  { cle: 'acces_operateur_non_traces', noms: TRACES_D_ACCES_OPERATEUR, titre: 'titre_operateur', aucun: 'aucun_operateur', consequence: 'consequence_operateur' },
];
function ligneDePerte(nomAffiche, n) {
  const row = document.createElement('div'); row.className = 'kv';
  const val = document.createElement('b'); val.className = 'warn'; val.textContent = String(n);
  row.append(nomAffiche, val);
  return row;
}
function pertesParGenre(ing, famille) {
  const box = document.createElement('div'); box.className = 'sys-bilans';
  box.dataset.pertesParGenre = famille.cle;   // marque de POSE pour le harnais, aucune règle CSS ne la vise
  const h = document.createElement('div'); h.className = 'sys-tile-l'; h.textContent = motDesPertesParGenre(famille.titre); box.appendChild(h);
  const total = ing[famille.cle + '_total'];
  if (typeof total !== 'number') { box.appendChild(muted(motDesPertesParGenre('non_publie'))); return box; }
  const servi = ing[famille.cle];
  const parGenre = (servi && typeof servi === 'object') ? servi : {};
  const genres = Object.keys(parGenre).sort();
  if (!total && !genres.length) { box.appendChild(muted(motDesPertesParGenre(famille.aucun))); return box; }
  // Un total sans ventilation (le verrou de la table par genre a échoué côté démon) n'est pas un zéro.
  if (!genres.length) {
    const nom = document.createElement('span'); nom.textContent = motDesPertesParGenre('sans_ventilation');
    box.appendChild(ligneDePerte(nom, total));
    return box;
  }
  for (const g of genres) {
    const v = parGenre[g] || {};
    const connu = famille.noms[g];
    const nom = document.createElement('span');
    nom.textContent = connu ? (LANG === 'en' ? connu.en : connu.fr) : g;
    if (!connu) { const inconnu = document.createElement('span'); inconnu.className = 'muted'; inconnu.textContent = motDesPertesParGenre('genre_inconnu'); nom.append(' ', inconnu); }
    box.appendChild(ligneDePerte(nom, Number(v.n) || 0));
    // L'aveu à DEUX nœuds : la conséquence au puits, la cause SERVIE collée à côté, telle quelle.
    if (v.derniere_cause) {
      const aveu = document.createElement('div'); aveu.className = 'bad'; aveu.style.cssText = 'margin:0;font-size:12px';
      const dit = document.createElement('span');
      dit.textContent = motDesPertesParGenre(famille.consequence);
      aveu.append(dit, ' « ' + String(v.derniere_cause).trim() + ' »');
      box.appendChild(aveu);
    }
  }
  return box;
}

// S37 — CE QU'UN COMPOSANT PORTE À CÔTÉ DE SON ÉTAT : toute grandeur à verdict posée sur l'objet
// (`<clé>_verdict`) est lue ; une grandeur NON LISIBLE ou des abandons > 0 sont dits à côté de la
// pastille, même quand l'état du composant ne les reflète pas (la taille de la base n'entre pas dans
// l'état du stockage). Les clés sont découvertes sur l'objet ; le libellé est nommé quand il est connu.
const COMPOSANT_LBL = {
  queue_depth: 'file spool',
  disk_used_pct: 'usage disque',
  db_size_bytes: 'taille base',
  abandons_dernier_passage: 'abandons du dernier passage',
  abandons_dernier_tick: 'abandons du dernier tick',
  // `P10.7-n` — SANS CETTE LIGNE, LA TUILE AFFICHAIT SA CLÉ BRUTE. Le rendu des verdicts DÉCOUVRE
  // les clés par leur suffixe, donc ce verdict était bien LU dès le jour où le démon l'a publié —
  // mais il se lisait `cache_indicateurs : …`, un nom de champ servi à un humain. Le libellé est
  // bilingue PAR CONSTRUCTION, comme le reste de cette console.
  cache_indicateurs: LANG === 'en' ? 'indicator cache' : 'cache d\u2019indicateurs',
  // `P4.1-v` — LA PROFONDEUR DE LA QUARANTAINE D'INGEST. Distincte de la file : celle-ci dit
  // combien de lots ATTENDENT leur tour, celle-là combien en sont SORTIS sans jamais entrer en
  // base. Sans cette entrée, la tuile rendrait sa clé brute à un humain.
  quarantine_depth: LANG === 'en' ? 'ingest quarantine' : 'quarantaine d\u2019ingest',
};
function verdictsDuComposant(c) {
  const out = [];
  for (const k of Object.keys(c).filter(k => k.endsWith('_verdict')).sort()) {
    const base = k.slice(0, -'_verdict'.length);
    const m = lireMesure(c, base);
    const lbl = COMPOSANT_LBL[base] || base;
    const s = document.createElement('span'); s.className = 'sys-comp-v';
    if (m.verdict !== VERDICT_LU) {
      s.textContent = lbl + ' : ' + motDeVerdict(m.verdict) + (m.cause ? ' (' + m.cause + ')' : '');
      s.classList.add('bad');
      if (m.detail) s.title = m.detail;
    } else if (base.startsWith('abandons') && Number(m.valeur) > 0) {
      s.textContent = lbl + ' : ' + m.valeur;
      s.classList.add('warn');
    } else {
      continue;
    }
    out.push(s);
  }
  return out;
}

// P11.4-g — LA RÉFÉRENCE DOCUMENTAIRE D'UN AVERTISSEMENT DOIT ÊTRE ATTEIGNABLE. Plusieurs détails servis
// par le démon citent un document du dépôt (`cf. docs/DR-plume-restore.md`, `cf. docs/CIM.md §5.1bis`…).
// POURQUOI PAS UN LIEN. Mesuré le 2026-08-23 : le démon ne sert en fichiers QUE le répertoire web
// (`ServeDir`, un seul point de montage) ; `docs/` est une surface de DÉPÔT, atteignable depuis le README
// et gardée comme telle, jamais une route HTTP. Un lien rendrait 404, c'est-à-dire un cul-de-sac de plus
// là où on vient d'en réparer un. Ce qui rend la référence atteignable, c'est donc qu'elle se LISE en
// entier et se COPIE en un geste — pour la retrouver dans le dépôt ou la coller dans un ticket.
// Le motif est DÉRIVÉ du texte servi, jamais d'une liste de documents : un nouveau détail qui citerait un
// autre document reçoit le même traitement sans que rien ne soit ajouté ici.
const REFERENCE_DE_DOCUMENT = /(docs\/[A-Za-z0-9._\/-]*[A-Za-z0-9])/g;
function detailAvecSesReferences(texte) {
  const t = String(texte || '');
  const noeuds = [];
  let pos = 0;
  REFERENCE_DE_DOCUMENT.lastIndex = 0;
  for (let m = REFERENCE_DE_DOCUMENT.exec(t); m; m = REFERENCE_DE_DOCUMENT.exec(t)) {
    if (m.index > pos) noeuds.push(document.createTextNode(t.slice(pos, m.index)));
    noeuds.push(valeurTransportee(m[1], { titre: 'Copier le chemin de ce document' }));
    pos = m.index + m[1].length;
  }
  if (!noeuds.length) return [document.createTextNode(t)];
  if (pos < t.length) noeuds.push(document.createTextNode(t.slice(pos)));
  return noeuds;
}
function componentRow(c) {
  const row = document.createElement('div');
  row.className = 'sys-comp';
  const st = String(c.state || 'red');
  const dot = document.createElement('span'); dot.className = 'fdot ' + (STATE_DOT[st] || 'muet');
  const name = document.createElement('b'); name.className = 'sys-comp-n'; name.textContent = c.component;
  const badge = document.createElement('span'); badge.className = 'sys-comp-b sys-' + st; badge.textContent = STATE_LBL[st] || st;
  // Le détail est rendu EN NŒUDS et non par `textContent` : il porte des références qui deviennent des
  // valeurs copiables. Il n'est plus tronqué non plus (cf. `.sys-comp-d`, style.css).
  const detail = document.createElement('span'); detail.className = 'sys-comp-d muted';
  detail.append(...detailAvecSesReferences(c.detail));
  row.append(dot, name, badge, ...verdictsDuComposant(c), detail);
  return row;
}

async function loadSystemView() {
  const wrap = $('#system-body'); if (!wrap) return;
  let m, h;
  try { [m, h] = await Promise.all([api('/system/metrics'), api('/system/health')]); }
  catch (e) { wrap.replaceChildren(muted(prefixeDUnEchecRenduTelQuel() + e.message)); return; }
  rendreSysteme(wrap, m, h);
}

// Le rendu, séparé du chargement : il prend les DEUX réponses telles que le serveur les publie, et c'est
// lui que le témoin de CI exerce sur des objets fabriqués (verdict `illisible`, puis `lu`).
function rendreSysteme(wrap, m, h) {
  wrap.replaceChildren();

  // posture globale
  const posture = h.posture || m.posture || 'green';
  const head = document.createElement('div'); head.className = 'sys-posture';
  const pdot = document.createElement('span'); pdot.className = 'fdot ' + (STATE_DOT[posture] || 'muet');
  const ptxt = document.createElement('b'); ptxt.textContent = 'Posture : ' + (STATE_LBL[posture] || posture);
  const pver = document.createElement('span'); pver.className = 'muted'; pver.style.marginLeft = 'auto';
  // La version de schéma QUITTE l'en-tête quand elle n'est pas établie : « v? » y tiendrait la place d'un
  // numéro, et un numéro manquant se lit comme un défaut d'affichage. L'aveu prend sa place, en dessous.
  const causeDuSchema = causeDeLaVersionDeSchemaNonEtablie(m);
  pver.textContent = causeDuSchema
    ? 'plume ' + (m.version || '?') + ' · uptime ' + humanAge(m.uptime_s || 0)
    : 'plume ' + (m.version || '?') + ' · schéma v' + (m.schema_version || '?') + ' · uptime ' + humanAge(m.uptime_s || 0);
  head.append(pdot, ptxt, pver);
  wrap.appendChild(head);
  if (causeDuSchema) {
    // Aveu à DEUX NŒUDS : la phrase est un nœud texte ENTIER (la seule forme que le lexique sait
    // traduire), la cause SERVIE par le démon est collée dans un SECOND nœud, telle quelle.
    const aveu = document.createElement('div'); aveu.className = 'bad'; aveu.style.cssText = 'margin:0;font-size:12px';
    const dit = document.createElement('span');
    dit.textContent = 'Version de schéma NON ÉTABLIE : le démon ne l\'a pas lue et en nomme la cause —';
    aveu.append(dit, ' « ' + causeDuSchema + ' »');
    wrap.appendChild(aveu);
  }

  // santé par composant
  const comps = document.createElement('div'); comps.className = 'sys-comps';
  (h.components || []).forEach(c => comps.appendChild(componentRow(c)));
  wrap.appendChild(comps);

  // tuiles self-métriques
  const grid = document.createElement('div'); grid.className = 'sys-grid';
  const p = m.process || {}, ing = m.ingest || {}, se = m.search || {}, sc = m.scheduler || {}, db = m.db || {}, hote = m.host || {};
  grid.append(
    mesureTile('CPU cumulé', p, 'cpu_seconds', v => v.toFixed(1) + ' s'),
    mesureTile('RSS mémoire', p, 'rss_bytes', fmtBytes),
    tile('Ingest / h', String(ing.events_1h ?? 0), 'total ' + (ing.events_total ?? 0)),
    mesureTile('File spool', ing, 'queue_depth', String, 'fichiers en attente'),
    // `P4.1-v` — LES LOTS ÉCARTÉS SONT À L'ÉCRAN, PAS SEULEMENT DANS UN JOURNAL. Un lot que le
    // dépôt durable n'a pas su écrire quitte la file et n'y revient jamais seul : il est
    // conservé et rejouable, mais absent de la base tant que personne ne l'y remet. Le
    // sous-titre nomme le geste, parce qu'un compte sans geste de fermeture est une rançon.
    mesureTile('Quarantaine ingest', ing, 'quarantine_depth', String,
      LANG === 'en' ? 'set-aside batches — replay with spool-requeue' : 'lots écartés — rejouer avec spool-requeue'),
    tile('Recherche p50', (se.p50_ms ?? 0) + ' ms', 'p95 ' + (se.p95_ms ?? 0) + ' ms'),
    tile('Recherches', String(se.requests_total ?? 0), se.samples ? se.samples + ' échantillons' : ''),
    tile('Scheduler', String(sc.rule_ticks_total ?? 0) + ' ticks', sc.rule_last_tick ? 'règles : ' + humanAge(Math.max(0, (m.ts || 0) - sc.rule_last_tick)) : 'démarrage'),
    tile('Rollups', String(sc.rollup_ticks_total ?? 0) + ' ticks', sc.rollup_last_tick ? humanAge(Math.max(0, (m.ts || 0) - sc.rollup_last_tick)) : 'démarrage'),
    mesureTile('Taille base', db, 'size_bytes', fmtBytes),
    // S33 — l'identité de l'hôte publie son VERDICT sans sa valeur : lue, ou pourquoi pas.
    mesureTile('Identité hôte', hote, 'identity', () => 'lue', 'décide des actions ciblées'),
    tile('Alertes ouvertes', String(m.alerts_open ?? 0)),
    tile('Requêtes HTTP', String((m.http && m.http.requests_total) ?? 0), 'dont 5xx : ' + ((m.http && m.http.responses_5xx_total) ?? 0)),
  );
  wrap.appendChild(grid);
  wrap.appendChild(bilansDeTicks(sc));
  FAMILLES_DE_PERTES.forEach(famille => wrap.appendChild(pertesParGenre(ing, famille)));

  // ADMIN : bulletin/MOTD + bundle de diagnostic.
  if (socIsAdmin()) {
    wrap.appendChild(adminTools());
  }
}

// Le puits du bulletin : avant le corps du panneau Système, hors de ce que son rafraîchissement repeint.
function puitsDuBulletin() {
  const corps = $('#system-body');
  return corps && corps.parentNode ? puitsDuRefusDUnGeste(corps.parentNode, 'bulletin', corps) : null;
}
function adminTools() {
  const box = document.createElement('div'); box.className = 'sys-admin';
  const h = document.createElement('h3'); h.textContent = 'Administration (opérateur)'; box.appendChild(h);

  // --- bulletin / MOTD ---
  const bl = document.createElement('div'); bl.className = 'sys-bulletin';
  const lbl = document.createElement('label'); lbl.textContent = 'Bulletin / MOTD (bandeau diffusé à tous) :'; lbl.className = 'muted';
  const ta = document.createElement('textarea'); ta.id = 'sys-bulletin-msg'; ta.rows = 2; ta.maxLength = 2000;
  ta.placeholder = 'ex : maintenance planifiée 22h-23h — collecte non interrompue';
  const lvl = document.createElement('select'); lvl.id = 'sys-bulletin-level'; lvl.className = 'field'; lvl.title = 'Niveau du bulletin'; // P11.4-b : chrome partagé
  [['info', 'Info'], ['warn', 'Attention'], ['critical', 'Critique']].forEach(([v, t]) => { const o = document.createElement('option'); o.value = v; o.textContent = t; lvl.appendChild(o); });
  // P11.4-b : classes partagées (`.k` n'existait pas ; `.k-theme` est le chrome du sélecteur de thème).
  const save = document.createElement('button'); save.className = 'btn-primary'; save.type = 'button'; save.textContent = 'Publier';
  const clear = document.createElement('button'); clear.className = 'btn'; clear.type = 'button'; clear.textContent = 'Effacer';
  const rowb = document.createElement('div'); rowb.className = 'sys-bulletin-row'; rowb.append(lvl, save, clear);
  bl.append(lbl, ta, rowb);
  // pré-remplit avec le bulletin courant.
  // `P10.20-b` (rang 2) — L'ADMINISTRATEUR QUI ROUVRE L'ÉDITEUR APPREND CE QUE LA ZONE DE SAISIE NE
  // PORTE PAS. Sur un bulletin non établi, le pré-remplissage laissait le champ VIDE et se taisait :
  // celui qui vient d'ouvrir l'éditeur lisait « aucun bulletin posé » à l'endroit même où il aurait
  // corrigé le sien. « Effacer » est en plus RENDU INERTE avec son motif (grammaire `P11.4-l`) : ce
  // geste supprime la ligne `setting` — donc, ici, un message que personne n'a pu lire. « Publier »
  // reste applicable : c'est une écriture délibérée d'un texte que l'administrateur vient de saisir.
  api('/bulletin').then(d => {
    const cause = causeDuBulletinNonEtabli(d);
    if (cause) {
      avouerLeBulletinNonEtabli(bl, cause);
      clear.setAttribute('aria-disabled', 'true');
      clear.title = 'Le bulletin courant n\'a PAS été lu : l\'effacer ici supprimerait la ligne d\'un message d\'exploitation que cette lecture n\'a pas pu rendre — un bandeau diffusé à TOUS les comptes disparaîtrait sans que personne ne l\'ait lu.';
      clear.onclick = () => toast('Le bulletin courant n\'a PAS été lu : l\'effacer ici supprimerait la ligne d\'un message d\'exploitation que cette lecture n\'a pas pu rendre — un bandeau diffusé à TOUS les comptes disparaîtrait sans que personne ne l\'ait lu.', 'bad', 9000);
      return;
    }
    if (d && d.bulletin) { ta.value = d.bulletin.message || ''; lvl.value = d.bulletin.level || 'info'; }
  }).catch(() => {});
  // `P10.27-d` — LA PUBLICATION ET L'EFFACEMENT DU BULLETIN DISENT LEUR REFUS PAR LA FORME PARTAGÉE (`peindreLeRefusDUnGeste`,
  // core.js), dans un puits posé avant le corps du panneau (`#system-body`, que chaque rafraîchissement repeint). MESURÉ
  // AVANT CE LOT (témoin 119d) : « erreur : » + `e.message` dans un avis qui s'efface — le JSON brut du refus du rôle,
  // ou « Failed to fetch » nu lu comme un échec du démon.
  save.onclick = async () => {
    const puits = puitsDuBulletin(); effacerLeRefusDUnGeste(puits);
    try { await apiSend('/bulletin', 'POST', { message: ta.value.trim(), level: lvl.value }); toast('bulletin publié', 'ok'); loadBulletin(); }
    catch (e) { peindreLeRefusDUnGeste(puits, e); }
  };
  clear.onclick = async () => {
    const puits = puitsDuBulletin(); effacerLeRefusDUnGeste(puits);
    try { await apiSend('/bulletin', 'DELETE'); ta.value = ''; toast('bulletin effacé', 'ok'); loadBulletin(); }
    catch (e) { peindreLeRefusDUnGeste(puits, e); }
  };
  box.appendChild(bl);

  // --- bundle de diagnostic ---
  const dl = document.createElement('div'); dl.className = 'sys-diag';
  const dlbl = document.createElement('span'); dlbl.className = 'muted'; dlbl.textContent = 'Bundle de diagnostic (non-secret, pour le support) : ';
  const dbtn = document.createElement('button'); dbtn.className = 'btn'; dbtn.type = 'button'; dbtn.textContent = 'Télécharger le diagnostic'; // P11.4-b
  dbtn.onclick = async () => {
    try {
      const v = await api('/system/diag');
      // `P10.20-a` — UN PAQUET PARTIELLEMENT NON LU PART QUAND MÊME, MAIS IL LE DIT À CELUI QUI L'ENVOIE.
      // `diag_bundle_json` (daemon/src/handlers/system.rs) sert, en 200, la forme entière du paquet et
      // AVOUE deux fois : chaque sous-liste ratée porte `non_lu: true` avec sa cause, et `error` NOMME les
      // familles manquantes. Le fichier partait au support sans un mot : celui-ci y lisait des listes vides
      // et en concluait « rien ne s'est passé sur cette machine », alors que personne n'avait pu les lire.
      // Le téléchargement n'est PAS refusé — un paquet partiel vaut mieux que rien pour une reprise — mais
      // la cause SERVIE est dite, telle quelle, au moment où le fichier part.
      direLesListesNonLuesDuPaquet(v);
      downloadText('plume-diag-' + (v.generated_at || Math.floor(Date.now() / 1000)) + '.json', 'application/json', JSON.stringify(v, null, 2));
      direLaVersionDeSchemaDuPaquet(v);
    } catch (e) { toast(prefixeDUnEchecRenduTelQuel() + e.message, 'bad'); }
  };
  dl.append(dlbl, dbtn);
  box.appendChild(dl);
  return box;
}

// `P10.20-b` — LE PAQUET REMIS AU SUPPORT DIT AUSSI, À CELUI QUI L'ENVOIE, QUE SA VERSION DE SCHÉMA N'A
// PAS ÉTÉ LUE. Le corps le dit déjà (le démon y pose la clé nommée) ; mais le fichier part par un
// téléchargement, personne ne le relit ici, et le support découvrirait seul un `schema_version: null`.
// L'avis est une CHAÎNE (un avis n'a pas de nœud à deux morceaux) et la cause SERVIE y est collée telle
// quelle. Rend `true` quand l'aveu a été dit — c'est ce que le harnais ESM juge.
// `P10.20-a` — LE MÊME PAQUET DIT AUSSI QUELLES DE SES LISTES N'ONT PAS ÉTÉ LUES. `diag_bundle_json`
// (daemon/src/handlers/system.rs) avoue DEUX fois quand une sous-lecture échoue : la sous-liste ratée
// porte `non_lu: true` avec sa cause, et `error` NOMME les familles manquantes. Le fichier partait au
// support sans un mot : celui-ci y lisait des listes vides et en concluait « rien ne s'est passé sur cette
// machine », alors que personne n'avait pu les lire. Le téléchargement n'est PAS refusé — un paquet
// partiel vaut mieux que rien pour une reprise d'incident — mais la cause SERVIE est dite, telle quelle,
// au moment où le fichier part. Sœur exacte de `direLaVersionDeSchemaDuPaquet` : même forme, même retour,
// et c'est ce retour que le harnais ESM juge.
function direLesListesNonLuesDuPaquet(paquet) {
  const cause = paquet && typeof paquet.error === 'string' ? paquet.error.trim() : '';
  if (!cause) return false;
  toast('Bundle de diagnostic PARTIELLEMENT NON LU : le démon a refusé une partie des lectures et en nomme la cause — « ' + cause + ' »', 'err', 9000);
  return true;
}
function direLaVersionDeSchemaDuPaquet(paquet) {
  const cause = causeDeLaVersionDeSchemaNonEtablie(paquet);
  if (!cause) return false;
  toast('Version de schéma NON ÉTABLIE dans ce paquet de diagnostic : le démon ne l\'a pas lue et en nomme la cause — « ' + cause + ' »', 'err', 9000);
  return true;
}

// Bandeau MOTD (appelé au boot + après une mutation admin). Aucun bulletin -> caché (invariant mode 0).
async function loadBulletin() {
  const el = $('#bulletin-banner'); if (!el) return;
  let d;
  try { d = await api('/bulletin'); } catch { el.hidden = true; return; }
  const b = d && d.bulletin;
  // `P10.20-b` (rang 2) — L'AVEU PASSE AVANT LE REPLI, ET LE BANDEAU RESTE VISIBLE. Le cacher serait
  // rendre « rien n'a été annoncé » sur une lecture qui n'a pas eu lieu, sur le seul canal par lequel
  // l'exploitation parle à tout le monde. Le ton est celui de l'alerte, jamais celui d'un « info ».
  const causeDuBulletin = causeDuBulletinNonEtabli(d);
  if (causeDuBulletin) {
    el.className = 'bulletin-banner lvl-critical';
    el.replaceChildren();
    avouerLeBulletinNonEtabli(el, causeDuBulletin);
    el.hidden = false;
    return;
  }
  if (!b || !b.message) { el.hidden = true; el.replaceChildren(); return; }
  el.className = 'bulletin-banner lvl-' + (b.level || 'info');
  el.replaceChildren();
  const msg = document.createElement('span'); msg.className = 'bulletin-msg'; msg.textContent = b.message;
  el.appendChild(msg);
  if (b.updated_by) { const by = document.createElement('span'); by.className = 'bulletin-by muted'; by.textContent = '— ' + b.updated_by + (b.updated ? ' · ' + fmtTs(b.updated) : ''); el.appendChild(by); }
  el.hidden = false;
}

// `direLaVersionDeSchemaDuPaquet` est exposée pour le harnais ESM (témoin 96 : l'aveu dit à celui qui
// envoie le paquet), au même titre que `rendreSysteme` ; elle n'a qu'un appelant applicatif, le bouton
// « Télécharger le diagnostic ».
export { GENRES_D_ACCES, TRACES_D_ACCES_OPERATEUR, loadSystemView, loadBulletin, rendreSysteme, lireMesure, componentRow, detailAvecSesReferences, direLaVersionDeSchemaDuPaquet, direLesListesNonLuesDuPaquet, motDesPertesParGenre };
