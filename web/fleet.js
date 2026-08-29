// fleet.js — extracted from app.js (DEEP state-container split). Behaviour-preserving.
// Flotte d'agents (P0 UI): inventaire des hotes/endpoints (GET /api/fleet, lecture seule).
import { $, apiSend, confirmModal, exportBar, fetchInto, fmtTs, humanAge, ic, modal, muted, pagedList, socRole, toast } from './core.js';

// =================================================================================================
// FLOTTE D'AGENTS (P0 UI) — inventaire des HÔTES/endpoints qui remontent des données. LECTURE (viewer+) :
// 100% GET /api/fleet (même redaction/RBAC que le reste ; l'authorizer read-pool ne laisse JAMAIS fuir
// token.token_hash). AFFICHAGE SEUL : la console ne pilote pas l'hôte (invariant #3) — l'enrôlement et la
// config de push sont montrés, jamais commandés d'ici. Statut = fraîcheur du dernier signal de l'hôte : un
// hôte muet = son agent est probablement tombé (≠ une SOURCE calme, qui reste normale). VERSION / OS de
// l'agent : NON disponibles côté daemon (le shipper ne les transmet pas) -> non affichés (suivi différé).
//
// P11.10-a — « MUET » NE VEUT PAS DIRE « INCIDENT ». Trois situations rendaient le même mot : une machine
// DÉCOMMISSIONNÉE, une machine de TEST, et un AGENT TOMBÉ — seule la dernière est un incident. La colonne
// « Attendu de l'hôte » rend désormais le verdict que le DÉMON dérive (`attente`, jeton stable) avec son
// déclarant et sa date, sur la grammaire des sources (`P11.3-c`) : un enrôlement, l'exploitant, ou personne.
// Et l'en-tête ne mélange plus : les parts viennent du démon (`repartition`, calculée sur le PARC et non sur
// la page), elles s'additionnent, et seule « muet(s) » alerte.
const FLEET_DOT  = { fresh: 'frais', stale: 'warn', silent: 'muet' };   // pastille (réutilise .fdot existants)

const FLEET_TXT  = { fresh: 'ok',    stale: 'fwarn', silent: 'bad'  };   // couleur du libellé (classes existantes)

const FLEET_LBL  = { fresh: 'frais', stale: 'en retard', silent: 'muet' };

const FLEET_RANK = { silent: 0, stale: 1, fresh: 2 };                    // tri : problèmes d'abord

// L'ATTENTE, RENDUE. Les jetons viennent du démon (`VerdictDHote::jeton`) et ne sont pas réécrits ici —
// la console pivote dessus, elle ne recalcule pas le verdict (leçon de `P11.3-d`).
const ATT_LBL = { signal_attendu: 'signal attendu', silence_attendu: 'silence attendu', retire: 'retirée du parc', non_declare: 'personne n\'a rien dit' };

const ATT_TXT = { signal_attendu: 'ok', silence_attendu: 'calm', retire: 'mut', non_declare: 'mut' };

// Ce que l'exploitant peut déclarer, et le mot exact du démon. Enum FERMÉ, miroir de `ATTENTES_DECLARABLES`.
const ATT_CHOIX = [
  { value: 'signal_attendu', label: 'un signal est attendu — son silence est un incident' },
  { value: 'silence_attendu', label: 'son silence est attendu — machine de test, banc, saisonnière' },
  { value: 'retire', label: 'retirée du parc — décommissionnée' },
];

// Déclarer une machine de son propre parc est un geste ÉDITORIAL (miroir du path-guard RBAC editor+).
const canDeclareHosts = () => { const r = socRole(); return r === 'admin' || r === 'editor'; };

// export (client) des lignes DÉJÀ chargées (aucune colonne secrète : host/statut/timestamps/nom d'enrôlement).
const FLEET_EXPORT_COLS = [
  { key: 'host', label: 'host' }, { key: 'status', label: 'status' }, { key: 'last_seen', label: 'last_seen' },
  { key: 'signals', label: 'signals' }, { key: 'first_seen', label: 'first_seen' }, { key: 'enrolled', label: 'enrolled' },
  { key: 'enroll_name', label: 'enroll_name' }, { key: 'enroll_created', label: 'enroll_created' }, { key: 'token_last_used', label: 'token_last_used' },
  { key: 'attente', label: 'attente' }, { key: 'attente_libelle', label: 'attente_libelle' },
];

function fleetExportRow(h) {
  return {
    host: h.host || '', status: h.status || '', last_seen: h.last_seen ? fmtTs(h.last_seen) : '',
    signals: h.signals == null ? 0 : h.signals, first_seen: h.first_seen ? fmtTs(h.first_seen) : '',
    enrolled: h.enrolled ? 'oui' : 'non', enroll_name: h.enroll_name || '',
    enroll_created: h.enroll_created ? fmtTs(h.enroll_created) : '', token_last_used: h.token_last_used ? fmtTs(h.token_last_used) : '',
    attente: h.attente || '', attente_libelle: h.attente_libelle || '',
  };
}

function fleetExportBar(hosts) {
  return exportBar('flotte', () => ({ cols: FLEET_EXPORT_COLS, rows: hosts.map(fleetExportRow) }), 'fleet');
}

// RENDU PUR de l'inventaire à partir de la charge utile de /api/fleet (exercé par le harnais ESM sur des
// objets fabriqués ; `loadFleetView` ne fait que l'appeler après le fetch). Même découpe que
// `renderSourcesInventory` — un rendu qui n'est atteignable qu'après un appel réseau n'est pas jugeable.
function renderFleetInventory(wrap, d) {
  // `P10.7-d` — UN REFUS DU DÉMON ARRIVE EN 200, ET CETTE VUE EN TIRAIT UN INCIDENT.
  //
  // CE QUE LA MESURE DU 2026-08-29 A MONTRÉ, EN EXERÇANT CETTE FONCTION SUR LE CORPS EXACT QUE LE DÉMON
  // SERT. `daemon/src/handlers/fleet.rs` rend, portillon de concurrence CLOS,
  // `portillon::corps_de_refus(json!({ "hosts": [] }))` — soit `{hosts: [], error: <la cause>}`, en 200.
  // `api()` ne jette pas là-dessus, `fetchInto` non plus : le corps arrivait ici INTACT, et rien ne lisait
  // `error` (le module ne citait pas ce mot une seule fois). La suite ne lisait donc que la FORME, et la
  // forme d'un refus est celle d'un parc vide.
  //
  // CE QUI SORTAIT ALORS N'ÉTAIT PAS « AUCUNE DONNÉE », ET C'EST LE POINT. Deux phrases, dans cet ordre :
  //   1. `<div class="bad">` « Ingestion en panne — aucune donnée reçue récemment (tous les hôtes
  //      apparaîtront « en retard » / « muets ») » — parce que `pipeline_fresh` est ABSENT du corps de
  //      refus, donc faux, donc la branche d'alarme ;
  //   2. `<div class="muted">` « aucun hôte distant n'a encore poussé de données — hôte local uniquement ».
  // La première est pire qu'une absence : c'est un INCIDENT AFFIRMÉ. La console n'a rien lu et déclare une
  // panne d'ingestion — un exploitant qui la croit ouvre une intervention sur une chaîne qui va bien.
  // Rendre moins que ce qu'on sait est une lacune ; rendre PLUS est un mensonge, et c'était celui-ci.
  //
  // LE TEST EST SÉPARÉ DE CELUI DU VIDE, ET IL PASSE AVANT TOUTE LECTURE DE LA FORME — y compris avant la
  // bannière, qui est la fautive. La cause n'est PAS recopiée : elle est écrite une seule fois, dans
  // `daemon/src/handlers/portillon.rs`, et rendue telle quelle. Ce module n'ajoute que ce que le démon ne
  // peut pas savoir : QUELLE vue a été demandée, et ce que le refus n'établit pas.
  //
  // CE QUE CELA FERME EN PLUS DU LIBELLÉ : aucune ligne d'hôte n'est posée, donc aucun geste de
  // déclaration (`declareHostExpectation` / `clearHostExpectation`, deux ÉCRITURES) ne peut partir d'une
  // lecture qui n'a pas eu lieu. La barre d'export n'est pas posée non plus : exporter le vide d'un refus
  // en ferait un fichier qui a l'air d'un relevé.
  //
  // DIRECTION DE L'ERREUR : le refus l'emporte sur ce qui serait servi à côté. Le corps du démon ne porte
  // aujourd'hui aucun hôte avec sa cause ; s'il en portait, ce serait un résultat INCOMPLET, et le rendre
  // en table le présenterait comme complet.
  const refusServi = (d && d.error != null) ? String(d.error).trim() : '';
  if (refusServi) {
    wrap.replaceChildren();
    const bad = document.createElement('div');
    bad.className = 'bad';
    bad.style.cssText = 'margin:0 0 9px;font-size:12px';
    bad.textContent = "Inventaire de la flotte NON LU : le démon a refusé et en nomme la cause — « " + refusServi
      + " » Ce n'est PAS une absence : aucun hôte n'a été lu, donc rien ici n'établit qu'il n'y en a pas, "
      + "et surtout rien n'établit que l'ingestion soit en panne — cette vue ne l'a pas regardée.";
    wrap.appendChild(bad);
    return;
  }
  const hosts = (d.hosts || []).slice();
  const srvNow = d.now || Math.floor(Date.now() / 1000);
  wrap.replaceChildren();
  const banner = document.createElement('div');
  banner.className = d.pipeline_fresh ? 'muted' : 'bad';
  banner.style.cssText = 'margin:0 0 9px;font-size:12px';
  banner.textContent = d.pipeline_fresh
    ? "Une ligne par hôte/machine (endpoint où un agent pousse) — statut de l'agent, dernier signal, enrôlement, et ce qu'on ATTEND de la machine. Un hôte « muet » n'est un incident que si personne n'a déclaré le contraire : une machine de test ou décommissionnée se déclare, et cesse alors d'alerter. Affichage seul — aucune commande d'hôte depuis la console (version/OS de l'agent non transmis par le collecteur, non affichés). → Pour les sources par type de donnée, voir Inventaire des sources."
    : 'Ingestion en panne — aucune donnée reçue récemment (tous les hôtes apparaîtront « en retard » / « muets »).';
  wrap.appendChild(banner);
  if (!hosts.length) { wrap.appendChild(muted("aucun hôte distant n'a encore poussé de données — hôte local uniquement.")); return; }
  // EN-TÊTE : les parts viennent du DÉMON (`repartition`, calculée sur le PARC ENTIER) et elles
  // s'additionnent. Avant P11.10-a la console comptait sur les lignes AFFICHÉES (bornées à 500) à côté
  // d'un total calculé sur le parc : au-delà du plafond de page, les trois nombres ne se retrouvaient
  // plus dans le total annoncé — le même défaut que P11.3-d a mesuré sur les alertes de sources.
  const r = d.repartition || null;
  const head = document.createElement('div'); head.className = 'alerthead';
  const sub = document.createElement('span'); sub.className = 'fleetsum';
  if (r) {
    sub.innerHTML = `${r.flotte} hôte(s) dans le parc · <b class="ok">${r.frais}</b> frais · <b class="fwarn">${r.en_retard}</b> en retard · <b class="bad">${r.muet_inattendu}</b> muet(s)`
      + (r.muet_attendu ? ` · <b class="calm">${r.muet_attendu}</b> muet(s) attendu(s)` : '')
      + (r.retires ? ` <span class="muted">+ ${r.retires} retirée(s) du parc</span>` : '');
    sub.title = "Les parts font le tout : frais + en retard + muets + muets attendus = le parc. Seuls les « muets » alertent — un silence déclaré attendu, non. Les machines retirées sont hors du parc et comptées à part.";
  } else {
    // Charge utile sans répartition (démon antérieur) : on le DIT plutôt que de recomposer un compte qui
    // ne se retrouverait pas — c'est exactement le défaut que cette clé ferme.
    sub.textContent = `${hosts.length} hôte(s) — répartition non publiée par le démon (comptes non rendus)`;
  }
  head.appendChild(sub);
  head.appendChild(fleetExportBar(hosts));
  wrap.appendChild(head);
  const tblHost = document.createElement('div'); wrap.appendChild(tblHost);
  const editable = canDeclareHosts();
  // Ce qui reste à trancher : des machines muettes que personne n'a déclarées. La phrase n'apparaît que
  // s'il y en a, et elle dit l'issue selon le rôle (un lecteur ne se voit pas offrir un geste interdit).
  const aTrancher = r ? r.muet_inattendu : hosts.filter(h => h.status === 'silent' && h.attente === 'non_declare').length;
  if (aTrancher) {
    const hint = document.createElement('div'); hint.className = 'fwarn'; hint.style.cssText = 'margin:0 0 8px;font-size:12px';
    hint.textContent = aTrancher + " hôte(s) muet(s) que personne n'a déclarés : un agent tombé et une machine décommissionnée se ressemblent tant que personne ne le dit. "
      + (editable ? "Actions → « déclarer » : silence attendu (elle reste au parc, sans alerter) ou retirée du parc (persistant, réversible, audité)."
                  : "La déclaration demande le rôle éditeur ou administrateur (geste persistant, réversible, audité).");
    wrap.insertBefore(hint, tblHost);
  }
  const ageTxt = s => 'il y a ' + humanAge(s);
  const columns = [
    { key: 'host', label: 'Hôte', sortable: true, sortVal: h => h.host || '', render: h => {
      const f = document.createDocumentFragment();
      const ico = document.createElement('span'); ico.innerHTML = ic('server'); ico.style.cssText = 'margin-right:6px;color:var(--mut)'; f.appendChild(ico);
      const nm = document.createElement('span'); nm.textContent = h.host || ''; f.appendChild(nm);
      if (h.dans_la_flotte === false) {
        const b = document.createElement('span'); b.className = 'badge fleetbadge-retire'; b.textContent = 'hors parc';
        b.style.cssText = 'margin-left:6px;color:var(--mut)';
        b.title = "Retirée du parc par un humain de cette installation : elle reste listée (son historique n'est pas effacé) mais sort du dénominateur et de l'alerte.";
        f.appendChild(b);
      }
      return f;
    } },
    { key: 'status', label: 'Statut', sortable: true, sortVal: h => (FLEET_RANK[h.status] ?? 9), render: h => {
      const f = document.createDocumentFragment();
      // Un silence DÉCLARÉ attendu n'est plus peint comme une alarme : le mot reste « muet » (c'est la
      // même observation) mais la couleur d'alarme est réservée à ce qui alerte VRAIMENT.
      const alarme = h.alerte_si_muet !== false;
      const dot = document.createElement('span'); dot.className = 'fdot ' + (h.status === 'silent' && !alarme ? 'calme' : (FLEET_DOT[h.status] || 'calme'));
      const lbl = document.createElement('b'); lbl.className = h.status === 'silent' && !alarme ? 'calm' : (FLEET_TXT[h.status] || 'calm');
      lbl.textContent = FLEET_LBL[h.status] || h.status || '—';
      f.append(dot, lbl); return f;
    } },
    // P11.10-a — CE QU'ON ATTEND DE LA MACHINE, et QUI l'a dit. Le badge nomme le déclarant plutôt qu'un
    // oui/non nu, et la seconde ligne porte la provenance PROPRE du geste (son auteur, sa date, son motif).
    { key: 'attente', label: "Attendu de l'hôte", sortable: true, sortVal: h => ATT_LBL[h.attente] || '', render: h => {
      const f = document.createDocumentFragment();
      const b = document.createElement('span'); b.className = 'badge fleetbadge-attente';
      b.textContent = h.declaree_par || ATT_LBL[h.attente] || '—';
      b.classList.add(ATT_TXT[h.attente] || 'mut');
      b.title = h.attente === 'non_declare'
        ? "Personne ne l'a déclarée — ni un enrôlement, ni un humain de cette installation. Son silence alerte donc, ce qui est le défaut sûr : on ne peut pas deviner qu'une machine a été décommissionnée."
        : 'Déclarée : quelqu\'un a dit ce qu\'on attend de cette machine. Le détail dit qui, quand, et pourquoi.';
      f.appendChild(b);
      const why = document.createElement('span'); why.className = 'muted fleetwhy'; why.style.cssText = 'display:block;font-size:10px';
      why.textContent = h.attente_libelle || (ATT_LBL[h.attente] || 'aucune déclaration');
      f.appendChild(why);
      return f;
    } },
    { key: 'last_seen', label: 'Dernier signal', sortable: true, sortVal: h => h.last_seen || 0, render: h => {
      const sp = document.createElement('span'); sp.textContent = h.last_seen ? ageTxt(h.age_s) : '—'; if (h.last_seen) sp.title = fmtTs(h.last_seen); return sp;
    } },
    { key: 'signals', label: 'Signaux', sortable: true, align: 'r', sortVal: h => h.signals || 0, render: h => {
      const sp = document.createElement('span'); sp.textContent = String(h.signals == null ? 0 : h.signals); sp.title = 'Total des signaux reçus (événements + métriques + snapshots, dans la fenêtre de rétention)'; return sp;
    } },
    { key: 'first_seen', label: 'Premier vu', sortable: true, sortVal: h => h.first_seen || 0, render: h => {
      const sp = document.createElement('span'); sp.textContent = h.first_seen ? fmtTs(h.first_seen) : '—'; return sp;
    } },
    { key: 'enroll', label: 'Enrôlement', sortable: true, sortVal: h => h.enrolled ? (h.enroll_name || '~') : '', render: h => {
      if (!h.enrolled) { const sp = document.createElement('span'); sp.className = 'muted'; sp.textContent = 'non enrôlé'; sp.title = "Aucun token d'agent lié à cet hôte (ingest via token partagé, ou hôte local)."; return sp; }
      const b = document.createElement('span'); b.className = 'badge'; b.textContent = h.enroll_name || 'agent';
      b.style.cssText = 'color:var(--ok);border-color:color-mix(in srgb,var(--ok) 40%,transparent)';
      b.title = "Token d'agent lié à cet hôte" + (h.enroll_created ? ' — créé le ' + fmtTs(h.enroll_created) : '');
      return b;
    } },
    { key: 'token_last_used', label: 'Dernier push agent', sortable: true, sortVal: h => h.token_last_used || 0, render: h => {
      const sp = document.createElement('span');
      if (h.token_last_used) { sp.textContent = ageTxt(Math.max(0, srvNow - h.token_last_used)); sp.title = fmtTs(h.token_last_used); }
      else { sp.textContent = '—'; sp.className = 'muted'; sp.title = 'Non disponible (hôte non enrôlé, ou mode multi-tenant où le token ne suit pas le dernier push).'; }
      return sp;
    } },
  ];
  if (editable) columns.push({ key: 'actions', label: 'Actions', render: h => {
    const box = document.createElement('span'); box.style.whiteSpace = 'nowrap';
    const dec = document.createElement('button'); dec.type = 'button'; dec.className = 'picon fleetdeclare';
    dec.textContent = 'déclarer';
    dec.title = "Dire ce qu'on attend de cette machine : un signal, un silence normal, ou la sortie du parc (persistant, réversible, audité)";
    dec.onclick = e => { e.stopPropagation(); declareHostExpectation(h); };
    box.appendChild(dec);
    if (h.attente !== 'non_declare') {
      const clr = document.createElement('button'); clr.type = 'button'; clr.className = 'picon'; clr.style.marginLeft = '6px'; clr.innerHTML = ic('x');
      clr.title = "Retirer la déclaration : la machine reprend le défaut — son silence alerte de nouveau";
      clr.onclick = e => { e.stopPropagation(); clearHostExpectation(h); };
      box.appendChild(clr);
    }
    return box;
  } });
  // `P11.18-m` — LA RECHERCHE EST POSÉE, ET SA PORTÉE EST CELLE DE LA ROUTE. Cette vue demande une
  // limite (`/fleet?limit=500`) que le démon borne au même plafond : les lignes tenues ici sont donc une
  // FENÊTRE du parc dès qu'il dépasse ce plafond, et la déclarer est ce qui empêche la liste de rendre
  // « aucun résultat » pour un hôte qui EXISTE. Le texte cherché est celui des cellules RENDUES : un hôte
  // se cherche par son nom, par le mot de son statut, par ce qui est déclaré de lui et par son enrôlement.
  // `P11.18-z` — L'IDENTITÉ DE CETTE LISTE, ET C'EST ELLE QUI ARME SA MÉMOIRE DE RECHERCHE. Déclarer
  // un hôte (`declareHostExpectation`) ou retirer une déclaration (`clearHostExpectation`) rappellent
  // `loadFleetView()`, qui refabrique l'hôte de la liste : sans identité, la recherche de l'exploitant
  // repartait à zéro à chaque geste éditorial. La clé est un LITTÉRAL — stable d'un rendu à l'autre,
  // propre à cette liste — et c'est le motif de rangement que le dépôt porte déjà (`group.storeKey`),
  // jamais un second.
  pagedList(tblHost, { mode: 'client', pageSize: 50, rows: hosts, columns, emptyText: 'aucun hôte', storeKey: 'soc_fleet_hosts', recherche: { fenetre: true } });
  const legend = document.createElement('div'); legend.className = 'muted'; legend.style.cssText = 'margin-top:8px;font-size:11px';
  legend.textContent = "Statut = fraîcheur du dernier signal de l'hôte : frais (<15 min) · en retard (15 min–1 h) · muet (>1 h). « Attendu de l'hôte » dit ce que quelqu'un a déclaré de cette machine, et qui : un enrôlement (un jeton d'agent y est lié), l'exploitant (avec sa date et son motif), ou personne. Un silence n'est un incident QUE si personne n'a déclaré le contraire — une machine de test se déclare « silence attendu » (elle reste au parc, sans alerter), une machine décommissionnée se déclare « retirée » (elle sort du dénominateur, sans disparaître de la liste). Ces déclarations ne touchent ni la collecte, ni les règles, ni la rétention. « Signaux » = volume total reçu (rétention). « Enrôlement » = token d'agent lié à l'hôte ; « Dernier push agent » = dernier appel authentifié du token (mode mono-tenant). Version et OS de l'agent ne sont pas transmis par le collecteur (différés).";
  wrap.appendChild(legend);
}

// Inventaire de la flotte : GET /api/fleet (borné à 500 hôtes = plafond serveur ; une flotte réelle en compte
// bien moins) puis pagedList mode CLIENT -> tri par colonne + pagination locale + export du jeu complet chargé,
// exactement comme l'inventaire des Sources (loadSourcesView). Statut server-side (fresh/stale/silent) mappé au
// vocabulaire UI (frais / en retard / muet) ; la RÉPARTITION, elle, vient du démon et porte sur le parc entier.
async function loadFleetView() {
  const wrap = $('#fleet-body'); if (!wrap) return;
  const d = await fetchInto(wrap, '/fleet?limit=500&sort=status&dir=asc'); if (!d) return;
  renderFleetInventory(wrap, d);
}

// DÉCLARER CE QU'ON ATTEND D'UNE MACHINE. Trois réponses, dont le RÉARMEMENT : sans lui, un exploitant
// pourrait taire une machine et jamais se dédire. Le démon EXIGE un motif sur les deux valeurs qui
// éteignent l'alerte — la question est donc posée ici, et la validation est locale AVANT l'appel pour que
// le refus se lise dans la fenêtre plutôt qu'en message d'erreur.
async function declareHostExpectation(h) {
  const eteint = v => v === 'silence_attendu' || v === 'retire';
  const r = await modal({
    title: "Attendu de l'hôte : " + h.host, okText: 'Déclarer', danger: false,
    message: "Ce que vous déclarez décide si le silence de cette machine LÈVE une alerte. Rien d'autre n'est touché : ni la collecte, ni les règles, ni la rétention — la machine reste listée et ses signaux continuent d'être reçus.",
    validate: v => (eteint(v.attente) && !String(v.motif || '').trim()) ? "Un motif est requis : éteindre l'alerte sur une machine sans dire pourquoi est illisible six mois plus tard." : null,
    fields: [
      { name: 'attente', label: 'Ce qu\'on attend', type: 'select', value: h.attente === 'non_declare' ? 'silence_attendu' : h.attente, options: ATT_CHOIX },
      { name: 'motif', label: 'Motif (requis pour éteindre l\'alerte)', type: 'textarea', value: h.attente_motif || '', placeholder: 'ex : banc de test, machine décommissionnée le …' },
    ],
  });
  if (!r) return;
  if (eteint(r.attente) && !await confirmModal(`Déclarer « ${h.host} » : ${ATT_LBL[r.attente]} ? L'alerte « hôtes muets » cessera de compter cette machine, et la console dira que vous l'avez déclarée, avec la date et le motif. Geste persistant, réversible, audité.`, { danger: true, okText: 'Déclarer' })) return;
  try { await apiSend('/hosts/settings', 'PUT', { host: h.host, action: 'set_attente', value: r.attente, motif: r.motif || '' }); }
  catch (e) { toast((e && e.message) || 'échec', 'bad'); return; }
  toast('déclaration enregistrée', 'ok'); loadFleetView();
}

async function clearHostExpectation(h) {
  if (!await confirmModal(`Retirer la déclaration de « ${h.host} » ? La machine reprend le défaut : personne n'a rien dit, donc son silence alerte de nouveau. Geste audité.`, { danger: false, okText: 'Retirer la déclaration' })) return;
  try { await apiSend('/hosts/settings', 'PUT', { host: h.host, action: 'clear' }); }
  catch (e) { toast((e && e.message) || 'échec', 'bad'); return; }
  toast('déclaration retirée', 'ok'); loadFleetView();
}


export { loadFleetView, renderFleetInventory };
