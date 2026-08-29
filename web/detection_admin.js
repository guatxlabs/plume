// detection_admin.js — administration de la detection : couverture ATT&CK + regles / canaux /
// parsers / actions / mode global / playbooks (CRUD UI). Contient les cablages DOM + charges initiales.
// Extrait d'app.js (decoupe par concern — meme patron que freshness.js).
// PURE MOVE : corps de fonctions IDENTIQUES au monolithe, seuls les import/export sont ajoutes.
// Le cycle app<->module est benin : les fonctions importees d'app.js ne sont appelees qu'a
// l'EXECUTION (handlers/async apres await), jamais a l'evaluation du module.
import { $, LANG, esc, sev, fmtTs, ic, muted, api, apiSend, confirmModal, toast, pagedList, mitreName, managedBadge, gateDeleteBtn, contentSubmit, contentDelete, fetchInto, formMsg, socIsAdmin, lsSet, collapsibleGroup, disclosure } from './core.js';
import { S, lireLeStockageDuSite, ecrireDansLeStockageDuSite } from './state.js';
import { initSigmaImport } from './sigmaimport.js';
import { loadAttackMatrix, poserLesPortesDeTechnique } from './attack.js';
import { setAlertMitreFilter } from './alerts.js';
// P11.2-a/b + P11.1-e : ligne, interrupteur et destination PARTAGÉS (règles, playbooks, runbooks, détection avancée).
import { producerRow, rowButton, enabledSwitch, announceCreated, takePendingNote, detectionDestination, destinationNote, DESTINATIONS } from './producer_ui.js';
// P11.12-a : LE champ de recherche partagé des listes (voir `recherche_de_liste.js` pour la mesure
// des trois filtres existants et la raison pour laquelle aucun n'était reprenable).
import { champDeRecherche, filtrerParRecherche, resumeDeRecherche, texteCherchable } from './recherche_de_liste.js';

// PURPLE — panneau couverture ATT&CK (onglet Détection) : agrège alert.mitre par technique via
// /api/coverage/detections (count + 1re détection), trié count DESC. Chaque chip pivote vers les
// alertes filtrées par cette technique (setAlertMitreFilter). Lecture seule, idempotent.
async function renderCoverage() {
  const b = $('#cov-body'); if (!b) return;
  // `P10.7-d` — LA RÉPONSE N'EST PLUS DÉCONSTRUITE, PARCE QUE LA DÉCONSTRUCTION JETAIT L'AVEU.
  //
  // CE QUE LA MESURE DU 2026-08-29 A MONTRÉ, EN EXERÇANT `renderCoverage` SUR LE CORPS EXACT DU DÉMON.
  // `daemon/src/handlers/alerts.rs` rend, portillon de concurrence CLOS,
  // `portillon::corps_de_refus(json!({ "detections": [] }))` — soit `{detections: [], error: <la cause>}`,
  // en 200 : `api()` ne jette que sur `!r.ok`, sur un corps vide ou non-JSON, donc pas ici.
  // `({ detections } = await api(…))` ne retenait QUE la clé nommée : `error` arrivait et repartait dans la
  // même expression, sans qu'aucun nom ne le porte. La vue sortait alors « aucune technique détectée ».
  //
  // POURQUOI CELLE-CI EST UNE DES PIRES DE LA CONSOLE. Sur une matrice de couverture purple, « aucune
  // technique détectée » n'est pas un vide : c'est un VERDICT DE COUVERTURE. Il se lit « rien ne nous a
  // touchés » — ou pire, « nos règles ne détectent rien » — et c'est le genre de phrase dont on tire une
  // décision (créer des règles, rouvrir un angle mort, déclarer une campagne infructueuse). Elle était
  // rendue par une lecture QUI N'A PAS EU LIEU.
  //
  // LE CORPS EST LIÉ, PUIS LU — le test du refus AVANT celui du vide, et non fondu avec lui : les fondre
  // est exactement ce que `check_a_refusal_is_not_rendered_as_an_absence.py` rend non-écrivable sous
  // `web/`. La cause n'est pas recopiée ici ; elle est écrite une seule fois dans
  // `daemon/src/handlers/portillon.rs` et rendue telle quelle.
  let rep;
  try { rep = await api('/coverage/detections'); } catch (e) { b.innerHTML = '<div class="muted">couverture indisponible</div>'; return; }
  const refusServi = (rep && rep.error != null) ? String(rep.error).trim() : '';
  if (refusServi) {
    b.innerHTML = '<div class="bad">' + esc("Couverture ATT&CK NON LUE : le démon a refusé et en nomme la cause — « " + refusServi
      + " » Ce n'est PAS une absence : aucune technique n'a été lue, donc rien ici n'établit qu'aucune n'a "
      + "été détectée, ni que la couverture soit nulle.") + '</div>';
    return;
  }
  const detections = rep.detections || [];
  if (!detections.length) { b.innerHTML = '<div class="muted">aucune technique détectée (les alertes taguées MITRE apparaîtront ici)</div>'; return; }
  b.innerHTML = detections.map(d => {
    const nm = mitreName(d.mitre);
    return `<div class="kv"><span><span class="mitrechip mitrepivot" data-m="${esc(d.mitre)}" title="Voir les alertes ${esc(d.mitre)}">${esc(d.mitre)}</span>${nm ? ` <span class="muted">— ${esc(nm)}</span>` : ''}</span>` +
    `<b title="1re détection ${fmtTs(d.first_ts)}">${d.count} détection(s) <span class="muted">· depuis ${fmtTs(d.first_ts)}</span></b></div>`;
  }).join('');
  b.querySelectorAll('.mitrepivot').forEach(el => el.onclick = () => setAlertMitreFilter(el.dataset.m));
}

// `P11.20-j` — LE DERNIER DÉPLI ÉCRIT À LA MAIN DANS LA CONSOLE, RALLIÉ AU DÉPLI PARTAGÉ.
//
// CE QUE LE CONSTAT DE LA CLÉ DISAIT, ET CE QUE LA MESURE DU 2026-08-29 EN RÉFUTE. Il annonçait UN bouton
// (`#rule-collapse`) câblé DEUX fois, aux lignes 350 et 532. C'est faux : `#rule-collapse` n'apparaît
// qu'UNE seule fois dans ce module (et une fois dans `index.html`). Le second site pilotait
// `#parser-collapse` — un AUTRE bouton, un AUTRE panneau (`#parser-list`), une AUTRE clé de stockage
// (`soc_parser_open`). Ce n'était donc pas un double câblage (qui serait un bug : deux gestionnaires se
// contredisant sur un même bouton) mais un PATRON RECOPIÉ sur deux panneaux — moins grave, et qui se
// corrige autrement : en retirant le patron, pas en dédoublonnant un câblage.
//
// LE PRIX RÉEL, MESURÉ PLUTÔT QUE SUPPOSÉ. La question posée était « le bouton annonce-t-il son état à
// l'assistance technique ? ». La réponse est OUI, et elle l'était déjà : les deux `apply()` posaient
// `aria-expanded` à chaque bascule, et `index.html` le porte au repos sur les deux boutons. Le défaut
// d'accessibilité que la clé laissait craindre N'EXISTAIT PAS. Ce qui manquait vraiment est plus petit et
// se mesure : `aria-controls`. `disclosure` le pose depuis le panneau (`core.js`), la version écrite à la
// main non — `index.html` n'en porte aucun. Les deux boutons ne nommaient donc pas la région qu'ils
// commandent.
//
// POURQUOI LE RALLIEMENT EST SÛR ICI, ET LES DEUX OBSTACLES QUI ONT ÉTÉ VÉRIFIÉS AVANT :
//   * `disclosure` juge l'ouverture sur `!panel.hidden && !panel.classList.contains('hidden')`. Mesuré :
//     ni `#rule-list` ni `#parser-list` ne portent la classe `hidden` dans `index.html` — le verdict par
//     défaut est donc juste, et aucun `isOpen` sur mesure n'est nécessaire.
//   * `disclosure` pose `.on` sur le bouton. Mesuré sur la feuille : AUCUNE règle ne vise `.picon.on` (les
//     règles `.on` sont toutes portées par un ancêtre : `.sidebar a`, `.subtab`, `.agseg`, `.srctoggle`,
//     `.evnum`, `.plmore`). La marque est donc inerte visuellement sur ces deux boutons : elle ajoute un
//     état lisible par le programme sans rien changer à l'écran.
// Le chevron, lui, reste peint ici : `disclosure` ne connaît pas d'icône, et c'est le seul signal d'état
// que ces boutons donnent à l'œil.
//
// UN GAIN QUI N'ÉTAIT PAS DEMANDÉ, ET QU'IL FAUT DIRE. L'ordre a changé : l'ancien clic ÉCRIVAIT dans le
// stockage AVANT de repeindre, si bien qu'un navigateur refusant le stockage jetait et le panneau ne
// bougeait pas du tout. Ici l'état visible est posé d'abord, la persistance ensuite : un stockage refusé
// coûte la MÉMOIRE du pli, plus le pli lui-même.
//
// CE QUE CE RALLIEMENT NE TIENT PAS : `disclosure` installe un observateur qui resynchronise le bouton si
// le panneau est replié AILLEURS. Mesuré : rien d'autre dans `web/` n'écrit `hidden` sur ces deux
// panneaux — l'observateur garde donc une porte que personne n'ouvre aujourd'hui, et le chevron, lui,
// n'est pas repeint par lui (il ne l'était pas davantage avant).
function deplierUnPanneauPersiste(bouton, liste, cle) {
  if (!bouton || !liste) return;
  const peindreLeChevron = () => { bouton.innerHTML = ic(liste.hidden ? 'chevright' : 'chevdown'); };
  // `P4.13-a` (reprise) — LECTURE FAITE À L'ÉVALUATION DU MODULE, donc gardée : un navigateur qui refuse
  // le stockage de site JETTE à l'ACCÈS, et le graphe ES entier cessait de se lier (mesuré par le
  // sous-banc « stockage refusé » de `web_esm_harnais.mjs`). Refus -> `null` -> le panneau s'ouvre, ce
  // qui est déjà le défaut d'une première visite.
  liste.hidden = lireLeStockageDuSite(cle) === '0';
  const persister = v => { try { localStorage.setItem(cle, v); } catch (e) {} };
  disclosure(bouton, liste, {
    open: () => { liste.hidden = false; peindreLeChevron(); persister('1'); },
    close: () => { liste.hidden = true; peindreLeChevron(); persister('0'); },
  });
  peindreLeChevron();
}

// --- page admin : règles de détection (P4) ---
const RF = { name: '#rf-name', query: '#rf-query', issoql: '#rf-issoql', op: '#rf-op', threshold: '#rf-threshold', sev: '#rf-sev', interval: '#rf-interval', window: '#rf-window', enabled: '#rf-enabled', mitre: '#rf-mitre', compliance: '#rf-compliance' };
// #38 : un tag de conformité = `cadre[:contrôle]`, virgules ; cadre ∈ vocab (le serveur tranche/valide).
// Hint client indicatif : signale un format grossièrement invalide sans dupliquer le vocab (source = serveur).
const COMPLIANCE_ENTRY_RE = /^[a-z0-9_]+(:[A-Za-z0-9._\-/() ]+)?$/;
function refreshComplianceHint() {
  const inp = $(RF.compliance), hint = $('#rf-compliance-hint'); if (!inp || !hint) return;
  const v = (inp.value || '').trim();
  if (!v) { hint.textContent = ''; hint.className = 'rf-hint'; return; }
  const parts = v.split(',').map(s => s.trim()).filter(Boolean);
  const bad = parts.filter(p => !COMPLIANCE_ENTRY_RE.test(p));
  if (bad.length) { hint.textContent = 'format attendu : cadre[:contrôle] séparés par des virgules (ex pci_dss:8.7,hipaa:164.312)'; hint.className = 'rf-hint bad'; return; }
  hint.textContent = 'couverture (posture) : ' + parts.join(', ') + ' — le serveur valide le vocabulaire des cadres'; hint.className = 'rf-hint ok';
}
if ($('#rf-compliance')) $('#rf-compliance').addEventListener('input', refreshComplianceHint);
// PURPLE — technique MITRE ATT&CK : T + 4 chiffres, sous-technique optionnelle .yyy (ex T1110 / T1190.001)
const MITRE_RE = /^T\d{4}(\.\d{3})?$/;
function normMitre(s) { return (s || '').trim().toUpperCase(); }
// hint live sous le champ MITRE : vide -> rien ; valide -> reconnu ; invalide -> format attendu
function refreshMitreHint() {
  const inp = $(RF.mitre), hint = $('#rf-mitre-hint'); if (!inp || !hint) return;
  const v = normMitre(inp.value);
  if (!v) { hint.textContent = ''; hint.className = 'rf-hint'; return; }
  const ok = MITRE_RE.test(v);
  hint.textContent = ok ? 'technique reconnue : ' + v : 'format attendu : Txxxx ou Txxxx.yyy (ex T1110)';
  hint.className = 'rf-hint ' + (ok ? 'ok' : 'bad');
}
if ($(RF.mitre)) $(RF.mitre).addEventListener('input', refreshMitreHint);
/* state: editingRule -> S (state.js) */
/* state: ruleSort -> S (state.js) */
// P11.12-a — CE QU'UNE RÈGLE OFFRE À LA RECHERCHE : ce qu'un analyste connaît d'elle. Son NOM, sa REQUÊTE
// (« où est la règle qui compte les échecs SSH ? » se répond par le texte de la requête, pas par le nom),
// et la TECHNIQUE couverte — son identifiant ET son nom, parce que « brute force » est ce qu'on retient,
// pas « T1110 ». Rien d'autre : la gravité a déjà son tri et son groupement, les y remettre ferait
// remonter tout le catalogue sur le mot « high ».
// La sous-technique tombe d'elle-même : chercher « T1110 » trouve la règle taguée « T1110.003 », par
// inclusion de chaîne — c'est aussi ce qui fait qu'une cellule de la matrice ATT&CK (`P11.6-b`), dont
// l'identifiant est la technique PARENTE, ouvre bien les règles qui la couvrent.
function texteCherchableDUneRegle(r) {
  return texteCherchable([r && r.name, r && r.query, r && r.mitre, mitreName((r && r.mitre) || '')]);
}
// La recherche courante du panneau. Remplacée au câblage du champ ; sans champ dans le document (test,
// rendu partiel), elle vaut la chaîne vide et la liste rend exactement comme avant.
let rechercheDesRegles = () => '';
// L'autre bout de la même poignée : POSER la recherche depuis ailleurs. Une surface qui sait déjà quelle
// règle intéresse l'analyste (une cellule de la matrice ATT&CK, un chip de technique) ouvre ce panneau
// SUR ce critère au lieu de le laisser recommencer. Exportée pour cela, et pour que le harnais juge la
// composition du tri et de la recherche par le même chemin que l'interface.
let poserLaRechercheDesRegles = () => {};
// Dernier catalogue servi par `/api/rules`. La frappe REDESSINE, elle ne recharge pas : filtrer est une
// comparaison de chaînes sur des lignes déjà en mémoire, et une requête HTTP par caractère serait un coût
// réseau pour un travail local (même partage `charger`/`rendre` que le panneau des indicateurs).
let reglesChargees = [];
// P11.5-d — CE QU'UNE MODIFICATION D'OVERLAY NE DIT PAS D'ELLE-MÊME, DIT PAR LE SERVEUR. Cette console
// portait sa PROPRE copie française de la phrase ; les deux avaient déjà divergé, et c'est la copie d'ici
// qui affirmait « Seule la bascule actif/inactif survit » alors que la case du formulaire, elle, ne
// survivait pas. `/api/rules` la sert désormais UNE fois pour toute la liste, dérivée côté serveur des
// colonnes que la réimposition écrase réellement — il n'y a plus qu'un seul endroit où elle s'écrit.
let avertissementOverlayRegle = '';
// P11.14-a — UN PANNEAU VIDE DISAIT « AUCUNE RÈGLE » ALORS QU'IL N'AVAIT RIEN PU LIRE. Le chargement
// avalait son erreur (`catch { return; }`) et sortait SANS TOUCHER À `#rule-list` : la div reste celle
// d'`index.html`, c'est-à-dire vide, et rien ne distingue « le serveur n'a pas répondu » de « il n'y a
// pas de règle ». Pour un outil de sécurité c'est le pire malentendu : l'exploitant a cru ses règles
// perdues. `fetchInto` (core) est le mécanisme PARTAGÉ créé pour exactement ce motif — il écrit la cause
// DANS l'hôte et rend `null` — et quatre panneaux de ce module le contournaient de la même façon.
async function loadRules() {
  const wrap = $('#rule-list'); if (!wrap) return;
  const d = await fetchInto(wrap, '/rules'); if (!d) return;
  reglesChargees = d.rules || [];
  avertissementOverlayRegle = d.avertissement_overlay || '';
  renderRules();
}
function renderRules() {
  const wrap = $('#rule-list'); if (!wrap) return;
  const rules = reglesChargees.slice();
  if (S.ruleSort === 'sev') rules.sort((a, b) => b.severity - a.severity || a.id - b.id);
  wrap.replaceChildren();
  const note = takePendingNote('rules'); if (note) wrap.appendChild(note); // P11.1-e : où arrive ce qui vient d'être créé
  if (!rules.length) { wrap.appendChild(muted('aucune règle - clique " + Nouvelle règle "')); return; }
  // P11.12-a — RECHERCHE ACTIVE : liste de RÉSULTATS, plate, dans l'ordre du sélecteur de tri.
  // POURQUOI PLATE ET NON GROUPÉE. Le groupement par gravité est REPLIABLE et son pliage est PERSISTÉ
  // (`soc_rule_collapsed`) : une correspondance tombée dans une section repliée serait invisible, et
  // forcer l'ouverture pendant la recherche écraserait le pliage choisi par l'exploitant dès le premier
  // clic. Une recherche répond par ses résultats ; le classement par gravité revient dès qu'elle est vidée.
  // Le tri, lui, n'est PAS remplacé : il s'applique avant le filtre et ordonne les résultats.
  const requete = rechercheDesRegles();
  if (requete) {
    const trouvees = filtrerParRecherche(rules, requete, texteCherchableDUneRegle);
    wrap.appendChild(resumeDeRecherche(trouvees.length, rules.length, {
      filtre: document.createTextNode('règle(s) — la recherche cache le reste ; le tri reste celui du sélecteur'),
      vide: document.createTextNode('Aucune règle ne porte ces mots dans son nom, sa requête ou sa technique ATT&CK. Échap efface la recherche.'),
    }));
    if (!trouvees.length) return;
    const host = document.createElement('div');
    pagedList(host, { mode: 'client', pageSize: 50, rows: trouvees, renderRow: ruleRow });
    wrap.appendChild(host);
    return;
  }
  // `P11.15-b` — LE REGROUPEMENT VIENT DE LA FABRIQUE, ET SA CLÉ EST DÉRIVÉE. Ce panneau écrivait sa
  // propre partition par gravité : la boucle, la `Map`, la clé de pliage, la pastille et le libellé. La
  // fabrique partagée mesure ce que les LIGNES portent — une règle porte `severity`, donc elle se groupe
  // par gravité, exactement comme avant, sans qu'un mot le lui dise. Elle porte aussi `mitre`, donc la
  // technique ATT&CK devient un second axe offert, sans qu'une ligne lui soit écrite ici.
  // CE QUI CHANGE VRAIMENT : chacun des groupes construisait sa page de lignes MÊME REPLIÉ ; la feuille les
  // masquait ensuite. Le corps d'un groupe replié n'est plus bâti du tout.
  const host = document.createElement('div');
  pagedList(host, { mode: 'client', pageSize: 50, rows: rules, renderRow: ruleRow, group: { storeKey: 'soc_rule_collapsed' } });
  wrap.appendChild(host);
}
// P11.12-a — UNE RÈGLE QU'ON VIENT D'ENREGISTRER DOIT SE VOIR. Une recherche active n'a aucune raison de
// contenir la règle qu'on vient d'écrire : le geste réussirait et la liste n'en montrerait rien — un succès
// invisible, la famille de défauts que cette campagne poursuit. La recherche est donc VIDÉE au retour d'un
// enregistrement (et d'elle seule : supprimer depuis une recherche la conserve, on est en train de faire le
// ménage dans un sous-ensemble). Le classement par gravité revient, la règle est là où on l'attend.
function apresEnregistrementDUneRegle() {
  poserLaRechercheDesRegles('');
  return loadRules();
}
// Modèle de ligne d'une règle (forme UNIQUE partagée avec playbooks/runbooks — `producer_ui.js`).
// Conséquence de l'interrupteur : lever des alertes (ou du risque) ; pas de confirmation (rien ne touche le
// réseau). Bascule ADMIN-only via /enabled (audité, persistant — overlays config.d compris) ; un non-admin voit
// la case en lecture seule, le serveur re-gate (403).
function ruleRowModel(r) {
  const dest = DESTINATIONS[detectionDestination(r.risk_score)];
  const chips = [];
  // tag MITRE ATT&CK (purple) : technique que la règle DÉTECTE — clé de jointure avec Forge (red).
  if (r.mitre) { const mt = document.createElement('span'); mt.className = 'mitrechip'; mt.textContent = r.mitre; const _mn = mitreName(r.mitre); mt.title = (_mn ? r.mitre + ' — ' + _mn + ' · ' : '') + 'technique MITRE ATT&CK détectée par cette règle'; chips.push(mt); }
  // #38 : cadres de conformité couverts (posture/couverture, pas certification) — un chip par cadre distinct.
  if (r.compliance) {
    const seen = new Set();
    r.compliance.split(',').map(s => s.trim()).filter(Boolean).forEach(p => {
      const fw = p.split(':')[0]; if (!fw || seen.has(fw)) return; seen.add(fw);
      const c = document.createElement('span'); c.className = 'mitrechip'; c.textContent = fw.toUpperCase();
      c.title = 'cadre de conformité couvert : ' + r.compliance + ' (posture / couverture — pas une certification)';
      chips.push(c);
    });
  }
  return {
    family: 'rule', extraClass: 'sev-' + r.severity, name: r.name, origin: r.managed, chips,
    enabled: !!r.enabled,
    consequence: (Number(r.risk_score) > 0 ? 'ajoute ' + r.risk_score + ' au score de risque des entités (' : 'lève une alerte ' + sev(r.severity) + ' (') + dest.label + ') à chaque évaluation où le seuil est franchi',
    toggleAllowed: socIsAdmin(), toggleDeniedReason: "l'activation/désactivation d'une règle est réservée à l'administrateur",
    confirmOnEnable: false,
    onToggle: next => apiSend('/rules/' + r.id + '/enabled', 'POST', { enabled: next }),
    summary: `${r.op} ${r.threshold}`, summaryTitle: `${r.is_soql ? 'GXQL' : 'SQL'} : ${r.query}`,
    meta: `${sev(r.severity)} - ${r.last_value == null ? 'pas encore évaluée' : 'dernier ' + r.last_value}${r.last_fired ? ' - ' + fmtTs(r.last_fired) : ''}`,
  };
}
function ruleRow(r) {
  const m = ruleRowModel(r);
  const row = producerRow(m);
  const meta = row.metaEl;
  const test = rowButton('Tester', { title: 'Évalue la requête maintenant, sans lever d\'alerte', onClick: async () => {
    meta.textContent = '...';
    const j = await apiSend('/rules/' + r.id + '/test');
    meta.textContent = j.error ? ('erreur : ' + j.error) : `test : ${j.value} -> ${j.fired ? 'déclenche' : 'ok'}`;
    meta.title = j.sql || '';
  } });
  // MIROIR UX : éditer une règle BASELINE (seed/builtin managed=0) est réservé admin (le serveur 403 sinon) —
  // bouton grisé pour un non-admin plutôt qu'une action qui échoue. Overlay (1) et perso (2) restent éditables.
  const baselineLocked = !socIsAdmin() && r.managed === 0;
  const edit = rowButton('Éditer', { cls: 'crud-btn', disabled: baselineLocked, title: baselineLocked ? 'détection baseline (seed/builtin) : édition réservée à l\'administrateur ; créez plutôt votre propre règle' : '', onClick: baselineLocked ? null : () => openRuleForm(r) });
  const del = rowButton('', { cls: 'crud-btn', icon: ic('x'), title: 'Supprimer' });
  if (gateDeleteBtn(del, r.managed)) del.onclick = async () => { if (await confirmModal('Supprimer la règle "' + r.name + '" ?', { danger: true })) { if (await contentDelete('/rules/' + r.id, 'règle')) loadRules(); } };
  row.append(test, edit, del);
  return row;
}
// P11.14-a — LE FORMULAIRE DE RÈGLE EST UN ÉLÉMENT DE LA PAGE, PAS LE CONTENU D'UNE MODALE JETABLE.
// Il est écrit dans `index.html`, à l'intérieur de la section « Règles de détection ». La présentation
// en modale le DÉPLAÇAIT à demeure dans un calque `.modal-ov` fabriqué une seule fois — et `closeModals()`
// (core) retire du document TOUS les `.modal-ov`. Or toute ouverture de modale de la console commence par
// là (`modal()` l'appelle en premier : confirmation de suppression, menu d'une cellule ATT&CK, lien de
// retour d'un import Sigma). Le formulaire partait avec le calque : `$('#rule-form')` valait `null`,
// « + Nouvelle règle » levait une TypeError et ne faisait plus rien, et SEUL un rechargement de la page
// rendait le balisage — ce qui se lit comme une perte.
// LE CALQUE EST DONC JETABLE, LE FORMULAIRE NON : refait à chaque ouverture, défait à chaque fermeture, et
// le formulaire est REMIS DANS SA SECTION avant chaque ouverture comme après chaque fermeture. Le module
// garde la référence de l'élément et de sa section : même si un `closeModals()` étranger détache le calque
// pendant que la modale est ouverte, l'élément est retrouvé et réancré au geste suivant, sans rechargement.
const FORMULAIRE_DE_REGLE = $('#rule-form');
const SECTION_DES_REGLES = FORMULAIRE_DE_REGLE && FORMULAIRE_DE_REGLE.parentNode;
let calqueDuFormulaireDeRegle = null;   // le calque, tant que la modale est ouverte ; null sinon
// Remet le formulaire là où `index.html` le pose (dans sa section, avant la liste), et lui rend les classes
// qu'il y porte. Idempotent : s'il y est déjà, rien ne bouge.
function rendreLeFormulaireASaSection() {
  const form = FORMULAIRE_DE_REGLE; if (!form) return null;
  form.classList.remove('rulemodal'); form.classList.add('hidden');
  const hote = SECTION_DES_REGLES;
  if (hote && form.parentNode !== hote) {
    const liste = $('#rule-list');
    if (liste && liste.parentNode === hote) hote.insertBefore(form, liste); else hote.appendChild(form);
  }
  return form;
}
// Échap ferme la modale — posé UNE fois sur le document, sur l'état du module et non sur un calque donné
// (le calque, lui, est refait à chaque ouverture ; un écouteur par ouverture en laisserait un par geste).
document.addEventListener('keydown', e => { if (e.key === 'Escape' && calqueDuFormulaireDeRegle) closeRuleForm(); });
function openRuleForm(r) {
  S.editingRule = r ? r.id : null;
  const form = rendreLeFormulaireASaSection();   // réancre : le calque de l'ouverture précédente a pu être retiré
  if (!form) return;
  // présenter en MODAL (overlay centré) au lieu d'un formulaire inline constant
  if (form.parentNode) {
    const ov = document.createElement('div'); ov.id = 'rule-form-ov'; ov.className = 'modal-ov';
    ov.addEventListener('click', e => { if (e.target === ov) closeRuleForm(); });
    form.parentNode.insertBefore(ov, form); ov.appendChild(form);
    ov.style.display = 'flex';
    calqueDuFormulaireDeRegle = ov;
  }
  form.classList.remove('hidden'); form.classList.add('rulemodal');
  $(RF.name).value = r ? r.name : '';
  $(RF.query).value = r ? r.query : '';
  $(RF.issoql).value = r ? (r.is_soql ? '1' : '0') : '1';
  if (!socIsAdmin()) $(RF.issoql).value = '1'; // SQL brut = admin only (toggle masqué côté non-admin)
  $(RF.op).value = r ? r.op : '>';
  $(RF.threshold).value = r ? r.threshold : 0;
  $(RF.sev).value = r ? r.severity : 2;
  $(RF.interval).value = r ? r.interval_s : 300;
  $(RF.window).value = r ? r.window_s : 3600;
  $(RF.enabled).checked = r ? r.enabled : true;
  if ($(RF.mitre)) $(RF.mitre).value = r ? (r.mitre || '') : '';
  if ($(RF.compliance)) $(RF.compliance).value = r ? (r.compliance || '') : '';
  refreshMitreHint();
  refreshComplianceHint();
  // P11.1-e : la destination est dite AVANT d'enregistrer (le span de résultat porte le lien).
  const res = $('#rf-result'); if (res) { res.className = 'muted'; res.replaceChildren(destinationNote(detectionDestination(r && r.risk_score), '', 'dès la première évaluation (Intervalle)')); }
  // P11.5-c : DIT AVANT L'ÉDITION, pas après. Une règle d'overlay config.d se modifie ici (le serveur
  // accepte, 200) mais le fichier versionné réimpose au prochain démarrage les champs qu'il porte — un
  // succès partiel qui se défait tout seul, que rien n'annonçait. P11.5-d : la phrase vient du serveur
  // (`/api/rules`), qui la DÉRIVE de ce que la réimposition écrase vraiment ; il la redit à l'identique
  // dans la réponse d'une modification acceptée (`avertissement`).
  if (res && r && Number(r.managed) === 1 && avertissementOverlayRegle) {
    const av = document.createElement('div');
    av.textContent = avertissementOverlayRegle;
    res.appendChild(av);
  }
  $(RF.name).focus();
}
// P11.6-b — CE PANNEAU EST LA DESTINATION DES PORTES DE LA MATRICE ATT&CK. Lui seul sait ouvrir sa
// recherche et son formulaire ; il les POSE sur la matrice au chargement plutôt que d'être importé par
// elle (l'import inverse existe déjà, le refermer ferait un cycle).
// Ouvrir les règles d'une technique = poser la recherche partagée sur son identifiant : c'est le même
// chemin que la frappe d'un analyste, donc rien de neuf à maintenir, et l'inclusion de chaîne y retrouve
// les règles taguées par une sous-technique de celle-ci.
function ouvrirLesReglesDeLaTechnique(tid) {
  location.hash = 'detection';
  poserLaRechercheDesRegles(tid || '');
}
// Créer la règle qui couvrira une technique : le formulaire de création ordinaire, la technique déjà
// renseignée (et son indice de format rafraîchi, comme après une frappe).
function ouvrirLaCreationPourLaTechnique(tid) {
  location.hash = 'detection';
  openRuleForm(null);
  if ($(RF.mitre)) { $(RF.mitre).value = normMitre(tid); refreshMitreHint(); }
}
poserLesPortesDeTechnique({ regles: ouvrirLesReglesDeLaTechnique, creer: ouvrirLaCreationPourLaTechnique });

function closeRuleForm() {
  rendreLeFormulaireASaSection();                  // le formulaire rentre chez lui AVANT que le calque parte
  const ov = calqueDuFormulaireDeRegle; calqueDuFormulaireDeRegle = null;
  if (ov && ov.parentNode) ov.remove();            // rien de jetable ne survit à la fermeture
}
if ($('#rule-new')) $('#rule-new').onclick = () => openRuleForm(null);
if ($('#rf-cancel')) $('#rf-cancel').onclick = closeRuleForm;
if ($('#rf-test')) $('#rf-test').onclick = async () => {
  const q = $(RF.query).value.trim(), res = $('#rf-result');
  if (!q) { res.textContent = "écris une requête d'abord"; return; }
  res.textContent = '...';
  const body = { query: q, is_soql: $(RF.issoql).value === '1', op: $(RF.op).value, threshold: Number($(RF.threshold).value) || 0, window_s: Number($(RF.window).value) || 3600 };
  try {
    const j = await apiSend('/rule-test', 'POST', body);
    res.textContent = j.error ? ('' + j.error) : `valeur = ${j.value} -> ${j.fired ? 'déclencherait' : 'ne déclenche pas (seuil non franchi)'}`;
    res.title = j.sql || '';
  } catch (e) { res.textContent = '' + e.message; }
};
if ($('#rule-form')) $('#rule-form').addEventListener('submit', async e => {
  e.preventDefault();
  // normalise le tag MITRE (trim+upper) ; vide autorisé ; sinon doit matcher Txxxx[.yyy]
  const mitre = $(RF.mitre) ? normMitre($(RF.mitre).value) : '';
  if (mitre && !MITRE_RE.test(mitre)) { formMsg('#rf-result', 'MITRE invalide : format attendu Txxxx[.yyy] (ex T1110)', true); toast('MITRE invalide : format attendu Txxxx[.yyy] (ex T1110)', 'bad'); return; }
  const body = {
    name: $(RF.name).value.trim() || 'Règle',
    query: $(RF.query).value.trim(),
    // SQL brut réservé admin (garde-fou #2) : un non-admin envoie toujours GXQL (le serveur 403 sinon).
    is_soql: socIsAdmin() ? ($(RF.issoql).value === '1') : true,
    op: $(RF.op).value,
    threshold: Number($(RF.threshold).value) || 0,
    severity: Number($(RF.sev).value),
    interval_s: Number($(RF.interval).value) || 300,
    window_s: Number($(RF.window).value) || 3600,
    enabled: $(RF.enabled).checked,
    mitre,
    // #38 : tags de conformité (cadre[:contrôle], CSV) — le serveur normalise/valide le vocabulaire des cadres.
    compliance: $(RF.compliance) ? $(RF.compliance).value.trim() : '',
  };
  if (!body.query) { formMsg('#rf-result', 'Écris une requête (qui renvoie un nombre).', true); toast('Écris une requête (qui renvoie un nombre).', 'bad'); return; }
  // garde-fou #1 : le serveur VALIDE (GXQL compile / MITRE / …). Sur erreur -> {error} affiché, MODALE OUVERTE.
  if (!await contentSubmit(S.editingRule ? '/rules/' + S.editingRule : '/rules', body, '#rf-result')) return;
  closeRuleForm();
  announceCreated('rules', 'alerts', body.name, body.enabled ? 'première évaluation dans ' + body.interval_s + ' s' : 'OFF : activez-la dans la liste'); // P11.1-e
  apresEnregistrementDUneRegle();
  renderCoverage(); // re-render la couverture après création/édition (le tag MITRE peut avoir changé)
});
loadRules();
renderCoverage();
// Import Sigma en masse (admin) : câble le bouton « Importer un ruleset Sigma » + rafraîchisseur post-import
// (recharge la liste des règles, la couverture et la matrice ATT&CK -> la boucle « fermer les angles morts »).
initSigmaImport({ onImported: () => { loadRules(); renderCoverage(); loadAttackMatrix(); } });
// tri + pliage du panneau Règles (persistés)
(() => {
  const sortSel = $('#rule-sort'), collapse = $('#rule-collapse'), list = $('#rule-list');
  // P11.12-a : le champ de recherche partagé. Il REDESSINE (pas de rechargement) et se compose avec le tri.
  const champ = $('#rule-search');
  if (champ) { const poignee = champDeRecherche(champ, { auChangement: () => renderRules() }); rechercheDesRegles = poignee.valeur; poserLaRechercheDesRegles = poignee.poser; }
  // `P4.13-b` — LE TRI S'APPLIQUE, LA PERSISTANCE EST SEULEMENT TENTÉE, ET SON REFUS SE DIT. Nue,
  // l'écriture jetait `SecurityError` ENTRE la pose de `S.ruleSort` et `renderRules()` : mesuré le
  // 2026-08-30 sous `PLUME_HARNAIS_STOCKAGE_REFUSE=1`, `S.ruleSort` passait bien de `id` à `sev` mais
  // `#rule-list` n'était JAMAIS repeinte — le sélecteur annonçait « Sévérité ↓ » au-dessus d'une liste
  // restée dans l'ordre des identifiants. Le tri, lui, vit dans `S` : il s'applique donc sans stockage,
  // et seule sa mémoire d'un chargement à l'autre est perdue. L'avis vient EN DERNIER pour qu'il ne
  // s'interpose pas dans la chaîne, et il est dit parce qu'une capture vide ferait croire le choix retenu.
  if (sortSel) { sortSel.value = S.ruleSort; sortSel.onchange = () => { S.ruleSort = sortSel.value; const retenu = ecrireDansLeStockageDuSite('soc_rule_sort', S.ruleSort); renderRules(); if (!retenu) toast(LANG === 'en' ? 'Rule sort applied for this session only: this browser refuses site storage, so it will not be kept on the next load.' : "Tri des règles appliqué pour cette session seulement : ce navigateur refuse le stockage de site, il ne sera pas retenu au prochain chargement.", 'info', 5000); }; }
  deplierUnPanneauPersiste(collapse, list, 'soc_rule_open');
})();

// --- notifications multi-canal ---
const NFK = { name: '#nf-name', kind: '#nf-kind', url: '#nf-url', sev: '#nf-sev', config: '#nf-config', enabled: '#nf-enabled' };
/* state: editingNotif -> S (state.js) */
async function loadNotifiers() {
  const wrap = $('#notif-list'); if (!wrap) return;
  // /api/notifiers est désormais admin-only (le token/mdp du canal n'est plus exposé). Un non-admin reçoit
  // 403 {error} -> la cause est ÉCRITE dans le panneau (P11.14-a) et la liste n'est pas remplacée par
  // `undefined` ; un refus ne se lit plus comme « aucun canal ».
  const d = await fetchInto(wrap, '/notifiers'); if (!d) return;
  const notifiers = Array.isArray(d.notifiers) ? d.notifiers : [];
  wrap.replaceChildren();
  if (!notifiers.length) { wrap.appendChild(muted('aucun canal - les alertes ne sont envoyées nulle part. Clique " + Nouveau canal ".')); return; }
  notifiers.forEach(n => wrap.appendChild(notifRow(n)));
}
function notifRow(n) {
  const row = document.createElement('div'); row.className = 'rulerow';
  // COMMUTATEUR PARTAGÉ (`P11.13-c`) : ce que la bascule arme, c'est un ENVOI SORTANT à chaque alerte ; la
  // case nue ne disait ni le canal ni le seuil. `enabledSwitch` l'écrit à côté de l'interrupteur, dans les
  // deux états, et rétablit la case si le serveur refuse.
  const en = enabledSwitch({
    enabled: !!n.enabled, name: n.name, allowed: true, confirmOnEnable: false,
    consequence: 'chaque alerte de sévérité ' + sev(n.min_severity) + ' ou plus part vers ' + n.kind + (n.url ? ' (' + n.url + ')' : '') + ' ; OFF, plus aucune notification ne sort par ce canal',
    onToggle: (next) => apiSend('/notifiers/' + n.id, 'POST', { enabled: next }),
  });
  const name = document.createElement('span'); name.className = 'rulename'; name.textContent = n.name;
  const kind = document.createElement('code'); kind.className = 'rulecond'; kind.textContent = `${n.kind} >= ${sev(n.min_severity)}`;
  const meta = document.createElement('span'); meta.className = 'rulemeta muted'; meta.textContent = n.url || '(pas d\'URL)';
  // has_auth (miroir du has_secret des connecteurs) : le token/mdp n'est JAMAIS renvoyé -> simple indicateur.
  const auth = document.createElement('span'); auth.className = 'rulemeta muted';
  auth.textContent = n.has_auth ? '• auth' : '';
  if (n.has_auth) auth.title = 'credential enregistré (token ntfy / user:pass SMTP) — jamais réaffiché';
  const test = document.createElement('button'); test.textContent = 'Tester';
  test.onclick = async () => { meta.textContent = '...'; const j = await apiSend('/notifiers/' + n.id + '/test'); meta.textContent = j.ok ? 'envoyé' : 'échec (vérifie URL / curl / config)'; };
  const edit = document.createElement('button'); edit.textContent = 'Éditer'; edit.onclick = () => openNotifForm(n);
  const del = document.createElement('button'); del.innerHTML = ic('x'); del.onclick = async () => { if (await confirmModal('Supprimer le canal "' + n.name + '" ?', { danger: true })) { await apiSend('/notifiers/' + n.id, 'DELETE'); loadNotifiers(); } };
  row.append(en, name, kind, meta, auth, test, edit, del);
  return row;
}
function openNotifForm(n) {
  S.editingNotif = n ? n.id : null;
  $('#notif-form').classList.remove('hidden');
  $(NFK.name).value = n ? n.name : '';
  $(NFK.kind).value = n ? n.kind : 'ntfy';
  $(NFK.url).value = n ? n.url : '';
  $(NFK.sev).value = n ? n.min_severity : 2;
  // Le blob `config` (token ntfy / user:pass SMTP) n'est JAMAIS renvoyé par l'API (has_auth booléen seul).
  // À l'ÉDITION : champ vide -> laisser vide CONSERVE le credential existant ; saisir un JSON complet le REMPLACE.
  $(NFK.config).value = '';
  const cfgEl = $(NFK.config);
  if (cfgEl) cfgEl.placeholder = n
    ? (n.has_auth
        ? 'credential enregistré — laisse vide pour le conserver, ou saisis un JSON complet pour le remplacer'
        : '{"token":"..."} (ntfy) ou {"user":"...","pass":"..."} (SMTP) — aucun credential enregistré')
    : '{"token":"..."} (ntfy) ou {"user":"...","pass":"..."} (SMTP) — optionnel';
  $(NFK.enabled).checked = n ? n.enabled : true;
  $('#nf-result').textContent = '';
  $(NFK.name).focus();
}
if ($('#notif-new')) $('#notif-new').onclick = () => openNotifForm(null);
if ($('#nf-cancel')) $('#nf-cancel').onclick = () => $('#notif-form').classList.add('hidden');
if ($('#notif-form')) $('#notif-form').addEventListener('submit', async e => {
  e.preventDefault();
  const cfgRaw = $(NFK.config).value.trim();
  if (cfgRaw) { try { JSON.parse(cfgRaw); } catch (_) { $('#nf-result').textContent = 'config JSON invalide'; return; } }
  const body = { name: $(NFK.name).value.trim() || 'Canal', kind: $(NFK.kind).value, url: $(NFK.url).value.trim(), min_severity: Number($(NFK.sev).value), enabled: $(NFK.enabled).checked };
  // config (secret) ré-envoyée UNIQUEMENT si (re)saisie -> omise = conserver l'existant côté serveur (comme les connecteurs).
  if (cfgRaw) body.config = cfgRaw;
  await apiSend(S.editingNotif ? '/notifiers/' + S.editingNotif : '/notifiers', 'POST', body);
  $('#notif-form').classList.add('hidden');
  loadNotifiers();
});
loadNotifiers();

// --- parsers (registre modulaire d'extraction de champs à l'ingestion) ---
const PF = { name: '#pf-name', source: '#pf-source', pattern: '#pf-pattern', enabled: '#pf-enabled' };
/* state: editingParser -> S (state.js) */
// ouvre le formulaire parser : p = parser à modifier (édition), null = nouveau. Défauts modifiables, pas supprimables.
function openParserForm(p) {
  S.editingParser = p ? p.id : null;
  $('#parser-form').classList.remove('hidden');
  $(PF.name).value = p ? p.name : '';
  $(PF.source).value = p ? p.source : '*';
  $(PF.pattern).value = p ? p.pattern : '';
  $(PF.enabled).checked = p ? !!p.enabled : true;
  $('#pf-sample').value = ''; $('#pf-result').textContent = ''; $(PF.name).focus();
}
/* state: parserSort -> S (state.js) */
async function loadParsers() {
  const wrap = $('#parser-list'); if (!wrap) return;
  const d = await fetchInto(wrap, '/parsers'); if (!d) return;   // P11.14-a : la cause est écrite dans le panneau
  const parsers = d.parsers || [];
  if (S.parserSort === 'source') parsers.sort((a, b) => (a.source || '').localeCompare(b.source || '') || a.id - b.id);
  wrap.replaceChildren();
  if (!parsers.length) { wrap.appendChild(muted('aucun parser')); return; }
  // `P11.15-b` — MÊME FABRIQUE, MÊME DÉRIVATION : un parseur porte `source`, il se groupe par source. La
  // partition écrite à la main ici était la seconde copie de celle des règles ; le parseur sans source
  // n'est plus rangé sous un libellé écrit sur place, mais sous le groupe « sans source » que la fabrique
  // nomme pour toutes les vues, et il reste compté.
  const host = document.createElement('div');
  // `P11.18-m` — LA RECHERCHE PORTE SUR TOUT LE REGISTRE : `/api/parsers` rend la table entière, sans borne
  // ni pagination. Elle se compose avec le groupement par source — la partition est refaite sur les lignes
  // trouvées — et le texte cherché est celui de la ligne RENDUE (nom, source, motif d'extraction).
  pagedList(host, { mode: 'client', pageSize: 50, rows: parsers, renderRow: parserRow, group: { storeKey: 'soc_parser_collapsed' }, recherche: true });
  wrap.appendChild(host);
}
function parserRow(p) {
  const row = document.createElement('div'); row.className = 'rulerow';
  // #1c-toggle : (dés)activation ADMIN-only via /enabled (audité + persistant pour les overlays config.d).
  // COMMUTATEUR PARTAGÉ (`P11.13-c`) : ce que la bascule arme, c'est l'EXTRACTION DE CHAMPS sur une source ;
  // la case nue ne disait pas quels events perdent leurs champs quand elle retombe. Le refus au lecteur passe
  // par le même commutateur (`allowed` / `deniedReason`), il n'est plus une case grisée sans raison lisible.
  const en = enabledSwitch({
    enabled: !!p.enabled, name: p.name, allowed: socIsAdmin(), confirmOnEnable: false,
    consequence: 'les events de source=' + p.source + ' sont découpés en champs par ce parseur (choix persistant : il survit au reboot, même pour un overlay config.d) ; OFF, ils restent bruts et les recherches sur ces champs ne rendent plus rien',
    onToggle: (next) => apiSend('/parsers/' + p.id + '/enabled', 'POST', { enabled: next }),
  });
  const name = document.createElement('span'); name.className = 'rulename'; name.textContent = p.name + (p.builtin ? ' · défaut' : '');
  const src = document.createElement('code'); src.className = 'rulecond'; src.textContent = 'source=' + p.source;
  const pat = document.createElement('span'); pat.className = 'rulemeta muted'; pat.textContent = p.pattern; pat.title = p.pattern;
  pat.style.cssText = 'overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:44ch';
  name.appendChild(managedBadge(p.managed)); // origine du contenu (builtin/overlay/perso)
  row.append(en, name, src, pat);
  const edit = document.createElement('button'); edit.className = 'crud-btn'; edit.innerHTML = ic('pencil'); edit.title = 'Modifier';
  // MIROIR UX : éditer un parseur BASELINE (seed/builtin managed=0) est réservé admin (403 serveur).
  if (!socIsAdmin() && p.managed === 0) { edit.disabled = true; edit.title = 'parseur baseline (seed/builtin) : édition réservée à l\'administrateur'; }
  else edit.onclick = () => openParserForm(p);
  row.append(edit);
  // delete : managed=2 (perso) UNIQUEMENT ; builtin (managed=0)/overlay (managed=1) -> bouton grisé (se désactivent via la case).
  const del = document.createElement('button'); del.className = 'crud-btn'; del.innerHTML = ic('x'); del.title = 'Supprimer';
  if (gateDeleteBtn(del, p.managed)) del.onclick = async () => { if (await confirmModal('Supprimer le parser "' + p.name + '" ?', { danger: true })) { if (await contentDelete('/parsers/' + p.id, 'parseur')) loadParsers(); } };
  row.append(del);
  return row;
}
if ($('#parser-new')) $('#parser-new').onclick = () => openParserForm(null);
if ($('#pf-cancel')) $('#pf-cancel').onclick = () => $('#parser-form').classList.add('hidden');
if ($('#pf-test')) $('#pf-test').onclick = async () => {
  const res = $('#pf-result'); res.textContent = '...';
  try {
    const j = await apiSend('/parser-test', 'POST', { pattern: $(PF.pattern).value, sample: $('#pf-sample').value });
    res.textContent = j.error ? ('' + j.error) : (j.matched ? ('OK → ' + JSON.stringify(j.fields)) : 'aucune correspondance');
  } catch (e) { res.textContent = '' + e.message; }
};
// rétroactif : dry-run (compte) -> confirmation -> écriture. N'écrase aucun champ déjà présent.
if ($('#parser-reparse')) $('#parser-reparse').onclick = async () => {
  const btn = $('#parser-reparse'); btn.disabled = true; const lbl = btn.textContent; btn.textContent = '↻ calcul…';
  try {
    const d = await apiSend('/parsers/reparse', 'POST', { dry_run: true });
    if (d.error) { toast(d.error, 'bad'); return; }
    if (!d.matched) { toast('Rien à ré-enrichir sur les ' + d.scanned + ' events des 30 derniers jours.'); return; }
    const warn = d.truncated ? ('\n\n⚠ plafonné à ' + d.cap + ' écritures/passe — relance pour finir.') : '';
    if (!await confirmModal('Réappliquer les parsers actifs : ' + d.matched + ' / ' + d.scanned + ' events (30 j) seront ré-enrichis (sans écraser l\'existant).' + warn + '\n\nContinuer ?')) return;
    btn.textContent = '↻ application…';
    const r = await apiSend('/parsers/reparse', 'POST', {});
    if (r.error) { toast(r.error, 'bad'); return; }
    toast(r.updated + ' events mis à jour' + (r.truncated ? ' (plafond atteint, relance pour le reste)' : '') + '.', 'ok');
  } catch (e) { toast('' + e.message, 'bad'); } finally { btn.disabled = false; btn.textContent = lbl; }
};
if ($('#parser-form')) $('#parser-form').addEventListener('submit', async e => {
  e.preventDefault();
  const body = { name: $(PF.name).value.trim() || 'Parser', source: $(PF.source).value.trim() || '*', pattern: $(PF.pattern).value, enabled: $(PF.enabled).checked };
  if (!body.pattern) { formMsg('#pf-result', 'Écris un motif regex (avec des groupes nommés).', true); toast('Écris un motif regex (avec des groupes nommés).', 'bad'); return; }
  // garde-fou #1 : le serveur valide la regex (non vide / ≤1000 / compile). Erreur -> {error} affiché, formulaire OUVERT.
  if (!await contentSubmit(S.editingParser ? '/parsers/' + S.editingParser : '/parsers', body, '#pf-result')) return;
  S.editingParser = null;
  $('#parser-form').classList.add('hidden'); loadParsers();
});
loadParsers();
// tri + pliage du panneau Parsers (persistés)
(() => {
  const sortSel = $('#parser-sort'), collapse = $('#parser-collapse'), list = $('#parser-list');
  // `P4.13-b` — MÊME GESTE, MÊME MESURE QUE POUR LES RÈGLES (voir le bloc du tri des règles) : sous refus
  // de stockage, `S.parserSort` passait de `default` à `source` et `loadParsers()` n'était jamais appelée,
  // donc `#parser-list` gardait l'ordre précédent sous un sélecteur qui annonçait l'autre.
  if (sortSel) { sortSel.value = S.parserSort; sortSel.onchange = () => { S.parserSort = sortSel.value; const retenu = ecrireDansLeStockageDuSite('soc_parser_sort', S.parserSort); loadParsers(); if (!retenu) toast(LANG === 'en' ? 'Parser sort applied for this session only: this browser refuses site storage, so it will not be kept on the next load.' : 'Tri des parsers appliqué pour cette session seulement : ce navigateur refuse le stockage de site, il ne sera pas retenu au prochain chargement.', 'info', 5000); }; }
  deplierUnPanneauPersiste(collapse, list, 'soc_parser_open');
})();

// --- moteur de réponse () ---
// `P11.18-h` — CE QU'UNE ACTION OFFRE À LA RECHERCHE, LU SUR LA LIGNE ET NON DÉCIDÉ POUR CETTE VUE. Ce que
// `actionRow` rend est exactement ce qui se cherche : le GESTE et sa CIBLE — « où est le ban de 10.0.0.5 »
// est la question qu'on pose à une file de riposte —, l'HÔTE où il s'applique, l'ÉTAT tel que le démon le
// sert, puis la ligne de méta : le MOTIF et le RÉSULTAT.
// LA RÈGLE PRODUCTRICE N'EST PAS UN CHAMP, ET ELLE N'EST PAS RELUE ICI. La route ne sert aucun identifiant
// de règle ; le moteur de réponse inscrit son producteur DANS le motif sous la forme `famille:nom`, et
// c'est de là que la fabrique de liste tire l'axe « règle ». Le motif porte donc déjà le nom du groupe,
// mot pour mot : chercher l'en-tête d'un groupe cherche ses lignes, sans qu'une seconde lecture de la
// raison — qui pourrait diverger de celle de la fabrique — soit écrite dans ce panneau.
// CE QUI EN EST ÉCARTÉ, ET POURQUOI : les mots que la CONSOLE substitue à un état — « dry-run » / « RÉEL »
// pour un booléen, « central » pour un hôte absent. Ce sont des mots d'interface, pas des mots du
// registre ; les rendre cherchables ferait dépendre la recherche de la langue choisie, et la file de
// riposte se chercherait autrement en anglais qu'en français. La phrase rendue quand rien n'est trouvé
// NOMME donc ce sur quoi la recherche porte, pour que cette limite se lise au lieu de se deviner.
function texteCherchableDUneAction(a) {
  return texteCherchable([a && a.kind, a && a.target, a && a.host, a && a.status, a && a.reason, a && a.result]);
}
// La recherche courante de la file, et l'autre bout de la même poignée — même forme que le panneau des
// règles quelques centaines de lignes plus haut. Sans champ dans le document (test, rendu partiel), la
// recherche vaut la chaîne vide et la liste rend exactement comme avant.
let rechercheDesActions = () => '';
let poserLaRechercheDesActions = () => {};
// Dernière réponse servie par `/api/actions` — la RÉPONSE ENTIÈRE, pas ses seules lignes : la fenêtre, le
// nombre servi et le total borné sont ce qui décide de la portée que la recherche doit annoncer. La frappe
// REDESSINE, elle ne recharge pas : filtrer est une comparaison de chaînes sur des lignes déjà en mémoire,
// et une requête HTTP par caractère serait un coût réseau pour un travail local (même partage
// `charger`/`dessiner` que les règles et que la file d'alertes).
let actionsChargees = null;

async function loadActions() {
  const wrap = $('#act-list'); if (!wrap) return;
  const d = await fetchInto(wrap, '/actions'); if (!d) return;   // P11.14-a : la cause est écrite dans le panneau
  actionsChargees = d;
  dessinerLesActions();
}
// `P11.18-h` — UNE ACTION QU'ON VIENT DE CRÉER DOIT SE VOIR. Une recherche posée n'a aucune raison de
// contenir la ligne qu'on vient d'écrire : le geste réussirait et la file n'en montrerait rien — un succès
// invisible, la famille de défauts que cette campagne poursuit. La recherche est donc vidée à la CRÉATION,
// et d'elle seule : approuver ou annuler travaille DANS le sous-ensemble qu'on regarde, et l'en éjecter
// ferait perdre sa place à l'exploitant au milieu d'un tri de file.
function apresCreationDUneAction() {
  poserLaRechercheDesActions('');
  return loadActions();
}
// LE DESSIN, sur une réponse DÉJÀ servie. Séparé du chargement pour la recherche, et c'est aussi ce qui le
// rend jugeable sans réseau.
function dessinerLesActions() {
  const wrap = $('#act-list'); const d = actionsChargees;
  if (!wrap || !d) return;
  const actions = d.actions || [];
  wrap.replaceChildren();
  // `P11.17-e` — UNE LISTE VIDE N'EST PAS TOUJOURS UNE FILE VIDE. Le démon rend désormais, à côté des
  // lignes, le TOTAL du registre (borné) : si le registre en compte et qu'aucune ligne n'est arrivée,
  // « aucune action » serait FAUX — et sur la file des gestes de riposte, l'erreur va alors dans le sens
  // dangereux. La vue dit ce qu'elle sait, et rien de plus.
  if (!actions.length) { wrap.appendChild(muted(typeof d.total === 'number' && d.total > 0 ? MOT_ACTIONS_ILLISIBLES : 'aucune action')); return; }
  // tri : pending d'abord, puis récence (done_ts desc). Il ordonne les lignes DANS chaque groupe.
  const PRANK = { pending: 0, approved: 1 };
  actions.sort((a, b) => ((PRANK[a.status] ?? 2) - (PRANK[b.status] ?? 2)) || ((b.done_ts || 0) - (a.done_ts || 0)));
  // `P11.15-b` puis `P11.17-e` — CE QUE CETTE LISTE COUVRE, DIT AVANT D'ÊTRE LUE. Le compte des en-têtes
  // était celui des lignes SERVIES et non celui du registre ; présenter l'un pour l'autre fait lire « il y
  // a N actions » là où il y en a peut-être mille. La phrase de `P11.15-b` était un PANSEMENT — la vue
  // disait ce qu'elle savait faute de total. Le remède est en amont : la route rend le total, borné et
  // annoncé comme tel, et la vue écrit « tant sur tant ».
  wrap.appendChild(muted(motDeLaBorneDesActions(d)));
  // `P11.18-h` — LA RECHERCHE SE COMPOSE AVEC LE REGROUPEMENT AU LIEU DE LE DÉFAIRE. Les deux panneaux qui
  // portaient déjà la recherche rendent une liste PLATE dès qu'elle est posée, et pour une raison écrite :
  // chez eux une correspondance tombée dans une section repliée serait INVISIBLE (les règles) ou même pas
  // chargée (les groupes d'alertes, dont chaque dépli est une requête). Ici ni l'un ni l'autre : les lignes
  // sont toutes en mémoire, et l'en-tête d'un groupe ANNONCE SON COMPTE — un groupe replié qui affiche « 3 »
  // ne cache pas ses correspondances, il les résume. Défaire le regroupement ferait donc perdre la lecture
  // par règle productrice au moment précis où l'on cherche une règle. La partition est refaite sur les
  // lignes TROUVÉES : un groupe sans correspondance disparaît, et le compte de chaque en-tête est celui
  // des lignes retenues.
  const requete = rechercheDesActions();
  const trouvees = requete ? filtrerParRecherche(actions, requete, texteCherchableDUneAction) : actions;
  if (requete) {
    // Une liste qui cache des lignes le DIT ; et quand elle ne trouve rien, elle nomme ce qu'elle a cherché
    // ET jusqu'où elle a cherché.
    const borne = laFenetreBorneLeRegistre(d);
    wrap.appendChild(resumeDeRecherche(trouvees.length, actions.length, {
      filtre: document.createTextNode(borne ? MOT_RECHERCHE_ACTIONS_FENETRE : MOT_RECHERCHE_ACTIONS_REGISTRE),
      vide: document.createTextNode(borne ? MOT_RECHERCHE_ACTIONS_RIEN_FENETRE : MOT_RECHERCHE_ACTIONS_RIEN_REGISTRE),
    }));
    if (!trouvees.length) return;
  }
  // `P11.17-c` — LE REGROUPEMENT PAR RÈGLE N'EST PAS ÉCRIT ICI. La fabrique lit ce que les lignes portent :
  // une action nomme la règle qui l'a produite (le moteur de réponse l'inscrit dans sa raison), son état et
  // l'hôte où elle s'applique — trois axes offerts, dont la règle est le premier de l'ordre partagé. Le
  // panneau ne rendait qu'UN groupe contenant toute la liste, et il en construisait chaque ligne même replié.
  const host = document.createElement('div');
  pagedList(host, { mode: 'client', pageSize: 50, rows: trouvees, renderRow: actionRow, group: { storeKey: 'soc_act_collapsed' } });
  wrap.appendChild(host);
}
// `P11.17-e` — CE QUE LA VUE AFFICHE QUAND LA BORNE MORD. Le démon rend, à côté des lignes, la FENÊTRE
// qu'il sert (`window`), le nombre de lignes SERVIES (`served`) et le TOTAL du registre borné par le
// plafond de comptage partagé (`total`, `total_capped`) — le même idiome que `/api/query` et que le
// journal d'audit. Quatre phrases, une par état de connaissance, et aucune ne présente une fenêtre comme
// un total : « tant sur tant » quand la borne mord, « tant sur PLUS DE tant » quand le comptage lui-même
// est plafonné, « c'est tout le registre » quand elle ne mord pas, et un aveu quand le démon n'a pas pu
// compter — un total absent n'est PAS un zéro.
// Fonction PURE (une réponse -> une phrase) : c'est ce qui la rend tenable par le harnais ESM, dans les
// deux sens (une borne qui mord doit se dire ; un registre entier servi ne doit pas s'annoncer tronqué).
function motDeLaBorneDesActions(d) {
  const servies = d && d.actions ? d.actions.length : 0;
  if (!laFenetreBorneLeRegistre(d)) return servies + MOT_ACTIONS_TOUT_LE_REGISTRE;
  if (!d || typeof d.total !== 'number') return servies + MOT_ACTIONS_SERVIES_A + (d && d.window ? d.window : servies) + MOT_ACTIONS_SERVIES_B;
  if (d.total_capped) return servies + MOT_ACTIONS_SUR + MOT_ACTIONS_PLUS_DE + d.total + MOT_ACTIONS_HORS_ATTEINTE;
  return servies + MOT_ACTIONS_SUR + d.total + MOT_ACTIONS_HORS_ATTEINTE;
}
// `P11.18-h` — LA BORNE MORD-ELLE ? UNE SEULE LECTURE, DEUX EMPLOIS. La phrase de la fenêtre et celle de la
// recherche répondent à la MÊME question ; l'écrire deux fois serait la laisser diverger, et une portée qui
// diverge de la borne qu'elle annonce est exactement le défaut que `P11.17-e` a fermé en amont. Le registre
// n'est ENTIÈREMENT servi que lorsqu'il a été compté (`total` numérique), que le comptage n'a pas lui-même
// été plafonné, et qu'il ne dépasse pas les lignes rendues. Tout le reste — comptage impossible, comptage
// plafonné, total supérieur au servi — est une fenêtre qui borne, et un total absent n'est PAS un zéro.
function laFenetreBorneLeRegistre(d) {
  const servies = d && d.actions ? d.actions.length : 0;
  return !(d && typeof d.total === 'number' && !d.total_capped && d.total <= servies);
}
// Le vocabulaire de la borne, écrit dans les deux langues. La console ne dit que ce que la réponse porte.
const MOT_ACTIONS_SUR = LANG === 'en' ? ' action(s) shown out of ' : ' action(s) affichée(s) sur ';
const MOT_ACTIONS_PLUS_DE = LANG === 'en' ? 'more than ' : 'plus de ';
const MOT_ACTIONS_HORS_ATTEINTE = LANG === 'en'
  ? ' in the register — the route serves the most recent ones; older ones are not reachable from this panel.'
  : " au registre — la route sert les plus récentes ; les plus anciennes ne sont pas atteignables depuis ce panneau.";
const MOT_ACTIONS_TOUT_LE_REGISTRE = LANG === 'en' ? ' action(s) — that is the whole register.' : " action(s) — c'est tout le registre.";
const MOT_ACTIONS_SERVIES_A = LANG === 'en' ? ' action(s) served (window of ' : ' action(s) servie(s) (fenêtre de ';
const MOT_ACTIONS_SERVIES_B = LANG === 'en'
  ? ') — the register could NOT be counted, so it may hold more.'
  : ") — le registre n'a PAS pu être compté, il peut donc en contenir davantage.";
const MOT_ACTIONS_ILLISIBLES = LANG === 'en'
  ? 'The register holds actions, but none could be read — this is NOT an empty queue.'
  : "Le registre compte des actions, mais aucune n'a pu être lue — ce n'est PAS une file vide.";
// `P11.18-h` — CE QUE LA RECHERCHE COUVRE, DIT SANS L'ARRONDIR. La route sert une FENÊTRE des actions les
// plus récentes ; une recherche du navigateur ne porte donc que sur les lignes SERVIES. Taire cette limite
// ferait rendre « aucun résultat » pour une action qui EXISTE — et sur une file de gestes de riposte,
// l'erreur va dans le sens dangereux. Deux états, séparés par le prédicat de la borne lui-même : ils ne
// peuvent pas contredire la phrase écrite juste au-dessus d'eux. Les quatre phrases sont écrites EN ENTIER
// dans les deux langues, à l'endroit du rendu : une phrase recollée à l'exécution ne serait jamais égale à
// une clé du lexique et resterait en français, et une phrase posée sous une clé d'objet ne serait vue par
// aucune garde — deux dérives déjà mesurées sur la file d'alertes.
const MOT_RECHERCHE_ACTIONS_FENETRE = LANG === 'en'
  ? 'action(s) among the SERVED lines — the search does not reach into the register beyond that window; grouping and order stay as they are'
  : "action(s) parmi les lignes SERVIES — la recherche ne descend pas dans le registre au-delà de cette fenêtre ; le regroupement et l'ordre restent posés";
const MOT_RECHERCHE_ACTIONS_REGISTRE = LANG === 'en'
  ? 'action(s) — the search covers the whole register, which is served in full here; grouping and order stay as they are'
  : "action(s) — la recherche porte sur tout le registre, servi ici en entier ; le regroupement et l'ordre restent posés";
const MOT_RECHERCHE_ACTIONS_RIEN_FENETRE = LANG === 'en'
  ? 'No SERVED action carries these words in its kind, target, host, status, reason or result — and the search does not go past the served window, so an older action may exist without being reachable from this panel. Esc clears the search.'
  : "Aucune action SERVIE ne porte ces mots dans son geste, sa cible, son hôte, son état, son motif ou son résultat — et la recherche ne descend pas au-delà de la fenêtre servie : une action plus ancienne peut exister sans être atteignable depuis ce panneau. Échap efface la recherche.";
const MOT_RECHERCHE_ACTIONS_RIEN_REGISTRE = LANG === 'en'
  ? 'No action in the register carries these words in its kind, target, host, status, reason or result — and the whole register is served here, so none exists. Esc clears the search.'
  : "Aucune action du registre ne porte ces mots dans son geste, sa cible, son hôte, son état, son motif ou son résultat — et le registre est servi ici en entier : il n'en existe donc aucune. Échap efface la recherche.";
const MOT_RECHERCHE_ACTIONS_INVITE = LANG === 'en' ? 'Search an action…' : 'Rechercher une action…';
const MOT_RECHERCHE_ACTIONS_ETIQUETTE = LANG === 'en' ? 'Search an action' : 'Rechercher une action';
const MOT_RECHERCHE_ACTIONS_AIDE = LANG === 'en'
  ? 'Searches the kind, target, host, status, reason and result of each SERVED action; it composes with the grouping. Esc clears the search.'
  : "Cherche dans le geste, la cible, l'hôte, l'état, le motif et le résultat de chaque action SERVIE ; se combine avec le regroupement. Échap efface la recherche.";
function actionRow(a) {
  const row = document.createElement('div'); row.className = 'rulerow';
  const st = document.createElement('span'); st.className = 'actst act-' + a.status; st.textContent = a.status;
  const k = document.createElement('code'); k.className = 'rulecond'; k.textContent = `${a.kind} ${a.target}`;
  const hostEl = document.createElement('span'); hostEl.className = 'casechip'; hostEl.textContent = '@' + (a.host || 'central');
  hostEl.title = a.host ? `Appliqué sur l'hôte ${a.host} (par son agent responder)` : 'Appliqué par le central';
  const dry = document.createElement('span'); dry.className = a.dry_run ? 'muted' : 'bad'; dry.textContent = a.dry_run ? 'dry-run' : 'RÉEL';
  const meta = document.createElement('span'); meta.className = 'rulemeta muted';
  meta.textContent = (a.reason ? a.reason + ' - ' : '') + (a.result || ''); if (a.done_ts) meta.title = fmtTs(a.done_ts);
  row.append(st, k, hostEl, dry, meta);
  if (a.status === 'pending') {
    const ap = document.createElement('button'); ap.textContent = 'Approuver';
    ap.onclick = async () => { if (await confirmModal(`Approuver : ${a.kind} ${a.target}${a.dry_run ? ' (dry-run)' : ' - REEL'} ?`, { okText: 'Approuver', danger: !a.dry_run })) { await apiSend('/actions/' + a.id + '/approve'); loadActions(); } };
    row.append(ap);
  }
  if (a.status === 'pending' || a.status === 'approved') {
    const ca = document.createElement('button'); ca.textContent = 'Annuler';
    ca.onclick = async () => { await apiSend('/actions/' + a.id + '/cancel'); loadActions(); };
    row.append(ca);
  }
  return row;
}
if ($('#act-new')) $('#act-new').onclick = () => { $('#act-form').classList.remove('hidden'); $('#af-target').focus(); };
if ($('#af-cancel')) $('#af-cancel').onclick = () => $('#act-form').classList.add('hidden');
if ($('#act-form')) $('#act-form').addEventListener('submit', async e => {
  e.preventDefault();
  const body = { kind: $('#af-kind').value, target: $('#af-target').value.trim(), dry_run: $('#af-dry').checked, reason: $('#af-reason').value.trim() };
  if (!body.target) { $('#af-result').textContent = 'cible requise'; return; }
  const j = await apiSend('/actions', 'POST', body);
  if (j.error) { $('#af-result').textContent = '' + j.error; return; }
  $('#act-form').classList.add('hidden'); $('#af-target').value = ''; $('#af-reason').value = ''; $('#af-result').textContent = '';
  apresCreationDUneAction();   // `P11.18-h` : la ligne qu'on vient d'écrire n'a aucune raison de porter la recherche posée
});
// `P11.18-h` — LE CHAMP DE RECHERCHE DE LA FILE DE RIPOSTE, POSÉ PAR LE MÉCANISME PARTAGÉ. Il REDESSINE
// (aucun rechargement), Échap le vide, et le chrome `.field` vient du câblage : trois propriétés que ce
// panneau n'a pas à réécrire.
// POURQUOI LE CHAMP EST CONSTRUIT ICI ET NON DANS `index.html`, OÙ VIVENT CEUX DES RÈGLES ET DES ALERTES.
// L'en-tête de ce panneau ne porte AUCUN conteneur d'outils : il n'a qu'un titre et un bouton de création,
// là où les deux autres panneaux ont un `.hdtools`. Le conteneur partagé est donc créé, le champ y est posé,
// et le bouton de création l'y rejoint — l'en-tête prend la forme des deux autres au lieu d'en inventer une
// troisième. Sa place naturelle reste le document ; c'est écrit ici pour que l'y déplacer soit une reprise
// et non une découverte, et pour nommer ce qui manque alors : la largeur de ces champs est bornée dans la
// feuille par une règle qui les ÉNUMÈRE (`#rule-search,#alert-search`), et `#act-search` n'y figure pas.
(() => {
  const tete = document.querySelector('#actions-panel .panelhead');
  if (!tete) return;
  const outils = document.createElement('div'); outils.className = 'hdtools';
  const champ = document.createElement('input');
  champ.id = 'act-search'; champ.type = 'search';
  champ.placeholder = MOT_RECHERCHE_ACTIONS_INVITE;
  champ.title = MOT_RECHERCHE_ACTIONS_AIDE;
  champ.setAttribute('aria-label', MOT_RECHERCHE_ACTIONS_ETIQUETTE);
  outils.appendChild(champ);
  tete.appendChild(outils);
  const creer = $('#act-new'); if (creer) outils.appendChild(creer);   // insérer DÉTACHE : le bouton n'a jamais deux parents
  const poignee = champDeRecherche(champ, { auChangement: () => dessinerLesActions() });
  rechercheDesActions = poignee.valeur; poserLaRechercheDesActions = poignee.poser;
})();
loadActions();

// --- mode global observe/active ---
// P11.14-a — UN MODE NON LU N'EST PAS « OBSERVATION ». Cette charge avalait son échec (`catch (e) {}`) puis
// PEIGNAIT sa valeur de repli : l'interrupteur affirmait « Observation — propositions seulement », en vert,
// alors qu'il n'avait rien pu lire. Sur une console de sécurité l'écart va dans le sens DANGEREUX — croire
// qu'on observe quand on ne sait pas si l'on applique. Le mode a donc TROIS rendus et non deux, et le
// troisième est celui que le reste du produit emploie déjà pour une grandeur qu'on n'a pas su lire
// (`system.js` : « NON LISIBLE » à côté de sa cause). La cause, elle, est écrite dans l'hôte par le
// mécanisme PARTAGÉ `fetchInto` — le badge d'état, qui est la région `role="status"` voisine.
// L'INTERRUPTEUR D'UN ÉTAT NON LU EST DÉSARMÉ : on n'arme pas ce qu'on ne sait pas lire, et une bascule
// dont l'état courant est inconnu n'a pas de destination. `aria-checked="mixed"` est l'état indéterminé
// que la norme donne à un `role="switch"` ; `data-mode` vide dit la même chose au gestionnaire de clic.
async function loadMode() {
  const b = $('#mode-badge'), tg = $('#mode-toggle'); if (!tg) return;
  let mode = null;                                    // null = NON LU, jamais replié sur 'observe'
  // Le badge est l'hôte de la cause : `fetchInto` l'y écrit et rend null. Sans badge dans le document, la
  // lecture reste la même et l'échec vaut toujours « non lu » — jamais une valeur par défaut.
  if (b) { const d = await fetchInto(b, '/mode'); if (d) mode = d.mode || 'observe'; }
  else { try { const d = await api('/mode'); mode = d.mode || 'observe'; } catch (e) { mode = null; } }
  peindreLeMode(tg, b, mode);
}
// D13 — INTERRUPTEUR ON/OFF color-codé (piste + bouton), au lieu d'un bouton dont le libellé = la DESTINATION.
// Vert = Observation (sûr) ; ambre/rouge = Actif (armé, réponses automatiques) ; gris inerte = état NON LU.
// L'ÉTAT COURANT est porté par data-mode (le handler s'y fie, PLUS jamais à className) ; aria-checked=« armé ».
// Le libellé décrit le mode COURANT (pas une destination). L'interrupteur reste #mode-toggle -> viewer-hide CSS
// + confirm d'armement intacts. `mode` vaut 'active', 'observe', ou null (non lu) — la peinture est PURE, ce
// qui met les trois rendus sur le même chemin et permet de les juger l'un contre l'autre.
function peindreLeMode(tg, b, mode) {
  const lu = mode === 'active' || mode === 'observe';
  const active = mode === 'active';
  tg.dataset.mode = lu ? mode : '';
  tg.classList.toggle('armed', lu && active);
  tg.disabled = !lu;                                  // rien à basculer tant que l'état n'est pas lu
  tg.setAttribute('aria-checked', lu ? (active ? 'true' : 'false') : 'mixed');
  // Gris de l'état non lu, rendu à la feuille dès que le mode est lu. Même idiome que le mot d'état de
  // l'interrupteur partagé (`producer_ui.js`), qui peint déjà son mot avec `var(--mut)`.
  tg.style.color = lu ? '' : 'var(--mut)';
  tg.style.borderColor = lu ? '' : 'var(--bd)';
  if (lu) {
    tg.setAttribute('aria-label', active
      ? 'Mode ACTIF (réponses automatiques armées) — cliquer pour repasser en Observation'
      : 'Mode Observation (propositions seulement) — cliquer pour armer les réponses automatiques');
    tg.title = active
      ? 'Réponses automatiques ARMÉES — cliquer pour revenir en Observation'
      : 'Observation (propositions seulement) — cliquer pour armer les réponses automatiques';
  } else {
    // Aucune phrase d'état ne survit à une lecture ratée : celle de la lecture PRÉCÉDENTE affirmerait
    // encore un mode. Le nom accessible retombe alors sur le contenu du bouton, qui dit « NON LISIBLE ».
    tg.removeAttribute('aria-label'); tg.removeAttribute('title');
  }
  if (lu) {
    tg.innerHTML = '<span class="mt-track"><span class="mt-knob"></span></span><span class="mt-lbl">' + (active ? 'ACTIF' : 'OBSERVE') + '</span>';
  } else {
    // Le mot de l'état non lu est celui que le produit emploie DÉJÀ pour une grandeur qu'il n'a pas su lire
    // (`system.js`) : un seul vocabulaire pour un seul fait. Posé par `textContent`, il est REGARDÉ par la
    // garde du lexique — et il y figure, donc il se traduit comme le reste. La piste passe au gris neutre :
    // ni le vert d'Observation ni le rouge d'Actif ne doit paraître quand rien n'a été lu.
    const piste = document.createElement('span'); piste.className = 'mt-track'; piste.style.background = 'var(--mut)';
    const bouton = document.createElement('span'); bouton.className = 'mt-knob'; piste.appendChild(bouton);
    const mot = document.createElement('span'); mot.className = 'mt-lbl'; mot.textContent = 'NON LISIBLE';
    tg.replaceChildren(piste, mot);
  }
  if (!b) return;
  // Le code couleur du badge suit le même partage : ni vert ni rouge quand rien n'a été lu.
  b.className = 'modestate' + (lu ? (active ? ' bad' : ' ok') : '');
  // Non lu : `fetchInto` a DÉJÀ écrit la cause dans le badge — l'écraser la ferait disparaître.
  if (!lu) return;
  // libellé descriptif à côté de l'interrupteur (état COURANT + conséquence), même code couleur.
  b.innerHTML = `<span class="fdot ${active ? 'bad' : 'ok'}"></span>` + (active ? 'Actif — réponses automatiques' : 'Observation — propositions seulement');
}
if ($('#mode-toggle')) $('#mode-toggle').onclick = async () => {
  const tg = $('#mode-toggle');
  // P11.14-a — FAIL-CLOSED : `data-mode` vide = état NON LU. Sans état courant il n'y a pas de destination,
  // et le repli implicite était « armer ». Le bouton est déjà désarmé dans ce cas ; la garde ferme le chemin.
  if (tg.dataset.mode !== 'active' && tg.dataset.mode !== 'observe') return;
  const active = tg.dataset.mode === 'active';   // D13 — état COURANT via data-attribute (jamais className)
  const next = active ? 'observe' : 'active';
  // confirm DESTRUCTIF conservé à l'armement (passage en Actif) : exécution réelle sans approbation.
  if (next === 'active' && !await confirmModal('Mode ACTIF : les playbooks exécuteront les réponses AUTOMATIQUEMENT (réel, sans approbation). Confirmer ?', { okText: 'Activer', danger: true })) return;
  await apiSend('/mode', 'POST', { mode: next });
  loadMode();
};

// --- playbooks (détection -> réponse) ---
const PB = { name: '#pb-name', query: '#pb-query', issoql: '#pb-issoql', kind: '#pb-kind', interval: '#pb-interval', window: '#pb-window', enabled: '#pb-enabled' };
/* state: editingPb -> S (state.js) */
// Libellé humain d'une option du `<select id="pb-kind">` : le nom technique (la valeur envoyée) suivi de ce que
// l'action fait sur chaque cible. La durée du ban n'est JAMAIS écrite ici : elle est `ban_duration_s`, servie par
// le démon avec la liste (la même que posent les exécuteurs). Sans valeur servie, le libellé ne dit pas de durée.
function actionKindOptionLabel(kind, banDurationS) {
  const en = LANG === 'en';
  const heures = Number(banDurationS) > 0 ? Math.round(Number(banDurationS) / 3600) : null;
  const effet = {
    ban_ip: heures == null ? (en ? 'bans the source IP' : "bannit l'IP source") : (en ? 'bans the source IP for ' + heures + ' h' : "bannit l'IP source " + heures + ' h'),
    kill_pid: en ? 'terminates the target process' : 'termine le processus cible',
    stop_service: en ? 'stops the target service' : 'arrête le service cible',
  }[kind];
  return effet ? kind + ' — ' + effet : kind;
}
function labelActionKindOptions(banDurationS) {
  const sel = $('#pb-kind'); if (!sel || !sel.options) return;
  [...sel.options].forEach(o => { o.textContent = actionKindOptionLabel(o.value, banDurationS); });
}
async function loadPlaybooks() {
  const wrap = $('#pb-list'); if (!wrap) return;
  const d = await fetchInto(wrap, '/playbooks'); if (!d) return;   // P11.14-a : la cause est écrite dans le panneau
  const playbooks = d.playbooks || [], mode = d.mode || 'observe', ban_duration_s = d.ban_duration_s === undefined ? null : d.ban_duration_s;
  labelActionKindOptions(ban_duration_s);
  wrap.replaceChildren();
  const note = takePendingNote('playbooks'); if (note) wrap.appendChild(note); // P11.1-e
  if (!playbooks.length) { wrap.appendChild(muted('aucun playbook')); return; }
  // groupe repliable « Playbooks » (même chrome que Détection/Parseurs) — tri par nom (localeCompare)
  playbooks.sort((a, b) => (a.name || '').localeCompare(b.name || ''));
  const set = lsSet('soc_pb_collapsed');
  // `P11.15-b` : le corps n'est bâti qu'au premier dépli — un groupe replié ne construisait pas moins de
  // lignes qu'un groupe ouvert, la feuille se contentait de les masquer.
  wrap.appendChild(collapsibleGroup(set, 'soc_pb_collapsed', 'playbooks', 'Playbooks', playbooks.length, () => playbooks.map(p => pbRow(p, mode))));
}
// Modèle de ligne d'un playbook : la MÊME forme que ruleRowModel / runbookRowModel (`producer_ui.js`).
// `P11.2-b` : la conséquence vient du serveur (`consequence`, durée du ban incluse) et se lit dans les deux
// états ; l'activation CONFIRME (elle arme une action réseau/processus) ; le mode global dit si ON exécute
// (Actif) ou propose (Observation : file Actions, en attente, dry-run).
function playbookRowModel(p, mode) {
  const consequence = (p.consequence || ('-> ' + p.action_kind)) + (mode === 'active' ? ' — mode Actif : EXÉCUTÉ sans approbation' : ' — mode Observation : PROPOSÉ dans Actions (en attente, dry-run), pas exécuté');
  return {
    family: 'playbook', name: p.name, origin: p.managed, enabled: !!p.enabled, consequence,
    // #1c-toggle : (dés)activation ADMIN-only via /enabled (audité + persistant pour les overlays config.d).
    toggleAllowed: socIsAdmin(), toggleDeniedReason: "l'activation/désactivation d'un playbook est réservée à l'administrateur",
    confirmOnEnable: true,
    onToggle: next => apiSend('/playbooks/' + p.id + '/enabled', 'POST', { enabled: next }),
    summary: '-> ' + p.action_kind, summaryTitle: p.query,
    meta: 'toutes les ' + (p.interval_s || 0) + ' s sur ' + (p.window_s || 0) + ' s',
  };
}
function pbRow(p, mode) {
  const row = producerRow(playbookRowModel(p, mode));
  const meta = row.metaEl;
  const test = rowButton('Tester', { title: 'Liste les cibles que la requête rend maintenant, sans poser d\'action', onClick: async () => { meta.textContent = '...'; const j = await apiSend('/playbooks/' + p.id + '/test'); meta.textContent = j.error ? ('erreur : ' + j.error) : `${j.valides} cible(s) : ${(j.targets || []).slice(0, 5).join(', ')}`; } });
  // MIROIR UX : éditer un playbook BASELINE (seed/builtin managed=0) est réservé admin (403 serveur).
  const baselineLocked = !socIsAdmin() && p.managed === 0;
  const edit = rowButton('Éditer', { cls: 'crud-btn', disabled: baselineLocked, title: baselineLocked ? 'playbook baseline (seed/builtin) : édition réservée à l\'administrateur' : '', onClick: baselineLocked ? null : () => openPbForm(p) });
  const del = rowButton('', { cls: 'crud-btn', icon: ic('x'), title: 'Supprimer' });
  if (gateDeleteBtn(del, p.managed)) del.onclick = async () => { if (await confirmModal('Supprimer le playbook "' + p.name + '" ?', { danger: true })) { if (await contentDelete('/playbooks/' + p.id, 'playbook')) loadPlaybooks(); } };
  row.append(test, edit, del);
  return row;
}
function openPbForm(p) {
  S.editingPb = p ? p.id : null;
  $('#pb-form').classList.remove('hidden');
  $(PB.name).value = p ? p.name : '';
  $(PB.query).value = p ? p.query : '';
  $(PB.issoql).value = p ? (p.is_soql ? '1' : '0') : '1';
  if (!socIsAdmin()) $(PB.issoql).value = '1'; // SQL brut = admin only (toggle masqué côté non-admin)
  $(PB.kind).value = p ? p.action_kind : 'ban_ip';
  $(PB.interval).value = p ? p.interval_s : 300;
  $(PB.window).value = p ? p.window_s : 3600;
  $(PB.enabled).checked = p ? p.enabled : true;
  // P11.1-e : la destination est dite AVANT d'enregistrer (condition = requête, 1re colonne = cible ; action = enum).
  const res = $('#pb-result'); if (res) { res.className = 'muted'; res.replaceChildren(destinationNote('actions', '', '')); }
  $(PB.name).focus();
}
if ($('#pb-new')) $('#pb-new').onclick = () => openPbForm(null);
if ($('#pb-cancel')) $('#pb-cancel').onclick = () => $('#pb-form').classList.add('hidden');
if ($('#pb-form')) $('#pb-form').addEventListener('submit', async e => {
  e.preventDefault();
  // SQL brut réservé admin (garde-fou #2) : un non-admin envoie toujours GXQL (le serveur 403 sinon).
  const body = { name: $(PB.name).value.trim() || 'Playbook', query: $(PB.query).value.trim(), is_soql: socIsAdmin() ? ($(PB.issoql).value === '1') : true, action_kind: $(PB.kind).value, interval_s: Number($(PB.interval).value) || 300, window_s: Number($(PB.window).value) || 3600, enabled: $(PB.enabled).checked };
  if (!body.query) { formMsg('#pb-result', 'requête requise', true); toast('requête requise', 'bad'); return; }
  // garde-fous #1/#3 : le serveur valide (requête compile, action ∈ enum fermé). Erreur -> {error} affiché, formulaire OUVERT.
  if (!await contentSubmit(S.editingPb ? '/playbooks/' + S.editingPb : '/playbooks', body, '#pb-result')) return;
  $('#pb-form').classList.add('hidden');
  announceCreated('playbooks', 'actions', body.name, body.enabled ? 'première évaluation dans ' + body.interval_s + ' s' : 'OFF : activez-le dans la liste (confirmation demandée)'); // P11.1-e
  loadPlaybooks();
});
loadPlaybooks();
loadMode();

export { renderCoverage, loadRules, renderRules, peindreLeMode, poserLaRechercheDesRegles, apresEnregistrementDUneRegle, ouvrirLesReglesDeLaTechnique, ouvrirLaCreationPourLaTechnique, loadNotifiers, loadParsers, loadActions, dessinerLesActions, poserLaRechercheDesActions, apresCreationDUneAction, texteCherchableDUneAction, laFenetreBorneLeRegistre, loadMode, loadPlaybooks, motDeLaBorneDesActions, ruleRowModel, ruleRow, texteCherchableDUneRegle, playbookRowModel, pbRow, actionKindOptionLabel };
