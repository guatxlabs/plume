// producer_ui.js — rendu PARTAGÉ des « producteurs » (règle de détection, playbook de réponse, runbook,
// corrélation, baseline) : UNE ligne, UN interrupteur, UNE phrase de destination.
//
// P11.2-a : un playbook livré (seed / config.d) et un runbook créé à la main rendaient par deux chemins
// (`.rulerow` + classes partagées d'un côté, une div à styles en ligne et des boutons de classe `ghost`
// — classe sans AUCUNE règle CSS, donc bouton gris du navigateur — de l'autre). Ici une seule fabrique
// de ligne, nourrie par UN modèle de ligne ; les deux tables restent (elles n'ont ni le même exécuteur ni
// le même contenu), c'est la FORME RENDUE qui est unique.
//
// P11.2-b : l'interrupteur dit son état avec le MOT (ON / OFF), nomme sa CONSÉQUENCE (ce que l'activation
// arme), et demande CONFIRMATION à l'activation quand la conséquence touche le réseau ou un processus.
//
// P11.1-e : chaque surface qui crée un producteur dit OÙ son produit arrivera, avec le lien.
import { confirmModal, managedBadge, motiverLeRefusAuLecteur, toast } from './core.js';

// --- destinations : où arrive ce qu'un producteur produit. Clé = famille de producteur. ---------------------
// `hash` = onglet de la console (routage par `location.hash`), `label` = le nom de l'onglet tel qu'affiché.
const DESTINATIONS = {
  alerts:  { hash: 'alerts',  label: 'Alertes', lead: 'ses alertes arrivent dans', tail: '' },
  risk:    { hash: 'risk',    label: 'Risque',  lead: 'sa contribution au score des entités arrive dans', tail: '(mode risque : pas d\'alerte directe)' },
  actions: { hash: 'actions', label: 'Actions', lead: 'les actions qu\'il pose arrivent dans', tail: '(mode Observation : en attente, dry-run ; mode Actif : exécutées)' },
  cases:   { hash: 'cases',   label: 'Cas',     lead: 'sa checklist est proposée dans', tail: '(cas élevé en incident dont la tactique ou la technique dominante correspond, ou attachée à la main depuis le cas)' },
};
// Règle / corrélation / baseline : une entrée en mode risque (risk_score > 0) ne lève pas d'alerte, elle
// alimente le score d'entité. La destination est DÉRIVÉE de ce champ, pas d'un choix de l'appelant.
function detectionDestination(riskScore) { return Number(riskScore) > 0 ? 'risk' : 'alerts'; }
function destinationOf(destKey) { return DESTINATIONS[destKey] || DESTINATIONS.alerts; }
function capitalize(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

// Élément « <nom> — <lead> <lien> <tail> ». Tout texte passe par textContent ; seul le lien est un <a>.
function destinationNote(destKey, name, extra) {
  const d = destinationOf(destKey);
  const el = document.createElement('div'); el.className = 'muted producer-dest';
  el.style.cssText = 'margin:6px 0 8px;font-size:12px';
  if (name) { const b = document.createElement('b'); b.textContent = name; el.append(b, document.createTextNode(' — ' + d.lead + ' ')); }
  else el.appendChild(document.createTextNode(capitalize(d.lead) + ' '));
  const a = document.createElement('a'); a.href = '#' + d.hash; a.textContent = d.label; a.title = 'Ouvrir ' + d.label; el.appendChild(a);
  const rest = [d.tail, extra].filter(Boolean).join(' · ');
  if (rest) el.appendChild(document.createTextNode(' ' + rest));
  return el;
}
// Phrase sans lien, pour un toast ou le message d'une modale.
function destinationSentence(destKey) {
  const d = destinationOf(destKey);
  return capitalize(d.lead) + ' l\'onglet ' + d.label + (d.tail ? ' ' + d.tail : '') + '.';
}
// Note « en attente » : posée par la surface qui vient de créer, consommée par le prochain rendu de liste.
const pendingNotes = new Map();
function announceCreated(listKey, destKey, name, extra) {
  pendingNotes.set(listKey, { destKey, name, extra });
  const d = destinationOf(destKey);
  toast((name ? '« ' + name + ' » enregistré — ' : '') + d.lead + ' ' + d.label, 'ok', 5200);
}
function takePendingNote(listKey) {
  const n = pendingNotes.get(listKey); if (!n) return null;
  pendingNotes.delete(listKey);
  return destinationNote(n.destKey, n.name, n.extra);
}

// --- interrupteur ON / OFF ---------------------------------------------------------------------------------
// opts : { enabled, name, consequence, allowed, deniedReason, confirmOnEnable, onToggle(next) -> Promise }
// Le mot porte l'état ; la conséquence est écrite à côté dans les DEUX états (avant de basculer, on sait ce
// que ça arme). `onToggle` rejette -> la case revient à l'état précédent, le mot aussi.
function enabledSwitch(opts) {
  const lbl = document.createElement('label'); lbl.className = 'producer-switch';
  lbl.style.cssText = 'display:inline-flex;gap:6px;align-items:center;font-size:12px;flex:0 0 auto;max-width:min(100%,440px)';
  const cb = document.createElement('input'); cb.type = 'checkbox'; cb.className = 'crud-toggle'; cb.checked = !!opts.enabled;
  const word = document.createElement('b'); word.className = 'producer-state';
  const what = document.createElement('span'); what.className = 'muted producer-consequence';
  what.style.cssText = 'font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis';
  const paint = () => {
    const on = cb.checked;
    word.textContent = on ? 'ON' : 'OFF';
    word.style.color = on ? 'var(--bad)' : 'var(--mut)';
    what.textContent = (on ? ' · ' : ' · à l\'activation : ') + (opts.consequence || '');
    cb.setAttribute('aria-label', (opts.name ? opts.name + ' : ' : '') + (on ? 'ON' : 'OFF') + ' — ' + (opts.consequence || ''));
    lbl.title = (on ? 'ON — ' : 'OFF — à l\'activation : ') + (opts.consequence || '') + (opts.allowed ? '' : ' · ' + (opts.deniedReason || 'réservé à l\'administrateur'));
  };
  if (!opts.allowed) { cb.disabled = true; }
  cb.onchange = async () => {
    const next = cb.checked;
    if (next && opts.confirmOnEnable) {
      // La phrase de réversibilité est celle de TOUTES les familles : elle nommait « Actions », l'onglet d'une
      // seule d'entre elles, alors que ce commutateur arme aussi une collecte, une sortie de données ou une
      // porte d'entrée. Ce qu'elle doit dire est le même partout — OFF arrête la suite, pas ce qui a eu lieu.
      const ok = await confirmModal('Activer « ' + (opts.name || '') + ' » ? Une fois ON : ' + (opts.consequence || '') + '. Réversible : repasser sur OFF arrête l\'effet pour la suite ; ce qui a déjà eu lieu n\'est pas défait.', { okText: 'Activer', danger: true });
      if (!ok) { cb.checked = false; paint(); return; }
    }
    try { await opts.onToggle(next); paint(); toast((opts.name ? opts.name + ' : ' : '') + (next ? 'ON' : 'OFF'), 'ok'); }
    catch (err) { cb.checked = !next; paint(); toast('Bascule refusée : ' + ((err && err.message) || err), 'bad'); }
  };
  paint();
  lbl.append(cb, word, what);
  return lbl;
}

// --- bouton de ligne : la classe partagée TOUJOURS (P11.4-b — un bouton porte son chrome, même hors d'un
//     `.rulerow` ; dans la ligne, `.rulerow button` produit le même chrome). `crud-btn` = geste d'écriture :
//     refusé à un lecteur, il ne s'efface plus, il reste inerte AVEC sa raison (P11.4-l) — la même grammaire
//     que l'interrupteur ci-dessus, dont le refus est écrit dans l'infobulle de son enveloppe survolable.
//     La raison est posée ICI, à la construction, pour ce que cette fabrique rend ; le capteur partagé de
//     `core` rattrape les boutons qu'aucune fabrique ne construit (le gabarit de la page).
function rowButton(label, opts = {}) {
  const b = document.createElement('button'); b.type = 'button';
  if (opts.icon) b.innerHTML = opts.icon; else b.textContent = label; // `icon` = SVG statique de `ic()` (core), jamais une donnée
  b.className = 'btn btn-sm' + (opts.cls ? ' ' + opts.cls : '');
  if (opts.title) b.title = opts.title;
  if (opts.disabled) b.disabled = true;
  if (opts.onClick) b.onclick = opts.onClick;
  motiverLeRefusAuLecteur(b);
  return b;
}

// --- LA ligne : un seul chemin pour toutes les familles ----------------------------------------------------
// model : { name, origin (0 builtin / 1 overlay / 2 perso — convention `managed` des règles et playbooks),
//           enabled, consequence, toggleAllowed, toggleDeniedReason, confirmOnEnable, onToggle,
//           summary, summaryTitle, meta, chips: [Element], extraClass, buttons: [Element] }
function producerRow(model) {
  const row = document.createElement('div'); row.className = 'rulerow' + (model.extraClass ? ' ' + model.extraClass : '');
  row.dataset.producer = model.family || '';
  row.appendChild(enabledSwitch({
    enabled: model.enabled, name: model.name, consequence: model.consequence,
    allowed: !!model.toggleAllowed, deniedReason: model.toggleDeniedReason,
    confirmOnEnable: !!model.confirmOnEnable, onToggle: model.onToggle || (async () => {}),
  }));
  const name = document.createElement('span'); name.className = 'rulename'; name.textContent = model.name || '';
  (model.chips || []).forEach(c => { name.appendChild(document.createTextNode(' ')); name.appendChild(c); });
  name.appendChild(managedBadge(model.origin));
  row.appendChild(name);
  if (model.summary != null) { const k = document.createElement('code'); k.className = 'rulecond'; k.textContent = model.summary; if (model.summaryTitle) k.title = model.summaryTitle; row.appendChild(k); }
  const meta = document.createElement('span'); meta.className = 'rulemeta muted'; meta.textContent = model.meta || ''; row.appendChild(meta);
  row.metaEl = meta; // la cellule de résultat (« Tester ») sans requête DOM : même chose dans le harnais et le navigateur
  (model.buttons || []).forEach(b => row.appendChild(b));
  return row;
}

export { DESTINATIONS, detectionDestination, destinationNote, destinationSentence, announceCreated, takePendingNote, enabledSwitch, rowButton, producerRow };
