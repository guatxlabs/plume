// Amorçage du lexique sous `LANG='en'` (`P11.8-a`) : marche initiale sur le document, intro Parsers en anglais
// (HTML riche, hors marche), puis l'OBSERVATEUR qui traduit ce qui arrive APRÈS coup — nœuds ajoutés (éléments
// et nœuds texte) et attributs affichés (`title`, `placeholder`, `aria-label`, `label`). Le dictionnaire et la
// marche vivent dans `i18n.js` ; ce module ne fait que les poser sur le document vivant. Il n'importe pas `app.js`.
import { $, LANG } from './core.js';
import { i18nWalk } from './i18n.js';

function installI18nObserver() {
  if (LANG === 'en') {
    i18nWalk(document.body);
    // bloc d'intro Parsers (HTML riche, trop fragmenté pour le walk) -> version EN dédiée
    const pi = $('#parsers-intro');
    if (pi) pi.innerHTML = 'Extracts fields (regex named groups <code>(?&lt;name&gt;…)</code>) from the message <b>at ingestion, for all sources</b> (k3s / host / container — parsing is central, mode-independent). Built-in defaults (toggleable) + your custom parsers. <code>source=*</code> = all.<br><b>When?</b> a parser is <b>effective on save</b>, for <b>new</b> events. For <b>old</b> ones: <b>↻ Re-apply</b> (retroactive, with confirmation) — or <code>| rex</code> on the fly in a search.<br><b>IP direction:</b> name <code>src_ip</code> = the <b>initiator</b> (the attacker when inbound), <code>dst_ip</code> = the <b>target</b>. <code>src_ip</code>/<code>rhost</code> are promoted to a searchable column; an IP of uncertain direction → leave it in a neutral field (e.g. <code>ip</code>), never <code>src_ip</code>.';
    // P11.8-a : les nœuds TEXTE comptent (un `textContent = '…'` sur un élément déjà attaché ajoute un nœud Text, pas un
    // élément), et un attribut posé APRÈS attachement est re-traduit — la garde anti-boucle vit dans `i18nWalk`.
    new MutationObserver(ms => ms.forEach(m => {
      if (m.type === 'attributes') { i18nWalk(m.target); return; }
      m.addedNodes.forEach(nd => { if (nd.nodeType === 1 || nd.nodeType === 3) i18nWalk(nd); });
    })).observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ['title', 'placeholder', 'aria-label', 'label'] });
  }
}

export { installI18nObserver };
