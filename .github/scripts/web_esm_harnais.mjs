#!/usr/bin/env node
// Harnais ESM de la surface web — shim DOM minimal, aucun cadre de test, aucun réseau.
//
// CE QU'IL PROUVE, ET RIEN D'AUTRE
// --------------------------------
// 1. LE GRAPHE DE MODULES SE LIE. Depuis le découpage de `app.js` en modules ES, un import d'un
//    symbole déplacé est une `SyntaxError` à l'édition de liens (« does not provide an export
//    named … ») : le module échoue, la cascade remonte jusqu'à `app.js`, `route()` ne pose jamais
//    `app-ready`, et l'interface reste VIDE — le shell seul visible. Aucun test Rust ne peut le voir.
//    Chaque module suivi sous `web/` est importé ici, dans un processus Node muni d'un `document`
//    factice ; une erreur de lien nomme le module et le symbole.
// 2. LE VERDICT D'UNE GRANDEUR EST RENDU (`S37`). Le démon publie `<clé>_verdict` / `<clé>_cause` /
//    `<clé>_detail` à côté d'une grandeur (`S32`), et la surface doit rendre un ÉTAT quand le verdict
//    n'est pas « lu » — jamais un zéro, jamais une case vide. Le panneau Système est rendu sur des
//    objets fabriqués : verdict `illisible` sur chaque famille (mesure, verdict sans valeur, bilan de
//    boucle, grandeur de composant), puis verdict `lu` — le second témoin interdit qu'une version qui
//    dirait TOUJOURS « non lisible » passe le premier.
//
// Le shim ne rend pas de mise en page : il enregistre l'arbre que les modules construisent, et
// c'est le TEXTE de cet arbre qui est jugé. `fetch` est absent par construction — une surface qui
// appellerait le réseau au chargement d'un module est une erreur, et elle se voit ici.
import { readdirSync } from "node:fs";
import { pathToFileURL } from "node:url";
import path from "node:path";

const RACINE = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..", "..");
const WEB = path.join(RACINE, "web");

// ---------------------------------------------------------------------------------------------
// SHIM DOM — le strict nécessaire pour que les modules se chargent et construisent un arbre.
// ---------------------------------------------------------------------------------------------
class Element {
  constructor(tag) {
    this.tagName = String(tag).toUpperCase();
    this.children = [];
    this.parentNode = null;
    this.attributes = {};
    this.style = {};
    this.dataset = {};
    this.hidden = false;
    this.value = "";
    this.options = [];
    this.selectedIndex = -1;
    this._text = "";
    this._classes = new Set();
    this.classList = {
      add: (...c) => c.forEach((x) => this._classes.add(x)),
      remove: (...c) => c.forEach((x) => this._classes.delete(x)),
      toggle: (x, f) => { if (f === undefined ? !this._classes.has(x) : f) this._classes.add(x); else this._classes.delete(x); },
      contains: (x) => this._classes.has(x),
    };
  }
  get className() { return [...this._classes].join(" "); }
  set className(v) { this._classes = new Set(String(v).split(/\s+/).filter(Boolean)); }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(""); }
  set textContent(v) { this._text = String(v ?? ""); this.children = []; }
  get innerHTML() { return this._html ?? ""; }
  set innerHTML(v) { this._html = String(v); this.children = []; this._text = ""; }
  get innerText() { return this.textContent; }
  set innerText(v) { this.textContent = v; }
  get firstChild() { return this.children[0] ?? null; }
  get lastChild() { return this.children[this.children.length - 1] ?? null; }
  get childNodes() { return this.children; }
  get isConnected() { return true; }
  appendChild(c) { if (c instanceof Fragment) { c.children.forEach((x) => this.appendChild(x)); return c; } c.parentNode = this; this.children.push(c); return c; }
  append(...cs) { cs.forEach((c) => this.appendChild(typeof c === "string" ? document.createTextNode(c) : c)); }
  prepend(...cs) { cs.reverse().forEach((c) => { const n = typeof c === "string" ? document.createTextNode(c) : c; n.parentNode = this; this.children.unshift(n); }); }
  replaceChildren(...cs) { this.children = []; this._text = ""; this.append(...cs); }
  insertBefore(n, ref) { const i = this.children.indexOf(ref); n.parentNode = this; if (i < 0) this.children.push(n); else this.children.splice(i, 0, n); return n; }
  removeChild(c) { this.children = this.children.filter((x) => x !== c); return c; }
  remove() { if (this.parentNode) this.parentNode.removeChild(this); }
  replaceWith(...cs) { if (!this.parentNode) return; const p = this.parentNode, i = p.children.indexOf(this); p.children.splice(i, 1, ...cs); cs.forEach((c) => (c.parentNode = p)); }
  setAttribute(k, v) { this.attributes[k] = String(v); }
  getAttribute(k) { return this.attributes[k] ?? null; }
  removeAttribute(k) { delete this.attributes[k]; }
  hasAttribute(k) { return k in this.attributes; }
  addEventListener() {}
  removeEventListener() {}
  dispatchEvent() { return true; }
  focus() {} blur() {} click() {} scrollIntoView() {} select() {}
  closest() { return null; }
  contains(n) { return n === this || this.children.some((c) => c.contains && c.contains(n)); }
  getBoundingClientRect() { return { top: 0, left: 0, width: 0, height: 0, right: 0, bottom: 0 }; }
  querySelector() { return new Element("div"); }
  querySelectorAll() { return []; }
  getContext() { return null; }
  cloneNode() { const e = new Element(this.tagName); e.className = this.className; e._text = this._text; return e; }
}
class Text { constructor(t) { this._t = String(t); this.parentNode = null; } get textContent() { return this._t; } set textContent(v) { this._t = String(v); } contains() { return false; } }
class Fragment extends Element { constructor() { super("#fragment"); } }

const stockage = () => { const m = new Map(); return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), clear: () => m.clear(), key: (i) => [...m.keys()][i] ?? null, get length() { return m.size; } }; };

const document = {
  documentElement: new Element("html"),
  head: new Element("head"),
  body: new Element("body"),
  title: "",
  cookie: "",
  hidden: false,
  visibilityState: "visible",
  readyState: "complete",
  createElement: (t) => new Element(t),
  createElementNS: (_ns, t) => new Element(t),
  createTextNode: (t) => new Text(t),
  createDocumentFragment: () => new Fragment(),
  // Jamais `null` : un module qui câble `$('#x').onclick = …` au chargement ne doit pas s'arrêter ici.
  querySelector: () => new Element("div"),
  querySelectorAll: () => [],
  getElementById: () => new Element("div"),
  addEventListener() {}, removeEventListener() {},
  execCommand: () => false,
};
const fenetre = {
  document,
  localStorage: stockage(),
  sessionStorage: stockage(),
  location: { hash: "", pathname: "/", search: "", href: "http://plume.invalid/", origin: "http://plume.invalid", host: "plume.invalid", hostname: "plume.invalid", protocol: "http:", reload() {}, replace() {}, assign() {} },
  history: { pushState() {}, replaceState() {}, back() {}, state: null },
  navigator: { language: "fr-FR", userAgent: "harnais", clipboard: { writeText: async () => {} }, onLine: true },
  matchMedia: () => ({ matches: false, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} }),
  getComputedStyle: () => ({ getPropertyValue: () => "" }),
  requestAnimationFrame: (f) => setTimeout(f, 0),
  cancelAnimationFrame: (h) => clearTimeout(h),
  addEventListener() {}, removeEventListener() {}, dispatchEvent() { return true; },
  innerWidth: 1280, innerHeight: 800, devicePixelRatio: 1, scrollY: 0,
  scrollTo() {}, alert() {}, confirm: () => false, prompt: () => null, open() { return null; }, print() {},
  HTMLElement: Element, Element, Node: Element, Image: Element,
  MutationObserver: class { observe() {} disconnect() {} },
  ResizeObserver: class { observe() {} disconnect() {} unobserve() {} },
  IntersectionObserver: class { observe() {} disconnect() {} unobserve() {} },
  EventSource: class { constructor() { this.readyState = 0; } close() {} addEventListener() {} },
  WebSocket: class { constructor() { this.readyState = 0; } close() {} addEventListener() {} send() {} },
  // Réseau : absent par construction. Un appel au chargement d'un module est une faute, et elle se voit.
  fetch: undefined,
};
for (const [k, v] of Object.entries(fenetre)) Object.defineProperty(globalThis, k, { value: v, writable: true, configurable: true });
globalThis.window = globalThis;
globalThis.self = globalThis;

// Le texte d'un sous-arbre, tel qu'un lecteur le verrait (sans mise en page).
const texte = (el) => el.textContent;

// ---------------------------------------------------------------------------------------------
// 1. LE GRAPHE DE MODULES SE LIE — chaque module suivi de `web/`, sauf le service worker (il n'est
//    pas un module ES et lit des globales de son propre contexte).
// ---------------------------------------------------------------------------------------------
const modules = readdirSync(WEB).filter((f) => f.endsWith(".js") && f !== "sw.js").sort();
const liens = [];
for (const f of modules) {
  try {
    await import(pathToFileURL(path.join(WEB, f)).href);
  } catch (e) {
    liens.push(`${f} : ${e && e.name} — ${e && e.message}`);
  }
}
if (liens.length) {
  for (const l of liens) console.error(`::error::module web qui ne se charge pas : ${l}`);
  console.error(`\n${liens.length} module(s) sur ${modules.length} ne se chargent pas : l'interface serait VIDE.`);
  process.exit(1);
}
const PLANCHER_MODULES = 20;
if (modules.length < PLANCHER_MODULES) {
  console.error(`::error::seulement ${modules.length} modules découverts sous web/, plancher ${PLANCHER_MODULES} : la découverte est cassée, le harnais refuse de conclure.`);
  process.exit(2);
}

// ---------------------------------------------------------------------------------------------
// 2. LE VERDICT EST RENDU — panneau Système sur des objets fabriqués.
// ---------------------------------------------------------------------------------------------
const { rendreSysteme, lireMesure } = await import(pathToFileURL(path.join(WEB, "system.js")).href);
const echecs = [];
const exiger = (cond, msg) => { if (!cond) echecs.push(msg); };

// (a) TOUT ILLISIBLE — chaque famille d'émission du démon, avec une cause de l'ensemble fermé.
const illisible = (cause, detail) => ({ verdict: "illisible", cause, detail });
const poser = (obj, cle, m) => { if (m.verdict === "lu") obj[cle] = m.valeur; obj[cle + "_verdict"] = m.verdict; obj[cle + "_cause"] = m.cause; if (m.detail) obj[cle + "_detail"] = m.detail; return obj; };
const mA = {
  ts: 1000, version: "x", schema_version: 1, uptime_s: 10,
  process: { verdict: "illisible", cause: "source_absente", detail: "/proc/self/stat : absent" },
  // Une VALEUR à côté du verdict illisible : un chiffre résiduel ne doit JAMAIS passer devant le mot.
  ingest: poser({ events_total: 5, events_1h: 1, queue_depth: 42 }, "queue_depth", illisible("source_refusee", "spool : accès refusé")),
  search: { requests_total: 0, p50_ms: 0, p95_ms: 0, samples: 0 },
  scheduler: poser(poser({ rule_ticks_total: 3, rule_last_tick: 990 }, "regles_abandons", illisible("forme_inconnue", "regles : liste illisible")), "rapports_abandons", { verdict: "lu", valeur: 2, cause: "aucune" }),
  db: poser({}, "size_bytes", illisible("source_illisible", "stat : E/S")),
  host: poser({}, "identity", illisible("source_absente", "/etc/hostname : absent")),
  alerts_open: 0, http: { requests_total: 1, responses_5xx_total: 0 },
};
const hA = {
  posture: "yellow",
  components: [
    poser({ component: "store", state: "green", detail: "disque données 10% utilisé" }, "db_size_bytes", illisible("source_illisible", "stat : E/S")),
    poser({ component: "detection", state: "yellow", detail: "scheduler actif" }, "abandons_dernier_tick", { verdict: "lu", valeur: 4, cause: "aucune" }),
  ],
};
const wrapA = new Element("div");
rendreSysteme(wrapA, mA, hA);
const tuiles = (wrap) => wrap.children.find((c) => c.classList.contains("sys-grid")).children;
const tuile = (wrap, label) => tuiles(wrap).find((t) => t.children.some((c) => c.classList.contains("sys-tile-l") && c.textContent === label));
for (const [label, cause] of [["CPU cumulé", "source absente"], ["RSS mémoire", "source absente"], ["File spool", "accès refusé"], ["Taille base", "source illisible"], ["Identité hôte", "source absente"]]) {
  const t = tuile(wrapA, label);
  exiger(t, `(a) tuile « ${label} » absente du panneau`);
  if (!t) continue;
  const v = t.children.find((c) => c.classList.contains("sys-tile-v")).textContent;
  exiger(v === "NON LISIBLE", `(a) « ${label} » : verdict illisible rendu « ${v} » au lieu de l'état distinct « NON LISIBLE »`);
  exiger(v !== "0" && v !== "" && v !== "—" && !/^0(\.0)? /.test(v), `(a) « ${label} » : rendu aplati en « ${v} »`);
  exiger(t.classList.contains("sys-illisible"), `(a) « ${label} » : la tuile ne porte pas la classe d'état sys-illisible`);
  exiger(texte(t).includes(cause), `(a) « ${label} » : la cause « ${cause} » n'est pas nommée (texte : « ${texte(t)} »)`);
}
const bilansA = wrapA.children.find((c) => c.classList.contains("sys-bilans"));
exiger(bilansA, "(a) aucun bloc de bilans de boucles rendu");
if (bilansA) {
  const tb = texte(bilansA);
  exiger(/regles.*TICK AVEUGLE — forme non reconnue/s.test(tb), `(a) bilan de la boucle « regles » : tick aveugle non rendu comme tel (texte : « ${tb} »)`);
  exiger(/rapports.*2 abandon/s.test(tb), `(a) bilan de la boucle « rapports » : 2 abandons non visibles (texte : « ${tb} »)`);
  const lignes = bilansA.children.filter((c) => c.classList.contains("kv"));
  exiger(lignes.length === 2, `(a) ${lignes.length} ligne(s) de bilan au lieu de 2 : les boucles ne sont pas découvertes sur les clés publiées`);
}
const compsA = wrapA.children.find((c) => c.classList.contains("sys-comps"));
const ligneComp = (wrap, nom) => wrap.children.find((c) => c.classList.contains("sys-comps")).children.find((r) => r.children.some((x) => x.textContent === nom));
const store = ligneComp(wrapA, "store");
exiger(store && /taille base : NON LISIBLE \(source illisible\)/.test(texte(store)), `(a) composant store : taille de base illisible invisible à côté de l'état (texte : « ${store && texte(store)} »)`);
const det = ligneComp(wrapA, "detection");
exiger(det && /abandons du dernier tick : 4/.test(texte(det)), `(a) composant detection : 4 abandons invisibles (texte : « ${det && texte(det)} »)`);
void compsA;

// (b) TOUT LU — la valeur s'affiche, y compris un VRAI zéro, et aucun état d'erreur ne paraît.
const lu = (valeur) => ({ verdict: "lu", valeur, cause: "aucune" });
const mB = {
  ts: 1000, version: "x", schema_version: 1, uptime_s: 10,
  process: { cpu_seconds: 12.34, rss_bytes: 2048, verdict: "lu", cause: "aucune" },
  ingest: poser({ events_total: 5, events_1h: 1 }, "queue_depth", lu(0)),
  search: { requests_total: 0, p50_ms: 0, p95_ms: 0, samples: 0 },
  scheduler: poser({ rule_ticks_total: 3, rule_last_tick: 990 }, "regles_abandons", lu(0)),
  db: poser({}, "size_bytes", lu(3 * 1048576)),
  host: poser({}, "identity", { verdict: "lu", valeur: undefined, cause: "aucune" }),
  alerts_open: 0, http: { requests_total: 1, responses_5xx_total: 0 },
};
const hB = { posture: "green", components: [poser({ component: "store", state: "green", detail: "ok" }, "db_size_bytes", lu(10))] };
const wrapB = new Element("div");
rendreSysteme(wrapB, mB, hB);
for (const [label, attendu] of [["CPU cumulé", "12.3 s"], ["RSS mémoire", "2.0 Ko"], ["File spool", "0"], ["Taille base", "3.0 Mo"], ["Identité hôte", "lue"]]) {
  const t = tuile(wrapB, label);
  exiger(t, `(b) tuile « ${label} » absente du panneau`);
  if (!t) continue;
  const v = t.children.find((c) => c.classList.contains("sys-tile-v")).textContent;
  exiger(v === attendu, `(b) « ${label} » lue : rendu « ${v} » au lieu de « ${attendu} » — une version qui dirait toujours « non lisible » passerait le témoin (a) sans rien prouver`);
  exiger(!t.classList.contains("sys-illisible") && !texte(t).includes("NON LISIBLE"), `(b) « ${label} » lue : porte tout de même l'état illisible`);
}
const bilansB = wrapB.children.find((c) => c.classList.contains("sys-bilans"));
exiger(bilansB && /regles0$/.test(texte(bilansB).replace(/^.*boucle de fond/s, "")), `(b) bilan « regles » lu à zéro : doit rendre un VRAI zéro (texte : « ${bilansB && texte(bilansB)} »)`);
const storeB = ligneComp(wrapB, "store");
exiger(storeB && !/NON LISIBLE|non publié/.test(texte(storeB)), `(b) composant store lu : porte tout de même un état d'erreur (texte : « ${storeB && texte(storeB)} »)`);

// (c) RIEN DE PUBLIÉ — troisième état, distinct des deux autres (pas encore de tick, clé absente).
const mC = { ...mB, scheduler: { rule_ticks_total: 0 }, host: {}, db: {} };
const wrapC = new Element("div");
rendreSysteme(wrapC, mC, { posture: "green", components: [] });
const tC = tuile(wrapC, "Taille base");
exiger(tC && tC.children.find((c) => c.classList.contains("sys-tile-v")).textContent === "non publié", `(c) grandeur jamais publiée : rendu « ${tC && texte(tC)} » au lieu de « non publié »`);
exiger(/aucun bilan publié/.test(texte(wrapC.children.find((c) => c.classList.contains("sys-bilans")))), "(c) aucun bilan de boucle : le démarrage n'est pas dit");

// Le lecteur lui-même : un verdict NON lu l'emporte sur une valeur présente — c'est l'aplatissement
// que la garde nomme, et il ne doit pas pouvoir se reconstruire ici.
exiger(lireMesure({ x: 0, x_verdict: "illisible", x_cause: "source_absente" }, "x").verdict === "illisible", "lireMesure : une valeur présente à côté d'un verdict illisible a été prise pour une lecture");
// La propriété « le verdict l'emporte sur une valeur présente » est tenue DEUX fois (le lecteur retire la
// valeur, le rendu ne l'affiche que sur `lu`) : une mutation de l'un seul ne change pas le DOM. Cette
// assertion tient le lecteur SEUL, pour que la première ligne de défense ait son propre témoin.
exiger(lireMesure({ x: 42, x_verdict: "illisible", x_cause: "source_absente" }, "x").valeur === undefined, "lireMesure : la valeur 42 traverse à côté d'un verdict illisible — seul le rendu la retenait encore");
exiger(lireMesure({ x: 0, x_verdict: "lu", x_cause: "aucune" }, "x").valeur === 0, "lireMesure : un vrai zéro lu a été perdu");
exiger(lireMesure({ x_verdict: "inconnu", x_cause: "aucune" }, "x").verdict === "inconnu", "lireMesure : un mot de verdict inconnu du client a été rangé du côté « lu »");

// ---------------------------------------------------------------------------------------------
// 3. UN PLAYBOOK LIVRÉ ET UN RUNBOOK CRÉÉ RENDENT PAR LE MÊME CHEMIN (`P11.2-a`, `P11.2-b`).
//    Les deux lignes sortent de la même fabrique (`producer_ui.js`) : même classe de ligne, même
//    interrupteur qui porte le MOT de son état et la phrase de sa conséquence, même badge d'origine
//    (le codage inverse de `runbook.managed` est normalisé à la frontière), mêmes classes de bouton —
//    aucune classe sans règle CSS (`ghost`, `primary`). Le témoin inverse (ON <-> OFF) interdit qu'un
//    interrupteur qui dirait toujours le même mot passe.
// ---------------------------------------------------------------------------------------------
{
  const { pbRow } = await import(pathToFileURL(path.join(WEB, "detection_admin.js")).href);
  const { rbRow } = await import(pathToFileURL(path.join(WEB, "runbooks.js")).href);
  const livre = { id: 1, name: "SSH CVE (livré)", enabled: false, query: "search source=sshd | stats count by src_ip", is_soql: true, action_kind: "ban_ip", consequence: "bannit l'IP source pendant 4 h (témoin)", interval_s: 300, window_s: 3600, managed: 0 };
  const cree = { id: 7, key: "custom-x", name: "Runbook créé", match_kind: "tactic", match_key: "initial-access", description: "", managed: 0, active: true, steps: 3 };
  const ligneP = pbRow(livre, "observe");
  const ligneR = rbRow(cree);
  const signature = (row) => row.children.filter((c) => c.tagName !== "BUTTON").map((c) => c.className).join(" | ");
  exiger(ligneP.classList.contains("rulerow") && ligneR.classList.contains("rulerow"), `(3) les deux lignes ne portent pas la classe partagée rulerow (${ligneP.className} / ${ligneR.className})`);
  exiger(signature(ligneP) === signature(ligneR), `(3) structure différente entre playbook livré et runbook créé :\n  ${signature(ligneP)}\n  ${signature(ligneR)}`);
  const interrupteur = (row) => row.children.find((c) => c.classList.contains("producer-switch"));
  const sp = interrupteur(ligneP), sr = interrupteur(ligneR);
  exiger(sp && sr, "(3) l'interrupteur partagé manque sur l'une des deux lignes");
  if (sp && sr) {
    exiger(/\bOFF\b/.test(texte(sp)) && !/\bON\b/.test(texte(sp)), `(3) playbook livré désactivé : l'interrupteur ne dit pas OFF (« ${texte(sp)} »)`);
    exiger(texte(sp).includes("bannit l'IP source pendant 4 h"), `(3) la conséquence servie par le démon n'est pas rendue à côté de l'état (« ${texte(sp)} »)`);
    exiger(texte(sp).includes("Observation") && texte(sp).includes("PROPOSÉ"), `(3) le mode courant (Observation : proposé, pas exécuté) n'est pas dit (« ${texte(sp)} »)`);
    exiger(/\bON\b/.test(texte(sr)) && !/\bOFF\b/.test(texte(sr)), `(3) runbook créé actif : l'interrupteur ne dit pas ON (« ${texte(sr)} »)`);
  }
  const badge = (row) => { const n = row.children.find((c) => c.classList.contains("rulename")); return n && n.children.find((c) => c.classList.contains("mgbadge")); };
  exiger(badge(ligneP) && badge(ligneP).textContent === "builtin", `(3) playbook livré : badge d'origine « ${badge(ligneP) && badge(ligneP).textContent} » au lieu de builtin`);
  exiger(badge(ligneR) && badge(ligneR).textContent === "perso", `(3) runbook créé (runbook.managed=0 = custom) : badge « ${badge(ligneR) && badge(ligneR).textContent} » au lieu de perso — le codage inverse n'est pas normalisé`);
  const classesBoutons = (row) => row.children.filter((c) => c.tagName === "BUTTON").map((c) => c.className);
  const horsCharte = [...classesBoutons(ligneP), ...classesBoutons(ligneR)].filter((c) => c.split(/\s+/).some((k) => k && k !== "crud-btn" && k !== "mg-nodel"));
  exiger(horsCharte.length === 0, `(3) bouton(s) à classe sans règle CSS : ${horsCharte.join(", ")}`);
  exiger(classesBoutons(ligneR).length >= 3 && classesBoutons(ligneP).length >= 3, "(3) l'une des lignes n'a pas ses boutons d'action");
  // Témoin inverse : le mot suit l'état dans les deux familles.
  const sp2 = interrupteur(pbRow({ ...livre, enabled: true }, "active"));
  const sr2 = interrupteur(rbRow({ ...cree, active: false }));
  exiger(sp2 && /\bON\b/.test(texte(sp2)) && texte(sp2).includes("EXÉCUTÉ"), `(3) playbook ON en mode Actif : « ${sp2 && texte(sp2)} »`);
  exiger(sr2 && /\bOFF\b/.test(texte(sr2)), `(3) runbook désactivé : « ${sr2 && texte(sr2)} »`);
}

// ---------------------------------------------------------------------------------------------
// 4. LA LISTE DES ALERTES A UNE SEULE BARRE D'ACTIONS (`P11.1-b`, `P11.1-c`). Plate / Règle / Hôte /
//    Technique sont des TRIS ; la barre est rendue par UNE fonction pure sur le modèle {tri, portée,
//    hors case, facettes}. Témoin : sur TOUTES les combinaisons, le même jeu d'actions est présent ;
//    une action impossible est DÉSACTIVÉE avec sa raison, jamais absente. Témoin inverse : sans facette
//    l'acquittement est global, sous une facette il ne porte que sur les alertes affichées. Et le chip
//    de la facette source dit l'objet, la portée et l'étendue des dates (la cloche d'une source).
// ---------------------------------------------------------------------------------------------
{
  const { alertActionBarHtml, alertListModel } = await import(pathToFileURL(path.join(WEB, "alerts.js")).href);
  const { S } = await import(pathToFileURL(path.join(WEB, "state.js")).href);
  const attrs = (html, re) => [...html.matchAll(re)].map((m) => m[1]).sort();
  const boutons = (html) => [...html.matchAll(/<button\b([^>]*)>/g)].map((m) => m[1]);
  const signature = (html) => {
    const views = attrs(html, /data-g="([a-z]*)"/g).join(",");
    const acts = attrs(html, /data-act="([a-z-]+)"/g).filter((a) => !a.startsWith("clear-")).map((a) => (a.startsWith("ack") ? "ack" : a)).join(",");
    return `${views} / ${acts} / export:${html.includes("alertbar-export")}`;
  };
  const modeles = [];
  for (const view of ["", "rule", "host", "mitre"]) for (const scopeAll of [false, true]) for (const uncased of [true, false]) for (const facette of ["", "mitre", "source"]) {
    if (facette === "source" && view) continue; // la facette source force la vue plate (limite nommée, cf. RAISON_FACETTE_SOURCE)
    modeles.push({ view, scopeAll, uncased, mitre: facette === "mitre" ? "T1046" : "", source: facette === "source" ? "k8s" : "" });
  }
  const charges = { count: 3, countLabel: "3 alerte(s)", ackableIds: [1, 2, 3] };
  const signatures = new Set(modeles.map((m) => signature(alertActionBarHtml(m, charges))));
  exiger(signatures.size === 1, `(4) ${signatures.size} jeux d'actions différents selon la vue au lieu d'un seul :\n  ${[...signatures].join("\n  ")}`);
  exiger([...signatures][0].startsWith(",host,mitre,rule / ack,scope,uncased / export:true"), `(4) jeu d'actions inattendu : ${[...signatures][0]}`);
  // Sous la facette source : les tris groupés et la portée sont DÉSACTIVÉS avec leur raison, pas retirés.
  const sousSource = alertActionBarHtml({ view: "", scopeAll: false, uncased: false, mitre: "", source: "k8s" }, { ...charges, sourceSpan: { from: 1_700_000_000, to: 1_700_090_000 } });
  const desactives = boutons(sousSource).filter((b) => /\bdisabled\b/.test(b));
  exiger(desactives.length === 4, `(4) sous la facette source, ${desactives.length} bouton(s) désactivé(s) au lieu de 4 (3 tris groupés + portée)`);
  exiger(desactives.every((b) => /title="[^"]*côté client[^"]*"/.test(b)), "(4) un bouton désactivé sous la facette source ne porte pas sa raison");
  exiger(!/data-act="ack-all"/.test(sousSource) && /data-act="ack-shown"/.test(sousSource) && /Acquitter les 3 affichée/.test(sousSource), "(4) sous une facette, l'acquittement doit porter sur les 3 alertes affichées, jamais être global");
  exiger(/Source : /.test(sousSource) && /3 alerte\(s\) active\(s\) imputée\(s\) à cette source, toutes dates \(du .+ au .+\)/.test(sousSource) && /sans lien avec sa fraîcheur/.test(sousSource), `(4) le chip de la facette source ne dit pas objet + portée + étendue des dates + indépendance de la fraîcheur : ${sousSource.match(/Source : .*?<\/span><button/)?.[0]}`);
  // Témoin inverse : sans facette, sur les actives, l'acquittement est GLOBAL et le dit.
  const sansFacette = alertActionBarHtml({ view: "rule", scopeAll: false, uncased: true, mitre: "", source: "" }, { count: 9, countLabel: "9 groupe(s)", ackableIds: [] });
  exiger(/data-act="ack-all"[^>]*title="[^"]*y compris celles hors de cette page/.test(sansFacette) && !/\bdisabled\b[^>]*>[^<]*Tout acquitter/.test(sansFacette), "(4) sans facette, « Tout acquitter » doit être global, actif, et dire qu'il dépasse la page");
  // Vue groupée sous facette technique : rien d'affiché à acquitter par liste -> désactivé AVEC la raison.
  const groupeFacette = alertActionBarHtml({ view: "host", scopeAll: true, uncased: false, mitre: "T1046", source: "" }, { count: 2, countLabel: "2 groupe(s)", ackableIds: [] });
  exiger(/data-act="ack-shown" disabled[^>]*title="[^"]*dépliez un groupe/.test(groupeFacette), "(4) en vue groupée sous facette, l'acquittement doit être désactivé avec la raison « dépliez un groupe »");
  // Le modèle lit l'état partagé, et « hors case » vaut oui par défaut (champ absent).
  S.alertGroupBy = "host"; S.alertGroupAll = true; S.alertMitreFilter = "T1110"; S.alertSourceFilter = ""; delete S.alertUncased;
  const m = alertListModel();
  exiger(m.view === "host" && m.scopeAll === true && m.uncased === true && m.mitre === "T1110" && m.source === "", `(4) alertListModel ne reflète pas l'état : ${JSON.stringify(m)}`);
  S.alertUncased = false;
  exiger(alertListModel().uncased === false, "(4) alertListModel : « hors case » posé à faux n'est pas lu");
  S.alertGroupBy = ""; S.alertGroupAll = false; S.alertMitreFilter = ""; S.alertUncased = true;
}

// ---------------------------------------------------------------------------------------------
// 4. LA RECHERCHE ET LA COUVERTURE ATT&CK (`P11.6-a`, `P11.9-a`, `P11.9-b`, `P11.9-c`).
//    (a) Une technique sans nom se DIT : « nom inconnu », jamais une cellule vide ; une sous-technique
//        que le démon n'a pas nommée se résout par son parent côté client.
//    (b) L'éditeur de requête ne réécrit JAMAIS `!=` : une séquence de frappe réelle (regex avec `|`,
//        puis espace, puis Entrée/Tab) laisse le « différent » en place — et le témoin inverse prouve
//        que la complétion est bien VIVANTE sur cet éditeur (Tab accepte une suggestion). La cause
//        mesurée du constat est la ligature `!=` de la police (calt) : l'éditeur la coupe, et c'est tenu.
//    (c) La palette « Modèles » liste mes modèles (modifiables, supprimables) ET les modèles livrés
//        (copiables), avec ses états vides et indisponibles nommés.
//    (d) Le badge de troncature dit ce qui s'est passé et comment continuer selon le contexte de
//        feuilletage (saut direct par numéro de page vs parcours par curseur vs total).
// ---------------------------------------------------------------------------------------------
{
  const { techniqueCell, techniqueDisplayName, NOM_INCONNU } = await import(pathToFileURL(path.join(WEB, "attack.js")).href);
  // (a) nom servi par le démon
  let c = techniqueCell({ tid: "T1110", name: "Brute Force", covered: true, rule_count: 1, alert_count: 0 }, 1);
  exiger(texte(c).includes("Brute Force"), `(4a) nom servi non rendu : « ${texte(c)} »`);
  // nom ABSENT (null) et identifiant hors catalogue -> le MOT, pas un vide
  c = techniqueCell({ tid: "T9999", name: null, covered: false }, 1);
  const nomEl = c.children.find((x) => x.classList.contains("attack-tname"));
  exiger(nomEl && nomEl.textContent === NOM_INCONNU, `(4a) technique hors catalogue : nom rendu « ${nomEl && nomEl.textContent} » au lieu de « ${NOM_INCONNU} »`);
  exiger(nomEl && nomEl.classList.contains("attack-tname-inconnu"), "(4a) la cellule sans nom ne porte pas sa classe d'état");
  exiger(c.title.includes(NOM_INCONNU) && c.title.includes("hors du catalogue"), `(4a) l'infobulle ne dit pas pourquoi le nom manque : « ${c.title} »`);
  // sous-technique sans nom servi -> résolue par le parent via la table locale
  exiger(techniqueDisplayName({ tid: "T1110.003" }) === "Brute Force", `(4a) sous-technique non nommée par le démon : « ${techniqueDisplayName({ tid: "T1110.003" })} » au lieu du parent`);
  exiger(techniqueDisplayName({ tid: "T1110", name: "   " }) === "Brute Force", "(4a) un nom vide servi doit compter comme absent");
  exiger(techniqueDisplayName({ tid: "T9999" }) === null, "(4a) hors catalogue -> null (la cellule dit le mot), pas une chaîne");

  // (b) l'éditeur — objet fabriqué qui porte la sélection et dispatch ses écouteurs.
  const { primeCompletionMeta, initSoqlComplete } = await import(pathToFileURL(path.join(WEB, "soql_complete.js")).href);
  class Editeur extends Element {
    constructor() { super("textarea"); this.selectionStart = 0; this.selectionEnd = 0; this._ecouteurs = {}; }
    addEventListener(type, fn) { (this._ecouteurs[type] = this._ecouteurs[type] || []).push(fn); }
    dispatchEvent(ev) { (this._ecouteurs[ev.type] || []).forEach((f) => f(ev)); return true; }
    setSelectionRange(a, b) { this.selectionStart = a; this.selectionEnd = b; }
  }
  const schema = {
    base_keywords: ["search", "metric"], commands: ["where", "stats", "table", "sort"],
    stats_functions: ["count", "sum"], eval_functions: ["if"], operators: ["=", "!=", ">", "<", ">=", "<=", "=~", ":"],
    fields: { core: ["ts", "host", "source", "message", "status", "severity"], extended: [] },
    values: { severity: [{ value: 1, label: "low" }, { value: 3, label: "high" }], source: ["sshd", "web"] },
  };
  primeCompletionMeta(schema, []);
  const ed = new Editeur();
  const getById = document.getElementById;
  document.getElementById = (id) => (id === "sql" ? ed : new Element("div"));
  initSoqlComplete();
  document.getElementById = getById;
  exiger(ed.dataset.acWired === "1", "(4b) l'éditeur fabriqué n'a pas été câblé par initSoqlComplete");
  exiger(ed.style.fontVariantLigatures === "none", `(4b) les ligatures de police ne sont pas coupées sur l'éditeur (« ${ed.style.fontVariantLigatures} ») : un « != » tapé s'afficherait comme un glyphe barré`);
  const pause = () => new Promise((r) => setTimeout(r, 0));
  const touche = (key) => ({ type: "keydown", key, ctrlKey: false, metaKey: false, preventDefault() {} });
  const taper = async (texte) => {
    for (const ch of texte) {
      ed.dispatchEvent(touche(ch));
      const p = ed.selectionStart;
      ed.value = ed.value.slice(0, p) + ch + ed.value.slice(p);
      ed.setSelectionRange(p + 1, p + 1);
      ed.dispatchEvent({ type: "input" });
      await pause();
    }
  };
  const sequences = [
    'search message=~"(foo|bar)" status!=200',
    'search message=~"^a.*b$" severity!=3',
    'search host!=db | where source!=sshd',
  ];
  for (const seq of sequences) {
    ed.value = ""; ed.setSelectionRange(0, 0);
    await taper(seq);
    exiger(ed.value === seq, `(4b) la frappe seule a altéré le texte : « ${ed.value} »`);
    await taper(" ");
    exiger(ed.value === seq + " ", `(4b) l'espace après « ${seq} » a réécrit le texte : « ${ed.value} »`);
    const avantEntree = ed.value;
    ed.dispatchEvent(touche("Enter")); await pause();
    exiger(ed.value.includes("!="), `(4b) Entrée après l'espace a fait disparaître « != » : « ${ed.value} »`);
    const nbDiff = (ed.value.match(/!=/g) || []).length, nbAttendu = (avantEntree.match(/!=/g) || []).length;
    exiger(nbDiff === nbAttendu, `(4b) le nombre de « != » a changé après Entrée (${nbAttendu} -> ${nbDiff}) : « ${ed.value} »`);
  }
  // Témoin INVERSE : la complétion est vivante sur cet éditeur — Tab sur « sever » insère « severity ».
  ed.value = ""; ed.setSelectionRange(0, 0);
  await taper("search sever");
  ed.dispatchEvent(touche("Tab")); await pause();
  exiger(ed.value.startsWith("search severity"), `(4b) témoin inverse : Tab n'a pas complété « sever » (« ${ed.value} ») — l'éditeur fabriqué n'est pas relié à la complétion, les témoins précédents ne prouvent rien`);

  // (c) la palette des modèles
  const { renderTemplatePalette } = await import(pathToFileURL(path.join(WEB, "soql_complete.js")).href);
  const appels = [];
  const actions = { load: (m) => appels.push(["load", m]), edit: (m) => appels.push(["edit", m]), remove: (m) => appels.push(["remove", m]), copy: (m) => appels.push(["copy", m]) };
  const mien = { id: 1, name: "Mon modèle", soql: "search a" }, livre = { id: "lib-x", title: "Livré", soql: "search b", keywords: ["b"] };
  const liste = new Element("div");
  renderTemplatePalette(liste, "", [mien], [livre], actions);
  const t = texte(liste);
  exiger(t.includes("Mes modèles") && t.includes("Mon modèle") && t.includes("Modèles livrés") && t.includes("Livré"), `(4c) palette : sections ou lignes absentes (« ${t} »)`);
  const lignes = liste.children.filter((x) => x.classList.contains("soql-tpl-item"));
  exiger(lignes.length === 2, `(4c) ${lignes.length} ligne(s) au lieu de 2`);
  const titres = (row) => row.children.filter((x) => x.tagName === "BUTTON").map((x) => x.title);
  exiger(titres(lignes[0]).includes("Modifier ce modèle") && titres(lignes[0]).includes("Supprimer ce modèle"), `(4c) un modèle personnel ne porte pas modifier + supprimer : ${titres(lignes[0]).join(" / ")}`);
  exiger(titres(lignes[1]).some((x) => x.startsWith("Copier dans mes modèles")) && !titres(lignes[1]).includes("Supprimer ce modèle"), `(4c) un modèle livré doit se copier et ne pas se supprimer : ${titres(lignes[1]).join(" / ")}`);
  renderTemplatePalette(liste, "", [], [livre], actions);
  exiger(texte(liste).includes("Aucun modèle personnel"), "(4c) l'état vide des modèles personnels n'est pas nommé");
  renderTemplatePalette(liste, "", null, [livre], actions);
  exiger(texte(liste).includes("indisponibles"), "(4c) un chargement échoué des modèles personnels n'est pas distingué d'une liste vide");
  renderTemplatePalette(liste, "b", [mien], [livre], actions);
  exiger(!texte(liste).includes("Mon modèle") && texte(liste).includes("Livré"), "(4c) le filtre ne s'applique pas aux deux groupes");

  // (d) le badge de troncature selon le contexte de feuilletage
  const { truncationBadge } = await import(pathToFileURL(path.join(WEB, "viz.js")).href);
  const saut = truncationBadge({ truncated: true }, { keyset: true, saut: true, page: 7 });
  exiger(/page sautée/.test(saut[1]) && /partiel/.test(saut[1]), `(4d) page sautée : libellé « ${saut[1]} »`);
  exiger(saut[2].includes("◀") && saut[2].includes("curseur") && /page 1/.test(saut[2]), `(4d) page sautée : l'infobulle ne dit pas comment continuer (« ${saut[2]} »)`);
  const curseur = truncationBadge({ truncated: true }, { keyset: true, saut: false, page: 2 });
  exiger(/plafond/.test(curseur[1]) && /page plus petite/.test(curseur[2]), `(4d) page par curseur tronquée : « ${curseur[1]} / ${curseur[2]} »`);
  const total = truncationBadge({ truncated: true }, null);
  exiger(total[1] === "tronqué — ampleur inconnue" && /Resserrez/.test(total[2]), `(4d) hors feuilletage : « ${total[1]} / ${total[2]} »`);
  const chiffre = truncationBadge({ truncated: true, topn_ecartes: 40, topn_total: 100 }, { keyset: true, saut: true, page: 3 });
  exiger(/40.*écartés.*40 %/.test(chiffre[1]), `(4d) une ampleur CHIFFRÉE doit l'emporter sur le contexte : « ${chiffre[1]} »`);
}

// ---------------------------------------------------------------------------------------------
// 5. L'INVENTAIRE DES SOURCES (`P11.3-a`) — attendue par construction / inattendue / marquée, et le
//    geste d'acquittement offert à l'éditeur, rendus sur des objets fabriqués.
// ---------------------------------------------------------------------------------------------
{
  const { renderSourcesInventory } = await import(pathToFileURL(path.join(WEB, "sources.js")).href);
  // parcours du tableau rendu par pagedList : lignes <tr> du <tbody>, cellules <td>, texte par cellule.
  const lignesDe = (wrap) => {
    const out = [];
    const marcher = (el) => { if (!el || !el.children) return; if (el.tagName === "TR" && el.parentNode && el.parentNode.tagName === "TBODY") out.push(el); el.children.forEach(marcher); };
    marcher(wrap);
    return out;
  };
  const celluleTexte = (tr, i) => texte(tr.children[i]);
  const enTetes = (wrap) => { let th = []; const marcher = (el) => { if (!el || !el.children) return; if (el.tagName === "THEAD") th = el.children[0].children.map((x) => texte(x)); el.children.forEach(marcher); }; marcher(wrap); return th; };
  const inventaire = {
    ok: true, pipeline_fresh: true, sources: [
      // livrée par ce dépôt : attendue par construction, la raison nomme le fichier ; calme sans cadence déclarée.
      { source: "portprobe", expected: true, unexpected: false, in_collectors: true, raison_attendue: "émise par un fichier livré (collectors/portprobe.sh)", marquage: null, cadence_declaree: "non_declaree", cadence_interval_s: null, cadence_capteur: null, observed_interval_s: 72, last_seen: 1000, age_s: 7200, n_24h: 1200, status: "calme" },
      // rien ne la déclare, personne ne l'a marquée : le signal.
      { source: "derive-deploiement", expected: false, unexpected: true, in_collectors: false, raison_attendue: null, marquage: null, cadence_declaree: "non_declaree", cadence_interval_s: null, cadence_capteur: null, observed_interval_s: 3600, last_seen: 1000, age_s: 3000, n_24h: 24, status: "calme" },
      // marquée attendue par un éditeur : qui et quand sont rendus.
      { source: "vault-custom", expected: true, unexpected: false, in_collectors: false, raison_attendue: "marquée attendue par eve (ts 1700000000)", marquage: { expected: true, updated_by: "eve", updated: 1700000000 }, cadence_declaree: "non_declaree", cadence_interval_s: null, cadence_capteur: null, observed_interval_s: 600, last_seen: 1000, age_s: 120, n_24h: 144, status: "frais" },
      // continue déclarée et dépassée : en retard, avec la cadence et la sonde.
      { source: "auditd", expected: true, unexpected: false, in_collectors: true, raison_attendue: "émise par un fichier livré (collectors/auditd.sh)", marquage: null, cadence_declaree: "continue", cadence_interval_s: 120, cadence_capteur: "audit", observed_interval_s: 30, last_seen: 1000, age_s: 1200, n_24h: 2880, status: "en_retard" },
    ],
  };
  const ligne = (rows, nom) => rows.find((tr) => celluleTexte(tr, 0).startsWith(nom));
  // (a) LECTEUR (viewer) : verdicts et raisons rendus, aucune colonne d'action.
  document.body.className = "role-viewer";
  const invA = new Element("div");
  renderSourcesInventory(invA, inventaire);
  const lignesA = lignesDe(invA);
  exiger(lignesA.length === 4, `(inventaire) ${lignesA.length} ligne(s) rendue(s) au lieu de 4`);
  const colsA = enTetes(invA);
  exiger(!colsA.includes("Actions"), `(inventaire, viewer) une colonne Actions est offerte à un rôle qui ne peut pas marquer (${colsA.join(", ")})`);
  const lPort = ligne(lignesA, "portprobe"), lDer = ligne(lignesA, "derive-deploiement"), lVc = ligne(lignesA, "vault-custom"), lAud = ligne(lignesA, "auditd");
  exiger(lPort && !celluleTexte(lPort, 0).includes("inattendu"), "(inventaire) une source LIVRÉE porte le badge « inattendu » : la dérivation n'est pas lue");
  exiger(lPort && texte(lPort).includes("collectors/portprobe.sh"), `(inventaire) la raison « attendue par construction » (fichier livré) n'est pas rendue : « ${lPort && texte(lPort)} »`);
  exiger(lDer && celluleTexte(lDer, 0).includes("inattendu"), "(inventaire) une source que rien ne déclare ne porte PAS le badge « inattendu »");
  exiger(lDer && celluleTexte(lDer, 1).includes("non déclarée"), `(inventaire) le « non » d'une source inattendue n'est pas expliqué : « ${lDer && celluleTexte(lDer, 1)} »`);
  exiger(lVc && !celluleTexte(lVc, 0).includes("inattendu") && texte(lVc).includes("marquée attendue par eve"), `(inventaire) le marquage (qui) n'est pas rendu : « ${lVc && texte(lVc)} »`);
  exiger(lAud && texte(lAud).includes("en retard") && texte(lAud).includes("continu · 2 min"), `(inventaire) « en retard » et la cadence déclarée ne sont pas rendus : « ${lAud && texte(lAud)} »`);
  exiger(lPort && texte(lPort).includes("calme") && !texte(lPort).includes("retard") && texte(lPort).includes("non déclarée"), `(inventaire) une source sans cadence déclarée, silencieuse 2 h, doit lire « calme » et « non déclarée » : « ${lPort && texte(lPort)} »`);
  exiger(texte(invA).includes("1 source(s) que rien ne déclare"), "(inventaire) le compte des signaux n'est pas rendu en tête");
  exiger(!texte(invA).includes("dégradé"), "(inventaire) le mot « dégradé » survit dans l'inventaire");
  // (b) ÉDITEUR : la colonne Actions existe et offre « marquer attendue » sur le signal, « marquer inattendue » sur l'acquittée.
  document.body.className = "role-editor";
  const invB = new Element("div");
  renderSourcesInventory(invB, inventaire);
  const colsB = enTetes(invB);
  exiger(colsB.includes("Actions"), `(inventaire, editor) aucune colonne Actions : l'éditeur n'a toujours aucune issue (${colsB.join(", ")})`);
  const lignesB = lignesDe(invB);
  const actionsDe = (tr) => { const td = tr.children[tr.children.length - 1]; const out = []; const marcher = (el) => { if (!el || !el.children) return; if (el.tagName === "BUTTON") out.push(texte(el)); el.children.forEach(marcher); }; marcher(td); return out; };
  exiger(actionsDe(ligne(lignesB, "derive-deploiement")).includes("marquer attendue"), `(inventaire, editor) le signal n'offre pas « marquer attendue » : ${JSON.stringify(actionsDe(ligne(lignesB, "derive-deploiement")))}`);
  exiger(actionsDe(ligne(lignesB, "vault-custom")).includes("marquer inattendue"), "(inventaire, editor) une source marquée n'offre pas le geste inverse (réversibilité)");
  exiger(texte(invB).includes("Actions → « marquer attendue »"), "(inventaire, editor) l'en-tête ne dit pas à l'éditeur où est le geste");
  document.body.className = "";
}

// ---------------------------------------------------------------------------------------------
// 6. LA FRAÎCHEUR (`P11.3-b`) — le statut vient du démon ; une périodique dans sa cadence est « frais »
//    ou « calme », jamais « en retard » ; « dégradé » n'existe plus ; les alertes sont un compte.
// ---------------------------------------------------------------------------------------------
{
  const { renderFreshnessDetail, freshState, countStates } = await import(pathToFileURL(path.join(WEB, "freshness.js")).href);
  const feeds = {
    pipeline_fresh: true, unattributed_alerts: 0, feeds: [
      // périodique (courrier) à 66 min sans cadence déclarée : calme — le cas du constat.
      { kind: "event", name: "mail", status: "calme", age_s: 66 * 60, last_seen: 1000, n_24h: 96, active_alerts: 0, cadence_declaree: "non_declaree", cadence_interval_s: null, cadence_capteur: null, observed_interval_s: 900 },
      // périodique DANS sa cadence : frais.
      { kind: "event", name: "kube-rbac", status: "frais", age_s: 600, last_seen: 1000, n_24h: 48, active_alerts: 0, cadence_declaree: "non_declaree", cadence_interval_s: null, cadence_capteur: null, observed_interval_s: 1800 },
      // continue déclarée, silence au-delà : en retard, la raison est dite.
      { kind: "event", name: "kube-audit", status: "en_retard", age_s: 1500, last_seen: 1000, n_24h: 5000, active_alerts: 0, cadence_declaree: "continue", cadence_interval_s: 120, cadence_capteur: "kube-audit", observed_interval_s: 17 },
      // frais avec alertes actives : la cloche, pas un état.
      { kind: "event", name: "cloudflare", status: "frais", age_s: 30, last_seen: 1000, n_24h: 3000, active_alerts: 2, cadence_declaree: "non_declaree", cadence_interval_s: null, cadence_capteur: null, observed_interval_s: 28 },
      // événementiel, deux jours de calme : calme.
      { kind: "event", name: "yara", status: "calme", age_s: 172800, last_seen: 1000, n_24h: 0, active_alerts: 0, cadence_declaree: "evenementielle", cadence_interval_s: null, cadence_capteur: "yara", observed_interval_s: null },
    ],
  };
  const html = renderFreshnessDetail(feeds);
  const brut = html.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
  exiger(!/dégradé/.test(brut), "(fraîcheur) le mot « dégradé » survit dans le détail");
  exiger(/2 frais/.test(brut) && /2 calme/.test(brut) && /1 en retard/.test(brut), `(fraîcheur) compteurs de tête faux : « ${brut.slice(0, 400)} »`);
  exiger(/1 avec alertes actives/.test(brut), "(fraîcheur) les alertes actives ne sont pas comptées à part en tête");
  exiger(freshState(feeds.feeds[0]) === "calme", `(fraîcheur) le courrier à 66 min lit « ${freshState(feeds.feeds[0])} » au lieu de « calme »`);
  exiger(freshState(feeds.feeds[1]) === "frais", "(fraîcheur) une périodique dans sa cadence ne lit pas « frais »");
  exiger(freshState(feeds.feeds[3]) === "frais", "(fraîcheur) des alertes actives font basculer l'état de collecte");
  exiger(freshState({ status: "warn" }) === "calme" && freshState({ status: "inconnu" }) === "attente", "(fraîcheur) un mot inconnu du client n'est pas rangé du côté calme / attente");
  const sc = countStates(feeds.feeds);
  exiger(sc.frais === 2 && sc.calme === 2 && sc.en_retard === 1 && sc.muet === 0 && sc.alertes === 1, `(fraîcheur) agrégation ${JSON.stringify(sc)}`);
  exiger(/en retard — cadence déclarée dépassée/.test(brut), "(fraîcheur) le groupe « en retard » ne dit pas ce qu'il désigne");
  exiger(/kube-audit[^]*?au-delà de 2 min/.test(brut), `(fraîcheur) la ligne en retard ne nomme pas la cadence dépassée : « ${brut} »`);
  exiger(/mail cadence non déclarée/.test(brut) && /yara événementiel/.test(brut) && /kube-audit continu · 2 min/.test(brut), `(fraîcheur) la cadence déclarée n'est pas rendue à côté du nom : « ${brut} »`);
  exiger(/Il ne devient un retard que pour une source dont la sonde DÉCLARE une cadence continue/.test(brut), "(fraîcheur) l'en-tête ne dit plus ce qu'est un retard");
  exiger(!/expected_s|4x|4×/.test(html), "(fraîcheur) la surface dérive encore un retard d'une moyenne observée");
  // pipeline en panne : tout muet, le bandeau rouge.
  const panne = renderFreshnessDetail({ pipeline_fresh: false, feeds: feeds.feeds.map((f) => ({ ...f, status: "muet" })) }).replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
  exiger(/Ingestion en panne/.test(panne) && /5 muet/.test(panne), "(fraîcheur) l'ingestion en panne n'est pas rendue muette partout");
}

// ---------------------------------------------------------------------------------------------
// 7. LES COMPOSANTS PARTAGÉS DE L'ADMINISTRATION (`P11.4-a`, `P11.4-b`, `P11.5-b`) — une carte se
//    replie par le bouton qui l'a ouverte et ce bouton n'est jamais grisé ; un formulaire de création
//    rendu par un module porte les classes partagées (primaire / secondaire) et aucun bouton nu ; la
//    confirmation partagée REFUSE de se poser sans conséquence nommée, bloque quand on l'écarte, laisse
//    passer quand on la valide.
// ---------------------------------------------------------------------------------------------
{
  const { disclosure, confirmWithConsequence } = await import(pathToFileURL(path.join(WEB, "core.js")).href);
  // (a) dépli : ouvrir, refermer, état du bouton.
  const btn = new Element("button"), panel = new Element("div"); panel.id = "p"; panel.classList.add("hidden");
  const d = disclosure(btn, panel);
  exiger(d && btn.getAttribute("aria-expanded") === "false", "(dépli) le bouton ne porte pas son état fermé à l'armement");
  btn.onclick();
  exiger(!panel.classList.contains("hidden") && !panel.hidden, "(dépli) le premier clic n'ouvre pas la carte");
  exiger(btn.getAttribute("aria-expanded") === "true" && btn.classList.contains("on"), "(dépli) la carte ouverte ne se lit pas sur le bouton");
  exiger(btn.disabled !== true, "(dépli) le bouton est grisé pendant que la carte est ouverte");
  btn.onclick();
  exiger(panel.classList.contains("hidden") && panel.hidden === true, "(dépli) le second clic ne REPLIE pas la carte — c'est le constat de `P11.4-a`");
  exiger(btn.getAttribute("aria-expanded") === "false" && !btn.classList.contains("on"), "(dépli) la carte repliée ne se lit pas sur le bouton");
  // `isOpen`/`open`/`close` sur mesure (plusieurs boutons, un panneau) : le bouton dont le contenu n'est
  // pas affiché n'est pas « ouvert ».
  let contenu = null;
  const b2 = new Element("button"), b3 = new Element("button"), shared = new Element("div");
  const mk = (b, type) => disclosure(b, shared, { isOpen: () => contenu === type, open: () => { contenu = type; }, close: () => { contenu = null; } });
  mk(b2, "http"); mk(b3, "taxii");
  b2.onclick();
  exiger(contenu === "http" && b2.getAttribute("aria-expanded") === "true", "(dépli) ouverture sur mesure");
  b3.onclick();
  exiger(contenu === "taxii", "(dépli) un autre bouton sur le même panneau REMPLACE le contenu au lieu de replier");
  b3.onclick();
  exiger(contenu === null, "(dépli) le bouton dont le contenu est affiché replie au second clic");

  // (b) un formulaire de création rendu par un module : classes partagées, aucun bouton nu.
  const { openDestinationForm } = await import(pathToFileURL(path.join(WEB, "destinations.js")).href);
  const host = new Element("div"); host.id = "destination-form-host";
  const qsAvant = document.querySelector;
  document.querySelector = (sel) => (sel === "#destination-form-host" ? host : new Element("div"));
  try { openDestinationForm(null); } finally { document.querySelector = qsAvant; }
  const boutons = [], parcourir = (el, anc) => { if (!el || !el.children) return; for (const c of el.children) { if (c.tagName === "BUTTON") boutons.push({ el: c, anc: [...anc] }); parcourir(c, [...anc, c]); } };
  parcourir(host, []);
  exiger(boutons.length >= 2, `(classes) le formulaire de destination rend ${boutons.length} bouton(s), au moins 2 attendus`);
  const PARTAGEES = ["btn", "btn-primary", "btn-danger", "btn-link", "picon"];
  const nus = boutons.filter(({ el, anc }) => !PARTAGEES.some((k) => el.classList.contains(k)) && !anc.some((a) => a.classList.contains("rf-actions")));
  exiger(nus.length === 0, `(classes) ${nus.length} bouton(s) NU(s) dans le formulaire de destination : ${nus.map((n) => n.el.textContent).join(", ")} — c'est le constat de \`P11.4-b\``);
  exiger(boutons.some(({ el }) => el.classList.contains("btn-primary") && /Créer/.test(el.textContent)), "(classes) le bouton « Créer » ne porte pas la classe primaire partagée");
  exiger(boutons.some(({ el }) => el.classList.contains("btn") && /Annuler/.test(el.textContent)), "(classes) le bouton « Annuler » ne porte pas la classe secondaire partagée");

  // (c) la confirmation partagée : refuse sans conséquence, bloque quand écartée, laisse passer validée.
  let refusee = false;
  try { await confirmWithConsequence("Supprimer", ""); } catch (e) { refusee = true; }
  exiger(refusee, "(confirmation) une confirmation SANS conséquence nommée a été posée");
  const derniereOverlay = () => document.body.children.filter((c) => c.classList.contains("modal-ov")).pop();
  const p1 = confirmWithConsequence("Supprimer le compte « x »", "ses sessions cessent immédiatement");
  const ov1 = derniereOverlay();
  exiger(ov1, "(confirmation) aucune fenêtre posée");
  const html1 = ov1 ? ov1.children[0].children[0].innerHTML : "";
  exiger(/modal-consequence/.test(html1) && /ses sessions cessent immédiatement/.test(html1) && /Supprimer le compte/.test(html1), `(confirmation) la conséquence n'est pas rendue comme telle : « ${html1.slice(0, 200)} »`);
  ov1.onclick({ target: ov1 }); // écartée (clic hors de la boîte)
  exiger((await p1) === false, "(confirmation) écartée, elle LAISSE PASSER");
  const p2 = confirmWithConsequence("Enregistrer la rétention", "purge irréversible");
  const ov2 = derniereOverlay();
  ov2.children[0].children[0].onsubmit({ preventDefault() {} }); // validée
  exiger((await p2) === true, "(confirmation) validée, elle BLOQUE");
  // `fields` : la valeur saisie revient (ressaisie du nom d'un tenant), null quand écartée.
  const p3 = confirmWithConsequence("Supprimer le tenant", "destruction", { fields: [{ name: "confirm", label: "Nom" }] });
  const ov3 = derniereOverlay(); ov3.onclick({ target: ov3 });
  exiger((await p3) === null, "(confirmation) avec champs, écartée, ne rend pas null");
}

if (echecs.length) {
  for (const e of echecs) console.error(`::error::${e}`);
  console.error(`\n${echecs.length} témoin(s) en échec : la surface aplatit un verdict.`);
  process.exit(1);
}
console.log(`OK — ${modules.length} modules web se lient ; le panneau Système rend l'état « NON LISIBLE » avec sa cause sur 5 tuiles, les bilans de boucles et les grandeurs de composant, et la valeur quand le verdict est « lu » (vrai zéro compris) ; un playbook livré et un runbook créé rendent par la même fabrique de ligne, avec le mot de leur état et leur conséquence ; la liste des alertes rend une seule barre d'actions sur tous ses tris, et la facette source dit son objet et son étendue ; une technique ATT&CK sans nom se dit, l'éditeur de requête laisse « != » en place sous la frappe, la palette des modèles porte modifier/supprimer/copier, et le badge de troncature nomme le saut de page ; l'inventaire des sources rend attendue / inattendue / marquée avec la raison et offre l'acquittement à l'éditeur ; la fraîcheur rend le statut du démon (une périodique dans sa cadence = frais, jamais « dégradé ») et compte les alertes à part ; une carte d'administration se replie par son bouton sans jamais le griser, un formulaire de création ne rend aucun bouton nu, et la confirmation partagée exige une conséquence nommée, bloque écartée et passe validée.`);
