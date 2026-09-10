// catalogue_attack.js — LES NOMS DES TECHNIQUES ATT&CK, DÉRIVÉS DU CATALOGUE QUE LE DÉMON SERT. Module FEUILLE.
//
// `P11.6-c` (2026-09-10). La console portait une table de 14 libellés écrite à la main pour les surfaces dont
// les routes servent `mitre` NU (file d'alertes, administration des règles, couverture des détections) ; ce
// que la table ignorait arrivait à l'exploitant en numéro seul — `T1562`, cité par deux règles livrées, et
// une sous-technique d'exploitant, `T1195.002`, rencontrés SANS NOM en usage réel le 2026-08-27. Une table
// tenue à la main est une source qui vieillit sans le dire. Elle n'existe plus : le démon sert son catalogue
// ENTIER par une route dédiée (`GET /api/attack/catalogue`, constante, sans permis de requête), et ce module
// en dérive chaque libellé. Une technique qui apparaît demain dans une détection est nommée sans qu'aucune
// table de la console ait à être complétée — c'est la propriété que l'exploitant a ajoutée à la clé.
//
// CE QUE CE MODULE COMPOSE LUI-MÊME, ET AVEC QUOI. Un seul cas : une sous-technique dont le démon ne connaît
// que le parent (`T1195.002`). Il se compose à partir du nom SERVI du parent et du GABARIT SERVI
// (`forms.unknown_sub_technique`) — le même que le démon applique ; aucune forme n'est écrite ici.
//
// CE QUI EST DIT, ET JAMAIS TU. Un nom absent n'est pas une chaîne vide : `nomDeTechnique` rend l'ÉTAT
// (`servi`, `composé`, `hors catalogue`, `hors format`, `non chargé`, `indisponible`) et un MOTIF lisible pour
// tout état sans nom, que les surfaces affichent à la place du nom. Une console qui n'a pas encore reçu le
// catalogue le dit ; elle n'invente pas.
//
// POURQUOI UNE FEUILLE. `core.js` lit ce module (en-tête de groupe « technique ATT&CK ») et `core.js` est
// importé par presque tout : un module qui lirait `api` de `core.js` fermerait un cycle. Ce module n'importe
// donc RIEN ; le geste réseau lui est PRÊTÉ (`chargerLeCatalogueAttack(api)`, appelé à l'ouverture de session
// par `login.js`), et le harnais lui pose un objet sans réseau (`poserLeCatalogueAttack`).

/// Les clés de l'objet servi, telles que le démon les écrit (`attack_names::catalogue_attack_json`).
export const CLES_DU_CATALOGUE_SERVI = { techniques: 'techniques', sousTechniques: 'sub_techniques', formes: 'forms', sousTechniqueInconnue: 'unknown_sub_technique' };

/// Le registre : rempli une fois par session, lu par chaque surface qui nomme une technique.
export const CATALOGUE_ATTACK = { techniques: null, sousTechniques: null, formeSousTechniqueInconnue: null, etat: 'non chargé', cause: '' };

/// Le motif affiché à la place d'un nom, par état sans nom. Phrases FRANÇAISES, traduites par le lexique ;
/// posées sous `message:` — la forme que la garde du lexique reconnaît comme un texte SERVI.
const MOTIFS = {
  'hors catalogue': { message: 'nom inconnu : identifiant hors du catalogue ATT&CK du démon' },
  'hors format': { message: 'nom inconnu : identifiant hors format' },
  'non chargé': { message: 'nom non servi : catalogue des noms pas encore chargé' },
  'indisponible': { message: 'nom non servi : catalogue des noms indisponible' },
};

let chargement = null;

/// Pose l'objet servi SANS réseau. Rend `true` si la forme est celle du démon ; sinon l'état dit ce qui manque.
export function poserLeCatalogueAttack(corps) {
  const c = corps && typeof corps === 'object' ? corps : null;
  const techniques = c && c[CLES_DU_CATALOGUE_SERVI.techniques];
  const sous = c && c[CLES_DU_CATALOGUE_SERVI.sousTechniques];
  const forme = c && c[CLES_DU_CATALOGUE_SERVI.formes] && c[CLES_DU_CATALOGUE_SERVI.formes][CLES_DU_CATALOGUE_SERVI.sousTechniqueInconnue];
  const formeComplete = typeof forme === 'string' && forme.includes('{parent}') && forme.includes('{n}');
  if (!techniques || typeof techniques !== 'object' || Object.keys(techniques).length === 0 || !sous || typeof sous !== 'object' || !formeComplete) {
    CATALOGUE_ATTACK.techniques = null; CATALOGUE_ATTACK.sousTechniques = null; CATALOGUE_ATTACK.formeSousTechniqueInconnue = null;
    CATALOGUE_ATTACK.etat = 'indisponible'; CATALOGUE_ATTACK.cause = 'forme servie inattendue';
    return false;
  }
  CATALOGUE_ATTACK.techniques = techniques; CATALOGUE_ATTACK.sousTechniques = sous; CATALOGUE_ATTACK.formeSousTechniqueInconnue = forme;
  CATALOGUE_ATTACK.etat = 'chargé'; CATALOGUE_ATTACK.cause = '';
  return true;
}

/// Revient à l'état « non chargé » : ce que le harnais fait entre deux scénarios pour juger l'état initial, et
/// ce qu'une session qui se ferme laisserait. Aucun nom ne survit à l'oubli.
export function oublierLeCatalogueAttack() {
  CATALOGUE_ATTACK.techniques = null; CATALOGUE_ATTACK.sousTechniques = null; CATALOGUE_ATTACK.formeSousTechniqueInconnue = null;
  CATALOGUE_ATTACK.etat = 'non chargé'; CATALOGUE_ATTACK.cause = '';
}

/// Marque le catalogue indisponible, avec la cause (message d'erreur du geste réseau). Rien n'est inventé.
export function catalogueAttackIndisponible(cause) {
  CATALOGUE_ATTACK.techniques = null; CATALOGUE_ATTACK.sousTechniques = null; CATALOGUE_ATTACK.formeSousTechniqueInconnue = null;
  CATALOGUE_ATTACK.etat = 'indisponible'; CATALOGUE_ATTACK.cause = String(cause || '');
}

/// Charge le catalogue une fois par session, avec le geste réseau PRÊTÉ (`api` de `core.js`). Dédupliqué :
/// deux appelants partagent la même promesse. Rend `true` si le catalogue est posé. Silencieux en échec —
/// l'état et la cause sont dans le registre, et chaque surface les dit à la place du nom.
export function chargerLeCatalogueAttack(api) {
  if (CATALOGUE_ATTACK.etat === 'chargé') return Promise.resolve(true);
  if (chargement) return chargement;
  chargement = (async () => {
    try { return poserLeCatalogueAttack(await api('/attack/catalogue')); }
    catch (e) { catalogueAttackIndisponible(e && e.message ? e.message : e); return false; }
    finally { chargement = null; }
  })();
  return chargement;
}

/// Normalisation MIROIR de celle du démon : blancs, casse ; `T` + chiffres (+ `.` + chiffres), sinon null.
function identifiantNormalise(id) {
  const t = String(id == null ? '' : id).trim().toUpperCase();
  return /^T\d+(\.\d+)?$/.test(t) ? t : null;
}

/// Le nom d'une technique tel que le démon le rend, ou l'ÉTAT qui explique son absence. Jamais une chaîne vide.
///   { id, nom, etat, motif } — `nom` est null dès que `etat` n'est ni `servi` ni `composé`, et `motif` porte alors la phrase.
export function nomDeTechnique(id) {
  const norm = identifiantNormalise(id);
  const brut = String(id == null ? '' : id).trim();
  if (!norm) return { id: brut, nom: null, etat: 'hors format', motif: MOTIFS['hors format'].message };
  if (CATALOGUE_ATTACK.etat !== 'chargé') {
    const etat = CATALOGUE_ATTACK.etat === 'indisponible' ? 'indisponible' : 'non chargé';
    return { id: norm, nom: null, etat, motif: MOTIFS[etat].message };
  }
  const t = CATALOGUE_ATTACK.techniques[norm];
  if (t && typeof t.name === 'string' && t.name.trim()) return { id: norm, nom: t.name.trim(), etat: 'servi', motif: null };
  const s = CATALOGUE_ATTACK.sousTechniques[norm];
  if (s && typeof s.name === 'string' && s.name.trim()) return { id: norm, nom: s.name.trim(), etat: 'servi', motif: null };
  const point = norm.indexOf('.');
  if (point > 0) {
    const parent = CATALOGUE_ATTACK.techniques[norm.slice(0, point)];
    if (parent && typeof parent.name === 'string' && parent.name.trim()) {
      const nom = CATALOGUE_ATTACK.formeSousTechniqueInconnue.replace('{parent}', parent.name.trim()).replace('{n}', norm.slice(point + 1));
      return { id: norm, nom, etat: 'composé', motif: null };
    }
  }
  return { id: norm, nom: null, etat: 'hors catalogue', motif: MOTIFS['hors catalogue'].message };
}

/// « T1562 — Impair Defenses », ou « T9999 — nom inconnu : … » : l'identifiant suivi du nom ou du motif.
export function libelleDeTechnique(id) {
  const n = nomDeTechnique(id);
  return n.id + ' — ' + (n.nom || n.motif);
}
