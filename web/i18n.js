// i18n.js — dictionnaire FR->EN + application au DOM (extrait de app.js, ES module).
// Importe LANG depuis core.js ; i18nWalk est appelé au boot et par l'observer dans app.js.
import { LANG } from './core.js';

// ============ i18n FR/EN ============
// Dico FR->EN appliqué au DOM (les DONNÉES — logs, IP, messages — ne matchent aucune clé -> jamais
// traduites ; seuls les libellés connus le sont). Observer = traduit aussi le contenu rendu dynamiquement.
// Non traduit = reste en FR (dégradation gracieuse ; le dico s'étoffe). Actif seulement si LANG='en'.
const I18N_EN = {
  // navigation
  "Vue d'ensemble": "Overview", "Recherche & Explore": "Search & Explore", "Dashboards": "Dashboards",
  "Détection": "Detection", "Parsers": "Parsers", "Réponse": "Response", "Cases": "Cases", "Réglages": "Settings",
  "Navigation": "Navigation", "Menu": "Menu",
  // sections / titres
  "Alertes": "Alerts", "Firewall": "Firewall", "Contrôles (zéro-trou)": "Controls (zero-gap)",
  "Intégrations & hôtes": "Integrations & hosts", "Fraîcheur des sources": "Source freshness",
  "Règles de détection": "Detection rules", "Notifications": "Notifications", "Canaux de notification": "Notification channels",
  "Parsers (extraction de champs)": "Parsers (field extraction)", "Réseau sortant (egress)": "Outbound network (egress)",
  "Cases (gestion d'incident)": "Cases (incident management)", "Comptes & accès": "Accounts & access",
  "Résultats": "Results", "Capteurs": "Sensors", "Hôtes": "Hosts", "Playbooks": "Playbooks", "Actions": "Actions",
  // header / contrôles
  // P11 (2026-08-22) : chaînes posées par le superviseur — confirmation de source push, titres de la barre de recherche, porte des alertes
  "Créer et frapper le jeton": "Create and mint the token", "Nom de la source push": "Push source name", "Environnement (env_id)": "Environment (env_id)",
  "Enregistrer la requête courante dans mes modèles (nommée, persistante, privée à votre compte)": "Save the current query into my templates (named, persistent, private to your account)",
  "Modèles de requête : mes modèles (modifiables) et la bibliothèque livrée": "Query templates: my templates (editable) and the shipped library",
  "Ouvrir la liste des alertes": "Open the alert list", "Posture de sécurité — ouvrir la liste des alertes": "Security posture — open the alert list",
  "Types de sources & états (frais/calme/en retard/muet)": "Source types & states (fresh/quiet/late/silent)",
  "Navigateur": "Browser", "Posture de sécurité": "Security posture", "Rechercher dans les logs": "Search logs",
  "Rechercher dans les logs...  (ex: source:sshd failed)": "Search logs...  (e.g. source:sshd failed)",
  "Fenêtre temporelle": "Time window", "Rafraîchissement auto": "Auto-refresh", "Plage temporelle": "Time range",
  "Plage temporelle (presets + intervalle précis)": "Time range (presets + exact interval)",
  "Fuseau horaire d'affichage": "Display time zone",
  "Fuseau horaire d'affichage (stockage toujours en UTC)": "Display time zone (always stored in UTC)",
  "Langue / Language": "Language", "Changer de thème": "Toggle theme", "Thème clair / sombre": "Light / dark theme",
  "Tout": "All", "2 j": "2 d", "7 j": "7 d", "30 j": "30 d", "90 j": "90 d", "1 an": "1 yr", "Off": "Off",
  "Visualisation": "Visualization", "Table": "Table", "Barres": "Bars", "Courbe": "Line", "Stat": "Stat", "Suggestions": "Suggestions",
  // explore (Plume panel : destination des drilldowns ; « Plume panel » = nom propre, identique FR/EN)
  "Plume panel": "Plume panel",
  "Requête GXQL ou SQL — les drilldowns atterrissent ici": "GXQL or SQL query — drilldowns land here",
  "Détail :": "Detail:", "(drillé)": "(drilled)", "Effacer le fil d'Ariane": "Clear the breadcrumb",
  "Exécuter": "Run", "? Aide": "? Help", "← Retour": "← Back", "Aide": "Help", "Panneau": "Panel",
  "Enregistrer la requête comme panneau": "Save query as a panel", "Revenir à la requête précédente (drilldown)": "Back to previous query (drilldown)",
  "Aide : syntaxe des requêtes (GXQL)": "Help: query syntax (GXQL)",
  "Événements par page": "Events per page", "Événements par page (pagination)": "Events per page (pagination)",
  "Fenêtre temporelle (Explore)": "Time window (Explore)",
  "Fenêtre temporelle de la recherche — glissante depuis maintenant (perf)": "Search time window — sliding from now (perf)",
  "Arrêter la requête en cours": "Stop the running query",
  "Annulé": "Cancelled", "Trop lourd même sur 60s — resserre la fenêtre": "Too heavy even at 60s — narrow the window",
  // dashboards
  "Vue": "View", "Vue : ensemble de dashboards": "View: a set of dashboards", "Renommer la vue": "Rename view",
  "+ Vue": "+ View", "Nouvelle vue": "New view", "Suppr. vue": "Del. view",
  "Supprimer la vue (les dashboards sont conservés)": "Delete view (dashboards are kept)",
  "Édition": "Edit", "Mode édition : placer/redimensionner les dashboards et leurs panneaux": "Edit mode: place/resize dashboards and panels",
  "+ Dashboard": "+ Dashboard", "Ajouter un dashboard à cette vue": "Add a dashboard to this view",
  // formulaires
  "+ Nouvelle règle": "+ New rule", "Nom de la règle": "Rule name", "Type": "Type", "Condition": "Condition",
  "Seuil": "Threshold", "Sévérité": "Severity", "sévérité": "severity", "Intervalle(s)": "Interval (s)", "Fenêtre(s)": "Window (s)",
  "actif": "enabled", "Enregistrer": "Save", "Tester la requête": "Test query", "Annuler": "Cancel", "Tester": "Test",
  "+ Nouveau canal": "+ New channel", "Nom du canal": "Channel name", "Nom du canal (ex: ntfy perso)": "Channel name (e.g. my ntfy)",
  "Sévérité min": "Min severity",
  "+ Nouveau parser": "+ New parser", "↻ Réappliquer aux events": "↻ Re-apply to events",
  "Réappliquer les parsers actifs aux events déjà stockés (30 j)": "Re-apply active parsers to stored events (30 d)",
  "Nom du parser": "Parser name", "Nom (ex: nginx access)": "Name (e.g. nginx access)", "Source": "Source",
  "Motif regex": "Regex pattern", "Ligne d'exemple": "Sample line", "coller une ligne d'exemple pour tester…": "paste a sample line to test…",
  "basculer": "switch", "+ Playbook": "+ Playbook", "Nom du playbook": "Playbook name",
  "Nom (ex: SSH bruteforce -> ban)": "Name (e.g. SSH bruteforce -> ban)", "Action": "Action",
  "+ Nouvelle action": "+ New action", "Cible": "Target", "raison (optionnel)": "reason (optional)",
  "Créer (en attente d'approbation)": "Create (pending approval)", "Créer": "Create",
  // cases
  "Filtre statut": "Status filter", "Actifs + clos": "Active + closed", "Ouverts": "Open", "En cours": "In progress",
  "Contenus": "Contained", "Clos": "Closed", "+ Case": "+ Case",
  "Tous statuts": "All statuses", "Toutes priorités": "All priorities", "Nouveau": "New", "Triage": "Triage",
  "Résolu": "Resolved", "Ouvert": "Open", "Enquête": "Investigating", "Contenu": "Contained",
  "P1 critique": "P1 critical", "P2 haute": "P2 high", "P3 moyenne": "P3 medium", "P4 basse": "P4 low",
  "Tri : pertinence": "Sort: relevance", "Récemment mis à jour": "Recently updated", "Priorité": "Priority",
  "Échéance SLA": "SLA due", "En retard": "Overdue", "RETARD": "OVERDUE", "aucun case": "no case",
  "Nouveau case": "New case", "Statut": "Status", "Assigné": "Assignee", "Assigner": "Assign", "Note": "Note",
  "Résumé": "Summary", "Enregistrer le résumé": "Save summary", "Timeline": "Timeline",
  "Résoudre": "Resolve", "Clore": "Close", "Rouvrir": "Reopen", "Rattacher un élément…": "Attach an item…",
  "Rattacher un élément": "Attach an item", "Rattacher": "Attach", "Détacher": "Detach",
  "Événement": "Event", "Alerte": "Alert", "Action / observation": "Action / observation", "Description": "Description",
  "Élément rattaché": "Item attached", "Élément détaché": "Item detached", "case introuvable": "case not found",
  "Sévérité (optionnel)": "Severity (optional)", "Assigné (optionnel)": "Assignee (optional)",
  "Résumé (optionnel)": "Summary (optional)", "créé": "created", "assigné": "assignee", "statut": "status",
  "priorité": "priority", "alerte": "alert", "event": "event", "action": "action",
  // réglages / comptes
  "nom d'utilisateur admin": "admin username", "mot de passe (>= 12 caractères)": "password (>= 12 chars)",
  "+ Nouveau compte": "+ New account", "Rôle": "Role", "editor - lecture + écriture": "editor - read + write",
  "viewer - lecture seule": "viewer - read only", "admin - tout + gestion des comptes": "admin - everything + account management",
  "nom d'utilisateur (a-z, . _ -)": "username (a-z, . _ -)",
  // recherche / résultats / footer / toasts
  "Champs intéressants": "Notable fields", "connexion...": "connecting...", "connecté": "connected", "maj": "upd.",
  "exécution…": "running…", "Panneau créé": "Panel created", "Dashboard créé": "Dashboard created",
  "Vue créée": "View created", "Vue renommée": "View renamed", "compte créé": "account created",
  "compte mis à jour": "account updated", "Case mis à jour": "Case updated", "Dashboard rattaché à la vue": "Dashboard attached to the view",
  "Ajouter à un case": "Add to a case", "Tout afficher": "Show all", "envoyé": "sent", "déclenche": "fires",
  "déclencherait": "would fire", "Glisser pour réorganiser la vue": "Drag to reorder the view",
  "Modifier": "Edit", "Supprimer": "Delete", "Fermer": "Close", "Renommer le dashboard": "Rename dashboard",
  "Largeur (colonnes)": "Width (columns)", "Ajouter un panneau": "Add a panel", "Éditer le panneau": "Edit panel",
  "Éditer (rôle / mot de passe)": "Edit (role / password)", "Redimensionner (glisser)": "Resize (drag)",
  "chargement…": "loading…",
  // états de fraîcheur + types
  "frais": "fresh", "calme": "quiet", "muet": "down", "continu": "stream", "périodique": "periodic",
  "événement": "event", "dormant": "dormant",
  // P11.8-a — couverture ATT&CK (attack.js)
  "nom inconnu": "unknown name", "aucune règle": "no rule",
  "ANGLE MORT — aucune règle ne couvre cette technique. Importez un ruleset Sigma pour la couvrir (bouton « Importer un ruleset Sigma »).": "BLIND SPOT — no rule covers this technique. Import a Sigma ruleset to cover it (button “Import a Sigma ruleset”).",
  "Combler les angles morts : importer une bibliothèque de détection Sigma": "Close the blind spots: import a Sigma detection library",
  "Importer un ruleset Sigma →": "Import a Sigma ruleset →",
  "couverture ATT&CK indisponible (endpoint non déployé).": "ATT&CK coverage unavailable (endpoint not deployed).",
  "aucune tactique dans la matrice de couverture.": "no tactic in the coverage matrix.",
  "couverte (peu de règles)": "covered (few rules)", "couverte (dense)": "covered (dense)", "angle mort (aucune détection)": "blind spot (no detection)",
  // P11.8-a — modèles de requête et complétion (soql_complete.js, savedqueries.js)
  "Modèles": "Templates", "Modèles de requête (GXQL)": "Query templates (GXQL)", "Mes modèles": "My templates", "Modèles livrés": "Shipped templates",
  "+ Enregistrer la requête courante": "+ Save the current query", "Enregistrer le texte de la barre dans mes modèles": "Save the query bar text into my templates",
  "Charger dans la barre (sans exécuter)": "Load into the bar (without running)", "Modifier ce modèle": "Edit this template", "Supprimer ce modèle": "Delete this template",
  "Copier dans mes modèles (pour le modifier)": "Copy into my templates (to edit it)",
  "Aucun modèle personnel — « Enregistrer » range la requête courante ici.": "No personal template — “Save” puts the current query here.",
  "Aucun modèle livré ne correspond.": "No shipped template matches.", "Mes modèles : indisponibles (chargement échoué).": "My templates: unavailable (load failed).",
  "Rechercher (ex : ssh, scan, firewall, dns)…": "Search (e.g. ssh, scan, firewall, dns)…", "Rechercher un modèle": "Search a template",
  "Requête valide": "Valid query", "Requête invalide": "Invalid query", "champ étendu": "extended field", "opérateur": "operator",
  "Enregistrer dans mes modèles": "Save into my templates", "Nom du modèle": "Template name", "Requête (GXQL)": "Query (GXQL)",
  "ex : erreurs 4xx — 24 h": "e.g. 4xx errors — 24 h", "search source=… | stats count by …": "search source=… | stats count by …",
  "Modèle enregistré — retrouvez-le sous « Modèles »": "Template saved — find it under “Templates”", "Modifier le modèle": "Edit template",
  "Modèle mis à jour": "Template updated", "Modèle supprimé": "Template deleted",
  "Aucune requête récente": "No recent query", "Effacer l’historique": "Clear history", "Historique effacé": "History cleared",
  "Récentes": "Recent", "Requêtes récemment exécutées (ce navigateur)": "Recently run queries (this browser)",
  "Enregistrer la requête courante (nommée, persistante, privée à votre compte)": "Save the current query (named, persistent, private to your account)",
  "Modèles de requête (bibliothèque de snippets GXQL)": "Query templates (GXQL snippet library)",
  // P11.8-a — résultats et feuilletage (viz.js)
  "(pas de partie HTML)": "(no HTML part)", "HTML (rendu isolé)": "HTML (isolated rendering)", "Texte": "Text",
  "Cliquer pour exécuter le drill du panneau": "Click to run the panel drill", "Cliquer pour voir ce qui se cache derrière ce chiffre": "Click to see what is behind this figure",
  "Cliquer pour voir les événements": "Click to see the events", "Cliquer pour voir tous les détails": "Click to see all details",
  "Reinitialiser le zoom": "Reset zoom", "Sortir du drill": "Leave the drill", "Voir le mail complet (admin, audité)": "View the full mail (admin, audited)",
  "aucune donnée": "no data", "aucune donnée numérique": "no numeric data", "précédent": "previous", "suivant": "next",
  "tronqué — ampleur inconnue": "truncated — unknown extent", "page partielle — plafond de lignes du serveur": "partial page — server row cap",
  "page sautée — contenu partiel": "skipped-to page — partial content",
  // P11.8-a — cas (cases.js)
  "+ Nouveau case": "+ New case", "ARCHIVÉ": "ARCHIVED", "Ajouter": "Add", "Ajouter une note…": "Add a note…", "Archiver": "Archive", "Désarchiver": "Unarchive",
  "Aucune autre case cible": "No other target case", "Aucune autre case à lier": "No other case to link", "Bloque": "Blocks", "Case": "Case",
  "Case ordinaire — non élevé en incident.": "Ordinary case — not raised to an incident.", "Case à lier": "Case to link", "Cases liés": "Linked cases",
  "Cible de la recherche": "Search target", "Doublon": "Duplicate", "Dé-fusionné": "Unmerged", "Déclarer": "Declare", "Déclarer un incident": "Declare an incident",
  "Détacher cet élément": "Detach this item", "Détacher cet élément de la timeline ? (une note de traçabilité est conservée)": "Detach this item from the timeline? (a traceability note is kept)",
  "Fermer le détail": "Close the detail", "Fusionner": "Merge", "Fusionné dans": "Merged into", "GXQL indisponible": "GXQL unavailable",
  "Ignorer": "Skip", "Ignorer l'étape": "Skip the step", "Incident déclaré": "Incident declared", "Incident rétrogradé": "Incident downgraded",
  "Lien retiré": "Link removed", "Lier": "Link", "Mettre en file": "Queue", "Non (réel, requiert approbation)": "No (real, requires approval)",
  "Note (optionnel)": "Note (optional)", "Oui (dry-run)": "Yes (dry run)", "Pilote / commander (optionnel)": "Lead / commander (optional)",
  "Prépare l'action via /api/actions (approbation + ledger)": "Prepares the action via /api/actions (approval + ledger)", "Raison (auditée)": "Reason (audited)",
  "Rechercher": "Search", "Relié": "Related", "Renseigne une référence ou une description.": "Provide a reference or a description.",
  "Retirer le lien": "Remove the link", "Runbook attaché": "Runbook attached", "Référence (optionnel : alert:ID ou event:ID)": "Reference (optional: alert:ID or event:ID)",
  "Rétrograder": "Downgrade", "Simulation (dry-run)": "Simulation (dry run)", "Tier (1=critique … 4=bas)": "Tier (1=critical … 4=low)",
  "Tier 1 (critique)": "Tier 1 (critical)", "Tier 2": "Tier 2", "Tier 3": "Tier 3", "Tier 4 (bas)": "Tier 4 (low)", "Titre": "Title", "Titre (si nouveau case)": "Title (if new case)",
  "Type (optionnel)": "Type (optional)", "Type de lien": "Link type", "Valeur ($target$)": "Value ($target$)", "contexte / résumé de l'incident": "incident context / summary",
  "contexte de l'élément rattaché": "context of the attached item", "ex: Bruteforce SSH 203.0.113.7": "e.g. SSH bruteforce 203.0.113.7", "ignoré": "skipped", "utilisateur…": "user…",
  // P11.8-a — modèles de données et pivot (datamodels.js)
  "(sélectionnez un modèle)": "(select a model)", "(sélectionnez un objet)": "(select an object)", "(tronqué)": "(truncated)", "Actif": "Enabled",
  "Authentification": "Authentication", "Catégorie CIM": "CIM category", "Catégorie CIM (optionnelle)": "CIM category (optional)", "Champ": "Field", "Champs": "Fields",
  "Champ source (optionnel — renomme un champ existant)": "Source field (optional — renames an existing field)", "Contrainte (GXQL)": "Constraint (GXQL)",
  "Contrainte (fragment GXQL, optionnel)": "Constraint (GXQL fragment, optional)", "Dataset": "Dataset", "Dernière heure": "Last hour",
  "Enregistrer comme dataset": "Save as dataset", "Exécuter sur la fenêtre courante du Pivot": "Run on the current Pivot window", "Modèle": "Model",
  "Nom (identifiant)": "Name (identifier)", "Nom du dataset": "Dataset name", "Nom public": "Public name", "Nouveau champ": "New field",
  "Nouveau modèle de données": "New data model", "Nouvel objet": "New object", "Objet": "Object", "Objets": "Objects", "Origine": "Origin", "Parent": "Parent",
  "Parent (héritage de contrainte)": "Parent (constraint inheritance)", "Retirer": "Remove", "Source (si renommage)": "Source (if renaming)", "Suppr.": "Del.",
  "aucune colonne (résultat vide).": "no column (empty result).", "champ créé": "field created", "champ supprimé": "field deleted", "dataset enregistré": "dataset saved",
  "dataset supprimé": "dataset deleted", "déclarez des champs sur cet objet pour découper/agréger.": "declare fields on this object to split/aggregate.",
  "désactivé": "disabled", "modèle créé": "model created", "modèle supprimé": "model deleted", "objet créé": "object created", "objet supprimé": "object deleted",
  "sélectionnez un modèle pour voir ses objets.": "select a model to see its objects.", "sélectionnez un objet pour voir/ajouter ses champs.": "select an object to see/add its fields.",
  "événements d’auth (login/logout/échecs)": "auth events (login/logout/failures)",
  // P11.8-a — savoir search-time (knowledge.js)
  "Champ source": "Source field", "Expression": "Expression", "Filtre (GXQL)": "Filter (GXQL)", "Label": "Label", "Nom": "Name", "Nom canonique": "Canonical name",
  "Ordre": "Order", "Ordre (résolution)": "Order (resolution)", "Valeur": "Value", "source=web severity=HIGH": "source=web severity=HIGH",
};
function i18nWalk(root) {
  if (LANG !== 'en' || !root) return;
  if (root.querySelectorAll) root.querySelectorAll('[placeholder],[title],[aria-label]').forEach(el => {
    ['placeholder', 'title', 'aria-label'].forEach(a => { const v = el.getAttribute(a); if (v && I18N_EN[v.trim()]) el.setAttribute(a, I18N_EN[v.trim()]); });
  });
  const w = document.createTreeWalker(root.nodeType === 3 ? root.parentNode || root : root, NodeFilter.SHOW_TEXT, null);
  const nodes = []; let n; while ((n = w.nextNode())) nodes.push(n);
  nodes.forEach(t => { const k = t.nodeValue.trim(); if (k && I18N_EN[k]) t.nodeValue = t.nodeValue.replace(k, I18N_EN[k]); });
}

export { i18nWalk };
