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
  "Requête soql ou SQL — les drilldowns atterrissent ici": "soql or SQL query — drilldowns land here",
  "Détail :": "Detail:", "(drillé)": "(drilled)", "Effacer le fil d'Ariane": "Clear the breadcrumb",
  "Exécuter": "Run", "? Aide": "? Help", "← Retour": "← Back", "Aide": "Help", "Panneau": "Panel",
  "Enregistrer la requête comme panneau": "Save query as a panel", "Revenir à la requête précédente (drilldown)": "Back to previous query (drilldown)",
  "Aide : syntaxe des requêtes (SOQL)": "Help: query syntax (SOQL)",
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
  "nom d'utilisateur admin": "admin username", "mot de passe (>= 6 caractères)": "password (>= 6 chars)",
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
