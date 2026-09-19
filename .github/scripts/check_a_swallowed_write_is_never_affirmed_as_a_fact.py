#!/usr/bin/env python3
"""Une écriture SQL AVALÉE n'est jamais AFFIRMÉE comme un fait — garde de CI (`P10.20-w`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
`execute` de rusqlite rend un `Result<usize>` qui porte DEUX informations : l'écriture a-t-elle eu
lieu, et COMBIEN de lignes elle a touchées. L'idiome qui jette ce résultat — `let _ = conn.execute(…)`,
`conn.execute(…).ok()`, `conn.execute(…).unwrap_or(0)` — efface les deux d'un coup : une base passée en
lecture seule, une table absente d'un cache de schéma de pool périmé, un verrou indisponible, une
contrainte violée deviennent indiscernables d'une écriture réussie.

Le geste n'est pas grave en lui-même. Il le devient quand la ligne SUIVANTE AFFIRME cette écriture :

  * `ledger_append(…)` / `audit_config_change(…)` / `audit_source_change(…)` posent le fait dans une
    trace TAMPER-EVIDENT et NON PURGEABLE — « MFA TOTP désactivée », « dossier archivé », « bulletin
    posé ». Le registre est exactement l'objet qu'on relit quand on doute du reste ;
  * `netban_upsert(…)` / `netban_remove(…)` ARMENT un blocage réseau sur une riposte dont la ligne
    n'a peut-être jamais été écrite ;
  * `last_insert_rowid()` rend le dernier identifiant inséré sur LA CONNEXION, toutes tables
    confondues : après une écriture avalée, il rend l'identifiant d'une AUTRE ligne — un maillon du
    registre, une riposte voisine — et cet identifiant part dans le corps servi à la console.

C'est la CONJONCTION qui est jugée ici, jamais l'avalement seul. Mesuré le 2026-09-19 sur l'arbre :
`daemon/src` hors `tests/` porte 733 écritures dont le résultat n'est pas scruté. Une garde sur
`let _ = …execute(` seul naîtrait donc rouge sur des centaines de sites et ne se brancherait pas — et
une garde qui ne se branche pas ne tient rien. La conjonction, elle, en isole 43.

CE QUI ÉTAIT FAUX OU IMPRÉCIS DANS LE RELEVÉ DE `P10.20-t`, ET QUI EST CORRIGÉ ICI (2026-09-19)
-----------------------------------------------------------------------------------------------
Le relevé qui a produit `P10.20-w` appariait une écriture avalée à un fait situé dans une FENÊTRE DE
QUINZE LIGNES bornée par la fonction englobante. Une fenêtre de lignes est une approximation de la
portée, et elle se trompe DANS LES DEUX SENS. Le critère tenu ici est structurel : le fait doit être
DANS LE MÊME BLOC que l'écriture, ou dans un bloc OUVERT APRÈS elle.

  * SUR-COMPTE, `cases.rs::case_apply_update`. `P10.20-w` lui attribue HUIT écritures avalées suivies
    d'une ligne de registre. Il y en a QUATRE (lignes 181, 198, 210, 217 sur l'arbre du 2026-09-19).
    Les cinq autres (166, 169, 172, 175 — titre, sévérité, propriétaire, résumé — et 189, priorité)
    vivent chacune dans son propre `if let Some(v) = b.get(…)`, et AUCUN de ces blocs ne porte de
    ligne de registre : les `ledger_append` de cette fonction sont ceux de l'assignation, du statut
    et du verdict, dans des blocs FRÈRES. Les apparier serait accuser une écriture d'un fait qui
    parle d'autre chose. Le compte de vingt-huit sites sous `handlers/` descend donc à VINGT-QUATRE
    par ce seul écart (le total sous `handlers/`, identifiants compris, est de 32) ;
  * SOUS-COMPTE, LE `COMMIT` AVALÉ. `P10.20-t` compte « sept sous `handlers/` : INSERT avalé puis
    `last_insert_rowid()` servi », et nomme `case_create_row`, trois sites de `dashboards.rs` et trois
    de `dash_ergonomics.rs`. Il en manque DEUX, d'une forme différente et plus retorse :
    `scheduled_reports.rs::report_create` (ligne 89) et `workflow_actions.rs::workflow_action_create`
    (ligne 122) écrivent `Ok(_) => { let _ = conn.execute_batch("COMMIT"); Json(json!({ "id":
    conn.last_insert_rowid() })) }`. L'INSERT y est vérifié (`?` dans la closure) et l'AUDIT aussi ;
    c'est le `COMMIT` qui est avalé, et l'identifiant d'une transaction NON VALIDÉE part au client
    comme un identifiant persisté ;
  * SOUS-COMPTE, HORS `handlers/`. `P10.20-w` écrit « deux marqueurs de semis (`seeds.rs`) précèdent
    aussi un registre ». La conjonction en trouve ONZE hors `handlers/` : les deux marqueurs de semis
    (`seed_ti_alert_rules`, `seed_risk_rules`, qui précèdent un `audit_config_change`), huit autres
    sites de `seeds.rs` qui servent `last_insert_rowid()` après un INSERT avalé, et
    `overlays_oac.rs::load_overlay_dashboards` (ligne 468), qui fait de même au chargement d'un
    overlay. Le relevé ne les voyait pas parce que son vocabulaire de fait ne contenait PAS
    `last_insert_rowid` : il ne cherchait que le registre et l'armement ;
  * FAUSSE FAMILLE, `find_or_create_view` (`seeds.rs`, ligne 166). Un premier relevé par la
    conjonction l'accusait : `conn.execute(…).ok()?` puis `conn.last_insert_rowid()`. La lecture du
    site le REFUSE — le `?` fait SORTIR de la closure quand l'écriture rate, donc l'identifiant n'est
    jamais atteint sur l'échec. Une chaîne qui porte un `?` APRÈS son jeton absorbant ne fabrique
    aucun fait, et elle est hors population (épreuve « le `?` qui suit l'absorption ») ;
  * HORS FAMILLE, `is_err()`. `conn.execute_batch("BEGIN IMMEDIATE").is_err()` est le geste
    fail-closed le plus répandu du dépôt — 113 sites le 2026-09-19 sur l'arbre, dont 92 sous
    `handlers/`. Il ne perd PAS l'échec, il le TESTE : la route refuse avant d'écrire quoi que ce
    soit. L'accuser aurait triplé la population avec des sites que rien ne doit refermer. Ce qu'il
    perd est le COMPTE de lignes, c'est-à-dire la famille de `P10.20-b` côté écriture, et c'est écrit
    dans « ce qu'elle ne tient pas » plutôt que jugé ici.

LES DEUX PRIMITIVES N'ENTRENT PAS DANS LA POPULATION, ET LA RAISON EST STRUCTURELLE
-----------------------------------------------------------------------------------
`P10.20-t` nomme deux sites où l'écriture avalée EST le fait au lieu de le précéder : `ledger_append`
(`daemon/src/ledger.rs`) avale l'INSERT final du registre, et `netban_upsert` (`daemon/src/auth.rs`)
avale son INSERT dans `net_ban` puis rend `true` — « armé » — sous un `#[must_use]` qui promet le
contraire. Ces deux-là sont HORS de cette garde, et ce n'est pas un oubli : la conjonction cherche un
fait qui SUIT l'écriture dans la même fonction, et dans ces deux corps il n'y a rien après — le retour
de la fonction est le fait. Les juger demanderait un second geste (« une primitive d'affirmation rend
un succès inconditionnel »), qui n'est pas celui-ci ; ils sont suivis sous `P10.20-v`. Ce que cette
garde tient, en revanche, c'est que leurs APPELANTS restent sous surveillance : les deux sites qui
arment un ban après une écriture avalée sont dans la classe la plus haute de l'ensemble nommé.

CE QUE LA POPULATION VAUT LE JOUR DE L'ÉCRITURE (2026-09-19, sur l'arbre)
-------------------------------------------------------------------------
`daemon/src`, sous-répertoires compris, `tests/` ÉLAGUÉ dans la descente, commentaires DÉPOUILLÉS,
modules `#[cfg(test)]` COUPÉS, littéraux de chaîne EXCLUS :

  * 733 écritures dont le résultat n'est pas scruté, dont la grande majorité en `let _ =` ;
  * 43 d'entre elles sont SUIVIES d'un fait qui les affirme, sur 13 fichiers. C'est la population ;
  * 32 sont sous `handlers/`, 11 hors (`seeds.rs` 10, `overlays_oac.rs` 1).

L'instantané de `cc4d0f7` et l'arbre rendent la MÊME population de 43 sites, aux mêmes formes : les
corrections en cours sur `auth.rs`, `ledger.rs`, `actions.rs` et `playbooks.rs` n'avaient encore touché
aucun site de conjonction au moment de l'écriture — seules DEUX lignes d'accusation ont bougé dans
`actions.rs`, et rien d'autre. Le nombre total d'écritures avalées, lui, diffère (735 sur
l'instantané, 733 sur l'arbre) : il n'entre dans aucun verdict, et il bougera encore.

POURQUOI UN ENSEMBLE NOMMÉ, ET POURQUOI LA FORME PORTE LE FAIT
---------------------------------------------------------------
Un cliquet de COMPTE se laisse compenser : une accusation fermée et une ouverte le même jour laissent
le total immobile. `SITES_ADMIS` est donc une liste de SITES, jugée DANS LES DEUX SENS — une accusation
hors ensemble est une FORME NEUVE (rouge, avec fichier, fonction et forme), une entrée qui n'est plus
accusée est une EXEMPTION SANS OBJET (rouge, à retirer à la main en disant pourquoi).

Et la forme n'est pas seulement la chaîne avalée : elle porte AUSSI le fait qui suit
(`let _ -> ledger_append`, `unwrap_or -> ledger_append+netban_remove+netban_upsert`). C'est ce qui
distingue cette garde d'un compte de sites, et c'est réglé sur un défaut mesuré : si l'entrée ne
portait que `let _`, transformer `run_playbooks` pour qu'il pose une ligne de registre sur une écriture
ratée — au lieu de ne rien armer — laisserait la forme immobile alors que le site aurait changé de
gravité. Un changement de conjonction rougit donc des DEUX côtés (forme neuve pour la nouvelle,
exemption sans objet pour l'ancienne), ce qui est la bonne lecture : ce n'est pas le même site.

TOUS LES LECTEURS DE FORME SONT IMPORTÉS, ET LEURS TÉMOINS SONT JOUÉS
----------------------------------------------------------------------
`apparier`, `fonctions`, `arguments`, `bras_du_match`, `spans_de_chaines_rust`, `sans_commentaires_rust`,
`coupe_tests`, `positions_de_coupe`, `chaine_detaillee`, `portee_englobante` et `parcours_des_sources`
viennent des gardes de forme voisines, par ré-import à travers la garde de famille. Aucun n'est
recopié : la recopie est ce qui a fait vivre quatre grammaires divergentes du littéral Rust (`P10.20-c`
à `-e`). Un import n'exécute AUCUN témoin, donc `temoins_du_lecteur()` et
`temoins_des_lecteurs_de_forme()` sont appelés ici avant tout verdict, comme dans les deux gardes
sœurs : sans cet appel, un lecteur partagé régressé laisserait cette garde-ci verte à compte amputé.

CE QUE CE VERT NE DIRA PAS
---------------------------
La liste complète est dans `ce_qui_n_est_pas_tenu()`, et son premier terme est l'angle mort PARTAGÉ
avec `P10.20-l` : le `match conn.execute(…) { Ok(_) => …, Err(_) => … }` dont le bras d'erreur SE TAIT
est la même faute écrite autrement, et cette garde ne le voit pas. Le second est le critère de
portée lui-même, dont les manques sont MESURÉS et nommés plus bas.
"""
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

RACINE = (os.path.abspath(sys.argv[1]) if len(sys.argv) > 1
          else os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))

# LES LECTEURS SONT IMPORTÉS, JAMAIS RECOPIÉS. La garde de famille évalue sa propre `RACINE` À L'IMPORT
# (par `sys.argv`), et elle-même importe la garde sœur de la même façon : on lui passe donc la racine
# DÉJÀ calculée ici, pour qu'aucun des modules ne cherche un dépôt git (une archive dépliée en est
# dépourvue) ni ne juge un arbre différent de celui-ci.
_ARGV = sys.argv
sys.argv = [_ARGV[0], RACINE]
try:
    from check_a_truncated_list_is_never_served_as_a_complete_one import (  # noqa: E402
        ARBRE_FABRIQUE, SOURCES_ATTENDUES, apparier, chaine_detaillee, coupe_tests,
        dans_une_chaine_rust, debut_instruction, fonctions, parcours_des_sources, portee_englobante,
        positions_de_coupe, refuser_sur_aveu, sans_commentaires_rust, spans_de_chaines_rust,
        temoins_des_lecteurs_de_forme, temoins_du_lecteur)
finally:
    sys.argv = _ARGV

DEMON = os.path.join(RACINE, "daemon", "src")
ETIQUETTE = "ecriture-avalee-affirmee"

# --- LE GESTE, MOITIÉ UNE : L'ÉCRITURE ------------------------------------------------------------
# Les deux méthodes rusqlite qui ÉCRIVENT et rendent un `Result`. Les espaces sont tolérés : un
# `rustfmt` qui coupe entre le receveur et la méthode ne doit pas faire disparaître un site.
ECRITURE_SQL = re.compile(r"\.\s*execute(?:_batch)?\s*\(")

# LES JETONS ABSORBANTS — ils convertissent l'ÉCHEC en valeur, et le compte de lignes disparaît avec
# lui. `unwrap_or(0)` mérite sa place autant que `ok()` : le zéro qu'il rend se lit « aucune ligne ne
# correspondait » alors qu'il peut vouloir dire « l'écriture n'a pas eu lieu » (famille `P10.20-b`,
# côté écriture).
ABSORBANTS = ("ok", "unwrap_or", "unwrap_or_default", "unwrap_or_else", "map_or", "map_or_else")
# LES SCRUTATEURS PARTIELS — ils perdent le COMPTE mais TESTENT l'échec, et le corps qui suit refuse.
# Ils sont hors population, avec leur raison mesurée en en-tête ; ils sont nommés pour que l'épreuve
# négative puisse tenir qu'ils n'y entrent pas.
SCRUTATEURS_PARTIELS = ("is_ok", "is_err")
# LES JETONS TRAVERSANTS — ils rendent encore un `Result`, donc l'échec vit toujours : on continue.
TRAVERSANTS = ("map", "and_then", "map_err", "or_else", "inspect", "inspect_err", "filter")
# LES JETONS PROPAGATEURS — l'échec SORT. `?` le rend à l'appelant ou à la closure, `unwrap`/`expect`
# TUENT le processus. Aucun des trois ne laisse atteindre le fait qui suit.
PROPAGATEURS = ("?", "unwrap", "expect")

# LA LIAISON SOURDE — `let _ = <receveur>.execute(…)`. Le `_` jette le `Result` sans même le nommer.
# Le receveur doit être un CHEMIN (mesuré le 2026-09-19 sur l'arbre : `conn`, `c`, `rconn`,
# `self.conn`, et rien d'autre) : exiger l'absence de parenthèse écarte `let _ = envelopper(
# conn.execute(…))`, où le `_` porte sur l'enveloppe et non sur l'écriture.
LIAISON_SOURDE = re.compile(r"\A\s*let\s+_\s*(?::\s*[^=]*?)?=\s*[&*\s]*[A-Za-z_][\w:.\[\]\s]*\Z")

# --- LE GESTE, MOITIÉ DEUX : LE FAIT QUI AFFIRME L'ÉCRITURE ---------------------------------------
# Chacun est nommé parce qu'il pose un fait que personne ne peut plus recouper : une trace non
# purgeable, un blocage réseau, ou un identifiant rendu au client.
FAITS_QUI_AFFIRMENT = (
    ("ledger_append", re.compile(r"\bledger_append\s*\(")),
    ("audit_config_change", re.compile(r"\baudit_config_change\s*\(")),
    ("audit_source_change", re.compile(r"\baudit_source_change\s*\(")),
    ("netban_upsert", re.compile(r"\bnetban_upsert\s*\(")),
    ("netban_remove", re.compile(r"\bnetban_remove\s*\(")),
    ("last_insert_rowid", re.compile(r"\blast_insert_rowid\s*\(")),
)

# --- PLANCHER DE NON-DÉGÉNÉRESCENCE (première écriture, 2026-09-19) -------------------------------
# Ils ne réclament PAS un volume de code : ils constatent qu'une LECTURE est cassée. Sous eux, rendre
# vert serait rendre vert en étant aveugle — le défaut que cette garde nomme, appliqué à elle-même.
# DÉRIVÉS du relevé du jour par la règle des deux tiers des gardes sœurs : 69 % de 43 sites = 29,6 ->
# 29, et 65 % de 13 fichiers = 8,4 -> 8. ILS NE MONTENT JAMAIS ; à chaque lot qui ferme des sites, ils
# se RE-DÉRIVENT du relevé de ce moment-là, par la même règle, avec sa date écrite ici. Ce qu'ils ne
# séparent PAS, et c'est voulu : une découverte PARTIELLEMENT aveugle passe sous eux sans les
# franchir — c'est le jugement de l'ensemble nommé dans les deux sens qui la prend.
PLANCHER_SITES = 29
PLANCHER_FICHIERS = 8

# ================================================================================================
# L'ENSEMBLE NOMMÉ — SIX CLASSES, JUGÉES DANS LES DEUX SENS
# ================================================================================================
# La valeur d'une entrée est le TUPLE DES FORMES admises pour cette fonction, une forme par site (les
# doublons sont significatifs : `case_apply_update` admet QUATRE fois la même forme). Une forme
# s'écrit `<chaîne avalée> -> <faits qui suivent, triés>`.

# --- CLASSE 1 : L'ÉCRITURE AVALÉE PRÉCÈDE UN ARMEMENT. C'est le rang le plus haut : une riposte dont
# la ligne n'a peut-être pas été écrite fait poser un BLOCAGE RÉSEAU, et la trace l'atteste.
# VIDE depuis `P10.20-w` : les deux entrées sont RETIRÉES parce que les deux écritures sont désormais
# scrutées, et la raison est écrite à chaque site.
#   * `actions.rs::respond_run` — la clôture de l'action passe par un `match` : `Err` pose son propre
#     genre de registre (`action.exec.verdict-non-ecrit`) et `continue`, donc aucun miroir `net_ban`
#     n'est touché. Ce que l'entrée disait de l'armement était d'ailleurs FAUX sur ce site : le `0`
#     d'`unwrap_or` menait au bloc « verdict conservé », qui se terminait par un `continue` — l'écriture
#     ratée n'armait rien, elle FABRIQUAIT un verdict dans la trace non purgeable ;
#   * `playbooks.rs::run_playbooks` — le marqueur `last_run` passe par `marquer_le_passage_du_playbook`,
#     qui compte les lignes ; un marqueur non écrit refuse le tour de CE playbook (aucune riposte
#     posée, aucun ban armé) et entre dans le bilan du tick.
SITES_QUI_ARMENT = {}

# --- CLASSE 2 : L'IDENTIFIANT EMPRUNTÉ EST RENDU **ET** LE REGISTRE L'AFFIRME. Un seul site, et c'est
# le geste d'`action_create` mot pour mot — celui que `P10.20-t` a fermé sur la riposte.
# VIDE depuis `P10.20-w` : l'entrée de `cases.rs::case_create_row` est RETIRÉE parce que l'écriture est
# comptée et que `last_insert_rowid()` n'est plus interrogé que sur la branche à UNE ligne écrite. La
# fonction rend `DossierOuvert`, le refus est nommé AVANT la timeline, le registre et l'identifiant, et
# le contrat de `case_create` change avec (503 nommé là où un 200 servait un identifiant emprunté).
SITES_IDENTIFIANT_ET_REGISTRE = {}

# --- CLASSE 3 : L'ÉCRITURE AVALÉE PRÉCÈDE UNE LIGNE DE REGISTRE OU D'AUDIT. La trace non purgeable
# affirme une mutation qui n'a peut-être pas eu lieu. Aucun identifiant n'est emprunté ici.
SITES_REGISTRE_APRES_ECRITURE_AVALEE = {
    ("daemon/src/handlers/caseops.rs", "sla_multilevel_tick"): ("let _ -> ledger_append",),
    ("daemon/src/handlers/caseops.rs", "case_merge"): ("let _ -> ledger_append",),
    ("daemon/src/handlers/caseops.rs", "case_unmerge"): ("let _ -> ledger_append",),
    # QUATRE sites, pas huit : les cinq autres écritures avalées de cette fonction vivent dans des
    # blocs FRÈRES qui ne portent aucun registre (l'écart mesuré contre `P10.20-w`, en en-tête).
    ("daemon/src/handlers/cases.rs", "case_apply_update"):
        ("let _ -> ledger_append", "let _ -> ledger_append", "let _ -> ledger_append",
         "let _ -> ledger_append"),
    ("daemon/src/handlers/cases.rs", "escalate_overdue_cases"): ("let _ -> ledger_append",),
    ("daemon/src/handlers/cases.rs", "case_set_archived"):
        ("let _ -> ledger_append", "let _ -> ledger_append"),
    # Le registre atteste « MFA TOTP désactivée » et la route rend `ok` sur un DELETE avalé : le
    # second facteur d'un compte peut rester en place pendant que la trace dit le contraire.
    ("daemon/src/handlers/idp.rs", "mfa_disable"): ("let _ -> ledger_append",),
    ("daemon/src/handlers/incidents.rs", "incident_apply_tier"): ("let _ -> ledger_append",),
    ("daemon/src/handlers/incidents.rs", "step_advance"): ("let _ -> ledger_append",),
    # DEUX écritures ET l'audit avalés, avec un corps de succès : le bulletin d'accueil peut n'avoir
    # jamais été posé pendant que l'audit de configuration dit qu'il l'a été.
    ("daemon/src/handlers/system.rs", "bulletin_set"):
        ("let _ -> audit_config_change", "let _ -> audit_config_change"),
    ("daemon/src/handlers/system.rs", "bulletin_clear"): ("let _ -> audit_config_change",),
}

# --- CLASSE 4 : L'IDENTIFIANT EST SERVI, SANS REGISTRE. Rien n'entre dans la trace, mais la console
# reçoit l'identifiant d'une AUTRE ligne et le repose ensuite sur chaque geste qui vise cet objet.
SITES_IDENTIFIANT_SERVI_SANS_REGISTRE = {
    ("daemon/src/handlers/dash_ergonomics.rs", "library_panel_create"):
        ("let _ -> last_insert_rowid",),
    ("daemon/src/handlers/dash_ergonomics.rs", "playlist_create"): ("let _ -> last_insert_rowid",),
    ("daemon/src/handlers/dash_ergonomics.rs", "snapshot_create"): ("let _ -> last_insert_rowid",),
    ("daemon/src/handlers/dashboards.rs", "dash_create"): ("let _ -> last_insert_rowid",),
    ("daemon/src/handlers/dashboards.rs", "panel_create"): ("let _ -> last_insert_rowid",),
    ("daemon/src/handlers/dashboards.rs", "view_create"): ("let _ -> last_insert_rowid",),
    # LES DEUX SITES QUE `P10.20-t` NE COMPTAIT PAS, et ils ne sont pas de la même forme que les six
    # ci-dessus : l'INSERT y est vérifié (`?`) et l'audit aussi, c'est le `COMMIT` qui est avalé. Un
    # identifiant de transaction NON VALIDÉE part au client comme un identifiant persisté.
    ("daemon/src/handlers/scheduled_reports.rs", "report_create"): ("let _ -> last_insert_rowid",),
    ("daemon/src/handlers/workflow_actions.rs", "workflow_action_create"):
        ("let _ -> last_insert_rowid",),
}

# --- CLASSE 5 : DÉGRADÉ MAIS FAIL-CLOSED. Le compte de lignes EXISTE (`unwrap_or(0)`) et le fait qui
# suit lui est CONDITIONNÉ : aucun fait n'est fabriqué sur une écriture ratée. Ce qui reste faux est la
# CAUSE — « l'écriture n'a pas eu lieu » et « aucune ligne ne correspondait » deviennent le même zéro,
# donc le même refus, et la phrase servie désigne la mauvaise.
# VIDE depuis `P10.20-w` : les cinq entrées sont RETIRÉES parce que les cinq écritures sont comptées par
# un `match`, et que les deux zéros y sont séparés — « la base n'a pas pris l'écriture » rend un 503
# NOMMÉ, « aucune ligne ne correspondait » garde EXACTEMENT sa sortie d'avant (404 nu, `ok: false`, ou
# 204). Le classement de cette classe était FAUX sur `cases.rs::ack_all` : son `ledger_append` n'était
# pas conditionné au compte, il posait `alert.ack_all 0 alertes` sur une écriture qui n'avait pas eu
# lieu — un fait FABRIQUÉ dans la trace non purgeable, donc un site de rang trois et non de rang cinq.
SITES_DEGRADES_MAIS_FAIL_CLOSED = {}

# --- CLASSE 6 : AMORÇAGE, HORS CHEMIN DE REQUÊTE. Semis de démonstration et chargement d'overlays :
# aucun client ne reçoit ces identifiants, mais un semis partiel construit un arbre d'objets
# incohérent EN SILENCE (un dashboard rattaché à l'identifiant d'une vue voisine), et deux marqueurs
# de semis précèdent un audit de configuration.
SITES_AMORCAGE = {
    ("daemon/src/overlays_oac.rs", "load_overlay_dashboards"): ("let _ -> last_insert_rowid",),
    ("daemon/src/seeds.rs", "seed_demo"):
        ("let _ -> last_insert_rowid", "let _ -> last_insert_rowid", "let _ -> last_insert_rowid",
         "let _ -> last_insert_rowid"),
    ("daemon/src/seeds.rs", "seed_dashboard_head"): ("let _ -> last_insert_rowid",),
    ("daemon/src/seeds.rs", "seed_default_dashboard"): ("let _ -> last_insert_rowid",),
    ("daemon/src/seeds.rs", "seed_obs_dashboard"): ("let _ -> last_insert_rowid",),
    ("daemon/src/seeds.rs", "seed_runbooks"): ("let _ -> last_insert_rowid",),
    # LES DEUX MARQUEURS DE SEMIS que `P10.20-w` nomme : l'INSERT du marqueur est avalé et l'audit de
    # configuration suit. Un semis rejoué deux fois écrirait deux audits pour une seule pose.
    ("daemon/src/seeds.rs", "seed_ti_alert_rules"): ("let _ -> audit_config_change",),
    ("daemon/src/seeds.rs", "seed_risk_rules"): ("let _ -> audit_config_change",),
}

CLASSES = (
    ("rang 1 — l'écriture avalée ARME un blocage réseau", SITES_QUI_ARMENT),
    ("rang 2 — identifiant emprunté SERVI **et** registre", SITES_IDENTIFIANT_ET_REGISTRE),
    ("rang 3 — registre ou audit APRÈS une écriture avalée", SITES_REGISTRE_APRES_ECRITURE_AVALEE),
    ("rang 4 — identifiant emprunté SERVI, sans registre", SITES_IDENTIFIANT_SERVI_SANS_REGISTRE),
    ("rang 5 — dégradé mais fail-closed (la CAUSE est fausse, pas le fait)",
     SITES_DEGRADES_MAIS_FAIL_CLOSED),
    ("rang 6 — amorçage, hors chemin de requête", SITES_AMORCAGE),
)
SITES_ADMIS = {}
for _libelle, _classe in CLASSES:
    for _cle, _formes in _classe.items():
        SITES_ADMIS[_cle] = tuple(sorted(SITES_ADMIS.get(_cle, ()) + tuple(_formes)))


# ================================================================================================
# LE VERDICT DE CHAÎNE
# ================================================================================================
def verdict_de_la_chaine(jetons):
    """`(genre, chaîne)` — `genre` dans {`absorbe`, `scrute`, `propage`, `nu`}.

    UN `?` N'IMPORTE OÙ DANS LA CHAÎNE FAIT SORTIR, ET C'EST TESTÉ D'ABORD. `…execute(…).ok()?` a
    l'air d'absorber, mais la fonction — ou la closure — REND sur l'échec : le fait qui suit n'est
    jamais atteint, donc il n'y a pas de conjonction. Sans cette règle, `seeds.rs::find_or_create_view`
    entrait dans la population par une lecture trop rapide de son `.ok()` (mesuré le 2026-09-19).

    Ensuite on lit de gauche à droite : un TRAVERSANT laisse l'échec vivant, on continue ; un
    ABSORBANT le convertit en valeur, c'est un candidat ; un SCRUTATEUR PARTIEL le TESTE (le corps qui
    suit refuse), hors population ; un PROPAGATEUR le rend ou tue. Un jeton INCONNU arrête la lecture
    SANS accuser — ne pas conclure est la seule réponse honnête quand le lecteur ignore ce que le
    jeton fait du `Result`."""
    if any(nom == "?" for nom, _i, _a1, _a2 in jetons):
        return "propage", ".".join(j[0] for j in jetons[:4])
    for nom, _index, _a1, _a2 in jetons:
        if nom in ABSORBANTS:
            return "absorbe", ".".join(j[0] for j in jetons[:4])
        if nom in SCRUTATEURS_PARTIELS:
            return "scrute", ".".join(j[0] for j in jetons[:4])
        if nom in PROPAGATEURS or nom not in TRAVERSANTS:
            return "propage", ".".join(j[0] for j in jetons[:4])
    return ("nu", "") if not jetons else ("propage", ".".join(j[0] for j in jetons[:4]))


def faits_dans_la_portee(code, coupes, spans, depart, fin_fonction):
    """Les faits qui AFFIRMENT l'écriture qui se termine en `depart` : ceux du MÊME BLOC, ou d'un bloc
    ouvert APRÈS elle. Rendu `[(nom du fait, position)]`.

    LE CRITÈRE EST STRUCTUREL, ET IL REMPLACE UNE FENÊTRE DE LIGNES. On suit la profondeur d'accolades
    depuis la fin de l'écriture ; dès qu'elle passe SOUS zéro, le bloc qui portait l'écriture est
    refermé et ce qui suit appartient à un frère ou à un ancêtre : l'appariement s'arrête là. Deux
    conséquences MESURÉES le 2026-09-19 sur l'arbre, et elles vont en sens contraire :

      * il ÉVITE cinq fausses accusations dans `cases.rs::case_apply_update`, où quatre écritures
        vivent dans des `if let Some(v) = b.get(…)` sans registre pendant que les `ledger_append` de
        l'assignation, du statut et du verdict vivent dans des blocs FRÈRES ;
      * il MANQUE quatre sites où le fait est posé dans un bloc ANCÊTRE, après la fermeture de celui
        de l'écriture : `incidents.rs::attach_runbook` (l'INSERT d'étape est dans la boucle, le
        registre annonce le nombre d'étapes APRÈS la boucle), `incidents.rs::incident_apply_tier`
        (deux écritures conditionnelles, registre après) et `idp.rs::login_mfa_post` (la consommation
        du pas TOTP anti-rejeu est avalée dans son `if let`, le registre « login MFA validé » suit
        dans un bloc de verrou frère). Les prendre demanderait d'admettre les blocs ancêtres, ce qui
        ajouterait CINQ fausses accusations dans `actions.rs::respond_run`, où chaque écriture avalée
        est suivie d'un `continue` qui rend le registre inatteignable. Le choix est le moindre des
        deux, il est mesuré, et le manque est écrit dans « ce qu'elle ne tient pas ».
    """
    profondeur, plancher, bornes = 0, 0, []
    for c in coupes:
        # `c < depart`, PAS `c <= depart`, ET C'EST UN DÉFAUT MESURÉ (2026-09-19, mutation `is_err`
        # rejouée sur cette garde) : `depart` est l'index du PREMIER caractère qui suit l'expression
        # d'écriture, et cet index EST parfois une accolade ouvrante — `if conn.execute(…).is_err() {`.
        # L'exclure faisait compter la fermante SANS son ouvrante, la profondeur tombait à -1 dès le
        # premier bloc, et TOUT le reste de la fonction passait pour « hors du bloc ». Le site
        # disparaissait alors de la population EN VERT.
        if c < depart:
            continue
        if c >= fin_fonction:
            break
        if code[c] == "{":
            profondeur += 1
        elif code[c] == "}":
            profondeur -= 1
            plancher = min(plancher, profondeur)
        bornes.append((c, plancher))
    trouves = []
    for nom, motif in FAITS_QUI_AFFIRMENT:
        for m in motif.finditer(code, depart, fin_fonction):
            if dans_une_chaine_rust(spans, m.start()):
                continue
            sorti = False
            for borne, plancher_ici in bornes:
                if borne >= m.start():
                    break
                sorti = plancher_ici < 0
            if not sorti:
                trouves.append((nom, m.start()))
    return trouves


# ================================================================================================
# LA DÉCOUVERTE — UN SITE EST UNE CONJONCTION, JAMAIS UN AVALEMENT SEUL
# ================================================================================================
def analyser(chemin_relatif, texte, journal, aveux_du_lecteur=None):
    """[(chemin, ligne, fonction, forme, extrait)] pour UN fichier.

    `journal` recueille ce que CETTE garde avoue avoir perdu (une parenthèse non appariée, une
    écriture hors de toute fonction) ; `aveux_du_lecteur` ce que le LECTEUR PARTAGÉ avoue (`P10.20-d`).
    Deux causes, deux remèdes, jamais mélangés : sans le second, une région avalée par le lecteur
    retirerait des sites SANS UN MOT et le plancher accuserait le dépôt là où la cause est
    l'instrument."""
    journal_du_lecteur = []
    brut = sans_commentaires_rust(texte, journal_du_lecteur)
    if journal_du_lecteur and aveux_du_lecteur is not None:
        aveux_du_lecteur[chemin_relatif] = [f"ligne {texte.count(chr(10), 0, o) + 1} : {m}"
                                            for m, o in journal_du_lecteur]
    code = coupe_tests(brut)
    fns = fonctions(code)
    coupes = positions_de_coupe(code)
    spans = spans_de_chaines_rust(code)
    sites = []
    for m in ECRITURE_SQL.finditer(code):
        if dans_une_chaine_rust(spans, m.start()):
            continue
        ouvrante = m.end() - 1
        fin = apparier(code, ouvrante)
        if fin < 0:
            ligne = code.count("\n", 0, m.start()) + 1
            journal.append(f"{chemin_relatif}:{ligne} — parenthèse d'appel non appariée sur l'écriture "
                           "SQL : le lecteur a perdu la fin de l'expression")
            continue
        jetons, apres = chaine_detaillee(code, fin)
        genre, chaine = verdict_de_la_chaine(jetons)
        debut = debut_instruction(coupes, m.start())
        sourde = bool(LIAISON_SOURDE.match(code[debut:m.start()]))
        if genre == "absorbe":
            forme_chaine = f"let _.{chaine}" if sourde else chaine
        elif genre == "nu" and sourde:
            forme_chaine = "let _"
        else:
            continue
        englobante = portee_englobante(fns, m.start())
        if not englobante:
            ligne = code.count("\n", 0, m.start()) + 1
            journal.append(f"{chemin_relatif}:{ligne} — écriture HORS de toute fonction : la portée est "
                           "introuvable, et un site sans fonction ne peut pas entrer dans l'ensemble")
            continue
        faits = faits_dans_la_portee(code, coupes, spans, apres, englobante[3])
        if not faits:
            continue
        forme = f"{forme_chaine} -> " + "+".join(sorted({n for n, _p in faits}))
        extrait = " ".join(code[debut:apres].split())[:150]
        sites.append((chemin_relatif, code.count("\n", 0, m.start()) + 1, englobante[0], forme, extrait))
    return sites


def fichiers_du_corpus(racine=None):
    """Tous les `.rs` de `daemon/src/`, SOUS-RÉPERTOIRES COMPRIS, artefacts et `tests/` ÉLAGUÉS.

    L'élagage passe par le geste PARTAGÉ (`parcours_des_sources`, `P11.8-m`) : il exclut PAR NOM DANS
    la descente, et porter une liste à la main ici serait la « copie divergente » que
    `check_no_guard_walks_the_tree_unpruned.py` juge. `tests` et `tests.rs` s'ajoutent par l'argument
    prévu pour cela : un test peut écrire n'importe quelle forme sans qu'aucune route ne la serve.
    `racine` n'est là que pour les ÉPREUVES INTERNES, qui doivent soumettre un arbre FABRIQUÉ à ce
    lecteur-ci sans toucher au dépôt."""
    racine = DEMON if racine is None else racine
    if not os.path.isdir(racine):
        return []
    trouves = []
    for dossier, fichiers in parcours_des_sources(racine, hors=("tests", "tests.rs")):
        trouves += [os.path.join(dossier, n) for n in fichiers
                    if n.endswith(".rs") and os.path.isfile(os.path.join(dossier, n))]
    return sorted(trouves)


def decouvrir():
    sites, journal, aveux_du_lecteur = [], [], {}
    for chemin in fichiers_du_corpus():
        with open(chemin, encoding="utf-8", errors="replace") as fh:
            texte = fh.read()
        sites += analyser(os.path.relpath(chemin, RACINE), texte, journal, aveux_du_lecteur)
    return sites, journal, aveux_du_lecteur


# ================================================================================================
# LE JUGEMENT CONTRE L'ENSEMBLE NOMMÉ — DANS LES DEUX SENS, ET SUR LES FORMES
# ================================================================================================
def juger_contre_l_ensemble(sites, admis):
    """[(genre, fichier, phrase)] — `forme neuve` quand une forme accusée dépasse ce qui est admis,
    `exemption sans objet` quand une forme admise n'est plus accusée autant qu'elle le déclare."""
    vus = {}
    for chemin, ligne, fn, forme, _extrait in sites:
        vus.setdefault((chemin, fn), []).append((forme, ligne))
    ecarts = []
    for cle in sorted(set(vus) | set(admis)):
        chemin, fn = cle
        formes_vues, formes_admises = {}, {}
        for forme, ligne in vus.get(cle, []):
            formes_vues.setdefault(forme, []).append(ligne)
        for forme in admis.get(cle, ()):
            formes_admises[forme] = formes_admises.get(forme, 0) + 1
        for forme in sorted(set(formes_vues) | set(formes_admises)):
            n_vu, n_admis = len(formes_vues.get(forme, [])), formes_admises.get(forme, 0)
            if n_vu > n_admis:
                lignes = ", ".join(str(x) for x in sorted(formes_vues[forme])[n_admis:])
                ecarts.append(("forme neuve", chemin,
                               f"FORME NEUVE — `{fn}` ({chemin}) avale une écriture SQL sous la forme "
                               f"`{forme}` {n_vu} fois pour {n_admis} admise(s) ; ligne(s) en trop : "
                               f"{lignes}. Une écriture dont un registre, un armement ou un "
                               "identifiant servi dépend se SCRUTE — lignes écrites comptées, refus "
                               "nommé AVANT le fait — sinon elle entre dans SITES_ADMIS AVEC son rang "
                               "et sa raison, jamais en silence."))
            if n_vu < n_admis:
                ecarts.append(("exemption sans objet", chemin,
                               f"EXEMPTION SANS OBJET — `{fn}` ({chemin}) est admis {n_admis} fois sous "
                               f"la forme `{forme}` et n'est accusé que {n_vu} fois : l'écriture est "
                               "désormais scrutée, ou la CONJONCTION a changé (regardez la « forme "
                               "neuve » qui l'accompagne : ce n'est pas le même site), ou le site "
                               "n'existe plus, ou cette garde a cessé de le voir. Dans les quatre cas "
                               "l'entrée se retire à la main EN DISANT LEQUEL — un canal qui rétrécit "
                               "ne doit pas passer pour un défaut fermé."))
    return ecarts


# ================================================================================================
# LES ÉPREUVES INTERNES — JOUÉES AVANT TOUTE LECTURE DU DÉPÔT, DANS LES DEUX SENS
# ================================================================================================
# Les extraits sont FABRIQUÉS, jamais pris sur l'arbre : adosser un témoin à `case_create_row` ou à
# `run_playbooks` en ferait une RANÇON — il rougirait le jour où le site est réparé, et aucun geste ne
# pourrait le refermer.
EPREUVES = [
    # --- LES DEUX MUTATIONS D'INSTRUMENT QUE `P10.20-w` EXIGE, JOUÉES À CHAQUE EXÉCUTION.
    ("(1) MUTATION QUI DOIT ÊTRE VUE : `let _ = conn.execute(…)` puis `ledger_append(…)`",
     'fn e1(conn: &Connection, id: i64) -> bool {\n'
     '    let _ = conn.execute("UPDATE t SET a=1 WHERE id=?1", params![id]);\n'
     '    ledger_append(conn, "t.maj", &format!("#{id} mis à jour"));\n'
     '    true\n}\n', {"let _ -> ledger_append"}),
    ("(2) MUTATION QUI NE DOIT PAS L'ÊTRE : `match conn.execute(…)` dont le bras d'erreur REFUSE",
     'fn e2(conn: &Connection, id: i64) -> Result<(), String> {\n'
     '    match conn.execute("UPDATE t SET a=1 WHERE id=?1", params![id]) {\n'
     '        Ok(0) => return Err("aucune ligne".into()),\n'
     '        Ok(_) => {}\n'
     '        Err(e) => return Err(format!("écriture NON faite : {e}")),\n'
     '    }\n'
     '    ledger_append(conn, "t.maj", &format!("#{id} mis à jour"));\n'
     '    Ok(())\n}\n', set()),
    # --- LES AUTRES FORMES DE LA CONJONCTION, TELLES QUE L'ARBRE LES PORTE.
    ("(3) `execute_batch` avalé puis l'identifiant servi — le `COMMIT` de `report_create`",
     'fn e3(conn: &Connection) -> Response {\n'
     '    let _ = conn.execute_batch("COMMIT");\n'
     '    Json(json!({ "id": conn.last_insert_rowid() })).into_response()\n}\n',
     {"let _ -> last_insert_rowid"}),
    ("(4) `.unwrap_or(0)` puis un registre CONDITIONNEL — dégradé mais fail-closed",
     'fn e4(conn: &Connection, id: i64) -> bool {\n'
     '    let n = conn.execute("DELETE FROM t WHERE id=?1", params![id]).unwrap_or(0);\n'
     '    if n > 0 {\n'
     '        ledger_append(conn, "t.suppr", &format!("#{id} supprimé"));\n'
     '    }\n'
     '    n > 0\n}\n', {"unwrap_or -> ledger_append"}),
    ("(5) `.ok()` puis un armement de ban",
     'fn e5(conn: &Connection, ip: &str) -> bool {\n'
     '    conn.execute("INSERT INTO action(target) VALUES(?1)", params![ip]).ok();\n'
     '    netban_upsert(conn, ip, None, "auto", "playbook", "prod")\n}\n',
     {"ok -> netban_upsert"}),
    ("(6) l'audit de configuration est un fait au même titre que le registre",
     'fn e6(conn: &Connection, v: &str) -> rusqlite::Result<()> {\n'
     '    let _ = conn.execute("DELETE FROM bulletin", []);\n'
     '    audit_config_change(conn, "config.bulletin", v, 2, v, "{}")\n}\n',
     {"let _ -> audit_config_change"}),
    ("(7) DEUX faits après la même écriture : la forme les porte tous, triés",
     'fn e7(conn: &Connection, ip: &str) -> i64 {\n'
     '    let _ = conn.execute("INSERT INTO action(target) VALUES(?1)", params![ip]);\n'
     '    let id = conn.last_insert_rowid();\n'
     '    ledger_append(conn, "action.queued", &format!("#{id}"));\n'
     '    id\n}\n', {"let _ -> last_insert_rowid+ledger_append"}),
    ("(8) le fait est PLUS PROFOND que l'écriture — un bloc ouvert après elle",
     'fn e8(conn: &Connection, id: i64, doit: bool) -> bool {\n'
     '    let _ = conn.execute("UPDATE t SET a=1 WHERE id=?1", params![id]);\n'
     '    if doit {\n'
     '        for _k in 0..2 {\n'
     '            ledger_append(conn, "t.maj", "profond");\n'
     '        }\n'
     '    }\n'
     '    true\n}\n', {"let _ -> ledger_append"}),
    # CE TÉMOIN TIENT LA BORNE DU BLOC À UN CARACTÈRE PRÈS, et il est né d'une mutation qui a trouvé un
    # vrai défaut (2026-09-19) : quand l'expression d'écriture est immédiatement suivie d'une accolade
    # OUVRANTE, l'index qui la suit EST cette accolade. La compter est obligatoire — sans elle, la
    # fermante du même bloc fait tomber la profondeur à -1 et tout le reste de la fonction passe pour
    # « hors du bloc ». Le site disparaissait alors EN VERT, et aucun autre témoin ne le disait.
    ("(9) l'écriture est suivie d'une ACCOLADE OUVRANTE, et le fait vient après le bloc",
     'fn e9(conn: &Connection, id: i64) -> bool {\n'
     '    match conn.execute("UPDATE t SET a=1 WHERE id=?1", params![id]).ok() {\n'
     '        Some(_) => {}\n'
     '        None => {}\n'
     '    }\n'
     '    ledger_append(conn, "t.maj", &format!("#{id}"));\n'
     '    true\n}\n', {"ok -> ledger_append"}),
    # --- LES TÉMOINS NÉGATIFS : chacun est une forme que la garde DOIT laisser passer.
    ("témoin négatif : l'écriture avalée SANS aucun fait après elle (la population des centaines)",
     'fn n1(conn: &Connection, id: i64) {\n'
     '    let _ = conn.execute("UPDATE t SET a=1 WHERE id=?1", params![id]);\n}\n', set()),
    ("témoin négatif : le fait est AVANT l'écriture, il ne l'affirme pas",
     'fn n2(conn: &Connection, id: i64) {\n'
     '    ledger_append(conn, "t.demande", &format!("#{id}"));\n'
     '    let _ = conn.execute("UPDATE t SET a=1 WHERE id=?1", params![id]);\n}\n', set()),
    ("témoin négatif : le fait est dans un bloc FRÈRE (le cas mesuré de `case_apply_update`)",
     'fn n3(conn: &Connection, id: i64, a: Option<&str>, b: Option<&str>) {\n'
     '    if let Some(v) = a {\n'
     '        let _ = conn.execute("UPDATE t SET titre=?1 WHERE id=?2", params![v, id]);\n'
     '    }\n'
     '    if let Some(v) = b {\n'
     '        let _ = conn.execute("UPDATE t SET porteur=?1 WHERE id=?2", params![v, id]);\n'
     '        ledger_append(conn, "t.porteur", &format!("#{id} -> {v}"));\n'
     '    }\n}\n', {"let _ -> ledger_append"}),
    ("témoin négatif : le `?` qui SUIT l'absorption — `seeds.rs::find_or_create_view`",
     'fn n4(conn: &Connection, name: &str) -> Option<i64> {\n'
     '    conn.execute("INSERT INTO view(name) VALUES(?1)", params![name]).ok()?;\n'
     '    Some(conn.last_insert_rowid())\n}\n', set()),
    ("témoin négatif : `?` nu — l'échec sort avant le fait",
     'fn n5(conn: &Connection, id: i64) -> rusqlite::Result<i64> {\n'
     '    conn.execute("INSERT INTO t(id) VALUES(?1)", params![id])?;\n'
     '    Ok(conn.last_insert_rowid())\n}\n', set()),
    ("témoin négatif : `.is_err()` — le COMPTE est perdu, l'ÉCHEC est testé et la route refuse",
     'fn n6(conn: &Connection, id: i64) -> Response {\n'
     '    if conn.execute_batch("BEGIN IMMEDIATE").is_err() { return server_err("verrou"); }\n'
     '    ledger_append(conn, "t.maj", &format!("#{id}"));\n'
     '    ok_json()\n}\n', set()),
    ("témoin négatif : `.unwrap()` — une panique, jamais un fait inventé",
     'fn n7(conn: &Connection, id: i64) -> i64 {\n'
     '    conn.execute("INSERT INTO t(id) VALUES(?1)", params![id]).unwrap();\n'
     '    conn.last_insert_rowid()\n}\n', set()),
    ("témoin négatif : la conjonction est dans un commentaire `//`",
     'fn n8(conn: &Connection, id: i64) -> rusqlite::Result<usize> {\n'
     '    // AVANT : let _ = conn.execute("UPDATE t SET a=1", []); ledger_append(conn, "t.maj", "");\n'
     '    conn.execute("UPDATE t SET a=1 WHERE id=?1", params![id])\n}\n', set()),
    ("témoin négatif : la conjonction est DANS UNE CHAÎNE (phrase d'aveu, gabarit de message)",
     'fn n9() -> &\'static str {\n'
     '    "le site d\'avant faisait let _ = conn.execute(sql, p); ledger_append(conn, k, d) — corrigé"\n}\n',
     set()),
    # CES DEUX TÉMOINS TIENNENT L'EXCLUSION DES LITTÉRAUX LÀ OÙ ELLE PORTE VRAIMENT, ET C'EST UNE
    # MESURE : une conjonction ENTIÈREMENT citée dans une phrase n'est déjà pas vue (le préfixe de son
    # instruction n'est pas une liaison sourde), donc les deux témoins qui précèdent ne prouvaient RIEN
    # de l'exclusion. Débrancher `dans_une_chaine_rust` les laissait verts (mutation jouée le
    # 2026-09-19). Ce qui compte est le littéral posé À CÔTÉ d'une écriture réelle : sur le FAIT, il
    # fabriquerait une conjonction là où il n'y a qu'une phrase ; sur l'ÉCRITURE, il ajouterait un
    # second site à une fonction qui n'en porte qu'un.
    ("témoin négatif : le nom du FAIT n'est que CITÉ dans un message, après une écriture avalée",
     'fn n13(conn: &Connection, id: i64) -> bool {\n'
     '    let _ = conn.execute("UPDATE t SET a=1 WHERE id=?1", params![id]);\n'
     '    eprintln!("le correctif remplacera ledger_append(conn, k, d) par un refus nommé");\n'
     '    true\n}\n', set()),
    ("témoin positif ET négatif : une écriture réelle, et une AUTRE seulement citée dans une phrase",
     'fn n14(conn: &Connection, id: i64) -> bool {\n'
     '    let _ = conn.execute("UPDATE t SET a=1 WHERE id=?1", params![id]);\n'
     '    let note = "la forme d\'avant : conn.execute(sql, p).ok()";\n'
     '    ledger_append(conn, "t.maj", note);\n'
     '    true\n}\n', {"let _ -> ledger_append"}),
    ("témoin négatif : la conjonction est dans une CHAÎNE BRUTE `r#\"…\"#`",
     'fn n10() -> &\'static str {\n'
     '    r#"motif interdit : let _ = conn.execute(..); ledger_append(..) — voir P10.20-w"#\n}\n',
     set()),
    ("témoin négatif : la conjonction est dans un `#[cfg(test)] mod`",
     'fn n11() -> i64 { 0 }\n'
     '#[cfg(test)]\nmod tests {\n    use super::*;\n'
     '    #[test]\n    fn t(conn: &Connection) {\n'
     '        let _ = conn.execute("INSERT INTO t(id) VALUES(1)", []);\n'
     '        ledger_append(conn, "t.maj", "témoin");\n    }\n}\n', set()),
    ("témoin négatif : `let _ = envelopper(conn.execute(…))` — le `_` porte sur l'ENVELOPPE",
     'fn n12(conn: &Connection, id: i64) {\n'
     '    let _ = journaliser(conn.execute("UPDATE t SET a=1 WHERE id=?1", params![id]));\n'
     '    ledger_append(conn, "t.maj", &format!("#{id}"));\n}\n', set()),
    # --- L'ANGLE MORT EST PROUVÉ, PAS ALLÉGUÉ. Ce témoin est DÉFENSIF dans un seul sens : il rougit
    # si la garde se met à voir le `match` muet, ce qui veut dire que le paragraphe « ce que ce vert
    # ne dit pas » doit être réécrit AVANT que le verdict reprenne. Il n'exige jamais qu'un défaut
    # survive.
    ("angle mort ÉCRIT, partagé avec `P10.20-l` : le `match` dont le bras `Err` SE TAIT",
     'fn a1(conn: &Connection, id: i64) -> bool {\n'
     '    match conn.execute("UPDATE t SET a=1 WHERE id=?1", params![id]) {\n'
     '        Ok(_) => {}\n'
     '        Err(_) => {}\n'
     '    }\n'
     '    ledger_append(conn, "t.maj", &format!("#{id}"));\n'
     '    true\n}\n', set()),
    ("angle mort ÉCRIT : le `Result` LIÉ à un nom, jeté plus bas",
     'fn a2(conn: &Connection, id: i64) -> bool {\n'
     '    let ecrit = conn.execute("UPDATE t SET a=1 WHERE id=?1", params![id]);\n'
     '    drop(ecrit);\n'
     '    ledger_append(conn, "t.maj", &format!("#{id}"));\n'
     '    true\n}\n', set()),
    ("angle mort ÉCRIT : le fait est posé par une FONCTION APPELÉE, pas par un jeton connu",
     'fn a3(conn: &Connection, id: i64) -> bool {\n'
     '    let _ = conn.execute("UPDATE t SET a=1 WHERE id=?1", params![id]);\n'
     '    tracer_la_mutation(conn, id);\n'
     '    true\n}\n', set()),
]

# LA DESCENTE S'ÉPROUVE SUR UN ARBRE FABRIQUÉ, JAMAIS SUR `handlers/connectors/` : l'adosser au
# sous-répertoire réel en ferait une rançon, qui rougirait le jour où ce répertoire est renommé. Les
# CHEMINS du faux arbre sont ceux des gardes sœurs (`ARBRE_FABRIQUE`, `SOURCES_ATTENDUES`), IMPORTÉS et
# non recopiés — c'est le même élagage qui est jugé. S'y ajoute ICI un fichier sous `tests/`, que ce
# corpus-ci élague et que les leurs ne connaissent pas.
SOURCE_FABRIQUEE = ('fn ecrire(conn: &Connection, id: i64) -> bool {\n'
                    '    let _ = conn.execute("UPDATE t SET a=1 WHERE id=?1", params![id]);\n'
                    '    ledger_append(conn, "t.maj", &format!("#{id}"));\n'
                    '    true\n}\n')
ARBRE_DE_CETTE_GARDE = ARBRE_FABRIQUE + (("tests", "suite_fabriquee.rs"),)

SOURCE_LITTERAL_D_OCTET = ('fn a4(conn: &Connection, bytes: &[u8], j: usize, id: i64) -> bool {\n'
                           '    let _q = bytes[j] == b\'"\';\n'
                           '    let _ = conn.execute("UPDATE t SET a=1 WHERE id=?1", params![id]);\n'
                           '    ledger_append(conn, "t.maj", &format!("#{id}"));\n'
                           '    true\n}\n')


def epreuve_du_litteral_d_octet():
    """UN ANCIEN ANGLE MORT DES LECTEURS PARTAGÉS, DEVENU UNE PROPRIÉTÉ CONSOMMÉE (`P10.20-m`).

    `apparier` et `fonctions` sont des lecteurs PARTAGÉS. Jusqu'à `P10.20-m`, `apparier` sautait les
    chaînes mais PAS les littéraux de caractère : sur `b'"'` il ouvrait une fausse chaîne, perdait des
    accolades, et la portée tombait. Depuis, le littéral est reconnu : le site DOIT être trouvé et il
    ne DOIT y avoir aucun aveu. Si cette épreuve retombe, c'est que le lecteur partagé a régressé — la
    garde le DIT au lieu de rendre un compte amputé. La propriété elle-même est tenue par témoin et par
    mutation dans le fichier qui POSSÈDE ces lecteurs ; ici on tient seulement qu'elle est CONSOMMÉE."""
    errs = []
    journal = []
    sites = analyser("/angle_mort_octet.rs", SOURCE_LITTERAL_D_OCTET, journal)
    if not sites:
        errs.append("épreuve du LITTÉRAL D'OCTET : la garde ne TROUVE plus la conjonction qui suit un "
                    "littéral d'octet — `apparier` ou `fonctions` a régressé sur les littéraux de "
                    "caractère (`P10.20-m`). Un compte amputé serait rendu vert : la garde refuse de "
                    "conclure.")
    if journal:
        errs.append(f"épreuve du LITTÉRAL D'OCTET : le lecteur partagé AVOUE une portée introuvable "
                    f"({journal}) là où il doit la situer depuis `P10.20-m` — la propriété n'est plus "
                    "consommée, la garde refuse de conclure.")
    return errs


def epreuve_de_la_borne_de_fonction():
    """UNE ÉCRITURE AVALÉE DANS UNE FONCTION ET UN FAIT DANS LA SUIVANTE NE SONT PAS LE MÊME SITE.

    C'est la borne que la fenêtre de lignes du relevé de `P10.20-t` ne tenait que par accident : quinze
    lignes après une écriture posée en fin de fonction tombent dans la fonction d'à côté. Sans cette
    épreuve, `portee_englobante` pourrait être débranchée — et la garde accuserait une fonction pour un
    registre qui appartient à sa voisine, sans qu'aucun témoin ne tombe."""
    source = ('fn avant(conn: &Connection, id: i64) {\n'
              '    let _ = conn.execute("UPDATE t SET a=1 WHERE id=?1", params![id]);\n'
              '}\n'
              'fn apres(conn: &Connection, id: i64) {\n'
              '    ledger_append(conn, "t.maj", &format!("#{id}"));\n'
              '}\n')
    errs = []
    journal = []
    sites = analyser("/borne_de_fonction.rs", source, journal)
    if sites:
        errs.append("épreuve de la BORNE DE FONCTION : une écriture avalée dans `avant` est appariée à "
                    f"un registre posé dans `apres` ({sites}) — la garde accuse une fonction pour le "
                    "fait d'une autre.")
    if journal:
        errs.append(f"épreuve de la BORNE DE FONCTION : le lecteur avoue ({journal}) sur une source de "
                    "deux fonctions tenant en six lignes — la borne n'est plus mesurable.")
    # ET LA MÊME PROPRIÉTÉ, ÉPROUVÉE SANS LA BORNE DE FONCTION. Mesuré le 2026-09-19 : couper le scan à
    # la fin de la fonction est REDONDANT avec la borne de bloc — sortir d'une fonction fait toujours
    # passer la profondeur sous zéro —, si bien que débrancher la première seule ne change RIEN. La
    # borne de fonction reste (elle borne le scan et elle donne le NOM qui entre dans l'ensemble), mais
    # la propriété que la clé réclame est tenue ICI, sur la seule borne qui la porte : `fin_fonction`
    # est poussée jusqu'au bout du texte, et l'appariement doit TOUJOURS refuser de franchir
    # l'accolade qui ferme `avant`.
    code = coupe_tests(sans_commentaires_rust(source))
    debut_apres_ecriture = code.index(");", code.index(".execute(")) + 2
    faits = faits_dans_la_portee(code, positions_de_coupe(code), spans_de_chaines_rust(code),
                                 debut_apres_ecriture, len(code))
    if faits:
        errs.append(f"épreuve de la BORNE DE BLOC : {faits} — la profondeur d'accolades n'arrête plus "
                    "l'appariement, et le registre de la fonction SUIVANTE est attribué à l'écriture "
                    "avalée de la précédente. C'est la faute que la fenêtre de quinze lignes du relevé "
                    "de `P10.20-t` commettait par construction.")
    return errs


def epreuve_de_la_descente():
    """Le CORPUS descend dans les sous-répertoires, et il élague — jugé DANS LES DEUX SENS.

    Sans le sens POSITIF, la descente pourrait être débranchée sans qu'aucun témoin ne tombe, et la
    garde redeviendrait plate en silence. Sans le sens NÉGATIF, un `target/` posé sous l'arbre — ou un
    module de test — entrerait dans le corpus et la garde accuserait du code qu'aucun geste local ne
    referme. Le troisième volet est le plus important : un fichier LISTÉ mais non ANALYSÉ ne prouve
    rien."""
    errs = []
    with tempfile.TemporaryDirectory(prefix="plume-ecriture-avalee-") as racine:
        for rel in ARBRE_DE_CETTE_GARDE:
            chemin = os.path.join(racine, *rel)
            os.makedirs(os.path.dirname(chemin), exist_ok=True)
            with open(chemin, "w", encoding="utf-8") as fh:
                fh.write(SOURCE_FABRIQUEE)
        vus = {os.path.relpath(c, racine).replace(os.sep, "/") for c in fichiers_du_corpus(racine)}
        manquants = sorted(SOURCES_ATTENDUES - vus)
        if manquants:
            errs.append(f"épreuve de la DESCENTE (positif) : {manquants} n'est pas dans le corpus — la "
                        "découverte est redevenue PLATE, et une conjonction écrite sous "
                        "`handlers/connectors/` ne serait plus jamais vue")
        artefacts = sorted(vus - SOURCES_ATTENDUES)
        if artefacts:
            errs.append(f"épreuve de la DESCENTE (élagage) : {artefacts} est entré dans le corpus — le "
                        "parcours n'élague plus les artefacts d'outil ni `tests/` par le geste partagé "
                        "(`parcours_des_sources`), et la garde accuserait du code dérivé ou un test")
        sites = analyser("sous_repertoire_fabrique/mod.rs", SOURCE_FABRIQUEE, [])
        if {f for _c, _l, _fn, f, _x in sites} != {"let _ -> ledger_append"}:
            errs.append("épreuve de la DESCENTE (analyse) : le fichier d'un sous-répertoire est LISTÉ "
                        "mais sa conjonction n'est pas ACCUSÉE — un corpus qui s'élargit sans que le "
                        "lecteur suive ne vaut rien")
    return errs


def valider_instrument():
    """L'instrument s'éprouve AVANT de rendre un verdict, et dans les deux sens.

    CHAQUE ÉPREUVE A ÉTÉ ÉPROUVÉE PAR MUTATION le 2026-09-19, et la phrase dit ce qui a été MESURÉ :
    vider `ABSORBANTS`, retirer la liaison sourde, vider `FAITS_QUI_AFFIRMENT`, débrancher la borne de
    bloc, débrancher la borne de fonction, débrancher l'exclusion des chaînes, débrancher `coupe_tests`,
    débrancher le dépouillement des commentaires, faire de `is_err` un absorbant, vider l'ensemble
    nommé, y ajouter une entrée bidon, et débrancher le jugement de l'ensemble."""
    errs = []
    # LES LECTEURS PARTAGÉS SE VALIDENT AVANT DE SERVIR (`P10.20-d`, `P10.20-r`). Ils sont IMPORTÉS,
    # donc leurs témoins ne tournent pas à l'import : sans ces deux appels, un lecteur amputé de sa
    # reconnaissance des chaînes brutes ou des littéraux de caractère ne serait épinglé que par la
    # garde qui le PORTE, et celle-ci resterait verte à compte amputé.
    try:
        temoins_du_lecteur()
    except AssertionError as e:
        errs.append(f"lecteur partagé (`sans_commentaires_rust`) : {e}")
    try:
        temoins_des_lecteurs_de_forme()
    except AssertionError as e:
        errs.append(f"lecteurs de forme Rust (`apparier`, `fonctions`, `arguments`, "
                    f"`bras_du_match`, `spans_de_chaines_rust`) : {e}")

    for nom, src, attendues in EPREUVES:
        journal = []
        sites = analyser("/epreuve.rs", src, journal)
        vues = {f for _c, _l, _fn, f, _x in sites}
        if journal:
            errs.append(f"épreuve « {nom} » : le lecteur avoue avoir perdu quelque chose ({journal[0]})")
        if attendues and vues != attendues:
            errs.append(f"épreuve « {nom} » : formes vues {sorted(vues) or 'aucune'}, attendu "
                        f"{sorted(attendues)} — la garde ne voit plus la conjonction qu'elle nomme, ou "
                        "elle l'étiquette autrement et l'ensemble nommé ne peut plus la reconnaître")
        if not attendues and vues:
            errs.append(f"épreuve « {nom} » : accusée sous {sorted(vues)} alors qu'elle SCRUTE, qu'elle "
                        "propage, qu'elle est hors famille, ou qu'elle est un angle mort ÉCRIT — la "
                        "garde accuse une forme qu'aucun geste local ne referme, ou elle a cessé d'être "
                        "aveugle là où son verdict déclare l'être (auquel cas c'est le verdict qu'il "
                        "faut réécrire)")

    # --- L'ÉCRITURE, ÉPROUVÉE À SON PROPRE NIVEAU ET DANS LES DEUX SENS.
    if not ECRITURE_SQL.search("conn.execute(sql, p)") \
            or not ECRITURE_SQL.search("conn\n        .execute_batch(sql)"):
        errs.append("épreuve de l'ÉCRITURE (positif) : `execute`/`execute_batch` n'est plus reconnu — "
                    "la population de cette garde est vide, et son vert ne dit plus rien")
    if ECRITURE_SQL.search("conn.query_row(sql, [], f)") or ECRITURE_SQL.search("s.query_map([], f)"):
        errs.append("épreuve de l'ÉCRITURE (négatif) : une LECTURE est entrée dans la population. "
                    "`query_row` appartient à `check_a_single_row_read_that_failed_is_never_served_as_"
                    "a_fact.py` et `query_map` à `check_a_truncated_list_is_never_served_as_a_complete_"
                    "one.py` — les trois ensembles nommés compteraient alors les mêmes sites")

    # --- LE VOCABULAIRE DU FAIT NE DOIT PAS SE VIDER EN SILENCE : sans lui, la conjonction est
    # impossible et la garde serait verte quoi que l'arbre porte.
    if len(FAITS_QUI_AFFIRMENT) < 4:
        errs.append(f"épreuve du VOCABULAIRE DU FAIT : {len(FAITS_QUI_AFFIRMENT)} fait(s) déclaré(s) "
                    "pour les six que la clé nomme (registre, deux audits, deux armements, identifiant "
                    "servi) — la conjonction ne peut plus se former, et le vert ne dirait rien")

    # --- LA LIAISON SOURDE, DANS LES DEUX SENS.
    for exemple in ("let _ = conn", "let _ = c", "let _ = self.conn", "let _: () = conn"):
        if not LIAISON_SOURDE.match(exemple):
            errs.append(f"épreuve de la LIAISON SOURDE (positif) : `{exemple}.execute(…)` n'est plus "
                        "reconnu comme une écriture jetée — la forme la plus répandue du dépôt "
                        "disparaîtrait de la population")
    for contre in ("let n = conn", "let _ = journaliser(conn", "removed += conn"):
        if LIAISON_SOURDE.match(contre):
            errs.append(f"épreuve de la LIAISON SOURDE (négatif) : `{contre}.execute(…)` est pris pour "
                        "une écriture jetée alors que le résultat est LIÉ, COMPTÉ ou ENVELOPPÉ")

    # --- LES DEUX LECTEURS DE TEXTE SONT NOUÉS : aucune borne d'instruction ne tombe DANS un littéral.
    fabrique = 'fn f() { let c = \'"\'; let s = "a;b{c}"; let t = r#"d;e{f}"#; }'
    spans = spans_de_chaines_rust(fabrique)
    if len(spans) != 2 or fabrique[spans[0][0]:spans[0][1]] != '"a;b{c}"':
        errs.append(f"épreuve des LITTÉRAUX : {len(spans)} littéral(aux) vu(s) sur une source qui en "
                    "porte DEUX (une chaîne simple, une chaîne brute) précédés d'un littéral de "
                    "CARACTÈRE — l'exclusion des chaînes ne tient plus. Dans un sens une conjonction "
                    "CITÉE dans une phrase deviendrait un site fantôme ; dans l'autre un `'\"'` "
                    "ouvrirait une fausse chaîne qui avale la fin du fichier et fait DISPARAÎTRE des "
                    "sites réels, en vert")
    dedans = [c for c in positions_de_coupe(fabrique) if dans_une_chaine_rust(spans, c)]
    if dedans:
        errs.append(f"épreuve des LITTÉRAUX (accord des deux lecteurs) : {len(dedans)} borne(s) "
                    "d'instruction tombe(nt) DANS un littéral — `spans_de_chaines_rust` et "
                    "`positions_de_coupe` ne lisent plus le même texte, et l'un des deux ment")

    # --- L'ANGLE MORT DES LECTEURS PARTAGÉS SE SOLDE PAR UN AVEU, jamais par un site retiré.
    errs += epreuve_du_litteral_d_octet()
    # --- LA BORNE DE FONCTION, ET LA DESCENTE DU CORPUS.
    errs += epreuve_de_la_borne_de_fonction()
    errs += epreuve_de_la_descente()

    # --- L'ENSEMBLE NOMMÉ EST JUGÉ DANS LES DEUX SENS ET SUR LES FORMES, À SON PROPRE NIVEAU.
    faux_site = [("daemon/src/handlers/fabrique.rs", 7, "fn_fabriquee", "let _ -> ledger_append",
                  'let _ = conn.execute(..)')]
    genres = {g for g, _f, _p in juger_contre_l_ensemble(faux_site, {})}
    if genres != {"forme neuve"}:
        errs.append(f"épreuve de l'ENSEMBLE (forme neuve) : genres {sorted(genres) or 'aucun'} au lieu "
                    "de ['forme neuve'] — une accusation hors ensemble ne rougit plus, et l'ensemble ne "
                    "peut plus que grandir en silence")
    genres = {g for g, _f, _p in juger_contre_l_ensemble(
        [], {("daemon/src/handlers/fabrique.rs", "fn_fantome"): ("let _ -> ledger_append",)})}
    if genres != {"exemption sans objet"}:
        errs.append(f"épreuve de l'ENSEMBLE (exemption sans objet) : genres {sorted(genres) or 'aucun'} "
                    "au lieu de ['exemption sans objet'] — une entrée sans objet ne rougit plus, et la "
                    "liste cesse de descendre quand le dépôt guérit")
    if juger_contre_l_ensemble(faux_site, {("daemon/src/handlers/fabrique.rs", "fn_fabriquee"):
                                           ("let _ -> ledger_append",)}):
        errs.append("épreuve de l'ENSEMBLE (accord) : un site EXACTEMENT admis produit un écart — la "
                    "garde serait rouge sur l'arbre qu'elle déclare elle-même admis")
    mute = [("daemon/src/handlers/fabrique.rs", 7, "fn_fabriquee", "let _ -> netban_upsert",
             'let _ = conn.execute(..)')]
    genres = {g for g, _f, _p in juger_contre_l_ensemble(
        mute, {("daemon/src/handlers/fabrique.rs", "fn_fabriquee"): ("let _ -> ledger_append",)})}
    if genres != {"forme neuve", "exemption sans objet"}:
        errs.append(f"épreuve de l'ENSEMBLE (changement de CONJONCTION) : genres "
                    f"{sorted(genres) or 'aucun'} au lieu des DEUX — un site admis parce qu'il précède "
                    "un registre, réécrit pour ARMER un ban, passerait sans un mot. C'est précisément "
                    "pour ce cas que la forme porte le fait et non un simple compte")
    return errs


# ================================================================================================
# LE VERDICT
# ================================================================================================
def ce_qui_n_est_pas_tenu():
    print(f"\n[{ETIQUETTE}] CE QU'ELLE NE TIENT PAS :\n"
          "  * LE PLUS LOURD, ET IL EST PARTAGÉ AVEC `P10.20-l` : elle ne lit que la CHAÎNE posée sur "
          "l'écriture. Un `match conn.execute(…) { Ok(_) => …, Err(_) => … }` dont le bras d'erreur SE "
          "TAIT est la MÊME faute écrite autrement, et elle ne le voit pas. Deux témoins de ce fichier "
          "la reproduisent pour que l'angle mort soit prouvé et non allégué. La fermer demanderait de "
          "lire le BRAS `Err` — décider si son corps propage ou se tait — et tant que ce n'est pas "
          "fait, un site neuf peut s'écrire en `match` sans rougir. Un `Result` LIÉ à un nom puis "
          "jeté plus bas est dans le même trou.\n"
          "  * SON CRITÈRE DE PORTÉE A DES MANQUES MESURÉS, et ils sont nommés : le fait doit être dans "
          "le MÊME BLOC que l'écriture ou dans un bloc ouvert APRÈS elle. Quatre sites où le fait est "
          "posé dans un bloc ANCÊTRE lui échappent sur l'arbre du 2026-09-19 — "
          "`incidents.rs::attach_runbook` (le registre annonce le nombre d'étapes APRÈS la boucle qui "
          "les insère), `incidents.rs::incident_apply_tier` (deux écritures conditionnelles), et "
          "`idp.rs::login_mfa_post` (la consommation du pas TOTP anti-rejeu est avalée, le registre "
          "« login MFA validé » suit dans un bloc frère). Admettre les blocs ancêtres les prendrait et "
          "ajouterait CINQ fausses accusations dans `actions.rs::respond_run`, où chaque écriture "
          "avalée est suivie d'un `continue`. Le choix est le moindre des deux, pas une absence de "
          "défaut.\n"
          "  * elle ne juge PAS `is_ok()`/`is_err()` sur une écriture. Ils TESTENT l'échec et la route "
          "refuse — mais ils perdent le COMPTE de lignes, donc « aucune ligne ne correspondait » y "
          "reste indiscernable d'un succès sans effet. C'est la famille de `P10.20-b` côté écriture, "
          "elle est hors périmètre ici et elle n'est tenue par rien.\n"
          "  * elle ne juge PAS les deux PRIMITIVES d'affirmation, `ledger_append` (ledger.rs) et "
          "`netban_upsert` (auth.rs), où l'écriture avalée EST le fait au lieu de le précéder : il n'y "
          "a rien après elles dans leur corps, donc aucune conjonction à former. Elles sont suivies "
          "sous `P10.20-v`, et ce vert-ci ne dit rien d'elles.\n"
          "  * elle ne reconnaît que SIX noms de fait. Un fait posé par une fonction intermédiaire — "
          "un enrobage qui appelle le registre — n'est pas vu, et un témoin de ce fichier le "
          "reproduit. Élargir le vocabulaire est un geste à MESURER, pas à deviner.\n"
          "  * elle ne dit RIEN du rang. Les six classes de `SITES_ADMIS` portent un rang et une raison "
          "LUS À LA MAIN le 2026-09-19 ; la garde, elle, ne sait pas les recalculer. Un site neuf est "
          "accusé sans rang, et c'est à la lecture de le lui donner en entrant dans l'ensemble.\n"
          "  * elle ne sait pas si l'écriture et le fait parlent du MÊME OBJET. Deux écritures et deux "
          "registres dans un même bloc sont appariés deux à deux sans lire ce qu'ils touchent.\n"
          "  * elle ne prouve RIEN à l'exécution. Elle constate qu'une forme est absente du dépôt, "
          "jamais qu'une réponse réelle refuse avant d'écrire au registre.")


def main():
    # --- LES ÉPREUVES D'ABORD : aucune lecture du dépôt tant que l'instrument n'a pas été éprouvé.
    errs = valider_instrument()
    if errs:
        for e in errs:
            print(f"::error::{e}")
        print(f"\n[{ETIQUETTE}] l'INSTRUMENT est faux : aucun verdict n'est rendu.")
        ce_qui_n_est_pas_tenu()
        return 2

    # --- L'ANCRAGE : `execute` doit être la méthode rusqlite que cette garde croit lire. Sans lui, un
    # dépôt qui aurait changé de bibliothèque rendrait zéro site et la garde serait verte pour la pire
    # des raisons.
    cargo = os.path.join(RACINE, "daemon", "Cargo.toml")
    manifeste = ""
    if os.path.isfile(cargo):
        with open(cargo, encoding="utf-8", errors="replace") as fh:
            manifeste = fh.read()
    if not re.search(r"^\s*rusqlite\s*=", manifeste, re.M):
        print("::error::aucun `rusqlite` dans daemon/Cargo.toml : `execute`/`execute_batch` n'est plus "
              "la méthode que cette garde croit lire, et sa population n'a plus d'ancrage. Elle REFUSE "
              "DE CONCLURE.")
        ce_qui_n_est_pas_tenu()
        return 2

    sites, journal, aveux_du_lecteur = decouvrir()
    # L'AVEU DU LECTEUR PASSE AVANT CELUI DE LA GARDE (`P10.20-d`) : une région avalée par le lecteur
    # est la cause AMONT, et la nommer évite d'accuser une parenthèse qu'il a lui-même déplacée.
    if aveux_du_lecteur and refuser_sur_aveu(ETIQUETTE, aveux_du_lecteur, "Rust"):
        ce_qui_n_est_pas_tenu()
        return 2
    if journal:
        for a in journal:
            print(f"::error::{a}")
        print(f"\n[{ETIQUETTE}] REFUS DE CONCLURE — le lecteur avoue avoir perdu une expression ; il ne "
              "rend pas un compte amputé en vert.")
        ce_qui_n_est_pas_tenu()
        return 2

    fichiers = {c for c, _l, _f, _fo, _x in sites}
    if len(sites) < PLANCHER_SITES or len(fichiers) < PLANCHER_FICHIERS:
        print(f"::error::{len(sites)} site(s) découvert(s) sur {len(fichiers)} fichier(s), planchers "
              f"{PLANCHER_SITES}/{PLANCHER_FICHIERS} (dérivés le 2026-09-19 du relevé de ce jour-là sur "
              "l'arbre : 43 sites sur 13 fichiers, règle des deux tiers). La DÉCOUVERTE est cassée, ou "
              "un lot a fermé assez de sites pour que les planchers doivent être RE-DÉRIVÉS du relevé "
              "du jour — dans le second cas, ils descendent, avec leur date écrite dans le fichier. La "
              "garde REFUSE DE CONCLURE plutôt que de rendre vert en étant aveugle.")
        ce_qui_n_est_pas_tenu()
        return 2

    for chemin, ligne, fn, forme, extrait in sorted(sites):
        print(f"::error file={chemin},line={ligne}::`{fn}` jette le résultat d'une écriture SQL puis "
              f"AFFIRME cette écriture (forme `{forme}`) : le fait posé ensuite ne peut plus être "
              f"recoupé, et rien ne distingue l'écriture faite de l'écriture perdue — `{extrait}`")

    par_forme = {}
    for _c, _l, _f, forme, _x in sites:
        par_forme[forme] = par_forme.get(forme, 0) + 1
    print(f"\n[{ETIQUETTE}] POPULATION DÉCOUVERTE le jour de l'exécution : {len(sites)} conjonction(s) "
          f"sur {len(fichiers)} fichier(s) de daemon/src (sous-répertoires compris, `tests/` élagué) — "
          + " · ".join(f"{f} {n}" for f, n in sorted(par_forme.items(), key=lambda p: (-p[1], p[0])))
          + ". Commentaires DÉPOUILLÉS, modules `#[cfg(test)]` COUPÉS, littéraux de chaîne EXCLUS : une "
            "conjonction citée dans une note ou dans une phrase n'est jamais un site.")

    ecarts = juger_contre_l_ensemble(sites, SITES_ADMIS)
    if ecarts:
        for _genre, chemin, phrase in ecarts:
            print(f"::error file={chemin}::{phrase}")
        print(f"::error::{len(ecarts)} écart(s) entre les accusations du jour et l'ensemble nommé. "
              "L'ensemble se corrige à la main, AVEC le rang et la raison ; zéro reste atteignable.")
        ce_qui_n_est_pas_tenu()
        return 1

    print(f"[{ETIQUETTE}] ADMIS, par classe : "
          + " · ".join(f"{lib} : {sum(len(f) for f in cl.values())} site(s)/{len(cl)} fonction(s)"
                       for lib, cl in CLASSES) + ".")
    print(f"[{ETIQUETTE}] l'ensemble nommé est EXACTEMENT ce que l'arbre porte ({len(sites)} site(s)) — "
          "ni forme neuve, ni exemption sans objet, ni CONJONCTION changée.")
    print(f"[{ETIQUETTE}] CE QUE CE VERT NE DIT PAS : les {len(sites)} conjonctions admises sont des "
          "DÉFAUTS CONNUS ET NON CORRIGÉS, admis pour que cette garde puisse être câblée VERTE le jour "
          "où elle est écrite plutôt que d'attendre une campagne — une garde qui naît rouge ne se "
          "branche pas, et une garde qui ne se branche pas ne tient rien. Le vert dit UNE chose et une "
          "seule : AUCUNE CONJONCTION NEUVE n'est entrée depuis le 2026-09-19. Il ne dit pas que "
          "l'arbre est sain — deux de ces sites arment un blocage réseau, neuf servent un identifiant "
          "emprunté. CHAQUE correction doit RETIRER son entrée de SITES_ADMIS, sous peine "
          "d'« exemption sans objet » : c'est ce qui fait descendre la liste au lieu de la laisser "
          "devenir un décor.")
    ce_qui_n_est_pas_tenu()
    return 0


if __name__ == "__main__":
    sys.exit(main())
