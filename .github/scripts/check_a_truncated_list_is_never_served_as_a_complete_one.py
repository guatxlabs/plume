#!/usr/bin/env python3
"""Une liste TRONQUÉE n'est jamais servie comme une liste COMPLÈTE — garde de CI (`P10.7-f`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
Un itérateur de lignes de rusqlite (`query_map`, `query_and_then`) rend des `Result<T>`, une ligne à
la fois : le mappeur peut échouer sur UNE ligne sans que la requête ait échoué. L'idiome aplati —
`.flatten()`, `.filter_map(Result::ok)`, `.filter_map(|r| r.ok())`, `.flat_map(|r| r.ok())` — jette
cette ligne-là et rend la SUITE. Le corps servi est alors une liste qui a la forme d'une liste
complète : aucune clé n'a changé, aucun total ne dit qu'il manque quelque chose, et le lecteur ne
peut pas distinguer « il y a quatre règles activées » de « il y en avait cinq et la cinquième ne
s'est pas décodée ».

La cause n'est pas exotique. Elle est banale : un cache de schéma de pool périmé fait réussir le
`prepare` et sortir l'échec comme une ERREUR DE LIGNE (`P10.7-f`, famille mesurée dans la note
`flatten-avale-no-such-table-au-premier-pas`), une colonne ajoutée par une migration n'est pas encore
vue par la connexion qui sert, un `TEXT` corrompu ne se convertit pas. Dans les trois cas la route
rend 200 et la liste est plus courte qu'elle ne devrait, SANS UN MOT.

LA SECONDE FAMILLE — LE PARCOURS QUI N'A PAS LIEU (`P10.20-p`, ajoutée le 2026-09-16)
--------------------------------------------------------------------------------------
La première famille juge un parcours qui a LIEU et dont une ligne est avalée. La seconde juge un
parcours qui N'A PAS LIEU DU TOUT : `if let Ok(mut s) = conn.prepare(..) { .. }` sans `else`, et le
même `if let` posé sur `query_map`. Si la lecture rate, le bloc entier est SAUTÉ, la liste reste
VIDE — et elle est servie comme complète. C'est la même phrase que le nom de ce fichier, poussée à
son extrême : la troncature à ZÉRO. `P10.20-p` l'a mesurée sur trois sites (`suppressions_get`, qui
servait « aucun collecteur n'a auto-reporté » et un parcours dit COMPLET alors que rien n'avait été
lu ; `object_field_allow` ; `compute_freshness`), les a corrigés, et a laissé À TENIR le cliquet qui
empêche la forme de revenir.

CE CLIQUET EST À ZÉRO SITE NOMMÉ, et il l'est parce que l'arbre est à zéro : relevé le 2026-09-16 sur
`daemon/src/handlers/`, sous-répertoires compris, commentaires dépouillés et `#[cfg(test)]` coupé, la
forme n'existe plus — ni sur `prepare`, ni sur `query_map`. UN GREP NAÏF EN VERRAIT UN DE PLUS,
`freshness.rs:840`, qui est la PROSE du correctif de `P10.20-g` citant la forme qu'il vient de
retirer : tout cliquet de ce dépôt doit dépouiller les commentaires, sans quoi il accuse un texte qui
raconte sa propre guérison.

UN ZÉRO NE SE DÉFEND PAS PAR UN PLANCHER DE POPULATION — il n'y a rien à mesurer. Il se défend par
les ÉPREUVES fabriquées jouées avant tout verdict (forme muette accusée, forme AVEC `else`
innocentée, forme scrutée par un `match` qui parle innocentée, forme en commentaire, forme dans une
chaîne, forme sous `cfg(test)`, `let ... else` innocenté, `query_row` laissé à la famille voisine) et
par les mutations qui les tuent — vider le geste, débrancher le jugement de l'ensemble, débrancher
l'exclusion des chaînes, poser une entrée bidon. Toutes jouées le 2026-09-16, toutes rouges.

CE QUE LA SECONDE FAMILLE A COÛTÉ, MESURÉ : 0,75 s -> 0,97 s sur `daemon/src/handlers/` (+29 %), et
non 0,75 s -> 1,50 s, parce que le dépouillement est PARTAGÉ entre les deux familles
(`preparer_le_texte`). Elle n'a RIEN coûté en câblage : elle vit dans une garde déjà branchée.

CE QU'ELLE PARTAGE ET CE QU'ELLE NE PARTAGE PAS AVEC LA PREMIÈRE. Elle partage les lecteurs, le
corpus et l'aveu du lecteur — une région avalée les fausse toutes les deux pour la même cause. Elle
NE partage PAS le plancher : le jugement des parcours muets est rendu AVANT le plancher de la
première famille, pour qu'un effondrement de celui-ci ne transforme pas une accusation en refus de
conclure. Et un site peut être accusé par les DEUX : ce sont deux fautes distinctes (le parcours peut
ne pas avoir lieu, ET s'il a lieu ses lignes sont avalées), chacune dans son ensemble nommé.

CE QUE L'ARBRE PORTE, MESURÉ LE 2026-09-16
-------------------------------------------
Relevé ligne par ligne sur `daemon/src/handlers/*.rs` (les quatre écritures d'aplatissement passées
au `grep -n`, puis chaque occurrence relue dans son contexte) :

  * QUATRE-VINGTS occurrences d'un aplatissement dans le répertoire ;
  * QUATORZE d'entre elles sont dans un COMMENTAIRE — la moitié sont des notes de lots qui racontent
    le défaut qu'ils viennent de fermer (`alerts.rs`, `liste_bornee.rs`, `destinations.rs`,
    `threat_intel.rs`). Un texte qui NOMME la forme n'est jamais un site : c'est exactement sous
    cette écriture qu'un site « connu » cesse d'exister sans qu'un `grep` le voie ;
  * SOIXANTE-SIX sont du CODE. Huit sont HORS FAMILLE, parce que leur RECEVEUR n'est pas un itérateur
    de lignes : un `Option<Option<_>>` rendu par une fonction, trois `.ok().flatten()` sur un
    `query_row` (famille VOISINE, dite plus bas), un `capture_names().flatten()` d'expression
    régulière, un `.await.ok().flatten()` de tâche, et deux lectures aplaties gardées pour les
    témoins. CES DEUX DERNIÈRES MÉRITENT D'ÊTRE DITES : elles vivent sous une FONCTION
    `#[cfg(test)]`, et `coupe_tests` NE LES COUPE PAS — il coupe au premier `#[cfg(test)] mod`, et
    aucun aplatissement de ce répertoire n'est dans un tel module (mesuré : 66 avant la coupe, 66
    après). C'est le receveur qui les tient hors famille, pas la coupe de test ;
  * restent CINQUANTE-HUIT SITES de la famille, sur trente et un fichiers. TROIS sont admis pour une
    raison écrite (deux arbitrages ASSUMÉS, un INDÉCIDABLE) ; CINQUANTE-CINQ sont des défauts.

CE RELEVÉ-LÀ A ÉTÉ FAIT SUR LE RÉPERTOIRE PLAT, ET LES HUIT HORS-FAMILLE ONT ÉTÉ RE-MESURÉS LE 2026-09-16
(lot des connecteurs), parce qu'un lot précédent avait publié un sous-compte FAUX — « cinq `.ok().flatten()`
sur l'arbre, dont deux sur un `query_row` ». Le sous-compte faux venait d'un `grep` d'UNE LIGNE : sur
`daemon/src/handlers/dashboards.rs:554`, `rustfmt` coupe entre `.ok()` et `.flatten()`, et un motif
mono-ligne ne le voit pas. Re-mesuré avec un motif qui tolère les blancs, commentaires dépouillés et
modules de test coupés : SIX `.ok().flatten()` dans `daemon/src/handlers/`, dont TROIS sur un `query_row`
(`dashboards.rs:554` — `panel_cache_ttl`, `freshness.rs:643` et `:759` — `compute_freshness`), DEUX sur une
fonction rendant `Result<Option<_>>` sous `#[cfg(test)]` (`cases.rs:307`, `caseops.rs:687` : les deux
lectures « gardées pour les témoins »), UNE sur un `.await` de tâche (`detection.rs:1317`). Avec le
`ref_bib.a_ecrire().flatten()` de `dashboards.rs:312` (un `Option<Option<_>>` rendu par une fonction) et le
`capture_names().flatten()` de `detection.rs:1290`, le compte des HORS-FAMILLE est bien HUIT, et la
composition ci-dessus est EXACTE — c'est la re-mesure du lot précédent qui était fausse, pas la phrase
d'origine. Le même motif rejoué sur l'arbre du matin (`git archive 693e475`) donne les MÊMES six : aucune
de ces occurrences n'a bougé de la journée.

CE QUE LE MÊME RELEVÉ DONNE AUJOURD'HUI, POUR QUE LA DESCENTE SE VÉRIFIE : `daemon/src/handlers/`, SOUS-
RÉPERTOIRES COMPRIS, porte 69 occurrences BRUTES et DIX dans le CODE au 2026-09-16 après `P10.20-c` (contre 81
et 67 le matin, même mesure, même répertoire ; ONZE juste avant `P10.20-c`) — les 56 corrections de la journée ont converti des
sites en COMMENTAIRES qui racontent le défaut fermé, et c'est pourquoi le compte brut ne bouge presque pas
pendant que le code fond. Des DIX : DEUX sont les sites de la famille encore admis, HUIT sont les hors-famille
énumérées ci-dessus. La ONZIÈME d'avant (`actions.rs:1173`) était un COMMENTAIRE que le lecteur partagé
`sans_commentaires_rust` prenait pour du code, parce qu'il lisait le littéral de caractère `'\"'` de
`actions.rs:888` comme une durée de vie ouvrant une chaîne ; défaut du LECTEUR, fermé par `P10.20-c` le
2026-09-16 (littéral apparié et rendu tel quel, dix témoins dans `temoins_du_lecteur`, neuf gardes re-mesurées
avant/après à verdict identique). Elle n'avait produit aucune accusation (aucun `query_map(` dans son
expression) ; ce qui est dit ici est la mesure, pas un dépouillement parfait. DEPUIS `P10.20-d` (même
jour) le lecteur tient AUSSI les chaînes brutes (`r#"…"#`, `br#"…"#`, deux niveaux de dièses) et cette
garde lui PASSE SON JOURNAL : un aveu vaut refus de conclure, plus un compte amputé rendu en vert. Ce
qu'il ne tient toujours pas — le corps des macros, les apostrophes d'attribut, le code généré — est écrit
en tête du lecteur.

CE QUE LES CINQUANTE-CINQ SERVENT, MESURÉ PAR UN CRITÈRE ÉCRIT (le type de retour de la fonction
englobante, rejouable sur l'arbre) : QUARANTE-CINQ rendent DIRECTEMENT un type porteur de corps —
`Response` 27, `Json<Value>` 11, `Value` 5, `Option<Value>` 1, `Vec<Value>` 1. QUATRE rendent un type
métier qui entre dans un corps servi un cran plus loin (`dominant_tactic_and_target`, `index_stats`,
`soql_known_sources_bornees`, `sources_declarees_par_connecteurs`), soit QUARANTE-NEUF servis. Les SIX
dernières ne servent AUCUN corps : `respond_run`, `load_policies`, `load_active_silences`,
`load_active_engagements`, `eval_baseline`, `sla_recalcule_la_priorite_bornee` — et ce sont celles que
cette garde sait le moins bien formuler, parce qu'il n'y existe aucun corps où poser un aveu. LE CRITÈRE
est mécanique et se rejoue ; LE CLASSEMENT ci-dessus, lui, est celui du MATIN. La campagne du jour a
depuis changé le type de retour de plusieurs de ces fonctions — `index_stats` (rang trois) et
`dominant_tactic_and_target` (rang quatre, vague B) rendent un `rusqlite::Result`, ce qui est
précisément le geste que cette garde réclame pour une lecture sans corps — donc le rejouer aujourd'hui
donnerait une autre répartition. Ce paragraphe décrit le POINT DE DÉPART, pas l'arbre courant.

POURQUOI UNE SŒUR, ET NON UNE EXTENSION DE `P10.7-g`
-----------------------------------------------------
`check_a_read_that_did_not_happen_is_never_served_as_a_fact.py` juge la même espèce de faute, mais sa
POPULATION est la VOIE : tout appel à `read_with_watchdog`, `read_with`, `with_write`, `run_query_ex`
ou `run_query`. Derrière cette population, l'avalement n'est qu'un SYMPTÔME parmi d'autres, et la
garde ne le voit que là où la voie le lui présente. Deux angles morts de FORME y sont mesurés, et ce
fichier les prouve plutôt que de les alléguer (les deux extraits sont soumis à `lectures_avalees` de
la garde sœur dans les épreuves internes, et elle n'en rend AUCUN) :

  * `chaine_apres` ne lit que le jeton COLLÉ à la fermante de la lecture. Sur
    `query_map(…).map(|x| x.flatten().collect())`, ce jeton est `map(…)` — absent du vocabulaire
    `AVALE` — et le `.flatten()` vit DANS l'argument, que ce lecteur-là n'ouvre pas ;
  * un aplatissement posé sur une VARIABLE LIÉE n'est relié à aucune lecture
    (`let Ok(rows) = s.query_map(…) else { … }; for src in rows.flatten()`).

LES DEUX EXTRAITS QUI PROUVENT CES ANGLES MORTS SONT FABRIQUÉS, ET PLUS ADOSSÉS À AUCUN SITE (relu le
2026-09-16, après la vague B du rang quatre). Ils l'ont été : la chaîne enveloppée vivait en
`daemon/src/handlers/caseops.rs:323` et `:363` (fermés par CE lot), la liaison en
`daemon/src/handlers/soql_meta.rs:218` (fermée au rang deux). Les citer encore comme « sites prouvés »
enseignerait un arbre qui n'existe plus. Et les épreuves elles-mêmes n'y ont JAMAIS été adossées — c'est
la règle que ce fichier s'écrit pour tous ses témoins : un extrait pris sur l'arbre serait une RANÇON,
qui rougirait le jour où le site est réparé. L'écriture (ii) n'a d'ailleurs plus AUCUN site sur l'arbre
au 2026-09-16, et la garde continue de la voir — c'est exactement ce que des extraits fabriqués
garantissent.

Et la population des cinq voies laisse hors jugement tout ce qui vit derrière `req_conn!` ou derrière
un `&Connection` passé en argument — c'est-à-dire la grande majorité des gestionnaires, et la
quasi-totalité des cinquante-huit sites ci-dessus. ÉLARGIR LA GARDE SŒUR NE LES AURAIT PAS ATTEINTS :
sa mesure du 2026-08-30 a refusé `req_conn!` pour son GRAIN (une seule lecture avalée y compte autant
de fois qu'il y a de gestionnaires), et ce refus est toujours vrai. La population de CETTE garde
n'est donc pas une voie : c'est LE GESTE. Un aplatissement dont le receveur est un itérateur de
lignes est un site, quelle que soit la façon dont la connexion est arrivée là — et le grain est
exact, parce qu'un geste ne se démultiplie pas par le nombre de ses appelants.

POURQUOI UN ENSEMBLE NOMMÉ, ET NON UN COMPTE
---------------------------------------------
Un cliquet de compte a deux angles morts, tous deux mesurés sur la garde sœur : une accusation fermée
et une accusation ouverte le même jour laissent le compte immobile (le site neuf entre en silence),
et une descente réelle n'est qu'une note que personne n'est obligé de lire. `SITES_ADMIS` est donc
une LISTE DE SITES, jugée DANS LES DEUX SENS : une accusation hors ensemble est une FORME NEUVE
(rouge), une entrée sans accusation est une EXEMPTION SANS OBJET (rouge). La liste ne peut que
descendre, et zéro est atteignable — une garde dont l'ensemble serait vide ne réclame rien, donc elle
n'est pas une rançon.

RELEVÉ APRÈS LE RANG UN (2026-09-16, même jour, lot suivant) : les huit sites de sécurité et
d'administration sont ENTIÈRES OU AVOUÉES (collecte en bloc, `corps_de_liste_illisible`, cinq cents
nommé pour le tableau nu des fournisseurs d'identité, cinq cent trois pour la remise d'actions, tick
aveugle compté pour le responder local) et leurs entrées ont quitté l'ensemble : la garde rendait
alors cinquante sites sur vingt-six fichiers, quarante-sept défauts connus.

RELEVÉ APRÈS LE RANG DEUX (2026-09-16, lot suivant) : les dix sites de DÉTECTION sont fermés à leur
tour — cinq listes servies avouent (`rules_list`, `parsers_list`, `baselines_list`, `playbooks_list`,
le vocabulaire de complétion, dont le cache SWR n'accueille plus un aveu), cinq lectures INTERNES
rendent un `Result` et chaque appelant agit en connaissance (tour de dispatch sauté et compté sans
marquer aucune alerte envoyée ; cache d'engagements CONSERVÉ et compté plutôt que vidé ; ligne de base
« non évaluée » ; source « indéterminée » et jamais « inattendue »). La garde rend désormais QUARANTE
sites sur vingt-deux fichiers, trente-sept défauts connus. Les comptes des paragraphes ci-dessus sont
le RELEVÉ DU MATIN, gardés tels quels comme point de départ ; les planchers ne montent jamais.

RELEVÉ APRÈS LE RANG TROIS (2026-09-16, lot suivant) : les cinq sites où la ligne avalée FAUSSAIT UN
NOMBRE sont fermés. Le recensement des entités à risque (`risk_entities_page`) solde sa passe bornée en
bloc AVANT de compter, si bien que `total`, `over_threshold_total` et `over_threshold_hors_parc`
retombent ENSEMBLE sur `TotalBorne::sans_lecture()` et deux `null` — un compte dont une ligne n'a pas pu
être lue est « non établi », jamais un entier plus petit. La progression d'un case (`case_steps_json`),
qui DÉRIVE de `steps.len()`, est `null` sous l'aveu plutôt que `0/0`. Les deux lectures qui alimentent
`indexes` (`index_stats`, désormais porteuse d'un `rusqlite::Result`, et la liste des politiques) avouent
ensemble : plus aucun index ne s'affiche « 0 event », plus aucun n'est absent de la liste, et aucune
politique perdue ne se relit « hérite du global » (`ok` retombe à `false`, comme le catalogue des rôles
du rang un). Le recalcul d'échéances SLA (`sla_recalcule_la_priorite_bornee`), dernière lecture INTERNE
de l'ensemble, porte sa ligne illisible dans `manque` : la route ne rend plus `204` = « tout recalculé »
au-dessus d'un dossier qu'elle n'a pas su lire. La garde rend désormais TRENTE-CINQ sites sur VINGT
fichiers, trente-deux défauts connus — tous de rang quatre.

RELEVÉ APRÈS LA VAGUE A DU RANG QUATRE (2026-09-16, lot suivant) : treize accusations de rang quatre
tombent sur SIX fonctions de CONTENU ET DE MODÈLES. Trois listes servies avouent sous la forme du dépôt
(`liste_bornee::corps_de_liste_illisible` : la clé existe, VIDE, et `error` nomme la cause) — le
sélecteur de vues (`views_list`), les panneaux d'un tableau de bord (`dash_get`, qui PANIQUAIT sur deux
`unwrap()` et dont le solde en bloc précède désormais le filtre de portée, pour qu'un échec de ligne ne
puisse pas se cacher derrière « ce panneau était privé ») et la liste des datasets (`datasets_list`).
Deux corps portent PLUSIEURS listes — SIX familles de savoir (`knowledge_list`) et les TROIS étages de
l'arbre de modèles (`datamodels_list`) — et l'aveu y NOMME la lecture ratée
(`liste_bornee::corps_de_listes_illisibles` : `non_lus` porte les clés concernées, chacune présente et
vide, les autres restant servies), parce qu'un `error` global y suspecterait cinq familles honnêtes avec
la sixième ; c'est la forme que `case_metrics_json` (`non_etablis`) et `freshness.rs` (`non_lus`)
emploient déjà. Le SEUL site du lot qui REFUSE au lieu d'avouer dans son corps est la CAPTURE
d'instantané (`capture_dashboard_data`, qui rend désormais un `rusqlite::Result`) : son produit n'est pas
une page relue en ligne mais un artefact FIGÉ dans `dashboard_snapshot.data` et partageable par jeton à
des tiers — un aveu embarqué y serait relu par quelqu'un qui ne peut plus rien recouper, donc
`snapshot_create` rend un cinq cent trois nommé et n'écrit RIEN. La garde rend désormais VINGT-DEUX sites
sur DIX-SEPT fichiers, dix-neuf défauts connus, tous de rang quatre.

RELEVÉ APRÈS LA VAGUE B DU RANG QUATRE (2026-09-16, lot suivant) : les DIX-NEUF dernières accusations de
rang quatre tombent, sur DIX-NEUF fonctions et QUATORZE fichiers, et la classe du rang quatre devient
VIDE — l'ensemble nommé ne porte plus que les DEUX arbitrages assumés et l'INDÉCIDABLE. Ce sont les
listes de RÉGLAGE, et ce qui leur est propre a été écrit plutôt que supposé : l'objet avalé continue
d'EXISTER et d'AGIR (un canal de notification invisible émet quand même, un rapport planifié invisible
s'exécute quand même sous son `run_as_role`, une règle d'ingestion invisible jette ou masque quand même,
un lookup invisible enrichit quand même toute recherche GXQL, une destination invisible exporte quand
même hors du périmètre), si bien que la conclusion « ce n'est pas configuré » fait fabriquer une SECONDE
copie qui s'AJOUTE à la première. Le silence produisait donc du DOUBLON OPÉRANT, jamais un simple trou
d'affichage. QUINZE routes servies soldent leur parcours en bloc et avouent par
`liste_bornee::corps_de_liste_illisible` (clé présente et VIDE, `error` nommant la cause ; `ok` retombé à
`false` pour les deux tables de déclaration ; métadonnées d'une AUTRE lecture conservées — fiche
d'engagement, métadonnée de runbook, compteurs live d'ingestion) ; DEUX corps nominalement TABLEAU NU
(`ai_providers_list`, `destinations_list`) rendent un cinq cents NOMMÉ, la forme des fournisseurs
d'identité du rang un ; `case_runbooks_json`, qui porte DEUX lectures de lignes, avoue PAR LECTURE
(`corps_de_listes_illisibles`, `non_lus`), l'autre restant servie ; les deux listes de `caseops.rs`
avaient DÉJÀ la branche `Lignes::Illisible` du fabricant borné, et le solde en bloc y fait simplement
tomber aussi l'erreur de LIGNE. TROIS sites PANIQUAIENT sur deux `unwrap()` (`notifiers_list`,
`processors_list`, `lookups_list`) et QUATRE portaient DEUX voies de silence (un 500 ou un `[]` en 200
sur la préparation, plus la ligne avalée) : les deux voies rendent désormais le même aveu. Enfin,
`dominant_tactic_and_target` rend un `rusqlite::Result` parce que sa valeur ENTRE DANS UNE
RECOMMANDATION — mesuré sous mutation : en avalant UNE alerte sur trois, la tactique dominante bascule de
`initial-access` à `credential-access`, donc le runbook recommandé change —, et un échec TOTAL rendait le
triplet vide, indiscernable d'« aucune alerte liée », le cas où le repli générique est LÉGITIME ; son
second appelant, `case_runbook_attach`, refuse en cinq cent trois nommé sans rien écrire, parce
qu'attacher FIGE les étapes et que le geste est idempotent-refusant. La garde rend désormais TROIS sites
sur TROIS fichiers, ZÉRO défaut connu.

RELEVÉ APRÈS LE LOT DES CONNECTEURS (2026-09-16, lot suivant) — DEUX GESTES, ET LE SECOND CHANGE LA
POPULATION. (1) L'INDÉCIDABLE EST TRANCHÉ : `fleet::host_inventory_simple` était du CODE MORT. La question
que son entrée portait — code mort, ou lecteur à REBRANCHER ? — se tranche par la mesure : aucun appelant
de production (deux appels de témoin seulement), un doc-commentaire « partagé par /api/integrations » faux
depuis que `freshness.rs:315` passe par `hotes_du_panneau_bornes`, et un rebranchement qui ré-introduirait
la liste NON BORNÉE que `P11.20-l` a fermée le 2026-09-03. La fonction est SUPPRIMÉE, ses deux témoins
rebranchés sur le chemin de production (ils y gagnent : ils jugeaient une fonction que la route n'appelait
plus), et la classe INDÉCIDABLE devient VIDE. (2) LE CORPUS DESCEND : cette garde ne lisait que le
répertoire PLAT et le disait dans son verdict ; elle lit désormais `daemon/src/handlers/` ET SES
SOUS-RÉPERTOIRES, en élaguant par le geste partagé (`parcours_des_sources`, `P11.8-m`). La descente fait
entrer UN site que la borne plate cachait — `connectors/mod.rs:273`, `connectors_list` — et il est CORRIGÉ
dans le même lot, pas admis : parcours soldé en bloc et cinq cents NOMMÉ, la forme du TABLEAU NU
(`idp_providers_list` au rang un, `ai_providers_list` et `destinations_list` à la vague B). Ce site portait
les DEUX voies de silence du rang quatre — `Err(_) => Vec::new()` sur la préparation, aplatissement sur le
parcours — et ce qui lui est propre est mesuré : `web/connectors.js:29` peint « aucun connecteur … rien
n'est collecté » sur un tableau vide, pendant que le connecteur avalé continue d'interroger son vendeur et
d'ingérer (`run_due_connectors` lit la table, pas cette vue), et que son `last_error`, son `last_ok` et son
`has_key` — la seule trace d'une clé de livraison PUSH liée — disparaissent avec lui. La garde rend
désormais DEUX sites sur DEUX fichiers : EXACTEMENT les deux arbitrages ASSUMÉS, et plus rien d'autre.

LES PLANCHERS SE RELISENT, AVEC LEUR DATE (2026-09-16, après la vague B du rang quatre). Ils valaient
15/11 après la vague A, dérivés du relevé de ce moment-là (22 sites sur 17 fichiers) ; l'arbre porte
maintenant 3 sites sur 3 fichiers pour de VRAIES corrections. La MÊME règle des deux tiers, réappliquée
au relevé DU JOUR, donne 69 % de 3 = 2,07 pour les sites — 2 — et 65 % de 3 = 1,95 pour les fichiers, où
le plancher et l'arrondi NE DONNENT PLUS LA MÊME VALEUR (1 contre 2) : à cette magnitude la règle cesse
de discriminer, et c'est la plus HAUTE des deux qui est retenue, parce qu'un plancher plus bas serait un
filet plus lâche et que rien n'oblige à descendre plus qu'il ne faut. D'où 2/2. LA RÉSERVE, ET ELLE EST
PLUS IMPORTANTE QUE LE CHIFFRE : la population restante est EXACTEMENT les deux arbitrages ASSUMÉS et
l'INDÉCIDABLE. Aucun des trois ne se ferme par un lot de correction — les deux premiers ne partiraient
que si leur arbitrage CHANGEAIT, le troisième que si sa question était TRANCHÉE. Le plancher ne sépare
donc plus « descente réelle » de « découverte cassée » : il ne reste plus rien à faire descendre. Ce qui
sépare encore, c'est le jugement de l'ensemble nommé DANS LES DEUX SENS — l'un de ces trois sites cessant
d'être vu devient une « exemption sans objet », rouge —, et ce filet-là ne dépend d'aucun volume. Le
plancher n'est plus qu'un garde-fou grossier contre un effondrement TOTAL du lecteur.

CE QUE LA RELECTURE DES PLANCHERS VALAIT APRÈS LA VAGUE A, GARDÉ POUR QUE LA RÈGLE SE VÉRIFIE SUR TROIS
PASSAGES. Ils valaient
24/13 après le rang trois, re-dérivés alors du relevé de ce jour-là (35 sites sur 20 fichiers) ; l'arbre
porte maintenant 22 sites sur 17 fichiers pour de VRAIES corrections, et un plancher laissé à 24 rougirait
sur le dépôt que cette garde vient d'aider à guérir. La MÊME règle des deux tiers est réappliquée au relevé
DU JOUR : 69 % de 22 = 15, 65 % de 17 = 11. Ils ne montent jamais, et le filet de l'ensemble nommé jugé
dans les deux sens reste, lui, insensible au volume.

CE QUE LA RELECTURE DES PLANCHERS VALAIT APRÈS LE RANG TROIS, GARDÉ POUR QUE LA RÈGLE SE VÉRIFIE SUR DEUX
PASSAGES. Ils valaient alors 40/20, dérivés du relevé du matin (58 sites sur 31 fichiers, soit 69 % et
65 %) ; l'arbre portait 35 sites sur 20 fichiers pour de VRAIES corrections, et un plancher laissé à 40
aurait rendu la garde rouge sur le dépôt qu'elle venait d'aider à guérir. Ils ont été re-dérivés du relevé
de ce jour-là par la même règle — 69 % de 35 = 24, 65 % de 20 = 13 —, ils ne montent jamais, et ils se
relisent de la même façon à chaque descente.
Ce n'est pas le seul filet : une découverte PARTIELLEMENT aveugle est déjà prise par le jugement de
l'ensemble nommé dans les deux sens (chaque site qui cesse d'être vu sans que son entrée soit retirée
devient une « exemption sans objet », rouge). Le plancher ne couvre que le cas où la découverte s'effondre
ASSEZ pour que le rouge de l'ensemble puisse être pris pour une guérison.

LES CINQUANTE-CINQ DÉFAUTS ÉTAIENT ADMIS LE JOUR DE L'ÉCRITURE — IL N'EN RESTE AUCUN
------------------------------------------------------------------------------------------
Ils étaient entrés dans l'ensemble pour que la garde puisse être câblée VERTE le jour où elle est
écrite : une garde qui naît rouge sur cinquante-cinq sites ne se branche pas, et une garde qui ne se
branche pas ne tient rien. Chaque entrée portait SA raison, en une ligne, qui disait ce qui était servi
tronqué et le geste LOCAL qui la fermait. Corriger un site SANS retirer son entrée fait rougir la garde
en « exemption sans objet » : c'est voulu, et c'est ce qui a empêché l'ensemble de devenir un décor —
c'est aussi ce qui l'a fait DESCENDRE, 58 -> 50 -> 40 -> 35 -> 22 -> 3, en cinq lots du 2026-09-16.

CE QUE LE VERT DIT DÉSORMAIS, ET CE QU'IL NE DIT TOUJOURS PAS. Les trois classes de DÉFAUTS CONNUS sont
VIDES : l'arbre ne porte plus aucun aplatissement de cette famille qui soit reconnu comme un défaut. Ce
qui reste dans l'ensemble — deux arbitrages ASSUMÉS et un INDÉCIDABLE — n'est pas une dette à rembourser
mais trois positions ÉCRITES, que seul un changement d'arbitrage ou une question tranchée retirera. Le
vert ne dit rien de plus qu'avant sur ce que cette garde ne sait pas voir : la liste en est plus bas, et
elle n'a pas raccourci.
"""
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
from check_every_help_trigger_has_a_section import (  # noqa: E402  (source unique de vérité)
    refuser_sur_aveu, sans_commentaires_rust, temoins_du_lecteur)

RACINE = (os.path.abspath(sys.argv[1]) if len(sys.argv) > 1
          else os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))))

# LA GARDE SŒUR EST IMPORTÉE POUR SES LECTEURS DE FORME (`apparier`, `coupe_tests`, `fonctions`, et
# depuis `P10.20-p`/`P10.20-r` `if_let_sans_branche`, `spans_de_chaines_rust`, `dans_une_chaine_rust`,
# `MOTIF_LIANT_IF_LET_TOUT_MOTIF`) : les recopier ferait deux appariements de parenthèses qui
# pourraient diverger, et ce dépôt paie cher les lecteurs jumeaux. L'import est SAIN — il n'exécute
# qu'une compilation de regexes (mesuré à 23 ms) — MAIS son module évalue sa propre `RACINE` À
# L'IMPORT, par un `git rev-parse` quand aucun argument ne lui est passé. On lui passe donc la racine
# DÉJÀ calculée ici : l'import ne cherche plus de dépôt git (une archive dépliée en est dépourvue) et
# ne peut pas juger un arbre différent de celui que cette garde juge.
# `temoins_des_lecteurs_de_forme` EST IMPORTÉ AVEC EUX ET JOUÉ (`P10.20-r`) : un import n'exécute aucun
# témoin, et tant que ceux-ci vivaient dans le `valider_instrument` de la garde sœur, un `apparier`
# amputé de sa règle du littéral laissait CETTE garde-ci VERTE À SORTIE IDENTIQUE — mesuré.
_ARGV = sys.argv
sys.argv = [_ARGV[0], RACINE]
try:
    from check_a_read_that_did_not_happen_is_never_served_as_a_fact import (  # noqa: E402
        MOTIF_LIANT_IF_LET_TOUT_MOTIF, apparier, coupe_tests, dans_une_chaine_rust, fonctions,
        if_let_sans_branche, spans_de_chaines_rust, temoins_des_lecteurs_de_forme)
finally:
    sys.argv = _ARGV

# L'ÉLAGAGE DU PARCOURS EST LE GESTE PARTAGÉ, JAMAIS UNE LISTE RECOPIÉE (`P11.8-m`, et
# `check_no_guard_walks_the_tree_unpruned.py` juge la divergence). Ce module n'évalue AUCUNE racine à
# l'import (`racine_designee()` n'y est appelée que dans un corps de fonction) : l'importer ne cherche pas
# de dépôt git et ne peut pas juger un arbre différent de celui-ci.
from check_every_style_selector_has_a_target import parcours_des_sources  # noqa: E402

HANDLERS = os.path.join(RACINE, "daemon", "src", "handlers")
DEMON = os.path.join(RACINE, "daemon", "src")
ETIQUETTE = "liste-tronquee"

# --- LE GESTE, ET SON RECEVEUR -------------------------------------------------------------------
# LA LECTURE : les deux méthodes de rusqlite qui rendent un ITÉRATEUR DE `Result<T>`. `query_row` n'y
# est PAS — il rend UNE ligne, son `.ok()` confond « aucune ligne » et « pas lu », et c'est une
# famille VOISINE que cette garde ne juge pas (elle le dit dans son verdict). Au 2026-09-16,
# `query_and_then` n'a AUCUN site dans `daemon/src/handlers/` (`grep -rn query_and_then` : 0) ; il est
# nommé parce qu'il porte la MÊME forme, et le jour où il entre, il entre jugé.
LECTURE_LIGNES = re.compile(r"\.\s*(?:query_map|query_and_then)\s*\(")
# L'AVALEMENT, SOUS SES QUATRE ÉCRITURES DE SURFACE. Les espaces sont tolérés partout : un `rustfmt`
# qui coupe la ligne ne doit pas faire disparaître un site.
AVALE_LIGNE = re.compile(
    r"\.\s*(?:flatten\s*\(\s*\)"
    r"|filter_map\s*\(\s*Result\s*::\s*ok\s*\)"
    r"|filter_map\s*\(\s*\|\s*[A-Za-z_]\w*\s*\|\s*[A-Za-z_]\w*\s*\.\s*ok\s*\(\s*\)\s*\)"
    r"|flat_map\s*\(\s*\|\s*[A-Za-z_]\w*\s*\|\s*[A-Za-z_]\w*\s*\.\s*ok\s*\(\s*\)\s*\))")
# Les jetons TRANSPARENTS d'une chaîne directe : ils changent la façon dont l'échec de la REQUÊTE est
# traité, jamais celui d'une LIGNE. `?` et `unwrap()` propagent ou tuent ; `expect(..)` aussi.
TRANSPARENT = ("?", "unwrap", "expect")
# La liaison d'une lecture à un nom, sous les quatre formes que l'arbre porte (`let`, `let Ok(..)`
# d'un `let ... else`, `if let Ok(..)`, et le bras d'un `match` dont la lecture est le scrutateur).
LIE_PAR_LET = re.compile(
    r"\b(?:if\s+)?let\s+(?:Ok\s*\(\s*)?(?:mut\s+)?([A-Za-z_]\w*)\s*\)?\s*(?::[^=]*)?=\s*[^;]*$", re.S)
MATCH_EN_TETE = re.compile(r"\bmatch\s+[^;{}]*$", re.S)
LIE_PAR_BRAS = re.compile(r"\bOk\s*\(\s*(?:mut\s+)?([A-Za-z_]\w*)\s*\)\s*=>")
# `for <motif> in <nom>.flatten()` : le même site que la liaison, isolé pour que la phrase imprimée
# nomme la BOUCLE — c'est là que le lecteur ira, pas sur le `let` qui est vingt lignes plus haut.
BOUCLE_AVANT = re.compile(r"\bfor\s+[^;{}]*\bin\s+$", re.S)

ECRITURES = {
    "i": "écriture (i), chaîne directe",
    "ii": "écriture (ii), chaîne enveloppée",
    "iii": "écriture (iii), liaison",
    "iv": "écriture (iv), boucle sur une liaison",
}
# Une accusation par OCCURRENCE d'aplatissement : quand deux écritures désignent la MÊME occurrence,
# la plus SPÉCIFIQUE gagne, et le site n'est jamais compté deux fois.
RANG_ECRITURE = {"i": 0, "ii": 1, "iv": 2, "iii": 3}

# ================================================================================================
# LA SECONDE FAMILLE — LE PARCOURS QUI N'A PAS LIEU (`P10.20-p`, 2026-09-16)
# ================================================================================================
# CE QU'ELLE JUGE, ET POURQUOI C'EST LA MÊME PHRASE QUE LE NOM DU FICHIER. La première famille juge un
# parcours qui a LIEU et dont une ligne est avalée : la liste servie est TRONQUÉE. Celle-ci juge un
# parcours qui N'A PAS LIEU DU TOUT — `if let Ok(mut s) = conn.prepare(..) { .. }` sans `else`, ou le
# même `if let` sur `query_map` : si la préparation rate (cache de schéma de pool périmé, table hors
# d'atteinte, colonne qu'une migration vient d'ajouter), le bloc est SAUTÉ, la liste reste VIDE, et
# elle est servie comme complète. C'est la troncature à ZÉRO, et c'est l'affirmation la plus grave
# qu'un corps de liste sache porter : « il n'y a rien » au lieu de « je n'ai pas lu ».
#
# POURQUOI ICI ET NON DANS LA GARDE DE FORME DES LECTURES UNIQUES, MESURÉ ET DIT (`P10.20-p` laissait
# le choix ouvert entre les deux fichiers) :
#   * LE NOM. `check_a_single_row_read_that_failed_is_never_served_as_a_fact` dit ce qu'elle tient : UNE
#     LIGNE. Une préparation ratée ne rend aucune ligne et `query_map` rend un ITÉRATEUR ; y loger cette
#     famille rendrait ce nom faux pour un tiers de son contenu, et ce dépôt juge les noms. Ici le nom
#     reste exact : une liste vide servie comme complète EST une liste tronquée servie comme complète.
#   * LE CORPUS ET LES LECTEURS sont déjà les bons (`daemon/src/handlers/`, sous-répertoires compris,
#     commentaires dépouillés, `#[cfg(test)]` coupé) : zéro ligne de découverte à réécrire.
#   * LE COÛT, ET IL N'EST PAS NUL : `main()` d'ici REFUSE DE CONCLURE (code 2) quand le lecteur avoue
#     ou quand le plancher de la PREMIÈRE famille est franchi, et ce refus TAIRAIT la seconde. Le
#     jugement de la seconde famille est donc placé AVANT le plancher de la première — un effondrement
#     du plancher de l'une n'efface pas les accusations de l'autre, il les laisse imprimées. Ce qui
#     reste partagé (l'aveu du lecteur, les épreuves d'instrument) doit l'être : les deux familles lisent
#     le même texte avec les mêmes lecteurs, et un lecteur faux les rend fausses toutes les deux.
#   * CE QU'IL FAUDRAIT CÂBLER SI ELLE VIVAIT AILLEURS : une garde neuve coûterait un pas de `ci.yml` et
#     une ligne d'agrégation, et resterait ROUGE dans
#     `check_every_guard_written_is_a_guard_wired.py` jusqu'à ce que ce pas existe. Ici, RIEN À CÂBLER.
#
# CE QUE CETTE FAMILLE NE PARTAGE PAS AVEC LA PREMIÈRE : un site peut être accusé par les DEUX (une
# préparation muette dont le parcours, quand il a lieu, aplatit ses lignes). Ce sont DEUX fautes
# distinctes — le parcours peut ne pas avoir lieu, ET s'il a lieu ses lignes sont avalées — et chacune
# a son ensemble nommé. Aucun site n'est jamais compté deux fois DANS LE MÊME ensemble.
PREPARATION = re.compile(r"\.\s*(?:prepare|prepare_cached)\s*\(")
# `query_row` N'ENTRE PAS : il rend UNE ligne, pas un parcours, et c'est la famille de la garde sœur.
# MESURÉ le 2026-09-16 sur `daemon/src/handlers/` : le SEUL `if let Ok(..) = <lecture>` sans `else` du
# répertoire est un `query_row` (`action_approve`, actions.rs:565, liaison par TUPLE), et il est laissé
# HORS de cet ensemble À DESSEIN — il relève de `P10.20-q`, dont le remède touche le registre.
PARCOURS_MUET = {"prepare": PREPARATION, "query_map": LECTURE_LIGNES}
FORMES_MUETTES = {
    "prepare": "préparation muette — `if let Ok(..) = <conn>.prepare(..) { .. }` sans `else`",
    "query_map": "parcours muet — `if let Ok(..) = <stmt>.query_map(..) { .. }` sans `else`",
}

# L'ENSEMBLE NOMMÉ DE LA SECONDE FAMILLE — VIDE, ET JUGÉ DANS LES DEUX SENS.
# Il part vide parce que l'arbre est à zéro : relevé le 2026-09-16 sur `daemon/src/handlers/`,
# sous-répertoires compris, commentaires dépouillés et `#[cfg(test)]` coupé — ZÉRO `if let Ok(..) =
# <conn>.prepare(` et ZÉRO sur `query_map` (un grep NAÏF en verrait un de plus : `freshness.rs:840`,
# qui est la PROSE du correctif de `P10.20-g` citant la forme qu'il a retirée — tout cliquet doit
# dépouiller les commentaires, sans quoi il accuse un texte qui raconte sa propre guérison).
# LA CLÉ EST (fichier, fonction) ET LA VALEUR LE TUPLE DES FORMES, jamais un compte : un COMPTE se
# laisse compenser, et réécrire une préparation muette en parcours muet laisserait le total immobile.
# ZÉRO EST LA VALEUR ATTENDUE, ET C'EST UN CLIQUET, PAS UN CONSTAT : la non-dégénérescence ne peut PAS
# venir d'un plancher de population (elle est nulle), elle vient des ÉPREUVES fabriquées jouées avant
# tout verdict — forme muette accusée, forme avec `else` innocentée, forme dans un `match` qui parle
# innocentée, forme en commentaire, forme dans une chaîne, forme sous `cfg(test)` — et de la mutation
# qui les tue. Sans elles, ce zéro serait vert le jour où le geste cesserait de voir quoi que ce soit.
PARCOURS_MUETS_ADMIS = {}

# --- PLANCHER DE NON-DÉGÉNÉRESCENCE (relu le 2026-09-16, après le LOT DES CONNECTEURS) -----------
# Ils ne réclament PAS un volume de code : ils constatent qu'une LECTURE est cassée. Sous eux, rendre
# vert serait rendre vert en étant aveugle, et c'est le défaut que cette garde nomme, appliqué à
# elle-même : la découverte est cassée, pas le dépôt guéri.
#
# PREMIÈRE ÉCRITURE (relevé du matin, 2026-09-16) : 58 sites sur 31 fichiers -> 40/20, soit 69 % et
# 65 %. PREMIÈRE RELECTURE (même jour, après les rangs un, deux et trois) : 35 sites sur 20 fichiers
# -> 24/13, par la même règle. SECONDE RELECTURE (même jour, après la VAGUE A du rang quatre) :
# 22 sites sur 17 fichiers -> 15/11. TROISIÈME RELECTURE (même jour, après la VAGUE B) : l'arbre porte
# 3 sites sur 3 fichiers pour de VRAIES corrections — 55 entrées retirées de l'ensemble nommé depuis le
# matin, aucune amnistiée — et un plancher laissé à 15 rougirait sur le dépôt que cette garde vient
# d'aider à guérir.
#
# CE QUE LA RÈGLE DONNE À CETTE MAGNITUDE, ET OÙ ELLE CESSE DE DISCRIMINER. 69 % de 3 = 2,07 -> 2 pour
# les sites (troncature et arrondi s'accordent). 65 % de 3 = 1,95 : la troncature donne 1, l'arrondi
# donne 2 — la règle des deux tiers ne tranche plus. On retient la plus HAUTE (2), parce qu'un plancher
# plus bas serait un filet plus lâche et que rien n'oblige à descendre plus qu'il ne faut. D'où 2/2.
#
# LA RÉSERVE, PLUS IMPORTANTE QUE LE CHIFFRE : la population restante est EXACTEMENT les deux
# arbitrages ASSUMÉS et l'INDÉCIDABLE. Aucun des trois ne se ferme par un lot de correction — les deux
# premiers ne partiraient que si leur arbitrage CHANGEAIT, le troisième que si sa question était
# TRANCHÉE. Le plancher ne sépare donc plus « descente réelle » de « découverte cassée » : il ne reste
# plus rien à faire descendre. Ce qui sépare encore, c'est le jugement de l'ensemble nommé DANS LES DEUX
# SENS (l'un de ces trois sites cessant d'être vu devient une « exemption sans objet », rouge), et ce
# filet-là ne dépend d'aucun volume. Le plancher n'est plus qu'un garde-fou grossier contre un
# effondrement TOTAL du lecteur. Il ne monte jamais.
#
# QUATRIÈME RELECTURE (2026-09-16, après le LOT DES CONNECTEURS). L'arbre porte 2 sites sur 2 fichiers :
# l'INDÉCIDABLE a été tranché (code mort SUPPRIMÉ) et le site que la descente dans `handlers/connectors/`
# a fait entrer a été CORRIGÉ dans le même lot. La règle des deux tiers, réappliquée au relevé DU JOUR :
# 69 % de 2 = 1,38 -> 1, et 65 % de 2 = 1,30 -> 1 — cette fois troncature et arrondi S'ACCORDENT tous les
# deux sur 1, donc la réserve écrite à la relecture précédente (« la règle ne discrimine plus, on retient
# la plus haute ») ne s'applique pas ici : il n'y a plus de désaccord à arbitrer. D'où 1/1.
#
# ET IL Y A UNE RAISON DE DESCENDRE, PAS SEULEMENT UNE RÈGLE QUI LE PERMET. Laisser 2/2 au-dessus d'une
# population de 2 ferait de ce plancher une RANÇON sur les deux arbitrages ASSUMÉS : le jour où
# `liste_bornee::lire` rendra un `Result` par ligne — l'entrée dit elle-même qu'elle devra DISPARAÎTRE ce
# jour-là — la garde tomberait sous le plancher et refuserait de conclure, en accusant la DÉCOUVERTE là
# où le dépôt aurait guéri. C'est exactement le défaut que cette garde nomme, appliqué à elle-même dans
# l'autre sens. À 1/1 elle ne refuse plus que sur un effondrement TOTAL du lecteur (zéro site), ce qui est
# tout ce qu'un plancher peut encore séparer à cette magnitude. Il ne monte jamais.
PLANCHER_SITES = 1
PLANCHER_FICHIERS = 1

# ================================================================================================
# L'ENSEMBLE NOMMÉ — TROIS CLASSES, JUGÉES DANS LES DEUX SENS
# ================================================================================================
# --- CLASSE 1 : LES ARBITRAGES ASSUMÉS. Ce ne sont PAS des défauts : l'aplatissement y est le
# moindre mal, et l'arbitrage est écrit DANS LE CODE, pas ici. Ces deux entrées survivent à une
# campagne de correction ; elles ne disparaissent que si l'arbitrage lui-même change.
SITES_ASSUMES = {
    # `liste_bornee.rs:41-44` l'écrit : perdre la LISTE ENTIÈRE pour une ligne échangerait une
    # troncature contre une indisponibilité, et ce module rend déjà `Illisible` quand la REQUÊTE
    # échoue. RÉSERVE À DIRE : une liste amputée d'une ligne se déclare `Lues`, donc le `served <
    # window` du corps borné s'y lit « la borne ne mord pas » alors qu'une ligne manque. Le jour où
    # `lire` rend un `Result` par ligne, cette entrée doit DISPARAÎTRE.
    ("daemon/src/handlers/liste_bornee.rs", "lire"): 1,
    # FAIL-CLOSED, documenté en `datamodels.rs:257-259` : une allowlist AMPUTÉE fait REFUSER le champ
    # au Pivot (400), elle n'en invente aucun. L'absence y est un refus, pas une valeur rassurante —
    # c'est ce que cette garde réclame ailleurs, et l'accuser poserait un rouge qu'aucun geste local
    # ne referme.
    ("daemon/src/handlers/datamodels.rs", "object_field_allow"): 1,
}

# --- CLASSE 2 : L'INDÉCIDABLE. Ni défaut ni arbitrage tant que la question n'est pas tranchée ;
# l'entrée porte la question, pas une excuse.
#
# CLASSE TRANCHÉE ET VIDÉE LE 2026-09-16 — UN SITE, ET LA QUESTION AVAIT UNE RÉPONSE MESURABLE. L'entrée
# qui vivait ici était `fleet::host_inventory_simple`, et elle portait la question « code MORT (le
# supprimer ferme le site) ou lecteur à REBRANCHER (il redevient un défaut de rang 3) ? ». Trois mesures
# l'ont tranchée : (a) `grep -rn host_inventory_simple` ne rendait, hors prose, QUE la définition et DEUX
# appels de TÉMOIN — aucun appelant de production ; (b) son doc-commentaire disait « partagé par
# /api/integrations », et c'était faux depuis que `freshness.rs:315` sert la liste du panneau par
# `hotes_du_panneau_bornes` (bornée, coupe prouvée par la ligne excédentaire, total compté) ; (c) le
# REBRANCHER aurait ré-introduit une liste NON BORNÉE dans un panneau de synthèse, c'est-à-dire le défaut
# que `P11.20-l` a fermé le 2026-09-03. La fonction est donc SUPPRIMÉE de `fleet.rs`, et ses deux témoins
# rebranchés sur `hotes_du_panneau_bornes` : ils jugeaient une fonction que la route n'appelait plus, ils
# jugent maintenant le chemin de production. Le site ne se ferme pas par un aveu — il se ferme parce qu'il
# n'y a plus de site. Le dictionnaire reste, VIDE : la classe est une classe de l'ensemble, et son vide
# est le seul état qui dise « aucune question n'est en suspens ici ».
SITE_INDECIDABLE = {}

# --- CLASSE 3 : LES DÉFAUTS CONNUS, NON CORRIGÉS. Chaque entrée dit ce qui est servi tronqué et le
# geste LOCAL qui la ferme. Trois gestes reviennent, et aucun ne demande de toucher à cette garde :
# rendre un `Result` au lieu d'un `Vec`, solder le parcours en bloc
# (`collect::<rusqlite::Result<Vec<_>>>()`), ou poser `error`/`non_lu` dans le `json!` DÉJÀ construit.
# Les rangs ordonnent la dette par ce qu'un lecteur CROIT quand la liste est courte.

# RANG 1 — SÉCURITÉ ET ADMINISTRATION : une ligne avalée retire un accès, une règle de blocage ou une
# action de la vue de celui qui décide. C'est la classe où « la liste est courte » se lit « il n'y a
# rien de plus », et où cette lecture-là est une décision de sécurité.
#
# RANG UN CLOS LE 2026-09-16 — HUIT SITES, SIX FICHIERS, PLUS UNE SEULE ENTRÉE. Les huit entrées qui
# vivaient ici (`tokens_list`, `users_list`, `roles_list`, `idp_providers_list`, `netban_list`,
# `field_filters_list`, `actions_pending`, `respond_run`) sont RETIRÉES parce que leurs sites sont
# corrigés, pas amnistiés : chaque parcours est soldé en bloc (`collect::<rusqlite::Result<Vec<_>>>()`)
# et l'échec sort sous la forme que le dépôt emploie déjà — `error` dans le corps déjà construit
# (`liste_bornee::corps_de_liste_illisible`) pour les cinq listes JSON, un 5xx nommé pour la liste SSO
# (son corps est un TABLEAU NU, il n'a aucune clé où poser l'aveu), un 503 nommé pour la remise TSV aux
# agents (son seul lecteur écarte toute ligne non numérique, donc une ligne d'aveu n'y serait lue par
# personne), et un tour SAUTÉ ET COMPTÉ (`metrics::compter_un_tick_aveugle("responder_local", ..)`) pour
# la seule lecture interne du rang, qui ne sert aucun corps. Le dictionnaire reste, VIDE : le rang est
# une classe de l'ensemble, et son vide est le seul état qui dise « il n'y a plus rien à admettre ici ».
DEFAUTS_RANG_1_SECURITE = {}

# RANG 2 — DÉTECTION : une ligne avalée n'est pas une ligne d'affichage en moins, c'est de la
# DÉTECTION EN MOINS. Le produit continue de tourner, plus aveugle, et rien ne l'écrit.
#
# RANG DEUX CLOS LE 2026-09-16 — DIX SITES, SEPT FICHIERS, PLUS UNE SEULE ENTRÉE. Les dix entrées qui
# vivaient ici (`rules_list`, `parsers_list`, `baselines_list`, `playbooks_list`, `eval_baseline`,
# `load_policies`, `load_active_silences`, `load_active_engagements`, `soql_known_sources_bornees`,
# `sources_declarees_par_connecteurs`) sont RETIRÉES parce que leurs sites sont corrigés, pas amnistiés.
# CINQ listes SERVIES soldent leur parcours en bloc et avouent sous la forme du dépôt
# (`liste_bornee::corps_de_liste_illisible`) ; le vocabulaire de complétion y ajoute la distinction que
# son type déclarait ne pas tenir (`SourcesConnues::non_lue`) et son cache SWR de deux minutes N'ACCUEILLE
# PLUS un aveu — une lecture ratée ne se ressert pas. CINQ lectures INTERNES rendent désormais un `Result`,
# et chaque appelant agit en connaissance : le dispatch de notifications SAUTE son tour en le comptant
# (`dispatch_policies` / `dispatch_silences`) plutôt que de router à plat ou de notifier ce qu'un silence
# non lu aurait tu, et il ne marque aucune alerte `notified=1` (le tour suivant relit) ; le cache de portée
# des engagements GARDE sa valeur précédente et compte le tour (`engagement_scope_refresh`) plutôt que de
# se vider — se vider arme l'auto-ban contre une cible de pentest autorisée —, la route `GET
# /api/engagements/active` rendant un cinq cent trois nommé parce que son corps est un TABLEAU NU et que
# son unique consommateur (`collectors/engagement-adapter.sh`) porte déjà un fail-closed gradué sur le
# statut ; l'évaluation de ligne de base sur un historique non lu rend `ok=false` — « non évalué », ni
# anomalie ni normalité — que `run_baselines` compte sans avancer `last_bucket` ; et une source dont la
# déclaration par connecteur n'a pas pu être lue est servie `indeterminee`, jamais `unexpected`. Le
# dictionnaire reste, VIDE : le rang est une classe de l'ensemble, et son vide est le seul état qui dise
# « il n'y a plus rien à admettre ici ».
DEFAUTS_RANG_2_DETECTION = {}

# RANG 3 — DES COMPTES SERVIS COMME DES FAITS : ici la ligne avalée ne manque pas seulement dans une
# liste, elle FAUSSE un nombre que le corps affirme (un total, un recensement, un cumul d'index).
#
# RANG TROIS CLOS LE 2026-09-16 — CINQ SITES, QUATRE FICHIERS, PLUS UNE SEULE ENTRÉE. Les cinq entrées
# qui vivaient ici (`risk_entities_page`, `case_steps_json`, `index_stats`, `index_policies_list`,
# `sla_recalcule_la_priorite_bornee`) sont RETIRÉES parce que leurs sites sont corrigés, pas amnistiés.
# Le geste est le même qu'aux deux rangs précédents — solder le parcours en bloc
# (`collect::<rusqlite::Result<Vec<_>>>()`) — mais la conséquence est propre à ce rang : c'est le NOMBRE
# qui retombe, jamais un entier plus petit servi comme un fait. `risk_entities_page` compte APRÈS avoir
# soldé sa passe bornée, donc `total`, `over_threshold_total` et `over_threshold_hors_parc` valent
# ensemble `null` (`TotalBorne::sans_lecture()`, la règle « jamais (0, false) » que `liste_bornee` écrit
# pour lui-même) ; `case_steps_json`, dont `progress.total` DÉRIVE de `steps.len()`, sert `steps: []`
# avec `error` (`liste_bornee::corps_de_liste_illisible`) et `progress: null` plutôt qu'un `0/0` qui se
# lirait « ce case n'a aucune étape, et c'est établi » ; les DEUX lectures qui alimentent `indexes`
# avouent ensemble — `index_stats` rend désormais un `rusqlite::Result`, donc plus aucun index géré ne
# s'affiche « 0 event » et plus aucun index non géré ne DISPARAÎT de la liste (elle était dérivée des
# clés de cette map), et plus aucune politique perdue ne se relit « hérite du global », `ok` retombant
# à `false` comme le catalogue des rôles du rang un ; `sla_recalcule_la_priorite_bornee`, la DERNIÈRE
# lecture interne de l'ensemble, porte sa ligne illisible dans `manque`, de sorte que la route d'upsert
# SLA ne rend plus `204` = « tout recalculé » au-dessus d'un dossier qu'elle n'a pas su lire. Le
# dictionnaire reste, VIDE : le rang est une classe de l'ensemble, et son vide est le seul état qui
# dise « il n'y a plus rien à admettre ici ».
DEFAUTS_RANG_3_COMPTES = {}

# RANG 4 — LISTES DE CONFIGURATION ET DE CONTENU : la ligne avalée fait disparaître un objet d'une
# liste que l'opérateur lit comme exhaustive. Moins grave que les trois rangs précédents, jamais
# anodin : c'est sur ces listes qu'on conclut « ce n'est pas configuré ».
#
# VAGUE A CLOSE LE 2026-09-16 — TREIZE ACCUSATIONS, SIX FONCTIONS, QUATRE FICHIERS. Les entrées de
# `capture_dashboard_data`, `dash_get`, `views_list`, `knowledge_list` (SIX lectures), `datamodels_list`
# (TROIS) et `datasets_list` sont RETIRÉES parce que leurs sites sont corrigés, pas amnistiés. Trois
# listes servies soldent leur parcours en bloc et avouent par `liste_bornee::corps_de_liste_illisible` ;
# les DEUX corps qui portent plusieurs listes avouent PAR LECTURE — `corps_de_listes_illisibles` pose
# `non_lus` avec le NOM des familles non lues, chacune présente et vide, les autres restant servies,
# parce qu'un aveu qui couvre tout ne couvre rien. La capture d'instantané, elle, REFUSE : elle rend un
# `rusqlite::Result` et `snapshot_create` répond 503 sans rien écrire, parce que son produit est FIGÉ et
# PARTAGEABLE PAR JETON — un aveu embarqué dans l'artefact serait relu par un tiers qui ne peut plus
# rien recouper.
#
# VAGUE B CLOSE LE 2026-09-16 — DIX-NEUF ACCUSATIONS, DIX-NEUF FONCTIONS, QUATORZE FICHIERS. Les entrées
# de `case_links_json`, `case_queues_json`, `host_settings_get`, `policies_list`, `silences_list`,
# `ai_providers_list`, `engagement_get`, `reports_list`, `dominant_tactic_and_target`,
# `case_runbooks_json`, `runbooks_admin_list`, `runbook_get`, `notifiers_list`, `destinations_list`,
# `processors_list`, `list_for_owner`, `source_settings_get`, `lookups_list` et
# `workflow_actions_list` sont RETIRÉES parce que leurs sites sont corrigés, pas amnistiés. QUINZE
# listes servies soldent leur parcours en bloc et avouent par `liste_bornee::corps_de_liste_illisible` ;
# DEUX corps nominalement TABLEAU NU rendent un cinq cents nommé (forme de `idp_providers_list`, rang
# un) ; `case_runbooks_json`, qui porte DEUX lectures de lignes, avoue PAR LECTURE
# (`corps_de_listes_illisibles` : `non_lus` NOMME la lecture ratée, l'autre restant servie) ; les deux
# listes de `caseops.rs` avaient DÉJÀ la branche `Lignes::Illisible` du fabricant borné, et le solde en
# bloc y fait tomber aussi l'erreur de LIGNE. `dominant_tactic_and_target`, seule lecture du rang qui ne
# sert aucun corps, rend un `rusqlite::Result` — le geste que cette garde nomme pour ce cas —, parce que
# sa valeur ENTRE DANS UNE RECOMMANDATION et qu'un échec TOTAL rendait le triplet vide, indiscernable
# d'« aucune alerte liée ». Le dictionnaire reste, VIDE : le rang est une classe de l'ensemble, et son
# vide est le seul état qui dise « il n'y a plus rien à admettre ici ».
DEFAUTS_RANG_4_CONFIGURATION = {}

CLASSES = (
    ("assumé", SITES_ASSUMES),
    ("indécidable", SITE_INDECIDABLE),
    ("défaut connu — rang 1 sécurité/administration", DEFAUTS_RANG_1_SECURITE),
    ("défaut connu — rang 2 détection", DEFAUTS_RANG_2_DETECTION),
    ("défaut connu — rang 3 comptes servis comme des faits", DEFAUTS_RANG_3_COMPTES),
    ("défaut connu — rang 4 configuration et contenu", DEFAUTS_RANG_4_CONFIGURATION),
)
SITES_ADMIS = {}
for _libelle, _classe in CLASSES:
    for _cle, _n in _classe.items():
        SITES_ADMIS[_cle] = SITES_ADMIS.get(_cle, 0) + _n
DEFAUTS_CONNUS = {c: n for lib, cl in CLASSES if lib.startswith("défaut") for c, n in cl.items()}


# ================================================================================================
# LES LECTEURS DE FORME
# ================================================================================================
# Le littéral de CARACTÈRE, pour que `positions_de_coupe` ne prenne pas le guillemet d'un `'"'` pour
# l'ouverture d'une chaîne. C'est le trou de `P10.20-c`, un cran plus bas : le lecteur partagé
# `sans_commentaires_rust` a été corrigé le 2026-09-16, mais il RESTITUE le littéral tel quel, et ce
# scanner-ci, qui lit sa sortie, y retombait. MESURÉ le 2026-09-16 sur la garde sœur de `P10.20-b` :
# trois fichiers de `handlers/` portent le cas (`actions.rs:889`, `freshness.rs:496`,
# `panneau_avoue.rs:237`), et la fausse chaîne ouverte par leur `'"'` avalait la fin du fichier.
# ICI l'effet était BORNÉ — `positions_de_coupe` ne sert qu'à `debut_instruction`, donc au PRÉFIXE lu
# par `liaisons` et à l'extrait imprimé ; un préfixe faux fait manquer une liaison, il n'en invente
# pas. Le verdict de cette garde est IDENTIQUE avant et après (2 sites, 2 fichiers, mêmes écritures,
# sortie octet pour octet identique). Il est corrigé quand même : une borne d'instruction fausse est
# une borne d'instruction fausse, et le prochain lecteur qui s'appuiera dessus n'aura pas cette chance.
# Une durée de vie (`'a`, `'static`) n'a pas de guillemet fermant après un caractère : elle ne matche
# pas. LE TÉMOIN DE CETTE CORRECTION VIT DANS LA GARDE SŒUR
# (`check_a_single_row_read_that_failed_is_never_served_as_a_fact.py`, « épreuve des LITTÉRAUX, accord
# des deux lecteurs ») : elle IMPORTE `positions_de_coupe`, et la mutation qui retire ces trois lignes
# la fait rougir.
CARACTERE_LITTERAL = re.compile(r"'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f]{1,6}\}|.)|[^\\'])'")


def positions_de_coupe(code):
    """Indices des `;`, `{` et `}` HORS chaîne : les bornes d'instruction. Une accolade dans un
    littéral SQL ne coupe rien, et un `'"'` n'ouvre pas de chaîne."""
    out, j, n = [], 0, len(code)
    while j < n:
        c = code[j]
        car = CARACTERE_LITTERAL.match(code, j)
        if car:
            j = car.end()
            continue
        if c == '"':
            j += 1
            while j < n and code[j] != '"':
                j += 2 if code[j] == "\\" else 1
            j += 1
            continue
        if c in ";{}":
            out.append(j)
        j += 1
    return out


def debut_instruction(coupes, i):
    """Index du premier caractère de l'instruction qui contient `i`."""
    bas, haut = 0, len(coupes)
    while bas < haut:
        mil = (bas + haut) // 2
        if coupes[mil] < i:
            bas = mil + 1
        else:
            haut = mil
    return coupes[bas - 1] + 1 if bas else 0


def chaine_detaillee(code, fin):
    """Les méthodes chaînées après la fermante en `fin`, AVEC les bornes de leurs arguments :
    `[(nom, index du jeton, début d'argument, fin d'argument)]` et l'index de fin d'expression.

    C'EST LA DIFFÉRENCE AVEC `chaine_apres` DE LA GARDE SŒUR, ET C'EST TOUT LE PREMIER ANGLE MORT :
    là-bas l'argument est élidé en `(…)`, donc `map(|x| x.flatten().collect())` rend le jeton
    `map(…)`, qui n'appartient à aucun vocabulaire d'avalement. Ici l'argument est RENDU, et
    l'écriture (ii) l'ouvre."""
    jetons, k = [], fin + 1
    while k < len(code):
        c = code[k]
        if c in " \t\n":
            k += 1
            continue
        if c == "?":
            jetons.append(("?", k, -1, -1))
            k += 1
            continue
        if c != ".":
            break
        m = re.match(r"\.\s*([A-Za-z_]\w*)\s*", code[k:])
        if not m:
            break
        nom, debut_jeton = m.group(1), k
        k += m.end()
        if code.startswith("::", k):  # turbofish : `.collect::<Vec<_>>()`
            g = code.find("<", k)
            if g < 0:
                break
            prof, j = 0, g
            while j < len(code):
                if code[j] == "<":
                    prof += 1
                elif code[j] == ">":
                    prof -= 1
                    if prof == 0:
                        break
                j += 1
            if j >= len(code):
                break
            k = j + 1
            while k < len(code) and code[k] in " \t\n":
                k += 1
        a1 = a2 = -1
        if k < len(code) and code[k] == "(":
            e = apparier(code, k)
            if e < 0:
                break
            a1, a2 = k + 1, e
            k = e + 1
        jetons.append((nom, debut_jeton, a1, a2))
    return jetons, k


def jeton_avale(nom, code, a1, a2):
    """Le jeton lui-même EST un avalement de ligne."""
    if nom == "flatten":
        return a1 >= 0 and not code[a1:a2].strip()
    if nom in ("filter_map", "flat_map") and a1 >= 0:
        arg = code[a1:a2].strip()
        return bool(re.fullmatch(r"Result\s*::\s*ok", arg)
                    or re.fullmatch(r"\|\s*[A-Za-z_]\w*\s*\|\s*[A-Za-z_]\w*\s*\.\s*ok\s*\(\s*\)", arg))
    return False


def portee_englobante(fns, i):
    """(nom, début, fin) de la plus petite fonction qui contient `i`, ou None."""
    dedans = [f for f in fns if f[2] < i < f[3]]
    return min(dedans, key=lambda f: f[3] - f[2]) if dedans else None


def liaisons(code, coupes, debut_lecture, apres, fns):
    """Les noms auxquels CETTE lecture est liée, avec la portée où les chercher :
    `[(nom, début de portée, fin de portée)]`.

    Deux formes, et elles couvrent l'arbre du 2026-09-16 : le préfixe d'instruction qui ouvre par
    `let`/`let Ok(..)`/`if let Ok(..)`, et le `match` dont la lecture est le SCRUTATEUR, dont les bras
    lient par `Ok(<nom>)`. La portée s'arrête à la fonction englobante — un nom n'est pas suivi d'une
    fonction à l'autre, et le dire est plus honnête que de fouiller le fichier entier."""
    out = []
    prefixe = code[debut_instruction(coupes, debut_lecture):debut_lecture]
    englobante = portee_englobante(fns, debut_lecture)
    fin_portee = englobante[3] if englobante else len(code)
    m = LIE_PAR_LET.search(prefixe)
    if m:
        out.append((m.group(1), apres, fin_portee))
    # LE BRAS DU `match` DONT LA LECTURE EST LE SCRUTATEUR. La portée est le BLOC du `match`, jamais
    # la fonction : un `Ok(rows)` de bras ne vit pas au-delà de son accolade.
    j = apres
    while j < len(code) and code[j] in " \t\n":
        j += 1
    if j < len(code) and code[j] == "{" and MATCH_EN_TETE.search(prefixe):
        f = apparier(code, j)
        if f > 0:
            for b in LIE_PAR_BRAS.finditer(code, j, f):
                out.append((b.group(1), b.end(), f))
    return out


# ================================================================================================
# LA DÉCOUVERTE — UN SITE EST UNE OCCURRENCE D'APLATISSEMENT, PAS UN APPEL
# ================================================================================================
def preparer_le_texte(chemin_relatif, texte, aveux_du_lecteur=None):
    """`(code, fonctions, bornes d'instruction, intervalles de chaîne)` — LE DÉPOUILLEMENT, UNE FOIS.

    Les DEUX familles de cette garde lisent le MÊME texte avec les MÊMES lecteurs. Le faire deux fois
    par fichier DOUBLAIT le temps d'exécution (MESURÉ le 2026-09-16 sur `daemon/src/handlers/` :
    0,75 s avant la seconde famille, 1,50 s en dépouillant deux fois, 0,97 s en dépouillant une seule).
    La seconde famille coûte donc 0,22 s (+29 %) et non 0,75 s. `aveux_du_lecteur` recueille ce que le LECTEUR
    PARTAGÉ avoue (`P10.20-d`) ; il est COMMUN aux deux familles, parce qu'une région avalée les
    fausse toutes les deux pour la même cause."""
    journal_du_lecteur = []
    brut = sans_commentaires_rust(texte, journal_du_lecteur)
    if journal_du_lecteur and aveux_du_lecteur is not None:
        aveux_du_lecteur[chemin_relatif] = [f"ligne {texte.count(chr(10), 0, o) + 1} : {m}"
                                            for m, o in journal_du_lecteur]
    code = coupe_tests(brut)
    return code, fonctions(code), positions_de_coupe(code), spans_de_chaines_rust(code)


def analyser(chemin_relatif, texte, journal, aveux_du_lecteur=None, prepare=None):
    """[(chemin, ligne, fonction, écriture, extrait)] pour UN fichier. `journal` recueille ce que CETTE
    GARDE avoue avoir perdu (une parenthèse non appariée) : un aveu vaut refus de conclure, jamais un
    compte amputé rendu vert. `aveux_du_lecteur` recueille ce que le LECTEUR PARTAGÉ avoue (`P10.20-d`,
    2026-09-16) — deux causes distinctes, deux remèdes distincts, jamais mélangées dans un même sac.
    Sans ce second journal, une région avalée par le lecteur retirait des sites SANS UN MOT, et le
    plancher de découverte accusait le dépôt là où la cause était l'instrument.

    `prepare` est la sortie de `preparer_le_texte` quand l'appelant l'a déjà calculée pour l'autre
    famille ; les ÉPREUVES, elles, passent un texte brut et la laissent se calculer."""
    code, fns, coupes, _spans = prepare or preparer_le_texte(chemin_relatif, texte, aveux_du_lecteur)
    trouves = {}

    def poser(index, ecriture, extrait):
        ancien = trouves.get(index)
        if ancien and RANG_ECRITURE[ancien[0]] <= RANG_ECRITURE[ecriture]:
            return
        trouves[index] = (ecriture, extrait)

    for m in LECTURE_LIGNES.finditer(code):
        ouvrante = m.end() - 1
        fin = apparier(code, ouvrante)
        if fin < 0:
            ligne = code.count("\n", 0, m.start()) + 1
            journal.append(f"{chemin_relatif}:{ligne} — parenthèse d'appel non appariée sur la lecture "
                           "de lignes : le lecteur a perdu la fin de l'expression")
            continue
        jetons, apres = chaine_detaillee(code, fin)

        # --- (i) CHAÎNE DIRECTE : seuls `?`, `unwrap()` et `expect(..)` s'intercalent.
        for nom, index, a1, a2 in jetons:
            if jeton_avale(nom, code, a1, a2):
                poser(index, "i", code[index:index + 60].split("\n")[0].strip())
                break
            if nom not in TRANSPARENT:
                break

        # --- (ii) CHAÎNE ENVELOPPÉE : l'avalement vit DANS l'argument d'un jeton de la chaîne.
        for nom, _index, a1, a2 in jetons:
            if a1 < 0:
                continue
            for av in AVALE_LIGNE.finditer(code, a1, a2):
                poser(av.start(), "ii", code[av.start():av.start() + 60].split("\n")[0].strip())

        # --- (iii)/(iv) LIAISON : la lecture porte un nom, et le nom porte l'avalement.
        for nom_lie, portee_deb, portee_fin in liaisons(code, coupes, m.start(), apres, fns):
            motif = re.compile(r"\b" + re.escape(nom_lie) + r"\s*(" + AVALE_LIGNE.pattern + r")")
            for u in motif.finditer(code, portee_deb, portee_fin):
                amont = code[max(0, u.start() - 200):u.start()]
                ecriture = "iv" if BOUCLE_AVANT.search(amont) else "iii"
                poser(u.start(1), ecriture, code[u.start():u.start() + 60].split("\n")[0].strip())

    sites = []
    for index in sorted(trouves):
        ecriture, extrait = trouves[index]
        englobante = portee_englobante(fns, index)
        if not englobante:
            ligne = code.count("\n", 0, index) + 1
            journal.append(f"{chemin_relatif}:{ligne} — aplatissement HORS de toute fonction : la portée "
                           "est introuvable, et un site sans fonction ne peut pas entrer dans l'ensemble")
            continue
        sites.append((chemin_relatif, code.count("\n", 0, index) + 1, englobante[0], ecriture, extrait))
    return sites


def analyser_les_parcours_muets(chemin_relatif, texte, journal, aveux_du_lecteur=None, prepare=None):
    """[(chemin, ligne, fonction, forme, extrait)] pour UN fichier — LA SECONDE FAMILLE (`P10.20-p`).

    LE GESTE, EN UNE PHRASE : une préparation (`prepare`, `prepare_cached`) ou un parcours (`query_map`,
    `query_and_then`) LIÉ par un `if let Ok(..)` dont le bloc n'est suivi d'AUCUN `else`. Le prédicat
    est `if_let_sans_branche`, IMPORTÉ de la garde des lectures non faites et jamais recopié ; le motif
    de liaison est le LARGE (`MOTIF_LIANT_IF_LET_TOUT_MOTIF`), qui voit aussi `Ok((a, b, c))` — le motif
    étroit de la jambe B est aveugle au tuple, mesuré le 2026-09-16, et un ensemble qui part de ZÉRO
    n'a aucun plafond à déplacer en voyant plus.

    TROIS EXCLUSIONS, ET CHACUNE A SON ÉPREUVE : les commentaires sont DÉPOUILLÉS (sans quoi la prose du
    correctif de `P10.20-g`, qui cite la forme qu'elle a retirée, serait un site), les modules
    `#[cfg(test)]` sont COUPÉS (un test peut écrire n'importe quelle forme sans qu'une route la serve),
    et les LITTÉRAUX DE CHAÎNE sont exclus (`spans_de_chaines_rust` : une forme citée dans un gabarit de
    message ou dans un extrait de doc n'est pas du code, et `if let Ok(..) = x.prepare(y) { }` écrit
    DANS une chaîne serait autrement accusé — mesuré en écrivant cette famille).

    `prepare` a le même sens que dans `analyser` : le dépouillement est PARTAGÉ entre les deux
    familles, jamais refait."""
    code, fns, coupes, spans = prepare or preparer_le_texte(chemin_relatif, texte, aveux_du_lecteur)
    trouves = {}
    for forme, motif in PARCOURS_MUET.items():
        for m in motif.finditer(code):
            if dans_une_chaine_rust(spans, m.start()):
                continue
            ouvrante = m.end() - 1
            fin = apparier(code, ouvrante)
            if fin < 0:
                ligne = code.count("\n", 0, m.start()) + 1
                journal.append(f"{chemin_relatif}:{ligne} — parenthèse d'appel non appariée sur une "
                               "préparation ou un parcours : le lecteur a perdu la fin de l'expression")
                continue
            _jetons, apres = chaine_detaillee(code, fin)
            if not if_let_sans_branche(code, m.start(), apres, MOTIF_LIANT_IF_LET_TOUT_MOTIF):
                continue
            trouves[m.start()] = forme
    sites = []
    for index in sorted(trouves):
        englobante = portee_englobante(fns, index)
        if not englobante:
            ligne = code.count("\n", 0, index) + 1
            journal.append(f"{chemin_relatif}:{ligne} — préparation ou parcours muet HORS de toute "
                           "fonction : la portée est introuvable, et un site sans fonction ne peut pas "
                           "entrer dans l'ensemble")
            continue
        extrait = " ".join(code[debut_instruction(coupes, index):index + 60].split())[:110]
        sites.append((chemin_relatif, code.count("\n", 0, index) + 1, englobante[0],
                      trouves[index], extrait))
    return sites


def juger_les_parcours_muets(sites, admis):
    """[(genre, fichier, phrase)] — le MÊME jugement dans les deux sens que la première famille, mais
    sur les FORMES et non sur un compte : une préparation muette réécrite en parcours muet rougit des
    DEUX côtés (forme neuve pour la nouvelle, exemption sans objet pour l'ancienne), ce qui est la
    bonne lecture — ce n'est pas le même site."""
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
                               f"FORME NEUVE — `{fn}` ({chemin}) porte la forme « "
                               f"{FORMES_MUETTES[forme]} » {n_vu} fois pour {n_admis} admise(s) ; "
                               f"ligne(s) en trop : {lignes}. Si "
                               "la lecture rate, le bloc est SAUTÉ : la liste reste VIDE et elle est "
                               "servie comme complète, sans un mot. La forme doit AVOUER (une fin de "
                               "parcours non commencée, une cause « pas lu » portée par le corps), ou "
                               "rendre un `Result` à l'appelant — sinon elle entre dans "
                               "PARCOURS_MUETS_ADMIS AVEC sa raison, jamais en silence."))
            if n_vu < n_admis:
                ecarts.append(("exemption sans objet", chemin,
                               f"EXEMPTION SANS OBJET — `{fn}` ({chemin}) est admis {n_admis} fois sous "
                               f"la forme « {FORMES_MUETTES[forme]} » et n'est accusé que {n_vu} fois : "
                               "le site avoue désormais, ou il a CHANGÉ DE FORME, ou il n'existe plus, "
                               "ou cette garde a cessé de le voir. Dans les quatre cas l'entrée se "
                               "retire à la main EN DISANT LEQUEL — un canal qui rétrécit ne doit pas "
                               "passer pour un défaut fermé."))
    return ecarts


def fichiers_du_corpus(racine=None):
    """Tous les `.rs` de `daemon/src/handlers/`, SOUS-RÉPERTOIRES COMPRIS, artefacts ÉLAGUÉS.

    LA PREMIÈRE FORME NE LISAIT QUE LE RÉPERTOIRE PLAT, et son verdict le disait — un site y vivait
    pourtant (`connectors/mod.rs`, `connectors_list`), invisible à la garde qui existait pour le voir.
    Une borne qui s'annonce n'est pas une borne innocente : elle dit exactement où écrire ce que la garde
    ne verra pas. La descente est donc faite, et le site qu'elle a fait entrer a été CORRIGÉ le même jour.

    L'ÉLAGAGE PASSE PAR `parcours_des_sources` (le geste partagé, `P11.8-m`) : il exclut PAR NOM, DANS la
    descente (`dossiers[:] = …`, jamais un filtrage après coup qui aurait déjà LU le répertoire), et
    porter une liste à la main ici serait la « copie divergente » que
    `check_no_guard_walks_the_tree_unpruned.py` juge. Cette racine-ci DESCEND (`daemon/src/handlers`), elle
    n'est donc pas DOMINANTE au sens de cette garde-là et n'aurait pas été accusée ; on élague quand même,
    parce qu'un `vendor/` ou un `.venv` posé sous l'arbre n'est pas une impossibilité de principe, et que
    le coût est d'une ligne.

    `racine` n'est là que pour les ÉPREUVES INTERNES, qui doivent pouvoir soumettre un arbre FABRIQUÉ à ce
    lecteur-ci sans toucher au dépôt."""
    racine = HANDLERS if racine is None else racine
    if not os.path.isdir(racine):
        return []
    trouves = []
    for dossier, fichiers in parcours_des_sources(racine):
        trouves += [os.path.join(dossier, n) for n in fichiers
                    if n.endswith(".rs") and os.path.isfile(os.path.join(dossier, n))]
    return sorted(trouves)


def decouvrir():
    """Les DEUX familles en UNE passe de lecture : chaque fichier n'est ouvert et dépouillé qu'une fois.

    Le journal et les aveux du lecteur sont COMMUNS, et c'est voulu : une région avalée par le lecteur
    fausse les deux familles pour la même cause, et deux sacs séparés laisseraient croire le contraire."""
    sites, muets, journal, aveux_du_lecteur = [], [], [], {}
    for chemin in fichiers_du_corpus():
        with open(chemin, encoding="utf-8", errors="replace") as fh:
            texte = fh.read()
        rel = os.path.relpath(chemin, RACINE)
        prepare = preparer_le_texte(rel, texte, aveux_du_lecteur)
        sites += analyser(rel, texte, journal, aveux_du_lecteur, prepare)
        muets += analyser_les_parcours_muets(rel, texte, journal, aveux_du_lecteur, prepare)
    return sites, muets, journal, aveux_du_lecteur


# ================================================================================================
# LE JUGEMENT CONTRE L'ENSEMBLE NOMMÉ — DANS LES DEUX SENS
# ================================================================================================
def juger_contre_l_ensemble(sites, admis):
    """[(genre, fichier, phrase)] — `forme neuve` quand une accusation dépasse ce qui est admis,
    `exemption sans objet` quand une entrée n'est plus accusée autant qu'elle le déclare."""
    vus = {}
    for chemin, _ligne, fn, _ecriture, _extrait in sites:
        vus[(chemin, fn)] = vus.get((chemin, fn), 0) + 1
    ecarts = []
    for (chemin, fn), n in sorted(vus.items()):
        admise = admis.get((chemin, fn), 0)
        if n > admise:
            ecarts.append(("forme neuve", chemin,
                           f"FORME NEUVE — `{fn}` aplatit {n} fois un itérateur de lignes pour "
                           f"{admise} admise(s) dans SITES_ADMIS. La forme doit solder son parcours "
                           "(`collect::<rusqlite::Result<Vec<_>>>()`), rendre un `Result`, ou entrer "
                           "dans l'ensemble AVEC sa raison — jamais en silence."))
    for (chemin, fn), n in sorted(admis.items()):
        if vus.get((chemin, fn), 0) < n:
            ecarts.append(("exemption sans objet", chemin,
                           f"EXEMPTION SANS OBJET — `{fn}` est admis {n} fois dans SITES_ADMIS et n'est "
                           f"accusé que {vus.get((chemin, fn), 0)} fois : le site solde désormais son "
                           "parcours, ou n'existe plus, ou cette garde a cessé de le voir. Dans les trois "
                           "cas l'entrée se retire à la main EN DISANT LEQUEL — un canal qui rétrécit ne "
                           "doit pas passer pour un défaut fermé."))
    return ecarts


# ================================================================================================
# LES ÉPREUVES INTERNES — JOUÉES AVANT TOUTE LECTURE DU DÉPÔT, DANS LES DEUX SENS
# ================================================================================================
# Les extraits sont FABRIQUÉS ici, jamais pris sur l'arbre : adosser un témoin à `tokens_list` ou à
# `knowledge_list` en ferait une RANÇON — il rougirait le jour où le site est réparé, et aucun geste
# ne pourrait le refermer.
EPREUVES = [
    # (nom, source Rust, écritures attendues — vide = aucune accusation)
    ("(i) chaîne directe, `unwrap()` intercalé",
     'fn e1(conn: &Connection) -> Vec<i64> {\n'
     '    let mut s = conn.prepare("SELECT a FROM t").unwrap();\n'
     '    s.query_map([], |r| r.get(0)).unwrap().flatten().collect()\n}\n', {"i"}),
    ("(i) chaîne directe, `?` intercalé, avalement par `filter_map(Result::ok)`",
     'fn e1b(conn: &Connection) -> rusqlite::Result<Vec<i64>> {\n'
     '    let mut s = conn.prepare("SELECT a FROM t")?;\n'
     '    Ok(s.query_map([], |r| r.get(0))?.filter_map(Result::ok).collect())\n}\n', {"i"}),
    ("(ii) chaîne enveloppée, l'avalement vit dans l'argument de `map`",
     'fn e2(conn: &Connection) -> Vec<i64> {\n'
     '    conn.prepare("SELECT a FROM t")\n'
     '        .and_then(|mut s| s.query_map([], |r| r.get(0)).map(|x| x.flatten().collect()))\n'
     '        .unwrap_or_default()\n}\n', {"ii"}),
    ("(iii) liaison par `let ... else`",
     'fn e3(conn: &Connection) -> Vec<i64> {\n'
     '    let Ok(mut s) = conn.prepare("SELECT a FROM t") else { return Vec::new() };\n'
     '    let Ok(rows) = s.query_map([], |r| r.get(0)) else { return Vec::new() };\n'
     '    rows.flat_map(|r| r.ok()).collect()\n}\n', {"iii"}),
    ("(iii) liaison par un bras de `match` dont la lecture est le scrutateur",
     'fn e3b(conn: &Connection, mut s: Statement) -> Vec<i64> {\n'
     '    match s.query_map([], |r| r.get(0)) {\n'
     '        Ok(rows) => rows.flatten().collect(),\n'
     '        Err(_) => Vec::new(),\n'
     '    }\n}\n', {"iii"}),
    ("(iv) boucle sur une liaison posée par `if let Ok(..)`",
     'fn e4(conn: &Connection) -> Vec<i64> {\n'
     '    let mut o = Vec::new();\n'
     '    if let Ok(mut s) = conn.prepare("SELECT a FROM t") {\n'
     '        if let Ok(rows) = s.query_map([], |r| r.get(0)) {\n'
     '            for a in rows.flatten() { o.push(a); }\n'
     '        }\n    }\n    o\n}\n', {"iv"}),
    # --- LES TÉMOINS NÉGATIFS : chacun est une forme que la garde DOIT laisser passer.
    ("témoin négatif : `query_row(..).ok().flatten()` (famille voisine, Option imbriquée)",
     'fn n1(conn: &Connection) -> Option<i64> {\n'
     '    conn.query_row("SELECT MAX(ts) FROM t", [], |r| r.get::<_, Option<i64>>(0)).ok().flatten()\n}\n',
     set()),
    # CE TÉMOIN-CI A ÉTÉ AJOUTÉ PARCE QUE LE PRÉCÉDENT NE TENAIT PAS CE QUE SON NOM ANNONÇAIT, ET
    # C'EST MESURÉ (2026-09-16) : en faisant entrer `query_row` dans le RECEVEUR — la mutation qui
    # fait entrer la famille voisine — le témoin ci-dessus reste VERT, parce que son `.ok()` casse la
    # chaîne directe avant l'avalement. Il tue autre chose (l'intercalation d'un `.ok()`), et il est
    # gardé pour cela ; la mutation du receveur, elle, est tuée ICI, où le `query_row` est LIÉ et son
    # nom aplati — exactement la forme que la garde accuserait si son receveur débordait.
    ("témoin négatif : un `query_row` LIÉ puis aplati — le receveur, pas l'intercalation",
     'fn n1b(conn: &Connection) -> Option<i64> {\n'
     '    let dernier = conn.query_row("SELECT MAX(ts) FROM t", [], |r| r.get::<_, Option<i64>>(0)).ok();\n'
     '    dernier.flatten()\n}\n', set()),
    ("témoin négatif : `capture_names().flatten()` (aucune lecture de lignes)",
     'fn n2(re: &Regex) -> Vec<String> {\n'
     '    let mut o = Vec::new();\n'
     '    for name in re.capture_names().flatten() { o.push(name.to_string()); }\n'
     '    o\n}\n', set()),
    ("témoin négatif : `.await.ok().flatten()` (une tâche, pas un itérateur de lignes)",
     'async fn n3(db_path: String, sql: String) -> Option<Value> {\n'
     '    tokio::task::spawn_blocking(move || eval_value(&db_path, &sql)).await.ok().flatten()\n}\n',
     set()),
    ("témoin négatif : `Option<Option<_>>` rendu par une fonction",
     'fn n4(ref_bib: &RefBibliotheque) -> Option<i64> { ref_bib.a_ecrire().flatten() }\n', set()),
    ("témoin négatif : l'aplatissement est dans un commentaire `//`",
     'fn n5(conn: &Connection) -> Vec<i64> {\n'
     '    // l\'idiome d\'avant : s.query_map([], f).flatten().collect() — remplacé par un solde en bloc\n'
     '    let mut s = conn.prepare("SELECT a FROM t").unwrap();\n'
     '    s.query_map([], |r| r.get(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()\n}\n',
     set()),
    ("témoin négatif : l'aplatissement est dans un `#[cfg(test)] mod`",
     'fn n6() -> i64 { 0 }\n'
     '#[cfg(test)]\nmod tests {\n    use super::*;\n'
     '    #[test]\n    fn t(conn: &Connection) {\n'
     '        let mut s = conn.prepare("SELECT a FROM t").unwrap();\n'
     '        let v: Vec<i64> = s.query_map([], |r| r.get(0)).unwrap().flatten().collect();\n'
     '        assert!(v.is_empty());\n    }\n}\n', set()),
    ("témoin négatif : le parcours est SOLDÉ EN BLOC — c'est la forme que la garde réclame",
     'fn n7(conn: &Connection) -> rusqlite::Result<Vec<i64>> {\n'
     '    let mut s = conn.prepare("SELECT a FROM t")?;\n'
     '    s.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<Vec<_>>>()\n}\n', set()),
    ("témoin négatif : un `map` SANS avalement dedans",
     'fn n8(conn: &Connection) -> rusqlite::Result<Vec<rusqlite::Result<i64>>> {\n'
     '    let mut s = conn.prepare("SELECT a FROM t")?;\n'
     '    Ok(s.query_map([], |r| r.get(0))?.map(|r| r.map(|x| x + 1)).collect())\n}\n', set()),
]


# --- LES ÉPREUVES DE LA SECONDE FAMILLE (`P10.20-p`) : (nom, source Rust, formes attendues).
# Les extraits sont FABRIQUÉS, jamais pris sur l'arbre — et ils ne PEUVENT pas l'être ici, puisque
# l'arbre est à zéro. Adosser un témoin à `suppressions_get` ou à `compute_freshness`, qui portaient
# ces formes le matin même, en ferait une RANÇON : il rougirait parce qu'ils sont RÉPARÉS.
EPREUVES_DES_PARCOURS_MUETS = [
    ("(1) la PRÉPARATION muette — la forme que `P10.20-p` nomme",
     'fn m1(conn: &Connection) -> Vec<i64> {\n'
     '    let mut o = Vec::new();\n'
     '    if let Ok(mut s) = conn.prepare("SELECT a FROM t") {\n'
     '        if let Ok(rows) = s.query_map([], |r| r.get(0)) {\n'
     '            for a in rows { if let Ok(v) = a { o.push(v); } }\n'
     '        } else { o.push(-1); }\n'
     '    }\n    o\n}\n', {"prepare"}),
    ("(2) le PARCOURS muet seul — la préparation, elle, propage",
     'fn m2(conn: &Connection) -> rusqlite::Result<Vec<i64>> {\n'
     '    let mut o = Vec::new();\n'
     '    let mut s = conn.prepare("SELECT a FROM t")?;\n'
     '    if let Ok(rows) = s.query_map([], |r| r.get(0)) {\n'
     '        for a in rows { o.push(a?); }\n'
     '    }\n    Ok(o)\n}\n', {"query_map"}),
    ("(3) LES DEUX ÉTAGES muets — deux sites, pas un",
     'fn m3(conn: &Connection) -> Vec<i64> {\n'
     '    let mut o = Vec::new();\n'
     '    if let Ok(mut s) = conn.prepare("SELECT a FROM t") {\n'
     '        if let Ok(rows) = s.query_map([], |r| r.get(0)) {\n'
     '            for a in rows { if let Ok(v) = a { o.push(v); } }\n'
     '        }\n    }\n    o\n}\n', {"prepare", "query_map"}),
    ("(4) témoin négatif : la MÊME forme AVEC `else` — c'est celle que la garde réclame",
     'fn n1(conn: &Connection) -> Value {\n'
     '    let mut o = Vec::new();\n'
     '    let mut fin = FinDeParcours::Complet;\n'
     '    if let Ok(mut s) = conn.prepare("SELECT a FROM t") {\n'
     '        if let Ok(rows) = s.query_map([], |r| r.get::<_, i64>(0)) {\n'
     '            for a in rows { match a { Ok(v) => o.push(v), Err(_) => fin = FinDeParcours::Partiel } }\n'
     '        } else { fin = FinDeParcours::NonCommence; }\n'
     '    } else { fin = FinDeParcours::NonCommence; }\n'
     '    json!({ "rows": o, "fin": fin.mot() })\n}\n', set()),
    ("(5) témoin négatif : le `match` qui PARLE — la lecture est scrutée, pas enjambée",
     'fn n2(conn: &Connection) -> Value {\n'
     '    let mut o: Vec<i64> = Vec::new();\n'
     '    match conn.prepare("SELECT a FROM t") {\n'
     '        Ok(mut s) => match s.query_map([], |r| r.get(0)) {\n'
     '            Ok(rows) => for a in rows { if let Ok(v) = a { o.push(v); } },\n'
     '            Err(e) => return json!({ "error": e.to_string() }),\n'
     '        },\n'
     '        Err(e) => return json!({ "error": e.to_string() }),\n'
     '    }\n    json!({ "rows": o })\n}\n', set()),
    ("(6) témoin négatif : la forme est dans un COMMENTAIRE (la prose du correctif de `P10.20-g`)",
     'fn n3(conn: &Connection) -> rusqlite::Result<Vec<i64>> {\n'
     '    // AVANT : `if let Ok(mut s) = conn.prepare(..)` SANS branche d\'échec — la famille quittait\n'
     '    // le relevé sans qu\'un seul champ ne bouge. Remplacé par un `match` qui pose NonCommence.\n'
     '    let mut s = conn.prepare("SELECT a FROM t")?;\n'
     '    s.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<Vec<_>>>()\n}\n', set()),
    ("(7) témoin négatif : la forme est dans une CHAÎNE (un gabarit de message, un extrait de doc)",
     'fn n4() -> &\'static str {\n'
     '    "corrigé : if let Ok(mut s) = conn.prepare(sql) { } ne dit pas que la lecture a raté"\n}\n',
     set()),
    ("(8) témoin négatif : la forme est dans un `#[cfg(test)] mod`",
     'fn n5() -> i64 { 0 }\n'
     '#[cfg(test)]\nmod tests {\n    use super::*;\n'
     '    #[test]\n    fn t(conn: &Connection) {\n'
     '        if let Ok(mut s) = conn.prepare("SELECT a FROM t") {\n'
     '            if let Ok(rows) = s.query_map([], |r| r.get::<_, i64>(0)) { assert!(rows.count() >= 0); }\n'
     '        }\n    }\n}\n', set()),
    ("(9) témoin négatif : `query_row` — la famille VOISINE, qui ne rend PAS un parcours",
     'fn n6(conn: &Connection) -> StatusCode {\n'
     '    if let Ok((k, t, d)) = conn.query_row("SELECT k,t,d FROM a WHERE id=?1", params![id],\n'
     '        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)? != 0))) {\n'
     '        armer(&k, &t, d);\n'
     '    }\n    StatusCode::NO_CONTENT\n}\n', set()),
    ("(10) témoin négatif : `let ... else` — l'échec a une branche, elle est juste écrite autrement",
     'fn n7(conn: &Connection) -> Vec<i64> {\n'
     '    let Ok(mut s) = conn.prepare("SELECT a FROM t") else { return Vec::new() };\n'
     '    let Ok(rows) = s.query_map([], |r| r.get(0)) else { return Vec::new() };\n'
     '    rows.collect::<rusqlite::Result<Vec<_>>>().unwrap_or_default()\n}\n', set()),
]


# LA DESCENTE S'ÉPROUVE SUR UN ARBRE FABRIQUÉ, JAMAIS SUR `handlers/connectors/`. Adosser le témoin au
# sous-répertoire réel en ferait une RANÇON : il rougirait le jour où ce répertoire est renommé, fusionné
# ou vidé, et aucun geste local ne pourrait le refermer. C'est la même règle que pour les extraits Rust.
SOURCE_FABRIQUEE = ('fn liste(conn: &Connection) -> Vec<i64> {\n'
                    '    let mut s = conn.prepare("SELECT a FROM t").unwrap();\n'
                    '    s.query_map([], |r| r.get(0)).unwrap().flatten().collect()\n}\n')
# Les chemins du faux arbre : deux profondeurs de SOURCES (qui doivent être vues) et deux ARTEFACTS
# d'outil (qui doivent être élagués DANS la descente).
ARBRE_FABRIQUE = (("a_plat.rs",),
                  ("sous_repertoire_fabrique", "mod.rs"),
                  ("sous_repertoire_fabrique", "encore_dessous", "profond.rs"),
                  ("target", "debug", "artefact_de_construction.rs"),
                  ("__pycache__", "artefact_python.rs"))
SOURCES_ATTENDUES = {"a_plat.rs", "sous_repertoire_fabrique/mod.rs",
                     "sous_repertoire_fabrique/encore_dessous/profond.rs"}


def epreuve_de_la_descente():
    """Le CORPUS descend dans les sous-répertoires, et il élague — jugé DANS LES DEUX SENS.

    Sans le sens POSITIF, la descente pourrait être débranchée sans qu'aucun témoin ne tombe, et la garde
    redeviendrait plate en silence — exactement l'état où un site de `handlers/connectors/` a vécu depuis
    le premier jour. Sans le sens NÉGATIF, un `target/` posé sous l'arbre entrerait dans le corpus et la
    garde accuserait du code qu'aucun geste local ne referme (et se rendrait illisible : un répertoire de
    construction porte des ordres de grandeur plus de fichiers que les sources dont il dérive).

    Le troisième volet est le plus important : un fichier LISTÉ mais non ANALYSÉ ne prouve rien. Le site
    du sous-répertoire doit ressortir d'`analyser`, avec son écriture."""
    errs = []
    with tempfile.TemporaryDirectory(prefix="plume-liste-tronquee-") as racine:
        for rel in ARBRE_FABRIQUE:
            chemin = os.path.join(racine, *rel)
            os.makedirs(os.path.dirname(chemin), exist_ok=True)
            with open(chemin, "w", encoding="utf-8") as fh:
                fh.write(SOURCE_FABRIQUEE)
        vus = {os.path.relpath(c, racine).replace(os.sep, "/") for c in fichiers_du_corpus(racine)}
        manquants = sorted(SOURCES_ATTENDUES - vus)
        if manquants:
            errs.append(f"épreuve de la DESCENTE (positif) : {manquants} n'est pas dans le corpus — la "
                        "découverte est redevenue PLATE, et un site écrit sous `handlers/connectors/` (ou "
                        "sous n'importe quel sous-répertoire à venir) ne serait plus jamais vu")
        artefacts = sorted(v for v in vus - SOURCES_ATTENDUES)
        if artefacts:
            errs.append(f"épreuve de la DESCENTE (élagage) : {artefacts} est entré dans le corpus — le "
                        "parcours n'élague plus les artefacts d'outil par le geste partagé "
                        "(`parcours_des_sources`), et la garde accuserait du code dérivé qu'aucun geste "
                        "local ne referme")
        sites = analyser("sous_repertoire_fabrique/mod.rs", SOURCE_FABRIQUEE, [])
        if {e for _c, _l, _f, e, _x in sites} != {"i"}:
            errs.append("épreuve de la DESCENTE (analyse) : le fichier d'un sous-répertoire est LISTÉ mais "
                        "son site n'est pas ACCUSÉ — un corpus qui s'élargit sans que le lecteur suive ne "
                        "vaut rien")
    return errs


def valider_instrument():
    """L'instrument s'éprouve AVANT de rendre un verdict, et dans les deux sens. Un instrument qui
    prétend mesurer ce qu'il n'atteint pas est pire qu'une garde absente.

    CHAQUE ÉPREUVE A ÉTÉ ÉPROUVÉE PAR MUTATION le 2026-09-16, et la phrase dit ce qui a été MESURÉ,
    pas ce qui serait joli. Onze mutations jouées contre ce lot, onze tuées : débrancher l'écriture
    (ii), débrancher la liaison, forcer `jeton_avale` à vrai, élargir le receveur à `query_row`,
    débrancher `coupe_tests`, débrancher le dépouillement des commentaires, cesser de distinguer la
    boucle, vider `TRANSPARENT`, débrancher le jugement de l'ensemble, rendre `apparier` aveugle, et
    élider les arguments de la chaîne (c'est-à-dire RECOPIER l'angle mort de la garde sœur).

    ET UN TÉMOIN A DÛ ÊTRE AJOUTÉ PARCE QUE LE LOT NE TENAIT PAS CE QU'IL ANNONÇAIT. La mutation « le
    receveur s'élargit à `query_row` » a d'abord SURVÉCU : le témoin négatif de la famille voisine
    s'écrit `query_row(..).ok().flatten()`, et son `.ok()` casse la chaîne directe AVANT l'avalement —
    il reste vert quel que soit le receveur. Il est gardé pour ce qu'il tue vraiment (l'intercalation
    d'un `.ok()`), et la mutation est désormais tuée par un témoin qui LIE le `query_row` puis aplatit
    son nom, plus deux témoins au niveau du prédicat."""
    errs = []
    # LE LECTEUR PARTAGÉ SE VALIDE AVANT DE SERVIR (`P10.20-d`, 2026-09-16). Il est IMPORTÉ, donc ses
    # témoins ne tournent pas à l'import : sans cet appel, un lecteur amputé de sa reconnaissance des
    # chaînes brutes ou des littéraux de caractère ne serait épinglé que par la garde qui le PORTE.
    # Le coût est nul et il est MESURÉ : 0,34 ms, contre 0,58 s pour cette garde entière (0,06 %).
    try:
        temoins_du_lecteur()
    except AssertionError as e:
        errs.append(f"lecteur partagé (`sans_commentaires_rust`) : {e}")
    # LES LECTEURS DE FORME RUST AUSSI (`P10.20-r`, 2026-09-16). Ils sont IMPORTÉS de la garde sœur,
    # donc leurs témoins ne tournent pas à l'import : sans cet appel, un `apparier` amputé de sa règle
    # du littéral de caractère, ou un `arguments` qui coupe sur la virgule d'un `','`, n'était épinglé
    # que par la garde qui les PORTE — et CETTE garde-ci restait VERTE À SORTIE IDENTIQUE sous la
    # mutation, mesuré. Le coût est de 0,23 ms, contre 0,97 s pour cette garde entière (0,02 %).
    try:
        temoins_des_lecteurs_de_forme()
    except AssertionError as e:
        errs.append(f"lecteurs de forme Rust (`apparier`, `fonctions`, `arguments`, "
                    f"`bras_du_match`) : {e}")
    for nom, src, attendues in EPREUVES:
        journal = []
        sites = analyser("/epreuve.rs", src, journal)
        vues = {e for _c, _l, _f, e, _x in sites}
        if journal:
            errs.append(f"épreuve « {nom} » : le lecteur avoue avoir perdu quelque chose ({journal[0]})")
        if attendues and vues != attendues:
            errs.append(f"épreuve « {nom} » : écritures vues {sorted(vues) or 'aucune'}, attendu "
                        f"{sorted(attendues)} — la garde ne voit plus la forme qu'elle nomme, ou elle la "
                        "range sous la mauvaise écriture et la phrase imprimée ment sur le site")
        if not attendues and vues:
            errs.append(f"épreuve « {nom} » : accusée sous {sorted(vues)} alors qu'elle est HORS FAMILLE "
                        "ou HONNÊTE — la garde accuse une forme qu'aucun geste local ne referme")

    # --- LE RECEVEUR, ÉPROUVÉ À SON PROPRE NIVEAU ET DANS LES DEUX SENS. Le témoin `n1b` ci-dessus
    # tue la mutation qui fait entrer `query_row` dans la population, mais il pourrait passer pour une
    # raison ÉTRANGÈRE (un `let` qui ne se lierait pas). Ces deux-ci n'interrogent que le prédicat.
    if not LECTURE_LIGNES.search("stmt.query_map([], f)") or not LECTURE_LIGNES.search("s.query_and_then([], f)"):
        errs.append("épreuve du RECEVEUR (positif, au niveau du prédicat) : `query_map` ou "
                    "`query_and_then` n'est plus reconnu comme une lecture de LIGNES — la population "
                    "de cette garde est vide, et son vert ne dit plus rien")
    if LECTURE_LIGNES.search("conn.query_row(sql, [], f)"):
        errs.append("épreuve du RECEVEUR (négatif, au niveau du prédicat) : `query_row` est entré dans "
                    "la population. C'est la famille VOISINE — une seule ligne, où le défaut est de "
                    "confondre « aucune ligne » et « pas lu » — et l'y faire entrer sans la mesurer est "
                    "la faute que la garde sœur a payée deux fois")

    # --- LES DEUX ANGLES MORTS DE LA GARDE SŒUR SONT PROUVÉS, PAS ALLÉGUÉS. Sans cette épreuve, la
    # raison d'être de ce fichier serait une affirmation d'en-tête ; le jour où la sœur apprend l'une
    # des deux formes, c'est ICI qu'on l'apprend, et la question « faut-il encore deux gardes ? » se
    # repose avec une mesure. L'épreuve est DÉFENSIVE dans un seul sens : elle rougit si la sœur se
    # met à voir, elle n'exige jamais qu'un défaut survive.
    lectures_avalees = None
    sys.argv = [_ARGV[0], RACINE]
    try:
        from check_a_read_that_did_not_happen_is_never_served_as_a_fact import lectures_avalees
    except Exception as e:  # noqa: BLE001 — l'aveu vaut mieux qu'un silence
        errs.append(f"épreuve des ANGLES MORTS : la garde sœur n'est pas importable ({e})")
    finally:
        sys.argv = _ARGV
    if lectures_avalees is not None:
        enveloppe = ('let v = conn.prepare(sql).and_then(|mut s| '
                     's.query_map(params![id], |r| r.get(0)).map(|x| x.flatten().collect()));')
        liaison = ('let Ok(rows) = s.query_map(params![n], |r| r.get::<_, String>(0)) else { return out; };\n'
                   'for src in rows.flatten() { out.push(src); }')
        # Les deux extraits sont FABRIQUÉS et ne sont plus adossés à aucun site (relu le 2026-09-16,
        # après la vague B du rang quatre) : `caseops.rs:323/363` portait la chaîne enveloppée,
        # `soql_meta.rs:218` la liaison, et les deux sont fermés. `depuis` garde la trace de ce qu'ils
        # reproduisent, sans prétendre que l'arbre le porte encore.
        for libelle, extrait, depuis in (("CHAÎNE ENVELOPPÉE", enveloppe, "caseops.rs:323/363, fermé"),
                                         ("LIAISON", liaison, "soql_meta.rs:218, fermé")):
            if lectures_avalees(extrait):
                errs.append(f"épreuve des ANGLES MORTS ({libelle}) : la garde sœur VOIT désormais cette "
                            f"forme (extrait FABRIQUÉ, reproduit d'après {depuis}). Ce n'est pas une "
                            "panne — c'est que la raison d'être de cette garde-ci a changé, et l'en-tête "
                            "doit être re-mesuré avant que le verdict reprenne.")
            if not analyser("/angle_mort.rs", "fn a(conn: &Connection) -> Vec<Value> { let mut out = "
                            "Vec::new(); " + extrait + " out }", []):
                errs.append(f"épreuve des ANGLES MORTS ({libelle}) : CETTE garde ne voit pas non plus la "
                            "forme qu'elle existe pour voir — les deux sœurs sont aveugles au même "
                            "endroit, et le verdict ne vaut rien")

    # --- LE CORPUS DESCEND, ET IL ÉLAGUE — sur un arbre FABRIQUÉ, dans les deux sens.
    errs += epreuve_de_la_descente()

    # --- L'ENSEMBLE NOMMÉ EST JUGÉ DANS LES DEUX SENS, À SON PROPRE NIVEAU. Sans ces deux épreuves,
    # un `juger_contre_l_ensemble` débranché rendrait la garde verte quoi que l'arbre porte.
    faux_site = [("daemon/src/handlers/fabrique.rs", 7, "fn_fabriquee", "i", ".flatten()")]
    genres = {g for g, _f, _p in juger_contre_l_ensemble(faux_site, {})}
    if genres != {"forme neuve"}:
        errs.append(f"épreuve de l'ENSEMBLE (forme neuve) : genres {sorted(genres) or 'aucun'} au lieu de "
                    "['forme neuve'] — une accusation hors ensemble ne rougit plus, et l'ensemble ne "
                    "peut plus que grandir en silence")
    genres = {g for g, _f, _p in juger_contre_l_ensemble(
        [], {("daemon/src/handlers/fabrique.rs", "fn_fantome"): 1})}
    if genres != {"exemption sans objet"}:
        errs.append(f"épreuve de l'ENSEMBLE (exemption sans objet) : genres {sorted(genres) or 'aucun'} au "
                    "lieu de ['exemption sans objet'] — une entrée sans objet ne rougit plus, et la liste "
                    "cesse de descendre quand le dépôt guérit")
    if juger_contre_l_ensemble(faux_site, {("daemon/src/handlers/fabrique.rs", "fn_fabriquee"): 1}):
        errs.append("épreuve de l'ENSEMBLE (accord) : un site EXACTEMENT admis produit un écart — la garde "
                    "serait rouge sur l'arbre qu'elle déclare elle-même admis")

    # ============================================================================================
    # LA SECONDE FAMILLE — LE PARCOURS QUI N'A PAS LIEU (`P10.20-p`)
    # ============================================================================================
    # ELLE N'A PAS DE PLANCHER DE POPULATION, ET ELLE NE PEUT PAS EN AVOIR : l'arbre est à ZÉRO. Sa
    # non-dégénérescence tient ENTIÈREMENT à ces épreuves. Sans elles, le jour où `PREPARATION` cesse
    # de matcher ou où `if_let_sans_branche` rend toujours `None`, le zéro resterait vert et la garde
    # serait aveugle en annonçant qu'elle ne voit rien. MUTATION JOUÉE le 2026-09-16 : vider
    # `PARCOURS_MUET` (la population par le geste) fait tomber les trois épreuves positives.
    for nom, src, attendues in EPREUVES_DES_PARCOURS_MUETS:
        journal = []
        muets = analyser_les_parcours_muets("/muet.rs", src, journal)
        vues = {f for _c, _l, _fn, f, _x in muets}
        if journal:
            errs.append(f"épreuve des PARCOURS MUETS « {nom} » : le lecteur avoue avoir perdu quelque "
                        f"chose ({journal[0]})")
        if attendues and vues != attendues:
            errs.append(f"épreuve des PARCOURS MUETS « {nom} » : formes vues {sorted(vues) or 'aucune'}, "
                        f"attendu {sorted(attendues)} — la garde ne voit plus la forme qu'elle nomme, ou "
                        "elle l'étiquette autrement et l'ensemble nommé ne peut plus la reconnaître")
        if not attendues and vues:
            errs.append(f"épreuve des PARCOURS MUETS « {nom} » : accusée sous {sorted(vues)} alors "
                        "qu'elle AVOUE, qu'elle propage, ou qu'elle n'est pas du code — la garde accuse "
                        "une forme qu'aucun geste local ne referme")
    # LE GRAIN : deux étages muets d'un même bloc font DEUX sites, sur deux lignes. L'extrait est
    # retrouvé PAR SON NOM et non par son rang dans la liste — un témoin qu'un ré-ordonnancement ferait
    # porter sur une autre source serait vert pour la mauvaise raison.
    src_deux = next(s for n, s, _a in EPREUVES_DES_PARCOURS_MUETS if n.startswith("(3)"))
    if len({(c, l) for c, l, _f, _fo, _x in analyser_les_parcours_muets("/deux.rs", src_deux, [])}) != 2:
        errs.append("épreuve des PARCOURS MUETS (grain) : les DEUX étages muets d'un même bloc ne font "
                    "pas deux sites — soit l'un est perdu, soit ils sont comptés sur la même ligne, et "
                    "l'ensemble nommé ne pourrait plus en fermer un sans fermer l'autre")
    # --- LE RECEVEUR DE LA SECONDE FAMILLE, À SON PROPRE NIVEAU ET DANS LES DEUX SENS.
    if not PREPARATION.search("conn.prepare(sql)") or not PREPARATION.search("c\n    .prepare_cached(sql)"):
        errs.append("épreuve du RECEVEUR MUET (positif) : `prepare`/`prepare_cached` n'est plus reconnu "
                    "— la seconde famille est vide, et son zéro ne dit plus rien")
    if PREPARATION.search("conn.query_row(sql, [], f)") or PREPARATION.search("s.query_map([], f)"):
        errs.append("épreuve du RECEVEUR MUET (négatif) : `query_row` ou `query_map` est entré dans la "
                    "PRÉPARATION — les deux formes de la seconde famille seraient confondues, et une "
                    "entrée de l'ensemble nommé ne dirait plus quel étage est muet")
    if "query_row" in PARCOURS_MUET:
        errs.append("épreuve du RECEVEUR MUET (famille voisine) : `query_row` est entré dans la seconde "
                    "famille. Il rend UNE ligne, pas un parcours : c'est la famille de "
                    "`check_a_single_row_read_that_failed_is_never_served_as_a_fact.py`, et le seul site "
                    "de `handlers/` qui porte cette forme (`action_approve`) relève de `P10.20-q`")
    # --- L'ENSEMBLE NOMMÉ DE LA SECONDE FAMILLE, JUGÉ DANS LES DEUX SENS ET SUR LES FORMES.
    faux_muet = [("daemon/src/handlers/fabrique.rs", 9, "fn_fabriquee", "prepare", "if let Ok(mut s)")]
    genres = {g for g, _f, _p in juger_les_parcours_muets(faux_muet, {})}
    if genres != {"forme neuve"}:
        errs.append(f"épreuve de l'ENSEMBLE MUET (forme neuve) : genres {sorted(genres) or 'aucun'} au "
                    "lieu de ['forme neuve'] — une préparation muette NEUVE ne rougit plus, et le "
                    "cliquet à zéro ne serait plus qu'un décor")
    genres = {g for g, _f, _p in juger_les_parcours_muets(
        [], {("daemon/src/handlers/fabrique.rs", "fn_fantome"): ("prepare",)})}
    if genres != {"exemption sans objet"}:
        errs.append(f"épreuve de l'ENSEMBLE MUET (exemption sans objet) : genres "
                    f"{sorted(genres) or 'aucun'} au lieu de ['exemption sans objet'] — une entrée bidon "
                    "ne rougit plus, et l'ensemble cesserait de redescendre quand le dépôt guérit")
    if juger_les_parcours_muets(faux_muet, {("daemon/src/handlers/fabrique.rs", "fn_fabriquee"): ("prepare",)}):
        errs.append("épreuve de l'ENSEMBLE MUET (accord) : un site EXACTEMENT admis produit un écart — "
                    "la garde serait rouge sur l'arbre qu'elle déclare elle-même admis")
    mute = [("daemon/src/handlers/fabrique.rs", 9, "fn_fabriquee", "query_map", "if let Ok(rows)")]
    genres = {g for g, _f, _p in juger_les_parcours_muets(
        mute, {("daemon/src/handlers/fabrique.rs", "fn_fabriquee"): ("prepare",)})}
    if genres != {"forme neuve", "exemption sans objet"}:
        errs.append(f"épreuve de l'ENSEMBLE MUET (changement de FORME) : genres "
                    f"{sorted(genres) or 'aucun'} au lieu des DEUX — une préparation muette admise qui "
                    "devient un parcours muet passerait sans un mot. C'est pour ce cas que cet ensemble "
                    "porte des FORMES et non des comptes")
    return errs


# ================================================================================================
# LE VERDICT
# ================================================================================================
def ce_qui_n_est_pas_tenu():
    print(f"\n[{ETIQUETTE}] CE QU'ELLE NE TIENT PAS :\n"
          "  * une LECTURE INTERNE sans corps servi est jugée comme les autres, et le geste qui la ferme "
          "n'est PAS le même : il faut rendre un `Result` à l'appelant, pas poser un aveu dans un corps "
          "qui n'existe pas. Elles étaient SIX au relevé du matin (`respond_run`, `load_policies`, "
          "`load_active_silences`, `load_active_engagements`, `eval_baseline`, "
          "`sla_recalcule_la_priorite_bornee`) ; les rangs un, deux et trois les ont TOUTES SIX fermées, "
          "et il n'en reste AUCUNE dans l'ensemble. La phrase est corrigée à chaque rang plutôt que gardée "
          "telle quelle : une garde qui énumère des entrées qui n'existent plus enseigne un arbre qui "
          "n'est pas celui qu'elle juge. Ce que la garde ne sait toujours pas faire n'a pas changé — elle "
          "ne distingue pas une lecture interne d'une liste servie, et le rouge qu'elle poserait sur la "
          "prochaine ne se refermerait pas par le geste qu'elle nomme.\n"
          "  * elle ne dit PAS si un aveu de région couvre la lecture accusée. Une fonction qui pose déjà "
          "`error` pour une AUTRE de ses lectures reste accusée pour celle-ci — c'est voulu (un aveu qui "
          "couvre tout ne couvre rien), mais cela veut dire que le rouge ne mesure pas la distance qui "
          "reste à parcourir.\n"
          "  * elle ne tient pas ce que la CONSOLE affiche. Le démon peut avouer une troncature ; qu'un "
          "module de `web/` lise l'aveu se juge ailleurs "
          "(`check_a_refusal_is_not_rendered_as_an_absence.py`).\n"
          "  * elle ne tient pas les `.ok()` sur `query_row` — famille VOISINE, pas la même : là-bas c'est "
          "UNE ligne, et le défaut est de confondre « aucune ligne » (fait légitime) avec « pas lu » (fait "
          "inventé). ELLE EST DÉSORMAIS MESURÉE, parce qu'un « trois occurrences » écrit ici sans mesure "
          "était faux d'un ordre de grandeur : au 2026-09-16, `daemon/src/handlers/` (SOUS-RÉPERTOIRES "
          "COMPRIS) porte CINQUANTE `.ok()` posés DIRECTEMENT sur un `query_row(`, sur VINGT fichiers et "
          "QUARANTE-SIX fonctions — commentaires dépouillés et modules de test coupés, mêmes lecteurs que "
          "cette garde. Le sous-compte « trois » ne décrivait que les `.ok().flatten()`, pas la famille. "
          "CE QUE DIX SITES LUS DONNENT (échantillon, 2026-09-16) : QUATRE servent la valeur DANS UN CORPS "
          "— `idp.rs:664` (`mfa_status` sert `enrolled:false`), `system.rs:16` (`schema_version` retombe à "
          "`1` et part dans /healthz, /metrics et /api/system/metrics), `prefs.rs:17` (`prefs_read` rend "
          "`{}`), `incidents.rs:197` (`runbook_meta_json`) ; DEUX sont INTERNES — `caseops.rs:49` "
          "(`sla_policy_for`, repli silencieux sur le SLA legacy) et `panneau_avoue.rs:524` (`cache_lire`, "
          "un simple recalcul) ; QUATRE sont FAIL-CLOSED et ne servent aucun fait inventé, seulement une "
          "cause fausse — `dashboards.rs:200` et `users_lookups.rs:101` et `connectors/mod.rs:500` (et `:574`, même forme) rendent "
          "404 « introuvable », `idp.rs:709` rend 400 « aucun enrôlement en cours ». LA DÉCISION EST PRISE, "
          "ET ELLE N'EST PAS UN ÉLARGISSEMENT DE CELLE-CI : `P10.20-b` a donné à cette famille sa PROPRE "
          "garde, `check_a_single_row_read_that_failed_is_never_served_as_a_fact.py`, le 2026-09-16 — "
          "population par un geste VOISIN mais distinct (un `query_row(` dont la chaîne ABSORBE l'échec, "
          "ce qui contient `.ok()` sans s'y réduire), ensemble nommé portant les FORMES et non des "
          "comptes, verdict et planchers séparés pour qu'un refus de conclure de l'une ne fasse pas taire "
          "l'autre. L'épreuve du RECEVEUR ci-dessus reste donc vraie et reste là : les deux populations "
          "sont DISJOINTES par construction, et aucun site n'est compté deux fois.\n"
          "  * elle lit `daemon/src/handlers/` ET SES SOUS-RÉPERTOIRES depuis le 2026-09-16 (l'ancienne "
          "borne PLATE cachait `connectors/mod.rs`, corrigé le même jour), mais elle ne lit QUE cela. Les "
          "modules hors `handlers/` qui servent des corps ne sont toujours pas mesurés — un corps servi "
          "peut naître ailleurs, et tant que la mesure n'est pas faite, le vert ne dit rien d'eux.\n"
          "  * elle DÉPOUILLE les commentaires par le lecteur partagé `sans_commentaires_rust`, qui prenait un "
          "littéral de caractère pour une durée de vie : le `'\"'` de `daemon/src/handlers/actions.rs:888` "
          "(`SHELL_META`) ouvrait une fausse chaîne et un commentaire de ce fichier (`actions.rs:1173`) passait "
          "pour du code. Défaut du lecteur, fermé par `P10.20-c` le 2026-09-16 (littéral apparié, dix témoins, "
          "neuf gardes re-mesurées avant et après à verdict identique) ; ici le compte dans le code passe de onze "
          "à dix et aucune accusation ne bouge, parce que cette occurrence n'avait pas de `query_map(` dans son "
          "expression. Les CHAÎNES BRUTES sont tenues depuis `P10.20-d` (même jour) et cette garde PASSE "
          "désormais le journal du lecteur : un aveu la fait refuser de conclure. Ce qu'il ne tient toujours "
          "pas (corps des macros, apostrophes d'attribut, code généré) est écrit en tête du lecteur.\n"
          "  * LA SECONDE FAMILLE (parcours muets, `P10.20-p`) ne voit QUE le `if let Ok(..)` SANS "
          "`else`. Un `match` dont les deux bras se taisent, un `while let Ok(..)`, un `if let` dont "
          "le `else` existe mais ne dit RIEN (`else { }`) ne sont pas vus : le premier est la famille "
          "de `check_a_read_that_did_not_happen_is_never_served_as_a_fact.py` (jambe Q), les deux "
          "autres ne sont sur AUCUN site de `handlers/` au 2026-09-16 et les accuser poserait un rouge "
          "que rien n'aurait mesuré.\n"
          "  * LA SECONDE FAMILLE ne lit QUE `daemon/src/handlers/`. Le même geste sur `daemon/src` "
          "ENTIER relève, au 2026-09-16, DIX-HUIT préparations muettes et DIX-HUIT parcours muets dans "
          "DIX fichiers (`cold_store/reader.rs`, `cold_store/seal.rs`, `field_filter.rs`, "
          "`governance.rs`, `knowledge.rs`, `parsers.rs`, `processors.rs`, `scim.rs` — de "
          "l'authentification —, `seeds.rs`, `tenants.rs`). HORS PÉRIMÈTRE, ET DIT. (`docs/ROADMAP.md` "
          "écrivait « neuf préparations muettes » sous `P10.20-p` : c'était un compte de FICHIERS, pas "
          "de sites, et il en manquait un — `governance.rs::reload_custom_roles`.)\n"
          "  * LA SECONDE FAMILLE ne dit rien du RANG. Un site neuf est accusé sans que la garde sache "
          "si la liste vide ouvre une porte, est servie, ou refuse ; c'est à la lecture de le lui "
          "donner en entrant dans `PARCOURS_MUETS_ADMIS`.\n"
          "  * elle ne suit pas la liaison à travers un APPEL. Un itérateur rendu par une fonction et "
          "aplati chez son appelant n'est relié à aucune lecture ; la portée d'un nom lié s'arrête à sa "
          "fonction, et c'est dit plutôt que sous-entendu.\n"
          "  * elle ne juge pas ce que le MAPPEUR fait. Un mappeur qui ne peut pas échouer rend "
          "l'aplatissement inoffensif ; la garde l'accuse quand même, parce qu'elle lit du texte et qu'un "
          "mappeur infaillible aujourd'hui gagne un `r.get()` demain.\n"
          "  * elle ne prouve RIEN à l'exécution. Elle constate qu'une forme est absente du dépôt, jamais "
          "qu'une réponse réelle avoue sa troncature.")


def main():
    # --- LES ÉPREUVES D'ABORD : aucune lecture du dépôt tant que l'instrument n'a pas été éprouvé.
    errs = valider_instrument()
    if errs:
        for e in errs:
            print(f"::error::{e}")
        print(f"\n[{ETIQUETTE}] l'INSTRUMENT est faux : aucun verdict n'est rendu.")
        ce_qui_n_est_pas_tenu()
        return 2

    # --- L'ANCRAGE : `query_map` doit être la méthode rusqlite que cette garde croit lire. Sans cet
    # ancrage, un dépôt qui aurait changé de bibliothèque rendrait zéro site et la garde serait verte
    # pour la pire des raisons.
    cargo = os.path.join(RACINE, "daemon", "Cargo.toml")
    manifeste = ""
    if os.path.isfile(cargo):
        with open(cargo, encoding="utf-8", errors="replace") as fh:
            manifeste = fh.read()
    hors_handlers = 0
    for dossier, sous, noms in os.walk(DEMON):
        sous[:] = [d for d in sous if d not in ("tests", "handlers")]
        for nom in noms:
            if not nom.endswith(".rs"):
                continue
            with open(os.path.join(dossier, nom), encoding="utf-8", errors="replace") as fh:
                hors_handlers += fh.read().count(".query_map(")
    if not re.search(r"^\s*rusqlite\s*=", manifeste, re.M) and hors_handlers == 0:
        print("::error::ni `rusqlite` dans daemon/Cargo.toml ni un seul `.query_map(` dans daemon/src "
              "hors handlers : `query_map` n'est plus la méthode que cette garde croit lire, et sa "
              "population n'a plus d'ancrage. Elle REFUSE DE CONCLURE.")
        ce_qui_n_est_pas_tenu()
        return 2

    sites, muets, journal, aveux_du_lecteur = decouvrir()
    # L'AVEU DU LECTEUR PASSE AVANT CELUI DE LA GARDE (`P10.20-d`) : une région avalée par le lecteur est
    # la cause AMONT, et la nommer évite d'accuser une parenthèse que le lecteur a lui-même déplacée.
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

    # --- LA SECONDE FAMILLE EST JUGÉE ICI, AVANT LE PLANCHER DE LA PREMIÈRE, ET C'EST DÉLIBÉRÉ
    # (`P10.20-p`). Le plancher ne mesure que la population de la PREMIÈRE famille ; le laisser
    # s'exécuter d'abord ferait TAIRE une préparation muette neuve au motif qu'une liste tronquée a
    # disparu, c'est-à-dire changer un verdict qui ACCUSE en un verdict qui REFUSE DE CONCLURE. Les
    # accusations de la seconde famille sont donc imprimées quoi qu'il arrive au plancher de l'autre.
    for chemin, ligne, fn, forme, extrait in sorted(muets):
        print(f"::error file={chemin},line={ligne}::`{fn}` — {FORMES_MUETTES[forme]} : si la lecture "
              f"rate, le bloc est SAUTÉ, la liste reste VIDE et elle est servie comme complète — "
              f"`{extrait}`")
    ecarts_muets = juger_les_parcours_muets(muets, PARCOURS_MUETS_ADMIS)
    for _genre, chemin, phrase in ecarts_muets:
        print(f"::error file={chemin}::{phrase}")
    print(f"[{ETIQUETTE}] PARCOURS MUETS (`P10.20-p`) : {len(muets)} site(s) découvert(s), "
          f"{len(PARCOURS_MUETS_ADMIS)} entrée(s) dans PARCOURS_MUETS_ADMIS, {len(ecarts_muets)} "
          "écart(s). Le cliquet est à ZÉRO SITE NOMMÉ : toute préparation ou tout parcours lié par un "
          "`if let Ok(..)` sans `else` sous `daemon/src/handlers/` est une forme neuve. HORS PÉRIMÈTRE "
          "ET DIT : le même geste sur `daemon/src` ENTIER relève, au 2026-09-16, 18 préparations "
          "muettes et 18 parcours muets dans DIX fichiers (`cold_store/reader.rs`, `cold_store/seal.rs`, "
          "`field_filter.rs`, `governance.rs`, `knowledge.rs`, `parsers.rs`, `processors.rs`, `scim.rs` "
          "— de l'authentification —, `seeds.rs`, `tenants.rs`), ni jugés ni classés.")

    fichiers = {c for c, _l, _f, _e, _x in sites}
    if len(sites) < PLANCHER_SITES or len(fichiers) < PLANCHER_FICHIERS:
        print(f"::error::{len(sites)} site(s) découvert(s) sur {len(fichiers)} fichier(s), planchers "
              f"{PLANCHER_SITES}/{PLANCHER_FICHIERS} (relus le 2026-09-16 après la VAGUE B du rang "
              "quatre, sur le relevé de ce moment-là : 3 sites sur 3 fichiers). La DÉCOUVERTE est "
              "cassée, pas le dépôt guéri : la garde REFUSE DE CONCLURE plutôt que de rendre vert en "
              "étant aveugle. ATTENTION, ces planchers-ci ne veulent plus dire ce qu'ils voulaient dire : "
              "la population restante est EXACTEMENT les deux arbitrages assumés et l'indécidable, qu'aucun "
              "lot de correction ne fermera. Une descente sous eux n'est donc PAS une guérison — c'est un "
              "lecteur qui s'est effondré, ou un de ces trois sites qu'on a retiré sans retirer son entrée "
              "(et l'ensemble nommé le dirait alors en « exemption sans objet »).")
        ce_qui_n_est_pas_tenu()
        return 2

    for chemin, ligne, fn, ecriture, extrait in sorted(sites):
        print(f"::error file={chemin},line={ligne}::`{fn}` aplatit un itérateur de lignes "
              f"({ECRITURES[ecriture]}) : une ligne illisible est avalée et la liste est servie comme "
              f"complète, sans un mot — `{extrait}`")

    par_ecriture = {}
    for _c, _l, _f, e, _x in sites:
        par_ecriture[e] = par_ecriture.get(e, 0) + 1
    print(f"\n[{ETIQUETTE}] POPULATION DÉCOUVERTE le jour de l'exécution : {len(sites)} site(s) sur "
          f"{len(fichiers)} fichier(s) de daemon/src/handlers — "
          + " · ".join(f"{ECRITURES[e]} {n}" for e, n in sorted(par_ecriture.items(),
                                                                key=lambda p: RANG_ECRITURE[p[0]]))
          + ". Commentaires DÉPOUILLÉS et modules de test COUPÉS : une occurrence citée en commentaire "
            "ou écrite dans un `#[cfg(test)] mod` n'est jamais un site.")

    ecarts = juger_contre_l_ensemble(sites, SITES_ADMIS)
    if ecarts or ecarts_muets:
        for _genre, chemin, phrase in ecarts:
            print(f"::error file={chemin}::{phrase}")
        print(f"::error::{len(ecarts)} écart(s) sur les LISTES TRONQUÉES et {len(ecarts_muets)} sur les "
              "PARCOURS MUETS, entre les accusations du jour et les ensembles nommés. Chaque ensemble se "
              "corrige à la main, AVEC la raison ; zéro reste atteignable pour les deux — et il est DÉJÀ "
              "atteint pour les parcours muets.")
        ce_qui_n_est_pas_tenu()
        return 1

    print(f"[{ETIQUETTE}] ADMIS, par classe : "
          + " · ".join(f"{lib} {sum(cl.values())}" for lib, cl in CLASSES) + ".")
    print(f"[{ETIQUETTE}] l'ensemble nommé est EXACTEMENT ce que l'arbre porte ({len(sites)} site(s)) — "
          "ni forme neuve, ni exemption sans objet.")
    restants = sum(DEFAUTS_CONNUS.values())
    if restants:
        print(f"[{ETIQUETTE}] CE QUE LE VERT NE DIT PAS : les {restants} accusations de "
              "la classe (3) sont des DÉFAUTS CONNUS ET NON CORRIGÉS, admis pour que cette garde puisse être "
              "câblée verte AUJOURD'HUI plutôt que d'attendre une campagne. Chacune sert une liste tronquée "
              "comme complète. CHAQUE correction doit RETIRER son entrée de SITES_ADMIS, sous peine "
              "d'« exemption sans objet » — c'est ce qui fait descendre la liste au lieu de la laisser "
              "devenir un décor.")
    else:
        print(f"[{ETIQUETTE}] CE QUE LE VERT DIT, ET CE QU'IL NE DIT PAS : les TROIS classes de DÉFAUTS "
              "CONNUS sont VIDES, et la classe INDÉCIDABLE aussi — plus aucun aplatissement de cette "
              "famille n'est admis comme un défaut ni laissé en suspens (58 accusations le matin du "
              "2026-09-16, 55 fermées en cinq lots, l'indécidable TRANCHÉ en code mort supprimé et le site "
              "que la descente dans les sous-répertoires a fait entrer corrigé le même jour ; aucune "
              "amnistiée). Ce qui reste dans l'ensemble n'est pas une dette : DEUX arbitrages ASSUMÉS, "
              "deux positions écrites que seul un changement d'arbitrage retirera. Le vert ne dit "
              "toujours rien de ce que cette garde ne sait pas voir : la liste en suit.")
    ce_qui_n_est_pas_tenu()
    return 0


if __name__ == "__main__":
    sys.exit(main())
