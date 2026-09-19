#!/usr/bin/env python3
"""Une lecture qui N'A PAS EU LIEU n'est jamais servie comme un FAIT — garde de CI (`P10.7-g`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
Le démon a TROIS voies pour lire des lignes derrière une route : la lecture gardée par chien de garde
(`read_with_watchdog`, `daemon/src/query_exec.rs`), la lecture simple (`read_with`, même module, MÊME
signature à trois arguments et MÊME chemin de défaut), et l'exécution de requête (`run_query`/
`run_query_ex`, même module). Les trois peuvent ÉCHOUER — connexion de lecture indisponible, budget de
5 s épuisé sous charge, table absente, colonne refusée par l'authorizer. Quand elles échouent, ce que la route servait
jusqu'ici avait la FORME d'un résultat : `controls: []`, `totals: {}`, `rows: []`, `total: 0`. Un
lecteur ne peut pas distinguer ce corps d'une mesure RÉELLEMENT à zéro, et sur une route de posture il
se lit « aucun contrôle en échec » — la valeur la plus rassurante, servie précisément quand rien n'a
été mesuré.

`P10.7-e` a fermé DEUX routes le 2026-08-30 et a dit lui-même ce qui le condamnerait : « son correctif
est honnête sur une route et muet ailleurs ». Cette garde-ci est la dérivation qui manquait. Elle ne
nomme aucune route : elle DÉCOUVRE la population et la juge sur une forme.

LES DEUX VOIES NE SONT PAS SYMÉTRIQUES, ET C'EST LE CŒUR DE CETTE GARDE
-----------------------------------------------------------------------
La mesure du 2026-08-30, inscrite dans le commentaire de `read_with_watchdog`, réfute l'intuition :

  * la valeur par DÉFAUT n'est rendue que sur UN chemin — `read_conn_get` n'a pas pu fournir de
    connexion. Rien dans la CONCURRENCE ne le déclenche : aucun plafond ne borne les connexions en
    cours ;
  * quand la garde de budget INTERROMPT, la closure est DÉJÀ en cours ; c'est elle qui reçoit
    `SQLITE_INTERRUPT`, et c'est SA valeur qui remonte. Le défaut n'apparaît nulle part.

Donc habiller le seul défaut rend un appelant honnête sur le chemin RARE en le laissant muet sur le
chemin que la CHARGE déclenche. C'est exactement la forme du défaut que `P10.7-e` a failli reproduire.
D'où DEUX JAMBES, et une règle qui les sépare :

  (A) LA VALEUR PAR DÉFAUT. Quand elle s'écoule vers une réponse de la MÊME fonction, elle doit porter
      un aveu, ou passer par un constructeur d'aveu DÉRIVÉ. Elle ne juge que la voie GARDÉE, et la
      raison est mesurée, écrite au point d'application : sur `read_with`, le vocabulaire d'aveu de
      cette jambe (la clé `error`) est FAUX quatre fois sur dix, parce que l'arbre y avoue en TYPÉ.
  (B) LA CLOSURE, SUR LES DEUX VOIES DE LECTURE — c'est le même code, exécuté sur la même connexion.
      Aucune lecture de lignes avalée (`.ok()`, `.unwrap_or*()`, `.flatten()`) sans qu'une BRANCHE de
      la closure construise un aveu. L'avalement est reconnu sous TROIS écritures : la CHAÎNE DIRECTE
      (`.query_map(..).flatten()`), le BRAS du `match` dont la lecture est le SCRUTATEUR
      (`match ..query_map(..) { Ok(r) => r.flatten().collect(), .. }`), et — depuis `P10.7-h` — le
      `if let Ok(<nom>) = <lecture> { .. }` SANS `else`, où le chemin d'échec n'est écrit NULLE PART.
      Les deux dernières étaient des angles morts : la deuxième jusqu'au matin du 2026-08-30, la
      troisième jusqu'au soir. La troisième est la plus grosse, et la jambe Q savait DÉJÀ refuser
      cette forme sur les voies de requête — la jambe B ne faisait que ne pas la lire.
  (Q) L'EXÉCUTION DE REQUÊTE. Le bras d'erreur ne peut pas être JETÉ : il propage, devient un statut
      d'échec, ou entre dans le corps sous un aveu.

  **(B) NE PEUT PAS ÊTRE SATISFAITE PAR (A), ET LA GARDE LE REFUSE EXPLICITEMENT.** L'aveu de la
  jambe B est cherché DANS LA RÉGION DE LA CLOSURE SEULEMENT — le deuxième argument (le défaut) est
  découpé de la recherche par construction, pas par convention. Sans ce refus, la garde ENTÉRINERAIT
  le défaut mesuré : elle laisserait un défaut habillé excuser la voie que la charge déclenche. Un
  mutant fabriqué le prouve dans les deux sens (`temoin 7`), et l'arbre réel le prouve aussi :
  `daemon/src/handlers/search.rs` porte un défaut HONNÊTE depuis `P10.7-a` et sa closure reste
  accusée par la jambe B.

CE QU'EST UN AVEU, AU SENS DE CETTE GARDE
------------------------------------------
La clé `error` — celle que posent `bad_req`/`server_err` (`daemon/src/main.rs`), le refus de portillon
(`handlers::portillon::corps_de_refus`) et le corps de lecture non faite de `P10.7-e`. C'est donc la clé
que les consommateurs testent DÉJÀ. Une expression porte un aveu si son texte pose cette clé, ou si
elle appelle une fonction dont le corps PROPRE la pose — liste DÉRIVÉE de `daemon/src`, jamais écrite
ici. Cette dérivation ramasse aussi des handlers qui posent `error` en ligne ; c'est sans effet, un
handler prend des extracteurs et ne s'écrit dans aucune expression de défaut.

LA POPULATION EST DÉCOUVERTE, JAMAIS ÉNUMÉRÉE
----------------------------------------------
Tout appel, dans `daemon/src/handlers/` (texte DÉPOUILLÉ DE SES COMMENTAIRES), à l'une des QUATRE voies —
les trois de lecture ci-dessus, plus la voie d'ÉCRITURE `with_write` entrée le 2026-08-30 (`P10.7-l`),
qui n'est pas une voie de lecture mais porte la MÊME fermeture en troisième position, donc la MÊME
région. Les jambes A et Q n'y ont rien à juger (pas de valeur par défaut — le deuxième argument est
`&au` —, pas de `Result`), et la jambe B n'y accuse que si un CORPS est servi ; c'est mesuré, pas
commode, et le détail est au cliquet B.
Une route neuve est couverte sans être nommée ici. MAIS UNE VOIE OMISE, ELLE, NE L'EST PAS : `read_with`
a manqué à cette liste jusqu'au 2026-08-30, et ses douze appels sur cinq fichiers n'étaient jugés par
AUCUNE jambe. C'est la leçon la plus chère de cette garde — une jambe étendue sur une population amputée
reste aveugle, et le site cité en PREUVE de l'angle mort (`handlers/dashboards.rs`) était précisément
celui qu'elle ne voyait pas. Une occurrence en COMMENTAIRE n'est JAMAIS comptée —
il en existe une sur l'arbre (`daemon/src/handlers/alerts.rs`, dans le commentaire de la vue « tous
statuts ») et c'est la forme sous laquelle un site « connu » cesse d'exister sans qu'un `grep` le voie.

MAIS UN SITE DÉCOUVERT PEUT AVOIR UNE RÉGION QUI NE S'OUVRE PAS, ET C'EST CE QUE `P10.7-j` A CORRIGÉ.
La fermeture n'est pas toujours un `|conn| …` : elle peut être le NOM d'une fonction, passé SANS
parenthèses (`read_with_watchdog(&db_path, BTreeMap::new(), rule_compliance_map)`, un seul site sur
l'arbre au 2026-08-30). Le relevé de noms exigeait un `(` collé au nom : la jambe B n'ouvrait donc RIEN,
alors que la jambe A accusait le même site depuis le premier jour. Ce n'était pas la population qui
manquait — c'était une écriture de Rust ordinaire que le lecteur ne suivait pas, et c'est un TROISIÈME
axe après les bras de `match` et les `if let` sans branche. Il faut le dire, parce que la leçon inverse
(« une jambe étendue sur une population amputée reste aveugle ») est vraie AUSSI dans l'autre sens : une
population complète dont les RÉGIONS ne s'ouvrent pas est tout aussi aveugle, et le compte ne le dit pas.

CE QUE `P10.7-j` A REFUSÉ DE FAIRE, ET LA MESURE QUI L'A ARRÊTÉ. Le lot devait faire entrer `req_conn!`
dans la population. Il ne l'a PAS fait, et la raison est écrite en toutes lettres dans « ce qu'elle ne
tient pas » : l'énoncé de départ était faux sur cinq comptes, les dix sites cités en PREUVE ne passent
pas par cette voie, et l'extension prototypée y multiplie UNE lecture avalée par HUIT accusations. La
forme dérivable existe (`with_write`, même signature à trois arguments), elle est mesurée, et elle n'est
pas livrée tant que ses dix accusations n'ont pas été classées une par une.

CE QUE `P10.7-l` A FAIT LE 2026-08-30 : IL A CLASSÉ LES DIX, PUIS N'EN A GARDÉ QUE CINQ. C'est le cœur
du lot, plus que l'élargissement lui-même. Les dix accusations que `with_write` apportait ne sont PAS
dix défauts : CINQ servent un corps (`legal_holds_list` sert `{"ok":true,"holds":[]}` = « aucune
conservation légale », `mode_get` sert `{"mode":"observe"}` = « les playbooks ne sont pas armés »,
`ledger_sinks_list`, `case_get_json` pour sa timeline tronquée, `setting_days` pour la rétention dite
« effective ») ; TROIS sont FAIL-CLOSED — une lecture ratée y rend `false`, le gestionnaire rend 404, et
l'absence y est donc un REFUS, ce que cette garde RÉCLAME déjà ; DEUX ne servent aucun corps (un
recompute SLA sauté, un maillon de journal d'intégrité au `prev_hash` vide), et ce sont de vrais défauts
qu'AUCUNE jambe de ce fichier ne sait formuler, faute d'un corps où poser `error`. Le tri est DÉRIVABLE,
pas énuméré : sur la voie d'écriture, la jambe B n'ouvre la région que si le gestionnaire englobant rend
une réponse PORTEUSE DE CORPS (`RETOUR_REPONSE`) — le critère de la jambe A, déjà écrit ici — et il
sépare EXACTEMENT les cinq des cinq. Un cliquet posé AVANT ce tri aurait rejoué l'accusation à tort que
ce dépôt a refusée deux fois le même jour, et il aurait posé cinq rouges qu'aucun geste ne referme.

L'INSTRUMENT SE VALIDE AVANT DE RENDRE UN VERDICT, DANS LES DEUX SENS
----------------------------------------------------------------------
DIX-NEUF mutants fabriqués, joués à chaque exécution : un corps par défaut nu DOIT accuser, le même avec un
aveu NE DOIT PAS ; une lecture de ligne avalée DOIT accuser, la même sous une branche qui avoue NE DOIT
PAS ; une exécution de requête dont la cause est jetée DOIT accuser, son branchement NE DOIT PAS ; et le
commentaire qui NOMME la fonction ne doit JAMAIS être compté. Le septième est le cœur : un défaut qui
AVOUE au-dessus d'une closure qui AVALE doit rester accusé par la jambe B.

Les mutants 8 à 11 tiennent l'avalement écrit dans un BRAS DE MATCH, et le 8 et le 10 sont une PAIRE
DISCRIMINANTE : le bras y est le MÊME texte, seul le SCRUTATEUR change, et le verdict doit s'inverser.
Les mutants 12 à 15 tiennent la forme SANS BRANCHE D'ÉCHEC, et ils portent la MÊME discrimination en
trois axes : le 13 est le 12 avec un `else` (le verdict doit s'inverser sur la seule présence de la
branche), le 14 est le 12 dont le SCRUTATEUR n'est pas une lecture, et le 15 est le 12 EN COMMENTAIRE. S'y ajoutent des témoins AU NIVEAU DE L'UNITÉ, qui n'interrogent que le
lecteur de chaînes : la forme neuve est vue, un bras qui SOLDE son parcours ne l'est pas, et un seul
avalement n'est jamais compté deux fois (`Ok(mut s) => s.query_map(..).unwrap_or_default()` appartient
à la chaîne directe, pas au bras). CHACUN A ÉTÉ ÉPROUVÉ PAR MUTATION le 2026-08-30 : débrancher la
détection des bras, forcer le contrôle du scrutateur à vrai puis à faux, retirer l'arrêt sur une
lecture — les quatre mutations rendent l'instrument ROUGE (code 2). C'est ainsi qu'un témoin FAUX a été
retiré du lot : le témoin de scrutateur écrit au niveau de `lectures_avalees` restait VERT sous la
mutation, son entrée ne contenant aucune lecture ; il est conservé pour ce qu'il tue vraiment, et le
contrôle qu'il prétendait éprouver l'est désormais à son propre niveau.

PLANCHER SUR LA POPULATION, PAS SUR LES VIOLATIONS
---------------------------------------------------
Sous un nombre minimal de SITES DÉCOUVERTS, la lecture est cassée et la garde REFUSE DE CONCLURE
(code 2), ce qui n'est pas une violation (code 1). Le compte d'accusations, lui, A LE DROIT D'ATTEINDRE
ZÉRO : un témoin qui exigerait que le défaut survive serait une RANÇON, verte tant que le travail n'est
pas fait et rouge le jour où il l'est. Les plafonds sont des CLIQUETS : ils ne montent jamais, et
descendre est une note, pas un échec.

CE FICHIER EST AUSSI LE PORTEUR DES LECTEURS DE FORME RUST (`P10.20-m`, `P10.20-r`, 2026-09-16)
-------------------------------------------------------------------------------------------------
`_saut_de_litteral_rust`, `apparier`, `arguments`, `_debut_du_corps`, `fonctions`, `bras_du_match`,
`spans_de_chaines_rust` et `dans_une_chaine_rust` sont IMPORTÉS par deux autres gardes
(`check_a_truncated_list_is_never_served_as_a_complete_one.py` directement,
`check_a_single_row_read_that_failed_is_never_served_as_a_fact.py` par ré-import). Ils tiennent tous
leur règle du littéral de caractère de `RE_CARACTERE_RUST`, importée du lecteur partagé et JAMAIS
recopiée — c'est la recopie qui a fait vivre quatre grammaires divergentes sous `.github/scripts/`
(`P10.20-c` à `-e`), et `spans_de_chaines_rust` est le cinquième exemplaire, rapatrié ici le
2026-09-16 depuis la garde de forme des lectures uniques qui en portait sa propre copie.

CE QUE `P10.20-r` A FERMÉ, ET CE QU'IL A RÉFUTÉ :
  * `arguments` et `bras_du_match` découpaient par virgule en sautant les CHAÎNES mais pas les
    LITTÉRAUX DE CARACTÈRE. Deux fautes en une : `','` coupait un argument ou un bras en deux, et
    `'"'` ouvrait une fausse chaîne qui en fondait plusieurs. MESURE : sur `daemon/src/handlers/`,
    61 appels sur 21 568 et 2 blocs de `match` sur 820 se découpent autrement selon que la règle est
    connue. RÉFUTÉ EN CHEMIN, et c'est la mesure qui compte : AU NIVEAU DE LA CONSOMMATION RÉELLE,
    l'écart est NUL — pendant une exécution complète, `arguments` est appelé 116 fois et
    `bras_du_match` 67, et aucun de ces 183 appels ne change de résultat. Le défaut n'était pas
    MORDANT, il était ARMÉ ; il est fermé parce qu'une découpe fausse est une découpe fausse, et que
    le prochain appel de voie dont un argument porte `','` n'aurait pas eu cette chance.
  * LES TÉMOINS DE CES LECTEURS SONT DÉSORMAIS APPELABLES (`temoins_des_lecteurs_de_forme`) ET JOUÉS
    PAR LES TROIS GARDES. Avant, ils vivaient dans le `valider_instrument` d'ici, et un import
    n'exécute aucun témoin : MESURÉ le 2026-09-16, sous une mutation qui retire la règle du littéral
    à `_saut_de_litteral_rust`, la garde de famille restait VERTE À SORTIE IDENTIQUE OCTET POUR
    OCTET. RÉFUTATION DE L'ÉNONCÉ DE `P10.20-r` : ce n'était vrai que d'UNE des deux consommatrices.
    La garde de forme des lectures uniques, elle, tuait déjà cette mutation-là par son
    `epreuve_du_litteral_d_octet` (code 2) — elle ne jouait pas LES témoins, mais elle n'était pas
    sans filet. Elle les joue maintenant aussi, et pour les deux autres lecteurs (`arguments`,
    `bras_du_match`) elle était, elle, entièrement aveugle.

CE QUE CES LECTEURS NE TIENNENT TOUJOURS PAS : le `;` d'une déclaration GÉNÉRIQUE (`fn f<T>(x: T);`)
n'est pas vu (aucune sur `daemon/src`, mesuré) ; les virgules de GÉNÉRIQUES (`HashMap<K, V>`) ne sont
pas suivies par `arguments` ; une chaîne brute non refermée court jusqu'à la fin du texte.

LA JAMBE B LIT DÉSORMAIS TOUTE LIAISON `if let Ok(..)` (`P10.20-s`, 2026-09-19)
-------------------------------------------------------------------------------
Il n'existe plus qu'UN motif de liaison dans ce fichier — `MOTIF_LIANT_IF_LET_TOUT_MOTIF` —, et c'est
une garantie STRUCTURELLE : le motif étroit (`Ok(<nom simple>)`) est SUPPRIMÉ, donc aucune jambe ne
peut se re-rétrécir en silence. Le tuple (`Ok((kind, target, dry))`) et le motif imbriqué
(`Ok(Some(t))`) sont vus comme le nom simple l'était.

CE QUE L'ÉLARGISSEMENT A COÛTÉ, MESURÉ AVANT DE L'APPLIQUER, sur l'arbre du 2026-09-19 : ZÉRO. Ni
site ni closure sourde de plus, jambe B à zéro accusation avant comme après, `SITES_ADMIS["B"]` VIDE
et `PLAFOND_CLOSURE_SOURDE` inchangé à zéro. Le plafond n'avait d'ailleurs RIEN à déplacer : depuis
`P10.7-y` il n'est plus un chiffre, il est DÉRIVÉ d'un ensemble nommé jugé dans les deux sens — un
site neuf y rougit comme FORME NEUVE, il ne consomme pas une marge.

ET LE SITE QUI MOTIVAIT L'ÉLARGISSEMENT N'AURAIT JAMAIS ÉTÉ VU PAR LUI. Ce fichier a écrit que le
tuple de `action_approve` (actions.rs) échappait à la jambe B faute d'un motif assez large. La cause
était AILLEURS, et elle est mesurée : sur l'arbre qui portait encore ce tuple, le motif large fait
passer la population BRUTE de la forme sous `daemon/src/handlers/` de zéro à UN site — et la jambe B,
elle, reste à zéro accusation. `action_approve` lit derrière `req_conn!`, une voie que la POPULATION
de cette garde ne nomme pas (c'est écrit depuis `P10.7-j`, et c'est toujours vrai) : sa région ne
s'ouvre pas, donc son texte n'est jamais lu, quel que soit le motif. Un motif élargi sur une
population amputée reste aveugle — la même leçon que `read_with` a coûtée, sur un quatrième axe.

CE QUE LE MOTIF LARGE NE VOIT TOUJOURS PAS, et c'est nommé pour être vu : `if let Some(x) = <lecture>`
(pas d'enveloppe `Ok`), `while let`, et `if let Ok(..) = <lecture> { .. } else { .. }` dont le `else`
NE PARLE PAS — la présence de la branche suffit à innocenter, comme la jambe Q le fait déjà sur la
même forme. Aucune de ces trois n'existe sous `daemon/src/handlers/` au 2026-09-19 (mesuré).
"""
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_every_help_trigger_has_a_section import (  # noqa: E402  (source unique de vérité)
    RE_CARACTERE_RUST, refuser_sur_aveu, sans_commentaires_rust, temoins_du_lecteur)

RACINE = (sys.argv[1] if len(sys.argv) > 1
          else subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True,
                              text=True, check=True).stdout.strip())
DEMON = os.path.join(RACINE, "daemon", "src")
HANDLERS = os.path.join(DEMON, "handlers")

ETIQUETTE = "lecture-non-faite"

# --- LES VOIES, NOMMÉES PAR LEUR SITE DE DÉFINITION ----------------------------------------------
# Elles sont définies dans `daemon/src/query_exec.rs` ; la garde EXIGE de les y trouver (témoin
# d'ancrage) avant de compter quoi que ce soit dans les handlers.
#
# `read_with` A ÉTÉ AJOUTÉ LE 2026-08-30, ET SON ABSENCE ÉTAIT UN ANGLE MORT PLUS LARGE QUE CELUI QUE
# `P10.7-g` NOMMAIT. Les deux voies de lecture ont la MÊME signature à trois arguments (chemin, valeur
# par défaut, closure) et le MÊME chemin de défaut — `read_with` rend `default` sur `Err(_)` de
# `read_conn_get`, ligne pour ligne comme sa sœur gardée. Douze appels sur cinq fichiers de
# `daemon/src/handlers/` n'étaient donc jugés par AUCUNE des trois jambes. C'est ce qui a fait rater à
# la garde le site que `P10.7-g` citait comme sa preuve (`handlers/dashboards.rs`) : la forme y était
# bien, mais sous une voie que la population ne nommait pas. Une jambe étendue sur une population
# amputée reste aveugle — l'ordre des alternatives place la plus LONGUE d'abord, sinon `read_with`
# capterait `read_with_watchdog`.
VOIE_GARDEE = "read_with_watchdog"
VOIE_SIMPLE = "read_with"
VOIES_LECTURE = (VOIE_GARDEE, VOIE_SIMPLE)
# LA VOIE D'ÉCRITURE, ENTRÉE LE 2026-08-30 (`P10.7-l`) — ET ELLE N'EST PAS UNE VOIE DE LECTURE.
# `with_write(st, au, f)` (`daemon/src/query_exec.rs:341`) prend le mutex écrivain du tenant et passe
# `&Connection` à la fermeture : MÊME signature à trois arguments, fermeture en TROISIÈME position,
# donc `corps_de_la_closure` s'y applique MOT POUR MOT. Elle n'a NI valeur par défaut (son deuxième
# argument est `&au`, pas un corps de repli) NI `Result` : les jambes A et Q n'y ont RIEN à juger, et
# un témoin fabriqué le prouve dans les deux sens (`temoins 16` et `20`). C'est `P10.7-j` qui l'avait
# DÉSIGNÉE en refusant `req_conn!` — non pour la taille de celle-ci, mais pour son GRAIN : la région
# de `req_conn!` va jusqu'à la fin du gestionnaire, si bien qu'UNE lecture avalée y comptait HUIT
# accusations contre huit gestionnaires. Ici la région est la fermeture, exactement comme pour
# `read_with*`.
VOIE_ECRITURE = "with_write"
# LA JAMBE A JUGE LES DEUX VOIES DE LECTURE (`P10.7-i`, 2026-09-08) — jamais la voie d'écriture, dont le
# deuxième argument est l'identité de l'appelant et non un défaut. Elle s'est arrêtée à la voie gardée le
# 2026-08-30 parce que son vocabulaire d'aveu (la clé `error`) accusait À TORT quatre sites de `read_with`
# qui avouent par le TYPE ; le vocabulaire lit désormais les constructeurs documentés `AVEU`, et les six
# accusations restantes de `read_with` étaient VRAIES (quatre listes et deux vues d'ensemble servies comme
# des faits quand la lecture n'avait pas eu lieu) : elles sont corrigées, et la voie est jugée.
VOIES_JUGEES_PAR_A = (VOIE_GARDEE, "read_with")
# Les voies dont le TROISIÈME argument est une région de fermeture. La jambe B les juge toutes ; les
# jambes A et Q n'en jugent qu'une (`VOIE_GARDEE`).
VOIES_FERMETURE = VOIES_LECTURE + (VOIE_ECRITURE,)
VOIES_REQUETE = ("run_query_ex", "run_query")
APPEL = re.compile(r"\b(read_with_watchdog|read_with|with_write|run_query_ex|run_query)\s*\(")

# Une fonction dont la sortie EST une réponse : ce qu'elle calcule s'écoule vers son corps servi.
RETOUR_REPONSE = re.compile(r"->\s*(?:Response\b|Json\s*<|impl\s+IntoResponse\b|\(\s*StatusCode\b)")
RETOUR_RESULTAT = re.compile(r"->\s*Result\s*<")

FN = re.compile(r"(?:pub(?:\(crate\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[(<]")
# La clé `error`, posée comme clé d'objet JSON ou par affectation.
POSE_AVEU = re.compile(r'"error"\s*(?::|\.into\(\))|\[\s*"error"\s*\]\s*=')
# Une fonction dont la sortie peut s'écrire DANS une expression (défaut, bras de match).
RETOUR_CORPS = re.compile(r"->\s*(?:Value|Json\s*<\s*Value\s*>|Response|String)\s*$")
# Une lecture de LIGNES sur une connexion.
LECTURE = re.compile(r"\.\s*(?:query_row|query_map|query|prepare|prepare_cached)\s*\(")
# Les trois formes qui font d'un refus une absence.
AVALE = re.compile(r"^(?:ok|unwrap_or|unwrap_or_default|unwrap_or_else|flatten)$")
# Un statut d'échec explicite, ou un abandon COMPTÉ (le démon publie ses abandons par tick).
STATUT_ECHEC = re.compile(r"\bStatusCode::|\+=\s*1\b|\breturn\s+Err\s*\(|\bErr\s*\(")
# Un identifiant d'échec PRÉ-CONSTRUIT (`let mut fail = CorrEval { …, ok: false }`) : rendre cette
# valeur-là EST un statut d'échec, pas une valeur rassurante.
MARQUE_ECHEC = re.compile(r"\bok\s*:\s*false\b")

# --- PLANCHERS DE NON-DÉGÉNÉRESCENCE (relevé du 2026-08-30, APRÈS l'entrée de `with_write`) ------
# Arbre du jour : 75 sites (33 lectures + 19 écritures + 23 requêtes) sur 26 fichiers de
# `daemon/src/handlers/` — c'était 56 sur 23 tant que `with_write` n'était pas de la famille, et 44
# sur 20 avant `read_with`. Les planchers gardent la proportion que l'auteur avait choisie
# (68 % des sites : 0,68 × 75 = 51 ; ~60 % des fichiers : 0,60 × 26 = 15,6, arrondi VERS LE BAS à 15
# — un plancher trop haut refuserait de conclure sur un arbre sain, ce qui est le défaut inverse) :
# ils constatent une LECTURE cassée, ils ne réclament pas un volume de code.
# SOUS ces planchers, c'est la LECTURE qui est cassée, pas le démon qui aurait cessé d'appeler : la
# garde refuse de conclure (code 2) au lieu de rendre vert en étant aveugle.
PLANCHER_SITES = 51
PLANCHER_FICHIERS = 15

# --- CLIQUETS (relevé du 2026-08-30) — ILS NE MONTENT JAMAIS -------------------------------------
# Chacun vaut le compte d'accusations DU JOUR. Descendre est une NOTE imprimée, pas un échec ; le
# compte a le droit d'atteindre zéro (c'est ce qui évite la rançon).
# jambe A : 16 le 2026-08-30. Depuis le 2026-09-10 (`P10.7-y`) le compte est DÉRIVÉ de l'ensemble nommé
# `SITES_ADMIS["A"]` (plus bas) : ce n'est plus un chiffre qui borne, c'est une liste de sites qui juge.
#
# ┌─ LA HAUSSE DE 12 À 17 N'EST PAS UNE RÉGRESSION : C'EST UN ÉLARGISSEMENT DU REGARD. ────────────┐
# │ AUCUNE ligne de `daemon/` n'a empiré entre les deux relevés du 2026-08-30 ; c'est la garde qui  │
# │ s'est mise à voir. Les CINQ accusations neuves existaient déjà hier, muettes, et les seize      │
# │ anciennes sont TOUTES encore là — vérifié par différence des deux journaux, dans les deux sens :│
# │ zéro accusation disparue. Un verdict qui cesse d'accuser serait une perte même si le total      │
# │ montait ; il n'y en a pas.                                                                     │
# └────────────────────────────────────────────────────────────────────────────────────────────────┘
# D'OÙ VIENNENT LES CINQ, une par une, relues sur l'arbre le 2026-08-30 (aucune n'est fausse) :
#   · UNE de la détection ÉTENDUE aux bras de `match` (`P10.7-g`) — `handlers/dashboards.rs`,
#     `match stmt.query_map(..) { Ok(r) => r.flatten().collect(), .. }`. C'était l'angle mort nommé :
#     la chaîne directe était accusée, ce bras-là ne l'était pas. Mesuré dans les DEUX sens en
#     soumettant les deux formes à la machinerie de cette garde ;
#   · QUATRE de l'entrée de `read_with` dans la population — `dash_ergonomics.rs` ×3 (`.map(|rows|
#     rows.flatten()..)`, une liste TRONQUÉE servie comme complète) et `overview.rs` (CINQ `query_row
#     (..).unwrap_or(0)` servis en `{"open_alerts": 0, "events": 0, ..}`, le corps le plus rassurant
#     du démon rendu précisément quand rien n'a été lu).
#
# POURQUOI LE CLIQUET DE HIER ÉTAIT UN CHIFFRE, PAS UNE POPULATION. Il était descendu de 13 à 12 pour
# QUATRE closures fermées, et l'écart accusait la garde : elle ne comptait que ce qu'elle savait voir.
# Deux causes ont été mesurées depuis, et non une seule : le bras de `match` (nommé par `P10.7-g`) ET
# une voie entière hors population (`read_with`, 12 appels sur 5 fichiers), qui est la raison pour
# laquelle le site cité en preuve de `P10.7-g` — `handlers/dashboards.rs` — n'apparaissait nulle part :
# la forme y était, sous une voie que la garde ne nommait pas. Une jambe étendue sur une population
# amputée reste aveugle, et c'est la leçon que ce cliquet porte désormais.
# jambe B : 27 le 2026-09-08 (28 -> 27 : un aveu TYPÉ reconnu). Depuis le 2026-09-10 (`P10.7-y`) le compte est
# DÉRIVÉ de `SITES_ADMIS["B"]`. L'ARBRE ÉTAIT À 25 DEPUIS LE LOT `d7bb103` (`P11.22-g`, 2026-09-10 13:57Z) ET LE
# CLIQUET NE POUVAIT QUE LE NOTER : bisecté sur neuf commits du jour, les deux closures disparues sont
# `caseops.rs` `case_links_get` et `case_queues`, dont le corps rend désormais `Lignes::Illisible` +
# `TotalBorne::sans_lecture()` sur `Err(_)` — un aveu RÉEL, pas un canal rétréci (vérifié sur le diff).
#
# ┌─ LA HAUSSE DE 17 À 22 N'EST PAS UNE RÉGRESSION : C'EST UN ÉLARGISSEMENT DU REGARD. ────────────┐
# │ AUCUNE ligne de `daemon/` n'a changé entre les deux relevés du 2026-08-30 — l'arbre est celui   │
# │ de `ac7ffac`, mot pour mot. C'est la garde qui s'est mise à lire une TROISIÈME écriture de      │
# │ l'avalement. Les CINQ accusations neuves existaient déjà avant, muettes, et les DIX-SEPT        │
# │ anciennes sont TOUTES encore là — vérifié par différence des deux journaux, dans les deux sens, │
# │ SITE PAR SITE : zéro site accusé perdu. Un verdict qui cesse d'accuser serait une perte même si │
# │ le total montait ; il n'y en a pas.                                                             │
# └────────────────────────────────────────────────────────────────────────────────────────────────┘
# LES CINQ, UNE PAR UNE, RELUES SUR L'ARBRE LE 2026-08-30 — les cinq servent un CORPS, aucune n'est
# un calcul interne dont l'absence serait un fait légitime, et c'est la mesure qui a AUTORISÉ
# l'extension (sans elle, l'élargir aurait rejoué l'accusation à tort que `P10.7-g` avait refusée) :
#   · `fleet.rs:253` et `fleet.rs:276` -> `fleet_scan_all` : `host_rollup` illisible laisse `hosts`
#     VIDE et `fleet_response` sert `{"hosts": []}` = « la flotte est vide ». LA PLUS GRAVE des cinq :
#     la closure rend `true` en troisième position quoi qu'il arrive, donc la flotte vide est MISE EN
#     CACHE (`fleet_map().lock().insert`) et resservie pendant tout le TTL ;
#   · `overview.rs:68` -> `environments` : `event_rollup` illisible laisse `envs` vide, et le repli
#     « prod toujours présent » sert alors `[{env:"prod", n:0}]` — un corps qui a l'air NORMAL ;
#   · `caseops.rs:613` -> `case_links_json` : `{"links": []}` = « ce case n'a aucun lien » ;
#   · `sources.rs:357` -> déjà accusé (par `pipeline_is_fresh`), et la closure elle-même porte
#     désormais deux `if let` sans branche sur l'inventaire des sources ;
#   · `soql_meta.rs:180` -> `soql_known_sources` : vocabulaire de complétion servi par
#     `/api/soql/schema`. La MOINS grave des cinq — un lecteur n'y lit pas une posture — mais le
#     résultat est MIS EN CACHE 120 s, donc une lecture ratée se resert.
#
# CE QUE LA MESURE A ÉCARTÉ, ET POURQUOI CE N'EST PAS UN OUBLI. La forme sans branche est employée
# 43 fois sur 15 fichiers de `daemon/src/handlers/` (relevé du 2026-08-30 ; l'allégation portée par la
# version précédente de ce fichier disait 42 sur 14 — elle était FAUSSE d'un site et d'un fichier).
# Sur ces 43 : 19 tombent dans une région que la jambe B juge (7 dans une closure, 12 dans le corps
# d'une fonction appelée à un niveau), et 24 sont HORS de toute région jugée — elles vivent derrière
# `req_conn!` (`daemon/src/state.rs`), une QUATRIÈME voie de lecture que la population de cette garde
# ne nomme pas (181 emplois sur 32 fichiers de handlers). Les élargir demande d'élargir la POPULATION,
# pas la jambe ; c'est la leçon que `read_with` a coûtée le matin même, et elle n'est pas rejouée ici.
# Des 19 jugeables, 5 sites d'appel gagnent une accusation ; les 14 autres tombent dans une closure
# DÉJÀ accusée (le compte est par SITE D'APPEL, pas par lecture) ou dans une région qui AVOUE —
# `freshness.rs:579` porte trois `if let` sans branche et reste INNOCENTÉ parce que sa closure pose
# `corps["error"]` via `releve.aveu()`. C'est voulu : la garde ne juge pas si l'aveu couvre CETTE
# lecture-là, et c'est écrit dans « ce qu'elle ne tient pas ».
#
# PLAN DE DESCENTE — le geste qui ferme chacune des cinq, dans l'ordre de gravité :
#   1. `fleet_scan_all` : rendre au troisième champ la valeur « le parcours a-t-il abouti » au lieu de
#      `true` constant, et ne cacher que si elle est vraie ; le corps porte alors la coupe. -> 21.
#   2. `overview::environments` : distinguer le repli « prod » du repli « rien n'a été lu » (le second
#      pose `error`). -> 20.
#   3. `case_links_json` : rendre `Result` ou poser la coupe dans le corps de `case_links_get`. -> 19.
#   4. `sources_inventory` : la closure porte déjà un `ok: false` dans son défaut ; poser la même clé
#      quand l'inventaire est TRONQUÉ. -> 18.
#   5. `soql_known_sources` : ne pas MET­TRE EN CACHE une liste issue d'une lecture ratée. -> 17.
# Chacun est un geste LOCAL, jouable aujourd'hui, et aucun ne demande de toucher à cette garde.
#
# ┌─ LA HAUSSE DE 22 À 23 N'EST PAS UNE RÉGRESSION : C'EST UN ÉLARGISSEMENT DU REGARD. ────────────┐
# │ AUCUNE ligne de `daemon/` n'a changé (`P10.7-j`, 2026-08-30) : la garde s'est mise à OUVRIR une │
# │ région qu'elle refermait, celle d'une fermeture écrite en CHEMIN DE FONCTION NU. Les VINGT-DEUX │
# │ accusations anciennes sont TOUTES encore là — vérifié par différence des deux journaux, dans    │
# │ les DEUX sens, ligne par ligne : zéro accusation disparue, et aucune CAUSE IMPRIMÉE perdue (les │
# │ phrases des vingt-deux sont identiques mot pour mot). L'unique accusation neuve est nommée      │
# │ ci-dessous.                                                                                     │
# └────────────────────────────────────────────────────────────────────────────────────────────────┘
# D'OÙ VIENT LA SEULE, relue sur l'arbre le 2026-08-30 : `compliance.rs:341` -> `rule_compliance_map`.
# La closure y est passée SANS parenthèses (`read_with_watchdog(&db_path, BTreeMap::new(),
# rule_compliance_map)`) ; le relevé de noms de `corps_de_la_closure` exigeait un `(` collé au nom et ne
# voyait donc rien. Le corps avale DEUX lectures sans branche (`compliance.rs:193` `conn.prepare(..)` et
# `:196` `stmt.query_map(..)`) : une lecture ratée rend une map VIDE, et la posture sert alors « aucune
# règle activée ne couvre aucun contrôle d'aucun cadre » — un corps de conformité au plus rassurant
# possible, servi précisément quand rien n'a été lu. Le site était DÉJÀ dans la population et DÉJÀ accusé
# par la jambe A (son défaut `BTreeMap::new()` n'avoue pas) : la jambe B ne faisait que ne pas lire la
# région. C'est la MÊME leçon que les bras de `match` et les `if let` sans branche, sur un troisième axe :
# ce n'est pas la population qui manquait, c'est une écriture de Rust ordinaire que le lecteur ne suivait
# pas. Et c'est aussi la réfutation de ce que ce fichier affirmait hier — il attribuait ces deux
# lectures-là à `req_conn!` ; elles n'ont jamais été derrière `req_conn!`.
#
# PLAN DE DESCENTE — le geste qui ferme la vingt-troisième :
#   6. `rule_compliance_map` : distinguer « aucune règle mappée » de « la table `rule` n'a pas été lue ».
#      Le plus court est de lui faire rendre un `Option`/`Result` et de poser la coupe dans le corps de
#      `compliance_posture`, qui construit DÉJÀ une réponse et sait déjà y écrire une cause. -> 22.
# Il reste LOCAL, jouable aujourd'hui, et il ne demande pas de toucher à cette garde.
#
# ┌─ LA HAUSSE DE 23 À 28 N'EST PAS UNE RÉGRESSION : C'EST UN ÉLARGISSEMENT DU REGARD. ────────────┐
# │ AUCUNE ligne de `daemon/` n'a changé (`P10.7-l`, 2026-08-30 ; mesures prises sur un point FIXE,│
# │ `git worktree --detach HEAD` = e7c16e7, parce qu'un autre lot écrivait dans `threat_intel.rs`, │
# │ `admin_ui.rs` et `ai.rs` pendant ce relevé). C'est la garde qui s'est mise à juger la RÉGION    │
# │ d'une QUATRIÈME voie, celle de l'ÉCRITURE (`with_write`). Les VINGT-TROIS accusations anciennes │
# │ sont TOUTES encore là — vérifié par différence des deux journaux, dans les DEUX sens, sur la    │
# │ ligne ENTIÈRE (site ET cause) : zéro accusation disparue, zéro cause imprimée perdue, et les    │
# │ jambes A (16) et Q (3) sont inchangées au site près. Les CINQ neuves sont nommées ci-dessous.   │
# └────────────────────────────────────────────────────────────────────────────────────────────────┘
# CE QUE LE COMPTE NE DISAIT PAS, ET C'EST LE CŒUR DE CE LOT. `P10.7-j` avait mesuré `with_write` —
# 19 sites sur 6 fichiers, 10 accusés par la jambe B — et REFUSÉ de la livrer tant que ces dix
# n'étaient pas CLASSÉES une par une, parce qu'un compte ne dit pas lesquelles sont des défauts et
# que poser un cliquet avant le tri rejouerait l'accusation à tort refusée deux fois le même jour.
# Les dix ont été relues sur l'arbre le 2026-08-30. ELLES NE SONT PAS TOUTES DES DÉFAUTS : CINQ
# servent un CORPS, TROIS sont FAIL-CLOSED (l'absence y est un REFUS, exactement ce que la garde
# réclame) et DEUX ne servent aucun corps du tout. La garde n'en accuse donc que CINQ, et le tri est
# DÉRIVABLE, pas énuméré : sur la voie d'écriture, la jambe B ne juge la région que si la fonction
# englobante rend une RÉPONSE PORTEUSE DE CORPS (`RETOUR_REPONSE` — `Response`, `Json<…>`,
# `impl IntoResponse`), jamais un `-> StatusCode` nu. Le critère existait DÉJÀ dans ce fichier (c'est
# celui de la jambe A) et il sépare EXACTEMENT les cinq des cinq — vérifié site par site.
#
# ET UNE PRÉCISION SUR UN COMPTE ÉCRIT HIER. `P10.7-j` annonçait « ZÉRO chevauchement avec une région
# déjà jugée » : c'est vrai de ce qui compte — aucun site `with_write` ne vit à l'intérieur d'une
# fermeture `read_with*` (vérifié sur les indices de texte), et AUCUNE région FAUTIVE n'est partagée,
# donc aucune accusation n'est comptée deux fois. Mais c'est faux au pied de la lettre : TROIS noms de
# région sont ouverts des DEUX côtés (`get`, `is_empty`, `now` — des auxiliaires résolus par nom, qui
# n'avalent aucune lecture et n'accusent donc rien). Le compte juste est : zéro chevauchement FAUTIF,
# trois régions innocentes communes (mesuré le 2026-08-30 sur e7c16e7).
#
# LES CINQ ACCUSÉES — elles servent un CORPS, et le corps est rassurant :
#   · `governance.rs:30` -> `legal_holds_list` : `{"ok": true, "holds": []}` = « aucune conservation
#     légale en cours ». LA PLUS GRAVE des cinq : c'est le corps sur lequel un admin décide qu'une
#     purge est permise, et il affirme `ok: true` à côté ;
#   · `engagement.rs:852` -> `mode_get` : `unwrap_or_else(|_| "observe")` sert `{"mode": "observe"}`
#     — la console lit « les playbooks ne sont PAS armés » alors que le mode stocké peut être
#     `active` (exécution réelle ban/kill/stop). La valeur de repli est la plus rassurante des deux ;
#   · `governance.rs:186` -> `ledger_sinks_list` : `{"ok": true, "sinks": []}` = « aucun export du
#     journal d'intégrité n'est configuré » ;
#   · `cases.rs:489` -> `case_get_json` : le site est accusé pour SA lecture de TIMELINE
#     (`query_map(..).ok()?.flatten()`), qui sert une timeline TRONQUÉE sous un 200. ATTENTION à la
#     phrase imprimée : elle compte TROIS lectures, mais les deux autres (`query_row(..).ok()?` et
#     `prepare(..).ok()?`) rendent `None`, donc un 404 — elles sont FAIL-CLOSED. Le compte de
#     lectures d'une phrase n'est pas un compte de défauts, et c'est vrai partout dans ce journal ;
#   · `admin_ui.rs:20` -> `setting_days` : les valeurs de rétention servies comme « EFFECTIVES
#     courantes » retombent sur l'env/la conf quand la table `setting` n'a pas été lue. LA MOINS
#     GRAVE — le repli est le résolveur DOCUMENTÉ — mais `.ok()` confond « aucune ligne » (fait
#     légitime) et « pas lu » (fait inventé), et c'est cette confusion-là que la garde nomme.
#
# LES TROIS ACQUITTÉES PARCE QUE FAIL-CLOSED — l'absence y est un REFUS, pas une valeur rassurante :
#   · `caseops.rs:598` -> `case_merge` : les deux `query_row(..).ok()` alimentent
#     `let (Some(..), Some(..)) = .. else { return false }`, et `case_merge_handler` rend alors
#     `StatusCode::NOT_FOUND`. Une lecture ratée REFUSE la fusion ; elle n'en invente pas une ;
#   · `caseops.rs:605` -> `case_unmerge` : même forme, même 404 ;
#   · `cases.rs:522` -> `case_apply_update` : même forme, même 404 (le patch n'est pas appliqué).
#   Les accuser reviendrait à réclamer un aveu là où le refus EST déjà écrit — et sur une route qui
#   rend un `StatusCode` nu, il n'existe aucun corps où poser la clé `error` : le rouge serait
#   INFERMABLE. C'est le rouge que ce dépôt refuse de poser.
#
# LES DEUX ACQUITTÉES PARCE QU'AUCUN CORPS N'EST SERVI — et ce sont de VRAIS défauts, nommés ici et
# NON corrigés par ce lot, comme `ioc_cache_reload` (`threat_intel.rs`) avant elles :
#   · `caseops.rs:674` -> `sla_policy_upsert` : trois régions fautives. La liste d'ids à recalculer
#     (`prepare(..).and_then(..).unwrap_or_default()`) rend un vecteur VIDE quand la lecture échoue :
#     le recompute SLA est silencieusement sauté et la route rend 204 « fait ». `sla_apply_policy`
#     rend `()` sur une lecture ratée (échéance non reposée). `ledger_append` lit le hash précédent
#     en `unwrap_or_default()` : une lecture ratée écrit un maillon dont le `prev_hash` est VIDE,
#     donc une CHAÎNE D'INTÉGRITÉ rompue sans que rien ne le dise ;
#   · `caseops.rs:698` -> `sla_policy_delete` : le même `ledger_append`.
#   Aucune de ces trois régions n'a de corps servi où poser `error` ; le geste est ailleurs (rendre
#   un `Result`, ou ne pas écrire un maillon dont le précédent n'a pas été lu). La jambe B ne sait
#   pas le formuler, et un cliquet qui les compterait serait un rouge qu'aucun aveu ne referme.
#
# PLAN DE DESCENTE — un geste LOCAL par accusation, jouable aujourd'hui, aucun ne touche cette garde,
# et les cinq closures construisent DÉJÀ un objet JSON : la coupe s'y écrit sans changer de type.
#   7. `legal_holds_list` : sur `Err(_)` de `prepare` / `unwrap_or_default` du parcours, poser
#      `"error": "liste des conservations NON LUE"` (et retirer `ok: true`). -> 27.
#   8. `mode_get` : distinguer `Err(QueryReturnedNoRows)` (aucun mode posé -> `observe` est un FAIT)
#      de `Err(_)` (poser `error`, ne pas affirmer `observe`). -> 26.
#   9. `ledger_sinks_list` : même geste que 7 sur `sinks`. -> 25.
#  10. `case_get_json` : solder le parcours de la timeline (`collect::<Result<Vec<_>>>()`) ou poser
#      `"error": "timeline possiblement TRONQUÉE"` dans le `json!` qu'il construit déjà. -> 24.
#  11. `setting_days` : distinguer `QueryReturnedNoRows` (le résolveur descend d'un cran : c'est un
#      fait) d'une vraie erreur de lecture, et laisser `retention_settings_get` poser la coupe dans
#      l'objet qu'il construit. -> 23.
# jambe Q : 3 le 2026-08-30. Depuis le 2026-09-10 (`P10.7-y`) le compte est DÉRIVÉ de `SITES_ADMIS["Q"]`.

# --- ENSEMBLES NOMMÉS (`P10.7-y`, 2026-09-10) — LES TROIS CLIQUETS DE COMPTE SONT DEVENUS TROIS LISTES DE SITES
# JUGÉES DANS LES DEUX SENS. Un cliquet de compte a deux angles morts, tous deux MESURÉS sur cette garde :
#   · une accusation FERMÉE et une accusation OUVERTE le même jour laissent le compte immobile — le cliquet
#     rend vert, et le site neuf entre sans être nommé ;
#   · une descente réelle (27 -> 25 le 2026-09-10, par `d7bb103`) n'est qu'une NOTE imprimée : personne
#     n'est obligé de la lire, et le cliquet est resté à 27 pendant neuf commits.
# Chaque entrée est un site d'appel accusé — (fichier, fonction) -> nombre d'accusations — relevé le
# 2026-09-10 sur l'arbre de `0db5f10` en jouant cette garde. Le jugement est SYMÉTRIQUE :
#   · une accusation hors de l'ensemble (ou un site qui en gagne une de plus) est une FORME NEUVE :
#     rouge — la forme doit avouer, ou entrer ici AVEC sa raison ;
#   · une entrée sans accusation est une EXEMPTION SANS OBJET : rouge — le site avoue désormais, ou n'existe
#     plus, ou la garde a cessé de le voir ; dans les trois cas l'ensemble doit le DIRE, et le troisième cas
#     est exactement celui qu'un cliquet de compte laissait passer en vert.
# Renommer une fonction accusée fait donc rougir DEUX fois (forme neuve + exemption sans objet) : c'est voulu,
# la liste se corrige à la main avec la raison du renommage. ZÉRO reste atteignable jambe par jambe : une
# jambe dont l'ensemble est vide ne réclame rien — aucune rançon.
SITES_ADMIS = {
    "A": {  # défaut NU servi : 3 accusations sur 2 sites (15 le 2026-09-10 ; douze défauts portent leur cause dans leur littéral depuis le lot 92)
        # `fleet` ×2 : le défaut gardé est `FlotteLue::non_lue()` (lot 100 ; un triplet typé depuis le lot 91) et l'aveu `error`
        # est posé dans le corps du gestionnaire quand la flotte n'est pas lue ; cet instrument juge le littéral du défaut, qui ne peut pas
        # porter la clé. Exemption gardée avec sa raison ; corps_rassurants_avouent.rs tient la propriété.
        ("daemon/src/handlers/fleet.rs", "fleet"): 2,
        # `compliance_posture` : le défaut des règles mappées est TYPÉ (`Err(())` au lot 92, `Err(String)` portant la cause
        # depuis le lot 99, où la lecture ratée rejoint aussi la cause) et il atteint `error` par
        # `corps_de_lecture_non_faite` ; cet instrument juge le littéral du défaut, qui ne peut pas porter la clé. Exemption
        # gardée avec sa raison ; defauts_gardes_avouent.rs tient la propriété.
        ("daemon/src/handlers/compliance.rs", "compliance_posture"): 1,
    },
    "B": {  # closure SOURDE : AUCUNE depuis le lot 101 (`P10.7-g`) — les deux derniers silences voulus (résolveur de rétention,
        # couverture froide de la recherche) sont typés et disent leur lecture ratée. Un site neuf rougit ici (FORME NEUVE).
        # `P10.20-s` (2026-09-19) A ÉLARGI LE MOTIF DE LIAISON DE CETTE JAMBE SANS Y AJOUTER UNE SEULE ENTRÉE, et c'est la
        # mesure qui l'autorise : sur l'arbre du jour, le motif large (tuple et motif imbriqué compris) accuse EXACTEMENT
        # autant que l'étroit — zéro. Aucun reste n'a donc eu à être admis, cet ensemble reste VIDE, et
        # `PLAFOND_CLOSURE_SOURDE` reste à zéro. Un plafond DÉRIVÉ d'un ensemble nommé n'a d'ailleurs aucune marge à
        # consommer : un site neuf y rougit, il n'y entre pas en silence.
    },
    "Q": {  # cause JETÉE : AUCUNE depuis le lot 102 (`P10.7-g`) — le compte total porte `total_error` à côté de `-1`, et
        # l'union des clés de labels dit qu'elle n'est pas établie quand l'échantillon ne se lit pas. Un site neuf rougit ici.
    },
}
PLAFOND_DEFAUT_NU = sum(SITES_ADMIS["A"].values())
PLAFOND_CLOSURE_SOURDE = sum(SITES_ADMIS["B"].values())
PLAFOND_CAUSE_JETEE = sum(SITES_ADMIS["Q"].values())


def _saut_de_litteral_rust(code, j):
    """Index APRÈS le littéral qui commence en `j` — une CHAÎNE `"…"` (échappements compris) ou un
    littéral de CARACTÈRE ou d'OCTET (`'x'`, `'\\n'`, `'\\u{1}'`, `b'"'`) —, ou None si `code[j]`
    n'ouvre aucun littéral. L'apostrophe qui n'en ouvre pas un est une DURÉE DE VIE (`'a`, `'static`,
    `'outer:`) : elle ne fait sauter personne. La règle du littéral de caractère est `RE_CARACTERE_RUST`,
    IMPORTÉE du lecteur partagé et non recopiée — c'est la recopie qui a fait vivre quatre grammaires
    divergentes sous `.github/scripts/` (`P10.20-c` à `-e`).

    POURQUOI UN SCANNER DOIT ENCORE CONNAÎTRE LES LITTÉRAUX APRÈS LE LECTEUR PARTAGÉ (`P10.20-m`, mesuré
    le 2026-09-16) : `sans_commentaires_rust` RESTITUE les littéraux tels quels, c'est son contrat. Le
    `"` de `'"'` est donc toujours là quand ce fichier relit sa sortie, et le prendre pour une ouverture
    de chaîne fait avaler le texte jusqu'au guillemet suivant. MESURE DU DÉFAUT, sur `daemon/src` : 38
    fonctions rendues INVISIBLES (`apparier` rendait -1, donc `fonctions` les laissait tomber) dans 25
    fichiers — `handlers/actions.rs` (`render_arg`, `render_vetted`), `handlers/freshness.rs`
    (`extract_query_sources`), `handlers/panneau_avoue.rs` (`sql_sans_litteraux`), `handlers/query.rs`
    (`csv_cell`), `main.rs` (`load_config`) — et 6 autres dont le corps s'arrêtait au mauvais endroit.
    Une fonction invisible ne rougit jamais : la garde ne l'accuse pas, elle ne la LIT pas."""
    if code[j] == '"':
        k, n = j + 1, len(code)
        while k < n and code[k] != '"':
            k += 2 if code[k] == "\\" else 1
        return k + 1
    if code[j] == "'":
        m = RE_CARACTERE_RUST.match(code, j)
        return m.end() if m else None
    return None


CHAINE_BRUTE_RUST = re.compile(r"(?:b?r)(#*)\"")


def spans_de_chaines_rust(code):
    """Les intervalles `[début, fin)` des littéraux de CHAÎNE, brutes comprises (`r"…"`, `r#"…"#`,
    `b"…"`). Les littéraux de CARACTÈRE et d'OCTET (`'"'`, `b'"'`, `'\\''`) sont SAUTÉS et non rendus :
    le guillemet qu'ils portent n'ouvre pas une chaîne, et une forme écrite juste après eux n'est pas
    « dans une chaîne ».

    POURQUOI ICI ET PAS DANS CHAQUE GARDE (`P10.20-r`, 2026-09-16) : ce lecteur existait en DOUBLE —
    `spans_de_chaines` de `check_a_single_row_read_that_failed_is_never_served_as_a_fact.py` en était
    une copie, avec sa propre grammaire du littéral de caractère. Deux grammaires jumelles finissent
    par diverger, et c'est la recopie qui a fait vivre quatre grammaires divergentes sous
    `.github/scripts/` (`P10.20-c` à `-e`). La règle du littéral est `RE_CARACTERE_RUST`, importée du
    lecteur partagé, ici comme dans `_saut_de_litteral_rust`.

    CE QU'IL NE TIENT PAS, ET C'EST DIT : une chaîne brute NON REFERMÉE court jusqu'à la fin du texte
    (`k = n`), et le `#` de clôture n'est pas apparié autrement que par une recherche littérale."""
    spans, j, n = [], 0, len(code)
    while j < n:
        if code[j] == "'":
            c = RE_CARACTERE_RUST.match(code, j)
            if c:
                j = c.end()
                continue
        m = CHAINE_BRUTE_RUST.match(code, j)
        if m:
            cloture = '"' + m.group(1)
            k = code.find(cloture, m.end())
            k = n if k < 0 else k + len(cloture)
            spans.append((j, k))
            j = k
            continue
        if code[j] == '"':
            k = j + 1
            while k < n and code[k] != '"':
                k += 2 if code[k] == "\\" else 1
            spans.append((j, min(k + 1, n)))
            j = min(k + 1, n)
            continue
        j += 1
    return spans


def dans_une_chaine_rust(spans, i):
    """`i` tombe-t-il dans l'un des intervalles rendus par `spans_de_chaines_rust` ? (dichotomie)"""
    bas, haut = 0, len(spans)
    while bas < haut:
        mil = (bas + haut) // 2
        if spans[mil][1] <= i:
            bas = mil + 1
        elif spans[mil][0] > i:
            haut = mil
        else:
            return True
    return False


def apparier(code, i):
    """Index de la fermante appariée de l'ouvrante en `i` (-1 si le texte s'épuise). Les chaînes Rust ET
    LES LITTÉRAUX DE CARACTÈRE OU D'OCTET sont sautés (`_saut_de_litteral_rust`, `P10.20-m`) : ni une
    parenthèse écrite dans un littéral, ni le `"` d'un `'"'` ne comptent."""
    paires = {"(": ")", "[": "]", "{": "}"}
    if code[i] not in paires:
        return -1
    pile, j = [paires[code[i]]], i + 1
    while j < len(code):
        c = code[j]
        if c in "\"'":
            saut = _saut_de_litteral_rust(code, j)
            if saut is not None:
                j = saut
                continue
            # une apostrophe qui n'ouvre pas de littéral est une durée de vie : elle repart seule.
        if c in paires:
            pile.append(paires[c])
        elif c in ")]}":
            if not pile or pile[-1] != c:
                return -1
            pile.pop()
            if not pile:
                return j
        j += 1
    return -1


def arguments(code, i):
    """Tranches `(début, fin)` des arguments de tête de l'appel dont la `(` est en `i`, et l'index de
    la `)` fermante. Les virgules de GÉNÉRIQUES (`HashMap<K, V>`) ne sont PAS suivies — c'est dit dans
    « ce qu'elle ne tient pas » ; aucun site de l'arbre n'en porte en position d'argument.

    LA DÉCOUPE CONNAÎT LE LITTÉRAL DE CARACTÈRE DEPUIS `P10.20-r` (2026-09-16), PAR LA MÊME RÈGLE QUE
    L'APPARIEMENT (`_saut_de_litteral_rust`, donc `RE_CARACTERE_RUST` IMPORTÉE) et jamais par une
    recopie. Les BORNES de cette découpe étaient déjà justes — `apparier` saute les littéraux depuis
    `P10.20-m` —, mais la boucle interne, elle, ne les sautait pas, et elle se trompait DEUX FOIS :
      * `','` (une virgule ÉCRITE dans un littéral) coupait un argument en deux — `split(',')`,
        `s.trim_matches(',')` ;
      * `'"'` ouvrait une FAUSSE chaîne qui avalait le texte jusqu'au guillemet suivant, et les
        virgules de cette région disparaissaient — un argument en absorbait plusieurs.
    MESURÉ le 2026-09-16 sur `daemon/src/handlers/` : sur les 21 568 appels du corpus, 61 se découpent
    autrement selon que la règle est connue ou non (`alerts.rs:580` porte `|c: char| c.is_whitespace()
    || c == ',' || c == ';'`, `compliance.rs:38` un `split(',')`, `caseops.rs:147` un `IN
    ('resolved','closed','contained')`). AU NIVEAU DE LA CONSOMMATION RÉELLE, en revanche, l'écart est
    NUL AUJOURD'HUI et c'est dit plutôt que tu : pendant une exécution complète de cette garde,
    `arguments` est appelé 116 fois et `bras_du_match` 67 fois, et AUCUN de ces 183 appels ne change de
    résultat. Le défaut n'était donc pas MORDANT — il était ARMÉ, et il l'aurait été au premier appel
    de voie dont un argument porte `','`."""
    f = apparier(code, i)
    if f < 0:
        return None, -1
    out, prof, deb, j = [], 0, i + 1, i + 1
    while j < f:
        c = code[j]
        if c in "\"'":
            saut = _saut_de_litteral_rust(code, j)
            if saut is not None:
                j = saut
                continue
            # une apostrophe qui n'ouvre pas de littéral est une durée de vie : elle repart seule.
        if c in "([{":
            prof += 1
        elif c in ")]}":
            prof -= 1
        elif c == "," and prof == 0:
            out.append((deb, j))
            deb = j + 1
        j += 1
    out.append((deb, f))
    return out, f


def coupe_tests(code):
    """Un module de test EN LIGNE est coupé : un test peut écrire n'importe quelle forme sans qu'une
    route la serve."""
    m = re.search(r"#\[cfg\(test\)\]\s*(?:pub(?:\(crate\))?\s+)?mod\s", code)
    return code[:m.start()] if m else code


def _debut_du_corps(code, ouvrante):
    """Index de l'accolade qui ouvre le CORPS de la `fn` dont la signature commence en `ouvrante` (la `(`
    de ses paramètres ou le `<` de ses génériques), ou -1 quand cette `fn` N'A PAS DE CORPS.
    DEUX FAUTES FERMÉES ICI LE 2026-09-16 (`P10.20-m`), et la SECONDE n'était pas dans le constat.
      (1) Le premier `{` du texte n'est pas forcément du CODE : `const DEDUP_SCOPE_SEP: char = '\\u{1}';`
          (daemon/src/ingest/store.rs:195) en porte un DANS un littéral de caractère. Les littéraux sont
          donc sautés, et les groupes `(…)` / `[…]` de la signature franchis d'un coup.
      (2) UNE DÉCLARATION SANS CORPS — une méthode de `trait`, un `extern` — se termine par `;` ; le
          premier `{` du texte est alors celui de la fonction SUIVANTE, et la déclaration lui VOLE son
          corps. MESURÉ le 2026-09-16 sur `daemon/src` : 23 entrées fabriquées de cette façon — les
          quatre `fn` du trait `JsonBody` (main.rs:988) portaient toutes le corps de la première méthode
          de l'`impl` qui suit, les quatre de `SqlExec` (migrate.rs:271) aussi. Un `;` atteint avant
          toute accolade rend donc -1 : la déclaration n'entre pas dans la population.
    ET LES DEUX SONT LIÉES, C'EST POURQUOI ELLES SONT CORRIGÉES ENSEMBLE : apprendre le littéral SEUL
    aggravait la faute — `query_soql` (store.rs:195), qui s'arrêtait sur le `{` du `'\\u{1}'` et ne
    volait donc qu'un corps de deux caractères, serait allé prendre celui de `dedup_scoped_by_host`.
    CE QUE CE GESTE NE TIENT PAS, ET C'EST DIT : le `;` d'une déclaration GÉNÉRIQUE (`fn f<T>(x: T);`)
    n'est pas vu — `FN` s'arrête sur le `<` et le `>` qui le ferme n'est pas apparié (un `>` est aussi
    une comparaison), donc le scan entre dans les génériques caractère par caractère. Une telle
    déclaration vole encore le corps qui la suit ; il n'y en a AUCUNE sur `daemon/src` (mesuré)."""
    j, n = ouvrante, len(code)
    while j < n:
        c = code[j]
        if c in "\"'":
            saut = _saut_de_litteral_rust(code, j)
            if saut is not None:
                j = saut
                continue
        if c in "([":
            f = apparier(code, j)
            if f < 0:
                return -1
            j = f + 1
            continue
        if c == ";":
            return -1
        if c == "{":
            return j
        j += 1
    return -1


def fonctions(code):
    """[(nom, signature, début du corps, fin du corps)] pour chaque `fn`/`async fn` QUI A UN CORPS — une
    déclaration de `trait` n'en a pas, et elle ne vole plus celui de la fonction suivante (`P10.20-m`,
    `_debut_du_corps`). La borne du corps est `apparier`, qui saute les littéraux de caractère."""
    out = []
    for m in FN.finditer(code):
        i = _debut_du_corps(code, m.end() - 1)
        if i < 0:
            continue
        f = apparier(code, i)
        if f < 0:
            continue
        out.append((m.group(1), code[m.end() - 1:i].replace("\n", " "), i, f))
    return out


def fichiers_rust(rep):
    for dossier, sous, noms in os.walk(rep):
        sous[:] = [d for d in sous if d != "tests"]
        for nom in sorted(noms):
            if nom.endswith(".rs") and nom != "tests.rs":
                yield os.path.join(dossier, nom)


def sources(rep):
    for chemin in fichiers_rust(rep):
        with open(chemin, encoding="utf-8", errors="replace") as fh:
            yield chemin, fh.read()


# ================================================================================================
# CE QU'EST UN AVEU — DÉRIVÉ, JAMAIS ÉNUMÉRÉ
# ================================================================================================
def definitions(src, aveux_du_lecteur=None):
    """{nom: [(fichier, ligne, corps)]} pour tout `fn` du démon, hors tests.
    `aveux_du_lecteur` (facultatif) recueille les pertes de synchronisation du LECTEUR PARTAGÉ, par
    fichier (`P10.20-d`, 2026-09-16). Sans ce journal, un fichier dont une région serait avalée perdrait
    ses définitions EN SILENCE : les corps de fonction seraient tronqués, les aveux qu'ils portent
    invisibles, et la garde ACCUSERAIT un démon qu'elle n'a pas lu."""
    out = {}
    for chemin, texte in src:
        journal = []
        brut = sans_commentaires_rust(texte, journal)
        if journal and aveux_du_lecteur is not None:
            aveux_du_lecteur[os.path.relpath(chemin, RACINE)] = [
                f"ligne {texte.count(chr(10), 0, o) + 1} : {m}" for m, o in journal]
        code = coupe_tests(brut)
        for nom, sig, b, f in fonctions(code):
            out.setdefault(nom, []).append((chemin, code.count("\n", 0, b) + 1, code[b:f + 1], sig))
    return out


DOC_D_AVEU = re.compile(r"///\s*AVEU\b[^\n]*\n(?:[ \t]*///[^\n]*\n)*[ \t]*(?:pub(?:\([^)]*\))?\s+)?fn\s+([A-Za-z_]\w*)")


def constructeurs_avoues_par_leur_doc(src):
    """LE VOCABULAIRE TYPÉ (`P10.7-i`, mesuré le 2026-09-08) : l'arbre avoue AUSSI par des constructeurs
    nommés — `RollupCoverage::unproven()`, `Cap::sans_base()`, `Exactitude::indecidable()` … — dont le
    corps bâtit une variante « rien d'établi ». La propriété qui les reconnaît est DÉRIVABLE et c'est
    celle que l'arbre se donne : leur commentaire de documentation commence par `AVEU` (six sur six le
    jour de la mesure, aucune liste). Lu sur le texte BRUT, puisque `definitions` retire les commentaires."""
    out = set()
    for _chemin, texte in src:
        out.update(m.group(1) for m in DOC_D_AVEU.finditer(texte))
    return out


def constructeurs_d_aveu(defs, src=()):
    """Les fonctions dont le corps PROPRE pose la clé `error` ET qui rendent une valeur écrivable dans
    une expression — PLUS celles que leur documentation déclare `AVEU` (`constructeurs_avoues_par_leur_doc`).
    Aucun point fixe : suivre les appelants ferait de tout handler un constructeur
    (mesuré le 2026-08-30 : 298 noms au lieu de 36), et un critère qui reconnaît tout ne refuse rien."""
    out = constructeurs_avoues_par_leur_doc(src)
    for nom, sites in defs.items():
        for _chemin, _ligne, corps, sig in sites:
            if POSE_AVEU.search(corps) and RETOUR_CORPS.search(sig.strip()):
                out.add(nom)
    # UNE SEULE passe, et seulement pour les ENVELOPPES MINCES — un corps qui n'est QU'UN appel
    # (`fn bad_req(msg) -> Response { err_json(StatusCode::BAD_REQUEST, msg) }`). Sans elle, `bad_req`
    # et `server_err` ne sont pas des aveux et la garde accuse un bras qui rend un 400 nommé ; avec un
    # POINT FIXE au lieu d'une passe minces-seulement, tout handler appelant `bad_req` deviendrait un
    # constructeur (mesuré le 2026-08-30 : 298 noms au lieu de 40) — un critère qui reconnaît tout ne
    # refuse rien.
    minces = set()
    for nom, sites in defs.items():
        for _chemin, _ligne, corps, sig in sites:
            interieur = corps.strip()[1:-1].strip()
            m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_:]*)\s*\(.*\)", interieur, re.S)
            if m and m.group(1).split("::")[-1] in out and RETOUR_CORPS.search(sig.strip()):
                minces.add(nom)
    return out | minces


def porte_un_aveu(texte, constructeurs):
    """Le texte pose la clé `error`, ou appelle un constructeur d'aveu dérivé."""
    if POSE_AVEU.search(texte):
        return True
    return any(re.search(r"\b" + re.escape(n) + r"\s*\(", texte) for n in constructeurs)


# ================================================================================================
# LA CHAÎNE D'APPELS QUI SUIT UNE EXPRESSION
# ================================================================================================
def chaine_apres(code, fin):
    """Les méthodes chaînées après la fermante en `fin` : `['await', 'ok', 'and_then']`, `'?'` compris.
    Rend `(jetons, index de fin de l'expression)`."""
    jetons, k = [], fin + 1
    while k < len(code):
        c = code[k]
        if c in " \t\n":
            k += 1
            continue
        if c == "?":
            jetons.append("?")
            k += 1
            continue
        if c == ".":
            m = re.match(r"\.\s*([a-z_][a-z0-9_]*)\s*", code[k:])
            if not m:
                break
            jetons.append(m.group(1))
            k += m.end()
            if k < len(code) and code[k] == "(":
                e = apparier(code, k)
                if e < 0:
                    break
                jetons[-1] += "()" if e == k + 1 else "(…)"
                k = e + 1
            continue
        break
    return jetons, k


def sort_des_enveloppes(code, deb, fin):
    """Si l'appel est le corps d'une closure passée à un lanceur (`spawn_blocking(move || …)`), l'appel
    REMONTE aux bornes du LANCEUR : la cause se traite là, pas dans la closure. Rend `(début, fin)`.
    Sans la remontée du DÉBUT, `match spawn_blocking(move || run_query(…)).await { … }` n'est pas vu
    comme un branchement — le texte qui précède l'appel interne finit par `move ||` et non par `match`."""
    for _ in range(3):
        prof, i = 0, deb - 1
        while i >= 0:
            c = code[i]
            if c in ")]}":
                prof += 1
            elif c in "([{":
                if prof == 0:
                    break
                prof -= 1
            i -= 1
        if i < 0 or code[i] != "(":
            return deb, fin
        entre = code[i + 1:deb]
        if not re.fullmatch(r"\s*(?:move\s*)?\|\s*\|\s*", entre):
            return deb, fin
        f = apparier(code, i)
        if f < 0 or f < fin:
            return deb, fin
        # Le lanceur commence à son NOM, pas à sa parenthèse.
        n = re.search(r"[A-Za-z_][A-Za-z0-9_:]*\s*$", code[max(0, i - 80):i])
        fin, deb = f, (max(0, i - 80) + n.start() if n else i)
    return deb, fin


def bras_du_match(code, ouvrante):
    """[(motif, corps)] pour chaque bras de tête du bloc de `match` ouvert en `ouvrante`.

    LA DÉCOUPE CONNAÎT LE LITTÉRAL DE CARACTÈRE DEPUIS `P10.20-r` (2026-09-16), par la même règle
    importée qu'`arguments` et `apparier` (`_saut_de_litteral_rust`). Un `match` sur un `char` — la
    forme la plus banale qui soit — porte ses motifs EN LITTÉRAUX : `soql_glue.rs` a un bras `'"' =>
    …`, `handlers/connectors/httppull.rs:49` un bras `'[' => …`. Sans la règle, le `"` d'un motif
    ouvrait une fausse chaîne et les bras suivants FUSIONNAIENT dans un seul : un bras d'erreur qui
    parle devenait invisible, exactement la faute que la coupure sur `}` a fermée le 2026-08-30 pour
    une autre cause. MESURÉ sur `daemon/src/handlers/` : 2 blocs de `match` sur les 820 du corpus se
    découpent autrement (`httppull.rs:49` — 2 bras au lieu de 3 —, `datasource.rs:201`, dont un bras
    porte `s.ends_with('}')`). AU NIVEAU DE LA CONSOMMATION, l'écart est NUL aujourd'hui : aucun de
    ces deux blocs n'est atteint par les 67 appels d'une exécution complète."""
    f = apparier(code, ouvrante)
    if f < 0:
        return []
    corps, out, prof, deb, j = code[ouvrante + 1:f], [], 0, 0, 0
    while j < len(corps):
        c = corps[j]
        if c in "\"'":
            saut = _saut_de_litteral_rust(corps, j)
            if saut is not None:
                j = saut
                continue
            # une apostrophe qui n'ouvre pas de littéral est une durée de vie : elle repart seule.
        if c in "([{":
            prof += 1
        elif c in ")]}":
            prof -= 1
        elif c == "," and prof == 0:
            out.append(corps[deb:j])
            deb = j + 1
        j += 1
        # UN BRAS À CORPS DE BLOC N'EST PAS SUIVI D'UNE VIRGULE : `Ok(v) => { … } Err(e) => { … }`.
        # Sans cette coupure, les deux bras n'en font qu'un et le bras d'erreur devient invisible —
        # mesuré le 2026-08-30 : SIX sites innocents accusés, dont `alerting.rs` qui COMPTE son abandon.
        if c == "}" and prof == 0 and corps[deb:j].count("=>") >= 1:
            out.append(corps[deb:j])
            deb = j
            while deb < len(corps) and corps[deb] in " \t\n,":
                deb += 1
            j = deb
        continue
    if corps[deb:].strip():
        out.append(corps[deb:])
    rendus = []
    for bras in out:
        i = bras.find("=>")
        if i > 0:
            rendus.append((bras[:i], bras[i + 2:]))
    return rendus


def temoins_des_lecteurs_de_forme():
    """LES LECTEURS DE FORME RUST SE VALIDENT AVANT DE SERVIR — comme `temoins_du_lecteur` le fait pour
    le dépouilleur de commentaires depuis `P10.20-d`, et POUR LA MÊME RAISON MESURÉE (`P10.20-r`,
    2026-09-16).

    `apparier`, `fonctions`, `arguments` et `bras_du_match` sont IMPORTÉS par deux autres gardes
    (`check_a_truncated_list_is_never_served_as_a_complete_one.py` directement,
    `check_a_single_row_read_that_failed_is_never_served_as_a_fact.py` par ré-import). Un import
    n'exécute aucun témoin : tant que ces témoins vivaient dans le `valider_instrument` de CE fichier,
    un lecteur amputé n'était épinglé que par la garde qui le PORTE. MESURÉ le 2026-09-16 : sous une
    mutation qui retire la règle du littéral de caractère à `apparier`, la garde de famille restait
    VERTE À SORTIE IDENTIQUE — un scanner amputé traversait deux gardes sans un mot. Ces témoins-ci
    sont donc APPELABLES, et les deux consommatrices les jouent au départ de leur propre instrument.

    ILS LÈVENT `AssertionError` plutôt que de rendre une liste : c'est la forme de `temoins_du_lecteur`,
    et trois appelants qui traitent l'aveu de la même façon valent mieux que deux conventions.

    CE QU'ILS NE TIENNENT PAS : ils jugent les lecteurs sur des extraits FABRIQUÉS, jamais sur l'arbre.
    Un lecteur juste sur ces huit formes et faux sur une neuvième reste vert ici."""
    # --- (1) LE LITTÉRAL DE CARACTÈRE, AU NIVEAU DU PRÉDICAT, DANS LES DEUX SENS.
    assert _saut_de_litteral_rust("let s: &'static str = n();", 7) is None, \
        "témoin de la DURÉE DE VIE (négatif) : `'static` est pris pour un littéral de caractère — le " \
        "scanner sauterait du CODE, et toute portée qui le suit serait fausse"
    assert _saut_de_litteral_rust("c == '\"' && x", 5) == 8, \
        "témoin du LITTÉRAL (positif, au niveau du prédicat) : `'\"'` n'est plus sauté d'un bloc — sans " \
        "lui tous les témoins qui suivent pourraient être verts par accident"
    # --- (2) L'APPARIEMENT NE SE PERD PAS DANS UN LITTÉRAL.
    assert apparier("f('\"', x)", 1) == 8, \
        "témoin de l'APPARIEMENT : la fermante de `f('\"', x)` n'est plus trouvée — le `\"` d'un `'\"'` " \
        "ouvre une fausse chaîne et l'expression est perdue jusqu'au guillemet suivant"
    # --- (3) LES FONCTIONS, ET LEURS CORPS (`P10.20-m`). LE TEXTE EST FABRIQUÉ ICI, JAMAIS PRIS SUR
    # L'ARBRE : adossé à `handlers/actions.rs`, ce témoin deviendrait une RANÇON — rouge le jour où
    # quelqu'un réécrit ce fichier, et aucun geste ne le refermerait. Les FORMES, elles, sont celles de
    # l'arbre (`actions.rs` `'"'`, `freshness.rs` `b'"'`, `panneau_avoue.rs` `'"'`, `ingest/store.rs`
    # `'\u{1}'` et sa déclaration de `trait`). MESURE DU DÉFAUT sur `daemon/src` : 38 fonctions
    # INVISIBLES dans 25 fichiers et 6 corps bornés au mauvais endroit. Une fonction invisible ne rougit
    # jamais — elle n'est pas LUE : le lecteur ne fabrique pas d'accusation, il en PERD, en vert.
    fabrique = ("const SHELL_META: [char; 3] = [';', '\"', '|'];\n"
                "fn apres_le_litteral(c: char) -> bool { c == '\"' }\n"
                "fn avec_duree_de_vie<'a>(s: &'a str) -> &'a str { s.trim_matches('\"') }\n"
                "fn octet(b: u8) -> bool { b == b'\"' }\n"
                "fn tableau(k: &[u8]) -> [u8; 4] { [0; 4] }\n"
                "const SEP: char = '\\u{1}';\n"
                "trait Sans { fn declaree(&self) -> bool; }\n"
                "fn volee() -> bool { true }\n")
    fab = coupe_tests(sans_commentaires_rust(fabrique))
    attendues = ["apres_le_litteral", "avec_duree_de_vie", "octet", "tableau", "volee"]
    vues = [n for n, _sig, _b, _f in fonctions(fab)]
    assert vues == attendues, (
        f"témoin du LITTÉRAL DE CARACTÈRE : fonctions vues {vues} au lieu de {attendues} — soit le `\"` "
        "d'un `'\"'` (ou d'un `b'\"'`) ouvre encore une fausse chaîne et la fonction devient INVISIBLE, "
        "soit l'accolade d'un `'\\u{1}'` est prise pour un corps, soit le `;` d'un type TABLEAU "
        "(`-> [u8; 4]`) est lu comme la fin d'une déclaration (13 fonctions de `daemon/src` perdues "
        "ainsi, mesuré par mutation le 2026-09-16), soit une DÉCLARATION de `trait` (`fn declaree(..);`) "
        "vole le corps de la suivante")
    corps_fab = {n: fab[b:f + 1] for n, _sig, b, f in fonctions(fab)}
    assert corps_fab.get("volee", "").strip() == "{ true }", (
        f"témoin du CORPS VOLÉ : le corps de `volee` est {corps_fab.get('volee')!r} au lieu de "
        "`{ true }` — une fonction sans corps prend celui de sa voisine, et les DEUX entrées portent "
        "alors le même texte (23 entrées fabriquées ainsi sur `daemon/src`)")
    # --- (4) LA DÉCOUPE PAR VIRGULE DES ARGUMENTS CONNAÎT LE LITTÉRAL (`P10.20-r`), DANS LES DEUX SENS.
    src = "separer(',', '\"', texte)"
    tranches, _f = arguments(src, src.index("("))
    lus = [src[a:b].strip() for a, b in (tranches or [])]
    assert lus == ["','", "'\"'", "texte"], (
        f"témoin des ARGUMENTS (littéral de caractère) : {lus} au lieu de [\"','\", \"'\\\"'\", "
        "'texte'] — soit la virgule ÉCRITE dans `','` coupe encore un argument en deux, soit le `\"` de "
        "`'\"'` ouvre une fausse chaîne qui avale les virgules suivantes et fond plusieurs arguments en "
        "un. Les deux font dire au lecteur qu'une voie porte un nombre d'arguments qu'elle n'a pas, et "
        "le troisième argument — la fermeture — devient alors le mauvais texte")
    src_nu = "nouveau(&'static str, x)"
    tr_nu, _f = arguments(src_nu, src_nu.index("("))
    assert [src_nu[a:b].strip() for a, b in (tr_nu or [])] == ["&'static str", "x"], (
        "témoin des ARGUMENTS (négatif, durée de vie) : `&'static str` n'est plus lu comme un argument "
        "entier — une apostrophe qui n'ouvre AUCUN littéral fait sauter du code")
    src_ch = 'appeler("a,b", c)'
    tr_ch, _f = arguments(src_ch, src_ch.index("("))
    assert len(tr_ch or []) == 2, (
        f"témoin des ARGUMENTS (négatif, chaîne) : {len(tr_ch or [])} argument(s) au lieu de 2 — une "
        "virgule ÉCRITE DANS une chaîne coupe désormais, et tout appel dont un littéral porte une "
        "virgule serait lu de travers")
    # --- (5) LA DÉCOUPE DES BRAS DE `match` CONNAÎT LE LITTÉRAL (`P10.20-r`), DANS LES DEUX SENS.
    src_b = "match c { '\"' => 1, ',' => 2, _ => 3 }"
    motifs = [m.strip() for m, _c in bras_du_match(src_b, src_b.index("{"))]
    assert motifs == ["'\"'", "','", "_"], (
        f"témoin des BRAS (littéral de caractère) : motifs {motifs} au lieu de [\"'\\\"'\", \"','\", "
        "'_'] — un `match` sur un `char` (`soql_glue.rs` porte un bras `'\"' => …`) voit ses bras "
        "FUSIONNER, et un bras d'erreur qui parle devient invisible")
    src_bc = 'match s { "a,b" => 1, _ => 2 }'
    assert len(bras_du_match(src_bc, src_bc.index("{"))) == 2, (
        "témoin des BRAS (négatif, chaîne) : une virgule ÉCRITE DANS une chaîne coupe un bras en deux "
        "— le motif rendu serait un fragment de littéral")
    # --- (6) LES INTERVALLES DE CHAÎNE, DANS LES DEUX SENS (lecteur consommé par la garde de forme des
    # lectures uniques ET par la famille des parcours muets).
    fab_s = 'fn f() { let c = \'"\'; let s = "a;b{c}"; let t = r#"d;e{f}"#; }'
    spans = spans_de_chaines_rust(fab_s)
    assert len(spans) == 2 and fab_s[spans[0][0]:spans[0][1]] == '"a;b{c}"', (
        f"témoin des LITTÉRAUX : {len(spans)} littéral(aux) vu(s) sur une source qui en porte DEUX (une "
        "chaîne simple, une chaîne brute) précédés d'un littéral de CARACTÈRE — dans un sens une forme "
        "CITÉE dans une phrase deviendrait un site fantôme ; dans l'autre un `'\"'` ouvrirait une fausse "
        "chaîne qui avale la fin du fichier et fait DISPARAÎTRE des sites réels, en vert")
    assert dans_une_chaine_rust(spans, fab_s.index("a;b{c}")), \
        "témoin de l'APPARTENANCE (positif) : un index INTÉRIEUR à une chaîne est déclaré dehors"
    assert not dans_une_chaine_rust(spans, fab_s.index("let c")), \
        "témoin de l'APPARTENANCE (négatif) : un index de CODE est déclaré dans une chaîne, et tout " \
        "site réel serait écarté comme un fantôme"


# ================================================================================================
# JAMBE Q — LE BRAS D'ERREUR NE PEUT PAS ÊTRE JETÉ
# ================================================================================================
GARDE, JETE, PROPAGE, NON_CLASSE = "gardé", "jeté", "propagé", "non classé"


def bras_derreur_garde(motif, corps, constructeurs, portee):
    """Un bras d'erreur est GARDÉ s'il porte la cause, avoue, propage, ou devient un statut d'échec."""
    lie = re.search(r"Err\s*\(\s*(?:Ok\s*\(\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\)", motif)
    if lie and re.search(r"\b" + re.escape(lie.group(1)) + r"\b", corps):
        return True
    if porte_un_aveu(corps, constructeurs) or STATUT_ECHEC.search(corps):
        return True
    # `Err(_) => return fail` où `fail` a été construit AVEC sa marque d'échec (`ok: false`).
    for m in re.finditer(r"\b(?:return\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*[,;}\s]*$", corps.strip()):
        d = re.search(r"let\s+(?:mut\s+)?" + re.escape(m.group(1)) + r"\s*(?::[^=]*)?=\s*", portee)
        if d and MARQUE_ECHEC.search(portee[d.end():d.end() + 600]):
            return True
    return False


def juger_le_match(code, apres, constructeurs, portee):
    """`apres` pointe juste après l'expression : le bloc de `match` doit y commencer."""
    i = apres
    while i < len(code) and code[i] in " \t\n":
        i += 1
    if i >= len(code) or code[i] != "{":
        return NON_CLASSE, "le bloc de bras est introuvable"
    bras = bras_du_match(code, i)
    err = [(m, c) for m, c in bras if re.search(r"\bErr\s*\(|\bJoinError\b", m)]
    fourre = [(m, c) for m, c in bras if m.strip() in ("_", "&_")]
    if not err and not fourre:
        return JETE, "aucun bras ne nomme l'erreur : la cause n'est écrite nulle part"
    for m, c in err + fourre:
        if not bras_derreur_garde(m, c, constructeurs, portee):
            return JETE, f"le bras `{re.sub(r'\\s+', ' ', m.strip())[:60]}` rend une valeur sans sa cause"
    return GARDE, ""


def juger_la_cause(code, deb, fin, portee_deb, portee_fin, sig, constructeurs, profondeur=0):
    """Le sort de la cause d'un `run_query`/`run_query_ex`. Rend `(verdict, raison)`."""
    portee = code[portee_deb:portee_fin]
    deb, fin = sort_des_enveloppes(code, deb, fin)
    jetons, apres = chaine_apres(code, fin)
    if "?" in jetons:
        return PROPAGE, ""
    avales = [j for j in jetons if AVALE.match(j.split("(")[0])]
    if avales:
        # `unwrap_or_else(|e| <aveu>)` porte la cause ; `.ok()` ne la porte jamais.
        bloc = code[fin:apres]
        if porte_un_aveu(bloc, constructeurs):
            return GARDE, ""
        return JETE, f"la cause est avalée par `.{avales[0]}`"
    # L'appel est-il le scrutateur d'un `match` / d'un `if let` ?
    avant = code[max(portee_deb, deb - 120):deb].rstrip()
    if avant.endswith("match") or avant.endswith("match &"):
        return juger_le_match(code, apres, constructeurs, portee)
    mif = re.search(r"if\s+let\s+([^=]{1,60})=\s*$", avant)
    if mif:
        i = apres
        while i < len(code) and code[i] in " \t\n":
            i += 1
        if i < len(code) and code[i] == "{":
            f = apparier(code, i)
            if f > 0 and not re.match(r"\s*else\b", code[f + 1:f + 12]):
                return JETE, "un `if let` sans `else` : le chemin d'échec n'est écrit nulle part"
        return GARDE, ""
    # Expression FINALE d'une fonction qui rend un `Result` : la cause remonte à l'appelant.
    reste = code[apres:portee_fin].strip()
    if reste in ("", "}") and RETOUR_RESULTAT.search(sig):
        return PROPAGE, ""
    # Liaison : `let <motif> = <expression>;` -> on suit le nom lié.
    if profondeur >= 2:
        return NON_CLASSE, "la liaison est relayée plus de deux fois"
    debut_instr = code.rfind(";", portee_deb, deb)
    debut_instr = max(debut_instr + 1, portee_deb + 1)
    tete = code[debut_instr:deb]
    mlet = re.search(r"let\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*|\([^)]*\))\s*(?::[^=]*)?=\s*[^=]*$", tete)
    if not mlet:
        return NON_CLASSE, "ni chaîne, ni branchement, ni liaison reconnus"
    noms = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", mlet.group(1))
    if not noms:
        return NON_CLASSE, "la liaison n'a pas de nom"
    return suivre_la_liaison(code, noms[0], apres, portee_deb, portee_fin, constructeurs, profondeur)


def suivre_la_liaison(code, nom, depuis, portee_deb, portee_fin, constructeurs, profondeur):
    """La première consommation du nom lié décide du sort de la cause."""
    portee = code[portee_deb:portee_fin]
    for m in re.finditer(r"(?<![\w.])" + re.escape(nom) + r"\b", code[depuis:portee_fin]):
        pos = depuis + m.start()
        avant = code[max(portee_deb, pos - 140):pos].rstrip()
        jetons, apres = chaine_apres(code, pos + len(nom) - 1)
        if avant.endswith("match") or avant.endswith("match &"):
            return juger_le_match(code, apres, constructeurs, portee)
        if re.search(r"if\s+let\s+[^=]{1,60}=\s*$", avant) or re.search(r"while\s+let\s+[^=]{1,60}=\s*$", avant):
            i = apres
            while i < len(code) and code[i] in " \t\n":
                i += 1
            if i < len(code) and code[i] == "{":
                f = apparier(code, i)
                if f > 0 and not re.match(r"\s*else\b", code[f + 1:f + 12]):
                    return JETE, "un `if let` sans `else` : le chemin d'échec n'est écrit nulle part"
            return GARDE, ""
        if "?" in jetons:
            return PROPAGE, ""
        avales = [j for j in jetons if AVALE.match(j.split("(")[0])]
        if avales:
            if porte_un_aveu(code[pos:apres], constructeurs):
                return GARDE, ""
            return JETE, f"la cause est avalée par `.{avales[0]}` sur `{nom}`"
        # RELAIS : `let (a, b) = tokio::join!(x, y)` -> on suit la position de `nom` dans les arguments.
        debut_instr = max(code.rfind(";", portee_deb, pos) + 1, portee_deb + 1)
        tete = code[debut_instr:pos]
        mlet = re.search(r"let\s+(?:mut\s+)?(\([^)]*\)|[A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]*)?=\s*", tete)
        if mlet:
            cibles = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", mlet.group(1))
            # LE RANG EST CELUI DE L'APPEL QUI CONTIENT LA POSITION, pas du premier `(` de l'instruction :
            # `let (count_res, page) = tokio::join!(count_fut, page_fut)` commence par le `(` du MOTIF, et
            # le prendre pour le macro-appel range TOUT en position 0 — mesuré le 2026-08-30, `page_fut`
            # était accusé sous le nom de `count_res`.
            rang, meilleure = None, -1
            for mo in re.finditer(r"([A-Za-z_][A-Za-z0-9_:]*)\s*!?\s*\(", code[debut_instr:pos + 1]):
                i0 = debut_instr + mo.end() - 1
                a, f0 = arguments(code, i0)
                if not a or not (i0 < pos < f0) or i0 <= meilleure:
                    continue
                for r, (d0, ff) in enumerate(a):
                    if d0 <= pos < ff:
                        rang, meilleure = r, i0
            if cibles and rang is not None and rang < len(cibles):
                return suivre_la_liaison(code, cibles[rang], max(apres, debut_instr), portee_deb,
                                         portee_fin, constructeurs, profondeur + 1)
        continue
    return NON_CLASSE, "aucune consommation du nom lié n'a été reconnue"


# ================================================================================================
# JAMBE B — UNE LECTURE DE LIGNES AVALÉE
# ================================================================================================
# Les noms de méthode qui SONT la lecture. Rencontrés en suivant un nom lié par un bras, ils rendent
# la main à la détection DIRECTE — sans quoi le MÊME avalement serait compté deux fois.
NOM_LECTURE = re.compile(r"^(?:query_row|query_map|query|prepare|prepare_cached)$")
# Un bras qui LIE ce que la lecture a rendu : `Ok(r) =>`, `Ok(mut s) =>`. Le bras d'erreur ne lie pas
# une lecture réussie ; c'est la jambe Q qui juge son sort, et seulement pour les voies de requête.
BRAS_LIANT = re.compile(r"^\s*Ok\s*\(\s*(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*$")


def scrutateur_est_la_lecture(texte, deb):
    """Le texte entre le dernier `match` et la lecture qui commence en `deb` n'est-il QUE le RECEVEUR
    de cette lecture (`match stmt` ., `match conn.prepare(&sql)`) ?

    C'EST LA CONDITION QUI EMPÊCHE L'ÉLARGISSEMENT D'ACCUSER À TORT. Sans elle, il suffirait qu'une
    accolade suive une lecture pour que les bras du `match` le plus proche EN AMONT — un `match` qui
    porte sur tout autre chose — soient fouillés. Une ponctuation d'instruction (`;` `{` `}` `=` `=>`)
    ou un mot-clé entre les deux prouve que ce `match` n'est pas celui-ci, et le refus est alors NET :
    la jambe se tait plutôt que de deviner."""
    mots = list(re.finditer(r"\bmatch\b", texte[:deb]))
    if not mots:
        return False
    entre = texte[mots[-1].end():deb]
    if not entre.strip() or re.search(r"[;{}=]|\b(?:if|while|let|for|return|match)\b", entre):
        return False
    prof = 0
    for c in entre:
        if c in "([":
            prof += 1
        elif c in ")]":
            prof -= 1
            if prof < 0:
                return False
    return prof == 0


def bras_qui_avale(texte, deb, apres):
    """La lecture qui commence en `deb` est-elle le scrutateur d'un `match` dont un BRAS avale ce
    qu'elle lui a lié ? Rend la chaîne fautive, ou None.

    ANGLE MORT COMBLÉ, MESURÉ LE 2026-08-30 SUR LA MACHINERIE DE CETTE GARDE, DANS LES DEUX SENS :
    `.query_map(..).flatten()` était accusé ; la MÊME opération écrite `match ..query_map(..) { Ok(r)
    => r.flatten().collect(), .. }` ne l'était PAS. La raison est structurelle : `chaine_apres` bute
    sur l'accolade des bras et rend une chaîne VIDE. C'était l'idiome de trois des sites fermés ce
    jour-là, d'où un cliquet qui n'avait baissé que d'une unité pour quatre fermetures.

    LA CHAÎNE EST SUIVIE DEPUIS LE NOM LIÉ, ET ELLE S'ARRÊTE À LA PREMIÈRE LECTURE RENCONTRÉE.
    `Ok(mut s) => s.query_map(..).unwrap_or_default()` avale le PARCOURS, pas l'énoncé préparé, et la
    détection DIRECTE le voit déjà sur `query_map` ; sans cet arrêt, un seul avalement serait compté
    deux fois et le cliquet monterait sans qu'aucun défaut neuf n'existe."""
    if not scrutateur_est_la_lecture(texte, deb):
        return None
    i = apres
    while i < len(texte) and texte[i] in " \t\n":
        i += 1
    if i >= len(texte) or texte[i] != "{":
        return None
    for motif, corps in bras_du_match(texte, i):
        m = BRAS_LIANT.match(motif)
        if not m:
            continue
        nom = m.group(1)
        for oc in re.finditer(r"(?<![\w.])" + re.escape(nom) + r"\b", corps):
            jetons, _ = chaine_apres(corps, oc.start() + len(nom) - 1)
            for j in jetons:
                base = j.split("(")[0]
                if NOM_LECTURE.match(base):
                    break
                if AVALE.match(base):
                    return f"{motif.strip()} => {'.'.join(jetons)}"
    return None


# --- LA TROISIÈME ÉCRITURE : `if let Ok(..) = <lecture> { .. }` SANS `else` (`P10.7-h`) -----------
# `if let` AVEC `else` n'est PAS jugé ici : une branche existe, et ce qu'elle fait relève du
# reconnaisseur d'aveu au niveau de la région — c'est EXACTEMENT la règle que la jambe Q applique déjà
# à la même forme sur les voies de requête (`juger_la_cause`), et la faire diverger ferait dire deux
# choses différentes à la même garde sur le même texte.
#
# IL N'Y A PLUS QU'UN MOTIF DE LIAISON (`P10.20-s`, 2026-09-19), ET C'EST UNE PROPRIÉTÉ STRUCTURELLE,
# PAS UN RÉGLAGE. Le motif ÉTROIT (`Ok(<nom simple>)`, `mut` compris) vivait ici à côté du large et
# servait de DÉFAUT à la jambe B : le tuple (`Ok((kind, target, dry))`) et le motif imbriqué
# (`Ok(Some(t))`) lui échappaient. Il est SUPPRIMÉ plutôt que laissé en défaut, parce qu'un motif
# étroit encore écrit est un rétrécissement qu'une mutation d'une ligne rétablit sans que rien ne le
# dise. Ce qui reste est un seul objet, partagé par la jambe B d'ici et par la famille des PARCOURS
# MUETS de `check_a_truncated_list_is_never_served_as_a_complete_one.py`, qui le passe explicitement.
#
# CE QUE L'ÉLARGISSEMENT A COÛTÉ, MESURÉ AVANT DE L'APPLIQUER, sur l'arbre du 2026-09-19 : ZÉRO
# accusation de plus jambe B, zéro site de plus dans la population BRUTE de la forme sous
# `daemon/src/handlers/`. Sur l'arbre qui portait encore le tuple de `action_approve`, le motif large
# fait passer cette population brute de zéro à UN — et la jambe B y reste à ZÉRO : ce site lit
# derrière `req_conn!`, une voie hors population, donc sa région ne s'ouvre pas et son texte n'est
# jamais lu. Élargir le motif ne l'aurait PAS rendu visible ; ce qui manquait était la population.
# Hors `handlers/`, sur tout `daemon/src`, le large ajoute UN site au strict (`rollups.rs`,
# `rollup_events`, forme `Ok(Some(t))`) — hors population lui aussi, et nommé ici pour être vu.
MOTIF_LIANT_IF_LET_TOUT_MOTIF = re.compile(r"^Ok\s*\(.*\)$", re.S)


def egal_de_tete(texte):
    """Index du `=` de LIAISON (profondeur 0, ni `==` ni `!=`/`<=`/`>=`), ou None."""
    prof = 0
    for i, c in enumerate(texte):
        if c in "([{":
            prof += 1
        elif c in ")]}":
            prof -= 1
            if prof < 0:
                return None
        elif c == "=" and prof == 0 and texte[i + 1:i + 2] != "=" and texte[i - 1:i] not in "=!<>":
            return i
        elif c == ";" and prof == 0:
            return None
    return None


def if_let_est_le_scrutateur(texte, deb, motif=MOTIF_LIANT_IF_LET_TOUT_MOTIF):
    """Le `if let Ok(..) =` le plus proche EN AMONT lie-t-il la lecture qui commence en `deb` ?

    C'EST LA MÊME CONDITION QUI EMPÊCHE D'ACCUSER À TORT que pour le `match`, et pour la même raison :
    sans elle, il suffirait qu'un `if let` quelconque précède une lecture pour que celle-ci soit
    déclarée sans branche. Une ponctuation d'instruction (`;` `{` `}` `=`) ou un mot-clé entre le `=`
    et la lecture prouve que ce `if let` porte sur autre chose, et le refus est alors NET.

    `motif` est le motif de liaison accepté. Depuis `P10.20-s` il n'en existe plus qu'UN
    (`MOTIF_LIANT_IF_LET_TOUT_MOTIF`), et c'est aussi le DÉFAUT : la liaison par TUPLE et le motif
    IMBRIQUÉ sont vus comme le nom simple. Le paramètre survit parce qu'une consommatrice le passe
    explicitement, et parce qu'il garantit qu'il n'y a QU'UN lecteur de cette forme : la seule autre
    façon de la lire autrement serait d'en recopier un second, et ce dépôt paie cher les lecteurs
    jumeaux (`P10.20-c` à `-e`)."""
    mots = list(re.finditer(r"\bif\s+let\b", texte[:deb]))
    if not mots:
        return False
    reste = texte[mots[-1].end():deb]
    eg = egal_de_tete(reste)
    if eg is None:
        return False
    if not motif.match(reste[:eg].strip()):
        return False
    entre = reste[eg + 1:]
    if not entre.strip() or re.search(r"[;{}=]|\b(?:if|while|let|for|return|match)\b", entre):
        return False
    prof = 0
    for c in entre:
        if c in "([":
            prof += 1
        elif c in ")]":
            prof -= 1
            if prof < 0:
                return False
    return prof == 0


def if_let_sans_branche(texte, deb, apres, motif=MOTIF_LIANT_IF_LET_TOUT_MOTIF):
    """La lecture qui commence en `deb` est-elle liée par un `if let Ok(..)` dont le bloc n'est
    suivi d'AUCUN `else` ? Alors son échec n'a pas de branche : il n'est écrit nulle part.

    `motif` a le même sens que dans `if_let_est_le_scrutateur` et il est PASSÉ, jamais réinventé."""
    if not if_let_est_le_scrutateur(texte, deb, motif):
        return None
    i = apres
    while i < len(texte) and texte[i] in " \t\n":
        i += 1
    if i >= len(texte) or texte[i] != "{":
        return None
    f = apparier(texte, i)
    if f < 0:
        return None
    if re.match(r"\s*else\b", texte[f + 1:f + 14]):
        return None
    return "if let Ok(..) = <lecture> { .. } sans `else`"


def lectures_avalees(texte):
    """[(ligne relative, chaîne, forme)] pour chaque lecture de lignes dont le refus est avalé, sous
    l'une des TROIS écritures. La FORME est rendue avec l'avalement pour que le journal les distingue :
    sans elle, une écriture qui en précède une autre dans le fichier ferait TAIRE la seconde dans la
    phrase imprimée — le site resterait accusé, mais une cause vraie cesserait d'être nommée, et ce
    dépôt tient qu'un canal de détection qui rétrécit est une perte même quand le verdict ne bouge pas.
    Les trois branches s'excluent (`continue`) : une lecture ne compte JAMAIS deux fois.

    UNE FORME CITÉE DANS UN LITTÉRAL DE CHAÎNE N'EST PAS UNE LECTURE (`P10.20-s`, 2026-09-19). Le
    COMMENTAIRE était déjà écarté — `analyser` dépouille le texte avant d'arriver ici — mais la CHAÎNE
    ne l'était pas, et `sans_commentaires_rust` restitue les littéraux tels quels, c'est son contrat.
    Les trois écritures étaient donc accusables depuis une phrase d'aide, un gabarit SQL ou un message
    d'erreur qui cite la forme fautive : ÉPROUVÉ sur corpus fabriqué, une closure dont le seul contenu
    est `let aide = "… if let Ok(rows) = conn.query_map(…) { } sans else";` était accusée. Le défaut
    n'était pas MORDANT — sur l'arbre du 2026-09-19, ZÉRO des 468 appariements de `LECTURE` sous
    `daemon/src/handlers/` (et zéro des 831 de tout `daemon/src`) tombe dans un littéral de chaîne — il
    était ARMÉ, et il s'arme d'autant plus que le motif de liaison s'élargit. L'exclusion est celle que
    la famille des listes tronquées applique déjà, avec le MÊME lecteur (`spans_de_chaines_rust`),
    jamais une copie.

    CE QU'ELLE NE TIENT PAS : les intervalles sont calculés sur le FRAGMENT reçu (région de fermeture,
    corps de fonction). Un fragment qui commencerait À L'INTÉRIEUR d'un littéral serait lu à l'envers ;
    les fragments que `corps_de_la_closure` rend commencent tous à une frontière de jeton (début du
    troisième argument, début d'un corps de fonction), et c'est cette propriété-là qui le garantit."""
    out = []
    spans = spans_de_chaines_rust(texte)
    for r in LECTURE.finditer(texte):
        if dans_une_chaine_rust(spans, r.start()):
            continue
        fin = apparier(texte, r.end() - 1)
        if fin < 0:
            continue
        jetons, apres = chaine_apres(texte, fin)
        ligne = texte.count("\n", 0, r.start()) + 1
        if any(AVALE.match(j.split("(")[0]) for j in jetons):
            out.append((ligne, ".".join(jetons), "chaîne directe"))
            continue
        bras = bras_qui_avale(texte, r.start(), apres)
        if bras:
            out.append((ligne, bras, "bras de match"))
            continue  # DÉFENSIF, et il n'est prouvé par AUCUN témoin : les deux écritures s'excluent
            # déjà par construction (le mot-clé `match` qui précède la lecture fait échouer le contrôle
            # de `if_let_est_le_scrutateur`). Le retirer ne change RIEN sur l'arbre du 2026-08-30 —
            # mesuré — et c'est dit ici plutôt que couvert par un témoin qui serait vert quoi qu'il
            # arrive : un instrument qui prétend éprouver ce qu'il n'atteint pas est pire que rien.
        sans = if_let_sans_branche(texte, r.start(), apres)
        if sans:
            out.append((ligne, sans, "sans branche d'échec"))
    return out


def corps_de_la_closure(code, tranches, fin, defs):
    """La RÉGION DE LA CLOSURE : le troisième argument et au-delà, PLUS le corps des fonctions qu'elle
    appelle directement — un niveau, et seulement les noms qui ont UNE définition dans l'arbre.

    LE DEUXIÈME ARGUMENT — LE DÉFAUT — N'EN FAIT PAS PARTIE, ET C'EST LE POINT : la jambe B ne peut
    pas être satisfaite par la jambe A. La coupure est STRUCTURELLE (l'index de départ est celui du
    troisième argument), pas une convention qu'un correctif pourrait contourner."""
    texte = code[tranches[2][0]:fin]
    corps = [("<closure>", texte)]
    noms = set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", texte))
    # LA FERMETURE ÉCRITE EN CHEMIN DE FONCTION NU (`P10.7-j`, mesuré le 2026-08-30). Le troisième
    # argument n'est pas toujours un `|conn| …` : il peut être le NOM d'une fonction, passé sans
    # parenthèses (`read_with_watchdog(&db_path, BTreeMap::new(), rule_compliance_map)`). Le relevé de
    # noms ci-dessus exige un `(` collé au nom — il ne voyait donc RIEN dans ce texte, et la jambe B
    # n'ouvrait pas le corps. Le site était pourtant DANS la population depuis toujours : il est accusé
    # par la jambe A depuis le premier jour, et c'est sa CLOSURE qui restait muette. Un seul site de
    # l'arbre porte cette écriture au 2026-08-30 (`daemon/src/handlers/compliance.rs:341`), et il avale
    # DEUX lectures. Ce n'est PAS un élargissement de la population : c'est la région d'un site déjà
    # découvert qui cessait de s'ouvrir sur une écriture de Rust parfaitement ordinaire.
    nu = re.fullmatch(r"\s*([A-Za-z_][A-Za-z0-9_:]*)\s*", texte)
    if nu:
        noms.add(nu.group(1).split("::")[-1])
    for nom in sorted(noms):
        sites = defs.get(nom)
        if sites and len(sites) == 1:
            corps.append((nom, sites[0][2]))
    return corps


# ================================================================================================
# L'INSTRUMENT SE VALIDE — SEPT MUTANTS, DANS LES DEUX SENS
# ================================================================================================
# --- LES SOURCES FABRIQUÉES DE LA VOIE D'ÉCRITURE (`P10.7-l`) ------------------------------------
# Elles sont FABRIQUÉES ICI, jamais prises sur l'arbre : adosser un témoin à `legal_holds_list` ou à
# `case_merge` en ferait une RANÇON — il rougirait le jour où le site est réparé, et aucun geste ne
# pourrait le refermer. Les quatre partagent MOT POUR MOT la même lecture ; ce qui change est le TYPE
# DE RETOUR du gestionnaire (16 contre 17), la présence de l'aveu (16 contre 18), puis l'avalement
# lui-même (16 contre 19).
ECRITURE_SOURDE_CORPS = (
    'pub(crate) async fn w16(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {\n'
    '    with_write(&st, &au, |conn| {\n'
    '        let n: i64 = conn.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0)).unwrap_or(0);\n'
    '        Json(json!({ "ok": true, "n": n }))\n    })\n}\n')
ECRITURE_SOURDE_STATUT = (
    'pub(crate) async fn w17(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> StatusCode {\n'
    '    with_write(&st, &au, |conn| {\n'
    '        let n: i64 = conn.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0)).unwrap_or(0);\n'
    '        if n > 0 { StatusCode::NO_CONTENT } else { StatusCode::NOT_FOUND }\n    })\n}\n')
ECRITURE_QUI_AVOUE = (
    'pub(crate) async fn w18(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Json<Value> {\n'
    '    with_write(&st, &au, |conn| {\n'
    '        let n: i64 = conn.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0)).unwrap_or(0);\n'
    '        Json(json!({ "n": n, "error": "compte NON ÉTABLI : la lecture n a pas abouti" }))\n    })\n}\n')
# La fermeture PROPRE : elle prouve que la jambe A ne lit JAMAIS le deuxième argument de `with_write`
# (`&au`, qui n'avoue évidemment pas), et que la seule présence d'un site d'écriture n'accuse rien.
ECRITURE_PROPRE = (
    'pub(crate) async fn w19(State(st): State<AppState>, Extension(au): Extension<AuthUser>) -> Response {\n'
    '    with_write(&st, &au, |conn| {\n'
    '        let n: i64 = conn.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))?;\n'
    '        Json(json!({ "n": n })).into_response()\n    })\n}\n')

MUTANTS = [
    # (nom, source Rust, jambe attendue en accusation ou None)
    ("1. un corps par défaut NU",
     'pub(crate) async fn r1() -> Json<Value> {\n'
     '    let v = read_with_watchdog(&db, json!({ "rows": [] }), move |conn| lit(conn));\n'
     '    Json(v)\n}\n', "A"),
    ("2. le même défaut, AVEC son aveu",
     'pub(crate) async fn r2() -> Json<Value> {\n'
     '    let v = read_with_watchdog(&db, json!({ "rows": [], "error": "lecture NON FAITE" }), move |conn| lit(conn));\n'
     '    Json(v)\n}\n', None),
    ("3. une lecture de ligne AVALÉE dans la closure",
     'pub(crate) async fn r3() -> Json<Value> {\n'
     '    let v = read_with_watchdog(&db, json!({ "rows": [], "error": "x" }), move |conn| {\n'
     '        let n: i64 = conn.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0)).unwrap_or(0);\n'
     '        json!({ "n": n })\n    });\n    Json(v)\n}\n', "B"),
    ("4. la même lecture, sous une branche qui AVOUE",
     'pub(crate) async fn r4() -> Json<Value> {\n'
     '    let v = read_with_watchdog(&db, json!({ "rows": [], "error": "x" }), move |conn| {\n'
     '        let n: i64 = conn.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0)).unwrap_or(0);\n'
     '        json!({ "n": n, "error": "compte NON ÉTABLI : la lecture n\'a pas abouti" })\n    });\n'
     '    Json(v)\n}\n', None),
    ("5. une exécution de requête dont la CAUSE EST JETÉE",
     'pub(crate) async fn r5() -> Json<Value> {\n'
     '    let res = match run_query(&db, &sql) {\n'
     '        Ok(v) => v,\n'
     '        Err(_) => json!({ "columns": [], "rows": [] }),\n'
     '    };\n    Json(res)\n}\n', "Q"),
    ("6. la même exécution, BRANCHÉE sur sa cause",
     'pub(crate) async fn r6() -> Json<Value> {\n'
     '    let res = match run_query(&db, &sql) {\n'
     '        Ok(v) => v,\n'
     '        Err(e) => json!({ "columns": [], "rows": [], "error": format!("NON LU : {e}") }),\n'
     '    };\n    Json(res)\n}\n', None),
    ("7. LE CŒUR — un défaut qui AVOUE au-dessus d'une closure qui AVALE",
     'pub(crate) async fn r7() -> Json<Value> {\n'
     '    let v = read_with_watchdog(&db, corps_de_refus(json!({ "rows": [] })), move |conn| {\n'
     '        let n: i64 = conn.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0)).unwrap_or(0);\n'
     '        json!({ "n": n })\n    });\n    Json(v)\n}\n', "B"),
    # --- LES QUATRE SUIVANTS TIENNENT LA FORME AJOUTÉE LE 2026-08-30 (`P10.7-g`) : L'AVALEMENT ÉCRIT
    # DANS UN BRAS DE MATCH. Le 8 et le 10 sont une PAIRE DISCRIMINANTE — le bras y est le MÊME texte
    # (`Ok(r) => r.flatten().collect()`), seul le SCRUTATEUR change, et le verdict doit s'inverser.
    # Sans le 10, une détection qui fouillerait les bras de TOUT `match` passerait le 8 et accuserait
    # à tort partout ailleurs ; c'est la faute que ce dépôt tient pour pire que l'angle mort.
    ("8. UN BRAS DE MATCH qui avale, scrutateur = une LECTURE de lignes",
     'pub(crate) async fn r8() -> Json<Value> {\n'
     '    let v = read_with_watchdog(&db, json!({ "rows": [], "error": "x" }), move |conn| {\n'
     '        let mut stmt = conn.prepare("SELECT a FROM t").unwrap();\n'
     '        let out: Vec<Value> = match stmt.query_map([], |r| Ok(json!({ "a": r.get::<_, i64>(0)? }))) {\n'
     '            Ok(r) => r.flatten().collect(),\n'
     '            Err(_) => Vec::new(),\n'
     '        };\n'
     '        json!({ "rows": out })\n    });\n    Json(v)\n}\n', "B"),
    ("9. LE MÊME BRAS, sous une branche qui AVOUE",
     'pub(crate) async fn r9() -> Json<Value> {\n'
     '    let v = read_with_watchdog(&db, json!({ "rows": [], "error": "x" }), move |conn| {\n'
     '        let mut stmt = conn.prepare("SELECT a FROM t").unwrap();\n'
     '        let out: Vec<Value> = match stmt.query_map([], |r| Ok(json!({ "a": r.get::<_, i64>(0)? }))) {\n'
     '            Ok(r) => r.flatten().collect(),\n'
     '            Err(_) => Vec::new(),\n'
     '        };\n'
     '        json!({ "rows": out, "error": "liste possiblement TRONQUÉE : parcours non soldé" })\n'
     '    });\n    Json(v)\n}\n', None),
    ("10. LE MÊME BRAS, mais le scrutateur N'EST PAS une lecture",
     'pub(crate) async fn r10() -> Json<Value> {\n'
     '    let v = read_with_watchdog(&db, json!({ "rows": [], "error": "x" }), move |conn| {\n'
     '        let n: i64 = conn.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))?;\n'
     '        let out: Vec<Value> = match charger_le_cache(&n) {\n'
     '            Ok(r) => r.flatten().collect(),\n'
     '            Err(_) => Vec::new(),\n'
     '        };\n'
     '        json!({ "n": n, "rows": out })\n    });\n    Json(v)\n}\n', None),
    ("11. LE MÊME BRAS, EN COMMENTAIRE — il ne doit JAMAIS compter",
     'pub(crate) async fn r11() -> Json<Value> {\n'
     '    let v = read_with_watchdog(&db, json!({ "rows": [], "error": "x" }), move |conn| {\n'
     '        // let out: Vec<Value> = match stmt.query_map([], f) {\n'
     '        //     Ok(r) => r.flatten().collect(),\n'
     '        //     Err(_) => Vec::new(),\n'
     '        // };\n'
     '        let n: i64 = conn.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))?;\n'
     '        json!({ "n": n })\n    });\n    Json(v)\n}\n', None),
    # --- LES QUATRE SUIVANTS TIENNENT LA FORME AJOUTÉE PAR `P10.7-h` : `if let Ok(..) = <lecture>`
    # SANS `else`. Le 12 accuse ; le 13 est le MÊME texte AVEC un `else` (la présence de la branche,
    # et elle seule, inverse le verdict) ; le 14 est le MÊME `if let` dont le SCRUTATEUR n'est pas une
    # lecture — sans lui, la jambe B lirait les `if let` de tout l'arbre et accuserait à tort, la
    # faute que ce dépôt tient pour PIRE que l'angle mort ; le 15 met la forme EN COMMENTAIRE.
    ("12. UN `if let Ok(..)` SANS `else` sur une lecture : le chemin d'échec n'est écrit nulle part",
     'pub(crate) async fn r12() -> Json<Value> {\n'
     '    let v = read_with_watchdog(&db, json!({ "rows": [], "error": "x" }), move |conn| {\n'
     '        let mut out: Vec<Value> = Vec::new();\n'
     '        if let Ok(mut s) = conn.prepare("SELECT a FROM t") {\n'
     '            if let Ok(rows) = s.query_map([], |r| r.get::<_, i64>(0)) {\n'
     '                for a in rows.flatten() { out.push(json!({ "a": a })); }\n'
     '            }\n        }\n'
     '        json!({ "rows": out })\n    });\n    Json(v)\n}\n', "B"),
    ("13. LE MÊME, mais CHAQUE `if let` a son `else` : la branche existe",
     'pub(crate) async fn r13() -> Json<Value> {\n'
     '    let v = read_with_watchdog(&db, json!({ "rows": [], "error": "x" }), move |conn| {\n'
     '        let mut out: Vec<Value> = Vec::new();\n'
     '        if let Ok(mut s) = conn.prepare("SELECT a FROM t") {\n'
     '            if let Ok(rows) = s.query_map([], |r| r.get::<_, i64>(0)) {\n'
     '                for a in rows.flatten() { out.push(json!({ "a": a })); }\n'
     '            } else { out.push(json!({ "coupe": "parcours NON COMMENCÉ" })); }\n'
     '        } else { out.push(json!({ "coupe": "énoncé NON PRÉPARÉ" })); }\n'
     '        json!({ "rows": out })\n    });\n    Json(v)\n}\n', None),
    ("14. LE MÊME `if let` sans `else`, mais le SCRUTATEUR N'EST PAS une lecture",
     'pub(crate) async fn r14() -> Json<Value> {\n'
     '    let v = read_with_watchdog(&db, json!({ "rows": [], "error": "x" }), move |conn| {\n'
     '        let n: i64 = conn.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))?;\n'
     '        let mut out: Vec<Value> = Vec::new();\n'
     '        if let Ok(c) = charger_le_cache(&n) { out.push(c); }\n'
     '        json!({ "n": n, "rows": out })\n    });\n    Json(v)\n}\n', None),
    ("15. LE MÊME `if let` sans `else`, EN COMMENTAIRE — il ne doit JAMAIS compter",
     'pub(crate) async fn r15() -> Json<Value> {\n'
     '    let v = read_with_watchdog(&db, json!({ "rows": [], "error": "x" }), move |conn| {\n'
     '        // if let Ok(mut s) = conn.prepare("SELECT a FROM t") {\n'
     '        //     if let Ok(rows) = s.query_map([], f) { for a in rows.flatten() {} }\n'
     '        // }\n'
     '        let n: i64 = conn.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))?;\n'
     '        json!({ "n": n })\n    });\n    Json(v)\n}\n', None),
    # --- LES TROIS SUIVANTS TIENNENT LA VOIE D'ÉCRITURE (`P10.7-l`). Le 16 et le 17 sont une PAIRE
    # DISCRIMINANTE : la fermeture est le MÊME texte, seul le TYPE DE RETOUR du gestionnaire change, et
    # le verdict doit s'inverser. Sans le 17, la garde accuserait les trois sites FAIL-CLOSED de l'arbre
    # (une lecture ratée y rend `false` -> 404) et les deux qui ne servent AUCUN corps — cinq rouges
    # qu'aucun aveu ne pourrait refermer, puisqu'un `-> StatusCode` n'a pas de corps où poser `error`.
    ("16. LA VOIE D'ÉCRITURE : une fermeture qui AVALE, sous un gestionnaire qui sert un CORPS",
     ECRITURE_SOURDE_CORPS, "B"),
    ("17. LA MÊME fermeture, sous un gestionnaire qui rend un `StatusCode` NU : aucun corps servi",
     ECRITURE_SOURDE_STATUT, None),
    ("18. LA MÊME fermeture servant un corps, mais qui AVOUE", ECRITURE_QUI_AVOUE, None),
    ("19. UNE ÉCRITURE dont la fermeture ne cache RIEN : le deuxième argument est `&au`, pas un défaut",
     ECRITURE_PROPRE, None),
    # --- LES SIX SUIVANTS TIENNENT L'ÉLARGISSEMENT DU MOTIF DE LIAISON (`P10.20-s`, 2026-09-19). Le
    # numéro 20 n'est pas libre : c'est le témoin de l'ASYMÉTRIE DES JAMBES, écrit dans
    # `valider_instrument` et cité deux fois plus haut ; la suite reprend donc à 21.
    # Le 21 et le 22 sont une PAIRE DISCRIMINANTE — le `if let` y lie le MÊME tuple sur la MÊME
    # lecture, seule la présence de l'`else` change, et le verdict doit s'inverser. Le 24 tient le
    # COMMENTAIRE, le 25 tient l'exclusion qui manquait (le LITTÉRAL DE CHAÎNE), et le 26 tient le
    # motif IMBRIQUÉ, la seule forme que l'arbre porte réellement hors de la population (`rollups.rs`).
    # LE 23 EST DÉCLARÉ NON PROUVÉ, et il est gardé pour ce qu'il DIT plutôt que pour ce qu'il tue :
    # aucune des mutations jouées sur ce lot ne le fait rougir, parce qu'un tuple écrit dans un BRAS
    # n'est de toute façon pas suivi (`BRAS_LIANT` reste étroit, c'est déclaré plus bas) et parce que
    # son bras d'erreur pose la clé d'aveu. Il est ici pour qu'un `match` qui PARLE reste, par écrit,
    # une forme que cette garde n'accuse pas ; un instrument qui prétend éprouver ce qu'il n'atteint
    # pas est pire que rien, et c'est pourquoi la limite est dite au lieu d'être comptée.
    ("21. UNE LIAISON PAR TUPLE sans `else` sur une lecture : le motif étroit ne la voyait pas",
     'pub(crate) async fn r21() -> Json<Value> {\n'
     '    let v = read_with_watchdog(&db, json!({ "rows": [], "error": "x" }), move |conn| {\n'
     '        let mut out = json!({ "rows": [] });\n'
     '        if let Ok((kind, target, dry)) = conn.query_row("SELECT kind, target, dry_run FROM action WHERE id=?1",\n'
     '            params![id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)? != 0))) {\n'
     '            out = json!({ "kind": kind, "target": target, "dry": dry });\n'
     '        }\n'
     '        out\n    });\n    Json(v)\n}\n', "B"),
    ("22. LE MÊME TUPLE, AVEC son `else` : la branche existe, et elle seule inverse le verdict",
     'pub(crate) async fn r22() -> Json<Value> {\n'
     '    let v = read_with_watchdog(&db, json!({ "rows": [], "error": "x" }), move |conn| {\n'
     '        let mut out = json!({ "rows": [] });\n'
     '        if let Ok((kind, target, dry)) = conn.query_row("SELECT kind, target, dry_run FROM action WHERE id=?1",\n'
     '            params![id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)? != 0))) {\n'
     '            out = json!({ "kind": kind, "target": target, "dry": dry });\n'
     '        } else { out = json!({ "coupe": "riposte NON RELUE" }); }\n'
     '        out\n    });\n    Json(v)\n}\n', None),
    ("23. LE MÊME TUPLE sous un `match` dont le bras d'erreur PARLE",
     'pub(crate) async fn r23() -> Json<Value> {\n'
     '    let v = read_with_watchdog(&db, json!({ "rows": [], "error": "x" }), move |conn| {\n'
     '        match conn.query_row("SELECT kind, target FROM action WHERE id=?1", params![id],\n'
     '            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))) {\n'
     '            Ok((kind, target)) => json!({ "kind": kind, "target": target }),\n'
     '            Err(e) => json!({ "error": format!("riposte NON LUE : {e}") }),\n'
     '        }\n    });\n    Json(v)\n}\n', None),
    ("24. LE MÊME TUPLE, EN COMMENTAIRE — il ne doit JAMAIS compter",
     'pub(crate) async fn r24() -> Json<Value> {\n'
     '    let v = read_with_watchdog(&db, json!({ "rows": [], "error": "x" }), move |conn| {\n'
     '        // if let Ok((kind, target, dry)) = conn.query_row("SELECT k, t, d FROM action", params![id], f) {\n'
     '        //     out = json!({ "kind": kind });\n'
     '        // }\n'
     '        json!({ "ok": true })\n    });\n    Json(v)\n}\n', None),
    ("25. LE MÊME TUPLE, DANS UN LITTÉRAL DE CHAÎNE — une forme CITÉE n'est pas une lecture",
     'pub(crate) async fn r25() -> Json<Value> {\n'
     '    let v = read_with_watchdog(&db, json!({ "rows": [], "error": "x" }), move |conn| {\n'
     '        let aide = "forme fautive : if let Ok((a, b)) = conn.query_row(SELECT a, b FROM t) { .. } sans else";\n'
     '        json!({ "aide": aide })\n    });\n    Json(v)\n}\n', None),
    ("26. UN MOTIF IMBRIQUÉ `Ok(Some(t))` sans `else` — la seule forme que l'arbre porte vraiment",
     'pub(crate) async fn r26() -> Json<Value> {\n'
     '    let v = read_with_watchdog(&db, json!({ "rows": [], "error": "x" }), move |conn| {\n'
     '        let mut out = json!({ "rows": [] });\n'
     '        if let Ok(Some(t)) = conn.query_row("SELECT MIN(ts) FROM event", [], |r| r.get::<_, Option<i64>>(0)) {\n'
     '            out = json!({ "depuis": t });\n'
     '        }\n'
     '        out\n    });\n    Json(v)\n}\n', "B"),
]

# La dernière ligne est du COMMENTAIRE Rust, et l'arbre en porte une du même genre
# (`daemon/src/handlers/admin_ui.rs`) : mesuré le 2026-08-30, les handlers portent 20 occurrences du
# mot `with_write` pour 19 sites — la vingtième est cette mention-là.
COMMENTAIRE_QUI_NOMME = (
    "// read_with_watchdog = pool read-only + interruption anti-scan-trop-long\n"
    "/* run_query(&db, &sql) y vivait avant P10.7-e */\n"
    "//! la closure passe par read_with_watchdog(&db, json!({}), |conn| lit(conn))\n"
    "// la mutation passe par with_write(&st, &au, |conn| ecrit(conn)) depuis le refactor T1\n"
)


def resumer_les_formes(fautives):
    """`region` : forme ×n (ex. `…`) · … — CHAQUE forme rencontrée est nommée avec un exemple, pour
    qu'aucune cause vraie ne cesse d'être imprimée quand une autre entre dans le champ."""
    morceaux = []
    for nom_corps, av in fautives:
        par_forme = {}
        for _ligne, chaine, forme in av:
            par_forme.setdefault(forme, []).append(chaine)
        detail = ", ".join(f"{f} ×{len(v)} (ex. `{v[0][:40]}`)" for f, v in sorted(par_forme.items()))
        morceaux.append(f"`{nom_corps}` {detail}")
    return " · ".join(morceaux)


def analyser(chemin, texte, defs, constructeurs, aveux, aveux_du_lecteur=None):
    """Rend (sites, accusations) pour UN fichier. `aveux` recueille les pertes de lecture DE CETTE GARDE
    (appel non apparié, portée introuvable) ; `aveux_du_lecteur` recueille celles du LECTEUR PARTAGÉ
    (`P10.20-d`) — deux causes distinctes, deux remèdes distincts, jamais mélangées dans un même sac."""
    journal = []
    brut = sans_commentaires_rust(texte, journal)
    if journal and aveux_du_lecteur is not None:
        aveux_du_lecteur[os.path.relpath(chemin, RACINE)] = [
            f"ligne {texte.count(chr(10), 0, o) + 1} : {m}" for m, o in journal]
    code = coupe_tests(brut)
    fns = fonctions(code)
    sites, accusations = [], []
    for m in APPEL.finditer(code):
        voie = m.group(1)
        ligne = code.count("\n", 0, m.start()) + 1
        ou = f"{os.path.relpath(chemin, RACINE)}:{ligne}"
        tranches, fin = arguments(code, m.end() - 1)
        if tranches is None:
            aveux.append(f"{ou} — parenthèse d'appel non appariée")
            continue
        englobantes = sorted([f for f in fns if f[2] < m.start() < f[3]], key=lambda f: f[3] - f[2])
        if not englobantes:
            aveux.append(f"{ou} — appel hors de toute fonction : la portée est introuvable")
            continue
        nom_fn, sig, pdeb, pfin = englobantes[0]
        sites.append((ou, voie, nom_fn))
        if voie in VOIES_FERMETURE:
            if len(tranches) < 3:
                aveux.append(f"{ou} — `{voie}` lu avec {len(tranches)} argument(s) au lieu de 3")
                continue
            # --- JAMBE A : le défaut, s'il s'écoule vers une réponse de la MÊME fonction.
            # ELLE NE JUGE QUE LA VOIE GARDÉE, ET LA RAISON EST MESURÉE, PAS COMMODE (2026-08-30).
            # Étendue à `read_with`, elle accuse DIX sites dont QUATRE avouent déjà, dans un
            # vocabulaire TYPÉ que le reconnaisseur d'aveu (la clé `error`) ne lit pas :
            # `query.rs:1100/1860` rendent `(RollupCoverage::unproven(), DimRollupCoverage::unproven())`
            # et `query.rs:1132/1892` rendent `rr.cap.sans_base()` — trois constructeurs dont le corps
            # bâtit une variante « rien d'établi » et dont l'arbre dit lui-même qu'ils sont des AVEUX.
            # Quatre accusations FAUSSES sur dix, c'est le défaut que ce dépôt tient pour PIRE que
            # l'angle mort qu'il comblerait. [ÉTAT DU 2026-08-30 ; DEPUIS LE 2026-09-08 le vocabulaire
            # lit ces constructeurs (doc `AVEU`), les quatre fausses accusations sont tombées, les six
            # vraies ont été corrigées, et `read_with` est jugé : `VOIES_JUGEES_PAR_A`.] Et le remède évident — n'accuser qu'un défaut qui est
            # lui-même un corps servi — RÉTRÉCIRAIT un canal existant : il ferait taire trois
            # accusations vraies de la voie gardée (`compliance.rs:341` rend une `BTreeMap::new()`,
            # `fleet.rs:253/276` un `(Vec::new(), false, false)`). La jambe A reste donc où son
            # vocabulaire d'aveu est vrai ; l'élargir demande d'abord d'élargir CE vocabulaire, et
            # c'est un lot à part. La jambe B, elle, n'a pas ce problème : elle juge la CLOSURE, qui
            # est le même code sur les deux voies — les cinq accusations qu'elle gagne sur `read_with`
            # ont été relues une à une le 2026-08-30, et les cinq sont vraies.
            # SUR LA VOIE D'ÉCRITURE, LE DEUXIÈME ARGUMENT N'EST PAS UN DÉFAUT — c'est `&au`, l'identité
            # de l'appelant. La jambe A ne doit JAMAIS le lire : elle accuserait « le défaut `&au` n'avoue
            # pas », une phrase qui ne veut rien dire. Le `voie == VOIE_GARDEE` ci-dessous le garantit
            # déjà ; le témoin 20 le tient dans le temps, parce qu'une extension future de la jambe A est
            # exactement ce qui rouvrirait ce trou.
            defaut = code[tranches[1][0]:tranches[1][1]].strip()
            if voie in VOIES_JUGEES_PAR_A and RETOUR_REPONSE.search(sig) and not porte_un_aveu(defaut, constructeurs):
                accusations.append(("A", ou, nom_fn,
                                    f"le défaut `{re.sub(r'\\s+', ' ', defaut)[:70]}` est servi par une "
                                    f"fonction qui rend une réponse, et il n'avoue pas"))
            # --- JAMBE B : la closure, et ELLE SEULE (le défaut est hors de la région).
            # UNE accusation par SITE D'APPEL — le compte n'a pas changé de grain — mais la phrase
            # les AGRÈGE au lieu de s'arrêter à la première région fautive. La boucle s'arrêtait
            # avant ; mesuré le 2026-08-30, l'arrêt faisait TAIRE une cause vraie dès qu'une
            # écriture plus précoce en apparaissait une autre : sur `sources.rs:357`, l'entrée de la
            # forme sans branche dans la closure masquait le `ok().flatten()` de `pipeline_is_fresh`,
            # nommé la veille. Le site restait accusé, donc aucun code de sortie ne l'aurait dit —
            # c'est exactement la perte silencieuse que ce dépôt refuse.
            #
            # SUR LA VOIE D'ÉCRITURE, ET LÀ SEULEMENT, LA JAMBE B EXIGE UN CORPS SERVI. La règle de ce
            # fichier est qu'une lecture non faite ne soit pas servie comme un FAIT ; encore faut-il
            # qu'un fait soit SERVI. Sur `read_with*`, la valeur de la fermeture EST le corps rendu (le
            # deuxième argument est lui-même un corps de repli) : la question ne se pose pas. Sur
            # `with_write`, elle se pose, et la mesure du 2026-08-30 y répond : des DIX sites accusés
            # sans ce contrôle, CINQ servent un corps, TROIS sont FAIL-CLOSED (une lecture ratée y rend
            # `false` -> `StatusCode::NOT_FOUND` : l'absence est un REFUS, ce que la garde réclame
            # DÉJÀ) et DEUX ne servent aucun corps (un recompute sauté, un maillon de journal au
            # `prev_hash` vide) — de vrais défauts, mais dont l'aveu n'a nulle part où s'écrire, donc un
            # rouge qu'aucun geste ne refermerait. Le critère est celui de la jambe A, DÉJÀ écrit ici,
            # et il sépare EXACTEMENT les cinq des cinq. CE QU'IL NE TIENT PAS est déclaré plus bas :
            # un `-> StatusCode` qui rend 204 alors qu'une lecture n'a pas eu lieu (`sla_policy_upsert`)
            # lui échappe. Il SOUS-accuse ; il n'accuse jamais à tort.
            if voie == VOIE_ECRITURE and not RETOUR_REPONSE.search(sig):
                continue
            fautives = []
            for nom_corps, corps in corps_de_la_closure(code, tranches, fin, defs):
                av = lectures_avalees(corps)
                if av and not porte_un_aveu(corps, constructeurs):
                    fautives.append((nom_corps, av))
            if fautives:
                total = sum(len(av) for _n, av in fautives)
                accusations.append(("B", ou, nom_fn,
                                    f"{total} lecture(s) de lignes avalée(s) sans qu'aucune branche "
                                    f"n'y construise un aveu — " + resumer_les_formes(fautives)))
        else:
            verdict, raison = juger_la_cause(code, m.start(), fin, pdeb, pfin, sig, constructeurs)
            if verdict == JETE:
                accusations.append(("Q", ou, nom_fn, f"{raison} — un refus du moteur devient une absence"))
            elif verdict == NON_CLASSE:
                accusations.append(("?", ou, nom_fn, raison))
    return sites, accusations


def ecarts_contre_les_ensembles(a_par_jambe, admis_par_jambe=None):
    """Les écarts entre les accusations du jour et les ensembles nommés, JUGÉS DANS LES DEUX SENS —
    rendus comme des phrases, jamais imprimés ici.

    POURQUOI CE JUGEMENT EST UNE FONCTION ET NON UNE BOUCLE DANS `main` (`P10.20-s`, 2026-09-19) :
    tant qu'il vivait dans `main`, RIEN ne l'éprouvait. Sur un arbre où les accusations coïncident
    exactement avec les ensembles — c'est le cas depuis le lot 102 —, le débrancher entièrement laisse
    la garde VERTE À SORTIE IDENTIQUE, et le canal qui refuse les formes neuves disparaîtrait sans
    qu'aucun code de sortie ne le dise. Extrait, il est appelé par deux témoins fabriqués (une
    accusation hors de l'ensemble, une entrée sans accusation) qui le tuent dans les deux sens.

    `admis_par_jambe` est l'ensemble jugé ; il est PASSÉ pour que les témoins n'aient pas à toucher au
    `SITES_ADMIS` réel, et le défaut reste celui de ce fichier."""
    if admis_par_jambe is None:
        admis_par_jambe = SITES_ADMIS
    messages = []
    for jambe in ("A", "B", "Q"):
        vus = {}
        for ou, fn, _raison in a_par_jambe.get(jambe, []):
            cle = (ou.rsplit(":", 1)[0], fn)
            vus[cle] = vus.get(cle, 0) + 1
        admis = admis_par_jambe[jambe]
        for (fichier, fn), n in sorted(vus.items()):
            if n > admis.get((fichier, fn), 0):
                messages.append(
                    f"::error file={fichier}::[{jambe}] FORME NEUVE — `{fn}` porte {n} accusation(s) pour "
                    f"{admis.get((fichier, fn), 0)} admise(s) dans SITES_ADMIS[\"{jambe}\"]. La forme doit "
                    "avouer, ou entrer dans l'ensemble AVEC sa raison — jamais en silence.")
        for (fichier, fn), n in sorted(admis.items()):
            if vus.get((fichier, fn), 0) < n:
                messages.append(
                    f"::error file={fichier}::[{jambe}] EXEMPTION SANS OBJET — `{fn}` est admis {n} fois dans "
                    f"SITES_ADMIS[\"{jambe}\"] et n'est accusé que {vus.get((fichier, fn), 0)} fois : le site "
                    "avoue désormais, ou n'existe plus, ou cette garde a cessé de le voir. Dans les trois cas, "
                    "retirer l'entrée en disant lequel — un canal qui rétrécit ne doit pas passer pour un défaut fermé.")
    return messages


def valider_instrument(defs, constructeurs):
    errs = []
    for nom, src, attendu in MUTANTS:
        _s, acc = analyser("/mutant.rs", src, defs, constructeurs, [])
        jambes = {j for j, *_ in acc if j != "?"}
        if attendu is None and jambes:
            errs.append(f"témoin « {nom} » : accusé sur {sorted(jambes)} alors qu'il est HONNÊTE — "
                        "la garde accuse une forme qui avoue déjà")
        if attendu is not None and attendu not in jambes:
            errs.append(f"témoin « {nom} » : NON accusé (jambes vues : {sorted(jambes) or 'aucune'}), "
                        f"attendu la jambe {attendu} — la garde laisse passer le défaut qu'elle nomme")
    # LE COMMENTAIRE QUI NOMME LA FONCTION N'EST JAMAIS UN SITE.
    brut = [("/typé.rs", "/// AVEU : rien n\'est établi ici.\n    pub(crate) fn rien_d_etabli() -> Self { Self(Etat::Rien) }\n"
                          "/// Pas un aveu.\n    pub(crate) fn plein() -> Self { Self(Etat::Plein) }\n")]
    typés = constructeurs_avoues_par_leur_doc(brut)
    if typés != {"rien_d_etabli"}:
        errs.append(f"témoin du VOCABULAIRE TYPÉ : {sorted(typés)} au lieu de ['rien_d_etabli'] — la doc `AVEU` "
                    "n\'est plus lue, ou une doc qui n\'avoue pas est prise pour un aveu")
    for defaut, attendu in (("Portee::rien_d_etabli()", None), ("Portee::plein()", "A")):
        _s, acc = analyser("/typé_voie.rs", "fn f() -> Json<Value> { Json(read_with_watchdog(&d, " + defaut + ", |c| lit(c))) }",
                           defs, constructeurs | typés, [])
        jambes = {j for j, *_ in acc if j != "?"}
        if (attendu is None and "A" in jambes) or (attendu == "A" and "A" not in jambes):
            errs.append(f"témoin du DÉFAUT TYPÉ « {defaut} » : jambes vues {sorted(jambes) or 'aucune'}, attendu "
                        f"{attendu or 'aucune accusation'} — un aveu porté par le type ne vaut plus un aveu porté par une clé")
    s, _a = analyser("/commentaire.rs", COMMENTAIRE_QUI_NOMME, defs, constructeurs, [])
    if s:
        errs.append(f"témoin du COMMENTAIRE : {len(s)} site(s) comptés dans un texte qui n'est fait que "
                    "de commentaires — le dépouillement ne retire plus les commentaires")
    # Le dépouillement doit, dans l'autre sens, laisser le CODE intact.
    s, _a = analyser("/code.rs", "fn f() -> Json<Value> { Json(read_with_watchdog(&d, json!({}), |c| lit(c))) }",
                     defs, constructeurs, [])
    if len(s) != 1:
        errs.append(f"témoin INVERSE du dépouillement : {len(s)} site(s) au lieu de 1 — le lecteur a "
                    "cessé de voir un appel réel")
    # LA FORME AJOUTÉE, AU NIVEAU DE L'UNITÉ ET DANS LES DEUX SENS. Le mutant 8 pourrait passer pour
    # une raison ÉTRANGÈRE (un corps voisin ramassé par la région de la closure) ; ces témoins-ci
    # n'interrogent que le lecteur de chaînes, sans région ni constructeur.
    bras = ('let v: Vec<Value> = match stmt.query_map([], f) { Ok(r) => r.flatten().collect(), '
            'Err(_) => Vec::new() };')
    if not lectures_avalees(bras):
        errs.append("témoin du BRAS (direct) : `match ..query_map(..) { Ok(r) => r.flatten() .. }` "
                    "n'est plus vu comme un avalement — l'angle mort de `P10.7-g` est rouvert")
    if lectures_avalees(bras.replace("stmt.query_map([], f)", "charger_le_cache(&n)")):
        errs.append("témoin du SCRUTATEUR (négatif) : le MÊME bras est compté alors que le scrutateur "
                    "n'est PAS une lecture — la jambe B accuserait les bras de tout `match` de l'arbre")
    # LE CONTRÔLE DU SCRUTATEUR, ÉPROUVÉ À SON PROPRE NIVEAU — ET C'EST UNE CORRECTION D'INSTRUMENT.
    # Le témoin ci-dessus, joué SEUL, était FAUX : il est vert par construction. Son entrée ne
    # contient aucune lecture, donc `lectures_avalees` n'entre jamais dans sa boucle et le contrôle
    # qu'il prétend éprouver n'est pas même appelé. MESURÉ le 2026-08-30 : en forçant
    # `scrutateur_est_la_lecture` à rendre TOUJOURS vrai, ce témoin restait VERT. Il est conservé —
    # il tue bien une implémentation qui fouillerait les bras de TOUT `match` de la région — mais il
    # ne prouve pas ce que son nom annonce, et les deux témoins qui suivent, eux, le prouvent : joués
    # contre la même mutation, ils rougissent.
    scrut = "let v: Vec<Value> = match stmt.query_map([], f) {"
    if not scrutateur_est_la_lecture(scrut, scrut.index(".query_map")):
        errs.append("témoin du SCRUTATEUR (positif, au niveau du prédicat) : `match stmt.query_map(..)` "
                    "n'est plus reconnu comme un `match` dont la lecture EST le scrutateur")
    etranger = 'let m = match mode { 0 => "a", _ => "b" };\nlet n = conn.query_row(sql, [], f);'
    if scrutateur_est_la_lecture(etranger, etranger.index(".query_row")):
        errs.append("témoin du SCRUTATEUR (négatif, au niveau du prédicat) : un `match` ÉTRANGER, clos "
                    "avant la lecture, est pris pour le scrutateur — la jambe B lirait les bras d'un "
                    "`match` qui ne juge pas cette lecture")
    if lectures_avalees(bras.replace("r.flatten().collect()", "r.collect::<Result<Vec<_>>>()?")):
        errs.append("témoin du BRAS (négatif) : un bras qui SOLDE son parcours est compté comme un "
                    "avalement — la jambe B accuserait la forme même qu'elle réclame")
    # UN SEUL AVALEMENT NE PEUT PAS ÊTRE COMPTÉ DEUX FOIS. `Ok(mut s) => s.query_map(..).unwrap_or_
    # default()` est déjà vu par la chaîne DIRECTE sur `query_map` ; si le bras le recomptait, le
    # cliquet monterait sans qu'aucun défaut neuf n'existe — une hausse qui n'apprendrait rien.
    double = ('let v = match conn.prepare(sql) { Ok(mut s) => s.query_map([], f).map(|x| x.flatten()'
              '.collect()).unwrap_or_default(), Err(_) => Vec::new() };')
    if len(lectures_avalees(double)) != 1:
        errs.append(f"témoin du DOUBLE COMPTE : {len(lectures_avalees(double))} avalement(s) relevé(s) "
                    "au lieu de 1 sur un site qui n'en porte qu'un")
    # LA FORME SANS BRANCHE, AU NIVEAU DE L'UNITÉ, ET DANS LES DEUX SENS. Comme pour le bras, les
    # mutants pourraient passer pour une raison ÉTRANGÈRE ; ces témoins-ci n'interrogent que le
    # lecteur de chaînes, sans région ni constructeur.
    sans_b = ("let mut o = Vec::new(); if let Ok(rows) = stmt.query_map([], f) "
              "{ for x in rows.flatten() { o.push(x); } }")
    if not lectures_avalees(sans_b):
        errs.append("témoin SANS BRANCHE (direct) : `if let Ok(rows) = ..query_map(..) { .. }` sans "
                    "`else` n'est plus vu comme un avalement — l'angle mort de `P10.7-h` est rouvert")
    avec_b = sans_b + " else { o.push(json!({ \"error\": \"NON LU\" })); }"
    if lectures_avalees(avec_b):
        errs.append("témoin SANS BRANCHE (négatif, `else` présent) : le MÊME `if let` est compté "
                    "alors qu'une branche d'échec EXISTE — la jambe B accuserait la forme qu'elle "
                    "réclame, et elle dirait le contraire de la jambe Q sur le même texte")
    # LE CONTRÔLE DU SCRUTATEUR DE LA FORME NEUVE, ÉPROUVÉ À SON PROPRE NIVEAU — la correction
    # d'instrument du matin est appliquée d'emblée ici : un témoin écrit au niveau de
    # `lectures_avalees` sur une entrée SANS lecture serait vert par construction.
    sif = "if let Ok(mut s) = conn.prepare(sql) {"
    if not if_let_est_le_scrutateur(sif, sif.index(".prepare")):
        errs.append("témoin du SCRUTATEUR `if let` (positif, au niveau du prédicat) : "
                    "`if let Ok(mut s) = conn.prepare(..)` n'est plus reconnu comme liant la lecture")
    etr_if = "if let Ok(c) = charger_le_cache(&n) { o.push(c); }\nlet n = conn.query_row(sql, [], f);"
    if if_let_est_le_scrutateur(etr_if, etr_if.index(".query_row")):
        errs.append("témoin du SCRUTATEUR `if let` (négatif, au niveau du prédicat) : un `if let` "
                    "ÉTRANGER, clos avant la lecture, est pris pour celui qui la lie — la jambe B "
                    "déclarerait « sans branche » des lectures qu'aucun `if let` ne porte")
    # UNE LECTURE NE COMPTE QU'UNE FOIS, ET UNE IMBRICATION EN PORTE DEUX (l'énoncé préparé ET son
    # parcours) : ni plus — un double compte ferait monter le cliquet sans qu'aucun défaut neuf
    # n'existe — ni moins — une lecture perdue rendrait un compte amputé en vert.
    imbrique = ("if let Ok(mut s) = conn.prepare(sql) { if let Ok(rows) = s.query_map([], f) "
                "{ for x in rows.flatten() { o.push(x); } } }")
    if len(lectures_avalees(imbrique)) != 2:
        errs.append(f"témoin de l'IMBRICATION : {len(lectures_avalees(imbrique))} avalement(s) "
                    "relevé(s) au lieu de 2 sur un site qui porte DEUX lectures sans branche")
    # LES TROIS ÉCRITURES SONT DISTINGUÉES DANS LA PHRASE. Sans cela, une écriture en masquerait une
    # autre dans le journal et une cause vraie cesserait d'être nommée sans qu'aucun code de sortie
    # ne le dise (mesuré le 2026-08-30 sur `sources.rs:357`).
    formes = {f for _l, _c, f in lectures_avalees(imbrique)
              + lectures_avalees("let v = stmt.query_map([], f).flatten().collect();")}
    if formes != {"sans branche d'échec", "chaîne directe"}:
        errs.append(f"témoin des FORMES : {sorted(formes)} au lieu des deux écritures attendues — le "
                    "journal ne distingue plus les causes qu'il imprime")
    # DEUX RÉGIONS FAUTIVES SONT NOMMÉES TOUTES LES DEUX, EN UNE SEULE ACCUSATION, ET LEURS FORMES
    # AVEC. La boucle de la jambe B s'ARRÊTAIT à la première région fautive ; mesuré le 2026-08-30,
    # l'arrêt a fait TAIRE une cause vraie (`sources.rs:357` : l'entrée de la forme sans branche dans
    # la closure masquait le `ok().flatten()` de `pipeline_is_fresh`, nommé la veille) sans qu'aucun
    # code de sortie ne le dise — le site restait accusé, le compte restait juste.
    # LA FONCTION APPELÉE EST FABRIQUÉE ICI, PAS PRISE SUR L'ARBRE. Adosser ce témoin à une vraie
    # fonction fautive du démon en ferait une RANÇON : il rougirait le jour où elle est réparée, et
    # aucun geste ne pourrait le refermer. `defs` est donc AUGMENTÉ d'une définition inventée.
    defs_fab = dict(defs)
    defs_fab["aide_fabriquee"] = [("/fabrique.rs", 1, '{ let n: Option<i64> = conn.query_row('
                                  '"SELECT MAX(ts) FROM t", [], |r| r.get(0)).ok().flatten(); n }',
                                  "(conn: &Connection) -> Option<i64>")]
    src_agr = ('pub(crate) async fn r16() -> Json<Value> {\n'
               '    let v = read_with_watchdog(&db, json!({ "rows": [], "error": "x" }), move |conn| {\n'
               '        let mut out: Vec<Value> = Vec::new();\n'
               '        if let Ok(mut s) = conn.prepare("SELECT a FROM t") {\n'
               '            if let Ok(rows) = s.query_map([], |r| r.get::<_, i64>(0)) {\n'
               '                for a in rows.flatten() { out.push(json!({ "a": a })); }\n'
               '            }\n        }\n'
               '        json!({ "rows": out, "last": aide_fabriquee(conn) })\n    });\n    Json(v)\n}\n')
    _s, acc_agr = analyser("/agregation.rs", src_agr, defs_fab, constructeurs, [])
    raisons = [r for j, _o, _f, r in acc_agr if j == "B"]
    if len(raisons) != 1:
        errs.append(f"témoin de l'AGRÉGATION (grain) : {len(raisons)} accusation(s) B pour UN site "
                    "d'appel — le cliquet ne compte plus des sites, et sa valeur ne veut plus rien dire")
    elif not all(t in raisons[0] for t in ("<closure>", "aide_fabriquee")):
        errs.append(f"témoin de l'AGRÉGATION (régions) : « {raisons[0][:150]} » ne nomme pas les DEUX "
                    "régions fautives — la jambe s'arrête à la première et une cause vraie cesse "
                    "d'être imprimée sans qu'aucun code de sortie ne le dise")
    elif not all(t in raisons[0] for t in ("sans branche d'échec", "chaîne directe")):
        errs.append(f"témoin de l'AGRÉGATION (formes) : « {raisons[0][:150]} » ne distingue plus les "
                    "écritures — deux causes de nature différente sont rendues indiscernables")
    # LA FERMETURE ÉCRITE EN CHEMIN DE FONCTION NU (`P10.7-j`), DANS LES TROIS SENS. Les définitions
    # sont FABRIQUÉES ICI, jamais prises sur l'arbre : adosser ces témoins à `rule_compliance_map` en
    # ferait une RANÇON — ils rougiraient le jour où il est réparé, et aucun geste ne pourrait les
    # refermer. Le troisième témoin est celui qui manque le plus souvent : un nom SANS définition ne
    # doit ni accuser ni faire tomber le lecteur, sinon la garde inventerait une région qu'elle n'a
    # jamais lue. CHACUN A ÉTÉ ÉPROUVÉ PAR MUTATION le 2026-08-30, et la phrase dit ce qui a été
    # MESURÉ, pas ce qui serait joli : débrancher la résolution du chemin nu rend le PREMIER rouge (et
    # avec lui le témoin de prédicat) ; chercher l'aveu dans le texte de la fermeture au lieu de la
    # RÉGION RÉSOLUE rend le DEUXIÈME rouge — et il est le SEUL témoin de tout ce fichier à tuer
    # cette mutation-là, les autres ne jugeant que des régions `<closure>` (RE-MESURÉ le 2026-08-30 après
    # l'entrée de la voie d'écriture : aucun des témoins neufs ne la tue) ; faire INVENTER un corps à un nom
    # inconnu rend le TROISIÈME rouge.
    defs_fab["fermeture_nue_sourde"] = [("/fabrique.rs", 1,
        '{ let mut o = Vec::new(); if let Ok(mut s) = conn.prepare("SELECT a FROM t") '
        '{ if let Ok(rows) = s.query_map([], f) { for a in rows.flatten() { o.push(a); } } } '
        'json!({ "o": o }) }', "(conn: &Connection) -> Value")]
    defs_fab["fermeture_nue_qui_avoue"] = [("/fabrique.rs", 1,
        '{ let mut o = Vec::new(); if let Ok(mut s) = conn.prepare("SELECT a FROM t") '
        '{ if let Ok(rows) = s.query_map([], f) { for a in rows.flatten() { o.push(a); } } } '
        'json!({ "o": o, "error": "liste possiblement TRONQUÉE : lecture NON SOLDÉE" }) }',
        "(conn: &Connection) -> Value")]
    nu_src = ('pub(crate) async fn r17() -> Json<Value> {\n'
              '    let v = read_with_watchdog(&db, json!({ "rows": [], "error": "x" }), NOM);\n'
              '    Json(v)\n}\n')
    def jambes_de(nom):
        _s, a = analyser("/chemin_nu.rs", nu_src.replace("NOM", nom), defs_fab, constructeurs, [])
        return {j for j, *_ in a}
    if "B" not in jambes_de("fermeture_nue_sourde"):
        errs.append("témoin du CHEMIN NU (positif) : une fermeture passée SANS parenthèses "
                    "(`read_with_watchdog(&db, defaut, ma_fonction)`) dont le corps AVALE n'est pas "
                    "accusée — la jambe B a cessé d'ouvrir la région d'un site pourtant DÉCOUVERT, et "
                    "l'angle mort de `P10.7-j` est rouvert")
    if "B" in jambes_de("fermeture_nue_qui_avoue"):
        errs.append("témoin du CHEMIN NU (négatif) : la MÊME fermeture nue, dont le corps AVOUE, est "
                    "accusée — la jambe B accuserait la forme même qu'elle réclame")
    if "B" in jambes_de("fonction_qui_nexiste_pas"):
        errs.append("témoin du CHEMIN NU (nom inconnu) : un chemin SANS définition dans l'arbre "
                    "produit une accusation B — la garde accuse une région qu'elle n'a jamais lue")
    # ET LE MÊME CONTRÔLE À SON PROPRE NIVEAU : la résolution doit rendre DEUX régions (le texte du
    # chemin, qui ne porte aucune lecture, ET le corps résolu), et un `|conn| …` ordinaire ne doit PAS
    # en gagner une de plus. Sans ce témoin-ci, le précédent pourrait passer pour une raison ÉTRANGÈRE.
    faux_code = 'read_with_watchdog(&db, json!({}), fermeture_nue_sourde)'
    tr_nu, fin_nu = arguments(faux_code, faux_code.index("("))
    regions_nu = [n for n, _c in corps_de_la_closure(faux_code, tr_nu, fin_nu, defs_fab)]
    if regions_nu != ["<closure>", "fermeture_nue_sourde"]:
        errs.append(f"témoin du CHEMIN NU (au niveau du prédicat) : régions {regions_nu} au lieu du "
                    "texte du chemin PLUS le corps résolu — la résolution du chemin nu est cassée")
    # CE TÉMOIN-CI EST DÉFENSIF, ET IL EST DÉCLARÉ NON PROUVÉ. Relâcher le `fullmatch` en `match` — la
    # mutation qui fait justement « déborder la résolution de sa forme » — laisse la garde ENTIÈREMENT
    # VERTE sur l'arbre du 2026-08-30 : le premier identifiant d'un `move |conn| …` est `move`, qui n'a
    # aucune définition, donc aucune région n'est inventée. Le témoin est conservé parce qu'il tiendrait
    # le jour où une fermeture commencerait par un nom défini ; il est dit ici plutôt que compté parmi
    # les témoins prouvés, car un instrument qui prétend éprouver ce qu'il n'atteint pas est pire que rien.
    faux_lam = 'read_with_watchdog(&db, json!({}), move |conn| lit(conn))'
    tr_l, fin_l = arguments(faux_lam, faux_lam.index("("))
    if [n for n, _c in corps_de_la_closure(faux_lam, tr_l, fin_l, defs_fab)][0] != "<closure>":
        errs.append("témoin du CHEMIN NU (négatif, au niveau du prédicat) : une fermeture `|conn| …` "
                    "ordinaire est prise pour un chemin nu — la résolution déborde de sa forme")
    # LA VOIE D'ÉCRITURE, À SON PROPRE NIVEAU (`P10.7-l`). Les mutants 16 à 19 pourraient passer pour
    # une raison ÉTRANGÈRE — le PIRE cas étant que le site ne soit pas DÉCOUVERT du tout : le 17, le 18
    # et le 19 seraient alors verts pour la mauvaise raison, et la garde n'accuserait plus rien sur
    # cette voie sans qu'aucun compte ne bouge. Ces trois témoins-ci le tiennent, et ils ont été
    # ÉPROUVÉS PAR MUTATION le 2026-08-30 : retirer `with_write` de `APPEL` rend le PREMIER rouge ;
    # retirer le contrôle `RETOUR_REPONSE` de la jambe B rend le DEUXIÈME rouge ; étendre la jambe A à
    # la voie d'écriture rend le TROISIÈME rouge.
    for nom, src in (("qui avale", ECRITURE_SOURDE_CORPS), ("à statut nu", ECRITURE_SOURDE_STATUT),
                     ("qui avoue", ECRITURE_QUI_AVOUE), ("propre", ECRITURE_PROPRE)):
        s_ec, _a = analyser("/ecriture.rs", src, defs, constructeurs, [])
        if len(s_ec) != 1 or s_ec[0][1] != VOIE_ECRITURE:
            errs.append(f"témoin de la POPULATION d'ÉCRITURE ({nom}) : {len(s_ec)} site(s) au lieu de 1 "
                        "— `with_write` n'est plus DÉCOUVERT, et les témoins qui l'innocentent sont "
                        "verts pour la mauvaise raison")
    _s, acc_st = analyser("/ecriture_statut.rs", ECRITURE_SOURDE_STATUT, defs, constructeurs, [])
    if acc_st:
        errs.append(f"témoin du CORPS SERVI (négatif) : {len(acc_st)} accusation(s) sur une fermeture "
                    "d'écriture dont le gestionnaire rend un `StatusCode` NU — la garde réclame un aveu "
                    "là où aucun corps n'est servi, et le rouge serait INFERMABLE")
    _s, acc_ec = analyser("/ecriture_corps.rs", ECRITURE_SOURDE_CORPS, defs, constructeurs, [])
    jambes_ec = {j for j, *_ in acc_ec}
    if jambes_ec != {"B"}:
        errs.append(f"témoin de l'ASYMÉTRIE des jambes : jambes {sorted(jambes_ec)} au lieu de ['B'] sur "
                    "un site d'écriture — le deuxième argument de `with_write` est `&au`, pas un défaut, "
                    "et la jambe A n'a RIEN à y juger (elle accuserait « le défaut `&au` n'avoue pas »)")
    # L'aveu se reconnaît, et son absence aussi.
    if not porte_un_aveu('json!({ "rows": [], "error": "x" })', constructeurs):
        errs.append("témoin d'AVEU : la clé `error` n'est plus reconnue")
    if porte_un_aveu('json!({ "rows": [], "errors": 0, "err": 1 })', constructeurs):
        errs.append("témoin d'AVEU (négatif) : `errors`/`err` sont comptés comme la clé `error`")
    if "corps_de_refus" not in constructeurs:
        errs.append("témoin d'ANCRAGE : `corps_de_refus` n'est plus dérivé comme constructeur d'aveu — "
                    "la dérivation ne lit plus `daemon/src/handlers/portillon.rs`")
    # LE JUGEMENT CONTRE LES ENSEMBLES NOMMÉS S'ÉPROUVE À SON PROPRE NIVEAU (`P10.20-s`, 2026-09-19).
    # Il vivait dans `main` et RIEN ne l'atteignait : sur un arbre où les accusations coïncident avec
    # les ensembles, le débrancher laisse la garde VERTE à sortie identique. Les deux témoins sont
    # SYMÉTRIQUES, et c'est le point — un seul des deux sens laisserait l'autre s'éteindre en silence.
    fab_acc = {"B": [("daemon/src/handlers/fabrique.rs:1", "lit_tout", "tuple lié sans `else`")]}
    neuve = ecarts_contre_les_ensembles(fab_acc, {"A": {}, "B": {}, "Q": {}})
    if len(neuve) != 1 or "FORME NEUVE" not in neuve[0] or "lit_tout" not in neuve[0]:
        errs.append("témoin du JUGEMENT (forme neuve) : une accusation hors de l'ensemble nommé ne rend "
                    f"pas un écart qui NOMME le site — rendu {neuve}")
    sans_objet = ecarts_contre_les_ensembles(
        {}, {"A": {}, "B": {("daemon/src/handlers/fabrique.rs", "lit_tout"): 1}, "Q": {}})
    if len(sans_objet) != 1 or "EXEMPTION SANS OBJET" not in sans_objet[0]:
        errs.append("témoin du JUGEMENT (exemption sans objet) : une entrée de l'ensemble nommé que rien "
                    f"n'accuse ne rend pas d'écart — rendu {sans_objet}")
    if ecarts_contre_les_ensembles(fab_acc, {"A": {}, "B": {("daemon/src/handlers/fabrique.rs", "lit_tout"): 1}, "Q": {}}):
        errs.append("témoin du JUGEMENT (négatif) : une accusation EXACTEMENT admise rend un écart — le "
                    "jugement accuse ce que l'ensemble nomme, et l'exemption ne servirait plus à rien")
    # LES LECTEURS DE FORME RUST SE VALIDENT ICI COMME AILLEURS — LA MÊME FONCTION, PAS UNE COPIE.
    try:
        temoins_des_lecteurs_de_forme()
    except AssertionError as e:
        errs.append(f"lecteurs de forme Rust (`apparier`, `fonctions`, `arguments`, "
                    f"`bras_du_match`) : {e}")
    return errs


def ce_qui_n_est_pas_tenu(non_classes=0):
    print(f"\n[{ETIQUETTE}] CE QUE CETTE GARDE NE TIENT PAS :\n"
          "  * que le NOM d'une fonction accusée soit stable : les ensembles nommés (`P10.7-y`) sont indexés par "
          "(fichier, fonction), et renommer une fonction accusée fait rougir deux fois — forme neuve et exemption "
          "sans objet. C'est le signal voulu ; la liste se corrige à la main, avec la raison.\n"
          "  * qu'un aveu soit VRAI. Elle juge qu'une cause atteint le corps servi, pas que la phrase "
          "qui l'accompagne dise quelque chose. Un `error: \"\"` la satisferait.\n"
          "  * la liaison par TUPLE et le motif IMBRIQUÉ SONT LUS depuis `P10.20-s` (2026-09-19) : il "
          "n'existe plus qu'un motif de liaison (`MOTIF_LIANT_IF_LET_TOUT_MOTIF`), le même que la "
          "famille des PARCOURS MUETS consomme. CE QUI RESTE HORS DE PORTÉE, et c'est nommé pour être "
          "vu : `if let Some(x) = <lecture>` (aucune enveloppe `Ok`), `while let`, et `if let Ok(..) = "
          "<lecture> { .. } else { .. }` dont l'`else` NE PARLE PAS — la présence de la branche suffit "
          "à innocenter, comme la jambe Q le fait déjà sur la même forme. Aucune des trois n'existe "
          "sous `daemon/src/handlers/` au 2026-09-19, mesuré.\n"
          "  * CE QUE L'ÉLARGISSEMENT DE CE MOTIF N'A PAS RÉPARÉ, ET C'EST LA LEÇON DU LOT. Ce fichier "
          "a écrit que le tuple de `action_approve` (actions.rs) échappait à la jambe B faute d'un "
          "motif assez large ; la cause était AILLEURS. Sur l'arbre qui portait encore ce tuple, le "
          "motif large fait passer la population BRUTE de la forme sous `daemon/src/handlers/` de zéro "
          "à UN site, et la jambe B y reste à ZÉRO accusation : ce site lit derrière `req_conn!`, une "
          "voie que la POPULATION ne nomme pas, donc sa région ne s'ouvre pas et son texte n'est "
          "jamais lu. Un motif élargi sur une population amputée reste aveugle — la même leçon que "
          "`read_with` a coûtée, sur un quatrième axe après les bras de `match`, les `if let` sans "
          "branche et la fermeture écrite en chemin nu.\n"
          "  * la JAMBE EXÉCUTÉE. Rien ici ne lance le routeur sous un budget épuisé : la garde lit du "
          "texte. Ce qu'elle prouve, c'est qu'une forme est absente du dépôt, jamais qu'une réponse "
          "réelle avoue. Le levier EXISTE (`PLUME_QUERY_BUDGET_MS`, lu par `query_budget_ms`) et aucun "
          "levier neuf n'est à inventer ; ce qui manque est un point d'entrée qui monte le routeur sans "
          "réseau — le poser DÉPLACERAIT un compteur déclaré ailleurs, il n'est donc pas posé ici.\n"
          "  * le DÉFAUT d'une fonction qui ne rend PAS de réponse (`-> Value`, `-> Vec<_>`). La règle "
          "dit « vers une réponse de la MÊME fonction » ; un défaut qui traverse deux fonctions avant "
          "d'être servi lui échappe. Trois sites de l'arbre sont dans ce cas au 2026-08-30.\n"
          "  * les lectures faites à DEUX niveaux d'appel. La jambe B suit UN niveau, et seulement les "
          "noms qui ont une définition UNIQUE dans l'arbre ; un homonyme n'est pas suivi.\n"
          "  * le DÉFAUT de `read_with` EST jugé par la jambe A depuis le 2026-09-08 (`P10.7-i`) : le "
          "vocabulaire d'aveu lit les constructeurs que l'arbre documente `AVEU` (six le jour de la mesure), "
          "les quatre sites qui avouaient par le TYPE ne sont plus accusés, et les six qui servaient une "
          "liste vide ou des zéros comme un fait avouent. Ce que le vocabulaire typé NE LIT PAS : un "
          "constructeur qui avoue sans porter cette doc — il serait accusé, et c'est l'aveu écrit qui "
          "manque, pas la garde.\n"
          "  * LA POPULATION, ET C'EST TOUJOURS LE PLUS GRAND ANGLE MORT — mais la description qu'en "
          "faisait ce fichier était FAUSSE SUR CINQ POINTS, re-mesurés le 2026-08-30 (`P10.7-j`) avec la "
          "machinerie de cette garde, commentaires DÉPOUILLÉS. Elle disait : `req_conn!` 181 emplois "
          "(mesuré 180) ; la forme `if let Ok(..) = <lecture>` sans `else` employée 43 fois sur 15 "
          "fichiers (mesuré 42 sur 14 — l'allégation de 42/14 que ce fichier avait DÉCLARÉE fausse était "
          "donc juste, et sa correction était l'erreur) ; 24 de ces formes hors de toute région jugée sur "
          "9 fichiers (mesuré 23 sur 8) ; et surtout, que ces 23 vivraient DERRIÈRE `req_conn!` en citant "
          "en preuve les six de `system.rs` et les quatre de `admin_ui.rs` — or ces DIX-LÀ ne passent PAS "
          "par `req_conn!` : `system_diag` écrit le prologue À LA MAIN (`req_db(&st, &au)` puis `.lock()`) "
          "et `suppressions_get` prend DÉLIBÉRÉMENT `st.db` (la base PLATEFORME, c'est documenté au-dessus "
          "de la fonction). SIX des 23 seulement sont atteignables depuis un `req_conn!` "
          "(les quatre sites de `index_policies.rs`, `ioc_cache_reload` (`threat_intel.rs`)). Citer en preuve un site hors de la "
          "voie qu'on accuse est la faute que ce dépôt paie le plus cher — et la voie qui manquait "
          "VRAIMENT pour deux de ces sites n'était pas une voie du tout : c'était la RÉGION d'un site "
          "déjà découvert, comblée par ce lot.\n"
          "  * LA VOIE D'ÉCRITURE N'EST PAS UNE VOIE, C'EN EST QUATRE, et une seule est jugée "
          "(mesuré le 2026-08-30 sur `daemon/src/handlers/`) : `req_conn!` 180 emplois sur 32 fichiers, "
          "le MÊME prologue écrit à la main `req_db(..)` + `.lock()` 18 sur 10, `st.db(.clone()).lock()` "
          "37 sur 5 — 235 sites qu'AUCUNE jambe ne juge. La quatrième, `with_write` (19 sites sur 6 "
          "fichiers), est entrée dans la population le 2026-08-30 (`P10.7-l`) et la jambe B y juge la "
          "RÉGION DE LA FERMETURE, comme sur `read_with*`. Les trois autres restent hors champ pour la "
          "raison MESURÉE que `P10.7-j` a écrite : leur région va jusqu'à la fin du gestionnaire, et une "
          "seule lecture avalée y compte autant de fois qu'il y a de gestionnaires.\n"
          "  * `with_write` HORS de `daemon/src/handlers/` : 2 sites sur 1 fichier "
          "(`daemon/src/ingest/obs.rs`, mesuré le 2026-08-30) ne sont PAS jugés. La population de cette "
          "garde est le répertoire des handlers, et l'ingest n'y est pas — ce n'est pas un oubli, c'est "
          "la borne du fichier, mais un corps servi peut naître ailleurs qu'ici.\n"
          "  * `req_conn!` N'EST PAS ENTRÉE DANS LA POPULATION, ET C'EST UNE MESURE, PAS UN OUBLI. "
          "L'extension a été PROTOTYPÉE le 2026-08-30 (région = de la macro à la fin de la fonction "
          "englobante, la portée du garde de verrou, PLUS un niveau d'appel — la règle de "
          "`corps_de_la_closure`) : 68 accusations, le cliquet B passerait de 22 à 90. Ce n'est pas la "
          "TAILLE qui l'a arrêtée, c'est le GRAIN. Pour `read_with*`, la valeur de la fermeture EST le "
          "corps servi ; pour `req_conn!`, « de la macro à la fin de la fonction » est TOUT LE RESTE du "
          "gestionnaire — validation, mutation, audit, réponse — et l'ouverture à un niveau y traîne des "
          "auxiliaires qui ne servent aucun corps. Conséquence MESURÉE : l'UNIQUE lecture avalée de "
          "`ledger_append` compte HUIT fois, contre huit gestionnaires différents ; `parsers_reload` "
          "quatre ; `processors_reload` et `field_filters_reload` trois chacun. Un cliquet qui bouge de "
          "huit pour un seul geste local ne nomme plus de site — c'est la hausse qui n'apprend rien, celle "
          "que le témoin du DOUBLE COMPTE refuse déjà au niveau de l'unité.\n"
          "  * SUR LA VOIE D'ÉCRITURE, LA JAMBE B N'ACCUSE QUE SI UN CORPS EST SERVI, et ce critère "
          "SOUS-ACCUSE. Des 10 sites que la jambe accusait sans lui (mesuré le 2026-08-30, `P10.7-l`), 5 "
          "servent un corps et sont accusés ; 3 sont FAIL-CLOSED (`case_merge`, `case_unmerge`, "
          "`case_apply_update` : une lecture ratée y rend `false` -> 404) et sont ACQUITTÉS à raison ; 2 "
          "ne servent AUCUN corps et sont acquittés faute de pouvoir formuler l'aveu — ce sont pourtant "
          "de VRAIS défauts, nommés ici et NON corrigés : `caseops.rs:674` (`sla_policy_upsert` rend 204 "
          "« fait » alors que la liste d'ids à recalculer peut être VIDE faute d'avoir été lue, et "
          "`sla_apply_policy` renonce en silence) et `caseops.rs:674/698` (`ledger_append` lit le hash "
          "précédent en `unwrap_or_default()` : une lecture ratée écrit un maillon au `prev_hash` VIDE, "
          "donc une CHAÎNE D'INTÉGRITÉ rompue que rien ne signale). Un gestionnaire qui rend un "
          "`StatusCode` NU n'a aucun corps où poser `error` : l'accuser poserait un rouge qu'aucun geste "
          "ne referme, et c'est ce que ce dépôt refuse. Le jour où le vocabulaire d'aveu dépassera la "
          "clé `error` (le même manque que pour le défaut de `read_with`), ces deux-là redeviendront "
          "formulables.\n"
          "  * `case_get_json` (`cases.rs:489`) EST accusé, mais sa phrase compte TROIS lectures quand "
          "UNE SEULE sert un corps : le parcours de la timeline (`query_map(..).ok()?.flatten()`) rend "
          "une liste TRONQUÉE sous un 200, tandis que les deux autres (`query_row`/`prepare` en "
          "`.ok()?`) rendent `None`, donc un 404 — elles sont FAIL-CLOSED. Le compte de lectures d'une "
          "phrase n'est PAS un compte de défauts, ici comme partout ailleurs dans ce journal.\n"
          "  * CE QUE LE COMPTE NE DISAIT PAS — les 23 formes que ce fichier déclarait hors région jugée, "
          "classées une par une le 2026-08-30, et elles ne sont PAS toutes des défauts. DEUX d'entre "
          "elles (`compliance.rs:193/196`) sont ENTRÉES dans le champ avec le comblement du chemin nu "
          "ci-dessus : il en reste VINGT ET UNE hors de toute région jugée, sur 7 fichiers. QUINZE des "
          "23 servent un CORPS : "
          "le dénombrement d'hôtes par source (`admin_ui.rs`) (le compte d'hôtes qui marque une entrée `contested` — une lecture ratée "
          "efface le signal ANTI-EMPOISONNEMENT sans rien dire, la plus grave des 23), "
          "`admin_ui.rs:731/737`, `ai.rs:76` (servi tel quel par `ai_redaction_policy_get` : l'admin lit "
          "la politique PAR DÉFAUT en croyant lire celle qui est stockée ; côté application le repli est "
          "conservateur), les quatre sites de `index_policies.rs`, et les SIX de "
          "`system.rs` (bundle de support : `recent_events: []`, `heartbeat_alerts: []` — le signal de "
          "capteur muet lu comme PROPRE — et `unclassified_by_source: []` qui contredit alors le compte "
          "`events_without_category` servi dans le MÊME corps). DEUX sont un calcul interne dont "
          "l'absence est un fait LÉGITIME et DOCUMENTÉ : `cases.rs:87/97` (`resolve_case_ref` — la cible "
          "a été purgée par la rétention, la ref BRUTE reste affichée, et deux tests le fixent). DEUX "
          "sont FAIL-CLOSED, et l'absence y est un REFUS, pas un fait rassurant : `datamodels.rs:262/263` "
          "(une allowlist vide fait REJETER tout champ du Pivot -> 400). DEUX ne sont NI l'un NI l'autre, "
          "et ce sont celles qu'aucune jambe de cette garde ne saurait formuler : `ioc_cache_reload` (`threat_intel.rs`) "
          "remplaçait ATOMIQUEMENT le cache de correspondance par un set VIDE ; aucune route ne mentait, "
          "la DÉTECTION s'éteignait, et il n'existait aucun corps servi où poser `error`. CE SITE EST FERMÉ "
          "DEPUIS LE 2026-08-30 (`P10.7-k`) : la lecture est désormais ENTIÈRE OU NULLE, l'état vivant est "
          "préservé, et l'aveu passe par une route de couverture qui existait déjà. LE CONSTAT DE FORME RESTE "
          "VRAI, ET C'EST POURQUOI IL EST GARDÉ ICI : cette garde n'aurait PAS su l'exiger, et deux défauts de "
          "la MÊME espèce restent ouverts ailleurs — un maillon de journal d'intégrité écrit avec un hachage "
          "précédent VIDE, et un recalcul d'échéances SAUTÉ pendant qu'une route rend « fait ». Tant que le "
          "vocabulaire d'aveu se limite à une clé de CORPS, cette famille échappe par sa FORME, jamais par sa "
          "portée. Et les DEUX "
          "entrées du jour (`compliance.rs:193/196`) servent un CORPS : c'est la seule des 23 dont la "
          "voie était DÉJÀ dans la population, et elle échappait par sa RÉGION, pas par sa voie. Ces "
          "classements sont dans `daemon/`, ils sont NOMMÉS ici et ne sont pas corrigés par ce lot ; "
          "sur les 21 qui restent, DEUX seulement passent par `req_conn!` (`index_policies.rs:89/90`, "
          "plus `:27/30` par un niveau d'appel depuis le même gestionnaire).\n"
          "  * l'aveu est cherché DANS LA RÉGION, jamais sur la lecture. Une closure qui avoue UNE "
          "coupe innocente TOUTES ses lectures, y compris celles dont l'échec n'est couvert par aucun "
          "aveu : `freshness.rs:579` porte trois `if let` sans branche sur des `prepare` et reste "
          "innocenté parce qu'il pose `corps[\"error\"]` pour ses PARCOURS. C'est un choix — le "
          "resserrer accuserait la surface la plus consciencieuse de l'arbre — mais ce n'en est pas "
          "moins un trou, et il est ici pour être vu.\n"
          "  * le `if let` n'est suivi que s'il lie par `Ok(..)` : `Some(x)` et `while let` ne le sont "
          "pas. Un `if let` AVEC `else` n'est PAS jugé sur ce que son `else` fait — la branche existe, "
          "et c'est tout ce que cette jambe constate ; c'est la règle que la jambe Q applique déjà à "
          "la même forme.\n"
          "  * UNE FORME CITÉE DANS UN LITTÉRAL DE CHAÎNE n'est plus comptée depuis `P10.20-s` — elle "
          "l'était, sur les TROIS écritures de l'avalement, et le commentaire seul était écarté. Le "
          "défaut n'était pas MORDANT (zéro appariement de lecture dans un littéral sur "
          "`daemon/src/handlers/` comme sur tout `daemon/src` au 2026-09-19) ; il était ARMÉ, et il "
          "s'arme d'autant plus que le motif de liaison s'élargit. Ce qui reste : les intervalles sont "
          "calculés sur le FRAGMENT reçu, et un fragment qui commencerait à l'intérieur d'un littéral "
          "serait lu à l'envers — les fragments rendus commencent tous à une frontière de jeton.\n"
          "  * le bras n'est suivi que s'il lie par `Ok(<nom>)` : `Ok((a, b))`, `Some(x)` et un bras "
          "fourre-tout `_ =>` ne le sont pas. C'EST LE TROU SYMÉTRIQUE DE CELUI QUE `P10.20-s` A "
          "FERMÉ SUR LE `if let`, ET IL EST LE PLUS GRAND DES DEUX — MESURÉ sur l'arbre du "
          "2026-09-19 : sur `daemon/src/handlers/`, 140 bras de `match` scrutant une lecture lient "
          "par un nom simple et sont suivis, 14 lient par un motif que `BRAS_LIANT` ne suit pas "
          "(tuples `Ok((owner, vis))`, `Ok((n, s))`, `Ok((v, s))`, `Ok((name, did, data, created, "
          "by, role))` ; imbriqués `Ok(Some(..))` ; un bras gardé `Ok(d) if ..` ; un littéral "
          "`Ok(0)`), soit 18 sur tout `daemon/src`. CE QUE CE TROU COÛTE AUJOURD'HUI, mesuré aussi : "
          "UN seul de ces 14 bras porte un avalement dans son corps (`dash_ergonomics.rs`, "
          "`snapshot_get`), et c'est une analyse JSON (`serde_json::from_str(..).unwrap_or_else(..)`), "
          "pas une lecture de lignes. Le fermer demande d'extraire les noms liés d'un motif composé, "
          "pas d'élargir une expression rationnelle — `bras_qui_avale` suit la chaîne DEPUIS LE NOM "
          "LIÉ, et un tuple n'en a pas un seul. Ce n'est donc pas fait ici, et le compte est écrit "
          "pour que le lot qui le fera parte d'une mesure.\n"
          "  * la chaîne d'un bras est suivie DEPUIS LE NOM LIÉ. Un avalement écrit dans une closure "
          "INTERNE au bras (`Ok(r) => r.filter_map(|x| x.ok()).collect()`) lui échappe ; aucun site de "
          "l'arbre n'en porte au 2026-08-30, et le jour où il y en aura un, c'est cette ligne-ci qu'il "
          "faudra tenir, pas le compte.\n"
          "  * les virgules de GÉNÉRIQUES en position d'argument (`HashMap<K, V>` non tourné en "
          "turbofish) découperaient mal un appel. Aucun site de l'arbre n'en porte ; le jour où il y en "
          "aura un, c'est un aveu de lecture qu'il faudra poser, pas un compte amputé rendu en vert.\n"
          "  * ce que l'ANALYSTE voit. Le démon avoue ; qu'une console lise `error` se juge ailleurs "
          "(`check_a_refusal_is_not_rendered_as_an_absence.py`).\n"
          "  * un ÉCHANGE. Les cliquets portent sur un COMPTE : rendre un site honnête et en casser un "
          "autre laisse le compte immobile et le verdict vert. C'est pourquoi CHAQUE site accusé est "
          "imprimé à chaque exécution — l'échange est visible dans le journal, il n'est pas refusé par "
          "le code de sortie.\n"
          f"  * {non_classes} site(s) d'exécution de requête dont le sort de la cause n'a PAS été "
          "classé : ils ne sont pas accusés, et ils ne sont pas innocentés.")


def main():
    # LE LECTEUR PARTAGÉ SE VALIDE AVANT DE SERVIR (`P10.20-d`, 2026-09-16). Il est IMPORTÉ, donc ses
    # témoins ne tournent pas à l'import : sans cet appel, un lecteur amputé de sa reconnaissance des
    # chaînes brutes ou des littéraux de caractère ne serait épinglé que par la garde qui le PORTE, et
    # celle-ci rendrait un compte amputé en vert. Le coût est nul et il est MESURÉ : 0,34 ms, contre
    # 1,62 s pour l'exécution complète de cette garde (0,02 %).
    try:
        temoins_du_lecteur()
    except AssertionError as e:
        print(f"::error::lecteur partagé (`sans_commentaires_rust`) : {e}")
        print(f"\n[{ETIQUETTE}] l'INSTRUMENT est faux : aucun verdict n'est rendu.")
        ce_qui_n_est_pas_tenu()
        return 2

    src_demon = list(sources(DEMON))
    ancre = next((t for c, t in src_demon if c.endswith(os.path.join("daemon", "src", "query_exec.rs"))), "")
    manquantes = [v for v in VOIES_FERMETURE + VOIES_REQUETE if f"fn {v}" not in ancre]
    if manquantes:
        print(f"::error::les voies {manquantes} ne sont plus DÉFINIES dans daemon/src/query_exec.rs : "
              "la population de cette garde n'a plus d'ancrage.")
        ce_qui_n_est_pas_tenu()
        return 2

    aveux_du_lecteur = {}
    defs = definitions(src_demon, aveux_du_lecteur)
    # L'AVEU DU LECTEUR PASSE AVANT L'INSTRUMENT ET AVANT TOUT VERDICT (`P10.20-d`) : une région avalée
    # tronque les corps, et l'instrument accuserait alors la DÉRIVATION là où la cause est le LECTEUR.
    if aveux_du_lecteur and refuser_sur_aveu(ETIQUETTE, aveux_du_lecteur, "Rust"):
        ce_qui_n_est_pas_tenu()
        return 2
    constructeurs = constructeurs_d_aveu(defs, src_demon)

    errs = valider_instrument(defs, constructeurs)
    if errs:
        for e in errs:
            print(f"::error::{e}")
        print(f"\n[{ETIQUETTE}] l'INSTRUMENT est faux : aucun verdict n'est rendu.")
        ce_qui_n_est_pas_tenu()
        return 2

    sites, accusations, aveux = [], [], []
    fichiers = set()
    for chemin, texte in sources(HANDLERS):
        s, a = analyser(chemin, texte, defs, constructeurs, aveux, aveux_du_lecteur)
        if s:
            fichiers.add(os.path.relpath(chemin, RACINE))
        sites += s
        accusations += a

    # LE SECOND JUGEMENT DU MÊME JOURNAL, ET CE QU'IL VAUT AUJOURD'HUI, DIT PLUTÔT QUE SOUS-ENTENDU :
    # `analyser` relit les fichiers de `HANDLERS`, qui est un SOUS-ARBRE de `DEMON` filtré de la même
    # façon — il ne peut donc rien ajouter au journal que la passe des définitions n'ait déjà vu, et ce
    # contrôle ne peut pas rougir tant que cette inclusion tient. Il est là pour que la règle « chaque
    # appel du lecteur passe son journal, chaque journal est jugé avant le verdict » ne dépende pas
    # d'une inclusion qui peut changer d'un lot à l'autre.
    if aveux_du_lecteur and refuser_sur_aveu(ETIQUETTE, aveux_du_lecteur, "Rust"):
        ce_qui_n_est_pas_tenu()
        return 2
    if aveux:
        for a in aveux:
            print(f"::error::{a}")
        print(f"\n[{ETIQUETTE}] REFUS DE CONCLURE — le lecteur avoue avoir perdu un appel ; il ne rend "
              "pas un compte amputé en vert.")
        ce_qui_n_est_pas_tenu()
        return 2

    gardes = [s for s in sites if s[1] in VOIES_LECTURE]
    ecritures = [s for s in sites if s[1] == VOIE_ECRITURE]
    requetes = [s for s in sites if s[1] in VOIES_REQUETE]
    if len(sites) < PLANCHER_SITES or len(fichiers) < PLANCHER_FICHIERS:
        print(f"::error::{len(sites)} site(s) découvert(s) sur {len(fichiers)} fichier(s), planchers "
              f"{PLANCHER_SITES}/{PLANCHER_FICHIERS} : la DÉCOUVERTE est cassée, pas le démon. La garde "
              "REFUSE DE CONCLURE plutôt que de rendre vert en étant aveugle.")
        ce_qui_n_est_pas_tenu()
        return 2
    if not gardes or not ecritures or not requetes:
        print(f"::error::une des trois familles n'est plus appelée nulle part ({len(gardes)} lecture(s), "
              f"{len(ecritures)} écriture(s), {len(requetes)} requête(s)) : la lecture ne voit plus "
              "qu'une part de la famille.")
        ce_qui_n_est_pas_tenu()
        return 2

    # TÉMOIN D'ANTI-TAUTOLOGIE, ET IL N'EST PAS UNE RANÇON : il exige qu'un aveu EXISTE quelque part
    # sur l'arbre, jamais qu'un défaut survive. Le jour où tout avoue, il reste vert.
    a_par_jambe = {}
    for jambe, ou, fn, raison in accusations:
        a_par_jambe.setdefault(jambe, []).append((ou, fn, raison))
    # Il se compte sur les sites que la jambe A JUGE RÉELLEMENT (la voie gardée), jamais sur toute la
    # famille : mesuré contre `gardes`, il se relâcherait du seul fait que `read_with` a rejoint la
    # population — un témoin qui s'affaiblit quand le regard s'élargit est un témoin faux.
    juges_par_a = [s for s in sites if s[1] == VOIE_GARDEE]
    if len(a_par_jambe.get("A", [])) >= len(juges_par_a):
        print(f"::error::AUCUN des {len(juges_par_a)} défauts de lecture gardée ne porte d'aveu : le "
              "reconnaisseur d'aveu ne reconnaît plus rien. La garde REFUSE DE CONCLURE.")
        ce_qui_n_est_pas_tenu()
        return 2

    for jambe in ("A", "B", "Q"):
        for ou, fn, raison in a_par_jambe.get(jambe, []):
            fichier, ligne = ou.rsplit(":", 1)
            print(f"::error file={fichier},line={ligne}::[{jambe}] `{fn}` — {raison}")
    for ou, fn, raison in a_par_jambe.get("?", []):
        print(f"::notice file={ou.rsplit(':', 1)[0]},line={ou.rsplit(':', 1)[1]}::[?] `{fn}` — "
              f"sort de la cause NON CLASSÉ ({raison})")

    na, nb, nq = (len(a_par_jambe.get(j, [])) for j in ("A", "B", "Q"))
    nc = len(a_par_jambe.get("?", []))
    print(f"\n[{ETIQUETTE}] POPULATION DÉCOUVERTE le jour de l'exécution : {len(sites)} site(s) sur "
          f"{len(fichiers)} fichier(s) de daemon/src/handlers — {len(gardes)} lecture(s) (gardée ou "
          f"simple), {len(ecritures)} écriture(s) `with_write`, {len(requetes)} exécution(s) de requête. "
          "Commentaires DÉPOUILLÉS : une occurrence citée en commentaire n'est jamais un site.")
    print(f"[{ETIQUETTE}] ACCUSATIONS : jambe A (défaut nu) {na}/{PLAFOND_DEFAUT_NU} · jambe B "
          f"(closure sourde) {nb}/{PLAFOND_CLOSURE_SOURDE} · jambe Q (cause jetée) "
          f"{nq}/{PLAFOND_CAUSE_JETEE} · non classés {nc}.")

    # `P10.7-y` — JUGEMENT DANS LES DEUX SENS, site par site, contre l'ensemble nommé de chaque jambe.
    # Le jugement lui-même vit dans `ecarts_contre_les_ensembles`, qui est éprouvé par deux témoins.
    messages = ecarts_contre_les_ensembles(a_par_jambe)
    for m in messages:
        print(m)
    if messages:
        print(f"::error::{len(messages)} écart(s) entre les accusations du jour et les ensembles nommés. L'ensemble se "
              "corrige à la main, avec la raison ; ZÉRO reste atteignable jambe par jambe.")
        ce_qui_n_est_pas_tenu(nc)
        return 1
    print(f"[{ETIQUETTE}] les trois ensembles nommés sont EXACTEMENT ce que l'arbre porte "
          f"(A {na}, B {nb}, Q {nq}) — ni forme neuve, ni exemption sans objet.")
    ce_qui_n_est_pas_tenu(nc)
    return 0


if __name__ == "__main__":
    sys.exit(main())
