#!/usr/bin/env python3
"""Un test qui REND LA MAIN SANS CONCLURE le DIT par le canal, et n'est jamais muet (`P11.23-b`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
=============================================
Un test qui ne peut pas voir — plate-forme sans `/proc`, levier de configuration éteint, clé
SQLCipher posée dans l'environnement — a le droit de ne rien prouver. Il n'a PAS le droit de se
présenter comme un test qui a prouvé. Or c'est exactement ce qu'il fait : il sort en 0, et le
portail de déploiement comme les jobs Rust de `ci.yml` ne lisent que ce 0.

MESURÉ SUR CET ARBRE LE 2026-08-31, avant correction — la population est DÉRIVÉE, pas listée :
QUATORZE chemins de `daemon/src/tests/` rendaient la main sans exercer l'assertion qui justifie
leur test. NEUF n'imprimaient rien du tout. Et les CINQ qui imprimaient ne valaient pas mieux :
`libtest` détourne les sorties du fil de chaque test et ne les rend que pour les tests qui
ÉCHOUENT (mesuré sur une caisse d'essai : 0 occurrence sous `cargo test` nu, 3 sous `--nocapture`,
3 sous `--show-output`). Un aveu imprimé depuis un test VERT part dans le vide.

CE QU'ELLE EXIGE, ET POURQUOI PAS PLUS
=======================================
Elle n'exige PAS qu'un test échoue sur un environnement aveugle : ce serait une RANÇON — un rouge
qu'aucun geste ne pourrait refermer sur un conteneur durci ou une machine non-Linux. Elle exige
que le refus EMPRUNTE LE CANAL, c'est-à-dire qu'il atteigne celui qui décide pendant que la suite
reste verte.

ELLE NE CHERCHE PAS UN MOT D'AVEU DANS UN CORPS, et c'est le cœur de sa conception. Un piège
mesuré le 2026-08-31 sur une autre garde : un mot trop générique compté comme un aveu la rendait
VERTE sur le site le plus grave. Ici le critère est POSITIONNEL, pas lexical — l'appel au canal
doit se trouver DANS LE BLOC du `return`, au même niveau d'accolades. Un aveu écrit ailleurs dans
le même test ne blanchit donc rien. Ce n'est pas une subtilité : `vieillissement_serie.rs` porte
DEUX sorties de refus dans LE MÊME test, et un critère d'appartenance au corps aurait laissé la
seconde muette pour toujours.

TROIS CANAUX
============
  0  tenu.
  1  violé — le site est NOMMÉ (fichier, ligne, test, et ce qui manque).
  2  l'instrument ne peut pas voir — il REFUSE DE CONCLURE, il n'accuse pas.

LA SECONDE FAMILLE, MESURÉE LE 2026-09-02 (`P11.23-e`)
=======================================================
Un refus peut s'écrire SANS sortie anticipée : les assertions vivent dans une branche que
l'environnement peut ne pas prendre, et la jumelle ne porte aucun verdict. Rien ne sort, donc
l'analyse ci-dessus ne voyait rien.

LA POPULATION A ÉTÉ DÉRIVÉE, PAS ESTIMÉE. Sur 1 847 fonctions de test de la caisse, 82 ne portent
AUCUNE assertion sur un chemin d'exécution garanti ; 64 d'entre elles bouclent sur un corpus
LITTÉRAL non vide (leur chemin muet n'existe pas) ou délèguent leur verdict à un auxiliaire ; des
18 restantes, celles dont le chemin muet s'ouvre sans toucher une ligne de Rust sont SEPT — cinq
branches conditionnées par une lecture d'environnement ou par un levier du produit, et deux dont
la jumelle n'est pas vide mais ne fait que du ménage. Toutes empruntent désormais le canal.

CE QUE CETTE GARDE AJOUTE, ET SON CRITÈRE RESTE POSITIONNEL : un `if` dont la CONDITION lit
l'environnement, dont la branche prise porte une assertion et ne sort pas, et dont la JUMELLE ne
porte aucun verdict, doit appeler le canal DANS le bloc de cette jumelle, à sa profondeur. Une
jumelle absente est refusée avec le geste écrit (`else { … }`).

CE QU'ELLE NE TIENT PAS — DIT PLUTÔT QUE SOUS-ENTENDU
======================================================
  · UNE CONDITION QUI CACHE SA LECTURE. Le critère de population reconnaît les lectures
    d'environnement ÉCRITES DANS LA CONDITION. MESURÉ : deux sites réels de
    `branche_d_echec_muette.rs` passent par un auxiliaire (`priver_de_lecture(&rules)`) et
    échappent donc à cette garde — ils empruntent le canal parce qu'un humain les y a mis, pas
    parce qu'elle les y oblige.
  · LES AUTRES CONSTRUITS. `match` sur l'environnement et boucles sur une collection dérivée de
    l'environnement ne sont pas analysés. MESURÉ le 2026-09-02 : zéro `match` de cette forme, et
    les trois boucles trouvées portent déjà leur propre plancher de non-vacuité.
  · UNE CHAÎNE `else if`. Le site est laissé hors population : sa jumelle n'est pas un bloc.
  · UN CORPUS QUI PERD SA MATIÈRE. Un test qui boucle sur un corpus lu d'un fichier de données ne
    sort pas et ne branche pas : il itère zéro fois. Ce qui tient cette forme est un PLANCHER dans
    l'instrument qui produit le corpus, pas cette garde.
  · UNE SEULE CAISSE. La population est celle de la caisse qui PORTE le canal (dérivée : on remonte
    de `canal_de_refus.rs` jusqu'au `Cargo.toml`). Les caisses jumelles ne peuvent pas appeler le
    canal d'une autre — l'exiger serait une rançon. MESURÉ le 2026-08-31 : `agent`,
    `collector-syslog` et `collector-mail` portent ZÉRO chemin de retour anticipé dans leurs tests,
    donc cette borne est aujourd'hui VIDE. Le jour où l'une en écrit un, il faudra y porter le
    canal, et cette garde ne le dira pas.
  · LE TEXTE, PAS L'EXÉCUTION. Elle établit que chaque chemin de refus APPELLE le canal ; que le
    canal ait vraiment écrit, seule l'exécution le montre — c'est le rôle du mode `--lire`.
  · LE BRAS DE L'ENFANT, ET LUI SEUL. Voir la section suivante : un `if` qui lit une variable que
    le test pose chez l'enfant est le bras de l'enfant par définition, quoi qu'il fasse ; et la
    lecture par un auxiliaire n'est suivie que d'UN niveau, dans le même fichier, pour une fonction
    écrite `fn nom(` (un auxiliaire générique `fn nom<T>(` n'est pas trouvé : le test est alors
    accusé, jamais blanchi).

LES TESTS EN SOUS-PROCESSUS (`P7.20-a`, vague BF)
==================================================
Un test qui relance SON PROPRE binaire (`current_exe()`) avec un environnement modifié (`.env(`)
définit un protocole à deux bras ; le bras de l'ENFANT sort tôt et c'est sa fonction, pas un
aveuglement. AVANT CETTE VAGUE, TOUT le test était hors population, parent compris : MESURÉ par le
lot BE4 sur `liste_d_exemption_ssrf_lue_entree_par_entree.rs`, le parent qui refuse de conclure
(`localhost` qui ne rend pas ses deux adresses) passait la garde en rc=0 son appel au canal retiré.

CE QUI EST HORS POPULATION, DÉSORMAIS : les seuls BRAS DE L'ENFANT — chaque `if` du corps dont la
condition lit (`env::var(` ou `env::var_os(`) une variable que ce test POSE par `.env(` (premier
argument comparé tel qu'écrit), directement ou par un auxiliaire du même fichier
(`if let Some(dir) = repertoire_de_l_enfant("…")`). Un test peut en porter plusieurs (un écrivain
puis la sous-commande, `sous_commandes_ne_creent_ni_ne_delient_la_base.rs`). Tout le reste du test
— le PARENT — est jugé comme un test ordinaire, par les deux familles. Un protocole sans bras
reconnu voit chacun de ses `return` jugé, et la faute le dit.

MESURÉ SUR L'ARBRE de la vague BF : 28 chemins jugés au lieu de 23 (cinq refus de PARENTS entrent
dans la population : les deux témoins (d) de `liste_d_exemption_ssrf_lue_entree_par_entree.rs`,
`porte_ne_lache_pas_les_verrous_du_wal.rs`, `puits_du_registre_garde_les_verrous_de_la_base.rs` et
`sous_commandes_ne_creent_ni_ne_delient_la_base.rs`), tous conformes ; aucun faux positif. L'épreuve
BE4 rejouée : le canal retiré du parent rend rc=1 sur ce fichier, rc=0 sous la garde d'avant.

MUTANTS JOUÉS (chacun pose sa substitution dans cette garde ; chacun rend rc=2, le témoin nommé) :
  G1 tout `return` d'un protocole hors population (l'ancien critère) → « le PARENT sort sans le
     canal » ; G2 marqueur non comparé (`if lus` au lieu de `lus & poses`) → « la condition lit une
     variable que le test ne POSE pas » ; G3 auxiliaire non suivi → « bras de l'enfant par un
     auxiliaire » ; G4 auxiliaire admis sans comparer sa variable → « l'auxiliaire lit une AUTRE
     variable » ; G5 premier bras seul (`break`) → « DEUX bras d'enfant » ; G6 `return` jugé hors
     du bloc direct du bras → « `return` NICHÉ dans le bras » ; G7 famille des branches sautée pour
     un protocole → « branche d'environnement du PARENT » ; G8 bras non exclu de la famille des
     branches → « bras de l'enfant SANS `return` » ; G9 `env::var_os(` non lu → « lu par
     `env::var_os` » ; G10 faute sans la phrase du protocole → « la condition lit une variable que
     le test ne POSE pas » ; G11 dernier argument de `.env(` au lieu du premier → « le PARENT sort
     sans le canal » ; G12 variables posées lues sur tout le fichier au lieu du corps du test
     (`premiers_arguments(brut, net, 0, len(net), ".env(")`) → « la variable est posée par un AUTRE
     test du même fichier ».

LES BORNES DE LECTURE (vague BG) : la variable n'est lue que dans la CONDITION du `if` (de `if` à
l'accolade qui ouvre sa branche) et dans le CORPS de l'auxiliaire appelé par cette condition (de son
accolade à celle qui le ferme). Une borne repoussée ramasse une lecture voisine — le bras de l'enfant
du même test, un test suivant du fichier — fait du `if` du PARENT un bras de l'enfant et blanchit son
`return` muet. MESURÉ : sous chacun des cinq premiers mutants ci-dessous, la garde d'avant ces
témoins rendait rc=0 sur l'arbre, et l'épreuve BE4 (appel au canal retiré du parent,
`liste_d_exemption_ssrf_lue_entree_par_entree.rs`, refus de conclure du premier témoin (d)) rendait
rc=0 sous PM_AUX_JUSQU_FIN, PM_AUX_DEPUIS_LE_DEBUT et PM_LUS_JUSQU_FIN ; elle rend rc=1 avec la garde,
rc=2 sous chacun des six.
Chaque témoin rougit SEUL sous son mutant (jugé hors de l'ordre des témoins) :
  G13 (PM_AUX_JUSQU_FIN) corps de l'auxiliaire lu jusqu'à la fin du fichier
     (`marqueurs_lus(brut, net, ouvre, len(net))`) → « l'auxiliaire du PARENT ne lit pas la
     variable, lue PLUS LOIN dans le fichier » ; G14 (PM_AUX_DEPUIS_LE_DEBUT) corps de l'auxiliaire
     lu depuis le début du fichier (`marqueurs_lus(brut, net, 0, ferme)`) → « … lue PLUS HAUT dans
     le fichier » ; G15 (PM_LUS_JUSQU_FIN) condition lue jusqu'à la fin du fichier
     (`marqueurs_lus(brut, net, pos + 2, len(net))`) → « le `if` du PARENT vient AVANT le bras de
     l'enfant » et « la variable est lue APRÈS le test, hors de toute condition » ; G16
     (PM_BRAS_COND_A_FIN_DU_TEST) condition lue jusqu'à la fin du test
     (`marqueurs_lus(brut, net, pos + 2, fin)`) → « le `if` du PARENT vient AVANT le bras de
     l'enfant » ; G17 (PM_APPELS_A_FIN_DU_TEST) auxiliaires cherchés jusqu'à la fin du test
     (`re.finditer(r"\\w+", net[pos + 2:fin])`) → « l'auxiliaire qui lit la variable est appelé APRÈS
     la condition du PARENT » ; G18 (PM_LUS_DEPUIS_LE_DEBUT_DU_TEST) condition lue depuis le début du
     test (`marqueurs_lus(brut, net, acc, j)`) → « le PARENT sort sans le canal », rouge aussi
     avant ces témoins.
LES AUTRES BORNES (vague BG, correction après vérification) — sous chacun de ces mutants, la garde
d'avant ces témoins rendait rc=0, témoins verts ; chacun rend rc=2 désormais, le témoin nommé rouge :
  G19 (PM_APPELS_DEPUIS_LE_DEBUT_DU_TEST) auxiliaires cherchés depuis le début du test
     (`re.finditer(r"\\w+", net[acc:j])`) → « bras de l'enfant par un auxiliaire, PUIS un `if` du
     PARENT muet ». MESURÉ : sous ce mutant, l'arbre passait de 28 chemins jugés à 26 — les deux
     parents (d) de `liste_d_exemption_ssrf_lue_entree_par_entree.rs` sortaient de la population,
     l'auxiliaire `jouer_dans_l_enfant`, appelé dans le bras de l'enfant, lisant la variable posée ;
  G20 (PM_POSES_JUSQU_FIN) variables posées lues jusqu'à la fin du fichier
     (`premiers_arguments(brut, net, acc, len(net), ".env(")`) → « la variable du PARENT est posée
     par un test SUIVANT du fichier » (G12 ne tient que le début de cette plage) ;
  G21 (PM_DEF_PREFIXE) auxiliaire cherché sans sa parenthèse (`f"fn {nom}"`) → « le PARENT appelle
     `repertoire()` » et « auxiliaire GÉNÉRIQUE `fn nom<T>(` non trouvé » ;
  G22 (PM_PHRASE_MEME_AVEC_BRAS) phrase du protocole ajoutée même avec un bras reconnu
     (`if protocole:`) → « bras de l'enfant par un auxiliaire, PUIS un `if` du PARENT muet »
     (fragment exigé ABSENT) ;
  G23 (PM_PHRASE_SANS_PROTOCOLE) phrase du protocole ajoutée à tout test sans bras (`if not bras:`)
     → « test ORDINAIRE : sa faute ne parle pas d'un binaire relancé ».
LES BORNES PROCHES ET LES DEUX MOITIÉS DU PROTOCOLE (vague BH) — G15 à G17 ne tenaient que les bornes
lointaines (fin du test, fin du fichier). La borne la plus proche, l'accolade qui FERME la branche du
`if` au lieu de celle qui l'ouvre, ramasse une lecture ou un appel écrit DANS la branche d'un `if` du
PARENT : ce `if` devenait un bras de l'enfant et son `return` muet était blanchi. Et aucun témoin ne
tenait l'une ou l'autre moitié de la conjonction `current_exe()` ET `.env(` : un test qui pose `.env(X)`
sur un AUTRE binaire, et dont un `if` lit X, aurait eu son `return` blanchi. Sous chacun des mutants
ci-dessous, la garde d'avant ces témoins rendait rc=0, témoins verts, arbre inchangé ; chacun rend rc=2
désormais, son témoin rouge SEUL (jugé hors de l'ordre des témoins) :
  G24 (V_LUS_JUSQU_FIN_DE_LA_BRANCHE) condition lue jusqu'à l'accolade qui ferme la branche
     (`marqueurs_lus(brut, net, pos + 2, fin_de_bloc(net, j) or j)`) → « le `if` du PARENT lit la
     variable DANS sa branche, pas dans sa condition » ;
  G25 (V_APPELS_JUSQU_FIN_DE_LA_BRANCHE) auxiliaires cherchés jusqu'à l'accolade qui ferme la branche
     (`re.finditer(r"\\w+", net[pos + 2:(fin_de_bloc(net, j) or j)])`) → « le `if` du PARENT appelle
     l'auxiliaire qui lit la variable DANS sa branche » ;
  G26 (V_BRAS_SANS_PROTOCOLE) bras calculés sans tester le protocole
     (`bras = bras_de_l_enfant(net, brut, acc, fin)`) → « `.env(` sur un AUTRE binaire, sans
     `current_exe()` » ;
  G27 (V_PROTOCOLE_SANS_CURRENT_EXE) protocole reconnu par `.env(` seul → le même témoin ;
  G28 (V_PROTOCOLE_SANS_ENV) protocole reconnu par `current_exe()` seul → « `current_exe()` sans
     `.env(` : pas de protocole, la faute n'en parle pas » (la phrase du protocole s'y ajoutait) ;
  G29 (PM_COND_YIELD_SANS_ACCOLADE) un `if` sans accolade à profondeur nulle rendu quand même, sa
     condition coupée à la fin du test (`yield pos, min(j, fin - 1)`) → « garde de motif `if` dans
     `matches!`, sans accolade, suivie d'une fonction ». Le mutant n'est PAS équivalent : la garde de
     motif lit alors le bras de l'enfant écrit plus loin dans le test, et sa « branche », appariée
     depuis la fin du test, se referme dans la fonction SUIVANTE du fichier — elle couvre le `if` muet
     du PARENT. Sans fonction imbriquée après le test, l'appariement ne se referme pas et rien ne
     change : c'est pourquoi le témoin porte une fonction suivante ;
  G30 (V_COND_PROF_IGNOREE) accolade de la branche cherchée à toute profondeur de parenthèses
     (`elif c == "{":`) → « condition du bras qui porte une accolade entre parenthèses (closure) ».
     Avant ce témoin, ce mutant ne rougissait que par l'ARBRE (rc=1, un seul site d'un fichier de test
     qu'un autre travail peut réécrire), témoins verts.
MESURÉ SUR L'ARBRE (vague BH) : 28 chemins jugés, 258 hors population, aucun fautif, sous la garde
d'avant ces témoins comme sous celle-ci, et sous chacun des six mutants G24 à G29 : l'arbre ne porte
aujourd'hui aucune de ces formes, seuls les témoins fabriqués les tiennent.
LA PORTÉE DU PROTOCOLE ET LE CROCHET (vague BH, correction après vérification) — les témoins de G27 et
G28 n'avaient la moitié absente NULLE PART dans leur source : un protocole lu sur tout le fichier
restait vert. Sous chacun de ces mutants, la garde d'avant ces témoins rendait rc=0, témoins verts,
arbre inchangé ; chacun rend rc=2 désormais, son témoin rouge SEUL :
  G31 (V_PROTOCOLE_SUR_LE_FICHIER) les deux moitiés lues sur le fichier (`in net`) → « `current_exe()`
     dans un AUTRE test, `.env(` sur `sh` dans celui-ci » et « `current_exe()` dans une AIDE » : le
     `return` muet d'un test qui lance `sh` était blanchi ;
  G32 (V_CURRENT_EXE_SUR_LE_FICHIER) `current_exe()` seul lu sur le fichier → les deux mêmes témoins ;
  G33 (V_ENV_SUR_LE_FICHIER) `.env(` seul lu sur le fichier → « `.env(` seulement dans un AUTRE test » :
     la phrase du protocole s'ajoutait à la faute (pas de blanchiment) ;
  G34 (V_COND_CROCHETS_IGNORES) le crochet ne compte plus dans la profondeur (`if c in "(":`) → « motif
     de tranche `if let [S { .. }] = …` » : l'accolade du motif coupait la condition, le bras de
     l'enfant était jugé comme une sortie du test.
"""

import os
import re
import sys

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.realpath(os.path.join(ICI, "..", ".."))
CANAL = os.path.join(RACINE, "daemon", "src", "tests", "canal_de_refus.rs")

# LA DÉCOUPE DES ARGUMENTS EST CELLE DU LECTEUR PARTAGÉ, IMPORTÉE ET JAMAIS RECOPIÉE (`P10.21-f`).
# Ce fichier en portait une COPIE, restée en arrière quand le lecteur a appris le littéral de
# caractère (`P10.20-r`) puis le chevron (`P10.21-b`) : elle coupait sur la virgule d'une CHAÎNE et
# sur celle d'un GÉNÉRIQUE. Le module importé évalue sa propre racine À L'IMPORT (un `git rev-parse`
# quand aucun argument ne lui est passé) : on lui passe celle de cette garde, pour qu'il ne cherche
# aucun dépôt git (une archive dépliée en est dépourvue). Ses témoins sont JOUÉS par `temoins()` : un
# import n'exécute aucun témoin, et un lecteur amputé traverserait cette garde sans un mot.
sys.path.insert(0, ICI)
_ARGV = sys.argv
sys.argv = [_ARGV[0], RACINE]
try:
    from check_a_read_that_did_not_happen_is_never_served_as_a_fact import (  # noqa: E402
        arguments, temoins_des_lecteurs_de_forme)
finally:
    sys.argv = _ARGV

CODE_TENU = 0
CODE_VIOLE = 1
CODE_INSTRUMENT = 2

# L'APPEL EST RECONNU PAR SON CHEMIN QUALIFIÉ, jamais par le seul nom de la fonction : la caisse
# porte déjà un `qb_refuser_de_conclure` (le banc de `query_verify.rs`, qui PANIQUE au lieu de
# rendre la main) et un motif court les confondrait.
APPEL = "canal_de_refus::refuser_de_conclure"
VARIABLE_DECL = re.compile(r'const\s+VARIABLE_DU_CANAL\s*:\s*&str\s*=\s*"([^"]+)"\s*;')
ATTR_TEST = re.compile(r"#\[\s*(?:tokio::)?test\s*[\](]")

# CE QUI FAIT D'UNE CONDITION UNE LECTURE D'ENVIRONNEMENT. Sur-approximation ASSUMÉE : elle
# reconnaît l'appel ÉCRIT DANS LA CONDITION, jamais un mot d'aveu dans un corps. Ses faux négatifs
# sont NOMMÉS dans le bandeau — une condition qui délègue à un auxiliaire lui échappe.
LECTURES_D_ENVIRONNEMENT = (
    "env::var", "env::var_os", "cfg!(", ".exists()", "fs::read", "fs::metadata",
    "fs::read_dir", "fs::read_to_string", "fs::symlink_metadata", "libc::",
    "Command::new", "available_parallelism", "target_os",
)
ASSERTION = re.compile(r"\b(assert|assert_eq|assert_ne|debug_assert|panic|unreachable)\s*!")


# =================================================================================================
# L'ANALYSEUR — c'est LUI que les témoins fabriqués exercent, pas une copie.
# =================================================================================================
def sans_chaines_ni_commentaires(s):
    """Copie de `s` où chaînes, caractères et commentaires sont remplacés par des espaces.

    Les longueurs et les retours à la ligne sont PRÉSERVÉS : les positions calculées sur la copie
    valent sur l'original, donc un numéro de ligne reste juste. Sans ce blanchiment, une accolade
    dans une chaîne (« {annonce:?} ») décalerait tout l'appariement de blocs."""
    out = list(s)
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == "/" and i + 1 < n and s[i + 1] == "/":
            j = s.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif c == "/" and i + 1 < n and s[i + 1] == "*":
            prof, j = 0, i
            while j < n:
                if s[j] == "/" and j + 1 < n and s[j + 1] == "*":
                    prof += 1
                    j += 2
                elif s[j] == "*" and j + 1 < n and s[j + 1] == "/":
                    prof -= 1
                    j += 2
                    if prof == 0:
                        break
                else:
                    j += 1
            for k in range(i, min(j, n)):
                if s[k] != "\n":
                    out[k] = " "
            i = j
        elif c == "r" and i + 1 < n and s[i + 1] in '#"':
            j, d = i + 1, 0
            while j < n and s[j] == "#":
                d += 1
                j += 1
            if j < n and s[j] == '"':
                fin = s.find('"' + "#" * d, j + 1)
                fin = n if fin < 0 else fin + 1 + d
                for k in range(i, fin):
                    if s[k] != "\n":
                        out[k] = " "
                i = fin
            else:
                i += 1
        elif c == '"':
            j = i + 1
            while j < n:
                if s[j] == "\\":
                    j += 2
                    continue
                if s[j] == '"':
                    j += 1
                    break
                j += 1
            for k in range(i, min(j, n)):
                if s[k] != "\n":
                    out[k] = " "
            i = j
        elif c == "'":
            m = re.match(r"'(\\.|[^\\'])'", s[i:])
            if m:
                for k in range(i, i + m.end()):
                    out[k] = " "
                i += m.end()
            else:
                i += 1
        else:
            i += 1
    return "".join(out)


def fin_de_bloc(net, ouvrante):
    prof = 0
    for j in range(ouvrante, len(net)):
        if net[j] == "{":
            prof += 1
        elif net[j] == "}":
            prof -= 1
            if prof == 0:
                return j
    return None


def zones_a_ignorer(net, deb, fin):
    """Les intervalles du corps qui ne sont PAS le flot du test : closures, `fn` imbriquées,
    blocs `async`. Un `return` y sort de la closure, pas du test."""
    zones = []
    for m in re.finditer(r"(\|\s*[^|{}\n]*\||\|\|)\s*(->\s*[^{;]+)?\{", net[deb:fin]):
        a = deb + m.end() - 1
        b = fin_de_bloc(net, a)
        if b:
            zones.append((deb + m.start(), b))
    for m in re.finditer(r"\bfn\s+\w+", net[deb + 1:fin]):
        a0 = deb + 1 + m.start()
        acc = net.find("{", a0)
        if acc == -1 or acc > fin:
            continue
        b = fin_de_bloc(net, acc)
        if b:
            zones.append((a0, b))
    for m in re.finditer(r"\basync\s*(move\s*)?\{", net[deb:fin]):
        a = deb + m.end() - 1
        b = fin_de_bloc(net, a)
        if b:
            zones.append((deb + m.start(), b))
    return zones


def est_terminal(net, pos, fin):
    """Ce `return` est-il la DERNIÈRE instruction du corps du test ?

    Un `return` terminal ne saute rien : le test est déjà allé au bout. L'accuser serait une
    sur-accusation — pas une rançon (le geste est de retirer un mot), mais une garde qui accuse à
    tort finit par être désarmée. Le point-virgule qui clôt l'instruction est cherché à PROFONDEUR
    0, pour que `return Ok(());` soit reconnu comme une seule instruction."""
    prof = 0
    j = pos
    while j < fin:
        c = net[j]
        if c in "([{":
            prof += 1
        elif c in ")]}":
            prof -= 1
        elif c == ";" and prof == 0:
            return net[j + 1:fin].strip() == ""
        j += 1
    return False


def ouvrante_du_bloc(net, deb, pos):
    """L'accolade qui ouvre le bloc le plus INTÉRIEUR contenant `pos`, en remontant depuis `deb`."""
    pile = []
    for j in range(deb, pos):
        if net[j] == "{":
            pile.append(j)
        elif net[j] == "}":
            if pile:
                pile.pop()
    return pile[-1] if pile else deb


def arguments_de_l_appel(brut, parenthese):
    """Les arguments NON VIDES de l'appel dont la `(` est en `parenthese`, lus dans le texte brut
    (les littéraux y sont intacts : le nom du test se compare à son `"…"`), ou None si l'appel ne se
    referme pas. Découpés par `arguments`, le lecteur PARTAGÉ : une virgule écrite dans une chaîne ou
    dans un générique ne coupe pas.

    CE QUE LA COPIE D'ORIGINE COUPAIT AUTREMENT, MESURÉ le 2026-09-23 sur l'instantané 69284b7 : sur
    les 21 appels au canal de `daemon/src`, CINQ se découpaient autrement, tous pour une virgule
    ÉCRITE DANS la cause (`tests/sec.rs`, `tests/vieillissement_serie.rs`) — quatre ou cinq
    arguments lus au lieu de trois ; AUCUN pour un chevron. Verdict inchangé sur les cinq : la garde
    ne juge que le compte (au moins trois) et les deux premiers arguments, et une coupure en trop ne
    fait que MULTIPLIER les morceaux de la cause. Armé, pas mordant : la copie ne pouvait pas faire
    passer un appel fautif, mais sur un deuxième argument qui porte une virgule (chaîne ou générique)
    elle citait dans l'accusation un FRAGMENT (`nom_de::<A`) au lieu de dire qu'il manque un
    argument — les témoins fabriqués tiennent les deux formes."""
    tranches, _fermante = arguments(brut, parenthese)
    if tranches is None:
        return None
    return [a for a in (brut[deb:fin].strip() for deb, fin in tranches) if a != ""]


def faute_des_arguments(brut, trouve, nom):
    """L'appel trouvé à l'offset `trouve` porte-t-il ses trois arguments, et nomme-t-il SON test ?
    Rend la faute, ou None. Une seule rédaction pour les deux familles."""
    par = brut.find("(", trouve + len(APPEL))
    args = arguments_de_l_appel(brut, par) if par != -1 else None
    if args is None or len(args) < 3:
        return ("l'appel au canal n'a pas ses trois arguments "
                "(`module_path!()`, le nom du test, la cause).")
    if args[0] != "module_path!()":
        return (f"le 1er argument du canal est `{args[0]}` et non `module_path!()` : "
                "un chemin de module écrit à la main dérive au premier déplacement.")
    if args[1] != f'"{nom}"':
        return (f"le canal est appelé avec {args[1]} alors que le test s'appelle "
                f"`{nom}` : l'aveu enverrait chercher au mauvais endroit.")
    return None


def appel_dans_le_bloc(net, ouvrante, borne):
    """L'offset du dernier `APPEL` écrit DANS le bloc ouvert en `ouvrante`, à SA profondeur, avant
    `borne`. C'est LE critère positionnel : un appel niché dans un sous-bloc ne compte pas."""
    trouve, prof, j = None, 0, ouvrante + 1
    while j < borne:
        if net[j] == "{":
            prof += 1
        elif net[j] == "}":
            prof -= 1
        elif prof == 0 and net.startswith(APPEL, j):
            trouve = j
        j += 1
    return trouve


def conditions_des_if(net, acc, fin):
    """Chaque `if` du corps, dans l'ordre : (position du mot `if`, position de l'accolade qui ouvre
    sa branche). LA CONDITION va de `if` à cette accolade, à profondeur nulle de parenthèses. Une
    seule lecture pour les deux usages (branches muettes, bras de l'enfant)."""
    for m in re.finditer(r"\bif\b", net[acc:fin]):
        pos = acc + m.start()
        j, prof = pos + 2, 0
        while j < fin:
            c = net[j]
            if c in "([":
                prof += 1
            elif c in ")]":
                prof -= 1
            elif c == "{" and prof == 0:
                break
            j += 1
        if j < fin:
            yield pos, j


def premiers_arguments(brut, net, deb, fin, appel):
    """Le premier argument, tel qu'écrit, de chaque appel `appel(` (texte exact, parenthèse
    comprise) écrit entre `deb` et `fin` hors chaînes et commentaires."""
    trouves = set()
    j = net.find(appel, deb)
    while j != -1 and j < fin:
        args = arguments_de_l_appel(brut, j + len(appel) - 1)
        if args:
            trouves.add(args[0])
        j = net.find(appel, j + 1)
    return trouves


def marqueurs_lus(brut, net, deb, fin):
    """Les variables d'environnement LUES entre `deb` et `fin` : premier argument de `env::var(`
    et de `env::var_os(`."""
    return (premiers_arguments(brut, net, deb, fin, "env::var(")
            | premiers_arguments(brut, net, deb, fin, "env::var_os("))


def bras_de_l_enfant(net, brut, acc, fin):
    """LES BRAS DE L'ENFANT d'un test qui relance son binaire : CHAQUE `if` du corps dont la
    condition lit (`env::var(` ou `env::var_os(`) une variable que ce test POSE chez l'enfant par
    `.env(` — directement, ou par un appel d'une fonction du MÊME fichier dont le corps la lit (un
    niveau : `if let Some(dir) = repertoire_de_l_enfant("…")`). Un test peut en porter PLUSIEURS (un
    écrivain, puis la sous-commande : `sous_commandes_ne_creent_ni_ne_delient_la_base.rs`). Rend la
    liste des (position du `if`, accolade qui ferme sa branche), vide si aucun `if` ne la lit."""
    poses = premiers_arguments(brut, net, acc, fin, ".env(")
    bras = []
    for pos, j in conditions_des_if(net, acc, fin):
        lus = marqueurs_lus(brut, net, pos + 2, j)
        for appel in re.finditer(r"\w+", net[pos + 2:j]):
            dfn = net.find(f"fn {appel.group(0)}(")
            ouvre = net.find("{", dfn) if dfn != -1 else -1
            ferme = fin_de_bloc(net, ouvre) if ouvre != -1 else None
            if ferme is not None:
                lus |= marqueurs_lus(brut, net, ouvre, ferme)
        ferme = fin_de_bloc(net, j) if lus & poses else None
        if ferme is not None:
            bras.append((pos, ferme))
    return bras


PROTOCOLE_SANS_BRAS = (" CE TEST RELANCE SON BINAIRE (`current_exe()` et `.env(`), mais aucun `if` "
                       "ne lit par `env::var(`/`env::var_os(` une variable qu'il pose par `.env(` : "
                       "le bras de l'enfant n'est pas reconnu, et chaque `return` est jugé comme une "
                       "sortie du test.")


def branches_muettes(net, brut, acc, fin, zones, nom, chemin):
    """LA SECONDE FAMILLE (`P11.23-e`) : une branche conditionnée par une lecture d'environnement,
    qui porte l'assertion et ne sort pas, dont la JUMELLE ne porte aucun verdict."""
    sites = []
    for pos, j in conditions_des_if(net, acc, fin):
        if any(a <= pos <= b for a, b in zones):
            continue
        cond = net[pos + 2:j]
        if not any(lecture in cond for lecture in LECTURES_D_ENVIRONNEMENT):
            continue
        f_then = fin_de_bloc(net, j)
        if f_then is None:
            continue
        corps_then = net[j:f_then + 1]
        # La branche doit PORTER un verdict, et ne pas SORTIR (cette forme-là est déjà tenue).
        if not ASSERTION.search(corps_then):
            continue
        if re.search(r"\breturn\b", corps_then):
            continue
        ligne = brut[:pos].count("\n") + 1
        site = {"fichier": chemin, "ligne": ligne, "test": nom,
                "hors_population": False, "famille": "branche", "faute": None}
        m_else = re.match(r"\s*else\b", net[f_then + 1:])
        if not m_else:
            site["faute"] = ("cette branche est conditionnée par une lecture d'ENVIRONNEMENT, elle "
                             "porte l'assertion du test, et elle n'a PAS de jumelle : quand la "
                             "condition est fausse, le test rend la main sans rien avoir prouvé et "
                             "sans le dire. Écrire la jumelle : `else { "
                             "crate::tests::canal_de_refus::refuser_de_conclure(module_path!(), "
                             f'"{nom}", "<pourquoi rien n\'a pu être mesuré ici>") }}`.')
            sites.append(site)
            continue
        apres = f_then + 1 + m_else.end()
        if re.match(r"\s*if\b", net[apres:]):
            continue  # chaîne `else if` : hors population, borne dite dans le bandeau
        k = net.find("{", apres)
        if k == -1 or k > fin:
            continue
        f_else = fin_de_bloc(net, k)
        if f_else is None:
            continue
        if ASSERTION.search(net[k:f_else + 1]):
            continue  # la jumelle porte SON propre verdict : rien n'est muet
        trouve = appel_dans_le_bloc(net, k, f_else)
        if trouve is None:
            site["faute"] = ("la jumelle de cette branche d'environnement ne porte AUCUN verdict et "
                             "n'appelle PAS le canal : la propriété que ce test nomme n'est pas "
                             "exercée, et rien ne le dit. Écrire, dans CE bloc `else` : "
                             "`crate::tests::canal_de_refus::refuser_de_conclure(module_path!(), "
                             f'"{nom}", "<pourquoi rien n\'a pu être mesuré ici>")`.')
        else:
            site["faute"] = faute_des_arguments(brut, trouve, nom)
        sites.append(site)
    return sites


def analyser(brut, chemin="<fabriqué>"):
    """Rend (sites, tests_vus). Un site = un dict décrivant UN `return` de test et son verdict.

    C'est la SEULE fonction de jugement : les témoins fabriqués et l'arbre réel passent par elle."""
    net = sans_chaines_ni_commentaires(brut)
    sites, tests_vus = [], 0
    for m in ATTR_TEST.finditer(net):
        mf = re.search(r"\bfn\s+(\w+)\s*(?:<[^>]*>)?\s*\(", net[m.end():])
        if not mf:
            continue
        nom = mf.group(1)
        acc = net.find("{", m.end() + mf.end())
        if acc == -1:
            continue
        fin = fin_de_bloc(net, acc)
        if fin is None:
            continue
        tests_vus += 1
        corps_net = net[acc:fin]
        # PROTOCOLE DE RÉ-EXÉCUTION : le test relance SON PROPRE binaire avec un environnement
        # modifié. Le bras de l'ENFANT sort tôt par construction : HORS POPULATION, et lui seul. Le
        # PARENT, qui peut refuser de conclure (localhost qui ne rend pas ses deux adresses), est
        # jugé comme tout test.
        protocole = "current_exe()" in corps_net and ".env(" in corps_net
        bras = bras_de_l_enfant(net, brut, acc, fin) if protocole else []
        zones = zones_a_ignorer(net, acc, fin)
        for r in re.finditer(r"\breturn\b", corps_net):
            pos = acc + r.start()
            if any(a <= pos <= b for a, b in zones):
                continue
            if est_terminal(net, pos, fin):
                continue
            ligne = brut[:pos].count("\n") + 1
            site = {"fichier": chemin, "ligne": ligne, "test": nom,
                    "hors_population": False, "famille": "sortie", "faute": None}
            if any(a <= pos <= b for a, b in bras):
                site["hors_population"] = True
                sites.append(site)
                continue
            # ── LE CRITÈRE EST POSITIONNEL : l'appel doit être dans LE BLOC du `return`, au même
            #    niveau d'accolades. Un aveu ailleurs dans le test ne blanchit pas ce chemin-ci.
            ouv = ouvrante_du_bloc(net, acc, pos)
            trouve = appel_dans_le_bloc(net, ouv, pos)
            if trouve is None:
                site["faute"] = ("ce `return` sort du test SANS passer par le canal. Écrire, dans "
                                 "CE bloc et juste avant lui : "
                                 "`crate::tests::canal_de_refus::refuser_de_conclure(module_path!(), "
                                 f'"{nom}", "<pourquoi rien n\'a pu être mesuré ici>")`.')
                if protocole and not bras:
                    site["faute"] += PROTOCOLE_SANS_BRAS
                sites.append(site)
                continue
            site["faute"] = faute_des_arguments(brut, trouve, nom)
            sites.append(site)
        # LA SECONDE FAMILLE — jugée sur les MÊMES zones à ignorer, plus le bras de l'enfant d'un
        # protocole de ré-exécution (qui n'est pas un aveuglement) ; le parent est jugé.
        sites.extend(branches_muettes(net, brut, acc, fin, zones + bras, nom, chemin))
    return sites, tests_vus


# =================================================================================================
# LES TÉMOINS — FABRIQUÉS ICI, jamais lus du dépôt. Ils s'exercent sur `analyser` elle-même.
# =================================================================================================
def temoins():
    """Rend None si l'instrument est sain, sinon la faute constatée."""
    # LES LECTEURS PARTAGÉS D'ABORD : `arguments` est importé, et ses témoins ne vivent pas ici.
    try:
        temoins_des_lecteurs_de_forme()
    except AssertionError as e:
        return f"lecteurs de forme Rust partagés (`arguments`, `apparier`) : {e}"
    A = 'crate::tests::canal_de_refus::refuser_de_conclure'
    cas = []

    cas.append(("POSITIF — retour NU, aucun aveu", """
        #[test]
        fn t_muet() {
            if !cfg!(target_os = "linux") { return; }
            assert!(true);
        }
    """, [("t_muet", True)]))

    cas.append(("NÉGATIF — retour précédé de l'appel, dans le bon bloc", """
        #[test]
        fn t_avoue() {
            if !cfg!(target_os = "linux") {
                %s(module_path!(), "t_avoue", "rien à mesurer ici");
                return;
            }
            assert!(true);
        }
    """ % A, [("t_avoue", False)]))

    # LE TÉMOIN QUI INTERDIT LA FAUSSE CORRECTION : un aveu AILLEURS dans le même test ne blanchit
    # pas un second chemin muet. Une garde qui chercherait le mot dans le CORPS passerait ce cas.
    cas.append(("POSITIF — un aveu dans le test, un SECOND chemin muet", """
        #[test]
        fn t_deux_sorties() {
            if a {
                %s(module_path!(), "t_deux_sorties", "porte A");
                return;
            }
            if b { return; }
            assert!(true);
        }
    """ % A, [("t_deux_sorties", False), ("t_deux_sorties", True)]))

    # ET SON JUMEAU : l'appel niché DANS un sous-bloc n'est pas sur le chemin du `return`.
    cas.append(("POSITIF — appel niché dans un sous-bloc, hors du chemin", """
        #[test]
        fn t_niche() {
            if a {
                if b { %s(module_path!(), "t_niche", "…"); }
                return;
            }
        }
    """ % A, [("t_niche", True)]))

    cas.append(("NÉGATIF — `return` dans une closure : ce n'est pas une sortie de test", """
        #[test]
        fn t_closure() {
            let f = |x: u8| { if x == 0 { return 1; } x };
            assert_eq!(f(0), 1);
        }
    """, []))

    cas.append(("NÉGATIF — protocole de ré-exécution : hors population", """
        #[test]
        fn t_reexec() {
            if std::env::var("MARQUEUR").is_ok() { assert!(true); return; }
            let exe = std::env::current_exe().unwrap();
            std::process::Command::new(exe).env("MARQUEUR", "1").output().unwrap();
        }
    """, [("t_reexec", False)]))

    cas.append(("POSITIF — le canal nomme un AUTRE test que celui qui l'appelle", """
        #[test]
        fn t_mal_nomme() {
            if a {
                %s(module_path!(), "t_le_voisin", "…");
                return;
            }
        }
    """ % A, [("t_mal_nomme", True)]))

    cas.append(("POSITIF — chemin de module écrit à la main au lieu de `module_path!()`", """
        #[test]
        fn t_module_en_dur() {
            if a {
                %s("plume_daemon::tests", "t_module_en_dur", "…");
                return;
            }
        }
    """ % A, [("t_module_en_dur", True)]))

    cas.append(("NÉGATIF — `return` TERMINAL : il ne saute rien", """
        #[test]
        fn t_return_terminal() {
            assert!(true);
            return;
        }
    """, []))

    cas.append(("NÉGATIF — `return Ok(());` terminal, point-virgule à profondeur 0", """
        #[test]
        fn t_return_ok_terminal() -> Result<(), ()> {
            assert!(true);
            return Ok(());
        }
    """, []))

    # PIÈGE D'ACCOLADE : une accolade DANS une chaîne ne doit pas décaler l'appariement de blocs.
    cas.append(("POSITIF — accolade dans une chaîne, l'appariement tient", """
        #[test]
        fn t_accolade_en_chaine() {
            let s = "{ ceci n'ouvre rien }";
            if a { return; }
            assert!(s.len() > 0);
        }
    """, [("t_accolade_en_chaine", True)]))

    # ── LA SECONDE FAMILLE (`P11.23-e`) : une branche d'environnement dont la jumelle est muette.
    cas.append(("POSITIF — branche d'environnement, AUCUNE jumelle", """
        #[test]
        fn t_branche_nue() {
            if std::env::var("PLUME_X").is_ok() {
                assert!(quelque_chose);
            }
            assert!(autre_chose);
        }
    """, [("t_branche_nue", True)]))

    cas.append(("NÉGATIF — branche d'environnement, jumelle qui AVOUE", """
        #[test]
        fn t_branche_avouee() {
            if std::env::var("PLUME_X").is_ok() {
                assert!(quelque_chose);
            } else {
                %s(module_path!(), "t_branche_avouee", "levier posé : rien mesuré");
            }
        }
    """ % A, [("t_branche_avouee", False)]))

    # LE TÉMOIN QUI INTERDIT LA FAUSSE CORRECTION, DEUXIÈME FAMILLE : un aveu dans LA PREMIÈRE
    # jumelle ne blanchit pas la SECONDE. C'est la transposition exacte de `t_deux_sorties`, et un
    # critère d'appartenance au corps laisserait la seconde muette pour toujours.
    cas.append(("POSITIF — deux branches d'environnement, la seconde jumelle MUETTE", """
        #[test]
        fn t_deux_branches() {
            if std::env::var("A").is_ok() {
                assert!(un);
            } else {
                %s(module_path!(), "t_deux_branches", "porte A");
            }
            if std::env::var("B").is_ok() {
                assert!(deux);
            } else {
                let _ = 1;
            }
        }
    """ % A, [("t_deux_branches", False), ("t_deux_branches", True)]))

    cas.append(("POSITIF — l'aveu de la jumelle est NICHÉ dans un sous-bloc", """
        #[test]
        fn t_jumelle_nichee() {
            if cfg!(target_os = "linux") {
                assert!(un);
            } else {
                if bavard { %s(module_path!(), "t_jumelle_nichee", "…"); }
            }
        }
    """ % A, [("t_jumelle_nichee", True)]))

    cas.append(("NÉGATIF — la jumelle porte SON PROPRE verdict", """
        #[test]
        fn t_jumelle_qui_juge() {
            if std::env::var("A").is_ok() {
                assert!(un);
            } else {
                assert!(deux);
            }
        }
    """, []))

    cas.append(("NÉGATIF — condition qui ne lit PAS l'environnement : hors population", """
        #[test]
        fn t_condition_ordinaire() {
            if compte > 3 {
                assert!(un);
            }
            assert!(deux);
        }
    """, []))

    cas.append(("NÉGATIF — branche d'environnement DANS une closure", """
        #[test]
        fn t_branche_en_closure() {
            let f = || { if std::env::var("A").is_ok() { assert!(un); } };
            f();
            assert!(deux);
        }
    """, []))

    # ET LA FRONTIÈRE ENTRE LES DEUX FAMILLES : une branche qui SORT est jugée UNE fois, par la
    # règle du `return` — pas deux, ce qui doublerait l'accusation sur un site déjà conforme.
    cas.append(("NÉGATIF — branche d'environnement qui SORT avec son aveu : jugée UNE fois", """
        #[test]
        fn t_branche_qui_sort() {
            if !std::env::var("A").is_ok() {
                %s(module_path!(), "t_branche_qui_sort", "levier éteint");
                return;
            }
            assert!(un);
        }
    """ % A, [("t_branche_qui_sort", False)]))

    cas.append(("POSITIF — la jumelle avoue au nom d'un AUTRE test", """
        #[test]
        fn t_jumelle_mal_nommee() {
            if std::env::var("A").is_ok() {
                assert!(un);
            } else {
                %s(module_path!(), "t_le_voisin", "…");
            }
        }
    """ % A, [("t_jumelle_mal_nommee", True)]))

    # ── LA DÉCOUPE DES ARGUMENTS (`P10.21-f`) : une virgule de CHAÎNE ou de GÉNÉRIQUE dans le
    #    DEUXIÈME argument ne fait pas un troisième argument. La copie d'origine en faisait un, et
    #    l'accusation citait alors un fragment (`"t_frag` ou `nom_de::<A`) au lieu de dire ce qui
    #    manque. Les formes sont fabriquées ; la CLOSURE DE LECTURE tient le cas neutre : ses virgules
    #    de générique ne blanchissent ni n'accusent un appel juste.
    FAUTE_DU_COMPTE = "l'appel au canal n'a pas ses trois arguments"
    for nom, appel in (("virgule dans la chaîne du nom", '"t_frag, suite"'),
                       ("virgule d'un générique", "nom_de::<A, B>()")):
        sites, _ = analyser("""
        #[test]
        fn t_frag() {
            if a {
                %s(module_path!(), %s);
                return;
            }
        }
    """ % (A, appel), "<témoin>")
        fautes = [s["faute"] or "" for s in sites]
        if len(fautes) != 1 or not fautes[0].startswith(FAUTE_DU_COMPTE):
            return (f"témoin de DÉCOUPE « {nom} » : l'analyseur rend {fautes}, attendu une faute qui dit "
                    f"« {FAUTE_DU_COMPTE} » — la virgule d'une chaîne ou d'un générique coupe encore un "
                    "argument, et l'accusation cite un FRAGMENT")
    sites, _ = analyser("""
        #[test]
        fn t_cause_a_generique() {
            if a {
                %s(module_path!(), "t_cause_a_generique", &format!("{}", r.get::<_, i64>(0)));
                return;
            }
        }
    """ % A, "<témoin>")
    if [s["faute"] for s in sites] != [None]:
        return (f"témoin de DÉCOUPE « cause portant une closure de lecture » : {[s['faute'] for s in sites]} "
                "au lieu d'un site conforme")

    # ── LES TESTS EN SOUS-PROCESSUS (`P7.20-a`, vague BF) : seul le bras de l'ENFANT est hors
    #    population ; le PARENT qui refuse de conclure est jugé. (nom, source, sites jugés attendus,
    #    sites hors population attendus, fragment exigé dans la faute ou None.)
    E = "std::process::Command::new(std::env::current_exe().unwrap())"
    cas_proto = [
        ("POSITIF — protocole : le PARENT sort sans le canal (forme mesurée par BE4)", """
        #[test]
        fn t_parent_muet() {
            if std::env::var(ENFANT).is_ok() { jouer(); return; }
            if !localhost_double() { return; }
            let mut c = %s;
            c.env(ENFANT, "1");
            juger(c);
        }
    """ % E, [("t_parent_muet", True)], 1, None),
        ("NÉGATIF — protocole : le PARENT sort par le canal", """
        #[test]
        fn t_parent_avoue() {
            if std::env::var(ENFANT).is_ok() { jouer(); return; }
            if let Err(cause) = localhost_double() {
                %s(module_path!(), "t_parent_avoue", &cause);
                return;
            }
            let mut c = %s;
            c.env(ENFANT, "1");
            juger(c);
        }
    """ % (A, E), [("t_parent_avoue", False)], 1, None),
        ("POSITIF — protocole : la condition lit une variable que le test ne POSE pas", """
        #[test]
        fn t_marqueur_etranger() {
            if std::env::var(AUTRE).is_ok() { jouer(); return; }
            let mut c = %s;
            c.env(ENFANT, "1");
        }
    """ % E, [("t_marqueur_etranger", True)], 0, "le bras de l'enfant n'est pas reconnu"),
        ("NÉGATIF — protocole : bras de l'enfant par un auxiliaire du fichier", """
        fn repertoire_de_l_enfant(cas: &str) -> Option<String> {
            let v = std::env::var(ENFANT).ok()?;
            (v == cas).then(|| v)
        }
        #[test]
        fn t_auxiliaire() {
            if let Some(dir) = repertoire_de_l_enfant("x") { jouer(&dir); return; }
            let mut c = %s;
            c.env(ENFANT, "x");
        }
    """ % E, [], 1, None),
        ("POSITIF — protocole : l'auxiliaire lit une AUTRE variable", """
        fn repertoire_de_l_enfant(cas: &str) -> Option<String> {
            let v = std::env::var(AUTRE).ok()?;
            (v == cas).then(|| v)
        }
        #[test]
        fn t_auxiliaire_etranger() {
            if let Some(dir) = repertoire_de_l_enfant("x") { jouer(&dir); return; }
            let mut c = %s;
            c.env(ENFANT, "x");
        }
    """ % E, [("t_auxiliaire_etranger", True)], 0, "le bras de l'enfant n'est pas reconnu"),
        ("NÉGATIF — protocole : bras de l'enfant lu par `env::var_os`", """
        #[test]
        fn t_var_os() {
            if std::env::var_os(ENFANT).is_some() { crate::main(); return; }
            let mut c = %s;
            c.env(ENFANT, "1");
        }
    """ % E, [], 1, None),
        ("NÉGATIF — protocole : DEUX bras d'enfant (un écrivain, puis la sous-commande)", """
        #[test]
        fn t_deux_bras() {
            if let Ok(base) = std::env::var(ECRIVAIN) { ecrire(&base); return; }
            if std::env::var_os(ENFANT).is_some() { crate::main(); return; }
            %s.env(ECRIVAIN, "b").output().unwrap();
            %s.env(ENFANT, "1").output().unwrap();
        }
    """ % (E, E), [], 2, None),
        ("NÉGATIF — protocole : `return` NICHÉ dans le bras de l'enfant", """
        #[test]
        fn t_retour_niche() {
            if std::env::var(ENFANT).is_ok() {
                for x in cas() { if x.vide() { return; } }
                jouer();
                return;
            }
            let mut c = %s;
            c.env(ENFANT, "1");
        }
    """ % E, [], 2, None),
        ("POSITIF — protocole : branche d'environnement du PARENT, sans jumelle", """
        #[test]
        fn t_branche_du_parent() {
            if std::env::var(ENFANT).is_ok() { jouer(); return; }
            let mut c = %s;
            c.env(ENFANT, "1");
            if std::env::var("PLUME_X").is_ok() {
                assert!(juger(c));
            }
        }
    """ % E, [("t_branche_du_parent", True)], 1, None),
        ("NÉGATIF — protocole : bras de l'enfant SANS `return`, jumelle sans verdict", """
        #[test]
        fn t_bras_sans_retour() {
            if std::env::var(ENFANT).is_ok() {
                assert!(jouer());
            } else {
                let s = %s.env(ENFANT, "1").status().unwrap();
                consigner(s);
            }
        }
    """ % E, [], 0, None),
        ("POSITIF — protocole : la variable est posée par un AUTRE test du même fichier", """
        #[test]
        fn t_autre() {
            if std::env::var(AUTRE).is_ok() { jouer(); return; }
            let mut c = %s;
            c.env(AUTRE, "1");
        }
        #[test]
        fn t_parent_garde_par_l_autre() {
            if std::env::var(ENFANT).is_ok() { jouer(); return; }
            if std::env::var(AUTRE).is_ok() { return; }
            let mut c = %s;
            c.env(ENFANT, "1");
        }
    """ % (E, E), [("t_parent_garde_par_l_autre", True)], 2, None),
        # ── LES BORNES DE LECTURE (vague BG) : la variable n'est lue QUE dans la condition du `if`
        #    (de `if` à son accolade) et dans le CORPS de l'auxiliaire appelé (de son accolade à celle
        #    qui le ferme). Chaque témoin place une lecture de la variable posée JUSTE HORS d'une borne :
        #    une borne repoussée la ramasse, fait du `if` du PARENT un bras de l'enfant et blanchit son
        #    `return` muet. Forme mesurée par BE4 : l'auxiliaire est écrit avant les tests, et les tests
        #    suivants du fichier lisent la variable.
        ("POSITIF — protocole : l'auxiliaire du PARENT ne lit pas la variable, lue PLUS LOIN dans le fichier", """
        fn localhost_double() -> bool { resoudre("localhost").len() == 2 }
        #[test]
        fn t_aux_avant() {
            if std::env::var(ENFANT).is_ok() { jouer(); return; }
            if !localhost_double() { return; }
            let mut c = %s;
            c.env(ENFANT, "1");
        }
    """ % E, [("t_aux_avant", True)], 1, None),
        ("POSITIF — protocole : l'auxiliaire du PARENT ne lit pas la variable, lue PLUS HAUT dans le fichier", """
        #[test]
        fn t_aux_apres() {
            if std::env::var(ENFANT).is_ok() { jouer(); return; }
            if !localhost_double() { return; }
            let mut c = %s;
            c.env(ENFANT, "1");
        }
        fn localhost_double() -> bool { resoudre("localhost").len() == 2 }
    """ % E, [("t_aux_apres", True)], 1, None),
        ("POSITIF — protocole : le `if` du PARENT vient AVANT le bras de l'enfant", """
        #[test]
        fn t_parent_d_abord() {
            if !localhost_double() { return; }
            if std::env::var(ENFANT).is_ok() { jouer(); return; }
            let mut c = %s;
            c.env(ENFANT, "1");
        }
    """ % E, [("t_parent_d_abord", True)], 1, None),
        ("POSITIF — protocole : la variable est lue APRÈS le test, hors de toute condition", """
        #[test]
        fn t_lu_apres_le_test() {
            if std::env::var(ENFANT).is_ok() { jouer(); return; }
            if !localhost_double() { return; }
            let mut c = %s;
            c.env(ENFANT, "1");
        }
        fn marqueur_de_l_enfant() -> bool { std::env::var(ENFANT).is_ok() }
    """ % E, [("t_lu_apres_le_test", True)], 1, None),
        ("POSITIF — protocole : l'auxiliaire qui lit la variable est appelé APRÈS la condition du PARENT", """
        fn repertoire_de_l_enfant(cas: &str) -> Option<String> {
            let v = std::env::var(ENFANT).ok()?;
            (v == cas).then(|| v)
        }
        #[test]
        fn t_appel_apres_la_condition() {
            if !localhost_double() { return; }
            if let Some(dir) = repertoire_de_l_enfant("x") { jouer(&dir); return; }
            let mut c = %s;
            c.env(ENFANT, "x");
        }
    """ % E, [("t_appel_apres_la_condition", True)], 1, None),
        # ── LES AUTRES BORNES (vague BG, correction) : le DÉBUT de la recherche des auxiliaires, la
        #    FIN de la lecture des variables posées, la parenthèse de `fn nom(`, et la phrase du
        #    protocole. Un fragment préfixé `!` doit être ABSENT de toute faute.
        ("POSITIF — protocole : bras de l'enfant par un auxiliaire, PUIS un `if` du PARENT muet", """
        fn repertoire_de_l_enfant(cas: &str) -> Option<String> {
            let v = std::env::var(ENFANT).ok()?;
            (v == cas).then(|| v)
        }
        #[test]
        fn t_aux_puis_parent() {
            if let Some(dir) = repertoire_de_l_enfant("x") { jouer(&dir); return; }
            if !localhost_double() { return; }
            let mut c = %s;
            c.env(ENFANT, "x");
        }
    """ % E, [("t_aux_puis_parent", True)], 1, "!le bras de l'enfant n'est pas reconnu"),
        ("POSITIF — protocole : la variable du PARENT est posée par un test SUIVANT du fichier", """
        #[test]
        fn t_premier() {
            if std::env::var(ENFANT).is_ok() { jouer(); return; }
            if std::env::var(AUTRE).is_ok() { return; }
            let mut c = %s;
            c.env(ENFANT, "1");
        }
        #[test]
        fn t_second() {
            if std::env::var(AUTRE).is_ok() { jouer(); return; }
            let mut c = %s;
            c.env(AUTRE, "1");
        }
    """ % (E, E), [("t_premier", True)], 2, None),
        ("POSITIF — protocole : le PARENT appelle `repertoire()`, seul `fn repertoire_de_l_enfant(` lit la variable", """
        fn repertoire_de_l_enfant(cas: &str) -> Option<String> {
            let v = std::env::var(ENFANT).ok()?;
            (v == cas).then(|| v)
        }
        #[test]
        fn t_prefixe() {
            if std::env::var(ENFANT).is_ok() { jouer(); return; }
            if repertoire().is_none() { return; }
            let mut c = %s;
            c.env(ENFANT, "1");
        }
    """ % E, [("t_prefixe", True)], 1, None),
        ("POSITIF — protocole : auxiliaire GÉNÉRIQUE `fn nom<T>(` non trouvé, le test est accusé", """
        fn repertoire_de_l_enfant<T: AsRef<str>>(cas: T) -> Option<String> {
            let v = std::env::var(ENFANT).ok()?;
            (v == cas.as_ref()).then(|| v)
        }
        #[test]
        fn t_generique() {
            if let Some(dir) = repertoire_de_l_enfant("x") { jouer(&dir); return; }
            let mut c = %s;
            c.env(ENFANT, "x");
        }
    """ % E, [("t_generique", True)], 0, "le bras de l'enfant n'est pas reconnu"),
        ("POSITIF — test ORDINAIRE : sa faute ne parle pas d'un binaire relancé", """
        #[test]
        fn t_ordinaire() {
            if !localhost_double() { return; }
            assert!(juger());
        }
    """, [("t_ordinaire", True)], 0, "!CE TEST RELANCE SON BINAIRE"),
        # ── LES BORNES PROCHES ET LE PROTOCOLE (vague BH) : la condition et ses appels s'arrêtent à
        #    l'accolade qui OUVRE la branche, pas à celle qui la ferme ; une lecture ou un appel écrit
        #    DANS la branche d'un `if` du PARENT n'en fait pas un bras de l'enfant. Et le protocole
        #    exige ses DEUX moitiés : `.env(` sur un autre binaire, ou `current_exe()` sans `.env(`, ne
        #    font pas de bras.
        ("POSITIF — protocole : le `if` du PARENT lit la variable DANS sa branche, pas dans sa condition", """
        #[test]
        fn t_lu_dans_la_branche() {
            if std::env::var(ENFANT).is_ok() { jouer(); return; }
            if !localhost_double() { eprintln!("{:?}", std::env::var(ENFANT)); return; }
            let mut c = %s;
            c.env(ENFANT, "1");
        }
    """ % E, [("t_lu_dans_la_branche", True)], 1, None),
        ("POSITIF — protocole : le `if` du PARENT appelle l'auxiliaire qui lit la variable DANS sa branche", """
        fn repertoire_de_l_enfant(cas: &str) -> Option<String> {
            let v = std::env::var(ENFANT).ok()?;
            (v == cas).then(|| v)
        }
        #[test]
        fn t_aux_dans_la_branche() {
            if std::env::var(ENFANT).is_ok() { jouer(); return; }
            if !localhost_double() { let _ = repertoire_de_l_enfant("x"); return; }
            let mut c = %s;
            c.env(ENFANT, "x");
        }
    """ % E, [("t_aux_dans_la_branche", True)], 1, None),
        ("POSITIF — `.env(` sur un AUTRE binaire, sans `current_exe()` : pas de protocole, pas de bras", """
        #[test]
        fn t_autre_binaire() {
            if std::env::var(ENFANT).is_ok() { return; }
            std::process::Command::new("sh").env(ENFANT, "1").status().unwrap();
        }
    """, [("t_autre_binaire", True)], 0, "!CE TEST RELANCE SON BINAIRE"),
        ("POSITIF — `current_exe()` sans `.env(` : pas de protocole, la faute n'en parle pas", """
        #[test]
        fn t_sans_env() {
            let exe = std::env::current_exe().unwrap();
            if !localhost_double() { return; }
            std::process::Command::new(exe).status().unwrap();
        }
    """, [("t_sans_env", True)], 0, "!CE TEST RELANCE SON BINAIRE"),
        # La condition d'un `if` sans accolade à profondeur nulle (garde de motif dans `matches!`) n'est
        # pas une condition : elle n'est pas rendue. Rendue jusqu'à la fin du test, elle lirait le bras de
        # l'enfant écrit PLUS LOIN, et sa « branche » s'apparierait dans la fonction SUIVANTE du fichier,
        # couvrant le `if` muet du PARENT.
        ("POSITIF — protocole : garde de motif `if` dans `matches!`, sans accolade, suivie d'une fonction", """
        #[test]
        fn t_garde_de_motif() {
            assert!(matches!(prealable(), Some(n) if n > 0));
            if std::env::var(ENFANT).is_ok() { jouer(); return; }
            if !localhost_double() { return; }
            let mut c = %s;
            c.env(ENFANT, "1");
        }
        fn suivante() { if a { b(); } }
    """ % E, [("t_garde_de_motif", True)], 1, None),
        # L'accolade qui ouvre la branche est cherchée à profondeur NULLE de parenthèses : celle d'une
        # closure écrite DANS la condition ne la coupe pas, sinon la lecture de la variable qui la suit
        # n'est pas vue et le bras de l'enfant est jugé comme une sortie du test.
        ("NÉGATIF — protocole : condition du bras qui porte une accolade entre parenthèses (closure)", """
        #[test]
        fn t_closure_dans_la_condition() {
            if std::env::args().any(|a| { a.is_empty() }) && std::env::var(ENFANT).is_ok() { jouer(); return; }
            let mut c = %s;
            c.env(ENFANT, "1");
        }
    """ % E, [], 1, None),
        # Le crochet compte dans la profondeur comme la parenthèse : l'accolade d'un motif de struct écrit
        # dans un motif de tranche (`if let [S { .. }] = …`) n'ouvre pas la branche.
        ("NÉGATIF — protocole : condition du bras à motif de tranche `if let [S { .. }] = …`", """
        #[test]
        fn t_motif_de_tranche() {
            if let [S { a, .. }] = lire(std::env::var(ENFANT)).as_slice() { jouer(a); return; }
            let mut c = %s;
            c.env(ENFANT, "1");
        }
    """ % E, [], 1, None),
        # LE PROTOCOLE SE LIT DANS LE CORPS DU TEST, jamais sur le fichier : `current_exe()` écrit dans un
        # AUTRE test ou dans une aide, ou `.env(` écrit dans un autre test, ne font pas de ce test-ci un
        # binaire relancé.
        ("POSITIF — `current_exe()` dans un AUTRE test, `.env(` sur `sh` dans celui-ci : pas de bras", """
        #[test]
        fn t_relance_a_cote() {
            if std::env::var(ENFANT).is_ok() { jouer(); return; }
            let mut c = %s;
            c.env(ENFANT, "1");
        }
        #[test]
        fn t_sh_a_cote() {
            if std::env::var(AUTRE).is_ok() { return; }
            std::process::Command::new("sh").env(AUTRE, "1").status().unwrap();
        }
    """ % E, [("t_sh_a_cote", True)], 1, None),
        ("POSITIF — `current_exe()` dans une AIDE du fichier, `.env(` dans le corps : pas de bras", """
        fn binaire() -> std::path::PathBuf { std::env::current_exe().unwrap() }
        #[test]
        fn t_binaire_par_une_aide() {
            if std::env::var(ENFANT).is_ok() { return; }
            std::process::Command::new(binaire()).env(ENFANT, "1").status().unwrap();
        }
    """, [("t_binaire_par_une_aide", True)], 0, None),
        ("POSITIF — `current_exe()` dans le corps, `.env(` seulement dans un AUTRE test : la faute n'en parle pas", """
        #[test]
        fn t_exe_sans_env_ici() {
            let exe = std::env::current_exe().unwrap();
            if !localhost_double() { return; }
            std::process::Command::new(exe).status().unwrap();
        }
        #[test]
        fn t_env_ailleurs() {
            assert!(std::process::Command::new("sh").env(AUTRE, "1").status().unwrap().success());
        }
    """, [("t_exe_sans_env_ici", True)], 0, "!CE TEST RELANCE SON BINAIRE"),
    ]
    for nom, source, attendu, hp_attendu, fragment in cas_proto:
        sites, _ = analyser(source, "<témoin>")
        obtenu = [(s["test"], s["faute"] is not None) for s in sites if not s["hors_population"]]
        hp = len([s for s in sites if s["hors_population"]])
        if obtenu != attendu or hp != hp_attendu:
            return (f"témoin « {nom} » : l'analyseur rend {obtenu} et {hp} site(s) hors population, "
                    f"attendu {attendu} et {hp_attendu}")
        if fragment and fragment.startswith("!"):
            if any(fragment[1:] in (s["faute"] or "") for s in sites):
                return f"témoin « {nom} » : la faute dit « {fragment[1:]} » à tort : {[s['faute'] for s in sites]}"
        elif fragment and not all(fragment in (s["faute"] or "") for s in sites if s["faute"]):
            return f"témoin « {nom} » : la faute ne dit pas « {fragment} » : {[s['faute'] for s in sites]}"

    for nom, source, attendu in cas:
        sites, _ = analyser(source, "<témoin>")
        obtenu = [(s["test"], s["faute"] is not None) for s in sites if not s["hors_population"]]
        # un site hors population est un site VU mais non jugé : on l'atteste séparément
        if nom.startswith("NÉGATIF — protocole"):
            hp = [s for s in sites if s["hors_population"]]
            if len(hp) != 1:
                return f"témoin « {nom} » : {len(hp)} site hors population, attendu 1"
            if obtenu:
                return f"témoin « {nom} » : {obtenu} jugé alors que le test est hors population"
            continue
        if obtenu != attendu:
            return f"témoin « {nom} » : l'analyseur rend {obtenu}, attendu {attendu}"

    # ÉPREUVE DE L'INSTRUMENT LUI-MÊME : un analyseur qui ne reconnaîtrait plus aucun test rendrait
    # « zéro violation » sur tout, et aucun témoin ci-dessus ne bougerait s'ils étaient vides.
    _, vus = analyser("#[test]\nfn a() { return; }\n#[test]\nfn b() { assert!(true); }", "<témoin>")
    if vus != 2:
        return f"l'analyseur ne reconnaît que {vus} fonction(s) de test sur 2 fabriquées"
    return None


# =================================================================================================
# LA CAISSE ET LE CANAL — dérivés, jamais recopiés.
# =================================================================================================
def variable_du_canal():
    try:
        source = open(CANAL, encoding="utf-8").read()
    except OSError:
        return None, None
    m = VARIABLE_DECL.search(source)
    return (m.group(1) if m else None), source


def caisse_du_canal():
    d = os.path.dirname(CANAL)
    while d.startswith(RACINE) and len(d) > len(RACINE):
        if os.path.exists(os.path.join(d, "Cargo.toml")):
            return d
        d = os.path.dirname(d)
    return None


def ecrivain_est_vivant(source):
    """Le canal ÉCRIT-il vraiment ? Un écrivain vidé laisserait tous les sites conformes et le
    canal mort : le lecteur ne saurait pas distinguer « personne n'a refusé » de « rien n'écrit »."""
    corps = re.search(r"pub\(crate\) fn refuser_de_conclure\b.*?\n    \}", source, re.S)
    if not corps:
        return "`refuser_de_conclure` INTROUVABLE dans le canal"
    c = corps.group(0)
    if "VARIABLE_DU_CANAL" not in c:
        return "le canal n'ouvre rien : sa fonction ne lit pas `VARIABLE_DU_CANAL`"
    if ".append(true)" not in c:
        return "le canal n'ouvre pas en AJOUT : deux refus s'écraseraient"
    if "write_all" not in c:
        return "le canal n'écrit rien : aucun `write_all` dans sa fonction"
    return None


# =================================================================================================
def mode_lire():
    """Le canal est RELU et SERVI, bruyamment. Il ne fait jamais échouer : un environnement aveugle
    n'a aucun geste pour refermer un rouge, ce serait une rançon."""
    variable, source = variable_du_canal()
    if variable is None:
        print("::error::le canal est introuvable ou `VARIABLE_DU_CANAL` a changé de forme "
              f"({os.path.relpath(CANAL, RACINE)}) : le lecteur REFUSE DE CONCLURE.", file=sys.stderr)
        return CODE_INSTRUMENT
    faute = ecrivain_est_vivant(source)
    if faute:
        print(f"::error::l'écrivain du canal est cassé ({faute}) : un journal vide ne voudrait rien "
              "dire, le lecteur REFUSE DE CONCLURE.", file=sys.stderr)
        return CODE_INSTRUMENT
    chemin = os.environ.get(variable, "")
    if not chemin:
        print(f"::error::`{variable}` n'est pas posée dans l'environnement de ce pas : le canal "
              "n'a pas été armé, donc « aucun refus » ne voudrait rien dire. Le lecteur REFUSE DE "
              "CONCLURE. Poser la variable dans le MÊME `run:` que la suite.", file=sys.stderr)
        return CODE_INSTRUMENT
    if not os.path.exists(chemin):
        print(f"canal relu ({variable}={chemin}) : AUCUN test n'a refusé de conclure. "
              "Chaque test de la suite a exercé son assertion.")
        return CODE_TENU
    try:
        lignes = [l for l in open(chemin, encoding="utf-8", errors="replace").read().splitlines() if l.strip()]
    except OSError as e:
        print(f"::error::journal des refus illisible ({chemin} : {e}) : le lecteur REFUSE DE CONCLURE.",
              file=sys.stderr)
        return CODE_INSTRUMENT
    if not lignes:
        print(f"canal relu ({variable}={chemin}) : AUCUN test n'a refusé de conclure.")
        return CODE_TENU
    print(f"::warning::{len(lignes)} test(s) ont REFUSÉ DE CONCLURE dans cette suite. Ils sont VERTS "
          "et ne prouvent RIEN : ce que la suite établit est plus étroit que ce que le compte de "
          "tests laisse croire.")
    for l in lignes:
        site, _, cause = l.partition("\t")
        print(f"::warning::REFUS DE CONCLURE — {site} : {cause}")
        print(f"  REFUS  {site}\n         {cause}")
    print(f"\n{len(lignes)} refus consigné(s). La suite reste VERTE À DESSEIN : un environnement "
          "aveugle n'a aucun geste pour refermer un rouge, et un rouge inrefermable est une rançon.")
    return CODE_TENU


def mode_garde():
    variable, source = variable_du_canal()
    if variable is None:
        print(f"::error::`VARIABLE_DU_CANAL` INTROUVABLE dans {os.path.relpath(CANAL, RACINE)} — la "
              "garde jugerait des sites contre un canal qui n'existe plus : elle REFUSE DE CONCLURE.",
              file=sys.stderr)
        return CODE_INSTRUMENT
    faute = ecrivain_est_vivant(source)
    if faute:
        print(f"::error::l'écrivain du canal est cassé ({faute}) : exiger que les sites l'empruntent "
              "n'achèterait rien. La garde REFUSE DE CONCLURE.", file=sys.stderr)
        return CODE_INSTRUMENT
    faute = temoins()
    if faute:
        print(f"::error::instrument INVALIDE ({faute}) : la garde REFUSE DE CONCLURE.", file=sys.stderr)
        return CODE_INSTRUMENT
    caisse = caisse_du_canal()
    if caisse is None:
        print("::error::la caisse du canal n'a pas pu être dérivée (aucun `Cargo.toml` au-dessus de "
              f"{os.path.relpath(CANAL, RACINE)}) : la garde REFUSE DE CONCLURE.", file=sys.stderr)
        return CODE_INSTRUMENT

    sources = os.path.join(caisse, "src")
    fichiers = []
    for d, _, fs in os.walk(sources):
        for f in sorted(fs):
            if f.endswith(".rs"):
                fichiers.append(os.path.join(d, f))
    if not fichiers:
        print(f"::error::aucun `.rs` sous {os.path.relpath(sources, RACINE)} : la garde REFUSE DE "
              "CONCLURE.", file=sys.stderr)
        return CODE_INSTRUMENT

    tous, tests, hors = [], 0, 0
    for chemin in sorted(fichiers):
        try:
            brut = open(chemin, encoding="utf-8").read()
        except OSError as e:
            print(f"::error::{os.path.relpath(chemin, RACINE)} illisible ({e}) : la garde REFUSE DE "
                  "CONCLURE.", file=sys.stderr)
            return CODE_INSTRUMENT
        sites, vus = analyser(brut, os.path.relpath(chemin, RACINE))
        tests += vus
        for s in sites:
            if s["hors_population"]:
                hors += 1
            else:
                tous.append(s)
    if tests == 0:
        print(f"::error::AUCUNE fonction de test reconnue dans {os.path.relpath(sources, RACINE)} : "
              "l'instrument ne voit rien, il REFUSE DE CONCLURE.", file=sys.stderr)
        return CODE_INSTRUMENT

    fautifs = [s for s in tous if s["faute"]]
    if fautifs:
        for s in fautifs:
            print(f"::error file={s['fichier']},line={s['ligne']}::{s['fichier']}:{s['ligne']} — "
                  f"test `{s['test']}` : {s['faute']}")
        print(f"::error::{len(fautifs)} chemin(s) de refus sur {len(tous)} n'empruntent pas le canal. "
              "Un test qui rend la main sans conclure et sans le dire se présente au portail comme un "
              "test qui a prouvé.", file=sys.stderr)
        return CODE_VIOLE

    sorties = len([s for s in tous if s.get("famille") == "sortie"])
    branches = len(tous) - sorties
    print(f"TENU — les {len(tous)} chemin(s) qui rendent la main sans conclure ({sorties} sortie(s) "
          f"anticipée(s), {branches} branche(s) d'environnement à jumelle muette), sur {tests} "
          f"fonctions de test de `{os.path.relpath(caisse, RACINE)}`, empruntent tous le canal "
          f"(`{variable}`), nomment leur propre test et prennent `module_path!()`. "
          f"{hors} site(s) hors population (bras de l'enfant d'un protocole de ré-exécution ; le parent est jugé).")
    print("POURQUOI CETTE GARDE EXISTE : `libtest` détourne la sortie d'un test qui RÉUSSIT — un "
          "refus imprimé depuis un test vert part dans le vide, et le portail comme la CI ne lisent "
          "que le code de sortie. Le critère est POSITIONNEL (l'appel doit être dans LE BLOC du "
          "`return`), jamais lexical : un aveu ailleurs dans le même test ne blanchit rien.")
    print("CE QU'ELLE N'ACCUSE PAS : un `return` TERMINAL (dernière instruction du corps) ne saute "
          "rien et reste hors population.")
    print("CE QU'ELLE NE TIENT PAS : une condition qui CACHE sa lecture d'environnement derrière un "
          "auxiliaire (deux sites réels de `branche_d_echec_muette.rs` sont dans ce cas) ; le `match` "
          "et les boucles sur une collection dérivée de l'environnement (mesurés : zéro et trois, ces "
          "trois-là portant déjà leur plancher) ; une chaîne `else if` ; un corpus qui perd sa matière "
          "(c'est un plancher dans l'instrument qui tient cette forme) ; une seule caisse, celle qui "
          "porte le canal ; le TEXTE, pas l'exécution (que le canal ait écrit, seul `--lire` le montre) ; "
          "dans un protocole de ré-exécution, tout `if` qui lit une variable posée chez l'enfant est un "
          "bras de l'enfant, et un auxiliaire n'est suivi que d'un niveau, dans le même fichier.")
    return CODE_TENU


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--lire":
        return mode_lire()
    if len(sys.argv) > 1:
        print(f"::error::usage : {os.path.basename(__file__)} [--lire]", file=sys.stderr)
        return CODE_INSTRUMENT
    return mode_garde()


if __name__ == "__main__":
    sys.exit(main())
