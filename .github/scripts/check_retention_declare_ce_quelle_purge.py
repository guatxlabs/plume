#!/usr/bin/env python3
"""`P4.9-a` — UN LEVIER DE RÉTENTION DÉCLARE TOUTES LES TABLES QU'IL PURGE.

CE QUI A ÉTÉ MESURÉ. Un lot a lu les NOMS des leviers de bonne foi et publié un horizon optimiste
d'un facteur quarante-cinq ; son témoin était vert parce qu'il vérifiait une constante contre
elle-même. Recensement dérivé du 2026-09-04, en suivant les instructions de suppression et jamais
les noms : TROIS des cinq leviers déclaraient moins qu'ils ne gouvernent — un nom qui porte
« metric » et purge le PRÉ-AGRÉGÉ (la table brute étant purgée par un voisin, en HEURES), un levier
qui purge TROIS tables en n'en nommant qu'une, un autre qui n'atteint que les alertes déjà traitées.

LA PROPRIÉTÉ TENUE, ET POURQUOI ELLE N'EST PAS CELLE QU'ON ÉCRIT D'ABORD. « Un levier nomme une
table qu'il gouverne » est trop faible : le levier des événements la satisferait tout en taisant deux
tables sur trois. La propriété est donc : **l'ensemble des tables purgées par la passe de rétention
est EXACTEMENT l'ensemble déclaré**, dans les deux sens — une purge ajoutée sans déclaration fait
rougir, une déclaration devenue fausse aussi.

CE QUI EST DÉRIVÉ, ET DE QUOI. Les clés viennent de `RETENTION_FIELDS`, les tables purgées viennent
du CORPS de la passe de rétention (les appels de purge et les instructions de suppression), et la
déclaration est ce qu'on compare aux deux. Aucun nom de table n'est écrit dans cette garde.

LE DÉPOUILLEUR RUST EST CELUI DU DÉPÔT (`P10.20-h`, mesuré le 2026-09-16)
------------------------------------------------------------------------
Cette garde portait son PROPRE dépouilleur — une substitution `//.*$` appliquée LIGNE PAR LIGNE, sans
la moindre notion de chaîne, de littéral de caractère, de commentaire de bloc ni de chaîne qui
franchit une fin de ligne. Il se trompait, et pas en théorie : sur les 168 fichiers de production de
`daemon/src` (100 676 lignes), il lisait 65 lignes de 21 fichiers autrement que le lecteur du dépôt —
60 CHAÎNES COUPÉES par un `//` posé dedans (une URL `"https://…"`, un `splitn(2, "://")`), et 5
COMMENTAIRES DE BLOC en fin de ligne (`bool /* asc */`) laissés tels quels, donc lus comme du code.
Aucune de ces 65 lignes ne portait un appel de purge ni une instruction de suppression : le défaut
était RÉEL et son effet sur le verdict d'aujourd'hui était NUL. Il ne l'aurait pas été le jour où une
URL aurait été écrite sur la même ligne qu'un `chunked_purge(…)`, ni le jour où une purge aurait été
mise en commentaire de bloc — ce second cas fabrique une ACCUSATION, pas un silence.

Le lecteur est désormais `sans_commentaires_rust` (`check_every_help_trigger_has_a_section`), celui
que `P10.20-c`, `P10.20-d` et `P10.20-e` ont éprouvé : il tient les chaînes (y compris celles qui
franchissent une fin de ligne), les chaînes brutes `r#"…"#`, les littéraux de caractère `'"'`, les
durées de vie et les commentaires de bloc, il PRÉSERVE LA HAUTEUR (vérifié ici par un témoin, et
mesuré : aucun des 168 fichiers ne change de hauteur), et il AVOUE quand il perd la synchronisation.
L'aveu est branché : cette garde REFUSE DE CONCLURE (code 2) en nommant la ligne plutôt que de rendre
un compte amputé en vert. Ses témoins (`temoins_du_lecteur`) sont joués avant tout verdict.

Les clés, la portée déclarée et le corps de la passe sont dérivés du texte DÉPOUILLÉ, jamais du texte
brut : une table `RETENTION_FIELDS` ou une entrée `FAMILLES_DE_RETENTION` écrite dans un commentaire
de bloc n'est plus une déclaration. Corrigé par CONSTRUCTION ; mesuré inerte sur cet arbre le
2026-09-16 (mêmes 5 clés, même portée de 5 clés, même corps de 240 lignes, même population de 2
sites), pas forcément sur celui qu'on écrira demain.

CE QUE CETTE GARDE NE TIENT PAS, ÉCRIT POUR ÊTRE OPPOSABLE :
  - elle voit les purges ÉCRITES DANS LE CORPS de la passe ; ce qu'une fonction APPELÉE supprime de
    son côté (le vieillissement vers le tier froid, par exemple) lui échappe — c'est une autre
    propriété, et la confondre ferait accuser à tort ;
  - elle ne vérifie pas QUEL levier gouverne QUELLE table, seulement que l'union coïncide : rattacher
    chaque table à son levier demanderait de suivre les variables de borne, et une garde qui se
    tromperait de rattachement serait pire que pas de garde ;
  - elle ne dit rien des UNITÉS ni des prédicats (« seulement les alertes déjà traitées ») : ceux-là
    vivent dans la déclaration et dans la documentation, à la lecture d'un humain ;
  - une purge écrite DANS UNE CHAÎNE reste lue comme du code : le dépouilleur rend les chaînes telles
    quelles au lieu de les aveugler (c'est ce qui permet de lire le nom de table, qui EST une chaîne).
    Assumé, et c'était déjà le cas avant ;
  - le corps des MACROS, les apostrophes d'ATTRIBUT et le code GÉNÉRÉ restent hors de la grammaire du
    dépouilleur (dit en tête de `sans_commentaires_rust`) ;
  - le corpus est celui de `daemon/src` hors `tests/` : une purge écrite dans une autre caisse est
    invisible, et c'est la même frontière qu'avant ce lot.

Sorties : 0 = déclaration exacte · 1 = REFUS nommé · 2 = REFUS DE CONCLURE.
"""
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_every_help_trigger_has_a_section import (  # noqa: E402  (LE LECTEUR RUST DU DÉPÔT — `P10.20-h`)
    refuser_sur_aveu, sans_commentaires_rust, temoins_du_lecteur)

ETIQUETTE = "retention-declare-ce-quelle-purge"

RACINE = Path("daemon/src")
MAIN = Path("daemon/src/main.rs")
PASSE = Path("daemon/src/rollups.rs")
FONCTION = "fn retention_run_tenant"

# LA DÉCLARATION VIT DANS UN SEUL FICHIER, ET C'EST LE PLUS RICHE (il porte aussi les UNITÉS).
# Une seconde table disant la même chose a existé quelques heures dans `main.rs` le 2026-09-04 : elle a
# été retirée, parce que deux déclarations d'une même relation dérivent — le défaut de `P8.9-n`.
DECLARATION = Path("daemon/src/handlers/panneau_avoue.rs")

# LES DEUX SITES QUI SUPPRIMENT DES LIGNES AU TITRE DU CYCLE DE VIE, mesurés le 2026-09-04 : la passe
# de rétention, et le vieillissement vers le tier froid — qui purge `event` depuis une fonction APPELÉE,
# donc invisible à un balayage borné à la passe. La liste sert de CONTRAT : un troisième site qui
# appellerait une aide de purge fait rougir tant qu'il n'est pas nommé ici et sa table déclarée.
SITES_DU_CYCLE_DE_VIE = [PASSE, Path("daemon/src/cold_store/aging.rs")]


def depouiller_texte(texte: str, journal=None) -> str:
    """LE LECTEUR DE CETTE GARDE, EN UN SEUL POINT — et c'est ce point que ses témoins exercent.
    L'écrire ici plutôt que d'appeler `sans_commentaires_rust` sur chaque site n'est pas cosmétique :
    une mutation de l'instrument qui remplacerait le lecteur SURVIVAIT tant que les témoins appelaient
    le lecteur partagé en direct au lieu de passer par le geste de la garde (mesuré le 2026-09-16, en
    jouant le mutant « ancienne substitution `//.*$` remise » : il survivait à neuf témoins verts)."""
    return sans_commentaires_rust(texte, journal)


def depouiller(chemin: Path, aveux: dict) -> str:
    """LE DÉPOUILLEMENT A LIEU ICI, où un NOM DE FICHIER existe : c'est ce qui permet à l'AVEU du
    lecteur d'être entendu plutôt que prononcé dans le vide (`P10.20-d`, `P10.20-h`). Une purge citée
    dans une explication n'est pas une purge, et une garde qui les confond accuse le texte qui la
    documente ; mais un `//` posé dans une URL n'est pas une explication, et une garde qui coupe là
    devient aveugle à ce qui suit SANS UN MOT."""
    texte = chemin.read_text(encoding="utf-8", errors="replace")
    journal = []
    src = depouiller_texte(texte, journal)
    if journal:
        aveux[str(chemin)] = [f"ligne {texte.count(chr(10), 0, o) + 1} : {m}" for m, o in journal]
    return src


def corpus_de_production(racine: Path, aveux: dict) -> dict:
    """`{chemin: texte dépouillé}` — le corpus de PRODUCTION, DÉRIVÉ de l'arbre et lu UNE FOIS. Les
    suites de tests sont hors du cycle de vie du produit."""
    out = {}
    for f in sorted(racine.rglob("*.rs")):
        if "/tests/" in str(f) or f.name == "tests.rs":
            continue
        out[f] = depouiller(f, aveux)
    return out


def cles_declarees(src: str) -> list:
    bloc = re.search(r"RETENTION_FIELDS[^=]*=\s*\[(.*?)\n\];", src, re.S)
    return re.findall(r'\(\s*"([a-z_][a-z0-9_]*)"', bloc.group(1)) if bloc else []


def portee_declaree(src: str) -> dict:
    """La déclaration UNIQUE, lue telle qu'elle est écrite — `(table, clé, unité)` — et INVERSÉE en
    `clé -> [tables]`. L'inversion se fait ici et nulle part ailleurs : c'est ce qui évite d'entretenir
    une seconde table dans l'autre sens."""
    bloc = re.search(r"FAMILLES_DE_RETENTION[^=]*=\s*&\[(.*?)\n\];", src, re.S)
    if not bloc:
        return {}
    out = {}
    for table, cle in re.findall(r'\(\s*"([a-z_][a-z0-9_]*)"\s*,\s*"([a-z_][a-z0-9_]*)"\s*,', bloc.group(1)):
        out.setdefault(cle, []).append(table)
    return {c: sorted(set(t)) for c, t in out.items()}


def corps_de_la_passe(src: str) -> str:
    """Le CORPS de la passe de rétention, borné à sa propre fonction : une purge écrite ailleurs dans
    le fichier n'est pas de la rétention."""
    i = src.find(FONCTION)
    if i < 0:
        return ""
    j = src.find("\npub(crate) fn ", i + 1)
    k = src.find("\nfn ", i + 1)
    fins = [x for x in (j, k) if x > 0]
    return src[i : min(fins)] if fins else src[i:]


def tables_par_les_aides(src: str) -> list:
    """Les tables supprimées par les AIDES DE PURGE — le canal du cycle de vie. Mesuré le 2026-09-04 :
    ces aides ne sont appelées que depuis deux fichiers, ce qui en fait une population sûre."""
    t = set()
    t |= set(re.findall(r'chunked_purge\(\s*\n?\s*db\s*,\s*\n?\s*"([a-z_][a-z0-9_]*)"', src))
    t |= set(re.findall(r'retention_prune_table\(\s*\n?\s*db\s*,\s*\n?\s*"([a-z_][a-z0-9_]*)"', src))
    return sorted(t)


def tables_par_instruction(corps: str) -> list:
    """Les tables supprimées par une instruction ÉCRITE À LA MAIN, cherchées UNIQUEMENT dans le corps de
    la passe. Les élargir au fichier entier accuserait des suppressions qui ne relèvent pas du cycle de
    vie — mesuré : plus de soixante-dix instructions de suppression dans le démon, presque toutes des
    gestes légitimes d'utilisateur. Une garde qui les compterait serait une rançon."""
    return sorted(set(re.findall(r'DELETE\s+FROM\s+([a-z_][a-z0-9_]*)', corps)))


def fichiers_qui_purgent(corpus: dict) -> list:
    """Quels fichiers de PRODUCTION appellent une aide de purge — la population, DÉRIVÉE de l'arbre.
    LE MÊME PRÉDICAT QUE L'EXTRACTION, et pas un autre : un fichier « purge » s'il en résulte une
    TABLE. Écarter les fichiers qui DÉFINISSENT une aide était trop grossier — la passe de rétention
    définit l'une d'elles ET l'appelle douze fois, et se serait exclue elle-même."""
    return [f for f in sorted(corpus) if tables_par_les_aides(corpus[f])]


def valider_linstrument() -> list:
    faux = []
    if cles_declarees('const RETENTION_FIELDS: [x; 1] = [\n    ("a_days", "E", 1, 2, 3),\n];') != ["a_days"]:
        faux.append("lecture des clés cassée")
    # LES NOMS FABRIQUÉS NE RESSEMBLENT PAS AUX NOMS RÉELS, ET C'EST DÉLIBÉRÉ : le 2026-09-04, un
    # fixture portant des chiffres (`t1`, `t2`) a révélé que la classe de caractères de cette garde
    # excluait les chiffres — invisible sur les tables du produit, qui n'en portent aucun. Un corpus
    # calqué sur l'existant valide l'accord avec l'existant, pas la correction.
    p = portee_declaree(
        'pub(crate) const FAMILLES_DE_RETENTION: &[(&str, &str, i64)] = &[\n'
        '    ("t1", "a_days", 86_400),\n    ("t2", "a_days", 86_400),\n    ("t3", "b_hours", 3_600),\n];'
    )
    if p != {"a_days": ["t1", "t2"], "b_hours": ["t3"]}:
        faux.append(f"lecture de la portée cassée : {p!r}")
    if portee_declaree("rien") != {}:
        faux.append("une source sans portée devrait rendre un dictionnaire vide")

    src = 'fn retention_run_tenant() {\n  chunked_purge(db, "alpha", ..);\n  retention_prune_table(db, "beta", ..);\n  conn.execute("DELETE FROM gamma WHERE ts < ?1");\n}\nfn autre() {\n  chunked_purge(db, "ailleurs", ..);\n  conn.execute("DELETE FROM geste_utilisateur WHERE id=?1");\n}\n'
    aides = tables_par_les_aides(src)
    if aides != ["ailleurs", "alpha", "beta"]:
        faux.append(f"extraction par les AIDES cassée : {aides!r}")
    instr = tables_par_instruction(corps_de_la_passe(src))
    if instr != ["gamma"]:
        faux.append(f"extraction par INSTRUCTION cassée : {instr!r}")
    if "geste_utilisateur" in instr:
        faux.append("une suppression HORS de la passe est comptée comme rétention")
    commente = 'fn retention_run_tenant() {\n  // chunked_purge(db, "citee_en_commentaire", ..);\n  chunked_purge(db, "vraie", ..);\n}\n'
    if tables_par_les_aides(depouiller_texte(commente)) != ["vraie"]:
        faux.append("une purge CITÉE en commentaire est comptée à tort")
    # UN APPEL ÉCRIT SUR PLUSIEURS LIGNES DOIT ÊTRE VU : c'est la forme du site du tier froid.
    multi = 'chunked_purge(\n    db,\n    "sur_plusieurs_lignes",\n    &format!("..."),\n);'
    if tables_par_les_aides(multi) != ["sur_plusieurs_lignes"]:
        faux.append("un appel de purge écrit sur plusieurs lignes échappe à l'extraction")

    # --- LE DÉPOUILLEMENT (`P10.20-h`, 2026-09-16) ------------------------------------------------
    # Les formes sur lesquelles la substitution `//.*$` par ligne se trompait, éprouvées À TRAVERS les
    # lectures de cette garde : c'est son VERDICT qui est tenu, pas seulement le texte rendu. MESURÉ,
    # un par un, en remettant l'ancien dépouilleur derrière `depouiller_texte` : CINQ rougissent — la
    # purge et la suppression écrites dans un commentaire de BLOC, la chaîne MULTILIGNE, l'URL, et
    # l'AVEU. Les autres sont de NON-RÉGRESSION et le disent : l'ancienne substitution n'avait AUCUNE
    # notion de chaîne, donc elle coupait au `//` même après un littéral `'"'` ou une chaîne brute —
    # elle avait raison par accident sur ces deux formes-là, et il faut l'écrire plutôt que de laisser
    # croire que ces témoins-là prouvent le correctif.
    litteral = ('fn retention_run_tenant() {\n'
                '  let sep = \'"\'; // chunked_purge(db, "fantome_apres_litteral", ..);\n'
                '  chunked_purge(db, "vraie", ..);\n}\n')
    if tables_par_les_aides(depouiller_texte(litteral)) != ["vraie"]:
        faux.append("après un littéral de caractère guillemet, une purge COMMENTÉE est comptée")
    brute = ('fn retention_run_tenant() {\n'
             '  let m = r#"un " nu"#; // chunked_purge(db, "fantome_apres_brute", ..);\n'
             '  chunked_purge(db, "vraie", ..);\n}\n')
    if tables_par_les_aides(depouiller_texte(brute)) != ["vraie"]:
        faux.append("après une chaîne brute à guillemet nu, une purge COMMENTÉE est comptée")
    bloc = ('fn retention_run_tenant() {\n'
            '  /* provisoirement retiré :\n'
            '  chunked_purge(db, "fantome_en_bloc", ..);\n'
            '  conn.execute("DELETE FROM fantome_bloc_instr WHERE ts < ?1");\n'
            '  */\n'
            '  chunked_purge(db, "vraie", ..);\n}\n')
    nu_bloc = depouiller_texte(bloc)
    if tables_par_les_aides(nu_bloc) != ["vraie"]:
        faux.append("une purge écrite dans un commentaire de BLOC est comptée comme une purge réelle")
    if tables_par_instruction(corps_de_la_passe(nu_bloc)) != []:
        faux.append("une suppression écrite dans un commentaire de BLOC est comptée")
    if len(nu_bloc.split("\n")) != len(bloc.split("\n")):
        faux.append("le dépouillement ne préserve plus la HAUTEUR — tout numéro de ligne rendu serait faux")
    multiligne = ('fn retention_run_tenant() {\n'
                  '  let aide = "voir\n'
                  '      https://exemple"; chunked_purge(db, "apres_url_multiligne", ..);\n}\n')
    if tables_par_les_aides(depouiller_texte(multiligne)) != ["apres_url_multiligne"]:
        faux.append("un `//` d'URL dans une chaîne qui franchit la fin de ligne fait MANGER la fin de cette ligne")
    url = 'fn f() {\n  let u = "https://exemple/x"; chunked_purge(db, "apres_url", ..);\n}\n'
    if tables_par_les_aides(depouiller_texte(url)) != ["apres_url"]:
        faux.append("un `//` d'URL coupe encore la ligne — la purge qui suit est perdue")
    vie = 'fn borne<\'a>(s: &\'a str) -> &\'a str { s }\nchunked_purge(db, "apres_vie", ..);\n'
    if tables_par_les_aides(depouiller_texte(vie)) != ["apres_vie"]:
        faux.append("témoin de NON-RÉGRESSION : une durée de vie `'a` ouvre un littéral")
    ordinaire = 'chunked_purge(db, "vraie", ..); // chunked_purge(db, "fantome", ..);\n'
    if tables_par_les_aides(depouiller_texte(ordinaire)) != ["vraie"]:
        faux.append("témoin de NON-RÉGRESSION : un commentaire de LIGNE ordinaire n'est plus retiré")
    # L'AVEU DANS LES DEUX SENS : muet sur du Rust valide, parlant sur une chaîne jamais refermée.
    propre = []
    depouiller_texte(url, propre)
    if propre:
        faux.append(f"le lecteur avoue une perte sur du Rust valide : {propre!r}")
    perdu = []
    depouiller_texte('fn f() {\n  let x = "jamais refermee;\n  chunked_purge(db, "t", ..);\n}\n', perdu)
    if not perdu:
        faux.append("le lecteur n'avoue plus une chaîne jamais refermée — il rendrait un compte amputé en vert")
    return faux


def main() -> int:
    temoins_du_lecteur()
    faux = valider_linstrument()
    if faux:
        for f in faux:
            print(f"::error::instrument invalide — {f}")
        print("\nLa garde ne peut pas conclure : elle ne se croit pas elle-même.")
        return 2

    for f in [MAIN, DECLARATION] + SITES_DU_CYCLE_DE_VIE:
        if not f.exists():
            print(f"::error::{f} est introuvable — aucun verdict possible.")
            return 2
    if not RACINE.is_dir():
        print(f"::error::{RACINE} est introuvable — la dérivation est cassée, aucun verdict rendu.")
        return 2

    # --- LE CORPUS, LU ET DÉPOUILLÉ UNE FOIS, AVEC LE JOURNAL --------------------------------------
    aveux: dict = {}
    corpus = corpus_de_production(RACINE, aveux)
    for f in [MAIN, DECLARATION] + SITES_DU_CYCLE_DE_VIE:
        if f not in corpus:
            corpus[f] = depouiller(f, aveux)
    if aveux:
        # Un lecteur qui a ouvert un littéral qui n'en était pas un a AVALÉ du code : tout ce qu'il a
        # lu depuis est faux, et un compte amputé rendu en vert est pire qu'une garde absente.
        refuser_sur_aveu(ETIQUETTE, aveux, "Rust")
        return 2

    cles = cles_declarees(corpus[MAIN])
    portee = portee_declaree(corpus[DECLARATION])
    if not cles or not portee:
        print(f"::error::les leviers ({MAIN}) ou leur portée ({DECLARATION}) ne sont plus lisibles.")
        return 2

    # LA POPULATION DES SITES EST DÉRIVÉE DE L'ARBRE, PAS RECOPIÉE : un troisième fichier qui se
    # mettrait à purger fait rougir tant qu'il n'est pas nommé et sa table déclarée.
    trouves = fichiers_qui_purgent(corpus)
    attendus = sorted(str(f) for f in SITES_DU_CYCLE_DE_VIE)
    if sorted(str(f) for f in trouves) != attendus:
        for f in trouves:
            if str(f) not in attendus:
                print(f"::error::{f} appelle une aide de purge et n'est pas un site du cycle de vie déclaré. "
                      "Nommez-le dans la garde ET déclarez la table qu'il purge, ou n'employez pas ces aides.")
        for a in attendus:
            if a not in [str(f) for f in trouves]:
                print(f"::error::{a} est déclaré site du cycle de vie mais n'appelle plus aucune aide de purge.")
        print("\nLa population des sites qui suppriment a changé.")
        return 1

    purgees = set()
    for f in SITES_DU_CYCLE_DE_VIE:
        purgees |= set(tables_par_les_aides(corpus[f]))
    corps = corps_de_la_passe(corpus[PASSE])
    if not corps:
        print(f"::error::le corps de `{FONCTION}` est introuvable — la garde ne juge rien.")
        return 2
    purgees |= set(tables_par_instruction(corps))
    purgees = sorted(purgees)
    if not purgees:
        print("::error::aucune purge trouvée — l'extraction est aveugle.")
        return 2

    defauts = []
    for c in cles:
        if c not in portee:
            defauts.append(f"::error::le levier `{c}` n'a AUCUNE portée déclarée dans {DECLARATION}.")
    for c in portee:
        if c not in cles:
            defauts.append(f"::error::{DECLARATION} déclare `{c}`, qui n'est pas un levier de `RETENTION_FIELDS`.")

    declarees = sorted({t for ts in portee.values() for t in ts})
    for t in purgees:
        if t not in declarees:
            defauts.append(f"::error::le cycle de vie purge `{t}`, qu'AUCUN levier ne déclare. Le périmètre "
                           "déclaré doit couvrir TOUTES les tables purgées.")
    for t in declarees:
        if t not in purgees:
            defauts.append(f"::error::`{t}` est déclarée gouvernée, mais plus aucun site ne la purge : "
                           "la déclaration est devenue fausse.")

    if defauts:
        for d in defauts:
            print(d)
        print(f"\n{len(defauts)} divergence(s) entre ce qu'un levier DÉCLARE et ce que le cycle de vie PURGE.")
        return 1

    print(
        f"{len(cles)} levier(s), {len(declarees)} table(s) déclarée(s) dans {DECLARATION.name}, "
        f"{len(purgees)} table(s) réellement purgée(s) par {len(SITES_DU_CYCLE_DE_VIE)} site(s) du cycle "
        "de vie : les deux ensembles coïncident."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
