#!/usr/bin/env python3
"""Un test dont TOUTES les assertions vivent dans une boucle sur une table DÉCLARÉE passe par le
plancher — sinon vider la table le rend VERT ET VIDE (`P11.23-g`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
=============================================
Un test qui boucle sur une table déclarée ailleurs que lui n'a d'assertion QUE dans cette boucle.
Le jour où la table perd sa matière, la boucle itère zéro fois : le test rend la main, `libtest`
compte un test PASSÉ de plus, et la propriété annoncée n'a été exercée sur RIEN.

MESURÉ SUR CET ARBRE LE 2026-09-02, PAR PROPRIÉTÉ ET NON PAR LISTE : sur 1 848 fonctions de test
de la caisse, DIX n'ont aucune assertion sur un chemin garanti et dépendent, pour toutes leurs
assertions, d'une boucle sur une table déclarée hors d'elles — douze tables, dont six vivent dans
une caisse VOISINE (`guatx_core`), où ce dépôt ne peut rien garder. La démonstration a été jouée :
`COLLECTORS` vidée, sans plancher, `hotes_muets_prefixe_de_dedup_ne_collisionne_avec_aucun_capteur`
rend « ok. 1 passed » en ayant exercé zéro assertion.

CE N'EST PAS LA FAMILLE DU CANAL DE REFUS, ET C'EST DÉLIBÉRÉ
=============================================================
`P11.23-b`/`P11.23-e` laissent VERT et consignent l'aveu : c'est le bon geste pour un
ENVIRONNEMENT aveugle, où aucun geste ne refermerait un rouge. Une table déclarée vidée n'est pas
un environnement — c'est une PANNE D'INSTRUMENT, dont le geste de fermeture est une ligne de
source. Elle doit donc ROUGIR. La garde du canal le dit elle-même dans son bandeau : « un corpus
qui perd sa matière […] ce qui tient cette forme est un PLANCHER dans l'instrument qui produit le
corpus, pas cette garde ». Cette garde-ci est cet énoncé rendu obligatoire.

CE QU'ELLE ACCUSE, ET POURQUOI PAS PLUS
========================================
Un site est jugé quand TOUTES ces conditions tiennent — chacune retire une classe de fausse
accusation, et c'est le mauvais sens de l'erreur ici :
  · le test n'a AUCUNE assertion sur un chemin garanti (hors boucle, hors closure jamais appelée
    depuis un chemin garanti). Un test qui porte SON PROPRE plancher — `assert!(tpls.len() >= 10)`
    avant la boucle, comme `soql_templates_all_compile` — est HORS POPULATION, et c'est
    l'échappatoire légitime : il déclare déjà ce qu'il exige de sa matière ;
  · la boucle qui porte l'assertion itère un IDENTIFIANT DE CONSTANTE (majuscules et soulignés),
    c'est-à-dire une table déclarée AILLEURS que sous les yeux du lecteur du test. Un littéral
    écrit dans la boucle (`for x in ["a","b"]`), une plage (`0..n`), une collection construite dans
    le test : hors population — les vider, c'est éditer l'assertion elle-même ;
  · la table n'est pas déclarée DANS le corps du test (`const`/`static`/`let` local) : là encore, la
    matière est sous les yeux de qui lit.

DEUX INDIRECTIONS SONT SUIVIES, PARCE QUE DEUX SITES RÉELS LES PORTENT
======================================================================
  · L'assertion enfermée dans une closure que SEULE la boucle appelle (le cas
    `completion_vocab_commands_compile`, dont le `panic!` vit dans `minimal`).
  · La boucle sur un PARAMÈTRE de closure, résolue aux ARGUMENTS des sites d'appel (le cas
    `soql_docs_cover_all_vocab`, qui passe sept tables à un auxiliaire `check`). Le site reporté
    est alors le site d'APPEL : c'est là que le geste se pose.

LE VERDICT EST PAR BOUCLE, PAS PAR TEST. Un test qui route une table par le plancher et en laisse
une seconde NUE est accusé sur la seconde. C'est la transposition exacte du témoin `t_deux_sorties`
de la garde du canal : un site conforme ne blanchit jamais son voisin.

TROIS CANAUX
============
  0  tenu.
  1  violé — le site est NOMMÉ (fichier, ligne, test, table, et le geste exact).
  2  l'instrument ne peut pas voir — il REFUSE DE CONCLURE, il n'accuse pas.

CE QU'ELLE NE TIENT PAS — DIT PLUTÔT QUE SOUS-ENTENDU
======================================================
  · ELLE NE TIENT QUE LA VACUITÉ. Une table de 23 entrées tombée à 1 franchit le plancher et
    franchit cette garde. Le zéro est la seule frontière MESURÉE entre « le témoin a bouclé » et
    « le témoin n'a pas bouclé » ; tout autre plancher serait un nombre choisi.
  · ELLE NE VOIT PAS UNE BOUCLE QUI FILTRE. `for x in TABLE.iter().filter(…)` peut itérer zéro fois
    sur une table PLEINE : le plancher est franchi et le test reste muet. MESURÉ le 2026-09-02 :
    zéro site de cette forme dans la population. Rien ici ne l'empêcherait demain.
  · ELLE NE VOIT PAS LA VACUITÉ HORS D'UNE BOUCLE `for`. `assert!(TABLE.iter().all(…))` est VRAI
    sur le vide et son assertion est sur un chemin garanti. MESURÉ le 2026-09-02 sur les quatre
    caisses : zéro occurrence sur une table nommée. La borne est dite, pas fermée.
  · ELLE NE SUIT QU'UN NIVEAU D'INDIRECTION. Une table passée à un auxiliaire qui la repasse à un
    second lui échappe. Aucun site de cette forme aujourd'hui.
  · UNE SEULE CAISSE — celle qui PORTE le plancher, dérivée en remontant de son fichier jusqu'au
    `Cargo.toml`. Les caisses jumelles ne peuvent pas appeler la macro d'une autre ; l'exiger serait
    une rançon. MESURÉ le 2026-09-02 : `agent`, `collector-syslog` et `collector-mail` portent ZÉRO
    site de cette forme, donc cette borne est aujourd'hui VIDE.
  · LE TEXTE, PAS L'EXÉCUTION. Elle établit que le site PASSE PAR le plancher ; que le plancher
    rougisse vraiment, c'est le témoin `le_plancher_des_tables_declarees_accuse_l_instrument_et_
    nomme_la_table` qui le tient, sur des tables FABRIQUÉES.
  · ELLE NE DIT RIEN DE LA CAISSE VOISINE. Six des douze tables vivent dans `guatx_core` : le
    plancher les surveille depuis ici, mais rien dans CE dépôt n'empêche leur vidage.
"""

import importlib.util
import os
import re
import sys

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.realpath(os.path.join(ICI, "..", ".."))
PLANCHER = os.path.join(RACINE, "daemon", "src", "tests", "plancher_des_tables_declarees.rs")
GARDE_DU_CANAL = os.path.join(ICI, "check_a_test_that_declines_to_conclude_says_so.py")

CODE_TENU = 0
CODE_VIOLE = 1
CODE_INSTRUMENT = 2

# L'ANALYSEUR LEXICAL EST IMPORTÉ, JAMAIS RECOPIÉ. `P11.23-e` l'a mesuré : une copie dérive sans
# que rien ne le dise. Si la garde du canal disparaît ou change de forme, celle-ci REFUSE DE
# CONCLURE plutôt que de juger avec un analyseur de fortune.
def _analyseur_partage():
    try:
        spec = importlib.util.spec_from_file_location("garde_du_canal", GARDE_DU_CANAL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except Exception as e:  # noqa: BLE001 — toute panne d'import est un refus de conclure
        return None, f"la garde du canal est illisible ({e})"
    manquants = [n for n in ("sans_chaines_ni_commentaires", "fin_de_bloc", "ATTR_TEST", "ASSERTION")
                 if not hasattr(module, n)]
    if manquants:
        return None, f"la garde du canal ne porte plus {', '.join(manquants)}"
    return module, None


# Une table DÉCLARÉE : un identifiant de constante Rust (majuscules/chiffres/soulignés), seul ou
# derrière un chemin de module, éventuellement suivi de `.iter()` et d'adaptateurs SANS argument.
# Un adaptateur AVEC argument (`.filter(|x| …)`) ne rentre pas : la borne est dite dans le bandeau.
NOMMEE = re.compile(r"^&?\s*(?:[A-Za-z_][A-Za-z0-9_]*::)*([A-Z][A-Z0-9_]{2,})\s*"
                    r"(?:\.\s*iter\s*\(\s*\)\s*(?:\.\s*\w+\s*\(\s*\)\s*)*)?$")
DECLAREE_DANS_LE_TEST = re.compile(r"\b(?:const|static|let)\s+(?:mut\s+)?([A-Z][A-Z0-9_]{2,})\b")


def _plat(s):
    return " ".join(s.split())


def analyser(brut, chemin, macro, g):
    """Rend (sites, tests_vus). Un site = UNE boucle porteuse sur une table déclarée, et son verdict.

    C'est la SEULE fonction de jugement : les témoins fabriqués et l'arbre réel passent par elle."""
    net = g.sans_chaines_ni_commentaires(brut)
    sites, tests_vus = [], 0

    def fin_de_bloc(pos):
        return g.fin_de_bloc(net, pos)

    for m in g.ATTR_TEST.finditer(net):
        mf = re.search(r"\bfn\s+(\w+)\s*(?:<[^>]*>)?\s*\(", net[m.end():])
        if not mf:
            continue
        nom = mf.group(1)
        acc = net.find("{", m.end() + mf.end())
        if acc == -1:
            continue
        fin = fin_de_bloc(acc)
        if fin is None:
            continue
        tests_vus += 1
        corps = net[acc:fin + 1]
        locales = set(DECLAREE_DANS_LE_TEST.findall(corps))

        boucles, closures = [], []
        # ── LES BOUCLES : `for … in EXPR {` et `.for_each(|…| {`.
        for b in re.finditer(r"\bfor\s+", corps):
            pos = acc + b.start()
            j, prof = pos + 3, 0
            while j < fin:
                c = net[j]
                if c in "([":
                    prof += 1
                elif c in ")]":
                    prof -= 1
                elif c == "{" and prof == 0:
                    break
                j += 1
            if j >= fin:
                continue
            f = fin_de_bloc(j)
            if f is None:
                continue
            entete = net[pos + 3:j]
            mi = re.search(r"\bin\b", entete)
            expr_net = (entete[mi.end():] if mi else entete).strip()
            # L'expression est relue sur le BRUT : `stringify!` et la macro y sont intacts, alors
            # que le blanchiment n'y touche pas non plus — mais la borne du brut est la seule qui
            # rende le texte cité au lecteur.
            deb_expr = pos + 3 + (mi.end() if mi else 0)
            sites_expr = (deb_expr, j)
            boucles.append({"ouv": j, "fin": f, "expr": _plat(expr_net),
                            "brut": _plat(brut[sites_expr[0]:sites_expr[1]]),
                            "ligne": brut[:pos].count("\n") + 1})
        for b in re.finditer(r"\.\s*(for_each|try_for_each)\s*\(", corps):
            pos = acc + b.start()
            mb = re.compile(r"\s*(?:move\s*)?(\|[^|]*\||\|\|)\s*\{").match(net, acc + b.end())
            if not mb:
                continue
            ouv = mb.end() - 1
            f = fin_de_bloc(ouv)
            if f is None:
                continue
            k = pos
            while k > acc and net[k - 1] not in ";{}":
                k -= 1
            boucles.append({"ouv": ouv, "fin": f, "expr": _plat(net[k:pos]),
                            "brut": _plat(brut[k:pos]), "ligne": brut[:pos].count("\n") + 1})

        # ── LES CLOSURES LIÉES : `let nom = |p1, p2| { … }`, paramètres découpés en profondeur.
        for c in re.finditer(r"\blet\s+(\w+)\s*(?::[^=]+)?=\s*(?:move\s*)?(\|([^|\n]*)\||\|\|)"
                             r"\s*(?:->[^{]+)?\{", corps):
            ouv = acc + c.end() - 1
            f = fin_de_bloc(ouv)
            if f is None:
                continue
            prof, cur, bruts = 0, [], []
            for ch in (c.group(3) or ""):
                if ch in "([{<":
                    prof += 1
                elif ch in ")]}>":
                    prof -= 1
                elif ch == "," and prof == 0:
                    bruts.append("".join(cur))
                    cur = []
                    continue
                cur.append(ch)
            bruts.append("".join(cur))
            closures.append({"nom": c.group(1), "ouv": ouv, "fin": f,
                             "params": [x.split(":")[0].strip().lstrip("&").strip()
                                        for x in bruts if x.strip()]})

        def dans_boucle(p):
            return [b for b in boucles if b["ouv"] < p < b["fin"]]

        def dans_closure(p):
            return [c for c in closures if c["ouv"] < p < c["fin"]]

        def appels(c):
            for a in re.finditer(r"\b%s\s*\(" % re.escape(c["nom"]), corps):
                q = acc + a.start()
                if c["ouv"] < q < c["fin"]:
                    continue
                yield q

        # ── POINT FIXE : une closure est ATTEIGNABLE SANS BOUCLE si un de ses appels l'est.
        atteignables = set()
        change = True
        while change:
            change = False
            for c in closures:
                if c["nom"] in atteignables:
                    continue
                for q in appels(c):
                    if dans_boucle(q):
                        continue
                    if any(x["nom"] not in atteignables for x in dans_closure(q)):
                        continue
                    atteignables.add(c["nom"])
                    change = True
                    break

        def garantie(p):
            if dans_boucle(p):
                return False
            return all(c["nom"] in atteignables for c in dans_closure(p))

        assertions = [acc + a.start() for a in g.ASSERTION.finditer(corps)]
        if not assertions:
            continue
        # HORS POPULATION — le test porte SON PROPRE plancher : une assertion sur un chemin garanti.
        if any(garantie(p) for p in assertions):
            continue

        # ── LES BOUCLES PORTEUSES, et pour chacune la table qu'elle itère RÉELLEMENT.
        porteuses = {}  # (ligne, expr_brut) -> dict du site
        for p in assertions:
            enveloppantes = list(dans_closure(p))
            for b in dans_boucle(p):
                base = b["expr"].strip("&").strip()
                resolue = False
                for c in enveloppantes:
                    if not (c["ouv"] < b["ouv"] and b["fin"] < c["fin"]):
                        continue
                    if base not in c["params"]:
                        continue
                    idx = c["params"].index(base)
                    for q in appels(c):
                        par = net.find("(", q + len(c["nom"]))
                        args = g.arguments(brut, par + 1) if par != -1 else None
                        if args and len(args) > idx:
                            resolue = True
                            arg = _plat(args[idx])
                            porteuses[(brut[:q].count("\n") + 1, arg)] = {
                                "ligne": brut[:q].count("\n") + 1, "expr": arg,
                                "via": c["nom"], "test": nom}
                if not resolue:
                    porteuses[(b["ligne"], b["brut"])] = {
                        "ligne": b["ligne"], "expr": b["brut"], "via": None, "test": nom}
            # une assertion sous une closure que SEULE une boucle appelle : la boucle du site d'appel
            for c in enveloppantes:
                if c["nom"] in atteignables:
                    continue
                for q in appels(c):
                    for b in dans_boucle(q):
                        porteuses[(b["ligne"], b["brut"])] = {
                            "ligne": b["ligne"], "expr": b["brut"], "via": c["nom"], "test": nom}

        for site in porteuses.values():
            expr = site["expr"]
            # LE SITE EST-IL DÉJÀ ROUTÉ ? On le RECONNAÎT plutôt que de l'écarter en silence : la
            # POPULATION (routés + nus) est ce qui prouve que l'analyseur voit encore quelque chose.
            conforme = macro + "!" in expr
            # DÉNUDER l'appel au plancher rend la table telle que la boucle l'itérerait sans lui :
            # `table_declaree!(T).iter()` -> `T.iter()`. Sans ce retour à la forme nue, un site
            # conforme SORTIRAIT de la population — et la population est le contrôle positif.
            denu = re.sub(r"%s!\s*\(\s*([^()]*?)\s*\)" % re.escape(macro), r"\1", expr)
            mn = NOMMEE.match(denu if conforme else expr)
            if not mn:
                continue  # littéral, plage, collection locale : hors population
            table = mn.group(1)
            if table in locales:
                continue  # table déclarée DANS le test : la matière est sous les yeux du lecteur
            if conforme:
                sites.append({"fichier": chemin, "ligne": site["ligne"], "test": nom,
                              "table": table, "conforme": True, "faute": None})
                continue
            ou = (f" (passée à `{site['via']}`)" if site["via"] else "")
            sites.append({
                "fichier": chemin, "ligne": site["ligne"], "test": nom, "table": table,
                "conforme": False,
                "faute": (
                    f"toutes les assertions de ce test vivent dans une boucle sur `{table}`{ou}, "
                    f"une table déclarée AILLEURS que lui : le jour où elle perd sa matière, la "
                    f"boucle itère zéro fois et le test se présente VERT sans rien avoir prouvé. "
                    f"Écrire `{macro}!({table})` à la place de `{expr}` — le plancher rougit alors "
                    f"en accusant l'INSTRUMENT. (Ou, si ce test doit garder sa forme, lui donner "
                    f"SON propre plancher sur un chemin garanti : il sort de la population.)")})
    return sites, tests_vus


# =================================================================================================
# LES TÉMOINS — FABRIQUÉS ICI, jamais lus du dépôt. Ils s'exercent sur `analyser` elle-même.
# =================================================================================================
def temoins(macro, g):
    """Rend None si l'instrument est sain, sinon la faute constatée."""
    cas = [
        ("POSITIF — boucle NUE sur une table déclarée, aucune autre assertion", """
            #[test]
            fn t_nu() {
                for x in TABLE_DECLAREE {
                    assert!(bon(x));
                }
            }
        """, [("t_nu", "TABLE_DECLAREE", False)]),

        ("NÉGATIF — la même boucle, routée par le plancher", """
            #[test]
            fn t_route() {
                for x in %s!(TABLE_DECLAREE) {
                    assert!(bon(x));
                }
            }
        """ % macro, [("t_route", "TABLE_DECLAREE", True)]),

        ("NÉGATIF — le test porte SON PROPRE plancher sur un chemin garanti", """
            #[test]
            fn t_plancher_maison() {
                assert!(TABLE_DECLAREE.len() >= 3, "la table doit porter au moins trois entrées");
                for x in TABLE_DECLAREE {
                    assert!(bon(x));
                }
            }
        """, []),

        ("NÉGATIF — littéral écrit dans la boucle : la matière est sous les yeux", """
            #[test]
            fn t_litteral() {
                for x in ["a", "b"] {
                    assert!(bon(x));
                }
            }
        """, []),

        ("NÉGATIF — plage : rien à vider", """
            #[test]
            fn t_plage() {
                for i in 0..PLAFOND {
                    assert!(bon(i));
                }
            }
        """, []),

        ("NÉGATIF — table déclarée DANS le test", """
            #[test]
            fn t_table_locale() {
                const TABLE_DECLAREE: &[&str] = &["a"];
                for x in TABLE_DECLAREE {
                    assert!(bon(x));
                }
            }
        """, []),

        # LE CAS `completion_vocab_commands_compile` : le `panic!` vit dans une closure que SEULE la
        # boucle appelle. Une garde qui ne regarderait que les assertions du corps le manquerait.
        ("POSITIF — assertion enfermée dans une closure appelée SEULEMENT par la boucle", """
            #[test]
            fn t_closure_sous_boucle() {
                let minimal = |c: &str| -> String {
                    match c {
                        "a" => "un".to_string(),
                        autre => panic!("cas non couvert : {autre}"),
                    }
                };
                for cmd in TABLE_DECLAREE {
                    let _ = minimal(cmd);
                }
            }
        """, [("t_closure_sous_boucle", "TABLE_DECLAREE", False)]),

        ("NÉGATIF — la closure est AUSSI appelée hors boucle : son assertion est garantie", """
            #[test]
            fn t_closure_hors_boucle() {
                let juge = |c: &str| { assert!(bon(c)); };
                juge("ancrage");
                for cmd in TABLE_DECLAREE {
                    juge(cmd);
                }
            }
        """, []),

        # LE CAS `soql_docs_cover_all_vocab` : la boucle itère un PARAMÈTRE, et la table est passée
        # au SITE D'APPEL — c'est là que le geste se pose, donc c'est là que le site est reporté.
        ("POSITIF — boucle sur un PARAMÈTRE de closure, table résolue au site d'appel", """
            #[test]
            fn t_indirection() {
                let check = |table: &[(&'static str, &'static str)], jetons: &[&str], nom: &str| {
                    for j in jetons {
                        assert!(decrit(table, j), "{nom}");
                    }
                };
                check(DOC_UNE, TABLE_DECLAREE, "une");
            }
        """, [("t_indirection", "TABLE_DECLAREE", False)]),

        ("NÉGATIF — même indirection, l'argument routé par le plancher", """
            #[test]
            fn t_indirection_routee() {
                let check = |table: &[(&'static str, &'static str)], jetons: &[&str], nom: &str| {
                    for j in jetons {
                        assert!(decrit(table, j), "{nom}");
                    }
                };
                check(DOC_UNE, %s!(TABLE_DECLAREE), "une");
            }
        """ % macro, [("t_indirection_routee", "TABLE_DECLAREE", True)]),

        # LE TÉMOIN QUI INTERDIT LA FAUSSE CORRECTION — transposition de `t_deux_sorties` : router
        # UNE table ne blanchit pas la seconde. Une garde à verdict PAR TEST passerait ce cas.
        ("POSITIF — deux tables, la première routée, la SECONDE nue", """
            #[test]
            fn t_deux_tables() {
                for x in %s!(TABLE_UNE) {
                    assert!(bon(x));
                }
                for y in TABLE_DEUX {
                    assert!(bon(y));
                }
            }
        """ % macro, [("t_deux_tables", "TABLE_UNE", True), ("t_deux_tables", "TABLE_DEUX", False)]),

        ("NÉGATIF — `for_each` routé par le plancher", """
            #[test]
            fn t_for_each_route() {
                %s!(TABLE_DECLAREE).iter().for_each(|x| {
                    assert!(bon(x));
                });
            }
        """ % macro, [("t_for_each_route", "TABLE_DECLAREE", True)]),

        ("POSITIF — `for_each` NU sur une table déclarée", """
            #[test]
            fn t_for_each_nu() {
                TABLE_DECLAREE.iter().for_each(|x| {
                    assert!(bon(x));
                });
            }
        """, [("t_for_each_nu", "TABLE_DECLAREE", False)]),

        ("NÉGATIF — accolade dans une chaîne : l'appariement de blocs tient", """
            #[test]
            fn t_accolade_en_chaine() {
                let s = "{ ceci n'ouvre rien }";
                assert!(!s.is_empty());
                for x in TABLE_DECLAREE {
                    assert!(bon(x));
                }
            }
        """, []),
    ]
    for nom, source, attendu in cas:
        sites, _ = analyser(source, "<témoin>", macro, g)
        obtenu = [(s["test"], s["table"], s["conforme"]) for s in sites]
        if obtenu != attendu:
            return f"témoin « {nom} » : l'analyseur rend {obtenu}, attendu {attendu}"

    # ÉPREUVE DE L'INSTRUMENT LUI-MÊME : un analyseur qui ne reconnaîtrait plus aucune fonction de
    # test rendrait « zéro violation » sur tout, et aucun témoin ci-dessus ne bougerait.
    _, vus = analyser("#[test]\nfn a() { for x in T_UN { assert!(x); } }\n"
                      "#[test]\nfn b() { assert!(true); }", "<témoin>", macro, g)
    if vus != 2:
        return f"l'analyseur ne reconnaît que {vus} fonction(s) de test sur 2 fabriquées"
    return None


# =================================================================================================
# LE PLANCHER ET SA CAISSE — dérivés, jamais recopiés.
# =================================================================================================
def plancher_est_vivant():
    """Rend (nom_de_macro, faute). Le NOM de la macro est LU dans le plancher : une garde qui
    exigerait un nom recopié serait verte le jour où le plancher renomme sa forme."""
    try:
        source = open(PLANCHER, encoding="utf-8").read()
    except OSError as e:
        return None, f"le plancher est illisible ({os.path.relpath(PLANCHER, RACINE)} : {e})"
    m = re.search(r"macro_rules!\s+(\w+)", source)
    if not m:
        return None, (f"aucune `macro_rules!` dans {os.path.relpath(PLANCHER, RACINE)} : la garde "
                      "exigerait une forme qui n'existe plus")
    corps = re.search(r"pub\(crate\) fn non_vide\b.*?\n    \}", source, re.S)
    if not corps:
        return None, "`non_vide` INTROUVABLE dans le plancher"
    c = corps.group(0)
    if "is_empty()" not in c or "assert!" not in c:
        return None, ("le plancher n'exige plus rien : `non_vide` ne porte plus d'`assert!` sur "
                      "`is_empty()` — router les sites par lui n'achèterait RIEN")
    if "INSTRUMENT" not in c:
        return None, ("le message du plancher n'accuse plus l'INSTRUMENT : un rouge y serait lu "
                      "comme une propriété fausse, et le geste de fermeture serait cherché ailleurs")
    return m.group(1), None


def caisse_du_plancher():
    d = os.path.dirname(PLANCHER)
    while d.startswith(RACINE) and len(d) > len(RACINE):
        if os.path.exists(os.path.join(d, "Cargo.toml")):
            return d
        d = os.path.dirname(d)
    return None


def main():
    if len(sys.argv) > 1:
        print(f"::error::usage : {os.path.basename(__file__)}", file=sys.stderr)
        return CODE_INSTRUMENT

    g, faute = _analyseur_partage()
    if faute:
        print(f"::error::l'analyseur partagé est indisponible ({faute}) : cette garde jugerait avec "
              "un analyseur de fortune. Elle REFUSE DE CONCLURE.", file=sys.stderr)
        return CODE_INSTRUMENT

    macro, faute = plancher_est_vivant()
    if faute:
        print(f"::error::{faute}. La garde REFUSE DE CONCLURE.", file=sys.stderr)
        return CODE_INSTRUMENT

    faute = temoins(macro, g)
    if faute:
        print(f"::error::instrument INVALIDE ({faute}) : la garde REFUSE DE CONCLURE.", file=sys.stderr)
        return CODE_INSTRUMENT

    caisse = caisse_du_plancher()
    if caisse is None:
        print("::error::la caisse du plancher n'a pas pu être dérivée (aucun `Cargo.toml` au-dessus "
              f"de {os.path.relpath(PLANCHER, RACINE)}) : la garde REFUSE DE CONCLURE.", file=sys.stderr)
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

    tous, tests = [], 0
    for chemin in sorted(fichiers):
        try:
            brut = open(chemin, encoding="utf-8").read()
        except OSError as e:
            print(f"::error::{os.path.relpath(chemin, RACINE)} illisible ({e}) : la garde REFUSE DE "
                  "CONCLURE.", file=sys.stderr)
            return CODE_INSTRUMENT
        sites, vus = analyser(brut, os.path.relpath(chemin, RACINE), macro, g)
        tests += vus
        tous.extend(sites)
    if tests == 0:
        print(f"::error::AUCUNE fonction de test reconnue dans {os.path.relpath(sources, RACINE)} : "
              "l'instrument ne voit rien, il REFUSE DE CONCLURE.", file=sys.stderr)
        return CODE_INSTRUMENT

    # CONTRÔLE POSITIF CONTRE LE VERT PAR VACUITÉ — et il porte sur la POPULATION, pas sur un
    # compte d'occurrences textuelles. Un analyseur qui cesserait de reconnaître les boucles
    # porteuses rendrait « zéro violation » avec EXACTEMENT la sortie d'un arbre sain : ici, il
    # rend une population VIDE, et une population vide est un aveuglement, pas un verdict.
    # MESURÉE le 2026-09-02 : DIX tests, dix-neuf boucles porteuses, douze tables.
    population = sorted({(s["fichier"], s["test"]) for s in tous})
    if not population:
        print(f"::error::AUCUN test de {os.path.relpath(sources, RACINE)} ne porte ses assertions "
              "dans une boucle sur une table DÉCLARÉE — ni conforme, ni nu. La population mesurée "
              "le 2026-09-02 valait DIX : un zéro signifie que l'analyseur ne voit plus la forme "
              "qu'il juge. La garde REFUSE DE CONCLURE.", file=sys.stderr)
        return CODE_INSTRUMENT

    fautifs = [s for s in tous if not s["conforme"]]
    if fautifs:
        for s in fautifs:
            print(f"::error file={s['fichier']},line={s['ligne']}::{s['fichier']}:{s['ligne']} — "
                  f"test `{s['test']}` : {s['faute']}")
        print(f"::error::{len(fautifs)} boucle(s) porteuse(s) sur {len(tous)} ne passent pas par "
              f"le plancher. Vider la table les rendrait VERTES ET VIDES.", file=sys.stderr)
        return CODE_VIOLE

    tables = sorted({s["table"] for s in tous})
    print(f"TENU — sur {tests} fonctions de test de `{os.path.relpath(caisse, RACINE)}`, les "
          f"{len(population)} qui portent TOUTES leurs assertions dans une boucle sur une table "
          f"DÉCLARÉE passent par le plancher `{macro}!` : {len(tous)} boucle(s) porteuse(s), "
          f"{len(tables)} table(s) ({', '.join(tables)}). Vider l'une d'elles fait ROUGIR en "
          f"accusant l'INSTRUMENT, au lieu de rendre le test vert et vide.")
    print("CE QU'ELLE N'ACCUSE PAS : un test qui porte SON PROPRE plancher sur un chemin garanti "
          "(c'est l'échappatoire légitime) ; une boucle sur un littéral, une plage, une collection "
          "construite dans le test, ou une table déclarée DANS son corps — les vider, c'est éditer "
          "l'assertion elle-même.")
    print("CE QU'ELLE NE TIENT PAS : la seule VACUITÉ, jamais l'ampleur (23 entrées tombées à 1 "
          "passent) ; une boucle qui FILTRE (`.filter(…)`, zéro site aujourd'hui) ; un "
          "`assert!(TABLE.iter().all(…))`, vrai sur le vide et garanti (zéro site sur les quatre "
          "caisses) ; plus d'UN niveau d'indirection ; une seule caisse, celle qui porte le plancher "
          "(les trois caisses jumelles portent zéro site) ; le TEXTE, pas l'exécution ; et RIEN de ce "
          "qui arrive aux tables de la caisse voisine `guatx_core`, où six d'entre elles vivent.")
    return CODE_TENU


if __name__ == "__main__":
    sys.exit(main())
