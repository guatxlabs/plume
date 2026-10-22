#!/usr/bin/env python3
"""La surface web lit chaque verdict que le démon publie — garde de CI (`S37`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
Depuis `S28`, le démon distingue « lu » de « pas lisible » par des TYPES (`Mesure<T>`), et `S32` en a
fixé la convention de publication : à côté d'une grandeur `<clé>`, les clés `<clé>_verdict`,
`<clé>_cause` et `<clé>_detail` ; `P4.1-r` y a ajouté les bilans des boucles de fond. Toute cette
chaîne d'honnêteté s'arrête à la frontière du navigateur si la surface ne lit pas le verdict : une
grandeur ILLISIBLE côté démon se rend alors comme une case vide, un tiret ou un zéro — c'est-à-dire
exactement la valeur rassurante que la chaîne avait pour but de ne plus produire. Le défaut est
SILENCIEUX des deux côtés : le démon a fait son travail, la surface compile, aucun test ne rougit.

CE QUE CETTE GARDE VÉRIFIE
--------------------------
L'ensemble des clés `_verdict` émises est DÉRIVÉ du code du démon, jamais écrit ici ni dans le
navigateur : les sites qui posent un verdict sont les appels à `poser_dans`, `poser_verdict_dans`
et `poser_bilan` (un seul auteur, `mesure_environnement::Mesure`), le verdict d'objet entier posé par
`insert("verdict")`, et tout littéral `"<clé>_verdict"` qu'un site écrirait à la main. Une clé posée
par un gabarit (`format!("{boucle}_abandons")`) est RÉSOLUE sur la table des boucles du démon : la
garde rend alors une clé concrète par boucle, et note le SUFFIXE du gabarit.

Pour chaque clé dérivée, la surface doit la LIRE : un littéral de la clé dans le CODE (pas un
commentaire) d'un module web qui lit `_verdict` — ou, pour une clé de gabarit, le littéral du
suffixe (`_abandons_verdict`), puisque la surface découvre ces boucles sur les clés publiées au lieu
de les énumérer. Une clé citée dans un commentaire ne compte pas : c'est précisément sous cette forme
qu'une clé « connue » peut cesser d'être lue sans qu'un grep le voie.

L'INSTRUMENT SE VALIDE AVANT DE RENDRE UN VERDICT
--------------------------------------------------
Deux témoins sur un corpus de contrôle : des formes d'émission que la dérivation DOIT reconnaître et
des formes qu'elle NE DOIT PAS compter (un appel en commentaire, un pointeur JSON de lecture
`"/ingest/x_verdict"`, le gabarit générique `"{cle}_verdict"` du module auteur) ; des formes de
lecture que le lecteur DOIT reconnaître et des formes qu'il NE DOIT PAS compter (la clé dans un
commentaire de ligne ou de bloc). Puis deux planchers sur l'arbre réel — un nombre minimal de clés
dérivées, et une clé connue trouvée des DEUX côtés — sans quoi la garde refuse de conclure au lieu
de rendre vert en ne voyant rien.

LES AVEUX DE SUCCÈS ET LES REFUS NOMMÉS DU PLAN DE CONTRÔLE (`P10.30-d`, 2026-10-19)
-------------------------------------------------------------------------------------
Un verdict n'est pas la seule chose qu'une surface peut aplatir. Un SUCCÈS peut porter un aveu sous une
clé (`corps[CLE_X] = …` : le geste a eu lieu, quelque chose manque) ; MESURÉ le 2026-10-19 : la clé
`evenement_du_tenant_non_ecrit` (daemon/src/rbac.rs) était servie par quatre gestes et lue par AUCUN
module web — le succès se lisait nu. Et un refus en cinq cent trois du plan de contrôle des tenants
(daemon/src/tenants.rs) nommé par une phrase `CAUSE_X` se lisait comme un refus quelconque. La garde
DÉRIVE donc aussi, du code de production du démon : (a) toute clé posée par `<corps>[CLE_X] =`, résolue
sur sa constante `CLE_X: &str` ; le web doit en citer le littéral dans son CODE ; (b) toute phrase
`CAUSE_X` servie en cinq cent trois par daemon/src/tenants.rs (`err_json(StatusCode::SERVICE_UNAVAILABLE,
…)`, le tuple `(StatusCode::SERVICE_UNAVAILABLE, …)`, `refuser_le_geste_non_ecrit(…)`, ou l'appel d'un RELAIS à cause fixe — une fonction du démon dont
le corps ne sert que ce cinq cent trois sur sa `CAUSE_X`, comme `refuser_le_geste_sans_anti_verrouillage_lu`),
réduite à son OUVERTURE (le texte avant « : ») ; le web doit citer cette ouverture ENTIÈRE dans son CODE —
c'est elle que la surface reconnaît. Mêmes témoins sur corpus de contrôle, dans les deux sens ; chaque branche
qui refuse de conclure (clé ou cause sans constante, ouverture illisible) a le sien ; mêmes planchers (une clé
et une ouverture témoins, trouvées des deux côtés). Le verdict lui-même vit dans UNE fonction,
`verdict_des_aveux`, que `main` appelle sur l'arbre et que le corpus de contrôle joue sur chacune de ses
issues : lu en entier (0), lu en commentaire seulement (1), erreur de dérivation (2), et chaque condition du
plancher seule en défaut (2) — deux clés, deux refus nommés, la clé témoin non dérivée, l'ouverture témoin non
dérivée. Et `main` lui-même est JOUÉ, en sous-processus, sur une racine fabriquée : il doit rendre le code de ce
verdict (2, puis 1) et s'y arrêter, sans atteindre le harnais ESM.

CE QUE CETTE GARDE NE PROUVE PAS, ET QUI EST PROUVÉ AILLEURS
------------------------------------------------------------
Qu'une clé soit LUE ne dit pas comment elle est RENDUE. Le harnais ESM (`web_esm_harnais.mjs`,
lancé en dernier pas) rend le panneau sur des objets fabriqués et exige l'état distinct, la cause
nommée et les abandons visibles — et, dans l'autre sens, la valeur quand le verdict est « lu ».
"""
import contextlib
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile

RACINE = (sys.argv[1] if len(sys.argv) > 1
          else subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True,
                              text=True, check=True).stdout.strip())
DEMON = os.path.join(RACINE, "daemon", "src")
WEB = os.path.join(RACINE, "web")
HARNAIS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web_esm_harnais.mjs")

# Plancher de non-dégénérescence : sous ce nombre de clés dérivées, c'est la dérivation qui est
# cassée, pas le démon qui a cessé de publier. Relevé sur l'arbre : 14 clés, dont 6 de gabarit.
MIN_CLES = 3
# Une clé connue qui doit être trouvée des DEUX côtés — le témoin anti-tautologie sur l'arbre réel.
CLE_TEMOIN = "queue_depth"

# --- Émission côté démon ----------------------------------------------------------------------
POSER = re.compile(r'\.poser(?:_verdict)?_dans\(\s*&mut\s+\w+\s*,\s*"([A-Za-z_][A-Za-z0-9_]*)"\s*\)')
BILAN_LITTERAL = re.compile(r'poser_bilan\(\s*&mut\s+\w+\s*,\s*"([A-Za-z_][A-Za-z0-9_]*)"\s*,')
BILAN_GABARIT = re.compile(r'poser_bilan\(\s*&mut\s+\w+\s*,\s*&format!\(\s*"\{(\w+)\}(_[A-Za-z0-9_]+)"\s*\)\s*,')
VERDICT_OBJET = re.compile(r'\.insert\(\s*"verdict"\s*\.into\(\)')
# Une clé `_verdict` écrite à la main dans un objet JSON : `insert("x_verdict".into(), …)` ou
# `json!({ "x_verdict": … })`. Un littéral nu (`("proc_verdict", "conntrack.sh")` : le NOM d'un champ
# d'événement d'un capteur, dans l'inventaire des champs collectés) n'est pas une publication.
LITTERAL_VERDICT = re.compile(r'"([A-Za-z_][A-Za-z0-9_]*)_verdict"\s*(?:\.into\(\)|:)')
CONST_BOUCLE = re.compile(r'const\s+((?:BOUCLE|PASSE)_[A-Z0-9_]+)\s*:\s*&str\s*=\s*"([A-Za-z0-9_]+)"')
# `PASSE_` EST ADMIS À CÔTÉ DE `BOUCLE_` DEPUIS LE 2026-08-31 : une passe de fond publie le même
# bilan qu'une boucle sans en être une — elle est jouée UNE FOIS au démarrage, et son verdict vaut
# jusqu'au redémarrage. Ne reconnaître que `BOUCLE_` aurait fait accuser à tort une constante
# parfaitement déclarée, au motif qu'elle ne porte pas le nom d'un mécanisme qu'elle n'a pas.
PUBLIE = re.compile(r"(?:crate::)?bilan_de_tick::publier\(\s*(?:crate::)?(?:[a-z_][a-z0-9_]*::)*([A-Z][A-Z0-9_]{3,})\s*,")
TABLE_BOUCLES = re.compile(r'const\s+BOUCLES\s*:\s*\[&str;\s*\d+\]\s*=\s*\[([^\]]*)\]')
# Un `#[cfg(test)]` qui ouvre un MODULE (attributs intercalés et visibilité admis), jamais un élément isolé.
MODULE_DE_TEST = re.compile(r"#\[cfg\(test\)\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\b")

# Marqueur d'une clé de gabarit : `{boucle}_abandons` -> clés `regles_abandons`… + suffixe `_abandons`.
OBJET = "<objet>"


# LE DÉPOUILLEMENT N'EST PLUS RECOPIÉ ICI (`P11.8-f`). Il vivait en quatre exemplaires dans quatre
# gardes, et les quatre portaient la même cécité : aucun ne reconnaissait le littéral d'expression
# régulière, si bien qu'un `"` posé dans un motif ouvrait une fausse chaîne et que les commentaires de la
# région n'étaient PLUS RETIRÉS — une émission citée en commentaire y redevenait une émission. Mesuré le
# 2026-08-24 sur `web/` : `core.js` 124 lignes, `viz.js` 4 lignes, `app.js` 2 lignes lues de travers.
# La règle vit désormais à UN endroit, avec ses limites et son aveu de perte de synchronisation ; c'est le
# geste de `sans_commentaires_css`, que la garde du chrome importe de la garde des sélecteurs.
# En Rust, `'` n'est PAS un délimiteur (c'est une durée de vie `&'static str`), une chaîne peut franchir
# une fin de ligne et `/` est toujours une division : d'où deux entrées et non un drapeau.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_every_help_trigger_has_a_section import (  # noqa: E402  (source unique de vérité)
    refuser_sur_aveu, sans_commentaires_js, sans_commentaires_rust, temoins_du_lecteur)


def fichiers_du_demon():
    """Les sources du démon HORS tests : un test peut poser une clé factice sans que le démon la
    publie. Découverte par parcours, pas par liste."""
    for dossier, sous, noms in os.walk(DEMON):
        sous[:] = [d for d in sous if d != "tests"]
        for nom in sorted(noms):
            if nom.endswith(".rs") and nom != "tests.rs":
                yield os.path.join(dossier, nom)


def deriver_cles(sources, aveux=None):
    """`sources` : liste de (chemin, texte Rust). Rend ({clé: [sites]}, {suffixe: [sites]}, erreurs).
    Une clé `OBJET` désigne un verdict posé sur l'objet entier (`insert("verdict")`).
    `aveux` (facultatif) recueille les pertes de synchronisation du lecteur RUST, PAR FICHIER, comme
    `lecteurs_du_web` le fait pour le lecteur JavaScript (`P10.20-d`, 2026-09-16) : sans ce journal, un
    fichier dont une région serait avalée cesserait de publier des clés EN SILENCE, et la garde rendrait
    un plancher franchi par un démon qu'elle n'a pas lu."""
    cles, suffixes, erreurs = {}, {}, []
    boucles, table, publiees = {}, None, set()
    textes = []
    for chemin, texte in sources:
        journal = []
        code = sans_commentaires_rust(texte, journal)
        if journal and aveux is not None:
            aveux[os.path.relpath(chemin, RACINE)] = [f"ligne {texte.count(chr(10), 0, o) + 1} : {m}"
                                                      for m, o in journal]
        # Un module de test en ligne (`#[cfg(test)] mod …`) est coupé : tout ce qui suit est du test.
        # SEUL UN MODULE coupe (`P10.21-i`, 2026-09-23) : couper au premier `#[cfg(test)]` venu faisait
        # d'une simple FONCTION de témoin posée en tête de `metrics.rs` la fin du fichier, et les dix clés
        # publiées après elle disparaissaient — la garde refusait de conclure sur un démon intact.
        m_test = MODULE_DE_TEST.search(code)
        if m_test:
            code = code[:m_test.start()]
        textes.append((chemin, code))
        for m in CONST_BOUCLE.finditer(code):
            boucles[m.group(1)] = m.group(2)
        # LA POPULATION SE DÉRIVE DE CE QUI PUBLIE, PLUS D'UNE TABLE ÉCRITE — corrigé le 2026-08-31,
        # après que cette garde eut REFUSÉ DE CONCLURE, à raison : le démon parcourait une table tenue
        # à la main, il DÉRIVE désormais sa liste du registre de publication, donc la table a disparu.
        # LA NOUVELLE DÉRIVATION EST STRICTEMENT MEILLEURE : elle lit les constantes passées à
        # `publier(…)` dans le code de PRODUCTION — la MÊME source que le démon —, là où la table
        # pouvait diverger de ce qui publie réellement, ce qui ÉTAIT le défaut fermé.
        for m in PUBLIE.finditer(code):
            publiees.add(m.group(1).split("::")[-1])
        t = TABLE_BOUCLES.search(code)
        if t:
            table = [x.strip() for x in t.group(1).split(",") if x.strip()]

    def noter(d, cle, chemin):
        d.setdefault(cle, []).append(os.path.relpath(chemin, RACINE))

    for chemin, code in textes:
        for m in POSER.finditer(code):
            noter(cles, m.group(1), chemin)
        for m in BILAN_LITTERAL.finditer(code):
            noter(cles, m.group(1), chemin)
        for m in BILAN_GABARIT.finditer(code):
            suffixe = m.group(2)
            if table is None and not publiees:
                erreurs.append(f"{os.path.relpath(chemin, RACINE)} : gabarit `{{{m.group(1)}}}{suffixe}` "
                               f"et AUCUNE population dérivable — ni table, ni appel à `publier(<CONST>)` en production")
                continue
            noms = table if table is not None else sorted(publiees)
            for nom_const in noms:
                if nom_const.split("::")[-1] not in boucles:
                    erreurs.append(f"table BOUCLES cite `{nom_const}` qui n'est pas une constante `&str` connue")
                    continue
                noter(cles, boucles[nom_const.split("::")[-1]] + suffixe, chemin)
            noter(suffixes, suffixe, chemin)
        if VERDICT_OBJET.search(code):
            noter(cles, OBJET, chemin)
        # Un littéral `"x_verdict"` écrit à la main (hors gabarit `{cle}_verdict`, hors pointeur JSON
        # `"/a/x_verdict"` — le motif exige que la chaîne COMMENCE par la clé).
        for m in LITTERAL_VERDICT.finditer(code):
            noter(cles, m.group(1), chemin)
    return cles, suffixes, erreurs


# --- Aveux de succès et refus nommés (`P10.30-d`) ----------------------------------------------
# `<corps>[CLE_X] = …` : une clé d'aveu posée sur un corps de succès. `CLE_X: &str = "<clé>"` la résout.
AVEU_POSE = re.compile(r"\b[a-z_][a-z0-9_]*\[\s*(CLE_[A-Z0-9_]+)\s*\]\s*=(?!=)")
CONST_CLE = re.compile(r'const\s+(CLE_[A-Z0-9_]+)\s*:\s*&str\s*=\s*"([A-Za-z_][A-Za-z0-9_]*)"\s*;')
CONST_CAUSE = re.compile(r'const\s+(CAUSE_[A-Z0-9_]+)\s*:\s*&str\s*=\s*"((?:[^"\\]|\\.)*)"\s*;', re.S)
# Un refus en cinq cent trois du plan de contrôle des tenants : `err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_X)`,
# sa forme `format!("{CAUSE_X} ({cause})")`, ou `refuser_le_geste_non_ecrit(CAUSE_X, …)` (qui sert ce cinq cent trois).
# LE TUPLE AUSSI (2026-10-20) : `(StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": CAUSE_X })))` et
# `Err((StatusCode::SERVICE_UNAVAILABLE, CAUSE_X.to_string()))` servent le même cinq cent trois sans passer par
# `err_json` ; le motif n'exigeait que `err_json(`, et un refus nommé réécrit en tuple sortait de la dérivation sans
# rien dire (MESURÉ : la seule réécriture en tuple du refus `CAUSE_TENANT_NON_LU_DROIT_NON_POSE` de tenants.rs faisait
# tomber le compte de 8 à 7 refus nommés ; réécrire celui de l'ouverture témoin fait refuser de conclure, pas taire).
# La parenthèse ouvrante qui précède le code couvre les trois : `err_json(`, le tuple `(`, `Err((`.
REFUS_503 = re.compile(r'(?:\(\s*StatusCode::SERVICE_UNAVAILABLE\s*,\s*(?:Json\(\s*)?(?:json!\(\s*\{\s*"error"\s*:\s*)?'
                       r'(?:format!\(\s*"\{)?'
                       r'|refuser_le_geste_non_ecrit\(\s*)(CAUSE_[A-Z0-9_]+)\b')
# Un RELAIS à cause fixe : une fonction de n'importe quel fichier du démon dont le corps ne fait que servir ce cinq
# cent trois sur une `CAUSE_X` à elle (`refuser_le_geste_sans_anti_verrouillage_lu`, daemon/src/rbac.rs, qui sert
# `CAUSE_DERNIER_ADMINISTRATEUR_NON_ETABLI`). Son APPEL dans le plan de contrôle des tenants sert donc `CAUSE_X`.
RELAIS_A_CAUSE_FIXE = re.compile(r'\bfn\s+([a-z_][a-z0-9_]*)\s*\([^)]*\)\s*->\s*Response\s*\{\s*'
                                 r'err_json\(\s*StatusCode::SERVICE_UNAVAILABLE\s*,\s*(?:format!\(\s*"\{)?(CAUSE_[A-Z0-9_]+)\b')
FICHIER_DES_REFUS_DU_PLAN_DE_CONTROLE = "tenants.rs"
CLE_D_AVEU_TEMOIN = "registre_sans_maillon"
OUVERTURE_TEMOIN = "DESTRUCTION REFUSÉE, RIEN N'EST DÉTRUIT"
MIN_CLES_D_AVEU = 3
MIN_REFUS_NOMMES = 3


def code_de_production_rust(texte):
    """Le code Rust sans commentaires, coupé au premier MODULE de test en ligne — la même coupe que
    `deriver_cles` (les pertes de synchronisation y sont déjà avouées, sur les mêmes fichiers)."""
    code = sans_commentaires_rust(texte, [])
    m = MODULE_DE_TEST.search(code)
    return code[:m.start()] if m else code


def ouverture_d_une_cause(texte):
    """L'ouverture d'une phrase `CAUSE_X` : le texte avant le premier « : », continuations de ligne retirées.
    Rend la chaîne vide quand la phrase n'a pas d'ouverture lisible (aucun « : », ou une tête trop courte)."""
    phrase = re.sub(r"\\\r?\n\s*", "", texte)
    tete = phrase.split(" :", 1)[0].strip() if " :" in phrase else ""
    return tete if len(tete) >= 12 else ""


def deriver_aveux_et_refus(sources):
    """`sources` : liste de (chemin, texte Rust). Rend ({clé d'aveu: [sites]}, {ouverture: [constantes]}, erreurs)."""
    cles_const, causes, poses, refus, relais, erreurs = {}, {}, {}, {}, {}, []
    codes = [(chemin, code_de_production_rust(texte)) for chemin, texte in sources]
    for chemin, code in codes:
        rel = os.path.relpath(chemin, RACINE)
        for m in CONST_CLE.finditer(code):
            cles_const[m.group(1)] = m.group(2)
        for m in CONST_CAUSE.finditer(code):
            causes[m.group(1)] = m.group(2)
        for m in AVEU_POSE.finditer(code):
            poses.setdefault(m.group(1), []).append(rel)
        for m in RELAIS_A_CAUSE_FIXE.finditer(code):
            relais[m.group(1)] = m.group(2)
    for chemin, code in codes:
        if os.path.basename(chemin) != FICHIER_DES_REFUS_DU_PLAN_DE_CONTROLE:
            continue
        rel = os.path.relpath(chemin, RACINE)
        for m in REFUS_503.finditer(code):
            refus.setdefault(m.group(1), []).append(rel)
        for nom_du_relais, cause in sorted(relais.items()):
            # L'APPEL (nu ou qualifié, `rbac::nom(`), pas la définition (`fn nom(`).
            if re.search(r"(?<!fn )(?<!\w)" + re.escape(nom_du_relais) + r"\s*\(", code):
                refus.setdefault(cause, []).append(rel)
    aveux = {}
    for nom, sites in sorted(poses.items()):
        if nom not in cles_const:
            erreurs.append(f"{', '.join(sorted(set(sites)))} : `[{nom}] =` pose une clé d'aveu dont la constante "
                           f"`{nom}: &str` n'est pas lisible")
            continue
        aveux.setdefault(cles_const[nom], []).extend(sites)
    ouvertures = {}
    for nom in sorted(refus):
        if nom not in causes:
            erreurs.append(f"{FICHIER_DES_REFUS_DU_PLAN_DE_CONTROLE} : le refus nommé `{nom}` n'a pas de constante lisible")
            continue
        o = ouverture_d_une_cause(causes[nom])
        if not o:
            erreurs.append(f"{FICHIER_DES_REFUS_DU_PLAN_DE_CONTROLE} : `{nom}` n'a pas d'ouverture lisible (texte avant « : »)")
            continue
        ouvertures.setdefault(o, []).append(nom)
    return aveux, ouvertures, erreurs


def aveu_est_lu(cle, codes_web):
    """La clé d'aveu est lue si son littéral entre guillemets figure dans le CODE d'un module web."""
    motif = re.compile(r"""(['"`])""" + re.escape(cle) + r"""\1""")
    return sorted(os.path.relpath(c, RACINE) for c, code in codes_web.items() if motif.search(code))


def ouverture_est_lue(ouverture, codes_web):
    """L'ouverture est lue si elle figure, entière, dans le CODE d'un module web (le motif qui la reconnaît)."""
    return sorted(os.path.relpath(c, RACINE) for c, code in codes_web.items() if ouverture in code)


def codes_web_de(sources_js):
    """`sources_js` : liste de (chemin, texte JS BRUT). Rend {chemin: CODE sans commentaires} — ce que lisent
    `aveu_est_lu` et `ouverture_est_lue`. Le même câblage sert `main` et le corpus de contrôle : une clé ou une
    ouverture citée seulement en commentaire n'est pas lue, et c'est jugé sur ce chemin-là."""
    return {c: sans_commentaires_js(t, []) for c, t in sources_js}


def listes_sourdes(aveux_cles, ouvertures, codes_web):
    """Rend (clés d'aveu que le CODE d'aucun module web ne lit, ouvertures qu'il ne reconnaît pas), triées."""
    return ([cle for cle in sorted(aveux_cles) if not aveu_est_lu(cle, codes_web)],
            [o for o in sorted(ouvertures) if not ouverture_est_lue(o, codes_web)])


def verdict_des_aveux(sources_rs, sources_js):
    """LE VERDICT DES AVEUX DE SUCCÈS ET DES REFUS NOMMÉS (`P10.30-d`), écrit UNE fois : `main` l'appelle sur l'arbre, le
    corpus de contrôle de `valider_instrument` sur ses propres sources, par le même chemin. `sources_rs` et `sources_js` :
    listes de (chemin, texte BRUT). Dit ses lignes `::error::` et rend (code, bilan) : 0 (tout est lu, le bilan le compte),
    1 (un aveu ou un refus nommé que le web ne lit pas) ou 2 (refus de conclure : dérivation incomplète ou dégénérée), bilan
    vide. Une erreur de dérivation n'est JAMAIS avalée, et le web n'est lu que par `codes_web_de` (le code sans ses
    commentaires). Jusqu'au 2026-10-19, `main` portait ce câblage en propre et le corpus de contrôle n'en jouait que les
    pièces : aucun témoin ne voyait `main` avaler une erreur de dérivation, ni lire le web brut. Que `main` rende le code
    non nul qu'il reçoit est jugé à part, en le jouant sur une racine fabriquée (`jouer_main_sur_une_racine_fabriquee`)."""
    aveux_cles, ouvertures, aerr = deriver_aveux_et_refus(sources_rs)
    for e in aerr:
        print(f"::error::{e}")
    if aerr:
        print("\nla DÉRIVATION des aveux et des refus nommés est incomplète : aucun verdict n'est rendu.")
        return 2, ""
    if (len(aveux_cles) < MIN_CLES_D_AVEU or CLE_D_AVEU_TEMOIN not in aveux_cles
            or len(ouvertures) < MIN_REFUS_NOMMES or OUVERTURE_TEMOIN not in ouvertures):
        print(f"::error::dérivation des aveux dégénérée : {len(aveux_cles)} clé(s) d'aveu (plancher {MIN_CLES_D_AVEU}, "
              f"témoin `{CLE_D_AVEU_TEMOIN}`), {len(ouvertures)} refus nommé(s) (plancher {MIN_REFUS_NOMMES}, témoin "
              f"« {OUVERTURE_TEMOIN} ») : la garde refuse de conclure.")
        return 2, ""
    codes_web = codes_web_de(sources_js)
    if not aveu_est_lu(CLE_D_AVEU_TEMOIN, codes_web) or not ouverture_est_lue(OUVERTURE_TEMOIN, codes_web):
        print(f"::error::la clé témoin `{CLE_D_AVEU_TEMOIN}` ou l'ouverture témoin « {OUVERTURE_TEMOIN} » n'est lue par "
              "aucun module web : soit la surface a régressé, soit le motif de lecture ne reconnaît plus le code.")
        return 1, ""
    cles_sourdes, ouvertures_sourdes = listes_sourdes(aveux_cles, ouvertures, codes_web)
    sourds = [f"la clé d'aveu `{cle}` est posée sur un succès par le démon ({', '.join(sorted(set(aveux_cles[cle])))}) et "
              f"AUCUN module web ne la lit dans son code : ce succès se lira NU, l'aveu perdu à l'écran."
              for cle in cles_sourdes]
    sourds += [f"le refus nommé « {o} » ({', '.join(ouvertures[o])}, daemon/src/{FICHIER_DES_REFUS_DU_PLAN_DE_CONTROLE}) est "
               f"servi en cinq cent trois et AUCUN module web n'en reconnaît l'ouverture : il se lira comme un refus quelconque."
               for o in ouvertures_sourdes]
    for e in sourds:
        print(f"::error::{e}")
    if sourds:
        print(f"\n{len(sourds)} aveu(x) ou refus nommé(s) du démon ne sont lus nulle part dans web/.")
        return 1, ""
    return 0, f"{len(aveux_cles)} clé(s) d'aveu de succès et {len(ouvertures)} refus nommé(s) du plan de contrôle, chacun lu"


# --- Lecture côté surface ---------------------------------------------------------------------
def lecteurs_du_web(sources, aveux=None):
    """`sources` : liste de (chemin, texte JS). Rend {chemin: code sans commentaires} pour les modules
    dont le CODE lit `_verdict`. Un module qui ne cite `_verdict` qu'en commentaire n'est pas un lecteur.
    `aveux` (facultatif) recueille les pertes de synchronisation du lecteur, PAR FICHIER : sans elles, un
    module dont une région serait avalée cesserait d'être un lecteur en silence."""
    out = {}
    for chemin, texte in sources:
        journal = []
        code = sans_commentaires_js(texte, journal)
        if journal and aveux is not None:
            aveux[os.path.basename(chemin)] = [f"ligne {texte.count(chr(10), 0, o) + 1} : {m}" for m, o in journal]
        if "_verdict" in code:
            out[chemin] = code
    return out


def est_lue(cle, lecteurs):
    """Une clé est lue si son littéral (entre guillemets simples, doubles ou accents graves), ou le
    littéral `<clé>_verdict`, figure dans le CODE d'un lecteur. `OBJET` est lu par `.verdict`."""
    if cle == OBJET:
        motif = re.compile(r"\.verdict\b|\[\s*['\"]verdict['\"]\s*\]")
    else:
        k = re.escape(cle)
        # Trois formes de lecture : le littéral entre guillemets (`'queue_depth'`, `'queue_depth_verdict'`),
        # l'accès de propriété (`c.queue_depth_verdict`), la clé d'un objet littéral (`queue_depth: 'libellé'`).
        # Pas un identifiant nu : une variable locale homonyme n'est pas une lecture.
        motif = re.compile(r"""(['"`])""" + k + r"""(?:_verdict)?\1"""
                           r"""|\.""" + k + r"""_verdict\b"""
                           r"""|(?<![\w$.])""" + k + r"""(?:_verdict)?\s*:(?!:)""")
    return sorted(os.path.relpath(c, RACINE) for c, code in lecteurs.items() if motif.search(code))


def suffixe_est_lu(suffixe, lecteurs):
    motif = re.compile(r"""(['"`])""" + re.escape(suffixe + "_verdict") + r"""\1""")
    return sorted(os.path.relpath(c, RACINE) for c, code in lecteurs.items() if motif.search(code))


# --- Validation de l'instrument ---------------------------------------------------------------
def valider_instrument():
    errs = []
    # LE LECTEUR PARTAGÉ SE VALIDE ICI AUSSI (`P11.8-f`). Il est IMPORTÉ, donc ses témoins ne tournent pas
    # à l'import : sans cet appel, un lecteur privé de sa reconnaissance des expressions régulières ou de
    # son aveu de perte de synchronisation ne serait épinglé que par la garde qui le PORTE, et cette
    # garde-ci rendrait un compte amputé en vert.
    try:
        temoins_du_lecteur()
    except AssertionError as e:
        errs.append(f"lecteur JavaScript partagé : {e}")
    rust = [
        ("a.rs",
         'queue.poser_dans(&mut ingest, "queue_depth");\n'
         'crate::maintenance::identite_hote().poser_verdict_dans(&mut hote, "identity");\n'
         'crate::bilan_de_tick::poser_bilan(&mut detection, "abandons_dernier_tick", b.as_ref());\n'
         'for boucle in BOUCLES { poser_bilan(&mut scheduler, &format!("{boucle}_abandons"), d.as_ref()); }\n'
         'process.insert("verdict".into(), json!(x.verdict()));\n'
         'store.insert("main_verdict".into(), json!("lu"));\n'
         'let j = json!({ "json_verdict": "lu" });\n'
         '("proc_verdict", "conntrack.sh"),\n'
         '// x.poser_dans(&mut ingest, "fictive_commentee");\n'
         '/* x.poser_dans(&mut ingest, "fictive_bloc"); */\n'
         'lisible(&mut o, "/ingest/pointeur_verdict", "/ingest/pointeur_cause");\n'
         'objet.insert(format!("{cle}_verdict"), json!(self.verdict()));\n'
         'let url = "http://exemple.invalid/x"; y.poser_dans(&mut z, "apres_url");\n'
         'fn f() -> (&\'static str, String) { x.poser_dans(&mut y, "apres_duree_de_vie"); }\n'
         '// x.poser_dans(&mut y, "commentee_apres_duree_de_vie");\n'),
        ("b.rs",
         'pub(crate) const BOUCLE_REGLES: &str = "regles";\n'
         'pub(crate) const BOUCLE_RISQUE: &str = "risque";\n'
         'pub(crate) const BOUCLES: [&str; 2] = [BOUCLE_REGLES, BOUCLE_RISQUE];\n'
         '#[cfg(test)]\npub(crate) fn aide_de_temoin() -> u8 { 0 }\n'
         'y.poser_dans(&mut z, "apres_fonction_de_test");\n'
         '#[cfg(test)]\nmod tests { fn t() { x.poser_dans(&mut y, "fictive_test"); } }\n'),
    ]
    cles, suffixes, derr = deriver_cles(rust)
    attendu = {"queue_depth", "identity", "abandons_dernier_tick", "regles_abandons", "risque_abandons",
               OBJET, "main_verdict", "apres_url", "apres_duree_de_vie", "apres_fonction_de_test"}
    # `main_verdict` : le littéral `"main_verdict"` n'est pas `"<clé>_verdict"`… il l'est : clé `main`.
    attendu = (attendu - {"main_verdict"}) | {"main", "json"}
    if derr:
        errs.append(f"témoin POSITIF (dérivation) : erreurs inattendues {derr}")
    if set(cles) != attendu:
        errs.append(f"témoin de DÉRIVATION en échec : attendu {sorted(attendu)}, obtenu {sorted(cles)} — "
                    "une forme d'émission n'est plus reconnue, ou une forme qui n'émet rien est comptée "
                    "(commentaire, test, pointeur de lecture, gabarit générique).")
    if set(suffixes) != {"_abandons"}:
        errs.append(f"témoin de GABARIT en échec : suffixes {sorted(suffixes)} au lieu de ['_abandons']")

    js = [
        ("lecteur.js",
         "function mesureTile(label, obj, cle) { const v = obj[cle + '_verdict']; return v; }\n"
         "mesureTile('File', ing, 'queue_depth');\n"
         "const k = Object.keys(sc).filter(k => k.endsWith('_abandons_verdict'));\n"
         "const p = obj.verdict ?? null;\n"
         "const LBL = { disk_used_pct: 'usage disque', x: c.db_size_bytes_verdict };\n"
         "let identite = 1; const cas = { identite_case: 2 };\n"
         "// mesureTile('X', ing, 'commentee');\n"
         "/* mesureTile('X', ing, 'bloc'); */\n"
         "const s = 'une url http://exemple.invalid/ dans une chaîne'; mesureTile('Y', db, 'apres_url');\n"),
        ("muet.js",
         "// ce module ne cite _verdict qu'en commentaire : 'queue_depth' ici ne compte pas\n"
         "const x = 'identity';\n"),
    ]
    lecteurs = lecteurs_du_web(js)
    if set(os.path.basename(c) for c in lecteurs) != {"lecteur.js"}:
        errs.append(f"témoin de LECTEURS en échec : {sorted(lecteurs)} — un module qui ne cite `_verdict` "
                    "qu'en commentaire ne doit pas être un lecteur")
    for cle, doit in (("queue_depth", True), ("apres_url", True), (OBJET, True),
                      ("disk_used_pct", True), ("db_size_bytes", True),
                      ("commentee", False), ("bloc", False), ("identity", False), ("identite", False)):
        if bool(est_lue(cle, lecteurs)) != doit:
            errs.append(f"témoin de LECTURE en échec sur `{cle}` : attendu {'lue' if doit else 'NON lue'} — "
                        "une clé citée en commentaire, ou hors d'un lecteur, ne compte pas")
    if not suffixe_est_lu("_abandons", lecteurs) or suffixe_est_lu("_autre", lecteurs):
        errs.append("témoin de SUFFIXE en échec : `_abandons_verdict` doit être reconnu, `_autre_verdict` non")

    # `P10.30-d` — LES AVEUX DE SUCCÈS ET LES REFUS NOMMÉS, sur un corpus de contrôle, dans les deux sens.
    rust_aveux = [
        ("ledger.rs", 'pub(crate) const CLE_A: &str = "aveu_a";\n'
                      'pub(crate) const CLE_B: &str = "aveu_b";\n'
                      'pub(crate) const CLE_C: &str = "aveu_commente";\n'
                      'pub(crate) const CLE_D: &str = "aveu_seulement_compare";\n'
                      'pub(crate) const CLE_T: &str = "aveu_de_test";\n'),
        ("rbac.rs", 'fn f(corps: &mut Value) { corps[CLE_A] = json!(1); }\n'
                    'fn g(o: &mut Value) { if x { o[CLE_B] = json!(CAUSE_Y); } }\n'
                    '// corps[CLE_C] = json!(1);\n'
                    'fn h(corps: &Value) -> bool { corps[CLE_D] == json!(1) }\n'
                    'pub(crate) const CAUSE_R: &str = "REFUS PAR UN RELAIS FIXE : u";\n'
                    'pub(crate) const CAUSE_V: &str = "RELAIS JAMAIS APPELÉ ICI : t";\n'
                    'pub(crate) fn refuser_par_relais(c: &str) -> Response {\n'
                    '    err_json(StatusCode::SERVICE_UNAVAILABLE, format!("{CAUSE_R} ({c})"))\n}\n'
                    'pub(crate) fn refuser_jamais_appele() -> Response { err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_V) }\n'
                    '#[cfg(test)]\nmod tests { fn t(corps: &mut Value) { corps[CLE_T] = json!(1); } }\n'),
        ("tenants.rs", 'pub(crate) const CAUSE_X: &str = "TENANT ILLISIBLE, RIEN FAIT : le plan \\\n     de contrôle.";\n'
                       'pub(crate) const CAUSE_Y: &str = "BASCULE PERDUE, RIEN N\'A CHANGÉ : x";\n'
                       'pub(crate) const CAUSE_Z: &str = "DESTRUCTION REFUSÉE AVANT TOUT : y";\n'
                       'pub(crate) const CAUSE_N: &str = "INCONNU QUATRE CENT QUATRE : z";\n'
                       'pub(crate) const CAUSE_C: &str = "REFUS COMMENTÉ SEULEMENT : w";\n'
                       'fn a() -> Response { return err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_X); }\n'
                       'fn b() -> Response { refuser_le_geste_non_ecrit(CAUSE_Y, &cause) }\n'
                       'fn c() -> Response { err_json(StatusCode::SERVICE_UNAVAILABLE, format!("{CAUSE_Z} ({cause})")) }\n'
                       'fn d() -> Response { err_json(StatusCode::NOT_FOUND, CAUSE_N) }\n'
                       'fn r() -> Response { return refuser_par_relais(&cause); }\n'
                       'pub(crate) const CAUSE_U: &str = "REFUS EN TUPLE JSON, RIEN FAIT : u";\n'
                       'pub(crate) const CAUSE_W: &str = "REFUS EN TUPLE D\'ERREUR, RIEN FAIT : w";\n'
                       'pub(crate) const CAUSE_M: &str = "TUPLE QUATRE CENT QUATRE : m";\n'
                       'fn t() -> Response { (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": CAUSE_U }))).into_response() }\n'
                       'fn t2() -> Result<(), (StatusCode, String)> { Err((StatusCode::SERVICE_UNAVAILABLE, CAUSE_W.to_string())) }\n'
                       'fn t3() -> Response { (StatusCode::NOT_FOUND, Json(json!({ "error": CAUSE_M }))).into_response() }\n'
                       '// err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_C)\n'),
        ("autre.rs", 'pub(crate) const CAUSE_H: &str = "HORS DU PLAN DE CONTRÔLE : v";\n'
                     'fn e() -> Response { err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_H) }\n'
                     'fn e2() -> Response { refuser_jamais_appele() }\n'),
    ]
    attendues = {"TENANT ILLISIBLE, RIEN FAIT", "BASCULE PERDUE, RIEN N'A CHANGÉ", "DESTRUCTION REFUSÉE AVANT TOUT",
                 "REFUS PAR UN RELAIS FIXE", "REFUS EN TUPLE JSON, RIEN FAIT", "REFUS EN TUPLE D'ERREUR, RIEN FAIT"}
    a_cles, a_ouv, a_err = deriver_aveux_et_refus(rust_aveux)
    if a_err:
        errs.append(f"témoin des AVEUX (dérivation) : erreurs inattendues {a_err}")
    if set(a_cles) != {"aveu_a", "aveu_b"}:
        errs.append(f"témoin des CLÉS D'AVEU en échec : obtenu {sorted(a_cles)} au lieu de ['aveu_a', 'aveu_b'] — "
                    "une pose n'est plus reconnue, ou une comparaison, un commentaire, un module de test est compté")
    if set(a_ouv) != attendues:
        errs.append(f"témoin des REFUS NOMMÉS en échec : obtenu {sorted(a_ouv)} au lieu de {sorted(attendues)} — un cinq "
                    "cent trois nommé du plan de contrôle (direct, `refuser_le_geste_non_ecrit`, `format!`, en tuple, ou par "
                    "un relais à cause fixe) n'est plus reconnu, ou un quatre cent quatre, un commentaire, un autre fichier, "
                    "un relais qu'il n'appelle pas est compté")
    # LES BRANCHES QUI REFUSENT DE CONCLURE, chacune sur un corpus qui ne déclenche qu'elle.
    for quoi, corpus in (
            ("une clé d'aveu sans constante lisible",
             [("rbac.rs", "fn f(corps: &mut Value) { corps[CLE_FANTOME] = json!(1); }\n")]),
            ("un refus nommé sans constante lisible",
             [("tenants.rs", "fn a() -> Response { err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_FANTOME) }\n")]),
            ("un refus nommé sans ouverture (aucun « : »)",
             [("tenants.rs", 'pub(crate) const CAUSE_S: &str = "PHRASE SANS DEUX POINTS NULLE PART";\n'
                             "fn a() -> Response { err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_S) }\n")]),
            ("un refus nommé dont l'ouverture est trop courte",
             [("tenants.rs", 'pub(crate) const CAUSE_S: &str = "TROP COURT : x";\n'
                             "fn a() -> Response { err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_S) }\n")]),
    ):
        _, _, e_err = deriver_aveux_et_refus(corpus)
        if len(e_err) != 1:
            errs.append(f"témoin des AVEUX en échec : {quoi} rend {len(e_err)} erreur(s) au lieu d'une — la garde "
                        f"conclurait sans l'avoir lu ({e_err})")
    # LA LECTURE, par le MÊME câblage que `main` (`codes_web_de` sur le texte BRUT) : en code, lue ; en commentaire
    # seulement, non ; TRONQUÉE dans le code (ses douze premiers caractères et plus, pas l'ouverture entière), non.
    js_aveux = codes_web_de([
        (os.path.join(WEB, "lit.js"),
         "const CLE = 'aveu_a'; const O = /^BASCULE PERDUE, RIEN N'A CHANGÉ(?![\\p{L}])/u;\n"
         "const P = /^DESTRUCTION REFUSÉE AVANT/u;\n"
         "// const K = 'aveu_b'; /^TENANT ILLISIBLE, RIEN FAIT/ /^REFUS PAR UN RELAIS FIXE/\n"
         "/* 'aveu_b' REFUS PAR UN RELAIS FIXE */\n"),
    ])
    if (not aveu_est_lu("aveu_a", js_aveux) or aveu_est_lu("aveu_b", js_aveux)
            or not ouverture_est_lue("BASCULE PERDUE, RIEN N'A CHANGÉ", js_aveux)
            or ouverture_est_lue("TENANT ILLISIBLE, RIEN FAIT", js_aveux)
            or ouverture_est_lue("REFUS PAR UN RELAIS FIXE", js_aveux)
            or ouverture_est_lue("DESTRUCTION REFUSÉE AVANT TOUT", js_aveux)):
        errs.append("témoin de LECTURE DES AVEUX en échec : une clé ou une ouverture citée en CODE doit être lue ; la "
                    "même citée en commentaire, ou une ouverture tronquée dans le code, non")
    # LE VERDICT : les sourds, nommés un à un, dans les deux sens.
    sourdes = listes_sourdes(a_cles, a_ouv, js_aveux)
    if sourdes != (["aveu_b"], ["DESTRUCTION REFUSÉE AVANT TOUT", "REFUS EN TUPLE D'ERREUR, RIEN FAIT",
                                "REFUS EN TUPLE JSON, RIEN FAIT", "REFUS PAR UN RELAIS FIXE", "TENANT ILLISIBLE, RIEN FAIT"]):
        errs.append(f"témoin des SOURDS en échec : obtenu {sourdes} — une clé ou une ouverture que le web ne lit pas "
                    "n'est plus comptée sourde, ou une qu'il lit l'est")
    # LE VERDICT ENTIER, par la fonction même que `main` appelle (`verdict_des_aveux`), sur un corpus qui franchit les
    # planchers réels : lu en entier, il conclut 0 ; une clé et une ouverture lues seulement en commentaire le font conclure 1,
    # et chacune y est nommée ; une erreur de dérivation, ou chaque condition du plancher seule en défaut, le font REFUSER de
    # conclure (2).
    rs_verdict = [
        ("ledger.rs", f'pub(crate) const CLE_TEMOIN: &str = "{CLE_D_AVEU_TEMOIN}";\n'
                      'pub(crate) const CLE_A: &str = "aveu_a";\npub(crate) const CLE_B: &str = "aveu_b";\n'),
        ("rbac.rs", "fn f(corps: &mut Value) { corps[CLE_TEMOIN] = json!(1); corps[CLE_A] = json!(2); corps[CLE_B] = json!(3); }\n"),
        ("tenants.rs", f'pub(crate) const CAUSE_T: &str = "{OUVERTURE_TEMOIN} : x";\n'
                       'pub(crate) const CAUSE_P: &str = "BASCULE PERDUE, RIEN N\'A CHANGÉ : y";\n'
                       'pub(crate) const CAUSE_Q: &str = "TENANT ILLISIBLE, RIEN FAIT : z";\n'
                       "fn a() -> Response { err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_T) }\n"
                       "fn b() -> Response { err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_P) }\n"
                       "fn c() -> Response { err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_Q) }\n"),
    ]
    tete_js = f"const K = ['{CLE_D_AVEU_TEMOIN}', 'aveu_a']; const O = [/^{OUVERTURE_TEMOIN}/u, /^BASCULE PERDUE, RIEN N'A CHANGÉ/u];\n"
    js_tout_lu = [(os.path.join(WEB, "lit.js"), tete_js + "const L = ['aveu_b', /^TENANT ILLISIBLE, RIEN FAIT/u];\n")]
    js_commente = [(os.path.join(WEB, "lit.js"), tete_js + "// const L = ['aveu_b', /^TENANT ILLISIBLE, RIEN FAIT/u];\n")]
    rs_fantome = rs_verdict[:2] + [("tenants.rs", rs_verdict[2][1]
                                    + "fn d() -> Response { err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_FANTOME) }\n")]
    rs_sous_plancher = [rs_verdict[0], ("rbac.rs", "fn f(corps: &mut Value) { corps[CLE_TEMOIN] = json!(1); corps[CLE_A] = json!(2); }\n"),
                        rs_verdict[2]]
    # LES TROIS AUTRES CONDITIONS DU PLANCHER, chacune seule en défaut (2026-10-20) : avant, seul le plancher des CLÉS était
    # éprouvé, et retirer le plancher des refus nommés, l'abaisser d'un, ou retirer l'un des deux termes de témoin
    # (`CLE_D_AVEU_TEMOIN`, `OUVERTURE_TEMOIN`) restait vert — une dérivation qui perd son témoin concluait OK. Chaque corpus
    # ci-dessous franchit TOUTES les autres conditions, et le web y lit tout ce qui est dérivé : sans la condition visée, le
    # verdict rendrait 0.
    rs_deux_refus = rs_verdict[:2] + [("tenants.rs", f'pub(crate) const CAUSE_T: &str = "{OUVERTURE_TEMOIN} : x";\n'
                                                     'pub(crate) const CAUSE_P: &str = "BASCULE PERDUE, RIEN N\'A CHANGÉ : y";\n'
                                                     "fn a() -> Response { err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_T) }\n"
                                                     "fn b() -> Response { err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_P) }\n")]
    rs_sans_cle_temoin = [("ledger.rs", 'pub(crate) const CLE_A: &str = "aveu_a";\npub(crate) const CLE_B: &str = "aveu_b";\n'
                                        'pub(crate) const CLE_C: &str = "aveu_c";\n'),
                          ("rbac.rs", "fn f(corps: &mut Value) { corps[CLE_A] = json!(1); corps[CLE_B] = json!(2); corps[CLE_C] = json!(3); }\n"),
                          rs_verdict[2]]
    rs_sans_ouverture_temoin = rs_verdict[:2] + [("tenants.rs", 'pub(crate) const CAUSE_P: &str = "BASCULE PERDUE, RIEN N\'A CHANGÉ : y";\n'
                                                                'pub(crate) const CAUSE_Q: &str = "TENANT ILLISIBLE, RIEN FAIT : z";\n'
                                                                'pub(crate) const CAUSE_S: &str = "DÉRIVÉE SANS SON TÉMOIN, RIEN FAIT : s";\n'
                                                                "fn b() -> Response { err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_P) }\n"
                                                                "fn c() -> Response { err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_Q) }\n"
                                                                "fn s() -> Response { err_json(StatusCode::SERVICE_UNAVAILABLE, CAUSE_S) }\n")]
    js_tout_lu_large = [(os.path.join(WEB, "lit.js"), tete_js + "const L = ['aveu_b', 'aveu_c', /^TENANT ILLISIBLE, RIEN FAIT/u, "
                                                                "/^DÉRIVÉE SANS SON TÉMOIN, RIEN FAIT/u];\n")]
    # LE TÉMOIN NON LU PAR LE WEB (2026-10-22) : le démon dérive tout, au-dessus des planchers, mais le web ne lit pas la clé
    # témoin (ou l'ouverture témoin) alors qu'il lit tout le reste. Le verdict doit conclure 1 PAR la branche du témoin, qui
    # se nomme « n'est lue par aucun module web » : avant, aucun corpus ne la jouait, et la faire rendre 0 restait vert.
    js_sans_cle_temoin = [(os.path.join(WEB, "lit.js"),
                           f"const K = ['aveu_a', 'aveu_b']; const O = [/^{OUVERTURE_TEMOIN}/u, "
                           "/^BASCULE PERDUE, RIEN N'A CHANGÉ/u, /^TENANT ILLISIBLE, RIEN FAIT/u];\n")]
    js_sans_ouverture_temoin = [(os.path.join(WEB, "lit.js"),
                                 f"const K = ['{CLE_D_AVEU_TEMOIN}', 'aveu_a', 'aveu_b']; "
                                 "const O = [/^BASCULE PERDUE, RIEN N'A CHANGÉ/u, /^TENANT ILLISIBLE, RIEN FAIT/u];\n")]
    for quoi, corpus_rs, corpus_js, rc_attendu, doit_nommer in (
            ("tout lu dans le code", rs_verdict, js_tout_lu, 0, ()),
            ("une clé et une ouverture lues seulement en commentaire", rs_verdict, js_commente, 1,
             ("`aveu_b`", "« TENANT ILLISIBLE, RIEN FAIT »")),
            ("un refus nommé sans constante lisible (erreur de dérivation)", rs_fantome, js_tout_lu, 2, ("`CAUSE_FANTOME`",)),
            ("deux clés d'aveu seulement (sous le plancher)", rs_sous_plancher, js_tout_lu, 2, ("dégénérée",)),
            ("deux refus nommés seulement (sous le plancher)", rs_deux_refus, js_tout_lu, 2, ("dégénérée", "2 refus nommé(s)")),
            ("trois clés d'aveu sans la clé témoin", rs_sans_cle_temoin, js_tout_lu_large, 2, ("dégénérée",)),
            ("trois refus nommés sans l'ouverture témoin", rs_sans_ouverture_temoin, js_tout_lu_large, 2, ("dégénérée",)),
            ("la clé témoin non lue par le web, tout le reste lu", rs_verdict, js_sans_cle_temoin, 1,
             ("n'est lue par aucun module web",)),
            ("l'ouverture témoin non lue par le web, tout le reste lu", rs_verdict, js_sans_ouverture_temoin, 1,
             ("n'est lue par aucun module web",)),
    ):
        dit = io.StringIO()
        with contextlib.redirect_stdout(dit):
            rc_obtenu, _ = verdict_des_aveux(corpus_rs, corpus_js)
        manque = [n for n in doit_nommer if n not in dit.getvalue()]
        if rc_obtenu != rc_attendu or manque or (rc_attendu == 0 and "::error::" in dit.getvalue()):
            errs.append(f"témoin du VERDICT DES AVEUX en échec : {quoi} rend rc={rc_obtenu} au lieu de {rc_attendu}"
                        + (f", sans nommer {', '.join(manque)}" if manque else "")
                        + " — le verdict que `main` rend avale une erreur de dérivation, lit le web brut, ou conclut sans "
                          "avoir lu")
    # `main` REND LE CODE DU VERDICT DES AVEUX (2026-10-20). Le corpus ci-dessus juge la fonction, pas son appelant : un
    # `main` qui ne propagerait que le 1 (un refus de conclure imprimé, puis la garde qui poursuit et conclut), ou qui
    # ignorerait le code reçu, restait vert. `main` est donc JOUÉ, dans un sous-processus, sur une racine hostile
    # fabriquée (argv[1]) qui franchit toutes les étapes d'avant : il doit s'arrêter sur le verdict des aveux, avec son
    # code, sans atteindre l'étape suivante (le harnais ESM). L'enfant ne rejoue pas ce témoin-ci (variable d'environnement).
    if os.environ.get(ENFANT_DU_TEMOIN_DE_MAIN) != "1":
        for quoi, corpus_rs, corpus_js, rc_attendu, doit_nommer in (
                ("un refus nommé sans constante lisible", rs_fantome, js_tout_lu, 2, "`CAUSE_FANTOME`"),
                ("une clé et une ouverture lues seulement en commentaire", rs_verdict, js_commente, 1, "`aveu_b`"),
        ):
            rc_obtenu, dit = jouer_main_sur_une_racine_fabriquee(corpus_rs, corpus_js[0][1])
            suite_atteinte = [m for m in ("harnais ESM", "OK —", "l'INSTRUMENT est faux") if m in dit]
            if rc_obtenu != rc_attendu or doit_nommer not in dit or suite_atteinte:
                errs.append(f"témoin de MAIN en échec : sur une racine où le verdict des aveux rend {rc_attendu} ({quoi}), "
                            f"`main` rend rc={rc_obtenu}"
                            + (f", sans nommer {doit_nommer}" if doit_nommer not in dit else "")
                            + (f", et poursuit au-delà ({', '.join(suite_atteinte)})" if suite_atteinte else "")
                            + " — `main` avale le code du verdict des aveux au lieu de le rendre")
    return errs


# Le témoin de `main` joue la garde dans un sous-processus : l'enfant porte cette variable et ne relance pas le témoin.
ENFANT_DU_TEMOIN_DE_MAIN = "GARDE_DES_VERDICTS_ENFANT_DU_TEMOIN_DE_MAIN"
# Ce qui fait franchir à `main` les étapes d'avant le verdict des aveux : trois clés `_verdict` dont le témoin, lues.
RS_VERDICTS_D_UNE_RACINE_FABRIQUEE = ('fn v(o: &mut Value) { q.poser_dans(&mut o, "' + CLE_TEMOIN + '"); '
                                      'q.poser_dans(&mut o, "cle_b"); q.poser_dans(&mut o, "cle_c"); }\n')
JS_VERDICTS_D_UNE_RACINE_FABRIQUEE = "const V = ['" + CLE_TEMOIN + "_verdict', 'cle_b_verdict', 'cle_c_verdict'];\n"


def jouer_main_sur_une_racine_fabriquee(sources_rs, texte_js):
    """Écrit `sources_rs` (+ les verdicts d'une racine fabriquée) sous daemon/src/ et `texte_js` sous web/lit.js d'une
    racine temporaire, y joue ce script entier (`main`, argv[1] = la racine) et rend (code de sortie, sortie)."""
    with tempfile.TemporaryDirectory(prefix="garde-des-verdicts-") as racine:
        os.makedirs(os.path.join(racine, "daemon", "src"))
        os.makedirs(os.path.join(racine, "web"))
        for nom, texte in list(sources_rs) + [("verdicts.rs", RS_VERDICTS_D_UNE_RACINE_FABRIQUEE)]:
            with open(os.path.join(racine, "daemon", "src", os.path.basename(nom)), "w", encoding="utf-8") as fh:
                fh.write(texte)
        with open(os.path.join(racine, "web", "lit.js"), "w", encoding="utf-8") as fh:
            fh.write(JS_VERDICTS_D_UNE_RACINE_FABRIQUEE + texte_js)
        try:
            r = subprocess.run([sys.executable, os.path.abspath(__file__), racine], capture_output=True, text=True,
                               timeout=300, env=dict(os.environ, **{ENFANT_DU_TEMOIN_DE_MAIN: "1"}))
        except subprocess.TimeoutExpired:
            return None, "le sous-processus n'a pas rendu en 300 s"
        return r.returncode, r.stdout + r.stderr


def main():
    errs = valider_instrument()
    if errs:
        for e in errs:
            print(f"::error::{e}")
        print("\nl'INSTRUMENT est faux : aucun verdict n'est rendu.")
        return 2

    sources_rs = []
    for chemin in fichiers_du_demon():
        with open(chemin, encoding="utf-8", errors="replace") as fh:
            sources_rs.append((chemin, fh.read()))
    sources_js = []
    for nom in sorted(os.listdir(WEB)):
        if nom.endswith(".js"):
            with open(os.path.join(WEB, nom), encoding="utf-8", errors="replace") as fh:
                sources_js.append((os.path.join(WEB, nom), fh.read()))

    aveux_rust = {}
    cles, suffixes, derr = deriver_cles(sources_rs, aveux_rust)
    # L'AVEU DU LECTEUR RUST PASSE AVANT TOUT VERDICT (`P10.20-d`). Une région avalée produit d'abord des
    # erreurs de dérivation trompeuses, puis un compte amputé : la cause se nomme ici, une seule fois.
    if aveux_rust and refuser_sur_aveu("verdicts", aveux_rust, "Rust"):
        return 2
    for e in derr:
        print(f"::error::{e}")
    if derr:
        print("\nla DÉRIVATION est incomplète : aucun verdict n'est rendu.")
        return 2
    if len(cles) < MIN_CLES:
        print(f"::error::seulement {len(cles)} clé(s) `_verdict` dérivée(s) du démon ({sorted(cles)}), "
              f"plancher {MIN_CLES} : la dérivation est cassée, la garde refuse de conclure.")
        return 2
    if CLE_TEMOIN not in cles:
        print(f"::error::la clé témoin `{CLE_TEMOIN}` n'est plus dérivée du démon : soit le démon a cessé "
              f"de la publier (changez le témoin), soit la dérivation ne voit plus son site.")
        return 2

    aveux = {}
    lecteurs = lecteurs_du_web(sources_js, aveux)
    if aveux and refuser_sur_aveu("verdicts", aveux):
        return 2
    if not lecteurs:
        print("::error::aucun module sous web/ ne lit `_verdict` dans son CODE : la surface aplatit tous "
              "les verdicts.")
        return 1
    if not est_lue(CLE_TEMOIN, lecteurs):
        print(f"::error::la clé témoin `{CLE_TEMOIN}` est publiée mais aucun lecteur ne la lit : soit la "
              f"surface a régressé, soit le motif de lecture ne reconnaît plus la forme du code.")
        return 1

    manquantes = []
    for cle, sites in sorted(cles.items()):
        if est_lue(cle, lecteurs):
            continue
        # Clé de gabarit : lue par balayage du suffixe.
        gabarit = next((s for s in suffixes if cle.endswith(s)), None)
        if gabarit and suffixe_est_lu(gabarit, lecteurs):
            continue
        manquantes.append((cle, sites))
    for cle, sites in manquantes:
        nom = "verdict d'objet entier (`insert(\"verdict\")`)" if cle == OBJET else f"`{cle}_verdict`"
        print(f"::error::{nom} est publié par le démon ({', '.join(sorted(set(sites)))}) et AUCUN module "
              f"web ne lit cette clé dans son code : la surface aplatit ce verdict en valeur — une "
              f"grandeur illisible se rendra comme un zéro, un tiret ou une case vide. Faites-la lire "
              f"par `lireMesure` (web/system.js) et rendre par le témoin ESM.")
    if manquantes:
        print(f"\n{len(manquantes)} clé(s) sur {len(cles)} publiées avec un verdict ne sont lues nulle part.")
        return 1

    # `P10.30-d` — LES AVEUX DE SUCCÈS ET LES REFUS NOMMÉS : le MÊME verdict que le corpus de contrôle a joué.
    rc_des_aveux, bilan_des_aveux = verdict_des_aveux(sources_rs, sources_js)
    if rc_des_aveux != 0:
        return rc_des_aveux

    if shutil.which("node") is None:
        print("::error::`node` est absent : le harnais ESM ne peut pas rendre le panneau, la garde refuse "
              "de conclure (la lecture d'une clé ne dit pas comment elle est rendue).")
        return 2
    r = subprocess.run(["node", HARNAIS], cwd=RACINE, capture_output=True, text=True)
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    if r.returncode != 0:
        print(f"\nle harnais ESM rougit (rc={r.returncode}) : une clé est lue, mais pas rendue comme un état.")
        return 1

    print(f"OK — {len(cles)} clé(s) `_verdict` dérivées du démon ({len(suffixes)} gabarit(s) résolu(s)), "
          f"chacune lue par la surface ({', '.join(sorted(os.path.relpath(c, RACINE) for c in lecteurs))}) ; "
          f"{bilan_des_aveux}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
