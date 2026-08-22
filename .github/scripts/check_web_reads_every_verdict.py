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

CE QUE CETTE GARDE NE PROUVE PAS, ET QUI EST PROUVÉ AILLEURS
------------------------------------------------------------
Qu'une clé soit LUE ne dit pas comment elle est RENDUE. Le harnais ESM (`web_esm_harnais.mjs`,
lancé en dernier pas) rend le panneau sur des objets fabriqués et exige l'état distinct, la cause
nommée et les abandons visibles — et, dans l'autre sens, la valeur quand le verdict est « lu ».
"""
import os
import re
import shutil
import subprocess
import sys

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
CONST_BOUCLE = re.compile(r'const\s+(BOUCLE_[A-Z0-9_]+)\s*:\s*&str\s*=\s*"([A-Za-z0-9_]+)"')
TABLE_BOUCLES = re.compile(r'const\s+BOUCLES\s*:\s*\[&str;\s*\d+\]\s*=\s*\[([^\]]*)\]')

# Marqueur d'une clé de gabarit : `{boucle}_abandons` -> clés `regles_abandons`… + suffixe `_abandons`.
OBJET = "<objet>"


# Délimiteurs de chaîne par langage. En Rust, `'` n'en est PAS un : c'est une durée de vie
# (`&'static str`), et la prendre pour une ouverture de chaîne protégerait tout ce qui suit, jusqu'au
# `'` suivant, du retrait des commentaires — une émission COMMENTÉE y serait comptée. Un littéral de
# caractère `'"'` reste le cas non couvert, et il est dit.
CHAINES_RUST = '"'
CHAINES_JS = "\"'`"


def sans_commentaires(src, delimiteurs=CHAINES_JS):
    """Retire les commentaires `//` et `/* */` en respectant les chaînes (une URL dans une chaîne
    n'est pas un commentaire). Une chaîne brute Rust `r#"…"#` ou un gabarit JS multi-ligne sont
    traités comme des chaînes ordinaires."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if c in delimiteurs:
            j = i + 1
            while j < n and src[j] != c:
                j += 2 if src[j] == "\\" else 1
            out.append(src[i:j + 1])
            i = j + 1
        elif src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def fichiers_du_demon():
    """Les sources du démon HORS tests : un test peut poser une clé factice sans que le démon la
    publie. Découverte par parcours, pas par liste."""
    for dossier, sous, noms in os.walk(DEMON):
        sous[:] = [d for d in sous if d != "tests"]
        for nom in sorted(noms):
            if nom.endswith(".rs") and nom != "tests.rs":
                yield os.path.join(dossier, nom)


def deriver_cles(sources):
    """`sources` : liste de (chemin, texte Rust). Rend ({clé: [sites]}, {suffixe: [sites]}, erreurs).
    Une clé `OBJET` désigne un verdict posé sur l'objet entier (`insert("verdict")`)."""
    cles, suffixes, erreurs = {}, {}, []
    boucles, table = {}, None
    textes = []
    for chemin, texte in sources:
        code = sans_commentaires(texte, CHAINES_RUST)
        # Un module de test en ligne (`#[cfg(test)] mod …`) est coupé : tout ce qui suit est du test.
        coupe = code.find("#[cfg(test)]")
        if coupe >= 0:
            code = code[:coupe]
        textes.append((chemin, code))
        for m in CONST_BOUCLE.finditer(code):
            boucles[m.group(1)] = m.group(2)
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
            if table is None:
                erreurs.append(f"{os.path.relpath(chemin, RACINE)} : gabarit `{{{m.group(1)}}}{suffixe}` "
                               f"sans table `BOUCLES` résolue — les clés concrètes ne peuvent pas être dérivées")
                continue
            for nom_const in table:
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


# --- Lecture côté surface ---------------------------------------------------------------------
def lecteurs_du_web(sources):
    """`sources` : liste de (chemin, texte JS). Rend {chemin: code sans commentaires} pour les modules
    dont le CODE lit `_verdict`. Un module qui ne cite `_verdict` qu'en commentaire n'est pas un lecteur."""
    out = {}
    for chemin, texte in sources:
        code = sans_commentaires(texte)
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
         '#[cfg(test)]\nmod tests { fn t() { x.poser_dans(&mut y, "fictive_test"); } }\n'),
    ]
    cles, suffixes, derr = deriver_cles(rust)
    attendu = {"queue_depth", "identity", "abandons_dernier_tick", "regles_abandons", "risque_abandons",
               OBJET, "main_verdict", "apres_url", "apres_duree_de_vie"}
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
    return errs


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

    cles, suffixes, derr = deriver_cles(sources_rs)
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

    lecteurs = lecteurs_du_web(sources_js)
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
          f"chacune lue par la surface ({', '.join(sorted(os.path.relpath(c, RACINE) for c in lecteurs))}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
