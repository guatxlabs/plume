#!/usr/bin/env python3
"""`P8.9-l` — LA RÈGLE QUE LES DOCUMENTS EXIGENT DES FICHIERS EST TENUE PAR UN INSTRUMENT.

CE QUI ÉTAIT MESURÉ (2026-08-30, re-mesuré le 2026-09-09). `AGENTS.md` et `CONTRIBUTING.md` refusent le
récit à la première personne dans les messages de commit ET l'exigent des commentaires de code et de
la documentation (« ils s'adressent au lecteur, pas à un interlocuteur »). Le message de commit est
tenu par `verifier-message-de-commit.sh` ; les FICHIERS ne l'étaient par rien, et dix-sept lignes de
commentaires et de prose portaient « j'avais compté », « mon premier jet », « rejoué par moi ». La
classe avait déjà été corrigée à la main une fois, sans garde, et elle était revenue.

LA FAMILLE N'EST PAS RECOPIÉE ICI : ELLE EST LUE DANS LE VÉRIFICATEUR DE MESSAGE. Les deux motifs
(récit, possessif) sont extraits de `verifier-message-de-commit.sh` — si le vérificateur change de
vocabulaire, cette garde suit ; s'il n'est plus lisible, elle refuse de conclure (code 2).

LE CRITÈRE EST DÉRIVÉ DE LA RÈGLE, ET IL NE DOIT PAS ACCUSER À TORT. Sont jugés : le texte des
COMMENTAIRES des fichiers de code, et la PROSE des documents Markdown hors blocs de code. Sont retirés
AVANT le jugement, parce que la règle les nomme légitimes : les CITATIONS entre guillemets français —
y compris quand elles s'étendent sur plusieurs lignes —, les chaînes entre guillemets droits (un
message adressé à l'exploitant : « je n'ai pas pu mesurer »), et les extraits entre accents graves
(un identifiant `moi`, `$moi`). Le vérificateur de message lui-même est hors corpus : il PORTE la
famille qu'il interdit.

L'INDEX (`docs/ROADMAP.md`) EST SOUS UN CLIQUET, PAS SOUS LE PLAFOND ZÉRO. Ses cellules sont des
constats de mesure où la première personne marque une prémisse réfutée de l'auteur ; mesuré le
2026-09-09 : 52 lignes (PLAFOND_INDEX). Le cliquet ne garde que la BAISSE — une ligne de plus rougit, une
ligne de moins invite à abaisser le plafond — et il est écrit ici comme un reste, pas comme une norme.

Sortie 0 = rien hors plafond ; 1 = une ligne s'adresse à l'auteur ; 2 = refus de conclure.
`--liste` imprime les lignes retenues (fichier:ligne, motif, extrait).
"""
import os
import re
import subprocess
import sys

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.realpath(os.path.join(ICI, os.pardir, os.pardir))
VERIFICATEUR = ".github/scripts/verifier-message-de-commit.sh"
INDEX = "docs/ROADMAP.md"
PLAFOND_INDEX = 0           # 52 le 2026-09-09, 0 le 2026-09-10 (`P8.9-l`, 89 réécritures) ; ne peut que baisser, et il est en bas
MIN_FICHIERS = 300
MIN_MOTIFS = 2

COMMENTAIRE = {
    ".rs": re.compile(r"//+!?\s?(.*)"), ".js": re.compile(r"//\s?(.*)"), ".mjs": re.compile(r"//\s?(.*)"),
    ".py": re.compile(r"#\s?(.*)"), ".sh": re.compile(r"#\s?(.*)"), ".yml": re.compile(r"#\s?(.*)"),
    ".yaml": re.compile(r"#\s?(.*)"), ".toml": re.compile(r"#\s?(.*)"), ".ps1": re.compile(r"#\s?(.*)"),
    ".css": re.compile(r"/\*\s?(.*?)\*/"),
}
LEGITIME = re.compile(r"«[^»]*»|\"[^\"]*\"|`[^`]*`")


def motifs_du_verificateur(texte):
    """Les motifs `grep -qiE "…"` que le vérificateur applique au STYLE et dont la faute nommée est le
    RÉCIT ou le POSSESSIF de l'auteur — la famille que la règle exige des fichiers. Le repère de session
    (« hier », « aujourd'hui »), lui, reste une faute de MESSAGE : dans un fichier, « aujourd'hui » veut
    dire « sur cet arbre » et vieillit avec lui, ce que d'autres gardes datent ; il n'est pas pris ici."""
    out = []
    for m in re.finditer(r'printf \'%s\' "\$style" \| grep -qiE "((?:[^"\\]|\\.)*)"; then\n\s*ajoute "([^"]*)"', texte):
        brut, faute = m.group(1).replace('\\"', '"'), m.group(2).lower()
        if "premiere personne" not in faute and "première personne" not in faute and "possessif" not in faute:
            continue
        try:
            out.append(re.compile(brut, re.I))
        except re.error:
            return None
    return out


def lignes_jugees(nom, texte):
    """[(numéro, texte jugé)] : commentaires d'un fichier de code, prose d'un document Markdown."""
    ext = os.path.splitext(nom)[1]
    out, dans_bloc, dans_citation = [], False, False
    for i, l in enumerate(texte.split("\n"), 1):
        if ext == ".md":
            if l.strip().startswith("```"):
                dans_bloc = not dans_bloc
                continue
            if dans_bloc:
                continue
            brut = l
        else:
            m = COMMENTAIRE[ext].search(l)
            if not m:
                continue
            brut = m.group(1)
        # une citation ouverte sur une ligne et fermée sur une autre couvre tout ce qui est entre les deux
        if dans_citation:
            if "»" in brut:
                brut = brut.split("»", 1)[1]
                dans_citation = False
            else:
                continue
        if brut.count("«") > brut.count("»"):
            brut = brut.rsplit("«", 1)[0]
            dans_citation = True
        out.append((i, LEGITIME.sub("", brut)))
    return out


def retenues(nom, texte, motifs):
    out = []
    for i, s in lignes_jugees(nom, texte):
        for p in motifs:
            m = p.search(s)
            if m:
                out.append((nom, i, m.group(0), s.strip()[:100]))
                break
    return out


def fichiers_suivis():
    r = subprocess.run(["git", "ls-files"], cwd=RACINE, capture_output=True, text=True)
    if r.returncode:
        return None
    return [f for f in r.stdout.split("\n") if f and (os.path.splitext(f)[1] in COMMENTAIRE or f.endswith(".md"))
            and f != VERIFICATEUR and f != os.path.basename(__file__) and not f.endswith(os.path.basename(__file__))]


def valider_instrument(motifs):
    """Témoins FABRIQUÉS, dans les deux sens : ce qui doit être retenu, ce qui ne doit pas l'être."""
    fautes = []
    def cas(nom, texte, attendu):
        obtenu = sorted(i for _, i, _, _ in retenues(nom, texte, motifs))
        if obtenu != sorted(attendu):
            fautes.append(f"« {nom} » : lignes attendues {sorted(attendu)}, obtenues {obtenu}")
    cas("recit.rs", "// j'avais compté sur un grep brut\nlet x = 1; // mon premier jet tombait\n", [1, 2])
    cas("code.rs", "let moi = 1;\nlet je_suis = 2; // un identifiant, pas un récit\n", [])
    cas("citation.rs", "// sinon « je n'ai pas pu lire » se lirait comme un vide\n", [])
    cas("citation-longue.rs", "// la réponse dit « si je sais servir cette forme,\n// alors la page est passée par moi ». Puis rien.\n", [])
    cas("message.py", "print(\"je refuse de conclure\")  # message à l'exploitant\n", [])
    cas("identifiant.sh", "echo \"$moi : RIEN\"  # l'aveu porte `$moi`\n", [])
    cas("prose.md", "Paragraphe.\n\n```\n# j'ai écrit ceci dans un bloc\n```\n\nJ'avais cru que non.\n", [7])
    cas("regle.md", "- le récit à la première personne (« j'ai essayé », « ma première version ») ;\n", [])
    cas("possessif.js", "// ma faute : le compteur\n", [1])
    cas("feature.js", "// Palette : MES MODÈLES de requête (per-user)\n", [])
    return fautes


def main():
    lister = "--liste" in sys.argv
    try:
        src = open(os.path.join(RACINE, VERIFICATEUR), encoding="utf-8").read()
    except OSError as e:
        print(f"::error::{VERIFICATEUR} illisible ({e}) : la famille n'est pas dérivable, aucun verdict.")
        return 2
    motifs = motifs_du_verificateur(src)
    if not motifs or len(motifs) < MIN_MOTIFS:
        print(f"::error::{VERIFICATEUR} : {0 if not motifs else len(motifs)} motif(s) de style lu(s), plancher "
              f"{MIN_MOTIFS} — la famille n'est plus dérivable, aucun verdict.")
        return 2
    ecarts = valider_instrument(motifs)
    if ecarts:
        print("::error::l'INSTRUMENT NE SE RECONNAÎT PLUS LUI-MÊME — aucun verdict sur l'arbre :")
        for e in ecarts:
            print("  " + e, file=sys.stderr)
        return 2
    fichiers = fichiers_suivis()
    if fichiers is None or len(fichiers) < MIN_FICHIERS:
        print(f"::error::{0 if fichiers is None else len(fichiers)} fichier(s) dans le corpus, plancher {MIN_FICHIERS} : "
              f"le corpus n'est plus reconnu, aucun verdict.")
        return 2
    toutes = []
    for f in fichiers:
        try:
            texte = open(os.path.join(RACINE, f), encoding="utf-8").read()
        except (OSError, UnicodeDecodeError):
            continue
        toutes.extend(retenues(f, texte, motifs))
    index = [x for x in toutes if x[0] == INDEX]
    hors = [x for x in toutes if x[0] != INDEX]
    if lister:
        for f, i, motif, extrait in toutes:
            print(f"{f}:{i}  [{motif}]  {extrait}")
    rc = 0
    if hors:
        for f, i, motif, extrait in hors:
            print(f"::error file={f},line={i}::commentaire ou prose à la première personne (« {motif} ») : {extrait}")
        print(f"\n{len(hors)} ligne(s) s'adressent à l'auteur au lieu du lecteur (AGENTS.md §2, CONTRIBUTING.md « Écrire pour "
              f"le public »). Réécrire le fait sans son auteur : « la première version comptait 7 sites » dit la même "
              f"chose que « mon premier comptage », et reste vrai quand l'auteur change. Une CITATION se met entre « » ; "
              f"un message à l'exploitant reste entre guillemets droits.")
        rc = 1
    if len(index) > PLAFOND_INDEX:
        for f, i, motif, extrait in index:
            print(f"::error file={f},line={i}::index : « {motif} » — {extrait}")
        print(f"\n{INDEX} : {len(index)} ligne(s) à la première personne, plafond {PLAFOND_INDEX} (cliquet à la baisse). "
              f"Une cellule neuve décrit ce qui a été réfuté sans nommer son auteur.")
        rc = 1
    if rc == 0:
        print(f"check_prose_addresses_the_reader_not_the_author : {len(fichiers)} fichiers, {len(motifs)} motifs lus dans "
              f"{VERIFICATEUR} ; 0 ligne hors index, {len(index)} dans l'index (plafond {PLAFOND_INDEX}, ne peut que baisser).")
    return rc


if __name__ == "__main__":
    sys.exit(main())
