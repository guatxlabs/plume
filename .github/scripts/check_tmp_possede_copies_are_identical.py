#!/usr/bin/env python3
"""La possession des temporaires est UN fichier, copié à l'identique dans chaque caisse qui la porte
(`P8.9-o`).

La question qui décidait : porter la possession par une aide PARTAGÉE entre caisses (une dépendance
entre elles, que rien d'autre ne justifie) ou la RECOPIER dans chacune (ce qu'une clé voisine déplore,
parce qu'une copie dérive). Tranché : recopier, mais sous une garde qui refuse la dérive — les copies
sont un seul fichier logique, `daemon/src/tmp_possede.rs` fait foi, et la CI arme le balayage « aucun
temporaire laissé » sur chaque caisse qui porte `src/tmp_possede.rs` (dérivation de `P8.9-m`).

Refuse de conclure quand la référence manque ou qu'aucune copie n'existe : un « tout est identique »
sur un ensemble vide ne prouverait rien.
"""
import os, sys

REFERENCE = "daemon/src/tmp_possede.rs"


def copies(racine):
    out = []
    for caisse in sorted(os.listdir(racine)):
        p = os.path.join(racine, caisse, "src", "tmp_possede.rs")
        if os.path.isfile(p) and os.path.relpath(p, racine) != REFERENCE:
            out.append(os.path.relpath(p, racine))
    return out


def juger(racine, silencieux=False):
    ref = os.path.join(racine, REFERENCE)
    if not os.path.isfile(ref):
        if not silencieux:
            print(f"::error::référence absente ({REFERENCE}) : la garde REFUSE DE CONCLURE", file=sys.stderr)
        return 2
    autres = copies(racine)
    if not autres:
        if not silencieux:
            print("::error::aucune copie de tmp_possede.rs hors du démon : soit la possession n'est plus portée ailleurs, "
                  "soit la découverte est cassée — la garde REFUSE DE CONCLURE", file=sys.stderr)
        return 2
    attendu = open(ref, "rb").read()
    rc = 0
    for rel in autres:
        if open(os.path.join(racine, rel), "rb").read() != attendu:
            rc = 1
            if not silencieux:
                print(f"::error file={rel}::cette copie de la possession des temporaires DIVERGE de {REFERENCE} : "
                      f"recopier la référence telle quelle (un seul fichier logique, quatre emplacements).", file=sys.stderr)
    if rc == 0 and not silencieux:
        print(f"{len(autres)} copie(s) identique(s) à {REFERENCE} : {', '.join(autres)}")
    return rc


def epreuves():
    import tempfile, shutil
    bac = tempfile.mkdtemp(prefix="tmp-possede-garde-")
    try:
        def poser(rel, contenu):
            p = os.path.join(bac, rel); os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "w", encoding="utf-8").write(contenu)
        poser(REFERENCE, "A\n"); poser("agent/src/tmp_possede.rs", "A\n"); poser("collector-mail/src/tmp_possede.rs", "A\n")
        if juger(bac, True) != 0: return "trois copies identiques doivent passer"
        poser("collector-mail/src/tmp_possede.rs", "B\n")
        if juger(bac, True) != 1: return "une copie divergente doit rougir"
        shutil.rmtree(os.path.join(bac, "agent")); shutil.rmtree(os.path.join(bac, "collector-mail"))
        if juger(bac, True) != 2: return "sans copie, la garde doit refuser de conclure"
        os.remove(os.path.join(bac, REFERENCE))
        if juger(bac, True) != 2: return "sans référence, la garde doit refuser de conclure"
    finally:
        shutil.rmtree(bac, ignore_errors=True)
    return None


def main():
    faute = epreuves()
    if faute:
        print(f"::error::instrument INVALIDE, la garde REFUSE DE CONCLURE — {faute}", file=sys.stderr)
        return 2
    return juger(os.getcwd())


if __name__ == "__main__":
    sys.exit(main())
