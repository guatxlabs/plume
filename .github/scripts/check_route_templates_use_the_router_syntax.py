#!/usr/bin/env python3
"""UN GABARIT DE ROUTE S'ÉCRIT DANS LA SYNTAXE DU ROUTEUR — garde de CI (`P7.19-d`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
La montée `axum` 0.7 -> 0.8 change la syntaxe des gabarits de route : `/api/cases/:id` devient
`/api/cases/{id}`. La bibliothèque REFUSE de démarrer sur un littéral resté à l'ancienne forme, si
bien que la table de routage s'est migrée toute seule, sous peine de panique — c'est un endroit qui
ne pouvait PAS rester en arrière.

TOUT LE RESTE, SI. MESURÉ le 2026-08-26 sur l'arbre, APRÈS la migration de la table : l'ancienne
syntaxe survivait dans CINQUANTE-HUIT fichiers — commentaires de doc au-dessus des handlers,
modules de la console, et surtout deux endroits où elle ne décrivait pas le code mais le CONTRAT :

  · DEUX CORPS DE REFUS SERVIS. Le refus « store de bans plein » disait à un exploitant de libérer
    par `DELETE /api/netban/:ip` ; le refus de purge sous rétention légale le renvoyait vers
    `/api/legal-holds/:id/release`. Ce ne sont pas des commentaires : ce sont des octets que le
    démon ÉCRIT à un client, et ils lui donnaient une adresse dans une grammaire morte.
  · CINQ DOCUMENTS D'INTÉGRATION PUBLIÉS (fournisseur d'identité natif, kit d'intégration, préréglages
    de connecteurs, purge). Un intégrateur lit ces pages et non le code.

Une garde qui ne juge que les littéraux de `.route(` est donc VERTE EN ÉTANT AVEUGLE : elle tient le
seul endroit que la bibliothèque tenait déjà, et laisse la DESCRIPTION du contrat en arrière.

LE CRITÈRE, ET POURQUOI CE N'EST PAS « INTERDIRE L'ANCIENNE FORME »
------------------------------------------------------------------
Interdire purement l'ancienne forme rendrait INÉCRIVABLE la seule phrase qui vaille la peine d'être
écrite sur cette rupture : « la valeur était `…/:id`, elle est `…/{id}` ». Le critère est donc :

    une ligne qui porte l'ANCIENNE forme doit porter la NOUVELLE sur la MÊME ligne.

Une ligne qui ne porte que l'ancienne DÉCRIT un contrat mort ; une ligne qui porte les deux NOMME
une rupture. Le jugement est à la LIGNE, délibérément : une ligne est ce qu'un lecteur grep, et un
paragraphe qui nommerait la rupture deux lignes plus bas ne l'aiderait pas.

CE QUE CETTE GARDE NE TIENT PAS
-------------------------------
  · SON CORPUS EST LES TROIS SURFACES QUI DÉCRIVENT LE CONTRAT (`daemon/src`, `web`, `docs`), pas le
    dépôt entier. Les scripts de garde en sont EXCLUS, et c'est délibéré : leurs témoins NÉGATIFS
    doivent pouvoir porter l'ancienne syntaxe seule (`check_sensitive_routes_are_confirmed.py` en a
    un). Une garde qui interdirait à une autre garde d'écrire son témoin négatif détruirait la preuve
    qu'elle prétend défendre.
  · ELLE NE JUGE QUE LA FORME `/:nom`. Un `:nom` isolé, hors gabarit, n'est pas jugé — ce n'est pas
    un gabarit de route.
  · ELLE ÉCARTE, EN LES IMPRIMANT, les lignes où `/:` est ouvert par un caractère de littéral
    d'expression régulière JavaScript (`(`, `=`, `,`, `[`, `!`), forme que `web/` peut légitimement
    porter. Aucune n'existe dans le corpus au 2026-08-26 ; elles sont imprimées pour qu'un écart
    futur se VOIE au lieu de se taire.
  · ELLE NE PROUVE RIEN SUR LE COMPORTEMENT SERVI. Elle tient une COHÉRENCE D'ÉCRITURE ; ce que le
    routeur fait vraiment est tenu par `router_un_segment_statique_gagne_sur_son_parametre_frere` et
    `router_path_i64_ecrit_la_valeur_de_refus_sans_guillemets`, qui traversent le routeur réel.

L'INSTRUMENT SE VALIDE AVANT DE RENDRE UN VERDICT
-------------------------------------------------
Témoin POSITIF (une ligne à l'ancienne seule DOIT être accusée), témoin NÉGATIF (la nouvelle seule ne
doit PAS l'être), témoin de la TOLÉRANCE (les deux sur une ligne ne doit PAS l'être) et témoin
d'ÉCART (un littéral d'expression régulière ne doit pas être accusé). Puis un plancher sur le corpus
réel : si le corpus dérivé est vide, la garde DIT qu'elle n'a rien lu au lieu de rendre vert.
"""
import os
import re
import subprocess
import sys

RACINE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SURFACES = ("daemon/src/", "web/", "docs/")

ANCIENNE = re.compile(r"/:[a-z_][a-z0-9_]*")
NOUVELLE = re.compile(r"/\{[a-z_][a-z0-9_]*\}")
OUVREURS_REGEX = "(=,[!"


def juge(ligne):
    """(accusee, ecartee) pour UNE ligne. Une ligne sans ancienne forme n'est ni l'un ni l'autre."""
    positions = [m.start() for m in ANCIENNE.finditer(ligne)]
    if not positions:
        return False, False
    retenues = [i for i in positions if not (i > 0 and ligne[i - 1] in OUVREURS_REGEX)]
    if not retenues:
        return False, True
    if NOUVELLE.search(ligne):
        return False, False
    return True, False


def corpus():
    """DÉRIVÉ de `git ls-files` (fichiers SUIVIS), lu dans l'arbre de TRAVAIL.

    Suivis, pour que la CI juge exactement ce qu'un commit apporte ; lus dans l'arbre de travail,
    pour que la mesure d'avant le commit soit la même que celle d'après.
    """
    out = subprocess.run(["git", "-C", RACINE, "ls-files", "-z"], capture_output=True, text=True)
    if out.returncode != 0:
        return None
    return [c for c in out.stdout.split("\0") if c and c.startswith(SURFACES)]


def valider_instrument():
    errs = []
    cas = [
        ("positif", "//   DELETE /api/knowledge/tag/:id     (editor+)", (True, False)),
        ("negatif", '        .route("/api/cases/{id}", get(case_get))', (False, False)),
        ("tolerance", "axum 0.7 wrote `/api/cases/:id`, axum 0.8 writes `/api/cases/{id}`", (False, False)),
        ("ecart", "const reste = txt.replace(/:not\\(\\s*\\.([\\w-]+)\\s*\\)/g, x);", (False, True)),
        ("vide", "rien a dire ici", (False, False)),
    ]
    for nom, ligne, attendu in cas:
        obtenu = juge(ligne)
        if obtenu != attendu:
            errs.append(f"témoin {nom} en échec : attendu {attendu}, obtenu {obtenu} sur `{ligne}`")
    return errs


def main():
    errs = valider_instrument()
    if errs:
        print("INSTRUMENT INVALIDE — aucun verdict n'est rendu :")
        for e in errs:
            print(f"  · {e}")
        return 2

    fichiers = corpus()
    if fichiers is None:
        print("INSTRUMENT MUET : `git ls-files` a échoué — la garde ne lit rien, elle ne conclut pas.")
        return 2
    if len(fichiers) < 50:
        print(f"INSTRUMENT MUET : le corpus dérivé ne contient que {len(fichiers)} fichier(s) suivi(s) "
              f"sous {SURFACES} — les surfaces qui décrivent le contrat ont bougé, la garde ne conclut pas.")
        return 2

    defauts, ecartees, lus = [], [], 0
    for rel in fichiers:
        chemin = os.path.join(RACINE, rel)
        try:
            with open(chemin, encoding="utf-8") as fh:
                lignes = fh.read().splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        lus += 1
        for n, ligne in enumerate(lignes, 1):
            accusee, ecartee = juge(ligne)
            if accusee:
                defauts.append((rel, n, ligne.strip()[:150]))
            elif ecartee:
                ecartees.append((rel, n, ligne.strip()[:110]))

    print(f"fichiers suivis lus : {lus} (sur {len(fichiers)} du corpus dérivé)")
    if ecartees:
        print(f"écartées (forme d'un littéral d'expression régulière, PAS un gabarit) : {len(ecartees)}")
        for rel, n, ligne in ecartees:
            print(f"  · {rel}:{n} — {ligne}")

    if defauts:
        print(f"\nGABARIT DE ROUTE EN SYNTAXE MORTE — {len(defauts)} ligne(s) :")
        for rel, n, ligne in defauts:
            print(f"  · {rel}:{n} — {ligne}")
        print("\nLe routeur écrit `/api/x/{id}` depuis axum 0.8 ; `/api/x/:id` le ferait PANIQUER au")
        print("démarrage. Une ligne qui décrit le contrat dans la forme d'avant enseigne une adresse")
        print("que le démon ne sert pas. Pour NOMMER la rupture, porter les DEUX formes sur la même ligne.")
        return 1

    print("aucun gabarit de route en syntaxe morte dans les surfaces qui décrivent le contrat.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
