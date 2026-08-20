#!/usr/bin/env python3
"""Publier dans le spool, c'est aussi survivre à une coupure — garde de CI (`S27`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
La livraison au moins une fois des capteurs repose sur « écrire un temporaire puis renommer ».
Ce motif donne l'ATOMICITÉ DU CONTENU — un lecteur voit l'ancien fichier ou le nouveau, jamais un
fichier à moitié écrit — et RIEN D'AUTRE. Il ne donne PAS la DURABILITÉ : après une coupure
d'alimentation ou du noyau, l'entrée de répertoire peut manquer alors que le fichier existe. Les
octets sont là, leur NOM n'y est pas, et `ship.sh` parcourt le spool PAR NOM. L'événement de
sécurité disparaît, et rien ne le compte, puisque personne ne compte ce qui manque.

Mesuré le 2026-08-20 sur l'arbre : le motif était écrit à la main dans SEPT capteurs en plus de la
bibliothèque, chacun avec sa propre copie de `chmod 0640 "$tmp"; mv -f "$tmp" "$SPOOL/<nom>"`. Une
correction capteur par capteur aurait fermé sept sites et raté le huitième.

CE N'EST DONC PAS UNE LISTE DE CAPTEURS — c'est une RÈGLE SUR LE MOTIF
----------------------------------------------------------------------
`collectors/lib.sh` porte la voie unique : `spool_write` (contenu en argument) et
`spool_publish_file` (temporaire déjà rempli par l'appelant). Les deux synchronisent le CONTENU
avant le renommage et le RÉPERTOIRE après. La règle est la contraposée : **toute publication dans
`$SPOOL` écrite ailleurs que dans la bibliothèque est nécessairement une publication qui ne
synchronise rien.** Un capteur écrit demain est couvert par construction — son auteur n'a pas
d'autre endroit où publier.

DEUX JAMBES, PARCE QU'UNE GARDE STATIQUE NE PROUVE QUE LA FORME
---------------------------------------------------------------
1. STATIQUE : aucun `mv`/`cp` vers `$SPOOL` hors de la bibliothèque.
2. EXÉCUTÉE : la bibliothèque est SOURCÉE pour de vrai, avec un `sync` instrumenté en tête de PATH,
   et l'on vérifie que les deux synchronisations ont lieu ET DANS LE BON ORDRE — la première quand
   le fichier final n'existe PAS ENCORE (donc avant le renommage), la seconde quand il existe (donc
   après). Sans la seconde jambe, retirer les deux appels de `lib.sh` laisserait cette garde verte.

CE QUE LA JAMBE EXÉCUTÉE PROUVE, ET CE QU'ELLE NE PROUVE PAS — à lire avant de s'en réclamer :
elle prouve que les APPELS de synchronisation sont faits, au bon endroit du chemin de publication.
Elle NE PROUVE PAS que la donnée survive à une coupure d'alimentation : cela demanderait de couper
le courant d'une vraie machine à l'instant exact, ou un pilote de blocs qui simule la perte du cache
d'écriture. Un test qui prétendrait le contraire mentirait. Le défaut RÉEL fermé ici est qu'AUCUN
appel n'existait ; le matériel qui ment sur son propre `flush` reste hors de portée.

PÉRIMÈTRE — CE QUE CETTE GARDE NE COUVRE PAS, dit pour qu'on ne s'en réclame pas trop
--------------------------------------------------------------------------------------
Elle balaie le SHELL. Le binaire d'agent porte sa propre garde dérivée, dans son module de
publication. Restent hors de portée des deux : le récepteur syslog, le collecteur mail, et les sept
écritures de spool des récepteurs poussés du central — surfaces recensées et nommées dans
`docs/ROADMAP.md` (`S27`), avec la raison pour laquelle leur arbitrage n'est pas le même (le coût
mesuré y tombe sur un chemin appelé à chaque requête, sur un fil d'exécution qu'un `fsync` bloquant
fige). Une garde qui prétendrait les couvrir sans les corriger serait pire que leur absence.

L'EXCLUSION QUI NE PEUT PAS POURRIR
-----------------------------------
`collectors/engagement-adapter.sh` est un ENFORCER (il applique des décisions, il ne collecte pas)
et il ne source PAS `lib.sh` — une autre garde, `check_collector_exit_is_classified.py`, EXIGE même
qu'il ne le fasse pas. Il publie donc un événement de santé sans la voie unique, et cette garde le
sait plutôt que de l'ignorer : son exclusion est NOMMÉE, son nombre est BORNÉ, et la garde
RE-VÉRIFIE qu'il ne source toujours pas la bibliothèque. Le jour où il la source, l'exclusion tombe
d'elle-même. Un capteur NOUVEAU qui publierait sans la voie unique n'est, lui, dans aucune liste :
il fait rougir.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

LIB = "collectors/lib.sh"

# Publication dans le spool : un `mv`/`cp` dont la LIGNE mentionne $SPOOL. Le motif est volontairement
# large sur le déplacement et étroit sur la cible : ce qui compte est « un nom apparaît dans le spool ».
PUBLICATION = re.compile(r"\b(?:mv|cp)\b[^\n]*\$\{?SPOOL\b")

# Exclusions NOMMÉES et BORNÉES, re-vérifiées plus bas (elles ne sont pas déclaratives).
ENFORCERS_SANS_LIB = ("collectors/engagement-adapter.sh",)

# PLANCHERS, pas des comptes exacts : ajouter un capteur est de la routine et ne doit pas obliger à
# toucher ce fichier. Ils ferment le seul vrai mode de panne d'une garde par balayage — une découverte
# cassée qui ne lit RIEN et rapporte un vert joyeux.
# MESURÉ le 2026-08-20 : `git ls-files '*.sh' '*.bash'` = 54 fichiers ; 59 appels de la voie unique
# (`spool_write` + `spool_publish_file`), dont les 7 que cette clé a ramenés dans la bibliothèque.
MIN_SCRIPTS = 45
MIN_APPELS_VOIE_UNIQUE = 45


def echec(msg):
    print(f"::error::{msg}")
    print(f"check_publication_is_durable : {msg}", file=sys.stderr)
    sys.exit(1)


def strip_comment(ligne):
    """Retire un commentaire `#` hors guillemets (un `#` dans "..." n'en ouvre pas un)."""
    out, quote, i = [], None, 0
    while i < len(ligne):
        c = ligne[i]
        if quote:
            if c == "\\" and quote == '"':
                out.append(c)
                i += 1
                if i < len(ligne):
                    out.append(ligne[i])
                i += 1
                continue
            if c == quote:
                quote = None
            out.append(c)
        elif c in "'\"":
            quote = c
            out.append(c)
        elif c == "#":
            break
        else:
            out.append(c)
        i += 1
    return "".join(out)


def valider_le_motif():
    """TÉMOINS de la garde elle-même : un motif qui ne reconnaît pas ce qu'il doit refuser rend vert
    en étant aveugle, et un motif trop large finit désarmé à force de faux positifs."""
    doit_matcher = [
        'mv -f "$tmp" "$SPOOL/web-$now.json"',
        'if [ -s "$tmp" ]; then chmod 0640 "$tmp"; mv -f "$tmp" "$SPOOL/x.json"; else rm -f "$tmp"; fi',
        'cp "$tmp" "${SPOOL}/y.json"',
    ]
    ne_doit_pas_matcher = [
        'spool_publish_file "$tmp" "web-$now.json"',
        'spool_write "ufw-$ts.json" "$(emit_event "$events")" nl',
        '_sw_tmp=$(mktemp "$SPOOL/.xx.XXXXXX")',
        'rm -f "$SPOOL/$1"',
        'mv -f "$_st_tmp" "$1"',
    ]
    for l in doit_matcher:
        if not PUBLICATION.search(strip_comment(l)):
            echec(f"témoin POSITIF du motif en échec — la garde ne reconnaîtrait pas : {l}")
    for l in ne_doit_pas_matcher:
        if PUBLICATION.search(strip_comment(l)):
            echec(f"témoin NÉGATIF du motif en échec — la garde refuserait à tort : {l}")


def scripts_suivis():
    out = subprocess.run(
        ["git", "ls-files", "*.sh", "*.bash"], capture_output=True, text=True, check=True
    ).stdout.split()
    return sorted(out)


def jambe_statique(scripts):
    fautifs = []
    appels_voie_unique = 0
    for f in scripts:
        try:
            src = open(f, encoding="utf-8", errors="replace").read()
        except OSError as e:
            echec(f"lecture impossible de {f} : {e}")
        appels_voie_unique += len(re.findall(r"\bspool_(?:write|publish_file)\b", src))
        if f == LIB or f in ENFORCERS_SANS_LIB:
            continue
        for i, ligne in enumerate(src.splitlines(), 1):
            if PUBLICATION.search(strip_comment(ligne)):
                fautifs.append(f"{f}:{i}: {ligne.strip()}")
    if fautifs:
        for x in fautifs:
            print(f"::error file={x.split(':')[0]}::publication dans $SPOOL hors de la voie unique")
            print(f"  {x}")
        echec(
            "publication réinventée hors de `spool_write`/`spool_publish_file` — un renommage seul "
            "donne l'atomicité du CONTENU, jamais la DURABILITÉ (l'entrée de répertoire peut manquer "
            "après coupure alors que le fichier existe)"
        )
    if appels_voie_unique < MIN_APPELS_VOIE_UNIQUE:
        echec(
            f"plancher : {appels_voie_unique} appel(s) de la voie unique trouvé(s) (< {MIN_APPELS_VOIE_UNIQUE}) "
            "— la découverte est cassée, cette garde ne verrait rien"
        )
    return appels_voie_unique


def exclusions_toujours_valides(scripts):
    """L'exclusion des enforcers tient à un critère OBJECTIF : ils ne sourcent pas la bibliothèque.
    On le RE-VÉRIFIE ; le jour où c'est faux, l'exclusion tombe au lieu de survivre par inertie."""
    for f in ENFORCERS_SANS_LIB:
        if f not in scripts:
            echec(f"{f} n'est plus suivi — l'exclusion nommée de cette garde vise un fichier absent")
        src = open(f, encoding="utf-8", errors="replace").read()
        if re.search(r"^\s*\.\s+.*lib\.sh", src, re.M):
            echec(
                f"{f} source désormais {LIB} : il a accès à `spool_publish_file`, donc son exclusion "
                "de cette garde n'a plus de raison d'être — retirez-la et faites-le publier par la voie unique"
            )


def jambe_executee():
    """Source VRAIMENT lib.sh, avec un `sync` instrumenté, et vérifie les deux appels ET leur ORDRE."""
    if shutil.which("sh") is None:
        echec("aucun `sh` — la jambe exécutée ne peut pas rendre de verdict (et ne rendra pas un faux vert)")
    with tempfile.TemporaryDirectory() as base:
        binz = os.path.join(base, "bin")
        spool = os.path.join(base, "spool")
        journal = os.path.join(base, "appels.txt")
        os.makedirs(binz)
        os.makedirs(spool)
        cible = os.path.join(spool, "essai-1.json")
        # `sync` INSTRUMENTÉ. Il se comporte comme un GNU `sync` (il ÉCHOUE sur un chemin absent —
        # sans quoi la détection d'instrument de lib.sh le classerait « ignore son opérande ») et
        # journalise, pour chaque appel réussi, le chemin ET si la CIBLE FINALE existait déjà. C'est
        # cette seconde colonne qui prouve l'ORDRE : avant le renommage la cible n'existe pas, après
        # elle existe. Un simple compte d'appels ne prouverait pas l'ordre, et l'ordre est le sujet.
        with open(os.path.join(binz, "sync"), "w", encoding="utf-8") as f:
            f.write(
                "#!/bin/sh\n"
                'for p in "$@"; do [ -e "$p" ] || exit 1; done\n'
                'if [ -e "%s" ]; then etat=cible-presente; else etat=cible-absente; fi\n'
                'for p in "$@"; do printf "%%s\\t%%s\\n" "$p" "$etat" >> "%s"; done\n'
                "exit 0\n" % (cible, journal)
            )
        os.chmod(os.path.join(binz, "sync"), 0o755)
        env = dict(os.environ, PATH=binz + os.pathsep + os.environ.get("PATH", ""), PLUME_SPOOL=spool)
        script = (
            f'. "{LIB}"\n'
            "plume_init\n"
            'spool_write "essai-1.json" "{\\"kind\\":\\"events\\"}" nl\n'
        )
        r = subprocess.run(["sh", "-eu", "-c", script], env=env, capture_output=True, text=True)
        if r.returncode != 0:
            echec(f"la publication de contrôle a échoué (rc={r.returncode}) : {r.stderr.strip()}")
        if not os.path.exists(cible):
            echec("la publication de contrôle n'a produit aucun fichier — le témoin ne mesure rien")
        try:
            appels = [l.split("\t") for l in open(journal, encoding="utf-8").read().splitlines() if l]
        except OSError:
            appels = []
        # On ignore les appels de la SONDE de détection d'instrument (chemins inexistants : le stub
        # échoue dessus, donc ils ne sont jamais journalisés) — seuls les appels réels comptent.
        avant = [p for p, etat in appels if etat == "cible-absente"]
        apres = [p for p, etat in appels if etat == "cible-presente"]
        if not any(os.path.basename(p).startswith(".") and os.path.dirname(p) == spool for p in avant):
            echec(
                "aucune synchronisation du CONTENU avant le renommage — `spool_write` publierait un nom "
                f"désignant des octets jamais écrits (appels vus : {appels})"
            )
        if spool not in apres:
            echec(
                "aucune synchronisation du RÉPERTOIRE après le renommage — après coupure, l'entrée de "
                f"répertoire peut manquer alors que le fichier existe (appels vus : {appels})"
            )
        # NÉGATIF, et il protège une DÉCISION : `state_write` ne doit PAS synchroniser. Un filigrane
        # qui survit aux événements qu'il acquitte fait disparaître ces événements ; un filigrane perdu
        # ne coûte qu'une relecture dédoublonnée par le central.
        os.remove(journal)
        etat = os.path.join(base, "wm")
        script2 = f'. "{LIB}"\nplume_init\nstate_write "{etat}" "42"\n'
        r2 = subprocess.run(["sh", "-eu", "-c", script2], env=env, capture_output=True, text=True)
        if r2.returncode != 0:
            echec(f"l'écriture de filigrane de contrôle a échoué (rc={r2.returncode}) : {r2.stderr.strip()}")
        if os.path.exists(journal) and open(journal, encoding="utf-8").read().strip():
            echec(
                "`state_write` synchronise : l'asymétrie de lib.sh est inversée. Un filigrane DURABLE "
                "écrit avant des événements qui ne le sont pas transforme une perte improbable en perte "
                "certaine — cf. le bandeau de collectors/lib.sh"
            )
        return len(appels)


def main():
    if not os.path.exists(LIB):
        echec(f"{LIB} introuvable — exécutez cette garde depuis la racine du dépôt")
    valider_le_motif()
    scripts = scripts_suivis()
    if len(scripts) < MIN_SCRIPTS:
        echec(f"plancher : {len(scripts)} script(s) suivi(s) découvert(s) (< {MIN_SCRIPTS}) — découverte cassée")
    exclusions_toujours_valides(scripts)
    appels = jambe_statique(scripts)
    n = jambe_executee()
    print(
        f"check_publication_is_durable : {len(scripts)} script(s) balayé(s), {appels} appel(s) de la voie "
        f"unique, publication de contrôle synchronisée ({n} appel(s) observé(s), contenu AVANT le "
        "renommage puis répertoire APRÈS). Prouve que les appels sont faits, pas la survie à une coupure."
    )


if __name__ == "__main__":
    main()
