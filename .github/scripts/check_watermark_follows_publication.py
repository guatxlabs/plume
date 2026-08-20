#!/usr/bin/env python3
"""Acquitter APRÈS avoir publié, jamais avant — garde de CI (`S30`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
Un capteur incrémental fait deux gestes : il PUBLIE une enveloppe dans le spool, et il MARQUE sa
progression (filigrane, offset d'octets, curseur, repère daté relu en `find -newer`, registre
« déjà signalé », base de référence). Marquer AVANT de publier rend le marqueur MENTEUR : une
coupure entre les deux perd les événements, et rien ne le signale — le marqueur affirme qu'ils sont
acquittés, donc personne ne les relira jamais. Aucune synchronisation ne répare ça : c'est l'ORDRE
qui est faux. C'est même précisément pourquoi `S27` a laissé le marqueur NON DURABLE : le rendre
durable dans le mauvais ordre aurait transformé une perte improbable en perte certaine.

Dans le bon sens, la même coupure produit un REJEU : le passage suivant relit la même tranche et la
republie. Un rejeu se voit, se compte, et se ferme en donnant une clé de dédoublonnage ; une perte
ne laisse rien à compter.

CE N'EST PAS UNE LISTE DE CAPTEURS — c'est une RÈGLE SUR LE MOTIF
----------------------------------------------------------------
`S27` annonçait CINQ capteurs fautifs. Le compte était faux, et pour la raison que `S27` avait
elle-même nommée à propos du sien : il avait été dérivé du SYMBOLE `state_write`, pas du MOTIF.
Recherche refaite sur le motif « un site qui marque la progression et un site qui publie, dans le
même flot » : DIX-SEPT capteurs. Les douze manquants marquaient autrement — redirection brute
(`printf '%s' "$size" > "$OFF"`), `touch` d'un fichier-repère, ajout d'une ligne dans un registre,
renommage d'une base de référence, et jusqu'à un point de reprise avancé par un OUTIL EXTERNE
(`ausearch --checkpoint`) au moment de la lecture. Aucune de ces formes n'apparaît dans un
`grep state_write`.

La règle est donc la contraposée, comme pour `check_publication_is_durable.py` : **tout marqueur de
progression écrit ailleurs que par la bibliothèque est nécessairement un marqueur écrit dans le
mauvais ordre.** `collectors/lib.sh` porte la voie unique — un capteur MET EN ATTENTE
(`state_stage`, `state_stage_append`, `state_stage_file`) et n'a pas le geste d'écrire ; les seuls
points d'écriture sont `spool_write_then_ack` / `spool_publish_then_ack` (publient PUIS écrivent) et
`plume_exit_nodata` (rien n'a été publié, donc rien n'est acquitté). L'ordre est INTERNE à ces
fonctions. Un capteur écrit demain est couvert par construction.

DEUX JAMBES, PARCE QU'UNE GARDE STATIQUE NE PROUVE QUE LA FORME
---------------------------------------------------------------
1. STATIQUE : aucune écriture directe de marqueur hors de la bibliothèque — appel de `state_write`,
   redirection / `mv` / `cp` / `touch` vers un chemin d'état, ET redirection vers un PARAMÈTRE
   POSITIONNEL dans un script qui manipule des chemins d'état (c'est cette dernière forme qui
   cachait `containerd` : le chemin d'état y était passé en argument à une fonction interne).
2. EXÉCUTÉE : la bibliothèque est SOURCÉE pour de vrai et l'on vérifie l'ORDRE des deux effets —
   au moment où la publication se synchronise, le marqueur n'existe PAS ENCORE ; il n'apparaît
   qu'après. Puis une COUPURE SIMULÉE entre les deux (le processus meurt dans l'écriture du
   marqueur) : l'enveloppe publiée est là, le marqueur ne l'est pas — donc le passage suivant
   REJOUE au lieu de perdre.

CE QUE LA JAMBE EXÉCUTÉE PROUVE, ET CE QU'ELLE NE PROUVE PAS — à lire avant de s'en réclamer.
Elle prouve l'ORDRE des deux effets, et qu'une interruption entre eux laisse l'événement publié
avec un marqueur NON avancé : la tranche sera relue. Elle NE PROUVE PAS que le rejeu soit sans
conséquence — seuls les événements porteurs d'une clé de dédoublonnage sont absorbés par le
central, et sept capteurs n'en portent aucune (leurs doublons seront VISIBLES, ce qui reste
préférable à une perte muette : cf. le bandeau de `collectors/lib.sh`). Elle NE PROUVE PAS non plus
la survie à une coupure d'alimentation : cela demanderait de couper le courant d'une machine à
l'instant exact. Le défaut RÉELLEMENT fermé est l'ORDRE ; le matériel qui ment sur son propre
vidage de cache reste hors de portée, et un test qui prétendrait le contraire mentirait.

PÉRIMÈTRE — CE QUE CETTE GARDE NE COUVRE PAS, dit pour qu'on ne s'en réclame pas trop
--------------------------------------------------------------------------------------
Elle balaie le SHELL des capteurs. Le capteur Windows tient le même invariant par sa propre forme
(`Stage-Watermark` / `Complete-Run`, garde `check_windows_collector_is_honest.py`) et le binaire
d'agent aussi (`CursorStore::save` n'est appelé qu'après ship+ack, cf. `agent/src/buffer.rs`).
Aucune des trois ne couvre les récepteurs poussés du central : là, ce n'est pas un marqueur qui est
en cause mais la durabilité de la réception (`S31`).

LES EXCLUSIONS, NOMMÉES, BORNÉES, ET RE-VÉRIFIÉES
--------------------------------------------------
Deux fichiers écrivent sous `$STATE` sans acquitter quoi que ce soit. Leur exclusion n'est pas
déclarative : le critère est re-vérifié à chaque exécution, et le jour où il devient faux
l'exclusion tombe au lieu de survivre par inertie.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

LIB = "collectors/lib.sh"

# --- EXCLUSIONS NOMMÉES ET BORNÉES ---------------------------------------------------------------
# `engagement-adapter.sh` est un ENFORCER : il ne source PAS `lib.sh` (une autre garde,
# `check_collector_exit_is_classified.py`, EXIGE même qu'il ne le fasse pas), donc il n'a aucune
# primitive de mise en attente à sa disposition. Son état (`.applied`, `.failcount`, `.heartbeat`)
# n'acquitte aucun événement collecté : il borne un REVERT. Critère re-vérifié : il ne source pas
# la bibliothèque. Le jour où il la source, l'exclusion tombe.
ENFORCERS_SANS_LIB = ("collectors/engagement-adapter.sh",)

# `conntrack.sh` tient un CACHE de résolution inverse. Il n'acquitte rien : sa perte coûte une
# re-résolution, et son contenu ne conditionne l'émission d'aucun événement (il ENRICHIT un message
# déjà construit). Critère re-vérifié : le seul chemin d'état non temporaire qu'il écrit est
# celui-là.
CACHES_SANS_ACQUITTEMENT = {"collectors/conntrack.sh": "rdns.cache"}

# PLANCHERS, pas des comptes exacts : ajouter un capteur est de la routine et ne doit pas obliger à
# toucher ce fichier. Ils ferment le seul vrai mode de panne d'une garde par balayage — une
# découverte cassée qui ne lit RIEN et rapporte un vert joyeux.
MIN_SCRIPTS = 45
# MESURÉ le 2026-08-20 : 54 scripts suivis, 35 mises en attente, 30 publications acquittantes.
MIN_MISES_EN_ATTENTE = 25
MIN_PUBLICATIONS_ACQUITTANTES = 22

# --- LES MOTIFS ----------------------------------------------------------------------------------
# Une affectation qui FABRIQUE un chemin sous $STATE / $STATE_DIR, directement ou via `mktemp`.
AFFECT_ETAT = re.compile(
    r'^\s*(?:local\s+)?([A-Za-z_][A-Za-z0-9_]*)=\$?[("\']*.*\$\{?(?:STATE|STATE_DIR)\b[^\n]*$'
)
# Une affectation DÉRIVÉE d'un chemin d'état déjà connu : X="$SEEN.tmp".
AFFECT_DERIVEE = re.compile(r'^\s*(?:local\s+)?([A-Za-z_][A-Za-z0-9_]*)=\$?[("\']*.*\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?')
# Écritures : redirection, déplacement, copie, `touch`.
REDIRECTION = re.compile(r'>>?\s*"?\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?')
REDIRECTION_LITTERALE = re.compile(r'>>?\s*"?\$\{?(?:STATE|STATE_DIR)\}?/([^"\s]+)')
DEPLACEMENT = re.compile(r'\b(?:mv|cp)\b[^\n]*?"?\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?"?\s*$')
TOUCH = re.compile(r'\btouch\b([^\n]*)')
REDIRECTION_POSITIONNELLE = re.compile(r'>>?\s*"?\$\{?([0-9])\}?')
ECRITURE_PRIVEE = re.compile(r'(?<![A-Za-z0-9_])(state_write|_plume_ack_commit)\s')


def echec(msg):
    print(f"::error::{msg}")
    print(f"check_watermark_follows_publication : {msg}", file=sys.stderr)
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


def est_temporaire(chemin):
    """Un fichier de TRAVAIL, pas un marqueur : nom caché (`.x`) ou suffixe `.tmp`. La bibliothèque
    et les capteurs y écrivent librement — c'est le RENOMMAGE final qui est le marqueur, et lui
    passe par la mise en attente."""
    base = os.path.basename(chemin.strip('"\''))
    return base.startswith(".") or base.endswith(".tmp") or "$$" in base


def variables_d_etat(src):
    """Variables qui portent un chemin sous $STATE / $STATE_DIR, et si ce chemin est un temporaire.
    Deux passes pour attraper les dérivées (`X="$SEEN.tmp"`)."""
    etat = {}
    for ligne in src.splitlines():
        l = strip_comment(ligne)
        m = AFFECT_ETAT.match(l)
        if m:
            etat[m.group(1)] = est_temporaire(l.split("=", 1)[1])
    for _ in range(2):
        for ligne in src.splitlines():
            l = strip_comment(ligne)
            m = AFFECT_DERIVEE.match(l)
            if m and m.group(1) not in etat and m.group(2) in etat:
                etat[m.group(1)] = est_temporaire(l.split("=", 1)[1])
    return etat


def valider_le_motif():
    """TÉMOINS de la garde elle-même : un motif qui ne reconnaît pas ce qu'il doit refuser rend vert
    en étant aveugle, et un motif trop large finit désarmé à force de faux positifs."""
    fautifs = [
        ('WM="$STATE_DIR/ufw.watermark"', 'state_write "$WM" "$ts"'),
        ('OFF="$STATE/falco.offset"', 'printf \'%s\' "$size" > "$OFF"'),
        ('OFFF="$STATE/kube-audit.offset"', 'echo "$SIZE" > "$OFFF"'),
        ('STAMP="$STATE_DIR/clamav.stamp"', 'touch "$STAMP"'),
        ('SEEN="$STATE_DIR/vuln.seen"', 'printf \'%s\\n\' "$key" >> "$SEEN"'),
        ('BASE="$STATE/integrity.base"', 'mv -f "$cur" "$BASE"'),
        ('IMG_STATE="$STATE_DIR/containerd.images"', 'printf \'%s\\n\' "$idv" >> "$2"'),
    ]
    for affect, ecriture in fautifs:
        src = f"{affect}\n{ecriture}\n"
        if not analyser(src, "temoin.sh"):
            echec(f"témoin POSITIF du motif en échec — la garde ne verrait pas : {ecriture}")
    innocents = [
        ('WM="$STATE_DIR/ufw.watermark"', 'state_stage "$WM" "$ts"'),
        ('SEEN="$STATE_DIR/vuln.seen"', 'state_stage_append "$SEEN" "$key"'),
        ('cur=$(mktemp "$STATE/.integrity.base.XXXXXX")', 'sort -o "$cur" "$cur"'),
        ('upd=$(mktemp "$STATE_DIR/.imgdrift.upd.XXXXXX")', 'printf \'%s\\n\' "$x" >> "$upd"'),
        ('WM="$STATE_DIR/ufw.watermark"', 'last=$(cat "$WM" 2>/dev/null || echo 0)'),
        ('tmpf=$(mktemp)', 'printf \'%s\' "$x" > "$tmpf"'),
        ('WM="$STATE_DIR/ufw.watermark"', '# state_write "$WM" "$ts" dans un commentaire'),
    ]
    for affect, ligne in innocents:
        src = f"{affect}\n{ligne}\n"
        if analyser(src, "temoin.sh"):
            echec(f"témoin NÉGATIF du motif en échec — la garde refuserait à tort : {ligne}")


def analyser(src, nom):
    """Rend la liste des écritures directes de marqueur trouvées dans `src`."""
    etat = variables_d_etat(src)
    persistants = {v for v, tmp in etat.items() if not tmp}
    fautifs = []
    # L'exclusion nommée porte sur un FICHIER d'état, pas sur un fichier source : on résout la (ou les)
    # variable(s) qui portent ce chemin, sans quoi l'exclusion ne couvrirait que la ligne d'affectation
    # et laisserait passer toutes les écritures — une exclusion qui n'exclut rien est pire qu'aucune.
    autorise = CACHES_SANS_ACQUITTEMENT.get(nom)
    if autorise:
        for ligne in src.splitlines():
            l = strip_comment(ligne)
            m = AFFECT_ETAT.match(l)
            if m and autorise in l:
                persistants.discard(m.group(1))
    for i, ligne in enumerate(src.splitlines(), 1):
        l = strip_comment(ligne)
        if not l.strip():
            continue
        if autorise and autorise in l:
            continue
        m = ECRITURE_PRIVEE.search(l)
        if m:
            fautifs.append((i, l.strip(), f"appel direct de `{m.group(1)}`"))
            continue
        for motif, quoi in ((REDIRECTION, "redirection"), (DEPLACEMENT, "déplacement")):
            m = motif.search(l)
            if m and m.group(1) in persistants:
                fautifs.append((i, l.strip(), f"{quoi} vers le chemin d'état `${m.group(1)}`"))
                break
        else:
            m = REDIRECTION_LITTERALE.search(l)
            if m and not est_temporaire(m.group(1)):
                fautifs.append((i, l.strip(), "redirection vers un chemin d'état littéral"))
                continue
            m = TOUCH.search(l)
            if m and any(f"${v}" in m.group(1) or "${%s}" % v in m.group(1) for v in persistants):
                fautifs.append((i, l.strip(), "`touch` d'un chemin d'état (sa DATE est le marqueur)"))
                continue
            if persistants:
                m = REDIRECTION_POSITIONNELLE.search(l)
                if m:
                    fautifs.append(
                        (i, l.strip(), f"redirection vers le paramètre positionnel `${m.group(1)}` — "
                                      "un chemin d'état passé en argument échappe à toute lecture statique")
                    )
    return fautifs


def scripts_suivis():
    out = subprocess.run(
        ["git", "ls-files", "*.sh", "*.bash"], capture_output=True, text=True, check=True
    ).stdout.split()
    return sorted(out)


def exclusions_toujours_valides(scripts):
    for f in ENFORCERS_SANS_LIB:
        if f not in scripts:
            echec(f"{f} n'est plus suivi — l'exclusion nommée de cette garde vise un fichier absent")
        src = open(f, encoding="utf-8", errors="replace").read()
        if re.search(r"^\s*\.\s+.*lib\.sh", src, re.M):
            echec(
                f"{f} source désormais {LIB} : il a accès à `state_stage`, donc son exclusion n'a "
                "plus de raison d'être — retirez-la et faites-le mettre son état en attente"
            )
    for f, cache in CACHES_SANS_ACQUITTEMENT.items():
        if f not in scripts:
            echec(f"{f} n'est plus suivi — l'exclusion nommée de cette garde vise un fichier absent")
        src = open(f, encoding="utf-8", errors="replace").read()
        if cache not in src:
            echec(
                f"{f} n'écrit plus `{cache}` : l'exclusion vise un fichier d'état qui n'existe plus. "
                "Retirez-la plutôt que de la laisser couvrir autre chose."
            )


def jambe_statique(scripts):
    fautifs, mises_en_attente, publications = [], 0, 0
    for f in scripts:
        try:
            src = open(f, encoding="utf-8", errors="replace").read()
        except OSError as e:
            echec(f"lecture impossible de {f} : {e}")
        mises_en_attente += len(re.findall(r"\bstate_stage(?:_append|_file)?\b", src))
        publications += len(re.findall(r"\bspool_(?:write|publish)_then_ack\b", src))
        if f == LIB or f in ENFORCERS_SANS_LIB:
            continue
        for i, ligne, quoi in analyser(src, f):
            fautifs.append((f, i, ligne, quoi))
    if fautifs:
        for f, i, ligne, quoi in fautifs:
            print(f"::error file={f},line={i}::{f} : {quoi} — marqueur de progression écrit hors de la voie unique")
            print(f"  {f}:{i}: {ligne}")
        echec(
            f"{len(fautifs)} écriture(s) directe(s) de marqueur de progression, dans : "
            + ", ".join(sorted({f for f, _, _, _ in fautifs}))
            + " — un marqueur écrit hors de `spool_*_then_ack` / `plume_exit_nodata` est écrit AVANT "
              "la publication qu'il prétend acquitter : une coupure entre les deux PERD les "
              "événements, et rien ne le signale. Mettez-le en attente (`state_stage`, "
              "`state_stage_append`, `state_stage_file`) et publiez par `spool_write_then_ack` / "
              "`spool_publish_then_ack`."
        )
    if mises_en_attente < MIN_MISES_EN_ATTENTE:
        echec(
            f"plancher : {mises_en_attente} mise(s) en attente trouvée(s) (< {MIN_MISES_EN_ATTENTE}) "
            "— la découverte est cassée, cette garde ne verrait rien"
        )
    if publications < MIN_PUBLICATIONS_ACQUITTANTES:
        echec(
            f"plancher : {publications} publication(s) acquittante(s) trouvée(s) "
            f"(< {MIN_PUBLICATIONS_ACQUITTANTES}) — la découverte est cassée"
        )
    return mises_en_attente, publications


def _sh(script, env):
    return subprocess.run(["sh", "-c", script], env=env, capture_output=True, text=True)


def jambe_executee():
    """Source VRAIMENT lib.sh et vérifie l'ORDRE des deux effets, puis une COUPURE entre eux."""
    if shutil.which("sh") is None:
        echec("aucun `sh` — la jambe exécutée ne peut pas rendre de verdict (et ne rendra pas un faux vert)")
    lib = os.path.abspath(LIB)
    with tempfile.TemporaryDirectory() as base:
        binz, spool, etat = (os.path.join(base, x) for x in ("bin", "spool", "state"))
        journal = os.path.join(base, "appels.txt")
        for d in (binz, spool, etat):
            os.makedirs(d)
        wm = os.path.join(etat, "essai.watermark")
        cible = os.path.join(spool, "essai-1.json")
        # `sync` INSTRUMENTÉ : il se comporte comme un GNU `sync` (il ÉCHOUE sur un chemin absent,
        # sans quoi la détection d'instrument de lib.sh le classerait « ignore son opérande ») et
        # journalise, à chaque appel, si le FILIGRANE existait déjà. C'est cette colonne qui prouve
        # l'ordre : la publication se synchronise AVANT que le marqueur n'existe.
        with open(os.path.join(binz, "sync"), "w", encoding="utf-8") as f:
            f.write(
                "#!/bin/sh\n"
                'for p in "$@"; do [ -e "$p" ] || exit 1; done\n'
                'if [ -e "%s" ]; then etat=filigrane-present; else etat=filigrane-absent; fi\n'
                'printf "%%s\\n" "$etat" >> "%s"\n'
                "exit 0\n" % (wm, journal)
            )
        os.chmod(os.path.join(binz, "sync"), 0o755)
        env = dict(
            os.environ,
            PATH=binz + os.pathsep + os.environ.get("PATH", ""),
            PLUME_SPOOL=spool,
            PLUME_STATE=etat,
        )

        # (1) TÉMOIN NÉGATIF : mettre en attente n'écrit RIEN. Sans lui, une mise en attente qui
        # écrirait tout de suite passerait ce test comme une fleur.
        r = _sh(f'set -eu\n. "{lib}"\nplume_init\nstate_stage "{wm}" "41"\n', env)
        if r.returncode != 0:
            echec(f"la mise en attente de contrôle a échoué (rc={r.returncode}) : {r.stderr.strip()}")
        if os.path.exists(wm):
            echec("`state_stage` a ÉCRIT le marqueur : la mise en attente n'attend rien, l'ordre n'est plus tenu")

        # (2) ORDRE : publication puis acquittement.
        r = _sh(
            f'set -eu\n. "{lib}"\nplume_init\nstate_stage "{wm}" "42"\n'
            'spool_write_then_ack "essai-1.json" \'{"kind":"events"}\' nl\n',
            env,
        )
        if r.returncode != 0:
            echec(f"la publication de contrôle a échoué (rc={r.returncode}) : {r.stderr.strip()}")
        if not os.path.exists(cible):
            echec("la publication de contrôle n'a produit aucun fichier — le témoin ne mesure rien")
        if not os.path.exists(wm):
            echec("le marqueur mis en attente n'a jamais été écrit — la publication n'acquitte plus rien")
        appels = [l for l in open(journal, encoding="utf-8").read().splitlines() if l]
        if not appels:
            echec("aucune synchronisation observée — l'instrument ne mesure rien (voir S27)")
        if "filigrane-present" in appels:
            echec(
                "le marqueur existait DÉJÀ pendant la synchronisation de la publication : l'ordre est "
                f"inversé, l'acquittement précède la publication (appels vus : {appels})"
            )

        # (3) COUPURE SIMULÉE ENTRE LES DEUX. Le processus meurt DANS l'écriture du marqueur, une
        # fois l'enveloppe publiée. Ce qu'on exige : l'enveloppe est là, le marqueur ne l'est pas —
        # donc le passage suivant relit la même tranche et REJOUE, au lieu de perdre en silence.
        os.remove(wm)
        os.remove(cible)
        r = _sh(
            f'set -eu\n. "{lib}"\nplume_init\n'
            "state_write() { kill -9 $$; }\n"
            f'state_stage "{wm}" "43"\n'
            'spool_write_then_ack "essai-1.json" \'{"kind":"events"}\' nl\n'
            'echo NON-INTERROMPU\n',
            env,
        )
        if "NON-INTERROMPU" in r.stdout:
            echec("la coupure simulée n'a pas eu lieu — ce témoin ne prouverait rien")
        if not os.path.exists(cible):
            echec(
                "après coupure entre les deux gestes, l'enveloppe publiée MANQUE : la publication "
                "n'est pas terminée avant l'acquittement"
            )
        if os.path.exists(wm):
            echec(
                "après coupure entre les deux gestes, le marqueur EXISTE alors que le passage a été "
                "interrompu : il acquitte ce que personne ne garantit avoir livré"
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
    attentes, publications = jambe_statique(scripts)
    n = jambe_executee()
    print(
        f"check_watermark_follows_publication : {len(scripts)} script(s) balayé(s), "
        f"{attentes} mise(s) en attente, {publications} publication(s) acquittante(s), "
        f"ordre vérifié à l'exécution ({n} synchronisation(s) observée(s), marqueur ABSENT pendant "
        "chacune) et coupure simulée entre les deux gestes : enveloppe publiée, marqueur non écrit. "
        "Prouve l'ORDRE, pas l'innocuité du rejeu ni la survie à une coupure d'alimentation."
    )


if __name__ == "__main__":
    main()
