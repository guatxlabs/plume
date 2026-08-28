#!/usr/bin/env python3
"""Un enforcer qui ne peut pas lire sa liste de protection REFUSE — garde de CI (`S36`).

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
Un enforcer applique une protection en lisant une liste — ce qu'il doit épargner, ou ce qu'il
doit ré-armer. Quand cette lecture échouait, les deux enforcers livrés prenaient la branche la
plus PERMISSIVE, et rien ne le disait :

  * `collectors/respond.sh` — la liste des IP à NE JAMAIS bannir se lisait
    `[ -r "$F" ] && grep -qxF "$ip" "$F" && return 0` puis `return 1`. Quatre faits distincts
    tombaient sur la même branche « bannis » : lue-et-absente (le seul fait), fichier manquant,
    accès refusé, et recherche en erreur (un RÉPERTOIRE à la place du fichier — `-r` le passe, et
    sous root il passe même un mode 000). Le ban partait sur une IP déclarée intouchable, et son
    résultat remontait au central comme un succès ordinaire.

  * `collectors/engagement-adapter.sh` — celui-ci ÉCRIT l'invariant INVERSE dans son en-tête
    (« une exemption est une défense BAISSÉE : son mode de panne DOIT être re-arm, jamais
    laisser-ouvert »), et faisait le contraire : son compteur d'échecs, son battement et son set
    appliqué se lisaient `"$(cat "$F" 2>/dev/null || echo 0)"`. Un compteur d'armement qu'on ne
    sait plus lire vaut zéro, donc ne franchit JAMAIS son seuil : le REVERT-ALL promis ne partait
    plus, et les exemptions — des défenses baissées — tenaient tant que le central restait
    injoignable.

CE QUE CETTE GARDE VÉRIFIE — DEUX TÉMOINS, ET LE SECOND EST LE CŒUR
--------------------------------------------------------------------
Chaque enforcer est exécuté TEL QU'IL EST LIVRÉ, dans un `PATH` fabriqué (seuls les utilitaires
énumérés ici existent, `curl` et `nft` sont des bouchons qui enregistrent) et contre une
arborescence temporaire. Rien de la machine qui exécute la garde n'entre dans le verdict.
  (1) LISTE ILLISIBLE -> la protection REFUSE, et le refus est NOMMÉ (cause de l'ensemble fermé).
  (2) LISTE LISIBLE ET RÉELLEMENT VIDE -> le comportement normal, SANS refus. Sans ce témoin, une
      version qui refuserait TOUJOURS passerait le témoin (1) sans rien prouver : elle serait le
      défaut symétrique — un responder qui n'applique plus rien, un adaptateur qui révoque à
      chaque cycle une exemption parfaitement valide.
  (3) LA DERNIÈRE LIGNE SANS SAUT DE LIGNE FINAL, DANS LES DEUX SENS. Ajouté le 2026-08-27 parce
      que cette garde était AVEUGLE là où le chemin l'était : tous ses témoins de forme écrivaient
      un `\n` terminal, et `while read` n'exécute pas son corps sur une dernière ligne non
      terminée. Contenu `nginx.service` SANS `\n` -> le ban PARTAIT (`nft add element`, remonté
      `done`) ; le MÊME contenu AVEC `\n` était refusé. Le témoin jumeau — une liste bien formée
      et non terminée — exige qu'elle ÉPARGNE encore, sans quoi « refuser tout fichier non
      terminé » passerait pour une correction.
Un troisième témoin sert d'instrument : le compteur d'armement doit encore ARMER (deuxième cycle
d'échec -> revert-all), sinon « pas de refus » ne prouverait rien non plus.

CE QUI RESTE HORS TÉMOIN, ET POURQUOI C'EST DIT
------------------------------------------------
Une seule branche de `respond.sh` n'est pas exercée : chemin PAR DÉFAUT (`PLUME_RESPONDER_ALLOW`
non posée) et fichier absent -> `hors-liste`, c'est-à-dire le ban suit son cours. La jouer
exigerait de faire dépendre le verdict de la présence de `/etc/plume/responder.allow` sur la
machine qui exécute la garde — exactement ce que cette garde refuse. La branche jumelle, chemin
POSÉ par l'opérateur et fichier absent -> REFUS, est testée : c'est celle qui portait le risque.

LA LISTE DES ENFORCERS N'EST PAS ÉCRITE ICI — elle est DÉRIVÉE de la garde voisine
`check_collector_exit_is_classified.py`, dont le critère est objectif et déjà auto-invalidant.
Un troisième enforcer ajouté là-bas fait ROUGIR cette garde tant qu'il n'a pas ses deux témoins :
une couverture qu'on ne peut pas oublier d'étendre.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile

RACINE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_collector_exit_is_classified import ENFORCERS  # noqa: E402  (source unique de vérité)

# Vocabulaire FERMÉ des causes — les mêmes mots que le démon (`daemon/src/mesure_environnement.rs`)
# et que la bibliothèque des capteurs. Un refus qui nommerait autre chose est une surface libre.
CAUSES = {"source_absente", "source_refusee", "source_illisible", "forme_inconnue"}

# Utilitaires autorisés dans le `PATH` fabriqué. Tout ce qui n'y est pas est ABSENT pour l'enforcer,
# quelle que soit la machine : c'est ce qui rend le verdict reproductible (pas de `cscli` ni de
# `fail2ban-client` qui traîneraient sur un poste et changeraient de levier en cours de route).
OUTILS = ["cat", "sed", "tr", "grep", "date", "mkdir", "touch", "mktemp", "chmod", "mv", "rm"]

ERREURS = []


def echec(msg):
    ERREURS.append(msg)


def bac_a_sable(tmp, bouchons):
    """`PATH` ne contenant QUE `OUTILS` (liens vers les vrais) et les bouchons demandés."""
    binaire = os.path.join(tmp, "bin")
    os.makedirs(binaire, exist_ok=True)
    for outil in OUTILS:
        vrai = shutil.which(outil)
        if not vrai:
            echec(f"utilitaire `{outil}` introuvable sur cette machine : la garde ne peut pas "
                  f"fabriquer son bac à sable, elle REFUSE de conclure.")
            return None
        cible = os.path.join(binaire, outil)
        if not os.path.exists(cible):
            os.symlink(vrai, cible)
    for nom, corps in bouchons.items():
        chemin = os.path.join(binaire, nom)
        with open(chemin, "w", encoding="utf-8") as f:
            f.write(corps)
        os.chmod(chemin, 0o755)
    return binaire


def lancer(interpreteur, script, env, args=()):
    """L'interpréteur est résolu sur le PATH RÉEL : le `PATH` fabriqué ne sert qu'à l'enforcer,
    dont il borne les outils visibles. Sans cela, c'est le harnais lui-même qui ne démarre pas."""
    binaire = shutil.which(interpreteur)
    if not binaire:
        echec(f"interpréteur `{interpreteur}` introuvable — la garde refuse de conclure.")
        return None
    return subprocess.run([binaire, os.path.join(RACINE, script), *args],
                          capture_output=True, text=True, env=env, timeout=120)


# =============================================================================
# ENFORCER 1 — `collectors/respond.sh` : la LISTE D'ÉPARGNE (« ne bannir JAMAIS »)
# =============================================================================
BOUCHON_CURL = r"""#!/bin/sh
cat >/dev/null 2>&1                       # consomme la config d'auth passee sur l'entree standard
corps=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    --data-binary) corps="$2"; shift ;;
    http*) url="$1" ;;
  esac
  shift
done
case "$url" in
  *"/api/actions/pending"*) printf '%s\n' "$PENDING_TSV" ;;
  *"/api/actions/result"*)  printf '%s\n' "$corps" >> "$RESULTATS" ;;
esac
exit 0
"""

BOUCHON_NFT = r"""#!/bin/sh
printf '%s\n' "$*" >> "$NFT_TRACE"
exit 0
"""


def scenario_respond(nom, prepare_liste, attendu, cible="203.0.113.7"):
    """attendu : ('refus', causes) | ('applique',) | ('epargnee',)

    `cible` = l'IP de l'action `ban_ip` tirée de `/api/actions/pending`. Elle était figée sur une
    IPv4 : c'est ce qui rendait cette garde AVEUGLE à toute la famille IPv6 (`P4.7-b`)."""
    with tempfile.TemporaryDirectory() as tmp:
        resultats = os.path.join(tmp, "resultats.jsonl")
        trace_nft = os.path.join(tmp, "nft.trace")
        open(resultats, "w").close()
        open(trace_nft, "w").close()
        liste = prepare_liste(tmp)
        binaire = bac_a_sable(tmp, {"curl": BOUCHON_CURL, "nft": BOUCHON_NFT})
        if binaire is None:
            return
        env = {
            "PATH": binaire,
            "PLUME_RESPONDER": "1",
            "PLUME_RESPONDER_APPLY": "1",
            "PLUME_CENTRAL": "http://central.invalid",
            "PLUME_HOST_LABEL": "hote-de-garde",
            "PLUME_TOKEN": "jeton-de-garde",
            "PLUME_BAN_BACKEND": "auto",
            "PENDING_TSV": f"1\tban_ip\t{cible}\t0",
            "RESULTATS": resultats,
            "NFT_TRACE": trace_nft,
        }
        if liste is not None:
            env["PLUME_RESPONDER_ALLOW"] = liste
        p = lancer("sh", "collectors/respond.sh", env)
        if p is None:
            return
        sortie = open(resultats, encoding="utf-8").read()
        appels_nft = open(trace_nft, encoding="utf-8").read()
        if p.returncode != 0:
            echec(f"respond/{nom}: l'enforcer s'est terminé en {p.returncode} — "
                  f"stderr={p.stderr.strip()[:400]}")
            return
        if not sortie.strip():
            echec(f"respond/{nom}: AUCUN résultat remonté au central. Le harnais n'a pas exercé "
                  f"l'enforcer — cette garde refuse de conclure. stderr={p.stderr.strip()[:400]}")
            return
        genre = attendu[0]
        if genre == "refus":
            if '"status":"failed"' not in sortie or "fail-closed" not in sortie:
                echec(f"respond/{nom}: liste ILLISIBLE et le ban n'a PAS été refusé — "
                      f"la protection a disparu en silence. Remonté : {sortie.strip()[:300]}")
            causes = {c for c in CAUSES if f"cause={c}" in sortie}
            if not causes & attendu[1]:
                echec(f"respond/{nom}: refus NON NOMMÉ (aucune cause de {sorted(attendu[1])} dans "
                      f"le résultat) — un refus muet ne se distingue pas d'une panne. "
                      f"Remonté : {sortie.strip()[:300]}")
            if "add element" in appels_nft:
                echec(f"respond/{nom}: un ban a QUAND MÊME été posé ({appels_nft.strip()[:200]}) "
                      f"alors que la liste d'épargne est illisible.")
        elif genre == "applique":
            if '"status":"done"' not in sortie:
                echec(f"respond/{nom}: liste LISIBLE et réellement vide, et pourtant le ban n'a pas "
                      f"été appliqué — un enforcer qui refuse TOUJOURS ne protège rien non plus. "
                      f"Remonté : {sortie.strip()[:300]}")
            if "add element" not in appels_nft:
                echec(f"respond/{nom}: le chemin d'enforcement n'a jamais été atteint (aucun appel "
                      f"au bouchon) — l'instrument est aveugle, la garde refuse de conclure.")
        elif genre == "epargnee":
            if '"status":"failed"' not in sortie or "liste d epargne" not in sortie:
                echec(f"respond/{nom}: l'IP figure DANS la liste et n'a pas été épargnée. "
                      f"Remonté : {sortie.strip()[:300]}")
            if "add element" in appels_nft:
                echec(f"respond/{nom}: ban posé sur une IP présente dans la liste d'épargne.")


def temoins_respond():
    def liste_absente_mais_posee(tmp):
        return os.path.join(tmp, "liste-qui-nexiste-pas.allow")   # chemin POSÉ, fichier absent

    def liste_repertoire(tmp):
        d = os.path.join(tmp, "liste-repertoire")
        os.makedirs(d)
        return d

    def liste_mode_000(tmp):
        f = os.path.join(tmp, "liste-fermee.allow")
        open(f, "w").write("203.0.113.7\n")
        os.chmod(f, 0o000)
        return f

    def liste_vide(tmp):
        f = os.path.join(tmp, "liste-vide.allow")
        open(f, "w").write("# aucune IP epargnee sur cet hote\n")
        return f

    def liste_avec_ip(tmp):
        f = os.path.join(tmp, "liste.allow")
        open(f, "w").write("203.0.113.7\n")
        return f

    def liste_de_l_autre_politique(tmp):
        """Le contenu que l'installateur du CENTRAL sème dans `/etc/plume/responder.allow` :
        des NOMS DE SERVICE pour `stop_service`. Bien formé — pour l'autre lecteur."""
        f = os.path.join(tmp, "liste-du-central.allow")
        open(f, "w").write(
            "# 1 service systemd autorise par ligne pour l action stop_service (ex: nginx.service)\n"
            "nginx.service\n"
        )
        return f

    def liste_avec_cidr(tmp):
        """Une ligne CIDR : de la BONNE politique, mais que la recherche par égalité de ligne
        n'a jamais pu apparier. Elle laissait le ban partir en silence."""
        f = os.path.join(tmp, "liste-cidr.allow")
        open(f, "w").write("203.0.113.0/24\n")
        return f

    def contenu_par_defaut(script, motif):
        """LE CONTENU QUE L'INSTALLATEUR POSE — EXTRAIT DU SCRIPT, JAMAIS RECOPIÉ ICI.

        Recopier ce contenu ferait de ce témoin une tautologie : il vérifierait que la copie se
        comporte comme la copie. En le LISANT dans l'installateur, un contenu par défaut qui
        gagnerait demain une ligne non commentée fait rougir cette garde — ce qui est le point,
        puisqu'une telle ligne DÉSARMERAIT tout bannissement de l'hôte, fail-closed."""
        chemin = os.path.join(RACINE, script)
        try:
            texte = open(chemin, encoding="utf-8").read()
        except OSError:
            return None
        m = re.search(motif, texte, re.S)
        if not m:
            return None
        brut = m.group(1)
        lignes = [l for l in re.findall(r'"([^"]*)"', brut)] if "echo" in brut else brut.split("\\n")
        lignes = [l for l in lignes if l.strip() != ""]
        # VALIDATION DE L'INSTRUMENT, ET ELLE NE DOIT PAS SE CONFONDRE AVEC LE VERDICT. Ce qui est
        # vérifié ici est que l'EXTRACTION a marché — plusieurs lignes, dont au moins une qui
        # ressemble à l'en-tête que ces fichiers portent. Ce qui NE l'est pas ici : que le contenu
        # soit acceptable. Un contenu par défaut qui gagnerait une ligne non commentée doit faire
        # rougir le SCÉNARIO (« la liste refuse alors qu'elle devrait laisser passer »), pas être
        # rangé en « forme changée » — deux fautes distinctes, deux messages distincts, sans quoi
        # cette garde commettrait à son tour le défaut qu'elle poursuit.
        if len(lignes) < 3 or not any(l.lstrip().startswith("#") for l in lignes):
            return None
        return "\n".join(lignes) + "\n"

    def liste_par_defaut_du_central(tmp):
        contenu = contenu_par_defaut(
            "bootstrap.sh", r"printf '(.*?)' > /etc/plume/responder\.allow")
        if contenu is None:
            return None
        f = os.path.join(tmp, "defaut-central.allow")
        open(f, "w").write(contenu)
        return f

    def liste_par_defaut_de_l_agent(tmp):
        contenu = contenu_par_defaut(
            "bootstrap-agent.sh", r'if \[ ! -f "\$RESP_ALLOW" \]; then\n\s*\{(.*?)\n\s*\} > "\$RESP_ALLOW"')
        if contenu is None:
            return None
        f = os.path.join(tmp, "defaut-agent.allow")
        open(f, "w").write(contenu)
        return f

    def liste_de_l_autre_politique_sans_saut_final(tmp):
        """LE MÊME CONTENU, SANS `\\n` TERMINAL — et c'est ce qui manquait à cette garde.

        MESURÉ le 2026-08-27 sur `respond.sh` tel qu'il était livré : `while IFS= read -r`
        n'exécute PAS son corps sur une dernière ligne non terminée (`read` rend un code non
        nul). La ligne fautive n'était donc jamais présentée à `is_ip`, la liste passait pour
        bien formée, et le ban PARTAIT (`nft add element …`, remonté en `{"status":"done"}`).
        Les deux témoins qui précèdent écrivaient TOUS DEUX un saut de ligne final : la garde
        était aveugle exactement là où le chemin l'était. La mutation qui le prouve : retirer
        le `|| [ -n "$_vle_l" ]` de `verdict_liste_epargne` fait retomber CE témoin — et lui
        seul — sur `done`."""
        f = os.path.join(tmp, "liste-du-central-sans-saut.allow")
        with open(f, "w") as fh:
            fh.write("nginx.service")          # PAS de "\n" : c'est tout le témoin
        return f

    def liste_avec_ip_sans_saut_final(tmp):
        """LE TÉMOIN NÉGATIF DU PRÉCÉDENT. Une liste BIEN FORMÉE et sans saut de ligne final doit
        continuer d'ÉPARGNER : une correction qui refuserait tout fichier non terminé
        transformerait la lecture en refus permanent et passerait le témoin positif sans rien
        prouver. C'est le témoin qui interdit de « corriger » par un refus global."""
        f = os.path.join(tmp, "liste-sans-saut.allow")
        with open(f, "w") as fh:
            fh.write("203.0.113.7")
        return f

    # (1) LISTE ILLISIBLE -> REFUS NOMMÉ
    scenario_respond("liste-posee-mais-absente", liste_absente_mais_posee,
                     ("refus", {"source_absente"}))
    scenario_respond("liste-non-lisible", liste_repertoire,
                     ("refus", {"source_illisible", "source_refusee"}))
    if os.geteuid() != 0:   # sous root, `-r` est vrai sur un mode 000 : le témoin n'aurait aucun sens
        scenario_respond("liste-acces-refuse", liste_mode_000,
                         ("refus", {"source_refusee"}))
    # (1 bis) LISTE DE L'AUTRE POLITIQUE -> REJETÉE, PAS IGNORÉE (`P4.7-a`).
    # C'est le témoin qui SÈME l'un des deux contenus et exige que l'AUTRE lecteur le refuse. Avant
    # ce contrôle, ce scénario rendait `("applique",)` : le responder cherchait une IP, n'en trouvait
    # aucune, concluait « hors-liste » et BANNISSAIT — la liste d'épargne de l'exploitant était vide
    # sans que rien ne l'ait jamais dite vide. La mutation qui le prouve : retirer la boucle de forme
    # de `verdict_liste_epargne` fait retomber ce cas sur `done`, et ce témoin devient rouge.
    scenario_respond("liste-de-l-autre-politique", liste_de_l_autre_politique,
                     ("refus", {"forme_inconnue"}))
    # (1 ter) UNE LIGNE DE LA BONNE POLITIQUE QUE LA RECHERCHE NE SAIT PAS APPARIER (CIDR) : la
    # protection promise n'existe pas non plus, et elle cesse d'être promise en silence.
    scenario_respond("liste-cidr-non-appariable", liste_avec_cidr,
                     ("refus", {"forme_inconnue"}))
    # (1 quater) LA MÊME LIGNE FAUTIVE, SANS SAUT DE LIGNE FINAL. Le trou que les deux témoins
    # précédents ne pouvaient pas voir : ils écrivaient tous deux un `\n` terminal.
    scenario_respond("liste-de-l-autre-politique-SANS-SAUT-FINAL",
                     liste_de_l_autre_politique_sans_saut_final,
                     ("refus", {"forme_inconnue"}))
    # (1 quinquies) TÉMOIN NÉGATIF DU PRÉCÉDENT : bien formée ET sans saut final -> ÉPARGNE.
    scenario_respond("ip-dans-la-liste-SANS-SAUT-FINAL", liste_avec_ip_sans_saut_final,
                     ("epargnee",))
    # (2) LISTE LISIBLE ET RÉELLEMENT VIDE -> COMPORTEMENT NORMAL, SANS REFUS
    scenario_respond("liste-lisible-et-vide", liste_vide, ("applique",))
    # (2 bis) LE CONTENU QUE CHAQUE INSTALLATEUR POSE — LU DANS L'INSTALLATEUR — NE REFUSE RIEN.
    # C'est la contrepartie du contrôle de forme : puisqu'une ligne non conforme DÉSARME tout
    # bannissement de l'hôte (fail-closed), une installation NEUVE ne doit jamais partir dans cet
    # état. MESURÉ le 2026-08-27 : les deux fichiers par défaut ne portent QUE des commentaires en
    # colonne zéro, et le ban suit son cours.
    for nom, prepare in (("liste-par-defaut-du-central", liste_par_defaut_du_central),
                         ("liste-par-defaut-de-l-agent", liste_par_defaut_de_l_agent)):
        with tempfile.TemporaryDirectory() as sonde:
            if prepare(sonde) is None:
                echec(f"respond/{nom}: le contenu par défaut n'a pas pu être EXTRAIT de "
                      f"l'installateur (forme changée ?) — cette garde ne peut pas juger ce qu'une "
                      f"installation neuve pose, elle REFUSE DE CONCLURE.")
                continue
        scenario_respond(nom, prepare, ("applique",))
    # (3) la liste sert encore à ce pour quoi elle existe
    scenario_respond("ip-dans-la-liste", liste_avec_ip, ("epargnee",))


# =============================================================================
# ENFORCER 2 — `collectors/engagement-adapter.sh` : l'ÉTAT QUI ARME LE FAIL-CLOSED
# =============================================================================
BOUCHON_CURL_KO = """#!/bin/sh
cat >/dev/null 2>&1
exit 7
"""


def lancer_adaptateur(tmp, etat, args=(), cycles=1):
    binaire = bac_a_sable(tmp, {"curl": BOUCHON_CURL_KO})
    if binaire is None:
        return None
    env = {
        "PATH": binaire,
        "PLUME_ENGAGEMENT_ADAPTER": "1",
        "PLUME_CENTRAL": "http://central.invalid",
        "PLUME_TOKEN": "jeton-de-garde",
        "PLUME_HOST_LABEL": "hote-de-garde",
        "PLUME_STATE": etat,
        "PLUME_SPOOL": os.path.join(tmp, "spool-inexistant"),
        "HOME": tmp,
    }
    dernier = None
    for _ in range(cycles):
        dernier = lancer("bash", "collectors/engagement-adapter.sh", env, args)
    return dernier


def scenario_adaptateur(nom, prepare_etat, attendu_present, attendu_absent, cycles=1, args=()):
    with tempfile.TemporaryDirectory() as tmp:
        etat = os.path.join(tmp, "etat")
        os.makedirs(etat)
        prepare_etat(etat)
        p = lancer_adaptateur(tmp, etat, args=args, cycles=cycles)
        if p is None:
            return
        if p.returncode != 0:
            echec(f"adaptateur/{nom}: terminé en {p.returncode} — stderr={p.stderr.strip()[:400]}")
            return
        journal = p.stderr
        if "engagement-adapter:" not in journal:
            echec(f"adaptateur/{nom}: aucune ligne de journal — le harnais n'a pas exercé "
                  f"l'enforcer, la garde refuse de conclure.")
            return
        for attendu in attendu_present:
            if attendu not in journal:
                echec(f"adaptateur/{nom}: « {attendu} » ABSENT du journal du cycle. "
                      f"Journal : {journal.strip()[-500:]}")
        for interdit in attendu_absent:
            if interdit in journal:
                echec(f"adaptateur/{nom}: « {interdit} » PRÉSENT alors qu'il ne devrait pas l'être. "
                      f"Journal : {journal.strip()[-500:]}")


def temoins_adaptateur():
    def compteur_repertoire(etat):
        os.makedirs(os.path.join(etat, "engagement-adapter.failcount"))

    def compteur_mode_000(etat):
        f = os.path.join(etat, "engagement-adapter.failcount")
        open(f, "w").write("0\n")
        os.chmod(f, 0o000)

    def compteur_reel_a_zero(etat):
        open(os.path.join(etat, "engagement-adapter.failcount"), "w").write("0\n")

    def battement_repertoire(etat):
        open(os.path.join(etat, "engagement-adapter.failcount"), "w").write("0\n")
        os.makedirs(os.path.join(etat, "engagement-adapter.heartbeat"))

    def applique_repertoire(etat):
        open(os.path.join(etat, "engagement-adapter.failcount"), "w").write("0\n")
        os.makedirs(os.path.join(etat, "engagement-adapter.applied"))

    # (1) ÉTAT D'ARMEMENT ILLISIBLE -> RE-ARM IMMÉDIAT, ET IL EST NOMMÉ
    scenario_adaptateur("compteur-non-lisible", compteur_repertoire,
                        ["FAIL-CLOSED", "mode=revert-all"], [])
    if os.geteuid() != 0:
        scenario_adaptateur("compteur-acces-refuse", compteur_mode_000,
                            ["FAIL-CLOSED", "source_refusee", "mode=revert-all"], [])
    scenario_adaptateur("set-applique-non-lisible", applique_repertoire,
                        ["FAIL-CLOSED", "HOLD impossible", "mode=revert-all"], [])
    scenario_adaptateur("battement-non-lisible", battement_repertoire,
                        ["FAIL-CLOSED horloge"], [])
    # (2) ÉTAT LISIBLE ET RÉELLEMENT À ZÉRO -> COMPORTEMENT NORMAL (tolérance au blip), SANS REVERT
    scenario_adaptateur("compteur-lisible-a-zero", compteur_reel_a_zero,
                        ["mode=hold"], ["FAIL-CLOSED", "mode=revert-all"])
    # (3) INSTRUMENT : le compteur ARME toujours au bout de N cycles — sans quoi « pas de revert »
    #     au témoin (2) ne prouverait rien.
    scenario_adaptateur("compteur-lisible-deux-cycles", compteur_reel_a_zero,
                        ["mode=revert-all"], [], cycles=2)


# =============================================================================
# `P4.7-b` — LE CORPUS PARTAGÉ : LE MÊME FICHIER, PRÉSENTÉ AUX DEUX LECTEURS
# =============================================================================
# LE DÉFAUT QUE CE BLOC REND NON-ÉCRIVABLE. Deux lecteurs se promettent le même critère d'adresse —
# `ressemble_a_une_adresse` (Rust, démon) et `is_ip` (shell, agent) — et ne peuvent pas partager un
# littéral. L'équivalence était donc AFFIRMÉE EN COMMENTAIRE, et les deux témoins qui prétendaient
# la tenir ne se rencontraient jamais : celui du démon n'exerçait que la fonction Rust, celui-ci
# n'exerçait que le shell, et son corpus était EXCLUSIVEMENT IPv4 (`203.0.113.7`, `203.0.113.0/24`).
# Toute la famille IPv6 est passée entre les deux : le démon lisait une liste d'épargne
# `2001:db8::1` / `::1` comme une liste de NOMS DE SERVICE, sans un mot, pendant que le fichier
# affirmait à l'exploitant que « les deux lecteurs REFUSENT le contenu de l'autre politique ».
#
# CE QUI EST TENU ICI, ET CE QUI NE L'EST PAS. Ce bloc mesure la colonne `agent` de
# `collectors/predicat-adresse.corpus` en EXÉCUTANT le prédicat EXTRAIT DU SCRIPT LIVRÉ ; la colonne
# `demon` est mesurée par `daemon/src/tests/allowlist_du_responder.rs`. NI L'UN NI L'AUTRE NE PROUVE
# SEUL LA PROPRIÉTÉ : chacun prend l'autre colonne pour acquise. C'est le FICHIER PARTAGÉ qui les
# relie, et c'est pourquoi les deux REFUSENT DE CONCLURE s'il manque, maigrit, ou perd une
# combinaison. La propriété promise est ÉTROITE et elle est écrite dans le corpus : tout ce que
# l'agent lit comme une adresse, le démon le refuse (CONTENANCE) ; et aucune ligne n'est retenue par
# les deux (AUCUN SILENCE À DEUX). L'ÉGALITÉ des deux prédicats n'est PAS promise — elle est fausse,
# et le corpus le dit ligne par ligne.
CORPUS_PARTAGE = os.path.join(RACINE, "collectors", "predicat-adresse.corpus")


def corpus_partage():
    """Lit le corpus commun. Rend `None` — et NOMME le refus — plutôt qu'une liste vide : un corpus
    absent rendrait tous les témoins qui suivent verts en n'exerçant rien."""
    try:
        texte = open(CORPUS_PARTAGE, encoding="utf-8").read()
    except OSError as e:
        echec(f"corpus-partage: `collectors/predicat-adresse.corpus` illisible ({e}) — la frontière "
              f"que les deux lecteurs se promettent n'est mesurée par personne, cette garde REFUSE "
              f"DE CONCLURE.")
        return None
    lignes = []
    for rang, brute in enumerate(texte.splitlines(), start=1):
        if brute.startswith("#") or not brute.strip():
            continue
        champs = brute.split("\t")
        if len(champs) != 3 or champs[1] not in ("refuse", "nom-de-service") \
                or champs[2] not in ("adresse", "forme-inconnue"):
            echec(f"corpus-partage: ligne {rang} hors format (`chaine<TAB>demon<TAB>agent`, "
                  f"vocabulaires fermés) : {brute!r} — cette garde REFUSE DE CONCLURE.")
            return None
        lignes.append(tuple(champs))
    if len(lignes) < 25:
        echec(f"corpus-partage: seulement {len(lignes)} lignes de corpus — il a maigri, cette garde "
              f"REFUSE DE CONCLURE.")
        return None
    for combinaison in (("refuse", "adresse"), ("refuse", "forme-inconnue"),
                        ("nom-de-service", "forme-inconnue")):
        if not any((d, a) == combinaison for _, d, a in lignes):
            echec(f"corpus-partage: la combinaison {combinaison} a disparu du corpus — la couverture "
                  f"n'est plus celle que les deux témoins annoncent. REFUS DE CONCLURE.")
            return None
    for chaine, d, a in lignes:
        if (d, a) == ("nom-de-service", "adresse"):
            echec(f"corpus-partage: `{chaine}` est DÉCLARÉE retenue par les DEUX lecteurs — c'est le "
                  f"défaut de `P4.7-b` écrit dans le corpus, pas un cas à couvrir.")
            return None
    return lignes


def predicat_d_adresse_de_l_agent():
    """EXTRAIT `is_ip` de `collectors/respond.sh` — jamais recopié ici. Recopier ferait de ce témoin
    une tautologie : il vérifierait que la copie se comporte comme la copie, et le jour où le script
    livré change, la copie continuerait de dire vrai. Rend le fragment de shell, ou `None`."""
    chemin = os.path.join(RACINE, "collectors", "respond.sh")
    try:
        texte = open(chemin, encoding="utf-8").read()
    except OSError as e:
        echec(f"corpus-partage: `collectors/respond.sh` illisible ({e}) — REFUS DE CONCLURE.")
        return None
    for ligne in texte.splitlines():
        if ligne.startswith("is_ip()") and "grep" in ligne:
            return ligne
    echec("corpus-partage: `is_ip()` n'est plus défini sur une ligne unique de `collectors/"
          "respond.sh` (forme changée ?) — cette garde ne peut plus l'extraire, elle REFUSE DE "
          "CONCLURE plutôt que de juger sur une copie.")
    return None


def verdicts_de_l_agent(definition, chaines):
    """Joue le prédicat sur chaque chaîne, dans un `sh` séparé. Rend {chaine: 'adresse'|'forme-inconnue'}
    ou `None` si l'exécution elle-même a échoué (un instrument muet n'est pas un verdict)."""
    sh = shutil.which("sh")
    if not sh:
        echec("corpus-partage: `sh` introuvable — REFUS DE CONCLURE.")
        return None
    rendu = {}
    for c in chaines:
        p = subprocess.run([sh, "-c", definition + '\nis_ip "$1"', "harnais", c],
                           capture_output=True, text=True, timeout=30)
        if p.returncode not in (0, 1):
            echec(f"corpus-partage: le prédicat a rendu {p.returncode} sur {c!r} (ni vrai ni faux) — "
                  f"REFUS DE CONCLURE. stderr={p.stderr.strip()[:200]}")
            return None
        rendu[c] = "adresse" if p.returncode == 0 else "forme-inconnue"
    return rendu


# `P4.7-b` (reprise du 2026-08-28) — (P1) N'ÉTAIT TENUE QUE SUR LES 30 LIGNES DU CORPUS.
# Le corpus s'annonçait « LA DÉFINITION COMMUNE » et les installateurs écrivaient « AUCUNE ligne
# n'est acceptée EN SILENCE par les deux » — un UNIVERSEL —, alors que les deux témoins ne
# comparaient que des colonnes DÉCLARÉES sur un ÉCHANTILLON : une clause ajoutée demain à `is_ip`
# sur une forme ABSENTE du corpus aurait cassé (P1) sans faire rougir personne.
# (P1) EST DEPUIS DÉCOMPOSÉE EN DEUX MOITIÉS BALAYÉES, reliées par une borne STRUCTURELLE publiée
# dans l'en-tête du corpus :
#     (S)  s != "" et tous les caractères de s dans [0-9a-fA-F.:] et au moins un dans {'.', ':'}
#   MOITIÉ AGENT (ICI)   : tout ce que `is_ip` — EXTRAIT DU SCRIPT LIVRÉ — accepte satisfait (S).
#   MOITIÉ DÉMON (Rust)  : tout ce qui satisfait (S) est REFUSÉ par `allowlist_stop_service`.
#   COMPOSITION          : tout ce que l'agent lit comme une adresse, le démon le refuse = (P1).
# UN BALAYAGE EST UN ÉCHANTILLON, LUI AUSSI — ET CELUI-CI L'A ÉTÉ. Premier jet du 2026-08-28 :
# alphabet écrit à la main, longueurs 1 à 3. MESURÉ contre lui : élargir `is_ip` à la forme
# CROCHETÉE (`[::1]`) ne le faisait PAS rougir — aucun crochet dans l'alphabet, donc la même faute
# que le corpus, un cran plus loin. CE QUI FERME LA CLASSE : l'alphabet est DÉRIVÉ de la ligne
# `is_ip` ELLE-MÊME. On ne peut pas élargir un ERE sans ÉCRIRE les caractères qu'on y admet, et ces
# caractères entrent alors dans le balayage du même geste — la mutation crochetée le fait désormais
# rougir (mesuré).
# LA LIMITE, ÉCRITE : une clause qui n'introduit AUCUN caractère littéral (une classe POSIX
# `[[:alpha:]]`, un `.`) élargit sans enrichir l'alphabet. `.` est déjà couvert ; une classe
# nommée ne l'est pas, et ce trou-là reste. Le balayage borne aussi les LONGUEURS (voir plus bas) :
# il est plus large que 30 lignes, il n'est pas total.
ALPHABET_DE_BASE = "09afF.:%/# -"   # un représentant par classe : chiffre, hex bas, hex haut,
                                    # hors-hex, les deux séparateurs, les deux habillages coupés
                                    # par le lecteur du démon, le commentaire, le blanc, le tiret.
LONGUEUR_DE_BASE = 3                # exhaustif sur l'alphabet de base
LONGUEUR_DERIVEE = 2                # exhaustif sur l'alphabet DÉRIVÉ, plus large donc plus court
NOYAUX_D_ENCADREMENT = ("1", "::")  # ... complété par `c + noyau + d` : c'est ce qui atteint `[1]`


def satisfait_la_borne_structurelle(s):
    """(S), écrite ici dans les mots de l'en-tête du corpus. Elle est écrite DEUX fois, une par
    langage — la même impossibilité que le prédicat lui-même ; ce qui change est qu'elle fait TROIS
    clauses structurelles au lieu d'un prédicat complet."""
    hexa = "0123456789abcdefABCDEF"
    return bool(s) and all(c in hexa + ".:" for c in s) and any(c in ".:" for c in s)


def verdicts_de_l_agent_par_lot(definition, chaines):
    """Joue le prédicat sur BEAUCOUP de chaînes dans UN seul `sh` (une chaîne par ligne, `IFS= read -r`
    préserve blancs de tête et de fin). Aucune chaîne du balayage ne porte de saut de ligne, donc le
    protocole ligne à ligne est total. Rend la liste des verdicts, ou `None`."""
    sh = shutil.which("sh")
    if not sh:
        echec("corpus-partage: `sh` introuvable — REFUS DE CONCLURE.")
        return None
    programme = definition + '\nwhile IFS= read -r _c; do if is_ip "$_c"; then printf "1\\n"; else printf "0\\n"; fi; done'
    p = subprocess.run([sh, "-c", programme], input="\n".join(chaines) + "\n",
                       capture_output=True, text=True, timeout=600)
    verdicts = [l for l in p.stdout.split("\n") if l != ""]
    if p.returncode != 0 or len(verdicts) != len(chaines) or any(v not in ("0", "1") for v in verdicts):
        echec(f"corpus-partage: le balayage n'a pas rendu un verdict par chaîne "
              f"({len(verdicts)} pour {len(chaines)}, rc={p.returncode}) — REFUS DE CONCLURE. "
              f"stderr={p.stderr.strip()[:200]}")
        return None
    return verdicts


def alphabet_derive(definition):
    """L'alphabet du balayage, DÉRIVÉ de la ligne `is_ip` livrée : tout caractère imprimable qu'elle
    porte, plus l'alphabet de base. C'est ce qui rend le balayage insensible à MON choix d'alphabet —
    un élargissement du prédicat écrit ses propres caractères, et ils entrent ici du même geste."""
    return "".join(sorted({c for c in definition if c.isprintable()} | set(ALPHABET_DE_BASE)))


def balayage(definition):
    """Trois familles, plus des chaînes LONGUES ciblées (c'est une borne de LONGUEUR qui avait laissé
    le dernier silence à deux) :
      (a) EXHAUSTIF jusqu'à `LONGUEUR_DE_BASE` sur l'alphabet de base ;
      (b) EXHAUSTIF jusqu'à `LONGUEUR_DERIVEE` sur l'alphabet DÉRIVÉ de la ligne `is_ip` ;
      (c) ENCADREMENTS `c + noyau + d` sur l'alphabet dérivé — c'est ce qui atteint une forme
          délimitée comme `[1]` ou `[::]`, que (b) est trop court pour former."""
    derive = alphabet_derive(definition)
    sortie = []
    chaines = [""]
    for _ in range(LONGUEUR_DE_BASE):
        chaines = [t + c for t in chaines for c in ALPHABET_DE_BASE]
        sortie.extend(chaines)
    chaines = [""]
    for _ in range(LONGUEUR_DERIVEE):
        chaines = [t + c for t in chaines for c in derive]
        sortie.extend(chaines)
    for c in derive:
        for d in derive:
            for noyau in NOYAUX_D_ENCADREMENT:
                sortie.append(c + noyau + d)
    sortie.extend(["dead:beef:cafe:cafe:cafe:cafe:cafe:cafe:cafe:cafe",
                   "0000:0000:0000:0000:0000:ffff:255.255.255.255",
                   "00000:0000:0000:0000:0000:ffff:255.255.255.255",
                   "f" * 45, "f" * 45 + ":" + "f" * 45, ":" * 100, "dead:" * 20,
                   "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:DB8::1", "FE80::DEAD",
                   "999.999.999.999", "01.02.03.04", "plume-daemon.service", "soc.example.com",
                   "[::1]", "[2001:db8::1]", "fe80::1%eth0", "203.0.113.0/24"])
    vus, uniques = set(), []
    for c in sortie:
        if c not in vus:
            vus.add(c)
            uniques.append(c)
    return uniques


def temoin_de_la_moitie_agent(definition):
    """MOITIÉ AGENT DE (P1), BALAYÉE SUR LE SCRIPT LIVRÉ : tout ce que `is_ip` accepte satisfait (S).
    C'est CE témoin qui ferme l'angle mort de l'échantillon : une clause ajoutée demain à `is_ip` sur
    une forme absente du corpus (`[`, `]`, une zone `%`, un blanc) le fait rougir ici."""
    chaines = balayage(definition)
    verdicts = verdicts_de_l_agent_par_lot(definition, chaines)
    if verdicts is None:
        return
    acceptees = [c for c, v in zip(chaines, verdicts) if v == "1"]
    # NON-DÉGÉNÉRESCENCE, DANS LES DEUX SENS, AVANT TOUT VERDICT : un prédicat qui n'accepterait rien
    # (ou tout) tiendrait ou casserait la propriété sans rien mesurer.
    if not (50 <= len(acceptees) <= len(chaines) - 50):
        echec(f"corpus-partage/BALAYAGE: `is_ip` accepte {len(acceptees)} chaînes sur "
              f"{len(chaines)} — un prédicat dégénéré ne mesure rien. REFUS DE CONCLURE.")
        return
    for c in acceptees:
        if not satisfait_la_borne_structurelle(c):
            echec(f"corpus-partage/CONTENANCE-BALAYÉE: `is_ip` de `collectors/respond.sh` accepte "
                  f"{c!r}, qui NE SATISFAIT PAS la borne structurelle (S) publiée par "
                  f"`collectors/predicat-adresse.corpus`. La moitié AGENT de (P1) est rompue : le "
                  f"classificateur du démon ne contient plus le lecteur d'hôte, donc une liste "
                  f"d'épargne peut redevenir une allowlist `stop_service` silencieuse — et le "
                  f"corpus, qui ne porte que 30 lignes, ne la verrait pas.")


def temoins_du_corpus_partage():
    corpus = corpus_partage()
    definition = predicat_d_adresse_de_l_agent()
    if corpus is None or definition is None:
        return
    chaines = [c for c, _, _ in corpus]

    # ---- VALIDATION DE L'INSTRUMENT PAR MUTATION, AVANT TOUT VERDICT, ET DANS LES DEUX SENS.
    # Un harnais qui rendrait toujours la même chose passerait la comparaison sans rien mesurer.
    temoin = ["203.0.113.7", "2001:db8::1", "nginx.service"]
    negatif = verdicts_de_l_agent("is_ip() { printf '%s' \"$1\" | grep -qE '^ZZZ$'; }", temoin)
    positif = verdicts_de_l_agent("is_ip() { printf '%s' \"$1\" | grep -qE '.*'; }", temoin)
    if negatif is None or positif is None:
        return
    if set(negatif.values()) != {"forme-inconnue"} or set(positif.values()) != {"adresse"}:
        echec(f"corpus-partage: L'INSTRUMENT N'EST PAS VALIDÉ — un prédicat muté en `^ZZZ$` doit "
              f"tout refuser et un prédicat muté en `.*` doit tout accepter ; mesuré "
              f"{negatif} / {positif}. Cette garde REFUSE DE CONCLURE.")
        return

    mesures = verdicts_de_l_agent(definition, chaines)
    if mesures is None:
        return

    # ---- (A bis) LA MOITIÉ AGENT DE (P1), BALAYÉE — elle ne dépend PAS des 30 lignes du corpus.
    temoin_de_la_moitie_agent(definition)

    # ---- (A) LA COLONNE `agent` DU CORPUS EST-ELLE CE QUE LE SCRIPT LIVRÉ FAIT ?
    for chaine, attendu_demon, attendu_agent in corpus:
        if mesures[chaine] != attendu_agent:
            echec(f"corpus-partage/agent: `{chaine}` — le corpus annonce `{attendu_agent}` et "
                  f"`is_ip` de `collectors/respond.sh` rend `{mesures[chaine]}`. Le fichier que les "
                  f"DEUX témoins partagent ne décrit plus le lecteur d'hôte : tout ce qui en est "
                  f"dérivé est faux, à commencer par ce que le README promet à l'exploitant.")

    # ---- (B) LES DEUX PROPRIÉTÉS, DÉRIVÉES DES DEUX COLONNES — c'est ici, et NULLE PART ailleurs,
    #      que les deux lecteurs se rencontrent sur une même chaîne.
    for chaine, attendu_demon, _ in corpus:
        if mesures[chaine] == "adresse" and attendu_demon != "refuse":
            echec(f"corpus-partage/CONTENANCE: `{chaine}` est une ADRESSE pour `collectors/"
                  f"respond.sh` (MESURÉ) et le corpus annonce que le démon la retient comme un NOM "
                  f"DE SERVICE. C'est `P4.7-b` : une liste d'épargne parfaitement utilisable par "
                  f"l'agent est lue par le démon comme une allowlist `stop_service`, sans un mot.")
        if mesures[chaine] == "adresse" and attendu_demon == "nom-de-service":
            echec(f"corpus-partage/SILENCE-A-DEUX: `{chaine}` est retenue par LES DEUX lecteurs — "
                  f"aucun des deux ne dira jamais que le fichier porte l'autre politique.")

    # ---- (C) ET LE VERDICT DE BOUT EN BOUT, PAR L'ENFORCER LIVRÉ. Le prédicat est une moitié ; ce
    #      que l'exploitant subit est ce que `respond.sh` FAIT de la liste. Trois témoins, et ils
    #      couvrent LES DEUX DIRECTIONS du défaut.
    def liste_ipv6_pure(tmp):
        """La politique de l'agent, écrite en IPv6 : elle DOIT être lue, et elle DOIT épargner."""
        f = os.path.join(tmp, "epargne-ipv6.allow")
        open(f, "w").write("# IP a NE JAMAIS bannir\n2001:db8::1\nfe80::dead\n")
        return f

    def liste_ipv6_mappee(tmp):
        """L'AUTRE SENS de la divergence : la forme IPv4-mappée est une adresse pour le démon et
        une forme illisible pour l'agent. Elle désarme TOUT ban de cet hôte — c'est fail-closed,
        donc acceptable, mais ce n'est PAS « les deux lecteurs partagent le même critère »."""
        f = os.path.join(tmp, "epargne-mappee.allow")
        open(f, "w").write("::ffff:203.0.113.7\n")
        return f

    # (C1) DIRECTION « ON N'ÉPARGNE PLUS CE QU'ON DEVAIT PROTÉGER » : une liste IPv6 épargne bien
    #      une cible IPv6. Sans ce témoin, « refuser toute IPv6 » passerait pour une correction.
    scenario_respond("epargne-ipv6-pure-EPARGNE", liste_ipv6_pure, ("epargnee",),
                     cible="2001:db8::1")
    # (C2) DIRECTION « ON NE BANNIT PLUS RIEN » : la MÊME liste ne doit pas bloquer un ban légitime
    #      sur une adresse qui n'y figure pas. Une liste IPv6 est LISIBLE, pas suspecte.
    scenario_respond("epargne-ipv6-pure-LAISSE-PASSER", liste_ipv6_pure, ("applique",),
                     cible="203.0.113.7")
    # (C3) LA FORME MIXTE DÉSARME L'HÔTE, ET C'EST DIT : refus NOMMÉ, aucun ban posé. C'est la
    #      moitié de la divergence que le correctif ne ferme PAS (le démon, lui, la reconnaît).
    scenario_respond("epargne-ipv6-mappee-DESARME", liste_ipv6_mappee, ("refus", {"forme_inconnue"}))


def main():
    couverts = {"collectors/respond.sh": temoins_respond,
                "collectors/engagement-adapter.sh": temoins_adaptateur}
    manquants = set(ENFORCERS) - set(couverts)
    if manquants:
        echec("enforcer(s) sans témoins dans cette garde : " + ", ".join(sorted(manquants)) +
              ". La liste est DÉRIVÉE de check_collector_exit_is_classified.py : un enforcer "
              "ajouté là-bas doit recevoir ici ses DEUX témoins (liste illisible -> refus nommé ; "
              "liste lisible et vide -> comportement normal).")
    for chemin, temoins in couverts.items():
        if chemin in ENFORCERS:
            temoins()
    # `P4.7-b` — LE CORPUS PARTAGÉ. Il n'appartient à aucun des deux enforcers : il est la frontière
    # ENTRE le lecteur d'hôte et le lecteur du démon, et c'est précisément parce qu'elle
    # n'appartenait à personne qu'elle n'était mesurée par personne.
    if "collectors/respond.sh" in ENFORCERS:
        temoins_du_corpus_partage()

    if ERREURS:
        for e in ERREURS:
            print(f"::error::{e}")
        print(f"\n{len(ERREURS)} défaut(s) : un enforcer laisse passer quand sa liste de protection "
              f"n'est pas lisible, ou refuse quand elle l'est.")
        return 1
    print(f"{len(ENFORCERS)} enforcers : liste illisible -> refus NOMMÉ ; liste lisible et vide -> "
          f"comportement normal.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
