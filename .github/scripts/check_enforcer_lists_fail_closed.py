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


def scenario_respond(nom, prepare_liste, attendu):
    """attendu : ('refus', causes) | ('applique',) | ('epargnee',)"""
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
            "PENDING_TSV": "1\tban_ip\t203.0.113.7\t0",
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
