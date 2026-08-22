#!/usr/bin/env python3
"""Un capteur ne doit pas ANNONCER une couverture que son bac à sable lui retire — garde de CI.

LE DÉFAUT QUE CETTE GARDE REND NON-ÉCRIVABLE
--------------------------------------------
`collectors/integrity.sh` annonce, dans son en-tête et dans `docs/DETECTION-CATALOG.md`
(T1098.004), surveiller `~/.ssh/authorized_keys` — un vecteur de persistance SSH. Le drop-in de
durcissement partagé posait `ProtectHome=true`, qui est un SCALAIRE : systemd applique LAST-WINS et
un drop-in est lu APRÈS l'unit, donc cette ligne écrasait le `ProtectHome=read-only` que
`systemd/plume-integrity.service` posait exprès. `ProtectHome=true` ne rend pas /home et /root
illisibles : il REMPLACE le point de montage par un répertoire vide. Le glob du capteur ne matchait
alors plus rien — sans erreur, sans avertissement, sans une ligne de moins dans le journal.

MESURÉ le 2026-08-20 (systemd 261, sonde différentielle à une seule variable, le capteur exécuté TEL
QUEL) : la baseline FIM perd EXACTEMENT une famille sous `ProtectHome=yes` — 86 lignes au lieu de
87, zéro entrée `authkeys` au lieu de 1, tout le reste identique. Les deux installeurs ne disaient
même pas la même chose : `bootstrap.sh` (central) pose l'unit SANS le drop-in, `bootstrap-agent.sh`
AVEC — le même capteur était couvert d'un côté, aveugle de l'autre.

CE QUE CETTE GARDE VÉRIFIE — DEUX JAMBES, AUCUNE ÉNUMÉRATION
------------------------------------------------------------
1. COUVERTURE ATTEIGNABLE. Pour tout capteur qui déclare des chemins à empreinter (critère
   OBJECTIF : il définit `emit_hash`), les chemins qu'il ANNONCE sont extraits de son code, le bac à
   sable EFFECTIF de son unit est recomposé (unit, puis drop-in partagé — scalaires écrasés,
   listes unionnées, comme systemd), et tout chemin annoncé que ce bac à sable masque est une
   ERREUR qui NOMME le chemin, la directive et le fichier qui la pose. Un chemin ajouté demain à la
   liste annoncée est donc contrôlé d'office : la liste n'est jamais recopiée ici.
2. PROPRIÉTÉ DU SCALAIRE. `ProtectHome=` a été RETIRÉ du drop-in partagé pour que la valeur
   délibérée d'une unit ne soit plus écrasée. Ce retrait ne relâche rien tant que CHAQUE unit
   déclare la sienne : c'est exactement ce que cette jambe exige, sur toutes les unités livrées.

LA TABLE DE MASQUAGE EST MESURÉE, ET ELLE EST TOTALE
-----------------------------------------------------
Une directive de bac à sable ne peut pas entrer dans une unit sans DIRE ce qu'elle masque : toute
directive dont le nom relève de la famille (`Protect…`, `Private…`, `…Paths`, `TemporaryFileSystem`,
`Root…`) et qui n'est pas dans la table fait échouer la garde. Ce qui est dans la table est mesuré,
pas supposé — cf. `MASQUAGE` ci-dessous, en particulier le fait, CONTRE-INTUITIF et vérifié le
2026-08-20 sur systemd 261, que RIEN ne re-expose un chemin masqué par `ProtectHome=yes` (ni
`ReadWritePaths=`, ni `ReadOnlyPaths=`, ni `BindReadOnlyPaths=`) alors que `ProtectHome=tmpfs`, lui,
se laisse re-exposer par un `Bind…Paths=`.

VALIDATION DE L'INSTRUMENT
--------------------------
Une garde qui ne trouverait plus rien à analyser rendrait un vert joyeux. Avant de conclure, elle
rejoue donc sa propre décision sur DEUX bacs à sable synthétiques, avec la liste annoncée réelle :
`ProtectHome=yes` DOIT masquer au moins un chemin annoncé (témoin positif) et `ProtectHome=read-only`
n'en masquer aucun (témoin négatif). Un parseur qui rendrait une liste vide échoue au premier.
"""
import re
import subprocess
import sys

# --- Table de MASQUAGE, mesurée le 2026-08-20 (systemd 261, sonde différentielle) -------------------
# Pour chaque directive de la famille : ce qu'elle masque, et si un `Bind…Paths=`/`ReadOnlyPaths=`
# peut re-exposer un sous-chemin. `None` = valeur non modélisée -> la garde refuse de conclure.
#
#   ProtectHome=yes|true|on ... monte `/systemd/inaccessible/dir` sur /home, /root, /run/user.
#       MESURÉ : ReadWritePaths=, ReadOnlyPaths= et BindReadOnlyPaths= sur ces chemins ne les
#       rendent PAS lisibles (0 entrée authkeys dans les trois cas). Donc re-exposable = False.
#   ProtectHome=tmpfs ........ monte un tmpfs NEUF sur les mêmes chemins. MESURÉ : un
#       BindReadOnlyPaths= plus profond se monte PAR-DESSUS et re-expose (1 entrée authkeys).
#   ProtectHome=read-only|no . ne masque RIEN (lecture autorisée, écriture refusée — mesuré
#       « Read-only file system »).
#   ProtectSystem=… .......... ne masque RIEN : rend l'arborescence en lecture seule.
#   PrivateTmp=yes ........... REMPLACE /tmp et /var/tmp par un tmpfs neuf ; mesure antérieure du
#       dépôt (2026-08-02) : ReadWritePaths= n'y peut rien (226/NAMESPACE). Re-exposable = False.
HOME_PREFIXES = ("/home", "/root", "/run/user")
MASQUAGE = {
    "ProtectHome": {
        "yes": (HOME_PREFIXES, False), "true": (HOME_PREFIXES, False), "on": (HOME_PREFIXES, False),
        "1": (HOME_PREFIXES, False), "tmpfs": (HOME_PREFIXES, True),
        "read-only": ((), False), "no": ((), False), "false": ((), False), "off": ((), False),
        "0": ((), False),
    },
    "ProtectSystem": {v: ((), False) for v in
                      ("yes", "true", "on", "1", "no", "false", "off", "0", "full", "strict")},
    "PrivateTmp": {v: (("/tmp", "/var/tmp"), False) for v in ("yes", "true", "on", "1")}
                  | {v: ((), False) for v in ("no", "false", "off", "0", "disconnected")},
    "PrivateDevices": {v: (("/dev",), False) for v in ("yes", "true", "on", "1")}
                      | {v: ((), False) for v in ("no", "false", "off", "0")},
    # Ne touchent ni /home ni les chemins du FIM : /proc/sys, /sys, les cgroups en lecture seule.
    "ProtectKernelTunables": None, "ProtectKernelModules": None, "ProtectKernelLogs": None,
    "ProtectControlGroups": None, "ProtectClock": None, "ProtectHostname": None,
}
NEUTRES = {"ProtectKernelTunables", "ProtectKernelModules", "ProtectKernelLogs",
           "ProtectControlGroups", "ProtectClock", "ProtectHostname"}

# Réglages de TYPE LISTE : un drop-in les UNIONNE (il n'écrase pas). Une valeur vide les réinitialise.
LISTES = {"InaccessiblePaths", "ReadOnlyPaths", "ReadWritePaths", "BindPaths", "BindReadOnlyPaths",
          "TemporaryFileSystem", "ExecPaths", "NoExecPaths"}
# Listes qui MASQUENT ce qu'elles nomment, et listes qui RE-EXPOSENT.
LISTES_MASQUANTES = {"InaccessiblePaths", "TemporaryFileSystem"}
# Seuls les Bind…Paths= sont retenus comme RE-EXPOSANTS, parce que c'est ce qui a été MESURÉ (sous
# `ProtectHome=tmpfs`, 2026-08-20). `ReadOnlyPaths=`/`ReadWritePaths=` ont été mesurés INCAPABLES de
# re-exposer sous `ProtectHome=yes` ; leur effet sous `tmpfs` n'a PAS été mesuré, donc ils ne comptent
# pas ici — une garde qui croirait à une re-exposition non mesurée serait aveugle, jamais bruyante.
LISTES_REEXPOSANTES = {"BindPaths", "BindReadOnlyPaths"}
# La FAMILLE, reconnue par la FORME du nom : une directive de bac à sable ajoutée demain y tombe et
# doit être déclarée ci-dessus, sinon la garde échoue au lieu de la traverser sans la voir.
FAMILLE = re.compile(r"^(Protect|Private|Inaccessible|ReadOnly|ReadWrite|Bind|Temporary|Root)")
NON_MODELISABLES = {"RootDirectory", "RootImage", "RootHash", "RootVerity", "RootImageOptions"}


def sous(chemin: str, prefixe: str) -> bool:
    """`chemin` est-il SOUS `prefixe` (comparaison PAR COMPOSANTS) ? `/homeless` n'est pas sous /home."""
    return chemin == prefixe or chemin.startswith(prefixe.rstrip("/") + "/")


def lire_reglages(texte: str):
    """Rend {clé: [valeurs...]} pour un fichier d'unit ou de drop-in (sections confondues : les
    fichiers de ce dépôt n'ont qu'une section [Service] qui porte du durcissement)."""
    out = {}
    for ligne in texte.splitlines():
        ligne = ligne.strip()
        if not ligne or ligne.startswith(("#", ";", "[")):
            continue
        if "=" not in ligne:
            continue
        cle, val = ligne.split("=", 1)
        out.setdefault(cle.strip(), []).append(val.strip())
    return out


def composer(unit: dict, dropin: dict):
    """Le bac à sable EFFECTIF, comme systemd le compose : scalaire = LAST-WINS (le drop-in est lu
    après l'unit), liste = UNION (une valeur vide réinitialise). Rend {clé: (valeurs, origine)}."""
    eff = {}
    for origine, reglages in (("unit", unit), ("drop-in", dropin)):
        for cle, vals in reglages.items():
            if cle in LISTES:
                for v in vals:
                    if v == "":
                        eff[cle] = ([], origine)
                    else:
                        prec = eff.get(cle, ([], origine))[0]
                        eff[cle] = (prec + v.split(), origine)
            else:
                eff[cle] = ([vals[-1]], origine)
    return eff


def masques_de(eff: dict, errs: list, ou: str):
    """Rend (masques, reexposes) : masques = [(prefixe, directive, origine, reexposable)]."""
    masques, reexposes = [], []
    for cle, (vals, origine) in eff.items():
        if cle in LISTES:
            if cle in LISTES_MASQUANTES:
                masques += [(p.lstrip("-+!:"), f"{cle}=", origine, True) for p in vals]
            elif cle in LISTES_REEXPOSANTES:
                # `-` = optionnel, `+` = relatif à la racine : on ne garde que le chemin.
                reexposes += [p.lstrip("-+!:").split(":")[0] for p in vals]
            continue
        if not FAMILLE.match(cle):
            continue
        if cle in NON_MODELISABLES:
            errs.append(f"{ou}: `{cle}=` change la racine du bac à sable et n'est pas modélisé ici. "
                        f"Cette garde refuse de conclure sur une couverture qu'elle ne sait pas calculer.")
            continue
        table = MASQUAGE.get(cle, ...)
        if table is ...:
            errs.append(f"{ou}: directive de bac à sable `{cle}=` inconnue de la table MASQUAGE de "
                        f"cette garde. DITES CE QU'ELLE MASQUE (chemins, et si un Bind…Paths= la "
                        f"re-expose) dans .github/scripts/check_fim_coverage_is_reachable.py.")
            continue
        if cle in NEUTRES or table is None:
            continue
        v = vals[-1].lower()
        if v not in table:
            errs.append(f"{ou}: `{cle}={vals[-1]}` — valeur non mesurée. Mesurez ce qu'elle masque "
                        f"avant de l'employer, puis inscrivez-la dans la table MASQUAGE.")
            continue
        prefixes, reexposable = table[v]
        masques += [(p, f"{cle}={vals[-1]}", origine, reexposable) for p in prefixes]
    return masques, reexposes


def injoignables(annonces, masques, reexposes):
    """Les chemins annoncés que le bac à sable retire, avec la directive coupable."""
    out = []
    for chemin in annonces:
        for prefixe, directive, origine, reexposable in masques:
            if not sous(chemin, prefixe):
                continue
            if reexposable and any(sous(chemin, r) for r in reexposes):
                continue
            out.append((chemin, directive, origine, prefixe))
            break
    return out


def annonces_de(src: str):
    """Les chemins que le capteur ANNONCE empreinter — DÉRIVÉS de son code, jamais recopiés.
    Quatre formes, qui sont toutes celles qu'un capteur FIM peut écrire :
      `FILES="${PLUME_FIM_FILES:-…}"`  la liste de fichiers critiques (défaut livré)
      `emit_hash <kind> /chemin`        un chemin littéral
      `for f in /a/* /b/*; do … emit_hash` une famille de chemins (le préfixe du glob suffit)
      `find / -xdev`                    la racine balayée pour les binaires SUID/SGID
      `UNIT_DIRS_DOC="/a /b …"`         la table de repli des répertoires d'unités systemd (P3.8-a) —
                                        la liste DÉRIVÉE à l'exécution n'est pas lisible ici, la
                                        table documentée en est le plancher annoncé
    """
    chemins = set()
    for m in re.finditer(r'PLUME_FIM_FILES:-([^}"]*)[}"]', src):
        chemins |= {w for w in m.group(1).split() if w.startswith("/")}
    for m in re.finditer(r'^\s*UNIT_DIRS_DOC="([^"]*)"', src, re.M):
        chemins |= {w for w in m.group(1).split() if w.startswith("/")}
    for m in re.finditer(r"^\s*emit_hash\s+\w+\s+(/\S+)", src, re.M):
        chemins.add(m.group(1).strip('"'))
    lignes = src.splitlines()
    for i, ligne in enumerate(lignes):
        m = re.match(r"\s*for\s+\w+\s+in\s+(.+?);?\s*do\b(.*)$", ligne)
        if not m:
            continue
        corps = m.group(2) + "\n".join(lignes[i + 1:i + 4])
        if "emit_hash" not in corps:
            continue
        chemins |= {w for w in m.group(1).split() if w.startswith("/")}
    if re.search(r"^\s*find\s+/\s+-xdev", src, re.M):
        chemins.add("/")
    # Un glob ne dit rien de plus qu'un préfixe : /home/*/.ssh/authorized_keys est joignable si et
    # seulement si /home l'est. On garde le chemin tel quel : `sous()` raisonne par composants et
    # `*` n'est jamais un préfixe de masquage.
    return sorted(chemins)


def main() -> int:
    errs = []
    suivis = subprocess.run(["git", "ls-files", "collectors/*.sh", "systemd/plume-*.service",
                             "bootstrap-agent.sh"],
                            capture_output=True, text=True, check=True).stdout.split()
    capteurs = [p for p in suivis if p.startswith("collectors/")]
    unites = [p for p in suivis if p.startswith("systemd/")]

    # Le drop-in partagé est celui que l'INSTALLEUR pose — on le lui demande, on ne le devine pas.
    if "bootstrap-agent.sh" not in suivis:
        print("::error::bootstrap-agent.sh introuvable : cette garde ne sait plus quel drop-in "
              "s'applique aux collecteurs, elle refuse de conclure.")
        return 1
    boot = open("bootstrap-agent.sh", encoding="utf-8").read()
    m = re.search(r'COMMON_HARDENING="\$SRC/(\S+?)"', boot)
    if not m:
        print("::error::bootstrap-agent.sh ne définit plus COMMON_HARDENING=\"$SRC/…\" : le drop-in "
              "de durcissement n'est plus localisable. Adaptez cette garde AVANT de la contourner.")
        return 1
    dropin_path = m.group(1)
    dropin = lire_reglages(open(dropin_path, encoding="utf-8").read())

    # --- Jambe 1 : la couverture ANNONCÉE doit être ATTEIGNABLE ------------------------------------
    analyses = 0
    for capteur in capteurs:
        src = open(capteur, encoding="utf-8").read()
        # Critère OBJECTIF d'un capteur qui déclare des chemins : il définit `emit_hash`.
        if not re.search(r"^\s*emit_hash\s*\(\)", src, re.M):
            continue
        nom = capteur.split("/")[-1][:-3]
        unit_path = f"systemd/plume-{nom}.service"
        if unit_path not in unites:
            continue
        annonces = annonces_de(src)
        if len(annonces) < 5:
            errs.append(f"{capteur}: seulement {len(annonces)} chemin(s) annoncé(s) extrait(s) — "
                        f"l'extraction est cassée, cette garde ne vérifierait rien.")
            continue
        analyses += 1
        unit = lire_reglages(open(unit_path, encoding="utf-8").read())
        eff = composer(unit, dropin)
        masques, reexposes = masques_de(eff, errs, f"{unit_path} + {dropin_path}")
        for chemin, directive, origine, prefixe in injoignables(annonces, masques, reexposes):
            errs.append(
                f"{capteur}: le chemin ANNONCÉ `{chemin}` est HORS DE PORTÉE du capteur.\n"
                f"      `{directive}` ({origine}) remplace `{prefixe}` par un répertoire vide : le "
                f"glob ne matchera rien, SANS erreur ni avertissement.\n"
                f"      Deux issues, jamais le silence : rendre le chemin joignable (l'unit possède "
                f"son propre scalaire ; un drop-in partagé ne doit pas l'écraser), ou RETIRER cette "
                f"annonce du capteur ET de docs/DETECTION-CATALOG.md.")
        # Le témoin RUNTIME doit exister : la CI ne voit que les fichiers du dépôt, alors que le
        # bac à sable réel est décidé à l'installation par l'exploitant (il peut poser son propre
        # drop-in). Sans aveu à l'exécution, ce cas-là redeviendrait muet.
        if "plume_report_availability" not in src:
            errs.append(f"{capteur}: aucun aveu à l'exécution. Un exploitant peut resserrer le bac à "
                        f"sable après l'installation, hors de portée de cette garde : le capteur doit "
                        f"alors le DIRE (plume_report_availability … missing-source …), pas rendre "
                        f"une baseline amputée en silence.")

    if analyses < 1:
        errs.append("aucun capteur déclarant des chemins (`emit_hash`) n'a été analysé : soit la "
                    "découverte est cassée — cette garde ne vérifierait alors RIEN —, soit le FIM a "
                    "disparu du dépôt.")

    # --- Jambe 2 : chaque unit possède son propre ProtectHome= --------------------------------------
    # `ProtectHome=` a été retiré du drop-in partagé parce qu'un scalaire de drop-in ÉCRASE la valeur
    # délibérée d'une unit. Ce retrait ne relâche rien tant que chaque unit déclare la sienne.
    if "ProtectHome" in dropin:
        errs.append(f"{dropin_path}: `ProtectHome=` est de retour dans le drop-in PARTAGÉ. C'est un "
                    f"SCALAIRE : il écrase la valeur que chaque unit pose délibérément (last-wins), "
                    f"et c'est ainsi que la famille `authkeys` du FIM avait disparu en silence. "
                    f"Posez la valeur dans l'unit concernée.")
    for unit_path in unites:
        if "ProtectHome" not in lire_reglages(open(unit_path, encoding="utf-8").read()):
            errs.append(f"{unit_path}: ne déclare pas `ProtectHome=`. Le drop-in partagé ne le pose "
                        f"plus pour personne : sans cette ligne, cette unit tourne SANS protection "
                        f"des répertoires personnels.")

    # --- Validation de l'INSTRUMENT : témoin positif ET témoin négatif ------------------------------
    # On rejoue la décision sur des bacs à sable synthétiques, avec la VRAIE liste annoncée.
    temoins = []
    for capteur in capteurs:
        src = open(capteur, encoding="utf-8").read()
        if not re.search(r"^\s*emit_hash\s*\(\)", src, re.M):
            continue
        annonces = annonces_de(src)
        for valeur, doit_masquer in (("yes", True), ("read-only", False)):
            faux = lire_reglages(f"[Service]\nProtectHome={valeur}\n")
            mq, rx = masques_de(composer(faux, {}), [], "<témoin>")
            masque = bool(injoignables(annonces, mq, rx))
            temoins.append((capteur, valeur, masque))
            if masque is not doit_masquer:
                errs.append(
                    f"INSTRUMENT INVALIDE ({capteur}) : sous `ProtectHome={valeur}` la garde conclut "
                    f"« {'des chemins masqués' if masque else 'aucun chemin masqué'} », attendu le "
                    f"contraire. Le témoin {'positif' if doit_masquer else 'négatif'} ne passe plus — "
                    f"soit l'extraction des chemins annoncés est cassée, soit la table MASQUAGE l'est. "
                    f"Cette garde refuse de rendre vert dans cet état.")

    if errs:
        for e in errs:
            print(f"::error::{e}")
        print(f"\n{len(errs)} écart(s) entre la couverture ANNONCÉE et la couverture ATTEIGNABLE.")
        return 1
    print(f"{analyses} capteur(s) à chemins analysé(s), {len(unites)} unit(s) vérifiée(s) : tout "
          f"chemin annoncé est atteignable sous le bac à sable effectif, et chaque unit possède son "
          f"ProtectHome=. Témoins de l'instrument : {len(temoins)} (positif + négatif par capteur).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
