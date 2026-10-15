#!/usr/bin/env python3
"""Le collecteur Windows ne peut ni MENTIR ni OUBLIER — garde de CI.

DEUX DÉFAUTS MESURÉS QUE CETTE GARDE REND NON-ÉCRIVABLES
--------------------------------------------------------
Mesuré le 2026-08-02, harnais pwsh exécutant `collectors/windows/plume-collector.ps1` TEL QUEL
(journal Windows et central simulés ; les cmdlets Windows n'existent pas sous Linux) :

  (1) PERTE DÉFINITIVE ET SILENCIEUSE. `Flush-Events` attrapait l'échec du POST, écrivait un
      `Write-Warning` (qui ne va NULLE PART sous tâche planifiée), puis vidait le tampon
      INCONDITIONNELLEMENT — et `Set-Watermark` avait DÉJÀ avancé le filigrane. Central
      indisponible pendant UN run : 42 événements éligibles -> 0 arrivés -> **42 perdus, 0
      rattrapé** au rétablissement. Même harnais, central disponible : 0 perdu / 42 arrivés.
      Second chemin, même cause : dépôt WMI cassé -> le run mourait sur
      `(Get-CimInstance …).Caption` APRÈS l'écriture du filigrane et AVANT le POST final —
      12 collectés, 0 POST tenté, 12 perdus.
  (2) CÉCITÉ MUETTE. Journal `Security` en ACCÈS REFUSÉ (le technicien qui lance le script hors
      SYSTEM) : 12 événements attendus, **0 arrivé, 0 aveu**, code de retour 0, et le battement
      de santé annonçait « plume windows collector ok ». Vu du SOC, rien ne distinguait
      « capteur aveugle » de « rien ne s'est passé » — le défaut que
      `check_collector_exit_is_classified.py` rend impossible côté shell, et dont ce fichier-ci
      était HORS PÉRIMÈTRE (cette garde-là ne balaie que `collectors/*.sh`).

CE NE SONT PAS DES LISTES DE SITES — CE SONT DEUX PARTITIONS FERMÉES
--------------------------------------------------------------------
* HONNÊTETÉ. En PowerShell, la seule façon de transformer « impossible » en silence est de
  SUPPRIMER une erreur : un `catch` qui n'en fait rien, ou `-ErrorAction SilentlyContinue|Ignore`.
  On exige donc : tout `catch` CLASSE (une des trois primitives, miroir de `collectors/lib.sh`)
  ou RELÈVE ; et aucune suppression muette n'est recevable. Un capteur ajouté demain est couvert
  par construction : son auteur ne peut pas avaler une erreur sans choisir un cas.
* DURABILITÉ. Deux gestes seulement sont IRRÉVERSIBLES : oublier le tampon, et avancer le
  filigrane. Le second est le seul qui rende la perte définitive (le journal Windows EST le
  spool tant que le filigrane ne bouge pas). On exige donc que le filigrane s'écrive à UN SEUL
  endroit, APRÈS un envoi acquitté : un chemin d'écriture ajouté demain ne peut pas contourner
  le point de commit, parce que le CONSTRUCTEUR de chemin d'état est unique.

PÉRIMÈTRE, ET POURQUOI L'EXEMPTION NE PEUT PAS POURRIR
-------------------------------------------------------
La garde balaie TOUS les `collectors/windows/*.ps1` suivis (plancher : 1). Les règles de
DURABILITÉ ne s'appliquent qu'aux fichiers qui PERSISTENT une progression (un littéral de chemin
d'état : .watermark/.cursor/.state/.bookmark). Un fichier qui n'en persiste aucune n'a rien à
oublier — et cette exemption est AUTO-INVALIDANTE : le jour où il en persiste une, il retombe
sous la règle sans que personne n'ait à y penser.

POURQUOI L'AST ET PAS UNE REGEX — et pourquoi la garde ÉCHOUE quand elle ne peut pas conclure
----------------------------------------------------------------------------------------------
Les faits sont extraits par LE PARSEUR DE POWERSHELL lui-même (`windows_collector_ast.ps1`) :
une regex confondrait un `catch` avec le mot « catch » d'un commentaire français et ne saurait
pas dire dans quelle fonction se trouve une commande. Si `pwsh` est absent, ou si le fichier ne
parse pas, cette garde ÉCHOUE au lieu de passer : un contrôle qui se tait quand il ne sait pas
est exactement le défaut qu'on ferme ici. (`pwsh` est fourni par l'image `ubuntu-24.04` des
runners GitHub ; en local : https://github.com/PowerShell/PowerShell/releases.)

TROISIÈME PROPRIÉTÉ, JOUÉE ET NON LUE : LE CLAIR NE PART PAS VERS UN HÔTE DISTANT (P10.33-i)
------------------------------------------------------------------------------------------
Le collecteur envoyait `Authorization: Bearer <jeton>` et les événements à `$Central/api/ingest`
sans regarder le schéma : `http://` vers un central distant partait en clair. La porte est celle des
capteurs shell (`plume_verifier_le_transport`, collectors/lib.sh) : `https://` et `http://` vers la
boucle locale (127.0.0.0/8, ::1, localhost) admis ; tout autre `http://` refusé en code 2 avant toute
lecture, sauf `PLUME_SHIP_ALLOW_PLAINTEXT=1` (env ou plume.conf). Une adresse qui ne commence pas par
`schéma://` est refusée, opt-in ou non : `Invoke-RestMethod` la lirait en relatif, autrement que la
porte (`1http://hote` et `http:\\\\hote` partaient en clair vers un hôte distant, mesuré au proxy témoin).
Cette partie EXÉCUTE `collectors/windows/plume-collector.ps1` TEL QUEL sous `pwsh`, par un harnais
qui ne remplace que ce qui n'existe pas hors Windows ou qui sortirait de la machine :
  · `Invoke-RestMethod` est un CENTRAL SIMULÉ qui COMPTE chaque appel (URL, présence du jeton) ;
    `PLUME_HARNAIS_CENTRAL_EN_PANNE=1` le fait lever, comme un central injoignable ;
  · `Get-WinEvent` compte chaque lecture de journal et ne rend rien ;
  · le lecteur `C:` est un répertoire temporaire : `plume.conf` et les filigranes y vivent vraiment.
Chaque cas ADMIS exige au moins un appel au central, une lecture de journal et un filigrane écrit :
c'est ce qui prouve que les faux sont branchés — sans cela, « 0 appel » dans un cas refusé ne
prouverait rien.

CE QUE LA PARTIE JOUÉE NE TIENT PAS
· Seul `Invoke-RestMethod` est simulé. Un envoi par `Invoke-WebRequest`, `curl` ou une classe .NET
  (`HttpClient`, `WebClient`) échapperait au compte : la garde REFUSE donc un collecteur qui appelle
  une autre commande réseau qu'`Invoke-RestMethod` (liste fermée de commandes, pas des types .NET).
· WINDOWS POWERSHELL 5.1 N'EST EXÉCUTÉ NULLE PART. La tâche planifiée lance `powershell -File`
  (collectors/windows/README.md), c'est-à-dire 5.1 sur .NET Framework ; cette garde joue `pwsh` 7 sous
  Linux (.NET 10). Ni la syntaxe de la porte sous 5.1 (tenue par RELECTURE seulement : ni `??`, ni `?.`,
  ni ternaire, ni `&&`, ni méthode .NET Core seule), ni l'analyse de `[System.Uri]` de .NET Framework, ni
  la façon dont `Invoke-RestMethod` 5.1 lit une URL ne sont jouées ici.
· `http://evil.localhost` est refusé (nom DNS autre que `localhost`) alors que .NET 10 le RÉSOUT en
  boucle locale (sonde 2026-10-15 : `::1,127.0.0.1`, RFC 6761) : sévérité de trop, pas une fuite.
· Une adresse sans schéma vers la boucle locale (`127.0.0.1:7000`) est REFUSÉE ici, alors que la porte
  shell la lit en `http://` comme curl : `Invoke-RestMethod` ne la lit pas ainsi.
· L'hôte jugé est l'hôte NORMALISÉ par `[System.Uri]` : `http://127.1`, `http://0x7f.1`,
  `http://[0:0:0:0:0:0:0:1]` et `http://loopback` (réécrit `localhost` par .NET) sont admis ici et
  refusés par la porte shell, plus stricte sur l'écriture. Tous visent la boucle locale.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Vocabulaire FERMÉ de `reason` — SOURCE UNIQUE, partagée avec la garde des capteurs shell. Le
# collecteur PowerShell doit déclarer EXACTEMENT le même : deux vocabulaires qui dérivent, ce sont
# deux SOC qui ne répondent pas à la même requête.
from check_collector_exit_is_classified import REASONS

HERE = Path(__file__).resolve().parent
AST_DUMPER = HERE / "windows_collector_ast.ps1"

# Miroir PowerShell des trois primitives de `collectors/lib.sh`. Un `catch` doit en appeler une
# (ou relever) : c'est la partition, pas une liste de capteurs.
PRIMITIVES = ("Plume-Unavailable", "Plume-Disabled", "Plume-NoData")
# Fonctions DÉSIGNÉES du protocole de durabilité (comme `plume_unavailable` l'est côté shell).
COMMIT_FN = "Complete-Run"      # seul endroit autorisé à écrire l'état
FLUSH_FN = "Flush-Events"       # envoie le tampon ; LÈVE si le POST n'est pas acquitté
PROOF_VAR = "script:DeliveryFailed"   # preuve de livraison
BUFFER_VAR = "script:Events"          # tampon d'événements
REASONS_VAR = "script:PlumeReasons"   # vocabulaire fermé déclaré côté PowerShell
COLLECT_FN = "Collect-Log"      # collecte générique d'un journal
OUTCOMES_PARAM = "Outcomes"     # table `identifiant -> issue` dont la liste d'ids est DÉRIVÉE

# Cmdlets d'ÉCRITURE de fichier (liste fermée : ce sont les verbes qui persistent).
WRITE_CMDS = {
    "set-content", "add-content", "out-file", "tee-object", "export-csv", "export-clixml",
    "new-item", "copy-item", "move-item", "rename-item", "remove-item", "set-itemproperty",
}
# Suffixes de fichier d'ÉTAT : leur présence est ce qui rend un collecteur « capable d'oublier ».
STATE_SUFFIXES = (".watermark", ".cursor", ".state", ".bookmark")
# Valeurs de -ErrorAction qui AVALENT l'erreur sans que rien ne puisse la classer.
MUTE_ERRORACTIONS = {"silentlycontinue", "ignore"}

MIN_FILES = 1     # plancher : si la découverte casse, cette garde ne vérifierait RIEN.
MIN_CATCHES = 8   # idem : un AST vide passerait joyeusement au vert (mesuré : 14 le 2026-08-02).

# CODES DE SORTIE : 0 conforme · 1 une PROPRIÉTÉ est violée · 2 l'instrument REFUSE DE CONCLURE.
# CORRIGÉ LE 2026-08-29 (`P8.27-h`). Cette garde DISAIT « elle REFUSE DE CONCLURE » et sortait en
# 1, c'est-à-dire par le canal d'une propriété violée : le défaut même que `P7.19-b` a fermé pour
# le banc, ici sur son propre chemin. MESURÉ : 29 des 43 gardes de ce dépôt emploient déjà le
# code 2 pour un instrument indisponible, et un balayage du dépôt le 2026-08-29 n'a trouvé QUE
# CE FICHIER où la formule est suivie d'une sortie en 1 — le chiffre « cinq gardes » qui
# circulait est FAUX, il comptait des occurrences en commentaire ou sur des chemins qui sortent
# bien en 2. Rien ne change pour l'intégration : le pas de `ci.yml` échoue sur tout code non nul,
# et l'intention écrite là-bas (« s'il manquait, la garde ÉCHOUE au lieu de passer ») est tenue.
CODE_INSTRUMENT = 2


def ast_of(path: str) -> dict:
    pwsh = shutil.which("pwsh") or shutil.which("powershell")
    if not pwsh:
        print(
            "::error::`pwsh` INTROUVABLE : cette garde ne peut pas analyser le collecteur "
            "PowerShell, donc elle REFUSE DE CONCLURE (elle ne passe pas au vert). Installer "
            "PowerShell 7 (fourni par l'image ubuntu-24.04 des runners GitHub)."
        )
        sys.exit(CODE_INSTRUMENT)
    p = subprocess.run(
        [pwsh, "-NoProfile", "-NonInteractive", "-File", str(AST_DUMPER), "-Path", path],
        capture_output=True, text=True,
    )
    if p.returncode != 0 or not p.stdout.strip():
        print(f"::error::{path}: extraction AST impossible (rc={p.returncode}) : "
              f"{p.stderr.strip()[:400]} — la garde REFUSE DE CONCLURE.")
        sys.exit(CODE_INSTRUMENT)
    return json.loads(p.stdout)


def quoted(s: str):
    """Chaînes entre quotes d'un fragment de code PowerShell."""
    return re.findall(r"""['"]([^'"]*)['"]""", s)


def check(path: str, errs: list) -> int:
    d = ast_of(path)
    if d["parse_errors"]:
        for e in d["parse_errors"]:
            errs.append(f"{path}: NE PARSE PAS — {e}")
        return 0
    funcs = {f["name"] for f in d["functions"]}
    cmds = d["commands"]

    # ---------- (1) HONNÊTETÉ : tout `catch` classe ou relève ----------
    for c in d["catches"]:
        if any(p in c["calls"] for p in PRIMITIVES) or c["has_throw"]:
            continue
        errs.append(
            f"{path}:{c['line']}: `catch` qui n'AVOUE RIEN — une erreur y devient du silence, et le "
            f"SOC ne peut plus distinguer « capteur aveugle » de « rien à signaler ». Choisissez le "
            f"cas :\n"
            f"        prérequis absent / source illisible .. Plume-Unavailable <source> <reason> \"<détail>\"\n"
            f"        coupé par l'opérateur ................ Plume-Disabled <source> \"<détail>\"\n"
            f"        rien de neuf (silence légitime) ...... Plume-NoData <source>\n"
            f"      ou relevez (`throw`) si l'échec doit arrêter le run."
        )
    if len(d["catches"]) < MIN_CATCHES:
        errs.append(
            f"{path}: seulement {len(d['catches'])} `catch` vus (plancher {MIN_CATCHES}) : soit "
            f"l'extraction AST a décroché — cette garde ne vérifierait alors RIEN — soit le fichier a "
            f"vraiment fondu ; dans ce cas baissez MIN_CATCHES depuis votre propre compte."
        )

    # ---------- (2) HONNÊTETÉ : aucune suppression d'erreur muette ----------
    for s in d["silencers"]:
        if s["value"].strip("'\"").lower() in MUTE_ERRORACTIONS:
            errs.append(
                f"{path}:{s['line']}: `-ErrorAction {s['value']}` sur `{s['cmd']}` — l'erreur est avalée "
                f"AVANT tout `catch`, donc AUCUNE classification n'est possible. Utilisez "
                f"`-ErrorAction Stop` dans un `try` dont le `catch` classe."
            )

    # ---------- (3) COUPLAGE : une primitive appelée doit être DÉFINIE ----------
    called = {n for c in cmds for n in [c["name"]] if n in PRIMITIVES}
    for p in sorted(called - funcs):
        errs.append(
            f"{path}: appelle `{p}` qui n'est DÉFINIE nulle part dans le fichier — « commande "
            f"introuvable » à l'exécution : on remplacerait un capteur muet par un capteur cassé."
        )

    # ---------- (4) VOCABULAIRE : le même des deux côtés ----------
    decl = [a for a in d["assignments"] if a["left"] == REASONS_VAR]
    if called:
        if not decl:
            errs.append(
                f"{path}: le vocabulaire fermé `${REASONS_VAR}` n'est pas déclaré : `reason` "
                f"redeviendrait de la prose libre, et `search reason=…` ne rendrait plus rien."
            )
        else:
            got = set(quoted(decl[0]["right"]))
            if got != set(REASONS):
                errs.append(
                    f"{path}:{decl[0]['line']}: vocabulaire `reason` DIVERGENT de celui des capteurs "
                    f"shell (source unique : REASONS de check_collector_exit_is_classified.py). "
                    f"En trop : {sorted(got - set(REASONS))} · manquants : {sorted(set(REASONS) - got)}"
                )

    # ---------- (5) VISIBILITÉ : l'aveu doit être celui que la règle de détection interroge ----------
    # Émettre ne suffit pas à VOIR (leçon mesurée côté shell : un aveu RAFRAÎCHIT même la source).
    # La règle livrée `de-collector-unavailable.json` interroge `category=config collect_status=…`.
    if called and not any(
        c["name"] == "Add-Event" and "collect_status" in c["text"] and "-Category 'config'" in c["text"]
        for c in cmds
    ):
        errs.append(
            f"{path}: les aveux d'indisponibilité ne portent pas `-Category 'config'` + `collect_status` "
            f"— la règle livrée `config.d/rules/catalog/de-collector-unavailable.json` "
            f"(`search category=config collect_status=unavailable`) ne les verrait pas : le capteur "
            f"avouerait dans le vide."
        )

    # ---------- (5bis) ISSUE : on ne collecte pas un identifiant sans dire ce qu'il vaut ----------
    # `fields.action` est l'OUTCOME normalisé du CIM — l'axe sur lequel composent les détections
    # cross-source. MESURÉ le 2026-08-02 : trois échecs d'ouverture de session Windows (4625) en base,
    # et `search category=auth action=failure` en comptait ZÉRO, tandis que les DEUX règles de
    # brute-force livrées (T1110, activées) sont exactement cette requête. La cause tenait à la
    # SIGNATURE : `Collect-Log -Ids @(…)` laissait déclarer QUOI collecter sans jamais dire QUELLE
    # ISSUE l'enregistrement porte. On exige donc que la liste d'identifiants soit DÉRIVÉE d'une table
    # d'issues : un identifiant ajouté demain arrive avec son issue, ou il n'arrive pas.
    for c in cmds:
        if c["name"] != COLLECT_FN:
            continue
        if "-Ids" in c["text"]:
            errs.append(
                f"{path}:{c['line']}: `{COLLECT_FN} -Ids …` — une liste d'identifiants NUE dit QUOI "
                f"collecter sans jamais dire QUELLE ISSUE l'enregistrement porte, et `fields.action` "
                f"reste vide : l'événement est stocké et RESTE INVISIBLE aux règles qui interrogent "
                f"`action=…` (mesuré : 0 échec Windows vu par `category=auth action=failure`). "
                f"Passez `-{OUTCOMES_PARAM} @{{ <id> = '<issue>' }}` — la liste d'identifiants en est dérivée."
            )
        elif f"-{OUTCOMES_PARAM}" not in c["text"]:
            errs.append(
                f"{path}:{c['line']}: `{COLLECT_FN}` appelé sans `-{OUTCOMES_PARAM}` : les événements "
                f"collectés partiraient sans outcome CIM, donc invisibles aux détections `action=…`."
            )
    if not any(c["name"] == COLLECT_FN for c in cmds) and COLLECT_FN in funcs:
        errs.append(
            f"{path}: `{COLLECT_FN}` est défini mais jamais appelé — soit l'extraction AST a décroché "
            f"(la règle des issues ne vérifierait alors RIEN), soit la collecte de journaux a disparu."
        )

    # ---------- (6) DURABILITÉ — seulement si ce fichier PERSISTE une progression ----------
    # Un littéral de CHEMIN d'état se TERMINE par son extension. Le test a d'abord été « le suffixe
    # apparaît quelque part », et il prenait `"$($_.State)"` (l'état d'une connexion TCP) pour un
    # fichier d'état : la garde rougissait sur un faux. Mesuré, corrigé, et gardé écrit — un
    # discriminant trop large, ici, ne se voit qu'au premier faux positif.
    state_lits = [s for s in d["strings"]
                  if s["value"].strip("'\"").lower().endswith(STATE_SUFFIXES)]
    # SECONDE JAMBE : un fichier qui NOMME une progression (fonction …Watermark/Cursor/Bookmark) en
    # persiste une, littéral repéré ou non. Sans elle, obscurcir le nom du fichier d'état suffirait à
    # s'exempter des règles de durabilité — l'exemption doit être un CONSTAT, pas un choix d'écriture.
    names_progress = [f["name"] for f in d["functions"]
                      if re.search(r"(?i)watermark|cursor|bookmark", f["name"])]
    if not state_lits:
        if names_progress:
            errs.append(
                f"{path}: le fichier manipule une progression ({names_progress}) mais AUCUN littéral de "
                f"chemin d'état n'a été repéré : l'analyse a décroché, donc les règles de durabilité ne "
                f"vérifieraient RIEN. Nommer le fichier d'état par un littéral se terminant par "
                f"{list(STATE_SUFFIXES)}."
            )
        return len(d["catches"])   # rien à oublier : exemption AUTO-INVALIDANTE (vérifiée ici même)

    builders = {s["enclosing"] for s in state_lits}
    if len(builders) != 1 or "" in builders:
        errs.append(
            f"{path}: le chemin du fichier d'état est fabriqué à {len(builders)} endroits "
            f"({sorted(builders)}) au lieu d'UN SEUL constructeur. Tant qu'il y en a plusieurs, un "
            f"futur capteur peut écrire sa progression sans passer par le point de commit."
        )
        return len(d["catches"])
    builder = builders.pop()

    writes = [c for c in cmds if c["name"].lower() in WRITE_CMDS and builder in c["text"]]
    if not writes:
        errs.append(
            f"{path}: AUCUNE écriture d'état trouvée alors que le fichier déclare un chemin d'état "
            f"(via `{builder}`) : soit l'analyse a décroché, soit le filigrane n'est plus persisté du "
            f"tout (le collecteur réexpédierait tout à chaque run). Dans les deux cas, mesurez."
        )
    for w in writes:
        if w["enclosing"] != COMMIT_FN:
            errs.append(
                f"{path}:{w['line']}: écriture d'état HORS de `{COMMIT_FN}` (dans "
                f"`{w['enclosing'] or '<script>'}`). C'est LE geste irréversible : écrit avant la preuve "
                f"de livraison, il transforme une indisponibilité du central en PERTE DÉFINITIVE "
                f"(mesuré : 42/42). Mettez le filigrane en attente (`Stage-Watermark`) ; `{COMMIT_FN}` "
                f"le commettra une fois le POST acquitté."
            )

    body_vars = {v["name"] for v in d["variables"] if v["enclosing"] == COMMIT_FN}
    if PROOF_VAR not in body_vars:
        errs.append(
            f"{path}: `{COMMIT_FN}` ne consulte plus `${PROOF_VAR}` : il commettrait le filigrane "
            f"même quand le central n'a rien acquitté. C'est exactement le défaut d'origine."
        )
    # ORDRE : livrer PUIS oublier. L'ordre est interne à la fonction pour qu'aucun appelant ne
    # puisse l'inverser ; on vérifie qu'il n'a pas été inversé DANS la fonction.
    flush_offsets = [c["offset"] for c in cmds if c["enclosing"] == COMMIT_FN and c["name"] == FLUSH_FN]
    commit_writes = [w["offset"] for w in writes if w["enclosing"] == COMMIT_FN]
    if not flush_offsets:
        errs.append(f"{path}: `{COMMIT_FN}` n'appelle plus `{FLUSH_FN}` : il oublierait des événements JAMAIS envoyés.")
    elif commit_writes and min(flush_offsets) > min(commit_writes):
        errs.append(
            f"{path}: dans `{COMMIT_FN}`, l'écriture du filigrane précède l'envoi `{FLUSH_FN}` — "
            f"on oublierait avant d'avoir livré."
        )

    # ---------- (7) La preuve de livraison est bien POSÉE par l'échec d'envoi ----------
    if not any(a["left"] == PROOF_VAR and a["enclosing"] == FLUSH_FN and "true" in a["right"].lower()
               for a in d["assignments"]):
        errs.append(
            f"{path}: `{FLUSH_FN}` ne pose plus `${PROOF_VAR} = $true` quand le POST échoue — la preuve "
            f"de livraison est toujours « vraie », donc le garde-fou de `{COMMIT_FN}` ne mord plus."
        )

    # ---------- (8) Le tampon reste PRIVÉ à ses deux opérations ----------
    decl_lines = {a["line"] for a in d["assignments"] if a["left"] == BUFFER_VAR}
    for v in d["variables"]:
        if v["name"] != BUFFER_VAR:
            continue
        if v["enclosing"] in ("Add-Event", FLUSH_FN):
            continue
        if v["enclosing"] == "" and v["line"] in decl_lines:
            continue
        errs.append(
            f"{path}:{v['line']}: `${BUFFER_VAR}` manipulé hors de `Add-Event`/`{FLUSH_FN}` "
            f"(dans `{v['enclosing'] or '<script>'}`) — vider le tampon ailleurs, c'est réintroduire "
            f"l'oubli d'événements non livrés."
        )
    return len(d["catches"])


# =================================================================================================
# P10.33-i — LA PORTE DU TRANSPORT, JOUÉE SUR LE COLLECTEUR TEL QUEL
# =================================================================================================
COLLECTOR = "collectors/windows/plume-collector.ps1"
# Commandes réseau : le harnais ne compte que la première. Toute autre, présente dans le collecteur,
# rendrait le compte d'appels AVEUGLE — la garde le refuse au lieu de compter faux.
NET_CMD_COUNTED = "invoke-restmethod"
NET_CMDS = {"invoke-restmethod", "irm", "invoke-webrequest", "iwr", "curl", "wget", "curl.exe",
            "wget.exe", "start-bitstransfer", "send-mailmessage"}

HARNAIS_PS1 = r"""
param([Parameter(Mandatory)][string]$Collecteur, [Parameter(Mandatory)][string]$Racine)
$ErrorActionPreference = 'Stop'
# Le lecteur C: du collecteur (plume.conf, répertoire d'état) est un répertoire temporaire.
New-PSDrive -Name C -PSProvider FileSystem -Root $Racine -Scope Global | Out-Null
# CENTRAL SIMULÉ : compte chaque appel. Mêmes paramètres que l'appel du collecteur ; lève en panne.
function global:Invoke-RestMethod {
  [CmdletBinding()]
  param([Parameter(Mandatory)][uri]$Uri, [string]$Method, [int]$TimeoutSec, [hashtable]$Headers,
        [string]$ContentType, $Body)
  $jeton = 'sans-jeton'
  if ($Headers -and $Headers.ContainsKey('Authorization')) { $jeton = 'bearer' }
  Add-Content -LiteralPath $env:PLUME_HARNAIS_JOURNAL -Value "APPEL $($Uri.AbsoluteUri) $jeton"
  if ($env:PLUME_HARNAIS_CENTRAL_EN_PANNE -eq '1') {
    throw [System.Net.Http.HttpRequestException]::new('central simule injoignable')
  }
}
# JOURNAL WINDOWS SIMULÉ : compte chaque lecture, ne rend rien.
function global:Get-WinEvent {
  [CmdletBinding()]
  param([hashtable]$FilterHashtable, [int]$MaxEvents)
  Add-Content -LiteralPath $env:PLUME_HARNAIS_JOURNAL -Value "LECTURE $($FilterHashtable.LogName)"
}
$global:LASTEXITCODE = 0
& $Collecteur
exit $LASTEXITCODE
"""

# (nom, PLUME_CENTRAL en env (None = absent), env en plus, lignes de plume.conf, verdict attendu, texte exigé
#  sur stderr, motifs regex interdits sur stdout et stderr). Verdicts : 'refus' (code 2, 0 appel, 0 lecture, aucun état),
# 'admis' (code 0, >= 1 appel au central annoncé, >= 1 lecture, filigranes écrits), 'panne' (code 1).
CENTRAL_DISTANT = "http://central.example.org:8080"
SANS_SCHEMA = "schema suivi de ://"
# Motifs (regex) interdits sur stdout et stderr : l'identifiant `jeton` et le mot de passe de l'URL.
# « jeton » est aussi un mot des messages (« jeton et evenements lisibles ») : seule cette phrase est admise.
IDENTITE_IMPRIMEE = (r"motdepasse-temoin", r"jeton(?! et evenements lisibles)")
TRANSPORT_CASES = [
    ("http distant", CENTRAL_DISTANT, {}, [], "refus", "PLUME_SHIP_ALLOW_PLAINTEXT=1", None),
    ("http distant, opt-in a 0", CENTRAL_DISTANT, {"PLUME_SHIP_ALLOW_PLAINTEXT": "0"}, [], "refus",
     "EN CLAIR", None),
    ("sans schema, distant", "central.example.org:8080", {}, [], "refus", SANS_SCHEMA, None),
    # `Invoke-RestMethod` lit ces trois-là en RELATIF : `http:\\hote` partait vers `http://hote`,
    # `1http://hote` vers `http://1http//hote` (mesuré au proxy témoin). Refusés AVANT `[System.Uri]`.
    ("sans schema, boucle locale", "127.0.0.1:7000", {}, [], "refus", SANS_SCHEMA, None),
    ("http:\\\\ (barres inverses), distant", "http:\\\\central.example.org", {}, [], "refus", SANS_SCHEMA,
     None),
    ("1http:// (schema illisible), meme avec l'opt-in", "1http://central.example.org",
     {"PLUME_SHIP_ALLOW_PLAINTEXT": "1"}, [], "refus", SANS_SCHEMA, None),
    # Commence par `http://` mais `[System.Uri]` ne la lit pas en absolu : branche « illisible ».
    ("illisible en absolu (http:///hote)", "http:///central.example.org", {}, [], "refus", "illisible",
     None),
    ("http distant par IPv4 (RFC 5737)", "http://192.0.2.10:7000", {}, [], "refus", "'192.0.2.10'", None),
    # Un nom qui FINIT par `localhost` n'est pas `localhost` (comparaison exacte, pas un suffixe).
    ("nom finissant par localhost", "http://notlocalhost:7000", {}, [], "refus", "'notlocalhost'", None),
    ("piege : 127.0.0.1 en prefixe d'un nom", "http://127.0.0.1.example.org:7000", {}, [], "refus",
     "127.0.0.1.example.org", None),
    ("piege : localhost en prefixe d'un nom", "http://localhost.example.org:7000", {}, [], "refus",
     "localhost.example.org", None),
    ("piege : 127.0.0.1 en identite", "http://127.0.0.1@example.org:7000", {}, [], "refus",
     "'example.org'", None),
    ("identite dans l'URL, jamais imprimee", "http://jeton:motdepasse-temoin@central.example.org", {},
     [], "refus", "EN CLAIR", IDENTITE_IMPRIMEE),
    ("opt-in + identite dans l'URL, jamais imprimee", "http://jeton:motdepasse-temoin@central.example.org",
     {"PLUME_SHIP_ALLOW_PLAINTEXT": "1"}, [], "admis", "AVERTISSEMENT", IDENTITE_IMPRIMEE),
    # `::ffff:127.0.0.1` n'est pas `::1` : refusé, comme par la porte shell. C'est ce cas qui interdit
    # `[System.Uri]::IsLoopback`, qui le dit en boucle locale.
    ("IPv6 a IPv4 projete, hors ::1", "http://[::ffff:127.0.0.1]:7000", {}, [], "refus", "EN CLAIR", None),
    ("autre schema, meme avec l'opt-in", "ftp://central.example.org", {"PLUME_SHIP_ALLOW_PLAINTEXT": "1"},
     [], "refus", "non pris en charge", None),
    ("http distant + opt-in (env)", CENTRAL_DISTANT, {"PLUME_SHIP_ALLOW_PLAINTEXT": "1"}, [], "admis",
     "AVERTISSEMENT", None),
    ("http distant + opt-in (plume.conf, central et jeton par l'env)", CENTRAL_DISTANT, {},
     ["PLUME_SHIP_ALLOW_PLAINTEXT=1"], "admis", "AVERTISSEMENT", None),
    ("http distant + opt-in, tout par plume.conf", None, {},
     [f"PLUME_CENTRAL={CENTRAL_DISTANT}", "PLUME_TOKEN=jeton-temoin", "PLUME_SHIP_ALLOW_PLAINTEXT=1"],
     "admis", "AVERTISSEMENT", None),
    ("https distant", "https://central.example.org", {}, [], "admis", None, None),
    ("http boucle 127.0.0.1", "http://127.0.0.1:7000", {}, [], "admis", None, None),
    ("http boucle 127.0.0.0/8", "http://127.10.20.30:7000", {}, [], "admis", None, None),
    ("http boucle localhost", "http://localhost:7000", {}, [], "admis", None, None),
    ("http boucle [::1]", "http://[::1]:7000", {}, [], "admis", None, None),
    ("central en panne (distinct d'un refus)", "https://central.example.org",
     {"PLUME_HARNAIS_CENTRAL_EN_PANNE": "1"}, [], "panne", None, None),
]


def jouer_le_transport(errs: list) -> int:
    """Joue chaque cas sur le collecteur tel quel ; rend le nombre de cas joués."""
    pwsh = shutil.which("pwsh") or shutil.which("powershell")
    if not pwsh:   # ast_of() a déjà refusé de conclure avant d'arriver ici
        sys.exit(CODE_INSTRUMENT)
    # Le compte d'appels n'a de sens que si le seul transport du collecteur est celui qu'on simule.
    d = ast_of(COLLECTOR)
    autres = sorted({c["name"] for c in d["commands"]
                     if c["name"].lower() in NET_CMDS and c["name"].lower() != NET_CMD_COUNTED})
    if autres:
        errs.append(
            f"{COLLECTOR}: commande(s) réseau {autres} hors du central simulé (`Invoke-RestMethod`) : "
            f"le compte d'appels du harnais serait aveugle à cet envoi. Envoyez par "
            f"`Invoke-RestMethod`, ou étendez le harnais AVANT d'ajouter un transport."
        )
        return 0
    collecteur = str(Path(COLLECTOR).resolve())
    joues = 0
    with tempfile.TemporaryDirectory(prefix="plume-harnais-windows-") as base:
        harnais = Path(base) / "harnais.ps1"
        harnais.write_text(HARNAIS_PS1, encoding="utf-8")
        for i, (nom, central, env_plus, conf, attendu, exige, interdit) in enumerate(TRANSPORT_CASES):
            racine = Path(base) / f"cas{i}"
            (racine / "ProgramData" / "plume").mkdir(parents=True)
            journal = Path(base) / f"journal{i}.txt"
            journal.write_text("", encoding="utf-8")
            if conf:
                (racine / "ProgramData" / "plume" / "plume.conf").write_text(
                    "\n".join(conf) + "\n", encoding="utf-8")
            env = {k: v for k, v in os.environ.items()
                   if not k.startswith("PLUME_") and k != "COMPUTERNAME"}
            env.update({"COMPUTERNAME": "HARNAIS", "PLUME_HARNAIS_JOURNAL": str(journal)})
            if central is not None:
                env["PLUME_CENTRAL"] = central
                env["PLUME_TOKEN"] = "jeton-temoin"
            env.update(env_plus)
            try:
                p = subprocess.run(
                    [pwsh, "-NoProfile", "-NonInteractive", "-File", str(harnais),
                     "-Collecteur", collecteur, "-Racine", str(racine)],
                    capture_output=True, text=True, env=env, cwd=base, timeout=120,
                )
            except subprocess.TimeoutExpired:
                print(f"::error::cas « {nom} » : pwsh n'a pas rendu la main en 120 s — la garde "
                      f"REFUSE DE CONCLURE.")
                sys.exit(CODE_INSTRUMENT)
            joues += 1
            lignes = journal.read_text(encoding="utf-8").splitlines()
            appels = [ln for ln in lignes if ln.startswith("APPEL ")]
            lectures = [ln for ln in lignes if ln.startswith("LECTURE ")]
            etat = racine / "ProgramData" / "plume" / "state"
            filigranes = sorted(etat.glob("*.watermark")) if etat.is_dir() else []
            vu = (f"code {p.returncode}, {len(appels)} appel(s) au central, {len(lectures)} lecture(s) "
                  f"de journal, {len(filigranes)} filigrane(s), etat {'cree' if etat.exists() else 'absent'}"
                  f" ; stderr : {p.stderr.strip()[:300]!r}")
            defauts = []
            if attendu == "refus":
                if p.returncode != 2:
                    defauts.append("code de sortie 2 attendu (refus de transport)")
                if appels:
                    defauts.append("AUCUN appel au central attendu — le jeton est parti en clair")
                if lectures:
                    defauts.append("AUCUNE lecture de journal attendue : le refus doit tomber avant la collecte")
                if etat.exists():
                    defauts.append("aucun répertoire d'état attendu : rien ne doit avancer")
                if "REFUS" not in p.stderr:
                    defauts.append("refus NOMMÉ attendu sur stderr")
            elif attendu == "admis":
                if p.returncode != 0:
                    defauts.append("code 0 attendu (transport admis)")
                central_vu = central or CENTRAL_DISTANT
                if not appels:
                    defauts.append("au moins un appel au central attendu (le central simulé est-il branché ?)")
                elif any(not a.startswith(f"APPEL {central_vu.rstrip('/')}/api/ingest ") for a in appels):
                    defauts.append(f"appels attendus vers {central_vu}/api/ingest seulement")
                if any(not a.endswith(" bearer") for a in appels):
                    defauts.append("chaque appel doit porter le jeton")
                if not lectures:
                    defauts.append("au moins une lecture de journal attendue (le faux Get-WinEvent est-il branché ?)")
                if not filigranes:
                    defauts.append("des filigranes commis attendus après un envoi acquitté")
            else:   # panne
                if p.returncode != 1:
                    defauts.append("code 1 attendu (panne du central), DISTINCT du code 2 d'un refus")
                if not appels:
                    defauts.append("un appel (en échec) au central attendu")
                if filigranes:
                    defauts.append("aucun filigrane ne doit être commis quand le POST a échoué")
            if exige and exige not in p.stderr:
                defauts.append(f"stderr doit contenir {exige!r}")
            for motif in interdit or ():
                if re.search(motif, p.stderr) or re.search(motif, p.stdout):
                    defauts.append(f"motif {motif!r} imprimé : l'identité de l'URL ne doit jamais s'imprimer")
            for df in defauts:
                errs.append(f"{COLLECTOR}: transport, cas « {nom} » ({central or 'plume.conf'}) : {df}. VU : {vu}")
            print(f"  transport · {nom:<62} {'OK' if not defauts else 'ROUGE'} · {vu[:110]}")
    return joues


def main() -> int:
    files = subprocess.run(
        ["git", "ls-files", "collectors/windows/*.ps1"], capture_output=True, text=True, check=True
    ).stdout.split()
    errs: list = []
    total_catches = 0
    for f in files:
        total_catches += check(f, errs)
    joues = 0
    if COLLECTOR in files:
        joues = jouer_le_transport(errs)
    else:
        errs.append(f"{COLLECTOR} introuvable parmi les fichiers suivis : la porte du transport n'est pas jouée.")
    if len(files) < MIN_FILES:
        errs.append(
            f"seulement {len(files)} collecteur(s) PowerShell découvert(s), plancher {MIN_FILES} : la "
            f"découverte est cassée (cette garde ne vérifierait RIEN) ou le collecteur Windows a "
            f"disparu du dépôt."
        )
    if errs:
        for e in errs:
            print(f"::error::{e}")
        print(f"\n{len(errs)} défaut(s) sur {len(files)} collecteur(s) PowerShell.")
        return 1
    print(
        f"{len(files)} collecteur(s) PowerShell, {total_catches} `catch` : toute erreur est classée "
        f"(incapacité / désactivé / rien de neuf) ou relevée, et aucun filigrane ne s'écrit avant un "
        f"envoi acquitté ; {joues} cas de transport joués sur le collecteur tel quel (http distant "
        f"refusé en code 2 sans appel ni lecture, opt-in, https et boucle locale admis)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
