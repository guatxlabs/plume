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
· Seul `Invoke-RestMethod`, écrit NU, est simulé. Tout autre chemin d'envoi rendrait le compte AVEUGLE ;
  la garde le REFUSE donc dans l'AST, sans attendre de l'exécuter (P10.33-i), par des LISTES FERMÉES de
  ce que le collecteur EMPLOIE — pas par une liste de méchants : une première version listait les
  commandes réseau, et le vérificateur du 2026-10-18 a fait passer, écrits en dur dans le source,
  `Microsoft.PowerShell.Utility\\Invoke-WebRequest` (et `…\\Invoke-RestMethod`, qui contourne le central
  simulé), `& 'C:\\…\\curl.exe'`, `Start-Process`, `cmd /c`, `[scriptblock]::Create`,
  `[Activator]::CreateInstance(…GetTypeFromProgID…)`, `([xml]…).Load(url)`, `Invoke-Command
  -ComputerName`, `Set-Content` vers un chemin UNC ; puis celui du 2026-10-19, `ForEach-Object Load 'url'`
  (une connexion est tentée, mesuré), un chemin UNC par `-Path:'…'`, `('…')`, `FileSystem::`, une table
  ou une variable, et `-ComputerName` par splatting. Sont refusés : une commande hors de `CMDS_ADMIS` (nom
  qualifié, chemin et `.exe` compris) ou au nom calculé (`& $x`) ; un paramètre de cmdlet hors de
  `PARAMS_ADMIS`, tel qu'écrit (`-Comp`, abréviation de `-Compress` qui est admis, est refusé) ; par
  `@p`, les clés de la table LITTÉRALE affectée à `$p`, jugées comme des paramètres — une table
  introuvable, calculée, ou dont la variable est lue ou modifiée ailleurs (`$p.ComputerName = …`) est
  refusée ; un type nommé hors de `TYPES_ADMIS` (chaque composant, contrainte `[T]$x` comprise) ; le
  type passé à `New-Object`, littéral ou variable affectée de chaînes littérales seulement (tout autre
  argument de type est refusé comme calculé) ; une méthode appelée hors de `METHODES_ADMISES`, par
  `x.M()`, `[T]::M()` ou comme membre de `ForEach-Object`/`%`/`foreach` (1er argument positionnel ou
  `-MemberName`, nom calculé refusé) ; TOUTE chaîne littérale du script qui commence par `\\\\` ou `//`,
  préfixe de fournisseur `FileSystem::` compris ; un nom `System.Net.*` en chaîne ; `using namespace
  System.Net…`, `using assembly|module`. Le témoin de la garde porte un exemple PAR SITE de refus, et
  par forme. CE QUE L'AST NE TIENT PAS : ce qui n'est pas ÉCRIT dans le source — un nom de type, de
  commande ou de méthode fabriqué à l'exécution et passé à une commande ou une méthode ADMISE (une
  propriété lue sur un objet admis n'est pas jugée), un chemin UNC CALCULÉ (concaténé, lu de la
  configuration) passé à `Set-Content`/`Get-Content`/`Test-Path`, l'usage d'une méthode admise sur un
  autre objet que celui pour lequel elle a été admise ; la portée des variables n'est pas suivie
  (`$p` et `$script:p` sont le même nom pour la garde, ce qui ne peut qu'en refuser plus).
· WINDOWS POWERSHELL 5.1 N'EST EXÉCUTÉ NULLE PART — mais il est désormais JUGÉ (P10.33-i). La tâche
  planifiée lance `powershell -File` (collectors/windows/README.md), c'est-à-dire 5.1 sur .NET
  Framework ; cette garde joue `pwsh` 7 sous Linux (.NET 10). Jambes, chacune avec son témoin :
  (a) PSScriptAnalyzer `PSSA_VERSION` (installé à cette version, nupkg vérifié par `PSSA_SHA256` dans le
      job `shell` de ci.yml) joue `PSUseCompatibleSyntax` (cible 5.1), `PSUseCompatibleCommands` et
      `PSUseCompatibleTypes` contre les trois profils Windows PowerShell 5.1 Desktop qu'il LIVRE
      (`PROFILS_51` : Windows 10 1809, Windows Server 2016 et 2019 — le témoin exige un diagnostic
      nommant CHACUNE des trois plateformes), et `PSUseBOMForUnicodeEncodedFile` ; tout diagnostic
      rougit. Module absent, autre version, profil manquant : REFUS DE CONCLURE (code 2), jamais un vert ;
  (b) l'ENCODAGE DU SOURCE, lu en octets : sans BOM, 5.1 lit un script dans la page de code ANSI.
      Mesuré le 2026-10-18 (vérificateur) : le collecteur était en UTF-8 sans BOM, et lu en cp1252 il
      avait 19 erreurs de parsage — « — » (E2 80 94) y devient « â€" », 0x94 étant un guillemet fermant
      pour PowerShell. La tâche planifiée mourait au parsage, avant la porte du clair, et cette garde
      affichait « compatible ». Tout octet non ASCII exige le BOM UTF-8 ;
  (c) l'AST interdit la syntaxe postérieure à 5.1 (`??`, `??=`, ternaire, `&&`/`||`, `?.`, `?[`, bloc
      `clean`, opérateur d'arrière-plan `… &`, échappements `` `u{…} `` et `` `e `` — lus par paires,
      ``` ``e ``` n'en est pas un —, `-replace` dont le remplacement est un bloc de script ÉCRIT, et la
      lecture de `$IsWindows`/`$IsLinux`/`$IsMacOS`/`$IsCoreCLR`, absents de 5.1) — mesuré le 2026-10-18,
      PSScriptAnalyzer 1.25.0 ne voit ni `${x}?[0]`, ni `Get-Date &`, ni `` `u{…} `` ; un bloc de script
      passé à `-replace` par une variable n'est pas vu ;
  (d) tout type NOMMÉ doit exister dans chacun des trois profils 5.1, le nom étant résolu PAR LES
      PROFILS (types complets et accélérateurs de 5.1) et jamais par pwsh 7, qui résout `[uint]` alors que
      5.1 n'a pas cet accélérateur — mesuré, `PSUseCompatibleTypes` ne voit pas
      `[System.Management.Automation.PSStyle]` (PowerShell 7.2) ;
  (e) tout membre statique `[T]::M` d'un type connu de 5.1 doit exister dans ses profils — mesuré,
      `PSUseCompatibleTypes` ne voit pas `[Math]::Clamp` (.NET Core 2.0).
  Un fichier TÉMOIN fabriqué à chaque passage, sans BOM, passe par le MÊME puits que le collecteur
  (`errs`, d'où il est relu puis retiré) : chaque (jambe, ligne) attendue doit y être, et la ligne
  `[System.Uri]` sur aucune — sinon la garde refuse de conclure. Le verdict imprimé est TIRÉ du bilan de
  ce jugement (comptes, version, profils chargés), pas écrit en dur ; jugement non joué = code 2.
  CE QUE L'ANALYSE STATIQUE NE PROUVE PAS : le COMPORTEMENT de .NET Framework 4.x à l'exécution — la
  normalisation de l'hôte par `[System.Uri]` (la porte juge `Host`/`HostNameType`, que .NET Framework
  peut lire autrement que .NET 10 pour `127.1`, `0x7f.1`, `loopback`), la façon dont
  `Invoke-RestMethod` 5.1 lit une URL (proxy système, négociation TLS par `ServicePointManager`) — les
  REDIRECTIONS, elles, ne sont plus suivies par construction : `-MaximumRedirection 0` est exigé ÉCRIT sur
  chaque `Invoke-RestMethod` (site `envoi:redirection`), et `jouer_la_redirection` joue 301/302/303/307/308
  par le vrai cmdlet sous pwsh 7 ; 5.1 ne lève que sur 301/302 et rend les autres comme une réponse au corps
  vide, que le collecteur refuse d'acquitter (jugement au corps `"queued":true`, joué sous pwsh 7 par un 200
  sans corps ou étranger ; 5.1 lui-même non exécuté), les différences de SÉMANTIQUE d'une cmdlet de même nom et mêmes paramètres
  entre 5.1 et 7 (encodage par défaut de `Set-Content`/`Out-File`, `ConvertTo-Json`) ; une SURCHARGE de
  méthode d'instance absente de .NET Framework (`'abc'.Contains('a', [StringComparison]::Ordinal)` : le
  type de l'objet n'est pas connu statiquement) ; la page de code d'un poste dont l'ANSI n'est pas
  cp1252 (le BOM rend la question sans objet, la jambe (b) l'exige) ; ni rien de ce qu'aucun profil livré
  ne connaît (le plus récent est PowerShell 7.0 : une commande APPARUE après 7.0 et absente de 5.1 n'est
  vue que si l'analyseur la connaît — `Get-Date -AsUTC` l'est, mesuré).
· `http://evil.localhost` est refusé (nom DNS autre que `localhost`) alors que .NET 10 le RÉSOUT en
  boucle locale (sonde 2026-10-15 : `::1,127.0.0.1`, RFC 6761) : sévérité de trop, pas une fuite.
· Une adresse sans schéma vers la boucle locale (`127.0.0.1:7000`) est REFUSÉE ici, alors que la porte
  shell la lit en `http://` comme curl : `Invoke-RestMethod` ne la lit pas ainsi.
· L'hôte jugé est l'hôte NORMALISÉ par `[System.Uri]` : `http://127.1`, `http://0x7f.1`,
  `http://[0:0:0:0:0:0:0:1]` et `http://loopback` (réécrit `localhost` par .NET) sont admis ici et
  refusés par la porte shell, plus stricte sur l'écriture. Tous visent la boucle locale.
QUATRIÈME PROPRIÉTÉ, LUE : LA DOC D'INSTALLATION NE CONTREDIT PAS LE SCRIPT (P10.32-n)
-------------------------------------------------------------------------------------
Le pas à pas Windows (docs/INSTALLER-SANS-OUVRIR-DE-BRECHE.md §2.5 et §3) et le README du collecteur
ont recopié des phrases périmées par les correctifs du script : « ne pose jamais le champ CIM
`action` » (faux depuis la table d'issues de `Collect-Log`), « certificat non reconnu : le lot est
perdu » (faux depuis `Complete-Run`, qui ne commet rien après un envoi raté). Et rien ne tenait
« `PLUME_TLS_INSECURE` n'est pas lue dans plume.conf » : y ajouter un cas laissait tout vert. On
juge donc, hors passages barrés (`~~…~~`, l'historique d'un défaut corrigé) :
  · les clés lues dans plume.conf par le script == les trois clés que la doc annonce ;
  · si le script pose `action`, aucune phrase ne dit qu'il ne la pose jamais ;
  · aucune phrase ne dit qu'un lot est perdu (le journal Windows est le spool) ;
  · chaque doc dit que `PLUME_TOKEN` ne se pose jamais en variable machine (lisible par tout
    utilisateur local), puisqu'elle propose des variables machine pour d'autres réglages.
CE QU'ELLE NE TIENT PAS : c'est une lecture de phrases. Une autre tournure fausse passe ; une clé de
plume.conf lue ailleurs que dans le `switch` de lecture du fichier échappe au relevé.
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
# Le harnais ne compte que `Invoke-RestMethod` écrit NU. Tout autre chemin vers l'extérieur rendrait le
# compte d'appels AVEUGLE : la garde le refuse au lieu de compter faux.
NET_CMD_COUNTED = "invoke-restmethod"
# P10.33-i — CE SONT DES LISTES FERMÉES, PAS DES LISTES DE MÉCHANTS. Une liste de commandes réseau
# (« Invoke-WebRequest, curl, bitsadmin… ») laissait passer, mesuré par le vérificateur du 2026-10-18 :
# `Microsoft.PowerShell.Utility\Invoke-WebRequest` (le nom qualifié n'est pas le nom de la liste — et
# `…\Invoke-RestMethod` contourne en plus le central simulé, donc n'est pas compté), `& 'C:\…\curl.exe'`,
# `Start-Process`, `cmd /c`, `[scriptblock]::Create`, `[Activator]::CreateInstance(…GetTypeFromProgID…)`,
# `([xml]…).Load(url)`, `Invoke-Command -ComputerName`, `Set-Content` vers un chemin UNC. On admet donc
# ce que le collecteur EMPLOIE (relevé le 2026-10-18 sur l'AST), et RIEN D'AUTRE : une commande, un
# paramètre de cmdlet, un type ou une méthode qui n'y est pas est refusé, quel que soit son nom.
# Ajouter une entrée = l'avoir lue : elle ne doit ni envoyer, ni exécuter du code fabriqué, ni ouvrir
# une session distante. Les fonctions DÉFINIES dans le fichier sont admises (leur corps est jugé).
CMDS_ADMIS = {
    "convertto-json", "foreach-object", "get-ciminstance", "get-content", "get-date",
    "get-netfirewallprofile", "get-nettcpconnection", "get-process", "get-winevent", NET_CMD_COUNTED,
    "join-path", "new-item", "new-object", "out-null", "set-content", "set-strictmode", "sort-object",
    "test-path", "where-object",
}
# Paramètres des cmdlets, tels qu'ÉCRITS : `-Comp` (abréviation de `-ComputerName`) n'est pas `-Path`.
# Pas de `-ComputerName`, `-CimSession`, `-Session`, `-ComObject`, `-Proxy`.
PARAMS_ADMIS = {
    "body", "compress", "contenttype", "depth", "erroraction", "filterhashtable", "force", "headers",
    "itemtype", "maximumredirection", "maxevents", "method", "nonewline", "path", "raw", "state",
    "timeoutsec", "uri", "value", "version",
}
# P10.33-i — L'ENVOI NE SUIT AUCUNE REDIRECTION. La porte du transport juge l'adresse ÉCRITE ; une réponse
# 3xx enverrait ailleurs. Mesuré le 2026-10-27 sous pwsh 7.6.3 (cf. `jouer_la_redirection`) : sans
# `-MaximumRedirection 0`, un central admis qui répond 307/308 vers un autre hôte en `http://` y fait
# partir le corps EN CLAIR, et sur 302 le lot est compté livré sans être arrivé. Chaque `Invoke-RestMethod`
# compté doit donc porter ce paramètre ÉCRIT, valeur littérale `0` (variable, autre valeur, splatting
# seul : refusé).
PARAM_REDIRECTION = "maximumredirection"
# Types NOMMÉS (chaque composant d'un nom générique ou tableau), et type passé à `New-Object`. Pas de
# `[scriptblock]`, `[type]`, `[Activator]`, `[powershell]`, `[ipaddress]`, ni rien de `System.Net.*`
# hors des deux réglages TLS (qui n'envoient rien).
TYPES_ADMIS = {
    "bool", "console", "convert", "datetime", "datetimeoffset", "hashtable", "int", "int64", "ordered",
    "pscustomobject", "ref", "string", "system.net.securityprotocoltype", "system.net.servicepointmanager",
    "system.uri", "system.urihostnametype", "system.urikind", "timespan", "xml",
    "system.collections.arraylist",
}
# Méthodes APPELÉES (`x.M()`, `[T]::M()`, et le membre de `ForEach-Object M`). Pas de `Load`, `Create`,
# `Start`, `Invoke`, `InvokeScript`, `CreateInstance`, `GetTypeFromProgID`. Une propriété LUE n'est pas jugée
# (elle n'envoie rien).
METHODES_ADMISES = {
    "add", "addminutes", "clear", "containskey", "new", "parse", "split", "toint64", "tolowerinvariant",
    "tostring", "touniversaltime", "tounixtimeseconds", "toxml", "trim", "trimend", "trycreate",
    "writeline",
}
NET_TYPES_ADMIS = {"System.Net.ServicePointManager", "System.Net.SecurityProtocolType"}
NOM_NET = re.compile(r"(?i)(?<![\w.])(?:system\.net(?!\w)(?:\.[\w.+`]*)?|net\.[\w.+`]+)")
# Chemin UNC : `Set-Content '\\hote\partage\x'` envoie par SMB, sans aucune commande réseau. Jugé sur TOUTE
# chaîne littérale du script (argument, `-Path:'…'`, `('…')`, valeur d'une table, variable), préfixe de
# fournisseur compris (`FileSystem::\\…`, `Microsoft.PowerShell.Core\FileSystem::\\…`).
UNC = re.compile(r"^(?i:(?:[\w.]+\\)?FileSystem::)?(?:\\\\|//)")
# `ForEach-Object Load 'url'` APPELLE la méthode `Load` (mesuré par le vérificateur du 2026-10-19 : une
# connexion est tentée) : le nom de membre de ForEach-Object est jugé comme une méthode appelée.
FOREACH_CMDS = {"foreach-object", "%", "foreach"}


def noms_net(texte: str) -> list:
    """Noms `System.Net.*` NORMALISÉS (préfixe `System.` rétabli) trouvés dans un nom de type ou une chaîne."""
    out = []
    for m in NOM_NET.finditer(texte or ""):
        n = m.group(0).rstrip(".")
        if not n.lower().startswith("system."):
            n = "System." + n
        # « System.Net » seul (espace importé, préfixe concaténé à l'exécution) n'est pas admis non plus.
        out.append("System.Net" + n[len("System.Net"):])
    return out


def net_admis(nom: str) -> bool:
    return nom.lower() in {a.lower() for a in NET_TYPES_ADMIS}


def composants_de_type(nom: str) -> list:
    """`System.Int32[]` -> [system.int32] ; `List[System.Net.WebClient]` -> [list, system.net.webclient]."""
    return [x.lower() for x in re.split(r"[\[\],\s]+", nom or "") if x]


def envois_hors_du_central_simule(d: dict) -> list:
    """(ligne, site, quoi) pour tout ce que le central simulé (`Invoke-RestMethod` nu) ne compterait pas.

    `site` nomme la règle qui a refusé : le témoin de la garde en exige un exemple PAR SITE."""
    fonctions = {f["name"].lower() for f in d["functions"]}
    affectations: dict = {}
    for a in d.get("assignments", []):
        if a.get("cible"):
            affectations.setdefault(a["cible"].lower(), []).append(a)

    def valeurs_ecrites(nom: str, forme: str):
        """Les affectations de `$nom`, si TOUTES sont de la forme écrite demandée et que la variable n'est lue
        nulle part ailleurs qu'où on la juge (sinon : None, la valeur n'est pas lisible dans le source)."""
        aff = affectations.get(nom.lower(), [])
        if not aff or any(a["forme"] != forme for a in aff):
            return None
        gauches = {a["offset_gauche"] for a in aff}
        autres = [v for v in d["variables"] if v.get("nom", "").lower() == nom.lower()
                  and v["offset"] not in gauches and not (forme == "table" and v["splatted"])]
        if forme == "table" and autres:
            return None   # `$p.ComputerName = …`, `$p.Add(…)`, `$p += …` : la table n'est plus celle écrite
        return aff

    vus = []
    for c in d["commands"]:
        n = c["name"].lower()
        # Le membre de ForEach-Object (1er argument positionnel, ou `-MemberName`) est une MÉTHODE APPELÉE.
        # Jugé avant tout `continue` : `%` est aussi refusé comme commande, et les deux le disent.
        if n in FOREACH_CMDS:
            membres = [a for a in c.get("arguments", []) if a["kind"] != "scriptblock"
                       and (a["parametre"] == "" or a["parametre"].lower().startswith("m"))]
            if membres:
                a = membres[0]
                nom = a["valeur"] if a["kind"] == "chaine" else ""
                if nom.lower() not in METHODES_ADMISES:
                    vus.append((c["line"], "membre-foreach",
                                f"`{c['name']} {nom or '<nom calculé>'}` appelle la méthode `{nom or '<nom calculé>'}`, "
                                f"hors de METHODES_ADMISES"))
        if not n:
            vus.append((c["line"], "invocation-dynamique",
                        f"commande au nom CALCULÉ `{c['text'][:60]}` (`& $x`, `& (Get-Command …)`)"))
            continue
        if n in fonctions:
            continue
        if n not in CMDS_ADMIS:
            vus.append((c["line"], "commande", f"commande `{c['name']}` hors de CMDS_ADMIS "
                        f"(un nom qualifié par module, un chemin ou un `.exe` n'est pas le nom admis)"))
            continue
        for prm in c.get("params", []):
            if prm.lower() not in PARAMS_ADMIS:
                vus.append((c["line"], "parametre", f"paramètre `-{prm}` de `{c['name']}` hors de PARAMS_ADMIS"))
        if n == NET_CMD_COUNTED and not any(
                a["parametre"].lower() == PARAM_REDIRECTION and a["kind"] in ("autre", "chaine")
                and a["valeur"].strip() == "0" for a in c.get("arguments", [])):
            vus.append((c["line"], "redirection", f"`{c['name']}` sans `-MaximumRedirection 0` écrit : il suivrait "
                        f"une réponse 3xx vers un hôte que la porte du transport n'a pas jugé (corps en clair, "
                        f"ou lot compté livré sans être arrivé)"))
        # SPLATTING : `@p` vaut les clés de la table LITTÉRALE affectée à `$p`, jugées comme des paramètres.
        # Table introuvable, calculée ou modifiée après coup : refusé (ses paramètres ne sont pas écrits).
        for a in c.get("arguments", []):
            if a["kind"] != "splat":
                continue
            aff = valeurs_ecrites(a["valeur"], "table")
            if aff is None:
                vus.append((c["line"], "splat", f"`{c['name']} @{a['valeur']}` : la table n'est pas une table "
                            f"littérale du script, ou elle est modifiée ou lue ailleurs (paramètres non écrits)"))
                continue
            for cle in sorted({k for x in aff for k in x["cles"]}):
                if not cle or cle.lower() not in PARAMS_ADMIS:
                    vus.append((c["line"], "parametre", f"paramètre `{cle or '<clé calculée>'}` de `{c['name']}` "
                                f"(par `@{a['valeur']}`) hors de PARAMS_ADMIS"))
        if n == "new-object":
            # Le TYPE : `-TypeName`/`-T…` ou positionnel (le 2e positionnel, `-ArgumentList`, est jugé aussi).
            for a in c.get("arguments", []):
                if a["parametre"] and not a["parametre"].lower().startswith("t"):
                    continue
                if a["kind"] == "chaine":
                    noms = [a["valeur"]]
                elif a["kind"] == "variable":
                    aff = valeurs_ecrites(a["valeur"], "chaine")
                    noms = [x["chaine"] for x in aff] if aff is not None else [None]
                else:
                    noms = [None]
                for lit in noms:
                    if lit is None:
                        vus.append((c["line"], "new-object", f"`New-Object` d'un type CALCULÉ "
                                    f"(`{a['valeur'][:40]}`, non affecté d'une seule chaîne littérale)"))
                    elif lit.lower() not in TYPES_ADMIS:
                        vus.append((c["line"], "new-object", f"`New-Object {lit}` : type hors de TYPES_ADMIS"))
    for st in d["strings"]:
        if UNC.match(st.get("valeur", "")):
            vus.append((st["line"], "unc", f"chemin UNC `{st['valeur'][:60]}` écrit dans le source (envoi SMB)"))
    for t in d.get("types", []):
        for comp in composants_de_type(t["written"]):
            if comp not in TYPES_ADMIS:
                vus.append((t["line"], "type", f"type `{comp}` (écrit `[{t['written']}]`) hors de TYPES_ADMIS"))
    for m in d.get("members", []):
        if m["invoked"] and m["member"].lower() not in METHODES_ADMISES:
            vus.append((m["line"], "methode", f"méthode `{m['member'] or '<nom calculé>'}` hors de METHODES_ADMISES"))
    for st in d["strings"]:
        for nom in sorted(n for n in set(noms_net(st["value"].strip("'\""))) if not net_admis(n)):
            vus.append((st["line"], "chaine-net", f"nom de type .NET `{nom}` en chaîne ({st['value'][:60]})"))
    for u in d.get("usings", []):
        if u["kind"].lower() != "namespace" or noms_net(u["text"].split(None, 2)[-1]):
            vus.append((u["line"], "using", f"`{u['text']}` (un nom court deviendrait illisible à l'AST)"))
    return sorted(set(vus))


HARNAIS_PS1 = r"""
param([Parameter(Mandatory)][string]$Collecteur, [Parameter(Mandatory)][string]$Racine)
$ErrorActionPreference = 'Stop'
# Le lecteur C: du collecteur (plume.conf, répertoire d'état) est un répertoire temporaire.
New-PSDrive -Name C -PSProvider FileSystem -Root $Racine -Scope Global | Out-Null
# CENTRAL SIMULÉ : compte chaque appel. Mêmes paramètres que l'appel du collecteur ; lève en panne ;
# sinon rend l'acquittement du vrai central (`202 {"queued":true,"durable":true}`, `ingest_post`).
# `PLUME_HARNAIS_CENTRAL_REEL=1` : l'appel, compté, part ENSUITE par le VRAI cmdlet avec les paramètres
# reçus, vers un central local qui répond ce que le cas veut (redirection, cf. `jouer_la_redirection`).
function global:Invoke-RestMethod {
  [CmdletBinding()]
  param([Parameter(Mandatory)][uri]$Uri, [string]$Method, [int]$TimeoutSec, [int]$MaximumRedirection,
        [hashtable]$Headers, [string]$ContentType, $Body)
  $jeton = 'sans-jeton'
  if ($Headers -and $Headers.ContainsKey('Authorization')) { $jeton = 'bearer' }
  Add-Content -LiteralPath $env:PLUME_HARNAIS_JOURNAL -Value "APPEL $($Uri.AbsoluteUri) $jeton"
  if ($env:PLUME_HARNAIS_CENTRAL_EN_PANNE -eq '1') {
    throw [System.Net.Http.HttpRequestException]::new('central simule injoignable')
  }
  if ($env:PLUME_HARNAIS_CENTRAL_REEL -eq '1') {
    return (Microsoft.PowerShell.Utility\Invoke-RestMethod @PSBoundParameters)
  }
  [pscustomobject]@{ queued = $true; durable = $true }
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


def executer_le_harnais(pwsh: str, base: Path, tag: str, nom: str, central, env_plus: dict, conf: list):
    """Joue le collecteur TEL QUEL sous le harnais, dans un lecteur `C:` neuf (`base/tag`) ; rend
    (processus, appels au central, lectures de journal, filigranes écrits, répertoire d'état)."""
    harnais = base / "harnais.ps1"
    if not harnais.exists():
        harnais.write_text(HARNAIS_PS1, encoding="utf-8")
    racine = base / tag
    (racine / "ProgramData" / "plume").mkdir(parents=True)
    journal = base / f"journal-{tag}.txt"
    journal.write_text("", encoding="utf-8")
    if conf:
        (racine / "ProgramData" / "plume" / "plume.conf").write_text("\n".join(conf) + "\n", encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith("PLUME_") and k != "COMPUTERNAME"}
    env.update({"COMPUTERNAME": "HARNAIS", "PLUME_HARNAIS_JOURNAL": str(journal)})
    if central is not None:
        env["PLUME_CENTRAL"] = central
        env["PLUME_TOKEN"] = "jeton-temoin"
    env.update(env_plus)
    try:
        p = subprocess.run(
            [pwsh, "-NoProfile", "-NonInteractive", "-File", str(harnais),
             "-Collecteur", str(Path(COLLECTOR).resolve()), "-Racine", str(racine)],
            capture_output=True, text=True, env=env, cwd=str(base), timeout=120,
        )
    except subprocess.TimeoutExpired:
        print(f"::error::cas « {nom} » : pwsh n'a pas rendu la main en 120 s — la garde REFUSE DE CONCLURE.")
        sys.exit(CODE_INSTRUMENT)
    lignes = journal.read_text(encoding="utf-8").splitlines()
    etat = racine / "ProgramData" / "plume" / "state"
    filigranes = sorted(etat.glob("*.watermark")) if etat.is_dir() else []
    return (p, [ln for ln in lignes if ln.startswith("APPEL ")], [ln for ln in lignes if ln.startswith("LECTURE ")],
            filigranes, etat)


def jouer_le_transport(errs: list, envois_hors_irm: int) -> int:
    """Joue chaque cas sur le collecteur tel quel ; rend le nombre de cas joués.

    `envois_hors_irm` : nombre d'envois que le central simulé ne compterait pas, déjà portés dans `errs`
    par `juger_statiquement` (même puits que son témoin). Le harnais n'est alors pas joué : son compte
    d'appels n'aurait pas de sens. Le forcer à 0 ne masque rien — les défauts sont déjà dans `errs`."""
    pwsh = shutil.which("pwsh") or shutil.which("powershell")
    if not pwsh:   # ast_of() a déjà refusé de conclure avant d'arriver ici
        sys.exit(CODE_INSTRUMENT)
    if envois_hors_irm:
        return 0
    joues = 0
    with tempfile.TemporaryDirectory(prefix="plume-harnais-windows-") as base:
        for i, (nom, central, env_plus, conf, attendu, exige, interdit) in enumerate(TRANSPORT_CASES):
            p, appels, lectures, filigranes, etat = executer_le_harnais(
                pwsh, Path(base), f"cas{i}", nom, central, env_plus, conf)
            joues += 1
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


# P10.33-i — LA REDIRECTION, JOUÉE PAR LE VRAI CMDLET. Le central simulé ne suit rien : il ne pouvait pas
# voir qu'`Invoke-RestMethod` suit une réponse 3xx vers un hôte que la porte n'a jamais jugé. Ici l'appel
# compté part ENSUITE par le vrai cmdlet (`PLUME_HARNAIS_CENTRAL_REEL=1`), vers un central local ADMIS
# (`http://127.0.0.1:<port>`) qui répond le code du cas avec `Location:` vers un SECOND serveur local, qui
# figure l'hôte hors porte et compte ce qu'il reçoit. Mesuré le 2026-10-27 sous pwsh 7.6.3 sans
# `-MaximumRedirection 0` : sur 307/308, ce second serveur reçoit le corps ; sur 301/302, il reçoit un GET
# sans corps, répond 200, et le collecteur commet ses filigranes — lot compté livré, arrivé nulle part.
# Attendu : toute redirection = PANNE (code 1, rien reçu hors porte, aucun filigrane) ; 200 qui acquitte
# comme le central (`{"queued":true,…}`) = ADMIS (le cas qui prouve que le vrai cmdlet est branché).
# WINDOWS POWERSHELL 5.1 NE LÈVE PAS SUR 303/307/308 (vérificateur du 2026-10-27, source du cmdlet .NET
# Framework : `MaximumRedirectExceeded` pour Found/Moved/MovedPermanently seulement ; un 3xx sous
# `AllowAutoRedirect = false` y est une réponse NORMALE). Ce que 5.1 rend alors au collecteur est la
# réponse elle-même, au corps vide : on la joue ici sous pwsh 7 par un 200 sans corps, puis par un 200 au
# corps étranger (page d'un mandataire, autre service) — le collecteur juge l'acquittement à son CONTENU,
# donc ces cas sont des PANNES. CE QUE CES CAS NE TIENNENT PAS : Windows PowerShell 5.1 n'est pas exécuté
# (sa réponse est reproduite, pas observée) ; une redirection https -> http n'est pas jouée (aucun
# certificat ici ; pwsh 7.4+ la refuse de lui-même, `-MaximumRedirection 0` la refuse sous les deux).
# (code rendu par le central admis, corps d'un 200 (None pour un 3xx), verdict, libellé)
ACQUITTEMENT_DU_CENTRAL = b'{"queued":true,"durable":true}'
REDIRECTION_CASES = [
    (307, None, "panne", "repond 307"), (308, None, "panne", "repond 308"),
    (303, None, "panne", "repond 303"), (302, None, "panne", "repond 302"), (301, None, "panne", "repond 301"),
    (200, b"", "panne", "repond 200 sans corps (le 3xx vu par 5.1)"),
    (200, b'{"ok":true}', "panne", "repond 200 au JSON etranger"),
    (200, b"<html>connexion</html>", "panne", "repond 200 en HTML (mandataire)"),
    # `queued` présent mais faux, ou vrai sans être un booléen : chacun des deux termes de la condition
    # d'acquittement (`$reponse.queued`, `-is [bool]`) a son cas, sans quoi le retirer laisse la garde verte.
    (200, b'{"queued":false}', "panne", "repond 200 queued:false"),
    (200, b'{"queued":"true"}', "panne", "repond 200 queued en chaine"),
    (200, ACQUITTEMENT_DU_CENTRAL, "admis", "acquitte comme le central (202 queued)"),
]


def jouer_la_redirection(errs: list, envois_hors_irm: int) -> int:
    """Joue chaque code de REDIRECTION_CASES sur le collecteur tel quel ; rend le nombre de cas joués."""
    import http.server
    import threading
    pwsh = shutil.which("pwsh") or shutil.which("powershell")
    if not pwsh:
        sys.exit(CODE_INSTRUMENT)
    if envois_hors_irm:
        return 0
    hors_porte: list = []

    class HorsPorte(http.server.BaseHTTPRequestHandler):
        def _recu(self):
            n = int(self.headers.get("Content-Length") or 0)
            hors_porte.append((self.command, n, self.headers.get("Authorization") is not None))
            if n:
                self.rfile.read(n)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')
        do_POST = do_GET = _recu

        def log_message(self, *a):
            pass

    hp = http.server.ThreadingHTTPServer(("127.0.0.1", 0), HorsPorte)
    threading.Thread(target=hp.serve_forever, daemon=True).start()
    joues = 0
    try:
        with tempfile.TemporaryDirectory(prefix="plume-harnais-redirection-") as base:
            for i, (code, corps, attendu, libelle) in enumerate(REDIRECTION_CASES):
                recus_central: list = []

                class Central(http.server.BaseHTTPRequestHandler):
                    def do_POST(self, code=code, corps=corps):
                        n = int(self.headers.get("Content-Length") or 0)
                        recus_central.append(n)
                        if n:
                            self.rfile.read(n)
                        if corps is not None:
                            # L'acquittement réel est un 202 ; les corps étrangers, un 200 quelconque.
                            self.send_response(202 if corps == ACQUITTEMENT_DU_CENTRAL else code)
                            ct = "text/html" if corps.startswith(b"<") else "application/json"
                            self.send_header("Content-Type", ct)
                            self.send_header("Content-Length", str(len(corps)))
                            self.end_headers()
                            self.wfile.write(corps)
                            return
                        self.send_response(code)
                        self.send_header("Location", f"http://127.0.0.1:{hp.server_address[1]}/api/ingest")
                        self.send_header("Content-Length", "0")
                        self.end_headers()

                    def log_message(self, *a):
                        pass

                srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Central)
                threading.Thread(target=srv.serve_forever, daemon=True).start()
                hors_porte.clear()
                nom = f"central admis qui {libelle}"
                try:
                    p, appels, _lectures, filigranes, _etat = executer_le_harnais(
                        pwsh, Path(base), f"redir{i}", nom, f"http://127.0.0.1:{srv.server_address[1]}",
                        {"PLUME_HARNAIS_CENTRAL_REEL": "1"}, [])
                finally:
                    srv.shutdown()
                    srv.server_close()
                joues += 1
                vu = (f"code {p.returncode}, {len(appels)} appel(s) compté(s), {len(recus_central)} requête(s) au "
                      f"central, {len(hors_porte)} hors porte {hors_porte}, {len(filigranes)} filigrane(s) ; "
                      f"stderr : {p.stderr.strip()[-200:]!r}")
                defauts = []
                if not appels or not recus_central:
                    defauts.append("au moins un appel au central attendu (le vrai cmdlet est-il branché ?)")
                if hors_porte:
                    defauts.append("RIEN ne doit arriver à l'hôte vers lequel le central redirige : la porte du "
                                   "transport ne l'a pas jugé")
                if attendu == "panne":
                    if p.returncode != 1:
                        defauts.append("code 1 attendu : une redirection, ou une réponse sans "
                                       "`\"queued\":true`, est un envoi NON acquitté")
                    if filigranes:
                        defauts.append("aucun filigrane ne doit être commis : le lot n'est pas arrivé au central")
                else:
                    if p.returncode != 0:
                        defauts.append("code 0 attendu (central qui acquitte)")
                    if not filigranes:
                        defauts.append("des filigranes commis attendus après un envoi acquitté")
                for df in defauts:
                    errs.append(f"{COLLECTOR}: redirection, cas « {nom} » : {df}. VU : {vu}")
                print(f"  redirection · {nom:<70} {'OK' if not defauts else 'ROUGE'} · {vu[:140]}")
    finally:
        hp.shutdown()
        hp.server_close()
    return joues


# =================================================================================================
# P10.33-i — CE QUE LE COLLECTEUR NE PEUT PAS ÉCRIRE, JUGÉ SANS L'EXÉCUTER : WINDOWS POWERSHELL 5.1
# (QU'AUCUN RUNNER LINUX N'EXÉCUTE) ET TOUT ENVOI QUE LE CENTRAL SIMULÉ NE COMPTERAIT PAS
# =================================================================================================
# Monter PSScriptAnalyzer = changer les DEUX ensemble ; le pas d'installation de ci.yml les LIT ici.
# Empreinte relevée le 2026-10-18 : sha256 du nupkg servi par la galerie, dont le SHA512 publié
# (`PackageHash` de l'API v2) concorde.
PSSA_VERSION = "1.25.0"
PSSA_SHA256 = "14e634c828eb98efb9f40b2918ba90f139ed5eccdf663a2a747736d996995d60"
# Les profils Windows PowerShell 5.1 Desktop (.NET Framework) que ce module LIVRE, tous trois, et la
# plateforme que PSScriptAnalyzer NOMME dans ses messages pour chacun (le témoin exige les trois : une
# analyse restreinte à un profil rendrait le même « 0 diagnostic » sur le collecteur).
PROFILS_51 = (
    "win-48_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework",   # Windows 10 1809
    "win-8_x64_10.0.14393.0_5.1.14393.2791_x64_4.0.30319.42000_framework",   # Windows Server 2016
    "win-8_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework",    # Windows Server 2019
)
PLATEFORMES_51 = ("Microsoft Windows 10 Pro", "Microsoft Windows Server 2016 Datacenter",
                  "Microsoft Windows Server 2019 Datacenter")
REGLES_PROFILEES = ("PSUseCompatibleCommands", "PSUseCompatibleTypes")
# Lecture du SOURCE par Windows PowerShell 5.1 : sans BOM, il lit un script dans la page de code ANSI.
# Mesuré par le vérificateur du 2026-10-18 : le collecteur en UTF-8 SANS BOM, lu en cp1252, a 19 erreurs
# de parsage (« — » = E2 80 94, et 0x94 = U+201D, que PowerShell prend pour un guillemet fermant) — la
# tâche planifiée mourait au parsage, avant la porte du clair. Deux jambes : la règle du module, et la
# lecture des OCTETS ici même.
BOM_UTF8 = b"\xef\xbb\xbf"
# TÉMOIN fabriqué à chaque passage, écrit SANS BOM. Chaque (jambe, ligne) de TEMOIN_51_ATTENDU doit
# sortir par le MÊME puits que les défauts du collecteur (`errs`), et la ligne `[System.Uri]` par AUCUNE
# jambe (témoin négatif : le collecteur l'emploie, une jambe qui la refuserait rougirait sur un faux).
# Une jambe = un SITE de refus : en retirer un laisse sa ligne muette, et la garde refuse de conclure.
TEMOIN_51 = r"""using namespace System.Net
$a = $null
$b = $a ?? 'x'
$c = $true ? 1 : 2
$h = '{}' | ConvertFrom-Json -AsHashtable
$i = ${a}?[0]
$s = [System.Management.Automation.PSStyle]::Instance
$w = [System.Net.Http.HttpClient]::new()
$u = [System.Uri]'https://example.org'
$c2 = New-Object Net.WebClient
Invoke-WebRequest -Uri 'https://example.org'
Microsoft.PowerShell.Utility\Invoke-RestMethod -Uri 'https://example.org'
& 'C:\Windows\System32\curl.exe' 'https://example.org'
bitsadmin /transfer j https://example.org C:\x
Invoke-Expression 'Get-Date'
Add-Type -TypeDefinition 'public class X {}'
$outil = 'curl.exe'; & $outil 'https://example.org'
Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName 'hote'
New-Object -ComObject 'WinHttp.WinHttpRequest.5.1'
$x = [scriptblock]::Create('Get-Date')
$o = [Activator]::CreateInstance([type]::GetTypeFromProgID('WinHttp.WinHttpRequest.5.1'))
$d = ([xml]'<a/>').Load('https://example.org')
$r = $ExecutionContext.InvokeCommand.InvokeScript('Get-Date')
Set-Content -Path '\\192.0.2.10\partage\x' -Value 1
$t = 'System.Net.WebClient'
[System.Net.WebClient]$wc = $null
[System.Management.Automation.PSStyle]$p = $null
$a ??= 1
Get-Date && Get-Date
Get-Date &
function F { clean { 2 } }
$e = "`u{2014}"
$n = [uint]1
$m = [System.Math]::Clamp(5, 1, 3)
$z = 'é — x'
$ip = [ipaddress]'192.0.2.10'
([xml]'<a/>') | ForEach-Object Load 'https://example.org'
([xml]'<a/>') | % Load 'https://example.org'
([xml]'<a/>') | ForEach-Object -MemberName Load
Set-Content -Path:'\\192.0.2.10\p\a' -Value 1
Set-Content -Path ('\\192.0.2.10\p\b') -Value 1
Get-Content 'FileSystem::\\192.0.2.10\p\c'
Get-WinEvent -FilterHashtable @{ Path = '\\192.0.2.10\p\d' }
$q = '//192.0.2.10/p/e'; Set-Content -Path $q -Value 1
$p5 = @{ ClassName = 'Win32_OperatingSystem'; ComputerName = 'hote' }; Get-CimInstance @p5
Get-CimInstance @inconnu
$nom8 = 'System.IO.StreamWriter'; New-Object $nom8
New-Object ('System.IO.' + 'StreamWriter')
Get-CimInstance Win32_OperatingSystem -Comp 'hote'
$col = [System.Drawing.Color]
$esc = "`e[0m"
if ($IsWindows) { 1 }
$r2 = 'a1' -replace '\d', { $_.Value }
([xml]'<a/>') | ForEach-Object -MemberName:Load
$p6 = @{ Path = 'x' }; $p6.ComputerName = 'h'; Get-Content @p6
$ok = "``e"
Invoke-RestMethod -Uri 'https://example.org'
Invoke-RestMethod -Uri 'https://example.org' -MaximumRedirection 1
$n9 = 0; Invoke-RestMethod -Uri 'https://example.org' -MaximumRedirection $n9
Invoke-RestMethod -Uri 'https://example.org' -MaximumRedirection 0
Invoke-RestMethod -Uri 'https://example.org' -MaximumRedirection:0
"""
TEMOIN_51_ATTENDU = {   # jambe -> lignes qui DOIVENT sortir par le puits
    "PSUseCompatibleSyntax": {3, 4},
    "PSUseCompatibleCommands": {5},
    "PSUseCompatibleTypes": {8},
    "PSUseBOMForUnicodeEncodedFile": {0},   # diagnostic de FICHIER : le module ne donne pas de ligne
    "encodage": {35},
    "ast-syntaxe": {3, 4, 6, 28, 29, 30, 31, 32, 51, 52, 53},
    # 50 : `[System.Drawing.Color]` manque au SEUL profil Windows Server 2016 (présent dans les deux autres).
    "ast-types": {7, 27, 33, 50},
    "ast-membres": {34},
    "envoi:commande": {11, 12, 13, 14, 15, 16},
    "envoi:invocation-dynamique": {17},
    # 49 : `-Comp` abrège `-Compress`, qui est admis — l'abréviation, elle, ne l'est pas.
    "envoi:parametre": {18, 19, 39, 45, 49},
    "envoi:splat": {46, 55},   # 55 : table littérale MODIFIÉE avant le splatting
    "envoi:new-object": {10, 47, 48},
    "envoi:type": {8, 20, 21, 26, 36},
    "envoi:methode": {22, 23},
    "envoi:membre-foreach": {37, 38, 39, 54},
    "envoi:unc": {24, 40, 41, 42, 43, 44},
    "envoi:chaine-net": {25},
    "envoi:using": {1},
    # 57-59 : `Invoke-RestMethod` nu sans `-MaximumRedirection 0` écrit (absent, autre valeur, variable).
    "envoi:redirection": {57, 58, 59},
}
# Lignes qu'AUCUNE jambe ne doit signaler : `[System.Uri]` (le collecteur l'emploie), un accent grave
# ÉCHAPPÉ suivi de « e » (``e n'est pas l'échappement `e), et `-MaximumRedirection 0` sous ses deux
# écritures (séparée, collée par `:`).
TEMOIN_51_NEUTRES = {9, 56, 60, 61}
# Noms de types que le PARSEUR traite lui-même (pas des accélérateurs du profil).
TYPES_DU_PARSEUR = {"ordered"}


def analyser_51(chemins: list) -> dict:
    pwsh = shutil.which("pwsh") or shutil.which("powershell")
    if not pwsh:
        sys.exit(CODE_INSTRUMENT)
    try:
        p = subprocess.run(
            [pwsh, "-NoProfile", "-NonInteractive", "-File", str(AST_DUMPER), "-Compatibilite",
             "-Version", PSSA_VERSION, "-Profils", ",".join(PROFILS_51), "-Path", ",".join(chemins)],
            capture_output=True, text=True, timeout=600,
        )
    except subprocess.TimeoutExpired:
        print("::error::PSScriptAnalyzer n'a pas rendu la main en 600 s — la garde REFUSE DE CONCLURE.")
        sys.exit(CODE_INSTRUMENT)
    ligne = next((ln for ln in p.stdout.splitlines() if ln.startswith("PLUME-PSSA-JSON:")), None)
    if p.returncode != 0 or ligne is None:
        print(
            f"::error::PSScriptAnalyzer {PSSA_VERSION} INDISPONIBLE (rc={p.returncode}) : "
            f"{p.stderr.strip()[:400]} — la compatibilité Windows PowerShell 5.1 du collecteur ne peut "
            f"pas être jugée, la garde REFUSE DE CONCLURE (elle ne passe pas au vert). Installer cette "
            f"version (nupkg vérifié par PSSA_SHA256 : voir le pas « PSScriptAnalyzer épinglé » du job "
            f"`shell` de ci.yml) dans un répertoire de PSModulePath."
        )
        sys.exit(CODE_INSTRUMENT)
    return json.loads(ligne[len("PLUME-PSSA-JSON:"):])


def _noms(v) -> set:
    """Une rubrique de membres du profil : liste de noms, ou objet dont les clés sont les noms."""
    return {k.lower() for k in (v.keys() if isinstance(v, dict) else (v or []))}


def index_des_profils(fichiers: list) -> list:
    """Par profil : (nom, types complets, accélérateur -> type complet, type complet -> membres statiques)."""
    out = []
    for f in fichiers:
        j = json.loads(Path(f).read_text(encoding="utf-8-sig"))
        t = j["Runtime"]["Types"]
        noms, statiques = set(), {}
        for a in t["Assemblies"].values():
            for ns, ty in (a.get("Types") or {}).items():
                for n, corps in ty.items():
                    plein = f"{ns}.{n}".lower()
                    noms.add(plein)
                    st = (corps or {}).get("Static") or {}
                    statiques[plein] = set().union(*(_noms(st.get(r)) for r in ("Methods", "Properties", "Fields", "Events")))
        accel = {k.lower(): (v.get("Type") if isinstance(v, dict) else str(v)).lower()
                 for k, v in t["TypeAccelerators"].items()}
        out.append((Path(f).stem, noms, accel, statiques))
    if not out or any(len(n) < 1000 or len(a) < 10 or len(s) < 1000 for _, n, a, s in out):
        print(f"::error::profils 5.1 illisibles ou vides ({[(p, len(n), len(a)) for p, n, a, _ in out]}) — "
              f"la garde REFUSE DE CONCLURE.")
        sys.exit(CODE_INSTRUMENT)
    return out


def nom_de_base(nom: str) -> str:
    """`System.Int32[]` -> `system.int32` ; `List[string]` -> `list` ; `List`1[[…]]` -> `list`1`."""
    return re.split(r"\[", nom, maxsplit=1)[0].strip().lower()


def type_du_profil(nom: str, noms: set, accel: dict):
    """Le type complet que Windows PowerShell 5.1 donnerait à ce nom écrit, ou None."""
    for candidat in (nom, "system." + nom):
        if candidat in noms:
            return candidat
    return accel.get(nom)


def types_hors_51(types: list, profils: list) -> list:
    """Tout type NOMMÉ absent d'un profil. Le nom est résolu par les profils 5.1, jamais par pwsh 7 :
    pwsh 7 résout `[uint]` en System.UInt32, et Windows PowerShell 5.1 n'a pas cet accélérateur."""
    hors = []
    for t in types:
        ecrit = nom_de_base(t["written"])
        if ecrit in TYPES_DU_PARSEUR:
            continue
        manquants = [p for p, noms, accel, _ in profils if type_du_profil(ecrit, noms, accel) is None]
        if manquants:
            hors.append((t["line"], t["written"], manquants))
    return hors


def membres_statiques_hors_51(membres: list, profils: list) -> list:
    """`[T]::M` dont le type existe en 5.1 mais pas le membre (`[Math]::Clamp`, .NET Core 2.0) —
    mesuré : PSUseCompatibleTypes ne le voit pas. `::new` est le constructeur (PowerShell 5.0)."""
    hors = []
    for m in membres:
        if not (m["static"] and m["type"] and m["member"]) or m["member"].lower() == "new":
            continue
        base = nom_de_base(m["type"])
        manquants = []
        for p, noms, accel, statiques in profils:
            plein = type_du_profil(base, noms, accel)
            if plein is not None and m["member"].lower() not in statiques.get(plein, set()):
                manquants.append(p)
        if manquants:
            hors.append((m["line"], f"[{m['type']}]::{m['member']}", manquants))
    return hors


def encodage_illisible_par_51(octets: bytes) -> int:
    """Ligne du premier octet non ASCII d'un fichier SANS BOM UTF-8 ; 0 si 5.1 le lit tel qu'écrit."""
    if octets.startswith(BOM_UTF8):
        return 0
    for i, b in enumerate(octets):
        if b > 0x7F:
            return octets.count(b"\n", 0, i) + 1
    return 0


def diagnostics_statiques(octets: bytes, d: dict, pssa: list, profils: list) -> list:
    """(ligne, jambe, message) pour UN fichier — la même fonction juge le témoin et le collecteur."""
    out = []
    for x in pssa:
        out.append((x["line"] or 0, x["rule"],
                    f"Windows PowerShell 5.1 (que lance la tâche planifiée) — {x['message']}"))
    ligne = encodage_illisible_par_51(octets)
    if ligne:
        out.append((ligne, "encodage",
                    "octet non ASCII dans un fichier SANS BOM UTF-8 : Windows PowerShell 5.1 le lit dans la "
                    "page de code ANSI, et un « — » devient un guillemet fermant (la tâche planifiée meurt au "
                    "parsage, avant tout aveu). Encodez en UTF-8 AVEC BOM, ou en ASCII."))
    for x in d["post51"]:
        out.append((x["line"], "ast-syntaxe",
                    f"syntaxe postérieure à Windows PowerShell 5.1 ({x['forme']}) : `{x['text'][:80]}` — "
                    f"la tâche planifiée échouerait au parsage ou lirait autre chose."))
    for ligne, ecrit, manquants in types_hors_51(d["types"], profils):
        out.append((ligne, "ast-types", f"type `[{ecrit}]` absent de Windows PowerShell 5.1 (profils {manquants})."))
    for ligne, quoi, manquants in membres_statiques_hors_51(d.get("members", []), profils):
        out.append((ligne, "ast-membres",
                    f"membre statique `{quoi}` absent de Windows PowerShell 5.1 (profils {manquants})."))
    for ligne, site, quoi in envois_hors_du_central_simule(d):
        if site == "redirection":
            out.append((ligne, f"envoi:{site}", f"{quoi}. Écrivez `-MaximumRedirection 0` sur l'appel."))
            continue
        out.append((ligne, f"envoi:{site}",
                    f"{quoi} — hors du central simulé (`Invoke-RestMethod` nu) : le compte d'appels du harnais "
                    f"serait aveugle à cet envoi. Envoyez par `Invoke-RestMethod`, ou lisez l'entrée et "
                    f"ajoutez-la à sa liste fermée (ou étendez le harnais) AVANT de l'employer."))
    return out


def juger_statiquement(errs: list) -> dict:
    """Juge le témoin PUIS le collecteur par le MÊME puits (`errs`) ; relit et retire du puits ce qu'y a
    déposé le témoin. Retirer ce dépôt ou une jambe fait taire le témoin : la garde refuse de conclure.
    Rend le bilan dont `main` tire son verdict (rien n'y est écrit en dur)."""
    debut = len(errs)
    with tempfile.TemporaryDirectory(prefix="plume-compat-51-") as base:
        temoin = str(Path(base) / "temoin-51.ps1")
        Path(temoin).write_bytes(TEMOIN_51.encode("utf-8"))
        r = analyser_51([COLLECTOR, temoin])
        if r.get("version") != PSSA_VERSION:
            print(f"::error::PSScriptAnalyzer chargé en {r.get('version')!r}, épinglé {PSSA_VERSION} — "
                  f"la garde REFUSE DE CONCLURE.")
            sys.exit(CODE_INSTRUMENT)
        charges = [Path(f).stem for f in r.get("profils", [])]
        if charges != list(PROFILS_51):
            print(f"::error::profils chargés {charges}, attendus {list(PROFILS_51)} — la garde REFUSE DE CONCLURE.")
            sys.exit(CODE_INSTRUMENT)
        profils = index_des_profils(r["profils"])
        asts = {}
        for chemin in (temoin, COLLECTOR):
            asts[chemin] = ast_of(chemin)
            for ligne, jambe, msg in diagnostics_statiques(Path(chemin).read_bytes(), asts[chemin],
                                                           r["fichiers"][chemin], profils):
                errs.append(f"{chemin}:{ligne}: [{jambe}] {msg}")

    # --- témoin : relu DANS le puits, puis retiré ---
    prefixe = f"{temoin}:"
    du_temoin = [e for e in errs[debut:] if e.startswith(prefixe)]
    errs[debut:] = [e for e in errs[debut:] if not e.startswith(prefixe)]
    vu: dict = {}
    plateformes = {regle: set() for regle in REGLES_PROFILEES}
    for e in du_temoin:
        m = re.match(re.escape(prefixe) + r"(\d+): \[([^\]]+)\] (.*)", e, re.S)
        vu.setdefault(m.group(2), set()).add(int(m.group(1)))
        if m.group(2) in plateformes:
            plateformes[m.group(2)].update(re.findall(r"on platform '([^']+)'", m.group(3)))
    muettes = {j: sorted(att - vu.get(j, set())) for j, att in TEMOIN_51_ATTENDU.items() if not att <= vu.get(j, set())}
    fausses = sorted(j for j, lignes in vu.items() if TEMOIN_51_NEUTRES & lignes)
    profils_muets = {regle: sorted(set(PLATEFORMES_51) - vus) for regle, vus in plateformes.items()
                     if not set(PLATEFORMES_51) <= vus}
    encodage_faux = [nom for nom, octets in (("avec BOM", BOM_UTF8 + TEMOIN_51.encode("utf-8")),
                                             ("ASCII", b"$a = 1\n"))
                     if encodage_illisible_par_51(octets)]
    if muettes or fausses or profils_muets or encodage_faux:
        print(f"::error::témoin du jugement statique : jambes MUETTES {muettes}, jambes qui signalent "
              f"une ligne neutre (`[System.Uri]`, ``e, `-MaximumRedirection 0`) {fausses}, plateformes 5.1 non jugées {profils_muets}, encodage refusé à tort "
              f"{encodage_faux} (vu : { {j: sorted(v) for j, v in vu.items()} }) — l'instrument ne juge pas "
              f"ce qu'il prétend, la garde REFUSE DE CONCLURE.")
        sys.exit(CODE_INSTRUMENT)

    d = asts[COLLECTOR]
    octets = Path(COLLECTOR).read_bytes()
    return {
        "version": r["version"],
        "profils": len(charges),
        "jambes_temoin": len(TEMOIN_51_ATTENDU),
        "lignes_temoin": len({ln for lignes in vu.values() for ln in lignes}),
        "envois_collecteur": sum(1 for e in errs[debut:] if "[envoi:" in e),
        "commandes": len(d["commands"]),
        "types": len(d["types"]),
        "methodes": sum(1 for m in d.get("members", []) if m["invoked"]),
        "encodage": "UTF-8 avec BOM" if octets.startswith(BOM_UTF8) else "ASCII",
    }


# --- P10.32-n : la doc d'installation ne contredit pas le script ---------------------------------
DOCS_WINDOWS = {
    # chemin -> (début, fin) de la tranche jugée ; None = tout le fichier
    "collectors/windows/README.md": None,
    "docs/INSTALLER-SANS-OUVRIR-DE-BRECHE.md": ("### 2.5 Windows", "\n## 4. "),
}
# Ce que les deux docs annoncent : « plume.conf ne porte que trois clés ».
CLES_PLUME_CONF_DOCUMENTEES = {"PLUME_CENTRAL", "PLUME_TOKEN", "PLUME_SHIP_ALLOW_PLAINTEXT"}
PHRASE_ACTION_JAMAIS = re.compile(r"jamais[^.]{0,60}champ CIM `action`|champ CIM `action`[^.]{0,30}jamais", re.I)
PHRASE_LOT_PERDU = re.compile(r"\blot\b[^.]{0,25}\bperdu", re.I)
AVERTISSEMENT_JETON = "`PLUME_TOKEN` ne se pose jamais en variable machine"


def texte_juge(brut: str) -> str:
    t = re.sub(r"~~.*?~~", "", brut, flags=re.S)
    t = re.sub(r"(?m)^\s*>\s?", "", t)
    t = t.replace("**", "")
    return re.sub(r"\s+", " ", t)


def juger_la_doc(errs: list) -> None:
    src = Path(COLLECTOR).read_text(encoding="utf-8-sig")
    i = src.find("Get-Content $ConfFile")
    if i < 0:
        errs.append(f"{COLLECTOR}: lecture de plume.conf (`Get-Content $ConfFile`) introuvable : la "
                    f"concordance des clés avec la doc ne peut pas être jugée.")
        cles = None
    else:
        bloc = src[i:src.find("\n}", i)]
        cles = set(re.findall(r"'(PLUME_[A-Z_]+)'\s*\{", bloc))
        if cles != CLES_PLUME_CONF_DOCUMENTEES:
            errs.append(f"{COLLECTOR}: plume.conf lit {sorted(cles)}, la doc annonce "
                        f"{sorted(CLES_PLUME_CONF_DOCUMENTEES)} (et que `PLUME_TLS_INSECURE` n'y est pas lue).")
    pose_action = bool(re.search(r"\$fields\['action'\]\s*=|\baction\s*=\s*'", src))
    for chemin, tranche in DOCS_WINDOWS.items():
        brut = Path(chemin).read_text(encoding="utf-8")
        if tranche:
            a = brut.find(tranche[0]); b = brut.find(tranche[1], a + 1)
            if a < 0 or b < 0:
                errs.append(f"{chemin}: tranche {tranche!r} introuvable : la doc Windows n'est pas jugée.")
                continue
            brut = brut[a:b]
        t = texte_juge(brut)
        if pose_action:
            for m in PHRASE_ACTION_JAMAIS.finditer(t):
                errs.append(f"{chemin}: « …{m.group(0)}… » alors que le script pose `fields.action` "
                            f"(table d'issues de {COLLECT_FN}, `blocked` du pare-feu).")
        for m in PHRASE_LOT_PERDU.finditer(t):
            errs.append(f"{chemin}: « …{m.group(0)}… » alors qu'un envoi raté ne commet aucun filigrane "
                        f"({COMMIT_FN}) : le run suivant relit, seuls les échantillons sont perdus.")
        if AVERTISSEMENT_JETON not in t:
            errs.append(f"{chemin}: la phrase « {AVERTISSEMENT_JETON} » manque, alors que la doc propose "
                        f"des variables machine (lisibles par tout utilisateur local).")


def main() -> int:
    files = subprocess.run(
        ["git", "ls-files", "collectors/windows/*.ps1"], capture_output=True, text=True, check=True
    ).stdout.split()
    errs: list = []
    total_catches = 0
    for f in files:
        total_catches += check(f, errs)
    joues = joues_redirection = 0
    bilan = None   # posé par juger_statiquement : le verdict en est TIRÉ, jamais écrit en dur
    if COLLECTOR in files:
        bilan = juger_statiquement(errs)
    else:
        errs.append(f"{COLLECTOR} introuvable parmi les fichiers suivis : la porte du transport n'est pas jouée.")
    if bilan is not None:
        joues = jouer_le_transport(errs, bilan["envois_collecteur"])
        joues_redirection = jouer_la_redirection(errs, bilan["envois_collecteur"])
        juger_la_doc(errs)
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
    if bilan is None:
        print("::error::le jugement statique du collecteur (Windows PowerShell 5.1, envois hors du central "
              "simulé) n'a pas été joué — la garde REFUSE DE CONCLURE.")
        return CODE_INSTRUMENT
    # PLANCHER des cas joués, dérivé de la liste : sans lui, un harnais qui ne joue RIEN rendait le vert
    # (mesuré par le vérificateur du 2026-10-19 : « 0 cas de transport joués », code 0).
    if joues < len(TRANSPORT_CASES):
        print(f"::error::{joues} cas de transport joués sur {len(TRANSPORT_CASES)} : la porte du clair n'a pas "
              f"été jouée sur le collecteur — la garde REFUSE DE CONCLURE.")
        return CODE_INSTRUMENT
    if joues_redirection < len(REDIRECTION_CASES):
        print(f"::error::{joues_redirection} cas de redirection joués sur {len(REDIRECTION_CASES)} : le suivi des "
              f"réponses 3xx n'a pas été joué sur le collecteur — la garde REFUSE DE CONCLURE.")
        return CODE_INSTRUMENT
    print(
        f"{len(files)} collecteur(s) PowerShell, {total_catches} `catch` : toute erreur est classée "
        f"(incapacité / désactivé / rien de neuf) ou relevée, et aucun filigrane ne s'écrit avant un "
        f"envoi acquitté ; {joues}/{len(TRANSPORT_CASES)} cas de transport joués sur le collecteur tel quel (http distant "
        f"refusé en code 2 sans appel ni lecture, opt-in, https et boucle locale admis) ; "
        f"{joues_redirection}/{len(REDIRECTION_CASES)} cas de redirection et "
        f"d'acquittement joués par le vrai cmdlet (3xx et réponse sans `queued` = panne, rien reçu hors porte, "
        f"aucun filigrane) ; "
        f"la doc Windows ne contredit pas le script (clés de plume.conf, `action`, spool, jeton) ; "
        f"{bilan['commandes']} commandes, {bilan['types']} types nommés et {bilan['methodes']} appels de "
        f"méthode du collecteur, tous dans les listes fermées (aucun envoi hors d'`Invoke-RestMethod` nu "
        f"ÉCRIT dans le source) ; source en {bilan['encodage']}, jugé contre {bilan['profils']} profils "
        f"Windows PowerShell 5.1 Desktop par PSScriptAnalyzer {bilan['version']} et par l'AST ; témoin : "
        f"{bilan['jambes_temoin']} jambes rouges sur {bilan['lignes_temoin']} lignes, aucune sur ses {len(TEMOIN_51_NEUTRES)} lignes neutres (`[System.Uri]`, ``e, `-MaximumRedirection 0`)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
