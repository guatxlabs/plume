#Requires -Version 5.1
<#
  Plume — collecteur Windows (natif PowerShell).
  ============================================================================
  Équivalent Windows des collecteurs POSIX-sh (`collectors/*.sh`). Ramasse les
  sources utiles à la surveillance d'un poste OU d'un serveur Windows et les
  POST directement au central Plume sur `/api/ingest` (même contrat que
  `collectors/ship.sh` : enveloppe {ts,host,kind:events,events:[...]} +
  `Authorization: Bearer <token>`). Aucun agent sh/spool requis côté Windows.

  Sources couvertes (chacune dégrade proprement si indisponible — même
  philosophie « auto-disable if tool absent » que les collecteurs Linux) :
    - windows-security  : ouverture/échec de session (4624/4625), logoff (4634),
                          privilèges spéciaux (4672), Kerberos/NTLM (4768/4769/4771/4776),
                          création de processus (4688), verrouillage de compte (4740),
                          gestion de comptes (4720/4722/4724/4726/4732/4756).  category=auth|exec|account
    - windows-firewall  : paquets/connexions BLOQUÉS par le pare-feu Windows (WFP :
                          5152/5157) + état des profils (Get-NetFirewallProfile).  category=firewall
    - windows-system    : arrêts inattendus (6008), échecs de service (7031/7034/7000).  category=system
    - windows-defender  : détections Microsoft Defender (1006/1015/1116/1117).  category=malware
    - windows-network   : connexions TCP établies (distantes) + ports en écoute.  category=network

  CE QUE CETTE LISTE NE COUVRE PAS EST DIT PAR LE PRODUIT, PAS PAR CE COMMENTAIRE.
  Une liste d'identifiants EST un filtre ; un filtre non déclaré est un angle mort, et un
  commentaire qui l'énumère vieillit sans prévenir. `Report-Coverage` interroge donc le CANAL sur
  la MÊME fenêtre et émet, à chaque run, un événement `category=config type=collector-coverage`
  portant les identifiants PRODUITS et NON COLLECTÉS, avec leur compte (borné, et il dit quand il
  a été borné). Le trou est ainsi mesurable depuis le SOC, sur chaque hôte, sans relire ce fichier.

  Idempotence : un filigrane par source (dernier `TimeCreated` traité) est
  persisté sous $StateDir ; seuls les nouveaux événements sont expédiés. Chaque
  événement porte aussi un `dedup` (le central dédoublonne dans l'heure).

  DEUX INVARIANTS, chacun fermé par une garde de CI
  (`.github/scripts/check_windows_collector_is_honest.py`) :

  1. RIEN N'EST OUBLIÉ AVANT D'AVOIR ÉTÉ LIVRÉ. Le filigrane n'est PAS écrit là où il est
     calculé : il est MIS EN ATTENTE (`Stage-Watermark`) et n'est COMMIS qu'après un POST
     ACQUITTÉ, par `Complete-Run`, seul endroit du fichier qui écrive sur le disque d'état.
     Le journal Windows EST le spool : tant que le filigrane ne bouge pas, le run suivant
     relit exactement ce qui n'est pas passé (at-least-once ; les réémissions sont absorbées
     par le `dedup`, cloisonné par hôte côté central). Le prix assumé : les ÉCHANTILLONS
     (profils pare-feu, instantané réseau, battement) d'un run perdu ne sont pas rejoués —
     ils sont recalculés au run suivant, donc aucune HISTOIRE n'est perdue.
     MESURÉ le 2026-08-02 sur la version précédente, harnais pwsh (journal Windows et
     central simulés, collecteur exécuté TEL QUEL) : central indisponible pendant un run,
     42 événements éligibles -> 0 arrivés, filigrane avancé quand même -> **42 perdus
     DÉFINITIVEMENT** (0 rattrapé au rétablissement). Même harnais, central disponible :
     0 perdu / 42 arrivés. Second chemin de perte mesuré : dépôt WMI cassé -> le run mourait
     sur `(Get-CimInstance …).Caption` APRÈS l'écriture du filigrane et AVANT tout POST —
     12 événements collectés, 0 POST tenté, filigrane avancé : 12 perdus.

  2. UN CAPTEUR QUI NE PEUT PAS COLLECTER LE DIT. Miroir PowerShell de la partition fermée de
     `collectors/lib.sh` : (I) incapacité -> `Plume-Unavailable`, (II) coupé par l'opérateur ->
     `Plume-Disabled`, (III) rien de neuf -> `Plume-NoData` (silence LÉGITIME, aucun octet).
     Tout `catch` de ce fichier doit classer ou relever ; aucune suppression d'erreur muette
     (`-ErrorAction SilentlyContinue`) n'y est plus recevable. Les événements produits sont
     ceux de `plume_report_availability` (category=config, `collect_status=unavailable`),
     donc la règle EXISTANTE `config.d/rules/catalog/de-collector-unavailable.json` couvre
     Windows sans une ligne de plus.
     MESURÉ le 2026-08-02 sur la version précédente : journal Security en ACCÈS REFUSÉ (le cas
     du technicien qui lance le script hors SYSTEM) -> 12 événements attendus, **0 arrivé, 0 aveu**,
     code de retour 0, et le battement de santé annonçait quand même « plume windows collector ok ».

  Déploiement (voir README.md de ce dossier) : tâche planifiée toutes les 1–5 min,
  en compte SYSTEM (accès au journal Security). Config par variables d'env
  (PLUME_CENTRAL / PLUME_TOKEN) ou fichier C:\ProgramData\plume\plume.conf (KEY=value).
  Le jeton N'a PAS de paramètre de ligne de commande : cf. le bandeau P5.5-a sous `param()`.

  Sûreté : lecture seule du système, aucun secret en clair dans le code, TLS
  vérifié par défaut (PLUME_TLS_INSECURE=1 pour un central en certificat auto-signé
  de test uniquement). N'expédie que des métadonnées d'événements, jamais de contenu
  de fichier.
#>

[CmdletBinding()]
param(
  [string]$Central = $env:PLUME_CENTRAL,
  [int]$MaxAgeMinutes = 60,   # borne de rattrapage au 1er run (pas de filigrane) — anti-flood
  [int]$BatchSize = 400       # nb max d'événements par POST
)

# P5.5-a — IL N'Y A PLUS DE PARAMÈTRE `-Token`, ET C'EST LA CORRECTION.
# Le script en acceptait un, et le README disait « ne vous en servez pas ». Une consigne n'est pas une
# garde : dès que l'audit `Process Creation` est actif — ce que les prérequis de ce collecteur DEMANDENT
# d'activer — la ligne de commande complète part dans l'événement Security 4688 si la GPO « Include
# command line » est posée, ET dans Sysmon ID 1 SANS aucune GPO. MESURÉ le 2026-08-02 : un jeton-appât
# passé via `-Token` est ressorti lisible dans le SOC par TROIS chemins indépendants
# (`windows-security`/exec via ce script, `WinEventLog:Security`/exec via l'agent Rust,
# `WinEventLog:Microsoft-Windows-Sysmon/Operational`/endpoint via Sysmon). Le jeton arrivait donc en
# clair dans le SOC que ce collecteur alimente. Le paramètre est retiré : le jeton vient de
# l'environnement (PLUME_TOKEN, hérité du processus) ou de C:\ProgramData\plume\plume.conf.
# CE QUI RESTE OUVERT ET NE SE CORRIGE PAS ICI : si l'OPÉRATEUR tape lui-même un jeton sur une ligne de
# commande (n'importe laquelle), l'audit d'exécution le capturera. C'est une propriété de l'audit
# Windows, pas de ce script — cf. collectors/windows/README.md.
$Token = $env:PLUME_TOKEN

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# --- Configuration : env > fichier plume.conf ------------------------------------------------
$ConfFile = 'C:\ProgramData\plume\plume.conf'
if ((-not $Central -or -not $Token) -and (Test-Path $ConfFile)) {
  Get-Content $ConfFile | ForEach-Object {
    if ($_ -match '^\s*([A-Z_]+)\s*=\s*(.+?)\s*$') {
      switch ($Matches[1]) {
        'PLUME_CENTRAL' { if (-not $Central) { $Central = $Matches[2] } }
        'PLUME_TOKEN'   { if (-not $Token)   { $Token   = $Matches[2] } }
      }
    }
  }
}
if (-not $Central) { throw 'PLUME_CENTRAL manquant (variable d''env ou C:\ProgramData\plume\plume.conf).' }
if (-not $Token)   { throw 'PLUME_TOKEN manquant. Sur le central : plume-daemon token <nom> <HOTE> (le 2e argument LIE le jeton a cette machine ; sans lui il faut declarer --relais, et un relais laisse usurper n''importe quel hote). A poser dans C:\ProgramData\plume\plume.conf, JAMAIS en ligne de commande.' }
$Central   = $Central.TrimEnd('/')
$StateDir  = 'C:\ProgramData\plume\state'
$HostName  = $env:COMPUTERNAME
# HORODATAGE — NE PAS revenir à `Get-Date -UFormat %s`. Sur Windows PowerShell 5.1, `%s` rend l'heure
# LOCALE exprimée comme si elle était UTC : l'epoch produit est décalé du décalage horaire de la machine.
# MESURÉ le 2026-08-02 (Windows 11 Enterprise 24H2, fuseau « Romance Standard Time ») : `%s` = epoch vrai
# + 7 201 s, soit exactement l'offset UTC (+02:00) ; la même mesure en fuseau UTC donne un écart nul —
# c'est pourquoi le défaut est resté invisible. Tous les événements arrivaient donc DEUX HEURES DANS LE
# FUTUR au central. `[DateTimeOffset]` est sans ambiguïté et indépendant du fuseau ET de la culture.
$NowEpoch  = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

# =================================================================================================
# TAMPON, LIVRAISON, ET SORTIES CLASSÉES
# -------------------------------------------------------------------------------------------------
# Ces fonctions sont définies AVANT tout le reste parce que tout le reste s'en sert pour AVOUER :
# la première ligne de collecte du fichier (réglage TLS, création du répertoire d'état) peut déjà
# échouer, et elle doit pouvoir le dire.
# =================================================================================================

# Accumulateur d'événements + envoi par lots.
$script:Events = New-Object System.Collections.ArrayList
# Preuve de livraison. `$true` dès qu'un POST n'a pas été acquitté : plus AUCUN filigrane ne sera
# commis pendant ce run (cf. Complete-Run). C'est ce drapeau qui transforme « j'ai oublié » en
# « je relirai ».
$script:DeliveryFailed = $false

function Add-Event {
  param([string]$Source, [string]$Category, [int]$Severity, [string]$Message,
        [hashtable]$Fields, [int64]$Ts = $NowEpoch, [string]$SrcIp, [string]$DstIp, [string]$Dedup)
  $o = [ordered]@{ ts = $Ts; source = $Source; category = $Category; severity = $Severity
                   message = $Message; fields = $Fields }
  if ($SrcIp) { $o.src_ip = $SrcIp }
  if ($DstIp) { $o.dst_ip = $DstIp }
  # LE NOM DE L'HÔTE EST PRÉFIXÉ ICI — ET, DEPUIS LE 2026-08-02, LE CENTRAL LE FAIT AUSSI DE SON CÔTÉ.
  # Le défaut : `event.dedup` était UNIQUE au niveau de la BASE, pas de l'hôte ; deux machines qui
  # produisaient la même clé se volaient leurs événements, la seconde étant écartée en SILENCE par
  # l'INSERT OR IGNORE du central. Les identifiants d'enregistrement du journal Windows repartent de 1
  # sur CHAQUE machine, donc la collision était certaine dès le 2e poste, et maximale au moment où le
  # SOC en a le plus besoin (l'enrôlement). MESURÉ le 2026-08-02 sur deux Windows Server 2022
  # (WS22-LAB, WS22-GUI) : sur 311 enregistrements Sysmon présents sur la 2e machine, 266 sont arrivés
  # et 45 ont disparu — exactement les 45 que la 1re machine avait déjà expédiés ; et le battement de
  # santé horaire de la 2e machine (clé `windows-agent-health-<heure>`) n'a JAMAIS été stocké.
  # LA GARANTIE N'EST PLUS ICI : le central CLOISONNE désormais `event.dedup` par l'hôte de la ligne
  # (`dedup_scoped_by_host`, daemon/src/ingest/store.rs) — parce qu'un correctif par émetteur ne tenait
  # pas (mesuré : au moins 29 formes de clé distinctes dans 30 fichiers livrés, 6 langages, plus les
  # capteurs qu'écriront les clients). Ce préfixe-ci devient donc REDONDANT, et on le GARDE : il ne coûte rien, il rend la clé
  # lisible côté poste, et un collecteur doit rester correct même branché sur un central plus ancien.
  # Ce qui reste EXIGÉ d'un émetteur : une clé STABLE pour un même événement (c'est elle qui absorbe
  # les réémissions), pas une clé qui porte l'hôte.
  if ($Dedup) { $o.dedup  = "$HostName-$Dedup" }
  $null = $script:Events.Add([pscustomobject]$o)
  if ($script:Events.Count -ge $BatchSize) { Flush-Events }
}

# Envoie le tampon. Ne VIDE le tampon qu'une fois le POST ACQUITTÉ ; un échec LÈVE.
#
# POURQUOI LEVER PLUTÔT QU'AVERTIR. La version précédente attrapait l'échec, écrivait un
# `Write-Warning`, puis vidait le tampon INCONDITIONNELLEMENT — et le filigrane avait déjà avancé.
# Sous tâche planifiée, un `Write-Warning` ne va NULLE PART : la perte était silencieuse ET
# définitive (mesuré : 42/42). Lever fait deux choses qu'aucun drapeau ne fait : le run s'arrête
# donc `Complete-Run` ne commet AUCUN filigrane (le journal Windows reste le spool), et le code de
# retour non nul est ENREGISTRÉ par le planificateur de tâches (`LastTaskResult`), donc l'échec
# devient une chose qu'un opérateur peut voir.
function Flush-Events {
  if ($script:Events.Count -eq 0) { return }
  $envelope = [ordered]@{ ts = $NowEpoch; host = $HostName; kind = 'events'; events = @($script:Events) }
  $body = $envelope | ConvertTo-Json -Depth 6 -Compress
  $n = $script:Events.Count
  try {
    Invoke-RestMethod -Uri "$Central/api/ingest" -Method Post -TimeoutSec 20 `
      -Headers @{ Authorization = "Bearer $Token" } -ContentType 'application/json' -Body $body | Out-Null
  } catch {
    $script:DeliveryFailed = $true
    throw "POST /api/ingest a échoué ($n événement(s) NON livrés — aucun filigrane ne sera commis, le run suivant relira) : $($_.Exception.Message)"
  }
  $script:Events.Clear()
}

# --- Sorties CLASSÉES — miroir PowerShell de `collectors/lib.sh` -------------------------------
# La partition est la MÊME, et elle est fermée : (I) incapacité, (II) désactivé, (III) rien de neuf.
# Seuls (I) et (II) sont des MENSONGES quand ils sont muets ; (III) est un silence honnête.
# Le format d'événement est celui de `plume_report_availability` — AUCUNE nouvelle catégorie, aucun
# nouveau champ : la règle `config.d/rules/catalog/de-collector-unavailable.json` (elle interroge
# `category=config collect_status=unavailable`) couvre donc Windows sans être touchée.
# DÉDUP : bucket HORAIRE, comme côté Linux — un capteur cadencé à 5 min qui reste incapable écrit
# ~24 lignes/jour au lieu de 288, tout en RÉ-AFFIRMANT son incapacité chaque heure.
$script:PlumeReasons = @('missing-dependency','missing-source','missing-config','subsystem-absent','unreachable','disabled')

function Plume-Report-Availability {
  param([string]$Source, [string]$Status, [string]$Reason, [string]$Detail, [int]$Severity)
  Add-Event -Source $Source -Category 'config' -Severity $Severity `
    -Message "capteur $Source $Status : $Reason — $Detail" `
    -Fields @{ type='collector-availability'; collector=$Source; collect_status=$Status; reason=$Reason; detail=$Detail } `
    -Dedup "avail-$Source-$Reason-$([int]($NowEpoch/3600))"
}

# (I) PRÉREQUIS ABSENT / SOURCE ILLISIBLE. Sévérité 2 : ce n'est pas une attaque, c'est un TROU DE
# COUVERTURE. La raison est validée contre le vocabulaire FERMÉ — une raison inventée LÈVE, elle ne
# se glisse pas dans la base en prose libre.
function Plume-Unavailable {
  param([string]$Source, [string]$Reason, [string]$Detail = '')
  if ($script:PlumeReasons -notcontains $Reason) {
    throw "Plume-Unavailable : raison '$Reason' hors vocabulaire fermé ($($script:PlumeReasons -join ', '))"
  }
  Plume-Report-Availability -Source $Source -Status 'unavailable' -Reason $Reason -Detail $Detail -Severity 2
}

# (II) COUPÉ PAR L'OPÉRATEUR. Sévérité 1 : c'est un CHOIX, pas une panne ; mais il reste DIT.
# Aucun appelant aujourd'hui (ce collecteur n'a pas d'interrupteur par source) — et c'est
# exactement la raison de l'écrire : sans elle, l'auteur du premier capteur Windows à interrupteur
# n'aurait aucune primitive correcte, et la garde lui refuserait le `catch` muet : on l'aurait
# poussé à ranger son cas en « rien de neuf », c'est-à-dire à mentir.
function Plume-Disabled {
  param([string]$Source, [string]$Detail = '')
  Plume-Report-Availability -Source $Source -Status 'disabled' -Reason 'disabled' -Detail $Detail -Severity 1
}

# (III) RIEN DE NEUF. N'émet RIEN, volontairement : le battement de santé couvre déjà la liveness et
# l'IHM sait dire « calme ». La fonction n'existe QUE pour porter un NOM — c'est ce nom qui prouve, à
# la relecture comme à la CI, que le silence est ici un CHOIX et non un oubli.
function Plume-NoData {
  param([string]$Source)
  $null = $Source
}

# Traduit l'échec d'une lecture de journal en cas de la partition. Le discriminant est
# `FullyQualifiedErrorId`, JAMAIS le message : les messages de Windows sont LOCALISÉS (un Windows
# français dit « Aucun événement… »), et une garde qui lirait le texte classerait une vraie cécité en
# « rien de neuf » dès que la machine n'est pas anglophone — précisément le mensonge qu'on ferme ici.
# La partition penche du côté SÛR : SEUL `NoMatchingEventsFound` vaut « rien de neuf » ; tout le
# reste — y compris un identifiant que Microsoft renommerait demain — est déclaré INCAPACITÉ. Se
# tromper coûte alors un aveu de trop, jamais un angle mort.
# NON MESURÉ SUR UN VRAI WINDOWS (aucune VM allumée) : les identifiants viennent de la documentation
# du cmdlet et sont exercés par le harnais ; le SENS de l'erreur, lui, ne dépend pas d'eux.
function Get-WinEventFailureKind {
  param($ErrorRecord)
  $id = ''
  if ($null -ne $ErrorRecord -and $ErrorRecord.PSObject.Properties['FullyQualifiedErrorId']) {
    $id = [string]$ErrorRecord.FullyQualifiedErrorId
  }
  if ($id -like 'NoMatchingEventsFound*') { return 'nodata' }
  if ($id -like 'NoMatchingLogsFound*' -or $id -like '*LogNotFound*') { return 'subsystem-absent' }
  return 'missing-source'
}

# Même traduction pour une cmdlet d'inventaire (pare-feu, réseau, CIM) : cmdlet absente du poste =
# dépendance manquante, tout le reste = le sous-système est là mais n'a pas répondu.
function Get-CmdletFailureReason {
  param($ErrorRecord)
  $id = ''
  if ($null -ne $ErrorRecord -and $ErrorRecord.PSObject.Properties['FullyQualifiedErrorId']) {
    $id = [string]$ErrorRecord.FullyQualifiedErrorId
  }
  if ($id -like 'CommandNotFoundException*') { return 'missing-dependency' }
  return 'subsystem-absent'
}

# =================================================================================================
# FILIGRANES — CALCULÉS PARTOUT, ÉCRITS À UN SEUL ENDROIT
# =================================================================================================

# Le SEUL constructeur de chemin de filigrane du fichier. La garde de CI exige que le littéral
# `.watermark` n'apparaisse qu'ici : un futur capteur ne peut donc pas se fabriquer son propre
# chemin d'état, et toute écriture de filigrane passe forcément par le point de commit unique.
function Get-WatermarkPath {
  param([string]$Name)
  Join-Path $StateDir "$Name.watermark"
}

# Filigranes MIS EN ATTENTE pendant le run ; commis (ou non) par Complete-Run.
$script:PendingWatermarks = @{}

# Filigrane par source (dernier TimeCreated traité, ISO 8601).
#
# BORNE AU PRÉSENT, des DEUX côtés. Un seul enregistrement daté du FUTUR dans le journal Windows suffit
# sinon à rendre la source AVEUGLE, DÉFINITIVEMENT et EN SILENCE : le filigrane prend cette date, le
# `StartTime` de la requête suivante est dans le futur, `Get-WinEvent` ne renvoie rien, lève, et le
# `catch` plus bas avale l'erreur. MESURÉ le 2026-08-02 (Windows 11 Enterprise 24H2) : des 4624/4688
# écrits pendant l'installation portaient une heure décalée de ~6 h ; après un run, `win-auth`,
# `win-process` et `win-account` avaient tous un filigrane à +6 h, et le run suivant a expédié
# ZÉRO événement en sortant 0 sans un mot — `category=exec` est resté figé à 59 alors que 12 nouveaux
# 4688 attendaient dans le journal. Le seul remède était de supprimer l'état à la main.
# Les horloges reculent (VM restaurée, resynchronisation NTP, RTC en heure locale) : ce cas n'est pas
# théorique, et il ne doit pas coûter la visibilité de l'hôte.
function Get-Watermark {
  param([string]$Name, [string]$Source)
  $f = Get-WatermarkPath $Name
  $floor = (Get-Date).AddMinutes(-$MaxAgeMinutes)
  if (Test-Path $f) {
    try {
      $wm = [datetime]::Parse((Get-Content $f -Raw))
      # Filigrane dans le futur -> il ne peut venir que d'une horloge fausse : on le ramène au plancher
      # de rattrapage au lieu de rester aveugle.
      if ($wm -gt (Get-Date)) { return $floor }
      return $wm
    } catch {
      # Un état illisible n'est pas « rien de neuf » : le capteur repart au plancher, donc il a
      # potentiellement un TROU entre le plancher et le dernier filigrane valide. Ça se dit.
      Plume-Unavailable $Source 'missing-source' "filigrane $Name illisible ($($_.Exception.Message)) — rattrapage borné à $MaxAgeMinutes min"
    }
  }
  return $floor
}

# MET EN ATTENTE (n'écrit rien). Le nom est délibérément différent de l'ancien `Set-Watermark` :
# un appel resté en arrière lèverait « commande introuvable » au lieu d'écrire en douce.
function Stage-Watermark {
  param([string]$Name, [datetime]$Value)
  # Ne jamais mettre en attente un filigrane futur : on plafonne à maintenant.
  $now = Get-Date
  if ($Value -gt $now) { $Value = $now }
  $script:PendingWatermarks[$Name] = $Value
}

# FIN DE RUN — le SEUL point du fichier qui écrive un filigrane sur le disque.
# L'ORDRE EST INTERNE À CETTE FONCTION, et c'est le point : un appelant ne peut pas se tromper
# d'ordre, parce qu'il n'a pas les deux gestes à sa disposition. On livre, PUIS on oublie.
function Complete-Run {
  Flush-Events
  if ($script:DeliveryFailed) { return }
  $failed = @()
  foreach ($name in @($script:PendingWatermarks.Keys)) {
    try {
      Set-Content -Path (Get-WatermarkPath $name) -Value $script:PendingWatermarks[$name].ToString('o') -NoNewline
    } catch {
      $failed += $name
      Plume-Unavailable 'windows-agent' 'missing-source' "filigrane $name non persistable dans $StateDir ($($_.Exception.Message)) — le run suivant réexpédiera"
    }
  }
  if ($failed.Count -gt 0) { Flush-Events }
}

# =================================================================================================
# À PARTIR D'ICI, TOUT PEUT AVOUER
# =================================================================================================

# TLS : vérifié par défaut ; opt-out explicite de test seulement.
if ($env:PLUME_TLS_INSECURE -eq '1') {
  try { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } }
  catch { Plume-Unavailable 'windows-agent' 'missing-config' "PLUME_TLS_INSECURE demandé mais non applicable sur cet hôte ($($_.Exception.Message)) — la vérification TLS reste ACTIVE" }
}
try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 }
catch { Plume-Unavailable 'windows-agent' 'missing-config' "TLS 1.2 non imposable sur cet hôte ($($_.Exception.Message))" }

# Répertoire d'état. S'il n'est pas créable, les filigranes ne seront pas persistables : chaque run
# rattrapera $MaxAgeMinutes et réexpédiera (dédoublonné côté central). Ce n'est pas une perte, mais
# ce n'est pas normal — donc ça se dit.
try { $null = New-Item -ItemType Directory -Force -Path $StateDir }
catch { Plume-Unavailable 'windows-agent' 'missing-source' "répertoire d'état $StateDir non créable ($($_.Exception.Message)) — aucun filigrane ne sera persisté" }

# Extrait EventData (Name -> Value) depuis le XML d'un événement (robuste, indépendant de l'ordre).
function Get-EventData {
  param($Evt, [string]$Source)
  $h = @{}
  try {
    $xml = [xml]$Evt.ToXml()
    foreach ($d in $xml.Event.EventData.Data) {
      if ($d.Name) { $h[$d.Name] = [string]$d.'#text' }
    }
  } catch {
    # L'événement est bien là, mais son contenu ne se lit pas : les champs métier (utilisateur,
    # ligne de commande, port…) manqueront. Deduplé à l'heure, donc au plus un aveu par heure.
    Plume-Unavailable $Source 'subsystem-absent' "EventData illisible sur au moins un enregistrement ($($_.Exception.Message)) — champs métier absents"
  }
  return $h
}

# P4.12-a — UNE SEULE FRONTIÈRE D'ADRESSE, POUR TOUS LES SITES DE CE CAPTEUR.
#
# CE QUI ÉTAIT FAUX, MESURÉ le 2026-08-29. La frontière n'existait qu'au site d'AUTHENTIFICATION
# (`$sip -eq '-' -or ...`), et nulle part ailleurs. Le site WFP passait `$d['SourceAddress']` /
# `$d['DestAddress']` DIRECTEMENT à `Add-Event`, dont le seul test est la véracité PowerShell
# (`if ($SrcIp)`) — or `'-'`, `'0.0.0.0'` et `'127.0.0.1'` sont tous VRAIS. Conséquences, sur des
# enregistrements banals :
#   · une connexion en boucle locale bloquée (5157, `SourceAddress='127.0.0.1'`) fabriquait une
#     entité `127.0.0.1` PARTAGÉE PAR TOUT LE PARC — le « seau unique » que la colonne d'adresse est
#     censée défaire ;
#   · un DHCP DISCOVER bloqué (5152) écrivait `src_ip=0.0.0.0` et `dst_ip=255.255.255.255` sur chaque
#     poste, à chaque bail.
# Et l'écart n'est pas seulement interne à ce fichier : `agent/src/source/windows.rs`, le SECOND
# capteur Windows livré, écarte ces valeurs depuis le MÊME jour où il s'est mis à peupler la colonne —
# le MÊME enregistrement rendrait donc une entité par un capteur et AUCUNE par l'autre, exactement le
# défaut que
# `.github/scripts/check_a_windows_sensor_promotes_the_address_it_carries.py` s'intitule rendre
# non-écrivable (et sur lequel elle était VERTE : elle ne lisait la frontière QUE sur le chemin
# d'authentification). La garde lit désormais CHAQUE site de promotion et REFUSE d'en voir un qui ne
# passe pas par cette fonction.
#
# LA BORNE DE CETTE FRONTIÈRE, DITE : elle compare des CHAÎNES. Elle ne REPLIE donc pas
# `::ffff:203.0.113.7` sur `203.0.113.7` comme le fait l'agent (`valeur_exploitable`, analyse par
# `IpAddr`) : deux écritures de la même machine restent deux entités ici. Le repli demanderait un
# analyseur .NET (`[System.Net.IPAddress]`, `IsIPv4MappedToIPv6`) dont l'absence sur une version
# ancienne du cadriciel LÈVE sous le `Set-StrictMode -Version 2.0` de ce fichier, et aucun `pwsh`
# n'existe sur le poste où ce lot est écrit pour l'éprouver. L'écart est donc ASSUMÉ, IMPRIMÉ par la
# garde, et porté par `P4.12-c` — pas caché.
function Adresse-Exploitable {
  param([string]$Valeur)
  $v = "$Valeur".Trim()
  if (-not $v) { return $null }
  if ($v -in @('-', '127.0.0.1', '::1', '::ffff:127.0.0.1', '0.0.0.0', '::', '255.255.255.255', '224.0.0.251', 'ff02::1')) { return $null }
  return $v
}

# Sévérité par EventID (défaut 1 = info-bas).
function Sev-For([int]$id) {
  switch ($id) {
    4625 { 2 } 4740 { 3 } 4672 { 2 } 4720 { 2 } 4726 { 2 } 4732 { 2 } 4756 { 2 }
    4768 { 1 } 4769 { 1 } 4771 { 2 } 4776 { 1 }
    5152 { 1 } 5157 { 2 } 6008 { 3 } 7031 { 2 } 7034 { 2 } 7000 { 2 }
    1116 { 4 } 1015 { 4 } 1006 { 4 } 1117 { 3 }
    default { 1 }
  }
}

# =================================================================================================
# L'ISSUE N'EST PAS UNE OPTION — ET LA LISTE D'IDENTIFIANTS EN EST DÉRIVÉE
# -------------------------------------------------------------------------------------------------
# `fields.action` porte l'OUTCOME normalisé du CIM : c'est LUI que les détections cross-source
# interrogent. Les deux règles de brute-force LIVRÉES (« Brute-force auth par IP » et « RBA :
# brute-force d'authentification », toutes deux T1110, activées) compilent
# `category=auth action=failure`.
# MESURÉ le 2026-08-02, trois échecs d'ouverture de session Windows (4625) réellement ingérés à la
# forme des DEUX émetteurs livrés : `search category=auth | stats count by source` rendait
# `windows-security 2 · WinEventLog:Security 1 · sudo 366`, et `search category=auth action=failure
# | stats count by source` rendait **sudo 17 et RIEN pour Windows**. Les échecs étaient en base ; la
# règle qui prétend les détecter n'en voyait aucun.
#
# CE QUI CHANGE STRUCTURELLEMENT : `Collect-Log` ne prend plus de liste d'identifiants. Il prend une
# table `identifiant -> issue`, et la liste des identifiants collectés en est DÉRIVÉE (`.Keys`). On
# ne peut donc plus collecter un identifiant sans dire ce qu'il vaut ; et une issue hors du
# vocabulaire fermé LÈVE au lieu de se glisser en base en prose libre. La garde de CI
# (`check_windows_collector_is_honest.py`) refuse en plus tout appel qui passerait `-Ids` en dur.
# =================================================================================================

# Vocabulaire FERMÉ des issues acceptées. `'-'` = « cet enregistrement ne porte pas d'issue » : c'est
# une DÉCLARATION qu'il faut écrire, pas un oubli qui passe. `'@status'` = « l'issue n'est pas dans
# l'identifiant mais dans le code de statut de l'enregistrement » (Kerberos/NTLM).
# Les mots réels appartiennent au vocabulaire NEUTRE `action_vocab` du CIM (config.d/cim/cim.v1.json).
$script:PlumeOutcomes = @('success','failure','session_open','session_close','allowed','blocked','-','@status')

# Résout `@status` : `Status` (Kerberos 4768/4769/4771) ou `Error Code` (NTLM 4776) valent 0x0 en cas
# de succès. ABSENT ou ILLISIBLE -> `failure` : on ne déclare pas un succès qu'on n'a pas lu (un faux
# `success` fabriquerait un angle mort sur la détection de brute-force ; un faux `failure` fait du bruit).
function Resolve-StatusOutcome {
  param([hashtable]$Data, [string]$Source)
  $raw = $null
  foreach ($k in @('Status','Error Code','ErrorCode')) { if (-not $raw -and $Data.ContainsKey($k)) { $raw = [string]$Data[$k] } }
  if (-not $raw) { return 'failure' }
  $raw = $raw.Trim()
  try {
    if ($raw -match '^0[xX]([0-9a-fA-F]+)$') { if ([Convert]::ToInt64($Matches[1],16) -eq 0) { return 'success' } else { return 'failure' } }
    if ([int64]$raw -eq 0) { return 'success' }
  } catch {
    # Un code de statut illisible n'est pas un succès. On le DIT (l'issue restera `failure`), sinon un
    # format inattendu de Windows silencierait la moitié du prédicat de détection.
    Plume-Unavailable $Source 'subsystem-absent' "code de statut d'authentification illisible ('$raw') — issue prise pour un échec"
  }
  return 'failure'
}

# RECENSEMENT DE COUVERTURE — ce que le canal a produit et que ce collecteur NE COLLECTE PAS.
# Une table d'identifiants EST un filtre, et un filtre non déclaré est un angle mort : sur un
# contrôleur de domaine promu le 2026-08-02, 2×4768 et 8×4769 ont été écrits dans `Security` et le
# collecteur en a remonté 0, sans un mot. Ajouter les quatre identifiants manquants n'aurait fermé
# que CE trou-là. Le recensement, lui, ne dépend d'aucune liste : il DEMANDE au canal ce qu'il a
# produit sur la MÊME fenêtre, et déclare la différence. Un identifiant nouveau (nouvelle version de
# Windows, nouveau rôle, nouvelle sous-catégorie d'audit activée) apparaît donc tout seul.
# Le recensement est BORNÉ (`$CensusMaxEvents`) et il DIT quand il a été borné (`census_capped`) :
# un recensement qui se croirait complet mentirait à son tour.
$script:CensusScope = @{}   # canal -> @{ ids = @{}; since = <datetime> }

function Declare-Collected {
  param([string]$LogName, [int[]]$Ids, [datetime]$Since)
  if (-not $script:CensusScope.ContainsKey($LogName)) { $script:CensusScope[$LogName] = @{ ids = @{}; since = $Since } }
  $sc = $script:CensusScope[$LogName]
  foreach ($i in $Ids) { $sc.ids[[int]$i] = $true }
  if ($Since -lt $sc.since) { $sc.since = $Since }
}

# Collecte générique d'un journal, avec filigrane. `$Outcomes` = table identifiant -> issue ;
# la liste des identifiants interrogés en est DÉRIVÉE.
function Collect-Log {
  param([string]$Name, [string]$LogName, [hashtable]$Outcomes, [string]$Source, [string]$Category)
  if (-not $Outcomes -or $Outcomes.Count -eq 0) {
    throw "Collect-Log '$Name' : aucune table d'issues. Un identifiant collecté sans issue déclarée laisse fields.action vide, donc invisible aux règles qui interrogent action=..."
  }
  foreach ($k in $Outcomes.Keys) {
    if ($script:PlumeOutcomes -notcontains [string]$Outcomes[$k]) {
      throw "Collect-Log '$Name' : issue '$($Outcomes[$k])' (identifiant $k) hors vocabulaire fermé ($($script:PlumeOutcomes -join ', '))"
    }
  }
  $ids = @($Outcomes.Keys | ForEach-Object { [int]$_ })
  $since = Get-Watermark -Name $Name -Source $Source
  Declare-Collected -LogName $LogName -Ids $ids -Since $since
  $filter = @{ LogName = $LogName; StartTime = $since; Id = $ids }
  $max = $since
  try {
    $evts = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
  } catch {
    # Journal absent / accès refusé / aucun événement : TROIS choses différentes, qui étaient
    # indiscernables vues du SOC. On les sépare (cf. Get-WinEventFailureKind).
    $kind = Get-WinEventFailureKind $_
    if ($kind -eq 'nodata') { Plume-NoData $Source }
    else { Plume-Unavailable $Source $kind "canal '$LogName' illisible ($($_.Exception.Message))" }
    return
  }
  # P5.4-b — `exec` SANS ligne de commande a l'air complet et ne l'est pas. Sans la GPO « Include
  # command line in process creation events » (et sans Sysmon, qui peuple `CommandLine` dans son
  # propre schéma, hors audit Windows), un 4688 arrive sans `CommandLine` : l'événement paraît entier,
  # et toute règle/recherche qui filtre sur la ligne de commande rend zéro sans savoir pourquoi.
  # On COMPTE, et on le déclare en fin de run (jamais on n'invente une valeur).
  $cmdlinePresent = 0; $cmdlineAbsent = 0
  foreach ($e in ($evts | Sort-Object TimeCreated)) {
    if ($e.TimeCreated -le $since) { continue }
    if ($e.TimeCreated -gt $max) { $max = $e.TimeCreated }
    $d = Get-EventData -Evt $e -Source $Source
    $id = [int]$e.Id
    $sev = Sev-For $id
    $msg = ($e.Message -split "`r?`n")[0]
    if (-not $msg) { $msg = "$Source event $id" }
    $fields = @{ event_id = $id; provider = $e.ProviderName; level = "$($e.LevelDisplayName)"
                 record_id = $e.RecordId; channel = $LogName }
    $issue = [string]$Outcomes[$id]
    if ($issue -eq '@status') { $issue = Resolve-StatusOutcome -Data $d -Source $Source }
    if ($issue -ne '-') { $fields['action'] = $issue }
    if ($id -eq 4688) { if ($d.ContainsKey('CommandLine') -and $d['CommandLine']) { $cmdlinePresent++ } else { $cmdlineAbsent++ } }
    foreach ($k in $d.Keys) { if ($d[$k] -and -not $fields.ContainsKey($k)) { $fields[$k] = $d[$k] } }
    $sip = Adresse-Exploitable $d['IpAddress']
    $ded = "$Source-$($e.RecordId)"
    Add-Event -Source $Source -Category $Category -Severity $sev -Message $msg -Fields $fields `
              -Ts (To-Epoch $e.TimeCreated) -SrcIp $sip -Dedup $ded
  }
  if ($cmdlinePresent + $cmdlineAbsent -gt 0) {
    Report-ExecCompleteness -Source $Source -Present $cmdlinePresent -Absent $cmdlineAbsent
  }
  Stage-Watermark -Name $Name -Value $max
}

# P5.4-b — DÉCLARE l'incomplétude de `exec`. Sévérité 2 (trou de couverture, pas une attaque), même
# famille que `Plume-Unavailable` : le capteur COLLECTE, mais il sait que ce qu'il rend est amputé.
# Dédup horaire, comme les aveux d'indisponibilité.
function Report-ExecCompleteness {
  param([string]$Source, [int]$Present, [int]$Absent)
  if ($Absent -le 0) { return }
  Add-Event -Source $Source -Category 'config' -Severity 2 `
    -Message "exec incomplet : $Absent creation(s) de processus sans ligne de commande sur $($Present + $Absent) — activez l'audit 'Include command line in process creation events' (GPO) ou Sysmon" `
    -Fields @{ type='collector-coverage'; collector=$Source; gap='exec-cmdline'
               cmdline_absent=$Absent; cmdline_present=$Present } `
    -Dedup "coverage-cmdline-$Source-$([int]($NowEpoch/3600))"
}

# RECENSEMENT — émet, par canal interrogé, ce que le canal a produit et qui n'est PAS collecté.
# Ne LÈVE jamais le run : un recensement en échec est un aveu d'indisponibilité, pas une perte.
$CensusMaxEvents = 5000
function Report-Coverage {
  param([string]$Source)
  foreach ($LogName in @($script:CensusScope.Keys)) {
    $sc = $script:CensusScope[$LogName]
    try {
      $all = Get-WinEvent -FilterHashtable @{ LogName = $LogName; StartTime = $sc.since } -MaxEvents $CensusMaxEvents -ErrorAction Stop
    } catch {
      $kind = Get-WinEventFailureKind $_
      if ($kind -eq 'nodata') { Plume-NoData $Source }
      else { Plume-Unavailable $Source $kind "recensement de couverture impossible sur '$LogName' ($($_.Exception.Message))" }
      continue
    }
    $manquants = @{}
    $vus = 0
    foreach ($e in $all) {
      $vus++
      $id = [int]$e.Id
      if (-not $sc.ids.ContainsKey($id)) { $manquants[$id] = 1 + ($(if ($manquants.ContainsKey($id)) { $manquants[$id] } else { 0 })) }
    }
    $capped = [int]($vus -ge $CensusMaxEvents)
    $liste = (($manquants.Keys | Sort-Object) -join ',')
    $total = 0; foreach ($v in $manquants.Values) { $total += $v }
    $sev = $(if ($total -gt 0) { 2 } else { 0 })
    Add-Event -Source $Source -Category 'config' -Severity $sev `
      -Message "couverture $LogName : $total evenement(s) non collecte(s) sur $vus, identifiants [$liste]" `
      -Fields @{ type='collector-coverage'; collector=$Source; gap='channel-ids'; channel=$LogName
                 uncollected_ids=$liste; uncollected_events=$total; census_seen=$vus
                 collected_ids=((($sc.ids.Keys | Sort-Object) -join ',')); census_capped=$capped } `
      -Dedup "coverage-ids-$Source-$LogName-$([int]($NowEpoch/3600))"
  }
}

# Epoch (s) depuis un DateTime.
function To-Epoch([datetime]$dt) { [DateTimeOffset]::new($dt.ToUniversalTime(), [TimeSpan]::Zero).ToUnixTimeSeconds() }

# --- 1) Journal Security : auth / exec / account --------------------------------------------
# (Le journal Security exige des droits élevés : exécuter en SYSTEM ou administrateur.)
# CIM : la création de processus (4688) porte `exec`, le nom CANONIQUE de la taxonomie v1.3
# (`CIM_CATEGORIES`, guatx-core). Elle a porté `process` — un nom HORS taxonomie — jusqu'au
# 2026-07-23 ; les événements de cette période sont retrouvés par l'alias de LECTURE du daemon
# (cf. `cim_read_alias_exec`, soql_glue.rs) et non par une réécriture de données.
# KERBEROS/NTLM : sur un CONTRÔLEUR DE DOMAINE, l'authentification de TOUT le parc passe par 4768
# (ticket TGT), 4769 (ticket de service), 4771 (échec de pré-authentification) et 4776 (validation
# NTLM). MESURÉ le 2026-08-02 après promotion d'un WS22-GUI en DC : une création de compte et deux
# authentifications ont écrit 2×4768 et 8×4769 dans `Security` ; le collecteur en a remonté 0.
# 4768/4769/4776 sont écrits AUSSI BIEN en succès qu'en échec -> `@status` (l'issue est dans le code
# de statut, pas dans l'identifiant) ; 4771 ne s'écrit QUE sur échec -> `failure`, dit en clair. Et pour que le PROCHAIN trou ne dorme pas jusqu'au prochain
# relecteur, `Report-Coverage` déclare, à chaque run, ce que le canal produit et qui n'est pas ici.
Collect-Log -Name 'win-auth'    -LogName 'Security' -Source 'windows-security' -Category 'auth' -Outcomes @{
  4624 = 'session_open'; 4625 = 'failure'; 4634 = 'session_close'; 4672 = 'success'; 4740 = '-'
  4768 = '@status';      4769 = '@status'; 4771 = 'failure';       4776 = '@status'
}
# 4688 n'est écrit QUE lorsque le processus a été créé -> `success`, ce qui aligne `category=exec` sur le
# flux Linux (`collectors/auditd.sh` rend `action=failure` quand l'`execve` échoue).
Collect-Log -Name 'win-process' -LogName 'Security' -Source 'windows-security' -Category 'exec' -Outcomes @{
  4688 = 'success'
}
Collect-Log -Name 'win-account' -LogName 'Security' -Source 'windows-security' -Category 'account' -Outcomes @{
  4720 = 'success'; 4722 = 'success'; 4724 = 'success'; 4726 = 'success'; 4732 = 'success'; 4756 = 'success'
}

# --- 2) Pare-feu Windows : connexions bloquées (WFP) + état des profils ----------------------
# 5152 = paquet bloqué, 5157 = connexion bloquée (audit « Filtering Platform Connection »).
$fwSince = Get-Watermark -Name 'win-firewall' -Source 'windows-firewall'
$fwMax = $fwSince
Declare-Collected -LogName 'Security' -Ids @(5152,5157) -Since $fwSince
try {
  $fw = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=@(5152,5157); StartTime=$fwSince } -ErrorAction Stop
  foreach ($e in ($fw | Sort-Object TimeCreated)) {
    if ($e.TimeCreated -le $fwSince) { continue }
    if ($e.TimeCreated -gt $fwMax) { $fwMax = $e.TimeCreated }
    $d = Get-EventData -Evt $e -Source 'windows-firewall'
    # 5152 = paquet BLOQUÉ, 5157 = connexion BLOQUÉE : l'issue est dans la définition même de
    # l'identifiant -> `blocked`, le mot NEUTRE du CIM. Sans lui, `category=firewall action=blocked`
    # (la forme portable d'une règle de filtrage) ne rendait rien sur Windows.
    $fields = @{ event_id=[int]$e.Id; action='blocked'; direction=$d['Direction']; protocol=$d['Protocol']
                 app=$d['Application']; src_port=$d['SourcePort']; dst_port=$d['DestPort']
                 record_id=$e.RecordId }
    Add-Event -Source 'windows-firewall' -Category 'firewall' -Severity (Sev-For ([int]$e.Id)) `
      -Message "pare-feu: connexion bloquée ($($d['Direction'])) $($d['SourceAddress']):$($d['SourcePort']) -> $($d['DestAddress']):$($d['DestPort']) [$($d['Protocol'])]" `
      -Fields $fields -Ts (To-Epoch $e.TimeCreated) -SrcIp (Adresse-Exploitable $d['SourceAddress']) -DstIp (Adresse-Exploitable $d['DestAddress']) `
      -Dedup "windows-firewall-$($e.RecordId)"
  }
  Stage-Watermark -Name 'win-firewall' -Value $fwMax
} catch {
  $kind = Get-WinEventFailureKind $_
  if ($kind -eq 'nodata') { Plume-NoData 'windows-firewall' }
  else { Plume-Unavailable 'windows-firewall' $kind "5152/5157 illisibles dans 'Security' ($($_.Exception.Message))" }
}
# État des profils pare-feu (config, envoyé à chaque run comme signal de santé/config).
try {
  foreach ($p in (Get-NetFirewallProfile -ErrorAction Stop)) {
    Add-Event -Source 'windows-firewall' -Category 'firewall' -Severity $(if ($p.Enabled) { 0 } else { 3 }) `
      -Message "profil pare-feu $($p.Name): enabled=$($p.Enabled) inbound=$($p.DefaultInboundAction)" `
      -Fields @{ profile=$p.Name; enabled=[bool]$p.Enabled; inbound="$($p.DefaultInboundAction)"; outbound="$($p.DefaultOutboundAction)" } `
      -Dedup "windows-fwprofile-$($p.Name)-$([int]($NowEpoch/3600))"
  }
} catch {
  Plume-Unavailable 'windows-firewall' (Get-CmdletFailureReason $_) "état des profils illisible ($($_.Exception.Message))"
}

# --- 3) Journal System : arrêts inattendus, échecs de service --------------------------------
Collect-Log -Name 'win-system' -LogName 'System' -Source 'windows-system' -Category 'system' -Outcomes @{
  6008 = 'failure'; 7000 = 'failure'; 7031 = 'failure'; 7034 = 'failure'
}

# --- 4) Microsoft Defender : détections ------------------------------------------------------
# 1117 = une action a été PRISE sur la menace -> `blocked`. 1006/1015/1116 sont des CONSTATS de
# détection sans verdict d'action : `'-'` est écrit exprès, pour ne pas annoncer une remédiation
# qui n'a pas eu lieu.
Collect-Log -Name 'win-defender' -LogName 'Microsoft-Windows-Windows Defender/Operational' `
            -Source 'windows-defender' -Category 'malware' -Outcomes @{
  1006 = '-'; 1015 = '-'; 1116 = '-'; 1117 = 'blocked'
}

# --- 5) Réseau : connexions TCP établies (distantes) + ports en écoute -----------------------
# Instantané périodique (pas de filigrane) ; dédup par tuple dans l'heure.
$procById = @{}
try {
  Get-Process -ErrorAction Stop | ForEach-Object { $procById[$_.Id] = $_.ProcessName }
} catch {
  # Non bloquant : les connexions restent collectées, sans le nom du processus.
  Plume-Unavailable 'windows-network' (Get-CmdletFailureReason $_) "table des processus illisible ($($_.Exception.Message)) — les connexions partiront sans le nom du processus"
}
$bucket = [int]($NowEpoch / 3600)
try {
  Get-NetTCPConnection -State Established -ErrorAction Stop | Where-Object {
    $_.RemoteAddress -and $_.RemoteAddress -notin @('127.0.0.1','::1','0.0.0.0','::')
  } | ForEach-Object {
    $pname = $procById[[int]$_.OwningProcess]
    Add-Event -Source 'windows-network' -Category 'network' -Severity 0 `
      -Message "tcp établi $($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort) ($pname)" `
      -Fields @{ local_port=$_.LocalPort; remote_port=$_.RemotePort; state="$($_.State)"; process=$pname; pid=[int]$_.OwningProcess } `
      -SrcIp $_.LocalAddress -DstIp $_.RemoteAddress `
      -Dedup "windows-net-$($_.RemoteAddress)-$($_.RemotePort)-$bucket"
  }
} catch {
  Plume-Unavailable 'windows-network' (Get-CmdletFailureReason $_) "connexions TCP établies illisibles ($($_.Exception.Message))"
}
try {
  Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object {
    $_.LocalAddress -notin @('127.0.0.1','::1')
  } | ForEach-Object {
    $pname = $procById[[int]$_.OwningProcess]
    Add-Event -Source 'windows-network' -Category 'network' -Severity 0 `
      -Message "port en écoute $($_.LocalAddress):$($_.LocalPort) ($pname)" `
      -Fields @{ local_port=$_.LocalPort; state='Listen'; process=$pname; pid=[int]$_.OwningProcess } `
      -SrcIp $_.LocalAddress -Dedup "windows-listen-$($_.LocalPort)-$bucket"
  }
} catch {
  Plume-Unavailable 'windows-network' (Get-CmdletFailureReason $_) "ports en écoute illisibles ($($_.Exception.Message))"
}

# --- Heartbeat (dead-man's-switch) + envoi final ---------------------------------------------
# `os` est un ORNEMENT du battement, pas le battement. Il était lu par
# `(Get-CimInstance … -ErrorAction SilentlyContinue).Caption` : dépôt WMI cassé (panne Windows
# banale) -> la cmdlet ne rend RIEN -> sous `Set-StrictMode -Version 2.0`, `.Caption` sur $null
# LÈVE, hors de tout try/catch, et le run mourait AVANT le POST final. MESURÉ le 2026-08-02 :
# 12 événements collectés, 0 POST tenté, filigrane déjà écrit — 12 perdus. Un ornement ne doit pas
# pouvoir tuer un battement de coeur.
$osCaption = ''
try {
  $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
  if ($null -ne $osInfo) { $osCaption = [string]$osInfo.Caption }
} catch {
  Plume-Unavailable 'windows-agent' (Get-CmdletFailureReason $_) "Win32_OperatingSystem illisible ($($_.Exception.Message)) — battement émis sans le nom de l'OS"
}
Add-Event -Source 'windows-agent' -Category 'health' -Severity 0 -Message 'plume windows collector ok' `
          -Fields @{ os = $osCaption; collector='windows' } `
          -Dedup "windows-agent-health-$([int]($NowEpoch/3600))"
# CE QUE CE COLLECTEUR NE COLLECTE PAS, DIT PAR LE CANAL LUI-MÊME. Émis APRÈS toute la collecte
# (les portées de recensement sont enregistrées au fil des `Collect-Log`) et AVANT `Complete-Run`,
# donc le recensement part dans le même envoi que les événements qu'il qualifie.
Report-Coverage -Source 'windows-agent'
Complete-Run
