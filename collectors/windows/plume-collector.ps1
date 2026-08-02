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
                          privilèges spéciaux (4672), création de processus (4688),
                          verrouillage de compte (4740), gestion de comptes
                          (4720/4722/4724/4726/4732/4756).  category=auth|exec|account
    - windows-firewall  : paquets/connexions BLOQUÉS par le pare-feu Windows (WFP :
                          5152/5157) + état des profils (Get-NetFirewallProfile).  category=firewall
    - windows-system    : arrêts inattendus (6008), échecs de service (7031/7034/7000).  category=system
    - windows-defender  : détections Microsoft Defender (1006/1015/1116/1117).  category=malware
    - windows-network   : connexions TCP établies (distantes) + ports en écoute.  category=network

  Idempotence : un filigrane par source (dernier `TimeCreated` traité) est
  persisté sous $StateDir ; seuls les nouveaux événements sont expédiés. Chaque
  événement porte aussi un `dedup` (le central dédoublonne dans l'heure).

  Déploiement (voir README.md de ce dossier) : tâche planifiée toutes les 1–5 min,
  en compte SYSTEM (accès au journal Security). Config par variables d'env
  (PLUME_CENTRAL / PLUME_TOKEN) ou fichier C:\ProgramData\plume\plume.conf (KEY=value).

  Sûreté : lecture seule du système, aucun secret en clair dans le code, TLS
  vérifié par défaut (PLUME_TLS_INSECURE=1 pour un central en certificat auto-signé
  de test uniquement). N'expédie que des métadonnées d'événements, jamais de contenu
  de fichier.
#>

[CmdletBinding()]
param(
  [string]$Central = $env:PLUME_CENTRAL,
  [string]$Token   = $env:PLUME_TOKEN,
  [int]$MaxAgeMinutes = 60,   # borne de rattrapage au 1er run (pas de filigrane) — anti-flood
  [int]$BatchSize = 400       # nb max d'événements par POST
)

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
if (-not $Token)   { throw 'PLUME_TOKEN manquant (créé sur le central : plume-daemon token <nom>).' }
$Central   = $Central.TrimEnd('/')
$StateDir  = 'C:\ProgramData\plume\state'
$null = New-Item -ItemType Directory -Force -Path $StateDir -ErrorAction SilentlyContinue
$HostName  = $env:COMPUTERNAME
# HORODATAGE — NE PAS revenir à `Get-Date -UFormat %s`. Sur Windows PowerShell 5.1, `%s` rend l'heure
# LOCALE exprimée comme si elle était UTC : l'epoch produit est décalé du décalage horaire de la machine.
# MESURÉ le 2026-08-02 (Windows 11 Enterprise 24H2, fuseau « Romance Standard Time ») : `%s` = epoch vrai
# + 7 201 s, soit exactement l'offset UTC (+02:00) ; la même mesure en fuseau UTC donne un écart nul —
# c'est pourquoi le défaut est resté invisible. Tous les événements arrivaient donc DEUX HEURES DANS LE
# FUTUR au central. `[DateTimeOffset]` est sans ambiguïté et indépendant du fuseau ET de la culture.
$NowEpoch  = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

# TLS : vérifié par défaut ; opt-out explicite de test seulement.
if ($env:PLUME_TLS_INSECURE -eq '1') {
  try { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } } catch {}
}
try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 } catch {}

# --- Helpers ---------------------------------------------------------------------------------

# Epoch (s) depuis un DateTime.
function To-Epoch([datetime]$dt) { [DateTimeOffset]::new($dt.ToUniversalTime(), [TimeSpan]::Zero).ToUnixTimeSeconds() }

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
function Get-Watermark([string]$name) {
  $f = Join-Path $StateDir "$name.watermark"
  $floor = (Get-Date).AddMinutes(-$MaxAgeMinutes)
  if (Test-Path $f) {
    try {
      $wm = [datetime]::Parse((Get-Content $f -Raw))
      # Filigrane dans le futur -> il ne peut venir que d'une horloge fausse : on le ramène au plancher
      # de rattrapage au lieu de rester aveugle.
      if ($wm -gt (Get-Date)) { return $floor }
      return $wm
    } catch {}
  }
  return $floor
}
function Set-Watermark([string]$name, [datetime]$dt) {
  # Ne jamais ÉCRIRE un filigrane futur : on plafonne à maintenant.
  $now = Get-Date
  if ($dt -gt $now) { $dt = $now }
  try { Set-Content -Path (Join-Path $StateDir "$name.watermark") -Value $dt.ToString('o') -NoNewline } catch {}
}

# Extrait EventData (Name -> Value) depuis le XML d'un événement (robuste, indépendant de l'ordre).
function Get-EventData($evt) {
  $h = @{}
  try {
    $xml = [xml]$evt.ToXml()
    foreach ($d in $xml.Event.EventData.Data) {
      if ($d.Name) { $h[$d.Name] = [string]$d.'#text' }
    }
  } catch {}
  return $h
}

# Accumulateur d'événements + envoi par lots.
$script:Events = New-Object System.Collections.ArrayList
function Add-Event {
  param([string]$Source, [string]$Category, [int]$Severity, [string]$Message,
        [hashtable]$Fields, [int64]$Ts = $NowEpoch, [string]$SrcIp, [string]$DstIp, [string]$Dedup)
  $o = [ordered]@{ ts = $Ts; source = $Source; category = $Category; severity = $Severity
                   message = $Message; fields = $Fields }
  if ($SrcIp) { $o.src_ip = $SrcIp }
  if ($DstIp) { $o.dst_ip = $DstIp }
  # LE NOM DE L'HÔTE EST PRÉFIXÉ ICI, ET NULLE PART AILLEURS. `event.dedup` est UNIQUE au niveau de
  # la BASE, pas de l'hôte : deux machines qui produisent la même clé se volent leurs événements —
  # la seconde est écartée en SILENCE par l'INSERT OR IGNORE du central. Les identifiants
  # d'enregistrement du journal Windows repartent de 1 sur CHAQUE machine, donc la collision est
  # certaine dès le 2e poste, et maximale au moment où le SOC en a le plus besoin (l'enrôlement).
  # MESURÉ le 2026-08-02 sur deux Windows Server 2022 (WS22-LAB, WS22-GUI) : sur 311 enregistrements
  # Sysmon présents sur la 2e machine, 266 sont arrivés et 45 ont disparu — exactement les 45 que la
  # 1re machine avait déjà expédiés ; et le battement de santé horaire de la 2e machine (clé
  # `windows-agent-health-<heure>`) n'a JAMAIS été stocké. Préfixer ICI plutôt qu'à chaque appel rend
  # la faute non-représentable : un nouvel Add-Event ne peut pas oublier l'hôte.
  if ($Dedup) { $o.dedup  = "$HostName-$Dedup" }
  $null = $script:Events.Add([pscustomobject]$o)
  if ($script:Events.Count -ge $BatchSize) { Flush-Events }
}
function Flush-Events {
  if ($script:Events.Count -eq 0) { return }
  $envelope = [ordered]@{ ts = $NowEpoch; host = $HostName; kind = 'events'; events = @($script:Events) }
  $body = $envelope | ConvertTo-Json -Depth 6 -Compress
  try {
    Invoke-RestMethod -Uri "$Central/api/ingest" -Method Post -TimeoutSec 20 `
      -Headers @{ Authorization = "Bearer $Token" } -ContentType 'application/json' -Body $body | Out-Null
  } catch {
    Write-Warning "POST /api/ingest a échoué : $($_.Exception.Message)"
  }
  $script:Events.Clear()
}

# Sévérité par EventID (défaut 1 = info-bas).
function Sev-For([int]$id) {
  switch ($id) {
    4625 { 2 } 4740 { 3 } 4672 { 2 } 4720 { 2 } 4726 { 2 } 4732 { 2 } 4756 { 2 }
    5152 { 1 } 5157 { 2 } 6008 { 3 } 7031 { 2 } 7034 { 2 } 7000 { 2 }
    1116 { 4 } 1015 { 4 } 1006 { 4 } 1117 { 3 }
    default { 1 }
  }
}

# Collecte générique d'un journal via filtre, avec filigrane.
function Collect-Log {
  param([string]$Name, [string]$LogName, [int[]]$Ids, [string]$Source, [string]$Category)
  $since = Get-Watermark $Name
  $filter = @{ LogName = $LogName; StartTime = $since }
  if ($Ids) { $filter.Id = $Ids }
  $max = $since
  try {
    $evts = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
  } catch {
    # Journal absent / aucun événement / accès refusé -> on saute cette source proprement.
    return
  }
  foreach ($e in ($evts | Sort-Object TimeCreated)) {
    if ($e.TimeCreated -le $since) { continue }
    if ($e.TimeCreated -gt $max) { $max = $e.TimeCreated }
    $d = Get-EventData $e
    $id = [int]$e.Id
    $sev = Sev-For $id
    $msg = ($e.Message -split "`r?`n")[0]
    if (-not $msg) { $msg = "$Source event $id" }
    $fields = @{ event_id = $id; provider = $e.ProviderName; level = "$($e.LevelDisplayName)"
                 record_id = $e.RecordId; channel = $LogName }
    foreach ($k in $d.Keys) { if ($d[$k] -and -not $fields.ContainsKey($k)) { $fields[$k] = $d[$k] } }
    $sip = $d['IpAddress']; if ($sip -eq '-' -or $sip -eq '::1' -or $sip -eq '127.0.0.1') { $sip = $null }
    $ded = "$Source-$($e.RecordId)"
    Add-Event -Source $Source -Category $Category -Severity $sev -Message $msg -Fields $fields `
              -Ts (To-Epoch $e.TimeCreated) -SrcIp $sip -Dedup $ded
  }
  Set-Watermark $Name $max
}

# --- 1) Journal Security : auth / exec / account --------------------------------------------
# (Le journal Security exige des droits élevés : exécuter en SYSTEM ou administrateur.)
# CIM : la création de processus (4688) porte `exec`, le nom CANONIQUE de la taxonomie v1.3
# (`CIM_CATEGORIES`, guatx-core). Elle a porté `process` — un nom HORS taxonomie — jusqu'au
# 2026-07-23 ; les événements de cette période sont retrouvés par l'alias de LECTURE du daemon
# (cf. `cim_read_alias_exec`, soql_glue.rs) et non par une réécriture de données.
Collect-Log -Name 'win-auth'    -LogName 'Security' -Ids @(4624,4625,4634,4672,4740) -Source 'windows-security' -Category 'auth'
Collect-Log -Name 'win-process' -LogName 'Security' -Ids @(4688)                     -Source 'windows-security' -Category 'exec'
Collect-Log -Name 'win-account' -LogName 'Security' -Ids @(4720,4722,4724,4726,4732,4756) -Source 'windows-security' -Category 'account'

# --- 2) Pare-feu Windows : connexions bloquées (WFP) + état des profils ----------------------
# 5152 = paquet bloqué, 5157 = connexion bloquée (audit « Filtering Platform Connection »).
$fwSince = Get-Watermark 'win-firewall'
$fwMax = $fwSince
try {
  $fw = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=@(5152,5157); StartTime=$fwSince } -ErrorAction Stop
  foreach ($e in ($fw | Sort-Object TimeCreated)) {
    if ($e.TimeCreated -le $fwSince) { continue }
    if ($e.TimeCreated -gt $fwMax) { $fwMax = $e.TimeCreated }
    $d = Get-EventData $e
    $fields = @{ event_id=[int]$e.Id; direction=$d['Direction']; protocol=$d['Protocol']
                 app=$d['Application']; src_port=$d['SourcePort']; dst_port=$d['DestPort']
                 record_id=$e.RecordId }
    Add-Event -Source 'windows-firewall' -Category 'firewall' -Severity (Sev-For ([int]$e.Id)) `
      -Message "pare-feu: connexion bloquée ($($d['Direction'])) $($d['SourceAddress']):$($d['SourcePort']) -> $($d['DestAddress']):$($d['DestPort']) [$($d['Protocol'])]" `
      -Fields $fields -Ts (To-Epoch $e.TimeCreated) -SrcIp $d['SourceAddress'] -DstIp $d['DestAddress'] `
      -Dedup "windows-firewall-$($e.RecordId)"
  }
  Set-Watermark 'win-firewall' $fwMax
} catch {}
# État des profils pare-feu (config, envoyé à chaque run comme signal de santé/config).
try {
  foreach ($p in (Get-NetFirewallProfile -ErrorAction Stop)) {
    Add-Event -Source 'windows-firewall' -Category 'firewall' -Severity $(if ($p.Enabled) { 0 } else { 3 }) `
      -Message "profil pare-feu $($p.Name): enabled=$($p.Enabled) inbound=$($p.DefaultInboundAction)" `
      -Fields @{ profile=$p.Name; enabled=[bool]$p.Enabled; inbound="$($p.DefaultInboundAction)"; outbound="$($p.DefaultOutboundAction)" } `
      -Dedup "windows-fwprofile-$($p.Name)-$([int]($NowEpoch/3600))"
  }
} catch {}

# --- 3) Journal System : arrêts inattendus, échecs de service --------------------------------
Collect-Log -Name 'win-system' -LogName 'System' -Ids @(6008,7000,7031,7034) -Source 'windows-system' -Category 'system'

# --- 4) Microsoft Defender : détections ------------------------------------------------------
Collect-Log -Name 'win-defender' -LogName 'Microsoft-Windows-Windows Defender/Operational' `
            -Ids @(1006,1015,1116,1117) -Source 'windows-defender' -Category 'malware'

# --- 5) Réseau : connexions TCP établies (distantes) + ports en écoute -----------------------
# Instantané périodique (pas de filigrane) ; dédup par tuple dans l'heure.
try {
  $procById = @{}
  Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procById[$_.Id] = $_.ProcessName }
  $bucket = [int]($NowEpoch / 3600)
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
  Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object {
    $_.LocalAddress -notin @('127.0.0.1','::1')
  } | ForEach-Object {
    $pname = $procById[[int]$_.OwningProcess]
    Add-Event -Source 'windows-network' -Category 'network' -Severity 0 `
      -Message "port en écoute $($_.LocalAddress):$($_.LocalPort) ($pname)" `
      -Fields @{ local_port=$_.LocalPort; state='Listen'; process=$pname; pid=[int]$_.OwningProcess } `
      -SrcIp $_.LocalAddress -Dedup "windows-listen-$($_.LocalPort)-$bucket"
  }
} catch {}

# --- Heartbeat (dead-man's-switch) + envoi final ---------------------------------------------
Add-Event -Source 'windows-agent' -Category 'health' -Severity 0 -Message 'plume windows collector ok' `
          -Fields @{ os = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption; collector='windows' } `
          -Dedup "windows-agent-health-$([int]($NowEpoch/3600))"
Flush-Events
