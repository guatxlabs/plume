# Dump AST -> JSON d'un collecteur PowerShell, pour `check_windows_collector_is_honest.py`.
# ============================================================================================
# POURQUOI L'AST ET PAS UNE REGEX. La garde qui suit interdit des FORMES (un `catch` qui ne
# classe pas, une suppression d'erreur muette, une écriture d'état hors du point de commit).
# Une regex sur le texte confond un `catch` avec le mot « catch » dans un commentaire français,
# et ne sait pas dire dans quelle fonction se trouve une commande. On lit donc le fichier avec
# LE PARSEUR DE POWERSHELL LUI-MÊME : ce qui est analysé ici est exactement ce que l'hôte
# exécutera. Un fichier qui ne parse pas fait ÉCHOUER la garde — jamais passer.
#
# Ce script n'applique AUCUNE règle : il ne fait qu'exposer des faits. Les règles sont en
# Python, à côté des autres gardes du dépôt.
#
# SECOND MODE (P10.33-i) : `-Compatibilite`. La tâche planifiée lance Windows PowerShell 5.1, qu'aucun
# runner Linux n'exécute ; PSScriptAnalyzer, lui, tourne sous pwsh 7 et juge un script CONTRE les
# profils de Windows PowerShell 5.1 qu'il livre (commandes, paramètres, types, syntaxe). Ce mode charge
# la version EXACTE demandée, charge les profils NOMMÉS, analyse chaque fichier et imprime une ligne
# `PLUME-PSSA-JSON:` (le reste de la sortie — avertissements du module — n'est pas du verdict).
# `PSUseBOMForUnicodeEncodedFile` en plus : sans BOM, Windows PowerShell 5.1 lit le source dans la page de
# code ANSI (un « — » UTF-8 y devient un guillemet fermant).
# Code 3 : module ou profil absent. La garde en fait un REFUS DE CONCLURE, jamais un vert.
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string[]]$Path,
  [switch]$Compatibilite,
  [string]$Version,
  [string[]]$Profils
)

$ErrorActionPreference = 'Stop'

if ($Compatibilite) {
  # `pwsh -File` ne fabrique pas de tableau : les listes arrivent jointes par des virgules.
  $Path = @($Path | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
  $Profils = @($Profils | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
  $m = @(Get-Module -ListAvailable -Name PSScriptAnalyzer | Where-Object { $_.Version -eq [version]$Version })
  if ($m.Count -eq 0) {
    $vus = @(Get-Module -ListAvailable -Name PSScriptAnalyzer | ForEach-Object { "$($_.Version)" }) -join ', '
    [Console]::Error.WriteLine("PSScriptAnalyzer $Version introuvable (versions vues : '$vus' ; PSModulePath=$env:PSModulePath)")
    exit 3
  }
  Import-Module -Name $m[0].Path -Force
  $charge = @(Get-Module -Name PSScriptAnalyzer)
  if ($charge.Count -ne 1 -or $charge[0].Version -ne [version]$Version) {
    [Console]::Error.WriteLine("PSScriptAnalyzer chargé : '$($charge.Version -join ',')', attendu $Version")
    exit 3
  }
  $dir = Join-Path $charge[0].ModuleBase 'compatibility_profiles'
  $fichiersProfils = @()
  foreach ($p in $Profils) {
    $f = Join-Path $dir "$p.json"
    if (-not (Test-Path -LiteralPath $f -PathType Leaf)) {
      [Console]::Error.WriteLine("profil de compatibilité absent du module : $f")
      exit 3
    }
    $fichiersProfils += $f
  }
  if ($fichiersProfils.Count -eq 0) { [Console]::Error.WriteLine('aucun profil demandé'); exit 3 }
  $regles = @{
    IncludeRules = @('PSUseCompatibleSyntax', 'PSUseCompatibleCommands', 'PSUseCompatibleTypes', 'PSUseBOMForUnicodeEncodedFile')
    Rules        = @{
      PSUseCompatibleSyntax   = @{ Enable = $true; TargetVersions = @('5.1') }
      PSUseCompatibleCommands = @{ Enable = $true; TargetProfiles = @($Profils) }
      PSUseCompatibleTypes    = @{ Enable = $true; TargetProfiles = @($Profils) }
    }
  }
  $parFichier = [ordered]@{}
  foreach ($cible in $Path) {
    $c = (Resolve-Path -LiteralPath $cible).Path
    $parFichier[$cible] = @(Invoke-ScriptAnalyzer -Path $c -Settings $regles | ForEach-Object {
        [ordered]@{ rule = $_.RuleName; line = $_.Line; message = $_.Message }
      })
  }
  $sortie = [ordered]@{
    version     = "$($charge[0].Version)"
    module_base = $charge[0].ModuleBase
    profils     = @($fichiersProfils)
    fichiers    = $parFichier
  }
  'PLUME-PSSA-JSON:' + ($sortie | ConvertTo-Json -Depth 6 -Compress)
  exit 0
}

if ($Path.Count -ne 1) { throw 'le mode AST prend un seul fichier' }
$full = (Resolve-Path -LiteralPath $Path[0]).Path

$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($full, [ref]$tokens, [ref]$errors)

$funcs = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))

# Fonction ENGLOBANTE d'un décalage : la plus INTERNE dont l'étendue le contient ('' au niveau du script).
function Get-Enclosing([int]$offset) {
  $best = ''
  $bestLen = [int]::MaxValue
  foreach ($f in $funcs) {
    $s = $f.Extent.StartOffset; $e = $f.Extent.EndOffset
    if ($offset -ge $s -and $offset -lt $e -and ($e - $s) -lt $bestLen) {
      $best = $f.Name; $bestLen = $e - $s
    }
  }
  return $best
}

function Get-CallNames($node) {
  @($node.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
    ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
}

# --- catch : le construct qui, en PowerShell, transforme « impossible » en silence -----------
$catches = @()
foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CatchClauseAst] }, $true)) {
  $throws = @($c.Body.FindAll({ param($n) $n -is [System.Management.Automation.Language.ThrowStatementAst] }, $true))
  $catches += [ordered]@{
    line      = $c.Extent.StartLineNumber
    enclosing = Get-Enclosing $c.Extent.StartOffset
    calls     = @(Get-CallNames $c.Body)
    has_throw = ($throws.Count -gt 0)
    text      = $c.Extent.Text
  }
}

# --- commandes : nom, position, fonction englobante, texte ----------------------------------
$commands = @()
foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
  $name = $c.GetCommandName()
  if (-not $name) { $name = '' }
  # P10.33-i : paramètres tels qu'ÉCRITS (une abréviation `-Comp` reste `Comp`) et arguments littéraux
  # (chaînes), pour les listes fermées de la garde.
  $params = @($c.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] } |
      ForEach-Object { $_.ParameterName })
  $litteraux = @($c.CommandElements | Select-Object -Skip 1 | Where-Object {
        $_ -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
        $_ -is [System.Management.Automation.Language.ExpandableStringExpressionAst] } | ForEach-Object { "$($_.Value)" })
  $commands += [ordered]@{
    name       = $name
    line       = $c.Extent.StartLineNumber
    offset     = $c.Extent.StartOffset
    enclosing  = Get-Enclosing $c.Extent.StartOffset
    text       = $c.Extent.Text
    params     = @($params)
    litteraux  = @($litteraux)
  }
}

# --- suppressions d'erreur muettes : -ErrorAction SilentlyContinue|Ignore --------------------
$silencers = @()
foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
  $els = @($c.CommandElements)
  for ($i = 0; $i -lt $els.Count; $i++) {
    $el = $els[$i]
    if ($el -isnot [System.Management.Automation.Language.CommandParameterAst]) { continue }
    if ($el.ParameterName -notlike 'ErrorAction*' -and $el.ParameterName -notlike 'ea') { continue }
    $val = ''
    if ($null -ne $el.Argument) { $val = $el.Argument.Extent.Text }
    elseif ($i + 1 -lt $els.Count) { $val = $els[$i + 1].Extent.Text }
    $silencers += [ordered]@{
      line  = $el.Extent.StartLineNumber
      value = $val
      cmd   = $c.GetCommandName()
    }
  }
}

# --- littéraux de chaîne (repérage des chemins d'état) --------------------------------------
$strings = @()
foreach ($s in $ast.FindAll({ param($n)
      $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
      $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst] }, $true)) {
  $strings += [ordered]@{
    line      = $s.Extent.StartLineNumber
    enclosing = Get-Enclosing $s.Extent.StartOffset
    value     = $s.Extent.Text
  }
}

# --- affectations de variables ---------------------------------------------------------------
$assigns = @()
foreach ($a in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)) {
  $left = ''
  if ($a.Left -is [System.Management.Automation.Language.VariableExpressionAst]) {
    $left = $a.Left.VariablePath.UserPath
  } else { $left = $a.Left.Extent.Text }
  $assigns += [ordered]@{
    line      = $a.Extent.StartLineNumber
    enclosing = Get-Enclosing $a.Extent.StartOffset
    left      = $left
    right     = $a.Right.Extent.Text
  }
}

# --- références de variables ------------------------------------------------------------------
$vars = @()
foreach ($v in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)) {
  $vars += [ordered]@{
    line      = $v.Extent.StartLineNumber
    enclosing = Get-Enclosing $v.Extent.StartOffset
    name      = $v.VariablePath.UserPath
  }
}

# --- types nommés par le script (P10.33-i) ------------------------------------------------------
# `[T]`, `[T]::Membre`, `[T]$x`, `[T[]]`, `[A[B]]` : le nom ÉCRIT, seul. Le nom que pwsh 7 lui RÉSOUT
# n'est PAS exposé : pwsh 7 résout `[uint]` en System.UInt32, alors que Windows PowerShell 5.1 n'a pas
# cet accélérateur (mesuré, vérificateur du 2026-10-18) — la garde résout par les PROFILS 5.1. Rien n'est jugé ici.
$types = @()
foreach ($t in $ast.FindAll({ param($n)
      $n -is [System.Management.Automation.Language.TypeExpressionAst] -or
      $n -is [System.Management.Automation.Language.TypeConstraintAst] }, $true)) {
  $types += [ordered]@{
    line      = $t.Extent.StartLineNumber
    enclosing = Get-Enclosing $t.Extent.StartOffset
    written   = $t.TypeName.FullName
  }
}

# --- membres appelés ou lus (P10.33-i) : `x.M()`, `[T]::M()`, `[T]::P` ------------------------------
# `member` vide = nom de membre CALCULÉ (`$o.$m()`). `type` = nom écrit du type d'un accès statique.
$members = @()
foreach ($m in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.MemberExpressionAst] }, $true)) {
  $nom = ''
  if ($m.Member -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $nom = $m.Member.Value }
  $typeStatique = ''
  if ($m.Static -and $m.Expression -is [System.Management.Automation.Language.TypeExpressionAst]) {
    $typeStatique = $m.Expression.TypeName.FullName
  }
  $members += [ordered]@{
    line    = $m.Extent.StartLineNumber
    member  = $nom
    invoked = ($m -is [System.Management.Automation.Language.InvokeMemberExpressionAst])
    static  = [bool]$m.Static
    type    = $typeStatique
  }
}

# --- `using namespace|assembly|module` : un espace de noms importé rend `[WebClient]` illisible ---------
$usings = @($ast.UsingStatements | ForEach-Object {
    [ordered]@{ line = $_.Extent.StartLineNumber; kind = "$($_.UsingStatementKind)"; text = $_.Extent.Text }
  })

# --- syntaxe postérieure à Windows PowerShell 5.1 (jambe indépendante de PSScriptAnalyzer) ---------
# Mesuré le 2026-10-18 : PSScriptAnalyzer 1.25.0 signale `??`, `??=`, le ternaire, `&&`/`||` et `${x}?.m`,
# mais PAS l'index null-conditionnel `${x}?[0]`. Les nœuds sont reconnus par NOM de classe : la jambe
# ne dépend pas de la version de pwsh qui l'exécute.
$post51 = @()
foreach ($n in $ast.FindAll({ param($x) $true }, $true)) {
  $k = $n.GetType().Name
  $forme = ''
  if ($k -eq 'TernaryExpressionAst') { $forme = 'ternaire' }
  elseif ($k -eq 'PipelineChainAst') { $forme = 'chaîne de pipelines && / ||' }
  elseif ($k -eq 'BinaryExpressionAst' -and "$($n.Operator)" -eq 'QuestionQuestion') { $forme = 'opérateur ??' }
  elseif ($k -eq 'AssignmentStatementAst' -and "$($n.Operator)" -eq 'QuestionQuestionEquals') { $forme = 'affectation ??=' }
  elseif (($k -eq 'MemberExpressionAst' -or $k -eq 'InvokeMemberExpressionAst' -or $k -eq 'IndexExpressionAst') -and
          $n.PSObject.Properties['NullConditional'] -and $n.NullConditional) { $forme = 'accès null-conditionnel ?. / ?[' }
  elseif ($k -eq 'ScriptBlockAst' -and $n.PSObject.Properties['CleanBlock'] -and $n.CleanBlock) { $forme = 'bloc clean' }
  elseif ($k -eq 'PipelineAst' -and $n.PSObject.Properties['Background'] -and $n.Background) { $forme = 'opérateur d''arrière-plan &' }
  if ($forme) { $post51 += [ordered]@{ line = $n.Extent.StartLineNumber; forme = $forme; text = $n.Extent.Text } }
}

# L'échappement `u{…} (PowerShell 6) n'est pas un nœud : c'est le TEXTE d'une chaîne extensible. Windows
# PowerShell 5.1 le lit sans erreur comme les caractères « u{2014} » — un changement de sens muet.
foreach ($tk in $tokens) {
  if (($tk.Kind -eq 'StringExpandable' -or $tk.Kind -eq 'HereStringExpandable') -and $tk.Text -match '`u\{') {
    $post51 += [ordered]@{ line = $tk.Extent.StartLineNumber; forme = 'échappement `u{…}'; text = $tk.Text }
  }
}

$out = [ordered]@{
  file         = $full
  parse_errors = @($errors | ForEach-Object { "ligne $($_.Extent.StartLineNumber): $($_.Message)" })
  functions    = @($funcs | ForEach-Object { [ordered]@{ name = $_.Name; line = $_.Extent.StartLineNumber; start = $_.Extent.StartOffset; end = $_.Extent.EndOffset } })
  catches      = @($catches)
  commands     = @($commands)
  silencers    = @($silencers)
  strings      = @($strings)
  assignments  = @($assigns)
  variables    = @($vars)
  types        = @($types)
  usings       = @($usings)
  post51       = @($post51)
  members      = @($members)
}
$out | ConvertTo-Json -Depth 8 -Compress
