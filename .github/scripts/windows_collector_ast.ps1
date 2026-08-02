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
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Path)

$ErrorActionPreference = 'Stop'
$full = (Resolve-Path -LiteralPath $Path).Path

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
  $commands += [ordered]@{
    name      = $name
    line      = $c.Extent.StartLineNumber
    offset    = $c.Extent.StartOffset
    enclosing = Get-Enclosing $c.Extent.StartOffset
    text      = $c.Extent.Text
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
}
$out | ConvertTo-Json -Depth 8 -Compress
