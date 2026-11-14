<#
.SYNOPSIS
    Test-PsSyntax - developer lint for the toolkit (not used on competition boxes).

.DESCRIPTION
    1. Parses every .ps1 with the PowerShell language parser (catches syntax errors).
    2. Flags syntax that only exists in PowerShell 7+ and would break on
       Windows PowerShell 5.1 (Server 2012 R2 / 2016): ?.  ??  ??=  ?[  &&  ||  ternary ?:
    3. If PSScriptAnalyzer is installed, runs it with tools\lint\PSScriptAnalyzerSettings.psd1.

    READS: .ps1 files under the paths given.  CHANGES: nothing.

.EXAMPLE
    pwsh -File tools/lint/Test-PsSyntax.ps1 -Path windows
#>
param([string[]]$Path = @('windows'))

$files = Get-ChildItem -Path $Path -Recurse -Filter *.ps1 | Sort-Object FullName
$problems = 0
$ps7Tokens = @('QuestionDot', 'QuestionQuestion', 'QuestionQuestionEquals', 'QuestionLBracket', 'AndAnd', 'OrOr')
foreach ($f in $files) {
    $tokens = $null; $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errors)
    foreach ($e in $errors) { $problems++; Write-Output ("PARSE  {0}:{1}  {2}" -f $f.FullName, $e.Extent.StartLineNumber, $e.Message) }
    foreach ($t in $tokens) {
        if ($ps7Tokens -contains [string]$t.Kind) { $problems++; Write-Output ("PS7    {0}:{1}  '{2}' is PowerShell 7 only" -f $f.FullName, $t.Extent.StartLineNumber, $t.Text) }
        if ([string]$t.Kind -eq 'QuestionMark') { $problems++; Write-Output ("PS7    {0}:{1}  ternary '?' is PowerShell 7 only" -f $f.FullName, $t.Extent.StartLineNumber) }
    }
}
Write-Output ("Parsed {0} files; syntax/compat problems: {1}" -f @($files).Count, $problems)

if (Get-Module -ListAvailable PSScriptAnalyzer) {
    $settings = Join-Path $PSScriptRoot 'PSScriptAnalyzerSettings.psd1'
    $results = foreach ($f in $files) { Invoke-ScriptAnalyzer -Path $f.FullName -Settings $settings }
    $results | Sort-Object ScriptName, Line | Format-Table -AutoSize Severity, RuleName, ScriptName, Line, Message | Out-String -Width 220
    Write-Output ("PSScriptAnalyzer findings: {0}" -f @($results).Count)
    if ($results) { $problems += @($results).Count }
} else {
    Write-Output 'PSScriptAnalyzer not installed - skipped (Install-Module PSScriptAnalyzer -Scope CurrentUser).'
}
if ($problems -gt 0) { exit 1 }
