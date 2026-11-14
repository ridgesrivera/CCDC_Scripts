<#
.SYNOPSIS
    Disable-Accounts - DISABLE (never delete) rogue or unneeded accounts. CHANGES STATE.

.DESCRIPTION
    PURPOSE
      Shut out accounts the Red Team created or abuses, in a way you can undo
      in seconds if it turns out the account was needed (e.g. it was scored).

    WHY DISABLE, NOT DELETE?
      * Deleting is irreversible: a recreated account gets a NEW SID, so its
        group memberships, file ACLs and profile are gone.
      * The disabled account is evidence for your incident report.
      * If the scoring engine needed it, re-enable and you are back in 10 seconds.

    SAFETY RAILS
      * Refuses to disable the account you are logged in as.
      * Skips config scoredAccounts unless -AllowScored.
      * Every disable is logged with the exact re-enable command, and a
        rollback script (plain commands, no secrets) is written next to the log.

    WHAT IT READS    local SAM / AD, config\ccdc.json
    WHAT IT CHANGES  userAccountControl / UserFlags "account disabled" bit
    HOW TO UNDO      run the generated C:\ccdc\logs\Disable-Accounts_*_rollback.ps1, or:
                       net user <name> /active:yes                (local)
                       Enable-ADAccount <name>                    (domain)

    MANUAL EQUIVALENT
      net user eviluser /active:no
      Disable-ADAccount -Identity eviluser
      Disabled != logged out: also end their sessions:  quser  then  logoff <id>
      Domain Kerberos tickets already issued stay valid until they expire -
      disabling blocks NEW tickets (the DC re-checks status on TGS requests).

.EXAMPLE
    .\Disable-Accounts.ps1 -Users backdoor,hacker -WhatIf
.EXAMPLE
    .\Disable-Accounts.ps1 -Scope Domain -Users eviladmin -Force
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][string[]]$Users,
    [ValidateSet('Local', 'Domain')][string]$Scope,
    [switch]$AllowScored,
    [switch]$Force,
    [string]$ConfigPath
)

. "$PSScriptRoot\..\lib\CCDC-Common.ps1"
Initialize-Ccdc -ScriptName 'Disable-Accounts'
$config = Get-CcdcConfig -Path $ConfigPath
if (-not $Scope) { $Scope = if (Test-CcdcIsDC) { 'Domain' } else { 'Local' } }
$scored = Get-CcdcScoredAccounts -Config $config | ForEach-Object { $_.ToLower() }

$rollback = $script:CcdcLogFile -replace '\.log$', '_rollback.ps1'
$rollbackLines = New-Object System.Collections.ArrayList
[void]$rollbackLines.Add("# Rollback for Disable-Accounts run $($script:CcdcStamp) on $env:COMPUTERNAME - re-enables accounts. Review before running.")

$UF_ACCOUNTDISABLE = 0x2   # same bit for local UserFlags and AD userAccountControl

foreach ($name in $Users) {
    if ($name -ieq $env:USERNAME) { Write-Finding -Level RED -Category 'Safety' -Message "Refusing to disable '$name' - that is YOU."; continue }
    if (-not $AllowScored -and $scored -contains $name.ToLower()) {
        Write-Finding -Level YELLOW -Category 'Safety' -Message "Skipping '$name' - listed as a SCORED account in config (use -AllowScored if you are sure)."; continue
    }

    if ($Scope -eq 'Local') {
        try { $obj = [ADSI]"WinNT://$env:COMPUTERNAME/$name,user"; $flags = [int]$obj.UserFlags.Value }
        catch { Write-Finding -Level YELLOW -Category 'Target' -Message "Local user '$name' not found"; continue }
        if ($flags -band $UF_ACCOUNTDISABLE) { Write-Finding -Level INFO -Category 'Target' -Message "'$name' already disabled"; continue }
        $undo = "net user `"$name`" /active:yes"
        $ok = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target "Local\$name" -Action 'Disable account' -Undo $undo -ScriptBlock {
            $obj.UserFlags.Value = $flags -bor $UF_ACCOUNTDISABLE
            $obj.SetInfo()
        }
    } else {
        $domainDN = [string]([ADSI]'LDAP://RootDSE').defaultNamingContext
        $s = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$domainDN", "(&(objectClass=user)(sAMAccountName=$name))")
        $r = $s.FindOne()
        if (-not $r) { Write-Finding -Level YELLOW -Category 'Target' -Message "Domain user '$name' not found"; continue }
        $obj = $r.GetDirectoryEntry()
        $uac = [int]$obj.Properties['userAccountControl'].Value
        if ($uac -band $UF_ACCOUNTDISABLE) { Write-Finding -Level INFO -Category 'Target' -Message "'$name' already disabled"; continue }
        $groups = @($obj.Properties['memberOf'] | ForEach-Object { ($_ -split ',')[0] -replace '^CN=' })
        if ($groups) { Write-Finding -Level INFO -Category 'Target' -Message "$name is in: $($groups -join ', ')" }
        $undo = "Enable-ADAccount -Identity '$name'   # or: dsmod user `"$($r.Properties['distinguishedname'][0])`" -disabled no"
        $ok = Invoke-CcdcChange -Cmdlet $PSCmdlet -Force:$Force -Target "Domain\$name" -Action 'Disable account' -Undo $undo -ScriptBlock {
            $obj.Properties['userAccountControl'].Value = $uac -bor $UF_ACCOUNTDISABLE
            $obj.CommitChanges()
        }
    }
    if ($ok) {
        [void]$rollbackLines.Add($undo)
        Write-Finding -Level GREEN -Category 'Disable' -Message "Disabled $Scope\$name"
        # Show (do not kill) their live sessions so you can decide to log them off.
        $sessions = (& quser 2>$null) | Select-String -Pattern ("^\s*>?{0}\s" -f [regex]::Escape($name))
        foreach ($sess in $sessions) { Write-Finding -Level YELLOW -Category 'Session' -Message "Live session: $($sess.Line.Trim())" -Detail 'End it with: logoff <ID>' }
    }
}

if ($rollbackLines.Count -gt 1) {
    $rollbackLines | Set-Content -Path $rollback -Encoding UTF8
    Write-Finding -Level INFO -Category 'Rollback' -Message "Rollback commands written to $rollback"
}
Complete-Ccdc
