@{
    # Lint settings for the toolkit. Run: Invoke-ScriptAnalyzer -Path windows -Recurse -Settings tools\lint\PSScriptAnalyzerSettings.psd1
    Severity     = @('Error', 'Warning')

    # Check compatibility with Windows PowerShell 5.1 on Windows Server 2016 / 2012 R2.
    Rules        = @{
        PSUseCompatibleSyntax = @{ Enable = $true; TargetVersions = @('5.1') }
    }

    ExcludeRules = @(
        # Justification: these are interactive console tools. Write-Host is the only
        # way to get coloured output in Windows PowerShell 5.1, and colour IS the UX
        # (RED / YELLOW / GREEN findings).
        'PSAvoidUsingWriteHost',
        # Justification: harden scripts implement -WhatIf/-Confirm through the shared
        # Invoke-CcdcChange helper ($PSCmdlet.ShouldProcess is called there), which
        # the analyzer cannot follow across the dot-sourced lib.
        'PSShouldProcess',
        'PSUseShouldProcessForStateChangingFunctions'
    )
}
