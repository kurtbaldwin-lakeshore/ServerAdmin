#Requires -Version 5.1
<#
.SYNOPSIS
    Plants the six graded capstone faults (F1 to F6) of SA1 Learning Plan 9 for snapshot SA1-FAULTS.

.DESCRIPTION
    INSTRUCTOR ONLY. Never give this file, Test-SA1Faults.ps1 or the fault list to students.

    Run on DC01, signed in as SA1\Administrator, in Windows PowerShell 5.1 started with Run as administrator.
    The script uses your own sign-in (Kerberos); it never asks for, stores or prints a password.

    Build the base of SA1-FAULTS first (podfiles/POD_FACTS.md, Learning Plan 9 specifics):
      - snapshot SA1-DOMAIN (sa1.lab, standard OU tree and accounts; WinRM is on in the domain)
      - Lab 5.2 DHCP setup on SRV01: scope 192.168.50.0 "SA1 Clients", options 003/006/015,
        CLIENT01 on DHCP with the reservation 192.168.50.150
      - Lab 8.3 share Projects on SRV01 (C:\Shares\Projects; share Authenticated Users Change)
      - Lab 6.1 GPO "SA1 Student Desktop" linked to OU Students
    Check that every ticket works on the base before you plant the faults.

    The faults (same numbers as POD_FACTS.md and the instructor key):
      F1  DHCP scope option 006 DNS Servers on SRV01 = 192.168.50.11 (no host there)
      F2  AD account emoss disabled
      F3  Link of GPO "SA1 Student Desktop" on OU Students disabled (Link Enabled = No)
      F4  Share Projects on SRV01: only Everyone Read (Authenticated Users Change removed)
      F5  Scheduled task "SA1 Index Service" on SRV01: At startup, SYSTEM, endless PowerShell loop
      F6  SRV-CORE: inbound firewall rule group "Windows Remote Management" disabled
    F6 runs LAST, because it closes WinRM to SRV-CORE (after F6, Invoke-Command to SRV-CORE fails).

    AFTER THIS SCRIPT (by hand):
      1. On CLIENT01, signed in with the local account student, in an administrator window:
             ipconfig /renew
             ipconfig /flushdns
         ipconfig /all must now show DNS Servers 192.168.50.11 (F1 reaches the client only after a renew).
      2. Run Test-SA1Faults.ps1 on DC01: F1 to F6 must all show PRESENT.
      3. Sign out of every console and take the NetLab snapshot SA1-FAULTS.

.PARAMETER ListOnly
    Show the checks and the planned changes, and change nothing (like -WhatIf).

.EXAMPLE
    .\Set-SA1Faults.ps1 -ListOnly
    .\Set-SA1Faults.ps1
#>
[CmdletBinding()]
param(
    [switch]$ListOnly
)

$ErrorActionPreference = 'Stop'

# ---------------- Pod values (POD_FACTS.md) ----------------
$DhcpServer   = 'SRV01'
$ScopeId      = '192.168.50.0'
$BadDns       = '192.168.50.11'
$UserName     = 'emoss'
$GpoName      = 'SA1 Student Desktop'
$StudentsOU   = 'OU=Students,OU=Lakeshore,DC=sa1,DC=lab'
$FileServer   = 'SRV01'
$ShareName    = 'Projects'
$TaskName     = 'SA1 Index Service'
$TaskArgument = '-NoProfile -WindowStyle Hidden -Command "while ($true) { }"'
$CoreServer   = 'SRV-CORE'
$FwGroup      = 'Windows Remote Management'

# ---------------- Output helpers ----------------
function Write-Status {
    param([string]$Tag, [string]$Text, [string]$Color = 'Gray')
    Write-Host ('[{0}] {1}' -f $Tag, $Text) -ForegroundColor $Color
}

$script:Failed = 0

function Invoke-FaultStep {
    param(
        [string]$Id,
        [string]$Plan,
        [scriptblock]$Action
    )
    if ($ListOnly) {
        Write-Status -Tag 'PLAN' -Text ('{0}  {1}' -f $Id, $Plan) -Color Cyan
        return
    }
    try {
        $detail = & $Action
        Write-Status -Tag ' OK ' -Text ('{0}  {1}  {2}' -f $Id, $Plan, $detail) -Color Green
    }
    catch {
        $script:Failed++
        Write-Status -Tag 'FAIL' -Text ('{0}  {1}  ERROR: {2}' -f $Id, $Plan, $_.Exception.Message) -Color Red
    }
}

# Runs a DhcpServer cmdlet block against SRV01: with the local DhcpServer module (-ComputerName SRV01) when
# DC01 has it (RSAT-DHCP), otherwise inside Invoke-Command on SRV01.
function Invoke-OnDhcpServer {
    param([scriptblock]$LocalBlock, [scriptblock]$RemoteBlock)
    if (Get-Module -ListAvailable -Name DhcpServer) {
        try {
            return (& $LocalBlock)
        }
        catch {
            Write-Status -Tag 'INFO' -Text ('DhcpServer cmdlet with -ComputerName failed ({0}); trying Invoke-Command on {1}' -f $_.Exception.Message, $DhcpServer) -Color Yellow
        }
    }
    return (Invoke-Command -ComputerName $DhcpServer -ScriptBlock $RemoteBlock -ErrorAction Stop)
}

# ---------------- Pre-checks (read-only) ----------------
Write-Host ''
Write-Host 'SA1 capstone faults: Set-SA1Faults.ps1 (instructor only)' -ForegroundColor White
if ($ListOnly) { Write-Host 'ListOnly: nothing will be changed.' -ForegroundColor Cyan }
Write-Host ''

$preOk = $true
function Test-Pre {
    param([string]$Name, [scriptblock]$Check)
    try {
        $r = & $Check
        Write-Status -Tag 'CHCK' -Text ('{0}: {1}' -f $Name, $r) -Color Gray
    }
    catch {
        $script:preOk = $false
        Write-Status -Tag 'FAIL' -Text ('{0}: {1}' -f $Name, $_.Exception.Message) -Color Red
    }
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Status -Tag 'FAIL' -Text 'Start Windows PowerShell with Run as administrator.' -Color Red
    $preOk = $false
}
if ($env:COMPUTERNAME -ne 'DC01') {
    Write-Status -Tag 'WARN' -Text ('This script is meant for DC01; you are on {0}.' -f $env:COMPUTERNAME) -Color Yellow
}

Test-Pre -Name 'Modules ActiveDirectory and GroupPolicy' -Check {
    Import-Module ActiveDirectory -ErrorAction Stop
    Import-Module GroupPolicy -ErrorAction Stop
    'loaded'
}
Test-Pre -Name ('WinRM to {0}' -f $FileServer) -Check { Test-WSMan -ComputerName $FileServer -ErrorAction Stop | Out-Null; 'answers' }
Test-Pre -Name ('WinRM to {0}' -f $CoreServer) -Check { Test-WSMan -ComputerName $CoreServer -ErrorAction Stop | Out-Null; 'answers' }
Test-Pre -Name ('DHCP scope {0} on {1}' -f $ScopeId, $DhcpServer) -Check {
    $s = Invoke-OnDhcpServer -LocalBlock {
        Get-DhcpServerv4Scope -ComputerName $DhcpServer -ScopeId $ScopeId -ErrorAction Stop
    } -RemoteBlock {
        Get-DhcpServerv4Scope -ScopeId '192.168.50.0' -ErrorAction Stop
    }
    'found: {0}' -f $s.Name
}
Test-Pre -Name ('AD user {0}' -f $UserName) -Check { $u = Get-ADUser -Identity $UserName; 'Enabled {0}' -f $u.Enabled }
Test-Pre -Name ('GPO link {0} on OU Students' -f $GpoName) -Check {
    $link = (Get-GPInheritance -Target $StudentsOU).GpoLinks | Where-Object { $_.DisplayName -eq $GpoName }
    if (-not $link) { throw ('GPO {0} is not linked to {1}' -f $GpoName, $StudentsOU) }
    'linked, Enabled {0}' -f $link.Enabled
}
Test-Pre -Name ('Share {0} on {1}' -f $ShareName, $FileServer) -Check {
    $acl = Invoke-Command -ComputerName $FileServer -ErrorAction Stop -ArgumentList $ShareName -ScriptBlock {
        param($n)
        Get-SmbShareAccess -Name $n -ErrorAction Stop | ForEach-Object { '{0} {1} {2}' -f $_.AccountName, $_.AccessControlType, $_.AccessRight }
    }
    $acl -join '; '
}

if (-not $preOk) {
    Write-Host ''
    Write-Status -Tag 'STOP' -Text 'A pre-check failed. Nothing was changed. Fix the base snapshot and run the script again.' -Color Red
    exit 1
}
Write-Host ''

# ---------------- F1: DHCP option 006 points at a host that does not exist ----------------
Invoke-FaultStep -Id 'F1' -Plan ('{0} scope {1}: option 006 DNS Servers = {2}' -f $DhcpServer, $ScopeId, $BadDns) -Action {
    $val = Invoke-OnDhcpServer -LocalBlock {
        Set-DhcpServerv4OptionValue -ComputerName $DhcpServer -ScopeId $ScopeId -DnsServer $BadDns -Force -ErrorAction Stop
        (Get-DhcpServerv4OptionValue -ComputerName $DhcpServer -ScopeId $ScopeId -OptionId 6 -ErrorAction Stop).Value
    } -RemoteBlock {
        Set-DhcpServerv4OptionValue -ScopeId '192.168.50.0' -DnsServer '192.168.50.11' -Force -ErrorAction Stop
        (Get-DhcpServerv4OptionValue -ScopeId '192.168.50.0' -OptionId 6 -ErrorAction Stop).Value
    }
    if (($val -join ',') -ne $BadDns) { throw ('option 006 reads {0}' -f ($val -join ',')) }
    'option 006 now {0}; remember ipconfig /renew on CLIENT01' -f ($val -join ',')
}

# ---------------- F2: account emoss disabled ----------------
Invoke-FaultStep -Id 'F2' -Plan ('Disable-ADAccount {0}' -f $UserName) -Action {
    Disable-ADAccount -Identity $UserName
    $u = Get-ADUser -Identity $UserName
    if ($u.Enabled) { throw 'Enabled still True' }
    'Enabled {0}' -f $u.Enabled
}

# ---------------- F3: GPO link on OU Students disabled ----------------
Invoke-FaultStep -Id 'F3' -Plan ('Set-GPLink {0} on OU Students -LinkEnabled No' -f $GpoName) -Action {
    Set-GPLink -Name $GpoName -Target $StudentsOU -LinkEnabled No | Out-Null
    $link = (Get-GPInheritance -Target $StudentsOU).GpoLinks | Where-Object { $_.DisplayName -eq $GpoName }
    if ($link.Enabled) { throw 'link still enabled' }
    'link Enabled {0}' -f $link.Enabled
}

# ---------------- F4: share Projects reduced to Everyone Read ----------------
Invoke-FaultStep -Id 'F4' -Plan ('{0} share {1}: Everyone Read only (revoke Authenticated Users)' -f $FileServer, $ShareName) -Action {
    $acl = Invoke-Command -ComputerName $FileServer -ErrorAction Stop -ArgumentList $ShareName -ScriptBlock {
        param($n)
        $ErrorActionPreference = 'Stop'
        # Grant first, so the share never has an empty permission list
        Grant-SmbShareAccess -Name $n -AccountName 'Everyone' -AccessRight Read -Force | Out-Null
        Revoke-SmbShareAccess -Name $n -AccountName 'NT AUTHORITY\Authenticated Users' -Force | Out-Null
        Get-SmbShareAccess -Name $n | ForEach-Object { '{0} {1} {2}' -f $_.AccountName, $_.AccessControlType, $_.AccessRight }
    }
    if (($acl | Where-Object { $_ -like '*Authenticated Users*' })) { throw ('Authenticated Users still listed: {0}' -f ($acl -join '; ')) }
    'share access now: {0}' -f ($acl -join '; ')
}

# ---------------- F5: scheduled task with an endless loop on SRV01 ----------------
Invoke-FaultStep -Id 'F5' -Plan ('{0}: Register-ScheduledTask "{1}" (At startup, SYSTEM) and start it' -f $FileServer, $TaskName) -Action {
    $state = Invoke-Command -ComputerName $FileServer -ErrorAction Stop -ArgumentList $TaskName, $TaskArgument -ScriptBlock {
        param($name, $argument)
        $ErrorActionPreference = 'Stop'
        if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $name -Confirm:$false
        }
        $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argument
        $trigger   = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        # ExecutionTimeLimit zero = no time limit (the default 72 hours would stop the loop); priority 5 = normal
        $settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -Priority 5 -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        Register-ScheduledTask -TaskName $name -TaskPath '\' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Lakeshore document index' | Out-Null
        Start-ScheduledTask -TaskName $name
        Start-Sleep -Seconds 5
        $loop = Get-CimInstance -ClassName Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -like '*while*' }
        '{0}; loop processes: {1}' -f (Get-ScheduledTask -TaskName $name).State, @($loop).Count
    }
    if ($state -notlike 'Running*') { throw ('task state: {0}' -f $state) }
    'task {0}' -f $state
}

# ---------------- F6 (LAST): WinRM firewall rules on SRV-CORE disabled ----------------
Invoke-FaultStep -Id 'F6' -Plan ('{0}: Disable-NetFirewallRule -DisplayGroup "{1}" (last step)' -f $CoreServer, $FwGroup) -Action {
    $opt = New-PSSessionOption -OpenTimeout 30000 -OperationTimeout 60000
    $remoteNote = ''
    try {
        Invoke-Command -ComputerName $CoreServer -SessionOption $opt -ErrorAction Stop -ArgumentList $FwGroup -ScriptBlock {
            param($g)
            Disable-NetFirewallRule -DisplayGroup $g -ErrorAction Stop
        }
    }
    catch {
        # The session can break once its own port closes; the port test below decides.
        $remoteNote = ' (remote session ended: {0})' -f $_.Exception.Message
    }
    Start-Sleep -Seconds 3
    $open = Test-NetConnection -ComputerName $CoreServer -Port 5985 -InformationLevel Quiet -WarningAction SilentlyContinue
    if ($open) { throw ('TCP 5985 on {0} still answers{1}' -f $CoreServer, $remoteNote) }
    'TCP 5985 on {0} closed{1}' -f $CoreServer, $remoteNote
}

# ---------------- Summary ----------------
Write-Host ''
if ($ListOnly) {
    Write-Status -Tag 'DONE' -Text 'ListOnly: no changes were made.' -Color Cyan
}
elseif ($script:Failed -gt 0) {
    Write-Status -Tag 'DONE' -Text ('{0} step(s) FAILED. Fix the cause, revert the base if needed, and run again. Do not take the snapshot.' -f $script:Failed) -Color Red
    exit 1
}
else {
    Write-Status -Tag 'DONE' -Text 'All six faults planted.' -Color Green
    Write-Host 'Next: on CLIENT01 (local account student, administrator window) run ipconfig /renew and ipconfig /flushdns,' -ForegroundColor White
    Write-Host '      run Test-SA1Faults.ps1 on DC01 (all PRESENT), sign out everywhere, then take snapshot SA1-FAULTS.' -ForegroundColor White
}
