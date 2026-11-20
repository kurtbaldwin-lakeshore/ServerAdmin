#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only check of the six SA1 capstone faults (F1 to F6) on a pod: PRESENT, FIXED or UNKNOWN.

.DESCRIPTION
    INSTRUCTOR ONLY. Never give this file to students.

    Run on DC01 as SA1\Administrator in Windows PowerShell 5.1 (Run as administrator). The script changes nothing:
    it only reads AD, Group Policy, DHCP, the share, the scheduled task and the WinRM port.

    Use it
      - after Set-SA1Faults.ps1, before you take snapshot SA1-FAULTS: every fault must be PRESENT;
      - on a freshly reverted pod, to check the snapshot before students start;
      - at the end of an in-person capstone: FIXED for each ticket the student solved.

    F1 is checked on the DHCP server. Whether CLIENT01 already holds the bad DNS server is seen only on CLIENT01
    (ipconfig /all: DNS Servers 192.168.50.11 while the fault is present); WinRM to CLIENT01 is not assumed.
    F6 cannot be read through WinRM while it is present, so it is checked with ping and a TCP test of port 5985.

.EXAMPLE
    .\Test-SA1Faults.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$DhcpServer = 'SRV01'
$ScopeId    = '192.168.50.0'
$BadDns     = '192.168.50.11'
$GoodDns    = '192.168.50.10'
$UserName   = 'emoss'
$GpoName    = 'SA1 Student Desktop'
$StudentsOU = 'OU=Students,OU=Lakeshore,DC=sa1,DC=lab'
$FileServer = 'SRV01'
$ShareName  = 'Projects'
$TaskName   = 'SA1 Index Service'
$CoreServer = 'SRV-CORE'

$results = New-Object System.Collections.Generic.List[object]
function Add-Result {
    param([string]$Fault, [string]$Ticket, [string]$Status, [string]$Detail)
    $results.Add([pscustomobject]@{ Fault = $Fault; Ticket = $Ticket; Status = $Status; Detail = $Detail })
}

# ---------------- F1: DHCP option 006 ----------------
try {
    if (Get-Module -ListAvailable -Name DhcpServer) {
        $dns = (Get-DhcpServerv4OptionValue -ComputerName $DhcpServer -ScopeId $ScopeId -OptionId 6 -ErrorAction Stop).Value
    }
    else {
        $dns = Invoke-Command -ComputerName $DhcpServer -ErrorAction Stop -ScriptBlock {
            (Get-DhcpServerv4OptionValue -ScopeId '192.168.50.0' -OptionId 6 -ErrorAction Stop).Value
        }
    }
    $list = @($dns) -join ','
    if (@($dns) -contains $BadDns) { Add-Result 'F1' 'A' 'PRESENT' ('scope option 006 = {0}; on CLIENT01 check ipconfig /all' -f $list) }
    elseif ($list -eq $GoodDns)   { Add-Result 'F1' 'A' 'FIXED'   ('scope option 006 = {0}; on CLIENT01 check ipconfig /all after renew' -f $list) }
    else                          { Add-Result 'F1' 'A' 'UNKNOWN' ('scope option 006 = {0}' -f $list) }
}
catch { Add-Result 'F1' 'A' 'UNKNOWN' ('cannot read option 006: {0}' -f $_.Exception.Message) }

# ---------------- F2: account emoss ----------------
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $u = Get-ADUser -Identity $UserName -Properties LockedOut
    if (-not $u.Enabled) { Add-Result 'F2' 'B' 'PRESENT' ('{0} Enabled False' -f $UserName) }
    else { Add-Result 'F2' 'B' 'FIXED' ('{0} Enabled True, LockedOut {1}' -f $UserName, $u.LockedOut) }
}
catch { Add-Result 'F2' 'B' 'UNKNOWN' $_.Exception.Message }

# ---------------- F3: GPO link on OU Students ----------------
try {
    Import-Module GroupPolicy -ErrorAction Stop
    $link = (Get-GPInheritance -Target $StudentsOU).GpoLinks | Where-Object { $_.DisplayName -eq $GpoName }
    if (-not $link)       { Add-Result 'F3' 'C' 'UNKNOWN' ('{0} is not linked to OU Students' -f $GpoName) }
    elseif ($link.Enabled) { Add-Result 'F3' 'C' 'FIXED'   'link Enabled True' }
    else                  { Add-Result 'F3' 'C' 'PRESENT' 'link Enabled False' }
}
catch { Add-Result 'F3' 'C' 'UNKNOWN' $_.Exception.Message }

# ---------------- F4: share permissions of Projects ----------------
try {
    $acl = Invoke-Command -ComputerName $FileServer -ErrorAction Stop -ArgumentList $ShareName -ScriptBlock {
        param($n)
        Get-SmbShareAccess -Name $n -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Account = [string]$_.AccountName; Type = [string]$_.AccessControlType; Right = [string]$_.AccessRight }
        }
    }
    $text = ($acl | ForEach-Object { '{0} {1} {2}' -f $_.Account, $_.Type, $_.Right }) -join '; '
    $auChange = $acl | Where-Object { $_.Account -like '*Authenticated Users' -and $_.Type -eq 'Allow' -and ($_.Right -eq 'Change' -or $_.Right -eq 'Full') }
    if ($auChange) { Add-Result 'F4' 'D' 'FIXED' $text }
    else { Add-Result 'F4' 'D' 'PRESENT' $text }
}
catch { Add-Result 'F4' 'D' 'UNKNOWN' $_.Exception.Message }

# ---------------- F5: scheduled task and loop on SRV01 ----------------
try {
    $info = Invoke-Command -ComputerName $FileServer -ErrorAction Stop -ArgumentList $TaskName -ScriptBlock {
        param($name)
        $t = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        $loop = Get-CimInstance -ClassName Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -like '*while*' }
        $state = 'not found'
        if ($t) { $state = [string]$t.State }
        [pscustomobject]@{ State = $state; Loops = @($loop).Count }
    }
    $detail = 'task {0}; loop processes {1}' -f $info.State, $info.Loops
    if ($info.Loops -gt 0 -or ($info.State -ne 'Disabled' -and $info.State -ne 'not found')) { Add-Result 'F5' 'E' 'PRESENT' $detail }
    else { Add-Result 'F5' 'E' 'FIXED' $detail }
}
catch { Add-Result 'F5' 'E' 'UNKNOWN' $_.Exception.Message }

# ---------------- F6: WinRM port on SRV-CORE ----------------
try {
    $ping = Test-Connection -ComputerName $CoreServer -Count 2 -Quiet
    $port = Test-NetConnection -ComputerName $CoreServer -Port 5985 -InformationLevel Quiet -WarningAction SilentlyContinue
    if ($port)     { Add-Result 'F6' 'F' 'FIXED'   'ping True; TCP 5985 True' }
    elseif ($ping) { Add-Result 'F6' 'F' 'PRESENT' 'ping True; TCP 5985 False' }
    else           { Add-Result 'F6' 'F' 'UNKNOWN' ('{0} does not answer ping: is it running?' -f $CoreServer) }
}
catch { Add-Result 'F6' 'F' 'UNKNOWN' $_.Exception.Message }

# ---------------- Report ----------------
Write-Host ($results | Format-Table -AutoSize -Wrap | Out-String -Width 200)
$present = @($results | Where-Object { $_.Status -eq 'PRESENT' }).Count
$fixed   = @($results | Where-Object { $_.Status -eq 'FIXED' }).Count
$unknown = @($results | Where-Object { $_.Status -eq 'UNKNOWN' }).Count
$color = 'Yellow'
if ($present -eq 6) { $color = 'Green' }
Write-Host ('PRESENT {0}   FIXED {1}   UNKNOWN {2}   (a new SA1-FAULTS pod must show PRESENT 6)' -f $present, $fixed, $unknown) -ForegroundColor $color
