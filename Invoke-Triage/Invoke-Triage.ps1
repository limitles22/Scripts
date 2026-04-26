<#
.SYNOPSIS
    Invoke-Triage - Endpoint triage script for SOC analysts.
.DESCRIPTION
    Collects forensic artifacts from a Windows endpoint
    for initial incident response triage.
.EXAMPLE
    .\Invoke-Triage.ps1
.EXAMPLE
    .\Invoke-Triage.ps1 -Output report.txt
#>

param(
    [string]$Output
)

# ============================================================
#  HEADER
# ============================================================
function Show-Header {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  ENDPOINT TRIAGE REPORT" -ForegroundColor Cyan
    Write-Host "  Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
}

# ============================================================
#  SECTION 1 - SYSTEM INFO
# ============================================================
function Get-SystemInfo {
    Write-Host "[1] SYSTEM INFORMATION" -ForegroundColor Green
    Write-Host "    Hostname:  $env:COMPUTERNAME"
    Write-Host "    User:      $env:USERNAME"
    Write-Host "    Domain:    $env:USERDOMAIN"

    $OS = Get-CimInstance Win32_OperatingSystem
    Write-Host "    OS:        $($OS.Caption)"
    Write-Host "    Build:     $($OS.BuildNumber)"
    Write-Host "    Uptime:    $(((Get-Date) - $OS.LastBootUpTime).ToString('dd\.hh\:mm\:ss'))"

    $IP = (Get-NetIPAddress -AddressFamily IPv4 |
           Where-Object { $_.IPAddress -ne '127.0.0.1' } |
           Select-Object -First 1).IPAddress
    Write-Host "    IP:        $IP"
    Write-Host ""
}

function Get-SuspiciousProcesses {
    Write-Host "[2] RUNNING PROCESSES" -ForegroundColor Green
    Get-Process |Where-Object { $_.Path -and $_.Path -notlike 'C:\Windows\*' -and $_.Path -notlike 'C:\Program Files\*' -and $_.Path -notlike 'C:\Program Files (x86)\*'} | Select-Object ProcessName, Id, Path | Format-Table -AutoSize
    Write-Host ""
}

function Get-NetworkConnections {
    Write-Host "[3] NETWORK CONNECTIONS" -ForegroundColor Green
    Get-NetTCPConnection | Where-Object {$_.State -like "Established" -and $_.RemoteAddress -notlike "127.0.0.1" -and $_.RemoteAddress -notlike "0.0.0.0" } | Select-Object CreationTime, State, @{Name='ProcessName'; Expression={ (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName }}, OwningProcess, RemoteAddress, RemotePort | Format-Table -AutoSize
    Write-Host ""
}

function Get-SheduledTasksCheck {
    Write-Host "[4] SHEDULED TASKS" -ForegroundColor Green
    Get-ScheduledTask | Where-Object { $_.Actions.Execute -and $_.Actions.Execute -notlike "%windir%\System32\*" -and $_.Actions.Execute -notlike "C:\Windows\System32\*" -and $_.Actions.Execute -notlike "%SystemRoot%\System32\*" -and $_.Actions.Execute -notlike "%ProgramFiles%\*" -and $_.Actions.Execute -notlike "C:\Program Files\*"  -and $_.Actions.Execute -notlike "C:\Program Files (x86)\*"} | Select-Object TaskName, TaskPath, State, @{Name='Action'; Expression={ $_.Actions.Execute }} | Format-List *
    Write-Host ""
}

function Get-SuspiciousServices {
    Write-Host "[5] SUSPICIOUS SERVICES" -ForegroundColor Green
    Get-CimInstance Win32_Service | Where-Object {$_.PathName -and $_.PathName -notlike '"C:\WINDOWS\*' -and $_.PathName -notlike 'C:\WINDOWS\*' -and $_.PathName -notlike '"C:\Program Files\*' -and $_.PathName -notlike 'C:\Program Files\*' -and $_.PathName -notlike '"C:\Program Files (x86)\*' -and $_.PathName -notlike 'C:\Program Files (x86)\*' } | Select-Object Name, PathName, ServiceType, Started, StartName | Format-List *
    Write-Host ""
}

function Get-SuspiciousUsers {
    Write-Host "[6] LOCAL ACCOUNTS" -ForegroundColor Green
    Get-LocalUser | Select-Object Name, SID, PasswordRequired, PasswordLastSet, Enabled, LastLogon | Format-List *
    Write-Host ""
}

function Get-SuspiciousEvents {
    Write-Host "[7] SUSPICIOUS EVENTS" -ForegroundColor Green
    $securityAvailable = $false
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625,4624,4720} -MaxEvents 10 -ErrorAction Stop
        $securityAvailable = $true
    } catch {
        $securityAvailable = $false
    }

    if ($securityAvailable) {
        $events | Format-List TimeCreated, Id, Message
    } else {
        Write-Host "    Security log not available, using System log..." -ForegroundColor Yellow
        Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 10 -ErrorAction SilentlyContinue | Format-List TimeCreated, Id, Message
    }
    Write-Host ""
}

# ============================================================
#  RUN
# ============================================================

if ($Output) {
    Start-Transcript -Path $Output
}

Show-Header
Get-SystemInfo
Get-SuspiciousProcesses
Get-NetworkConnections
Get-SheduledTasksCheck
Get-SuspiciousServices
Get-SuspiciousUsers
Get-SuspiciousEvents

if ($Output) {
    Stop-Transcript
}
