# Invoke-Triage.ps1

PowerShell endpoint triage script for SOC analysts. Collects forensic artifacts from a Windows endpoint in a single command for initial incident response.

## What it does

Instead of opening 7 different tools (Task Manager, Event Viewer, netstat, services.msc...), you run one script and get a full triage report in seconds.

| Section | What it collects |
|---------|-----------------|
| System Info | Hostname, OS, IP, user, uptime |
| Processes | Running processes outside standard paths (Windows, Program Files) |
| Network | Established TCP connections with process name resolution |
| Scheduled Tasks | Tasks executing from non-standard locations |
| Services | Services with executables outside standard paths |
| Local Accounts | All local accounts with status and last logon |
| Security Events | Security log (4624/4625/4720) with System log fallback (7045) |

## Usage

```powershell
# Basic triage - output to console
.\Invoke-Triage.ps1

# Export to file
.\Invoke-Triage.ps1 -Output report.txt
```

> Requires Administrator privileges for full results.

## Example Output

```
============================================
  ENDPOINT TRIAGE REPORT
  Date: 2026-04-24 19:57:34
============================================

[1] SYSTEM INFORMATION
    Hostname:  YOURPC
    User:      analyst
    OS:        Microsoft Windows 11 Pro
    IP:        192.168.1.100

[2] RUNNING PROCESSES
ProcessName          Id Path
-----------          -- ----
beacon             1234 C:\Users\victim\AppData\Local\Temp\beacon.exe

[4] SCHEDULED TASKS
TaskName : ExplorerUpdater
Action   : C:\Users\victim\AppData\Local\Temp\beacon.exe

...
```

## Detection Logic

The script filters by **path exclusion**: it removes known-good locations (Windows, Program Files) and shows what remains. This catches the majority of malware that executes from Temp, AppData, Downloads, or custom directories.

## Planned Improvements (v2)

- Digital signature verification (`Get-AuthenticodeSignature`) as a second detection layer
- Active Directory support (`Get-ADUser`) when running on a Domain Controller
- DNS cache analysis (`Get-DnsClientCache`)
- Registry autoruns (Run/RunOnce keys)

