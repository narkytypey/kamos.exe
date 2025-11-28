#  KAMOS - Stealth System Recon Engine (for windows, for now <3)

<div align="center">

![Version](https://img.shields.io/badge/version-1.0-blue.svg?style=for-the-badge)
![Language](https://img.shields.io/badge/language-C%2B%2B-red.svg?style=for-the-badge)
![Platform](https://img.shields.io/badge/platform-Windows-0078D4.svg?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)
![Status](https://img.shields.io/badge/status-Active-brightgreen.svg?style=for-the-badge)

**A weaponized reconnaissance tool that operates silently through native Windows APIs. Designed to evade EDR/AV detection while gathering complete system intelligence.**

[ Documentation ](#-documentation) 

</div>

---

Modern Endpoint Detection & Response (EDR) systems are trained to catch obvious reconnaissance. They watch for cmd.exe spawning child processes and flag the classic recon sequence immediately.

```
Traditional Reconnaissance (Gets Caught):
┌─────────────────────────────────┐
│ cmd.exe (PARENT)                │ ◄── EDR ALARM 
├─→ whoami.exe (CHILD)            │     "Process Creation Detected"
├─→ ipconfig.exe (CHILD)          │     "Child Process Anomaly"
├─→ tasklist.exe (CHILD)          │     "Command Execution Pattern"
└─→ systeminfo.exe (CHILD)        │
└─────────────────────────────────┘
        ❌ IMMEDIATE DETECTION
```

vs.

```
KAMOS Approach (Stays Silent):
┌──────────────────────────────────┐
│ kamos.exe (SINGLE PROCESS)       │ ◄── EDR: "Normal Activity"
├─ OpenProcessToken()             │     ✓ Legitimate API
├─ GetAdaptersAddresses()         │     ✓ Common operation
├─ CreateToolhelp32Snapshot()     │     ✓ Standard enumeration
├─ GetSystemInfo()                │     ✓ Regular query
└─ FindFirstFile()                │     ✓ File system access
└──────────────────────────────────┘
        ✅ ZERO DETECTION
```

---

##  Why KAMOS is Different

| Aspect | Traditional Tools | KAMOS |
|--------|-------------------|-------|
| **Child Processes** | ❌ 4-6 spawned | ✅ 0 (single binary) |
| **EDR Signature** | ❌ cmd.exe parent-child | ✅ zero behavioral flags |
| **Command-Line Keywords** | ❌ obvious (`whoami`, `ipconfig`) | ✅ subtle arguments |
| **Process Footprint** | ❌ multiple PIDs | ✅ single PID |
| **API Layer** | ❌ shell wrapper | ✅ direct native APIs |
| **Evasion Rating** | ❌ Low | ✅ **MILITARY GRADE** |
| **Binary Size** | ❌ Multiple files | ✅ Single ~300KB executable |

---

## Features

### Token & Privilege Enumeration
Extract current user identity, all privileges, and group memberships directly from process token.

```bash
kamos.exe tokeninfo
```

**Output:**
```
[*] User Information
    Username: CORPORATE\Administrator
    SID: S-1-5-21-3623811015-3361044348-30300510-500

[*] Privileges
    SeDebugPrivilege ........................ ENABLED 
    SeImpersonatePrivilege ................. ENABLED 
    SeLoadDriverPrivilege .................. ENABLED 
    SeTcbPrivilege ......................... DISABLED
    SeBackupPrivilege ...................... ENABLED 

[*] Group Membership
    [+] CORPORATE\Domain Admins (ENABLED)
    [+] CORPORATE\Enterprise Admins (ENABLED)
    [+] Builtin\Administrators (ENABLED)
```

**Replaces**: `whoami /priv` • `whoami /groups` • `Get-TokenPrivileges`

---

### Network Intelligence
Full network adapter enumeration including IPv4, IPv6, DNS servers, gateways, and operational status.

```bash
kamos.exe network
```

**Output:**
```
[Adapter 1] Intel(R) Ethernet
    Status: UP 
    MAC Address: 00-1A-2B-3C-4D-5E
    IPv4: 192.168.1.100
    IPv6: fe80::800:27ff:fe00:abcd
    Gateway: 192.168.1.1
    DNS: 8.8.8.8, 8.8.4.4

[Adapter 2] Hyper-V Virtual Switch
    Status: DOWN
    MAC Address: 00-15-5D-00-11-22
```

**Replaces**: `ipconfig /all` • `Get-NetAdapter` • `wmic nicconfig`

---

### Process Enumeration
Real-time process listing with parent-child relationships, integrity levels, and command line arguments.

```bash
kamos.exe proclist
```

**Output:**
```
PID      PPID     Process Name                      Integrity      
──────────────────────────────────────────────────────────────────
4        0        System                            System
568      4        smss.exe                          System
648      568      csrss.exe                         System
2156     648      explorer.exe                      High
3024     2156     chrome.exe                        Medium
4128     3024     chrome.exe                        Medium
```

**Replaces**: `tasklist` • `tasklist /v` • `Get-Process` • `wmic process list`

---

### System Intelligence
Comprehensive system profiling including OS version, CPU architecture, memory, uptime, and domain information.

```bash
kamos.exe sysinfo
```

**Output:**
```
[*] Computer Details
    Computer Name: WORKSTATION-42
    Domain: CORPORATE.LOCAL
    OS Version: 10.0 Build 19045 (Windows 10 Pro)
    OS Type: Workstation
    
[*] Processor Information
    Architecture: x64
    Processor Count: 8 cores
    Page Size: 4096 bytes
    
[*] Memory Information
    Total Physical Memory: 16384 MB (16 GB)
    Available Memory: 8192 MB (8 GB)
    Memory Load: 50%
    
[*] System Uptime
    Uptime: 45 days, 12 hours, 33 minutes
```

**Replaces**: `systeminfo` • `Get-ComputerInfo` • `msinfo32` • `wmic os`

---

### Directory Listing
Enumerate directory contents with full file metadata (size, timestamps, attributes).

```bash
kamos.exe dir C:\Users\Administrator\
```

**Output:**
```
[Path] C:\Users\Administrator\

Filename                           Size            Type
────────────────────────────────────────────────────────
Desktop                            <DIR>           <FOLDER>
Documents                          <DIR>           <FOLDER>
Downloads                          <DIR>           <FOLDER>
AppData                            <DIR>           <FOLDER>
.bashrc                            1024 B          <FILE>
passwords.txt                      2048 B          <FILE>
config.json                        4096 B          <FILE>
```

**Replaces**: `dir` • `ls` • `Get-ChildItem`

---

### Full System Recon
Execute all reconnaissance modules in optimal sequence for complete system profiling.

```bash
kamos.exe all
```

Runs: tokeninfo → network → proclist → sysinfo → dir (C:\)

---

## Technical Architecture

### Why It's Impossible to Detect

#### 1. **Zero Child Process Creation**
Traditional tools use the Win32 `CreateProcess()` function which triggers EDR process creation callbacks.

```cpp
// ❌ Detected Immediately
CreateProcess(L"cmd.exe", L"/c whoami", ...);

// ✅ Silent
OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
```

#### 2. **Native API Legitimacy**
Every API KAMOS uses is called thousands of times daily by legitimate Windows processes.

```
GetAdaptersAddresses()  → Called by: Outlook, Chrome, Zoom, Teams, Discord, etc.
GetTokenInformation()   → Called by: Windows Defender, Task Scheduler, UAC, etc.
CreateToolhelp32Snapshot() → Called by: Task Manager, Process Explorer, Performance Monitor
FindFirstFile()         → Called by: Windows Explorer, File Manager, Backup Utilities
```

#### 3. **Single Process Identity**
No suspicious parent-child relationships. No process tree anomalies. Just one process doing legitimate work.

#### 4. **Behavioral Stealth**
Even if EDR hooks the APIs, KAMOS operations appear normal:
- Asking for token info = regular diagnostic activity
- Enumerating adapters = network troubleshooting
- Listing processes = system monitoring
- Querying disk = file operations

---

### API Implementation Stack

| Function | Purpose | Risk Level |
|----------|---------|-----------|
| `OpenProcessToken()` | Access process token | 🟢 Low (diagnostic) |
| `GetTokenInformation()` | Query token data | 🟢 Low (common) |
| `GetAdaptersAddresses()` | Network enumeration | 🟢 Low (frequent) |
| `CreateToolhelp32Snapshot()` | Process enumeration | 🟢 Low (normal) |
| `GetSystemInfo()` | CPU/architecture info | 🟢 Low (standard) |
| `GlobalMemoryStatusEx()` | Memory querying | 🟢 Low (routine) |
| `FindFirstFile()` | Directory listing | 🟢 Low (daily) |
| `RtlGetVersion()` | OS version | 🟢 Low (diagnostic) |

**Result**: Pure green across the board. No suspicious APIs.

---

## 📦 Installation & Deployment

### Quick Build

```bash
# Clone repository
git clone https://github.com/YourUsername/kamos.git
cd kamos

# Build with automated script
build.bat

# or you can built with cmake and their alternatives it is on you
cmake --build . --config Release
```

### Compilation Requirements

- **Visual Studio 2019+** or **Visual Studio Build Tools**
- **Windows SDK** (included with Visual Studio)
- **C++17 support**

##  Usage Guide

### Command Syntax

```bash
kamos.exe <command>
```

### Available Commands

| Command | Description |
|---------|-------------|
| `tokeninfo` | Token, privileges, and group membership |
| `network` | Network adapter configuration and DNS |
| `proclist` | Process listing with parent relationships |
| `sysinfo` | System information and specs |
| `dir <path>` | Directory enumeration |
| `all` | Complete system reconnaissance |

### Command Examples

```bash
# Get current user privileges
kamos.exe tokeninfo

# Check network configuration
kamos.exe network

# List all running processes
kamos.exe proclist

# System information
kamos.exe sysinfo

# Browse directories
kamos.exe dir C:\Users\
kamos.exe dir C:\Windows\System32
kamos.exe dir C:\

# Full reconnaissance (all modules)
kamos.exe all
```

---


### KAMOS v1.0

- [ ] Registry key enumeration (HKLM/HKCU)
- [ ] Scheduled tasks listing (TaskScheduler COM)
- [ ] Installed software inventory (registry parsing)
- [ ] ARP table enumeration (GetIpNetTable)
- [ ] Network connections (GetTcpTable, GetUdpTable)
- [ ] Windows services (OpenSCManager)
- [ ] Firewall rules (INetFwPolicy2)
- [ ] WLAN profiles (WlanEnumInterfaces)
- [ ] Bitlocker status
- [ ] User accounts (NetUserEnum)
- [ ] File shares (NetShareEnum)
- [ ] JSON output format
- [ ] Output encryption
- [ ] C2 integration


## Legal & Disclaimer

**AUTHORIZED USE ONLY**
I dont dictate, just informing

##  References

### Documentation
- [Microsoft Windows API](https://docs.microsoft.com/en-us/windows/win32/)
- [Process Creation & EDR](https://docs.microsoft.com/en-us/windows/win32/procthread/process-creation)
- [Token Management](https://docs.microsoft.com/en-us/windows/win32/secauthz/tokens)

## 📄 License

Do You Have Any? Cuz we dont have :)

```
Copyright (c) 2024 KAMOS Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files...
```


</div>
