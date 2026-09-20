# Volatrace: Automated Windows Memory Forensics & Incident Triage Framework

Volatrace is an automated Digital Forensics and Incident Response (DFIR) framework designed to eliminate manual CLI overhead during memory analysis. Powered by Volatility 3, Volatrace rapidly parses raw Windows memory images, correlates process hierarchies, detects injected shellcode, maps active network connections, and compiles all artifacts into an interactive, SOC-ready HTML triage dashboard.

---

## 🎯 Key Features

- **Automated Incident Triage:** Runs critical memory inspection plugins sequentially without manual repetitive syntax.
- **Process Hierarchy Mapping (`windows.pstree`):** Reconstructs parent-child execution paths to expose anomalous child processes, root shell invocations, and masqueraded binaries.
- **Memory Injection Detection (`windows.malfind`):** Scans for unbacked memory allocations configured with `PAGE_EXECUTE_READWRITE` (RWX) permissions (e.g., shellcode stagers, reflective DLLs).
- **Network Socket Reconstruction (`windows.netscan`):** Recovers active and closed TCP/UDP endpoints to identify Command and Control (C2) communication.
- **Responsive SOC Dashboard:** Outputs a dark-themed HTML report equipped with real-time text search, risk scoring, and categorized investigation tabs.

---

## 🛡️ MITRE ATT&CK Mapping

| Tactic | Technique | ID | Detection Artifact |
| :--- | :--- | :--- | :--- |
| Execution | Command and Scripting Interpreter | T1059 | Child `cmd.exe` spawned under desktop shell (`explorer.exe`) |
| Defense Evasion | Process Injection | T1055 | Unbacked RWX memory sections identified via `malfind` |
| Defense Evasion | Masquerading | T1036 | Processes executing outside standard `System32` paths |
| Command and Control | Application Layer Protocol | T1071 | Rogue network sockets recovered via `netscan` |

---

## 🚀 Installation

### 1. Prerequisites
Ensure Python 3.8+ is installed on your host system (Windows or Linux).

### 2. Clone the Repository
```bash
git clone [https://github.com/cyberdef09/Volatrace-.git](https://github.com/cyberdef09/Volatrace-.git)
cd Volatrace-
