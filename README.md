# Volatrace: Automated Windows Memory Forensics & Incident Triage Framework

Volatrace is an automated Digital Forensics and Incident Response (DFIR) framework built to eliminate manual command-line overhead during memory analysis. Powered by Volatility 3, Volatrace inspects raw Windows memory dumps, reconstructs process execution hierarchies, catches injected shellcode, maps network sockets, and compiles all findings into a responsive HTML triage dashboard.

---

## 🎯 Key Features

- **Automated Incident Triage:** Executes primary memory analysis routines in a single pass without manual script intervention.
- **Process Hierarchy Reconstruction (`windows.pstree`):** Traces parent-child execution lineages to spot suspicious command-line executions, unauthorized shells, and masqueraded binaries.
- **Injected Code Detection (`windows.malfind`):** Highlights unbacked executable memory allocations configured with `PAGE_EXECUTE_READWRITE` (RWX) permissions.
- **Network Socket Recovery (`windows.netscan`):** Reconstructs active, listening, and closed TCP/UDP sockets to locate Command & Control (C2) communication.
- **SOC-Ready Dashboard:** Generates a lightweight, dark-themed HTML report with real-time text searching, risk counters, and categorized artifact tabs.

---

## 🛡️ MITRE ATT&CK Mapping

| Tactic | Technique | ID | Detection Artifact |
| :--- | :--- | :--- | :--- |
| Execution | Command and Scripting Interpreter | T1059 | Identification of child `cmd.exe` spawned under `explorer.exe` |
| Defense Evasion | Process Injection | T1055 | Unbacked RWX memory allocations identified via `malfind` |
| Defense Evasion | Masquerading | T1036 | Non-standard execution locations outside `System32` |
| Command and Control | Application Layer Protocol | T1071 | Active and closed outbound sockets extracted via `netscan` |

---

## ⚙️ Requirements & Installation

### Prerequisites
- Python 3.8 or higher
- Git installed on host system (Windows or Linux)

### Step 1: Clone the Repository
```bash
git clone [https://github.com/cyberdef09/Volatrace-.git](https://github.com/cyberdef09/Volatrace-.git)
cd Volatrace-
