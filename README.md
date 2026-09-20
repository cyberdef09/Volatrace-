# Volatrace: Automated Windows Memory Forensics & Incident Triage Framework

Volatrace is a high-speed digital forensics and incident response (DFIR) framework designed to eliminate manual command-line overhead during memory analysis. Powered by Volatility 3, Volatrace inspects raw memory images, extracts core execution artifacts, detects injected shellcode, maps rogue network connections, and compiles findings into an interactive HTML dashboard.

---

## 🎯 Key Features

- **Automated Incident Triage:** Runs core memory forensic checks sequentially without manual intervention.
- **Process Hierarchy Mapping (`windows.pstree`):** Reconstructs parent-child process execution paths to detect anomalous child processes, shell spawns, and masquerading.
- **Memory Injection Detection (`windows.malfind`):** Scans for unbacked memory allocations configured with `PAGE_EXECUTE_READWRITE` (RWX) permissions.
- **Network Socket Reconstruction (`windows.netscan`):** Recovers active and closed TCP/UDP endpoints to expose Command and Control (C2) communication.
- **Responsive SOC Dashboard:** Generates an interactive, dark-themed HTML report featuring instant search and categorized alert tabs.

---

## 🛡️ MITRE ATT&CK Mapping

| Tactic | Technique | ID | Detection Artifact |
| :--- | :--- | :--- | :--- |
| **Execution** | Command and Scripting Interpreter | T1059 | Child `cmd.exe` spawning from explorer |
| **Defense Evasion** | Process Injection | T1055 | RWX memory protections identified via `malfind` |
| **Defense Evasion** | Masquerading | T1036 | Displaced system processes |
| **Command and Control** | Application Layer Protocol | T1071 | Rogue network sockets extracted via `netscan` |

---

## 🚀 Installation & Usage

### 1. Clone the Repository
```bash
git clone [https://github.com/cyberdef09/Volatrace-.git](https://github.com/cyberdef09/Volatrace-.git)
cd Volatrace-
