# Volatrace - Windows Memory Forensics & Incident Triage Framework

Volatrace is an automated digital forensics and incident response (DFIR) command-line tool designed to eliminate manual overhead during memory analysis. It parses raw memory images, reconstructs process execution hierarchies, detects injected shellcode, maps active network connections, and compiles all artifacts into an interactive, SOC-ready HTML triage dashboard.

---

## Features

- **Automated Memory Triage:** Executes core forensic routines sequentially without manual multi-step commands.
- **Process Lineage Analysis:** Uncovers process family trees to flag suspicious child processes, unauthorized shell spawns, and masquerading system binaries.
- **Injected Shellcode Hunting:** Scans target virtual memory descriptors for unbacked allocations carrying `PAGE_EXECUTE_READWRITE` permissions.
- **Active Network Socket Tracking:** Identifies listening, active, and terminated network sockets to pinpoint outbound Command & Control (C2) channels.
- **Interactive Visual Dashboard:** Builds a standalone dark-mode HTML incident report with search, severity indicators, and tabbed inspection views.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Detection Artifact |
| :--- | :--- | :--- | :--- |
| Execution | Command and Scripting Interpreter | T1059 | Child `cmd.exe` spawned under standard user processes |
| Defense Evasion | Process Injection | T1055 | Unbacked RWX memory allocations identified during injection triage |
| Defense Evasion | Masquerading | T1036 | Processes executing outside verified operating system paths |
| Command and Control | Application Layer Protocol | T1071 | Rogue network sockets recovered during endpoint scan |

---

## Windows Installation & Usage Guide

### 1. Clone the Repository
```cmd
git clone [https://github.com/cyberdef09/Volatrace-.git](https://github.com/cyberdef09/Volatrace-.git)
cd Volatrace-
```

### 2. Set Up Virtual Environment (Recommended)
```cmd
python -m venv venv
venv\Scripts\activate
```

### 3. Install Dependencies
```cmd
pip install -r requirements.txt
```

### 4. Place Target Memory Dump
Copy your target memory image (`sample.raw`, `memory.dmp`, or `.vmem`) inside the `Volatrace-` folder.

Verify the file exists:
```cmd
dir sample.raw
```

### 5. Run Triage Scan
```cmd
python Volatrace.py sample.raw
```

*(Replace `sample.raw` with the exact filename of your memory dump).*

### 6. View Interactive Report
```cmd
start output\Forensic_Dashboard_*.html
```

---

## Linux Installation & Usage Guide

### 1. Clone the Repository
```bash
git clone [https://github.com/cyberdef09/Volatrace-.git](https://github.com/cyberdef09/Volatrace-.git)
cd Volatrace-
```

### 2. Set Up Virtual Environment (Recommended)
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip3 install -r requirements.txt
```

### 4. Place Target Memory Dump
Copy your target memory image (`sample.raw`, `memory.dmp`, or `.vmem`) inside the `Volatrace-` folder.

Verify the file exists:
```bash
ls -lh sample.raw
```

### 5. Run Triage Scan
```bash
python3 Volatrace.py sample.raw
```

*(Replace `sample.raw` with the exact filename of your memory dump).*

### 6. View Interactive Report
```bash
xdg-open output/Forensic_Dashboard_*.html
```

---

## Expected Terminal Output

```text
=================================================================
      Volatrace - SOC Tier-2 Memory Forensics Dashboard       
=================================================================
[*] Analyzing Memory Target: sample.raw
[+] Extracting Process Execution Hierarchy...
[+] Scanning Injected Shellcode (RWX Memory Pages)...
[+] Recovering Active Network Sockets...
[*] Compiling Triage Dashboard...

[✓] Investigation Complete!
[✓] Dashboard Ready: output/Forensic_Dashboard_20260920_110000.html
```

