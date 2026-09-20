# Volatrace - Windows Memory Forensics & Incident Triage Framework

Volatrace is an automated digital forensics and incident response (DFIR) framework designed to eliminate manual command-line overhead during memory analysis. It rapidly parses raw Windows memory images, reconstructs process execution lineages, detects injected shellcode, maps active network connections, and compiles all artifacts into an interactive, SOC-ready HTML triage dashboard.

---

## Key Features

- Automated Incident Triage: Runs critical memory inspection routines sequentially without manual multi-step commands.
- Process Hierarchy Mapping: Reconstructs parent-child execution paths to expose anomalous child processes, root shell invocations, and masqueraded binaries.
- Injected Shellcode Detection: Scans target virtual memory descriptors for unbacked allocations carrying PAGE_EXECUTE_READWRITE permissions.
- Network Socket Recovery: Reconstructs active, listening, and closed TCP/UDP endpoints to identify Command and Control (C2) communication.
- Responsive SOC Dashboard: Outputs a dark-themed HTML report equipped with real-time text search, risk scoring, and categorized investigation tabs.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Detection Artifact |
| :--- | :--- | :--- | :--- |
| Execution | Command and Scripting Interpreter | T1059 | Child cmd.exe spawned under desktop shell (explorer.exe) |
| Defense Evasion | Process Injection | T1055 | Unbacked RWX memory sections identified during injection triage |
| Defense Evasion | Masquerading | T1036 | Processes executing outside standard System32 paths |
| Command and Control | Application Layer Protocol | T1071 | Rogue network sockets recovered during endpoint scan |

---

## Complete User Guide: Step-by-Step Commands

### Step 1: Clone the Repository

For Windows:
git clone https://github.com/cyberdef09/Volatrace-.git
cd Volatrace-

For Linux:
git clone https://github.com/cyberdef09/Volatrace-.git
cd Volatrace-

---

### Step 2: Set Up Virtual Environment (Optional but Recommended)

For Windows (Command Prompt):
python -m venv venv
venv\Scripts\activate

For Linux (Bash):
python3 -m venv venv
source venv/bin/activate

---

### Step 3: Install All Dependencies

For Windows:
pip install -r requirements.txt

For Linux:
pip3 install -r requirements.txt

---

### Step 4: Add Your Target Memory Dump
Place your raw memory dump file (such as sample.raw, memory.dmp, or evidence.raw) directly inside the Volatrace- folder.

To verify the file is present:

For Windows:
dir sample.raw

For Linux:
ls -lh sample.raw

---

### Step 5: Run Automated Triage Analysis

For Windows:
python Volatrace.py sample.raw

For Linux:
python3 Volatrace.py sample.raw

(Note: Replace sample.raw with the exact filename of your memory image).

---

### Step 6: View the Interactive Dashboard Report
Once the scan completes, open the generated HTML report in your browser:

For Windows:
start output\Forensic_Dashboard_*.html

For Linux:
xdg-open output/Forensic_Dashboard_*.html

---

## Expected Terminal Output During Execution

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

---
