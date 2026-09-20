# Volatrace: Automated Windows Memory Forensics & Incident Triage Framework

Volatrace is an automated Digital Forensics and Incident Response (DFIR) framework designed to eliminate manual command-line overhead during memory analysis. Powered by Volatility 3, Volatrace rapidly parses raw Windows memory images, correlates process hierarchies, detects injected shellcode, maps active network connections, and compiles all artifacts into an interactive, SOC-ready HTML triage dashboard.

---

## Key Features

- Automated Incident Triage: Runs critical memory inspection plugins sequentially without manual repetitive syntax.
- Process Hierarchy Mapping (windows.pstree): Reconstructs parent-child execution paths to expose anomalous child processes, root shell invocations, and masqueraded binaries.
- Memory Injection Detection (windows.malfind): Scans for unbacked memory allocations configured with PAGE_EXECUTE_READWRITE (RWX) permissions.
- Network Socket Reconstruction (windows.netscan): Recovers active and closed TCP/UDP endpoints to identify Command and Control (C2) communication.
- Responsive SOC Dashboard: Outputs a dark-themed HTML report equipped with real-time text search, risk scoring, and categorized investigation tabs.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Detection Artifact |
| :--- | :--- | :--- | :--- |
| Execution | Command and Scripting Interpreter | T1059 | Child cmd.exe spawned under explorer.exe |
| Defense Evasion | Process Injection | T1055 | Unbacked RWX memory sections identified via malfind |
| Defense Evasion | Masquerading | T1036 | Processes executing outside standard System32 paths |
| Command and Control | Application Layer Protocol | T1071 | Rogue network sockets recovered via netscan |

---

## Complete User Guide: Step-by-Step Commands

### Step 1: Clone the repository
git clone https://github.com/cyberdef09/Volatrace-.git

### Step 2: Enter project folder
cd Volatrace-

### Step 3: Install all dependencies
pip install -r requirements.txt

### Step 4: Add your target memory dump
Copy your acquired Windows memory file (e.g. sample.raw, memory.dmp, or evidence.raw) directly into this folder.

To verify the file is present:
dir sample.raw

### Step 5: Run the automated triage analysis
python Volatrace.py sample.raw

(Replace sample.raw with the exact filename of your memory dump).

### Step 6: View the interactive dashboard report
Once the terminal displays analysis complete, open the generated HTML report in your browser:

On Windows:
start output\Forensic_Dashboard_*.html

On Linux:
xdg-open output/Forensic_Dashboard_*.html

---

## Expected Terminal Output During Execution

Target: sample.raw
[*] Running windows.pstree (Process Tree Extraction)...
[*] Running windows.malfind (Injected Shellcode Scan)...
[*] Running windows.netscan (Active Socket Recovery)...
[*] Compiling Triage Dashboard...

[DONE] Investigation Complete!
[DONE] Dashboard Ready: output/Forensic_Dashboard_20260920_110000.html

---

## Case Study: MemLabs Incident Findings

During baseline testing against a real-world compromised endpoint memory, Volatrace automatically flagged:
- Phishing Execution: Extracted user execution of compressed archives (Important.rar) and accompanying terminal invocations (cmd.exe).
- Memory Injection: Identified 11 anomalous allocations carrying PAGE_EXECUTE_READWRITE protections in core system processes (svchost.exe PID 948).
- Forensic Footprint: Confirmed memory acquisition artifacts left by live acquisition tools (DumpIt.exe).

---

## Repository Structure

- Volatrace.py : Core triage engine and HTML dashboard generator
- requirements.txt : Project dependencies (Volatility 3)
- README.md : Documentation and full user manual
- output/ : Directory containing generated forensic HTML reports

---

## License

This project is licensed under the MIT License.
