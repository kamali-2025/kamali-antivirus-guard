# 🛡️ Python Antivirus Guard (v2.5)

**Created by Dr. Alireza Kamali Dehkordi**

A lightweight, defensive Windows desktop security suite built with Python and Tkinter, featuring a **Dark Cyber-SOC Console**, real-time folder monitoring, multi-engine malware scanning, **Smart Risk Scoring**, **MITRE ATT&CK** technique tagging, automated quarantine, and compliance reporting.

---

## ✨ What's New in v2.5
* **Dark Cyber-SOC Console UI:** Modern dark-mode Security Operations Center interface with real-time telemetry, threat status badges, and color-coded severity logs.
* **Smart Risk Score Engine:** Dynamic threat scoring (`0–100`) evaluating file entropy, PE header anomalies, suspicious strings, and signature matches.
* **MITRE ATT&CK Mapping:** Automatically maps detected behaviors and signatures to relevant **MITRE ATT&CK** tactics and technique IDs.
* **Auto-Quarantine & Isolation:** Safely isolates flagged files into an encrypted/locked quarantine vault with one-click restore or permanent purge.
* **Real-Time Watchdog Shield:** Continuous background directory monitoring that inspects newly created or modified files on the fly.
* **PDF & CSV Audit Reporting:** Export detailed scan summaries, risk scores, file hashes (`SHA-256`), and MITRE ATT&CK findings to **PDF** or **CSV** reports.

---

## 🚀 Key Features
* **Multi-Engine Detection:**
  * Cryptographic hash matching (`MD5` / `SHA-256`) via `signatures.json`
  * Heuristic & Shannon entropy analysis for packed or obfuscated executables
  * Suspicious API & script pattern inspection
* **Flexible Scan Modes:** Quick Scan, Full Directory Scan, Single File Inspection, and Real-Time Folder Watchdog.
* **Standalone Windows Executable:** Bundled via PyInstaller (`PythonAntivirusGuard.spec`) for zero-dependency execution on Windows.

---

## 🛠️ Installation & Usage

### Option 1: Run from Source
1. Clone the repository:
   ```bash
   git clone https://github.com
   cd kamali-antivirus-guard
   ```
2. Install required dependencies:
   ```bash
   pip install watchdog reportlab
   ```
3. Launch the Cyber-SOC Console:
   ```bash
   python antivirus_gui.py
   ```

### Option 2: Run Standalone `.exe`
Download **`PythonAntivirusGuard.exe`** from the **[Releases](https://github.com)** section and run it directly on Windows.

---

## ⚠️ Disclaimer
This software is designed for **educational, research, and defensive security auditing purposes**. It is intended to complement—not replace—enterprise endpoint protection or Windows Defender.
