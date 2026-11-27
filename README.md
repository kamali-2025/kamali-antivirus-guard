# 🛡️ Python Antivirus Guard (v1.1)
**Created by Dr. Alireza Kamali Dehkordi**

A lightweight, defensive Windows desktop security suite built with Python and Tkinter, featuring real-time folder monitoring, signature-based malware scanning, quarantine management, startup auditing, and live network/IP threat inspection.

## ✨ Key Features
- **Folder & File Scanner:** Scans files against SHA-256 threat signatures (`signatures.json`) and heuristic rules.
- **Real-Time Folder Monitor:** Continuously watches target directories for newly created or modified suspicious files.
- **Quarantine Vault:** Safely isolates flagged files and allows controlled restoration.
- **Startup Audit:** Inspects Windows startup entries for unauthorized persistence programs.
- **Network / IP Threat Guard (New in v1.1):**
  - Scans active external TCP connections (`netstat`) and maps each remote IP to its Windows process (`PID` / `.exe`).
  - Queries public registry & geolocation data (country, city, ISP/ASN, and cloud/VPN flags) for any target IP.
  - Applies defensive **Windows Defender Firewall** inbound/outbound block rules (`netsh advfirewall`) with one click.

## 🚀 How to Run from Source (Windows)
```bash
python antivirus_gui.py
```
*(No external pip packages required—uses Python's built-in standard library and Windows system utilities.)*
