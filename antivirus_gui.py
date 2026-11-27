# ==========================================
# Python Antivirus Guard
# Created by: Dr. Alireza Kamali Dehkordi
# ==========================================
import math
import winreg
import csv
from datetime import datetime
import hashlib
import json
import os
import re
import shutil
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

import sys
import urllib.request
import subprocess
APP_DIR = os.path.dirname(
    os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__)
)
SIGNATURES_FILE = os.path.join(APP_DIR, "signatures.json")
QUARANTINE_DIR = os.path.join(APP_DIR, "quarantine_vault")
MANIFEST_FILE = os.path.join(QUARANTINE_DIR, "manifest.json")
LOG_FILE = os.path.join(APP_DIR, "scan_history.csv")

# Replace with your own GitHub Raw / Gist JSON URL whenever you want live cloud updates
UPDATE_URL = "https://githubusercontent.com"


def update_signatures_online():
    db = load_signatures()
    try:
        req = urllib.request.Request(
            UPDATE_URL, headers={"User-Agent": "PythonAntivirusGuard/1.0"}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            remote_db = json.loads(resp.read().decode("utf-8"))

        db.setdefault("hashes", {}).update(remote_db.get("hashes", {}))
        db.setdefault("heuristics", {}).update(remote_db.get("heuristics", {}))
        db["version"] = remote_db.get("version", db.get("version", "1.0"))

        with open(SIGNATURES_FILE, "w", encoding="utf-8") as f:
            json.dump(db, f, indent=4)
        return True, f"Updated to v{db['version']} ({len(db['hashes'])} hashes, {len(db['heuristics'])} rules)"
    except Exception:
        return False, f"Offline/Local mode ({len(db.get('hashes', {}))} hashes, {len(db.get('heuristics', {}))} rules active)"



def load_signatures():
    default_db = {
        "hashes": {
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Test-File"
        },
        "heuristics": {
            "Suspicious PowerShell Execution": "powershell.*-enc",
            "Dangerous System Eval": "eval\\s*\\(\\s*base64_decode",
            "Unauthorized Shadow Copy Deletion": "vssadmin\\s+delete\\s+shadows",
        },
    }
    if not os.path.exists(SIGNATURES_FILE):
        with open(SIGNATURES_FILE, "w", encoding="utf-8") as f:
            json.dump(default_db, f, indent=4)
        return default_db

    with open(SIGNATURES_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def log_event(file_path, detection_type, threat_name, action):
    file_exists = os.path.isfile(LOG_FILE)
    with open(LOG_FILE, mode="a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(
                ["Timestamp", "File Path", "Detection Type", "Threat Name", "Action"]
            )
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            file_path,
            detection_type,
            threat_name,
            action,
        ])


def load_manifest():
    if os.path.exists(MANIFEST_FILE):
        with open(MANIFEST_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_manifest(manifest):
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    with open(MANIFEST_FILE, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=4)


def quarantine_file(file_path, detection_type, threat_name):
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    filename = os.path.basename(file_path)
    quarantined_name = f"{filename}.quarantined"
    quarantined_path = os.path.join(QUARANTINE_DIR, quarantined_name)

    counter = 1
    while os.path.exists(quarantined_path):
        quarantined_name = f"{filename}_{counter}.quarantined"
        quarantined_path = os.path.join(QUARANTINE_DIR, quarantined_name)
        counter += 1

    original_abs_path = os.path.abspath(file_path)
    shutil.move(file_path, quarantined_path)

    manifest = load_manifest()
    manifest[quarantined_name] = {
        "original_path": original_abs_path,
        "threat": threat_name,
        "quarined_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    save_manifest(manifest)
    log_event(original_abs_path, detection_type, threat_name, "Quarantined")
    return quarantined_name


def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def scan_single_file(file_path, db):
    try:
        file_hash = calculate_sha256(file_path)
        if file_hash in db["hashes"]:
            threat = db["hashes"][file_hash]
            q_name = quarantine_file(file_path, "Signature", threat)
            return f"[ALERT - SIGNATURE] {file_path} ({threat}) -> {q_name}"

        with open(file_path, "rb") as f:
            content = f.read()

        for rule_name, pattern_str in db["heuristics"].items():
            if re.search(pattern_str.encode("utf-8"), content, re.IGNORECASE):
                q_name = quarantine_file(file_path, "Heuristic", rule_name)
                return f"[ALERT - HEURISTIC] {file_path} ({rule_name}) -> {q_name}"

        # Step 3: Entropy Check (flags packed/encrypted executables & scripts)
        risky_exts = (".exe", ".dll", ".bat", ".ps1", ".vbs", ".scr", ".cmd")
        if file_path.lower().endswith(risky_exts):
            entropy = calculate_entropy(file_path)
            if entropy >= 7.5:
                reason = f"High Entropy / Packed ({entropy}/8.0)"
                q_name = quarantine_file(file_path, "Entropy", reason)
                return f"[ALERT - ENTROPY] {file_path} ({reason}) -> {q_name}"

    except (PermissionError, FileNotFoundError, OSError):
        pass
    return None




def calculate_entropy(file_path):
    """Calculates Shannon entropy (0 to 8). High values (>7.2) indicate packed or encrypted files."""
    try:
        with open(file_path, "rb") as f:
            data = f.read(1024 * 512)  # Read first 512 KB for speed
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        for byte_val in range(256):
            count = data.count(byte_val)
            if count > 0:
                p_x = count / length
                entropy -= p_x * math.log2(p_x)
        return round(entropy, 2)
    except OSError:
        return 0.0


def audit_windows_startup():
    """Reads Windows 11 Current User Startup Registry entries."""
    startup_items = []
    reg_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_READ) as key:
            index = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, index)
                    startup_items.append(f"{name} -> {value}")
                    index += 1
                except OSError:
                    break
    except OSError as e:
        startup_items.append(f"Could not read registry: {e}")
    return startup_items

class AntivirusGUI:
    def run_startup_audit(self):
        self.log_ui("--- Windows 11 Startup Registry Audit ---")
        items = audit_windows_startup()
        if not items:
            self.log_ui("No user startup registry entries found.")
        for item in items:
            self.log_ui(f"[STARTUP] {item}")

    def __init__(self, root):
        self.root = root
        self.root.title("Python Antivirus Guard - Created by Dr. Alireza Kamali Dehkordi")
        self.root.geometry("860x520")

        
        self.monitoring = False
        self.db = load_signatures()

        btn_frame = tk.Frame(root, pady=10)
        btn_frame.pack(fill=tk.X, padx=10)

        tk.Button(btn_frame, text="Scan Folder", width=15, command=self.start_scan).pack(side=tk.LEFT, padx=5)
        self.monitor_btn = tk.Button(btn_frame, text="Start Monitor", width=15, command=self.toggle_monitor)
        self.monitor_btn.pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Quarantine Vault", width=15, command=self.open_quarantine_window).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Reload Signatures", width=15, command=self.reload_db).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Create Test Threat", width=15, command=self.create_test_file).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Startup Audit", width=15, command=self.run_startup_audit).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Check Updates", width=15, command=self.auto_update_db).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Network / IP Guard", width=17, command=self.open_network_guard).pack(side=tk.LEFT, padx=5)

        self.status_var = tk.StringVar(value="Status: Ready | Signatures loaded.")
        tk.Label(root, textvariable=self.status_var, anchor="w", fg="blue").pack(fill=tk.X, padx=12)

        self.console = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=22, font=("Consolas", 10))
        self.console.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.log_ui("System initialized. External database: signatures.json")
        self.log_ui("Python Antivirus Guard v1.0 | Created by Dr. Alireza Kamali Dehkordi")
        self.auto_update_db()
        self.log_ui("System initialized. External database: signatures.json")

    def log_ui(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.console.insert(tk.END, f"[{timestamp}] {message}\n")
        self.console.see(tk.END)

    def reload_db(self):
        self.db = load_signatures()
        self.log_ui("Reloaded threat definitions from signatures.json.")

    def auto_update_db(self):
        def _worker():
            self.status_var.set("Status: Checking for definition updates...")
            ok, msg = update_signatures_online()
            self.db = load_signatures()
            self.log_ui(f"[UPDATE] {msg}")
            self.status_var.set(f"Status: Ready | {msg}")
        threading.Thread(target=_worker, daemon=True).start()


        self.db = load_signatures()
        self.log_ui("Reloaded threat definitions from signatures.json.")

    def create_test_file(self):
        os.makedirs("test_lab", exist_ok=True)
        path = os.path.join("test_lab", "suspicious_demo.bat")
        with open(path, "w", encoding="utf-8") as f:
            f.write("powershell.exe -enc SGVsbG8=")
        self.log_ui(f"Created safe test file: {os.path.abspath(path)}")

    def start_scan(self):
        folder = filedialog.askdirectory(title="Select Folder to Scan")
        if not folder:
            return
        threading.Thread(target=self._run_scan_thread, args=(folder,), daemon=True).start()

    def _run_scan_thread(self, folder):
        self.status_var.set(f"Status: Scanning {folder}...")
        self.log_ui(f"Starting recursive scan on: {folder}")
        scanned, threats = 0, 0

        for root_dir, _, files in os.walk(folder):
            if os.path.abspath(root_dir).startswith(os.path.abspath(QUARANTINE_DIR)):
                continue
            for file in files:
                scanned += 1
                alert = scan_single_file(os.path.join(root_dir, file), self.db)
                if alert:
                    threats += 1
                    self.log_ui(alert)

        self.status_var.set(f"Status: Scan complete ({scanned} checked, {threats} quarantined).")
        self.log_ui(f"Scan finished: {scanned} file(s) scanned, {threats} threat(s) isolated.")

    def toggle_monitor(self):
        if not self.monitoring:
            folder = filedialog.askdirectory(title="Select Folder to Monitor in Real Time")
            if not folder:
                return
            self.monitoring = True
            self.monitor_btn.config(text="Stop Monitor", bg="#ffcccc")
            self.status_var.set(f"Status: Real-time protection active on {folder}")
            self.log_ui(f"Real-time monitor started on: {folder}")
            threading.Thread(target=self._monitor_thread, args=(folder,), daemon=True).start()
        else:
            self.monitoring = False
            self.monitor_btn.config(text="Start Monitor", bg="SystemButtonFace")
            self.status_var.set("Status: Real-time monitor stopped.")
            self.log_ui("Real-time monitor stopped.")

    def _monitor_thread(self, folder):
        known_files = {}
        while self.monitoring:
            for root_dir, _, files in os.walk(folder):
                if os.path.abspath(root_dir).startswith(os.path.abspath(QUARANTINE_DIR)):
                    continue
                for file in files:
                    file_path = os.path.join(root_dir, file)
                    try:
                        mtime = os.path.getmtime(file_path)
                        if file_path not in known_files or known_files[file_path] != mtime:
                            known_files[file_path] = mtime
                            alert = scan_single_file(file_path, self.db)
                            if alert:
                                self.log_ui(alert)
                    except FileNotFoundError:
                        continue
            time.sleep(1.5)

    def open_quarantine_window(self):
        manifest = load_manifest()
        win = tk.Toplevel(self.root)
        win.title("Quarantine Vault")
        win.geometry("550x320")

        listbox = tk.Listbox(win, width=80, height=12)
        listbox.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        keys = list(manifest.keys())
        for q_name in keys:
            info = manifest[q_name]
            listbox.insert(tk.END, f"{q_name} | Threat: {info['threat']} | From: {info['original_path']}")

        def restore_selected():
            sel = listbox.curselection()
            if not sel:
                return
            q_name = keys[sel[0]]
            info = manifest[q_name]
            q_path = os.path.join(QUARANTINE_DIR, q_name)
            orig_path = info["original_path"]

            if os.path.exists(q_path):
                os.makedirs(os.path.dirname(orig_path), exist_ok=True)
                shutil.move(q_path, orig_path)
                del manifest[q_name]
                save_manifest(manifest)
                log_event(orig_path, "Manual Override", "False Positive", "Restored")
                self.log_ui(f"[RESTORED] {q_name} -> {orig_path}")
                messagebox.showinfo("Restored", f"File restored to:\n{orig_path}")
                win.destroy()

        tk.Button(win, text="Restore Selected File", command=restore_selected).pack(pady=8)
    def open_network_guard(self):
        win = tk.Toplevel(self.root)
        win.title("Network & IP Threat Guard (Defensive Monitor)")
        win.geometry("760x480")

        top = tk.Frame(win)
        top.pack(fill=tk.X, padx=10, pady=8)

        tk.Label(top, text="Target IP:").pack(side=tk.LEFT)
        ip_entry = tk.Entry(top, width=22, font=("Consolas", 10))
        ip_entry.pack(side=tk.LEFT, padx=6)

        out = scrolledtext.ScrolledText(win, wrap=tk.WORD, height=20, font=("Consolas", 10))
        out.pack(fill=tk.BOTH, expand=True, padx=10, pady=6)

        def write_out(msg):
            out.insert(tk.END, msg + "\n")
            out.see(tk.END)

        def scan_connections():
            out.delete("1.0", tk.END)
            write_out("[SCAN] Checking active external TCP connections on Windows...")
            try:
                tasks = {}
                tl = subprocess.check_output("tasklist /FO CSV /NH", shell=True, text=True, errors="ignore")
                for line in tl.splitlines():
                    parts = [p.strip('"') for p in line.split('","')]
                    if len(parts) >= 2:
                        tasks[parts[1]] = parts[0]

                ns = subprocess.check_output("netstat -ano -p TCP", shell=True, text=True, errors="ignore")
                found = 0
                for line in ns.splitlines():
                    cols = line.split()
                    if len(cols) >= 5 and cols[0] == "TCP":
                        remote, state, pid = cols[2], cols[3], cols[4]
                        ip = remote.rsplit(":", 1)[0].strip("[]")
                        if ip.startswith(("127.", "0.0.0.0", "::", "192.168.", "10.")):
                            continue
                        proc = tasks.get(pid, "Unknown")
                        write_out(f"  {state:<12} | Remote: {remote:<22} | App: {proc} (PID {pid})")
                        found += 1
                write_out(f"\n[DONE] Found {found} external connection(s). Paste any IP above to inspect or block.")
                self.log_ui(f"[NET-GUARD] Scanned active connections ({found} external endpoints).")
            except Exception as e:
                write_out(f"[ERROR] Could not read netstat: {e}")

        def lookup_ip():
            ip = ip_entry.get().strip()
            if not ip:
                messagebox.showwarning("Missing IP", "Enter an IPv4/IPv6 address first.")
                return
            write_out(f"\n[LOOKUP] Querying public registry & geolocation for {ip}...")
            def _worker():
                try:
                    url = f"http://ip-api.com{ip}?fields=status,message,country,regionName,city,isp,org,as,hosting,proxy"
                    req = urllib.request.Request(url, headers={"User-Agent": "PythonAntivirusGuard/1.0"})
                    with urllib.request.urlopen(req, timeout=6) as resp:
                        data = json.loads(resp.read().decode("utf-8"))
                    if data.get("status") != "success":
                        write_out(f"  Lookup failed: {data.get('message', 'Invalid IP')}")
                        return
                    write_out(f"  Location : {data.get('city')}, {data.get('regionName')}, {data.get('country')}")
                    write_out(f"  ISP / Org: {data.get('isp')} | {data.get('org')} ({data.get('as')})")
                    write_out(f"  Flags    : Hosting/Cloud={data.get('hosting')} | VPN/Proxy={data.get('proxy')}")
                    self.log_ui(f"[IP-LOOKUP] {ip} -> {data.get('country')} ({data.get('isp')})")
                except Exception as e:
                    write_out(f"  [ERROR] Lookup failed: {e}")
            threading.Thread(target=_worker, daemon=True).start()

        def block_ip():
            ip = ip_entry.get().strip()
            if not re.match(r"^[0-9a-fA-F:.]+$", ip):
                messagebox.showwarning("Invalid IP", "Enter a valid IP address to block.")
                return
            rule_name = f"KamaliAV_Block_{ip}"
            cmd_in = f'netsh advfirewall firewall add rule name="{rule_name}_IN" dir=in action=block remoteip={ip}'
            cmd_out = f'netsh advfirewall firewall add rule name="{rule_name}_OUT" dir=out action=block remoteip={ip}'
            try:
                subprocess.check_call(cmd_in, shell=True)
                subprocess.check_call(cmd_out, shell=True)
                write_out(f"\n[BLOCKED] Windows Firewall rule added for {ip} (Inbound & Outbound).")
                self.log_ui(f"[FIREWALL] Blocked suspicious IP: {ip}")
                messagebox.showinfo("IP Blocked", f"Blocked {ip} in Windows Defender Firewall.")
            except Exception:
                write_out(f"\n[ADMIN REQUIRED] Run Antivirus as Administrator, or run in Admin CMD:\n  {cmd_in}\n  {cmd_out}")

        tk.Button(top, text="Scan Connections", command=scan_connections).pack(side=tk.LEFT, padx=4)
        tk.Button(top, text="Inspect IP", command=lookup_ip).pack(side=tk.LEFT, padx=4)
        tk.Button(top, text="Block IP (Firewall)", fg="white", bg="#b71c1c", command=block_ip).pack(side=tk.LEFT, padx=4)
        scan_connections()


if __name__ == "__main__":
    app_root = tk.Tk()
    AntivirusGUI(app_root)
    app_root.mainloop()
