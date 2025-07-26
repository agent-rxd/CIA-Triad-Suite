import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, simpledialog, ttk
import hashlib
import os
import sqlite3
from datetime import datetime
import threading
import time
import shutil  # For backup functionality
import subprocess  # For ping in availability
from cryptography.fernet import Fernet  # For encryption/decryption

# --- Global Styling (Hacker Theme) ---
FONT_LARGE = ('Consolas', 12, 'bold')
FONT_MEDIUM = ('Consolas', 10)
BG_MAIN = '#1a1a1a'
BG_FRAME = '#222222'
FG_LABEL = '#00ff00'  # Hacker green
BG_ENTRY = '#333333'
FG_ENTRY = '#00ff00'
BG_BUTTON_PRIMARY = '#008000'  # Scan/Encrypt/Backup Now
BG_BUTTON_SECONDARY = '#cc5500'  # Check/Decrypt/Check Backup
BG_BUTTON_BROWSE = '#3498db'
BG_BUTTON_REPORT = '#008b8b'
BG_BUTTON_PERIODIC_START = '#006400'
BG_BUTTON_PERIODIC_STOP = '#8b0000'
BG_BUTTON_PERIODIC_MAIN = '#4b0082'  # Combined Periodic button
BG_BUTTON_CLEAR = '#555555'
FG_BUTTON = 'white'
BG_TEXT_AREA = '#111111'
FG_TEXT_AREA = '#00ff00'
BG_STATUS = '#333333'
FG_STATUS = '#00ff00'

# Log message tag colors
TAG_INFO = "#00ffff"  # Cyan
TAG_SUCCESS = "#33ff33"  # Bright green
TAG_WARNING = "#ffff00"  # Yellow
TAG_ERROR = "#ff3333"  # Red
TAG_ALERT = "#ff0000"  # Bright red, bold


class CIATriadSuiteApp:
    def __init__(self, master):
        self.master = master
        master.title("AGENT RXD's  CIA Triad Suite")
        master.geometry("900x700")  # Larger window for tabs
        master.configure(bg=BG_MAIN)

        self.db_name = "cia_triad_suite.sqlite"  # New database name for the suite
        self.periodic_scan_job = None
        self.network_monitor_job = None

        # --- Main Notebook (Tabbed Interface) ---
        self.notebook = ttk.Notebook(master)
        self.notebook.pack(pady=10, padx=10, expand=True, fill=tk.BOTH)

        # Configure Notebook style (for tabs)
        style = ttk.Style()
        style.theme_use('clam')  # Use a theme that allows more customization
        style.configure('TNotebook', background=BG_MAIN, borderwidth=0)
        style.configure('TNotebook.Tab', background=BG_FRAME, foreground=FG_LABEL,
                        font=FONT_LARGE, padding=[10, 5])
        style.map('TNotebook.Tab', background=[('selected', BG_BUTTON_BROWSE)],
                  foreground=[('selected', 'white')])

        # Create Frames for each tab
        self.confidentiality_frame = tk.Frame(self.notebook, bg=BG_MAIN)
        self.integrity_frame = tk.Frame(self.notebook, bg=BG_MAIN)
        self.availability_frame = tk.Frame(self.notebook, bg=BG_MAIN)

        self.notebook.add(self.confidentiality_frame, text="Confidentiality Tools")
        self.notebook.add(self.integrity_frame, text="Integrity Tools")
        self.notebook.add(self.availability_frame, text="Availability Tools")

        # --- Common Log and Status Bar ---
        # Create these widgets BEFORE calling init_db or populating tabs
        self.log_text = scrolledtext.ScrolledText(master, wrap=tk.WORD, font=FONT_MEDIUM, bg=BG_TEXT_AREA,
                                                  fg=FG_TEXT_AREA, bd=2, relief=tk.SUNKEN)
        self.log_text.pack(pady=10, padx=10, expand=True, fill=tk.BOTH)
        self.log_text.tag_config("info", foreground=TAG_INFO)
        self.log_text.tag_config("success", foreground=TAG_SUCCESS)
        self.log_text.tag_config("warning", foreground=TAG_WARNING)
        self.log_text.tag_config("error", foreground=TAG_ERROR)
        self.log_text.tag_config("alert", foreground=TAG_ALERT, font=(FONT_MEDIUM[0], FONT_MEDIUM[1], 'bold'))

        bottom_frame = tk.Frame(master, bg=BG_STATUS, bd=1, relief=tk.SUNKEN)
        bottom_frame.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_label = tk.Label(bottom_frame, text="Ready", anchor=tk.W, bg=BG_STATUS, fg=FG_STATUS,
                                     font=FONT_MEDIUM)
        self.status_label.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        tk.Button(bottom_frame, text="Clear Output", command=self.clear_log_output, font=FONT_MEDIUM,
                  bg=BG_BUTTON_CLEAR, fg=FG_BUTTON, relief=tk.RAISED, bd=2).pack(side=tk.RIGHT, padx=5, pady=2)

        # --- Populate Tabs ---
        self.create_confidentiality_widgets(self.confidentiality_frame)
        self.create_integrity_widgets(self.integrity_frame)
        self.create_availability_widgets(self.availability_frame)

        # Now initialize the database, which uses log_message
        self.init_db()

    def init_db(self):
        """Initializes the SQLite database and ensures schema is up-to-date."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()

            # Table for file integrity hashes
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_hashes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT UNIQUE,
                    hash_value TEXT,
                    scan_timestamp TEXT,
                    type TEXT
                )
            ''')
            conn.commit()

            # Check and add 'type' column if missing
            cursor.execute("PRAGMA table_info(file_hashes)")
            columns = [col[1] for col in cursor.fetchall()]
            if 'type' not in columns:
                self.log_message("Database schema update: Adding 'type' column to file_hashes table...", "warning")
                cursor.execute("ALTER TABLE file_hashes ADD COLUMN type TEXT")
                cursor.execute("UPDATE file_hashes SET type = 'file' WHERE type IS NULL")
                conn.commit()
                self.log_message("Database schema updated successfully. Existing entries marked as 'file'.", "success")

            # Table for settings (e.g., backup paths, ping targets, encryption keys)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            ''')
            conn.commit()

            self.log_message("Database initialized successfully.", "info")
        except sqlite3.Error as e:
            self.log_message(f"Database error during initialization/update: {e}", "error")
        finally:
            if conn:
                conn.close()

    def log_message(self, message, level="info"):
        """Logs messages to the scrolled text area with color coding."""
        timestamp = datetime.now().strftime("[%H:%M:%S]")
        self.log_text.insert(tk.END, f"{timestamp} {message}\n", level)
        self.log_text.see(tk.END)
        self.status_label.config(text=f"Status: {message.splitlines()[0]}")

    def clear_log_output(self):
        """Clears the content of the log output text area."""
        self.log_text.delete(1.0, tk.END)
        self.log_message("Output screen cleared.", "info")

    def browse_path(self, entry_widget):
        """Opens a dialog to select a file or directory and updates the given entry widget."""
        initial_dir = os.path.expanduser('~')
        try:
            current_dir = os.getcwd()
            if os.path.exists(current_dir):
                initial_dir = current_dir
        except FileNotFoundError:
            self.log_message("Warning: Current working directory not found, defaulting to home directory.", "warning")
        except Exception as e:
            self.log_message(f"Error getting current directory: {e}, defaulting to home directory.", "error")

        path = filedialog.askopenfilename(initialdir=initial_dir)
        if not path:
            path = filedialog.askdirectory(initialdir=initial_dir)
        if path:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, path)

    def calculate_file_hash(self, filepath, hash_algorithm='sha256'):
        """Calculates the hash of a file."""
        hasher = hashlib.new(hash_algorithm)
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except FileNotFoundError:
            self.log_message(f"Error: File not found - {filepath}", "error")
            return None
        except IOError as e:
            self.log_message(f"Error reading file {filepath}: {e}", "error")
            return None

    # --- Integrity Tools Section (Adapted from previous code) ---
    def create_integrity_widgets(self, parent_frame):
        path_frame = tk.Frame(parent_frame, bg=BG_FRAME, bd=5, relief=tk.GROOVE)
        path_frame.pack(pady=10, padx=10, fill=tk.X)

        tk.Label(path_frame, text="File/Folder Path:", font=FONT_LARGE, bg=BG_FRAME, fg=FG_LABEL).pack(side=tk.LEFT,
                                                                                                       padx=5)
        self.integrity_path_entry = tk.Entry(path_frame, width=60, font=FONT_MEDIUM, bg=BG_ENTRY, fg=FG_ENTRY, bd=2,
                                             relief=tk.FLAT, insertbackground=FG_ENTRY)
        self.integrity_path_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        tk.Button(path_frame, text="Browse", command=lambda: self.browse_path(self.integrity_path_entry),
                  font=FONT_MEDIUM, bg=BG_BUTTON_BROWSE, fg=FG_BUTTON, relief=tk.RAISED, bd=2).pack(side=tk.LEFT,
                                                                                                    padx=5)

        button_frame_main = tk.Frame(parent_frame, bg=BG_FRAME, bd=5, relief=tk.GROOVE)
        button_frame_main.pack(pady=5, padx=10, fill=tk.X)

        tk.Button(button_frame_main, text="Scan", command=self.start_scan_thread, font=FONT_LARGE, bg=BG_BUTTON_PRIMARY,
                  fg=FG_BUTTON, relief=tk.RAISED, bd=3, padx=10, pady=5).pack(side=tk.LEFT, expand=True, padx=5)
        tk.Button(button_frame_main, text="Check Integrity", command=self.start_check_thread, font=FONT_LARGE,
                  bg=BG_BUTTON_SECONDARY, fg=FG_BUTTON, relief=tk.RAISED, bd=3, padx=10, pady=5).pack(side=tk.LEFT,
                                                                                                      expand=True,
                                                                                                      padx=5)

        button_frame_new = tk.Frame(parent_frame, bg=BG_FRAME, bd=5, relief=tk.GROOVE)
        button_frame_new.pack(pady=5, padx=10, fill=tk.X)

        self.periodic_scan_button = tk.Menubutton(button_frame_new, text="Periodic Scan", font=FONT_LARGE,
                                                  bg=BG_BUTTON_PERIODIC_MAIN, fg=FG_BUTTON, relief=tk.RAISED, bd=3,
                                                  padx=10, pady=5)
        self.periodic_scan_button.pack(side=tk.LEFT, expand=True, padx=5)
        self.periodic_scan_button.menu = tk.Menu(self.periodic_scan_button, tearoff=0, bg=BG_FRAME, fg=FG_LABEL,
                                                 font=FONT_MEDIUM)
        self.periodic_scan_button["menu"] = self.periodic_scan_button.menu
        self.periodic_scan_button.menu.add_command(label="Start Periodic Scan", command=self.start_periodic_scan,
                                                   background=BG_BUTTON_PERIODIC_START, foreground=FG_BUTTON)
        self.periodic_scan_button.menu.add_command(label="Stop Periodic Scan", command=self.stop_periodic_scan,
                                                   background=BG_BUTTON_PERIODIC_STOP, foreground=FG_BUTTON)

        tk.Button(button_frame_new, text="Generate Report", command=self.generate_report, font=FONT_LARGE,
                  bg=BG_BUTTON_REPORT, fg=FG_BUTTON, relief=tk.RAISED, bd=3, padx=10, pady=5).pack(side=tk.LEFT,
                                                                                                   expand=True, padx=5)

    def start_scan_thread(self):
        path = self.integrity_path_entry.get()
        if not path:
            messagebox.showwarning("Input Error", "Please provide a file or folder path to scan.", parent=self.master)
            return
        self.log_message(f"Starting scan and saving baseline for: {path}...", "info")
        threading.Thread(target=self._scan_and_save_hashes, args=(path,)).start()

    def _scan_and_save_hashes(self, path_to_scan):
        conn = None
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            scan_time = datetime.now().isoformat()

            path_to_scan_norm = os.path.normpath(path_to_scan)

            if os.path.isfile(path_to_scan_norm):
                file_hash = self.calculate_file_hash(path_to_scan_norm)
                if file_hash:
                    cursor.execute(
                        "INSERT OR REPLACE INTO file_hashes (file_path, hash_value, scan_timestamp, type) VALUES (?, ?, ?, ?)",
                        (path_to_scan_norm, file_hash, scan_time, 'file'))
                    self.log_message(f"Scanned & Saved: {path_to_scan_norm} -> {file_hash}", "success")
            elif os.path.isdir(path_to_scan_norm):
                self.log_message(f"Scanning directory: {path_to_scan_norm}", "info")
                file_count = 0
                dir_count = 0
                for root, dirs, files in os.walk(path_to_scan_norm):
                    for d in dirs:
                        dir_path = os.path.normpath(os.path.join(root, d))
                        cursor.execute(
                            "INSERT OR REPLACE INTO file_hashes (file_path, hash_value, scan_timestamp, type) VALUES (?, ?, ?, ?)",
                            (dir_path, "IS_DIRECTORY", scan_time, 'directory'))
                        dir_count += 1
                    for file in files:
                        filepath = os.path.normpath(os.path.join(root, file))
                        file_hash = self.calculate_file_hash(filepath)
                        if file_hash:
                            cursor.execute(
                                "INSERT OR REPLACE INTO file_hashes (file_path, hash_value, scan_timestamp, type) VALUES (?, ?, ?, ?)",
                                (filepath, file_hash, scan_time, 'file'))
                            file_count += 1
                            if file_count % 100 == 0:
                                self.log_message(f"  Scanned {file_count} files...", "info")
                            else:
                                self.log_message(f"  Scanned: {filepath} -> {file_hash}", "info")
                self.log_message(
                    f"Scan complete for directory. Total files: {file_count}, Total directories: {dir_count}",
                    "success")
            else:
                self.log_message(f"Error: Path '{path_to_scan}' does not exist or is not accessible.", "error")
                return

            conn.commit()
            self.log_message("Baseline scan completed and saved successfully!", "success")

        except sqlite3.Error as e:
            self.log_message(f"Database error during scan: {e}", "error")
        finally:
            if conn:
                conn.close()

    def start_check_thread(self):
        path = self.integrity_path_entry.get()
        if not path:
            messagebox.showwarning("Input Error", "Please provide a file or folder path to check integrity.",
                                   parent=self.master)
            return
        self.log_message(f"Starting integrity check for: {path}...", "info")
        threading.Thread(target=self._check_integrity_of_files_or_folder, args=(path,)).start()

    def _check_integrity_of_files_or_folder(self, path_to_check):
        conn = None
        report_data = {
            "timestamp": datetime.now().isoformat(),
            "path_checked": path_to_check,
            "status": "Completed",
            "files_ok": [], "files_modified": [], "files_new": [], "files_deleted": [],
            "dirs_new": [], "dirs_deleted": [], "errors": []
        }

        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()

            path_to_check_norm = os.path.normpath(path_to_check)
            cursor.execute(
                "SELECT file_path, hash_value, type FROM file_hashes WHERE file_path LIKE ? || '%' OR file_path = ?",
                (path_to_check_norm + os.sep, path_to_check_norm))
            stored_items = {os.path.normpath(row[0]): {'hash': row[1], 'type': row[2]} for row in cursor.fetchall()}

            current_files_on_disk = {}
            current_dirs_on_disk = set()

            if os.path.isfile(path_to_check_norm):
                if path_to_check_norm in stored_items and stored_items[path_to_check_norm]['type'] == 'file':
                    stored_hash = stored_items[path_to_check_norm]['hash']
                    current_hash = self.calculate_file_hash(path_to_check_norm)
                    if current_hash:
                        if current_hash == stored_hash:
                            self.log_message(f"INTEGRITY OK: {path_to_check_norm}", "success")
                            report_data["files_ok"].append(path_to_check_norm)
                        else:
                            self.log_message(f"*** ALERT ***: {path_to_check_norm} (HASH MISMATCH!)", "alert")
                            report_data["files_modified"].append(path_to_check_norm)
                else:
                    self.log_message(
                        f"INFO: {path_to_check_norm} (No baseline hash found in database for this file or it's a directory.)",
                        "warning")
                    report_data["errors"].append(f"No baseline for {path_to_check_norm}")
            elif os.path.isdir(path_to_check_norm):
                self.log_message(f"Checking integrity for directory: {path_to_check_norm}", "info")

                for root, dirs, files in os.walk(path_to_check_norm):
                    for file in files:
                        filepath = os.path.normpath(os.path.join(root, file))
                        current_hash = self.calculate_file_hash(filepath)
                        if current_hash:
                            current_files_on_disk[filepath] = current_hash
                    for d in dirs:
                        dir_path = os.path.normpath(os.path.join(root, d))
                        current_dirs_on_disk.add(dir_path)

                for filepath, current_hash in current_files_on_disk.items():
                    if filepath in stored_items and stored_items[filepath]['type'] == 'file':
                        if current_hash == stored_items[filepath]['hash']:
                            self.log_message(f"  INTEGRITY OK: {filepath}", "success")
                            report_data["files_ok"].append(filepath)
                        else:
                            self.log_message(f"  *** ALERT ***: {filepath} (HASH MISMATCH!)", "alert")
                            report_data["files_modified"].append(filepath)
                    else:
                        self.log_message(f"  NEW FILE DETECTED: {filepath}", "warning")
                        report_data["files_new"].append(filepath)

                for dir_path in current_dirs_on_disk:
                    if dir_path not in stored_items or stored_items[dir_path]['type'] != 'directory':
                        self.log_message(f"  NEW FOLDER DETECTED: {dir_path}", "warning")
                        report_data["dirs_new"].append(dir_path)

                for item_path, item_details in stored_items.items():
                    if item_path.startswith(path_to_check_norm + os.sep) and not os.path.exists(item_path):
                        if item_details['type'] == 'file':
                            if item_path not in current_files_on_disk:
                                self.log_message(f"  DELETED FILE DETECTED: {item_path}", "alert")
                                report_data["files_deleted"].append(item_path)
                        elif item_details['type'] == 'directory':
                            if item_path not in current_dirs_on_disk:
                                self.log_message(f"  DELETED FOLDER DETECTED: {item_path}", "alert")
                                report_data["dirs_deleted"].append(item_path)
            else:
                self.log_message(f"Error: Path '{path_to_check}' does not exist or is not accessible.", "error")
                report_data["status"] = "Error"
                report_data["errors"].append(f"Path not found: {path_to_check}")

            self.log_message("Integrity check completed.", "info")

        except sqlite3.Error as e:
            self.log_message(f"Database error during check: {e}", "error")
            report_data["status"] = "Error"
            report_data["errors"].append(f"Database error: {e}")
        except Exception as e:
            self.log_message(f"An unexpected error occurred during check: {e}", "error")
            report_data["status"] = "Error"
            report_data["errors"].append(f"Unexpected error: {e}")
        finally:
            if conn:
                conn.close()
            self.last_report_data = report_data

    def start_periodic_scan(self):
        if self.periodic_scan_job:
            messagebox.showwarning("Periodic Scan", "Periodic scan is already running.", parent=self.master)
            return

        path_to_scan = self.integrity_path_entry.get()
        if not path_to_scan:
            messagebox.showwarning("Input Error",
                                   "Please provide a file or folder path in the main entry for periodic scan.",
                                   parent=self.master)
            return

        interval_dialog_result = self._show_periodic_scan_interval_dialog()
        if interval_dialog_result is None:
            return

        interval_value, interval_unit = interval_dialog_result
        if interval_unit == "seconds":
            interval_seconds = interval_value
            display_unit = "second(s)"
        else:
            interval_seconds = interval_value * 60
            display_unit = "minute(s)"

        if interval_seconds <= 0:
            messagebox.showwarning("Input Error", "Interval must be a positive number.", parent=self.master)
            return

        self.log_message(f"Starting periodic scan of '{path_to_scan}' every {interval_value} {display_unit}.", "info")
        self._schedule_periodic_scan(interval_seconds, path_to_scan)

    def _show_periodic_scan_interval_dialog(self):
        dialog = tk.Toplevel(self.master)
        dialog.title("Configure Periodic Scan")
        dialog.geometry("400x200")
        dialog.transient(self.master)
        dialog.grab_set()
        dialog.configure(bg=BG_FRAME)

        tk.Label(dialog, text="Scan every:", font=FONT_MEDIUM, bg=BG_FRAME, fg=FG_LABEL).pack(pady=10)

        interval_entry = tk.Entry(dialog, width=10, font=FONT_MEDIUM, bg=BG_ENTRY, fg=FG_ENTRY, bd=2, relief=tk.FLAT,
                                  insertbackground=FG_ENTRY)
        interval_entry.insert(0, "1")
        interval_entry.pack(pady=5)

        unit_var = tk.StringVar(value="seconds")
        unit_menu = tk.OptionMenu(dialog, unit_var, "seconds", "minutes")
        unit_menu.config(font=FONT_MEDIUM, bg=BG_BUTTON_BROWSE, fg=FG_BUTTON, relief=tk.RAISED, bd=2)
        unit_menu["menu"].config(bg=BG_BUTTON_BROWSE, fg=FG_BUTTON)
        unit_menu.pack(pady=5)

        result = None

        def on_ok():
            nonlocal result
            try:
                value = int(interval_entry.get())
                unit = unit_var.get()
                if value <= 0:
                    messagebox.showwarning("Invalid Input", "Interval value must be positive.", parent=dialog)
                    return
                result = (value, unit)
                dialog.destroy()
            except ValueError:
                messagebox.showwarning("Invalid Input", "Please enter a valid number for the interval.", parent=dialog)

        tk.Button(dialog, text="OK", command=on_ok, font=FONT_MEDIUM, bg=BG_BUTTON_PERIODIC_START, fg=FG_BUTTON,
                  relief=tk.RAISED, bd=2).pack(pady=10)

        self.master.wait_window(dialog)
        return result

    def _schedule_periodic_scan(self, interval_seconds, path_to_scan):
        self.periodic_scan_job = self.master.after(int(interval_seconds * 1000),
                                                   lambda: threading.Thread(target=self._run_periodic_check,
                                                                            args=(path_to_scan,
                                                                                  interval_seconds)).start())
        self.log_message(f"Next periodic scan scheduled in {interval_seconds} seconds.", "info")

    def _run_periodic_check(self, path_to_scan, interval_seconds):
        self.log_message(f"Performing scheduled integrity check for: {path_to_scan}...", "info")
        self._check_integrity_of_files_or_folder(path_to_scan)
        self._schedule_periodic_scan(interval_seconds, path_to_scan)

    def stop_periodic_scan(self):
        if self.periodic_scan_job:
            self.master.after_cancel(self.periodic_scan_job)
            self.periodic_scan_job = None
            self.log_message("Periodic scan stopped.", "success")
        else:
            self.log_message("No periodic scan is currently running.", "warning")

    def generate_report(self):
        if not hasattr(self, 'last_report_data'):
            self.log_message("No integrity check has been performed yet to generate a report.", "warning")
            return

        report = self.last_report_data
        report_str = f"--- Integrity Report ---\n"
        report_str += f"Report Timestamp: {report['timestamp']}\n"
        report_str += f"Path Checked: {report['path_checked']}\n"
        report_str += f"Overall Status: {report['status']}\n\n"

        report_str += f"Files OK: {len(report['files_ok'])}\n"
        if report['files_ok']:
            for f in report['files_ok']:
                report_str += f"  - {f}\n"
        report_str += "\n"

        report_str += f"Files Modified: {len(report['files_modified'])}\n"
        if report['files_modified']:
            for f in report['files_modified']:
                report_str += f"  - {f}\n"
        report_str += "\n"

        report_str += f"New Files Detected: {len(report['files_new'])}\n"
        if report['files_new']:
            for f in report['files_new']:
                report_str += f"  - {f}\n"
        report_str += "\n"

        report_str += f"Deleted Files Detected: {len(report['files_deleted'])}\n"
        if report['files_deleted']:
            for f in report['files_deleted']:
                report_str += f"  - {f}\n"
        report_str += "\n"

        report_str += f"New Folders Detected: {len(report['dirs_new'])}\n"
        if report['dirs_new']:
            for d in report['dirs_new']:
                report_str += f"  - {d}\n"
        report_str += "\n"

        report_str += f"Deleted Folders Detected: {len(report['dirs_deleted'])}\n"
        if report['dirs_deleted']:
            for d in report['dirs_deleted']:
                report_str += f"  - {d}\n"
        report_str += "\n"

        if report['errors']:
            report_str += f"Errors Encountered: {len(report['errors'])}\n"
            for err in report['errors']:
                report_str += f"  - {err}\n"
            report_str += "\n"

        self.log_message("\n" + report_str, "info")

        save_report = messagebox.askyesno("Save Report", "Do you want to save this report to a file?",
                                          parent=self.master)
        if save_report:
            file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                     filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                                                     title="Save Report As", parent=self.master)
            if file_path:
                try:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(report_str)
                    self.log_message(f"Report saved to {file_path}", "success")
                except IOError as e:
                    self.log_message(f"Error saving report: {e}", "error")

    # --- Confidentiality Tools Section ---
    def create_confidentiality_widgets(self, parent_frame):
        # Encryption/Decryption Frame
        encrypt_frame = tk.LabelFrame(parent_frame, text="File Encryption / Decryption", font=FONT_LARGE, bg=BG_FRAME,
                                      fg=FG_LABEL, bd=2, relief=tk.GROOVE)
        encrypt_frame.pack(pady=10, padx=10, fill=tk.X)

        tk.Label(encrypt_frame, text="File Path:", font=FONT_MEDIUM, bg=BG_FRAME, fg=FG_LABEL).pack(side=tk.LEFT,
                                                                                                    padx=5)
        self.encrypt_file_entry = tk.Entry(encrypt_frame, width=50, font=FONT_MEDIUM, bg=BG_ENTRY, fg=FG_ENTRY, bd=2,
                                           relief=tk.FLAT, insertbackground=FG_ENTRY)
        self.encrypt_file_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        tk.Button(encrypt_frame, text="Browse", command=lambda: self.browse_path(self.encrypt_file_entry),
                  font=FONT_MEDIUM, bg=BG_BUTTON_BROWSE, fg=FG_BUTTON, relief=tk.RAISED, bd=2).pack(side=tk.LEFT,
                                                                                                    padx=5)

        tk.Label(encrypt_frame, text="Password:", font=FONT_MEDIUM, bg=BG_FRAME, fg=FG_LABEL).pack(side=tk.LEFT, padx=5)
        self.encrypt_password_entry = tk.Entry(encrypt_frame, width=20, show="*", font=FONT_MEDIUM, bg=BG_ENTRY,
                                               fg=FG_ENTRY, bd=2, relief=tk.FLAT, insertbackground=FG_ENTRY)
        self.encrypt_password_entry.pack(side=tk.LEFT, padx=5)

        encrypt_decrypt_button_frame = tk.Frame(encrypt_frame, bg=BG_FRAME)
        encrypt_decrypt_button_frame.pack(pady=10, fill=tk.X)
        tk.Button(encrypt_decrypt_button_frame, text="Encrypt", command=self.start_encrypt_thread, font=FONT_LARGE,
                  bg=BG_BUTTON_PRIMARY, fg=FG_BUTTON, relief=tk.RAISED, bd=3, padx=10, pady=5).pack(side=tk.LEFT,
                                                                                                    expand=True, padx=5)
        tk.Button(encrypt_decrypt_button_frame, text="Decrypt", command=self.start_decrypt_thread, font=FONT_LARGE,
                  bg=BG_BUTTON_SECONDARY, fg=FG_BUTTON, relief=tk.RAISED, bd=3, padx=10, pady=5).pack(side=tk.LEFT,
                                                                                                      expand=True,
                                                                                                      padx=5)

        # Secure Data Deletion Frame
        delete_frame = tk.LabelFrame(parent_frame, text="Secure Data Deletion", font=FONT_LARGE, bg=BG_FRAME,
                                     fg=FG_LABEL, bd=2, relief=tk.GROOVE)
        delete_frame.pack(pady=10, padx=10, fill=tk.X)

        tk.Label(delete_frame, text="File/Folder Path:", font=FONT_MEDIUM, bg=BG_FRAME, fg=FG_LABEL).pack(side=tk.LEFT,
                                                                                                          padx=5)
        self.delete_path_entry = tk.Entry(delete_frame, width=50, font=FONT_MEDIUM, bg=BG_ENTRY, fg=FG_ENTRY, bd=2,
                                          relief=tk.FLAT, insertbackground=FG_ENTRY)
        self.delete_path_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        tk.Button(delete_frame, text="Browse", command=lambda: self.browse_path(self.delete_path_entry),
                  font=FONT_MEDIUM, bg=BG_BUTTON_BROWSE, fg=FG_BUTTON, relief=tk.RAISED, bd=2).pack(side=tk.LEFT,
                                                                                                    padx=5)

        tk.Button(delete_frame, text="Secure Delete", command=self.start_secure_delete_thread, font=FONT_LARGE,
                  bg=BG_BUTTON_SECONDARY, fg=FG_BUTTON, relief=tk.RAISED, bd=3, padx=10, pady=5).pack(pady=10)

    def _derive_key(self, password, salt=None):
        """Derives a key from a password using PBKDF2HMAC."""
        if salt is None:
            salt = os.urandom(16)
        kdf = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt,
            100000,
            dklen=32
        )
        return base64.urlsafe_b64encode(kdf), salt

    def start_encrypt_thread(self):
        filepath = self.encrypt_file_entry.get()
        password = self.encrypt_password_entry.get()
        if not filepath or not password:
            messagebox.showwarning("Input Error", "Please provide file path and password.", parent=self.master)
            return
        self.log_message(f"Starting encryption for: {filepath}...", "info")
        threading.Thread(target=self._encrypt_file, args=(filepath, password)).start()

    def _encrypt_file(self, filepath, password):
        try:
            filepath_norm = os.path.normpath(filepath)
            if not os.path.exists(filepath_norm):
                self.log_message(f"Error: File not found - {filepath_norm}", "error")
                return

            # Generate a new key for each encryption
            # For a real application, you'd derive the key from the password
            # and store the salt with the encrypted file.
            # For this demo, we'll generate a key and save it to a .key file.
            key = Fernet.generate_key()
            f = Fernet(key)

            with open(filepath_norm, 'rb') as file:
                file_data = file.read()
            encrypted_data = f.encrypt(file_data)

            # Save the key to a .key file
            key_file = filepath_norm + ".key"
            with open(key_file, 'wb') as k_file:
                k_file.write(key)

            # Save the encrypted data to a .encrypted file
            with open(filepath_norm + ".encrypted", 'wb') as file:
                file.write(encrypted_data)

            self.log_message(
                f"File encrypted successfully: {filepath_norm}. Encrypted file saved as {filepath_norm}.encrypted. Key saved to {key_file}",
                "success")
            self.log_message("IMPORTANT: Keep the .key file secure and remember your password!", "alert")

        except Exception as e:
            self.log_message(f"Error during encryption: {e}", "error")

    def start_decrypt_thread(self):
        filepath = self.encrypt_file_entry.get()
        password = self.encrypt_password_entry.get()
        if not filepath or not password:
            messagebox.showwarning("Input Error", "Please provide file path and password.", parent=self.master)
            return
        self.log_message(f"Starting decryption for: {filepath}...", "info")
        threading.Thread(target=self._decrypt_file, args=(filepath, password)).start()

    def _decrypt_file(self, filepath, password):
        try:
            filepath_norm = os.path.normpath(filepath)
            encrypted_filepath = filepath_norm
            # Assume key file is next to encrypted file with .key extension
            key_filepath = filepath_norm.replace(".encrypted", ".key")

            if not os.path.exists(encrypted_filepath):
                self.log_message(f"Error: Encrypted file not found - {encrypted_filepath}", "error")
                return
            if not os.path.exists(key_filepath):
                self.log_message(f"Error: Key file not found - {key_filepath}. Cannot decrypt.", "error")
                return

            with open(key_filepath, 'rb') as k_file:
                key = k_file.read()

            f = Fernet(key)

            with open(encrypted_filepath, 'rb') as file:
                encrypted_data = file.read()

            decrypted_data = f.decrypt(encrypted_data)

            # Save decrypted file (e.g., remove .encrypted extension)
            decrypted_filepath = filepath_norm.replace(".encrypted", ".decrypted")
            with open(decrypted_filepath, 'wb') as file:
                file.write(decrypted_data)

            self.log_message(
                f"File decrypted successfully: {filepath_norm}. Decrypted file saved as {decrypted_filepath}",
                "success")

        except Exception as e:
            self.log_message(f"Error during decryption (check password/key file): {e}", "error")

    def start_secure_delete_thread(self):
        path = self.delete_path_entry.get()
        if not path:
            messagebox.showwarning("Input Error", "Please provide a file or folder path to securely delete.",
                                   parent=self.master)
            return

        confirm = messagebox.askyesno("Confirm Secure Delete",
                                      f"WARNING: This will PERMANENTLY delete '{path}'. This action cannot be undone. Are you sure?",
                                      parent=self.master)
        if not confirm:
            self.log_message("Secure delete cancelled by user.", "info")
            return

        self.log_message(f"Starting secure deletion for: {path}...", "info")
        threading.Thread(target=self._secure_delete, args=(path,)).start()

    def _secure_delete(self, path_to_delete):
        path_to_delete_norm = os.path.normpath(path_to_delete)
        try:
            if os.path.isfile(path_to_delete_norm):
                self._overwrite_file(path_to_delete_norm)
                os.remove(path_to_delete_norm)
                self.log_message(f"Securely deleted file: {path_to_delete_norm}", "success")
            elif os.path.isdir(path_to_delete_norm):
                self.log_message(f"Starting secure deletion for directory: {path_to_delete_norm}", "info")
                for root, dirs, files in os.walk(path_to_delete_norm, topdown=False):
                    for name in files:
                        filepath = os.path.normpath(os.path.join(root, name))
                        self._overwrite_file(filepath)
                        os.remove(filepath)
                        self.log_message(f"  Deleted file: {filepath}", "info")
                    for name in dirs:
                        dirpath = os.path.normpath(os.path.join(root, name))
                        os.rmdir(dirpath)
                        self.log_message(f"  Deleted directory: {dirpath}", "info")
                os.rmdir(path_to_delete_norm)  # Remove the top-level directory
                self.log_message(f"Securely deleted directory: {path_to_delete_norm}", "success")
            else:
                self.log_message(f"Error: Path '{path_to_delete}' does not exist or is not a file/directory.", "error")
        except Exception as e:
            self.log_message(f"Error during secure deletion of {path_to_delete}: {e}", "error")

    def _overwrite_file(self, filepath, passes=3):
        """Overwrites a file with random data multiple times."""
        try:
            with open(filepath, 'r+b') as f:
                length = f.tell()  # Get current file size
                f.seek(0)  # Go to beginning
                for _ in range(passes):
                    f.write(os.urandom(length))  # Overwrite with random bytes
                    f.seek(0)  # Reset for next pass
                f.truncate()  # Truncate to original size if new data is larger
            self.log_message(f"  Overwritten {filepath} with {passes} passes.", "info")
        except Exception as e:
            self.log_message(f"  Error overwriting {filepath}: {e}", "error")

    # --- Availability Tools Section ---
    def create_availability_widgets(self, parent_frame):
        # Backup Frame
        backup_frame = tk.LabelFrame(parent_frame, text="Automated Backup & Restore", font=FONT_LARGE, bg=BG_FRAME,
                                     fg=FG_LABEL, bd=2, relief=tk.GROOVE)
        backup_frame.pack(pady=10, padx=10, fill=tk.X)

        tk.Label(backup_frame, text="Source Path:", font=FONT_MEDIUM, bg=BG_FRAME, fg=FG_LABEL).pack(side=tk.LEFT,
                                                                                                     padx=5)
        self.backup_source_entry = tk.Entry(backup_frame, width=40, font=FONT_MEDIUM, bg=BG_ENTRY, fg=FG_ENTRY, bd=2,
                                            relief=tk.FLAT, insertbackground=FG_ENTRY)
        self.backup_source_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        tk.Button(backup_frame, text="Browse", command=lambda: self.browse_path(self.backup_source_entry),
                  font=FONT_MEDIUM, bg=BG_BUTTON_BROWSE, fg=FG_BUTTON, relief=tk.RAISED, bd=2).pack(side=tk.LEFT,
                                                                                                    padx=5)

        tk.Label(backup_frame, text="Destination Path:", font=FONT_MEDIUM, bg=BG_FRAME, fg=FG_LABEL).pack(side=tk.LEFT,
                                                                                                          padx=5)
        self.backup_dest_entry = tk.Entry(backup_frame, width=40, font=FONT_MEDIUM, bg=BG_ENTRY, fg=FG_ENTRY, bd=2,
                                          relief=tk.FLAT, insertbackground=FG_ENTRY)
        self.backup_dest_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        tk.Button(backup_frame, text="Browse", command=lambda: self.browse_path(self.backup_dest_entry),
                  font=FONT_MEDIUM, bg=BG_BUTTON_BROWSE, fg=FG_BUTTON, relief=tk.RAISED, bd=2).pack(side=tk.LEFT,
                                                                                                    padx=5)

        backup_button_frame = tk.Frame(backup_frame, bg=BG_FRAME)
        backup_button_frame.pack(pady=10, fill=tk.X)
        tk.Button(backup_button_frame, text="Perform Backup Now", command=self.start_backup_thread, font=FONT_LARGE,
                  bg=BG_BUTTON_PRIMARY, fg=FG_BUTTON, relief=tk.RAISED, bd=3, padx=10, pady=5).pack(side=tk.LEFT,
                                                                                                    expand=True, padx=5)
        tk.Button(backup_button_frame, text="Check Last Backup", command=self.check_last_backup, font=FONT_LARGE,
                  bg=BG_BUTTON_SECONDARY, fg=FG_BUTTON, relief=tk.RAISED, bd=3, padx=10, pady=5).pack(side=tk.LEFT,
                                                                                                      expand=True,
                                                                                                      padx=5)

        # Network Connectivity Monitor Frame
        network_frame = tk.LabelFrame(parent_frame, text="Network Connectivity Monitor", font=FONT_LARGE, bg=BG_FRAME,
                                      fg=FG_LABEL, bd=2, relief=tk.GROOVE)
        network_frame.pack(pady=10, padx=10, fill=tk.X)

        tk.Label(network_frame, text="Target Host (IP/Domain):", font=FONT_MEDIUM, bg=BG_FRAME, fg=FG_LABEL).pack(
            side=tk.LEFT, padx=5)
        self.ping_host_entry = tk.Entry(network_frame, width=30, font=FONT_MEDIUM, bg=BG_ENTRY, fg=FG_ENTRY, bd=2,
                                        relief=tk.FLAT, insertbackground=FG_ENTRY)
        self.ping_host_entry.insert(0, "8.8.8.8")  # Default Google DNS
        self.ping_host_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

        tk.Label(network_frame, text="Interval (seconds):", font=FONT_MEDIUM, bg=BG_FRAME, fg=FG_LABEL).pack(
            side=tk.LEFT, padx=5)
        self.ping_interval_entry = tk.Entry(network_frame, width=10, font=FONT_MEDIUM, bg=BG_ENTRY, fg=FG_ENTRY, bd=2,
                                            relief=tk.FLAT, insertbackground=FG_ENTRY)
        self.ping_interval_entry.insert(0, "5")  # Default 5 seconds
        self.ping_interval_entry.pack(side=tk.LEFT, padx=5)

        network_button_frame = tk.Frame(network_frame, bg=BG_FRAME)
        network_button_frame.pack(pady=10, fill=tk.X)
        tk.Button(network_button_frame, text="Start Monitor", command=self.start_network_monitor, font=FONT_LARGE,
                  bg=BG_BUTTON_PRIMARY, fg=FG_BUTTON, relief=tk.RAISED, bd=3, padx=10, pady=5).pack(side=tk.LEFT,
                                                                                                    expand=True, padx=5)
        tk.Button(network_button_frame, text="Stop Monitor", command=self.stop_network_monitor, font=FONT_LARGE,
                  bg=BG_BUTTON_SECONDARY, fg=FG_BUTTON, relief=tk.RAISED, bd=3, padx=10, pady=5).pack(side=tk.LEFT,
                                                                                                      expand=True,
                                                                                                      padx=5)

    def start_backup_thread(self):
        source_path = self.backup_source_entry.get()
        dest_path = self.backup_dest_entry.get()
        if not source_path or not dest_path:
            messagebox.showwarning("Input Error", "Please provide both source and destination paths for backup.",
                                   parent=self.master)
            return

        # Confirm overwrite if destination exists and is not empty
        if os.path.exists(dest_path) and os.listdir(dest_path):
            confirm = messagebox.askyesno("Confirm Backup",
                                          f"Destination '{dest_path}' is not empty. Existing files might be overwritten or merged. Continue?",
                                          parent=self.master)
            if not confirm:
                self.log_message("Backup cancelled by user.", "info")
                return

        self.log_message(f"Starting backup from '{source_path}' to '{dest_path}'...", "info")
        threading.Thread(target=self._perform_backup, args=(source_path, dest_path)).start()

    def _perform_backup(self, source, destination):
        try:
            source_norm = os.path.normpath(source)
            destination_norm = os.path.normpath(destination)

            if not os.path.exists(source_norm):
                self.log_message(f"Error: Source path '{source_norm}' does not exist.", "error")
                return
            if not os.path.isdir(destination_norm):
                os.makedirs(destination_norm, exist_ok=True)  # Create destination if it doesn't exist

            if os.path.isfile(source_norm):
                shutil.copy2(source_norm, destination_norm)
                self.log_message(f"Backed up file: {source_norm} to {destination_norm}", "success")
            elif os.path.isdir(source_norm):
                # Using copytree, but handle existing directory
                # If destination_norm already exists, copytree expects it not to exist unless dirs_exist_ok=True (Python 3.8+)
                # For broader compatibility, we'll iterate or use a safer approach for merging

                # Simple approach: copy files, overwrite if exists
                for root, _, files in os.walk(source_norm):
                    relative_path = os.path.relpath(root, source_norm)
                    target_dir = os.path.join(destination_norm, relative_path)
                    os.makedirs(target_dir, exist_ok=True)
                    for file in files:
                        src_file = os.path.join(root, file)
                        dest_file = os.path.join(target_dir, file)
                        shutil.copy2(src_file, dest_file)
                        self.log_message(f"  Backed up: {src_file}", "info")
                self.log_message(f"Directory backup complete: {source_norm} to {destination_norm}", "success")

            # Save last backup timestamp
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                           ('last_backup_timestamp', datetime.now().isoformat()))
            cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                           ('last_backup_source', source_norm))
            cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                           ('last_backup_dest', destination_norm))
            conn.commit()
            conn.close()
            self.log_message("Backup operation completed successfully!", "success")

        except Exception as e:
            self.log_message(f"Error during backup: {e}", "error")

    def check_last_backup(self):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM settings WHERE key = 'last_backup_timestamp'")
        last_backup_ts = cursor.fetchone()
        cursor.execute("SELECT value FROM settings WHERE key = 'last_backup_source'")
        last_backup_source = cursor.fetchone()
        cursor.execute("SELECT value FROM settings WHERE key = 'last_backup_dest'")
        last_backup_dest = cursor.fetchone()
        conn.close()

        if last_backup_ts and last_backup_source and last_backup_dest:
            self.log_message(f"Last Backup Details:", "info")
            self.log_message(f"  Timestamp: {last_backup_ts[0]}", "info")
            self.log_message(f"  Source: {last_backup_source[0]}", "info")
            self.log_message(f"  Destination: {last_backup_dest[0]}", "info")

            # Check if destination path still exists
            if os.path.exists(last_backup_dest[0]) and os.path.isdir(last_backup_dest[0]):
                self.log_message(f"  Backup destination '{last_backup_dest[0]}' is accessible.", "success")
            else:
                self.log_message(f"  WARNING: Backup destination '{last_backup_dest[0]}' is NOT accessible.", "warning")
        else:
            self.log_message("No previous backup records found.", "warning")

    def start_network_monitor(self):
        if self.network_monitor_job:
            messagebox.showwarning("Network Monitor", "Network monitor is already running.", parent=self.master)
            return

        target_host = self.ping_host_entry.get()
        try:
            interval = int(self.ping_interval_entry.get())
            if interval <= 0:
                raise ValueError("Interval must be positive.")
        except ValueError:
            messagebox.showwarning("Input Error", "Please enter a valid positive number for ping interval.",
                                   parent=self.master)
            return

        self.log_message(f"Starting network monitor for {target_host} every {interval} seconds...", "info")
        self._schedule_network_ping(target_host, interval)

    def _schedule_network_ping(self, host, interval):
        self.network_monitor_job = self.master.after(interval * 1000,
                                                     lambda: threading.Thread(target=self._perform_ping,
                                                                              args=(host, interval)).start())

    def _perform_ping(self, host, interval):
        try:
            # Use platform-specific ping command
            param = '-n' if os.name == 'nt' else '-c'
            command = ['ping', param, '1', host]

            start_time = time.time()
            result = subprocess.run(command, capture_output=True, text=True,
                                    timeout=interval - 1 if interval > 1 else 1)
            end_time = time.time()
            latency = (end_time - start_time) * 1000  # in ms

            if result.returncode == 0:
                self.log_message(f"Network OK: {host} (Latency: {latency:.2f}ms)", "success")
            else:
                self.log_message(
                    f"Network ALERT: {host} (No response or error: {result.stderr.strip() or result.stdout.strip()})",
                    "alert")
        except subprocess.TimeoutExpired:
            self.log_message(f"Network ALERT: {host} (Ping timed out)", "alert")
        except Exception as e:
            self.log_message(f"Network Monitor Error for {host}: {e}", "error")
        finally:
            self._schedule_network_ping(host, interval)  # Reschedule regardless of success/failure

    def stop_network_monitor(self):
        if self.network_monitor_job:
            self.master.after_cancel(self.network_monitor_job)
            self.network_monitor_job = None
            self.log_message("Network monitor stopped.", "success")
        else:
            self.log_message("Network monitor is not running.", "warning")


# --- Main Application Execution ---
if __name__ == "__main__":
    # Ensure cryptography Fernet is available
    try:
        from cryptography.fernet import Fernet
        import base64  # For key handling if needed (Fernet handles it internally for direct use)
    except ImportError:
        messagebox.showerror("Dependency Error",
                             "The 'cryptography' library is not installed. Please install it using:\n\npip install cryptography",
                             parent=tk.Tk())
        exit()

    root = tk.Tk()
    app = CIATriadSuiteApp(root)
    root.mainloop()
