# AGENT RXD's CIA Triad Suite

A comprehensive cybersecurity desktop application built with Python and Tkinter, designed to provide a unified set of tools for managing **Confidentiality**, **Integrity**, and **Availability** (CIA) of digital assets. This suite empowers users with essential tools to protect their data from unauthorized access, ensure its trustworthiness, and maintain its accessibility.

## Features:

### 🔒 Confidentiality Tools
-   **File Encryption/Decryption:** Securely encrypt and decrypt sensitive files using a strong symmetric encryption algorithm (`cryptography.fernet`) and a user-defined password. Keys are managed locally.
-   **Secure Data Deletion:** Permanently overwrite file and folder contents multiple times before deletion to prevent unauthorized data recovery.

### ✅ Integrity Tools
-   **Baseline Scanning:** Calculate and store cryptographic hash values (SHA256 digital fingerprints) for selected files and entire folders. Directories are also baselined for their presence.
-   **Integrity Checking:** Verify the current state of files and folders against their stored baselines to detect any modifications, new additions, or deletions.
-   **Periodic Monitoring:** Schedule automated integrity checks at configurable intervals (in seconds or minutes) for continuous vigilance over critical data.
-   **Report Generation:** Generate detailed summary reports of the last integrity check, outlining status (OK, Modified, New, Deleted Files/Folders).

### 🚀 Availability Tools
-   **Automated Backup & Restore:** Specify source and destination paths to perform direct file/folder backups. The tool also records and allows checking of the last backup status.
-   **Network Connectivity Monitor:** Periodically ping a target host (IP address or domain) at user-defined intervals to monitor network reachability and latency.

## Technologies Used:

-   **Python 3.x:** The core programming language.
-   **Tkinter:** For building the graphical user interface (GUI).
-   **`hashlib`:** For cryptographic hashing (SHA256) in integrity checks.
-   **`sqlite3`:** For a lightweight, local database to store file baselines and application settings.
-   **`cryptography`:** Specifically `cryptography.fernet` for robust file encryption/decryption.
-   **`os`, `shutil`, `subprocess`, `threading`, `time`:** Standard Python modules used for file system operations, high-level file operations (like copying), running external commands (ping), concurrent processing, and time-related functions.

## Setup:

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/agent-rxd/CIA-Triad-Suite.git
    ```
2.  **Navigate to the project directory:**
    ```bash
    cd CIA-Triad-Suite
    ```
3.  **Install dependencies:**
    Ensure you have `pip` installed.
    ```bash
    pip install -r requirements.txt
    ```
4.  **Run the application:**
    ```bash
    python cia_triad_suite.py
    ```

## Usage:

Once the application is running, navigate through the tabs (Confidentiality, Integrity, Availability) to access different tools. Use the "Browse" buttons to select files/folders and input required details in the entry fields before clicking action buttons. The main output log will display all operations and results.

## Contribution:

Contributions are welcome! If you have suggestions for improvements or new features, feel free to fork the repository, make your changes, and submit a pull request.

## License:

This project is open-source and available under the [MIT License](https://opensource.org/licenses/MIT).
*(You can click the link above or replace it with a different license if you prefer. MIT is a common and permissive choice.)*
