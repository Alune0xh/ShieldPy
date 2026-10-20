<h1>ShieldPy — Heuristic Malware Detection System</h1>

A desktop application that uses heuristic analysis to check files and directories for potentially malicious behavior, equipped with a role-based access control system and an analytics dashboard.

<h2> Features </h2>
- Heuristic detection engine with 20 rules (entropy analysis, magic byte verification, double extension detection, keyword scanning, and more)<br>
- Role-based access control (admin / user)<br>
- Scan history and audit logging<br>
- Analytics dashboard with charts<br>
- File quarantine management<br>
- SQLite-backed database

<h2> Roles </h2>

<b>Admin</b> — Full access: Can view scan history and logs of all users, restore or permanently delete files from quarantine, and view system-wide analytics.

<b>User</b> — Restricted access: Can scan files, view their own scan history and logs, and view their own analytics. They do not have access to other users' data or the ability to manage quarantined files.

> The first registered account automatically becomes the administrator. All subsequent accounts are assigned the user role. The default administrator account details are provided in `admin.py`.
> Admin info: username `admin` / password `Admin@123456`

<h2> Tech Stack </h2>
Python, PyQt5, SQLite, matplotlib, bcrypt, python-magic

<h2> Installation </h2>

Install the required dependencies:

```bash
pip install PyQt5
pip install bcrypt
pip install python-magic-bin
pip install matplotlib
```

<h2> Step 1 — Database initialization (run only once): </h2>

```bash
python database.py
```
<h2>Step 2 — Create the administrator account (run only once):</h2>

```bash
python admin.py
```
<h2>Step 3 — Run the application:</h2>

```bash
python main.py
```

```bash
ShieldPy/
├── main.py                 # Entry point — launches the application
├── admin.py                # Seeds the default admin account (run once)
├── auth_window.py          # Login & registration UI with email verification
├── antivirus_main.py       # Main dashboard — scanner, quarantine, logs, analytics
├── rules_for_detection.py  # Heuristic engine — 18+ detection rules
├── realscanner.py          # Scans files and directories, saves results to DB
├── safefolder.py           # Quarantine — isolate, restore, or delete threats
├── analytics.py            # Fetches scan stats and summary counts from DB
├── analytics_panel.py      # Analytics UI — charts and stat cards
├── login.py                # Auth logic — signup, login, bcrypt, email verification
├── database.py             # Initializes SQLite schema and tables
├── logs.py                 # Audit logger — records all security events
├── hash_checker.py         # SHA-256 file hashing 
├── antivirus.db            # SQLite database (auto-created on first run)
└── README.md
```