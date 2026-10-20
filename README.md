<h1>ShieldPy — Heuristic Malware Detection System</h1>

დესკტოპ-აპლიკაცია, რომელიც ჰევრისტიკული ანალიზის გამოყენებით ფაილებსა და დირექტორიებში პოტენციურად მავნე ქცევას ამოწმებს და აღჭურვილია როლებზე დაფუძნებული წვდომის კონტროლის სისტემითა და ანალიტიკური დაფით.

<h2> Features </h2>
- Heuristic detection engine with 20 rules (entropy analysis, magic byte verification, double extension detection, keyword scanning, and
more)<br>
- Role-based access control (admin / user)<br>
- Scan history and audit logging<br>
- Analytics dashboard with charts<br>
- File quarantine management<br>
- SQLite-backed database

<h2> Roles </h2>

<b>Admin</b>— სრული წვდომა: შეუძლია ყველა მომხმარებლის სკანირების ისტორიისა და ლოგების ნახვა, ფაილების აღდგენა ან სამუდამოდ წაშლა კარანტინიდან და სისტემის მასშტაბით ანალიტიკის ნახვა.

<b>User</b> — შეზღუდული წვდომა: შეუძლიათ ფაილების სკანირება, საკუთარი სკანირების ისტორიისა და ჟურნალების ნახვა და საკუთარი ანალიტიკის ნახვა. არ აქვთ სხვა მომხმარებლების მონაცემებზე წვდომა ან კარანტინში მოთავსებული ფაილების მართვის უფლება.

> პირველი რეგისტრირებული ანგარიში ავტომატურად ხდება ადმინისტრატორი. ყველა შემდგომ ანგარიშს ენიჭება მომხმარებლის როლი. ნაგულისხმევი ადმინისტრატორის ანგარიში მოცემულია `admin.py`.
> Admin ინფო: username `admin` / password `Admin@123456`

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

<h2> How to Run </h2>

<b>Step 1 </b>- მონაცემთა ბაზის ინიციალიზაცია (გაუშვით მხოლოდ ერთხელ):

```bash
python database.py
```

<b>Step 2 </b>— შექმენით ადმინისტრატორის ანგარიში (გაუშვით მხოლოდ ერთხელ):

```bash
python admin.py
```

<b>Step 3 </b> — გაუშვით აპლიკაცია:

```bash
python main.py
```

 <h2>Project Structure</h2>

```
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
└── antivirus.db            # SQLite database (auto-created on first run)
└──  README.md
```
