import sqlite3

DB_PATH = "antivirus.db"

def initialize_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                hashed_psw TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                role TEXT,
                access_level TEXT,
                created_at TIMESTAMP DEFAULT (datetime('now', 'localtime'))
            )
        """)

   
        conn.execute("""
            CREATE TABLE IF NOT EXISTS signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT,
                file_hash TEXT UNIQUE,
                threat_score INTEGER
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS scanned_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                filename TEXT,
                filepath TEXT,
                file_hash TEXT,
                file_size INTEGER,
                scan_score INTEGER,
                status TEXT,
                scanned_at TIMESTAMP DEFAULT (datetime('now', 'localtime')),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS quarantine (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                original_path TEXT,
                vault_path TEXT,
                file_hash TEXT,
                quarantined_at TIMESTAMP DEFAULT (datetime('now', 'localtime')),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """) 
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (  
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,         
                details TEXT,                 
                timestamp TIMESTAMP DEFAULT (datetime('now', 'localtime')),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        conn.commit()
        
        known_virus_signatures = [
        ("Eicar_Test_File", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", 100),
        ("Trojan_Dropper_A", "2d75bc5a4f217826315570c9603f90547f8a7092176378e9f291589139ee93c8", 100),
        ("Ransomware_Stub", "85515c6de4e364ea2128a1ec5626966a3eb74965005b4a532395b058a69e7100", 100),
        ("WannaCry", "07c44729e2c570b37db695323249474831f5861d45318bf49ccf5d2f5c8ea1cd", 100),
        ("Dridex", "6f8f1b26324ea0f3f566fbdcb4a61eb92d054ccf0300c52b3549c774056b8f02", 100),
        ("Stuxnet_Variant_A", "fe1419e9dde6d479bd7cda27edd39fafdab2668d498931931a2769b370727129", 100),
        ("Carabank", "16d2e5a617f5ab0170c869dbfe68087d21d4e6923d60e0ea58cc6cabe353da0c", 100),
        ("Emotet", "5726b610b8df672e55f1368d32327b9c93fbe4734c3ded8307a4b4d3b927b9b1", 100)

        
        ]
        try:
            conn.executemany(
            "INSERT OR IGNORE INTO signatures (rule_name, file_hash, threat_score) VALUES (?, ?, ?)", 
             known_virus_signatures
        )
            conn.commit()
        except Exception as e:
              print("DB error:", e)
if __name__ == "__main__":
    initialize_db()

