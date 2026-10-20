import os
import sqlite3
from rules_for_detection import RulesForViruses
from hash_checker import HashChecker
from logs import AuditLogger


class FileScanner:
    def __init__(self, db_path):
        self.db_path = db_path
        self.rules_engine = RulesForViruses(db_path)
        self.hash_checker = HashChecker()

    def get_stored_hash(self, filepath):
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT file_hash FROM scanned_files WHERE filepath = ? ORDER BY scanned_at DESC LIMIT 1",
                (filepath,)
            ).fetchone()
        return row[0] if row else None

    def single_file_scan(self, full_path, user_id):

        if not os.path.exists(full_path):
            return {
                "file": os.path.basename(full_path),
                "path": full_path,
                "score": 0,
                "status": "error",
                "reasons": [f"File not found: {full_path}"],
            }

        file_size = os.path.getsize(full_path)
        stored_hash = self.get_stored_hash(full_path)
        current_hash = self.hash_checker.new_hash(full_path)

        analysis = self.rules_engine.analyzing(
            filepath=full_path,
            stored_hash=stored_hash,
            hash_checker=self.hash_checker 
        )

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO scanned_files (user_id, filename, filepath, file_hash, file_size, scan_score, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (user_id, os.path.basename(full_path), full_path, current_hash, file_size, analysis["score"], analysis["status"]))
            conn.commit()
        if analysis["status"] in ["dangerous", "fatal"]:
            AuditLogger(self.db_path).log_event(user_id, "threat was caught", f"File: {os.path.basename(full_path)}")


        return {
            "file":    os.path.basename(full_path),
            "path":    full_path,
            "score":   analysis["score"],
            "status":  analysis["status"],
            "reasons": analysis["reasons"],
        }

    def scan_path(self, target_path, user_id):
        if not os.path.exists(target_path):
            return f"Error: Path {target_path} does not exist."
        
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
            username = row[0] if row else "Unknown"

        AuditLogger(self.db_path).log_event(user_id, "info", f"File scanned by {username}, Target: {os.path.basename(target_path)}")

        scan_logs = []

        if os.path.isfile(target_path):
            try:
                log = self.single_file_scan(target_path, user_id)
                scan_logs.append(log)
            except Exception as e:
                print(f"Error scanning file {target_path}: {e}")
                scan_logs.append({
                    "file": os.path.basename(target_path),
                    "path": target_path,
                    "score": 0,
                    "status": "error",
                    "reasons": [str(e)],
                })

        elif os.path.isdir(target_path):
            for root, _, files in os.walk(target_path):
                for file in files:
                    full_path = os.path.join(root, file)
                    try:
                        log = self.single_file_scan(full_path, user_id)
                        scan_logs.append(log)
                    except Exception as e:
                        print(f"Error scanning file {full_path}: {e}")
                        scan_logs.append({
                            "file": file,
                            "path": full_path,
                            "score": 0,
                            "status": "error",
                            "reasons": [str(e)],
                        })

        return scan_logs