import os
import shutil
import sqlite3
from .logs import AuditLogger

class QuarantineManager:
    def __init__(self, db_path, vault_dir="safe_folder_for_viruses"):
        self.db_path = db_path
        self.vault_dir = vault_dir
        
        if not os.path.exists(self.vault_dir):
            os.makedirs(self.vault_dir)

    def isolate_file(self, original_path, user_id, file_hash):
        if not os.path.exists(original_path):
            return False, "File no longer exists at target location."
        try:
            filename = os.path.basename(original_path)
            vault_filename = f"{filename}.locked"
            vault_path = os.path.join(self.vault_dir, vault_filename)
            shutil.move(original_path, vault_path) 


            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO quarantine (user_id, original_path, vault_path, file_hash)
                    VALUES (?, ?, ?, ?)
                """, (user_id, original_path, vault_path, file_hash))
                conn.commit()

            AuditLogger(self.db_path).log_event(user_id, "file got quarantined", f"File: {filename}")
            return True, f"File successfully isolated in vault as {vault_filename}"
        except Exception as e:
            return False, f"Failed to quarantine file: {str(e)}"

    def get_quarantine_list(self, user_id, user_role):
        with sqlite3.connect(self.db_path) as conn:
            if user_role == "admin":
                rows = conn.execute("""
                    SELECT id, original_path, vault_path, file_hash, quarantined_at
                    FROM quarantine
                    ORDER BY quarantined_at DESC
                """).fetchall()
            else:
                rows = conn.execute("""
                    SELECT id, original_path, vault_path, file_hash, quarantined_at
                    FROM quarantine
                    WHERE user_id = ?
                    ORDER BY quarantined_at DESC
                """, (user_id,)).fetchall()
        return [
            {
                "id": i[0],
                "original_path": i[1],
                "vault_path": i[2],
                "file_hash": i[3],
                "quarantined_at": i[4]
            }
            for i in rows
        ]

    def restore_from_quarantine(self, quarantine_id, user_id, user_role): 
        if user_role != "admin":
            return False, "Access Denied: Only administrators can restore files from quarantine." 
        
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("""
                SELECT original_path, vault_path FROM quarantine
                WHERE id = ?
            """, (quarantine_id,)).fetchone()

        if not row:
            return False, "Quarantine record not found."

        original_path, vault_path = row

        if not os.path.exists(vault_path):
            return False, "Vault file missing — it may have been deleted."

        try:
            os.makedirs(os.path.dirname(original_path), exist_ok=True) 
            shutil.move(vault_path, original_path) 
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM quarantine WHERE id = ?", (quarantine_id,))
                conn.commit()
            AuditLogger(self.db_path).log_event(user_id, "file got restored", f"Path: {original_path}")
            return True, f"File restored to: {original_path}"
        except Exception as e:
            return False, f"Restore failed: {str(e)}"

    def delete_from_quarantine(self, quarantine_id, user_id, user_role): 
        if user_role != "admin":
            return False, "Access Denied: Only administrators can permanently delete files."
        
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("""
                SELECT vault_path FROM quarantine
                WHERE id = ?
            """, (quarantine_id,)).fetchone()

        if not row:
            return False, "Quarantine record not found."

        vault_path = row[0]

        try:
            if os.path.exists(vault_path):
                os.remove(vault_path) 
            with sqlite3.connect(self.db_path) as conn: 
                conn.execute("DELETE FROM quarantine WHERE id = ?", (quarantine_id,))
                conn.commit()
            AuditLogger(self.db_path).log_event(user_id, "file got deleted", f"Record ID: {quarantine_id}")
            return True, "File permanently deleted from vault."
        except Exception as e:
            return False, f"Deletion failed {str(e)}"