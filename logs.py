import sqlite3

class AuditLogger:
    def __init__(self, db_path):
        self.db_path = db_path

    def log_event(self, user_id, action, details=None): 
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO audit_logs (user_id, action, details)
                    VALUES (?, ?, ?)
                """, (user_id, action, details))
                conn.commit()
            return True
        except Exception as e:
            print(f"Failed to write audit log: {e}")
            return False

    def get_logs(self, user_id, user_role):
        rows = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor() 
                
                if user_role == "admin":
                    cursor.execute("""
                        SELECT l.id, u.username, l.action, l.details, l.timestamp 
                        FROM audit_logs l
                        LEFT JOIN users u ON l.user_id = u.id
                        ORDER BY l.timestamp DESC
                    """)
                    rows = cursor.fetchall()
                else:
                    cursor.execute("""
                        SELECT l.id, u.username, l.action, l.details, l.timestamp 
                        FROM audit_logs l
                        LEFT JOIN users u ON l.user_id = u.id
                        WHERE l.user_id = ?
                        ORDER BY l.timestamp DESC
                    """, (user_id,))
                    rows = cursor.fetchall()
        except Exception as e:
            print(f"Failed to fetch audit logs: {e}")
            return [] 
                
        return [
            {
                "id": i[0],
                "username": i[1] if i[1] else "System/Guest", 
                "action": i[2],
                "details": i[3] if i[3] else "",
                "timestamp": i[4]
            }
            for i in rows
        ]