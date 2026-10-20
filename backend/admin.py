import sqlite3
import bcrypt
import database

database.initialize_db()

username = "admin"
password = "Admin@123456"   
email    = "admin@shieldpy.local"

hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

with sqlite3.connect(database.DB_PATH) as conn:
    conn.execute(
        "INSERT OR IGNORE INTO users(username, email, hashed_psw, role, access_level) VALUES(?,?,?,?,?)",
        (username, email, hashed, "admin", "EXECUTE")
    )
    conn.commit()
    print(f"Admin '{username}' created. Password: {password}")