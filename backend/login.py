import sqlite3
import re
import random
import smtplib
from email.message import EmailMessage
import bcrypt
from .mydata import EMAIL_PASSWORD, SENDER_EMAIL
from .logs import AuditLogger

class LoginManager:
    def __init__(self, db_path):
        self.db_path = db_path
        self.pending_verifications = {} 
        self.current_user_role = None 

    def validation(self, password):
        if len(password) < 12: 
            return False, "Password must be at least 12 characters"
        if not re.search(r"(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*(),.?\":{}|<>])", password):
            return False, "Password must contain uppercase, lowercase, digit, and special symbol"
        return True, None

    def send_verification_email(self, to_email, code): 
        sender_email = SENDER_EMAIL  
        sender_password = EMAIL_PASSWORD
        smtp_server = 'smtp.gmail.com'

        message = EmailMessage()
        message['From'] = sender_email
        message['To'] = to_email
        message['Subject'] = 'თქვენი ვერიფიკაციის კოდი'
        message.set_content(f'თქვენი ერთჯერადი კოდია: {code}')

        try:
            with smtplib.SMTP_SSL(smtp_server, 465) as server:
                server.login(sender_email, sender_password)
                server.send_message(message)
            return True
        except Exception as e:
            print(f"Failed to send email: {e}")
            return False

    def initiate_signup(self, username, email, password):
        is_valid, error = self.validation(password) 
        if not is_valid:
            return False, error
        
        with sqlite3.connect(self.db_path) as conn:
            existing = conn.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email)).fetchone() 
            if existing:
                return False, "Username or Email already exists"

        verification_code = str(random.randint(100000, 999999))
        
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        self.pending_verifications[username] = {
            "email": email,
            "hashed_psw": hashed,
            "code": verification_code
        }

        
        if self.send_verification_email(email, verification_code):
            return True, "Verification code sent to your email!"
        return False, "Failed to send verification email. Try again."

    def complete_signup(self, username, user_entered_code):
        if username not in self.pending_verifications:
            return False, "No registration session found for this user."

        user_data = self.pending_verifications[username]

        if user_entered_code == user_data["code"]: 
            try:
                with sqlite3.connect(self.db_path) as conn:
                    count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
                    
                    role = "admin" if count == 0 else "user"
                    lvl = "EXECUTE" if count == 0 else "READ"

                    conn.execute(
                        "INSERT INTO users(username, email, hashed_psw, role, access_level) VALUES(?,?,?,?,?)",
                        (username, user_data["email"], user_data["hashed_psw"], role, lvl)
                    )
                    conn.commit()
                del self.pending_verifications[username]
                return True, "Account created successfully!"
            except sqlite3.IntegrityError:
                return False, "Account registration failed."
        else:
            return False, "Incorrect verification code."

    def login(self, username, password):
        with sqlite3.connect(self.db_path) as conn:
            info = conn.execute("SELECT id, hashed_psw, role FROM users WHERE username = ?", (username,)).fetchone()
        if info:
            user_id, hashed_psw, role = info[0], info[1], info[2]
            if bcrypt.checkpw(password.encode(), hashed_psw.encode()):
                self.current_user_role = role
                AuditLogger(self.db_path).log_event(user_id, "info", f"{username} logged in")
                return True, "Login successful", user_id, role
        return False, "Invalid username or password", None, None