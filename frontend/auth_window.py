import backend.database as database
import os
from backend.login import LoginManager

from PyQt5.QtWidgets import (
    QWidget, QStackedWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QMessageBox,
    QGraphicsDropShadowEffect, QInputDialog
)
from PyQt5.QtGui import QPixmap, QPainter, QColor, QIcon
from PyQt5.QtCore import Qt, QEvent

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BG_PATH = os.path.join(BASE_DIR, "mesame.jpg").replace("\\", "/")

from PyQt5.QtGui import QPixmap, QPainter, QColor, QIcon, QPen
from PyQt5.QtCore import Qt, QEvent, QPropertyAnimation




def add_glow(widget, color="#4fd8ff", blur=20):
    glow = QGraphicsDropShadowEffect()
    glow.setColor(QColor(color))
    glow.setBlurRadius(blur)
    glow.setOffset(0, 0)
    widget.setGraphicsEffect(glow)


class CornerBracket(QWidget):
    def __init__(self, size=28, thickness=2, color="#4fd8ff", corner="tl"):
        super().__init__()
        self.setFixedSize(size, size)
        self.thickness = thickness
        self.color = QColor(color)


class AuthWindow(QWidget):
    def __init__(self, dashboard):
        super().__init__()
        self.bg_pixmap = QPixmap(BG_PATH)
        
        self.dashboard = dashboard
        self.login_manager = LoginManager(database.DB_PATH)
        self.init_ui()

    def paintEvent(self, event):
        painter = QPainter(self)
        if not self.bg_pixmap.isNull():
            scaled = self.bg_pixmap.scaled(
                self.size(), Qt.IgnoreAspectRatio, Qt.SmoothTransformation
            )
            painter.drawPixmap(0, 0, scaled)

        pen = QPen(QColor(79, 216, 255, 18))
        painter.setPen(pen)
        for y in range(0, self.height(), 4):
            painter.drawLine(0, y, self.width(), y)

        super().paintEvent(event)

    def init_ui(self):
        self.setWindowTitle("ShieldPy security gateway")
        self.setGeometry(100, 100, 900, 650)
        icon_path = os.path.join(BASE_DIR, "login.png").replace("\\", "/")
        self.setWindowIcon(QIcon(icon_path))

        outer_layout = QHBoxLayout()
        outer_layout.setAlignment(Qt.AlignCenter)
        outer_layout.setSpacing(25)

        self.card = QWidget() 
        self.card.setFixedSize(500, 520)
        self.card.setAttribute(Qt.WA_StyledBackground, True)
        self.card.setStyleSheet("""
            QWidget {
                background-color: rgba(8, 15, 35, 210);
                border-radius: 14px;
            }
            QLineEdit {
                background-color: rgba(20, 35, 60, 180);
                border: 1px solid #4fd8ff;
                border-radius: 6px;
                color: #eafcff;
                padding: 5px;
                font-size: 15px;
            }
            QPushButton {
                background-color: rgba(0, 80, 120, 200);
                border: 1px solid #4fd8ff;
                border-radius: 6px;
                color: #eafcff;
                padding: 5px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(0, 110, 160, 220);
            }
            QLabel {
                background-color: transparent;
                color: #eafcff;
                font-family: 'Courier New';
                font-size: 14px;
            }
        """)

        card_glow = QGraphicsDropShadowEffect()
        card_glow.setColor(QColor("#7ee8ff"))
        card_glow.setOffset(0, 0)
        card_glow.setBlurRadius(15)
        self.card.setGraphicsEffect(card_glow)
 
        self.pulse_anim = QPropertyAnimation(card_glow, b"blurRadius")
        self.pulse_anim.setStartValue(15)
        self.pulse_anim.setKeyValueAt(0.5, 40)
        self.pulse_anim.setEndValue(15)
        self.pulse_anim.setDuration(2200)
        self.pulse_anim.setLoopCount(-1) 
        self.pulse_anim.start()

        card_layout = QVBoxLayout(self.card)
        card_layout.setContentsMargins(0, 0, 0, 0)

        self.stack = QStackedWidget()
        self.stack.setStyleSheet("background-color: transparent;")

        self.tab_login = QWidget()
        self.tab_login.setStyleSheet("background-color: transparent;")
        self.tab_signup = QWidget()
        self.tab_signup.setStyleSheet("background-color: transparent;")

        self.create_login_tab()
        self.create_signup_tab()

        self.stack.addWidget(self.tab_login)
        self.stack.addWidget(self.tab_signup)

        card_layout.addWidget(self.stack)

        outer_layout.addWidget(self.card)
        self.setLayout(outer_layout)

    def create_login_tab(self): 
        layout = QVBoxLayout()
        layout.setContentsMargins(40, 35, 40, 35)
        layout.setAlignment(Qt.AlignTop)

        title = QLabel("Sentinel")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 38px; font-weight: bold; color: #ffffff; background-color: transparent;")
        add_glow(title, "#4fd8ff", 25)

        subtitle = QLabel("Threat detection system")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("font-size: 14px; color: #cdeffd; background-color: transparent;")
        add_glow(subtitle, "#4fd8ff", 12)

        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(25)

        self.login_user = QLineEdit()
        self.login_user.setPlaceholderText("enter your username")
        self.login_user.setFixedWidth(380)
        self.login_user.setFixedHeight(40)
        self.login_user.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.login_user, alignment=Qt.AlignHCenter)

        layout.addSpacing(10)

        self.login_password = QLineEdit()
        self.login_password.setPlaceholderText("enter your password")
        self.login_password.setEchoMode(QLineEdit.Password) 
        self.login_password.setFixedWidth(380)
        self.login_password.setFixedHeight(40)
        self.login_password.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.login_password, alignment=Qt.AlignHCenter)

        layout.addSpacing(20)

        login_btn = QPushButton("START SECURING YOUR SYSTEM")
        login_btn.setFixedWidth(380)
        login_btn.setFixedHeight(40)
        login_btn.clicked.connect(self.handle_login_action)
        layout.addWidget(login_btn, alignment=Qt.AlignHCenter)

        layout.addSpacing(10)
        self.register_link = QLabel('<a href="register" style="color: #4fd8ff;">Don\'t have an account? Click here</a>')
        self.register_link.setAlignment(Qt.AlignCenter)
        self.register_link.linkActivated.connect(lambda: self.stack.setCurrentIndex(1))
        layout.addWidget(self.register_link)

        layout.addStretch()

        status_label = QLabel("SYSTEM STATUS")
        status_label.setAlignment(Qt.AlignCenter)
        status_label.setStyleSheet("font-size: 12px; color: #cdeffd; background-color: transparent;")
        add_glow(status_label, "#4fd8ff", 10)
        layout.addWidget(status_label)

        for text in [
            "● Threat Engine: ONLINE",
            "● Analysis Core: READY",
            "● Database: CONNECTED",
            "● Attack Mapping: READY",
        ]:
            lbl = QLabel(text)
            lbl.setAlignment(Qt.AlignCenter)
            lbl.setStyleSheet("font-size: 12px; color: #b8f1ff; background-color: transparent;")
            add_glow(lbl, "#4fd8ff", 8)
            layout.addWidget(lbl)

        self.tab_login.setLayout(layout)

    def create_signup_tab(self): 
        layout = QVBoxLayout()
        layout.setContentsMargins(40, 35, 40, 35)
        layout.setAlignment(Qt.AlignTop)

        title = QLabel("Sentinel")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 38px; font-weight: bold; color: #ffffff; background-color: transparent;")
        add_glow(title, "#4fd8ff", 25)

        subtitle = QLabel("Create a new account")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("font-size: 14px; color: #cdeffd; background-color: transparent;")
        add_glow(subtitle, "#4fd8ff", 12)

        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(25)

        self.signup_user = QLineEdit()
        self.signup_user.setPlaceholderText("create your username")
        self.signup_user.setFixedWidth(380)
        self.signup_user.setFixedHeight(40)
        self.signup_user.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.signup_user, alignment=Qt.AlignHCenter)

        layout.addSpacing(10)

        self.signup_email = QLineEdit()
        self.signup_email.setPlaceholderText("enter your email address")
        self.signup_email.setFixedWidth(380)
        self.signup_email.setFixedHeight(40)
        self.signup_email.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.signup_email, alignment=Qt.AlignHCenter)

        layout.addSpacing(10)

        self.signup_password = QLineEdit()
        self.signup_password.setPlaceholderText("create a strong password")
        self.signup_password.setEchoMode(QLineEdit.Password)
        self.signup_password.setFixedWidth(380)
        self.signup_password.setFixedHeight(40)
        self.signup_password.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.signup_password, alignment=Qt.AlignHCenter)

        layout.addSpacing(20)

        register_btn = QPushButton("REGISTER")
        register_btn.setFixedWidth(380)
        register_btn.setFixedHeight(40)
        register_btn.clicked.connect(self.handle_signup_action)
        layout.addWidget(register_btn, alignment=Qt.AlignHCenter)

        layout.addSpacing(10)

        signin_btn = QPushButton("SIGN IN")
        signin_btn.setFixedWidth(380)
        signin_btn.setFixedHeight(40)
        signin_btn.clicked.connect(lambda: self.stack.setCurrentIndex(0)) 
        layout.addWidget(signin_btn, alignment=Qt.AlignHCenter)

        self.signup_user.installEventFilter(self)
        self.signup_email.installEventFilter(self)
        self.signup_password.installEventFilter(self)

        self.signup_user.returnPressed.connect(self.handle_signup_action)
        self.signup_email.returnPressed.connect(self.handle_signup_action)
        self.signup_password.returnPressed.connect(self.handle_signup_action)

        layout.addStretch()
        self.tab_signup.setLayout(layout)

    def handle_login_action(self):
       user, password = self.login_user.text(), self.login_password.text()
       success, msg, user_id, role = self.login_manager.login(user, password)
       if success:
           self.dashboard.user_id = user_id 
           self.dashboard.user_role = role    
           self.dashboard.username = user
           self.dashboard.load_quarantine_from_db()
           self.dashboard.show()
           self.close()
       else:
          QMessageBox.warning(self, "Error", msg)

    def handle_signup_action(self):
        try:
            username = self.signup_user.text()
            email = self.signup_email.text()
            password = self.signup_password.text()

            success, msg = self.login_manager.initiate_signup(username, email, password)

            if not success:
                QMessageBox.warning(self, "Error", msg)
                return
            code, ok = QInputDialog.getText(
                self, "Verify your email",
                f"{msg}\n\nEnter the 6-digit code sent to {email}:"
            )

            if not ok or not code:
                QMessageBox.information(self, "Cancelled", "Signup was not completed.")
                return

            verified, verify_msg = self.login_manager.complete_signup(username, code)

            if verified:
                QMessageBox.information(self, "Success", verify_msg)
                self.stack.setCurrentIndex(0)
            else:
                QMessageBox.warning(self, "Error", verify_msg)

        except Exception as e:
            import traceback
            traceback.print_exc()
            QMessageBox.critical(self, "Unexpected Error", str(e))

    def eventFilter(self, source, event):
        if event.type() == QEvent.KeyPress and event.key() == Qt.Key_Escape:
            self.close()
            return True
        return super().eventFilter(source, event)

