import sys
from PyQt5.QtWidgets import QApplication
from frontend.antivirus_main import AntivirusDashboard
from frontend.auth_window import AuthWindow
import backend.database as database

from backend.login import LoginManager
from backend.realscanner import FileScanner
from backend.safefolder import QuarantineManager

if __name__ == "__main__":
    database.initialize_db()
    app = QApplication(sys.argv)
    dashboard = AntivirusDashboard()
    auth = AuthWindow(dashboard)
    auth.show()
    sys.exit(app.exec_())