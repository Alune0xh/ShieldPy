import sys
import database
from PyQt5.QtWidgets import QApplication
from antivirus_main import AntivirusDashboard
from auth_window import AuthWindow

if __name__ == "__main__":
    database.initialize_db()
    app = QApplication(sys.argv)
    dashboard = AntivirusDashboard()
    auth = AuthWindow(dashboard)
    auth.show()
    sys.exit(app.exec_())