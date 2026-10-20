import os
import sqlite3 
from PyQt5.QtWidgets import (
     QWidget, QLabel, QPushButton, QLineEdit,
     QTextBrowser, QFileDialog, QVBoxLayout,
    QHBoxLayout, QStackedWidget, QFrame,
    QTableWidget, QTableWidgetItem, QHeaderView

)
from PyQt5.QtCore import Qt 
from analytics_panel import AnalyticsPanel
from PyQt5.QtGui import  QIcon


class AntivirusDashboard(QWidget): 
    def __init__(self):
        super().__init__()
        import database
        database.initialize_db() 

        from login import LoginManager
        from realscanner import FileScanner
        from safefolder import QuarantineManager


        self.login_manager = LoginManager(database.DB_PATH)
        self.scanner = FileScanner(database.DB_PATH) 
        self.quarantine_manager = QuarantineManager(database.DB_PATH) 

        self.user_id = None 
        self.user_role = None 
        self.username = None 

        self.init_ui() 


    def init_ui(self): 
        self.setWindowTitle("ShieldPy Antivirus Engine v1.0") 
        self.setGeometry(100, 100, 900, 600) 
        self.setStyleSheet("background-color: #0d1117;") 
        self.setWindowIcon(QIcon("N3.png")) 

        main_layout = QHBoxLayout() 
        main_layout.setContentsMargins(0, 0, 0, 0) 
        main_layout.setSpacing(0) 

        sidebar = QWidget()
        sidebar.setFixedWidth(200)
        sidebar.setStyleSheet("background-color: #0d1f3c;")
        sidebar_layout = QVBoxLayout(sidebar) 
        sidebar_layout.setContentsMargins(15, 25, 15, 25)
        sidebar_layout.setSpacing(8) 

        app_title = QLabel("SHIELDPY") 
        app_title.setStyleSheet("""
            color: #4fd8ff;
            font-size: 16px;
            font-weight: bold;
            font-family: 'Courier New';
            padding-bottom: 20px;
        """)
        sidebar_layout.addWidget(app_title) 

        self.nav_buttons = {} 
        for name in ["Home", "Logs", "Analytics"]: 
            btn = QPushButton(name)
            btn.setFixedHeight(40)
            btn.setStyleSheet("""
                QPushButton {
                    background-color: transparent;
                    color: #a0b4c8;
                    font-size: 14px;
                    font-family: 'Courier New';
                    text-align: left;
                    padding-left: 12px;
                    border-radius: 6px;
                    border: none;
                }
                QPushButton:hover {
                    background-color: rgba(79, 216, 255, 0.1);
                    color: #4fd8ff;
                }
            """)
            btn.clicked.connect(lambda checked, n=name: self.switch_page(n)) 
            sidebar_layout.addWidget(btn)
            self.nav_buttons[name] = btn

        sidebar_layout.addStretch()

        logout_btn = QPushButton("Log out")
        logout_btn.setFixedHeight(38)
        logout_btn.setStyleSheet("""
         QPushButton {
        background-color: rgba(220, 38, 38, 0.12);
        border: 1px solid rgba(220, 38, 38, 0.5);
        border-radius: 6px;
        color: #f87171;
        font-size: 13px;
        font-weight: bold;
        font-family: 'Courier New';
        padding: 6px;
        }
        QPushButton:hover {
        background-color: rgba(220, 38, 38, 0.25);
        border: 1px solid #dc2626;
          }
         """)
        sidebar_layout.addWidget(logout_btn)
        sidebar_layout.addSpacing(8)
        version_label = QLabel("v1.0.0")
        logout_btn.clicked.connect(self.handle_logout)


        version_label.setStyleSheet("color: #3a5068; font-size: 11px; font-family: 'Courier New';")
        version_label.setAlignment(Qt.AlignCenter)
        sidebar_layout.addWidget(version_label)

        self.stack = QStackedWidget()
        self.stack.setStyleSheet("background-color: #0d1117;")

        self.page_home = self.build_home_page() 
        self.page_logs = self.build_logs_page() 
        self.page_analytics = QWidget()

        self.stack.addWidget(self.page_home) 
        self.stack.addWidget(self.page_logs)
        self.stack.addWidget(self.page_analytics) 

        main_layout.addWidget(sidebar) 
        main_layout.addWidget(self.stack)
        self.setLayout(main_layout)

        self.switch_page("Home") 

        self.load_quarantine_from_db()  


    def build_home_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 25, 30, 25)
        layout.setSpacing(15)
        
        self.scan_title = QLabel("Welcome back 👋")  
        self.scan_title.setStyleSheet("color: #eafcff; font-size: 22px; font-weight: bold; font-family: 'Courier New';")
        subtitle = QLabel("Choose a file to scan for threats and manage quarantined items.")
        subtitle.setStyleSheet("color: #4a6a80; font-size: 13px; font-family: 'Courier New';")
        layout.addWidget(self.scan_title)
        layout.addWidget(subtitle)

        
        scan_card = QFrame()
        scan_card.setStyleSheet("""
            QFrame {
                background-color: #111d2e;
                border: 1px solid #1e3a5a;
                border-radius: 10px;
            }
        """)
        card_layout = QVBoxLayout(scan_card)
        card_layout.setContentsMargins(20, 20, 20, 20)
        card_layout.setSpacing(10)

        path_row = QHBoxLayout() 
        self.path_input = QLineEdit() 
        self.path_input.setPlaceholderText("Select or paste a file path...") 
        self.path_input.setFixedHeight(38)
        self.path_input.setStyleSheet("""
            QLineEdit {
                background-color: #0d1f3c;
                border: 1px solid #1e3a5a;
                border-radius: 6px;
                color: #eafcff;
                padding: 5px 10px;
                font-size: 13px;
                font-family: 'Courier New';
            }
        """)

        browse_btn = QPushButton("Browse") 
        browse_btn.setFixedHeight(38)
        browse_btn.setFixedWidth(90)
        browse_btn.setStyleSheet("""
            QPushButton {
                background-color: #1a3a5c;
                border: 1px solid #4fd8ff;
                border-radius: 6px;
                color: #4fd8ff;
                font-size: 13px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #1e4a70; }
        """)
        browse_btn.clicked.connect(self.handle_browse)

        path_row.addWidget(self.path_input)
        path_row.addWidget(browse_btn)
        card_layout.addLayout(path_row)

        scan_btn = QPushButton("SCAN TARGET") 
        scan_btn.setFixedHeight(40)
        scan_btn.setStyleSheet("""
            QPushButton {
                background-color: #0a4a8a;
                border: 1px solid #4fd8ff;
                border-radius: 6px;
                color: #eafcff;
                font-size: 14px;
                font-weight: bold;
                font-family: 'Courier New';
            }
            QPushButton:hover { background-color: #0d5ea8; }
        """)
        scan_btn.clicked.connect(self.handle_system_scan) 
        card_layout.addWidget(scan_btn)

        layout.addWidget(scan_card)
        
        bottom_split = QHBoxLayout() 
        bottom_split.setSpacing(15)

        left_panel = QVBoxLayout()
        console_label = QLabel("Detection Logs:")
        console_label.setStyleSheet("color: #4a6a80; font-size: 13px; font-family: 'Courier New';")
        left_panel.addWidget(console_label)
        

        self.log_console = QTextBrowser()
        self.log_console.setStyleSheet("""
            QTextBrowser {
                background-color: #080f1a;
                border: 1px solid #1e3a5a;
                border-radius: 8px;
                color: #4fd8ff;
                font-family: 'Courier New';
                font-size: 15px;
                padding: 12px;
            }
        """)
        left_panel.addWidget(self.log_console)
        bottom_split.addLayout(left_panel, 1)


        right_panel = QVBoxLayout()
        quarantine_label = QLabel("⛉ Safe Folder (Quarantine):")
        quarantine_label.setStyleSheet("color: #4a6a80; font-size: 13px; font-family: 'Courier New';")
        right_panel.addWidget(quarantine_label)
       

        self.quarantine_table = QTableWidget()
        self.quarantine_table.setColumnCount(3) 
        self.quarantine_table.setHorizontalHeaderLabels(["Isolated File", "Score", "Actions"]) 
        self.quarantine_table.verticalHeader().setVisible(False) 
        self.quarantine_table.setStyleSheet("""
            QTableWidget {
                background-color: #080f1a;
                border: 1px solid #1e3a5a;
                border-radius: 8px;
                gridline-color: #1e3a5a;
                color: #eafcff;
                font-family: 'Courier New';
                font-size: 12px;
            }
            QHeaderView::section {
                background-color: #111d2e;
                color: #4fd8ff;
                padding: 5px;
                border: 1px solid #1e3a5a;
                font-family: 'Courier New';
            }
        """)
        self.quarantine_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.quarantine_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.quarantine_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.quarantine_table.setColumnWidth(2, 150)

        
        right_panel.addWidget(self.quarantine_table)
        bottom_split.addLayout(right_panel, 1)

        layout.addLayout(bottom_split)
        return page
    

    def build_logs_page(self):
       page = QWidget()
       layout = QVBoxLayout(page)
       layout.setContentsMargins(30, 25, 30, 25)
       layout.setSpacing(15)

       title = QLabel("Logs")
       title.setStyleSheet("color: #eafcff; font-size: 22px; font-weight: bold; font-family: 'Courier New';")
       subtitle = QLabel("View all security events and actions performed in the system.")
       subtitle.setStyleSheet("color: #4a6a80; font-size: 13px; font-family: 'Courier New';")
       layout.addWidget(title)
       layout.addWidget(subtitle)
       

       self.logs_table = QTableWidget()
       self.logs_table.setColumnCount(5)
       self.logs_table.setHorizontalHeaderLabels(["Time", "Event", "Details", "User", "Level"])
       self.logs_table.verticalHeader().setVisible(False)
       self.logs_table.setSelectionBehavior(QTableWidget.SelectRows)
       self.logs_table.setEditTriggers(QTableWidget.NoEditTriggers) 
       self.logs_table.setShowGrid(False)
       self.logs_table.setStyleSheet("""
        QTableWidget {
            background-color: #080f1a;
            border: 1px solid #1e3a5a;
            border-radius: 8px;
            color: #eafcff;
            font-family: 'Courier New';
            font-size: 13px;
        }
        QHeaderView::section {
            background-color: #111d2e;
            color: #4fd8ff;
            padding: 8px;
            border: none;
            border-bottom: 1px solid #1e3a5a;
            font-family: 'Courier New';
            font-size: 13px;
            font-weight: bold;
        }
        QTableWidget::item {
            padding: 5px 8px;
            border-bottom: 1px solid #0d1824;
        }
        QTableWidget::item:selected {
            background-color: rgba(79, 216, 255, 0.1);
        }
        QScrollBar:vertical {
            background: #080f1a;
            width: 8px;
            border-radius: 4px;
        }
        QScrollBar::handle:vertical {
            background: #1e3a5a;
            border-radius: 4px;
        }
        """)
       self.logs_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
       self.logs_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
       self.logs_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
       self.logs_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
       self.logs_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
       self.logs_table.horizontalHeader().setStretchLastSection(True)
       layout.addWidget(self.logs_table)

       return page
 
    def switch_page(self, name):
        pages = {"Home": 0, "Logs": 1, "Analytics": 2}
        self.stack.setCurrentIndex(pages[name])
        
        for btn_name, btn in self.nav_buttons.items(): 
            if btn_name == name: 
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: rgba(79, 216, 255, 0.15);
                        color: #4fd8ff;
                        font-size: 14px;
                        font-family: 'Courier New';
                        text-align: left;
                        padding-left: 12px;
                        border-radius: 6px;
                        border-left: 3px solid #4fd8ff;
                    }
                """) 
            else: 
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: transparent;
                        color: #a0b4c8;
                        font-size: 14px;
                        font-family: 'Courier New';
                        text-align: left;
                        padding-left: 12px;
                        border-radius: 6px;
                        border: none;
                    }
                    QPushButton:hover {
                        background-color: rgba(79, 216, 255, 0.1);
                        color: #4fd8ff;
                    }
                """) 

        if name == "Logs": 
            self.stack.setCurrentIndex(pages[name]) 
            self.load_logs() 
        elif name == "Analytics": 
            import database 
            old_page = self.page_analytics 
            self.page_analytics = AnalyticsPanel(database.DB_PATH, self.user_id, self.user_role)
            self.stack.removeWidget(old_page) 
            self.stack.insertWidget(2, self.page_analytics) 
            self.stack.setCurrentIndex(2) 
            old_page.deleteLater() 
        else: 
            self.stack.setCurrentIndex(pages[name])
    
    def _format_event(self, action):
       action_lower = action.lower()
       if "logged in" in action_lower or action_lower == "info":
          return "Access Granted"
       if "logged out" in action_lower:
        return "Session Terminated"
       return action.replace("_", " ").title()
    
    #ლოგების ჩატვირთვა - admin ყველას ხედავს, user მხოლოდ საკუთარს
    def load_logs(self):
        try:
           import database, sqlite3
           from PyQt5.QtGui import QColor
           self.logs_table.setRowCount(0) 

           with sqlite3.connect(database.DB_PATH) as conn:
              if self.user_role == "admin":
                 audit_rows = conn.execute("""
                    SELECT l.timestamp, l.action, l.details, u.username
                    FROM audit_logs l
                    LEFT JOIN users u ON l.user_id = u.id
                    ORDER BY l.timestamp DESC LIMIT 50
                 """).fetchall() 
                 scan_rows = conn.execute("""
                    SELECT f.scanned_at, f.filename, f.status, f.scan_score, u.username
                    FROM scanned_files f
                    LEFT JOIN users u ON f.user_id = u.id
                    ORDER BY f.scanned_at DESC LIMIT 50
                """).fetchall() 
              else: 
                audit_rows = conn.execute("""
                    SELECT l.timestamp, l.action, l.details, u.username
                    FROM audit_logs l
                    LEFT JOIN users u ON l.user_id = u.id
                    WHERE l.user_id = ?
                    ORDER BY l.timestamp DESC LIMIT 50
                """, (self.user_id,)).fetchall() 
                scan_rows = conn.execute("""
                    SELECT f.scanned_at, f.filename, f.status, f.scan_score, u.username
                    FROM scanned_files f
                    LEFT JOIN users u ON f.user_id = u.id
                    WHERE f.user_id = ?
                    ORDER BY f.scanned_at DESC LIMIT 50
                """, (self.user_id,)).fetchall() 

           all_rows = [] 
           for timestamp, action, details, username in audit_rows:
               action_lower = action.lower()
               if "threat" in action_lower or "fatal" in action_lower: 
                   level, level_color = "Warning", "#f87171"
               elif "quarantine" in action_lower or "delete" in action_lower: 
                   level, level_color = "Info", "#fbbf24"
               else:
                   level, level_color = "Info", "#4fd8ff"
               all_rows.append((
                   timestamp,
                   self._format_event(action),
                   details or "—", 
                   username or "System", 
                   level, level_color
                ))

           for timestamp, filename, status, score, username in scan_rows:
               status_lower = status.lower()
               if status_lower in ("fatal", "dangerous"): 
                   level, level_color = "Warning", "#f87171"
               elif status_lower == "suspicious": 
                   level, level_color = "Warning", "#fbbf24"
               else: 
                   level, level_color = "Info", "#34d399"
                   all_rows.append((
                   timestamp,
                   f"File Scanned ({status.upper()})", 
                   filename,
                   username or "Unknown", 
                   level, level_color
                   ))

           all_rows.sort(key=lambda x: x[0], reverse=True) 

          
           for timestamp, event, details, user, level, level_color in all_rows:
                row = self.logs_table.rowCount() 
                self.logs_table.insertRow(row)

                time_item = QTableWidgetItem(timestamp) 
                time_item.setForeground(QColor("#6a8a9a"))
                self.logs_table.setItem(row, 0, time_item)# 

                event_item = QTableWidgetItem(event) 
                event_item.setTextAlignment(Qt.AlignCenter) 
                self.logs_table.setItem(row, 1, event_item) 

                detail_item = QTableWidgetItem(details)
                detail_item.setForeground(QColor("#c0d8e8")) 
                detail_item.setTextAlignment(Qt.AlignCenter) 
                self.logs_table.setItem(row, 2, detail_item) 

                user_item = QTableWidgetItem(user) 
                user_item.setForeground(QColor("#4fd8ff"))
                user_item.setTextAlignment(Qt.AlignCenter)
                self.logs_table.setItem(row, 3, user_item) 

                level_item = QTableWidgetItem(level) 
                level_item.setForeground(QColor(level_color))
                level_item.setTextAlignment(Qt.AlignCenter)
                self.logs_table.setItem(row, 4, level_item) 

                self.logs_table.setRowHeight(row, 38)


        except Exception as e: 
          import traceback 
          traceback.print_exc() 
          print(f"[!] Could not load logs: {e}")

    def load_analytics(self):
        try:
            import database, sqlite3
            with sqlite3.connect(database.DB_PATH) as conn:
                total = conn.execute("SELECT COUNT(*) FROM scanned_files").fetchone()[0]
                threats = conn.execute(
                    "SELECT COUNT(*) FROM scanned_files WHERE status IN ('dangerous', 'fatal')"
                ).fetchone()[0]
                clean = total - threats

            self.stat_labels["files_scanned"].setText(str(total))
            self.stat_labels["threats"].setText(str(threats))
            self.stat_labels["clean"].setText(str(clean))
        except Exception as e:
            print(f"Analytics error: {e}")


    def handle_browse(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File to Scan") 
        if path: 
            self.path_input.setText(path) 
    

    def handle_system_scan(self):
        target = self.path_input.text().strip()
        if not target: 
            self.log_console.append("[!] Error: No target path specified.")
            return

        self.log_console.append(f"🔎 Starting scan on: {target}") 

        try: 
            import database
            from realscanner import FileScanner

            if self.scanner is None: 
                self.scanner = FileScanner(database.DB_PATH) 

            results = self.scanner.single_file_scan(target, user_id=self.user_id)
            
            if results and isinstance(results, dict): 
                score = results.get('score', 0) 
                self.log_console.append(f"📄 Status: {results.get('status', 'Unknown')}")
                self.log_console.append(f"🎯 Threat Score: {score}")
                self.log_console.append("⚠️ Detection Reasons:")
                for reason in results.get('reasons', []):
                    self.log_console.append(f"  > {reason}") 
                
                
                if score >= 70:
                   filename = os.path.basename(target)
                   from hash_checker import HashChecker
                   file_hash = HashChecker().new_hash(target)
                   self.log_console.append(f"[🚨] HIGH RISK DETECTED! Isolating '{filename}' to Quarantine...")
                   try:
                      success, message = self.quarantine_manager.isolate_file(
                         target, self.user_id, file_hash
                      )
                      if success:
                         self.log_console.append("✅ " + message)
                         with sqlite3.connect(database.DB_PATH) as conn:
                            row = conn.execute(
                                "SELECT id FROM quarantine WHERE file_hash = ? ORDER BY quarantined_at DESC LIMIT 1",
                                (file_hash,)
                            ).fetchone()
                         q_id = row[0] if row else -1
                         self.add_to_quarantine_table(q_id, filename, score)
                      else:
                         self.log_console.append("❌ " + message)
                   except Exception as e:
                      self.log_console.append(f"[!] Quarantine failed: {e}")
                
                self.log_console.append("")

            elif isinstance(results, str):
               self.log_console.append(f"[-] Engine Notice: {results}")

        except Exception as e:
            self.log_console.append(f"[!] Scan Exception: {str(e)}")

    
    def add_to_quarantine_table(self, q_id, filename, score):
        row = self.quarantine_table.rowCount()
        self.quarantine_table.insertRow(row)
        
        # 1. ფაილის სახელი
        self.quarantine_table.setItem(row, 0, QTableWidgetItem(f"🔒 {filename}"))
        self.quarantine_table.item(row, 0).setData(Qt.UserRole, q_id)
        self.quarantine_table.item(row, 0).setTextAlignment(Qt.AlignCenter)
        
        
        score_item = QTableWidgetItem(str(score))
        score_item.setForeground(Qt.red)
        score_item.setTextAlignment(Qt.AlignCenter)
        self.quarantine_table.setItem(row, 1, score_item)
        
        
        action_widget = QWidget()
        action_layout = QHBoxLayout()
        action_layout.setContentsMargins(4, 2, 4, 2)
        action_layout.setSpacing(6)
        action_layout.setAlignment(Qt.AlignCenter)
        
        
        if self.user_role == "admin" or self.user_role is None:
          restore_btn = QPushButton("Restore")
          restore_btn.setFixedSize(65, 24)
          restore_btn.setStyleSheet("""
          QPushButton {
            background-color: #059669; color: white; border: none; 
            border-radius: 4px; font-size: 11px; font-weight: bold; font-family: 'Courier New';
            }
           QPushButton:hover { background-color: #047857; }
          """)
          restore_btn.clicked.connect(lambda _, q_id=q_id: self.restore_file_action(q_id))

          delete_btn = QPushButton("Delete")
          delete_btn.setFixedSize(65, 24)
          delete_btn.setStyleSheet("""
          QPushButton {
            background-color: #dc2626; color: white; border: none; 
            border-radius: 4px; font-size: 11px; font-weight: bold; font-family: 'Courier New';
           }
          QPushButton:hover { background-color: #b91c1c; }
          """)
          delete_btn.clicked.connect(lambda _, q_id=q_id: self.delete_file_action(q_id))

          action_layout.addWidget(restore_btn)
          action_layout.addWidget(delete_btn)
        else:
          locked = QLabel("Admin only")
          locked.setStyleSheet("color: #3a5068; font-size: 11px; font-family: 'Courier New';")
          action_layout.addWidget(locked)

        action_widget.setLayout(action_layout)
        self.quarantine_table.setCellWidget(row, 2, action_widget)


    def restore_file_action(self, q_id): 
        success, message = self.quarantine_manager.restore_from_quarantine(
        q_id, self.user_id, self.user_role
        )
        self.log_console.append(f"[{'+'  if success else '!'}] {message}")
        if success:
          self.remove_row_by_qid(q_id) 


    def delete_file_action(self, q_id):
       success, message = self.quarantine_manager.delete_from_quarantine(
        q_id, self.user_id, self.user_role
       )
       if success:
          self.log_console.append(f"[-] {message}")
          self.remove_row_by_qid(q_id)
       else:
          self.log_console.append(f"[!] {message}")

    
    def remove_row_by_qid(self, q_id):
        for row in range(self.quarantine_table.rowCount()):
            item = self.quarantine_table.item(row, 0)
            if item and item.data(Qt.UserRole) == q_id:
              self.quarantine_table.removeRow(row)
              break

    def load_quarantine_from_db(self):
        if hasattr(self, 'scan_title') and self.username:
           self.scan_title.setText(f"Welcome back, {self.username} 👋") 
           
        try:
           import database, sqlite3
           self.quarantine_table.setRowCount(0)
           with sqlite3.connect(database.DB_PATH) as conn: 
            if self.user_role == "admin" or self.user_role is None:             
              rows = conn.execute("""
                SELECT id, original_path, file_hash FROM quarantine
                ORDER BY quarantined_at DESC
               """).fetchall()
            else:
              rows = conn.execute("""
                    SELECT id, original_path, file_hash FROM quarantine
                    WHERE user_id = ?
                    ORDER BY quarantined_at DESC
                """, (self.user_id,)).fetchall()
            
            for q_id, original_path, file_hash in rows:
                filename = os.path.basename(original_path)
                score_row = conn.execute(
                    "SELECT scan_score FROM scanned_files WHERE file_hash = ? ORDER BY scanned_at DESC LIMIT 1",
                    (file_hash,)
                 ).fetchone()
                score = score_row[0] if score_row else 100
                self.add_to_quarantine_table(q_id, filename, score)
        except Exception as e:
          print(f"Quarantine load error: {e}")

    def handle_logout(self):
      from auth_window import AuthWindow
      from logs import AuditLogger
      import database
      AuditLogger(database.DB_PATH).log_event(self.user_id, "logged out", f"Session ended")
    
      self.user_id = None
      self.user_role = None
      self.username = None

      self.log_console.clear()
      self.path_input.clear()
      self.quarantine_table.setRowCount(0)
      if hasattr(self, 'logs_table'):
       self.logs_table.setRowCount(0)

      self.auth = AuthWindow(self)
      self.auth.show()
      self.close()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Escape:
            self.log_console.append("Shutdown signal intercepted via Escape key sequence")
            self.close()


