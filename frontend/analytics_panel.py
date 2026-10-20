import sys
import numpy as np
from PyQt5.QtWidgets import QFrame, QVBoxLayout, QHBoxLayout, QLabel, QApplication, QWidget
from matplotlib.figure import Figure
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from backend.analytics import get_scan_stats, get_summary_counts


BG_DARK = "#0a0e1a"
CARD_DARK = "#0f1729"
BORDER_DARK = "#1e293b"
TEXT_LIGHT = "#e2e8f0"
TEXT_MUTED = "#64748b"
ACCENT_CYAN = "#38bdf8"


class AnalyticsPanel(QFrame):
    def __init__(self, db_path, user_id, user_role):
        super().__init__()
        self.db_path = db_path
        self.user_id = user_id
        self.user_role = user_role

        self.stats_data = get_scan_stats(db_path, user_id, user_role)
        self.summary = get_summary_counts(db_path, user_id, user_role)
        self.init_ui()

    def init_ui(self):
        self.setStyleSheet(f"background-color: {BG_DARK};")
        outer_layout = QVBoxLayout()
        outer_layout.setContentsMargins(30, 25, 30, 25)
        outer_layout.setSpacing(20)

        heading = QLabel("Analytics")
        heading.setStyleSheet(f"font-size: 22px; font-weight: bold; color: {TEXT_LIGHT};")
        outer_layout.addWidget(heading)

        stats_row = QHBoxLayout()
        stats_row.addWidget(self.build_stat_card("Threats Detected", self.summary["threats"], "#ef4444"))
        stats_row.addWidget(self.build_stat_card("Files Scanned", self.summary["scanned"], ACCENT_CYAN))
        stats_row.addWidget(self.build_stat_card("Files Deleted", self.summary["deleted"], "#f97316"))
        stats_row.addWidget(self.build_stat_card("Files Restored", self.summary["restored"], "#22c55e"))
        outer_layout.addLayout(stats_row)

        bottom_row = QHBoxLayout()
        bottom_row.addWidget(self.build_card("Scans per Day", self.build_line_chart()))
        bottom_row.addWidget(self.build_card("Protection Status", self.build_donut()))
        outer_layout.addLayout(bottom_row)

        outer_layout.addStretch(1)
        self.setLayout(outer_layout)

    def build_stat_card(self, label_text, value, color):
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background-color: {CARD_DARK};
                border: 1px solid {BORDER_DARK};
                border-radius: 12px;
            }}
        """)
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)

        label = QLabel(label_text)
        label.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 13px; font-weight: 500;")

        number = QLabel(str(value))
        number.setStyleSheet(f"color: {color}; font-size: 28px; font-weight: bold;")

        layout.addWidget(label)
        layout.addWidget(number)
        card.setLayout(layout)
        return card

    def build_card(self, title_text, chart_widget): 
        card = QFrame()
        card.setMinimumHeight(500)
        card.setStyleSheet(f"""
            QFrame {{
                background-color: {CARD_DARK};
                border: 1px solid {BORDER_DARK};
                border-radius: 12px;
            }}
        """)
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel(title_text)
        title.setStyleSheet(f"font-size: 16px; font-weight: bold; color: {TEXT_LIGHT}; padding-bottom: 5px;")

        layout.addWidget(title)
        layout.addWidget(chart_widget)
        layout.addStretch()
        card.setLayout(layout)
        return card

    def build_line_chart(self):  
        fig = Figure(figsize=(6, 4.5), facecolor=CARD_DARK, layout='constrained')
        ax = fig.add_subplot(111)
        ax.set_facecolor(CARD_DARK)

        daily = self.stats_data.get("daily_counts", {})

        if daily and any(daily.values()):
            x_labels = list(daily.keys())
            y_values = list(daily.values())
            x_indices = np.arange(len(x_labels))

            ax.plot(x_indices, y_values, marker='o', color=ACCENT_CYAN, linewidth=2, markersize=6)

            ax.set_xticks(x_indices)
            ax.set_xticklabels(x_labels)
            ax.grid(True, axis='y', linestyle='-', linewidth=0.5, color=BORDER_DARK)

            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)

            y_max = max(y_values)
            y_max = max(y_max, 5)

            ax.set_ylim(0, y_max * 1.1)
            ax.spines['bottom'].set_bounds(0, len(x_labels) - 1)
            ax.spines['left'].set_bounds(0, y_max)

            ax.spines['bottom'].set_color(BORDER_DARK)
            ax.spines['left'].set_color(BORDER_DARK)
            ax.tick_params(colors=TEXT_MUTED, labelsize=9, pad=6)
        else:
            ax.text(0.5, 0.5, "No data available for the last 7 days", ha='center', va='center', color=TEXT_MUTED)
            ax.axis('off')

        return FigureCanvas(fig)

    def build_donut(self):
        fig = Figure(figsize=(4, 4.5), facecolor=CARD_DARK, layout='constrained')
        ax = fig.add_subplot(111)
        ax.set_facecolor(CARD_DARK)

        breakdown = self.stats_data.get("status_breakdown", {})
        safe = breakdown.get("safe", 0)
        at_risk = sum(breakdown.get(k, 0) for k in ("suspicious", "dangerous", "fatal"))
        total = safe + at_risk

        if total == 0:
            ax.text(0.5, 0.5, "No data yet", ha='center', va='center', color=TEXT_MUTED)
            ax.axis('off')
            return FigureCanvas(fig)

        pie_colors = ['#22c55e', '#ef4444' if at_risk > 0 else BORDER_DARK]

        ax.pie([safe, at_risk], colors=pie_colors, startangle=90, counterclock=False,
               wedgeprops=dict(width=0.25, edgecolor=CARD_DARK, linewidth=2))

        pct = (safe / total) * 100
        ax.text(0, 0.05, f"{pct:.0f}%", ha='center', va='center', fontsize=24, fontweight='bold', color=TEXT_LIGHT)
        ax.text(0, -0.18, "Protected", ha='center', va='center', fontsize=10, fontweight='medium', color=TEXT_MUTED)
        ax.axis('off')

        return FigureCanvas(fig)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    DB_PATH = "antivirus.db"
    window = AnalyticsPanel(DB_PATH, user_id=1, user_role="admin")
    window.resize(1150, 600)
    window.show()
    sys.exit(app.exec_())