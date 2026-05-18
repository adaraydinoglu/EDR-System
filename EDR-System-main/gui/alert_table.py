"""
gui/alert_table.py
Gerçek zamanlı alarm tablosu.
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QMenu, QDialog, QTextEdit, QLabel, QHBoxLayout, QPushButton
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont
from datetime import datetime

SEVERITY_BG = {
    "CRITICAL": QColor("#4a0000"),
    "HIGH":     QColor("#4a2800"),
    "MEDIUM":   QColor("#3a3200"),
    "LOW":      QColor("#0a2a0a"),
}
SEVERITY_TR = {
    "CRITICAL": "🔴 KRİTİK",
    "HIGH":     "🟠 YÜKSEK",
    "MEDIUM":   "🟡 ORTA",
    "LOW":      "🟢 DÜŞÜK",
}
COLUMNS = ["Zaman", "Kural Adı", "Şiddet", "Süreç", "MITRE ID", "Skor", "Aksiyon"]


class AlertDetailDialog(QDialog):
    def __init__(self, alert, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Alarm Detayı — {alert.rule_name}")
        self.setMinimumSize(650, 450)
        layout = QVBoxLayout(self)

        text = QTextEdit()
        text.setReadOnly(True)
        ev = alert.trigger_event
        pid_str  = str(ev.process_id.pid) if ev and ev.process_id else "-"
        path_str = ev.path    if ev else "-"
        cmd_str  = ev.cmdline if ev else "-"
        proc_str = ev.process_name if ev else "-"

        detail = (
            f"KURAL ADI       : {alert.rule_name}\n"
            f"ŞİDDET          : {alert.severity}\n"
            f"GÜVENİLİRLİK   : {alert.confidence}\n"
            f"TAKTİK          : {alert.tactic}\n"
            f"TEKNİK          : {alert.technique}\n"
            f"MITRE ID        : {alert.mitre_id}\n"
            f"KAYNAK          : {alert.source}\n"
            f"PUAN            : {alert.total_score}\n"
            f"AKSİYON         : {alert.response_action}\n"
            f"KORELASYON ID   : {alert.correlation_id}\n"
            f"\n--- HEDEF SÜREÇ ---\n"
            f"Süreç           : {proc_str}\n"
            f"PID             : {pid_str}\n"
            f"Komut Satırı    : {cmd_str}\n"
            f"Yol             : {path_str}\n"
            f"Ebeveyn Süreç   : {alert.parent_process}\n"
            f"\n--- SOY ZİNCİRİ ---\n"
            f"{' → '.join(alert.ancestry_chain) if alert.ancestry_chain else 'Bilinmiyor'}\n"
        )
        text.setPlainText(detail)
        layout.addWidget(text)

        close_btn = QPushButton("Kapat")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn, alignment=Qt.AlignmentFlag.AlignRight)


class AlertTable(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._alerts = []
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)

        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)
        self.table.doubleClicked.connect(lambda idx: self._show_detail(idx.row()))
        layout.addWidget(self.table)

    def add_alert(self, alert):
        self._alerts.append(alert)
        row = self.table.rowCount()
        self.table.insertRow(row)

        ev = alert.trigger_event
        proc = ev.process_name if ev else "-"
        time_str = datetime.fromtimestamp(alert.timestamp).strftime("%H:%M:%S")
        bg = SEVERITY_BG.get(alert.severity, QColor("#2a2a3e"))

        values = [
            time_str,
            alert.rule_name,
            SEVERITY_TR.get(alert.severity, alert.severity),
            proc,
            alert.mitre_id,
            str(alert.total_score),
            alert.response_action,
        ]
        bold_font = QFont()
        bold_font.setBold(True)

        for col, val in enumerate(values):
            item = QTableWidgetItem(val)
            item.setBackground(bg)
            item.setForeground(QColor("#ffffff"))
            if col == 2:
                item.setFont(bold_font)
            self.table.setItem(row, col, item)

        self.table.scrollToBottom()

    def _context_menu(self, pos):
        row = self.table.rowAt(pos.y())
        if row < 0:
            return
        menu = QMenu(self)
        menu.addAction("🔍 Detay Görüntüle").triggered.connect(lambda: self._show_detail(row))
        menu.addAction("❌ Süreci Sonlandır").triggered.connect(lambda: self._kill_process(row))
        menu.exec(self.table.viewport().mapToGlobal(pos))

    def _show_detail(self, row):
        if 0 <= row < len(self._alerts):
            AlertDetailDialog(self._alerts[row], self).exec()

    def _kill_process(self, row):
        if 0 <= row < len(self._alerts):
            alert = self._alerts[row]
            if alert.trigger_event and alert.trigger_event.process_id:
                pid = alert.trigger_event.process_id.pid
                try:
                    import psutil
                    psutil.Process(pid).kill()
                except Exception:
                    pass

    @property
    def count(self):
        return len(self._alerts)
