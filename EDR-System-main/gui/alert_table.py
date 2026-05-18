"""
gui/alert_table.py
Gerçek zamanlı alarm tablosu.
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QMenu, QDialog, QTextEdit, QLabel, QHBoxLayout, QPushButton,
    QLineEdit, QComboBox
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont
from datetime import datetime

# LOW = blue, MEDIUM = yellow, HIGH = orange, CRITICAL = red
SEVERITY_BG = {
    "CRITICAL": QColor("#cc0000"), # Red
    "HIGH":     QColor("#ff8800"), # Orange
    "MEDIUM":   QColor("#cccc00"), # Yellow
    "LOW":      QColor("#0044cc"), # Blue
}
SEVERITY_TR = {
    "CRITICAL": "🔴 KRİTİK",
    "HIGH":     "🟠 YÜKSEK",
    "MEDIUM":   "🟡 ORTA",
    "LOW":      "🔵 DÜŞÜK",
}
COLUMNS = ["Zaman", "İncident Adı", "Şiddet", "Root PID", "Alarm Sayısı", "Kök Süreç", "Aksiyon"]


class IncidentDetailDialog(QDialog):
    def __init__(self, incident_dict, parent=None):
        super().__init__(parent)
        name = incident_dict.get('incident_name', 'Bilinmeyen İncident')
        self.setWindowTitle(f"İncident Detayı — {name}")
        self.setMinimumSize(700, 500)
        layout = QVBoxLayout(self)

        text = QTextEdit()
        text.setReadOnly(True)
        
        ancestry = incident_dict.get("ancestry_chain", [])
        tactics = incident_dict.get("tactics", [])
        mitre_ids = incident_dict.get("mitre_ids", [])
        network_info = incident_dict.get("network_info", [])
        
        detail = (
            f"İNCİDENT ADI    : {name}\n"
            f"İNCİDENT ID     : {incident_dict.get('incident_id', '-')}\n"
            f"ŞİDDET          : {incident_dict.get('severity', '-')}\n"
            f"ROOT PID        : {incident_dict.get('root_pid', '-')}\n"
            f"ALARM SAYISI    : {incident_dict.get('alert_count', 0)}\n"
            f"TETİKLENEN KURAL: {', '.join(incident_dict.get('rule_hits', []))}\n"
            f"TAKTİKLER       : {', '.join(tactics) if tactics else '-'}\n"
            f"MITRE ID'LER    : {', '.join(mitre_ids) if mitre_ids else '-'}\n"
            f"\n--- SÜREÇ ZİNCİRİ ---\n"
            f"{' → '.join(ancestry) if ancestry else 'Bilinmiyor'}\n"
            f"\n--- AĞ BAĞLANTILARI ---\n"
        )
        
        if network_info:
            for net in network_info:
                ip = net.get("dst_ip", "?")
                port = net.get("dst_port", "?")
                proto = net.get("proto", "TCP")
                detail += f"  {proto} → {ip}:{port}\n"
        else:
            detail += "  Tespit edilmedi.\n"
            
        text.setPlainText(detail)
        layout.addWidget(text)

        close_btn = QPushButton("Kapat")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn, alignment=Qt.AlignmentFlag.AlignRight)


class AlertTable(QWidget):
    """
    Shows incidents (aggregated alerts). Retains the class name AlertTable for compatibility
    with main_window, but functionally displays Incidents.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self._incidents = {}  # incident_id -> incident_dict
        self._incident_order = []  # To maintain chronological order
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        
        # ── Filtre Çubuğu ──────────────────────────────────────────────
        filter_layout = QHBoxLayout()
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("İncident, süreç veya kural ara...")
        self.search_input.textChanged.connect(self._apply_filters)
        
        self.severity_combo = QComboBox()
        self.severity_combo.addItem("Tüm Şiddetler", "")
        self.severity_combo.addItem("🔴 KRİTİK", "CRITICAL")
        self.severity_combo.addItem("🟠 YÜKSEK", "HIGH")
        self.severity_combo.addItem("🟡 ORTA", "MEDIUM")
        self.severity_combo.addItem("🔵 DÜŞÜK", "LOW")
        self.severity_combo.currentIndexChanged.connect(self._apply_filters)
        
        filter_layout.addWidget(QLabel("🔍 Ara:"))
        filter_layout.addWidget(self.search_input)
        filter_layout.addSpacing(20)
        filter_layout.addWidget(QLabel("⚠️ Şiddet:"))
        filter_layout.addWidget(self.severity_combo)
        
        layout.addLayout(filter_layout)

        # ── Tablo ──────────────────────────────────────────────────────
        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)
        self.table.doubleClicked.connect(lambda idx: self._show_detail(idx.row()))
        layout.addWidget(self.table)

    def add_incident(self, incident_dict):
        iid = incident_dict.get("incident_id")
        if not iid:
            return
            
        if iid not in self._incidents:
            self._incident_order.append(iid)
            
        self._incidents[iid] = incident_dict
        self._refresh_table()

    def _refresh_table(self):
        self.table.setRowCount(0)
        search_text = self.search_input.text().lower()
        severity_filter = self.severity_combo.currentData()
        
        for iid in self._incident_order:
            incident = self._incidents[iid]
            
            # Apply filters
            name = incident.get("incident_name", "").lower()
            ancestry = " ".join(incident.get("ancestry_chain", [])).lower()
            rules = " ".join(incident.get("rule_hits", [])).lower()
            severity = incident.get("severity", "")
            
            if severity_filter and severity != severity_filter:
                continue
                
            if search_text and search_text not in name and search_text not in ancestry and search_text not in rules:
                continue

            # Add to table
            row = self.table.rowCount()
            self.table.insertRow(row)
            
            timestamp = incident.get("last_seen", 0)
            time_str = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S")
            bg = SEVERITY_BG.get(severity, QColor("#2a2a3e"))
            
            root_proc = incident.get("ancestry_chain", ["Bilinmiyor"])[0]

            values = [
                time_str,
                incident.get("incident_name", "-"),
                SEVERITY_TR.get(severity, severity),
                str(incident.get("root_pid", "-")),
                str(incident.get("alert_count", 0)),
                root_proc,
                "İncele",
            ]
            
            bold_font = QFont()
            bold_font.setBold(True)

            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                item.setBackground(bg)
                item.setForeground(QColor("#ffffff") if severity != "MEDIUM" else QColor("#000000"))
                if col == 0:
                    item.setData(Qt.ItemDataRole.UserRole, iid) # Store incident ID
                if col == 2:
                    item.setFont(bold_font)
                self.table.setItem(row, col, item)

        self.table.scrollToBottom()
        
    def _apply_filters(self):
        self._refresh_table()

    def _context_menu(self, pos):
        row = self.table.rowAt(pos.y())
        if row < 0:
            return
        menu = QMenu(self)
        menu.addAction("🔍 Detay Görüntüle").triggered.connect(lambda: self._show_detail(row))
        menu.addAction("❌ Kök Süreci Sonlandır").triggered.connect(lambda: self._kill_process(row))
        menu.exec(self.table.viewport().mapToGlobal(pos))

    def _show_detail(self, row):
        if row >= 0:
            item = self.table.item(row, 0)
            if item:
                iid = item.data(Qt.ItemDataRole.UserRole)
                if iid in self._incidents:
                    IncidentDetailDialog(self._incidents[iid], self).exec()

    def _kill_process(self, row):
        if row >= 0:
            item = self.table.item(row, 0)
            if item:
                iid = item.data(Qt.ItemDataRole.UserRole)
                if iid in self._incidents:
                    incident = self._incidents[iid]
                    pid = incident.get("root_pid")
                    if pid:
                        try:
                            import psutil
                            psutil.Process(pid).kill()
                        except Exception:
                            pass

    @property
    def count(self):
        return len(self._incidents)
