"""
gui/process_feed.py
Canlı süreç / olay akışı widget'ı.
"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QListWidget, QListWidgetItem, QComboBox, QLabel
)
from PyQt6.QtGui import QColor, QFont
from models.event_schema import EventType
from datetime import datetime

MAX_ITEMS = 500

EVENT_ICONS = {
    "process_create":       "🟢",
    "process_terminate":    "🔴",
    "file_create":          "📄",
    "file_modify":          "✏️",
    "file_delete":          "🗑️",
    "network_connect":      "🌐",
    "task_create":          "⏰",
    "registry_modify":      "🔧",
    "process_access":       "👁️",
    "create_remote_thread": "💉",
    "dll_load":             "📦",
}

EVENT_COLORS = {
    "create_remote_thread": "#ff6b6b",
    "process_access":       "#ffa07a",
    "network_connect":      "#87ceeb",
    "process_create":       "#90ee90",
    "process_terminate":    "#ff8888",
    "file_create":          "#d8d8a0",
    "task_create":          "#ffcc44",
}

EVENT_NAMES_TR = {
    "process_create":       "Süreç Oluşturma",
    "process_terminate":    "Süreç Sonlandırma",
    "file_create":          "Dosya Oluşturma",
    "file_modify":          "Dosya Değiştirme",
    "file_delete":          "Dosya Silme",
    "network_connect":      "Ağ Bağlantısı",
    "task_create":          "Görev Oluşturma",
    "registry_modify":      "Kayıt Değişikliği",
    "process_access":       "Süreç Erişimi",
    "create_remote_thread": "Uzak Thread Oluşturma",
    "dll_load":             "DLL Yükleme",
}


class ProcessFeed(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._all_events = []
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        # Filter row
        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Olay Filtresi:"))
        self.filter_combo = QComboBox()
        self.filter_combo.addItem("Tümü", None)
        for et in EVENT_NAMES_TR.keys():
            self.filter_combo.addItem(EVENT_NAMES_TR.get(et, et), et)
        self.filter_combo.currentIndexChanged.connect(self._apply_filter)
        filter_row.addWidget(self.filter_combo)
        filter_row.addStretch()
        layout.addLayout(filter_row)

        self.list_widget = QListWidget()
        mono = QFont("Consolas", 10)
        self.list_widget.setFont(mono)
        layout.addWidget(self.list_widget)

    def add_event(self, event_dict):
        self._all_events.append(event_dict)
        if len(self._all_events) > MAX_ITEMS:
            self._all_events.pop(0)

        current_filter = self.filter_combo.currentData()
        event_type = event_dict.get("event_type", "")
        if current_filter is None or event_type == current_filter:
            self._add_item_to_list(event_dict)

    def _add_item_to_list(self, event_dict):
        if self.list_widget.count() >= MAX_ITEMS:
            self.list_widget.takeItem(0)

        event_type = event_dict.get("event_type", "")
        timestamp = event_dict.get("timestamp", 0)
        time_str  = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S")
        icon      = EVENT_ICONS.get(event_type, "•")
        type_name = EVENT_NAMES_TR.get(event_type, event_type)
        proc      = event_dict.get("process_name", "-") or "-"

        text = f"{time_str}  {icon}  {type_name:<25}  {proc}"
        item = QListWidgetItem(text)
        color = EVENT_COLORS.get(event_type, "#a0a0b0")
        item.setForeground(QColor(color))
        self.list_widget.addItem(item)
        self.list_widget.scrollToBottom()

    def _apply_filter(self):
        self.list_widget.clear()
        current_filter = self.filter_combo.currentData()
        for event_dict in self._all_events:
            event_type = event_dict.get("event_type", "")
            if current_filter is None or event_type == current_filter:
                self._add_item_to_list(event_dict)
