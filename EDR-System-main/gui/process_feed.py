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
    EventType.PROCESS_CREATE:       "🟢",
    EventType.PROCESS_TERMINATE:    "🔴",
    EventType.FILE_CREATE:          "📄",
    EventType.FILE_MODIFY:          "✏️",
    EventType.FILE_DELETE:          "🗑️",
    EventType.NETWORK_CONNECT:      "🌐",
    EventType.TASK_CREATE:          "⏰",
    EventType.REGISTRY_MODIFY:      "🔧",
    EventType.PROCESS_ACCESS:       "👁️",
    EventType.CREATE_REMOTE_THREAD: "💉",
    EventType.DLL_LOAD:             "📦",
}

EVENT_COLORS = {
    EventType.CREATE_REMOTE_THREAD: "#ff6b6b",
    EventType.PROCESS_ACCESS:       "#ffa07a",
    EventType.NETWORK_CONNECT:      "#87ceeb",
    EventType.PROCESS_CREATE:       "#90ee90",
    EventType.PROCESS_TERMINATE:    "#ff8888",
    EventType.FILE_CREATE:          "#d8d8a0",
    EventType.TASK_CREATE:          "#ffcc44",
}

EVENT_NAMES_TR = {
    EventType.PROCESS_CREATE:       "Süreç Oluşturma",
    EventType.PROCESS_TERMINATE:    "Süreç Sonlandırma",
    EventType.FILE_CREATE:          "Dosya Oluşturma",
    EventType.FILE_MODIFY:          "Dosya Değiştirme",
    EventType.FILE_DELETE:          "Dosya Silme",
    EventType.NETWORK_CONNECT:      "Ağ Bağlantısı",
    EventType.TASK_CREATE:          "Görev Oluşturma",
    EventType.REGISTRY_MODIFY:      "Kayıt Değişikliği",
    EventType.PROCESS_ACCESS:       "Süreç Erişimi",
    EventType.CREATE_REMOTE_THREAD: "Uzak Thread Oluşturma",
    EventType.DLL_LOAD:             "DLL Yükleme",
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
        for et in EventType:
            self.filter_combo.addItem(EVENT_NAMES_TR.get(et, et.name), et)
        self.filter_combo.currentIndexChanged.connect(self._apply_filter)
        filter_row.addWidget(self.filter_combo)
        filter_row.addStretch()
        layout.addLayout(filter_row)

        self.list_widget = QListWidget()
        mono = QFont("Consolas", 10)
        self.list_widget.setFont(mono)
        layout.addWidget(self.list_widget)

    def add_event(self, event):
        self._all_events.append(event)
        if len(self._all_events) > MAX_ITEMS:
            self._all_events.pop(0)

        current_filter = self.filter_combo.currentData()
        if current_filter is None or event.event_type == current_filter:
            self._add_item_to_list(event)

    def _add_item_to_list(self, event):
        if self.list_widget.count() >= MAX_ITEMS:
            self.list_widget.takeItem(0)

        time_str  = datetime.fromtimestamp(event.timestamp).strftime("%H:%M:%S")
        icon      = EVENT_ICONS.get(event.event_type, "•")
        type_name = EVENT_NAMES_TR.get(event.event_type, event.event_type.name)
        proc      = event.process_name or "-"

        text = f"{time_str}  {icon}  {type_name:<25}  {proc}"
        item = QListWidgetItem(text)
        color = EVENT_COLORS.get(event.event_type, "#a0a0b0")
        item.setForeground(QColor(color))
        self.list_widget.addItem(item)
        self.list_widget.scrollToBottom()

    def _apply_filter(self):
        self.list_widget.clear()
        current_filter = self.filter_combo.currentData()
        for event in self._all_events:
            if current_filter is None or event.event_type == current_filter:
                self._add_item_to_list(event)
