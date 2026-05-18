"""
gui/stats_widget.py
İstatistik / özet paneli.
"""
from collections import defaultdict
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QFrame, QGridLayout, QSizePolicy
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont


class StatCard(QFrame):
    """Büyük sayaç kartı."""

    def __init__(self, title: str, value: str = "0",
                 bg: str = "#1a237e", accent: str = "#5c9eff", parent=None):
        super().__init__(parent)
        self.setObjectName("statCard")
        self.setMinimumHeight(110)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setStyleSheet(
            f"QFrame#statCard {{ background-color: {bg}; border-radius: 10px;"
            f" border: 1px solid {accent}33; }}"
        )

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(4)

        self.value_lbl = QLabel(value)
        vfont = QFont("Segoe UI", 34, QFont.Weight.Bold)
        self.value_lbl.setFont(vfont)
        self.value_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.value_lbl.setStyleSheet(f"color: {accent}; background: transparent; border: none;")

        self.title_lbl = QLabel(title)
        tfont = QFont("Segoe UI", 11)
        self.title_lbl.setFont(tfont)
        self.title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title_lbl.setStyleSheet("color: rgba(255,255,255,0.65); background: transparent; border: none;")

        layout.addWidget(self.value_lbl)
        layout.addWidget(self.title_lbl)

    def set_value(self, val):
        self.value_lbl.setText(str(val))


class RuleRow(QWidget):
    def __init__(self, rule_name: str, count: int, parent=None):
        super().__init__(parent)
        row = QHBoxLayout(self)
        row.setContentsMargins(4, 2, 4, 2)

        name = QLabel(f"• {rule_name}")
        name.setStyleSheet("color: #c0c8e0; font-size: 12px; background: transparent;")

        self.count_lbl = QLabel(str(count))
        self.count_lbl.setStyleSheet(
            "color: #ff6b6b; font-weight: bold; font-size: 13px;"
            " min-width: 40px; background: transparent;"
        )
        self.count_lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        row.addWidget(name)
        row.addWidget(self.count_lbl)

    def update_count(self, val):
        self.count_lbl.setText(str(val))


class StatsWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._counters: dict = defaultdict(int)
        self._rule_rows: dict = {}
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        # ── Stat Cards ──────────────────────────────────
        grid = QGridLayout()
        grid.setSpacing(12)

        self.card_total    = StatCard("Toplam Alarm",  "0", "#12124a", "#6699ff")
        self.card_critical = StatCard("Kritik Alarm",  "0", "#3a0000", "#ff4444")
        self.card_high     = StatCard("Yüksek Alarm",  "0", "#3a1800", "#ff8844")
        self.card_events   = StatCard("Toplam Olay",   "0", "#0a2a0a", "#44cc88")
        self.card_procs    = StatCard("Aktif Süreçler", "0", "#2a0a2a", "#cc44cc")

        grid.addWidget(self.card_total,    0, 0)
        grid.addWidget(self.card_critical, 0, 1)
        grid.addWidget(self.card_high,     0, 2)
        grid.addWidget(self.card_events,   0, 3)
        grid.addWidget(self.card_procs,    0, 4)
        layout.addLayout(grid)

        # ── Top Rules ────────────────────────────────────
        section_lbl = QLabel("En Çok Tetiklenen Kurallar")
        section_lbl.setStyleSheet(
            "font-size: 14px; font-weight: bold; color: #a0c4ff; margin-top: 4px;"
        )
        layout.addWidget(section_lbl)

        self.rules_container = QVBoxLayout()
        self.rules_container.setSpacing(2)
        layout.addLayout(self.rules_container)

        layout.addStretch()

        self._active_pids = set()

    # ── Public slots ──────────────────────────────────────
    def on_alert(self, alert_dict):
        severity = alert_dict.get("severity", "MEDIUM")
        rule_name = alert_dict.get("rule_name", "Unknown")

        self._counters["total"] += 1
        self._counters[severity] += 1
        self._counters[f"rule__{rule_name}"] += 1

        self.card_total.set_value(self._counters["total"])
        self.card_critical.set_value(self._counters["CRITICAL"])
        self.card_high.set_value(self._counters["HIGH"])
        self._refresh_rule(rule_name)

    def on_event(self, event_dict):
        self._counters["events"] += 1
        self.card_events.set_value(self._counters["events"])

        # Track active processes based on PROCESS_CREATE and PROCESS_TERMINATE
        event_type = event_dict.get("event_type")
        details = event_dict.get("details", {})
        pid = event_dict.get("process_id", {}).get("pid") if event_dict.get("process_id") else None

        if pid:
            if event_type == 1: # EventType.PROCESS_CREATE
                self._active_pids.add(pid)
            elif event_type == 2: # EventType.PROCESS_TERMINATE
                self._active_pids.discard(pid)
            
            self.card_procs.set_value(len(self._active_pids))

    def _refresh_rule(self, rule_name: str):
        count = self._counters[f"rule__{rule_name}"]
        if rule_name in self._rule_rows:
            self._rule_rows[rule_name].update_count(count)
        else:
            row = RuleRow(rule_name, count)
            self._rule_rows[rule_name] = row
            self.rules_container.addWidget(row)
