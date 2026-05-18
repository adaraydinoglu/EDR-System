"""
gui/process_tree.py

Hierarchical process tree that polls ProcessTreeTracker every 2 seconds
for a full snapshot rather than relying solely on the event stream.
Features:
  - Full parent → child hierarchy
  - Network activity column (dst IP:port)
  - Severity badge on flagged processes
  - Text search with parent expansion
"""
import datetime
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QTreeWidget, QTreeWidgetItem,
    QLineEdit, QHBoxLayout, QLabel, QPushButton
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QFont, QBrush

# Severity → row foreground colour
SEVERITY_FG = {
    "CRITICAL": QColor("#ff3333"),
    "HIGH":     QColor("#ff9933"),
    "MEDIUM":   QColor("#ffff33"),
    "LOW":      QColor("#3399ff"),
    "":         QColor("#cccccc"),
}

SEVERITY_ICON = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "":         "",
}

COLUMNS = ["Süreç / Olay", "PID", "Komut Satırı", "Ağ Bağlantısı", "Durum", "Şiddet"]


class ProcessTree(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._nodes = {}          # str(pid) → QTreeWidgetItem
        self._snapshot: list = [] # latest data from tracker
        self._setup_ui()
        self._start_poll_timer()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        # Header
        hdr = QLabel("🌳 Süreç Ağacı — Canlı Görünüm")
        hdr.setStyleSheet("font-size: 15px; font-weight: bold; color: #a0c4ff;")
        layout.addWidget(hdr)

        # Filter bar
        filter_row = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Süreç adı veya PID ara...")
        self.search_input.textChanged.connect(self._apply_filter)

        self.expand_btn = QPushButton("Tümünü Genişlet")
        self.expand_btn.clicked.connect(self.tree.expandAll if hasattr(self, "tree") else lambda: None)

        filter_row.addWidget(QLabel("🔍"))
        filter_row.addWidget(self.search_input)
        filter_row.addWidget(self.expand_btn)
        layout.addLayout(filter_row)

        # Tree widget
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(COLUMNS)
        self.tree.header().setStretchLastSection(False)
        self.tree.setColumnWidth(0, 220)
        self.tree.setColumnWidth(1, 60)
        self.tree.setColumnWidth(2, 320)
        self.tree.setColumnWidth(3, 160)
        self.tree.setColumnWidth(4, 80)
        self.tree.setColumnWidth(5, 80)
        self.tree.setAlternatingRowColors(True)
        layout.addWidget(self.tree)

        # Wire expand button now that tree exists
        self.expand_btn.clicked.disconnect()
        self.expand_btn.clicked.connect(self.tree.expandAll)

    # ── Polling ───────────────────────────────────────────────────────────────

    def _start_poll_timer(self):
        self._timer = QTimer(self)
        self._timer.setInterval(2000)  # 2-second refresh
        self._timer.timeout.connect(self._poll_snapshot)
        self._timer.start()

    def _poll_snapshot(self):
        """Fetch latest snapshot from backend and refresh the tree."""
        try:
            from core.process_tree_tracker import process_tree_tracker
            snapshot = process_tree_tracker.get_tree_snapshot()
            self._snapshot = snapshot
            self._rebuild_tree(snapshot)
        except Exception:
            pass  # backend not yet running — silent

    # ── Tree Build ────────────────────────────────────────────────────────────

    def _rebuild_tree(self, snapshot: list):
        """Diff and update the tree; avoid full clear to reduce flicker."""
        existing_pids = set(self._nodes.keys())
        new_pids      = {str(n["pid"]) for n in snapshot}

        # Remove nodes that disappeared (shouldn't happen often)
        for pid_str in existing_pids - new_pids:
            item = self._nodes.pop(pid_str, None)
            if item:
                parent = item.parent() or self.tree.invisibleRootItem()
                parent.removeChild(item)

        pid_map = {str(n["pid"]): n for n in snapshot}

        # Add or update nodes
        for node_data in snapshot:
            pid_str    = str(node_data["pid"])
            parent_pid = str(node_data["parent_pid"]) if node_data["parent_pid"] else None

            if pid_str not in self._nodes:
                # Determine parent item
                parent_item = self.tree.invisibleRootItem()
                if parent_pid and parent_pid in self._nodes:
                    parent_item = self._nodes[parent_pid]

                item = QTreeWidgetItem(parent_item)
                self._nodes[pid_str] = item
                if parent_item != self.tree.invisibleRootItem():
                    parent_item.setExpanded(True)

            self._update_item(self._nodes[pid_str], node_data)

    def _update_item(self, item: QTreeWidgetItem, data: dict):
        """Populate / refresh a single tree row from snapshot data."""
        name    = data["name"]
        pid     = str(data["pid"])
        cmdline = data.get("cmdline", "")
        sev     = data.get("highest_severity", "")
        status  = "Aktif" if data.get("status") == "running" else "Sonlandı"

        # Network: pick first connection if any
        conns = data.get("network_connections", [])
        net_str = ""
        if conns:
            latest = conns[-1]
            ip   = latest.get("dst_ip", "")
            port = latest.get("dst_port", "")
            if ip:
                net_str = f"{ip}:{port}" if port else ip

        # Icon
        sev_icon = SEVERITY_ICON.get(sev, "")
        prefix   = "⚪ " if status == "Sonlandı" else ("🟢 " if not sev else f"{sev_icon} ")

        item.setText(0, f"{prefix}{name}")
        item.setText(1, pid)
        item.setText(2, cmdline[:120])
        item.setText(3, net_str)
        item.setText(4, status)
        item.setText(5, sev)

        # Colour coding
        fg = SEVERITY_FG.get(sev, QColor("#cccccc"))
        if status == "Sonlandı":
            fg = QColor("#666666")
        for col in range(6):
            item.setForeground(col, fg)

    # ── Event stream (fallback for when tracker not ready) ────────────────────

    def add_event(self, event_dict):
        """
        Still called by main_window for immediate responsiveness.
        The polling timer will later reconcile with the full snapshot.
        """
        event_type = event_dict.get("event_type")
        if event_type not in ("process_create", "process_terminate"):
            return

        pid = event_dict.get("pid") or (
            event_dict.get("process_id", {}) or {}
        ).get("pid")
        if not pid:
            return

        pid_str   = str(pid)
        proc_name = event_dict.get("process_name", "Bilinmiyor")

        if event_type == "process_create" and pid_str not in self._nodes:
            parent_pid = str(event_dict.get("parent_pid", ""))
            parent_item = self._nodes.get(parent_pid, self.tree.invisibleRootItem())
            item = QTreeWidgetItem(parent_item)
            item.setText(0, f"🟢 {proc_name}")
            item.setText(1, pid_str)
            item.setText(2, event_dict.get("commandline", ""))
            item.setText(4, "Aktif")
            if parent_item != self.tree.invisibleRootItem():
                parent_item.setExpanded(True)
            self._nodes[pid_str] = item

        elif event_type == "process_terminate" and pid_str in self._nodes:
            item = self._nodes[pid_str]
            item.setText(0, f"⚪ {proc_name}")
            item.setText(4, "Sonlandı")
            for col in range(6):
                item.setForeground(col, QColor("#666666"))

    # ── Filter ────────────────────────────────────────────────────────────────

    def _apply_filter(self):
        text = self.search_input.text().lower()
        if not text:
            for node in self._nodes.values():
                node.setHidden(False)
            return

        for node in self._nodes.values():
            node.setHidden(True)

        for node in self._nodes.values():
            if text in node.text(0).lower() or text in node.text(1):
                node.setHidden(False)
                parent = node.parent()
                while parent:
                    parent.setHidden(False)
                    parent.setExpanded(True)
                    parent = parent.parent()
