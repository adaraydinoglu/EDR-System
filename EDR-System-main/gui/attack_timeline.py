"""
gui/attack_timeline.py

Attack timeline view with:
  - Left pane: Incident list (grouped, named incidents)
  - Right pane: Full chain detail for selected incident
    (ancestry → trigger event → network → AI explanation)
"""
import datetime
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QListWidget, QListWidgetItem,
    QLabel, QSplitter, QTextEdit, QFrame, QScrollArea
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont

SEVERITY_FG = {
    "CRITICAL": "#ff3333",
    "HIGH":     "#ff9933",
    "MEDIUM":   "#cccc00",
    "LOW":      "#3399ff",
}
SEVERITY_ICON = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
}


def _ts(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S")


class AttackTimeline(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        # incident_id → {incident_dict, [alert_dicts]}
        self._incidents: dict = {}
        self._incident_order: list = []   # ordered list of incident_ids for display
        self._standalone_alerts: list = []
        self._setup_ui()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)

        hdr = QLabel("🛡️  Saldırı Zaman Çizelgesi — Olaylar & İncidentler")
        hdr.setStyleSheet("font-size: 15px; font-weight: bold; color: #a0c4ff; padding: 4px;")
        layout.addWidget(hdr)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: incident / alert list
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        lbl = QLabel("İncidentler / Alarmlar")
        lbl.setStyleSheet("font-weight: bold; color: #88aaff; padding: 2px 4px;")
        left_layout.addWidget(lbl)

        self.incident_list = QListWidget()
        self.incident_list.setStyleSheet("""
            QListWidget { background-color: #0d0f1a; border: 1px solid #1a1e30; }
            QListWidget::item { padding: 8px 6px; border-bottom: 1px solid #1a1e30; }
            QListWidget::item:selected { background-color: #1e2a4a; }
        """)
        self.incident_list.itemSelectionChanged.connect(self._on_selection_changed)
        left_layout.addWidget(self.incident_list)
        splitter.addWidget(left)

        # Right: chain detail
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        lbl2 = QLabel("Saldırı Zinciri Detayı")
        lbl2.setStyleSheet("font-weight: bold; color: #88aaff; padding: 2px 4px;")
        right_layout.addWidget(lbl2)

        self.detail_view = QTextEdit()
        self.detail_view.setReadOnly(True)
        self.detail_view.setStyleSheet("""
            QTextEdit {
                background-color: #0a0c16;
                color: #d0d8f0;
                font-family: 'Consolas', monospace;
                font-size: 12px;
                border: 1px solid #1a1e30;
            }
        """)
        right_layout.addWidget(self.detail_view)
        splitter.addWidget(right)

        splitter.setSizes([320, 680])
        layout.addWidget(splitter)

    # ── Ingest ────────────────────────────────────────────────────────────────

    def add_incident(self, incident_dict: dict):
        """Called by main_window when bridge.new_incident fires."""
        iid = incident_dict.get("incident_id", "")
        if not iid:
            return

        if iid not in self._incidents:
            self._incidents[iid] = {"meta": incident_dict, "alerts": []}
            self._incident_order.append(iid)
            self._add_incident_list_item(iid, incident_dict)
        else:
            # Update existing item
            self._incidents[iid]["meta"] = incident_dict
            self._refresh_incident_item(iid, incident_dict)

    def add_alert(self, alert_dict: dict):
        """Called by main_window for every alert — attach to incident or standalone."""
        iid = alert_dict.get("incident_id", "")
        if iid and iid in self._incidents:
            self._incidents[iid]["alerts"].append(alert_dict)
        else:
            # Standalone alert (no incident grouping — solo LOW/MEDIUM)
            self._standalone_alerts.append(alert_dict)
            self._add_standalone_list_item(alert_dict)

    # ── List population ───────────────────────────────────────────────────────

    def _add_incident_list_item(self, iid: str, meta: dict):
        sev  = meta.get("severity", "LOW")
        name = meta.get("incident_name", "Unknown Incident")
        icon = SEVERITY_ICON.get(sev, "")
        color = SEVERITY_FG.get(sev, "#ffffff")

        text = f"{icon}  {name}\n  ID: {iid}  |  {sev}"
        item = QListWidgetItem(text)
        item.setData(Qt.ItemDataRole.UserRole, ("incident", iid))
        item.setForeground(QColor(color))

        bold = QFont()
        bold.setBold(True)
        item.setFont(bold)

        self.incident_list.insertItem(0, item)  # newest on top

    def _refresh_incident_item(self, iid: str, meta: dict):
        for i in range(self.incident_list.count()):
            item = self.incident_list.item(i)
            if item and item.data(Qt.ItemDataRole.UserRole) == ("incident", iid):
                sev  = meta.get("severity", "LOW")
                name = meta.get("incident_name", "Unknown")
                cnt  = meta.get("alert_count", 0)
                icon = SEVERITY_ICON.get(sev, "")
                item.setText(f"{icon}  {name}\n  ID: {iid}  |  {sev}  |  {cnt} alarm")
                item.setForeground(QColor(SEVERITY_FG.get(sev, "#ffffff")))
                break

    def _add_standalone_list_item(self, alert_dict: dict):
        sev  = alert_dict.get("severity", "LOW")
        rule = alert_dict.get("rule_name", "Unknown")
        ts   = alert_dict.get("timestamp", 0)
        icon = SEVERITY_ICON.get(sev, "")
        color = SEVERITY_FG.get(sev, "#aaaaaa")

        text = f"{icon}  {rule}\n  {_ts(ts)}  |  {sev}"
        item = QListWidgetItem(text)
        item.setData(Qt.ItemDataRole.UserRole, ("alert", len(self._standalone_alerts) - 1))
        item.setForeground(QColor(color))
        self.incident_list.addItem(item)

    # ── Detail view ───────────────────────────────────────────────────────────

    def _on_selection_changed(self):
        selected = self.incident_list.selectedItems()
        if not selected:
            return
        kind, key = selected[0].data(Qt.ItemDataRole.UserRole)
        if kind == "incident":
            self._show_incident_detail(key)
        else:
            idx = key
            if 0 <= idx < len(self._standalone_alerts):
                self._show_alert_detail(self._standalone_alerts[idx])

    def _show_incident_detail(self, iid: str):
        data = self._incidents.get(iid)
        if not data:
            return
        meta   = data["meta"]
        alerts = data["alerts"]

        lines = []
        lines.append("=" * 70)
        lines.append(f"  İNCİDENT: {meta.get('incident_name', 'Unknown')}")
        lines.append(f"  ID: {iid}  |  Şiddet: {meta.get('severity', '?')}")
        lines.append("=" * 70)

        # Ancestry chain
        ancestry = meta.get("ancestry_chain", [])
        if ancestry:
            lines.append("")
            lines.append("🧬 SÜREÇ ZİNCİRİ:")
            chain_str = "  " + "  →  ".join(ancestry)
            lines.append(chain_str)

        # Tactics / MITRE
        tactics  = meta.get("tactics", [])
        mitres   = meta.get("mitre_ids", [])
        if tactics:
            lines.append(f"\n🎭 TAKTİKLER: {', '.join(tactics)}")
        if mitres:
            lines.append(f"🔗 MITRE IDs: {', '.join(mitres)}")

        # Network
        nets = meta.get("network_info", [])
        if nets:
            lines.append("\n🌐 AĞ BAĞLANTILARI:")
            for conn in (nets if isinstance(nets, list) else [nets]):
                ip   = conn.get("dst_ip", "?")
                port = conn.get("dst_port", "?")
                proto = conn.get("proto", "TCP")
                lines.append(f"  {proto}  →  {ip}:{port}")

        # Contributing alerts
        if alerts:
            lines.append(f"\n🚨 BAĞLI ALARMLAR ({len(alerts)}):")
            for i, a in enumerate(alerts, 1):
                ev  = a.get("trigger_event", {})
                proc = ev.get("process_name", "-")
                cmd  = ev.get("commandline", "")
                ts   = a.get("timestamp", 0)
                lines.append(f"\n  [{i}] {a.get('rule_name', '-')}  |  {a.get('severity', '-')}")
                lines.append(f"      Zaman  : {_ts(ts)}")
                lines.append(f"      Süreç  : {proc}")
                if cmd:
                    lines.append(f"      Komut  : {cmd[:100]}")
                ni = a.get("network_info", {})
                if ni and ni.get("dst_ip"):
                    lines.append(f"      Ağ     : {ni['dst_ip']}:{ni.get('dst_port', '')}")
                ai = a.get("ai_explanation", "")
                if ai:
                    lines.append(f"      🤖 AI  : {ai[:200]}")

        self.detail_view.setPlainText("\n".join(lines))

    def _show_alert_detail(self, alert: dict):
        ev  = alert.get("trigger_event", {})
        lines = []
        lines.append("=" * 70)
        lines.append(f"  ALARM: {alert.get('rule_name', '?')}")
        lines.append(f"  Şiddet: {alert.get('severity', '?')}  |  Güven: {alert.get('confidence', '?')}")
        lines.append("=" * 70)
        lines.append(f"\nTaktik : {alert.get('tactic', '-')}")
        lines.append(f"Teknik : {alert.get('technique_name', alert.get('technique', '-'))}")
        lines.append(f"MITRE  : {alert.get('mitre_id', '-')}")
        lines.append(f"\nSüreç  : {ev.get('process_name', '-')}")
        lines.append(f"PID    : {ev.get('pid', '-')}")
        lines.append(f"Komut  : {ev.get('commandline', '-')}")
        ancestry = alert.get("ancestry_chain", [])
        if ancestry:
            lines.append(f"\n🧬 Zincir: {' → '.join(ancestry)}")
        ni = alert.get("network_info", {})
        if ni and ni.get("dst_ip"):
            lines.append(f"\n🌐 Ağ: {ni['dst_ip']}:{ni.get('dst_port', '')}")
        ai = alert.get("ai_explanation", "")
        if ai:
            lines.append(f"\n🤖 AI Açıklama: {ai}")
        self.detail_view.setPlainText("\n".join(lines))
