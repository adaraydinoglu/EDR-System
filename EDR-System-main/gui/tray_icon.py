"""
gui/tray_icon.py
System Tray ikonu, bildirimler ve tray menüsü.
"""
from PyQt6.QtWidgets import QSystemTrayIcon, QMenu, QApplication
from PyQt6.QtGui import QIcon, QPixmap, QColor, QPainter, QBrush, QPolygonF
from PyQt6.QtCore import Qt, QPointF


def _make_shield_icon(color: str = "#e94560") -> QIcon:
    """Küçük bir kalkan ikonu üretir (harici dosyaya gerek yok)."""
    px = QPixmap(32, 32)
    px.fill(Qt.GlobalColor.transparent)
    painter = QPainter(px)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(QBrush(QColor(color)))
    painter.setPen(Qt.PenStyle.NoPen)
    shield = QPolygonF([
        QPointF(16, 2),
        QPointF(30, 8),
        QPointF(30, 20),
        QPointF(16, 30),
        QPointF(2, 20),
        QPointF(2, 8),
    ])
    painter.drawPolygon(shield)
    painter.end()
    return QIcon(px)


class TrayIcon(QSystemTrayIcon):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.setIcon(_make_shield_icon())
        self.setToolTip("🛡️ EDR Koruma Sistemi")

        menu = QMenu()
        show_act = menu.addAction("🖥️  Göster")
        show_act.triggered.connect(self._show_window)
        menu.addSeparator()
        quit_act = menu.addAction("❌  Çıkış")
        quit_act.triggered.connect(QApplication.quit)

        self.setContextMenu(menu)
        self.activated.connect(self._on_activated)
        self.show()

    def _show_window(self):
        self.main_window.show()
        self.main_window.raise_()
        self.main_window.activateWindow()

    def _on_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self._show_window()

    def notify_critical(self, rule_name: str, process_name: str):
        """CRITICAL alarm geldiğinde Windows bildirimi göster."""
        if self.isSystemTrayAvailable():
            self.showMessage(
                "🚨 KRİTİK ALARM TESPİT EDİLDİ",
                f"Kural : {rule_name}\nSüreç : {process_name}",
                QSystemTrayIcon.MessageIcon.Critical,
                6000,
            )
