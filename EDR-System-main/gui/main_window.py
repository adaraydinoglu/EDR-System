"""
gui/main_window.py
Ana pencere: Backend kontrolü + sekmeli görünüm.
"""
import threading
from datetime import datetime

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QPushButton, QLabel, QStatusBar, QSizePolicy
)
from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtGui import QFont, QCloseEvent

from gui.alert_table import AlertTable
from gui.process_feed import ProcessFeed
from gui.stats_widget import StatsWidget
from gui.tray_icon import TrayIcon
from gui.bridge import bridge
from gui.styles import DARK_STYLE
from core.logger import logger


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self._backend_running = False
        self._backend_thread: threading.Thread | None = None
        self._alert_count = 0
        self._event_count = 0

        self.setWindowTitle("🛡️  EDR Koruma Sistemi")
        self.setMinimumSize(1150, 720)
        self.setStyleSheet(DARK_STYLE)

        self._build_ui()
        self._connect_bridge()

        # System tray (pencere kapatılınca arka planda kalır)
        self.tray = TrayIcon(self)

    # ─────────────────────────────────────────────────────
    # UI İnşa
    # ─────────────────────────────────────────────────────
    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # ── Başlık / Kontrol Çubuğu ──────────────────────
        header = QWidget()
        header.setStyleSheet("background-color: #16213e; border-bottom: 1px solid #2a2a4e;")
        header.setFixedHeight(60)
        h_layout = QHBoxLayout(header)
        h_layout.setContentsMargins(16, 0, 16, 0)

        title_lbl = QLabel("🛡️  EDR Koruma Sistemi")
        title_lbl.setObjectName("headerLabel")
        title_font = QFont("Segoe UI", 16, QFont.Weight.Bold)
        title_lbl.setFont(title_font)

        self.status_dot = QLabel("⚫")
        self.status_dot.setObjectName("statusDot")
        self.status_dot.setToolTip("Sistem durumu")

        self.status_text = QLabel("Durduruldu")
        self.status_text.setStyleSheet("color: #888899; font-size: 13px;")

        self.start_btn = QPushButton("▶  Başlat")
        self.start_btn.setObjectName("startButton")
        self.start_btn.clicked.connect(self._start_backend)

        self.stop_btn = QPushButton("■  Durdur")
        self.stop_btn.setObjectName("stopButton")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_backend)

        h_layout.addWidget(title_lbl)
        h_layout.addStretch()
        h_layout.addWidget(self.status_dot)
        h_layout.addWidget(self.status_text)
        h_layout.addSpacing(16)
        h_layout.addWidget(self.start_btn)
        h_layout.addWidget(self.stop_btn)

        root_layout.addWidget(header)

        # ── Sekmeler ─────────────────────────────────────
        self.tabs = QTabWidget()

        self.alert_tab   = AlertTable()
        self.process_tab = ProcessFeed()
        self.stats_tab   = StatsWidget()

        self.tabs.addTab(self.alert_tab,   "🔴  Alarmlar")
        self.tabs.addTab(self.process_tab, "📋  Süreç Akışı")
        self.tabs.addTab(self.stats_tab,   "📊  İstatistikler")

        root_layout.addWidget(self.tabs)

        # ── Durum Çubuğu ─────────────────────────────────
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self._sb_label = QLabel("Hazır  |  Alarm: 0  |  Olay: 0")
        self._sb_label.setStyleSheet("color: #6688aa; padding: 2px 8px;")
        self.status_bar.addWidget(self._sb_label)

    # ─────────────────────────────────────────────────────
    # Bridge Bağlantıları
    # ─────────────────────────────────────────────────────
    def _connect_bridge(self):
        bridge.new_alert.connect(self._on_alert)
        bridge.new_event.connect(self._on_event)

    @pyqtSlot(object)
    def _on_alert(self, alert):
        self._alert_count += 1
        self.alert_tab.add_alert(alert)
        self.stats_tab.on_alert(alert)
        self._update_status_bar()

        # Alarm sekmesini ışıldatmak için başlığı güncelle
        self.tabs.setTabText(0, f"🔴  Alarmlar ({self._alert_count})")

        # CRITICAL ise bildirim gönder
        if alert.severity == "CRITICAL":
            proc = alert.trigger_event.process_name if alert.trigger_event else "-"
            self.tray.notify_critical(alert.rule_name, proc)

    @pyqtSlot(object)
    def _on_event(self, event):
        self._event_count += 1
        self.process_tab.add_event(event)
        self.stats_tab.on_event()
        self._update_status_bar()

    def _update_status_bar(self):
        now = datetime.now().strftime("%H:%M:%S")
        self._sb_label.setText(
            f"Son Olay: {now}  |  Alarm: {self._alert_count}  |  Olay: {self._event_count}"
        )

    # ─────────────────────────────────────────────────────
    # Backend Kontrolü
    # ─────────────────────────────────────────────────────
    def _start_backend(self):
        if self._backend_running:
            return
        self._backend_running = True
        self._backend_thread = threading.Thread(
            target=self._run_backend, daemon=True, name="EDR-Backend"
        )
        self._backend_thread.start()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_dot.setText("🟢")
        self.status_text.setText("Aktif")
        self.status_text.setStyleSheet("color: #44cc88; font-size: 13px;")
        logger.info("GUI: Backend başlatıldı.")

    def _stop_backend(self):
        self._backend_running = False
        self._set_stopped_ui()
        logger.info("GUI: Backend durduruldu.")

        try:
            from core.event_bus import event_bus
            event_bus.stop()
        except Exception:
            pass
        try:
            from core.cleanup_manager import cleanup_manager
            cleanup_manager.stop()
        except Exception:
            pass

    def _set_stopped_ui(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_dot.setText("🔴")
        self.status_text.setText("Durduruldu")
        self.status_text.setStyleSheet("color: #cc4444; font-size: 13px;")

    def _run_backend(self):
        """Backend iş mantığı — ana thread dışı bir thread'de çalışır."""
        try:
            from core.event_bus import event_bus
            from core.cleanup_manager import cleanup_manager
            from detection.sigma_engine import SigmaEngine
            from detection.engine import DetectionEngine
            from response.responder import Responder
            from collectors.wmi_monitor import wmi_monitor
            from collectors.filesystem_monitor import filesystem_monitor
            from collectors.task_monitor import task_monitor
            from collectors.sysmon_monitor import sysmon_monitor
            from collectors.network_monitor import network_monitor
            from config import WATCHDOG_INTERVAL
            import time

            # 1. EventBus + Bridge
            event_bus.running = True
            event_bus.start_dispatching()
            bridge.setup()

            # 2. Yöneticiler
            cleanup_manager.start()

            # 3. Detection motorları
            sigma_engine    = SigmaEngine()
            detection_engine = DetectionEngine()
            responder       = Responder()

            # 4. Toplayıcılar
            wmi_monitor.start()
            filesystem_monitor.start()
            task_monitor.start()
            sysmon_monitor.start()
            network_monitor.start()

            logger.info("Tüm toplayıcılar başlatıldı.")

            # 5. Watchdog
            collectors = {
                "WMI":        wmi_monitor,
                "FileSystem": filesystem_monitor,
                "Task":       task_monitor,
                "Sysmon":     sysmon_monitor,
                "Network":    network_monitor,
            }
            wdog = threading.Thread(
                target=self._watchdog, args=(collectors, WATCHDOG_INTERVAL),
                daemon=True, name="Watchdog"
            )
            wdog.start()

            # Ana thread'i canlı tut
            while self._backend_running:
                time.sleep(1)

        except Exception as e:
            logger.error(f"Backend hatası: {e}")
        finally:
            self._backend_running = False
            # GUI güncellemesi thread-safe: signal emit
            bridge.status_changed.emit("stopped")

    def _watchdog(self, collectors: dict, interval: int):
        import time
        while self._backend_running:
            for name, monitor in collectors.items():
                if hasattr(monitor, "thread") and monitor.thread and not monitor.thread.is_alive():
                    logger.error(f"Watchdog: {name} çöktü, yeniden başlatılıyor...")
                    monitor.start()
            time.sleep(interval)

    # ─────────────────────────────────────────────────────
    # Pencere Kapatma → Tray'e Küçült
    # ─────────────────────────────────────────────────────
    def closeEvent(self, event: QCloseEvent):
        event.ignore()
        self.hide()
        self.tray.showMessage(
            "EDR Arka Planda Çalışıyor",
            "Kapat için tray ikonuna sağ tıklayın → Çıkış",
            TrayIcon.MessageIcon.Information,
            3000,
        )
