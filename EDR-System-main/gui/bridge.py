"""
gui/bridge.py
EventBus → Qt Signal köprüsü.
Backend thread'lerinden gelen olayları thread-safe biçimde GUI'ye iletir.
"""
from PyQt6.QtCore import QObject, pyqtSignal


class GuiBridge(QObject):
    """
    EventBus subscriber'ı olarak kayıt olur ve
    gelen event/alert'leri Qt Signal olarak emit eder.
    Qt signal/slot mekanizması cross-thread çağrıları otomatik queued yapar.
    """
    new_alert = pyqtSignal(object)   # AlertSchema
    new_event = pyqtSignal(object)   # EventSchema
    status_changed = pyqtSignal(str) # "running" | "stopped"

    def __init__(self):
        super().__init__()
        self._subscribed = False

    def setup(self):
        """EventBus hazır olduktan sonra çağrılmalı."""
        if self._subscribed:
            return
        from core.event_bus import event_bus
        event_bus.subscribe_events(self._on_event)
        event_bus.subscribe_alerts(self._on_alert)
        self._subscribed = True

    def _on_event(self, event):
        self.new_event.emit(event)

    def _on_alert(self, alert):
        self.new_alert.emit(alert)


# Global tekil instance
bridge = GuiBridge()
