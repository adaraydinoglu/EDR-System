"""
gui/bridge.py
EventBus → Qt Signal bridge.
Converts backend objects to plain dicts before crossing the thread boundary.
"""
from PyQt6.QtCore import QObject, pyqtSignal


class GuiBridge(QObject):
    """
    Subscribes to EventBus channels and re-emits as typed Qt signals.
    Qt's queued-connection mechanism makes all cross-thread calls safe.
    """
    new_alert    = pyqtSignal(dict)   # JSON-parsed alert dict
    new_event    = pyqtSignal(dict)   # event.to_dict()
    new_incident = pyqtSignal(dict)   # incident dict from IncidentManager
    status_changed = pyqtSignal(str)  # "running" | "stopped"

    def __init__(self):
        super().__init__()
        self._subscribed = False

    def setup(self):
        """Call once after EventBus is running."""
        if self._subscribed:
            return
        from core.event_bus import event_bus
        from core.process_tree_tracker import process_tree_tracker

        event_bus.subscribe_events(self._on_event)
        event_bus.subscribe_alerts(self._on_alert)
        event_bus.subscribe_incidents(self._on_incident)

        # Start the backend process tree tracker
        process_tree_tracker.setup()

        self._subscribed = True

    def _on_event(self, event):
        self.new_event.emit(event.to_dict())

    def _on_alert(self, alert):
        import json
        self.new_alert.emit(json.loads(alert.to_json()))

    def _on_incident(self, incident_dict: dict):
        self.new_incident.emit(incident_dict)


# Global singleton instance
bridge = GuiBridge()

