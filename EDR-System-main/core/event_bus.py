import queue
from typing import Callable, Dict, List
import threading
from models.event_schema import EventSchema
from models.alert_schema import AlertSchema
from core.logger import logger


class EventBus:
    """
    Centralized Pub/Sub mechanism for decoupling collectors, detection, and response.
    Supports three channels: events, alerts, and incidents.
    """
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(EventBus, cls).__new__(cls)
            cls._instance._init()
        return cls._instance

    def _init(self):
        self.event_queue    = queue.Queue()
        self.alert_queue    = queue.Queue()
        self.incident_queue = queue.Queue()
        self._subscribers: Dict[str, List[Callable]] = {
            "events":    [],
            "alerts":    [],
            "incidents": [],
        }
        self.running = True

    # ── Publish ──────────────────────────────────────────────────────────────

    def publish_event(self, event: EventSchema):
        self.event_queue.put(event)

    def publish_alert(self, alert: AlertSchema):
        self.alert_queue.put(alert)

    def publish_incident(self, incident_dict: dict):
        """Publish a serialisable incident dict to all incident subscribers."""
        self.incident_queue.put(incident_dict)

    # ── Subscribe ────────────────────────────────────────────────────────────

    def subscribe_events(self, callback: Callable[[EventSchema], None]):
        self._subscribers["events"].append(callback)

    def subscribe_alerts(self, callback: Callable[[AlertSchema], None]):
        self._subscribers["alerts"].append(callback)

    def subscribe_incidents(self, callback: Callable[[dict], None]):
        self._subscribers["incidents"].append(callback)

    # ── Dispatch threads ─────────────────────────────────────────────────────

    def start_dispatching(self):
        threading.Thread(target=self._dispatch_events,    daemon=True, name="EventDispatcher").start()
        threading.Thread(target=self._dispatch_alerts,    daemon=True, name="AlertDispatcher").start()
        threading.Thread(target=self._dispatch_incidents, daemon=True, name="IncidentDispatcher").start()
        logger.info("Event Bus dispatchers started.")

    def _dispatch_events(self):
        while self.running:
            try:
                event = self.event_queue.get(timeout=1)
                for cb in self._subscribers["events"]:
                    try:
                        cb(event)
                    except Exception as e:
                        logger.error(f"Error in event subscriber {cb.__name__}: {e}")
                self.event_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Event dispatch error: {e}")

    def _dispatch_alerts(self):
        while self.running:
            try:
                alert = self.alert_queue.get(timeout=1)
                for cb in self._subscribers["alerts"]:
                    try:
                        cb(alert)
                    except Exception as e:
                        logger.error(f"Error in alert subscriber {cb.__name__}: {e}")
                self.alert_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Alert dispatch error: {e}")

    def _dispatch_incidents(self):
        while self.running:
            try:
                incident = self.incident_queue.get(timeout=1)
                for cb in self._subscribers["incidents"]:
                    try:
                        cb(incident)
                    except Exception as e:
                        logger.error(f"Error in incident subscriber {cb.__name__}: {e}")
                self.incident_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Incident dispatch error: {e}")

    def stop(self):
        self.running = False


event_bus = EventBus()

