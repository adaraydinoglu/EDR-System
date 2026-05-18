import queue
from typing import Callable, Dict, List
import threading
from models.event_schema import EventSchema
from models.alert_schema import AlertSchema
from core.logger import logger

class EventBus:
    """
    Centralized Pub/Sub mechanism for decoupling collectors, detection, and response.
    """
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(EventBus, cls).__new__(cls)
            cls._instance._init()
        return cls._instance

    def _init(self):
        self.event_queue = queue.Queue()
        self.alert_queue = queue.Queue()
        self._subscribers: Dict[str, List[Callable]] = {
            "events": [],
            "alerts": []
        }
        self.running = True

    def publish_event(self, event: EventSchema):
        self.event_queue.put(event)

    def publish_alert(self, alert: AlertSchema):
        self.alert_queue.put(alert)

    def subscribe_events(self, callback: Callable[[EventSchema], None]):
        self._subscribers["events"].append(callback)

    def subscribe_alerts(self, callback: Callable[[AlertSchema], None]):
        self._subscribers["alerts"].append(callback)

    def start_dispatching(self):
        threading.Thread(target=self._dispatch_events, daemon=True, name="EventDispatcher").start()
        threading.Thread(target=self._dispatch_alerts, daemon=True, name="AlertDispatcher").start()
        logger.info("Event Bus dispatchers started.")

    def _dispatch_events(self):
        while self.running:
            try:
                event = self.event_queue.get(timeout=1)
                for callback in self._subscribers["events"]:
                    try:
                        callback(event)
                    except Exception as e:
                        logger.error(f"Error in event subscriber {callback.__name__}: {e}")
                self.event_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Event dispatch error: {e}")

    def _dispatch_alerts(self):
        while self.running:
            try:
                alert = self.alert_queue.get(timeout=1)
                for callback in self._subscribers["alerts"]:
                    try:
                        callback(alert)
                    except Exception as e:
                        logger.error(f"Error in alert subscriber {callback.__name__}: {e}")
                self.alert_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Alert dispatch error: {e}")

    def stop(self):
        self.running = False

event_bus = EventBus()
