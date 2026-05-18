import threading
import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from core.event_bus import event_bus
from models.event_schema import EventSchema, EventType
from config import MONITORED_PATHS
from core.logger import logger

class EDRFileSystemEventHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        self._publish(EventType.FILE_CREATE, event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        self._publish(EventType.FILE_MODIFY, event.src_path)

    def _publish(self, ev_type: EventType, path: str):
        # We don't reliably have process context for file creation via just watchdog.
        # Future ETW/Sysmon integration handles this better.
        ev = EventSchema(
            event_type=ev_type,
            path=path,
            details={"file_extension": os.path.splitext(path)[1].lower()}
        )
        event_bus.publish_event(ev)

class FileSystemMonitor:
    def __init__(self):
        self.observer = Observer()
        self.handler = EDRFileSystemEventHandler()

    def start(self):
        paths_to_monitor = []
        for path in MONITORED_PATHS:
            if os.path.exists(path):
                paths_to_monitor.append(path)
                self.observer.schedule(self.handler, path, recursive=True)
                
        self.observer.start()
        logger.info(f"Filesystem Monitor started. Watching: {paths_to_monitor}")

filesystem_monitor = FileSystemMonitor()