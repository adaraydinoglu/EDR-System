import threading
import win32evtlog
from core.event_bus import event_bus
from models.event_schema import EventSchema, EventType
from core.logger import logger

class TaskMonitor:
    """
    Monitors Scheduled Tasks via Windows Event Log instead of schtasks.exe polling.
    Uses Event ID 106 (Task Registered) from Microsoft-Windows-TaskScheduler/Operational.
    """
    def __init__(self):
        self.running = False
        self.thread = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._watch_events, daemon=True, name="TaskMonitor")
        self.thread.start()
        logger.info("Task Monitor started (Event Log Watcher).")

    def _watch_events(self):
        server = 'localhost'
        log_type = 'Microsoft-Windows-TaskScheduler/Operational'
        
        try:
            # We open the log and seek to the end.
            hand = win32evtlog.OpenEventLog(server, log_type)
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            # Read whatever is there initially to jump to the end
            while win32evtlog.ReadEventLog(hand, flags, 0):
                pass
                
            while self.running:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if events:
                    for event in events:
                        if event.EventID == 106: # Task Registered
                            strings = event.StringInserts
                            task_name = strings[0] if strings else "Unknown"
                            
                            ev = EventSchema(
                                event_type=EventType.TASK_CREATE,
                                details={
                                    "task_name": task_name,
                                    "event_id": event.EventID
                                }
                            )
                            event_bus.publish_event(ev)
                else:
                    win32evtlog.EvtWait(None, 2000) # Simple sleep fallback if EvtWait not wrapped perfectly
                    
        except Exception as e:
            # EvtWait might not be in pywin32 win32evtlog directly depending on version, fallback to sleep
            import time
            while self.running:
                try:
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    if events:
                        for event in events:
                            # 106 = Task Registered
                            # Note: To read this log, script needs Admin rights and the log must be enabled.
                            if event.EventID == 106:
                                task_name = event.StringInserts[0] if event.StringInserts else "Unknown"
                                ev = EventSchema(
                                    event_type=EventType.TASK_CREATE,
                                    details={"task_name": task_name}
                                )
                                event_bus.publish_event(ev)
                    time.sleep(2)
                except Exception as inner_e:
                    logger.error(f"Error reading event log: {inner_e}")
                    time.sleep(5)

task_monitor = TaskMonitor()