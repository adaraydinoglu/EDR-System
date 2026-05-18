import threading
import time
import win32evtlog
import uuid
from core.event_bus import event_bus
from models.event_schema import EventSchema, EventType
from models.process_identity import ProcessIdentity
from collectors.sysmon_parser import SysmonParser
from core.process_manager import ProcessManager
from core.logger import logger
from config import THREAD_RESTART_DELAY

class SysmonMonitor:
    """
    Consumes Microsoft-Windows-Sysmon/Operational events.
    """
    def __init__(self):
        self.running = False
        self.thread = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._watch_loop, daemon=True, name="SysmonMonitor")
        self.thread.start()
        logger.info("Sysmon Monitor started.")

    def _watch_loop(self):
        server = 'localhost'
        log_type = 'Microsoft-Windows-Sysmon/Operational'
        
        try:
            hand = win32evtlog.OpenEventLog(server, log_type)
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            # Jump to end
            while win32evtlog.ReadEventLog(hand, flags, 0):
                pass
                
            while self.running:
                try:
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    if events:
                        for event in events:
                            xml_str = win32evtlog.EvtRender(None, event, win32evtlog.EvtRenderEventXml)
                            parsed = SysmonParser.parse_event(xml_str)
                            self._process_sysmon_event(parsed)
                    else:
                        time.sleep(1)
                except Exception as inner_e:
                    # Exception isolation for stability
                    logger.error(f"Sysmon Read Error (Restarting watcher): {inner_e}")
                    time.sleep(THREAD_RESTART_DELAY)
                    # Try to reopen handle
                    try:
                        hand = win32evtlog.OpenEventLog(server, log_type)
                    except:
                        pass
        except Exception as e:
            logger.error(f"Failed to start Sysmon watcher. Is Sysmon installed? Error: {e}")

    def _process_sysmon_event(self, parsed: dict):
        event_id = parsed.get("EventID")
        data = parsed.get("EventData", {})
        
        if not event_id:
            return

        ev_id_str = str(uuid.uuid4())
        timestamp = time.time()
        
        if event_id == 1: # Process Create
            pid = int(data.get("ProcessId", 0))
            parent_pid = int(data.get("ParentProcessId", 0))
            process_name = data.get("Image", "").split("\\")[-1]
            cmdline = data.get("CommandLine", "")
            path = data.get("Image", "")
            
            identity = ProcessIdentity(pid, timestamp)
            parent_identity = ProcessIdentity(parent_pid, 0.0) # Placeholder parent time
            
            ProcessManager.register_process(identity, {
                "name": process_name,
                "cmdline": cmdline,
                "path": path,
                "parent_pid": parent_pid
            })
            
            event = EventSchema(
                event_type=EventType.PROCESS_CREATE,
                event_id=ev_id_str,
                timestamp=timestamp,
                process_id=identity,
                process_name=process_name,
                parent_process_id=parent_identity,
                cmdline=cmdline,
                path=path
            )
            event_bus.publish_event(event)
            
        elif event_id == 10: # Process Access (LSASS dumping etc)
            src_pid = int(data.get("SourceProcessId", 0))
            tgt_image = data.get("TargetImage", "")
            access_mask = data.get("GrantedAccess", "")
            
            # Find identity in cache, fallback to current time
            identity = ProcessIdentity(src_pid, timestamp)
            
            event = EventSchema(
                event_type=EventType.PROCESS_ACCESS,
                event_id=ev_id_str,
                timestamp=timestamp,
                process_id=identity,
                process_name=data.get("SourceImage", "").split("\\")[-1],
                details={
                    "target_image": tgt_image,
                    "granted_access": access_mask
                }
            )
            event_bus.publish_event(event)

        elif event_id == 8: # Create Remote Thread
            src_pid = int(data.get("SourceProcessId", 0))
            tgt_image = data.get("TargetImage", "")
            
            identity = ProcessIdentity(src_pid, timestamp)
            event = EventSchema(
                event_type=EventType.CREATE_REMOTE_THREAD,
                event_id=ev_id_str,
                timestamp=timestamp,
                process_id=identity,
                process_name=data.get("SourceImage", "").split("\\")[-1],
                details={
                    "target_image": tgt_image
                }
            )
            event_bus.publish_event(event)

sysmon_monitor = SysmonMonitor()
