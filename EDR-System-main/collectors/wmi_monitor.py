import threading
import wmi
import pythoncom
from core.event_bus import event_bus
from models.event_schema import EventSchema, EventType
from models.process_identity import ProcessIdentity
from core.process_manager import ProcessManager
from core.filters import is_whitelisted
from core.logger import logger
import time

class WMIMonitor:
    """
    Uses WMI Win32_ProcessStartTrace and Win32_ProcessStopTrace to monitor
    process lifecycles accurately, capturing short-lived processes and avoiding polling.
    """
    def __init__(self):
        self.running = False
        self.threads = []

    def start(self):
        self.running = True
        t1 = threading.Thread(target=self._watch_process_starts, daemon=True, name="WMI_ProcessStart")
        t2 = threading.Thread(target=self._watch_process_stops, daemon=True, name="WMI_ProcessStop")
        self.threads.extend([t1, t2])
        for t in self.threads:
            t.start()
        logger.info("WMI Process Monitor started.")

    def _watch_process_starts(self):
        pythoncom.CoInitialize()
        try:
            c = wmi.WMI()
            watcher = c.Win32_ProcessStartTrace.watch_for("creation")
            while self.running:
                try:
                    process_started = watcher(timeout_ms=1000)
                    if not process_started:
                        continue
                        
                    pid = int(process_started.ProcessID)
                    parent_pid = int(process_started.ParentProcessID)
                    process_name = process_started.ProcessName
                    
                    if is_whitelisted(process_name):
                        continue

                    # WMI Event doesn't have command line, so we need to query Win32_Process for details.
                    # This must be fast before the process dies.
                    cmdline = ""
                    path = ""
                    try:
                        # Attempt to get full process object for cmdline
                        procs = c.Win32_Process(ProcessId=pid)
                        if procs:
                            p = procs[0]
                            cmdline = p.CommandLine or ""
                            path = p.ExecutablePath or ""
                    except Exception:
                        pass # Process might have died already
                    
                    timestamp = time.time()
                    identity = ProcessIdentity(pid, timestamp)
                    
                    # We don't have parent create_time easily here unless we look it up in cache
                    # A robust implementation would look up parent in cache.
                    parent_identity = ProcessIdentity(parent_pid, 0.0) # 0.0 as placeholder if unknown
                    
                    # Register lifecycle
                    ProcessManager.register_process(identity, {
                        "name": process_name,
                        "cmdline": cmdline,
                        "path": path,
                        "parent_pid": parent_pid
                    })

                    event = EventSchema(
                        event_type=EventType.PROCESS_CREATE,
                        timestamp=timestamp,
                        process_id=identity,
                        process_name=process_name,
                        parent_process_id=parent_identity,
                        cmdline=cmdline,
                        path=path
                    )
                    
                    event_bus.publish_event(event)
                    
                except wmi.x_wmi_timed_out:
                    continue
                except Exception as e:
                    logger.error(f"Error in WMI Process Start watcher: {e}")
        finally:
            pythoncom.CoUninitialize()

    def _watch_process_stops(self):
        pythoncom.CoInitialize()
        try:
            c = wmi.WMI()
            watcher = c.Win32_ProcessStopTrace.watch_for("creation")
            while self.running:
                try:
                    process_stopped = watcher(timeout_ms=1000)
                    if not process_stopped:
                        continue
                        
                    pid = int(process_stopped.ProcessID)
                    process_name = process_stopped.ProcessName
                    
                    # We need to find the specific instance in the cache by PID to unregister it.
                    # Since we use (pid, create_time), we search the cache.
                    from core.cache_manager import cache_manager
                    target_identity = None
                    with cache_manager.lock:
                        for ident in list(cache_manager.process_cache.keys()):
                            if ident.pid == pid:
                                target_identity = ident
                                break
                    
                    if target_identity:
                        event = EventSchema(
                            event_type=EventType.PROCESS_TERMINATE,
                            process_id=target_identity,
                            process_name=process_name
                        )
                        event_bus.publish_event(event)
                        ProcessManager.unregister_process(target_identity)
                        
                except wmi.x_wmi_timed_out:
                    continue
                except Exception as e:
                    logger.error(f"Error in WMI Process Stop watcher: {e}")
        finally:
            pythoncom.CoUninitialize()

wmi_monitor = WMIMonitor()
