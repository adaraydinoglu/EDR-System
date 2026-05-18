import threading
import time
import psutil
import uuid
from core.event_bus import event_bus
from models.event_schema import EventSchema, EventType
from models.process_identity import ProcessIdentity
from core.logger import logger
from core.cache_manager import cache_manager

class NetworkMonitor:
    """
    Polls psutil.net_connections for outbound network connections.
    Future ETW Migration: This module provides an abstraction that can be seamlessly
    switched to use Microsoft-Windows-TCPIP ETW provider for asynchronous events.
    """
    def __init__(self):
        self.running = False
        self.thread = None
        # Track active connections to calculate first_seen, last_seen, count
        self.active_conns = {}

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._poll_connections, daemon=True, name="NetMonitor")
        self.thread.start()
        logger.info("Network Monitor started (psutil polling layer).")

    def _poll_connections(self):
        while self.running:
            try:
                conns = psutil.net_connections(kind='inet')
                current_time = time.time()
                
                for conn in conns:
                    if conn.status == 'ESTABLISHED' and conn.raddr and conn.pid:
                        conn_key = f"{conn.pid}_{conn.raddr.ip}_{conn.raddr.port}"
                        
                        if conn_key not in self.active_conns:
                            # New connection
                            self.active_conns[conn_key] = {
                                "first_seen": current_time,
                                "last_seen": current_time,
                                "count": 1
                            }
                            
                            # Publish event
                            self._publish_network_event(conn, current_time)
                        else:
                            # Update existing connection state
                            self.active_conns[conn_key]["last_seen"] = current_time
                            self.active_conns[conn_key]["count"] += 1
                
                # Cleanup dead connections from local state
                to_delete = [k for k, v in self.active_conns.items() if current_time - v["last_seen"] > 10]
                for k in to_delete:
                    del self.active_conns[k]
                    
                time.sleep(2) # Polling interval
            except Exception as e:
                logger.error(f"Network Monitor Error: {e}")
                time.sleep(2)

    def _publish_network_event(self, conn, timestamp):
        pid = conn.pid
        dst_ip = conn.raddr.ip
        dst_port = conn.raddr.port
        
        # We need to resolve PID to ProcessIdentity from cache
        identity = ProcessIdentity(pid, timestamp) # Fallback identity
        process_name = "unknown"
        with cache_manager.lock:
            for cached_id, (_, details) in list(cache_manager.process_cache.items()):
                if cached_id.pid == pid:
                    identity = cached_id
                    process_name = details.get("name", "unknown")
                    break
                    
        conn_state = self.active_conns.get(f"{pid}_{dst_ip}_{dst_port}", {})
        
        event = EventSchema(
            event_type=EventType.NETWORK_CONNECT,
            event_id=str(uuid.uuid4()),
            timestamp=timestamp,
            process_id=identity,
            process_name=process_name,
            details={
                "src_ip": conn.laddr.ip if conn.laddr else "",
                "src_port": conn.laddr.port if conn.laddr else 0,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": "TCP",
                "first_seen": conn_state.get("first_seen", timestamp),
                "last_seen": conn_state.get("last_seen", timestamp),
                "connection_count": conn_state.get("count", 1),
                "dns_name": "" # Placeholder for future DNS correlation
            }
        )
        event_bus.publish_event(event)

network_monitor = NetworkMonitor()
