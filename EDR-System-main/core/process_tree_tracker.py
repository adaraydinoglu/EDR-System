"""
core/process_tree_tracker.py

Thread-safe backend registry that:
  - Maintains every PID → process metadata (name, parent, cmdline, network)
  - Builds a full ancestry chain for correlation
  - Attaches network connections (IP, port) to the owning PID
  - Exposes get_tree_snapshot() for the GUI
"""
import threading
import time
from typing import Dict, List, Optional
from core.logger import logger


class ProcessNode:
    __slots__ = (
        "pid", "name", "parent_pid", "parent_name",
        "cmdline", "start_time", "end_time",
        "network_connections", "alert_severities",
    )

    def __init__(self, pid, name, parent_pid, parent_name, cmdline, start_time):
        self.pid               = pid
        self.name              = name
        self.parent_pid        = parent_pid
        self.parent_name       = parent_name
        self.cmdline           = cmdline
        self.start_time        = start_time
        self.end_time          = None               # None = still running
        self.network_connections: List[dict] = []  # {dst_ip, dst_port, proto}
        self.alert_severities:  List[str]   = []   # severities of alerts that hit this PID


class ProcessTreeTracker:
    """
    Singleton backend process tree.

    Subscribes to EventBus for PROCESS_CREATE, PROCESS_TERMINATE, and
    NETWORK_CONNECT events so it stays in sync with real telemetry.
    """

    def __init__(self):
        self._lock  = threading.RLock()
        self._nodes: Dict[int, ProcessNode] = {}   # pid → ProcessNode
        self._subscribed = False

    # ── EventBus integration ────────────────────────────────────────────────

    def setup(self):
        """Call once after EventBus is running."""
        if self._subscribed:
            return
        from core.event_bus import event_bus
        from models.event_schema import EventType

        def _on_event(event):
            if event.event_type == EventType.PROCESS_CREATE:
                self._on_process_create(event)
            elif event.event_type == EventType.PROCESS_TERMINATE:
                self._on_process_terminate(event)
            elif event.event_type == EventType.NETWORK_CONNECT:
                self._on_network_connect(event)

        event_bus.subscribe_events(_on_event)
        self._subscribed = True

    # ── Private handlers ────────────────────────────────────────────────────

    def _on_process_create(self, event):
        pid = event.process_id.pid if event.process_id else None
        if not pid:
            return
        parent_pid = event.parent_process_id.pid if event.parent_process_id else None
        node = ProcessNode(
            pid=pid,
            name=event.process_name,
            parent_pid=parent_pid,
            parent_name=event.parent_name,
            cmdline=event.cmdline,
            start_time=event.timestamp,
        )
        with self._lock:
            self._nodes[pid] = node

    def _on_process_terminate(self, event):
        pid = event.process_id.pid if event.process_id else None
        if not pid:
            return
        with self._lock:
            if pid in self._nodes:
                self._nodes[pid].end_time = event.timestamp

    def _on_network_connect(self, event):
        pid = event.process_id.pid if event.process_id else None
        if not pid:
            return
        details = event.details or {}
        conn = {
            "dst_ip":   details.get("dst_ip", details.get("remote_ip", "")),
            "dst_port": details.get("dst_port", details.get("remote_port", "")),
            "proto":    details.get("proto", details.get("protocol", "TCP")),
            "time":     event.timestamp,
        }
        with self._lock:
            if pid in self._nodes:
                # Keep only the last 10 connections per process
                conns = self._nodes[pid].network_connections
                conns.append(conn)
                if len(conns) > 10:
                    conns.pop(0)

    # ── Public API ──────────────────────────────────────────────────────────

    def mark_alert(self, pid: int, severity: str):
        """Called by CorrelationEngine / DetectionEngine to colour the tree node."""
        with self._lock:
            if pid in self._nodes:
                self._nodes[pid].alert_severities.append(severity)

    def get_ancestry(self, pid: int, max_depth: int = 8) -> List[str]:
        """
        Return ordered ancestor names from oldest → newest, ending with the
        process itself.  e.g. ['explorer.exe', 'brave.exe', 'powershell.exe']
        """
        chain = []
        visited = set()
        with self._lock:
            current_pid = pid
            while current_pid and current_pid not in visited:
                visited.add(current_pid)
                node = self._nodes.get(current_pid)
                if not node:
                    break
                chain.append(node.name)
                current_pid = node.parent_pid
                if len(chain) >= max_depth:
                    break
        chain.reverse()
        return chain

    def get_network_connections(self, pid: int) -> List[dict]:
        with self._lock:
            node = self._nodes.get(pid)
            return list(node.network_connections) if node else []

    def get_tree_snapshot(self) -> List[dict]:
        """
        Return a serialisable list of all known process nodes for the GUI.
        Each dict contains pid, name, parent_pid, cmdline, status,
        network_connections, and highest_alert_severity.
        """
        SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "": 0}
        snapshot = []
        with self._lock:
            for node in self._nodes.values():
                sevs = node.alert_severities
                highest = max(sevs, key=lambda s: SEV_ORDER.get(s, 0)) if sevs else ""
                snapshot.append({
                    "pid":              node.pid,
                    "name":             node.name,
                    "parent_pid":       node.parent_pid,
                    "parent_name":      node.parent_name,
                    "cmdline":          node.cmdline,
                    "start_time":       node.start_time,
                    "end_time":         node.end_time,
                    "status":           "terminated" if node.end_time else "running",
                    "network_connections": list(node.network_connections),
                    "highest_severity": highest,
                })
        return snapshot

    def get_node(self, pid: int) -> Optional[dict]:
        with self._lock:
            node = self._nodes.get(pid)
            if not node:
                return None
            return {
                "pid": node.pid, "name": node.name,
                "parent_pid": node.parent_pid,
                "cmdline": node.cmdline,
            }


process_tree_tracker = ProcessTreeTracker()
