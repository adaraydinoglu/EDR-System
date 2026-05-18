"""
core/incident_manager.py

Groups ALL alerts whose trigger process belongs to the same attack chain
into a single named Incident.

Grouping key: the *root* PID of the attack chain (ancestor walk).
This means multiple rules firing on the same powershell.exe process
(PowerShell_Execution AND Encoded_PowerShell AND network) all merge into
one "Suspicious Browser → PowerShell Attack" incident instead of three
separate alerts.

Architecture:
  - _pid_to_incident_id: maps every seen PID to its incident
  - When a new alert arrives:
      1. Walk ancestry PIDs — if any already has an incident, join that
      2. Otherwise create a new incident and register all ancestry PIDs
  - alert.incident_id / alert.incident_name stamped in-place
  - incident dict published to event_bus (GUI picks it up via bridge)
"""
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import List, Dict, Optional

from core.logger import logger


# ── Incident name templates ──────────────────────────────────────────────────
# Ordered: more-specific sets first
_CHAIN_NAMES: List[tuple] = [
    ({"winword.exe",   "powershell.exe"},  "Office Macro → PowerShell Execution"),
    ({"winword.exe",   "cmd.exe"},         "Office Macro → Shell Execution"),
    ({"excel.exe",     "powershell.exe"},  "Office Macro → PowerShell Execution"),
    ({"excel.exe",     "cmd.exe"},         "Office Macro → Shell Execution"),
    ({"powerpnt.exe",  "powershell.exe"},  "Office Macro → PowerShell Execution"),
    ({"outlook.exe",   "powershell.exe"},  "Office Macro → PowerShell Execution"),
    ({"brave.exe",     "powershell.exe"},  "Suspicious Browser → PowerShell Attack"),
    ({"chrome.exe",    "powershell.exe"},  "Suspicious Browser → PowerShell Attack"),
    ({"firefox.exe",   "powershell.exe"},  "Suspicious Browser → PowerShell Attack"),
    ({"msedge.exe",    "powershell.exe"},  "Suspicious Browser → PowerShell Attack"),
    ({"iexplore.exe",  "powershell.exe"},  "Suspicious Browser → PowerShell Attack"),
    ({"mshta.exe",     "powershell.exe"},  "LOLBin → PowerShell Execution Chain"),
    ({"powershell.exe","cmd.exe"},         "Shell Nesting / Defense Evasion Chain"),
    ({"powershell.exe","wscript.exe"},     "PowerShell → Script Interpreter Chain"),
    ({"vssadmin.exe"},                     "Ransomware Pre-Stage: Shadow Copy Deletion"),
    ({"wmic.exe"},                         "WMIC Remote Execution Attempt"),
    ({"schtasks.exe"},                     "Persistence: Scheduled Task Creation"),
    ({"certutil.exe"},                     "LOLBin: certutil Decode / Download"),
    ({"regsvr32.exe"},                     "LOLBin: regsvr32 DLL Execution"),
    ({"msbuild.exe"},                      "LOLBin: MSBuild Code Execution"),
    ({"bitsadmin.exe"},                    "LOLBin: BITSAdmin Download"),
    ({"rundll32.exe"},                     "Suspicious rundll32 Execution"),
]


def _name_from_chain(ancestry: List[str]) -> str:
    """Map an ancestry list to a human-readable incident name."""
    lowered = {p.lower() for p in ancestry}
    for proc_set, name in _CHAIN_NAMES:
        if proc_set.issubset(lowered):
            return name
    if len(ancestry) >= 2:
        tail = " → ".join(ancestry[-3:])
        return f"Multi-Process Execution Chain: {tail}"
    return f"Suspicious Activity: {ancestry[-1] if ancestry else 'Unknown Process'}"


@dataclass
class Incident:
    incident_id:    str
    incident_name:  str
    severity:       str
    root_pid:       int                              # PID that started the chain
    first_seen:     float = field(default_factory=time.time)
    last_seen:      float = field(default_factory=time.time)
    rule_hits:      List[str] = field(default_factory=list)   # rule names fired
    alert_ids:      List[str] = field(default_factory=list)   # correlation IDs
    ancestry_chain: List[str] = field(default_factory=list)
    tactics:        List[str] = field(default_factory=list)
    mitre_ids:      List[str] = field(default_factory=list)
    network_info:   List[dict] = field(default_factory=list)

    _SEV = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

    def merge_alert(self, alert) -> bool:
        """
        Merge alert into this incident.
        Returns True if this is a NEW rule hit (not seen before for this incident).
        """
        self.last_seen = time.time()
        is_new = alert.rule_name not in self.rule_hits
        if is_new:
            self.rule_hits.append(alert.rule_name)

        if alert.correlation_id and alert.correlation_id not in self.alert_ids:
            self.alert_ids.append(alert.correlation_id)

        # Escalate severity monotonically
        if self._SEV.get(alert.severity, 0) > self._SEV.get(self.severity, 0):
            self.severity = alert.severity

        if alert.tactic and alert.tactic not in self.tactics:
            self.tactics.append(alert.tactic)
        if alert.mitre_id and alert.mitre_id not in self.mitre_ids:
            self.mitre_ids.append(alert.mitre_id)

        # Merge network info if present
        ni = getattr(alert, "network_info", {})
        if ni and ni.get("dst_ip") and ni not in self.network_info:
            self.network_info.append(ni)

        return is_new

    def to_dict(self) -> dict:
        return {
            "incident_id":    self.incident_id,
            "incident_name":  self.incident_name,
            "severity":       self.severity,
            "root_pid":       self.root_pid,
            "first_seen":     self.first_seen,
            "last_seen":      self.last_seen,
            "alert_count":    len(self.alert_ids),
            "rule_hits":      self.rule_hits,
            "alert_ids":      self.alert_ids,
            "ancestry_chain": self.ancestry_chain,
            "tactics":        self.tactics,
            "mitre_ids":      self.mitre_ids,
            "network_info":   self.network_info,
        }


class IncidentManager:
    """
    Thread-safe incident registry.

    Grouping strategy (PID-based, not fingerprint-based):
      - Every PID that has ever triggered an alert is mapped to an incident ID.
      - When a new alert arrives, we walk the ancestry PIDs.
      - If ANY ancestor PID already belongs to an incident → merge.
      - Otherwise create a new incident and register all ancestry PIDs.

    This guarantees that PowerShell_Execution + Encoded_PowerShell +
    Browser_Spawning_Shell all resolve to the same incident because they
    share the same PID.
    """

    # Incidents with no new activity for this long are "closed" (new alerts
    # for the same PID will still re-open / extend them)
    TTL = 600   # 10 minutes

    def __init__(self):
        self._lock           = threading.RLock()
        self._by_id:         Dict[str, Incident] = {}
        self._pid_to_iid:    Dict[int, str] = {}    # pid → incident_id

    # ── Public API ───────────────────────────────────────────────────────────

    def ingest_alert(self, alert) -> Optional[Incident]:
        """
        Route alert to correct incident (create or merge).
        Mutates alert.incident_id / alert.incident_name in-place.
        Returns the Incident, or None for solo LOW-noise alerts.
        """
        from core.process_tree_tracker import process_tree_tracker

        pid = alert.trigger_event.process_id.pid if (
            alert.trigger_event and alert.trigger_event.process_id
        ) else None

        # Resolve full ancestry (PIDs + names)
        ancestry_names, ancestry_pids = self._resolve_ancestry(pid, process_tree_tracker)

        # Ensure there's something meaningful to work with
        if not ancestry_names:
            # Fall back to trigger_event fields
            if alert.trigger_event:
                if alert.trigger_event.parent_name:
                    ancestry_names.append(alert.trigger_event.parent_name)
                if alert.trigger_event.process_name:
                    ancestry_names.append(alert.trigger_event.process_name)
            if not ancestry_names:
                ancestry_names = [alert.rule_name]

        # Don't create incidents for solo LOW alerts with no chain
        if len(ancestry_names) <= 1 and alert.severity == "LOW":
            return None

        # Overwrite alert's ancestry_chain with the full resolved version
        alert.ancestry_chain = ancestry_names

        now = time.time()

        with self._lock:
            # --- Find existing incident via PID walk ---
            incident = self._find_incident_for_pids(ancestry_pids, now)

            if incident:
                is_new_rule = incident.merge_alert(alert)
                if is_new_rule:
                    # Extend ancestry with any new names
                    for name in ancestry_names:
                        if name not in incident.ancestry_chain:
                            incident.ancestry_chain.append(name)
                    # Re-name if the chain changed
                    incident.incident_name = _name_from_chain(incident.ancestry_chain)
                logger.debug(
                    f"IncidentManager: merged rule '{alert.rule_name}' → "
                    f"'{incident.incident_name}' (id={incident.incident_id})"
                )
            else:
                # Create new incident
                iid = str(uuid.uuid4())[:8].upper()
                root_pid = ancestry_pids[0] if ancestry_pids else (pid or 0)
                name = _name_from_chain(ancestry_names)
                incident = Incident(
                    incident_id=iid,
                    incident_name=name,
                    severity=alert.severity,
                    root_pid=root_pid,
                    ancestry_chain=list(ancestry_names),
                )
                incident.merge_alert(alert)
                self._by_id[iid] = incident
                logger.info(
                    f"IncidentManager: new incident '{name}' (id={iid}, "
                    f"rule='{alert.rule_name}')"
                )

            # Register all ancestry PIDs → this incident
            for p in ancestry_pids:
                self._pid_to_iid[p] = incident.incident_id

        # Stamp the alert
        alert.incident_id   = incident.incident_id
        alert.incident_name = incident.incident_name

        # Publish updated incident to GUI
        try:
            from core.event_bus import event_bus
            event_bus.publish_incident(incident.to_dict())
        except Exception as e:
            logger.error(f"IncidentManager: publish failed: {e}")

        return incident

    def get_all(self) -> List[dict]:
        with self._lock:
            return [i.to_dict() for i in self._by_id.values()]

    def get_by_id(self, incident_id: str) -> Optional[dict]:
        with self._lock:
            i = self._by_id.get(incident_id)
            return i.to_dict() if i else None

    # ── Private helpers ──────────────────────────────────────────────────────

    def _resolve_ancestry(self, pid, tracker) -> tuple:
        """
        Walk the process tree upwards from pid.
        Returns (names_oldest_first, pids_oldest_first).
        """
        if not pid:
            return [], []
        names = tracker.get_ancestry(pid)   # already oldest→newest
        # Also collect PIDs in the same order by walking manually
        pids = []
        visited = set()
        cur = pid
        chain = []
        with tracker._lock:
            while cur and cur not in visited:
                visited.add(cur)
                node = tracker._nodes.get(cur)
                if not node:
                    break
                chain.append(cur)
                cur = node.parent_pid
        chain.reverse()
        pids = chain
        return names, pids

    def _find_incident_for_pids(self, pids: List[int], now: float) -> Optional[Incident]:
        """Return an active incident that already owns any of these PIDs."""
        for p in pids:
            iid = self._pid_to_iid.get(p)
            if iid:
                incident = self._by_id.get(iid)
                if incident and (now - incident.last_seen) < self.TTL:
                    return incident
                # Expired — clean up mapping
                if iid in self._pid_to_iid.values():
                    self._pid_to_iid = {
                        k: v for k, v in self._pid_to_iid.items() if v != iid
                    }
        return None
incident_manager = IncidentManager()
