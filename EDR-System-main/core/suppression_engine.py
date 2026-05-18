"""
core/suppression_engine.py

Prevents alert fatigue by suppressing only truly redundant alerts.

Fingerprint strategy (updated):
  - incident_id | rule_name  → if this exact rule already fired for this
    incident within SUPPRESSION_COOLDOWN, suppress it.
  - Falls back to  rule_name | process_name | source  when no incident is
    assigned yet (solo non-incident alerts).

This means:
  ✓  PowerShell_Execution + Encoded_PowerShell on the same PID → two
     alerts (different rule names) that merge into ONE incident.
  ✓  PowerShell_Execution firing a SECOND time for the same PID within
     30 seconds → suppressed (same incident + same rule).
  ✓  The same rule firing on a DIFFERENT PID → not suppressed (different
     incident_id or no incident).
"""
import threading
import time
from typing import Dict, Tuple
from models.alert_schema import AlertSchema
from config import SUPPRESSION_COOLDOWN, BURST_WINDOW_SEC, MAX_ALERTS_PER_BURST
from core.logger import logger


class SuppressionEngine:
    def __init__(self):
        self._lock  = threading.RLock()
        # fingerprint → (last_seen_time, count_in_window)
        self._state: Dict[str, Tuple[float, int]] = {}

    def _fingerprint(self, alert: AlertSchema) -> str:
        """
        Build a suppression key.
        If the alert has been assigned to an incident, scope the key to that
        incident so different rules on the same chain are NOT suppressed
        relative to each other, but the SAME rule repeated on the same chain is.
        """
        if alert.incident_id:
            return f"{alert.incident_id}|{alert.rule_name}"

        # No incident yet (solo alert path)
        target = ""
        if alert.trigger_event:
            target = alert.trigger_event.process_name or alert.trigger_event.path
        return f"{alert.rule_name}|{target}|{alert.source}"

    def should_suppress(self, alert: AlertSchema) -> bool:
        fp  = self._fingerprint(alert)
        now = time.time()

        with self._lock:
            if fp not in self._state:
                self._state[fp] = (now, 1)
                return False

            last_seen, count = self._state[fp]

            # Outside cooldown window → always let through, reset counter
            if now - last_seen > SUPPRESSION_COOLDOWN:
                self._state[fp] = (now, 1)
                return False

            # Inside burst window
            if now - last_seen <= BURST_WINDOW_SEC:
                if count >= MAX_ALERTS_PER_BURST:
                    self._state[fp] = (now, count + 1)
                    return True          # suppress burst
                self._state[fp] = (now, count + 1)
                return False

            # Between burst window and cooldown → rate-limit (suppress)
            self._state[fp] = (now, count + 1)
            return True

    def cleanup(self):
        now = time.time()
        with self._lock:
            stale = [
                fp for fp, (ts, _) in self._state.items()
                if now - ts > SUPPRESSION_COOLDOWN
            ]
            for fp in stale:
                del self._state[fp]


suppression_engine = SuppressionEngine()
