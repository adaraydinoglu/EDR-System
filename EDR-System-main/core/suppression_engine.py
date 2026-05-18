import threading
import time
from typing import Dict, Tuple
from models.alert_schema import AlertSchema
from config import SUPPRESSION_COOLDOWN, BURST_WINDOW_SEC, MAX_ALERTS_PER_BURST
from core.logger import logger

class SuppressionEngine:
    """
    Prevents alert fatigue by suppressing duplicate, burst, and noisy alerts.
    """
    def __init__(self):
        self.lock = threading.RLock()
        
        # fingerprint -> (last_seen_time, count_in_burst_window)
        self.state: Dict[str, Tuple[float, int]] = {}

    def _generate_fingerprint(self, alert: AlertSchema) -> str:
        # Fingerprint: Rule + Target Process (or path) + Source
        target = alert.trigger_event.process_name if alert.trigger_event.process_name else alert.trigger_event.path
        return f"{alert.rule_name}|{target}|{alert.source}"

    def should_suppress(self, alert: AlertSchema) -> bool:
        fingerprint = self._generate_fingerprint(alert)
        current_time = time.time()
        
        with self.lock:
            if fingerprint not in self.state:
                self.state[fingerprint] = (current_time, 1)
                return False
                
            last_seen, count = self.state[fingerprint]
            
            # Cooldown check
            if current_time - last_seen > SUPPRESSION_COOLDOWN:
                self.state[fingerprint] = (current_time, 1)
                return False
                
            # Burst check
            if current_time - last_seen <= BURST_WINDOW_SEC:
                if count >= MAX_ALERTS_PER_BURST:
                    # Suppress
                    self.state[fingerprint] = (current_time, count + 1)
                    return True
                else:
                    self.state[fingerprint] = (current_time, count + 1)
                    return False
                    
            # If not in burst window but within cooldown, just increment count and reset last seen
            # Rate limiting kicks in
            self.state[fingerprint] = (current_time, count + 1)
            return True

    def cleanup(self):
        current_time = time.time()
        with self.lock:
            to_delete = [
                fp for fp, (last_seen, _) in self.state.items()
                if current_time - last_seen > SUPPRESSION_COOLDOWN
            ]
            for fp in to_delete:
                del self.state[fp]

suppression_engine = SuppressionEngine()
