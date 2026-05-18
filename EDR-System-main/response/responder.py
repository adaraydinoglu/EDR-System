import psutil
from core.event_bus import event_bus
from models.alert_schema import AlertSchema
from core.logger import logger
from config import CRITICAL_SCORE_THRESHOLD, RESPONSE_ENABLED, AUTO_KILL_THRESHOLD

class Responder:
    """
    Automated response policy execution layer.
    """
    def __init__(self):
        event_bus.subscribe_alerts(self.handle_alert)

    def handle_alert(self, alert: AlertSchema):
        self._log_alert(alert)
        self._enforce_policy(alert)

    def _log_alert(self, alert: AlertSchema):
        alert_msg = (
            f"[ALERT] {alert.severity} - {alert.rule_name} "
            f"| Mitre: {alert.mitre_id} "
            f"| Target: {alert.trigger_event.process_name} "
            f"| Score: {alert.total_score} "
            f"| CorrID: {alert.correlation_id}"
        )
        
        if alert.severity == "CRITICAL":
            logger.error(alert_msg)
        elif alert.severity == "HIGH":
            logger.warning(alert_msg)
        else:
            logger.info(alert_msg)
            
        logger.log_alert(alert.to_json())

    def _enforce_policy(self, alert: AlertSchema):
        if not RESPONSE_ENABLED:
            return

        # 1. Rule-based specific action
        action = alert.response_action.lower()
        pid = alert.trigger_event.process_id.pid if alert.trigger_event.process_id else None
        
        if not pid:
            return

        if action == "kill":
            self._kill_process(pid, alert.rule_name)
        elif action == "isolate":
            self._isolate_network(pid)
        elif action == "quarantine":
            self._quarantine_file(alert.trigger_event.path)
            
        # 2. Score-based fallback (if action was just 'log' but score is critical)
        if action == "log" and alert.total_score >= AUTO_KILL_THRESHOLD:
            self._kill_process(pid, "Critical Score Threshold Exceeded")

    def _kill_process(self, pid: int, reason: str):
        try:
            p = psutil.Process(pid)
            p.kill()
            logger.info(f"[RESPONSE] Killed PID {pid} due to {reason}")
        except psutil.NoSuchProcess:
            logger.debug(f"[RESPONSE] PID {pid} already dead. Could not kill.")
        except psutil.AccessDenied:
            logger.error(f"[RESPONSE] Access Denied killing PID {pid}")
        except Exception as e:
            logger.error(f"[RESPONSE] Failed to kill PID {pid}: {e}")

    def _isolate_network(self, pid: int):
        # Placeholder for network isolation via Windows Firewall API (netsh advfirewall) or WFP.
        logger.warning(f"[RESPONSE] Network Isolation triggered for PID {pid}. (Placeholder - WFP integration required)")

    def _quarantine_file(self, path: str):
        # Placeholder for moving file to a quarantine vault and changing ACLs.
        if path:
            logger.warning(f"[RESPONSE] Quarantine triggered for file {path}. (Placeholder)")

responder = Responder()
