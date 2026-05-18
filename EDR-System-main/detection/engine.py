"""
detection/engine.py

Stateless per-event detection engine.

Key changes vs. previous version:
  - Every alert is routed through incident_manager.ingest_alert() so
    multiple rules firing on the same PID (PowerShell_Execution +
    Encoded_PowerShell + network event) all collapse into ONE incident.
  - ancestry_chain is resolved from process_tree_tracker before
    calling incident_manager so the full chain is available.
  - suppression_engine is called AFTER incident merging so the
    suppression fingerprint is incident_id|rule_name, not the old
    rule|process|source key (which caused duplicates).
"""
import uuid

from core.event_bus import event_bus
from models.event_schema import EventSchema, EventType
from models.alert_schema import AlertSchema
from detection.rules import RULES
from core.cache_manager import cache_manager
from core.risk_engine import RiskEngine
from core.suppression_engine import suppression_engine
from core.incident_manager import incident_manager
from core.process_tree_tracker import process_tree_tracker
from core.logger import logger


class DetectionEngine:
    def __init__(self):
        event_bus.subscribe_events(self.analyze_event)

    def analyze_event(self, event: EventSchema):
        # 1. Base risk evaluation (mutates event.risk_score / event.severity)
        event_risk, _ = RiskEngine.evaluate_event(event)

        if event.process_id and event_risk > 0:
            total_risk, _ = RiskEngine.update_cumulative_risk(event.process_id, event_risk)
            cumulative_sev = RiskEngine.get_severity_for_score(total_risk)
            if cumulative_sev != "LOW":
                event.severity = cumulative_sev

        # 2. Add to recent-events cache for timeline / correlation engine
        cache_manager.add_recent_event(event)

        # 3. Evaluate every stateless JSON rule
        matched_any = False
        for rule in RULES:
            try:
                if rule["match"](event):
                    self._trigger_alert(rule, event)
                    matched_any = True
            except Exception as e:
                logger.error(
                    f"DetectionEngine: Error in rule '{rule.get('name')}': {e}"
                )

        # 4. Fallback Anomaly Detection
        # If no specific rule matched but the event/process has a high risk score, trigger an anomaly
        if not matched_any and event.severity in ["MEDIUM", "HIGH", "CRITICAL"]:
            anomaly_rule = {
                "name": "Behavioral_Anomaly_Detected",
                "severity": event.severity,
                "confidence": "LOW",
                "tactic": "Unknown",
                "technique": "Unknown",
                "score": event_risk,
                "technique_name": "Suspicious Behavior"
            }
            self._trigger_alert(anomaly_rule, event)

    # ── Alert construction ───────────────────────────────────────────────────

    def _trigger_alert(self, rule: dict, event: EventSchema):
        pid = event.process_id.pid if event.process_id else None

        # --- Resolve ancestry from the tracker (full chain, not just parent) ---
        ancestry = process_tree_tracker.get_ancestry(pid) if pid else []
        if not ancestry:
            # Fallback: parent_name → process_name
            if event.parent_name:
                ancestry.append(event.parent_name)
            if event.process_name:
                ancestry.append(event.process_name)

        # --- Network info ---
        network_info = {}
        if event.event_type == EventType.NETWORK_CONNECT:
            d = event.details or {}
            network_info = {
                "dst_ip":   d.get("dst_ip",   d.get("remote_ip", "")),
                "dst_port": d.get("dst_port", d.get("remote_port", "")),
                "proto":    d.get("proto",    d.get("protocol", "TCP")),
            }
        elif pid:
            conns = process_tree_tracker.get_network_connections(pid)
            if conns:
                network_info = conns[-1]

        # --- Cumulative score ---
        if pid:
            current_score, _ = RiskEngine.update_cumulative_risk(
                event.process_id, rule.get("score", 0)
            )
        else:
            current_score = rule.get("score", 0)

        # Severity: use cumulative score but never downgrade below rule's declared severity
        _SEV = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        computed_sev = RiskEngine.get_severity_for_score(current_score)
        rule_sev     = rule.get("severity", "MEDIUM")
        final_severity = (
            computed_sev
            if _SEV.get(computed_sev, 0) >= _SEV.get(rule_sev, 0)
            else rule_sev
        )

        corr_id = str(uuid.uuid4())[:8].upper()

        alert = AlertSchema(
            rule_name=rule["name"],
            severity=final_severity,
            confidence=rule.get("confidence", "MEDIUM"),
            tactic=rule.get("tactic", "Unknown"),
            technique=rule.get("technique", ""),
            trigger_event=event,
            technique_name=rule.get("technique_name", ""),
            mitre_id=rule.get("mitre_id", rule.get("technique", "")),
            source="DetectionEngine",
            score_added=rule.get("score", 0),
            total_score=current_score,
            ancestry_chain=ancestry,
            correlation_id=corr_id,
            network_info=network_info,
        )

        # --- Route through IncidentManager FIRST ---
        # This stamps alert.incident_id / alert.incident_name and merges
        # into an existing incident if this PID (or an ancestor PID) was
        # already seen. Returns None only for solo LOW-noise alerts.
        incident_manager.ingest_alert(alert)

        # --- Suppression: per-rule within the same incident ---
        # Use incident_id + rule_name so different rules on the same PID
        # each get one alert but repeated identical rule+PID combos are dropped.
        if suppression_engine.should_suppress(alert):
            return

        # --- Mark process tree node ---
        if pid:
            process_tree_tracker.mark_alert(pid, final_severity)

        event_bus.publish_alert(alert)
