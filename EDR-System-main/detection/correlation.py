"""
detection/correlation.py

Stateful correlation engine.
- Uses ProcessTreeTracker for full ancestry resolution (not just parent_name)
- Groups correlated alerts into incidents via IncidentManager
- Attaches network connection info to alerts for NETWORK_CONNECT events
"""
from core.event_bus import event_bus
from core.timeline_engine import timeline_engine
from core.suppression_engine import suppression_engine
from core.risk_engine import RiskEngine
from core.incident_manager import incident_manager
from core.process_tree_tracker import process_tree_tracker
from models.event_schema import EventSchema, EventType
from models.alert_schema import AlertSchema
from detection.correlation_rules import CORRELATION_RULES
from detection.rule_loader import load_rules
from core.logger import logger
import uuid


class CorrelationEngine:
    def __init__(self):
        # Load JSON-driven chain rules (browser→shell, shell→encoded, etc.)
        self._chain_rules = load_rules("correlation_rules.json")
        event_bus.subscribe_events(self.analyze_sequence)

    def analyze_sequence(self, event: EventSchema):
        if not event.process_id:
            return

        # 1. Legacy explicit correlation rules (e.g. ransomware extension counting)
        recent_events = timeline_engine.get_timeline(event.process_id)
        for c_rule in CORRELATION_RULES:
            try:
                if c_rule["match"](recent_events, event):
                    self._trigger_alert(c_rule, event, recent_events)
            except Exception as e:
                logger.error(f"Error in explicit correlation rule {c_rule.get('name')}: {e}")

        # 2. JSON-driven chain / ancestry rules
        for rule in self._chain_rules:
            try:
                if rule["match"](event):
                    self._trigger_alert(rule, event, recent_events[-5:])
            except Exception as e:
                logger.error(f"Error in chain rule {rule.get('name')}: {e}")

    def _trigger_alert(self, rule: dict, event: EventSchema, correlated: list):
        # Build full ancestry chain from the backend process tree
        pid = event.process_id.pid if event.process_id else None
        if pid:
            ancestry = process_tree_tracker.get_ancestry(pid)
        else:
            ancestry = self._build_simple_ancestry(event)

        # Attach network info if this is a network event
        network_info = {}
        if event.event_type == EventType.NETWORK_CONNECT:
            d = event.details or {}
            network_info = {
                "dst_ip":   d.get("dst_ip", d.get("remote_ip", "")),
                "dst_port": d.get("dst_port", d.get("remote_port", "")),
                "proto":    d.get("proto", d.get("protocol", "TCP")),
            }
        elif pid:
            # Pull any network connections the process already has
            conns = process_tree_tracker.get_network_connections(pid)
            if conns:
                network_info = conns[-1]   # Most recent connection

        # Suppression check
        temp_alert = AlertSchema(
            rule_name=rule["name"],
            severity=rule.get("severity", "HIGH"),
            confidence=rule.get("confidence", "HIGH"),
            tactic=rule.get("tactic", "Unknown"),
            technique=rule.get("technique", "Unknown"),
            mitre_id=rule.get("mitre_id", rule.get("technique", "")),
            source="CorrelationEngine",
            trigger_event=event,
            ancestry_chain=ancestry,
        )

        if suppression_engine.should_suppress(temp_alert):
            return

        # Cumulative risk
        current_score = 0
        if event.process_id:
            current_score, final_severity = RiskEngine.update_cumulative_risk(
                event.process_id, rule.get("score", 0)
            )
        else:
            current_score  = rule.get("score", 0)
            final_severity = temp_alert.severity

        # Never downgrade below the rule's declared severity
        sev_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        computed = RiskEngine.get_severity_for_score(current_score)
        if sev_order.get(computed, 0) < sev_order.get(temp_alert.severity, 0):
            final_severity = temp_alert.severity

        corr_id = str(uuid.uuid4())[:8].upper()

        alert = AlertSchema(
            rule_name=rule["name"],
            severity=final_severity,
            confidence=temp_alert.confidence,
            tactic=temp_alert.tactic,
            technique=temp_alert.technique,
            technique_name=rule.get("technique_name", ""),
            mitre_id=temp_alert.mitre_id,
            source="CorrelationEngine",
            trigger_event=event,
            correlated_event_ids=[e.event_id for e in correlated[-5:] if e.event_id],
            score_added=rule.get("score", 0),
            total_score=current_score,
            ancestry_chain=ancestry,
            correlation_id=corr_id,
            network_info=network_info,
        )

        # Mark the process tree node with this severity
        if pid:
            process_tree_tracker.mark_alert(pid, final_severity)

        # Group into an incident (also stamps alert.incident_id / alert.incident_name)
        incident_manager.ingest_alert(alert)

        event_bus.publish_alert(alert)

    def _build_simple_ancestry(self, event: EventSchema) -> list:
        chain = []
        if event.parent_name:
            chain.append(event.parent_name)
        if event.process_name:
            chain.append(event.process_name)
        return chain
