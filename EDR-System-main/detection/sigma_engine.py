from typing import List, Dict, Any, Callable
from models.event_schema import EventSchema, EventType
from models.alert_schema import AlertSchema
from core.event_bus import event_bus
from core.timeline_engine import timeline_engine
from core.suppression_engine import suppression_engine
from core.scoring import ScoringEngine
from storage.database import db_manager
from core.logger import logger
import uuid

class SigmaEngine:
    """
    Evaluates YAML/Dict based Sigma-like rules and complex stateful behavioral chains.
    """
    def __init__(self):
        self.rules = self._load_rules()
        event_bus.subscribe_events(self.analyze_event)

    def _load_rules(self) -> List[Dict]:
        return [
            # 1. Credential Dumping (LSASS Access)
            {
                "name": "LSASS_Memory_Dump",
                "tactic": "Credential Access",
                "technique": "OS Credential Dumping",
                "mitre_id": "T1003.001",
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "score": 100,
                "response_action": "Kill",
                "condition": lambda e, tl: (
                    e.event_type == EventType.PROCESS_ACCESS
                    and "lsass.exe" in e.details.get("target_image", "").lower()
                    and any(mask in e.details.get("granted_access", "") for mask in ["0x1010", "0x1410", "0x1f0fff"])
                )
            },
            # 2. Behavioral Injection Chain (Multi-Event)
            {
                "name": "Process_Injection_Chain",
                "tactic": "Privilege Escalation",
                "technique": "Process Injection",
                "mitre_id": "T1055",
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "score": 100,
                "response_action": "Kill",
                "condition": self._detect_injection_chain
            },
            # 3. Encoded PowerShell + Network (Timeline Correlation)
            {
                "name": "Suspicious_PS_Network_Activity",
                "tactic": "Execution",
                "technique": "PowerShell",
                "mitre_id": "T1059.001",
                "severity": "HIGH",
                "confidence": "MEDIUM",
                "score": 80,
                "response_action": "Isolate",
                "condition": self._detect_ps_network_chain
            }
        ]

    def _detect_injection_chain(self, current_event: EventSchema, timeline: List[EventSchema]) -> bool:
        # Looking for CreateRemoteThread following a sequence of events.
        if current_event.event_type != EventType.CREATE_REMOTE_THREAD:
            return False
            
        target = current_event.details.get("target_image", "")
        # Very simplified check: Did this process also open handle to the target recently?
        # In a real scenario, we'd check Sysmon Event 10 -> Event 8 sequence.
        has_access = any(
            e.event_type == EventType.PROCESS_ACCESS and e.details.get("target_image", "") == target
            for e in timeline
        )
        return has_access

    def _detect_ps_network_chain(self, current_event: EventSchema, timeline: List[EventSchema]) -> bool:
        if current_event.event_type != EventType.NETWORK_CONNECT:
            return False
            
        if "powershell.exe" not in current_event.process_name.lower():
            return False

        # Look in ancestry timeline for encoded command execution
        has_encoded = any(
            e.event_type == EventType.PROCESS_CREATE 
            and "powershell.exe" in e.process_name.lower()
            and "-enc" in e.cmdline.lower()
            for e in timeline
        )
        return has_encoded

    def analyze_event(self, event: EventSchema):
        # 1. Update timeline
        timeline_engine.add_event(event)
        
        # 2. Get ancestry-aware timeline context
        timeline_context = []
        if event.process_id:
            timeline_context = timeline_engine.get_ancestry_timeline(event.process_id)

        # 3. Evaluate Rules
        for rule in self.rules:
            try:
                if rule["condition"](event, timeline_context):
                    self._trigger_alert(rule, event, timeline_context)
            except Exception as e:
                logger.error(f"Rule evaluation error ({rule.get('name')}): {e}")

    def _trigger_alert(self, rule: dict, trigger_event: EventSchema, timeline: List[EventSchema]):
        # Calculate scores
        current_score = rule["score"]
        if trigger_event.process_id:
            current_score = ScoringEngine.add_score(trigger_event.process_id, rule["score"])

        correlation_id = str(uuid.uuid4())
        
        # Build ancestry chain strings
        ancestry = [e.process_name for e in timeline if e.event_type == EventType.PROCESS_CREATE]
        
        alert = AlertSchema(
            rule_name=rule["name"],
            severity=rule["severity"],
            confidence=rule["confidence"],
            tactic=rule["tactic"],
            technique=rule["technique"],
            mitre_id=rule["mitre_id"],
            source="SigmaEngine",
            trigger_event=trigger_event,
            correlated_event_ids=[e.event_id for e in timeline if e.event_id],
            timeline_id=trigger_event.process_id.pid if trigger_event.process_id else None,
            parent_process=trigger_event.parent_name,
            ancestry_chain=ancestry,
            response_action=rule["response_action"],
            score_added=rule["score"],
            total_score=current_score,
            correlation_id=correlation_id
        )

        # 4. Suppression Engine Check
        if suppression_engine.should_suppress(alert):
            logger.debug(f"Suppressed alert: {alert.rule_name} for {alert.trigger_event.process_name}")
            return

        # 5. Persist to DB
        db_manager.insert_alert(alert.to_json(), correlation_id, alert.rule_name, alert.severity)

        # 6. Publish to Event Bus for Response Layer
        event_bus.publish_alert(alert)

sigma_engine = SigmaEngine()
