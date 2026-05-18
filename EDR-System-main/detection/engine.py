from core.event_bus import event_bus
from models.event_schema import EventSchema
from models.alert_schema import AlertSchema
from detection.rules import RULES
from detection.correlation_rules import CORRELATION_RULES
from core.cache_manager import cache_manager
from core.scoring import ScoringEngine
from core.logger import logger
from config import CRITICAL_SCORE_THRESHOLD

class DetectionEngine:
    def __init__(self):
        # Subscribe to events
        event_bus.subscribe_events(self.analyze_event)

    def analyze_event(self, event: EventSchema):
        # Add to recent events cache for stateful correlation
        cache_manager.add_recent_event(event)

        # 1. Stateless Rules
        for rule in RULES:
            try:
                if rule["match"](event):
                    self._trigger_alert(rule, event, [])
            except Exception as e:
                logger.error(f"Error in rule {rule.get('name')}: {e}")

        # 2. Stateful Correlation Rules
        recent_events = cache_manager.get_recent_events()
        for c_rule in CORRELATION_RULES:
            try:
                if c_rule["match"](recent_events, event):
                    # We pass recent_events as correlated context (can be optimized to pass only matches)
                    self._trigger_alert(c_rule, event, recent_events[-5:]) 
            except Exception as e:
                logger.error(f"Error in correlation rule {c_rule.get('name')}: {e}")

    def _trigger_alert(self, rule: dict, event: EventSchema, correlated: list):
        # Add score
        current_score = 0
        if event.process_id:
            current_score = ScoringEngine.add_score(event.process_id, rule["score"])
        else:
            current_score = rule["score"]

        alert = AlertSchema(
            rule_name=rule["name"],
            severity=rule["severity"],
            confidence=rule["confidence"],
            tactic=rule["tactic"],
            technique=rule["technique"],
            mitre_id=rule.get("mitre_id", rule.get("technique", "")),
            source="DetectionEngine",
            trigger_event=event,
            correlated_event_ids=[e.event_id for e in correlated if e.event_id],
            score_added=rule["score"],
            total_score=current_score
        )
        
        # Publish Alert
        event_bus.publish_alert(alert)
