from dataclasses import dataclass, field
import time
from typing import Dict, Any, List, Optional
from models.event_schema import EventSchema
import json

@dataclass
class AlertSchema:
    rule_name: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    confidence: str # HIGH, MEDIUM, LOW
    tactic: str
    technique: str
    mitre_id: str  # e.g., T1059
    source: str    # Which collector generated it
    trigger_event: EventSchema
    correlated_event_ids: List[str] = field(default_factory=list)
    timeline_id: Optional[str] = None
    parent_process: str = ""
    ancestry_chain: List[str] = field(default_factory=list)
    detection_stage: str = "Initial Access" # Default stage
    response_action: str = "Log" # Log, Isolate, Kill, Quarantine
    score_added: int = 0
    total_score: int = 0
    timestamp: float = field(default_factory=time.time)
    correlation_id: str = ""

    def to_json(self):
        return json.dumps({
            "timestamp": self.timestamp,
            "correlation_id": self.correlation_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "confidence": self.confidence,
            "tactic": self.tactic,
            "technique": self.technique,
            "mitre_id": self.mitre_id,
            "source": self.source,
            "score_added": self.score_added,
            "total_score": self.total_score,
            "timeline_id": self.timeline_id,
            "detection_stage": self.detection_stage,
            "response_action": self.response_action,
            "parent_process": self.parent_process,
            "ancestry_chain": self.ancestry_chain,
            "trigger_event": self.trigger_event.to_dict() if self.trigger_event else {},
            "correlated_event_ids": self.correlated_event_ids
        })
