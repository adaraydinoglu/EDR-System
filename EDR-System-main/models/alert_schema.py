from dataclasses import dataclass, field
import time
from typing import Dict, Any, List, Optional
from models.event_schema import EventSchema
import json

@dataclass
class AlertSchema:
    # ── Required (no defaults) ───────────────────────────────────────────────
    rule_name:      str
    severity:       str           # CRITICAL, HIGH, MEDIUM, LOW
    confidence:     str           # HIGH, MEDIUM, LOW
    tactic:         str
    technique:      str           # MITRE technique ID, e.g. T1059.001
    trigger_event:  EventSchema   # The raw event that triggered this alert

    # ── Optional (with defaults) ─────────────────────────────────────────────
    technique_name: str  = ""     # Human-readable name, e.g. "PowerShell"
    mitre_id:       str  = ""     # Canonical MITRE ID (parent or same as technique)
    source:         str  = ""     # Which engine produced this alert
    correlated_event_ids: List[str] = field(default_factory=list)
    timeline_id:    Optional[str] = None
    parent_process: str  = ""
    ancestry_chain: List[str] = field(default_factory=list)
    detection_stage: str = "Initial Access"
    response_action: str = "Log"  # Log, Isolate, Kill, Quarantine
    score_added:    int  = 0
    total_score:    int  = 0
    timestamp:      float = field(default_factory=time.time)
    correlation_id: str  = ""
    ai_explanation: str  = ""
    ai_analysis:    Dict[str, Any] = field(default_factory=dict)
    # ── Incident grouping ─────────────────────────────────────────────────────
    incident_id:    str  = ""     # Shared ID for all alerts in one incident
    incident_name:  str  = ""     # Human-readable incident name
    network_info:   Dict[str, Any] = field(default_factory=dict)  # dst_ip, dst_port, proto

    def to_json(self):
        return json.dumps({
            "timestamp":      self.timestamp,
            "correlation_id": self.correlation_id,
            "incident_id":    self.incident_id,
            "incident_name":  self.incident_name,
            "rule_name":      self.rule_name,
            "severity":       self.severity,
            "confidence":     self.confidence,
            "tactic":         self.tactic,
            "technique":      self.technique,
            "technique_name": self.technique_name,
            "mitre_id":       self.mitre_id,
            "source":         self.source,
            "score_added":    self.score_added,
            "total_score":    self.total_score,
            "risk":           self.total_score,
            "timeline_id":    self.timeline_id,
            "detection_stage":  self.detection_stage,
            "response_action":  self.response_action,
            "process":          self.trigger_event.process_name if self.trigger_event else "",
            "parent_process":   self.trigger_event.parent_name  if self.trigger_event else self.parent_process,
            "commandline":      self.trigger_event.cmdline       if self.trigger_event else "",
            "ai_explanation":   self.ai_explanation,
            "ai_analysis":      self.ai_analysis,
            "ancestry_chain":   self.ancestry_chain,
            "network_info":     self.network_info,
            "trigger_event":    self.trigger_event.to_dict() if self.trigger_event else {},
            "correlated_event_ids": self.correlated_event_ids
        })
