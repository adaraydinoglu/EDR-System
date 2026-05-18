from typing import List
from models.event_schema import EventType, EventSchema

CORRELATION_RULES = [
    {
        "name": "Ransomware_Behavior_File_Extension",
        "tactic": "Impact",
        "technique": "T1486",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "score": 100,
        "match": lambda recent_events, current_event: check_ransomware_extensions(recent_events, current_event)
    }
]

def check_ransomware_extensions(recent_events: List[EventSchema], current_event: EventSchema) -> bool:
    """
    Checks if there are multiple file creations with known ransomware extensions.
    """
    if current_event.event_type != EventType.FILE_CREATE:
        return False
        
    ext = current_event.details.get("file_extension", "")
    suspicious_exts = [".encrypted", ".locked", ".crypt", ".wncry"]
    
    if ext in suspicious_exts:
        # Check if we saw this recently
        count = sum(1 for e in recent_events if e.event_type == EventType.FILE_CREATE and e.details.get("file_extension") == ext)
        if count >= 3:
            return True
    return False
