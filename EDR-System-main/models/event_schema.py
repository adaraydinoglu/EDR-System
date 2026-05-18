from dataclasses import dataclass, field
from enum import Enum, auto
import time
from typing import Dict, Any, Optional
from models.process_identity import ProcessIdentity

class EventType(Enum):
    PROCESS_CREATE = auto()
    PROCESS_TERMINATE = auto()
    FILE_CREATE = auto()
    FILE_MODIFY = auto()
    FILE_DELETE = auto()
    NETWORK_CONNECT = auto()
    TASK_CREATE = auto()
    REGISTRY_MODIFY = auto()
    PROCESS_ACCESS = auto()         # Sysmon ID 10
    CREATE_REMOTE_THREAD = auto()   # Sysmon ID 8
    DLL_LOAD = auto()               # Sysmon ID 7

@dataclass
class EventSchema:
    event_type: EventType
    timestamp: float = field(default_factory=time.time)
    process_id: Optional[ProcessIdentity] = None
    process_name: str = ""
    parent_process_id: Optional[ProcessIdentity] = None
    parent_name: str = ""
    cmdline: str = ""
    path: str = ""
    user: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    
    # Added for correlation linking
    event_id: str = ""
    
    def to_dict(self):
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.name,
            "timestamp": self.timestamp,
            "pid": self.process_id.pid if self.process_id else None,
            "process": self.process_name,
            "parent_pid": self.parent_process_id.pid if self.parent_process_id else None,
            "parent": self.parent_name,
            "cmdline": self.cmdline,
            "path": self.path,
            "user": self.user,
            "details": self.details
        }
