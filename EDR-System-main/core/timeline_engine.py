import threading
import time
from typing import Dict, List
from models.event_schema import EventSchema
from models.process_identity import ProcessIdentity
from core.cache_manager import cache_manager
from config import TIMELINE_WINDOW_SECONDS
from core.logger import logger

class TimelineEngine:
    """
    Builds behavioral timelines per process identity.
    Tracks sequencing of events across a sliding window.
    """
    def __init__(self):
        self.lock = threading.RLock()
        # Mapping process to a list of events within the window
        self.timelines: Dict[ProcessIdentity, List[EventSchema]] = {}

    def add_event(self, event: EventSchema):
        if not event.process_id:
            return

        with self.lock:
            if event.process_id not in self.timelines:
                self.timelines[event.process_id] = []
            
            self.timelines[event.process_id].append(event)
            self._prune_timeline(event.process_id)

    def _prune_timeline(self, identity: ProcessIdentity):
        # Sliding time window logic
        cutoff = time.time() - TIMELINE_WINDOW_SECONDS
        timeline = self.timelines[identity]
        self.timelines[identity] = [e for e in timeline if e.timestamp >= cutoff]

    def get_timeline(self, identity: ProcessIdentity) -> List[EventSchema]:
        with self.lock:
            return list(self.timelines.get(identity, []))

    def get_ancestry_timeline(self, identity: ProcessIdentity, levels: int = 3) -> List[EventSchema]:
        """
        Gathers timeline events not just for the process, but its parents up to N levels.
        """
        combined = []
        current_identity = identity
        
        for _ in range(levels):
            if not current_identity:
                break
                
            combined.extend(self.get_timeline(current_identity))
            
            # Fetch parent identity from cache
            details = cache_manager.get_process(current_identity)
            parent_pid = details.get("parent_pid")
            
            if not parent_pid:
                break
                
            # Attempt to resolve parent identity. 
            # In a real scenario, parent create_time needs to be looked up.
            # We simplify here for demonstration.
            resolved_parent = None
            for cached_id in cache_manager.process_cache.keys():
                if cached_id.pid == parent_pid:
                    resolved_parent = cached_id
                    break
                    
            current_identity = resolved_parent

        # Sort by timestamp
        return sorted(combined, key=lambda e: e.timestamp)

timeline_engine = TimelineEngine()
