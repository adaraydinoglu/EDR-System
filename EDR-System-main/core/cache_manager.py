import threading
import time
from typing import Dict, Any, List, Optional
from models.process_identity import ProcessIdentity
from models.event_schema import EventSchema
from config import CACHE_MAX_SIZE, CACHE_EVICTION_POLICY, CACHE_TTL
from core.logger import logger

class CacheManager:
    """
    Centralized thread-safe cache with TTL and Eviction policies.
    """
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(CacheManager, cls).__new__(cls)
            cls._instance._init()
        return cls._instance

    def _init(self):
        self.lock = threading.RLock()
        
        # Dicts keeping (timestamp, data) for TTL
        self.process_cache: Dict[ProcessIdentity, Tuple[float, Dict[str, Any]]] = {}
        self.score_cache: Dict[ProcessIdentity, Tuple[float, int]] = {}
        
        self.recent_events: List[EventSchema] = []

    def add_process(self, identity: ProcessIdentity, details: Dict[str, Any]):
        with self.lock:
            self._enforce_size_limit(self.process_cache)
            self.process_cache[identity] = (time.time(), details)

    def get_process(self, identity: ProcessIdentity) -> Dict[str, Any]:
        with self.lock:
            item = self.process_cache.get(identity)
            if item:
                # Update access time (LRU behavior)
                self.process_cache[identity] = (time.time(), item[1])
                return item[1]
            return {}
            
    def remove_process(self, identity: ProcessIdentity):
        with self.lock:
            self.process_cache.pop(identity, None)

    def add_score(self, identity: ProcessIdentity, score: int) -> int:
        with self.lock:
            self._enforce_size_limit(self.score_cache)
            current_time, current_score = self.score_cache.get(identity, (time.time(), 0))
            new_score = current_score + score
            self.score_cache[identity] = (time.time(), new_score)
            return new_score
            
    def get_score(self, identity: ProcessIdentity) -> int:
        with self.lock:
            item = self.score_cache.get(identity)
            return item[1] if item else 0

    def remove_score(self, identity: ProcessIdentity):
        with self.lock:
            self.score_cache.pop(identity, None)

    def add_recent_event(self, event: EventSchema):
        with self.lock:
            self.recent_events.append(event)
            if len(self.recent_events) > CACHE_MAX_SIZE:
                self.recent_events.pop(0)

    def get_recent_events(self) -> List[EventSchema]:
        with self.lock:
            return list(self.recent_events)

    def _enforce_size_limit(self, cache_dict: dict):
        if len(cache_dict) >= CACHE_MAX_SIZE:
            if CACHE_EVICTION_POLICY == "LRU":
                # Find oldest access time
                oldest_key = min(cache_dict.keys(), key=lambda k: cache_dict[k][0])
                del cache_dict[oldest_key]
            else:
                # Random/Arbitrary eviction
                del cache_dict[next(iter(cache_dict))]

    def cleanup_ttl(self):
        current_time = time.time()
        with self.lock:
            # Cleanup process cache
            expired_procs = [k for k, (ts, _) in self.process_cache.items() if current_time - ts > CACHE_TTL]
            for k in expired_procs:
                del self.process_cache[k]
                
            # Cleanup score cache
            expired_scores = [k for k, (ts, _) in self.score_cache.items() if current_time - ts > CACHE_TTL]
            for k in expired_scores:
                del self.score_cache[k]

cache_manager = CacheManager()
