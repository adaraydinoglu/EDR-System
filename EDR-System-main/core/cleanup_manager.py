import threading
import time
from config import CLEANUP_INTERVAL
from core.cache_manager import cache_manager
from core.scoring import ScoringEngine
from storage.database import db_manager
from core.logger import logger
from core.suppression_engine import suppression_engine

class CleanupManager:
    """
    Global background thread responsible for cleaning up stale data across all caches.
    Prevents memory leaks and mitigates PID reuse artifacts.
    """
    def __init__(self):
        self.running = False
        self.thread = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._cleanup_loop, daemon=True, name="CleanupManager")
        self.thread.start()
        logger.info("Cleanup Manager started.")

    def stop(self):
        self.running = False

    def _cleanup_loop(self):
        while self.running:
            try:
                time.sleep(CLEANUP_INTERVAL)
                self._perform_cleanup()
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")

    def _perform_cleanup(self):
        # 1. Decay Scores
        ScoringEngine.decay_scores()
        
        # 2. Cache TTL & Eviction
        cache_manager.cleanup_ttl()
        
        # 3. Suppression Engine Cooldowns
        suppression_engine.cleanup()
        
        # 4. Database Retention Cleanup (Run less frequently in real app, but ok here)
        db_manager.cleanup_retention()

cleanup_manager = CleanupManager()
