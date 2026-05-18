from core.cache_manager import cache_manager
from models.process_identity import ProcessIdentity
from config import SCORE_DECAY_RATE, CRITICAL_SCORE_THRESHOLD
from core.logger import logger

class ScoringEngine:
    @staticmethod
    def add_score(identity: ProcessIdentity, score: int) -> int:
        if not identity:
            return 0
        total = cache_manager.add_score(identity, score)
        logger.debug(f"Added {score} to {identity}. Total: {total}")
        return total

    @staticmethod
    def decay_scores():
        """
        Periodically reduces the score of processes to prevent false positives
        from accumulating over a long period.
        """
        with cache_manager.lock:
            to_remove = []
            for identity, (ts, current_score) in list(cache_manager.score_cache.items()):
                new_score = max(0, current_score - SCORE_DECAY_RATE)
                cache_manager.score_cache[identity] = (ts, new_score)
                if new_score == 0:
                    to_remove.append(identity)

            for identity in to_remove:
                cache_manager.remove_score(identity)