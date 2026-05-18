from typing import Optional, Dict, Any
from models.process_identity import ProcessIdentity
from core.cache_manager import cache_manager
from core.logger import logger

class ProcessManager:
    """
    Manages process lifecycles, tracking creations and terminations to handle PID reuse.
    """
    
    @staticmethod
    def register_process(identity: ProcessIdentity, details: Dict[str, Any]):
        cache_manager.add_process(identity, details)
        logger.debug(f"Process registered: {identity} ({details.get('name', 'Unknown')})")

    @staticmethod
    def unregister_process(identity: ProcessIdentity):
        cache_manager.remove_process(identity)
        # Also clean up score if process dies
        cache_manager.remove_score(identity)
        logger.debug(f"Process unregistered and cleaned up: {identity}")

    @staticmethod
    def get_process_details(identity: ProcessIdentity) -> Dict[str, Any]:
        return cache_manager.get_process(identity)
