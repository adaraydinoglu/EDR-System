import os
import logging

# ==========================================
# EDR SYSTEM CONFIGURATION
# Future-proof, Production-Oriented Setup
# ==========================================

# ======================
# CORE SYSTEM
# ======================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ALERTS_DIR = os.path.join(BASE_DIR, "alerts")
STORAGE_DIR = os.path.join(BASE_DIR, "storage")

os.makedirs(ALERTS_DIR, exist_ok=True)
os.makedirs(STORAGE_DIR, exist_ok=True)

# ======================
# LOGGING
# ======================
LOG_LEVEL = logging.INFO
LOG_FILE = os.path.join(ALERTS_DIR, "edr_system.log")
JSON_LOG_FILE = os.path.join(ALERTS_DIR, "alerts.json")  # Alias for ALERT_LOG_PATH
ALERT_LOG_PATH = JSON_LOG_FILE
JSON_LOGGING = True

# ======================
# CACHE
# ======================
CACHE_MAX_SIZE = 50000
CACHE_EVICTION_POLICY = "LRU"
CACHE_TTL = 7200  # 2 hours in seconds

# ======================
# CLEANUP & SUPERVISION
# ======================
CLEANUP_INTERVAL = 30  # Seconds between background cleanups
THREAD_RESTART_DELAY = 3  # Seconds before restarting a crashed collector
WATCHDOG_INTERVAL = 10  # Seconds between watchdog health checks

# ======================
# SCORING
# ======================
SCORE_DECAY_RATE = 5
CRITICAL_SCORE_THRESHOLD = 100
AUTO_KILL_THRESHOLD = 100

# ======================
# TIMELINE
# ======================
TIMELINE_WINDOW_SECONDS = 300  # 5 minutes memory for behavioral sequences
MAX_TIMELINE_EVENTS = 1000

# ======================
# SUPPRESSION
# ======================
SUPPRESSION_COOLDOWN = 3600  # 1 hour cooldown per fingerprint
SUPPRESSION_BURST_LIMIT = 5  # Max events per burst
MAX_ALERTS_PER_BURST = SUPPRESSION_BURST_LIMIT  # Alias for existing code
BURST_WINDOW_SEC = 10

# ======================
# DATABASE
# ======================
SQLITE_PATH = os.path.join(STORAGE_DIR, "edr_state.db")
DATABASE_BATCH_SIZE = 100
DATABASE_BATCH_WINDOW_SEC = 5
EVENT_RETENTION_DAYS = 7

# ======================
# MONITORING
# ======================
MONITORED_PATHS = [
    os.path.expandvars(r"%TEMP%"),
    os.path.expandvars(r"%USERPROFILE%\Downloads"),
    os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
    os.path.expandvars(r"%APPDATA%")
]
NETWORK_MONITOR_ENABLED = True
SYSMON_ENABLED = True
WMI_ENABLED = True

# ======================
# RESPONSE
# ======================
RESPONSE_ENABLED = True
QUARANTINE_ENABLED = False  # Placeholder flag for future features
