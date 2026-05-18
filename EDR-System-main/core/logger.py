import logging
import json
import logging.handlers
from config import LOG_FILE, JSON_LOG_FILE, LOG_LEVEL

class EDRLogger:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(EDRLogger, cls).__new__(cls)
            cls._instance._setup_loggers()
        return cls._instance

    def _setup_loggers(self):
        self.logger = logging.getLogger("EDR_MAIN")
        self.logger.setLevel(LOG_LEVEL)

        # Console Handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_format = logging.Formatter('%(asctime)s - [%(levelname)s] - %(message)s')
        console_handler.setFormatter(console_format)
        
        # File Handler (General logs)
        file_handler = logging.handlers.RotatingFileHandler(
            LOG_FILE, maxBytes=5*1024*1024, backupCount=3
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(console_format)

        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)
        
        # JSON Alert Logger
        self.alert_logger = logging.getLogger("EDR_ALERTS")
        self.alert_logger.setLevel(logging.INFO)
        
        json_handler = logging.handlers.RotatingFileHandler(
            JSON_LOG_FILE, maxBytes=10*1024*1024, backupCount=5
        )
        json_handler.setLevel(logging.INFO)
        json_handler.setFormatter(logging.Formatter('%(message)s')) # Just raw JSON
        self.alert_logger.addHandler(json_handler)

    def info(self, msg):
        self.logger.info(msg)

    def debug(self, msg):
        self.logger.debug(msg)

    def warning(self, msg):
        self.logger.warning(msg)

    def error(self, msg):
        self.logger.error(msg)
        
    def log_alert(self, alert_json):
        self.alert_logger.info(alert_json)

logger = EDRLogger()
