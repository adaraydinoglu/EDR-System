import sqlite3
import threading
import json
import time
from typing import List, Dict, Any
from config import SQLITE_PATH, EVENT_RETENTION_DAYS, DATABASE_BATCH_SIZE, DATABASE_BATCH_WINDOW_SEC
from core.logger import logger

class DatabaseManager:
    """
    SQLite backend with WAL mode and batched async-safe inserts.
    """
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(DatabaseManager, cls).__new__(cls)
            cls._instance._init()
        return cls._instance

    def _init(self):
        self.lock = threading.Lock()
        self.batch_queue = []
        self._init_db()
        self.running = True
        threading.Thread(target=self._batch_writer, daemon=True, name="DBWriter").start()

    def _get_conn(self):
        # sqlite3 connections are thread-local generally, but with check_same_thread=False
        # and our own locking, we can share it, though creating a new one per thread is safer.
        conn = sqlite3.connect(SQLITE_PATH, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self):
        with self.lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            
            # Events Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    event_type TEXT,
                    timestamp REAL,
                    pid INTEGER,
                    process_name TEXT,
                    cmdline TEXT,
                    details TEXT
                )
            ''')
            
            # Alerts Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    correlation_id TEXT,
                    rule_name TEXT,
                    severity TEXT,
                    timestamp REAL,
                    data TEXT
                )
            ''')
            
            conn.commit()
            conn.close()

    def insert_event(self, event_dict: dict):
        self.batch_queue.append({
            "type": "event",
            "data": event_dict
        })

    def insert_alert(self, alert_json: str, correlation_id: str, rule_name: str, severity: str):
        self.batch_queue.append({
            "type": "alert",
            "data": {
                "correlation_id": correlation_id,
                "rule_name": rule_name,
                "severity": severity,
                "timestamp": time.time(),
                "json": alert_json
            }
        })

    def _batch_writer(self):
        while self.running:
            time.sleep(DATABASE_BATCH_WINDOW_SEC) # Batch window
            if not self.batch_queue:
                continue
                
            batch = []
            with self.lock:
                batch = self.batch_queue[:]
                self.batch_queue.clear()
                
            if not batch:
                continue
                
            try:
                conn = self._get_conn()
                cursor = conn.cursor()
                
                for item in batch:
                    if item["type"] == "event":
                        d = item["data"]
                        cursor.execute('''
                            INSERT OR IGNORE INTO events (id, event_type, timestamp, pid, process_name, cmdline, details)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        ''', (d.get("event_id"), d.get("event_type"), d.get("timestamp"), d.get("pid"), 
                              d.get("process"), d.get("cmdline"), json.dumps(d.get("details", {}))))
                    elif item["type"] == "alert":
                        d = item["data"]
                        cursor.execute('''
                            INSERT INTO alerts (correlation_id, rule_name, severity, timestamp, data)
                            VALUES (?, ?, ?, ?, ?)
                        ''', (d["correlation_id"], d["rule_name"], d["severity"], d["timestamp"], d["json"]))
                
                conn.commit()
                conn.close()
                logger.debug(f"Batched {len(batch)} records to SQLite.")
            except Exception as e:
                logger.error(f"DB Batch Write Error: {e}")
                # Re-queue on failure
                with self.lock:
                    self.batch_queue.extend(batch)

    def cleanup_retention(self):
        try:
            cutoff = time.time() - (EVENT_RETENTION_DAYS * 86400)
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
            cursor.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff,))
            conn.commit()
            conn.close()
            logger.info("Database retention cleanup completed.")
        except Exception as e:
            logger.error(f"DB Cleanup Error: {e}")

db_manager = DatabaseManager()
