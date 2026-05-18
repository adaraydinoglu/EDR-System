import threading
import queue
import time
import json
from google import genai
from google.genai import types

from core.event_bus import event_bus
from models.alert_schema import AlertSchema
from core.logger import logger
from config import AI_EVALUATION_ENABLED, GEMINI_API_KEY, AI_AUTO_RESPONSE

class AIEngine:
    """
    AI-powered evaluation engine using Google Gemini API.
    Listens for Alerts, sends contextual data to Gemini, 
    and applies response actions (whitelist or kill) based on LLM output.
    """
    def __init__(self):
        self.enabled = AI_EVALUATION_ENABLED
        self.api_key = GEMINI_API_KEY
        self.auto_response = AI_AUTO_RESPONSE
        self.client = None
        self.alert_queue = queue.Queue()
        self.running = False
        self.thread = None

    def start(self):
        if not self.enabled or not self.api_key:
            logger.warning("AIEngine is disabled or API Key is missing. Skipping AI initialization.")
            return

        try:
            self.client = genai.Client(api_key=self.api_key)
            self.running = True
            self.thread = threading.Thread(target=self._worker_loop, daemon=True, name="AIEngineWorker")
            self.thread.start()
            
            # Subscribe to alerts
            event_bus.subscribe_alerts(self._on_alert)
            logger.info("AIEngine initialized and started.")
        except Exception as e:
            logger.error(f"Failed to initialize AIEngine: {e}")

    def stop(self):
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)

    def _on_alert(self, alert: AlertSchema):
        # Evaluate ALL alerts so AI can completely control risk scoring and whitelisting.
        self.alert_queue.put(alert)

    def _worker_loop(self):
        while self.running:
            try:
                alert = self.alert_queue.get(timeout=2)
                self._evaluate_alert(alert)
                self.alert_queue.task_done()
                time.sleep(2)  # Rate limiting sleep
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"AIEngine worker error: {e}")

    def _evaluate_alert(self, alert: AlertSchema):
        if not self.client:
            return

        # Prepare context payload
        context = {
            "rule_name": alert.rule_name,
            "original_severity": alert.severity,
            "process": alert.trigger_event.process_name if alert.trigger_event else "Unknown",
            "parent": alert.trigger_event.parent_name if alert.trigger_event else "Unknown",
            "cmdline": alert.trigger_event.cmdline if alert.trigger_event else "",
            "path": alert.trigger_event.path if alert.trigger_event else "",
            "ancestry_chain": alert.ancestry_chain,
            "network_info": alert.network_info
        }
        
        prompt = f"""
You are the absolute core Risk Engine of an EDR system.
Review the following security alert context. Some normal processes like browsers (Opera, Chrome, Brave) often trigger alerts because they download cache files or write to temp paths. Command prompts (CMD) might be normal or suspicious depending on the command line.
Your task is to determine if this is a false positive (is_whitelisted: true) or a genuine threat.
Provide an absolute risk score from 0 to 100 based on the REAL threat level.
Recommend an action: 'kill' if it's a critical threat, 'log' if it's suspicious but not critical, 'ignore' if it's safe.

Context:
{json.dumps(context, indent=2)}

You MUST return ONLY a raw JSON object with the following schema:
{{
    "is_whitelisted": bool,
    "ai_risk_score": int,
    "action": "kill" | "isolate" | "log" | "ignore",
    "explanation": "Brief explanation of your decision"
}}
"""
        
        try:
            response = self.client.models.generate_content(
                model='gemini-1.5-flash',
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.1,
                    response_mime_type="application/json",
                ),
            )
            
            result_text = response.text
            ai_decision = json.loads(result_text)
            
            alert.ai_analysis = ai_decision
            alert.ai_explanation = ai_decision.get("explanation", "")
            
            logger.info(f"[AIEngine] Evaluated Alert '{alert.rule_name}': Whitelisted={ai_decision.get('is_whitelisted')} | Score={ai_decision.get('ai_risk_score')} | Action={ai_decision.get('action')}")
            
            self._apply_decision(alert, ai_decision)
            
        except json.JSONDecodeError:
            logger.error(f"AIEngine: Failed to parse JSON from Gemini response. Raw: {response.text}")
        except Exception as e:
            logger.error(f"AIEngine: API request failed: {e}")

    def _apply_decision(self, alert: AlertSchema, decision: dict):
        action = decision.get("action", "log").lower()
        is_whitelist = decision.get("is_whitelisted", False)
        ai_score = decision.get("ai_risk_score", 0)
        
        # Completely override the EDR's static risk score and severity with AI's decision
        alert.total_score = ai_score
        if ai_score >= 90: alert.severity = "CRITICAL"
        elif ai_score >= 60: alert.severity = "HIGH"
        elif ai_score >= 30: alert.severity = "MEDIUM"
        else: alert.severity = "LOW"
        
        if is_whitelist:
            alert.severity = "LOW"
            logger.info(f"[AIEngine] Whitelisted process {alert.trigger_event.process_name if alert.trigger_event else 'Unknown'} based on AI evaluation.")
            
        elif action == "kill" and self.auto_response:
            from response.responder import responder
            pid = alert.trigger_event.process_id.pid if alert.trigger_event and alert.trigger_event.process_id else None
            if pid:
                logger.warning(f"[AIEngine] AI recommended KILL for PID {pid}. Executing...")
                responder._kill_process(pid, f"AI Decision: {decision.get('explanation')}")

ai_engine = AIEngine()
