"""
core/ai_engine.py

AI-powered evaluation engine using Google Gemini.

Key improvements:
  - KNOWN_SAFE_PROCESSES fast-path: skip API for browsers/system apps
  - Robust JSON extraction (handles plain JSON and markdown code blocks)
  - 3-attempt retry with exponential backoff
  - After AI decision, re-publishes updated incident to GUI for live colour update
  - No response_mime_type (incompatible with older google-genai builds)
"""

import threading
import queue
import time
import json
import re

from google import genai

from core.event_bus import event_bus
from models.alert_schema import AlertSchema
from core.logger import logger
from config import AI_EVALUATION_ENABLED, GEMINI_API_KEY, AI_AUTO_RESPONSE


# ── Known-safe process list ───────────────────────────────────────────────────
# Alarms from these processes are whitelisted WITHOUT an API call unless the
# command-line contains a known malicious token.
KNOWN_SAFE_PROCESSES = {
    "opera.exe", "opera_crashreporter.exe", "opera_autoupdate.exe",
    "chrome.exe", "chromium.exe", "brave.exe", "firefox.exe",
    "msedge.exe", "iexplore.exe", "safari.exe",
    "explorer.exe", "svchost.exe", "services.exe",
    "winlogon.exe", "lsass.exe", "csrss.exe",
    "taskhostw.exe", "sihost.exe", "fontdrvhost.exe",
    "ctfmon.exe", "dllhost.exe", "conhost.exe",
    "code.exe", "devenv.exe", "git.exe", "node.exe",
    "spotify.exe", "discord.exe", "teams.exe",
    "onedrive.exe", "dropbox.exe",
}

# Command-line tokens that override the safe-list (always needs AI review)
MALICIOUS_TOKENS = [
    "-enc", "-encodedcommand", "downloadstring",
    "invoke-expression", "iex ", "bypass",
    "mimikatz", "sekurlsa", "shadowcopy", "lsadump",
]


class AIEngine:
    """
    Subscribes to the alert channel, evaluates each alert with Gemini,
    then re-publishes the updated incident so the GUI row colour updates live.
    """

    def __init__(self):
        self.enabled      = AI_EVALUATION_ENABLED
        self.api_key      = GEMINI_API_KEY
        self.auto_response = AI_AUTO_RESPONSE
        self.client       = None
        self.alert_queue  = queue.Queue()
        self.running      = False
        self.thread       = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        if not self.enabled or not self.api_key:
            logger.warning("AIEngine disabled or API key missing — skipping.")
            return
        try:
            self.client  = genai.Client(api_key=self.api_key)
            self.running = True
            self.thread  = threading.Thread(
                target=self._worker_loop, daemon=True, name="AIEngineWorker"
            )
            self.thread.start()
            event_bus.subscribe_alerts(self._on_alert)
            logger.info("AIEngine initialized and started.")
        except Exception as e:
            logger.error(f"Failed to initialize AIEngine: {e}")

    def stop(self):
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)

    # ── Alert ingestion ───────────────────────────────────────────────────────

    def _on_alert(self, alert: AlertSchema):
        self.alert_queue.put(alert)

    def _worker_loop(self):
        while self.running:
            try:
                alert = self.alert_queue.get(timeout=2)
                self._evaluate_alert(alert)
                self.alert_queue.task_done()
                time.sleep(1)   # gentle rate-limiting between evaluations
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"AIEngine worker error: {e}")

    # ── JSON extraction ───────────────────────────────────────────────────────

    def _extract_json(self, text: str) -> dict:
        """
        Robustly extract a JSON object from Gemini's response text.
        Handles: plain JSON, ```json ... ```, and JSON embedded in prose.
        """
        # 1. Direct parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # 2. Markdown code block
        m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except json.JSONDecodeError:
                pass

        # 3. First JSON object found in text
        m = re.search(r"\{[^{}]+\}", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                pass

        raise ValueError(f"No valid JSON found in response: {text[:300]}")

    # ── Evaluation ────────────────────────────────────────────────────────────

    def _evaluate_alert(self, alert: AlertSchema):
        if not self.client:
            return

        proc    = (alert.trigger_event.process_name or "").lower() if alert.trigger_event else ""
        cmdline = (alert.trigger_event.cmdline or "").lower()      if alert.trigger_event else ""
        path    = (alert.trigger_event.path    or "")              if alert.trigger_event else ""

        # ── Fast-path whitelist ───────────────────────────────────────────────
        is_malicious_cmd = any(tok in cmdline for tok in MALICIOUS_TOKENS)
        if proc in KNOWN_SAFE_PROCESSES and not is_malicious_cmd:
            decision = {
                "is_whitelisted": True,
                "ai_risk_score":  5,
                "action":         "ignore",
                "explanation":    (
                    f"{proc} is a known-safe application. "
                    "Writing to temp/AppData or making network connections is normal behaviour."
                ),
            }
            logger.info(f"[AIEngine] Fast-path whitelist: {proc}")
            self._apply_decision(alert, decision)
            return

        # ── Build Gemini prompt ───────────────────────────────────────────────
        context = {
            "rule_name":        alert.rule_name,
            "original_severity": alert.severity,
            "process":          alert.trigger_event.process_name if alert.trigger_event else "Unknown",
            "parent":           alert.trigger_event.parent_name  if alert.trigger_event else "Unknown",
            "cmdline":          cmdline,
            "path":             path,
            "ancestry_chain":   alert.ancestry_chain,
            "network_info":     alert.network_info,
        }

        prompt = (
            "You are the risk analysis core of a Windows EDR security system.\n"
            "Review this alert and decide: false positive or real threat?\n\n"
            "RULES:\n"
            "- Browsers (Opera, Chrome, Firefox, Edge, Brave) writing to AppData/Temp = NORMAL cache. Score 0-10.\n"
            "- System processes (svchost, explorer, lsass, services) doing routine work = NORMAL. Score 0-15.\n"
            "- CMD/PowerShell is suspicious ONLY with -enc, downloadstring, invoke-expression, mimikatz, bypass flags.\n"
            "- CMD/PowerShell with simple commands (dir, ipconfig, echo) = NOT suspicious. Score 0-20.\n"
            "- Score 0-29=LOW  30-59=MEDIUM  60-89=HIGH  90-100=CRITICAL\n\n"
            f"Alert:\n{json.dumps(context, indent=2)}\n\n"
            "Return ONLY raw JSON (no markdown fences, no extra text):\n"
            '{"is_whitelisted": true/false, "ai_risk_score": 0-100, '
            '"action": "kill|isolate|log|ignore", "explanation": "..."}'
        )

        # ── Call API with retry ───────────────────────────────────────────────
        last_err = None
        for attempt in range(3):
            try:
                response = self.client.models.generate_content(
                    model="gemini-1.5-flash",
                    contents=prompt,
                )
                decision = self._extract_json(response.text)
                alert.ai_analysis    = decision
                alert.ai_explanation = decision.get("explanation", "")
                logger.info(
                    f"[AIEngine] '{alert.rule_name}' → "
                    f"Whitelisted={decision.get('is_whitelisted')} | "
                    f"Score={decision.get('ai_risk_score')} | "
                    f"Action={decision.get('action')}"
                )
                self._apply_decision(alert, decision)
                return
            except Exception as e:
                last_err = e
                logger.warning(f"[AIEngine] Attempt {attempt + 1}/3 failed: {e}")
                time.sleep(2 ** attempt)   # 1 s, 2 s, 4 s

        logger.error(f"[AIEngine] All retries failed for '{alert.rule_name}': {last_err}")

    # ── Apply decision ────────────────────────────────────────────────────────

    def _apply_decision(self, alert: AlertSchema, decision: dict):
        is_whitelist = decision.get("is_whitelisted", False)
        ai_score     = int(decision.get("ai_risk_score", alert.total_score))
        action       = decision.get("action", "log").lower()

        # Override EDR's static score/severity with AI's verdict
        alert.total_score = ai_score
        if is_whitelist or ai_score < 30:
            alert.severity = "LOW"
        elif ai_score < 60:
            alert.severity = "MEDIUM"
        elif ai_score < 90:
            alert.severity = "HIGH"
        else:
            alert.severity = "CRITICAL"

        if is_whitelist:
            logger.info(
                f"[AIEngine] Whitelisted: "
                f"{alert.trigger_event.process_name if alert.trigger_event else 'Unknown'} "
                f"— {decision.get('explanation', '')}"
            )

        # ── Re-publish incident so GUI row updates colour live ────────────────
        if alert.incident_id:
            try:
                from core.incident_manager import incident_manager
                updated = incident_manager.get_by_id(alert.incident_id)
                if updated:
                    updated["severity"]       = alert.severity
                    updated["ai_explanation"] = alert.ai_explanation
                    event_bus.publish_incident(updated)
            except Exception as e:
                logger.error(f"[AIEngine] Failed to re-publish incident: {e}")

        # ── Auto-kill (only for genuine threats) ──────────────────────────────
        if action == "kill" and self.auto_response and not is_whitelist:
            from response.responder import responder
            pid = (
                alert.trigger_event.process_id.pid
                if alert.trigger_event and alert.trigger_event.process_id
                else None
            )
            if pid:
                logger.warning(
                    f"[AIEngine] KILL PID {pid}: {decision.get('explanation', '')}"
                )
                responder._kill_process(pid, f"AI: {decision.get('explanation', '')}")


ai_engine = AIEngine()
