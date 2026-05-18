from models.event_schema import EventSchema, EventType
from models.process_identity import ProcessIdentity
from core.cache_manager import cache_manager
from core.logger import logger
from typing import Tuple


class RiskEngine:
    """
    Centralized Risk Engine.

    Evaluates per-event risk, maintains cumulative process scores, maps
    scores to severity levels, and applies contextual whitelisting so
    that trusted applications still trigger alerts when they behave
    suspiciously (e.g. Brave → PowerShell → encoded command).
    """

    # ── Base process risk weights ────────────────────────────────────────────
    PROCESS_RISK: dict = {
        "powershell.exe": 20,
        "pwsh.exe":       20,
        "cmd.exe":        10,
        "wscript.exe":    30,
        "cscript.exe":    30,
        "mshta.exe":      40,
        "certutil.exe":   40,
        "regsvr32.exe":   35,
        "rundll32.exe":   30,
        "msbuild.exe":    35,
        "bitsadmin.exe":  40,
    }

    # ── Contextual trust: reduce risk ONLY when behaviour is clean ───────────
    # These processes are trusted at face value but NOT blindly.
    # A trusted parent spawning a shell, or a trusted process with a
    # suspicious commandline, will still score full risk.
    TRUSTED_PROCESSES: set = {
        "explorer.exe", "svchost.exe", "services.exe",
        "brave.exe", "chrome.exe", "chromium.exe", "firefox.exe", "msedge.exe",
        "opera.exe", "opera_crashreporter.exe", "opera_autoupdate.exe",
        "iexplore.exe",
        "code.exe", "devenv.exe", "winlogon.exe", "lsass.exe",
        "taskhostw.exe", "sihost.exe", "ctfmon.exe", "dllhost.exe",
        "spotify.exe", "discord.exe", "teams.exe",
        "onedrive.exe", "dropbox.exe", "git.exe", "node.exe",
    }

    # ── Suspicious commandline tokens and their risk additions ──────────────
    CMDLINE_RISKS: list = [
        (40, ["-enc", "-encodedcommand"]),
        (30, ["downloadstring", "invoke-webrequest"]),
        (25, ["invoke-expression", "iex "]),
        (20, ["bypass", "-nop", "-noprofile"]),
        (15, ["hidden", "-windowstyle hidden"]),
        (20, ["net user", "net localgroup"]),
        (30, ["mimikatz", "sekurlsa", "lsadump"]),
        (30, ["process call create"]),           # WMIC lateral movement
        (30, ["delete shadows", "shadowcopy delete"]),  # Ransomware prep
    ]

    @staticmethod
    def evaluate_event(event: EventSchema) -> Tuple[int, str]:
        """
        Evaluate a single event, mutate event.risk_score / event.severity,
        and return (event_risk_score, severity).
        """
        score = 0
        proc_name = event.process_name.lower()
        cmdline   = event.cmdline.lower()
        path      = event.path.lower()

        # 1. Base process risk
        score += RiskEngine.PROCESS_RISK.get(proc_name, 0)

        # 2. Commandline modifiers
        for risk_delta, tokens in RiskEngine.CMDLINE_RISKS:
            if any(tok in cmdline for tok in tokens):
                score += risk_delta

        # 3. Path modifiers — skip for trusted processes (browsers write to temp/appdata constantly)
        is_trusted = proc_name in RiskEngine.TRUSTED_PROCESSES
        if not is_trusted and any(frag in path for frag in ["\\temp\\", "\\tmp\\", "appdata"]):
            # Executable or script dropped in temp is a major indicator
            suspicious_exts = (".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".vbe", ".wsf", ".hta")
            if event.event_type == EventType.FILE_CREATE and path.endswith(suspicious_exts):
                score += 50
            elif event.event_type == EventType.FILE_CREATE:
                score += 15  # Generic file creation in monitored temp/appdata path
            else:
                score += 20  # Other interactions with temp/appdata

        # 4. Contextual whitelisting for trusted processes
        # Trusted processes (browsers, system apps) only get penalised
        # when a genuinely suspicious cmdline token was found.
        # Pure path-based score for trusted apps is capped to LOW territory.
        if is_trusted:
            has_bad_cmd = any(
                tok in cmdline for _, toks in RiskEngine.CMDLINE_RISKS for tok in toks
            )
            if not has_bad_cmd:
                score = min(score, 10)   # cap to LOW if no suspicious cmdline

        event.risk_score = score
        event.severity   = RiskEngine.get_severity_for_score(score)
        return score, event.severity

    @staticmethod
    def update_cumulative_risk(
        identity: ProcessIdentity, event_score: int
    ) -> Tuple[int, str]:
        """
        Accumulate event_score onto the process identity's running total.
        Returns (total_score, severity).
        """
        if not identity or event_score <= 0:
            total = cache_manager.get_score(identity) if identity else 0
            return total, RiskEngine.get_severity_for_score(total)

        total    = cache_manager.add_score(identity, event_score)
        severity = RiskEngine.get_severity_for_score(total)
        logger.debug(
            f"RiskEngine: +{event_score} → {identity} | total={total} ({severity})"
        )
        return total, severity

    @staticmethod
    def get_severity_for_score(score: int) -> str:
        """Map a numeric risk score to a severity label."""
        if   score >= 90: return "CRITICAL"
        elif score >= 60: return "HIGH"
        elif score >= 30: return "MEDIUM"
        else:             return "LOW"

