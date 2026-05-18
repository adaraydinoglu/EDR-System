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
        "brave.exe", "chrome.exe", "firefox.exe", "msedge.exe",
        "code.exe", "devenv.exe", "winlogon.exe", "lsass.exe",
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

        # 3. Path modifiers
        if any(frag in path for frag in ["\\temp\\", "\\tmp\\", "appdata"]):
            score += 20
            # Executable dropped in temp is a major indicator
            if event.event_type == EventType.FILE_CREATE and path.endswith((".exe", ".dll", ".bat", ".ps1")):
                score += 50

        # 4. Contextual whitelisting
        # A trusted process gets a discount ONLY when it has no suspicious
        # commandline, is not in a suspicious path, and is a PROCESS_CREATE
        # with no special arguments — i.e. genuinely normal invocation.
        if proc_name in RiskEngine.TRUSTED_PROCESSES:
            is_clean = (
                event.event_type == EventType.PROCESS_CREATE
                and score == 0           # nothing suspicious detected yet
                and not cmdline.strip()  # no commandline at all
            )
            if is_clean:
                score = max(0, score - 5)  # small baseline discount
            # If score > 0 the process is behaving suspiciously — no discount.

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

