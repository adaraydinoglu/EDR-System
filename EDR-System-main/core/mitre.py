"""
core/mitre.py

Canonical MITRE ATT&CK technique catalogue.
Provides ID → (name, tactic) lookups so every alert can carry
a human-readable technique name without any network calls.

Usage:
    from core.mitre import mitre
    name = mitre.get_name("T1059.001")   # "PowerShell"
    tactic = mitre.get_tactic("T1059")   # "Execution"
    info = mitre.get("T1027")            # {"id": ..., "name": ..., "tactic": ...}
"""

from typing import Dict, Optional


# ---------------------------------------------------------------------------
# Catalogue  (ID -> {"name": str, "tactic": str})
# Extend freely — order does not matter.
# ---------------------------------------------------------------------------
_CATALOGUE: Dict[str, Dict[str, str]] = {
    # ── Execution ───────────────────────────────────────────────────────────
    "T1059":       {"name": "Command and Scripting Interpreter",    "tactic": "Execution"},
    "T1059.001":   {"name": "PowerShell",                           "tactic": "Execution"},
    "T1059.003":   {"name": "Windows Command Shell",                "tactic": "Execution"},
    "T1059.005":   {"name": "Visual Basic",                         "tactic": "Execution"},
    "T1059.007":   {"name": "JavaScript",                           "tactic": "Execution"},
    "T1047":       {"name": "Windows Management Instrumentation",   "tactic": "Execution"},
    "T1053":       {"name": "Scheduled Task/Job",                   "tactic": "Execution / Persistence"},
    "T1053.005":   {"name": "Scheduled Task",                       "tactic": "Execution / Persistence"},
    "T1106":       {"name": "Native API",                           "tactic": "Execution"},

    # ── Persistence ─────────────────────────────────────────────────────────
    "T1547":       {"name": "Boot or Logon Autostart Execution",    "tactic": "Persistence"},
    "T1547.001":   {"name": "Registry Run Keys / Startup Folder",   "tactic": "Persistence"},
    "T1136":       {"name": "Create Account",                       "tactic": "Persistence"},

    # ── Defense Evasion ─────────────────────────────────────────────────────
    "T1027":       {"name": "Obfuscated Files or Information",      "tactic": "Defense Evasion"},
    "T1027.001":   {"name": "Binary Padding",                       "tactic": "Defense Evasion"},
    "T1036":       {"name": "Masquerading",                         "tactic": "Defense Evasion"},
    "T1070":       {"name": "Indicator Removal",                    "tactic": "Defense Evasion"},
    "T1112":       {"name": "Modify Registry",                      "tactic": "Defense Evasion"},
    "T1140":       {"name": "Deobfuscate/Decode Files or Information","tactic": "Defense Evasion"},
    "T1218":       {"name": "System Binary Proxy Execution",        "tactic": "Defense Evasion"},
    "T1218.005":   {"name": "Mshta",                                "tactic": "Defense Evasion"},
    "T1218.010":   {"name": "Regsvr32",                             "tactic": "Defense Evasion"},
    "T1218.011":   {"name": "Rundll32",                             "tactic": "Defense Evasion"},

    # ── Credential Access ───────────────────────────────────────────────────
    "T1003":       {"name": "OS Credential Dumping",                "tactic": "Credential Access"},
    "T1003.001":   {"name": "LSASS Memory",                         "tactic": "Credential Access"},
    "T1555":       {"name": "Credentials from Password Stores",     "tactic": "Credential Access"},

    # ── Discovery ───────────────────────────────────────────────────────────
    "T1082":       {"name": "System Information Discovery",         "tactic": "Discovery"},
    "T1083":       {"name": "File and Directory Discovery",         "tactic": "Discovery"},
    "T1057":       {"name": "Process Discovery",                    "tactic": "Discovery"},
    "T1018":       {"name": "Remote System Discovery",              "tactic": "Discovery"},

    # ── Lateral Movement ────────────────────────────────────────────────────
    "T1021":       {"name": "Remote Services",                      "tactic": "Lateral Movement"},
    "T1021.001":   {"name": "Remote Desktop Protocol",              "tactic": "Lateral Movement"},

    # ── Collection ──────────────────────────────────────────────────────────
    "T1005":       {"name": "Data from Local System",               "tactic": "Collection"},
    "T1074":       {"name": "Data Staged",                          "tactic": "Collection"},

    # ── Command and Control ─────────────────────────────────────────────────
    "T1071":       {"name": "Application Layer Protocol",           "tactic": "Command and Control"},
    "T1071.001":   {"name": "Web Protocols",                        "tactic": "Command and Control"},
    "T1105":       {"name": "Ingress Tool Transfer",                "tactic": "Command and Control"},
    "T1095":       {"name": "Non-Application Layer Protocol",       "tactic": "Command and Control"},

    # ── Exfiltration ────────────────────────────────────────────────────────
    "T1041":       {"name": "Exfiltration Over C2 Channel",         "tactic": "Exfiltration"},
    "T1048":       {"name": "Exfiltration Over Alternative Protocol","tactic": "Exfiltration"},

    # ── Impact ──────────────────────────────────────────────────────────────
    "T1486":       {"name": "Data Encrypted for Impact",            "tactic": "Impact"},
    "T1490":       {"name": "Inhibit System Recovery",              "tactic": "Impact"},
    "T1489":       {"name": "Service Stop",                         "tactic": "Impact"},

    # ── Initial Access ──────────────────────────────────────────────────────
    "T1566":       {"name": "Phishing",                             "tactic": "Initial Access"},
    "T1566.001":   {"name": "Spearphishing Attachment",             "tactic": "Initial Access"},
    "T1190":       {"name": "Exploit Public-Facing Application",    "tactic": "Initial Access"},
}


class MitreMapping:
    """Thin wrapper around the catalogue for typed lookups."""

    def get(self, technique_id: str) -> Optional[Dict[str, str]]:
        """Return full entry or None if not in catalogue."""
        entry = _CATALOGUE.get(technique_id)
        if entry:
            return {"id": technique_id, **entry}
        # Try parent technique (T1059.001 -> T1059)
        parent = technique_id.split(".")[0]
        entry = _CATALOGUE.get(parent)
        if entry:
            return {"id": parent, **entry}
        return None

    def get_name(self, technique_id: str) -> str:
        entry = self.get(technique_id)
        return entry["name"] if entry else technique_id  # fall back to raw ID

    def get_tactic(self, technique_id: str) -> str:
        entry = self.get(technique_id)
        return entry["tactic"] if entry else "Unknown"

    def enrich(self, technique_id: str) -> Dict[str, str]:
        """
        Returns a dict ready to be merged into a rule or alert:
            {"mitre_id": ..., "technique_name": ..., "tactic": ...}
        """
        entry = self.get(technique_id)
        if entry:
            return {
                "mitre_id":       entry["id"],
                "technique_name": entry["name"],
                "tactic":         entry["tactic"],
            }
        return {
            "mitre_id":       technique_id,
            "technique_name": technique_id,
            "tactic":         "Unknown",
        }


# Module-level singleton
mitre = MitreMapping()
