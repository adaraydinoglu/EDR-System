from models.event_schema import EventType

# Simple stateless rules
RULES = [
    {
        "name": "Suspicious_CMD_Execution",
        "tactic": "Execution",
        "technique": "T1059.003",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "score": 30,
        "match": lambda e: (
            e.event_type == EventType.PROCESS_CREATE
            and "cmd.exe" in e.process_name.lower()
        )
    },
    {
        "name": "PowerShell_Execution",
        "tactic": "Execution",
        "technique": "T1059.001",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "score": 40,
        "match": lambda e: (
            e.event_type == EventType.PROCESS_CREATE
            and "powershell.exe" in e.process_name.lower()
        )
    },
    {
        "name": "Encoded_PowerShell",
        "tactic": "Defense Evasion",
        "technique": "T1027",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "score": 90,
        "match": lambda e: (
            e.event_type == EventType.PROCESS_CREATE
            and "powershell.exe" in e.process_name.lower()
            and any(flag in e.cmdline.lower() for flag in ["-enc", "-encodedcommand"])
        )
    },
    {
        "name": "Execution_From_AppData",
        "tactic": "Execution",
        "technique": "T1059",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "score": 60,
        "match": lambda e: (
            e.event_type == EventType.PROCESS_CREATE
            and "appdata" in e.path.lower()
        ) # Filtering of safe processes happens at the collector or engine level
    },
    {
        "name": "Office_Spawning_Shell",
        "tactic": "Execution",
        "technique": "T1059",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "score": 95,
        "match": lambda e: (
            e.event_type == EventType.PROCESS_CREATE
            and e.parent_name.lower() in ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"]
            and e.process_name.lower() in ["cmd.exe", "powershell.exe"]
        )
    }
]