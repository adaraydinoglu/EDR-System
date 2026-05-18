# Simple filters for the collectors to drop noise early

SAFE_APPDATA_PROCESSES = [
    "code.exe",
    "discord.exe",
    "teams.exe",
    "slack.exe",
    "spotify.exe",
    "telegram.exe",
    "whatsapp.exe",
    "chrome.exe",
    "brave.exe",
    "msedge.exe",
    "onedrive.exe"
]

WHITELISTED_SYSTEM_PROCESSES = [
    "svchost.exe",
    "csrss.exe",
    "smss.exe",
    "wininit.exe",
    "lsass.exe",
    "services.exe",
    "winlogon.exe",
    "explorer.exe"
]

def is_safe_appdata(process_name: str) -> bool:
    return process_name.lower() in SAFE_APPDATA_PROCESSES

def is_whitelisted(process_name: str) -> bool:
    return process_name.lower() in WHITELISTED_SYSTEM_PROCESSES