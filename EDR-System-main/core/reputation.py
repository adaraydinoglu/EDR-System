import hashlib
import os

class ReputationEngine:
    """
    Evaluates reputation of processes based on paths, hashes, and signatures.
    """
    LOLBINS = {
        "rundll32.exe", "regsvr32.exe", "certutil.exe", "msbuild.exe",
        "mshta.exe", "powershell.exe", "cmd.exe", "wmic.exe",
        "cscript.exe", "wscript.exe", "vssadmin.exe", "bitsadmin.exe"
    }

    SUSPICIOUS_PATHS = [
        "temp", "tmp", "appdata", "programdata"
    ]

    @staticmethod
    def is_lolbin(process_name: str) -> bool:
        return process_name.lower() in ReputationEngine.LOLBINS

    @staticmethod
    def is_suspicious_path(path: str) -> bool:
        path_lower = path.lower()
        return any(sp in path_lower for sp in ReputationEngine.SUSPICIOUS_PATHS)

    @staticmethod
    def calculate_hash(path: str) -> str:
        if not path or not os.path.exists(path):
            return ""
        try:
            sha256_hash = hashlib.sha256()
            with open(path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return ""

    @staticmethod
    def is_microsoft_signed(path: str) -> bool:
        # Placeholder for actual signature verification (Authenticode)
        # using pefile or win32api in a real implementation.
        return False
