from dataclasses import dataclass, field
import time

@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    create_time: float

    def __str__(self):
        return f"{self.pid}@{int(self.create_time)}"
    
    def __eq__(self, other):
        if not isinstance(other, ProcessIdentity):
            return False
        return self.pid == other.pid and self.create_time == other.create_time

    def __hash__(self):
        return hash((self.pid, self.create_time))
