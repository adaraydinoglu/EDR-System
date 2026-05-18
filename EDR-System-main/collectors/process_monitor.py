import psutil
import time
import logging

from detection.rules import RULES
from core.scoring import add_score


logging.basicConfig(
    filename="alerts/alerts.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

seen = set()

WHITELIST = [
    "python.exe",
    "cmd.exe",
    "conhost.exe"
]


def build_event(proc):

    try:

        parent = proc.parent()

        return {
            "type": "process_create",
            "pid": proc.pid,
            "process": proc.name(),
            "parent": parent.name() if parent else "unknown",
            "cmdline": " ".join(proc.cmdline()),
            "path": proc.exe() if proc.exe() else ""
        }

    except:
        return None


def detect(event):

    for rule in RULES:

        try:

            if rule["match"](event):

                total_score = add_score(
                    event["pid"],
                    rule["score"]
                )

                alert = (
                    f'[RULE] {rule["name"]} | '
                    f'PID={event["pid"]} | '
                    f'PROC={event["process"]} | '
                    f'SCORE={total_score}'
                )

                print(alert)

                logging.warning(alert)

                if total_score >= 100:

                    critical = (
                        f'[CRITICAL] High risk activity detected | '
                        f'PID={event["pid"]} | '
                        f'PROC={event["process"]}'
                    )

                    print(critical)

                    logging.critical(critical)

        except:
            pass


def start():

    print("[+] Process monitor started")

    while True:

        for proc in psutil.process_iter():

            try:

                if proc.pid in seen:
                    continue

                seen.add(proc.pid)

                event = build_event(proc)

                if not event:
                    continue

                if event["process"].lower() in WHITELIST:
                    continue

                detect(event)

            except:
                pass

        time.sleep(2)