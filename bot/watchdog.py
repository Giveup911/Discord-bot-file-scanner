r"""
Watchdog for bot.py -- restarts the scanner if it dies.
Register as a Windows Scheduled Task to run at logon (run install_watchdog.bat as admin).
Or run manually:  python watchdog.py
"""

import subprocess
import time
import os
import sys
import logging
from datetime import datetime

BOT_DIR = os.path.dirname(os.path.abspath(__file__))
BOT_SCRIPT = os.path.join(BOT_DIR, "bot.py")
LOG_FILE = os.path.join(BOT_DIR, "logs", "watchdog.log")
CHECK_INTERVAL = 30  # seconds between checks
RESTART_COOLDOWN = 10  # seconds to wait before restarting after crash

os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] watchdog: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("watchdog")


def is_bot_running():
    try:
        result = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq python.exe", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.strip().splitlines():
            if "python" in line.lower():
                pid_check = subprocess.run(
                    ["wmic", "process", "where",
                     f"processid={line.split(',')[1].strip('\"')}",
                     "get", "commandline"],
                    capture_output=True, text=True, timeout=10,
                )
                if "bot.py" in pid_check.stdout:
                    return True
    except Exception:
        pass

    try:
        result = subprocess.run(
            ["wmic", "process", "where",
             "name='python.exe' or name='python3.exe' or name='pythonw.exe'",
             "get", "processid,commandline", "/format:csv"],
            capture_output=True, text=True, timeout=15,
        )
        for line in result.stdout.splitlines():
            if "bot.py" in line and "watchdog" not in line:
                return True
    except Exception as e:
        log.warning(f"Process check error: {e}")
    return False


def start_bot():
    log.info(f"Starting bot.py...")
    proc = subprocess.Popen(
        [sys.executable, BOT_SCRIPT],
        cwd=BOT_DIR,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
    )
    log.info(f"Bot started (PID {proc.pid})")
    return proc


def main():
    log.info("=" * 50)
    log.info("Watchdog started")
    log.info(f"Monitoring: {BOT_SCRIPT}")
    log.info(f"Check interval: {CHECK_INTERVAL}s")
    log.info("=" * 50)

    proc = None
    consecutive_crashes = 0

    while True:
        try:
            if proc is not None and proc.poll() is not None:
                exit_code = proc.returncode
                consecutive_crashes += 1
                log.warning(f"Bot exited with code {exit_code} "
                            f"(crash #{consecutive_crashes})")
                proc = None

                backoff = min(RESTART_COOLDOWN * consecutive_crashes, 300)
                log.info(f"Waiting {backoff}s before restart...")
                time.sleep(backoff)

            if not is_bot_running():
                if proc is not None:
                    log.warning("Bot process lost — restarting")
                    proc = None
                proc = start_bot()
                time.sleep(5)
                if proc.poll() is not None:
                    log.error(f"Bot failed to start (exit code {proc.returncode})")
                    proc = None
                else:
                    log.info("Bot is running")
                    consecutive_crashes = 0
            else:
                if consecutive_crashes > 0:
                    consecutive_crashes = 0

        except KeyboardInterrupt:
            log.info("Watchdog stopped by user")
            break
        except Exception as e:
            log.error(f"Watchdog error: {e}")

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
