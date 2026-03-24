"""
Gmail Spam Filter Daemon
------------------------
Runs the spam filter continuously every N minutes.
Designed to run as a background service 24/7.

Usage:
  python gmail_daemon.py              # runs every 5 minutes
  python gmail_daemon.py --interval=10  # runs every 10 minutes
"""

import time
import sys
import os
import logging
import signal
from datetime import datetime
from gmail_spam_filter import get_gmail_service, scan_inbox

# Config
DEFAULT_INTERVAL_MINUTES = 5
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'gmail_daemon.log')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger(__name__)

running = True

def handle_signal(sig, frame):
    global running
    log.info("Shutdown signal received. Stopping after current scan...")
    running = False

signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT, handle_signal)


def run_daemon(interval_minutes=DEFAULT_INTERVAL_MINUTES):
    log.info(f"Gmail Spam Filter Daemon starting (interval: {interval_minutes}m)")
    log.info(f"Logs: {LOG_FILE}")

    # Wait until credentials.json exists (user may not have set it up yet)
    creds_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'credentials.json')
    token_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'token.json')
    while not os.path.exists(creds_path) and not os.path.exists(token_path):
        log.warning("Waiting for credentials.json... (place it in /home/user/Claude/)")
        for _ in range(30):
            if not running:
                return
            time.sleep(1)

    service = get_gmail_service()
    log.info("Gmail authenticated successfully.")

    scan_count = 0
    while running:
        scan_count += 1
        log.info(f"--- Scan #{scan_count} started ---")
        try:
            scan_inbox(service, max_emails=100, dry_run=False)
            log.info(f"Scan #{scan_count} complete.")
        except Exception as e:
            log.error(f"Scan #{scan_count} failed: {e}", exc_info=True)

        if not running:
            break

        next_run = datetime.now().strftime('%H:%M:%S')
        log.info(f"Next scan in {interval_minutes} minute(s)... (Ctrl+C to stop)")
        for _ in range(interval_minutes * 60):
            if not running:
                break
            time.sleep(1)

    log.info("Daemon stopped.")


if __name__ == '__main__':
    interval = DEFAULT_INTERVAL_MINUTES
    for arg in sys.argv[1:]:
        if arg.startswith('--interval='):
            interval = int(arg.split('=')[1])
    run_daemon(interval)
