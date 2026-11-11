
"""
LoginShield (v0.2)
Suspicious login detection using rolling time-window analysis.
"""

import argparse
from datetime import datetime, timedelta
from collections import defaultdict, deque


# --------------------------------------------------
# CONSTANTS & CONFIGURATION
# --------------------------------------------------

LOG_FILE = "sample_logs.txt"
FAILED_THRESHOLD = 5
DEFAULT_WINDOW = 10

VALID_STATUSES = {"SUCCESS", "FAILED"}


# --------------------------------------------------
# COMMAND-LINE ARGUMENTS
# --------------------------------------------------

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="LoginShield - Suspicious Login Detection Tool"
    )

    parser.add_argument(
        "--log-file",
        type=str,
        default=LOG_FILE,
        help="Path to the authentication log file"
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=FAILED_THRESHOLD,
        help="Minimum failed attempts required to trigger an alert"
    )

    parser.add_argument(
        "--window",
        type=int,
        default=DEFAULT_WINDOW,
        help="Time window in minutes for detecting failed logins"
    )

    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("--threshold must be at least 1")

    if args.window < 1:
        parser.error("--window must be at least 1 minute")

    return args


# --------------------------------------------------
# LOG PARSING
# --------------------------------------------------

def parse_log_line(line):
    """
    Parses a log line and validates its fields.

    Expected format:
    YYYY-MM-DD HH:MM:SS,IP,USERNAME,STATUS
    """

    cleaned_line = line.strip()

    if not cleaned_line:
        return None

    parts = cleaned_line.split(",")

    if len(parts) != 4:
        return None

    timestamp_text = parts[0].strip()
    ip_address = parts[1].strip()
    username = parts[2].strip()
    status = parts[3].strip().upper()

    if not timestamp_text or not ip_address or not username:
        return None

    if status not in VALID_STATUSES:
        return None

    try:
        timestamp = datetime.strptime(
            timestamp_text,
            "%Y-%m-%d %H:%M:%S"
        )
    except ValueError:
        return None

    return {
        "timestamp": timestamp,
        "ip_address": ip_address,
        "username": username,
        "status": status
    }


# --------------------------------------------------
# SLIDING-WINDOW DETECTION ENGINE
# --------------------------------------------------

def analyze_log_file(file_path, window_minutes):
    """
    Finds the maximum number of failed login attempts
    from each IP within any rolling time window.
    """

    failed_events = defaultdict(list)

    try:
        with open(file_path, mode="r", encoding="utf-8") as file:

            for line_number, line in enumerate(file, start=1):

                record = parse_log_line(line)

                if record is None:
                    continue

                if record["status"] == "FAILED":

                    ip = record["ip_address"]

                    failed_events[ip].append(
                        record["timestamp"]
                    )

    except FileNotFoundError:
        print(f"[ERROR] Could not find the log file: '{file_path}'")
        return None

    except OSError as err:
        print(f"[ERROR] Could not read file '{file_path}': {err}")
        return None

    window = timedelta(minutes=window_minutes)

    max_attempts = {}

    for ip, timestamps in failed_events.items():

        # Sort timestamps to support logs in any order
        timestamps.sort()

        attempts = deque()

        highest_count = 0

        for current_time in timestamps:

            attempts.append(current_time)

            # Remove attempts outside the rolling window
            while current_time - attempts[0] > window:
                attempts.popleft()

            highest_count = max(
                highest_count,
                len(attempts)
            )

        max_attempts[ip] = highest_count

    return max_attempts


# --------------------------------------------------
# SECURITY REPORT
# --------------------------------------------------

def display_security_report(
    failed_attempts,
    threshold,
    file_path,
    window_minutes
):
    """
    Displays the security analysis report.
    """

    print("\n" + "=" * 60)
    print("               LOGINSHIELD SECURITY AUDIT REPORT")
    print("=" * 60)

    print(f"Log File Analyzed     : {file_path}")
    print(f"Alert Threshold       : >= {threshold} failed attempts")
    print(f"Detection Window      : {window_minutes} minutes")

    print("-" * 60)

    if not failed_attempts:
        print("No failed login attempts were recorded.")
        print("=" * 60 + "\n")
        return

    suspicious_count = 0

    for ip, count in sorted(failed_attempts.items()):

        if count >= threshold:

            suspicious_count += 1

            print(
                f"[ALERT] SUSPICIOUS IP DETECTED: "
                f"{ip:<15} ({count} failed attempts)"
            )

        else:

            print(
                f"[INFO]  Normal activity       : "
                f"{ip:<15} ({count} failed attempts)"
            )

    print("-" * 60)

    print(
        f"Summary: {suspicious_count} suspicious IP(s) "
        f"flagged reaching or exceeding threshold."
    )

    print("=" * 60 + "\n")


# --------------------------------------------------
# MAIN FUNCTION
# --------------------------------------------------

def main():
    """
    Main entry point of LoginShield.
    """

    args = parse_arguments()

    print("[*] Starting LoginShield audit...")

    failed_attempts = analyze_log_file(
        args.log_file,
        args.window
    )

    if failed_attempts is not None:

        display_security_report(
            failed_attempts,
            args.threshold,
            args.log_file,
            args.window
        )


# --------------------------------------------------
# SCRIPT ENTRY POINT
# --------------------------------------------------

if __name__ == "__main__":
    main()
