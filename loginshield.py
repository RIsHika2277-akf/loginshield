"""
LoginShield (v0.1)
A simple, beginner-friendly Python script to detect suspicious login activity
by analyzing authentication logs for repeated failed login attempts.
"""
import argparse
# Standard library imports:
# None required for v0.1, keeping the script lightweight and dependency-free.

# -------------------------------------------------------------------------
# CONSTANTS & CONFIGURATION
# -------------------------------------------------------------------------
# In Python, variables in ALL_CAPS are 'constants' - settings we don't expect
# to change during runtime.
LOG_FILE = "sample_logs.txt"
FAILED_THRESHOLD = 5
VALID_STATUSES = {"SUCCESS", "FAILED"}
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

    return parser.parse_args()


def parse_log_line(line):
    """
    CONCEPT: String Manipulation (.strip and .split) and Input Validation.
    Takes a single comma-separated log line and safely extracts:
    Timestamp, IP Address, Username, Status.

    Returns a dictionary if valid, or None if the line is malformed/empty.
    """
    # .strip() removes leading/trailing whitespace and newlines (\n)
    cleaned_line = line.strip()

    # Skip empty lines
    if not cleaned_line:
        return None

    # .split(",") breaks the CSV string on each comma and returns a list
    parts = cleaned_line.split(",")

    # Validate CSV structure: must contain exactly 4 fields
    if len(parts) != 4:
        return None

    timestamp = parts[0].strip()
    ip_address = parts[1].strip()
    username = parts[2].strip()
    status = parts[3].strip().upper()  # Standardize case (e.g. "failed" -> "FAILED")

    # Guard against lines with commas but missing values (e.g. "time,,user,SUCCESS")
    if not timestamp or not ip_address or not username or not status:
        return None

    # STATUS VALIDATION: Reject any record where status is not SUCCESS or FAILED
    if status not in VALID_STATUSES:
        return None

    return {
        "timestamp": timestamp,
        "ip_address": ip_address,
        "username": username,
        "status": status,
    }


def analyze_log_file(file_path):
    """
    CONCEPTS: File Handling (with open), Exception Handling (try/except),
    and Dictionaries (dict).
    Reads the specified log file line by line and counts ONLY failed attempts per IP.
    """
    # A dictionary stores key-value pairs: { "IP_ADDRESS": failure_count }
    failed_attempts = {}

    try:
        # 'with open(...)' opens the file safely and automatically closes it when finished
        with open(file_path, mode="r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                record = parse_log_line(line)

                # Skip blank or malformed lines safely without crashing
                if record is None:
                    continue

                # REQUIREMENT: Count only FAILED events; SUCCESS events are ignored
                if record["status"] == "FAILED":
                    ip = record["ip_address"]

                    # Increment the failed count for this IP
                    if ip in failed_attempts:
                        failed_attempts[ip] += 1
                    else:
                        failed_attempts[ip] = 1

    except FileNotFoundError:
        # Gracefully alert the user if the target log file does not exist
        print(f"[ERROR] Could not find the log file: '{file_path}'")
        return None
    except OSError as err:
        # Catch unexpected file read/permission errors safely
        print(f"[ERROR] Could not read file '{file_path}': {err}")
        return None

    return failed_attempts


def display_security_report(failed_attempts, threshold, file_path):
    """
    CONCEPTS: Iteration (.items()), Conditionals (if/else), and Formatted Strings (f-strings).
    Evaluates failed login counts against the threshold and prints a formatted terminal audit report.
    """
    print("\n" + "=" * 60)
    print("               LOGINSHIELD SECURITY AUDIT REPORT")
    print("=" * 60)
    print(f"Log File Analyzed     : {file_path}")
    print(f"Alert Threshold       : >= {threshold} failed attempts")
    print("-" * 60)

    if not failed_attempts:
        print("No failed login attempts were recorded.")
        print("=" * 60 + "\n")
        return

    suspicious_count = 0

    # .items() iterates over key-value pairs: ip (string) and count (integer)
    for ip, count in failed_attempts.items():
        # REQUIREMENT: Flag counts greater than or equal to threshold (>= 5)
        if count >= threshold:
            suspicious_count += 1
            print(f"[ALERT] SUSPICIOUS IP DETECTED: {ip:<15} ({count} failed attempts)")
        else:
            print(f"[INFO]  Normal activity       : {ip:<15} ({count} failed attempts)")

    print("-" * 60)
    print(f"Summary: {suspicious_count} suspicious IP(s) flagged reaching or exceeding threshold.")
    print("=" * 60 + "\n")


def main():
    """
    Entry point of LoginShield.
    Reads command-line arguments, analyzes logs,
    and generates a security report.
    """
    args = parse_arguments()

    print("[*] Starting LoginShield audit...")

    failed_attempts = analyze_log_file(args.log_file)

    if failed_attempts is not None:
        display_security_report(
            failed_attempts,
            args.threshold,
            args.log_file
        )


# CONCEPT: The 'if __name__ == "__main__":' guard
# Ensures main() executes only when run directly (python loginshield.py),
# not when imported as a module in another script or test.
if __name__ == "__main__":
    main()
