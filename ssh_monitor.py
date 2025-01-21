#!/usr/bin/env python3
"""
Simplified SSH Log Monitoring & Analysis Script
----------------------------------------------
This script reads settings from config.ini and the AbuseIPDB API key from .env.
It then:
  1. Allows the user to either provide a sample log file path (by drag-and-drop
     or manual entry) or press Enter to use the default from config.ini.
  2. Parses SSH auth logs for failed/successful login attempts.
  3. Identifies suspicious brute-force patterns:
       - Multiple failed attempts in a row (failed_threshold).
       - Multiple failures in a short time window (time_window_threshold).
  4. Checks IP reputation via AbuseIPDB.
  5. Logs alerts in JSON format.

Usage:
  python ssh_monitor.py

Requirements:
  - pip install requests python-dotenv
"""

import re
import sys
import json
import os
import ipaddress
import requests
from datetime import datetime, timedelta
from dataclasses import dataclass
from configparser import ConfigParser
from dotenv import load_dotenv

# Load .env file to fetch environment variables (e.g., ABUSEIPDB_API_KEY)
load_dotenv()


@dataclass
class LoginEvent:
    """Stores a single login attempt from the SSH auth log."""
    timestamp: datetime
    ip: str
    event_type: str  # "FAILED" or "SUCCESS"
    raw_line: str


def read_config() -> dict:
    """
    Read config.ini and return a dictionary of settings.
    """
    cfg = ConfigParser()
    cfg.read("config.ini")

    settings = {}
    # Defaults in [default] section
    settings["log_file_path"] = cfg.get("default", "log_file_path", fallback="/var/log/auth.log")
    settings["failed_threshold"] = cfg.getint("default", "failed_threshold", fallback=3)
    settings["time_window_seconds"] = cfg.getint("default", "time_window_seconds", fallback=300)
    settings["time_window_threshold"] = cfg.getint("default", "time_window_threshold", fallback=10)
    settings["reputation_threshold"] = cfg.getint("default", "reputation_threshold", fallback=50)
    settings["alert_log"] = cfg.get("default", "alert_log", fallback="alerts.json")

    # Whitelist/Blacklist can be comma-separated
    whitelist_str = cfg.get("default", "whitelist", fallback="")
    settings["whitelist"] = [item.strip() for item in whitelist_str.split(",") if item.strip()]

    blacklist_str = cfg.get("default", "blacklist", fallback="")
    settings["blacklist"] = [item.strip() for item in blacklist_str.split(",") if item.strip()]

    return settings


def parse_log_timestamp(log_line: str) -> datetime:
    """
    Extract the timestamp from a syslog-style line, e.g., 'Mar 15 09:23:45'.
    We add the current year because syslog typically omits it.
    Falls back to current time if parsing fails.
    """
    try:
        parts = log_line.split()
        timestamp_str = " ".join(parts[:3]) + f" {datetime.now().year}"
        return datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")
    except (ValueError, IndexError):
        return datetime.now()


def parse_log_file(filepath: str) -> list[LoginEvent]:
    """
    Read the SSH log file, parse out relevant events (FAILED or SUCCESS),
    and return a list of LoginEvent objects.
    """
    events = []
    # Regex patterns
    failed_regex = r"Failed password for .* from ([^\s]+) port"
    success_regex = r"Accepted (?:password|publickey) for .* from ([^\s]+) port"

    try:
        with open(filepath, 'r', encoding='utf-8') as log_file:
            for line in log_file:
                line = line.strip()
                if not line:
                    continue

                # Check for Failed
                match = re.search(failed_regex, line)
                if match:
                    raw_ip = match.group(1)
                    ts = parse_log_timestamp(line)
                    events.append(LoginEvent(timestamp=ts, ip=raw_ip, event_type="FAILED", raw_line=line))
                    continue

                # Check for Success
                match = re.search(success_regex, line)
                if match:
                    raw_ip = match.group(1)
                    ts = parse_log_timestamp(line)
                    events.append(LoginEvent(timestamp=ts, ip=raw_ip, event_type="SUCCESS", raw_line=line))
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {filepath}")

    return events


def is_whitelisted(ip: str, whitelist: list[str]) -> bool:
    """Check if the IP is in the whitelist (supports individual IP or CIDR)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for entry in whitelist:
            if '/' in entry:
                network = ipaddress.ip_network(entry, strict=False)
                if ip_obj in network:
                    return True
            else:
                if ip_obj == ipaddress.ip_address(entry):
                    return True
        return False
    except ValueError:
        # If it's not a valid IP, treat it as not whitelisted.
        return False


def is_blacklisted(ip: str, blacklist: list[str]) -> bool:
    """Check if the IP is in the blacklist (supports individual IP or CIDR)."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for entry in blacklist:
            if '/' in entry:
                network = ipaddress.ip_network(entry, strict=False)
                if ip_obj in network:
                    return True
            else:
                if ip_obj == ipaddress.ip_address(entry):
                    return True
        return False
    except ValueError:
        # If it's not a valid IP, treat it as not blacklisted.
        return False


def determine_severity_by_count(count: int) -> str:
    """
    Simple logic to assign severity based on count of attempts.
    Adjust as desired.
    """
    if count >= 10:
        return "HIGH"
    elif count >= 5:
        return "MEDIUM"
    else:
        return "LOW"


def detect_repeated_failures(events: list[LoginEvent], failed_threshold: int) -> list[dict]:
    """
    For each IP, check if it triggers a threshold of consecutive failures
    before a success. Generate an alert if the threshold is met.
    Returns a list of alert dictionaries (serialized to JSON later).
    """
    alerts = []
    # Sort primarily by IP, then by timestamp
    events_sorted = sorted(events, key=lambda e: (e.ip, e.timestamp))

    current_ip = None
    fail_count = 0
    fail_logs = []

    for event in events_sorted:
        if event.ip != current_ip:
            # Reset counters when switching to a new IP
            current_ip = event.ip
            fail_count = 0
            fail_logs = []

        if event.event_type == "FAILED":
            fail_count += 1
            fail_logs.append(event.raw_line)
        else:  # "SUCCESS"
            # If fail_count was beyond threshold before success
            if fail_count >= failed_threshold:
                alerts.append({
                    "timestamp": datetime.now().isoformat(),
                    "alert_type": "RepeatedFailures",
                    "source_ip": current_ip,
                    "failed_count": fail_count,
                    "severity": determine_severity_by_count(fail_count),
                    "raw_logs": fail_logs
                })
            fail_count = 0
            fail_logs = []

    # Edge case: If file ended on fails with no success afterward
    if fail_count >= failed_threshold:
        alerts.append({
            "timestamp": datetime.now().isoformat(),
            "alert_type": "RepeatedFailures",
            "source_ip": current_ip,
            "failed_count": fail_count,
            "severity": determine_severity_by_count(fail_count),
            "raw_logs": fail_logs
        })

    return alerts


def detect_time_window(events: list[LoginEvent], time_window: int, threshold: int) -> list[dict]:
    """
    Check if there's a burst of failed attempts within a time window
    (time_window seconds). Returns a list of alert dicts.
    """
    alerts = []
    # Sort by timestamp
    events_sorted = sorted(events, key=lambda e: e.timestamp)
    failures = [e for e in events_sorted if e.event_type == "FAILED"]

    i = 0
    while i < len(failures):
        window_start = failures[i].timestamp
        ip = failures[i].ip
        window_end = window_start + timedelta(seconds=time_window)

        count_in_window = 1
        raw_logs = [failures[i].raw_line]

        # Check subsequent failures for the same IP within time_window
        j = i + 1
        while j < len(failures):
            if failures[j].ip == ip and failures[j].timestamp <= window_end:
                count_in_window += 1
                raw_logs.append(failures[j].raw_line)
            j += 1

        if count_in_window >= threshold:
            alerts.append({
                "timestamp": datetime.now().isoformat(),
                "alert_type": "TimeWindowBurst",
                "source_ip": ip,
                "failed_count_in_window": count_in_window,
                "time_window_seconds": time_window,
                "severity": determine_severity_by_count(count_in_window),
                "raw_logs": raw_logs
            })

        i += 1

    return alerts


def check_ip_reputation(ip: str, threshold: int) -> dict:
    """
    Check the IP's reputation on AbuseIPDB.
    If the abuse confidence score >= threshold, return an alert dict.
    Otherwise return None. The API key is taken from the environment.
    """
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return {}  # No alert, as we can't check

    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip
    }
    try:
        response = requests.get("https://api.abuseipdb.com/api/v2/check",
                                headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json()
            score = data["data"]["abuseConfidenceScore"]
            if score >= threshold:
                return {
                    "timestamp": datetime.now().isoformat(),
                    "alert_type": "ReputationCheck",
                    "source_ip": ip,
                    "severity": "HIGH",
                    "abuse_score": score
                }
    except requests.exceptions.RequestException:
        # Could log an error or ignore
        pass
    return {}


def main():
    # 1. Read config settings
    cfg = read_config()

    # Prompt user to optionally provide a sample log path
    user_input = input(
        "Drag/Drop a sample log file here or type its path, then press Enter.\n"
        f"Or simply press Enter to use the default from config.ini ({cfg['log_file_path']}): "
    ).strip()

    # If user provided something (possibly with single quotes from drag/drop),
    # remove quotes. Otherwise use default.
    if user_input:
        log_path = user_input.strip("'\"")
    else:
        log_path = cfg["log_file_path"]

    # 2. Parse the chosen log file
    events = parse_log_file(log_path)
    if not events:
        print(f"No SSH events found in {log_path} or file not accessible.")
        sys.exit(0)

    # 3. Pattern detection
    repeated_failures_alerts = detect_repeated_failures(events, cfg["failed_threshold"])
    time_window_alerts = detect_time_window(events, cfg["time_window_seconds"], cfg["time_window_threshold"])

    # 4. Reputation checks + whitelist/blacklist
    unique_ips = {e.ip for e in events}
    rep_alerts = []
    for ip in unique_ips:
        # Skip whitelisted
        if is_whitelisted(ip, cfg["whitelist"]):
            continue
        # Flag blacklisted
        if is_blacklisted(ip, cfg["blacklist"]):
            rep_alerts.append({
                "timestamp": datetime.now().isoformat(),
                "alert_type": "BlacklistHit",
                "source_ip": ip,
                "severity": "HIGH",
                "description": "IP found in blacklist"
            })
            continue
        # Check reputation
        rep_alert = check_ip_reputation(ip, cfg["reputation_threshold"])
        if rep_alert:
            rep_alerts.append(rep_alert)

    # 5. Combine all alerts
    all_alerts = repeated_failures_alerts + time_window_alerts + rep_alerts

    if not all_alerts:
        print("No alerts generated. System appears normal.")
        sys.exit(0)

    # 6. Write alerts to JSON log file
    try:
        with open(cfg["alert_log"], "a", encoding="utf-8") as f:
            for alert in all_alerts:
                f.write(json.dumps(alert) + "\n")
        print(f"[INFO] {len(all_alerts)} alerts written to {cfg['alert_log']}")
    except IOError:
        print(f"[ERROR] Unable to write alerts to {cfg['alert_log']}")

    # Also print to stdout
    for alert in all_alerts:
        print(json.dumps(alert, indent=2))

    print(f"\n[INFO] Total Alerts Generated: {len(all_alerts)}")


if __name__ == "__main__":
    main()
