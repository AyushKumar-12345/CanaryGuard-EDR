import os
import sys
import json
import time
import math
import hmac
import socket
import hashlib
import logging
import argparse
import datetime
import platform
import collections
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

DEFAULT_CONFIG = {
    "watch_directories": ["."],
    "baseline_file": "baseline.json",
    "log_file": "logs/fim.log",
    "audit_json_file": "logs/audit_events.json",
    "report_file": "reports/report.json",
    "hmac_secret_file": ".fim_key",
    "canary_filename": ".canary_token.dat",
    "canary_directories": [],
    "webhook_url": "",
    "entropy_threshold": 7.2,
    "rapid_mod_threshold_count": 5,
    "rapid_mod_window_seconds": 3,
    "excluded_extensions": [".tmp", ".log", ".swp", ".git"]
}

def load_or_create_config(config_path: str = "config.json") -> dict:
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                user_config = json.load(f)
                config = DEFAULT_CONFIG.copy()
                config.update(user_config)
                return config
        except Exception:
            return DEFAULT_CONFIG.copy()
    else:
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        return DEFAULT_CONFIG.copy()

CONFIG = load_or_create_config()

def get_or_create_hmac_secret(key_file: str) -> bytes:
    if os.path.exists(key_file):
        try:
            with open(key_file, "rb") as f:
                key = f.read().strip()
                if key:
                    return key
        except Exception:
            pass
    key = hashlib.sha256(os.urandom(64)).hexdigest().encode("utf-8")
    try:
        with open(key_file, "wb") as f:
            f.write(key)
    except Exception:
        pass
    return key

HMAC_SECRET = get_or_create_hmac_secret(CONFIG["hmac_secret_file"])

def setup_logging() -> logging.Logger:
    log_dir = os.path.dirname(CONFIG["log_file"])
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    logger = logging.getLogger("CanaryGuard")
    logger.setLevel(logging.DEBUG)
    if not logger.handlers:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_fmt = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        console_handler.setFormatter(console_fmt)
        file_handler = logging.FileHandler(CONFIG["log_file"], encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_fmt = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(file_fmt)
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)
    return logger

logger = setup_logging()

def should_ignore_file(filepath: str) -> bool:
    abs_path = os.path.abspath(filepath)
    ignored_exact = [
        os.path.abspath(CONFIG.get("baseline_file", "baseline.json")),
        os.path.abspath(CONFIG.get("log_file", "logs/fim.log")),
        os.path.abspath(CONFIG.get("audit_json_file", "logs/audit_events.json")),
        os.path.abspath(CONFIG.get("report_file", "reports/report.json")),
        os.path.abspath(CONFIG.get("hmac_secret_file", ".fim_key"))
    ]
    if abs_path in ignored_exact:
        return True
    excluded_exts = tuple(CONFIG.get("excluded_extensions", []))
    if filepath.endswith(excluded_exts):
        return True
    return False

def log_audit_json(event_type: str, severity: str, details: dict) -> None:
    audit_file = CONFIG["audit_json_file"]
    audit_dir = os.path.dirname(audit_file)
    if audit_dir:
        os.makedirs(audit_dir, exist_ok=True)
    payload = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "hostname": socket.gethostname(),
        "event_type": event_type,
        "severity": severity,
        "details": details
    }
    try:
        with open(audit_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload) + "\n")
    except Exception as e:
        logger.error(f"Audit log write failed: {e}")

def dispatch_webhook_alert(event_type: str, severity: str, details: dict) -> None:
    webhook_url = CONFIG.get("webhook_url", "").strip()
    if not webhook_url:
        return
    payload = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "hostname": socket.gethostname(),
        "alert_type": event_type,
        "severity": severity,
        "details": details
    }
    try:
        requests.post(webhook_url, json=payload, timeout=3)
    except Exception as e:
        logger.error(f"Webhook dispatch failed: {e}")

def trigger_alert(event_type: str, severity: str, details: dict) -> None:
    if severity == "CRITICAL":
        logger.critical(f"[{event_type}] {details}")
    elif severity == "WARNING":
        logger.warning(f"[{event_type}] {details}")
    else:
        logger.info(f"[{event_type}] {details}")
    log_audit_json(event_type, severity, details)
    dispatch_webhook_alert(event_type, severity, details)

def calculate_shannon_entropy(filepath: str) -> float:
    try:
        byte_counts = collections.Counter()
        total_bytes = 0
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                byte_counts.update(chunk)
                total_bytes += len(chunk)
        if total_bytes == 0:
            return 0.0
        entropy = 0.0
        for count in byte_counts.values():
            p_x = count / total_bytes
            if p_x > 0:
                entropy -= p_x * math.log2(p_x)
        return round(entropy, 4)
    except Exception:
        return 0.0

def compute_hashes(filepath: str) -> Tuple[Optional[str], Optional[str]]:
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        raw_hash = sha256.hexdigest()
        signed_hmac = hmac.new(HMAC_SECRET, raw_hash.encode("utf-8"), hashlib.sha256).hexdigest()
        return raw_hash, signed_hmac
    except PermissionError:
        logger.warning(f"Permission denied reading: {filepath}")
        return None, None
    except FileNotFoundError:
        return None, None
    except Exception as e:
        logger.error(f"Error computing hashes for {filepath}: {e}")
        return None, None

def get_file_metadata(filepath: str) -> dict:
    try:
        stat = os.stat(filepath)
        return {
            "size_bytes": stat.st_size,
            "modified_time": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "created_time": datetime.datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "permissions": oct(stat.st_mode)[-4:],
            "entropy": calculate_shannon_entropy(filepath)
        }
    except Exception:
        return {}

def plant_canary_tokens(directories: List[str]) -> List[str]:
    planted = []
    token_name = CONFIG.get("canary_filename", ".canary_token.dat")
    for d in directories:
        if not os.path.exists(d):
            os.makedirs(d, exist_ok=True)
        token_path = os.path.abspath(os.path.join(d, token_name))
        token_data = f"CANARY_TOKEN:{hashlib.sha256(token_path.encode()).hexdigest()}:{time.time()}\n"
        try:
            with open(token_path, "w", encoding="utf-8") as f:
                f.write(token_data)
            planted.append(token_path)
            logger.info(f"Canary token planted: {token_path}")
        except Exception as e:
            logger.error(f"Failed to plant canary at {token_path}: {e}")
    return planted

def create_baseline(target_paths: List[str]) -> dict:
    canary_dirs = CONFIG.get("canary_directories", [])
    if canary_dirs:
        plant_canary_tokens(canary_dirs)
    baseline = {
        "meta": {
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "target_paths": [os.path.abspath(p) for p in target_paths],
            "platform": platform.system(),
            "python_version": platform.python_version(),
            "hostname": socket.gethostname(),
            "entropy_threshold": CONFIG.get("entropy_threshold", 7.2),
            "total_files": 0,
            "error_count": 0
        },
        "files": {}
    }
    file_count = 0
    error_count = 0
    for target_path in target_paths:
        abs_target = os.path.abspath(target_path)
        if not os.path.exists(abs_target):
            logger.error(f"Target path does not exist: {abs_target}")
            continue
        for root, dirs, files in os.walk(abs_target):
            dirs[:] = [d for d in dirs if not d.startswith(".git")]
            for filename in files:
                filepath = os.path.abspath(os.path.join(root, filename))
                if should_ignore_file(filepath):
                    continue
                raw_hash, signed_hmac = compute_hashes(filepath)
                if raw_hash and signed_hmac:
                    baseline["files"][filepath] = {
                        "hash": raw_hash,
                        "hmac": signed_hmac,
                        "metadata": get_file_metadata(filepath)
                    }
                    file_count += 1
                else:
                    error_count += 1
    baseline["meta"]["total_files"] = file_count
    baseline["meta"]["error_count"] = error_count
    baseline_path = CONFIG.get("baseline_file", "baseline.json")
    base_dir = os.path.dirname(baseline_path)
    if base_dir:
        os.makedirs(base_dir, exist_ok=True)
    with open(baseline_path, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=2)
    logger.info(f"Baseline saved to {baseline_path} ({file_count} files indexed)")
    return baseline

def load_baseline() -> Optional[dict]:
    baseline_path = CONFIG.get("baseline_file", "baseline.json")
    if not os.path.exists(baseline_path):
        logger.error(f"Baseline file missing at {baseline_path}")
        return None
    try:
        with open(baseline_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Corrupted baseline file: {e}")
        return None

def check_integrity(target_paths: List[str]) -> dict:
    baseline = load_baseline()
    if not baseline:
        sys.exit(1)
    baseline_files = baseline.get("files", {})
    current_files = {}
    for target_path in target_paths:
        abs_target = os.path.abspath(target_path)
        if not os.path.exists(abs_target):
            continue
        for root, dirs, files in os.walk(abs_target):
            dirs[:] = [d for d in dirs if not d.startswith(".git")]
            for filename in files:
                filepath = os.path.abspath(os.path.join(root, filename))
                if should_ignore_file(filepath):
                    continue
                raw_hash, signed_hmac = compute_hashes(filepath)
                if raw_hash and signed_hmac:
                    current_files[filepath] = {
                        "hash": raw_hash,
                        "hmac": signed_hmac,
                        "metadata": get_file_metadata(filepath)
                    }
    results = {
        "check_time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "hostname": socket.gethostname(),
        "modified": [],
        "deleted": [],
        "new_files": [],
        "canary_tampered": [],
        "entropy_anomalies": [],
        "unchanged": [],
        "summary": {}
    }
    canary_token_name = CONFIG.get("canary_filename", ".canary_token.dat")
    entropy_threshold = float(CONFIG.get("entropy_threshold", 7.2))
    for filepath, info in baseline_files.items():
        is_canary = os.path.basename(filepath) == canary_token_name
        if filepath not in current_files:
            entry = {"path": filepath, "baseline_hash": info["hash"]}
            if is_canary:
                results["canary_tampered"].append(entry)
                trigger_alert("RANSOMWARE_CANARY_DELETED", "CRITICAL", entry)
            else:
                results["deleted"].append(entry)
                trigger_alert("FILE_DELETED", "WARNING", entry)
        else:
            curr_info = current_files[filepath]
            curr_hash = curr_info["hash"]
            curr_entropy = curr_info["metadata"].get("entropy", 0.0)
            if curr_hash != info["hash"]:
                entry = {
                    "path": filepath,
                    "baseline_hash": info["hash"],
                    "current_hash": curr_hash,
                    "entropy": curr_entropy
                }
                if is_canary:
                    results["canary_tampered"].append(entry)
                    trigger_alert("RANSOMWARE_CANARY_MODIFIED", "CRITICAL", entry)
                else:
                    results["modified"].append(entry)
                    severity = "CRITICAL" if curr_entropy >= entropy_threshold else "WARNING"
                    trigger_alert("FILE_MODIFIED", severity, entry)
                if curr_entropy >= entropy_threshold:
                    results["entropy_anomalies"].append(entry)
                    trigger_alert("HIGH_ENTROPY_ENCRYPTION_DETECTED", "CRITICAL", entry)
            else:
                results["unchanged"].append(filepath)
    for filepath, curr_info in current_files.items():
        if filepath not in baseline_files:
            curr_entropy = curr_info["metadata"].get("entropy", 0.0)
            entry = {
                "path": filepath,
                "current_hash": curr_info["hash"],
                "entropy": curr_entropy
            }
            results["new_files"].append(entry)
            trigger_alert("NEW_FILE_CREATED", "INFO", entry)
            if curr_entropy >= entropy_threshold:
                results["entropy_anomalies"].append(entry)
                trigger_alert("HIGH_ENTROPY_NEW_FILE", "CRITICAL", entry)
    total_alerts = (
        len(results["modified"])
        + len(results["deleted"])
        + len(results["canary_tampered"])
        + len(results["entropy_anomalies"])
    )
    results["summary"] = {
        "total_baseline_files": len(baseline_files),
        "unchanged": len(results["unchanged"]),
        "modified": len(results["modified"]),
        "deleted": len(results["deleted"]),
        "new_files": len(results["new_files"]),
        "canary_tampered": len(results["canary_tampered"]),
        "entropy_anomalies": len(results["entropy_anomalies"]),
        "status": "ALERT" if total_alerts > 0 else "CLEAN"
    }
    return results

def save_report(results: dict) -> None:
    report_file = CONFIG.get("report_file", "reports/report.json")
    report_dir = os.path.dirname(report_file)
    if report_dir:
        os.makedirs(report_dir, exist_ok=True)
    report_payload = {k: v for k, v in results.items() if k != "unchanged"}
    report_payload["unchanged_count"] = len(results.get("unchanged", []))
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report_payload, f, indent=2)

class EventDrivenIntegrityHandler(FileSystemEventHandler):
    def __init__(self, baseline_files: dict):
        super().__init__()
        self.baseline_files = baseline_files
        self.recent_events = collections.deque()
        self.canary_name = CONFIG.get("canary_filename", ".canary_token.dat")
        self.entropy_threshold = float(CONFIG.get("entropy_threshold", 7.2))
        self.rapid_threshold = int(CONFIG.get("rapid_mod_threshold_count", 5))
        self.rapid_window = float(CONFIG.get("rapid_mod_window_seconds", 3))

    def _check_rapid_modification(self, event_path: str):
        now = time.time()
        self.recent_events.append(now)
        while self.recent_events and (now - self.recent_events[0] > self.rapid_window):
            self.recent_events.popleft()
        if len(self.recent_events) >= self.rapid_threshold:
            trigger_alert("RAPID_MODIFICATION_BURST", "CRITICAL", {
                "events_count": len(self.recent_events),
                "time_window_seconds": self.rapid_window,
                "latest_trigger_file": event_path
            })
            self.recent_events.clear()

    def on_modified(self, event):
        if event.is_directory:
            return
        filepath = os.path.abspath(event.src_path)
        if should_ignore_file(filepath):
            return
        self._check_rapid_modification(filepath)
        curr_hash, _ = compute_hashes(filepath)
        if not curr_hash:
            return
        curr_entropy = calculate_shannon_entropy(filepath)
        if os.path.basename(filepath) == self.canary_name:
            trigger_alert("RANSOMWARE_CANARY_MODIFIED", "CRITICAL", {
                "path": filepath,
                "entropy": curr_entropy
            })
            return
        if filepath in self.baseline_files:
            original_hash = self.baseline_files[filepath]["hash"]
            if curr_hash != original_hash:
                sev = "CRITICAL" if curr_entropy >= self.entropy_threshold else "WARNING"
                trigger_alert("REALTIME_FILE_MODIFIED", sev, {
                    "path": filepath,
                    "baseline_hash": original_hash,
                    "current_hash": curr_hash,
                    "entropy": curr_entropy
                })
        else:
            trigger_alert("REALTIME_UNTRACKED_FILE_MODIFIED", "INFO", {
                "path": filepath,
                "current_hash": curr_hash,
                "entropy": curr_entropy
            })

    def on_created(self, event):
        if event.is_directory:
            return
        filepath = os.path.abspath(event.src_path)
        if should_ignore_file(filepath):
            return
        curr_hash, _ = compute_hashes(filepath)
        curr_entropy = calculate_shannon_entropy(filepath)
        sev = "CRITICAL" if curr_entropy >= self.entropy_threshold else "INFO"
        trigger_alert("REALTIME_FILE_CREATED", sev, {
            "path": filepath,
            "hash": curr_hash,
            "entropy": curr_entropy
        })

    def on_deleted(self, event):
        if event.is_directory:
            return
        filepath = os.path.abspath(event.src_path)
        if should_ignore_file(filepath):
            return
        self._check_rapid_modification(filepath)
        if os.path.basename(filepath) == self.canary_name:
            trigger_alert("RANSOMWARE_CANARY_DELETED", "CRITICAL", {"path": filepath})
            return
        if filepath in self.baseline_files:
            trigger_alert("REALTIME_BASELINE_FILE_DELETED", "WARNING", {
                "path": filepath,
                "baseline_hash": self.baseline_files[filepath]["hash"]
            })
        else:
            trigger_alert("REALTIME_FILE_DELETED", "INFO", {"path": filepath})

    def on_moved(self, event):
        if event.is_directory:
            return
        src_path = os.path.abspath(event.src_path)
        dest_path = os.path.abspath(event.dest_path)
        if should_ignore_file(dest_path):
            return
        self._check_rapid_modification(dest_path)
        trigger_alert("REALTIME_FILE_RENAMED", "WARNING", {
            "source_path": src_path,
            "destination_path": dest_path
        })

def run_event_monitor(target_paths: List[str]) -> None:
    baseline = load_baseline()
    if not baseline:
        sys.exit(1)
    baseline_files = baseline.get("files", {})
    event_handler = EventDrivenIntegrityHandler(baseline_files)
    observer = Observer()
    for path in target_paths:
        abs_p = os.path.abspath(path)
        if os.path.exists(abs_p):
            observer.schedule(event_handler, path=abs_p, recursive=True)
            logger.info(f"Attached kernel filesystem monitor to: {abs_p}")
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

def parse_cli_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="CanaryGuard-EDR",
        description="Enterprise File Integrity Monitoring & Ransomware Canary Engine"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--init", action="store_true", help="Create cryptographic baseline snapshot")
    group.add_argument("--check", action="store_true", help="Execute single-pass integrity audit")
    group.add_argument("--watch", action="store_true", help="Start real-time kernel event-driven detection daemon")
    group.add_argument("--report", action="store_true", help="Display latest audit report")
    parser.add_argument("--path", nargs="*", default=None, help="Target paths to monitor")
    return parser.parse_args()

def main() -> None:
    args = parse_cli_arguments()
    target_paths = args.path if args.path else CONFIG.get("watch_directories", ["."])
    if args.init:
        create_baseline(target_paths)
    elif args.check:
        results = check_integrity(target_paths)
        save_report(results)
        print(json.dumps(results["summary"], indent=2))
    elif args.watch:
        run_event_monitor(target_paths)
    elif args.report:
        report_file = CONFIG.get("report_file", "reports/report.json")
        if os.path.exists(report_file):
            with open(report_file, "r", encoding="utf-8") as f:
                print(f.read())
        else:
            logger.error("No report found.")

if __name__ == "__main__":
    main()