"""
dashboard_bridge.py
Connects the cybersecurity multi-agent system to the Flask IP Defense Dashboard.

Consumes classified threats from Kafka and:
  1. Writes blocked IPs into the Flask dashboard's SQLite database
  2. Writes log entries for every threat event
  3. Exposes a /sync endpoint so the dashboard can pull live ES data

Run alongside your agents:
  python dashboard_bridge.py

The Flask dashboard will then show real-time threat data from your AI agents.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime
from typing import Any

from flask import Flask, jsonify
from loguru import logger
from dotenv import load_dotenv

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────
# Path to the Flask dashboard's SQLite database
DASHBOARD_DB: str = os.getenv(
    "DASHBOARD_DB_PATH",
    "../ip-defense-dashboard/database.db"   # adjust if needed
)

KAFKA_BOOTSTRAP: str = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
BRIDGE_PORT: int     = int(os.getenv("BRIDGE_PORT", 5050))

# Only auto-block IPs for these severity levels
AUTO_BLOCK_SEVERITIES: set[str] = {"critical", "high"}


# ── SQLite helpers ─────────────────────────────────────────────────────────────

def get_dashboard_db() -> sqlite3.Connection:
    """
    Return a connection to the Flask dashboard's SQLite database.

    Returns:
        sqlite3.Connection with row_factory set
    """
    conn = sqlite3.connect(DASHBOARD_DB)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_tables() -> None:
    """
    Create dashboard tables if they don't exist yet.
    Safe to call on every startup.
    """
    conn = get_dashboard_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips(
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS logs(
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            time    TEXT,
            message TEXT
        )
    """)
    conn.commit()
    conn.close()
    logger.info(f"[BRIDGE] Dashboard DB ready at {DASHBOARD_DB}")


def write_log(message: str) -> None:
    """
    Insert a log entry into the Flask dashboard's logs table.

    Args:
        message: human-readable log string
    """
    try:
        conn = get_dashboard_db()
        conn.execute(
            "INSERT INTO logs(time, message) VALUES(?, ?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), message)
        )
        conn.commit()
        conn.close()
    except Exception as exc:
        logger.error(f"[BRIDGE] Failed to write log: {exc}")


def block_ip_in_dashboard(ip: str, reason: str) -> bool:
    """
    Add an IP to the Flask dashboard's blocked_ips table.
    Silently ignores duplicates (IP already blocked).

    Args:
        ip:     IP address string to block
        reason: reason for blocking (shown in log)

    Returns:
        True if newly blocked, False if already existed
    """
    try:
        conn = get_dashboard_db()
        existing = conn.execute(
            "SELECT id FROM blocked_ips WHERE ip_address = ?", (ip,)
        ).fetchone()

        if existing:
            conn.close()
            return False

        conn.execute(
            "INSERT INTO blocked_ips(ip_address) VALUES(?)", (ip,)
        )
        conn.execute(
            "INSERT INTO logs(time, message) VALUES(?, ?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
             f"[AUTO-BLOCKED by AI Agent] {ip} — {reason}")
        )
        conn.commit()
        conn.close()
        logger.warning(f"[BRIDGE] Blocked IP in dashboard: {ip} | {reason}")
        return True

    except Exception as exc:
        logger.error(f"[BRIDGE] Failed to block IP {ip}: {exc}")
        return False


# ── Threat Processing ──────────────────────────────────────────────────────────

def process_threat(threat: dict[str, Any]) -> None:
    """
    Process a classified threat from Kafka and push it to the Flask dashboard.

    Actions taken:
        - Always: writes a log entry with threat summary
        - If severity is critical/high AND source_ip exists: blocks the IP

    Args:
        threat: classified threat dict from the threats.classified Kafka topic
    """
    severity    = threat.get("severity", "unknown")
    source_ip   = threat.get("source_ip")
    agent_id    = threat.get("agent_id", "unknown-agent")
    mitre_ttp   = threat.get("mitre_ttp", "")
    details     = threat.get("details", {})
    pattern     = details.get("pattern", "unknown pattern")
    confidence  = threat.get("confidence", 0.0)

    # Always log the threat
    log_msg = (
        f"[{severity.upper()}] {pattern} detected by {agent_id} "
        f"| src={source_ip or 'N/A'} | TTP={mitre_ttp} "
        f"| confidence={confidence:.0%}"
    )
    write_log(log_msg)

    # Auto-block high/critical threats with a known source IP
    if severity in AUTO_BLOCK_SEVERITIES and source_ip:
        reason = f"{pattern} ({mitre_ttp}) — confidence {confidence:.0%}"
        blocked = block_ip_in_dashboard(source_ip, reason)
        if blocked:
            write_log(f"[RESPONSE] Auto-blocked {source_ip} — triggered by {pattern}")


# ── Kafka Consumer Thread ──────────────────────────────────────────────────────

def kafka_consumer_loop() -> None:
    """
    Background thread that consumes threats.classified topic
    and pushes data to the Flask dashboard database.
    """
    try:
        from confluent_kafka import Consumer, KafkaError
    except ImportError:
        logger.error("[BRIDGE] confluent-kafka not installed — Kafka sync disabled")
        return

    consumer = Consumer({
        "bootstrap.servers": KAFKA_BOOTSTRAP,
        "group.id": "dashboard-bridge-group",
        "auto.offset.reset": "latest",
    })
    consumer.subscribe(["threats.classified"])
    logger.info("[BRIDGE] Kafka consumer started — listening to threats.classified")

    while True:
        msg = consumer.poll(1.0)
        if msg is None:
            continue
        if msg.error():
            if msg.error().code() != KafkaError._PARTITION_EOF:
                logger.error(f"[BRIDGE] Kafka error: {msg.error()}")
            continue

        try:
            threat = json.loads(msg.value().decode("utf-8"))
            process_threat(threat)
        except Exception as exc:
            logger.exception(f"[BRIDGE] Error processing threat: {exc}")


# ── Flask Sync API ─────────────────────────────────────────────────────────────

bridge_app = Flask(__name__)


@bridge_app.route("/health")
def health() -> Any:
    """Health check for the bridge service."""
    return jsonify({"status": "ok", "service": "dashboard-bridge"})


@bridge_app.route("/sync/stats")
def sync_stats() -> Any:
    """
    Returns current dashboard stats — total blocked IPs and recent logs.
    The Flask dashboard can call this to show a live summary panel.
    """
    try:
        conn = get_dashboard_db()
        blocked_count = conn.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0]
        recent_logs   = conn.execute(
            "SELECT time, message FROM logs ORDER BY id DESC LIMIT 20"
        ).fetchall()
        conn.close()

        return jsonify({
            "blocked_ips": blocked_count,
            "recent_logs": [
                {"time": r["time"], "message": r["message"]}
                for r in recent_logs
            ],
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@bridge_app.route("/sync/inject_test")
def inject_test() -> Any:
    """
    Inject a synthetic test threat into the dashboard.
    Useful for demo — proves the pipeline works without needing a live attack.
    """
    test_threat = {
        "severity": "high",
        "source_ip": "192.168.99.99",
        "agent_id": "network-monitor-01",
        "mitre_ttp": "T1046",
        "confidence": 0.91,
        "details": {"pattern": "port_scan_demo", "distinct_ports": 75},
    }
    process_threat(test_threat)
    return jsonify({"status": "injected", "threat": test_threat})


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    """
    Start the dashboard bridge:
      1. Ensure SQLite tables exist
      2. Start Kafka consumer in background thread
      3. Start Flask sync API on port 5050
    """
    ensure_tables()

    # Start Kafka consumer in background
    thread = threading.Thread(target=kafka_consumer_loop, daemon=True)
    thread.start()

    logger.info(f"[BRIDGE] Sync API running on http://localhost:{BRIDGE_PORT}")
    logger.info("[BRIDGE] Flask dashboard: http://localhost:5000")
    logger.info("[BRIDGE] Test injection: http://localhost:5050/sync/inject_test")

    bridge_app.run(host="0.0.0.0", port=BRIDGE_PORT)


if __name__ == "__main__":
    main()