"""
IP Defense Dashboard - Real-Time Cybersecurity Traffic Monitor

Features:
  ✓ Real-time user IP tracking via server-side logging
  ✓ Request rate analysis and anomaly detection
  ✓ Suspicious activity flagging (brute force, port scanning patterns)
  ✓ Auto-blocking dangerous IPs
  ✓ Live visitor analytics dashboard
  ✓ Security metrics and trends
"""

from __future__ import annotations

import sqlite3
import hashlib
import secrets
import csv
import os
from datetime import datetime, timedelta
from collections import defaultdict
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
DATABASE = "database.db"
IP_LOG_FILE = "ip_logs.csv"  # Persistent IP data for ML models

# ────────────────────────────────────────────────────────────────────────────────
# SECURITY MONITORING CONFIG
# ────────────────────────────────────────────────────────────────────────────────

# Rate limiting thresholds (requests per minute)
SUSPICIOUS_REQUEST_RATE = 30  # >30 req/min = suspicious
CRITICAL_REQUEST_RATE = 100   # >100 req/min = critical

# Failed login attempts before auto-block
FAILED_LOGIN_THRESHOLD = 5

# Memory cache for real-time request tracking (IP -> list of timestamps)
request_tracker = defaultdict(list)
failed_login_tracker = defaultdict(int)

# ────────────────────────────────────────────────────────────────────────────────
# DATABASE FUNCTIONS
# ────────────────────────────────────────────────────────────────────────────────

def init_db() -> None:
    """Initialize SQLite database with required tables."""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Users table for login
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    
    # IP requests tracking
    c.execute("""
        CREATE TABLE IF NOT EXISTS ip_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            method TEXT,
            endpoint TEXT,
            status_code INTEGER,
            user_agent TEXT,
            threat_level TEXT DEFAULT 'normal'
        )
    """)
    
    # Blocked IPs
    c.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            reason TEXT,
            blocked_at TEXT,
            severity TEXT DEFAULT 'high'
        )
    """)
    
    # Security logs
    c.execute("""
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT,
            ip_address TEXT,
            message TEXT,
            severity TEXT DEFAULT 'info'
        )
    """)
    
    # Create default admin user if not exists
    try:
        password_hash = hashlib.sha256("admin123".encode()).hexdigest()
        c.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("admin", password_hash)
        )
    except sqlite3.IntegrityError:
        pass
    
    conn.commit()
    conn.close()
    
    # Initialize CSV log file for ML training
    init_ip_log()


def get_db_connection() -> sqlite3.Connection:
    """Get a database connection."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def is_ip_blocked(ip: str) -> bool:
    """Check if an IP is in the blocked list."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT 1 FROM blocked_ips WHERE ip_address = ?", (ip,))
    result = c.fetchone()
    conn.close()
    return result is not None


def get_client_ip() -> str:
    """Extract client IP address from request."""
    if request.environ.get('HTTP_X_FORWARDED_FOR'):
        return request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0].strip()
    return request.environ.get('REMOTE_ADDR', 'unknown')


def init_ip_log() -> None:
    """Initialize CSV file for IP logging if it doesn't exist."""
    if not os.path.exists(IP_LOG_FILE):
        with open(IP_LOG_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'timestamp', 'ip_address', 'method', 'endpoint', 
                'status_code', 'user_agent', 'threat_level'
            ])


def log_request_to_csv(ip: str, method: str, endpoint: str, status_code: int, threat_level: str) -> None:
    """Log request to CSV file for ML model training."""
    try:
        with open(IP_LOG_FILE, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now().isoformat(),
                ip,
                method,
                endpoint,
                status_code,
                request.headers.get('User-Agent', 'unknown'),
                threat_level
            ])
    except Exception as e:
        print(f"Error writing to CSV: {e}")


def log_request(ip: str, method: str, endpoint: str, status_code: int) -> None:
    """Log incoming request to database and CSV file."""
    conn = get_db_connection()
    c = conn.cursor()
    user_agent = request.headers.get('User-Agent', 'unknown')
    
    # Analyze threat level
    threat_level = analyze_threat_level(ip)
    
    c.execute("""
        INSERT INTO ip_requests 
        (ip_address, timestamp, method, endpoint, status_code, user_agent, threat_level)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (ip, datetime.now().isoformat(), method, endpoint, status_code, user_agent, threat_level))
    
    conn.commit()
    conn.close()
    
    # Also log to CSV for ML model training
    log_request_to_csv(ip, method, endpoint, status_code, threat_level)


def analyze_threat_level(ip: str) -> str:
    """Analyze IP threat level based on request patterns."""
    conn = get_db_connection()
    c = conn.cursor()
    
    # Count requests in last minute
    one_minute_ago = (datetime.now() - timedelta(minutes=1)).isoformat()
    c.execute(
        "SELECT COUNT(*) FROM ip_requests WHERE ip_address = ? AND timestamp > ?",
        (ip, one_minute_ago)
    )
    recent_count = c.fetchone()[0]
    
    # Count failed login attempts
    failed_logins = failed_login_tracker.get(ip, 0)
    
    conn.close()
    
    # Determine threat level
    if recent_count > CRITICAL_REQUEST_RATE or failed_logins >= FAILED_LOGIN_THRESHOLD:
        return "critical"
    elif recent_count > SUSPICIOUS_REQUEST_RATE or failed_logins >= 3:
        return "suspicious"
    elif recent_count > 10:
        return "warning"
    return "normal"


def security_log(ip: str, event_type: str, message: str, severity: str = "info") -> None:
    """Write security event to log."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO security_logs (timestamp, event_type, ip_address, message, severity)
        VALUES (?, ?, ?, ?, ?)
    """, (datetime.now().isoformat(), event_type, ip, message, severity))
    conn.commit()
    conn.close()


# ────────────────────────────────────────────────────────────────────────────────
# AUTHENTICATION & MIDDLEWARE
# ────────────────────────────────────────────────────────────────────────────────

def login_required(f):
    """Decorator to require login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.before_request
def check_blocked_ip():
    """Check if incoming IP is blocked."""
    client_ip = get_client_ip()
    if is_ip_blocked(client_ip):
        security_log(client_ip, "blocked_access", "Blocked IP attempted access", "critical")
        return jsonify({"error": "Access denied - your IP is blocked"}), 403


@app.after_request
def log_request_middleware(response):
    """Log all requests after processing."""
    if request.endpoint not in ['static']:
        client_ip = get_client_ip()
        log_request(client_ip, request.method, request.path, response.status_code)
    return response


# ────────────────────────────────────────────────────────────────────────────────
# ROUTES - Authentication
# ────────────────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    """Redirect to dashboard or login."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page."""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        client_ip = get_client_ip()
        
        # Check if IP has too many failed attempts
        if failed_login_tracker.get(client_ip, 0) >= FAILED_LOGIN_THRESHOLD:
            security_log(client_ip, "brute_force_detected", 
                        f"Too many failed login attempts from {client_ip}", "critical")
            block_ip(client_ip, "Brute force attack detected")
            return jsonify({"error": "Too many failed attempts - IP blocked"}), 403
        
        # Verify credentials
        conn = get_db_connection()
        c = conn.cursor()
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        c.execute("SELECT id FROM users WHERE username = ? AND password_hash = ?", 
                 (username, password_hash))
        user = c.fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = username
            failed_login_tracker[client_ip] = 0  # Reset counter
            security_log(client_ip, "login_success", f"User {username} logged in", "info")
            return redirect(url_for('dashboard'))
        else:
            failed_login_tracker[client_ip] += 1
            security_log(client_ip, "login_failed", 
                        f"Failed login attempt for user {username}", "warning")
    
    return render_template('login.html')


@app.route('/logout')
def logout():
    """Logout user."""
    username = session.get('username', 'unknown')
    security_log(get_client_ip(), "logout", f"User {username} logged out", "info")
    session.clear()
    return redirect(url_for('login'))


# ────────────────────────────────────────────────────────────────────────────────
# ROUTES - Dashboard
# ────────────────────────────────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard with security metrics."""
    conn = get_db_connection()
    c = conn.cursor()
    
    # Get statistics
    c.execute("SELECT COUNT(*) FROM ip_requests")
    total_requests = c.fetchone()[0]
    
    c.execute("SELECT COUNT(DISTINCT ip_address) FROM ip_requests")
    unique_ips = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM blocked_ips")
    blocked_count = c.fetchone()[0]
    
    # Get recent suspicious activity
    c.execute("""
        SELECT DISTINCT ip_address, COUNT(*) as request_count, 
               MAX(timestamp) as last_seen, threat_level
        FROM ip_requests
        WHERE timestamp > datetime('now', '-1 hour')
        GROUP BY ip_address
        ORDER BY request_count DESC
        LIMIT 10
    """)
    suspicious_ips = c.fetchall()
    
    # Get recent security logs
    c.execute("""
        SELECT timestamp, event_type, ip_address, message, severity
        FROM security_logs
        ORDER BY id DESC
        LIMIT 20
    """)
    logs = c.fetchall()
    
    # Get blocked IPs
    c.execute("""
        SELECT ip_address, reason, blocked_at, severity
        FROM blocked_ips
        ORDER BY blocked_at DESC
        LIMIT 15
    """)
    blocked_ips = c.fetchall()
    
    conn.close()
    
    return render_template('dashboard.html',
                         total_requests=total_requests,
                         unique_ips=unique_ips,
                         blocked_count=blocked_count,
                         suspicious_ips=suspicious_ips,
                         logs=logs,
                         blocked_ips=blocked_ips,
                         username=session.get('username'))


# ────────────────────────────────────────────────────────────────────────────────
# ROUTES - IP Management
# ────────────────────────────────────────────────────────────────────────────────

def block_ip(ip: str, reason: str) -> bool:
    """Block an IP address."""
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
            INSERT INTO blocked_ips (ip_address, reason, blocked_at, severity)
            VALUES (?, ?, ?, ?)
        """, (ip, reason, datetime.now().isoformat(), "high"))
        conn.commit()
        conn.close()
        security_log(ip, "ip_blocked", f"IP blocked: {reason}", "critical")
        return True
    except sqlite3.IntegrityError:
        return False


@app.route('/block_ip', methods=['POST'])
@login_required
def block_ip_route():
    """Block an IP address via dashboard."""
    ip = request.form.get('ip', '')
    reason = request.form.get('reason', 'Manual block')
    
    if block_ip(ip, reason):
        return redirect(url_for('dashboard'))
    return redirect(url_for('dashboard'))


@app.route('/unblock/<ip>')
@login_required
def unblock_ip(ip: str):
    """Unblock an IP address."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM blocked_ips WHERE ip_address = ?", (ip,))
    conn.commit()
    conn.close()
    security_log(get_client_ip(), "ip_unblocked", f"IP unblocked: {ip}", "info")
    return redirect(url_for('dashboard'))


# ────────────────────────────────────────────────────────────────────────────────
# ROUTES - API (for real-time updates)
# ────────────────────────────────────────────────────────────────────────────────

@app.route('/api/live_visitors')
@login_required
def live_visitors():
    """Get real-time visitor data."""
    conn = get_db_connection()
    c = conn.cursor()
    
    # Get last 5 minutes of unique IPs
    five_min_ago = (datetime.now() - timedelta(minutes=5)).isoformat()
    c.execute("""
        SELECT DISTINCT ip_address, MAX(timestamp) as last_seen, 
               COUNT(*) as requests, threat_level
        FROM ip_requests
        WHERE timestamp > ?
        GROUP BY ip_address
        ORDER BY last_seen DESC
        LIMIT 20
    """, (five_min_ago,))
    
    visitors = [{
        'ip': row['ip_address'],
        'last_seen': row['last_seen'],
        'requests': row['requests'],
        'threat_level': row['threat_level']
    } for row in c.fetchall()]
    
    conn.close()
    return jsonify(visitors)


@app.route('/api/threat_stats')
@login_required
def threat_stats():
    """Get threat statistics."""
    conn = get_db_connection()
    c = conn.cursor()
    
    c.execute("""
        SELECT threat_level, COUNT(*) as count
        FROM ip_requests
        WHERE timestamp > datetime('now', '-1 hour')
        GROUP BY threat_level
    """)
    
    stats = {row['threat_level']: row['count'] for row in c.fetchall()}
    conn.close()
    
    return jsonify({
        'normal': stats.get('normal', 0),
        'warning': stats.get('warning', 0),
        'suspicious': stats.get('suspicious', 0),
        'critical': stats.get('critical', 0)
    })


@app.route('/api/download_ip_logs')
@login_required
def download_ip_logs():
    """Download IP logs CSV for ML model training."""
    if not os.path.exists(IP_LOG_FILE):
        return jsonify({"error": "No IP logs available yet"}), 404
    
    with open(IP_LOG_FILE, 'r') as f:
        csv_data = f.read()
    
    return csv_data, 200, {
        'Content-Type': 'text/csv',
        'Content-Disposition': f'attachment; filename=ip_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    }


@app.route('/api/ip_logs_preview')
@login_required
def ip_logs_preview():
    """Get preview of IP logs (last 100 entries)."""
    if not os.path.exists(IP_LOG_FILE):
        return jsonify({"entries": [], "total_records": 0})
    
    entries = []
    try:
        with open(IP_LOG_FILE, 'r') as f:
            reader = csv.DictReader(f)
            # Get all rows
            all_rows = list(reader)
            # Return last 100
            entries = all_rows[-100:] if len(all_rows) > 100 else all_rows
    except Exception as e:
        return jsonify({"error": str(e), "entries": []}), 500
    
    return jsonify({
        "entries": entries,
        "total_records": len(entries),
        "csv_file": IP_LOG_FILE
    })


if __name__ == '__main__':
    init_db()
    app.run(debug=False, host='0.0.0.0', port=5000)