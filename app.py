from flask import Flask, render_template, request, redirect, session
import sqlite3
from datetime import datetime

app = Flask(__name__)
app.secret_key = "supersecretkey"


def get_db():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
    CREATE TABLE IF NOT EXISTS blocked_ips(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT
    )
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        time TEXT,
        message TEXT
    )
    """)

    conn.commit()
    conn.close()


init_db()


# LOGIN
@app.route("/", methods=["GET","POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        user_ip = request.remote_addr

        if username == "admin" and password == "admin":

            session["user"] = username

            print(f"[LOGIN] {datetime.now()} User logged in from IP: {user_ip}", flush=True)

            conn = get_db()
            conn.execute(
                "INSERT INTO logs(time,message) VALUES(?,?)",
                (datetime.now(), f"User login from IP {user_ip}")
            )
            conn.commit()
            conn.close()

            return redirect("/dashboard")

        print(f"[FAILED LOGIN] {datetime.now()} Failed login from {user_ip}", flush=True)

    return render_template("login.html")


# DASHBOARD
@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/")

    conn = get_db()

    blocked_ips = conn.execute(
        "SELECT * FROM blocked_ips"
    ).fetchall()

    logs = conn.execute(
        "SELECT * FROM logs ORDER BY id DESC"
    ).fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        blocked_ips=blocked_ips,
        logs=logs
    )


# BLOCK IP
@app.route("/block_ip", methods=["POST"])
def block_ip():

    if "user" not in session:
        return redirect("/")

    ip = request.form.get("ip")

    conn = get_db()

    conn.execute(
        "INSERT INTO blocked_ips(ip_address) VALUES(?)",
        (ip,)
    )

    conn.execute(
        "INSERT INTO logs(time,message) VALUES(?,?)",
        (datetime.now(), f"Blocked IP {ip}")
    )

    conn.commit()
    conn.close()

    print(f"[BLOCK] {datetime.now()} Blocked IP: {ip}", flush=True)

    return redirect("/dashboard")


# UNBLOCK IP
@app.route("/unblock/<int:id>")
def unblock(id):

    conn = get_db()

    conn.execute(
        "DELETE FROM blocked_ips WHERE id=?",
        (id,)
    )

    conn.commit()
    conn.close()

    print(f"[UNBLOCK] {datetime.now()} Unblocked IP ID: {id}", flush=True)

    return redirect("/dashboard")


# LOGOUT
@app.route("/logout")
def logout():

    print(f"[LOGOUT] {datetime.now()} User logged out", flush=True)

    session.clear()

    return redirect("/")


if __name__ == "__main__":
    app.run(host="0.0.0.0",port=5000)