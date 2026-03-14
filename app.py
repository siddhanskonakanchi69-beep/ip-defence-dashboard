from flask import Flask, render_template, request, redirect, session
import sqlite3
from datetime import datetime

app = Flask(__name__)
app.secret_key = "secret123"


def get_db():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS blocked_ips(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        time TEXT,
        message TEXT
    )
    """)

    conn.commit()
    conn.close()


init_db()


@app.route("/", methods=["GET","POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        if username == "admin" and password == "admin":
            session["user"] = username
            return redirect("/dashboard")

    return render_template("login.html")


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


@app.route("/block_ip", methods=["POST"])
def block_ip():

    if "user" not in session:
        return redirect("/")

    ip = request.form["ip"]

    conn = get_db()

    conn.execute(
        "INSERT INTO blocked_ips(ip_address) VALUES(?)",
        (ip,)
    )

    conn.execute(
        "INSERT INTO logs(time,message) VALUES(?,?)",
        (
            datetime.now(),
            f"Blocked IP {ip}"
        )
    )

    conn.commit()
    conn.close()

    return redirect("/dashboard")


@app.route("/unblock/<int:id>")
def unblock(id):

    conn = get_db()

    conn.execute(
        "DELETE FROM blocked_ips WHERE id=?",
        (id,)
    )

    conn.execute(
        "INSERT INTO logs(time,message) VALUES(?,?)",
        (
            datetime.now(),
            "IP Unblocked"
        )
    )

    conn.commit()
    conn.close()

    return redirect("/dashboard")


@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")


if __name__ == "__main__":
    app.run(host="0.0.0.0",port=5000)