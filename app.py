from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# -------------------------
# DATABASE MODELS
# -------------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    password = db.Column(db.String(50))


class BlockedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(100))


class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(200))
    time = db.Column(db.DateTime, default=datetime.utcnow)


# -------------------------
# LOGIN
# -------------------------

@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        print(f"[LOGIN ATTEMPT] from {request.remote_addr}")

        user = User.query.filter_by(username=username, password=password).first()

        if user:

            print("[LOGIN SUCCESS]")

            session["user"] = username

            log = Log(message="Admin logged in")
            db.session.add(log)
            db.session.commit()

            return redirect("/dashboard")

        else:
            print("[LOGIN FAILED]")
            return "Invalid credentials"

    return render_template("login.html")


# -------------------------
# DASHBOARD
# -------------------------

@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/")

    blocked_ips = BlockedIP.query.all()

    try:
        logs = Log.query.order_by(Log.time.desc()).all()
    except:
        logs = []

    return render_template("dashboard.html", blocked_ips=blocked_ips, logs=logs)


# -------------------------
# BLOCK IP
# -------------------------

@app.route("/block_ip", methods=["POST"])
def block_ip():

    if "user" not in session:
        return redirect("/")

    ip = request.form["ip"]

    print(f"[SECURITY ALERT] Blocked IP {ip}")

    new_ip = BlockedIP(ip_address=ip)

    db.session.add(new_ip)

    log = Log(message=f"Blocked IP {ip}")
    db.session.add(log)

    db.session.commit()

    return redirect("/dashboard")


# -------------------------
# UNBLOCK IP
# -------------------------

@app.route("/unblock/<int:id>")
def unblock(id):

    if "user" not in session:
        return redirect("/")

    ip = BlockedIP.query.get(id)

    print(f"[SECURITY] Unblocked IP {ip.ip_address}")

    log = Log(message=f"Unblocked IP {ip.ip_address}")
    db.session.add(log)

    db.session.delete(ip)

    db.session.commit()

    return redirect("/dashboard")


# -------------------------
# LOGOUT
# -------------------------

@app.route("/logout")
def logout():

    session.clear()

    print("[SESSION] Admin logged out")

    return redirect("/")


# -------------------------
# DATABASE INITIALIZATION
# -------------------------

with app.app_context():

    db.create_all()

    if not User.query.filter_by(username="admin").first():

        admin = User(username="admin", password="admin123")

        db.session.add(admin)
        db.session.commit()

        print("Admin user created")


# -------------------------
# RUN APP
# -------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)