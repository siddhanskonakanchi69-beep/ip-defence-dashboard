from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
import datetime

app = Flask(__name__)
app.secret_key = "secret123"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# ---------------------
# Database Models
# ---------------------

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    password = db.Column(db.String(50))


class BlockedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50))
    status = db.Column(db.String(20))


class Logs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(100))
    timestamp = db.Column(db.String(100))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---------------------
# Routes
# ---------------------

@app.route("/", methods=["GET","POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(
            username=request.form["username"],
            password=request.form["password"]
        ).first()

        if user:
            login_user(user)
            return redirect("/dashboard")

        flash("Invalid login")

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    ips = BlockedIP.query.all()
    logs = Logs.query.order_by(Logs.id.desc()).limit(10)
    return render_template("dashboard.html", ips=ips, logs=logs)


@app.route("/block", methods=["POST"])
@login_required
def block():
    ip = request.form["ip"]

    new_ip = BlockedIP(ip=ip, status="blocked")
    db.session.add(new_ip)

    log = Logs(
        action=f"Blocked IP {ip}",
        timestamp=str(datetime.datetime.now())
    )

    db.session.add(log)
    db.session.commit()

    return redirect("/dashboard")


@app.route("/unblock/<ip>")
@login_required
def unblock(ip):
    record = BlockedIP.query.filter_by(ip=ip).first()

    if record:
        db.session.delete(record)

        log = Logs(
            action=f"Unblocked IP {ip}",
            timestamp=str(datetime.datetime.now())
        )

        db.session.add(log)
        db.session.commit()

    return redirect("/dashboard")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/")


# ---------------------
# Run
# ---------------------

if __name__ == "__main__":
    with app.app_context():
        db.create_all()

        if not User.query.filter_by(username="admin").first():
            admin = User(username="admin", password="admin123")
            db.session.add(admin)
            db.session.commit()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)