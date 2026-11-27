import os
import sqlite3
from functools import wraps
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, g, abort
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "instance", "pcms.db")

ROLES = {
    "admin": "System Administrator",
    "operator": "Port / Terminal Operator",
    "container_manager": "Container Manager",
    "warehouse_manager": "Warehouse / Yard Manager",
    "staff": "Authorized Staff",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 full_name TEXT NOT NULL,
 role TEXT NOT NULL,
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vessels (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 reference TEXT UNIQUE NOT NULL,
 name TEXT NOT NULL,
 arrival_expected TEXT,
 arrival_actual TEXT,
 departure_expected TEXT,
 departure_actual TEXT,
 status TEXT NOT NULL DEFAULT 'Scheduled',
 notes TEXT
);
CREATE TABLE IF NOT EXISTS locations (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 code TEXT UNIQUE NOT NULL,
 name TEXT NOT NULL,
 location_type TEXT NOT NULL,
 capacity INTEGER NOT NULL CHECK(capacity >= 0),
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS containers (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 container_code TEXT UNIQUE NOT NULL,
 size TEXT NOT NULL,
 container_type TEXT NOT NULL,
 dimensions TEXT,
 weight REAL NOT NULL DEFAULT 0,
 category TEXT,
 vessel_id INTEGER,
 cargo_description TEXT,
 status TEXT NOT NULL DEFAULT 'Arrived',
 location_id INTEGER,
 created_at TEXT NOT NULL,
 FOREIGN KEY(vessel_id) REFERENCES vessels(id),
 FOREIGN KEY(location_id) REFERENCES locations(id)
);
CREATE TABLE IF NOT EXISTS movements (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 container_id INTEGER NOT NULL,
 old_status TEXT,
 new_status TEXT NOT NULL,
 old_location TEXT,
 new_location TEXT,
 notes TEXT,
 moved_at TEXT NOT NULL,
 moved_by TEXT NOT NULL,
 FOREIGN KEY(container_id) REFERENCES containers(id)
);
"""

def db():
    if "db" not in g:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

def close_db(_=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count == 0:
        conn.execute(
            "INSERT INTO users(username,password_hash,full_name,role,created_at) VALUES(?,?,?,?,?)",
            ("admin", generate_password_hash("admin123"), "System Administrator", "admin", datetime.now().isoformat(timespec="minutes"))
        )
    if conn.execute("SELECT COUNT(*) FROM locations").fetchone()[0] == 0:
        now = datetime.now().isoformat(timespec="minutes")
        conn.executemany(
            "INSERT INTO locations(code,name,location_type,capacity,created_at) VALUES(?,?,?,?,?)",
            [("Y-A01","North Yard A01","Yard",120,now),("Y-B02","South Yard B02","Yard",80,now),("W-01","Main Warehouse 01","Warehouse",60,now)]
        )
    if conn.execute("SELECT COUNT(*) FROM vessels").fetchone()[0] == 0:
        conn.executemany(
            "INSERT INTO vessels(reference,name,arrival_expected,status,notes) VALUES(?,?,?,?,?)",
            [("VSL-2026-001","MV Ocean Star","2026-11-25T08:00","Scheduled","Demo vessel record"),
             ("VSL-2026-002","MV Pacific Trader","2026-11-23T14:30","Docked","Demo vessel record")]
        )
    if conn.execute("SELECT COUNT(*) FROM containers").fetchone()[0] == 0:
        vessel = conn.execute("SELECT id FROM vessels ORDER BY id LIMIT 1").fetchone()["id"]
        loc = conn.execute("SELECT id FROM locations ORDER BY id LIMIT 1").fetchone()["id"]
        now = datetime.now().isoformat(timespec="minutes")
        demo = [
            ("PCMU100001","20 ft","Dry","6.06 x 2.44 x 2.59 m",8.5,"General","In Yard",loc,vessel,"General merchandise"),
            ("PCMU100002","40 ft","Refrigerated","12.19 x 2.44 x 2.59 m",12.2,"Temperature controlled","In Warehouse",None,vessel,"Fresh produce"),
            ("PCMU100003","60 ft","Open Top","18.29 x 2.44 x 2.59 m",18.0,"Oversized","Arrived",None,None,"Industrial equipment"),
        ]
        for row in demo:
            conn.execute("""INSERT INTO containers(container_code,size,container_type,dimensions,weight,category,status,location_id,vessel_id,cargo_description,created_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)""", (*row, now))
    conn.commit()
    conn.close()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def roles_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not session.get("user_id"):
                return redirect(url_for("login"))
            if session.get("role") not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated
    return decorator

def log_movement(container_id, old_status, new_status, old_location, new_location, notes=""):
    db().execute(
        """INSERT INTO movements(container_id,old_status,new_status,old_location,new_location,notes,moved_at,moved_by)
        VALUES(?,?,?,?,?,?,?,?)""",
        (container_id, old_status, new_status, old_location, new_location, notes,
         datetime.now().isoformat(timespec="minutes"), session.get("username","system"))
    )

def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ.get("PCMS_SECRET_KEY", "change-this-development-secret-key")
    app.teardown_appcontext(close_db)
    init_db()

    @app.context_processor
    def inject_globals():
        return {"roles": ROLES, "current_year": datetime.now().year}

    @app.route("/")
    def index():
        return redirect(url_for("dashboard") if session.get("user_id") else url_for("login"))

    @app.route("/login", methods=["GET","POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username","").strip()
            password = request.form.get("password","")
            user = db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if user and check_password_hash(user["password_hash"], password):
                session.clear()
                session.update(user_id=user["id"], username=user["username"], full_name=user["full_name"], role=user["role"])
                flash("Welcome back. You are signed in.", "success")
                return redirect(url_for("dashboard"))
            flash("Invalid username or password.", "error")
        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        flash("You have been signed out.", "success")
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        conn = db()
        stats = {
            "containers": conn.execute("SELECT COUNT(*) FROM containers").fetchone()[0],
            "vessels": conn.execute("SELECT COUNT(*) FROM vessels WHERE status NOT IN ('Departed')").fetchone()[0],
            "yard": conn.execute("SELECT COUNT(*) FROM containers WHERE status='In Yard'").fetchone()[0],
            "delayed": conn.execute("SELECT COUNT(*) FROM containers WHERE status='Delayed'").fetchone()[0],
        }
        total_capacity = conn.execute("SELECT COALESCE(SUM(capacity),0) FROM locations").fetchone()[0]
        occupied = conn.execute("SELECT COUNT(*) FROM containers WHERE location_id IS NOT NULL").fetchone()[0]
        stats["capacity"] = total_capacity
        stats["occupied"] = occupied
        stats["utilization"] = round((occupied / total_capacity) * 100) if total_capacity else 0
        recent = conn.execute("""SELECT c.*, l.code AS location_code, v.name AS vessel_name
            FROM containers c LEFT JOIN locations l ON c.location_id=l.id LEFT JOIN vessels v ON c.vessel_id=v.id
            ORDER BY c.id DESC LIMIT 6""").fetchall()
        vessel_status = conn.execute("SELECT status,COUNT(*) AS total FROM vessels GROUP BY status").fetchall()
        container_status = conn.execute("SELECT status,COUNT(*) AS total FROM containers GROUP BY status").fetchall()
        container_status = [dict(row) for row in container_status]
        return render_template("dashboard.html", stats=stats, recent=recent, vessel_status=vessel_status, container_status=container_status)

    @app.route("/containers", methods=["GET","POST"])
    @login_required
    def containers():
        conn = db()
        if request.method == "POST":
            if session["role"] not in ("admin","container_manager","operator"):
                abort(403)
            code = request.form.get("container_code","").strip().upper()
            if not code:
                flash("Container ID is required.", "error")
            else:
                try:
                    cur = conn.execute("""INSERT INTO containers(container_code,size,container_type,dimensions,weight,category,vessel_id,cargo_description,status,created_at)
                        VALUES(?,?,?,?,?,?,?,?,?,?)""",
                        (code,request.form.get("size"),request.form.get("container_type"),request.form.get("dimensions"),
                         float(request.form.get("weight") or 0),request.form.get("category"),
                         request.form.get("vessel_id") or None,request.form.get("cargo_description"),
                         request.form.get("status","Arrived"),datetime.now().isoformat(timespec="minutes")))
                    log_movement(cur.lastrowid, None, request.form.get("status","Arrived"), None, None, "Container registered")
                    conn.commit()
                    flash("Container registered successfully.", "success")
                    return redirect(url_for("containers"))
                except sqlite3.IntegrityError:
                    conn.rollback()
                    flash("That Container ID already exists. Every Container ID must be unique.", "error")
                except ValueError:
                    conn.rollback()
                    flash("Please enter a valid weight.", "error")
        q = request.args.get("q","").strip()
        status = request.args.get("status","")
        sql = """SELECT c.*,v.name AS vessel_name,l.code AS location_code FROM containers c
                 LEFT JOIN vessels v ON c.vessel_id=v.id LEFT JOIN locations l ON c.location_id=l.id WHERE 1=1"""
        params = []
        if q:
            sql += " AND (c.container_code LIKE ? OR c.cargo_description LIKE ? OR v.name LIKE ?)"
            params += [f"%{q}%"]*3
        if status:
            sql += " AND c.status=?"; params.append(status)
        sql += " ORDER BY c.id DESC"
        rows = conn.execute(sql, params).fetchall()
        vessels = conn.execute("SELECT id,name FROM vessels ORDER BY name").fetchall()
        locations = conn.execute("SELECT id,code,name,capacity,(SELECT COUNT(*) FROM containers c WHERE c.location_id=locations.id) AS occupied FROM locations ORDER BY code").fetchall()
        return render_template("containers.html", rows=rows, vessels=vessels, locations=locations, q=q, selected_status=status)

    @app.route("/containers/<int:cid>/update", methods=["POST"])
    @login_required
    def update_container(cid):
        if session["role"] not in ("admin","container_manager","operator","warehouse_manager"):
            abort(403)
        conn = db()
        old = conn.execute("""SELECT c.*,l.code AS location_code FROM containers c LEFT JOIN locations l ON c.location_id=l.id WHERE c.id=?""",(cid,)).fetchone()
        if not old: abort(404)
        new_status = request.form.get("status",old["status"])
        new_location = request.form.get("location_id") or None
        locrow = conn.execute("SELECT code FROM locations WHERE id=?",(new_location,)).fetchone() if new_location else None
        new_location_code = locrow["code"] if locrow else None
        if new_location:
            capacity_row = conn.execute("SELECT capacity,(SELECT COUNT(*) FROM containers WHERE location_id=?) AS occupied FROM locations WHERE id=?", (new_location,new_location)).fetchone()
            already_here = old["location_id"] == int(new_location)
            if capacity_row and not already_here and capacity_row["occupied"] >= capacity_row["capacity"]:
                flash("This storage location is at full capacity. Choose another location.", "error")
                return redirect(request.referrer or url_for("locations"))
        conn.execute("UPDATE containers SET status=?,location_id=? WHERE id=?",(new_status,new_location,cid))
        if new_status != old["status"] or new_location_code != old["location_code"]:
            log_movement(cid,old["status"],new_status,old["location_code"],new_location_code,request.form.get("notes",""))
        conn.commit()
        flash("Container status and location updated.", "success")
        return redirect(url_for("containers"))

    @app.route("/containers/<int:cid>/delete", methods=["POST"])
    @roles_required("admin")
    def delete_container(cid):
        db().execute("DELETE FROM movements WHERE container_id=?",(cid,))
        db().execute("DELETE FROM containers WHERE id=?",(cid,))
        db().commit()
        flash("Container record deleted.", "success")
        return redirect(url_for("containers"))

    @app.route("/vessels", methods=["GET","POST"])
    @login_required
    def vessels():
        conn = db()
        if request.method == "POST":
            if session["role"] not in ("admin","operator"): abort(403)
            try:
                conn.execute("""INSERT INTO vessels(reference,name,arrival_expected,arrival_actual,departure_expected,departure_actual,status,notes)
                    VALUES(?,?,?,?,?,?,?,?)""",
                    (request.form["reference"].strip().upper(),request.form["name"].strip(),request.form.get("arrival_expected"),
                     request.form.get("arrival_actual"),request.form.get("departure_expected"),request.form.get("departure_actual"),
                     request.form.get("status","Scheduled"),request.form.get("notes")))
                conn.commit()
                flash("Vessel registered successfully.", "success")
                return redirect(url_for("vessels"))
            except sqlite3.IntegrityError:
                conn.rollback(); flash("Vessel reference must be unique.", "error")
        rows = conn.execute("""SELECT v.*,COUNT(c.id) AS container_count FROM vessels v
            LEFT JOIN containers c ON c.vessel_id=v.id GROUP BY v.id ORDER BY v.id DESC""").fetchall()
        return render_template("vessels.html", rows=rows)

    @app.route("/vessels/<int:vid>/update", methods=["POST"])
    @login_required
    def update_vessel(vid):
        if session["role"] not in ("admin","operator"): abort(403)
        db().execute("UPDATE vessels SET status=?,arrival_actual=?,departure_actual=? WHERE id=?",
                     (request.form.get("status"),request.form.get("arrival_actual"),request.form.get("departure_actual"),vid))
        db().commit()
        flash("Vessel information updated.", "success")
        return redirect(url_for("vessels"))

    @app.route("/cargo", methods=["GET","POST"])
    @login_required
    def cargo():
        conn = db()
        if request.method == "POST":
            if session["role"] not in ("admin","operator","container_manager"): abort(403)
            conn.execute("UPDATE containers SET cargo_description=?,category=? WHERE id=?",
                         (request.form.get("cargo_description"),request.form.get("category"),request.form.get("container_id")))
            conn.commit()
            flash("Cargo details saved against the selected container.", "success")
            return redirect(url_for("cargo"))
        rows = conn.execute("""SELECT c.id,c.container_code,c.cargo_description,c.category,c.weight,v.name AS vessel_name
            FROM containers c LEFT JOIN vessels v ON v.id=c.vessel_id ORDER BY c.id DESC""").fetchall()
        return render_template("cargo.html", rows=rows, containers=conn.execute("SELECT id,container_code FROM containers ORDER BY container_code").fetchall())

    @app.route("/locations", methods=["GET","POST"])
    @login_required
    def locations():
        conn = db()
        if request.method == "POST":
            if session["role"] not in ("admin","warehouse_manager"): abort(403)
            try:
                conn.execute("INSERT INTO locations(code,name,location_type,capacity,created_at) VALUES(?,?,?,?,?)",
                             (request.form["code"].strip().upper(),request.form["name"].strip(),request.form["location_type"],
                              int(request.form["capacity"]),datetime.now().isoformat(timespec="minutes")))
                conn.commit()
                flash("Storage location created.", "success")
                return redirect(url_for("locations"))
            except (sqlite3.IntegrityError,ValueError):
                conn.rollback(); flash("Location code must be unique and capacity must be a whole number.", "error")
        rows = conn.execute("""SELECT l.*,COUNT(c.id) AS occupied FROM locations l
            LEFT JOIN containers c ON c.location_id=l.id GROUP BY l.id ORDER BY l.code""").fetchall()
        containers = conn.execute("SELECT c.id,c.container_code,c.status,c.location_id,l.code AS location_code FROM containers c LEFT JOIN locations l ON l.id=c.location_id ORDER BY c.container_code").fetchall()
        return render_template("locations.html", rows=rows, containers=containers)

    @app.route("/tracking")
    @login_required
    def tracking():
        q = request.args.get("q","").strip()
        rows = []
        if q:
            rows = db().execute("""SELECT c.*,l.code AS location_code,v.name AS vessel_name FROM containers c
                LEFT JOIN locations l ON l.id=c.location_id LEFT JOIN vessels v ON v.id=c.vessel_id
                WHERE c.container_code LIKE ? ORDER BY c.id DESC""",(f"%{q}%",)).fetchall()
        history = []
        if rows:
            history = db().execute("""SELECT m.*,c.container_code FROM movements m JOIN containers c ON c.id=m.container_id
                WHERE c.id=? ORDER BY m.id DESC""",(rows[0]["id"],)).fetchall()
        return render_template("tracking.html", q=q, rows=rows, history=history)

    @app.route("/reports")
    @login_required
    def reports():
        conn = db()
        by_size = conn.execute("SELECT size,COUNT(*) AS total FROM containers GROUP BY size").fetchall()
        by_status = conn.execute("SELECT status,COUNT(*) AS total FROM containers GROUP BY status").fetchall()
        by_size = [dict(row) for row in by_size]
        by_status = [dict(row) for row in by_status]
        locations = conn.execute("""SELECT l.code,l.name,l.capacity,COUNT(c.id) AS occupied FROM locations l
            LEFT JOIN containers c ON c.location_id=l.id GROUP BY l.id ORDER BY l.code""").fetchall()
        return render_template("reports.html", by_size=by_size, by_status=by_status, locations=locations)

    @app.route("/users", methods=["GET","POST"])
    @roles_required("admin")
    def users():
        conn = db()
        if request.method == "POST":
            username=request.form.get("username","").strip()
            password=request.form.get("password","")
            full_name=request.form.get("full_name","").strip()
            role=request.form.get("role","staff")
            if not username or len(password)<8 or not full_name or role not in ROLES:
                flash("Enter all details. Password must contain at least 8 characters.", "error")
            else:
                try:
                    conn.execute("INSERT INTO users(username,password_hash,full_name,role,created_at) VALUES(?,?,?,?,?)",
                                 (username,generate_password_hash(password),full_name,role,datetime.now().isoformat(timespec="minutes")))
                    conn.commit(); flash("User account created.", "success"); return redirect(url_for("users"))
                except sqlite3.IntegrityError:
                    conn.rollback(); flash("Username already exists.", "error")
        rows=conn.execute("SELECT id,username,full_name,role,created_at FROM users ORDER BY id").fetchall()
        return render_template("users.html", rows=rows)

    @app.errorhandler(403)
    def forbidden(_):
        return render_template("error.html", code=403, message="Your account does not have permission to access this action."),403
    @app.errorhandler(404)
    def not_found(_):
        return render_template("error.html", code=404, message="The requested record or page could not be found."),404

    return app
