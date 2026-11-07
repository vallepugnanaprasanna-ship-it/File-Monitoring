from flask import (
    Flask, render_template, jsonify, request,
    redirect, url_for, flash, session, send_file
)
from pathlib import Path
from dotenv import load_dotenv
from werkzeug.security import check_password_hash
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)
from reportlab.lib.styles import getSampleStyleSheet
from io import BytesIO
from functools import wraps
import os

from database import (
    create_table,
    create_admin_table,
    get_all_files,
    get_all_events,
    get_statistics,
    register_file,
    update_hash,
    add_event,
    connect_db
)

from hash_generator import generate_hash
from file_monitor import start_monitoring


# ==================================
# 1. LOAD ENVIRONMENT VARIABLES
# ==================================

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

if not app.secret_key:
    raise ValueError("SECRET_KEY missing in .env file")

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


# ==================================
# 2. PROJECT CONFIGURATION
# ==================================

MONITOR_FOLDER = Path("monitorerd_files").resolve()
MONITOR_FOLDER.mkdir(parents=True, exist_ok=True)

create_table()
create_admin_table()


# ==================================
# 3. LOGIN REQUIRED
# ==================================

def login_required(function):

    @wraps(function)
    def decorated_function(*args, **kwargs):

        if "admin" not in session:
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return decorated_function


# ==================================
# 4. ADMIN LOGIN
# ==================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    conn = connect_db()

    try:
        admin = conn.execute(
            "SELECT * FROM admins WHERE username = ?",
            (username,)
        ).fetchone()

    finally:
        conn.close()

    if admin and check_password_hash(
        admin["password_hash"], password
    ):

        session.clear()
        session["admin"] = admin["username"]

        flash("Login successful!", "success")

        return redirect(url_for("dashboard"))

    flash("Invalid username or password.", "error")

    return render_template("login.html")


# ==================================
# 5. ADMIN LOGOUT
# ==================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# ==================================
# 6. MAIN DASHBOARD PAGE
# ==================================

@app.route("/")
@login_required
def dashboard():

    return render_template(
        "dashboard.html",
        stats=get_statistics(),
        files=get_all_files(),
        events=get_all_events(50),
        admin=session["admin"]
    )


# ==================================
# 7. MONITORED FILES PAGE
# ==================================

@app.route("/files")
@login_required
def monitored_files():

    return render_template(
        "files.html",
        files=get_all_files(),
        admin=session["admin"]
    )


# ==================================
# 8. SECURITY ALERTS PAGE
# ==================================

@app.route("/alerts")
@login_required
def security_alerts():

    return render_template(
        "alerts.html",
        events=get_all_events(100),
        admin=session["admin"]
    )


# ==================================
# 9. DASHBOARD LIVE API
# ==================================

@app.route("/api/dashboard")
@login_required
def dashboard_api():

    return jsonify({
        "stats": get_statistics(),
        "files": [
            dict(row) for row in get_all_files()
        ],
        "events": [
            dict(row) for row in get_all_events(50)
        ]
    })


# ==================================
# 10. REGISTER NEW FILE
# ==================================

@app.route("/register", methods=["POST"])
@login_required
def register():

    filename = request.form.get("filename", "").strip()

    if not filename:
        flash("Enter a filename.", "error")
        return redirect(url_for("monitored_files"))

    candidate = (MONITOR_FOLDER / filename).resolve()

    try:
        candidate.relative_to(MONITOR_FOLDER)

    except ValueError:
        flash("Invalid file path.", "error")
        return redirect(url_for("monitored_files"))

    if not candidate.is_file():
        flash("File does not exist.", "error")
        return redirect(url_for("monitored_files"))

    relative_path = os.path.relpath(
        candidate,
        Path.cwd()
    )

    file_hash = generate_hash(str(candidate))

    if file_hash:

        register_file(relative_path, file_hash)

        add_event(relative_path, "REGISTERED")

        flash("File registered successfully!", "success")

    else:
        flash("Unable to read file.", "error")

    return redirect(url_for("monitored_files"))


# ==================================
# 11. RE-BASELINE FILE
# ==================================

@app.route("/rebaseline/<int:file_id>", methods=["POST"])
@login_required
def rebaseline(file_id):

    records = get_all_files()

    record = next(
        (row for row in records if row["id"] == file_id),
        None
    )

    if record is None:
        flash("File record not found.", "error")
        return redirect(url_for("monitored_files"))

    candidate = (
        Path.cwd() / record["file_path"]
    ).resolve()

    try:
        candidate.relative_to(MONITOR_FOLDER)

    except ValueError:
        flash("Invalid file location.", "error")
        return redirect(url_for("monitored_files"))

    if not candidate.is_file():
        flash("File is unavailable.", "error")
        return redirect(url_for("monitored_files"))

    new_hash = generate_hash(str(candidate))

    if new_hash:

        update_hash(
            record["file_path"],
            new_hash
        )

        add_event(
            record["file_path"],
            "RE-BASELINED"
        )

        flash(
            "New baseline saved successfully.",
            "success"
        )

    else:
        flash("Unable to read file.", "error")

    return redirect(url_for("monitored_files"))


# ==================================
# 12. DOWNLOAD PDF SECURITY REPORT
# ==================================

@app.route("/download-report")
@login_required
def download_report():

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=35,
        leftMargin=35,
        topMargin=35,
        bottomMargin=35
    )

    styles = getSampleStyleSheet()

    elements = []

    elements.append(
        Paragraph(
            "FileGuard Security Report",
            styles["Title"]
        )
    )

    elements.append(Spacer(1, 15))

    # Security Summary

    stats = get_statistics()

    summary_data = [
        ["Metric", "Count"],
        ["Total Files", str(stats["total"])],
        ["Safe Files", str(stats["safe"])],
        ["Modified Files", str(stats["modified"])],
        ["Deleted Files", str(stats["deleted"])]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[250, 150]
    )

    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0),
         colors.HexColor("#2563eb")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("PADDING", (0, 0), (-1, -1), 8)
    ]))

    elements.append(
        Paragraph("Security Summary", styles["Heading2"])
    )

    elements.append(summary_table)
    elements.append(Spacer(1, 20))

    # Monitored Files

    elements.append(
        Paragraph("Monitored Files", styles["Heading2"])
    )

    file_data = [["File", "Status", "SHA-256"]]

    for file_record in get_all_files():

        file_data.append([
            str(file_record["file_path"]),
            str(file_record["status"]),
            str(file_record["file_hash"])
        ])

    file_table = Table(
        file_data,
        colWidths=[145, 75, 230],
        repeatRows=1
    )

    file_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0),
         colors.HexColor("#2563eb")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5)
    ]))

    elements.append(file_table)
    elements.append(Spacer(1, 20))

    # Recent Security Events

    elements.append(
        Paragraph(
            "Recent Security Events",
            styles["Heading2"]
        )
    )

    event_data = [["File", "Event", "Date and Time"]]

    for event in get_all_events(100):

        event_data.append([
            str(event["file_path"]),
            str(event["event_type"]),
            str(event["event_time"])
        ])

    event_table = Table(
        event_data,
        colWidths=[170, 90, 190],
        repeatRows=1
    )

    event_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0),
         colors.HexColor("#2563eb")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE")
    ]))

    elements.append(event_table)

    document.build(elements)

    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="FileGuard_Security_Report.pdf",
        mimetype="application/pdf"
    )


# ==================================
# 13. RUN APPLICATION
# ==================================

if __name__ == "__main__":

    observer = start_monitoring()

    try:
        app.run(
            host="127.0.0.1",
            port=5000,
            debug=False,
            use_reloader=False
        )

    finally:
        observer.stop()
        observer.join()