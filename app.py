import hashlib
import os
import secrets
import socket
from datetime import datetime, timedelta

import psycopg2
from flask import (Flask, abort, jsonify, redirect, render_template, request,
                   send_from_directory, session, url_for)
from psycopg2.extras import RealDictCursor

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FILES_DIR = os.path.join(BASE_DIR, "files")
LOGS_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOGS_DIR, exist_ok=True)

HEARTBEAT_LOG_FILE = os.path.join(LOGS_DIR, "heartbeats.log")

ALLOWED = {
    "windows": "agent_api.exe",
    "ubuntu": "ubuntu_agent.sh",
    "mac": "mac_agent.pkg"
}

USER_CREDENTIALS = {
    "admin": "password123"
}

TOKENS = {}

# PostgreSQL connection config
import psycopg2

DB_CONFIG = {
    "dbname": "cve_advisories",
    "user": "postgres",
    "password": "root",
    "host": "localhost",
    "port": 5432
}

try:
    conn = psycopg2.connect(**DB_CONFIG)
    print("✅ Connected to PostgreSQL server!")
    conn.close()
except Exception as e:
    print("❌ Connection failed:", e)


def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)

def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def log_download(os_name, ip):
    """Store or update download log in PostgreSQL, keeping only one entry per IP."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        hostname = "Unknown"



    conn = get_db_connection()
    cur = conn.cursor()

    # Insert new record or update if IP already exists
    cur.execute("""
        INSERT INTO downloads (download_time, ip_address, hostname, os_name)
        VALUES (NOW(), %s, %s, %s)
        ON CONFLICT (ip_address)
        DO UPDATE SET
            download_time = EXCLUDED.download_time,
            hostname = EXCLUDED.hostname,
            os_name = EXCLUDED.os_name
    """, (ip, hostname, os_name))

    conn.commit()
    cur.close()
    conn.close()


@app.route("/")
def home():
    if "user" in session:
        return redirect("/dashboard")
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    if USER_CREDENTIALS.get(username) == password:
        session["user"] = username
        return redirect("/dashboard")
    return render_template("login.html", error="Invalid credentials")

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    return render_template("dashboard.html")

@app.route("/get_link/<os_name>")
def get_link(os_name):
    if "user" not in session:
        abort(403)
    if os_name not in ALLOWED:
        abort(404)

    filename = ALLOWED[os_name]
    path = os.path.join(FILES_DIR, filename)
    if not os.path.exists(path):
        abort(404)

    token = secrets.token_hex(8)
    TOKENS[token] = filename

    download_url = url_for("download_file", filename=filename, token=token, _external=True)
    checksum = sha256_of_file(path)
    return jsonify({"url": download_url, "sha256": checksum})

@app.route("/downloads/<path:filename>")
def download_file(filename):
    token = request.args.get("token")
    if not token or TOKENS.get(token) != filename:
        abort(403, "Invalid or missing token")

    os_name = next((os for os, file in ALLOWED.items() if file == filename), "unknown")
    ip_address = request.remote_addr
    log_download(os_name, ip_address)

    TOKENS.pop(token, None)
    return send_from_directory(FILES_DIR, filename, as_attachment=True)

@app.route("/agent_heartbeat", methods=["POST"])
def agent_heartbeat():
    ip_address = request.remote_addr
    data = request.get_json() or {}
    hostname = data.get("hostname", "Unknown")

    now = datetime.now().isoformat()
    with open(HEARTBEAT_LOG_FILE, "a") as f:
        f.write(f"{now} | {ip_address} | {hostname}\n")

    return jsonify({"status": "heartbeat received"})


@app.route("/server_dashboard")
def server_dashboard():
    if "user" not in session:
        return redirect("/")

    # Fetch downloads from PostgreSQL
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT download_time AS datetime,
               ip_address AS ip,
               hostname,
               os_name
        FROM downloads
        ORDER BY download_time DESC
    """)
    logs = cur.fetchall()
    conn.close()

    unique_ips = {log["ip"] for log in logs}
    latest_download_time = logs[0]["datetime"] if logs else None

    # Read heartbeats from file (time, IP, hostname)
    heartbeats = {}
    if os.path.exists(HEARTBEAT_LOG_FILE):
        with open(HEARTBEAT_LOG_FILE, "r") as f:
            for line in f:
                parts = line.strip().split(" | ")
                if len(parts) == 3:
                    hb_time_str, ip, hostname = parts
                    try:
                        hb_time = datetime.fromisoformat(hb_time_str)
                        if ip not in heartbeats or hb_time > heartbeats[ip]["time"]:
                            heartbeats[ip] = {"time": hb_time, "hostname": hostname}
                    except ValueError:
                        continue

    # Determine active/inactive
    now = datetime.now()
    ACTIVE_THRESHOLD = timedelta(seconds=10)

    for log in logs:
        last_hb = heartbeats.get(log["ip"])
        if last_hb:
            # Override DB hostname with the latest from heartbeat
            log["hostname"] = last_hb["hostname"]

            diff = (now - last_hb["time"]).total_seconds()
        #     if diff <= ACTIVE_THRESHOLD.total_seconds():
        #         log["status"] = f"Active (last seen {int(diff)}s ago)"
        #     else:
        #         log["status"] = f"Inactive (last seen {int(diff)}s ago)"
        # else:
        #     log["status"] = "No heartbeat received"

            diff = (now - last_hb["time"]).total_seconds()
            if diff <= ACTIVE_THRESHOLD.total_seconds():
                log["status"] = "Active"
            else:
                log["status"] = "Inactive"
        else:
            log["status"] = "Agent never started"


    return render_template(
        "server_dashboard.html",
        logs=logs,
        unique_ips=len(unique_ips),
        latest_download_time=latest_download_time.strftime('%Y-%m-%d %H:%M:%S') if latest_download_time else "N/A"
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
