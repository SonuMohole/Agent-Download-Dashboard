import hashlib
import os
import secrets
from flask import Flask, abort, jsonify, request, send_from_directory, url_for, render_template, redirect, session

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Secret for sessions

BASE_DIR = os.path.dirname(__file__)
FILES_DIR = os.path.join(BASE_DIR, "files")

ALLOWED = {
    "windows": "agent_api.zip",
    "ubuntu":  "ubuntu_agent.sh",
    "mac":     "mac_agent.pkg"
}

# Simple user credentials (replace with DB later)
USER_CREDENTIALS = {
    "admin": "password123"
}

# Token storage
TOKENS = {}

def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

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

    # Generate one-time token
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
    TOKENS.pop(token, None)  # One-time token
    return send_from_directory(FILES_DIR, filename, as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
