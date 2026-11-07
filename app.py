
import os
import sqlite3
import uuid
import secrets
from io import BytesIO
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_file
)

from werkzeug.security import (
    generate_password_hash, check_password_hash
)
from werkzeug.utils import secure_filename

from cryptography.fernet import Fernet

# -----------------------------
# APPLICATION CONFIGURATION
# -----------------------------

app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024

os.makedirs("uploads", exist_ok=True)

# Generate Flask secret key
if not os.path.exists("secret.key"):
    with open("secret.key", "wb") as f:
        f.write(secrets.token_bytes(32))

with open("secret.key", "rb") as f:
    app.secret_key = f.read()

# Generate encryption key
if not os.path.exists("vault.key"):
    with open("vault.key", "wb") as f:
        f.write(Fernet.generate_key())

with open("vault.key", "rb") as f:
    cipher = Fernet(f.read())


# -----------------------------
# DATABASE CONNECTION
# -----------------------------

def get_db():
    db = sqlite3.connect("vault.db")
    db.row_factory = sqlite3.Row
    return db


# -----------------------------
# CREATE DATABASE TABLES
# -----------------------------

def init_db():
    db = get_db()

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS folders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            UNIQUE(user_id, name)
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            folder_id INTEGER,
            filename TEXT NOT NULL,
            stored_name TEXT NOT NULL
        )
    """)

    db.commit()
    db.close()


init_db()


# -----------------------------
# LOGIN REQUIRED DECORATOR
# -----------------------------

def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return function(*args, **kwargs)
    return wrapper


# -----------------------------
# HOME PAGE
# -----------------------------

@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# -----------------------------
# USER REGISTRATION
# -----------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"].strip()
        password = request.form["password"]

        if not username or len(password) < 8:
            flash("Username required. Password must be at least 8 characters.")
            return redirect(url_for("register"))

        db = get_db()

        try:
            db.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, generate_password_hash(password))
            )

            db.commit()

            flash("Registration successful! Please login.")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("Username already exists.")

        finally:
            db.close()

    return render_template("register.html")


# -----------------------------
# USER LOGIN
# -----------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"].strip()
        password = request.form["password"]

        db = get_db()

        user = db.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        db.close()

        if user and check_password_hash(user["password"], password):

            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]

            return redirect(url_for("dashboard"))

        flash("Invalid username or password.")

    return render_template("login.html")


# -----------------------------
# DASHBOARD
# -----------------------------

@app.route("/dashboard")
@login_required
def dashboard():

    db = get_db()
    uid = session["user_id"]

    keyword = request.args.get("q", "").strip()

    files = db.execute("""
        SELECT files.*, folders.name AS folder_name
        FROM files
        LEFT JOIN folders ON files.folder_id = folders.id
        WHERE files.user_id = ?
        AND files.filename LIKE ?
        ORDER BY files.id DESC
    """, (uid, "%" + keyword + "%")).fetchall()

    folders = db.execute(
        "SELECT * FROM folders WHERE user_id = ?",
        (uid,)
    ).fetchall()

    db.close()

    return render_template(
        "dashboard.html",
        files=files,
        folders=folders,
        username=session["username"],
        keyword=keyword
    )


# -----------------------------
# CREATE FOLDER
# -----------------------------

@app.route("/create_folder", methods=["POST"])
@login_required
def create_folder():

    name = request.form["folder_name"].strip()

    if not name or len(name) > 50:
        flash("Enter a valid folder name.")
        return redirect(url_for("dashboard"))

    db = get_db()

    try:
        db.execute(
            "INSERT INTO folders (user_id, name) VALUES (?, ?)",
            (session["user_id"], name)
        )

        db.commit()
        flash("Folder created successfully.")

    except sqlite3.IntegrityError:
        flash("Folder already exists.")

    finally:
        db.close()

    return redirect(url_for("dashboard"))


# -----------------------------
# UPLOAD FILE
# -----------------------------

@app.route("/upload", methods=["POST"])
@login_required
def upload():

    file = request.files.get("file")

    if not file or not file.filename:
        flash("Please select a file.")
        return redirect(url_for("dashboard"))

    filename = secure_filename(file.filename)

    if not filename:
        flash("Invalid filename.")
        return redirect(url_for("dashboard"))

    folder_id = request.form.get("folder_id") or None
    uid = session["user_id"]

    db = get_db()

    if folder_id:
        folder = db.execute(
            "SELECT id FROM folders WHERE id = ? AND user_id = ?",
            (folder_id, uid)
        ).fetchone()

        if not folder:
            db.close()
            flash("Invalid folder.")
            return redirect(url_for("dashboard"))

    stored_name = str(uuid.uuid4()) + ".enc"
    path = os.path.join("uploads", stored_name)

    try:
        data = file.read()
        encrypted_data = cipher.encrypt(data)

        with open(path, "wb") as f:
            f.write(encrypted_data)

        db.execute("""
            INSERT INTO files
            (user_id, folder_id, filename, stored_name)
            VALUES (?, ?, ?, ?)
        """, (uid, folder_id, filename, stored_name))

        db.commit()

        flash("File uploaded and encrypted successfully.")

    except Exception:
        if os.path.exists(path):
            os.remove(path)

        flash("File upload failed.")

    finally:
        db.close()

    return redirect(url_for("dashboard"))


# -----------------------------
# DOWNLOAD FILE
# -----------------------------

@app.route("/download/<int:file_id>")
@login_required
def download(file_id):

    db = get_db()

    record = db.execute(
        "SELECT * FROM files WHERE id = ? AND user_id = ?",
        (file_id, session["user_id"])
    ).fetchone()

    db.close()

    if not record:
        flash("File not found.")
        return redirect(url_for("dashboard"))

    path = os.path.join("uploads", record["stored_name"])

    try:
        with open(path, "rb") as f:
            encrypted_data = f.read()

        original_data = cipher.decrypt(encrypted_data)

        return send_file(
            BytesIO(original_data),
            as_attachment=True,
            download_name=record["filename"]
        )

    except Exception:
        flash("File could not be decrypted or downloaded.")
        return redirect(url_for("dashboard"))


# -----------------------------
# DELETE FILE
# -----------------------------

@app.route("/delete/<int:file_id>", methods=["POST"])
@login_required
def delete(file_id):

    db = get_db()

    record = db.execute(
        "SELECT * FROM files WHERE id = ? AND user_id = ?",
        (file_id, session["user_id"])
    ).fetchone()

    if record:

        path = os.path.join("uploads", record["stored_name"])

        if os.path.exists(path):
            os.remove(path)

        db.execute(
            "DELETE FROM files WHERE id = ? AND user_id = ?",
            (file_id, session["user_id"])
        )

        db.commit()
        flash("File deleted successfully.")

    else:
        flash("File not found.")

    db.close()

    return redirect(url_for("dashboard"))


# -----------------------------
# LOGOUT
# -----------------------------

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# -----------------------------
# RUN APPLICATION
# -----------------------------

if __name__ == "__main__":
    app.run(debug=True)
