from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import sqlite3
import re
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime

app = Flask(__name__)
app.secret_key = "supersecretkey"
SECRET_KEY = "jwtsecret"

DATABASE = "database.db"

# ---------------- DATABASE ---------------- #
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()

    conn.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )
    ''')

    conn.execute('''
    CREATE TABLE IF NOT EXISTS contacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        phone TEXT UNIQUE,
        email TEXT UNIQUE
    )
    ''')

    # default admin user
    conn.execute(
        "INSERT OR IGNORE INTO users (id, username, password) VALUES (1, ?, ?)",
        ("admin", generate_password_hash("admin"))
    )

    conn.commit()
    conn.close()

# ---------------- AUTH ---------------- #
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return wrapper

# ---------------- VALIDATION ---------------- #
def valid_email(e):
    return re.match(r"[^@]+@[^@]+\.[^@]+", e)

def valid_phone(p):
    return p.isdigit() and len(p) == 10

# ---------------- LOGIN (WEB) ---------------- #
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user'] = username
            flash("Login successful", "success")
            return redirect(url_for('index'))   # ✅ FIXED

        flash("Invalid credentials", "danger")

    return render_template("login.html")

# ---------------- LOGIN (API JWT) ---------------- #
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json

    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username=?",
        (data['username'],)
    ).fetchone()
    conn.close()

    if user and check_password_hash(user['password'], data['password']):
        token = jwt.encode({
            'user': user['username'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, SECRET_KEY, algorithm="HS256")

        return jsonify({"token": token})

    return jsonify({"error": "Invalid credentials"}), 401

# ---------------- LOGOUT ---------------- #
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# ---------------- HOME ---------------- #
@app.route('/')
@login_required
def index():
    search = request.args.get('search')
    conn = get_db()

    if search:
        contacts = conn.execute("""
            SELECT * FROM contacts
            WHERE name LIKE ? OR phone LIKE ? OR email LIKE ?
        """, ('%'+search+'%', '%'+search+'%', '%'+search+'%')).fetchall()
    else:
        contacts = conn.execute("SELECT * FROM contacts").fetchall()

    conn.close()
    return render_template("index.html", contacts=contacts)

# ---------------- ADD ---------------- #
@app.route('/add', methods=['GET','POST'])
@login_required
def add():
    if request.method == 'POST':
        name = request.form['name']
        phone = request.form['phone']
        email = request.form['email']

        if not valid_phone(phone):
            flash("Phone must be 10 digits", "danger")

        elif not valid_email(email):
            flash("Invalid email format", "danger")

        else:
            try:
                conn = get_db()
                conn.execute(
                    "INSERT INTO contacts (name, phone, email) VALUES (?, ?, ?)",
                    (name, phone, email)
                )
                conn.commit()
                conn.close()

                flash("Contact added", "success")
                return redirect('/')

            except sqlite3.IntegrityError:
                flash("Phone or Email already exists", "danger")

    return render_template("add.html")

# ---------------- EDIT ---------------- #
@app.route('/edit/<int:id>', methods=['GET','POST'])
@login_required
def edit(id):
    conn = get_db()
    contact = conn.execute(
        "SELECT * FROM contacts WHERE id=?",
        (id,)
    ).fetchone()

    if request.method == 'POST':
        conn.execute(
            "UPDATE contacts SET name=?, phone=?, email=? WHERE id=?",
            (request.form['name'], request.form['phone'], request.form['email'], id)
        )
        conn.commit()
        conn.close()

        flash("Updated successfully", "success")
        return redirect('/')

    conn.close()
    return render_template("edit.html", contact=contact)

# ---------------- DELETE ---------------- #
@app.route('/delete/<int:id>')
@login_required
def delete(id):
    conn = get_db()
    conn.execute("DELETE FROM contacts WHERE id=?", (id,))
    conn.commit()
    conn.close()

    flash("Deleted successfully", "success")
    return redirect('/')

# ---------------- API CONTACTS ---------------- #
def token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({"error": "Token missing"}), 403

        try:
            jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except:
            return jsonify({"error": "Invalid token"}), 403

        return f(*args, **kwargs)
    return wrapper

@app.route('/api/contacts')
@token_required
def api_contacts():
    conn = get_db()
    data = conn.execute("SELECT * FROM contacts").fetchall()
    conn.close()

    return jsonify([dict(x) for x in data])

# ---------------- MAIN ---------------- #
if __name__ == '__main__':
    init_db()
    app.run(debug=True)