"""
VulnerableBank - A deliberately insecure Python Flask application
For security audit demonstration purposes ONLY.
"""

import os
import sqlite3
import hashlib
import pickle
import subprocess
import yaml
import jwt
import logging
from flask import Flask, request, jsonify, session, render_template_string
from functools import wraps
import xml.etree.ElementTree as ET

app = Flask(__name__)

# VULN-01: Hardcoded secret key
app.secret_key = "supersecret123"
JWT_SECRET = "jwt_secret_do_not_share"

# VULN-02: Debug mode enabled in production
app.config['DEBUG'] = True

# VULN-03: Logging sensitive data
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

DB_PATH = "bank.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT,
        email TEXT,
        balance REAL,
        role TEXT DEFAULT 'user',
        ssn TEXT,
        credit_card TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY,
        from_user TEXT,
        to_user TEXT,
        amount REAL,
        note TEXT
    )''')
    # VULN-04: Weak MD5 password hashing
    c.execute("INSERT OR IGNORE INTO users VALUES (1,'admin',?,'admin@bank.com',999999,'admin','123-45-6789','4111111111111111')",
              (hashlib.md5(b"admin123").hexdigest(),))
    c.execute("INSERT OR IGNORE INTO users VALUES (2,'alice',?,'alice@bank.com',5000,'user','987-65-4321','5500005555555559')",
              (hashlib.md5(b"password").hexdigest(),))
    conn.commit()
    conn.close()

# VULN-05: Broken authentication - JWT not verified properly
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Token missing'}), 401
        try:
            # VULN-05a: Algorithm confusion - accepts 'none' algorithm
            data = jwt.decode(token, JWT_SECRET, algorithms=["HS256", "none"])
            request.user = data
        except Exception as e:
            logger.debug(f"JWT error: {e} | token={token}")  # VULN-03 continued
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated

# VULN-06: SQL Injection
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')

    logger.info(f"Login attempt - user: {username}, password: {password}")  # Logs credentials

    # VULN-04 continued: MD5 hash for password comparison
    hashed = hashlib.md5(password.encode()).hexdigest()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # VULN-06: Direct string interpolation = SQL injection
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{hashed}'"
    c.execute(query)
    user = c.fetchone()
    conn.close()

    if user:
        token = jwt.encode({'id': user[0], 'username': user[1], 'role': user[5]},
                           JWT_SECRET, algorithm='HS256')
        return jsonify({'token': token, 'message': 'Login successful'})
    return jsonify({'error': 'Invalid credentials'}), 401

# VULN-07: XSS via Server-Side Template Injection (SSTI)
@app.route('/profile')
@token_required
def profile():
    username = request.user.get('username', '')
    # VULN-07: Unsanitized input passed directly to render_template_string
    template = f"""
    <html><body>
    <h1>Welcome, {username}!</h1>
    <p>Your account is active.</p>
    </body></html>
    """
    return render_template_string(template)

# VULN-08: Insecure Deserialization
@app.route('/restore_session', methods=['POST'])
def restore_session():
    session_data = request.data
    # VULN-08: Deserializing untrusted user input
    try:
        user_session = pickle.loads(session_data)
        return jsonify({'status': 'Session restored', 'data': str(user_session)})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# VULN-09: Command Injection
@app.route('/ping', methods=['GET'])
@token_required
def ping():
    host = request.args.get('host', 'localhost')
    # VULN-09: Shell=True + unvalidated input = command injection
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return jsonify({'output': result.stdout + result.stderr})

# VULN-10: Path Traversal
@app.route('/download', methods=['GET'])
@token_required
def download_file():
    filename = request.args.get('file', '')
    # VULN-10: No path sanitization
    base_path = "/var/app/reports/"
    full_path = base_path + filename
    try:
        with open(full_path, 'r') as f:
            return jsonify({'content': f.read()})
    except FileNotFoundError:
        return jsonify({'error': 'File not found'}), 404

# VULN-11: XXE (XML External Entity)
@app.route('/import_transactions', methods=['POST'])
@token_required
def import_transactions():
    xml_data = request.data
    # VULN-11: Parsing XML without disabling external entities
    try:
        root = ET.fromstring(xml_data)
        transactions = []
        for tx in root.findall('transaction'):
            transactions.append({
                'from': tx.find('from').text,
                'to': tx.find('to').text,
                'amount': tx.find('amount').text
            })
        return jsonify({'imported': transactions})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# VULN-12: Insecure Direct Object Reference (IDOR)
@app.route('/account/<int:user_id>', methods=['GET'])
@token_required
def get_account(user_id):
    # VULN-12: No authorization check - any authenticated user can view any account
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, username, email, balance, ssn, credit_card FROM users WHERE id=?", (user_id,))
    user = c.fetchone()
    conn.close()
    if user:
        # VULN-12b: Returns sensitive data like SSN and credit card
        return jsonify({
            'id': user[0], 'username': user[1],
            'email': user[2], 'balance': user[3],
            'ssn': user[4], 'credit_card': user[5]
        })
    return jsonify({'error': 'User not found'}), 404

# VULN-13: Mass Assignment / Unvalidated Input
@app.route('/update_profile', methods=['POST'])
@token_required
def update_profile():
    data = request.get_json()
    user_id = request.user['id']
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # VULN-13: Attacker can set 'role' to 'admin' or update 'balance'
    for key, value in data.items():
        c.execute(f"UPDATE users SET {key}=? WHERE id=?", (value, user_id))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Profile updated'})

# VULN-14: YAML deserialization (unsafe load)
@app.route('/load_config', methods=['POST'])
@token_required
def load_config():
    config_data = request.data.decode()
    # VULN-14: yaml.load without Loader is dangerous
    config = yaml.load(config_data)
    return jsonify({'config': str(config)})

# VULN-15: Rate limiting absent + sensitive data exposure
@app.route('/transfer', methods=['POST'])
@token_required
def transfer():
    data = request.get_json()
    to_user = data.get('to_user')
    amount = float(data.get('amount', 0))
    note = data.get('note', '')

    user_id = request.user['id']
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # VULN-15a: No rate limiting on financial transactions
    # VULN-15b: No amount validation (negative amounts = steal money)
    c.execute("SELECT balance FROM users WHERE id=?", (user_id,))
    sender = c.fetchone()

    # VULN-06 again: SQL injection in to_user lookup
    c.execute(f"SELECT id FROM users WHERE username='{to_user}'")
    receiver = c.fetchone()

    if not receiver:
        conn.close()
        return jsonify({'error': 'Recipient not found'}), 404

    new_sender_balance = sender[0] - amount
    c.execute("UPDATE users SET balance=? WHERE id=?", (new_sender_balance, user_id))
    c.execute("UPDATE users SET balance = balance + ? WHERE username=?", (amount, to_user))
    # VULN-15c: Transaction note stored without sanitization (stored XSS)
    c.execute("INSERT INTO transactions VALUES (NULL,?,?,?,?)",
              (request.user['username'], to_user, amount, note))
    conn.commit()
    conn.close()
    return jsonify({'message': f'Transferred {amount} to {to_user}', 'new_balance': new_sender_balance})

# VULN-16: Information Disclosure via verbose errors
@app.errorhandler(Exception)
def handle_exception(e):
    import traceback
    # VULN-16: Exposes full stack trace to the client
    return jsonify({'error': str(e), 'traceback': traceback.format_exc()}), 500

# VULN-17: CORS misconfiguration
@app.after_request
def after_request(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = '*'
    response.headers['Access-Control-Allow-Headers'] = '*'
    # VULN-18: Missing security headers
    # Missing: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, HSTS
    return response

if __name__ == '__main__':
    init_db()
    # VULN-19: Running on 0.0.0.0 with debug=True
    app.run(host='0.0.0.0', port=5000, debug=True)
