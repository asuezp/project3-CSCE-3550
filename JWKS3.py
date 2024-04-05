import os
import sqlite3
import secrets
import time
from functools import wraps
from flask import Flask, request, jsonify
from argon2 import PasswordHasher
from cryptography.fernet import Fernet

app = Flask(__name__)

# Set up SQLite database
conn = sqlite3.connect('jwks_server.db')
c = conn.cursor()

# Create tables
c.execute('''CREATE TABLE IF NOT EXISTS jwks
             (id INTEGER PRIMARY KEY AUTOINCREMENT, 
              key_id TEXT, 
              public_key TEXT, 
              private_key BLOB)''')

c.execute('''CREATE TABLE IF NOT EXISTS users
             (id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT NOT NULL UNIQUE,
              password_hash TEXT NOT NULL,
              email TEXT UNIQUE,
              date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
              last_login TIMESTAMP)''')

c.execute('''CREATE TABLE IF NOT EXISTS auth_logs
             (id INTEGER PRIMARY KEY AUTOINCREMENT,
              request_ip TEXT NOT NULL,
              request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
              user_id INTEGER,
              FOREIGN KEY(user_id) REFERENCES users(id))''')

conn.commit()

# Set up Argon2 password hasher
ph = PasswordHasher()

# AES encryption
key = os.environ.get('NOT_MY_KEY').encode()
fernet = Fernet(key)

# Rate limiter
request_times = {}
rate_limit = 10  # 10 requests per second

def rate_limit_decorator(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        ip = request.remote_addr
        now = time.time()
        if ip in request_times:
            if now - request_times[ip] < 1:
                request_count = request_times[ip]
                if request_count >= rate_limit:
                    return {'error': 'Too many requests'}, 429
                request_times[ip] += 1
            else:
                request_times[ip] = 1
        else:
            request_times[ip] = 1
        result = func(*args, **kwargs)
        return result
    return wrapper

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    email = data['email']

    # Generate a random password
    password = secrets.token_hex(16)

    # Hash the password using Argon2
    password_hash = ph.hash(password)

    # Store the user details in the database
    c.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", (username, password_hash, email))
    conn.commit()

    return jsonify({'password': password}), 201

@app.route('/auth', methods=['POST'])
@rate_limit_decorator
def authenticate():
    data = request.get_json()
    username = data['username']
    password = data['password']

    # Fetch the user details from the database
    c.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    if user:
        user_id, stored_hash = user
        try:
            # Verify the password using Argon2
            ph.verify(stored_hash, password)
            # Update the last_login timestamp
            c.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user_id,))
            conn.commit()
            return {'user_id': user_id}, 200
        except:
            pass
    return {'error': 'Invalid username or password'}, 401

@app.route('/jwks', methods=['GET'])
def get_jwks():
    c.execute("SELECT key_id, public_key, private_key FROM jwks")
    jwks = []
    for key_id, public_key, private_key in c.fetchall():
        # Decrypt the private key using AES
        decrypted_private_key = fernet.decrypt(private_key).decode()
        jwks.append({
            'kty': 'RSA',
            'kid': key_id,
            'n': public_key,
            'd': decrypted_private_key
        })
    return jsonify({'keys': jwks})

if __name__ == '__main__':
    app.run(debug=True)