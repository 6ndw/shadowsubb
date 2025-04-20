# app.py
from flask import Flask, render_template, request, jsonify, redirect, url_for
import sqlite3
from datetime import datetime, timedelta
import secrets
import hashlib

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Database initialization
def init_db():
    conn = sqlite3.connect('license.db')
    c = conn.cursor()
    
    # API keys table
    c.execute('''CREATE TABLE IF NOT EXISTS api_keys
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 key TEXT UNIQUE NOT NULL,
                 is_active INTEGER DEFAULT 1,
                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Serial numbers table
    c.execute('''CREATE TABLE IF NOT EXISTS serial_numbers
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 serial TEXT UNIQUE NOT NULL,
                 email TEXT,
                 user_name TEXT,
                 is_used INTEGER DEFAULT 0,
                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                 expiry_date TIMESTAMP,
                 license_type TEXT)''')
    
    # Activations table
    c.execute('''CREATE TABLE IF NOT EXISTS activations
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 serial_id INTEGER,
                 device_id TEXT,
                 activation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                 last_check TIMESTAMP,
                 FOREIGN KEY(serial_id) REFERENCES serial_numbers(id))''')
    
    conn.commit()
    conn.close()

# Helper functions
def generate_serial():
    return secrets.token_hex(8).upper()

def hash_device_id(device_id):
    return hashlib.sha256(device_id.encode()).hexdigest()

# API Endpoints
@app.route('/check_key', methods=['POST'])
def check_key():
    data = request.json
    if not data or 'key' not in data:
        return jsonify({'status': 'error', 'message': 'Invalid request'}), 400
    
    conn = sqlite3.connect('license.db')
    c = conn.cursor()
    c.execute("SELECT is_active FROM api_keys WHERE key = ?", (data['key'],))
    result = c.fetchone()
    conn.close()
    
    if result and result[0] == 1:
        return jsonify({'status': 'valid'})
    else:
        return jsonify({'status': 'invalid'}), 403

@app.route('/verify_serial', methods=['POST'])
def verify_serial():
    data = request.json
    if not data or 'serial' not in data or 'device_id' not in data:
        return jsonify({'status': 'error', 'message': 'Invalid request'}), 400
    
    hashed_device_id = hash_device_id(data['device_id'])
    
    conn = sqlite3.connect('license.db')
    c = conn.cursor()
    
    # Check if serial exists and is valid
    c.execute('''SELECT id, expiry_date, is_used FROM serial_numbers 
                 WHERE serial = ?''', (data['serial'],))
    serial_data = c.fetchone()
    
    if not serial_data:
        conn.close()
        return jsonify({'status': 'invalid', 'message': 'Invalid serial number'}), 403
    
    serial_id, expiry_date, is_used = serial_data
    
    # Check if license has expired
    if expiry_date and datetime.strptime(expiry_date, '%Y-%m-%d %H:%M:%S') < datetime.now():
        conn.close()
        return jsonify({'status': 'expired', 'message': 'License has expired'}), 403
    
    # Check if this device is already activated
    c.execute('''SELECT 1 FROM activations 
                 WHERE serial_id = ? AND device_id = ?''', 
                 (serial_id, hashed_device_id))
    already_activated = c.fetchone()
    
    if already_activated:
        # Update last check time
        c.execute('''UPDATE activations SET last_check = CURRENT_TIMESTAMP
                     WHERE serial_id = ? AND device_id = ?''',
                     (serial_id, hashed_device_id))
        conn.commit()
        conn.close()
        
        # Get user info
        conn = sqlite3.connect('license.db')
        c = conn.cursor()
        c.execute('''SELECT user_name, email, expiry_date FROM serial_numbers
                     WHERE id = ?''', (serial_id,))
        user_info = c.fetchone()
        conn.close()
        
        return jsonify({
            'status': 'valid',
            'user_name': user_info[0],
            'email': user_info[1],
            'expiry_date': user_info[2]
        })
    
    # If serial is unused, activate it
    if not is_used:
        c.execute('''UPDATE serial_numbers SET is_used = 1
                     WHERE id = ?''', (serial_id,))
        c.execute('''INSERT INTO activations 
                     (serial_id, device_id, last_check)
                     VALUES (?, ?, CURRENT_TIMESTAMP)''',
                     (serial_id, hashed_device_id))
        conn.commit()
        
        # Get user info
        c.execute('''SELECT user_name, email, expiry_date FROM serial_numbers
                     WHERE id = ?''', (serial_id,))
        user_info = c.fetchone()
        conn.close()
        
        return jsonify({
            'status': 'valid',
            'user_name': user_info[0],
            'email': user_info[1],
            'expiry_date': user_info[2]
        })
    
    conn.close()
    return jsonify({'status': 'used', 'message': 'Serial number already used'}), 403

# Admin Interface
@app.route('/admin')
def admin_dashboard():
    return render_template('admin.html')

@app.route('/admin/keys')
def manage_keys():
    conn = sqlite3.connect('license.db')
    c = conn.cursor()
    c.execute("SELECT id, key, is_active, created_at FROM api_keys")
    keys = c.fetchall()
    conn.close()
    return render_template('add_key.html', keys=keys)

@app.route('/admin/add_key', methods=['POST'])
def add_key():
    key = request.form.get('key')
    if not key:
        return redirect(url_for('manage_keys'))
    
    conn = sqlite3.connect('license.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO api_keys (key) VALUES (?)", (key,))
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # Key already exists
    finally:
        conn.close()
    
    return redirect(url_for('manage_keys'))

@app.route('/admin/toggle_key/<int:key_id>')
def toggle_key(key_id):
    conn = sqlite3.connect('license.db')
    c = conn.cursor()
    c.execute("UPDATE api_keys SET is_active = NOT is_active WHERE id = ?", (key_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('manage_keys'))

@app.route('/admin/serials')
def manage_serials():
    conn = sqlite3.connect('license.db')
    c = conn.cursor()
    c.execute('''SELECT id, serial, user_name, email, is_used, 
                 expiry_date, license_type FROM serial_numbers''')
    serials = c.fetchall()
    conn.close()
    return render_template('add_serial.html', serials=serials)

@app.route('/admin/add_serial', methods=['POST'])
def add_serial():
    user_name = request.form.get('user_name')
    email = request.form.get('email')
    license_type = request.form.get('license_type')
    custom_serial = request.form.get('serial')
    
    # Generate serial if not provided
    serial = custom_serial if custom_serial else generate_serial()
    
    # Calculate expiry date based on license type
    expiry_date = None
    if license_type == 'day':
        expiry_date = datetime.now() + timedelta(days=1)
    elif license_type == 'month':
        expiry_date = datetime.now() + timedelta(days=30)
    elif license_type == 'year':
        expiry_date = datetime.now() + timedelta(days=365)
    elif license_type == 'custom':
        days = int(request.form.get('custom_days', 0))
        if days > 0:
            expiry_date = datetime.now() + timedelta(days=days)
    
    conn = sqlite3.connect('license.db')
    c = conn.cursor()
    try:
        c.execute('''INSERT INTO serial_numbers 
                     (serial, user_name, email, expiry_date, license_type)
                     VALUES (?, ?, ?, ?, ?)''',
                     (serial, user_name, email, expiry_date, license_type))
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # Serial already exists
    finally:
        conn.close()
    
    return redirect(url_for('manage_serials'))

@app.route('/admin/activations')
def view_activations():
    conn = sqlite3.connect('license.db')
    c = conn.cursor()
    c.execute('''SELECT a.id, s.serial, s.user_name, s.email, 
                 a.activation_date, a.last_check, s.expiry_date
                 FROM activations a
                 JOIN serial_numbers s ON a.serial_id = s.id''')
    activations = c.fetchall()
    conn.close()
    return render_template('view_activations.html', activations=activations)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)