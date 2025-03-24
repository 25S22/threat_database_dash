from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import pandas as pd
import json
import os

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Change this in production!

# JSON files for storing devices and permissions
JSON_FILE = "devices.json"
PERMISSIONS_FILE = "permissions.json"

# Temporary in-memory storage
users = {
    "admin": {"password": "admin123", "role": "admin"},
    "alice": {"password": "alice123", "role": "user"},
    "bob": {"password": "bob123", "role": "user"}
}
devices_db = []
permissions = {user: "full" for user in users if users[user]['role'] == "user"}  # Default full access

# ---------------- FUNCTION: SAVE AND LOAD JSON ---------------- #
def load_devices():
    """Load devices from JSON file on server startup."""
    global devices_db
    if os.path.exists(JSON_FILE):
        with open(JSON_FILE, "r") as file:
            try:
                devices_db = json.load(file)
                print(f"Loaded {len(devices_db)} devices from JSON.")
            except json.JSONDecodeError:
                print("Error decoding JSON. Resetting devices.")
                devices_db = []


def save_devices():
    """Save devices to JSON file."""
    with open(JSON_FILE, "w") as file:
        json.dump(devices_db, file, indent=4)
        print(f"Saved {len(devices_db)} devices to JSON.")


def load_permissions():
    """Load permissions from JSON file on startup."""
    global permissions
    if os.path.exists(PERMISSIONS_FILE):
        with open(PERMISSIONS_FILE, "r") as file:
            try:
                permissions = json.load(file)
                print("Loaded permissions from JSON.")
            except json.JSONDecodeError:
                print("Error decoding permissions JSON.")
                permissions = {user: "full" for user in users if users[user]['role'] == "user"}


def save_permissions():
    """Save permissions to JSON file."""
    with open(PERMISSIONS_FILE, "w") as file:
        json.dump(permissions, file, indent=4)
        print("Saved permissions to JSON.")


# ---------------- LOAD DEVICES AND PERMISSIONS ON STARTUP ---------------- #
load_devices()
load_permissions()


# ---------------- HOME PAGE ---------------- #
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/privacy')
def privacy():
    return render_template('privacy.html')


# ---------------- ADMIN LOGIN ---------------- #
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username in users and users[username]['role'] == 'admin' and users[username]['password'] == password:
            session['username'] = username
            session['role'] = 'admin'
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template('admin-login.html', error="Invalid admin credentials!")

    return render_template('admin-login.html')


# ---------------- USER LOGIN ---------------- #
@app.route('/user-login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username in users and users[username]['role'] == 'user' and users[username]['password'] == password:
            session['username'] = username
            session['role'] = 'user'
            session['access_level'] = permissions.get(username, "full")
            return redirect(url_for('user_dashboard'))
        else:
            return render_template('user-login.html', error="Invalid user credentials!")

    return render_template('user-login.html')


# ---------------- USER REGISTRATION ---------------- #
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            return "Username and password required!", 400
        if username in users:
            return "User already exists!", 400

        users[username] = {"password": password, "role": "user"}
        permissions[username] = "full"
        save_permissions()
        return redirect(url_for('user_login'))

    return render_template('register.html')


# ---------------- ADMIN DASHBOARD ---------------- #
@app.route('/admin-dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    """
    Handles Admin Dashboard with file upload, displays devices, and manages permissions.
    """
    if session.get('role') != 'admin':
        return redirect(url_for('admin_login'))

    global devices_db

    if request.method == 'POST':
        if 'fileUpload' in request.files:
            file = request.files['fileUpload']
            if file.filename == '':
                return "No file selected", 400

            try:
                file.seek(0)
                if file.filename.endswith('.csv'):
                    df = pd.read_csv(file)
                elif file.filename.endswith('.txt'):
                    df = pd.read_csv(file, sep=None, engine='python')
                else:
                    return "Unsupported file format. Please upload CSV or TXT.", 400
            except Exception as e:
                return f"Error reading file: {e}", 400

            if "IP Address" not in df.columns:
                return redirect(url_for('admin_dashboard'))

            # Remove duplicates
            df = df.drop_duplicates(subset=["IP Address"], keep='first')

            # Prepare new devices with Date/Time instead of Company
            new_devices = []
            for _, row in df.iterrows():
                ip_val = row.get('IP Address', '')
                if pd.isnull(ip_val) or not str(ip_val).strip():
                    continue
                device_info = {
                    'ip': str(ip_val).strip(),
                    'date_time': str(row.get('Date/Time', '')).strip(),  # Changed to Date/Time
                    'location': str(row.get('Country', '')).strip(),
                    'isp': str(row.get('ISP', '')).strip(),
                    'os': str(row.get('Operating System', '')).strip()
                }
                new_devices.append(device_info)

            # Filter out duplicates
            existing_ips = {d['ip'] for d in devices_db}
            unique_new_devices = [d for d in new_devices if d['ip'] not in existing_ips]

            devices_db.extend(unique_new_devices)
            save_devices()

        # Update permissions
        for user in users:
            if users[user]["role"] == "user":
                permissions[user] = request.form.get(user, "full")
        save_permissions()

    return render_template('admin_dashboard.html', devices=devices_db, users=users, permissions=permissions)


# ---------------- DELETE ALL DEVICES ---------------- #
@app.route('/admin/delete_all', methods=['POST'])
def delete_all():
    """
    Deletes all devices in the admin dashboard and clears the JSON file.
    """
    if session.get('role') != 'admin':
        return redirect(url_for('admin_login'))

    global devices_db
    devices_db = []
    save_devices()  # Clear JSON file
    print("All device entries deleted.")
    return redirect(url_for('admin_dashboard'))


# ---------------- USER DASHBOARD ---------------- #
@app.route('/user-dashboard')
def user_dashboard():
    if session.get('role') != 'user':
        return redirect(url_for('user_login'))

    access_level = session.get('access_level', 'full')
    return render_template('user_dashboard.html', devices=devices_db, access_level=access_level)


# ---------------- API ENDPOINTS ---------------- #
@app.route('/api/statistics')
def api_statistics():
    total_devices = len(devices_db)
    unique_isps = len({d['isp'] for d in devices_db if d.get('isp')})
    unique_locations = len({d['location'] for d in devices_db if d.get('location')})

    stats = {
        "totalDevices": total_devices,
        "uniqueIsps": unique_isps,
        "uniqueLocations": unique_locations
    }
    return jsonify(stats)


@app.route('/api/devices')
def api_devices():
    return jsonify(devices_db)


# ---------------- LOGOUT ---------------- #
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


# ---------------- FLASK MAIN ---------------- #
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))  # Render uses PORT 10000
    app.run(host="0.0.0.0", port=port, debug=True)
