import os
import logging
from flask import Flask, render_template, request, jsonify, session
import threading
import time
import requests
from datetime import datetime
import psycopg2
from psycopg2 import sql
from config import API_TOKEN, REGISTRATION_GROUP_ID, DATABASE_URL
import pytz
import random
import bcrypt
import binascii

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configure logging
logging.basicConfig(level=logging.INFO)

send_messages = False
restricted_groups = []
pin_first_message = False
first_message_sent_groups = {}
users = {}  # In-memory store for user data. Loaded from database at startup.
verification_codes = {}  # Store verification codes for users

# Establish database connection
conn = psycopg2.connect(DATABASE_URL)
cursor = conn.cursor()

# Create the users table if it does not exist
create_table_query = """
CREATE TABLE IF NOT EXISTS users (
    user_id VARCHAR(255) PRIMARY KEY,
    password TEXT NOT NULL,
    verified BOOLEAN NOT NULL
);
"""
cursor.execute(create_table_query)
conn.commit()

def fetch_registered_users():
    global users
    cursor.execute("SELECT user_id, password, verified FROM users")
    users = {row[0]: {'password': binascii.unhexlify(row[1][2:]), 'verified': row[2]} for row in cursor.fetchall()}
    logging.info(f"Fetched registered users: {users}")

# Fetch registered users when the bot starts
fetch_registered_users()

@app.route('/')
def index():
    if 'user' in session:
        return render_template('index.html')
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    user_id = data['userId']
    password = data['password']

    # Check if user already exists in the database
    cursor.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
    if cursor.fetchone():
        return jsonify(status="User already exists")

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    verification_code = str(random.randint(100000, 999999))
    verification_codes[user_id] = verification_code
    send_verification_code(user_id, verification_code)
    users[user_id] = {'password': hashed_password, 'verified': False}

    return jsonify(status="Verification code sent")

@app.route('/verify_code', methods=['POST'])
def verify_code():
    data = request.get_json()
    user_id = data['userId']
    code = data['code']

    if verification_codes.get(user_id) == code:
        users[user_id]['verified'] = True
        store_user_info(user_id, users[user_id]['password'])
        return jsonify(status="Registration successful")

    return jsonify(status="Invalid code")

@app.route('/login', methods=['POST'])
def login():
    # Update users from the registration group before processing the login request
    fetch_registered_users()

    data = request.get_json()
    user_id = data['userId']
    password = data['password']

    # Check if user exists in the database and is verified
    if user_id in users and bcrypt.checkpw(password.encode('utf-8'), users[user_id]['password']) and users[user_id].get('verified', False):
        session['user'] = user_id
        return jsonify(status="Login successful")

    return jsonify(status="Invalid credentials or user not verified")

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user', None)
    return jsonify(status="Logged out")

@app.route('/start_bot', methods=['POST'])
def start_bot():
    if 'user' not in session:
        return jsonify(status="Unauthorized"), 401

    global send_messages, restricted_groups, pin_first_message, first_message_sent_groups
    send_messages = True
    first_message_sent_groups = {}

    data = request.get_json()
    message = data['message']
    groups = data['groups']
    delay = int(data['delay'])
    restrict_permissions = data['restrict_permissions']
    disable_web_page_preview = data['disable_web_page_preview']
    pin_first_message = data['pin_first_message']
    time_zone = data['time_zone']
    start_time = datetime.strptime(data['start_time'], '%H:%M').time()
    end_time = datetime.strptime(data['end_time'], '%H:%M').time()

    # Convert start and end times to UTC
    tz = pytz.timezone(time_zone)
    start_time = tz.localize(datetime.combine(datetime.today(), start_time)).astimezone(pytz.utc).time()
    end_time = tz.localize(datetime.combine(datetime.today(), end_time)).astimezone(pytz.utc).time()

    restricted_groups = groups if restrict_permissions else []

    logging.info(f"Received start_bot request: message={message}, groups={groups}, delay={delay}, restrict_permissions={restrict_permissions}, disable_web_page_preview={disable_web_page_preview}, pin_first_message={pin_first_message}, start_time={start_time}, end_time={end_time}, time_zone={time_zone}")

    threading.Thread(target=message_scheduler, args=(message, groups, delay, restrict_permissions, disable_web_page_preview, start_time, end_time)).start()

    return jsonify(status="Bot started")

@app.route('/stop_bot', methods=['POST'])
def stop_bot():
    if 'user' not in session:
        return jsonify(status="Unauthorized"), 401

    global send_messages
    send_messages = False
    for group in restricted_groups:
        restore_user_permissions(group)
    return jsonify(status="Bot stopped")

@app.route('/restore_permissions', methods=['POST'])
def restore_permissions():
    if 'user' not in session:
        return jsonify(status="Unauthorized"), 401

    global restricted_groups
    for group in restricted_groups:
        restore_user_permissions(group)
    return jsonify(status="Permissions restored")

def send_message(chat_id, text, disable_web_page_preview=False, pin_message=False):
    url = f'https://api.telegram.org/bot{API_TOKEN}/sendMessage'
    payload = {
        'chat_id': chat_id,
        'text': text,
        'disable_web_page_preview': disable_web_page_preview
    }
    logging.info(f"Sending message to {chat_id}: {text}")
    try:
        response = requests.post(url, data=payload)
        response_data = response.json()
        logging.info(f"Response: {response_data}")
        if not response.ok:
            logging.error(f"Error sending message: {response_data}")

        if pin_message:
            message_id = response_data.get('result', {}).get('message_id')
            if (message_id):
                pin_message_to_chat(chat_id, message_id)
    except Exception as e:
        logging.error(f"Exception during send_message: {e}", exc_info=True)

def pin_message_to_chat(chat_id, message_id):
    url = f'https://api.telegram.org/bot{API_TOKEN}/pinChatMessage'
    payload = {
        'chat_id': chat_id,
        'message_id': message_id
    }
    logging.info(f"Pinning message {message_id} to chat {chat_id}")
    try:
        response = requests.post(url, data=payload)
        response_data = response.json()
        logging.info(f"Response: {response_data}")
        if not response.ok:
            logging.error(f"Error pinning message: {response_data}")
    except Exception as e:
        logging.error(f"Exception during pin_message_to_chat: {e}", exc_info=True)

def restrict_user_permissions(chat_id):
    url = f'https://api.telegram.org/bot{API_TOKEN}/setChatPermissions'
    payload = {
        'chat_id': chat_id,
        'permissions': {
            'can_send_messages': False,
            'can_send_media_messages': False,
            'can_send_polls': False,
            'can_send_other_messages': False,
            'can_add_web_page_previews': False,
            'can_change_info': False,
            'can_invite_users': False,
            'can_pin_messages': False
        }
    }
    logging.info(f"Restricting permissions for {chat_id}")
    try:
        response = requests.post(url, json=payload)
        response_data = response.json()
        logging.info(f"Response: {response_data}")
        if not response.ok:
            logging.error(f"Error restricting permissions: {response_data}")
    except Exception as e:
        logging.error(f"Exception during restrict_user_permissions: {e}", exc_info=True)

def restore_user_permissions(chat_id):
    url = f'https://api.telegram.org/bot{API_TOKEN}/setChatPermissions'
    payload = {
        'chat_id': chat_id,
        'permissions': {
            'can_send_messages': True,
            'can_send_media_messages': True,
            'can_send_polls': True,
            'can_send_other_messages': True,
            'can_add_web_page_previews': True,
            'can_change_info': True,
            'can_invite_users': True,
            'can_pin_messages': True
        }
    }
    logging.info(f"Restoring permissions for {chat_id}")
    try:
        response = requests.post(url, json=payload)
        response_data = response.json()
        logging.info(f"Response: {response_data}")
        if not response.ok:
            logging.error(f"Error restoring permissions: {response_data}")
    except Exception as e:
        logging.error(f"Exception during restore_user_permissions: {e}", exc_info=True)

def send_verification_code(chat_id, code):
    text = f"Your verification code is: {code}"
    send_message(chat_id, text)

def message_scheduler(message, groups, delay, restrict_permissions, disable_web_page_preview, start_time, end_time):
    while send_messages:
        current_time = datetime.utcnow().time()
        if start_time <= current_time <= end_time:
            for group in groups:
                if restrict_permissions:
                    restrict_user_permissions(group)
                if pin_first_message and group not in first_message_sent_groups:
                    send_message(group, message, disable_web_page_preview, pin_message=True)
                    first_message_sent_groups[group] = True
                else:
                    send_message(group, message, disable_web_page_preview, pin_message=False)
            time.sleep(delay)
        else:
            logging.info(f"Current time {current_time} is outside the scheduled time window {start_time} - {end_time}.")
            time.sleep(60)  # Check again in one minute

def store_user_info(user_id, hashed_password):
    cursor.execute(
        """
        INSERT INTO users (user_id, password, verified)
        VALUES (%s, %s, %s)
        ON CONFLICT (user_id) 
        DO UPDATE SET password = EXCLUDED.password, verified = EXCLUDED.verified
        """,
        (user_id, binascii.hexlify(hashed_password).decode(), True)
    )
    conn.commit()
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
