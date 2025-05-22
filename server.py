import os import uuid import json import datetime import logging import base64 import time import threading from flask import Flask, request, jsonify, send_from_directory from flask_socketio import SocketIO, emit

─── Logging Configuration ─────────────────────────────────────────────

logging.basicConfig( level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s', datefmt='%H:%M:%S' )

─── App and SocketIO Initialization ─────────────────────────────────────

app = Flask(name) app.config['SECRET_KEY'] = 'secret!' socketio = SocketIO(app, async_mode='threading', cors_allowed_origins=lambda origin: True)

─── Dynamic CORS Reflection ─────────────────────────────────────────────

@app.after_request def add_cors_headers(response): origin = request.headers.get("Origin") if origin: response.headers["Access-Control-Allow-Origin"] = origin response.headers["Vary"] = "Origin" response.headers["Access-Control-Allow-Credentials"] = "true" response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS" response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization" return response

─── Folders Setup ─────────────────────────────────────────────────────────

USER_DATA_DIR = "user_data" if not os.path.exists(USER_DATA_DIR): os.makedirs(USER_DATA_DIR)

CHAT_HISTORY_DIR = "chat_history" if not os.path.exists(CHAT_HISTORY_DIR): os.makedirs(CHAT_HISTORY_DIR)

MEDIA_DIR = "media" if not os.path.exists(MEDIA_DIR): os.makedirs(MEDIA_DIR)

BACKGROUND_DIR = "backgrounds" if not os.path.exists(BACKGROUND_DIR): os.makedirs(BACKGROUND_DIR)

PROFILE_PICS_DIR = "profile_pictures" if not os.path.exists(PROFILE_PICS_DIR): os.makedirs(PROFILE_PICS_DIR)

GROUPS_DIR = "groups" if not os.path.exists(GROUPS_DIR): os.makedirs(GROUPS_DIR)

─── Utility Functions ─────────────────────────────────────────────────────

def save_user_data(user_data): user_file = os.path.join(USER_DATA_DIR, f"user_{user_data['user_id']}.json") with open(user_file, "w", encoding="utf-8") as f: json.dump(user_data, f)

def get_chat_filename(user1, user2): sorted_ids = sorted([user1, user2]) return os.path.join(CHAT_HISTORY_DIR, f"chat_{sorted_ids[0]}_{sorted_ids[1]}.jsonl")

def generate_message_id(timestamp): return str(timestamp) + base64.b64encode(os.urandom(4)).decode('utf-8').replace('=', '').replace('/', '')

def log_chat_message(sender, recipient, message, reply=None, read=False, sender_username=None, message_id=None, timestamp=None): if sender_username is None: sender_username = sender if not timestamp: timestamp = int(time.time() * 1000) if not message_id: message_id = generate_message_id(timestamp) entry = { "message_id": message_id, "timestamp": timestamp, "sender": sender, "sender_username": sender_username, "recipient": recipient, "message": message, "read": read } if reply: entry["reply"] = reply filename = get_chat_filename(sender, recipient) with open(filename, "a", encoding="utf-8") as f: f.write(json.dumps(entry) + "\n")

def get_media_filename(user1, user2): sorted_ids = sorted([user1, user2]) return os.path.join(MEDIA_DIR, f"media_{sorted_ids[0]}_{sorted_ids[1]}.jsonl")

def log_media_message(sender, recipient, file_path, original_filename, file_size, is_voice=False): entry = { "timestamp": datetime.datetime.utcnow().isoformat(), "sender": sender, "recipient": recipient, "file_path": file_path, "original_filename": original_filename, "file_size": file_size, "is_voice": is_voice } filename = get_media_filename(sender, recipient) with open(filename, "a", encoding="utf-8") as f: f.write(json.dumps(entry) + "\n")

def get_group_chat_filename(group_id): return os.path.join(GROUPS_DIR, f"group_{group_id}_chat.jsonl")

def log_group_message(group_id, sender, message, sender_username, reply=None): entry = { "timestamp": datetime.datetime.utcnow().isoformat(), "sender": sender, "sender_username": sender_username, "message": message } if reply: entry["reply"] = reply filename = get_group_chat_filename(group_id) with open(filename, "a", encoding="utf-8") as f: f.write(json.dumps(entry) + "\n")

def log_group_media_message(group_id, sender, file_path, original_filename, file_size, is_voice=False): sender_username = "Anonymous" if sender in connected_users: sender_username = connected_users[sender].get("username", "Anonymous") entry = { "timestamp": datetime.datetime.utcnow().isoformat(), "sender": sender, "sender_username": sender_username, "media": file_path, "original_filename": original_filename, "file_size": file_size, "is_voice": is_voice } filename = get_group_chat_filename(group_id) with open(filename, "a", encoding="utf-8") as f: f.write(json.dumps(entry) + "\n")

def get_client_ip(): forwarded = request.headers.getlist("X-Forwarded-For") if forwarded: return forwarded[0].split(",")[0].strip() return request.remote_addr

─── In‑Memory Storage for Connected Users ──────────────────────────────────

connected_users = {}

─── Socket.IO Handlers ─────────────────────────────────────────────────────

@socketio.on("connect") def handle_connect(): ip = get_client_ip() provided_user_id = request.args.get("user_id") if provided_user_id: user_file = os.path.join(USER_DATA_DIR, f"user_{provided_user_id}.json") if os.path.exists(user_file): with open(user_file, "r", encoding="utf-8") as f: user_data = json.load(f) user_data["sid"] = request.sid user_data["ip"] = ip user_data.setdefault("background_image", "") connected_users[provided_user_id] = user_data emit("registration", user_data) return user_id = str(uuid.uuid4()) user_data = { "user_id": user_id, "username": "Anonymous", "email": "", "password": "", "profile_picture": "", "ip": ip, "sid": request.sid, "friends": [] } connected_users[user_id] = user_data save_user_data(user_data) emit("registration", user_data) logging.info("User connected: %s", user_data)

... other handlers ...

─── Endpoints for Chat History ─────────────────────────────────────────────

@app.route("/mark_read", methods=["POST"]) def mark_read(): data = request.get_json() user_id = data.get("user_id") partner_id = data.get("partner_id")

if not user_id or not partner_id:
    return jsonify({"error": "user_id and partner_id required"}), 400

filename = get_chat_filename(user_id, partner_id)

if not os.path.exists(filename):
    return jsonify({"message": "No history"}), 200

messages = []
with open(filename, "r", encoding="utf-8") as f:
    for line in f:
        try:
            msg = json.loads(line)
            if msg.get("recipient") == user_id and not msg.get("read", False):
                msg["read"] = True
            messages.append(msg)
        except:
            continue

with open(filename, "w", encoding="utf-8") as f:
    for msg in messages:
        f.write(json.dumps(msg) + "\n")

logging.info("Marked as read: Conversation %s & %s", user_id, partner_id)
return jsonify({"message": "Marked as read"})

─── Run Server ─────────────────────────────────────────────────────────────

if name == 'main': socketio.run( app, host="0.0.0.0", port=int(os.environ.get('PORT', 5001)), debug=True, use_reloader=False, allow_unsafe_werkzeug=True )

