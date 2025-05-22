import os
import uuid
import json
import datetime
import logging

import base64
import time
import threading

from flask import Flask, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit

# ─── Logging Configuration ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%H:%M:%S'
)

# ─── App and SocketIO Initialization ─────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins=lambda origin: True)

# ─── Dynamic CORS Reflection ─────────────────────────────────────────────
@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin")
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response

# ─── Folders Setup ─────────────────────────────────────────────────────────
USER_DATA_DIR = "user_data"
if not os.path.exists(USER_DATA_DIR):
    os.makedirs(USER_DATA_DIR)

CHAT_HISTORY_DIR = "chat_history"
if not os.path.exists(CHAT_HISTORY_DIR):
    os.makedirs(CHAT_HISTORY_DIR)

MEDIA_DIR = "media"
if not os.path.exists(MEDIA_DIR):
    os.makedirs(MEDIA_DIR)
    
BACKGROUND_DIR = "backgrounds"
if not os.path.exists(BACKGROUND_DIR):
    os.makedirs(BACKGROUND_DIR)

PROFILE_PICS_DIR = "profile_pictures"
if not os.path.exists(PROFILE_PICS_DIR):
    os.makedirs(PROFILE_PICS_DIR)

GROUPS_DIR = "groups"
if not os.path.exists(GROUPS_DIR):
    os.makedirs(GROUPS_DIR)

# ─── Utility Functions ─────────────────────────────────────────────────────
def save_user_data(user_data):
    user_file = os.path.join(USER_DATA_DIR, f"user_{user_data['user_id']}.json")
    with open(user_file, "w", encoding="utf-8") as f:
        json.dump(user_data, f)

def get_chat_filename(user1, user2):
    sorted_ids = sorted([user1, user2])
    return os.path.join(CHAT_HISTORY_DIR, f"chat_{sorted_ids[0]}_{sorted_ids[1]}.jsonl")

def generate_message_id(timestamp):
    return str(timestamp) + base64.b64encode(os.urandom(4)).decode('utf-8').replace('=', '').replace('/', '')

def log_chat_message(sender, recipient, message, reply=None, read=False, sender_username=None, message_id=None, timestamp=None):
    if sender_username is None:
        sender_username = sender

    if not timestamp:
        timestamp = int(time.time() * 1000)  # Match frontend timestamp format

    if not message_id:
        message_id = generate_message_id(timestamp)  # Ensure backend uses the same format

    entry = {
        "message_id": message_id,
        "timestamp": timestamp,  # Ensure timestamp is in milliseconds
        "sender": sender,
        "sender_username": sender_username,
        "recipient": recipient,
        "message": message,
        "read": read
    }

    if reply:
        entry["reply"] = reply

    filename = get_chat_filename(sender, recipient)
    with open(filename, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

def get_media_filename(user1, user2):
    sorted_ids = sorted([user1, user2])
    return os.path.join(MEDIA_DIR, f"media_{sorted_ids[0]}_{sorted_ids[1]}.jsonl")

def log_media_message(sender, recipient, file_path, original_filename, file_size, is_voice=False):
    entry = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "sender": sender,
        "recipient": recipient,
        "file_path": file_path,
        "original_filename": original_filename,
        "file_size": file_size,
        "is_voice": is_voice
    }
    filename = get_media_filename(sender, recipient)
    with open(filename, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

def get_group_chat_filename(group_id):
    return os.path.join(GROUPS_DIR, f"group_{group_id}_chat.jsonl")

def log_group_message(group_id, sender, message, sender_username, reply=None):
    entry = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "sender": sender,
        "sender_username": sender_username,
        "message": message
    }
    if reply:
        entry["reply"] = reply
    filename = get_group_chat_filename(group_id)
    with open(filename, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

def log_group_media_message(group_id, sender, file_path, original_filename, file_size, is_voice=False):
    sender_username = "Anonymous"
    if sender in connected_users:
        sender_username = connected_users[sender].get("username", "Anonymous")
    entry = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "sender": sender,
        "sender_username": sender_username,
        "media": file_path,
        "original_filename": original_filename,
        "file_size": file_size,
        "is_voice": is_voice
    }
    filename = get_group_chat_filename(group_id)
    with open(filename, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

def get_client_ip():
    forwarded = request.headers.getlist("X-Forwarded-For")
    if forwarded:
        return forwarded[0].split(",")[0].strip()
    return request.remote_addr

# ─── In‑Memory Storage for Connected Users ──────────────────────────────────
connected_users = {}

# ─── Socket.IO Handlers ─────────────────────────────────────────────────────
@socketio.on("connect")
@socketio.on("connect")
def handle_connect():
    ip = get_client_ip()
    provided_user_id = request.args.get("user_id")

    if provided_user_id:
        user_file = os.path.join(USER_DATA_DIR, f"user_{provided_user_id}.json")
        if os.path.exists(user_file):
            with open(user_file, "r", encoding="utf-8") as f:
                user_data = json.load(f)

            user_data["sid"] = request.sid
            user_data["ip"] = ip

            # Ensure background_image is included
            user_data.setdefault("background_image", "")

            connected_users[provided_user_id] = user_data
            emit("registration", user_data)
            return

    user_id = str(uuid.uuid4())
    user_data = {
        "user_id": user_id,
        "username": "Anonymous",
        "email": "",
        "password": "",
        "profile_picture": "",
        "ip": ip,
        "sid": request.sid,
        "friends": []
    }
    connected_users[user_id] = user_data
    save_user_data(user_data)
    emit("registration", user_data)
    logging.info("User connected: %s", user_data)

@socketio.on("update_username")
def handle_update_username(data):
    new_username = data.get("username", "").strip()
    if not new_username:
        emit("error", {"message": "Username cannot be empty."})
        logging.error("Error: Username cannot be empty.")
        return
    sender = None
    for user in connected_users.values():
        if user.get("sid") == request.sid:
            sender = user
            break
    if not sender:
        emit("error", {"message": "User not found."})
        logging.error("Error: User not found.")
        return
    sender["username"] = new_username
    save_user_data(sender)
    emit("username_updated", {"username": new_username})
    logging.info("Username updated for %s: %s", sender["user_id"], new_username)

@socketio.on("private_message")
def handle_private_message(data):
    sender = None
    for user in connected_users.values():
        if user.get("sid") == request.sid:
            sender = user
            break
    if not sender:
        emit("error", {"message": "Sender not registered."})
        logging.error("Error: Sender not registered.")
        return
        
      
    target_user_id = data.get("to")
    message_text = data.get("message")
    recipient = data.get("to")
    message = data.get("message")
    reply = data.get("reply")
    user_id = data.get("user_id")
    message_id = data.get("message_id")
    
    if not target_user_id or not message:
        emit("error", {"message": "Target user and message are required."})
        logging.error("Error: Target user and message are required.")
        return
    payload = {
        "from": sender["user_id"],
        "username": sender["username"],
        "message": message,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "profile_picture": sender.get("profile_picture", "")
    }
    if reply:
        payload["reply"] = reply
    target = connected_users.get(target_user_id)
    if target:
        socketio.emit("private_message", payload, room=target["sid"])
    log_chat_message(sender["user_id"], target_user_id, message_text, reply=reply, read=False, sender_username=sender["username"], message_id=data.get("message_id"))    
    emit("private_message_sent", {"recipient": recipient, "message": message, "user_id": user_id, "message_id": message_id})
    logging.info("Message sent from %s to %s", sender["user_id"], target_user_id)

@socketio.on("group_message")
def handle_group_message(data):
    group_id = data.get("group_id")
    message = data.get("message")
    reply = data.get("reply")
    sender = None
    for user in connected_users.values():
        if user.get("sid") == request.sid:
            sender = user
            break
    if not sender:
        emit("error", {"message": "Sender not registered."})
        logging.error("Error: Sender not registered.")
        return
    group = load_group(group_id)
    if not group:
        emit("error", {"message": "Group not found."})
        logging.error("Error: Group not found.")
        return
    payload = {
        "group_id": group_id,
        "from": sender["user_id"],
        "username": sender["username"],
        "message": message,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "profile_picture": sender.get("profile_picture", "")
    }
    if reply:
        payload["reply"] = reply
    for member_id in group.get("members", []):
        if member_id in connected_users:
            member = connected_users[member_id]
            socketio.emit("group_message", payload, room=member["sid"])
    log_group_message(group_id, sender["user_id"], message, sender["username"], reply=reply)
    logging.info("Group message sent in group %s by %s", group_id, sender["user_id"])

@socketio.on("disconnect")
def handle_disconnect():
    sid = request.sid
    for uid, user in list(connected_users.items()):
        if user.get("sid") == sid:
            logging.info("User disconnected: %s", user)
            del connected_users[uid]
            break


@socketio.on("delete_message")
def handle_delete_message(data):
    message_id = data.get("message_id")

    if not message_id:
        emit("error", {"message": "message_id required"})
        return

    # Broadcast delete event to all clients
    socketio.emit("message_deleted", {"message_id": message_id})
    
   
@socketio.on("accept_group_invite")
def handle_accept_group_invite(data):
    group_id = data.get("group_id")
    user_id = data.get("user_id")

    if not group_id or not user_id:
        emit("error", {"message": "Group ID and User ID required."})
        return

    group_file = os.path.join(GROUPS_DIR, f"group_{group_id}.json")
    
    if not os.path.exists(group_file):
        emit("error", {"message": "Group not found."})
        return

    with open(group_file, "r+", encoding="utf-8") as f:
        group_data = json.load(f)
        
        # Check if user is already in the group
        if user_id not in group_data.get("members", []):
            group_data["members"].append(user_id)  # Add user to the group
            
            # Save the updated group data
            f.seek(0)
            json.dump(group_data, f)
            f.truncate()
    
    emit("group_updated", group_data, room=group_id)
    logging.info(f"User {user_id} joined group {group_id}")
 
@app.route("/delete_message", methods=["POST"])
@app.route("/delete_message", methods=["POST"])
def delete_message():
    data = request.get_json()
    message_id = data.get("message_id")
    user_id = data.get("user_id")
    recipient_id = data.get("recipient")

    if not message_id or not user_id or not recipient_id:
        return jsonify({"success": False, "error": "Message ID, User ID, and Recipient ID required"}), 400

    # 🚀 **Immediately broadcast delete event** to both users
    if user_id in connected_users:
        socketio.emit("message_deleted", {"message_id": message_id}, room=connected_users[user_id]["sid"])
    if recipient_id in connected_users:
        socketio.emit("message_deleted", {"message_id": message_id}, room=connected_users[recipient_id]["sid"])

    # ⏳ **Wait 5 seconds before deleting from history**
    def delayed_delete():
        time.sleep(3)
        chat_history_dir = "chat_history"
        file_names = [f"chat_{user_id}_{recipient_id}.jsonl", f"chat_{recipient_id}_{user_id}.jsonl"]
        message_found = False

        for chat_file in file_names:
            file_path = os.path.join(chat_history_dir, chat_file)
            if not os.path.exists(file_path):
                continue

            updated_messages = []
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    message = json.loads(line)
                    if message.get("message_id") == message_id and message.get("sender") == user_id:
                        message_found = True
                        continue  # Skip adding this message back (delete it)
                    updated_messages.append(message)

            if message_found:
                with open(file_path, "w", encoding="utf-8") as f:
                    for msg in updated_messages:
                        f.write(json.dumps(msg) + "\n")
                break

    threading.Thread(target=delayed_delete).start()  # Run deletion in background

    return jsonify({"success": True})

@app.route("/upload_background", methods=["POST"])
def upload_background():
    user_id = request.form.get("user_id")
    if not user_id:
        return jsonify({"success": False, "error": "User ID required"}), 400

    if "background" not in request.files:
        return jsonify({"success": False, "error": "No file uploaded"}), 400

    file = request.files["background"]
    if file.filename == "":
        return jsonify({"success": False, "error": "Empty filename"}), 400

    # Use the user_id to generate a filename
    ext = os.path.splitext(file.filename)[1]
    filename = f"{user_id}_background{ext}"
    file_path = os.path.join(BACKGROUND_DIR, filename)
    file.save(file_path)

    # Optionally, update the user's data to store the background filename
    user_file = os.path.join(USER_DATA_DIR, f"user_{user_id}.json")
    if os.path.exists(user_file):
        with open(user_file, "r+", encoding="utf-8") as f:
            user_data = json.load(f)
            user_data["background_image"] = filename
            f.seek(0)
            json.dump(user_data, f)
            f.truncate()

    return jsonify({"success": True, "filename": filename})
    
@app.route("/backgrounds/<filename>")
def serve_background(filename):
    return send_from_directory(BACKGROUND_DIR, filename)
    
# ─── Endpoints for Chat History ─────────────────────────────────────────────
@app.route("/history", methods=["GET"])
def get_history():
    user_id = request.args.get("user_id")
    partner_id = request.args.get("partner_id")
    if not user_id or not partner_id:
        return jsonify({"error": "user_id and partner_id required"}), 400
    filename = get_chat_filename(user_id, partner_id)
    history = []
    if os.path.exists(filename):
        with open(filename, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    msg = json.loads(line)
                    history.append(msg)
                except Exception as e:
                    logging.error("Error parsing history line: %s", e)
                    continue
    history.sort(key=lambda x: x["timestamp"])
    return jsonify({"history": history})

@app.route("/history_list", methods=["GET"])
def history_list():
    user_id = request.args.get("user_id")
    if not user_id:
        return jsonify({"error": "user_id required"}), 400
    user_file = os.path.join(USER_DATA_DIR, f"user_{user_id}.json")
    if not os.path.exists(user_file):
        return jsonify({"error": "User not found"}), 404
    with open(user_file, "r", encoding="utf-8") as f:
        user = json.load(f)
    friends = user.get("friends", [])
    conversations = []
    for friend_id in friends:
        friend_file = os.path.join(USER_DATA_DIR, f"user_{friend_id}.json")
        if os.path.exists(friend_file):
            with open(friend_file, "r", encoding="utf-8") as f:
                friend = json.load(f)
            unread_count = 0
            chat_file = get_chat_filename(user_id, friend_id)
            if os.path.exists(chat_file):
                with open(chat_file, "r", encoding="utf-8") as f:
                    for line in f:
                        try:
                            msg = json.loads(line)
                            if msg.get("recipient") == user_id and not msg.get("read", False):
                                unread_count += 1
                        except:
                            continue
            conversations.append({
                "partner_id": friend_id,
                "partner_name": friend.get("username", friend_id),
                "unread_count": unread_count,
                "online": friend_id in connected_users,
                "profile_picture": friend.get("profile_picture", "")
            })
    return jsonify({"conversations": conversations})

@app.route("/mark_read", methods=["POST"])
def mark_read():
    data = request.get_json()
    user_id = data.get("user_id")
    partner_id = data.get("partner_id")
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

# ─── Endpoints for Media (Private Chat) ─────────────────────────────────────
@app.route("/upload_media", methods=["POST"])
def upload_media():
    user_id = request.form.get("user_id")
    partner_id = request.form.get("partner_id")
    if not user_id or not partner_id:
        return jsonify({"error": "user_id and partner_id required"}), 400
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400
    ext = os.path.splitext(file.filename)[1]
    unique_name = str(uuid.uuid4()) + ext
    file_path = os.path.join(MEDIA_DIR, unique_name)
    file.save(file_path)
    file_size = os.path.getsize(file_path)
    log_media_message(user_id, partner_id, unique_name, file.filename, file_size)
    if partner_id in connected_users:
        partner = connected_users.get(partner_id)
        sender = connected_users.get(user_id)
        payload = {
            "from": user_id,
            "username": sender["username"] if sender else "Anonymous",
            "media": unique_name,
            "original_filename": file.filename,
            "file_size": file_size,
            "is_voice": False,
            "profile_picture": sender.get("profile_picture", "") if sender else ""
        }
        socketio.emit("media_message", payload, room=partner["sid"])
    logging.info("Media uploaded from %s to %s: %s", user_id, partner_id, unique_name)
    return jsonify({"message": "Media uploaded", "file": unique_name})

@app.route("/upload_voice", methods=["POST"])
def upload_voice():
    user_id = request.form.get("user_id")
    partner_id = request.form.get("partner_id")
    if not user_id or not partner_id:
        return jsonify({"error": "user_id and partner_id required"}), 400
    if "voice" not in request.files:
        return jsonify({"error": "No voice file uploaded"}), 400
    voice_file = request.files["voice"]
    if voice_file.filename == "":
        return jsonify({"error": "Empty filename"}), 400
    ext = os.path.splitext(voice_file.filename)[1]
    unique_name = str(uuid.uuid4()) + ext
    file_path = os.path.join(MEDIA_DIR, unique_name)
    voice_file.save(file_path)
    file_size = os.path.getsize(file_path)
    log_media_message(user_id, partner_id, unique_name, voice_file.filename, file_size, is_voice=True)
    if partner_id in connected_users:
        partner = connected_users.get(partner_id)
        sender = connected_users.get(user_id)
        payload = {
            "from": user_id,
            "username": sender["username"] if sender else "Anonymous",
            "media": unique_name,
            "original_filename": voice_file.filename,
            "file_size": file_size,
            "is_voice": True,
            "profile_picture": sender.get("profile_picture", "") if sender else ""
        }
        socketio.emit("media_message", payload, room=partner["sid"])
    logging.info("Voice uploaded from %s to %s: %s", user_id, partner_id, unique_name)
    return jsonify({"message": "Voice note uploaded", "file": unique_name})

@app.route("/media_history", methods=["GET"])
def media_history():
    user_id = request.args.get("user_id")
    partner_id = request.args.get("partner_id")
    if not user_id or not partner_id:
        return jsonify({"error": "user_id and partner_id required"}), 400
    filename = get_media_filename(user_id, partner_id)
    history = []
    now = datetime.datetime.utcnow()
    if os.path.exists(filename):
        with open(filename, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    ts = datetime.datetime.fromisoformat(entry["timestamp"])
                    if (now - ts).total_seconds() <= 86400:
                        history.append(entry)
                except:
                    continue
    history.sort(key=lambda x: x["timestamp"])
    return jsonify({"media": history})

@app.route("/download_media/<filename>", methods=["GET"])
def download_media(filename):
    return send_from_directory(MEDIA_DIR, filename, as_attachment=True)

# ─── Endpoint to Serve Profile Pictures ─────────────────────────────────────
@app.route("/profile_pictures/<filename>", methods=["GET"])
def serve_profile_picture(filename):
    return send_from_directory(PROFILE_PICS_DIR, filename, as_attachment=False)

# ─── Endpoints for Group Media and Voice Uploads ─────────────────────────────
@app.route("/upload_group_media", methods=["POST"])
def upload_group_media():
    user_id = request.form.get("user_id")
    group_id = request.form.get("group_id")
    if not user_id or not group_id:
        return jsonify({"error": "user_id and group_id required"}), 400
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400
    ext = os.path.splitext(file.filename)[1]
    unique_name = str(uuid.uuid4()) + ext
    file_path = os.path.join(MEDIA_DIR, unique_name)
    file.save(file_path)
    file_size = os.path.getsize(file_path)
    log_group_media_message(group_id, user_id, unique_name, file.filename, file_size, is_voice=False)
    group = load_group(group_id)
    if group:
        sender = connected_users.get(user_id)
        payload = {
            "group_id": group_id,
            "from": user_id,
            "username": sender["username"] if sender else "Anonymous",
            "media": unique_name,
            "original_filename": file.filename,
            "file_size": file_size,
            "is_voice": False,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "profile_picture": sender.get("profile_picture", "") if sender else ""
        }
        for member_id in group.get("members", []):
            if member_id in connected_users:
                member = connected_users[member_id]
                socketio.emit("group_message", payload, room=member["sid"])
    return jsonify({"message": "Group media uploaded", "file": unique_name})

@app.route("/upload_group_voice", methods=["POST"])
def upload_group_voice():
    user_id = request.form.get("user_id")
    group_id = request.form.get("group_id")
    if not user_id or not group_id:
        return jsonify({"error": "user_id and group_id required"}), 400
    if "voice" not in request.files:
        return jsonify({"error": "No voice file uploaded"}), 400
    voice_file = request.files["voice"]
    if voice_file.filename == "":
        return jsonify({"error": "Empty filename"}), 400
    ext = os.path.splitext(voice_file.filename)[1]
    unique_name = str(uuid.uuid4()) + ext
    file_path = os.path.join(MEDIA_DIR, unique_name)
    voice_file.save(file_path)
    file_size = os.path.getsize(file_path)
    log_group_media_message(group_id, user_id, unique_name, voice_file.filename, file_size, is_voice=True)
    group = load_group(group_id)
    if group:
        sender = connected_users.get(user_id)
        payload = {
            "group_id": group_id,
            "from": user_id,
            "username": sender["username"] if sender else "Anonymous",
            "media": unique_name,
            "original_filename": voice_file.filename,
            "file_size": file_size,
            "is_voice": True,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "profile_picture": sender.get("profile_picture", "") if sender else ""
        }
        for member_id in group.get("members", []):
            if member_id in connected_users:
                member = connected_users[member_id]
                socketio.emit("group_message", payload, room=member["sid"])
    return jsonify({"message": "Group voice note uploaded", "file": unique_name})

# ─── Endpoints for Account Management ─────────────────────────────────────────
@app.route("/connect_email", methods=["POST"])
def connect_email():
    data = request.get_json()
    user_id = data.get("user_id")
    email = data.get("email")
    password = data.get("password")
    if not user_id or not email or not password:
        return jsonify({"error": "user_id, email, and password required"}), 400
    user_file = os.path.join(USER_DATA_DIR, f"user_{user_id}.json")
    if not os.path.exists(user_file):
        return jsonify({"error": "User not found"}), 404
    with open(user_file, "r", encoding="utf-8") as f:
        user = json.load(f)
    user["email"] = email
    user["password"] = password
    save_user_data(user)
    logging.info("Email connected for user %s", user_id)
    return jsonify({"message": "Email connected successfully", "user": user})

@app.route("/upload_profile_picture", methods=["POST"])
def upload_profile_picture():
    user_id = request.form.get("user_id")
    if not user_id:
        return jsonify({"error": "user_id required"}), 400
    if "profile" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["profile"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400
    ext = os.path.splitext(file.filename)[1]
    unique_name = str(uuid.uuid4()) + ext
    file_path = os.path.join(PROFILE_PICS_DIR, unique_name)
    file.save(file_path)
    user_file = os.path.join(USER_DATA_DIR, f"user_{user_id}.json")
    if not os.path.exists(user_file):
        return jsonify({"error": "User not found"}), 404
    with open(user_file, "r", encoding="utf-8") as f:
        user = json.load(f)
    user["profile_picture"] = unique_name
    save_user_data(user)
    logging.info("Profile picture updated for user %s", user_id)
    return jsonify({"message": "Profile picture updated", "profile_picture": unique_name})

@app.route("/delete_account", methods=["POST"])
def delete_account():
    data = request.get_json()
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"error": "user_id required"}), 400
    logging.info("Delete account requested for user %s", user_id)
    return jsonify({"message": "Delete account not implemented yet"}), 501

# ─── Friend Management Endpoints ───────────────────────────────────────────
@app.route("/search_friends", methods=["GET"])
def search_friends():
    username_query = request.args.get("username", "").strip()
    exclude_id = request.args.get("exclude", "")
    results = []
    if username_query:
        for filename in os.listdir(USER_DATA_DIR):
            if filename.startswith("user_") and filename.endswith(".json"):
                filepath = os.path.join(USER_DATA_DIR, filename)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        user = json.load(f)
                    if exclude_id and user.get("user_id") == exclude_id:
                        continue
                    if username_query.lower() in user.get("username", "").lower():
                        results.append(user)
                except:
                    continue
    return jsonify({"results": results})

@app.route("/friends", methods=["GET"])
def get_friends():
    user_id = request.args.get("user_id")
    if not user_id:
        return jsonify({"error": "user_id required"}), 400
    user_file = os.path.join(USER_DATA_DIR, f"user_{user_id}.json")
    if not os.path.exists(user_file):
        return jsonify({"error": "User not found"}), 404
    with open(user_file, "r", encoding="utf-8") as f:
        user = json.load(f)
    friends_list = []
    for friend_id in user.get("friends", []):
        friend_file = os.path.join(USER_DATA_DIR, f"user_{friend_id}.json")
        if os.path.exists(friend_file):
            with open(friend_file, "r", encoding="utf-8") as ff:
                friend = json.load(ff)
            friend["online"] = friend_id in connected_users
            friends_list.append(friend)
    return jsonify({"friends": friends_list})

@app.route("/add_friend", methods=["POST"])
def add_friend():
    data = request.get_json()
    user_id = data.get("user_id")
    friend_id = data.get("friend_id")
    if not user_id or not friend_id:
        return jsonify({"error": "user_id and friend_id required"}), 400
    user_file = os.path.join(USER_DATA_DIR, f"user_{user_id}.json")
    if not os.path.exists(user_file):
        return jsonify({"error": "User not found"}), 404
    with open(user_file, "r", encoding="utf-8") as f:
        user = json.load(f)
    friends = user.get("friends", [])
    if friend_id not in friends:
        friends.append(friend_id)
        user["friends"] = friends
        with open(user_file, "w", encoding="utf-8") as f:
            json.dump(user, f)
        logging.info("Friend added: %s added friend %s", user_id, friend_id)
        return jsonify({"message": "Friend added"})
    else:
        return jsonify({"message": "Friend already exists"}), 200

@app.route("/delete_friend", methods=["POST"])
def delete_friend():
    data = request.get_json()
    user_id = data.get("user_id")
    friend_id = data.get("friend_id")
    if not user_id or not friend_id:
        return jsonify({"error": "user_id and friend_id required"}), 400
    user_file = os.path.join(USER_DATA_DIR, f"user_{user_id}.json")
    if not os.path.exists(user_file):
        return jsonify({"error": "User not found"}), 404
    with open(user_file, "r", encoding="utf-8") as f:
        user = json.load(f)
    friends = user.get("friends", [])
    if friend_id in friends:
        friends.remove(friend_id)
        user["friends"] = friends
        with open(user_file, "w", encoding="utf-8") as f:
            json.dump(user, f)
        logging.info("Friend deleted: %s deleted friend %s", user_id, friend_id)
        return jsonify({"message": "Friend deleted"})
    else:
        return jsonify({"message": "Friend not found"}), 200

# ─── Group Management Endpoints ─────────────────────────────────────────────
@app.route("/create_group", methods=["POST"])
def create_group():
    data = request.get_json()
    creator_id = data.get("creator_id")
    members = data.get("members", [])
    group_name = data.get("group_name", "Group " + str(uuid.uuid4()))
    if not creator_id:
        return jsonify({"error": "creator_id required"}), 400
    group_id = str(uuid.uuid4())
    group = {
        "group_id": group_id,
        "creator": creator_id,
        "members": [creator_id],
        "pending": members,
        "group_name": group_name,
        "created_at": datetime.datetime.utcnow().isoformat()
    }
    group_file = os.path.join(GROUPS_DIR, f"group_{group_id}.json")
    with open(group_file, "w", encoding="utf-8") as f:
        json.dump(group, f)
    for member_id in members:
        if member_id in connected_users:
            member = connected_users[member_id]
            socketio.emit("group_join_request", group, room=member["sid"])
    logging.info("Group created: %s", group)
    return jsonify({"message": "Group created", "group": group})

@app.route("/group_join_response", methods=["POST"])
def group_join_response():
    data = request.get_json()
    user_id = data.get("user_id")
    group_id = data.get("group_id")
    response = data.get("response")
    if not user_id or not group_id or response not in ["accept", "decline"]:
        return jsonify({"error": "user_id, group_id, and valid response required"}), 400
    group = load_group(group_id)
    if not group:
        return jsonify({"error": "Group not found"}), 404
    if user_id in group.get("pending", []):
        group["pending"].remove(user_id)
        if response == "accept":
            group["members"].append(user_id)
        save_group(group)
        return jsonify({"message": f"Group join {response}ed", "group": group})
    else:
        return jsonify({"message": "No pending request for this user"}), 200

@app.route("/group_add_member", methods=["POST"])
def group_add_member():
    data = request.get_json()
    group_id = data.get("group_id")
    admin_id = data.get("admin_id")
    new_member_id = data.get("new_member_id")
    if not group_id or not admin_id or not new_member_id:
        return jsonify({"error": "group_id, admin_id, and new_member_id required"}), 400
    group = load_group(group_id)
    if not group:
        return jsonify({"error": "Group not found"}), 404
    if group["creator"] != admin_id:
        return jsonify({"error": "Only group creator can add members"}), 403
    if new_member_id in group["members"] or new_member_id in group["pending"]:
        return jsonify({"message": "User already in group or pending"}), 200
    group["pending"].append(new_member_id)
    save_group(group)
    if new_member_id in connected_users:
        member = connected_users[new_member_id]
        socketio.emit("group_join_request", group, room=member["sid"])
    return jsonify({"message": "Member added to group (pending join)", "group": group})

@app.route("/group_remove_member", methods=["POST"])
def group_remove_member():
    data = request.get_json()
    group_id = data.get("group_id")
    admin_id = data.get("admin_id")
    member_id = data.get("member_id")
    if not group_id or not admin_id or not member_id:
        return jsonify({"error": "group_id, admin_id, and member_id required"}), 400
    group = load_group(group_id)
    if not group:
        return jsonify({"error": "Group not found"}), 404
    if group["creator"] != admin_id:
        return jsonify({"error": "Only group creator can remove members"}), 403
    if member_id in group["members"]:
        group["members"].remove(member_id)
        save_group(group)
        return jsonify({"message": "Member removed", "group": group})
    else:
        return jsonify({"message": "Member not found in group"}), 200

@app.route("/group_delete", methods=["POST"])
def group_delete():
    data = request.get_json()
    group_id = data.get("group_id")
    admin_id = data.get("admin_id")
    if not group_id or not admin_id:
        return jsonify({"error": "group_id and admin_id required"}), 400
    group = load_group(group_id)
    if not group:
        return jsonify({"error": "Group not found"}), 404
    if group["creator"] != admin_id:
        return jsonify({"error": "Only group creator can delete group"}), 403
    group_file = os.path.join(GROUPS_DIR, f"group_{group_id}.json")
    if os.path.exists(group_file):
        os.remove(group_file)
    return jsonify({"message": "Group deleted"})

@app.route("/leave_group", methods=["POST"])
def leave_group():
    data = request.get_json()
    group_id = data.get("group_id")
    user_id = data.get("user_id")
    if not group_id or not user_id:
        return jsonify({"error": "group_id and user_id required"}), 400
    group = load_group(group_id)
    if not group:
        return jsonify({"error": "Group not found"}), 404
    if user_id in group["members"]:
        group["members"].remove(user_id)
        save_group(group)
        return jsonify({"message": "Left group", "group": group})
    else:
        return jsonify({"message": "User not in group"}), 200

@app.route("/group_chat_history", methods=["GET"])
def group_chat_history():
    group_id = request.args.get("group_id")
    if not group_id:
        return jsonify({"error": "group_id required"}), 400
    filename = get_group_chat_filename(group_id)
    history = []
    if os.path.exists(filename):
        with open(filename, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    msg = json.loads(line)
                    history.append(msg)
                except Exception as e:
                    logging.error("Error parsing group chat line: %s", e)
                    continue
    history.sort(key=lambda x: x["timestamp"])
    return jsonify({"history": history})

@app.route("/groups", methods=["GET"])
def get_groups():
    user_id = request.args.get("user_id")
    if not user_id:
        return jsonify({"error": "user_id required"}), 400
    groups = []
    for filename in os.listdir(GROUPS_DIR):
        if filename.startswith("group_") and filename.endswith(".json"):
            filepath = os.path.join(GROUPS_DIR, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    group = json.load(f)
                if user_id in group.get("members", []):
                    group["status"] = "accepted"
                    groups.append(group)
                elif user_id in group.get("_", []):
                    group["status"] = "*"
                    groups.append(group)
            except:
                continue
    return jsonify({"groups": groups})

# Helper functions for group file operations
def load_group(group_id):
    group_file = os.path.join(GROUPS_DIR, f"group_{group_id}.json")
    if os.path.exists(group_file):
        with open(group_file, "r", encoding="utf-8") as f:
            return json.load(f)
    return None

def save_group(group):
    group_file = os.path.join(GROUPS_DIR, f"group_{group['group_id']}.json")
    with open(group_file, "w", encoding="utf-8") as f:
        json.dump(group, f)

# ─── Main ───────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5001, debug=True, use_reloader=False)
