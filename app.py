"""
RizzRoom — Flask + MySQL backend (Step 2)
Adds:
- Attachments (S3 presign + DB link)
- Emoji reactions
- Admin moderation (delete message, suspend user)
- Better error handling & validation
- UTF8MB4 everywhere
- Socket.IO events prepared for future: broadcast, music sync (placeholders)

Run:
  pip install flask flask-socketio eventlet flask-mysqldb flask-bcrypt flask-jwt-extended boto3 python-dotenv
  python app.py

Requires MySQL and AWS env vars (see .env example at bottom of file)
"""
from dotenv import load_dotenv
load_dotenv()

from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO, join_room, leave_room, emit
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from werkzeug.exceptions import HTTPException
import boto3, os, uuid, re, datetime
import MySQLdb
from MySQLdb.cursors import DictCursor
from MySQLdb import IntegrityError


# ------------------ App & Config ------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'supersecret')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'jwtsecret')
app.config['MYSQL_HOST'] = os.getenv('DB_HOST', 'localhost')
app.config['MYSQL_USER'] = os.getenv('DB_USER', 'root')
app.config['MYSQL_PASSWORD'] = os.getenv('DB_PASS', '')
app.config['MYSQL_DB'] = os.getenv('DB_NAME', 'rizz_room')
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'


socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')


bcrypt = Bcrypt(app)
jwt = JWTManager(app)

S3_BUCKET = os.getenv('S3_BUCKET', 'rizzroom-uploads')
S3_REGION = os.getenv('AWS_REGION', 'ap-south-1')
MAX_FILE_SIZE = int(os.getenv('MAX_UPLOAD_BYTES', str(5 * 1024 * 1024)))
ALLOWED_MIME = set(os.getenv('ALLOWED_MIME', 'image/png,image/jpeg,image/gif,video/mp4,application/pdf').split(','))

s3_client = boto3.client('s3', region_name=S3_REGION)

ROOM_GLOBAL = 'rizzroom-main'


conn = MySQLdb.connect(
    host=os.getenv("DB_HOST", "localhost"),
    user=os.getenv("DB_USER", "root"),
    passwd=os.getenv("DB_PASS", ""),
    db=os.getenv("DB_NAME", "rizz_room"),
    cursorclass=DictCursor
)

@app.get("/")
def home():
    return render_template("index.html")

# ------------------ Helpers ------------------

def db():
    return conn.cursor()


def sanitize_filename(name: str) -> str:
    return re.sub(r'[^a-zA-Z0-9._-]', '_', name or 'file')


def require_json(*keys):
    data = request.get_json(silent=True) or {}
    missing = [k for k in keys if data.get(k) in (None, '')]
    if missing:
        return None, (f"Missing fields: {', '.join(missing)}", 400)
    return data, None


def user_can_moderate(user):
    return user and user.get('role') in ('admin',)


def get_user(user_id: int):
    c = db()
    c.execute("SELECT id, username, status, role FROM users WHERE id=%s", (user_id,))
    return c.fetchone()

# ------------------ Error Handling ------------------

@app.errorhandler(HTTPException)
def handle_http(e: HTTPException):
    return jsonify({"error": e.name, "message": e.description}), e.code

@app.errorhandler(Exception)
def handle_exception(e: Exception):
    # Log in real app
    return jsonify({"error": "ServerError", "message": str(e)}), 500

# ------------------ Auth ------------------

@app.post('/register')
def register():
    data, err = require_json('username', 'email', 'password')
    if err:
        return jsonify({"msg": err[0]}), err[1]

    username = data['username'].strip()
    email = data['email'].strip().lower()
    password = data['password']
    c = db()

    try:
        c.execute(
            "INSERT INTO users (username,email,password_hash,status,role) VALUES (%s,%s,%s,'pending','user')",
            (username, email, password)
        )
        conn.commit()
    except IntegrityError as ex:
        if ex.args[0] == 1062:  # Duplicate entry
            return jsonify({"msg": "Username or email already registered"}), 400
        return jsonify({"msg": "Database error", "detail": str(ex)}), 500
    except Exception as ex:
        return jsonify({"msg": "Registration failed", "detail": str(ex)}), 400

    return jsonify({"msg": "Registered. Wait for approval."}), 201

@app.post('/login')
def login():
    data, err = require_json('username','password')
    print("#1", data, err)
    if err: return jsonify({"msg": err[0]}), err[1]
    c = db()
    c.execute("SELECT * FROM users WHERE username=%s", (data['username'],))
    user = c.fetchone()
    # if not user or not bcrypt.check_password_hash(user['password_hash'], data['password']):
    #     return jsonify({"msg": "Invalid credentials"}), 401
    if user['status'] != 'active':
        return jsonify({"msg": "Account not approved yet"}), 403

    token = create_access_token(identity=user['id'])
    return jsonify({"access_token": token, "user": {"id": user['id'], "username": user['username'], "role": user['role']}})

# ------------------ Admin Moderation ------------------

@app.get('/admin/users/pending')
@jwt_required()
def admin_pending_users():
    uid = get_jwt_identity()
    admin = get_user(uid)
    if not user_can_moderate(admin):
        return jsonify({"msg": "Forbidden"}), 403
    c = db()
    c.execute("SELECT id, username, email, created_at FROM users WHERE status='pending' ORDER BY created_at ASC")
    return jsonify(c.fetchall())

@app.post('/admin/users/<int:user_id>/approve')
@jwt_required()
def admin_approve_user(user_id):
    uid = get_jwt_identity()
    admin = get_user(uid)
    if not user_can_moderate(admin):
        return jsonify({"msg": "Forbidden"}), 403
    c = db()
    c.execute("UPDATE users SET status='active' WHERE id=%s", (user_id,))
    conn.commit()
    return jsonify({"msg": "User approved"})

@app.post('/admin/users/<int:user_id>/suspend')
@jwt_required()
def admin_suspend_user(user_id):
    uid = get_jwt_identity()
    admin = get_user(uid)
    if not user_can_moderate(admin):
        return jsonify({"msg": "Forbidden"}), 403
    c = db()
    c.execute("UPDATE users SET status='suspended' WHERE id=%s", (user_id,))
    conn.commit()
    return jsonify({"msg": "User suspended"})

@app.delete('/admin/messages/<int:message_id>')
@jwt_required()
def admin_delete_message(message_id):
    uid = get_jwt_identity()
    admin = get_user(uid)
    if not user_can_moderate(admin):
        return jsonify({"msg": "Forbidden"}), 403
    c = db()
    c.execute("UPDATE messages SET deleted_at=NOW() WHERE id=%s", (message_id,))
    conn.commit()
    # Notify room
    socketio.emit('message:delete', {"id": message_id}, to=ROOM_GLOBAL)
    return jsonify({"msg": "Message deleted"})

# ------------------ S3 Presign & Attachments ------------------

@app.post('/uploads/presign')
@jwt_required()
def presign_upload():
    data, err = require_json('filename','mime_type','size_bytes')
    if err: return jsonify({"msg": err[0]}), err[1]

    filename = sanitize_filename(data['filename'])
    size_bytes = int(data['size_bytes'])
    mime_type = data['mime_type']

    if size_bytes > MAX_FILE_SIZE:
        return jsonify({"msg": "File too large", "max": MAX_FILE_SIZE}), 400
    if mime_type not in ALLOWED_MIME:
        return jsonify({"msg": "MIME type not allowed"}), 400

    key = f"uploads/{datetime.datetime.utcnow().strftime('%Y/%m/%d')}/{uuid.uuid4()}-{filename}"
    presigned = s3_client.generate_presigned_post(
        Bucket=S3_BUCKET,
        Key=key,
        Fields={"Content-Type": mime_type},
        Conditions=[["content-length-range", 0, MAX_FILE_SIZE], {"Content-Type": mime_type}],
        ExpiresIn=3600,
    )
    return jsonify({"url": presigned['url'], "fields": presigned['fields'], "s3_key": key, "max_size": MAX_FILE_SIZE})

@app.post('/messages/<int:message_id>/attachments')
@jwt_required()
def attach_file(message_id):
    data, err = require_json('s3_key','mime_type','size_bytes')
    if err: return jsonify({"msg": err[0]}), err[1]

    uid = get_jwt_identity()
    # Optional: verify message ownership or room membership
    c = db()
    c.execute("SELECT id FROM messages WHERE id=%s AND deleted_at IS NULL", (message_id,))
    msg = c.fetchone()
    if not msg:
        return jsonify({"msg": "Message not found"}), 404

    c.execute(
        "INSERT INTO attachments (message_id, s3_key, mime_type, size_bytes) VALUES (%s,%s,%s,%s)",
        (message_id, data['s3_key'], data['mime_type'], int(data['size_bytes']))
    )
    c.execute("UPDATE messages SET has_attachments=1 WHERE id=%s", (message_id,))
    conn.commit()

    socketio.emit('attachment:new', {"message_id": message_id, "s3_key": data['s3_key']}, to=ROOM_GLOBAL)
    return jsonify({"msg": "Attachment linked"}), 201

# ------------------ Messages & Reactions ------------------

@app.get('/rooms/main/messages')
@jwt_required()
def list_messages():
    before_id = request.args.get('before')
    limit = min(int(request.args.get('limit', 50)), 100)
    c = db()
    if before_id:
        c.execute("SELECT * FROM messages_view WHERE id < %s ORDER BY id DESC LIMIT %s", (before_id, limit))
    else:
        c.execute("SELECT * FROM messages_view ORDER BY id DESC LIMIT %s", (limit,))
    return jsonify(list(reversed(c.fetchall())))

@app.post('/rooms/main/messages')
@jwt_required()
def create_message():
    data, err = require_json('content')
    if err: return jsonify({"msg": err[0]}), err[1]
    uid = get_jwt_identity()

    content = (data['content'] or '').strip()
    if not content:
        return jsonify({"msg": "Empty message"}), 400

    c = db()
    c.execute("INSERT INTO messages (room_id, user_id, content) VALUES (%s,%s,%s)", (1, uid, content))
    msg_id = c.lastrowid
    conn.commit()

    payload = {"id": msg_id, "user_id": uid, "content": content}
    socketio.emit('message:new', payload, to=ROOM_GLOBAL)
    return jsonify(payload), 201

@app.post('/messages/<int:message_id>/reactions')
@jwt_required()
def add_reaction(message_id):
    data, err = require_json('emoji')
    if err: return jsonify({"msg": err[0]}), err[1]
    uid = get_jwt_identity()
    emoji = data['emoji'][:16]

    c = db()
    c.execute("INSERT IGNORE INTO message_reactions (message_id, user_id, emoji) VALUES (%s,%s,%s)", (message_id, uid, emoji))
    conn.commit()

    socketio.emit('reaction:new', {"message_id": message_id, "user_id": uid, "emoji": emoji}, to=ROOM_GLOBAL)
    return jsonify({"msg": "Reaction added"}), 201

@app.delete('/messages/<int:message_id>/reactions')
@jwt_required()
def remove_reaction(message_id):
    emoji = request.args.get('emoji', '')[:16]
    uid = get_jwt_identity()
    c = db()
    c.execute("DELETE FROM message_reactions WHERE message_id=%s AND user_id=%s AND emoji=%s", (message_id, uid, emoji))
    conn.commit()

    socketio.emit('reaction:remove', {"message_id": message_id, "user_id": uid, "emoji": emoji}, to=ROOM_GLOBAL)
    return jsonify({"msg": "Reaction removed"})

@app.delete('/messages/<int:message_id>')
@jwt_required()
def delete_own_message(message_id):
    uid = get_jwt_identity()
    c = db()
    c.execute("UPDATE messages SET deleted_at=NOW() WHERE id=%s AND user_id=%s", (message_id, uid))
    conn.commit()
    socketio.emit('message:delete', {"id": message_id}, to=ROOM_GLOBAL)
    return jsonify({"msg": "Message deleted"})

# ------------------ Socket.IO Events ------------------

@socketio.on('join')
def sio_join(data):
    username = data.get('username', 'anon')
    join_room(ROOM_GLOBAL)
    emit('system', {"msg": f"{username} joined"}, to=ROOM_GLOBAL)

@socketio.on('typing')
def sio_typing(data):
    emit('user:typing', {"user": data.get('user'), "state": data.get('state', True)}, to=ROOM_GLOBAL, include_self=False)

# --- Future placeholders ---
@socketio.on('broadcast:start')
def sio_broadcast_start(data):
    # Placeholder for future audio broadcast signaling
    emit('broadcast:status', {"state": "started", "by": data.get('user')}, to=ROOM_GLOBAL)

@socketio.on('broadcast:stop')
def sio_broadcast_stop(data):
    emit('broadcast:status', {"state": "stopped", "by": data.get('user')}, to=ROOM_GLOBAL)

@socketio.on('music:play')
def sio_music_play(data):
    # data: {"track_key": "s3_key", "position_ms": 0}
    emit('music:sync', data, to=ROOM_GLOBAL)

@socketio.on('music:stop')
def sio_music_stop(data):
    emit('music:sync', {"track_key": None}, to=ROOM_GLOBAL)

# ------------------ Main ------------------
if __name__ == '__main__':
    # For websockets, eventlet/gevent is recommended
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
