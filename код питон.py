import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
from datetime import datetime
from flask_cors import CORS
from socket import gethostname, gethostbyname
import hashlib
import json
from functools import wraps

# Инициализация Flask
app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = os.urandom(32).hex()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///messages.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

# Инициализация SQLAlchemy
db = SQLAlchemy(app)


# Модель Message (ваша версия)
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(50), nullable=False)
    recipient = db.Column(db.String(50), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_file = db.Column(db.Boolean, default=False)
    file_name = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"Message(id={self.id}, sender='{self.sender}', recipient='{self.recipient}')"


# Остальные модели
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120), nullable=False)
    path = db.Column(db.String(256), nullable=False)
    hash = db.Column(db.String(64), nullable=False)
    owner = db.Column(db.String(80), nullable=False)
    recipient = db.Column(db.String(80), nullable=False)


# Создаем папки если их нет
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", logger=True, engineio_logger=True)


# Шифрование
class AESCipher:
    def __init__(self, key=None):
        self.key = key if key else get_random_bytes(32)
        self.block_size = AES.block_size

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

    def decrypt(self, data):
        data = base64.b64decode(data)
        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

    def encrypt_file(self, file_path):
        with open(file_path, 'rb') as f:
            data = f.read()

        cipher = AES.new(self.key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        encrypted_path = file_path + '.enc'
        with open(encrypted_path, 'wb') as f:
            [f.write(x) for x in (cipher.nonce, tag, ciphertext)]

        return encrypted_path

    def decrypt_file(self, encrypted_path, original_hash):
        with open(encrypted_path, 'rb') as f:
            nonce, tag, ciphertext = [f.read(x) for x in (16, 16, -1)]

        cipher = AES.new(self.key, AES.MODE_EAX, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)

        if hashlib.sha256(data).hexdigest() != original_hash:
            raise ValueError("File integrity compromised!")

        decrypted_path = encrypted_path[:-4]
        with open(decrypted_path, 'wb') as f:
            f.write(data)

        return decrypted_path


cipher = AESCipher()


# Декоратор для проверки аутентификации
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


# Маршруты
@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('Username already exists!')
            return redirect(url_for('register'))

        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session['username'] = username
            return redirect(url_for('chat'))
        else:
            flash('Invalid username or password!')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/chat')
@login_required
def chat():
    messages = Message.query.filter(
        (Message.sender == session['username']) |
        (Message.recipient == session['username'])
    ).order_by(Message.timestamp.asc()).all()

    decrypted_messages = []
    for msg in messages:
        if msg.is_file:
            decrypted_content = f"FILE:{msg.file_name}"
        else:
            decrypted_content = cipher.decrypt(msg.content)

        decrypted_messages.append({
            'id': msg.id,
            'sender': msg.sender,
            'recipient': msg.recipient,
            'content': decrypted_content,
            'is_file': msg.is_file,
            'file_name': msg.file_name,
            'time': msg.timestamp.strftime('%H:%M')
        })

    return render_template('chat.html',
                           username=session['username'],
                           messages=decrypted_messages)


@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return {'status': 'error', 'message': 'No file part'}, 400

    file = request.files['file']
    recipient = request.form.get('recipient')

    if file.filename == '':
        return {'status': 'error', 'message': 'No selected file'}, 400

    if not recipient:
        return {'status': 'error', 'message': 'No recipient specified'}, 400

    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    encrypted_path = cipher.encrypt_file(file_path)
    file_hash = hashlib.sha256(open(file_path, 'rb').read()).hexdigest()

    file_record = File(
        filename=filename,
        path=encrypted_path,
        hash=file_hash,
        owner=session['username'],
        recipient=recipient
    )
    db.session.add(file_record)

    msg = Message(
        sender=session['username'],
        recipient=recipient,
        content=f"FILE:{filename}",
        is_file=True,
        file_name=filename
    )
    db.session.add(msg)
    db.session.commit()

    os.unlink(file_path)

    return {'status': 'success', 'message': 'File uploaded and encrypted'}


@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file_record = File.query.get_or_404(file_id)

    if session['username'] not in [file_record.owner, file_record.recipient]:
        return "Access denied", 403

    try:
        decrypted_path = cipher.decrypt_file(file_record.path, file_record.hash)
    except ValueError as e:
        return str(e), 400

    response = send_from_directory(
        directory=os.path.dirname(decrypted_path),
        path=os.path.basename(decrypted_path),
        as_attachment=True,
        download_name=file_record.filename
    )

    os.unlink(decrypted_path)

    return response


# WebSocket обработчики
@socketio.on('connect')
def handle_connect():
    if 'username' in session:
        join_room(session['username'])
        emit('connection_status', {'status': 'connected', 'username': session['username']})


@socketio.on('disconnect')
def handle_disconnect():
    if 'username' in session:
        leave_room(session['username'])


@socketio.on('message')
def handle_message(data):
    if 'username' not in session:
        emit('error', {'message': 'Not authenticated'}, room=request.sid)
        return

    sender = session['username']
    recipient = data.get('recipient')
    message_content = data.get('message')

    if not recipient or not message_content:
        emit('error', {'message': 'Recipient and message required'}, room=request.sid)
        return

    encrypted_msg = cipher.encrypt(message_content)
    msg = Message(
        sender=sender,
        recipient=recipient,
        content=encrypted_msg,
        is_file=False
    )
    db.session.add(msg)
    db.session.commit()

    message_data = {
        'sender': sender,
        'recipient': recipient,
        'message': message_content,
        'time': datetime.utcnow().strftime('%H:%M'),
        'id': msg.id
    }

    emit('new_message', message_data, room=recipient)
    emit('message_delivered', message_data, room=sender)


@app.route('/api/docs')
def api_docs():
    return json.dumps({
        'version': '1.0',
        'endpoints': {
            '/register': 'Регистрация пользователя',
            '/login': 'Аутентификация',
            '/chat': 'Основной интерфейс чата',
            '/upload': 'Загрузка файлов',
            '/download/<id>': 'Скачивание файлов'
        },
        'security': {
            'encryption': 'AES-256 EAX mode',
            'password_hashing': 'PBKDF2-HMAC-SHA256',
            'file_verification': 'SHA-256'
        }
    }, indent=2)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    local_ip = gethostbyname(gethostname())
    print("\nСервер запущен. Доступные адреса:")
    print(f"  На этом устройстве: http://localhost:5000")
    print(f"  В локальной сети: http://{local_ip}:5000")
    print(f"  Документация API: http://localhost:5000/api/docs")

    socketio.run(
        app,
        host='0.0.0.0',
        port=5000,
        debug=True,
        allow_unsafe_werkzeug=True
    )