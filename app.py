from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from sqlalchemy.orm import relationship
import bcrypt
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
import hmac
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['ENCRYPTION_KEY'] = hashlib.sha256(
    b'master_secret_key').digest()  # В реальном проекте используйте безопасное хранилище ключей

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    sent_messages = relationship('Message', foreign_keys='Message.sender_id', backref='sender')
    received_messages = relationship('Message', foreign_keys='Message.receiver_id', backref='receiver')


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_content = db.Column(db.Text, nullable=False)
    iv = db.Column(db.Text, nullable=False)
    hmac = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


def encrypt_message(message: str, key: bytes) -> tuple:
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    hmac_val = hmac.new(key, ct_bytes + iv, hashlib.sha256).digest()
    return (
        base64.b64encode(ct_bytes).decode('utf-8'),
        base64.b64encode(iv).decode('utf-8'),
        base64.b64encode(hmac_val).decode('utf-8')
    )


def decrypt_message(encrypted: str, iv: str, hmac_val: str, key: bytes) -> str:
    try:
        ct_bytes = base64.b64decode(encrypted)
        iv_bytes = base64.b64decode(iv)
        hmac_bytes = base64.b64decode(hmac_val)

        expected_hmac = hmac.new(key, ct_bytes + iv_bytes, hashlib.sha256).digest()
        if not hmac.compare_digest(hmac_bytes, expected_hmac):
            raise ValueError("HMAC verification failed")

        cipher = AES.new(key, AES.MODE_CBC, iv_bytes)
        pt = unpad(cipher.decrypt(ct_bytes), AES.block_size)
        return pt.decode('utf-8')
    except (ValueError, KeyError, TypeError) as e:
        return f"Ошибка дешифрования: {str(e)}"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            return 'Имя пользователя уже существует!'

        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        new_user = User(username=username, password_hash=hashed.decode('utf-8'))
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            login_user(user)
            return redirect(url_for('contacts'))

        return 'Неверное имя пользователя или пароль'
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/contacts')
@login_required
def contacts():
    all_users = User.query.filter(User.id != current_user.id).order_by(User.username).all()
    return render_template('contacts.html', contacts=all_users)


@app.route('/chat/<int:contact_id>', methods=['GET', 'POST'])
@login_required
def chat(contact_id):
    contact = User.query.get_or_404(contact_id)

    if request.method == 'POST':
        content = request.form['content']
        encrypted, iv, hmac_val = encrypt_message(content, app.config['ENCRYPTION_KEY'])

        new_message = Message(
            sender_id=current_user.id,
            receiver_id=contact.id,
            encrypted_content=encrypted,
            iv=iv,
            hmac=hmac_val
        )
        db.session.add(new_message)
        db.session.commit()
        return redirect(url_for('chat', contact_id=contact.id))

    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == contact.id)) |
        ((Message.sender_id == contact.id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()

    decrypted_messages = []
    for msg in messages:
        decrypted = decrypt_message(
            msg.encrypted_content,
            msg.iv,
            msg.hmac,
            app.config['ENCRYPTION_KEY']
        )
        decrypted_messages.append({
            'content': decrypted,
            'sender': msg.sender,
            'timestamp': msg.timestamp,
            'error': 'Ошибка' in decrypted
        })

    all_contacts = User.query.filter(User.id != current_user.id).order_by(User.username).all()

    return render_template('chat.html',
                           messages=decrypted_messages,
                           contact=contact,
                           contacts=all_contacts)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)