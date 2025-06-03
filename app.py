import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
import hmac
import base64
from io import BytesIO
from urllib.parse import quote, unquote

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///emeska.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['ENCRYPTION_KEY'] = hashlib.sha256(b'master_secret_key').digest()

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('static/images', exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy='dynamic')
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver',
                                        lazy='dynamic')
    files = db.relationship('File', backref='owner', lazy='dynamic')


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_content = db.Column(db.Text, nullable=False)
    iv = db.Column(db.Text, nullable=False)
    hmac = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=True)


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    encrypted_filename = db.Column(db.String(255), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    iv = db.Column(db.Text, nullable=False)
    hmac = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    message = db.relationship('Message', backref='file', uselist=False)


def encrypt_data(data: bytes, key: bytes) -> tuple:
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    hmac_val = hmac.new(key, ct_bytes + iv, hashlib.sha256).digest()
    return (
        base64.b64encode(ct_bytes).decode('utf-8'),
        base64.b64encode(iv).decode('utf-8'),
        base64.b64encode(hmac_val).decode('utf-8')
    )


def decrypt_data(encrypted: str, iv: str, hmac_val: str, key: bytes) -> bytes:
    try:
        ct_bytes = base64.b64decode(encrypted)
        iv_bytes = base64.b64decode(iv)
        hmac_bytes = base64.b64decode(hmac_val)

        expected_hmac = hmac.new(key, ct_bytes + iv_bytes, hashlib.sha256).digest()
        if not hmac.compare_digest(hmac_bytes, expected_hmac):
            raise ValueError("HMAC verification failed")

        cipher = AES.new(key, AES.MODE_CBC, iv_bytes)
        pt = unpad(cipher.decrypt(ct_bytes), AES.block_size)
        return pt
    except (ValueError, KeyError, TypeError) as e:
        raise ValueError(f"Decryption error: {str(e)}")


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}


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
            flash('Имя пользователя уже существует!', 'error')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Регистрация успешна! Теперь вы можете войти.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('contacts'))

        flash('Неверное имя пользователя или пароль', 'error')

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
        # Обработка файла
        if 'file' in request.files:
            file = request.files['file']
            if file.filename != '' and allowed_file(file.filename):
                try:
                    # Генерация уникального имени файла
                    filename = secure_filename(file.filename)
                    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                    safe_filename = f"{timestamp}_{filename}"

                    # Чтение и шифрование файла
                    file_data = file.read()
                    encrypted_data, iv, hmac_val = encrypt_data(file_data, app.config['ENCRYPTION_KEY'])

                    # Сохранение файла
                    encrypted_filename = f"file_{current_user.id}_{contact_id}_{timestamp}{os.path.splitext(filename)[1]}"
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)

                    with open(file_path, 'wb') as f:
                        f.write(base64.b64decode(encrypted_data))

                    # Сохранение информации о файле
                    new_file = File(
                        filename=safe_filename,
                        encrypted_filename=encrypted_filename,
                        owner_id=current_user.id,
                        iv=iv,
                        hmac=hmac_val
                    )
                    db.session.add(new_file)
                    db.session.flush()

                    # Создание сообщения
                    new_message = Message(
                        sender_id=current_user.id,
                        receiver_id=contact.id,
                        encrypted_content=f"Файл: {safe_filename}",
                        iv=iv,
                        hmac=hmac_val,
                        file_id=new_file.id
                    )
                    db.session.add(new_message)

                except Exception as e:
                    db.session.rollback()
                    flash(f'Ошибка при загрузке файла: {str(e)}', 'error')
                    return redirect(url_for('chat', contact_id=contact.id))

        # Обработка текстового сообщения
        if 'content' in request.form and request.form['content']:
            try:
                content = request.form['content']
                encrypted, iv, hmac_val = encrypt_data(content.encode('utf-8'), app.config['ENCRYPTION_KEY'])

                new_message = Message(
                    sender_id=current_user.id,
                    receiver_id=contact.id,
                    encrypted_content=encrypted,
                    iv=iv,
                    hmac=hmac_val
                )
                db.session.add(new_message)
            except Exception as e:
                flash(f'Ошибка при отправке сообщения: {str(e)}', 'error')

        db.session.commit()
        return redirect(url_for('chat', contact_id=contact.id))

    # Получение сообщений
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == contact.id)) |
        ((Message.sender_id == contact.id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()

    decrypted_messages = []
    for msg in messages:
        try:
            decrypted = decrypt_data(
                msg.encrypted_content,
                msg.iv,
                msg.hmac,
                app.config['ENCRYPTION_KEY']
            ).decode('utf-8')
            error = False
        except Exception as e:
            decrypted = f"Ошибка дешифрования"
            error = True

        decrypted_messages.append({
            'content': decrypted,
            'sender': msg.sender,
            'timestamp': msg.timestamp,
            'error': error,
            'file': msg.file
        })

    return render_template('chat.html',
                           messages=decrypted_messages,
                           contact=contact,
                           contacts=User.query.filter(User.id != current_user.id).all())


@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.owner_id != current_user.id and not Message.query.filter(
            ((Message.sender_id == current_user.id) | (Message.receiver_id == current_user.id)),
            Message.file_id == file_id
    ).first():
        flash('У вас нет доступа к этому файлу', 'error')
        return redirect(url_for('contacts'))

    try:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.encrypted_filename)
        if not os.path.exists(file_path):
            flash('Файл не найден на сервере', 'error')
            return redirect(url_for('contacts'))
        with open(file_path, 'rb') as f:
            encrypted_data = base64.b64encode(f.read()).decode('utf-8')
        file_data = decrypt_data(encrypted_data, file.iv, file.hmac, app.config['ENCRYPTION_KEY'])

        mem_file = BytesIO()
        mem_file.write(file_data)
        mem_file.seek(0)
        download_name = secure_filename(file.filename) # Clean filename
        # download_name = quote(file.filename) # encode for compatibility  (remove)

        return send_file(
            mem_file,
            as_attachment=True,
            download_name=download_name, # send clean file
            mimetype='application/octet-stream'
        )
    except Exception as e:
        flash(f'Ошибка при загрузке файла: {str(e)}', 'error')
        return redirect(url_for('contacts'))


@app.before_request
def create_tables():
    db.create_all()
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
