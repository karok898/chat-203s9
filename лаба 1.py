import os
from dotenv import load_dotenv
from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, BooleanField, FileField
from wtforms.validators import DataRequired, EqualTo, Length, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from functools import wraps
import hashlib
from flask_socketio import SocketIO, emit
from cryptography.fernet import Fernet

# Загрузка переменных окружения
load_dotenv()


# Конфигурация приложения
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///app.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB


# Инициализация приложения
app = Flask(__name__)
app.config.from_object(Config)

# Инициализация расширений
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app)

# Инициализация шифрования
key = os.environ.get('ENCRYPTION_KEY')
if not key:
    raise ValueError("ENCRYPTION_KEY не установлена в .env!")
cipher = Fernet(key.encode())


# Модели базы данных
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_file = db.Column(db.Boolean, default=False)
    filename = db.Column(db.String(255))
    encrypted = db.Column(db.Boolean, default=False)

    sender = db.relationship('User', foreign_keys=[sender_id])
    recipient = db.relationship('User', foreign_keys=[recipient_id])


# Формы
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=64)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already taken.')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class MessageForm(FlaskForm):
    recipient = StringField('Recipient', validators=[DataRequired()])
    message = TextAreaField('Message', validators=[DataRequired()])
    file = FileField('File')
    encrypt = BooleanField('Encrypt')
    submit = SubmitField('Send')


# Функции для работы с пользователями
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


# Маршруты
@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('chat'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/chat')
@login_required
def chat():
    form = MessageForm()
    users = User.query.filter(User.id != current_user.id).all()
    messages = Message.query.filter(
        (Message.sender_id == current_user.id) |
        (Message.recipient_id == current_user.id)
    ).order_by(Message.timestamp).all()

    # Расшифровка сообщений
    decrypted_messages = []
    for msg in messages:
        if msg.encrypted:
            try:
                content = cipher.decrypt(msg.text.encode()).decode()
            except:
                content = "[encrypted message]"
        else:
            content = msg.text

        decrypted_messages.append({
            'id': msg.id,
            'sender': msg.sender.username,
            'recipient': msg.recipient.username,
            'content': content,
            'time': msg.timestamp.strftime('%H:%M'),
            'is_file': msg.is_file,
            'filename': msg.filename,
            'encrypted': msg.encrypted
        })

    return render_template('chat.html', form=form, messages=decrypted_messages, users=users)


@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('chat'))

    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('chat'))

    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # Здесь можно добавить логику для сохранения информации о файле в базу
        flash('File uploaded successfully!', 'success')
        return redirect(url_for('chat'))


@app.route('/download/<filename>')
@login_required
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


# WebSocket обработчики
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        join_room(current_user.username)
        emit('connection_status', {'status': 'connected', 'username': current_user.username})


@socketio.on('send_message')
def handle_message(data):
    recipient = User.query.filter_by(username=data['recipient']).first()
    if not recipient:
        emit('error', {'message': 'Recipient not found'})
        return

    if data.get('encrypt', False):
        encrypted_text = cipher.encrypt(data['message'].encode()).decode()
        msg = Message(
            sender_id=current_user.id,
            recipient_id=recipient.id,
            text=encrypted_text,
            encrypted=True
        )
    else:
        msg = Message(
            sender_id=current_user.id,
            recipient_id=recipient.id,
            text=data['message'],
            encrypted=False
        )

    db.session.add(msg)
    db.session.commit()

    message_data = {
        'sender': current_user.username,
        'recipient': recipient.username,
        'message': data['message'],
        'time': datetime.utcnow().strftime('%H:%M'),
        'encrypted': data.get('encrypt', False)
    }

    emit('new_message', message_data, room=current_user.username)
    emit('new_message', message_data, room=recipient.username)


# Создание базы данных и папок при запуске
with app.app_context():
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    db.create_all()

if __name__ == '__main__':
    socketio.run(app, debug=True)