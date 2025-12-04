"""
Definizione dei modelli di dati per il database.

Questo modulo contiene le classi che definiscono la struttura del database
utilizzando SQLAlchemy ORM (Object-Relational Mapper). Ogni classe
rappresenta una tabella nel database e i suoi attributi corrispondono
alle colonne della tabella. Vengono definiti anche metodi utili per
interagire con i dati del modello.
"""

from . import db, login_manager
from argon2 import PasswordHasher
from datetime import datetime, timedelta
import secrets
from flask_login import UserMixin
from flask import current_app
from itsdangerous import URLSafeTimedSerializer as Serializer
from sqlalchemy.orm import validates

ph = PasswordHasher()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(150), nullable=False)
    cognome = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    codice_fiscale = db.Column(db.String(16), unique=True, nullable=False)
    telefono = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=False)
    activation_token = db.Column(db.String(128), unique=True)
    activation_token_expiration = db.Column(db.DateTime, nullable=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
    lock_until = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = ph.hash(password)

    def check_password(self, password):
        return ph.verify(self.password_hash, password)

    def is_locked(self):
        if self.lock_until is None:
            return False
        return datetime.utcnow() < self.lock_until

    def register_failed_login(self, max_attempts=5, lock_minutes=15):
        self.failed_login_attempts = (self.failed_login_attempts or 0) + 1
        if self.failed_login_attempts >= max_attempts:
            self.lock_until = datetime.utcnow() + timedelta(minutes=lock_minutes)
            self.failed_login_attempts = 0
        return self.lock_until

    def reset_login_lock(self):
        self.failed_login_attempts = 0
        self.lock_until = None

    def generate_activation_token(self):
        self.activation_token = secrets.token_urlsafe(32)
        self.activation_token_expiration = datetime.utcnow() + timedelta(hours=24)
        return self.activation_token

    def get_reset_token(self):
        s = Serializer(current_app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id}, salt='password-reset-salt')

    @staticmethod
    def verify_reset_token(token, expires_sec=1800):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(
                token, 
                salt='password-reset-salt', 
                max_age=expires_sec
            )['user_id']
        except:
            return None
        return User.query.get(user_id)

class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_token = db.Column(db.String(128), unique=True, nullable=False)
    user_agent = db.Column(db.String(255))
    ip_address = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    active = db.Column(db.Boolean, default=True)

    user = db.relationship('User', backref=db.backref('sessions', lazy=True))

    @staticmethod
    def new(user_id: int, token: str, user_agent: str, ip: str):
        s = Session(user_id=user_id, session_token=token, user_agent=user_agent, ip_address=ip)
        db.session.add(s)
        return s

    def touch(self):
        self.last_seen = datetime.utcnow()

    def revoke(self):
        self.active = False

class LoginChallenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    attempts = db.Column(db.Integer, default=0)
    consumed = db.Column(db.Boolean, default=False)

    user = db.relationship('User', backref=db.backref('login_challenges', lazy=True))

    @staticmethod
    def new_for(user_id: int, code: str, ttl_minutes: int = 10):
        challenge = LoginChallenge(
            user_id=user_id,
            code=code,
            expires_at=datetime.utcnow() + timedelta(minutes=ttl_minutes),
        )
        db.session.add(challenge)
        return challenge

    def is_expired(self):
        return datetime.utcnow() > self.expires_at

    def register_attempt(self):
        self.attempts = (self.attempts or 0) + 1

    def consume(self):
        self.consumed = True
