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
