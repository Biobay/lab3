from . import db, login_manager
from argon2 import PasswordHasher
import secrets
from flask_login import UserMixin

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

ph = PasswordHasher()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(150), nullable=False)
    cognome = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    codice_fiscale = db.Column(db.String(16), unique=True, nullable=False)
    telefono = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=False)
    activation_token = db.Column(db.String(128), unique=True)

    def set_password(self, password):
        self.password_hash = ph.hash(password)

    def check_password(self, password):
        try:
            return ph.verify(self.password_hash, password)
        except Exception:
            return False

    def generate_activation_token(self):
        self.activation_token = secrets.token_urlsafe(32)
