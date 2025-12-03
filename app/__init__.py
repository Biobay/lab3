"""
Factory dell'applicazione e inizializzazione delle estensioni.

Questo file contiene la funzione `create_app`, che è la factory per l'applicazione Flask.
Inizializza l'app, carica la configurazione, registra le estensioni principali
(SQLAlchemy, LoginManager, Mail) e importa i blueprint. Questo pattern permette
di creare diverse istanze dell'app con configurazioni differenti (es. per test,
produzione, sviluppo) e previene problemi di importazione circolare.
"""

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from config import Config
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
except ImportError:
    Limiter = None
    get_remote_address = None

db = SQLAlchemy()
mail = Mail()
login_manager = LoginManager()
login_manager.login_view = 'main.login'
login_manager.login_message = 'Per accedere a questa pagina è necessario effettuare il login.'
login_manager.login_message_category = 'info'

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)

    # Rate limiting (optional if Flask-Limiter installed)
    if Limiter and get_remote_address:
        storage_uri = app.config.get('RATELIMIT_STORAGE_URI')
        limiter = Limiter(
            get_remote_address,
            app=app,
            default_limits=["200 per day", "50 per hour"],
            storage_uri=storage_uri
        )  # global sane defaults

    from app.routes import main
    app.register_blueprint(main)

    return app
