"""
Factory dell'applicazione e inizializzazione delle estensioni.

Questo file contiene la funzione `create_app`, che è la factory per l'applicazione Flask.
Inizializza l'app, carica la configurazione, registra le estensioni principali
(SQLAlchemy, LoginManager, Mail) e importa i blueprint. Questo pattern permette
di creare diverse istanze dell'app con configurazioni differenti (es. per test,
produzione, sviluppo) e previene problemi di importazione circolare.
"""

from flask import Flask, request, redirect, url_for
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
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
    # Carica variabili da .env se presente
    load_dotenv()
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    # Abilita CSRF globale per tutte le richieste/moduli
    CSRFProtect(app)

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

    # Enforce session token cookie for authenticated users
    @app.before_request
    def _enforce_session_token():
        from flask_login import current_user, logout_user
        from app.models import Session
        # Applica solo ad utenti autenticati
        if not getattr(request, 'endpoint', None):
            return None
        if not current_user.is_authenticated:
            return None

        name = app.config.get('SESSION_TOKEN_COOKIE_NAME', 'session_token')
        token = request.cookies.get(name)
        if not token:
            # Nessun token: logout e redirect a login
            logout_user()
            resp = redirect(url_for('main.login'))
            try:
                resp.delete_cookie(name, path='/')
            except Exception:
                pass
            return resp

        s = Session.query.filter_by(session_token=token, user_id=current_user.id).first()
        if not s or not s.active:
            # Token non valido o revocato: logout e redirect
            logout_user()
            resp = redirect(url_for('main.login'))
            try:
                resp.delete_cookie(name, path='/')
            except Exception:
                pass
            return resp

        # Sessione valida: aggiorna last_seen
        try:
            s.touch()
            db.session.commit()
        except Exception:
            db.session.rollback()
        return None

    # Opzionale: forza HTTPS e imposta HSTS in produzione
    if app.config.get('FORCE_HTTPS'):
        @app.before_request
        def _force_https_redirect():
            if not request.is_secure and request.headers.get('X-Forwarded-Proto', 'http') != 'https':
                url = request.url.replace('http://', 'https://', 1)
                return redirect(url, code=301)

    if app.config.get('HSTS_ENABLED'):
        @app.after_request
        def _set_hsts_header(response):
            max_age = app.config.get('HSTS_MAX_AGE', 31536000)
            response.headers['Strict-Transport-Security'] = f'max-age={max_age}; includeSubDomains'
            return response

    return app
