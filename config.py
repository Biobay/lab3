"""
File di configurazione per l'applicazione Flask.

Questo modulo definisce le classi di configurazione per l'applicazione.
La classe `Config` carica le impostazioni da variabili d'ambiente o utilizza
valori di default, separando la configurazione dal codice sorgente per
maggiore sicurezza e flessibilità.
"""

import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-super-secret-key-that-you-should-change'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance/app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # Rate limit storage backend (Flask-Limiter)
    # In sviluppo usiamo memoria per evitare dipendenze; per produzione usare Redis o altro backend.
    RATELIMIT_STORAGE_URI = os.environ.get('RATELIMIT_STORAGE_URL') or os.environ.get('RATELIMIT_STORAGE_URI') or 'memory://'
    # Configurazione per Flask-Mail
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.googlemail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME') # Es: la-tua-email@gmail.com
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') # La password della tua email o una password per app
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', MAIL_USERNAME)

    # Configurazione per reCAPTCHA
    RECAPTCHA_PUBLIC_KEY = os.environ.get('RECAPTCHA_PUBLIC_KEY') # La tua Site Key
    RECAPTCHA_PRIVATE_KEY = os.environ.get('RECAPTCHA_SECRET_KEY') # La tua Secret Key
    RECAPTCHA_PARAMETERS = {'hl': 'it'}

    # Rate limiting storage backend (Flask-Limiter)
    # Examples: 'redis://localhost:6379', 'memcached://localhost:11211'
    # (già definito sopra con fallback a 'memory://')

    # Cookie di sessione custom per enforcement revoche
    SESSION_TOKEN_COOKIE_NAME = os.environ.get('SESSION_TOKEN_COOKIE_NAME', 'session_token')
    SESSION_TOKEN_COOKIE_SECURE = os.environ.get('SESSION_TOKEN_COOKIE_SECURE', 'false').lower() in ['true', 'on', '1']
    SESSION_TOKEN_COOKIE_SAMESITE = os.environ.get('SESSION_TOKEN_COOKIE_SAMESITE', 'Lax')
    SESSION_TOKEN_COOKIE_HTTPONLY = True
    SESSION_TOKEN_COOKIE_MAX_AGE = int(os.environ.get('SESSION_TOKEN_COOKIE_MAX_AGE', 60*60*24*30))  # 30 giorni

    # Allinea anche i cookie nativi di Flask
    SESSION_COOKIE_SECURE = SESSION_TOKEN_COOKIE_SECURE
    REMEMBER_COOKIE_SECURE = SESSION_TOKEN_COOKIE_SECURE
    SESSION_COOKIE_SAMESITE = os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax')

    # HTTPS/HSTS (abilitare in produzione)
    FORCE_HTTPS = os.environ.get('FORCE_HTTPS', 'false').lower() in ['true', 'on', '1']
    HSTS_ENABLED = os.environ.get('HSTS_ENABLED', 'false').lower() in ['true', 'on', '1']
    HSTS_MAX_AGE = int(os.environ.get('HSTS_MAX_AGE', 31536000))  # 1 anno
