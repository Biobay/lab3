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
    RATELIMIT_STORAGE_URI = os.environ.get('RATELIMIT_STORAGE_URI')
