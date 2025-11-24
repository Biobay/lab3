from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from config import Config

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

    from app.routes import main
    app.register_blueprint(main)

    return app
