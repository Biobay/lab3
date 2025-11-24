from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from app import db
from app.models import User
from app.forms import RegistrationForm, LoginForm
from app.email import send_activation_email
from sqlalchemy.exc import IntegrityError
from flask_login import login_user, logout_user, login_required, current_user

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return redirect(url_for('main.dashboard'))

@main.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            user = User(
                nome=form.nome.data,
                cognome=form.cognome.data,
                email=form.email.data,
                codice_fiscale=form.codice_fiscale.data,
                telefono=form.telefono.data
            )
            user.set_password(form.password.data)
            user.generate_activation_token()
            
            db.session.add(user)
            
            try:
                db.session.flush()
                send_activation_email(user)
                db.session.commit()
                flash('Un link di attivazione è stato inviato alla tua email.', 'info')
                return redirect(url_for('main.login'))
            except Exception as e:
                db.session.rollback()
                current_app.logger.error(f"Errore nell'invio dell'email di attivazione: {e}")
                flash('Si è verificato un errore durante la registrazione. Impossibile inviare l\'email di attivazione.', 'danger')

        except IntegrityError:
            db.session.rollback()
            flash('Errore: Email, codice fiscale o numero di telefono già registrati.', 'danger')
            
    return render_template('register.html', title='Registrazione', form=form)

@main.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            if user.is_active:
                login_user(user, remember=form.remember_me.data)
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('main.dashboard'))
            else:
                flash('Il tuo account non è ancora stato attivato. Controlla la console per il link di attivazione.', 'warning')
        else:
            flash('Accesso non riuscito. Controlla email e password.', 'danger')
    return render_template('login.html', title='Accesso', form=form)

@main.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Sei stato disconnesso.', 'success')
    return redirect(url_for('main.login'))

@main.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', title='Dashboard')

@main.route('/activate/<token>')
def activate(token):
    user = User.query.filter_by(activation_token=token).first()
    if user:
        user.is_active = True
        user.activation_token = None
        db.session.commit()
        flash('Il tuo account è stato attivato! Ora puoi effettuare il login.', 'success')
        return redirect(url_for('main.login'))
    else:
        flash('Link di attivazione non valido o scaduto.', 'danger')
        return redirect(url_for('main.register'))
