"""
Definizione delle route e della logica di visualizzazione (view).

Questo file mappa gli URL alle funzioni Python (view functions). Quando un utente
visita un URL, la funzione associata viene eseguita. Contiene la logica
principale dell'applicazione, come la gestione della registrazione, del login,
dell'attivazione dell'account e la visualizzazione delle pagine.
"""

from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from app import db
from app.models import User, Session
from app.forms import RegistrationForm, LoginForm, RequestResetForm, ResetPasswordForm
from app.email import send_activation_email, send_reset_password_email
from sqlalchemy.exc import IntegrityError
from flask_login import login_user, logout_user, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

main = Blueprint('main', __name__)

# Attach per-route limits via decorator using the app-level limiter
try:
    limiter = Limiter(key_func=get_remote_address)
except Exception:
    limiter = None

def session_key_func():
    # Preferisci email se presente, altrimenti IP
    return request.form.get('email') or get_remote_address()

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
@limiter.limit("10 per minute; 100 per hour", key_func=session_key_func) if limiter else (lambda f: f)
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    form = LoginForm() # convalida del CSRF inclusa
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            # Check account lock
            if user.is_locked():
                flash('Account temporaneamente bloccato per troppi tentativi. Riprova più tardi.', 'warning')
                return render_template('login.html', title='Accesso', form=form)
        if user and user.check_password(form.password.data):
            if user.is_active:
                login_user(user, remember=form.remember_me.data)
                # crea una sessione tracciata
                token = secrets.token_urlsafe(32)
                sess = Session.new(
                    user_id=user.id,
                    token=token,
                    user_agent=request.headers.get('User-Agent', ''),
                    ip=get_remote_address()
                )
                db.session.commit()
                user.reset_login_lock()
                db.session.commit()
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('main.dashboard'))
            else:
                flash('Il tuo account non è ancora stato attivato. Controlla la console per il link di attivazione.', 'warning')
        else:
            if user:
                user.register_failed_login(max_attempts=5, lock_minutes=15)
                db.session.commit()
            flash('Accesso non riuscito. Controlla email e password.', 'danger')
    return render_template('login.html', title='Accesso', form=form)

@main.route('/logout')
@login_required
def logout():
    # revoca la sessione corrente se presente via header token
    token = request.headers.get('X-Session-Token')
    if token:
        s = Session.query.filter_by(session_token=token, user_id=current_user.id, active=True).first()
        if s:
            s.revoke()
            db.session.commit()
    logout_user()
    flash('Sei stato disconnesso.', 'success')
    return redirect(url_for('main.login'))

@main.route('/dashboard')
@login_required
def dashboard():
    # aggiorna last_seen della sessione corrente se token presente
    token = request.headers.get('X-Session-Token')
    if token:
        s = Session.query.filter_by(session_token=token, user_id=current_user.id, active=True).first()
        if s:
            s.touch()
            db.session.commit()
    return render_template('dashboard.html', title='Dashboard')

@main.route('/sessions')
@login_required
def sessions():
    items = Session.query.filter_by(user_id=current_user.id).order_by(Session.active.desc(), Session.last_seen.desc()).all()
    return render_template('sessions.html', title='Le mie sessioni', sessions=items)

@main.route('/sessions/revoke', methods=['POST'])
@login_required
def revoke_session():
    token = request.form.get('token')
    s = Session.query.filter_by(session_token=token, user_id=current_user.id, active=True).first()
    if s:
        s.revoke()
        db.session.commit()
        flash('Sessione revocata.', 'success')
    else:
        flash('Sessione non trovata o già revocata.', 'warning')
    return redirect(url_for('main.sessions'))

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

@main.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("3 per 10 minutes") if limiter else (lambda f: f)
def forgot_password():
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            try:
                send_reset_password_email(user)
                flash('Ti abbiamo inviato un email con le istruzioni per resettare la password.', 'info')
                return redirect(url_for('main.login'))
            except Exception as e:
                current_app.logger.error(f"Errore invio email reset: {e}")
                flash('Impossibile inviare l\'email di reset in questo momento.', 'danger')
        else:
            # In caso di email non trovata, manteniamo risposta generica per sicurezza
            flash('Se l\'email è registrata, riceverai un messaggio con le istruzioni.', 'info')
            return redirect(url_for('main.login'))
    return render_template('forgot_password.html', title='Password dimenticata', form=form)

@main.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.verify_reset_token(token)
    if not user:
        flash('Il link di reset non è valido o è scaduto.', 'danger')
        return redirect(url_for('main.forgot_password'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('La tua password è stata aggiornata. Ora puoi effettuare il login.', 'success')
        return redirect(url_for('main.login'))
    return render_template('reset_password.html', title='Reset Password', form=form)
