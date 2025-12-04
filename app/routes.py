"""
Definizione delle route e della logica di visualizzazione (view).

Questo file mappa gli URL alle funzioni Python (view functions). Quando un utente
visita un URL, la funzione associata viene eseguita. Contiene la logica
principale dell'applicazione, come la gestione della registrazione, del login,
dell'attivazione dell'account e la visualizzazione delle pagine.
"""

from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, session
import secrets
from app import db
from app.models import User, Session, LoginChallenge
from app.security import log_security_event
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
                log_security_event(
                    event_type='registration_success',
                    user_id=user.id,
                    message='User registered and activation email sent',
                    ip_address=get_remote_address(),
                    user_agent=request.headers.get('User-Agent','')
                )
                db.session.commit()
                flash('Un link di attivazione è stato inviato alla tua email.', 'info')
                return redirect(url_for('main.login'))
            except Exception as e:
                
                db.session.rollback()
                current_app.logger.error(f"Errore nell'invio dell'email di attivazione: {e}")
                flash('Si è verificato un errore durante la registrazione. Impossibile inviare l\'email di attivazione.', 'danger')

        except IntegrityError:
            db.session.rollback()
            log_security_event(
                event_type='registration_conflict',
                user_id=None,
                message='Duplicate email/codice_fiscale/telefono during registration',
                ip_address=get_remote_address(),
                user_agent=request.headers.get('User-Agent','')
            )
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
                log_security_event(
                    event_type='account_locked',
                    user_id=user.id,
                    message='Login attempted while account locked',
                    ip_address=get_remote_address(),
                    user_agent=request.headers.get('User-Agent','')
                )
                return render_template('login.html', title='Accesso', form=form)
        if user and user.check_password(form.password.data):
            if user.is_active:
                # 2FA: genera codice e invia email, salva pre-auth in sessione, mostra pagina MFA
                code = f"{secrets.randbelow(1000000):06d}"
                challenge = LoginChallenge.new_for(user.id, code, ttl_minutes=10)
                try:
                    from app.email import send_mfa_code_email
                    send_mfa_code_email(user, code)
                except Exception as e:
                    current_app.logger.error(f"Errore invio codice MFA: {e}")
                log_security_event(
                    event_type='mfa_code_sent',
                    user_id=user.id,
                    message='MFA code generated and sent via email',
                    ip_address=get_remote_address(),
                    user_agent=request.headers.get('User-Agent','')
                )
                db.session.commit()
                # salva l'utente pre-autenticato nella sessione server-side
                session['preauth_user_id'] = user.id
                # Mostra direttamente la pagina per inserire il codice
                flash('Ti abbiamo inviato un codice di sicurezza via email. Inseriscilo qui sotto per accedere.', 'info')
                return render_template('mfa.html', title='Verifica codice', user_id=user.id)
            else:
                flash('Il tuo account non è ancora stato attivato. Controlla la console per il link di attivazione.', 'warning')
        else:
            if user:
                user.register_failed_login(max_attempts=5, lock_minutes=15)
                db.session.commit()
                log_security_event(
                    event_type='login_failed',
                    user_id=user.id,
                    message='Invalid password',
                    ip_address=get_remote_address(),
                    user_agent=request.headers.get('User-Agent','')
                )
            flash('Accesso non riuscito. Controlla email e password.', 'danger')
    return render_template('login.html', title='Accesso', form=form)

@main.route('/mfa', methods=['GET', 'POST'])
def mfa():
    # prendi l'utente pre-autenticato dalla sessione
    user_id = session.get('preauth_user_id') or request.args.get('user_id', type=int) or request.form.get('user_id', type=int)
    if not user_id:
        flash('Sessione MFA non valida.', 'danger')
        return redirect(url_for('main.login'))
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        challenge = LoginChallenge.query.filter_by(user_id=user_id, consumed=False).order_by(LoginChallenge.expires_at.desc()).first()
        if not challenge or challenge.is_expired():
            flash('Codice scaduto o non valido. Richiedi un nuovo accesso.', 'danger')
            log_security_event(
                event_type='mfa_invalid_or_expired',
                user_id=user_id,
                message='MFA code invalid or expired',
                ip_address=get_remote_address(),
                user_agent=request.headers.get('User-Agent','')
            )
            return redirect(url_for('main.login'))
        challenge.register_attempt()
        if challenge.attempts > 5:
            flash('Troppi tentativi. Riprova più tardi.', 'warning')
            db.session.commit()
            return redirect(url_for('main.login'))
        if code == challenge.code:
            challenge.consume()
            # esegui login e crea sessione tracciata
            user = User.query.get(user_id)
            login_user(user, remember=True, fresh=True)
            token = secrets.token_urlsafe(32)
            Session.new(
                user_id=user.id,
                token=token,
                user_agent=request.headers.get('User-Agent', ''),
                ip=get_remote_address()
            )
            user.reset_login_lock()
            # pulisci stato pre-auth dalla sessione
            session.pop('preauth_user_id', None)
            db.session.commit()
            flash('Accesso verificato.', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            db.session.commit()
            flash('Codice non corretto.', 'danger')
            log_security_event(
                event_type='mfa_failure',
                user_id=user_id,
                message='Incorrect MFA code',
                ip_address=get_remote_address(),
                user_agent=request.headers.get('User-Agent','')
            )
            return render_template('mfa.html', title='Verifica codice', user_id=user_id)
    return render_template('mfa.html', title='Verifica codice', user_id=user_id)

@main.route('/mfa/resend', methods=['POST'])
def mfa_resend():
    user_id = session.get('preauth_user_id')
    if not user_id:
        flash('Sessione MFA non valida.', 'danger')
        return redirect(url_for('main.login'))
    user = User.query.get(user_id)
    code = f"{secrets.randbelow(1000000):06d}"
    LoginChallenge.new_for(user.id, code, ttl_minutes=10)
    try:
        from app.email import send_mfa_code_email
        send_mfa_code_email(user, code)
    except Exception as e:
        current_app.logger.error(f"Errore reinvio codice MFA: {e}")
    db.session.commit()
    log_security_event(
        event_type='mfa_code_resent',
        user_id=user.id,
        message='MFA code resent',
        ip_address=get_remote_address(),
        user_agent=request.headers.get('User-Agent','')
    )
    flash('Nuovo codice inviato.', 'info')
    return render_template('mfa.html', title='Verifica codice', user_id=user.id)

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
    log_security_event(
        event_type='logout',
        user_id=current_user.id,
        message='User logged out',
        ip_address=get_remote_address(),
        user_agent=request.headers.get('User-Agent','')
    )
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
        log_security_event(
            event_type='account_activated',
            user_id=user.id,
            message='Account activated via token',
            ip_address=get_remote_address(),
            user_agent=request.headers.get('User-Agent','')
        )
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
            log_security_event(
                event_type='password_reset_unknown_email',
                user_id=None,
                message='Password reset requested for unknown email',
                ip_address=get_remote_address(),
                user_agent=request.headers.get('User-Agent','')
            )
            flash('Se l\'email è registrata, riceverai un messaggio con le istruzioni.', 'info')
            return redirect(url_for('main.login'))
    return render_template('forgot_password.html', title='Password dimenticata', form=form)

@main.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.verify_reset_token(token)
    if not user:
        flash('Il link di reset non è valido o è scaduto.', 'danger')
        log_security_event(
            event_type='password_reset_invalid_token',
            user_id=None,
            message='Invalid or expired password reset token',
            ip_address=get_remote_address(),
            user_agent=request.headers.get('User-Agent','')
        )
        return redirect(url_for('main.forgot_password'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        log_security_event(
            event_type='password_reset_success',
            user_id=user.id,
            message='Password reset successful',
            ip_address=get_remote_address(),
            user_agent=request.headers.get('User-Agent','')
        )
        flash('La tua password è stata aggiornata. Ora puoi effettuare il login.', 'success')
        return redirect(url_for('main.login'))
    return render_template('reset_password.html', title='Reset Password', form=form)
