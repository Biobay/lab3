"""
Definizione delle route e della logica di visualizzazione (view).

Questo file mappa gli URL alle funzioni Python (view functions). Quando un utente
visita un URL, la funzione associata viene eseguita. Contiene la logica
principale dell'applicazione, come la gestione della registrazione, del login,
dell'attivazione dell'account e la visualizzazione delle pagine.
"""

from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, session, abort
import os
import secrets
from werkzeug.utils import secure_filename
from app import db
from app.models import User, Session, LoginChallenge, Post, Comment, Rating
from app.security import log_security_event
from app.forms import (
    RegistrationForm,
    LoginForm,
    RequestResetForm,
    ResetPasswordForm,
    PostForm,
    CommentForm,
    RatingForm,
    SearchForm,
    AdminCodeForm,
)
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


def user_or_ip_key_func():
    """Usa l'ID utente se autenticato, altrimenti IP remoto.

    Utile per rate limiting di azioni autenticate come creazione post/commenti.
    """
    if current_user.is_authenticated:
        return str(current_user.id)
    return get_remote_address()

@main.route('/', methods=['GET'])
def index():
    """Homepage pubblica: lista dei post più recenti con ricerca semplice."""
    form = SearchForm(request.args)
    query = Post.query.filter_by(is_public=True).order_by(Post.created_at.desc())
    if form.validate():
        q = (form.q.data or '').strip()
        if q:
            like = f"%{q}%"
            query = query.filter((Post.title.ilike(like)) | (Post.body.ilike(like)))
    posts = query.all()
    return render_template('posts.html', title='Blog', posts=posts, search_form=form)

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
                # Reset failed login attempts on successful password verification
                user.reset_login_lock()
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


# per gestire la verifica MFA
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
            # imposta cookie session_token sicuro
            cookie_name = current_app.config.get('SESSION_TOKEN_COOKIE_NAME', 'session_token')
            resp = redirect(url_for('main.dashboard'))
            resp.set_cookie(
                cookie_name,
                token,
                max_age=current_app.config.get('SESSION_TOKEN_COOKIE_MAX_AGE', 60*60*24*30),
                httponly=current_app.config.get('SESSION_TOKEN_COOKIE_HTTPONLY', True),
                secure=current_app.config.get('SESSION_TOKEN_COOKIE_SECURE', False),
                samesite=current_app.config.get('SESSION_TOKEN_COOKIE_SAMESITE', 'Lax'),
                path='/'
            )
            return resp
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
    # revoca la sessione corrente se presente (preferisci cookie rispetto all'header)
    cookie_name = current_app.config.get('SESSION_TOKEN_COOKIE_NAME', 'session_token')
    token = request.cookies.get(cookie_name) or request.headers.get('X-Session-Token')
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
    resp = redirect(url_for('main.login'))
    try:
        resp.delete_cookie(cookie_name, path='/')
    except Exception:
        pass
    return resp

@main.route('/dashboard')
@login_required
def dashboard():
    # l'aggiornamento last_seen è gestito dal before_request globale
    return render_template('dashboard.html', title='Dashboard')


@main.route('/become-admin', methods=['GET', 'POST'])
@login_required
def become_admin():
    form = AdminCodeForm()
    if form.validate_on_submit():
        if form.code.data == '666666':
            current_user.role = 'admin'
            db.session.commit()
            flash('Ora sei amministratore!', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Codice errato.', 'danger')
    return render_template('become_admin.html', title='Diventa amministratore', form=form)


@main.route('/posts')
def posts_list():
    """Alias esplicito per la lista dei post (uguale a index)."""
    return index()


@main.route('/posts/new', methods=['GET', 'POST'])
@login_required
@limiter.limit("5 per minute; 100 per day", key_func=user_or_ip_key_func) if limiter else (lambda f: f)
def create_post():
    form = PostForm()
    if form.validate_on_submit():
        image_filename = None
        file = form.image.data
        if file:
            allowed_exts = current_app.config.get('ALLOWED_UPLOAD_EXTENSIONS', {"jpg", "jpeg", "png", "gif"})
            filename = secure_filename(file.filename or '')
            ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
            if not filename or ext not in allowed_exts:
                flash('Estensione file non permessa.', 'danger')
                return render_template('create_post.html', title='Nuovo post', form=form)
            upload_folder = current_app.config.get('UPLOAD_FOLDER')
            os.makedirs(upload_folder, exist_ok=True)
            image_filename = f"{secrets.token_hex(8)}_{filename}"
            file.save(os.path.join(upload_folder, image_filename))

        post = Post(
            title=form.title.data,
            body=form.body.data,
            image_filename=image_filename,
            author_id=current_user.id,
            is_public=True,
        )
        db.session.add(post)
        db.session.commit()
        log_security_event(
            event_type='post_created',
            user_id=current_user.id,
            message=f'Post {post.id} created',
            ip_address=get_remote_address(),
            user_agent=request.headers.get('User-Agent', '')
        )
        flash('Post creato con successo.', 'success')
        return redirect(url_for('main.post_detail', post_id=post.id))
    return render_template('create_post.html', title='Nuovo post', form=form)


@main.route('/posts/<int:post_id>', methods=['GET', 'POST'])
def post_detail(post_id):
    post = Post.query.get_or_404(post_id)
    if not post.is_public and not current_user.is_authenticated:
        abort(403)
    comment_form = CommentForm()
    rating_form = RatingForm()
    if request.method == 'POST' and current_user.is_authenticated:
        # Distinguere quale form è stato inviato tramite nome del submit
        if 'comment_submit' in request.form and comment_form.validate_on_submit():
            comment = Comment(
                body=comment_form.body.data,
                author_id=current_user.id,
                post_id=post.id,
            )
            db.session.add(comment)
            db.session.commit()
            log_security_event(
                event_type='comment_created',
                user_id=current_user.id,
                message=f'Comment on post {post.id}',
                ip_address=get_remote_address(),
                user_agent=request.headers.get('User-Agent', '')
            )
            flash('Commento aggiunto.', 'success')
            return redirect(url_for('main.post_detail', post_id=post.id))
        elif 'rating_submit' in request.form and rating_form.validate_on_submit():
            rating = Rating.query.filter_by(user_id=current_user.id, post_id=post.id).first()
            if rating is None:
                rating = Rating(user_id=current_user.id, post_id=post.id, value=rating_form.value.data)
                db.session.add(rating)
            else:
                rating.value = rating_form.value.data
            db.session.commit()
            log_security_event(
                event_type='post_rated',
                user_id=current_user.id,
                message=f'Post {post.id} rated {rating_form.value.data}',
                ip_address=get_remote_address(),
                user_agent=request.headers.get('User-Agent', '')
            )
            flash('Voto registrato.', 'success')
            return redirect(url_for('main.post_detail', post_id=post.id))
    # calcolo rating medio
    avg_rating = None
    if post.ratings:
        avg_rating = sum(r.value for r in post.ratings) / len(post.ratings)
    return render_template('post_detail.html', title=post.title, post=post, comment_form=comment_form, rating_form=rating_form, avg_rating=avg_rating)


@main.route('/posts/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if not (current_user.is_admin or post.author_id == current_user.id):
        abort(403)
    db.session.delete(post)
    db.session.commit()
    log_security_event(
        event_type='post_deleted',
        user_id=current_user.id,
        message=f'Post {post.id} deleted',
        ip_address=get_remote_address(),
        user_agent=request.headers.get('User-Agent', '')
    )
    flash('Post eliminato.', 'success')
    return redirect(url_for('main.index'))


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
    # se stai revocando la sessione corrente, rimuovi anche il cookie
    cookie_name = current_app.config.get('SESSION_TOKEN_COOKIE_NAME', 'session_token')
    resp = redirect(url_for('main.sessions'))
    try:
        if token and request.cookies.get(cookie_name) == token:
            resp.delete_cookie(cookie_name, path='/')
    except Exception:
        pass
    return resp

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
