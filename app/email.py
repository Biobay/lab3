"""
Modulo per la gestione e l'invio di email.

Questo file contiene le funzioni ausiliarie per l'invio di email dall'applicazione,
come l'email di attivazione dell'account. L'invio viene eseguito in un thread
separato per non bloccare la richiesta principale e migliorare la reattività
dell'applicazione.
"""

from flask import render_template, url_for, current_app
from flask_mail import Message
from app import mail
from threading import Thread

def send_async_email(app, msg):
    with app.app_context():
        try:
            mail.send(msg)
        except Exception as e:
            app.logger.error(f"Errore durante l'invio dell'email nel thread: {e}")

def send_email(subject, recipients, text_body, html_body):
    app = current_app._get_current_object()
    # Assicurati che MAIL_DEFAULT_SENDER sia configurato
    sender = app.config.get('MAIL_DEFAULT_SENDER')
    if not sender:
        raise ValueError("MAIL_DEFAULT_SENDER non è configurato.")
    msg = Message(subject, sender=sender, recipients=recipients)
    msg.body = text_body
    msg.html = html_body
    Thread(target=send_async_email, args=(app, msg)).start()

def send_activation_email(user):
    token = user.activation_token
    activation_link = url_for('main.activate', token=token, _external=True)
    send_email('Attiva il tuo account per la Banca Sicura',
               recipients=[user.email],
               text_body=render_template('email/activation.txt', user=user, activation_link=activation_link),
               html_body=render_template('email/activation.html', user=user, activation_link=activation_link))

def send_reset_password_email(user):
    token = user.get_reset_token()
    reset_link = url_for('main.reset_password', token=token, _external=True)
    send_email('Reset della tua password',
               recipients=[user.email],
               text_body=render_template('email/reset_password.txt', user=user, reset_link=reset_link),
               html_body=render_template('email/reset_password.html', user=user, reset_link=reset_link))
