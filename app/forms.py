"""
Definizione dei form dell'applicazione.

Questo modulo utilizza la libreria Flask-WTF per definire i form web,
come il form di registrazione e di login. Ogni classe di form specifica
i campi, le etichette e i validatori necessari per la raccolta e la
validazione dei dati inviati dall'utente.
"""

from flask_wtf import FlaskForm, RecaptchaField
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField, ValidationError, TextAreaField, IntegerField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Regexp, NumberRange, Optional
from app.models import User

class RegistrationForm(FlaskForm):
    nome = StringField('Nome', validators=[DataRequired()])
    cognome = StringField('Cognome', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    codice_fiscale = StringField('Codice Fiscale', validators=[DataRequired(), Length(min=16, max=16)])
    telefono = StringField('Telefono', validators=[DataRequired()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=12, message="La password deve essere lunga almeno 12 caratteri."),
        Regexp(r'(?=.*[a-z])', message="La password deve contenere almeno una lettera minuscola."),
        Regexp(r'(?=.*[A-Z])', message="La password deve contenere almeno una lettera maiuscola."),
        Regexp(r'(?=.*\d)', message="La password deve contenere almeno un numero."),
        Regexp(r'(?=.*[@$!%*?&])', message="La password deve contenere almeno un carattere speciale (@$!%*?&).")
    ])
    confirm_password = PasswordField('Conferma Password', validators=[DataRequired(), EqualTo('password')])
    recaptcha = RecaptchaField()
    submit = SubmitField('Registrati')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Ricordami')
    recaptcha = RecaptchaField()
    submit = SubmitField('Accedi')

class RequestResetForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    recaptcha = RecaptchaField()
    submit = SubmitField('Richiedi Reset Password')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('Nessun account trovato con questa email. Devi prima registrarti.')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Nuova Password', validators=[
        DataRequired(),
        Length(min=12, message="La password deve essere lunga almeno 12 caratteri."),
        Regexp(r'(?=.*[a-z])', message="La password deve contenere almeno una lettera minuscola."),
        Regexp(r'(?=.*[A-Z])', message="La password deve contenere almeno una lettera maiuscola."),
        Regexp(r'(?=.*\d)', message="La password deve contenere almeno un numero."),
        Regexp(r'(?=.*[@$!%*?&])', message="La password deve contenere almeno un carattere speciale (@$!%*?&).")
    ])
    confirm_password = PasswordField('Conferma Nuova Password',
                                     validators=[DataRequired(), EqualTo('password', message='Le password devono corrispondere.')])
    submit = SubmitField('Resetta Password')


class PostForm(FlaskForm):
    title = StringField('Titolo', validators=[DataRequired(), Length(min=3, max=200)])
    body = TextAreaField('Contenuto', validators=[DataRequired(), Length(min=3)])
    image = FileField('Immagine (opzionale)', validators=[Optional(), FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Solo immagini sono permesse.')])
    submit = SubmitField('Pubblica post')


class CommentForm(FlaskForm):
    body = TextAreaField('Commento', validators=[DataRequired(), Length(min=1, max=1000)])
    submit = SubmitField('Aggiungi commento')


class RatingForm(FlaskForm):
    value = IntegerField('Voto (1-5)', validators=[DataRequired(), NumberRange(min=1, max=5)])
    submit = SubmitField('Vota')


class SearchForm(FlaskForm):
    q = StringField('Cerca', validators=[Optional(), Length(min=1, max=200)])
    submit = SubmitField('Cerca')


class AdminCodeForm(FlaskForm):
    code = StringField('Codice amministratore', validators=[DataRequired(), Length(min=1, max=32)])
    submit = SubmitField('Diventa amministratore')
