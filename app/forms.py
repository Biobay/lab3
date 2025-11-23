from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Regexp

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
    submit = SubmitField('Registrati')
