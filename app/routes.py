from flask import Blueprint, render_template, redirect, url_for, flash, request
from app import db
from app.models import User
from app.forms import RegistrationForm
from sqlalchemy.exc import IntegrityError

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return redirect(url_for('main.register'))

@main.route('/register', methods=['GET', 'POST'])
def register():
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
            db.session.commit()

            # Simulazione invio email
            activation_link = url_for('main.activate', token=user.activation_token, _external=True)
            print("--- SIMULAZIONE INVIO EMAIL ---")
            print(f"Ciao {user.nome},")
            print("Grazie per esserti registrato. Per attivare il tuo account, clicca sul seguente link:")
            print(activation_link)
            print("-----------------------------")

            flash('Registrazione avvenuta con successo! Controlla la console per il link di attivazione.', 'success')
            return redirect(url_for('main.register'))
        except IntegrityError:
            db.session.rollback()
            flash('Errore durante la registrazione. Riprova.', 'danger')
    return render_template('register.html', title='Registrazione', form=form)

@main.route('/activate/<token>')
def activate(token):
    user = User.query.filter_by(activation_token=token).first()
    if user:
        user.is_active = True
        user.activation_token = None  # Il token può essere usato solo una volta
        db.session.commit()
        flash('Il tuo account è stato attivato! Ora puoi effettuare il login.', 'success')
        return redirect(url_for('main.register')) # O una pagina di login
    else:
        flash('Link di attivazione non valido o scaduto.', 'danger')
        return redirect(url_for('main.register'))
