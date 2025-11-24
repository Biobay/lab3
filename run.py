from app import create_app, db
from app.models import User

from dotenv import load_dotenv

load_dotenv()

app = create_app()

@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User}

# Comandi CLI per la gestione degli utenti
import click

@app.cli.command("list-users")
def list_users():
    """Mostra tutti gli utenti nel database."""
    users = User.query.all()
    if not users:
        print("Nessun utente trovato nel database.")
        return
    click.echo("--- Lista Utenti ---")
    for user in users:
        status = "Attivo" if user.is_active else "Non Attivo"
        click.echo(f"ID: {user.id}, Email: {user.email}, Nome: {user.nome}, Stato: {status}")
    click.echo("--------------------")

@app.cli.command("delete-user")
@click.argument("email")
def delete_user(email):
    """Cancella un utente tramite la sua email."""
    user = User.query.filter_by(email=email).first()
    if user:
        if click.confirm(f"Sei sicuro di voler eliminare l'utente {user.email}?", abort=True):
            db.session.delete(user)
            db.session.commit()
            click.echo(f"Utente {email} cancellato con successo.")
    else:
        click.echo(f"Errore: Utente con email {email} non trovato.")

@app.cli.command("delete-all-users")
def delete_all_users():
    """Cancella TUTTI gli utenti dal database."""
    if click.confirm("ATTENZIONE: Stai per cancellare tutti gli utenti. Questa azione è irreversibile. Sei sicuro?", abort=True):
        num_rows_deleted = db.session.query(User).delete()
        db.session.commit()
        click.echo(f"{num_rows_deleted} utenti sono stati cancellati.")
