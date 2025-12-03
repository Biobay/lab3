"""
Script per l'inizializzazione del database.

Questo script, se eseguito, crea il database e tutte le tabelle definite
nei modelli SQLAlchemy. Va eseguito una sola volta per creare lo schema
iniziale o per ricrearlo da zero dopo aver cancellato il file del database.
"""

from app import create_app, db

app = create_app()

with app.app_context():
    db.create_all()
    print("Database initialized!")
