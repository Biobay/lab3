# Piattaforma di Risoluzione Controversie Bancarie - Modulo di Registrazione Sicura

Questo progetto è un'applicazione web Flask che implementa un modulo di registrazione utente sicuro.

## Funzionalità

- Registrazione Utente con nome, cognome, email, codice fiscale e telefono.
- Validazione avanzata della password (lunghezza minima, caratteri maiuscoli/minuscoli, numeri, simboli).
- Hashing delle password utilizzando Argon2.
- Prevenzione della User Enumeration tramite messaggi di errore generici.
- Attivazione dell'account tramite un link univoco.
- Simulazione dell'invio di email: il link di attivazione viene stampato sulla console del server.

## Prerequisiti

- Python 3.6+
- `pip` e `venv`

## Setup e Installazione

1.  **Clonare il repository (o scaricare i file):**
    ```bash
    git clone <URL_DEL_TUO_REPOSITORY>
    cd <NOME_DELLA_CARTELLA>
    ```

2.  **Creare e attivare un ambiente virtuale:**
    Questo isola le dipendenze del progetto.

    *   Su macOS/Linux:
        ```bash
        python3 -m venv venv
        source venv/bin/activate
        ```
    *   Su Windows:
        ```bash
        python -m venv venv
        .\venv\Scripts\activate
        ```
    Dopo l'attivazione, il tuo prompt dei comandi dovrebbe mostrare `(venv)`.

3.  **Installare le dipendenze:**
    Assicurati che il tuo ambiente virtuale sia attivo, quindi esegui:
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configurare variabili ambiente (.env):**
    Copia `.env.example` in `.env` e modifica i valori necessari (chiavi email, rate limiting, ecc.).
    ```bash
    cp .env.example .env
    ```

5.  **Inizializzare il database:**
    Questo comando crea il file del database (`app.db`) e le tabelle necessarie.
    ```bash
    python3 init_db.py
    ```
    Dovresti vedere il messaggio "Database initialized!".

### Rate Limiting (Flask-Limiter)

- In sviluppo, il progetto usa lo storage in memoria (`memory://`).
- In produzione si consiglia un backend persistente (es. Redis).

Per usare Redis:
```bash
pip install redis
# Avvia un server Redis locale o usa un endpoint gestito
# Imposta l'URI di storage nel tuo .env
echo "RATELIMIT_STORAGE_URI=redis://localhost:6379" >> .env
```

## Esecuzione dell'Applicazione

1.  **Avviare il server di sviluppo Flask:**
    Assicurati che il tuo ambiente virtuale sia ancora attivo.
    ```bash
    flask run
    ```
    *In alternativa:*
    ```bash
    python -m flask run
    ```

2.  **Accedere all'applicazione:**
    Apri il tuo browser web e vai all'indirizzo:
    [http://127.0.0.1:5000/register](http://127.0.0.1:5000/register)

## Come funziona

1.  **Registrazione:** Compila il modulo di registrazione. Se i dati sono validi, l'utente viene creato nel database con lo stato `is_active = False`.
2.  **Attivazione:**
    *   Il sistema genera un link di attivazione univoco.
    *   **Invece di inviare un'email**, il link viene stampato sulla console dove hai avviato il server (`flask run`).
    *   Copia e incolla quel link nel tuo browser.
3.  **Account Attivato:** L'account viene contrassegnato come `is_active = True` e puoi (in una futura implementazione) effettuare il login.

## Visualizzare il Database

Per ispezionare gli utenti registrati, puoi usare l'estensione di VS Code "SQLite" (di alexcvzz) per aprire e visualizzare il file `instance/app.db`.
