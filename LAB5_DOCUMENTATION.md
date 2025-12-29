# SecureMicroBlog - Documentazione di Progetto (Lab 5)

**Studente:** Mario Mastrulli  
**Matricola:** ER-2050  
**Corso:** Application Security – Laboratories  
**Data:** 28 Dicembre 2025

---

## 1. Introduzione
Questo documento costituisce la documentazione di design per il Laboratorio 5. L'obiettivo è estendere il sistema di autenticazione precedentemente sviluppato in un servizio web di contenuti (Microblog) applicando meccanismi di **sicurezza difensiva**. Il sistema si basa su attori distinti con privilegi gerarchici e gestisce contenuti generati dagli utenti, inclusi file multimediali, garantendo integrità, tracciabilità e protezione contro le vulnerabilità comuni del web (OWASP Top 10).

---

## 2. Architettura del Sistema

### 2.1 Stack Tecnologico
L'applicazione è sviluppata con il framework **Flask**, scelto per la sua modularità. La sicurezza è garantita dall'integrazione di:

*   **SQLAlchemy (ORM):** Per la prevenzione di SQL Injection tramite query parametrizzate.
*   **Argon2id:** Per l'hashing delle password resistente ad attacchi offline.
*   **Flask-WTF:** Per la gestione dei form con validazione server-side e protezione CSRF globale.
*   **Flask-Limiter:** Per mitigare attacchi di forza bruta e DoS applicativo su endpoint critici.

**Inizializzazione (`app/__init__.py`):**
```python
def create_app(config_class=Config):
    # ...
    db.init_app(app)
    login_manager.init_app(app)
    
    # Abilita CSRF globale per tutte le richieste/moduli
    CSRFProtect(app)

    # Rate limiting (optional if Flask-Limiter installed)
    if Limiter and get_remote_address:
        limiter = Limiter(
            key_func=get_remote_address,
            app=app,
            default_limits=["200 per day", "50 per hour"],
            storage_uri=storage_uri
        )
```

---

## 3. Struttura del Database
Le tabelle sono state progettate per supportare il **Role-Based Access Control (RBAC)** e la tracciabilità delle azioni.

### 3.1 Tabella `User`
Gestisce l'identità e i privilegi.

**Codice (`app/models.py`):**
```python
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user') # 'user' o 'admin'
    is_active = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = ph.hash(password) # Argon2id hashing
```
*   **Giustificazione:** `role` definisce i privilegi per RBAC. `password_hash` protegge le credenziali.

### 3.2 Tabella `Post`
Gestisce i contenuti generati dagli utenti.

**Codice (`app/models.py`):**
```python
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)
    image_filename = db.Column(db.String(255), nullable=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False) # Soft Delete
```
*   **Giustificazione:** `author_id` collega il contenuto all'autore per il controllo di proprietà. `image_filename` salva il nome del file sanitizzato.

### 3.3 Tabella `SecurityEvent`
Per l'Audit Logging e la tracciabilità.

**Codice (`app/models.py`):**
```python
class SecurityEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    event_type = db.Column(db.String(64), nullable=False)
    ip_address = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
```
*   **Giustificazione:** Permette di tracciare "chi ha fatto cosa e da dove", essenziale per l'analisi forense.

---

## 4. Flussi e Diagrammi di Sequenza (Implementazione)

### 4.1 Flusso: Creazione Post con Upload Immagine
Questo processo include la validazione del file, il controllo anti-spam e la protezione CSRF.

**Codice (`app/routes.py`):**
```python
@main.route("/post/new", methods=['GET', 'POST'])
@login_required
def create_post():
    form = PostForm()
    if form.validate_on_submit(): # Validazione CSRF e Input
        image_filename = None
        if form.image.data:
            file = form.image.data
            # Validazione Estensione (Whitelist)
            allowed_exts = current_app.config.get('ALLOWED_UPLOAD_EXTENSIONS', {"jpg", "jpeg", "png", "gif"})
            filename = secure_filename(file.filename or '')
            ext = filename.rsplit(' . ', 1)[-1].lower() if ' . ' in filename else ''
            
            if not filename or ext not in allowed_exts:
                flash('Estensione file non permessa.', 'danger')
                return render_template('create_post.html', title='Nuovo post', form=form)
            
            # Rinomina Randomica per Sicurezza
            image_filename = f"{secrets.token_hex(8)}_{filename}"
            file.save(os.path.join(upload_folder, image_filename))

        post = Post(..., image_filename=image_filename, author_id=current_user.id)
        db.session.add(post)
        db.session.commit()
        
        # Audit Log
        log_security_event(event_type='post_created', ...)
```

### 4.2 Flusso: Moderazione Amministrativa (Eliminazione)
Il sistema verifica i permessi prima di consentire l'eliminazione.

**Codice (`app/routes.py`):**
```python
@main.route('/posts/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    
    # Controllo RBAC: Solo Admin o Autore possono cancellare
    if not (current_user.is_admin or post.author_id == current_user.id):
        abort(403) # Forbidden
        
    # Soft Delete (o Hard Delete a seconda della configurazione)
    db.session.delete(post) 
    db.session.commit()
    
    # Audit Log
    log_security_event(event_type='post_deleted', user_id=current_user.id, ...)
```

---

## 5. Meccanismi di Sicurezza Applicati

### 5.1 Role-Based Access Control (RBAC)
Ogni rotta critica esegue un controllo lato server.
*   **Utenti:** Possono modificare/eliminare solo i propri contenuti (`post.author_id == current_user.id`).
*   **Admin:** Hanno privilegi globali (`current_user.is_admin`).

### 5.2 Protezione CSRF
Tutti i moduli (`PostForm`, `CommentForm`, `RatingForm`) ereditano da `FlaskForm` e includono automaticamente un token CSRF nascosto, validato da `form.validate_on_submit()`.

### 5.3 Sicurezza Upload
*   **Whitelist:** Solo estensioni permesse.
*   **Rinomina:** Uso di `secrets.token_hex(8)` per prevenire IDOR e sovrascritture.
*   **Path Traversal:** Uso di `secure_filename`.

### 5.4 Audit Logging
Ogni azione critica (login, creazione post, eliminazione) viene registrata nella tabella `SecurityEvent` per garantire la non-ripudiabilità.

---

## 6. Conclusioni e Funzionalità Opzionali

Il design del sistema è stato arricchito con componenti avanzati per elevare la postura di sicurezza:

### 6.1 Security Headers and Hardening
Implementazione di header HTTP di sicurezza per mitigare attacchi client-side.

**Codice (`app/__init__.py`):**
```python
@app.after_request
def _set_security_headers(response):
    # HSTS: Forza HTTPS
    if app.config.get('HSTS_ENABLED'):
         response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # X-Frame-Options: Previene Clickjacking
    response.headers.setdefault('X-Frame-Options', 'DENY')
    
    # X-Content-Type-Options: Previene MIME Sniffing
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    
    # CSP: Content Security Policy
    response.headers.setdefault('Content-Security-Policy', "default-src 'self'; ...")
    
    return response
```

### 6.2 Rate Limiting Granulare
Protezione specifica per endpoint sensibili.

**Codice (`app/routes.py`):**
```python
@main.route("/post/<int:post_id>/comment", methods=['POST'])
@limiter.limit("5 per minute") # Limite specifico per prevenire spam
def add_comment(post_id):
    # ...
```
