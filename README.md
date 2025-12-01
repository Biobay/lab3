# Banking Dispute Resolution Platform - Secure Registration Form

This project is a Flask web application that implements a secure user registration form.

## Features

- User registration with first name, last name, email, tax code, and phone number.
- Advanced password validation (minimum length, uppercase/lowercase characters, numbers, symbols).
- Password hashing using Argon2.
- Prevention of user enumeration via generic error messages.
- Account activation via a unique link.
- Simulation of email sending: the activation link is printed to the server console.

## Prerequisites

- Python 3.6+
- `pip` and `venv`

## Setup and Installation

1. **Clone the repository (or download the files):**
```bash
git clone <URL_OF_YOUR_REPOSITORY>
cd <FOLDER_NAME>
```

2. **Create and activate a virtual environment:**
This isolates the project's dependencies.

* On macOS/Linux:
```bash
python3 -m venv venv
source venv/bin/activate
```
* On Windows:
```bash
python -m venv venv
.\venv\Scripts\activate
```
After activation, your command prompt should display `(venv)`.

3. **Install dependencies:**
Make sure your virtual environment is running, then run:
```bash
pip install -r requirements.txt
```

4. **Initialize the database:**
This command creates the database file (`app.db`) and the necessary tables.
```bash
python3 init_db.py
```
You should see the message "Database initialized!".

## Running the Application

1. **Start the Flask development server:**
Make sure your virtual environment is still running.
```bash
flask run
```
*Alternatively:*
```bash
python -m flask run
```

2. **Access the application:**
Open your web browser and go to:
[http://127.0.0.1:5000/register](http://127.0.0.1:5000/register)

## How it works

1. **Registration:** Fill out the registration form. If the data is valid, the user is created in the database with the status `is_active = False`.
2. **Activation:**
* The system generates a unique activation link.
* **Instead of sending an email**, the link is printed to the console where you started the server (`flask run`).
* Copy and paste that link into your browser.
3. **Account Activated:** The account is marked as `is_active = True` and you can log in (in a future implementation).

## Viewing the Database

To inspect registered users, you can use the VS Code extension "SQLite" (by alexcvzz) to open and view the `instance/app.db` file.
