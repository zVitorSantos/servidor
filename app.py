from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = '1234'  # Para usar sessões, é preciso de uma chave secreta

# Banco de dados fictício
users_db = []

@app.route('/')
def main():
    return render_template('main.html')

def get_user_by_email_or_username(email_or_username):
    conn = sqlite3.connect('database/users.db')
    cursor = conn.cursor()
    cursor.execute("""
    SELECT * FROM users WHERE username=? OR email=?
    """, (email_or_username, email_or_username))
    user = cursor.fetchone()
    conn.close()
    return user

def check_credentials(username_or_email, password):
    user = get_user_by_email_or_username(username_or_email)
    if user and check_password_hash(user[4], password):  
        return True
    return False

def register_user(name, username, email, password):
    try:
        hashed_password = generate_password_hash(password)
        conn = sqlite3.connect('database/users.db')
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO users (name, username, email, password) VALUES (?, ?, ?, ?)
        """, (name, username, email, hashed_password))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False

@app.route('/login', methods=['POST'])
def login():
    email_or_username = request.form.get('loginName')
    password = request.form.get('loginPassword')

    if check_credentials(email_or_username, password):
        session['user_id'] = email_or_username 
        return redirect(url_for('main'))
    else:
        flash('Credenciais inválidas. Por favor, tente novamente.')
        return redirect(url_for('main'))

@app.route('/register', methods=['POST'])
def register():
    name = request.form.get('registerName')
    username = request.form.get('registerUsername')
    email = request.form.get('registerEmail')
    password = request.form.get('registerPassword')
    repeat_password = request.form.get('registerRepeatPassword')

    if password != repeat_password:
        flash('As senhas não coincidem. Por favor, tente novamente.')
        return redirect(url_for('main'))

    existing_user = get_user_by_email_or_username(email)
    if existing_user:
        flash('Um usuário com esse email já está registrado.')
        return redirect(url_for('main'))

    register_user(name, username, email, password)
    flash('Registro bem-sucedido! Agora você pode fazer login.')
    return redirect(url_for('main'))

if __name__ == '__main__':
    app.run(debug=True)
