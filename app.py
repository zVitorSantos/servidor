from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = '1234'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.abspath('database/users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    username = db.Column(db.String(80), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(120), nullable=False)
    approved = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<User {self.username}>'

def get_user_by_email_or_username(email_or_username):
    user = User.query.filter((User.username == email_or_username) | (User.email == email_or_username)).first()
    return user

def check_credentials(username_or_email, password):
    user = get_user_by_email_or_username(username_or_email)
    if user and check_password_hash(user.password, password):
        return True
    return False

def register_user(name, username, email, password):
    try:
        hashed_password = generate_password_hash(password)
        user = User(name=name, username=username, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        return user.id
    except Exception as e:
        db.session.rollback()
        return None

# Função decoradora para verificar se o usuário está logado
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('main'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def main():
    if 'user_id' in session:
        return redirect(url_for('app_main'))
    else:
        return redirect(url_for('login_page'))

@app.route('/app')
@login_required
def app_main():
    return render_template('app.html')

@app.route('/login_page')
def login_page():
    return render_template('main.html')

# Função de login
@app.route('/login', methods=['POST'])
def login():
    email_or_username = request.form.get('loginName')
    password = request.form.get('loginPassword')

    user = get_user_by_email_or_username(email_or_username)
    if user is None:
        flash('Email ou Usuário não cadastrado', 'error')
        return redirect(url_for('login_page'))

    if check_credentials(email_or_username, password):
        session['user_id'] = email_or_username
        return redirect(url_for('app_main'))
    else:
        flash('Credenciais inválidas. Por favor, tente novamente.', 'error')
        return redirect(url_for('login_page'))

if __name__ == '__main__':
    app.run(debug=True)