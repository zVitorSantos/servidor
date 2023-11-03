from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
from flask_login import UserMixin, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from datetime import timedelta
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
    is_admin = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<User {self.username}>'

def get_user_by_email_or_username(email_or_username):
    user = User.query.filter((User.username == email_or_username) | (User.email == email_or_username)).first()
    return user

def get_user_by_id(user_id):
    user = User.query.get(user_id)
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
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Decorador para verificar se é admin
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin: 
            flash('Você não tem permissão para acessar esta página.', 'warning')
            return redirect(url_for('main'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def main():
    if 'user_id' in session:
        # Busca o usuário pelo ID armazenado na sessão
        user = get_user_by_id(session['user_id'])
        if user:
            if user.is_admin:
                # Se o usuário for admin, renderiza a página de administração
                return render_template('admin.html')
            else:
                # Se o usuário não for admin, renderiza a página do aplicativo
                return render_template('app.html')
        else:
            # Se não encontrar o usuário (por exemplo, se foi deletado), limpa a sessão e redireciona para login
            session.pop('user_id', None)
            flash('Sua sessão é inválida. Por favor, faça o login novamente.', 'error')
            return redirect(url_for('login'))
    else:
        # Se não estiver logado, renderiza a página de login
        return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Se o usuário já estiver logado, redirecione para a página principal do aplicativo
    if 'user_id' in session:
        return redirect(url_for('main'))
    
    # Se for uma solicitação POST, processe o formulário de login
    if request.method == 'POST':
        email_or_username = request.form.get('loginName')
        password = request.form.get('loginPassword')
        remember = 'loginCheck' in request.form  # Verifica se o checkbox "Me lembre" foi marcado

        user = get_user_by_email_or_username(email_or_username)
        if user is None:
            flash('Email ou Usuário não cadastrado', 'error')
            return render_template('login.html')

        if check_credentials(email_or_username, password):
            # Armazena o ID do usuário na sessão
            session['user_id'] = user.id
            
            # Se o checkbox "Me lembre" foi marcado, a sessão se torna permanente
            if remember:
                session.permanent = True
                app.permanent_session_lifetime = timedelta(days=7)
            else:
                session.permanent = False

            return redirect(url_for('main'))
        else:
            flash('Credenciais inválidas. Por favor, tente novamente.', 'error')
            return render_template('login.html')
    
    # Se for uma solicitação GET, mostre o formulário de login
    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)
