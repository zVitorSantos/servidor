from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response, jsonify
from flask_login import UserMixin, LoginManager, AnonymousUserMixin, login_required, current_user, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from datetime import timedelta
import logging
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = '1234'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.abspath('database/users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    user = db.session.query(User).get(int(user_id))
    # app.logger.debug(f"User loaded: {user}")
    return user

db = SQLAlchemy(app)

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    username = db.Column(db.String(80), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<User {self.username}>'
    
class Anonymous(AnonymousUserMixin):
    is_admin = False

login_manager.anonymous_user = Anonymous

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

logging.basicConfig(level=logging.DEBUG)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        logging.debug(f"Sessão atual: {session}")
        if not current_user.is_authenticated:
            logging.warning("Acesso sem autenticação")
            return jsonify({'error': 'Não autenticado'}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        logging.debug(f"Usuário {current_user.username} admin status: {current_user.is_admin}")
        if not current_user.is_admin:
            logging.warning("Acesso sem permissão de administrador")
            return jsonify({'error': 'Acesso negado'}), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/check-permission', methods=['GET'])
@login_required
def check_permission():
    if current_user.is_admin:
        return jsonify({'isAllowed': True})
    else:
        return jsonify({'isAllowed': False}), 403

# Rota para listar usuários
@app.route('/users')
@login_required
@admin_required 
def list_users_route():
    try:
        users = User.query.all()
        users_data = [
            {
                'id': user.id,
                'name': user.name,
                'username': user.username,
                'email': user.email,
                'is_admin': user.is_admin
            } for user in users
        ]
        return jsonify(users_data)
    except Exception as e:
        logging.error(f'Erro ao buscar usuários: {e}')
        return jsonify({'error': 'Erro interno do servidor'}), 500

def register_user(name, username, email, password, is_admin=False):
    try:
        hashed_password = generate_password_hash(password)
        user = User(name=name, username=username, email=email, password=hashed_password, is_admin=is_admin)
        db.session.add(user)
        db.session.commit()
        return user.id
    except Exception as e:
        db.session.rollback()
        return None

@app.route('/register', methods=['POST'])
@login_required
@admin_required
def register_user_route():
    data = request.form
    name = data.get('name')
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    is_admin = data.get('is_admin') == 'on'

    # Verifique se o usuário ou email já existe
    existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
    if existing_user:
        return jsonify({'success': False, 'message': 'Nome de usuário ou email já cadastrado.'}), 409

    # Caso não exista, prossiga com a criação do novo usuário
    try:
        hashed_password = generate_password_hash(password)
        user = User(name=name, username=username, email=email, password=hashed_password, is_admin=is_admin)
        db.session.add(user)
        db.session.commit()
        return jsonify({'success': True, 'user_id': user.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    
@app.route('/delete-user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user_route(user_id):
    try:
        user = User.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        logging.error(f'Erro ao apagar usuário: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/')
def main():
    logging.debug(f"Sessão atual na rota principal: {session}")
    logging.debug(f"Usuário atual na rota principal: {current_user}")
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
        remember = 'loginCheck' in request.form 

        user = get_user_by_email_or_username(email_or_username)
        if user is None:
            flash('Email ou Usuário não cadastrado', 'error')
            return render_template('login.html')

        if check_credentials(email_or_username, password):
            login_user(user, remember=remember, fresh=True)
            # Armazena o ID do usuário na sessão
            session['user_id'] = user.id
            logging.debug(f"Usuário {user.username} logado com sucesso. Sessão: {session}")
            
            # Se o checkbox "Me lembre" foi marcado, a sessão se torna permanente
            if remember:
                session.permanent = True
                app.permanent_session_lifetime = timedelta(days=7)
                logging.debug("Sessão configurada como permanente.")
            else:
                session.permanent = False
            logging.debug(f"Sessão permanente: {session.permanent}")

            return redirect(url_for('main'))
        else:
            flash('Credenciais inválidas. Por favor, tente novamente.', 'error')
            return render_template('login.html')
    
    # Se for uma solicitação GET, mostre o formulário de login
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user() 
    # Remove o ID do usuário da sessão
    session.pop('user_id', None)
    # Mostra uma mensagem ao usuário
    flash('Você foi desconectado com sucesso.', 'success')
    # Redireciona para a página de login ou para a página principal
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
