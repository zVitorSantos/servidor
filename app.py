from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = '1234'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database/users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    username = db.Column(db.String(80), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

@app.route('/')
def main():
    return render_template('main.html')

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
        return True
    except Exception as e:
        db.session.rollback()
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

    if register_user(name, username, email, password):
        flash('Registro bem-sucedido! Agora você pode fazer login.')
    else:
        flash('Ocorreu um erro ao tentar registrar o usuário. Por favor, tente novamente.')

    return redirect(url_for('main'))

if __name__ == '__main__':
    app.run(debug=True)
