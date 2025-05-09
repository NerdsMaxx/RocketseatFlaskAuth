from typing import Any

from flask import Flask, request, jsonify, Response
from flask_login import LoginManager, login_user, current_user, logout_user, login_required

from database import db
from models.user import User

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)

login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id: int) -> User:
    return User.query.get(user_id)

@app.post('/login')
def login() -> Response | tuple[Response, int]:
    data: Any = request.json
    username: str = data.get('username')
    password: str = data.get('password')

    if username and password:
        user: User = User.query.filter_by(username=username).first()

        if user and user.password == password:
            login_user(user)
            print(current_user.is_authenticated)
            return create_response('Autenticação realizada com sucesso', None)

    return create_response('Credenciais inválidas', 400)

@app.post('/user')
@login_required
def create_user() -> Response | tuple[Response, int]:
    data: Any = request.json
    username: str = data.get('username')
    password: str = data.get('password')

    if username and password:
        user: User = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()
        return create_response('Usuário cadastrado com sucesso!', None)

    return create_response('Dados inválidos', 400)


@app.get('/user/<int:id_user>')
@login_required
def read_user(id_user) -> Response:
    user: User = User.query.get(id_user)

    if user:
        return jsonify({'username': user.username})

    return create_response('Usuário não foi encontrado!', 404)

@app.put('/user/<int:id_user>')
@login_required
def update_user(id_user) -> Response:
    user: User = User.query.get(id_user)

    if user:
        data: Any = request.json
        password: str = data.get('password')
        password = password.strip() if password else ''

        if password and len(password) > 0:
            user.password = password
            db.session.commit()

            return create_response('Usuário foi atualizado com sucesso!', None)
        else:
            return create_response('Request inválido!', 400)

    return create_response('Usuário não foi encontrado!', 404)

@app.delete('/user/<int:id_user>')
@login_required
def delete_user(id_user) -> Response:
    user: User = User.query.get(id_user)

    if id_user == current_user.id:
        return create_response('Deleção não permitida!', 403)

    if user:
        db.session.delete(user)
        db.session.commit()
        return create_response('Usuário foi deletado com sucesso!', None)

    return create_response('Usuário não foi encontrado!', 404)


@app.get('/logout')
@login_required
def logout() -> Response:
    logout_user()
    return create_response('Logout realizado com sucesso!', None)

def create_response(message: str, status: int | None) -> tuple[Response, int] | Response:
    response: Response = jsonify({'message': message})
    return (response, status) if status else response

if __name__ == '__main__':
    app.run(debug=True)