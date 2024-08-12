from flask import Flask, request, jsonify
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from bcrypt import hashpw, gensalt, checkpw

from models.user import User
from database import db


app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:admin123@127.0.0.1:3306/flask_crud'   # 'instance:///database.db'

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)

# View
login_manager.login_view = 'login'


# Create database in terminal
"""
flask shell
db.create_all()
db.session.commit() # To save the changes
"""

# Create a user
"""
flask shell
user = User(username='admin', password='admin')
db.session.add(user)
db.session.commit()
"""


# Recuperate the user
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# For login with password it's better to use POST method
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if username and password:
        # Check if user exists
        user = User.query.filter_by(username=username).first()
        if user and checkpw(str.encode(password), str.encode(user.password)):
            login_user(user)
            print(current_user.is_authenticated)
            return jsonify({'message': 'Authenticated'})

    return jsonify({'message': 'Invalid credentials'}), 400


@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out'})


@app.route("/user", methods=['POST'])
def create_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if username and password:
        hashed_password = hashpw(str.encode(password), gensalt())
        user = User(username=username, password=hashed_password, role='user')
        db.session.add(user)
        db.session.commit()
        return jsonify({'message': 'User created'})

    return jsonify({'message': 'Invalid data'}), 400


@app.route("/user/<int:user_id>", methods=['GET'])
@login_required
def get_user(user_id):
    user = User.query.get(user_id)
    if user:
        return jsonify({'username': user.username})
    return jsonify({'message': 'User not found'}), 404


@app.route("/user/<int:user_id>", methods=['PUT'])
@login_required
def update_user(user_id):
    user = User.query.get(user_id)
    if (user_id != current_user.id) and (current_user.role != 'admin'):
        return jsonify({'message': 'You cannot update other users'}), 403
    if user:
        data = request.json
        user.password = data.get('password')
        db.session.commit()
        return jsonify({'message': f'User {user_id} updated'})
    return jsonify({'message': 'User not found'}), 404


@app.route("/user/<int:user_id>", methods=['DELETE'])
@login_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if current_user.role != 'admin':
        return jsonify({'message': 'You cannot delete users'}), 403
    if user_id != current_user.id:
        return jsonify({'message': 'You cannot delete yourself'}), 403
    if user and user_id != current_user.id:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': f'User {user_id} deleted'})
    return jsonify({'message': 'User not found'}), 404


# No terminal rodar o docker-compose up


if __name__ == '__main__':
    app.run(debug=True)

