from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = "somethingsecret"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/stevo4932/apps/GeoNotesREST/geonotes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50))
    description = db.Column(db.String(250))
    address = db.Column(db.String(100))
    lat = db.Column(db.Float)
    lon = db.Column(db.Float)
    time = db.Column(db.DateTime)
    user_id = db.Column(db.Integer)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    users = User.query.all()
    output = []
    for user in users:
        user_data = {
            'public_id': user.public_id,
            'name': user.name,
            'password': user.password,
            'admin': user.admin
        }
        output.append(user_data)
    return jsonify({'users': output})


@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message': 'User is not admin'}), 403

    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No user found!'})

    user_data = {
        'public_id': user.public_id,
        'name': user.name,
        'password': user.password,
        'admin': user.admin
    }
    return jsonify({'message': user_data})


@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):

    if not current_user.admin:
        return jsonify({'message': 'User is not admin'}), 403

    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id= str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'user created'})


@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message': 'User is not admin'}), 403

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user.admin = True
    db.session.commit()
    return jsonify({'message': 'The user has been promoted'})


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message': 'User is not admin'}), 403

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'The user has been deleted'})


@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Missing username or password', 401, {'WWW-Authenticate': 'Basic realm="Login required!'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response("Invalid Credentials", 401, {'WWW-Authenticate': 'Basic realm="Login required!'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})

    return make_response("Invalid Credentials", 401, {'WWW-Authenticate': 'Basic realm="Login required!'})


def produce_note_list(notes):
    output = []
    for note in notes:
        output.append(produce_full_note(note))
    return output


def produce_full_note(note):
    return {
        'title': note.title,
        'description': note.description,
        'address': note.address,
        'lat': note.lat,
        'lon': note.lon,
        'time': note.time,
        'note_id': note.id
    }


@app.route('/note', methods=['GET'])
@token_required
# need to add lat and lon values.
def get_notes(current_user):
    notes = Note.query.all()
    return jsonify(produce_note_list(notes)), 200


@app.route('/note/user', methods=['GET'])
@token_required
def get_user_notes(current_user):
    notes = Note.query.find_by(user_id=current_user.id).all()
    return jsonify(produce_note_list(notes)), 200


@app.route('/note/<int:note_id>', methods=['GET'])
@token_required
def get_note(current_user, note_id):
    note = Note.query.filter_by(id=note_id).first()
    return jsonify(produce_full_note(note)), 200


@app.route('/note', methods=['POST'])
@token_required
def create_note(current_user):
    data = request.get_json()
    note = Note(
        title=data['title'],
        description=data['description'],
        address=data['address'],
        lat=data['lat'],
        lon=data['lon'],
        time=datetime.datetime.utcnow(),
        user_id=current_user.id
    )
    db.session.add(note)
    db.session.commit()
    return jsonify({'message': 'Note created'}), 200


@app.route('/note/<note_id>', methods=['DELETE'])
@token_required
def delete_note(current_user, note_id):
    note = Note.query.filter_by(id=note_id).first()
    db.session.delete(note)
    db.session.commit()
    return jsonify({'message': 'The note has been deleted'}), 200


if __name__ == '__main__':
    app.run(debug=True)
