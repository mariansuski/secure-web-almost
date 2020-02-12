from datetime import datetime, timedelta
from secrets import token_urlsafe

import bcrypt
from flask import current_app
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

TOKEN_VALID_TIME = timedelta(minutes=30)
TOKEN_LENGTH = 50

# użytkownik
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(), index=True, unique=True)
    email = db.Column(db.String(), unique=True)
    password_hash = db.Column(db.String())
    notes = db.relationship('Note', backref='owner', lazy=True)
    login_attempts = db.relationship('Login', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(
            password.encode(), bcrypt.gensalt()).decode()

    def __repr__(self):
        return f'{self.login}'

# notatka
class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String())
    body = db.Column(db.String())
    public = db.Column(db.Boolean())
    share_list = db.relationship('Share', backref='note', lazy=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return f'<Note id={self.id} title={self.title}>'

# połączenie użytkownika z notatką (id)
class Share(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    note_id = db.Column(db.Integer, db.ForeignKey('note.id'))
    user_name = db.Column(db.String(), index=True)

    def __repr__(self):
        return f'User: {self.user_name} NoteId: {self.note_id}'

# tabela z loginami 
class Login(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    successful = db.Column(db.Boolean())
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip = db.Column(db.String())

# początkowe wartości
def initial_input():
    suski = User(
        login='adamsuski', email='adammarian@suski.com')
    suski.set_password('AdamSuski')
    db.session.add(suski)

    adam = User(
        login='adamadam', email='adamadam@adam.com')
    adam.set_password('AdamAdam')
    db.session.add(adam)

    notatka1 = Note(title='Pierwsza notatka',
                body='To jest notatka numer jeden. Jest ona prywatna co może powodować zamieszanie',
                owner=adam, public=False)
    db.session.add(notatka1)
    share = Share(note=notatka1, user_name='adamadam')
    db.session.add(share)

    notka = Note(title='Pierwsza notatka publiczna',
                body='To jest pierwsza publiczna notatka co może byc dziwne bo jest już jedna notatka. Jest jednak ona prywatna',
                owner=adam, public=True)
    db.session.add(notka)

    db.session.commit()
