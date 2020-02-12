import ssl
from datetime import datetime, timedelta
from time import sleep
from urllib.parse import urlsplit, urlunsplit

import bcrypt
from config import Config
from flask import (Blueprint, Flask, Response, abort, current_app, flash,
                   redirect, render_template, request, session, url_for)
from flask_login import current_user, login_required, login_user, logout_user
from flask_misaka import Misaka
from flask_session import Session
from forms import ChangePasswordForm, CreateNoteForm, LoginForm, RegisterForm
from login import login_manager
from models import Login, Note, Share, User, db, initial_input
from password_strength import PasswordPolicy, PasswordStats
from flask_wtf.csrf import CSRFError

################################
#configuracja
app = Flask(__name__)
app.config.from_object(Config)
Session(app)
Misaka(app, escape=True)

db.init_app(app)
with app.app_context():
    db.drop_all()
    db.create_all()
    db.session.commit()
    initial_input()
login_manager.init_app(app)


policy = PasswordPolicy.from_names(
    length=8,  # minimalna dlugosc: 8
    uppercase=2,  # minimum 2 wielkie litery
    numbers=2,  # minimum 2 cyfry
    special=2,  # minimum 2 specialne znaki
)
################################
##sciezki
# index
@app.route('/')
def index():
    return render_template('index.html')

# rejestracja
@app.route('/register', methods=['GET', 'POST'])
def register():
    logout_user()
    form = RegisterForm(meta={'csrf_context': session})
    if form.validate_on_submit():
        flash('Konto zostało utworzone', 'alert-success')

        login = form.login.data
        password = form.password.data
        email = form.email.data
        
        #entropia
        tested_pass=policy.password(password)
        #
        print(tested_pass.strength())  # >0.6 good
        print(tested_pass.test())
        #
        password_hash = bcrypt.hashpw(
            password.encode(), bcrypt.gensalt(16)).decode()

        user = User(login=login, password_hash=password_hash, email=email)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('index'))

    return render_template('register.html', form=form)

# logowanie użutkownika
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm(meta={'csrf_context': session})
    user = User.query.filter_by(login=form.login.data).first()

    if user and form.password.data:  # podejście do logowania
        ip = request.remote_addr
        login = Login(successful=form.validate(), ip=ip, user=user)
        db.session.add(login)
        db.session.commit()
        # opóźnienie w przypadku brute force
        time_boundary = datetime.utcnow() - timedelta(minutes=5)
        tries = len([a for a in user.login_attempts if a.timestamp > time_boundary and not a.successful])
        delay=0
        if tries >3:
            delay=3
        if tries >10:
            delay=5
        if tries >30:
            delay=15

        sleep(delay)

    if form.validate_on_submit():
        login_user(user)
        next_page = session.get('next', None)
        session['next'] = None
        if not next_page:
            next_page = url_for('view_notes')
        return redirect(next_page)

    return render_template('login.html', form=form)

# strona z kontem (możliwość zmiany hasła)
@app.route('/account')
@login_required
def account():
    user = User.query.filter_by(id=current_user.id).first()
    login_attempts = sorted(user.login_attempts, key=lambda a: a.timestamp, reverse=True)
    time_format = r'%d/%m/%Y %H:%M:%S'
    login_attempts = [{'ip': a.ip, 'successful': a.successful, 'time': a.timestamp.strftime(time_format)}
                      for a in login_attempts]

    return render_template('account.html', login_attempts=login_attempts)

# zmiana hasła
@app.route('/account/changePassword', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm(meta={'csrf_context': session})
    form.login.data = current_user.login
    if form.validate_on_submit():
        password = form.password.data
        #entropia
        tested_pass=policy.password(password)
        #
        print(tested_pass.strength())  # >0.6 good
        print(tested_pass.test())
        #
        current_id = current_user.id
        user = User.query.filter_by(id=current_id).first()
        user.set_password(password)
        db.session.commit()

        flash('Hasło zostało zmienione', 'alert-success')
        return redirect(url_for('account'))

    return render_template('change_password.html', form=form)

# dodanie notatki
@app.route('/myNotes', methods=['GET', 'POST'])
@login_required
def my_notes():
    user = User.query.filter_by(id=current_user.id).first()
    form = CreateNoteForm(meta={'csrf_context': session})
    if form.validate_on_submit():
        title = form.title.data
        body = form.body.data
        public = form.public.data
        note = Note(title=title,
                    body=body, owner=user, public=public)
        db.session.add(note)
        shares_list = {row.strip() for row in form.shares.data.split()}
        for user_name in shares_list:
            share = Share(note=note, user_name=user_name)
            db.session.add(share)
        db.session.commit()
        flash('Notatka została dodana', 'alert alert-success')
    notes = user.notes
    return render_template('my_notes.html', form=form, notes=notes)

# usuń notatkę
@app.route('/myNotes/delete/<int:id>')
@login_required
def delete_note(id):
    user = User.query.filter_by(id=current_user.id).first()
    notes = [note for note in user.notes if note.id == id]
    if len(notes) > 1:
        abort(500)
    if len(notes) < 1:
        abort(404)
    note = notes[0]
    db.session.delete(note)
    db.session.commit()

    return redirect(url_for('my_notes'))

# główny panel podglądu notatki
@app.route('/notes')
@login_required
def view_notes():
    user = User.query.filter_by(id=current_user.id).first()
    public_notes = Note.query.filter_by(public=True).all()
    shared_with_me_id = [share.note_id for share in Share.query.filter_by(
        user_name=user.login).all()]
    notes_shared_with_me = Note.query.filter(
        Note.id.in_(shared_with_me_id)).all()
    notes = public_notes + notes_shared_with_me

    return render_template('view_notes.html', notes=notes)


# wylogowanie użytkownika
@app.route('/logout')
def logout():
    logout_user()
    flash('Nastąpiło poprawne wylogowanie', 'alert-success')

    return redirect(url_for('index'))

#error
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template(url_for('index'))

@app.errorhandler(400)
def page_wrong_request(error):
    return render_template(url_for('index'))

@app.errorhandler(401)
def page_unauthorized(error):
    return render_template(url_for('index'))

@app.errorhandler(403)
def page_forbidden(error):
    return render_template(url_for('index'))

@app.errorhandler(404)
def page_not_found(error):
    return render_template(url_for('index'))