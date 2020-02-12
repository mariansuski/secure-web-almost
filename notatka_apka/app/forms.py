from datetime import timedelta

import bcrypt
from config import Config
from flask import current_app
from flask_wtf.form import FlaskForm
from models import User
from wtforms import (BooleanField, FileField, Form, IntegerField,
                     PasswordField, StringField, TextAreaField,
                     ValidationError)
from wtforms.csrf.session import SessionCSRF
from wtforms.validators import (DataRequired, Email, EqualTo, Length,
                                NumberRange, Regexp)

######################
#sprawdzenie czy juz jest w bazie itd
# sprawdza czy jest juz taki login (jest inny niz te ktore sa juz w bazie)
class UniqueLogin(object):
    def __init__(self, message=None):
        if not message:
            message = 'Login jest zajęty'
        self.message = message

    def __call__(self, form, field):
        login = field.data
        with current_app.app_context():
            result = User.query.filter(User.login == login).first()
            if result is not None:
                raise ValidationError(self.message)

# sprawdza czy jest juz taki email (jest inny niz te ktore sa juz w bazie)
class UniqueEmail(object):
    def __init__(self, message=None):
        if not message:
            message = 'Email jest już zajęty'
        self.message = message

    def __call__(self, form, field):
        email = field.data
        with current_app.app_context():
            result = User.query.filter(User.email == email).first()
            if result is not None:
                raise ValidationError(self.message)

# sprawdza czy login jest w bazie danych
class LoginInDatabase(object):
    def __init__(self, message=None):
        if not message:
            message = 'Nie ma takiego loginu'
        self.message = message

    def __call__(self, form, field):
        login = field.data
        with current_app.app_context():
            result = User.query.filter(User.login == login).first()
            if result is None:
                raise ValidationError(self.message)

# sprawdza czy haslo jest poprawne 
class CorrectPassword(object):
    def __init__(self, message=None):
        if not message:
            message = 'Hasło nieprawidłowe'
        self.message = message

    def __call__(self, form, field):
        login = form.login.data
        password = field.data
        with current_app.app_context():
            user = User.query.filter(User.login == login).first()
            if user is None:
                return
            if not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
                raise ValidationError(self.message)

#form'y z validacja   
# base form
class BaseForm(FlaskForm):
    class Meta:
        csrf = True
        csrf_class = SessionCSRF
        csrf_secret = Config.SECRET_KEY.encode()
        csrf_time_limit = timedelta(minutes=15)

# registration form
class RegisterForm(BaseForm):
    login = StringField('login', validators=[
        DataRequired('Nie wpisałeś loginu'),
        Length(min=6, message='Login musi mieć minimum 6 znaków'),
        Length(max=20, message='Login może mieć max 20 znaków'),
        Regexp('^[A-Za-z0-9_-]',
               message='Login musi mieć wyłącznie litery, liczby i znaki _-'),
        UniqueLogin()
    ])

    password = PasswordField('password', validators=[
        DataRequired('Nie wpisałeś hasła'),
        Length(min=8, message='Hasło musi mieć minimum 8 znaków'),
        Length(max=20, message='Hasło musi mieć maksimum 20 znaków')
    ])
    password2 = PasswordField('Password', validators=[
        EqualTo('password', 'Hasła nie są takie same')
    ])

    email = StringField('Mail', validators=[
        DataRequired('Nie wpisałeś maila'),
        Email('E-mail nie jest poprawny'),
        UniqueEmail()
    ])

# login form
class LoginForm(BaseForm):
    login = StringField('login', validators=[
        DataRequired('Nie wpisałeś loginu'),
        Length(min=6, message='Login musi mieć minimum 6 znaków'),
        Length(max=20, message='Login może mieć max 20 znaków'),
        Regexp('^[A-Za-z0-9_-]',
               message='Login musi mieć wyłącznie litery, liczby i znaki _-'),
        LoginInDatabase()
    ])
    password = StringField('password', validators=[
        DataRequired('Nie wpisałeś hasła'),
        Length(min=8, message='Hasło musi mieć minimum 8 znaków'),
        Length(max=20, message='Hasło musi mieć maksimum 20 znaków'),
        CorrectPassword()
    ])

# change password form
class ChangePasswordForm(BaseForm):
    login = StringField('login', validators=[
        DataRequired('Nie wpisałeś loginu'),
        Length(min=6, message='Login musi mieć minimum 6 znaków'),
        Length(max=20, message='Login może mieć max 20 znaków'),
        Regexp('^[A-Za-z0-9_-]',
               message='Login musi mieć wyłącznie litery, liczby i znaki _-'),
        LoginInDatabase()
    ])

    old_password = PasswordField('Old password', validators=[
        DataRequired('Nie wpisałeś starego hasła'),
        Length(min=8, message='Hasło musi mieć minimum 8 znaków'),
        Length(max=20, message='Hasło musi mieć maksimum 20 znaków'),
        CorrectPassword()
    ])

    password = PasswordField('password', validators=[
        DataRequired('Nie wpisałeś nowego hasła'),
        Length(min=8, message='Hasło ma mieć minimum 8 znaków'),
        Length(max=20, message='Hasło ma mieć maksimum 20 znaków')
    ])
    password2 = PasswordField('password2', validators=[
        EqualTo('password', 'Hasła są różne')
    ])

# create note form
class CreateNoteForm(BaseForm):
    title = StringField(validators=[
        DataRequired('Nie wpisałeś tytułu'),
        Length(max=20, message='Wpisany tytuł jest za długi')
    ])
    body = TextAreaField(validators=[
        DataRequired('Nic nie wpisałeś'),
        Length(max=300, message='Ojj za długa notatka')
    ])

    public = BooleanField()
    shares = TextAreaField(validators=[
        Length(max=104,message='Max 5 loginów')
    ])
