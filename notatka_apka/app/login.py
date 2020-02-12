from flask import current_app
from flask_login import LoginManager
from models import User

login_manager = LoginManager()
login_manager.login_view = 'app.login'
login_manager.login_message = 'Musisz być zalogowany'
login_manager.login_message_category = "alert-danger"


@login_manager.user_loader
def load_user(user_id):
    with current_app.app_context():
        return User.query.filter_by(id=int(user_id)).first()
