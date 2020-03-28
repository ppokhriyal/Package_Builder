from datetime import datetime
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from pkgbuilder import db, login_manager, app
from flask_login import UserMixin


@login_manager.user_loader
def load_user(user_id):
        return User.query.get(int(user_id))


class User(db.Model,UserMixin):
        id = db.Column(db.Integer,primary_key=True)
        username = db.Column(db.String(20),unique=True,nullable=False)
        email = db.Column(db.String(120),unique=True,nullable=False)
        password = db.Column(db.String(60),nullable=False)
        password_decrypted = db.Column(db.String(60),nullable=False)

        def __repr__(self):
        	return f"User('{self.username}','{self.email}')"


class Register_Host(db.Model):
	id = db.Column(db.Integer,primary_key=True)
	ipaddress = db.Column(db.String(20),unique=True,nullable=False)
	hostname = db.Column(db.String(20),unique=True,nullable=False)

	def __repr__(self):
		return f"{self.ipaddress}"