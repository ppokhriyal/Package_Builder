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
	pkg_info = db.relationship('Pkgdetails',backref='author',lazy=True,cascade='all,delete-orphan')
	reg_host = db.relationship('Register_Host',backref='register_remote_host',lazy=True,cascade='all,delete-orphan')
	log = db.relationship('Logs',backref='logmeup',lazy=True,cascade='all,delete-orphan')
	
	def __repr__(self):
		return f"User('{self.username}','{self.email}')"

class Pkgdetails(db.Model):
	id = db.Column(db.Integer,primary_key=True)
	pkgbuild_id = db.Column(db.Integer,unique=True,nullable=False)
	pkgname = db.Column(db.String(60),nullable=False)
	date_posted = db.Column(db.DateTime(),nullable=False,default=datetime.utcnow)
	description = db.Column(db.Text,nullable=False)
	md5sum_pkg = db.Column(db.String(50),nullable=False)
	md5sum_patch = db.Column(db.String(50))
	os_arch = db.Column(db.Text,nullable=False)
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

	def __repr__(self):
		return f"Pkgdetails('{self.pkgbuild_id}','{self.pkgname}','{self.description}','{self.md5sum_patch}')"
	
class Register_Host(db.Model):
	id = db.Column(db.Integer,primary_key=True)
	ipaddress = db.Column(db.String(20),unique=True,nullable=False)
	hostname = db.Column(db.String(20),unique=True,nullable=False)
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

	def __repr__(self):
		return f"{self.ipaddress}"

class Logs(db.Model):
	id = db.Column(db.Integer,primary_key=True)
	pkgbuild_id = db.Column(db.Integer,unique=True,nullable=False)
	pkgname = db.Column(db.String(60),nullable=False)
	date_removed = db.Column(db.DateTime(),nullable=False,default=datetime.utcnow)
	md5sum_pkg = db.Column(db.String(50),nullable=False)
	md5sum_patch = db.Column(db.String(50))
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
	def __repr__(self):
		return f"Logs('{self.pkgbuild_id}','{self.pkgname}','{self.md5sum_pkg}','{self.md5sum_patch}')"
