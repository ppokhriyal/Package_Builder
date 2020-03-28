from flask_wtf import FlaskForm
from flask_mde import Mde, MdeField
from flask_wtf.file import FileField, FileAllowed
from flask_login import current_user
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField
from wtforms.ext.sqlalchemy.fields import QuerySelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, InputRequired,IPAddress
from pkgbuilder.models import User,Register_Host


class LoginForm(FlaskForm):
    email = StringField('Email',validators=[DataRequired(),Email()])
    password = PasswordField('Password',validators=[DataRequired()])
    submit = SubmitField('Login')



class RegistrationForm(FlaskForm):

    username = StringField('Username',validators=[DataRequired(),Length(min=2,max=20)])
    email = StringField('Email',validators=[DataRequired(),Email()])
    password = PasswordField('Password',validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',validators=[DataRequired(),EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self,username):

        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a diffrent one.')

    def validate_email(self,email):

        user = User.query.filter_by(email=email.data).first()
        check_email_valid = email.data
        if check_email_valid.split('@')[1] != "vxlsoftware.com":
            raise ValidationError('Please enter your valid vxlsoftware email id.')
        if user:
           raise ValidationError('That email is taken. Please choose a diffrent one.')


class AddHostMachineForm(FlaskForm):
	remote_host_ip = StringField('Remote Host IP Address',validators=[DataRequired(),IPAddress(message="Please Give Valid IP-Address")])
	submit = SubmitField('Register')

#Function for loading remote host ip address from database
def load_remote_host_ip():
	return Register_Host.query

class BuildTestPackageForm(FlaskForm):

	test_pkg_build_id = StringField('Package Build ID',render_kw={'readonly':True},validators=[DataRequired()])
	test_pkg_name = StringField('Package Name',validators=[DataRequired()])
	test_pkg_description = TextAreaField('Description',validators=[DataRequired()])
	os_arch = SelectField('OS Architecture',choices=[('32','32-Bit'),('64','64-Bit'),('Multi-Arch','Multi-Arch')])
	remote_host_ip = QuerySelectField(query_factory=lambda:Register_Host.query.all())
	raw_pkg_path = StringField('Package Structure',validators=[DataRequired()])
	need_patch = BooleanField('Required Patch')
	remove = TextAreaField('Remove Packages')
	install_script = TextAreaField('Install Script')
	submit = SubmitField('Build')