from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField # Added BooleanField for remember me
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from auth.models import User

class RegistrationForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[
            DataRequired(message='Username is required.'),
            Length(min=3, max=20, message='Username must be between 3 and 20 characters long.')
        ]
    )
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message='Password is required.'),
            Length(min=8, message='Password must be at least 8 characters long.')
        ]
    )
    confirm_password = PasswordField(
        'Confirm Password',
        validators=[
            DataRequired(message='Please confirm your password.'),
            EqualTo('password', message='Passwords must match.')
        ]
    )
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

# --- NEW: LoginForm ---
class LoginForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[DataRequired(message='Username is required.')]
    )
    password = PasswordField(
        'Password',
        validators=[DataRequired(message='Password is required.')]
    )
    remember_me = BooleanField('Remember Me') # Optional: for persistent sessions
    submit = SubmitField('Login')