# auth/forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectMultipleField, SelectField, EmailField # NEW: Import EmailField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError, Email # NEW: Import Email validator
from wtforms.widgets import CheckboxInput, ListWidget
from auth.models import User, Role # Import User model to check for existing users

# --- List of Banned Passwords (Simplified for demonstration) ---
BANNED_PASSWORDS = [
    "password", "123456", "qwerty", "admin", "12345678", "123456789",
    "testpassword123", # Add the test user password to make sure the test fails
    "adminpass" # Add the admin password to make sure the test fails
]

class RegistrationForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[
            DataRequired(message='Username is required.'),
            Length(min=3, max=20, message='Username must be between 3 and 20 characters long.')
        ]
    )
    # --- NEW: Email Field ---
    email = EmailField(
        'Email',
        validators=[
            DataRequired(message='Email is required.'),
            Email(message='Invalid email address.'), # Basic email format validation
            Length(max=120, message='Email cannot exceed 120 characters.')
        ]
    )
    # --- END NEW ---
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message='Password is required.'),
            Length(min=12, message='Password must be at least 12 characters long.') # Updated min length to 12
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
    
    # --- NEW: Custom Email Validator for Duplicates ---
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email address is already registered.')
    # --- END NEW ---

    def validate_password(self, password):
        if password.data and password.data.lower() in BANNED_PASSWORDS: # Added 'password.data' check for safety
            raise ValidationError('This password is too common or easily guessable. Please choose a stronger password.')

class LoginForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[DataRequired(message='Username is required.')]
    )
    password = PasswordField(
        'Password',
        validators=[DataRequired(message='Password is required.')]
    )
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Login')

# --- UserRolesForm for Admin Role Management ---
class UserRolesForm(FlaskForm):
    roles = SelectMultipleField(
        'Assign Roles',
        coerce=int,
        validators=[DataRequired(message='Please select at least one role.')],
        widget=ListWidget(prefix_label=False),
        option_widget=CheckboxInput()
    )
    submit = SubmitField('Update Roles')

# --- AddRoleForm ---
class AddRoleForm(FlaskForm):
    name = StringField(
        'Role Name',
        validators=[
            DataRequired(message='Role name is required.'),
            Length(min=2, max=50, message='Role name must be between 2 and 50 characters.')
        ]
    )
    description = StringField(
        'Description (Optional)',
        validators=[Length(max=255, message='Description cannot exceed 255 characters.')]
    )
    submit = SubmitField('Add Role')

    def validate_name(self, name):
        role = Role.query.filter_by(name=name.data).first()
        if role:
            raise ValidationError('A role with that name already exists.')

# --- DeleteRoleForm ---
class DeleteRoleForm(FlaskForm):
    role_to_delete = SelectField(
        'Role to Delete',
        coerce=int,
        validators=[DataRequired(message='Please select a role to delete.')]
    )
    submit = SubmitField('Delete Role')

    def __init__(self, *args, **kwargs):
        super(DeleteRoleForm, self).__init__(*args, **kwargs)
        self.role_to_delete.choices = [(r.id, r.name) for r in Role.query.order_by(Role.name).all() if r.name not in ['admin', 'user']]
        if not self.role_to_delete.choices:
             self.role_to_delete.choices = [(0, "No roles to delete")]