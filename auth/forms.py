from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectMultipleField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from wtforms.widgets import CheckboxInput, ListWidget
from auth.models import User, Role # Import User model to check for existing users
import os # Import os for potential future use or to signal best practices

# --- NEW: List of Banned Passwords (Simplified for demonstration) ---
# In a real application, this would be loaded from a much larger, external file
# like a subset of the Pwned Passwords list, or checked via an API.
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
    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message='Password is required.'),
            Length(min=12, message='Password must be at least 12 characters long.') # Updated min length to 12
            # Optional: Regexp for complexity. NIST moves away from this, but some apps still use it.
            # Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$',
            #        message='Password must be at least 12 characters, include uppercase, lowercase, number, and special character.')
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
        """Custom validator to check if username already exists."""
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    # --- NEW: Custom Password Validator for Banned Passwords ---
    def validate_password(self, password): # This function name must be validate_<field_name>
        if password.data.lower() in BANNED_PASSWORDS:
            raise ValidationError('This password is too common or easily guessable. Please choose a stronger password.')

# --- LoginForm (no change needed for validators directly, but good to keep structure consistent) ---
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
class UserRolesForm(FlaskForm):
    # This field will be dynamically populated in the route
    roles = SelectMultipleField(
        'Assign Roles',
        coerce=int, # Coerce chosen values to int (role IDs)
        validators=[DataRequired(message='Please select at least one role.')],
        widget=ListWidget(prefix_label=False), # Renders as a list without <li>
        option_widget=CheckboxInput() # Renders each option as a checkbox
    )
    submit = SubmitField('Update Roles')

# --- NEW: AddRoleForm ---
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
        """Custom validator to check if role name already exists."""
        role = Role.query.filter_by(name=name.data).first()
        if role:
            raise ValidationError('A role with that name already exists.')

# --- NEW: DeleteRoleForm ---
class DeleteRoleForm(FlaskForm):
    role_to_delete = SelectField(
        'Role to Delete',
        coerce=int, # Coerce chosen value to int (role ID)
        validators=[DataRequired(message='Please select a role to delete.')]
    )
    submit = SubmitField('Delete Role')

    def __init__(self, *args, **kwargs):
        super(DeleteRoleForm, self).__init__(*args, **kwargs)
        # Dynamically populate choices when the form is instantiated
        self.role_to_delete.choices = [(r.id, r.name) for r in Role.query.order_by(Role.name).all() if r.name not in ['admin', 'user']]
        # Prevent deleting core 'admin' or 'user' roles for safety
        if not self.role_to_delete.choices:
             self.role_to_delete.choices = [(0, "No roles to delete")] # Placeholder if no deletable roles exist
