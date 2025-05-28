from flask import Blueprint, render_template, redirect, url_for, flash, request
from auth.forms import RegistrationForm # Import forms
from auth.models import User # Import models
from app import db # Import the db instance

# Create an authentication Blueprint
auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Form submission is valid, process registration
        username = form.username.data
        password = form.password.data

        # Create new user instance
        new_user = User(username=username)
        new_user.set_password(password) # Hash the password

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('auth.login')) # Redirect to login page (will be created in Phase 2)
        except Exception as e:
            db.session.rollback() # Rollback in case of database error
            flash('An error occurred during registration. Please try again.', 'danger')
            print(f"Error during registration: {e}") # Log actual error for debugging
    
    # If GET request or form validation fails, render the registration form
    return render_template('register.html', form=form)

# We'll add login and logout routes in a later phase