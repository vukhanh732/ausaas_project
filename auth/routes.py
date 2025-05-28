from flask import Blueprint, render_template, redirect, url_for, flash, request, session, current_app # Added session, current_app
from auth.forms import RegistrationForm, LoginForm # Import LoginForm
from auth.models import User
from app import db # Import the db instance

# Create an authentication Blueprint
auth_bp = Blueprint('auth', __name__)

# User loader for Flask-Login (we'll implement Flask-Login in Phase 3 for better user management)
# For now, we'll manually manage session with user_id.

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        new_user = User(username=username)
        new_user.set_password(password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('auth.login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'danger')
            current_app.logger.error(f"Error during registration for user '{username}': {e}", exc_info=True) # Log the full traceback
    
    return render_template('register.html', form=form)

# --- NEW: Login Route ---
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        remember_me = form.remember_me.data

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            # Login successful
            session['user_id'] = user.id # Store user ID in session
            session['username'] = user.username # Store username in session
            
            # Optional: for 'Remember Me' functionality, set a permanent session
            if remember_me:
                session.permanent = True 
                current_app.logger.info(f"User '{username}' logged in (remembered).")
            else:
                session.permanent = False
                current_app.logger.info(f"User '{username}' logged in (session).")

            flash('You have been logged in successfully!', 'success')
            next_page = request.args.get('next') # Handle redirect to requested page
            return redirect(next_page or url_for('home')) # Redirect to home or next page
        else:
            # Login failed
            flash('Invalid username or password. Please try again.', 'danger')
            current_app.logger.warning(f"Failed login attempt for username: {username}")
    
    return render_template('login.html', form=form)

# --- NEW: Logout Route ---
@auth_bp.route('/logout')
def logout():
    session.pop('user_id', None) # Remove user_id from session
    session.pop('username', None) # Remove username from session
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))