# auth/routes.py
from flask import Blueprint, render_template, redirect, url_for, flash, request, session, current_app
from auth.forms import RegistrationForm, LoginForm
from auth.models import User
from app import db
from auth.auth_decorators import login_required, roles_required # NEW: Import decorators

auth_bp = Blueprint('auth', __name__)

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
            current_app.logger.error(f"Error during registration for user '{username}': {e}", exc_info=True)
    
    return render_template('register.html', form=form)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        remember_me = form.remember_me.data

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            
            if remember_me:
                session.permanent = True 
                current_app.logger.info(f"User '{username}' logged in (remembered).")
            else:
                session.permanent = False
                current_app.logger.info(f"User '{username}' logged in (session).")

            flash('You have been logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('home'))
        else:
            flash('Invalid username or password. Please try again.', 'danger')
            current_app.logger.warning(f"Failed login attempt for username: {username}")
    
    return render_template('login.html', form=form)

@auth_bp.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

# --- NEW: Protected Dashboard Route ---
@auth_bp.route('/dashboard')
@login_required # Only logged-in users can access
def dashboard():
    username = session.get('username')
    return render_template('dashboard.html', username=username)

# --- NEW: Admin-only Route ---
@auth_bp.route('/admin_panel')
@roles_required('admin') # Only users with the 'admin' role can access
def admin_panel():
    username = session.get('username')
    return render_template('admin_panel.html', username=username)