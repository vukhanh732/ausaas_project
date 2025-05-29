# auth/routes.py
from flask import Blueprint, render_template, redirect, url_for, flash, request, session, current_app
import itsdangerous
from auth.forms import RegistrationForm, LoginForm, UserRolesForm, AddRoleForm, DeleteRoleForm # TwoFactorSetupForm removed
from auth.models import User, Role # Ensure User is imported
from app import db, mail # NEW: Import 'mail' from app
from auth.auth_decorators import login_required, roles_required
from itsdangerous import URLSafeTimedSerializer # NEW: For generating time-limited tokens
from flask_mail import Message # NEW: For sending emails

auth_bp = Blueprint('auth', __name__)

# --- Configure Token Serializer (for email verification) ---
# This needs app context or SECRET_KEY
def get_serializer():
    # Ensure app context is available if called outside a request
    # This is slightly redundant as get_serializer is called within send_verification_email which has app_context.
    # But good for robustness if called differently.
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY'])

# --- NEW: Email Verification Route ---
@auth_bp.route('/verify_email/<token>')
def verify_email(token):
    serializer = get_serializer()
    try:
        email = serializer.loads(token, salt='email-verification-salt', max_age=3600) # Token valid for 1 hour
    except (itsdangerous.SignatureExpired, itsdangerous.BadTimeSignature): 
        flash('The verification link is invalid or has expired.', 'danger')
        current_app.logger.warning(f"Invalid or expired verification token received: {token}")
        return redirect(url_for('auth.resend_verification_email')) # Will create this route later

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Verification failed: User not found.', 'danger')
        current_app.logger.warning(f"Verification attempt for non-existent email: {email}")
        return redirect(url_for('auth.register')) # Suggest registration

    if user.is_email_verified:
        flash('Your email is already verified. You can log in.', 'info')
        return redirect(url_for('auth.login'))

    user.is_email_verified = True
    try:
        db.session.commit()
        flash('Your email address has been successfully verified! You can now log in.', 'success')
        current_app.logger.info(f"User '{user.username}' email verified.")
    except Exception as e:
        db.session.rollback()
        flash('An error occurred during verification. Please try again.', 'danger')
        current_app.logger.error(f"Error verifying email for user '{user.username}' ({email}): {e}", exc_info=True)

    return redirect(url_for('auth.login'))

# --- Helper to Send Verification Email ---
def send_verification_email(user):
    serializer = get_serializer()
    # Token valid for 3600 seconds (1 hour)
    token = serializer.dumps(user.email, salt='email-verification-salt') 
    
    verification_url = url_for('auth.verify_email', token=token, _external=True)
    
    msg = Message(
        "Verify Your Email for AUSAAS Account",
        sender=current_app.config['MAIL_DEFAULT_SENDER'],
        recipients=[user.email]
    )
    # Render email body from a template
    msg.html = render_template('email_verification.html', username=user.username, verification_url=verification_url)
    
    mail.send(msg)
    current_app.logger.info(f"Verification email sent to {user.email}.")

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data # NEW: Get email
        password = form.password.data

        new_user = User(username=username, email=email) # NEW: Pass email
        new_user.set_password(password)
        new_user.is_email_verified = False # NEW: Set to False initially

        try:
            db.session.add(new_user)
            db.session.commit()
            
            # NEW: Send verification email
            send_verification_email(new_user)

            flash('Registration successful! Please check your email to verify your account.', 'success')
            return redirect(url_for('auth.login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'danger')
            current_app.logger.error(f"Error during registration for user '{username}' ({email}): {e}", exc_info=True)
    
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
            session['user_roles'] = [role.name for role in user.roles]
            
            if remember_me:
                session.permanent = True 
                current_app.logger.info(f"User '{username}' logged in (remembered). Roles: {session['user_roles']}")
            else:
                session.permanent = False
                current_app.logger.info(f"User '{username}' logged in (session). Roles: {session['user_roles']}")

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
    session.pop('user_roles', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@auth_bp.route('/dashboard')
@login_required
def dashboard():
    username = session.get('username')
    user_roles = session.get('user_roles', [])
    return render_template('dashboard.html', username=username, user_roles=user_roles)

@auth_bp.route('/admin_panel')
@roles_required('admin')
def admin_panel():
    username = session.get('username')
    user_roles = session.get('user_roles', [])
    return render_template('admin_panel.html', username=username, user_roles=user_roles)

@auth_bp.route('/manage_users', methods=['GET'])
@roles_required('admin')
def manage_users():
    users = User.query.all()
    all_roles = Role.query.all()

    user_forms = []
    for user in users:
        form = UserRolesForm(obj=user)
        form.roles.choices = [(r.id, r.name) for r in all_roles]
        form.roles.default = [role.id for role in user.roles]
        form.process()

        user_forms.append({'user': user, 'form': form})
        
    return render_template('manage_users.html', user_forms=user_forms)

@auth_bp.route('/update_user_roles/<int:user_id>', methods=['POST'])
@roles_required('admin')
def update_user_roles(user_id):
    user = User.query.get_or_404(user_id)
    
    all_roles = Role.query.all()
    form = UserRolesForm()
    form.roles.choices = [(r.id, r.name) for r in all_roles]

    if form.validate_on_submit():
        # Clear existing roles and assign new ones
        user.roles.clear() # Clear existing roles
        for role_id in form.roles.data:
            role = Role.query.get(role_id)
            if role:
                user.roles.append(role)
        
        try:
            db.session.commit()
            flash(f"Roles for user '{user.username}' updated successfully!", 'success')
        except Exception as e:
            db.session.rollback()
            flash(f"Error updating roles for user '{user.username}'.", 'danger')
            current_app.logger.error(f"Error updating roles for user '{user.username}': {e}", exc_info=True)
    else:
        flash(f"Form validation failed for user '{user.username}'. Please check your selections.", 'danger')
        current_app.logger.warning(f"Role update validation failed for user '{user.username}': {form.errors}")

    return redirect(url_for('auth.manage_users'))

@auth_bp.route('/roles_management', methods=['GET', 'POST'])
@roles_required('admin')
def roles_management():
    add_form = AddRoleForm()
    delete_form = DeleteRoleForm()

    # Handle POST for Add Role
    if add_form.validate_on_submit() and request.form.get('submit') == 'Add Role':
        new_role_name = add_form.name.data
        new_role_description = add_form.description.data

        new_role = Role(name=new_role_name, description=new_role_description)
        try:
            db.session.add(new_role)
            db.session.commit()
            flash(f"Role '{new_role_name}' added successfully!", 'success')
            return redirect(url_for('auth.roles_management'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error adding role '{new_role_name}'.", 'danger')
            current_app.logger.error(f"Error adding role '{new_role_name}': {e}", exc_info=True)
    
    # Handle POST for Delete Role
    if delete_form.validate_on_submit() and request.form.get('submit') == 'Delete Role':
        role_id_to_delete = delete_form.role_to_delete.data
        role_to_delete_obj = Role.query.get(role_id_to_delete)

        if role_to_delete_obj and role_to_delete_obj.name not in ['admin', 'user']: # Safety check
            try:
                # Remove role from all users first
                for user in role_to_delete_obj.users:
                    user.roles.remove(role_to_delete_obj)
                db.session.delete(role_to_delete_obj)
                db.session.commit()
                flash(f"Role '{role_to_delete_obj.name}' deleted successfully!", 'success')
                return redirect(url_for('auth.roles_management'))
            except Exception as e:
                db.session.rollback()
                flash(f"Error deleting role '{role_to_delete_obj.name}'.", 'danger')
                current_app.logger.error(f"Error deleting role '{role_to_delete_obj.name}': {e}", exc_info=True)
        else:
            flash("Cannot delete core 'admin' or 'user' roles, or role not found.", 'danger')
    
    all_roles = Role.query.order_by(Role.name).all()
    return render_template('roles_management.html', add_form=add_form, delete_form=delete_form, all_roles=all_roles)