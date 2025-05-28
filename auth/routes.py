from flask import Blueprint, render_template, redirect, url_for, flash, request, session, current_app
from auth.forms import RegistrationForm, LoginForm, UserRolesForm, AddRoleForm, DeleteRoleForm
from auth.models import User, Role
from app import db
from auth.auth_decorators import login_required, roles_required 

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

@auth_bp.route('/admin_panel')
@roles_required('admin') # Only users with the 'admin' role can access
def admin_panel():
    username = session.get('username')
    return render_template('admin_panel.html', username=username)

# --- NEW: User Management Routes ---
@auth_bp.route('/manage_users', methods=['GET'])
@roles_required('admin') # Only admins can access this page
def manage_users():
    # Fetch all users
    users = User.query.all()
    # Fetch all available roles
    all_roles = Role.query.all()

    # Create a form for each user for role assignment
    user_forms = []
    for user in users:
        # Create a form instance for this specific user
        form = UserRolesForm(obj=user) # Populate form with user's current roles

        # Dynamically set role choices based on all available roles
        form.roles.choices = [(r.id, r.name) for r in all_roles]

        # Select the roles the user currently has
        form.roles.default = [role.id for role in user.roles]
        form.process() # Process to apply default selections

        user_forms.append({'user': user, 'form': form})

    return render_template('manage_users.html', user_forms=user_forms)

@auth_bp.route('/update_user_roles/<int:user_id>', methods=['POST'])
@roles_required('admin') # Only admins can submit this form
def update_user_roles(user_id):
    user = User.query.get_or_404(user_id)

    # Create a form instance, dynamically populate choices before validation
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

# --- NEW: Role Management Routes ---
@auth_bp.route('/roles_management', methods=['GET', 'POST'])
@roles_required('admin') # Only admins can access this page
def roles_management():
    add_form = AddRoleForm()
    delete_form = DeleteRoleForm()

    # Handle POST for Add Role
    if add_form.validate_on_submit() and request.form.get('submit') == 'Add Role': # Check which form was submitted
        new_role_name = add_form.name.data
        new_role_description = add_form.description.data

        new_role = Role(name=new_role_name, description=new_role_description)
        try:
            db.session.add(new_role)
            db.session.commit()
            flash(f"Role '{new_role_name}' added successfully!", 'success')
            return redirect(url_for('auth.roles_management')) # Redirect to clear form
        except Exception as e:
            db.session.rollback()
            flash(f"Error adding role '{new_role_name}'.", 'danger')
            current_app.logger.error(f"Error adding role '{new_role_name}': {e}", exc_info=True)

    # Handle POST for Delete Role
    if delete_form.validate_on_submit() and request.form.get('submit') == 'Delete Role': # Check which form was submitted
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
                return redirect(url_for('auth.roles_management')) # Redirect to clear form
            except Exception as e:
                db.session.rollback()
                flash(f"Error deleting role '{role_to_delete_obj.name}'.", 'danger')
                current_app.logger.error(f"Error deleting role '{role_to_delete_obj.name}': {e}", exc_info=True)
        else:
            flash("Cannot delete core 'admin' or 'user' roles, or role not found.", 'danger')

    # If GET request or form validation fails, render the page
    all_roles = Role.query.order_by(Role.name).all() # Fetch all roles for display
    return render_template('roles_management.html', add_form=add_form, delete_form=delete_form, all_roles=all_roles)