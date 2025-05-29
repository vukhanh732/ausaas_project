# app.py
from flask import Flask, render_template, redirect, url_for, session, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message # NEW: Import Mail and Message (and Message, though Message is used in routes.py)
from config import Config
import os
import logging
import click
from flask.cli import with_appcontext


# Initialize database
db = SQLAlchemy()
mail = Mail() # NEW: Initialize Mail

# Configure logging for the main app
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    app.secret_key = app.config['SECRET_KEY'] 
    
    if not os.path.exists(app.instance_path):
        os.makedirs(app.instance_path)

    db.init_app(app)
    mail.init_app(app) # NEW: Initialize Mail with the app

    # Register Blueprints
    from auth import auth_bp # Import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')

    # --- Register Custom CLI Commands within create_app() ---
    app.cli.add_command(init_app_data_command)
    # --- END NEW ---

    # --- Main Application Routes (Non-auth) ---
    @app.route('/')
    def home():
        username = session.get('username')
        user_roles = session.get('user_roles', []) # Pass roles to home template
        return render_template('home.html', username=username, user_roles=user_roles)

    # --- Error Handling ---
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('error.html', code=404, message="The page you requested could not be found."), 404

    @app.errorhandler(403)
    def forbidden_access(e):
        return render_template('error.html', code=403, message="You do not have permission to access this resource."), 403

    @app.errorhandler(500)
    def internal_server_error(e):
        current_app.logger.error(f"Internal Server Error: {e}", exc_info=True)
        return render_template('error.html', code=500, message="An unexpected error occurred on the server. Please try again later."), 500


    return app

# --- Custom CLI Command Definition ---
# --- Custom CLI Command Definition ---
@click.command('init-app-data')
@with_appcontext
def init_app_data_command():
    """Initializes the database, creates default roles, and optionally creates an admin user."""
    from auth.models import User, Role, init_roles # Import models and init_roles
    
    click.echo('Creating all database tables...')
    db.create_all() # Create tables
    click.echo('Database tables created.')

    click.echo('Initializing default roles (admin, user, developer, it)...')
    init_roles(current_app) # Initialize roles using the app context
    click.echo('Default roles initialized.')

    all_roles = Role.query.all()
    role_choices = [(str(r.id), r.name) for r in all_roles]
    
    admin_username = click.prompt("Enter desired admin username (or leave blank to skip admin creation)", default="")
    if admin_username:
        user = User.query.filter_by(username=admin_username).first()
        
        if not user:
            # --- NEW: Prompt for Admin Email ---
            admin_email = click.prompt("Enter admin email")
            # --- END NEW ---
            admin_password = click.prompt("Enter admin password", hide_input=True, confirmation_prompt=True)
            # --- NEW: Pass email to User constructor ---
            user = User(username=admin_username, email=admin_email)
            # --- END NEW ---
            user.set_password(admin_password)
            db.session.add(user)
            db.session.commit()
            click.echo(f"User '{admin_username}' created.")
        else:
            click.echo(f"User '{admin_username}' already exists. Skipping creation.")

        # ... (rest of the role assignment logic) ...
        selected_role_ids = click.prompt(
            f"Assign roles to '{admin_username}' (comma-separated IDs from {all_roles}):",
            type=str,
            default="1" # Default to 'admin' role ID
        ).split(',')
        
        assigned_roles_names = []
        for role_id_str in selected_role_ids:
            try:
                role_id = int(role_id_str.strip())
                role = Role.query.get(role_id)
                if role:
                    if role not in user.roles:
                        user.roles.append(role)
                        assigned_roles_names.append(role.name)
            except ValueError:
                click.echo(f"Warning: Invalid role ID '{role_id_str}'. Skipping.")
        
        if assigned_roles_names:
            db.session.commit()
            click.echo(f"Assigned roles: {', '.join(assigned_roles_names)} to user '{admin_username}'.")
        else:
            click.echo(f"No valid roles assigned to user '{admin_username}'.")
        
    else:
        click.echo("User creation skipped.")

    click.echo("Application data initialization complete.")

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)