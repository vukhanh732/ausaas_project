from flask import Flask, render_template, redirect, url_for, session, current_app 
from flask_sqlalchemy import SQLAlchemy
from config import Config
import os
import logging
import click
from flask.cli import with_appcontext


# Initialize database
db = SQLAlchemy()

# Configure logging for the main app
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    app.secret_key = app.config['SECRET_KEY'] 
    
    if not os.path.exists(app.instance_path):
        os.makedirs(app.instance_path)

    db.init_app(app)

    # Register Blueprints
    from auth import auth_bp # Import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')

    # --- Register Custom CLI Commands within create_app() ---
    # This ensures the Flask CLI discovers the command when it loads the app factory.
    app.cli.add_command(init_app_data_command) # This line now goes here
    # --- END NEW ---

    # --- Main Application Routes (Non-auth) ---
    @app.route('/')
    def home():
        username = session.get('username')
        return render_template('home.html', username=username)

    # --- Error Handling ---
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('error.html', code=404, message="The page you requested could not be found."), 404

    @app.errorhandler(403) # NEW: Forbidden error handler
    def forbidden_access(e):
        return render_template('error.html', code=403, message="You do not have permission to access this resource."), 403

    @app.errorhandler(500) # NEW: Internal Server Error handler
    def internal_server_error(e):
        # Log the full error for debugging in development, but show generic message to user
        current_app.logger.error(f"Internal Server Error: {e}", exc_info=True)
        return render_template('error.html', code=500, message="An unexpected error occurred on the server. Please try again later."), 500

    return app

# --- Custom CLI Command Definition (MOVED OUTSIDE create_app) ---
# This function is now outside `create_app`, but its registration is inside it.
@click.command('init-app-data') # Register this function as a CLI command
@with_appcontext # Ensures the Flask app context is available
def init_app_data_command():
    """Initializes the database, creates default roles, and optionally creates an admin user."""
    from auth.models import User, Role, init_roles # Import models and init_roles
    
    click.echo('Creating all database tables...')
    db.create_all() # Create tables
    click.echo('Database tables created.')

    click.echo('Initializing default roles (admin, user)...')
    # Use current_app from Flask, as we're in an app context (provided by @with_appcontext)
    init_roles(current_app) # Initialize roles using the app context
    click.echo('Default roles initialized.')

    # Check if an admin user already exists, if not, prompt to create one
    admin_username = click.prompt("Enter desired admin username (or leave blank to skip admin creation)", default="")
    if admin_username:
        if not User.query.filter_by(username=admin_username).first():
            admin_password = click.prompt("Enter admin password", hide_input=True, confirmation_prompt=True)
            new_admin_user = User(username=admin_username)
            new_admin_user.set_password(admin_password)
            db.session.add(new_admin_user)
            db.session.commit()
            
            new_admin_user.add_role('admin') # Assign admin role
            db.session.commit()
            click.echo(f"Admin user '{admin_username}' created and assigned 'admin' role.")
        else:
            click.echo(f"Admin user '{admin_username}' already exists. Skipping creation.")
            existing_admin = User.query.filter_by(username=admin_username).first()
            if not existing_admin.has_role('admin'):
                existing_admin.add_role('admin')
                db.session.commit()
                click.echo(f"Assigned 'admin' role to existing user '{admin_username}'.")
    else:
        click.echo("Admin user creation skipped.")

    click.echo("Application data initialization complete.")


# --- Update the if __name__ == '__main__': block ---
# This block is only executed when app.py is run directly (e.g., `python app.py`),
# not when `flask <command>` is used.
if __name__ == '__main__':
    app = create_app()
    # No longer call db.create_all() or init_roles() or register_cli_commands() directly here.
    # Everything is now handled by the custom CLI command discovered by `flask init-app-data`.
    # The `app.cli.add_command` is inside `create_app()`
    app.run(debug=True) # debug=True is for development only!