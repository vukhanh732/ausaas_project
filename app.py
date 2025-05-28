from flask import Flask, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from config import Config
import os # For instance folder creation

# Initialize database
db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Ensure the instance folder exists for SQLite DB
    # This folder is where SQLite database files usually reside
    if not os.path.exists(app.instance_path):
        os.makedirs(app.instance_path)

    db.init_app(app)

    # Register Blueprints
    from auth import auth_bp # Import the Blueprint from auth/__init__.py
    app.register_blueprint(auth_bp, url_prefix='/auth') # All auth routes will start with /auth

    # --- Main Application Routes (Non-auth) ---
    @app.route('/')
    def home():
        return render_template('home.html')

    # --- Error Handling (Example) ---
    @app.errorhandler(404)
    def page_not_found(e):
        return "<h1>404</h1><p>The page you requested could not be found.</p>", 404

    return app

if __name__ == '__main__':
    app = create_app()
    
    # Create database tables if they don't exist
    with app.app_context():
        db.create_all()
        print("Database tables created.")

    app.run(debug=True) # debug=True is for development only!