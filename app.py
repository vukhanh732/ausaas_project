from flask import Flask, render_template, redirect, url_for, session # Added session
from flask_sqlalchemy import SQLAlchemy
from config import Config
import os

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # --- NEW: Set app.secret_key for session management ---
    app.secret_key = app.config['SECRET_KEY'] 
    
    if not os.path.exists(app.instance_path):
        os.makedirs(app.instance_path)

    db.init_app(app)

    from auth import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')

    @app.route('/')
    def home():
        # --- NEW: Pass user data to home template ---
        username = session.get('username') # Get username from session
        return render_template('home.html', username=username) # Pass it to the template

    @app.errorhandler(404)
    def page_not_found(e):
        return "<h1>404</h1><p>The page you requested could not be found.</p>", 404

    return app

if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        db.create_all()
        print("Database tables created.")

    app.run(debug=True)