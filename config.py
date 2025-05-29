import os

class Config:
    # General Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-very-secret-key-that-should-be-random' # VERY IMPORTANT: Change for production!
    FLASK_APP = os.environ.get('FLASK_APP') or 'app.py'

    # Database configuration
    # For production, consider environment variables for DATABASE_URL
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
                              'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance', 'ausaas.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False # Suppress warning

     # --- NEW Email Configuration ---
    MAIL_SERVER = os.environ.get('MAIL_SERVER') or 'sandbox.smtp.mailtrap.io' # e.g., 'smtp.gmail.com'
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 2525)             # e.g., 587 for TLS, 465 for SSL
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS') is not None         # True for TLS
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME') or '5e1371a21497bd' 
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') or 'ebb6322088efab'
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER') or 'no-reply@yourdomain.com'
    # --- END NEW Email Configuration ---

    # Ensure the instance folder exists for SQLite DB
    # Flask will create 'instance' if it doesn't exist for the DB file.
    INSTANCE_FOLDER_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance')