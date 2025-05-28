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

    # Ensure the instance folder exists for SQLite DB
    # Flask will create 'instance' if it doesn't exist for the DB file.
    INSTANCE_FOLDER_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance')