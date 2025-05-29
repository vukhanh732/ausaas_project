# auth/models.py
from app import db # Import db from the main app instance
from werkzeug.security import generate_password_hash, check_password_hash
from flask import current_app # Import current_app for app context in Role creation

# --- Association Table for Many-to-Many Relationship ---
# This is a helper table that doesn't need its own model
user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True)
)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    # --- NEW Email Verification Fields ---
    email = db.Column(db.String(120), unique=True, nullable=False) # Email address for verification
    is_email_verified = db.Column(db.Boolean, default=False, nullable=False) # Verification status
    # --- END NEW Email Verification Fields ---

    # Define relationship to roles
    roles = db.relationship('Role', secondary=user_roles, lazy='subquery',
                            backref=db.backref('users', lazy=True))

    def set_password(self, password):
        """Hashes the password and stores it."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Checks if the provided password matches the stored hash."""
        return check_password_hash(self.password_hash, password)

    # Helper methods for roles
    def has_role(self, role_name):
        """Checks if the user has a specific role."""
        return any(role.name == role_name for role in self.roles)

    def add_role(self, role_name):
        """Adds a role to the user, creating the role if it doesn't exist."""
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            role = Role(name=role_name)
            db.session.add(role)
            db.session.commit()

        if role not in self.roles:
            self.roles.append(role)
            db.session.commit()

    def __repr__(self):
        return f'<User {self.username}>'

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(255)) # Optional description for the role

    def __repr__(self):
        return f'<Role {self.name}>'

# Function to initialize default roles (optional but good for setup)
def init_roles(app):
    """Initializes default roles in the database if they don't already exist."""
    with app.app_context():
        if not Role.query.filter_by(name='admin').first():
            db.session.add(Role(name='admin', description='Administrator role'))
            current_app.logger.info("Added 'admin' role.")
        if not Role.query.filter_by(name='user').first():
            db.session.add(Role(name='user', description='Standard user role'))
            current_app.logger.info("Added 'user' role.")
        if not Role.query.filter_by(name='developer').first():
            db.session.add(Role(name='developer', description='Developer role with access to dev tools'))
            current_app.logger.info("Added 'developer' role.")
        if not Role.query.filter_by(name='it').first():
            db.session.add(Role(name='it', description='IT Support role for system maintenance'))
            current_app.logger.info("Added 'it' role.")
        db.session.commit()