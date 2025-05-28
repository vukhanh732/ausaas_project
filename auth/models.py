# auth/models.py
from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask import current_app # Import current_app for app context in Role creation

# --- NEW: Association Table for Many-to-Many Relationship ---
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

    # --- NEW: Define relationship to roles ---
    # `secondary=user_roles` specifies the association table
    # `backref='users'` creates a .users attribute on Role to get users associated with that role
    roles = db.relationship('Role', secondary=user_roles, lazy='subquery',
                            backref=db.backref('users', lazy=True))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # --- NEW: Helper methods for roles ---
    def has_role(self, role_name):
        return any(role.name == role_name for role in self.roles)

    def add_role(self, role_name):
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            # Create the role if it doesn't exist
            role = Role(name=role_name)
            db.session.add(role)
            db.session.commit() # Commit new role first to get an ID

        if role not in self.roles:
            self.roles.append(role)
            db.session.commit() # Commit user's role change

    def __repr__(self):
        return f'<User {self.username}>'

# --- NEW: Role Model ---
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(255)) # Optional description for the role

    def __repr__(self):
        return f'<Role {self.name}>'

# --- NEW: Function to initialize default roles (optional but good for setup) ---
def init_roles(app):
    with app.app_context():
        # Check if roles exist, create if not
        if not Role.query.filter_by(name='admin').first():
            db.session.add(Role(name='admin', description='Administrator role'))
            current_app.logger.info("Added 'admin' role.")
        if not Role.query.filter_by(name='user').first():
            db.session.add(Role(name='user', description='Standard user role'))
            current_app.logger.info("Added 'user' role.")
        db.session.commit()