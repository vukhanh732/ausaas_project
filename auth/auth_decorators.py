# auth/auth_decorators.py
from functools import wraps
from flask import session, flash, redirect, url_for, request

def login_required(f):
    """
    Decorator to ensure a user is logged in to access a route.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            # Redirect to login page, remember 'next' URL for after login
            return redirect(url_for('auth.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def roles_required(*role_names):
    """
    Decorator to ensure a user has one of the specified roles to access a route.
    Usage: @roles_required('admin', 'moderator')
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Ensure user is logged in first
            if 'user_id' not in session:
                flash('Please log in to access this page.', 'danger')
                return redirect(url_for('auth.login', next=request.url))

            # Import User model here to avoid circular imports
            from auth.models import User 
            user = User.query.get(session['user_id'])
            
            if not user: # User ID in session but user not found (e.g., deleted account)
                session.clear() # Clear invalid session
                flash('Your session is invalid. Please log in again.', 'danger')
                return redirect(url_for('auth.login', next=request.url))

            # Check if user has any of the required roles
            if not any(user.has_role(role_name) for role_name in role_names):
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('home')) # Redirect to home or a 403 page
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator