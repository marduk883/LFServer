from functools import wraps
from flask import session, redirect, url_for, flash

def login_required(f):
    """
    Decorator to protect routes that require login.
    If the user is not logged in, they are redirected to the login page.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" in session:
            # User is logged in, proceed with the original function
            return f(*args, **kwargs)
        else:
            # User is not logged in, flash a message and redirect to login page
            flash(message="You must log in to view this page", category="danger")
            return redirect(url_for("login"))
    return decorated_function