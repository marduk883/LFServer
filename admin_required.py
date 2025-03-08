from functools import wraps
from flask import session, redirect, url_for, flash

def admin_required(f):
    """
    Decorator to protect routes that require admin access.
    If the user is not an admin, they are redirected to the mainpage.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" in session and "user_type" in session and session["user_type"] == "admin":
            # User is an admin, proceed with the original function
            return f(*args, **kwargs)
        else:
            # User is not an admin, flash a message and redirect to mainpage
            return redirect(url_for("404"))
    return decorated_function