import pytz
from flask import session, redirect
from functools import wraps
from pytz import utc

# Factor in different timezones and store under UTC for consistency.
def convert_utc_to_local(utc_dt):
    if "timezone" in session:
        local_tz = pytz.timezone(session["timezone"])
        return utc_dt.replace(tzinfo=utc).astimezone(local_tz)
    return utc_dt

# Define the login_requirement from user.
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get("user_id")
        if user_id is None:
            return redirect ("/login")
        return f(*args, **kwargs)
    
    return decorated_function

# Define a password_valid for users.
def valid_password(password):
    """Check password length, digit, and symbol."""
    symbols_used = "!@#$%&'"
    
    if len(password) < 5 or len(password) > 8:
        return ("Password must have 5 to 8 characters, a number and a symbol.", 401)
    elif not any(char.isdigit() for char in password):
        return ("Password must have 5 to 8 characters, a number and a symbol.", 401)
    elif not any(char in symbols_used for char in password):
        return ("Password must have 5 to 8 characters, a number and a symbol.", 401)
    
    # Means valid.
    return None  
    
    
