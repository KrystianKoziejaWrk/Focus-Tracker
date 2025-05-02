# flask_backend/routes.py
from flask import Blueprint, request, jsonify, flash, render_template, redirect, url_for, session, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    create_access_token,
    jwt_required,
    get_jwt_identity,
    verify_jwt_in_request,
    get_jwt,
    set_access_cookies,
    unset_jwt_cookies
)
from google.auth.transport import requests
from google.oauth2 import id_token
from flask_backend.models import db, Users, FocusSession
from datetime import datetime, timedelta, timezone
import pytz
import json
from requests_oauthlib import OAuth2Session
import bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Email, Length
from flask_limiter.util import get_remote_address
# Import the limiter from the extensions module
from flask_backend.extensions import limiter
import base64
import os
from flask_wtf.csrf import CSRFError

# Define a login form
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])

# Hash the password
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)

# Verify the password
def verify_password(password, hashed_password):
    # Ensure the hashed password is in bytes
    if isinstance(hashed_password, str):
        hashed_password = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

# Define a dummy csrf_exempt decorator if not available
try:
    from flask_wtf.csrf import csrf_exempt
except ImportError:
    def csrf_exempt(func):
        return func

auth = Blueprint("auth", __name__)

# List of common time zones
COMMON_TIMEZONES = [
    "UTC",
    "US/Eastern",
    "US/Central",
    "US/Mountain",
    "US/Pacific",
    "Europe/London",
    "Europe/Berlin",
    "Asia/Tokyo",
    "Australia/Sydney"
]

# Homepage route
@auth.route("/")
def homepage():
    try:
        verify_jwt_in_request(optional=True)
        user_id = get_jwt_identity()
        user = Users.query.get(user_id) if user_id else None
    except Exception as e:
        print("DEBUG: Homepage access failed =>", e)
        user = None

    # Count total users and focus session entries
    total_users = Users.query.count()
    total_entries = FocusSession.query.count()
    print(f"DEBUG: Total users: {total_users}, Total entries: {total_entries}")

    return render_template("homepage.html", user=user, total_users=total_users, total_entries=total_entries)

@auth.route("/list_users")
def list_users():
    users = Users.query.all()
    users_data = [{"id": user.id, "username": user.username, "email": user.email} for user in users]
    return jsonify(users_data)

@auth.route("/chart_data", methods=["GET"])
@jwt_required()
def chart_data():
    user_id = get_jwt_identity()
    user = Users.query.get(user_id)
    # Use user's timezone; default to UTC if not set.
    user_timezone = user.timezone if user and user.timezone else "UTC"
    local_tz = pytz.timezone(user_timezone)

    # Get the current time in the user's timezone.
    now_local = datetime.now(local_tz)
    print(f"DEBUG: Current local time: {now_local}")

    # Adjust weekday so Sunday is 0, Monday is 1, ..., Saturday is 6
    adjusted_weekday = now_local.weekday() # monday = 0 sunday = 6
    adjusted_weekday = (adjusted_weekday + 1) % 7
    print(f"DEBUG: Adjusted weekday (Sunday=0): {adjusted_weekday}")

    # Determine the most recent Sunday (start of the week).
    start_of_week = now_local - timedelta(days=adjusted_weekday)
    start_of_week = start_of_week.replace(hour=0, minute=0, second=0, microsecond=0)

    # Determine the end of the week (Saturday).
    end_of_week = start_of_week + timedelta(days=6, hours=23, minutes=59, seconds=59)

    print(f"DEBUG: Start of week (local): {start_of_week}")
    print(f"DEBUG: End of week (local): {end_of_week}")

    # Build labels for each day of the week (in user timezone).
    labels = []
    for i in range(7):
        day = start_of_week + timedelta(days=i)
        print(f"DEBUG: Day being added: {day.weekday()}")
        labels.append(day.strftime("%Y-%m-%d"))

    # Convert the week boundaries back to UTC for querying.
    start_of_week_utc = start_of_week.astimezone(pytz.utc)
    end_of_week_utc = end_of_week.astimezone(pytz.utc)

    print(f"DEBUG: Start of week (UTC): {start_of_week_utc}")
    print(f"DEBUG: End of week (UTC): {end_of_week_utc}")

    # Query sessions for the current week.
    sessions = FocusSession.query.filter(
        FocusSession.user_id == user_id,
        FocusSession.start_time >= start_of_week_utc,
        FocusSession.start_time <= end_of_week_utc
    ).all()

    # Initialize a dictionary with each day as key and 0 duration.
    durations_dict = {label: 0 for label in labels}

    # For each session, convert its start_time to the user's timezone and add its duration.
    for s in sessions:
        utc_time = s.start_time
        if utc_time.tzinfo is None:
            utc_time = utc_time.replace(tzinfo=pytz.utc)
        local_time = utc_time.astimezone(local_tz)
        day_str = local_time.strftime("%Y-%m-%d")
        if day_str in durations_dict:
            durations_dict[day_str] += s.duration

    # Build the durations list in the order of labels.
    durations = [durations_dict[label] for label in labels]

    return jsonify({"labels": labels, "data": durations})

@auth.route("/change_timezone", methods=["POST"])
@csrf_exempt  # Disable CSRF protection for this route
@jwt_required()
def change_timezone():
    user_id = get_jwt_identity()
    new_timezone = request.form.get("timezone")
    user = Users.query.get(user_id)
    if user:
        user.timezone = new_timezone
        db.session.commit()
        flash("Time zone updated successfully!", "success")
    else:
        flash("User not found.", "danger")
    return redirect(url_for("auth.dashboard"))

@auth.route("/dashboard")
@jwt_required()  # Requires a valid JWT token
def dashboard():
    try:
        user_id = get_jwt_identity()  # Get the user ID from the JWT token
        user = Users.query.get(user_id)
        print("DEBUG: User timezone is now:", user.timezone)
        sessions = FocusSession.query.filter_by(user_id=user_id).all()
        user_timezone = user.timezone if user and user.timezone else "UTC"

        # Convert session times to the user's timezone
        def convert_to_local_time(utc_time):
            if utc_time.tzinfo is None:
                utc_time = utc_time.replace(tzinfo=timezone.utc)
            local_tz = pytz.timezone(user_timezone)
            return utc_time.astimezone(local_tz)

        sessions_converted = []
        for s in sessions:
            local_time = convert_to_local_time(s.start_time)
            print(f"DEBUG: Session {s.id} UTC: {s.start_time}, Local: {local_time}")
            sessions_converted.append({
                "id": s.id,
                "start_time": local_time.strftime("%Y-%m-%d %H:%M:%S"),
                "end_time": convert_to_local_time(s.end_time).strftime("%Y-%m-%d %H:%M:%S") if s.end_time else "Ongoing",
                "duration": s.duration
            })

        return render_template("dashboard.html", sessions=sessions_converted, user=user, timezones=COMMON_TIMEZONES)
    except Exception as e:
        print("DEBUG: Dashboard access failed =>", e)
        flash(f"Dashboard access failed: {str(e)}", "danger")
        return redirect(url_for("auth.login"))

# Google OAuth configuration
encoded_json = os.getenv("GOOGLE_CLIENT_SECRET_JSON")
if encoded_json:
    google_creds = json.loads(base64.b64decode(encoded_json).decode("utf-8"))
else:
    raise RuntimeError("GOOGLE_CLIENT_SECRET_JSON is not set")

GOOGLE_CLIENT_ID = google_creds["web"]["client_id"]
GOOGLE_CLIENT_SECRET = google_creds["web"]["client_secret"]

# Determine the environment and set the redirect URI
if os.getenv("FLASK_ENV") == "production":
    REDIRECT_URI = "https://learnhowyouwork-91f5c3d6eadf.herokuapp.com/google/callback"
else:
    REDIRECT_URI = "http://127.0.0.1:5000/google/callback"

google_auth = OAuth2Session(
    GOOGLE_CLIENT_ID,
    redirect_uri=REDIRECT_URI,
    scope=[
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
        "openid"
    ],
)  

@auth.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["user_input"]
        email = request.form["email_input"]
        password = request.form["password_input"]

        # Check if the user already exists
        user_check = Users.query.filter_by(email=email).first()
        if user_check:
            flash("User already exists!")
            return redirect(url_for("auth.login"))
        
        # Hash the password before storing it
        hashed_password = hash_password(password).decode('utf-8')  # Decode bytes to string
        user_object = Users(username=username, email=email, password=hashed_password)
        db.session.add(user_object)
        db.session.commit()
        print("DEBUG: User created =>", user_object)
        flash("Registration successful!")
        return redirect(url_for("auth.dashboard"))
    
    return render_template("register.html")

# adding the website version for tracking so we can actually use it
# on other os!
@auth.route("/focus-tracker")
def focus_tracker():
    return render_template("focus_tracker.html")

@auth.route("/login", methods=["GET", "POST"])
@csrf_exempt  # Disable CSRF protection for this route
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        email = request.form["email_input"]
        password = request.form["password_input"]

        user = Users.query.filter_by(email=email).first()
        if not user or not verify_password(password, user.password):
            flash("Invalid email or password")
            return redirect(url_for("auth.login"))

        access_token = create_access_token(identity=str(user.id), expires_delta=timedelta(days=7))
        response = make_response(redirect(url_for("auth.dashboard")))
        set_access_cookies(response, access_token)
        flash("Login successful!")
        return response

    return render_template("login.html")

@auth.route("/google-login")
def google_login():
    source = request.args.get("source", "web")
    print(f"DEBUG: login_source from session => {source}")
    authorization_url, state = google_auth.authorization_url(
        "https://accounts.google.com/o/oauth2/auth",
        access_type="offline",
        prompt="consent",
    )
    session["oauth_state"] = state
    print(f"DEBUG: oauth_state set in session => {state}")
    print(f"DEBUG: oauth_state from session => {session.get('oauth_state')}")
    session["login_source"] = source
    print("DEBUG: Authorization URL =>", authorization_url)
    return redirect(authorization_url)

@auth.route("/google/callback")
def google_callback():
    print("DEBUG: /google/callback route hit")
    try:
        state = session.get("oauth_state")
        if not state:
            print("DEBUG: State missing from session")
            return jsonify({"msg": "State missing from session"}), 400

        google = OAuth2Session(
            GOOGLE_CLIENT_ID,
            redirect_uri=REDIRECT_URI,
            state=state
        )
        token = google.fetch_token(
            "https://oauth2.googleapis.com/token",
            client_secret=GOOGLE_CLIENT_SECRET,
            authorization_response=request.url,
        )
        print("DEBUG: Token =>", token)

        user_info = google.get("https://www.googleapis.com/oauth2/v3/userinfo").json()
        print("DEBUG: User Info =>", user_info)

        email = user_info["email"]
        username = user_info["name"]

        # Check if the user exists or create a new one
        user = Users.query.filter_by(email=email).first()
        if not user:
            user = Users(username=username, email=email)
            db.session.add(user)
            db.session.commit()
            print("DEBUG: New user created =>", user)

        # Generate access token for the user
        access_token = create_access_token(identity=str(user.id), expires_delta=timedelta(days=7))
        print("DEBUG: Access Token =>", access_token)

        source = session.get("login_source", "web")
        print(f"DEBUG: login_source from session => {source}")

        if source != "pyqt":
            response = make_response(redirect(url_for("auth.dashboard")))
            set_access_cookies(response, access_token)  # Store JWT token in cookies
            print("DEBUG: JWT Token stored in cookie")
            flash("Login successful with Google!")
            return response
        else:
            print("DEBUG: Redirecting to PyQt application with access token")
            return redirect(f"http://127.0.0.1:8000/callback?access_token={access_token}")
    except Exception as e:
        print("DEBUG: Google login failed =>", e)
        return jsonify({"msg": f"Google login failed: {str(e)}"}), 401

@auth.route("/logout")
def logout():
    response = make_response(redirect(url_for("auth.homepage")))
    unset_jwt_cookies(response)
    flash("Logout successful")
    return response

@csrf_exempt
@auth.route("/add_session", methods=["POST"])
@jwt_required()
def add_session():
    # Check if the request is from PyQt
    if request.args.get("source") == "pyqt" or request.headers.get("X-Source") == "pyqt":
        print("DEBUG: CSRF exemption applied for PyQt request")
    else:
        # Perform CSRF validation for non-PyQt requests
        try:
            csrf.protect()
        except CSRFError as e:
            print(f"DEBUG: CSRF validation failed: {e}")
            return jsonify({"msg": "CSRF token is missing or invalid"}), 400

    # Process the request
    user_id = get_jwt_identity()
    data = request.get_json()
    print("DEBUG: Received JSON data in /add_session:", data)
    if not data:
        return jsonify({"msg": "No JSON data provided"}), 400
    duration = data.get("duration")
    if duration is None:
        return jsonify({"msg": "Duration is required"}), 400
    print(f"DEBUG: Received focus session data with duration: {duration}")
    print(f"DEBUG: User ID from JWT: {user_id}")
    new_session = FocusSession(user_id=user_id, duration=duration)
    db.session.add(new_session)
    db.session.commit()
    print("DEBUG: Focus session added to the database")
    return jsonify({"message": "Focus session added!"}), 201

@auth.route("/get_sessions", methods=["GET"])
@jwt_required()
def get_sessions():
    user_id = get_jwt_identity()
    user = Users.query.get(user_id)
    sessions = FocusSession.query.filter_by(user_id=user_id).all()
    user_timezone = user.timezone
    def convert_to_local_time(utc_time):
        local_tz = pytz.timezone(user_timezone)
        return utc_time.astimezone(local_tz)
    sessions_data = [
        {
            "id": s.id,
            "start_time": convert_to_local_time(s.start_time).strftime("%Y-%m-%d %H:%M:%S"),
            "end_time": convert_to_local_time(s.end_time).strftime("%Y-%m-%d %H:%M:%S"),
            "duration": s.duration
        }
        for s in sessions
    ]
    return jsonify(sessions_data)

@auth.route("/get_csrf_token", methods=["GET"])
def get_csrf_token():
    csrf_token = generate_csrf()
    return jsonify({"csrf_token": csrf_token})