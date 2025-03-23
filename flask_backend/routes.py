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
    return render_template("homepage.html", user=user)

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
    # Determine the most recent Sunday.
    # Python's weekday() gives Monday=0 ... Sunday=6.
    # If today is Sunday (6), then days_to_subtract = 0; otherwise, subtract (weekday+1) days.
    days_to_subtract = (now_local.weekday() + 1) % 7
    start_of_week = now_local - timedelta(days=days_to_subtract)
    # Set time to the start of that day.
    start_of_week = start_of_week.replace(hour=0, minute=0, second=0, microsecond=0)
    end_of_week = start_of_week + timedelta(days=6, hours=23, minutes=59, seconds=59)

    # Build labels for each day of the week (in user timezone).
    labels = []
    for i in range(7):
        day = start_of_week + timedelta(days=i)
        # You can format the day as you like.
        labels.append(day.strftime("%Y-%m-%d"))

    # Convert the week boundaries back to UTC for querying,
    # assuming your stored timestamps are in UTC.
    start_of_week_utc = start_of_week.astimezone(pytz.utc)
    end_of_week_utc = end_of_week.astimezone(pytz.utc)

    # Query sessions for the current week.
    sessions = FocusSession.query.filter(
        FocusSession.user_id == user_id,
        FocusSession.start_time >= start_of_week_utc,
        FocusSession.start_time <= end_of_week_utc
    ).all()

    # Initialize a dictionary with each day as key and 0 duration.
    durations_dict = {label: 0 for label in labels}

    # For each session, convert its start_time to the user's timezone,
    # then add its duration (assumed to be in seconds) to the corresponding day.
    for s in sessions:
        # Ensure the time is UTC-aware.
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



# Time zone change route
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

# Dashboard route
@auth.route("/dashboard")
@jwt_required()
def dashboard():
    try:
        user_id = get_jwt_identity()
        user = Users.query.get(user_id)
        print("DEBUG: User timezone is now:", user.timezone)
        sessions = FocusSession.query.filter_by(user_id=user_id).all()
        user_timezone = user.timezone if user and user.timezone else "UTC"

        def convert_to_local_time(utc_time):
            # If the datetime is naive, assume it's in UTC.
            if utc_time.tzinfo is None:
                utc_time = utc_time.replace(tzinfo=timezone.utc)
            local_tz = pytz.timezone(user_timezone)
            return utc_time.astimezone(local_tz)

        # Build a list of sessions with converted times
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
with open("flask_backend/client_secret.json", "r") as f:
    google_creds = json.load(f)

GOOGLE_CLIENT_ID = google_creds["web"]["client_id"]
GOOGLE_CLIENT_SECRET = google_creds["web"]["client_secret"]
REDIRECT_URI = google_creds["web"]["redirect_uris"][0]

google_auth = OAuth2Session(
    GOOGLE_CLIENT_ID,
    redirect_uri=REDIRECT_URI,
    scope=[
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
        "openid"
    ],
)

# Register account
@auth.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["user_input"]
        email = request.form["email_input"]
        password = request.form["password_input"]

        user_check = Users.query.filter_by(email=email).first()
        if user_check:
            flash("User already exists!")
            return redirect(url_for("auth.login"))
        
        hashed_password = generate_password_hash(password)
        user_object = Users(username=username, email=email, password=hashed_password)
        db.session.add(user_object)
        db.session.commit()
        print("DEBUG: User created =>", user_object)
        flash("Registration successful!")
        return redirect(url_for("auth.dashboard"))
    
    return render_template("register.html")

# Default login account page
@auth.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.is_json:
            data = request.get_json()
            email = data.get("email")
            password = data.get("password")
            print(f"DEBUG: Received JSON login request with email: {email}")
        else:
            email = request.form["email_input"]
            password = request.form["password_input"]
            print(f"DEBUG: Received form login request with email: {email}")

        user = Users.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            print("DEBUG: Invalid email or password")
            if request.is_json:
                return jsonify({"msg": "Invalid email or password"}), 401
            else:
                flash("Invalid email or password")
                return redirect(url_for("auth.login"))

        access_token = create_access_token(identity=str(user.id), expires_delta=timedelta(days=7))

        if request.is_json:
            print("DEBUG: Login successful, returning JSON response")
            return jsonify({"access_token": access_token})
        else:
            response = make_response(redirect(url_for("auth.dashboard")))
            set_access_cookies(response, access_token)
            print("DEBUG: JWT Token stored in cookie")
            flash("Login successful!")
            return response

    return render_template("login.html")

# Google login page
@auth.route("/google-login")
def google_login():
    source = request.args.get("source", "web")
    authorization_url, state = google_auth.authorization_url(
        "https://accounts.google.com/o/oauth2/auth",
        access_type="offline",
        prompt="consent",
    )
    session["oauth_state"] = state
    session["login_source"] = source
    print("DEBUG: Authorization URL =>", authorization_url)
    return redirect(authorization_url)

# Google callback
@auth.route("/google/callback")
def google_callback():
    try:
        state = session.get("oauth_state")
        if not state:
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

        user = Users.query.filter_by(email=email).first()
        if not user:
            user = Users(username=username, email=email)
            db.session.add(user)
            db.session.commit()
            print("DEBUG: New user created =>", user)

        access_token = create_access_token(identity=str(user.id), expires_delta=timedelta(days=7))
        print("DEBUG: Access Token =>", access_token)

        source = session.get("login_source", "web")
        if source == "pyqt":
            print("DEBUG: Redirecting to PyQt application with access token")
            return redirect(f"http://127.0.0.1:8000/callback?access_token={access_token}")
        else:
            response = make_response(redirect(url_for("auth.dashboard")))
            set_access_cookies(response, access_token)
            print("DEBUG: JWT Token stored in cookie")
            flash("Login successful with Google!")
            return response
    except Exception as e:
        print("DEBUG: Google login failed =>", e)
        return jsonify({"msg": f"Google login failed: {str(e)}"}), 401

@auth.route("/logout")
def logout():
    response = make_response(redirect(url_for("auth.homepage")))
    unset_jwt_cookies(response)
    flash("Logout successful")
    return response

# Place csrf_exempt as the outermost decorator for this API endpoint.
@csrf_exempt
@auth.route("/add_session", methods=["POST"])
@jwt_required()
def add_session():
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
