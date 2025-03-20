from flask import Blueprint, request, jsonify, flash, render_template, redirect, url_for, session, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request, get_jwt, set_access_cookies
from google.auth.transport import requests
from google.oauth2 import id_token
from flask_backend.models import db, Users, FocusSession
from datetime import datetime, timedelta
import pytz
import json
from requests_oauthlib import OAuth2Session

auth = Blueprint("auth", __name__)

#homepage route idk why i cant just put it insdie of app py
@auth.route("/")
def homepage():
    return render_template("homepage.html")

@auth.route("/list_users")
def list_users():
    users = Users.query.all()
    users_data = [{"id": user.id, "username": user.username, "email": user.email} for user in users]
    return jsonify(users_data)

#dashboard route
@auth.route("/dashboard")
@jwt_required()
def dashboard():
    try:
        verify_jwt_in_request()
        user_id = get_jwt_identity()
        user = Users.query.get(user_id)
        sessions = FocusSession.query.filter_by(user_id=user_id).all()

        return render_template("dashboard.html", sessions=sessions, user=user)
    except Exception as e:
        print("DEBUG: Dashboard access failed =>", e)
        flash(f"Dashboard access failed: {str(e)}", "danger")
        return redirect(url_for("auth.login"))

#loading google credentials form a file
with open("flask_backend/client_secret.json", "r") as f:
    google_creds = json.load(f)

GOOGLE_CLIENT_ID = google_creds["web"]["client_id"]
GOOGLE_CLIENT_SECRET = google_creds["web"]["client_secret"]
REDIRECT_URI = google_creds["web"]["redirect_uris"][0]

# OAuth config
google_auth = OAuth2Session(
    GOOGLE_CLIENT_ID,
    redirect_uri="http://127.0.0.1:5000/google/callback",
    scope=[
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
        "openid"
    ],
)

#Register account
@auth.route("/register", methods=["GET", "POST"])
def register():
    #If we get a post or update request from the template...
    if request.method == "POST":

        username = request.form["user_input"]
        email = request.form["email_input"]
        password = request.form["password_input"]

        user_check = Users.query.filter_by(email=email).first()
        if user_check:
            flash("User already exists!")
            return redirect(url_for("auth.register"))
        
        #hash the password
        hashed_password = generate_password_hash(password)

        #Creating the new user obejct
        user_object = Users(username = username, email = email, password = hashed_password,)
        db.session.add(user_object)
        db.session.commit()

        flash("Registration successful!")
        return redirect(url_for("auth.login"))
    
    return render_template("register.html")

#Default login account page
@auth.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email_input"]
        password = request.form["password_input"]

        user = Users.query.filter_by(email = email).first()
        #if the user does not exist or the password input is not the same then we are going to redirect back to login
        if not user or not check_password_hash(user.password, password):
            flash("Invalid email or password")
            return redirect(url_for("auth.login"))
        #Creating the java scrypt web token
        access_token = create_access_token(identity=user.id, expires_delta=timedelta(days=7))

        #store the jwt in the session
        session["jwt_token"] = access_token

        flash("Login successful!")
        return redirect(url_for("auth.dashboard"))
    
    return render_template("login.html")

#Super Cool Google login page
@auth.route("/google-login")
def google_login():
    # Redirect to the cool google login page
    authorization_url, state = google_auth.authorization_url(
        "https://accounts.google.com/o/oauth2/auth",
        access_type="offline",
        prompt="consent",
    )
    session["oauth_state"] = state
    print("DEBUG: Authorization URL =>", authorization_url)
    return redirect(authorization_url)

#Then when they sign up we got to send them back
@auth.route("/google/callback")
def google_callback():
    try:
        print("DEBUG: Trying to get token")
        # Exchange auth token for access token
        token = google_auth.fetch_token(
            "https://oauth2.googleapis.com/token",
            client_secret=GOOGLE_CLIENT_SECRET,
            authorization_response=request.url,
        )
        print("DEBUG: Token =>", token)  # Add this line for debugging

        # Get the user information
        user_info = google_auth.get("https://www.googleapis.com/oauth2/v3/userinfo").json()
        print("DEBUG: User Info =>", user_info)  # Add this line for debugging

        email = user_info["email"]
        username = user_info["name"]

        # See if the user already exists in the database
        user = Users.query.filter_by(email=email).first()
        if not user:
            # Create the new user account
            user = Users(username=username, email=email)
            db.session.add(user)
            db.session.commit()
            print("DEBUG: New user created =>", user)  # Add this line for debugging

        # Create a jwt token
        access_token = create_access_token(identity=str(user.id), expires_delta=timedelta(days=7))
        print("DEBUG: Access Token =>", access_token)  # Add this line for debugging

        # Store the jwt token in a cookie
        response = make_response(redirect(url_for("auth.dashboard")))
        set_access_cookies(response, access_token)
        print("DEBUG: JWT Token stored in cookie")  # Add this line for debugging

        flash("Login successful with Google!")
        return response
    except Exception as e:
        print("DEBUG: Google login failed =>", e)
        flash(f"Google login failed: {str(e)}", "danger")
        return redirect(url_for("auth.login"))

@auth.route("/logout")
def logout():
    session.pop("jwt_token", None) #Removes jwt token
    flash("Logout successful")
    return redirect(url_for("auth.homepage"))

"""
IMPORTANT STUFF FOR GETTING UPLOADING SESSION DATA AND GETTING IT AS WELL!!!!
"""

#First we are going to add a create session route
@auth.route("/add_session", methods=["POST"])
@jwt_required()
def add_session():
    user_id = get_jwt_identity()
    data = request.json
    duration = data.get("duration")

    new_session = FocusSession(user_id = user_id, duration = duration)
    db.session.add(new_session)
    db.session.commit()
    
    return jsonify({"message": "Focus session added!"}) , 201

#getting the user sessions
@auth.route("/get_sessions", methods=["GET"])
@jwt_required()
def get_sessions():
    user_id = get_jwt_identity()
    user = Users.query.get(user_id)

    #These are all the focus session datas that we are going to want to display
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
