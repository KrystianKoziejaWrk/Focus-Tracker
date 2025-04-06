# flask_backend/app.py
from flask import Flask, jsonify, request, render_template, url_for, redirect, flash, session
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, set_access_cookies, unset_jwt_cookies
from flask_wtf.csrf import CSRFProtect, generate_csrf
from google.auth.transport.requests import Request
from google.oauth2 import id_token
from flask_backend.models import db, Users, FocusSession
from flask_backend.routes import auth  # Import the blueprint
from dotenv import load_dotenv
import os

# Import the limiter from the new extensions module
from flask_backend.extensions import limiter

# Load environment variables from .env file
load_dotenv()

FLASK_API_URL = os.getenv("FLASK_API_URL", "http://127.0.0.1:5000")
GOOGLE_LOGIN_URL = os.getenv("GOOGLE_LOGIN_URL", "http://127.0.0.1:5000/google-login?source=pyqt")

app = Flask(__name__)

# Initialize the limiter with the Flask app
limiter.init_app(app)

jwt = JWTManager(app)

# Custom handler for missing or invalid JWT tokens
@jwt.unauthorized_loader
def custom_unauthorized_response(err):
    return redirect(url_for("auth.login"))

# For development, disable CSRF entirely (do not disable in production!)
app.config["WTF_CSRF_ENABLED"] = False
csrf = CSRFProtect(app)

# Use environment variables for configuration
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# JWT config
app.config["JWT_TOKEN_LOCATION"] = ["cookies", "headers"]  # Accept JWT tokens from both cookies and headers
app.config["JWT_COOKIE_SECURE"] = True  # Only send cookies over HTTPS
app.config["JWT_COOKIE_HTTPONLY"] = True  # Prevent JavaScript access to cookies
app.config["JWT_COOKIE_CSRF_PROTECT"] = False  # Disable JWT cookie CSRF protection for development

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Initialize the database and JWT
db.init_app(app)

with app.app_context():
    db.create_all()

# Register the blueprint
app.register_blueprint(auth, url_prefix='/')

# Ensure CSRF token is available in all templates
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf())

if __name__ == "__main__":
    app.run(debug=True)
