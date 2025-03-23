from flask import Flask, jsonify, request, send_from_directory, render_template, url_for, redirect, flash, session
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, set_access_cookies, unset_jwt_cookies
from flask_wtf.csrf import CSRFProtect, generate_csrf

# Google auth
from google.auth.transport.requests import Request
from google.oauth2 import id_token

from flask_backend.models import db, Users, FocusSession
from flask_backend.routes import auth

import os

app = Flask(__name__)
csrf = CSRFProtect(app)

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"  # SQLite for local testing
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Security keys
app.config["SECRET_KEY"] = "supersecretkey"
app.config["JWT_SECRET_KEY"] = "jwtsecretkey"

# JWT config
app.config["JWT_TOKEN_LOCATION"] = ["cookies", "headers"]  # Accept JWT tokens from both cookies and headers
app.config["JWT_COOKIE_SECURE"] = False  # Set to True in production with HTTPS
app.config["JWT_COOKIE_CSRF_PROTECT"] = False  # Disable JWT cookie CSRF protection for development

"""THIS IS THE MOST INSECURE CODE IN 20202022020202022020205 PLEASE DO NOT DEPLOY APP UNTIL THIS IS CHANGED"""
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Initialize the database
db.init_app(app)
jwt = JWTManager(app)

with app.app_context():
    db.create_all()

# Register Blueprint
app.register_blueprint(auth, url_prefix='/')  # Ensure the blueprint is registered with the correct prefix

# Ensure CSRF token is available in all templates by returning it directly.
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf())

if __name__ == "__main__":
    app.run(debug=True)
