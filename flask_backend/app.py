from flask import Flask, jsonify, request, send_from_directory, render_template, url_for, redirect, flash, session
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, set_access_cookies, unset_jwt_cookies


# Google auth
from google.auth.transport.requests import Request
from google.oauth2 import id_token

from flask_backend.models import db, Users, FocusSession
from flask_backend.routes import auth

import os

app = Flask(__name__)

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"  # SQLite for local testing
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


# Security keys
app.config["SECRET_KEY"] = "supersecretkey"
app.config["JWT_SECRET_KEY"] = "jwtsecretkey"

# JWT config
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_SECURE"] = False  # Set to True in production with HTTPS


"""THIS IS THE MOST INSECURE CODE IN 20202022020202022020205 PLEASE DO NOT DEPLOY APP UNTILL THIS IS CHANGED"""
#This is the whole google error we got please look at this before deploying bro please!!!!!!!!!!!!!
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'


#enable JWT
jwt = JWTManager(app)
# Initialize the database
db.init_app(app)

with app.app_context():
    db.create_all()

#register Blueprint
app.register_blueprint(auth)

if __name__ == "__main__":
    app.run(debug=True)