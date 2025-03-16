from flask import Flask, jsonify, request, send_from_directory, render_template, url_for, redirect, flash
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

# Google auth
from google.auth.transport.requests import Request
from google.oauth2 import id_token

from models import db, Users

app = Flask(__name__)

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"  # SQLite for local testing
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize the database
db.init_app(app)

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
