from flask import Flask, jsonify, request, send_from_directory, render_template, url_for, redirect, flash, session
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
# Google auth
from google.auth.transport.requests import Request
from google.oauth2 import id_token

from models import db, Users, FocusSession

app = Flask(__name__)

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"  # SQLite for local testing
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


# Initialize the database
db.init_app(app)

with app.app_context():
    db.create_all()


@app.route("/")
def home():
    render_template("base.html")


'''
All of this is the user authentication
so we got the google and default logins
'''

#Creating the approutes for logging in and logging out
@app.route("/signup", methods=["POST","GET"])
def signup():
    if request.method == "POST":

        session.permanent = True

        user_name = request.form["user_name_input"]
        session["user_name"] = user_name

        user_email = request.form["user_email_input"]
        session["user_email"] = user_email

        user_password = request.form["user_password_input"]
        session["user_password"] = user_email

        






if __name__ == "__main__":
    app.run(debug=True)
