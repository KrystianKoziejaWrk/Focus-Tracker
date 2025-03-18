from flask import Flask, jsonify, request, send_from_directory, render_template, url_for, redirect, flash, session
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
# Google auth
from google.auth.transport.requests import Request
from google.oauth2 import id_token

from models import db, Users, FocusSession

#New imports
from flask_jwt_extended import JWTManager
from routes import auth

app = Flask(__name__)

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"  # SQLite for local testing
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

#security keys
app.config["SECRET_KEY"] = "supersecretkey"
app.config["JWT_SECRET_KEY"] = "jwtsecretkey"


#enable JWT
jwt = JWTManager(app)


# Initialize the database
db.init_app(app)

with app.app_context():
    db.create_all()

#register Blueprint
app.register_blueprint(auth, url_prefix="/auth")



@app.route("/")
def home():
    return render_template("base.html")

if __name__ == "__main__":
    app.run(debug=True)
