from flask import Flask, jsonify, request, send_from_directory, render_template, url_for, redirect, flash

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

#Google auth
from google.auth.transport import requests
from google.oauth2 import id_token

from models import db, Users

app = Flask(__name__)


if __name__ == "__main__":
    app.run()