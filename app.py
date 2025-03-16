from flask import Flask, jsonify, request, send_from_directory, render_template, url_for, redirect, session, request, flash

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)


if __name__ == "__main__":
    app.run()