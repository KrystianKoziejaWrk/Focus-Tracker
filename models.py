from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import pytz

db = SQLAlchemy()

class Users(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)  # Fixed naming
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=True)
    timezone = db.Column(db.String(50), default="UTC")
    

    # Relationship with focus sessions
    sessions = db.relationship("FocusSession", back_populates="user", cascade="all, delete-orphan")

    #Constructors. We do not have to make 2 constructors
    def __init__(self, username, email, password=None, timezone="UTC"):
        self.username = username
        self.email = email
        self.password = password
        self.timezone = timezone



class FocusSession(db.Model):
    __tablename__ = "focus_sessions"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)  # Fixed table reference



    start_time = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(pytz.utc))
    end_time = db.Column(db.DateTime(timezone=True), nullable=True)

    duration = db.Column(db.Integer, nullable=False)

    user = db.relationship("Users", back_populates="sessions")

    def __init__(self, user_id, duration):
        self.user_id = user_id
        self.duration = duration
        self.start_time = datetime.now(pytz.utc)
        self.end_time = (self.start_time + timedelta(minutes=duration)).astimezone(pytz.utc) # Calculating the end time based off the duration
