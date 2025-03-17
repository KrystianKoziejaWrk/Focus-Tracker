from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Users(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)  # Fixed naming
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=True)

    # Relationship with focus sessions
    sessions = db.relationship("FocusSession", back_populates="user", cascade="all, delete-orphan")




    #Constructors. We do not have to make 2 constructors
    def __init__(self, username, email, password=None):
        self.username = username
        self.email = email
        self.password = password



class FocusSession(db.Model):
    __tablename__ = "focus_sessions"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)  # Fixed table reference
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    duration = db.Column(db.Integer, nullable=True)
    end_time = db.Column(db.Datetime, nullale = False)
        


    duration = db.Column(db.Integer, nullable=False)  # Duration in minutes

    user = db.relationship("Users", back_populates="sessions")


    def __init__(self, user_id, duration, start_time = None):
        self.user_id = user_id
        self.duration = duration
        self.start_time = start_time