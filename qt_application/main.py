from PyQt6.QtWidgets import QApplication, QMainWindow, QPushButton, QLabel, QVBoxLayout, QWidget, QLineEdit, QHBoxLayout
from PyQt6.QtGui import QFont
import sys
import time
import keyboard
import requests
import json
import webbrowser

from api_handler import send_focus_data

FLASK_API_URL = "http://127.0.0.1:5000/login"
GOOGLE_LOGIN_URL = "http://127.0.0.1:5000/google-login"

def save_token(token):
    with open("token.json", "w") as f:
        json.dump({"jwt_token": token}, f)

def load_token():
    try:
        with open("token.json", "r") as f:
            data = json.load(f)
            return data.get("jwt_token")
    except FileNotFoundError:
        return None

def clear_token():
    with open("token.json", "w") as f:
        json.dump({"jwt_token": ""}, f)

class LoginWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Login")
        self.setGeometry(100, 100, 400, 300)

        layout = QVBoxLayout()

        self.email_input = QLineEdit(self)
        self.email_input.setPlaceholderText("Enter email")
        self.email_input.setFont(QFont("Arial", 12))

        self.password_input = QLineEdit(self)
        self.password_input.setPlaceholderText("Enter Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setFont(QFont("Arial", 12))

        self.login_button = QPushButton("Login", self)
        self.login_button.setFont(QFont("Arial", 12))
        self.login_button.clicked.connect(self.login)

        self.google_login_button = QPushButton("Login with Google", self)
        self.google_login_button.setFont(QFont("Arial", 12))
        self.google_login_button.clicked.connect(self.google_login)

        self.status_label = QLabel("")
        self.status_label.setFont(QFont("Arial", 12))

        layout.addWidget(self.email_input)
        layout.addWidget(self.password_input)
        layout.addWidget(self.login_button)
        layout.addWidget(self.google_login_button)
        layout.addWidget(self.status_label)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def login(self):
        email = self.email_input.text()
        password = self.password_input.text()
        print(f"DEBUG: Sending login request with email: {email}")

        response = requests.post(FLASK_API_URL, json={"email": email, "password": password})

        if response.status_code == 200:
            jwt_token = response.json().get("access_token")
            save_token(jwt_token)
            self.status_label.setText("Login successful!")
            print("DEBUG: Login successful, JWT token received")

            self.close()
            self.open_focus_tracker(jwt_token)
        else:
            self.status_label.setText("Login failed.")
            print("DEBUG: Login failed, status code:", response.status_code)

    def google_login(self):
        webbrowser.open(GOOGLE_LOGIN_URL)

    def open_focus_tracker(self, jwt_token):
        self.focus_tracker = FocusTracker(jwt_token)
        self.focus_tracker.show()

class FocusTracker(QMainWindow):
    def __init__(self, jwt_token):
        super().__init__()

        self.jwt_token = jwt_token
        self.focus_active = False
        self.start_time = None

        self.setWindowTitle("Focus Tracker")
        self.setGeometry(100, 100, 400, 300)

        layout = QVBoxLayout()
        self.status_label = QLabel("Status: Not Tracking")
        self.status_label.setFont(QFont("Arial", 12))

        self.logout_button = QPushButton("Logout", self)
        self.logout_button.setFont(QFont("Arial", 12))
        self.logout_button.clicked.connect(self.logout)

        layout.addWidget(self.status_label)
        layout.addWidget(self.logout_button)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        keyboard.add_hotkey("ctrl+shift+f", self.toggle_focus)

    def toggle_focus(self):
        if not self.focus_active:
            self.start_time = time.time()
            self.focus_active = True
            self.status_label.setText("Status: Focused (Press Ctrl+Shift+F to stop)")
        else:
            duration = int(time.time() - self.start_time)
            send_focus_data(duration, self.jwt_token)

            self.focus_active = False
            self.status_label.setText("Status: Not Tracking (Press Ctrl+Shift+F to Start)")

    def logout(self):
        clear_token()
        self.close()
        self.login_window = LoginWindow()
        self.login_window.show()

if __name__ == "__main__":
    app = QApplication(sys.argv)

    jwt_token = load_token()

    if jwt_token:
        window = FocusTracker(jwt_token)
    else:
        window = LoginWindow()

    window.show()
    sys.exit(app.exec())
