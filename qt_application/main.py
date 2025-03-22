from PyQt6.QtWidgets import QApplication, QMainWindow, QPushButton, QLabel, QVBoxLayout, QWidget, QLineEdit, QHBoxLayout
from PyQt6.QtGui import QFont
import sys
import time
import keyboard
import requests
import json
import webbrowser
from PyQt6.QtCore import QUrl, QEventLoop, QTimer, QThread, pyqtSignal
from PyQt6.QtNetwork import QNetworkAccessManager, QNetworkRequest, QNetworkReply
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading

from api_handler import send_focus_data

FLASK_API_URL = "http://127.0.0.1:5000/login"
GOOGLE_LOGIN_URL = "http://127.0.0.1:5000/google-login?source=pyqt"
GOOGLE_CALLBACK_URL = "http://127.0.0.1:5000/google/callback"

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
    token_received = pyqtSignal(str)

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

        print("DEBUG: Connecting token_received signal to handle_token_received slot")
        self.token_received.connect(self.handle_token_received)

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
        print("DEBUG: Opening Google login URL")
        webbrowser.open(GOOGLE_LOGIN_URL)
        self.start_local_server()

    def start_local_server(self):
        print("DEBUG: Starting local server")
        self.server_thread = threading.Thread(target=self.run_local_server, daemon=True)
        self.server_thread.start()

    def run_local_server(self):
        server_address = ('', 8000)
        httpd = HTTPServer(server_address, self.RequestHandler)
        self.RequestHandler.app = self  # Pass the app instance to the handler
        self.httpd = httpd
        print("DEBUG: Local server running on port 8000")
        httpd.serve_forever()

    class RequestHandler(BaseHTTPRequestHandler):
        app = None

    def do_GET(self):
        print(f"DEBUG: Received GET request: {self.path}")
        if self.path.startswith("/callback"):
            if "?" in self.path:
                query = self.path.split("?", 1)[1]
                try:
                    params = dict(qc.split("=") for qc in query.split("&"))
                    print("DEBUG: Parsed query parameters:", params)
                except Exception as e:
                    print("DEBUG: Error parsing query params:", e)
                    self.send_error(400, "Bad Request")
                    return
                jwt_token = params.get("access_token")
                if jwt_token:
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"Login successful! You can close this window.")
                    print(f"DEBUG: JWT token received in RequestHandler: {jwt_token}")
                    # Shutdown the server first.
                    self.server.shutdown()
                    print("DEBUG: Server shutdown initiated.")
                    # Use QTimer.singleShot with a 100ms delay to ensure the main event loop is ready.
                    def emit_token_signal():
                        print("DEBUG: Emitting token_received signal from QTimer callback")
                        self.app.token_received.emit(jwt_token)
                    QTimer.singleShot(100, emit_token_signal)
                    print("DEBUG: QTimer.singleShot scheduled to emit token_received signal.")
                else:
                    print("DEBUG: access_token not found in query parameters")
                    self.send_error(400, "Missing access_token")
            else:
                print("DEBUG: No query parameters found in callback URL")
                self.send_error(400, "No query parameters provided")



    def handle_token_received(self, jwt_token):
        print(f"DEBUG: Entered handle_token_received with token: {jwt_token}")
        try:
            save_token(jwt_token)
            self.status_label.setText("Login successful!")
            print("DEBUG: Token saved and status label updated")
            self.open_focus_tracker(jwt_token)
            print("DEBUG: FocusTracker should now be open")
        except Exception as e:
            print(f"DEBUG: Exception in handle_token_received: {e}")

    def open_focus_tracker(self, jwt_token):
        print(f"DEBUG: Opening FocusTracker with token: {jwt_token}")
        try:
            self.focus_tracker = FocusTracker(jwt_token)
            self.focus_tracker.show()
            self.focus_tracker.raise_()
            self.focus_tracker.activateWindow()
            print("DEBUG: FocusTracker is now visible")
            self.close()
        except Exception as e:
            print(f"DEBUG: Exception in open_focus_tracker: {e}")

    def closeEvent(self, event):
        if hasattr(self, 'httpd'):
            print("DEBUG: Shutting down HTTP server on close")
            self.httpd.shutdown()
        event.accept()

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
        print("DEBUG: FocusTracker initialized with token:", jwt_token)

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
        print("DEBUG: Loaded existing JWT token, launching FocusTracker")
        window = FocusTracker(jwt_token)
    else:
        print("DEBUG: No existing JWT token, launching LoginWindow")
        window = LoginWindow()

    window.show()
    sys.exit(app.exec())
