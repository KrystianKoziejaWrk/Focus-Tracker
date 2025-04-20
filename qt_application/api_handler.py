import requests

# Flask API endpoints
FLASK_API_URL = "https://learnhowyouwork-91f5c3d6eadf.herokuapp.com/add_session"
CSRF_TOKEN_URL = "https://learnhowyouwork-91f5c3d6eadf.herokuapp.com/get_csrf_token"

def get_csrf_token():
    """
    Fetches the CSRF token from the backend.
    """
    try:
        response = requests.get(CSRF_TOKEN_URL)
        if response.status_code == 200:
            csrf_token = response.json().get("csrf_token")
            print(f"DEBUG: CSRF token fetched: {csrf_token}")
            return csrf_token
        else:
            print(f"DEBUG: Failed to fetch CSRF token: {response.status_code}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"DEBUG: Error fetching CSRF token: {e}")
        return None

def send_focus_data(duration, jwt_token):
    """
    Sends the focus session data to the backend API.

    Parameters:
        duration (int): Duration of the focus session in minutes.
        jwt_token (str): JWT authentication token for the user.

    Returns:
        dict: API response.
    """
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "Content-Type": "application/json",
        "X-Source": "pyqt"  # Add this header to identify PyQt requests
    }

    # Fetch the CSRF token
    csrf_token = get_csrf_token()
    if (csrf_token):
        headers["X-CSRFToken"] = csrf_token  # Add the CSRF token to the headers

    payload = {"duration": duration}
    print(f"DEBUG: Sending focus session data with duration: {duration}")
    print(f"DEBUG: JWT token: {jwt_token}")

    try:
        response = requests.post(FLASK_API_URL, json=payload, headers=headers)
        print(f"DEBUG: Received response: {response.status_code} - {response.text}")
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"DEBUG: Request failed with error: {e}")
        return {"error": str(e)}