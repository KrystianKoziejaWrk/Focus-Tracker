import requests

# Flask API endpoint (Update this with your actual deployed backend URL)
FLASK_API_URL = "https://learnhowyouwork-91f5c3d6eadf.herokuapp.com/add_session"

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
        "Content-Type": "application/json"
    }
    
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