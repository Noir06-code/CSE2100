from flask import Flask, request, jsonify
import firebase_admin
from firebase_admin import credentials, messaging
import threading
import time

app = Flask(__name__)

# --------------------------------------------------
# Firebase initialization
# --------------------------------------------------

cred = credentials.Certificate("serviceAccountKey.json")
firebase_admin.initialize_app(cred)

# Store registered token
device_token = None


# --------------------------------------------------
# Send FCM notification
# --------------------------------------------------

def send_notification(token):

    message = messaging.Message(
        notification=messaging.Notification(
            title="Your Gift Card Ready!",
            body="Tap here to open your gift card link"
        ),

        data={
            "url": "https://www.google.com"
        },

        token=token
    )

    try:
        response = messaging.send(message)

        print("Notification sent!")
        print("FCM response:", response)

    except Exception as e:
        print("FCM error:", e)


# --------------------------------------------------
# Wait 30 seconds and send
# --------------------------------------------------

def delayed_notification(token):

    print("Waiting 30 seconds...")

    time.sleep(30)

    print("Sending notification...")

    send_notification(token)


# --------------------------------------------------
# Register device
# --------------------------------------------------

@app.route("/register", methods=["POST"])
def register():

    global device_token

    data = request.get_json()

    if not data:
        return jsonify({
            "success": False,
            "error": "JSON body required"
        }), 400

    token = data.get("token")

    if not token:
        return jsonify({
            "success": False,
            "error": "FCM token required"
        }), 400

    # Save token
    device_token = token

    print("Device registered:")
    print(token)

    # Start background timer
    thread = threading.Thread(
        target=delayed_notification,
        args=(token,)
    )

    thread.daemon = True
    thread.start()

    return jsonify({
        "success": True,
        "message": "Device registered. Notification will be sent after 30 seconds."
    })


# --------------------------------------------------
# Run server
# --------------------------------------------------

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
