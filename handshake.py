from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa  
from cryptography.hazmat.backends import default_backend
import binascii
import time 
app = Flask(__name__)

# Dictionary to store public keys & session tokens by user ID 
# e.g PUBLIC_KEYS[user_id] = {
#   "public_key":public_key, 
#   "device": [{"type":"value"}] i.e. "mac_address"
#   "session_token":"hard_coded_session_token"
# }  
PUBLIC_KEYS = {}    
CHALLENGES = {}     # Collection of challenges by user_id 
TOKEN_EXPIRY_DURATION = 15 # Expires after 15 seconds (for POC)

#
# register receives public key and returns a challenge
#  
@app.route("/register", methods=["POST"])
def register():
    try:
        data = request.get_json()
        public_key_pem = data.get("public_key")
        device = data.get("device")

        if not public_key_pem:
            return jsonify({"status": "error", "message": "Missing public key"}), 400

        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            user_id = "user123" # Hard coded user (replace with a call to users table etc)
            PUBLIC_KEYS[user_id] = {"public_key":public_key}
            PUBLIC_KEYS[user_id]["device"] = device
        except Exception as e:
            print(e)
            return jsonify({"status": "error", "message": f"Invalid public key: {e}"}), 400

        challenge = "random_challenge".encode('utf-8') # Hard coded challenge @todo challenge is hash of key
        CHALLENGES[user_id] = challenge 
        return jsonify({"status": "success", "message": "Registration successful", "challenge": challenge.hex(), "user_id":user_id}) # Return challenge to client

    except (ValueError, KeyError, TypeError) as e:
        print("register error"+e)

#
# Verifies signature and challenge and creates a token 
#
@app.route("/verify", methods=["POST"])
def verify():
    global PUBLIC_KEYS
    print("=====\nhandshake.verify()")
    try:
        data = request.get_json()
        challenge = data.get("challenge").encode('utf-8') 
        signature_hex = data.get("signature")

        if not challenge or not signature_hex:
            return jsonify({"status": "error", "message": "Missing challenge or signature"}), 400
        
        signature = bytes.fromhex(signature_hex) # Convert hex back to bytes
        user_id = data.get("user_id") #@todo hash user_id
        public_key = PUBLIC_KEYS[user_id]["public_key"]
        stored_challenge = CHALLENGES.get(user_id) # Retrieve the stored challenge

        if not public_key or not stored_challenge:
            return jsonify({"status": "error", "message": "Public key or challenge not found"}), 401 # Unauthorized

        try:
            public_key.verify(
                signature,
                stored_challenge, 
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except Exception as e: # Catch any verification errors
            return jsonify({"status": "error", "message": f"Signature verification failed: {e}"}), 400

        # ... (If verification is successful, proceed with authentication) ...
        PUBLIC_KEYS[user_id]["session_token"] = "hard_coded_session_token"
        PUBLIC_KEYS[user_id]["session_token_create"] = time.time() 
        PUBLIC_KEYS[user_id]["session_token_expiry"] = time.time() + TOKEN_EXPIRY_DURATION
        print("handshake.verify() success")
        return jsonify({"status": "success", "message": "Authentication successful", "session_token":"hard_coded_session_token"})

    except (ValueError, KeyError, TypeError) as e:        
        return jsonify({"status": "error", "message": f"An error occurred: {e}"}), 500

#
# Verifies signature and challenge and creates a token 
#
@app.route("/interact", methods=["POST"])
def interact():
    global PUBLIC_KEYS
    print("====\nhandshake.interact()")
    try:
        data = request.get_json()
        current_user_id = data.get("user_id") 
        session_token = data.get("session_token") 
        print("Interact 1")
        if validate_token(current_user_id, session_token):
            print("Interact pass")
            return jsonify({"status": "success", "message": f"Interact OK", "outcome":"Hello World (Authenticated)"}) 
        else:
            print("Interact token expired")
            return jsonify({"status": "error", "message": "No valid session"}), 419
    except Exception as e: # Catch any verification errors
        return jsonify({"status": "error", "message": f"Session verification failed: {e}"}), 400


#
# Verifies signature and challenge and creates a token 
#
@app.route("/get_challenge", methods=["POST"])
def get_challenge():
    global CHALLENGES
    print("in get challenge")
    try:
        data = request.get_json()
        print("data")
        print(data)
        #device = data.get("device")
        current_user_id = data.get("user_id")
        print("user?",current_user_id)
        challenge = "new_random_challenge".encode('utf-8') # Hard coded challenge @todo challenge is hash of key
        print("challenge",current_user_id)
        CHALLENGES[current_user_id] = challenge 
        return jsonify({"status": "success", "message": "Registration successful", "challenge": challenge.hex(), "user_id":current_user_id}) # Return challenge to client
    except Exception as e: # Catch any verification errors
        print(e)
        return jsonify({"status": "error", "message": f"get_challenge error: {e}"}), 400



#
# Compare user session tokens match and the expiry hasn't been exceed
#
def validate_token(current_user_id, received_token):
    global PUBLIC_KEYS
    result = False
    if received_token == PUBLIC_KEYS[current_user_id]["session_token"]:
        session_token_expiry = PUBLIC_KEYS[current_user_id]["session_token_expiry"]
        # Check if the session token is still valid
        if time.time() <= session_token_expiry:
            result = True
    return result


if __name__ == "__main__":
    app.run(debug=True)  # Set debug=False in production