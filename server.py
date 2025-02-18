from flask import Flask, request, jsonify
from flasgger import Swagger
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa  
from cryptography.hazmat.backends import default_backend
import time
import jwt 
app = Flask(__name__)
swagger = Swagger(app)


DEVICE_LIST = {}                # A list of devices by user_id / limits 1 device to 1 user 
CHALLENGES = {}                 # Collection of challenges by user_id 
TOKEN_EXPIRY_DURATION = 15      # Expires after 15 seconds (for POC)
SECRET_KEY = "temporary_key"    # Used to seed JWT token

#
# register receives public key and returns a challenge
#  
@app.route("/register", methods=["POST"])
def register():
    """
    Registers a device on the device list.
    ---
    parameters:
      - name: username
        in: body
        required: true
        type: string
      - name: password
        in: body
        required: true
        type: string
      - name: public_key
        in: body
        required: true
        type: string
      - name: device
        in: body
        required: true
        schema:
          type: object
          properties:
            type:
              type: string
              example: "mac_address"
            value:
              type: string        
              example: "XX.XX.XX.XX.XX"
    responses:
      200:
        description: Device registered successfully
        schema:
          type: object
          properties:
            user_id:
              type: string
            challenge:
              type: string         
      400:
        description: Bad request
    """

    try:
        data = request.get_json()
        public_key_pem = data.get("public_key")
        device = data.get("device")
        username = data.get("username")
        password = data.get("password")

        if not public_key_pem:
            return jsonify({"status": "error", "message": "Missing public key"}), 400

        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            user_id = validate_user(username, password)
            DEVICE_LIST[user_id] = {"public_key":public_key}
            DEVICE_LIST[user_id]["device"] = device
        except Exception as e:
            print(e)
            return jsonify({"status": "error", "message": f"Invalid public key: {e}"}), 400

        challenge = make_challenge()
        CHALLENGES[user_id] = challenge 
        print("\n/register is returning a challenge")
        return jsonify({"status": "success", "message": "Registration successful", "challenge": challenge.hex(), "user_id":user_id}) # Return challenge to client

    except (ValueError, KeyError, TypeError) as e:
        print("register error"+e)

#
# Verifies signature and challenge and creates a token 
#
@app.route("/verify", methods=["POST"])
def verify():
    """
   Verifies the signature of the device
    ---
    parameters:
      - name: user_id
        in: body
        required: true
        type: string
      - name: challenge
        in: body
        required: true
        type: string
      - name: signature
        in: body
        required: true
        type: string
    responses:
      200:
        description: Device registered successfully
        schema:
          type: object
          properties:
            session_token:
              type: string
      400:
        description: Bad request
      401:
        description: Unauthorised request
      500:
        description: Internal error
    """

    global DEVICE_LIST
    try:
        data = request.get_json()
        challenge = data.get("challenge").encode('utf-8') 
        signature_hex = data.get("signature")

        if not challenge or not signature_hex:
            return jsonify({"status": "error", "message": "Missing challenge or signature"}), 400
        
        signature = bytes.fromhex(signature_hex) # Convert hex back to bytes
        user_id = data.get("user_id") #@todo hash user_id
        public_key = DEVICE_LIST[user_id]["public_key"]
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

        # Create a JWT token
        token_data = {
            "user_id": user_id,
            "session_token_create": time.time(), # Set create time
            "session_token_expiry": time.time() + TOKEN_EXPIRY_DURATION  # Set expiration time
        }
        jwt_token = jwt.encode(token_data, SECRET_KEY, algorithm="HS256")
        DEVICE_LIST[user_id]["session_token"] = jwt_token
        print("\n/verify is returning a token")
        return jsonify({"status": "success", "message": "Authentication successful", "session_token": jwt_token})

    except (ValueError, KeyError, TypeError) as e:        
        return jsonify({"status": "error", "message": f"An error occurred: {e}"}), 500

#
# Verifies signature and challenge and creates a token 
#
@app.route("/interact", methods=["POST"])
def interact():
    """
    Simulation of a client's interaction with the server.
    ---
    parameters:
      - name: Authorization
        in: header
        type: string
        required: true
        description: Bearer token
    responses:
      200:
        description: Interaction was successful
        schema:
          type: object
          properties:
            outcome:
              type: string
      400:
        description: Bad request
      401:
        description: Unauthorized
      419:
        description: Token has expired
    """
    global DEVICE_LIST
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return jsonify({"status": "error", "message": "Authorization header missing"}), 401

        if not auth_header.startswith("Bearer "):
            return jsonify({"status": "error", "message": "Invalid authorization header format"}), 401

        # Extract the token from the header
        session_token = auth_header.split(" ")[1]  
        if validate_token(session_token):
            print("\n/interact token is valid so returning a response")
            return jsonify({"status": "success", "message": f"Interact OK", "outcome":"Hello World (Authenticated)"}) 
        else:
            print("\n/interact token is invalid so returning a 419 error")
            return jsonify({"status": "error", "message": "No valid session"}), 419
    except Exception as e: # Catch any verification errors
        return jsonify({"status": "error", "message": f"Session verification failed: {e}"}), 400


#
# generates challenge to a user_id 
#
@app.route("/get_challenge", methods=["POST"])
def get_challenge():
    """
    Generates a new challenge for a user with a registered device.
    ---
    parameters:
      - name: user_id
        in: body
        required: true
        type: string
      - name: device
        in: body
        required: true
        schema:
          type: object
          properties:
            type:
              type: string
              example: "mac_address"
            value:
              type: string        
              example: "XX.XX.XX.XX.XX"
    responses:
      200:
        description: New challenge generatedsuccessfully
        schema:
          type: object
          properties:
            challenge:
              type: string         
      400:
        description: Bad request
    """
    global CHALLENGES
    try:
        data = request.get_json()
        current_device = data.get("device") 
        user_id = data.get("user_id")
        listed_device = DEVICE_LIST[user_id]['device']
        if current_device == listed_device:
            challenge = make_challenge()
            CHALLENGES[user_id] = challenge 
            print("\n/get_challenge valid user_id & device so return new challenge")
            return jsonify({"status": "success", "message": "Registration successful", "challenge": challenge.hex(), "user_id":user_id}) # Return challenge to client
        else:
            return jsonify({"status": "error", "message": f"devices do not match: {e}"}), 400
    except Exception as e: # Catch any verification errors
        print(e)
        return jsonify({"status": "error", "message": f"get_challenge error: {e}"}), 400


#
# Compare user session tokens match and the expiry hasn't been exceed
#
def validate_token(received_token):
    global DEVICE_LIST, SECRET_KEY
    result = False
    try:
        decoded_payload = jwt.decode(received_token, SECRET_KEY, algorithms=["HS256"])
        user_id = decoded_payload["user_id"]  
        session_token_expiry = decoded_payload["session_token_expiry"] 
        # Check token exists 
        if received_token == DEVICE_LIST[user_id]["session_token"]:
            # Check if the session token is still valid
            if time.time() <= session_token_expiry:
                result = True
        return result
    except Exception as e: 
        return False


#
# validate_user: hard codes a user_id but this is a stub to look up database, registry  
#
def validate_user(username, password):
    # pasword is probably hashlib.sha256()
    return "user123"

def make_challenge():
    # Hard coded challenge should be dynamic seeded based on user_id & device
    return "random_challenge".encode('utf-8') 

if __name__ == "__main__":
    app.run(debug=True) 