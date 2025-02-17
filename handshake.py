from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa  
from cryptography.hazmat.backends import default_backend
import binascii

app = Flask(__name__)

public_keys = {} # Dictionary to store public keys, keyed by user ID 
challenges = {}     # Collection of challenges

@app.route("/register", methods=["POST"])
def register():
    try:
        data = request.get_json()
        #print("data")
        #print(data)
        public_key_pem = data.get("public_key")

        if not public_key_pem:
            return jsonify({"status": "error", "message": "Missing public key"}), 400

        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            user_id = "user123" # Replace with actual user ID generation
            public_keys[user_id] = {"public_key":public_key}
            #print("user_id")
            #print(user_id)

        except Exception as e:
            return jsonify({"status": "error", "message": f"Invalid public key: {e}"}), 400

        challenge = "random_challenge".encode('utf-8')

        # ... (Store the challenge associated with the user - e.g., in the database or session)
        challenges[user_id] = challenge # Store challenge for later use.
        #print("register success:"+challenge.hex())
        return jsonify({"status": "success", "message": "Registration successful", "challenge": challenge.hex(), "user_id":user_id}) # Return challenge to client

    except (ValueError, KeyError, TypeError) as e:
        print("register error"+e)



@app.route("/verify", methods=["POST"])
def verify():
    print("\nhandshake.verify()")
    try:
        data = request.get_json()
        #print("data")
        #print(data)

        challenge = data.get("challenge").encode('utf-8') # Challenge comes as string
        signature_hex = data.get("signature")

        if not challenge or not signature_hex:
            return jsonify({"status": "error", "message": "Missing challenge or signature"}), 400
        
        signature = bytes.fromhex(signature_hex) # Convert hex back to bytes
        user_id = data.get("user_id")
        public_key = public_keys[user_id]["public_key"]
        stored_challenge = challenges.get(user_id) # Retrieve the stored challenge

        if not public_key or not stored_challenge:
            return jsonify({"status": "error", "message": "Public key or challenge not found"}), 401 # Unauthorized

        try:
            public_key.verify(
                signature,
                stored_challenge, # Use stored challenge for verification
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except Exception as e: # Catch any verification errors
            return jsonify({"status": "error", "message": f"Signature verification failed: {e}"}), 400

        # ... (If verification is successful, proceed with authentication) ...
        public_keys[user_id] = {"session_token":  "hard_coded_session_token"}
        print("public_keys[user_id]")
        print(public_keys[user_id])
        print("handshake.verify() success")
        return jsonify({"status": "success", "message": "Authentication successful", "session_token":"hard_coded_session_token"})

    except (ValueError, KeyError, TypeError) as e:        
        return jsonify({"status": "error", "message": f"An error occurred: {e}"}), 500

if __name__ == "__main__":
    app.run(debug=True)  # Set debug=False in production