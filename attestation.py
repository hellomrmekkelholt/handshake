from flask import Flask, request, jsonify
from flasgger import Swagger
import base64
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from asn1crypto import cms
import time
import jwt 
import json

app = Flask(__name__)
swagger = Swagger(app)

CHALLENGES = {}                 # Collection of nonces  
CHALLENGE_EXPIRY = 10           # Challenges remain valid for 10 seconds
SECRET_KEY = "temporary_key"    # Example used to sign JWT token (instead of using the Server's private key)
TOKEN_EXPIRY_DURATION = 15      # Time the token expires is short 15 seconds for testing

# Mockup of precached Apple Public Keys (Replace with real keys)
APPLE_PUBLIC_KEYS = {
    "key1": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYFK4EEAAoDQgAEfakekey1...\n-----END PUBLIC KEY-----\n",
    "key2": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYFK4EEAAoDQgAEfakekey2...\n-----END PUBLIC KEY-----\n",
}

  
@app.route("/login", methods=["POST"])
def login(username, password):
    """
    Validates user, before returning a challenge to the Client to use for an attestation request.
    ---
    parameters:
      - name: username
        in: body
        type: string
        required: true
      - name: password
        in: body
        type: string
        required: true
    responses:
      200:
        status: attestation_required
        message: attestation required
        schema:
          type: object
          properties:
            challenge:
              type: string
            attestation_status:
              type: string
              description: either unverified or verified
            user:
              type: object 
              properties:
                username:
                  type: string
      401:
        description: Unauthorized
        status: invalid_user
        message: No matching user credentials 

    """
    try: 
      user = validate_user(username, password)
      if user != None:
        challenge = make_challenge()
        # Create a JWT token
        token_data = {
            "user": user,
            "attestation_status": "unverified",
            "challenge": challenge,
            "session_token_expiry": time.time() + TOKEN_EXPIRY_DURATION  # Set expiration time
        } 
        # todo sign JWT using Server’s private key
        jwt_token = jwt.encode(token_data, SECRET_KEY, algorithm="HS256")
        return jsonify({"status": "attestation_required", "message": "Attestaion required", "session_token": jwt_token})
      else:
        return jsonify({"status": "Unauthorized", "message": "No matching user credentials: {e}"}), 401
    except Exception as e:
      return jsonify({"status": "Unauthorized", "message": "No matching user credentials: {e}"}), 401



@app.route("/verify_device", methods=["POST"])
def verify_device(attestation_object_base64):
    """
    Verifies the challenge, certificate chain and signature of attestation request. If successful updates the token's attestation_status = verified 
    ---
    parameters:
      - name: Authorization
        in: header
        type: string
        required: true
        description: Bearer token
      - name: attestation_request
        in: body
        required: true
        schema:
          type: object
          properties:
            keyId:
              type: string        
              example: "base64_encoded_key_id"
            creationData:
              type: string        
              example: "base64_encoded_creation_data"
            challenge:
              type: string
              example: "base64_encoded_challenge"
            signature:
              type: string        
              example: "base64_encoded_signature"
    responses:
      200:
        status: success
        message: Device's attestation successful 
        schema:
          type: object
          properties:
            challenge:
              type: string
            attestation_status:
              type: string
              description: either unverified or verified
            user:
              type: object 
              properties:
                username:
                  type: string
      403:
        description: Unauthorized
        schema:
          type: object
          properties:
            session_token:
              type: string
    """
    try:
        # get User out of token
        auth_header = request.headers.get("Authorization")
        if not auth_header:
          return jsonify({"status": "error", "message": "Authorization header missing"}), 401
        if not auth_header.startswith("Bearer "):
            return jsonify({"status": "error", "message": "Invalid authorization header format"}), 401
        session_token = auth_header.split(" ")[1]  
        decoded_payload = jwt.decode(session_token, SECRET_KEY, algorithms=["HS256"])
        user = decoded_payload["user"]  
 
        # decode attestation object
        attestation_object_bytes = base64.b64decode(attestation_object_base64)
        attestation_object = json.loads(attestation_object_bytes.decode('utf-8'))
        # get values out of object
        key_id_base64 = base64.b64decode(attestation_object["keyId"])
        signature = base64.b64decode(attestation_object["signature"])
        creation_data_bytes = base64.b64decode(attestation_object["creationData"])
        client_challenge = base64.b64decode(attestation_object["challenge"])
        # Verify the challenge (nonce).
        if CHALLENGES.get(client_challenge) is None:
            print("Challenge Nonce not found, or is a replay attack")
            return jsonify({"status": "Forbidden", "message": "Nonce verification failed"}), 403
        # Remove challenge to prevent replay
        del CHALLENGES[client_challenge]

        # 2. Verify the Attestation Request Object with Apple
        # 2.1 Parse the CMS structure from creationData
        signed_data = cms.ContentInfo.load(creation_data_bytes)['content']
        certificates = signed_data['certificates']
        if not certificates:
            print("No certificates found in creation data.")
            return jsonify({"status": "Forbidden", "message": "Access Forbidden"}), 403

        # 2.2 Verify Certificate Chain
        if not verify_certificate_chain(certificates):
            print("Certificate chain verification failed.")
            return jsonify({"status": "Forbidden", "message": "Access Forbidden"}), 403

        # 2.3 Verify Signature of Attestation Object using keyId
        key_id = base64.b64decode(key_id_base64).decode("utf-8") 

        if key_id not in APPLE_PUBLIC_KEYS:
            print(f"Key ID '{key_id}' not found.")
            return jsonify({"status": "Forbidden", "message": "Access Forbidden"}), 403

        # Use apple public key to verify the signature on the device's attestation request 
        apple_public_key_pem = APPLE_PUBLIC_KEYS[key_id]
        apple_public_key = x509.load_pem_public_key(apple_public_key_pem.encode('utf-8'), default_backend()).public_key()
        verifier = signature_verification(apple_public_key, signed_data['encap_content_info']['content'].native, signature)

        if not verifier:
            print("Attestation object signature verification failed")
            return jsonify({"status": "Forbidden", "message": "Access Forbidden"}), 403
        
        # 3. Verify Device State (within creation data)
        # Should confirm source is from a secure enclave, boot state hasn't been comproimised etc
        print("Device state verification successful (placeholder)")
        print("Attestation verified successfully")

        # Create new token
        token_data = {
            "user": user,
            "attestation_status": "verified",
            "session_token_expiry": time.time() + TOKEN_EXPIRY_DURATION  # Set expiration time
        } 
        jwt_token = jwt.encode(token_data, SECRET_KEY, algorithm="HS256")
        return jsonify({"status": "success", "message": "Device's attestation successful", "token": jwt_token})
    except Exception as e:
        # To do pull existing jwt_token from header and send this back
        return jsonify({"status": "Unauthorized", "message": "Device's attestation failed", "token": jwt_token})


def verify_certificate_chain(certificates):
    """ Mock up of recursively works through chain to to verify each certificate until it gets to the root """
    try:
        for i in range(len(certificates) - 1):
            issuer = certificates[i + 1]
            subject = certificates[i]

            try:
                issuer_public_key = issuer.public_key
                issuer_public_key.verify(
                    subject.signature_value.native,
                    subject.tbs_certificate.dump(),
                    ec.ECDSA(hashes.SHA256())
                )
            except Exception as e:
                print(f"Certificate chain verification failed: {e}")
                return False

        # todo check if we need to verify the root certificate is an apple public cert 
        root_cert = certificates[-1]
        return True

    except Exception as e:
        print(f"Error verifying certificate chain: {e}")
        return False


def signature_verification(public_key, data, signature):
    """ use Apple's public key to verify signature """   
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception as e:
        print(f"Signature verification error: {e}")
        return False
    
def validate_user(username, password):
   """ Mock up of a function that validates a user via DB / IAM  """
   return {"username" : username}


def validate_token(received_token):
    """ Check token expiry hasn't been exceeded """
    global SECRET_KEY
    result = False
    try:
        decoded_payload = jwt.decode(received_token, SECRET_KEY, algorithms=["HS256"])
        session_token_expiry = decoded_payload["session_token_expiry"] 
        # Check if the session token is still valid (greater than now)
        if time.time() <= session_token_expiry:
            result = True
        return result
    except Exception as e: 
        return False


def make_challenge():
    """ Mockup to create a nonce and add it to the CHALLENGES collection with an expiry date
        Note: The challenge is hard coded 
              The challenge object should clean out expired challenges """
    new_nonce =  "random_challenge".encode('utf-8')
    CHALLENGES[new_nonce] = time.time() + CHALLENGE_EXPIRY 
    return new_nonce

if __name__ == "__main__":
    app.run(debug=True) 