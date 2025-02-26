from flask import Flask, request, jsonify
from flasgger import Swagger
import base64
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from asn1crypto import cms, core, pem
#from cryptography.hazmat.primitives.asymmetric import padding, rsa  
import time
import jwt 
import json
app = Flask(__name__)
swagger = Swagger(app)


CHALLENGES = {}                 # Collection of challenges  
CHALLENGE_EXPIRY = 10           # Challenges remain valid for 10 seconds


DEVICE_LIST = {}                # A list of devices by user_id / limits 1 device to 1 user 
TOKEN_EXPIRY_DURATION = 15      # Expires after 15 seconds (for POC)
SECRET_KEY = "temporary_key"    # Used to seed JWT token

#
# register receives public key and returns a challenge
#  
@app.route("/secure_request", methods=["POST"])
def secure_request():
    """
    Requires token verification but also 
    Requires device attestaion before returning the response.
    ---
    parameters:
      - name: Authorization
        in: header
        type: string
        required: true
        description: Bearer token
    responses:
      200:
        schema:
          type: object
          properties:
            challenge:
              type: string
          description: Attestation Required
      400:
        description: Bad request
      401:
        description: Unauthorized
      419:
        description: Token has expired
    """
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header:
          return jsonify({"status": "error", "message": "Authorization header missing"}), 401

        if not auth_header.startswith("Bearer "):
            return jsonify({"status": "error", "message": "Invalid authorization header format"}), 401

        # Get token from the header > authorization 
        session_token = auth_header.split(" ")[1]  
        if validate_token(session_token):
            print("\n/secure_request requires attestation to proceed. Generate challenge  ")
            challenge = make_challenge()
            return jsonify({"status": "attestation_required", "message": "Attestation Reuired", "challenge": challenge.hex()}) # Return challenge to client
        else:
          print("\n/interact token is invalid so returning a 419 error")
          return jsonify({"status": "error", "message": "No valid session"}), 419
    except Exception as e:
      return jsonify({"status": "error", "message": f"Session verification failed: {e}"}), 400


#
# Verifies the attestation and challenge and creates a token 
#
@app.route("/verify_attestation", methods=["POST"])
def verify_attestation(attestation_object_base64):
    """
    Requires token verification but also requires attestation request object to verify the device.
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
            challenge:
              type: string
              example: "base64_encoded_challenge"
            keyId:
              type: string        
              example: "base64_encoded_key_id"
            creationData:
              type: string        
              example: "base64_encoded_creation_data"
            signature:
              type: string        
              example: "base64_encoded_signature"
    responses:
      200:
        description: Device's attestation successful 
        schema:
          type: object
          properties:
            session_token:
              type: string
      403:
        description: Forbidden
      500: 
        description: Server Error
    """
    try:
        # decode attestation object
        attestation_object_bytes = base64.b64decode(attestation_object_base64)
        attestation_object = json.loads(attestation_object_bytes.decode('utf-8'))

        # Not used but would be needed to identify the key 
        # used to sign the attestation object.
        key_id = base64.b64decode(attestation_object["keyId"])
        signature = base64.b64decode(attestation_object["signature"])
        client_challenge = base64.b64decode(attestation_object["challenge"])
        stored_challenge = CHALLENGES.get(client_challenge)
        creation_data_bytes = base64.b64decode(attestation_object["creationData"])

        #1  Verify the Challenge Returned Matches the Server's Challenge
        if stored_challenge != None or client_challenge != stored_challenge:
            print("Challenge verification failed: Challenges do not match.")
            return jsonify({"status": "Forbidden", "message": "Access Forbidden"}), 403

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

        # 2.3 Verify Signature of Attestation Object
        apple_public_key = certificates[-1].public_key() #Using root certificate for signature verification
        verifier = signature_verification(apple_public_key, signed_data['encap_content_info']['content'].native, signature)
        if not verifier:
            print("Attestation object signature verification failed")
            return jsonify({"status": "Forbidden", "message": "Access Forbidden"}), 403

        # 3. Verify Device State (within creation data)
        # In a real world scenario, you would parse the creation data and perform your checks.
        print("Device state verification successful (placeholder)")
        print("Attestation verified successfully")

        #
        # Complete secure_request 
        #
        body = complete_secure_request()
        return jsonify({"status": "success", "message": "Access Forbidden", "body": body})

    except Exception as e:
        print(f"Error verifying attestation: {e}")
        return False



#
# Verifies a certificate chain
#
def verify_certificate_chain(certificates):
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

        # Verify the root certificate 
        # ?? revocation c
        root_cert = certificates[-1]
        #print(f"Root certificate: {root_cert.subject}")
        #print("Certificate chain verification successful.")
        return True

    except Exception as e:
        print(f"Error verifying certificate chain: {e}")
        return False

#
# uses Apple's public key to verify signature   
#
def signature_verification(public_key, data, signature):
    try:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception as e:
        print(f"Signature verification error: {e}")
        return False


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
            # Check if the session token is still valid (greater than now)
            if time.time() <= session_token_expiry:
                result = True
        return result
    except Exception as e: 
        return False



# This is a holder function it's not implemented to extract chain from creation_data. 
# Check if it should be ASN.1 parser.
def extract_certificate_chain(creation_data):
    return creation_data["certificate_chain"]


#
#  Creates a challenge and adds it to the CHALLENGES collection with an expiry date
#  Note: 
#   The challenge is hard coded 
#   The chellenge object shiould clean out expired challenges
#
def make_challenge():
    new_challenge = "random_challenge".encode('utf-8')
    challenge_expires = time.time() + CHALLENGE_EXPIRY
    CHALLENGES[{"challenge": new_challenge, "challenge_expires": challenge_expires}]
    return new_challenge 


#
#
# 
def complete_secure_request():
    return {"content": "confidential informatiojn"}

if __name__ == "__main__":
    app.run(debug=True) 