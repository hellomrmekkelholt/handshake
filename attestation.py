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
SECRET_KEY = "temporary_key"    # Used to seed JWT token

#
# login valdiates user before requesting device attestation
#  
@app.route("/login", methods=["POST"])
def login():
    """
    Validates user before generating challenge for Client's attestation request.
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
    token = ""
    try:
      return jsonify({"status": "attestaion_required", "message": "Attestation Required", "token":token})
    except Exception as e:
      return jsonify({"status": "Unauthorized", "message": "Invalid crednetialds: {e}"}), 401


#
# Verifies the attestation and challenge and creates a token 
#
@app.route("/verify_device", methods=["POST"])
def verify_device(attestation_object_base64):
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
        description: Forbidden
    """
    token = ""
    return jsonify({"status": "success", "message": "Access Forbidden", "token": token })



#
# Verifies a certificate chain
#
def verify_certificate_chain(certificates):
    return True

#
# uses Apple's public key to verify signature   
#
def signature_verification(public_key, data, signature):
    return True
    

#
# Compare user session tokens match and the expiry hasn't been exceed
#
def validate_token(received_token):
    result = True



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