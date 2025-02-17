from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # Or ec
from cryptography.hazmat.backends import default_backend
import json
import requests

SESSION_TOKEN = None

# 1. Generate the private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,  # Adjust key size as needed
    backend=default_backend()
)
public_key = private_key.public_key()

# Serialize the public key (for sending to the server during registration, if needed)
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# 5. Register the public key with the server
register_url = "http://127.0.0.1:5000/register"  # Replace with your server's registration endpoint
register_data = {"public_key": public_pem.decode('utf-8')}  # Send public key as a string

try:
    register_response = requests.post(register_url, json=register_data)
    register_response.raise_for_status()
    register_result = register_response.json()
    print(register_result)
    challenge_hex = register_result.get("challenge")
    challenge = bytes.fromhex(challenge_hex) # Decode from hex to bytes
    user_id = register_result.get("user_id")
    print("Registration result:", register_result)
except requests.exceptions.RequestException as e:
    print(f"Error sending registration request: {e}")
    exit()
except json.JSONDecodeError as e:
    print(f"Error parsing registration response: {e}")
    exit()


# 3. Generate the signature
print("\nVerify starts\n=====")
try:
    signature = private_key.sign(
        challenge,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    signature_hex = signature.hex()
except Exception as e:
    print(f"Error generating signature: {e}")
    exit()

# 4. Send the signature and challenge to the server for verification
verify_url = "http://127.0.0.1:5000/verify"  # Replace with your server's verification endpoint
data = {"challenge": challenge_hex, "signature": signature_hex, "user_id":user_id} # Send challenge in hex format

try:
    print("Client verify")
    verification_response = requests.post(verify_url, json=data)
    if (verification_response.status_code == 200):
        print("1")
        verification_response.raise_for_status()
        print("2")
        verification_result = verification_response.json()
        print("Verification result:", verification_result)
        SESSION_TOKEN = verification_result["session_token"] 

        print("Got the token:", SESSION_TOKEN)
    else:
        print("Error Validating:", verification_response.json() )
except requests.exceptions.RequestException as e:
    print(f"Error sending verification request: {e}")
    exit()
except json.JSONDecodeError as e:
    print(f"Error parsing verification response: {e}")
    exit()
