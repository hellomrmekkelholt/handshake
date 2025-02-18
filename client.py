from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # Or ec
from cryptography.hazmat.backends import default_backend
import json
import requests
import uuid
import hashlib


SESSION_TOKEN = None
USER_ID = None
PRIVATE_KEY = None
PUBLIC_KEY = None

def main():
    print("handshake client: \nOptions: register, interact, help and quit \n\n")

    while True:
        user_input = input("Enter a command (or type 'quit' or 'help' ): \n").strip().lower()

        if user_input == 'quit':
            print("Exiting the program.")
            break
        elif user_input == 'help':
            show_help()
        elif user_input == 'register':
            register_device()
        elif user_input == 'interact':
            interact()
        else:
            print("Unknown command. Please enter 'help' for a list of commands.")


def show_help():
    print("\nAvailable commands:")
    print("  register - Register a new user and generate a session token.")
    print("  interact - Interact with the server using the session token.")
    print("  help - Show this help message.")
    print("  quit - Exit the program.\n")


def register_device():    
    global SESSION_TOKEN, USER_ID, PRIVATE_KEY, PUBLIC_KEY

    # Generate the private key
    PRIVATE_KEY = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,  # Adjust key size as needed
        backend=default_backend()
    )
    PUBLIC_KEY = PRIVATE_KEY.public_key()

    # Serialize the public key (for sending to the server during registration, if needed)
    public_pem = PUBLIC_KEY.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Register the public key with the server
    print("=====\nRegistering device")
    register_url = "http://127.0.0.1:5000/register"  
    mac_address = get_mac_address()
    
    # hardcoded workaround
    username = "sample_user_name"
    password = hash_string("secret_password")
    register_data = {"username":username, "password":password, "public_key": public_pem.decode('utf-8'), "device": {"mac_address": mac_address}}  # Send public key as a string
    try:
        register_response = requests.post(register_url, json=register_data)
        register_response.raise_for_status()
        register_result = register_response.json()
        challenge_hex = register_result.get("challenge")
        #challenge = bytes.fromhex(challenge_hex) # Decode from hex to bytes
        USER_ID = register_result.get("user_id")
        #print("Registration result:", register_result)
    except requests.exceptions.RequestException as e:
        print(f"Error sending registration request: {e}")
        exit()
    except json.JSONDecodeError as e:
        print(f"Error parsing registration response: {e}")
        exit()
    print("Registration Success\n=====\n")


    # 3. Generate the signature
    verify(challenge_hex)


def interact():
    print("=====\nInteract starts")
    global SESSION_TOKEN, USER_ID
    interact_url = "http://127.0.0.1:5000/interact"
    headers = {
        "Authorization": f"Bearer {SESSION_TOKEN}"
    }
      
    #data = {"session_token": SESSION_TOKEN, "user_id":USER_ID} 
    try:
        interact_response = requests.post(interact_url, headers=headers)
        if (interact_response.status_code == 200):
            interact_response.raise_for_status()
            interact_result = interact_response.json()
            outcome = interact_result["outcome"]
            print("Interact Success Outcome:", outcome, "\n=====\n")
        elif (interact_response.status_code == 419):
            print("Token expired call reconnect\n=====\n")
            reconnect()
        else:
            print("Error Validating:", interact_response.json() )
    except requests.exceptions.RequestException as e:
        print(f"Error sending verification request: {e}")
        exit()
    except json.JSONDecodeError as e:
        print(f"Error parsing verification response: {e}")
        exit()


def reconnect():
    global  USER_ID
    print("====\nAttempt reconnect")
    get_challenge_url = "http://127.0.0.1:5000/get_challenge"  
    mac_address = get_mac_address()
    data = {"device": {"mac_address": mac_address}, "user_id":USER_ID} 
    try:
        get_challenge_response = requests.post(get_challenge_url, json=data)
        if (get_challenge_response.status_code == 200):
            get_challenge_response.raise_for_status()
            get_challenge_result = get_challenge_response.json()
            challenge_hex = get_challenge_result["challenge"]
            print("Challenge received\n=====\n")
            verify(challenge_hex)
        else:
            print("get_challenge returned error")
    except Exception as e:
        print(f"Error generating signature: {e}")
        exit()


def verify(challenge_hex):
    global SESSION_TOKEN, USER_ID, PRIVATE_KEY, PUBLIC_KEY
    print("=====\nVerify starts")
    challenge = bytes.fromhex(challenge_hex) # Decode from hex to bytes

    try:
        signature = PRIVATE_KEY.sign(
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

    # Send the signature and challenge to the server for verification
    verify_url = "http://127.0.0.1:5000/verify"  
    data = {"challenge": challenge_hex, "signature": signature_hex, "user_id":USER_ID} # Send challenge in hex format

    try:
        verify_response = requests.post(verify_url, json=data)
        if (verify_response.status_code == 200):
            verify_response.raise_for_status()
            verify_result = verify_response.json()
            SESSION_TOKEN = verify_result["session_token"]
        else:
            print("Error Validating:", verify_response.json() )
    except requests.exceptions.RequestException as e:
        print(f"Error sending verification request: {e}")
        exit()
    except json.JSONDecodeError as e:
        print(f"Error parsing verification response: {e}")
        exit()
    print("Verfication Completed\n====\n")


#
# Utilities
#
def get_mac_address():
    mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2*6, 2)][::-1])
    return mac

def hash_string(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    hashed_string = sha256_hash.hexdigest()
    return hashed_string



# Start CLI
if __name__ == "__main__":
    main()  