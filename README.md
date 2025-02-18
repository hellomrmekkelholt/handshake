# Handshake 
Creates a client / server application that uses public key to validate a digital signature and authenticate a device


## Installation

1. Install Python 3.13 or later. 
2. Clone the project and navigate to the directory:

    ```bash
    git clone https://github.com/hellomrmekkelholt/handshake.git
    cd handshake
    ```
3. Create your virtual environment and activate

    ```bash
    python3 -m venv <your_env_name>
    source <your_env_name>/bin/activate 
    ```

4. Install dependencies:

    ```bash
    pip install -r requirements.txt
    -- or --
    pip3 install -r requirements.txt
    ```

5. Start the server and the client: 

    ```bash
    python server.py
    python client.py
    -- or --
    python3 server.py
    python3 client.py
    ```

## Using the Client
Available commands:
* register - Register a user's device and generate a session token
* interact - Interact with the server using the session token. You **must** register first 
* help - Show this help message
* quit - Exit the program

### register & interact
When running you will see messages saying *Registration successful* and *Verfication Completed* - these indicate the server has 
1. The device was registered and a challenge was returned
2. The challenge once signed was verified
3. You can now run the **interact** option. But for only 15 seconds (for proof of concept the session expires after 15 seconds)
4. A successful interact call returns `Hello World (Authenticated)` 
5. If you call **interact** with an expired token it returns `419` error and the messages will show *Attempt reconnect* and *Verifcation Complete* messages indicating a new session_token and another 15 seconds  

## Accessing API docs 
`server.py` has swagger comments to generate API docs you can access them here:
 http://127.0.0.1:5000/apidocs/#/default

 ## Overview of the flow
![authentication](https://github.com/user-attachments/assets/a93bcc10-d89b-4f37-82b7-c1a00037a7bf)


