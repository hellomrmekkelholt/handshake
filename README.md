# Handshake 
A client / server application that uses private public keys to validate a digital signature and authenticate a device.

 ## Client Server Interaction Diagram
![Client Server Interaction Diagram](https://github.com/user-attachments/assets/a93bcc10-d89b-4f37-82b7-c1a00037a7bf)

## API docs 
[API docs here](https://github.com/user-attachments/files/18855064/authentication-api.pdf)
Additionally, the `server.py` script has swagger comments to generate API docs. Running `server.py` will generate API docs at: http://127.0.0.1:5000/apidocs/#/default

## API Code
The `server.py` script has implementation of the end points in the diagram. 

## Client Server Installation
**Note** Using tools like Postman to test the API endpoints (with public keys and signed challenges) can be cumbersome. The `client.py` script allows you to simulate the process.  

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

5. Start the server (while inside the virtual environement) : 

    ```bash
    python server.py
    -- or --
    python3 server.py
    ```
6. Start the client in a new terminal (remember to activate the virtual environment) : 

    ```bash
    source <your_env_name>/bin/activate
    
    python client.py
    -- or --
    python3 client.py
    ```


### Using the Client
Available commands:
* register - Register a user's device and generate a session token
* interact - Interact with the server using the session token. You **must** register first 
* help - Show this help message
* quit - Exit the program

#### register 
When running you will see messages saying *Registration successful* and *Verfication Completed* - these indicate the  
1. The device was registered on the server and a challenge was returned
2. The challenge once signed was verified
3. You can now run the **interact** option. 

#### interact
The session token is only valid for 15 seconds (for proof of concept)
1. A successful interact call returns `Hello World (Authenticated)` 
2. If you call **interact** with an expired token it returns `419` error. The client will attempt to reconnect, displaying messages *Attempt reconnect* and *Verifcation Complete* indicating a new session_token is created with a life span of another 15 seconds  
3. If you call **interact** without a token it will try to verify but the device isn't registered so it will fail. 
