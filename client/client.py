from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy
import socket
import json
import hashlib
import marshal
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# Misc globals
PUB_KEY_LENGTH = 180 # TODO we need to optimize this
SALT='DcU5opPnT#vXX*S2gjtoQLo@g'

# Session variables
CUR_USER = None # current logged in user
CUR_SESSION_ID = None # current session id
CLIENT_PUBLIC_KEY = None
CLIENT_PUBLIC_PEM = None
CLIENT_PRIVATE_KEY = None
SERVER_PUBLIC_PEM = None
SERVER_PUBLIC_KEY = None
SYMMETRIC_KEY = None
MAC_KEY = None
IV = None
CIPHER = None

app = Flask(__name__)

class User():
    def __init__(self, username):
        self.username = username

class Message():
    def __init__(self, content, timestamp, author):
        self.content = content
        self.timestamp = timestamp
        self.author = author

def get_key_pair():
    return "tempPublic"+str(datetime.now()), "tempPrivate"+str(datetime.now()) # TODO

"""
Attempts to connect to the server. If successful, returns (True, socket). If
not successful, returns (False, None)
"""
def connectToServer():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((socket.gethostname(), 5003))
        return (True, s)
    except:
        return (False, s)

"""
Sends a dictionary through a web socket to the server.
"""
def send_dict_to_server(s, data):
    # Add session id to the message if applicable
    print("SENDING TO SERVER: ", data)
    if "cur_session_id" in session:
        data["sessionid"] = session["cur_session_id"]

    # TODO: add MAC/digital signature to messages
    json_data = json.dumps(data)
    try:
        s.sendall(bytes(json_data, encoding="utf-8"))
        return True
    except Exception:
        return False

"""
Input a string of request type ("login"/"signup"/"chat"/...) 
and a dict of function parameters ({"username":..., "password":...}),
Output initial request to server
The output request contains:
type                    Request type ("login", "signup")
sessionid_encrypted     Client session id assymetrically encrypted with server public key
encrypted_parameters    Request Parameters (dict) symmetrically encrypted with private key
signature               Signature generated with MAC key, encrypted_parameters and timestamp
curr_timestamp          UNIX Timestamp-like timestamp at request
"""
def generate_request(request_type, parameters):
    curr_timestamp = str(datetime.timestamp(datetime.now()))
    parameters_bytes = marshal.dumps(parameters)
    parameters_encryptor = CIPHER.encryptor()
    encrypted_parameters = parameters_encryptor.update(parameters_bytes) + parameters_encryptor.finalize()
    tagger = hmac.HMAC(MAC_KEY, hashes.SHA3_256())
    tagger.update(encrypted_parameters + curr_timestamp.encode())
    signature = tagger.finalize()
    request_dict = dict({"type": request_type, "sessionid_encrypted": CUR_SESSION_ID_ENCRYPTED, "encrypted_parameters": encrypted_parameters, "signature":signature, "curr_timestamp": curr_timestamp})
    print(request_dict)
    return marshal.dumps(request_dict)

@app.route("/")
def index():
    return render_template('index.html')

@app.route("/chat")
def chat():
    # Connect to the server
    success, s = connectToServer()
    if not success:
        return redirect("/error/Error connecting to the server")

    # Get the users from the server
    reqForUsers = {"type": "getUsers"}
    successfullySent = send_dict_to_server(s, reqForUsers)
    if not successfullySent:
        return redirect("/error/Error getting users from the server")
    users =  eval(s.recv(2048).decode("utf-8"))

    return render_template('chat_select_user.html', users=[User(username) for username in users])

@app.route("/chatWith/<userChattingWith>", methods=['POST', 'GET'])
def chatWith(userChattingWith):
    if request.method == 'POST':
        print("Want to send a msg")
        # Connect to server
        content = request.form['content']
        success, s = connectToServer()
        if not success:
            return redirect("/error/Error connecting to the server")
        
        # Send message to the server
        reqToSendMessage = {"type": "sendMsg", "recipient": userChattingWith, "content": content}
        successfullySent = send_dict_to_server(s, reqToSendMessage)
        if not successfullySent:
            return redirect("/error/Error sending message to the server")

        # Receive confirmation from the server
        msg = s.recv(1024).decode("utf-8")
        print("Received message from server")
        print(msg)
        if msg == "SUCCESS":
            return(redirect("/chatWith/"+userChattingWith))
        return redirect("error/Error logging in")
    else:
        # Connect to the server
        success, s = connectToServer()
        if not success:
            return redirect("/error/Error connecting to the server")

        # Get the messages from the server
        reqForMessages = {"type": "getMessages", "recipient": userChattingWith}
        successfullySent = send_dict_to_server(s, reqForMessages)
        if not successfullySent:
            return redirect("/error/Error getting users from the server")
        messages =  eval(s.recv(2048).decode("utf-8"))
        print(messages)

        return render_template('chat.html', userChattingWith=userChattingWith, messages=[Message(m[0], m[1], m[2]) for m in messages])
        # return render_template('chat.html', userChattingWith=userChattingWith, messages=[])

@app.route("/login", methods=['POST', 'GET'])
def login():
    if request.method == "POST":
        print("Logging in...")
        # Connect to the server
        success, s = connectToServer()
        if not success:
            return redirect("/error/Failed to connect to the server.")

        # Get info from form
        username = request.form['username']
        password = request.form['password']

        if len(username) == 0:
            return redirect("/error/Username field empty")
        if len(password) == 0:
            return redirect("/error/Password field empty")

        # Hash password and generate public and private keys
        hashed_password = hashlib.sha3_512(str(SALT + password).encode()).hexdigest()
        hashed_password_with_session_id = hashlib.sha3_512((str(CUR_SESSION_ID) + hashed_password).encode()).hexdigest()

        # Prepare login request and encrypt session id to send
        login_parameters = dict({"username":username, "password": hashed_password_with_session_id})
        login_request = generate_request("login", login_parameters)

        # Send login request to backend server
        try:
            s.sendall(login_request)
        except Exception:
            return redirect('/error/Could not establish connection to the server')

        # Receive confirmation
        # TODO: Transform this part into secure communication
        msg = s.recv(1024).decode("utf-8")
        print(msg)
        if msg == "SUCCESS":
            return(redirect("/chat"))
        return redirect("error/Error logging in")
    else:
        return render_template('login.html')

@app.route("/signup", methods=['POST', 'GET'])
def signup():
    if request.method == 'POST':
        # Connect to the server
        success, s = connectToServer()
        if not success:
            return redirect("/error/Failed to connect to the server.")

        # Get info from form
        new_username = request.form['username']
        new_password = request.form['password']

        if len(new_username) == 0:
            return redirect("/error/Username left empty")
        if len(new_password) == 0:
            return redirect("/error/Password left empty")

        # Hash password and generate public and private keys
        hashed_password = hashlib.sha3_512(str(SALT + new_password).encode()).hexdigest()
        
        # Prepare data to send
        sign_up_parameters = dict({"username": new_username, "password": hashed_password})
        sign_up_request = generate_request("signup", sign_up_parameters)

        # Send new user info to backend server
        try:
            s.sendall(sign_up_request)
        except Exception:
            return redirect('/error/Could not establish connection to the server')

        # Receive confirmation
        msg = s.recv(1024)
        print(msg)
        if msg.decode("utf-8") == "SUCCESS":
            return(redirect("newUserSuccess"))
        return redirect("error/Username already taken")
    else:
        return render_template('signup.html')

@app.route("/newUserSuccess")
def new_user_success():
    return render_template("newUserSuccess.html")

@app.route("/error/<msg>")
def new_user_fail(msg):
    return f"<h1>Error</h1><p>There was an error: {msg}.<br/> Click <a href='/'>here</a> to go back to the home page.</p>"

@app.route("/test")
def test():
    return CLIENT_PUBLIC_PEM.decode('utf-8')

if __name__ == "__main__":
    print("Setting up")
    # Generate client public and private key
    CLIENT_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    CLIENT_PUBLIC_KEY = CLIENT_PRIVATE_KEY.public_key()
    CLIENT_PUBLIC_PEM = CLIENT_PUBLIC_KEY.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    
    # Send setup request along with client public key to server
    setup_req = marshal.dumps(dict({'type':'setup', 'client_public_pem': CLIENT_PUBLIC_PEM}))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((socket.gethostname(), 5003))
    s.sendall(setup_req)
    
    # Receive server public key, private keys and session id
    setup_reply = marshal.loads(s.recv(2048))
    setup_info_encrypted = setup_reply['setup_info_encrypted']
    SERVER_PUBLIC_PEM = setup_reply['server_public_key']
    SERVER_PUBLIC_KEY = serialization.load_pem_public_key(SERVER_PUBLIC_PEM)
    setup_info_decrypted = CLIENT_PRIVATE_KEY.decrypt(setup_info_encrypted, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    setup_info = marshal.loads(setup_info_decrypted)
    CUR_SESSION_ID = setup_info['session_id']
    CUR_SESSION_ID_ENCRYPTED = SERVER_PUBLIC_KEY.encrypt(CUR_SESSION_ID, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    SYMMETRIC_KEY = setup_info['private_key']
    MAC_KEY = setup_info['MAC_key']
    IV = setup_info['iv']
    CIPHER = Cipher(algorithms.AES(SYMMETRIC_KEY), modes.CTR(IV))
    print("Set up successfully!")

    # Initiate Flask application
    app.run()
