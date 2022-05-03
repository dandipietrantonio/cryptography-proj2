from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy
import socket
import json
import hashlib
import marshal
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


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

app = Flask(__name__)

def get_key_pair():
    return "tempPublic"+str(datetime.now()), "tempPrivate"+str(datetime.now()) # TODO

@app.route("/")
def index():
    return render_template('index.html')

@app.route("/chat")
def chat():
    return render_template('chat.html')

@app.route("/login", methods=['POST', 'GET'])
def login():
    if request.method == "POST":
        print("Logging in...")
        # Connect to the server
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((socket.gethostname(), 5003))

        # Get sessionid from server
        reqForSessionID = json.dumps(dict({"type": "login"}))
        try:
            s.sendall(bytes(reqForSessionID, encoding="utf-8"))
        except Exception:
            return redirect('/error/Could not establish connection to the server')
        CUR_SESSION_ID = s.recv(2048).decode("utf-8")
        print("Session ID: ", CUR_SESSION_ID)

        # Get info from form
        username = request.form['username']
        password = request.form['password']

        if len(username) == 0:
            return redirect("/error/Username field empty")
        if len(password) == 0:
            return redirect("/error/Password field empty")

        # Hash password and generate public and private keys
        hashed_password = hashlib.sha512(str(SALT + password).encode()).hexdigest()
        hashed_password_with_session_id = hashlib.sha512(str(CUR_SESSION_ID + hashed_password).encode()).hexdigest()
        public_key, PRIV_KEY = get_key_pair()

        # Prepare data to send
        u = dict({"username": username, "password": hashed_password_with_session_id, "public_key":public_key})
        userInfo = json.dumps(u)

        # Send user info to backend server
        try:
            s.sendall(bytes(userInfo, encoding="utf-8"))
        except Exception:
            return redirect('/error/Could not establish connection to the server')

        # Receive confirmation
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
        # Get info from form
        new_username = request.form['username']
        new_password = request.form['password']

        if len(new_username) == 0:
            return redirect("/error/Username left empty")
        if len(new_password) == 0:
            return redirect("/error/Password left empty")

        # Hash password and generate public and private keys
        hashed_password = hashlib.sha512(str(SALT + new_password).encode())

        # Prepare data to send
        u = dict({"type": "add_user", "username": new_username, "password": hashed_password.hexdigest()})
        userInfo = json.dumps(u)

        # Send new user info to backend server
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((socket.gethostname(), 5003))
            s.sendall(bytes(userInfo, encoding="utf-8"))
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
    CLIENT_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    CLIENT_PUBLIC_KEY = CLIENT_PRIVATE_KEY.public_key()
    CLIENT_PUBLIC_PEM = CLIENT_PUBLIC_KEY.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    setup_req = marshal.dumps(dict({'type':'setup', 'client_public_pem': CLIENT_PUBLIC_PEM}))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((socket.gethostname(), 5003))
    s.sendall(setup_req)
    SERVER_PUBLIC_PEM = s.recv(2048)
    SERVER_PUBLIC_KEY = serialization.load_pem_public_key(SERVER_PUBLIC_PEM)
    encrypted_msg = s.recv(2048)
    decrypted_msg = CLIENT_PRIVATE_KEY.decrypt(encrypted_msg, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    setup_info = marshal.loads(decrypted_msg)
    CUR_SESSION_ID = setup_info['session_id']
    SYMMETRIC_KEY = setup_info['private_key']
    MAC_KEY = setup_info['private_key']
    IV = setup_info['iv']
    print("Set up successfully!")
    app.run()
