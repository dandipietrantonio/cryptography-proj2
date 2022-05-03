from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
# from flask_session import Session
import socket
import json
import hashlib
from datetime import datetime

# Misc globals
PUB_KEY_LENGTH = 180 # TODO we need to optimize this
SALT='DcU5opPnT#vXX*S2gjtoQLo@g'


app = Flask(__name__)
app.secret_key = "yE2Mcr3*zCHex8K3XkdNhXRnp" # used to encrypt session data on server

# Session variables
# session["cur_user"] = None # current logged in user
# session["cur_session_id"] = None # current session id
# session["priv_key_with_s"] = None # current logged in user's private key to for client-server comms

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
        
        # Send messaage to the server
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

        # Get sessionid from server
        reqForSessionID = dict({"type": "login"})
        successfullySent = send_dict_to_server(s, reqForSessionID)
        if not successfullySent:
            return redirect("/error/Failed to get session ID from server")
        session["cur_session_id"] = s.recv(2048).decode("utf-8")
        print("Session ID: ", session["cur_session_id"])

        # Get info from form
        username = request.form['username']
        password = request.form['password']

        if len(username) == 0:
            return redirect("/error/Username field empty")
        if len(password) == 0:
            return redirect("/error/Password field empty")

        # Hash password and generate public and private keys
        hashed_password = hashlib.sha3_512(str(SALT + password).encode()).hexdigest()
        hashed_password_with_session_id = hashlib.sha3_512(str(session["cur_session_id"] + hashed_password).encode()).hexdigest()
        public_key, PRIV_KEY = get_key_pair()

        # Send data
        u = dict({"username": username, "password": hashed_password_with_session_id, "public_key":public_key})
        successfullySent = send_dict_to_server(s, u)

        if (successfullySent):
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
        hashed_password = hashlib.sha3_512(str(SALT + new_password).encode())

        # Prepare data to send
        u = dict({"type": "add_user", "username": new_username, "password": hashed_password.hexdigest()})

        # Send new user info to backend server
        try:
            success, s = connectToServer()
            if not success:
                return redirect("/error/Failed to connect to the server.")
            successfullySent = send_dict_to_server(s, u)
            if not successfullySent:
                return redirect('/error/Could not establish connection to the server')
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