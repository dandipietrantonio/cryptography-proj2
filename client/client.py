from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy
import socket
import json
import hashlib
from datetime import datetime

# Misc globals
PUB_KEY_LENGTH = 180 # TODO we need to optimize this
SALT='DcU5opPnT#vXX*S2gjtoQLo@g'

# Session variables
CUR_USER = None # current logged in user
CUR_SESSION_ID = None # current session id
PRIV_KEY = None

app = Flask(__name__)

def get_session_id(username):
    return hashlib.sha512(str(username + str(datetime.now())).encode()).hexdigest()

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
        # Get info from form
        username = request.form['username']
        password = request.form['password']

        if len(username) == 0:
            return redirect("/error/Username field empty")
        if len(password) == 0:
            return redirect("/error/Password field empty")

        # Hash password and generate public and private keys
        hashed_password = hashlib.sha512(str(SALT + password).encode())
        public_key, PRIV_KEY = get_key_pair()
        session_id = get_session_id(username)

        # Prepare data to send
        u = dict({"type": "login", "username": username, "password": hashed_password.hexdigest(), "public_key":public_key, "session_id":session_id})
        userInfo = json.dumps(u)

        # Send user info to backend server
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