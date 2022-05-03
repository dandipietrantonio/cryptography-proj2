import socket
import json
import mysql.connector
from dotenv import load_dotenv
from random import SystemRandom
import os
import hashlib

sessionIdToPrivKey = dict()

def cryptSecureRandomNum():
    return SystemRandom().random()

def add_user_to_db(db, username, password):
    print("username: ", username)
    print("password: ", password)

    cursor = db.cursor()

    cursor.execute(f"INSERT INTO users(username, password) VALUES (%s, %s)", (str(username), str(password)))
    db.commit()

    print(cursor.rowcount, "record inserted.")

def login(db, username, password, pubkey, session_id):
    print(f"Logging in {username} {password} {pubkey}")
    cursor = db.cursor()
    cursor.execute(f"SELECT password FROM users WHERE username=%s", [str(username)])
    res = cursor.fetchall()

    if(len(res) > 0):
        expectedPw = hashlib.sha3_512((str(session_id) + str(res[0][0])).encode()).hexdigest()
        if expectedPw == password: # Check if the password is valid
            # Try adding public key and session id
            try:
                cursor = db.cursor()
                cursor.execute(f"UPDATE users SET public_key=%sWHERE username=%s", (str(pubkey),str(username)))
                db.commit()
            except Exception as e:
                print("Failed to update the public key for real")
                print(e)
                return False

            # Try adding session id
            try:
                cursor = db.cursor()
                cursor.execute(f"INSERT INTO sessions(sessionid, username) VALUES (%s, %s)", (str(session_id), str(username)))
                db.commit()
            except Exception as e:
                print("Failed to update the session id")
                print(e)
                return False

            return True
        else:
            print("Failed to login the user")
    return False


if __name__ == '__main__':
    # Database connection
    load_dotenv()
    DB_PASSWORD = os.getenv('DB_PASSWORD')
    db = mysql.connector.connect(
        host="localhost",
        database="crypto_proj",
        user="root",
        password=DB_PASSWORD
    )

    # Socket connection
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((socket.gethostname(), 5003))
    s.listen(5)

    # Wait for incoming requests
    while True:
        cs, address = s.accept()
        req = json.loads(cs.recv(2048).decode("utf-8"))

        # Take action depending on the type of message receieved
        if req["type"]=="add_user":
            try:
                add_user_to_db(db, req['username'], req['password'])
                cs.send(bytes("SUCCESS", encoding="utf-8"))
            except Exception as e:
                cs.send(bytes("Username already taken", encoding="utf-8"))
        elif req["type"]=="login":
            # Send a random token back to the client so they can use it to re-hash their password and avoid data replay
            sessionid = hashlib.sha3_512(str(cryptSecureRandomNum()).encode()).hexdigest()
            cs.send(bytes(sessionid, encoding='utf-8'))

            # Get user's login info with sessionID-hashed password
            newReq = json.loads(cs.recv(2048).decode("utf-8"))
            if (login(db, newReq['username'], newReq['password'], newReq['public_key'], sessionid)):
                cs.send(bytes("SUCCESS", encoding="utf-8"))
            else:
                cs.send(bytes("Failure logging in", encoding="utf-8"))
