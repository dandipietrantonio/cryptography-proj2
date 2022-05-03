import socket
import json
from flask import session
import mysql.connector
from dotenv import load_dotenv
from random import SystemRandom
import os
import hashlib

sessionIdToUsername = dict()

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

            sessionIdToUsername[sessionid] = username
            return True
        else:
            print("Failed to login the user")
    return False

def getUsers():
    print("Getting users")
    cursor = db.cursor()
    cursor.execute(f"SELECT username FROM users")
    res = cursor.fetchall()
    return [r[0] for r in res]

def addMsgToDb(author, recipient, content):
    try:
        cursor = db.cursor()
        cursor.execute(f"INSERT INTO messages(author, recipient, content) VALUES (%s, %s, %s)", (str(author), str(recipient), str(content)))
        db.commit()
        print(cursor.rowcount, "record inserted.")
        return True
    except:
        return False

def getMessagesBetweenUsers(u1, u2):
    print(f"Getting messages between {u1} and {u2}")
    cursor = db.cursor()
    cursor.execute(f"SELECT * FROM messages WHERE (author=%s AND recipient=%s) OR (author=%s AND recipient=%s)", (str(u1), str(u2), str(u2), str(u1)))
    res = cursor.fetchall()

    # The client expects tuples of messages, (content, timestamp, author)
    return [(r[4], r[3].strftime("%m/%d/%Y, %H:%M:%S"), r[1]) for r in res]

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
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((socket.gethostname(), 5003))
    s.listen(5)

    # Wait for incoming requests
    while True:
        cs, address = s.accept()
        req = json.loads(cs.recv(2048).decode("utf-8"))
        print("Received message")
        print(req)
        reqType = req["type"]

        # Take action depending on the type of message receieved
        if reqType=="add_user":
            try:
                add_user_to_db(db, req['username'], req['password'])
                cs.send(bytes("SUCCESS", encoding="utf-8"))
            except Exception as e:
                cs.send(bytes("Username already taken", encoding="utf-8"))
        elif reqType=="login":
            # Send a random token back to the client so they can use it to re-hash their password and avoid data replay
            sessionid = hashlib.sha3_512(str(cryptSecureRandomNum()).encode()).hexdigest()
            cs.send(bytes(sessionid, encoding='utf-8'))

            # Get user's login info with sessionID-hashed password
            newReq = json.loads(cs.recv(2048).decode("utf-8"))
            if (login(db, newReq['username'], newReq['password'], newReq['public_key'], sessionid)):
                cs.send(bytes("SUCCESS", encoding="utf-8"))
            else:
                cs.send(bytes("Failure logging in", encoding="utf-8"))
        elif reqType=="getUsers":
            print("Sending users...")
            cs.send(str(getUsers()).encode())
            print("Users sent!")
        elif reqType=="sendMsg":
            sessionid = req["sessionid"]
            if sessionid in sessionIdToUsername.keys():
                author = sessionIdToUsername[sessionid]
                recipient = req["recipient"]
                content = req["content"]
                success = addMsgToDb(author, recipient, content)
                if success:
                    cs.send(bytes("SUCCESS", encoding="utf-8"))
                else:
                    cs.send(bytes("Failure sending message", encoding="utf-8"))
            else:
                cs.send(bytes("Failure sending message", encoding="utf-8"))
        elif reqType=="getMessages":
            sessionid = req["sessionid"]
            if sessionid in sessionIdToUsername.keys():
                author = sessionIdToUsername[sessionid]
                recipient = req["recipient"]
                messages = getMessagesBetweenUsers(author, recipient)
                if messages:
                    cs.send(str(messages).encode())
                else:
                    cs.send(bytes("Failure getting messages", encoding="utf-8"))
            else:
                cs.send(bytes("Failure getting messages", encoding="utf-8"))
                


