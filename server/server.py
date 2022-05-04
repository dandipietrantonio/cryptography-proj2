from multiprocessing import set_forkserver_preload
import socket
import json
import marshal
import pymysql
from setuptools import setup
from dotenv import load_dotenv
from random import SystemRandom
from datetime import datetime, timedelta
import os
import hashlib
import cryptography
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Global variables
SERVER_PRIVATE_KEY = None
SERVER_PUBLIC_KEY = None
SERVER_PUBLIC_PEM = None
SESSION_TTL_HOURS = 6

# Cache
# TODO: ADD TTL
sessionid_keys = dict()

sessionIdToUsername = dict()

def cryptSecureRandomNum():
    return SystemRandom().random()

def get_key_pair():
    return "tempPublic"+str(datetime.now()), "tempPrivate"+str(datetime.now()) # TODO

def add_user_to_db(db, username, password):
    print("username: ", username)
    print("password: ", password)

    cursor = db.cursor()

    cursor.execute(f"INSERT INTO users(username, password) VALUES (%s, %s)", (str(username), str(password)))
    db.commit()

    print(cursor.rowcount, "record inserted.")

def login(db, username, password, session_id):
    cursor = db.cursor()
    cursor.execute(f"SELECT password FROM users WHERE username=%s", [str(username)])
    res = cursor.fetchall()

    if(len(res) > 0):
        expectedPw = hashlib.sha3_512((str(session_id)+res[0][0]).encode()).hexdigest()
        if expectedPw == password: # Check if the password is valid
            # # Try adding public key and session id
            # try:
            #     cursor = db.cursor()
            #     cursor.execute(f"UPDATE users SET public_key=%sWHERE username=%s", (str(pubkey),str(username)))
            #     db.commit()
            # except Exception as e:
            #     print("Failed to update the public key for real")
            #     print(e)
            #     return False

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

"""
Input an int in UNIX timestamp format, check if the timestamp is valid
Return True if valid
"""
def validate_timestamp(request_timestamp):
    # Validate Timestamp
    request_time = datetime.fromtimestamp(request_timestamp)
    request_time_hours_until_now = (datetime.now() - request_time) / timedelta(hours=1)
    if not 0 < request_time_hours_until_now <= SESSION_TTL_HOURS:
        return False
    return True

"""
Input signature, encrypted message, MAC key, request_timestamp check if the signature is valid
Return True if valid
"""
def validate_signature(signature, encrypted_msg, MAC_key, request_timestamp):
    # Validate Signature
    tagger = hmac.HMAC(MAC_key, hashes.SHA3_256())
    tagger.update(encrypted_msg + request_timestamp.encode())
    try:
        tagger.verify(signature)
    except:
        return False
    return True

"""
Input encrypted message of parameters and cipher,
Decrypt the message and return a dict of parameters
"""
def decrypt_parameters(encrypted_parameters, cipher):
    parameters_decryptor = cipher.decryptor()
    decrypted_parameters_bytes = parameters_decryptor.update(encrypted_parameters) + parameters_decryptor.finalize()
    return marshal.loads(decrypted_parameters_bytes)

if __name__ == '__main__':
    # Database connection
    load_dotenv()
    DB_PASSWORD = os.getenv('DB_PASSWORD')
    # db = mysql.connector.connect(
    #     host="localhost",
    #     database="crypto_proj",
    #     user="root",
    #     password=DB_PASSWORD
    # )
    db = pymysql.connect(
        host="localhost",
        database="crypto_proj",
        user="root",
        password=DB_PASSWORD
    )

    # Initialize server public key and secret key
    SERVER_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    SERVER_PUBLIC_KEY = SERVER_PRIVATE_KEY.public_key()
    SERVER_PUBLIC_PEM = SERVER_PUBLIC_KEY.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # Socket connection
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((socket.gethostname(), 5003))
    s.listen(5)

    # Wait for incoming requests
    while True:
        cs, address = s.accept()

        req = marshal.loads(cs.recv(2048))
        # print("Received message", req)
        reqType = req["type"]

        # Take action depending on the type of message receieved
        if reqType=="signup":
            client_sessionid_encrypted = req["sessionid_encrypted"]
            request_timestamp = req['curr_timestamp']
            signature = req['signature']
            encrypted_new_user_info = req['encrypted_parameters']

            # Check timestamp
            if not validate_timestamp(int(float(request_timestamp))):
                cs.send(bytes("Please restart application", encoding="utf-8"))
                continue

            # Decrypt sessionid and find corresponding keys
            # TODO: Validate if session id hasn't expire
            client_sessionid = SERVER_PRIVATE_KEY.decrypt(client_sessionid_encrypted, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
            if client_sessionid not in sessionid_keys.keys():
                # (The client hasn't have the capability to process such error, TODO)
                cs.send(bytes("Session ID error", encoding="utf-8"))
            client_keys = sessionid_keys[client_sessionid]
            
            # Check signature
            if not validate_signature(signature, encrypted_new_user_info, client_keys['MAC_key'], request_timestamp):
                cs.send(bytes("Signature Mismatch", encoding="utf-8"))
                continue

            # Decrypt new user information
            user_info = decrypt_parameters(encrypted_new_user_info, client_keys['cipher'])
            username = user_info['username']
            password = user_info['password']

            # Sign up
            try:
                add_user_to_db(db, username, password)
                cs.send(bytes("SUCCESS", encoding="utf-8"))
            except Exception as e:
                cs.send(bytes("Username already taken", encoding="utf-8"))

        elif req["type"]=="login":
            client_sessionid_encrypted = req["sessionid_encrypted"]
            encrypted_user_info = req['encrypted_parameters']
            request_timestamp = req['curr_timestamp']
            signature = req['signature']

            # Check timestamp
            if not validate_timestamp(int(float(request_timestamp))):
                cs.send(bytes("Please restart application", encoding="utf-8"))
                continue

            # Find keys corresponding to client sessionid
            # TODO: Validate if session id hasn't expire
            client_sessionid = SERVER_PRIVATE_KEY.decrypt(client_sessionid_encrypted, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
            if client_sessionid not in sessionid_keys.keys():
                cs.send(bytes("Session ID error", encoding="utf-8"))
            client_keys = sessionid_keys[client_sessionid]            

            # Check signature
            if not validate_signature(signature, encrypted_user_info, client_keys['MAC_key'], request_timestamp):
                cs.send(bytes("Signature Mismatch", encoding="utf-8"))
                continue

            # Decrypt user information
            user_info = decrypt_parameters(encrypted_user_info, client_keys['cipher'])
            username = user_info['username']
            password = user_info['password']
            
            # Login
            try:
                if (login(db, username, password, client_sessionid)):
                    cs.send(bytes("SUCCESS", encoding="utf-8"))
                else:
                    cs.send(bytes("Failure logging in", encoding="utf-8"))
            except:
                cs.send(bytes("Error", encoding="utf-8"))

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

        elif reqType=="setup":
            # Receive client public key
            client_public_pem = req['client_public_pem']
            client_public_key = serialization.load_pem_public_key(client_public_pem)
            iv = os.urandom(16)
            private_key = os.urandom(32)
            MAC_key = os.urandom(32)
            client_cipher = Cipher(algorithms.AES(private_key), modes.CTR(iv))
            # Send server public key, session_id, private keys to client
            sessionid = os.urandom(32)
            setup_info = marshal.dumps(dict({"session_id": sessionid, "private_key": private_key, "MAC_key": MAC_key, "iv":iv}))
            setup_info_encrypted = client_public_key.encrypt(setup_info, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            setup_reply = {'server_public_key':SERVER_PUBLIC_PEM, "setup_info_encrypted":setup_info_encrypted}
            cs.sendall(marshal.dumps(setup_reply))
            # Record client public key, private keys and iv for sessionid
            sessionid_keys[sessionid] = {"client_public_key": client_public_key, "private_key": private_key, "MAC_key": MAC_key, "iv":iv, "cipher":client_cipher}
            
