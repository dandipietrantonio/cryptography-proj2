from multiprocessing import set_forkserver_preload
import socket
import json
import marshal
# import mysql.connector
import pymysql
from setuptools import setup
from dotenv import load_dotenv
from random import SystemRandom
import datetime
import os
import hashlib
import cryptography
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Global variables
SERVER_PRIVATE_KEY = None
SERVER_PUBLIC_KEY = None
SERVER_PUBLIC_PEM = None
SESSION_TTL_HOURS = 6

# Cache
# TODO: ADD TTL
sessionid_keys = dict()

sessionIdToPrivKey = dict()

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
        expectedPw = hashlib.sha3_512(str(session_id + str(res[0][0])).encode()).hexdigest()
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

            return True
        else:
            print("Failed to login the user")
    return False


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
    s.bind((socket.gethostname(), 5003))
    s.listen(5)

    # Wait for incoming requests
    while True:
        cs, address = s.accept()
        req = marshal.loads(cs.recv(2048))

        # Take action depending on the type of message receieved
        if req["type"]=="add_user":
            try:
                add_user_to_db(db, req['username'], req['password'])
                cs.send(bytes("SUCCESS", encoding="utf-8"))
            except Exception as e:
                cs.send(bytes("Username already taken", encoding="utf-8"))
        elif req["type"]=="login":
            # Retrieve sessionid and find corresponding keys
            # TODO: Validate if session id hasn't expire
            client_sessionid_encrypted = req["sessionid_encrypted"]
            client_sessionid = SERVER_PRIVATE_KEY.decrypt(client_sessionid_encrypted, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
            if client_sessionid not in sessionid_keys.keys():
                # (The client hasn't have the capability to process such error, TODO)
                cs.send(bytes("Session ID error", encoding="utf-8"))
            client_keys = sessionid_keys[client_sessionid]
            

            # Receive Login Info from client
            login_info= marshal.loads(cs.recv(2048))

            # Check timestamp
            request_timestamp = login_info['curr_timestamp']
            request_time = datetime.fromtimestamp(request_timestamp)
            request_time_hours_until_now = (datetime.datetime.now() - request_time) / datetime
            if request_time_hours_until_now < 0 or request_time_hours_until_now > SESSION_TTL_HOURS:
                cs.send(bytes("Please restart application", encoding="utf-8"))

            # TODO: Check signature

            # Decrypt user information
            encrypted_user_info = login_info['encrypted_user_info']
            client_decryptor = client_keys['cipher'].decryptor()
            decrypted_user_info = client_decryptor.update(encrypted_user_info) + client_decryptor.finalize()
            user_info = marshal.loads(decrypted_user_info)
            username = user_info['user_name']
            password = user_info['password']
            try:
                
                if (login(db, username, password, client_sessionid)):
                    cs.send(bytes("SUCCESS", encoding="utf-8"))
                else:
                    cs.send(bytes("Failure logging in", encoding="utf-8"))
            except:

                cs.send(bytes("Failure logging in", encoding="utf-8"))

        elif req["type"]=="setup":
            # Receive client public key
            client_public_pem = req['client_public_pem']
            client_public_key = serialization.load_pem_public_key(client_public_pem)
            iv = os.urandom(16)
            private_key = os.urandom(32)
            MAC_key = os.urandom(32)
            client_cipher = Cipher(algorithms.AES(private_key), modes.CBC(iv))
            # Send server public key, session_id, private keys to client
            sessionid = os.urandom(32)
            setup_info = marshal.dumps(dict({"session_id": sessionid, "private_key": private_key, "MAC_key": MAC_key, "iv":iv}))
            setup_info_encrypted = client_public_key.encrypt(setup_info, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            setup_reply = {'server_public_key':SERVER_PUBLIC_PEM, "setup_info_encrypted":setup_info_encrypted}
            cs.sendall(marshal.dumps(setup_reply))
            # Record client public key, private keys and iv for sessionid
            sessionid_keys[sessionid] = {"client_public_key": client_public_key, "private_key": private_key, "MAC_key": MAC_key, "iv":iv, "cipher":client_cipher}
            
