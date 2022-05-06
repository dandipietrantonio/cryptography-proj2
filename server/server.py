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
sessionIdToKeys = dict()
sessionIdToUsername = dict()
usernameToSessionId = dict()

def cryptSecureRandomNum():
    return SystemRandom().random()

def get_key_pair():
    return "tempPublic"+str(datetime.now()), "tempPrivate"+str(datetime.now()) # TODO

def add_user_to_db(db, username, password):
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
            sessionIdToUsername[session_id] = username
            usernameToSessionId[username] = session_id
            return True
        else:
            print("Failed to login the user")
    return False

def addMsgToDb(author, recipient, content, cipher):
    encrypted_content = encrypt_message(cipher, content)
    try:
        cursor = db.cursor()
        cursor.execute(f"INSERT INTO messages(author, recipient, content) VALUES (%s, %s, %s)", (str(author), str(recipient), encrypted_content))
        db.commit()
        print(cursor.rowcount, "record inserted.")
        return True
    except:
        return False

def getMessagesBetweenUsers(u1, u2):
    print(f"Getting messages between {u1} and {u2}")
    cursor = db.cursor()
    cursor.execute(f"SELECT * FROM messages WHERE (author=%s AND recipient=%s) OR (author=%s AND recipient=%s) ORDER BY timeSent", (str(u1), str(u2), str(u2), str(u1)))
    res = cursor.fetchall()
    messages = []
    for r in res:
        author = r[1]
        timeSent = r[3].strftime("%m/%d/%Y, %H:%M:%S")
        content = r[4]
        cipher = sessionIdToKeys[usernameToSessionId[author]]['cipher']
        decrypted_content = decrypt_message(cipher, content)
        messages.append((decrypted_content, timeSent, author))
    # The client expects tuples of messages, (content, timestamp, author)
    return messages

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

"""
Input a cipher, mac key, and a payload
Output the symetrically encrypted marshaled payload with a MAC tag
"""
def symetrically_encrypt_and_marshall(cipher, mac_key, payload):
    curr_timestamp = str(datetime.timestamp(datetime.now()))

    # Encrypt the payload
    payload["curr_timestamp"] = curr_timestamp
    payload_bytes = marshal.dumps(payload)
    payload_encryptor = cipher.encryptor()
    encrypted_payload = payload_encryptor.update(payload_bytes) + payload_encryptor.finalize()

    # Generate the MAC tag
    tagger = hmac.HMAC(mac_key, hashes.SHA3_256())
    tagger.update(encrypted_payload + curr_timestamp.encode())
    signature = tagger.finalize()

    return marshal.dumps({"signature": signature, "payload": encrypted_payload})

"""
Input a cipher and a symmtrically encrypted message content bytes
Output plaintext message content
"""
def decrypt_message(cipher, encrypted_message_bytes):
    message_decryptor = cipher.decryptor()
    decrypted_message_bytes = message_decryptor.update(encrypted_message_bytes) + message_decryptor.finalize()
    return decrypted_message_bytes.decode()

"""
Input a cipher and plaintext message content bytes
Output a symmtrically encrypted message content
"""
def encrypt_message(cipher, plaintext_message):
    message_encryptor = cipher.encryptor()
    encrypted_message_bytes = message_encryptor.update(plaintext_message.encode()) + message_encryptor.finalize()
    return encrypted_message_bytes

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

        if "sessionid_encrypted" in req.keys(): # This client already has a session ID

            # Get params from request
            client_sessionid_encrypted = req["sessionid_encrypted"]
            signature = req['signature']
            encrypted_parameters = req['encrypted_parameters']

            # Decrypt sessionid and find corresponding keys. TODO: Validate if session id hasn't expire
            client_sessionid = SERVER_PRIVATE_KEY.decrypt(client_sessionid_encrypted, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
            if client_sessionid not in sessionIdToKeys.keys():
                # (The client hasn't have the capability to process such error, TODO)
                res = symetrically_encrypt_and_marshall(client_keys['cipher'], client_keys['MAC_key'], {"msg": "Session ID error"})
                cs.send(res)
                continue
            client_keys = sessionIdToKeys[client_sessionid]

            # Decrypt parameters
            decrypted_parameters = decrypt_parameters(encrypted_parameters, client_keys['cipher'])
            request_timestamp = decrypted_parameters['curr_timestamp']
            reqType = decrypted_parameters['reqType']

            # Check timestamp
            if not validate_timestamp(int(float(request_timestamp))):
                res = symetrically_encrypt_and_marshall(client_keys['cipher'], client_keys['MAC_key'], {"msg": "Please restart application"})
                cs.send(res)
                continue
            
            # Check signature
            if not validate_signature(signature, encrypted_parameters, client_keys['MAC_key'], request_timestamp):
                res = symetrically_encrypt_and_marshall(client_keys['cipher'], client_keys['MAC_key'], {"msg": "Signature Mismatch"})
                cs.send(res)
                continue

            # Take action depending on the type of message receieved
            if reqType=="signup":

                # Decrypt new user information
                username = decrypted_parameters['username']
                password = decrypted_parameters['password']

                # Sign up
                try:
                    add_user_to_db(db, username, password)
                    res = symetrically_encrypt_and_marshall(client_keys['cipher'], client_keys['MAC_key'], {"msg": "SUCCESS"})
                    cs.send(res)
                except Exception as e:
                    res = symetrically_encrypt_and_marshall(client_keys['cipher'], client_keys['MAC_key'], {"msg": "Username already taken"})
                    cs.send(res)

            elif reqType=="login":
                # Decrypt user information
                username = decrypted_parameters['username']
                password = decrypted_parameters['password']
                
                # Login
                try:
                    if (login(db, username, password, client_sessionid)):
                        res = symetrically_encrypt_and_marshall(client_keys['cipher'], client_keys['MAC_key'], {"msg": "SUCCESS"})
                        cs.send(res)
                    else:
                        res = symetrically_encrypt_and_marshall(client_keys['cipher'], client_keys['MAC_key'], {"msg": "Failure logging in"})
                        cs.send(res)
                except:
                    res = symetrically_encrypt_and_marshall(client_keys['cipher'], client_keys['MAC_key'], {"msg": "Error"})
                    cs.send(res)

            elif reqType=="getUsers":
                users = list(usernameToSessionId.keys())
                try:
                    users.remove(sessionIdToUsername[client_sessionid])
                except:
                    print("User doesn't currently have a session...")
                res = symetrically_encrypt_and_marshall(client_keys['cipher'], client_keys['MAC_key'], {"msg": "SUCCESS", "users": str(users)})
                cs.send(res)
            elif reqType=="sendMsg":
                if client_sessionid in sessionIdToUsername.keys():
                    author = sessionIdToUsername[client_sessionid]
                    recipient = decrypted_parameters["recipient"]
                    content = decrypted_parameters["content"]
                    success = addMsgToDb(author, recipient, content, client_keys['cipher'])
                    if success:
                        res = symetrically_encrypt_and_marshall(client_keys['cipher'], client_keys['MAC_key'], {"msg": "SUCCESS"})
                        cs.send(res)
                    else:
                        res = symetrically_encrypt_and_marshall(client_keys['cipher'], client_keys['MAC_key'], {"msg": "Failure sending message"})
                        cs.send(res)
                else:
                    res = symetrically_encrypt_and_marshall(client_keys['cipher'], client_keys['MAC_key'], {"msg": "Failure sending message"})
                    cs.send(res)
            elif reqType=="getMessages":
                if client_sessionid in sessionIdToUsername.keys():
                    author = sessionIdToUsername[client_sessionid]
                    recipient = decrypted_parameters["recipient"]
                    messages = getMessagesBetweenUsers(author, recipient)

                    res = symetrically_encrypt_and_marshall(client_keys['cipher'], client_keys['MAC_key'], {"msg": "SUCCESS", "messages": str(messages)})
                    cs.send(res)
                else:
                    res = symetrically_encrypt_and_marshall(client_keys['cipher'], client_keys['MAC_key'], {"msg": "Failure getting messages"})
                    cs.send(res)
            elif reqType=="logout":
                username = sessionIdToUsername[client_sessionid]
                del sessionIdToUsername[client_sessionid]
                del usernameToSessionId[username]
        else: # if a request doesn't have a session id, we know it's a request for setup       
            # Receive client public key
            client_public_pem = req['client_public_pem']
            client_public_key = serialization.load_pem_public_key(client_public_pem)
            iv = os.urandom(16)
            private_key = os.urandom(32)
            MAC_key = os.urandom(32)
            client_cipher = Cipher(algorithms.AES(private_key), modes.CTR(iv))
            # Send server public key, session_id, private keys to client
            sessionid = os.urandom(32)
            print("Telling them their session ID is: ", sessionid)
            setup_info = marshal.dumps(dict({"session_id": sessionid, "private_key": private_key, "MAC_key": MAC_key, "iv":iv}))
            setup_info_encrypted = client_public_key.encrypt(setup_info, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            setup_reply = {'server_public_key':SERVER_PUBLIC_PEM, "setup_info_encrypted":setup_info_encrypted}
            cs.sendall(marshal.dumps(setup_reply))
            # Record client public key, private keys and iv for sessionid
            sessionIdToKeys[sessionid] = {"client_public_key": client_public_key, "private_key": private_key, "MAC_key": MAC_key, "iv":iv, "cipher":client_cipher}
            
