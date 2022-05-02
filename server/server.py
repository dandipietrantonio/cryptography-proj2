import socket
import json
import mysql.connector
from dotenv import load_dotenv
import os

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

    cursor.execute(f"SELECT * FROM users WHERE username=%s AND `password`=%s", (str(username), str(password)))

    res = cursor.fetchall()

    if(len(res) > 0):
        # Try adding public key
        try:
            cursor = db.cursor()
            cursor.execute(f"UPDATE users SET public_key=%s WHERE username=%s", (str(pubkey),str(username)))
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

        if req["type"]=="add_user":
            try:
                add_user_to_db(db, req['username'], req['password'])
                cs.send(bytes("SUCCESS", encoding="utf-8"))
            except Exception as e:
                cs.send(bytes("Username already taken", encoding="utf-8"))
        elif req["type"]=="login":
            if (login(db, req['username'], req['password'], req['public_key'], req['session_id'])):
                cs.send(bytes("SUCCESS", encoding="utf-8"))
            else:
                cs.send(bytes("Failure logging in", encoding="utf-8"))







# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
# db = SQLAlchemy(app)
# 
# class User(db.Model):
    # username = db.Column(db.String(200), primary_key=True, nullable=False)
    # password = db.Column(db.String(200), nullable=False)
    # is_online = db.Column(db.Integer, default=0)
# 
    # def __repr__(self):
        # return '<User %r>' % self.username

    
