# cryptography-proj2

To run:
 - activate the venv
 - install all dependencies
 - create the MySQL database using sql file in root, use credentials in server.py and your own password
 - in one terminal:
   - cd client
   - EXPORT FLASK_APP=client
   - EXPORT FLASK_DEBUG=1
   - flask run
 - in another terminal:
   - cd server
   - create a .env file with DB_PASSWORD=your db password
   - python3 server.py
 - go to localhost:5000 in browser and the app is running
