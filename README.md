# SafeChat

SafeChat is a fully end-to-end encrypted instant messaging application.

---

## Running SafeChat
1. Clone the repository
2. Install the requirements in requirements.txt
`pip install -r requirements.txt`
3. Source the virtual environment
`source venv/bin/activate`
4. Change to the server directory
5. Run the server
`python3 server.py`
6. In a separate terminal, source the virtual environment again and navigate to the client directory.
7. Run the client, using a specified port
`python3 client.py $PORT`
8. You can now find SafeChat at localhost:$PORT. If you want to use the chat features, you need to run a second client process on a separate port, sign in to an account there, and visit the chat page. See the presentation video for a visual guide.
