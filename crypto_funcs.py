from datetime import datetime
import hashlib

"""
Generates a MAC for msg, using symmetric key k. The MAC is generated as the
SHA3 hash of the current timestamp + msg + k, in that order. The function
returns the tag and the timestamp, both of which are sent to the server. The
server verifies the tag by making the same computation and ensuring that the
tag is consistent.
"""
def generate_mac_for_msg(msg, k):
    timestamp = datetime.now()
    return hashlib.SHA3_512(str(timestamp + msg + k).encode()).hexdigest()
