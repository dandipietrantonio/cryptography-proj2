from datetime import datetime
import hashlib

"""
Generates a MAC for msg, using symmetric key k. The MAC is generated as the 
"""
def generate_mac_for_msg(msg, k):
    timestamp = datetime.now()
