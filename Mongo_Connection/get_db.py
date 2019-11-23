from pymongo import MongoClient
import os

def get_db():    
    host = os.environ.get("MONGODB_HOSTNAME")
    username = os.environ.get("MONGODB_USERNAME")
    password = os.environ.get("MONGODB_PASSWORD")

    desired_db = os.environ.get("MONGODB_DATABASE")
    authSource = "exploits"
    authMechanism = "SCRAM-SHA-1"
    client = MongoClient(host, username=username, password=password, authSource=authSource, authMechanism=authMechanism)
    
    # client = MongoClient('mongodb://mongodb:27017/exploitdb')
    db = client[desired_db]

    return db

if __name__ == "__main__":
    get_db()