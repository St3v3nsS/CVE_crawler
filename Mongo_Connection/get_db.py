from pymongo import MongoClient
import os
import sys
sys.path.append('/home/john/Project/CVE_crawler/')
from Configs.read_cfg import read_cfg

def get_db():  
    cfg = read_cfg("mongodb")  
    host = os.environ.get("MONGODB_HOSTNAME")
    username = os.environ.get("MONGODB_USERNAME")
    password = os.environ.get("MONGODB_PASSWORD")

    desired_db = os.environ.get("MONGODB_DATABASE")
    client = MongoClient(host, username=username, password=password, authSource=cfg["authSource"], authMechanism=cfg["authMechanism"])
    
    db = client[desired_db]

    return db

if __name__ == "__main__":
    get_db()