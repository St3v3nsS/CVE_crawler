import re

from pymongo import MongoClient
import sys

client = MongoClient('mongodb://localhost:27017')
db = client['exploits']
collection = db['cves']

def check(url):
    vulns = []
    print(url)
    for doc in collection.find({"URI": {'$regex': re.escape(url)}}):
        print(doc.get('Vulnerability') + f'------>>>> {doc.get("Name")}')
        print()
        vulns.append(doc.get('Vulnerability'))
    return vulns
