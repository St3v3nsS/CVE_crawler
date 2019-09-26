import re
import sys


def check(date, collection):
    vulns = []

    for doc in collection.find({"Date": {'$regex': re.escape(date)}}):
        vulns.append(doc.get('Vulnerability'))
    return vulns


if __name__ == '__main__':
    date = sys.argv[1]
    from pymongo import MongoClient

    client = MongoClient('mongodb://localhost:27017')
    db = client['exploits']
    collection = db['cves']
    print(check(date, collection))