import re
import sys


def check(platform, collection):
    vulns = []

    for doc in collection.find({"Platform": {'$regex': re.escape(platform)}}):
        vulns.append(doc.get('Vulnerability'))
    return vulns


if __name__ == '__main__':
    platform = sys.argv[1]
    from pymongo import MongoClient

    client = MongoClient('mongodb://localhost:27017')
    db = client['exploits']
    collection = db['cves']
    print(check(platform, collection))