import re
import sys


def check(vuln_type, collection):
    vulns = []

    for doc in collection.find({"Type": {'$regex': re.escape(vuln_type)}}):
        vulns.append(doc.get('Vulnerability'))
    return vulns


if __name__ == '__main__':
    vuln_type = sys.argv[1]
    from pymongo import MongoClient

    client = MongoClient('mongodb://localhost:27017')
    db = client['exploits']
    collection = db['cves']
    print(check(vuln_type, collection))