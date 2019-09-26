import re
import sys


def check(url, collection):
    vulns = []
    print(f'Url in check {url}')
    blacklisted_paths = ['/', '/index.php', None, '']

    if url in blacklisted_paths:
        return vulns

    for doc in collection.find({"URI": {'$regex': re.escape(url)}}):
        vulns.append(doc.get('Vulnerability'))
    return vulns


if __name__ == '__main__':
    url = sys.argv[1]
    from pymongo import MongoClient

    client = MongoClient('mongodb://localhost:27017')
    db = client['exploits']
    collection = db['cves']
    print(check(url, collection))