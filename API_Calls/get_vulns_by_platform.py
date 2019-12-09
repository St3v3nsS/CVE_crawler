import re
import sys
sys.path.append('/home/john/Project/CVE_crawler/')
from Mongo_Connection import get_db as mongodb
collection = "cves"

def check(platform, collection):
    vulns = []

    for doc in collection.find({"Platform": {'$regex': re.escape(platform)}}):
        vulns.append(doc.get('Vulnerability'))
    return vulns


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('USAGE : python3 get_vulns_by_platform.py windows')
    platform = sys.argv[1]
    db = mongodb.get_db()
    collection = db[collection]
    print(check(platform, collection))