import re
import sys
sys.path.append('/home/john/Project/CVE_crawler/')
from Mongo_Connection import get_db as mongodb

cves = "cves"


def check(url, collection):
    vulns = []
    blacklisted_paths = ['/', '/index.php', None, '']

    if url in blacklisted_paths:
        return vulns

    for doc in collection.find({"URI": {'$regex': re.escape(url)}}):
        vulns.append(doc.get('Vulnerability'))
    return vulns


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('USAGE : python3 get_vulns_by_path.py /path/to/search')
    url = sys.argv[1]
    db = mongodb.get_db()

    collection = db[cves]
    print(check(url, collection))