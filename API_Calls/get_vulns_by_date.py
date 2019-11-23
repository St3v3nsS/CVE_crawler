import re
import sys
sys.path.append('/home/john/Project/CVE_crawler/')
from Mongo_Connection import get_db as mongodb
cves = "cves"

def check(date, collection):
    vulns = []

    for doc in collection.find({"Date": {'$regex': re.escape(date)}}):
        vulns.append(doc.get('Vulnerability'))
    return vulns


if __name__ == '__main__':
    date = sys.argv[1]
    db = mongodb.get_db()

    collection = db[cves]
    print(check(date, collection))