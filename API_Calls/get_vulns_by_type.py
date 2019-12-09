import re
import sys
sys.path.append('/home/john/Project/CVE_crawler/')
from Mongo_Connection import get_db as mongodb
cves = "cves"

def check(vuln_type, collection):
    vulns = []

    for doc in collection.find({"Type": {'$regex': re.escape(vuln_type)}}):
        vulns.append(doc.get('Vulnerability'))
    return vulns


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('USAGE : python3 get_vulns_by_type.py dos')
    vuln_type = sys.argv[1]
    db = mongodb.get_db()

    collection = db[cves]
    print(check(vuln_type, collection))