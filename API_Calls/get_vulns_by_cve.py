import re
import sys
sys.path.append('/home/john/Project/CVE_crawler/')
from Mongo_Connection import get_db as mongodb
cves = "cves"

def check(cve, collection):
    vulns = []

    for doc in collection.find({}):
        description = doc.get('Description')
        name = doc.get('Name')

        if not description:
            description = ''
        if not name:
            name = ''
        if cve in name or cve in description or cve in doc.get('Vulnerability'):
            vulns.append(doc)
    return vulns


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('USAGE : python3 get_vulns_by_cve.py CVE')
    cve = sys.argv[1]
    db = mongodb.get_db()

    collection = db[cves]

    if not cve.lower().startswith('cve'):
        cve = 'CVE-' + cve
    if len(cve.split('-')) < 3:
        print('USAGE : python3 get_vulns_by_cve.py CVE')
    else:
        cve = cve.replace('_', '-')
        print(check(cve, collection))