import re
import sys


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
            vulns.append(doc.get('Vulnerability'))
    return vulns


if __name__ == '__main__':
    print('USAGE : python3 get_vulns_by_cve.py CVE')
    cve = sys.argv[1]
    from pymongo import MongoClient

    client = MongoClient('mongodb://localhost:27017')
    db = client['exploits']
    collection = db['cves']

    if not cve.lower().startswith('cve'):
        cve = 'CVE-' + cve
    if len(cve.split('-')) < 3:
        print('idiot')
    else:
        cve = cve.replace('_', '-')
        print(check(cve, collection))