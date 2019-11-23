import re

def check(url, collection):
    vulns = []
    print(f'Url in check {url}')
    blacklisted_paths = ['/', '/index.php', None, '']

    if url in blacklisted_paths:
        return vulns

    for doc in collection.find({"URI": {'$regex': re.escape(url)}}):
         vulns.append(doc.get('Vulnerability'))
    return vulns
