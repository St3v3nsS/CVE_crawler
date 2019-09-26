import re

def check(url, collection, data):
    vulns = []
    print(f'Url in check {url}')
    blacklisted_paths = ['/', '/index.php', None, '']

    if url in blacklisted_paths:
        return vulns

    for doc in collection.find({"URI": {'$regex': re.escape(url)}}):
        description = doc.get('Description')
        name = doc.get('Name')
        if not description:
            description = ''
        if not name:
            name = ''
        if data:
            if data['cms'] in description or data['cms'] in name:
                if data['version'] == 'version':
                    vulns.append(doc.get('Vulnerability'))
                elif data['version'] in description or data['version'] in description:
                    vulns.append(doc.get('Vulnerability'))

            elif data['cms'] == 'Default':
                vulns.append(doc.get('Vulnerability'))
        else:
            vulns.append(doc.get('Vulnerability'))
    return vulns
