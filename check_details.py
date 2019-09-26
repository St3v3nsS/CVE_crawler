import re
import time


def check_details(data, collection):
    vulns = []

    for doc in collection.find({}):
        description = doc.get('Description')
        name = doc.get('Name')

        if not description:
            description = ''
        if not name:
            name = ''
        if data['cms'] in description or data['cms'] in name:
            if data['version'] in description or data['version'] in description:
                vulns.append(doc.get('Vulnerability'))

        for key in data['Plugins'].keys():
            if key in description or key in name:
                if data['Plugins'][key] in description or data['Plugins'][key] in name:
                    vulns.append(doc.get('Vulnerability'))

    return vulns