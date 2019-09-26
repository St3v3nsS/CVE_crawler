import re
import time
from packaging import version


def check_details(data, collection):
    vulns = []

    for doc in collection.find({}):
        description = doc.get('Description')
        name = doc.get('Name')

        if not description:
            description = ''
            description = re.sub('up to', '<=', description)
            description = re.sub('between', '-', description)
        else:
            description = description.lower()
        if not name:
            name = ''
        else:
            name = name.lower()
        if data['cms'] in description or data['cms'] in name:
            if data['version'] in description or data['version'] in description:
                vulns.append(doc.get('Vulnerability'))

        for key in data['Plugins'].keys():
            plugin = re.sub('_', r'\s', key).lower()
            vversion = data['Plugins'][key].lower()
            if plugin in description or plugin in name:
                regex_between = re.compile(r'((?:\d+?\.?)+)\s*-\s*((?:\d+?\.?)+)', description)
                regex_small = re.compile(r'(?:<=?)?\s*((?:\d+?\.?)+)\s*(?:<=?)?', description)
                regex_bigger = re.compile(r'(?:>?=?>?)?\s*((?:\d+?\.?)+)\s*(?:>?=?>?)?')
                if vversion in description or vversion in name:
                    vulns.append(doc.get('Vulnerability'))

    return vulns