import regex
import time
from packaging import version
import requests


def update_vulns(doc, vulns, domain):
    valid = False
    if doc.get('URI'):
        for url in doc.get('URI'):
            resp = requests.head('http://' + domain + url)
            if resp.status_code == 200 and not valid:
                valid = True
                break
        if valid:
            vulns.append(doc.get('Vulnerability'))
    return vulns


def check_details(data, collection, domain):
    vulns = []
    print(f'Domain in check {domain}')
    for doc in collection.find({}):
        description = doc.get('Description')
        name = doc.get('Name')
        vversion = data['version']
        cms = data['cms'].lower()

        if not description:
            description = ''

        else:
            description = description.lower()
            description = regex.sub('up to', '<=', description)
            description = regex.sub('between', '-', description)
        if not name:
            name = ''
        else:
            name = name.lower()
        if (cms in description or cms in name) and 'plugin' not in name and ('theme' not in name or 'theme' not in description):


            try:
                regex_between = regex.findall(r'((?:\d+?\.?)+)\s*-\s*((?:\d+?\.?)+)', description, timeout=2)
                regex_small = regex.findall(r'(?:(?:<=?)\s*v?((?:\d+?\.?)+)|v?((?:\d+?\.?)+)\s*(?:<=?))', description, timeout=2)
                regex_bigger = regex.findall(r'(?:(?:>=?)\s*v?((?:\d+?\.?)+)|v?((?:\d+?\.?)+)\s*(?:>=?))', description, timeout=2)
                if regex_between:
                    v1 = regex_between[0][0]
                    v2 = regex_between[0][1]
                    if version.parse(v1) <= version.parse(vversion) <= version.parse(v2):
                        print('Without:\t\t\t')
                        print(description)
                        print(name)
                        vulns = update_vulns(doc, vulns, domain)
                elif regex_small:
                    v1 = regex_small[0]
                    if isinstance(v1, tuple):
                        v1 = v1[0] if v1[0] else v1[1]
                    if version.parse(v1) <= version.parse(vversion):
                        print('Without:\t\t\t')
                        print(description)
                        print(name)
                        vulns = update_vulns(doc, vulns, domain)
                elif regex_bigger:
                    v2 = regex_bigger[0]
                    if isinstance(v2, tuple):
                        v2 = v2[0] if v2[0] else v2[1]
                    if version.parse(vversion) <= version.parse(v2):
                        print('Without:\t\t\t')
                        print(description)
                        print(name)
                        vulns = update_vulns(doc, vulns, domain)
                elif vversion and vversion != 'version' and (vversion in description or vversion in name):
                    print('Without:\t\t\t')
                    print(description)
                    print(name)
                    vulns = update_vulns(doc, vulns, domain)
            except TimeoutError as e:
                pass

        for key in data['Plugins'].keys():
            plugin = regex.sub('_', r' ', key).lower()
            vversion = data['Plugins'][key].lower()

            if plugin in description or plugin in name:

                try:
                    regex_between = regex.findall(r'((?:\d+?\.?)+)\s*-\s*((?:\d+?\.?)+)', description, timeout=2)
                    regex_small = regex.findall(r'(?:(?:<=?)\s*v?((?:\d+?\.?)+)|v?((?:\d+?\.?)+)\s*(?:<=?))', description, timeout=2)
                    regex_bigger = regex.findall(r'(?:(?:>=?)\s*v?((?:\d+?\.?)+)|v?((?:\d+?\.?)+)\s*(?:>=?))', description, timeout=2)
                    if regex_between:
                        v1 = regex_between[0][0]
                        v2 = regex_between[0][1]
                        if version.parse(v1) <= version.parse(vversion) <= version.parse(v2):
                            print('With:\t\t\t')
                            print(description)
                            print(name)
                            vulns = update_vulns(doc, vulns, domain)
                    elif regex_small:
                        v1 = regex_small[0]
                        if isinstance(v1, tuple):
                            v1 = v1[0] if v1[0] else v1[1]
                        if version.parse(v1) <= version.parse(vversion):
                            print('With:\t\t\t')
                            print(description)
                            print(name)
                            vulns = update_vulns(doc, vulns, domain)
                    elif regex_bigger:
                        v2 = regex_bigger[0]
                        if isinstance(v2, tuple):
                            v2 = v2[0] if v2[0] else v2[1]
                        if version.parse(vversion) <= version.parse(v2):
                            print('With:\t\t\t')
                            print(description)
                            print(name)
                            vulns = update_vulns(doc, vulns, domain)
                    elif vversion and vversion != 'version' and (vversion in description or vversion in name):
                        print('With:\t\t\t')
                        print(description)
                        print(name)
                        vulns = update_vulns(doc, vulns, domain)
                except TimeoutError as e:
                    pass
    return vulns
