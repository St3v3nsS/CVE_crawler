import regex
import time
from packaging import version
import requests
import traceback

def update_vulns(doc, vulns, domain, founded_version=True, is_plugin=False, already_founded_version=False, version_in_desc=True):
    
    valid = False
    inserted = False
    if doc.get('URI'):
        valid = any(requests.head('http://' + domain + url).status_code == 200 for url in doc.get('URI'))
        if is_plugin:
            if valid and founded_version and already_founded_version:
                vulns["true_vulns"].append(doc.get('Vulnerability'))
                inserted = True
        else:
            if valid and founded_version:
                vulns["true_vulns"].append(doc.get('Vulnerability'))
                inserted = True
    if not inserted:
        if founded_version and version_in_desc:
            vulns["possible_vulns"].append(doc.get('Vulnerability'))

    return vulns

def check_version(fixed, my_version, operation):
    if operation == '==':
        if version.parse(fixed) == version.parse(my_version):
            return True
    elif operation == '<':
        if version.parse(fixed) > version.parse(my_version):
            return True
    elif operation == '<=':
        if version.parse(fixed) >= version.parse(my_version):
            return True
    elif operation == '>':
        if version.parse(fixed) < version.parse(my_version):
            return True
    elif operation == '>=':
        if version.parse(fixed) <= version.parse(my_version):
            return True         
    elif operation == '<>':
        if version.parse(fixed[0]) <= version.parse(my_version) <= version.parse(fixed[1]):
            return True
    return False

def check_details(data, collection, domain):
    vulns = {
        "true_vulns": [],
        "possible_vulns": []
    }
    founded_version = False
    print(f'Domain in check {domain}')
    vversion = data['version']
    cms = data['cms'].lower()
    for doc in collection.find({}):
        description = doc.get('Description')
        name = doc.get('Name')
        founded_version_for_cms = False
        versions = doc.get('Versions')
        exploit_cms = versions.get('CMS')

        if not description:
            description = ''

        else:
            description = description.lower()
            description = regex.sub('(?:up to|before)', '<=', description)
            description = regex.sub('between', '-', description)
            description = regex.sub('</?h\d+>', '', description)
        if not name:
            name = ''
        else:
            name = name.lower()
        
        if len(exploit_cms.keys()) == 1 and versions.get('is_plugin') == 'no' and versions.get('is_theme') == 'no':
            key =  next(iter(exploit_cms.keys()))
            if cms in key:
                founded_version_for_cms = any(check_version(item.get(next(iter(item.keys()))),vversion, next(iter(item.keys()))) for item in exploit_cms.get(key)) 
                vulns = update_vulns(doc, vulns, domain, founded_version_for_cms, version_in_desc=True) 

        if versions.get('is_plugin') == 'yes':
            vulns = extract_infos(data, description, name, cms, doc, vulns, domain, vversion, 'Plugins')
        elif versions.get('is_theme') == 'yes':
            vulns = extract_infos(data, description, name, cms, doc, vulns, domain, vversion, 'Themes')
     
    return vulns

def extract_infos(data, description, name, cms, doc, vulns, domain, vversion, plug_or_theme):
    if plug_or_theme in data:
        for key in data[plug_or_theme].keys():
            plugin = regex.sub('_', r' ', key).lower()
            vvversion = data[plug_or_theme][key].lower()

            if (plugin in description or plugin in name) and (cms in description or cms in name):
                try:
                    pass
                except TimeoutError as e:
                    pass
    return vulns
