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
    if(fixed == '5.2.2'):
        print(str(fixed) + ' ' + my_version + ' ' + operation)
        print() 
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

def get_vulns(doc, vulns, domain, vversion, exploit_cms, key, already_founded_version=False):
    founded_version_for_cms = any(check_version(item.get(next(iter(item.keys()))),vversion, next(iter(item.keys()))) for item in exploit_cms.get(key)) 
    return (update_vulns(doc, vulns, domain, founded_version_for_cms, version_in_desc=True, already_founded_version=already_founded_version), founded_version_for_cms) 

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
        if not isinstance(versions, dict):
            print(doc.get('EDB-ID'))
            print(versions)
            print(type(versions))
            print()
            continue
        exploit_cms = versions.get('CMS')
        if not description:
            description = ''

        else:
            description = description[0].lower()
            description = regex.sub('(?:up to|before)', '<=', description)
            description = regex.sub('between', '-', description)
            description = regex.sub('</?h\d+>', '', description)
        if not name:
            name = ''
        else:
            name = name.lower()
        
        if len(exploit_cms.keys()) == 1 and versions.get('is_plugin') == 'no' and versions.get('is_theme') == 'no':
            if versions.get('connection_between'):
                pass
            else:
                for key in exploit_cms.keys():
                    if cms in key.lower():
                        vulns, _ = get_vulns(doc, vulns, domain, vversion, exploit_cms, key)

        if versions.get('is_plugin') == 'yes':
            vulns = extract_infos(data, description, name, cms, doc, vulns, domain, vversion, 'Plugins', exploit_cms)
        elif versions.get('is_theme') == 'yes':
            vulns = extract_infos(data, description, name, cms, doc, vulns, domain, vversion, 'Themes', exploit_cms)
     
    return vulns

def extract_infos(data, description, name, cms, doc, vulns, domain, vversion, plug_or_theme, exploit_cms):
    if plug_or_theme in data:
        for keyy in data[plug_or_theme].keys():
            plugin = regex.sub('_', r' ', keyy).lower()
            vvversion = data[plug_or_theme][keyy].lower()
            founded_version_for_plug = False
            for key in exploit_cms.keys():
                if (plugin in description or plugin in name) and (cms in description or cms in name) and (cms in key.lower()):
                    try:                        
                        fake_vulns, founded_version_for_plug = get_vulns(doc, vulns, domain, vversion, exploit_cms, key)
                        vulns, _ = get_vulns(doc, vulns, domain, vversion, exploit_cms, key, founded_version_for_plug)
                    except TimeoutError as e:
                        pass
    return vulns
