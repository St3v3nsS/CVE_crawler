import regex
import time
from packaging import version
import requests
import traceback

def update_vulns(doc, vulns, domain, obj):
    # 1.00 -> URI + v_nume
    # 0.75 -> URI + v_desc
    # 0.50 -> URI
    # 0.25 -> v_nume / v_desc

    # plugin/ theme
    # 1.00 -> URI + v_nume/ v_desc + v_cms
    # 0.75 -> URI + v_nume/ v_desc
    # 0.50 -> URI
    # 0.25 -> v_nume / v_desc 

    # obj = {
    #     "name": key,
    #     "found_in_name": find_cms_name,
    #     "found_in_desc": find_cms_desc,
    #     "is_plugin_or_theme": False
    # }
    if doc.get('EDB-ID') == "35916":
        print(obj)
    valid = False
    inserted = False
    if doc.get('URI'):
        valid = any(requests.head('http://' + domain + url).status_code == 200 for url in doc.get('URI'))
        if obj.get("is_plugin_or_theme") :
            if valid and obj.get("found_in_name") and obj.get("found_in_desc"):
                vulns["true_vulns"].append(doc.get('Vulnerability'))
                inserted = True
            elif valid and obj.get("found_in_name"):
                vulns["almost_true_vulns"].append(doc.get('Vulnerability'))
                inserted = True
            elif valid:
                vulns["probable_vulns"].append(doc.get('Vulnerability'))
                inserted = True    
        else:
            if valid and obj.get("found_in_name"):
                vulns["true_vulns"].append(doc.get('Vulnerability'))
                inserted = True
            elif valid and obj.get("found_in_desc"):
                vulns["almost_true_vulns"].append(doc.get('Vulnerability'))
                inserted = True
            elif valid:
                vulns["probable_vulns"].append(doc.get('Vulnerability'))
                inserted = True    
    if not inserted:
        if obj.get("found_in_name") or obj.get("found_in_desc"):
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

def find_in(exploit_title, key, vversion):
    # sign = next(iter(version.keys()))
    # value = version.get(sign)
    return any([check_version(versionn.get(next(iter(versionn.keys()))), vversion, next(iter(versionn.keys()))) for versionn in exploit_title.get(key)])

def find_key(objects, key):
    arr = [objecct.get('name') for objecct in objects]
    return arr.index(key)

def check_details(data, collection, domain):
    vulns = {
        "true_vulns": [],
        "almost_true": [],
        "probable_vulns": [],
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
        exploit_title = versions.get('CMS')
        exploit_desc = versions.get('description')
        if not description:
            description = ''

        else:
            description = description.lower()

        if not name:
            name = ''
        else:
            name = name.lower()
        
        if versions.get('is_plugin') == 'no' and versions.get('is_theme') == 'no':
            if versions.get('connection_between'):
                pass
            else:
               vulns = get_vulns(exploit_desc, exploit_title, cms,cms, doc, domain, vulns, vversion, False)
        if versions.get('is_plugin') == 'yes':
            vulns = extract_infos(data, description, name, cms, doc, vulns, domain, vversion, 'Plugins', exploit_title, exploit_desc)
        elif versions.get('is_theme') == 'yes':
            vulns = extract_infos(data, description, name, cms, doc, vulns, domain, vversion, 'Themes', exploit_title, exploit_desc)
     
    return vulns

def get_vulns(exploit_desc, exploit_title, cms,cms_or_plug, doc, domain, vulns, vversion, is_plugin):
    arr = []
    for keyy in exploit_desc.keys():
        if cms in keyy.lower(): 
            arr.append(find_in(exploit_desc, keyy, vversion))
    find_cms_desc = any(arr)

    for key in exploit_title.keys():
        if cms_or_plug in key.lower():
            find_cms_name = find_in(exploit_title, key, vversion)
            obj = {
                "name": key,
                "found_in_name": find_cms_name,
                "found_in_desc": find_cms_desc,
                "is_plugin_or_theme": is_plugin
            }
            vulns = update_vulns(doc, vulns, domain, obj)
    return vulns

def extract_infos(data, description, name, cms, doc, vulns, domain, vversion, plug_or_theme, exploit_title, exploit_desc):
    if plug_or_theme in data:
        for keyy in data[plug_or_theme].keys():
            plugin = regex.sub('_', r' ', keyy).lower()
            vvversion = data[plug_or_theme][keyy].lower()
            vulns = get_vulns(exploit_desc, exploit_title, cms, plugin, doc, domain, vulns, vversion, True)
                
    return vulns
