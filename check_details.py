import regex
import time
from packaging import version
import requests
import traceback

def update_vulns(doc, vulns, domain, founded_version=True, is_plugin=False, already_founded_version=False, version_in_desc=True):
    if doc.get('EDB-ID') == '44949':
        print("founded " + str(founded_version) + '\tIsPLugin ' + str(is_plugin) + '\t already ' + str(already_founded_version) + '\tversionindesc ' + str(version_in_desc))
    
    valid = False
    if doc.get('URI'):
        for url in doc.get('URI'):
            resp = requests.head('http://' + domain + url)
            if resp.status_code == 200 and not valid:
                valid = True
                break
        if is_plugin:
            if valid and founded_version and already_founded_version:
                vulns["true_vulns"].append(doc.get('Vulnerability'))
        else:
            if valid and founded_version:
                print("INHEREEEE")
                vulns["true_vulns"].append(doc.get('Vulnerability'))
    if founded_version and version_in_desc:
        vulns["possible_vulns"].append(doc.get('Vulnerability'))
    if doc.get('EDB-ID') == '44949':
        print(vulns["true_vulns"])
        time.sleep(2)
    return vulns

def remove_xs(versions):
    if isinstance(versions[0], tuple):
        return [(regex.sub(r'\.x', '', item[0]), regex.sub('\.x', '', item[1])) for item in versions]
    return [regex.sub(r'\.x', '', item) for item in versions]

def extract_vulns(doc, vversion, vulns, domain, name, description, is_plugin, already_founded_version):

    # name part
    founded_version = False
    version_in = False
    between_version_from_name = regex.findall(r'((?:[\dx]+\.?)+\s*(?:-\d+)?)\s*<=\s*((?:[\dx]+\.?)+\s*(?:-\d+)?)', name)
    if between_version_from_name:
        version_in = True
        between_version_from_name = remove_xs(between_version_from_name)
        founded_version = check_version(between_version_from_name, vversion, '<>')
        if founded_version:
            return (update_vulns(doc, vulns, domain,founded_version, is_plugin, already_founded_version, version_in), True)

    single_version_from_name = regex.findall(r'(?<![<=>\s\.\d])\s*((?:[\dx]+\.?)+\s*(?:-\d+)?)', name, timeout=2)
    if single_version_from_name:
        version_in = True
        single_version_from_name = remove_xs(single_version_from_name)
        founded_version = check_version(single_version_from_name, vversion, '==')
        if doc.get('EDB-ID') == '18791':
            print("N-FIXED        --------->" + str(single_version_from_name))
        if founded_version:
            return (update_vulns(doc, vulns, domain,founded_version, is_plugin, already_founded_version, version_in), True)


    if not founded_version:
        small_version_from_name = regex.findall(r'(?:<=?)\s*((?:[\dx]+\.?)+\s*(?:-\d+)?)', name)
        if small_version_from_name:
            version_in = True
            small_version_from_name = remove_xs(small_version_from_name)
            founded_version = check_version(small_version_from_name, vversion, '<=')
            if doc.get('EDB-ID') == '44949':
                print("N-SMALL        --------->" + str(small_version_from_name) + str(founded_version))
            if founded_version:
                return (update_vulns(doc, vulns, domain,founded_version, is_plugin, already_founded_version, version_in), True)
    
    if not founded_version:
        bigger_version_from_name = regex.findall(r'(?:>=?)\s*((?:[\dx]+\.?)+\s*(?:-\d+)?)', name)
        if bigger_version_from_name:
            version_in = True
            bigger_version_from_name = remove_xs(bigger_version_from_name)
            founded_version = check_version(bigger_version_from_name, vversion, '>=')
            if doc.get('EDB-ID') == '18791':
                print("N-BIGGER       --------->" + str(bigger_version_from_name))
            if founded_version:
                return (update_vulns(doc, vulns, domain,founded_version, is_plugin, already_founded_version, version_in), True)
    
    if not founded_version:
        # desc part
        regex_between = regex.findall(r'(?<!\w-)((?:\d+?\.?)+)\s*-\s*((?:\d+?\.?)+)(?![\d\-]|$)', description, timeout=2)
        regex_small = regex.findall(r'(?:(?:<=?)\s*v?((?:\d+?\.?)+)|v?((?:\d+?\.?)+)\s*(?:<=?))', description, timeout=2)
        regex_bigger = regex.findall(r'(?:(?:>=?)\s*v?((?:\d+?\.?)+)|(?!(?<=\w))v?((?:\d+?\.?)+)\s*(?:>=?))', description, timeout=2)
        if doc.get('EDB-ID') == '44949':
            print("D-NTYET        --------->" + str(1))
        if regex_between:
            version_in = True
            founded_version = check_version(regex_between, vversion, '<>')
            if doc.get('EDB-ID') == '44949':
                print(description)
                print("D-NTYET        --------->" + str(regex_between) + str(founded_version))
            if founded_version:
                return (update_vulns(doc, vulns, domain,founded_version, is_plugin, already_founded_version, version_in), True)
        elif regex_small and not founded_version:
            v1 = regex_small[0]
            version_in = True
            if isinstance(v1, tuple):
                v1 = v1[0] if v1[0] else v1[1]
            if doc.get('EDB-ID') == '44949':
                print("D-NTYET        --------->" + str(v1) + str(vversion))
            if version.parse(v1) >= version.parse(vversion):
                founded_version = True
                if doc.get('EDB-ID') == '44949':
                    print("D-SMALL        --------->" + str(v1))
                return (update_vulns(doc, vulns, domain,founded_version, is_plugin, already_founded_version, version_in), True)
        elif regex_bigger and not founded_version:
            v2 = regex_bigger[0]
            version_in = True
            if isinstance(v2, tuple):
                v2 = v2[0] if v2[0] else v2[1]
            if doc.get('EDB-ID') == '44949':
                print("D-NTYET        --------->" + str(v2))
            if version.parse(vversion) >= version.parse(v2):
                founded_version = True
                if doc.get('EDB-ID') == '18791':
                    print("D-BIGGER       --------->" + str(v2))
                return (update_vulns(doc, vulns, domain,founded_version, is_plugin, already_founded_version, version_in), True)
        elif vversion and vversion != 'version' and (vversion in description or vversion in name):
            founded_version = True
            version_in = True
            return (update_vulns(doc, vulns, domain,founded_version, is_plugin, already_founded_version, version_in), True)
    return (update_vulns(doc, vulns, domain,founded_version, is_plugin, already_founded_version, version_in), False)

def check_version(versions, my_version, operation):
    for fixed in versions:
        if operation == '==':
            if version.parse(fixed) == version.parse(my_version):
                return True
        elif operation == '<=':
            if version.parse(fixed) >= version.parse(my_version):
                return True
        elif operation == '>=':
            if version.parse(fixed) <= version.parse(my_version):
                return True
        elif operation == '<>':
            if version.parse(fixed[0]) <= version.parse(my_version) <= version.parse(fixed[1]):
                return True
        else:
            return False
    return False

def check_details(data, collection, domain):
    vulns = {
        "true_vulns": [],
        "possible_vulns": []
    }
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
            description = regex.sub('</?h\d+>', '', description)
        if not name:
            name = ''
        else:
            name = name.lower()
        if (cms in description or cms in name) and 'plugin' not in name and ('theme' not in name or 'theme' not in description):
            if doc.get('EDB-ID') == '18791':
                print(description + '\n' + name)
            try:
                (vulns, founded_version) = extract_vulns(doc, vversion, vulns,domain, name, description, False, False)
            except TimeoutError as e:
                traceback.print_tb(e.__traceback__)


        for key in data['Plugins'].keys():
            plugin = regex.sub('_', r' ', key).lower()
            vvversion = data['Plugins'][key].lower()

            if (plugin in description or plugin in name) and (cms in description or cms in name):
                try:
                    (vulns, _) = extract_vulns(doc, vvversion, vulns,domain, name, description, True, founded_version)
                except TimeoutError as e:
                    pass
    return vulns
