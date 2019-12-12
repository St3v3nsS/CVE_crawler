import regex
import time
from packaging import version
import requests
import traceback
import logging
import sys
sys.path.append('/home/john/Project/CVE_crawler/')
from Loggers import logger

class Checker(object):
    def __init__(self, domain, collection, data=None):
        self.domain = domain
        self.data = data
        self.collection = collection
        self.vulns_by_cms = []
        self.vulns_by_cms_and_plugs = []
        self.vulns = {
            "true_vulns": [],
            "almost_true": [],
            "probable_vulns": [],
            "possible_vulns": []
        }
        self.logger = logger.myLogger('Checker')
        self.logger.info('Initiating checker...')

    def set_data(self, data):
        self.data = data

    def update_vulns(self, doc, obj):
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
        self.logger.info(f'Checking for exploit target path in server: {doc.get("Vulnerability")}')
        valid = False
        inserted = False
        if doc.get('URI'):
            valid = any(requests.head('http://' + self.domain + url).status_code == 200 for url in doc.get('URI'))
            if obj.get("is_plugin_or_theme") :
                if valid and obj.get("found_in_name") and obj.get("found_in_desc"):
                    self.vulns["true_vulns"].append(doc.get('Vulnerability'))
                    inserted = True
                elif valid and obj.get("found_in_name"):
                    self.vulns["almost_true_vulns"].append(doc.get('Vulnerability'))
                    inserted = True
                elif valid:
                    self.vulns["probable_vulns"].append(doc.get('Vulnerability'))
                    inserted = True    
            else:
                if valid and obj.get("found_in_name"):
                    self.vulns["true_vulns"].append(doc.get('Vulnerability'))
                    inserted = True
                elif valid and obj.get("found_in_desc"):
                    self.vulns["almost_true_vulns"].append(doc.get('Vulnerability'))
                    inserted = True
                elif valid:
                    self.vulns["probable_vulns"].append(doc.get('Vulnerability'))
                    inserted = True    
        if not inserted:
            if obj.get("found_in_name") or obj.get("found_in_desc"):
                self.vulns["possible_vulns"].append(doc.get('Vulnerability'))

    def check_version(self, fixed, my_version, operation):

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

    def find_in(self, exploit_title, key, vversion):
        # sign = next(iter(version.keys()))
        # value = version.get(sign)
        return any([self.check_version(versionn.get(next(iter(versionn.keys()))), vversion, next(iter(versionn.keys()))) for versionn in exploit_title.get(key)])

    def find_key(self, objects, key):
        arr = [objecct.get('name') for objecct in objects]
        return arr.index(key)

    def check_details(self):
        self.logger.info('Checking details from zero')
        vversion = self.data['version']
        cms = self.data['cms'].lower()
        
        for doc in self.collection.find({}):                        
            self.update_vulns_without_plugs(doc, cms, vversion)
            self.update_vulns_with_plugs(doc, cms, vversion)
        
    def get_vulns(self, exploit_desc, exploit_title, cms,cms_or_plug, doc, vversion, is_plugin, is_plugin_vers=None):
        arr = []
        for keyy in exploit_desc.keys():
            if cms in keyy.lower(): 
                arr.append(self.find_in(exploit_desc, keyy, vversion))
        find_cms_desc = any(arr)

        for key in exploit_title.keys():
            if cms_or_plug in key.lower():
                find_cms_name = self.find_in(exploit_title, key, vversion)
                obj = {
                    "name": key,
                    "found_in_name": find_cms_name,
                    "found_in_desc": find_cms_desc,
                    "is_plugin_or_theme": is_plugin
                }
                self.update_vulns(doc, obj)
                if is_plugin:
                    self.vulns_by_cms_and_plugs.append({
                        "doc": doc.get("EDB-ID"),
                        "obj": obj
                    })
                else:
                    self.vulns_by_cms.append({
                        "doc": doc.get("EDB-ID"),
                        "obj": obj
                    })

    def extract_infos(self, description, name, cms, doc, vversion, plug_or_theme, exploit_title, exploit_desc):
        
        if plug_or_theme in self.data:
            for keyy in self.data[plug_or_theme].keys():
                plugin = regex.sub('_', r' ', keyy).lower()
                vvversion = self.data[plug_or_theme][keyy].lower()
                self.get_vulns(exploit_desc, exploit_title, cms, plugin, doc, vversion, True, vvversion)

    def get_all_vulns(self):
        return self.vulns

    def get_vulns_by_cms(self):
        return self.vulns_by_cms

    def get_vulns_by_cms_and_plug(self):
        return self.vulns_by_cms_and_plugs

    def update_vulns_from_redis(self, vulns):
        self.logger.info(f'Updating {len(vulns)} vulns from redis')
        for vuln in vulns:
            self.update_vulns(self.collection.find_one({"EDB-ID": vuln.get("doc")}), vuln.get("obj"))

    def update_vulns_just_cms(self, vulns):
        self.logger.info(f'Updating {len(vulns)} vulns from redis with just cms')
        self.update_vulns_from_redis(vulns)
        ids = [vuln.get("doc") for vuln in vulns]
        vversion = self.data['version']
        cms = self.data['cms'].lower()
        for doc in self.collection.find({"EDB-ID": { '$nin': ids}}):
            self.update_vulns_with_plugs(doc, cms, vversion)

    def update_vulns_with_plugs(self, doc, cms, vversion):
        name, description, versions, exploit_title, exploit_desc = self.extract_doc_data(doc)

        if versions.get('is_plugin') == 'yes':
            self.extract_infos(description, name, cms, doc, vversion, 'Plugins', exploit_title, exploit_desc)
        elif versions.get('is_theme') == 'yes':
            self.extract_infos(description, name, cms, doc, vversion, 'Themes', exploit_title, exploit_desc)

    def update_vulns_without_plugs(self, doc, cms, vversion):
        _, _, versions, exploit_title, exploit_desc = self.extract_doc_data(doc)

        if versions.get('is_plugin') == 'no' and versions.get('is_theme') == 'no':
            if versions.get('connection_between'):
                pass
            else:
                self.get_vulns(exploit_desc, exploit_title, cms,cms, doc, vversion, False)

    def extract_doc_data(self, doc):
        description = doc.get('Description')
        name = doc.get('Name')
        versions = doc.get('Versions')
        exploit_title = versions.get('CMS')
        exploit_desc = versions.get('description')

        description = '' if not description else description.lower()
        name = '' if not name else name.lower()

        return name, description, versions, exploit_title, exploit_desc

    def check_path(self, url):
        self.logger.info(f'Checking for url {url}')
        blacklisted_paths = ['/', '/index.php', None, '']

        if url not in blacklisted_paths:
            for doc in self.collection.find({"URI": {'$regex': regex.escape(url)}}):
                self.vulns["possible_vulns"].append(doc.get('Vulnerability'))
