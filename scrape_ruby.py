import re
import json
import os
import time, datetime
from url_normalize import url_normalize
from pymongo import MongoClient
from scrape_html import HTMLParser
from scrape_js import JSParser
from scrape_metasploit import MetasploitParser

client = MongoClient('mongodb://localhost:27017')
db = client['exploits']
collection = db['parse_exploit']
collection.create_index([("filename", 1)], unique=True)
cve_col = db['cves']
ce = db['ce']
ce.create_index([("filename", 1)], unique=True)
exploitdb = db['exploitdb']
mitre_ref = db['cve_refs']

counter = 0
counter_rb = 0
counter_html = 0
counter_js = 0
counter_metas = 0
counter_md = 0
counter_c = 0
counter_cpp = 0
counter_python = 0
counter_php = 0
counter_perl = 0
counter_txt = 0
counter_any = 0
counter_err = 0

file = open('/home/john/Desktop/ruby', 'a+')
dictionary = {}

for (root,dirs,files) in os.walk('/home/john/Desktop/exploitdb/exploitdb/exploits', topdown=True):
    for name in files:
        filename = os.path.join(root, name)
        counter += 1

        with open(filename) as f:
            exploit = f.read()
        
        exploit_type = root.split('/')[-1]
        name1, ext = os.path.splitext(name)
        
        description_edb = exploitdb.find_one({"filename":name})
        if description_edb is not None:
            description_edb = description_edb['title']

        platform_edb = exploitdb.find_one({"filename":name})
        if platform_edb is not None:
            platform_edb = platform_edb['platform']


        if dictionary.get(ext) is not None:
            dictionary[ext] += 1
        else:
            dictionary[ext] = 1

        if ext == '.html':
            counter_html += 1
            html_parser = HTMLParser(filename, name1, exploit_type, description_edb, platform_edb, exploit)
            html_parser.parse_infos()
        elif ext =='.js':
            counter_js += 1
            js_parser = JSParser(filename, name1, exploit_type, description_edb, platform_edb, exploit)
            js_parser.parse_infos()
        elif ext == '.rb':
            counter_rb += 1
            metasploit = re.findall('class Metasploit', exploit)    # Search for 'Metasploit' occurence
            if not metasploit:
                file.write(filename + '\n')
                continue
            counter_metas += 1
            metasploit_parser = MetasploitParser(filename, name1, exploit_type, description_edb, platform_edb, exploit)
            metasploit_parser.parse_infos()
        elif ext == '.pl':
            counter_perl += 1
        elif ext == '.cpp':
            counter_cpp += 1
        elif ext == '.c':
            counter_c += 1
        elif ext == '.php':
            counter_php += 1
        elif ext == '.md':
            counter_md += 1
        elif ext == '.py':
            counter_python += 1
        elif ext == '.txt':
            counter_txt += 1
        else:
            counter_any += 1
                
print('total: ' + str(counter))
print('ruby: ' + str(counter_rb))
print('metas: ' + str(counter_metas))
print('html: ' + str(counter_html))
print('js: ' + str(counter_js))
print('txt: ' + str(counter_txt))
print('pl: ' + str(counter_perl))
print('php: ' + str(counter_php))
print('python: ' + str(counter_python))
print('c: ' + str(counter_c))
print('cpp: ' + str(counter_cpp))
print('md: ' + str(counter_md))
print('anyother: ' + str(counter_any))
print('error: ' + str(counter_err))

print(dictionary)