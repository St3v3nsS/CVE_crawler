import re
import os
import time
from pymongo import MongoClient
from Scrapers.init_scrapers import add_scrapers

scrapers = add_scrapers()

client = MongoClient('mongodb://localhost:27017')
db = client['exploits']
collection = db['parse_exploit']
collection.create_index([("filename", 1)], unique=True)
cve_col = db['cves']
ce = db['ce']
ce.create_index([("filename", 1)], unique=True)
exploitdb = db['exploitdb']
mitre_ref = db['cve_refs']

dictionary = {}

start = time.time()


def parse_folder(path):
    for (root, dirs, files) in os.walk(path, topdown=True):
        for name in files:
            filename = os.path.join(root, name)

            with open(filename) as f:
                exploit = f.read()

            exploit_type = root.split('/')[-1]
            name1, ext = os.path.splitext(name)

            platform_edb = None
            description_edb = None
            date = None
            edb = exploitdb.find_one({"filename": name})
            if edb is not None:
                description_edb = edb['title']
                platform_edb = edb['platform']
                date = edb['date']

            if dictionary.get(ext) is not None:
                dictionary[ext]['total'] += 1
            else:
                obj = {
                    "total": 1,
                    "filename": filename
                }
                dictionary[ext] = obj

            if ext == '.rb':
                metasploit = re.findall('(?:class Metasploit|msf/core)', exploit)  # Search for 'Metasploit' occurence
                if metasploit:
                    ext = '.metasploit'

            print(filename)
            parser = scrapers.get(ext)
            if not parser:
                continue

            scraper = parser(filename, name1, exploit_type, description_edb, platform_edb, exploit, client, date)
            scraper.parse_infos()

    print(time.time() - start)
