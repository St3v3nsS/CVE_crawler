import re
import json
import time
from pymongo import MongoClient
from six import string_types

class HTMLParser(object):
    def __init__(self, filename, name, exploit_type, exploit):
        self.exploit = exploit
        self.filename = filename
        self.name = name
        self.exploit_type = exploit_type
        self.client = MongoClient('mongodb://localhost:27017')
        self.db = self.client['exploits']
        self.collection = self.db['cve_refs']
    
    def parse_infos(self):
        print(self.filename)
        title = 'NOCVE'
        if self.collection.find_one({"filename": self.name}) is not None:
            title = self.collection.find_one({"filename": self.name})['cve']
        
        comments = re.findall('\/\*(.*?)\*\/', self.exploit, re.S | re.M)
        comments.append(re.findall('<!--(.*)-->', self.exploit, re.S | re.M))
        comments.append(re.sub('<.*>', '', self.exploit, re.S | re.M))
        comments.append(re.findall("//'=+(.*?)//'=+", self.exploit, re.S | re.M))
        comments.append(re.findall('(?:##)+(.*)(?:##)+', self.exploit, re.S | re.M))

        new_comments = []
        for array in comments:
            if isinstance(array, string_types):
                new_comments.append(array)
            else:
                for comment in array:
                    new_comments.append(comment)

        refs = []
        description = []
        component = []
        vversion = []
        name = []
        for comment in new_comments:
            refs.extend(re.findall('source:\s(.*)', comment))
            refs.extend(re.findall('(https?.+)', comment))
            refs.extend(re.findall('(C[VW]E)-(\d+(-\d+)?)', comment))
            description.extend(re.findall('(?:Description|Summary|Product)\s*:?\s*(.*?)\n\n', comment))
            description.extend(re.findall('Vulnerability\.+:?(.*?)#', comment))
            component.extend(re.findall('Component\s*:\s*(.*)', comment))
            vversion.extend(re.findall('Vulnerable version\s*:\s*(.*)', comment))
            name.extend(re.findall('(?:Title|Name|Topic|Software)\s*:?\s*(.*)', comment))
            name.extend(re.findall('^(.*?)<br>', comment))
            name.extend(re.findall('Script\.+:?(.*?)#', comment))
            name.extend(re.findall('script\s*:\s*(.*)'))
            name.extend(re.findall('#\s*(\[fuzzylime \(cms\) <= 3\.0\])', comment))

        name.extend(re.findall('<tit[lr]e>(.*?)</tit[lr]e>', self.exploit))
        name.extend(re.findall('<h\d.?>(.*?)</h\d>', self.exploit))

        if not description:
            description = new_comments
        references = []
        for ref in list(set(refs)):
            if isinstance(ref,tuple):
                references.append([ref[0], ref[1]])
            else:
                references.append(['URL', ref])
        print(references)
        if description:
            print(description)
            print(component)
            print(vversion)
            print(name)
            if not name:
                name = component
            time.sleep(3)

        myDict = {
            title: {
                "Name": name,
                "Description": description,
                "Platform": "",
                "References": references,
                "Targets": [],
                "Type": self.exploit_type,
                "URI": []
            }
        }

        print(myDict)
    
    def parse_url(self):
        return obj



