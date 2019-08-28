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

        refs = []
        description = []
        component = []
        vversion = []
        name = []
        new_comments = []
        targets = []

        file = open('/home/john/Desktop/html', 'a+')
        file.write(self.filename)

        if self.collection.find_one({"filename": self.name}) is not None:
            title = self.collection.find_one({"filename": self.name})['cve']
        
        comments = re.findall('\/\*(.*?)\*\/', self.exploit, flags=re.S | re.M) # C-style comments
        comments.append(re.findall('<!?--(.*)--!?>', self.exploit, flags=re.S | re.M))  # HTML comments
        comments.append(re.sub('<.*>', '', self.exploit,flags= re.S | re.M))    # Take everything outside the < >
        comments.append(re.findall("//'=+(.*?)//'=+", self.exploit,flags= re.S | re.M)) # Some JS comments
        comments.append(re.findall('(?:##)+(.*)(?:##)+', self.exploit,flags= re.S | re.M))  # Some dashes

        name.extend(re.findall('<[tT][iI][Tt][lLRr][eE]>(.*?)</[Tt][Ii][Tt][LlRr][Ee]>', self.exploit)) # <title>
        name.extend(re.findall('<h\d.?>(.*?)</h\d>', self.exploit)) # headings
        tuples = re.findall('(Netscape|Opera|Safari).*(Browser).*(\(V.*?\))', self.exploit, flags=re.S|re.M)
        if tuples:
            tuples = tuples[0]
            name.extend([tuples[0] + ' ' + tuples[1] + ' ' + tuples[2]])
            vversion.extend([tuples[0] + ' ' + tuples[1] + ' ' + tuples[2]])
        for array in comments:  #   Make array from array of arrays
            if isinstance(array, string_types):
                new_comments.append(array)
            else:
                for comment in array:
                    new_comments.append(comment)

        for comment in new_comments:
            source_at_begin = re.findall('^[Ss]ource.*\n\n(.*)\s+(.*)\s+(.*)', comment) # For comments like source .. \n text \n text
            if source_at_begin:
                source_at_begin = source_at_begin[0]
                name.extend([source_at_begin[0] ])
                description.extend([source_at_begin[1]])
                if len(source_at_begin[0]) > 2:
                    targets.extend([source_at_begin[2]])
            if '==' in comment: # For comments like ==1.==
                values = re.findall('==5\..*?==(.*?)-', comment, flags=re.S|re.M)
                if values:
                    description.extend(values)
                    name.extend(re.findall('==3\.(.*?)==', comment))
                    
            elif '-----' in comment:    # For comments splitted by -----
                values = re.findall('(.*?)-+', comment,flags= re.S | re.M)
                if values:
                    name.extend([values[0]])
                    if len(values) > 1:
                        description.extend([values[1]])

            # All posibilities depending on how they write their code
            refs.extend(re.findall('[Ss]ource:\s(.*)', comment))
            refs.extend(re.findall('(https?.+)', comment))
            refs.extend(re.findall('(C[VW]E)-(\d+(-\d+)?)', comment))
            description.extend(re.findall('(?:Description|Summary|Product)\s*:?\s*(.*?)\n\n', comment))
            description.extend(re.findall('Vulnerability\.+:?(.*?)#', comment))
            component.extend(re.findall('Component\s*:\s*(.*)', comment))
            vversion.extend(re.findall('Vulnerable version\s*:\s*(.*)', comment))
            vversion.extend(re.findall('[^\w/](?:VERSIONS?|Versions?(?:\s*numbers:?\s*-+\n)?)\s*:?\s*(.*\s+.*)', comment))
            name.extend(re.findall('[^\w/](?:Title|Name|Topic|Software)\s*:?\s*(.*)', comment))
            name.extend(re.findall('^(.*?)<br>', comment))
            name.extend(re.findall('Script\.+:?(.*?)#', comment))
            name.extend(re.findall('#\s*(\[.*?\])', comment))
            targets.extend(re.findall('Tested\s*on:\s*(.*)', comment))
        
        # Transform arrays to strings by joining all the founded variants
        name = ' -- '.join(name)
        description = ' -- '.join(description)
        component = ' -- '.join(component)
        vversion = ' -- '.join(vversion)
        targets = ' -- '.join(targets)

        references = []
        for ref in list(set(refs)):
            if isinstance(ref,tuple):
                references.append([ref[0], ref[1]])
            else:
                references.append(['URL', ref])
        file.write('Refs:   ' + str(references) + '\n')
        file.write('Desc:   ' + description + '\n')
        file.write('Comp:   ' + component + '\n')
        file.write('Vers:   ' + vversion + '\n')
        file.write('Name:   ' + name + '\n')
        file.write('Targ:   ' + targets + '\n')
        file.write('\n')
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



