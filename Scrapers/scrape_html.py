import re
import regex
import datetime

from .scraper import Scraper
from six import string_types

class HTMLParser(Scraper):
    def __init__(self, filename=None, name=None, exploit_type=None, title=None, platform=None, exploit=None):
        ext = ['.html', '.xhtml']
        super().__init__(filename, name, exploit_type, title, platform, exploit, ext)
    
    def parse_infos(self):
        cves = self.db['cves']

        print(self.filename)

        query = self.parsed_col.find_one({"filename": self.filename})
        if query is not None:
            parsed = query['parsed']
            if parsed:
                return
        
        error = False
        parsed_file = True
        try:
            title = re.sub('\s', '_', self.title)
            title = re.sub('\.', '@', title)
            title = self.name + '_' + title

            refs = []
            description = []
            component = []
            vversion = []
            name = []
            new_comments = []
            targets = []

            self.exploit = re.sub('&\s*n\s*b\s*s\s*p\s*;', '', self.exploit)
            file = open('/home/john/Desktop/html', 'a+')

            if self.collection.find_one({"filename": self.name}) is not None:
                title = self.collection.find_one({"filename": self.name})['cve']
            
            # Even if the name of exploit exists, I need it for finding other stuffs, but it will not be included in the json

            comments = re.findall('\/\*(.*?)\*\/', self.exploit, flags=re.S | re.M) # C-style comments
            html_comments = re.findall('<!?--(.*?)--!?>', self.exploit, flags=re.S | re.M)  # HTML comments
            if html_comments:
                value = re.findall('(.*)\n(?:http|[sS]ource:)', html_comments[0])
                if value and '==' not in value[0] and len(value[0]) > 0 and '**' not in value[0]:
                    name.extend([value[0]])
                if not name:
                    value = re.findall('\n(.*?)\n', html_comments[0], flags=re.M|re.S)
                    if value and '--' not in value[0] and '==' not in value[0]:
                        name.extend([value[0]])
                    if not name:
                        value = re.findall('(.*?)\n\n', html_comments[0], flags=re.M|re.S)
                        if value and '--' not in value[0]:
                            name.extend([value[0]])
                    else:
                        value = re.findall('--\n(.*?)\n\n', html_comments[0], flags=re.M|re.S)
                        if value and ('###' not in value[0] or '===' not in value[0]):
                            description.extend([value[0]])
                else:
                    value = re.findall('\n\n(.*?)\n\n', html_comments[0], flags=re.M|re.S)
                    if value and ('###' not in value[0] or '===' not in value[0]):
                        description.extend([value[0]])


            comments.append(html_comments)  # HTML comments
            if not re.findall('^<.*>', self.exploit, flags=re.S |re.M):  
                comments.append(re.sub('<[\w\s]+>(.*)</\w+>', '', self.exploit,flags= re.S | re.M))    # Take everything outside the < >
            else:
                comments.append(re.sub('^<.*>', '', self.exploit,flags= re.S | re.M))    # Take everything outside the < >

            comments.append(re.findall("//'=+(.*?)//'=+", self.exploit,flags= re.S | re.M)) # Some JS comments
            comments.append(re.findall('(?:##)+(.*)(?:##)+', self.exploit,flags= re.S | re.M))  # Some dashes

            name.extend(re.findall('<[tT][iI][Tt][lLRr][eE]>(.*?)</[Tt][Ii][Tt][LlRr][Ee]>', self.exploit)) # <title>
            tuples = re.findall('(Netscape|Opera|Safari).*(Browser).*(\(V.*?\))', self.exploit, flags=re.S|re.M)
            if tuples:
                tuples = tuples[0]
                name.extend([tuples[0] + ' ' + tuples[1] + ' ' + tuples[2]])
                vversion.extend([tuples[0] + ' ' + tuples[1] + ' ' + tuples[2]])
                name.extend(re.findall('<h\d.?>(.*?)</h\d>', self.exploit)) # headings

            for array in comments:  #   Make array from array of arrays
                if isinstance(array, string_types):
                    new_comments.append(array)
                else:
                    for comment in array:
                        new_comments.append(comment)

            for comment in new_comments:
                source_at_begin = re.findall('^[Ss]ource.*\s+(.*)\s+(.*)\s+([^#]+?)\n', comment) # For comments like source .. \n text \n text
                if source_at_begin:
                    source_at_begin = source_at_begin[0]
                    name.extend([source_at_begin[0] ])
                    if ('###' not in source_at_begin[1] or '===' not in source_at_begin[1]):
                        description.extend([source_at_begin[1]])
                    if len(source_at_begin[0]) > 2 and '####' not in source_at_begin[2]:
                        targets.extend([source_at_begin[2]])
                if '==' in comment: # For comments like ==1.==
                    values = re.findall('==5\..*?==(.*?)-', comment, flags=re.S|re.M)
                    if values:
                        description.extend(values)
                        name.extend(re.findall('==3\.(.*?)==', comment))
                    else:
                        values = re.findall('==+\s+(.*?)\n', comment)
                        if values:
                            name.extend([values[0]])
                        
                elif '-----' in comment and not '//' in comment:    # For comments splitted by -----
                    values = re.findall('(.*?)--+', comment,flags= re.S | re.M)
                    if values:
                        name.extend([values[0]])
                        if len(values) > 1:
                            description.extend([values[1]])

                if not name:
                    name.extend(re.findall('<h\d.?>(.*?)</h\d>', self.exploit)) # headings

                # All posibilities depending on how they write their code
                refs.extend(re.findall('[Ss]ource:\s(.*)', comment))
                refs.extend(re.findall('(https?://[^,\'\s\"\]\)]+)', comment))
                refs.extend(re.findall('(C[VW]E)-(\d+(-\d+)?)', comment))
                description.extend(re.findall('(?:Description|Summary|Product|DESCRIPTION|Desc)\s*:?\s*(.*?)\n\n?', comment))
                description.extend(re.findall('Vulnerability\.+:?(.*?)#', comment))
                description.extend(re.findall('Vulnerability Details:\s+(.*)', comment))
                component.extend(re.findall('Component\s*:\s*(.*)', comment))
                vversion.extend(re.findall('Vulnerable version\s*:\s*(.*)', comment))
                vversion.extend(re.findall('[^\w/](?:VERSIONS?|Versions?(?:\s*numbers:?\s*-+\n)?)\s*:?\s*(.*\s+.*)', comment))
                vversion.extend(re.findall('Affected\s*version\s*:\s*(.*\s*.*)?\s*\w+:', comment))
                name.extend(re.findall('[^\w/](?:Title|Name|Topic|Software)\s*:?\s*(.*)', comment))
                name.extend(re.findall('^(.*?)<br>', comment))
                name.extend(re.findall('Script\.+:?(.*?)#', comment))
                name.extend(re.findall('#\s*(\[.*?\])', comment))
                if '##' not in comment:
                    name.extend(re.findall('\|\s+\|\s+(.*?)\s+\|\s+\|', comment))
                else:
                    values = re.findall('###+\s+(.*?)\s+###+', comment, flags=re.S|re.M)
                    if values:
                        values = values[0]
                        anothers = re.findall('\s+(.*)', comment)
                        if anothers and len(anothers) > 2 and '###' not in anothers[2]:
                            name.extend([anothers[1]])
                            targets.extend([anothers[2]])
                name.extend(re.findall('Vendor:\s*(.*)', comment))
                targets.extend(re.findall('(?:Tested|TESTED)\s*(?:on|ON)\s*:\s*(.*)', comment))
        
            # Transform arrays to strings by joining all the founded variants
            description = ' -- '.join(description)
            component = ' -- '.join(component)
            vversion = ' -- '.join(vversion)
            targets = ' -- '.join(targets)
            name = ' -- '.join(name)
            
            references = []
            for ref in list(set(refs)):
                if isinstance(ref,tuple):
                    references.append([ref[0], ref[1]])
                else:
                    references.append(['URL', ref])

            URI = self.parse_url()

            file.write(self.filename)
            file.write('Refs:   ' + str(references) + '\n')
            file.write('Desc:   ' + description + '\n')
            file.write('Comp:   ' + component + '\n')
            file.write('Vers:   ' + vversion + '\n')
            file.write('Name:   ' + self.title + '\n')
            file.write('Targ:   ' + targets + '\n')
            file.write('URIS:   ' + str(list(set(URI))) + '\n')
            file.write('Titl:   ' + title + '\n')
            file.write('\n')

            myDict = {
                "EDB-ID": self.name,
                "Vulnerability": title,
                "Name": self.title,
                "Description": name + ' -- ' + description + ' -- ' + vversion + ' -- ' + targets,
                "Platform": self.platform,
                "References": references,
                "Type": self.exploit_type,
                "URI": list(set(URI))   
            }

            cves.update({"EDB-ID":self.name}, myDict, upsert=True)
            print(myDict)
        except Exception as e:
            error = True
            parsed_file = False
        finally:
            parsed_obj = {
                "filename": self.filename,
                "parsed": parsed_file,
                "error": error,
                "date": datetime.datetime.now().isoformat()
            }

            self.parsed_col.update({"filename": self.filename}, parsed_obj, upsert=True)
    
    def parse_url(self):
        URIs = []
        URI = []
        try:
            URIs.extend(regex.findall('value=[\"\']?(?:https?://)?([^<>]+?)[\"\'\s]', self.exploit, timeout=5))
        except TimeoutError as e:
            print (e)
        try:    
            URIs.extend(regex.findall('[\"\']((?:https?:\/\/.*?)*?\.*?\/?\w*?\/[\S]*?)[\"\'](?:.*\+.*[\"\'](.*?)[\"])?', self.exploit, timeout=5))
        except TimeoutError as e:
            print (e)
        try:    
            URIs.extend(regex.findall('action=[\"\'](?:https?://)?([^>]*?)[\"\']', self.exploit, timeout=5, flags=re.M|re.S))
        except TimeoutError as e:
            print (e)
        try:    
            URIs.extend(regex.findall('^(?:GET|POST|PUT|PATCH)\s*(.*?)\s*H', self.exploit, timeout=5, flags=re.M))
        except TimeoutError as e:
            print (e)
        try:
            construct_uri = regex.findall('action=\s*.*?document.*?\+(.*?)\+(.*?)\+(.*?);', self.exploit, timeout=5 )
            for uri_to_construct in construct_uri:
                value1 = re.findall(re.escape(uri_to_construct[0]), self.exploit)[0]
                value2 = re.findall(re.escape(uri_to_construct[1]), self.exploit)[0]
                value3 = re.findall(re.escape(uri_to_construct[2]), self.exploit)[0]

                URIs.extend([value1+value2+value3])        
        except TimeoutError as e:
            print(e)
        
        header_values = ['application', 'image', 'audio', 'messages', 'video', 'text', 'multipart', 'firefox', 'chrome', 'chromium']

        for uri in URIs:
            if isinstance(uri, tuple):
                uri = uri[0] + uri[1]

            try:
                uri = regex.sub('[\"\']\s*\+.*[\"\']', 'www.example.com/', uri, timeout=5)
            except TimeoutError as e:
                print(e)

            if ',' in uri or '/bin/' in uri or '/' == uri or '==' in uri or 'cmd' in uri or '/div>' in uri:
                continue
            new_uris = uri.strip('/').split('/')
            if len(list(set(uri.strip('/').split('/')))) == 1 and len(new_uris) > 1:
                continue
            if len(new_uris) == 2:
                if new_uris[0].lower() not in header_values:
                    URI.append(uri)
            elif len(new_uris) == 1 and not uri.startswith('/') and '.' not in uri:
                continue
            else: 
                try:
                    if regex.findall('\w*@\w*(?:\.\w*)*', uri, timeout=5):
                        continue
                    else:
                        URI.append(uri)
                except TimeoutError as e:
                    print(e)

        return URI


