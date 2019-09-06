import datetime
import re
import time
import regex

from .scraper import Scraper


class PythonScraper(Scraper):
    def __init__(self, filename=None, name=None, exploit_type=None, title=None, platform=None, exploit=None):
        ext = ['.py']
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
            vversion = []
            name = []
            targets = []

            if self.collection.find_one({"filename": self.name}) is not None:
                title = self.collection.find_one({"filename": self.name})['cve']

            comments = re.findall('^#(.*?)import', self.exploit, flags=re.M | re.S)
            comments.extend(re.findall("['\"]{3}(.*?)['\"]{3}", self.exploit, flags=re.M | re.S))

            source_comment = re.findall('^\s*[Ss]ource\s*:\s*(.*)\s+(.*)\s+(.*)\s+([^#]+?)\n', self.exploit)
            if source_comment:
                refs.extend([source_comment[0][0]])
                name.extend([source_comment[0][1]])
                description.extend([source_comment[0][2]])
                targets.extend([source_comment[0][3]])

            for comment in comments:
                refs.extend(re.findall('Software\s*[lL]ink\s*:\s*(.*)', comment))
                refs.extend(re.findall('(C[VW]E)(?:\s*[-:]\s*)?((?:\d+)?-\d+)', comment))
                refs.extend(re.findall('[Rr]ef(?:erences?)?\s*:\s*(.*)', comment))
                refs.extend(re.findall('[dD]etails\s*:\s*(.*)', comment))

                list_sources = re.findall('References:?\n(.*)\s*', comment, flags=re.S)
                if list_sources:
                    refs.extend(re.findall('(https?:\/\/.*)', list_sources[0]))
                else:
                    list_sources = re.findall('REFERENCES:?\n(.*?)\s*(?:[IXV]\.)', comment, flags=re.S)
                    if list_sources:
                        refs.extend(re.findall('(https?:\/\/.*)', list_sources[0]))

                cvess = re.findall('(C[VW]Es)\s*:\s*(.*?)\n', comment)
                if cvess:
                    refs.extend([(cvess[0][0], value) for value in cvess[0][1].split(',')])

                name.extend(re.findall('(?:Exploit\s*)?[Tt]itle\s*:\s(.*)', comment))
                vversion.extend(re.findall('Versions?\s*:\s*(.*)', comment))
                targets.extend(re.findall('Product\s*:\s*(.*)', comment))
                targets.extend(re.findall('Installed On\s*:\s*(.*)', comment))
                vversion.extend(re.findall('Software\.+(.*)', comment))
                targets.extend(re.findall('Tested [Oo]n(?:\.+|\s+:?)?(.*)', comment))
                description.extend(re.findall('Vulnerability\s*:\s*([\s\S]*?)#\n', comment))
                description.extend(re.findall('[Dd]escription\s*:\s*(.*)', comment))
                dash_split = re.findall('(?:-{8})+(.*?)(?:-{8})', comment, flags=re.S)
                for item in dash_split:
                    description.extend(re.findall('(?:Description|Explanation)\s*:?\s*(.*)', item, flags=re.S))

                description.extend(re.findall('Known Issues:?\n(.*?)\n\n', comment, flags=re.S))
                description.extend(re.findall('(?:VULNERABILITY|INTRODUCTION)\n(.*?)\s*[IVX]\.', comment, flags=re.S))

            if not description:
                description.extend(re.findall('description=[\'\"](.*)[\'\"]', self.exploit))
            if not refs:
                refs.extend(re.findall('(C[VW]E)(?:\s*[-:]\s*)?((?:\d+)?-\d+)', self.exploit))

            description = ' -- '.join(description)
            vversion = ' -- '.join(vversion)
            targets = ' -- '.join(targets)
            name = ' -- '.join(name)

            references = []
            for ref in list(set(refs)):
                if isinstance(ref, tuple):
                    references.append([ref[0], ref[1]])
                else:
                    references.append(['URL', ref])

            URI = self.parse_url()

            f = open('/home/john/Desktop/pythontxt', 'a+')
            f.write(self.filename + '\n')
            f.write("Name: " + name + '\n')
            f.write("vers: " + vversion + '\n')
            f.write("Targ: " + targets + '\n')
            f.write("Refs: " + str(references) + '\n')
            f.write("Desc: " + description + '\n')
            f.write("URIs: " + str(URI) + '\n')

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

            cves.update({"EDB-ID": self.name}, myDict, upsert=True)

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
            URIs.extend(regex.findall('(https?://.*\/.*?)[\)\"]', self.exploit, timeout=5))
        except TimeoutError as e:
            print(e)
        try:
            URIs.extend(regex.findall('[\"\']((?:https?:\/\/.*?)*?\.*?\/?\w*?\/[\S]*?)[\"\'](?:.*\+.*[\"\'](.*?)[\"])?',
                                      self.exploit, timeout=5))
        except TimeoutError as e:
            print(e)
        try:
            URIs.extend(regex.findall('(?:url|path)\s*[=:]\s*[\'\"](.*?)[\'\"]', self.exploit, timeout=5))
        except TimeoutError as e:
            print(e)
        try:
            URIs.extend(regex.findall('^(?:GET|POST|PUT|PATCH)\s*(.*?)\s*H', self.exploit, timeout=5, flags=re.M))
        except TimeoutError as e:
            print(e)
        try:
            construct_uri = regex.findall('action=\s*.*?document.*?\+(.*?)\+(.*?)\+(.*?);', self.exploit, timeout=5)
            for uri_to_construct in construct_uri:
                value1 = re.findall(re.escape(uri_to_construct[0]), self.exploit)[0]
                value2 = re.findall(re.escape(uri_to_construct[1]), self.exploit)[0]
                value3 = re.findall(re.escape(uri_to_construct[2]), self.exploit)[0]

                URIs.extend([value1 + value2 + value3])
        except TimeoutError as e:
            print(e)

        header_values = ['application', 'image', 'audio', 'messages', 'video', 'text', 'multipart', 'firefox', 'chrome',
                         'chromium']

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
