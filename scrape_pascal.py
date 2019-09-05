import datetime
import re
import regex

from scraper import Scraper


class PascalScraper(Scraper):
    def __init__(self, filename, name, exploit_type, title, platform, exploit):
        super().__init__(filename, name, exploit_type, title, platform, exploit)

    def parse_infos(self):
        cves = self.db['cves']  # The main mongo collection

        print(self.filename)

        query = self.parsed_col.find_one({"filename": self.filename})   # Check if it is parsed
        if query is not None:
            parsed = query['parsed']
            if parsed:
                return  # If yes, skip

        error = False
        parsed_file = True

        try:
            # Create the title
            title = re.sub('\s', '_', self.title)
            title = re.sub('\.', '@', title)
            title = self.name + '_' + title

            refs = []
            description = []
            vversion = []
            name = []
            targets = []

            # Get the CVEs from mongo refs
            if self.collection.find_one({"filename": self.name}) is not None:
                title = self.collection.find_one({"filename": self.name})['cve']

            # The comments
            source_at_begin = re.findall('^[Ss]ource\s*:\s*(.*)\s+(.*)\s+(.*)\s+([^#]+?)\n', self.exploit,
                                         flags=re.M)  # For comments like source .. \n text \n text
            if source_at_begin:
                source_at_begin = source_at_begin[0]
                refs.extend([source_at_begin[0]])
                name.extend([source_at_begin[1]])
                if ('###' not in source_at_begin[2] or '===' not in source_at_begin[2]):
                    description.extend([source_at_begin[2]])
                if len(source_at_begin[1]) > 2 and 'program' not in source_at_begin[3]:
                    targets.extend([source_at_begin[3]])

            # Transform arrays to strings by joining all the founded possibilities
            description = ' -- '.join(description)
            vversion = ' -- '.join(vversion)
            targets = ' -- '.join(targets)
            name = ' -- '.join(name)

            # Edit the references to look like the metasploit ones
            references = []
            for ref in list(set(refs)):
                if isinstance(ref, tuple):
                    references.append([ref[0], ref[1]])
                else:
                    references.append(['URL', ref])

            URI = self.parse_url()

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
            # Add the details to mongodb
            cves.update({"EDB-ID": self.name}, myDict, upsert=True)

        except Exception as e:
            error = True
            parsed_file = False

        finally:
            # Update the parse collection
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

        header_values = ['application', 'image', 'audio', 'messages', 'video', 'text', 'multipart', 'firefox', 'chrome',
                         'chromium']

        # Edit the founded uri and filter them
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