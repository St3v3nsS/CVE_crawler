import datetime
import re
import time
import regex
from .scraper import Scraper


class SJSScraper(Scraper):
    def __init__(self, filename=None, name=None, exploit_type=None, title=None, platform=None, exploit=None):
        ext = ['.sjs']
        super().__init__(filename, name, exploit_type, title, platform, exploit, ext)

    def parse_infos(self):
        cves = self.db['cves']

        print(self.filename)

        if self.is_parsed():
            return

        error = False
        parsed_file = True
        try:
            title = self.construct_title()

            refs = []
            description = []
            vversion = []
            name = []
            targets = []

            comments = re.findall('#(.*)import', self.exploit, flags=re.S)
            if comments:
                comments = re.sub('^#\s*', '', comments[0], flags=re.M)
                comments = re.sub('\s+#', '', comments, flags=re.M)
                source_comment = re.findall('^\s*[Ss]ource\s*:\s*(.*)\s+(.*)\s+(.*)\s+([^#]+?)\n', comments)
                if source_comment:
                    refs.extend([source_comment[0][0]])
                    name.extend([source_comment[0][1]])
                    description.extend([source_comment[0][2]])
                    targets.extend([source_comment[0][3]])

                description.extend(re.findall('Description##\s+([\S\s]*?)#', comments, flags=re.M))

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

            myDict = {
                "EDB-ID": self.name,
                "Vulnerability": title,
                "Name": self.title,
                "Description": name + ' ' + description + ' ' + vversion + ' ' + targets,
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
            urls = regex.findall('(?:POST|GET|PUT|PATCH)\s*(.*?)\s*H', self.exploit, timeout=5)
            for uri in urls:
                if not uri.startswith('/'):
                    URIs.append('/' + uri)
        except TimeoutError as e:
            print(e)

        return self.extract_url(URIs)
