import datetime
import re
import regex

from .scraper import Scraper


class TTScraper(Scraper):
    def __init__(self, filename=None, name=None, exploit_type=None, title=None, platform=None, exploit=None, mongoclient=None, date=None):
        ext = ['.tt']
        super().__init__(filename, name, exploit_type, title, platform, exploit, mongoclient, date, ext)
        self.refs = None

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

            self.exploit = re.sub('#', '', self.exploit)

            values = re.findall('(?:\=\=)+\s+([\s\S]*?)\s+(?:\=\=)+', self.exploit)

            if values:
                name.extend([values[0]])

            refs.extend(re.findall('(https?:.*?)\s+', self.exploit))

            description = ' -- '.join(description)
            vversion = ' -- '.join(vversion)
            targets = ' -- '.join(targets)
            name = ' -- '.join(name)

            self.refs = list(set(refs))

            references = []
            for ref in list(set(refs)):
                if isinstance(ref, tuple):
                    references.append([ref[0], ref[1]])
                else:
                    if 'example' in ref or 'sitename' in ref:
                        continue
                    references.append(['URL', ref])

            URI = self.parse_url()

            myDict = {
                "EDB-ID": self.name,
                "Vulnerability": title,
                "Name": self.title,
                "Description": name + ' ' + description + ' Version: ' + vversion + ' Tested on: ' + targets,
                "Platform": self.platform,
                "References": references,
                "Type": self.exploit_type,
                "Date": self.date,
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
            URIs.extend(regex.findall('(https?:\/\/.*\/.*?)\s+', self.exploit, timeout=5))
        except TimeoutError as e:
            print(e)
        try:
            URIs.extend(regex.findall('[\"\']((?:https?:\/\/.*?)*?\.*?\/?\w*?\/[\S]*?)[\"\'](?:.*\+.*[\"\'](.*?)[\"])?',
                                      self.exploit, timeout=5))
        except TimeoutError as e:
            print(e)
        try:
            urls = regex.findall('(?:GET|POST|PUT|PATCH|HEAD)\s*(.*?)\s*H', self.exploit, timeout=5)
            for uri in urls:
                if not uri.startswith('/'):
                    URIs.append('/' + uri)
        except TimeoutError as e:
            print(e)

        return self.extract_url(URIs)
