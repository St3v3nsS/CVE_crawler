import datetime
import re
import time

import regex
from .scraper import Scraper


class SysScraper(Scraper):
    def __init__(self, filename=None, name=None, exploit_type=None, title=None, platform=None, exploit=None, mongoclient=None, date=None):
        ext = ['.sys']
        super().__init__(filename, name, exploit_type, title, platform, exploit, mongoclient, date, ext)

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
            targets = []

            refs.extend(re.findall('(C[VW]E)(?:\s*[-:]?\s*)?((?:\d+)?-?\d+)', self.exploit))
            refs.extend(re.findall('here:?\s*(.*?)\s', self.exploit))
            targets.extend(re.findall('Tested on:\n(.*)\n', self.exploit))

            description = ' -- '.join(description)
            targets = ' -- '.join(targets)

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
                "Description": description + ' ' + ' Tested on: ' + targets,
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
        URIs = ['/']

        try:
            URIs.extend(regex.findall('[\"\']((?:https?:\/\/.*?)*?\.*?\/?\w*?\/[\S]*?)[\"\'](?:.*\+.*[\"\'](.*?)[\"])?',
                                      self.exploit, timeout=5))
        except TimeoutError as e:
            print(e)
        try:
            URIs.extend(regex.findall('(?:GET|POST|PUT|PATCH|HEAD)\s*(.*?)\s*[H"]', self.exploit, timeout=5))
        except TimeoutError as e:
            print(e)
        try:
            URIs.extend(regex.findall('http:\/\/.*?(\/.*?)[\s\\)\]"\'<]', self.exploit, timeout=5))
        except TimeoutError as e:
            print(e)
        blacklist = regex.findall(r'(Exploit\s*[aA].*|Vendor.*|Software.*|Ref.*)', self.exploit)
        if blacklist:
            URIs = [item for item in URIs if item not in blacklist]
        return self.extract_url(URIs)
