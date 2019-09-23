import datetime
import re
import time

import regex
from .scraper import Scraper


class MidiScraper(Scraper):
    def __init__(self, filename=None, name=None, exploit_type=None, title=None, platform=None, exploit=None, mongoclient=None):
        ext = ['.mid']
        super().__init__(filename, name, exploit_type, title, platform, exploit, mongoclient, ext)

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
            name =[]
            vversion = []

            name.extend(re.findall('Exploit Title:\s*(.*)', self.exploit))
            refs.extend(re.findall('(C[VW]E)(?:\s*[-:]?\s*)?((?:\d+)?-?\d+)', self.exploit))
            refs.extend(re.findall('Software Link:?\s*(.*)', self.exploit))
            targets.extend(re.findall('Tested on:\s*(.*)', self.exploit))
            vversion.extend(re.findall('Version:\s*(.*)', self.exploit))

            description = ' -- '.join(description)
            targets = ' -- '.join(targets)
            name = ' -- '.join(name)
            vversion = ' -- '.join(vversion)

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
                "Description": name + ' ' + description + ' Version: ' + vversion + ' Tested on: ' + targets,
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
        return self.extract_url(URIs)
