import datetime
import re
import time

import regex

from .scraper import Scraper


class TxtScraper(Scraper):
    def __init__(self, filename=None, name=None, exploit_type=None, title=None, platform=None, exploit=None, mongoclient=None, date=None):
        ext = ['.txt']
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
            vversion = []
            name = []
            targets = []

            source_at_begin = re.findall(r'^(?:\/\/\s+)?[Ss]ource\s*:\s*(.*)\s+(.*)\s+(.*)\s+([^#]+?)\n', self.exploit,
                                         flags=re.M)  # For comments like source .. \n text \n text
            if source_at_begin:
                source_at_begin = source_at_begin[0]
                refs.extend([source_at_begin[0]])
                name.extend([source_at_begin[1]])
                if '#' not in source_at_begin[2] or '===' not in source_at_begin[2]:
                    description.extend([source_at_begin[2]])
                if len(source_at_begin[1]) > 2 and '#' not in source_at_begin[3]:
                    targets.extend([source_at_begin[3]])

            refs.extend(
                re.findall(r'(?:based on|[sS]ee|[vV]isit|[pP]ublished at|[Mm]ore|[sS]ite)\s*:?\s*(.*?)\s', self.exploit))
            refs.extend(re.findall(r'(C[VW]E)(?:\s*[-:]\s*)?((?:\d+)?-\d+)', self.exploit))

            name.extend(re.findall(r'<[tT][iI][tT][lL][eE]>(.*?)</', self.exploit))
            name.extend(re.findall(r'title=(.*)', self.exploit))
            name.extend(re.findall(r'(?<!\")\s(?<!\w)(?:Title|[Nn]ame|Exploit)\s*:?\s*(.*)', self.exploit))
            if not name:
                name.extend(re.findall(r'<h1>(.*?)</h1', self.exploit))
            vversion.extend(re.findall(r'Vulnerable\s(?:products|Systems)\s*:\s*\n(.*?)\n\n', self.exploit, flags=re.S))
            if not vversion:
                vversion.extend(re.findall(r'[Vv]ersions?\s*:?\s*(.*)', self.exploit))
            description.extend(
                re.findall(r'(?:[Dd]esc(?:ription)?|Summary|About)(?!\w)\s*:?\s*(.*?)\n\s+', self.exploit, flags=re.S | re.M))
            description.extend(re.findall(r'(?:Product|Vendor)\s*:\s*(.*)', self.exploit))
            description.extend(re.findall(r'(?:[iI]nformation|[iI]ntroduction|DESCRIPTION)\s*:?\n=+\n\s?(.*)\s*', self.exploit))
            refs.extend(re.findall('References?:?\s*(.*?)\s', self.exploit))
            refs.extend(re.findall(r'(?:[Aa]dvisory|can be found at|Thanks to.*?|Related URLs|Source|Download|Page|URL|available here)\s*:\s*(.*?)\s', self.exploit))
            refs.extend(re.findall(r'(?:(?:Software|Download)? ?[lL]ink\s*.*?|advisor(?:y|ies))\s*:\s*(.*)', self.exploit))
            targets.extend(re.findall(r'(?:[Tt]ested\s*(?:on|with)|Target)\s*:?\s*(.*)', self.exploit))

            description = ' -- '.join(description)
            vversion = ' -- '.join(vversion)
            targets = ' -- '.join(targets)
            name = ' -- '.join(name)

            references = []
            for ref in list(set(refs)):
                if isinstance(ref, tuple):
                    references.append([ref[0], ref[1]])
                else:
                    if not re.findall('(.*?)\.(.*?)\.', ref):
                        continue
                    references.append(['URL', ref])

            URI = self.parse_url()
            description = name + ' ' + description + ' Version: ' + vversion + ' Tested on: ' + targets
            myDict = self.create_object_for_mongo(title, description, references, URI)

            cves.update({"EDB-ID": self.name}, myDict, upsert=True)

        except Exception as e:
            error = str(e)
            parsed_file = False
            self.logger.error(self.filename + f'\t{error}'+'\t' + self.get_version_from_name())
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

        self.exploit = re.sub('\$argv\[\d\]', '/', self.exploit)
        try:
            try:
                URIs.extend(regex.findall(r'[\"\']((?:https?:\/\/.*?)*?\.*?\/?\w*?\/[\S]*?)[\"\'](?:.*\+.*[\"\'](.*?)[\"])?',
                                          self.exploit, timeout=5))
            except TimeoutError as e:
                pass
            try:
                URIs.extend(regex.findall(r'(?:GET|POST|PUT|PATCH|HEAD)\s*(.*?)\s*[H\"\']', self.exploit, timeout=5))
            except TimeoutError as e:
                pass
            try:
                URIs.extend(regex.findall(r'(\/[\/.a-zA-Z0-9-_\[\]]+)', self.exploit, timeout=5))
            except TimeoutError as e:
                pass
            try:
                URIs.extend(regex.findall(r'(?:GET|POST|PUT|PATCH|HEAD|EXAMPLE\s*\d+)\s*->\s*(.*)', self.exploit, timeout=5))
            except TimeoutError as e:
                pass
            try:
                URIs.extend(regex.findall(r'action=\"(.*?)\"', self.exploit, timeout=5))
            except TimeoutError as e:
                pass

            try:
                URIs.extend(regex.findall('([^\d]+\.\w+\?)', self.exploit, timeout=5))
            except TimeoutError as e:
                print(e)
                pass
        finally:
            blacklist = regex.findall(r'(Exploit\s*[aA].*|Vendor.*|Software*.*)', self.exploit)
            if blacklist:
                URIs = [item for item in URIs if item not in blacklist]
            return self.extract_url(URIs)
