import datetime
import re
import time

import regex

from .scraper import Scraper


class AspScraper(Scraper):
    def __init__(self, filename=None, name=None, exploit_type=None, title=None, platform=None, exploit=None):
        ext = ['.asp']
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

            source_at_begin = re.findall('^(?:\/\/\s+)?[Ss]ource\s*:\s*(.*)\s+(.*)\s+(.*)\s+([^#]+?)\n', self.exploit,
                                         flags=re.M)  # For comments like source .. \n text \n text
            if source_at_begin:
                source_at_begin = source_at_begin[0]
                refs.extend([source_at_begin[0]])
                name.extend([source_at_begin[1]])
                if ('#' not in source_at_begin[2] or '#' not in source_at_begin[2]) or '<%' not in source_at_begin[2] \
                        or '/' not in source_at_begin[2]:
                    description.extend([source_at_begin[2]])
                if len(source_at_begin[1]) > 2 and '#' not in source_at_begin[3] or '<%' not in source_at_begin[3] \
                        or '/' not in source_at_begin[3]:
                    targets.extend([source_at_begin[3]])

            refs.extend(re.findall('(?:based on|[sS]ee|[vV]isit|[pP]ublished at|[Mm]ore|site)\s*:?\s*(.*?)\s', self.exploit))
            refs.extend(re.findall('(C[VW]E)(?:\s*[-:]\s*)?((?:\d+)?-\d+)', self.exploit))

            name.extend(re.findall('Name\s*:\s*(.*)', self.exploit))
            name.extend(re.findall('<[tT][iI][tT][lL][eE]>(.*?)</', self.exploit))
            name.extend(re.findall('title=(.*)', self.exploit))

            name.extend(re.findall('(?:Title|Name)\s*:?\s*(.*)', self.exploit))
            vversion.extend(re.findall('Versions?\s*:?\s*(.*)', self.exploit))
            description.extend(
                re.findall('(?:[Dd]esc(?:ription)?|Summary)\s*:?\s*(.*?)\n\n', self.exploit, flags=re.S | re.M))
            refs.extend(re.findall('References?:?\s*(.*?)\s', self.exploit))
            refs.extend(re.findall('(?:Software [lL]ink\s*|advisor(?:y|ies)):\s*(.*)', self.exploit))
            targets.extend(re.findall('[Tt]ested\s*(?:on|with)\s*:?\s*(.*)', self.exploit))

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
            error = str(e)
            parsed_file = False
            self.logger.error(self.filename + f'\t{error}')
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
            URIs.extend(regex.findall('[\"\']((?:https?:\/\/.*?)*?\.*?\/?\w*?\/[\S]*?)[\"\'](?:.*\+.*[\"\'](.*?)[\"])?',
                                      self.exploit, timeout=5))
        except TimeoutError as e:
            print(e)
        try:
            URIs.extend(regex.findall(r'(?:GET|POST|PUT|PATCH|HEAD)\s*(.*?)\s*[H\"\\]', self.exploit, timeout=5))
        except TimeoutError as e:
            print(e)
        try:
            URIs.extend(regex.findall('(\/[\/.a-zA-Z0-9-_]+)', self.exploit, timeout=5))
        except TimeoutError as e:
            print(e)
        try:
            URIs.extend(regex.findall(r'action=\"(.*?)\"', self.exploit, timeout=5))
        except TimeoutError as e:
            print(e)
        try:
            URIs.extend(regex.findall('Response\.Redirect\(\"(.*)\"\)', self.exploit, timeout=5))
        except TimeoutError as e:
            print(e)
        try:
            URIs.extend(regex.findall('file\=\"(.*)\"', self.exploit, timeout=5))
        except TimeoutError as e:
            print(e)

        return self.extract_url(URIs)

