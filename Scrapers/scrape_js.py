import re
import regex
import datetime

from .scraper import Scraper
from six import string_types


class JSParser(Scraper):
    def __init__(self, filename=None, name=None, exploit_type=None, title=None, platform=None, exploit=None, mongoclient=None, date=None):
        ext = ['.js', '.svg']
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
            new_comments = []
            targets = []

            # Even if the name of exploit exists, I need it for finding other stuffs, but it will not be included in the json

            comments = re.findall('\/\*(.*?)\*\/', self.exploit, flags=re.S | re.M)  # Multiline comments
            comments.extend(re.findall('^//(.*)', self.exploit))  # Single-line comments

            source_at_begin = re.findall('^[Ss]ource\s*:\s*(.*)\s+(.*)\s+(.*)\s+([^#]+?)\n', self.exploit,
                                         flags=re.M)  # For comments like source .. \n text \n text
            if source_at_begin:
                source_at_begin = source_at_begin[0]
                refs.extend([source_at_begin[0]])
                name.extend([source_at_begin[1]])
                if ('###' not in source_at_begin[2] or '===' not in source_at_begin[2]):
                    description.extend([source_at_begin[2]])
                if len(source_at_begin[1]) > 2 and '####' not in source_at_begin[3]:
                    targets.extend([source_at_begin[3]])

            for array in comments:  # Make array from array of arrays
                if isinstance(array, string_types):
                    new_comments.append(array)
                else:
                    for comment in array:
                        new_comments.append(comment)

            for comment in new_comments:

                source_at_begin = re.findall('^[Ss]ource\s*:\s*(.*)\s+(.*)\s+(.*)\s+([^#]+?)\n', comment,
                                             flags=re.M)  # For comments like source .. \n text \n text
                if source_at_begin:
                    source_at_begin = source_at_begin[0]
                    refs.extend([source_at_begin[0]])
                    name.extend([source_at_begin[1]])
                    if ('###' not in source_at_begin[2] or '===' not in source_at_begin[2]):
                        description.extend([source_at_begin[2]])
                    if len(source_at_begin[1]) > 2 and '####' not in source_at_begin[3]:
                        targets.extend([source_at_begin[3]])

                # All posibilities depending on how they write their code
                refs.extend(re.findall('(https?://[^,\'\s\"\]\)]+)', comment))
                refs.extend(re.findall('(C[VW]E)-(\d+(-\d+)?)', comment))
                description.extend(
                    re.findall('(?:Description|Summary|Product|DESCRIPTION)\s*:?\s*(.*)\w', comment, flags=re.M))
                if '* ' in comment and not description:
                    value = re.findall('\*\s*(.*)', comment)
                    if value and '***' not in value[0]:
                        name.extend([value[0]])
                        if len(value) > 1:
                            description.extend([value[1]])

                if not description and '***' in comment:
                    value = re.findall('\n(.*)', comment)
                    if value and len(value) > 1:
                        description.extend([value[1]])

                vversion.extend(re.findall('Vulnerable version\s*:\s*(.*)', comment))
                vversion.extend(
                    re.findall('[^\w/](?:VERSIONS?|Versions?(?:\s*numbers:?\s*-+\n)?)\s*:?\s*(.*\s+.*)', comment))
                vversion.extend(re.findall('Affected\s*version\s*:\s*(.*\s*.*)?\s*\w+:', comment))
                name.extend(re.findall('[^\w/](?:Title|Name|Topic|Software)\s*:?\s*(.*)', comment))
                targets.extend(re.findall('(?:Tested|TESTED)\s*(?:on|ON)\s*:\s*(.*)', comment))

            # Transform arrays to strings by joining all the founded possibilities
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
            description = name + ' ' + description + ' Version: ' + vversion + ' Tested on: ' + targets,
            myDict = self.create_object_for_mongo(title, description, references, URI)

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
            URIs.extend(regex.findall('(?:url|path)\s*[=:]\s*[\'\"](.*?)[\'\"]', self.exploit, timeout=5))
        except TimeoutError as e:
            print(e)
        try:
            URIs.extend(regex.findall('^(?:GET|POST|PUT|PATCH|HEAD)\s*(.*?)\s*H', self.exploit, timeout=5, flags=re.M))
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
        blacklist = regex.findall(r'(Exploit\s*[aA].*|Vendor.*|Software.*|Ref.*)', self.exploit)
        if blacklist:
            URIs = [item for item in URIs if item not in blacklist]
        return self.extract_url(URIs)
