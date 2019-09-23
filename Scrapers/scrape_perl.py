from .scraper import Scraper
import datetime
import re
import time
import json
import regex
from .scraper import Scraper


class PerlScraper(Scraper):
    def __init__(self, filename=None, name=None, exploit_type=None, title=None, platform=None, exploit=None, mongoclient=None):
        ext = ['.pl', '.pm']
        super().__init__(filename, name, exploit_type, title, platform, exploit, mongoclient, ext)

    def parse_infos(self):

        cves = self.db['cves']

        print(self.filename)

        if self.filename.endswith('.pm'):
            with open('/home/john/Desktop/pm', 'a+') as f:
                f.write(self.filename + '\n')

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

            dictionary = None
            if re.findall('Msf', self.exploit):
                dictionary = self.parse_metasploit()

            source_at_begin = re.findall('^(?:\/\/\s+)?[Ss]ource\s*:\s*(.*)\s+(.*)\s+(.*)\s+([^#]+?)\n', self.exploit,
                                         flags=re.M)  # For comments like source .. \n text \n text
            if source_at_begin:
                source_at_begin = source_at_begin[0]
                refs.extend([source_at_begin[0]])
                name.extend([source_at_begin[1]])
                if ('#' not in source_at_begin[2] or '#' not in source_at_begin[2])or 'use' not in source_at_begin[2]\
                        or 'my' not in source_at_begin[2]:
                    description.extend([source_at_begin[2]])
                if len(source_at_begin[1]) > 2 and '#' not in source_at_begin[3] or 'use' not in source_at_begin[3]\
                        or 'my' not in source_at_begin[3]:
                    targets.extend([source_at_begin[3]])

            refs.extend(re.findall('(?:based on|[sS]ee|[vV]isit|[pP]ublished at|[Mm]ore)\s+:?\s*(.*?)\s', self.exploit))
            refs.extend(re.findall('(C[VW]E)(?:\s*[-:]\s*)?((?:\d+)?-\d+)', self.exploit))

            comments = re.findall('^(#.*?)(?:package|use|\$|my)', self.exploit, flags=re.S | re.M)
            comments.extend(re.findall('\s\/\/(.*)', self.exploit))

            for comment in comments:
                name.extend(re.findall('(?:Title|Name)\s*:?\s*(.*)', comment))
                vversion.extend(re.findall('Versions?\s*:?\s*(.*)', comment))
                description.extend(re.findall('(?:Desc(?:ription)?|Summary)\s*:?\s*(.*?)\n\n', comment, flags=re.S | re.M))
                refs.extend(re.findall('References?:?\s*(.*?)\s', comment))
                refs.extend(re.findall('(?:Software [lL]ink\s*|advisor(?:y|ies)):\s*(.*)', comment))
                targets.extend(re.findall('[Tt]ested\s*(?:on|with)\s*:?\s*(.*)', comment))

            references = []

            URI = self.parse_url()

            if dictionary is not None:
                name.extend([dictionary.get('Name')])
                description.extend([dictionary.get('Description')])
                if dictionary.get('Version') is not None:
                    vversion.extend([dictionary.get('Version')])
                if dictionary.get('Refs') is not None:
                    references.extend(dictionary.get('Refs'))
                if dictionary.get('Opts').get('RPATH') is not None and len(dictionary.get('Opts').get('RPATH')) > 3:
                    URI.append(dictionary.get('Opts').get('RPATH')[3])

            for ref in list(set(refs)):
                if isinstance(ref, tuple):
                    references.append([ref[0], ref[1]])
                else:
                    references.append(['URL', ref])

            description = ' -- '.join(description)
            vversion = ' -- '.join(vversion)
            targets = ' -- '.join(targets)
            name = ' -- '.join(name)

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

        self.exploit = re.sub('\$ARGV\[\d\]', '/', self.exploit)

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
            URIs.extend([''.join(re.findall('(?:path|url)\s*\.?=\s*\"?(.*)\"?;\s+', self.exploit))])
        except TimeoutError as e:
            print(e)

        return self.extract_url(URIs)

    def parse_metasploit(self):
        info = re.findall('my \$info\s*=\s*({.*?});\s+sub', self.exploit, flags=re.S)

        if not info:
            return None
        info = info[0]
        info = re.sub('=>', ':', info)
        info = re.sub('(\s#.*)', '', info)
        description = re.findall("[\"\']Description[\"\']\s*:\s*(.*?),\s*[\"\']", info, flags=re.S)[0]
        description = re.sub('"', "'", description)
        description = re.sub('\s+', ' ', description)
        description = re.sub(r'\\', '\\\\', description)
        info = re.sub("'", '"', info)
        info = re.sub('\s+', ' ', info)
        info = re.sub(',\s*([}\)\]])', '\g<1>', info)
        info = re.sub(r'\\\$', '', info)
        info = re.sub('((?:BadChars|Space)\"\s*:)\s*.*?([,}\]]\s*[,\"\[{}\]])', '\g<1> ""\g<2>', info)
        info = re.sub('(Prepend(?:Encoder)?\"\s*:)\s*.*?([,}\]]\s*[,\"\[{}\]])', '\g<1> ""\g<2>', info)
        info = re.sub('0x[a-fA-F0-9]+', '""', info)

        info = re.sub('\((\d+\+\d+)+\)', '""', info)
        info = re.sub('\"\"\s*\+\s*\d+', '""', info)
        info = re.sub(r'\\&.*?\s', '""', info)
        info = re.sub('([\"\']Description\"\s*:\s*).*?(,\s*[\"\'])', '\g<1>{}\g<2>'.format(description.replace('\\', '\\\\')), info, flags=re.S)

        info = re.sub('(?:Pex::Text::Freeform\s*\(\s*)?qq?\s*{(.*?)}\s*\)?,', '"\g<1>", ', info, flags=re.S)
        try:
            info = json.loads(info.replace('\\', '\\\\'))
            mydict = {
                'Name': info.get('Name'),
                'Description': info.get('Description'),
                'Version': info.get('Version'),
                'Refs': info.get('Refs'),
                'Targets': info.get('Targets'),
                'Opts': info.get('UserOpts')
            }
            return mydict
        except Exception as e:
            self.logger.error(self.filename + f'\t{str(e)}')
            self.logger.warning(self.filename + f'\t{info}')
            return None
