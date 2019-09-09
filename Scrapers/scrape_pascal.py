import datetime
import re
import regex

from .scraper import Scraper


class PascalScraper(Scraper):
    def __init__(self, filename=None, name=None, exploit_type=None, title=None, platform=None, exploit=None):
        ext = ['.pas']
        super().__init__(filename, name, exploit_type, title, platform, exploit, ext)

    def parse_infos(self):
        cves = self.db['cves']  # The main mongo collection

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
                "Description": name + ' ' + description + ' ' + vversion + ' ' + targets,
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

        try:
            URIs.extend(regex.findall('(https?://.*\/.*?)[\)\"]', self.exploit, timeout=5))
        except TimeoutError as e:
            print(e)
        try:
            URIs.extend(regex.findall('[\"\']((?:https?:\/\/.*?)*?\.*?\/?\w*?\/[\S]*?)[\"\'](?:.*\+.*[\"\'](.*?)[\"])?',
                                      self.exploit, timeout=5))
        except TimeoutError as e:
            print(e)

        # Edit the founded uri and filter them
        return self.extract_url(URIs)