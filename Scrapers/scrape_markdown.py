import datetime
import re

from .scraper import Scraper


class MDScraper(Scraper):
    def __init__(self, filename=None, name=None, exploit_type=None, title=None, platform=None, exploit=None):
        ext = ['.md']
        super().__init__(filename, name, exploit_type, title, platform, exploit, ext)

    def parse_infos(self):
        cves = self.db['cves']

        print(self.filename)

        query = self.parsed_col.find_one({"filename": self.filename})
        if query is not None:
            parsed = query['parsed']
            if parsed:
                return

        error = False
        parsed_file = True
        try:

            title = re.sub('\s', '_', self.title)
            title = re.sub('\.', '@', title)
            title = self.name + '_' + title

            refs = []
            description = []
            vversion = []
            name = []
            targets = []

            if self.collection.find_one({"filename": self.name}) is not None:
                title = self.collection.find_one({"filename": self.name})['cve']

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
                "Description": name + ' -- ' + description + ' -- ' + vversion + ' -- ' + targets,
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
        pass