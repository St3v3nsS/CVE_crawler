from pymongo import MongoClient

class Scraper(object):
    def __init__(self, filename, name, exploit_type, title, platform, exploit):
        self.exploit = exploit
        self.filename = filename
        self.name = name
        self.exploit_type = exploit_type
        self.title = title
        self.platform = platform
        self.client = MongoClient('mongodb://localhost:27017')
        self.db = self.client['exploits']
        self.collection = self.db['cve_refs']
        self.parsed_col = self.db['parse_exploit']
    
    def parse_infos(self):
        pass

    def parse_url(self):
        pass