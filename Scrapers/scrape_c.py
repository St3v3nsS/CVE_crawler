from .scraper import Scraper


class CScraper(Scraper):
    def __init__(self, filename=None, name=None, exploit_type=None, title=None, platform=None, exploit=None):
        ext = ['.c']
        super().__init__(filename, name, exploit_type, title, platform, exploit, ext)

    def parse_infos(self):
        pass

    def parse_url(self):
        pass