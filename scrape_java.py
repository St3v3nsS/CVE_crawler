from scraper import Scraper


class JavaScraper(Scraper):
    def __init__(self, filename, name, exploit_type, title, platform, exploit):
        super().__init__(filename, name, exploit_type, title, platform, exploit)

    def parse_infos(self):
        pass

    def parse_url(self):
        pass