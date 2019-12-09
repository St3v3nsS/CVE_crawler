import re
import time
from builtins import any
from urllib.parse import urlparse
from urllib.parse import unquote


class Queuer(object):
    def __init__(self, url_list):
        self.url_list = list(set(url_list))
        self.parsed_url = []
        self.parsed_domains = []
        self.current_domain = ''
        self.blacklist = ['instagram', 'facebook', 'twitter', 'flickr', 'linkedin', 'whatsapp', 'pinterest',
                          'www.wordpress.com', 'hbo', 'netflix', 'amazon', 'premiumcoding', 'javascript', 'oembed',
                          'wikipedia', 'fonts', 'google', 'bing', 'yahoo']
    
    def pop(self):
        return self.url_list.pop(0)
    
    def push(self, list_to_push, exploits):

        list_to_push = self.blacklisted_urls(list_to_push)
        self.url_list.extend(list_to_push)
        seen = set()
        seen_add = seen.add
        self.url_list = [x for x in self.url_list if not (x in seen or seen_add(x))]
        non_domain_lista = [x for x in self.url_list if not re.findall(re.escape(self.current_domain), urlparse(x).netloc)]
        domain_lista = [x for x in self.url_list if x not in non_domain_lista]
        self.url_list = domain_lista + non_domain_lista
        if not any(self.current_domain in urlparse(x).netloc for x in self.url_list):
            self.parsed_domains.append(self.current_domain)
            self.current_domain = ''
        print(len(self.url_list))

    def empty(self):
        return True if len(self.url_list) == 0 else False

    def blacklisted_urls(self, urls):
        to_push = []
        for url in urls:
            found = False
            for garbagge in self.blacklist:
                if garbagge in url:
                    found = True
                    break
            if not found:
                to_push.append(url)
        list_to_push = [unquote(re.sub('\"', '', re.sub(r'\\', '', x)))for x in to_push if x not in self.parsed_url]

        return list_to_push