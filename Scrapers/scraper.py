import time

from pymongo import MongoClient
from urllib.parse import unquote
from urllib.parse import unquote_plus
import regex
import re
import logging


class Scraper(object):
    def __init__(self, filename, name, exploit_type, title, platform, exploit, ext=None):
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
        self.ext = ext
        logging.basicConfig(filename='app.log', filemode='a+', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        self.logger = logging.getLogger('Scraper')

    def parse_infos(self):
        pass

    def parse_url(self):
        pass

    def get_ext(self):
        return self.ext

    def extract_url(self, URIs):
        URI = []

        header_values = ['application', 'image', 'audio', 'messages', 'video', 'text', 'multipart', 'firefox', 'chrome',
                         'chromium']

        bad_values = ['[', '\\r', '&', '*', ';', ')', ']', '(', '}', '{', '+', '=', '>', '<', '\\', ',', '/bin/', 'cmd',
                      '/div', '"', 'pre', 'target', 'path', 'HTTP', 'sys.arg', 'argv', 'form', 'x-php', '/usr/', '\/www.', 'http', 'x-']

        bad_values_equals = ['c', 'for', 'or', 'ind', 'IP', 'bin', 'ksh', 'TCP/IP', '', 'html', 'jpg', 'image', 'txt',
                      'xml', 'png', 'form', 'webp', 'json', 'script', 'body', 'p', 'h1', 'h2', 'a', 'form', 'iframe',
                             'xhtml', 'head', 'title', 'address', 'td', 'tr', '=', 'span', 'gif', 'jpeg', 'css', 'style']

        for uri in URIs:

            if isinstance(uri, tuple):
                uri = uri[0] + uri[1]

            items = re.findall(r'(\$.*?)[\/\?\'\"\)\.]', uri)
            if items:
                for item in items:
                    uri = re.sub(re.escape(item)+r'[\/\?\'\"\)\.]', self.recursive(item), uri)

                uri = re.sub('"', '', uri)
            try:
                uri = regex.sub('"\s*\\\\\\n\s*"', '', uri, timeout=5)
            except TimeoutError as e:
                print('slash ' + e)
            try:
                uri = regex.sub('%%', '%', uri, timeout=5)
            except TimeoutError as e:
                print('proc ' + e)
            try:
                uri = regex.sub('[\"\']\s*\+.*[\"\']', '', uri, timeout=5)
            except TimeoutError as e:
                print('plus ' + e)

            uri = unquote(uri)
            uri = unquote_plus(uri)

            uri = re.sub(r'\[[pP][Aa][Tt][Hh].*?\]', 'public', uri)
            uri = re.sub('\[(?:target|host).*?\]', 'www.example.com', uri)

            if ' ' in uri:
                URIs.extend(re.split('\s+', uri))
                continue
            try:
                uri = regex.sub('(?:http:\/\/.*?\/?)(?=\/\S)', '', uri, timeout=5)
            except TimeoutError as e:
                print('Sub ' + e)

            path = re.findall('(.*?)\?', uri)
            if path:
                uri = path[0]

            stopped = False
            for bad in bad_values:
                if bad in uri.lower() and not stopped:
                    stopped = True
                    break

            if stopped:
                continue

            if uri.endswith('.'):
                continue
            if '/%s' in uri:
                uri = re.sub('/%s', '/public', uri)
            elif '%s' in uri:
                uri = re.sub('%s', 'public/', uri)


            stopped = False
            for bad in bad_values_equals:
                if bad == uri.lstrip('/').lower() and not stopped:
                    stopped = True
            if stopped:
                continue

            uri = re.sub('^\/\/.*?(\/.*)', '\g<1>', uri, flags=re.M)
            uri = re.sub('//', '/', uri)
            if re.findall('(\/[\/0-9]+|\/mm\/yyyy)', uri):
                continue

            if uri == '/':
                uri = '/public/'

            if re.findall('www\..*?\..*', uri):
                continue


            new_uris = uri.strip('/').split('/')
            if len(list(set(uri.strip('/').split('/')))) == 1 and len(new_uris) > 1:
                continue
            if len(new_uris) == 2:
                if new_uris[0].lower() not in header_values:
                    URI.append('/' + uri.lstrip('/'))
            elif len(new_uris) == 1 and not uri.startswith('/') and '.' not in uri:
                continue
            elif re.findall('\d\.\d', uri):
                continue
            elif len(new_uris) == 1 and len(new_uris[0]) == 1:
                continue
            else:
                try:
                    if regex.findall('\w*@\w*(?:\.\w*)*', uri, timeout=5):
                        continue
                    else:
                        URI.append('/' + uri.lstrip('/'))
                except TimeoutError as e:
                    print('Some shiet ' + e)
                    continue

        return URI

    def is_parsed(self):
        query = self.parsed_col.find_one({"filename": self.filename})
        if query is not None:
            parsed = query['parsed']
            if parsed:
                return True
        return False

    def construct_title(self):
        title = re.sub('\s', '_', self.title)
        title = re.sub('\.', '@', title)
        title = self.name + '_' + title

        if self.collection.find_one({"filename": self.name}) is not None:
            title = self.collection.find_one({"filename": self.name})['cve']

        return title

    def recursive(self, wildcard, depth=5):
        final = ""
        uri = re.findall(re.escape(wildcard) + r'\s*=\s*(.*);', self.exploit)
        if not uri or depth < 0:
            return '/'
        if uri[0].startswith(('"', "'")) and uri[0].endswith(('"', "'")):
            return uri[0].strip('"\'')
        else:
            values = re.findall(r'(\$.*?)(?:\.|$)', uri[0], flags=re.M)
            for value in values:
                final += self.recursive(value, depth-1)
            return final