import time

from urllib.parse import unquote
from urllib.parse import unquote_plus
import regex
import logging


class Scraper(object):
    def __init__(self, filename, name, exploit_type, title, platform, exploit, mongoclient, date, ext=None):
        self.exploit = exploit
        self.filename = filename
        self.name = name
        self.exploit_type = exploit_type
        self.title = title
        self.platform = platform
        self.client = mongoclient
        self.date = date
        if mongoclient is not None:
            self.db = self.client['exploits']
            self.collection = self.db['cve_refs']
            self.parsed_col = self.db['parse_exploit']
        self.ext = ext
        logging.basicConfig(filename='app.log', filemode='a+',
                            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

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
                      '/div', '"', 'pre', 'target', 'path', 'HTTP', 'sys.arg', 'argv', 'x-php', '/usr/',
                      '\/www.', 'http', 'x-', '__',
                      'altervista']

        bad_values_equals = ['c', 'for', 'or', 'ind', 'IP', 'bin', 'ksh', 'TCP/IP', '', 'html', 'jpg', 'image', 'txt',
                             'xml', 'png', 'form', 'webp', 'json', 'script', 'body', 'p', 'h1', 'h2', 'a', 'form',
                             'iframe',
                             'xhtml', 'head', 'title', 'address', 'td', 'tr', '=', 'span', 'gif', 'jpeg', 'css', 'style'
                                                                                                                 'plain',
                             'table', 'pjpeg', 'media', 'if', 'textarea', 'center', 'font', 'str0ke', 'hostname', 'quicktime',
                             'form-data']

        for uri in URIs:
            if isinstance(uri, tuple):
                uri = uri[0] + uri[1]

            if 'milw0rm' in uri.lower():
                continue

            if uri.startswith(('com/', 'net/', 'org/')):
                uri = uri[3:]

            if '\n' in uri:
                continue

            try:
                items = regex.findall(r'(\$.*?)[\/\?\'\"\)\.]', uri)
                if items:
                    for item in items:
                        uri = regex.sub(regex.escape(item) + r'[\/\?\'\"\)\.]', self.recursive(item), uri)

                    uri = regex.sub('"', '', uri)
            except TimeoutError as e:
                pass
            try:
                uri = regex.sub('"\s*\\\\\\n\s*"', '', uri, timeout=5)
            except TimeoutError as e:
                print('slash ' + str(e))
            try:
                uri = regex.sub('%%', '%', uri, timeout=5)
            except TimeoutError as e:
                print('proc ' + str(e))
            try:
                uri = regex.sub('[\"\']\s*\+.*[\"\']', '', uri, timeout=5)
            except TimeoutError as e:
                print('plus ' + str(e))

            uri = unquote(uri)
            uri = unquote_plus(uri)
            try:
                uri = regex.sub(r'\[(?:[pP][Aa][Tt][Hh].*?|dir|product)\]', 'public', uri)
                uri = regex.sub('\[(?:target|host|victim|url).*?\]', 'www.example.com', uri)
            except TimeoutError as e:
                pass

            if ' ' in uri:
                URIs.extend(regex.split('\s+', uri))
                continue
            try:
                uri = regex.sub('(?:http:\/\/.*?\/?)(?=\/\S)', '', uri, timeout=5)
            except TimeoutError as e:
                print('Sub ' + str(e))

            try:
                path = regex.findall('(.*?)\?', uri)
                if path:
                    uri = path[0]
            except TimeoutError as e:
                pass

            stopped = False
            for bad in bad_values:
                if bad in uri.lower() and not stopped:
                    stopped = True
                    break
            if stopped:
                continue

            if uri.endswith('.'):
                uri = uri[:-1]

            try:
                if '/%s' in uri:
                    uri = regex.sub('/%s', '/public', uri)
                elif '%s' in uri:
                    uri = regex.sub('%s', 'public/', uri)
            except TimeoutError as e:
                pass

            stopped = False
            for bad in bad_values_equals:
                if bad == uri.lstrip('/').lower() and not stopped:
                    stopped = True
            if stopped:
                continue
            try:
                uri = regex.sub('^\/\/.*?(\/.*)', '\g<1>', uri, flags=regex.M)
                uri = regex.sub('//', '/', uri)
                if regex.findall('(\/[\/0-9]+|\/mm\/yyyy)', uri):
                    continue

                if uri == '/':
                    uri = '/public/'

                if regex.findall('www\..*?\..*', uri):
                    continue
            except TimeoutError as e:
                pass

            new_uris = uri.strip('/').split('/')
            if len(list(set(uri.strip('/').split('/')))) == 1 and len(new_uris) > 1:
                continue
            if len(new_uris) == 2:
                if new_uris[0].lower() not in header_values:
                    URI.append('/' + uri.lstrip('/'))
            elif len(new_uris) == 1 and not uri.startswith('/') and '.' not in uri:
                continue
            elif regex.findall('\d\.\d', uri):
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
                    print('Some shiet ' + str(e))
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
        title = regex.sub('\s', '_', self.title)
        title = regex.sub('\.', '@', title)
        title = self.name + '_' + title

        if self.collection.find_one({"filename": self.name}) is not None:
            title = self.collection.find_one({"filename": self.name})['cve']

        return title

    def recursive(self, wildcard, depth=5):
        final = ""
        uri = regex.findall(regex.escape(wildcard) + r'\s*=\s*(.*);', self.exploit)
        if not uri or depth < 0:
            return '/'
        if uri[0].startswith(('"', "'")) and uri[0].endswith(('"', "'")):
            return uri[0].strip('"\'')
        else:
            values = regex.findall(r'(\$.*?)(?:\.|$)', uri[0], flags=regex.M)
            for value in values:
                final += self.recursive(value, depth - 1)
            return final
