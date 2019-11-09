import time
import json
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
        # useful regexes
        self.between = r'((?:[\dx]+\.?)+\s*(?:-\d+)?)(\s*<=?\s*)((?:[\dx]+\.?)+\s*(?:-(?:[\dx]+\.?)+)?)'
        self.single = r'(?:x64|x32|x86|(?<![<=>\-\s\.\d]))\s*((?:(?:\d+\.?)+(?:[\dx]+)?)(?:\s*?)(?:-(?:[\dx]+\.?)+)?)(?!\w)'
        self.small = r'(<=?)\s*((?:[\dx]+\.?)+\s*(?:-(?:[\dx]+\.?)+)?)'
        self.big = r'(>=?)\s*((?:[\dx]+\.?)+\s*(?:-(?:[\dx]+\.?)+)?)'
    
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
                      '/div', '"', 'pre', 'target', 'path', 'http', 'sys.arg', 'argv', 'x-php', '/usr/',
                      '\/www.', 'http', 'x-', '__',
                      'altervista']

        bad_values_equals = ['c', 'for', 'or', 'ind', 'ip', 'bin', 'ksh', 'tcp/ip', '', 'html', 'jpg', 'image', 'txt',
                             'xml', 'png', 'form', 'webp', 'json', 'script', 'body', 'p', 'h1', 'h2', 'a', 'form',
                             'iframe',
                             'xhtml', 'head', 'title', 'address', 'td', 'tr', '=', 'span', 'gif', 'jpeg', 'css', 'style'
                                                                                                                 'plain',
                             'table', 'pjpeg', 'media', 'if', 'textarea', 'center', 'font', 'str0ke', 'hostname', 'quicktime',
                             'form-data', 'windows']

        for uri in URIs:
            if isinstance(uri, tuple):
                uri = uri[0] + uri[1]

            if 'milw0rm' in uri.lower():
                continue

            if uri.startswith(('com/', 'net/', 'org/')):
                uri = uri[3:]

            if '\n' in uri or uri.startswith('../'):
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
        URI = [regex.sub(r'(\/\.\.)+', '', regex.sub(r'//', '/', item)) for item in URI if 'Windows' not in item]
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

    def remove_xs(self, version):
        return regex.sub(r'(\.x.*)', r'', version)

    def remove_dash(self, version):
        versions = version.split('-')
        items = [self.remove_xs(version) for version in versions]
        return '.'.join(items).strip(',.;! ')

    def append_founded(self, versions, lst_item, version):
        
        between = regex.findall(self.between, version)
        single = regex.findall(self.single, version)
        small = regex.findall(self.small, version)
        big = regex.findall(self.big, version)

        if between:
            versions["CMS"][lst_item].append({"<>" : (self.remove_dash(between[0][0].strip()), self.remove_dash(between[0][2].strip()))})
        elif single:
            to_append = '=='
            if len(versions["CMS"][lst_item]) >= 1:
                to_append = next(iter(versions["CMS"][lst_item][0].keys()))
            versions["CMS"][lst_item].append({to_append: self.remove_dash(single[0].strip())})
        elif small:
            versions["CMS"][lst_item].append({small[0][0].strip():self.remove_dash(small[0][1].strip())})
        elif big:
            versions["CMS"][lst_item].append({big[0][0].strip():self.remove_dash(big[0][1].strip())})
        return versions


    def get_version_from_name(self, description):
        self.cms_regex = r'(?<![.\d])([\w\s!\']+(?:-\w)?[\w\s!\']+\s*?)(?:[<=>\d]+|$)'

        version = regex.findall(r'(.*)\s-\s\S', self.title, timeout=5)
        connection = None
        versions = {
            "connection_between": connection,
            "CMS" : {},
            "is_plugin": "no",
            "is_theme": "no", 
            "description": {}
        }
        if not version:
            return json.dumps(versions)
        version = version[0]
        if regex.findall(' and ', version):
            connection = 'and'
            version = regex.sub(' and ', ' / ', version)
        if regex.findall('(.*)\s*\+\s*', version):
            connection = 'and'
            version = regex.sub(r'(.*)\s*\+\s*', '\g<1> / ', version)
        version = regex.sub(self.single + r'\s((?:(?:\d+\.?)+(?:[\dx]+)?)(?:\s*?)(?:-(?:[\dx]+\.?)+)?)(?!\w)',' \g<1> / \g<2>', version)
        list_of_versions = version.split('/')
        list_of_versions = [item.strip() for item in list_of_versions]
        lst_item = None
        
        for version in list_of_versions:
            if ' plugin ' in version.lower() or 'component' in version.lower() or 'module' in version.lower():
                versions["is_plugin"] = "yes"
            elif ' theme ' in version.lower():
                versions["is_theme"] = "yes"
            if lst_item == None:
                lst_item = regex.findall(self.cms_regex, version)
                if lst_item:
                    lst_item = lst_item[0].strip()
                    versions["CMS"][lst_item] = []
                    versions = self.append_founded(versions, lst_item, version)
                else: lst_item = None
            elif lst_item in version or not regex.findall(self.cms_regex, version):
                versions = self.append_founded(versions, lst_item, version)
            else:
                lst_item = regex.findall(self.cms_regex, version)
                if lst_item:
                    lst_item = lst_item[0].strip()
                    versions["CMS"][lst_item] = []
                    versions = self.append_founded(versions, lst_item, version)
                else: lst_item = None
        versions['description'] = self.get_version_from_desc(description, versions) 
        for cms in versions.get('CMS').keys():
            versions['CMS'][cms] = self.remove_dups_dict(cms, versions['CMS'])
        return json.dumps(versions)

    def get_version_from_desc(self, description, versions):
        description = description.lower()
        description = regex.sub('up to', '<=', description)
        cms = versions.get('CMS')
        to_append = {}
        cms_to_check = cms.keys()

        # match the already founded cms
        for cms in cms_to_check:
            cmss = cms.lower()
            items = cmss.split(' ')
            to_append[cms] = []
            for i in range(len(items)):
                regexp = r'\s*'.join(items[i:])
                if regex.findall(r'prior to ' + regexp, description):
                    regexp1 = r'prior to ' + regexp + r'(((?:x64|x32|x86|(?<![<=>\-\s\.\d]))\s((?:(?:\d+\.?)+(?:[\dx]+)?)(?:\s*?)(?:-(?:[\dx]+\.?)+)?)(?!\w),?)+)(?: and)?((?:x64|x32|x86|(?<![<=>\-\s\.\d]))\s((?:(?:\d+\.?)+(?:[\dx]+)?)(?:\s*?)(?:-(?:[\dx]+\.?)+)?)(?!\w))?'
                    regexp1 = regex.findall(regexp, description)
                    if regexp1:
                        if isinstance(regexp1, tuple):
                            grp1 = regexp1[0][1].split(', ')
                            for grp in grp1:
                                to_append[cms].append({'<=': self.remove_dash(grp)})
                            if len(regexp[0])>=5:
                                to_append[cms].append({'<=': self.remove_dash(regexp[0][4])})
            
                if regex.findall(regexp, description):
                    if versions.get('is_plugin') == 'yes':
                        words_to_check = [regexp + r'\s*' + w for w in ['module', 'component', 'plugin', 'plug-in', 'plug in']]
                        to_append = self.extract_version_brute_force(words_to_check, description, to_append, cms, regexp)                       
                    elif versions.get('is_theme') == 'yes':
                        words_to_check = [regexp + r'theme']
                        to_append = self.extract_version_brute_force(words_to_check, description, to_append, cms, regexp)
                    else:
                        to_append = self.extract_version_brute_force([regexp], description, to_append, cms, regexp)
                
                    
            regexp = r'affects .*? versions prior to \s*((?:(?:\d+\.?)+(?:[\dx]+)?)(?:\s*?)(?:-(?:[\dx]+\.?)+)?) and' + self.single
            regexp = regex.findall(regexp, description)
            if regexp:
                to_append[cms].extend([{'<=': self.remove_dash(regexp[0][0])}, {'==': self.remove_dash(regexp[0][1])}])
            else:
                regexp = r'versions prior to \s*((?:(?:\d+\.?)+(?:[\dx]+)?)(?:\s*?)(?:-(?:[\dx]+\.?)+)?)'
                regexp = regex.findall(regexp, description)
                if regexp:
                    to_append[cms].extend([{'==':self.remove_dash(regexp[0])}])
                else:
                    regexp = r'affects versions ((?:[\dx]+\.?)+\s*(?:-\d+)?)(\s*<=?\s*)((?:[\dx]+\.?)+\s*(?:-(?:[\dx]+\.?)+)?) and ((?:[\dx]+\.?)+\s*(?:-\d+)?)(\s*<=?\s*)((?:[\dx]+\.?)+\s*(?:-(?:[\dx]+\.?)+)?)'
                    regexp = regex.findall(regexp, description)
                    if regexp:
                        to_append[cms].extend([{'<>':(self.remove_dash(regexp[0][0]), self.remove_dash(regexp[0][2]))}, {'<>':(self.remove_dash(regexp[0][3]), self.remove_dash(regexp[0][5]))}])
                    else:
                        regexp = r'affects versions ((?:[\dx]+\.?)+\s*(?:-\d+)?)(\s*<=?\s*)((?:[\dx]+\.?)+\s*(?:-(?:[\dx]+\.?)+)?)'
                        regexp = regex.findall(regexp, description)
                        if regexp:
                            to_append[cms].extend([{'<>':(self.remove_dash(regexp[0][0]), self.remove_dash(regexp[0][2]))}])

        # try find new ones
        possible_cms = ['Joomla!', 'WordPress', 'Drupal', 'PHP', 'MySQL', 'Jupiter', 'Nginx', 'Apache', 'OpenCart', 'Prestashop']
        for cms in possible_cms:
            lowerr = cms.lower()
            if cms == 'Joomla!':
                lowerr += r'?'
            possible_regexes = ['running ' + lowerr, lowerr + r'\s*before', lowerr + r'\s*(?:v(?:ersions?)?)?\s*', 'running ' + lowerr + r'\s*' +self.single + r'\s*or\s*']
            for item in possible_regexes:
                possible_regexess = [item + r'\s*' + ver for ver in [self.between, self.single, self.big, self.small]]
                
                for regexp in possible_regexess:
                    values = regex.findall(regexp, description)

                    if values:
                        if cms not in to_append.keys():
                            to_append[cms] = []

                        if self.between in regexp:
                            to_append[cms].extend([{'<>':(self.remove_dash(values[0][0]), self.remove_dash(values[0][2]))}])
                        elif self.single in regexp:
                            if isinstance(values[0], tuple):
                                to_append[cms].extend([{'==': self.remove_dash(values[0][0])}, {'==': self.remove_dash(values[0][1])}])
                            else:
                                to_append[cms].extend([{'==':self.remove_dash(values[0])}])
                        elif self.small in regexp:
                            to_append[cms].append({values[0][0].strip():self.remove_dash(values[0][1].strip())})
                        else:
                            to_append[cms].append({values[0][0].strip():self.remove_dash(values[0][1].strip())})
                        break
        for cms in to_append.keys():
            to_append[cms] = self.remove_dups_dict(cms, to_append)

        return to_append

    def remove_dups_dict(self, cms, to_append):
        return [dict(t) for t in {tuple(d.items()) for d in to_append[cms]}]

    def extract_version_brute_force(self, words_to_check, description, to_append, cms, regexp):
        not_found = True

        for word in words_to_check:
            if regex.findall(word, description):
                possible = ['below', self.single]
                for pos in possible:
                    regexp = word + r'\s*(?:v(?:ersions?)?)?\s*' + self.single + r'(and\s*{})'.format(pos)
                    vers = regex.findall(regexp, description)
                    if vers:
                        not_found = False
                        if 'below' in vers[0][1]:
                            to_append[cms].extend([{'<=': self.remove_dash(vers[0])}])
                        elif 'and' in vers[0][1]:
                            to_append[cms].extend([{'==': self.remove_dash(vers[0])}, {'==', self.remove_dash(vers[1])}])
                if not_found:
                    regexes_to_test = [word + r'\s*(?:v(?:ersions?)?)?\s*' + item for item in [self.between, self.small, self.big, self.single]]
                    
                    for regexp in regexes_to_test:
                        
                        vers = regex.findall(regexp, description)
                        if vers:
                            not_found = False
                            if self.single in regexp:
                                to_append[cms].extend([{'==': self.remove_dash(vers[0])}])
                            else:
                                to_append[cms].extend([{vers[0][0]: self.remove_dash(vers[0][1])}])
                            break
        if not_found:   
            value = regex.findall(regexp + self.small, description)
            if value:
                not_found = False
                to_append[cms].extend([{value[0][0]: self.remove_dash(value[0][1])}])
        
        return to_append     

    def create_object_for_mongo(self, title, description, references, URI):
        myDict = {
                "EDB-ID": self.name,
                "Vulnerability": title,
                "Name": self.title,
                "Description": str(description),
                "Versions": json.loads(self.get_version_from_name(str(description))),
                "Platform": self.platform,
                "References": references,
                "Type": self.exploit_type,
                "Date": self.date,
                "URI": list(set(URI))
            }
        return myDict
    