import re

from selectolax.parser import HTMLParser


def extract_infos(headers, content):
    data = dict()
    headers = {k.lower(): v for k, v in headers.items()}

    # check wp version
    wp_version = re.findall('wp-(?:emoji-release|embed)\.min\.js.*ver=(.*?)[\"\']', content)
    if wp_version:
       wp_version = wp_version[0]

    cms = 'Default'
    version = 'version'

    dom = HTMLParser(content)
    for tag in dom.tags('meta'):
        attrs = tag.attributes
        if 'name' in attrs:
            if 'generator' == attrs['name'].lower():
                cms = attrs['content']
                version = re.findall('\d+\.*\d*\.*\d*', cms)
                if version:
                    version = version[0]

    if cms == 'Default':
        if 'x-powered-by' in headers.keys():
            cms = headers.get('x-powered-by')
            if 'x-aspnet-version' in headers.keys():
                version = headers.get('x-aspnet-version')
        elif 'magento' in content.lower():
            cms = 'Magento'
        elif 'shopify' in content.lower():
            cms = 'Shopify'
        elif 'squarespace' in content.lower():
            cms = 'Squarespace'
        elif 'blogger.com' in content.lower():
            cms = 'Blogger'
        elif 'typo3' in content.lower():
            cms = 'TYPO3'
        elif 'opencart' in content.lower():
            cms = 'OpenCart'
        elif 'joomla' in content.lower():
            cms = 'Jooma'
        elif 'prestashop' in content.lower():
            cms = 'Prestashop'
        elif 'wordpress' in content.lower():
            cms = 'Wordpress'

    data['cms'] = cms
    if wp_version:
        data['version'] = wp_version
    else:
        data['version'] = version

    for key in headers.keys():
        if 'server' == key or 'x-server' == key:
            data['server'] = headers.get(key)
        if key.startswith('x-') and headers.get(key) not in data.values():
            data[key] = headers.get(key)

    plugins = re.findall('wp-content/plugins/(.*?)/.*ver=(.*?)[\s\'\"]', content)
    data['Plugins'] = {}
    if plugins:
        for plugin in plugins:
            if plugin[0] in data['Plugins']:
                continue
            data['Plugins'][plugin[0]] = plugin[1]
    return data
