import re

from selectolax.parser import HTMLParser

def append_info(info, data,plugin_or_theme):
    data[plugin_or_theme] = {}

    for info_type in info:
        if info_type[0] in data[plugin_or_theme]:
            continue
        data[plugin_or_theme][info_type[0]] = info_type[1]
    return data

def extract_infos(headers, content):
    data = dict()
    headers = {k.lower(): v for k, v in headers.items()}

    # check wp version
    wp_version = re.findall(r'wp-(?:emoji-release|embed)\.min\.js.*ver=(.*?)[\"\']', content)
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
                version = re.findall(r'\d+\.*\d*\.*\d*', cms)
                if version:
                    version = version[0]
                cms = re.sub(re.escape(version), '', cms).strip()

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
            cms = 'Joomla'
        elif 'prestashop' in content.lower():
            cms = 'Prestashop'
        elif 'wordpress' in content.lower():
            cms = 'Wordpress'
        elif 'drupal' in content.lower():
            cms = 'Drupal'

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

    plugins = re.findall(r'wp-content/plugins/(.*?)/.*ver=(.*?)[\s\'\"]', content)
    if plugins:
        data = append_info(plugins, data, 'Plugins')
    wp_themes = re.findall(r'/wp-content/themes/(.*)/.*?ver=(.*?)[\s\'\"]', content)
    if wp_themes:
        data = append_info(wp_themes, data, 'Themes')

    drupal_modules = re.findall(r'/modules/.*/(.*?)\.css\?v=(.*?)[\s\"\']', content)
    if drupal_modules:
        data = append_info(drupal_modules, data, 'Plugins')

    drupal_themes = re.findall(r'/themes/.*?/(.*)/css.*?v=(.*?)[\s\'\"]', content)
    if drupal_themes:
        data = append_info(drupal_themes, data, 'Themes')

    return data
