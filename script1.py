from selectolax.parser import HTMLParser
import sys
from urlparse import urlparse

def extract(content):
    links = []
    dom = HTMLParser(content)
    for tag in dom.tags('a'):
        attrs = tag.attributes
        if 'href' in attrs:
            if '#' not in attrs['href']:
                print(urlparse(attrs['href']))
                links.append(attrs['href'])
    
    # for sitemaps
    for tag in dom.tags('loc'):
        links.append(tag.text())
    links = list(set(links))


    return links

