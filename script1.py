from selectolax.parser import HTMLParser


def extract(content):
    links = []
    dom = HTMLParser(content)
    for tag in dom.tags('a'):
        attrs = tag.attributes
        if 'href' in attrs and attrs['href'] is not None:
            if '#' not in attrs['href']:
                links.append(attrs['href'])

    for tag in dom.tags('link'):
        attrs = tag.attributes
        if 'href' in attrs and attrs['href'] is not None:
            if '#' not in attrs['href']:
                links.append(attrs['href'])

    for tag in dom.tags('meta'):
        attrs = tag.attributes
        if 'href' in attrs and attrs['href'] is not None:
            if '#' not in attrs['href']:
                links.append(attrs['href'])

    # for sitemaps
    for tag in dom.tags('loc'):
        links.append(tag.text())
    links = list(set(links))

    return links
