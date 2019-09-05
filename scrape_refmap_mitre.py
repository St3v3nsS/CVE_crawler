import requests
from pymongo import MongoClient
from selectolax.parser import HTMLParser

#   Mongo initialize
client = MongoClient('mongodb://localhost:27017')
db = client['exploits']
collection = db['cve_refs']
collection.create_index([("filename", 1)], unique=True)


def extract(content):
    dom = HTMLParser(content)  # Create a parser
    for tag in dom.tags('tr'):  # For every tr
        tds = []
        for td in tag.iter():
            tds.append(td.text())   # Add the tds ---> EXPLOIT-DB:1 | CVE_NR_1
        if len(tds) == 2 and tds[0].startswith('EXPLOIT-DB'):
            obj = {
                "filename": tds[0].split(':')[1],
                "cve": tds[1].strip()
            }
            # Add the object to the database
            collection.update({"filename": tds[0].split(':')[1]}, obj, upsert=True)


url = 'https://cve.mitre.org/data/refs/refmap/source-EXPLOIT-DB.html'
headers = {
    "Accept": '*/*',
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36"
}

res = requests.get(url, headers=headers)
extract(res.content)
