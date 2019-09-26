import requests
from script1 import extract
from check_path import check
from Queuer import Queuer
from urllib.parse import urlparse
from extract_infos import extract_infos
from pymongo import MongoClient
from check_details import check_details

client = MongoClient('mongodb://localhost:27017')
db = client['exploits']
collection = db['cves']

domains = {}
myQueuer = Queuer(['https://amarculeseidiana.com/'])
exploits = {}
first_domain = ''
cnt = 1
while not myQueuer.empty():
    url = myQueuer.pop()
    print(f'Url in pyscript {url}')
    domain = urlparse(url).netloc
    if cnt == 1:
        first_domain = domain
        cnt += 1
    if not domain:
        domain = 'Paths'
    if domain not in exploits:
        exploits[domain] = []
    data_about_domain = {}
    if url.startswith('http'):
        try:
            resp = requests.get(url, headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.75 Safari/537.36'})
            response = extract(resp.content)
            if domain not in domains:
                data_about_domain = extract_infos(resp.headers, resp.text)
                domains[domain] = data_about_domain
            else:
                data_about_domain = domains.get(domain)
            exploits[domain].extend(check_details(data_about_domain, collection))
            myQueuer.push(response, first_domain)
        except Exception as e:
            print(e)

    exploits[domain].extend(check(urlparse(url).path, collection, data_about_domain))
    myQueuer.parsed.append(url)

for domain in exploits.keys():
    print(domain)
    print(list(set(exploits[domain])))
    print(len(set(exploits[domain])))
print(domains)
