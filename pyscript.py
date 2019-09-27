import requests
from script1 import extract
from check_path import check
from Queuer import Queuer
from urllib.parse import urlparse
from extract_infos import extract_infos
from pymongo import MongoClient
from check_details import check_details
import traceback

client = MongoClient('mongodb://localhost:27017')
db = client['exploits']
collection = db['cves']

domains = {}
myQueuer = Queuer(['http://localhost:8081/index.html'])
exploits = {}
first_domain = ''
cnt = 1
while not myQueuer.empty():
    url = myQueuer.pop()
    print(f'Url in pyscript {url}')
    domain = urlparse(url).netloc
    if domain not in myQueuer.parsed_domains:
        myQueuer.current_domain = domain
    elif domain != myQueuer.current_domain:
        continue

    if not domain or domain == '':
        domain = 'Paths'
    if domain not in exploits:
        exploits[domain] = []
    data_about_domain = {}
    to_url = False
    domain = myQueuer.current_domain
    if url.startswith('http'):
        try:
            resp = requests.get(url, headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.75 Safari/537.36'})
            response = extract(resp.content)
            myQueuer.push(response, exploits[domain])

            if '/tag/' in url or '/feed' in url:
                myQueuer.parsed_url.append(url)
                continue

            if domain not in domains:
                data_about_domain = extract_infos(resp.headers, resp.text)
                domains[domain] = data_about_domain
            else:
                data_about_domain = domains.get(domain)
            if data_about_domain['cms'] == 'Default':
                to_url = True
            exploits[domain].extend(check_details(data_about_domain, collection, domain))
        except Exception as e:
            traceback.print_tb(e.__traceback__)

    if to_url:
        exploits[domain].extend(check(urlparse(url).path, collection))
    myQueuer.parsed_url.append(url)

for domain in exploits.keys():
    print(domain)
    print(list(set(exploits[domain])))
    print(len(set(exploits[domain])))
print(domains)
