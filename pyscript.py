import requests
import sys
from script1 import extract
from check_path import check
from Queuer import Queuer
from urllib.parse import urlparse
from extract_infos import extract_infos
from pymongo import MongoClient
from check_details import check_details
import traceback
import time

client = MongoClient('mongodb://localhost:27017')
db = client['exploits']
collection = db['cves']

def crawler(argv):
    domains = {}
    myQueuer = Queuer(argv)
    exploits = {}
    first_domain = ''
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
            exploits[domain] = {
                "true_vulns" : [],
                "possible_vulns" : []
            }
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
                vulns = check_details(data_about_domain, collection, domain)
                exploits[domain]["true_vulns"].extend(vulns["true_vulns"])
                exploits[domain]["possible_vulns"].extend(vulns["possible_vulns"])
            except Exception as e:
                print(e)
                traceback.print_tb(e.__traceback__)
        if to_url:
            exploits[domain]["possible_vulns"].extend(check(urlparse(url).path, collection))
        myQueuer.parsed_url.append(url)
    
    exploits[domain]["possible_vulns"] = [item for item in exploits[domain]["possible_vulns"] if item not in exploits[domain]["true_vulns"]]

    for domain in exploits.keys():
        print(domain)
        print(list(set(exploits[domain]["true_vulns"])))
        print(len(set(exploits[domain]["true_vulns"])))
        print(list(set(exploits[domain]["possible_vulns"])))
        print(len(set(exploits[domain]["possible_vulns"])))
    print(domains)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("USAGE: python3 pyscript.py urls")
        print("E.g python3 pyscript.py http://localhost:80/index.html http://domain.com/sitemap.xml")
        exit(1)
    argv = [arg for arg in sys.argv if arg not in __file__]
    for arg in sys.argv:
        if arg not in __file__:
            domain = urlparse(arg).netloc
            if not any(domain in s for s in argv):
                argv.append('http://' + domain + '/sitemap.xml')
    print(argv)
    crawler(argv)