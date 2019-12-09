import requests
import sys
from get_urls import extract
from Queuer import Queuer
from urllib.parse import urlparse
from extract_infos import extract_infos
from Checker import Checker
import traceback
import time
sys.path.append('/home/john/Project/CVE_crawler/')
from Mongo_Connection import get_db as mongodb
from Detect_Malware import check_file
from Redis import handle_redis

cves = "cves"

db = mongodb.get_db()
collection = db[cves]

def get_index_page(domain):
    try:
        resp = requests.get(url='http://' + domain, headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.75 Safari/537.36'})
        if resp.status_code == 200:
            return resp.headers, resp.text
    except Exception:
        resp = requests.get(url='http://'+ domain + '/index.php', headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.75 Safari/537.36'})
        if resp.status_code == 200:
            return resp.headers, resp.text
    return None, None

def crawler(argv):
    domains = {}
    myQueuer = Queuer(argv)
    exploits = {}
    myChecker = None
    while not myQueuer.empty():
        url = myQueuer.pop()
        print(f'Url in pyscript {url}')
        
        domain = urlparse(url).netloc
        if domain not in myQueuer.parsed_domains:
            myQueuer.current_domain = domain
            is_parsed = False
            myChecker = Checker(domain)
        elif domain != myQueuer.current_domain:
            continue

        if not domain or domain == '':
            domain = 'Paths'
        if domain not in exploits:
            exploits[domain] = {
                "true_vulns" : [],
                "almost_true": [],
                "probable_vulns": [],
                "possible_vulns" : [],
                "malware": []
            }
        if not url.startswith('http'):
            myurl = "http://" + domain + url
        else:
            myurl = url
        try:
            malw_or_not = check_file.get_prediction_from_single_pe(myurl)
            print(malw_or_not)
        except Exception:
            pass

        if malw_or_not is not None:
            if isinstance(malw_or_not, tuple):
                exploits[domain]["malware"].append(malw_or_not[1])
            continue
        
        data_about_domain = {}
        to_url = False
        domain = myQueuer.current_domain
        if url.startswith('http'):
            try:
                resp = requests.get(url, headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.75 Safari/537.36'})
                response = extract(resp.content)
                
                if '/tag/' in url or '/feed' in url:
                    myQueuer.parsed_url.append(url)
                    continue
                
                myQueuer.push(response, exploits[domain])
                if not is_parsed:
                    if domain not in domains:
                        headers, data = get_index_page(domain)
                        if headers is None:
                            headers = resp.headers
                            data = resp.text
                        data_about_domain = extract_infos(headers, data)
                        domains[domain] = data_about_domain
                    else:
                        data_about_domain = domains.get(domain)
                    
                    if data_about_domain['cms'] == 'Default':
                        to_url = True

                    if not to_url: 
                        
                        if handle_redis.get_redis_just_cms(data_about_domain) is not None:
                            print("In rediss...")
                            myChecker.check_details(data_about_domain, collection) # to edit, look just for the founded exploits, not all collection
                            vulns = myChecker.get_all_vulns()
                        else:
                            myChecker.check_details(data_about_domain, collection)
                            vulns = myChecker.get_all_vulns()
                        exploits[domain]["true_vulns"].extend(vulns["true_vulns"])
                        exploits[domain]["almost_true"].extend(vulns["almost_true"])
                        exploits[domain]["probable_vulns"].extend(vulns["probable_vulns"])
                        exploits[domain]["possible_vulns"].extend(vulns["possible_vulns"])
                        is_parsed = True

                        handle_redis.update_redis_full(data_about_domain, myChecker.get_vulns_by_cms_and_plug())
                        handle_redis.update_redis_just_cms(data_about_domain, myChecker.get_vulns_by_cms())

            except Exception as e:
                print(e)
                traceback.print_tb(e.__traceback__)
        if to_url:
            myChecker.check_path(urlparse(url).path, collection)
            exploits[domain]["possible_vulns"].extend(myChecker.get_all_vulns())
        myQueuer.parsed_url.append(url)
    
    exploits[domain]["possible_vulns"] = [item for item in exploits[domain]["possible_vulns"] if item not in exploits[domain]["true_vulns"]]
    print()
    for domain in exploits.keys():
        print(domain)
        print("True Vulns")
        print(list(set(exploits[domain]["true_vulns"])))
        print("Almost true Vulns")
        print(list(set(exploits[domain]["almost_true"])))
        print("Probable Vulns")
        print(list(set(exploits[domain]["probable_vulns"])))
        print("Possible Vulns")
        print(str(list(set(exploits[domain]["possible_vulns"]))).encode('UTF-8'))
        print("Malware founded")
        print(list(set(exploits[domain]["malware"])))
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