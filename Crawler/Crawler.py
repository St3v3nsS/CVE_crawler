import requests
import sys
from get_urls import extract
from Queuer import Queuer
from urllib.parse import urlparse
from extract_infos import extract_infos
from Checker import Checker
import traceback
import time
import logging
sys.path.append('/home/john/Project/CVE_crawler/')
from Mongo_Connection import get_db as mongodb
from Detect_Malware import check_file
from Redis.Redis import Redis
from Loggers import logger

class Crawler(object):
    def __init__(self, urls):
        self.db = mongodb.get_db()
        self.collection = self.db["cves"]
        self.domains = {}
        self.myQueuer = Queuer(urls)
        self.exploits = {}
        self.myRedis = Redis()
        self.myCheckers = {}
        self.myChecker = None
        self.logger = logger.myLogger("Crawler")
        self.logger.info("Initializing Crawler...")
        self.logger.info(f"Redis at {self.myRedis.get_rj()}")
        ping = False
        self.logger.warn('Waiting for Redis...')
        while ping == False:
            try:
                ping = self.myRedis.get_rj().ping()
            except:
                pass
            self.logger.info(str('Redis Alive:'+str(ping)))
            time.sleep(1)

    def get_index_page(self, domain):
        try:
            resp = requests.get(url='http://' + domain, headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.75 Safari/537.36'})
            if resp.status_code == 200:
                return resp.headers, resp.text
        except Exception:
            extensions = ['html', 'htm', 'php', 'asp', 'aspx']
            for ext in extensions:
                resp = requests.get(url='http://'+ domain + f'/index.{ext}', headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.75 Safari/537.36'})
                if resp.status_code == 200:
                    return resp.headers, resp.text
        return None, None

    def get_checker(self, domain):
        if domain not in self.myCheckers.keys():
            self.myChecker = Checker(domain, self.collection)
            self.myCheckers[domain] = self.myChecker
        else:
            self.myChecker = self.myCheckers[domain]

    def crawl(self):
        while not self.myQueuer.empty():
            url = self.myQueuer.pop()
            self.logger.info(f'Url to check: {url}')
            
            domain = urlparse(url).netloc
            if domain not in self.myQueuer.parsed_domains:
                self.myQueuer.current_domain = domain
                self.get_checker(domain)
            elif domain != self.myQueuer.current_domain:
                continue

            if not domain or domain == '':
                domain = 'Paths'
            if domain not in self.exploits:
                self.exploits[domain] = {
                    "true_vulns" : [],
                    "almost_true": [],
                    "probable_vulns": [],
                    "possible_vulns" : [],
                    "malware": []
                }
            if domain not in self.domains.keys():
                self.domains[domain] = {
                    "data": {},
                    "is_parsed": False
                }
            if not url.startswith('http'):
                myurl = "http://" + url
            else:
                myurl = url
            try:
                malw_or_not = check_file.get_prediction_from_single_pe(myurl)
            except Exception as e:
                self.logger.error(e)

            if malw_or_not is not None:
                if isinstance(malw_or_not, tuple):
                    self.exploits[domain]["malware"].append(malw_or_not[1])
                    self.logger.info(f'Found a \033[91mMalware\033[0m file in {myurl}!')
                else:
                    self.logger.info(f'Found a \033[32mLegit\033[0m file in {myurl}!')
                continue
            
            data_about_domain = {}
            to_url = False
            domain = self.myQueuer.current_domain
           
            try:
                resp = requests.get(myurl, headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.75 Safari/537.36'})
                response = extract(resp.content)
                if '/tag/' in myurl or '/feed' in myurl:
                    self.myQueuer.parsed_url.append(myurl)
                    continue
                
                self.myQueuer.push(response)

                if not self.domains.get(domain)["is_parsed"]:
                    if domain not in self.domains or not self.domains.get(domain)["data"]:
                        headers, data = self.get_index_page(domain)
                        if headers is None:
                            headers = resp.headers
                            data = resp.text
                        data_about_domain = extract_infos(headers, data)
                        self.domains[domain]["data"] = data_about_domain
                    else:
                        data_about_domain = self.domains.get(domain)["data"]
                    if data_about_domain['cms'] == 'Default':
                        to_url = True

                    if not to_url:
                        self.myChecker.set_data(data_about_domain) 
                        full = self.myRedis.get_redis_full(data_about_domain)
                        self.logger.warn(f"FULL: {str(full)}")
                        if full is not None and full:
                            self.myChecker.update_vulns_from_redis(full)
                        else:
                            just_cms = self.myRedis.get_redis_just_cms(data_about_domain)
                            if just_cms is not None and just_cms:
                                self.myChecker.update_vulns_just_cms(just_cms)
                            else:
                                self.myChecker.check_details()
                        # also, check for route attack
                        self.myChecker.check_path(urlparse(url).path)
                        vulns = self.myChecker.get_all_vulns()
                        self.exploits[domain]["true_vulns"].extend(vulns["true_vulns"])
                        self.exploits[domain]["almost_true"].extend(vulns["almost_true"])
                        self.exploits[domain]["probable_vulns"].extend(vulns["probable_vulns"])
                        self.exploits[domain]["possible_vulns"].extend(vulns["possible_vulns"])
                        self.domains[domain]["is_parsed"] = True

                        self.update_redis(data_about_domain)

            except Exception as e:
                self.logger.error(e)
                traceback.print_tb(e.__traceback__)
            
            if to_url or self.domains[domain]["is_parsed"]:
                if self.domains[domain]["is_parsed"]:
                    data_about_domain = self.domains.get(domain)["data"]
                self.myChecker.check_path(urlparse(url).path)
                self.exploits[domain]["possible_vulns"].extend(self.myChecker.get_all_vulns())
                self.domains[domain]["is_parsed"] = True
                self.update_redis(data_about_domain)
            self.myQueuer.parsed_url.append(url)
        


        self.exploits[domain]["possible_vulns"] = [item for item in self.exploits[domain]["possible_vulns"] if item not in ['true_vulns', 'almost_true', "probable_vulns", "possible_vulns"]]
        for domain in self.exploits.keys():
            self.logger.info(domain)
            self.logger.info("True Vulns")
            self.logger.info(list(set(self.exploits[domain]["true_vulns"])))
            self.logger.info("Almost true Vulns")
            self.logger.info(list(set(self.exploits[domain]["almost_true"])))
            self.logger.info("Probable Vulns")
            self.logger.info(list(set(self.exploits[domain]["probable_vulns"])))
            self.logger.info("Possible Vulns")
            self.logger.info(str(list(set(self.exploits[domain]["possible_vulns"]))))
            self.logger.info("Malware found")
            self.logger.info(list(set(self.exploits[domain]["malware"])))
        self.logger.info(self.domains)

    def update_redis(self, data_about_domain):
        exploits_full = self.myChecker.get_vulns_by_cms_and_plug()
        self.myRedis.update_redis_full(data_about_domain, exploits_full)
        exploits_just_cms = self.myChecker.get_vulns_by_cms()
        self.myRedis.update_redis_just_cms(data_about_domain, exploits_just_cms)

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
    crawler = Crawler(argv)
    crawler.logger.info(f'Starting urls are: {str(argv)}')
    crawler.crawl()