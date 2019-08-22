import requests
from script1 import extract
from Queuer import Queuer
import time

myQueuer = Queuer(['https://wordpress.com/sitemap.xml'])
while(not myQueuer.empty()):
    resp = requests.get(myQueuer.pop(), headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36'})
    print(resp.headers)
    response = extract(resp.content)
    myQueuer.push(response)
    
    time.sleep(10)
