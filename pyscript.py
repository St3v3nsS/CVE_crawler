import requests
from script1 import extract
from check_path import check
from Queuer import Queuer
from urllib.parse import urlparse
import time

myQueuer = Queuer(['http://localhost:8080/urls.html'])
while(not myQueuer.empty()):
    url = myQueuer.pop()
    resp = requests.get(url, headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36'})
    print(resp.headers)
    print(check(urlparse(url).path))
    response = extract(resp.content)
    myQueuer.push(response)
    time.sleep(3)