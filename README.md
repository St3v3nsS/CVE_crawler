# CVE Crawler

A CVE Crawler for finding vulnerabilities in servers and detecting malware executables in a passive way.

## Dependencies

* [Docker](https://www.docker.com/products/docker-desktop)
* [Docker-compose](https://github.com/docker/compose)

## Installation

Go to project root folder, where docker-compose.yml is located, and then run ```docker-compose up -d --build && docker-compose logs -f```. This will bring up all the containers and then logs everything.

## Usage

There are seven main components or containers:

* API Calls
* Crawler
* Scraper
* Malware Detection system
* Redis
* MongoDB
* Vulnerable server

By typing ```docker ps -a``` you will find details about those containers.

The Scraper will take every exploit from [Exploit-DB](https://www.exploit-db.com/) and will populate the mongoDB database with exploits informations like *Name, Description, Vulnerability, URLs*. 
```docker container exec -it scraper bash``` for entering in the container.

The Crawler will take every URL you gave and will start looking at the files and extracting information like *CMS, Server, Plugins/Modules, Themes* and start matching with the exploit information extracted with Scraper. ```docker container exec -it crawler bash``` is the docker command. 

For finding specific vulnerability details, use one of the following scripts inside the ```api``` container:

* get_vulns_by_cve.py
* get_vulns_by_date.py
* get_vulns_by_path.py
* get_vulns_by_platform.py
* get_vulns_by_type.py

If you want to look in the database, just type in ```docker container exec -it mongodb bash```. Now, inside the container run ```mongo -u john -p -authenticationDatabase exploits``` with password ```pass```.

Redis is used for caching server extracted information for speed up the process of finding exploits. Inside the docker container, run ```redis-cli``` and then ```KEYS '*'``` will show all the keys stored.

The ML model is used by Crawler to determine if a blacklisted file is malware or not. The dataset used contains almost 200,000 encoded PE, legit and malware and the model has an average accuracy of 97%. 

For testing, use the vulnerable server provided. 

## TODO

- [ ] Better description extraction
- [ ] Better extraction of server informations
- [ ] Optimizations
- [ ] More CVE databases, maybe Mitre

## License

[MIT](https://choosealicense.com/licenses/mit/)
