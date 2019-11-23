# CVE Crawler

A CVE Crawler for finding vulnerabilities in servers.

## Dependencies

* [MongoDB](https://www.mongodb.com/)
* [Python3](https://www.python.org/download/releases/3.0/)

## Installation

Just instal mongoDB and Python3 with following dependencies:

* re
* regex
* progressbar
* tqdm
* selectolax
* pymongo

## Usage

Open a terminal, run ```mongod``` then open another terminal and run ```python3 update_exploits.py download_path_of_archive extarction_path_of_archive```. E.g ```python3 update_exploits.py /home/john/CVE_crawler/my_file.zip /home/john/CVE_crawler/exploitdb/```. This will populate the mongoDB database with exploits informations like *Name, Description, Vulnerability, URLs*. 

For finding the vulnerabilities in a server, type ```python3 pyscript.py url```. E.g ```python3 pyscript.url http://localhost:8081/index.html```.

For finding specific vulnerability details, use one of the following scripts:

* get_vulns_by_cve.py
* get_vulns_by_date.py
* get_vulns_by_path.py
* get_vulns_by_platform.py
* get_vulns_by_type.py

## TODO

- [ ] Malware Detection using ML
- [ ] Better description extraction
- [ ] Better extraction of server informations

## License

[MIT](https://choosealicense.com/licenses/mit/)
