import json
import sys

def read_cfg(name):
    with open('/home/john/Project/CVE_crawler/Configs/config.json') as configfile:
        cfg = json.load(configfile)
    return cfg[name]