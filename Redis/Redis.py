from rejson import Client, Path
import time
import sys
sys.path.append('/home/john/Project/CVE_crawler/')
from Configs.read_cfg import read_cfg
from Loggers import logger
from json import JSONDecoder


class RedisJsonDecoder(JSONDecoder):
    def decode(self, s, *args, **kwargs):
        if isinstance(s, bytes):
            s = s.decode('UTF-8')
        return super(RedisJsonDecoder, self).decode(s, *args, **kwargs)

class Redis(object):
    def __init__(self):
        self.cfg = read_cfg("redis")
        self.rj = Client(host=self.cfg.get("ip"), port=self.cfg.get("port"), decoder=RedisJsonDecoder(), decode_responses=True)
        self.logger = logger.myLogger("Redis")

    def create_key(self, infos, is_uuid=False):
        key = infos.get("cms") + '_' + infos.get("version") + '_' + self.generate_values(infos, "Plugins") + '_' + self.generate_values(infos, "Themes") \
            if is_uuid else infos.get("cms") + '_' + infos.get("version")
        self.logger.warn(f"Key: {str(key)}")

        return key[:-1] if key.endswith('_') else key
        
    def generate_values(self, infos, place):
        key = ''
        data = infos.get(place)
        for keyy in data.keys():
            key = key + keyy + ':' + data.get(keyy) + '_'
        return key[:-1]

    def update_redis_just_cms(self, infos, exploits):
        key = self.create_key(infos)
        obj = {
            "data": infos,
            "exploits": exploits if exploits else {}
        }
        self.rj.jsonset(key, Path.rootPath(), obj)
        self.logger.info(f"Inserted {key} just cms...")

    def update_redis_full(self, infos, exploits):

        key = self.create_key(infos, True)
        obj = {
            "data": infos,
            "exploits": exploits if exploits else {}
        }
        self.rj.jsonset(key, Path.rootPath(), obj)
        self.logger.info(f"Inserted full {key}...")

    def get_redis_just_cms(self, infos):
        key = self.create_key(infos)
        self.logger.info(f"Getting just cms {key}...")
        return self.rj.jsonget(key, Path(self.cfg.get("path")))

    def get_redis_full(self, infos):
        key = self.create_key(infos, True)
        self.logger.info(f"Getting full cms {key}...")
        self.logger.warn(f"FULL REDIS {self.rj.jsonget(key, Path.rootPath())}")

        return self.rj.jsonget(key, Path(self.cfg.get("path")))

    def get_rj(self):
        return self.rj

if __name__ == "__main__":
    infos = {
        
        "cms": "Drupal",
        "version": "7",
        "server": "Nginx",
        "Plugins": {"wp_cache": "4.2.1"},
        "Themes": {}
    }
    exploits = ["CVE_1234_2019", "33_EDB_VULN_TEST"]
    redis = Redis()
    redis.update_redis_full(infos, exploits)
    print('Redis full: ' + str(redis.get_redis_full(infos)))
    infos = {
        
        "cms": "Drupal",
        "version": "7",
    }
    exploits = ["CVE_1234_2019"]
    redis.update_redis_just_cms(infos, exploits)
    print('Redis just cms: ' + str(redis.get_redis_just_cms(infos)))