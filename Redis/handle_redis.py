from rejson import Client, Path
import uuid
import time

rj = Client(host='172.31.0.3', port=6379, decode_responses=True)

def create_key(infos, is_uuid=False):
    key = infos.get("cms") + '_' + infos.get("version") + '_' + generate_values(infos, "Plugins") + '_' + generate_values(infos, "Themes") \
        if is_uuid else infos.get("cms") + '_' + infos.get("version")

    return key[:-1] if key.endswith('_') else key
    
def generate_values(infos, place):
    key = ''
    data = infos.get(place)
    for keyy in data.keys():
        key = key + keyy + ':' + data.get(keyy) + '_'
    return key[:-1]


def update_redis_just_cms(infos, exploits):
    # Set the key `obj` to some object

    key = create_key(infos)
    obj = {
        "data": infos,
        "exploits": exploits
    }
    rj.jsonset(key, Path.rootPath(), obj)

def update_redis_full(infos, exploits):
    # Set the key `obj` to some object

    key = create_key(infos, True)
    obj = {
        "data": infos,
        "exploits": exploits
    }
    rj.jsonset(key, Path.rootPath(), obj)

def get_redis_just_cms(infos):

    return rj.jsonget(create_key(infos), Path('.exploits'))

def get_redis_full(infos):

    return rj.jsonget(create_key(infos, True), Path('.exploits'))

if __name__ == "__main__":
    infos = {
        
        "cms": "Drupal",
        "version": "7",
        "server": "Nginx",
        "Plugins": {"wp_cache": "4.2.1"},
        "Themes": {}
    }
    exploits = ["CVE_1234_2019", "33_EDB_VULN_TEST"]
    update_redis_full(infos, exploits)
    print('Redis full: ' + str(get_redis_full(infos)))
    infos = {
        
        "cms": "Drupal",
        "version": "7",
    }
    exploits = ["CVE_1234_2019"]
    update_redis_just_cms(infos, exploits)
    print('Redis just cms: ' + str(get_redis_just_cms(infos)))