import os, importlib
import pkgutil

from .scraper import Scraper

scrapers = dict()


def add_scrapers():
    pkg_dir = os.path.dirname(__file__)

    for (module_loader, name, ispkg) in pkgutil.iter_modules([pkg_dir]):
        importlib.import_module('.' + name, __package__)

    for cls in Scraper.__subclasses__():
        if 'Metasploit' in cls.__name__:
            scrapers['.metasploit'] = cls
        else:
            for ext in cls().get_ext():
                scrapers[ext] = cls

    with open('/home/john/Desktop/scrapers', 'w+') as f:
        f.write(str(scrapers))
    return scrapers


add_scrapers()


