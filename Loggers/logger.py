import logging

loggers = {}

def myLogger(name):
    global loggers

    if loggers.get(name):
        return loggers.get(name)
    logging.basicConfig(
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            level=logging.INFO)
    logger = logging.getLogger(name)
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    logger.propagate = False
    loggers[name] = logger

    return logger