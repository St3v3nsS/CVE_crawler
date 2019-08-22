class Queuer(object):
    def __init__(self, url_list):
        self.url_list = url_list
    
    def pop(self):
        return self.url_list.pop()
    
    def push(self, list_to_push):
        self.url_list.extend(list_to_push)

    def empty(self):
        return True if len(self.url_list) == 0 else False
