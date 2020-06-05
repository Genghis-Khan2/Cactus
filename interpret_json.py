import json

class packet_filter(object):

    def __init__(self):
        with open("criteria.json", "r") as json_file:
            json_object = json.load(json_file)
            self.whitelist_src = json_object["packet_filter"]["whitelisting_src"]
            self.whitelist_dest = json_object["packet_filter"]["whitelisting_dest"]
            self.src_whitelisted_ips = json_object["packet_filter"]["whitelist"]["dst"]["whitelisted_ips"]