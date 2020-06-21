import json
import encoders
import decoders
import os
from packet_filter import packet_filter


config_file_path = "config.json"


class dal(object):
    def __init__(self, path="config.json"):
        self.__path = path
        self.__file = open(self.__path, "r+")

    def __del__(self):
        self.__file.close()

    
    @property
    def path(self):
        return self.__path


    @path.setter
    def path(self, value):
        self.__path = value
        self.__file.close()
        self.__file = open(self.__path, "r+")


    @property
    def fileprop(self):
        return self.__file


    def write_packet_filter(self, acl):
        #with open(config_file_path, "a") as f:
        json.dump(acl, self.fileprop, cls=encoders.packet_filter_encoder, indent=4)


    def read_packet_filter(self):
        #with open(config_file_path, "r") as f:
        if not os.path.isfile(config_file_path):
            return packet_filter()
        return json.load(self.fileprop, cls=decoders.packet_filter_decoder)