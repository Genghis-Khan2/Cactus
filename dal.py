import json
import encoders
import decoders
import os
from packet_filter import packet_filter


config_file_path = "config.json"


class dal(object):
    def __init__(self, path=config_file_path):
        self.__path = path
        if not os.path.isfile(self.__path):
            self.__file = open(self.__path, "w+")
        else:
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

        json.dump(acl, self.fileprop, cls=encoders.packet_filter_encoder, indent=4)


    def read_packet_filter(self):

        if not os.path.isfile(config_file_path) or os.stat(self.path).st_size == 0:
            return packet_filter()
        return json.load(self.fileprop, cls=decoders.packet_filter_decoder)