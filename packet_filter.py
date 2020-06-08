from acl import acl
from conxion_table import conxion_table
from scapy.all import *

class packet_filter(object):

    def __init__(self):
        self.__acl = acl()
        self.__conxion_table=conxion_table()


    @property
    def acl(self):
        return self.__acl


    @property
    def conxion_table(self):
        return self.__conxion_table


    def filter_function(self, packet):
        if (UDP in packet or TCP in packet) and IP in packet:
            indices = [i for i, x in enumerate(my_list) if x == packet.src]  # List comprehension to get all the indices of entries who's source matches the packet source
            if len(indices) != 0:
                for index in indices:
                    if self.acl[index].satisfied_by(packet)):
                        #TODO: Send the packet through
                        return True 
        return False

    def run(self):
        sniff(count=0, lfilter=self.filter_function)