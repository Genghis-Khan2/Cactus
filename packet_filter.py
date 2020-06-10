from acl import acl
from conxion_table import conxion_table
from scapy.all import *
from __main__ import logger
class packet_filter(object):

    def __init__(self):
        self.__acl = acl()
        self.__conxion_table=conxion_table()


#region Properties
    @property
    def acl(self):
        return self.__acl

    @acl.setter
    def acl(self, value):
        self.__acl = value


    @property
    def conxion_table(self):
        return self.__conxion_table
#endregion


    def filter_function(self, packet):
        self.acl.lock.acquire()
        logger.info("Filterering")
        if (UDP in packet or TCP in packet) and IP in packet:
            acl_indices = [i for i, x in enumerate(self.acl.src_addresses) if x == packet.src]  # List comprehension to get all the acl_indices of entries who's source matches the packet source
            conxion_indices = [i for i, x in enumerate(self.conxion_table.src_addresses) if x == packet.src]
            for acl_index in acl_indices:
                if self.acl[acl_index].satisfied_by(packet):
                    if not self.acl[acl_index].check_conxion:
                        send(packet)
                        self.acl.lock.release()
                        return True
                    else:
                        for conxion_index in conxion_indices:
                            if self.conxion_table[conxion_index].satisfied_by(packet):
                                send(packet)
                                self.acl.lock.release()
                                return True
        self.acl.lock.release()
        return False

    def run(self):
        logger.info("Filtering started")
        sniff(count=0, lfilter=self.filter_function)