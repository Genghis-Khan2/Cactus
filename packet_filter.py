from acl import acl
from conxion_table import conxion_table
from scapy.all import *
from threading import Lock

class packet_filter(object):

    def __init__(self):
        self.__acl = acl()
        self.__conxion_table=conxion_table()
        self.__enabled=True
        self.__interfaces=[]


#region Properties
    @property
    def acl(self):
        return self.__acl

    @acl.setter
    def acl(self, value):
        self.__acl = value


    @property
    def enabled(self):
        return self.__enabled


    @enabled.setter
    def enabled(self, value):
        self.__enabled = value


    @property
    def interfaces(self):
        return self.__interfaces


    @interfaces.setter
    def interfaces(self, value):
        self.__interfaces = value


    @property
    def conxion_table(self):
        return self.__conxion_table
#endregion


    def filtering(self, packet):
        self.acl.lock.acquire()
        if self.enabled:
            if (UDP in packet or TCP in packet) and IP in packet:
                acl_indices=[i for i, x in enumerate(self.acl.src_addresses) if packet[IP].src in x]
                conxion_indices = [i for i, x in enumerate(self.conxion_table.src_addresses) if x == packet[IP].src]
                for acl_index in acl_indices:
                    if self.acl[acl_index].satisfied_by(packet):
                        if not self.acl[acl_index].check_conxion:
                            return True
                        else:
                            for conxion_index in conxion_indices:
                                if self.conxion_table[conxion_index].satisfied_by(packet):
                                    return True

            return False
        return True


    def filter_function(self, packet):
        result = self.filtering(packet)
        self.acl.lock.release()
        if result:
            send(packet, iface="enp0s3", verbose=0)
            logging.critical(f"Accepted:\n {packet.show(dump=True)}")
        return result


    def run(self):
        logging.info("Filtering started")
        while len(self.interfaces) == 0:
            pass
        sniff(count=0, lfilter=self.filter_function, iface=self.interfaces)