from acl import acl
from scapy.all import *
from threading import Lock

class packet_filter(object):

    def __init__(self):
        self.__acl = acl()
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


#endregion


    def filtering(self, packet):
        self.acl.lock.acquire()
        if self.enabled:
            if (UDP in packet or TCP in packet) and IP in packet:
                acl_indices=[i for i, x in enumerate(self.acl.src_addresses) if packet[IP].src in x]
                for acl_index in acl_indices:
                    if self.acl[acl_index].satisfied_by(packet):
                        return True

            return False
        return True


    def filter_function(self, packet):
        if IP in packet:
            if self.on_same_subnet(packet):
                print("Here")
                forward_packet = packet[Ether].payload
                send(forward_packet, iface="enp0s8", verbose=0)
                logging.critical(f"Accepted:\n {packet.show(dump=True)}")
                return True
            result = self.filtering(packet)
            self.acl.lock.release()
            if result:
                forward_packet = packet[Ether].payload
                send(forward_packet, iface="enp0s3", verbose=0)
                logging.critical(f"Accepted:\n {packet.show(dump=True)}")
            return result
        return False


    def on_same_subnet(self, packet):
        print("Here")
        return packet[IP].src.split(".")[:3] == ["10"]*3


    def run(self):
        logging.info("Filtering started")
        while len(self.interfaces) == 0:
            pass
        sniff(count=0, lfilter=self.filter_function, iface=self.interfaces)