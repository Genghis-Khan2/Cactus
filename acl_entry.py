from enum import Enum, auto
from tcp_flags import tcp_flags
from ip_address_range import ip_address_range
from port_range import port_range
from scapy.all import *

class acl_entry(object):
    """
    Describes an ACL row for the packet filter
    """

    def __init__(self):
        self.__src_address=ip_address_range()
        self.__dest_address=ip_address_range()
        self.__protocol="TCP"
        self.__src_port=port_range()
        self.__dest_port=port_range()
        self.__flag_bits=tcp_flags()
        self.__check_conxion=True


    def copy(self):
        entry=acl_entry()
        entry.check_conxion = self.check_conxion
        entry.flag_bits = self.flag_bits.copy()
        entry.__src_port = self.src_port.copy()
        entry.__dest_port=self.dest_port.copy()
        entry.__src_address=self.src_address.copy()
        entry.__dest_address=self.dest_address.copy()
        entry.protocol = self.protocol
        return entry

#region Properties
#region src_address property

    @property
    def src_address(self):
        return self.__src_address


    @src_address.setter
    def src_address(self, value):
        if isinstance(value, tuple):
            self.__src_address.tuple_address = value
        else:
            self.__src_address.single_address = value
#endregion
#region dest_address property
    @property
    def dest_address(self):
        return self.__dest_address


    @dest_address.setter
    def dest_address(self, value):
        if isinstance(value, tuple):
            self.__dest_address.tuple_address = value
        else:
            self.__dest_address.single_address = value
#endregion
#region protocol property
    @property
    def protocol(self):
        return self.__protocol


    @protocol.setter
    def protocol(self, value):
        if value == "TCP" or value == "UDP":
            self.__protocol = value
        else:
            pass  #TODO: Throw exception
#endregion
#region src_port property
    @property
    def src_port(self):
        return self.__src_port


    @src_port.setter
    def src_port(self, value):
        if isinstance(value, tuple):
            self.__src_port.tuple_port = (int(value[0]), int(value[1]))
        else:
            self.__src_port.single_port = int(value)
#endregion
#region dest_port property
    @property
    def dest_port(self):
        return self.__dest_port


    @dest_port.setter
    def dest_port(self, value):
        if isinstance(value, tuple):
            self.__dest_port.tuple_port = (int(value[0]), int(value[1]))
        else:
            self.__dest_port.single_port = int(value)
#endregion
#region flag_bits property
    @property
    def flag_bits(self):
        return self.__flag_bits


    @flag_bits.setter
    def flag_bits(self, value):
        self.__flag_bits = value
#endregion
#region check_conxion property
    @property
    def check_conxion(self):
        return self.__check_conxion


    @check_conxion.setter
    def check_conxion(self, value):
        self.__check_conxion = value
#endregion
#endregion

    def __eq__(self, value):
        #TODO: Create __eq__ for ip_range and port_range
        return (self.src_address == value.src_address and
               self.dest_address == value.dest_address and
               self.protocol == value.protocol and
               self.src_port == value.src_port and
               self.dest_port == value.dest_port and
               self.flag_bits == value.flag_bits and
               self.check_conxion == value.check_conxion)


    def satisfied_by(self, packet):
        return (packet.src in self.src_address and
            packet.dst in self.dest_address and
            packet.sport in self.src_port and
            packet.dport in self.dest_port and
            packet.proto.upper() == self.protocol
            ) #TODO: Check flag bits

    
    def __str__(self):  # Readable output
        return f"| {self.src_address}\t|\t{self.dest_address}\t|\t{self.src_port}\t|\t{self.dest_port}\t|\t{self.protocol}\t|\t{self.flag_bits}\t|\t{'X' if self.check_conxion else '-'}"