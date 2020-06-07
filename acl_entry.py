from enum import Enum, auto
from tcp_flags import tcp_flags

class acl_entry(object):
    """
    Describes an ACL row for the packet filter
    """

    def __init__(self):
        self.src_address=None
        self.dest_address=None
        self.protocol="TCP"
        self.src_port=0
        self.dest_port=0
        self.flag_bits=tcp_flags()
        self.check_conxion=True


    def __eq__(self, value):
        return (self.src_address == value.src_address and
               self.dest_address == value.dest_address and
               self.protocol == value.protocol and
               self.src_port == value.src_port and
               self.dest_port == value.dest_port and
               self.flag_bits == value.flag_bits and
               self.check_conxion == value.check_conxion)

    
    def __str__(self):  # Readable output
        return f"| {self.src_address}\t|\t{self.dest_address}\t|\t{self.src_port}\t|\t{self.dest_port}\t|\t{self.protocol}\t|\t{self.flag_bits}\t|\t{'X' if self.check_conxion else '-'}"