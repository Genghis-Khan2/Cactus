import acl
import conxion_table

class packet_filter(object):

    def __init__(self):
        self.__acl = acl()
        self.__conxion_table=conxion_table()