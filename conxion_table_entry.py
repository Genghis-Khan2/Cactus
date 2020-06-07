class conxion_table_entry(object):

    def __init__(self):
        self.__src_address=None
        self.__dest_address=None
        self.__src_port=0
        self.__dest_port=0

#region Properties
#region src_address property
    @property
    def src_address(self):
        return self.__src_address


    @src_address.setter
    def src_address(self, value):
        self.__src_address = value
#endregion
#region dest_address property
    @property
    def dest_address(self):
        return self.__dest_address


    @dest_address.setter
    def dest_address(self, value):
        self.__dest_address = value
#endregion
#region src_port property
    @property
    def src_port(self):
        return self.__src_port


    @src_port.setter
    def src_port(self, value):
        self.__src_port = value
#endregion
#region dest_port property
    @property
    def dest_port(self):
        return self.__dest_port


    @dest_port.setter
    def dest_port(self, value):
        self.__dest_port = value
#endregion
#endregion

    
    def __eq__(self, value):
        return (self.src_address == value.src_address and
               self.dest_address == value.dest_address and
               self.src_port == value.src_port and
               self.dest_port == value.dest_port)


    def __str__(self):
        return (f"| {self.src_address}\t|\t{self.dest_address}\t|\t{self.src_port}\t|\t{self.dest_port}")