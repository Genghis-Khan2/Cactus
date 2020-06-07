class conxion_table_entry(object):

    def __init__(self):
        self.src_address=None
        self.dest_address=None
        self.src_port=0
        self.dest_port=0

    
    def __eq__(self, value):
        return (self.src_address == value.src_address and
               self.dest_address == value.dest_address and
               self.src_port == value.src_port and
               self.dest_port == value.dest_port)