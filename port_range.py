import custom_exceptions

class port_range(object):

    def __init__(self):
        self.__start_port=0
        self.__end_port=0


    def copy(self):
        copy = port_range()
        copy.tuple_port = self.tuple_port
        return copy


#region start_port property
    @property
    def start_port(self):
        return self.__start_port


    @start_port.setter
    def start_port(self, value):
        if 0 <= value <= 65535:
            self.__start_port = value
        else:
            raise custom_exceptions.InvalidPortError()
#endregion
#region end_port property
    @property
    def end_port(self):
        return self.__end_port


    @end_port.setter
    def end_port(self, value):
        if 0 <= value <= 65535:
            self.__end_port = value
        else:
            raise custom_exceptions.InvalidPortError()
#endregion
#region single_port property    
    @property
    def single_port(self):
        return self.start_port if self.start_port == self.end_port else None

    
    @single_port.setter
    def single_port(self, value):
        self.start_port = self.end_port = value
#endregion
#region tuple_port property
    @property
    def tuple_port(self):
        return (self.start_port, self.end_port)


    @tuple_port.setter
    def tuple_port(self, value):
        self.start_port, self.end_port = value
#endregion


    def __str__(self):
        return str(self.single_port) if self.single_port else f"{self.start_port} - {self.end_port}"


    def __contains__(self, port):
        return self.start_port <= port <= self.end_port


    def __equ__(self, value):
        return isinstance(value, port_range) and self.tuple_port == value.tuple_port