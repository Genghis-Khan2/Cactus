from parse import parse, compile
from json import JSONEncoder
import socket

#region ip_address_range
class ip_address_range(object):

    def __init__(self):
        self.__start_address="0.0.0.0"
        self.__end_address="0.0.0.0"


    def copy(self):
        copy = ip_address_range()
        copy.tuple_address = self.tuple_address
        return copy


#region start_address property
    @property
    def start_address(self):
        return self.__start_address


    @start_address.setter
    def start_address(self, value):
        try:
            socket.inet_aton(value)
            self.__start_address = value
        except socket.error:
            raise InvalidIP
#endregion
#region end_address property
    @property
    def end_address(self):
        return self.__end_address


    @end_address.setter
    def end_address(self, value):
        #TODO: Check properly for ip address structure
        self.__end_address=value
#endregion
#region single_address property
    @property
    def single_address(self):
        return self.start_address if self.start_address == self.end_address else None


    @single_address.setter
    def single_address(self, value):
        self.start_address = self.end_address = value
#endregion
#region tuple_address property
    @property
    def tuple_address(self):
        return (self.start_address, self.end_address)


    @tuple_address.setter
    def tuple_address(self, value):
        #TODO: Make validity check
        self.start_address, self.end_address = value
#endregion

    def __contains__(self, address):
        p = compile("{a}.{b}.{c}.{d}")

        result = p.parse(self.end_address)
        end_1 = result['a']
        end_2 = result['b']
        end_3 = result['c']
        end_4 = result['d']

        result = p.parse(self.start_address)
        start_1 = result['a']
        start_2 = result['b']
        start_3 = result['c']
        start_4 = result['d']

        result = p.parse(self.address)
        address_1 = result['a']
        address_2 = result['b']
        address_3 = result['c']
        address_4 = result['d']

        return (start_1<=address_1<=end_1 and
            start_2 <= address_2<=end_2 and
            start_3 <= address_3 <= end_3 and
            start_4 <= address_4 <= end_4)

    
    def __str__(self):
        return (self.single_address 
            if self.single_address 
            else f"{self.start_address} - {self.end_address}")
#endregion
#TODO: Create serializer