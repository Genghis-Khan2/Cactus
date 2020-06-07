from enum import Enum, auto
from InvalidFlag import InvalidFlagError
from collections import Counter
class tcp_flags(object):

    def __init__(self):
        self.__list=[]


    def append(self, flag):
        if isinstance(flag, tcp_flags_type) and flag not in self:
            self.__list.append(flag)
        else:
            raise InvalidFlagError("Attempt to append non TCP-flag types")

    
    def remove(self, flag):
        if isinstance(flag, tcp_flags):
            self.__list.remove(flag)
        raise InvalidFlagError("Attempt to remove non TCP-flag type")

    def __eq__(self, value):
        if isinstance(value, tcp_flags_type):
            return Counter(self.__list) == Counter(value.__list)
        raise InvalidFlagError("Attempt to check for equality with non TCP-flag type")


    def __contains__(self, key):
        if isinstance(key, tcp_flags_type):
            return key in self.__list
        raise InvalidFlagError("Attempt to check if non TCP-flag type is contained")


    def __str__(self):
        output_string = ""
        output_string += "S" if tcp_flags_type.syn in self.__list else ""
        output_string += "A" if tcp_flags_type.ack in self.__list else ""
        output_string += "F" if tcp_flags_type.fin in self.__list else ""
        output_string += "R" if tcp_flags_type.rst in self.__list else ""
        output_string += "P" if tcp_flags_type.psh in self.__list else ""
        output_string += "U" if tcp_flags_type.urg in self.__list else ""
        return output_string

    

class tcp_flags_type(Enum):
    fin=auto()
    rst=auto()
    ack=auto()
    psh=auto()
    urg=auto()
    syn=auto()