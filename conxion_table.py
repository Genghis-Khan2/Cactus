import conxion_table_entry
from threading import Lock
import time

class conxion_table(object):

    def __init__(self):
        self.__list=[]
        self.__lock = Lock()


    @property
    def src_addresses(self):
        return [entry.src_address for entry in self.__list]


    @property
    def lock(self):
        return self.__lock


    def __getitem__(self, key):
        return self.__list[key]

    
    def __contains__(self, key) :
        return key in self.__list


    def append(self, object):
        if object not in self:  # We don't want duplicate entries
            self.__list.append(object)

    
    def __iadd__(self, object):
        self.append(object)
        return self

    
    def clear(self):
        self.__list.clear()


    def remove(self, value):
        self.__list.remove(value)


    def clear(self):
        self.__list.clear()


    def run(self):
        self.lock.acquire()
        time.sleep(60)
        self.clear()
        self.lock.release()


    def __str__(self):
        output_string=""
        output_string += "-"*75+'\n'
        output_string+="Source Address\t|\tDest. Address\t|\tSource Port   | Dest. Port\n"
        output_string += "-"*75+'\n'
        for entry in self.__list:
            output_string += str(entry)+"\n"
            output_string += "-"*75+"\n"
        output_string += "\n"*3
        return output_string 