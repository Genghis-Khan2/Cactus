import conxion_table_entry

class conxion_table(object):

    def __init__(self):
        self.__list=[]

    
    def __contains__(self, key) :
        return key in self.__list


    def append(self, object):
        if object not in self:  # We don't want duplicate entries
            self.__list.append(object)

    
    def clear(self):
        self.__list.clear()


    def remove(self, value):
        self.__list.remove(value)