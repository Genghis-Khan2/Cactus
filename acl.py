from acl_entry import acl_entry
from tcp_flags import tcp_flags_type

#region ACL 

class acl(object):

    def __init__(self):
        self.__entries=[]
        self.__whitelist=True


#region whitelist property
    @property
    def whitelist(self):
        return self.__whitelist


    @whitelist.setter
    def whitelist(self, value):
        self.__whitelist = value
#endregion

    
    def __contains__(self, key) :
        return key in self.__entries


    def append(self, object):
        if object not in self:  # We don't want duplicate entries
            self.__entries.append(object)

    
    def __iadd__(self, object):
        self.append(object)
        return self

    
    def clear(self):
        self.__entries.clear()


    def remove(self, value):
        self.__entries.remove(value)


    def __str__(self):
        output_string=""
        output_string += "-"*125+'\n'
        output_string+="Action\t|\tSource Address\t|\tDest. Address\t|\tSource Port   | Dest. Port | Protocol | Flag Bits | Check Connection\n"
        output_string += "-"*125+'\n'
        for entry in self.__entries:
            output_string += "Allow\t" if self.whitelist else "Deny\t"
            output_string += str(entry)+"\n"
            output_string += "-"*125+"\n"
        output_string += f"{'Deny' if self.whitelist else 'Allow'}\t|\tAll\t|\tAll\t|\tAll\t|\tAll\t|\tAll\t|\tAll\t|\t~"
        output_string += "\n" * 3
        return output_string
#endregion

#TODO: Create JSON serializer for ACL and for connection table