import acl_entry

class acl(object):

    def __init__(self):
        self.__entries=[]
        self.whitelist=True

    
    def __contains__(self, key) :
        return key in self.__entries


    def append(self, object):
        if object not in self:  # We don't want duplicate entries
            self.__entries.append(object)

    
    def clear(self):
        self.__entries.clear()


    def remove(self, value):
        self.__entries.remove(value)


    def __str__(self):
        output_string=""
        output_string += "-"*125+'\n'
        output_string+="Action\t|\tSource Address\t|\tDest. Address\t|\tSource Port   | Dest. Port | Protocol | Flag Bits | Check Connection\n"
        for entry in self.__entries:
            output_string += "Allow" if self.whitelist else "Deny"
            output_string += str(entry)+"\n"
            output_string += "-"*125+"\n"
        return output_string
