import json

from acl import acl
from acl_entry import acl_entry
from ip_address_range import ip_address_range
from packet_filter import packet_filter
from port_range import port_range
from tcp_flags import tcp_flags, tcp_flags_type


class ip_address_range_decoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs)


    def object_hook(self, dct):
        if "start_address" not in dct:
            return dct
        ip_range = ip_address_range()
        ip_range.start_address = dct['start_address']
        ip_range.end_address = dct['end_address']
        return ip_range


class port_range_decoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs)


    def object_hook(self, dct):
        if "start_port" not in dct:
            return dct
        ret = port_range()
        ret.start_port = dct['start_port']
        ret.end_port = dct['end_port']
        return ret


class acl_entry_decoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs)


    def object_hook(self, dct):
        if "src_address" not in dct:
            return dct
        entry = acl_entry()
        ip_decoder = ip_address_range_decoder()
        port_decoder = port_range_decoder()
        entry.src_address = ip_decoder.object_hook(dct['src_address'])
        entry.dest_address = ip_decoder.object_hook(dct['dest_address'])
        entry.src_port = port_decoder.object_hook(dct['src_port'])
        entry.dest_port = port_decoder.object_hook(dct['dest_port'])
        entry.protocol = dct['protocol']
        entry.check_conxion = dct['check_conxion']
        string = dct['tcp_flags']
        if 'A' in string:
            entry.flag_bits += tcp_flags_type.ack
        if 'S' in string:
            entry.flag_bits += tcp_flags_type.syn
        if 'U' in string:
            entry.flag_bits += tcp_flags_type.urg
        if 'R' in string:
            entry.flag_bits += tcp_flags_type.rst
        if 'F' in string:
            entry.flag_bits += tcp_flags_type.fin
        if 'P' in string:
            entry.flag_bits += tcp_flags_type.psh
        return entry


class acl_decoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs)


    def object_hook(self, dct):
        if "entries" not in dct:
            return dct
        ret = acl()
        entry_decoder = acl_entry_decoder()
        for entry in dct['entries']:
            ret += entry_decoder.object_hook(entry)
        ret.whitelist = dct['whitelist']

        return ret

class packet_filter_decoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs)
    

    def object_hook(self, dct):
        if "acl" not in dct:
            return dct
        filterer = packet_filter()
        decoder = acl_decoder()
        filterer.acl = decoder.object_hook(dct['acl'])
        filterer.enabled = dct['enabled']
        filterer.interfaces = [iface for iface in dct['interfaces']]

        return filterer
