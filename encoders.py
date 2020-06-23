import json

from acl import acl
from acl_entry import acl_entry
from ip_address_range import ip_address_range
from packet_filter import packet_filter
from port_range import port_range
from tcp_flags import tcp_flags


class ip_address_range_encoder(json.JSONEncoder):
    def default(self, ip_range):
        if isinstance(ip_range, ip_address_range):
            return {"start_address":ip_range.start_address, "end_address":ip_range.end_address}
        return super(ip_address_range_encoder, self).default(obj)


class port_range_encoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, port_range):
            return {"start_port": obj.start_port, "end_port": obj.end_port}
        return super(port_range_encoder, self).default(obj)


class tcp_flags_encoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, tcp_flags):
            return str(obj)
        return super(tcp_flags_encoder, self).default(obj)


class acl_entry_encoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, acl_entry):
            ip_range = ip_address_range_encoder()
            port_range = port_range_encoder()
            tcp_flags = tcp_flags_encoder()
            a={
                "src_address": ip_range.default(obj.src_address),
                "dest_address": ip_range.default(obj.dest_address),
                "src_port": port_range.default(obj.src_port),
                "dest_port": port_range.default(obj.dest_port),
                "protocol": obj.protocol,
                "tcp_flags": tcp_flags.default(obj.flag_bits),
            }
            return a
            
        return super(acl_entry_encoder, self).default(obj)


class acl_encoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, acl):
            encoder = acl_entry_encoder()
            a = {
            "entries": [encoder.default(entry) for entry in obj.entries],
            "whitelist": obj.whitelist
            }

            return a
        return super(acl_encoder, self).default(obj)


class packet_filter_encoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, packet_filter):
            encoder = acl_encoder()
            a = {
            "acl": encoder.default(obj.acl),
            "enabled": obj.enabled,
            "interfaces": obj.interfaces
            }

            return a
        return super(packet_filter_encoder, self).default(obj)