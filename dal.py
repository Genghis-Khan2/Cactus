import json
import encoders


config_file_path = "config.json"


class dal(object):
    def __init__(self, path="config.json"):
        self.__path = path
        self.__file = open(self.__path, "r+")

    def __del__(self):
        self.__file.close()


def write_ip_address_range(ip_address_range):
    with open(config_file_path, "a") as f:
        json.dump(ip_address_range, f, cls=encoders.ip_address_range_encoder, indent=4)


def write_port_range(port_range):
    with open(config_file_path, "a") as f:
        json.dump(port_range, f, cls=encoders.port_range_encoder, indent=4)


def write_acl_entry(entry):
    with open(config_file_path, "a") as f:
        json.dump(entry, f, cls=encoders.acl_entry_encoder, indent=4)


def write_acl(acl):
    with open(config_file_path, "a") as f:
        json.dump(acl, f, cls=encoders.acl_encoder, indent=4)


def write_packet_filter(acl):
    with open(config_file_path, "a") as f:
        json.dump(acl, f, cls=encoders.packet_filter_encoder, indent=4)