from argparse import ArgumentParser
import threading
from scapy.all import *
from packet_filter import packet_filter
from acl import acl
from conxion_table import conxion_table
from conxion_table_entry import conxion_table_entry
from acl_entry import acl_entry
from tcp_flags import tcp_flags, tcp_flags_type
from cactus_shell import cactus_shell
import dal


def parse_arguments():

    parser = ArgumentParser(description="Cactus Packet Filter")
    parser.add_argument("--reset", action="store_false", help="Reset the configuration file. Sets back to default")
    parser.add_argument("--altfile", metavar="Path", help="Alternate file to load configuration from")
    return parser.parse_args()


def main():
    args = parse_arguments()
    logging.basicConfig(filename='main.log', level=logging.INFO, filemode='w')

    filterer = packet_filter()
    entry=acl_entry()
    entry.dest_address="192.168.0.1"
    entry.src_address="10.1.1.1"
    entry.src_port=80
    entry.dest_port=(80, 96)
    entry.flag_bits+=tcp_flags_type.syn
    entry.flag_bits+=tcp_flags_type.ack

    entry2 = acl_entry()
    entry2.dest_address="192.168.155.32"
    entry2.src_address="10.1.1.1"
    entry2.src_port=112
    entry2.dest_port=(80, 96)
    entry2.flag_bits+=tcp_flags_type.syn
    entry2.flag_bits+=tcp_flags_type.fin
    entry2.check_conxion=False

    filterer.acl+=entry
    filterer.acl += entry2
    
    shell=cactus_shell(filterer)
    logging.info("Starting thread")
    threading.Thread(target=packet_filter.run, daemon=True)  # TODO: Solve race condition. Should be solved. Keep an eye out
    logging.info("Main: Thread running")
    shell.cmdloop()

if __name__=="__main__":
    main()