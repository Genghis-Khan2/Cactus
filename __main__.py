from argparse import ArgumentParser
import threading
import logging
from scapy.all import *
from packet_filter import packet_filter
from acl import acl
from conxion_table import conxion_table
from conxion_table_entry import conxion_table_entry
from acl_entry import acl_entry
from tcp_flags import tcp_flags, tcp_flags_type
from cactus_shell import cactus_shell


def parse_arguments():

    parser = ArgumentParser(description="Cactus Packet Filter")
    parser.add_argument("--reset", action="store_false", help="Reset the configuration file. Sets back to default")
    parser.add_argument("--altfile", metavar="Path", help="Alternate file to load configuration from")
    return parser.parse_args()


def main():
    args = parse_arguments()
    logging.basicConfig(filename='main.log', level=logging.INFO, filemode='w')


    entry = acl_entry()
    entry.src_port.single_port = 5012
    entry.flag_bits+=tcp_flags_type.ack
    entry.flag_bits+=tcp_flags_type.syn
    entry.flag_bits+=tcp_flags_type.rst
    entry.dest_port.single_port=80
    entry.dest_port.end_port = 96
    entry.src_address.single_address="192.168.1.1"
    entry.src_address.end_address = "192.168.1.3"
    entry.dest_address.single_address="192.168.10.1"
    entry.protocol="TCP"
    entry.check_conxion=False

    #print(entry.__dict__)

    entry2 = acl_entry()
    entry2.src_port.single_port = 5012
    entry2.flag_bits+=tcp_flags_type.syn
    entry2.flag_bits+=tcp_flags_type.fin
    entry2.dest_port.single_port=80
    entry2.src_address.single_address="10.0.0.1"
    entry2.dest_address.single_address="8.8.8.8"
    entry2.protocol="TCP"
    entry2.check_conxion=True
    acler = acl()
    acler.append(entry)
    acler.append(entry2)
   # print(acler)

    conx = conxion_table()
    con_entry = conxion_table_entry()
    con_entry.dest_port = 80
    con_entry.src_port = 14568
    con_entry.src_address = "192.168.1.3"
    con_entry.dest_address = "192.168.0.1"
    conx += con_entry
    #print(conx)
    filterer = packet_filter()
    filterer.acl = acler
    shell=cactus_shell()
    shell.packet_filter = filterer
    logging.info("Starting thread")
    threading.Thread(target=packet_filter.run, daemon=True)
    logging.info("Main: Thread running")
    shell.cmdloop()

if __name__=="__main__":
    main()