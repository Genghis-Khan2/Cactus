from argparse import ArgumentParser
import cmd
import threading
import logging
import time
from scapy.all import *
import interpret_json


def log_packet(packet):
    #logging.info(f'Received packet from {}')
    pass

def packet_filter_action():
    logging.info('Packet filter running')
    #sniff(prn=)


def main():


    parser = ArgumentParser(description="A python packet filter and application proxy")

    parser.add_argument("--noconfig", action="store_true", help="Don't use an existing file to setup the packet filter")
    parser.add_argument("--altfile", metavar="path", help="Use an alternate setup file")

    subnet_or_single_group = parser.add_mutually_exclusive_group()  # What this allows is that we may have either a subnet or a single address to filter for
    subnet_or_single_group.add_argument("--subnet", nargs=2, metavar=("start_address", "end_address"), help="Filter for a range of hosts") 
    subnet_or_single_group.add_argument("--single", metavar="address", help="Filter for a single host")

    args = parser.parse_args()

    packet_filter = interpret_json.packet_filter()

    if args.subnet is None and args.single is None:  # If no dest filtering is required by command line
        if packet_filter.whitelist_dest and not packet_filter.src_whitelisted_ips:  # If destination whitelisting is asked for in config and there are whitelisted ips (basically checks if there are ips to filter for)
            logging.error('Trying to filter packets for no whitelisted ip')
    logging.basicConfig(filename='main.log', level=logging.INFO, filemode='w')
    logging.info('Starting thread')
    filter_thread = threading.Thread(target=packet_filter_action)
    logging.info('Created thread object')
    filter_thread.start()
    logging.info('Started thread')


if __name__=="__main__":
    main()