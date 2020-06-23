from argparse import ArgumentParser
import threading
from scapy.all import *
from packet_filter import packet_filter
from acl import acl
from acl_entry import acl_entry
from tcp_flags import tcp_flags, tcp_flags_type
from cactus_shell import cactus_shell
from dal import dal


def parse_arguments():

    parser = ArgumentParser(description="Cactus Packet Filter")
    parser.add_argument("--reset", action="store_false", help="Reset the configuration file. Sets back to default")
    parser.add_argument("--altfile", metavar="Path", help="Alternate file to load configuration from")
    return parser.parse_args()


def main():
    DAL = dal()
    args = parse_arguments()
    logging.basicConfig(filename='main.log', level=logging.INFO, filemode='w')
    
    filterer = DAL.read_packet_filter()
    
    shell=cactus_shell(filterer)
    logging.info("Starting thread")

    packet_filter_thread = threading.Thread(target=filterer.run, daemon=True)
    packet_filter_thread.start()

    logging.info("Main: Thread running")
    shell.cmdloop()

if __name__=="__main__":
    main()