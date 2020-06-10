import cmd
from packet_filter import packet_filter
from acl_entry import acl_entry
from tcp_flags import tcp_flags_type
from packet_filter import packet_filter


class cactus_add_shell(cmd.Cmd):

    prompt="(Cactus-Add-ACLEntry) "
    entry=acl_entry()
    packet_filter=packet_filter()

    def do_srcadd(self, args):
        tuple_args = self.parse(args)
        if len(tuple_args) != 1:
            self.help_srcadd()
            return
        self.entry.src_address=tuple_args[0]


    def help_srcadd(self):
        print("Set the source address of the ACL entry. srcadd [address]")
    

    def do_srcprt(self, args):
        tuple_args = self.parse(args)
        if len(tuple_args) != 1:
            self.help_srcprt()
            return
        self.entry.src_port=int(tuple_args[0])


    def help_srcprt(self):
        print("Set the source port of the ACL entry. srcprt [port number]")

    
    def do_dstadd(self, args):
        tuple_args = self.parse(args)
        if len(tuple_args) != 1:
            self.help_dstadd()
            return
        self.entry.dest_address=tuple_args[0]


    def help_dstadd(self):
        print("Set the destination address of the ACL entry. dstadd [address]")


    def do_dstprt(self, args):
        tuple_args = self.parse(args)
        if len(tuple_args) != 1:
            self.help_dstprt()
            return
        self.entry.dest_port=int(tuple_args[0])


    def help_dstprt(self):
        print("Set the destination port of the ACL entry. dstprt [port number]")


    def do_check(self, args):
        tuple_args = self.parse(args)
        if len(tuple_args) != 1:
            self.help_check()
            return
        if tuple_args[0].lower() == "true":
            self.entry.check_conxion = True
        elif tuple_args[0].lower() == "false":
            self.entry.check_conxion = False
        else:
            self.help_check()
            return


    def help_check(self):
        print("Set the connection checking of the ACL entry. check [true | false]")


    def do_protocol(self, args):
        tuple_args = self.parse(args)
        if len(tuple_args) != 1:
            self.help_protocol()
            return
        self.entry.protocol=tuple_args[0]


    def help_protocol(self):
        print("Set the protocol of the ACL entry. protocol [TCP | UDP]")


    def do_flags(self, args):
        tuple_args = self.parse(args)
        if len(tuple_args) != 1:
            self.help_flags()
            return
        lower_args = tuple_args[0].lower()
        if "s" in lower_args:
            self.entry.flag_bits += tcp_flags_type.syn
        if "a" in lower_args:
            self.entry.flag_bits += tcp_flags_type.ack
        if "f" in lower_args:
            self.entry.flag_bits += tcp_flags_type.fin
        if "r" in lower_args:
            self.entry.flag_bits += tcp_flags_type.rst
        if "u" in lower_args:
            self.entry.flag_bits += tcp_flags_type.urg
        if "p" in lower_args:
            self.entry.flag_bits += tcp_flags_type.psh


    def help_flags(self):
        print("Set the TCP flags of the ACL entry. flags [S | A | F | P | U | R]")
    

    def do_done(self, args):
        self.packet_filter.acl.lock.acquire()
        self.packet_filter.acl+=self.entry
        self.packet_filter.acl.lock.release()
        print()
        return True


    def help_done(self):
        print("Finish setting up the ACL entry. Make sure to set up properly")


    def parse(self, args):
        return tuple(map(str, args.split()))


    def do_EOF(self, args):
        print()
        return True


    def do_exit(self, args):
        print()
        return True