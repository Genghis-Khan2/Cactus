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
            self.help_src()
            return
        self.entry.src_address=tuple_args[0]

    def do_srcprt(self, args):
        tuple_args = self.parse(args)
        if len(tuple_args) != 1:
            self.help_src()
            return
        self.entry.src_port=int(tuple_args[0])

    
    def do_dstadd(self, args):
        tuple_args = self.parse(args)
        if len(tuple_args) != 1:
            self.help_src()
            return
        self.entry.dest_address=tuple_args[0]


    def do_dstprt(self, args):
        tuple_args = self.parse(args)
        if len(tuple_args) != 1:
            self.help_src()
            return
        self.entry.dest_port=int(tuple_args[0])


    def do_check(self, args):
        tuple_args = self.parse(args)
        if len(tuple_args) != 1:
            self.help_src()
            return
        self.entry.check_conxion=bool(tuple_args[0])


    def do_protocol(self, args):
        tuple_args = self.parse(args)
        if len(tuple_args) != 1:
            self.help_src()
            return
        self.entry.protocol=tuple_args[0]


    def do_flags(self, args):
        tuple_args = self.parse(args)
        if len(tuple_args) != 1:
            self.help_src()
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
    

    def do_done(self, args):
        self.packet_filter.acl+=self.entry
        print()
        return True


    def parse(self, args):
        return tuple(map(str, args.split()))