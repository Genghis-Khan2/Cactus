import cmd
from packet_filter import packet_filter
from acl_entry import acl_entry
from tcp_flags import tcp_flags_type
from packet_filter import packet_filter
from dal import dal


class cactus_edit_shell(cmd.Cmd):

    def __init__(self, index, packet_filter):
        super(cactus_edit_shell, self).__init__()
        self.index = index
        self.packet_filter=packet_filter
        self.prompt="(Cactus-Edit) "
        self.entry=packet_filter.acl[index].copy()
        self.DAL = dal()

#region srcadd
    def do_srcadd(self, args):
        tuple_args = self.parse(args)
        if len(tuple_args) == 2:
            if tuple_args[0].lower() == "range":
                result = parse.parse("{}-{}", tuple_args[1])
                if result is None:
                    raise SyntaxError("Improper parse usage")
                if result.fixed[1] == "*":
                    self.entry.src_address=(result.fixed[0], "255.255.255.255")
                else:
                    self.entry.src_address = result.fixed
        elif len(tuple_args) == 1:
            if tuple_args[0] == "*":
                self.entry.src_address=("0.0.0.0", "255.255.255.255")
            else:
                self.entry.src_address=tuple_args[0]
        else:
            print(tuple_args)
            self.help_srcadd()
            return


    def complete_srcadd(self, text, line, begidx, endidx):
        completions=["range"]
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in completions if s.startswith(mline)]


    def help_srcadd(self):
        print("Set the source address of the ACL entry. srcadd [address] or srcadd range [start_address-end_address]")
#endregion
    
#region srcprt
    def do_srcprt(self, args):
        tuple_args = self.parse(args)
        if len(tuple_args) == 2:
            if tuple_args[0].lower() == "range":
                result = parse.parse("{}-{}", tuple_args[1])
                if result is None:
                    raise SyntaxError("Improper parse usage")
                if result.fixed[1] == "*":
                    self.entry.src_port=(result.fixed[0], 65535)
                else:
                    self.entry.src_port = result.fixed
        elif len(tuple_args) == 1:
            if tuple_args[0] == "*":
                self.entry.src_port=(0, 65535)
            else:
                self.entry.src_port=tuple_args[0]
        else:
            print(tuple_args)
            self.help_srcprt()
            return


    def complete_srcprt(self, text, line, begidx, endidx):
        completions=["range"]
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in completions if s.startswith(mline)]


    def help_srcprt(self):
        print("Set the source port of the ACL entry. srcprt [port number] or srcprt range [start_port-end_port]")
#endregion

#region dstadd
    def do_dstadd(self, args):
        tuple_args = self.parse(args)
        if len(tuple_args) == 2:
            if tuple_args[0].lower() == "range":
                result = parse.parse("{}-{}", tuple_args[1])
                if result is None:
                    raise SyntaxError("Improper parse usage")
                if result.fixed[1] == "*":
                    self.entry.dest_address=(result.fixed[0], "255.255.255.255")
                else:
                    self.entry.dest_address = result.fixed
        elif len(tuple_args) == 1:
            if tuple_args[0] == "*":
                self.entry.dest_port=("0.0.0.0", "255.255.255.255")
            else:
                self.entry.dest_address=tuple_args[0]
        else:
            print(tuple_args)
            self.help_dstadd()
            return


    def complete_dstadd(self, text, line, begidx, endidx):
        completions=["range"]
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in completions if s.startswith(mline)]


    def help_dstadd(self):
        print("Set the destination address of the ACL entry. dstadd [address]")
#endregion

#region dstprt
    def do_dstprt(self, args):
        tuple_args = self.parse(args)
        if len(tuple_args) == 2:
            if tuple_args[0].lower() == "range":
                result = parse.parse("{}-{}", tuple_args[1])
                if result is None:
                    raise SyntaxError("Improper parse usage")
                if result.fixed[1] == "*":
                    self.entry.dest_port=(result.fixed[0], 65535)
                else:
                    self.entry.dest_port = result.fixed
        elif len(tuple_args) == 1:
            if tuple_args[0] == "*":
                self.entry.dest_port=(0, 65535)
            else:
                self.entry.dest_port=tuple_args[0]
        else:
            print(tuple_args)
            self.help_dstprt()
            return


    def complete_dstprt(self, text, line, begidx, endidx):
        completions=["range"]
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in completions if s.startswith(mline)]


    def help_dstprt(self):
        print("Set the destination port of the ACL entry. dstprt [port number]")
#endregion

#region check
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
#endregion

#region protocol
    def do_protocol(self, args):
        tuple_args = self.parse(args)
        if len(tuple_args) != 1:
            self.help_protocol()
            return
        self.entry.protocol=tuple_args[0]


    def help_protocol(self):
        print("Set the protocol of the ACL entry. protocol [TCP | UDP]")

#endregion

#region flags
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
#endregion

#region done

    def do_done(self, args):
        self.packet_filter.acl.lock.acquire()
        self.packet_filter.acl[self.index] = self.entry
        self.packet_filter.acl.lock.release()
        self.DAL.empty_file()
        self.DAL.write_packet_filter(self.packet_filter)
        print()
        return True


    def help_done(self):
        print("Finish setting up the ACL entry. Make sure to set up properly")

#endregion

#region print
    def do_print(self, args):
        "Print the entry until now"
        print(self.entry)
#endregion

    def parse(self, args):
        return tuple(map(str, args.strip().split()))


    def do_EOF(self, args):
        print()
        return True


    def do_exit(self, args):
        print()
        return True