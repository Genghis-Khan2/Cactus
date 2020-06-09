import cmd
from packet_filter import packet_filter
from cactus_add_shell import cactus_add_shell

class cactus_shell(cmd.Cmd):
    intro="Welcome to the Cactus shell. Type help or ? for help"
    prompt="(Cactus) "
    packet_filter = packet_filter()

    def do_mode(self, args):
        tuple_args = self.parse(args)
        if len(tuple_args) != 1:
            self.help_mode()
            return
        if tuple_args[0].lower() == "blacklist":
            self.packet_filter.acl.whitelist = False
        elif tuple_args[0].lower() == "whitelist":
            self.packet_filter.acl.whitelist = True
        else:
            self.help_mode()
            return


    def do_print(self, args):
        "Prints out the tables"
        print(self.packet_filter.acl)

    
    def do_exit(self, args):
        print()
        return True


    def do_add(self, args):
        shell = cactus_add_shell()
        shell.packet_filter = self.packet_filter
        shell.cmdloop()


    def do_EOF(self, args):
        print()
        return True

    
    def help_mode(self):
        print("mode [blacklist | whitelist]")

    def parse(self, args):
        return tuple(map(str, args.split()))