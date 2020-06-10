import cmd
from packet_filter import packet_filter
from cactus_add_shell import cactus_add_shell


class cactus_shell(cmd.Cmd):
    intro="Welcome to the Cactus shell. Type help or ? for help"
    prompt="(Cactus) "
    packet_filter = packet_filter()
    ruler="="

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


    def do_enable(self, args):
        if self.packet_filter.enabled:
            print("Already enabled!")
        else:
            self.packet_filter.enabled=True


    def do_disable(self, args):
        if self.packet_filter.enabled:
            self.packet_filter.enabled=False
        else:
            print("Already disabled!")


    def do_print_state(self, args):
        print(f"{'enabled' if self.packet_filter.enabled else 'disabled'}")


    def do_print(self, args):
        "Prints out data"
        tuple_args = self.parse(args)
        if tuple_args[0].lower() == "acl":
            print(self.packet_filter.acl)
        elif tuple_args[0].lower() == "state":
            print(f'{"enabled" if self.packet_filter.enabled else "disabled"}')

    def complete_print(self, text, line, begidx, endidx):
        completions=["acl", "state"]
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in completions if s.startswith(mline)]

    
    def do_exit(self, args):
        print()
        return True


    def do_add(self, args):
        shell = cactus_add_shell()
        shell.packet_filter = self.packet_filter
        shell.cmdloop()


    def help_add(self):
        print("Add ACL entry")


    def do_EOF(self, args):
        print()
        return True

    
    def help_mode(self):
        print("mode [blacklist | whitelist]")

    def parse(self, args):
        return tuple(map(str, args.strip().split()))