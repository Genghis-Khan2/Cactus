import cmd
from packet_filter import packet_filter
from cactus_add_shell import cactus_add_shell
from cactus_edit_shell import cactus_edit_shell
from dal import dal


class cactus_shell(cmd.Cmd):
    intro="Welcome to the Cactus shell. Type help or ? for help"
    prompt="(Cactus) "
    packet_filter = packet_filter()
    ruler="="


    def __init__(self, packet_filter):
        super(cactus_shell, self).__init__()
        self.packet_filter = packet_filter
        self.DAL=dal()

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
        "Enable the packet filter"
        if self.packet_filter.enabled:
            print("Already enabled!")
        else:
            self.packet_filter.enabled=True


    def do_disable(self, args):
        "Disable the packet filter"
        if self.packet_filter.enabled:
            self.packet_filter.enabled=False
        else:
            print("Already disabled!")


    def do_print(self, args):
        "Prints out data"
        self.packet_filter.acl.lock.acquire()
        tuple_args = self.parse(args)
        if len(tuple_args) == 0 or tuple_args[0].lower() == "acl":
            print(self.packet_filter.acl)
        elif tuple_args[0].lower() == "state":
            print(f'{"enabled" if self.packet_filter.enabled else "disabled"}')
        elif tuple_args[0].lower() == "interfaces":
            if len(self.packet_filter.interfaces) > 0:
                for iface in self.packet_filter.interfaces[:-1]:
                    print(iface, end=", ")
                print(self.packet_filter.interfaces[-1])
        self.packet_filter.acl.lock.release()

    def complete_print(self, text, line, begidx, endidx):
        completions=["acl", "state", "interfaces"]
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in completions if s.startswith(mline)]

    
    def do_exit(self, args):
        print()
        return True


    def do_add(self, args):
        shell = cactus_add_shell(self.packet_filter)
        shell.packet_filter = self.packet_filter
        shell.cmdloop()


    def help_add(self):
        print("Add ACL entry")


    def do_edit(self, args):
        "Edit an ACL entry"
        self.packet_filter.acl.edit_print()
        entry_num = int(input("Please enter the number the entry you would like to edit: "))
        if entry_num > len(self.packet_filter.acl):
            print("Please enter valid entry numbers")
        else:
            shell=cactus_edit_shell(entry_num-1, self.packet_filter)
            shell.cmdloop()


    def do_remove(self, args):
        "Remove an ACL entry"
        self.packet_filter.acl.edit_print()
        entry_num = int(input("Please enter the number the entry you would like to remove: "))
        if entry_num > len(self.packet_filter.acl):
            print("Please enter valid entry numbers")
        else:
            self.packet_filter.acl.remove(self.packet_filter.acl[entry_num - 1])
            self.DAL.empty_file()
            self.DAL.write_packet_filter(self.packet_filter)


    def do_interface(self, args):
        tuple_args = self.parse(args)
        if len(tuple_args) == 2:
            if tuple_args[0].lower() == "add":
                if tuple_args[1] not in self.packet_filter.interfaces:
                    self.packet_filter.interfaces.append(tuple_args[1])
                    self.packet_filter.interfaces.sort(key=lambda s: s.lower())
            elif tuple_args[0].lower() == "remove":
                try:
                    if len(self.packet_filter.interfaces) > 1:
                        self.packet_filter.interfaces.remove(tuple_args[1])
                    else:
                        print("Cannot delete single interface")
                except ValueError:
                    print("Value does not exist")
            self.DAL.empty_file()
            self.DAL.write_packet_filter(self.packet_filter)
        else:
            print("Invalid interface action")


    def complete_interface(self, text, line, begidx, endidx):
        completions=["add", "remove"]
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in completions if s.startswith(mline)]


    def do_EOF(self, args):
        print()
        return True

    
    def help_mode(self):
        print("mode [blacklist | whitelist]")

    def parse(self, args):
        return tuple(map(str, args.strip().split()))