import argparse
import cmd
import os
import colorama
from colorama import Fore, Back, Style
from pathlib import PurePath
from datetime import datetime
import signal
from src.file_system.file_system import FileSystem

colorama.init(autoreset=True)

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

class FileSystemCLI(cmd.Cmd):
    intro = f"""
{Fore.GREEN}Virtual File System CLI started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}
Type {Fore.CYAN}help{Style.RESET_ALL} or {Fore.CYAN}?{Style.RESET_ALL} to list commands.
    """
    prompt = f"{Fore.BLUE}guest@VFS{Style.RESET_ALL}:{Fore.GREEN}/${Style.RESET_ALL} "
    
    def __init__(self, file_system: FileSystem):
        super().__init__()
        self.fs = file_system
        clear_console()
        
    def do_login(self, arg):
        """Login to the system: login <username> <password>"""
        try:
            args = arg.split()
            if len(args) != 2:
                print(f"{Fore.RED}Usage: login <username> <password>{Style.RESET_ALL}")
                return
            username, password = args
            if self.fs.auth_login(username, password):
                self.prompt = f"{Fore.BLUE}{username}@VFS{Style.RESET_ALL}:{Fore.GREEN}/${Style.RESET_ALL} "
                print(f"{Fore.GREEN}Successfully logged in as {username}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Invalid username or password{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

    def do_logout(self, arg):
        """Logout from the system"""
        try:
            self.fs.auth_logout()
            self.prompt = f"{Fore.BLUE}guest@VFS{Style.RESET_ALL}:{Fore.GREEN}/${Style.RESET_ALL} "
            print(f"{Fore.GREEN}Successfully logged out{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

    def do_clear(self, arg):
        """Clear the console screen"""
        clear_console()

    def do_pwd(self, arg):
        """Print current working directory"""
        try:
            print(self.fs.current_ftp_dir)
        except Exception as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

    def do_cd(self, arg):
        """Change directory: cd <path>"""
        try:
            path = arg.strip()
            self.fs.change_dir(path)
            print(f"{Fore.GREEN}Changed directory to {path}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

    def do_mkdir(self, arg):
        """Create a new directory: mkdir <path> [permissions]"""
        try:
            args = arg.split()
            if len(args) < 1:
                print(f"{Fore.RED}Usage: mkdir <path> [permissions]{Style.RESET_ALL}")
                return
            path = args[0]
            perms = args[1] if len(args) > 1 else "---"
            self.fs.mkdir(path, perms)
            print(f"{Fore.GREEN}Directory created successfully{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

    def do_rmdir(self, arg):
        """Remove a directory: rmdir <path>"""
        try:
            path = arg.strip()
            self.fs.rmdir(path)
            print(f"{Fore.GREEN}Directory removed successfully{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

    def do_touch(self, arg):
        """Create a new empty file: touch <path> [permissions]"""
        try:
            args = arg.split()
            if len(args) < 1:
                print(f"{Fore.RED}Usage: touch <path> [permissions]{Style.RESET_ALL}")
                return
            path = args[0]
            perms = args[1] if len(args) > 1 else "---"
            self.fs.create_file(path, perms)
            print(f"{Fore.GREEN}File created successfully{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

    def do_rm(self, arg):
        """Remove a file: rm <path>"""
        try:
            path = arg.strip()
            self.fs.delete_file(PurePath(path))
            print(f"{Fore.GREEN}File removed successfully{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

    def do_ls(self, arg):
        """List directory contents: ls [path]"""
        try:
            path = arg.strip() if arg else None
            files = self.fs.list_dir(path)
            for file in files:
                type_color = Fore.BLUE if file['type'] == 'd' else Fore.WHITE
                print(f"{file['type']}{file['permissions']} {file['owner']} {file['size']:8d} {file['date']} {type_color}{file['name']}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

    def do_chmod(self, arg):
        """Change file permissions: chmod <path> <username> <permissions> <public_permissions>"""
        try:
            args = arg.split()
            if len(args) != 4:
                print(f"{Fore.RED}Usage: chmod <path> <username> <permissions> <public_permissions>{Style.RESET_ALL}")
                return
            path, username, permissions, public_permissions = args
            self.fs.chmod(path, username, permissions, public_permissions)
            print(f"{Fore.GREEN}Permissions changed successfully{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

    def do_exit(self, arg):
        """Exit the CLI: exit"""
        print(f"{Fore.GREEN}Goodbye!{Style.RESET_ALL}")
        return True

    def do_help(self, arg):
        """Show help for a command: help [command]"""
        if arg:
            try:
                func = getattr(self, 'do_' + arg)
                print(f"{Fore.CYAN}{func.__doc__}{Style.RESET_ALL}")
            except AttributeError:
                print(f"{Fore.RED}No help available for {arg}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.CYAN}Available commands:{Style.RESET_ALL}")
            for name in self.get_names():
                if name.startswith('do_'):
                    cmd = name[3:]
                    func = getattr(self, name)
                    print(f"{Fore.GREEN}{cmd:15}{Style.RESET_ALL} - {func.__doc__}")
            print()

def signal_handler(sig, frame):
    print(f"\n{Fore.GREEN}Terminating gracefully...{Style.RESET_ALL}")
    exit(0)

def main():
    signal.signal(signal.SIGINT, signal_handler)
    
    parser = argparse.ArgumentParser(description='Virtual File System CLI')
    parser.add_argument('-i', '--interactive', action='store_true', help='Run in interactive mode')
    args = parser.parse_args()

    fs = FileSystem()  # Assuming FileSystem is properly initialized here

    if args.interactive or not any(vars(args).values()):
        FileSystemCLI(fs).cmdloop()
    else:
        parser.print_help()

if __name__ == '__main__':
    main()