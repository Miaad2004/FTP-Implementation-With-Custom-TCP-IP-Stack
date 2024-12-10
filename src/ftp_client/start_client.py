from client import FTPClient
from colorama import Fore, Style, init
import os


def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')


def main():
    init(autoreset=True)  # Automatically reset colors after each print
    clear_console()
    host = input(f"{Fore.CYAN}Enter FTP server address: {Style.RESET_ALL}")
    port = int(input(f"{Fore.CYAN}Enter port (default 21): {Style.RESET_ALL}") or "21")
    use_tls = input(f"{Fore.CYAN}Use TLS (y/n)? {Style.RESET_ALL}").lower() == 'y'

    client = FTPClient(host, port)
    if not client.connect():
        print(f"{Fore.RED}Connection failed{Style.RESET_ALL}")
        return

    if use_tls:
        if not client.auth_tls():
            print(f"{Fore.RED}TLS initialization failed{Style.RESET_ALL}")
            return
        print(f"{Fore.GREEN}TLS connection established{Style.RESET_ALL}")

    print(f"{Fore.CYAN}Please login using USER command{Style.RESET_ALL}")
    logged_in = False
    awaiting_rnto = False
    rnfr_filename = ""

    username = None
    protocol = "ftps" if use_tls else "ftp"
    prompt = f"{Fore.YELLOW}ftps>{Style.RESET_ALL}" if use_tls else f"{Fore.YELLOW}ftp>{Style.RESET_ALL}"

    while True:
        command = input(prompt).strip()
        command_parts = command.split(' ', 1)
        cmd = command_parts[0].upper()
        argument = command_parts[1] if len(command_parts) > 1 else ''

        # Handle authentication commands first
        if cmd == "USER":
            username = argument
            if client.user(username):
                if username.lower() == 'anonymous':
                    logged_in = True
                    prompt = f"{Fore.YELLOW}({username})({host}):{protocol}> {Style.RESET_ALL}"
                    print(f"{Fore.GREEN}230 Anonymous login successful{Style.RESET_ALL}")
                else:
                    print(f"{Fore.CYAN}331 Please specify the password{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}530 Invalid username{Style.RESET_ALL}")

        elif cmd == "PASS":
            if not logged_in:
                password = argument
                if client.pass_(password):
                    logged_in = True
                    prompt = f"{Fore.YELLOW}({username})({host}):{protocol}> {Style.RESET_ALL}"
                    print(f"{Fore.GREEN}230 Login successful{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}530 Login incorrect{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}503 Already logged in{Style.RESET_ALL}")

        elif cmd == "QUIT":
            break

        # Only allow other commands if logged in
        elif not logged_in:
            print(f"{Fore.RED}530 Please login with USER and PASS first{Style.RESET_ALL}")

        elif cmd == "LIST":
            print(client.list_files())
        elif cmd == "PWD":
            print(client.pwd())
        elif cmd == "RETR":
            filename = argument
            if client.download_file(filename):
                print(f"{Fore.GREEN}Downloaded {filename}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Download failed{Style.RESET_ALL}")
        elif cmd == "STOR":
            filename = argument
            if client.upload_file(filename):
                print(f"{Fore.GREEN}Uploaded {filename}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Upload failed{Style.RESET_ALL}")
        elif cmd == "DELE":
            filename = argument
            if client.dele(filename):
                print(f"{Fore.GREEN}Deleted {filename}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Delete failed{Style.RESET_ALL}")
        elif cmd == "MKD":
            dirname = argument
            if client.mkd(dirname):
                print(f"{Fore.GREEN}Created directory {dirname}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Directory creation failed{Style.RESET_ALL}")
        elif cmd == "RMD":
            dirname = argument
            if client.rmd(dirname):
                print(f"{Fore.GREEN}Removed directory {dirname} {Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Directory removal failed{Style.RESET_ALL}")
        elif cmd == "CWD":
            path = argument
            if client.cwd(path):
                print(f"{Fore.GREEN}Changed directory to {path}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Directory change failed{Style.RESET_ALL}")
        elif cmd == "CDUP":
            if client.cdup():
                print(f"{Fore.GREEN}Changed to parent directory{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Directory change failed{Style.RESET_ALL}")
        elif cmd == "REIN":
            if client.rein():
                print(f"{Fore.GREEN}Connection reinitialized{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Failed to reinitialize connection{Style.RESET_ALL}")
        elif cmd == "NOOP":
            if client.noop():
                print(f"{Fore.GREEN}NOOP command successful{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}NOOP command failed{Style.RESET_ALL}")
        elif cmd == "HELP":
            print(client.help(argument))
        elif cmd == "FEAT":
            print(client.feat())
        elif cmd == "RNFR":
            filename = argument
            if client.rnfr(filename):
                print(f"{Fore.CYAN}350 File exists, ready for destination name{Style.RESET_ALL}")
                awaiting_rnto = True
                rnfr_filename = filename
            else:
                print(f"{Fore.RED}RNFR command failed{Style.RESET_ALL}")
                awaiting_rnto = False
                rnfr_filename = ""

        elif cmd == "RNTO":
            if awaiting_rnto:
                new_filename = argument
                if client.rnto(new_filename):
                    print(f"{Fore.GREEN}250 Renamed {rnfr_filename} to {new_filename}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}RNTO command failed{Style.RESET_ALL}")
                awaiting_rnto = False
                rnfr_filename = ""
            else:
                print(f"{Fore.RED}503 Need RNFR before RNTO{Style.RESET_ALL}")

        elif cmd == "TYPE":
            type_code = argument
            if client.type(type_code):
                print(f"{Fore.GREEN}Set transfer type to {type_code}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Failed to set transfer type{Style.RESET_ALL}")
        elif cmd == "OPTS":
            option = argument
            if client.opts(option):
                print(f"{Fore.GREEN}Set option {option}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Failed to set option{Style.RESET_ALL}")
        elif cmd == "SYST":
            response = client.syst()
            print(response)

        elif cmd == "SITE":
            if argument.upper().startswith("CHMOD"):
                parts = argument.split()
                if len(parts) == 3:
                    mode = parts[1]
                    filename = parts[2]
                    if client.site_chmod(mode, filename):
                        print(f"{Fore.GREEN}Changed permissions of {filename} to {mode}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}Failed to change file permissions{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}Usage: SITE CHMOD <mode> <filename>{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Unsupported SITE command{Style.RESET_ALL}")

    client.quit()

if __name__ == "__main__":
    main()
