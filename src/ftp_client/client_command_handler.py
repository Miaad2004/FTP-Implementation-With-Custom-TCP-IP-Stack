from client import FTPClient

def main():
    host = input("Enter FTP server address: ")
    port = int(input("Enter port (default 21): ") or "21")
    use_tls = input("Use TLS (y/n)? ").lower() == 'y'

    client = FTPClient(host, port)
    if not client.connect():
        print("Connection failed")
        return

    if use_tls:
        if not client.auth_tls():
            print("TLS initialization failed")
            return
        print("TLS connection established")

    print("Please login using USER command")
    logged_in = False
    awaiting_rnto = False
    rnfr_filename = ""

    username = None
    protocol = "ftps" if use_tls else "ftp"
    prompt = "ftps>" if use_tls else "ftp>"

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
                    prompt = f"({username})({host}):{protocol}> "
                    print("230 Anonymous login successful")
                else:
                    print("331 Please specify the password")
            else:
                print("530 Invalid username")

        elif cmd == "PASS":
            if not logged_in:
                password = argument
                if client.pass_(password):
                    logged_in = True
                    prompt = f"({username})({host}):{protocol}> "
                    print("230 Login successful")
                else:
                    print("530 Login incorrect")
            else:
                print("503 Already logged in")

        elif cmd == "QUIT":
            break

        # Only allow other commands if logged in
        elif not logged_in:
            print("530 Please login with USER and PASS first")

        elif cmd == "LIST":
            print(client.list_files())
        elif cmd == "PWD":
            print(client.pwd())
        elif cmd == "RETR":
            filename = argument
            if client.download_file(filename):
                print(f"Downloaded {filename}")
            else:
                print("Download failed")
        elif cmd == "STOR":
            filename = argument
            if client.upload_file(filename):
                print(f"Uploaded {filename}")
            else:
                print("Upload failed")
        elif cmd == "DELE":
            filename = argument
            if client.dele(filename):
                print(f"Deleted {filename}")
            else:
                print("Delete failed")
        elif cmd == "MKD":
            dirname = argument
            if client.mkd(dirname):
                print(f"Created directory {dirname}")
            else:
                print("Directory creation failed")
        elif cmd == "RMD":
            dirname = argument
            if client.rmd(dirname):
                print(f"Removed directory {dirname} ")
            else:
                print("Directory removal failed")
        elif cmd == "CWD":
            path = argument
            if client.cwd(path):
                print(f"Changed directory to {path}")
            else:
                print("Directory change failed")
        elif cmd == "CDUP":
            if client.cdup():
                print("Changed to parent directory")
            else:
                print("Directory change failed")
        elif cmd == "REIN":
            if client.rein():
                print("Connection reinitialized")
            else:
                print("Failed to reinitialize connection")
        elif cmd == "NOOP":
            if client.noop():
                print("NOOP command successful")
            else:
                print("NOOP command failed")
        elif cmd == "HELP":
            print(client.help(argument))
        elif cmd == "FEAT":
            print(client.feat())
        elif cmd == "RNFR":
            filename = argument
            if client.rnfr(filename):
                print("350 File exists, ready for destination name")
                awaiting_rnto = True
                rnfr_filename = filename
            else:
                print("RNFR command failed")
                awaiting_rnto = False
                rnfr_filename = ""

        elif cmd == "RNTO":
            if awaiting_rnto:
                new_filename = argument
                if client.rnto(new_filename):
                    print(f"250 Renamed {rnfr_filename} to {new_filename}")
                else:
                    print("RNTO command failed")
                awaiting_rnto = False
                rnfr_filename = ""
            else:
                print("503 Need RNFR before RNTO")
                
        elif cmd == "TYPE":
            type_code = argument
            if client.type(type_code):
                print(f"Set transfer type to {type_code}")
            else:
                print("Failed to set transfer type")
        elif cmd == "OPTS":
            option = argument
            if client.opts(option):
                print(f"Set option {option}")
            else:
                print("Failed to set option")
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
                        print(f"Changed permissions of {filename} to {mode}")
                    else:
                        print("Failed to change file permissions")
                else:
                    print("Usage: SITE CHMOD <mode> <filename>")
            else:
                print("Unsupported SITE command")
                
    client.quit()

if __name__ == "__main__":
    main()
