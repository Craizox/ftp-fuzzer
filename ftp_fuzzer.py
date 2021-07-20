import socket
import time
import argparse


class bcolors:
    """Simple class for log info
    """
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    OKBLUE = '\033[94m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'



class fuzzer():
    """Class that contain all the method to use the fuzzer
    """

    def __init__(self):
        self.error = []
        self.buffer = ['', 'A']
        self.counter = 10
        self.command = [ 'TYPE', 'CWD', 'DELE', 'MDTM', 'PASV', 'MKD', 'NLST', 'PORT', 'PWD', 'RMD', 'RNFR', 'RNTO', 'SITE', 'SIZE', 'ACCT', 'APPE', 'CDUP', 'HELP', 'MODE', 'NOOP', 'REIN', 'STAT', 'STOU', 'STRU', 'SYST', 'ABOR']
        #self.chars = [ "(", ")", "-", "_", "=", "+", "!", "@", "#", "$", "%", "^", "&", "*", "}", "{", ";", ":", ".", "/", "?", "<", ">", "`", "~", "\n" ]

    def addValue(self, host, port, user, passwd, length, stopafter, delay):
        """Add all the argument to the class

        Args:
            host (str): Ipv4 address of the server
            port (str): Port on wich the server listen
            user (str): Username for the connection to the server
            passwd (str): Password for the connection to the server
            length (str): Size maximum of the buffer send to the server
            stopafter (str): Number of error before stoping the fuzzing
            delay (str): Number of second waiting between each request
        """
        self.host = host
        self.user = user
        self.passwd = passwd
        self.length = int(length) / 10
        self.stopafter = int(stopafter)
        self.port = 21 if (port == None) else int(port)
        self.delay = int(delay)

    def createBuffer(self):
        """Create all the buffers for the fuzzer
            Each time increment of 10 chars the new buffer to until it reach the wanted length
        """
        while len(self.buffer) < self.length + 2:
            self.buffer.append('A' * self.counter)
            self.counter += 10

    def fuzzerLoopWithoutCommand(self):
        """Send to the server all the buffer without any command
            If there is an error, add it to the corresponding list
        """
        for i in self.buffer:
            time.sleep(self.delay)
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.connect((self.host, self.port))
                data = self.socket.recv(1024)
            except:
                print(bcolors.FAIL + "Connexion to server {} failed".format(self.host) + bcolors.ENDC)
                continue            
            
            try:
                print(bcolors.OKBLUE + "[*] " + bcolors.ENDC + "Host: {0} Fuzzing without command with length ".format(self.host) + str(len(i)))
                self.socket.send("{}\r\n".format(i).encode())
                data = self.socket.recv(1024)
                self.socket.send(b'QUIT\r\n')
                quit = self.socket.recv(1024)
                self.socket.close()
            except:
                print(bcolors.WARNING + "[-] " + bcolors.ENDC + "Crash String : Without command with length {}".format(len(i)))
                self.error.append(('NONE', len(i)))
                self.stopafter -= 1
                if self.stopafter <= 0 :
                    print(bcolors.WARNING + "[-] " + bcolors.ENDC + "Program not responding exiting now")
                    return


    def fuzzerLoopPreAuth(self):
        """Fuzze only with the USER and PASS command, there is no need to have a account to do this stage
        """
        # USER command
        for i in self.buffer:
            time.sleep(self.delay)
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.connect((self.host, self.port))
                data = self.socket.recv(1024)
            except:
                print(bcolors.FAIL + "Connexion to server {} failed".format(self.host) + bcolors.ENDC)
                continue            

            try:
                print(bcolors.OKBLUE + "[*] " + bcolors.ENDC + "Host: {0} Fuzzing USER with length ".format(self.host) + str(len(i)))
                self.socket.send("USER {}\r\n".format(i).encode())
                data = self.socket.recv(1024)
                self.socket.send(b'QUIT\r\n')
                quit = self.socket.recv(1024)
                self.socket.close()
            except:
                print(bcolors.WARNING + "[-] " + bcolors.ENDC + "Crash String : command USER with length {}".format(len(i)))
                self.error.append(('USER', len(i)))
                self.stopafter -= 1
                if self.stopafter <= 0 :
                    print(bcolors.WARNING + "[-] " + bcolors.ENDC + "Program not responding exiting now")
                    return

        
        if self.user == None:
            return
        # PASS command
        for i in self.buffer:
            time.sleep(self.delay)
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.connect((self.host, self.port))
                data = self.socket.recv(1024)
            except:
                print(bcolors.FAIL + "Connexion to server {} failed".format(self.host) + bcolors.ENDC)
                continue

            try:            
                print(bcolors.OKBLUE + "[*] " + bcolors.ENDC + "Host: {0} Fuzzing PASS with length ".format(self.host) + str(len(i)))
                self.socket.send("USER {}\r\n".format(self.user).encode())
                data = self.socket.recv(1024)
                self.socket.send("PASS {}\r\n".format(i).encode())
                p = self.socket.recv(1024)
                self.socket.send(b'QUIT\r\n')
                quit = self.socket.recv(1024)
                self.socket.close()
            except:
                print(bcolors.WARNING + "[-] " + bcolors.ENDC + "Crash String : command PASS with length {}".format(len(i)))
                self.error.append(('PASS', len(i)))
                self.stopafter -= 1
                if self.stopafter <= 0 :
                    print(bcolors.WARNING + "[-] " + bcolors.ENDC + "Program not responding exiting now")
                    return


    def fuzzerLoopPostAuth(self):
        """Fuzze with all the other commands, and all the buffers previously created
            If an error occursed, add it to the corresponding list
        """
        for command in self.command:
            for i in self.buffer:
                time.sleep(self.delay)
                try:
                    self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.socket.connect((self.host, self.port))
                    data = self.socket.recv(1024)
                except:
                    print(bcolors.FAIL + "Connection to server {} failed".format(self.host) + bcolors.ENDC)
                    continue

                try: 
                    self.socket.send("USER {}\r\n".format(self.user).encode())
                    u = self.socket.recv(1024)
                    self.socket.send('PASS {}\r\n'.format(self.passwd).encode())
                    p = self.socket.recv(1024)
                    #Enter passive mode 
                    print(bcolors.OKBLUE + "[*] " + bcolors.ENDC + "Fuzzing {} with length ".format(command) + str(len(i)))
                    s = "{0} {1}\r\n".format(command, i)
                    self.socket.send(s.encode())
                    data = self.socket.recv(1024)
                    self.socket.send(b'QUIT\r\n')
                    self.socket.close()
                except:
                    print(bcolors.WARNING + "[-] " + bcolors.ENDC + "Crash String : command {0} with length {1}".format(command, len(i)))
                    self.error.append((command, len(i)))
                    self.stopafter -= 1
                    if self.stopafter <= 0 :
                        print(bcolors.WARNING + "[-] " + bcolors.ENDC + "Program not responding exiting now")
                        return

    def testConnection(self):
        """Test the connection with the server

        Returns:
            int : return True if the connection was successful and False otherwise
        """
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            print(bcolors.OKGREEN + "[*] " + bcolors.ENDC + "Connection to server {} succeed".format(self.host))
            return True
        except:
            print(bcolors.FAIL + "[*] " + bcolors.ENDC + "Connection to server {} failed".format(self.host))
            return False

    def printResult(self):
        """Print all the error get at the end
        """
        print(bcolors.OKBLUE + "*********** RESULT **********" + bcolors.ENDC)
        for i in self.error:
            print(bcolors.WARNING + "[-] " + bcolors.ENDC + "Crash String: Command {0} with length {1}".format(i[0],i[1]))


parser = argparse.ArgumentParser(description='FTP Fuzzer', epilog='How to use this Fuzzer')
parser.add_argument('-u', '--user', help='Username')
parser.add_argument('-d', '--delay', help="Delay between request", default=1)
parser.add_argument('--port', help='Server port')
parser.add_argument('--passwd', help='Password')
parser.add_argument('--host', help='Server Host')
parser.add_argument('-l', '--length', help="Buffer length", default=2000)
parser.add_argument('-s', '--stopafter', help="Stop after x error", default=1)
#Choose pre auth, by default not active
parser.add_argument("--pre", help="Pre authentication fuzzing", action="store_true")
arg = parser.parse_args()
print(arg)

stopafter = [ int(arg.stopafter) ]
fuzzer = fuzzer()
fuzzer.addValue(arg.host, arg.port, arg.user, arg.passwd, arg.length, arg.stopafter, arg.delay)
if arg.host == None:
    print(bcolors.WARNING + "Enter Host" + bcolors.ENDC)
    parser.print_help()
elif arg.pre:
    if not fuzzer.testConnection():
        exit(1)
    fuzzer.createBuffer()
    fuzzer.fuzzerLoopWithoutCommand()
    fuzzer.fuzzerLoopPreAuth()
    fuzzer.printResult()

elif arg.passwd == None:
    print(bcolors.WARNING + "Enter Password" + bcolors.ENDC)
    parser.print_help()
elif arg.user == None:
    print(bcolors.WARNING + "Enter Username" + bcolors.ENDC)
    parser.print_help()
else:
    if not fuzzer.testConnection():
        exit(1)
    fuzzer.createBuffer()
    fuzzer.fuzzerLoopWithoutCommand()
    fuzzer.fuzzerLoopPreAuth()
    fuzzer.fuzzerLoopPostAuth()
    fuzzer.printResult()
