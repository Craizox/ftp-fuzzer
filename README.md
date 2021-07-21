# Simple FTP Fuzzer

## Feature
That the most important feature

- Pre authentication test
- Change the buffer to single char, to Cyclic pattern or evilchar buffer
- Possibility to change the delay between each test 

## How To Use it

usage: ftp_fuzzer.py [--host] [options]

Options:
- --host              <value>     Host to connect to
- --passwd            <value>     Password of the FTP user
- --port              <value>     Port of the host
- --pre                           Launch the Fuzzer juts for the pre authentication
- -d, --delay         <delay>     Delay in second between each test
- -h, --help                      Show the help message
- -l, --length        <value>     Maximum size of the buffer send to the server
- -s, --stopafter     <value>     Number error before stoping
- -u, --user          <value>     Username of a FTP user