# P538 Project: portScanner

## Developers
- Jiecao Chen (jiecchen@indiana.edu)
- Tony Liu (xl41@indiana.edu)

## How to Compile
In the root of the source code, run

	$ make

which will generate an excutable file `portScanner`.

## How to Use
Plese note, running `portScanner` **requires root privileges**.
To get the help information, run

	$ sudo ./portScanner --help

which prints out

	portScanner [option1, ..., optionN]
	--help        	 Display this help screen
	--ports <port1, ..., portN-portM>
		Scan specified ports if there are.
		Ports separated by a comma or a range. (dflt: 1 - 1024)
	--ip <IP address to scan>
		Scan an individual IP address.
	--prefix <IP prefix to scan>
		Scan an IP prefix.
	--file <file name containing IP addresses to scan>
		Scan a list of IP addresses from a file respectively.
		The IP addresses in the file must be one on each line.
		At least specify one of --ip, --prefix, --file.
	--speedup <parallel threads to use>
		Specify the number of threads to be used (dflt: one thread)
	--scan <one or more scans>
		Scan subset of these flags: SYN, NULL, FIN, XMAS, ACK, UDP (dflt: all scan)
	--verbose
		verbose, print additional verbose info

 An example to run `portScanner` on Ubuntu 14.04

	sudo ./portScanner --ip 129.79.247.87 --ports 1-5,22 --speedup 5 --scan ACK SYN

its output

	Creating 5 threads ...
    Scanning ...
    ==========================================
    IP 129.79.247.87:
    Open Ports:
    ---------------------------------------
    Conclusion on Port 22: Open      Service Name: SSH-2.0-OpenSSH_5.3

    Detailed Results:              SYN             ACK
                                  Open      Unfiltered

    Closed/Filtered/Unfiltered:
	---------------------------------------
	Conclusion on Port 1: Unfiltered      Service Name: tcpmux
	Detailed Results:              SYN             ACK
       		                  Filtered      Unfiltered
	Conclusion on Port 2: Unfiltered      Service Name: compressnet
	Detailed Results:              SYN             ACK
		                      Filtered      Unfiltered
	Conclusion on Port 3: Unfiltered      Service Name: compressnet
	Detailed Results:              SYN             ACK
                          Filtered      Unfiltered
	Conclusion on Port 4: Unfiltered      Service Name: 
	Detailed Results:              SYN             ACK
                              Filtered      Unfiltered
	Conclusion on Port 5: Unfiltered      Service Name: rje
	Detailed Results:              SYN             ACK
                              Filtered      Unfiltered
								   

### Specify Ports: --ports
Ports `1,2,3,5` can be specified in two ways

	--ports 1-3,5

or literately,

	--ports 1,2,3,5



### Specify IP Addresses: --ip
To specify ip addresses/hostname, you can either specify in the command line (only one ip)

	--ip dagwood.soic.indiana.edu

or read from file when multiple ip addresses have to be scanned

	--file ips.txt

where in `ips.txt`, assume we have
	
	blondie.soic.indiana.edu
	www.google.com	
	129.79.247.87


## Brief Description of Source Files

### CFileOperation.[h|cpp]
  support file I/O operation

### parse.[h|cpp]
  parse the command line arguments
  
### Records.h
  define a class `Records`, used as processing queue

### Scanner.[h|cpp]
  major class to support ports scan

### types.h
  pre-define  several new types

### utils.[h|cpp]
  a various of supporting functions, parse the hostname, output formatting, standard service verifying, etc.

### portScanner.cpp
  main file, multi-threads supports added here

## Reference

+ http://en.cppreference.com/
+ http://www.binarytides.com/tcp-syn-portscan-in-c-with-linux-sockets/
+ http://www.binarytides.com/raw-udp-sockets-c-linux/
+ http://en.wikipedia.org/ for TCP UDP ICMP headers
+ Computer Networking: A Top-Down Approach (6th Edition)
+ http://stackoverflow.com/


