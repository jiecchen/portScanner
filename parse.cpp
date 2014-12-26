//
//  utils.cpp
//  portscanner
//
//  Created by Tony Liu on 11/2/14.
//  Copyright (c) 2014 Tony Liu. All rights reserved.
//

#include "parse.h"
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <iostream>
#include <sstream>
#include <stdarg.h>
#include <string.h>
#include <math.h>


/**
 * usage(FILE * file) -> void
 *
 * print the usage of this program to the file stream file
 *
 **/

void usage(FILE * file){
	if(file == NULL){
		file = stdout;
	}

	fprintf(file,
			"portScanner [option1, ..., optionN]\n"
			"  --help        \t Display this help screen\n"
			"  --ports <port1, ..., portN-portM>"
			"                \t Scan specified ports if there are.\n"
			"                \t Ports separated by a comma or a range. (dflt: 1 - 1024)\n"
			"  --ip <IP address to scan>"
			"                \t Scan an individual IP address.\n"
			"  --prefix <IP prefix to scan>"
			"                \t Scan an IP prefix.\n"
			"  --file <file name containing IP addresses to scan>"
			"                \t Scan a list of IP addresses from a file respectively.\n"
			"                \t The IP addresses in the file must be one on each line.\n"
			"                \t At least specify one of --ip, --prefix, --file.\n"
			"  --speedup <parallel threads to use>"
			"                \t Specify the number of threads to be used (dflt: one thread)\n"
			"  --scan <one or more scans>"
			"                \t Scan subset of these flags: SYN, NULL, FIN, XMAS, ACK, UDP (dflt: all scan)\n"
			"  --verbose     \t verbose, print additional verbose info\n");
    exit(EXIT_FAILURE);
}

/**
 *
 *
 * parse the command line arguments using getopt and
 * store the result in ps_args.
 *
 * ERRORS: Will exit on various errors
 *
 **/
void parse_args(ps_args_t * ps_args, int argc,  char * argv[]){
	int ch; //ch for each flag
	int nthread = 0;
	int option_index = 0;
	static struct option long_options[] = {
		{"help", no_argument, NULL, 'h'},
		{"ports", required_argument, NULL, 0},
		{"ip", required_argument, NULL, 'i'},
		{"prefix", required_argument, NULL, 0},
		{"file", required_argument, NULL, 'f'},
		{"speedup", required_argument, NULL, 0},
		{"scan", required_argument, NULL, 0},
		{"verbose", no_argument, NULL, 'v'},
		{0, 0, 0, 0}
	};
	//because there are some replicate short option, ban the short option
	//while ((ch = getopt_long_only (argc, argv, "h:i:f:v:1356", long_options, &option_index)) != -1){
	while ((ch = getopt_long(argc, argv, "hi::f::v1356", long_options, &option_index)) != -1){
        switch (ch) {
			case 0:
				switch (option_index) {
					case 1:
                        //ports
						parse_ports(ps_args->portList, optarg);
						break;
					case 3:
                        //ip prefix
                        if (NULL != optarg)
                            parse_prefix(ps_args->subnetIp, ps_args->prefixMask, optarg);
                        if ("" != ps_args->subnetIp && 0 != ps_args->prefixMask)
                            parse_prefix(ps_args->ipList, ps_args->subnetIp, ps_args->prefixMask);
						break;
					case 5:
                        //speedup
						nthread = atoi(optarg);
						if (0 < nthread)
							ps_args->nthread = nthread;
						else{
							fprintf(stderr,"ERROR: thread number %d must be more than one\n", nthread);
							exit(EXIT_FAILURE);
						}
						break;
					case 6:
                        //flags
                        for (int i = optind - 1; i <= argc - 1; i++){
                            if ('-' == argv[i][0]) break;
                            ps_args->flagList.push_back(argv[i]);
                            //parse_flags(ps_args->flagList, argv[i]);
                        }
						break;
					default:
						break;
				}
				break;
			case 'h':
				usage(stdout);
				break;
			case 'i':
                //ip list
				ps_args->ipList.push_back(optarg);
				break;
			case 'f':
                //ip list file
				ps_args->ipListFile = optarg;
				break;
			case 'v':
				ps_args->verbose = true;
                //printf("%c", ch);
				break;
            case ':':
                fprintf(stderr, "ERROR: %s: option '-%c' requires an argument\n",
                        argv[0], optopt);
            case '?':
                fprintf(stderr,"ERROR: unrecogize option -%c\n", optopt);
                exit(EXIT_FAILURE);
                break;
			default:
				usage(stdout);
				break;
		}
	}
    if(argc == 1){
        fprintf(stderr,"ERROR: require options\n");
        usage(stderr);
        exit(EXIT_FAILURE);
    }
    if (0 >= ps_args->ipList.size() && "\0" == ps_args->ipListFile){
        fprintf(stderr,"ERROR: at least specify one ip to scan\n");
        exit(EXIT_FAILURE);
    }
    if (0 >= ps_args->portList.size()){
        for (int i = 1; i <= MAX_SCAN_PORT; i++)
            ps_args->portList.push_back(i);
    }
    if (0 >= ps_args->flagList.size()){
        ps_args->flagList.push_back("ACK");
        ps_args->flagList.push_back("FIN");
        ps_args->flagList.push_back("NULL");
        ps_args->flagList.push_back("SYN");
        ps_args->flagList.push_back("UDP");
        ps_args->flagList.push_back("XMAS");
    }
	return ;
}
 
void parse_ip_file(std::list<std::string> &ipList, void * buffer, int buffersize){
    /*
    std::istringstream ss((char*)buffer);
    //std::string tmp = "\0";
    //while (std::getline(ss, tmp, '\n')){
    for (std::string line; std::getline(ss, line, '\n'); ){
        if (std::string::npos != line.find("."))
            ipList.push_back(line);
        line = "\0";
        //buffersize -= tmp.size();
    }
     */
    std::string str = static_cast<char*>(buffer);
    str += "\n";
    size_t pos = str.find_first_of("\n");
    std::string tmp = "\0";
    //std::cout << str.size() << " " << buffersize << " "<<tmp <<std::endl;
    while (std::string::npos != pos){
        tmp = str.substr(0, pos);
    
        ipList.push_back(tmp);
        str = str.substr(pos + 1, str.length() - pos);
        if (0 >= str.size()) break;
        //buffersize -= tmp.size();
        pos = str.find_first_of("\n");
        
        //std::cout << str.size() << " " << buffersize << " "<<tmp <<std::endl;
    }
}
//parse ports string, separated by comma or range
void parse_ports(std::list<int> &portList, std::string str){
    if ("\0" == str){
        return;
    }
    //if there is just one port
    if (std::string::npos == str.find(",") && std::string::npos == str.find("-")){
        portList.push_back(atoi(str.c_str()));
    }
    else if (std::string::npos != str.find(",")){
        //then parse ports are separated by comma
        size_t pos = str.find_first_of(",");
        std::string tmp = "\0";
        
        while (std::string::npos != pos){
            tmp = str.substr(0, pos);
            
            //TODO when push, there might be duplicate items in the list
            if (std::string::npos != tmp.find("-")){
                parse_range_ports(portList, tmp);
            }
            else{
                portList.push_back(atoi(tmp.c_str()));
            }
            str = str.substr(pos + 1, str.length() - pos);
            pos = str.find(",");
            
            //std::cout << str << " " << pos << " "<<tmp <<std::endl;
        }
	if (std::string::npos == str.find("-"))
	  parse_ports(portList, str);

    }
    //parse ports separated by range
    if (std::string::npos != str.find("-")){
        parse_range_ports(portList, str);
    }
}

void parse_range_ports(std::list<int> &portList, std::string str){
    //if empty, do nothing
    if ("\0" == str || "-" == str)
        return;
    else{
        //parse the begin and end of the range, then add every port between
        std::string strfirst = str.substr(0, str.find_first_of("-"));
        std::string strlast = str.substr(str.find_first_of("-") + 1, str.length() - str.find_first_of("-"));
        if ("\0" == strfirst && "\0" != strlast)
            portList.push_back(atoi(strlast.c_str()));
        else if ("\0" != strfirst && "\0" == strlast)
            portList.push_back(atoi(strfirst.c_str()));
        else{
            for (int i = atoi(strfirst.c_str()); i <= atoi(strlast.c_str()); i++)
                portList.push_back(i);
        }
    }
}
void parse_prefix(std::string &subnetIp, int &prefixMask, std::string str){
    if ("\0" == str)
        return;
    else{
        size_t pos = str.find("/");
        if (std::string::npos == pos){
            fprintf(stderr,"ERROR: prefix input error, should be <ip/mask>\n");
            return;
        }
        subnetIp = str.substr(0, pos);
        prefixMask = atoi(str.substr(pos + 1, str.length() - pos - 1).c_str());
    }
}

void parse_prefix(std::list<std::string> &ipList, const std::string subnetIp, const int prefixMask){
    if ("\0" != subnetIp && 0 != prefixMask){
        ssize_t pos = subnetIp.find_last_of(".");
        std::string ipprefix = subnetIp.substr(0, pos + 1);
        int lastdigit = atoi(subnetIp.substr(pos + 1, subnetIp.size() - pos - 1).c_str());
        std::stringstream ss;
        int netmask = (int)pow(2, MAX_NETMASK - prefixMask);
        for (int i = 0; i < netmask; i++){
            ss << ipprefix << lastdigit + i;
            ipList.push_back(ss.str());
            ss.str("");
        }
    }
}

// std::vector<ps_task_t> build_task_queue(ps_args_t ps_args){
//     std::vector<ps_task_t> ps_task_queue;
//     std::list<std::string>::iterator it_ip;
//     std::list<int>::iterator it_port;
//     std::list<std::string>::iterator it_flag;
//     for (it_ip = ps_args.ipList.begin(); it_ip != ps_args.ipList.end(); it_ip++){
//         for (it_port = ps_args.portList.begin(); it_port != ps_args.portList.end(); it_port++){
//             for (it_ip = ps_args.flagList.begin(); it_ip != ps_args.flagList.end(); it_ip++){
//                 ps_task_t ps_task;
//                 ps_task.ip = *it_ip;
//                 ps_task.port = *it_port;
//                 ps_task.flag = *it_flag;
//                 //port 1-1024 has service name
//                 if (ps_task.port > 0 && ps_task.port < 1025){
//                     if ( "" != serviceName[ps_task.port])
//                         ps_task.serviceName = serviceName[ps_task.port];
//                 }
//                 ps_task_queue.push_back(ps_task);
//             }
//         }
//     }
//     return ps_task_queue;
// }
