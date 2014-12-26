#ifndef __SCANNER_H_
#define __SCANNER_H_

#include <stdio.h> 
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include <netinet/tcp.h>   // tcp header
#include <netinet/udp.h>   // udp header
#include <netinet/ip.h>    // ip header
#include <netinet/ip_icmp.h>   // icmp header
#include <vector>
#include <map>
#include <iostream>

#include "types.h"


const int PACKET_SIZE = 1024 << 2;
const int BUF_SIZE = 65536;
const int TIMEOUT_S = 4;
const int MAX_TRY = 3;


const int SourcePorts[] = {43590, 43591, 43592, 43593, 43594, 43595, 43596};
const ScanType allTypes[] = {SYNScan, NULLScan, FINScan, ACKScan, XmasScan, UDPScan};
const std::string typeNames[] = {"SYN", "NULL", "FIN", "ACK", "Xmas", "UDP"};
const std::string resultNames[] = {"NoResult", "NoResponse", "Open", "Closed", "Filtered", "Unfiltered", "Open|Filtered"};















class Scanner {
 public:
  Scanner();
  void sendPackets(RecordIter);  // send packets
  void sendPackets(std::string ip, int port, ScanType mode = SYNScan);  // send packets
  bool recvPackets(); // recv and analyze packets
  bool markedQ(std::string ip_addr, int port, ScanType mode); // test if given ip-port-mode marked
  void showResults();
  ~Scanner();
 private:
  void process_packet(unsigned char* buf, int size);
  void setupRecvSocket(int timeout = 4); // setup a new recv socket
  ResultType analyzeTCPHeader(struct tcphdr *tcph, TPortsDict &portsDict);
  ResultType analyzeICMPHeader(struct icmphdr *icmph, TPortsDict &portsDict);
  ResultType analyzeUDPHeader(struct udphdr *udph, TPortsDict &portsDict);


  struct in_addr source_ip;
  char packet[PACKET_SIZE];  // char[] to represent the packet
  int s; // raw send socket
  int r; // raw recv socket
  struct iphdr *iph; // IP Header
  struct tcphdr *tcph; // TCP Header
  struct udphdr *udph;// udp Header
  TIPDict resultsMap;
  TPort2Scan port2scan;
};





#endif














