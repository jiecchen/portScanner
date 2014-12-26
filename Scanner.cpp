
#include "Scanner.h"
#include "utils.h"
#include "parse.h"
#include <iostream>








Scanner::Scanner() {
  // Create a raw socket
  this->s = socket (AF_INET, SOCK_RAW , IPPROTO_TCP);
  if(s < 0) {
    printf ("Error creating socket. Error number : %d . Error message : %s \n" , 
	    errno , strerror(errno));
    exit(0);
  }
  else {
    //printMSG("Socket created.\n");
  }


  // setup IP/TCP/UDP Headers
  this->iph = (struct iphdr *) packet;
  this->tcph = (struct tcphdr *) (packet + sizeof(struct ip));
  this->udph = (struct udphdr *) (packet + sizeof(struct ip));

  // setup local ip address
  char buf[20];
  get_local_ip(buf);
  //  printMSG("Local IP is %s \n", buf);
  this->source_ip.s_addr = inet_addr(buf);

  // index ports, use fixed port-scantype pair
  for (int i = SYNScan; i <= UDPScan; ++i) {
    ScanType t = (ScanType) i;
    port2scan[SourcePorts[t]] = t;
  }
  

   
  //IP_HDRINCL to tell the kernel that headers are included in the packet
  int one = 1;
  const int *val = &one;
  if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0) {
    printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , 
	    errno , strerror(errno));
    exit(0);
  }     


  // setup recv socket
  this->setupRecvSocket(TIMEOUT_S);
  
  // finally, clear map
  resultsMap.clear();

}


// test if given ip-port-scan_mode has be marked
bool Scanner::markedQ(std::string ip_addr, int port, ScanType mode) {
  struct in_addr dest_ip;
  dest_ip.s_addr = resolve_to_ip((char *) ip_addr.c_str());
  uint16_t d_port = htons(port);
  if (resultsMap.find(dest_ip.s_addr) != resultsMap.end() 
      && resultsMap[dest_ip.s_addr].find(d_port) != resultsMap[dest_ip.s_addr].end()
      && resultsMap[dest_ip.s_addr][d_port].find(mode) != resultsMap[dest_ip.s_addr][d_port].end()) {
    ResultType res = resultsMap[dest_ip.s_addr][d_port][mode];
    //    printMSG("I am inside markedQ\n");
    switch (mode) {
    case SYNScan:
      return res != Filtered;
    case ACKScan:
      return res != Filtered;
    case UDPScan:
      return res != Open_or_Filtered;
    default:
      return res != Open_or_Filtered;
    }
  }
  else {
    return false;
  }
}


void Scanner::sendPackets(std::string ip_addr, int port, ScanType mode) {
  // setup dest ip
  struct in_addr dest_ip;
  dest_ip.s_addr = resolve_to_ip((char *) ip_addr.c_str());

  // setup local port
  int source_port = SourcePorts[mode];

  // TCP or IP
  int packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr);
  uint16_t d_port;
  // construct  packet
  memset(packet, 0, PACKET_SIZE);
  switch (mode) {
    case SYNScan:
      constructSYNPacket(this->iph, this->tcph, source_ip, dest_ip, source_port, port);
      d_port = this->tcph->dest;
      break;
    case NULLScan:
      constructNULLPacket(this->iph, this->tcph, source_ip, dest_ip, source_port, port);
      d_port = this->tcph->dest;
      break;
    case FINScan:
      constructFINPacket(this->iph, this->tcph, source_ip, dest_ip, source_port, port);
      d_port = this->tcph->dest;
      break;
    case XmasScan:
      constructXmasPacket(this->iph, this->tcph, source_ip, dest_ip, source_port, port);
      d_port = this->tcph->dest;
      break;
    case ACKScan:
      constructACKPacket(this->iph, this->tcph, source_ip, dest_ip, source_port, port);
      d_port = this->tcph->dest;
      break;
  default: // TODO: DNS
      constructUDPPacket(this->iph, this->udph, source_ip, dest_ip, source_port, port);
      packet_size = sizeof(struct iphdr) + sizeof(struct udphdr);
      d_port = this->udph->dest;
      break;
  }


  // send the packet
  struct sockaddr_in dest;
  dest.sin_family = AF_INET;
  dest.sin_addr.s_addr = dest_ip.s_addr;
  if ( sendto (this->s, packet , packet_size, 
	       0 , (struct sockaddr *) &dest, sizeof (dest)) < 0) {
    printf ("Error sending syn packet. Error number : %d . Error message : %s \n" , 
	    errno , strerror(errno));
    exit(0);
  }




  //Initialize the ResultMap or return
  if (resultsMap.find(iph->daddr) != resultsMap.end() 
      && resultsMap[iph->daddr].find(d_port) != resultsMap[iph->daddr].end()
      && resultsMap[iph->daddr][d_port].find(mode) != resultsMap[iph->daddr][d_port].end()) {
    // has already been inserted
    // do nothing
  }
  else {
    printMSG("Packet sent to %s  Port %d\n", inet_ntoa((const struct in_addr&) iph->daddr), ntohs(d_port));
    switch (mode) {
    case SYNScan:
      resultsMap[iph->daddr][d_port][mode] = Filtered;
      break;
    case ACKScan:
      resultsMap[iph->daddr][d_port][mode] = Filtered;
      break;
    case UDPScan:
      resultsMap[iph->daddr][d_port][mode] = Open_or_Filtered;
      break;
    default:
      resultsMap[iph->daddr][d_port][mode] = Open_or_Filtered;
    }
  }

}




// setup a new recv socket, specify timeout
void Scanner::setupRecvSocket(int timeout) {
  // create a new raw socket
  this->r = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
  if(this->r < 0) {
    printf("Socket Error\n");
    fflush(stdout);
    exit(1);
  }

  // setup timeout
  struct timeval tv;
  tv.tv_sec = timeout;
  tv.tv_usec = 0;

  if (setsockopt(this->r, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
    perror("Failed to setup timeout!\n");
    exit(0);
  }

}



// recv and analyse the packet
bool Scanner::recvPackets() {
  unsigned char buffer[BUF_SIZE];
  struct sockaddr saddr;
  socklen_t saddr_size = sizeof(saddr);
  int data_size;


  //Receive a packet
  data_size = recvfrom(this->r, buffer, BUF_SIZE, 0 , &saddr , &saddr_size);
    
  if(data_size < 0) {
    return false;
  }   
  else {
    //Now process the packet
    process_packet(buffer, data_size);
    return true;
  }

}




// given the packet, analyze the packet, keep the analyzed result
void Scanner::process_packet(unsigned char* buffer, int size) {
  //Get the IP Header part of this packet
  struct iphdr *iph = (struct iphdr*)buffer;
  unsigned short iphdrlen;
  iphdrlen = iph->ihl * 4;


  if (resultsMap.find(iph->saddr) == resultsMap.end()) { // come from an unknow ip
    return;
  }

     
  if(iph->protocol == IPPROTO_TCP) {  // TCP Protocol
    struct tcphdr *tcph = (struct tcphdr *) (buffer + iphdrlen);             
    analyzeTCPHeader(tcph, resultsMap[iph->saddr]);   
  }
  else if (iph->protocol == IPPROTO_ICMP) { // ICMP Protocol
    printMSG("I got an ICMP packet\n");
    struct icmphdr *icmph = (struct icmphdr *) (buffer + iphdrlen);
    analyzeICMPHeader(icmph, resultsMap[iph->saddr]);
  }
  else if (iph->protocol == IPPROTO_UDP) { // UDP Protocol
    printMSG("I got an UDP packet\n");
    struct udphdr *udph = (struct udphdr *) (buffer + iphdrlen);
    analyzeUDPHeader(udph, resultsMap[iph->saddr]);
    //return NoResult;
  }
}




Scanner::~Scanner() {
  close(this->s);
  close(this->r);
}




//  given tcp header and scan mode, return the analyzed result
ResultType Scanner::analyzeTCPHeader(struct tcphdr *tcph, TPortsDict &portsDict) {
  int d_port = ntohs(tcph->dest);
  ScanType scan_mode;

  if (port2scan.find(d_port) != port2scan.end()) {
    scan_mode = port2scan[d_port];
  }
  else { // packet sent to unknown port
    return NoResult;
  }


  // check if packet responde to packet we sent
  if (portsDict.find(tcph->source) != portsDict.end() 
      && portsDict[tcph->source].find(scan_mode)!= portsDict[tcph->source].end()) { // do nothing
  }
  else { // not packet responses to our packet
    return NoResult;
  }


  printMSG("Analyzing TCP Header ... Sent to Port %d\n", d_port);

  switch (scan_mode) {
  case SYNScan:
    if (tcph->syn == 1) {  // feedback for syn packet
      portsDict[tcph->source][scan_mode] = Open;
      return Open;
    }
    else {
      return NoResult;
    }
    break;
  case ACKScan:
    if (tcph->rst == 1) {
      portsDict[tcph->source][scan_mode] = Unfiltered;
    return Unfiltered;
    }
    else {
      return NoResult;
    }

    break;
  case UDPScan:
    return NoResult;
    break;
  default: // FIN, NULL, Xmas
    if (tcph->rst == 1) {   // if return rst then port is closed
      portsDict[tcph->source][scan_mode] = Closed;
      return Closed;
    }
    else {
      return NoResult;
    }
    break;
  }
} 




//
ResultType Scanner::analyzeICMPHeader(struct icmphdr *icmph, TPortsDict &portsDict) {
  
  if (icmph->type != 3 || (icmph->code != 1 
      && icmph->code != 2 && icmph->code != 3
      && icmph->code != 9 && icmph->code != 10
			   && icmph->code != 13)) 
    return NoResult;
  
  // extract the port
  struct iphdr *iph = (struct iphdr *) ((char *) icmph + 8);
  struct tcphdr *tcph = (struct tcphdr *) ((char *) iph + sizeof(struct ip));
  struct udphdr *udph = (struct udphdr *) tcph;
  int port = ntohs(tcph->source);
  ScanType scan_mode;
  if (port2scan.find(port) != port2scan.end()) {
    scan_mode = port2scan[port];
  }
  else { // not packet responses to ourpaket
    return NoResult;
  }


  uint16_t d_port = tcph->dest;
  if (scan_mode == UDPScan) {
    d_port = udph->dest;
  }

  // check if packet responde to packet we sent
  if (portsDict.find(d_port) != portsDict.end() 
      && portsDict[d_port].find(scan_mode)!= portsDict[d_port].end()) { // do nothing
  }
  else { // not packet responses to our packet
    return NoResult;
  }

  printMSG("Analyzing TCMP Header ... Sent to Port %d\n", port);

  if(scan_mode == UDPScan) { // UDP
    if (icmph->code == 3) {
      portsDict[d_port][scan_mode] = Closed;
    }
    else {
      portsDict[d_port][scan_mode] = Filtered;
    }
  }
  else { // TCP
    portsDict[d_port][scan_mode] = Filtered;
  }
  return Filtered;
}




ResultType Scanner::analyzeUDPHeader(struct udphdr *udph, TPortsDict &portsDict) {
  int port = ntohs(udph->source);
  ScanType scan_mode;
  if (port2scan.find(port) != port2scan.end()) {
    scan_mode = port2scan[port];
  }
  else { // not packet responses to ourpaket
    return NoResult;
  }

  // check if packet response to packet we sent
  if (portsDict.find(udph->source) != portsDict.end() 
      && portsDict[udph->source].find(scan_mode)!= portsDict[udph->source].end()) { // do nothing
  }
  else { // not packet responses to our packet
    return NoResult;
  }

  printMSG("Analyzing UDP Header ... Sent to Port %d\n", port);
  portsDict[udph->source][scan_mode] = Open;
  return Open;
}




void Scanner::showResults() {
  TIPDict::iterator ipit;
  for (ipit = resultsMap.begin(); ipit != resultsMap.end(); ++ipit) {
    printf("==========================================\nIP %s:\n", inet_ntoa((const struct in_addr&) (ipit->first)));
    
    verifyStdServices(inet_ntoa((const struct in_addr&) (ipit->first)));
    

    TPortsDict::iterator portit;

    printf("Open Ports:\n---------------------------------------\n");
    for (portit = ipit->second.begin(); portit != ipit->second.end(); ++portit) {
      TResult::iterator resit;
      // infer conclusion
      ResultType conclusion = Open_or_Filtered;
      for (resit = portit->second.begin(); resit != portit->second.end(); ++resit) {
	if (resit->second == Open) 
	  conclusion = Open;
	else if (resit->second == Unfiltered && conclusion != Open) 
	  conclusion = Unfiltered;
	else if (conclusion == Open_or_Filtered && (resit->second == Filtered || resit->second == Open))
	  conclusion = resit->second;
      }
      if (conclusion != Open)
	continue;
      printf("Conclusion on Port %d: %s      Service Name: %s\n", ntohs(portit->first), resultNames[conclusion].c_str(), getServiceName(ntohs(portit->first)).c_str());
      
      
      printf("Detailed Results: ");
      for (resit = portit->second.begin(); resit != portit->second.end(); ++resit)
	printf("%16s", typeNames[resit->first].c_str());
      printf("\n%18s"," ");
      for (resit = portit->second.begin(); resit != portit->second.end(); ++resit) 
	printf("%16s", resultNames[resit->second].c_str());
      printf("\n");
    }


    printf("\nClosed/Filtered/Unfiltered:\n---------------------------------------\n");
    for (portit = ipit->second.begin(); portit != ipit->second.end(); ++portit) {
      TResult::iterator resit;
      // infer conclusion
      ResultType conclusion = Open_or_Filtered;
      for (resit = portit->second.begin(); resit != portit->second.end(); ++resit) {
	if (resit->second == Open) 
	  conclusion = Open;
	if (resit->second == Closed && conclusion != Open)
	  conclusion = Closed;
	if (resit->second == Unfiltered && conclusion != Open && conclusion != Closed) 
	  conclusion = Unfiltered;
	if (conclusion == Open_or_Filtered && (resit->second == Filtered || resit->second == Open))
	  conclusion = resit->second;
      }
      if (conclusion == Open)
	continue;
      printf("Conclusion on Port %d: %s      Service Name: %s\n", ntohs(portit->first), resultNames[conclusion].c_str(), getServiceName(ntohs(portit->first)).c_str());
      
      
      printf("Detailed Results: ");
      for (resit = portit->second.begin(); resit != portit->second.end(); ++resit)
	printf("%16s", typeNames[resit->first].c_str());
      printf("\n%18s"," ");
      for (resit = portit->second.begin(); resit != portit->second.end(); ++resit) 
	printf("%16s", resultNames[resit->second].c_str());
      printf("\n");
    }
  }
}



















