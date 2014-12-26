#include "utils.h"
#include "parse.h"
#include <errno.h>
#include <fcntl.h>
#include <thread>
#include <mutex>

extern bool VERBOSE;

in_addr_t resolve_to_ip(char *addr) {
  if ( inet_addr(addr) != (in_addr_t)-1 ) {
    return inet_addr(addr);
  }
  char *ip = hostname_to_ip(addr);
  if (ip != NULL) {
    // printMSG("%s resolved to %s \n", addr, ip);
    return inet_addr(ip);
  }
  else {
    printMSG("Unable to resolve: %s", addr);
    exit(1);
  }
}



// Get ip from domain name
char* hostname_to_ip(char * hostname)
{
  struct hostent *he;
  struct in_addr **addr_list;
  int i;
  
  if ( (he = gethostbyname( hostname ) ) == NULL) {
    // get the host info
    herror("gethostbyname");
    printMSG("I am unable to resolve %s \n", hostname);
    return NULL;
  }
 
  addr_list = (struct in_addr **) he->h_addr_list;
     
  for(i = 0; addr_list[i] != NULL; i++) 
    {
      //Return the first one;
      return inet_ntoa(*addr_list[i]) ;
    }
 
  return NULL;
}


// this function copy from the Internet
int get_local_ip (char * buffer)
{
  int sock = socket ( AF_INET, SOCK_DGRAM, 0);
 
  const char* kGoogleDnsIp = "8.8.8.8";
  int dns_port = 53;
  
  struct sockaddr_in serv;
  
  memset( &serv, 0, sizeof(serv) );
  serv.sin_family = AF_INET;
  serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
  serv.sin_port = htons( dns_port );
 
  int err = connect( sock , (const struct sockaddr*) &serv , sizeof(serv) );
 
  struct sockaddr_in name;
  socklen_t namelen = sizeof(name);
  err = getsockname(sock, (struct sockaddr*) &name, &namelen);
  
  const char *p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);
 
  close(sock);
  //  printMSG("Local source IP is %s \n", buffer);
  return 0;
}


unsigned short csum(unsigned short *ptr,int nbytes) 
{
  register long sum;
  unsigned short oddbyte;
  register short answer;
  
  sum=0;
  while(nbytes>1) {
    sum+=*ptr++;
    nbytes-=2;
  }
  if(nbytes==1) {
    oddbyte=0;
    *((u_char*)&oddbyte)=*(u_char*)ptr;
    sum+=oddbyte;
  }
  
  sum = (sum>>16)+(sum & 0xffff);
  sum = sum + (sum>>16);
  answer=(short)~sum;
  
  return(answer);
}



bool printMSG(std::string msg) {
    if (VERBOSE) {
      puts(msg.c_str());
    }
    return VERBOSE && !msg.empty();
}

bool printMSG(const char *fmt, ...) {
    if (!VERBOSE) return false;
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    return true;
}




void constructSYNPacket(struct iphdr *iph, struct tcphdr *tcph, struct in_addr source_ip, 
			struct in_addr dest_ip, int s_port, int d_port) {
  //IP Header
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
  iph->id = htons (54321); //Id of this packet
  iph->frag_off = htons(16384);
  iph->ttl = 64;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0;      //Set to 0 before calculating checksum
  iph->saddr = source_ip.s_addr;
  iph->daddr = dest_ip.s_addr;   
  iph->check = csum ((unsigned short *) iph, iph->tot_len >> 1);

  //TCP Header
  tcph->source = htons(s_port);
  tcph->dest = htons(d_port);
  tcph->seq = htonl(1105024978);
  tcph->ack_seq = 0;
  tcph->doff = sizeof(struct tcphdr) / 4;      //Size of tcp header
  tcph->fin=0;
  tcph->syn=1;
  tcph->rst=0;
  tcph->psh=0;
  tcph->ack=0;
  tcph->urg=0;
  tcph->window = htons(14600);  // maximum allowed window size
  tcph->check = 0;
  tcph->urg_ptr = 0;
  
  // now we need to calc the tcp checksum
  calcTCPCheckSums(tcph, source_ip, dest_ip);
}
 



void constructNULLPacket(struct iphdr *iph, struct tcphdr *tcph, struct in_addr source_ip, 
			struct in_addr dest_ip, int s_port, int d_port) {
  constructSYNPacket(iph, tcph, source_ip, dest_ip, s_port, d_port);
  tcph->syn = 0;
  tcph->check = 0;  
  // re-calc the checksums
  calcTCPCheckSums(tcph, source_ip, dest_ip);
}

void constructFINPacket(struct iphdr *iph, struct tcphdr *tcph, struct in_addr source_ip, 
			struct in_addr dest_ip, int s_port, int d_port) {
  constructSYNPacket(iph, tcph, source_ip, dest_ip, s_port, d_port);
  tcph->syn = 0;
  tcph->fin = 1;
  tcph->check = 0;  
  // re-calc the checksums
  calcTCPCheckSums(tcph, source_ip, dest_ip);
}

void constructXmasPacket(struct iphdr *iph, struct tcphdr *tcph, struct in_addr source_ip, 
			struct in_addr dest_ip, int s_port, int d_port) {
  constructSYNPacket(iph, tcph, source_ip, dest_ip, s_port, d_port);
  tcph->syn = 0;
  tcph->psh = 1;
  tcph->fin = 1;
  tcph->urg = 1;
  tcph->check = 0;  
  // re-calc the checksums
  calcTCPCheckSums(tcph, source_ip, dest_ip);
}

void constructACKPacket(struct iphdr *iph, struct tcphdr *tcph, struct in_addr source_ip, 
			struct in_addr dest_ip, int s_port, int d_port) {
  constructSYNPacket(iph, tcph, source_ip, dest_ip, s_port, d_port);
  tcph->syn = 0;
  tcph->ack = 1;
  tcph->check = 0;  
  // re-calc the checksums
  calcTCPCheckSums(tcph, source_ip, dest_ip);
}


void constructUDPPacket(struct iphdr* iph, struct udphdr* udph, struct in_addr source_ip,
			struct in_addr dest_ip, int s_port, int d_port) {
  //IP header     
  // struct sockaddr_in sin;
  struct pseudo_header_udp psh;
  
  //Data part
  char *data = (char *)udph + sizeof(struct udphdr);
  strcpy(data, "I'm Jiecao Chen");
  
     
     
  //Fill in the IP Header
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data);
  iph->id = htonl(54321); //Id of this packet
  iph->frag_off = 0;
  iph->ttl = 255;
  iph->protocol = IPPROTO_UDP;
  iph->check = 0;      //Set to 0 before calculating checksum
  iph->saddr = source_ip.s_addr;
  iph->daddr = dest_ip.s_addr;
     
  //Ip checksum
  iph->check = csum ((unsigned short *) iph, iph->tot_len);
  
  //UDP header
  udph->source = htons(s_port);
  udph->dest = htons(d_port);
  udph->len = htons(8 + strlen(data)); //udp header size
  udph->check = 0; 
  
  //Now the UDP checksum using the pseudo header
  psh.source_address = source_ip.s_addr;
  psh.dest_address = dest_ip.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_UDP;
  psh.udp_length = htons(sizeof(struct udphdr) + strlen(data));
     
  int psize = sizeof(struct pseudo_header_udp) + sizeof(struct udphdr) + strlen(data);
  char pseudogram[psize];
  
  memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header_udp));
  memcpy(pseudogram + sizeof(struct pseudo_header_udp), udph , sizeof(struct udphdr) + strlen(data));
     
  udph->check = csum( (unsigned short*) pseudogram , psize);
}




// calc the checksum
void calcTCPCheckSums(struct tcphdr *tcph, struct in_addr source_ip, struct in_addr dest_ip) {
  struct pseudo_header psh;
  psh.source_address = source_ip.s_addr;
  psh.dest_address = dest_ip.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(sizeof(struct tcphdr));
  memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));       
  tcph->check = csum( (unsigned short*) &psh , sizeof(struct pseudo_header));
}


static std::map<int, std::string> stdServiceNames;
std::mutex myMutex;


int conn_nonb(struct sockaddr_in sa, int sock, int timeout = 1) {   
  //return connect(sock, (struct sockaddr *)&sa, 16);
  int flags = 0, error = 0, ret = 0;
  fd_set  rset, wset;
  socklen_t   len = sizeof(error);
  struct timeval  ts;
    
  ts.tv_sec = timeout;
  ts.tv_usec = 0;
    
  //clear out descriptor sets for select
  //add socket to the descriptor sets
  FD_ZERO(&rset);
  FD_SET(sock, &rset);
  wset = rset;    //structure assignment ok
    
  //set socket nonblocking flag
  if( (flags = fcntl(sock, F_GETFL, 0)) < 0)
    return -1;
    
  if(fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0)
    return -1;
    
  //initiate non-blocking connect
  if( (ret = connect(sock, (struct sockaddr *)&sa, 16)) < 0 )
    if (errno != EINPROGRESS)
      return -1;

  if(ret == 0)    //then connect succeeded right away
    goto done;
    
  //we are waiting for connect to complete now
  if( (ret = select(sock + 1, &rset, &wset, NULL, (timeout) ? &ts : NULL)) < 0)
    return -1;
  if(ret == 0){   //we had a timeout
    errno = ETIMEDOUT;
    return -1;
  }

  //we had a positivite return so a descriptor is ready
  if (FD_ISSET(sock, &rset) || FD_ISSET(sock, &wset)){
    if(getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
      return -1;
  }else
    return -1;

  if(error){  //check if we had a socket error
    errno = error;
    return -1;
  }

 done:
  //put socket back in blocking mode
  if(fcntl(sock, F_SETFL, flags) < 0)
    return -1;

  return 0;
}


std::string extractVersion(std::string rawData, int port) {
  switch (port) {
  case 80:
    std::size_t st, ed;
    st = rawData.find("<address>");
    ed = rawData.find("</address>");
    if (st != std::string::npos && ed != std::string::npos) {
      return rawData.substr(st + 9, ed - st - 9);
    }
    else
      return "Http: unknow version";
  default:
    return rawData;
  }
}

bool verify(const char* addr, int port, std::string sendData, int timeout = 1) {
  struct sockaddr_in address;  
  int sock = -1;         
  fd_set fdset;
  struct timeval tv;
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = inet_addr(addr); 
  address.sin_port = htons(port);            
  tv.tv_sec = timeout;        
  tv.tv_usec = 0;

  sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  printMSG("   Verifying Standard Service on Port %d ...\n", port);
  if (conn_nonb(address, sock, 2) == 0) {
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    int M = 1000;
    char buffer[M];
    if (sendData != "") { // need to send data
      bzero(buffer, M);
      strcpy(buffer, sendData.c_str());
      sendto(sock, buffer, strlen(buffer), 0,
             (struct sockaddr *)&address, sizeof(address));
    }
    bzero(buffer, M);
    //printMSG("Now I am recving data... from port %d\n", port);
    int n = recvfrom(sock, buffer, M, 0, NULL, NULL);
    //printMSG("Recv: %s\n", buffer);
    myMutex.lock();
    stdServiceNames[port] = extractVersion(std::string(buffer), port);
    myMutex.unlock();
  }
  close(sock);
  return true;
}


void verifyStdServices(std::string ip_addr) {
  
  // verify services run on port 22, 24, 43, 80, 110, 143
  std::thread t1(verify, ip_addr.c_str(), 22, "", 2);
  std::thread t2(verify, ip_addr.c_str(), 24, "", 2);
  std::thread t3(verify, ip_addr.c_str(), 43, "", 2);
  std::thread t4(verify, ip_addr.c_str(), 80, "GET / HTTP/1.1\r\n\r\n", 2);
  std::thread t5(verify, ip_addr.c_str(), 110, "", 2);
  std::thread t6(verify, ip_addr.c_str(), 143, "", 2);
  t1.join();
  t2.join();
  t3.join();
  t4.join();
  t5.join();
  t6.join();
}


std::string getServiceName(int port) {
  if (port > 1024)
    return "Unkown";
  if (stdServiceNames.find(port) != stdServiceNames.end()) {
    return stdServiceNames[port];
  }
  else
    return serviceName[port - 1];
}















