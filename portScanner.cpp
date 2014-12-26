#include "Scanner.h"
#include "Records.h"
#include "types.h"
#include "utils.h"
#include "parse.h"
#include "CFileOperation.h"
#include <thread>
#include <mutex>
#include <vector>
#include <map>
#include <iostream>


using namespace std;

bool VERBOSE = true;

Records *pRcrd;
Scanner myScanner;
mutex mtx; // mutex
vector<ip_port_mode> vec; // to keep all (ip, port, mode) triples need to be scanned
map<string, ScanType> str2type = {{"SYN", SYNScan}, {"NULL", NULLScan}, {"FIN", FINScan}, {"ACK", ACKScan}, {"XMAS", XmasScan}, {"UDP", UDPScan}};
string types[] = {"SYN", "NULL", "FIN", "ACK", "XMAS", "UDP"};

void scan() {
  RecordIter it;

  mtx.lock();
  it = pRcrd->getNext();
  mtx.unlock();

  while (it != pRcrd->iend) {
    string ip_addr(it->ip_addr.c_str());
    int port = it->port;
    ScanType mode = it->mode;

    printMSG("Processing: %s   %d   %s\n", ip_addr.c_str(), port, typeNames[mode].c_str());


    for (int i = 0; i < MAX_TRY; ++i) {
      if (myScanner.markedQ(ip_addr, port, mode))
	break;
      myScanner.sendPackets(ip_addr, port, mode);
      myScanner.recvPackets();
    }

    mtx.lock();
    it = pRcrd->getNext();
    mtx.unlock();
  }
}



int main(int argc, char *argv[]) {
  ps_args_t ps_args;
  // TODO: we need to parse arguments
  parse_args(&ps_args, argc, argv);
  if (ps_args.ipListFile != "\0") {
    // read ip from file
    char buffer[FILE_MAX_SIZE];
    CFileOperation cfileoperation(ps_args.ipListFile);
    int ibufsize = cfileoperation.ReadFile(buffer, 0, FILE_MAX_SIZE);
    parse_ip_file(ps_args.ipList, buffer, ibufsize);
  }
  
 
  
  if (ps_args.portList.begin() == ps_args.portList.end()) {
    for (int i = 1; i <= 1024; ++i) 
      ps_args.portList.push_back(i);
  }

  if (ps_args.flagList.begin() == ps_args.flagList.end()) {
    for (int i = 0; i < 6; ++i) 
      ps_args.flagList.push_back(types[i]);
  }
  
  VERBOSE = ps_args.verbose;

  for (std::list<std::string>::iterator it1 = ps_args.ipList.begin(); it1 != ps_args.ipList.end(); it1++) {
    if (it1->size() < 4)
      continue;
    for (std::list<int>::iterator it2 = ps_args.portList.begin(); it2 != ps_args.portList.end(); it2++)
      for (std::list<std::string>::iterator it3 = ps_args.flagList.begin(); it3 != ps_args.flagList.end(); it3++) {
	ip_port_mode tmp;
	tmp.ip_addr = *it1;
	tmp.port = *it2;
	tmp.mode = str2type[*it3];
	vec.push_back(tmp);
      }
  }

  int Nthreads = ps_args.nthread;

  Records myRecords(vec);
  pRcrd = &myRecords;



  printf("Creating %d threads ...\n", Nthreads);
  printf("Scanning ...\n");
  thread t[Nthreads];
  // create multiple threads
  for (int i = 0; i < Nthreads; ++i) {
    t[i] = thread(scan);
  }
  for (int i = 0; i < Nthreads; ++i) {
    t[i].join();
  }
 
  myScanner.showResults();
  return 0;
}










