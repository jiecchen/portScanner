#ifndef __TYPES_H__
#define __TYPES_H__
#include <vector>
#include <map>
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>


enum ScanType {SYNScan, NULLScan, FINScan, ACKScan, XmasScan, UDPScan};
enum ResultType {NoResult, NoResponse, Open, Closed, Filtered, Unfiltered, Open_or_Filtered};


typedef struct ipportmode {
  std::string ip_addr;
  int port;
  ScanType mode;
} ip_port_mode;

typedef std::vector<ip_port_mode>::iterator RecordIter;

typedef std::map<ScanType, ResultType> TResult;
typedef std::map<uint16_t, TResult> TPortsDict;
typedef std::map<in_addr_t, TPortsDict> TIPDict;
typedef std::map<int, ScanType> TPort2Scan;




#endif
