#ifndef __RECORDS_H__
#define __RECORDS_H__
#include <vector>
#include "types.h"
#include "utils.h"





class Records {
public:
  Records(std::vector<ip_port_mode> &);
  std::vector<ip_port_mode>::iterator getNext();
  std::vector<ip_port_mode>::iterator iend;
  bool isEmpty();
private:
  bool lock();
  bool unlock();
  std::vector<ip_port_mode>::iterator icurrent;
  bool locked;
};

Records::Records(std::vector<ip_port_mode> &v) {
  locked = false;
  icurrent = v.begin();
  iend = v.end();
}

bool Records::lock() {
  if (locked)
    return false;
  locked = true;
  return true;
}

bool Records::unlock() {
  if (!locked) 
    return false;
  locked = false;
  return true;
}

std::vector<ip_port_mode>::iterator Records::getNext() {
  if (this->isEmpty())
    return iend;
  if (!lock()) {
    return iend;
  }
  std::vector<ip_port_mode>::iterator it = icurrent++;
  unlock();
  return it;
}

bool Records::isEmpty() {
  return this->icurrent == this->iend;
}

#endif
